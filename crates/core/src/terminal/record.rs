//! QL-12: MultiExec lines recorded in each terminal, so the Compare panel can group and diff them at
//! any time without typing the command again.
//!
//! * Before MultiExec holds a line's Enter, it hands each target terminal a [`RecordSlot`] (through the
//!   pane's input, so it arrives before the Enter). The pane starts recording when that Enter reaches
//!   the shell and stops when the prompt comes back ([`super::activity::prompt_came_back`], the QL-07
//!   check), when the output goes quiet for the QL-07 quiet spell (never at a password prompt), when
//!   the next MultiExec line is sent first, or at the per-line time cap. A connection that ends, or a
//!   terminal that closes, ends it too.
//! * What is kept is the text, not the bytes: [`TextRenderer`] drops escape sequences and replays
//!   carriage returns, backspaces and in-line cursor moves, so a progress bar leaves its last state and
//!   a redrawn line reads as it ended up. The command's own line (the prompt and the echo) and the
//!   prompt that came back are left out. A full-screen program's screens (the alternate screen) are not
//!   recorded; the main screen's line comes back after it, as on the terminal.
//! * Secrets are scrubbed as SS-11 saved output is: the login's, passwords typed for the terminal or
//!   its jump hosts, and QL-06 vault passwords typed into it (also one typed while it records). The
//!   text is hashed as it comes (exactly, and ignoring trailing whitespace) and capped like a Compare
//!   run's: the first and last halves are kept, and the whole output still groups right.
//! * Lines at password prompts and keys sent to full-screen programs are never lines (they pass
//!   straight through MultiExec), so nothing of them is recorded.
//! * Recordings live in memory only, for the MultiExec session: turning MultiExec off drops them, and a
//!   line goes once every terminal it ran in has closed. A session keeps at most
//!   [`RecordLimits::max_lines`] lines and [`RecordLimits::max_session_bytes`] of output; older lines
//!   go first, and the UI says how many went. Outputs never reach the audit log; an export is audited
//!   with what and where only (`bulk::BulkRuns::export_recorded`).
//! * Grouping, the headline and the diff are bulk.rs's (BX-03), on records built from the captures.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use super::activity::{is_password_prompt, prompt_came_back, FinishedHow};
use super::multiexec::MultiExecEvent;
use crate::adapters::exec_output::{CollectedOutput, OutputCollector, Scrubber};
use crate::bulk::{self, Counts, DiffLine, GroupOptions, HostOutput, HostResult, OutputDiff, OutputGroup, RecordedRun};
use crate::domain::now_rfc3339;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::policy::Tier;
use crate::store::JobTargetRecord;
use crate::vault::SecretString;

// ---- Text from terminal output ---------------------------------------------------------------------

/// A line longer than this many characters is broken in two (output that never ends a line).
const MAX_RENDER_CHARS: usize = 16 * 1024;
/// The longest control sequence parameters kept.
const MAX_CSI_CHARS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Escape {
    #[default]
    None,
    Started,
    Csi,
    /// OSC, DCS and the like: until BEL or `ESC \`.
    String,
    StringEsc,
    /// `ESC (` and the like: one more character names a character set.
    Charset,
}

/// Terminal output as the text its lines show (see the module comment): escape sequences dropped,
/// carriage returns, backspaces, erases and in-line cursor moves replayed on the current line. Moves to
/// other lines (cursor up, absolute positions) can't be followed line by line and are ignored.
#[derive(Debug, Default)]
pub struct TextRenderer {
    escape: Escape,
    csi: String,
    /// Bytes of a character split across two reads.
    partial: Vec<u8>,
    line: Vec<char>,
    col: usize,
    alternate: bool,
    /// The main screen's line while a full-screen program has the alternate one.
    saved: Option<(Vec<char>, usize)>,
    full_screen: bool,
}

impl TextRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds output; returns the lines it completed (without their line breaks).
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(bytes);
        let text = match std::str::from_utf8(&data) {
            Ok(text) => text.to_owned(),
            Err(err) if err.error_len().is_none() => {
                let valid = err.valid_up_to();
                self.partial = data[valid..].to_vec();
                String::from_utf8_lossy(&data[..valid]).into_owned()
            }
            Err(_) => String::from_utf8_lossy(&data).into_owned(),
        };
        let mut lines = Vec::new();
        for ch in text.chars() {
            self.push(ch, &mut lines);
        }
        lines
    }

    /// The line not finished yet (the main screen's, while a full-screen program is open).
    pub fn current(&self) -> String {
        match &self.saved {
            Some((line, _)) => line.iter().collect(),
            None => self.line.iter().collect(),
        }
    }

    /// A full-screen program is open now.
    pub fn alternate(&self) -> bool {
        self.alternate
    }

    /// A full-screen program was open at some point.
    pub fn full_screen(&self) -> bool {
        self.full_screen
    }

    fn push(&mut self, ch: char, lines: &mut Vec<String>) {
        match self.escape {
            Escape::Started => {
                self.escape = match ch {
                    '[' => {
                        self.csi.clear();
                        Escape::Csi
                    }
                    ']' | 'P' | 'X' | '^' | '_' => Escape::String,
                    '(' | ')' | '*' | '+' | '-' | '.' | '/' | '#' | '%' | ' ' => Escape::Charset,
                    // RIS, a full reset: the screen is cleared and the main one is back.
                    'c' => {
                        self.alternate = false;
                        self.saved = None;
                        self.line.clear();
                        self.col = 0;
                        Escape::None
                    }
                    _ => Escape::None,
                };
                return;
            }
            Escape::Charset => {
                self.escape = Escape::None;
                return;
            }
            Escape::Csi => {
                if ('@'..='~').contains(&ch) {
                    self.escape = Escape::None;
                    self.csi_final(ch);
                } else if self.csi.len() < MAX_CSI_CHARS {
                    self.csi.push(ch);
                }
                return;
            }
            Escape::String => {
                match ch {
                    '\x07' => self.escape = Escape::None,
                    '\x1b' => self.escape = Escape::StringEsc,
                    _ => {}
                }
                return;
            }
            Escape::StringEsc => {
                self.escape = if ch == '\\' { Escape::None } else { Escape::String };
                return;
            }
            Escape::None => {}
        }
        match ch {
            '\x1b' => self.escape = Escape::Started,
            // A full-screen program draws on the alternate screen: not recorded.
            _ if self.alternate => {}
            '\r' => self.col = 0,
            '\n' => {
                lines.push(self.line.drain(..).collect());
                self.col = 0;
            }
            '\x08' => self.col = self.col.saturating_sub(1),
            '\t' => self.col = ((self.col / 8 + 1) * 8).min(MAX_RENDER_CHARS),
            c if c.is_control() => {}
            c => self.put(c, lines),
        }
    }

    fn put(&mut self, c: char, lines: &mut Vec<String>) {
        if self.col >= MAX_RENDER_CHARS {
            lines.push(self.line.drain(..).collect());
            self.col = 0;
        }
        while self.line.len() < self.col {
            self.line.push(' ');
        }
        if self.col < self.line.len() {
            self.line[self.col] = c;
        } else {
            self.line.push(c);
        }
        self.col += 1;
    }

    fn set_alternate(&mut self, on: bool) {
        if on && !self.alternate {
            self.saved = Some((std::mem::take(&mut self.line), self.col));
            self.col = 0;
            self.alternate = true;
            self.full_screen = true;
        } else if !on && self.alternate {
            let (line, col) = self.saved.take().unwrap_or_default();
            self.line = line;
            self.col = col;
            self.alternate = false;
        }
    }

    fn csi_final(&mut self, ch: char) {
        let private = self.csi.starts_with(['?', '>', '=', '<']);
        let params: Vec<usize> = self
            .csi
            .trim_start_matches(['?', '>', '=', '<'])
            .split(';')
            .map(|p| p.parse().unwrap_or(0))
            .collect();
        let first = params.first().copied().unwrap_or(0);
        // A count: 0 or missing means 1.
        let n = first.clamp(1, MAX_RENDER_CHARS);
        let len = self.line.len();
        match ch {
            'h' | 'l' if private => {
                if params.iter().any(|p| matches!(p, 47 | 1047 | 1049)) {
                    self.set_alternate(ch == 'h');
                }
            }
            _ if self.alternate || private => {}
            // Erase in line: to the end, to the start, or all of it.
            'K' => match first {
                0 => self.line.truncate(self.col),
                1 => {
                    for cell in self.line.iter_mut().take(self.col + 1) {
                        *cell = ' ';
                    }
                }
                _ => self.line.clear(),
            },
            'C' => self.col = (self.col + n).min(MAX_RENDER_CHARS),
            'D' => self.col = self.col.saturating_sub(n),
            'G' | '`' => self.col = n - 1,
            // Delete characters: the rest of the line moves left.
            'P' if self.col < len => {
                let end = (self.col + n).min(len);
                self.line.drain(self.col..end);
            }
            // Insert blanks: the rest of the line moves right.
            '@' if self.col < len => {
                let room = MAX_RENDER_CHARS.saturating_sub(len).min(n);
                self.line.splice(self.col..self.col, std::iter::repeat_n(' ', room));
            }
            // Erase characters, the cursor stays.
            'X' => {
                for cell in self.line.iter_mut().skip(self.col).take(n) {
                    *cell = ' ';
                }
            }
            // Colours, cursor up and down, positions, scroll regions...: not followed.
            _ => {}
        }
    }
}

/// The text `output` shows once rendered (QL-12): completed lines joined with `\n`, then the line not
/// finished yet. For tests and the whole-output case.
pub fn render_text(output: &[u8]) -> String {
    let mut renderer = TextRenderer::new();
    let mut text: String = renderer.feed(output).into_iter().map(|l| l + "\n").collect();
    text.push_str(&renderer.current());
    text
}

// ---- One terminal's recording ----------------------------------------------------------------------

/// How a terminal's recording ended well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureEnd {
    /// The shell prompt came back.
    Prompt,
    /// The output stopped for the quiet spell: finished with a prompt Remotely doesn't know, or waiting
    /// for an answer.
    Quiet,
    /// The next MultiExec line was sent before the prompt came back (it answered a question, say).
    NextLine,
}

/// Where a terminal's recording of a line stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum CaptureState {
    /// Enter has not reached the shell yet: the line waits for its approval or its job.
    Waiting,
    /// Enter went; the prompt has not come back.
    Running,
    Done {
        how: CaptureEnd,
    },
    /// Still running at the time cap: recording stopped, the command goes on.
    TimedOut,
    /// The connection ended or the terminal closed before the prompt came back.
    Lost {
        reason: String,
    },
    /// Enter never reached this terminal.
    NotSent {
        reason: String,
    },
}

impl CaptureState {
    fn is_final(&self) -> bool {
        !matches!(self, CaptureState::Waiting | CaptureState::Running)
    }
}

/// QL-12's caps, and the per-line time limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLimits {
    /// Lines kept for the MultiExec session; older ones are dropped.
    pub max_lines: usize,
    /// Output kept per terminal per line, in bytes: the first and last halves, like a Compare run.
    pub max_output: usize,
    /// Output kept for the whole session, in bytes; the oldest lines go first.
    pub max_session_bytes: usize,
    /// A terminal whose prompt has not come back after this long stops recording the line.
    pub line_time: Duration,
}

impl Default for RecordLimits {
    fn default() -> Self {
        Self {
            max_lines: 200,
            max_output: crate::adapters::exec_output::MAX_OUTPUT_PER_STREAM,
            max_session_bytes: 32 * 1024 * 1024,
            line_time: Duration::from_secs(600),
        }
    }
}

/// The caps, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitsInfo {
    pub max_lines: usize,
    pub max_output_bytes: usize,
    pub max_session_bytes: usize,
    pub line_secs: u64,
}

impl From<RecordLimits> for LimitsInfo {
    fn from(l: RecordLimits) -> Self {
        Self {
            max_lines: l.max_lines,
            max_output_bytes: l.max_output,
            max_session_bytes: l.max_session_bytes,
            line_secs: l.line_time.as_secs(),
        }
    }
}

/// A recording in progress.
struct Capture {
    renderer: TextRenderer,
    collector: OutputCollector,
    /// The terminal's secrets, for the line not finished yet.
    secrets: Vec<SecretString>,
    /// The line Enter was pressed on: the prompt, then what was typed.
    typed_on: String,
    /// The command's own line has ended (its first line break): what follows is its output.
    command_line_done: bool,
    quiet: Option<Duration>,
    last_output: Option<Instant>,
    bytes: usize,
}

impl Capture {
    fn feed(&mut self, bytes: &[u8]) {
        for line in self.renderer.feed(bytes) {
            if !self.command_line_done {
                // The rest of the command's own line: the echo of what was typed.
                self.command_line_done = true;
                continue;
            }
            self.bytes += line.len() + 1;
            self.collector.stdout(line.as_bytes());
            self.collector.stdout(b"\n");
        }
    }

    /// The line not finished yet, scrubbed.
    fn current(&self) -> String {
        if !self.command_line_done {
            return String::new();
        }
        let refs: Vec<&SecretString> = self.secrets.iter().collect();
        let mut scrubber = Scrubber::new(&refs);
        let mut out = Vec::new();
        scrubber.push(self.renderer.current().as_bytes(), &mut out);
        scrubber.finish(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    fn finish(mut self, keep_current: bool) -> (CollectedOutput, bool) {
        if keep_current && self.command_line_done {
            let rest = self.renderer.current();
            self.collector.stdout(rest.as_bytes());
        }
        (self.collector.finish(), self.renderer.full_screen())
    }
}

struct SlotInner {
    name: String,
    state: CaptureState,
    limits: RecordLimits,
    capture: Option<Box<Capture>>,
    output: Option<CollectedOutput>,
    started: Option<Instant>,
    /// The end of the recorded run: the prompt, the last output (quiet), or the stop.
    ended: Option<Instant>,
    started_at: Option<String>,
    finished_at: Option<String>,
    full_screen: bool,
    /// MultiExec turned off or the line was dropped: nothing more is recorded.
    dropped: bool,
}

/// A slot's state as the views need it.
struct SlotView {
    terminal_id: Uuid,
    name: String,
    state: CaptureState,
    text: String,
    bytes: u64,
    truncated: bool,
    hashes: Option<(String, String)>,
    started: Option<Instant>,
    ended: Option<Instant>,
    started_at: Option<String>,
    finished_at: Option<String>,
    full_screen: bool,
}

/// One terminal's recording of one MultiExec line. MultiExec makes it; the terminal's pane fills it in.
pub struct RecordSlot {
    line_id: Uuid,
    terminal_id: Uuid,
    inner: Mutex<SlotInner>,
    hub: Weak<Hub>,
}

impl std::fmt::Debug for RecordSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordSlot")
            .field("line_id", &self.line_id)
            .field("terminal_id", &self.terminal_id)
            .finish_non_exhaustive()
    }
}

impl RecordSlot {
    pub(crate) fn terminal_id(&self) -> Uuid {
        self.terminal_id
    }

    /// Changes the state under the lock, then tells the hub (never under the lock).
    fn update<T>(&self, change: impl FnOnce(&mut SlotInner) -> (T, bool)) -> T {
        let (value, changed) = {
            let mut inner = locks::lock(&self.inner);
            if inner.dropped {
                return change(&mut SlotInner::gone()).0;
            }
            change(&mut inner)
        };
        if changed {
            if let Some(hub) = self.hub.upgrade() {
                hub.changed(self.line_id);
            }
        }
        value
    }

    /// Still worth feeding: started and not finished, nor dropped.
    pub(crate) fn recording(&self) -> bool {
        let inner = locks::lock(&self.inner);
        !inner.dropped && inner.state == CaptureState::Running
    }

    /// The line's Enter reached the shell: recording starts. `typed_on` is the cursor's line then.
    /// Returns false when the slot no longer waits (the line was cancelled, or MultiExec turned off).
    pub(crate) fn start(
        &self,
        typed_on: &str,
        secrets: Vec<SecretString>,
        quiet: Option<Duration>,
        now: Instant,
    ) -> bool {
        self.update(|inner| {
            if inner.state != CaptureState::Waiting {
                return (false, false);
            }
            let refs: Vec<&SecretString> = secrets.iter().collect();
            inner.capture = Some(Box::new(Capture {
                renderer: TextRenderer::new(),
                collector: OutputCollector::new(&refs, inner.limits.max_output),
                secrets,
                typed_on: typed_on.to_owned(),
                command_line_done: false,
                quiet,
                last_output: None,
                bytes: 0,
            }));
            inner.state = CaptureState::Running;
            inner.started = Some(now);
            inner.started_at = Some(now_rfc3339());
            (true, true)
        })
    }

    /// Output the shell printed while recording; `line` and `alternate` are the screen after it (the
    /// pane's [`super::activity::ScreenLine`]). Returns true when the prompt came back.
    pub(crate) fn output(&self, bytes: &[u8], line: &str, alternate: bool, now: Instant) -> bool {
        self.update(|inner| {
            let Some(capture) = inner.capture.as_mut() else {
                return (false, false);
            };
            capture.feed(bytes);
            capture.last_output = Some(now);
            let back = capture.command_line_done
                && !alternate
                && !capture.renderer.alternate()
                && prompt_came_back(line, &capture.typed_on);
            if back {
                inner.finish(
                    CaptureState::Done {
                        how: CaptureEnd::Prompt,
                    },
                    false,
                    now,
                );
            }
            (back, back)
        })
    }

    /// QL-06: a vault secret about to be typed into the terminal is scrubbed from the recording too.
    pub(crate) fn add_secret(&self, secret: &SecretString) {
        let mut inner = locks::lock(&self.inner);
        if let Some(capture) = inner.capture.as_mut() {
            capture.collector.add_secret(secret);
            capture.secrets.push(secret.clone());
        }
    }

    /// When [`RecordSlot::tick`] should next be called: the quiet spell after the last output (never
    /// while the terminal shows a password prompt) or the time cap.
    pub(crate) fn deadline(&self, line: &str) -> Option<Instant> {
        let inner = locks::lock(&self.inner);
        let capture = inner.capture.as_ref()?;
        let cap = inner.started.map(|s| s + inner.limits.line_time);
        let quiet = match (capture.quiet, capture.last_output) {
            (Some(quiet), Some(last)) if !is_password_prompt(line) => Some(last + quiet),
            _ => None,
        };
        [cap, quiet].into_iter().flatten().min()
    }

    /// Time passed: the recording ends if it went quiet or reached the cap. Returns true if it ended.
    pub(crate) fn tick(&self, now: Instant, line: &str) -> bool {
        let Some(deadline) = self.deadline(line) else {
            return false;
        };
        if now < deadline {
            return false;
        }
        self.update(|inner| {
            let Some(capture) = inner.capture.as_ref() else {
                return (false, false);
            };
            let capped = inner.started.is_some_and(|s| now >= s + inner.limits.line_time);
            if capped {
                inner.finish(CaptureState::TimedOut, true, now);
            } else {
                let last = capture.last_output.unwrap_or(now);
                inner.finish(CaptureState::Done { how: CaptureEnd::Quiet }, true, last);
            }
            (true, true)
        })
    }

    /// The next MultiExec line was sent to this terminal before the prompt came back.
    pub(crate) fn next_line(&self, now: Instant) {
        self.update(|inner| {
            if inner.capture.is_none() {
                return ((), false);
            }
            inner.finish(
                CaptureState::Done {
                    how: CaptureEnd::NextLine,
                },
                true,
                now,
            );
            ((), true)
        });
    }

    /// The connection ended (or the terminal closed) while recording, or before Enter came.
    pub(crate) fn lost(&self, reason: &str) {
        let now = Instant::now();
        self.update(|inner| match inner.state {
            CaptureState::Running => {
                inner.finish(
                    CaptureState::Lost {
                        reason: reason.to_owned(),
                    },
                    true,
                    now,
                );
                ((), true)
            }
            CaptureState::Waiting => {
                inner.state = CaptureState::NotSent {
                    reason: reason.to_owned(),
                };
                ((), true)
            }
            _ => ((), false),
        });
    }

    /// Enter will not reach this terminal.
    pub(crate) fn not_sent(&self, reason: &str) {
        self.update(|inner| {
            if inner.state != CaptureState::Waiting {
                return ((), false);
            }
            inner.state = CaptureState::NotSent {
                reason: reason.to_owned(),
            };
            ((), true)
        });
    }

    /// Nothing more is recorded or kept (MultiExec turned off, or the line dropped by a cap).
    fn drop_recording(&self) {
        let mut inner = locks::lock(&self.inner);
        inner.dropped = true;
        inner.capture = None;
        inner.output = None;
    }

    /// Bytes of output this slot keeps.
    fn kept_bytes(&self) -> usize {
        let inner = locks::lock(&self.inner);
        match (&inner.output, &inner.capture) {
            (Some(output), _) => output.stdout.len(),
            (None, Some(capture)) => capture.bytes.min(inner.limits.max_output),
            _ => 0,
        }
    }

    fn view(&self) -> SlotView {
        let inner = locks::lock(&self.inner);
        let (text, bytes, truncated, hashes) = match (&inner.output, &inner.capture) {
            (Some(o), _) => (
                o.stdout.clone(),
                o.stdout_bytes,
                o.truncated,
                Some((o.hash.clone(), o.hash_loose.clone())),
            ),
            (None, Some(c)) => {
                let (mut text, bytes, truncated) = c.collector.peek_stdout();
                text.push_str(&c.current());
                (text, bytes, truncated, None)
            }
            _ => (String::new(), 0, false, None),
        };
        SlotView {
            terminal_id: self.terminal_id,
            name: inner.name.clone(),
            state: inner.state.clone(),
            text,
            bytes,
            truncated,
            hashes,
            started: inner.started,
            ended: inner.ended,
            started_at: inner.started_at.clone(),
            finished_at: inner.finished_at.clone(),
            full_screen: inner.full_screen || inner.capture.as_ref().is_some_and(|c| c.renderer.full_screen()),
        }
    }
}

impl SlotInner {
    /// A stand-in for a dropped slot, so changes to it go nowhere.
    fn gone() -> Self {
        Self {
            name: String::new(),
            state: CaptureState::NotSent {
                reason: "dropped".into(),
            },
            limits: RecordLimits::default(),
            capture: None,
            output: None,
            started: None,
            ended: None,
            started_at: None,
            finished_at: None,
            full_screen: false,
            dropped: true,
        }
    }

    fn finish(&mut self, state: CaptureState, keep_current: bool, ended: Instant) {
        if let Some(capture) = self.capture.take() {
            let (output, full_screen) = capture.finish(keep_current);
            self.output = Some(output);
            self.full_screen |= full_screen;
        }
        self.state = state;
        self.ended = Some(ended);
        self.finished_at = Some(now_rfc3339());
    }
}

// ---- The session's recordings ----------------------------------------------------------------------

/// A recorded line in the list (newest first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedLine {
    pub id: Uuid,
    /// What was typed (a paste of several lines is one script).
    pub line: String,
    pub tier: Option<Tier>,
    /// The job that sent its Enter, once there is one.
    pub job_id: Option<Uuid>,
    /// When the line was held (RFC 3339).
    pub recorded_at: String,
    /// Waits for the approval dialog.
    pub waiting_approval: bool,
    pub terminals: usize,
    /// Terminals done with it (the prompt came back, or recording ended otherwise).
    pub finished: usize,
    /// "All 3 hosts the same", grouped by exact output.
    pub headline: String,
    pub groups: usize,
    /// Some terminal's output was cut in the middle (the per-line cap).
    pub truncated: bool,
    /// A full-screen program ran in some terminal: its screens are not recorded.
    pub full_screen: bool,
    /// From the first Enter to the last prompt, once every terminal is done.
    pub duration_ms: Option<i64>,
}

/// QL-12: the MultiExec session's recorded lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recordings {
    /// Newest first.
    pub lines: Vec<RecordedLine>,
    /// Older lines dropped by the session caps.
    pub dropped: usize,
    pub session_bytes: usize,
    pub limits: LimitsInfo,
}

/// One terminal of a recorded line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedTerminal {
    pub terminal_id: Uuid,
    pub name: String,
    #[serde(flatten)]
    pub state: CaptureState,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    /// So far, while it runs.
    pub duration_ms: Option<i64>,
    pub output_bytes: u64,
    pub truncated: bool,
    pub full_screen: bool,
}

/// A recorded line grouped like a Compare run (BX-03).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedResults {
    pub line: RecordedLine,
    pub counts: Counts,
    /// One per terminal, in the order the line went to them; `targetKey` is the terminal's id.
    pub hosts: Vec<HostResult>,
    pub terminals: Vec<RecordedTerminal>,
    pub groups: Vec<OutputGroup>,
    pub headline: String,
    pub ignore_trailing_whitespace: bool,
}

struct Line {
    id: Uuid,
    line: String,
    tier: Option<Tier>,
    job_id: Option<Uuid>,
    /// Shown: the bus took the line (held, or sent at once).
    shown: bool,
    waiting_approval: bool,
    recorded_at: String,
    slots: Vec<Arc<RecordSlot>>,
    /// LineFinished went out.
    finished_sent: bool,
}

struct Book {
    limits: RecordLimits,
    /// Oldest first.
    lines: VecDeque<Line>,
    dropped: usize,
}

struct Hub {
    book: Mutex<Book>,
    events: broadcast::Sender<MultiExecEvent>,
}

fn millis(from: Option<Instant>, to: Option<Instant>) -> Option<i64> {
    match (from, to) {
        (Some(from), Some(to)) => {
            Some(i64::try_from(to.saturating_duration_since(from).as_millis()).unwrap_or(i64::MAX))
        }
        _ => None,
    }
}

/// A slot as a job target, so bulk.rs groups it like a host of a Compare run.
fn target_record(v: &SlotView, now: Instant) -> JobTargetRecord {
    let (status, error, error_code) = match &v.state {
        CaptureState::Waiting => ("pending", None, None),
        CaptureState::Running => ("running", None, None),
        CaptureState::Done { .. } => ("succeeded", None, None),
        CaptureState::TimedOut => (
            "failed",
            Some("Still running at the time limit, so recording stopped (the command goes on)".to_owned()),
            Some("time_limit"),
        ),
        CaptureState::Lost { reason } => ("failed", Some(reason.clone()), Some("lost")),
        CaptureState::NotSent { reason } => ("failed", Some(reason.clone()), Some("not_sent")),
    };
    let done = matches!(v.state, CaptureState::Done { .. });
    let running = v.state == CaptureState::Running;
    JobTargetRecord {
        target_kind: "terminal".into(),
        target_key: v.terminal_id.to_string(),
        target_name: v.name.clone(),
        status: status.into(),
        exit_code: None,
        output: Some(v.text.clone()),
        error,
        started_at: v.started_at.clone(),
        finished_at: v.finished_at.clone(),
        duration_ms: millis(v.started, if running { Some(now) } else { v.ended }),
        safety_snapshot: None,
        stderr: None,
        stdout_bytes: Some(i64::try_from(v.bytes).unwrap_or(i64::MAX)),
        stderr_bytes: None,
        output_truncated: v.truncated,
        output_hash: v.hashes.as_ref().filter(|_| done).map(|h| h.0.clone()),
        output_hash_loose: v.hashes.as_ref().filter(|_| done).map(|h| h.1.clone()),
        error_code: error_code.map(str::to_owned),
        peer_ip: None,
        host_key: None,
    }
}

impl Line {
    fn views(&self) -> Vec<SlotView> {
        self.slots.iter().map(|s| s.view()).collect()
    }

    fn summary(&self, views: &[SlotView], now: Instant) -> RecordedLine {
        let records: Vec<JobTargetRecord> = views.iter().map(|v| target_record(v, now)).collect();
        let grouped = bulk::group_with_output(&records, GroupOptions::default());
        let finished = views.iter().filter(|v| v.state.is_final()).count();
        let first = views.iter().filter_map(|v| v.started).min();
        let last = views.iter().filter_map(|v| v.ended).max();
        RecordedLine {
            id: self.id,
            line: self.line.clone(),
            tier: self.tier,
            job_id: self.job_id,
            recorded_at: self.recorded_at.clone(),
            waiting_approval: self.waiting_approval,
            terminals: views.len(),
            finished,
            headline: grouped.headline,
            groups: grouped.groups.len(),
            truncated: views.iter().any(|v| v.truncated),
            full_screen: views.iter().any(|v| v.full_screen),
            duration_ms: if finished == views.len() {
                millis(first, last)
            } else {
                None
            },
        }
    }

    fn kept_bytes(&self) -> usize {
        self.slots.iter().map(|s| s.kept_bytes()).sum()
    }

    fn drop_slots(&self) {
        for slot in &self.slots {
            slot.drop_recording();
        }
    }

    /// Every terminal is done: the one QL-07 notification for the line (none if Enter reached none).
    fn finished_event(&self) -> Option<MultiExecEvent> {
        let views = self.views();
        if !views.iter().all(|v| v.state.is_final()) {
            return None;
        }
        let reached: Vec<Uuid> = views
            .iter()
            .filter(|v| v.started.is_some())
            .map(|v| v.terminal_id)
            .collect();
        let ran = reached.len();
        if ran == 0 {
            return None;
        }
        let first = views.iter().filter_map(|v| v.started).min();
        let last = views.iter().filter_map(|v| v.ended).max();
        let quiet = views
            .iter()
            .any(|v| v.state == CaptureState::Done { how: CaptureEnd::Quiet });
        let unfinished = views
            .iter()
            .filter(|v| !matches!(v.state, CaptureState::Done { .. }))
            .count();
        Some(MultiExecEvent::LineFinished {
            line_id: self.id,
            line: self.line.clone(),
            terminal_ids: reached,
            terminals: ran,
            after_secs: millis(first, last).map_or(0, |ms| u64::try_from(ms / 1000).unwrap_or(0)),
            how: if quiet { FinishedHow::Quiet } else { FinishedHow::Prompt },
            unfinished,
        })
    }
}

impl Book {
    fn line_mut(&mut self, id: Uuid) -> Option<&mut Line> {
        self.lines.iter_mut().find(|l| l.id == id)
    }

    fn line(&self, id: Uuid) -> Result<&Line> {
        self.lines
            .iter()
            .find(|l| l.id == id && l.shown)
            .ok_or_else(|| CoreError::InvalidInput("That recorded line is no longer kept.".into()))
    }

    /// Drops the oldest lines past the caps (never the newest). Returns whether any went.
    fn enforce_caps(&mut self) -> bool {
        let mut any = false;
        loop {
            let shown = self.lines.iter().filter(|l| l.shown).count();
            let over_lines = shown > self.limits.max_lines;
            let over_bytes = self.lines.len() > 1
                && self.lines.iter().map(Line::kept_bytes).sum::<usize>() > self.limits.max_session_bytes;
            if !(over_lines || over_bytes) || self.lines.len() <= 1 {
                return any;
            }
            if let Some(oldest) = self.lines.pop_front() {
                oldest.drop_slots();
                if oldest.shown {
                    self.dropped += 1;
                }
                any = true;
            }
        }
    }
}

impl Hub {
    /// A slot changed: the line's views update, and when every terminal is done, the line finishes.
    fn changed(&self, line_id: Uuid) {
        let mut events = Vec::new();
        {
            let mut book = locks::lock(&self.book);
            let Some(line) = book.line_mut(line_id) else {
                return;
            };
            if !line.shown {
                return;
            }
            events.push(MultiExecEvent::Recorded { line_id: Some(line_id) });
            if !line.finished_sent {
                if let Some(event) = line.finished_event() {
                    line.finished_sent = true;
                    events.push(event);
                }
            }
            if book.enforce_caps() {
                events.push(MultiExecEvent::Recorded { line_id: None });
            }
        }
        for event in events {
            let _ = self.events.send(event);
        }
    }
}

/// QL-12 (see the module comment): MultiExec's recordings for its session.
#[derive(Clone)]
pub(crate) struct Recorder {
    hub: Arc<Hub>,
}

impl Recorder {
    pub(crate) fn new(events: broadcast::Sender<MultiExecEvent>) -> Self {
        Self {
            hub: Arc::new(Hub {
                book: Mutex::new(Book {
                    limits: RecordLimits::default(),
                    lines: VecDeque::new(),
                    dropped: 0,
                }),
                events,
            }),
        }
    }

    pub(crate) fn set_limits(&self, limits: RecordLimits) {
        locks::lock(&self.hub.book).limits = limits;
    }

    fn send(&self, event: MultiExecEvent) {
        let _ = self.hub.events.send(event);
    }

    /// A line is about to be rated: a slot for each terminal it goes to, `(id, name)`, in order.
    /// Not shown until [`Recorder::taken`].
    pub(crate) fn begin(&self, line_id: Uuid, line: &str, targets: &[(Uuid, String)]) -> Vec<Arc<RecordSlot>> {
        let mut book = locks::lock(&self.hub.book);
        let limits = book.limits;
        let slots: Vec<Arc<RecordSlot>> = targets
            .iter()
            .map(|(id, name)| {
                Arc::new(RecordSlot {
                    line_id,
                    terminal_id: *id,
                    inner: Mutex::new(SlotInner {
                        name: name.clone(),
                        state: CaptureState::Waiting,
                        limits,
                        capture: None,
                        output: None,
                        started: None,
                        ended: None,
                        started_at: None,
                        finished_at: None,
                        full_screen: false,
                        dropped: false,
                    }),
                    hub: Arc::downgrade(&self.hub),
                })
            })
            .collect();
        book.lines.push_back(Line {
            id: line_id,
            line: line.to_owned(),
            tier: None,
            job_id: None,
            shown: false,
            waiting_approval: false,
            recorded_at: now_rfc3339(),
            slots: slots.clone(),
            finished_sent: false,
        });
        slots
    }

    /// The bus took the line: queued (`job_id`) or waiting for approval. It shows from now on.
    pub(crate) fn taken(&self, line_id: Uuid, tier: Tier, job_id: Option<Uuid>) {
        let mut events = Vec::new();
        {
            let mut book = locks::lock(&self.hub.book);
            let Some(line) = book.line_mut(line_id) else {
                return;
            };
            line.shown = true;
            line.tier = Some(tier);
            line.job_id = job_id;
            line.waiting_approval = job_id.is_none();
            events.push(MultiExecEvent::Recorded { line_id: Some(line_id) });
            // A quick line may be done in every terminal already.
            if let Some(event) = line.finished_event() {
                line.finished_sent = true;
                events.push(event);
            }
            if book.enforce_caps() {
                events.push(MultiExecEvent::Recorded { line_id: None });
            }
        }
        for event in events {
            self.send(event);
        }
    }

    /// The line was approved: its job sends Enter.
    pub(crate) fn approved(&self, line_id: Uuid, job_id: Uuid) {
        let mut book = locks::lock(&self.hub.book);
        if let Some(line) = book.line_mut(line_id) {
            line.job_id = Some(job_id);
            line.waiting_approval = false;
        }
        drop(book);
        self.send(MultiExecEvent::Recorded { line_id: Some(line_id) });
    }

    /// The line never ran (refused, or cancelled before its Enter): it goes.
    pub(crate) fn discard(&self, line_id: Uuid) {
        let shown = {
            let mut book = locks::lock(&self.hub.book);
            let Some(at) = book.lines.iter().position(|l| l.id == line_id) else {
                return;
            };
            book.lines.remove(at).map(|line| {
                line.drop_slots();
                line.shown
            })
        };
        if shown == Some(true) {
            self.send(MultiExecEvent::Recorded { line_id: Some(line_id) });
        }
    }

    /// The line's job ended. Cancelled before any Enter went: the line goes. Otherwise a terminal that
    /// is not connected now never got the Enter.
    pub(crate) fn job_ended(&self, line_id: Uuid, cancelled: bool, connected: impl Fn(Uuid) -> bool) {
        let slots = {
            let book = locks::lock(&self.hub.book);
            match book.lines.iter().find(|l| l.id == line_id) {
                Some(line) => line.slots.clone(),
                None => return,
            }
        };
        let started = slots.iter().any(|s| s.view().started.is_some());
        if cancelled && !started {
            self.discard(line_id);
            return;
        }
        for slot in slots {
            if cancelled {
                slot.not_sent("the line was cancelled before its Enter reached this terminal");
            } else if !connected(slot.terminal_id) {
                slot.not_sent("not connected when Enter was sent");
            }
        }
    }

    /// MultiExec turned off: every recording goes.
    pub(crate) fn clear(&self) {
        let any = {
            let mut book = locks::lock(&self.hub.book);
            let any = !book.lines.is_empty() || book.dropped > 0;
            for line in book.lines.drain(..) {
                line.drop_slots();
            }
            book.dropped = 0;
            any
        };
        if any {
            self.send(MultiExecEvent::Recorded { line_id: None });
        }
    }

    /// Terminals that closed: what they were recording is lost, and a line goes once all of its
    /// terminals have closed.
    fn forget_closed(&self, alive: &dyn Fn(Uuid) -> bool) {
        let (slots, gone) = {
            let mut book = locks::lock(&self.hub.book);
            let slots: Vec<Arc<RecordSlot>> = book
                .lines
                .iter()
                .flat_map(|l| l.slots.iter().cloned())
                .filter(|s| !alive(s.terminal_id))
                .collect();
            let before = book.lines.len();
            let mut kept = VecDeque::with_capacity(before);
            for line in book.lines.drain(..) {
                if line.slots.iter().any(|s| alive(s.terminal_id)) {
                    kept.push_back(line);
                } else {
                    line.drop_slots();
                }
            }
            book.lines = kept;
            (slots, book.lines.len() != before)
        };
        for slot in slots {
            slot.lost("the terminal closed");
        }
        if gone {
            self.send(MultiExecEvent::Recorded { line_id: None });
        }
    }

    pub(crate) fn list(&self, alive: &dyn Fn(Uuid) -> bool) -> Recordings {
        self.forget_closed(alive);
        let book = locks::lock(&self.hub.book);
        let now = Instant::now();
        let lines = book
            .lines
            .iter()
            .rev()
            .filter(|l| l.shown)
            .map(|l| l.summary(&l.views(), now))
            .collect();
        Recordings {
            lines,
            dropped: book.dropped,
            session_bytes: book.lines.iter().map(Line::kept_bytes).sum(),
            limits: book.limits.into(),
        }
    }

    pub(crate) fn results(
        &self,
        line_id: Uuid,
        opts: GroupOptions,
        alive: &dyn Fn(Uuid) -> bool,
    ) -> Result<RecordedResults> {
        self.forget_closed(alive);
        let book = locks::lock(&self.hub.book);
        let line = book.line(line_id)?;
        let now = Instant::now();
        let views = line.views();
        let records: Vec<JobTargetRecord> = views.iter().map(|v| target_record(v, now)).collect();
        let grouped = bulk::group_with_output(&records, opts);
        let terminals = views
            .iter()
            .zip(&records)
            .map(|(v, r)| RecordedTerminal {
                terminal_id: v.terminal_id,
                name: v.name.clone(),
                state: v.state.clone(),
                started_at: v.started_at.clone(),
                finished_at: v.finished_at.clone(),
                duration_ms: r.duration_ms,
                output_bytes: v.bytes,
                truncated: v.truncated,
                full_screen: v.full_screen,
            })
            .collect();
        Ok(RecordedResults {
            line: line.summary(&views, now),
            counts: grouped.counts,
            hosts: grouped.hosts,
            terminals,
            groups: grouped.groups,
            headline: grouped.headline,
            ignore_trailing_whitespace: opts.ignore_trailing_whitespace,
        })
    }

    /// One terminal's recorded output (so far, while it runs).
    pub(crate) fn output(&self, line_id: Uuid, terminal_id: Uuid) -> Result<HostOutput> {
        let book = locks::lock(&self.hub.book);
        let line = book.line(line_id)?;
        let slot = line
            .slots
            .iter()
            .find(|s| s.terminal_id == terminal_id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {terminal_id} of that line")))?;
        let v = slot.view();
        let record = target_record(&v, Instant::now());
        Ok(HostOutput {
            target_key: record.target_key,
            name: record.target_name,
            stdout: v.text,
            stderr: String::new(),
            truncated: v.truncated,
            exit_code: None,
            error: record.error,
        })
    }

    /// BX-03's diff between two terminals' outputs of a line (two groups' samples).
    pub(crate) fn diff(&self, line_id: Uuid, left: Uuid, right: Uuid, opts: GroupOptions) -> Result<OutputDiff> {
        let a = self.output(line_id, left)?;
        let b = self.output(line_id, right)?;
        let stdout: Vec<DiffLine> = bulk::diff_lines(&a.stdout, &b.stdout, opts);
        Ok(OutputDiff {
            left: a.name,
            right: b.name,
            left_exit_code: None,
            right_exit_code: None,
            stdout,
            stderr: Vec::new(),
        })
    }

    /// One line, or every one (oldest first), for an export.
    pub(crate) fn runs(&self, line_id: Option<Uuid>) -> Result<Vec<RecordedRun>> {
        let book = locks::lock(&self.hub.book);
        let now = Instant::now();
        let run = |l: &Line| RecordedRun {
            line: l.line.clone(),
            tier: l.tier.unwrap_or(Tier::Low),
            recorded_at: l.recorded_at.clone(),
            job_id: l.job_id,
            targets: l.views().iter().map(|v| target_record(v, now)).collect(),
        };
        match line_id {
            Some(id) => Ok(vec![run(book.line(id)?)]),
            None => Ok(book.lines.iter().filter(|l| l.shown).map(run).collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_are_dropped_and_colours_leave_plain_text() {
        assert_eq!(
            render_text(b"\x1b[01;34mbin\x1b[0m  \x1b[01;32mrun.sh\x1b[0m\r\n"),
            "bin  run.sh\n"
        );
        // OSC (a title, SS-08's folder report) ends with BEL or ST; charsets take one more character.
        assert_eq!(
            render_text(b"\x1b]0;alice@web01: ~\x07\x1b]7;file://web01/home\x1b\\\x1b(Bok\r\n"),
            "ok\n"
        );
        assert_eq!(render_text(b"caf\xc3\xa9\r\n"), "café\n");
    }

    #[test]
    fn carriage_returns_and_redraws_leave_the_last_state() {
        assert_eq!(render_text(b"10%\r50%\r100%\r\n"), "100%\n");
        // A shorter redraw keeps what it did not cover, as on a terminal, unless the line is erased.
        assert_eq!(render_text(b"downloading\rdone\r\n"), "doneloading\n");
        assert_eq!(render_text(b"downloading\r\x1b[Kdone\r\n"), "done\n");
        assert_eq!(render_text(b"downloading\r\x1b[2Kdone\r\n"), "done\n");
        assert_eq!(render_text(b"ab\x08\x08xy\r\n"), "xy\n");
        assert_eq!(render_text(b"abcdef\x1b[3D\x1b[Px\r\n"), "abcxf\n");
        assert_eq!(render_text(b"ac\x1b[D\x1b[@b\r\n"), "abc\n");
        assert_eq!(render_text(b"a\tb\r\n"), "a       b\n");
        assert_eq!(
            render_text(b"[    ]\r\x1b[2C##\r\n"),
            "[ ## ]\n",
            "a progress bar drawn in place"
        );
        // Split across reads, in the middle of an escape and of a character.
        let mut r = TextRenderer::new();
        let mut lines = r.feed(b"\x1b[3");
        lines.extend(r.feed(b"1mred\x1b[0m \xc3"));
        lines.extend(r.feed(b"\xa9\r\nnext"));
        assert_eq!(lines, ["red é"]);
        assert_eq!(r.current(), "next");
    }

    #[test]
    fn prompt_hook_reports_never_reach_the_text() {
        // SS-08's folder (OSC 7, ended by ST) and QL-09's user report (OSC 7777, ended by BEL), split
        // across two reads in the middle of the report.
        let mut r = TextRenderer::new();
        let mut lines = r.feed(b"web01\r\n\x1b]7;file://web01/home/alice\x1b\\\x1b]7777;remotely-us");
        lines.extend(r.feed(b"er=alice\x07$ "));
        assert_eq!(lines, ["web01"]);
        assert_eq!(r.current(), "$ ");
        assert_eq!(
            render_text(b"\x1b]7777;remotely-0123abcd\x07ok\r\n"),
            "ok\n",
            "the hook's set-up marker"
        );
    }

    #[test]
    fn a_full_screen_program_is_not_recorded_and_the_main_line_comes_back() {
        let mut r = TextRenderer::new();
        let mut lines = r.feed(b"before\r\n$ top");
        lines.extend(r.feed(b"\x1b[?1049h\x1b[H\x1b[2Jtop - 10:00 up 3 days\r\nTasks: 99\r\n"));
        assert!(r.alternate());
        assert_eq!(r.current(), "$ top", "the main screen's line is kept");
        lines.extend(r.feed(b"\x1b[?1049l\r\n$ "));
        assert!(!r.alternate() && r.full_screen());
        assert_eq!(lines, ["before", "$ top"]);
        assert_eq!(r.current(), "$ ");
    }

    #[test]
    fn endless_lines_are_broken_and_huge_counts_are_capped() {
        let long = "x".repeat(MAX_RENDER_CHARS + 10);
        let mut r = TextRenderer::new();
        let lines = r.feed(long.as_bytes());
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), MAX_RENDER_CHARS);
        assert_eq!(r.current().len(), 10);
        let mut r = TextRenderer::new();
        r.feed(b"a\x1b[999999999Cb");
        assert!(r.current().len() <= MAX_RENDER_CHARS + 1);
    }

    fn slot(limits: RecordLimits) -> (Recorder, Arc<RecordSlot>, Uuid) {
        let (events, _) = broadcast::channel(64);
        let recorder = Recorder::new(events);
        recorder.set_limits(limits);
        let line = Uuid::new_v4();
        let terminal = Uuid::new_v4();
        let slots = recorder.begin(line, "uptime", &[(terminal, "web01".into())]);
        recorder.taken(line, Tier::Low, Some(Uuid::new_v4()));
        (recorder, Arc::clone(&slots[0]), line)
    }

    #[test]
    fn a_recording_runs_from_enter_to_the_prompt_without_the_command_line_or_the_prompt() {
        let (recorder, slot, line) = slot(RecordLimits::default());
        let t0 = Instant::now();
        assert!(slot.start("alice@web01:~$ upt", vec![], None, t0));
        // The echo of the rest of the command arrives after Enter: it is not output.
        assert!(!slot.output(b"ime\r\n 10:00:00 up 3 days\r\n", "", false, t0));
        assert!(slot.output(
            b"alice@web01:~$ ",
            "alice@web01:~$ ",
            false,
            t0 + Duration::from_millis(5)
        ));
        let results = recorder.results(line, GroupOptions::default(), &|_| true).unwrap();
        assert_eq!(results.groups.len(), 1);
        assert_eq!(results.groups[0].stdout.as_deref(), Some(" 10:00:00 up 3 days\n"));
        assert_eq!(
            results.terminals[0].state,
            CaptureState::Done {
                how: CaptureEnd::Prompt
            }
        );
        assert_eq!(results.line.finished, 1);
    }

    #[test]
    fn quiet_never_ends_a_recording_at_a_password_prompt_but_the_cap_does() {
        let limits = RecordLimits {
            line_time: Duration::from_secs(60),
            ..RecordLimits::default()
        };
        let (_recorder, slot, _) = slot(limits);
        let t0 = Instant::now();
        slot.start("$ sudo ls", vec![], Some(Duration::from_secs(5)), t0);
        slot.output(
            b"\r\n[sudo] password for alice: ",
            "[sudo] password for alice: ",
            false,
            t0,
        );
        assert_eq!(
            slot.deadline("[sudo] password for alice: "),
            Some(t0 + Duration::from_secs(60)),
            "only the cap"
        );
        assert!(!slot.tick(t0 + Duration::from_secs(30), "[sudo] password for alice: "));
        assert!(slot.tick(t0 + Duration::from_secs(60), "[sudo] password for alice: "));
        assert_eq!(slot.view().state, CaptureState::TimedOut);
        assert_eq!(
            slot.view().text,
            "[sudo] password for alice: ",
            "what it showed is kept"
        );
    }

    #[test]
    fn output_that_stops_ends_a_recording_after_the_quiet_spell() {
        let (_recorder, slot, _) = slot(RecordLimits::default());
        let t0 = Instant::now();
        slot.start("➜  ~ ./build.sh", vec![], Some(Duration::from_secs(5)), t0);
        slot.output(
            "\r\nbuilt\r\n➜  srv ".as_bytes(),
            "➜  srv ",
            false,
            t0 + Duration::from_secs(1),
        );
        assert!(slot.recording(), "an unknown prompt");
        assert!(slot.tick(t0 + Duration::from_secs(6), "➜  srv "));
        let v = slot.view();
        assert_eq!(v.state, CaptureState::Done { how: CaptureEnd::Quiet });
        assert_eq!(v.text, "built\n➜  srv ", "the unknown prompt stays in the text");
        assert_eq!(millis(v.started, v.ended), Some(1000), "until the last output");
    }

    #[test]
    fn secrets_are_scrubbed_also_one_typed_while_recording() {
        let (_recorder, slot, _) = slot(RecordLimits::default());
        let t0 = Instant::now();
        slot.start("$ x", vec![SecretString::new("login-pw-1")], None, t0);
        slot.output(b"\r\nlogin-pw-1 typed\r\n", "", false, t0);
        slot.add_secret(&SecretString::new("vault-pw-2"));
        slot.output(b"vault-pw-2\r\npartial vault-pw-2", "partial vault-pw-2", false, t0);
        let running = slot.view();
        assert!(!running.text.contains("pw-"), "{}", running.text);
        slot.output(b"\r\n$ ", "$ ", false, t0);
        let done = slot.view();
        assert_eq!(done.text, "[redacted] typed\n[redacted]\npartial [redacted]\n");
    }

    #[test]
    fn a_long_output_is_cut_in_the_middle_and_still_hashed_whole() {
        let limits = RecordLimits {
            max_output: 64,
            ..RecordLimits::default()
        };
        let (_recorder, slot, _) = slot(limits);
        let t0 = Instant::now();
        slot.start("$ seq 100", vec![], None, t0);
        let body: String = (1..=100).map(|i| format!("{i}\r\n")).collect();
        slot.output(format!("\r\n{body}$ ").as_bytes(), "$ ", false, t0);
        let v = slot.view();
        assert!(v.truncated);
        assert!(
            v.text.starts_with("1\n2\n") && v.text.ends_with("99\n100\n"),
            "{}",
            v.text
        );
        assert!(v.text.contains("Remotely cut"));
        assert_eq!(v.bytes, 292);
    }

    #[test]
    fn the_session_keeps_its_newest_lines_and_counts_the_dropped_ones() {
        let (events, _) = broadcast::channel(64);
        let recorder = Recorder::new(events);
        recorder.set_limits(RecordLimits {
            max_lines: 2,
            ..RecordLimits::default()
        });
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        for (i, id) in ids.iter().enumerate() {
            recorder.begin(*id, &format!("echo {i}"), &[(Uuid::new_v4(), "web01".into())]);
            recorder.taken(*id, Tier::Low, Some(Uuid::new_v4()));
        }
        let list = recorder.list(&|_| true);
        let lines: Vec<&str> = list.lines.iter().map(|l| l.line.as_str()).collect();
        assert_eq!(lines, ["echo 2", "echo 1"], "newest first");
        assert_eq!(list.dropped, 1);
        recorder.clear();
        let list = recorder.list(&|_| true);
        assert!(list.lines.is_empty() && list.dropped == 0);
    }
}
