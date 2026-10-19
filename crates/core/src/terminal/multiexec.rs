//! SS-10 MultiExec: type once into several open terminals, as in MobaXterm, without skipping the
//! approval rules (CLAUDE.md architecture rules 1, 2 and 4).
//!
//! * The UI turns MultiExec on with the terminals that receive input ([`MultiExec::set_targets`]).
//!   Keys typed into one of them come here ([`MultiExec::input`]) and go to each; every terminal shows
//!   its own output. Keys typed into a terminal that is not a target go to it alone, as usual.
//! * A line buffer follows what is typed: printable characters, Backspace, Ctrl+W and Ctrl+U; Ctrl+C
//!   clears it. Keys it can't follow (Tab completion, arrow keys and other escape sequences, Ctrl+R and
//!   the other control keys) make the line "unreliable", and so does text that was on a terminal's line
//!   before MultiExec saw it.
//! * Enter is held. The line goes to the command bus as [`Command::TerminalLine`], which the policy
//!   engine rates like a bulk run's command: read-only, other or dangerous, a Prod target raises it,
//!   and an unreliable line is at least "other", never Low. Low: the job runner sends Enter at once.
//!   Higher: the approval dialog shows the line and the terminals; Enter goes once it is approved
//!   ([`MultiExec::approve`]). Cancelling ([`MultiExec::cancel`], or cancelling the job's countdown)
//!   sends Ctrl+C to every terminal instead, which clears the line. Keys typed meanwhile wait, and
//!   follow the Enter in order (or are dropped with it).
//! * A paste of several lines without bracketed paste is rated as one script and sent as a whole.
//!   With bracketed paste the shell waits for Enter anyway, and the whole paste is the line.
//! * Every line that is sent is audited by the bus and the job runner: the command, the terminals and
//!   their sessions, the tier, and the approval. Never the output. An empty line (Enter alone) is sent
//!   at once and not audited: it runs nothing.
//! * Two cases pass keys straight through, unrated and never logged or audited:
//!   - a password prompt: when a line starts while the terminal typed into shows a password or
//!     passphrase prompt, its keys and its Enter go only to the targets that show one too. So a
//!     password never lands in a shell, and a command never at a password prompt.
//!   - a full-screen program (xterm's alternate screen buffer: vim, less, top): keys go only to the
//!     targets that have one open too. What is typed there (vim's `:!command`) is not rated.
//! * A target is left out of a line when it is not connected, its session is protected (AP-04), its
//!   screen is in another state than the terminal typed into, or it was added while the line was
//!   being typed (it joins at the next line).

use std::collections::HashSet;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;

use super::Terminals;
use crate::command_bus::{ApprovalAnswers, ApprovalRequest, Command, CommandBus, SubmitOutcome};
use crate::domain::{Context, TargetRef};
use crate::error::{CoreError, Result};
use crate::jobs::{JobRunner, JobStatus};
use crate::policy::Tier;
use crate::presentation::Change;

/// Keys that wait for a held line's Enter, at most. More are dropped (and the UI is told).
pub const MAX_QUEUED_BYTES: usize = 64 * 1024;

const CTRL_C: u8 = 0x03;

// ---- The line buffer -------------------------------------------------------------------------------

/// Where the buffer is in an escape sequence the keyboard sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Escape {
    #[default]
    None,
    Started,
    Csi,
    Ss3,
}

/// What a byte did to the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Part of the line (or a key that edits it).
    Key,
    /// Enter, outside a bracketed paste: the shell runs the line.
    Enter,
    /// Ctrl+C: the shell drops the line.
    Interrupt,
}

/// The line being typed, as far as the keys show it (see the module comment).
#[derive(Debug, Default)]
pub(crate) struct LineBuffer {
    text: String,
    unreliable: bool,
    escape: Escape,
    csi: String,
    /// Inside a bracketed paste (`CSI 200 ~` to `CSI 201 ~`): Enter is part of the text.
    paste: bool,
    /// Bytes of a character not complete yet.
    partial: Vec<u8>,
}

impl LineBuffer {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn unreliable(&self) -> bool {
        self.unreliable
    }

    pub(crate) fn mark_unreliable(&mut self) {
        self.unreliable = true;
    }

    /// Nothing typed since the line started.
    pub(crate) fn is_empty(&self) -> bool {
        self.text.is_empty() && !self.unreliable && !self.paste
    }

    pub(crate) fn clear(&mut self) {
        *self = LineBuffer::default();
    }

    pub(crate) fn feed(&mut self, byte: u8) -> Step {
        match self.escape {
            Escape::Started => {
                self.escape = match byte {
                    b'[' => {
                        self.csi.clear();
                        Escape::Csi
                    }
                    b'O' => Escape::Ss3,
                    // Alt+key: readline moves or edits (Alt+B, Alt+.), which can't be followed.
                    0x1b => {
                        self.unreliable = true;
                        Escape::Started
                    }
                    _ => {
                        self.unreliable = true;
                        Escape::None
                    }
                };
                return Step::Key;
            }
            Escape::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::None;
                    match (self.csi.as_str(), byte) {
                        ("200", b'~') => self.paste = true,
                        ("201", b'~') => self.paste = false,
                        // Focus in and out: the terminal reports it, the line is untouched.
                        ("", b'I' | b'O') => {}
                        // Arrows, Home, End, Delete, Page Up...: the cursor moved or history changed.
                        _ => self.unreliable = true,
                    }
                } else if self.csi.len() < 16 {
                    self.csi.push(char::from(byte));
                }
                return Step::Key;
            }
            Escape::Ss3 => {
                // Arrows and F1-F4 in application mode.
                self.escape = Escape::None;
                self.unreliable = true;
                return Step::Key;
            }
            Escape::None => {}
        }
        if byte >= 0x80 {
            self.partial.push(byte);
            match std::str::from_utf8(&self.partial) {
                Ok(text) => {
                    self.text.push_str(text);
                    self.partial.clear();
                }
                Err(err) if err.error_len().is_some() || self.partial.len() >= 4 => self.partial.clear(),
                Err(_) => {}
            }
            return Step::Key;
        }
        self.partial.clear();
        if self.paste {
            // The shell inserts a bracketed paste as it is, line breaks too, until Enter after it.
            match byte {
                0x1b => self.escape = Escape::Started,
                b'\r' | b'\n' => self.text.push('\n'),
                b'\t' => self.text.push(' '),
                b' '..=b'~' => self.text.push(char::from(byte)),
                // How a shell takes other control characters in a paste is up to it.
                _ => self.unreliable = true,
            }
            return Step::Key;
        }
        match byte {
            0x1b => self.escape = Escape::Started,
            b'\r' | b'\n' => return Step::Enter,
            CTRL_C => {
                // The shell drops the line, whatever it held.
                self.clear();
                return Step::Interrupt;
            }
            // Backspace (DEL or ^H).
            0x7f | 0x08 => {
                self.text.pop();
            }
            // Ctrl+U: the line goes (from the cursor back, which is the end unless it moved).
            0x15 => self.text.clear(),
            // Ctrl+W: the word before the cursor goes.
            0x17 => {
                let kept = self.text.trim_end().len();
                self.text.truncate(kept);
                let start = self.text.rfind(char::is_whitespace).map_or(0, |i| i + 1);
                self.text.truncate(start);
            }
            // Ctrl+L clears the screen, Ctrl+D at the end of the line deletes nothing: harmless.
            0x0c | 0x04 => {}
            b' '..=b'~' => self.text.push(char::from(byte)),
            // Tab (completion), Ctrl+R (history search), Ctrl+A/E (cursor), Ctrl+P/N (history),
            // Ctrl+Y (yank), Ctrl+K, Ctrl+T, Ctrl+V, Ctrl+_ ...
            _ => self.unreliable = true,
        }
        Step::Key
    }
}

// ---- What the UI sees ------------------------------------------------------------------------------

/// How a line's keys are handled, from the screen of the terminal typed into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LineMode {
    /// A shell (or a program reading lines): Enter is held and the line rated.
    Command,
    /// A password or passphrase prompt: keys pass straight through, unrated and unlogged.
    Password,
    /// A full-screen program: keys pass straight through.
    FullScreen,
}

/// A target that did not get a line's keys, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeftOut {
    pub terminal_id: Uuid,
    pub reason: String,
}

/// What happened to keys sent to [`MultiExec::input`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum InputOutcome {
    /// The keys went to `reached`.
    Typed {
        mode: LineMode,
        reached: Vec<Uuid>,
        left_out: Vec<LeftOut>,
    },
    /// The terminal typed into is not a MultiExec target (or can't be one now): the keys went to it
    /// alone, as typing normally does.
    Alone { reason: String },
    /// Enter is held while the line is rated. Low: `job_id` sends it. Higher: answer `request` with
    /// [`MultiExec::approve`] or [`MultiExec::cancel`].
    Held {
        line_id: Uuid,
        tier: Tier,
        reached: Vec<Uuid>,
        left_out: Vec<LeftOut>,
        job_id: Option<Uuid>,
        request: Option<Box<ApprovalRequest>>,
    },
    /// A line waits for its Enter; these keys follow it once it is sent.
    Queued { line_id: Uuid, dropped: bool },
}

/// Sent as lines finish, and for lines held while earlier keys were replayed.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum MultiExecEvent {
    /// A held line ended: Enter went out (`sent`), or the line was cancelled and Ctrl+C went out.
    LineDone {
        line_id: Uuid,
        sent: bool,
        terminals: usize,
        status: Option<JobStatus>,
    },
    /// Keys that waited for a line were sent, and held another line (which may need approval).
    Outcome { outcome: InputOutcome },
}

/// One target as MultiExec sees it now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetState {
    pub terminal_id: Uuid,
    pub name: String,
    /// Gets what is typed now.
    pub receives: bool,
    /// Why not, when it does not.
    pub reason: Option<String>,
    /// How it gets keys when they pass straight through: at a password prompt, or to a full-screen
    /// program.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiExecStatus {
    pub on: bool,
    pub targets: Vec<TargetState>,
    /// The line waiting for its Enter, if any.
    pub held: Option<Uuid>,
}

// ---- The service -----------------------------------------------------------------------------------

/// The line being typed: where its keys go and how they are handled.
#[derive(Debug, Clone)]
struct Current {
    mode: LineMode,
    to: Vec<Uuid>,
    left_out: Vec<LeftOut>,
}

/// A line whose Enter waits.
struct Held {
    id: Uuid,
    /// The terminal typed into: the keys that wait are its own.
    from: Uuid,
    to: Vec<Uuid>,
    /// What came after the line's keys in the same input, sent once it is.
    after: Vec<u8>,
    request: Option<Uuid>,
    job: Option<Uuid>,
}

#[derive(Default)]
struct State {
    on: bool,
    targets: Vec<Uuid>,
    buffer: LineBuffer,
    current: Option<Current>,
    held: Option<Held>,
    queued: Vec<u8>,
}

struct Shared {
    ctx: Context,
    terminals: Terminals,
    bus: Arc<CommandBus>,
    jobs: Arc<JobRunner>,
    state: Mutex<State>,
    events: broadcast::Sender<MultiExecEvent>,
}

/// SS-10 (see the module comment). One per app: the Terminal page is the only place to type.
#[derive(Clone)]
pub struct MultiExec {
    shared: Arc<Shared>,
}

/// What a target's screen and session say about a line starting now.
#[derive(Clone)]
struct Seen {
    id: Uuid,
    name: String,
    connected: bool,
    protected: bool,
    password: bool,
    alternate: bool,
    dirty: bool,
}

impl MultiExec {
    pub fn new(ctx: Context, terminals: Terminals, bus: Arc<CommandBus>, jobs: Arc<JobRunner>) -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            shared: Arc::new(Shared {
                ctx,
                terminals,
                bus,
                jobs,
                state: Mutex::new(State::default()),
                events,
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MultiExecEvent> {
        self.shared.events.subscribe()
    }

    /// Turns MultiExec on for these terminals, or changes them. A line being typed keeps going to the
    /// targets it started with that are still picked; ones picked meanwhile join at the next line.
    pub async fn set_targets(&self, targets: Vec<Uuid>) -> Result<MultiExecStatus> {
        self.shared.bus.read_only().check(Change::MultiExec)?;
        let mut seen = HashSet::new();
        let targets: Vec<Uuid> = targets.into_iter().filter(|id| seen.insert(*id)).collect();
        let mut state = self.shared.state.lock().await;
        state.on = true;
        if let Some(current) = &mut state.current {
            let dropped: Vec<Uuid> = current.to.iter().filter(|id| !targets.contains(id)).copied().collect();
            current.to.retain(|id| targets.contains(id));
            // Part of a line is on their screens now, which MultiExec no longer follows there.
            if current.mode == LineMode::Command {
                for id in dropped {
                    self.shared.terminals.set_dirty(id, true);
                }
            }
        }
        state.targets = targets;
        self.status_of(&state).await
    }

    /// Turns MultiExec off. A line waiting for approval is cancelled (Ctrl+C to its terminals); one
    /// already approved goes ahead.
    pub async fn stop(&self) -> Result<MultiExecStatus> {
        let mut state = self.shared.state.lock().await;
        if let Some(held) = state.held.take() {
            match held.job {
                // In its countdown, cancelling it still stops it; the line then gets Ctrl+C.
                Some(job) => {
                    if self.shared.jobs.cancel(job) {
                        self.interrupt(&held.to).await;
                    }
                }
                None => {
                    if let Some(request) = held.request {
                        self.shared.bus.cancel_approval(request).await?;
                    }
                    self.interrupt(&held.to).await;
                }
            }
            self.done(held.id, false, held.to.len(), None);
        }
        if let Some(current) = state.current.take() {
            if current.mode == LineMode::Command && !state.buffer.is_empty() {
                for id in current.to {
                    self.shared.terminals.set_dirty(id, true);
                }
            }
        }
        *state = State::default();
        self.status_of(&state).await
    }

    pub async fn status(&self) -> Result<MultiExecStatus> {
        let state = self.shared.state.lock().await;
        self.status_of(&state).await
    }

    async fn status_of(&self, state: &State) -> Result<MultiExecStatus> {
        let mut targets = Vec::with_capacity(state.targets.len());
        for id in &state.targets {
            let seen = self.seen(*id).await;
            let reason = match &seen {
                None => Some("closed".to_owned()),
                Some(s) if s.protected => Some("protected: MultiExec leaves it out (AP-04)".to_owned()),
                Some(s) if !s.connected => Some("not connected".to_owned()),
                Some(_) => None,
            };
            let note = match &seen {
                Some(s) if reason.is_none() && s.alternate => {
                    Some("a full-screen program is open: keys pass straight through".to_owned())
                }
                Some(s) if reason.is_none() && s.password => {
                    Some("at a password prompt: keys pass straight through, never logged".to_owned())
                }
                _ => None,
            };
            targets.push(TargetState {
                terminal_id: *id,
                name: seen.map(|s| s.name).unwrap_or_else(|| "a closed terminal".into()),
                receives: reason.is_none(),
                reason,
                note,
            });
        }
        Ok(MultiExecStatus {
            on: state.on,
            targets,
            held: state.held.as_ref().map(|h| h.id),
        })
    }

    /// Keys typed into terminal `from` (raw bytes, as xterm.js sends them).
    pub async fn input(&self, from: Uuid, data: Vec<u8>) -> Result<InputOutcome> {
        let mut state = self.shared.state.lock().await;
        if let Some(held) = &state.held {
            if state.targets.contains(&from) || held.from == from {
                let line_id = held.id;
                let room = MAX_QUEUED_BYTES.saturating_sub(state.queued.len());
                let dropped = data.len() > room;
                state.queued.extend_from_slice(&data[..data.len().min(room)]);
                return Ok(InputOutcome::Queued { line_id, dropped });
            }
        }
        let outcome = self.process(&mut state, from, data).await?;
        Ok(outcome)
    }

    /// Answers the approval of a held line; once the job sends Enter, keys that waited follow.
    pub async fn approve(&self, line_id: Uuid, answers: ApprovalAnswers) -> Result<Uuid> {
        let mut state = self.shared.state.lock().await;
        let held = state
            .held
            .as_mut()
            .filter(|h| h.id == line_id)
            .ok_or_else(|| CoreError::InvalidInput("That MultiExec line is no longer waiting.".into()))?;
        let (Some(request), None) = (held.request, held.job) else {
            return Err(CoreError::InvalidInput(
                "That MultiExec line does not wait for an approval.".into(),
            ));
        };
        let job = self.shared.bus.approve(request, answers).await?;
        held.job = Some(job);
        self.wait_for(line_id, job);
        Ok(job)
    }

    /// Cancels a held line: its approval, or its job's countdown. Every terminal it went to gets
    /// Ctrl+C, which clears the line; keys typed after it are dropped.
    pub async fn cancel(&self, line_id: Uuid) -> Result<()> {
        let mut state = self.shared.state.lock().await;
        let Some(held) = state.held.as_ref().filter(|h| h.id == line_id) else {
            return Ok(());
        };
        if let Some(job) = held.job {
            // The job's end lets the line go (with Ctrl+C if it was cancelled in time).
            self.shared.jobs.cancel(job);
            return Ok(());
        }
        let request = held.request;
        if let Some(request) = request {
            self.shared.bus.cancel_approval(request).await?;
        }
        if let Some(held) = state.held.take() {
            state.queued.clear();
            self.interrupt(&held.to).await;
            self.done(held.id, false, held.to.len(), None);
        }
        Ok(())
    }

    fn done(&self, line_id: Uuid, sent: bool, terminals: usize, status: Option<JobStatus>) {
        let _ = self.shared.events.send(MultiExecEvent::LineDone {
            line_id,
            sent,
            terminals,
            status,
        });
    }

    /// Ctrl+C to each terminal: the line it holds goes.
    async fn interrupt(&self, to: &[Uuid]) {
        for id in to {
            let _ = self.shared.terminals.send_keys(*id, &[CTRL_C]).await;
            self.shared.terminals.set_dirty(*id, false);
        }
    }

    /// Lets the line go once its job has ended (in the background).
    fn wait_for(&self, line_id: Uuid, job: Uuid) {
        let this = self.clone();
        tokio::spawn(async move {
            let status = this.shared.jobs.wait(job).await.unwrap_or(JobStatus::Failed);
            if let Err(err) = this.release(line_id, status).await {
                tracing::warn!(error = %err, "MultiExec could not send the keys that waited for a line");
            }
        });
    }

    /// The held line's job ended: Enter went out, or (cancelled) it did not and Ctrl+C clears the line.
    async fn release(&self, line_id: Uuid, status: JobStatus) -> Result<()> {
        let mut state = self.shared.state.lock().await;
        if state.held.as_ref().map(|h| h.id) != Some(line_id) {
            return Ok(());
        }
        let Some(held) = state.held.take() else {
            return Ok(());
        };
        let queued = std::mem::take(&mut state.queued);
        if status == JobStatus::Cancelled {
            self.interrupt(&held.to).await;
            self.done(held.id, false, held.to.len(), Some(status));
            return Ok(());
        }
        for id in &held.to {
            self.shared.terminals.set_dirty(*id, false);
        }
        self.done(held.id, true, held.to.len(), Some(status));
        let mut rest = held.after;
        rest.extend_from_slice(&queued);
        if !rest.is_empty() && state.on {
            let outcome = self.process(&mut state, held.from, rest).await?;
            if matches!(outcome, InputOutcome::Held { .. }) {
                let _ = self.shared.events.send(MultiExecEvent::Outcome { outcome });
            }
        }
        Ok(())
    }

    /// What a terminal's screen and session say now; `None` once it has closed.
    async fn seen(&self, id: Uuid) -> Option<Seen> {
        let info = self.shared.terminals.pane_info(id)?;
        let target = self.shared.terminals.target(&self.shared.ctx, id).await.ok();
        Some(Seen {
            id,
            name: target.as_ref().map_or_else(|| info.name.clone(), |t| t.name.clone()),
            connected: info.screen.connected,
            protected: target.is_some_and(|t| t.protected),
            password: info.screen.at_password_prompt(),
            alternate: info.screen.alternate,
            dirty: info.dirty,
        })
    }

    /// A line starts in `from`: how its keys are handled, and which targets get them.
    async fn start_line(&self, state: &mut State, from: &Seen) -> Current {
        let mode = if from.alternate {
            LineMode::FullScreen
        } else if from.password {
            LineMode::Password
        } else {
            LineMode::Command
        };
        let mut to = Vec::new();
        let mut left_out = Vec::new();
        let mut dirty = false;
        for id in state.targets.clone() {
            let seen = if id == from.id {
                Some(from.clone())
            } else {
                self.seen(id).await
            };
            let Some(seen) = seen else {
                continue;
            };
            let reason = if seen.protected {
                Some("protected (AP-04)")
            } else if !seen.connected {
                Some("not connected")
            } else {
                match mode {
                    LineMode::FullScreen if !seen.alternate => Some("no full-screen program is open"),
                    LineMode::Password if seen.alternate || !seen.password => Some("not at a password prompt"),
                    LineMode::Command if seen.alternate => Some("a full-screen program is open"),
                    LineMode::Command if seen.password => Some("at a password prompt"),
                    _ => None,
                }
            };
            match reason {
                Some(reason) => left_out.push(LeftOut {
                    terminal_id: id,
                    reason: reason.into(),
                }),
                None => {
                    dirty |= seen.dirty;
                    to.push(id);
                }
            }
        }
        state.buffer.clear();
        if mode == LineMode::Command && dirty {
            // Text was typed on some line outside MultiExec: what the shells hold is not known.
            state.buffer.mark_unreliable();
        }
        Current { mode, to, left_out }
    }

    async fn send(&self, to: &[Uuid], bytes: &[u8], left_out: &mut Vec<LeftOut>) -> Vec<Uuid> {
        let mut reached = Vec::with_capacity(to.len());
        if bytes.is_empty() {
            return to.to_vec();
        }
        for id in to {
            match self.shared.terminals.send_keys(*id, bytes).await {
                Ok(()) => reached.push(*id),
                Err(_) => {
                    if !left_out.iter().any(|l| l.terminal_id == *id) {
                        left_out.push(LeftOut {
                            terminal_id: *id,
                            reason: "not connected".into(),
                        });
                    }
                }
            }
        }
        reached
    }

    /// Handles keys from `from` until they end or a line is held.
    async fn process(&self, state: &mut State, from: Uuid, data: Vec<u8>) -> Result<InputOutcome> {
        let from_seen = self.seen(from).await;
        let alone = match &from_seen {
            _ if !state.on => Some("MultiExec is off"),
            _ if !state.targets.contains(&from) => Some("this terminal is not picked for MultiExec"),
            None => Some("this terminal has closed"),
            Some(s) if s.protected => Some("this terminal's session is protected, so MultiExec leaves it out"),
            Some(s) if !s.connected => Some("this terminal is not connected"),
            Some(_) => None,
        };
        let Some(from_seen) = from_seen.filter(|_| alone.is_none()) else {
            self.shared.terminals.write(from, data).await;
            return Ok(InputOutcome::Alone {
                reason: alone.unwrap_or_default().to_owned(),
            });
        };

        let mut at = 0;
        let mut last = InputOutcome::Typed {
            mode: LineMode::Command,
            reached: Vec::new(),
            left_out: Vec::new(),
        };
        while at < data.len() {
            if state.current.is_none() {
                // A new line: the screen as it is now decides.
                let seen = match at {
                    0 => from_seen.clone(),
                    _ => self.seen(from).await.unwrap_or_else(|| from_seen.clone()),
                };
                let current = self.start_line(state, &seen).await;
                state.current = Some(current);
            }
            let Some(current) = state.current.clone() else {
                break;
            };
            match current.mode {
                LineMode::FullScreen => {
                    // A full-screen program reads keys, not lines: all of them, straight through.
                    let mut left_out = current.left_out.clone();
                    let reached = self.send(&current.to, &data[at..], &mut left_out).await;
                    state.current = None;
                    return Ok(InputOutcome::Typed {
                        mode: LineMode::FullScreen,
                        reached,
                        left_out,
                    });
                }
                LineMode::Password => {
                    // Straight through up to and with Enter (or Ctrl+C), never kept.
                    let end = data[at..]
                        .iter()
                        .position(|b| matches!(*b, b'\r' | b'\n' | CTRL_C))
                        .map(|i| at + i + 1);
                    let stop = end.unwrap_or(data.len());
                    let mut left_out = current.left_out.clone();
                    let reached = self.send(&current.to, &data[at..stop], &mut left_out).await;
                    if end.is_some() {
                        state.current = None;
                    }
                    at = stop;
                    last = InputOutcome::Typed {
                        mode: LineMode::Password,
                        reached,
                        left_out,
                    };
                }
                LineMode::Command => {
                    let start = at;
                    let mut enter = None;
                    while at < data.len() {
                        let byte = data[at];
                        at += 1;
                        match state.buffer.feed(byte) {
                            Step::Key => {}
                            Step::Interrupt => {
                                // The shells drop the line; the next keys start a new one.
                                break;
                            }
                            Step::Enter => {
                                enter = Some(at - 1);
                                break;
                            }
                        }
                    }
                    let mut left_out = current.left_out.clone();
                    let typed_end = enter.unwrap_or(at);
                    let reached = self.send(&current.to, &data[start..typed_end], &mut left_out).await;
                    if enter.is_none() {
                        if typed_end > start && data[typed_end - 1] == CTRL_C {
                            state.current = None;
                            state.buffer.clear();
                            for id in &current.to {
                                self.shared.terminals.set_dirty(*id, false);
                            }
                        }
                        last = InputOutcome::Typed {
                            mode: LineMode::Command,
                            reached,
                            left_out,
                        };
                        continue;
                    }
                    let Some(enter) = enter else { continue };
                    return self.enter(state, from, &current, &data, enter, reached, left_out).await;
                }
            }
        }
        Ok(last)
    }

    /// Enter at `data[enter]`: the line (with any further lines of the same paste) is rated, and Enter
    /// is held unless the line is empty.
    #[allow(clippy::too_many_arguments)]
    async fn enter(
        &self,
        state: &mut State,
        from: Uuid,
        current: &Current,
        data: &[u8],
        enter: usize,
        reached: Vec<Uuid>,
        left_out: Vec<LeftOut>,
    ) -> Result<InputOutcome> {
        // A paste of several lines is one script: its later lines go with the first one's Enter.
        let mut lines = vec![state.buffer.text().to_owned()];
        let mut unreliable = state.buffer.unreliable();
        let mut scan = LineBuffer::default();
        let mut last_enter = enter;
        for (i, byte) in data.iter().enumerate().skip(enter + 1) {
            match scan.feed(*byte) {
                Step::Enter => {
                    lines.push(scan.text().to_owned());
                    unreliable |= scan.unreliable();
                    scan.clear();
                    last_enter = i;
                }
                Step::Interrupt => {
                    // Ctrl+C after Enter: the shells drop that line, not the one already run.
                    scan.clear();
                }
                Step::Key => {}
            }
        }
        let keys = &data[enter..=last_enter];
        let after = data[last_enter + 1..].to_vec();
        let script = lines.join("\n").trim_end().to_owned();
        state.buffer.clear();
        state.current = None;

        let to = current.to.clone();
        if to.is_empty() {
            return Ok(InputOutcome::Typed {
                mode: LineMode::Command,
                reached,
                left_out,
            });
        }
        if script.trim().is_empty() && !unreliable && keys.iter().all(|b| matches!(*b, b'\r' | b'\n')) {
            // Enter on an empty line runs nothing: no rating, no audit.
            let mut left_out = left_out;
            let reached = self.send(&to, keys, &mut left_out).await;
            if after.is_empty() {
                return Ok(InputOutcome::Typed {
                    mode: LineMode::Command,
                    reached,
                    left_out,
                });
            }
            return Box::pin(self.process(state, from, after)).await;
        }

        let command = Command::TerminalLine {
            targets: to
                .iter()
                .map(|id| TargetRef::Terminal {
                    terminal_id: *id,
                    session_id: None,
                })
                .collect(),
            line: script,
            unreliable,
            keys: String::from_utf8_lossy(keys).into_owned(),
        };
        let line_id = Uuid::new_v4();
        let outcome = match self.shared.bus.submit(&self.shared.ctx, command).await {
            Ok(outcome) => outcome,
            Err(err) => {
                // Nothing will press Enter: clear the line the terminals hold, so it can't run later.
                self.interrupt(&to).await;
                return Err(err);
            }
        };
        let (tier, job_id, request) = match outcome {
            SubmitOutcome::Queued { job_id, tier, .. } => (tier, Some(job_id), None),
            SubmitOutcome::NeedsApproval { request } => (request.tier, None, Some(Box::new(request))),
        };
        state.held = Some(Held {
            id: line_id,
            from,
            to,
            after,
            request: request.as_ref().map(|r| r.id),
            job: job_id,
        });
        if let Some(job) = job_id {
            self.wait_for(line_id, job);
        }
        Ok(InputOutcome::Held {
            line_id,
            tier,
            reached,
            left_out,
            job_id,
            request,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `keys`, returning the line, whether it is unreliable, and the steps that were not keys.
    fn typed(keys: &[u8]) -> (String, bool, Vec<Step>) {
        let mut buffer = LineBuffer::default();
        let steps = keys
            .iter()
            .map(|b| buffer.feed(*b))
            .filter(|s| *s != Step::Key)
            .collect();
        (buffer.text().to_owned(), buffer.unreliable(), steps)
    }

    #[test]
    fn printable_keys_backspace_and_line_editing_are_followed() {
        assert_eq!(typed(b"uptime"), ("uptime".into(), false, vec![]));
        assert_eq!(typed(b"uptimx\x7fe").0, "uptime");
        assert_eq!(typed(b"ls\x08\x08df -h").0, "df -h");
        assert_eq!(typed(b"rm -rf /tmp/x\x15uptime").0, "uptime", "Ctrl+U clears the line");
        assert_eq!(
            typed(b"systemctl restart nginx  \x17status").0,
            "systemctl restart status"
        );
        assert_eq!(typed("echo café".as_bytes()).0, "echo café");
        assert_eq!(typed(b"\x0cuptime").0, "uptime", "Ctrl+L only clears the screen");
        let (text, unreliable, steps) = typed(b"uptime\r");
        assert_eq!((text.as_str(), unreliable), ("uptime", false));
        assert_eq!(steps, [Step::Enter]);
    }

    #[test]
    fn ctrl_c_drops_the_line() {
        let (text, unreliable, steps) = typed(b"rm -rf /\x1b[A\x03");
        assert_eq!(
            (text.as_str(), unreliable),
            ("", false),
            "the shell dropped it, unreliable or not"
        );
        assert_eq!(steps, [Step::Interrupt]);
    }

    #[test]
    fn keys_that_cannot_be_followed_make_the_line_unreliable() {
        for keys in [
            &b"syst\tstatus"[..], // Tab completion
            b"\x1b[A",            // Up: history
            b"ls\x1b[D\x1b[Drm ", // Left arrows, then typing mid-line
            b"\x12restart",       // Ctrl+R
            b"ls\x01rm ",         // Ctrl+A, then typing at the start
            b"\x10",              // Ctrl+P: history
            b"\x1bOA",            // Up in application mode
            b"echo \x1b.",        // Alt+.: the last argument
            b"ls \x19",           // Ctrl+Y: yank
            b"\x1b[3~",           // Delete
        ] {
            assert!(typed(keys).1, "{keys:?}");
        }
        assert!(!typed(b"\x1b[I\x1b[Ouptime").1, "focus reports change nothing");
    }

    #[test]
    fn a_bracketed_paste_is_text_even_with_line_breaks() {
        let (text, unreliable, steps) = typed(b"\x1b[200~cd /srv\rmake\tall\x1b[201~\r");
        assert_eq!(text, "cd /srv\nmake all");
        assert!(!unreliable);
        assert_eq!(steps, [Step::Enter], "only the Enter after the paste");
        // Ctrl+C inside a paste is not the key: the shell may keep the text before it.
        let (text, unreliable, steps) = typed(b"\x1b[200~rm -rf /srv\x03ls\x1b[201~");
        assert_eq!(text, "rm -rf /srvls");
        assert!(unreliable);
        assert!(steps.is_empty());
    }

    #[test]
    fn split_characters_are_joined() {
        let mut buffer = LineBuffer::default();
        for b in "é".as_bytes() {
            buffer.feed(*b);
        }
        assert_eq!(buffer.text(), "é");
        let mut bad = LineBuffer::default();
        bad.feed(0xff);
        bad.feed(b'x');
        assert_eq!(bad.text(), "x");
    }
}
