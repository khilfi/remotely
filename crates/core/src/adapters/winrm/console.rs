//! SS-12: the PowerShell console of a WinRM session, as a terminal pane's channels ([`ShellInput`], [`ShellOutput`]).
//!
//! The host runs `powershell.exe -NoLogo -NoProfile -Command -` (through `cmd.exe /c ... 2>&1`, so errors and output
//! arrive in the order PowerShell wrote them) in a WinRS shell, reading statements from its stdin. There is no
//! console on the host, so Remotely does here what a console would:
//!
//! * **Line editing**: what is typed is shown here (nothing at a password prompt, and never a vault secret), with
//!   Backspace, Ctrl+U, and Up and Down through this pane's history. Enter sends the line as it was typed. There is
//!   no tab completion or PSReadLine.
//! * **The prompt**: each statement goes as one line ([`statement_line`]): the lines as typed, quoted, made a script
//!   block by PowerShell's own parser and run in the console's scope, then an expression that prints an OSC 7790
//!   sequence with a nonce and the current folder. The console hides it and draws `PS <folder>> `, so the next prompt
//!   shows once the statement's output is done. On one line, the marker can't be read by `Read-Host` as its input,
//!   and a statement that doesn't parse or stops with an error still brings the prompt back (checked by hand against
//!   Windows PowerShell 5.1). A statement left open (`{`, a string, a here-string, a trailing backtick or pipe) gets
//!   `>> ` and goes once it closes.
//! * **While a statement runs**, a line typed goes to its stdin as it is (`Read-Host`), shown as `*`: PowerShell shows
//!   no `Read-Host` prompt while its stdin is a pipe, so a password it asks for can't be told apart. Ctrl+C sends
//!   WinRM's ctrl_c signal, then a marker. Enter on an empty line asks for a fresh prompt.
//! * The statement's state lives in that one PowerShell: a new connection starts a new one (the pane says so).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use uuid::Uuid;

use super::shell::{DeleteOnDrop, RemoteShell, MIN_EMPTY_GAP, POWERSHELL, RECEIVE_WAIT};
use super::soap::{self, Received};
use crate::adapters::remote::{SecretPromptShown, ShellEnd, ShellInput, ShellOutput};
use crate::error::{CoreError, Result};

/// Lines kept for Up and Down.
const HISTORY: usize = 200;
/// A line longer than this is not taken (PowerShell reads lines; a paste of a whole file belongs in a script).
pub const MAX_LINE: usize = 32 * 1024;
/// Bytes held while a sequence that may be the prompt marker is incomplete.
const MAX_HELD: usize = 4096;
/// Pasted lines kept while a statement runs; more are left out, and the pane says so.
const MAX_QUEUED: usize = 500;
/// The OSC number of the prompt marker.
const MARKER: &[u8] = b"\x1b]7790;";

/// The two ends of a console.
pub struct ConsoleShell {
    pub input: mpsc::Sender<ShellInput>,
    pub output: mpsc::Receiver<ShellOutput>,
    /// BX-13: where the console is now, for Type in all tabs.
    pub status: Arc<ConsoleStatus>,
}

/// BX-13: what Type in all tabs needs to know of a console: whether it is at its prompt (a line typed is a statement)
/// or a statement runs (a line typed is that statement's input, `Read-Host`), the lines of a statement left open it
/// holds (`>> `), and the line being typed now. Published by the [`Editor`] after every key and every output, so Type
/// in all tabs reads what the console really holds, not a guess from the keys or the screen: before it lets a line run,
/// it checks each console holds exactly the line and open statement it followed, and refuses otherwise (a recalled
/// history line, keys dropped while a statement ran, a desync).
#[derive(Debug, Default)]
pub struct ConsoleStatus {
    inner: std::sync::Mutex<ConsoleView>,
}

/// BX-13: a console's status at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsoleView {
    /// At the prompt (or the `>> ` of a statement left open): a line typed is a statement.
    pub at_prompt: bool,
    /// Lines of a statement left open, sent together once it closes.
    pub open: Vec<String>,
    /// The line being typed now (at the prompt): empty once it is sent.
    pub line: String,
}

impl ConsoleView {
    pub fn open_lines(&self) -> usize {
        self.open.len()
    }
}

impl ConsoleStatus {
    pub fn view(&self) -> ConsoleView {
        self.inner.lock().map(|v| v.clone()).unwrap_or_default()
    }

    fn publish(&self, state: State, open: &[String], line: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.at_prompt = state == State::Idle;
            inner.open = open.to_vec();
            inner.line.clear();
            inner.line.push_str(line);
        }
    }
}

/// BX-13: whether the console sends a statement once its last line is in: an empty line at the prompt (a fresh
/// prompt, nothing runs), a statement that closes, or an empty line ending one left open. The console's [`Editor`]
/// and Type in all tabs ([`statements`]) decide it here, so they never differ.
pub fn statement_ends(open: &[String], syntax: &Syntax, empty_alone: bool) -> bool {
    empty_alone || syntax.complete() || open.last().is_some_and(|l| l.trim().is_empty())
}

/// BX-13: what the console does with `lines` typed at its prompt, one Enter each, with `open` the lines of a statement
/// it holds already: the statements it sends, in order, each its lines, and the lines it still holds after them. An
/// empty line at the prompt sends no statement.
pub fn statements(open: &[String], lines: &[String]) -> (Vec<Vec<String>>, Vec<String>) {
    let all: Vec<&str> = open.iter().chain(lines).map(String::as_str).collect();
    let (sent, held_from) = statement_ranges(open.len(), &all);
    let take = |range: std::ops::Range<usize>| all[range].iter().map(|l| (*l).to_owned()).collect::<Vec<_>>();
    let sent = sent.into_iter().map(take).collect();
    (sent, take(held_from..all.len()))
}

/// BX-13: the same as line numbers: of `all` (a statement's first `open` lines held already, then the lines typed),
/// the ranges the console sends as statements, and where the lines it still holds start. `-Command -` reads a
/// script's lines the same way, which the PowerShell rules rate it by.
pub fn statement_ranges(open: usize, all: &[&str]) -> (Vec<std::ops::Range<usize>>, usize) {
    let mut held: Vec<String> = Vec::new();
    let mut start = 0;
    let mut syntax = Syntax::default();
    let mut sent = Vec::new();
    for (i, line) in all.iter().enumerate() {
        if held.is_empty() {
            start = i;
        }
        syntax.feed(line);
        held.push((*line).to_owned());
        if i < open {
            // The lines held already: still open.
            continue;
        }
        let empty_alone = line.trim().is_empty() && held.len() == 1;
        if !statement_ends(&held, &syntax, empty_alone) {
            continue;
        }
        held.clear();
        syntax = Syntax::default();
        if !empty_alone {
            sent.push(start..i + 1);
        }
    }
    let held_from = if held.is_empty() { all.len() } else { start };
    (sent, held_from)
}

/// The expression that prints the prompt marker: a string written through PowerShell's own output, so it comes after
/// everything the statement before it printed.
fn marker(nonce: &str) -> String {
    format!("\"$([char]27)]7790;{nonce};$((Get-Location).Path)$([char]7)\"")
}

/// The marker alone, as a line (the first prompt, and Enter on an empty line).
pub fn marker_line(nonce: &str) -> String {
    format!("{}\r\n", marker(nonce))
}

/// `text` as a PowerShell single-quoted string: `'` and the quotes PowerShell reads like it (U+2018 to U+201B) doubled,
/// so nothing in it can end the string.
pub fn single_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// One statement as Remotely sends it: the lines as typed, made one script block by PowerShell's own parser and run in
/// the console's scope (so variables and functions stay), then the prompt marker, all on one line. A statement that
/// doesn't parse, or stops with an error, prints PowerShell's message and the prompt still comes. Nothing typed is ever
/// reformatted: each line goes in whole as a quoted string.
pub fn statement_line(lines: &[String], nonce: &str) -> String {
    let parts: Vec<String> = lines.iter().map(|l| single_quoted(l)).collect();
    format!(
        "try {{ . ([scriptblock]::Create({})) }} catch {{ [Console]::Error.WriteLine($(if ($_.Exception.InnerException) \
{{ $_.Exception.InnerException.Message }} else {{ \"$_\" }})) }}; {}\r\n",
        parts.join(" + \"`n\" + "),
        marker(nonce)
    )
}

/// Starts the console in `shell`. `secret_prompt` says whether the pane shows a password prompt now (what is typed is
/// then not shown).
pub async fn start(
    shell: Arc<RemoteShell>,
    secret_prompt: SecretPromptShown,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<ConsoleShell> {
    // Review F4 #6: the shell goes if the start fails (a reconnect loop would otherwise leave one each try).
    let mut cleanup = DeleteOnDrop(Some(Arc::clone(&shell)));
    let command = shell
        .command(POWERSHELL, "-NoLogo -NoProfile -Command - 2>&1", true)
        .await?;
    let nonce = Uuid::new_v4().simple().to_string();
    // Progress bars mean nothing without a console; then the first prompt.
    let setup = format!("$ProgressPreference = 'SilentlyContinue'\r\n{}", marker_line(&nonce));
    shell.send(&command, setup.as_bytes(), false).await?;
    cleanup.0 = None;
    let (input_tx, input_rx) = mpsc::channel(256);
    let (output_tx, output_rx) = mpsc::channel(256);
    let (received_tx, received_rx) = mpsc::channel(16);
    tokio::spawn(receive_loop(Arc::clone(&shell), command.clone(), received_tx));
    let editor = Editor::new(nonce);
    let status = Arc::clone(&editor.status);
    let console = Console {
        shell,
        command,
        editor,
        output: output_tx,
        secret_prompt,
        _permit: permit,
    };
    tokio::spawn(console.run(input_rx, received_rx));
    Ok(ConsoleShell {
        input: input_tx,
        output: output_rx,
        status,
    })
}

/// Reads the command's output until it ends or the console stops listening.
async fn receive_loop(shell: Arc<RemoteShell>, command: String, to: mpsc::Sender<Result<Received>>) {
    loop {
        let asked = Instant::now();
        let got = shell.receive(&command, RECEIVE_WAIT).await;
        let stop = !matches!(&got, Ok(r) if r.done.is_none());
        let empty = matches!(&got, Ok(r) if r.stdout.is_empty() && r.stderr.is_empty());
        if to.send(got).await.is_err() || stop {
            return;
        }
        if empty {
            let spent = asked.elapsed();
            if spent < MIN_EMPTY_GAP {
                tokio::time::sleep(MIN_EMPTY_GAP - spent).await;
            }
        }
    }
}

struct Console {
    shell: Arc<RemoteShell>,
    command: String,
    editor: Editor,
    output: mpsc::Sender<ShellOutput>,
    secret_prompt: SecretPromptShown,
    /// One of the connection's shells, held while the console runs.
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Console {
    async fn run(mut self, mut input: mpsc::Receiver<ShellInput>, mut received: mpsc::Receiver<Result<Received>>) {
        let end = loop {
            tokio::select! {
                message = input.recv() => match message {
                    None | Some(ShellInput::Close) => break None,
                    Some(ShellInput::Data(bytes)) => {
                        let secret = (self.secret_prompt)();
                        let actions = self.editor.keys(&bytes, secret);
                        if let Err(err) = self.act(actions).await {
                            break Some(ShellEnd::Lost { reason: err.to_string() });
                        }
                    }
                    Some(ShellInput::Secret(bytes)) => {
                        let actions = self.editor.secret(&bytes);
                        if let Err(err) = self.act(actions).await {
                            break Some(ShellEnd::Lost { reason: err.to_string() });
                        }
                    }
                    Some(ShellInput::Resize { .. } | ShellInput::Break) => {}
                },
                got = received.recv() => match got {
                    Some(Ok(got)) => {
                        let mut shown = self.editor.output(&got.stdout);
                        if !got.stderr.is_empty() {
                            shown.extend(self.editor.output(&got.stderr));
                        }
                        if !shown.is_empty() && self.output.send(ShellOutput::Data(shown)).await.is_err() {
                            break None;
                        }
                        if let Some(code) = got.done {
                            break Some(ShellEnd::Exited { status: code.map(|c| c as u32) });
                        }
                        let actions = self.editor.after_prompt();
                        if let Err(err) = self.act(actions).await {
                            break Some(ShellEnd::Lost { reason: err.to_string() });
                        }
                    }
                    Some(Err(err)) => break Some(ShellEnd::Lost { reason: lost_reason(&err) }),
                    None => break Some(ShellEnd::Lost { reason: "the connection was lost".into() }),
                },
            }
        };
        let ended = end.is_some();
        if let Some(end) = end {
            let _ = self.output.send(ShellOutput::Closed(end)).await;
        }
        if !ended {
            let _ = self.shell.signal(&self.command, soap::SIGNAL_TERMINATE).await;
        }
        self.shell.delete().await;
    }

    async fn act(&mut self, actions: Vec<Action>) -> Result<()> {
        for action in actions {
            match action {
                Action::Show(bytes) => {
                    if self.output.send(ShellOutput::Data(bytes)).await.is_err() {
                        return Ok(());
                    }
                }
                Action::Send(text) => self.shell.send(&self.command, text.as_bytes(), false).await?,
                Action::Interrupt => self.shell.signal(&self.command, soap::SIGNAL_CTRL_C).await?,
            }
        }
        Ok(())
    }
}

/// The pane's words for a connection that dropped.
fn lost_reason(err: &CoreError) -> String {
    match err {
        CoreError::Io(_) | CoreError::Timeout { .. } => format!("{err}"),
        other => other.to_string(),
    }
}

/// What a key or an answer makes the console do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Bytes for the pane's screen.
    Show(Vec<u8>),
    /// Text for PowerShell's stdin.
    Send(String),
    /// WinRM's ctrl_c to the running statement.
    Interrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the first prompt.
    Starting,
    /// At a prompt.
    Idle,
    /// A statement was sent; its prompt marker hasn't come.
    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    /// After ESC.
    Start,
    /// After `ESC [` (or `ESC O`): parameters until the final byte.
    Sequence,
}

/// The console's own state: pure, so it is tested without a host.
pub struct Editor {
    nonce: String,
    state: State,
    line: String,
    /// Lines of a statement left open, sent together once it closes.
    open: Vec<String>,
    syntax: Syntax,
    history: VecDeque<String>,
    /// Where Up and Down are in the history (`None`: the line being typed).
    browsing: Option<usize>,
    escape: Escape,
    escape_bytes: Vec<u8>,
    /// UTF-8 bytes of a character split across two reads of the keyboard.
    partial: Vec<u8>,
    /// The last key was CR (an LF after it is the same Enter).
    after_cr: bool,
    /// The line being typed was typed while a statement ran, so it shows as `*` and isn't shown again at the prompt.
    masked: bool,
    /// Pasted lines that came while a statement ran: each goes at the prompt after it, as if typed then.
    queued: VecDeque<String>,
    /// Pasted lines were left out (more than [`MAX_QUEUED`]).
    queue_overflow: bool,
    /// Output held while it may be an incomplete prompt marker.
    held: Vec<u8>,
    /// The CR LF after a marker that PowerShell writes, still to hide.
    swallow: usize,
    at_line_start: bool,
    last_output_cr: bool,
    folder: String,
    /// BX-13: where it is, for Type in all tabs.
    status: Arc<ConsoleStatus>,
}

impl Editor {
    pub fn new(nonce: String) -> Self {
        Self {
            nonce,
            state: State::Starting,
            line: String::new(),
            open: Vec::new(),
            syntax: Syntax::default(),
            history: VecDeque::new(),
            browsing: None,
            escape: Escape::None,
            escape_bytes: Vec::new(),
            partial: Vec::new(),
            after_cr: false,
            masked: false,
            queued: VecDeque::new(),
            queue_overflow: false,
            held: Vec::new(),
            swallow: 0,
            at_line_start: true,
            last_output_cr: false,
            folder: String::new(),
            status: Arc::new(ConsoleStatus::default()),
        }
    }

    /// BX-13: the status Type in all tabs reads.
    pub fn status(&self) -> Arc<ConsoleStatus> {
        Arc::clone(&self.status)
    }

    fn publish(&self) {
        // BX-13: a line typed while a statement runs is its input (masked), not a statement, so Type in all tabs must
        // not read it as the prompt line; only publish the line at the prompt.
        let line = if self.state == State::Idle && !self.masked {
            self.line.as_str()
        } else {
            ""
        };
        self.status.publish(self.state, &self.open, line);
    }

    fn prompt(&self) -> String {
        if self.open.is_empty() {
            format!("PS {}> ", self.folder)
        } else {
            ">> ".to_owned()
        }
    }

    /// A vault secret typed at a prompt (QL-06): taken as typed, never shown, then Enter.
    pub fn secret(&mut self, bytes: &[u8]) -> Vec<Action> {
        self.masked = false;
        let text = String::from_utf8_lossy(bytes);
        let text = text.trim_end_matches(['\r', '\n']);
        let mut out = Vec::new();
        if self.state == State::Running {
            out.push(Action::Show(b"\r\n".to_vec()));
            out.push(Action::Send(format!("{text}\r\n")));
            self.line.clear();
        }
        self.publish();
        out
    }

    /// Keys from the pane. `secret`: the screen shows a password prompt, so nothing typed is shown. While a statement
    /// runs, what is typed (for it) shows as `*`: Windows PowerShell shows no `Read-Host` prompt while its stdin is a
    /// pipe, so a password it asks for can't be told apart.
    pub fn keys(&mut self, bytes: &[u8], secret: bool) -> Vec<Action> {
        let mut out = Vec::new();
        let mut shown = Vec::new();
        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(bytes);
        // Review F4 #9: two lines or more at once are a paste: lines of it that come while a statement runs wait, and
        // go one statement per prompt. A line typed alone while a statement runs is its input (Read-Host).
        let paste = line_endings(&data) >= 2;
        let mut at = 0;
        while at < data.len() {
            let byte = data[at];
            // Escape sequences: Up and Down; the rest are dropped.
            match self.escape {
                Escape::Start => {
                    self.escape = if byte == b'[' || byte == b'O' {
                        Escape::Sequence
                    } else {
                        Escape::None
                    };
                    at += 1;
                    continue;
                }
                Escape::Sequence => {
                    self.escape_bytes.push(byte);
                    if (0x40..=0x7e).contains(&byte) || self.escape_bytes.len() > 16 {
                        self.escape = Escape::None;
                        let sequence = std::mem::take(&mut self.escape_bytes);
                        match sequence.last() {
                            Some(b'A') => self.history_move(true, &mut shown),
                            Some(b'B') => self.history_move(false, &mut shown),
                            _ => {}
                        }
                    }
                    at += 1;
                    continue;
                }
                Escape::None => {}
            }
            let after_cr = std::mem::replace(&mut self.after_cr, false);
            match byte {
                0x1b => self.escape = Escape::Start,
                b'\r' => {
                    self.after_cr = true;
                    self.enter(secret, paste, &mut shown, &mut out);
                }
                b'\n' => {
                    if !after_cr {
                        self.enter(secret, paste, &mut shown, &mut out);
                    }
                }
                0x7f | 0x08 => {
                    if self.line.pop().is_some() && !secret {
                        shown.extend_from_slice(b"\x08 \x08");
                    }
                    if self.line.is_empty() {
                        self.masked = false;
                    }
                }
                0x03 => self.interrupt(&mut shown, &mut out),
                0x15 => {
                    if !secret {
                        for _ in 0..self.line.chars().count() {
                            shown.extend_from_slice(b"\x08 \x08");
                        }
                    }
                    self.line.clear();
                    self.masked = false;
                }
                b'\t' => {}
                b if b < 0x20 => {}
                _ => {
                    // A whole UTF-8 character, or wait for the rest of it. Review B4/R2: the bytes after the lead must
                    // be continuation bytes; if one isn't (a stray byte from a mouse report, a control key), the lead
                    // is invalid, so consume only it — otherwise a control byte (Ctrl+C, Ctrl+U) inside the run would be
                    // swallowed.
                    let len = utf8_len(byte);
                    let have = (data.len() - at).min(len);
                    if data[at + 1..at + have].iter().any(|b| !(0x80..=0xbf).contains(b)) {
                        at += 1;
                        continue;
                    }
                    if at + len > data.len() {
                        self.partial = data[at..].to_vec();
                        break;
                    }
                    if let Ok(text) = std::str::from_utf8(&data[at..at + len]) {
                        if self.line.len() + text.len() <= MAX_LINE {
                            self.line.push_str(text);
                            self.browsing = None;
                            let waiting = paste && self.state != State::Idle;
                            if self.state != State::Idle && !waiting {
                                self.masked = true;
                            }
                            if secret || waiting {
                                // Nothing at a password prompt; a pasted line shows when it goes.
                            } else if self.masked {
                                shown.extend(std::iter::repeat_n(b'*', text.chars().count()));
                            } else {
                                shown.extend_from_slice(text.as_bytes());
                            }
                        }
                    }
                    at += len;
                    continue;
                }
            }
            at += 1;
        }
        if !shown.is_empty() {
            out.push(Action::Show(shown));
        }
        self.publish();
        merge_shows(out)
    }

    fn history_move(&mut self, up: bool, shown: &mut Vec<u8>) {
        if self.state == State::Running || self.history.is_empty() {
            return;
        }
        let next = match (self.browsing, up) {
            (None, true) => Some(self.history.len() - 1),
            (Some(0), true) => Some(0),
            (Some(i), true) => Some(i - 1),
            (Some(i), false) if i + 1 < self.history.len() => Some(i + 1),
            (_, false) => None,
        };
        self.browsing = next;
        self.line = next.and_then(|i| self.history.get(i).cloned()).unwrap_or_default();
        shown.extend_from_slice(format!("\r\x1b[K{}{}", self.prompt(), self.line).as_bytes());
    }

    fn interrupt(&mut self, shown: &mut Vec<u8>, out: &mut Vec<Action>) {
        shown.extend_from_slice(b"^C");
        // Review M2: Ctrl+C drops whatever was typed, running or not — the line, what was typed ahead while a statement
        // ran, and any half-read character or escape — so a later LF can't run a line the user cancelled.
        self.line.clear();
        self.partial.clear();
        self.escape = Escape::None;
        self.escape_bytes.clear();
        self.masked = false;
        self.browsing = None;
        // Pasted lines still waiting go too: Ctrl+C stops the paste with the statement.
        self.queued.clear();
        if self.state == State::Running {
            out.push(Action::Show(std::mem::take(shown)));
            out.push(Action::Interrupt);
            // Ctrl+C stops the statement before its own marker: a marker of its own brings the prompt back.
            out.push(Action::Send(marker_line(&self.nonce)));
            return;
        }
        self.open.clear();
        self.syntax = Syntax::default();
        shown.extend_from_slice(format!("\r\n{}", self.prompt()).as_bytes());
    }

    fn enter(&mut self, secret: bool, paste: bool, shown: &mut Vec<u8>, out: &mut Vec<Action>) {
        if paste && self.state != State::Idle {
            // A pasted line while a statement runs: it goes as a statement of its own at the next prompt.
            let line = std::mem::take(&mut self.line);
            if self.queued.len() < MAX_QUEUED {
                self.queued.push_back(line);
            } else {
                self.queue_overflow = true;
            }
            self.masked = false;
            return;
        }
        shown.extend_from_slice(b"\r\n");
        let line = std::mem::take(&mut self.line);
        self.browsing = None;
        self.masked = false;
        match self.state {
            State::Running | State::Starting => {
                // To the running statement (Read-Host), as typed.
                out.push(Action::Show(std::mem::take(shown)));
                out.push(Action::Send(format!("{line}\r\n")));
            }
            State::Idle => {
                if !secret && !line.trim().is_empty() && self.history.back() != Some(&line) {
                    self.history.push_back(line.clone());
                    if self.history.len() > HISTORY {
                        self.history.pop_front();
                    }
                }
                let empty_alone = line.trim().is_empty() && self.open.is_empty();
                self.syntax.feed(&line);
                self.open.push(line);
                if !statement_ends(&self.open, &self.syntax, empty_alone) {
                    shown.extend_from_slice(b">> ");
                    return;
                }
                let text = if empty_alone {
                    marker_line(&self.nonce)
                } else {
                    statement_line(&self.open, &self.nonce)
                };
                self.open.clear();
                self.syntax = Syntax::default();
                self.state = State::Running;
                out.push(Action::Show(std::mem::take(shown)));
                out.push(Action::Send(text));
            }
        }
    }

    /// Output from the host: the prompt marker hidden and the prompt drawn, line feeds made CR LF.
    pub fn output(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut data = std::mem::take(&mut self.held);
        data.extend_from_slice(bytes);
        let mut out = Vec::with_capacity(data.len() + 16);
        let mut at = 0;
        // Review F4 #7: where the next BEL is, found once and reused, so output full of marker-like starts without a
        // BEL costs one scan, not one per start.
        let mut next_bel: Option<Option<usize>> = None;
        while at < data.len() {
            let byte = data[at];
            if self.swallow > 0 && matches!(byte, b'\r' | b'\n') {
                self.swallow -= 1;
                if byte == b'\n' {
                    self.swallow = 0;
                }
                at += 1;
                continue;
            }
            self.swallow = 0;
            if byte == 0x1b {
                let rest = &data[at..];
                let partial = rest.len() < MARKER.len() && MARKER.starts_with(rest);
                if partial && rest.len() < MAX_HELD {
                    self.held = rest.to_vec();
                    break;
                }
                if rest.starts_with(MARKER) {
                    if next_bel.is_none_or(|bel| bel.is_some_and(|b| b < at)) {
                        next_bel = Some(data[at..].iter().position(|b| *b == 0x07).map(|p| p + at));
                    }
                    // A marker is short: one whose BEL is further than MAX_HELD away is not one.
                    match next_bel.flatten().filter(|bel| bel - at < MAX_HELD) {
                        Some(bel) => {
                            let body = &data[at + MARKER.len()..bel];
                            if let Some(folder) = self.marker_folder(body) {
                                self.folder = folder;
                                self.prompt_now(&mut out);
                                self.swallow = 2;
                                at = bel + 1;
                                continue;
                            }
                        }
                        // No BEL yet, and the start is near the end: the rest may still come.
                        None if next_bel.flatten().is_none() && rest.len() < MAX_HELD => {
                            self.held = rest.to_vec();
                            break;
                        }
                        None => {}
                    }
                }
            }
            match byte {
                b'\n' if !self.last_output_cr => out.extend_from_slice(b"\r\n"),
                _ => out.push(byte),
            }
            self.last_output_cr = byte == b'\r';
            self.at_line_start = byte == b'\n';
            at += 1;
        }
        self.publish();
        out
    }

    /// The folder in a marker with this console's nonce; `None` for anything else (it stays in the output).
    fn marker_folder(&self, body: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(body).ok()?;
        let (nonce, folder) = text.split_once(';')?;
        (nonce == self.nonce).then(|| {
            folder
                .chars()
                .filter(|c| !c.is_control() && !crate::untrusted::is_format_char(*c))
                .take(260)
                .collect()
        })
    }

    fn prompt_now(&mut self, out: &mut Vec<u8>) {
        if !self.at_line_start {
            out.extend_from_slice(b"\r\n");
        }
        self.state = State::Idle;
        out.extend_from_slice(self.prompt().as_bytes());
        // What was typed while the statement ran isn't shown again (it may be a password): it starts afresh.
        if self.masked {
            self.line.clear();
            self.masked = false;
        }
        // With pasted lines waiting, they go first ([`Editor::after_prompt`]) and the line being typed after them.
        if self.queued.is_empty() {
            out.extend_from_slice(self.line.as_bytes());
        }
        self.at_line_start = false;
        self.last_output_cr = false;
    }

    /// Review F4 #9: at a prompt, the pasted lines that waited go, each shown as if typed now. Lines that leave a
    /// statement open go on with it; once one statement is sent, the rest wait for the prompt after it.
    pub fn after_prompt(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        if self.state != State::Idle || (self.queued.is_empty() && !self.queue_overflow) {
            return out;
        }
        let typing = std::mem::take(&mut self.line);
        let mut shown = Vec::new();
        while self.state == State::Idle {
            let Some(line) = self.queued.pop_front() else {
                break;
            };
            shown.extend_from_slice(line.as_bytes());
            self.line = line;
            self.enter(false, false, &mut shown, &mut out);
        }
        self.line = typing;
        if self.state == State::Idle {
            if std::mem::take(&mut self.queue_overflow) {
                shown.extend_from_slice(
                    format!(
                        "\r\n(more than {MAX_QUEUED} pasted lines: the rest were left out)\r\n{}",
                        self.prompt()
                    )
                    .as_bytes(),
                );
            }
            shown.extend_from_slice(self.line.as_bytes());
        }
        out.push(Action::Show(shown));
        self.publish();
        merge_shows(out)
    }
}

/// Line endings in `bytes`, CR LF counted once.
fn line_endings(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut after_cr = false;
    for byte in bytes {
        match byte {
            b'\r' => count += 1,
            b'\n' if !after_cr => count += 1,
            _ => {}
        }
        after_cr = *byte == b'\r';
    }
    count
}

fn utf8_len(first: u8) -> usize {
    match first {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// Joins neighbouring [`Action::Show`]s, keeping the order with the rest.
fn merge_shows(actions: Vec<Action>) -> Vec<Action> {
    let mut out: Vec<Action> = Vec::with_capacity(actions.len());
    for action in actions {
        match (out.last_mut(), action) {
            (Some(Action::Show(prev)), Action::Show(more)) => prev.extend(more),
            (_, Action::Show(more)) if more.is_empty() => {}
            (_, action) => out.push(action),
        }
    }
    out
}

/// Whether the lines typed so far close a PowerShell statement: brackets, quotes, here-strings, block comments, a
/// trailing backtick or pipe. A simple reading (F8 brings a parser): enough that Remotely's marker line never lands
/// inside a statement left open.
#[derive(Debug, Default, Clone)]
pub struct Syntax {
    depth: i64,
    quote: Option<char>,
    here: Option<char>,
    block_comment: bool,
    continued: bool,
}

impl Syntax {
    pub fn feed(&mut self, line: &str) {
        self.continued = false;
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        if let Some(q) = self.here {
            if chars.first() == Some(&q) && chars.get(1) == Some(&'@') {
                self.here = None;
                i = 2;
            } else {
                return;
            }
        }
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if self.block_comment {
                if c == '#' && next == Some('>') {
                    self.block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            match self.quote {
                Some('\'') => {
                    if c == '\'' {
                        if next == Some('\'') {
                            i += 2;
                            continue;
                        }
                        self.quote = None;
                    }
                    i += 1;
                    continue;
                }
                Some(_) => {
                    if c == '`' {
                        i += 2;
                        continue;
                    }
                    if c == '"' {
                        if next == Some('"') {
                            i += 2;
                            continue;
                        }
                        self.quote = None;
                    }
                    i += 1;
                    continue;
                }
                None => {}
            }
            match c {
                '#' => break,
                '<' if next == Some('#') => {
                    self.block_comment = true;
                    i += 2;
                    continue;
                }
                '@' if matches!(next, Some('\'' | '"')) && chars[i + 2..].iter().all(|c| c.is_whitespace()) => {
                    self.here = next;
                    break;
                }
                '\'' | '"' => self.quote = Some(c),
                '`' => {
                    if chars[i + 1..].iter().all(|c| c.is_whitespace()) {
                        self.continued = true;
                    }
                    i += 2;
                    continue;
                }
                '{' | '(' | '[' => self.depth += 1,
                '}' | ')' | ']' => self.depth -= 1,
                _ => {}
            }
            i += 1;
        }
        if self.quote.is_none() && self.here.is_none() && !self.block_comment && line.trim_end().ends_with('|') {
            self.continued = true;
        }
    }

    pub fn complete(&self) -> bool {
        self.depth <= 0 && self.quote.is_none() && self.here.is_none() && !self.block_comment && !self.continued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(actions: &[Action]) -> String {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Show(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .collect()
    }

    fn sent(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    fn ready(editor: &mut Editor) {
        let first = editor.output(b"\x1b]7790;n1;C:\\Users\\alice\x07\r\n");
        assert_eq!(String::from_utf8_lossy(&first), "PS C:\\Users\\alice> ");
    }

    #[test]
    fn a_line_is_echoed_sent_with_the_marker_and_its_prompt_drawn_after_the_output() {
        let mut editor = Editor::new("n1".into());
        ready(&mut editor);
        let typed = editor.keys(b"Get-Date\r", false);
        assert_eq!(shown(&typed), "Get-Date\r\n");
        let lines = sent(&typed);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("try { . ([scriptblock]::Create('Get-Date')) }"),
            "{lines:?}"
        );
        assert!(
            lines[0].ends_with("; \"$([char]27)]7790;n1;$((Get-Location).Path)$([char]7)\"\r\n"),
            "{lines:?}"
        );
        assert_eq!(lines[0].matches("\r\n").count(), 1, "one line");
        // The output, then the marker split across two answers.
        let out = editor.output(b"\nSunday, 1 November 2026\n\x1b]779");
        assert_eq!(String::from_utf8_lossy(&out), "\r\nSunday, 1 November 2026\r\n");
        let out = editor.output(b"0;n1;C:\\Temp\x07\r\n");
        assert_eq!(String::from_utf8_lossy(&out), "PS C:\\Temp> ");
        // A marker with another nonce (printed by a file) stays in the output.
        let out = editor.output(b"\x1b]7790;other;x\x07");
        assert_eq!(out, b"\x1b]7790;other;x\x07");
    }

    #[test]
    fn an_open_statement_waits_for_its_end_and_goes_whole() {
        let mut editor = Editor::new("n1".into());
        ready(&mut editor);
        let first = editor.keys(b"foreach ($i in 1..3) {\r", false);
        assert!(sent(&first).is_empty());
        assert!(shown(&first).ends_with(">> "));
        let second = editor.keys(b"  $i\r", false);
        assert!(sent(&second).is_empty());
        let last = editor.keys(b"}\r", false);
        let lines = sent(&last);
        assert!(
            lines[0].starts_with(
                "try { . ([scriptblock]::Create('foreach ($i in 1..3) {' + \"`n\" + '  $i' + \"`n\" + '}')) }"
            ),
            "{lines:?}"
        );
        // Ctrl+C drops an open statement.
        editor.output(b"1\n2\n3\n\x1b]7790;n1;C:\\\x07\r\n");
        editor.keys(b"$s = @\"\r", false);
        let cancelled = editor.keys(b"\x03", false);
        assert!(sent(&cancelled).is_empty());
        assert!(shown(&cancelled).ends_with("^C\r\nPS C:\\> "));
    }

    #[test]
    fn while_a_statement_runs_lines_go_to_its_stdin_and_ctrl_c_interrupts() {
        let mut editor = Editor::new("n1".into());
        ready(&mut editor);
        editor.keys(b"Read-Host 'Name'\r", false);
        let answer = editor.keys(b"bob\r", false);
        assert_eq!(sent(&answer), vec!["bob\r\n".to_owned()]);
        assert_eq!(
            shown(&answer),
            "***\r\n",
            "typed for a running statement: masked, it may be a password"
        );
        // Typed ahead, then the prompt comes: it isn't shown again.
        editor.keys(b"pw", false);
        let prompt = String::from_utf8_lossy(&editor.output(b"\x1b]7790;n1;C:\\\x07\r\n")).into_owned();
        assert!(prompt.ends_with("PS C:\\> ") && !prompt.contains("pw"), "{prompt:?}");
        editor.keys(b"Read-Host 'Name'\r", false);
        let typed_secretly = editor.keys(b"hunter2", true);
        assert!(shown(&typed_secretly).is_empty(), "nothing shown at a password prompt");
        let ctrl_c = editor.keys(b"\x03", false);
        assert!(ctrl_c.contains(&Action::Interrupt));
        assert!(
            sent(&ctrl_c)[0].starts_with("\"$([char]27)]7790;n1;"),
            "a marker brings the prompt back"
        );
        // A vault secret is never shown or kept in the history.
        let secret = editor.secret(b"s3cret\r");
        assert_eq!(sent(&secret), vec!["s3cret\r\n".to_owned()]);
        assert!(!shown(&secret).contains("s3cret"));
    }

    #[test]
    fn an_invalid_utf8_lead_byte_does_not_swallow_the_next_key() {
        // Review B4/R2: a stray high byte — an X10 mouse report a host turned on, which xterm delivers as binary — is a
        // UTF-8 lead not followed by continuation bytes. The console must consume only that byte, never keep it pending
        // and swallow the key after it: a swallowed Ctrl+C would leave the statement running while the line's keys
        // desync from what MultiExec followed.
        let mut editor = Editor::new("n1".into());
        ready(&mut editor);
        editor.keys(b"Read-Host 'Name'\r", false);
        editor.keys(b"typed-ahead", false);
        // 0xe0 is a 3-byte UTF-8 lead; the Ctrl+C (0x03) right after it is not a continuation byte.
        let out = editor.keys(b"\xe0\x03", false);
        assert!(out.contains(&Action::Interrupt), "the Ctrl+C still interrupts: {out:?}");
    }

    #[test]
    fn a_pasted_block_goes_one_statement_per_prompt() {
        let mut editor = Editor::new("n1".into());
        ready(&mut editor);
        // Three lines at once: the first goes, the others wait (not to the running statement's stdin, not shown).
        let pasted = editor.keys(b"Get-Date\r\nfunction f {\r\n  1 }\r\n$x = 2\r\nGet-Ch", false);
        let lines = sent(&pasted);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("try { . ([scriptblock]::Create('Get-Date'))"));
        assert_eq!(shown(&pasted), "Get-Date\r\n");
        assert!(
            editor.after_prompt().is_empty(),
            "nothing goes while the statement runs"
        );
        // Its prompt: the open function goes on with its next line, as one statement.
        let prompt = editor.output(b"Sunday\n\x1b]7790;n1;C:\\\x07\r\n");
        assert_eq!(String::from_utf8_lossy(&prompt), "Sunday\r\nPS C:\\> ");
        let next = editor.after_prompt();
        assert_eq!(shown(&next), "function f {\r\n>>   1 }\r\n");
        let lines = sent(&next);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("Create('function f {' + \"`n\" + '  1 }')"),
            "{lines:?}"
        );
        editor.output(b"\x1b]7790;n1;C:\\\x07\r\n");
        let last = editor.after_prompt();
        assert!(sent(&last)[0].contains("Create('$x = 2')"));
        // The line still being typed comes back once the pasted ones went.
        editor.output(b"\x1b]7790;n1;C:\\\x07\r\n");
        let typing = editor.after_prompt();
        assert!(sent(&typing).is_empty());
        let rest = editor.keys(b"ildItem\r", false);
        assert!(sent(&rest)[0].contains("Create('Get-ChildItem')"), "{rest:?}");
        // Ctrl+C drops what still waits.
        editor.output(b"\x1b]7790;n1;C:\\\x07\r\n");
        editor.keys(b"Start-Sleep 9\r\n1\r\n2\r\n", false);
        editor.keys(b"\x03", false);
        editor.output(b"\x1b]7790;n1;C:\\\x07\r\n");
        assert!(sent(&editor.after_prompt()).is_empty());
        // A line typed alone while a statement runs is still its input, masked.
        editor.keys(b"Read-Host\r", false);
        let answer = editor.keys(b"pw\r", false);
        assert_eq!(sent(&answer), vec!["pw\r\n".to_owned()]);
        assert_eq!(shown(&answer), "**\r\n");
        assert_eq!(line_endings(b"a\r\nb\nc\r"), 3);
    }

    #[test]
    fn history_backspace_and_utf8_keys() {
        let mut editor = Editor::new("n1".into());
        ready(&mut editor);
        editor.keys("Get-Item é\r".as_bytes(), false);
        editor.output(b"\x1b]7790;n1;C:\\\x07\r\n");
        let up = editor.keys(b"\x1b[A", false);
        assert!(shown(&up).ends_with("PS C:\\> Get-Item é"));
        // A character split across two reads.
        let bytes = "ü".as_bytes();
        editor.keys(&bytes[..1], false);
        let rest = editor.keys(&bytes[1..], false);
        assert_eq!(shown(&rest), "ü");
        let back = editor.keys(b"\x7f", false);
        assert_eq!(shown(&back), "\x08 \x08");
        // Enter on an empty line asks for a fresh prompt: only the marker goes.
        editor.keys(b"\x15", false);
        let empty = editor.keys(b"\r", false);
        assert!(sent(&empty)[0].starts_with("\"$([char]27)"));
    }

    #[test]
    fn typed_text_can_never_end_its_quoted_string() {
        assert_eq!(single_quoted("it's"), "'it''s'");
        assert_eq!(single_quoted("it\u{2019}s"), "'it\u{2019}\u{2019}s'");
        assert_eq!(single_quoted("$x `n \"y\""), "'$x `n \"y\"'");
        let line = statement_line(&["'); Stop-Computer; ('".to_owned()], "n1");
        assert!(line.contains("Create('''); Stop-Computer; (''')"), "{line}");
    }

    #[test]
    fn statements_say_what_the_console_sends_for_typed_lines() {
        let lines = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        // One line that closes: one statement.
        assert_eq!(
            statements(&[], &lines(&["Get-Date"])),
            (vec![lines(&["Get-Date"])], vec![])
        );
        // An open one is held, then sent whole with the line that closes it.
        let (none, held) = statements(&[], &lines(&["foreach ($i in 1..3) {"]));
        assert!(none.is_empty());
        assert_eq!(held, lines(&["foreach ($i in 1..3) {"]));
        let (sent_all, held) = statements(&held, &lines(&["  $i", "}", "hostname"]));
        assert_eq!(
            sent_all,
            vec![lines(&["foreach ($i in 1..3) {", "  $i", "}"]), lines(&["hostname"])]
        );
        assert!(held.is_empty());
        // An empty line at the prompt sends nothing; one inside an open statement ends it.
        assert_eq!(statements(&[], &lines(&[""])), (vec![], vec![]));
        let (split, _) = statements(&[], &lines(&["\"x", "", "Stop-Service a", "\""]));
        assert_eq!(split, vec![lines(&["\"x", ""]), lines(&["Stop-Service a"])]);
        // The Editor decides the same: the open function goes with its next line, as one statement.
        let mut editor = Editor::new("n1".into());
        editor.output(b"\x1b]7790;n1;C:\\\x07\r\n");
        assert!(editor.status().view().at_prompt);
        editor.keys(b"function f {\r", false);
        assert_eq!(editor.status().view().open_lines(), 1);
        assert_eq!(editor.status().view().open, ["function f {"]);
        let sent_now = editor.keys(b"1 }\r", false);
        assert!(sent(&sent_now)[0].contains("Create('function f {' + \"`n\" + '1 }')"));
        assert!(!editor.status().view().at_prompt, "a statement runs");
    }

    #[test]
    fn statements_left_open_are_seen() {
        let open = |lines: &[&str]| {
            let mut syntax = Syntax::default();
            for line in lines {
                syntax.feed(line);
            }
            !syntax.complete()
        };
        assert!(!open(&["Get-Process | Select-Object -First 3"]));
        assert!(open(&["Get-Process |"]));
        assert!(open(&["if ($true) {"]));
        assert!(!open(&["if ($true) {", "'x'", "}"]));
        assert!(open(&["$s = 'it''s"]));
        assert!(!open(&["$s = 'it''s'"]));
        assert!(open(&["$h = @'"]));
        assert!(!open(&["$h = @'", "{ not a block", "'@"]));
        assert!(open(&["Get-Item `"]));
        assert!(!open(&["Write-Output '{' # }"]));
        assert!(open(&["<# a comment"]));
        assert!(!open(&["\"a `\" b\""]));
    }
}
