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
//! * **While a statement runs**, a line typed goes to its stdin as it is (`Read-Host`); Ctrl+C sends WinRM's ctrl_c
//!   signal, then a marker. Enter on an empty line asks for a fresh prompt.
//! * The statement's state lives in that one PowerShell: a new connection starts a new one (the pane says so).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use uuid::Uuid;

use super::shell::{RemoteShell, MIN_EMPTY_GAP, POWERSHELL, RECEIVE_WAIT};
use super::soap::{self, Received};
use crate::adapters::remote::{SecretPromptShown, ShellEnd, ShellInput, ShellOutput};
use crate::error::{CoreError, Result};

/// Lines kept for Up and Down.
const HISTORY: usize = 200;
/// A line longer than this is not taken (PowerShell reads lines; a paste of a whole file belongs in a script).
pub const MAX_LINE: usize = 32 * 1024;
/// Bytes held while a sequence that may be the prompt marker is incomplete.
const MAX_HELD: usize = 4096;
/// The OSC number of the prompt marker.
const MARKER: &[u8] = b"\x1b]7790;";

/// The two ends of a console.
pub struct ConsoleShell {
    pub input: mpsc::Sender<ShellInput>,
    pub output: mpsc::Receiver<ShellOutput>,
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
    let command = shell
        .command(POWERSHELL, "-NoLogo -NoProfile -Command - 2>&1", true)
        .await?;
    let nonce = Uuid::new_v4().simple().to_string();
    // Progress bars mean nothing without a console; then the first prompt.
    let setup = format!("$ProgressPreference = 'SilentlyContinue'\r\n{}", marker_line(&nonce));
    shell.send(&command, setup.as_bytes(), false).await?;
    let (input_tx, input_rx) = mpsc::channel(256);
    let (output_tx, output_rx) = mpsc::channel(256);
    let (received_tx, received_rx) = mpsc::channel(16);
    tokio::spawn(receive_loop(Arc::clone(&shell), command.clone(), received_tx));
    let console = Console {
        shell,
        command,
        editor: Editor::new(nonce),
        output: output_tx,
        secret_prompt,
        _permit: permit,
    };
    tokio::spawn(console.run(input_rx, received_rx));
    Ok(ConsoleShell {
        input: input_tx,
        output: output_rx,
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
    /// Output held while it may be an incomplete prompt marker.
    held: Vec<u8>,
    /// The CR LF after a marker that PowerShell writes, still to hide.
    swallow: usize,
    at_line_start: bool,
    last_output_cr: bool,
    folder: String,
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
            held: Vec::new(),
            swallow: 0,
            at_line_start: true,
            last_output_cr: false,
            folder: String::new(),
        }
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
        let text = String::from_utf8_lossy(bytes);
        let text = text.trim_end_matches(['\r', '\n']);
        let mut out = Vec::new();
        if self.state == State::Running {
            out.push(Action::Show(b"\r\n".to_vec()));
            out.push(Action::Send(format!("{text}\r\n")));
            self.line.clear();
        }
        out
    }

    /// Keys from the pane. `secret`: the screen shows a password prompt, so nothing typed is shown.
    pub fn keys(&mut self, bytes: &[u8], secret: bool) -> Vec<Action> {
        let mut out = Vec::new();
        let mut shown = Vec::new();
        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(bytes);
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
                    self.enter(secret, &mut shown, &mut out);
                }
                b'\n' => {
                    if !after_cr {
                        self.enter(secret, &mut shown, &mut out);
                    }
                }
                0x7f | 0x08 => {
                    if self.line.pop().is_some() && !secret {
                        shown.extend_from_slice(b"\x08 \x08");
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
                }
                b'\t' => {}
                b if b < 0x20 => {}
                _ => {
                    // A whole UTF-8 character, or wait for the rest of it.
                    let len = utf8_len(byte);
                    if at + len > data.len() {
                        self.partial = data[at..].to_vec();
                        break;
                    }
                    if let Ok(text) = std::str::from_utf8(&data[at..at + len]) {
                        if self.line.len() + text.len() <= MAX_LINE {
                            self.line.push_str(text);
                            self.browsing = None;
                            if !secret {
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
        if self.state == State::Running {
            out.push(Action::Show(std::mem::take(shown)));
            out.push(Action::Interrupt);
            // Ctrl+C stops the statement before its own marker: a marker of its own brings the prompt back.
            out.push(Action::Send(marker_line(&self.nonce)));
            return;
        }
        self.line.clear();
        self.open.clear();
        self.syntax = Syntax::default();
        self.browsing = None;
        shown.extend_from_slice(format!("\r\n{}", self.prompt()).as_bytes());
    }

    fn enter(&mut self, secret: bool, shown: &mut Vec<u8>, out: &mut Vec<Action>) {
        shown.extend_from_slice(b"\r\n");
        let line = std::mem::take(&mut self.line);
        self.browsing = None;
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
                if !empty_alone && !self.syntax.complete() && !self.open.last().is_some_and(|l| l.trim().is_empty()) {
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
                let maybe_marker = rest.len() < MARKER.len() && MARKER.starts_with(rest) || rest.starts_with(MARKER);
                if maybe_marker {
                    match rest.iter().position(|b| *b == 0x07) {
                        Some(end) => {
                            let body = &rest[MARKER.len()..end];
                            if let Some(folder) = self.marker_folder(body) {
                                self.folder = folder;
                                self.prompt_now(&mut out);
                                self.swallow = 2;
                                at += end + 1;
                                continue;
                            }
                        }
                        None if rest.len() < MAX_HELD => {
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
        // What was typed while the statement ran, ready to edit.
        out.extend_from_slice(self.line.as_bytes());
        self.at_line_start = false;
        self.last_output_cr = false;
    }
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
