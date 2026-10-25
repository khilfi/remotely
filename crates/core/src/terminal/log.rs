//! SS-11 "log this session to a file": a terminal's output as plain text lines, each stamped with the
//! time it ended. Colour and cursor escapes are dropped, a carriage return that is not part of a line
//! break starts the line over (progress bars keep their last state), and backspace takes back a
//! character, so the file reads like the screen did.
//!
//! The writer runs in a task of its own, so a slow disk never holds up the terminal. What it writes
//! has had the terminal's login secrets scrubbed ([`Scrubber`]) twice: from the bytes as they arrive, and
//! from each rendered line, where a secret the terminal drew in pieces (split by a colour code, a cursor
//! move or a backspace, as in `hun\x1b[0mter2`) reads whole.
//!
//! QL-17: the same line splitter, without time stamps ([`ScrubbedLines`]), gives each pane's alert rules the
//! lines its output completes ([`crate::terminal::alerts`]). Each [`Line`] also says whether a full-screen program
//! drew it (xterm's alternate screen) and whether it was marked ([`LineLogger::mark_line`]: the line Enter was
//! pressed on), which the log ignores.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use time::OffsetDateTime;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::adapters::exec_output::Scrubber;
use crate::error::Result;
use crate::vault::SecretString;

/// A line longer than this is written in pieces, so a stream with no line breaks can't grow without end.
pub const MAX_LINE_CHARS: usize = 16 * 1024;

/// Where the line splitter is in an escape sequence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    /// Just after ESC.
    Started,
    /// CSI (`ESC [`): parameters until a final byte.
    Csi,
    /// OSC, DCS and the like: until BEL or `ESC \`.
    String,
    /// ESC inside a string: `\` ends it.
    StringEsc,
}

/// The longest control sequence parameters kept: enough for any private mode.
const MAX_CSI_CHARS: usize = 32;

/// A line of output as rendered: escapes dropped, redraws and backspaces applied, secrets scrubbed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// As drawn, not trimmed.
    pub text: String,
    /// QL-17: some of it was drawn while a full-screen program had the alternate screen (vim, less, top), or the
    /// screen switched while it was drawn.
    pub full_screen: bool,
    /// QL-17: [`LineLogger::mark_line`] was called while it was drawn.
    pub marked: bool,
}

/// Turns terminal output into timestamped text lines, with secrets scrubbed from the rendered text.
pub struct LineLogger {
    /// Bytes of a UTF-8 character split across two reads.
    partial: Vec<u8>,
    line: String,
    /// Characters in `line`, so a long line is not counted again for each character it gets.
    chars: usize,
    escape: Escape,
    /// The parameters of the control sequence being read (QL-17: the alternate screen's private modes).
    csi: String,
    /// A `\r` that may be the start of `\r\n`.
    carriage_return: bool,
    /// SS-11: scrubs each line as rendered, so a secret split by escapes or backspaces in the output is caught.
    /// It holds back only the end of a line cut at [`MAX_LINE_CHARS`] that may start a secret, for the next piece.
    scrubber: Scrubber,
    /// QL-17: a full-screen program has the alternate screen (`CSI ? 1049 h`, or the older 47 and 1047).
    alternate: bool,
    /// QL-17: the line being drawn is (partly) a full-screen program's.
    line_full_screen: bool,
    /// QL-17: the line being drawn was marked.
    marked: bool,
}

impl Default for LineLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl LineLogger {
    /// Scrubs nothing.
    pub fn new() -> Self {
        Self::scrubbing(&[])
    }

    /// Replaces `secrets` with `[redacted]` in the lines it renders.
    pub fn scrubbing(secrets: &[&SecretString]) -> Self {
        Self {
            partial: Vec::new(),
            line: String::new(),
            chars: 0,
            escape: Escape::None,
            csi: String::new(),
            carriage_return: false,
            scrubber: Scrubber::new(secrets),
            alternate: false,
            line_full_screen: false,
            marked: false,
        }
    }

    /// One more secret to scrub (QL-06), from the line being drawn on.
    pub fn add_secret(&mut self, secret: &SecretString) {
        self.scrubber.add(secret);
    }

    /// QL-17: what follows is drawn on a full-screen program's screen (a splitter started while one was open).
    pub fn set_alternate(&mut self, alternate: bool) {
        self.alternate = alternate;
        self.line_full_screen |= alternate;
    }

    /// QL-17: marks the line being drawn (the user pressed Enter on it); the mark comes back with it.
    pub fn mark_line(&mut self) {
        self.marked = true;
    }

    /// Takes the next output bytes; returns the lines they completed, stamped with `now`.
    pub fn feed(&mut self, bytes: &[u8], now: OffsetDateTime) -> Vec<String> {
        self.feed_lines(bytes)
            .into_iter()
            .map(|line| stamp(now, &line.text))
            .collect()
    }

    /// Takes the next output bytes; returns the lines they completed, without time stamps. A line longer than
    /// [`MAX_LINE_CHARS`] comes back in pieces.
    pub fn feed_lines(&mut self, bytes: &[u8]) -> Vec<Line> {
        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(bytes);
        let text = match std::str::from_utf8(&data) {
            Ok(text) => text.to_owned(),
            Err(err) if err.error_len().is_none() => {
                // Ends inside a character: keep its first bytes for the next read.
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

    /// What is left of the last line, when the log stops.
    pub fn finish(&mut self, now: OffsetDateTime) -> Option<String> {
        self.finish_line().map(|line| stamp(now, &line.text))
    }

    /// What is left of the last line, unless it is blank.
    pub fn finish_line(&mut self) -> Option<Line> {
        if !self.partial.is_empty() {
            let rest = String::from_utf8_lossy(&std::mem::take(&mut self.partial)).into_owned();
            self.line.push_str(&rest);
        }
        let line = self.take_line(true);
        (!line.text.trim().is_empty()).then_some(line)
    }

    /// Takes the line drawn so far, scrubbed. `whole`: it ended (a line break, or the log stopped); otherwise it was
    /// cut at [`MAX_LINE_CHARS`], and an end that may start a secret waits for the next piece (which keeps the marks).
    fn take_line(&mut self, whole: bool) -> Line {
        // The text as drawn is wiped once scrubbed: it may hold a secret the raw bytes had in pieces.
        let drawn = Zeroizing::new(std::mem::take(&mut self.line));
        self.chars = 0;
        let mut out = Vec::with_capacity(drawn.len());
        self.scrubber.push(drawn.as_bytes(), &mut out);
        if whole {
            self.scrubber.finish(&mut out);
        }
        let line = Line {
            // Valid UTF-8: what is held back starts where a secret does, so on a character boundary.
            text: String::from_utf8_lossy(&out).into_owned(),
            full_screen: self.line_full_screen,
            marked: self.marked,
        };
        if whole {
            self.line_full_screen = self.alternate;
            self.marked = false;
        }
        line
    }

    /// `CSI ? Pm h` / `CSI ? Pm l`: the private modes that switch to the alternate screen and back.
    fn private_mode(&mut self, set: bool) {
        if let Some(params) = self.csi.strip_prefix('?') {
            if params.split(';').any(|p| matches!(p, "47" | "1047" | "1049")) {
                self.switch_screen(set);
            }
        }
    }

    /// The screen switched. What was drawn on this line so far belongs to the full-screen program (on its way in or
    /// out), and so does what follows while it has the screen.
    fn switch_screen(&mut self, alternate: bool) {
        self.alternate = alternate;
        self.line_full_screen = alternate || !self.line.is_empty();
    }

    fn push(&mut self, ch: char, lines: &mut Vec<Line>) {
        match self.escape {
            Escape::Started => {
                self.escape = match ch {
                    '[' => {
                        self.csi.clear();
                        Escape::Csi
                    }
                    ']' | 'P' | 'X' | '^' | '_' => Escape::String,
                    // RIS, a full reset, leaves the alternate screen.
                    'c' => {
                        if self.alternate {
                            self.switch_screen(false);
                        }
                        Escape::None
                    }
                    _ => Escape::None,
                };
                return;
            }
            Escape::Csi => {
                if ('@'..='~').contains(&ch) {
                    self.escape = Escape::None;
                    if matches!(ch, 'h' | 'l') {
                        self.private_mode(ch == 'h');
                    }
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
        if self.carriage_return && ch != '\n' {
            // A lone carriage return: the line is redrawn from its start.
            self.line.clear();
            self.chars = 0;
        }
        self.carriage_return = false;
        match ch {
            '\x1b' => self.escape = Escape::Started,
            '\r' => self.carriage_return = true,
            '\n' => lines.push(self.take_line(true)),
            '\x08' => {
                if self.line.pop().is_some() {
                    self.chars -= 1;
                }
            }
            '\t' => {
                self.line.push('\t');
                self.chars += 1;
            }
            c if c.is_control() => {}
            c => {
                self.line.push(c);
                self.chars += 1;
                self.line_full_screen |= self.alternate;
                if self.chars >= MAX_LINE_CHARS {
                    lines.push(self.take_line(false));
                }
            }
        }
    }
}

/// QL-17: [`LineLogger`] behind a scrubber of the raw bytes, as the session log reads a terminal's output: a secret
/// the output holds whole goes before the line is drawn (so a backspace or carriage return that redraws part of it
/// can't leave the rest showing), and one drawn in pieces goes from the rendered line.
pub struct ScrubbedLines {
    raw: Scrubber,
    lines: LineLogger,
    clean: Vec<u8>,
}

impl ScrubbedLines {
    pub fn new(secrets: &[&SecretString]) -> Self {
        Self {
            raw: Scrubber::new(secrets),
            lines: LineLogger::scrubbing(secrets),
            clean: Vec::new(),
        }
    }

    /// One more secret to scrub from here on (QL-06: a vault password typed into the terminal).
    pub fn add_secret(&mut self, secret: &SecretString) {
        self.raw.add(secret);
        self.lines.add_secret(secret);
    }

    /// See [`LineLogger::set_alternate`].
    pub fn set_alternate(&mut self, alternate: bool) {
        self.lines.set_alternate(alternate);
    }

    /// See [`LineLogger::mark_line`].
    pub fn mark_line(&mut self) {
        self.lines.mark_line();
    }

    /// The lines these bytes completed.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Line> {
        self.clean.clear();
        self.raw.push(bytes, &mut self.clean);
        let clean = std::mem::take(&mut self.clean);
        let lines = self.lines.feed_lines(&clean);
        self.clean = clean;
        lines
    }

    /// The output ended: what the scrubber held back, and the last line unless it is blank.
    pub fn finish(&mut self) -> Vec<Line> {
        self.clean.clear();
        self.raw.finish(&mut self.clean);
        let clean = std::mem::take(&mut self.clean);
        let mut lines = self.lines.feed_lines(&clean);
        lines.extend(self.lines.finish_line());
        lines
    }
}

/// `[2026-10-19 14:03:22] text`.
pub fn stamp(at: OffsetDateTime, line: &str) -> String {
    format!("[{}] {}", clock(at), line.trim_end())
}

/// `2026-10-19 14:03:22`.
pub fn clock(at: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// The local time when Windows can say, UTC otherwise.
pub fn local_now() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

/// `+02:00`, or `UTC`.
pub fn offset_label(at: OffsetDateTime) -> String {
    let offset = at.offset();
    if offset.is_utc() {
        return "UTC".into();
    }
    let (hours, minutes, _) = offset.as_hms();
    let sign = if offset.is_negative() { '-' } else { '+' };
    format!("{sign}{:02}:{:02}", hours.unsigned_abs(), minutes.unsigned_abs())
}

/// What the terminal sends its log.
pub(crate) enum LogMessage {
    Output(Vec<u8>),
    /// QL-06: a vault secret typed into the terminal, scrubbed from here on.
    Secret(SecretString),
    Stop,
}

/// A running session log: send it output; [`SessionLog::stop`] ends it (dropping the sender does too, without
/// waiting for the last lines to reach the disk).
pub(crate) struct SessionLog {
    /// Tells this log from one started after it on the same terminal.
    pub id: Uuid,
    pub path: PathBuf,
    pub sender: mpsc::Sender<LogMessage>,
    writer: JoinHandle<()>,
}

impl SessionLog {
    /// Ends the log and waits (up to [`STOP_WAIT`]) until its last lines are on disk, so a log closed as the app
    /// exits (or installs an update) is complete.
    pub(crate) async fn stop(self) {
        let Self { sender, writer, .. } = self;
        // Both under the time limit: a full queue in front of a disk that hangs must not hold the exit up.
        let stopped = async move {
            let _ = sender.send(LogMessage::Stop).await;
            let _ = writer.await;
        };
        if tokio::time::timeout(STOP_WAIT, stopped).await.is_err() {
            tracing::warn!("a session log did not finish writing in time");
        }
    }
}

/// QL-15: called once when the log can't be written (a full disk, a removed drive), with why. The log has
/// stopped by then; the terminal says so and audits it. Gets the log's [`SessionLog::id`].
pub(crate) type OnFailure = Box<dyn FnOnce(Uuid, String) -> BoxFuture + Send>;

pub(crate) type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// How often the writer flushes to disk while output keeps coming.
const FLUSH_EVERY: Duration = Duration::from_secs(1);

/// How long [`SessionLog::stop`] waits for the last lines.
const STOP_WAIT: Duration = Duration::from_secs(2);

/// Opens (appends to) `path` and starts the writer task. `heading` is written first.
pub(crate) async fn start(
    path: &Path,
    heading: String,
    secrets: Vec<SecretString>,
    on_failure: OnFailure,
) -> Result<SessionLog> {
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    Ok(start_with(file, path, heading, secrets, on_failure))
}

/// [`start`] on any writer (tests give one that fails).
pub(crate) fn start_with<W: AsyncWrite + Unpin + Send + 'static>(
    file: W,
    path: &Path,
    heading: String,
    secrets: Vec<SecretString>,
    on_failure: OnFailure,
) -> SessionLog {
    let (sender, mut receiver) = mpsc::channel::<LogMessage>(1024);
    let id = Uuid::new_v4();
    let writer = tokio::spawn(async move {
        let mut out = BufWriter::new(file);
        let refs: Vec<&SecretString> = secrets.iter().collect();
        // Scrubbed twice. From the raw bytes: a secret the output has whole goes before the renderer sees it, so a
        // backspace or carriage return that redraws part of it later can't leave the rest showing. And from each
        // rendered line (the LineLogger's own scrubber): a secret the output drew in pieces (`hun\x1b[0mter2`,
        // `hunx\x08ter2`) reads whole only there.
        let mut lines = ScrubbedLines::new(&refs);
        let mut failure = out.write_all(format!("{heading}\r\n").as_bytes()).await.err();
        let mut flush = tokio::time::interval(FLUSH_EVERY);
        while failure.is_none() {
            tokio::select! {
                message = receiver.recv() => match message {
                    Some(LogMessage::Output(bytes)) => {
                        let now = local_now();
                        for line in lines.feed(&bytes) {
                            let line = stamp(now, &line.text);
                            if let Err(err) = out.write_all(format!("{line}\r\n").as_bytes()).await {
                                failure = Some(err);
                                break;
                            }
                        }
                    }
                    Some(LogMessage::Secret(secret)) => lines.add_secret(&secret),
                    Some(LogMessage::Stop) | None => break,
                },
                _ = flush.tick() => {
                    failure = out.flush().await.err();
                }
            }
        }
        if let Some(err) = failure {
            // Stopping beats losing lines silently: the terminal shows why, and the audit log has it.
            tracing::warn!(error = %err, "a session log could not be written; it stopped");
            drop(receiver);
            on_failure(id, err.to_string()).await;
            return;
        }
        let now = local_now();
        let mut tail: Vec<String> = lines.finish().iter().map(|line| stamp(now, &line.text)).collect();
        tail.push(format!("[{}] Remotely stopped logging", clock(now)));
        for line in tail {
            let _ = out.write_all(format!("{line}\r\n").as_bytes()).await;
        }
        let _ = out.flush().await;
    });
    SessionLog {
        id,
        path: path.to_owned(),
        sender,
        writer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const AT: OffsetDateTime = datetime!(2026-10-19 14:03:22 UTC);

    fn lines(chunks: &[&[u8]]) -> Vec<String> {
        let mut logger = LineLogger::new();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(logger.feed(chunk, AT));
        }
        out.extend(logger.finish(AT));
        out
    }

    #[test]
    fn each_line_gets_the_time_it_ended() {
        assert_eq!(
            lines(&[b"alice@web01:~$ uptime\r\n 10:00 up 3 days\r\n$ "]),
            [
                "[2026-10-19 14:03:22] alice@web01:~$ uptime",
                "[2026-10-19 14:03:22]  10:00 up 3 days",
                "[2026-10-19 14:03:22] $"
            ]
        );
    }

    #[test]
    fn colours_titles_and_cursor_moves_are_dropped() {
        let out = lines(&[b"\x1b]0;alice@web01: ~\x07\x1b[01;32malice\x1b[0m ok\x1b[K\r\n\x1bP+q\x1b\\done\n"]);
        assert_eq!(out, ["[2026-10-19 14:03:22] alice ok", "[2026-10-19 14:03:22] done"]);
    }

    #[test]
    fn a_progress_bar_keeps_its_last_state_and_backspace_takes_back() {
        let out = lines(&[b"10%\r50%\r100%\r\n", b"passwrd\x08\x08ord\n"]);
        assert_eq!(out, ["[2026-10-19 14:03:22] 100%", "[2026-10-19 14:03:22] password"]);
    }

    #[test]
    fn a_character_split_across_reads_arrives_whole() {
        let out = lines(&[&[b'c', b'a', b'f', 0xC3], &[0xA9, b'\r'], b"\n"]);
        assert_eq!(out, ["[2026-10-19 14:03:22] café"]);
    }

    #[test]
    fn a_line_break_split_across_reads_is_still_one_break() {
        let out = lines(&[b"one\r", b"\ntwo\r\n"]);
        assert_eq!(out, ["[2026-10-19 14:03:22] one", "[2026-10-19 14:03:22] two"]);
    }

    #[test]
    fn offsets_read_like_iso_8601() {
        assert_eq!(offset_label(AT), "UTC");
        assert_eq!(offset_label(datetime!(2026-10-19 14:03:22 +02:00)), "+02:00");
        assert_eq!(offset_label(datetime!(2026-10-19 14:03:22 -03:30)), "-03:30");
    }

    #[tokio::test]
    async fn the_log_file_has_a_heading_scrubbed_lines_and_an_ending() {
        let path = std::env::temp_dir().join(format!("remotely-log-{}.log", uuid::Uuid::new_v4()));
        let secret = SecretString::new(format!("pw-{}", uuid::Uuid::new_v4().simple()));
        let log = start(
            &path,
            "Remotely session log".into(),
            vec![secret.clone()],
            never_fails(),
        )
        .await
        .unwrap();
        log.sender
            .send(LogMessage::Output(
                format!("echo {}\r\nok\r\n", secret.expose()).into_bytes(),
            ))
            .await
            .unwrap();
        // QL-15: stopping waits until the last lines are on disk, as before an update's installer exits the app.
        log.stop().await;
        let text = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        assert!(text.starts_with("Remotely session log\r\n"), "{text}");
        assert!(text.contains("] echo [redacted]\r\n"), "{text}");
        assert!(text.contains("] ok\r\n"), "{text}");
        assert!(!text.contains(secret.expose()), "{text}");
        assert!(text.trim_end().ends_with("Remotely stopped logging"), "{text}");
    }

    /// What a log in the system temp folder holds after `messages`: the heading, the lines, the ending.
    async fn logged(secrets: Vec<SecretString>, messages: Vec<LogMessage>) -> String {
        let path = std::env::temp_dir().join(format!("remotely-log-{}.log", uuid::Uuid::new_v4()));
        let log = start(&path, "Remotely session log".into(), secrets, never_fails())
            .await
            .unwrap();
        for message in messages {
            log.sender.send(message).await.unwrap();
        }
        log.stop().await;
        let text = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        text
    }

    /// The logged lines without their time stamps.
    fn texts(log: &str) -> Vec<&str> {
        log.split("\r\n")
            .filter_map(|line| line.split_once("] ").map(|(_, text)| text))
            .collect()
    }

    fn output(bytes: &[u8]) -> LogMessage {
        LogMessage::Output(bytes.to_vec())
    }

    const PW: &str = "hunter2";

    #[tokio::test]
    async fn a_secret_split_by_a_colour_code_is_scrubbed_from_the_rendered_line() {
        let text = logged(
            vec![SecretString::new(PW)],
            vec![output(b"echo hun\x1b[0mter2\r\nok\r\n")],
        )
        .await;
        assert_eq!(
            texts(&text),
            ["echo [redacted]", "ok", "Remotely stopped logging"],
            "{text}"
        );
        assert!(!text.contains(PW), "{text}");
    }

    #[tokio::test]
    async fn a_secret_drawn_over_a_backspace_is_scrubbed_from_the_rendered_line() {
        let text = logged(vec![SecretString::new(PW)], vec![output(b"echo hunx\x08ter2\r\n")]).await;
        assert_eq!(texts(&text), ["echo [redacted]", "Remotely stopped logging"], "{text}");
        assert!(!text.contains(PW), "{text}");
    }

    #[tokio::test]
    async fn a_secret_split_across_two_output_chunks_is_scrubbed() {
        // The escape itself is cut in two as well.
        let text = logged(
            vec![SecretString::new(PW)],
            vec![output(b"echo hun\x1b[0"), output(b"mter2 done\r\n")],
        )
        .await;
        assert_eq!(
            texts(&text),
            ["echo [redacted] done", "Remotely stopped logging"],
            "{text}"
        );
        assert!(!text.contains(PW), "{text}");
    }

    #[tokio::test]
    async fn a_secret_added_later_is_scrubbed_from_rendered_lines_too() {
        // QL-06: a vault password typed into the terminal, sent to the log as it is typed.
        let text = logged(
            Vec::new(),
            vec![
                output(b"hunter1 is not it\r\n"),
                LogMessage::Secret(SecretString::new(PW)),
                output(b"echo hu\x1b[1mnter\x1b[0m2\r\n"),
            ],
        )
        .await;
        assert_eq!(
            texts(&text),
            ["hunter1 is not it", "echo [redacted]", "Remotely stopped logging"],
            "{text}"
        );
    }

    #[tokio::test]
    async fn plain_text_is_logged_unchanged() {
        // "hunt" starts the secret: held back while it might, then written as it was.
        let text = logged(
            vec![SecretString::new(PW)],
            vec![
                output(b"alice@web01:~$ uptime\r\n 10:00 up 3 days\r\nhunt"),
                output(b"ing\r\n"),
            ],
        )
        .await;
        assert_eq!(
            texts(&text),
            [
                "alice@web01:~$ uptime",
                " 10:00 up 3 days",
                "hunting",
                "Remotely stopped logging"
            ],
            "{text}"
        );
    }

    #[test]
    fn a_secret_across_a_long_line_cut_is_scrubbed() {
        let secret = SecretString::new(PW);
        let mut logger = LineLogger::scrubbing(&[&secret]);
        let long = format!("{}{PW}\r\n", "x".repeat(MAX_LINE_CHARS - 3));
        let mut out = logger.feed(long.as_bytes(), AT);
        out.extend(logger.finish(AT));
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[0], stamp(AT, &"x".repeat(MAX_LINE_CHARS - 3)));
        assert_eq!(out[1], "[2026-10-19 14:03:22] [redacted]");
    }

    fn texts_of(lines: &[Line]) -> Vec<&str> {
        lines.iter().map(|l| l.text.as_str()).collect()
    }

    #[test]
    fn lines_come_unstamped_and_untrimmed_too() {
        // QL-17: the alert rules read the same lines as the log, without its time stamps.
        let mut lines = LineLogger::new();
        let out = lines.feed_lines(b"\x1b[31mER");
        assert!(out.is_empty());
        let out = lines.feed_lines(b"ROR\x1b[0m: disk full  \r\n$ ");
        assert_eq!(texts_of(&out), ["ERROR: disk full  "]);
        assert!(!out[0].full_screen && !out[0].marked);
        assert_eq!(lines.finish_line().map(|l| l.text), Some("$ ".to_owned()));
        assert_eq!(lines.finish_line(), None, "nothing left");
    }

    #[test]
    fn lines_a_full_screen_program_drew_say_so() {
        let mut lines = LineLogger::new();
        let mut out = lines.feed_lines(b"before\r\n\x1b[?1049h\x1b[Htop - error\r\nTasks: 9\r\n");
        // Split across reads, and the line the switch back happens on counts as the program's too.
        out.extend(lines.feed_lines(b"q\x1b[?10"));
        out.extend(lines.feed_lines(b"49l\r\nafter error\r\n"));
        let flags: Vec<(&str, bool)> = out.iter().map(|l| (l.text.as_str(), l.full_screen)).collect();
        assert_eq!(
            flags,
            [
                ("before", false),
                ("top - error", true),
                ("Tasks: 9", true),
                ("q", true),
                ("after error", false)
            ]
        );
        // A splitter that starts while one is open.
        let mut late = LineLogger::new();
        late.set_alternate(true);
        let out = late.feed_lines(b"middle\r\n\x1bcfresh\r\n");
        assert_eq!(out.iter().map(|l| l.full_screen).collect::<Vec<_>>(), [true, false]);
    }

    #[test]
    fn a_marked_line_comes_back_marked_once() {
        let mut lines = LineLogger::new();
        lines.feed_lines(b"alice@web01:~$ grep error app.log");
        lines.mark_line();
        let out = lines.feed_lines(b"\r\nerror one\r\n");
        assert_eq!(
            out.iter().map(|l| (l.text.as_str(), l.marked)).collect::<Vec<_>>(),
            [("alice@web01:~$ grep error app.log", true), ("error one", false)]
        );
    }

    #[test]
    fn scrubbed_lines_scrub_the_raw_bytes_and_the_rendered_line() {
        let secret = SecretString::new(PW);
        let mut lines = ScrubbedLines::new(&[&secret]);
        // Whole in the raw bytes, then partly drawn over: the rest never shows.
        let mut out = lines.feed(b"echo hunter2\x08\x08xx\r\n");
        // In pieces: a colour code in the middle.
        out.extend(lines.feed(b"echo hun\x1b[0mter2\r\n"));
        // Added later, split across reads.
        lines.add_secret(&SecretString::new("s3cr3t-later"));
        out.extend(lines.feed(b"say s3cr3t-"));
        out.extend(lines.feed(b"later ok\r\nhunt"));
        out.extend(lines.finish());
        assert_eq!(
            texts_of(&out),
            ["echo [redactexx", "echo [redacted]", "say [redacted] ok", "hunt"]
        );
    }

    fn never_fails() -> OnFailure {
        Box::new(|_, reason| Box::pin(async move { panic!("the log failed: {reason}") }))
    }

    /// A disk that takes `room` bytes, then reports itself full.
    struct FullDisk {
        room: usize,
    }

    impl AsyncWrite for FullDisk {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.room < buf.len() {
                return std::task::Poll::Ready(Err(std::io::Error::other("There is not enough space on the disk.")));
            }
            self.room -= buf.len();
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_log_that_cant_be_written_stops_and_says_why() {
        let (failed, said) = tokio::sync::oneshot::channel();
        let on_failure: OnFailure = Box::new(move |id, reason| {
            Box::pin(async move {
                let _ = failed.send((id, reason));
            })
        });
        let log = start_with(
            FullDisk { room: 100 },
            Path::new("full.log"),
            "Remotely session log".into(),
            Vec::new(),
            on_failure,
        );
        // More than the BufWriter holds, so it reaches the "disk" at once.
        let line = "x".repeat(10_000);
        log.sender
            .send(LogMessage::Output(format!("{line}\r\n").into_bytes()))
            .await
            .unwrap();
        let (id, reason) = tokio::time::timeout(Duration::from_secs(5), said)
            .await
            .expect("the failure is reported")
            .unwrap();
        assert_eq!(id, log.id);
        assert!(reason.contains("not enough space"), "{reason}");
        // The writer has stopped: nothing takes output any more.
        tokio::time::timeout(Duration::from_secs(5), log.sender.closed())
            .await
            .expect("the log stopped");
    }
}
