//! SS-11 "log this session to a file": a terminal's output as plain text lines, each stamped with the
//! time it ended. Colour and cursor escapes are dropped, a carriage return that is not part of a line
//! break starts the line over (progress bars keep their last state), and backspace takes back a
//! character, so the file reads like the screen did.
//!
//! The writer runs in a task of its own, so a slow disk never holds up the terminal. What it writes
//! has had the terminal's login secrets scrubbed first ([`Scrubber`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use time::OffsetDateTime;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

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

/// Turns terminal output into timestamped text lines.
pub struct LineLogger {
    /// Bytes of a UTF-8 character split across two reads.
    partial: Vec<u8>,
    line: String,
    escape: Escape,
    /// A `\r` that may be the start of `\r\n`.
    carriage_return: bool,
}

impl Default for LineLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl LineLogger {
    pub fn new() -> Self {
        Self {
            partial: Vec::new(),
            line: String::new(),
            escape: Escape::None,
            carriage_return: false,
        }
    }

    /// Takes the next output bytes; returns the lines they completed, stamped with `now`.
    pub fn feed(&mut self, bytes: &[u8], now: OffsetDateTime) -> Vec<String> {
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
            self.push(ch, now, &mut lines);
        }
        lines
    }

    /// What is left of the last line, when the log stops.
    pub fn finish(&mut self, now: OffsetDateTime) -> Option<String> {
        if !self.partial.is_empty() {
            let rest = String::from_utf8_lossy(&std::mem::take(&mut self.partial)).into_owned();
            self.line.push_str(&rest);
        }
        let line = std::mem::take(&mut self.line);
        (!line.trim().is_empty()).then(|| stamp(now, &line))
    }

    fn push(&mut self, ch: char, now: OffsetDateTime, lines: &mut Vec<String>) {
        match self.escape {
            Escape::Started => {
                self.escape = match ch {
                    '[' => Escape::Csi,
                    ']' | 'P' | 'X' | '^' | '_' => Escape::String,
                    _ => Escape::None,
                };
                return;
            }
            Escape::Csi => {
                if ('@'..='~').contains(&ch) {
                    self.escape = Escape::None;
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
        }
        self.carriage_return = false;
        match ch {
            '\x1b' => self.escape = Escape::Started,
            '\r' => self.carriage_return = true,
            '\n' => lines.push(stamp(now, &std::mem::take(&mut self.line))),
            '\x08' => {
                self.line.pop();
            }
            '\t' => self.line.push('\t'),
            c if c.is_control() => {}
            c => {
                self.line.push(c);
                if self.line.chars().count() >= MAX_LINE_CHARS {
                    lines.push(stamp(now, &std::mem::take(&mut self.line)));
                }
            }
        }
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

/// A running session log: send it output; dropping the sender (or [`LogMessage::Stop`]) ends it.
pub(crate) struct SessionLog {
    pub path: PathBuf,
    pub sender: mpsc::Sender<LogMessage>,
}

/// How often the writer flushes to disk while output keeps coming.
const FLUSH_EVERY: Duration = Duration::from_secs(1);

/// Opens (appends to) `path` and starts the writer task. `heading` is written first.
pub(crate) async fn start(path: &Path, heading: String, secrets: Vec<SecretString>) -> Result<SessionLog> {
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    let (sender, mut receiver) = mpsc::channel::<LogMessage>(1024);
    tokio::spawn(async move {
        let mut out = BufWriter::new(file);
        let refs: Vec<&SecretString> = secrets.iter().collect();
        let mut scrubber = Scrubber::new(&refs);
        let mut lines = LineLogger::new();
        let mut clean = Vec::new();
        let _ = out.write_all(format!("{heading}\r\n").as_bytes()).await;
        let mut flush = tokio::time::interval(FLUSH_EVERY);
        loop {
            tokio::select! {
                message = receiver.recv() => match message {
                    Some(LogMessage::Output(bytes)) => {
                        clean.clear();
                        scrubber.push(&bytes, &mut clean);
                        for line in lines.feed(&clean, local_now()) {
                            if out.write_all(format!("{line}\r\n").as_bytes()).await.is_err() {
                                tracing::warn!("a session log could not be written");
                            }
                        }
                    }
                    Some(LogMessage::Secret(secret)) => scrubber.add(&secret),
                    Some(LogMessage::Stop) | None => break,
                },
                _ = flush.tick() => {
                    let _ = out.flush().await;
                }
            }
        }
        clean.clear();
        scrubber.finish(&mut clean);
        let now = local_now();
        let mut tail: Vec<String> = lines.feed(&clean, now);
        tail.extend(lines.finish(now));
        tail.push(format!("[{}] Remotely stopped logging", clock(now)));
        for line in tail {
            let _ = out.write_all(format!("{line}\r\n").as_bytes()).await;
        }
        let _ = out.flush().await;
    });
    Ok(SessionLog {
        path: path.to_owned(),
        sender,
    })
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
        let log = start(&path, "Remotely session log".into(), vec![secret.clone()])
            .await
            .unwrap();
        log.sender
            .send(LogMessage::Output(
                format!("echo {}\r\nok\r\n", secret.expose()).into_bytes(),
            ))
            .await
            .unwrap();
        log.sender.send(LogMessage::Stop).await.unwrap();
        drop(log);
        let mut text = String::new();
        for _ in 0..50 {
            text = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            if text.contains("stopped logging") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let _ = std::fs::remove_file(&path);
        assert!(text.starts_with("Remotely session log\r\n"), "{text}");
        assert!(text.contains("] echo [redacted]\r\n"), "{text}");
        assert!(text.contains("] ok\r\n"), "{text}");
        assert!(!text.contains(secret.expose()), "{text}");
        assert!(text.trim_end().ends_with("Remotely stopped logging"), "{text}");
    }
}
