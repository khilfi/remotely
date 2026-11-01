//! FD-09: the file server's request log: every request (who asked, for what, how many bytes, what came of it), the
//! last [`MAX_LOG_ENTRIES`] kept in memory with totals of all of them. The window reads it while the server runs; the
//! job keeps it as its output when the server stops, so Activity lists every request kept.

use std::collections::VecDeque;
use std::net::SocketAddr;

use serde::Serialize;

use super::uploads::size_text;
use crate::export::redact_secrets;
use crate::untrusted::is_format_char;

/// The requests kept; older ones are counted, not kept.
pub const MAX_LOG_ENTRIES: usize = 500;
/// The requests a status shows, newest first.
pub const STATUS_ENTRIES: usize = 200;
/// The longest path a log entry keeps, in characters.
const MAX_LOGGED_PATH: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    Tftp,
    Http,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Protocol::Tftp => "TFTP",
            Protocol::Http => "HTTP",
        }
    }
}

/// What came of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    /// A file or a listing went out whole.
    Sent,
    /// An upload arrived whole.
    Received,
    /// Refused: the path, a rule or a cap.
    Refused,
    /// Started, but didn't end well: the client went away or was too slow, or the server stopped.
    Failed,
}

/// One request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestEntry {
    /// When it came (RFC 3339, UTC).
    pub at: String,
    pub protocol: Protocol,
    /// The client's address (FD-03 masks it as an IP).
    pub ip: String,
    pub port: u16,
    /// `read` or `write` for TFTP, the method for HTTP.
    pub method: String,
    /// What it asked for, as sent (control and format characters shown as `_`, at most 200 characters, anything
    /// like a secret redacted).
    pub path: String,
    pub bytes: u64,
    pub outcome: Outcome,
    /// Why, for a refusal or a failure; what, for the rest ("a listing of 12 entries").
    pub detail: String,
}

/// Totals over every request, kept or not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub requests: u64,
    pub sent: u64,
    pub received: u64,
    pub refused: u64,
    pub failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Requests no longer kept in the log (past [`MAX_LOG_ENTRIES`]).
    pub dropped: u64,
}

#[derive(Debug, Default)]
pub struct RequestLog {
    entries: VecDeque<RequestEntry>,
    counts: Counts,
}

impl RequestLog {
    pub fn push(&mut self, entry: RequestEntry) {
        let c = &mut self.counts;
        c.requests += 1;
        match entry.outcome {
            Outcome::Sent => {
                c.sent += 1;
                c.bytes_sent = c.bytes_sent.saturating_add(entry.bytes);
            }
            Outcome::Received => {
                c.received += 1;
                c.bytes_received = c.bytes_received.saturating_add(entry.bytes);
            }
            Outcome::Refused => c.refused += 1,
            Outcome::Failed => {
                c.failed += 1;
                // A download cut off still sent what it sent; an upload cut off was deleted.
                if entry.method != "write" && entry.method != "PUT" {
                    c.bytes_sent = c.bytes_sent.saturating_add(entry.bytes);
                }
            }
        }
        if self.entries.len() >= MAX_LOG_ENTRIES {
            self.entries.pop_front();
            c.dropped += 1;
        }
        self.entries.push_back(entry);
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// The newest `n`, newest first.
    pub fn recent(&self, n: usize) -> Vec<RequestEntry> {
        self.entries.iter().rev().take(n).cloned().collect()
    }

    /// The log as the job keeps it: a line of totals, then one line a request, oldest first.
    pub fn text(&self) -> String {
        let c = self.counts;
        let mut text = format!(
            "{}: {} sent, {} received, {} refused, {} failed; {} sent, {} received\n",
            plural(c.requests, "request", "requests"),
            c.sent,
            c.received,
            c.refused,
            c.failed,
            size_text(c.bytes_sent),
            size_text(c.bytes_received),
        );
        if c.dropped > 0 {
            text.push_str(&format!(
                "the first {} are not kept; the last {MAX_LOG_ENTRIES} follow\n",
                plural(c.dropped, "request", "requests")
            ));
        }
        for e in &self.entries {
            let detail = if e.detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", e.detail)
            };
            text.push_str(&format!(
                "{} {} {} {}:{} {} {} {}{detail}\n",
                e.at,
                e.protocol.label(),
                e.method,
                e.ip,
                e.port,
                if e.path.is_empty() { "/" } else { &e.path },
                outcome_word(e.outcome),
                size_text(e.bytes),
            ));
        }
        text
    }

    /// "12 requests: 10 sent, 2 refused; 30 MB sent".
    pub fn summary(&self) -> String {
        let c = self.counts;
        if c.requests == 0 {
            return "no requests".into();
        }
        let mut parts = Vec::new();
        for (n, word) in [
            (c.sent, "sent"),
            (c.received, "received"),
            (c.refused, "refused"),
            (c.failed, "failed"),
        ] {
            if n > 0 {
                parts.push(format!("{n} {word}"));
            }
        }
        let mut text = format!("{}: {}", plural(c.requests, "request", "requests"), parts.join(", "));
        if c.bytes_sent > 0 {
            text.push_str(&format!("; {} sent", size_text(c.bytes_sent)));
        }
        if c.bytes_received > 0 {
            text.push_str(&format!("; {} received", size_text(c.bytes_received)));
        }
        text
    }
}

fn outcome_word(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Sent => "sent",
        Outcome::Received => "received",
        Outcome::Refused => "refused",
        Outcome::Failed => "failed",
    }
}

pub(crate) fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// A request's path as the log keeps it: what the client sent, made safe to show and keep.
pub fn clean_path(raw: &str) -> String {
    let mut out = String::new();
    for (i, c) in raw.chars().enumerate() {
        if i >= MAX_LOGGED_PATH {
            out.push('…');
            break;
        }
        out.push(
            if c.is_control() || is_format_char(c) || matches!(c, '\u{2028}' | '\u{2029}') {
                '_'
            } else {
                c
            },
        );
    }
    redact_secrets(&out).0
}

/// A new entry, its time now.
pub fn entry(protocol: Protocol, peer: SocketAddr, method: &str, path: &str) -> RequestEntry {
    RequestEntry {
        at: crate::domain::now_rfc3339(),
        protocol,
        ip: peer.ip().to_string(),
        port: peer.port(),
        method: method.to_owned(),
        path: clean_path(path),
        bytes: 0,
        outcome: Outcome::Failed,
        detail: String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "192.0.2.7:51234".parse().unwrap()
    }

    #[test]
    fn the_log_keeps_the_last_entries_and_counts_them_all() {
        let mut log = RequestLog::default();
        for i in 0..(MAX_LOG_ENTRIES + 5) {
            let mut e = entry(Protocol::Http, peer(), "GET", &format!("/f{i}"));
            e.outcome = Outcome::Sent;
            e.bytes = 10;
            log.push(e);
        }
        let c = log.counts();
        assert_eq!(c.requests, (MAX_LOG_ENTRIES + 5) as u64);
        assert_eq!(c.dropped, 5);
        assert_eq!(c.bytes_sent, 10 * (MAX_LOG_ENTRIES + 5) as u64);
        let recent = log.recent(3);
        assert_eq!(recent[0].path, format!("/f{}", MAX_LOG_ENTRIES + 4));
        let text = log.text();
        assert!(text.contains("the first 5 requests are not kept"), "{text}");
        assert_eq!(text.lines().count(), 2 + MAX_LOG_ENTRIES);
    }

    #[test]
    fn logged_paths_are_safe_to_show() {
        assert_eq!(clean_path("/a\r\nb\u{202E}c"), "/a__b_c");
        let long = "a".repeat(500);
        assert_eq!(clean_path(&long).chars().count(), MAX_LOGGED_PATH + 1);
        assert!(!clean_path("/x?password=hunter2").contains("hunter2"));
    }

    #[test]
    fn the_summary_says_what_came_of_them() {
        let mut log = RequestLog::default();
        assert_eq!(log.summary(), "no requests");
        let mut sent = entry(Protocol::Tftp, peer(), "read", "fw.bin");
        sent.outcome = Outcome::Sent;
        sent.bytes = 2048;
        log.push(sent);
        let mut refused = entry(Protocol::Tftp, peer(), "read", "../x");
        refused.outcome = Outcome::Refused;
        log.push(refused);
        assert_eq!(log.summary(), "2 requests: 1 sent, 1 refused; 2 KB sent");
    }
}
