//! FD-09: the file server's request log. Kept so that nothing a client does can push a file it fetched or sent out of
//! the record:
//!
//! * **Transfers** (a request that reached a file, a folder listing or an upload: sent, received, or cut off on the
//!   way) are never dropped. Repeats of the same one (protocol, method, path, client and result) are summed into one
//!   row with a count and the bytes of all of them; past [`MAX_TRANSFER_ROWS`] rows, new ones are summed per file.
//! * **Refusals** (a path refused, a file not there, a malformed or slow request, a busy server) are folded into one
//!   row per client and protocol, with a count and the last path asked for; past [`MAX_REFUSAL_ROWS`] clients, the rest
//!   are only counted. So a flood of bogus datagrams (whose source TFTP can't check) costs a counter, not the record.
//! * Totals of everything.
//!
//! The window reads it while the server runs; the job keeps it whole as its output when the server stops (sized so
//! every transfer row fits, [`MAX_JOB_OUTPUT`]).

use std::collections::HashMap;
use std::net::SocketAddr;

use serde::Serialize;

use super::uploads::size_text;
use crate::export::redact_secrets;
use crate::untrusted::is_format_char;

/// Transfer rows kept with their client; past this, new ones are summed per file (any client).
pub const MAX_TRANSFER_ROWS: usize = 10_000;
/// Clients whose refusals get a row of their own; past this, refusals are only counted.
pub const MAX_REFUSAL_ROWS: usize = 1000;
/// The rows of each kind a status shows, newest first.
pub const STATUS_ROWS: usize = 200;
/// Refusal rows the job's output lists (the most frequent first); the rest are counted.
const JOB_REFUSAL_ROWS: usize = 200;
/// The job's output: every transfer row (at most [`MAX_TRANSFER_ROWS`] and the per-file sums, each line well under
/// 700 bytes) and the refusal rows fit.
pub const MAX_JOB_OUTPUT: usize = 8 * 1024 * 1024;
/// The longest path or detail a row keeps, in characters.
const MAX_LOGGED_PATH: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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

/// One request, as it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEntry {
    /// When it came (RFC 3339, UTC).
    pub at: String,
    pub protocol: Protocol,
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
    /// It reached a file, a listing or an upload (a transfer row), rather than being refused before.
    pub transfer: bool,
}

/// A row of the log: one request, or repeats of it summed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogRow {
    pub first_at: String,
    /// The last one's time.
    pub at: String,
    pub protocol: Protocol,
    /// The client's address (FD-03 masks it as an IP); empty for a row summed over clients.
    pub ip: String,
    /// The last one's port.
    pub port: u16,
    pub method: String,
    /// The path (for a refusal row: the last one asked for).
    pub path: String,
    /// Bytes of all of them.
    pub bytes: u64,
    pub outcome: Outcome,
    /// The last one's detail.
    pub detail: String,
    /// How many requests the row stands for.
    pub times: u64,
    /// When the row last changed, for "newest first".
    #[serde(skip)]
    touched: u64,
}

/// Totals over every request.
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
    /// Requests refused from clients past [`MAX_REFUSAL_ROWS`]: counted only.
    pub refusals_unlisted: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TransferKey {
    protocol: Protocol,
    method: String,
    path: String,
    /// Empty: summed over clients (past [`MAX_TRANSFER_ROWS`]).
    ip: String,
    outcome: Outcome,
}

#[derive(Debug, Default)]
pub struct RequestLog {
    transfers: Vec<LogRow>,
    transfer_keys: HashMap<TransferKey, usize>,
    refusals: Vec<LogRow>,
    refusal_keys: HashMap<(Protocol, String), usize>,
    counts: Counts,
    clock: u64,
}

impl RequestLog {
    pub fn push(&mut self, entry: RequestEntry) {
        self.clock += 1;
        let c = &mut self.counts;
        c.requests += 1;
        let upload = entry.method == "write" || entry.method == "PUT";
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
                if !upload {
                    c.bytes_sent = c.bytes_sent.saturating_add(entry.bytes);
                }
            }
        }
        let transfer = entry.transfer || matches!(entry.outcome, Outcome::Sent | Outcome::Received);
        if transfer {
            self.push_transfer(entry);
        } else {
            self.push_refusal(entry);
        }
    }

    fn push_transfer(&mut self, entry: RequestEntry) {
        let mut key = TransferKey {
            protocol: entry.protocol,
            method: entry.method.clone(),
            path: entry.path.clone(),
            ip: entry.ip.clone(),
            outcome: entry.outcome,
        };
        // A new row past the cap is summed per file instead.
        if !self.transfer_keys.contains_key(&key) && self.transfers.len() >= MAX_TRANSFER_ROWS {
            key.ip = String::new();
        }
        match self.transfer_keys.get(&key) {
            Some(&i) => {
                let row = &mut self.transfers[i];
                row.at = entry.at;
                row.port = entry.port;
                row.bytes = row.bytes.saturating_add(entry.bytes);
                row.detail = entry.detail;
                row.times += 1;
                row.touched = self.clock;
            }
            None => {
                self.transfer_keys.insert(key.clone(), self.transfers.len());
                self.transfers.push(LogRow {
                    first_at: entry.at.clone(),
                    at: entry.at,
                    protocol: entry.protocol,
                    ip: key.ip,
                    port: entry.port,
                    method: entry.method,
                    path: entry.path,
                    bytes: entry.bytes,
                    outcome: entry.outcome,
                    detail: entry.detail,
                    times: 1,
                    touched: self.clock,
                });
            }
        }
    }

    fn push_refusal(&mut self, entry: RequestEntry) {
        let key = (entry.protocol, entry.ip.clone());
        match self.refusal_keys.get(&key) {
            Some(&i) => {
                let row = &mut self.refusals[i];
                row.at = entry.at;
                row.port = entry.port;
                row.method = entry.method;
                row.path = entry.path;
                row.detail = entry.detail;
                row.outcome = entry.outcome;
                row.times += 1;
                row.touched = self.clock;
            }
            None if self.refusals.len() >= MAX_REFUSAL_ROWS => {
                self.counts.refusals_unlisted += 1;
            }
            None => {
                self.refusal_keys.insert(key, self.refusals.len());
                self.refusals.push(LogRow {
                    first_at: entry.at.clone(),
                    at: entry.at,
                    protocol: entry.protocol,
                    ip: entry.ip,
                    port: entry.port,
                    method: entry.method,
                    path: entry.path,
                    bytes: 0,
                    outcome: entry.outcome,
                    detail: entry.detail,
                    times: 1,
                    touched: self.clock,
                });
            }
        }
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    pub fn transfer_rows(&self) -> usize {
        self.transfers.len()
    }

    pub fn refusal_rows(&self) -> usize {
        self.refusals.len()
    }

    /// The `n` transfer rows that changed last, newest first.
    pub fn recent_transfers(&self, n: usize) -> Vec<LogRow> {
        newest(&self.transfers, n)
    }

    /// The `n` refusal rows that changed last, newest first.
    pub fn recent_refusals(&self, n: usize) -> Vec<LogRow> {
        newest(&self.refusals, n)
    }

    /// The log as the job keeps it: the totals, every transfer row in the order they first came, then the refusals
    /// by client, the most frequent first.
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
        text.push_str(&format!(
            "transfers ({}; repeats summed):\n",
            plural(self.transfers.len() as u64, "row", "rows")
        ));
        for row in &self.transfers {
            let client = if row.ip.is_empty() {
                "(clients summed)".to_owned()
            } else {
                format!("{}:{}", row.ip, row.port)
            };
            let times = if row.times > 1 {
                format!(" ×{} since {}", row.times, row.first_at)
            } else {
                String::new()
            };
            text.push_str(&format!(
                "{} {} {} {client} {} {} {}{times}{}\n",
                row.at,
                row.protocol.label(),
                row.method,
                shown_path(&row.path),
                outcome_word(row.outcome),
                size_text(row.bytes),
                detail_text(&row.detail),
            ));
        }
        if !self.refusals.is_empty() || c.refusals_unlisted > 0 {
            text.push_str("refused or failed before a transfer, by client:\n");
            let mut rows: Vec<&LogRow> = self.refusals.iter().collect();
            rows.sort_by_key(|r| std::cmp::Reverse(r.times));
            for row in rows.iter().take(JOB_REFUSAL_ROWS) {
                text.push_str(&format!(
                    "{} {}: {} from {} to {}; last {} {}{}\n",
                    row.ip,
                    row.protocol.label(),
                    plural(row.times, "request", "requests"),
                    row.first_at,
                    row.at,
                    row.method,
                    shown_path(&row.path),
                    detail_text(&row.detail),
                ));
            }
            let rest = rows.len().saturating_sub(JOB_REFUSAL_ROWS);
            if rest > 0 {
                let more: u64 = rows.iter().skip(JOB_REFUSAL_ROWS).map(|r| r.times).sum();
                text.push_str(&format!(
                    "and {} from {} more clients\n",
                    plural(more, "request", "requests"),
                    rest
                ));
            }
            if c.refusals_unlisted > 0 {
                text.push_str(&format!(
                    "and {} from clients past the first {MAX_REFUSAL_ROWS}, counted only\n",
                    plural(c.refusals_unlisted, "request", "requests")
                ));
            }
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

fn newest(rows: &[LogRow], n: usize) -> Vec<LogRow> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_unstable_by_key(|i| std::cmp::Reverse(rows[*i].touched));
    order.into_iter().take(n).map(|i| rows[i].clone()).collect()
}

fn shown_path(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

fn detail_text(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(" ({detail})")
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

/// A request's path or detail as the log keeps it: what the client sent, made safe to show and keep.
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
        transfer: false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn peer(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, last], port))
    }

    fn done(mut e: RequestEntry, outcome: Outcome, bytes: u64) -> RequestEntry {
        e.outcome = outcome;
        e.bytes = bytes;
        e
    }

    #[test]
    fn a_flood_of_refusals_never_pushes_a_transfer_out() {
        let mut log = RequestLog::default();
        log.push(done(
            entry(Protocol::Tftp, peer(7, 50000), "read", "secrets.zip"),
            Outcome::Sent,
            4096,
        ));
        for i in 0..20_000u32 {
            // Spoofed sources: a new address for every datagram.
            let ip = SocketAddr::from(([198, 51, (i / 250) as u8, (i % 250) as u8], 1024));
            log.push(done(entry(Protocol::Tftp, ip, "read", "../x"), Outcome::Refused, 0));
        }
        let c = log.counts();
        assert_eq!(c.requests, 20_001);
        assert_eq!(c.refused, 20_000);
        assert_eq!(
            log.refusal_rows(),
            MAX_REFUSAL_ROWS,
            "one row per client, up to the cap"
        );
        assert_eq!(c.refusals_unlisted, 20_000 - MAX_REFUSAL_ROWS as u64);
        assert_eq!(log.transfer_rows(), 1);
        assert_eq!(log.recent_transfers(10)[0].path, "secrets.zip");
        let text = log.text();
        assert!(
            text.contains("secrets.zip sent 4 KB"),
            "{}",
            &text[..text.len().min(500)]
        );
        assert!(text.contains("counted only"));
        assert!(text.len() < MAX_JOB_OUTPUT);
    }

    #[test]
    fn repeats_are_summed_and_refusals_folded_per_client() {
        let mut log = RequestLog::default();
        for port in 0..5u16 {
            log.push(done(
                entry(Protocol::Http, peer(7, 40000 + port), "GET", "/fw.bin"),
                Outcome::Sent,
                100,
            ));
        }
        log.push(done(
            entry(Protocol::Http, peer(8, 40000), "GET", "/fw.bin"),
            Outcome::Sent,
            100,
        ));
        let mut cut = entry(Protocol::Tftp, peer(7, 1), "write", "half.bin");
        cut.transfer = true;
        log.push(done(cut, Outcome::Failed, 512));
        for _ in 0..3 {
            log.push(done(
                entry(Protocol::Http, peer(9, 1), "GET", "/../secret"),
                Outcome::Refused,
                0,
            ));
        }
        log.push(done(
            entry(Protocol::Http, peer(9, 1), "GET", "/other"),
            Outcome::Refused,
            0,
        ));
        assert_eq!(log.transfer_rows(), 3);
        let rows = log.recent_transfers(10);
        let summed = rows
            .iter()
            .find(|r| r.ip == "192.0.2.7" && r.path == "/fw.bin")
            .unwrap();
        assert_eq!((summed.times, summed.bytes, summed.port), (5, 500, 40004));
        assert!(rows
            .iter()
            .any(|r| r.path == "half.bin" && r.outcome == Outcome::Failed));
        assert_eq!(log.refusal_rows(), 1);
        let refusal = &log.recent_refusals(1)[0];
        assert_eq!((refusal.times, refusal.path.as_str()), (4, "/other"));
        assert_eq!(log.recent_transfers(1)[0].path, "half.bin", "newest first");
        let text = log.text();
        assert!(text.contains("×5 since"), "{text}");
        assert!(text.contains("192.0.2.9 HTTP: 4 requests"), "{text}");
    }

    #[test]
    fn past_the_row_cap_transfers_are_summed_per_file() {
        let mut log = RequestLog::default();
        for i in 0..(MAX_TRANSFER_ROWS as u32 + 50) {
            let ip = SocketAddr::from(([10, (i / 65536) as u8, (i / 256 % 256) as u8, (i % 256) as u8], 1));
            log.push(done(entry(Protocol::Tftp, ip, "read", "fw.bin"), Outcome::Sent, 1));
        }
        assert_eq!(log.transfer_rows(), MAX_TRANSFER_ROWS + 1);
        let summed = log.recent_transfers(1);
        assert_eq!((summed[0].ip.as_str(), summed[0].times), ("", 50));
        assert!(log.text().len() < MAX_JOB_OUTPUT);
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
        log.push(done(
            entry(Protocol::Tftp, peer(7, 1), "read", "fw.bin"),
            Outcome::Sent,
            2048,
        ));
        log.push(done(
            entry(Protocol::Tftp, peer(7, 1), "read", "../x"),
            Outcome::Refused,
            0,
        ));
        assert_eq!(log.summary(), "2 requests: 1 sent, 1 refused; 2 KB sent");
    }
}
