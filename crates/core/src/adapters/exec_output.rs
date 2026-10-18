//! What a remote command printed (BX-02, BX-03, BX-07), collected as it streams in.
//!
//! * Vault secrets used for the run (the sudo password, the login password) are replaced by
//!   `[redacted]` before anything else sees the bytes, even when a secret arrives split across two
//!   reads. The hashes and the stored text are taken after that, so neither can give a secret away.
//! * Each stream keeps its first and last [`MAX_OUTPUT_PER_STREAM`]` / 2` bytes; a longer output is
//!   cut in the middle, and the cut is marked in the text and flagged.
//! * Grouping needs the whole output, not the stored part, so each stream is hashed as it arrives:
//!   exactly, and with trailing whitespace ignored (spaces, tabs and `\r` at line ends, and blank
//!   lines at the end).

use std::collections::VecDeque;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vault::SecretString;

/// Bytes kept per stream (stdout, stderr) for each host: the first half and the last half.
pub const MAX_OUTPUT_PER_STREAM: usize = 64 * 1024;

/// What a scrubbed secret reads as.
pub const REDACTED: &str = "[redacted]";

/// Replaces secrets in a byte stream. Holds back the last few bytes of each read until it knows they
/// don't start a secret.
pub struct Scrubber {
    secrets: Vec<Zeroizing<Vec<u8>>>,
    longest: usize,
    pending: Zeroizing<Vec<u8>>,
    replacement: &'static [u8],
    found: usize,
}

impl Scrubber {
    /// Replaces each secret with `[redacted]`.
    pub fn new(secrets: &[&SecretString]) -> Self {
        Self::replacing(secrets, REDACTED.as_bytes())
    }

    /// Removes `marker` wherever it appears and counts it (BX-07: sudo's prompt).
    pub fn remover(marker: &str) -> Self {
        Self::replacing(&[&SecretString::new(marker)], b"")
    }

    fn replacing(secrets: &[&SecretString], replacement: &'static [u8]) -> Self {
        let mut secrets: Vec<Zeroizing<Vec<u8>>> = secrets
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| Zeroizing::new(s.expose().as_bytes().to_vec()))
            .collect();
        // Longest first, so a secret that contains another is replaced whole.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup_by(|a, b| a.as_slice() == b.as_slice());
        let longest = secrets.first().map_or(0, |s| s.len());
        Self {
            secrets,
            longest,
            pending: Zeroizing::new(Vec::new()),
            replacement,
            found: 0,
        }
    }

    /// How many times a secret was found so far.
    pub fn found(&self) -> usize {
        self.found
    }

    /// Scrubs `data` and appends what is safe to pass on to `out`.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<u8>) {
        if self.secrets.is_empty() {
            out.extend_from_slice(data);
            return;
        }
        self.pending.extend_from_slice(data);
        let mut at = 0;
        while let Some((pos, len)) = self.next_match(at) {
            out.extend_from_slice(&self.pending[at..pos]);
            out.extend_from_slice(self.replacement);
            self.found += 1;
            at = pos + len;
        }
        // The last `longest - 1` bytes may be the start of a secret that the next read completes.
        let keep_from = at.max(self.pending.len().saturating_sub(self.longest - 1));
        out.extend_from_slice(&self.pending[at..keep_from]);
        self.pending.drain(..keep_from);
    }

    /// The bytes held back; they can't hold a whole secret.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pending);
        self.pending.clear();
    }

    /// The first secret in `pending[from..]`: its position and length.
    fn next_match(&self, from: usize) -> Option<(usize, usize)> {
        let hay = &self.pending[from..];
        self.secrets
            .iter()
            .filter_map(|secret| find(hay, secret).map(|pos| (from + pos, secret.len())))
            .min_by_key(|(pos, len)| (*pos, std::cmp::Reverse(*len)))
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// SHA-256 of a stream with trailing whitespace ignored: spaces, tabs and `\r` at the end of each
/// line, and empty lines at the end. Streams in, so it never holds more than one run of whitespace.
#[derive(Default)]
struct LooseHasher {
    hash: Sha256,
    /// Whitespace since the last other byte on this line; kept only if more text follows on the line.
    spaces: Vec<u8>,
    /// Line breaks not yet hashed: only hashed once more text follows.
    newlines: usize,
}

impl LooseHasher {
    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            match byte {
                b'\n' => {
                    self.spaces.clear();
                    self.newlines += 1;
                }
                b' ' | b'\t' | b'\r' => self.spaces.push(byte),
                _ => {
                    for _ in 0..self.newlines {
                        self.hash.update(b"\n");
                    }
                    self.newlines = 0;
                    self.hash.update(&self.spaces);
                    self.spaces.clear();
                    self.hash.update([byte]);
                }
            }
        }
    }

    fn finish(self) -> [u8; 32] {
        self.hash.finalize().into()
    }
}

/// One stream (stdout or stderr): its first and last bytes, its size and its hashes.
struct Capture {
    half: usize,
    head: Vec<u8>,
    /// The last `half` bytes of the stream so far.
    tail: VecDeque<u8>,
    total: usize,
    exact: Sha256,
    loose: LooseHasher,
}

impl Capture {
    fn new(max: usize) -> Self {
        Self {
            half: (max / 2).max(1),
            head: Vec::new(),
            tail: VecDeque::new(),
            total: 0,
            exact: Sha256::new(),
            loose: LooseHasher::default(),
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.exact.update(data);
        self.loose.update(data);
        self.total += data.len();
        let room = self.half - self.head.len();
        self.head.extend_from_slice(&data[..room.min(data.len())]);
        let last = &data[data.len().saturating_sub(self.half)..];
        self.tail.extend(last);
        let excess = self.tail.len().saturating_sub(self.half);
        self.tail.drain(..excess);
    }

    fn finish(self) -> (StreamText, [u8; 32], [u8; 32]) {
        let after_head = self.total - self.head.len();
        let (text, truncated) = if after_head <= self.half {
            // Nothing was dropped: the head, then what followed it (all still in the tail).
            let mut bytes = self.head;
            bytes.extend(self.tail.range(self.tail.len() - after_head..));
            (String::from_utf8_lossy(&bytes).into_owned(), false)
        } else {
            let cut = self.total - self.head.len() - self.tail.len();
            let tail: Vec<u8> = self.tail.into_iter().collect();
            let text = format!(
                "{}\n… [Remotely cut {} from the middle: the output was {}] …\n{}",
                String::from_utf8_lossy(&self.head),
                human_bytes(cut),
                human_bytes(self.total),
                String::from_utf8_lossy(&tail)
            );
            (text, true)
        };
        (
            StreamText {
                text,
                bytes: self.total as u64,
                truncated,
            },
            self.exact.finalize().into(),
            self.loose.finish(),
        )
    }
}

struct StreamText {
    text: String,
    bytes: u64,
    truncated: bool,
}

/// "512 bytes", "64 KB", "1.2 MB".
pub fn human_bytes(n: usize) -> String {
    const KB: f64 = 1024.0;
    let n_f = n as f64;
    if n < 1024 {
        format!("{n} bytes")
    } else if n_f < KB * KB {
        format!("{:.0} KB", n_f / KB)
    } else {
        format!("{:.1} MB", n_f / (KB * KB))
    }
}

/// A command's output once it has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedOutput {
    pub stdout: String,
    pub stderr: String,
    /// Bytes each stream sent (after scrubbing).
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    /// Either stream was cut in the middle.
    pub truncated: bool,
    /// Hex SHA-256 over both whole streams, exactly.
    pub hash: String,
    /// The same, with trailing whitespace ignored.
    pub hash_loose: String,
}

/// Scrubs, caps and hashes stdout and stderr as they arrive.
pub struct OutputCollector {
    scrub_out: Scrubber,
    scrub_err: Scrubber,
    stdout: Capture,
    stderr: Capture,
    buf: Vec<u8>,
}

impl OutputCollector {
    /// `secrets`: replaced by `[redacted]` wherever they appear. `max_per_stream`: bytes kept per stream.
    pub fn new(secrets: &[&SecretString], max_per_stream: usize) -> Self {
        Self {
            scrub_out: Scrubber::new(secrets),
            scrub_err: Scrubber::new(secrets),
            stdout: Capture::new(max_per_stream),
            stderr: Capture::new(max_per_stream),
            buf: Vec::new(),
        }
    }

    pub fn stdout(&mut self, data: &[u8]) {
        self.buf.clear();
        self.scrub_out.push(data, &mut self.buf);
        self.stdout.push(&self.buf);
    }

    pub fn stderr(&mut self, data: &[u8]) {
        self.buf.clear();
        self.scrub_err.push(data, &mut self.buf);
        self.stderr.push(&self.buf);
    }

    pub fn finish(mut self) -> CollectedOutput {
        self.buf.clear();
        self.scrub_out.finish(&mut self.buf);
        self.stdout.push(&self.buf);
        self.buf.clear();
        self.scrub_err.finish(&mut self.buf);
        self.stderr.push(&self.buf);
        let (out, out_exact, out_loose) = self.stdout.finish();
        let (err, err_exact, err_loose) = self.stderr.finish();
        let combine = |a: &[u8; 32], b: &[u8; 32]| {
            let mut hash = Sha256::new();
            hash.update(b"stdout");
            hash.update(a);
            hash.update(b"stderr");
            hash.update(b);
            hex::encode(hash.finalize())
        };
        CollectedOutput {
            hash: combine(&out_exact, &err_exact),
            hash_loose: combine(&out_loose, &err_loose),
            truncated: out.truncated || err.truncated,
            stdout_bytes: out.bytes,
            stderr_bytes: err.bytes,
            stdout: out.text,
            stderr: err.text,
        }
    }

    /// The whole output at once (fakes, tests).
    pub fn collect(stdout: &[u8], stderr: &[u8], secrets: &[&SecretString], max_per_stream: usize) -> CollectedOutput {
        let mut collector = Self::new(secrets, max_per_stream);
        collector.stdout(stdout);
        collector.stderr(stderr);
        collector.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrub_in_pieces(text: &str, secrets: &[&str], piece: usize) -> String {
        let secrets: Vec<SecretString> = secrets.iter().map(|s| SecretString::new(*s)).collect();
        let refs: Vec<&SecretString> = secrets.iter().collect();
        let mut scrubber = Scrubber::new(&refs);
        let mut out = Vec::new();
        for chunk in text.as_bytes().chunks(piece) {
            scrubber.push(chunk, &mut out);
        }
        scrubber.finish(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn secrets_are_scrubbed_even_when_split_across_reads() {
        let text = "before s3cr3t-pw middle s3cr3t-pw end";
        for piece in 1..=text.len() {
            assert_eq!(
                scrub_in_pieces(text, &["s3cr3t-pw"], piece),
                "before [redacted] middle [redacted] end",
                "read {piece} bytes at a time"
            );
        }
    }

    #[test]
    fn several_secrets_and_overlaps_are_scrubbed() {
        assert_eq!(
            scrub_in_pieces("a-login-pw b-sudo-pw", &["sudo-pw", "login-pw"], 3),
            "a-[redacted] b-[redacted]"
        );
        // One secret inside another: the longer one is replaced whole.
        assert_eq!(
            scrub_in_pieces("xx hunter22 xx", &["hunter2", "hunter22"], 4),
            "xx [redacted] xx"
        );
        assert_eq!(scrub_in_pieces("aaaa", &["aa"], 1), "[redacted][redacted]");
        // A near miss at the end is passed on once the stream ends.
        assert_eq!(
            scrub_in_pieces("ends with s3cr3t-p", &["s3cr3t-pw"], 5),
            "ends with s3cr3t-p"
        );
    }

    #[test]
    fn no_secret_passes_through_untouched() {
        assert_eq!(scrub_in_pieces("plain text", &[], 2), "plain text");
        assert_eq!(scrub_in_pieces("plain text", &[""], 2), "plain text");
    }

    #[test]
    fn short_output_is_kept_whole() {
        let out = OutputCollector::collect(b"hello\n", b"warn\n", &[], 64);
        assert_eq!(out.stdout, "hello\n");
        assert_eq!(out.stderr, "warn\n");
        assert_eq!((out.stdout_bytes, out.stderr_bytes, out.truncated), (6, 5, false));
    }

    #[test]
    fn output_of_exactly_the_cap_is_not_cut() {
        let text: String = (0..64).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
        let mut collector = OutputCollector::new(&[], 64);
        for chunk in text.as_bytes().chunks(7) {
            collector.stdout(chunk);
        }
        let out = collector.finish();
        assert_eq!(out.stdout, text);
        assert!(!out.truncated);
    }

    #[test]
    fn long_output_keeps_its_start_and_end() {
        let lines: String = (1..=1000).map(|i| format!("line {i}\n")).collect();
        let mut collector = OutputCollector::new(&[], 200);
        for chunk in lines.as_bytes().chunks(13) {
            collector.stdout(chunk);
        }
        let out = collector.finish();
        assert!(out.truncated);
        assert_eq!(out.stdout_bytes, lines.len() as u64);
        assert!(out.stdout.starts_with("line 1\nline 2\n"), "{}", out.stdout);
        assert!(out.stdout.ends_with("line 999\nline 1000\n"), "{}", out.stdout);
        assert!(out.stdout.contains("Remotely cut"), "{}", out.stdout);
        assert!(!out.stdout.contains("line 500\n"));
        // The hash covers everything, not just what was kept.
        let whole = OutputCollector::collect(lines.as_bytes(), b"", &[], 1 << 20);
        assert_eq!(out.hash, whole.hash);
    }

    #[test]
    fn hashes_tell_outputs_apart_and_loose_ones_ignore_trailing_whitespace() {
        let a = OutputCollector::collect(b"ok\nload 0.1\n", b"", &[], 1024);
        let same = OutputCollector::collect(b"ok\nload 0.1\n", b"", &[], 1024);
        let spaced = OutputCollector::collect(b"ok   \r\nload 0.1\t\n\n\n", b"", &[], 1024);
        let other = OutputCollector::collect(b"ok\nload 0.2\n", b"", &[], 1024);
        let on_stderr = OutputCollector::collect(b"", b"ok\nload 0.1\n", &[], 1024);
        let inner_space = OutputCollector::collect(b"ok\nload  0.1\n", b"", &[], 1024);
        let blank_line = OutputCollector::collect(b"ok\n\nload 0.1\n", b"", &[], 1024);
        assert_eq!(a.hash, same.hash);
        assert_ne!(a.hash, spaced.hash);
        assert_eq!(a.hash_loose, spaced.hash_loose);
        assert_ne!(a.hash_loose, other.hash_loose);
        assert_ne!(a.hash, on_stderr.hash, "stdout and stderr are told apart");
        assert_ne!(
            a.hash_loose, inner_space.hash_loose,
            "only trailing whitespace is ignored"
        );
        assert_ne!(
            a.hash_loose, blank_line.hash_loose,
            "blank lines inside the output count"
        );
    }

    #[test]
    fn secrets_never_reach_the_text_or_the_hash() {
        let pw = SecretString::new("pw-7f3a9");
        let leaked = OutputCollector::collect(b"echo pw-7f3a9\n", b"pw-7f3a9", &[&pw], 1024);
        assert_eq!(leaked.stdout, "echo [redacted]\n");
        assert_eq!(leaked.stderr, "[redacted]");
        let typed = OutputCollector::collect(b"echo [redacted]\n", b"[redacted]", &[], 1024);
        assert_eq!(leaked.hash, typed.hash, "hashed after scrubbing");
    }

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(human_bytes(12), "12 bytes");
        assert_eq!(human_bytes(64 * 1024), "64 KB");
        assert_eq!(human_bytes(3 * 1024 * 1024 + 300 * 1024), "3.3 MB");
    }
}
