//! FD-04: one host's part of a bundle. [`collect_host`] goes through the bundle's items on a [`BundleHost`] (how a
//! kind of host runs a command and reads a file: [`SshHost`] today, F8's Windows hosts later) and puts each result
//! into the zip as it comes:
//!
//! * Caps: [`MAX_FILE_BYTES`] a file (an output keeps its start and end, a file its start), [`MAX_HOST_BYTES`] a host
//!   and [`MAX_BUNDLE_BYTES`] the bundle. What doesn't fit is cut or left out, and the manifest says which.
//! * Every file is text and scrubbed: the connection's vault secrets (the login and sudo passwords) through
//!   `exec_output`'s scrubber, then what looks like a password, a token or a private key ([`redact_secrets`] and PEM
//!   blocks). A file that isn't text (a NUL byte in it) can't be checked, so it is left out.
//! * A command that fails (an exit code, not found) or a file that can't be read is noted, and the host goes on; a
//!   connection that drops, or sudo refusing its password, ends the host.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use regex::Regex;
use sha2::{Digest, Sha256};

use super::presets::HostKind;
use super::spec::{BundleItem, MAX_BUNDLE_BYTES, MAX_FILE_BYTES, MAX_HOST_BYTES};
use super::writer::{blocking, ItemRecord, OpenBundle};
use crate::adapters::exec_output::{human_bytes, Scrubber, REDACTED};
use crate::adapters::remote::{EntryKind, ExecResult, ExecSession, RemoteFiles};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::vault::SecretString;

/// Room kept below a file's cap for the note that marks where an output was cut.
const CUT_NOTE_ROOM: u64 = 256;
/// Bytes read from a host's file at a time.
const READ_CHUNK: usize = 64 * 1024;

/// What was read of a file on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRead {
    pub bytes: Vec<u8>,
    /// The file's size on the host. A file that says 0 (`/proc`) counts what was read.
    pub size: u64,
    /// More was there than was read.
    pub more: bool,
}

/// FD-04: how one kind of host gives a bundle its commands' output and its files. F8 adds Windows hosts (PowerShell
/// over WinRM) as another implementation, with its own presets ([`HostKind`]).
#[async_trait]
pub trait BundleHost: Send + Sync {
    fn kind(&self) -> HostKind;
    /// `user@host:port`, and the jump hosts on the way, for the manifest.
    fn address(&self) -> String;
    /// The address this PC reached, if it reached the host itself.
    fn peer_ip(&self) -> Option<IpAddr>;
    /// Runs one command; each stream keeps its first and last halves of `max_bytes`.
    async fn run(&self, command: &str, max_bytes: usize) -> Result<ExecResult>;
    /// Reads a file's first `max_bytes`.
    async fn read(&self, path: &str, max_bytes: u64) -> Result<FileRead>;
    /// The secrets this connection knows (login, sudo), scrubbed from everything it gives.
    fn secrets(&self) -> &[SecretString];
    /// The connection dropped: the host's other items can't run.
    fn lost(&self) -> bool;
}

/// A Linux host over SSH: commands on exec channels of one kept connection (under sudo when the bundle says so,
/// BX-07), files over SFTP on the same connection as the login user.
pub struct SshHost {
    session: Box<dyn ExecSession>,
    files: Option<Arc<dyn RemoteFiles>>,
    address: String,
    sudo: Option<SecretString>,
    secrets: Vec<SecretString>,
}

impl SshHost {
    /// `secrets`: the login password, if the session has one (the sudo password is added).
    pub fn new(
        session: Box<dyn ExecSession>,
        address: String,
        sudo: Option<SecretString>,
        mut secrets: Vec<SecretString>,
    ) -> Self {
        secrets.extend(sudo.iter().cloned());
        Self {
            files: session.files(),
            session,
            address,
            sudo,
            secrets,
        }
    }

    pub async fn close(&self) {
        self.session.close().await;
    }
}

#[async_trait]
impl BundleHost for SshHost {
    fn kind(&self) -> HostKind {
        HostKind::Linux
    }

    fn address(&self) -> String {
        self.address.clone()
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.session.peer_ip()
    }

    async fn run(&self, command: &str, max_bytes: usize) -> Result<ExecResult> {
        match &self.sudo {
            Some(password) => self.session.run_sudo(command, password, max_bytes).await,
            None => self.session.run(command, max_bytes).await,
        }
    }

    async fn read(&self, path: &str, max_bytes: u64) -> Result<FileRead> {
        let files = self
            .files
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("this connection has no SFTP to read files with".into()))?;
        let entry = files
            .stat(path)
            .await?
            .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
        match entry.kind {
            EntryKind::File => {}
            EntryKind::Folder => return Err(CoreError::InvalidInput("it is a folder".into())),
            EntryKind::Other => return Err(CoreError::InvalidInput("it is not a regular file".into())),
        }
        let mut reader = files.read(path).await?;
        let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        let mut bytes = Vec::with_capacity(cap.min(usize::try_from(entry.size).unwrap_or(cap)).min(cap));
        let mut buf = vec![0; READ_CHUNK];
        while bytes.len() < cap {
            let room = (cap - bytes.len()).min(buf.len());
            let n = reader.read(&mut buf[..room]).await?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
        }
        // At the cap: one more byte says whether the file goes on (a /proc file's size says 0).
        let more = bytes.len() >= cap && reader.read(&mut buf[..1]).await? > 0;
        Ok(FileRead {
            size: entry.size.max(bytes.len() as u64),
            bytes,
            more,
        })
    }

    fn secrets(&self) -> &[SecretString] {
        &self.secrets
    }

    fn lost(&self) -> bool {
        self.session.is_closed()
    }
}

/// What one host gave.
#[derive(Debug, Clone, Default)]
pub struct HostReport {
    /// Files saved.
    pub saved: usize,
    /// Items that gave nothing (a failed command still saves its output, and counts as saved).
    pub failed: usize,
    pub bytes: u64,
    /// One line per item, for the job's journal (Activity shows it as the host's output).
    pub lines: Vec<String>,
}

/// PEM private keys: a whole block, or one cut off at the end of what was kept.
#[allow(clippy::expect_used)]
static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)")
        .expect("valid private key pattern")
});

/// Scrubs the connection's secrets from `bytes`, then redacts what looks like a password, a token or a private key.
/// Returns the text and how many places read `[redacted]`.
pub fn redact(bytes: &[u8], secrets: &[SecretString]) -> (String, usize) {
    let refs: Vec<&SecretString> = secrets.iter().collect();
    let mut scrubber = Scrubber::new(&refs);
    let mut out = Vec::with_capacity(bytes.len());
    scrubber.push(bytes, &mut out);
    scrubber.finish(&mut out);
    let text = String::from_utf8_lossy(&out);
    let keys = PRIVATE_KEY.replace_all(&text, format!("${{1}}\n{REDACTED}\n${{2}}"));
    let (text, _) = redact_secrets(&keys);
    let count = text.matches(REDACTED).count();
    (text, count)
}

/// At most `cap` bytes of `text`, cut on a character boundary with a note at the cut. Returns whether it was cut.
fn fit(text: &mut String, cap: u64, why: &str) -> bool {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    if text.len() <= cap {
        return false;
    }
    let note = format!("\n… [Remotely cut the rest: {why}] …\n");
    let mut end = cap.saturating_sub(note.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(&note);
    true
}

/// Why an item gets no room, once a cap is reached.
fn no_room(host_left: u64) -> String {
    if host_left == 0 {
        format!(
            "left out: the host's {} were reached",
            human_bytes(MAX_HOST_BYTES as usize)
        )
    } else {
        format!(
            "left out: the bundle's {} were reached",
            human_bytes(MAX_BUNDLE_BYTES as usize)
        )
    }
}

/// Collects `items` (saved under `names` in the host's folder) from one host into the bundle. An error means the
/// host stopped (its connection dropped, sudo refused its password); what it gave until then stays in the bundle.
pub async fn collect_host(
    bundle: &Arc<OpenBundle>,
    key: &str,
    host: &dyn BundleHost,
    items: &[BundleItem],
    names: &[String],
) -> Result<HostReport> {
    let folder = bundle
        .folder(key)
        .ok_or_else(|| CoreError::UnknownTarget(key.to_owned()))?;
    bundle.record_address(key, host.address(), host.peer_ip().map(|ip| ip.to_string()));
    let mut report = HostReport::default();
    for (item, name) in items.iter().zip(names) {
        let source = match item {
            BundleItem::Command { command } => redact_secrets(command).0,
            BundleItem::File { path } => path.clone(),
        };
        let mut record = ItemRecord {
            kind: match item {
                BundleItem::Command { .. } => "command",
                BundleItem::File { .. } => "file",
            },
            source: source.clone(),
            ..ItemRecord::default()
        };
        let host_left = MAX_HOST_BYTES.saturating_sub(report.bytes);
        let granted = bundle.reserve(MAX_FILE_BYTES.min(host_left));
        if granted == 0 {
            record.error = Some(no_room(host_left));
            report.failed += 1;
            report.lines.push(format!("{source}: {}", no_room(host_left)));
            bundle.record_item(key, record);
            continue;
        }
        let bytes = match item {
            BundleItem::Command { command } => {
                let max = usize::try_from(granted.saturating_sub(CUT_NOTE_ROOM).max(1)).unwrap_or(usize::MAX);
                match host.run(command, max).await {
                    Ok(result) => command_text(result, &mut record),
                    Err(err) => {
                        bundle.release(granted);
                        if matches!(err, CoreError::SudoPasswordRefused) || host.lost() {
                            bundle.record_item(key, failed(record, &err));
                            return Err(err);
                        }
                        report.failed += 1;
                        report.lines.push(format!("{source}: {err}"));
                        bundle.record_item(key, failed(record, &err));
                        continue;
                    }
                }
            }
            BundleItem::File { path } => match host.read(path, granted).await {
                Ok(read) if read.bytes.contains(&0) => {
                    bundle.release(granted);
                    let why = "left out: it isn't text, so Remotely can't check it for secrets";
                    record.error = Some(why.into());
                    record.original_bytes = Some(read.size);
                    report.failed += 1;
                    report.lines.push(format!("{source}: {why}"));
                    bundle.record_item(key, record);
                    continue;
                }
                Ok(read) => {
                    if read.more {
                        record.original_bytes = Some(read.size);
                        record.cut = Some(format!(
                            "the file is {}; its first {} are kept",
                            human_bytes(read.size as usize),
                            human_bytes(read.bytes.len())
                        ));
                    }
                    read.bytes
                }
                Err(err) => {
                    bundle.release(granted);
                    if host.lost() {
                        bundle.record_item(key, failed(record, &err));
                        return Err(err);
                    }
                    report.failed += 1;
                    report.lines.push(format!("{source}: {err}"));
                    bundle.record_item(key, failed(record, &err));
                    continue;
                }
            },
        };
        let (mut text, redacted) = redact(&bytes, host.secrets());
        if fit(&mut text, granted, "a file keeps at most what fits the bundle's limits") {
            record.original_bytes.get_or_insert(bytes.len() as u64);
            record.cut.get_or_insert_with(|| {
                format!(
                    "cut to {}, what fits the bundle's limits",
                    human_bytes(granted as usize)
                )
            });
        }
        let data = text.into_bytes();
        let stored = data.len() as u64;
        let sha256 = hex::encode(Sha256::digest(&data));
        bundle.release(granted.saturating_sub(stored));
        let entry = format!("{folder}/{name}");
        let written = {
            let entry = entry.clone();
            blocking(bundle, move |b| b.add(&entry, &data)).await
        };
        if let Err(err) = written {
            bundle.release(stored);
            bundle.record_item(key, failed(record, &err));
            return Err(err);
        }
        record.file = Some(entry);
        record.bytes = stored;
        record.sha256 = Some(sha256);
        record.redacted = redacted;
        report.saved += 1;
        report.bytes += stored;
        report.lines.push(describe(&record));
        bundle.record_item(key, record);
    }
    Ok(report)
}

fn failed(mut record: ItemRecord, err: &CoreError) -> ItemRecord {
    record.error = Some(redact_secrets(&err.to_string()).0);
    record
}

/// A command's output as one text: stdout, then stderr under a line that says so.
fn command_text(result: ExecResult, record: &mut ItemRecord) -> Vec<u8> {
    let ExecResult {
        exit_code,
        signal,
        output,
        duration_ms,
        ..
    } = result;
    record.exit_code = exit_code.map(i64::from);
    record.signal = signal;
    record.duration_ms = Some(duration_ms);
    if output.truncated {
        let whole = output.stdout_bytes + output.stderr_bytes;
        record.original_bytes = Some(whole);
        record.cut = Some(format!(
            "the output was {}; its middle was cut, and the file says where",
            human_bytes(whole as usize)
        ));
    }
    let mut text = output.stdout;
    if !output.stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("--- stderr ---\n");
        text.push_str(&output.stderr);
    }
    text.into_bytes()
}

/// One line of the host's journal output: `uname -a: exit 0, 120 bytes`.
fn describe(record: &ItemRecord) -> String {
    let mut parts = Vec::new();
    if let Some(code) = record.exit_code {
        parts.push(format!("exit {code}"));
    }
    if let Some(signal) = &record.signal {
        parts.push(format!("ended by signal {signal}"));
    }
    parts.push(human_bytes(record.bytes as usize));
    if record.redacted > 0 {
        parts.push(format!("{} redacted", record.redacted));
    }
    if record.cut.is_some() {
        parts.push("cut".into());
    }
    format!("{}: {}", record.source, parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_keys_and_passwords_are_redacted_and_counted() {
        let pw = SecretString::new("login-pw-7f3a");
        let kind = "OPENSSH PRIVATE KEY";
        let text = format!(
            "user=alice password=hunter2\nlogin-pw-7f3a\n-----BEGIN {kind}-----\nAAAAB3Nza\n-----END {kind}-----\nok\n"
        );
        let (clean, count) = redact(text.as_bytes(), &[pw]);
        assert!(!clean.contains("hunter2") && !clean.contains("login-pw-7f3a") && !clean.contains("AAAAB3Nza"));
        assert!(clean.contains(&format!("-----BEGIN {kind}-----\n[redacted]\n-----END {kind}-----")));
        assert!(clean.ends_with("ok\n"));
        assert_eq!(count, 3);
    }

    #[test]
    fn a_private_key_cut_off_at_the_end_is_redacted_too() {
        let kind = "RSA PRIVATE KEY";
        let (clean, count) = redact(format!("x\n-----BEGIN {kind}-----\nMIIEow").as_bytes(), &[]);
        assert!(!clean.contains("MIIEow"), "{clean}");
        assert_eq!(count, 1);
    }

    #[test]
    fn fitting_cuts_on_a_character_boundary_with_a_note() {
        let mut text = "é".repeat(1000);
        assert!(fit(&mut text, 500, "the limit"));
        assert!(text.len() <= 500, "{}", text.len());
        assert!(text.ends_with("[Remotely cut the rest: the limit] …\n"));
        let mut short = "ok".to_owned();
        assert!(!fit(&mut short, 500, "the limit"));
        assert_eq!(short, "ok");
    }
}
