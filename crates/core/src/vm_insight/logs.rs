//! VM-25: a VM's own log files, read only, a tail at a time.
//!
//! Workstation writes `vmware.log` in the VM's folder and keeps the older ones as `vmware-0.log`, `vmware-1.log`...;
//! VirtualBox writes `VBox.log` in the VM's log folder (`LogFldr`, `Logs` beside the .vbox) and keeps `VBox.log.1`,
//! `VBox.log.2`... A9: a log can be huge, so it is never read whole: the first read takes its last
//! [`DEFAULT_TAIL_BYTES`] (at most [`MAX_TAIL_BYTES`]), and following it reads only what was added since, at most
//! [`MAX_CHUNK_BYTES`] at a time (a log that grew more than that skips to its tail and says how much it skipped).
//! Reads end at the last complete line, so a line being written is read whole next time. A3: a folder on a share
//! or a device path is refused before anything is opened. The UI names a file only by a name the listing gave;
//! anything else is refused, so no path comes from the UI.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::adapters::hypervisor::Hypervisor;
use crate::error::{CoreError, Result};
use crate::untrusted::path_refusal;

/// The first read's tail.
pub const DEFAULT_TAIL_BYTES: u64 = 256 * 1024;
/// The most a tail may ask for.
pub const MAX_TAIL_BYTES: u64 = 2 * 1024 * 1024;
/// The most one follow read takes.
pub const MAX_CHUNK_BYTES: u64 = 512 * 1024;
/// Log files listed at most (Workstation keeps three old ones and VirtualBox three by default).
const MAX_FILES: usize = 20;

/// One log file of a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogFile {
    /// `vmware.log`, `vmware-0.log`, `VBox.log`, `VBox.log.1`.
    pub name: String,
    pub size: u64,
    /// When it was last written (RFC 3339).
    pub modified: Option<String>,
    /// The log the VM writes to now (or will, at its next start); the others are older.
    pub current: bool,
}

/// A VM's log files, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogListing {
    pub folder: Option<String>,
    pub files: Vec<LogFile>,
    /// Why there is nothing to list (no folder yet, a refused path).
    pub problem: Option<String>,
}

/// Part of a log, as the Log tab shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogChunk {
    pub file: String,
    /// Where `text` starts in the file, in bytes.
    pub start: u64,
    /// Where the next read starts: after the last complete line read.
    pub end: u64,
    /// The file's size when it was read.
    pub size: u64,
    pub text: String,
    /// The file goes on before `start` (this is its tail).
    pub truncated_before: bool,
    /// The file got shorter than where the last read ended (it was replaced at the VM's start): this is its tail.
    pub reset: bool,
    /// Bytes left out because the log grew more than [`MAX_CHUNK_BYTES`] since the last read.
    pub skipped: u64,
}

/// Which log a file name is, for sorting: `Some(0)` the current log, `Some(n + 1)` the n-th older one.
pub fn log_rank(hypervisor: Hypervisor, name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    match hypervisor {
        Hypervisor::Vmware => {
            if lower == "vmware.log" {
                return Some(0);
            }
            let n = lower.strip_prefix("vmware-")?.strip_suffix(".log")?;
            (!n.is_empty() && n.len() <= 3 && n.chars().all(|c| c.is_ascii_digit()))
                .then(|| n.parse::<u32>().ok().map(|n| n + 1))
                .flatten()
        }
        Hypervisor::VirtualBox => {
            if lower == "vbox.log" {
                return Some(0);
            }
            let n = lower.strip_prefix("vbox.log.")?;
            (!n.is_empty() && n.len() <= 3 && n.chars().all(|c| c.is_ascii_digit()))
                .then(|| n.parse::<u32>().ok())
                .flatten()
        }
    }
}

fn refuse(folder: &Path) -> Result<()> {
    match path_refusal(folder) {
        Some(refusal) => Err(CoreError::InvalidInput(format!(
            "The VM's log folder {} {}, so Remotely doesn't open it",
            folder.display(),
            refusal.describe()
        ))),
        None => Ok(()),
    }
}

/// The log files in `folder`, current first, then older ones by number.
pub async fn list(hypervisor: Hypervisor, folder: &Path) -> Result<Vec<LogFile>> {
    refuse(folder)?;
    let mut entries = match tokio::fs::read_dir(folder).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut found: Vec<(u32, LogFile)> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rank) = log_rank(hypervisor, &name) else {
            continue;
        };
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| OffsetDateTime::from(t).format(&Rfc3339).ok());
        found.push((
            rank,
            LogFile {
                name,
                size: meta.len(),
                modified,
                current: rank == 0,
            },
        ));
    }
    found.sort_by_key(|(rank, _)| *rank);
    Ok(found.into_iter().take(MAX_FILES).map(|(_, f)| f).collect())
}

/// Reads part of the log `name` in `folder`: its tail (`from` = `None`), or what was added after `from`. `tail` is
/// how much a tail takes (capped at [`MAX_TAIL_BYTES`]).
pub async fn read(hypervisor: Hypervisor, folder: &Path, name: &str, from: Option<u64>, tail: u64) -> Result<LogChunk> {
    refuse(folder)?;
    if log_rank(hypervisor, name).is_none() {
        return Err(CoreError::InvalidInput(format!(
            "'{name}' is not one of the VM's log files."
        )));
    }
    let path: PathBuf = folder.join(name);
    let mut file = tokio::fs::File::open(&path).await.map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => CoreError::InvalidInput(format!("{name} is not there any more.")),
        _ => err.into(),
    })?;
    let size = file.metadata().await?.len();
    let tail = tail.clamp(1, MAX_TAIL_BYTES);
    let (start, reset, skipped, follow) = match from {
        None => (size.saturating_sub(tail), false, 0, false),
        Some(at) if at > size => (size.saturating_sub(tail), true, 0, false),
        Some(at) if size - at > MAX_CHUNK_BYTES => {
            let start = size.saturating_sub(tail);
            (start, false, start.saturating_sub(at), false)
        }
        Some(at) => (at, false, 0, true),
    };
    file.seek(SeekFrom::Start(start)).await?;
    let mut bytes = Vec::with_capacity(usize::try_from(size - start).unwrap_or(0));
    (&mut file).take(size - start).read_to_end(&mut bytes).await?;
    Ok(cut(name, &bytes, start, size, follow, reset, skipped))
}

/// The lines of `bytes` (read from `start`): a tail that starts inside a line drops that part, and the text ends at
/// its last complete line. A follow read with no complete line yet is empty and ends where it started.
fn cut(name: &str, bytes: &[u8], start: u64, size: u64, follow: bool, reset: bool, skipped: u64) -> LogChunk {
    let mut from = 0usize;
    if start > 0 && !follow {
        // Mid-line: the first full line starts after the first line break.
        from = bytes.iter().position(|b| *b == b'\n').map_or(bytes.len(), |i| i + 1);
    }
    let body = &bytes[from..];
    let to = match body.iter().rposition(|b| *b == b'\n') {
        Some(i) => i + 1,
        // No line break: a follow read waits for the line to end; a tail of one long line shows it.
        None if follow => 0,
        None => body.len(),
    };
    let text = String::from_utf8_lossy(&body[..to]).into_owned();
    let first = start + from as u64;
    LogChunk {
        file: name.to_owned(),
        start: first,
        end: first + to as u64,
        size,
        text,
        truncated_before: first > 0,
        reset,
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_names_are_ranked_per_hypervisor() {
        assert_eq!(log_rank(Hypervisor::Vmware, "vmware.log"), Some(0));
        assert_eq!(log_rank(Hypervisor::Vmware, "VMware-2.log"), Some(3));
        assert_eq!(log_rank(Hypervisor::Vmware, "vmware-.log"), None);
        assert_eq!(log_rank(Hypervisor::Vmware, "vmware-x.log"), None);
        assert_eq!(log_rank(Hypervisor::Vmware, "vmware-1.log.bak"), None);
        assert_eq!(log_rank(Hypervisor::Vmware, r"..\vmware.log"), None);
        assert_eq!(log_rank(Hypervisor::Vmware, "VBox.log"), None);
        assert_eq!(log_rank(Hypervisor::VirtualBox, "VBox.log"), Some(0));
        assert_eq!(log_rank(Hypervisor::VirtualBox, "VBox.log.3"), Some(3));
        assert_eq!(log_rank(Hypervisor::VirtualBox, "VBoxHardening.log"), None);
        assert_eq!(log_rank(Hypervisor::VirtualBox, "VBox.log.12345"), None);
    }

    #[test]
    fn a_tail_starts_at_a_whole_line_and_ends_at_the_last_one() {
        let bytes = b"rtial line\nline two\nline three\nhalf";
        let chunk = cut("vmware.log", bytes, 100, 134, false, false, 0);
        assert_eq!(chunk.text, "line two\nline three\n");
        assert_eq!(chunk.start, 111);
        assert_eq!(chunk.end, 111 + 20);
        assert!(chunk.truncated_before);
        // The file's start: nothing dropped in front.
        let whole = cut("vmware.log", b"one\ntwo\n", 0, 8, false, false, 0);
        assert_eq!(
            (whole.text.as_str(), whole.truncated_before, whole.end),
            ("one\ntwo\n", false, 8)
        );
    }

    #[test]
    fn a_follow_read_waits_for_a_whole_line() {
        let waiting = cut("vmware.log", b"still being writ", 500, 516, true, false, 0);
        assert_eq!((waiting.text.as_str(), waiting.end), ("", 500));
        let more = cut("vmware.log", b"done\nnext par", 500, 513, true, false, 0);
        assert_eq!((more.text.as_str(), more.start, more.end), ("done\n", 500, 505));
    }

    #[test]
    fn a_share_is_refused_before_anything_is_opened() {
        let refused = tokio_test_block(read(
            Hypervisor::Vmware,
            Path::new(r"\\server\share\vm"),
            "vmware.log",
            None,
            DEFAULT_TAIL_BYTES,
        ));
        assert!(refused.unwrap_err().to_string().contains("network share"));
        let listing = tokio_test_block(list(Hypervisor::Vmware, Path::new(r"\\?\C:\VMs\web01")));
        assert!(listing.is_err());
    }

    fn tokio_test_block<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }
}
