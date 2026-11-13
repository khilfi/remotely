//! SS-08: files on a terminal's host, over SFTP on the terminal's own connection
//! ([`RemoteFiles`]): no second login, no second window.
//!
//! * The "Files here" drawer lists the folder the shell is in ([`super::folder`]), or the home folder
//!   when the shell does not say, and any folder the user opens from there ([`Terminals::list_folder`]).
//!   SS-14: with root browsing on ([`super::root_files`]), a listing can be root's ([`FolderListing::as_root`]).
//! * Downloads ([`Terminals::download`]) are reads: they skip approval, like saving a terminal's
//!   output (SS-11), and are audited the same way: the file's name, size, host path, where it was
//!   saved and its SHA-256, never its content. The folder is picked in a dialog the shell opens, or is
//!   Downloads. SS-14: a file of the same name there is kept and the new one gets a number, unless the user
//!   chose to replace it (always, or only when the host's is newer) or to skip it ([`Existing`]); a folder comes
//!   down with what is in it, except Git's own data (`.git`, so no download makes a Git working tree whose hooks a
//!   Git-aware tool would run), links to folders and what isn't a file, each counted as left out; at most
//!   [`MAX_UPLOAD_FILES`] files and folders in all (A9). Nothing lands in Remotely's own data folder.
//! * Uploads are changes: [`FileTransfers::upload`] submits a [`Command::FileUpload`] to the command
//!   bus (Low; Prod raises it; replacing a file is at least Medium; as root one higher), and the job runner carries
//!   it out here ([`TerminalActions::upload`]). Each uploaded file is audited with its name, size,
//!   destination and SHA-256. The files come from a dialog the shell opens or a drop on the terminal
//!   ([`FileTransfers::stage`]); the UI never names a path on this PC. SS-14: a folder goes up with what is in it
//!   (links and junctions left out), its folders made first.
//! * Uploads write as the logged-in user unless the folder is browsed as root; a protected folder fails with
//!   [`CoreError::RemotePermissionDenied`]. A new file that fails or is cancelled part way is deleted
//!   again; a replaced file stays as it was (H8).
//! * SS-14, the transfer queue: at most [`TRANSFERS_PER_HOST`] transfers run at a time on a terminal's connection,
//!   uploads and downloads together; the rest wait. A transfer pauses between two chunks (its slot goes to the next
//!   one). An upload goes on from the same offset when resumed, into what it wrote before (the new file, or H8's
//!   temporary file), once the host's file is checked to be exactly what was sent ([`RemoteWrite::resume`]), else from
//!   the start. A download comes down again from the start: SFTP's whole-second times can't tell a file rewritten in
//!   place, so its result is never part of each. The audit's SHA-256 is of the bytes sent or saved.
//!   Modification times are kept both ways; a replaced file on the host keeps its permissions and owner (H8).
//! * Every transfer is in [`Transfers`] while it runs and for a while after: progress, speed, cancel,
//!   pause, resume and retry for the transfers panel ([`TransferInfo`], sent on [`Terminals::subscribe_transfers`]).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{broadcast, watch, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::folder::FolderInfo;
use super::{audit, audit_entry, quoted_name, Control, Terminals};
use crate::adapters::remote::{EntryKind, RemoteEntry, RemoteFiles, RemoteWrite, Resumed, SetAttrs, Written};
use crate::command_bus::{
    human_size, Command, CommandBus, SubmitOutcome, UploadFile, MAX_FOLDER_DEPTH, MAX_UPLOAD_FILES,
};
use crate::domain::{Context, Target};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::policy::Tier;
use crate::store::NewAuditEntry;
use crate::untrusted::{is_device_name, is_format_char};

/// Bytes read or written at a time.
const CHUNK: usize = 256 * 1024;
/// Progress goes to the UI at most this often per transfer.
const PROGRESS_EVERY: Duration = Duration::from_millis(200);
/// Finished transfers kept for the panel.
const KEEP_FINISHED: usize = 200;
/// Files chosen or dropped are kept this long for their upload.
const STAGED_FOR: Duration = Duration::from_secs(3600);
/// SS-14: transfers running at a time on one terminal's connection; the rest wait their turn.
pub const TRANSFERS_PER_HOST: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferState {
    /// Waiting for its turn (one of [`TRANSFERS_PER_HOST`]).
    Queued,
    Running,
    /// SS-14: stopped between two chunks until it is resumed; its slot went to the next transfer.
    Paused,
    Done,
    Failed,
    Cancelled,
}

impl TransferState {
    fn finished(self) -> bool {
        matches!(
            self,
            TransferState::Done | TransferState::Failed | TransferState::Cancelled
        )
    }
}

/// SS-08: one file going up or down, for the transfers panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferInfo {
    pub id: Uuid,
    /// The upload's job (uploads go through the command bus).
    pub job_id: Option<Uuid>,
    pub terminal_id: Uuid,
    /// How the terminal is named: `'web01'`, or `alice@192.0.2.10:22 (not saved)`.
    pub terminal: String,
    pub direction: Direction,
    /// The file's name; SS-14: with its folders (`site/css/main.css`) for a file of a folder.
    pub name: String,
    /// On the host: where it goes, or where it comes from.
    pub remote_path: String,
    /// On this PC: the file uploaded, or (once known) where the download went.
    pub local_path: Option<String>,
    pub size: u64,
    pub done: u64,
    /// Recent speed.
    pub bytes_per_sec: u64,
    pub state: TransferState,
    /// Why it failed or was cancelled.
    pub message: Option<String>,
    pub sha256: Option<String>,
    /// An upload that replaces a file on the host (SS-14: or a download that replaces one on this PC).
    pub replace: bool,
    /// SS-14: through root browsing.
    pub as_root: bool,
}

/// What a finished transfer needs to run again.
#[derive(Debug, Clone)]
enum Again {
    Upload {
        local_path: PathBuf,
        /// The upload's host folder, and the file's name in it (with its folders).
        folder: String,
        name: String,
        as_root: bool,
        keep_times: bool,
    },
    Download {
        dest: PathBuf,
        existing: Existing,
        as_root: bool,
    },
}

struct Entry {
    info: TransferInfo,
    cancel: CancellationToken,
    /// SS-14: true while a pause is asked for.
    pause: watch::Sender<bool>,
    again: Again,
    last_emit: Option<Instant>,
    last_done: u64,
}

/// SS-08: the transfers of every terminal, newest last.
pub(crate) struct Transfers {
    list: Mutex<VecDeque<Entry>>,
    events: broadcast::Sender<TransferInfo>,
}

impl Default for Transfers {
    fn default() -> Self {
        Self {
            list: Mutex::default(),
            events: broadcast::channel(512).0,
        }
    }
}

impl Transfers {
    fn add(&self, info: TransferInfo, again: Again) -> CancellationToken {
        let cancel = CancellationToken::new();
        {
            let mut list = locks::lock(&self.list);
            list.push_back(Entry {
                info: info.clone(),
                cancel: cancel.clone(),
                pause: watch::channel(false).0,
                again,
                last_emit: None,
                last_done: 0,
            });
            // Keep the running ones, and the newest finished ones.
            let finished = list.iter().filter(|e| e.info.state.finished()).count();
            if finished > KEEP_FINISHED {
                if let Some(at) = list.iter().position(|e| e.info.state.finished()) {
                    list.remove(at);
                }
            }
        }
        let _ = self.events.send(info);
        cancel
    }

    fn change(&self, id: Uuid, change: impl FnOnce(&mut TransferInfo)) {
        let info = {
            let mut list = locks::lock(&self.list);
            let Some(entry) = list.iter_mut().find(|e| e.info.id == id) else {
                return;
            };
            change(&mut entry.info);
            entry.last_emit = Some(Instant::now());
            entry.last_done = entry.info.done;
            entry.info.clone()
        };
        let _ = self.events.send(info);
    }

    fn start(&self, id: Uuid) {
        self.change(id, |info| info.state = TransferState::Running);
    }

    fn set_state(&self, id: Uuid, state: TransferState) {
        self.change(id, |info| {
            info.state = state;
            info.bytes_per_sec = 0;
        });
    }

    /// `done` bytes so far; sent on at most every [`PROGRESS_EVERY`], with the speed since the last.
    fn progress(&self, id: Uuid, done: u64) {
        let now = Instant::now();
        let info = {
            let mut list = locks::lock(&self.list);
            let Some(entry) = list.iter_mut().find(|e| e.info.id == id) else {
                return;
            };
            entry.info.done = done;
            let since = entry.last_emit.map(|at| now.saturating_duration_since(at));
            if since.is_some_and(|d| d < PROGRESS_EVERY) {
                return;
            }
            if let Some(since) = since.filter(|d| !d.is_zero()) {
                let rate = (done.saturating_sub(entry.last_done)) as f64 / since.as_secs_f64();
                let previous = entry.info.bytes_per_sec as f64;
                let smoothed = if previous == 0.0 {
                    rate
                } else {
                    0.6 * previous + 0.4 * rate
                };
                entry.info.bytes_per_sec = smoothed.round() as u64;
            }
            entry.last_emit = Some(now);
            entry.last_done = done;
            entry.info.clone()
        };
        let _ = self.events.send(info);
    }

    fn finish(&self, id: Uuid, state: TransferState, message: Option<String>, sha256: Option<String>) {
        self.change(id, |info| {
            info.state = state;
            info.message = message;
            if sha256.is_some() {
                info.done = info.size.max(info.done);
            }
            info.sha256 = sha256;
            info.bytes_per_sec = 0;
        });
    }

    fn get(&self, id: Uuid) -> Option<(TransferInfo, Again)> {
        locks::lock(&self.list)
            .iter()
            .find(|e| e.info.id == id)
            .map(|e| (e.info.clone(), e.again.clone()))
    }

    fn cancel(&self, id: Uuid) -> bool {
        let list = locks::lock(&self.list);
        match list.iter().find(|e| e.info.id == id) {
            Some(entry) if !entry.info.state.finished() => {
                entry.cancel.cancel();
                true
            }
            _ => false,
        }
    }

    /// SS-14: root browsing on `terminal` ended: every transfer as root of it that has not finished is cancelled
    /// (a paused one too), so nothing more is written or read as root. The ids of those cancelled.
    pub(super) fn cancel_root(&self, terminal: Uuid) -> Vec<Uuid> {
        let list = locks::lock(&self.list);
        let mut cancelled = Vec::new();
        for entry in list.iter() {
            if entry.info.terminal_id == terminal && entry.info.as_root && !entry.info.state.finished() {
                entry.cancel.cancel();
                cancelled.push(entry.info.id);
            }
        }
        cancelled
    }

    /// Whether every one of `ids` has ended (or is gone from the list).
    pub(super) fn all_finished(&self, ids: &[Uuid]) -> bool {
        let list = locks::lock(&self.list);
        ids.iter().all(|id| {
            list.iter()
                .find(|e| e.info.id == *id)
                .is_none_or(|e| e.info.state.finished())
        })
    }

    /// SS-14: asks a transfer that has not finished to pause (`on`) or go on. False when there is none to.
    fn pause(&self, id: Uuid, on: bool) -> bool {
        let list = locks::lock(&self.list);
        match list.iter().find(|e| e.info.id == id) {
            Some(entry) if !entry.info.state.finished() => entry.pause.send_replace(on) != on,
            _ => false,
        }
    }

    fn token(&self, id: Uuid) -> Option<CancellationToken> {
        locks::lock(&self.list)
            .iter()
            .find(|e| e.info.id == id)
            .map(|e| e.cancel.clone())
    }

    fn pauser(&self, id: Uuid) -> watch::Receiver<bool> {
        locks::lock(&self.list)
            .iter()
            .find(|e| e.info.id == id)
            .map_or_else(|| watch::channel(false).1, |e| e.pause.subscribe())
    }

    fn list(&self) -> Vec<TransferInfo> {
        locks::lock(&self.list).iter().map(|e| e.info.clone()).collect()
    }
}

/// SS-08: a folder on the host, for the drawer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderListing {
    /// The folder, absolute; also when it could not be opened (QL-09), so the drawer still shows where
    /// it is and Up, the breadcrumbs and typed paths go on from there.
    pub path: String,
    /// The folder above, unless this is `/`.
    pub parent: Option<String>,
    pub entries: Vec<RemoteEntry>,
    /// QL-09: why the folder could not be opened (the host refused the login user, it is gone...).
    pub error: Option<FolderError>,
    /// QL-09: where Back goes: the folder that opened before this one, or the last one that opened when
    /// this one could not.
    pub back: Option<String>,
    /// A9: the folder holds more than [`MAX_LISTING`](crate::adapters::remote::MAX_LISTING) entries,
    /// and only that many are listed.
    pub more: bool,
    /// SS-14: listed as root (root browsing), so the drawer says so.
    pub as_root: bool,
    /// SS-14: root browsing is on for the terminal (whether or not this listing is root's).
    pub root_available: bool,
}

/// QL-09: a folder the drawer could not open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderError {
    /// `permission_denied`, `not_found`, `sftp`, ... ([`CoreError::code`]).
    pub code: &'static str,
    pub message: String,
}

/// QL-09: the folders the Back button goes through, per terminal.
const MAX_OPENED: usize = 50;

/// SS-08: an upload the job runner hands to the terminal it goes through.
pub struct UploadRun<'a> {
    pub ctx: Context,
    pub job_id: Uuid,
    pub tier: Tier,
    pub target: &'a Target,
    pub terminal_id: Uuid,
    pub folder: &'a str,
    pub files: &'a [UploadFile],
    /// SS-14: folders made first, relative to `folder`, parents first.
    pub folders: &'a [String],
    /// SS-14: each file gets its time on this PC.
    pub keep_times: bool,
    /// SS-14: through root browsing.
    pub as_root: bool,
    /// SS-14 (0.8.0 G3): a sync's deletes, relative to `folder`, done after the uploads.
    pub delete: &'a [String],
}

/// SS-08: how an upload went, file by file.
#[derive(Debug, Default)]
pub struct UploadReport {
    /// "a.txt (1.5 KB)".
    pub uploaded: Vec<String>,
    pub cancelled: usize,
    /// "a.txt: why".
    pub failed: Vec<String>,
    /// SS-14: folders made.
    pub folders: usize,
    /// SS-14 (0.8.0 G3): a sync's deletes done (one gone already counts too).
    pub deleted: usize,
}

impl UploadReport {
    /// For the job's audit entry.
    pub fn summary(&self, folder: &str) -> String {
        let mut parts = Vec::new();
        if self.folders > 0 {
            parts.push(match self.folders {
                1 => "1 folder made".to_owned(),
                n => format!("{n} folders made"),
            });
        }
        if !self.uploaded.is_empty() {
            // A folder's thousands of files are counted, not named.
            if self.uploaded.len() > 50 {
                parts.push(format!("uploaded {} files to {folder}", self.uploaded.len()));
            } else {
                parts.push(format!("uploaded to {folder}: {}", self.uploaded.join(", ")));
            }
        }
        if self.deleted > 0 {
            parts.push(match self.deleted {
                1 => format!("1 item deleted in {folder}"),
                n => format!("{n} items deleted in {folder}"),
            });
        }
        if self.cancelled > 0 {
            parts.push(format!("{} cancelled", self.cancelled));
        }
        if !self.failed.is_empty() {
            parts.push(format!("failed: {}", self.failed.join("; ")));
        }
        if parts.is_empty() {
            "nothing uploaded".to_owned()
        } else {
            parts.join("; ")
        }
    }

    /// Why the target failed, if a file did.
    pub fn failure(&self) -> Option<String> {
        match self.failed.as_slice() {
            [] => None,
            [one] => Some(one.clone()),
            several => Some(format!("{} files failed: {}", several.len(), several.join("; "))),
        }
    }
}

/// `folder/name`, one `/` between them.
pub fn join(folder: &str, name: &str) -> String {
    if folder.ends_with('/') {
        format!("{folder}{name}")
    } else {
        format!("{folder}/{name}")
    }
}

/// QL-09: where in `opened` (the folders that opened, oldest first) Back goes from the folder shown:
/// the one before it when it is the last that opened, otherwise (it could not be opened) the last.
fn back_index(opened: &[String], shown: &str) -> Option<usize> {
    match opened.last() {
        Some(last) if last == shown => opened.len().checked_sub(2),
        Some(_) => Some(opened.len() - 1),
        None => None,
    }
}

/// The folder above, `None` for `/`.
pub fn parent(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }
    match path.rsplit_once('/') {
        Some(("", _)) => Some("/".to_owned()),
        Some((above, _)) => Some(above.to_owned()),
        None => None,
    }
}

/// An absolute, clean host path: `path` as it is when absolute, from `home` for `~`, otherwise from
/// `base`; `.` and `..` resolved, no `/` at the end.
pub fn resolve(base: &str, home: &str, path: &str) -> String {
    let path = path.trim();
    let full = if path.starts_with('/') {
        path.to_owned()
    } else if path == "~" {
        home.to_owned()
    } else if let Some(rest) = path.strip_prefix("~/") {
        join(home, rest)
    } else {
        join(base, path)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in full.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// A file name for this PC: what Windows can't hold in a name becomes `_`, and a device name gets a `_`
/// in front, so a host file named `nul` or `com1.txt` is saved as a file instead of going to a device.
/// A8: Unicode format characters (Cf: U+202E RIGHT-TO-LEFT OVERRIDE, zero-width spaces and joiners,
/// bidi isolates, U+FEFF, the soft hyphen...) and the line and paragraph separators become `_` too, so
/// `invoice\u{202E}fdp.exe` is saved as `invoice_fdp.exe`, not shown as `invoiceexe.pdf`.
pub(crate) fn local_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            '\u{2028}' | '\u{2029}' => '_',
            c if c.is_control() || is_format_char(c) => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim_end_matches(['.', ' ']).to_owned();
    if cleaned.is_empty() {
        "download".to_owned()
    } else if is_device_name(&cleaned) {
        format!("_{cleaned}")
    } else {
        cleaned
    }
}

/// A8: what Windows' own browsers write for a file from the internet (zone 3), so SmartScreen and
/// Office's Protected View treat a downloaded file as one. No `HostUrl`: the host's name stays off disk.
#[cfg(windows)]
const ZONE_IDENTIFIER: &str = "[ZoneTransfer]\r\nZoneId=3\r\n";

/// A8: writes the Mark of the Web, the `Zone.Identifier` stream, on a downloaded file. `None` when it
/// is written; otherwise what to tell the user (the folder's file system may have no alternate data
/// streams, as FAT and exFAT drives don't), and the download still counts. Windows only. FD-09's file server marks
/// each upload it receives the same way.
pub(crate) async fn mark_downloaded(path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        match tokio::fs::write(PathBuf::from(stream), ZONE_IDENTIFIER).await {
            Ok(()) => None,
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "could not mark a download as from the internet");
                Some(
                    "Windows could not mark this file as downloaded from the internet (the folder's drive may be FAT or exFAT), so open it with care"
                        .to_owned(),
                )
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

/// The name a file of `name` gets when `taken` says it is there: `name (1).ext`, `name (2).ext`...
fn numbered(name: &str, n: usize) -> String {
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_owned(), format!(".{ext}")),
        _ => (name.to_owned(), String::new()),
    };
    if n == 0 {
        name.to_owned()
    } else {
        format!("{stem} ({n}){extension}")
    }
}

/// Creates a new file in `folder` named `name`, or `name (1)`, `name (2)`... when that is taken, so a
/// download never overwrites a file on this PC. Never a file Git takes as its own ([`is_git_name`]).
pub(crate) async fn claim_file(folder: &Path, name: &str) -> Result<(PathBuf, tokio::fs::File)> {
    if is_git_name(name) {
        return Err(git_data_refused(name));
    }
    let name = local_name(name);
    for n in 0..1000 {
        let candidate = folder.join(numbered(&name, n));
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(CoreError::InvalidInput(format!(
        "{} already holds too many files named like '{name}'.",
        folder.display()
    )))
}

/// SS-14: what to do with a file that is there already (the host's for an upload, this PC's for a download).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Existing {
    /// Ask first: nothing is submitted (or queued) while any is there.
    #[default]
    Ask,
    Replace,
    /// Replace it only when the one sent is newer (by modification time); otherwise leave it.
    ReplaceIfNewer,
    Skip,
    /// Keep it, and give the new one a number: `name (1).ext`.
    KeepBoth,
}

impl Existing {
    /// For a file that is there: replace it (`Some(true)`), send it beside it (`Some(false)`, [`Existing::KeepBoth`]),
    /// or leave it (`None`). `sent` and `there`: modification times, seconds since 1970.
    fn decide(self, sent: Option<u64>, there: Option<u64>) -> Option<bool> {
        match self {
            Existing::Ask | Existing::Replace => Some(true),
            Existing::ReplaceIfNewer => match (sent, there) {
                (Some(sent), Some(there)) if sent > there => Some(true),
                // Unknown times: left alone, as "newer" can't be told.
                _ => None,
            },
            Existing::Skip => None,
            Existing::KeepBoth => Some(false),
        }
    }
}

/// Seconds since 1970 of a time on this PC.
fn unix_secs(at: SystemTime) -> Option<u64> {
    at.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// SS-14: what [`Terminals::download_with`] takes.
#[derive(Debug, Clone, Copy, Default)]
pub struct DownloadOptions {
    pub existing: Existing,
    pub as_root: bool,
}

/// SS-14: how starting a download went.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DownloadStart {
    /// These are in the folder on this PC already (as they would be saved, with their folders); ask, then call again.
    /// `choice`: the folder, kept by [`FileTransfers::download`] for the answer, so no path of this PC comes back
    /// from the UI.
    Conflicts {
        existing: Vec<String>,
        dest: String,
        choice: Option<Uuid>,
    },
    /// Queued; `skipped` files were there already and left alone; `left_out`: what a folder held that doesn't come
    /// down (Git's data, links to folders, devices and the like).
    Queued {
        transfers: Vec<TransferInfo>,
        skipped: usize,
        left_out: usize,
    },
}

/// Where one downloaded file lands on this PC: its folder, its name there, and the modification time it had on the
/// host, which it keeps.
struct Landing {
    dest: PathBuf,
    name: String,
    modified: Option<u64>,
}

/// One file a download brings: where it comes from, where it goes on this PC, its host entry, and whether it
/// replaces a file there.
struct DownloadItem {
    remote: String,
    /// The folder on this PC it lands in, and its name there.
    dest: PathBuf,
    name: String,
    /// Its name with its folders, for the panel.
    shown: String,
    entry: RemoteEntry,
    replace: bool,
}

/// SS-14: a name Git takes as its own data on this PC (`.git`, as Windows would save it: `.GIT`, `.git.`, `.git `).
/// A folder or file of that name makes the folder around it a Git working tree, whose hooks and `core.fsmonitor` a
/// Git-aware tool runs when it opens the folder, so none comes down: not by a download, a folder sync or a fetch from
/// many hosts.
pub(crate) fn is_git_name(name: &str) -> bool {
    local_name(name).eq_ignore_ascii_case(".git")
}

/// SS-14: whether a path under a download's folder (parts split by `/`) has a part that lands as Git's own data.
fn lands_as_git(path: &str) -> bool {
    path.split('/').any(is_git_name)
}

/// SS-14: why `what` (a host path or name) isn't saved on this PC.
pub(crate) fn git_data_refused(what: &str) -> CoreError {
    CoreError::InvalidInput(format!(
        "{what} is Git's own data, so it isn't downloaded: on this PC it would make the folder a Git working tree, \
         whose hooks Git-aware tools run."
    ))
}

/// SS-14: `path` is in one of `protected` (final paths), its parts compared as Windows compares them, without case.
fn lands_in(path: &Path, protected: &[PathBuf]) -> bool {
    let parts = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let at = parts(path);
    protected.iter().any(|folder| {
        let folder = parts(folder);
        at.len() >= folder.len() && at[..folder.len()] == folder[..]
    })
}

/// SS-14: a host folder's files, for a download of the folder: links to folders are left out (they may lead back up),
/// links to files come down as the files they point to; Git's data ([`is_git_name`]) and what is neither a file nor
/// a folder are left out too, each counted in `left_out`. At most [`MAX_UPLOAD_FILES`] files and folders (A9: an
/// endless tree of empty folders is refused as well). Folders first in the list, parents first.
async fn walk_remote(
    files: &Arc<dyn RemoteFiles>,
    root: &str,
    top: &str,
    left_out: &mut usize,
) -> Result<(Vec<String>, Vec<(String, String, RemoteEntry)>)> {
    let mut folders = vec![top.to_owned()];
    let mut found = Vec::new();
    let mut queue = VecDeque::from([(root.to_owned(), top.to_owned(), 1usize)]);
    while let Some((folder, shown, depth)) = queue.pop_front() {
        let listing = files.list(&folder).await?;
        if listing.more {
            return Err(CoreError::InvalidInput(format!(
                "{folder} holds more than Remotely lists in one folder, so it can't come down whole. Download what is \
                 in it by parts, or pack it in the terminal first"
            )));
        }
        for entry in listing.entries {
            if is_git_name(&entry.name) {
                *left_out += 1;
                continue;
            }
            let path = join(&folder, &entry.name);
            let shown_path = format!("{shown}/{}", entry.name);
            match entry.kind {
                EntryKind::Folder if entry.link => *left_out += 1,
                EntryKind::Folder => {
                    if depth >= MAX_FOLDER_DEPTH {
                        return Err(CoreError::InvalidInput(format!(
                            "{root} is more than {MAX_FOLDER_DEPTH} folders deep, so it can't come down whole."
                        )));
                    }
                    folders.push(shown_path.clone());
                    queue.push_back((path, shown_path, depth + 1));
                }
                EntryKind::File => found.push((path, shown_path, entry)),
                EntryKind::Other => *left_out += 1,
            }
            if found.len() + folders.len() > MAX_UPLOAD_FILES {
                return Err(CoreError::InvalidInput(format!(
                    "{root} holds more than {MAX_UPLOAD_FILES} files and folders, so it can't come down in one go."
                )));
            }
        }
    }
    Ok((folders, found))
}

impl Terminals {
    pub(super) fn live(&self, id: Uuid) -> Result<(Arc<Control>, Arc<dyn RemoteFiles>)> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id} has closed")))?;
        let files = locks::lock(&control.files).clone().ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "{} is not connected, so its files can't be reached. Reconnect it first.",
                quoted_name(&control)
            ))
        })?;
        Ok((control, files))
    }

    /// SS-08: the folder the terminal's shell is in, as far as it is known.
    pub fn folder(&self, id: Uuid) -> Option<FolderInfo> {
        self.control(id).map(|c| locks::lock(&c.folder).clone())
    }

    /// SS-08: the login's home folder on the terminal's host.
    pub async fn home_folder(&self, id: Uuid) -> Result<String> {
        let (control, files) = self.live(id)?;
        home_of(&control, &files).await
    }

    /// SS-08: a folder on the terminal's host: `path` (absolute, or from the shell's folder), or with
    /// `None` the shell's folder, or the home folder when the shell has not said.
    pub async fn list_folder(&self, id: Uuid, path: Option<&str>) -> Result<FolderListing> {
        self.open_folder(id, path, None).await
    }

    /// QL-09: like [`Terminals::list_folder`], with a relative `path` taken from `from`: the folder the
    /// drawer shows, even one that could not be opened. A folder that can't be listed comes back with
    /// its path and the reason ([`FolderListing::error`]) instead of failing, so the drawer can go on
    /// from there. Errors are left for a terminal that can't reach its files at all.
    pub async fn open_folder(&self, id: Uuid, path: Option<&str>, from: Option<&str>) -> Result<FolderListing> {
        self.open_folder_as(id, path, from, false).await
    }

    /// SS-14: [`Terminals::open_folder`], as root when `as_root` (root browsing must be on).
    pub async fn open_folder_as(
        &self,
        id: Uuid,
        path: Option<&str>,
        from: Option<&str>,
        as_root: bool,
    ) -> Result<FolderListing> {
        let (control, files) = self.live(id)?;
        let home = home_of(&control, &files).await?;
        let shell = locks::lock(&control.folder)
            .path
            .clone()
            .unwrap_or_else(|| home.clone());
        let base = from.map_or_else(|| shell.clone(), |from| resolve("/", &home, from));
        let path = resolve(&base, &home, path.unwrap_or(&shell));
        let (_, files) = self.files_for(id, as_root)?;
        Ok(self.listing(&control, &files, path).await)
    }

    /// QL-09: the drawer's Back from `from` (the folder it shows): the folder that opened before it,
    /// or, when `from` could not be opened, the last one that did.
    pub async fn folder_back(&self, id: Uuid, from: &str) -> Result<FolderListing> {
        self.folder_back_as(id, from, false).await
    }

    /// SS-14: [`Terminals::folder_back`], as root when `as_root`.
    pub async fn folder_back_as(&self, id: Uuid, from: &str, as_root: bool) -> Result<FolderListing> {
        let (control, files) = self.files_for(id, as_root)?;
        let target = {
            let mut opened = locks::lock(&control.opened);
            let at = back_index(&opened, from)
                .ok_or_else(|| CoreError::InvalidInput("There is no folder to go back to.".into()))?;
            opened.truncate(at + 1);
            opened[at].clone()
        };
        Ok(self.listing(&control, &files, target).await)
    }

    /// Lists `path` (absolute), remembering it for Back when it opened.
    async fn listing(&self, control: &Control, files: &Arc<dyn RemoteFiles>, path: String) -> FolderListing {
        let (entries, more, error) = match files.list(&path).await {
            Ok(listing) => {
                let mut entries = listing.entries;
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                (entries, listing.more, None)
            }
            Err(err) => (
                Vec::new(),
                false,
                Some(FolderError {
                    code: err.code(),
                    message: err.to_string(),
                }),
            ),
        };
        let back = {
            let mut opened = locks::lock(&control.opened);
            if error.is_none() && opened.last() != Some(&path) {
                opened.push(path.clone());
                if opened.len() > MAX_OPENED {
                    opened.remove(0);
                }
            }
            back_index(&opened, &path).map(|at| opened[at].clone())
        };
        FolderListing {
            parent: parent(&path),
            path,
            entries,
            error,
            back,
            more,
            as_root: files.as_root(),
            root_available: locks::lock(&control.root).is_some(),
        }
    }

    /// SS-08: what is at `path` (absolute, `~/...`, or from the shell's folder): for a file name
    /// right-clicked in the terminal's output. `None` when nothing is there.
    pub async fn look_up(&self, id: Uuid, path: &str) -> Result<Option<(String, RemoteEntry)>> {
        let (control, files) = self.live(id)?;
        let home = home_of(&control, &files).await?;
        let base = locks::lock(&control.folder)
            .path
            .clone()
            .unwrap_or_else(|| home.clone());
        let full = resolve(&base, &home, path);
        Ok(files.stat(&full).await?.map(|entry| (full, entry)))
    }

    /// SS-08: which of `names` are in the host folder already. A folder of that name can't be
    /// replaced by a file, so it is an error.
    pub async fn upload_conflicts(&self, id: Uuid, folder: &str, names: &[String]) -> Result<Vec<String>> {
        let (_, files) = self.live(id)?;
        let mut existing = Vec::new();
        for name in names {
            let path = join(folder, name);
            match files.stat(&path).await? {
                None => {}
                Some(entry) if entry.kind == EntryKind::Folder => {
                    return Err(CoreError::InvalidInput(format!(
                        "{path} is a folder on the host, so a file can't replace it. Rename the file, or upload it elsewhere."
                    )))
                }
                Some(_) => existing.push(name.clone()),
            }
        }
        Ok(existing)
    }

    /// SS-08: the transfers panel's list, newest last.
    pub fn transfers(&self) -> Vec<TransferInfo> {
        self.inner.transfers.list()
    }

    /// SS-08: every change of a transfer (progress at most every 200 ms each).
    pub fn subscribe_transfers(&self) -> broadcast::Receiver<TransferInfo> {
        self.inner.transfers.events.subscribe()
    }

    /// SS-08: stops a transfer that has not finished. False when there is none to stop.
    pub fn cancel_transfer(&self, id: Uuid) -> bool {
        self.inner.transfers.cancel(id)
    }

    /// SS-14: pauses a transfer that has not finished (it stops after its current chunk). False when there is none to
    /// pause, or it is paused already.
    pub fn pause_transfer(&self, id: Uuid) -> bool {
        self.inner.transfers.pause(id, true)
    }

    /// SS-14: a paused transfer goes on where it stopped (once a slot is free). False when it isn't paused.
    pub fn resume_transfer(&self, id: Uuid) -> bool {
        self.inner.transfers.pause(id, false)
    }

    /// SS-08: downloads files from the terminal's host into `dest` on this PC; returns them as queued. A file of the
    /// same name there is kept and the new one gets a number. See [`Terminals::download_with`].
    pub async fn download(&self, ctx: &Context, id: Uuid, paths: &[String], dest: &Path) -> Result<Vec<TransferInfo>> {
        let options = DownloadOptions {
            existing: Existing::KeepBoth,
            as_root: false,
        };
        match self.download_with(ctx, id, paths, dest, options).await? {
            DownloadStart::Queued { transfers, .. } => Ok(transfers),
            DownloadStart::Conflicts { .. } => Ok(Vec::new()),
        }
    }

    /// SS-08, SS-14: downloads files and folders (with what is in them) from the terminal's host into `dest` on this
    /// PC, [`TRANSFERS_PER_HOST`] at a time with the uploads on the same connection. Each is audited when it is saved:
    /// name, size, host path, where it went, SHA-256. Never into a Git working tree ([`crate::save_guard`]). A file of
    /// the same name on this PC is handled as `options.existing` says: with [`Existing::Ask`], nothing is queued while
    /// any is there ([`DownloadStart::Conflicts`]).
    pub async fn download_with(
        &self,
        ctx: &Context,
        id: Uuid,
        paths: &[String],
        dest: &Path,
        options: DownloadOptions,
    ) -> Result<DownloadStart> {
        // The folder first (a Git working tree, Remotely's own data), whatever the terminal is doing.
        self.download_dest(dest)?;
        let (control, _) = self.live(id)?;
        let (_, files) = self.files_for(id, options.as_root)?;
        if paths.is_empty() {
            return Err(CoreError::InvalidInput("Choose a file to download.".into()));
        }
        if paths.len() > MAX_UPLOAD_FILES {
            return Err(CoreError::InvalidInput(format!(
                "One download takes at most {MAX_UPLOAD_FILES} files."
            )));
        }
        let home = home_of(&control, &files).await?;
        let base = locks::lock(&control.folder)
            .path
            .clone()
            .unwrap_or_else(|| home.clone());
        // What comes down: each file, and each folder's files with their folders (made on this PC first).
        let mut folders: Vec<String> = Vec::new();
        let mut found: Vec<(String, String, RemoteEntry)> = Vec::new();
        let mut left_out = 0;
        for path in paths {
            let full = resolve(&base, &home, path);
            let entry = files
                .stat(&full)
                .await?
                .ok_or_else(|| CoreError::RemoteNotFound { path: full.clone() })?;
            if is_git_name(&entry.name) {
                return Err(git_data_refused(&full));
            }
            match entry.kind {
                EntryKind::File => found.push((full, entry.name.clone(), entry)),
                EntryKind::Folder => {
                    let top = local_name(&entry.name);
                    let (subfolders, inside) = walk_remote(&files, &full, &top, &mut left_out).await?;
                    folders.extend(subfolders);
                    found.extend(inside);
                }
                EntryKind::Other => {
                    return Err(CoreError::InvalidInput(format!(
                        "{full} is not a regular file (a device, socket or broken link), so it can't be downloaded."
                    )))
                }
            }
            if found.len() + folders.len() > MAX_UPLOAD_FILES {
                return Err(CoreError::InvalidInput(format!(
                    "One download takes at most {MAX_UPLOAD_FILES} files and folders."
                )));
            }
        }
        self.land_downloads(ctx, &control, dest, found, folders, left_out, options)
            .await
    }

    /// SS-14: a folder of this PC a download may go into: never a Git working tree ([`crate::save_guard`]), never
    /// Remotely's own data (the database, the vault, the logs: a download that replaced a file there would replace the
    /// app's own). Its final path.
    pub(super) fn download_dest(&self, dest: &Path) -> Result<PathBuf> {
        crate::save_guard::refuse_repository_folder(dest, crate::save_guard::Saved::Download)?;
        if !dest.is_dir() {
            return Err(CoreError::InvalidInput(format!("{} is not a folder.", dest.display())));
        }
        let protected = self.protected_folders();
        let dest_real = crate::toolbox::file_server::final_place(dest).unwrap_or_else(|| dest.to_owned());
        if lands_in(&dest_real, &protected) {
            return Err(CoreError::InvalidInput(format!(
                "{} is Remotely's own data folder, so nothing is downloaded into it. Choose another folder.",
                dest.display()
            )));
        }
        Ok(dest_real)
    }

    /// SS-14: queues what a download brings: `found` as (host path, its name with its folders under `dest`, its entry),
    /// `folders` made first (as names under `dest`). Each lands under `dest` with its folders' names made safe for
    /// Windows, part by part, never in Remotely's own data and never as Git's own data (a part that would be `.git`
    /// here, whoever gathered the list, is left out and counted); a file there is handled as `options.existing` says.
    /// G3's sync to this PC lands its files this way too.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn land_downloads(
        &self,
        ctx: &Context,
        control: &Arc<Control>,
        dest: &Path,
        found: Vec<(String, String, RemoteEntry)>,
        folders: Vec<String>,
        mut left_out: usize,
        options: DownloadOptions,
    ) -> Result<DownloadStart> {
        let id = control.id;
        let dest_real = self.download_dest(dest)?;
        let protected = self.protected_folders();
        let folders: Vec<String> = folders
            .into_iter()
            .filter(|folder| {
                let git = lands_as_git(folder);
                left_out += usize::from(git);
                !git
            })
            .collect();
        // Where each lands: its folders' names made safe for Windows, part by part.
        let mut items = Vec::new();
        let mut conflicts = Vec::new();
        let mut skipped = 0;
        for (remote, shown, entry) in found {
            if lands_as_git(&shown) {
                left_out += 1;
                continue;
            }
            let mut parts: Vec<String> = shown.split('/').map(local_name).collect();
            let name = parts.pop().unwrap_or_else(|| "download".into());
            let folder = parts.iter().fold(dest.to_owned(), |at, part| at.join(part));
            let lands = parts
                .iter()
                .fold(dest_real.clone(), |at, part| at.join(part))
                .join(&name);
            if lands_in(&lands, &protected) {
                return Err(CoreError::InvalidInput(format!(
                    "{} would land in Remotely's own data folder, so nothing is downloaded. Choose another folder.",
                    folder.join(&name).display()
                )));
            }
            let there = std::fs::symlink_metadata(folder.join(&name)).ok();
            let mut replace = false;
            if let Some(there) = there {
                if there.is_dir() {
                    return Err(CoreError::InvalidInput(format!(
                        "{} is a folder on this PC, so a file can't replace it.",
                        folder.join(&name).display()
                    )));
                }
                match options.existing {
                    Existing::Ask => {
                        conflicts.push(parts.iter().chain([&name]).cloned().collect::<Vec<_>>().join("/"));
                        continue;
                    }
                    existing => match existing.decide(entry.modified, there.modified().ok().and_then(unix_secs)) {
                        Some(true) => replace = true,
                        Some(false) => {}
                        None => {
                            skipped += 1;
                            continue;
                        }
                    },
                }
            }
            items.push(DownloadItem {
                remote,
                dest: folder,
                name,
                shown,
                entry,
                replace,
            });
        }
        if !conflicts.is_empty() {
            return Ok(DownloadStart::Conflicts {
                existing: conflicts,
                dest: dest.display().to_string(),
                choice: None,
            });
        }
        for folder in &folders {
            let at = folder
                .split('/')
                .fold(dest.to_owned(), |at, part| at.join(local_name(part)));
            tokio::fs::create_dir_all(&at).await?;
        }
        let mut queued = Vec::new();
        for item in items {
            let info = TransferInfo {
                id: Uuid::new_v4(),
                job_id: None,
                terminal_id: id,
                terminal: quoted_name(control),
                direction: Direction::Download,
                name: item.shown.clone(),
                remote_path: item.remote.clone(),
                local_path: None,
                size: item.entry.size,
                done: 0,
                bytes_per_sec: 0,
                state: TransferState::Queued,
                message: None,
                sha256: None,
                replace: item.replace,
                as_root: options.as_root,
            };
            let existing = if item.replace {
                Existing::Replace
            } else {
                Existing::KeepBoth
            };
            self.inner.transfers.add(
                info.clone(),
                Again::Download {
                    dest: item.dest.clone(),
                    existing,
                    as_root: options.as_root,
                },
            );
            let this = self.clone();
            let ctx = *ctx;
            let control = Arc::clone(control);
            let landing = Landing {
                dest: item.dest,
                name: item.name,
                modified: item.entry.modified,
            };
            let transfer = info.id;
            tokio::spawn(async move {
                this.download_one(&ctx, &control, transfer, &landing).await;
            });
            queued.push(info);
        }
        Ok(DownloadStart::Queued {
            transfers: queued,
            skipped,
            left_out,
        })
    }

    async fn download_one(&self, ctx: &Context, control: &Arc<Control>, transfer: Uuid, landing: &Landing) {
        let transfers = &self.inner.transfers;
        let (Some((info, _)), Some(cancel)) = (transfers.get(transfer), transfers.token(transfer)) else {
            return;
        };
        if cancel.is_cancelled() {
            transfers.finish(transfer, TransferState::Cancelled, Some("cancelled".into()), None);
            return;
        }
        let mut pause = transfers.pauser(transfer);
        // The slot is held until the transfer shows as ended, so no more than four ever show as running.
        let mut slot = None;
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(None),
            result = self.copy_down(control, &info, landing, &mut pause, &mut slot) => result.map_err(Some),
        };
        match result {
            Ok((local, sha, saved, note)) => {
                let shown = local.display().to_string();
                transfers.change(transfer, |i| {
                    i.local_path = Some(shown.clone());
                    i.size = saved;
                });
                let root = if info.as_root { ", as root" } else { "" };
                let action = format!("Downloaded '{}' from {}{root}", info.name, quoted_name(control));
                let replaced = if info.replace { ", replacing the file there" } else { "" };
                let detail = format!(
                    "{}, {saved} bytes, SHA-256 {sha}; saved to {shown}{replaced}",
                    info.remote_path
                );
                if let Err(err) = audit(
                    &self.inner.store,
                    ctx,
                    "file_downloaded",
                    &action,
                    control.targets(),
                    &detail,
                )
                .await
                {
                    tracing::error!(error = %err, "could not audit a download");
                }
                transfers.finish(transfer, TransferState::Done, note, Some(sha));
            }
            Err(None) => transfers.finish(transfer, TransferState::Cancelled, Some("cancelled".into()), None),
            Err(Some(err)) => transfers.finish(transfer, TransferState::Failed, Some(err.to_string()), None),
        }
    }

    /// SS-14: waits while the transfer is paused (shown as paused), then for one of the connection's slots (shown as
    /// queued). A pause asked while it waits for a slot is kept.
    async fn take_slot(
        &self,
        slots: &Arc<Semaphore>,
        id: Uuid,
        pause: &mut watch::Receiver<bool>,
    ) -> Result<OwnedSemaphorePermit> {
        loop {
            if *pause.borrow_and_update() {
                self.inner.transfers.set_state(id, TransferState::Paused);
                while *pause.borrow_and_update() {
                    if pause.changed().await.is_err() {
                        break;
                    }
                }
                self.inner.transfers.set_state(id, TransferState::Queued);
            }
            let permit = Arc::clone(slots)
                .acquire_owned()
                .await
                .map_err(|_| CoreError::InvalidInput("The terminal has closed.".into()))?;
            if *pause.borrow() {
                drop(permit);
                continue;
            }
            self.inner.transfers.start(id);
            return Ok(permit);
        }
    }

    /// Copies one host file to a new file in `dest` (or over the one there, when it replaces it), keeps its time, then
    /// marks it as from the internet (A8); returns where it went, the SHA-256 and size of the bytes saved, and a note
    /// when the mark could not be written. A file left half written (or not yet marked) is deleted; one it would
    /// replace stays as it was until the last byte arrived. SS-14: a pause stops between two chunks; once it goes on,
    /// the host's file comes down again from the start (see the module's notes).
    async fn copy_down(
        &self,
        control: &Arc<Control>,
        info: &TransferInfo,
        landing: &Landing,
        pause: &mut watch::Receiver<bool>,
        slot: &mut Option<OwnedSemaphorePermit>,
    ) -> Result<(PathBuf, String, u64, Option<String>)> {
        let (dest, name) = (landing.dest.as_path(), landing.name.as_str());
        let mut modified = landing.modified;
        let slots = Arc::clone(&control.slots);
        *slot = Some(self.take_slot(&slots, info.id, pause).await?);
        let (_, files) = self.files_for(info.terminal_id, info.as_root)?;
        let mut reader = Some(files.read(&info.remote_path).await?);
        // A replacement is written beside the file it replaces, then takes its place.
        let (path, final_path, mut file) = if info.replace {
            let final_path = dest.join(name);
            let temp = dest.join(format!(".{name}.remotely-{}.part", &info.id.simple().to_string()[..12]));
            let file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .await?;
            (temp, final_path, file)
        } else {
            let (path, file) = claim_file(dest, name).await?;
            (path.clone(), path, file)
        };
        let mut cleanup = RemoveOnDrop(Some(path.clone()));
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
            if *pause.borrow() {
                drop(reader.take());
                drop(slot.take());
                *slot = Some(self.take_slot(&slots, info.id, pause).await?);
                let (_, files) = self.files_for(info.terminal_id, info.as_root)?;
                // SFTP's times are whole seconds, or missing, so a file rewritten in place at the same size and time
                // looks the same, and checking its bytes means reading them again anyway. So it comes down again
                // from the start: all of it as the host has it now, never part of each.
                let now = files
                    .stat(&info.remote_path)
                    .await?
                    .ok_or_else(|| CoreError::RemoteNotFound {
                        path: info.remote_path.clone(),
                    })?;
                if now.kind != EntryKind::File {
                    return Err(CoreError::InvalidInput(format!(
                        "{} is no longer a file on the host, so it can't come down.",
                        info.remote_path
                    )));
                }
                modified = now.modified;
                self.inner.transfers.change(info.id, |i| i.size = now.size);
                file.set_len(0).await?;
                file.seek(std::io::SeekFrom::Start(0)).await?;
                hasher = Sha256::new();
                done = 0;
                self.inner.transfers.progress(info.id, 0);
                reader = Some(files.read(&info.remote_path).await?);
            }
            let Some(open) = reader.as_mut() else {
                break;
            };
            let n = open.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).await?;
            done += n as u64;
            self.inner.transfers.progress(info.id, done);
        }
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        drop(reader);
        // A8: before the download counts as done (a replacement's mark goes with it when it takes the old one's place).
        let note = mark_downloaded(&path).await;
        // SS-14: the host's modification time, as the file had it there; after the mark, whose stream would move it.
        if let Some(at) = modified {
            let kept = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| file.set_modified(UNIX_EPOCH + Duration::from_secs(at)));
            if let Err(err) = kept {
                tracing::warn!(error = %err, "could not keep a download's modification time");
            }
        }
        if path != final_path {
            tokio::fs::rename(&path, &final_path).await?;
        }
        cleanup.0 = None;
        Ok((final_path, hex::encode(hasher.finalize()), done, note))
    }

    /// SS-08: the job runner's half of [`Command::FileUpload`]: SS-14: its folders made first, then its files over the
    /// terminal's SFTP channel, [`TRANSFERS_PER_HOST`] at a time, each audited as it lands.
    pub(crate) async fn run_upload(&self, run: UploadRun<'_>, cancel: &CancellationToken) -> Result<UploadReport> {
        let (control, files) = self.files_for(run.terminal_id, run.as_root)?;
        let mut report = UploadReport::default();
        // Folders first, parents before what is in them; one that can't be made fails what goes into it.
        let mut broken: HashMap<String, String> = HashMap::new();
        for folder in run.folders {
            if cancel.is_cancelled() {
                break;
            }
            let above = folder.rsplit_once('/').map(|(above, _)| above.to_owned());
            if let Some(why) = above.and_then(|a| broken.get(&a).cloned()) {
                broken.insert(folder.clone(), why);
                continue;
            }
            let path = join(run.folder, folder);
            let made = match files.lstat(&path).await {
                Ok(Some(entry)) if entry.kind == EntryKind::Folder && !entry.link => Ok(false),
                Ok(Some(_)) => Err(format!("{path} is a file on the host, so no folder can go there")),
                Ok(None) => files.make_folder(&path).await.map(|()| true).map_err(|e| e.to_string()),
                Err(err) => Err(err.to_string()),
            };
            match made {
                Ok(true) => report.folders += 1,
                Ok(false) => {}
                Err(why) => {
                    report.failed.push(format!("{folder}/: {why}"));
                    broken.insert(folder.clone(), why);
                }
            }
        }
        // Queued all at once, so the panel shows what is still to come.
        let mut set = tokio::task::JoinSet::new();
        for file in run.files {
            let info = TransferInfo {
                id: Uuid::new_v4(),
                job_id: Some(run.job_id),
                terminal_id: run.terminal_id,
                terminal: quoted_name(&control),
                direction: Direction::Upload,
                name: file.name.clone(),
                remote_path: join(run.folder, &file.name),
                local_path: Some(file.local_path.clone()),
                size: file.size,
                done: 0,
                bytes_per_sec: 0,
                state: TransferState::Queued,
                message: None,
                sha256: None,
                replace: file.replace,
                as_root: run.as_root,
            };
            let token = self.inner.transfers.add(
                info.clone(),
                Again::Upload {
                    local_path: PathBuf::from(&file.local_path),
                    folder: run.folder.to_owned(),
                    name: file.name.clone(),
                    as_root: run.as_root,
                    keep_times: run.keep_times,
                },
            );
            let above = file.name.rsplit_once('/').map(|(above, _)| above);
            if let Some(why) = above.and_then(|a| broken.get(a)) {
                let message = format!("its folder could not be made: {why}");
                self.inner
                    .transfers
                    .finish(info.id, TransferState::Failed, Some(message.clone()), None);
                report.failed.push(format!("{}: {message}", file.name));
                continue;
            }
            let job = UploadJob {
                ctx: run.ctx,
                job_id: run.job_id,
                tier: run.tier,
                target: run.target.clone(),
                folder: run.folder.to_owned(),
                keep_times: run.keep_times,
                control: Arc::clone(&control),
                info,
                token,
                file: file.clone(),
            };
            let this = self.clone();
            let cancel = cancel.clone();
            set.spawn(async move { this.upload_one(job, &cancel).await });
        }
        while let Some(done) = set.join_next().await {
            match done {
                Ok(Ok(Uploaded::Done(line))) => report.uploaded.push(line),
                Ok(Ok(Uploaded::Cancelled)) => report.cancelled += 1,
                Ok(Ok(Uploaded::Failed(line))) => report.failed.push(line),
                // An audit that failed stops the job, as it did before (QL-15 keeps the job's own result).
                Ok(Err(err)) => {
                    set.abort_all();
                    return Err(err);
                }
                Err(err) => report.failed.push(format!("an upload stopped: {err}")),
            }
        }
        // SS-14 (0.8.0 G3): a sync's deletes, once everything it sends has landed; none after a cancel, and none when an
        // upload failed (the host's folder would lose what this PC's couldn't replace).
        if !run.delete.is_empty() {
            if cancel.is_cancelled() || report.cancelled > 0 {
                report.failed.push("nothing was deleted: the sync was cancelled".into());
            } else if !report.failed.is_empty() {
                report
                    .failed
                    .push("nothing was deleted, since not everything was sent".into());
            } else {
                for name in run.delete {
                    match self.delete_synced(&run, &control, &files, name, cancel).await {
                        Ok(()) => report.deleted += 1,
                        Err(CoreError::Cancelled | CoreError::CancelledRemote) => {
                            report.cancelled += 1;
                            break;
                        }
                        Err(err) => report.failed.push(format!("{name}: {err}")),
                    }
                }
            }
        }
        Ok(report)
    }

    /// SS-14 (0.8.0 G3): one of a sync's deletes: a file or a link over SFTP, a folder with what is in it as G2's
    /// recursive delete does it (GNU `rm -rf --one-file-system` on the host, never through a link). Something gone
    /// already counts as deleted. Audited `file_changed`.
    async fn delete_synced(
        &self,
        run: &UploadRun<'_>,
        control: &Arc<Control>,
        files: &Arc<dyn RemoteFiles>,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let path = join(run.folder, name);
        super::file_ops::check_path(&path)?;
        let what = match files.lstat(&path).await? {
            None => return Ok(()),
            Some(entry) if entry.kind == EntryKind::Folder && !entry.link => {
                // A top-level folder is never deleted with what is in it (G2's rule).
                if !path[1..].contains('/') {
                    return Err(CoreError::InvalidInput(format!(
                        "{path} is a top-level folder, so Remotely won't delete it with what is in it"
                    )));
                }
                self.delete_tree(control, &path, run.as_root, cancel).await?;
                "the folder, with everything in it"
            }
            Some(entry) => {
                files.remove(&path).await?;
                if entry.link {
                    "the link"
                } else {
                    "the file"
                }
            }
        };
        let root = if run.as_root { " as root" } else { "" };
        audit_entry(
            &self.inner.store,
            &run.ctx,
            "file_changed",
            &format!("Deleted {path} on {}{root} (folder sync)", quoted_name(control)),
            Some(run.tier),
            Some(run.job_id),
            std::slice::from_ref(run.target),
            &format!("deleted {what}: this PC's folder doesn't have it"),
        )
        .await
    }

    /// One file of an upload: its turn, the bytes, the audit entry.
    async fn upload_one(&self, job: UploadJob, cancel: &CancellationToken) -> Result<Uploaded> {
        let transfers = &self.inner.transfers;
        let UploadJob { info, token, file, .. } = &job;
        if cancel.is_cancelled() || token.is_cancelled() {
            transfers.finish(info.id, TransferState::Cancelled, Some("cancelled".into()), None);
            return Ok(Uploaded::Cancelled);
        }
        let mut pause = transfers.pauser(info.id);
        // Held until the transfer shows as ended (see `download_one`).
        let mut slot = None;
        match self.copy_up(&job, cancel, &mut pause, &mut slot).await {
            Ok((size, sha, written, times)) => {
                let note = written.note();
                let replaced = match (file.replace, note.is_empty()) {
                    (false, _) => String::new(),
                    (true, true) => ", replacing the file there".to_owned(),
                    (true, false) => format!(", replacing the file there: {note}"),
                };
                let root = if info.as_root { ", as root" } else { "" };
                let action = format!(
                    "Uploaded '{}' to {} on {}{root}",
                    file.name,
                    job.folder,
                    quoted_name(&job.control)
                );
                // What was sent; finishing checked the host's file holds as many bytes.
                let detail = format!("{size} bytes sent, SHA-256 {sha}; to {}{replaced}", info.remote_path);
                job.audit("file_uploaded", &action, &detail, &self.inner.store).await?;
                transfers.change(info.id, |i| i.size = size);
                // H8: a kept backup or a write in place is worth a line in the panel; SS-14: so is a time not kept.
                let mut shown = match &written {
                    Written::ReplacedKeepingBackup { .. } | Written::InPlace { .. } => Some(note.clone()),
                    Written::Created | Written::Replaced => None,
                };
                if let Some(why) = times {
                    shown = Some(match shown {
                        Some(note) => format!("{note}; {why}"),
                        None => why,
                    });
                }
                transfers.finish(info.id, TransferState::Done, shown.clone(), Some(sha));
                Ok(Uploaded::Done(match shown {
                    Some(note) => format!("{} ({}; {note})", file.name, human_size(size)),
                    None => format!("{} ({})", file.name, human_size(size)),
                }))
            }
            Err(Stopped::Cancelled { left }) => {
                transfers.finish(
                    info.id,
                    TransferState::Cancelled,
                    Some(format!("cancelled; {left}")),
                    None,
                );
                Ok(Uploaded::Cancelled)
            }
            Err(Stopped::Failed { err, left }) => {
                let message = match left {
                    Some(left) => format!("{err}; {left}"),
                    None => err.to_string(),
                };
                transfers.finish(info.id, TransferState::Failed, Some(message.clone()), None);
                Ok(Uploaded::Failed(format!("{}: {message}", file.name)))
            }
        }
    }

    /// Sends one local file to the host. Returns its size, SHA-256, how it landed, and why its time wasn't kept (if
    /// it wasn't). The writer is opened and finished outside the cancel race, so a cancel never cuts a replacement's
    /// last step short; a cancel or failure while the bytes go up aborts it (H8: the old file stays as it was).
    async fn copy_up(
        &self,
        job: &UploadJob,
        cancel: &CancellationToken,
        pause: &mut watch::Receiver<bool>,
        slot: &mut Option<OwnedSemaphorePermit>,
    ) -> std::result::Result<(u64, String, Written, Option<String>), Stopped> {
        let UploadJob { info, token, file, .. } = job;
        let mut local = tokio::fs::File::open(&file.local_path).await.map_err(|err| {
            Stopped::failed(CoreError::InvalidInput(format!(
                "'{}' can't be read on this PC: {err}",
                file.local_path
            )))
        })?;
        let size = local.metadata().await.map_err(|err| Stopped::failed(err.into()))?.len();
        self.inner.transfers.change(info.id, |i| i.size = size);
        let nothing_left = || Stopped::Cancelled {
            left: "nothing was left on the host".into(),
        };
        let slots = Arc::clone(&job.control.slots);
        let permit = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(nothing_left()),
            () = token.cancelled() => return Err(nothing_left()),
            permit = self.take_slot(&slots, info.id, pause) => permit.map_err(Stopped::failed)?,
        };
        *slot = Some(permit);
        let (_, files) = self
            .files_for(info.terminal_id, info.as_root)
            .map_err(Stopped::failed)?;
        let mut writer = files
            .write(&info.remote_path, file.replace)
            .await
            .map_err(Stopped::failed)?;
        let pumped = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            () = token.cancelled() => None,
            result = self.pump(&mut local, writer.as_mut(), info, pause, &slots, slot) => Some(result),
        };
        let (done, sha, written) = match pumped {
            None => {
                return Err(Stopped::Cancelled {
                    left: writer.abort().await,
                })
            }
            Some(Err(err)) => {
                return Err(Stopped::Failed {
                    err,
                    left: Some(writer.abort().await),
                })
            }
            Some(Ok((done, sha))) => match writer.finish().await {
                Ok(written) => (done, sha, written),
                Err(err) => return Err(Stopped::Failed { err, left: None }),
            },
        };
        // SS-14: the file's time on this PC.
        let times = match (job.keep_times, file.modified) {
            (true, Some(at)) => files
                .set_attrs(
                    &info.remote_path,
                    SetAttrs {
                        modified: Some(at),
                        ..SetAttrs::default()
                    },
                )
                .await
                .err()
                .map(|err| format!("its modification time was not kept: {err}")),
            _ => None,
        };
        Ok((done, sha, written, times))
    }

    /// The local file's bytes into the writer, with progress. Returns how many and their SHA-256. SS-14: a pause stops
    /// between two chunks: the host's file closes, the slot goes to the next transfer, and the writer goes on from
    /// the same offset once it resumes if the host's file is still exactly what was sent, else from the start.
    async fn pump(
        &self,
        local: &mut tokio::fs::File,
        writer: &mut dyn RemoteWrite,
        info: &TransferInfo,
        pause: &mut watch::Receiver<bool>,
        slots: &Arc<Semaphore>,
        permit: &mut Option<OwnedSemaphorePermit>,
    ) -> Result<(u64, String)> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
            if *pause.borrow() {
                writer.pause().await?;
                drop(permit.take());
                *permit = Some(self.take_slot(slots, info.id, pause).await?);
                let sent = hex::encode(hasher.clone().finalize());
                match writer.resume(done, &sent).await? {
                    Resumed::GoesOn => {}
                    Resumed::FromStart => {
                        local.seek(std::io::SeekFrom::Start(0)).await?;
                        hasher = Sha256::new();
                        done = 0;
                        self.inner.transfers.progress(info.id, 0);
                    }
                }
            }
            let n = local.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            writer.write_all(&buf[..n]).await?;
            done += n as u64;
            self.inner.transfers.progress(info.id, done);
        }
        Ok((done, hex::encode(hasher.finalize())))
    }
}

/// What one file of an upload needs, owned, so the files go up side by side.
struct UploadJob {
    ctx: Context,
    job_id: Uuid,
    tier: Tier,
    target: Target,
    folder: String,
    keep_times: bool,
    control: Arc<Control>,
    info: TransferInfo,
    token: CancellationToken,
    file: UploadFile,
}

impl UploadJob {
    async fn audit(&self, event: &str, action: &str, detail: &str, store: &crate::store::Store) -> Result<()> {
        store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: Some(self.tier),
                    job_id: Some(self.job_id),
                    targets: std::slice::from_ref(&self.target),
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

/// How one file of an upload ended, as the job's report line.
enum Uploaded {
    Done(String),
    Cancelled,
    Failed(String),
}

/// Why an upload did not finish, and what it left on the host.
enum Stopped {
    Cancelled {
        left: String,
    },
    /// `left`: what the aborted write left, when the error came before it finished.
    Failed {
        err: CoreError,
        left: Option<String>,
    },
}

impl Stopped {
    fn failed(err: CoreError) -> Self {
        Self::Failed { err, left: None }
    }
}

/// The home folder, asked once per connection.
async fn home_of(control: &Control, files: &Arc<dyn RemoteFiles>) -> Result<String> {
    if let Some(home) = locks::lock(&control.home).clone() {
        return Ok(home);
    }
    let home = files.home().await?;
    *locks::lock(&control.home) = Some(home.clone());
    Ok(home)
}

/// Deletes a half-written download unless it was finished.
struct RemoveOnDrop(Option<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// SS-08: files chosen in the upload dialog or dropped on a terminal, waiting for their upload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedFiles {
    pub id: Uuid,
    /// What was picked: files, and SS-14 folders (with what is in them).
    pub files: Vec<StagedFile>,
    pub total: u64,
    /// SS-14: the files in all, a folder's counted one by one.
    pub count: usize,
    /// SS-14: links, junctions and what wasn't a file or folder inside the folders, left out.
    pub left_out: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedFile {
    pub name: String,
    pub size: u64,
    /// SS-14: a folder, with `files` files in it.
    pub folder: bool,
    pub files: usize,
}

/// SS-14: one file to upload, by its name with its folders.
#[derive(Debug, Clone)]
struct StagedItem {
    local: PathBuf,
    name: String,
    size: u64,
    modified: Option<u64>,
}

struct Staged {
    /// What was picked or dropped, as given (VM-23 takes an ISO this way).
    paths: Vec<PathBuf>,
    items: Vec<StagedItem>,
    /// SS-14: folders to make, parents first.
    folders: Vec<String>,
    at: Instant,
}

/// SS-14: a link, a junction or another reparse point: never followed into (it may lead anywhere on this PC).
pub(crate) fn is_link(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// SS-14: a local folder's files and folders, by their names under `top`; links and junctions are left out. Returns
/// how many were left out.
fn walk_local(root: &Path, top: &str, items: &mut Vec<StagedItem>, folders: &mut Vec<String>) -> Result<usize> {
    let mut left_out = 0;
    folders.push(top.to_owned());
    let mut queue = VecDeque::from([(root.to_owned(), top.to_owned(), 1usize)]);
    while let Some((folder, shown, depth)) = queue.pop_front() {
        let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(&folder)
            .map_err(|err| CoreError::InvalidInput(format!("'{}' can't be read: {err}", folder.display())))?
            .filter_map(std::result::Result::ok)
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                left_out += 1;
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let shown_name = format!("{shown}/{name}");
            if is_link(&meta) {
                left_out += 1;
            } else if meta.is_dir() {
                if depth >= MAX_FOLDER_DEPTH {
                    return Err(CoreError::InvalidInput(format!(
                        "'{top}' is more than {MAX_FOLDER_DEPTH} folders deep; upload a part of it."
                    )));
                }
                folders.push(shown_name.clone());
                queue.push_back((entry.path(), shown_name, depth + 1));
            } else if meta.is_file() {
                items.push(StagedItem {
                    local: entry.path(),
                    name: shown_name,
                    size: meta.len(),
                    modified: meta.modified().ok().and_then(unix_secs),
                });
            } else {
                left_out += 1;
            }
            if items.len() > MAX_UPLOAD_FILES {
                return Err(CoreError::InvalidInput(format!(
                    "One upload takes at most {MAX_UPLOAD_FILES} files; '{top}' holds more."
                )));
            }
        }
    }
    Ok(left_out)
}

/// SS-08: how starting an upload went.
// Built once per upload and handed straight to the UI, so the approval request it may carry (grown by VM-08's and
// VM-14's previews) isn't worth a box, which would also stop callers matching into it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum UploadStart {
    /// These are in the folder already; ask, then call again with another [`Existing`].
    Conflicts { existing: Vec<String>, folder: String },
    /// On the bus: queued (Low), or waiting for the approval dialog.
    Submitted { outcome: SubmitOutcome },
    /// Every file was there already and skipped.
    Nothing,
}

/// SS-08: what retrying a transfer started.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Retried {
    // Boxed: an upload's start may hold a whole approval request.
    Upload { start: Box<UploadStart> },
    Download { transfers: Vec<TransferInfo> },
}

/// SS-14: what an upload will do, file by file, once [`Existing`] decided about the files that are there.
struct UploadPlan {
    files: Vec<UploadFile>,
    folders: Vec<String>,
    conflicts: Vec<String>,
}

/// SS-08: the bus-facing side of file transfers (`Core.files`): files staged for upload, uploads
/// submitted as commands, retries. SS-14: file changes too ([`super::file_ops`]).
pub struct FileTransfers {
    /// FD-02: the workspace shown, whose terminals the uploads go to.
    pub(super) workspace: crate::workspaces::Current,
    pub(super) terminals: Terminals,
    pub(super) bus: Arc<CommandBus>,
    staged: Mutex<HashMap<Uuid, Staged>>,
    /// SS-14: folders on this PC a download's conflict question is about, by [`DownloadStart::Conflicts`]'s `choice`.
    chosen: Mutex<HashMap<Uuid, (PathBuf, Instant)>>,
}

/// SS-14: where a download goes: a folder the shell chose (Downloads or a dialog's), or the one a conflict question
/// was about.
#[derive(Debug, Clone)]
pub enum DownloadDest {
    Folder(PathBuf),
    Chosen(Uuid),
}

impl FileTransfers {
    pub fn new(workspace: crate::workspaces::Current, terminals: Terminals, bus: Arc<CommandBus>) -> Self {
        Self {
            workspace,
            terminals,
            bus,
            staged: Mutex::default(),
            chosen: Mutex::default(),
        }
    }

    /// SS-14: [`Terminals::download_with`] into `dest`. A conflict question keeps the folder for its answer
    /// ([`DownloadDest::Chosen`]), for as long as staged files are kept.
    pub async fn download(
        &self,
        terminal_id: Uuid,
        paths: &[String],
        dest: DownloadDest,
        options: DownloadOptions,
    ) -> Result<DownloadStart> {
        let folder = match dest {
            DownloadDest::Folder(folder) => folder,
            DownloadDest::Chosen(choice) => {
                let mut chosen = locks::lock(&self.chosen);
                chosen.retain(|_, (_, at)| at.elapsed() < STAGED_FOR);
                chosen.get(&choice).map(|(folder, _)| folder.clone()).ok_or_else(|| {
                    CoreError::InvalidInput("That download's folder is no longer known; download it again.".into())
                })?
            }
        };
        let start = self
            .terminals
            .download_with(&self.workspace.get(), terminal_id, paths, &folder, options)
            .await?;
        Ok(match start {
            DownloadStart::Conflicts { existing, dest, .. } => {
                let choice = Uuid::new_v4();
                locks::lock(&self.chosen).insert(choice, (folder, Instant::now()));
                DownloadStart::Conflicts {
                    existing,
                    dest,
                    choice: Some(choice),
                }
            }
            queued => queued,
        })
    }

    /// Keeps files picked in a dialog or dropped on a terminal for their upload. SS-14: a folder comes with what is
    /// in it (links and junctions left out, so nothing outside it comes along). Two of the same name are refused.
    pub fn stage(&self, paths: Vec<PathBuf>) -> Result<StagedFiles> {
        if paths.is_empty() {
            return Err(CoreError::InvalidInput("No file was chosen.".into()));
        }
        if paths.len() > MAX_UPLOAD_FILES {
            return Err(CoreError::InvalidInput(format!(
                "One upload takes at most {MAX_UPLOAD_FILES} files."
            )));
        }
        let mut shown: Vec<StagedFile> = Vec::with_capacity(paths.len());
        let mut items = Vec::new();
        let mut folders = Vec::new();
        let mut left_out = 0;
        for path in &paths {
            let meta = std::fs::symlink_metadata(path)
                .map_err(|err| CoreError::InvalidInput(format!("'{}' can't be read: {err}", path.display())))?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if shown.iter().any(|f| f.name == name) {
                return Err(CoreError::InvalidInput(format!(
                    "Two files are named '{name}'; upload them one at a time."
                )));
            }
            if is_link(&meta) {
                // What a link points to, as a file; a link to a folder isn't followed.
                let target = std::fs::metadata(path)
                    .map_err(|err| CoreError::InvalidInput(format!("'{}' can't be read: {err}", path.display())))?;
                if !target.is_file() {
                    return Err(CoreError::InvalidInput(format!(
                        "'{name}' is a link to a folder; pick the folder itself."
                    )));
                }
                items.push(StagedItem {
                    local: path.clone(),
                    name: name.clone(),
                    size: target.len(),
                    modified: target.modified().ok().and_then(unix_secs),
                });
                shown.push(StagedFile {
                    name,
                    size: target.len(),
                    folder: false,
                    files: 1,
                });
            } else if meta.is_dir() {
                let before = items.len();
                left_out += walk_local(path, &name, &mut items, &mut folders)?;
                let size = items[before..].iter().map(|i| i.size).sum();
                shown.push(StagedFile {
                    name,
                    size,
                    folder: true,
                    files: items.len() - before,
                });
            } else {
                items.push(StagedItem {
                    local: path.clone(),
                    name: name.clone(),
                    size: meta.len(),
                    modified: meta.modified().ok().and_then(unix_secs),
                });
                shown.push(StagedFile {
                    name,
                    size: meta.len(),
                    folder: false,
                    files: 1,
                });
            }
            if items.len() > MAX_UPLOAD_FILES {
                return Err(CoreError::InvalidInput(format!(
                    "One upload takes at most {MAX_UPLOAD_FILES} files."
                )));
            }
        }
        let id = Uuid::new_v4();
        let total = items.iter().map(|i| i.size).sum();
        let count = items.len();
        let mut staged = locks::lock(&self.staged);
        staged.retain(|_, s| s.at.elapsed() < STAGED_FOR);
        staged.insert(
            id,
            Staged {
                paths,
                items,
                folders,
                at: Instant::now(),
            },
        );
        Ok(StagedFiles {
            id,
            files: shown,
            total,
            count,
            left_out,
        })
    }

    /// Forgets staged files (the user closed the question about them).
    pub fn unstage(&self, id: Uuid) {
        locks::lock(&self.staged).remove(&id);
    }

    /// VM-23: staged files taken for another use than an upload (an ISO dropped on a VM). They are no
    /// longer staged afterwards.
    pub fn take_staged(&self, id: Uuid) -> Result<Vec<PathBuf>> {
        locks::lock(&self.staged)
            .remove(&id)
            .map(|s| s.paths)
            .ok_or_else(|| CoreError::InvalidInput("Those files are no longer waiting; drop them again.".into()))
    }

    /// Uploads staged files into `folder` on the terminal's host: a command on the bus. With
    /// [`Existing::Ask`], files that are there already come back as [`UploadStart::Conflicts`] and
    /// nothing is submitted.
    pub async fn upload(
        &self,
        terminal_id: Uuid,
        staged_id: Uuid,
        folder: &str,
        existing: Existing,
    ) -> Result<UploadStart> {
        self.upload_as(terminal_id, staged_id, folder, existing, false).await
    }

    /// SS-14: [`FileTransfers::upload`], as root when `as_root` (root browsing must be on; one tier higher).
    pub async fn upload_as(
        &self,
        terminal_id: Uuid,
        staged_id: Uuid,
        folder: &str,
        existing: Existing,
        as_root: bool,
    ) -> Result<UploadStart> {
        let (items, folders) = {
            let staged = locks::lock(&self.staged);
            let s = staged.get(&staged_id).ok_or_else(|| {
                CoreError::InvalidInput("Those files are no longer waiting to upload; choose them again.".into())
            })?;
            (s.items.clone(), s.folders.clone())
        };
        let folder = folder.trim_end_matches('/');
        let folder = if folder.is_empty() { "/" } else { folder };
        let (_, files) = self.terminals.files_for(terminal_id, as_root)?;
        let plan = plan_upload(&files, folder, &items, folders, existing).await?;
        if existing == Existing::Ask && !plan.conflicts.is_empty() {
            return Ok(UploadStart::Conflicts {
                existing: plan.conflicts,
                folder: folder.to_owned(),
            });
        }
        locks::lock(&self.staged).remove(&staged_id);
        if plan.files.is_empty() && plan.folders.is_empty() {
            return Ok(UploadStart::Nothing);
        }
        self.submit(terminal_id, folder, plan.files, plan.folders, as_root, true)
            .await
    }

    async fn submit(
        &self,
        terminal_id: Uuid,
        folder: &str,
        files: Vec<UploadFile>,
        folders: Vec<String>,
        as_root: bool,
        keep_times: bool,
    ) -> Result<UploadStart> {
        let target = self.terminals.target(&self.workspace.get(), terminal_id).await?;
        let command = Command::FileUpload {
            targets: vec![target.target],
            folder: folder.to_owned(),
            files,
            folders,
            keep_times,
            as_root,
            delete: Vec::new(),
        };
        let outcome = self.bus.submit(&self.workspace.get(), command).await?;
        Ok(UploadStart::Submitted { outcome })
    }

    /// Runs a finished transfer again: an upload goes through the bus again (it replaces the file if
    /// one is there now, which the approval shows), a download goes to the same folder.
    pub async fn retry(&self, transfer_id: Uuid) -> Result<Retried> {
        let (info, again) = self
            .terminals
            .inner
            .transfers
            .get(transfer_id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("transfer {transfer_id}")))?;
        if !info.state.finished() {
            return Err(CoreError::InvalidInput("That transfer is still running.".into()));
        }
        match again {
            Again::Upload {
                local_path,
                folder,
                name,
                as_root,
                keep_times,
            } => {
                let meta = std::fs::metadata(&local_path).map_err(|err| {
                    CoreError::InvalidInput(format!("'{}' can't be read any more: {err}", local_path.display()))
                })?;
                let (_, files) = self.terminals.files_for(info.terminal_id, as_root)?;
                let there = files.stat(&join(&folder, &name)).await?;
                if there.as_ref().is_some_and(|e| e.kind == EntryKind::Folder) {
                    return Err(CoreError::InvalidInput(format!(
                        "{} is a folder on the host, so a file can't replace it.",
                        join(&folder, &name)
                    )));
                }
                let file = UploadFile {
                    local_path: local_path.display().to_string(),
                    name: name.clone(),
                    size: meta.len(),
                    replace: there.is_some(),
                    modified: meta.modified().ok().and_then(unix_secs),
                };
                // The folders it is in, used as they are when they are there.
                let parts: Vec<&str> = name.split('/').collect();
                let folders = (1..parts.len()).map(|n| parts[..n].join("/")).collect();
                let start = self
                    .submit(info.terminal_id, &folder, vec![file], folders, as_root, keep_times)
                    .await?;
                Ok(Retried::Upload { start: Box::new(start) })
            }
            Again::Download {
                dest,
                existing,
                as_root,
            } => {
                let options = DownloadOptions { existing, as_root };
                let start = self
                    .terminals
                    .download_with(
                        &self.workspace.get(),
                        info.terminal_id,
                        std::slice::from_ref(&info.remote_path),
                        &dest,
                        options,
                    )
                    .await?;
                let transfers = match start {
                    DownloadStart::Queued { transfers, .. } => transfers,
                    DownloadStart::Conflicts { .. } => Vec::new(),
                };
                Ok(Retried::Download { transfers })
            }
        }
    }

    /// Where a finished download was saved, for "Open folder".
    pub fn saved_at(&self, transfer_id: Uuid) -> Option<PathBuf> {
        let (info, _) = self.terminals.inner.transfers.get(transfer_id)?;
        (info.direction == Direction::Download && info.state == TransferState::Done)
            .then(|| info.local_path.map(PathBuf::from))
            .flatten()
    }
}

/// SS-14: decides, for each staged file, whether it goes up as it is, replaces the host's, goes up beside it with a
/// number, or stays (by `existing`); each host folder is listed once. A folder of the upload where a file is, or a
/// file where a folder is, is refused.
async fn plan_upload(
    files: &Arc<dyn RemoteFiles>,
    folder: &str,
    items: &[StagedItem],
    folders: Vec<String>,
    existing: Existing,
) -> Result<UploadPlan> {
    // Each host folder's names, listed once; `None`: not there (the upload makes it). A folder with more than one
    // listing holds is asked about name by name.
    let mut listed: HashMap<String, Option<HashMap<String, RemoteEntry>>> = HashMap::new();
    let mut by_name: HashSet<String> = HashSet::new();
    async fn names_in(
        files: &Arc<dyn RemoteFiles>,
        listed: &mut HashMap<String, Option<HashMap<String, RemoteEntry>>>,
        by_name: &mut HashSet<String>,
        folder: &str,
    ) -> Result<()> {
        if listed.contains_key(folder) || by_name.contains(folder) {
            return Ok(());
        }
        match files.list(folder).await {
            Ok(listing) if listing.more => {
                by_name.insert(folder.to_owned());
            }
            Ok(listing) => {
                let names = listing.entries.into_iter().map(|e| (e.name.clone(), e)).collect();
                listed.insert(folder.to_owned(), Some(names));
            }
            Err(CoreError::RemoteNotFound { .. }) => {
                listed.insert(folder.to_owned(), None);
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }
    async fn entry_at(
        files: &Arc<dyn RemoteFiles>,
        listed: &mut HashMap<String, Option<HashMap<String, RemoteEntry>>>,
        by_name: &mut HashSet<String>,
        folder: &str,
        name: &str,
    ) -> Result<Option<RemoteEntry>> {
        names_in(files, listed, by_name, folder).await?;
        if by_name.contains(folder) {
            return files.stat(&join(folder, name)).await;
        }
        Ok(listed
            .get(folder)
            .and_then(|names| names.as_ref())
            .and_then(|names| names.get(name).cloned()))
    }
    for made in &folders {
        let (above, name) = match made.rsplit_once('/') {
            Some((above, name)) => (join(folder, above), name),
            None => (folder.to_owned(), made.as_str()),
        };
        if let Some(entry) = entry_at(files, &mut listed, &mut by_name, &above, name).await? {
            if entry.kind != EntryKind::Folder {
                return Err(CoreError::InvalidInput(format!(
                    "{} is a file on the host, so the folder '{made}' can't go there. Rename it, or upload elsewhere.",
                    join(&above, name)
                )));
            }
        }
    }
    let mut plan = UploadPlan {
        files: Vec::new(),
        folders,
        conflicts: Vec::new(),
    };
    // Names this upload gives in each folder, so a kept-both file never takes a number another file of it has or gets.
    let mut given: HashSet<String> = items.iter().map(|item| join(folder, &item.name)).collect();
    for item in items {
        let (sub, name) = match item.name.rsplit_once('/') {
            Some((sub, name)) => (Some(sub), name),
            None => (None, item.name.as_str()),
        };
        let host_folder = sub.map_or_else(|| folder.to_owned(), |sub| join(folder, sub));
        let there = entry_at(files, &mut listed, &mut by_name, &host_folder, name).await?;
        let mut file = UploadFile {
            local_path: item.local.display().to_string(),
            name: item.name.clone(),
            size: item.size,
            replace: false,
            modified: item.modified,
        };
        if let Some(entry) = there {
            if entry.kind == EntryKind::Folder {
                return Err(CoreError::InvalidInput(format!(
                    "{} is a folder on the host, so a file can't replace it. Rename the file, or upload it elsewhere.",
                    join(&host_folder, name)
                )));
            }
            if existing == Existing::Ask {
                plan.conflicts.push(item.name.clone());
                continue;
            }
            match existing.decide(item.modified, entry.modified) {
                Some(true) => file.replace = true,
                Some(false) => {
                    let mut n = 1;
                    loop {
                        let candidate = numbered(name, n);
                        let full = join(&host_folder, &candidate);
                        let taken = given.contains(&full)
                            || entry_at(files, &mut listed, &mut by_name, &host_folder, &candidate)
                                .await?
                                .is_some();
                        if !taken {
                            file.name = match sub {
                                Some(sub) => format!("{sub}/{candidate}"),
                                None => candidate,
                            };
                            break;
                        }
                        n += 1;
                        if n > 1000 {
                            return Err(CoreError::InvalidInput(format!(
                                "{host_folder} holds too many files named like '{name}'."
                            )));
                        }
                    }
                }
                None => continue,
            }
        }
        given.insert(join(folder, &file.name));
        plan.files.push(file);
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_resolve_from_the_shell_folder_or_home() {
        let home = "/home/alice";
        assert_eq!(resolve("/srv/www", home, "index.html"), "/srv/www/index.html");
        assert_eq!(resolve("/srv/www", home, "../logs/app.log"), "/srv/logs/app.log");
        assert_eq!(resolve("/srv/www", home, "/etc/hosts"), "/etc/hosts");
        assert_eq!(resolve("/srv/www", home, "~/notes.txt"), "/home/alice/notes.txt");
        assert_eq!(resolve("/srv/www", home, "~"), "/home/alice");
        assert_eq!(resolve("/", home, "./a//b/"), "/a/b");
        assert_eq!(resolve("/", home, "../.."), "/");
        assert_eq!(parent("/srv/www"), Some("/srv".into()));
        assert_eq!(parent("/srv"), Some("/".into()));
        assert_eq!(parent("/"), None);
        assert_eq!(join("/", "etc"), "/etc");
    }

    #[test]
    fn host_names_become_names_windows_takes() {
        assert_eq!(local_name("report.pdf"), "report.pdf");
        assert_eq!(local_name("a:b*c?.txt"), "a_b_c_.txt");
        assert_eq!(local_name("trailing. "), "trailing");
        assert_eq!(local_name("..."), "download");
    }

    #[test]
    fn names_windows_saves_as_git_are_git_data() {
        for git in [".git", ".GIT", ".git.", ".git ", ".GIT.", ".Git. .", ".git.."] {
            assert!(is_git_name(git), "{git:?}");
            assert!(lands_as_git(&format!("site/{git}/hooks/post-checkout")), "{git:?}");
            assert!(lands_as_git(&format!("{git}/HEAD")), "{git:?}");
        }
        for not_git in [".gitignore", ".git_", "git", "_.git", ".git (1)", ".github"] {
            assert!(!is_git_name(not_git), "{not_git:?}");
            assert!(!lands_as_git(&format!("site/{not_git}/x")), "{not_git:?}");
        }
    }

    #[tokio::test]
    async fn no_file_is_saved_under_a_name_git_takes() {
        let dir = std::env::temp_dir().join(format!("remotely-claim-git-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        for git in [".git", ".git.", ".GIT ", ".git. "] {
            assert!(claim_file(&dir, git).await.is_err(), "{git:?}");
        }
        assert!(!dir.join(".git").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn format_characters_never_reach_a_saved_name() {
        assert_eq!(local_name("invoice\u{202E}fdp.exe"), "invoice_fdp.exe");
        for c in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{FEFF}', '\u{00AD}', '\u{202A}', '\u{061C}', '\u{2028}', '\u{2029}',
        ] {
            let name = format!("report{c}.pdf");
            assert_eq!(local_name(&name), "report_.pdf", "U+{:04X}", u32::from(c));
        }
        // Letters of other scripts and ordinary spaces stay.
        assert_eq!(local_name("отчёт 2026 é.pdf"), "отчёт 2026 é.pdf");
        assert_eq!(local_name("\u{FEFF}"), "_");
    }

    #[test]
    fn device_names_are_saved_as_files() {
        for (host, here) in [
            ("nul", "_nul"),
            ("NUL", "_NUL"),
            ("nul.txt", "_nul.txt"),
            ("Com1", "_Com1"),
            ("com1.log", "_com1.log"),
            ("LPT9.tar.gz", "_LPT9.tar.gz"),
            ("lpt0", "_lpt0"),
            ("con", "_con"),
            ("Prn.pdf", "_Prn.pdf"),
            ("aux.c", "_aux.c"),
            ("CONIN$", "_CONIN$"),
            ("conout$.txt", "_conout$.txt"),
            ("COM¹", "_COM¹"),
            ("lpt³.txt", "_lpt³.txt"),
            ("nul .txt", "_nul .txt"),
            ("aux. ", "_aux"),
            ("nul..", "_nul"),
        ] {
            assert_eq!(local_name(host), here, "{host}");
        }
        for file in [
            "console.log",
            "nullable.txt",
            "auxiliary",
            "prnt.txt",
            "com10",
            "lpt",
            "com",
            "comx.txt",
            "my.nul",
            "connect.sh",
        ] {
            assert_eq!(local_name(file), file, "{file}");
        }
    }

    #[tokio::test]
    async fn a_download_never_overwrites_a_file_on_this_pc() {
        let dir = std::env::temp_dir().join(format!("remotely-claim-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let (first, _) = claim_file(&dir, "app.log").await.unwrap();
        let (second, _) = claim_file(&dir, "app.log").await.unwrap();
        let (third, _) = claim_file(&dir, "README").await.unwrap();
        let (fourth, _) = claim_file(&dir, "README").await.unwrap();
        assert_eq!(first.file_name().unwrap(), "app.log");
        assert_eq!(second.file_name().unwrap(), "app (1).log");
        assert_eq!(third.file_name().unwrap(), "README");
        assert_eq!(fourth.file_name().unwrap(), "README (1)");
        // A device name lands in the folder as a real file, numbered like any other.
        let (device, _) = claim_file(&dir, "nul.txt").await.unwrap();
        let (again, _) = claim_file(&dir, "nul.txt").await.unwrap();
        assert_eq!(device, dir.join("_nul.txt"));
        assert_eq!(again, dir.join("_nul (1).txt"));
        assert!(device.is_file() && again.is_file());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn upload_reports_say_what_landed_and_what_did_not() {
        let report = UploadReport {
            uploaded: vec!["a.txt (1.5 KB)".into()],
            cancelled: 1,
            failed: vec!["b.txt: alice can't write to /etc/b.txt on the host (permission denied).".into()],
            folders: 0,
            deleted: 0,
        };
        let summary = report.summary("/srv");
        assert!(summary.starts_with("uploaded to /srv: a.txt (1.5 KB); 1 cancelled; failed: b.txt"));
        assert!(report.failure().unwrap().starts_with("b.txt: alice can't"));
        assert_eq!(UploadReport::default().summary("/srv"), "nothing uploaded");
        let folder = UploadReport {
            uploaded: (0..60).map(|n| format!("f{n}")).collect(),
            folders: 3,
            ..UploadReport::default()
        };
        assert_eq!(folder.summary("/srv"), "3 folders made; uploaded 60 files to /srv");
    }

    #[test]
    fn existing_files_are_replaced_skipped_or_kept_beside_as_asked() {
        assert_eq!(Existing::Replace.decide(Some(1), Some(2)), Some(true));
        assert_eq!(Existing::Skip.decide(Some(3), Some(2)), None);
        assert_eq!(Existing::KeepBoth.decide(None, None), Some(false));
        assert_eq!(Existing::ReplaceIfNewer.decide(Some(3), Some(2)), Some(true));
        assert_eq!(
            Existing::ReplaceIfNewer.decide(Some(2), Some(2)),
            None,
            "as new is not newer"
        );
        assert_eq!(Existing::ReplaceIfNewer.decide(Some(1), Some(2)), None);
        assert_eq!(
            Existing::ReplaceIfNewer.decide(None, Some(2)),
            None,
            "unknown is left alone"
        );
        assert_eq!(numbered("report.pdf", 2), "report (2).pdf");
        assert_eq!(numbered(".bashrc", 1), ".bashrc (1)");
        assert_eq!(numbered("README", 0), "README");
    }

    #[test]
    fn a_folder_is_staged_with_what_is_in_it() {
        let root = std::env::temp_dir().join(format!("remotely-stage-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("site/css/empty")).unwrap();
        std::fs::write(root.join("site/index.html"), b"<p>hi</p>").unwrap();
        std::fs::write(root.join("site/css/main.css"), b"p{}").unwrap();
        let mut items = Vec::new();
        let mut folders = Vec::new();
        let left_out = walk_local(&root.join("site"), "site", &mut items, &mut folders).unwrap();
        assert_eq!(left_out, 0);
        assert_eq!(folders, vec!["site", "site/css", "site/css/empty"]);
        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["site/index.html", "site/css/main.css"]);
        assert!(items.iter().all(|i| i.modified.is_some()));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
