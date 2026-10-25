//! SS-08: files on a terminal's host, over SFTP on the terminal's own connection
//! ([`RemoteFiles`]): no second login, no second window.
//!
//! * The "Files here" drawer lists the folder the shell is in ([`super::folder`]), or the home folder
//!   when the shell does not say, and any folder the user opens from there ([`Terminals::list_folder`]).
//! * Downloads ([`Terminals::download`]) are reads: they skip approval, like saving a terminal's
//!   output (SS-11), and are audited the same way: the file's name, size, host path, where it was
//!   saved and its SHA-256, never its content. The folder is picked in a dialog the shell opens, or is
//!   Downloads; a file of the same name there is kept and the new one gets a number.
//! * Uploads are changes: [`FileTransfers::upload`] submits a [`Command::FileUpload`] to the command
//!   bus (Low; Prod raises it; replacing a file is at least Medium), and the job runner carries it out
//!   here ([`TerminalActions::upload`]). Each uploaded file is audited with its name, size,
//!   destination and SHA-256. The files come from a dialog the shell opens or a drop on the terminal
//!   ([`FileTransfers::stage`]); the UI never names a path on this PC.
//! * Uploads write as the logged-in user, never with sudo; a protected folder fails with
//!   [`CoreError::RemotePermissionDenied`]. A new file that fails or is cancelled part way is deleted
//!   again; a replaced file is left as far as it got, and the message says so.
//! * Every transfer is in [`Transfers`] while it runs and for a while after: progress, speed, cancel
//!   and retry for the transfers panel ([`TransferInfo`], sent on [`Terminals::subscribe_transfers`]).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::folder::FolderInfo;
use super::{audit, quoted_name, Control, Terminals};
use crate::adapters::remote::{EntryKind, RemoteEntry, RemoteFiles, RemoteWrite, Written};
use crate::command_bus::{human_size, Command, CommandBus, SubmitOutcome, UploadFile, MAX_UPLOAD_FILES};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferState {
    Queued,
    Running,
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
    /// An upload that replaces a file on the host.
    pub replace: bool,
}

/// What a finished transfer needs to run again.
#[derive(Debug, Clone)]
enum Again {
    Upload { local_path: PathBuf, folder: String },
    Download { dest: PathBuf },
}

struct Entry {
    info: TransferInfo,
    cancel: CancellationToken,
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

    fn token(&self, id: Uuid) -> Option<CancellationToken> {
        locks::lock(&self.list)
            .iter()
            .find(|e| e.info.id == id)
            .map(|e| e.cancel.clone())
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
}

/// SS-08: how an upload went, file by file.
#[derive(Debug, Default)]
pub struct UploadReport {
    /// "a.txt (1.5 KB)".
    pub uploaded: Vec<String>,
    pub cancelled: usize,
    /// "a.txt: why".
    pub failed: Vec<String>,
}

impl UploadReport {
    /// For the job's audit entry.
    pub fn summary(&self, folder: &str) -> String {
        let mut parts = Vec::new();
        if !self.uploaded.is_empty() {
            parts.push(format!("uploaded to {folder}: {}", self.uploaded.join(", ")));
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
fn local_name(name: &str) -> String {
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
/// streams, as FAT and exFAT drives don't), and the download still counts. Windows only.
async fn mark_downloaded(path: &Path) -> Option<String> {
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

/// Creates a new file in `folder` named `name`, or `name (1)`, `name (2)`... when that is taken, so a
/// download never overwrites a file on this PC.
async fn claim_file(folder: &Path, name: &str) -> Result<(PathBuf, tokio::fs::File)> {
    let name = local_name(name);
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_owned(), format!(".{ext}")),
        _ => (name.clone(), String::new()),
    };
    for n in 0..1000 {
        let candidate = match n {
            0 => folder.join(&name),
            n => folder.join(format!("{stem} ({n}){extension}")),
        };
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

impl Terminals {
    fn live(&self, id: Uuid) -> Result<(Arc<Control>, Arc<dyn RemoteFiles>)> {
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
        let (control, files) = self.live(id)?;
        let home = home_of(&control, &files).await?;
        let shell = locks::lock(&control.folder)
            .path
            .clone()
            .unwrap_or_else(|| home.clone());
        let base = from.map_or_else(|| shell.clone(), |from| resolve("/", &home, from));
        let path = resolve(&base, &home, path.unwrap_or(&shell));
        Ok(self.listing(&control, &files, path).await)
    }

    /// QL-09: the drawer's Back from `from` (the folder it shows): the folder that opened before it,
    /// or, when `from` could not be opened, the last one that did.
    pub async fn folder_back(&self, id: Uuid, from: &str) -> Result<FolderListing> {
        let (control, files) = self.live(id)?;
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

    /// SS-08: downloads files from the terminal's host into `dest` on this PC, one after another; returns
    /// them as queued. Each is audited when it is saved: name, size, host path, where it went, SHA-256. Never
    /// into a Git working tree ([`crate::save_guard`]).
    pub async fn download(&self, ctx: &Context, id: Uuid, paths: &[String], dest: &Path) -> Result<Vec<TransferInfo>> {
        crate::save_guard::refuse_repository_folder(dest, crate::save_guard::Saved::Download)?;
        let (control, files) = self.live(id)?;
        if !dest.is_dir() {
            return Err(CoreError::InvalidInput(format!("{} is not a folder.", dest.display())));
        }
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
        let mut found = Vec::new();
        for path in paths {
            let full = resolve(&base, &home, path);
            let entry = files
                .stat(&full)
                .await?
                .ok_or_else(|| CoreError::RemoteNotFound { path: full.clone() })?;
            match entry.kind {
                EntryKind::File => found.push((full, entry)),
                EntryKind::Folder => {
                    return Err(CoreError::InvalidInput(format!(
                        "{full} is a folder. Remotely downloads files: open the folder and pick the files in it."
                    )))
                }
                EntryKind::Other => {
                    return Err(CoreError::InvalidInput(format!(
                        "{full} is not a regular file (a device, socket or broken link), so it can't be downloaded."
                    )))
                }
            }
        }
        let mut queued = Vec::new();
        for (full, entry) in found {
            let info = TransferInfo {
                id: Uuid::new_v4(),
                job_id: None,
                terminal_id: id,
                terminal: quoted_name(&control),
                direction: Direction::Download,
                name: entry.name.clone(),
                remote_path: full,
                local_path: None,
                size: entry.size,
                done: 0,
                bytes_per_sec: 0,
                state: TransferState::Queued,
                message: None,
                sha256: None,
                replace: false,
            };
            self.inner
                .transfers
                .add(info.clone(), Again::Download { dest: dest.to_owned() });
            queued.push(info);
        }
        let this = self.clone();
        let ctx = *ctx;
        let ids: Vec<Uuid> = queued.iter().map(|t| t.id).collect();
        let dest = dest.to_owned();
        tokio::spawn(async move {
            for transfer in ids {
                this.download_one(&ctx, &control, &files, transfer, &dest).await;
            }
        });
        Ok(queued)
    }

    async fn download_one(
        &self,
        ctx: &Context,
        control: &Arc<Control>,
        files: &Arc<dyn RemoteFiles>,
        transfer: Uuid,
        dest: &Path,
    ) {
        let transfers = &self.inner.transfers;
        let (Some((info, _)), Some(cancel)) = (transfers.get(transfer), transfers.token(transfer)) else {
            return;
        };
        if cancel.is_cancelled() {
            transfers.finish(transfer, TransferState::Cancelled, Some("cancelled".into()), None);
            return;
        }
        transfers.start(transfer);
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(None),
            result = self.copy_down(files, &info, dest) => result.map_err(Some),
        };
        match result {
            Ok((local, sha, note)) => {
                let shown = local.display().to_string();
                transfers.change(transfer, |i| i.local_path = Some(shown.clone()));
                let action = format!("Downloaded '{}' from {}", info.name, quoted_name(control));
                let detail = format!(
                    "{}, {} bytes, SHA-256 {sha}; saved to {shown}",
                    info.remote_path, info.size
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

    /// Copies one host file to a new file in `dest`, then marks it as from the internet (A8); returns
    /// where it went, its SHA-256 and a note when the mark could not be written. A file left half
    /// written (or not yet marked) is deleted.
    async fn copy_down(
        &self,
        files: &Arc<dyn RemoteFiles>,
        info: &TransferInfo,
        dest: &Path,
    ) -> Result<(PathBuf, String, Option<String>)> {
        let mut reader = files.read(&info.remote_path).await?;
        let (path, mut file) = claim_file(dest, &info.name).await?;
        let mut cleanup = RemoveOnDrop(Some(path.clone()));
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
            let n = reader.read(&mut buf).await?;
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
        // A8: before the download counts as done.
        let note = mark_downloaded(&path).await;
        cleanup.0 = None;
        Ok((path, hex::encode(hasher.finalize()), note))
    }

    /// SS-08: the job runner's half of [`Command::FileUpload`]: each file in turn over the terminal's
    /// SFTP channel, audited as it lands.
    pub(crate) async fn run_upload(&self, run: UploadRun<'_>, cancel: &CancellationToken) -> Result<UploadReport> {
        let (control, files) = self.live(run.terminal_id)?;
        let mut report = UploadReport::default();
        // Queued all at once, so the panel shows what is still to come.
        let mut queue = Vec::new();
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
            };
            let token = self.inner.transfers.add(
                info.clone(),
                Again::Upload {
                    local_path: PathBuf::from(&file.local_path),
                    folder: run.folder.to_owned(),
                },
            );
            queue.push((info, token, file));
        }
        for (info, token, file) in queue {
            let transfers = &self.inner.transfers;
            if cancel.is_cancelled() || token.is_cancelled() {
                transfers.finish(info.id, TransferState::Cancelled, Some("cancelled".into()), None);
                report.cancelled += 1;
                continue;
            }
            transfers.start(info.id);
            match self.copy_up(&files, &info, file, cancel, &token).await {
                Ok((size, sha, written)) => {
                    let note = written.note();
                    let replaced = match (file.replace, note.is_empty()) {
                        (false, _) => String::new(),
                        (true, true) => ", replacing the file there".to_owned(),
                        (true, false) => format!(", replacing the file there: {note}"),
                    };
                    let action = format!(
                        "Uploaded '{}' to {} on {}",
                        file.name,
                        run.folder,
                        quoted_name(&control)
                    );
                    let detail = format!("{size} bytes, SHA-256 {sha}; to {}{replaced}", info.remote_path);
                    run.ctx_audit(&self.inner.store, "file_uploaded", &action, &detail)
                        .await?;
                    transfers.change(info.id, |i| i.size = size);
                    // H8: a kept backup or a write in place is worth a line in the panel.
                    let shown = match &written {
                        Written::ReplacedKeepingBackup { .. } | Written::InPlace { .. } => Some(note.clone()),
                        Written::Created | Written::Replaced => None,
                    };
                    transfers.finish(info.id, TransferState::Done, shown.clone(), Some(sha));
                    report.uploaded.push(match shown {
                        Some(note) => format!("{} ({}; {note})", file.name, human_size(size)),
                        None => format!("{} ({})", file.name, human_size(size)),
                    });
                }
                Err(Stopped::Cancelled { left }) => {
                    transfers.finish(
                        info.id,
                        TransferState::Cancelled,
                        Some(format!("cancelled; {left}")),
                        None,
                    );
                    report.cancelled += 1;
                }
                Err(Stopped::Failed { err, left }) => {
                    let message = match left {
                        Some(left) => format!("{err}; {left}"),
                        None => err.to_string(),
                    };
                    transfers.finish(info.id, TransferState::Failed, Some(message.clone()), None);
                    report.failed.push(format!("{}: {message}", file.name));
                }
            }
        }
        Ok(report)
    }

    /// Sends one local file to the host. Returns its size, SHA-256 and how it landed. The writer is
    /// opened and finished outside the cancel race, so a cancel never cuts a replacement's last step
    /// short; a cancel or failure while the bytes go up aborts it (H8: the old file stays as it was).
    async fn copy_up(
        &self,
        files: &Arc<dyn RemoteFiles>,
        info: &TransferInfo,
        file: &UploadFile,
        cancel: &CancellationToken,
        token: &CancellationToken,
    ) -> std::result::Result<(u64, String, Written), Stopped> {
        let mut local = tokio::fs::File::open(&file.local_path).await.map_err(|err| {
            Stopped::failed(CoreError::InvalidInput(format!(
                "'{}' can't be read on this PC: {err}",
                file.local_path
            )))
        })?;
        let size = local.metadata().await.map_err(|err| Stopped::failed(err.into()))?.len();
        self.inner.transfers.change(info.id, |i| i.size = size);
        if cancel.is_cancelled() || token.is_cancelled() {
            return Err(Stopped::Cancelled {
                left: "nothing was left on the host".into(),
            });
        }
        let mut writer = files
            .write(&info.remote_path, file.replace)
            .await
            .map_err(Stopped::failed)?;
        let pumped = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            () = token.cancelled() => None,
            result = self.pump(&mut local, writer.as_mut(), info) => Some(result),
        };
        match pumped {
            None => Err(Stopped::Cancelled {
                left: writer.abort().await,
            }),
            Some(Err(err)) => Err(Stopped::Failed {
                err,
                left: Some(writer.abort().await),
            }),
            Some(Ok((done, sha))) => match writer.finish().await {
                Ok(written) => Ok((done, sha, written)),
                Err(err) => Err(Stopped::Failed { err, left: None }),
            },
        }
    }

    /// The local file's bytes into the writer, with progress. Returns how many and their SHA-256.
    async fn pump(
        &self,
        local: &mut tokio::fs::File,
        writer: &mut dyn RemoteWrite,
        info: &TransferInfo,
    ) -> Result<(u64, String)> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
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

impl UploadRun<'_> {
    async fn ctx_audit(&self, store: &crate::store::Store, event: &str, action: &str, detail: &str) -> Result<()> {
        store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: Some(self.tier),
                    job_id: Some(self.job_id),
                    targets: std::slice::from_ref(self.target),
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
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
    pub files: Vec<StagedFile>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedFile {
    pub name: String,
    pub size: u64,
}

struct Staged {
    paths: Vec<PathBuf>,
    files: Vec<StagedFile>,
    at: Instant,
}

/// SS-08: what to do with files that are in the host folder already.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Existing {
    /// Ask first: nothing is submitted while any is there.
    Ask,
    Replace,
    Skip,
}

/// SS-08: how starting an upload went.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum UploadStart {
    /// These are in the folder already; ask, then call again with `replace` or `skip`.
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
    Upload { start: UploadStart },
    Download { transfers: Vec<TransferInfo> },
}

/// SS-08: the bus-facing side of file transfers (`Core.files`): files staged for upload, uploads
/// submitted as commands, retries.
pub struct FileTransfers {
    ctx: Context,
    terminals: Terminals,
    bus: Arc<CommandBus>,
    staged: Mutex<HashMap<Uuid, Staged>>,
}

impl FileTransfers {
    pub fn new(ctx: Context, terminals: Terminals, bus: Arc<CommandBus>) -> Self {
        Self {
            ctx,
            terminals,
            bus,
            staged: Mutex::default(),
        }
    }

    /// Keeps files picked in a dialog or dropped on a terminal for their upload. Folders are refused
    /// (Remotely uploads files), and so are two files of the same name.
    pub fn stage(&self, paths: Vec<PathBuf>) -> Result<StagedFiles> {
        if paths.is_empty() {
            return Err(CoreError::InvalidInput("No file was chosen.".into()));
        }
        if paths.len() > MAX_UPLOAD_FILES {
            return Err(CoreError::InvalidInput(format!(
                "One upload takes at most {MAX_UPLOAD_FILES} files."
            )));
        }
        let mut files = Vec::with_capacity(paths.len());
        for path in &paths {
            let meta = std::fs::metadata(path)
                .map_err(|err| CoreError::InvalidInput(format!("'{}' can't be read: {err}", path.display())))?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if meta.is_dir() {
                return Err(CoreError::InvalidInput(format!(
                    "'{name}' is a folder. Remotely uploads files: zip the folder, or pick the files in it."
                )));
            }
            if files.iter().any(|f: &StagedFile| f.name == name) {
                return Err(CoreError::InvalidInput(format!(
                    "Two files are named '{name}'; upload them one at a time."
                )));
            }
            files.push(StagedFile { name, size: meta.len() });
        }
        let id = Uuid::new_v4();
        let total = files.iter().map(|f| f.size).sum();
        let mut staged = locks::lock(&self.staged);
        staged.retain(|_, s| s.at.elapsed() < STAGED_FOR);
        staged.insert(
            id,
            Staged {
                paths,
                files: files.clone(),
                at: Instant::now(),
            },
        );
        Ok(StagedFiles { id, files, total })
    }

    /// Forgets staged files (the user closed the question about them).
    pub fn unstage(&self, id: Uuid) {
        locks::lock(&self.staged).remove(&id);
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
        let (paths, staged) = {
            let staged = locks::lock(&self.staged);
            let s = staged.get(&staged_id).ok_or_else(|| {
                CoreError::InvalidInput("Those files are no longer waiting to upload; choose them again.".into())
            })?;
            (s.paths.clone(), s.files.clone())
        };
        let folder = folder.trim_end_matches('/');
        let folder = if folder.is_empty() { "/" } else { folder };
        let names: Vec<String> = staged.iter().map(|f| f.name.clone()).collect();
        let there = self.terminals.upload_conflicts(terminal_id, folder, &names).await?;
        if existing == Existing::Ask && !there.is_empty() {
            return Ok(UploadStart::Conflicts {
                existing: there,
                folder: folder.to_owned(),
            });
        }
        let files: Vec<UploadFile> = paths
            .iter()
            .zip(&staged)
            .filter(|(_, f)| existing != Existing::Skip || !there.contains(&f.name))
            .map(|(path, f)| UploadFile {
                local_path: path.display().to_string(),
                name: f.name.clone(),
                size: f.size,
                replace: there.contains(&f.name),
            })
            .collect();
        locks::lock(&self.staged).remove(&staged_id);
        if files.is_empty() {
            return Ok(UploadStart::Nothing);
        }
        self.submit(terminal_id, folder, files).await
    }

    async fn submit(&self, terminal_id: Uuid, folder: &str, files: Vec<UploadFile>) -> Result<UploadStart> {
        let target = self.terminals.target(&self.ctx, terminal_id).await?;
        let command = Command::FileUpload {
            targets: vec![target.target],
            folder: folder.to_owned(),
            files,
        };
        let outcome = self.bus.submit(&self.ctx, command).await?;
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
            Again::Upload { local_path, folder } => {
                let size = std::fs::metadata(&local_path)
                    .map_err(|err| {
                        CoreError::InvalidInput(format!("'{}' can't be read any more: {err}", local_path.display()))
                    })?
                    .len();
                let there = self
                    .terminals
                    .upload_conflicts(info.terminal_id, &folder, std::slice::from_ref(&info.name))
                    .await?;
                let file = UploadFile {
                    local_path: local_path.display().to_string(),
                    name: info.name.clone(),
                    size,
                    replace: !there.is_empty(),
                };
                let start = self.submit(info.terminal_id, &folder, vec![file]).await?;
                Ok(Retried::Upload { start })
            }
            Again::Download { dest } => {
                let transfers = self
                    .terminals
                    .download(
                        &self.ctx,
                        info.terminal_id,
                        std::slice::from_ref(&info.remote_path),
                        &dest,
                    )
                    .await?;
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
        };
        let summary = report.summary("/srv");
        assert!(summary.starts_with("uploaded to /srv: a.txt (1.5 KB); 1 cancelled; failed: b.txt"));
        assert!(report.failure().unwrap().starts_with("b.txt: alice can't"));
        assert_eq!(UploadReport::default().summary("/srv"), "nothing uploaded");
    }
}
