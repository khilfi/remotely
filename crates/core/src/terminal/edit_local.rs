//! SS-08's last part (0.8.0 G4): "Edit on this PC". A host's file is downloaded into a folder only this Windows user
//! can open and opened in the editor chosen in Settings; each save is uploaded back, once the host's copy is checked to
//! be the one that was opened (`docs/plan-0.8.md`, "Edit on this PC").
//!
//! * **One command for the editing session** ([`crate::command_bus::Command::EditLocal`]): each save replaces the
//!   host's file, so it is rated as a replacement, Medium (never lower: [`crate::policy::MIN_REPLACE_TIER`]), one tier
//!   higher as root and for Prod, and approved once for the editing session. Its job lasts as long as the session, and
//!   every save is audited on its own (`file_changed`, with the bytes' SHA-256), as are the download
//!   (`file_edit_opened`) and the end (`file_edit_ended`, with why).
//! * **The copy** is in a folder of its own under Remotely's editing folder ([`Terminals::set_edit_folder`], under the
//!   data folder, never in a Git working tree), made with a DACL for this user alone ([`crate::private_folder`]),
//!   named as the host names the file (made safe for Windows, A8; a name Explorer or VS Code would act on by itself,
//!   `desktop.ini`, `.lnk`, `.scf`, `.code-workspace`..., gets `.txt` after it), and given the Mark of the Web. It opens
//!   in the editor's own program ([`crate::adapters::local_editor`]), never Windows' default action.
//! * **A save** is a change of the copy's size or time that stays for one poll and changes its bytes (the copy is
//!   looked at again after it is read: a save that began meanwhile settles first). Before it goes up, four checks:
//!   the read-only lock is off (FD-03; else it waits, [`EditState::Held`]); the terminal's connection, the one it has
//!   now (a reconnect gives it new files), still goes to the host, port, jump host and login the editing began on (else
//!   the session ends, [`EditEnd::ConnectionChanged`]); the session has not become Prod or protected since the approval
//!   (AP-01, as the bus asks again before a job; else it ends, [`EditEnd::LabelsChanged`]); and what is at the path is
//!   a regular file, never a link, whose SHA-256 is still the one last read or written. Then the save replaces it
//!   through [`RemoteFiles::replace_file`] (H8, never through a link, for any user); otherwise the session holds the
//!   save and asks: overwrite, save beside it (a new file of the next free name, `name (edited).ext`), compare (the
//!   host's copy downloaded beside the copy, and with VS Code opened as a diff), or keep editing. A save that failed
//!   goes again by itself after [`EditTuning::retry`], doubling up to 5 minutes, at once on a new save or Try again.
//! * **It ends** on Stop editing, after [`EDIT_LIMIT`], when the job is cancelled, the workspace changes, the app
//!   closes or the terminal closes, and (as root) when root browsing ends, which a vault lock does; the other sessions
//!   hold no secret and go on through a lock. Stop and the time limit send the last save up first. Many editors run as
//!   one instance, so the editor's process is never what ends it. An end that doesn't wait in line (a switch, the app,
//!   the terminal) interrupts a read or an upload in flight.
//! * **A save that didn't go up is never deleted.** Stop editing asks first ([`StopOutcome::Unsent`]: upload again,
//!   keep it on this PC, or discard it). Every other end keeps the copy in its private folder, with a record beside it
//!   (`<job>.kept.json`), listed as not uploaded ([`EditState::Kept`]) until the user saves it elsewhere or discards it;
//!   the sweep at start leaves those alone and lists them again. Other copies go when their session ends, and what an
//!   earlier run left behind (a crash) goes at the next start.
//! * **Reads and writes** go through the terminal's own SFTP (as root: its root browsing), at most
//!   [`MAX_EDIT_BYTES`] a file.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::file_ops::{check_path, last_part};
use super::files::{join, local_name, mark_downloaded, parent};
use super::{audit_entry, quoted_name, Terminals};
use crate::adapters::local_editor::{locate_local_editor, EditorKind, LocalEditors, LOCAL_EDITOR_PATH_KEY};
use crate::adapters::remote::{EntryKind, RemoteEntry, RemoteFiles};
use crate::domain::{now_rfc3339, Context, Environment, Target, TargetRef, WorkspaceId};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::locks;
use crate::policy::Tier;
use crate::vault::Destination;

/// The largest file edited on this PC (an editor is for text, not a disk image).
pub const MAX_EDIT_BYTES: u64 = 16 * 1024 * 1024;
/// An editing session's longest life (`docs/plan-0.8.md`).
pub const EDIT_LIMIT: Duration = Duration::from_secs(4 * 3600);
/// The longest wait before a failed save goes again by itself.
const RETRY_MAX: Duration = Duration::from_secs(300);
/// A kept copy's record, beside its folder: `<job>.kept.json`.
const KEPT_SUFFIX: &str = ".kept.json";
const MAX_KEPT_RECORD: u64 = 64 * 1024;
/// A file name's longest: 255 UTF-16 units on this PC, 255 bytes on a Linux host.
const NAME_MAX: usize = 255;

/// SS-08: what [`crate::command_bus::Command::EditLocal`] edits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditSpec {
    /// The open terminal whose connection reads and writes the file.
    pub terminal_id: Uuid,
    /// The host's file, absolute.
    pub path: String,
    /// Through the terminal's root browsing: every save as root.
    #[serde(default)]
    pub as_root: bool,
}

impl EditSpec {
    /// The one target: the file.
    pub fn targets(&self) -> Vec<TargetRef> {
        vec![TargetRef::RemotePath {
            terminal_id: self.terminal_id,
            session_id: None,
            step: 0,
        }]
    }

    pub fn validate(&self) -> Result<()> {
        check_path(&self.path)?;
        if self.path == "/" {
            return Err(CoreError::InvalidInput("The top folder (/) is not a file.".into()));
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        let root = if self.as_root { ", as root" } else { "" };
        format!(
            "Edit {} on this PC, each save replacing it on the host{root}",
            shown(&self.path)
        )
    }

    /// BX-02: the spec as the journal keeps it, its path through [`redact_secrets`]; whether it changed.
    pub fn for_journal(&self) -> (EditSpec, bool) {
        let (path, changed) = redact_secrets(&self.path);
        (EditSpec { path, ..self.clone() }, changed)
    }
}

/// A path for a message: without control or formatting characters, and not too long.
fn shown(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || crate::untrusted::is_format_char(c) {
                '?'
            } else {
                c
            }
        })
        .take(300)
        .collect()
}

/// SS-08: what the job runner hands to the terminals for [`crate::command_bus::Command::EditLocal`].
pub struct EditRun<'a> {
    pub ctx: Context,
    pub job_id: Uuid,
    pub tier: Tier,
    pub target: &'a Target,
    pub spec: &'a EditSpec,
}

/// Why an editing session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EditEnd {
    Stopped,
    TimeLimit,
    Cancelled,
    /// As root: the vault locked, which ends root browsing.
    VaultLocked,
    WorkspaceSwitched,
    AppClosing,
    TerminalClosed,
    RootEnded,
    /// The terminal's connection now goes to another host, port, jump host or login than when the editing began.
    ConnectionChanged,
    /// The session became Prod or protected since the approval.
    LabelsChanged,
}

impl EditEnd {
    fn detail(self) -> &'static str {
        match self {
            EditEnd::Stopped => "stopped by the user",
            EditEnd::TimeLimit => "it reached its 4 hours",
            EditEnd::Cancelled => "its job was cancelled",
            EditEnd::VaultLocked => "the vault locked, which ends root browsing",
            EditEnd::WorkspaceSwitched => "another workspace was opened",
            EditEnd::AppClosing => "the app closed",
            EditEnd::TerminalClosed => "its terminal closed",
            EditEnd::RootEnded => "root browsing ended",
            EditEnd::ConnectionChanged => {
                "its terminal now connects to another host, port, jump host or login than when the editing began"
            }
            EditEnd::LabelsChanged => "it was approved for other labels than its session has now",
        }
    }
}

/// Where an editing session stands, for the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum EditState {
    /// The copy is open and watched.
    Watching,
    /// A save is going up.
    Uploading,
    /// The host's copy changed since it was opened here: a save waits for the user's answer.
    Conflict { message: String },
    /// The last save could not go up; it goes again by itself after a while, on the next save, or on Try again.
    Failed { message: String },
    /// FD-03: the read-only lock is on: the save goes up once it is off.
    Held { message: String },
    /// The session ended; nothing of it is left on this PC.
    Ended { reason: EditEnd, message: String },
    /// The session ended with a save that didn't go up: this PC's copy is kept (also across a restart) until the user
    /// saves it elsewhere or discards it.
    Kept { reason: EditEnd, message: String },
}

/// SS-08: an editing session, or a copy kept after one, as the window lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditInfo {
    /// The session's job.
    pub id: Uuid,
    pub terminal_id: Uuid,
    /// The terminal's name: the session's, or `user@host:port`.
    pub name: String,
    pub path: String,
    pub as_root: bool,
    /// The editor on this PC: "VS Code", "Notepad++"...
    pub editor: String,
    pub state: EditState,
    /// Saves uploaded so far.
    pub saves: u32,
    /// What happened last, in words ("Saved beside it as hosts (edited)").
    pub note: Option<String>,
    pub started_at: String,
    /// When it ends by itself.
    pub ends_at: String,
    /// When it ended (a kept copy).
    pub ended_at: Option<String>,
}

/// SS-08: the user's answer when the host's copy changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EditAnswer {
    /// Replace the host's file with this PC's copy anyway.
    Overwrite,
    /// Upload this PC's copy as a new file beside it.
    SaveBeside,
    /// Download the host's copy beside this PC's and open both.
    Compare,
    /// Upload nothing now; the next save asks again.
    KeepEditing,
}

/// SS-08: what Stop editing does with a save that didn't go up ([`StopOutcome::Unsent`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StopChoice {
    /// Try the save again, and stop once it went up.
    Upload,
    /// Stop, and keep this PC's copy, listed as not uploaded.
    Keep,
    /// Stop, and delete this PC's copy with what didn't go up.
    Discard,
}

/// SS-08: what Stop editing did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum StopOutcome {
    Ended,
    /// This PC's copy holds a save that didn't go up, so nothing stopped: the user picks a [`StopChoice`].
    /// `conflict`: the host's copy changed (Upload again would only ask again).
    Unsent {
        message: String,
        conflict: bool,
    },
}

enum Msg {
    Stop {
        choice: Option<StopChoice>,
        reply: oneshot::Sender<StopOutcome>,
    },
    Answer(EditAnswer),
    Retry,
}

struct Session {
    info: Mutex<EditInfo>,
    tx: mpsc::Sender<Msg>,
    workspace: WorkspaceId,
    /// Ends that don't wait in line (a switch, the app closing, the terminal closing, a changed connection): the
    /// first one set wins, and the token interrupts a read or an upload in flight. A child of the job's cancel token.
    ending: CancellationToken,
    end: Mutex<Option<(EditEnd, Option<String>)>>,
}

impl Session {
    fn end(&self, why: EditEnd, note: Option<String>) {
        locks::lock(&self.end).get_or_insert((why, note));
        self.ending.cancel();
    }
}

/// A copy kept after its session ended with a save that didn't go up.
struct Kept {
    info: EditInfo,
    workspace: WorkspaceId,
    target: Target,
    folder: PathBuf,
    copy: PathBuf,
    record: PathBuf,
}

/// What `<job>.kept.json` holds: enough to list the kept copy again after a restart.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeptRecord {
    version: u32,
    id: Uuid,
    workspace_id: WorkspaceId,
    target: Target,
    terminal_id: Uuid,
    name: String,
    path: String,
    as_root: bool,
    editor: String,
    saves: u32,
    reason: EditEnd,
    message: String,
    started_at: String,
    ended_at: String,
    /// The copy's file name in its folder.
    file: String,
}

impl KeptRecord {
    fn info(&self) -> EditInfo {
        EditInfo {
            id: self.id,
            terminal_id: self.terminal_id,
            name: self.name.clone(),
            path: self.path.clone(),
            as_root: self.as_root,
            editor: self.editor.clone(),
            state: EditState::Kept {
                reason: self.reason,
                message: self.message.clone(),
            },
            saves: self.saves,
            note: None,
            started_at: self.started_at.clone(),
            ends_at: self.ended_at.clone(),
            ended_at: Some(self.ended_at.clone()),
        }
    }
}

/// How often the copy is looked at, how long a session may last, and the first wait before a failed save goes again by
/// itself (tests shorten them).
#[derive(Debug, Clone, Copy)]
pub struct EditTuning {
    pub poll: Duration,
    pub limit: Duration,
    pub retry: Duration,
}

impl Default for EditTuning {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(1),
            limit: EDIT_LIMIT,
            retry: Duration::from_secs(10),
        }
    }
}

/// SS-08: the open editing sessions, the kept copies, and what they need.
pub(super) struct Edits {
    sessions: Mutex<HashMap<Uuid, Arc<Session>>>,
    kept: Mutex<HashMap<Uuid, Kept>>,
    events: broadcast::Sender<(WorkspaceId, EditInfo)>,
    /// The folder copies go in; `None` until [`Terminals::set_edit_folder`] set it up (nothing is edited until then).
    folder: Mutex<Option<PathBuf>>,
    editors: RwLock<Arc<dyn LocalEditors>>,
    tuning: Mutex<EditTuning>,
}

impl Default for Edits {
    fn default() -> Self {
        #[cfg(not(feature = "fakes"))]
        let editors: Arc<dyn LocalEditors> = Arc::new(crate::adapters::local_editor::WindowsEditors);
        #[cfg(feature = "fakes")]
        let editors: Arc<dyn LocalEditors> = Arc::new(crate::adapters::local_editor::NoEditors);
        Self {
            sessions: Mutex::default(),
            kept: Mutex::default(),
            events: broadcast::channel(64).0,
            folder: Mutex::default(),
            editors: RwLock::new(editors),
            tuning: Mutex::new(EditTuning::default()),
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// What is at the host's `path`: `None` when nothing is; refused when it is a link (G2: nothing is saved through one),
/// not a regular file, or larger than [`MAX_EDIT_BYTES`].
async fn check_host(files: &Arc<dyn RemoteFiles>, path: &str) -> Result<Option<RemoteEntry>> {
    let Some(entry) = files.lstat(path).await? else {
        return Ok(None);
    };
    if entry.link {
        return Err(CoreError::InvalidInput(format!(
            "{} is a link now, and Remotely doesn't save through a link: edit the file it points to.",
            shown(path)
        )));
    }
    if entry.kind != EntryKind::File {
        return Err(CoreError::InvalidInput(format!("{} is not a file.", shown(path))));
    }
    if entry.size > MAX_EDIT_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "{} is larger than {} MB, too large to edit on this PC.",
            shown(path),
            MAX_EDIT_BYTES / (1024 * 1024)
        )));
    }
    Ok(Some(entry))
}

/// The host's file, whole ([`check_host`]'s refusals); `stop` interrupts it.
async fn read_host(files: &Arc<dyn RemoteFiles>, path: &str, stop: &CancellationToken) -> Result<Vec<u8>> {
    let entry = check_host(files, path)
        .await?
        .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
    let mut reader = files.read(path).await?;
    let mut bytes = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = tokio::select! {
            n = reader.read(&mut buf) => n?,
            () = stop.cancelled() => return Err(CoreError::Cancelled),
        };
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() as u64 > MAX_EDIT_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "{} grew past {} MB while it was read, too large to edit on this PC.",
                shown(path),
                MAX_EDIT_BYTES / (1024 * 1024)
            )));
        }
    }
    Ok(bytes)
}

/// Writes `bytes` to the host's `path`: with `replace`, over the file there itself (H8, never through a link:
/// [`RemoteFiles::replace_file`]); without it only as a new file. `stop` interrupts it, and what it made goes.
async fn write_host(
    files: &Arc<dyn RemoteFiles>,
    path: &str,
    bytes: &[u8],
    replace: bool,
    stop: &CancellationToken,
) -> Result<String> {
    let mut writer = if replace {
        files.replace_file(path).await?
    } else {
        files.write(path, false).await?
    };
    let sent = tokio::select! {
        sent = writer.write_all(bytes) => sent,
        () = stop.cancelled() => Err(CoreError::Cancelled),
    };
    if let Err(err) = sent {
        let _ = writer.abort().await;
        return Err(err);
    }
    Ok(writer.finish().await?.note())
}

fn utf16_units(text: &str) -> usize {
    text.encode_utf16().count()
}

fn bytes_of(text: &str) -> usize {
    text.len()
}

/// `stem` and `tail` together, the stem cut short (by whole characters) so the name fits [`NAME_MAX`] as `measure`
/// counts.
fn fit(stem: &str, tail: &str, measure: fn(&str) -> usize) -> String {
    let mut stem = stem.to_owned();
    while !stem.is_empty() && measure(&stem) + measure(tail) > NAME_MAX {
        stem.pop();
    }
    format!("{stem}{tail}")
}

/// A name's stem and its extension (with the dot): only a short extension counts, so a long name keeps its stem.
fn split_extension(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(at) if at > 0 && name.len() - at <= 16 => name.split_at(at),
        _ => (name, ""),
    }
}

/// `hosts (edited)`, `hosts (edited 2).conf`...: the name a save beside the host's file gets, at most 255 bytes.
fn beside_name(name: &str, n: usize) -> String {
    let (stem, extension) = split_extension(name);
    let edited = if n <= 1 {
        "edited".to_owned()
    } else {
        format!("edited {n}")
    };
    fit(stem, &format!(" ({edited}){extension}"), bytes_of)
}

/// `hosts (on the host).conf`: the host's copy downloaded beside this PC's to compare, at most 255 UTF-16 units.
fn host_copy_name(local: &str) -> String {
    let (stem, extension) = split_extension(local);
    fit(stem, &format!(" (on the host){extension}"), utf16_units)
}

/// The copy's name on this PC: the host's, made safe for Windows ([`local_name`]); one Explorer or VS Code acts on by
/// itself (a shortcut, `desktop.ini`, a VS Code workspace) gets `.txt` after it, so it opens as text; at most 255
/// UTF-16 units.
fn copy_name(host_name: &str) -> String {
    let name = local_name(host_name);
    let acts =
        crate::toolbox::file_server::paths::is_shell_file(&name) || name.to_lowercase().ends_with(".code-workspace");
    let (stem, extension) = split_extension(&name);
    let tail = if acts {
        format!("{extension}.txt")
    } else {
        extension.to_owned()
    };
    let fitted = fit(stem, &tail, utf16_units);
    let fitted = fitted.trim_end_matches(['.', ' ']);
    if fitted.is_empty() {
        "download".to_owned()
    } else {
        fitted.to_owned()
    }
}

/// The copy's size and time: what a save changes.
async fn seen(local: &Path) -> Option<(u64, Option<SystemTime>)> {
    let meta = tokio::fs::metadata(local).await.ok()?;
    Some((meta.len(), meta.modified().ok()))
}

/// Deletes a session's folder, tried a few times (an editor may hold the file a moment), on a blocking thread; what
/// stays goes at the next start.
async fn remove_folder(folder: PathBuf) {
    let removed = tokio::task::spawn_blocking(move || {
        for attempt in 0..5 {
            match std::fs::remove_dir_all(&folder) {
                Ok(()) => return,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
                Err(err) if attempt == 4 => {
                    tracing::warn!(error = %err, "could not delete an editing folder; it goes at the next start");
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    })
    .await;
    if removed.is_err() {
        tracing::warn!("deleting an editing folder stopped; it goes at the next start");
    }
}

/// The session's folder, deleted (one try, never a wait) if the session never got going; its end decides otherwise.
struct FolderGuard(Option<PathBuf>);

impl FolderGuard {
    fn take(&mut self) -> Option<PathBuf> {
        self.0.take()
    }
}

impl Drop for FolderGuard {
    fn drop(&mut self) {
        if let Some(folder) = self.0.take() {
            if let Err(err) = std::fs::remove_dir_all(&folder) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(error = %err, "could not delete an editing folder; it goes at the next start");
                }
            }
        }
    }
}

/// A kept copy's record and folder, after a restart: both real (no link or junction), the record small and of this
/// version, the copy a plain file in the folder.
fn read_kept(root: &Path, id: &str) -> Option<Kept> {
    let job = Uuid::parse_str(id).ok()?;
    if job.simple().to_string() != id {
        return None;
    }
    let record_path = root.join(format!("{id}{KEPT_SUFFIX}"));
    let folder = root.join(id);
    let meta = std::fs::symlink_metadata(&record_path).ok()?;
    if !meta.is_file() || meta.len() > MAX_KEPT_RECORD {
        return None;
    }
    if !std::fs::symlink_metadata(&folder).ok()?.is_dir() {
        return None;
    }
    let record: KeptRecord = serde_json::from_slice(&std::fs::read(&record_path).ok()?).ok()?;
    if record.version != 1 || record.id != job || record.file.is_empty() || local_name(&record.file) != record.file {
        return None;
    }
    let copy = folder.join(&record.file);
    if !std::fs::symlink_metadata(&copy).ok()?.is_file() {
        return None;
    }
    Some(Kept {
        info: record.info(),
        workspace: record.workspace_id,
        target: record.target,
        folder,
        copy,
        record: record_path,
    })
}

/// The editing folder at start: kept copies (a record beside a folder of the same name) stay and are returned; every
/// other entry goes (a link or junction itself, never what it points to). Also how many went.
fn sweep(root: &Path) -> Result<(usize, Vec<Kept>)> {
    let entries: Vec<std::fs::DirEntry> = std::fs::read_dir(root)?.flatten().collect();
    let mut kept = Vec::new();
    let mut stays: HashSet<OsString> = HashSet::new();
    for entry in &entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(KEPT_SUFFIX) else {
            continue;
        };
        if let Some(found) = read_kept(root, id) {
            stays.insert(entry.file_name());
            stays.insert(OsString::from(id));
            kept.push(found);
        }
    }
    let mut swept = 0;
    for entry in entries {
        if stays.contains(&entry.file_name()) {
            continue;
        }
        let path = entry.path();
        let gone = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match gone {
            Ok(()) => swept += 1,
            Err(err) => tracing::warn!(error = %err, "could not delete a copy left from an earlier edit"),
        }
    }
    Ok((swept, kept))
}

/// Why a save can't go up now.
enum Hold {
    /// Not now (the terminal is reconnecting, say): the save goes again later.
    Wait(String),
    /// Never through this session: it ends, keeping the copy.
    End(EditEnd, String),
}

/// One editing session's state between polls.
struct Watch {
    local: PathBuf,
    /// Where the terminal's connection went, and its login, when the editing began: a save goes only while it still
    /// does.
    place: Destination,
    user: String,
    /// The SHA-256 of what the host had when it was last read or written here.
    host_sha: String,
    /// The SHA-256 of what the host has from this PC: the copy as opened, or as last uploaded (or saved beside it).
    sent_sha: String,
    /// A save the user chose to keep editing on: not tried again until the copy changes.
    held_sha: Option<String>,
    /// The copy's size and time last handled, and one seen once (a save settles for a poll).
    handled: Option<(u64, Option<SystemTime>)>,
    settling: Option<(u64, Option<SystemTime>)>,
    /// A save waits for the user's answer: the message that says why.
    conflict: Option<String>,
    /// Look at the copy now, whatever its size and time say (Try again, Stop editing).
    force: bool,
    /// A failed save goes again by itself at this time.
    next_try: Option<Instant>,
    backoff: Duration,
    /// The read-only lock held a save: it goes once the lock is off.
    locked: bool,
    /// Why the copy holds a save that didn't go up, for Stop's question.
    unsent_why: Option<String>,
}

impl Terminals {
    /// SS-08 (G4): what opens copies on this PC (tests give [`crate::fakes::FakeLocalEditors`]).
    pub fn set_local_editors(&self, editors: Arc<dyn LocalEditors>) {
        *locks::write(&self.inner.edits.editors) = editors;
    }

    /// SS-08 (G4): how often copies are looked at, how long a session lasts and when a failed save goes again (tests
    /// shorten them).
    pub fn set_edit_tuning(&self, tuning: EditTuning) {
        *locks::lock(&self.inner.edits.tuning) = tuning;
    }

    /// SS-08 (G4): where copies go: a folder of its own each under `folder` (never in a Git working tree). What a run
    /// before left there (a crash) is deleted now, but copies kept with a save that didn't go up, which are listed
    /// again; returns how many entries were deleted.
    pub fn set_edit_folder(&self, folder: &Path) -> Result<usize> {
        crate::save_guard::refuse_repository_folder(folder, crate::save_guard::Saved::Download)?;
        std::fs::create_dir_all(folder)?;
        let (swept, kept) = sweep(folder)?;
        {
            let mut list = locks::lock(&self.inner.edits.kept);
            for copy in kept {
                list.insert(copy.info.id, copy);
            }
        }
        *locks::lock(&self.inner.edits.folder) = Some(folder.to_path_buf());
        Ok(swept)
    }

    fn edit_root(&self) -> Result<PathBuf> {
        locks::lock(&self.inner.edits.folder).clone().ok_or_else(|| {
            CoreError::InvalidInput(
                "Remotely's folder for copies edited on this PC could not be set up at start (the log says why), so \
                 nothing opens on this PC."
                    .into(),
            )
        })
    }

    /// SS-08 (G4): the editor copies open in: the one saved in Settings, else VS Code, Notepad++ or Notepad.
    pub async fn local_editor(&self, ctx: &Context) -> Result<Option<PathBuf>> {
        let saved = self.saved_local_editor(ctx).await?;
        Ok(locate_local_editor(saved.as_deref()))
    }

    /// SS-08 (G4): the editor's path saved in Settings, if any.
    pub async fn saved_local_editor(&self, ctx: &Context) -> Result<Option<PathBuf>> {
        Ok(self
            .inner
            .store
            .get_setting::<Option<String>>(ctx, LOCAL_EDITOR_PATH_KEY)
            .await?
            .flatten()
            .map(PathBuf::from))
    }

    /// SS-08 (G4): the shown workspace's editing sessions and kept copies.
    pub fn edits(&self, ctx: &Context) -> Vec<EditInfo> {
        let mut list: Vec<EditInfo> = locks::lock(&self.inner.edits.sessions)
            .values()
            .filter(|s| s.workspace == ctx.workspace_id)
            .map(|s| locks::lock(&s.info).clone())
            .collect();
        list.extend(
            locks::lock(&self.inner.edits.kept)
                .values()
                .filter(|k| k.workspace == ctx.workspace_id)
                .map(|k| k.info.clone()),
        );
        list.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        list
    }

    /// SS-08 (G4): every change of an editing session (its end too) and of a kept copy, with its workspace: the shell
    /// passes the shown workspace's on.
    pub fn subscribe_edits(&self) -> broadcast::Receiver<(WorkspaceId, EditInfo)> {
        self.inner.edits.events.subscribe()
    }

    fn edit_session(&self, ctx: &Context, id: Uuid) -> Result<Arc<Session>> {
        let session = locks::lock(&self.inner.edits.sessions)
            .get(&id)
            .cloned()
            .ok_or_else(|| CoreError::UnknownTarget(format!("editing session {id}: it has ended")))?;
        if session.workspace != ctx.workspace_id {
            return Err(CoreError::NotInWorkspace(format!("Editing session {id}")));
        }
        Ok(session)
    }

    /// SS-08 (G4): Stop editing. The last save goes up first (if the host's copy is unchanged). With nothing left
    /// unsent the copy is deleted and the session's job ends; otherwise nothing stops and the outcome says why, unless
    /// `choice` says what to do with it.
    pub async fn stop_edit(&self, ctx: &Context, id: Uuid, choice: Option<StopChoice>) -> Result<StopOutcome> {
        let session = self.edit_session(ctx, id)?;
        let (reply, answer) = oneshot::channel();
        if session.tx.send(Msg::Stop { choice, reply }).await.is_err() {
            return Ok(StopOutcome::Ended);
        }
        Ok(answer.await.unwrap_or(StopOutcome::Ended))
    }

    /// SS-08 (G4): the answer to a save held because the host's copy changed; Try again after a failed upload.
    pub async fn answer_edit(&self, ctx: &Context, id: Uuid, answer: Option<EditAnswer>) -> Result<()> {
        let session = self.edit_session(ctx, id)?;
        let msg = match answer {
            Some(answer) => Msg::Answer(answer),
            None => Msg::Retry,
        };
        let _ = session.tx.send(msg).await;
        Ok(())
    }

    /// SS-08 (G4): ends every editing session (of `workspace`, or all) without uploading more, at once (an upload in
    /// flight stops); a copy with a save that didn't go up is kept. Their job ids, to wait for.
    pub fn end_edits(&self, workspace: Option<WorkspaceId>, why: EditEnd) -> Vec<Uuid> {
        self.end_edits_where(why, |s| workspace.is_none_or(|w| w == s.workspace))
    }

    /// SS-08 (G4): ends the editing sessions as root (the vault locked: root browsing ends too); the others go on.
    pub fn end_root_edits(&self, why: EditEnd) -> Vec<Uuid> {
        self.end_edits_where(why, |s| locks::lock(&s.info).as_root)
    }

    /// SS-08 (G4): the terminal closed: its editing sessions end at once, without uploading more.
    pub(super) fn end_edits_of(&self, terminal_id: Uuid) {
        self.end_edits_where(EditEnd::TerminalClosed, |s| {
            locks::lock(&s.info).terminal_id == terminal_id
        });
    }

    fn end_edits_where(&self, why: EditEnd, which: impl Fn(&Session) -> bool) -> Vec<Uuid> {
        let sessions: Vec<(Uuid, Arc<Session>)> = locks::lock(&self.inner.edits.sessions)
            .iter()
            .filter(|(_, s)| which(s))
            .map(|(id, s)| (*id, Arc::clone(s)))
            .collect();
        for (_, session) in &sessions {
            session.end(why, None);
        }
        sessions.into_iter().map(|(id, _)| id).collect()
    }

    fn show_edit(&self, session: &Session, change: impl FnOnce(&mut EditInfo)) {
        let info = {
            let mut info = locks::lock(&session.info);
            change(&mut info);
            info.clone()
        };
        let _ = self.inner.edits.events.send((session.workspace, info));
    }

    /// SS-08 (G4): the job runner's half of [`crate::command_bus::Command::EditLocal`]: the whole editing session.
    pub(crate) async fn run_edit(&self, run: EditRun<'_>, cancel: &CancellationToken) -> Result<String> {
        run.spec.validate()?;
        let spec = run.spec;
        let (control, files) = self.files_for(spec.terminal_id, spec.as_root)?;
        if control.workspace != run.ctx.workspace_id {
            return Err(CoreError::NotInWorkspace(format!("Terminal {}", spec.terminal_id)));
        }
        let place = locks::lock(&control.place)
            .clone()
            .ok_or_else(|| CoreError::InvalidInput(format!("{} is not connected.", quoted_name(&control))))?;
        let user = files.user();
        let program = self
            .local_editor(&run.ctx)
            .await?
            .ok_or(CoreError::LocalEditorNotFound)?;
        let editor = EditorKind::of(&program);
        let root_folder = self.edit_root()?;
        let ending = cancel.child_token();
        let bytes = read_host(&files, &spec.path, &ending).await?;
        let host_sha = sha256_hex(&bytes);
        // A folder of its own, only this user's: deleted when the session ends, unless it keeps a save that didn't go up.
        let folder = root_folder.join(run.job_id.simple().to_string());
        crate::private_folder::make(&folder)?;
        let mut guard = FolderGuard(Some(folder.clone()));
        let local = folder.join(copy_name(last_part(&spec.path)));
        tokio::fs::write(&local, &bytes).await?;
        let mark = mark_downloaded(&local).await;
        let on = quoted_name(&control);
        let root = if spec.as_root { " as root" } else { "" };
        let detail = format!(
            "{} bytes, SHA-256 {host_sha}; opened in {}{}",
            bytes.len(),
            editor_name(editor, &program),
            mark.map(|m| format!("; {m}")).unwrap_or_default()
        );
        audit_entry(
            &self.inner.store,
            &run.ctx,
            "file_edit_opened",
            &format!("Opened {} on {on}{root} to edit on this PC", shown(&spec.path)),
            Some(run.tier),
            Some(run.job_id),
            std::slice::from_ref(run.target),
            &detail,
        )
        .await?;
        let editors = locks::read(&self.inner.edits.editors).clone();
        editors.open(&program, std::slice::from_ref(&local), false).await?;

        let tuning = *locks::lock(&self.inner.edits.tuning);
        let ends = time::OffsetDateTime::now_utc() + time::Duration::seconds(tuning.limit.as_secs() as i64);
        let (tx, mut rx) = mpsc::channel(16);
        let session = Arc::new(Session {
            info: Mutex::new(EditInfo {
                id: run.job_id,
                terminal_id: spec.terminal_id,
                name: control.name.clone(),
                path: spec.path.clone(),
                as_root: spec.as_root,
                editor: editor_name(editor, &program),
                state: EditState::Watching,
                saves: 0,
                note: None,
                started_at: now_rfc3339(),
                ends_at: ends
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                ended_at: None,
            }),
            tx,
            workspace: run.ctx.workspace_id,
            ending,
            end: Mutex::default(),
        });
        locks::lock(&self.inner.edits.sessions).insert(run.job_id, Arc::clone(&session));
        self.show_edit(&session, |_| {});

        let sha = sha256_hex(&bytes);
        let mut watch = Watch {
            handled: seen(&local).await,
            settling: None,
            local: local.clone(),
            place,
            user,
            host_sha,
            sent_sha: sha,
            held_sha: None,
            conflict: None,
            force: false,
            next_try: None,
            backoff: tuning.retry,
            locked: false,
            unsent_why: None,
        };
        let deadline = Instant::now() + tuning.limit;
        let mut choice = None;
        let (why, why_note) = loop {
            tokio::select! {
                biased;
                () = session.ending.cancelled() => break ended_why(&session),
                msg = rx.recv() => match msg {
                    Some(Msg::Stop { choice: asked, reply }) => {
                        let unsent = self.stop_asked(&run, &session, &mut watch, asked).await;
                        if session.ending.is_cancelled() {
                            let _ = reply.send(StopOutcome::Ended);
                            break ended_why(&session);
                        }
                        match unsent {
                            None => {
                                let _ = reply.send(StopOutcome::Ended);
                                choice = asked;
                                break (EditEnd::Stopped, None);
                            }
                            Some(unsent) => {
                                let _ = reply.send(unsent);
                            }
                        }
                    }
                    Some(Msg::Answer(answer)) => self.answered(&run, &session, &mut watch, &program, answer).await,
                    Some(Msg::Retry) => {
                        watch.force = true;
                        self.look(&run, &session, &mut watch).await;
                    }
                    None => break (EditEnd::Cancelled, None),
                },
                () = tokio::time::sleep(tuning.poll) => {
                    if Instant::now() >= deadline {
                        break (EditEnd::TimeLimit, None);
                    }
                    if let Some(why) = self.gone(spec) {
                        break (why, None);
                    }
                    self.look(&run, &session, &mut watch).await;
                }
            }
        };
        // The time limit sends the last save up first, as Stop editing does.
        if why == EditEnd::TimeLimit && self.gone(spec).is_none() {
            watch.force = true;
            self.look(&run, &session, &mut watch).await;
        }
        let unsent = self.unsent(&watch).await;
        let keep = unsent && choice != Some(StopChoice::Discard);
        let mut message = why.detail().to_owned();
        if let Some(note) = why_note {
            message.push_str(&format!(" ({note})"));
        }
        if keep {
            message.push_str("; its last save was not uploaded, so this PC's copy is kept");
        } else if unsent {
            message.push_str("; its last save was not uploaded and was discarded");
        }
        locks::lock(&self.inner.edits.sessions).remove(&run.job_id);
        let saves = locks::lock(&session.info).saves;
        let ended_at = now_rfc3339();
        let folder = guard.take();
        if keep {
            let info = {
                let mut info = locks::lock(&session.info);
                info.state = EditState::Kept {
                    reason: why,
                    message: message.clone(),
                };
                info.ended_at = Some(ended_at.clone());
                info.clone()
            };
            // Listed before the window hears of it.
            self.keep_copy(info.clone(), &run, folder.unwrap_or_default(), &local);
            let _ = self.inner.edits.events.send((session.workspace, info));
        } else {
            self.show_edit(&session, |info| {
                info.state = EditState::Ended {
                    reason: why,
                    message: message.clone(),
                };
                info.ended_at = Some(ended_at.clone());
            });
            if let Some(folder) = folder {
                remove_folder(folder).await;
            }
        }
        let note = format!(
            "{} uploaded; ended: {message}; this PC's copy {}",
            match saves {
                1 => "1 save".to_owned(),
                n => format!("{n} saves"),
            },
            if keep { "kept, not uploaded" } else { "deleted" }
        );
        audit_entry(
            &self.inner.store,
            &run.ctx,
            "file_edit_ended",
            &format!("Stopped editing {} on {on}{root} on this PC", shown(&spec.path)),
            Some(run.tier),
            Some(run.job_id),
            std::slice::from_ref(run.target),
            &note,
        )
        .await?;
        if why == EditEnd::Cancelled {
            return Err(CoreError::Cancelled);
        }
        Ok(note)
    }

    /// Lists a copy whose last save didn't go up, and writes its record beside its folder so it is listed again after
    /// a restart (without one, it is listed until the app closes, and the next start deletes it).
    fn keep_copy(&self, info: EditInfo, run: &EditRun<'_>, folder: PathBuf, local: &Path) {
        let record_path = folder.with_file_name(format!("{}{KEPT_SUFFIX}", run.job_id.simple()));
        let file = local
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let reason = match &info.state {
            EditState::Kept { reason, .. } => *reason,
            _ => EditEnd::Stopped,
        };
        let message = match &info.state {
            EditState::Kept { message, .. } => message.clone(),
            _ => String::new(),
        };
        let record = KeptRecord {
            version: 1,
            id: info.id,
            workspace_id: run.ctx.workspace_id,
            target: run.target.clone(),
            terminal_id: info.terminal_id,
            name: info.name.clone(),
            path: info.path.clone(),
            as_root: info.as_root,
            editor: info.editor.clone(),
            saves: info.saves,
            reason,
            message,
            started_at: info.started_at.clone(),
            ended_at: info.ended_at.clone().unwrap_or_default(),
            file,
        };
        let written = serde_json::to_vec_pretty(&record)
            .map_err(|e| CoreError::InvalidInput(e.to_string()))
            .and_then(|json| std::fs::write(&record_path, json).map_err(Into::into));
        if let Err(err) = written {
            tracing::warn!(error = %err, "a kept copy's record could not be written; it is listed until the app closes");
        }
        locks::lock(&self.inner.edits.kept).insert(
            info.id,
            Kept {
                info,
                workspace: run.ctx.workspace_id,
                target: run.target.clone(),
                folder,
                copy: local.to_path_buf(),
                record: record_path,
            },
        );
    }

    /// Why the session can't go on: its terminal closed, or (as root) root browsing ended.
    fn gone(&self, spec: &EditSpec) -> Option<EditEnd> {
        let Some(control) = self.control(spec.terminal_id) else {
            return Some(EditEnd::TerminalClosed);
        };
        if spec.as_root && locks::lock(&control.root).is_none() {
            return Some(EditEnd::RootEnded);
        }
        None
    }

    /// The copy differs from what the host has from this PC (it holds a save that didn't go up).
    async fn unsent(&self, watch: &Watch) -> bool {
        match tokio::fs::read(&watch.local).await {
            Ok(bytes) => sha256_hex(&bytes) != watch.sent_sha,
            Err(_) => false,
        }
    }

    /// Stop editing's question: the last save goes up first (unless the user chose to keep or discard it); `None` when
    /// nothing is left unsent, else what to ask.
    async fn stop_asked(
        &self,
        run: &EditRun<'_>,
        session: &Session,
        watch: &mut Watch,
        choice: Option<StopChoice>,
    ) -> Option<StopOutcome> {
        if matches!(choice, Some(StopChoice::Keep | StopChoice::Discard)) {
            return None;
        }
        if self.gone(run.spec).is_none() {
            watch.force = true;
            self.look(run, session, watch).await;
        }
        if !self.unsent(watch).await {
            return None;
        }
        let message = watch
            .unsent_why
            .clone()
            .unwrap_or_else(|| "Your last save wasn't uploaded.".to_owned());
        Some(StopOutcome::Unsent {
            message,
            conflict: watch.conflict.is_some(),
        })
    }

    /// One look at the copy: a save goes up, or waits.
    async fn look(&self, run: &EditRun<'_>, session: &Session, watch: &mut Watch) {
        // FD-03: a save the read-only lock held goes once the lock is off.
        if watch.locked && !self.inner.store.read_only().is_locked() {
            watch.locked = false;
            watch.force = true;
            match watch.conflict.clone() {
                Some(message) => self.show_edit(session, |info| info.state = EditState::Conflict { message }),
                None => self.show_edit(session, |info| info.state = EditState::Watching),
            }
        }
        let now = seen(&watch.local).await;
        if now.is_none() {
            // Mid-save (some editors write a new file and rename it over the old one).
            return;
        }
        let force = std::mem::take(&mut watch.force);
        let due = watch.next_try.is_some_and(|at| Instant::now() >= at);
        let saved = now != watch.handled;
        if !force && !due {
            if !saved {
                watch.settling = None;
                return;
            }
            if now != watch.settling {
                watch.settling = now;
                return;
            }
        }
        let bytes = match tokio::fs::read(&watch.local).await {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::debug!(error = %err, "an edited copy could not be read; looked at again next time");
                return;
            }
        };
        // A save that began while the copy was read settles first.
        let after = seen(&watch.local).await;
        if after != now {
            watch.settling = after;
            watch.force = force;
            return;
        }
        watch.handled = now;
        watch.settling = None;
        let sha = sha256_hex(&bytes);
        if sha == watch.sent_sha {
            // Back to what the host has from here: nothing waits any more.
            let waited = watch.next_try.is_some() || watch.held_sha.is_some() || watch.conflict.is_some();
            watch.next_try = None;
            watch.held_sha = None;
            watch.conflict = None;
            watch.unsent_why = None;
            if waited {
                self.show_edit(session, |info| info.state = EditState::Watching);
            }
            return;
        }
        if !force && watch.held_sha.as_deref() == Some(sha.as_str()) {
            return;
        }
        if bytes.len() as u64 > MAX_EDIT_BYTES {
            let message = format!(
                "The copy is larger than {} MB, so it was not uploaded.",
                MAX_EDIT_BYTES / (1024 * 1024)
            );
            watch.unsent_why = Some(message.clone());
            watch.next_try = None;
            self.show_edit(session, |info| info.state = EditState::Failed { message });
            return;
        }
        if watch.conflict.is_some() {
            // Saved again while the answer waits: the answer takes the newest copy.
            if saved {
                self.show_edit(session, |info| {
                    info.note = Some("Saved again here; the host's copy still changed since it was opened".into())
                });
            }
            return;
        }
        self.upload(run, session, watch, bytes, sha, false).await;
    }

    /// The terminal's files now, if its connection still goes where the editing began.
    fn files_now(&self, run: &EditRun<'_>, watch: &Watch) -> std::result::Result<Arc<dyn RemoteFiles>, Hold> {
        let (control, files) = self
            .files_for(run.spec.terminal_id, run.spec.as_root)
            .map_err(|err| Hold::Wait(err.to_string()))?;
        let place = locks::lock(&control.place).clone();
        if place.as_ref().is_some_and(|p| p.same(&watch.place)) && files.user() == watch.user {
            return Ok(files);
        }
        Err(Hold::End(
            EditEnd::ConnectionChanged,
            format!(
                "{} now connects to another host, port, jump host or login",
                quoted_name(&control)
            ),
        ))
    }

    /// AP-01: the session became Prod or protected since the approval, in words.
    async fn labels_changed(&self, run: &EditRun<'_>) -> Result<Option<String>> {
        let now = self.target(&run.ctx, run.spec.terminal_id).await?;
        if now.protected && !run.target.protected {
            return Ok(Some(format!("{} is protected now", now.name)));
        }
        if now.environment == Environment::Prod && run.target.environment != Environment::Prod {
            return Ok(Some(format!("{} is labelled Prod now", now.name)));
        }
        Ok(None)
    }

    /// Whether a save may go up now: the read-only lock is off, the connection goes where the editing began, and the
    /// labels are the approved ones. Its files, or `None` with the session's state saying why (or the session ending).
    async fn ready(&self, run: &EditRun<'_>, session: &Session, watch: &mut Watch) -> Option<Arc<dyn RemoteFiles>> {
        if self.inner.store.read_only().is_locked() {
            watch.locked = true;
            watch.unsent_why = Some("The read-only lock is on, so your last save wasn't uploaded.".into());
            self.show_edit(session, |info| {
                info.state = EditState::Held {
                    message: "The read-only lock is on: this save goes up once it is off.".into(),
                }
            });
            return None;
        }
        watch.locked = false;
        let files = match self.files_now(run, watch) {
            Ok(files) => files,
            Err(Hold::Wait(why)) => {
                self.failed(session, watch, &why, true);
                return None;
            }
            Err(Hold::End(why, note)) => {
                self.stop_with(session, watch, why, note);
                return None;
            }
        };
        match self.labels_changed(run).await {
            Ok(None) => Some(files),
            Ok(Some(change)) => {
                self.stop_with(session, watch, EditEnd::LabelsChanged, change);
                None
            }
            Err(err) => {
                self.failed(session, watch, &err.to_string(), true);
                None
            }
        }
    }

    /// A save can never go up through this session: it ends, keeping the copy.
    fn stop_with(&self, session: &Session, watch: &mut Watch, why: EditEnd, note: String) {
        let message = format!("The save was not uploaded: {note}. This PC's copy is kept.");
        watch.unsent_why = Some(message.clone());
        self.show_edit(session, |info| info.state = EditState::Failed { message });
        session.end(why, Some(note));
    }

    /// A save failed: it goes again by itself later (`retry`), on the next save, or on Try again.
    fn failed(&self, session: &Session, watch: &mut Watch, why: &str, retry: bool) {
        watch.unsent_why = Some(format!("Your last save wasn't uploaded: {why}"));
        if retry {
            watch.next_try = Some(Instant::now() + watch.backoff);
            watch.backoff = (watch.backoff * 2).min(RETRY_MAX);
        } else {
            watch.next_try = None;
        }
        let message = format!("The save was not uploaded: {why}");
        self.show_edit(session, |info| info.state = EditState::Failed { message });
    }

    /// Sends the copy up: after checking what is at the path is a regular file (never a link) and, unless `overwrite`,
    /// the one last read or written here.
    async fn upload(
        &self,
        run: &EditRun<'_>,
        session: &Session,
        watch: &mut Watch,
        bytes: Vec<u8>,
        sha: String,
        overwrite: bool,
    ) {
        let Some(files) = self.ready(run, session, watch).await else {
            return;
        };
        self.show_edit(session, |info| info.state = EditState::Uploading);
        let checked = if overwrite {
            check_host(&files, &run.spec.path).await.map(|_| true)
        } else {
            match read_host(&files, &run.spec.path, &session.ending).await {
                Ok(there) => Ok(sha256_hex(&there) == watch.host_sha),
                Err(CoreError::RemoteNotFound { .. }) => Ok(false),
                Err(err) => Err(err),
            }
        };
        match checked {
            Ok(true) => {}
            Ok(false) => {
                let message = format!(
                    "{} changed on the host since it was opened here (in a terminal, or by someone else), so the save \
                     was not uploaded. Overwrite it, save yours beside it, or compare the two.",
                    last_part(&run.spec.path)
                );
                watch.conflict = Some(message.clone());
                watch.next_try = None;
                watch.unsent_why = Some(format!(
                    "{} changed on the host since it was opened here, so your last save wasn't uploaded.",
                    last_part(&run.spec.path)
                ));
                self.show_edit(session, |info| info.state = EditState::Conflict { message });
                return;
            }
            // A link or a folder there now: nothing goes by itself until the user saves or tries again.
            Err(err @ CoreError::InvalidInput(_)) => {
                self.failed(session, watch, &err.to_string(), false);
                return;
            }
            Err(err) => {
                self.failed(session, watch, &err.to_string(), true);
                return;
            }
        }
        match write_host(&files, &run.spec.path, &bytes, true, &session.ending).await {
            Ok(written) => {
                watch.host_sha = sha.clone();
                self.sent(watch, &sha);
                // The count and the state change together, once the save is audited.
                let saves = locks::lock(&session.info).saves + 1;
                let replaced = if overwrite {
                    "; overwrote changes made on the host since it was opened"
                } else {
                    ""
                };
                let written = if written.is_empty() {
                    String::new()
                } else {
                    format!("; {written}")
                };
                let detail = format!("save {saves}: {} bytes, SHA-256 {sha}{replaced}{written}", bytes.len());
                self.audit_save(run, &format!("Saved {} from this PC", shown(&run.spec.path)), &detail)
                    .await;
                self.show_edit(session, |info| {
                    info.saves = saves;
                    info.state = EditState::Watching;
                    info.note = None;
                });
            }
            Err(err @ CoreError::InvalidInput(_)) => self.failed(session, watch, &err.to_string(), false),
            Err(err) => self.failed(session, watch, &err.to_string(), true),
        }
    }

    /// What the host has from this PC is now `sha`: nothing waits.
    fn sent(&self, watch: &mut Watch, sha: &str) {
        watch.sent_sha = sha.to_owned();
        watch.conflict = None;
        watch.held_sha = None;
        watch.next_try = None;
        watch.unsent_why = None;
        watch.backoff = locks::lock(&self.inner.edits.tuning).retry;
    }

    async fn audit_save(&self, run: &EditRun<'_>, action: &str, detail: &str) {
        let on = self
            .control(run.spec.terminal_id)
            .map(|c| quoted_name(&c))
            .unwrap_or_else(|| "the host".into());
        let root = if run.spec.as_root { " as root" } else { "" };
        let noted = audit_entry(
            &self.inner.store,
            &run.ctx,
            "file_changed",
            &format!("{action} on {on}{root}"),
            Some(run.tier),
            Some(run.job_id),
            std::slice::from_ref(run.target),
            detail,
        )
        .await;
        if let Err(err) = noted {
            tracing::error!(error = %err, "could not audit a save from this PC");
        }
    }

    /// The user's answer to a held save.
    async fn answered(
        &self,
        run: &EditRun<'_>,
        session: &Session,
        watch: &mut Watch,
        program: &Path,
        answer: EditAnswer,
    ) {
        if watch.conflict.is_none() && answer != EditAnswer::KeepEditing {
            return;
        }
        let bytes = match tokio::fs::read(&watch.local).await {
            Ok(bytes) => bytes,
            Err(err) => {
                self.show_edit(session, |info| {
                    info.note = Some(format!("This PC's copy could not be read: {err}"))
                });
                return;
            }
        };
        let sha = sha256_hex(&bytes);
        match answer {
            EditAnswer::Overwrite => self.upload(run, session, watch, bytes, sha, true).await,
            EditAnswer::KeepEditing => {
                // The next save asks again: what the host has is still not what was opened.
                watch.conflict = None;
                if sha != watch.sent_sha {
                    watch.held_sha = Some(sha);
                    watch.unsent_why = Some("You chose to keep editing, so your last save wasn't uploaded.".into());
                }
                self.show_edit(session, |info| {
                    info.state = EditState::Watching;
                    info.note = Some("Not uploaded; the next save asks again".into());
                });
            }
            EditAnswer::SaveBeside => {
                let Some(files) = self.ready(run, session, watch).await else {
                    return;
                };
                let folder = parent(&run.spec.path).unwrap_or_else(|| "/".into());
                let name = last_part(&run.spec.path).to_owned();
                let mut beside = None;
                for n in 1..100 {
                    let candidate = join(&folder, &beside_name(&name, n));
                    match files.lstat(&candidate).await {
                        Ok(None) => {
                            beside = Some(candidate);
                            break;
                        }
                        Ok(Some(_)) => continue,
                        Err(err) => {
                            self.show_edit(session, |info| {
                                info.note = Some(format!("Nothing was saved beside it: {err}"))
                            });
                            return;
                        }
                    }
                }
                let Some(beside) = beside else {
                    self.show_edit(session, |info| {
                        info.note = Some("Nothing was saved beside it: too many edited copies are there".into())
                    });
                    return;
                };
                match write_host(&files, &beside, &bytes, false, &session.ending).await {
                    Ok(_) => {
                        self.sent(watch, &sha);
                        let detail = format!(
                            "{} bytes, SHA-256 {sha}, as a new file beside it ({}), since the host's copy had changed",
                            bytes.len(),
                            shown(&beside)
                        );
                        self.audit_save(
                            run,
                            &format!("Saved a copy of {} from this PC", shown(&run.spec.path)),
                            &detail,
                        )
                        .await;
                        let shown_name = shown(last_part(&beside));
                        self.show_edit(session, |info| {
                            info.saves += 1;
                            info.state = EditState::Watching;
                            info.note = Some(format!("Saved beside it as {shown_name}; the next save asks again"));
                        });
                    }
                    Err(err) => self.show_edit(session, |info| {
                        info.note = Some(format!("Nothing was saved beside it: {err}"))
                    }),
                }
            }
            EditAnswer::Compare => {
                let files = match self.files_now(run, watch) {
                    Ok(files) => files,
                    Err(Hold::Wait(why) | Hold::End(_, why)) => {
                        self.show_edit(session, |info| {
                            info.note = Some(format!("The host's copy could not be read: {why}"))
                        });
                        return;
                    }
                };
                let there = match read_host(&files, &run.spec.path, &session.ending).await {
                    Ok(there) => there,
                    Err(err) => {
                        self.show_edit(session, |info| {
                            info.note = Some(format!("The host's copy could not be read: {err}"))
                        });
                        return;
                    }
                };
                let local_text = watch
                    .local
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let copy = watch.local.with_file_name(host_copy_name(&local_text));
                if let Err(err) = tokio::fs::write(&copy, &there).await {
                    self.show_edit(session, |info| {
                        info.note = Some(format!("The host's copy could not be saved here: {err}"))
                    });
                    return;
                }
                let _ = mark_downloaded(&copy).await;
                let editors = locks::read(&self.inner.edits.editors).clone();
                let files = [watch.local.clone(), copy];
                let opened = editors.open(program, &files, true).await;
                self.show_edit(session, |info| {
                    info.note = Some(match opened {
                        Ok(()) if EditorKind::of(program).compares() => {
                            "The two are open side by side; then overwrite it, save yours beside it, or keep editing"
                                .to_owned()
                        }
                        Ok(()) => "The host's copy is open beside yours; then overwrite it, save yours beside it, \
                                   or keep editing"
                            .to_owned(),
                        Err(err) => format!("The host's copy could not be opened: {err}"),
                    })
                });
            }
        }
    }

    fn kept_here(&self, ctx: &Context, id: Uuid) -> Result<(PathBuf, Target, EditInfo)> {
        let kept = locks::lock(&self.inner.edits.kept);
        let copy = kept
            .get(&id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("kept copy {id}: it was discarded")))?;
        if copy.workspace != ctx.workspace_id {
            return Err(CoreError::NotInWorkspace(format!("Kept copy {id}")));
        }
        Ok((copy.copy.clone(), copy.target.clone(), copy.info.clone()))
    }

    /// SS-08 (G4): a kept copy's file name on this PC, for the save dialog.
    pub fn kept_file_name(&self, ctx: &Context, id: Uuid) -> Result<String> {
        let (copy, _, _) = self.kept_here(ctx, id)?;
        Ok(copy
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "edited copy".into()))
    }

    /// SS-08 (G4): opens a kept copy in the editor again (to copy from it; nothing goes up from it).
    pub async fn open_kept(&self, ctx: &Context, id: Uuid) -> Result<()> {
        let (copy, _, _) = self.kept_here(ctx, id)?;
        let program = self.local_editor(ctx).await?.ok_or(CoreError::LocalEditorNotFound)?;
        let editors = locks::read(&self.inner.edits.editors).clone();
        editors.open(&program, &[copy], false).await
    }

    /// SS-08 (G4): saves a kept copy as `to` (from the shell's save dialog; never in a Git working tree), with the Mark
    /// of the Web. Audited, as a download is. The copy stays listed until it is discarded.
    pub async fn save_kept(&self, ctx: &Context, id: Uuid, to: &Path) -> Result<()> {
        crate::save_guard::refuse_repository(to, crate::save_guard::Saved::Download)?;
        let (copy, target, info) = self.kept_here(ctx, id)?;
        let bytes = tokio::fs::read(&copy).await?;
        let sha = sha256_hex(&bytes);
        let size = bytes.len();
        crate::save_guard::write_atomically(to, |mut file| async move {
            file.write_all(&bytes).await?;
            file.flush().await?;
            Ok(())
        })
        .await?;
        let mark = mark_downloaded(to).await;
        audit_entry(
            &self.inner.store,
            ctx,
            "file_edit_copy_saved",
            &format!("Saved the copy of {} kept on this PC", shown(&info.path)),
            None,
            Some(id),
            std::slice::from_ref(&target),
            &format!(
                "{size} bytes, SHA-256 {sha}, saved as {}{}",
                to.display(),
                mark.map(|m| format!("; {m}")).unwrap_or_default()
            ),
        )
        .await?;
        let name = to
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let updated = {
            let mut kept = locks::lock(&self.inner.edits.kept);
            kept.get_mut(&id).map(|k| {
                k.info.note = Some(format!("Saved as {name}"));
                (k.workspace, k.info.clone())
            })
        };
        if let Some(event) = updated {
            let _ = self.inner.edits.events.send(event);
        }
        Ok(())
    }

    /// SS-08 (G4): deletes a kept copy, with what didn't go up. Audited.
    pub async fn discard_kept(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.kept_here(ctx, id)?;
        let Some(kept) = locks::lock(&self.inner.edits.kept).remove(&id) else {
            return Ok(());
        };
        let _ = tokio::fs::remove_file(&kept.record).await;
        remove_folder(kept.folder.clone()).await;
        audit_entry(
            &self.inner.store,
            ctx,
            "file_edit_copy_discarded",
            &format!("Discarded the copy of {} kept on this PC", shown(&kept.info.path)),
            None,
            Some(id),
            std::slice::from_ref(&kept.target),
            "its last save had not been uploaded",
        )
        .await?;
        let mut info = kept.info;
        let reason = match &info.state {
            EditState::Kept { reason, .. } => *reason,
            _ => EditEnd::Stopped,
        };
        info.state = EditState::Ended {
            reason,
            message: "discarded".into(),
        };
        let _ = self.inner.edits.events.send((kept.workspace, info));
        Ok(())
    }
}

/// How a session ended through its `ending` token: the end set first, else its job was cancelled.
fn ended_why(session: &Session) -> (EditEnd, Option<String>) {
    locks::lock(&session.end).clone().unwrap_or((EditEnd::Cancelled, None))
}

/// "VS Code", or the program's file name for an editor Remotely doesn't know by name.
fn editor_name(kind: EditorKind, program: &Path) -> String {
    match kind {
        EditorKind::Other => program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "the editor".into()),
        known => known.label().to_owned(),
    }
}

impl super::files::FileTransfers {
    /// SS-08 (G4): edits a host's file on this PC ([`crate::command_bus::Command::EditLocal`]): the file is looked at
    /// first (a regular file, not a link, at most [`MAX_EDIT_BYTES`]) and an editor must be found on this PC.
    pub async fn edit_on_pc(
        &self,
        terminal_id: Uuid,
        path: String,
        as_root: bool,
    ) -> Result<crate::command_bus::SubmitOutcome> {
        let ctx = self.workspace.get();
        check_path(&path)?;
        self.terminals.edit_root()?;
        let (_, files) = self.terminals.files_for(terminal_id, as_root)?;
        let entry = files
            .lstat(&path)
            .await?
            .ok_or_else(|| CoreError::RemoteNotFound { path: path.clone() })?;
        if entry.link {
            return Err(CoreError::InvalidInput(format!(
                "{} is a link: edit the file it points to.",
                shown(&path)
            )));
        }
        if entry.kind != EntryKind::File {
            return Err(CoreError::InvalidInput(format!("{} is not a file.", shown(&path))));
        }
        if entry.size > MAX_EDIT_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "{} is larger than {} MB, too large to edit on this PC: download it instead.",
                shown(&path),
                MAX_EDIT_BYTES / (1024 * 1024)
            )));
        }
        if self.terminals.local_editor(&ctx).await?.is_none() {
            return Err(CoreError::LocalEditorNotFound);
        }
        let spec = EditSpec {
            terminal_id,
            path,
            as_root,
        };
        spec.validate()?;
        let command = crate::command_bus::Command::EditLocal {
            targets: spec.targets(),
            spec: Box::new(spec),
        };
        self.bus.submit(&ctx, command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_beside_and_for_the_host_s_copy() {
        assert_eq!(beside_name("hosts", 1), "hosts (edited)");
        assert_eq!(beside_name("nginx.conf", 1), "nginx (edited).conf");
        assert_eq!(beside_name("nginx.conf", 3), "nginx (edited 3).conf");
        assert_eq!(beside_name(".bashrc", 1), ".bashrc (edited)");
        assert_eq!(host_copy_name("nginx.conf"), "nginx (on the host).conf");
        assert_eq!(host_copy_name("hosts"), "hosts (on the host)");
    }

    #[test]
    fn long_names_are_cut_to_fit_both_sides() {
        let long = format!("{}.conf", "a".repeat(250));
        let beside = beside_name(&long, 2);
        assert!(beside.len() <= 255 && beside.ends_with(" (edited 2).conf"), "{beside}");
        let copy = host_copy_name(&long);
        assert!(
            utf16_units(&copy) <= 255 && copy.ends_with(" (on the host).conf"),
            "{copy}"
        );
        // Multi-byte characters count as the host (bytes) and Windows (UTF-16 units) count them; never cut in half.
        let wide = "é".repeat(127);
        let beside = beside_name(&wide, 1);
        assert!(beside.len() <= 255 && beside.ends_with(" (edited)"), "{beside}");
        let name = copy_name(&format!("{}.lnk", "x".repeat(253)));
        assert!(utf16_units(&name) <= 255 && name.ends_with(".lnk.txt"), "{name}");
    }

    #[test]
    fn copies_explorer_or_vs_code_would_act_on_open_as_text() {
        for (host, local) in [
            ("desktop.ini", "desktop.ini.txt"),
            ("x.scf", "x.scf.txt"),
            ("x.LNK", "x.LNK.txt"),
            ("site.url", "site.url.txt"),
            ("proj.code-workspace", "proj.code-workspace.txt"),
            ("nginx.conf", "nginx.conf"),
            ("CON", "_CON"),
            ("a:b.txt", "a_b.txt"),
        ] {
            assert_eq!(copy_name(host), local, "{host}");
        }
    }

    #[test]
    fn specs_check_their_path_and_keep_it_redacted_in_the_journal() {
        let spec = |path: &str| EditSpec {
            terminal_id: Uuid::nil(),
            path: path.into(),
            as_root: false,
        };
        assert!(spec("/etc/hosts").validate().is_ok());
        for bad in ["/", "etc/hosts", "/etc/../shadow", "/srv/a\rb", "/srv/x\u{200B}y"] {
            assert!(spec(bad).validate().is_err(), "{bad:?}");
        }
        let (kept, changed) = spec("/srv/token=ghp_abcdefghijklmnopqrstuvwxyz0123456789").for_journal();
        assert!(changed && !kept.path.contains("ghp_"), "{}", kept.path);
        let mut root = spec("/etc/hosts");
        root.as_root = true;
        assert_eq!(
            root.summary(),
            "Edit /etc/hosts on this PC, each save replacing it on the host, as root"
        );
    }

    #[test]
    fn the_start_sweep_keeps_kept_copies_and_deletes_the_rest() {
        let root = std::env::temp_dir().join(format!("remotely-sweep-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&root).unwrap();
        let kept_id = Uuid::new_v4().simple().to_string();
        std::fs::create_dir_all(root.join(&kept_id)).unwrap();
        std::fs::write(root.join(&kept_id).join("app.conf"), b"port = 81\n").unwrap();
        let record = KeptRecord {
            version: 1,
            id: Uuid::parse_str(&kept_id).unwrap(),
            workspace_id: WorkspaceId(Uuid::nil()),
            target: Target {
                target: TargetRef::RemotePath {
                    terminal_id: Uuid::nil(),
                    session_id: None,
                    step: 0,
                },
                name: "web01: /srv/app/app.conf".into(),
                environment: Environment::Lab,
                protected: false,
            },
            terminal_id: Uuid::nil(),
            name: "web01".into(),
            path: "/srv/app/app.conf".into(),
            as_root: false,
            editor: "VS Code".into(),
            saves: 0,
            reason: EditEnd::TerminalClosed,
            message: "its terminal closed".into(),
            started_at: now_rfc3339(),
            ended_at: now_rfc3339(),
            file: "app.conf".into(),
        };
        std::fs::write(
            root.join(format!("{kept_id}{KEPT_SUFFIX}")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        // Left by a crash: a folder without a record, a record without a folder, a record naming a path.
        let crashed = Uuid::new_v4().simple().to_string();
        std::fs::create_dir_all(root.join(&crashed)).unwrap();
        std::fs::write(root.join(&crashed).join("hosts"), b"x").unwrap();
        let orphan = Uuid::new_v4().simple().to_string();
        std::fs::write(root.join(format!("{orphan}{KEPT_SUFFIX}")), b"{}").unwrap();
        let sneaky = Uuid::new_v4().simple().to_string();
        std::fs::create_dir_all(root.join(&sneaky)).unwrap();
        let mut bad = serde_json::to_value(&record).unwrap();
        bad["id"] = serde_json::json!(Uuid::parse_str(&sneaky).unwrap());
        bad["file"] = serde_json::json!("..\\..\\secret.txt");
        std::fs::write(
            root.join(format!("{sneaky}{KEPT_SUFFIX}")),
            serde_json::to_vec(&bad).unwrap(),
        )
        .unwrap();

        let (swept, kept) = sweep(&root).unwrap();
        assert_eq!(swept, 4, "the crashed folder, the orphan record, and the sneaky pair");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].info.path, "/srv/app/app.conf");
        assert!(matches!(
            kept[0].info.state,
            EditState::Kept {
                reason: EditEnd::TerminalClosed,
                ..
            }
        ));
        assert!(root.join(&kept_id).join("app.conf").exists());
        assert!(!root.join(&crashed).exists() && !root.join(&sneaky).exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
