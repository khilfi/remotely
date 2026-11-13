//! SS-08's last part (0.8.0 G4): "Edit on this PC". A host's file is downloaded into a folder only this Windows user
//! can open and opened in the editor chosen in Settings; each save is uploaded back, once the host's copy is checked to
//! be the one that was opened (`docs/plan-0.8.md`, "Edit on this PC").
//!
//! * **One command for the editing session** ([`crate::command_bus::Command::EditLocal`]): each save replaces the
//!   host's file, so it is rated as a replacement, Medium (never lower: [`crate::policy::MIN_REPLACE_TIER`]), one tier
//!   higher as root and for Prod, and approved once for the editing session. Its job lasts as long as the session, and
//!   every save is audited on its own (`file_changed`, with the bytes' SHA-256), as the download is
//!   (`file_edit_opened`) and the end (`file_edit_ended`, with why).
//! * **The copy** is in a folder of its own under Remotely's editing folder ([`Terminals::set_edit_folder`], under the
//!   data folder, never in a Git working tree), made with a DACL for this user alone
//!   ([`crate::private_folder`]), named as the host names the file (made safe for Windows, A8), and given the Mark of
//!   the Web. It opens in the editor's own program ([`crate::adapters::local_editor`]), never Windows' default action.
//!   The folder goes when the session ends, and what an earlier run left behind (a crash) goes at the next start.
//! * **A save** is a change of the copy's size or time that stays for one poll and changes its bytes. Before it goes
//!   up, the host's file is read again: when its SHA-256 is still the one last read or written, the save replaces it
//!   (H8: a temporary file renamed over it, keeping its permissions and owner); otherwise the session holds the save and
//!   asks: overwrite, save beside it (a new file of the next free name, `name (edited).ext`), compare (the host's copy
//!   downloaded beside the copy, and with VS Code opened as a diff), or keep editing.
//! * **It ends** on Stop editing (the last save goes up first, if the host's copy is unchanged), after
//!   [`EDIT_LIMIT`] (likewise), and without uploading when the job is cancelled, the vault locks, the workspace changes,
//!   the app closes, the terminal closes, or (as root) root browsing ends. Many editors run as one instance, so the
//!   editor's process is never what ends it. The window lists the open sessions ([`Terminals::edits`]).
//! * **Reads and writes** go through the terminal's own SFTP (as root: its root browsing), at most
//!   [`MAX_EDIT_BYTES`] a file; a link, a folder or anything but a regular file is refused.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::file_ops::{check_path, last_part};
use super::files::{join, local_name, mark_downloaded, parent};
use super::{audit_entry, quoted_name, Terminals};
use crate::adapters::local_editor::{locate_local_editor, EditorKind, LocalEditors, LOCAL_EDITOR_PATH_KEY};
use crate::adapters::remote::{EntryKind, RemoteFiles};
use crate::domain::{now_rfc3339, Context, Target, TargetRef, WorkspaceId};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::locks;
use crate::policy::Tier;

/// The largest file edited on this PC (an editor is for text, not a disk image).
pub const MAX_EDIT_BYTES: u64 = 16 * 1024 * 1024;
/// An editing session's longest life (`docs/plan-0.8.md`).
pub const EDIT_LIMIT: Duration = Duration::from_secs(4 * 3600);

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EditEnd {
    Stopped,
    TimeLimit,
    Cancelled,
    VaultLocked,
    WorkspaceSwitched,
    AppClosing,
    TerminalClosed,
    RootEnded,
}

impl EditEnd {
    fn detail(self) -> &'static str {
        match self {
            EditEnd::Stopped => "stopped by the user",
            EditEnd::TimeLimit => "it reached its 4 hours",
            EditEnd::Cancelled => "its job was cancelled",
            EditEnd::VaultLocked => "the vault locked",
            EditEnd::WorkspaceSwitched => "another workspace was opened",
            EditEnd::AppClosing => "the app closed",
            EditEnd::TerminalClosed => "its terminal closed",
            EditEnd::RootEnded => "root browsing ended",
        }
    }

    /// Ends the user chose (or the time limit): the last save goes up first, if the host's copy is unchanged.
    fn uploads_last(self) -> bool {
        matches!(self, EditEnd::Stopped | EditEnd::TimeLimit)
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
    Conflict {
        message: String,
    },
    /// The last save could not go up; the next save (or Try again) tries again.
    Failed {
        message: String,
    },
    Ended {
        reason: EditEnd,
        message: String,
    },
}

/// SS-08: an editing session, as the window lists it.
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

enum Msg {
    Stop(EditEnd),
    Answer(EditAnswer),
    Retry,
}

struct Session {
    info: Mutex<EditInfo>,
    tx: mpsc::Sender<Msg>,
    workspace: WorkspaceId,
}

/// How often the copy is looked at, and how long a session may last (tests shorten both).
#[derive(Debug, Clone, Copy)]
pub struct EditTuning {
    pub poll: Duration,
    pub limit: Duration,
}

impl Default for EditTuning {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(1),
            limit: EDIT_LIMIT,
        }
    }
}

/// SS-08: the open editing sessions, and what they need.
pub(super) struct Edits {
    sessions: Mutex<HashMap<Uuid, Arc<Session>>>,
    events: broadcast::Sender<(WorkspaceId, EditInfo)>,
    /// The folder copies go in; `None`: this user's temp folder's `remotely-editing`.
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

/// The host's file, whole: refused when it is a link, not a regular file, or larger than [`MAX_EDIT_BYTES`].
async fn read_host(files: &Arc<dyn RemoteFiles>, path: &str) -> Result<Vec<u8>> {
    let entry = files
        .lstat(path)
        .await?
        .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
    if entry.link {
        return Err(CoreError::InvalidInput(format!(
            "{} is a link: edit the file it points to.",
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
    let mut reader = files.read(path).await?;
    let mut bytes = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
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

/// Writes `bytes` to the host's `path`, replacing what is there (H8) or, without `replace`, only as a new file.
async fn write_host(files: &Arc<dyn RemoteFiles>, path: &str, bytes: &[u8], replace: bool) -> Result<String> {
    let mut writer = files.write(path, replace).await?;
    if let Err(err) = writer.write_all(bytes).await {
        let _ = writer.abort().await;
        return Err(err);
    }
    Ok(writer.finish().await?.note())
}

/// `hosts (edited)`, `hosts (edited 2).conf`...: the name a save beside the host's file gets.
fn beside_name(name: &str, n: usize) -> String {
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_owned(), format!(".{ext}")),
        _ => (name.to_owned(), String::new()),
    };
    let edited = if n <= 1 {
        "edited".to_owned()
    } else {
        format!("edited {n}")
    };
    format!("{stem} ({edited}){extension}")
}

/// `hosts (on the host).conf`: the host's copy downloaded beside this PC's to compare.
fn host_copy_name(local: &str) -> String {
    match local.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} (on the host).{ext}"),
        _ => format!("{local} (on the host)"),
    }
}

/// The copy's size and time: what a save changes.
async fn seen(local: &Path) -> Option<(u64, Option<SystemTime>)> {
    let meta = tokio::fs::metadata(local).await.ok()?;
    Some((meta.len(), meta.modified().ok()))
}

/// Deletes the session's folder when dropped (tried a few times: an editor may hold the file a moment); what stays
/// goes at the next start.
struct FolderGuard(PathBuf);

impl Drop for FolderGuard {
    fn drop(&mut self) {
        for attempt in 0..5 {
            match std::fs::remove_dir_all(&self.0) {
                Ok(()) => return,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
                Err(err) if attempt == 4 => {
                    tracing::warn!(error = %err, "could not delete an editing folder; it goes at the next start");
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}

/// One editing session's state between polls.
struct Watch {
    files: Arc<dyn RemoteFiles>,
    local: PathBuf,
    /// The SHA-256 of what the host had when it was last read or written here.
    host_sha: String,
    /// The SHA-256 of this PC's copy as last opened or uploaded.
    local_sha: String,
    /// The copy's size and time last handled, and one seen once (a save settles for a poll).
    handled: Option<(u64, Option<SystemTime>)>,
    settling: Option<(u64, Option<SystemTime>)>,
    /// A save waits for the user's answer.
    conflict: bool,
    /// The last upload failed: the next poll tries again.
    retry: bool,
}

impl Terminals {
    /// SS-08 (G4): what opens copies on this PC (tests give [`crate::fakes::FakeLocalEditors`]).
    pub fn set_local_editors(&self, editors: Arc<dyn LocalEditors>) {
        *locks::write(&self.inner.edits.editors) = editors;
    }

    /// SS-08 (G4): how often copies are looked at and how long a session lasts (tests shorten them).
    pub fn set_edit_tuning(&self, tuning: EditTuning) {
        *locks::lock(&self.inner.edits.tuning) = tuning;
    }

    /// SS-08 (G4): where copies go: a folder of its own each under `folder` (never in a Git working tree). What a run
    /// before left there (a crash) is deleted now; returns how many were.
    pub fn set_edit_folder(&self, folder: &Path) -> Result<usize> {
        crate::save_guard::refuse_repository_folder(folder, crate::save_guard::Saved::Download)?;
        std::fs::create_dir_all(folder)?;
        let mut swept = 0;
        for entry in std::fs::read_dir(folder)?.flatten() {
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
        *locks::lock(&self.inner.edits.folder) = Some(folder.to_path_buf());
        Ok(swept)
    }

    fn edit_root(&self) -> PathBuf {
        locks::lock(&self.inner.edits.folder)
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("remotely-editing"))
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

    /// SS-08 (G4): the shown workspace's open editing sessions.
    pub fn edits(&self, ctx: &Context) -> Vec<EditInfo> {
        let sessions = locks::lock(&self.inner.edits.sessions);
        let mut list: Vec<EditInfo> = sessions
            .values()
            .filter(|s| s.workspace == ctx.workspace_id)
            .map(|s| locks::lock(&s.info).clone())
            .collect();
        list.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        list
    }

    /// SS-08 (G4): every change of an editing session (also its end), with its workspace: the shell passes the shown
    /// workspace's on.
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

    /// SS-08 (G4): Stop editing: the last save goes up (if the host's copy is unchanged), the copy is deleted, and the
    /// session's job ends.
    pub async fn stop_edit(&self, ctx: &Context, id: Uuid) -> Result<()> {
        let session = self.edit_session(ctx, id)?;
        let _ = session.tx.send(Msg::Stop(EditEnd::Stopped)).await;
        Ok(())
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

    /// SS-08 (G4): ends every editing session (of `workspace`, or all) without uploading more; their job ids, to wait
    /// for.
    pub fn end_edits(&self, workspace: Option<WorkspaceId>, why: EditEnd) -> Vec<Uuid> {
        let sessions: Vec<(Uuid, Arc<Session>)> = locks::lock(&self.inner.edits.sessions)
            .iter()
            .filter(|(_, s)| workspace.is_none_or(|w| w == s.workspace))
            .map(|(id, s)| (*id, Arc::clone(s)))
            .collect();
        for (_, session) in &sessions {
            let _ = session.tx.try_send(Msg::Stop(why));
        }
        sessions.into_iter().map(|(id, _)| id).collect()
    }

    /// SS-08 (G4): the terminal closed: its editing sessions end at once, without uploading more.
    pub(super) fn end_edits_of(&self, terminal_id: Uuid) {
        let sessions: Vec<Arc<Session>> = locks::lock(&self.inner.edits.sessions)
            .values()
            .filter(|s| locks::lock(&s.info).terminal_id == terminal_id)
            .cloned()
            .collect();
        for session in sessions {
            let _ = session.tx.try_send(Msg::Stop(EditEnd::TerminalClosed));
        }
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
        let program = self
            .local_editor(&run.ctx)
            .await?
            .ok_or(CoreError::LocalEditorNotFound)?;
        let editor = EditorKind::of(&program);
        let bytes = read_host(&files, &spec.path).await?;
        let host_sha = sha256_hex(&bytes);
        // A folder of its own, only this user's, deleted when the session ends however it ends.
        let folder = self.edit_root().join(run.job_id.simple().to_string());
        crate::private_folder::make(&folder)?;
        let guard = FolderGuard(folder.clone());
        let local = folder.join(local_name(last_part(&spec.path)));
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
            }),
            tx,
            workspace: run.ctx.workspace_id,
        });
        locks::lock(&self.inner.edits.sessions).insert(run.job_id, Arc::clone(&session));
        self.show_edit(&session, |_| {});

        let mut watch = Watch {
            handled: seen(&local).await,
            settling: None,
            files,
            local: local.clone(),
            host_sha,
            local_sha: sha256_hex(&bytes),
            conflict: false,
            retry: false,
        };
        let deadline = Instant::now() + tuning.limit;
        let why = loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break EditEnd::Cancelled,
                msg = rx.recv() => match msg {
                    Some(Msg::Stop(why)) => break why,
                    Some(Msg::Answer(answer)) => self.answered(&run, &session, &mut watch, &program, answer).await,
                    Some(Msg::Retry) => {
                        watch.retry = true;
                        self.look(&run, &session, &mut watch).await;
                    }
                    None => break EditEnd::Cancelled,
                },
                () = tokio::time::sleep(tuning.poll) => {
                    if Instant::now() >= deadline {
                        break EditEnd::TimeLimit;
                    }
                    if let Some(why) = self.gone(spec) {
                        break why;
                    }
                    self.look(&run, &session, &mut watch).await;
                }
            }
        };
        // Stop editing and the time limit send the last save up first; the copy is never thrown away silently.
        let mut last = None;
        if why.uploads_last() && self.gone(spec).is_none() {
            watch.settling = seen(&local).await;
            self.look(&run, &session, &mut watch).await;
            if watch.conflict {
                last = Some("its last save was not uploaded: the host's copy had changed");
            }
        } else if self.unsent(&watch).await {
            last = Some("its last save was not uploaded");
        }
        locks::lock(&self.inner.edits.sessions).remove(&run.job_id);
        let saves = locks::lock(&session.info).saves;
        let message = match last {
            Some(last) => format!("{}; {last}", why.detail()),
            None => why.detail().to_owned(),
        };
        self.show_edit(&session, |info| {
            info.state = EditState::Ended {
                reason: why,
                message: message.clone(),
            }
        });
        drop(guard);
        let note = format!(
            "{} uploaded; ended: {message}; this PC's copy deleted",
            match saves {
                1 => "1 save".to_owned(),
                n => format!("{n} saves"),
            }
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

    /// The copy differs from what was last uploaded (or opened).
    async fn unsent(&self, watch: &Watch) -> bool {
        match tokio::fs::read(&watch.local).await {
            Ok(bytes) => sha256_hex(&bytes) != watch.local_sha,
            Err(_) => false,
        }
    }

    /// One look at the copy: a save goes up, or waits for the user's answer.
    async fn look(&self, run: &EditRun<'_>, session: &Session, watch: &mut Watch) {
        let now = seen(&watch.local).await;
        if now.is_none() {
            // Mid-save (some editors write a new file and rename it over the old one).
            return;
        }
        if !watch.retry {
            if now == watch.handled {
                watch.settling = None;
                return;
            }
            if now != watch.settling {
                watch.settling = now;
                return;
            }
        }
        watch.handled = now;
        watch.settling = None;
        let bytes = match tokio::fs::read(&watch.local).await {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::debug!(error = %err, "an edited copy could not be read; looked at again next time");
                return;
            }
        };
        let sha = sha256_hex(&bytes);
        if sha == watch.local_sha && !watch.retry {
            return;
        }
        if bytes.len() as u64 > MAX_EDIT_BYTES {
            self.show_edit(session, |info| {
                info.state = EditState::Failed {
                    message: format!(
                        "The copy is larger than {} MB, so it was not uploaded.",
                        MAX_EDIT_BYTES / (1024 * 1024)
                    ),
                }
            });
            return;
        }
        if watch.conflict {
            // Saved again while the answer waits: the answer takes the newest copy.
            self.show_edit(session, |info| {
                info.note = Some("Saved again here; the host's copy still changed since it was opened".into())
            });
            return;
        }
        watch.retry = false;
        self.upload(run, session, watch, bytes, sha, false).await;
    }

    /// Sends the copy up: after checking the host's copy is the one last read or written, unless `overwrite`.
    async fn upload(
        &self,
        run: &EditRun<'_>,
        session: &Session,
        watch: &mut Watch,
        bytes: Vec<u8>,
        sha: String,
        overwrite: bool,
    ) {
        self.show_edit(session, |info| info.state = EditState::Uploading);
        let checked = if overwrite {
            Ok(true)
        } else {
            match read_host(&watch.files, &run.spec.path).await {
                Ok(there) => Ok(sha256_hex(&there) == watch.host_sha),
                Err(CoreError::RemoteNotFound { .. }) => Ok(false),
                Err(err) => Err(err),
            }
        };
        match checked {
            Ok(true) => {}
            Ok(false) => {
                watch.conflict = true;
                self.show_edit(session, |info| {
                    info.state = EditState::Conflict {
                        message: format!(
                            "{} changed on the host since it was opened here (in a terminal, or by someone else), so \
                             the save was not uploaded. Overwrite it, save yours beside it, or compare the two.",
                            last_part(&run.spec.path)
                        ),
                    }
                });
                return;
            }
            Err(err) => {
                watch.retry = true;
                self.show_edit(session, |info| {
                    info.state = EditState::Failed {
                        message: format!("The save was not uploaded: {err}"),
                    }
                });
                return;
            }
        }
        match write_host(&watch.files, &run.spec.path, &bytes, true).await {
            Ok(written) => {
                watch.host_sha = sha.clone();
                watch.local_sha = sha.clone();
                watch.conflict = false;
                watch.retry = false;
                let saves = {
                    let mut info = locks::lock(&session.info);
                    info.saves += 1;
                    info.saves
                };
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
                    info.state = EditState::Watching;
                    info.note = None;
                });
            }
            Err(err) => {
                watch.retry = true;
                self.show_edit(session, |info| {
                    info.state = EditState::Failed {
                        message: format!("The save was not uploaded: {err}"),
                    }
                });
            }
        }
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
        if !watch.conflict && answer != EditAnswer::KeepEditing {
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
                watch.conflict = false;
                watch.local_sha = sha;
                self.show_edit(session, |info| {
                    info.state = EditState::Watching;
                    info.note = Some("Not uploaded; the next save asks again".into());
                });
            }
            EditAnswer::SaveBeside => {
                let folder = parent(&run.spec.path).unwrap_or_else(|| "/".into());
                let name = last_part(&run.spec.path).to_owned();
                let mut beside = None;
                for n in 1..100 {
                    let candidate = join(&folder, &beside_name(&name, n));
                    match watch.files.lstat(&candidate).await {
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
                match write_host(&watch.files, &beside, &bytes, false).await {
                    Ok(_) => {
                        watch.conflict = false;
                        watch.local_sha = sha.clone();
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
                let there = match read_host(&watch.files, &run.spec.path).await {
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
    fn only_the_user_s_ends_upload_the_last_save() {
        assert!(EditEnd::Stopped.uploads_last() && EditEnd::TimeLimit.uploads_last());
        for end in [
            EditEnd::Cancelled,
            EditEnd::VaultLocked,
            EditEnd::WorkspaceSwitched,
            EditEnd::AppClosing,
            EditEnd::TerminalClosed,
            EditEnd::RootEnded,
        ] {
            assert!(!end.uploads_last(), "{end:?}");
        }
    }
}
