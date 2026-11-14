//! SS-14 (0.8.0 G3): compare a folder of this PC with a folder on a terminal's host, then sync one way
//! (`docs/plan-0.8.md`, "Compare and sync folders").
//!
//! * **Compare** is a read: both trees are walked (links, junctions and Git's own data, `.git` as Windows would save
//!   the name, so `.git.` and `.GIT ` too, left out on both sides and counted; at most [`MAX_UPLOAD_FILES`] items a side, [`MAX_FOLDER_DEPTH`] deep) and each path is
//!   missing on one side, the same, or different: newer (by modification time, two seconds of slack for SFTP's whole
//!   seconds and FAT's two), larger, and with "Compare contents" each file's SHA-256 (only files of the same size need
//!   it: the host's own `sha256sum`, else read over SFTP up to a cap; this PC's read here; [`CONTENT_SECONDS`] in all,
//!   each host file within [`HASH_SECONDS`]; what didn't fit keeps its size and time verdict, counted). The comparison
//!   is kept under an id, so
//!   a sync names its rows by their paths there and nothing else.
//! * **Sync to the host** is one [`Command::FileUpload`] job: what this PC has that the host lacks or holds older is
//!   uploaded (Low), what replaces a file there is Medium, and deleting what the host has that this PC doesn't happens
//!   only when chosen and is High ([`ActionKind::FileSyncDelete`]). As root, one tier higher; the Prod rule applies.
//!   Deletes run only once everything was sent.
//! * **Sync to this PC** is a download of the files picked (audited reads, the Mark of the Web, `save_guard` and
//!   Remotely's data folder as for any download), replacing files here that are older. Nothing on this PC is deleted:
//!   Remotely changes no file here beyond what a download writes.
//!
//! [`Command::FileUpload`]: crate::command_bus::Command::FileUpload
//! [`ActionKind::FileSyncDelete`]: crate::policy::ActionKind::FileSyncDelete

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::file_ops::check_path;
use super::file_reads::{HostHash, HASH_SECONDS};
use super::files::{is_git_name, join, DownloadOptions, DownloadStart, Existing};
use super::Terminals;
use crate::adapters::remote::{EntryKind, RemoteEntry, RemoteFiles};
use crate::command_bus::{Command, CommandBus, SubmitOutcome, UploadFile, MAX_FOLDER_DEPTH, MAX_UPLOAD_FILES};
use crate::error::{CoreError, Result};
use crate::local_files::LocalFiles;
use crate::locks;

/// Times this close count as the same (SFTP gives whole seconds; FAT keeps two).
const TIME_SLACK: u64 = 2;
/// Files whose contents a comparison hashes, at most.
pub const MAX_CONTENT_FILES: usize = 1000;
/// How long a comparison may hash files for "Compare contents", in all (each host file within [`HASH_SECONDS`] too).
pub const CONTENT_SECONDS: u64 = 600;
/// Comparisons kept for a sync, at most, and for how long.
const KEEP: usize = 20;
const KEEP_FOR: Duration = Duration::from_secs(3600);

/// What the Files page compares.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareRequest {
    pub terminal_id: Uuid,
    /// The local pane's listing (its folder is the one compared).
    pub listing: Uuid,
    /// The host's folder, absolute.
    pub host_folder: String,
    /// Each pair of files of the same size by its SHA-256 too.
    #[serde(default)]
    pub contents: bool,
    #[serde(default)]
    pub as_root: bool,
}

/// One side of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SideInfo {
    pub folder: bool,
    pub size: u64,
    pub modified: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Side {
    /// This PC.
    Here,
    /// The host.
    There,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RowState {
    Same,
    OnlyHere,
    OnlyThere,
    Differs,
    /// A file on one side, a folder on the other: no sync takes it.
    Conflict,
}

/// One path of a comparison, relative to both folders, `/`-separated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffRow {
    pub path: String,
    pub here: Option<SideInfo>,
    pub there: Option<SideInfo>,
    pub state: RowState,
    /// The side whose file is newer (beyond the slack).
    pub newer: Option<Side>,
    pub larger: Option<Side>,
    /// With "Compare contents": whether the SHA-256s are the same; `None` when not compared.
    pub same_content: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareCounts {
    pub same: usize,
    pub only_here: usize,
    pub only_there: usize,
    pub differs: usize,
    pub conflicts: usize,
}

/// A comparison, as the Files page shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub id: Uuid,
    /// This PC's folder, as Windows shows it.
    pub local: String,
    pub host: String,
    pub terminal_id: Uuid,
    pub as_root: bool,
    pub contents: bool,
    /// Every path but the same ones (counted).
    pub rows: Vec<DiffRow>,
    pub counts: CompareCounts,
    /// Links, junctions, Git's data and what is neither a file nor a folder, on both sides.
    pub left_out: usize,
    /// More files of the same size than [`MAX_CONTENT_FILES`], or more than [`CONTENT_SECONDS`] of hashing: those
    /// beyond were compared by size and time only.
    pub contents_capped: bool,
    /// Files whose contents were compared.
    pub contents_compared: usize,
    /// Files the host couldn't hash in time, or too large to read over SFTP for it: compared by size and time only.
    pub contents_unread: usize,
}

/// Which way a sync goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncDirection {
    ToHost,
    ToPc,
}

/// What a sync of a comparison sends: its rows by path (a folder takes the rows under it), and whether what is only
/// on the host is deleted there (to the host only).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRequest {
    pub comparison: Uuid,
    pub direction: SyncDirection,
    pub paths: Vec<String>,
    #[serde(default)]
    pub delete: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SyncStart {
    /// To the host: on the bus, queued or waiting for its approval.
    Submitted { outcome: Box<SubmitOutcome> },
    /// To this PC: downloads queued.
    Downloads { start: DownloadStart },
    /// Nothing picked needs to go.
    Nothing,
}

struct Kept {
    terminal_id: Uuid,
    as_root: bool,
    local: PathBuf,
    host: String,
    rows: BTreeMap<String, DiffRow>,
    at: Instant,
}

/// SS-14 (0.8.0 G3): compare and sync (`Core.sync`).
pub struct FolderSyncs {
    workspace: crate::workspaces::Current,
    terminals: Terminals,
    bus: Arc<CommandBus>,
    local: LocalFiles,
    kept: Mutex<HashMap<Uuid, Kept>>,
}

/// A local tree: each path under the root (folders and files), and how many were left out.
fn walk_local_tree(root: &Path) -> Result<(BTreeMap<String, SideInfo>, usize)> {
    let mut found = BTreeMap::new();
    let mut left_out = 0;
    let mut queue = VecDeque::from([(root.to_owned(), String::new(), 0usize)]);
    while let Some((folder, rel, depth)) = queue.pop_front() {
        let entries = std::fs::read_dir(&folder)
            .map_err(|err| CoreError::InvalidInput(format!("'{}' can't be read: {err}", folder.display())))?;
        for entry in entries.filter_map(std::result::Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                left_out += 1;
                continue;
            };
            if is_git_name(&name) || crate::terminal::files::is_link(&meta) {
                left_out += 1;
                continue;
            }
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let modified = meta
                .modified()
                .ok()
                .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            if meta.is_dir() {
                if depth + 1 >= MAX_FOLDER_DEPTH {
                    return Err(CoreError::InvalidInput(format!(
                        "'{}' is more than {MAX_FOLDER_DEPTH} folders deep; compare a part of it.",
                        root.display()
                    )));
                }
                found.insert(
                    path.clone(),
                    SideInfo {
                        folder: true,
                        size: 0,
                        modified,
                    },
                );
                queue.push_back((entry.path(), path, depth + 1));
            } else if meta.is_file() {
                found.insert(
                    path,
                    SideInfo {
                        folder: false,
                        size: meta.len(),
                        modified,
                    },
                );
            } else {
                left_out += 1;
            }
            if found.len() > MAX_UPLOAD_FILES {
                return Err(CoreError::InvalidInput(format!(
                    "'{}' holds more than {MAX_UPLOAD_FILES} files and folders; compare a part of it.",
                    root.display()
                )));
            }
        }
    }
    Ok((found, left_out))
}

/// A host tree, the same way: links, Git's data and what is neither a file nor a folder left out.
async fn walk_host_tree(files: &dyn RemoteFiles, root: &str) -> Result<(BTreeMap<String, SideInfo>, usize)> {
    let mut found = BTreeMap::new();
    let mut left_out = 0;
    let mut queue = VecDeque::from([(root.to_owned(), String::new(), 0usize)]);
    while let Some((folder, rel, depth)) = queue.pop_front() {
        let listing = files.list(&folder).await?;
        if listing.more {
            return Err(CoreError::InvalidInput(format!(
                "{folder} holds more than Remotely lists in one folder; compare a part of it."
            )));
        }
        for entry in listing.entries {
            // Git's data as Windows would save the name (`.git.`, `.GIT `): a sync to this PC never makes a `.git`.
            if is_git_name(&entry.name) || entry.link || entry.kind == EntryKind::Other {
                left_out += 1;
                continue;
            }
            let path = if rel.is_empty() {
                entry.name.clone()
            } else {
                format!("{rel}/{}", entry.name)
            };
            let folder_here = entry.kind == EntryKind::Folder;
            found.insert(
                path.clone(),
                SideInfo {
                    folder: folder_here,
                    size: if folder_here { 0 } else { entry.size },
                    modified: entry.modified,
                },
            );
            if folder_here {
                if depth + 1 >= MAX_FOLDER_DEPTH {
                    return Err(CoreError::InvalidInput(format!(
                        "{root} is more than {MAX_FOLDER_DEPTH} folders deep; compare a part of it."
                    )));
                }
                queue.push_back((join(&folder, &entry.name), path, depth + 1));
            }
            if found.len() > MAX_UPLOAD_FILES {
                return Err(CoreError::InvalidInput(format!(
                    "{root} holds more than {MAX_UPLOAD_FILES} files and folders; compare a part of it."
                )));
            }
        }
    }
    Ok((found, left_out))
}

/// How two sides of a path compare, before any content check.
pub fn compare_pair(path: &str, here: Option<SideInfo>, there: Option<SideInfo>) -> DiffRow {
    let mut row = DiffRow {
        path: path.to_owned(),
        here,
        there,
        state: RowState::Same,
        newer: None,
        larger: None,
        same_content: None,
    };
    match (here, there) {
        (Some(_), None) => row.state = RowState::OnlyHere,
        (None, Some(_)) => row.state = RowState::OnlyThere,
        (None, None) => {}
        (Some(h), Some(t)) if h.folder != t.folder => row.state = RowState::Conflict,
        (Some(h), Some(_)) if h.folder => {}
        (Some(h), Some(t)) => {
            row.newer = match (h.modified, t.modified) {
                (Some(a), Some(b)) if a > b + TIME_SLACK => Some(Side::Here),
                (Some(a), Some(b)) if b > a + TIME_SLACK => Some(Side::There),
                _ => None,
            };
            row.larger = match h.size.cmp(&t.size) {
                std::cmp::Ordering::Greater => Some(Side::Here),
                std::cmp::Ordering::Less => Some(Side::There),
                std::cmp::Ordering::Equal => None,
            };
            if row.newer.is_some() || row.larger.is_some() {
                row.state = RowState::Differs;
            }
        }
    }
    row
}

/// A file's row once its contents were compared: the same bytes are the same file, whatever the times say.
fn with_content(mut row: DiffRow, same: bool) -> DiffRow {
    row.same_content = Some(same);
    row.state = if same { RowState::Same } else { RowState::Differs };
    row
}

/// Whether a row goes in a sync that way (a folder's row: what is in it decides).
fn goes(row: &DiffRow, direction: SyncDirection) -> bool {
    match (direction, row.state) {
        (_, RowState::Same | RowState::Conflict) => false,
        (SyncDirection::ToHost, RowState::OnlyHere) | (SyncDirection::ToPc, RowState::OnlyThere) => true,
        (SyncDirection::ToHost, RowState::OnlyThere) | (SyncDirection::ToPc, RowState::OnlyHere) => false,
        (_, RowState::Differs) => true,
    }
}

/// `path` with every folder above it, the top one first.
fn ancestors(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').collect();
    (1..parts.len()).map(|n| parts[..n].join("/")).collect()
}

impl FolderSyncs {
    pub fn new(
        workspace: crate::workspaces::Current,
        terminals: Terminals,
        bus: Arc<CommandBus>,
        local: LocalFiles,
    ) -> Self {
        Self {
            workspace,
            terminals,
            bus,
            local,
            kept: Mutex::default(),
        }
    }

    /// The host's SHA-256 of a file within `limit`: its own `sha256sum`, else read over SFTP (capped).
    async fn host_hash(
        &self,
        request: &CompareRequest,
        files: &Arc<dyn RemoteFiles>,
        path: &str,
        size: u64,
        limit: Duration,
    ) -> Result<HostHash> {
        let (control, _) = self.terminals.files_for(request.terminal_id, request.as_root)?;
        self.terminals
            .hash_host_file(&control, files.as_ref(), path, size, request.as_root, limit)
            .await
    }

    /// SS-14: compares the local pane's folder with the host's (see the module's notes).
    pub async fn compare(&self, request: CompareRequest) -> Result<Comparison> {
        check_path(&request.host_folder)?;
        let local = self.local.folder_of(request.listing)?;
        let (_, files) = self.terminals.files_for(request.terminal_id, request.as_root)?;
        match files.stat(&request.host_folder).await? {
            Some(entry) if entry.kind == EntryKind::Folder => {}
            Some(_) => {
                return Err(CoreError::InvalidInput(format!(
                    "{} is not a folder on the host.",
                    request.host_folder
                )))
            }
            None => {
                return Err(CoreError::RemoteNotFound {
                    path: request.host_folder.clone(),
                })
            }
        }
        let root = local.clone();
        let (here, left_here) = tokio::task::spawn_blocking(move || walk_local_tree(&root))
            .await
            .map_err(|err| CoreError::InvalidInput(format!("the comparison stopped: {err}")))??;
        let (there, left_there) = walk_host_tree(files.as_ref(), &request.host_folder).await?;
        let paths: BTreeSet<&String> = here.keys().chain(there.keys()).collect();
        let mut rows: Vec<DiffRow> = paths
            .into_iter()
            .map(|p| compare_pair(p, here.get(p).copied(), there.get(p).copied()))
            .collect();
        let mut contents_capped = false;
        let mut contents_compared = 0;
        let mut contents_unread = 0;
        if request.contents {
            let deadline = Instant::now() + Duration::from_secs(CONTENT_SECONDS);
            let mut hashed = 0;
            for row in &mut rows {
                let (Some(h), Some(t)) = (row.here, row.there) else {
                    continue;
                };
                if h.folder || t.folder || h.size != t.size {
                    continue;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if hashed >= MAX_CONTENT_FILES || left.is_zero() {
                    contents_capped = true;
                    break;
                }
                hashed += 1;
                let limit = left.min(Duration::from_secs(HASH_SECONDS));
                let theirs = self
                    .host_hash(&request, &files, &join(&request.host_folder, &row.path), t.size, limit)
                    .await?;
                let HostHash::Done { sha256: theirs, .. } = theirs else {
                    // Too large to read over SFTP, or out of time: this pair keeps its size and time verdict.
                    contents_unread += 1;
                    continue;
                };
                let local_file = row.path.split('/').fold(local.clone(), |at, part| at.join(part));
                let mine = tokio::task::spawn_blocking(move || crate::local_files::file_sha256(&local_file))
                    .await
                    .map_err(|err| CoreError::InvalidInput(format!("the comparison stopped: {err}")))??;
                contents_compared += 1;
                *row = with_content(row.clone(), mine == theirs);
            }
        }
        let mut counts = CompareCounts::default();
        for row in &rows {
            match row.state {
                RowState::Same => counts.same += 1,
                RowState::OnlyHere => counts.only_here += 1,
                RowState::OnlyThere => counts.only_there += 1,
                RowState::Differs => counts.differs += 1,
                RowState::Conflict => counts.conflicts += 1,
            }
        }
        let id = Uuid::new_v4();
        let kept_rows: BTreeMap<String, DiffRow> = rows.iter().map(|r| (r.path.clone(), r.clone())).collect();
        {
            let mut kept = locks::lock(&self.kept);
            kept.retain(|_, k| k.at.elapsed() < KEEP_FOR);
            while kept.len() >= KEEP {
                let Some(oldest) = kept.iter().min_by_key(|(_, k)| k.at).map(|(id, _)| *id) else {
                    break;
                };
                kept.remove(&oldest);
            }
            kept.insert(
                id,
                Kept {
                    terminal_id: request.terminal_id,
                    as_root: request.as_root,
                    local: local.clone(),
                    host: request.host_folder.clone(),
                    rows: kept_rows,
                    at: Instant::now(),
                },
            );
        }
        // Folders the same on both sides say nothing; files the same are counted.
        rows.retain(|r| r.state != RowState::Same);
        Ok(Comparison {
            id,
            local: local.display().to_string(),
            host: request.host_folder,
            terminal_id: request.terminal_id,
            as_root: request.as_root,
            contents: request.contents,
            rows,
            counts,
            left_out: left_here + left_there,
            contents_capped,
            contents_compared,
            contents_unread,
        })
    }

    /// SS-14: syncs the picked rows of a comparison one way (see the module's notes).
    pub async fn sync(&self, request: SyncRequest) -> Result<SyncStart> {
        let (terminal_id, as_root, local, host, rows) = {
            let kept = locks::lock(&self.kept);
            let k = kept.get(&request.comparison).ok_or_else(|| {
                CoreError::InvalidInput("That comparison is no longer kept; compare the folders again.".into())
            })?;
            (
                k.terminal_id,
                k.as_root,
                k.local.clone(),
                k.host.clone(),
                k.rows.clone(),
            )
        };
        if request.paths.is_empty() {
            return Err(CoreError::InvalidInput("Pick what to sync.".into()));
        }
        // Each path picked is a row; a folder takes the rows under it.
        let mut picked: BTreeMap<String, DiffRow> = BTreeMap::new();
        for path in &request.paths {
            let row = rows
                .get(path)
                .ok_or_else(|| CoreError::InvalidInput(format!("'{path}' is not part of that comparison.")))?;
            picked.insert(path.clone(), row.clone());
            let inside = format!("{path}/");
            for (p, r) in rows.range(inside.clone()..) {
                if !p.starts_with(&inside) {
                    break;
                }
                picked.insert(p.clone(), r.clone());
            }
        }
        match request.direction {
            SyncDirection::ToHost => {
                self.to_host(terminal_id, as_root, &local, &host, picked, request.delete)
                    .await
            }
            SyncDirection::ToPc => self.to_pc(terminal_id, as_root, &local, &host, picked).await,
        }
    }

    async fn to_host(
        &self,
        terminal_id: Uuid,
        as_root: bool,
        local: &Path,
        host: &str,
        picked: BTreeMap<String, DiffRow>,
        delete: bool,
    ) -> Result<SyncStart> {
        let mut files = Vec::new();
        let mut folders: BTreeSet<String> = BTreeSet::new();
        let mut deletes: Vec<String> = Vec::new();
        for (path, row) in &picked {
            if row.state == RowState::OnlyThere {
                if delete {
                    deletes.push(path.clone());
                }
                continue;
            }
            if !goes(row, SyncDirection::ToHost) {
                continue;
            }
            let Some(here) = row.here else { continue };
            for above in ancestors(path) {
                folders.insert(above);
            }
            if here.folder {
                folders.insert(path.clone());
                continue;
            }
            let local_path = path.split('/').fold(local.to_owned(), |at, part| at.join(part));
            let meta = std::fs::metadata(&local_path).map_err(|err| {
                CoreError::InvalidInput(format!("'{}' can't be read any more: {err}", local_path.display()))
            })?;
            files.push(UploadFile {
                local_path: local_path.display().to_string(),
                name: path.clone(),
                size: meta.len(),
                replace: row.there.is_some(),
                modified: meta
                    .modified()
                    .ok()
                    .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            });
        }
        // A folder deleted takes what is in it, so nothing inside it is named again.
        let whole: BTreeSet<String> = deletes.iter().cloned().collect();
        deletes.retain(|d| !ancestors(d).iter().any(|a| whole.contains(a)));
        if files.is_empty() && folders.is_empty() && deletes.is_empty() {
            return Ok(SyncStart::Nothing);
        }
        // Parents first.
        let mut folders: Vec<String> = folders.into_iter().collect();
        folders.sort_by_key(|f| (f.matches('/').count(), f.clone()));
        let ctx = self.workspace.get();
        let target = self.terminals.target(&ctx, terminal_id).await?;
        let command = Command::FileUpload {
            targets: vec![target.target],
            folder: host.to_owned(),
            files,
            folders,
            keep_times: true,
            as_root,
            delete: deletes,
        };
        let outcome = self.bus.submit(&ctx, command).await?;
        Ok(SyncStart::Submitted {
            outcome: Box::new(outcome),
        })
    }

    async fn to_pc(
        &self,
        terminal_id: Uuid,
        as_root: bool,
        local: &Path,
        host: &str,
        picked: BTreeMap<String, DiffRow>,
    ) -> Result<SyncStart> {
        let mut found = Vec::new();
        let mut folders: BTreeSet<String> = BTreeSet::new();
        for (path, row) in &picked {
            if !goes(row, SyncDirection::ToPc) {
                continue;
            }
            let Some(there) = row.there else { continue };
            for above in ancestors(path) {
                folders.insert(above);
            }
            if there.folder {
                folders.insert(path.clone());
                continue;
            }
            let name = path.rsplit('/').next().unwrap_or(path).to_owned();
            found.push((
                join(host, path),
                path.clone(),
                RemoteEntry {
                    name,
                    kind: EntryKind::File,
                    link: false,
                    size: there.size,
                    modified: there.modified,
                    mode: None,
                    uid: None,
                    gid: None,
                },
            ));
        }
        if found.is_empty() && folders.is_empty() {
            return Ok(SyncStart::Nothing);
        }
        let mut folders: Vec<String> = folders.into_iter().collect();
        folders.sort_by_key(|f| (f.matches('/').count(), f.clone()));
        let ctx = self.workspace.get();
        let (control, _) = self.terminals.files_for(terminal_id, as_root)?;
        let options = DownloadOptions {
            existing: Existing::Replace,
            as_root,
        };
        let start = self
            .terminals
            .land_downloads(&ctx, &control, local, found, folders, 0, options)
            .await?;
        Ok(SyncStart::Downloads { start })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(size: u64, modified: u64) -> Option<SideInfo> {
        Some(SideInfo {
            folder: false,
            size,
            modified: Some(modified),
        })
    }

    #[test]
    fn pairs_compare_by_presence_time_and_size() {
        assert_eq!(compare_pair("a", file(1, 10), None).state, RowState::OnlyHere);
        assert_eq!(compare_pair("a", None, file(1, 10)).state, RowState::OnlyThere);
        assert_eq!(
            compare_pair("a", file(5, 100), file(5, 101)).state,
            RowState::Same,
            "within the slack"
        );
        let newer = compare_pair("a", file(5, 200), file(5, 100));
        assert_eq!(
            (newer.state, newer.newer, newer.larger),
            (RowState::Differs, Some(Side::Here), None)
        );
        let larger = compare_pair("a", file(4, 100), file(9, 100));
        assert_eq!(larger.larger, Some(Side::There));
        let folder = Some(SideInfo {
            folder: true,
            size: 0,
            modified: Some(1),
        });
        assert_eq!(compare_pair("a", folder, file(1, 1)).state, RowState::Conflict);
        assert_eq!(compare_pair("a", folder, folder).state, RowState::Same);
        // Contents decide over the times.
        assert_eq!(with_content(newer.clone(), true).state, RowState::Same);
        assert_eq!(
            with_content(compare_pair("a", file(5, 1), file(5, 1)), false).state,
            RowState::Differs
        );
    }

    #[test]
    fn each_direction_takes_its_own_rows() {
        let only_here = compare_pair("a", file(1, 1), None);
        let only_there = compare_pair("b", None, file(1, 1));
        let differs = compare_pair("c", file(1, 1), file(2, 1));
        assert!(goes(&only_here, SyncDirection::ToHost) && !goes(&only_here, SyncDirection::ToPc));
        assert!(goes(&only_there, SyncDirection::ToPc) && !goes(&only_there, SyncDirection::ToHost));
        assert!(goes(&differs, SyncDirection::ToHost) && goes(&differs, SyncDirection::ToPc));
        assert_eq!(ancestors("a/b/c.txt"), vec!["a", "a/b"]);
        assert!(ancestors("c.txt").is_empty());
    }

    #[test]
    fn a_local_tree_leaves_out_git_and_links() {
        let root = std::env::temp_dir().join(format!("remotely-sync-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("site/.git")).unwrap();
        std::fs::create_dir_all(root.join("site/css")).unwrap();
        std::fs::write(root.join("site/index.html"), b"<p>hi</p>").unwrap();
        std::fs::write(root.join("site/.git/HEAD"), b"ref").unwrap();
        let (found, left_out) = walk_local_tree(&root).unwrap();
        let paths: Vec<&str> = found.keys().map(String::as_str).collect();
        assert_eq!(paths, vec!["site", "site/css", "site/index.html"]);
        assert_eq!(left_out, 1);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn a_host_tree_leaves_out_names_windows_would_save_as_git() {
        let files = crate::fakes::FakeFiles::default()
            .with_dir("/srv/site")
            .with_file("/srv/site/index.html", b"<p>hi</p>")
            .with_dir("/srv/site/.git.")
            .with_file("/srv/site/.git./HEAD", b"ref: refs/heads/main\n")
            .with_dir("/srv/site/.git./hooks")
            .with_file("/srv/site/.git./hooks/post-checkout", b"#!/bin/sh\n")
            .with_dir("/srv/site/.git ")
            .with_file("/srv/site/.git /config", b"[core]\n")
            .with_dir("/srv/site/css")
            .with_dir("/srv/site/css/.GIT.")
            .with_file("/srv/site/css/.GIT./HEAD", b"ref\n")
            .with_file("/srv/site/.gitignore", b"*.log\n");
        let (found, left_out) = walk_host_tree(&files, "/srv/site").await.unwrap();
        let paths: Vec<&str> = found.keys().map(String::as_str).collect();
        assert_eq!(paths, vec![".gitignore", "css", "index.html"]);
        assert_eq!(left_out, 3, "each folder Git would take is counted once");
    }
}
