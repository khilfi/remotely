//! SS-14, BX-10 (0.8.0 G3): the Files page's IPC. The logic is in `remotely_core` (`local_files`, `bookmarks`,
//! `terminal::file_reads`, `terminal::sync`, `bulk_files`); this is the IPC around it.
//!
//! No path on this PC comes from the window unchecked: the local pane names files by its listing's id and their names
//! there (the core kept what it listed), a typed folder goes through the core's checks, and files from Explorer still
//! arrive as `files://dropped` (`files::dropped`), staged in the core. The Home and Downloads folders are the shell's.

use remotely_core::bookmarks::Bookmark;
use remotely_core::bulk::TargetPicks;
use remotely_core::bulk_files::BulkFilesStart;
use remotely_core::local_files::{LocalAsk, LocalListing};
use remotely_core::terminal::file_reads::{FileChecksum, FilePreview, FindRequest, FindResult};
use remotely_core::terminal::files::{
    DownloadDest, DownloadOptions, DownloadStart, Existing, StagedFiles, UploadStart,
};
use remotely_core::terminal::sync::{CompareRequest, Comparison, SyncRequest, SyncStart};
use remotely_core::CoreError;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

fn home_and_downloads(window: &WebviewWindow) -> IpcResult<(std::path::PathBuf, std::path::PathBuf)> {
    let home = window
        .path()
        .home_dir()
        .map_err(|err| CoreError::InvalidInput(format!("the home folder can't be found: {err}")))?;
    let downloads = window.path().download_dir().unwrap_or_else(|_| home.join("Downloads"));
    Ok((home, downloads))
}

/// SS-14: a folder of this PC for the local pane (Home, Downloads, the drives, a typed path, or one by its listing).
#[tauri::command]
pub async fn files_local_list(
    window: WebviewWindow,
    state: State<'_, AppState>,
    ask: LocalAsk,
) -> IpcResult<LocalListing> {
    let (home, downloads) = home_and_downloads(&window)?;
    let local = state.core.local_files.clone();
    // Reading a folder of thousands, or a slow drive, stays off the window's thread.
    let listing = tauri::async_runtime::spawn_blocking(move || local.list(ask, &home, &downloads))
        .await
        .map_err(|err| CoreError::InvalidInput(format!("the folder could not be read: {err}")))??;
    Ok(listing)
}

/// SS-14: a local file's SHA-256, by its listing and name.
#[tauri::command]
pub async fn files_local_checksum(state: State<'_, AppState>, listing: Uuid, name: String) -> IpcResult<String> {
    Ok(state.core.local_files.sha256(listing, &name).await?)
}

/// SS-14: files picked in the local pane staged for an upload, and the upload asked for (conflicts come back to be
/// answered with `files_upload` and the staged id, as for a dialog's files).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalUpload {
    staged: StagedFiles,
    start: UploadStart,
}

#[tauri::command]
pub async fn files_local_upload(
    state: State<'_, AppState>,
    id: Uuid,
    listing: Uuid,
    names: Vec<String>,
    folder: String,
    as_root: Option<bool>,
) -> IpcResult<LocalUpload> {
    let core = &state.core;
    let paths = core.local_files.paths_of(listing, &names)?;
    let staged = core.files.stage(paths)?;
    let start = match core
        .files
        .upload_as(id, staged.id, &folder, Existing::Ask, as_root.unwrap_or(false))
        .await
    {
        Ok(start) => start,
        Err(err) => {
            core.files.unstage(staged.id);
            return Err(err.into());
        }
    };
    Ok(LocalUpload { staged, start })
}

/// SS-14: downloads host files into the local pane's folder (by its listing); `choice` answers a conflict question.
#[tauri::command]
pub async fn files_download_here(
    state: State<'_, AppState>,
    id: Uuid,
    paths: Vec<String>,
    listing: Uuid,
    existing: Option<Existing>,
    as_root: Option<bool>,
    choice: Option<Uuid>,
) -> IpcResult<DownloadStart> {
    let core = &state.core;
    let options = DownloadOptions {
        existing: existing.unwrap_or(Existing::Ask),
        as_root: as_root.unwrap_or(false),
    };
    let dest = match choice {
        Some(choice) => DownloadDest::Chosen(choice),
        None => DownloadDest::Folder(core.local_files.folder_of(listing)?),
    };
    Ok(core.files.download(id, &paths, dest, options).await?)
}

/// SS-14: files under a host folder by a name pattern (a read).
#[tauri::command]
pub async fn files_find(state: State<'_, AppState>, id: Uuid, request: FindRequest) -> IpcResult<FindResult> {
    Ok(state.core.terminals.find(id, request).await?)
}

/// SS-14: the first bytes of a host file as text (a read).
#[tauri::command]
pub async fn files_preview(
    state: State<'_, AppState>,
    id: Uuid,
    path: String,
    as_root: Option<bool>,
) -> IpcResult<FilePreview> {
    Ok(state
        .core
        .terminals
        .preview(id, &path, as_root.unwrap_or(false))
        .await?)
}

/// SS-14: a host file's SHA-256 (a read).
#[tauri::command]
pub async fn files_checksum(
    state: State<'_, AppState>,
    id: Uuid,
    path: String,
    as_root: Option<bool>,
) -> IpcResult<FileChecksum> {
    Ok(state
        .core
        .terminals
        .checksum(id, &path, as_root.unwrap_or(false))
        .await?)
}

/// SS-14: a session's bookmarks.
#[tauri::command]
pub async fn files_bookmarks(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<Vec<Bookmark>> {
    let core = &state.core;
    Ok(core.bookmarks.list(&core.ctx(), session_id).await?)
}

#[tauri::command]
pub async fn files_bookmark_add(
    state: State<'_, AppState>,
    session_id: Uuid,
    name: String,
    path: String,
) -> IpcResult<Bookmark> {
    let core = &state.core;
    Ok(core.bookmarks.add(&core.ctx(), session_id, &name, &path).await?)
}

#[tauri::command]
pub async fn files_bookmark_rename(state: State<'_, AppState>, id: Uuid, name: String) -> IpcResult<Bookmark> {
    let core = &state.core;
    Ok(core.bookmarks.rename(&core.ctx(), id, &name).await?)
}

#[tauri::command]
pub async fn files_bookmark_remove(state: State<'_, AppState>, id: Uuid) -> IpcResult<bool> {
    let core = &state.core;
    Ok(core.bookmarks.remove(&core.ctx(), id).await?)
}

/// SS-14: compares the local pane's folder with a host folder (a read).
#[tauri::command]
pub async fn files_compare(state: State<'_, AppState>, request: CompareRequest) -> IpcResult<Comparison> {
    Ok(state.core.sync.compare(request).await?)
}

/// SS-14: syncs a comparison's picked rows one way: to the host on the bus, to this PC as downloads.
#[tauri::command]
pub async fn files_sync(state: State<'_, AppState>, request: SyncRequest) -> IpcResult<SyncStart> {
    Ok(state.core.sync.sync(request).await?)
}

/// BX-10: where a push's files come from: staged (a dialog, a drop) or the local pane's picks.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PushFrom {
    Staged { id: Uuid },
    Local { listing: Uuid, names: Vec<String> },
}

/// BX-10: pushes files of this PC into a folder on every picked host, through the bus.
#[tauri::command]
pub async fn files_push(
    state: State<'_, AppState>,
    picks: TargetPicks,
    from: PushFrom,
    folder: String,
    replace: bool,
    trust_new_host_keys: Option<bool>,
) -> IpcResult<BulkFilesStart> {
    let core = &state.core;
    let paths = match from {
        PushFrom::Staged { id } => core.files.take_staged(id)?,
        PushFrom::Local { listing, names } => core.local_files.paths_of(listing, &names)?,
    };
    Ok(core
        .bulk_files
        .push(&picks, paths, &folder, replace, trust_new_host_keys.unwrap_or(false))
        .await?)
}

/// BX-10: where a fetch's files go: the local pane's folder, or one picked in a dialog opened here.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum FetchTo {
    Local { listing: Uuid },
    Choose,
}

/// BX-10: fetches the same file from every picked host into a folder of this PC, through the bus. `None` when the
/// folder dialog was closed.
#[tauri::command]
pub async fn files_fetch(
    window: WebviewWindow,
    state: State<'_, AppState>,
    picks: TargetPicks,
    path: String,
    to: FetchTo,
    trust_new_host_keys: Option<bool>,
) -> IpcResult<Option<BulkFilesStart>> {
    let core = &state.core;
    let dest = match to {
        FetchTo::Local { listing } => core.local_files.folder_of(listing)?,
        FetchTo::Choose => {
            let (_, downloads) = home_and_downloads(&window)?;
            let (tx, rx) = tokio::sync::oneshot::channel();
            window
                .dialog()
                .file()
                .set_parent(&window)
                .set_title("Fetch into this folder (each host's file in a folder of its own)")
                .set_directory(downloads)
                .pick_folder(move |path| {
                    let _ = tx.send(path);
                });
            let Some(path) = rx.await.ok().flatten() else {
                return Ok(None);
            };
            path.into_path()
                .map_err(|err| CoreError::InvalidInput(format!("can't save there: {err}")))?
        }
    };
    Ok(Some(
        core.bulk_files
            .fetch(&picks, &path, &dest, trust_new_host_keys.unwrap_or(false))
            .await?,
    ))
}

/// BX-10: asks for files to push (a dialog opened here) and stages them. `None` when the dialog was closed.
#[tauri::command]
pub async fn files_pick_push(window: WebviewWindow, state: State<'_, AppState>) -> IpcResult<Option<StagedFiles>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Push files to the picked hosts")
        .pick_files(move |paths| {
            let _ = tx.send(paths);
        });
    let Some(paths) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let paths = paths
        .into_iter()
        .map(|p| {
            p.into_path()
                .map_err(|err| CoreError::InvalidInput(format!("can't read that file: {err}")))
        })
        .collect::<Result<Vec<_>, CoreError>>()?;
    Ok(Some(state.core.files.stage(paths)?))
}
