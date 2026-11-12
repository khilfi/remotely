//! SS-08 file transfer in the terminal (post-MVP P7): the "Files here" drawer, downloads, uploads and
//! the transfers panel. The logic is in `remotely_core::terminal::files`; this is the IPC around it.
//!
//! No path on this PC comes from the UI. Uploads take files picked in a dialog opened here, or dropped
//! on the window (caught in [`dropped`] and staged in the core; the UI gets a staged id and decides
//! which terminal it was dropped on). Downloads go to the Downloads folder or to a folder picked in a
//! dialog opened here. "Open folder" opens Explorer on a finished download by its transfer id.
//! Transfers reach the UI as `files://transfer` events, drops as `files://dropped`.

use std::path::PathBuf;

use remotely_core::adapters::remote::RemoteEntry;
use remotely_core::command_bus::SubmitOutcome;
use remotely_core::terminal::file_ops::FileChange;
use remotely_core::terminal::files::{
    DownloadDest, DownloadOptions, DownloadStart, Existing, FolderListing, Retried, StagedFiles, TransferInfo,
    UploadStart,
};
use remotely_core::terminal::folder::FolderInfo;
use remotely_core::terminal::root_files::{RootBrowsing, RootRequest};
use remotely_core::vault::{SecretId, SecretString};
use remotely_core::CoreError;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State, WebviewWindow, Window};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// SS-08: the shell's folder, as far as it is known.
#[tauri::command]
pub fn files_folder(state: State<'_, AppState>, id: Uuid) -> Option<FolderInfo> {
    state.core.terminals.folder(id)
}

/// SS-08: a folder on the terminal's host; without `path`, the shell's folder (or the home folder).
/// QL-09: a relative `path` goes on from `from`, the folder the drawer shows; a folder that can't be
/// opened comes back with its path and the reason.
#[tauri::command]
pub async fn files_list(
    state: State<'_, AppState>,
    id: Uuid,
    path: Option<String>,
    from: Option<String>,
    as_root: Option<bool>,
) -> IpcResult<FolderListing> {
    Ok(state
        .core
        .terminals
        .open_folder_as(id, path.as_deref(), from.as_deref(), as_root.unwrap_or(false))
        .await?)
}

/// QL-09: the drawer's Back from the folder it shows.
#[tauri::command]
pub async fn files_back(
    state: State<'_, AppState>,
    id: Uuid,
    from: String,
    as_root: Option<bool>,
) -> IpcResult<FolderListing> {
    Ok(state
        .core
        .terminals
        .folder_back_as(id, &from, as_root.unwrap_or(false))
        .await?)
}

/// SS-14: a change to files on the terminal's host (rename, move, copy, delete, new folder or file, permissions,
/// owner), through the command bus: queued (Low) or waiting for the approval dialog. The core checks every path.
#[tauri::command]
pub async fn files_change(
    state: State<'_, AppState>,
    id: Uuid,
    change: FileChange,
    as_root: bool,
) -> IpcResult<SubmitOutcome> {
    Ok(state.core.files.change(id, change, as_root).await?)
}

/// SS-14: starts browsing the terminal's host as root (its sftp-server under sudo). `reauth_required` when a vault
/// password would go to sudo somewhere it doesn't go yet; `login_parked` after sudo refused it, until `retry`.
#[tauri::command]
pub async fn files_root_start(
    state: State<'_, AppState>,
    id: Uuid,
    sudo_password_id: Option<SecretId>,
    vault_password: Option<SecretString>,
    retry: Option<bool>,
) -> IpcResult<RootBrowsing> {
    let core = &state.core;
    let request = RootRequest {
        sudo_password_id,
        vault_password,
        retry: retry.unwrap_or(false),
    };
    Ok(core.terminals.browse_as_root(&core.ctx(), id, request).await?)
}

/// SS-14: ends root browsing on the terminal; false when it wasn't on.
#[tauri::command]
pub async fn files_root_stop(state: State<'_, AppState>, id: Uuid) -> IpcResult<bool> {
    let core = &state.core;
    Ok(core.terminals.stop_root(&core.ctx(), id).await?)
}

/// SS-14: whether the terminal browses as root now.
#[tauri::command]
pub fn files_root_status(state: State<'_, AppState>, id: Uuid) -> Option<RootBrowsing> {
    state.core.terminals.root_browsing(id)
}

/// SS-14: pauses a transfer (it stops after its current chunk); false when there was none to pause.
#[tauri::command]
pub fn files_pause(state: State<'_, AppState>, transfer_id: Uuid) -> bool {
    state.core.terminals.pause_transfer(transfer_id)
}

/// SS-14: a paused transfer goes on from where it stopped.
#[tauri::command]
pub fn files_resume(state: State<'_, AppState>, transfer_id: Uuid) -> bool {
    state.core.terminals.resume_transfer(transfer_id)
}

/// SS-14: asks for a folder to upload with what is in it (a dialog opened here) and stages it. `None` when the user
/// closed the dialog.
#[tauri::command]
pub async fn files_pick_upload_folder(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> IpcResult<Option<StagedFiles>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Upload a folder to the terminal's folder")
        .pick_folder(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't read that folder: {err}")))?;
    Ok(Some(state.core.files.stage(vec![path])?))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LookedUp {
    /// The full host path.
    path: String,
    entry: RemoteEntry,
}

/// SS-08: a file name right-clicked in the terminal's output: what it is, from the shell's folder.
#[tauri::command]
pub async fn files_look_up(state: State<'_, AppState>, id: Uuid, path: String) -> IpcResult<Option<LookedUp>> {
    let found = state.core.terminals.look_up(id, &path).await?;
    Ok(found.map(|(path, entry)| LookedUp { path, entry }))
}

/// SS-08: asks for files to upload (a dialog opened here) and stages them. `None` when the user
/// closed the dialog.
#[tauri::command]
pub async fn files_pick_upload(window: WebviewWindow, state: State<'_, AppState>) -> IpcResult<Option<StagedFiles>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Upload files to the terminal's folder")
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
        .collect::<Result<Vec<PathBuf>, CoreError>>()?;
    Ok(Some(state.core.files.stage(paths)?))
}

/// SS-08: uploads staged files into `folder` on the terminal's host, through the command bus. With
/// `existing: "ask"`, files already there come back as conflicts and nothing is submitted.
#[tauri::command]
pub async fn files_upload(
    state: State<'_, AppState>,
    id: Uuid,
    staged_id: Uuid,
    folder: String,
    existing: Existing,
    as_root: Option<bool>,
) -> IpcResult<UploadStart> {
    Ok(state
        .core
        .files
        .upload_as(id, staged_id, &folder, existing, as_root.unwrap_or(false))
        .await?)
}

/// SS-08: staged files that will not be uploaded (dropped beside the terminals, or the question closed).
#[tauri::command]
pub fn files_unstage(state: State<'_, AppState>, staged_id: Uuid) {
    state.core.files.unstage(staged_id);
}

/// Where a download goes.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DownloadTo {
    Downloads,
    /// A folder picked in a dialog opened here.
    Choose,
}

/// SS-08: downloads files (SS-14: and folders with what is in them) from the terminal's host (paths absolute, or from
/// the shell's folder). `None` when the user closed the folder dialog. SS-14: `existing` says what to do with a file
/// that is there on this PC (by default a number is added); as root when `as_root`; `choice` answers a conflict
/// question, into the folder it was about.
// Tauri passes each argument by name, as the UI sends them.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn files_download(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: Uuid,
    paths: Vec<String>,
    to: DownloadTo,
    existing: Option<Existing>,
    as_root: Option<bool>,
    choice: Option<Uuid>,
) -> IpcResult<Option<DownloadStart>> {
    let options = DownloadOptions {
        existing: existing.unwrap_or(Existing::KeepBoth),
        as_root: as_root.unwrap_or(false),
    };
    // SS-14: the answer to a conflict question goes to the folder it was about, which the core kept.
    if let Some(choice) = choice {
        return Ok(Some(
            state
                .core
                .files
                .download(id, &paths, DownloadDest::Chosen(choice), options)
                .await?,
        ));
    }
    let downloads = window
        .path()
        .download_dir()
        .map_err(|err| CoreError::InvalidInput(format!("the Downloads folder can't be found: {err}")))?;
    let dest = match to {
        DownloadTo::Downloads => downloads,
        DownloadTo::Choose => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            window
                .dialog()
                .file()
                .set_parent(&window)
                .set_title("Download to this folder")
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
        state
            .core
            .files
            .download(id, &paths, DownloadDest::Folder(dest), options)
            .await?,
    ))
}

/// SS-08: every transfer the panel shows, newest last.
#[tauri::command]
pub fn files_transfers(state: State<'_, AppState>) -> Vec<TransferInfo> {
    state.core.terminals.transfers()
}

/// SS-08: stops a transfer; false when it had finished.
#[tauri::command]
pub fn files_cancel(state: State<'_, AppState>, transfer_id: Uuid) -> bool {
    state.core.terminals.cancel_transfer(transfer_id)
}

/// SS-08: runs a finished transfer again (an upload through the bus again).
#[tauri::command]
pub async fn files_retry(state: State<'_, AppState>, transfer_id: Uuid) -> IpcResult<Retried> {
    Ok(state.core.files.retry(transfer_id).await?)
}

/// SS-08: opens Explorer at a finished download, with the file selected.
#[tauri::command]
pub fn files_open_folder(state: State<'_, AppState>, transfer_id: Uuid) -> IpcResult<()> {
    let path = state
        .core
        .files
        .saved_at(transfer_id)
        .ok_or_else(|| CoreError::InvalidInput("That download has not finished.".into()))?;
    reveal(&path)
}

/// Explorer at a file this PC saved, with the file selected (FD-04 reuses it for a support bundle).
#[cfg(windows)]
pub(crate) fn reveal(path: &std::path::Path) -> IpcResult<()> {
    use std::os::windows::process::CommandExt;
    // Explorer reads `/select,"path"` itself; Rust's own quoting would wrap the whole argument.
    std::process::Command::new("explorer.exe")
        .raw_arg(format!("/select,\"{}\"", path.display()))
        .spawn()
        .map(drop)
        .map_err(|err| IpcError::new("io", format!("Explorer did not open: {err}")))
}

#[cfg(not(windows))]
pub(crate) fn reveal(_path: &std::path::Path) -> IpcResult<()> {
    Err(IpcError::new("unsupported", "Opening a folder needs Windows."))
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Dropped {
    /// The staged files, or why they could not be (a folder, two of one name).
    staged: Option<StagedFiles>,
    error: Option<String>,
    /// Where they were dropped, in CSS pixels of the window.
    x: f64,
    y: f64,
}

/// SS-08: files dropped on the window are staged here, so their paths never pass through the UI;
/// the UI hears where they fell and which staged id to upload.
pub fn dropped(window: &Window, paths: &[PathBuf], position: tauri::PhysicalPosition<f64>) {
    let Some(state) = window.try_state::<AppState>() else {
        return;
    };
    let scale = window.scale_factor().unwrap_or(1.0);
    let at = position.to_logical::<f64>(scale);
    let (staged, error) = match state.core.files.stage(paths.to_vec()) {
        Ok(staged) => (Some(staged), None),
        Err(err) => (None, Some(err.to_string())),
    };
    let _ = window.emit(
        "files://dropped",
        Dropped {
            staged,
            error,
            x: at.x,
            y: at.y,
        },
    );
}
