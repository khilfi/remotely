//! FD-09: the Toolbox's File server tab. The logic is in `remotely_core::toolbox::file_server`; this is the IPC around
//! it and the dialogs that choose what is served and where uploads go.
//!
//! * Starting is a command on the bus that the core builds after checking the folders and the address
//!   (`file_server_start`): Medium serving, High with uploads; the approval dialog answers it like any other.
//! * Stop, the status (the running server, or the last one in this workspace) and `fileserver://event` (started,
//!   requests came in, stopped), only for the shown workspace's server.
//! * A window reload stops the server (`Core::release_ui`), and so do a workspace switch, the vault locking and the
//!   app closing (`Core::shutdown`).

use std::path::PathBuf;
use std::sync::Arc;

use remotely_core::command_bus::SubmitOutcome;
use remotely_core::toolbox::file_server::{FileServerOptions, FileServerSpec, ServerStatus};
use remotely_core::{Core, CoreError};
use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// What a dialog chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PickFor {
    /// A folder to serve.
    Folder,
    /// One file to serve.
    File,
    /// The empty folder uploads go into.
    Uploads,
}

/// This PC's addresses, the last choices in this workspace and the server's status. A read.
#[tauri::command]
pub async fn file_server_options(state: State<'_, AppState>) -> IpcResult<FileServerOptions> {
    let core = &state.core;
    Ok(core.file_server.options(&core.ctx()).await?)
}

/// The running server, or the one that stopped last in this workspace. A read.
#[tauri::command]
pub fn file_server_status(state: State<'_, AppState>) -> Option<ServerStatus> {
    let core = &state.core;
    core.file_server.status(&core.ctx())
}

/// Asks for a file or folder (Downloads by default, or where the last choice was). `None` when the dialog was closed.
#[tauri::command]
pub async fn file_server_pick(
    window: WebviewWindow,
    purpose: PickFor,
    current: Option<String>,
) -> IpcResult<Option<String>> {
    let title = match purpose {
        PickFor::Folder => "Choose the folder to serve",
        PickFor::File => "Choose the file to serve",
        PickFor::Uploads => "Choose an empty folder for uploads",
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window.dialog().file().set_parent(&window).set_title(title);
    // The last choice's folder when it is still there (never opened when it is on a share), else Downloads.
    let start = current
        .map(PathBuf::from)
        .filter(|p| remotely_core::untrusted::path_refusal(p).is_none())
        .and_then(|p| {
            if p.is_dir() {
                Some(p)
            } else {
                p.parent().map(PathBuf::from)
            }
        })
        .filter(|p| p.is_dir());
    if let Some(folder) = start.or_else(|| window.path().download_dir().ok()) {
        dialog = dialog.set_directory(folder);
    }
    match purpose {
        PickFor::File => dialog.pick_file(move |path| {
            let _ = tx.send(path);
        }),
        PickFor::Folder | PickFor::Uploads => dialog.pick_folder(move |path| {
            let _ = tx.send(path);
        }),
    }
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't use that: {err}")))?;
    Ok(Some(path.display().to_string()))
}

/// Checks the choices against this PC and submits the server to the bus.
#[tauri::command]
pub async fn file_server_start(state: State<'_, AppState>, spec: FileServerSpec) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.file_server.submit(&core.ctx(), spec).await?)
}

/// Stop: the server ends and its job with it. False when it isn't running (here).
#[tauri::command]
pub fn file_server_stop(state: State<'_, AppState>, job_id: Uuid) -> bool {
    let core = &state.core;
    core.file_server.stop(&core.ctx(), job_id)
}

/// The server's events -> UI as `fileserver://event`, only the shown workspace's.
pub fn forward(app: &AppHandle, core: &Arc<Core>) {
    let mut events = core.file_server.subscribe();
    let handle = app.clone();
    let jobs = Arc::clone(&core.jobs);
    let shown = core.current().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    if jobs.workspace_of(event.job_id()) == Some(shown.get().workspace_id) {
                        let _ = handle.emit("fileserver://event", &event);
                    }
                }
                Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed file server events"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}
