//! SS-14, SS-08 (0.8.0 G4): editing a host's files from the Files drawer. The logic is in
//! `remotely_core::terminal::editor` ("Edit in the terminal": a tab on the host running its editor) and
//! `remotely_core::terminal::edit_local` ("Edit on this PC"); this is the IPC around them. Both are commands on the
//! bus, built by the core after it looked at the file: the window sends a terminal and a host path, never a command or a
//! path on this PC. Editing sessions' changes reach the window as `files://edit` events, the shown workspace's only. A
//! copy kept with a save that didn't go up is saved elsewhere through this shell's own save dialog: the window sends
//! only its id.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use remotely_core::command_bus::SubmitOutcome;
use remotely_core::jobs::JobStatus;
use remotely_core::terminal::edit_local::{EditAnswer, EditInfo, StopChoice, StopOutcome};
use remotely_core::terminal::editor::HostEditors;
use remotely_core::terminal::TerminalEvent;
use remotely_core::{Core, CoreError};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// How long the window waits for an editor job to open its tab (a High one has its countdown first).
const EDITOR_JOB_WAIT: Duration = Duration::from_secs(360);

/// SS-14: the editors the terminal's host has, and the session's choice.
#[tauri::command]
pub async fn files_host_editors(state: State<'_, AppState>, id: Uuid) -> IpcResult<HostEditors> {
    let core = &state.core;
    Ok(core.terminals.host_editors(&core.ctx(), id).await?)
}

/// SS-14: the session's own editor (`None`: the first of nano, micro, vim, vi the host has). Audited.
#[tauri::command]
pub async fn files_set_host_editor(
    state: State<'_, AppState>,
    session_id: Uuid,
    editor: Option<String>,
) -> IpcResult<()> {
    Ok(state.core.files.set_host_editor(session_id, editor).await?)
}

/// SS-14: opens a host's file in a terminal editor on the host, through the command bus: queued (Low) or waiting for
/// the approval dialog. Once the job is queued, the window opens a tab with [`terminal_editor_attach`].
#[tauri::command]
pub async fn files_open_in_editor(
    state: State<'_, AppState>,
    id: Uuid,
    path: String,
    as_root: bool,
    editor: Option<String>,
) -> IpcResult<SubmitOutcome> {
    Ok(state.core.files.open_in_editor(id, path, as_root, editor).await?)
}

/// SS-14: the tab an editor job opened: waits for the job, then forwards the tab's output and events like any pane's.
#[tauri::command]
pub async fn terminal_editor_attach(
    state: State<'_, AppState>,
    job_id: Uuid,
    cols: u16,
    rows: u16,
    on_output: Channel<InvokeResponseBody>,
    on_event: Channel<TerminalEvent>,
) -> IpcResult<Uuid> {
    let core = &state.core;
    let status = tokio::time::timeout(EDITOR_JOB_WAIT, core.jobs.wait(job_id))
        .await
        .map_err(|_| {
            CoreError::InvalidInput("The editor's job did not run in time; its tab was not opened.".into())
        })??;
    if status == JobStatus::Cancelled {
        return Err(CoreError::Cancelled.into());
    }
    // A failed job says why in its handoff.
    let handle = core.terminals.take_editor_tab(&core.ctx(), job_id)?;
    let id = crate::terminal::forward(Arc::clone(core), handle, on_output, on_event);
    core.terminals.resize(id, cols, rows).await;
    Ok(id)
}

/// SS-08: edits a host's file on this PC, through the command bus (one approval for the editing session).
#[tauri::command]
pub async fn files_edit_on_pc(
    state: State<'_, AppState>,
    id: Uuid,
    path: String,
    as_root: bool,
) -> IpcResult<SubmitOutcome> {
    Ok(state.core.files.edit_on_pc(id, path, as_root).await?)
}

/// SS-08: the shown workspace's editing sessions, and copies kept with a save that didn't go up.
#[tauri::command]
pub fn files_edits(state: State<'_, AppState>) -> Vec<EditInfo> {
    let core = &state.core;
    core.terminals.edits(&core.ctx())
}

/// SS-08: Stop editing: the last save goes up first (if the host's copy is unchanged), then the copy is deleted. A save
/// that didn't go up stops nothing (`unsent`) until `choice` says to upload it again, keep it or discard it.
#[tauri::command]
pub async fn files_edit_stop(
    state: State<'_, AppState>,
    id: Uuid,
    choice: Option<StopChoice>,
) -> IpcResult<StopOutcome> {
    let core = &state.core;
    Ok(core.terminals.stop_edit(&core.ctx(), id, choice).await?)
}

/// SS-08: opens a kept copy in the editor on this PC again.
#[tauri::command]
pub async fn files_edit_kept_open(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminals.open_kept(&core.ctx(), id).await?)
}

/// SS-08: asks where to save a kept copy (in Downloads by default), then saves it there. False when the dialog was
/// closed.
#[tauri::command]
pub async fn files_edit_kept_save(window: WebviewWindow, state: State<'_, AppState>, id: Uuid) -> IpcResult<bool> {
    let core = &state.core;
    let ctx = core.ctx();
    // FD-03: the save dialog is out of the masker's reach, so it offers no host file name while presenting.
    let name = if core.presentation.get().enabled {
        "edited copy".to_owned()
    } else {
        core.terminals.kept_file_name(&ctx, id)?
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Save the edited copy as")
        .set_file_name(name);
    if let Ok(downloads) = window.path().download_dir() {
        dialog = dialog.set_directory(downloads);
    }
    dialog.save_file(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(false);
    };
    let chosen: PathBuf = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't use that file: {err}")))?;
    core.terminals.save_kept(&ctx, id, &chosen).await?;
    Ok(true)
}

/// SS-08: deletes a kept copy and what didn't go up. Audited.
#[tauri::command]
pub async fn files_edit_kept_discard(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminals.discard_kept(&core.ctx(), id).await?)
}

/// SS-08: the answer to a save held because the host's copy changed; `None`: try a failed upload again.
#[tauri::command]
pub async fn files_edit_answer(state: State<'_, AppState>, id: Uuid, answer: Option<EditAnswer>) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminals.answer_edit(&core.ctx(), id, answer).await?)
}

/// SS-08: editing sessions' changes -> UI, the shown workspace's only (FD-02).
pub fn forward(app: &AppHandle, core: &Arc<Core>) {
    let mut edits = core.terminals.subscribe_edits();
    let handle = app.clone();
    let shown = core.current().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match edits.recv().await {
                Ok((workspace, edit)) => {
                    if workspace == shown.get().workspace_id {
                        let _ = handle.emit("files://edit", &edit);
                    }
                }
                Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed editing events"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}
