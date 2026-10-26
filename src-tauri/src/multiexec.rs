//! SS-10 MultiExec (post-MVP P6): keys typed into one terminal go to every picked one, and each line's
//! Enter waits for the policy engine (and, above Low, the approval dialog). The logic is in
//! `remotely_core::terminal::multiexec`; this is the IPC around it. Keys arrive as the raw body of
//! `multiexec_input`, like `terminal_write`, with the terminal typed into in the `x-terminal-id` header.
//! Lines that finish (Enter sent, or cancelled with Ctrl+C) reach the UI as `multiexec://event`.
//!
//! QL-12: the lines MultiExec recorded in each terminal, for the Compare panel's MultiExec view: the
//! list, one line grouped by output, a terminal's output, the diff between two, and the BX-05 export
//! (CSV, JSON or HTML) through a save dialog here in Rust. Recordings change as `multiexec://event`
//! (`recorded`, and `lineFinished` once a line is done everywhere: QL-07's one notification).

use remotely_core::bulk::{self, ExportFormat, GroupOptions, HostOutput, OutputDiff, RecordedExport};
use remotely_core::command_bus::ApprovalAnswers;
use remotely_core::terminal::multiexec::{InputOutcome, MultiExecStatus};
use remotely_core::terminal::record::{RecordedResults, Recordings};
use remotely_core::CoreError;
use tauri::ipc::{InvokeBody, Request};
use tauri::{State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The header naming the terminal the keys were typed into.
const TERMINAL_HEADER: &str = "x-terminal-id";

/// Turns MultiExec on for these terminals, or changes which ones receive input.
#[tauri::command]
pub async fn multiexec_set_targets(state: State<'_, AppState>, terminal_ids: Vec<Uuid>) -> IpcResult<MultiExecStatus> {
    Ok(state.core.multiexec.set_targets(terminal_ids).await?)
}

/// Turns MultiExec off; a line waiting for approval is cancelled (Ctrl+C to its terminals).
#[tauri::command]
pub async fn multiexec_stop(state: State<'_, AppState>) -> IpcResult<MultiExecStatus> {
    Ok(state.core.multiexec.stop().await?)
}

/// Which picked terminals receive what is typed now, and why the others don't.
#[tauri::command]
pub async fn multiexec_status(state: State<'_, AppState>) -> IpcResult<MultiExecStatus> {
    Ok(state.core.multiexec.status().await?)
}

/// Keys typed into a terminal while MultiExec is on: the raw request body.
#[tauri::command]
pub async fn multiexec_input(state: State<'_, AppState>, request: Request<'_>) -> IpcResult<InputOutcome> {
    let from = request
        .headers()
        .get(TERMINAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or_else(|| CoreError::InvalidInput("multiexec_input needs the terminal's id".into()))?;
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err(CoreError::InvalidInput("multiexec_input takes raw bytes".into()).into());
    };
    Ok(state.core.multiexec.input(from, bytes.clone()).await?)
}

/// The approval dialog's answers for a held line; returns the job that sends its Enter.
#[tauri::command]
pub async fn multiexec_approve(state: State<'_, AppState>, line_id: Uuid, answers: ApprovalAnswers) -> IpcResult<Uuid> {
    Ok(state.core.multiexec.approve(line_id, answers).await?)
}

/// Cancels a held line: its terminals get Ctrl+C instead of Enter.
#[tauri::command]
pub async fn multiexec_cancel(state: State<'_, AppState>, line_id: Uuid) -> IpcResult<()> {
    Ok(state.core.multiexec.cancel(line_id).await?)
}

/// QL-12: the lines recorded in this MultiExec session, newest first.
#[tauri::command]
pub async fn multiexec_recordings(state: State<'_, AppState>) -> IpcResult<Recordings> {
    Ok(state.core.multiexec.recordings())
}

/// QL-12: one recorded line, grouped by output like a Compare run (BX-03).
#[tauri::command]
pub async fn multiexec_recorded(
    state: State<'_, AppState>,
    line_id: Uuid,
    options: Option<GroupOptions>,
) -> IpcResult<RecordedResults> {
    Ok(state.core.multiexec.recorded(line_id, options.unwrap_or_default())?)
}

/// QL-12: one terminal's recorded output of a line (so far, while it runs).
#[tauri::command]
pub async fn multiexec_recorded_output(
    state: State<'_, AppState>,
    line_id: Uuid,
    terminal_id: Uuid,
) -> IpcResult<HostOutput> {
    Ok(state.core.multiexec.recorded_output(line_id, terminal_id)?)
}

/// QL-12: the line diff between two terminals' outputs of a line (two groups' samples).
#[tauri::command]
pub async fn multiexec_recorded_diff(
    state: State<'_, AppState>,
    line_id: Uuid,
    left: Uuid,
    right: Uuid,
    options: Option<GroupOptions>,
) -> IpcResult<OutputDiff> {
    Ok(state
        .core
        .multiexec
        .recorded_diff(line_id, left, right, options.unwrap_or_default())?)
}

/// QL-12, BX-05: saves one recorded line (`line_id`) or all of them as CSV, JSON or HTML, with groups
/// and diffs, to a file chosen in a save dialog. Audited with what and where, never the output.
#[tauri::command]
pub async fn multiexec_export(
    window: WebviewWindow,
    state: State<'_, AppState>,
    line_id: Option<Uuid>,
    format: ExportFormat,
    options: Option<GroupOptions>,
) -> IpcResult<Option<RecordedExport>> {
    let core = &state.core;
    // Before the dialog, so a line that went meanwhile says so instead of asking where to save.
    if core.multiexec.recorded_runs(line_id)?.is_empty() {
        return Err(CoreError::InvalidInput("There is no recorded line to export.".into()).into());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title(if line_id.is_some() {
            "Export the recorded line"
        } else {
            "Export the recorded lines"
        })
        .set_file_name(bulk::recorded_export_file_name(line_id, format))
        .add_filter(format.label(), &[format.extension()])
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't save there: {err}")))?;
    // As they are when the file is written (a line still running is saved as far as it got).
    let runs = core.multiexec.recorded_runs(line_id)?;
    let export = core
        .bulk
        .export_recorded(&core.ctx(), &runs, format, options.unwrap_or_default(), &path)
        .await?;
    tracing::info!(lines = export.lines, "MultiExec recordings exported");
    Ok(Some(export))
}
