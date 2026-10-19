//! SS-10 MultiExec (post-MVP P6): keys typed into one terminal go to every picked one, and each line's
//! Enter waits for the policy engine (and, above Low, the approval dialog). The logic is in
//! `remotely_core::terminal::multiexec`; this is the IPC around it. Keys arrive as the raw body of
//! `multiexec_input`, like `terminal_write`, with the terminal typed into in the `x-terminal-id` header.
//! Lines that finish (Enter sent, or cancelled with Ctrl+C) reach the UI as `multiexec://event`.

use remotely_core::command_bus::ApprovalAnswers;
use remotely_core::terminal::multiexec::{InputOutcome, MultiExecStatus};
use remotely_core::CoreError;
use tauri::ipc::{InvokeBody, Request};
use tauri::State;
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
