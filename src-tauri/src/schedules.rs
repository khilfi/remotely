//! VM-14, VM-27 schedules: the Schedules page's and a VM's Schedules tab's commands, the scheduler's loop, and its
//! events for the UI (`schedules://event`; R10's notification centre can list them). Saving, editing, approving,
//! pausing, resuming and deleting are the app's own data, audited in the core and refused by the read-only lock;
//! each run's commands go through the command bus under the approval given when the schedule was saved.

use std::sync::Arc;

use remotely_core::command_bus::ApprovalAnswers;
use remotely_core::schedules::{
    ChainLimits, SaveOutcome, ScheduleInput, SchedulePreview, ScheduleRun, ScheduleView, VmSchedules,
};
use remotely_core::{Core, CoreError};
use tauri::{App, Emitter, State};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The most runs one read returns.
const MAX_RUNS: usize = 200;

/// Starts the scheduler on the wall clock and forwards its events to the UI.
pub fn start(app: &App, core: &Arc<Core>) {
    let schedules = core.schedules.clone();
    tauri::async_runtime::spawn(async move { schedules.run(CancellationToken::new()).await });
    let mut events = core.schedules.subscribe();
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let _ = handle.emit("schedules://event", &event);
                }
                Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed schedule events"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

/// Every schedule, with its next and last run and what would make it ask again.
#[tauri::command]
pub async fn schedules_list(state: State<'_, AppState>) -> IpcResult<Vec<ScheduleView>> {
    Ok(state.core.schedules.list().await?)
}

#[tauri::command]
pub async fn schedule_get(state: State<'_, AppState>, id: Uuid) -> IpcResult<ScheduleView> {
    Ok(state.core.schedules.get(id).await?)
}

/// A schedule's run history, newest first.
#[tauri::command]
pub async fn schedule_runs(state: State<'_, AppState>, id: Uuid, limit: Option<usize>) -> IpcResult<Vec<ScheduleRun>> {
    Ok(state.core.schedules.runs(id, limit.unwrap_or(50).min(MAX_RUNS)).await?)
}

/// The editor's preview: when it would run, the VMs it finds now, warnings. Nothing is saved.
#[tauri::command]
pub async fn schedule_preview(state: State<'_, AppState>, input: ScheduleInput) -> IpcResult<SchedulePreview> {
    Ok(state.core.schedules.preview(input).await?)
}

/// Saves a new schedule or an edit; new content returns the approval to answer.
#[tauri::command]
pub async fn schedule_save(state: State<'_, AppState>, input: ScheduleInput) -> IpcResult<SaveOutcome> {
    Ok(state.core.schedules.save(input).await?)
}

/// The answers to a schedule's approval (the approval dialog's own way, not `command_approve`).
#[tauri::command]
pub async fn schedule_approve(
    state: State<'_, AppState>,
    request_id: Uuid,
    answers: ApprovalAnswers,
) -> IpcResult<ScheduleView> {
    Ok(state.core.schedules.approve(request_id, answers).await?)
}

/// A schedule waiting for its approval: the approval, asked again.
#[tauri::command]
pub async fn schedule_ask_approval(state: State<'_, AppState>, id: Uuid) -> IpcResult<SaveOutcome> {
    Ok(state.core.schedules.ask_approval(id).await?)
}

#[tauri::command]
pub async fn schedule_pause(state: State<'_, AppState>, id: Uuid) -> IpcResult<ScheduleView> {
    Ok(state.core.schedules.pause(id).await?)
}

/// Runs it again; if something changed since its approval, the approval to answer.
#[tauri::command]
pub async fn schedule_resume(state: State<'_, AppState>, id: Uuid) -> IpcResult<SaveOutcome> {
    Ok(state.core.schedules.resume(id).await?)
}

#[tauri::command]
pub async fn schedule_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    Ok(state.core.schedules.delete(id).await?)
}

/// A VM's Schedules tab: the schedules that reach it, and its snapshot chain (VM-27).
#[tauri::command]
pub async fn schedules_for_vm(state: State<'_, AppState>, vm_key: String) -> IpcResult<VmSchedules> {
    if vm_key.is_empty() || vm_key.len() > 1024 {
        return Err(CoreError::InvalidInput("Choose a VM.".into()).into());
    }
    Ok(state.core.schedules.for_vm(&vm_key).await?)
}

#[tauri::command]
pub async fn schedule_chain_limits(state: State<'_, AppState>) -> IpcResult<ChainLimits> {
    Ok(state.core.schedules.chain_limits().await?)
}

/// VM-27: when snapshot chains warn. Audited.
#[tauri::command]
pub async fn schedule_chain_limits_set(state: State<'_, AppState>, limits: ChainLimits) -> IpcResult<ChainLimits> {
    Ok(state.core.schedules.set_chain_limits(limits).await?)
}
