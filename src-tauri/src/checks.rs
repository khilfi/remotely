//! MO-08: health checks. The runner ticks on the wall clock for the shown workspace; its results and changes go to
//! the window as `checks://event` (the Checks tab, the widget, the status bar). Edits are the app's own data,
//! audited in the core and refused by the read-only lock; reads and "Run now" are not.

use std::sync::Arc;

use remotely_core::checks::{CheckHistory, CheckInput, CheckSummary, ChecksOverview, HealthCheck};
use remotely_core::metrics::history::HistoryRange;
use remotely_core::Core;
use tauri::{App, Emitter, State};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Starts the runner and forwards its events to the window. The runner follows the shown workspace only, so every
/// event is the shown workspace's (a run of the old one, in flight at a switch, is dropped).
pub fn start(app: &App, core: &Arc<Core>) {
    let checks = core.checks.clone();
    tauri::async_runtime::spawn(async move { checks.run(CancellationToken::new()).await });
    let mut events = core.checks.subscribe();
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let _ = handle.emit("checks://event", &event);
                }
                Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed health check events"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

/// Every check with its status, last result, uptime and sparkline over `range`.
#[tauri::command]
pub async fn checks_overview(state: State<'_, AppState>, range: HistoryRange) -> IpcResult<ChecksOverview> {
    Ok(state.core.checks.overview(range).await?)
}

/// The counts for the status bar.
#[tauri::command]
pub fn checks_summary(state: State<'_, AppState>) -> CheckSummary {
    state.core.checks.summary()
}

/// A check's history sheet.
#[tauri::command]
pub async fn check_history(state: State<'_, AppState>, id: Uuid, range: HistoryRange) -> IpcResult<CheckHistory> {
    Ok(state.core.checks.history(id, range).await?)
}

#[tauri::command]
pub async fn check_create(state: State<'_, AppState>, input: CheckInput) -> IpcResult<HealthCheck> {
    Ok(state.core.checks.create(input).await?)
}

#[tauri::command]
pub async fn check_update(state: State<'_, AppState>, id: Uuid, input: CheckInput) -> IpcResult<HealthCheck> {
    Ok(state.core.checks.update(id, input).await?)
}

#[tauri::command]
pub async fn check_pause(state: State<'_, AppState>, id: Uuid, paused: bool) -> IpcResult<HealthCheck> {
    Ok(state.core.checks.set_paused(id, paused).await?)
}

#[tauri::command]
pub async fn check_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    Ok(state.core.checks.delete(id).await?)
}

/// "Run now": at the next tick. A read: not audited.
#[tauri::command]
pub async fn check_run_now(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    Ok(state.core.checks.run_soon(id).await?)
}
