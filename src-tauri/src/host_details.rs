//! MO-13, MO-14, MO-15: host details. All reads: no approval, no audit, and the FD-03 read-only lock
//! doesn't stop them. A session's facts are read on an open terminal's or the dashboard's connection when
//! there is one; otherwise a Refresh or an admin read logs in once (the user asked) and keeps that
//! connection for a few minutes, until `host_details_release`.

use remotely_core::host_details::{AdminReport, SessionSpecs, UpdatesCheck, VmSpecs};
use remotely_core::metrics::{MetricPoint, ThisPcMemory};
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// MO-13: what was last read about the session (offline too); `None` before the first read.
#[tauri::command]
pub async fn host_specs(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<Option<SessionSpecs>> {
    let core = &state.core;
    Ok(core.host_details.session_specs(&core.ctx(), session_id).await?)
}

/// MO-13 Refresh: reads the session's OS and specs now.
#[tauri::command]
pub async fn host_specs_refresh(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<SessionSpecs> {
    let core = &state.core;
    Ok(core.host_details.refresh_session(&core.ctx(), session_id).await?)
}

/// MO-14: services, listening ports, logged-in users, boots and top processes.
#[tauri::command]
pub async fn host_admin(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<AdminReport> {
    let core = &state.core;
    Ok(core.host_details.admin(&core.ctx(), session_id).await?)
}

/// MO-14: pending updates (may take a minute while dnf refreshes its metadata).
#[tauri::command]
pub async fn host_updates(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<UpdatesCheck> {
    let core = &state.core;
    Ok(core.host_details.updates(&core.ctx(), session_id).await?)
}

/// The panel closed: Remotely's own connection to the session, if it made one, closes now.
#[tauri::command]
pub async fn host_details_release(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<()> {
    state.core.host_details.release(session_id).await;
    Ok(())
}

/// MO-13: a VM's hardware from its files (what was read before when they can't be read), and its guest's
/// facts from a linked session.
#[tauri::command]
pub async fn vm_specs(state: State<'_, AppState>, vmx_path: String) -> IpcResult<VmSpecs> {
    let core = &state.core;
    Ok(core.host_details.vm_specs(&core.ctx(), &vmx_path).await?)
}

/// MO-15: this PC's memory now and over the last 30 minutes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThisPcSeries {
    pub latest: Option<ThisPcMemory>,
    pub points: Vec<MetricPoint>,
}

/// MO-15: this PC's RAM in use and its total, and its paging files' use and size, from the metrics rounds
/// (memory only: nothing is read for it).
#[tauri::command]
pub fn metrics_this_pc(state: State<'_, AppState>) -> ThisPcSeries {
    let hub = state.core.metrics.hub();
    ThisPcSeries {
        latest: hub.this_pc(),
        points: hub.this_pc_series(),
    }
}
