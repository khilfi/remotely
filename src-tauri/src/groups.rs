//! QL-19: saved MultiExec groups for the Terminal page's Groups menu. A group only names sessions: the page
//! opens their terminals the usual way and picks them for MultiExec, whose lines still go through the
//! command bus. Every change is audited and refused by the read-only lock in the core.

use remotely_core::multiexec_groups::{GroupInput, MultiExecGroup};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Every group by name, each with its sessions in order.
#[tauri::command]
pub async fn multiexec_groups_list(state: State<'_, AppState>) -> IpcResult<Vec<MultiExecGroup>> {
    let core = &state.core;
    Ok(core.groups.list(&core.ctx()).await?)
}

/// Saves a new group of saved sessions. Audited.
#[tauri::command]
pub async fn multiexec_group_create(state: State<'_, AppState>, input: GroupInput) -> IpcResult<MultiExecGroup> {
    let core = &state.core;
    Ok(core.groups.create(&core.ctx(), input).await?)
}

/// Renames a group and sets its sessions. Audited.
#[tauri::command]
pub async fn multiexec_group_update(
    state: State<'_, AppState>,
    id: Uuid,
    input: GroupInput,
) -> IpcResult<MultiExecGroup> {
    let core = &state.core;
    Ok(core.groups.update(&core.ctx(), id, input).await?)
}

/// The sessions stay. Audited.
#[tauri::command]
pub async fn multiexec_group_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.groups.delete(&core.ctx(), id).await?)
}
