//! FD-02 customer workspaces: the top bar's switcher and its dialogs, the VMs page's Unassigned view, and AP-08's
//! per-workspace change ID rule. Workspace edits and VM assignments are audited and refused by the read-only lock in
//! the core. Switching closes what the old workspace had open there; the UI then loads again, so nothing it held in
//! memory shows in the new workspace.

use remotely_core::command_bus::ChangeIdRules;
use remotely_core::domain::WorkspaceId;
use remotely_core::inventory::UnassignedVm;
use remotely_core::store::VmRecord;
use remotely_core::transfer::TransferCommit;
use remotely_core::workspaces::{NewWorkspaceImport, SwitchPreview, Workspace, WorkspaceInput};
use tauri::State;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Every workspace of the user, archived ones too.
#[tauri::command]
pub async fn workspaces_list(state: State<'_, AppState>) -> IpcResult<Vec<Workspace>> {
    Ok(state.core.workspaces.list().await?)
}

/// The workspace shown now.
#[tauri::command]
pub async fn workspace_current(state: State<'_, AppState>) -> IpcResult<Workspace> {
    Ok(state.core.workspaces.shown().await?)
}

/// Makes a workspace (not shown yet). Audited in it.
#[tauri::command]
pub async fn workspace_create(state: State<'_, AppState>, input: WorkspaceInput) -> IpcResult<Workspace> {
    Ok(state.core.workspaces.create(input).await?)
}

#[tauri::command]
pub async fn workspace_rename(state: State<'_, AppState>, id: WorkspaceId, name: String) -> IpcResult<Workspace> {
    Ok(state.core.workspaces.rename(id, &name).await?)
}

#[tauri::command]
pub async fn workspace_set_color(state: State<'_, AppState>, id: WorkspaceId, color: String) -> IpcResult<Workspace> {
    Ok(state.core.workspaces.set_color(id, &color).await?)
}

/// Not the shown one, nor the last active one.
#[tauri::command]
pub async fn workspace_archive(state: State<'_, AppState>, id: WorkspaceId) -> IpcResult<Workspace> {
    Ok(state.core.workspaces.archive(id).await?)
}

#[tauri::command]
pub async fn workspace_restore(state: State<'_, AppState>, id: WorkspaceId) -> IpcResult<Workspace> {
    Ok(state.core.workspaces.restore(id).await?)
}

/// What switching would close, and whether jobs still running refuse it.
#[tauri::command]
pub async fn workspace_switch_preview(state: State<'_, AppState>, id: WorkspaceId) -> IpcResult<SwitchPreview> {
    Ok(state.core.switch_preview(id).await?)
}

/// Shows another workspace (the UI loads again after it).
#[tauri::command]
pub async fn workspace_switch(state: State<'_, AppState>, id: WorkspaceId) -> IpcResult<Workspace> {
    Ok(state.core.switch_workspace(id).await?)
}

/// The VMs on this PC no workspace has, as the last refresh found them.
#[tauri::command]
pub fn vm_unassigned(state: State<'_, AppState>) -> Vec<UnassignedVm> {
    state.core.inventory.unassigned()
}

/// Adds VMs from Unassigned to the shown workspace. Audited.
#[tauri::command]
pub async fn vm_claim(state: State<'_, AppState>, vmx_paths: Vec<String>) -> IpcResult<Vec<VmRecord>> {
    let core = &state.core;
    Ok(core.inventory.claim(&core.ctx(), &vmx_paths).await?)
}

/// Takes VMs out of the shown workspace, into Unassigned. Audited.
#[tauri::command]
pub async fn vm_release(state: State<'_, AppState>, vmx_paths: Vec<String>) -> IpcResult<Vec<VmRecord>> {
    let core = &state.core;
    Ok(core.inventory.release(&core.ctx(), &vmx_paths).await?)
}

/// AP-08: the shown workspace's change ID rule.
#[tauri::command]
pub async fn change_id_rules(state: State<'_, AppState>) -> IpcResult<ChangeIdRules> {
    let core = &state.core;
    Ok(core.bus.change_id_rules(&core.ctx()).await?)
}

/// AP-08: makes a change ID required for High and Critical actions on Prod targets, or optional. Audited.
#[tauri::command]
pub async fn change_id_rules_set(state: State<'_, AppState>, rules: ChangeIdRules) -> IpcResult<ChangeIdRules> {
    let core = &state.core;
    Ok(core.bus.set_change_id_rules(&core.ctx(), rules).await?)
}

/// FD-07: imports the opened file into a new workspace instead of the shown one.
#[tauri::command]
pub async fn transfer_commit_new_workspace(
    state: State<'_, AppState>,
    workspace: WorkspaceInput,
    request: TransferCommit,
) -> IpcResult<NewWorkspaceImport> {
    Ok(state.core.import_into_new_workspace(workspace, request).await?)
}
