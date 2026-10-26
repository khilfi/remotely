//! VM-21, VM-22, VM-10: the Deploy dialog and the VMs page's Clone. The logic is in `remotely_core::deploy`; this
//! is the IPC around it. A check is a read; a submit goes to the command bus as `Command::Deploy` (approval, then
//! one job with a step per VM), built in the core from the catalogue, never from paths the UI sends.

use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::command_bus::SubmitOutcome;
use remotely_core::deploy::service::{CloneRequest, DeployCheck, DeployRequest};
use tauri::State;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Why the request can't deploy, or what it would make (AP-02).
#[tauri::command]
pub async fn deploy_check(state: State<'_, AppState>, request: DeployRequest) -> IpcResult<DeployCheck> {
    let core = &state.core;
    Ok(core.deploy.check(&core.ctx(), &request).await?)
}

/// Submits the deploy: approval, then one job.
#[tauri::command]
pub async fn deploy_submit(state: State<'_, AppState>, request: DeployRequest) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.deploy.submit(&core.ctx(), &request).await?)
}

/// VM-10: why the picked VMs can't be cloned, or what the clones would be.
#[tauri::command]
pub async fn deploy_clone_check(state: State<'_, AppState>, request: CloneRequest) -> IpcResult<DeployCheck> {
    let core = &state.core;
    Ok(core.deploy.check_clone(&core.ctx(), &request).await?)
}

/// VM-10: submits the bulk clone: approval, then one job.
#[tauri::command]
pub async fn deploy_clone_submit(state: State<'_, AppState>, request: CloneRequest) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.deploy.submit_clone(&core.ctx(), &request).await?)
}

/// VirtualBox's host-only adapters, or with `bridged` the adapters it bridges to.
#[tauri::command]
pub async fn deploy_host_adapters(state: State<'_, AppState>, bridged: bool) -> IpcResult<Vec<String>> {
    Ok(state.core.deploy.host_adapters(bridged).await?)
}

/// Where the hypervisor puts new VMs.
#[tauri::command]
pub async fn deploy_default_folder(state: State<'_, AppState>, hypervisor: Hypervisor) -> IpcResult<String> {
    Ok(state.core.deploy.default_folder(hypervisor).await?)
}
