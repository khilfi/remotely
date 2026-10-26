//! VM-08: stacks and their instances. The logic is in `remotely_core::stacks`; this is the IPC around it. Edits are
//! the app's own data (audited, refused by the read-only lock); a deploy, an instance's start, stop or suspend, and a
//! teardown go to the command bus as `Command::Stack`, built in the core from the stack or the instance, never from
//! what the UI sends.

use remotely_core::command_bus::{PowerOp, SubmitOutcome};
use remotely_core::stacks::{Stack, StackCheck, StackDeployCheck, StackDeployRequest, StackInput, StackInstance};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Every stack, each with why it can't deploy now.
#[tauri::command]
pub async fn stacks_list(state: State<'_, AppState>) -> IpcResult<Vec<Stack>> {
    let core = &state.core;
    Ok(core.stacks.list(&core.ctx).await?)
}

/// The stack editor's check while it is filled in. A read.
#[tauri::command]
pub async fn stacks_check(state: State<'_, AppState>, input: StackInput) -> IpcResult<StackCheck> {
    let core = &state.core;
    Ok(core.stacks.check(&core.ctx, &input).await?)
}

#[tauri::command]
pub async fn stacks_add(state: State<'_, AppState>, input: StackInput) -> IpcResult<Stack> {
    let core = &state.core;
    Ok(core.stacks.add(&core.ctx, input).await?)
}

#[tauri::command]
pub async fn stacks_update(state: State<'_, AppState>, id: Uuid, input: StackInput) -> IpcResult<Stack> {
    let core = &state.core;
    Ok(core.stacks.update(&core.ctx, id, input).await?)
}

/// Its instances stay.
#[tauri::command]
pub async fn stacks_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.stacks.delete(&core.ctx, id).await?)
}

/// Why the stack can't deploy, or its AP-02 preview and VM-26's plan.
#[tauri::command]
pub async fn stacks_deploy_check(
    state: State<'_, AppState>,
    request: StackDeployRequest,
) -> IpcResult<StackDeployCheck> {
    let core = &state.core;
    Ok(core.stacks.check_deploy(&core.ctx, &request).await?)
}

/// Submits the stack's deploy: one approval, then one job.
#[tauri::command]
pub async fn stacks_deploy(state: State<'_, AppState>, request: StackDeployRequest) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.stacks.deploy(&core.ctx, &request).await?)
}

/// Every instance on this PC with its VMs as the VM list has them.
#[tauri::command]
pub async fn stacks_instances(state: State<'_, AppState>) -> IpcResult<Vec<StackInstance>> {
    let core = &state.core;
    Ok(core.stacks.instances(&core.ctx).await?)
}

/// Starts (boot order), shuts down or suspends (the last step first) an instance.
#[tauri::command]
pub async fn stacks_instance_power(state: State<'_, AppState>, id: Uuid, op: PowerOp) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.stacks.power(&core.ctx, id, op).await?)
}

/// Tears an instance down (Critical): the VMs its deploy made, and the hand-added ones `also` names.
#[tauri::command]
pub async fn stacks_teardown(state: State<'_, AppState>, id: Uuid, also: Vec<String>) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.stacks.teardown(&core.ctx, id, &also).await?)
}

/// Adds a VM to an instance by hand, at a step (from 0).
#[tauri::command]
pub async fn stacks_add_vm(
    state: State<'_, AppState>,
    id: Uuid,
    vm_key: String,
    step: u32,
) -> IpcResult<StackInstance> {
    let core = &state.core;
    Ok(core.stacks.add_vm(&core.ctx, id, &vm_key, step).await?)
}

/// Takes a VM out of an instance; the VM stays.
#[tauri::command]
pub async fn stacks_remove_vm(state: State<'_, AppState>, id: Uuid, vm_key: String) -> IpcResult<StackInstance> {
    let core = &state.core;
    Ok(core.stacks.remove_vm(&core.ctx, id, &vm_key).await?)
}

/// Forgets an instance; its VMs stay as they are.
#[tauri::command]
pub async fn stacks_forget_instance(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.stacks.forget_instance(&core.ctx, id).await?)
}
