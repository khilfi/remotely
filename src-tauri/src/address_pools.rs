//! VM-32 (0.8.0 G6): the Templates page's Address pools tab. The logic is in `remotely_core::address_pools`; this is the
//! IPC around it. Edits are the app's own data: audited in the core with no approval tier and refused by the read-only
//! lock. A deploy's claims never come from the window: the deploy runner takes them through the core.

use std::net::Ipv4Addr;

use remotely_core::address_pools::{AddressLease, AddressPool, AddressPoolInput};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The shown workspace's pools by name, with how many of each one's addresses are taken.
#[tauri::command]
pub async fn address_pools_list(state: State<'_, AppState>) -> IpcResult<Vec<AddressPool>> {
    let core = &state.core;
    Ok(core.address_pools.list(&core.ctx()).await?)
}

/// A pool's taken addresses: each with its VM, or the deploy claiming it.
#[tauri::command]
pub async fn address_pool_leases(state: State<'_, AppState>, id: Uuid) -> IpcResult<Vec<AddressLease>> {
    let core = &state.core;
    Ok(core.address_pools.leases(&core.ctx(), id).await?)
}

/// Audited.
#[tauri::command]
pub async fn address_pool_add(state: State<'_, AppState>, input: AddressPoolInput) -> IpcResult<AddressPool> {
    let core = &state.core;
    Ok(core.address_pools.add(&core.ctx(), input).await?)
}

/// Audited. A change that would take an address a VM holds is refused.
#[tauri::command]
pub async fn address_pool_update(
    state: State<'_, AppState>,
    id: Uuid,
    input: AddressPoolInput,
) -> IpcResult<AddressPool> {
    let core = &state.core;
    Ok(core.address_pools.update(&core.ctx(), id, input).await?)
}

/// Audited; refused while a VM holds one of its addresses or a deploy claims one.
#[tauri::command]
pub async fn address_pool_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.address_pools.delete(&core.ctx(), id).await?)
}

/// Frees an address whose VM is gone from the VMs page, or whose deploy isn't running. Audited.
#[tauri::command]
pub async fn address_pool_free(state: State<'_, AppState>, id: Uuid, ip: Ipv4Addr) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.address_pools.free(&core.ctx(), id, ip).await?)
}
