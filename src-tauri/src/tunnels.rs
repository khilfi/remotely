//! SS-07 port forwards and tunnels. Each session's saved forwards are edited in the session dialog
//! (`forwards_*`, audited by the core); a terminal's tunnels open on its connection through the
//! command bus (`terminal_tunnel_start` builds the command from the saved forward, so the UI never
//! names addresses or ports for a tunnel), and their state reaches the UI as `tunnels` terminal
//! events.

use std::collections::HashMap;

use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest};
use remotely_core::forwards::{ForwardInput, PortForward};
use remotely_core::terminal::tunnels::{TunnelInfo, TunnelStart};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// A session's saved forwards, in order.
#[tauri::command]
pub async fn forwards_list(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<Vec<PortForward>> {
    let core = &state.core;
    Ok(core.forwards.list(&core.ctx, session_id).await?)
}

/// Every session's saved forwards, by session (the Sessions page's list and the tree).
#[tauri::command]
pub async fn forwards_all(state: State<'_, AppState>) -> IpcResult<HashMap<Uuid, Vec<PortForward>>> {
    let core = &state.core;
    Ok(core.forwards.all(&core.ctx).await?)
}

/// Replaces a session's forwards with the dialog's list. Audited with what changed.
#[tauri::command]
pub async fn forwards_save(
    state: State<'_, AppState>,
    session_id: Uuid,
    forwards: Vec<ForwardInput>,
) -> IpcResult<Vec<PortForward>> {
    let core = &state.core;
    Ok(core.forwards.save(&core.ctx, session_id, &forwards).await?)
}

/// A terminal's tunnels: the session's forwards and each one's state.
#[tauri::command]
pub async fn terminal_tunnels(state: State<'_, AppState>, terminal_id: Uuid) -> IpcResult<Vec<TunnelInfo>> {
    let core = &state.core;
    Ok(core.terminals.tunnels(&core.ctx, terminal_id).await?)
}

/// Opens a saved forward on the terminal's connection, through the command bus: opening at once, or
/// the approval to show.
#[tauri::command]
pub async fn terminal_tunnel_start(
    state: State<'_, AppState>,
    terminal_id: Uuid,
    forward_id: Uuid,
) -> IpcResult<TunnelStart> {
    let core = &state.core;
    Ok(core.terminals.start_tunnel(&core.ctx, terminal_id, forward_id).await?)
}

/// The approval a tunnel waits for (one that started with the terminal asks this way).
#[tauri::command]
pub fn terminal_tunnel_request(
    state: State<'_, AppState>,
    terminal_id: Uuid,
    forward_id: Uuid,
) -> Option<ApprovalRequest> {
    state.core.terminals.tunnel_request(terminal_id, forward_id)
}

#[tauri::command]
pub async fn terminal_tunnel_approve(
    state: State<'_, AppState>,
    terminal_id: Uuid,
    forward_id: Uuid,
    answers: ApprovalAnswers,
) -> IpcResult<Uuid> {
    let core = &state.core;
    Ok(core
        .terminals
        .approve_tunnel(&core.ctx, terminal_id, forward_id, answers)
        .await?)
}

#[tauri::command]
pub async fn terminal_tunnel_decline(state: State<'_, AppState>, terminal_id: Uuid, forward_id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core
        .terminals
        .decline_tunnel(&core.ctx, terminal_id, forward_id)
        .await?)
}

/// Stops a tunnel (audited when it was open). It stays stopped after reconnects.
#[tauri::command]
pub async fn terminal_tunnel_stop(state: State<'_, AppState>, terminal_id: Uuid, forward_id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminals.stop_tunnel(&core.ctx, terminal_id, forward_id).await?)
}
