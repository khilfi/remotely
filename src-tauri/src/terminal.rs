//! Terminal plumbing between xterm.js and the core (SS-03). Bytes stay bytes both ways: keystrokes
//! arrive as the raw body of `terminal_write`, output leaves as raw channel messages (an
//! `ArrayBuffer` in JavaScript), so a multi-byte character split across two reads reaches xterm.js
//! whole. Status changes and host key questions (SS-05) go out on a second, JSON channel.

use remotely_core::adapters::remote::PtySize;
use remotely_core::known_hosts::KnownHost;
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalSettings};
use remotely_core::CoreError;
use tauri::ipc::{Channel, InvokeBody, InvokeResponseBody, Request};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The header naming the terminal a raw `terminal_write` is for.
const TERMINAL_HEADER: &str = "x-terminal-id";
/// Output chunks waiting at once are sent to the UI together, up to this many bytes.
const BATCH_BYTES: usize = 64 * 1024;

/// Opens a pane to a saved session. Async so it runs on the Tokio runtime, which the pane's task needs.
#[tauri::command]
pub async fn terminal_open(
    state: State<'_, AppState>,
    session_id: Uuid,
    cols: u16,
    rows: u16,
    on_output: Channel<InvokeResponseBody>,
    on_event: Channel<TerminalEvent>,
) -> IpcResult<Uuid> {
    let core = &state.core;
    let TerminalHandle {
        id,
        mut output,
        mut events,
    } = core
        .terminals
        .open(&core.ctx, session_id, PtySize { cols, rows })
        .await?;
    let closer = state.core.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(mut bytes) = output.recv().await {
            while bytes.len() < BATCH_BYTES {
                match output.try_recv() {
                    Ok(more) => bytes.extend_from_slice(&more),
                    Err(_) => break,
                }
            }
            if on_output.send(InvokeResponseBody::Raw(bytes)).is_err() {
                // The window went away: nobody can see this pane any more.
                closer.terminals.close(id).await;
                break;
            }
        }
    });
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            if on_event.send(event).is_err() {
                break;
            }
        }
    });
    Ok(id)
}

/// Keystrokes and pastes: the raw request body, with the terminal's id in the `x-terminal-id` header.
#[tauri::command]
pub async fn terminal_write(state: State<'_, AppState>, request: Request<'_>) -> IpcResult<()> {
    let id = request
        .headers()
        .get(TERMINAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or_else(|| CoreError::InvalidInput("terminal_write needs the terminal's id".into()))?;
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err(CoreError::InvalidInput("terminal_write takes raw bytes".into()).into());
    };
    state.core.terminals.write(id, bytes.clone()).await;
    Ok(())
}

#[tauri::command]
pub async fn terminal_resize(state: State<'_, AppState>, id: Uuid, cols: u16, rows: u16) -> IpcResult<()> {
    state.core.terminals.resize(id, cols, rows).await;
    Ok(())
}

/// Connects again now, dropping a live connection first.
#[tauri::command]
pub async fn terminal_reconnect(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    state.core.terminals.reconnect(id).await;
    Ok(())
}

#[tauri::command]
pub async fn terminal_close(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    state.core.terminals.close(id).await;
    Ok(())
}

/// SS-05: the answer to a first-connection host key question. Trusting saves the key (audited).
#[tauri::command]
pub fn terminal_host_key_answer(state: State<'_, AppState>, id: Uuid, trust: bool) -> IpcResult<()> {
    Ok(state.core.terminals.answer_host_key(id, trust)?)
}

/// SS-05: trusts the changed key that blocked this terminal (audited as a re-trust) and reconnects.
#[tauri::command]
pub async fn terminal_host_key_replace(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminals.replace_host_key(&core.ctx, id).await?)
}

#[tauri::command]
pub async fn terminal_settings(state: State<'_, AppState>) -> IpcResult<TerminalSettings> {
    Ok(state.core.terminal_settings().await?)
}

/// Applies to terminals opened from now on. Audited.
#[tauri::command]
pub async fn terminal_set_settings(
    state: State<'_, AppState>,
    settings: TerminalSettings,
) -> IpcResult<TerminalSettings> {
    state.core.set_terminal_settings(settings).await?;
    Ok(state.core.terminal_settings().await?)
}

/// SS-05: the trusted host keys.
#[tauri::command]
pub async fn known_hosts_list(state: State<'_, AppState>) -> IpcResult<Vec<KnownHost>> {
    let core = &state.core;
    Ok(core.known_hosts.list(&core.ctx).await?)
}

/// SS-05: forgets a key; the next connection asks again. Audited.
#[tauri::command]
pub async fn known_host_remove(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.known_hosts.remove(&core.ctx, id).await?)
}
