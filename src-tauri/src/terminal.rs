//! Terminal plumbing between xterm.js and the core: keystrokes come in through `terminal_write`, output
//! streams back over a Tauri channel. Today the core hands out a loopback shell; SS-03 swaps in an SSH
//! PTY behind the same commands.

use std::collections::HashMap;
use std::sync::Mutex;

use remotely_core::adapters::remote::ShellInput;
use remotely_core::locks;
use tauri::ipc::Channel;
use tauri::State;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

#[derive(Default)]
pub struct Terminals(Mutex<HashMap<Uuid, mpsc::Sender<ShellInput>>>);

impl Terminals {
    fn sender(&self, id: Uuid) -> Option<mpsc::Sender<ShellInput>> {
        locks::lock(&self.0).get(&id).cloned()
    }
}

/// Async so it runs on the Tokio runtime, which the shell task needs.
#[tauri::command]
pub async fn terminal_open(state: State<'_, AppState>, on_output: Channel<String>) -> Result<Uuid, IpcError> {
    let id = Uuid::new_v4();
    let mut shell = state.core.open_terminal();
    locks::lock(&state.terminals.0).insert(id, shell.input);
    tauri::async_runtime::spawn(async move {
        // TODO(SS-03): send raw bytes; lossy UTF-8 can split a multi-byte character across reads.
        while let Some(bytes) = shell.output.recv().await {
            if on_output.send(String::from_utf8_lossy(&bytes).into_owned()).is_err() {
                break;
            }
        }
    });
    Ok(id)
}

#[tauri::command]
pub async fn terminal_write(state: State<'_, AppState>, id: Uuid, data: String) -> Result<(), IpcError> {
    if let Some(tx) = state.terminals.sender(id) {
        let _ = tx.send(ShellInput::Data(data.into_bytes())).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn terminal_resize(state: State<'_, AppState>, id: Uuid, cols: u16, rows: u16) -> Result<(), IpcError> {
    if let Some(tx) = state.terminals.sender(id) {
        let _ = tx.send(ShellInput::Resize { cols, rows }).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn terminal_close(state: State<'_, AppState>, id: Uuid) -> Result<(), IpcError> {
    let tx = locks::lock(&state.terminals.0).remove(&id);
    if let Some(tx) = tx {
        let _ = tx.send(ShellInput::Close).await;
    }
    Ok(())
}
