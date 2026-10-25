//! Terminal plumbing between xterm.js and the core (SS-03). Bytes stay bytes both ways: keystrokes
//! arrive as the raw body of `terminal_write`, output leaves as raw channel messages (an
//! `ArrayBuffer` in JavaScript), so a multi-byte character split across two reads reaches xterm.js
//! whole. Status changes, host facts (QL-03) and host key questions (SS-05) go out on a second, JSON
//! channel.
//!
//! QL-02 quick connect, QL-04 the session tree and reachability, and SS-11 output are here too. Save
//! dialogs open here, not in the UI, so files are only written where the user chose.

use std::path::PathBuf;

use remotely_core::adapters::remote::PtySize;
use remotely_core::known_hosts::KnownHost;
use remotely_core::reachability::ReachabilityUpdate;
use remotely_core::sessions::tree::{SessionTree, TreeGrouping};
use remotely_core::sessions::{SessionFilter, SessionRecord};
use remotely_core::terminal::log::local_now;
use remotely_core::terminal::output::{self, SaveLayout, SavedOutput, TerminalText};
use remotely_core::terminal::quick::{QuickConnect, QuickConnectEntry, QuickOpened};
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalSettings};
use remotely_core::{Core, CoreError};
use serde::Serialize;
use std::sync::Arc;
use tauri::ipc::{Channel, InvokeBody, InvokeResponseBody, Request};
use tauri::{State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The header naming the terminal a raw `terminal_write` is for.
const TERMINAL_HEADER: &str = "x-terminal-id";
/// Output chunks waiting at once are sent to the UI together, up to this many bytes.
const BATCH_BYTES: usize = 64 * 1024;

/// Forwards a pane's output and events to its channels until either side goes away.
pub(crate) fn forward(
    core: Arc<Core>,
    handle: TerminalHandle,
    on_output: Channel<InvokeResponseBody>,
    on_event: Channel<TerminalEvent>,
) -> Uuid {
    let TerminalHandle {
        id,
        mut output,
        mut events,
    } = handle;
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
                core.terminals.close(id).await;
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
    id
}

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
    let handle = core
        .terminals
        .open(&core.ctx, session_id, PtySize { cols, rows })
        .await?;
    Ok(forward(Arc::clone(core), handle, on_output, on_event))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickConnected {
    id: Uuid,
    /// The session, when "Save as session" was ticked.
    session: Option<SessionRecord>,
}

/// QL-02: opens a pane to a host typed in the "New terminal" form. A typed password arrives as a
/// `SecretString` (zeroized when dropped) and goes to the core only.
#[tauri::command]
pub async fn terminal_quick_connect(
    state: State<'_, AppState>,
    request: QuickConnect,
    cols: u16,
    rows: u16,
    on_output: Channel<InvokeResponseBody>,
    on_event: Channel<TerminalEvent>,
) -> IpcResult<QuickConnected> {
    let core = &state.core;
    let QuickOpened { handle, session } = core
        .terminals
        .quick_connect(&core.ctx, request, PtySize { cols, rows })
        .await?;
    let id = forward(Arc::clone(core), handle, on_output, on_event);
    Ok(QuickConnected { id, session })
}

/// A second pane like an open one (split): same target, and a password typed for it.
#[tauri::command]
pub async fn terminal_open_like(
    state: State<'_, AppState>,
    id: Uuid,
    cols: u16,
    rows: u16,
    on_output: Channel<InvokeResponseBody>,
    on_event: Channel<TerminalEvent>,
) -> IpcResult<Uuid> {
    let core = &state.core;
    let handle = core.terminals.open_like(&core.ctx, id, PtySize { cols, rows }).await?;
    Ok(forward(Arc::clone(core), handle, on_output, on_event))
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

/// Applies to terminals opened from now on (font size and scrollback to open ones too). Audited.
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

// ---- QL-02 history and recent sessions, QL-04 tree and reachability ----------------------------------

/// QL-02: quick connections not saved as sessions, newest first.
#[tauri::command]
pub async fn quick_connect_history(state: State<'_, AppState>) -> IpcResult<Vec<QuickConnectEntry>> {
    let core = &state.core;
    Ok(core.terminals.quick_connect_history(&core.ctx).await?)
}

/// QL-02: forgets one entry, or the whole history without an id. Audited.
#[tauri::command]
pub async fn quick_connect_forget(state: State<'_, AppState>, id: Option<Uuid>) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminals.forget_quick_connects(&core.ctx, id).await?)
}

/// QL-02: the sessions opened most recently, newest first.
#[tauri::command]
pub async fn sessions_recent(state: State<'_, AppState>, limit: Option<u32>) -> IpcResult<Vec<SessionRecord>> {
    let core = &state.core;
    Ok(core.sessions.recent(&core.ctx, limit.unwrap_or(10).min(50)).await?)
}

/// QL-04: the Terminal page's session tree.
#[tauri::command]
pub async fn session_tree(
    state: State<'_, AppState>,
    grouping: TreeGrouping,
    filter: Option<SessionFilter>,
) -> IpcResult<SessionTree> {
    let core = &state.core;
    Ok(core
        .sessions
        .tree(&core.ctx, grouping, &filter.unwrap_or_default())
        .await?)
}

/// QL-04: the sessions the tree shows, so only they are checked; returns what is known so far.
/// Changes arrive as `reachability://update` events.
#[tauri::command]
pub fn reachability_watch(state: State<'_, AppState>, session_ids: Vec<Uuid>) -> ReachabilityUpdate {
    let reachability = &state.core.reachability;
    reachability.set_watched(session_ids);
    reachability.snapshot()
}

// ---- SS-11 output ---------------------------------------------------------------------------------
// Copying goes to the clipboard from Rust: see `terminal_output_copy` in clipboard.rs.

/// SS-11: the terminals' text with their login secrets scrubbed, for printing, audited as printed (which
/// terminals, never the text).
#[tauri::command]
pub async fn terminal_output_print(
    state: State<'_, AppState>,
    items: Vec<TerminalText>,
) -> IpcResult<Vec<TerminalText>> {
    let core = &state.core;
    let items = scrubbed(core, items).await?;
    core.terminals.record_printed(&core.ctx, &items).await?;
    Ok(items)
}

/// SS-11: `items` with their login secrets scrubbed, on a blocking thread.
async fn scrubbed(core: &Arc<Core>, items: Vec<TerminalText>) -> IpcResult<Vec<TerminalText>> {
    output::check_size(&items)?;
    let core = Arc::clone(core);
    tokio::task::spawn_blocking(move || core.terminals.scrub_output(items))
        .await
        .map_err(|err| IpcError::new("internal", format!("The text could not be read: {err}")))
}

/// Waits for the user's choice in a save or folder dialog; `None` when they closed it.
async fn chosen(
    rx: tokio::sync::oneshot::Receiver<Option<tauri_plugin_dialog::FilePath>>,
) -> IpcResult<Option<PathBuf>> {
    let Some(path) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't save there: {err}")))?;
    Ok(Some(path))
}

/// SS-11: asks where to save, then writes the terminals' text there: one `.txt` (a header per terminal
/// when there are several), or with `filePerTerminal` one file each in a chosen folder. Audited.
/// `None` when the user closed the dialog.
#[tauri::command]
pub async fn terminal_output_save(
    window: WebviewWindow,
    state: State<'_, AppState>,
    items: Vec<TerminalText>,
    layout: SaveLayout,
) -> IpcResult<Option<SavedOutput>> {
    output::check(&items)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let dialog = window.dialog().file().set_parent(&window);
    let layout = if items.len() == 1 { SaveLayout::OneFile } else { layout };
    match layout {
        SaveLayout::OneFile => {
            let title = match items.as_slice() {
                [one] => one.title.clone(),
                several => format!("{} terminals", several.len()),
            };
            dialog
                .set_title("Save the terminal output")
                .set_file_name(output::file_name(&title, local_now(), "txt"))
                .add_filter("Text", &["txt"])
                .save_file(move |path| {
                    let _ = tx.send(path);
                });
        }
        SaveLayout::FilePerTerminal => {
            dialog
                .set_title("Choose a folder for the terminals' output (one file each)")
                .pick_folder(move |path| {
                    let _ = tx.send(path);
                });
        }
    }
    let Some(dest) = chosen(rx).await? else {
        return Ok(None);
    };
    let core = &state.core;
    let saved = core.terminals.save_output(&core.ctx, items, layout, &dest).await?;
    tracing::info!(files = saved.files.len(), "terminal output saved");
    Ok(Some(saved))
}

/// SS-11: asks for a log file, then logs the pane's output to it with timestamps. Audited. `None`
/// when the user closed the dialog; otherwise the file's path.
#[tauri::command]
pub async fn terminal_log_start(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: Uuid,
    title: String,
) -> IpcResult<Option<String>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Log this terminal to a file")
        .set_file_name(output::file_name(&title, local_now(), "log"))
        .add_filter("Log", &["log", "txt"])
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = chosen(rx).await? else {
        return Ok(None);
    };
    let core = &state.core;
    core.terminals.start_log(&core.ctx, id, &path).await?;
    Ok(Some(path.display().to_string()))
}

/// SS-11: stops the pane's log. Audited.
#[tauri::command]
pub async fn terminal_log_stop(state: State<'_, AppState>, id: Uuid) -> IpcResult<bool> {
    let core = &state.core;
    Ok(core.terminals.stop_log(&core.ctx, id).await?)
}
