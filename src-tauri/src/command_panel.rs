//! The Terminal page's helpers (post-MVP P5): BX-08's command panel (favourite and built-in commands,
//! `{{variables}}` filled in before pasting), QL-06 "Type vault password", and QL-07's Windows
//! notification when a long command in a background tab finishes.
//!
//! Pasting a command is the terminal's own input path (`terminal_write`, as if typed), so nothing here
//! sends a command anywhere. A vault password goes from the vault to the shell inside the core: the UI
//! names the secret by id and never sees its value.

use std::collections::HashMap;

use remotely_core::snippets::{CommandInfo, Favourite, FavouriteInput, LibraryEntry};
use remotely_core::vault::SecretId;
use remotely_core::CoreError;
use tauri::{AppHandle, State};
use tauri_plugin_notification::NotificationExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Longest notification title and text the UI may ask for.
const MAX_TITLE: usize = 120;
const MAX_BODY: usize = 400;

/// BX-08: the favourite commands, folders by name (the top level first), each in the user's order.
#[tauri::command]
pub async fn favourites_list(state: State<'_, AppState>) -> IpcResult<Vec<Favourite>> {
    let core = &state.core;
    Ok(core.snippets.favourites(&core.ctx).await?)
}

/// BX-08: saves a new favourite at the end of its folder. Audited (name and folder, not the command).
#[tauri::command]
pub async fn favourite_add(state: State<'_, AppState>, input: FavouriteInput) -> IpcResult<Favourite> {
    let core = &state.core;
    Ok(core.snippets.add(&core.ctx, input).await?)
}

/// BX-08: changes a favourite; another folder puts it at that folder's end. Audited.
#[tauri::command]
pub async fn favourite_update(state: State<'_, AppState>, id: Uuid, input: FavouriteInput) -> IpcResult<Favourite> {
    let core = &state.core;
    Ok(core.snippets.update(&core.ctx, id, input).await?)
}

/// BX-08. Audited.
#[tauri::command]
pub async fn favourite_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.snippets.delete(&core.ctx, id).await?)
}

/// BX-08: one folder's favourites in a new order (`folder` null: the top level). Audited.
#[tauri::command]
pub async fn favourites_reorder(
    state: State<'_, AppState>,
    folder: Option<String>,
    ids: Vec<Uuid>,
) -> IpcResult<Vec<Favourite>> {
    let core = &state.core;
    Ok(core.snippets.reorder(&core.ctx, folder.as_deref(), &ids).await?)
}

/// BX-08: the built-in commands, each with what the policy engine makes of it under the current rules.
#[tauri::command]
pub fn command_library(state: State<'_, AppState>) -> Vec<LibraryEntry> {
    state.core.snippets.library()
}

/// BX-08: a command's `{{variables}}` and what the policy engine makes of it, while it is typed.
#[tauri::command]
pub fn command_inspect(state: State<'_, AppState>, command: String) -> CommandInfo {
    state.core.snippets.inspect(&command)
}

/// BX-08: the command with its `{{variables}}` filled in, ready to paste.
#[tauri::command]
pub fn command_fill(state: State<'_, AppState>, command: String, values: HashMap<String, String>) -> IpcResult<String> {
    Ok(state.core.snippets.fill(&command, &values)?)
}

/// QL-06: types a vault password or passphrase into the terminal, then Enter, when it shows a
/// password prompt (or `force`). The value never comes back here. Audited with the label.
#[tauri::command]
pub async fn terminal_type_secret(
    state: State<'_, AppState>,
    id: Uuid,
    secret_id: SecretId,
    force: bool,
) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminals.type_secret(&core.ctx, id, secret_id, force).await?)
}

/// QL-07: a Windows notification that a long command finished in a background tab. The UI decides
/// when (the tab is in the background, notifications are on for it); the text names the terminal and
/// how long the command ran, nothing of its output.
#[tauri::command]
pub fn notify_command_finished(app: AppHandle, title: String, body: String) -> IpcResult<()> {
    let title: String = title.chars().filter(|c| !c.is_control()).take(MAX_TITLE).collect();
    let body: String = body.chars().filter(|c| !c.is_control()).take(MAX_BODY).collect();
    if title.trim().is_empty() {
        return Err(CoreError::InvalidInput("A notification needs a title.".into()).into());
    }
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|err| IpcError::new("notification", format!("the notification could not be shown: {err}")))?;
    tracing::info!("long-command notification shown");
    Ok(())
}
