//! 0.7.0 F5: FD-06 notes, QL-26 stars and recents, QL-27 the trash and QL-28 bulk session edit. The app's own data:
//! nothing here goes through the bus. Notes, the trash and bulk edit are audited by the core and refused by the
//! read-only lock; stars and recents are neither, like the notification centre. A web link in a note opens through
//! ShellExecute only after the window's confirm showed its address, and only when the core reads it as `http(s)`.

use remotely_core::notes::{Note, NoteInput, NoteLink, NoteTarget, RenderedNote};
use remotely_core::sessions::{BulkEdit, BulkEditPreview};
use remotely_core::stars::{Recent, RecentKind, Star, StarKind};
use remotely_core::trash::{RestoreReport, TrashEntry, TrashKind};
use remotely_core::vault::SecretString;
use remotely_core::CoreError;
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The most sessions one bulk edit names.
const MAX_BULK: usize = 1000;

// ---- FD-06 notes ------------------------------------------------------------------------------------------------------

/// The note about a session, VM or folder, if it has one.
#[tauri::command]
pub async fn note_get(state: State<'_, AppState>, target: NoteTarget) -> IpcResult<Option<Note>> {
    let core = &state.core;
    Ok(core.notes.get(&core.ctx(), &target).await?)
}

/// Saves the note (an empty text deletes it). Audited without its text.
#[tauri::command]
pub async fn note_save(state: State<'_, AppState>, target: NoteTarget, input: NoteInput) -> IpcResult<Option<Note>> {
    let core = &state.core;
    Ok(core.notes.save(&core.ctx(), &target, input).await?)
}

/// F6: marks the note for the handover pack, or takes it out. Audited.
#[tauri::command]
pub async fn note_set_handover(state: State<'_, AppState>, target: NoteTarget, handover: bool) -> IpcResult<Note> {
    let core = &state.core;
    Ok(core.notes.set_handover(&core.ctx(), &target, handover).await?)
}

/// QL-20: every note in the workspace, for search.
#[tauri::command]
pub async fn notes_list(state: State<'_, AppState>) -> IpcResult<Vec<Note>> {
    let core = &state.core;
    Ok(core.notes.list(&core.ctx()).await?)
}

/// A note's text as HTML the window shows as it is, with its links and code blocks. A read: not audited.
#[tauri::command]
pub async fn note_render(state: State<'_, AppState>, body: String) -> IpcResult<RenderedNote> {
    let core = &state.core;
    let body = remotely_core::notes::clean_body(&body)?;
    Ok(core.notes.render(&core.ctx(), &body).await?)
}

/// Opens a note's web link in the default browser, after the window's confirm showed the address. Only an address the
/// core reads as `http` or `https` with a host opens; anything else is refused. Not audited: it changes nothing here.
#[tauri::command]
pub async fn note_open_link(url: String) -> IpcResult<()> {
    let names = remotely_core::notes::LinkNames::default();
    let NoteLink::Web { url } = remotely_core::notes::render::classify(&url, &names) else {
        return Err(CoreError::InvalidInput("Only web addresses (http or https) open from a note.".into()).into());
    };
    tokio::task::spawn_blocking(move || crate::command_panel::open_in_browser(&url))
        .await
        .map_err(|err| IpcError::new("browser", format!("The browser did not open: {err}")))?
}

// ---- QL-26 stars and recents ----------------------------------------------------------------------------------------

#[tauri::command]
pub async fn stars_list(state: State<'_, AppState>) -> IpcResult<Vec<Star>> {
    let core = &state.core;
    Ok(core.stars.list(&core.ctx()).await?)
}

/// Stars an item or takes its star off. Not audited; allowed while presenting.
#[tauri::command]
pub async fn stars_set(state: State<'_, AppState>, kind: StarKind, key: String, starred: bool) -> IpcResult<Vec<Star>> {
    let core = &state.core;
    Ok(core.stars.set(&core.ctx(), kind, &key, starred).await?)
}

#[tauri::command]
pub async fn recents_list(state: State<'_, AppState>) -> IpcResult<Vec<Recent>> {
    let core = &state.core;
    Ok(core.stars.recents(&core.ctx()).await?)
}

/// Notes that a VM's details or a page was opened (a session's terminal notes itself).
#[tauri::command]
pub async fn recents_opened(state: State<'_, AppState>, kind: RecentKind, key: String) -> IpcResult<Vec<Recent>> {
    let core = &state.core;
    Ok(core.stars.opened(&core.ctx(), kind, &key).await?)
}

// ---- QL-27 the trash ------------------------------------------------------------------------------------------------

#[tauri::command]
pub async fn trash_list(state: State<'_, AppState>) -> IpcResult<Vec<TrashEntry>> {
    let core = &state.core;
    Ok(core.trash.list(&core.ctx()).await?)
}

/// Puts an item back. SS-04: `vault_password` when the core asked for it (a restored session would send a vault
/// password somewhere new).
#[tauri::command]
pub async fn trash_restore(
    state: State<'_, AppState>,
    id: Uuid,
    vault_password: Option<SecretString>,
) -> IpcResult<RestoreReport> {
    let core = &state.core;
    Ok(core.trash.restore(&core.ctx(), id, vault_password.as_ref()).await?)
}

/// A delete's Undo: restores the newest trash entry of that item.
#[tauri::command]
pub async fn trash_undo(
    state: State<'_, AppState>,
    kind: TrashKind,
    item_id: String,
    vault_password: Option<SecretString>,
) -> IpcResult<RestoreReport> {
    let core = &state.core;
    Ok(core
        .trash
        .undo(&core.ctx(), kind, &item_id, vault_password.as_ref())
        .await?)
}

#[tauri::command]
pub async fn trash_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.trash.delete_now(&core.ctx(), id).await?)
}

#[tauri::command]
pub async fn trash_empty(state: State<'_, AppState>) -> IpcResult<usize> {
    let core = &state.core;
    Ok(core.trash.empty(&core.ctx()).await?)
}

// ---- QL-28 bulk edit ------------------------------------------------------------------------------------------------

fn bulk_ids(ids: &[Uuid]) -> IpcResult<()> {
    if ids.len() > MAX_BULK {
        return Err(CoreError::InvalidInput(format!("A bulk edit takes at most {MAX_BULK} sessions.")).into());
    }
    Ok(())
}

/// Before and after for each session, without saving.
#[tauri::command]
pub async fn sessions_bulk_preview(
    state: State<'_, AppState>,
    ids: Vec<Uuid>,
    edit: BulkEdit,
) -> IpcResult<BulkEditPreview> {
    bulk_ids(&ids)?;
    let core = &state.core;
    Ok(core.sessions.bulk_preview(&core.ctx(), &ids, &edit).await?)
}

/// Saves the edit on every session at once. SS-04, AP-06: `vault_password` when the core asked for it.
#[tauri::command]
pub async fn sessions_bulk_edit(
    state: State<'_, AppState>,
    ids: Vec<Uuid>,
    edit: BulkEdit,
    vault_password: Option<SecretString>,
) -> IpcResult<BulkEditPreview> {
    bulk_ids(&ids)?;
    let core = &state.core;
    Ok(core
        .sessions
        .bulk_edit(&core.ctx(), &ids, &edit, vault_password.as_ref())
        .await?)
}
