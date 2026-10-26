//! 0.5.0 navigation (R10): QL-25 the notification centre's history (in the core's memory: the UI adds what
//! it notified, the core redacts and keeps it), QL-21 the topology map's read of each VM's networks, and QL-23
//! the first-run wizard's folder dialog. Reads, the notification list's own state and a dialog: nothing here goes
//! through the bus, and none of it is audited (the settings the wizard saves go through Settings' own commands).

use remotely_core::host_details::networks::VmNetworks;
use remotely_core::notifications::{Notification, NotificationInput, NotificationList};
use remotely_core::CoreError;
use tauri::{Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The most entries one call names.
const MAX_IDS: usize = 1000;

fn checked(ids: &Option<Vec<u64>>) -> IpcResult<()> {
    if ids.as_ref().is_some_and(|ids| ids.len() > MAX_IDS) {
        return Err(CoreError::InvalidInput("Too many notifications at once.".into()).into());
    }
    Ok(())
}

/// QL-25: the history, newest first, with the unread count.
#[tauri::command]
pub fn notifications_list(state: State<'_, AppState>) -> NotificationList {
    let core = &state.core;
    core.notifications.list(&core.ctx())
}

/// QL-25: keeps a notification the UI showed (or a toast worth keeping). The core redacts its text.
#[tauri::command]
pub fn notifications_add(state: State<'_, AppState>, input: NotificationInput) -> IpcResult<Notification> {
    let core = &state.core;
    Ok(core.notifications.add(&core.ctx(), input)?)
}

/// QL-25: marks these entries read, or all of them when `ids` is null.
#[tauri::command]
pub fn notifications_mark_read(state: State<'_, AppState>, ids: Option<Vec<u64>>) -> IpcResult<NotificationList> {
    checked(&ids)?;
    let core = &state.core;
    Ok(core.notifications.mark_read(&core.ctx(), ids.as_deref()))
}

/// QL-25: removes these entries, or all of them when `ids` is null.
#[tauri::command]
pub fn notifications_clear(state: State<'_, AppState>, ids: Option<Vec<u64>>) -> IpcResult<NotificationList> {
    checked(&ids)?;
    let core = &state.core;
    Ok(core.notifications.clear(&core.ctx(), ids.as_deref()))
}

/// QL-21: every VM's network adapters for the map: what was read before, and a read of the VMs never read
/// (`fresh`: of every VM, a few at a time).
#[tauri::command]
pub async fn topology_vm_networks(state: State<'_, AppState>, fresh: bool) -> IpcResult<Vec<VmNetworks>> {
    let core = &state.core;
    Ok(core.host_details.vm_networks(&core.ctx(), fresh).await?)
}

/// QL-23: the first-run wizard's folder dialog, for a folder that holds VMs. Only picks it: adding it to the
/// scanned folders is `settings_set_scan_folders`, as in Settings. `None` when the dialog was closed.
#[tauri::command]
pub async fn vm_folder_pick(window: WebviewWindow) -> IpcResult<Option<String>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose a folder that holds VMs");
    if let Ok(documents) = window.path().document_dir() {
        dialog = dialog.set_directory(documents);
    }
    dialog.pick_folder(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't use that folder: {err}")))?;
    Ok(Some(path.display().to_string()))
}
