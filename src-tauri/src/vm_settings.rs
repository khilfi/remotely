//! VM-23, VM-24: the VM settings commands that carry a path of this PC (an ISO, a shared folder, an existing
//! VM) are built here, from a dialog opened here or files dropped on the window, so no such path comes from
//! the UI: the guest can read an attached ISO and a shared folder. The logic is in
//! `remotely_core::vm_settings`; changes go through the command bus like the UI's own commands.

use std::path::PathBuf;

use remotely_core::command_bus::SubmitOutcome;
use remotely_core::vm_settings::{ConsoleOutcome, GuestOsType};
use remotely_core::CoreError;
use tauri::{State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

fn into_path(path: tauri_plugin_dialog::FilePath) -> Result<PathBuf, CoreError> {
    path.into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't read that file: {err}")))
}

/// VM-23: asks for an ISO (a dialog opened here) and attaches it to the VM's CD/DVD drive (`slot`, or its
/// first), through the bus. `None` when the user closed the dialog.
#[tauri::command]
pub async fn vm_pick_iso(
    window: WebviewWindow,
    state: State<'_, AppState>,
    vmx_path: String,
    slot: Option<String>,
) -> IpcResult<Option<SubmitOutcome>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Attach an ISO image to the VM")
        .add_filter("ISO images", &["iso"])
        .pick_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = into_path(path)?;
    Ok(Some(state.core.vm_settings.attach_iso(&vmx_path, &path, slot).await?))
}

/// VM-23: an ISO dropped on a VM's row or details: the staged drop (`files://dropped`) is taken here and
/// attached through the bus.
#[tauri::command]
pub async fn vm_attach_dropped_iso(
    state: State<'_, AppState>,
    staged_id: Uuid,
    vmx_path: String,
) -> IpcResult<SubmitOutcome> {
    let paths = state.core.files.take_staged(staged_id)?;
    Ok(state.core.vm_settings.attach_dropped_iso(&vmx_path, paths).await?)
}

/// VM-23: asks for a folder (a dialog opened here) and shares it with the VM as `name`, through the bus.
#[tauri::command]
pub async fn vm_pick_shared_folder(
    window: WebviewWindow,
    state: State<'_, AppState>,
    vmx_path: String,
    name: String,
    writable: bool,
) -> IpcResult<Option<SubmitOutcome>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose the folder to share with the VM")
        .pick_folder(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = into_path(path)?;
    Ok(Some(
        state
            .core
            .vm_settings
            .add_shared_folder(&vmx_path, &name, &path, writable)
            .await?,
    ))
}

/// VM-24: asks for an existing VM's file (a dialog opened here): a Workstation `.vmx` or a VirtualBox
/// `.vbox`, added through the bus.
#[tauri::command]
pub async fn vm_pick_existing(window: WebviewWindow, state: State<'_, AppState>) -> IpcResult<Option<SubmitOutcome>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Add an existing VM")
        .add_filter("VMs (.vmx, .vbox)", &["vmx", "vbox"])
        .pick_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = into_path(path)?;
    Ok(Some(state.core.vm_settings.add_existing(&path).await?))
}

/// VM-24: the hypervisor's own window on the VM. Audited, no tier; a stopped VirtualBox VM starts with its
/// window (a power command, whose outcome comes back).
#[tauri::command]
pub async fn vm_open_console(state: State<'_, AppState>, vmx_path: String) -> IpcResult<ConsoleOutcome> {
    Ok(state.core.vm_settings.open_console(&vmx_path).await?)
}

/// VM-23: a running VirtualBox VM's screen, as a PNG data URL. A read.
#[tauri::command]
pub async fn vm_screenshot(state: State<'_, AppState>, vmx_path: String) -> IpcResult<String> {
    Ok(state.core.vm_settings.screenshot_data_url(&vmx_path).await?)
}

/// VM-23: the guest OS types the VM's hypervisor offers. A read.
#[tauri::command]
pub async fn vm_guest_os_types(state: State<'_, AppState>, vmx_path: String) -> IpcResult<Vec<GuestOsType>> {
    Ok(state.core.vm_settings.guest_os_types(&vmx_path).await?)
}
