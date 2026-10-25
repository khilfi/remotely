//! CV-01 to CV-03, VM-17: Image tools (Inspect, Convert, Verify), a VM's Export, and Import. The logic is in
//! `remotely_core::convert` and `remotely_core::deploy`; this is the IPC around it.
//!
//! A conversion's new image is named in a save dialog opened here, and an export's folder in a folder dialog opened
//! here, so no place a job writes comes from the UI: the core builds `Command::ImageConvert` and `Command::VmExport`
//! from them (refused when the UI sends one). The files read (an image to inspect, convert or import) are picked in a
//! dialog here too and shown to the UI, like the catalogue's images. An import is a deploy (approval, then a job).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use remotely_core::command_bus::SubmitOutcome;
use remotely_core::convert::formats::OutputKind;
use remotely_core::convert::import::ImportAnalysis;
use remotely_core::convert::inspect::ImageInfo;
use remotely_core::convert::service::{self, ConvertOptions, ExportOptions, ToolsReport};
use remotely_core::convert::verify::{VerifyProgress, VerifyReport};
use remotely_core::convert::ExportTarget;
use remotely_core::deploy::service::{DeployCheck, ImportRequest};
use remotely_core::CoreError;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

fn into_path(path: tauri_plugin_dialog::FilePath) -> Result<PathBuf, CoreError> {
    path.into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't use that file: {err}")))
}

/// What a file is picked for: its dialog's title and filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PickFor {
    /// A disk image to inspect, convert or verify.
    Image,
    /// Something to import as a VM: an appliance, a disk, or a VM's description.
    Import,
}

/// The conversion tools here now (qemu-img, vdiskmanager, VBoxManage, ovftool) and QEMU's download page. A read.
#[tauri::command]
pub async fn convert_tools(state: State<'_, AppState>) -> IpcResult<ToolsReport> {
    let core = &state.core;
    Ok(core.convert.tools(&core.ctx).await?)
}

/// Asks for a file (Downloads by default). `None` when the dialog was closed.
#[tauri::command]
pub async fn convert_pick(window: WebviewWindow, purpose: PickFor) -> IpcResult<Option<String>> {
    let (title, filter, extensions): (&str, &str, &[&str]) = match purpose {
        PickFor::Image => (
            "Choose a disk image",
            "Disk images",
            &["vmdk", "vdi", "vhd", "vhdx", "qcow2", "raw", "img"],
        ),
        PickFor::Import => (
            "Choose a VM or disk to import",
            "Appliances, disks and VM descriptions",
            &[
                "ova", "ovf", "vmdk", "vdi", "vhd", "vhdx", "qcow2", "raw", "img", "xml", "conf",
            ],
        ),
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title(title)
        .add_filter(filter, extensions);
    if let Ok(downloads) = window.path().download_dir() {
        dialog = dialog.set_directory(downloads);
    }
    dialog.pick_file(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    Ok(Some(into_path(chosen)?.display().to_string()))
}

/// CV-03 Inspect: what the image is. A read.
#[tauri::command]
pub async fn convert_inspect(state: State<'_, AppState>, path: String) -> IpcResult<ImageInfo> {
    Ok(state.core.convert.inspect(Path::new(&path)).await?)
}

/// CV-03 Convert: every output the image can become here, how, and why not. A read.
#[tauri::command]
pub async fn convert_options(state: State<'_, AppState>, path: String) -> IpcResult<ConvertOptions> {
    Ok(state.core.convert.options(Path::new(&path)).await?)
}

/// CV-03: asks where the new image goes (a save dialog beside the source, named after it), then submits the
/// conversion to the bus (Low: it runs at once). `None` when the dialog was closed.
#[tauri::command]
pub async fn convert_submit(
    window: WebviewWindow,
    state: State<'_, AppState>,
    source: String,
    kind: OutputKind,
    whole_megabytes: bool,
) -> IpcResult<Option<SubmitOutcome>> {
    let source = PathBuf::from(source);
    let default = service::default_output(&source, kind);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Save the new image as")
        .add_filter(kind.label(), &[kind.extension()]);
    if let Some(folder) = default.parent() {
        dialog = dialog.set_directory(folder);
    }
    if let Some(name) = default.file_name() {
        dialog = dialog.set_file_name(name.to_string_lossy());
    }
    dialog.save_file(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let output = into_path(chosen)?;
    let core = &state.core;
    Ok(Some(
        core.convert
            .submit_convert(&core.ctx, &source, &output, kind, whole_megabytes)
            .await?,
    ))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEvent {
    request: Uuid,
    done: u64,
    total: u64,
}

/// CV-03 Verify: sizes, checksums and (with qemu-img) a comparison, its progress sent as `convert://verify`
/// events under `request`. A read.
#[tauri::command]
pub async fn convert_verify(
    app: AppHandle,
    state: State<'_, AppState>,
    request: Uuid,
    first: String,
    second: Option<String>,
) -> IpcResult<VerifyReport> {
    let progress = Arc::new(move |p: VerifyProgress| {
        let _ = app.emit(
            "convert://verify",
            VerifyEvent {
                request,
                done: p.done,
                total: p.total,
            },
        );
    });
    let second = second.map(PathBuf::from);
    Ok(state
        .core
        .convert
        .verify(request, Path::new(&first), second.as_deref(), progress)
        .await?)
}

/// Stops Verify's `request`. False when it wasn't running.
#[tauri::command]
pub fn convert_verify_cancel(state: State<'_, AppState>, request: Uuid) -> bool {
    state.core.convert.cancel_verify(request)
}

/// VM-17, CV-02: every target the VM can be exported to here, and why not. A read.
#[tauri::command]
pub async fn export_options(state: State<'_, AppState>, vm_key: String) -> IpcResult<ExportOptions> {
    let core = &state.core;
    Ok(core.convert.export_options(&core.ctx, &vm_key).await?)
}

/// VM-17, CV-02: asks for the folder the export goes in (Documents by default), then submits it to the bus (Low; a
/// Prod VM's asks). `None` when the dialog was closed.
#[tauri::command]
pub async fn export_submit(
    window: WebviewWindow,
    state: State<'_, AppState>,
    vm_key: String,
    target: ExportTarget,
) -> IpcResult<Option<SubmitOutcome>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose the folder the export goes in");
    if let Ok(documents) = window.path().document_dir() {
        dialog = dialog.set_directory(documents);
    }
    dialog.pick_folder(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let folder = into_path(chosen)?;
    let core = &state.core;
    Ok(Some(
        core.convert.submit_export(&core.ctx, &vm_key, target, &folder).await?,
    ))
}

/// CV-01: what the picked file is and what it brings. A read.
#[tauri::command]
pub async fn import_analyze(state: State<'_, AppState>, path: String) -> IpcResult<ImportAnalysis> {
    Ok(state.core.deploy.analyze_import(Path::new(&path)).await?)
}

/// CV-01: why the import can't run, or its AP-02 preview. A read.
#[tauri::command]
pub async fn import_check(state: State<'_, AppState>, request: ImportRequest) -> IpcResult<DeployCheck> {
    let core = &state.core;
    Ok(core.deploy.check_import(&core.ctx, &request).await?)
}

/// CV-01: submits the import as a deploy: approval, then one job.
#[tauri::command]
pub async fn import_submit(state: State<'_, AppState>, request: ImportRequest) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.deploy.submit_import(&core.ctx, &request).await?)
}

/// Opens QEMU's download page in the default browser. Any other address is refused before Windows sees it.
#[tauri::command]
pub async fn convert_open_qemu_site(url: String) -> IpcResult<()> {
    tokio::task::spawn_blocking(move || open_checked(&url, crate::command_panel::open_in_browser))
        .await
        .map_err(|err| IpcError::new("browser", format!("The browser did not open: {err}")))?
}

fn open_checked(url: &str, open: impl FnOnce(&str) -> IpcResult<()>) -> IpcResult<()> {
    let url = service::checked_qemu_site(url)?;
    open(url.as_str())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    // Only the check: a test never starts the real browser.
    #[test]
    fn only_qemus_page_reaches_the_browser() {
        let opened = RefCell::new(Vec::new());
        open_checked(service::QEMU_DOWNLOAD, |u| {
            opened.borrow_mut().push(u.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(opened.borrow().as_slice(), ["https://www.qemu.org/download/#windows"]);
        assert!(open_checked("https://qemu.example.com/download/", |_| panic!("never opened")).is_err());
        assert!(open_checked("file:///C:/Windows/notepad.exe", |_| panic!("never opened")).is_err());
    }
}
