//! VM-19 to VM-21: the Templates page (sizes, images, launch templates). The logic is in
//! `remotely_core::catalog`; this is the IPC around it.
//!
//! * Image files and VM folders are picked in dialogs opened here (Downloads and Documents by default). The path
//!   comes back to the UI to show, and the core refuses network shares and device paths before the file system sees
//!   them, whatever the UI sends.
//! * Adding a file image hashes it in the core on a blocking thread; its progress reaches the UI as
//!   `catalog://hash` events with the request id the UI chose, which `catalog_image_cancel` takes to stop it.
//! * The Images tab's links open in the default browser only when the core's allow-list of official cloud image
//!   pages takes the address (`catalog::checked_site`). Opening a page changes nothing, so it is not audited and
//!   the read-only lock doesn't stop it.

use std::sync::Arc;

use remotely_core::catalog::{
    self, Image, ImageEdit, ImageInput, ImageKind, ImageSite, LaunchTemplate, OsProfile, Size, SizeInput,
    TemplateInput, TemplatePreview,
};
use remotely_core::CoreError;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The OS profiles, in the order the image editor offers them.
#[tauri::command]
pub fn catalog_profiles() -> Vec<OsProfile> {
    catalog::profiles().to_vec()
}

/// The official cloud image pages the Images tab links to.
#[tauri::command]
pub fn catalog_sites() -> Vec<ImageSite> {
    catalog::IMAGE_SITES.to_vec()
}

/// The twelve built-in sizes, then the owner's own.
#[tauri::command]
pub async fn catalog_sizes(state: State<'_, AppState>) -> IpcResult<Vec<Size>> {
    let core = &state.core;
    Ok(core.catalog.sizes(&core.ctx()).await?)
}

/// Audited.
#[tauri::command]
pub async fn catalog_size_add(state: State<'_, AppState>, input: SizeInput) -> IpcResult<Size> {
    let core = &state.core;
    Ok(core.catalog.add_size(&core.ctx(), input).await?)
}

/// An own size; built-ins are read only. Audited.
#[tauri::command]
pub async fn catalog_size_update(state: State<'_, AppState>, id: String, input: SizeInput) -> IpcResult<Size> {
    let core = &state.core;
    Ok(core.catalog.update_size(&core.ctx(), &id, input).await?)
}

/// Audited.
#[tauri::command]
pub async fn catalog_size_delete(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.catalog.delete_size(&core.ctx(), &id).await?)
}

/// Every image, each with why it can't deploy now.
#[tauri::command]
pub async fn catalog_images(state: State<'_, AppState>) -> IpcResult<Vec<Image>> {
    let core = &state.core;
    Ok(core.catalog.images(&core.ctx()).await?)
}

/// Asks for an image file of `kind` (Downloads by default). `None` when the dialog was closed.
#[tauri::command]
pub async fn catalog_image_pick(window: WebviewWindow, kind: ImageKind) -> IpcResult<Option<String>> {
    let (title, filter, extensions): (&str, &str, &[&str]) = match kind {
        ImageKind::CloudImage => (
            "Choose a cloud image",
            "Cloud images",
            &["vmdk", "ova", "img", "raw", "qcow2"],
        ),
        ImageKind::Iso => ("Choose an ISO image", "ISO images", &["iso"]),
        ImageKind::Appliance => ("Choose an OVA or OVF appliance", "Appliances", &["ova", "ovf"]),
        ImageKind::GoldenVm => {
            return Err(CoreError::InvalidInput("A golden VM is picked from the VM list.".into()).into())
        }
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
    let path = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't read that file: {err}")))?;
    Ok(Some(path.display().to_string()))
}

/// Asks for the folder a launch template's VMs go in (Documents by default). `None` when the dialog was closed.
#[tauri::command]
pub async fn catalog_folder_pick(window: WebviewWindow) -> IpcResult<Option<String>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose the folder the VMs go in");
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashEvent {
    request: Uuid,
    done: u64,
    total: u64,
}

/// Adds an image. A file is checked and hashed first, its progress sent as `catalog://hash` events under `request`.
/// Audited.
#[tauri::command]
pub async fn catalog_image_add(
    app: AppHandle,
    state: State<'_, AppState>,
    request: Uuid,
    input: ImageInput,
) -> IpcResult<Image> {
    let core = &state.core;
    let progress = Arc::new(move |p: catalog::HashProgress| {
        let _ = app.emit(
            "catalog://hash",
            HashEvent {
                request,
                done: p.done,
                total: p.total,
            },
        );
    });
    let image = core.catalog.add_image(&core.ctx(), request, input, progress).await?;
    tracing::info!(kind = image.kind().as_str(), "image added to the catalogue");
    Ok(image)
}

/// Stops hashing the image `request` adds. False when it wasn't being hashed.
#[tauri::command]
pub fn catalog_image_cancel(state: State<'_, AppState>, request: Uuid) -> bool {
    state.core.catalog.cancel_hash(request)
}

/// Its name, hypervisors, OS profile and notes. Audited.
#[tauri::command]
pub async fn catalog_image_update(state: State<'_, AppState>, id: Uuid, edit: ImageEdit) -> IpcResult<Image> {
    let core = &state.core;
    Ok(core.catalog.update_image(&core.ctx(), id, edit).await?)
}

/// The catalogue's entry only; the file or VM stays. Audited.
#[tauri::command]
pub async fn catalog_image_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.catalog.delete_image(&core.ctx(), id).await?)
}

/// Every launch template, each with why it can't deploy now.
#[tauri::command]
pub async fn catalog_templates(state: State<'_, AppState>) -> IpcResult<Vec<LaunchTemplate>> {
    let core = &state.core;
    Ok(core.catalog.templates(&core.ctx()).await?)
}

/// The editor's check while it is filled in: its problems and the names its default count would get.
#[tauri::command]
pub async fn catalog_template_preview(state: State<'_, AppState>, input: TemplateInput) -> IpcResult<TemplatePreview> {
    let core = &state.core;
    Ok(core.catalog.preview(&core.ctx(), &input).await?)
}

/// Audited.
#[tauri::command]
pub async fn catalog_template_add(state: State<'_, AppState>, input: TemplateInput) -> IpcResult<LaunchTemplate> {
    let core = &state.core;
    Ok(core.catalog.add_template(&core.ctx(), input).await?)
}

/// Audited.
#[tauri::command]
pub async fn catalog_template_update(
    state: State<'_, AppState>,
    id: Uuid,
    input: TemplateInput,
) -> IpcResult<LaunchTemplate> {
    let core = &state.core;
    Ok(core.catalog.update_template(&core.ctx(), id, input).await?)
}

/// Audited.
#[tauri::command]
pub async fn catalog_template_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.catalog.delete_template(&core.ctx(), id).await?)
}

/// Opens an official cloud image page in the default browser. Any address not on the core's list of those sites is
/// refused before Windows sees it.
#[tauri::command]
pub async fn catalog_open_site(url: String) -> IpcResult<()> {
    tokio::task::spawn_blocking(move || open_checked(&url, crate::command_panel::open_in_browser))
        .await
        .map_err(|err| IpcError::new("browser", format!("The browser did not open: {err}")))?
}

/// Hands `url` to `open` only when it is a page the app may open.
fn open_checked(url: &str, open: impl FnOnce(&str) -> IpcResult<()>) -> IpcResult<()> {
    let url = catalog::checked_site(url)?;
    open(url.as_str())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    // Only the check: a test never starts the real browser.

    #[test]
    fn an_official_cloud_image_page_reaches_the_browser() {
        let opened = RefCell::new(Vec::new());
        for site in catalog::IMAGE_SITES {
            open_checked(site.url, |u| {
                opened.borrow_mut().push(u.to_owned());
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(opened.into_inner().len(), 4);
    }

    #[test]
    fn any_other_address_is_refused_before_the_browser_sees_it() {
        for url in [
            "https://example.com/",
            "http://cloud-images.ubuntu.com/",
            "file:///C:/Windows/System32/cmd.exe",
            r"C:\Windows\System32\cmd.exe",
            "https://man7.org/linux/man-pages/man1/df.1.html",
            "https://cloud-images.ubuntu.com@example.com/",
            "",
        ] {
            let Err(err) = open_checked(url, |u| panic!("{u} reached the browser")) else {
                panic!("{url} was opened");
            };
            let json = serde_json::to_value(err).unwrap();
            assert_eq!(json["code"], "invalid_input", "{url}");
        }
    }
}
