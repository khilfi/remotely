//! FD-04 support bundles: the dialog's presets and tier preview, the save dialog, and Show folder. The logic is in
//! `remotely_core::support_bundle`; this is the IPC around it.
//!
//! The zip's place comes from a save dialog opened here (in Downloads, named `remotely-bundle-<workspace>-<UTC
//! time>.zip`), never from the UI: the core builds `Command::SupportBundle` from it and refuses one the UI sends.
//! Show folder opens Explorer at a finished bundle by its job id.

use std::path::PathBuf;

use remotely_core::command_bus::{CommandPreview, SubmitOutcome};
use remotely_core::support_bundle::{BundleLimits, BundleRequest, PresetView, LIMITS};
use remotely_core::CoreError;
use tauri::{Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The presets, each with its commands and files.
#[tauri::command]
pub fn bundle_presets(state: State<'_, AppState>) -> Vec<PresetView> {
    state.core.bundles.presets()
}

/// The caps (a file, a host, the bundle) and the most items, for the dialog's words.
#[tauri::command]
pub fn bundle_limits() -> BundleLimits {
    LIMITS
}

/// The tier and steps the bundle would get now, and the dangerous-command rules its commands match. A read.
#[tauri::command]
pub async fn bundle_preview(state: State<'_, AppState>, request: BundleRequest) -> IpcResult<CommandPreview> {
    let core = &state.core;
    Ok(core.bundles.preview(&core.ctx(), &request).await?)
}

/// Checks the request, asks where the zip goes, then submits the bundle to the bus. `None` when the dialog was
/// closed.
#[tauri::command]
pub async fn bundle_submit(
    window: WebviewWindow,
    state: State<'_, AppState>,
    request: BundleRequest,
) -> IpcResult<Option<SubmitOutcome>> {
    let core = &state.core;
    let ctx = core.ctx();
    // Before the save dialog: nothing to collect, no host or the read-only lock say so at once.
    core.bundles.check(&ctx, &request).await?;
    let name = core.bundles.default_file_name(&ctx).await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Save the support bundle as")
        .add_filter("Zip files", &["zip"])
        .set_file_name(name);
    if let Ok(downloads) = window.path().download_dir() {
        dialog = dialog.set_directory(downloads);
    }
    dialog.save_file(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let mut output: PathBuf = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't use that file: {err}")))?;
    if !output.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip")) {
        output.set_extension("zip");
    }
    Ok(Some(core.bundles.submit(&ctx, &request, &output).await?))
}

/// Explorer at a finished bundle, with the zip selected.
#[tauri::command]
pub async fn bundle_show_folder(state: State<'_, AppState>, job_id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    let path = core.bundles.saved_at(&core.ctx(), job_id).await?;
    crate::files::reveal(&path)
}
