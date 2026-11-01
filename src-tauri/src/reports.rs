//! FD-05, BX-12, FD-08: the inventory to Excel, the Ansible inventory and the handover pack. The logic is in
//! `remotely_core::reports`; this is the IPC around it.
//!
//! Each file's place comes from a save dialog opened here (in Documents, named
//! `remotely-<what>-<workspace>-<date>.<ext>`, without the workspace while presenting), never from the window, and the
//! core refuses a Git working tree. Each export reads the shown workspace (`core.ctx()` per call). Show in folder opens
//! Explorer at a file saved here, by the id its export returned, never at a path the window names.
//!
//! The inventory and the handover pack may read every SSH and WinRM host first, which takes minutes: each runs under an id the
//! window chose, in the toolbox's [`ToolRuns`] (so a reload of the window stops it, `lib.rs`), `reports_cancel` stops
//! it with nothing written, and `reports://progress` says how many hosts are done.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use remotely_core::bulk::{ResolvedTargets, TargetPicks};
use remotely_core::reports::{
    chosen_path, AnsibleExport, AnsibleFormat, AnsiblePreview, AnsibleRequest, HandoverExport, HandoverPreview,
    HandoverRequest, InventoryExport, InventoryRequest, ReadControl, ReadProgress, ReportKind, ReportsOverview,
};
use remotely_core::CoreError;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::toolbox::{Running, ToolRuns};
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Files saved in this run, by the id their export returned, for Show in folder.
#[derive(Default)]
pub struct SavedReports(Mutex<HashMap<Uuid, PathBuf>>);

impl SavedReports {
    fn remember(&self, path: PathBuf) -> Uuid {
        let id = Uuid::new_v4();
        if let Ok(mut saved) = self.0.lock() {
            // A few dozen at most in a run; the oldest go when there are many.
            if saved.len() >= 100 {
                saved.clear();
            }
            saved.insert(id, path);
        }
        id
    }

    fn get(&self, id: Uuid) -> Option<PathBuf> {
        self.0.lock().ok().and_then(|saved| saved.get(&id).cloned())
    }
}

/// An export's result, with the id Show in folder takes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Saved<T> {
    pub saved_id: Uuid,
    #[serde(flatten)]
    pub report: T,
}

fn made_by() -> String {
    format!("Remotely {}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    run: Uuid,
    #[serde(flatten)]
    progress: ReadProgress,
}

/// The export's cancel token and its progress events, for run `run`.
fn control(app: AppHandle, running: &Running<'_>, run: Uuid) -> ReadControl {
    ReadControl::new(running.token.clone()).with_progress(move |progress| {
        let _ = app.emit("reports://progress", ProgressEvent { run, progress });
    })
}

/// FD-03: the save dialog is Windows' own, so its suggested name leaves the workspace out while presenting.
fn presenting(state: &AppState) -> bool {
    state.core.presentation.get().enabled
}

/// Stops an export's host reads; nothing is written. False when it isn't going on any more.
#[tauri::command]
pub fn reports_cancel(runs: State<'_, ToolRuns>, run: Uuid) -> bool {
    runs.cancel(run)
}

/// Asks where to save, offering `name` in Documents. `None` when the dialog was closed.
async fn ask_path(
    window: &WebviewWindow,
    title: &str,
    name: String,
    filter: (&str, &[&str]),
) -> IpcResult<Option<PathBuf>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(window)
        .set_title(title)
        .add_filter(filter.0, filter.1)
        .set_file_name(name);
    if let Ok(documents) = window.path().document_dir() {
        dialog = dialog.set_directory(documents);
    }
    dialog.save_file(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let chosen: PathBuf = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't use that file: {err}")))?;
    Ok(Some(chosen_path(&chosen, filter.1)?))
}

/// The counts and names the export dialogs show.
#[tauri::command]
pub async fn reports_overview(state: State<'_, AppState>) -> IpcResult<ReportsOverview> {
    let core = &state.core;
    Ok(core.reports.overview(&core.ctx()).await?)
}

/// FD-05: asks where to save, then writes the inventory there, as run `run` (`reports_cancel`). `None` when the dialog
/// was closed.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn inventory_export(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    saved: State<'_, SavedReports>,
    runs: State<'_, ToolRuns>,
    run: Uuid,
    request: InventoryRequest,
) -> IpcResult<Option<Saved<InventoryExport>>> {
    let core = &state.core;
    let ctx = core.ctx();
    let running = Running::start(&runs, run);
    let name = core
        .reports
        .file_name(
            &ctx,
            ReportKind::Inventory,
            AnsibleFormat::Yaml,
            request.utc_offset_minutes,
            presenting(&state),
        )
        .await?;
    let Some(path) = ask_path(&window, "Save the inventory as", name, ("Excel workbook", &["xlsx"])).await? else {
        return Ok(None);
    };
    let control = control(app, &running, run);
    let report = core
        .reports
        .export_inventory(&ctx, &path, request, &made_by(), &control)
        .await?;
    tracing::info!(vms = report.vms, hosts = report.hosts, "inventory exported");
    Ok(Some(Saved {
        saved_id: saved.remember(path),
        report,
    }))
}

/// BX-12: the hosts the picks reach, SSH and WinRM sessions both, for the dialog's picker.
#[tauri::command]
pub async fn ansible_targets(state: State<'_, AppState>, picks: TargetPicks) -> IpcResult<ResolvedTargets> {
    let core = &state.core;
    Ok(core.reports.ansible_targets(&core.ctx(), &picks).await?)
}

/// BX-12: the file as it would be written, for the dialog's preview.
#[tauri::command]
pub async fn ansible_preview(state: State<'_, AppState>, request: AnsibleRequest) -> IpcResult<AnsiblePreview> {
    let core = &state.core;
    Ok(core.reports.ansible_preview(&core.ctx(), &request).await?)
}

/// BX-12: asks where to save, then writes the inventory there. `None` when the dialog was closed.
#[tauri::command]
pub async fn ansible_export(
    window: WebviewWindow,
    state: State<'_, AppState>,
    saved: State<'_, SavedReports>,
    request: AnsibleRequest,
    utc_offset_minutes: i32,
) -> IpcResult<Option<Saved<AnsibleExport>>> {
    let core = &state.core;
    let ctx = core.ctx();
    // Before the dialog: nothing to write says so at once.
    let preview = core.reports.ansible_preview(&ctx, &request).await?;
    if preview.hosts == 0 {
        return Err(CoreError::InvalidInput(
            "No SSH or WinRM session can go in the inventory: pick sessions, or VMs linked to one.".into(),
        )
        .into());
    }
    let name = core
        .reports
        .file_name(
            &ctx,
            ReportKind::Ansible,
            request.format,
            utc_offset_minutes,
            presenting(&state),
        )
        .await?;
    let filter: (&str, &[&str]) = match request.format {
        AnsibleFormat::Yaml => ("YAML inventory", &["yml", "yaml"]),
        AnsibleFormat::Ini => ("INI inventory", &["ini"]),
    };
    let Some(path) = ask_path(&window, "Save the Ansible inventory as", name, filter).await? else {
        return Ok(None);
    };
    let report = core.reports.export_ansible(&ctx, &path, &request).await?;
    tracing::info!(
        hosts = report.hosts,
        groups = report.groups,
        "Ansible inventory exported"
    );
    Ok(Some(Saved {
        saved_id: saved.remember(path),
        report,
    }))
}

/// FD-08: the counts the dialog shows for the chosen dates.
#[tauri::command]
pub async fn handover_preview(state: State<'_, AppState>, request: HandoverRequest) -> IpcResult<HandoverPreview> {
    let core = &state.core;
    Ok(core.reports.handover_preview(&core.ctx(), &request).await?)
}

/// FD-08: asks where to save, then writes the handover pack there, as run `run` (`reports_cancel`). `None` when the
/// dialog was closed.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn handover_export(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    saved: State<'_, SavedReports>,
    runs: State<'_, ToolRuns>,
    run: Uuid,
    request: HandoverRequest,
) -> IpcResult<Option<Saved<HandoverExport>>> {
    let core = &state.core;
    let ctx = core.ctx();
    let running = Running::start(&runs, run);
    // Before the dialog: a range that runs backwards says so at once.
    core.reports.handover_preview(&ctx, &request).await?;
    let name = core
        .reports
        .file_name(
            &ctx,
            ReportKind::Handover,
            AnsibleFormat::Yaml,
            request.utc_offset_minutes,
            presenting(&state),
        )
        .await?;
    let Some(path) = ask_path(&window, "Save the handover pack as", name, ("Zip files", &["zip"])).await? else {
        return Ok(None);
    };
    let control = control(app, &running, run);
    let report = core
        .reports
        .export_handover(&ctx, &path, &request, &made_by(), &control)
        .await?;
    tracing::info!(jobs = report.jobs, notes = report.notes, "handover pack saved");
    Ok(Some(Saved {
        saved_id: saved.remember(path),
        report,
    }))
}

/// Explorer at a file an export saved in this run, selected.
#[tauri::command]
pub async fn reports_show_file(saved: State<'_, SavedReports>, saved_id: Uuid) -> IpcResult<()> {
    let path = saved
        .get(saved_id)
        .ok_or_else(|| CoreError::InvalidInput("That file isn't known any more: open its folder yourself.".into()))?;
    crate::files::reveal(&path)
}
