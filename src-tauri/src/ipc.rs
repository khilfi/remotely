//! IPC commands the UI can call. Actions on VMs, hosts and the app go to the command bus; the rest
//! are reads, plus app settings (which are audited by the core).

use std::path::PathBuf;

use remotely_core::adapters::updater::UpdateInfo;
use remotely_core::command_bus::{ApprovalAnswers, Command, SubmitOutcome};
use remotely_core::inventory::{RefreshReport, VmFilter};
use remotely_core::policy::PolicyRules;
use remotely_core::store::{AuditEntry, ChainCheck, JobSummary, SavedFilter, Tag, VmRecord};
use remotely_core::{Core, CoreError};
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use crate::AppState;

/// Error shape the UI receives: a stable code plus a readable message.
#[derive(Debug, Serialize)]
pub struct IpcError {
    code: &'static str,
    message: String,
}

impl From<CoreError> for IpcError {
    fn from(err: CoreError) -> Self {
        Self {
            code: err.code(),
            message: err.to_string(),
        }
    }
}

type IpcResult<T> = Result<T, IpcError>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: &'static str,
    workspace_id: String,
    user_id: String,
    vmrun_path: Option<String>,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    let core = &state.core;
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        workspace_id: core.ctx.workspace_id.to_string(),
        user_id: core.ctx.user_id.to_string(),
        vmrun_path: core.vmrun_path().map(|p| p.display().to_string()),
    }
}

/// VM-01: finds every VM (Workstation's library, the chosen folders, `vmrun list`), saves the result
/// and returns it with any sources that could not be read.
#[tauri::command]
pub async fn vm_refresh(state: State<'_, AppState>) -> IpcResult<RefreshReport> {
    let core = &state.core;
    let report = core.inventory.refresh(&core.ctx).await?;
    tracing::info!(
        vms = report.vms.len(),
        warnings = report.warnings.len(),
        "inventory refresh"
    );
    Ok(report)
}

/// VM-01, VM-02: the VMs the last refresh found that match the filter (all of them without one),
/// without asking Workstation.
#[tauri::command]
pub async fn vm_list(state: State<'_, AppState>, filter: Option<VmFilter>) -> IpcResult<Vec<VmRecord>> {
    let core = &state.core;
    Ok(core.inventory.list(&core.ctx, &filter.unwrap_or_default()).await?)
}

/// VM-02: tags are the app's own labels for picking VMs; they change no VM, so they skip the bus.
#[tauri::command]
pub async fn tags_list(state: State<'_, AppState>) -> IpcResult<Vec<Tag>> {
    let core = &state.core;
    Ok(core.store.list_tags(&core.ctx).await?)
}

#[tauri::command]
pub async fn vm_tag(state: State<'_, AppState>, vmx_paths: Vec<String>, tag: String) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.store.tag_vms(&core.ctx, &vmx_paths, &tag).await?)
}

#[tauri::command]
pub async fn vm_untag(state: State<'_, AppState>, vmx_paths: Vec<String>, tag: String) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.store.untag_vms(&core.ctx, &vmx_paths, &tag).await?)
}

#[tauri::command]
pub async fn tag_delete(state: State<'_, AppState>, tag: String) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.store.delete_tag(&core.ctx, &tag).await?)
}

/// VM-02: saved filters, for selecting the same VMs again.
#[tauri::command]
pub async fn filters_list(state: State<'_, AppState>) -> IpcResult<Vec<SavedFilter>> {
    let core = &state.core;
    Ok(core.store.list_saved_filters(&core.ctx).await?)
}

/// Saving under an existing name replaces that filter.
#[tauri::command]
pub async fn filter_save(state: State<'_, AppState>, name: String, filter: VmFilter) -> IpcResult<SavedFilter> {
    let core = &state.core;
    Ok(core.store.save_filter(&core.ctx, &name, &filter).await?)
}

#[tauri::command]
pub async fn filter_delete(state: State<'_, AppState>, id: String) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.store.delete_saved_filter(&core.ctx, &id).await?)
}

/// The one way in for changes: command bus -> policy engine -> (approval) -> job runner.
#[tauri::command]
pub async fn command_submit(state: State<'_, AppState>, command: Command) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.bus.submit(&core.ctx, command).await?)
}

#[tauri::command]
pub async fn command_approve(
    state: State<'_, AppState>,
    request_id: Uuid,
    answers: ApprovalAnswers,
) -> IpcResult<Uuid> {
    Ok(state.core.bus.approve(request_id, answers).await?)
}

#[tauri::command]
pub async fn command_cancel_approval(state: State<'_, AppState>, request_id: Uuid) -> IpcResult<()> {
    Ok(state.core.bus.cancel_approval(request_id).await?)
}

#[tauri::command]
pub fn job_cancel(state: State<'_, AppState>, job_id: Uuid) -> bool {
    state.core.jobs.cancel(job_id)
}

#[tauri::command]
pub async fn jobs_recent(state: State<'_, AppState>, limit: Option<u32>) -> IpcResult<Vec<JobSummary>> {
    let core = &state.core;
    Ok(core.store.recent_jobs(&core.ctx, limit.unwrap_or(50)).await?)
}

#[tauri::command]
pub fn policy_rules(state: State<'_, AppState>) -> PolicyRules {
    state.core.bus.rules()
}

/// AP-05: newest audit entries first.
#[tauri::command]
pub async fn audit_recent(state: State<'_, AppState>, limit: Option<u32>) -> IpcResult<Vec<AuditEntry>> {
    let core = &state.core;
    Ok(core.store.recent_audit(&core.ctx, limit.unwrap_or(100)).await?)
}

#[tauri::command]
pub async fn audit_verify(state: State<'_, AppState>) -> IpcResult<ChainCheck> {
    Ok(state.core.store.verify_audit_chain().await?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// What the user chose; `None` means "find vmrun.exe automatically".
    vmrun_path_saved: Option<String>,
    /// What the app is using now; `None` means Workstation was not found.
    vmrun_path_in_use: Option<String>,
    /// FD-14: check GitHub Releases for updates (off at air-gapped sites).
    update_checks: bool,
    /// VM-01: folders scanned for .vmx files, besides Workstation's library.
    scan_folders: Vec<String>,
}

async fn settings(core: &Core) -> IpcResult<Settings> {
    Ok(Settings {
        vmrun_path_saved: core.saved_vmrun_path().await?.map(|p| p.display().to_string()),
        vmrun_path_in_use: core.vmrun_path().map(|p| p.display().to_string()),
        update_checks: core.update_checks_enabled().await?,
        scan_folders: core
            .scan_folders()
            .await?
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
    })
}

#[tauri::command]
pub async fn settings_get(state: State<'_, AppState>) -> IpcResult<Settings> {
    settings(&state.core).await
}

/// `None` or an empty string goes back to finding vmrun.exe automatically.
#[tauri::command]
pub async fn settings_set_vmrun_path(state: State<'_, AppState>, path: Option<String>) -> IpcResult<Settings> {
    let path = path
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    state.core.set_vmrun_path(path).await?;
    settings(&state.core).await
}

/// VM-01: the folders to scan for .vmx files. Each must exist.
#[tauri::command]
pub async fn settings_set_scan_folders(state: State<'_, AppState>, folders: Vec<String>) -> IpcResult<Settings> {
    let folders = folders
        .iter()
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .map(PathBuf::from)
        .collect();
    state.core.set_scan_folders(folders).await?;
    settings(&state.core).await
}

/// FD-14: turn update checks off (air-gapped sites) or back on.
#[tauri::command]
pub async fn settings_set_update_checks(state: State<'_, AppState>, enabled: bool) -> IpcResult<Settings> {
    state.core.set_update_checks(enabled).await?;
    settings(&state.core).await
}

/// FD-14: asks GitHub Releases for a newer signed version. `None` when up to date or when checks
/// are off. Installing is the `appUpdate` command, through the command bus.
#[tauri::command]
pub async fn update_check(state: State<'_, AppState>) -> IpcResult<Option<UpdateInfo>> {
    Ok(state.core.check_for_update().await?)
}
