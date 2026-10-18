//! IPC commands the UI can call. Actions on VMs, hosts and the app go to the command bus; the rest
//! are reads, plus the app's own data (settings, the vault, the session library), which the core
//! audits.

use std::path::PathBuf;

use remotely_core::adapters::updater::UpdateInfo;
use remotely_core::command_bus::{ApprovalAnswers, Command, SubmitOutcome, MAX_SNAPSHOT_NAME};
use remotely_core::inventory::{RefreshReport, VmFilter};
use remotely_core::policy::{ActionKind, PolicyRules, MAX_BULK_THRESHOLD, MAX_COUNTDOWN_SECONDS};
use remotely_core::sessions::{SessionFilter, SessionFolder, SessionInput, SessionRecord};
use remotely_core::snapshots::{VmSnapshots, OLD_AFTER_DAYS, SAFETY_PREFIX};
use remotely_core::store::{AuditEntry, ChainCheck, JobSummary, JobTargetRecord, SavedFilter, Tag, VmRecord};
use remotely_core::vault::{SecretId, SecretKind, SecretMeta, SecretString, UnlockMethod, VaultInfo, MAX_SECRET_BYTES};
use remotely_core::{AuditExport, Core, CoreError};
use serde::Serialize;
use tauri::{State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use zeroize::Zeroize;

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

/// A job's results per target, with the safety snapshot taken on each (VM-05).
#[tauri::command]
pub async fn job_targets(state: State<'_, AppState>, job_id: Uuid) -> IpcResult<Vec<JobTargetRecord>> {
    let core = &state.core;
    Ok(core.store.job_targets(&core.ctx, job_id).await?)
}

/// VM-04: snapshot trees read from each VM's .vmsd (a read, so no bus). `None` lists every VM the
/// last refresh found. Taking, reverting and deleting go through `command_submit`.
#[tauri::command]
pub async fn snapshots_list(state: State<'_, AppState>, vmx_paths: Option<Vec<String>>) -> IpcResult<Vec<VmSnapshots>> {
    let core = &state.core;
    Ok(core.snapshots.list(&core.ctx, vmx_paths.as_deref()).await?)
}

/// Fixed facts the snapshot manager shows and checks against.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotLimits {
    old_after_days: i64,
    safety_prefix: &'static str,
    max_name_length: usize,
}

#[tauri::command]
pub fn snapshot_limits() -> SnapshotLimits {
    SnapshotLimits {
        old_after_days: OLD_AFTER_DAYS,
        safety_prefix: SAFETY_PREFIX,
        max_name_length: MAX_SNAPSHOT_NAME,
    }
}

#[tauri::command]
pub fn policy_rules(state: State<'_, AppState>) -> PolicyRules {
    state.core.bus.rules()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionInfo {
    kind: ActionKind,
    label: &'static str,
}

/// AP-01: what the rules editor needs besides the rules: every action with its label, the
/// defaults (for "Reset to defaults") and the bounds the core checks.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCatalog {
    actions: Vec<ActionInfo>,
    defaults: PolicyRules,
    max_bulk_threshold: usize,
    max_countdown_seconds: u32,
}

#[tauri::command]
pub fn policy_catalog() -> PolicyCatalog {
    PolicyCatalog {
        actions: ActionKind::ALL
            .iter()
            .map(|&kind| ActionInfo {
                kind,
                label: kind.label(),
            })
            .collect(),
        defaults: PolicyRules::default(),
        max_bulk_threshold: MAX_BULK_THRESHOLD,
        max_countdown_seconds: MAX_COUNTDOWN_SECONDS,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySaved {
    rules: PolicyRules,
    /// What changed, as written to the audit log. Empty: nothing was saved.
    changes: Vec<String>,
}

/// AP-01: saves edited tier rules through the command bus, which checks them (an invalid rule comes
/// back as `invalid_rule` with the reason) and audits the change.
#[tauri::command]
pub async fn policy_set_rules(state: State<'_, AppState>, rules: PolicyRules) -> IpcResult<PolicySaved> {
    let core = &state.core;
    let changes = core.bus.set_rules(&core.ctx, rules).await?;
    Ok(PolicySaved {
        rules: core.bus.rules(),
        changes,
    })
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

/// AP-05: asks where to save, then writes the whole audit log there as CSV. The save dialog opens
/// here, not in the UI, so a file is only ever written where the user chose. `None` when the user
/// closed the dialog.
#[tauri::command]
pub async fn audit_export_csv(window: WebviewWindow, state: State<'_, AppState>) -> IpcResult<Option<AuditExport>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Export the audit log")
        .set_file_name(remotely_core::export::audit_file_name())
        .add_filter("CSV", &["csv"])
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't save there: {err}")))?;
    let report = state.core.export_audit_csv(&path).await?;
    tracing::info!(entries = report.entries, "audit log exported");
    Ok(Some(report))
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
    /// VM-06: how many VMs may power on at once.
    power_on_limit: usize,
    /// VM-03: seconds a soft stop may take before the VM counts as still running.
    shutdown_wait_secs: u64,
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
        power_on_limit: core.power_on_limit(),
        shutdown_wait_secs: core.shutdown_wait_secs(),
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

/// VM-06: how many VMs may power on at once.
#[tauri::command]
pub async fn settings_set_power_on_limit(state: State<'_, AppState>, limit: usize) -> IpcResult<Settings> {
    state.core.set_power_on_limit(limit).await?;
    settings(&state.core).await
}

/// VM-03: seconds a soft stop may take before the VM counts as still running.
#[tauri::command]
pub async fn settings_set_shutdown_wait(state: State<'_, AppState>, secs: u64) -> IpcResult<Settings> {
    state.core.set_shutdown_wait_secs(secs).await?;
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

// ---- Vault (SS-04, AP-06) ----------------------------------------------------------------------
// Secret values come in as `SecretString`, which never prints and is zeroized when dropped, and go
// straight to the vault. Nothing here returns one: the UI gets IDs, labels and kinds only.

#[tauri::command]
pub fn vault_info(state: State<'_, AppState>) -> VaultInfo {
    state.core.vault.info()
}

/// SS-04: creates the vault, unlocked. The vault password is always set: Critical actions ask for
/// it again (AP-06). `windows_login` also lets the Windows login unlock it day to day.
#[tauri::command]
pub async fn vault_setup(
    state: State<'_, AppState>,
    password: SecretString,
    windows_login: bool,
) -> IpcResult<VaultInfo> {
    let core = &state.core;
    Ok(core.vault.setup(&core.ctx, password, windows_login).await?)
}

/// With a password, unlocks with it; without, with the Windows login.
#[tauri::command]
pub async fn vault_unlock(state: State<'_, AppState>, password: Option<SecretString>) -> IpcResult<VaultInfo> {
    let core = &state.core;
    let method = match password {
        Some(password) => UnlockMethod::MasterPassword(password),
        None => UnlockMethod::WindowsLogin,
    };
    Ok(core.vault.unlock(&core.ctx, method).await?)
}

#[tauri::command]
pub async fn vault_lock(state: State<'_, AppState>) -> IpcResult<VaultInfo> {
    let core = &state.core;
    Ok(core.vault.lock(&core.ctx).await?)
}

#[tauri::command]
pub async fn vault_change_password(
    state: State<'_, AppState>,
    current: SecretString,
    new: SecretString,
) -> IpcResult<VaultInfo> {
    let core = &state.core;
    Ok(core.vault.change_password(&core.ctx, &current, new).await?)
}

#[tauri::command]
pub async fn vault_set_windows_login(
    state: State<'_, AppState>,
    password: SecretString,
    enabled: bool,
) -> IpcResult<VaultInfo> {
    let core = &state.core;
    Ok(core.vault.set_windows_login(&core.ctx, &password, enabled).await?)
}

/// Labels and kinds, with how many sessions use each. Works while the vault is locked.
#[tauri::command]
pub async fn secrets_list(state: State<'_, AppState>) -> IpcResult<Vec<SecretMeta>> {
    let core = &state.core;
    Ok(core.vault.list(&core.ctx).await?)
}

#[tauri::command]
pub async fn secret_add(
    state: State<'_, AppState>,
    kind: SecretKind,
    label: String,
    value: SecretString,
) -> IpcResult<SecretMeta> {
    let core = &state.core;
    Ok(core.vault.add(&core.ctx, kind, &label, value).await?)
}

/// SS-04: asks for a private key file, then stores it in the vault. The dialog opens here and the
/// file is read here, so the key never passes through the UI. `label` empty: the file name. `None`
/// when the user closed the dialog.
#[tauri::command]
pub async fn secret_import_key(
    window: WebviewWindow,
    state: State<'_, AppState>,
    label: String,
) -> IpcResult<Option<SecretMeta>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose a private key file")
        .pick_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't read that file: {err}")))?;
    let label = match label.trim() {
        "" => path
            .file_name()
            .map_or_else(|| "private key".to_owned(), |n| n.to_string_lossy().into_owned()),
        given => given.to_owned(),
    };
    let key = read_key_file(&path).await?;
    let core = &state.core;
    Ok(Some(
        core.vault.add(&core.ctx, SecretKind::PrivateKey, &label, key).await?,
    ))
}

/// Reads a key file of at most [`MAX_SECRET_BYTES`] into a zeroizing secret.
async fn read_key_file(path: &std::path::Path) -> Result<SecretString, CoreError> {
    let size = tokio::fs::metadata(path).await?.len();
    if size > MAX_SECRET_BYTES as u64 {
        return Err(CoreError::InvalidInput(format!(
            "That file is larger than {} KB, too large for a private key.",
            MAX_SECRET_BYTES / 1024
        )));
    }
    let bytes = tokio::fs::read(path).await?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(SecretString::new(text)),
        Err(err) => {
            err.into_bytes().zeroize();
            Err(CoreError::InvalidInput(
                "That file is not a text key file (OpenSSH, PEM or PuTTY .ppk).".into(),
            ))
        }
    }
}

/// A new value for a secret; its label and the sessions using it stay.
#[tauri::command]
pub async fn secret_replace(state: State<'_, AppState>, id: SecretId, value: SecretString) -> IpcResult<SecretMeta> {
    let core = &state.core;
    Ok(core.vault.replace(&core.ctx, id, value).await?)
}

#[tauri::command]
pub async fn secret_rename(state: State<'_, AppState>, id: SecretId, label: String) -> IpcResult<SecretMeta> {
    let core = &state.core;
    Ok(core.vault.rename(&core.ctx, id, &label).await?)
}

/// Sessions that used it lose it.
#[tauri::command]
pub async fn secret_delete(state: State<'_, AppState>, id: SecretId) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.vault.delete(&core.ctx, id).await?)
}

// ---- Session library (SS-01, SS-06) -------------------------------------------------------------
// The app's own data: changes skip the command bus and are audited by the core.

#[tauri::command]
pub async fn sessions_list(state: State<'_, AppState>, filter: Option<SessionFilter>) -> IpcResult<Vec<SessionRecord>> {
    let core = &state.core;
    Ok(core.sessions.list(&core.ctx, &filter.unwrap_or_default()).await?)
}

#[tauri::command]
pub async fn session_folders(state: State<'_, AppState>) -> IpcResult<Vec<SessionFolder>> {
    let core = &state.core;
    Ok(core.sessions.folders(&core.ctx).await?)
}

#[tauri::command]
pub async fn session_create(state: State<'_, AppState>, input: SessionInput) -> IpcResult<SessionRecord> {
    let core = &state.core;
    Ok(core.sessions.create(&core.ctx, input).await?)
}

#[tauri::command]
pub async fn session_update(state: State<'_, AppState>, id: Uuid, input: SessionInput) -> IpcResult<SessionRecord> {
    let core = &state.core;
    Ok(core.sessions.update(&core.ctx, id, input).await?)
}

#[tauri::command]
pub async fn session_duplicate(state: State<'_, AppState>, id: Uuid) -> IpcResult<SessionRecord> {
    let core = &state.core;
    Ok(core.sessions.duplicate(&core.ctx, id).await?)
}

#[tauri::command]
pub async fn session_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.sessions.delete(&core.ctx, id).await?)
}

/// `folder_id: None` moves them to the top level.
#[tauri::command]
pub async fn sessions_move(state: State<'_, AppState>, ids: Vec<Uuid>, folder_id: Option<Uuid>) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.sessions.move_to(&core.ctx, &ids, folder_id).await?)
}

#[tauri::command]
pub async fn folder_create(
    state: State<'_, AppState>,
    name: String,
    parent_id: Option<Uuid>,
) -> IpcResult<SessionFolder> {
    let core = &state.core;
    Ok(core.sessions.create_folder(&core.ctx, &name, parent_id).await?)
}

#[tauri::command]
pub async fn folder_rename(state: State<'_, AppState>, id: Uuid, name: String) -> IpcResult<SessionFolder> {
    let core = &state.core;
    Ok(core.sessions.rename_folder(&core.ctx, id, &name).await?)
}

#[tauri::command]
pub async fn folder_move(state: State<'_, AppState>, id: Uuid, parent_id: Option<Uuid>) -> IpcResult<SessionFolder> {
    let core = &state.core;
    Ok(core.sessions.move_folder(&core.ctx, id, parent_id).await?)
}

/// Its sessions and subfolders move up to its parent.
#[tauri::command]
pub async fn folder_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.sessions.delete_folder(&core.ctx, id).await?)
}
