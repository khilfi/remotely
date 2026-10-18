//! Core of Remotely. Holds no Tauri types, so a CLI or plugin host (FD-12) can reuse it.
//!
//! ```text
//!   UI / CLI / plugins
//!        │ reads                         │ changes
//!        ▼                               ▼
//!   inventory, snapshots,          command_bus ──► policy (tier + steps)
//!   metrics (in memory)                  │  impact preview, approvals, audit
//!                                        │  vault (AP-06 re-auth)
//!                                        ▼
//!                                   jobs (runner) ──► adapters::vmware (vmrun)
//!                                                 ├─► adapters::remote (russh)
//!                                                 └─► adapters::updater (FD-14)
//!
//!   sessions (SS-01), vault (SS-04), known_hosts (SS-05): the app's own data; changes are audited
//!   terminal (SS-03): interactive SSH panes ──► adapters::remote; opening and closing are audited
//!   bulk (BX-01, BX-03, BX-05): targets, grouped results, diffs and exports of remote command runs
//! ```
//!
//! Only [`command_bus::CommandBus`] can enqueue jobs, and adapters are only reachable through the job
//! runner (changes) or [`inventory::Inventory`] and [`metrics`] (reads).

pub mod adapters;
pub mod bulk;
pub mod capacity;
pub mod command_bus;
pub mod domain;
pub mod error;
pub mod export;
#[cfg(any(test, feature = "fakes"))]
pub mod fakes;
pub mod impact;
pub mod import;
pub mod inventory;
pub mod jobs;
pub mod known_hosts;
pub mod locks;
pub mod metrics;
pub mod policy;
pub mod sessions;
pub mod snapshots;
pub mod store;
pub mod terminal;
pub mod vault;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use adapters::host_counters::{HostCounters, WindowsCounters};
use adapters::remote::{RemoteAdapter, RusshAdapter};
use adapters::updater::{UpdateInfo, UpdaterAdapter};
use adapters::vmware::{SwitchableVmware, VmwareAdapter};
use bulk::BulkRuns;
use capacity::CapacityChecker;
use command_bus::CommandBus;
use domain::Context;
use impact::ImpactPreviewer;
use import::Importer;
use inventory::{Inventory, StoreDirectory};
use jobs::{JobLimits, JobRunner};
use known_hosts::KnownHosts;
use metrics::{GuestSource, Metrics, MetricsParts};
use policy::{PolicyEngine, PolicyRules};
use serde::Serialize;
use sessions::SessionLibrary;
use snapshots::SnapshotReader;
use store::{NewAuditEntry, Store};
use terminal::{TerminalSettings, Terminals, TERMINAL_SETTINGS_KEY};
use vault::{Dpapi, LocalVault, Vault, VaultOptions, VaultService};

pub use error::{CoreError, Result};

pub struct CoreConfig {
    pub db_path: PathBuf,
    /// Full path to vmrun.exe. Overrides the path saved in Settings; when neither is set,
    /// `REMOTELY_VMRUN`, the registry and the default install folders are tried.
    pub vmrun_path: Option<PathBuf>,
    /// Windows account (DOMAIN\user) that owns the data.
    pub account: String,
    pub display_name: String,
    /// FD-14. The shell passes the Tauri updater; [`adapters::updater::DisabledUpdater`] otherwise.
    pub updater: Arc<dyn UpdaterAdapter>,
}

/// The outside systems the core talks to: the real ones in the app, fakes in tests.
pub struct Adapters {
    pub vmware: Arc<dyn VmwareAdapter>,
    pub remote: Arc<dyn RemoteAdapter>,
    pub vault: Arc<dyn Vault>,
    pub host_counters: Arc<dyn HostCounters>,
    pub updater: Arc<dyn UpdaterAdapter>,
}

/// AP-05: what an audit export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExport {
    pub path: String,
    pub entries: usize,
    /// Rows with something that looked like a secret, replaced by `[redacted]`.
    pub redacted: usize,
}

pub struct Core {
    pub ctx: Context,
    pub store: Store,
    pub inventory: Inventory,
    /// VM-04: snapshot trees, read from each VM's .vmsd. Changes go through [`Core::bus`].
    pub snapshots: SnapshotReader,
    pub bus: CommandBus,
    pub jobs: Arc<JobRunner>,
    /// SS-04: set up, unlock, lock and the secrets' labels. Values go in, never out.
    pub vault: VaultService,
    /// SS-01, SS-06: saved sessions and their folders.
    pub sessions: SessionLibrary,
    /// SS-02: session lists from PuTTY, MobaXterm, OpenSSH and CSV.
    pub import: Importer,
    /// SS-05: trusted SSH host keys.
    pub known_hosts: Arc<KnownHosts>,
    /// SS-03: open terminal panes and their SSH connections.
    pub terminals: Terminals,
    /// BX-01, BX-03, BX-05: bulk run targets, results, diffs and exports. Running is the bus.
    pub bulk: BulkRuns,
    /// MO-01 to MO-04: host-side and guest metrics, history in memory, host capacity. Reads only.
    /// The shell starts its polling with [`Metrics::run`].
    pub metrics: Arc<Metrics>,
    pub host_counters: Arc<dyn HostCounters>,
    updater: Arc<dyn UpdaterAdapter>,
    vmware: Arc<SwitchableVmware>,
}

impl Core {
    pub async fn init(config: CoreConfig) -> Result<Self> {
        let store = Store::open(&config.db_path).await?;
        let interrupted = store.mark_interrupted_jobs().await?;
        if interrupted > 0 {
            tracing::warn!(interrupted, "jobs were open when the app last stopped");
        }
        let ctx = store.ensure_identity(&config.account, &config.display_name).await?;
        let saved = saved_vmrun_path(&store, &ctx).await?;
        let vmware: Arc<dyn VmwareAdapter> = Arc::from(adapters::vmware::connect(config.vmrun_path.or(saved)));
        // SS-04: the vault in this database, unlocked by the Windows login (DPAPI) or the master password.
        let vault = LocalVault::open(store.clone(), ctx, Arc::new(Dpapi), VaultOptions::default()).await?;
        Self::assemble(
            store,
            ctx,
            Adapters {
                vmware,
                remote: Arc::new(RusshAdapter::new()),
                vault: Arc::new(vault),
                host_counters: Arc::new(WindowsCounters::new()),
                updater: config.updater,
            },
            JobLimits::default(),
        )
        .await
    }

    /// Wires the modules together. Tests pass fake adapters here.
    pub async fn assemble(store: Store, ctx: Context, adapters: Adapters, limits: JobLimits) -> Result<Self> {
        let policy = load_policy(&store, &ctx).await?;
        let vmware = Arc::new(SwitchableVmware::new(adapters.vmware));
        let vmware_dyn: Arc<dyn VmwareAdapter> = vmware.clone();
        let known_hosts = Arc::new(KnownHosts::new(store.clone()));
        let terminals = Terminals::new(
            store.clone(),
            Arc::clone(&adapters.vault),
            Arc::clone(&adapters.remote),
            Arc::clone(&known_hosts),
        );
        // MO-01 to MO-04: reads only, so the collector holds adapters directly, not the job runner.
        let metrics = Arc::new(Metrics::new(MetricsParts {
            store: store.clone(),
            ctx,
            counters: Arc::clone(&adapters.host_counters),
            guest: GuestSource::new(
                store.clone(),
                ctx,
                Arc::clone(&adapters.remote),
                Arc::clone(&adapters.vault),
                Arc::clone(&known_hosts),
            ),
            capacity: CapacityChecker::new(
                store.clone(),
                Arc::clone(&vmware_dyn),
                Arc::clone(&adapters.host_counters),
            ),
        }));
        let jobs = JobRunner::new(
            store.clone(),
            Arc::clone(&vmware_dyn),
            adapters.remote,
            Arc::clone(&adapters.updater),
            Arc::clone(&adapters.vault),
            Arc::clone(&known_hosts),
            limits,
        );
        let bus = CommandBus::new(
            policy,
            Arc::new(StoreDirectory::new(store.clone())),
            Arc::clone(&jobs),
            store.clone(),
            Arc::clone(&adapters.vault),
            CapacityChecker::new(
                store.clone(),
                Arc::clone(&vmware_dyn),
                Arc::clone(&adapters.host_counters),
            ),
            ImpactPreviewer::new(store.clone(), Arc::clone(&vmware_dyn)),
        );
        if let Some(limit) = store.get_setting::<usize>(&ctx, store::POWER_ON_LIMIT_KEY).await? {
            jobs.set_power_on_limit(limit.clamp(1, JobLimits::MAX_POWER_ON));
        }
        if let Some(secs) = store.get_setting::<u64>(&ctx, store::SHUTDOWN_WAIT_KEY).await? {
            jobs.set_shutdown_wait(Duration::from_secs(secs.clamp(1, JobLimits::MAX_SHUTDOWN_WAIT_SECS)));
        }
        if let Some(limit) = store.get_setting::<usize>(&ctx, store::REMOTE_LIMIT_KEY).await? {
            jobs.set_remote_limit(limit.clamp(1, JobLimits::MAX_REMOTE));
        }
        Ok(Self {
            ctx,
            snapshots: SnapshotReader::new(store.clone(), Arc::clone(&vmware_dyn)),
            inventory: Inventory::new(store.clone(), vmware_dyn),
            vault: VaultService::new(adapters.vault, store.clone()),
            sessions: SessionLibrary::new(store.clone()),
            import: Importer::new(store.clone()),
            known_hosts,
            terminals,
            bulk: BulkRuns::new(store.clone()),
            metrics,
            store,
            bus,
            jobs,
            host_counters: adapters.host_counters,
            updater: adapters.updater,
            vmware,
        })
    }

    /// Path of the vmrun.exe in use, or `None` when Workstation was not found.
    pub fn vmrun_path(&self) -> Option<PathBuf> {
        self.vmware.tool_path()
    }

    /// The vmrun path saved in Settings, if any.
    pub async fn saved_vmrun_path(&self) -> Result<Option<PathBuf>> {
        saved_vmrun_path(&self.store, &self.ctx).await
    }

    /// Saves the vmrun path (`None` = find it automatically) and switches to it right away. The path
    /// must be an existing vmrun.exe. Audited, since it decides which program runs every VM action.
    pub async fn set_vmrun_path(&self, path: Option<PathBuf>) -> Result<Option<PathBuf>> {
        if let Some(path) = &path {
            adapters::vmware::validate_vmrun_path(path)?;
        }
        let as_text = path.as_ref().map(|p| p.display().to_string());
        self.store
            .put_setting(&self.ctx, store::VMRUN_PATH_KEY, &as_text)
            .await?;
        self.vmware.replace(Arc::from(adapters::vmware::connect(path)));
        let in_use = self.vmrun_path();
        let detail = format!(
            "saved: {}; in use: {}",
            as_text.as_deref().unwrap_or("find automatically"),
            in_use
                .as_ref()
                .map_or_else(|| "not found".to_owned(), |p| p.display().to_string())
        );
        self.audit_setting("Set the vmrun.exe path", &detail).await?;
        Ok(in_use)
    }

    /// VM-01: folders scanned for .vmx files, besides Workstation's library.
    pub async fn scan_folders(&self) -> Result<Vec<PathBuf>> {
        self.inventory.scan_folders(&self.ctx).await
    }

    /// VM-01: replaces the folders to scan. Each must be an existing folder; duplicates (any letter
    /// case) are dropped. Audited.
    pub async fn set_scan_folders(&self, folders: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
        let mut seen = std::collections::HashSet::new();
        let mut kept = Vec::new();
        for folder in folders {
            if !folder.is_dir() {
                return Err(CoreError::InvalidSetting(format!(
                    "{} is not an existing folder",
                    folder.display()
                )));
            }
            if seen.insert(adapters::vmware::path_key(&folder)) {
                kept.push(folder);
            }
        }
        let as_text: Vec<String> = kept.iter().map(|p| p.display().to_string()).collect();
        self.store
            .put_setting(&self.ctx, store::SCAN_FOLDERS_KEY, &as_text)
            .await?;
        let detail = if as_text.is_empty() {
            "none".to_owned()
        } else {
            as_text.join("; ")
        };
        self.audit_setting("Set the VM folders to scan", &detail).await?;
        Ok(kept)
    }

    /// VM-06: how many VMs may power on at once (default 3).
    pub fn power_on_limit(&self) -> usize {
        self.jobs.limits().power_on
    }

    /// VM-06: 1 to [`JobLimits::MAX_POWER_ON`]. Applies from the next job on. Audited.
    pub async fn set_power_on_limit(&self, limit: usize) -> Result<()> {
        if !(1..=JobLimits::MAX_POWER_ON).contains(&limit) {
            return Err(CoreError::InvalidSetting(format!(
                "VMs powered on at once must be 1 to {}",
                JobLimits::MAX_POWER_ON
            )));
        }
        self.store
            .put_setting(&self.ctx, store::POWER_ON_LIMIT_KEY, &limit)
            .await?;
        self.jobs.set_power_on_limit(limit);
        self.audit_setting("Set the parallel power-on limit", &limit.to_string())
            .await
    }

    /// VM-03: seconds a soft stop may take before the VM counts as still running (default 120).
    pub fn shutdown_wait_secs(&self) -> u64 {
        self.jobs.limits().shutdown_wait.as_secs()
    }

    /// VM-03: 1 to [`JobLimits::MAX_SHUTDOWN_WAIT_SECS`]. Applies from the next stop on. Audited.
    pub async fn set_shutdown_wait_secs(&self, secs: u64) -> Result<()> {
        if !(1..=JobLimits::MAX_SHUTDOWN_WAIT_SECS).contains(&secs) {
            return Err(CoreError::InvalidSetting(format!(
                "the shutdown wait must be 1 to {} seconds",
                JobLimits::MAX_SHUTDOWN_WAIT_SECS
            )));
        }
        self.store
            .put_setting(&self.ctx, store::SHUTDOWN_WAIT_KEY, &secs)
            .await?;
        self.jobs.set_shutdown_wait(Duration::from_secs(secs));
        self.audit_setting("Set the shutdown wait", &format!("{secs} s")).await
    }

    /// BX-02: how many hosts a bulk run reaches at once (default 10).
    pub fn bulk_parallel_limit(&self) -> usize {
        self.jobs.limits().remote
    }

    /// BX-02: 1 to [`JobLimits::MAX_REMOTE`]. Applies from the next run on. Audited.
    pub async fn set_bulk_parallel_limit(&self, limit: usize) -> Result<()> {
        if !(1..=JobLimits::MAX_REMOTE).contains(&limit) {
            return Err(CoreError::InvalidSetting(format!(
                "hosts at once must be 1 to {}",
                JobLimits::MAX_REMOTE
            )));
        }
        self.store
            .put_setting(&self.ctx, store::REMOTE_LIMIT_KEY, &limit)
            .await?;
        self.jobs.set_remote_limit(limit);
        self.audit_setting("Set the hosts a bulk run reaches at once", &limit.to_string())
            .await
    }

    /// FD-14: whether update checks are on. Defaults to on.
    pub async fn update_checks_enabled(&self) -> Result<bool> {
        Ok(self
            .store
            .get_setting::<bool>(&self.ctx, store::UPDATE_CHECKS_KEY)
            .await?
            .unwrap_or(true))
    }

    /// FD-14: turns update checks off (air-gapped sites) or back on. Audited.
    pub async fn set_update_checks(&self, enabled: bool) -> Result<()> {
        self.store
            .put_setting(&self.ctx, store::UPDATE_CHECKS_KEY, &enabled)
            .await?;
        let detail = if enabled { "on" } else { "off" };
        self.audit_setting("Set update checks", detail).await
    }

    /// FD-14: a read, so it skips the bus. Installing is [`command_bus::Command::AppUpdate`]. With
    /// update checks turned off this makes no network call and returns `None`.
    pub async fn check_for_update(&self) -> Result<Option<UpdateInfo>> {
        if !self.update_checks_enabled().await? {
            return Ok(None);
        }
        self.updater.check().await
    }

    /// AP-05: writes the workspace's whole audit log to `path` as CSV (see [`export::audit_csv`]) and
    /// logs that it did. A read, so it skips the bus.
    pub async fn export_audit_csv(&self, path: &Path) -> Result<AuditExport> {
        let entries = self.store.audit_for_export(&self.ctx).await?;
        let (csv, redacted) = export::audit_csv(&entries);
        tokio::fs::write(path, csv).await?;
        let file = path
            .file_name()
            .map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned());
        self.store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event: "audit_exported",
                    action: "Exported the audit log to CSV",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&format!("{} entries to {file}", entries.len())),
                },
            )
            .await?;
        Ok(AuditExport {
            path: path.display().to_string(),
            entries: entries.len(),
            redacted,
        })
    }

    async fn audit_setting(&self, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }

    /// SS-03: keep-alive, auto-reconnect and copy-on-select.
    pub async fn terminal_settings(&self) -> Result<TerminalSettings> {
        self.terminals.settings(&self.ctx).await
    }

    /// SS-03: applies to terminals opened from now on. Audited.
    pub async fn set_terminal_settings(&self, settings: TerminalSettings) -> Result<()> {
        settings.validate()?;
        self.store
            .put_setting(&self.ctx, TERMINAL_SETTINGS_KEY, &settings)
            .await?;
        self.audit_setting("Set the terminal settings", &settings.describe())
            .await
    }
}

/// AP-01: the saved rules, with defaults for actions added since they were saved. Saved rules that
/// no longer pass the checks (say, a check added in an update) are replaced by the defaults rather
/// than stopping the app from starting; the audit log says so.
async fn load_policy(store: &Store, ctx: &Context) -> Result<PolicyEngine> {
    let Some(mut rules) = store.get_setting::<PolicyRules>(ctx, store::POLICY_RULES_KEY).await? else {
        return PolicyEngine::new(PolicyRules::default());
    };
    rules.fill_missing_tiers();
    match PolicyEngine::new(rules) {
        Ok(engine) => Ok(engine),
        Err(err) => {
            tracing::error!(error = %err, "saved approval rules are invalid; using the defaults");
            let detail = format!("the saved rules were not valid ({err}); the default rules apply");
            store
                .append_audit(
                    ctx,
                    NewAuditEntry {
                        event: "setting_changed",
                        action: "Reset the approval rules to the defaults",
                        tier: None,
                        job_id: None,
                        targets: &[],
                        approval: None,
                        result: None,
                        detail: Some(&detail),
                    },
                )
                .await?;
            let defaults = PolicyRules::default();
            store.put_setting(ctx, store::POLICY_RULES_KEY, &defaults).await?;
            PolicyEngine::new(defaults)
        }
    }
}

async fn saved_vmrun_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store.get_setting::<Option<String>>(ctx, store::VMRUN_PATH_KEY).await?;
    Ok(saved.flatten().map(PathBuf::from))
}
