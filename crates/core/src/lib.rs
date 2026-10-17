//! Core of Remotely. Holds no Tauri types, so a CLI or plugin host (FD-12) can reuse it.
//!
//! ```text
//!   UI / CLI / plugins
//!        │ reads                         │ changes
//!        ▼                               ▼
//!   inventory, metrics ──► store    command_bus ──► policy (tier + steps)
//!                                        │  approvals, audit
//!                                        ▼
//!                                   jobs (runner) ──► adapters::vmware (vmrun)
//!                                                 ├─► adapters::remote (russh)
//!                                                 └─► adapters::updater (FD-14)
//! ```
//!
//! Only [`command_bus::CommandBus`] can enqueue jobs, and adapters are only reachable through the job
//! runner (changes) or [`inventory::Inventory`] and [`metrics`] (reads).

pub mod adapters;
pub mod command_bus;
pub mod domain;
pub mod error;
#[cfg(any(test, feature = "fakes"))]
pub mod fakes;
pub mod inventory;
pub mod jobs;
pub mod locks;
pub mod metrics;
pub mod policy;
pub mod store;
pub mod vault;

use std::path::PathBuf;
use std::sync::Arc;

use adapters::host_counters::{HostCounters, WindowsCounters};
use adapters::remote::{RemoteAdapter, RusshAdapter, ShellHandle};
use adapters::updater::{UpdateInfo, UpdaterAdapter};
use adapters::vmware::{SwitchableVmware, VmwareAdapter};
use command_bus::CommandBus;
use domain::Context;
use inventory::{Inventory, StoreDirectory};
use jobs::{JobLimits, JobRunner};
use policy::{PolicyEngine, PolicyRules};
use store::{NewAuditEntry, Store};
use vault::{UnimplementedVault, Vault};

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

pub struct Core {
    pub ctx: Context,
    pub store: Store,
    pub inventory: Inventory,
    pub bus: CommandBus,
    pub jobs: Arc<JobRunner>,
    pub vault: Arc<dyn Vault>,
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
        Self::assemble(
            store,
            ctx,
            Adapters {
                vmware,
                remote: Arc::new(RusshAdapter::new()),
                vault: Arc::new(UnimplementedVault),
                host_counters: Arc::new(WindowsCounters),
                updater: config.updater,
            },
            JobLimits::default(),
        )
        .await
    }

    /// Wires the modules together. Tests pass fake adapters here.
    pub async fn assemble(store: Store, ctx: Context, adapters: Adapters, limits: JobLimits) -> Result<Self> {
        let rules = store
            .get_setting::<PolicyRules>(&ctx, store::POLICY_RULES_KEY)
            .await?
            .unwrap_or_default();
        let policy = PolicyEngine::new(rules)?;
        let vmware = Arc::new(SwitchableVmware::new(adapters.vmware));
        let vmware_dyn: Arc<dyn VmwareAdapter> = vmware.clone();
        let jobs = JobRunner::new(
            store.clone(),
            Arc::clone(&vmware_dyn),
            adapters.remote,
            Arc::clone(&adapters.updater),
            limits,
        );
        let bus = CommandBus::new(
            policy,
            Arc::new(StoreDirectory::new(store.clone())),
            Arc::clone(&jobs),
            store.clone(),
            Arc::clone(&adapters.vault),
        );
        Ok(Self {
            ctx,
            inventory: Inventory::new(store.clone(), vmware_dyn),
            store,
            bus,
            jobs,
            vault: adapters.vault,
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
        self.store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action: "Set the vmrun.exe path",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        Ok(in_use)
    }

    /// FD-14: a read, so it skips the bus. Installing is [`command_bus::Command::AppUpdate`].
    pub async fn check_for_update(&self) -> Result<Option<UpdateInfo>> {
        self.updater.check().await
    }

    /// Opens a terminal. Until SS-03 this is a local loopback shell, not SSH.
    pub fn open_terminal(&self) -> ShellHandle {
        adapters::remote::loopback_shell()
    }
}

async fn saved_vmrun_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store.get_setting::<Option<String>>(ctx, store::VMRUN_PATH_KEY).await?;
    Ok(saved.flatten().map(PathBuf::from))
}
