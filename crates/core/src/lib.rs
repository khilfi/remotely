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
//!                                   jobs (runner) ──► adapters::hypervisor ──► adapters::vmware (vmrun)
//!                                                 │                      └─► adapters::virtualbox (VBoxManage, VM-18)
//!                                                 ├─► adapters::remote (russh)
//!                                                 └─► adapters::updater (FD-14)
//!                                                       └─► adapters::github (token from the vault)
//!
//!   sessions (SS-01), vault (SS-04), known_hosts (SS-05): the app's own data; changes are audited
//!   transfer (FD-07): encrypted export and import of that data; ssh_keys (SS-09): keys in the vault
//!   (pushing one to hosts is a command on the bus)
//!   vm_links (QL-01): sessions linked to the VMs they reach, by IP (adapters::network) or by hand
//!   terminal (SS-03): interactive SSH panes ──► adapters::remote; opening and closing are audited
//!     quick connect (QL-02), host name and IP (QL-03 ──► adapters::network), output and logs (SS-11),
//!     vault passwords typed at a prompt (QL-06), long runs finishing (QL-07)
//!     MultiExec (SS-10): typed into several at once; each line's Enter is a command on the bus, and the
//!     job runner sends it to the terminals
//!     files (SS-08): SFTP on each terminal's connection; the shell's folder (OSC 7); downloads are
//!     audited reads, uploads are commands on the bus that the job runner carries out in the terminal
//!     jump hosts (SS-07): every SSH connection goes through the session's jump host chain
//!     tunnels (SS-07): saved port forwards (forwards) open on a terminal's connection; opening one is
//!     a command on the bus, which the job runner carries out in the terminal; closing is audited
//!   snippets (BX-08): favourite and built-in commands for the terminal, classified by the policy engine
//!   reachability (QL-04): background TCP checks of the sessions the tree shows ──► adapters::network
//!   bulk (BX-01, BX-03, BX-05): targets, grouped results, diffs and exports of remote command runs
//!     (the Terminal page's Compare output)
//!   containers (CT-01, CT-02): Docker and Podman on marked sessions, Docker Desktop on this PC
//!     ──► adapters::containers (their CLIs, over adapters::remote or on this PC); reads skip the bus,
//!     changes are commands on it that the job runner carries out there
//! ```
//!
//! Only [`command_bus::CommandBus`] can enqueue jobs, and adapters are only reachable through the job
//! runner (changes) or [`inventory::Inventory`] and [`metrics`] (reads).

pub mod adapters;
pub mod bulk;
pub mod capacity;
pub mod command_bus;
pub mod containers;
pub mod domain;
pub mod error;
pub mod export;
#[cfg(any(test, feature = "fakes"))]
pub mod fakes;
pub mod forwards;
pub mod host_details;
pub mod impact;
pub mod import;
pub mod inventory;
pub mod jobs;
pub mod known_hosts;
pub mod locks;
pub mod metrics;
pub mod policy;
pub mod presentation;
pub mod reachability;
pub mod sessions;
pub mod snapshots;
pub mod snippets;
pub mod ssh_keys;
pub mod store;
pub mod terminal;
pub mod transfer;
pub mod updates;
pub mod vault;
pub mod vm_links;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use adapters::containers::cli::{validate_docker_path, CliEngines};
use adapters::containers::ContainerEngines;
use adapters::host_counters::{HostCounters, WindowsCounters};
use adapters::hypervisor::Hypervisors;
use adapters::network::{NetworkAdapter, SystemNetwork};
use adapters::remote::{RemoteAdapter, RusshAdapter};
use adapters::updater::UpdaterAdapter;
use adapters::virtualbox::{SwitchableVirtualBox, VirtualBoxAdapter};
use adapters::vmware::{SwitchableVmware, VmwareAdapter};
use bulk::BulkRuns;
use capacity::CapacityChecker;
use command_bus::CommandBus;
use containers::Containers;
use domain::Context;
use forwards::Forwards;
use host_details::{HostDetails, HostDetailsParts, SpecsCollector};
use impact::ImpactPreviewer;
use import::Importer;
use inventory::{Inventory, StoreDirectory};
use jobs::{JobLimits, JobRunner};
use known_hosts::KnownHosts;
use metrics::{GuestSource, Metrics, MetricsParts};
use policy::{PolicyEngine, PolicyRules};
use presentation::{Change, PresentationMode};
use reachability::ReachabilityChecker;
use serde::Serialize;
use sessions::SessionLibrary;
use snapshots::SnapshotReader;
use snippets::Snippets;
use ssh_keys::KeyManager;
use store::{NewAuditEntry, Store};
use terminal::files::FileTransfers;
use terminal::multiexec::MultiExec;
use terminal::{TerminalSettings, Terminals, TERMINAL_SETTINGS_KEY};
use transfer::Transfer;
use vault::{Dpapi, LocalVault, Vault, VaultOptions, VaultService};
use vm_links::VmLinks;

pub use error::{CoreError, Result};

pub struct CoreConfig {
    pub db_path: PathBuf,
    /// Full path to vmrun.exe. Overrides the path saved in Settings; when neither is set,
    /// `REMOTELY_VMRUN`, the registry and the default install folders are tried.
    pub vmrun_path: Option<PathBuf>,
    /// VM-18: full path to VBoxManage.exe. Overrides the path saved in Settings; when neither is set,
    /// `REMOTELY_VBOXMANAGE`, the registry and the default install folder are tried.
    pub vboxmanage_path: Option<PathBuf>,
    /// Windows account (DOMAIN\user) that owns the data.
    pub account: String,
    pub display_name: String,
    /// FD-14. The shell passes the Tauri updater; [`adapters::updater::DisabledUpdater`] otherwise.
    pub updater: Arc<dyn UpdaterAdapter>,
}

/// The outside systems the core talks to: the real ones in the app, fakes in tests.
pub struct Adapters {
    pub vmware: Arc<dyn VmwareAdapter>,
    /// VM-18: Oracle VirtualBox through VBoxManage.
    pub virtualbox: Arc<dyn VirtualBoxAdapter>,
    pub remote: Arc<dyn RemoteAdapter>,
    pub vault: Arc<dyn Vault>,
    pub host_counters: Arc<dyn HostCounters>,
    pub updater: Arc<dyn UpdaterAdapter>,
    /// DNS lookups (QL-01 linking sessions to VMs, QL-03 host name and IP) and QL-04 reachability
    /// probes.
    pub network: Arc<dyn NetworkAdapter>,
    /// CT-01, CT-02: container engines: their CLIs over SSH and Docker Desktop's on this PC.
    pub containers: Arc<dyn ContainerEngines>,
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
    /// VM-04: snapshot trees, read from each VM's .vmsd (VirtualBox: `showvminfo`). Changes go
    /// through [`Core::bus`].
    pub snapshots: SnapshotReader,
    pub bus: Arc<CommandBus>,
    pub jobs: Arc<JobRunner>,
    /// SS-04: set up, unlock, lock and the secrets' labels. Values go in, never out.
    pub vault: VaultService,
    /// SS-01, SS-06: saved sessions and their folders.
    pub sessions: SessionLibrary,
    /// SS-07: each session's saved port forwards. Opening one is on [`Core::terminals`] (the bus).
    pub forwards: Forwards,
    /// QL-01: links between sessions and the VMs they reach, automatic (by IP) or chosen by hand.
    pub links: Arc<VmLinks>,
    /// SS-02: session lists from PuTTY, MobaXterm, OpenSSH and CSV.
    pub import: Importer,
    /// SS-05: trusted SSH host keys.
    pub known_hosts: Arc<KnownHosts>,
    /// SS-09: SSH keys in the vault. Pushing one to hosts goes through [`Core::bus`].
    pub keys: KeyManager,
    /// FD-07: encrypted export and import of the session library, known hosts and vault.
    pub transfer: Transfer,
    /// SS-03: open terminal panes and their SSH connections.
    pub terminals: Terminals,
    /// SS-10: what is typed into one terminal goes to several; each line's Enter goes through the bus.
    pub multiexec: MultiExec,
    /// SS-08: uploads (commands on the bus) and retries; listing and downloads are on [`Core::terminals`].
    pub files: FileTransfers,
    /// BX-08: favourite commands and the built-in library for the Terminal page's command panel,
    /// classified by the bus's policy engine.
    pub snippets: Snippets,
    /// QL-04: background checks of the sessions the Terminal page's tree shows. Reads only. The shell
    /// starts it with [`ReachabilityChecker::run`].
    pub reachability: Arc<ReachabilityChecker>,
    /// BX-01, BX-03, BX-05: Compare targets, results, diffs and exports. Running is the bus.
    pub bulk: BulkRuns,
    /// CT-01, CT-02: container hosts, their containers, images, volumes and networks. Reads only;
    /// changes go through [`Core::bus`].
    pub containers: Containers,
    /// MO-01 to MO-04: host-side and guest metrics, history in memory, host capacity. Reads only.
    /// The shell starts its polling with [`Metrics::run`].
    pub metrics: Arc<Metrics>,
    /// MO-13, MO-14: OS and specs of VMs and SSH hosts, and an SSH host's admin details. Reads only.
    pub host_details: HostDetails,
    /// FD-03: presentation mode and its read-only lock (saved; the lock is shared through the store).
    pub presentation: PresentationMode,
    pub host_counters: Arc<dyn HostCounters>,
    updater: Arc<dyn UpdaterAdapter>,
    vmware: Arc<SwitchableVmware>,
    /// VM-18: swapped when the VBoxManage path changes in Settings.
    virtualbox: Arc<SwitchableVirtualBox>,
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
        let docker = saved_docker_path(&store, &ctx).await?;
        let saved_vbox = saved_vboxmanage_path(&store, &ctx).await?;
        let virtualbox: Arc<dyn VirtualBoxAdapter> =
            Arc::from(adapters::virtualbox::connect(config.vboxmanage_path.or(saved_vbox)));
        // SS-04: the vault in this database, unlocked by the Windows login (DPAPI) or the master password.
        let vault = LocalVault::open(store.clone(), ctx, Arc::new(Dpapi), VaultOptions::default()).await?;
        Self::assemble(
            store,
            ctx,
            Adapters {
                vmware,
                virtualbox,
                remote: Arc::new(RusshAdapter::new()),
                vault: Arc::new(vault),
                host_counters: Arc::new(WindowsCounters::new()),
                updater: config.updater,
                network: Arc::new(SystemNetwork),
                containers: Arc::new(CliEngines::new(docker.as_deref())),
            },
            JobLimits::default(),
        )
        .await
    }

    /// Wires the modules together. Tests pass fake adapters here.
    pub async fn assemble(store: Store, ctx: Context, adapters: Adapters, limits: JobLimits) -> Result<Self> {
        let policy = load_policy(&store, &ctx).await?;
        // FD-03: the lock applies before anything else can run.
        let presentation = PresentationMode::load(store.clone(), ctx).await;
        let vmware = Arc::new(SwitchableVmware::new(adapters.vmware));
        let vmware_dyn: Arc<dyn VmwareAdapter> = vmware.clone();
        let virtualbox = Arc::new(SwitchableVirtualBox::new(adapters.virtualbox));
        // VM-18: every module that reads or changes VMs reaches both hypervisors through this.
        let hypervisors = Hypervisors::new(vmware_dyn, virtualbox.clone());
        let known_hosts = Arc::new(KnownHosts::new(store.clone()));
        let links = Arc::new(VmLinks::new(store.clone(), Arc::clone(&adapters.network)));
        let containers = Containers::new(
            store.clone(),
            Arc::clone(&adapters.vault),
            Arc::clone(&adapters.remote),
            Arc::clone(&known_hosts),
            Arc::clone(&adapters.containers),
        );
        let terminals = Terminals::new(
            store.clone(),
            Arc::clone(&adapters.vault),
            Arc::clone(&adapters.remote),
            Arc::clone(&adapters.network),
            Arc::clone(&known_hosts),
            Arc::clone(&links),
        );
        // MO-13: terminals and the dashboard's kept connections read a session's facts as they go.
        let specs = SpecsCollector::new(store.clone());
        terminals.set_specs(specs.clone());
        let reachability = Arc::new(ReachabilityChecker::new(
            store.clone(),
            ctx,
            Arc::clone(&adapters.network),
        ));
        // MO-01 to MO-04: reads only, so the collector holds adapters directly, not the job runner.
        let guest = GuestSource::new(
            store.clone(),
            ctx,
            Arc::clone(&adapters.remote),
            Arc::clone(&adapters.vault),
            Arc::clone(&known_hosts),
        );
        guest.set_specs(specs.clone());
        let metrics = Arc::new(Metrics::new(MetricsParts {
            store: store.clone(),
            ctx,
            counters: Arc::clone(&adapters.host_counters),
            guest,
            capacity: CapacityChecker::new(store.clone(), hypervisors.clone(), Arc::clone(&adapters.host_counters)),
        }));
        let host_details = HostDetails::new(HostDetailsParts {
            store: store.clone(),
            collector: specs,
            terminals: terminals.clone(),
            metrics: Arc::clone(&metrics),
            hypervisors: hypervisors.clone(),
            vault: Arc::clone(&adapters.vault),
            remote: Arc::clone(&adapters.remote),
            known_hosts: Arc::clone(&known_hosts),
        });
        let jobs = JobRunner::new(
            store.clone(),
            hypervisors.clone(),
            adapters.remote,
            Arc::clone(&adapters.updater),
            Arc::clone(&adapters.vault),
            Arc::clone(&known_hosts),
            Arc::new(terminals.clone()),
            limits,
        );
        // CT-01, CT-02: container changes go from the job runner to the containers service.
        jobs.set_containers(Arc::new(containers.clone()));
        let bus = Arc::new(CommandBus::new(
            policy,
            Arc::new(
                StoreDirectory::new(store.clone())
                    .with_terminals(terminals.clone())
                    .with_containers(containers.clone()),
            ),
            Arc::clone(&jobs),
            store.clone(),
            Arc::clone(&adapters.vault),
            CapacityChecker::new(store.clone(), hypervisors.clone(), Arc::clone(&adapters.host_counters)),
            ImpactPreviewer::new(store.clone(), hypervisors.clone()).with_containers(containers.clone()),
        ));
        if let Some(limit) = store.get_setting::<usize>(&ctx, store::POWER_ON_LIMIT_KEY).await? {
            jobs.set_power_on_limit(limit.clamp(1, JobLimits::MAX_POWER_ON));
        }
        if let Some(secs) = store.get_setting::<u64>(&ctx, store::SHUTDOWN_WAIT_KEY).await? {
            jobs.set_shutdown_wait(Duration::from_secs(secs.clamp(1, JobLimits::MAX_SHUTDOWN_WAIT_SECS)));
        }
        if let Some(limit) = store.get_setting::<usize>(&ctx, store::REMOTE_LIMIT_KEY).await? {
            jobs.set_remote_limit(limit.clamp(1, JobLimits::MAX_REMOTE));
        }
        // SS-07: tunnels go through the bus, which reaches the terminals through the job runner.
        terminals.set_bus(&bus);
        let keys = KeyManager::new(store.clone(), Arc::clone(&adapters.vault));
        let snippets = Snippets::new(store.clone(), bus.policy());
        let multiexec = MultiExec::new(ctx, terminals.clone(), Arc::clone(&bus), Arc::clone(&jobs));
        let files = FileTransfers::new(ctx, terminals.clone(), Arc::clone(&bus));
        Ok(Self {
            ctx,
            snapshots: SnapshotReader::new(store.clone(), hypervisors.clone()),
            inventory: Inventory::new(store.clone(), hypervisors, Arc::clone(&links)),
            vault: VaultService::new(adapters.vault, store.clone()),
            sessions: SessionLibrary::new(store.clone(), Arc::clone(&links)),
            forwards: Forwards::new(store.clone()),
            links,
            import: Importer::new(store.clone()),
            known_hosts,
            keys,
            transfer: Transfer::new(store.clone()),
            bulk: BulkRuns::new(store.clone()).with_terminals(terminals.clone()),
            containers,
            terminals,
            multiexec,
            files,
            snippets,
            reachability,
            metrics,
            host_details,
            presentation,
            store,
            bus,
            jobs,
            host_counters: adapters.host_counters,
            updater: adapters.updater,
            vmware,
            virtualbox,
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
        self.store.read_only().check(Change::Settings)?;
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

    /// CT-02: the docker.exe in use (Docker Desktop's CLI), or `None` when it was not found.
    pub fn docker_path(&self) -> Option<PathBuf> {
        self.containers.this_pc_cli()
    }

    /// CT-02: the docker.exe path saved in Settings, if any.
    pub async fn saved_docker_path(&self) -> Result<Option<PathBuf>> {
        saved_docker_path(&self.store, &self.ctx).await
    }

    /// CT-02: saves the docker.exe path (`None` = find it: `REMOTELY_DOCKER`, then Docker Desktop's
    /// folder) and looks for it again at once. The path must be an existing docker.exe. Audited, since it
    /// decides which program this PC's container actions run.
    pub async fn set_docker_path(&self, path: Option<PathBuf>) -> Result<Option<PathBuf>> {
        self.store.read_only().check(Change::Settings)?;
        if let Some(path) = &path {
            validate_docker_path(path)?;
        }
        let as_text = path.as_ref().map(|p| p.display().to_string());
        self.store
            .put_setting(&self.ctx, containers::DOCKER_PATH_KEY, &as_text)
            .await?;
        self.containers.find_this_pc_cli(path.as_deref());
        let in_use = self.docker_path();
        let detail = format!(
            "saved: {}; in use: {}",
            as_text.as_deref().unwrap_or("find automatically"),
            in_use
                .as_ref()
                .map_or_else(|| "not found".to_owned(), |p| p.display().to_string())
        );
        self.audit_setting("Set the docker.exe path", &detail).await?;
        Ok(in_use)
    }

    /// VM-18: path of the VBoxManage.exe in use, or `None` when VirtualBox was not found.
    pub fn vboxmanage_path(&self) -> Option<PathBuf> {
        self.virtualbox.tool_path()
    }

    /// VM-18: the VBoxManage path saved in Settings, if any.
    pub async fn saved_vboxmanage_path(&self) -> Result<Option<PathBuf>> {
        saved_vboxmanage_path(&self.store, &self.ctx).await
    }

    /// VM-18: saves the VBoxManage path (`None` = find it automatically) and switches to it right
    /// away. The path must be an existing VBoxManage.exe. Audited, since it decides which program runs
    /// every VirtualBox VM action.
    pub async fn set_vboxmanage_path(&self, path: Option<PathBuf>) -> Result<Option<PathBuf>> {
        self.store.read_only().check(Change::Settings)?;
        if let Some(path) = &path {
            adapters::virtualbox::validate_vboxmanage_path(path)?;
        }
        let as_text = path.as_ref().map(|p| p.display().to_string());
        self.store
            .put_setting(&self.ctx, store::VBOXMANAGE_PATH_KEY, &as_text)
            .await?;
        self.virtualbox.replace(Arc::from(adapters::virtualbox::connect(path)));
        let in_use = self.vboxmanage_path();
        let detail = format!(
            "saved: {}; in use: {}",
            as_text.as_deref().unwrap_or("find automatically"),
            in_use
                .as_ref()
                .map_or_else(|| "not found".to_owned(), |p| p.display().to_string())
        );
        self.audit_setting("Set the VBoxManage.exe path", &detail).await?;
        Ok(in_use)
    }

    /// VM-01: folders scanned for .vmx files, besides Workstation's library.
    pub async fn scan_folders(&self) -> Result<Vec<PathBuf>> {
        self.inventory.scan_folders(&self.ctx).await
    }

    /// VM-01: replaces the folders to scan. Each must be an existing folder; it is saved with `\`, and
    /// duplicates (any letter case, `/` or `\`) are dropped. Audited.
    pub async fn set_scan_folders(&self, folders: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
        self.store.read_only().check(Change::Settings)?;
        let mut seen = std::collections::HashSet::new();
        let mut kept = Vec::new();
        for folder in folders {
            let folder = adapters::vmware::with_backslashes(&folder);
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
        self.store.read_only().check(Change::Settings)?;
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
        self.store.read_only().check(Change::Settings)?;
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
        self.store.read_only().check(Change::Settings)?;
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
        self.store.read_only().check(Change::Settings)?;
        self.store
            .put_setting(&self.ctx, store::UPDATE_CHECKS_KEY, &enabled)
            .await?;
        let detail = if enabled { "on" } else { "off" };
        self.audit_setting("Set update checks", detail).await
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

    /// SS-03, QL-04, QL-05: keep-alive, auto-reconnect, copy-on-select, font size, scrollback and
    /// reachability checks.
    pub async fn terminal_settings(&self) -> Result<TerminalSettings> {
        self.terminals.settings(&self.ctx).await
    }

    /// SS-03: connection settings apply to terminals opened from now on; QL-05's font size and
    /// scrollback to open ones too (the UI applies them); QL-04's checks at once. Audited.
    pub async fn set_terminal_settings(&self, settings: TerminalSettings) -> Result<()> {
        self.store.read_only().check(Change::Settings)?;
        settings.validate()?;
        self.store
            .put_setting(&self.ctx, TERMINAL_SETTINGS_KEY, &settings)
            .await?;
        self.terminals.apply_settings(&settings);
        self.reachability.poke();
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

async fn saved_docker_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store
        .get_setting::<Option<String>>(ctx, containers::DOCKER_PATH_KEY)
        .await?;
    Ok(saved.flatten().map(PathBuf::from))
}

async fn saved_vmrun_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store.get_setting::<Option<String>>(ctx, store::VMRUN_PATH_KEY).await?;
    Ok(saved.flatten().map(PathBuf::from))
}

async fn saved_vboxmanage_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store
        .get_setting::<Option<String>>(ctx, store::VBOXMANAGE_PATH_KEY)
        .await?;
    Ok(saved.flatten().map(PathBuf::from))
}
