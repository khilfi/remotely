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
//!   reachability (QL-04): background TCP checks of the sessions the tree shows, skipping hosts with an
//!     open connection and backing off from hosts that are down ──► adapters::network
//!   bulk (BX-01, BX-03, BX-05): targets, grouped results, diffs and exports of remote command runs
//!     (the Terminal page's Compare output)
//!   retention (BX-02): the job journal keeps outputs and command text for as long as Settings says, then
//!     a daily purge removes them; save_guard: no save path writes into a Git working tree
//!   catalog (VM-19 to VM-21): sizes, OS profiles, images and launch templates, what deploy (R2) runs; edits
//!     are audited like the session library, and a template resolves into one plan per VM
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
pub mod catalog;
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
pub mod login_guard;
pub mod metrics;
pub mod policy;
pub mod presentation;
pub mod reachability;
pub mod retention;
pub mod save_guard;
pub mod sessions;
pub mod settings;
pub mod snapshots;
pub mod snippets;
pub mod ssh_keys;
pub mod store;
pub mod terminal;
pub mod transfer;
pub mod untrusted;
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
use catalog::Catalog;
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
use login_guard::LoginGuard;
use metrics::{GuestSource, Metrics, MetricsParts};
use policy::{PolicyEngine, PolicyRules};
use presentation::{Change, PresentationMode};
use reachability::{ReachabilityChecker, TrackedRemote};
use retention::JournalRetention;
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
use vault::{Dpapi, LocalVault, SecretBindings, Vault, VaultOptions, VaultService, VaultStatus};
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

/// QL-15: the terminals and approvals a window had open, from [`Core::ui_snapshot`].
#[derive(Debug, Clone, Default)]
pub struct UiSnapshot {
    pub terminals: Vec<uuid::Uuid>,
    pub approvals: Vec<uuid::Uuid>,
}

/// QL-15: what [`Core::release_ui`] closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiReleased {
    pub terminals: usize,
    pub approvals: usize,
}

impl UiSnapshot {
    pub fn is_empty(&self) -> bool {
        self.terminals.is_empty() && self.approvals.is_empty()
    }
}

pub struct Core {
    pub ctx: Context,
    pub store: Store,
    pub inventory: Inventory,
    /// VM-04: snapshot trees, read from each VM's .vmsd (VirtualBox: `showvminfo`). Changes go
    /// through [`Core::bus`].
    pub snapshots: SnapshotReader,
    /// VM-19 to VM-21: sizes, images and launch templates (the app's own data, audited). Deploying is R2's.
    pub catalog: Catalog,
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
    /// BX-02: how long the job journal keeps outputs and command text, and the purge. The shell starts its
    /// schedule with [`JournalRetention::run`].
    pub retention: Arc<JournalRetention>,
    /// CT-01, CT-02: container hosts, their containers, images, volumes and networks. Reads only;
    /// changes go through [`Core::bus`].
    pub containers: Containers,
    /// MO-01 to MO-04: host-side and guest metrics, history in memory, host capacity. Reads only.
    /// The shell starts its polling with [`Metrics::run`].
    pub metrics: Arc<Metrics>,
    /// MO-13, MO-14: OS and specs of VMs and SSH hosts, and an SSH host's admin details. Reads only.
    pub host_details: HostDetails,
    /// MO-02, CT-01: parks refused background logins and caps them per host per hour.
    pub login_guard: LoginGuard,
    /// FD-03: presentation mode and its read-only lock (saved; the lock is shared through the store).
    pub presentation: PresentationMode,
    pub host_counters: Arc<dyn HostCounters>,
    updater: Arc<dyn UpdaterAdapter>,
    vmware: Arc<SwitchableVmware>,
    /// VM-18: swapped when the VBoxManage path changes in Settings.
    virtualbox: Arc<SwitchableVirtualBox>,
    /// SS-04, AP-06: where vault passwords may go without the vault password (shared by every module).
    bindings: SecretBindings,
}

/// What lets go of decrypted secrets when the vault locks ([`Core::spawn_lock_watch`]).
struct LockParts {
    guest: std::sync::Weak<Metrics>,
    containers: Containers,
    host_details: HostDetails,
    terminals: Terminals,
    transfer_closed: transfer::Closer,
    bindings: SecretBindings,
}

impl LockParts {
    async fn vault_locked(&self) {
        self.bindings.vault_locked();
        self.terminals.forget_logins();
        let file_closed = self.transfer_closed.close();
        self.containers.close_all().await;
        self.host_details.close_all().await;
        if let Some(metrics) = self.guest.upgrade() {
            metrics.guest().close_all().await;
        }
        tracing::info!(
            file_closed,
            "the vault locked: background connections closed, typed login passwords forgotten"
        );
    }
}

impl Core {
    pub async fn init(config: CoreConfig) -> Result<Self> {
        let store = Store::open(&config.db_path).await?;
        match Self::init_on(store.clone(), config).await {
            Ok(core) => Ok(core),
            Err(err) => {
                // QL-15: the database file is closed before the error is reported.
                store.close().await;
                Err(err)
            }
        }
    }

    async fn init_on(store: Store, config: CoreConfig) -> Result<Self> {
        let interrupted = store.mark_interrupted_jobs().await?;
        if interrupted > 0 {
            tracing::warn!(interrupted, "jobs were open when the app last stopped");
        }
        let ctx = store.ensure_identity(&config.account, &config.display_name).await?;
        // QL-15: before the saved paths are read below; `assemble` checks again, which then finds nothing.
        settings::repair(&store, &ctx).await?;
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
        // QL-15: a setting that can't be read gets its default (audited) rather than stopping the start.
        settings::repair(&store, &ctx).await?;
        let policy = load_policy(&store, &ctx).await?;
        // FD-03: the lock applies before anything else can run.
        let presentation = PresentationMode::load(store.clone(), ctx).await;
        // QL-04: every service reaches SSH through this, which notes the kept connections (the
        // dashboard's, the Containers page's, host details') so the reachability checks skip their hosts.
        let tracked = Arc::new(TrackedRemote::new(adapters.remote));
        let adapters = Adapters {
            remote: tracked.clone(),
            ..adapters
        };
        let vmware = Arc::new(SwitchableVmware::new(adapters.vmware));
        let vmware_dyn: Arc<dyn VmwareAdapter> = vmware.clone();
        let virtualbox = Arc::new(SwitchableVirtualBox::new(adapters.virtualbox));
        // VM-18: every module that reads or changes VMs reaches both hypervisors through this.
        let hypervisors = Hypervisors::new(vmware_dyn, virtualbox.clone());
        let known_hosts = Arc::new(KnownHosts::new(store.clone()));
        // SS-04, AP-06: one record of where vault passwords may go, for every module that sends one.
        let bindings = SecretBindings::new(store.clone(), Arc::clone(&adapters.vault));
        // MO-02, CT-01: one guard for every background login (dashboard and Containers page).
        let login_guard = LoginGuard::new();
        known_hosts.set_login_guard(login_guard.clone());
        let links = Arc::new(VmLinks::new(store.clone(), Arc::clone(&adapters.network)));
        let containers = Containers::new(
            store.clone(),
            Arc::clone(&adapters.vault),
            Arc::clone(&adapters.remote),
            Arc::clone(&known_hosts),
            Arc::clone(&adapters.containers),
            login_guard.clone(),
        );
        containers.set_bindings(bindings.clone());
        let terminals = Terminals::new(
            store.clone(),
            Arc::clone(&adapters.vault),
            Arc::clone(&adapters.remote),
            Arc::clone(&adapters.network),
            Arc::clone(&known_hosts),
            Arc::clone(&links),
        );
        terminals.set_bindings(bindings.clone());
        // MO-13: terminals and the dashboard's kept connections read a session's facts as they go.
        let specs = SpecsCollector::new(store.clone());
        terminals.set_specs(specs.clone());
        let reachability = Arc::new(ReachabilityChecker::new(
            store.clone(),
            ctx,
            Arc::clone(&adapters.network),
        ));
        // QL-04: a host with a connected terminal or a kept connection is not probed.
        reachability.add_connections(Arc::new(terminals.clone()));
        reachability.add_connections(tracked);
        // MO-01 to MO-04: reads only, so the collector holds adapters directly, not the job runner.
        let guest = GuestSource::new(
            store.clone(),
            ctx,
            Arc::clone(&adapters.remote),
            Arc::clone(&adapters.vault),
            Arc::clone(&known_hosts),
            login_guard.clone(),
        );
        guest.set_specs(specs.clone());
        if let Some(secs) = store.get_setting::<u64>(&ctx, metrics::guest::POLL_KEY).await? {
            if metrics::guest::POLL_CHOICES.contains(&secs) {
                guest.set_interval(Duration::from_secs(secs));
            }
        }
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
        bus.set_bindings(bindings.clone());
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
        let retention = Arc::new(JournalRetention::new(store.clone(), ctx, Arc::clone(&jobs)));
        let vault_status = adapters.vault.watch();
        let core = Self {
            ctx,
            snapshots: SnapshotReader::new(store.clone(), hypervisors.clone()),
            catalog: Catalog::new(store.clone()).with_hypervisors(hypervisors.clone()),
            inventory: Inventory::new(store.clone(), hypervisors, Arc::clone(&links)),
            vault: VaultService::new(adapters.vault, store.clone())
                .with_login_guard(login_guard.clone())
                .with_bindings(bindings.clone()),
            sessions: SessionLibrary::new(store.clone(), Arc::clone(&links))
                .with_policy(bus.policy())
                .with_bindings(bindings.clone()),
            forwards: Forwards::new(store.clone()),
            links,
            import: Importer::new(store.clone()).with_policy(bus.policy()),
            known_hosts,
            keys,
            transfer: Transfer::new(store.clone())
                .with_policy(bus.policy())
                .with_bindings(bindings.clone()),
            bulk: BulkRuns::new(store.clone()).with_terminals(terminals.clone()),
            retention,
            containers,
            terminals,
            multiexec,
            files,
            snippets,
            reachability,
            metrics,
            host_details,
            login_guard,
            presentation,
            store,
            bus,
            jobs,
            host_counters: adapters.host_counters,
            updater: adapters.updater,
            vmware,
            virtualbox,
            bindings,
        };
        core.spawn_lock_watch(vault_status);
        Ok(core)
    }

    /// SS-04: when the vault locks (idle, or on demand), what holds decrypted secrets lets go of them:
    /// the dashboard's, the Containers page's and host details' kept connections close, terminals forget
    /// the passwords typed for their logins (open shells stay open), and an opened FD-07 file closes.
    fn spawn_lock_watch(&self, mut status: tokio::sync::watch::Receiver<VaultStatus>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let parts = LockParts {
            guest: Arc::downgrade(&self.metrics),
            containers: self.containers.clone(),
            host_details: self.host_details.clone(),
            terminals: self.terminals.clone(),
            transfer_closed: self.transfer.closer(),
            bindings: self.bindings.clone(),
        };
        runtime.spawn(async move {
            let mut was = *status.borrow_and_update();
            while status.changed().await.is_ok() {
                let now = *status.borrow_and_update();
                if was == VaultStatus::Unlocked && now == VaultStatus::Locked {
                    parts.vault_locked().await;
                }
                was = now;
            }
        });
    }

    /// SS-04, AP-06: where vault passwords may go without asking; tests shorten its grace period.
    pub fn secret_bindings(&self) -> &SecretBindings {
        &self.bindings
    }

    /// QL-15: what the window shows now, taken when its page starts loading again (a reload, or a crash
    /// the user reloaded from), so [`Core::release_ui`] closes only what the old page had.
    pub fn ui_snapshot(&self) -> UiSnapshot {
        UiSnapshot {
            terminals: self.terminals.open_ids(),
            approvals: self.bus.pending_approvals(),
        }
    }

    /// QL-15: the page that showed `shown` is gone, so nothing it started may go on without anyone seeing it:
    /// MultiExec stops (a held line is cancelled), its terminals close with their tunnels (each audited), and the
    /// approvals it would have answered are cancelled (audited). Running jobs go on; Activity shows them.
    pub async fn release_ui(&self, shown: UiSnapshot) -> UiReleased {
        if let Err(err) = self.multiexec.stop().await {
            tracing::warn!(error = %err, "MultiExec did not stop cleanly after the window reloaded");
        }
        self.terminals.close_these(&shown.terminals).await;
        let approvals = self
            .bus
            .cancel_approvals(&shown.approvals, "the window reloaded, so nobody could answer it")
            .await;
        UiReleased {
            terminals: shown.terminals.len(),
            approvals,
        }
    }

    /// Before the app exits, also when an update's installer is about to end it (FD-14, QL-15): every terminal
    /// closes, audited, with its tunnels, and session logs are written out to the end.
    pub async fn shutdown(&self) {
        self.terminals.close_all().await;
    }

    /// MO-02, CT-01: the user pressed Retry on a parked or waiting host: the dashboard and the
    /// Containers page log in to it again on their next read. Changes nothing on the host or in the
    /// app's data, so it is not audited and the read-only lock allows it.
    pub fn retry_background_logins(&self, session_id: uuid::Uuid) {
        self.metrics.guest().retry(session_id);
        self.containers.retry(session_id);
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

    /// MO-02, P8: seconds between two polls of a host the dashboard watches (default 5).
    pub fn guest_poll_secs(&self) -> u64 {
        self.metrics.guest().interval().as_secs()
    }

    /// MO-02, P8: one of [`metrics::guest::POLL_CHOICES`] (5, 15, 30 or 60 s). Applies from each host's
    /// next poll on. Audited.
    pub async fn set_guest_poll_secs(&self, secs: u64) -> Result<()> {
        self.store.read_only().check(Change::Settings)?;
        let choices = metrics::guest::POLL_CHOICES;
        if !choices.contains(&secs) {
            let offered: Vec<String> = choices.iter().map(u64::to_string).collect();
            let text = match offered.split_last() {
                Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
                _ => offered.concat(),
            };
            return Err(CoreError::InvalidSetting(format!(
                "watched hosts can be polled every {text} seconds"
            )));
        }
        self.store
            .put_setting(&self.ctx, metrics::guest::POLL_KEY, &secs)
            .await?;
        self.metrics.guest().set_interval(Duration::from_secs(secs));
        self.audit_setting(
            "Set how often the dashboard polls watched hosts",
            &format!("every {secs} s"),
        )
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
    /// logs that it did. A read, so it skips the bus. Never into a Git working tree ([`save_guard`]). The rows
    /// are read and written one by one into a file next to `path`, which then takes its name, so a long log is
    /// never all in memory and a failed export leaves no half file.
    pub async fn export_audit_csv(&self, path: &Path) -> Result<AuditExport> {
        save_guard::refuse_repository(path, save_guard::Saved::AuditLog)?;
        let (entries, redacted) = save_guard::write_atomically(path, |file| self.write_audit_csv(file)).await?;
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
                    detail: Some(&format!("{entries} entries to {file}")),
                },
            )
            .await?;
        Ok(AuditExport {
            path: path.display().to_string(),
            entries,
            redacted,
        })
    }

    /// The audit log's CSV into `file`, row by row. Returns how many entries, and how many had something redacted.
    async fn write_audit_csv(&self, file: tokio::fs::File) -> Result<(usize, usize)> {
        use futures_util::TryStreamExt;
        use tokio::io::AsyncWriteExt;
        let mut out = tokio::io::BufWriter::new(file);
        out.write_all(export::audit_csv_header().as_bytes()).await?;
        let (mut entries, mut redacted) = (0, 0);
        // Dropped before anything else reads the database: it holds a connection.
        let mut rows = self.store.audit_entries(&self.ctx);
        while let Some(entry) = rows.try_next().await? {
            let (row, was) = export::audit_csv_row(&entry);
            out.write_all(row.as_bytes()).await?;
            entries += 1;
            redacted += usize::from(was);
        }
        drop(rows);
        out.flush().await?;
        out.into_inner().sync_all().await?;
        Ok((entries, redacted))
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
