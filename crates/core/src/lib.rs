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
//!     multiexec_groups (QL-19): saved sets of sessions that choose MultiExec's terminals; edits audited
//!     files (SS-08): SFTP on each terminal's connection; the shell's folder (OSC 7); downloads are
//!     audited reads, uploads are commands on the bus that the job runner carries out in the terminal
//!     jump hosts (SS-07): every SSH connection goes through the session's jump host chain
//!     tunnels (SS-07): saved port forwards (forwards) open on a terminal's connection; opening one is
//!     a command on the bus, which the job runner carries out in the terminal; closing is audited
//!     highlight and alert rules (QL-17): the UI colours matches; each pane alerts once per burst of matching lines
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
//!   metrics::history (MO-06): the rounds' 1-minute averages on disk, pruned daily; alerts (MO-07): rules
//!     run on each round, an alert list and events for the UI's notifications; dashboard (MO-16): the
//!     dashboard's layout, per workspace
//!   host_networks (VM-11): the hypervisors' networks, the VMs on each and their NAT port forwards ──►
//!     adapters::host_networks; changing a forward is a command on the bus. vm_insight (VM-25): a VM's logs and
//!     timeline; waste (VM-16, VM-14): the waste finder's report. Reads only
//!   notifications (QL-25): the notification centre's history, in memory and redacted
//!   support_bundle (FD-04): commands' output and files from many hosts into one zip; collecting is a command on the
//!     bus, which the job runner carries out on each host's kept connection (SFTP for files)
//!   toolbox (FD-09): ping, trace route, DNS, port checks and certificates from this PC (behind a jump host, ports and
//!     certificates from it) ──► adapters::net_tools; reads only. Wake-on-LAN is a command on the bus
//!   checks (MO-08): health checks run on a schedule with the toolbox's probes for the shown workspace, their
//!     results in a history pruned with MO-06's, their state read by MO-07's rules each round; edits audited
//! ```
//!
//! Only [`command_bus::CommandBus`] can enqueue jobs, and adapters are only reachable through the job
//! runner (changes) or [`inventory::Inventory`] and [`metrics`] (reads).

pub mod adapters;
pub mod alerts;
pub mod bulk;
pub mod capacity;
pub mod capacity_plan;
pub mod catalog;
pub mod checks;
pub mod command_bus;
pub mod containers;
pub mod convert;
pub mod dashboard;
pub mod deploy;
pub mod domain;
pub mod error;
pub mod export;
#[cfg(any(test, feature = "fakes"))]
pub mod fakes;
pub mod forwards;
pub mod host_details;
pub mod host_networks;
pub mod impact;
pub mod import;
pub mod inventory;
pub mod jobs;
pub mod known_hosts;
pub mod linked_clones;
pub mod locks;
pub mod login_guard;
pub mod metrics;
pub mod multiexec_groups;
pub mod notifications;
pub mod policy;
pub mod presentation;
pub mod reachability;
pub mod retention;
pub mod save_guard;
pub mod schedules;
pub mod sessions;
pub mod settings;
pub mod snapshots;
pub mod snippets;
pub mod ssh_keys;
pub mod stacks;
pub mod store;
pub mod support_bundle;
pub mod terminal;
pub mod toolbox;
pub mod transfer;
pub mod untrusted;
pub mod updates;
pub mod vault;
pub mod vm_insight;
pub mod vm_links;
pub mod vm_settings;
pub mod waste;
pub mod workspaces;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use adapters::containers::cli::{validate_docker_path, CliEngines};
use adapters::containers::ContainerEngines;
use adapters::host_counters::{HostCounters, WindowsCounters};
use adapters::hypervisor::Hypervisors;
use adapters::net_tools::{NetworkTools, SystemNetworkTools};
use adapters::network::{NetworkAdapter, SystemNetwork};
use adapters::remote::{RemoteAdapter, RusshAdapter};
use adapters::updater::UpdaterAdapter;
use adapters::virtualbox::{SwitchableVirtualBox, VirtualBoxAdapter};
use adapters::vmware::{SwitchableVmware, VmwareAdapter};
use alerts::Alerts;
use bulk::BulkRuns;
use capacity::CapacityChecker;
use catalog::Catalog;
use command_bus::CommandBus;
use containers::Containers;
use dashboard::Layouts;
use domain::Context;
use forwards::Forwards;
use host_details::{HostDetails, HostDetailsParts, SpecsCollector};
use impact::ImpactPreviewer;
use import::Importer;
use inventory::{Inventory, StoreDirectory};
use jobs::{JobLimits, JobRunner};
use known_hosts::KnownHosts;
use login_guard::LoginGuard;
use metrics::history::MetricsHistory;
use metrics::{GuestSource, Metrics, MetricsParts};
use multiexec_groups::MultiExecGroups;
use notifications::Notifications;
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
use terminal::rules::TerminalRules;
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
    /// CV-01 to CV-03, VM-17: the disk conversion tools (qemu-img when installed; the hypervisors' own).
    pub disk_tools: Arc<dyn adapters::disk_tools::DiskTools>,
    /// FD-09: the toolbox's probes from this PC (ICMP, DNS, TCP, a chain's trust check, adapters) and the
    /// Wake-on-LAN datagram.
    pub network_tools: Arc<dyn NetworkTools>,
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

/// QL-15: the terminals and approvals a window had open, from [`Core::ui_snapshot`]; FD-09: and the file server it
/// started.
#[derive(Debug, Clone, Default)]
pub struct UiSnapshot {
    pub terminals: Vec<uuid::Uuid>,
    pub approvals: Vec<uuid::Uuid>,
    /// FD-09: the file server's job.
    pub file_servers: Vec<uuid::Uuid>,
}

/// QL-15: what [`Core::release_ui`] closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiReleased {
    pub terminals: usize,
    pub approvals: usize,
    pub file_servers: usize,
}

impl UiSnapshot {
    pub fn is_empty(&self) -> bool {
        self.terminals.is_empty() && self.approvals.is_empty() && self.file_servers.is_empty()
    }
}

/// FD-09: how long a stop path waits for the file server's job to end (journaled and audited).
const FILE_SERVER_STOP_WAIT: Duration = Duration::from_secs(10);

/// FD-09: the server serving as one of `jobs` stops for `reason`; the rest (queued, or in their approval countdown)
/// are cancelled, so none starts serving after what stopped it.
fn stop_file_server_jobs(
    runner: &toolbox::file_server::Runner,
    runner_jobs: &JobRunner,
    jobs: &[uuid::Uuid],
    reason: toolbox::file_server::StopReason,
) {
    let stopped = runner.stop_these(jobs, reason);
    for job_id in jobs.iter().filter(|id| !stopped.contains(id)) {
        runner_jobs.cancel(*job_id);
    }
}

pub struct Core {
    /// FD-02: the workspace shown now ([`Core::ctx`]); [`Core::switch_workspace`] changes it.
    current: workspaces::Current,
    /// FD-02: the user's home workspace, which keeps this PC's settings and the update token.
    home: Context,
    /// FD-02: the user's workspaces (create, rename, colour, archive, restore).
    pub workspaces: workspaces::Workspaces,
    pub store: Store,
    /// Shared with the deploy runner, which lists the VMs it makes (VM-21), and with [`Core::schedules`], which
    /// reads the VMs' power states before a scheduled run.
    pub inventory: Arc<Inventory>,
    /// VM-04: snapshot trees, read from each VM's .vmsd (VirtualBox: `showvminfo`). Changes go
    /// through [`Core::bus`].
    pub snapshots: SnapshotReader,
    /// VM-19 to VM-21: sizes, images and launch templates (the app's own data, audited).
    pub catalog: Catalog,
    /// VM-21, VM-22, VM-10: deploys from launch templates or the Deploy dialog, and bulk clones; each is a
    /// command on [`Core::bus`].
    pub deploy: deploy::service::Deploys,
    /// VM-08: stacks of launch templates, their instances (deployed, started, stopped and torn down through
    /// [`Core::bus`]) and the VMs each instance holds.
    pub stacks: stacks::Stacks,
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
    /// QL-19: saved MultiExec groups (named sets of sessions). They only choose MultiExec's targets.
    pub groups: MultiExecGroups,
    /// SS-08: uploads (commands on the bus) and retries; listing and downloads are on [`Core::terminals`].
    pub files: FileTransfers,
    /// BX-08: favourite commands and the built-in library for the Terminal page's command panel,
    /// classified by the bus's policy engine.
    pub snippets: Snippets,
    /// QL-17: highlight and alert rules for terminal output; open panes follow their alert rules.
    pub terminal_rules: TerminalRules,
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
    /// MO-06: the dashboard's history on disk (1-minute averages), its retention and prune. The shell starts
    /// the prune's schedule with [`MetricsHistory::run`].
    pub history: Arc<MetricsHistory>,
    /// MO-07: alert rules, the alert list and alert events, evaluated on every metrics round.
    pub alerts: Arc<Alerts>,
    /// MO-16: the dashboard's layout of this workspace.
    pub layouts: Layouts,
    /// VM-14, VM-27: snapshot and power schedules, auto-suspend of idle VMs, and the scheduler. Each run submits to
    /// [`Core::bus`] under the approval given when its schedule was saved. The shell starts it with
    /// [`schedules::Schedules::run`]. FD-02: [`Core::schedules`] gives the shown workspace's.
    schedules: schedules::Schedules,
    /// QL-25: the notification centre's history, in memory (the module says why not on disk).
    pub notifications: Notifications,
    /// MO-13, MO-14: OS and specs of VMs and SSH hosts, and an SSH host's admin details. Reads only.
    pub host_details: HostDetails,
    /// FD-09: ping, trace route, DNS, port checks and the certificate viewer (reads), and Wake-on-LAN's options;
    /// sending a magic packet goes through [`Core::bus`].
    pub toolbox: toolbox::Toolbox,
    /// FD-09: the quick file server (TFTP and HTTP). Starting it is a command on [`Core::bus`]; it stops at its time
    /// limit, on Stop, on a workspace switch, a vault lock, a window reload and at [`Core::shutdown`].
    pub file_server: toolbox::file_server::FileServers,
    /// MO-08: health checks, their history and state; the shell starts the runner ([`checks::Checks::run`]).
    pub checks: checks::Checks,
    /// MO-02, CT-01: parks refused background logins and caps them per host per hour.
    pub login_guard: LoginGuard,
    /// FD-03: presentation mode and its read-only lock (saved; the lock is shared through the store).
    pub presentation: PresentationMode,
    /// VM-23, VM-24: VM settings the shell builds from dialogs and drops (ISOs, shared folders, an existing
    /// VM), guest OS types, screenshots and Open console. Changes go through [`Core::bus`].
    pub vm_settings: vm_settings::VmSettings,
    /// VM-11: the hypervisors' host networks, the VMs on each and their NAT port forwards. Reads only; changes go
    /// through [`Core::bus`].
    pub networks: host_networks::HostNetworks,
    /// VM-25: a VM's Log and Timeline tabs. Reads only.
    pub insight: vm_insight::VmInsight,
    /// VM-16, VM-14: the waste finder's report. Reads only; each row's action goes through [`Core::bus`].
    pub waste: waste::WasteFinder,
    pub host_counters: Arc<dyn HostCounters>,
    updater: Arc<dyn UpdaterAdapter>,
    vmware: Arc<SwitchableVmware>,
    /// VM-18: swapped when the VBoxManage path changes in Settings.
    virtualbox: Arc<SwitchableVirtualBox>,
    /// SS-04, AP-06: where vault passwords may go without the vault password (shared by every module).
    bindings: SecretBindings,
    /// VM-21: what the job runner makes new VMs with; tests shorten its waits.
    deployer: Arc<deploy::runner::Deployer>,
    /// VM-08: what the job runner waits on between a stack's steps; tests give it their own clock.
    stack_runner: Arc<stacks::StackRunner>,
    /// CV-01 to CV-03, VM-17: Image tools (Inspect, Convert, Verify), a VM's Export, and the conversion tools.
    /// Conversions and exports are commands on [`Core::bus`]; an import is a deploy ([`Core::deploy`]).
    pub convert: convert::service::Conversions,
    /// CV-03: what the job runner converts with; tests shorten its waits.
    converter: Arc<convert::Converter>,
    /// FD-04: support bundles from many hosts (presets, preview, submit, where one was saved). Collecting is a command
    /// on [`Core::bus`].
    pub bundles: support_bundle::SupportBundles,
}

/// What lets go of decrypted secrets when the vault locks ([`Core::spawn_lock_watch`]).
struct LockParts {
    guest: std::sync::Weak<Metrics>,
    containers: Containers,
    host_details: HostDetails,
    toolbox: toolbox::Toolbox,
    terminals: Terminals,
    transfer_closed: transfer::Closer,
    bindings: SecretBindings,
    /// FD-09: nobody may be at the PC any more, so the file server stops too.
    file_server: Arc<toolbox::file_server::Runner>,
    jobs: Arc<JobRunner>,
}

impl LockParts {
    async fn vault_locked(&self) {
        self.bindings.vault_locked();
        self.terminals.forget_logins();
        let open = self.jobs.file_server_jobs(None);
        stop_file_server_jobs(
            &self.file_server,
            &self.jobs,
            &open,
            toolbox::file_server::StopReason::VaultLocked,
        );
        if !open.is_empty() {
            tracing::info!("the vault locked: the file server stops");
        }
        let file_closed = self.transfer_closed.close();
        self.containers.close_all().await;
        self.host_details.close_all().await;
        self.toolbox.close_all().await;
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
        let ovftool = saved_ovftool_path(&store, &ctx).await?;
        let vmware: Arc<dyn VmwareAdapter> =
            Arc::from(adapters::vmware::connect_with(config.vmrun_path.or(saved), ovftool));
        let docker = saved_docker_path(&store, &ctx).await?;
        let saved_vbox = saved_vboxmanage_path(&store, &ctx).await?;
        let virtualbox: Arc<dyn VirtualBoxAdapter> =
            Arc::from(adapters::virtualbox::connect(config.vboxmanage_path.or(saved_vbox)));
        // SS-04: the vault in this database, unlocked by the Windows login (DPAPI) or the master password.
        let vault = LocalVault::open(store.clone(), ctx, Arc::new(Dpapi), VaultOptions::default()).await?;
        let qemu_img = saved_qemu_img_path(&store, &ctx).await?;
        let data_folder = config.db_path.parent().map(std::path::Path::to_path_buf);
        let core = Self::assemble(
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
                disk_tools: Arc::new(adapters::disk_tools::LocalDiskTools::new(qemu_img)),
                network_tools: Arc::new(SystemNetworkTools),
            },
            JobLimits::default(),
        )
        .await?;
        // FD-09: the database's folder (the vault, logs and WebView2's profile beside it) is never served.
        if let Some(folder) = data_folder.filter(|f| !f.as_os_str().is_empty()) {
            core.file_server.runner().protect(&folder);
        }
        Ok(core)
    }

    /// Wires the modules together. Tests pass fake adapters here.
    /// FD-02: `home` is the user's home workspace ([`Store::ensure_identity`]); the workspace shown last opens
    /// again, or the home one.
    pub async fn assemble(store: Store, home: Context, adapters: Adapters, limits: JobLimits) -> Result<Self> {
        let ctx = workspaces::starting(&store, &home).await?;
        let current = workspaces::Current::new(ctx);
        // QL-15: a setting that can't be read gets its default (audited) rather than stopping the start.
        settings::repair(&store, &ctx).await?;
        let policy = load_policy(&store, &ctx).await?;
        // FD-03: the lock applies before anything else can run.
        let presentation = PresentationMode::load(store.clone(), current.clone()).await;
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
        let network = Arc::clone(&adapters.network);
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
        // QL-17: every pane matches its output against the rules with an alert on, as they change.
        let terminal_rules = TerminalRules::load(store.clone(), &ctx).await?;
        terminals.set_rules(terminal_rules.subscribe());
        // MO-13: terminals and the dashboard's kept connections read a session's facts as they go.
        let specs = SpecsCollector::new(store.clone());
        terminals.set_specs(specs.clone());
        let reachability = Arc::new(ReachabilityChecker::new(
            store.clone(),
            current.clone(),
            Arc::clone(&adapters.network),
        ));
        // QL-04: a host with a connected terminal or a kept connection is not probed.
        reachability.add_connections(Arc::new(terminals.clone()));
        reachability.add_connections(tracked);
        // MO-01 to MO-04: reads only, so the collector holds adapters directly, not the job runner.
        let guest = GuestSource::new(
            store.clone(),
            current.clone(),
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
            current: current.clone(),
            counters: Arc::clone(&adapters.host_counters),
            guest,
            capacity: CapacityChecker::new(store.clone(), hypervisors.clone(), Arc::clone(&adapters.host_counters)),
        }));
        // MO-06, MO-07: the rounds go on to the history on disk, then to the alert rules.
        let history = Arc::new(MetricsHistory::new(store.clone(), ctx));
        metrics.add_observer(history.clone());
        let alerts = Arc::new(Alerts::load(store.clone(), ctx).await?);
        metrics.add_observer(alerts.clone());
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
        // FD-09: the toolbox's reads; a session behind a jump host is reached over its jump host's connection.
        let toolbox = toolbox::Toolbox::new(toolbox::ToolboxParts {
            store: store.clone(),
            tools: Arc::clone(&adapters.network_tools),
            network: Arc::clone(&adapters.network),
            remote: Arc::clone(&adapters.remote),
            vault: Arc::clone(&adapters.vault),
            known_hosts: Arc::clone(&known_hosts),
            login_guard: login_guard.clone(),
            terminals: terminals.clone(),
            host_details: host_details.clone(),
        });
        // MO-08: health checks run the toolbox's probes for the shown workspace; each round's alert rules read them.
        let checks = checks::Checks::new(checks::ChecksParts {
            store: store.clone(),
            current: current.clone(),
            toolbox: toolbox.clone(),
        });
        alerts.set_checks(Arc::new(checks.clone()));
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
        // FD-09: Wake-on-LAN's magic packet leaves through the job runner, and the file server runs as a job.
        jobs.set_network_tools(Arc::clone(&adapters.network_tools));
        let file_server_runner = Arc::new(toolbox::file_server::Runner::new());
        jobs.set_file_servers(file_server_runner.clone());
        // MO-06: a prune compacts the file only while no job runs.
        history.set_jobs(Arc::clone(&jobs));
        // VM-11: network targets and port forward previews.
        let networks = host_networks::HostNetworks::new(store.clone(), hypervisors.clone(), host_details.clone());
        let bus = Arc::new(CommandBus::new(
            policy,
            Arc::new(
                StoreDirectory::new(store.clone())
                    .with_terminals(terminals.clone())
                    .with_containers(containers.clone())
                    .with_host_networks(networks.clone()),
            ),
            Arc::clone(&jobs),
            store.clone(),
            Arc::clone(&adapters.vault),
            CapacityChecker::new(store.clone(), hypervisors.clone(), Arc::clone(&adapters.host_counters)),
            ImpactPreviewer::new(store.clone(), hypervisors.clone())
                .with_containers(containers.clone())
                .with_host_networks(networks.clone()),
        ));
        bus.set_bindings(bindings.clone());
        let file_server = toolbox::file_server::FileServers::new(
            store.clone(),
            Arc::clone(&adapters.network_tools),
            Arc::clone(&bus),
            file_server_runner,
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
        // SS-07: tunnels go through the bus, which reaches the terminals through the job runner.
        terminals.set_bus(&bus);
        let keys = KeyManager::new(store.clone(), Arc::clone(&adapters.vault));
        let snippets = Snippets::new(store.clone(), bus.policy());
        let multiexec = MultiExec::new(current.clone(), terminals.clone(), Arc::clone(&bus), Arc::clone(&jobs));
        let files = FileTransfers::new(current.clone(), terminals.clone(), Arc::clone(&bus));
        let retention = Arc::new(JournalRetention::new(store.clone(), current.clone(), Arc::clone(&jobs)));
        let vault_status = adapters.vault.watch();
        let catalog = Catalog::new(store.clone())
            .with_hypervisors(hypervisors.clone())
            .with_disk_tools(Arc::clone(&adapters.disk_tools));
        let inventory = Arc::new(Inventory::new(store.clone(), hypervisors.clone(), Arc::clone(&links)));
        // VM-21, VM-22, VM-10: the job runner makes each new VM through the deploy runner.
        let deployer = Arc::new(deploy::runner::Deployer::new(
            store.clone(),
            hypervisors.clone(),
            Arc::clone(&inventory),
            Arc::new(
                SessionLibrary::new(store.clone(), Arc::clone(&links))
                    .with_policy(bus.policy())
                    .with_bindings(bindings.clone()),
            ),
            Arc::clone(&adapters.vault),
        ));
        jobs.set_deployer(deployer.clone());
        // CV-01 to CV-03, VM-17: conversions and exports are jobs; imports convert through the deploy runner.
        let converter = Arc::new(convert::Converter::new(
            hypervisors.clone(),
            Arc::clone(&adapters.disk_tools),
            Arc::clone(&adapters.host_counters),
        ));
        jobs.set_converter(converter.clone());
        deployer.set_converter(Arc::clone(&converter));
        let convert = convert::service::Conversions::new(store.clone(), Arc::clone(&converter), Arc::clone(&bus));
        // FD-04: a support bundle is a job; the job runner writes its zip through the bundle runner.
        jobs.set_bundles(Arc::new(support_bundle::BundleRunner::new(store.clone())));
        let bundles = support_bundle::SupportBundles::new(store.clone(), Arc::clone(&bus));
        let deploy = deploy::service::Deploys::new(
            store.clone(),
            catalog.clone(),
            hypervisors.clone(),
            Arc::clone(&adapters.host_counters),
            Arc::clone(&bus),
        )
        .with_converter(Arc::clone(&converter));
        // VM-08: the job runner runs a stack's steps through the deploy runner and power commands, and waits between
        // them through the stack runner.
        let stack_runner = Arc::new(stacks::StackRunner::new(
            store.clone(),
            hypervisors.clone(),
            Arc::clone(&network),
        ));
        jobs.set_stacks(stack_runner.clone());
        let stacks = stacks::Stacks::new(
            store.clone(),
            catalog.clone(),
            deploy.clone(),
            hypervisors.clone(),
            Arc::clone(&adapters.host_counters),
            Arc::clone(&bus),
            Arc::clone(&inventory),
        );
        let vm_settings =
            vm_settings::VmSettings::new(current.clone(), store.clone(), hypervisors.clone(), Arc::clone(&bus));
        let insight = vm_insight::VmInsight::new(current.clone(), store.clone(), hypervisors.clone());
        let waste = waste::WasteFinder::new(current.clone(), store.clone(), hypervisors.clone())
            .with_inventory(Arc::clone(&inventory));
        // VM-14, VM-27: each run goes through the bus under its schedule's standing approval.
        let schedules = schedules::Schedules::new(schedules::ScheduleParts {
            current: current.clone(),
            store: store.clone(),
            bus: Arc::clone(&bus),
            jobs: Arc::clone(&jobs),
            hypervisors: hypervisors.clone(),
            inventory: Arc::clone(&inventory),
            metrics: Arc::clone(&metrics),
        });
        let core = Self {
            vm_settings,
            networks,
            insight,
            waste,
            convert,
            converter,
            bundles,
            workspaces: workspaces::Workspaces::new(store.clone(), current.clone()),
            current: current.clone(),
            home,
            snapshots: SnapshotReader::new(store.clone(), hypervisors.clone()),
            catalog,
            deploy,
            inventory,
            deployer,
            stack_runner,
            stacks,
            schedules,
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
                .with_bindings(bindings.clone())
                .with_checks(checks.clone()),
            bulk: BulkRuns::new(store.clone()).with_terminals(terminals.clone()),
            retention,
            containers,
            terminals,
            multiexec,
            groups: MultiExecGroups::new(store.clone()),
            files,
            snippets,
            terminal_rules,
            reachability,
            metrics,
            history,
            alerts,
            layouts: Layouts::new(store.clone(), current),
            notifications: Notifications::new(),
            host_details,
            toolbox,
            file_server,
            checks,
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
            toolbox: self.toolbox.clone(),
            terminals: self.terminals.clone(),
            transfer_closed: self.transfer.closer(),
            bindings: self.bindings.clone(),
            file_server: Arc::clone(self.file_server.runner()),
            jobs: Arc::clone(&self.jobs),
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

    /// VM-21: how the deploy runner waits for a guest's IP and for VirtualBox to let go of a VM; tests shorten it.
    pub fn set_deploy_tuning(&self, tuning: deploy::runner::DeployTuning) {
        self.deployer.set_tuning(tuning);
    }

    /// VM-08: the clock a stack job's readiness checks and delays wait on (tests give a fake one, so nothing sleeps),
    /// and how often a readiness check asks.
    pub fn set_stack_clock(&self, clock: Arc<dyn stacks::StackClock>, tuning: stacks::StackTuning) {
        self.stack_runner.set_clock(clock);
        self.stack_runner.set_tuning(tuning);
    }

    /// CV-03: how the conversion runner retries removing what a cancelled tool still holds; tests shorten it.
    pub fn set_convert_tuning(&self, tuning: convert::runner::ConvertTuning) {
        self.converter.set_tuning(tuning);
    }

    /// CV-03: the qemu-img.exe in use, or `None` when it isn't installed (or not found).
    pub fn qemu_img_path(&self) -> Option<PathBuf> {
        self.converter.disk_tools().qemu_img()
    }

    /// CV-03: the qemu-img.exe path saved in Settings, if any.
    pub async fn saved_qemu_img_path(&self) -> Result<Option<PathBuf>> {
        saved_qemu_img_path(&self.store, &self.ctx()).await
    }

    /// CV-03: saves the qemu-img.exe path (`None` = find it: `REMOTELY_QEMU_IMG`, then QEMU's default folder) and
    /// looks for it again at once. The path must be an existing qemu-img.exe. Audited, since it decides which
    /// program converts qcow2 and VHDX images.
    pub async fn set_qemu_img_path(&self, path: Option<PathBuf>) -> Result<Option<PathBuf>> {
        self.store.read_only().check(Change::Settings)?;
        if let Some(path) = &path {
            adapters::disk_tools::validate_qemu_img_path(path)?;
        }
        let as_text = path.as_ref().map(|p| p.display().to_string());
        self.store
            .put_setting(&self.ctx(), store::QEMU_IMG_PATH_KEY, &as_text)
            .await?;
        self.converter.disk_tools().locate_qemu_img(path);
        let in_use = self.qemu_img_path();
        let detail = format!(
            "saved: {}; in use: {}",
            as_text.as_deref().unwrap_or("find automatically"),
            in_use
                .as_ref()
                .map_or_else(|| "not found".to_owned(), |p| p.display().to_string())
        );
        self.audit_setting("Set the qemu-img.exe path", &detail).await?;
        Ok(in_use)
    }

    /// FD-02: who is acting, in the workspace shown now. What the UI reads and changes goes there.
    pub fn ctx(&self) -> Context {
        self.current.get()
    }

    /// FD-02: the user's home workspace (the first one), which keeps this PC's settings.
    pub fn home(&self) -> Context {
        self.home
    }

    /// FD-02: the workspace shown now, as a handle the services that follow it share.
    pub fn current(&self) -> &workspaces::Current {
        &self.current
    }

    /// VM-14, VM-27: the shown workspace's schedules. The scheduler ([`schedules::Schedules::run`]) goes through
    /// every active workspace whichever is shown.
    pub fn schedules(&self) -> schedules::Schedules {
        self.schedules.shown()
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
            file_servers: self.jobs.file_server_jobs(Some(self.ctx().workspace_id)),
        }
    }

    /// QL-15: the page that showed `shown` is gone, so nothing it started may go on without anyone seeing it:
    /// MultiExec stops (a held line is cancelled), its terminals close with their tunnels (each audited), the
    /// approvals it would have answered are cancelled (audited), and FD-09's file server stops (its job ends,
    /// audited). Other running jobs go on; Activity shows them.
    pub async fn release_ui(&self, shown: UiSnapshot) -> UiReleased {
        if let Err(err) = self.multiexec.stop().await {
            tracing::warn!(error = %err, "MultiExec did not stop cleanly after the window reloaded");
        }
        let file_servers = self
            .stop_file_servers(&shown.file_servers, toolbox::file_server::StopReason::PageReloaded)
            .await;
        self.terminals.close_these(&shown.terminals).await;
        let approvals = self
            .bus
            .cancel_approvals(&shown.approvals, "the window reloaded, so nobody could answer it")
            .await;
        UiReleased {
            terminals: shown.terminals.len(),
            approvals,
            file_servers,
        }
    }

    /// FD-09: stops the file server of `jobs` (a job not serving yet, still in its countdown, is cancelled) and waits
    /// for each job to end (journaled and audited), up to [`FILE_SERVER_STOP_WAIT`]. Returns how many there were.
    pub(crate) async fn stop_file_servers(
        &self,
        jobs: &[uuid::Uuid],
        reason: toolbox::file_server::StopReason,
    ) -> usize {
        stop_file_server_jobs(self.file_server.runner(), &self.jobs, jobs, reason);
        for job_id in jobs {
            if tokio::time::timeout(FILE_SERVER_STOP_WAIT, self.jobs.wait(*job_id))
                .await
                .is_err()
            {
                tracing::warn!(%job_id, "the file server's job did not end in time");
            }
        }
        jobs.len()
    }

    /// Before the app exits, also when an update's installer is about to end it (FD-14, QL-15): every terminal
    /// closes, audited, with its tunnels, and session logs are written out to the end. FD-09: the file server stops
    /// and its job ends, audited.
    pub async fn shutdown(&self) {
        let open = self.jobs.file_server_jobs(None);
        self.stop_file_servers(&open, toolbox::file_server::StopReason::AppClosing)
            .await;
        self.terminals.close_all().await;
        // MO-06: the minute still open is written as it is.
        if let Err(err) = self.history.flush_all().await {
            tracing::warn!(error = %err, "could not write the dashboard's last minute of history");
        }
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
        saved_vmrun_path(&self.store, &self.ctx()).await
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
            .put_setting(&self.ctx(), store::VMRUN_PATH_KEY, &as_text)
            .await?;
        let ovftool = saved_ovftool_path(&self.store, &self.ctx()).await?;
        self.vmware
            .replace(Arc::from(adapters::vmware::connect_with(path, ovftool)));
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

    /// VM-21: the ovftool.exe in use (OVA and OVF imports into Workstation), or `None` when it was not found.
    pub fn ovftool_path(&self) -> Option<PathBuf> {
        self.vmware.ovftool_path()
    }

    /// VM-21: the ovftool.exe path saved in Settings, if any.
    pub async fn saved_ovftool_path(&self) -> Result<Option<PathBuf>> {
        saved_ovftool_path(&self.store, &self.ctx()).await
    }

    /// VM-21: saves the ovftool.exe path (`None` = find it: `REMOTELY_OVFTOOL`, then the OVFTool folder next to
    /// vmrun.exe) and looks for it again at once. The path must be an existing ovftool.exe. Audited, since it decides
    /// which program imports appliances.
    pub async fn set_ovftool_path(&self, path: Option<PathBuf>) -> Result<Option<PathBuf>> {
        self.store.read_only().check(Change::Settings)?;
        if let Some(path) = &path {
            adapters::vmware::validate_ovftool_path(path)?;
        }
        let as_text = path.as_ref().map(|p| p.display().to_string());
        self.store
            .put_setting(&self.ctx(), store::OVFTOOL_PATH_KEY, &as_text)
            .await?;
        let vmrun = saved_vmrun_path(&self.store, &self.ctx()).await?;
        self.vmware
            .replace(Arc::from(adapters::vmware::connect_with(vmrun, path)));
        let in_use = self.ovftool_path();
        let detail = format!(
            "saved: {}; in use: {}",
            as_text.as_deref().unwrap_or("find automatically"),
            in_use
                .as_ref()
                .map_or_else(|| "not found".to_owned(), |p| p.display().to_string())
        );
        self.audit_setting("Set the ovftool.exe path", &detail).await?;
        Ok(in_use)
    }

    /// CT-02: the docker.exe in use (Docker Desktop's CLI), or `None` when it was not found.
    pub fn docker_path(&self) -> Option<PathBuf> {
        self.containers.this_pc_cli()
    }

    /// CT-02: the docker.exe path saved in Settings, if any.
    pub async fn saved_docker_path(&self) -> Result<Option<PathBuf>> {
        saved_docker_path(&self.store, &self.ctx()).await
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
            .put_setting(&self.ctx(), containers::DOCKER_PATH_KEY, &as_text)
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

    /// SS-12: the VNC viewer in use (the path saved in Settings, `REMOTELY_VNC_VIEWER`, or a viewer's default
    /// folder), or `None` when none was found.
    pub async fn vnc_viewer_path(&self) -> Result<Option<PathBuf>> {
        self.terminals.vnc_viewer(&self.ctx()).await
    }

    /// SS-12: the VNC viewer path saved in Settings, if any.
    pub async fn saved_vnc_viewer_path(&self) -> Result<Option<PathBuf>> {
        self.terminals.saved_vnc_viewer(&self.ctx()).await
    }

    /// SS-12: saves the VNC viewer's path (`None` = find it: `REMOTELY_VNC_VIEWER`, then the viewers' default
    /// folders). The path must be an existing viewer `.exe` on this PC. Audited, since it decides which program a VNC
    /// session starts.
    pub async fn set_vnc_viewer_path(&self, path: Option<PathBuf>) -> Result<Option<PathBuf>> {
        self.store.read_only().check(Change::Settings)?;
        if let Some(path) = &path {
            adapters::launcher::validate_vnc_viewer_path(path)?;
        }
        let as_text = path.as_ref().map(|p| p.display().to_string());
        self.store
            .put_setting(&self.ctx(), terminal::console::VNC_VIEWER_PATH_KEY, &as_text)
            .await?;
        let in_use = self.vnc_viewer_path().await?;
        let detail = format!(
            "saved: {}; in use: {}",
            as_text.as_deref().unwrap_or("find automatically"),
            in_use
                .as_ref()
                .map_or_else(|| "not found".to_owned(), |p| p.display().to_string())
        );
        self.audit_setting("Set the VNC viewer path", &detail).await?;
        Ok(in_use)
    }

    /// VM-18: path of the VBoxManage.exe in use, or `None` when VirtualBox was not found.
    pub fn vboxmanage_path(&self) -> Option<PathBuf> {
        self.virtualbox.tool_path()
    }

    /// VM-18: the VBoxManage path saved in Settings, if any.
    pub async fn saved_vboxmanage_path(&self) -> Result<Option<PathBuf>> {
        saved_vboxmanage_path(&self.store, &self.ctx()).await
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
            .put_setting(&self.ctx(), store::VBOXMANAGE_PATH_KEY, &as_text)
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
        self.inventory.scan_folders(&self.ctx()).await
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
            .put_setting(&self.ctx(), store::SCAN_FOLDERS_KEY, &as_text)
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
            .put_setting(&self.ctx(), store::POWER_ON_LIMIT_KEY, &limit)
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
            .put_setting(&self.ctx(), store::SHUTDOWN_WAIT_KEY, &secs)
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
            .put_setting(&self.ctx(), store::REMOTE_LIMIT_KEY, &limit)
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
            .put_setting(&self.ctx(), metrics::guest::POLL_KEY, &secs)
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
            .get_setting::<bool>(&self.ctx(), store::UPDATE_CHECKS_KEY)
            .await?
            .unwrap_or(true))
    }

    /// FD-14: turns update checks off (air-gapped sites) or back on. Audited.
    pub async fn set_update_checks(&self, enabled: bool) -> Result<()> {
        self.store.read_only().check(Change::Settings)?;
        self.store
            .put_setting(&self.ctx(), store::UPDATE_CHECKS_KEY, &enabled)
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
                &self.ctx(),
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
        let mut rows = self.store.audit_entries(&self.ctx());
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
                &self.ctx(),
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
        self.terminals.settings(&self.ctx()).await
    }

    /// SS-03: connection settings apply to terminals opened from now on; QL-05's font size and
    /// scrollback to open ones too (the UI applies them); QL-04's checks at once. Audited.
    pub async fn set_terminal_settings(&self, settings: TerminalSettings) -> Result<()> {
        self.store.read_only().check(Change::Settings)?;
        settings.validate()?;
        self.store
            .put_setting(&self.ctx(), TERMINAL_SETTINGS_KEY, &settings)
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

async fn saved_ovftool_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store
        .get_setting::<Option<String>>(ctx, store::OVFTOOL_PATH_KEY)
        .await?;
    Ok(saved.flatten().map(PathBuf::from))
}

async fn saved_qemu_img_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store
        .get_setting::<Option<String>>(ctx, store::QEMU_IMG_PATH_KEY)
        .await?;
    Ok(saved.flatten().map(PathBuf::from))
}

async fn saved_vboxmanage_path(store: &Store, ctx: &Context) -> Result<Option<PathBuf>> {
    let saved = store
        .get_setting::<Option<String>>(ctx, store::VBOXMANAGE_PATH_KEY)
        .await?;
    Ok(saved.flatten().map(PathBuf::from))
}
