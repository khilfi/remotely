//! Host details (MO-13, MO-14): OS and specs for VMs and SSH hosts, and an admin's view of an SSH
//! host on demand. Reads only: nothing here goes through the command bus or is audited (architecture
//! rule 3), and the FD-03 read-only lock doesn't stop it.
//!
//! * MO-13, SSH hosts ([`linux`]): one exec of [`linux::SPECS_SCRIPT`] on an exec channel, never in a
//!   shell, so nothing shows in a terminal, its log, MultiExec or QL-07. It runs
//!   - when a terminal opens, on that terminal's own connection ([`SpecsCollector::on_terminal`]),
//!     unless the facts are younger than [`SpecsTuning::terminal_min_age`];
//!   - from the dashboard's MO-02 poll, on its kept connection, when the facts are older than
//!     [`SpecsTuning::dashboard_max_age`] (checked at most every half hour);
//!   - on Refresh ([`HostDetails::refresh_session`]).
//!
//!   The latest facts are stored per session (migration 0014) with when and how they were read, so they
//!   show offline.
//! * MO-13, VMs: the hypervisor's files ([`crate::adapters::vm_hardware`]), read when the details are
//!   asked for and stored per VM, so they show when the files can't be read.
//! * MO-14 ([`admin`]): services, listening ports, logged-in users, the last boot and top processes,
//!   and separately pending updates (which can take a minute). Nothing polls: each is one read when
//!   the panel asks.
//!
//! Which connection a Refresh or an admin read uses: an open terminal's to the session, then the
//! dashboard's kept one, then a connection of its own, made only because the user asked and kept for
//! a few minutes for the next read. Never a login per read beyond those. Logins use the saved login
//! only, host keys must be trusted already (unknown fails, changed blocks and is audited), each jump
//! host with its own login, and secrets come from the vault for each new connection.

pub mod admin;
pub mod linux;
pub mod networks;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

pub use admin::{AdminDetails, UpdatesReport};
pub use linux::HostSpecs;

use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, ConnectRequest, ExecResult, ExecSession, RemoteAdapter, SessionSpec,
};
use crate::adapters::vm_hardware::VmHardware;
use crate::domain::{now_rfc3339, Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::KnownHosts;
use crate::locks;
use crate::metrics::guest::{spec_key, GuestVerifier};
use crate::metrics::Metrics;
use crate::store::Store;
use crate::terminal::Terminals;
use crate::vault::{Vault, VaultStatus};

/// What read a session's stored facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CollectedBy {
    /// A terminal's own connection, when it opened.
    Terminal,
    /// The dashboard's kept connection (MO-02).
    Dashboard,
    /// The user asked.
    Refresh,
}

impl CollectedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            CollectedBy::Terminal => "terminal",
            CollectedBy::Dashboard => "dashboard",
            CollectedBy::Refresh => "refresh",
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "terminal" => CollectedBy::Terminal,
            "dashboard" => CollectedBy::Dashboard,
            _ => CollectedBy::Refresh,
        }
    }
}

/// The connection a read ran on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Via {
    /// An open terminal's connection to the session.
    Terminal,
    /// The dashboard's kept connection (the session is watched).
    Dashboard,
    /// A connection Remotely made for this, kept for a few minutes.
    OwnConnection,
}

/// MO-13: a session's facts with when and how they were read.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSpecs {
    pub session_id: Uuid,
    pub specs: HostSpecs,
    pub collected_at: String,
    pub collected_by: CollectedBy,
    /// When the host last started: the read's time less its uptime.
    pub booted_at: Option<String>,
}

impl SessionSpecs {
    fn new(session_id: Uuid, specs: HostSpecs, collected_at: String, collected_by: CollectedBy) -> Self {
        let booted_at = specs.uptime_secs.and_then(|up| {
            let at = OffsetDateTime::parse(&collected_at, &Rfc3339).ok()?;
            let booted = at - time::Duration::seconds(i64::try_from(up).ok()?);
            booted.format(&Rfc3339).ok()
        });
        Self {
            session_id,
            specs,
            collected_at,
            collected_by,
            booted_at,
        }
    }
}

/// MO-14: the admin read.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminReport {
    pub session_id: Uuid,
    pub details: AdminDetails,
    pub collected_at: String,
    pub via: Via,
}

/// MO-16: what the dashboard's services widget shows of a watched host.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicesReport {
    pub session_id: Uuid,
    pub service_manager: admin::ServiceManager,
    pub running: Vec<admin::Service>,
    pub failed: Vec<admin::Service>,
    /// Without systemd: the services the init system lists as stopped or unknown.
    pub other: Vec<admin::Service>,
    pub collected_at: String,
}

/// MO-16: the services widget's read: done on the dashboard's kept connection, or not at all.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ServicesRead {
    Read {
        report: ServicesReport,
    },
    /// Nothing was read and nobody logged in for it: the host is not watched (`watched: false`), or the
    /// dashboard's connection to it is not up just now.
    NotConnected {
        watched: bool,
    },
}

/// MO-14: pending updates.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesCheck {
    pub session_id: Uuid,
    pub report: UpdatesReport,
    pub checked_at: String,
    pub took_ms: u64,
    pub via: Via,
}

/// MO-13: a VM's hardware, and what its guest says when a linked session has facts.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSpecs {
    /// The VM's key: .vmx path or VirtualBox UUID.
    pub vmx_path: String,
    pub hypervisor: Hypervisor,
    pub hardware: VmHardware,
    pub collected_at: String,
    /// The files could not be read now: this is what was read before.
    pub stored: bool,
    /// Why they could not be read now.
    pub problem: Option<String>,
    /// The guest's own facts, from a session linked to the VM.
    pub guest: Option<SessionSpecs>,
    pub guest_session_name: Option<String>,
}

/// The dashboard's one line, e.g. "4 vCPU · 8 GB · Ubuntu 24.04".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecsBrief {
    pub cpus: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub os: Option<String>,
    pub collected_at: String,
}

/// A short OS name and version: "Ubuntu 24.04", "RHEL 9.4", "Debian 12".
pub fn short_os(specs: &HostSpecs) -> Option<String> {
    let os = &specs.os;
    let name = match os.id.as_deref() {
        Some("ubuntu") => Some("Ubuntu".to_owned()),
        Some("rhel") => Some("RHEL".to_owned()),
        Some("debian") => Some("Debian".to_owned()),
        Some("centos") => Some("CentOS".to_owned()),
        Some("rocky") => Some("Rocky Linux".to_owned()),
        Some("almalinux") => Some("AlmaLinux".to_owned()),
        Some("fedora") => Some("Fedora".to_owned()),
        Some("ol") => Some("Oracle Linux".to_owned()),
        Some("sles") => Some("SLES".to_owned()),
        Some("opensuse-leap") => Some("openSUSE Leap".to_owned()),
        Some("alpine") => Some("Alpine".to_owned()),
        Some("amzn") => Some("Amazon Linux".to_owned()),
        _ => os.name.clone(),
    };
    match (name, os.version_id.as_deref()) {
        (Some(name), Some(version)) => Some(format!("{name} {version}")),
        (Some(name), None) => Some(name),
        (None, _) => specs.os_name(),
    }
}

impl SpecsBrief {
    fn of(specs: &HostSpecs, collected_at: &str) -> Self {
        Self {
            cpus: specs.cpu.logical_cpus,
            memory_bytes: specs.memory.total_bytes,
            os: short_os(specs),
            collected_at: collected_at.to_owned(),
        }
    }
}

/// Time limits and ages. The defaults suit real networks; tests shorten them.
#[derive(Debug, Clone)]
pub struct SpecsTuning {
    /// One run of [`linux::SPECS_SCRIPT`].
    pub specs_timeout: Duration,
    /// One run of [`admin::ADMIN_SCRIPT`].
    pub admin_timeout: Duration,
    /// [`admin::UPDATES_SCRIPT`]: dnf may refresh its metadata first.
    pub updates_timeout: Duration,
    /// A terminal that opens reads the facts only when they are older than this.
    pub terminal_min_age: Duration,
    /// The dashboard reads them again when they are older than this.
    pub dashboard_max_age: Duration,
    /// How often the dashboard looks at their age.
    pub dashboard_check: Duration,
    pub connect_timeout: Duration,
    /// Remotely's own connection closes after this long without a read.
    pub idle: Duration,
    /// VBoxManage and disk files.
    pub vm_timeout: Duration,
    pub agent: AgentSource,
}

impl Default for SpecsTuning {
    fn default() -> Self {
        Self {
            specs_timeout: Duration::from_secs(20),
            admin_timeout: Duration::from_secs(30),
            updates_timeout: Duration::from_secs(150),
            terminal_min_age: Duration::from_secs(10 * 60),
            dashboard_max_age: Duration::from_secs(6 * 3600),
            dashboard_check: Duration::from_secs(30 * 60),
            connect_timeout: Duration::from_secs(15),
            idle: Duration::from_secs(180),
            vm_timeout: Duration::from_secs(30),
            agent: AgentSource::System,
        }
    }
}

struct CollectorInner {
    store: Store,
    tuning: RwLock<SpecsTuning>,
    /// Sessions whose facts are being read now: a second terminal of the same session skips.
    busy: Mutex<HashMap<Uuid, Instant>>,
}

/// Reads a session's facts on a connection someone else holds (a terminal's, the dashboard's) and
/// stores them. Cloning gives another handle to the same one.
#[derive(Clone)]
pub struct SpecsCollector {
    inner: Arc<CollectorInner>,
}

/// Marks a session busy while its facts are read; clears the mark when dropped.
struct Busy<'a> {
    collector: &'a SpecsCollector,
    session_id: Uuid,
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        locks::lock(&self.collector.inner.busy).remove(&self.session_id);
    }
}

impl SpecsCollector {
    pub fn new(store: Store) -> Self {
        Self {
            inner: Arc::new(CollectorInner {
                store,
                tuning: RwLock::new(SpecsTuning::default()),
                busy: Mutex::default(),
            }),
        }
    }

    pub fn tuning(&self) -> SpecsTuning {
        locks::read(&self.inner.tuning).clone()
    }

    pub fn set_tuning(&self, tuning: SpecsTuning) {
        *locks::write(&self.inner.tuning) = tuning;
    }

    fn claim(&self, session_id: Uuid) -> Option<Busy<'_>> {
        let mut busy = locks::lock(&self.inner.busy);
        if busy.contains_key(&session_id) {
            return None;
        }
        busy.insert(session_id, Instant::now());
        Some(Busy {
            collector: self,
            session_id,
        })
    }

    /// How old the stored facts are; `None` when there are none (or their time can't be read).
    async fn age(&self, ctx: &Context, session_id: Uuid) -> Result<Option<Duration>> {
        let Some(stored) = self.inner.store.session_specs(ctx, session_id).await? else {
            return Ok(None);
        };
        Ok(age_of(&stored.collected_at))
    }

    /// Runs the script, parses and stores what it printed. A host that answers unlike Linux stores
    /// nothing.
    pub async fn collect(
        &self,
        ctx: &Context,
        session_id: Uuid,
        exec: &dyn ExecSession,
        by: CollectedBy,
    ) -> Result<SessionSpecs> {
        let timeout = self.tuning().specs_timeout;
        let result = run_with_timeout(exec, linux::SPECS_SCRIPT, linux::MAX_OUTPUT, timeout).await?;
        let specs = linux::parse(&result.output.stdout);
        if specs.is_empty() {
            return Err(CoreError::InvalidInput(
                "the host answered, but not like Linux: host details need a Linux host".into(),
            ));
        }
        let collected_at = now_rfc3339();
        let json = serde_json::to_string(&specs).map_err(|err| CoreError::InvalidInput(err.to_string()))?;
        self.inner
            .store
            .put_session_specs(ctx, session_id, &json, &collected_at, by.as_str())
            .await?;
        Ok(SessionSpecs::new(session_id, specs, collected_at, by))
    }

    /// Reads the facts when they are older than `min_age` (or missing) and no one is reading them now.
    /// `Ok(None)`: nothing to do.
    pub async fn collect_if_older(
        &self,
        ctx: &Context,
        session_id: Uuid,
        exec: &dyn ExecSession,
        min_age: Duration,
        by: CollectedBy,
    ) -> Result<Option<SessionSpecs>> {
        let Some(_busy) = self.claim(session_id) else {
            return Ok(None);
        };
        if self.age(ctx, session_id).await?.is_some_and(|age| age < min_age) {
            return Ok(None);
        }
        self.collect(ctx, session_id, exec, by).await.map(Some)
    }

    /// MO-13: a terminal to a saved session connected. Runs beside the shell, on its connection's exec
    /// channel; a failure is only logged (the terminal doesn't wait for it or show it).
    pub fn on_terminal(&self, ctx: Context, session_id: Uuid, exec: Arc<dyn ExecSession>) {
        let collector = self.clone();
        tokio::spawn(async move {
            let min_age = collector.tuning().terminal_min_age;
            if let Err(err) = collector
                .collect_if_older(&ctx, session_id, exec.as_ref(), min_age, CollectedBy::Terminal)
                .await
            {
                tracing::debug!(%session_id, error = %err, "host details: reading on a terminal's connection failed");
            }
        });
    }
}

fn age_of(at: &str) -> Option<Duration> {
    let then = OffsetDateTime::parse(at, &Rfc3339).ok()?;
    let secs = (OffsetDateTime::now_utc() - then).whole_seconds();
    Some(Duration::from_secs(u64::try_from(secs).unwrap_or(0)))
}

async fn run_with_timeout(
    exec: &dyn ExecSession,
    script: &str,
    max_output: usize,
    timeout: Duration,
) -> Result<ExecResult> {
    tokio::time::timeout(timeout, exec.run(script, max_output))
        .await
        .map_err(|_| CoreError::Timeout {
            command: "reading the host's details".into(),
            seconds: timeout.as_secs(),
        })?
}

/// Remotely's own connection to one session.
#[derive(Default)]
struct Kept {
    spec_key: String,
    connection: Option<Arc<dyn ExecSession>>,
    used: Option<Instant>,
}

struct Inner {
    store: Store,
    collector: SpecsCollector,
    terminals: Terminals,
    metrics: Arc<Metrics>,
    hypervisors: Hypervisors,
    vault: Arc<dyn Vault>,
    remote: Arc<dyn RemoteAdapter>,
    known_hosts: Arc<KnownHosts>,
    kept: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<Kept>>>>,
}

/// What [`HostDetails::new`] needs.
pub struct HostDetailsParts {
    pub store: Store,
    pub collector: SpecsCollector,
    pub terminals: Terminals,
    pub metrics: Arc<Metrics>,
    pub hypervisors: Hypervisors,
    pub vault: Arc<dyn Vault>,
    pub remote: Arc<dyn RemoteAdapter>,
    pub known_hosts: Arc<KnownHosts>,
}

/// The host details service. Cloning gives another handle to the same one.
#[derive(Clone)]
pub struct HostDetails {
    inner: Arc<Inner>,
}

impl HostDetails {
    pub fn new(parts: HostDetailsParts) -> Self {
        let inner = Arc::new(Inner {
            store: parts.store,
            collector: parts.collector,
            terminals: parts.terminals,
            metrics: parts.metrics,
            hypervisors: parts.hypervisors,
            vault: parts.vault,
            remote: parts.remote,
            known_hosts: parts.known_hosts,
            kept: Mutex::default(),
        });
        // Remotely's own connections close on their own when idle.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak: Weak<Inner> = Arc::downgrade(&inner);
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    close_idle(&inner).await;
                }
            });
        }
        Self { inner }
    }

    pub fn collector(&self) -> &SpecsCollector {
        &self.inner.collector
    }

    /// MO-13: what was last read about the session, if anything. Makes no connection.
    pub async fn session_specs(&self, ctx: &Context, session_id: Uuid) -> Result<Option<SessionSpecs>> {
        let Some(stored) = self.inner.store.session_specs(ctx, session_id).await? else {
            return Ok(None);
        };
        Ok(decode(session_id, &stored))
    }

    /// MO-13 Refresh: reads the facts now, on the connection [`HostDetails`] picks (which may log in,
    /// since the user asked).
    pub async fn refresh_session(&self, ctx: &Context, session_id: Uuid) -> Result<SessionSpecs> {
        let (exec, _via) = self.connection(ctx, session_id).await?;
        self.inner
            .collector
            .collect(ctx, session_id, exec.as_ref(), CollectedBy::Refresh)
            .await
    }

    /// MO-14: services, ports, users, boots and processes, read now.
    pub async fn admin(&self, ctx: &Context, session_id: Uuid) -> Result<AdminReport> {
        let (exec, via) = self.connection(ctx, session_id).await?;
        let timeout = self.inner.collector.tuning().admin_timeout;
        let result = run_with_timeout(exec.as_ref(), admin::ADMIN_SCRIPT, admin::MAX_OUTPUT, timeout).await?;
        Ok(AdminReport {
            session_id,
            details: admin::parse(&result.output.stdout),
            collected_at: now_rfc3339(),
            via,
        })
    }

    /// MO-16: the services widget's read of a watched host, every minute while the dashboard shows: on the
    /// dashboard's kept connection only, so it adds no login (MO-02's login guard rules stand as they are).
    /// A host that is not watched, or whose connection is down, reads nothing.
    pub async fn services(&self, session_id: Uuid) -> Result<ServicesRead> {
        let guest = self.inner.metrics.guest();
        let Some(exec) = guest.kept_connection(session_id).await else {
            let watched = guest.watched().await?.contains(&session_id);
            return Ok(ServicesRead::NotConnected { watched });
        };
        let timeout = self.inner.collector.tuning().admin_timeout;
        let result = run_with_timeout(exec.as_ref(), admin::SERVICES_SCRIPT, admin::MAX_OUTPUT, timeout).await?;
        let details = admin::parse(&result.output.stdout);
        Ok(ServicesRead::Read {
            report: ServicesReport {
                session_id,
                service_manager: details.service_manager,
                running: details.running,
                failed: details.failed,
                other: details.other_services,
                collected_at: now_rfc3339(),
            },
        })
    }

    /// MO-14: pending updates (apt's lists as they are, or dnf, which may refresh its metadata first).
    pub async fn updates(&self, ctx: &Context, session_id: Uuid) -> Result<UpdatesCheck> {
        let (exec, via) = self.connection(ctx, session_id).await?;
        let timeout = self.inner.collector.tuning().updates_timeout;
        let started = Instant::now();
        let result = tokio::time::timeout(timeout, exec.run(admin::UPDATES_SCRIPT, admin::MAX_OUTPUT))
            .await
            .map_err(|_| CoreError::Timeout {
                command: "checking for updates (the package manager may still be refreshing its metadata)".into(),
                seconds: timeout.as_secs(),
            })??;
        Ok(UpdatesCheck {
            session_id,
            report: admin::parse_updates(&result.output.stdout),
            checked_at: now_rfc3339(),
            took_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            via,
        })
    }

    /// Closes Remotely's own connection to the session, if it has one (the panel closed).
    pub async fn release(&self, session_id: Uuid) {
        let slot = locks::lock(&self.inner.kept).remove(&session_id);
        if let Some(slot) = slot {
            if let Some(connection) = slot.lock().await.connection.take() {
                connection.close().await;
            }
        }
    }

    /// SS-04: the vault locked: Remotely's own connections close (they logged in with vault secrets).
    pub async fn close_all(&self) {
        let slots: Vec<Arc<tokio::sync::Mutex<Kept>>> =
            locks::lock(&self.inner.kept).drain().map(|(_, slot)| slot).collect();
        for slot in slots {
            if let Some(connection) = slot.lock().await.connection.take() {
                connection.close().await;
            }
        }
    }

    /// MO-13: a VM's hardware, read from its files now; what was read before when they can't be read.
    pub async fn vm_specs(&self, ctx: &Context, vmx_path: &str) -> Result<VmSpecs> {
        self.inner.store.require_vm_here(ctx, vmx_path).await?;
        let vm = self
            .inner
            .store
            .find_vm(ctx, vmx_path)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(vmx_path.to_owned()))?;
        let timeout = self.inner.collector.tuning().vm_timeout;
        let read = tokio::time::timeout(timeout, self.inner.hypervisors.hardware(&vm.vmx_path))
            .await
            .unwrap_or_else(|_| {
                Err(CoreError::Timeout {
                    command: format!("reading {}'s hardware", vm.display_name),
                    seconds: timeout.as_secs(),
                })
            });
        let (hardware, collected_at, stored, problem) = match read {
            Ok(mut hardware) => {
                // VMware: the inventory may know what VMware Tools reported when the .vmx doesn't say.
                // (VirtualBox's is "Linux <kernel>" for Linux guests: the adapter keeps the kernel apart.)
                if hardware.guest_os_name.is_none() && vm.hypervisor == Hypervisor::Vmware {
                    hardware.guest_os_name.clone_from(&vm.guest_os_name);
                }
                let at = now_rfc3339();
                if let Ok(json) = serde_json::to_string(&hardware) {
                    self.inner.store.put_vm_specs(ctx, &vm.id, &json, &at).await?;
                }
                (hardware, at, false, None)
            }
            Err(err) => {
                let saved = self.inner.store.vm_specs(ctx, &vm.id).await?;
                match saved.and_then(|s| Some((serde_json::from_str::<VmHardware>(&s.specs).ok()?, s.collected_at))) {
                    Some((hardware, at)) => (hardware, at, true, Some(err.to_string())),
                    None => return Err(err),
                }
            }
        };
        // The guest's own facts, from a linked session that has some (the one read last).
        let linked = self
            .inner
            .store
            .sessions_by_vm(ctx)
            .await?
            .remove(&vm.id)
            .unwrap_or_default();
        let mut guest: Option<SessionSpecs> = None;
        for session_id in linked {
            if let Some(specs) = self.session_specs(ctx, session_id).await? {
                if guest.as_ref().is_none_or(|g| g.collected_at < specs.collected_at) {
                    guest = Some(specs);
                }
            }
        }
        let guest_session_name = match &guest {
            Some(g) => self.inner.store.get_session(ctx, g.session_id).await?.map(|s| s.name),
            None => None,
        };
        Ok(VmSpecs {
            vmx_path: vm.vmx_path.clone(),
            hypervisor: vm.hypervisor,
            hardware,
            collected_at,
            stored,
            problem,
            guest,
            guest_session_name,
        })
    }

    /// The connection a read uses: an open terminal's, the dashboard's, or Remotely's own.
    async fn connection(&self, ctx: &Context, session_id: Uuid) -> Result<(Arc<dyn ExecSession>, Via)> {
        if let Some(exec) = self.inner.terminals.commands_for(session_id) {
            return Ok((exec, Via::Terminal));
        }
        if let Some(exec) = self.inner.metrics.guest().kept_connection(session_id).await {
            return Ok((exec, Via::Dashboard));
        }
        let spec = self
            .inner
            .store
            .session_spec(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(session_id.to_string()))?;
        Ok((self.own_connection(ctx, &spec).await?, Via::OwnConnection))
    }

    async fn own_connection(&self, ctx: &Context, spec: &SessionSpec) -> Result<Arc<dyn ExecSession>> {
        let slot = Arc::clone(locks::lock(&self.inner.kept).entry(spec.id).or_default());
        let mut kept = slot.lock().await;
        let key = spec_key(spec);
        if kept.spec_key != key || kept.connection.as_ref().is_some_and(|c| c.is_closed()) {
            if let Some(old) = kept.connection.take() {
                old.close().await;
            }
        }
        if kept.connection.is_none() {
            kept.connection = Some(self.connect(ctx, spec).await?);
            kept.spec_key = key;
        }
        kept.used = Some(Instant::now());
        kept.connection
            .clone()
            .ok_or_else(|| CoreError::Ssh("no connection".into()))
    }

    /// Logs in with the saved login only: nothing is asked.
    async fn connect(&self, ctx: &Context, spec: &SessionSpec) -> Result<Arc<dyn ExecSession>> {
        let mut hops = spec.jumps();
        hops.push(spec);
        for hop in &hops {
            let what = if hop.id == spec.id {
                format!("'{}'", hop.name)
            } else {
                format!("the jump host '{}'", hop.name)
            };
            if hop.auth == AuthMethod::Password(None) {
                return Err(CoreError::AuthFailed(format!(
                    "no password is saved for {what}. Save it in the vault and choose it in that session, or open a terminal to it first"
                )));
            }
            let needs_vault = matches!(hop.auth, AuthMethod::Password(Some(_)) | AuthMethod::PrivateKey { .. });
            if needs_vault && self.inner.vault.status() != VaultStatus::Unlocked {
                return Err(CoreError::VaultLocked);
            }
        }
        let tuning = self.inner.collector.tuning();
        let credentials = crate::sessions::credentials(self.inner.vault.as_ref(), ctx, spec, None).await?;
        let jump_credentials =
            crate::sessions::jump_credentials(self.inner.vault.as_ref(), ctx, spec, &HashMap::new()).await?;
        let options = ConnectOptions {
            connect_timeout: tuning.connect_timeout,
            agent: tuning.agent.clone(),
            ..ConnectOptions::default()
        };
        let verifier = Arc::new(GuestVerifier {
            known_hosts: Arc::clone(&self.inner.known_hosts),
            ctx: *ctx,
            target: Target {
                target: TargetRef::Session { session_id: spec.id },
                name: spec.name.clone(),
                environment: spec.environment,
                protected: false,
            },
            record_blocked: true,
        });
        let limit = tuning.connect_timeout.saturating_mul(2);
        let connected = tokio::time::timeout(
            limit,
            self.inner.remote.connect(ConnectRequest {
                session: spec,
                credentials,
                jump_credentials,
                options: &options,
                verifier,
            }),
        )
        .await
        .map_err(|_| CoreError::Timeout {
            command: format!("logging in to '{}'", spec.name),
            seconds: limit.as_secs(),
        })?;
        match connected {
            Ok(connection) => Ok(Arc::from(connection)),
            Err(CoreError::HostKeyUnknown { address, jump }) => {
                let place = match &jump {
                    Some(name) => format!("the jump host '{name}' ({address})"),
                    None => address.clone(),
                };
                Err(CoreError::Ssh(format!(
                    "the host key of {place} is not trusted yet. Connect to it once in a terminal to check and trust it"
                )))
            }
            Err(err) => Err(err),
        }
    }
}

async fn close_idle(inner: &Inner) {
    let idle = inner.collector.tuning().idle;
    let slots: Vec<(Uuid, Arc<tokio::sync::Mutex<Kept>>)> = locks::lock(&inner.kept)
        .iter()
        .map(|(id, s)| (*id, Arc::clone(s)))
        .collect();
    for (id, slot) in slots {
        let Ok(mut kept) = slot.try_lock() else {
            continue;
        };
        if kept.used.is_none_or(|used| used.elapsed() >= idle) {
            if let Some(connection) = kept.connection.take() {
                connection.close().await;
            }
            drop(kept);
            locks::lock(&inner.kept).remove(&id);
        }
    }
}

fn decode(session_id: Uuid, stored: &crate::store::StoredSpecs) -> Option<SessionSpecs> {
    let specs: HostSpecs = serde_json::from_str(&stored.specs).ok()?;
    Some(SessionSpecs::new(
        session_id,
        specs,
        stored.collected_at.clone(),
        CollectedBy::parse(stored.collected_by.as_deref().unwrap_or("refresh")),
    ))
}

/// MO-13: each session's one-line summary for the dashboard, from the stored facts. The dashboard asks
/// every round, so the summaries are kept (P8): a round reads only when each session's facts were read,
/// and parses the stored JSON again only when one of them changed.
#[derive(Default)]
pub(crate) struct Briefs {
    /// By session: when its facts were read, and their summary (`None`: they don't parse).
    kept: Mutex<HashMap<Uuid, (String, Option<SpecsBrief>)>>,
}

impl Briefs {
    pub(crate) async fn get(&self, store: &Store, ctx: &Context) -> Result<HashMap<Uuid, SpecsBrief>> {
        let times = store.session_specs_times(ctx).await?;
        let changed = {
            let kept = locks::lock(&self.kept);
            times.len() != kept.len()
                || times
                    .iter()
                    .any(|(id, at)| kept.get(id).is_none_or(|(kept_at, _)| kept_at != at))
        };
        if changed {
            let parsed: HashMap<Uuid, (String, Option<SpecsBrief>)> = store
                .all_session_specs(ctx)
                .await?
                .into_iter()
                .map(|(id, stored)| {
                    let brief = serde_json::from_str::<HostSpecs>(&stored.specs)
                        .ok()
                        .map(|specs| SpecsBrief::of(&specs, &stored.collected_at));
                    (id, (stored.collected_at, brief))
                })
                .collect();
            *locks::lock(&self.kept) = parsed;
        }
        Ok(locks::lock(&self.kept)
            .iter()
            .filter_map(|(id, (_, brief))| Some((*id, brief.clone()?)))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_for_the_dashboard() {
        let specs = linux::parse(&linux::samples::ubuntu());
        assert_eq!(short_os(&specs).as_deref(), Some("Ubuntu 24.04"));
        let brief = SpecsBrief::of(&specs, "2026-10-22T10:00:00Z");
        assert_eq!(brief.cpus, Some(4));
        assert_eq!(brief.memory_bytes, Some(8_131_116 * 1024));

        let mut rhel = HostSpecs::default();
        rhel.os.id = Some("rhel".into());
        rhel.os.version_id = Some("9.4".into());
        assert_eq!(short_os(&rhel).as_deref(), Some("RHEL 9.4"));
        let mut other = HostSpecs::default();
        other.os.name = Some("Gentoo".into());
        assert_eq!(short_os(&other).as_deref(), Some("Gentoo"));
        let mut old = HostSpecs::default();
        old.os.pretty_name = Some("CentOS release 6.10 (Final)".into());
        assert_eq!(short_os(&old).as_deref(), Some("CentOS release 6.10 (Final)"));
    }

    #[test]
    fn the_boot_time_is_the_read_less_the_uptime() {
        let specs = HostSpecs {
            uptime_secs: Some(3 * 86_400 + 3600),
            ..HostSpecs::default()
        };
        let read = SessionSpecs::new(Uuid::nil(), specs, "2026-10-22T10:00:00Z".into(), CollectedBy::Terminal);
        assert_eq!(read.booted_at.as_deref(), Some("2026-10-19T09:00:00Z"));
        assert!(age_of("2026-10-22T10:00:00Z").is_some());
        assert_eq!(age_of("yesterday"), None);
    }
}
