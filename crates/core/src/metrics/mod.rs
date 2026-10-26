//! Metrics collector (MO-01 to MO-04). Reads only: samples go to the dashboard without passing the
//! command bus (CLAUDE.md, architecture rule 3).
//!
//! Two sources, because Workstation has no per-VM metrics API:
//! * Host side, no login ([`HostProcessSource`], MO-01): each running VM is a `vmware-vmx.exe`
//!   process; Windows gives its CPU, working set and disk I/O.
//! * Guest side, login needed ([`guest::GuestSource`], MO-02): /proc and `df` over SSH for the
//!   sessions the user watches, Linux only.
//!
//! [`Metrics`] polls both every 5 seconds, keeps the latest sample and 30 minutes of history per
//! series in memory ([`MetricsHub`]), measures what a round costs, and builds the dashboard's rows
//! (MO-03) and host capacity panel (MO-04). After each round it hands what it read to its observers
//! ([`RoundObserver`]): MO-06's history on disk ([`history`]) and MO-07's alerts ([`crate::alerts`]).

pub mod guest;
pub mod history;
pub mod procfs;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::host_counters::{HostCounters, HostTotals, SystemCpuTimes};
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::paging::PagingInfo;
use crate::adapters::vmware::path_key;
use crate::capacity::{CapacityChecker, HostCapacity};
use crate::domain::{now_rfc3339, Context, Environment, PowerState, TargetRef};
use crate::error::Result;
use crate::locks;
use crate::store::{NewAuditEntry, Store};
use crate::workspaces::Current;

pub use guest::{GuestSource, GuestTuning, WATCHED_KEY};
pub use procfs::MountUsage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MetricSource {
    Host,
    Guest,
}

impl MetricSource {
    pub fn as_str(self) -> &'static str {
        match self {
            MetricSource::Host => "host",
            MetricSource::Guest => "guest",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSample {
    pub source: MetricSource,
    pub target: TargetRef,
    pub ts: String,
    /// Busy share of the machine's own CPUs: a VM's vCPUs (host side) or the guest's CPUs.
    pub cpu_pct: Option<f64>,
    /// Host side: the VM process's share of this whole host's CPU, as Task Manager shows it.
    pub host_cpu_pct: Option<f64>,
    /// Host side: the VM process's working set as a share of this host's physical RAM.
    pub host_mem_pct: Option<f64>,
    /// Host side: the VM process's working set. Guest side: memory in use (total minus available).
    pub mem_bytes: Option<u64>,
    /// Host side: RAM assigned to the VM. Guest side: the guest's total memory.
    pub mem_total_bytes: Option<u64>,
    /// MO-15, guest side: swap in use and its size.
    pub swap_used_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub disk_read_bps: Option<f64>,
    pub disk_write_bps: Option<f64>,
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
    pub uptime_secs: Option<u64>,
    /// Guest side: space used on each mounted disk.
    pub mounts: Vec<MountUsage>,
}

impl MetricSample {
    /// The fullest mounted disk, in percent used.
    pub fn fullest_mount_pct(&self) -> Option<f64> {
        self.mounts.iter().map(|m| m.used_pct).reduce(f64::max)
    }
}

/// MO-01: one running VM's share of this host, for the VM list. From the latest host-side sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmHostUsage {
    pub vmx_path: String,
    pub host_cpu_pct: Option<f64>,
    pub host_mem_pct: Option<f64>,
    /// The VM process's working set.
    pub mem_bytes: Option<u64>,
    pub ts: String,
}

/// One point of a drill-down chart (MO-03).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricPoint {
    /// Unix time in milliseconds.
    pub t: i64,
    pub cpu_pct: Option<f64>,
    pub mem_bytes: Option<u64>,
    /// MO-15: the memory there is: a VM's configured RAM, a guest's or this PC's total.
    pub mem_total_bytes: Option<u64>,
    /// MO-15: swap (Linux) or the paging files (this PC) in use, and their size.
    pub swap_used_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub disk_read_bps: Option<f64>,
    pub disk_write_bps: Option<f64>,
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
    pub load1: Option<f64>,
    /// The fullest mounted disk.
    pub disk_used_pct: Option<f64>,
}

/// MO-02: where guest polling stands for one watched session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GuestState {
    /// Waiting for the first reading.
    Connecting,
    Ok,
    /// Logging in needs a secret from the vault, which is locked. Tried again once it is unlocked.
    VaultLocked,
    /// Can't reach the host, or it stopped answering.
    Unreachable,
    /// The host refused the login, or the login needs something typed.
    LoginFailed,
    /// The host key is not trusted yet, or it changed (blocked).
    HostKey,
    /// The hourly cap on background logins to the host was reached: waiting.
    Paused,
    /// The host answered, but not like Linux (no /proc).
    NoData,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestStatus {
    pub session_id: Uuid,
    pub state: GuestState,
    /// What went wrong, in words for the user. Never holds a secret.
    pub message: Option<String>,
    /// Seconds until the next try, while backing off.
    pub retry_in_secs: Option<u64>,
    /// When the last good reading arrived.
    pub last_ok: Option<String>,
    /// No new login until the session or its credentials change or the user presses Retry.
    pub parked: bool,
}

impl GuestStatus {
    pub fn new(session_id: Uuid, state: GuestState, message: Option<String>) -> Self {
        Self {
            session_id,
            state,
            message,
            retry_in_secs: None,
            last_ok: None,
            parked: false,
        }
    }
}

/// MO-01 NFR: what collecting costs, shown on the dashboard.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorCost {
    pub rounds: u64,
    pub interval_secs: u64,
    /// MO-02, P8: seconds between two polls of a watched host (Settings).
    pub guest_interval_secs: u64,
    /// Wall time of the last round, and of each source in it (they run side by side).
    pub round_ms: f64,
    pub host_ms: f64,
    pub guest_ms: f64,
    /// CPU this app's process used since the previous round, as a share of the whole host (the way
    /// Task Manager shows processes). It covers everything the core did in that time, so it is an
    /// upper bound on the collector's own cost. The window's WebView runs in its own processes.
    pub app_cpu_pct: Option<f64>,
    /// VM processes and guests read in the last round.
    pub vms: usize,
    pub guests: usize,
    pub collected_at: Option<String>,
}

/// One source's part of a round.
#[derive(Debug, Clone, Default)]
pub struct SourceRound {
    pub samples: Vec<MetricSample>,
    /// Guest side: every watched session's state.
    pub statuses: Vec<GuestStatus>,
    /// Host side, FD-02: the keys of every VM process seen, whichever workspace has the VM (the samples are the
    /// shown workspace's only). The capacity panel counts them all: they share this PC.
    pub running: Option<Vec<String>>,
}

#[async_trait]
pub trait MetricsSource: Send + Sync {
    fn name(&self) -> &'static str;
    async fn collect(&self) -> Result<SourceRound>;
}

/// MO-01: per-VM CPU, RAM and disk I/O from the `vmware-vmx.exe` processes, read through the host
/// counters adapter and matched to the inventory by .vmx path. FD-02: only the shown workspace's VMs; a process
/// whose VM the workspace doesn't list (another workspace's, or one no workspace has) is left out.
pub struct HostProcessSource {
    counters: Arc<dyn HostCounters>,
    store: Store,
    current: Current,
}

impl HostProcessSource {
    pub fn new(counters: Arc<dyn HostCounters>, store: Store, current: Current) -> Self {
        Self {
            counters,
            store,
            current,
        }
    }
}

/// A VM process's share of its own vCPUs, from its share of the whole host.
fn vcpu_share(host_pct: f64, logical_cpus: u32, vcpus: u32) -> Option<f64> {
    (vcpus > 0 && logical_cpus > 0).then(|| (host_pct * f64::from(logical_cpus) / f64::from(vcpus)).clamp(0.0, 100.0))
}

/// MO-01: a VM process's working set as a share of the host's physical RAM.
fn host_ram_share(working_set_bytes: u64, physical_ram_mb: u64) -> Option<f64> {
    let physical = physical_ram_mb.checked_mul(1024 * 1024).filter(|b| *b > 0)?;
    Some((working_set_bytes as f64 * 100.0 / physical as f64).clamp(0.0, 100.0))
}

#[async_trait]
impl MetricsSource for HostProcessSource {
    fn name(&self) -> &'static str {
        "host-process"
    }

    async fn collect(&self) -> Result<SourceRound> {
        let processes = self.counters.vm_processes().await?;
        // P8: no VM runs, so there is nothing to name or size: the inventory isn't read.
        if processes.is_empty() {
            return Ok(SourceRound {
                running: Some(Vec::new()),
                ..SourceRound::default()
            });
        }
        let running: Vec<String> = processes.iter().filter_map(|p| p.vmx_path.clone()).collect();
        let ts = now_rfc3339();
        // One read of the host's totals per round gives both shares of the host (MO-01).
        let totals = self.counters.host_totals().await.ok();
        let cpus = totals.map(|t| t.logical_cpus);
        let ram_mb = totals.map(|t| t.physical_ram_mb);
        // The inventory names the VM and gives its size. FD-02: a VM the shown workspace doesn't list isn't shown.
        let vms = self.store.list_vms(&self.current.get()).await.unwrap_or_default();
        let by_path: HashMap<String, &crate::store::VmRecord> =
            vms.iter().map(|v| (path_key(Path::new(&v.vmx_path)), v)).collect();
        // VM-18: a VirtualBox process started with the VM's name instead of its UUID.
        let vbox_by_name = virtualbox_names(&vms);
        let samples: Vec<MetricSample> = processes
            .into_iter()
            .filter_map(|p| {
                let by_name = || {
                    p.name
                        .as_deref()
                        .and_then(|name| vbox_by_name.get(&name.to_lowercase()))
                        .map(|vm| vm.vmx_path.clone())
                };
                let vmx = p.vmx_path.clone().or_else(by_name)?;
                let vm = Some(by_path.get(&path_key(Path::new(&vmx))).copied()?);
                let vcpus = vm.and_then(|v| v.num_vcpus);
                Some(MetricSample {
                    source: MetricSource::Host,
                    target: TargetRef::Vm {
                        vmx_path: vm.map_or(vmx, |v| v.vmx_path.clone()),
                    },
                    ts: ts.clone(),
                    cpu_pct: p
                        .cpu_pct
                        .zip(cpus.zip(vcpus))
                        .and_then(|(pct, (cpus, vcpus))| vcpu_share(pct, cpus, vcpus)),
                    host_cpu_pct: p.cpu_pct,
                    host_mem_pct: p
                        .working_set_bytes
                        .zip(ram_mb)
                        .and_then(|(bytes, mb)| host_ram_share(bytes, mb)),
                    mem_bytes: p.working_set_bytes,
                    mem_total_bytes: vm.and_then(|v| v.memsize_mb).map(|mb| u64::from(mb) * 1024 * 1024),
                    swap_used_bytes: None,
                    swap_total_bytes: None,
                    disk_read_bps: p.read_bps,
                    disk_write_bps: p.write_bps,
                    net_rx_bps: None,
                    net_tx_bps: None,
                    load1: None,
                    load5: None,
                    load15: None,
                    uptime_secs: None,
                    mounts: Vec::new(),
                })
            })
            .collect();
        // VM-18: a VirtualBox process named by its VM rather than its UUID counts once it is matched.
        let mut running = running;
        for sample in &samples {
            let key = sample.target.key();
            if !running.iter().any(|r| r.eq_ignore_ascii_case(&key)) {
                running.push(key);
            }
        }
        Ok(SourceRound {
            samples,
            statuses: Vec::new(),
            running: Some(running),
        })
    }
}

/// VM-18: VirtualBox VMs by their name (lower case), for processes that name their VM rather than
/// giving its UUID. A name two VMs share matches neither.
fn virtualbox_names(vms: &[crate::store::VmRecord]) -> HashMap<String, &crate::store::VmRecord> {
    let mut by_name: HashMap<String, Option<&crate::store::VmRecord>> = HashMap::new();
    for vm in vms.iter().filter(|v| v.hypervisor == Hypervisor::VirtualBox) {
        by_name
            .entry(vm.display_name.to_lowercase())
            .and_modify(|seen| *seen = None)
            .or_insert(Some(vm));
    }
    by_name
        .into_iter()
        .filter_map(|(name, vm)| vm.map(|vm| (name, vm)))
        .collect()
}

/// Which series a sample belongs to: its source and its target's key (.vmx path, VirtualBox UUID or
/// session id).
type SeriesKey = (MetricSource, String);

#[derive(Default)]
struct HubState {
    latest: HashMap<SeriesKey, MetricSample>,
    history: HashMap<SeriesKey, VecDeque<MetricPoint>>,
    statuses: HashMap<Uuid, GuestStatus>,
    /// The .vmx paths whose process the last good host round saw.
    running: Option<Vec<String>>,
    host_cpu_pct: Option<f64>,
    cost: CollectorCost,
    /// MO-15: this PC's RAM and paging files, round by round.
    this_pc: VecDeque<MetricPoint>,
    this_pc_latest: Option<ThisPcMemory>,
}

/// MO-15: this PC's memory now: RAM, the commit charge and the paging files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThisPcMemory {
    pub ram_total_bytes: u64,
    pub ram_used_bytes: u64,
    pub paging: Option<PagingInfo>,
}

/// The latest samples and an in-memory history per series, newest last.
pub struct MetricsHub {
    window: Duration,
    state: Mutex<HubState>,
}

impl MetricsHub {
    /// MO-03 drill-down: 30 minutes of history (360 points at 5 s) per series.
    pub const HISTORY: Duration = Duration::from_secs(30 * 60);

    pub fn new(window: Duration) -> Self {
        Self {
            window,
            state: Mutex::new(HubState::default()),
        }
    }

    pub(crate) fn point(t: i64, s: &MetricSample) -> MetricPoint {
        MetricPoint {
            t,
            cpu_pct: s.cpu_pct,
            mem_bytes: s.mem_bytes,
            mem_total_bytes: s.mem_total_bytes,
            swap_used_bytes: s.swap_used_bytes,
            swap_total_bytes: s.swap_total_bytes,
            disk_read_bps: s.disk_read_bps,
            disk_write_bps: s.disk_write_bps,
            net_rx_bps: s.net_rx_bps,
            net_tx_bps: s.net_tx_bps,
            load1: s.load1,
            disk_used_pct: s.fullest_mount_pct(),
        }
    }

    /// Records a round at `t` (Unix ms). `host: None` means the host side could not be read this
    /// round, so what it showed before stays. Guest series of sessions no longer watched are dropped.
    fn record(&self, t: i64, host: Option<Vec<MetricSample>>, guest: Option<SourceRound>) {
        let mut state = locks::lock(&self.state);
        let oldest = t - i64::try_from(self.window.as_millis()).unwrap_or(i64::MAX);
        if let Some(samples) = host {
            state.latest.retain(|(source, _), _| *source != MetricSource::Host);
            state.running = Some(samples.iter().map(|s| s.target.key()).collect());
            for sample in samples {
                let key = (MetricSource::Host, sample.target.key());
                state
                    .history
                    .entry(key.clone())
                    .or_default()
                    .push_back(Self::point(t, &sample));
                state.latest.insert(key, sample);
            }
        }
        if let Some(round) = guest {
            let watched: HashSet<String> = round.statuses.iter().map(|s| s.session_id.to_string()).collect();
            state
                .latest
                .retain(|(source, key), _| *source != MetricSource::Guest || watched.contains(key));
            state
                .history
                .retain(|(source, key), _| *source != MetricSource::Guest || watched.contains(key));
            state.statuses = round.statuses.into_iter().map(|s| (s.session_id, s)).collect();
            for sample in round.samples {
                let key = (MetricSource::Guest, sample.target.key());
                state
                    .history
                    .entry(key.clone())
                    .or_default()
                    .push_back(Self::point(t, &sample));
                state.latest.insert(key, sample);
            }
        }
        for points in state.history.values_mut() {
            while points.front().is_some_and(|p| p.t < oldest) {
                points.pop_front();
            }
        }
        state.history.retain(|_, points| !points.is_empty());
    }

    pub fn latest(&self, source: MetricSource, key: &str) -> Option<MetricSample> {
        locks::lock(&self.state).latest.get(&(source, key.to_owned())).cloned()
    }

    /// The series' points within the history window, oldest first.
    pub fn series(&self, source: MetricSource, key: &str) -> Vec<MetricPoint> {
        locks::lock(&self.state)
            .history
            .get(&(source, key.to_owned()))
            .map(|points| points.iter().copied().collect())
            .unwrap_or_default()
    }

    /// MO-01: each VM process the last good host round saw, with its share of the host. Reads
    /// memory only: no extra polling.
    pub fn host_usage(&self) -> Vec<VmHostUsage> {
        let state = locks::lock(&self.state);
        let mut usage: Vec<VmHostUsage> = state
            .latest
            .iter()
            .filter(|((source, _), _)| *source == MetricSource::Host)
            .map(|((_, key), s)| VmHostUsage {
                vmx_path: key.clone(),
                host_cpu_pct: s.host_cpu_pct,
                host_mem_pct: s.host_mem_pct,
                mem_bytes: s.mem_bytes,
                ts: s.ts.clone(),
            })
            .collect();
        usage.sort_by(|a, b| a.vmx_path.cmp(&b.vmx_path));
        usage
    }

    pub fn statuses(&self) -> HashMap<Uuid, GuestStatus> {
        locks::lock(&self.state).statuses.clone()
    }

    /// FD-02: forgets every reading (another workspace is shown). The collector's cost and this PC's own numbers
    /// stay: they are the PC's.
    pub fn clear(&self) {
        let mut state = locks::lock(&self.state);
        state.latest.clear();
        state.history.clear();
        state.statuses.clear();
    }

    pub fn running(&self) -> Option<Vec<String>> {
        locks::lock(&self.state).running.clone()
    }

    pub fn cost(&self) -> CollectorCost {
        locks::lock(&self.state).cost.clone()
    }

    /// MO-15: records this PC's memory (and, MO-06, its CPU) at `t`, keeping the history window.
    fn record_this_pc(&self, t: i64, memory: ThisPcMemory, cpu_pct: Option<f64>) {
        let mut state = locks::lock(&self.state);
        let oldest = t - i64::try_from(self.window.as_millis()).unwrap_or(i64::MAX);
        state.this_pc.push_back(this_pc_point(t, &memory, cpu_pct));
        while state.this_pc.front().is_some_and(|p| p.t < oldest) {
            state.this_pc.pop_front();
        }
        state.this_pc_latest = Some(memory);
    }

    /// This PC's CPU busy share, as the last round that could read it saw it.
    pub fn host_cpu_pct(&self) -> Option<f64> {
        locks::lock(&self.state).host_cpu_pct
    }

    /// MO-15: this PC's RAM in use and total (`mem_bytes`, `mem_total_bytes`) and its paging files in use
    /// and size (`swap_used_bytes`, `swap_total_bytes`), oldest first.
    pub fn this_pc_series(&self) -> Vec<MetricPoint> {
        locks::lock(&self.state).this_pc.iter().copied().collect()
    }

    pub fn this_pc(&self) -> Option<ThisPcMemory> {
        locks::lock(&self.state).this_pc_latest.clone()
    }
}

/// MO-15, MO-06: this PC's point of a round: its CPU busy share, RAM in use and all there is, and its paging files.
fn this_pc_point(t: i64, memory: &ThisPcMemory, cpu_pct: Option<f64>) -> MetricPoint {
    let paging = memory.paging.as_ref();
    MetricPoint {
        t,
        cpu_pct,
        mem_bytes: Some(memory.ram_used_bytes),
        mem_total_bytes: Some(memory.ram_total_bytes),
        swap_used_bytes: paging.map(|p| p.used_bytes),
        swap_total_bytes: paging.map(|p| p.total_bytes),
        disk_read_bps: None,
        disk_write_bps: None,
        net_rx_bps: None,
        net_tx_bps: None,
        load1: None,
        disk_used_pct: None,
    }
}

/// What one round read, handed to the collector's observers once it is recorded in the hub.
pub struct RecordedRound<'a> {
    /// When the round was recorded, Unix time in milliseconds.
    pub t_ms: i64,
    /// The VMs' host-side samples; `None` when the host side could not be read this round.
    pub host: Option<&'a [MetricSample]>,
    /// The guests polled in this round (a guest polled less often has no sample in the rounds between);
    /// `None` when the guest side failed.
    pub guest: Option<&'a [MetricSample]>,
    /// MO-15: this PC's memory, when it could be read.
    pub this_pc: Option<&'a ThisPcMemory>,
    /// This PC's CPU busy share since the previous round.
    pub host_cpu_pct: Option<f64>,
    /// Everything recorded so far: the latest samples, guest states, the running VMs.
    pub hub: &'a MetricsHub,
}

impl RecordedRound<'_> {
    /// This PC's point of the round, when its memory could be read.
    pub fn this_pc_point(&self) -> Option<MetricPoint> {
        self.this_pc.map(|m| this_pc_point(self.t_ms, m, self.host_cpu_pct))
    }
}

/// Something that follows the collector's rounds: MO-06's history on disk, MO-07's alerts. Called after
/// each round, in order; a slow observer delays the next round, so each does little (or once a minute).
#[async_trait]
pub trait RoundObserver: Send + Sync {
    async fn after_round(&self, round: &RecordedRound<'_>);
}

/// A session linked to a VM row, or the session of a session row.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedSession {
    pub id: Uuid,
    pub name: String,
    /// QL-01: linked automatically by IP address and not confirmed yet.
    pub auto: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RowKind {
    Vm,
    Session,
}

/// MO-03: one row of the overview grid: a VM (host-side metrics, plus guest metrics from a watched
/// linked session) or a watched session that is not a known VM's.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardRow {
    pub kind: RowKind,
    /// The VM's key (.vmx path or VirtualBox UUID) or the session id.
    pub key: String,
    pub name: String,
    /// VM-18: a VM row's hypervisor; `None` for a session.
    pub hypervisor: Option<Hypervisor>,
    pub environment: Environment,
    pub protected: bool,
    pub tags: Vec<String>,
    /// VMs: running whenever its process was seen in the last round, else the inventory's state.
    pub power_state: Option<PowerState>,
    /// A VM's vCPUs; MO-13: a host's CPUs, from its stored facts.
    pub vcpus: Option<u32>,
    /// A VM's configured RAM; MO-13: a host's RAM, from its stored facts.
    pub memsize_mb: Option<u32>,
    /// A VM's IP, or a session's `user@host:port`.
    pub address: Option<String>,
    pub guest_os: Option<String>,
    /// MO-13: when the host's (or the VM's linked session's) facts were read.
    pub specs_at: Option<String>,
    pub host: Option<MetricSample>,
    pub guest: Option<MetricSample>,
    /// Sessions that reach this VM, or the session itself.
    pub sessions: Vec<LinkedSession>,
    /// The session whose guest metrics this row shows, when one is watched.
    pub watched_session: Option<Uuid>,
    pub guest_status: Option<GuestStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardOverview {
    pub rows: Vec<DashboardRow>,
    pub cost: CollectorCost,
}

/// What the metrics collector needs. Built by [`crate::Core::assemble`].
pub struct MetricsParts {
    pub store: Store,
    /// FD-02: the workspace shown, whose VMs and watched hosts the rounds read.
    pub current: Current,
    pub counters: Arc<dyn HostCounters>,
    pub guest: GuestSource,
    pub capacity: CapacityChecker,
}

/// The previous round's CPU readings, for this app's and the host's CPU share.
struct CpuWatch {
    at: Instant,
    own: Duration,
    system: Option<SystemCpuTimes>,
}

/// The metrics collector: polls the host and guest sources, keeps their samples, and answers the
/// dashboard.
pub struct Metrics {
    store: Store,
    current: Current,
    counters: Arc<dyn HostCounters>,
    host: HostProcessSource,
    guest: GuestSource,
    capacity: CapacityChecker,
    hub: MetricsHub,
    interval: Duration,
    rounds: Mutex<u64>,
    cpu: Mutex<Option<CpuWatch>>,
    tx: broadcast::Sender<CollectorCost>,
    /// MO-13: the rows' one-line summaries, parsed once per reading of a host's facts.
    briefs: crate::host_details::Briefs,
    /// MO-06, MO-07: what follows the rounds (history on disk, alerts), in the order added.
    observers: Mutex<Vec<Arc<dyn RoundObserver>>>,
}

impl Metrics {
    /// MO-01 refresh rate.
    pub const INTERVAL: Duration = Duration::from_secs(5);

    pub fn new(parts: MetricsParts) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            host: HostProcessSource::new(Arc::clone(&parts.counters), parts.store.clone(), parts.current.clone()),
            store: parts.store,
            current: parts.current,
            counters: parts.counters,
            guest: parts.guest,
            capacity: parts.capacity,
            hub: MetricsHub::new(MetricsHub::HISTORY),
            interval: Self::INTERVAL,
            rounds: Mutex::new(0),
            cpu: Mutex::new(None),
            tx,
            briefs: crate::host_details::Briefs::default(),
            observers: Mutex::new(Vec::new()),
        }
    }

    pub fn hub(&self) -> &MetricsHub {
        &self.hub
    }

    /// MO-06, MO-07: `observer` follows every round from the next one on.
    pub fn add_observer(&self, observer: Arc<dyn RoundObserver>) {
        locks::lock(&self.observers).push(observer);
    }

    pub fn guest(&self) -> &GuestSource {
        &self.guest
    }

    /// The cost of each round, sent after it is recorded (the UI refreshes on it).
    pub fn subscribe(&self) -> broadcast::Receiver<CollectorCost> {
        self.tx.subscribe()
    }

    /// One round: both sources side by side, then the samples, statuses and cost are recorded.
    pub async fn collect_once(&self) -> CollectorCost {
        self.collect_once_at(history::now_ms()).await
    }

    /// One round recorded at `now_ms` (Unix ms): what [`Metrics::collect_once`] does with the wall clock.
    /// Tests give their own clock, so history minutes and alert durations pass without waiting.
    pub async fn collect_once_at(&self, now_ms: i64) -> CollectorCost {
        async fn timed(source: &dyn MetricsSource) -> (Result<SourceRound>, f64) {
            let started = Instant::now();
            let result = source.collect().await;
            (result, started.elapsed().as_secs_f64() * 1000.0)
        }
        let started = Instant::now();
        let ((host, host_ms), (guest, guest_ms)) = tokio::join!(timed(&self.host), timed(&self.guest));
        let round_ms = started.elapsed().as_secs_f64() * 1000.0;
        let host = host
            .inspect_err(|err| tracing::warn!(source = self.host.name(), error = %err, "metrics source failed"))
            .ok();
        let guest = guest
            .inspect_err(|err| tracing::warn!(source = self.guest.name(), error = %err, "metrics source failed"))
            .ok();
        let (app_cpu_pct, host_cpu_pct, totals) = self.cpu_shares().await;
        // MO-15: this PC's memory, from the totals just read and two cheap calls for the paging files.
        let this_pc = totals.map(|t| ThisPcMemory {
            ram_total_bytes: t.physical_ram_mb.saturating_mul(1024 * 1024),
            ram_used_bytes: t
                .physical_ram_mb
                .saturating_sub(t.available_ram_mb)
                .saturating_mul(1024 * 1024),
            paging: None,
        });
        let this_pc = match this_pc {
            Some(mut memory) => {
                memory.paging = self.counters.paging().await.ok();
                Some(memory)
            }
            None => None,
        };
        let rounds = {
            let mut rounds = locks::lock(&self.rounds);
            *rounds += 1;
            *rounds
        };
        let cost = CollectorCost {
            rounds,
            interval_secs: self.interval.as_secs(),
            guest_interval_secs: self.guest.interval().as_secs(),
            round_ms,
            host_ms,
            guest_ms,
            app_cpu_pct,
            vms: host.as_ref().map_or(0, |r| r.samples.len()),
            guests: guest.as_ref().map_or(0, |r| r.samples.len()),
            collected_at: Some(now_rfc3339()),
        };
        // FD-02: every VM process seen, for the capacity panel (the samples are the shown workspace's only).
        let host_running = host.as_ref().and_then(|r| r.running.clone());
        // Kept for the observers: the hub takes its own copy.
        let host_samples = host.map(|r| r.samples);
        let guest_samples = guest.as_ref().map(|r| r.samples.clone());
        let this_pc_kept = this_pc.clone();
        self.hub.record(now_ms, host_samples.clone(), guest);
        if host_running.is_some() {
            locks::lock(&self.hub.state).running = host_running;
        }
        if let Some(memory) = this_pc {
            self.hub.record_this_pc(now_ms, memory, host_cpu_pct);
        }
        {
            let mut state = locks::lock(&self.hub.state);
            state.cost = cost.clone();
            if host_cpu_pct.is_some() {
                state.host_cpu_pct = host_cpu_pct;
            }
        }
        let observers: Vec<Arc<dyn RoundObserver>> = locks::lock(&self.observers).clone();
        if !observers.is_empty() {
            let round = RecordedRound {
                t_ms: now_ms,
                host: host_samples.as_deref(),
                guest: guest_samples.as_deref(),
                this_pc: this_pc_kept.as_ref(),
                host_cpu_pct,
                hub: &self.hub,
            };
            for observer in &observers {
                observer.after_round(&round).await;
            }
        }
        // No subscriber is fine (tests, or the window is closed).
        let _ = self.tx.send(cost.clone());
        cost
    }

    /// This app's CPU share and the host's busy share since the previous round, and the host's totals
    /// read for them.
    async fn cpu_shares(&self) -> (Option<f64>, Option<f64>, Option<HostTotals>) {
        let at = Instant::now();
        let own = self.counters.own_cpu_time().await.ok();
        let system = self.counters.system_cpu_times().await.ok();
        let totals = self.counters.host_totals().await.ok();
        let cpus = totals.map(|t| t.logical_cpus);
        let mut watch = locks::lock(&self.cpu);
        let shares = match (watch.as_ref(), own) {
            (Some(before), Some(own)) => {
                let wall = at.saturating_duration_since(before.at).as_secs_f64();
                let app = cpus.filter(|_| wall > 0.0).and_then(|cpus| {
                    let used = own.checked_sub(before.own)?.as_secs_f64();
                    Some((used / wall / f64::from(cpus.max(1)) * 100.0).clamp(0.0, 100.0))
                });
                let host = system
                    .zip(before.system)
                    .and_then(|(now, then)| now.busy_pct_since(&then));
                (app, host)
            }
            _ => (None, None),
        };
        if let Some(own) = own {
            *watch = Some(CpuWatch { at, own, system });
        }
        (shares.0, shares.1, totals)
    }

    /// Polls every [`Metrics::INTERVAL`] until `stop` is cancelled. The caller spawns it on its runtime.
    pub async fn run(&self, stop: CancellationToken) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = ticker.tick() => {}
            }
            self.collect_once().await;
        }
    }

    /// MO-03: the overview grid. Running VMs (or VMs with a watched session) and watched sessions
    /// that are not a known VM's, with their latest samples and guest states.
    pub async fn overview(&self, ctx: &Context) -> Result<DashboardOverview> {
        let vms = self.store.list_vms(ctx).await?;
        let sessions = self.store.list_sessions(ctx).await?;
        let by_vm = self.store.sessions_by_vm(ctx).await?;
        let watched: HashSet<Uuid> = self.guest.watched().await?.into_iter().collect();
        let statuses = self.hub.statuses();
        // Every running or paused VM has a vmware-vmx process, so once a round has listed them, that
        // list is fresher than the inventory's last refresh.
        let running: Option<HashSet<String>> = self
            .hub
            .running()
            .map(|paths| paths.iter().map(|p| path_key(Path::new(p))).collect());
        let names: HashMap<Uuid, &crate::sessions::SessionRecord> = sessions.iter().map(|s| (s.id, s)).collect();
        let guest_of = |id: Uuid| self.hub.latest(MetricSource::Guest, &id.to_string());
        // MO-13: each session's stored facts, for the one-line summary under a row.
        let briefs = self.briefs.get(&self.store, ctx).await.unwrap_or_default();

        let mut rows = Vec::new();
        let mut on_vm_rows: HashSet<Uuid> = HashSet::new();
        for vm in &vms {
            let linked: Vec<LinkedSession> = by_vm
                .get(&vm.id)
                .into_iter()
                .flatten()
                .filter_map(|id| names.get(id))
                .map(|s| LinkedSession {
                    id: s.id,
                    name: s.name.clone(),
                    auto: s.vm_link == Some(crate::vm_links::VmLink::Auto),
                })
                .collect();
            let watched_session = linked.iter().map(|s| s.id).find(|id| watched.contains(id));
            let power_state = match running.as_ref().map(|r| r.contains(&path_key(Path::new(&vm.vmx_path)))) {
                Some(true) if vm.power_state == PowerState::Paused => PowerState::Paused,
                Some(true) => PowerState::Running,
                // Stopped since the inventory looked.
                Some(false) if vm.power_state.is_on() => PowerState::NotRunning,
                _ => vm.power_state,
            };
            if !power_state.is_on() && watched_session.is_none() {
                continue;
            }
            // The watched session's facts first, then any linked session's.
            let brief = watched_session
                .into_iter()
                .chain(linked.iter().map(|s| s.id))
                .find_map(|id| briefs.get(&id));
            on_vm_rows.extend(linked.iter().map(|s| s.id));
            rows.push(DashboardRow {
                kind: RowKind::Vm,
                key: vm.vmx_path.clone(),
                name: vm.display_name.clone(),
                hypervisor: Some(vm.hypervisor),
                environment: vm.environment,
                protected: vm.protected,
                tags: vm.tags.clone(),
                power_state: Some(power_state),
                vcpus: vm.num_vcpus,
                memsize_mb: vm.memsize_mb,
                address: vm.ip_address.clone(),
                guest_os: vm
                    .guest_os_name
                    .clone()
                    .or_else(|| brief.and_then(|b| b.os.clone()))
                    .or_else(|| vm.guest_os.clone()),
                specs_at: brief.map(|b| b.collected_at.clone()),
                host: self.hub.latest(MetricSource::Host, &vm.vmx_path),
                guest: watched_session.and_then(guest_of),
                sessions: linked,
                watched_session,
                guest_status: watched_session.and_then(|id| statuses.get(&id).cloned()),
            });
        }
        for session in &sessions {
            if !watched.contains(&session.id) || on_vm_rows.contains(&session.id) {
                continue;
            }
            let user = session.username.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
            let brief = briefs.get(&session.id);
            rows.push(DashboardRow {
                kind: RowKind::Session,
                key: session.id.to_string(),
                name: session.name.clone(),
                hypervisor: None,
                environment: session.environment,
                protected: session.protected,
                tags: session.tags.clone(),
                power_state: None,
                vcpus: brief.and_then(|b| b.cpus),
                memsize_mb: brief
                    .and_then(|b| b.memory_bytes)
                    .and_then(|bytes| u32::try_from(bytes / (1024 * 1024)).ok()),
                address: Some(format!(
                    "{user}{}",
                    crate::known_hosts::address(&session.host, session.port)
                )),
                guest_os: brief.and_then(|b| b.os.clone()),
                specs_at: brief.map(|b| b.collected_at.clone()),
                host: None,
                guest: guest_of(session.id),
                sessions: vec![LinkedSession {
                    id: session.id,
                    name: session.name.clone(),
                    auto: false,
                }],
                watched_session: Some(session.id),
                guest_status: statuses.get(&session.id).cloned(),
            });
        }
        rows.sort_by_key(|a| a.name.to_lowercase());
        Ok(DashboardOverview {
            rows,
            cost: self.hub.cost(),
        })
    }

    /// MO-04: the host capacity panel. The running VMs are the ones whose process the last round saw.
    pub async fn capacity(&self, ctx: &Context) -> HostCapacity {
        let mut capacity = self.capacity.host_capacity(ctx, self.hub.running()).await;
        capacity.host_cpu_pct = locks::lock(&self.hub.state).host_cpu_pct;
        // MO-15: the paging files, as the last round read them.
        capacity.paging = self.hub.this_pc().and_then(|m| m.paging);
        capacity
    }

    /// MO-02: the sessions watched for guest metrics.
    pub async fn watched(&self) -> Result<Vec<Uuid>> {
        self.guest.watched().await
    }

    /// MO-02: starts or stops guest metrics for a session. Watching means the app logs in to the
    /// host every round, so the change is audited like other settings. Reads only: no approval.
    pub async fn set_watched(&self, ctx: &Context, session_id: Uuid, watch: bool) -> Result<Vec<Uuid>> {
        let session = self
            .store
            .get_session(ctx, session_id)
            .await?
            .ok_or(crate::error::CoreError::UnknownTarget(session_id.to_string()))?;
        let mut watched = self.guest.watched().await?;
        if watched.contains(&session_id) == watch {
            return Ok(watched);
        }
        watched.retain(|id| *id != session_id);
        if watch {
            watched.push(session_id);
        }
        self.store.put_setting(ctx, WATCHED_KEY, &watched).await?;
        let target = session.target();
        let action = if watch {
            "Started guest metrics"
        } else {
            "Stopped guest metrics"
        };
        let detail = format!(
            "{} ({}), read over SSH every {} s",
            session.name,
            session.host,
            self.interval.as_secs()
        );
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: std::slice::from_ref(&target),
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        Ok(watched)
    }

    /// The context the collector reads for: the workspace shown.
    pub fn ctx(&self) -> Context {
        self.current.get()
    }

    /// FD-02: another workspace is shown: the old one's kept connections close, its hosts are forgotten, and the
    /// readings kept in memory go, so its VMs' and hosts' numbers never show in the new one.
    pub async fn leave_workspace(&self) {
        self.guest.leave_workspace().await;
        self.hub.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(source: MetricSource, target: TargetRef, cpu: f64) -> MetricSample {
        MetricSample {
            source,
            target,
            ts: now_rfc3339(),
            cpu_pct: Some(cpu),
            host_cpu_pct: None,
            host_mem_pct: None,
            mem_bytes: None,
            mem_total_bytes: None,
            swap_used_bytes: None,
            swap_total_bytes: None,
            disk_read_bps: None,
            disk_write_bps: None,
            net_rx_bps: None,
            net_tx_bps: None,
            load1: None,
            load5: None,
            load15: None,
            uptime_secs: None,
            mounts: Vec::new(),
        }
    }

    #[test]
    fn a_vm_process_share_of_the_host_becomes_a_share_of_its_vcpus() {
        assert_eq!(vcpu_share(12.5, 16, 2), Some(100.0));
        assert_eq!(vcpu_share(3.125, 16, 2), Some(25.0));
        assert_eq!(
            vcpu_share(50.0, 16, 2),
            Some(100.0),
            "overhead threads can go past its vCPUs"
        );
        assert_eq!(vcpu_share(10.0, 16, 0), None);
    }

    #[test]
    fn a_vm_process_working_set_becomes_a_share_of_host_ram() {
        const GB: u64 = 1024 * 1024 * 1024;
        assert_eq!(host_ram_share(8 * GB, 32 * 1024), Some(25.0));
        assert_eq!(host_ram_share(GB / 2, 16 * 1024), Some(3.125));
        assert_eq!(host_ram_share(0, 32 * 1024), Some(0.0));
        assert_eq!(
            host_ram_share(64 * GB, 32 * 1024),
            Some(100.0),
            "never past the whole host"
        );
        assert_eq!(host_ram_share(GB, 0), None, "host RAM unknown");
        assert_eq!(host_ram_share(GB, u64::MAX), None, "nonsense totals");
    }

    #[test]
    fn host_usage_lists_the_vms_the_last_host_round_saw() {
        let hub = MetricsHub::new(Duration::from_secs(60));
        let vm = |name: &str, cpu: f64, mem: f64| MetricSample {
            host_cpu_pct: Some(cpu),
            host_mem_pct: Some(mem),
            mem_bytes: Some(1024),
            ..sample(
                MetricSource::Host,
                TargetRef::Vm {
                    vmx_path: format!(r"C:\VMs\{name}\{name}.vmx"),
                },
                cpu * 8.0,
            )
        };
        let web = Uuid::new_v4();
        hub.record(
            0,
            Some(vec![vm("web", 6.25, 12.5), vm("db", 1.0, 25.0)]),
            Some(SourceRound {
                samples: vec![sample(
                    MetricSource::Guest,
                    TargetRef::Session { session_id: web },
                    50.0,
                )],
                statuses: vec![GuestStatus::new(web, GuestState::Ok, None)],
                running: None,
            }),
        );
        let usage = hub.host_usage();
        let shares: Vec<(&str, Option<f64>, Option<f64>)> = usage
            .iter()
            .map(|u| (u.vmx_path.as_str(), u.host_cpu_pct, u.host_mem_pct))
            .collect();
        assert_eq!(
            shares,
            [
                (r"C:\VMs\db\db.vmx", Some(1.0), Some(25.0)),
                (r"C:\VMs\web\web.vmx", Some(6.25), Some(12.5)),
            ],
            "VMs only, not guests"
        );
        // web stopped: no share any more, so the lists show a dash for it.
        hub.record(5_000, Some(vec![vm("db", 2.0, 25.0)]), None);
        assert_eq!(hub.host_usage().len(), 1);
        // The host side failed to read: what it showed stays.
        hub.record(10_000, None, None);
        assert_eq!(hub.host_usage()[0].host_cpu_pct, Some(2.0));
    }

    #[test]
    fn history_keeps_the_window_and_follows_running_vms_and_watched_hosts() {
        let hub = MetricsHub::new(Duration::from_secs(60));
        let vm = |name: &str| TargetRef::Vm {
            vmx_path: format!(r"C:\VMs\{name}\{name}.vmx"),
        };
        let web = Uuid::new_v4();
        let guest_round = |cpu: f64| SourceRound {
            samples: vec![sample(MetricSource::Guest, TargetRef::Session { session_id: web }, cpu)],
            statuses: vec![GuestStatus::new(web, GuestState::Ok, None)],
            running: None,
        };

        hub.record(
            0,
            Some(vec![sample(MetricSource::Host, vm("a"), 10.0)]),
            Some(guest_round(1.0)),
        );
        hub.record(
            30_000,
            Some(vec![
                sample(MetricSource::Host, vm("a"), 20.0),
                sample(MetricSource::Host, vm("b"), 5.0),
            ]),
            Some(guest_round(2.0)),
        );
        let a = vm("a").key();
        assert_eq!(hub.series(MetricSource::Host, &a).len(), 2);
        assert_eq!(hub.latest(MetricSource::Host, &a).unwrap().cpu_pct, Some(20.0));
        assert_eq!(hub.running().unwrap().len(), 2);

        // b stopped: no longer latest, its history stays for the drill-down. The host side failed
        // to read in the next round: what it showed stays.
        hub.record(
            90_000,
            Some(vec![sample(MetricSource::Host, vm("a"), 30.0)]),
            Some(guest_round(3.0)),
        );
        assert!(hub.latest(MetricSource::Host, &vm("b").key()).is_none());
        assert_eq!(hub.series(MetricSource::Host, &vm("b").key()).len(), 1);
        hub.record(95_000, None, None);
        assert_eq!(hub.latest(MetricSource::Host, &a).unwrap().cpu_pct, Some(30.0));
        // Older than the 60 s window: gone.
        let points: Vec<i64> = hub.series(MetricSource::Host, &a).iter().map(|p| p.t).collect();
        assert_eq!(points, [90_000]);
        assert!(hub.series(MetricSource::Host, &vm("b").key()).is_empty());

        // The session is no longer watched: its series and state go.
        hub.record(
            100_000,
            None,
            Some(SourceRound {
                samples: Vec::new(),
                statuses: Vec::new(),
                running: None,
            }),
        );
        assert!(hub.latest(MetricSource::Guest, &web.to_string()).is_none());
        assert!(hub.series(MetricSource::Guest, &web.to_string()).is_empty());
        assert!(hub.statuses().is_empty());
    }
}
