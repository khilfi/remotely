//! Job runner: runs commands the bus has cleared, against each target, with bounded parallelism.
//!
//! * Parallel limits: power-ons default to 3 (VM-06), remote commands to 10 (BX-02).
//! * Graceful shutdown (VM-03): a soft stop gets a set time; a VM still running after it is reported
//!   ([`JobEvent::StillRunning`]) and left running. Forcing it off is a separate hard-stop command,
//!   which the policy engine puts at Critical, so it gets its own approval.
//! * Graceful power operations (soft stop, restart, suspend) go through VMware Tools, and vmrun waits
//!   for Tools rather than failing when they are not running. So Tools are checked first, and a VM
//!   without them fails at once with the reason (VM-02, VM-03).
//! * VM-18 VirtualBox VMs: a soft stop presses the ACPI power button (the guest OS must handle it; no
//!   Guest Additions needed) and waits for the VM to be off, up to the shutdown wait as above. A
//!   graceful restart (`controlvm reboot`) needs the Guest Additions, so they are checked first, like
//!   VMware Tools. Suspend saves the VM's state without the guest's help.
//! * Countdown with cancel after approval (AP-03); cancel stops targets that have not started (BX-04)
//!   and stops waiting for a power call in flight, e.g. on a VM that waits for an answer in
//!   Workstation. vmrun is killed, but Workstation may still finish the action, so that target is
//!   reported as cancelled with its outcome unknown. A snapshot call in flight is left to finish: its
//!   outcome must be known (VM-05). A remote command in flight has its connection closed; the host
//!   may still finish it, and the target says so.
//! * Remote commands (BX-02): each host's secrets come from the vault just before it connects, and
//!   only the adapter gets them. A bulk run can't ask about an unknown host key, so it fails that host
//!   unless the run says to trust new keys; a changed key always blocks (SS-05). Each host has the
//!   run's time limit. Output, exit code, duration and the output's hashes are journaled per host;
//!   the adapter has already scrubbed the run's secrets from the output (BX-07).
//! * Safety snapshot before each VM's action when the approval asked for one (VM-05). One name per
//!   job, so a single bulk revert undoes it; a VM whose safety snapshot fails is left untouched.
//! * SS-10 MultiExec lines: the line's keys are already in each terminal; the job sends the Enter the
//!   policy engine held back ([`TerminalActions`]), to terminals that are still connected.
//! * SS-08 uploads: through the one open terminal, over its SFTP channel ([`TerminalActions::upload`]);
//!   each file is audited as it lands, and the end of the job says what landed and what did not.
//! * CT-01, CT-02 container changes: through the containers service ([`ContainerActions`]), one target
//!   (container, image, volume or a host's engine) at a time per slot. The CLI's output is kept with the
//!   job; the audit entry at the end says only what each target did ("reclaimed 1.2GB").
//! * H9 blast radius of bulk runs ([`Rollout`]): with a canary the first host runs alone and the job
//!   waits ([`JobEvent::CanaryWaiting`], up to [`CANARY_WAIT`]) for the user to say go on
//!   ([`JobRunner::go_on`]); a canary that fails, or no answer, stops the run and the rest are skipped.
//!   A stop after N failures starts no more hosts once N failed or ended with their outcome unknown;
//!   hosts already running finish. A host that timed out or was cancelled while its command (or a
//!   vmrun/VBoxManage power call, or a container change) ran ends as [`TargetStatus::Unknown`]: it
//!   may have run, so "retry failed" leaves it out unless asked.
//! * Each remote target's journal row and the job's end in the audit log name the address this PC
//!   reached and the host key the run accepted.
//! * Every job and target is journaled in the store, and the audit log gets an entry when the job
//!   starts and when it ends (NFR Audit, NFR Reliability).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{broadcast, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::exec_output::{CollectedOutput, OutputCollector, MAX_OUTPUT_PER_STREAM};
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, ExecRequest, HostKeyVerifier, RemoteAdapter, SessionSpec,
};
use crate::adapters::updater::UpdaterAdapter;
use crate::adapters::vmware::{path_key, ToolsState};
use crate::command_bus::{ApprovalRecord, Command, PowerOp, Rollout, SnapshotOp, StopMode};
use crate::containers::ContainerActions;
use crate::domain::{Context, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::{HostKey, HostKeyCheck, KnownHosts};
use crate::linked_clones::{LinkedClones, VboxMedia};
use crate::locks;
use crate::policy::{safety_snapshot_applies, ApprovalStep, Decision, Tier};
use crate::snapshots::safety_snapshot_name;
use crate::ssh_keys;
use crate::store::{NewAuditEntry, NewJob, Store, TargetResult};
use crate::terminal::files::UploadRun;
use crate::terminal::tunnels::TunnelRun;
use crate::terminal::TerminalActions;
use crate::vault::{SecretId, SecretString, Vault};
use crate::vm_settings::VmEditor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Countdown,
    Running,
    Succeeded,
    Failed,
    PartiallyFailed,
    Cancelled,
    /// The app stopped while the job was open (set at the next start).
    Interrupted,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            JobStatus::Queued => "queued",
            JobStatus::Countdown => "countdown",
            JobStatus::Running => "running",
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed => "failed",
            JobStatus::PartiallyFailed => "partially_failed",
            JobStatus::Cancelled => "cancelled",
            JobStatus::Interrupted => "interrupted",
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, JobStatus::Queued | JobStatus::Countdown | JobStatus::Running)
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            JobStatus::Queued,
            JobStatus::Countdown,
            JobStatus::Running,
            JobStatus::Succeeded,
            JobStatus::Failed,
            JobStatus::PartiallyFailed,
            JobStatus::Cancelled,
            JobStatus::Interrupted,
        ]
        .into_iter()
        .find(|status| status.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
    /// H9: timed out, or cancelled while its command ran: it may have run, and may still finish.
    Unknown,
}

impl TargetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetStatus::Pending => "pending",
            TargetStatus::Running => "running",
            TargetStatus::Succeeded => "succeeded",
            TargetStatus::Failed => "failed",
            TargetStatus::Skipped => "skipped",
            TargetStatus::Cancelled => "cancelled",
            TargetStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct JobLimits {
    /// VM-06: parallel power-ons, to avoid host disk and CPU spikes.
    pub power_on: usize,
    /// Other VM operations (stop, suspend, snapshots).
    pub vm_ops: usize,
    /// BX-02: hosts at a time for remote commands.
    pub remote: usize,
    /// VM-03: how long a soft stop may take before the VM counts as still running.
    pub shutdown_wait: Duration,
}

impl JobLimits {
    /// VM-06: the most power-ons the setting allows at once.
    pub const MAX_POWER_ON: usize = 32;
    /// BX-02: the most hosts the setting lets a bulk run reach at once (NFR Scale: 10 to 50).
    pub const MAX_REMOTE: usize = 50;
    /// VM-03: the longest shutdown wait the setting allows, in seconds.
    pub const MAX_SHUTDOWN_WAIT_SECS: u64 = 3600;
}

impl Default for JobLimits {
    fn default() -> Self {
        Self {
            power_on: 3,
            vm_ops: 4,
            remote: 10,
            shutdown_wait: Duration::from_secs(120),
        }
    }
}

/// A command the bus has cleared to run.
pub struct JobSpec {
    pub ctx: Context,
    pub command: Command,
    pub decision: Decision,
    pub approval: Option<ApprovalRecord>,
    pub safety_snapshot: bool,
    /// BX-04: the job whose failed targets this one retries.
    pub retry_of: Option<Uuid>,
}

/// How bulk runs connect (BX-02). The defaults suit real networks; tests shorten them.
#[derive(Debug, Clone)]
pub struct ExecTuning {
    pub connect_timeout: Duration,
    pub agent: AgentSource,
    /// Bytes kept per stream and host.
    pub max_output: usize,
}

impl Default for ExecTuning {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            agent: AgentSource::System,
            max_output: MAX_OUTPUT_PER_STREAM,
        }
    }
}

/// Progress events, forwarded to the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum JobEvent {
    Queued {
        job_id: Uuid,
        summary: String,
        tier: Tier,
        targets: usize,
        /// SS-10: a MultiExec line, whose terminals show what happened: the UI shows no toasts for it.
        quiet: bool,
    },
    /// AP-03: the job waits until `until` (RFC 3339) and can be cancelled until then.
    Countdown {
        job_id: Uuid,
        seconds: u32,
        until: String,
    },
    Started {
        job_id: Uuid,
    },
    /// BX-02: work on this target began (after the parallel limit let it).
    TargetStarted {
        job_id: Uuid,
        target: String,
        name: String,
    },
    TargetFinished {
        job_id: Uuid,
        target: String,
        name: String,
        status: TargetStatus,
        message: Option<String>,
        /// BX-02: a remote command's exit code.
        exit_code: Option<i64>,
        duration_ms: u64,
        /// VM-05: the safety snapshot taken on this target first, if one was.
        safety_snapshot: Option<String>,
        /// What the job says about this target when it ends well (VM-21: where the new VM is, its IP, what the
        /// after-deploy steps did).
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// H9: the canary host finished well and the others wait until `until` (RFC 3339) for the user to
    /// say go on ([`JobRunner::go_on`]) or cancel the job.
    CanaryWaiting {
        job_id: Uuid,
        target: String,
        name: String,
        /// How many hosts wait.
        rest: usize,
        until: String,
    },
    /// VM-03: these VMs did not shut down. Sent before `Finished`, so the UI can offer to force
    /// them off (a separate, Critical command).
    StillRunning {
        job_id: Uuid,
        targets: Vec<Target>,
    },
    Finished {
        job_id: Uuid,
        status: JobStatus,
        /// VM-01: what the job may have changed, so the UI reads again only what that touches.
        scope: JobScope,
    },
}

/// VM-01: what a job may have changed. The VM page refreshes the inventory after a `Vms` job and the
/// Containers page reads its hosts again after a `Containers` one; nothing is read again after the
/// rest (remote commands, uploads, tunnels, MultiExec lines, updates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JobScope {
    Vms,
    Containers,
    Other,
}

impl JobScope {
    pub fn of(command: &Command) -> Self {
        match command {
            Command::VmPower { .. }
            | Command::VmSnapshot { .. }
            | Command::VmProtect { .. }
            | Command::VmConfig { .. }
            | Command::VmDevice { .. }
            | Command::VmDisk { .. }
            | Command::VmLifecycle { .. } => JobScope::Vms,
            // VM-21: the new VMs show in the list.
            Command::Deploy { .. } => JobScope::Vms,
            Command::Container { .. } => JobScope::Containers,
            _ => JobScope::Other,
        }
    }
}

struct TargetOutcome {
    ok: bool,
    exit_code: Option<i64>,
    output: Option<CollectedOutput>,
    /// Why it counts as failed although it ran, e.g. "exit code 2".
    failure: Option<String>,
    /// What the end of the job's audit entry says about this target (SS-08: the files uploaded).
    note: Option<String>,
    /// The address this PC reached (a remote target reached directly).
    peer_ip: Option<String>,
}

impl TargetOutcome {
    fn done() -> Self {
        Self {
            ok: true,
            exit_code: None,
            output: None,
            failure: None,
            note: None,
            peer_ip: None,
        }
    }
}

/// H9: how long the rest of a run waits for the go-ahead after its canary host.
pub const CANARY_WAIT: Duration = Duration::from_secs(15 * 60);

/// H9: a job that waits for the go-ahead after its canary host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryWait {
    /// The canary host's name.
    pub name: String,
    /// How many hosts wait.
    pub rest: usize,
    /// Until when they wait (RFC 3339).
    pub until: String,
}

/// Why a target did not run to an outcome of its own.
enum Stop {
    /// The job was cancelled before the target started.
    Cancelled,
    /// H9: the run stopped starting hosts (after its failures, or its canary).
    Halted,
    Error(CoreError),
}

/// What one target's task hands back.
struct Ran {
    target: Target,
    outcome: std::result::Result<TargetOutcome, Stop>,
    duration_ms: u64,
    safety_snapshot: Option<String>,
    note: Option<String>,
    /// The host key its host presented and the run accepted.
    host_key: Option<String>,
    /// The target's parallel slot, given back only once its result is journaled, so the next target
    /// starts after the run's stop after failures has seen this one (H9).
    permit: Option<OwnedSemaphorePermit>,
}

/// What a job's targets came to, for its end.
#[derive(Default)]
struct Tally {
    succeeded: usize,
    failed: usize,
    unknown: usize,
    cancelled: usize,
    skipped: usize,
    still_running: Vec<Target>,
    in_flight: Vec<Target>,
    safety_snapshots: usize,
    notes: Vec<String>,
    /// QL-15: target results the journal could not keep.
    unjournaled: usize,
    /// H9: why the run stopped starting hosts, once it did.
    halted: Option<String>,
    /// Remote targets: `name at 192.0.2.10, key ssh-ed25519 SHA256:...`.
    reached: Vec<String>,
}

/// What gets journaled for one finished target.
struct Finished {
    status: TargetStatus,
    exit_code: Option<i64>,
    output: Option<CollectedOutput>,
    error: Option<String>,
    error_code: Option<&'static str>,
}

impl Finished {
    fn failed(err: &CoreError) -> Self {
        Self::with(TargetStatus::Failed, Some(err))
    }

    fn cancelled(err: Option<&CoreError>) -> Self {
        Self::with(TargetStatus::Cancelled, err)
    }

    /// H9: it may have run.
    fn unknown(err: &CoreError) -> Self {
        Self::with(TargetStatus::Unknown, Some(err))
    }

    fn with(status: TargetStatus, err: Option<&CoreError>) -> Self {
        Self {
            status,
            exit_code: None,
            output: None,
            error: err.map(ToString::to_string),
            error_code: err.map(CoreError::code),
        }
    }

    /// H9: not started, and why.
    fn skipped(why: &str) -> Self {
        Self {
            status: TargetStatus::Skipped,
            exit_code: None,
            output: None,
            error: Some(why.to_owned()),
            error_code: None,
        }
    }
}

/// A script to run on a host, and how (BX-02, BX-07; SS-09 pushes a key this way).
struct RemoteRun<'a> {
    script: &'a str,
    sudo: bool,
    sudo_password_id: Option<SecretId>,
    trust_new_host_keys: bool,
    timeout_secs: Option<u64>,
}

/// SS-05 for bulk runs: a trusted key passes; a changed key blocks, and that is audited; a key never
/// seen before is trusted (and audited) only when the run says so, since nobody can be asked. A key of
/// a new type for a host that has a trusted key of another type blocks like a changed key, ticked or
/// not: a man in the middle can present any type, and the run would hand it the passwords.
struct BulkVerifier {
    known_hosts: Arc<KnownHosts>,
    ctx: Context,
    target: Target,
    trust_new: bool,
    /// The key the session's own host presented once it was accepted, for the journal.
    accepted: Mutex<Option<String>>,
}

impl BulkVerifier {
    fn accept(&self, key: &HostKey, jump: Option<&str>) {
        if jump.is_none() {
            *locks::lock(&self.accepted) = Some(format!("{} {}", key.key_type, key.fingerprint));
        }
    }
}

#[async_trait]
impl HostKeyVerifier for BulkVerifier {
    async fn verify(&self, key: &HostKey, jump: Option<&str>) -> Result<()> {
        let checked = self.check(key, jump).await;
        if checked.is_ok() {
            self.accept(key, jump);
        }
        checked
    }

    async fn known_key_types(&self, host: &str, port: u16) -> Vec<String> {
        self.known_hosts
            .key_types(&self.ctx, host, port)
            .await
            .unwrap_or_default()
    }
}

impl BulkVerifier {
    async fn check(&self, key: &HostKey, jump: Option<&str>) -> Result<()> {
        let jump = jump.map(str::to_owned);
        match self.known_hosts.check(&self.ctx, key).await? {
            HostKeyCheck::Trusted => Ok(()),
            HostKeyCheck::Changed { previous } => {
                self.known_hosts
                    .record_blocked(&self.ctx, key, &previous, Some(&self.target))
                    .await?;
                Err(CoreError::HostKeyChanged {
                    address: key.address(),
                    jump,
                })
            }
            HostKeyCheck::Unknown { other_key_types } if !other_key_types.is_empty() => {
                self.known_hosts
                    .record_new_type_blocked(&self.ctx, key, &other_key_types, Some(&self.target))
                    .await?;
                Err(CoreError::HostKeyChanged {
                    address: key.address(),
                    jump,
                })
            }
            HostKeyCheck::Unknown { .. } if self.trust_new => {
                self.known_hosts.trust(&self.ctx, key, Some(&self.target)).await
            }
            HostKeyCheck::Unknown { .. } => Err(CoreError::HostKeyUnknown {
                address: key.address(),
                jump,
            }),
        }
    }
}

/// What every target of one job shares while it runs.
struct TargetsRun<'a> {
    id: Uuid,
    spec: &'a Arc<JobSpec>,
    semaphore: &'a Arc<Semaphore>,
    token: &'a CancellationToken,
    halt: &'a CancellationToken,
    safety_name: &'a Option<Arc<str>>,
    rollout: Rollout,
}

pub struct JobRunner {
    store: Store,
    /// VM-18: VMware and VirtualBox, each VM reached by its key.
    hypervisors: Hypervisors,
    /// VM-11, VM-12, VM-15, VM-16, VM-23, VM-24: settings, devices, disks and lifecycle changes.
    vm_editor: VmEditor,
    /// VM-04, VM-21: a snapshot delete is checked again just before it runs, for linked clones made since the approval.
    linked_clones: LinkedClones,
    remote: Arc<dyn RemoteAdapter>,
    updater: Arc<dyn UpdaterAdapter>,
    /// BX-02, BX-07: login and sudo secrets, read per host just before it connects.
    vault: Arc<dyn Vault>,
    /// SS-05: the host keys bulk runs check against.
    known_hosts: Arc<KnownHosts>,
    /// SS-10, SS-08: the open terminals a MultiExec line's Enter and an upload go to.
    terminals: Arc<dyn TerminalActions>,
    /// CT-01, CT-02: container hosts (set once the core is put together).
    containers: RwLock<Option<Arc<dyn ContainerActions>>>,
    /// VM-21, VM-22, VM-10: what makes each new VM of a deploy (set once the core is put together).
    deployer: RwLock<Option<Arc<dyn crate::deploy::DeployActions>>>,
    exec_tuning: RwLock<ExecTuning>,
    /// Read when a job starts, so a changed setting applies to the next job.
    limits: RwLock<JobLimits>,
    events: broadcast::Sender<JobEvent>,
    /// Open jobs (queued, in countdown or running) and their cancel tokens.
    running: Mutex<HashMap<Uuid, CancellationToken>>,
    /// Signalled whenever a job closes, for jobs waiting to run alone (FD-14).
    idle: Notify,
    /// H9: jobs whose canary host finished, waiting for the go-ahead.
    waiting: Mutex<HashMap<Uuid, (tokio::sync::oneshot::Sender<Context>, CanaryWait)>>,
    /// BX-02: a job is enqueued under the read side; the journal's compaction (VACUUM) holds the write side, so no
    /// job starts while it runs ([`JobRunner::when_idle`]).
    maintenance: tokio::sync::RwLock<()>,
}

impl JobRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Store,
        hypervisors: Hypervisors,
        remote: Arc<dyn RemoteAdapter>,
        updater: Arc<dyn UpdaterAdapter>,
        vault: Arc<dyn Vault>,
        known_hosts: Arc<KnownHosts>,
        terminals: Arc<dyn TerminalActions>,
        limits: JobLimits,
    ) -> Arc<Self> {
        // Room for a 200-host bulk run's events (NFR Scale) without the UI lagging behind.
        let (events, _) = broadcast::channel(1024);
        Arc::new(Self {
            vm_editor: VmEditor::new(hypervisors.clone(), store.clone()),
            linked_clones: LinkedClones::new(hypervisors.clone()),
            store,
            hypervisors,
            remote,
            updater,
            vault,
            known_hosts,
            terminals,
            containers: RwLock::new(None),
            deployer: RwLock::new(None),
            exec_tuning: RwLock::new(ExecTuning::default()),
            limits: RwLock::new(limits),
            events,
            running: Mutex::new(HashMap::new()),
            idle: Notify::new(),
            waiting: Mutex::new(HashMap::new()),
            maintenance: tokio::sync::RwLock::new(()),
        })
    }

    pub fn limits(&self) -> JobLimits {
        *locks::read(&self.limits)
    }

    /// VM-06: how many VMs may power on at once, from the next job on. At least 1.
    pub fn set_power_on_limit(&self, limit: usize) {
        locks::write(&self.limits).power_on = limit.max(1);
    }

    /// VM-03: how long a soft stop may take, from the next stop on.
    pub fn set_shutdown_wait(&self, wait: Duration) {
        locks::write(&self.limits).shutdown_wait = wait;
    }

    /// BX-02: how many hosts a bulk run reaches at once, from the next job on. At least 1.
    pub fn set_remote_limit(&self, limit: usize) {
        locks::write(&self.limits).remote = limit.max(1);
    }

    /// CT-01, CT-02: where container changes go.
    pub fn set_containers(&self, containers: Arc<dyn ContainerActions>) {
        *locks::write(&self.containers) = Some(containers);
    }

    /// VM-21, VM-22, VM-10: what makes a deploy's VMs.
    pub fn set_deployer(&self, deployer: Arc<dyn crate::deploy::DeployActions>) {
        *locks::write(&self.deployer) = Some(deployer);
    }

    /// BX-02: connect timeout, agent and output cap of bulk runs (tests shorten them).
    pub fn set_exec_tuning(&self, tuning: ExecTuning) {
        *locks::write(&self.exec_tuning) = tuning;
    }

    /// Number of open jobs.
    pub fn open_jobs(&self) -> usize {
        locks::lock(&self.running).len()
    }

    /// BX-02: runs `work` while no job is open, and holds back new ones until it is done (a submit waits for it, so
    /// it never meets a database busy compacting). `None`, without running it, when a job is open.
    pub async fn when_idle<T>(&self, work: impl std::future::Future<Output = T>) -> Option<T> {
        let _quiet = self.maintenance.write().await;
        if self.open_jobs() > 0 {
            return None;
        }
        Some(work.await)
    }

    /// Waits until `job_id` is the only open job. Cancelling the job stops the wait.
    async fn wait_to_run_alone(&self, job_id: Uuid, token: &CancellationToken) -> Result<()> {
        loop {
            let others = locks::lock(&self.running).keys().filter(|id| **id != job_id).count();
            if others == 0 {
                return Ok(());
            }
            // The timeout covers a job that closes between the count and the wait.
            tokio::select! {
                _ = self.idle.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                _ = token.cancelled() => return Err(CoreError::Cancelled),
            }
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.events.subscribe()
    }

    /// Waits until the job has ended and returns how (SS-10: MultiExec waits for a line's Enter to be
    /// sent before the next keys go out). A job that ended already answers from the journal.
    pub async fn wait(&self, job_id: Uuid) -> Result<JobStatus> {
        let mut events = self.subscribe();
        if locks::lock(&self.running).contains_key(&job_id) {
            loop {
                match events.recv().await {
                    Ok(JobEvent::Finished { job_id: id, status, .. }) if id == job_id => return Ok(status),
                    Ok(_) => {}
                    // Missed events: the journal says how it ended once it has.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if !locks::lock(&self.running).contains_key(&job_id) {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        let status = self.store.job_status(job_id).await?;
        Ok(status.unwrap_or(JobStatus::Interrupted))
    }

    /// H9: the rest of a job whose canary host finished may start. Only the command bus calls this
    /// ([`crate::command_bus::CommandBus::go_on`]). False when the job is not waiting for it.
    pub(crate) fn go_on(&self, ctx: &Context, job_id: Uuid) -> bool {
        match locks::lock(&self.waiting).remove(&job_id) {
            Some((go, _)) => go.send(*ctx).is_ok(),
            None => false,
        }
    }

    /// H9: the jobs waiting for the go-ahead after their canary host.
    pub fn waiting_for_go_ahead(&self) -> Vec<Uuid> {
        locks::lock(&self.waiting).keys().copied().collect()
    }

    /// H9: what a job waits for after its canary host, while it does.
    pub fn canary_wait(&self, job_id: Uuid) -> Option<CanaryWait> {
        locks::lock(&self.waiting).get(&job_id).map(|(_, wait)| wait.clone())
    }

    /// Cancels a job in its countdown, or the targets of a running job that have not started yet.
    /// Returns false if the job is not open.
    pub fn cancel(&self, job_id: Uuid) -> bool {
        match locks::lock(&self.running).get(&job_id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    /// Only the command bus calls this, after policy and approval.
    pub(crate) async fn enqueue(self: &Arc<Self>, spec: JobSpec) -> Result<Uuid> {
        // Until the job is in `running`: compaction then waits for it to end.
        let _not_compacting = self.maintenance.read().await;
        let id = Uuid::new_v4();
        let summary = spec.command.summary(spec.decision.targets.len());
        let countdown = spec.decision.steps.iter().find_map(|s| match s {
            ApprovalStep::Countdown { seconds } if *seconds > 0 => Some(*seconds),
            _ => None,
        });
        let status = if countdown.is_some() {
            JobStatus::Countdown
        } else {
            JobStatus::Queued
        };
        let countdown_until = countdown.map(|seconds| {
            let until = time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds.into());
            until
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        });

        self.store
            .insert_job(
                &spec.ctx,
                NewJob {
                    id,
                    summary: &summary,
                    action: spec.decision.action,
                    tier: spec.decision.tier,
                    command: &spec.command,
                    approval: spec.approval.as_ref(),
                    targets: &spec.decision.targets,
                    status,
                    countdown_until: countdown_until.as_deref(),
                    retry_of: spec.retry_of,
                },
            )
            .await?;

        let token = CancellationToken::new();
        locks::lock(&self.running).insert(id, token.clone());
        self.emit(JobEvent::Queued {
            job_id: id,
            summary: summary.clone(),
            tier: spec.decision.tier,
            targets: spec.decision.targets.len(),
            quiet: matches!(spec.command, Command::TerminalLine { .. }),
        });

        let this = Arc::clone(self);
        let spec = Arc::new(spec);
        tokio::spawn(async move {
            let countdown = countdown.zip(countdown_until);
            let ran = Arc::clone(&this)
                .run(id, Arc::clone(&spec), summary.clone(), countdown, token)
                .await;
            if let Err(err) = ran {
                // QL-15: only a job that could not start ends here (its journal or start audit failed),
                // so no target was touched. Each write is tried; one failing does not stop the next.
                tracing::error!(%id, error = %err, "job failed to run");
                if let Err(journal) = this.store.set_job_status(id, JobStatus::Failed).await {
                    tracing::error!(%id, error = %journal, "could not journal a job that failed to run");
                }
                let detail = format!("the job did not run, so no target was touched: {err}");
                let result = Some(JobStatus::Failed.as_str());
                if let Err(audit) = this
                    .audit(&spec.ctx, "job_finished", &summary, &spec, id, result, Some(&detail))
                    .await
                {
                    tracing::error!(%id, error = %audit, "could not audit a job that failed to run");
                }
                this.emit(JobEvent::Finished {
                    job_id: id,
                    status: JobStatus::Failed,
                    scope: JobScope::of(&spec.command),
                });
            }
            locks::lock(&this.running).remove(&id);
            this.idle.notify_waiters();
        });
        Ok(id)
    }

    /// Runs the job. An error means it never started (no target touched); once targets run, a failing journal or
    /// audit write is logged and the job goes on, so it always ends with its real result (QL-15).
    async fn run(
        self: Arc<Self>,
        id: Uuid,
        spec: Arc<JobSpec>,
        summary: String,
        countdown: Option<(u32, String)>,
        token: CancellationToken,
    ) -> Result<()> {
        let ctx = spec.ctx;

        if let Some((seconds, until)) = countdown {
            self.emit(JobEvent::Countdown {
                job_id: id,
                seconds,
                until,
            });
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(seconds.into())) => {}
                _ = token.cancelled() => {
                    if let Err(err) = self.store.set_job_status(id, JobStatus::Cancelled).await {
                        tracing::error!(%id, error = %err, "could not journal a job cancelled in its countdown");
                    }
                    if let Err(err) = self.audit(&ctx, "job_cancelled", &summary, &spec, id, Some("cancelled"),
                        Some("cancelled during the countdown; no target was touched")).await {
                        tracing::error!(%id, error = %err, "could not audit a job cancelled in its countdown");
                    }
                    self.emit(JobEvent::Finished {
                        job_id: id,
                        status: JobStatus::Cancelled,
                        scope: JobScope::of(&spec.command),
                    });
                    return Ok(());
                }
            }
        }

        self.store.set_job_status(id, JobStatus::Running).await?;
        // H9: how the run spreads is in the record from the start.
        let rollout = match &spec.command {
            Command::RemoteExec { rollout, .. } => rollout.describe(),
            _ => None,
        };
        let started: Vec<String> = spec
            .retry_of
            .map(|of| format!("retries the failed targets of job {of}"))
            .into_iter()
            .chain(rollout)
            .collect();
        let started = (!started.is_empty()).then(|| started.join("; "));
        self.audit(&ctx, "job_started", &summary, &spec, id, None, started.as_deref())
            .await?;
        self.emit(JobEvent::Started { job_id: id });

        let semaphore = Arc::new(Semaphore::new(self.parallelism(&spec.command)));
        // VM-05: named once, when the job starts, so every VM's safety snapshot has the same name.
        let safety_name: Option<Arc<str>> = (spec.safety_snapshot && safety_snapshot_applies(&spec.command))
            .then(|| safety_snapshot_name(safety_verb(&spec.command), time::OffsetDateTime::now_utc(), id).into());
        let rollout = match &spec.command {
            Command::RemoteExec { rollout, .. } => *rollout,
            _ => Rollout::default(),
        };
        // H9: no more targets start once this is cancelled; those running finish.
        let halt = CancellationToken::new();
        let mut tally = Tally::default();
        let mut targets = spec.decision.targets.clone();
        let rest = if rollout.canary && targets.len() > 1 {
            targets.split_off(1)
        } else {
            Vec::new()
        };
        let run = TargetsRun {
            id,
            spec: &spec,
            semaphore: &semaphore,
            token: &token,
            halt: &halt,
            safety_name: &safety_name,
            rollout,
        };
        Arc::clone(&self).run_targets(&run, targets, &mut tally).await;
        if !rest.is_empty() {
            let go = self.canary_answer(&run, &tally, rest.len()).await;
            match go {
                Ok(()) => Arc::clone(&self).run_targets(&run, rest, &mut tally).await,
                Err(why) => {
                    tally.halted.get_or_insert(why);
                    halt.cancel();
                    Arc::clone(&self).run_targets(&run, rest, &mut tally).await;
                }
            }
        }

        let Tally {
            succeeded,
            failed,
            unknown,
            cancelled,
            skipped,
            still_running,
            in_flight,
            safety_snapshots,
            notes,
            unjournaled,
            halted,
            reached,
        } = tally;
        let status = if token.is_cancelled() {
            JobStatus::Cancelled
        } else if failed == 0 && unknown == 0 && skipped == 0 {
            JobStatus::Succeeded
        } else if succeeded == 0 {
            JobStatus::Failed
        } else {
            JobStatus::PartiallyFailed
        };
        if let Err(err) = self.store.set_job_status(id, status).await {
            tracing::error!(%id, error = %err, "could not journal how a job ended");
        }
        let mut detail = format!("{succeeded} succeeded, {failed} failed, {cancelled} cancelled");
        if unknown > 0 {
            detail.push_str(&format!(
                "; {unknown} with the outcome unknown (timed out or cancelled while running: the command may have run there)"
            ));
        }
        if skipped > 0 {
            detail.push_str(&format!("; {skipped} not started"));
        }
        if let Some(why) = &halted {
            detail.push_str(&format!("; {why}"));
        }
        if unjournaled > 0 {
            detail.push_str(&format!(
                "; the job journal could not keep the result of {unjournaled} target(s)"
            ));
        }
        if let (Some(name), true) = (&safety_name, safety_snapshots > 0) {
            detail.push_str(&format!("; safety snapshot '{name}' taken on {safety_snapshots} VM(s)"));
        }
        for note in &notes {
            detail.push_str(&format!("; {note}"));
        }
        if !in_flight.is_empty() {
            let virtualbox = in_flight.iter().any(|t| {
                matches!(&t.target, TargetRef::Vm { vmx_path } if Hypervisor::of_key(vmx_path) == Hypervisor::VirtualBox)
            });
            let vmware = in_flight.iter().any(|t| {
                matches!(&t.target, TargetRef::Vm { vmx_path } if Hypervisor::of_key(vmx_path) == Hypervisor::Vmware)
            });
            let what = if matches!(
                spec.command,
                Command::RemoteExec { .. }
                    | Command::PushSshKey { .. }
                    | Command::RemoveSshKey { .. }
                    | Command::Container { .. }
            ) {
                "cancelled while the command was running, so the host may still finish it"
            } else if virtualbox && vmware {
                "cancelled while vmrun or VBoxManage was running, so Workstation or VirtualBox may still finish it"
            } else if virtualbox {
                "cancelled while VBoxManage was running, so VirtualBox may still finish it"
            } else {
                "cancelled while vmrun was running, so Workstation may still finish it"
            };
            let names: Vec<&str> = in_flight.iter().map(|t| t.name.as_str()).collect();
            detail.push_str(&format!("; {what}: {}", names.join(", ")));
        }
        if !reached.is_empty() {
            detail.push_str(&format!("; reached {}", reached.join("; ")));
        }
        if !still_running.is_empty() {
            let names: Vec<&str> = still_running.iter().map(|t: &Target| t.name.as_str()).collect();
            detail.push_str(&format!(
                "; still running after the soft stop: {}; forcing them off needs its own approval",
                names.join(", ")
            ));
            self.emit(JobEvent::StillRunning {
                job_id: id,
                targets: still_running,
            });
        }
        // Best effort: a failing audit write must not turn the job's real result into a failure.
        if let Err(err) = self
            .audit(
                &ctx,
                "job_finished",
                &summary,
                &spec,
                id,
                Some(status.as_str()),
                Some(&detail),
            )
            .await
        {
            tracing::error!(%id, error = %err, "could not audit a job's end");
        }
        self.emit(JobEvent::Finished {
            job_id: id,
            status,
            scope: JobScope::of(&spec.command),
        });
        Ok(())
    }

    /// Runs `targets` with the job's parallel limit and journals each as it ends, into `tally`. H9:
    /// once the stop after failures is reached, the targets not started yet are skipped.
    async fn run_targets(self: Arc<Self>, run: &TargetsRun<'_>, targets: Vec<Target>, tally: &mut Tally) {
        let id = run.id;
        let mut tasks = JoinSet::new();
        for target in targets {
            let this = Arc::clone(&self);
            let spec = Arc::clone(run.spec);
            let semaphore = Arc::clone(run.semaphore);
            let token = run.token.clone();
            let halt = run.halt.clone();
            let safety_name = run.safety_name.clone();
            tasks.spawn(async move {
                this.run_target(id, spec, target, semaphore, token, halt, safety_name)
                    .await
            });
        }
        while let Some(joined) = tasks.join_next().await {
            let ran = match joined {
                Ok(ran) => ran,
                Err(err) => {
                    tracing::error!(%id, error = %err, "target task panicked");
                    tally.failed += 1;
                    continue;
                }
            };
            self.record(run, ran, tally).await;
        }
    }

    /// One target, once the parallel limit lets it.
    #[allow(clippy::too_many_arguments)]
    async fn run_target(
        self: Arc<Self>,
        id: Uuid,
        spec: Arc<JobSpec>,
        target: Target,
        semaphore: Arc<Semaphore>,
        token: CancellationToken,
        halt: CancellationToken,
        safety_name: Option<Arc<str>>,
    ) -> Ran {
        let stopped = |target: Target, stop: Stop| Ran {
            target,
            outcome: Err(stop),
            duration_ms: 0,
            safety_snapshot: None,
            note: None,
            host_key: None,
            permit: None,
        };
        let permit = tokio::select! {
            permit = semaphore.acquire_owned() => permit.ok(),
            _ = token.cancelled() => None,
            _ = halt.cancelled() => None,
        };
        if permit.is_none() || token.is_cancelled() {
            let stop = if token.is_cancelled() {
                Stop::Cancelled
            } else {
                Stop::Halted
            };
            return stopped(target, stop);
        }
        if halt.is_cancelled() {
            return stopped(target, Stop::Halted);
        }
        let key = target.target.key();
        if let Err(err) = self.store.set_target_running(id, &key).await {
            tracing::warn!(%id, error = %err, "could not journal target start");
        }
        self.emit(JobEvent::TargetStarted {
            job_id: id,
            target: key,
            name: target.name.clone(),
        });
        let started = Instant::now();
        let mut safety_taken = None;
        if let (Some(name), TargetRef::Vm { vmx_path }) = (&safety_name, &target.target) {
            if let Err(err) = self.take_safety_snapshot(vmx_path, name).await {
                return Ran {
                    target,
                    outcome: Err(Stop::Error(err)),
                    duration_ms: started.elapsed().as_millis() as u64,
                    safety_snapshot: None,
                    note: None,
                    host_key: None,
                    permit,
                };
            }
            safety_taken = Some(name.to_string());
        }
        let accepted = Arc::new(Mutex::new(None));
        let mut outcome = self.execute(id, &spec, &target, &token, &accepted).await;
        let note = outcome.as_mut().ok().and_then(|o| o.note.take());
        let host_key = locks::lock(&accepted).take();
        Ran {
            target,
            outcome: outcome.map_err(Stop::Error),
            duration_ms: started.elapsed().as_millis() as u64,
            safety_snapshot: safety_taken,
            note,
            host_key,
            permit,
        }
    }

    /// Journals one finished target, tells the UI, and counts it.
    async fn record(&self, run: &TargetsRun<'_>, ran: Ran, tally: &mut Tally) {
        let id = run.id;
        let Ran {
            target,
            outcome,
            duration_ms,
            safety_snapshot,
            note,
            host_key,
            permit,
        } = ran;
        // Given back at the end, once this target counts.
        let _slot = permit;
        let mut peer_ip = None;
        let done = match outcome {
            Ok(o) => {
                peer_ip = o.peer_ip;
                Finished {
                    status: if o.ok {
                        TargetStatus::Succeeded
                    } else {
                        TargetStatus::Failed
                    },
                    exit_code: o.exit_code,
                    output: o.output,
                    error: if o.ok {
                        None
                    } else {
                        Some(o.failure.unwrap_or_else(|| "non-zero exit code".to_owned()))
                    },
                    error_code: None,
                }
            }
            Err(Stop::Cancelled | Stop::Error(CoreError::Cancelled)) => Finished::cancelled(None),
            Err(Stop::Halted) => Finished::skipped(
                tally
                    .halted
                    .as_deref()
                    .unwrap_or("not started: the run stopped before this host"),
            ),
            Err(Stop::Error(
                err @ (CoreError::CancelledInFlight | CoreError::VboxCancelledInFlight | CoreError::CancelledRemote),
            )) => {
                tally.in_flight.push(target.clone());
                Finished::unknown(&err)
            }
            Err(Stop::Error(err @ CoreError::CommandTimedOut { .. })) => Finished::unknown(&err),
            Err(Stop::Error(err @ CoreError::StillRunning { .. })) => {
                tally.still_running.push(target.clone());
                Finished::failed(&err)
            }
            Err(Stop::Error(err)) => Finished::failed(&err),
        };
        let event_note = note.clone();
        if let Some(note) = note {
            tally.notes.push(note);
        }
        match done.status {
            TargetStatus::Succeeded => tally.succeeded += 1,
            TargetStatus::Cancelled => tally.cancelled += 1,
            TargetStatus::Unknown => tally.unknown += 1,
            TargetStatus::Skipped => tally.skipped += 1,
            _ => tally.failed += 1,
        }
        if peer_ip.is_some() || host_key.is_some() {
            let at = peer_ip.as_deref().map(|ip| format!(" at {ip}")).unwrap_or_default();
            let key = host_key.as_deref().map(|k| format!(", key {k}")).unwrap_or_default();
            tally.reached.push(format!("'{}'{at}{key}", target.name));
        }
        let key = target.target.key();
        let out = done.output.as_ref();
        let journaled = self
            .store
            .set_target_result(
                id,
                &key,
                TargetResult {
                    status: Some(done.status),
                    exit_code: done.exit_code,
                    output: out.map(|o| o.stdout.as_str()),
                    stderr: out.map(|o| o.stderr.as_str()),
                    stdout_bytes: out.and_then(|o| i64::try_from(o.stdout_bytes).ok()),
                    stderr_bytes: out.and_then(|o| i64::try_from(o.stderr_bytes).ok()),
                    truncated: out.is_some_and(|o| o.truncated),
                    output_hash: out.map(|o| o.hash.as_str()),
                    output_hash_loose: out.map(|o| o.hash_loose.as_str()),
                    error: done.error.as_deref(),
                    error_code: done.error_code,
                    duration_ms: i64::try_from(duration_ms).ok(),
                    safety_snapshot: safety_snapshot.as_deref(),
                    peer_ip: peer_ip.as_deref(),
                    host_key: host_key.as_deref(),
                },
            )
            .await;
        if let Err(err) = journaled {
            // Returning here would drop the JoinSet and abort every target still running.
            tracing::error!(%id, error = %err, "could not journal a target's result");
            tally.unjournaled += 1;
        }
        tally.safety_snapshots += usize::from(safety_snapshot.is_some());
        self.emit(JobEvent::TargetFinished {
            job_id: id,
            target: key,
            name: target.name.clone(),
            status: done.status,
            message: done.error,
            exit_code: done.exit_code,
            duration_ms,
            safety_snapshot,
            note: event_note,
        });
        // H9: decided before this target's slot is given back, so no other target starts in between.
        if let Some(n) = run.rollout.stop_after_failures.map(|n| n as usize) {
            if tally.failed + tally.unknown >= n && !run.halt.is_cancelled() {
                tally.halted = Some(match n {
                    1 => "the run stopped after its first failure, so the hosts not started yet did not run".to_owned(),
                    n => format!("the run stopped after {n} failures, so the hosts not started yet did not run"),
                });
                run.halt.cancel();
            }
        }
    }

    /// H9: after the canary host: `Ok` once the user says go on; `Err` with why the rest won't run
    /// (the canary did not succeed, the job was cancelled, or nobody answered within [`CANARY_WAIT`]).
    async fn canary_answer(&self, run: &TargetsRun<'_>, tally: &Tally, rest: usize) -> std::result::Result<(), String> {
        let id = run.id;
        if run.token.is_cancelled() {
            return Err("the job was cancelled after its canary host".into());
        }
        if tally.succeeded == 0 {
            return Err("the canary host did not succeed, so the other hosts did not run".into());
        }
        let (go, answer) = tokio::sync::oneshot::channel();
        let until = time::OffsetDateTime::now_utc() + time::Duration::seconds(CANARY_WAIT.as_secs() as i64);
        let until = until
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let canary = run.spec.decision.targets.first();
        let name = canary.map(|t| t.name.clone()).unwrap_or_default();
        let wait = CanaryWait {
            name: name.clone(),
            rest,
            until: until.clone(),
        };
        locks::lock(&self.waiting).insert(id, (go, wait));
        self.emit(JobEvent::CanaryWaiting {
            job_id: id,
            target: canary.map(|t| t.target.key()).unwrap_or_default(),
            name,
            rest,
            until,
        });
        let answered = tokio::select! {
            ctx = answer => ctx.ok(),
            () = run.token.cancelled() => None,
            () = tokio::time::sleep(CANARY_WAIT) => None,
        };
        locks::lock(&self.waiting).remove(&id);
        let summary = run.spec.command.summary(run.spec.decision.targets.len());
        match answered {
            Some(ctx) => {
                let detail = format!(
                    "the canary host '{}' succeeded; the user said to run on the other {rest}",
                    canary.map_or("", |t| t.name.as_str())
                );
                if let Err(err) = self
                    .audit(&ctx, "canary_go_on", &summary, run.spec, id, None, Some(&detail))
                    .await
                {
                    tracing::error!(%id, error = %err, "could not audit a canary's go-ahead");
                }
                Ok(())
            }
            None if run.token.is_cancelled() => Err("the job was cancelled after its canary host".into()),
            None => Err(format!(
                "nobody said to go on within {} minutes of the canary host, so the other hosts did not run",
                CANARY_WAIT.as_secs() / 60
            )),
        }
    }

    async fn execute(
        &self,
        job_id: Uuid,
        spec: &JobSpec,
        target: &Target,
        token: &CancellationToken,
        accepted: &Arc<Mutex<Option<String>>>,
    ) -> Result<TargetOutcome> {
        match (&spec.command, &target.target) {
            (Command::VmPower { op, .. }, TargetRef::Vm { vmx_path }) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let in_flight = match Hypervisor::of_key(vmx_path) {
                    Hypervisor::Vmware => CoreError::CancelledInFlight,
                    Hypervisor::VirtualBox => CoreError::VboxCancelledInFlight,
                };
                // BX-04: cancel stops waiting. Dropping the call kills vmrun or VBoxManage (kill_on_drop).
                tokio::select! {
                    biased;
                    result = self.power(vmx_path, *op) => result?,
                    _ = token.cancelled() => return Err(in_flight),
                }
                // The VM list shows the new state before the next refresh asks vmrun.
                self.store
                    .set_vm_power_state(&spec.ctx, vmx_path, state_after(*op))
                    .await?;
                Ok(TargetOutcome::done())
            }
            (Command::VmSnapshot { op, .. }, TargetRef::Vm { vmx_path }) => {
                // VM-04, VM-21: a linked clone made from the snapshot since the approval (a deploy) counts too.
                let mut media = VboxMedia::default();
                if let Some(reason) = self.linked_clones.refusal(&spec.command, vmx_path, &mut media).await {
                    return Err(CoreError::LinkedClones(reason));
                }
                self.hypervisors.snapshot(vmx_path, op).await?;
                Ok(TargetOutcome::done())
            }
            (Command::VmProtect { protected, .. }, TargetRef::Vm { vmx_path }) => {
                // AP-04: the app's own flag; the VM itself is not touched.
                if !self.store.set_vm_protected(&spec.ctx, vmx_path, *protected).await? {
                    return Err(CoreError::UnknownTarget(vmx_path.clone()));
                }
                Ok(TargetOutcome::done())
            }
            // VM-23 and on. Once a VM's change has started it runs to its end: stopping vdiskmanager or
            // VBoxManage halfway through a disk, or between a .vmx's backup and its write, could leave the VM
            // broken. Cancel still stops the VMs not started yet.
            (
                Command::VmConfig { .. }
                | Command::VmDevice { .. }
                | Command::VmDisk { .. }
                | Command::VmLifecycle { .. },
                TargetRef::Vm { .. },
            ) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let note = self.vm_editor.run(&spec.ctx, job_id, &spec.command, target).await?;
                Ok(TargetOutcome {
                    note: Some(note),
                    ..TargetOutcome::done()
                })
            }
            (
                Command::RemoteExec {
                    script,
                    sudo,
                    sudo_password_id,
                    trust_new_host_keys,
                    timeout_secs,
                    ..
                },
                TargetRef::Session { session_id },
            ) => {
                let run = RemoteRun {
                    script,
                    sudo: *sudo,
                    sudo_password_id: *sudo_password_id,
                    trust_new_host_keys: *trust_new_host_keys,
                    timeout_secs: *timeout_secs,
                };
                self.run_remote(spec, target, *session_id, run, token, accepted).await
            }
            (
                Command::RemoveSshKey {
                    public_key,
                    trust_new_host_keys,
                    timeout_secs,
                    ..
                },
                TargetRef::Session { session_id },
            ) => {
                // SS-09: only the key's checked data is looked for on the host.
                let key = ssh_keys::parse_public_key(public_key)?;
                let script = ssh_keys::remove_key_script(&key);
                let run = RemoteRun {
                    script: &script,
                    sudo: false,
                    sudo_password_id: None,
                    trust_new_host_keys: *trust_new_host_keys,
                    timeout_secs: *timeout_secs,
                };
                self.run_remote(spec, target, *session_id, run, token, accepted).await
            }
            (
                Command::PushSshKey {
                    public_key,
                    trust_new_host_keys,
                    timeout_secs,
                    options,
                    ..
                },
                TargetRef::Session { session_id },
            ) => {
                // SS-09: checked again here, so only Remotely's own form of the key reaches a host.
                let key = ssh_keys::parse_public_key(public_key)?;
                options.validate(time::OffsetDateTime::now_utc().date())?;
                let script = ssh_keys::authorized_keys_script(&key, options);
                let run = RemoteRun {
                    script: &script,
                    sudo: false,
                    sudo_password_id: None,
                    trust_new_host_keys: *trust_new_host_keys,
                    timeout_secs: *timeout_secs,
                };
                self.run_remote(spec, target, *session_id, run, token, accepted).await
            }
            (Command::AppUpdate { version }, TargetRef::App) => {
                // FD-14: never update under a running job.
                self.wait_to_run_alone(job_id, token).await?;
                // The public releases need no token; the GitHub update token goes along when the vault can give it.
                let stored = crate::updates::stored_token(&self.store, self.vault.as_ref(), &spec.ctx).await?;
                // Cancel stops the download (dropping it ends the request). The installer only starts after the
                // job has ended, so nothing is half installed.
                tokio::select! {
                    biased;
                    _ = token.cancelled() => return Err(CoreError::Cancelled),
                    installed = self.updater.install(stored.usable(), version) => installed.map_err(|err| stored.explain(err))?,
                }
                Ok(TargetOutcome::done())
            }
            (
                Command::TerminalLine {
                    line, keys, unreliable, ..
                },
                TargetRef::Terminal { terminal_id, .. },
            ) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                // SS-10: the held key that runs the line (and the rest of a paste of several lines), only
                // as the bus checked them against the rated line.
                crate::terminal::multiexec::check_keys(line, keys.as_bytes(), *unreliable)
                    .map_err(CoreError::InvalidInput)?;
                self.terminals.send(*terminal_id, keys.as_bytes()).await?;
                Ok(TargetOutcome::done())
            }
            (Command::FileUpload { folder, files, .. }, TargetRef::Terminal { terminal_id, .. }) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let run = UploadRun {
                    ctx: spec.ctx,
                    job_id,
                    tier: spec.decision.tier,
                    target,
                    terminal_id: *terminal_id,
                    folder,
                    files,
                };
                let report = self.terminals.upload(run, token).await?;
                Ok(TargetOutcome {
                    ok: report.failed.is_empty(),
                    exit_code: None,
                    output: None,
                    failure: report.failure(),
                    note: Some(report.summary(folder)),
                    peer_ip: None,
                })
            }
            (Command::OpenTunnel { forward, .. }, TargetRef::Terminal { terminal_id, .. }) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                // SS-07: on the terminal's own connection; it stays open after the job.
                let run = TunnelRun {
                    ctx: spec.ctx,
                    job_id,
                    tier: spec.decision.tier,
                    terminal_id: *terminal_id,
                    forward,
                };
                let at = self.terminals.open_tunnel(run).await?;
                Ok(TargetOutcome {
                    note: Some(format!("listening on {at}")),
                    ..TargetOutcome::done()
                })
            }
            (Command::Container { op, .. }, container @ TargetRef::Container { .. }) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let containers = locks::read(&self.containers)
                    .clone()
                    .ok_or_else(|| CoreError::NotImplemented("container hosts"))?;
                // Cancel stops waiting; the engine may still finish what it was asked.
                let done = tokio::select! {
                    biased;
                    _ = token.cancelled() => return Err(CoreError::CancelledRemote),
                    done = containers.change(&spec.ctx, container, op) => done?,
                };
                let output = OutputCollector::collect(
                    done.stdout.as_bytes(),
                    done.stderr.as_bytes(),
                    &[],
                    MAX_OUTPUT_PER_STREAM,
                );
                Ok(TargetOutcome {
                    output: Some(output),
                    note: done.note.map(|note| format!("{}: {note}", target.name)),
                    ..TargetOutcome::done()
                })
            }
            // VM-21, VM-22, VM-10: one new VM, with its after-deploy steps. Cancel stops it and removes what this job
            // made for it; VMs already made stay.
            (Command::Deploy { spec: deploy, .. }, TargetRef::NewVm { name, .. }) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let deployer = locks::read(&self.deployer)
                    .clone()
                    .ok_or_else(|| CoreError::NotImplemented("deploys"))?;
                let vm = deploy
                    .vm(name)
                    .ok_or_else(|| CoreError::UnknownTarget(target.target.key()))?;
                let note = deployer.deploy_vm(&spec.ctx, job_id, deploy, vm, token).await?;
                // Activity shows each VM's result as its output.
                let output = OutputCollector::collect(note.as_bytes(), b"", &[], MAX_OUTPUT_PER_STREAM);
                Ok(TargetOutcome {
                    output: Some(output),
                    note: Some(format!("{}: {note}", vm.name)),
                    ..TargetOutcome::done()
                })
            }
            (command, other) => Err(CoreError::WrongTargetKind {
                action: command.summary(1),
                target: format!("a {} target", other.kind()),
            }),
        }
    }

    /// BX-02, SS-09: runs a script on one saved session's host over SSH.
    async fn run_remote(
        &self,
        spec: &JobSpec,
        target: &Target,
        session_id: Uuid,
        run: RemoteRun<'_>,
        token: &CancellationToken,
        accepted: &Arc<Mutex<Option<String>>>,
    ) -> Result<TargetOutcome> {
        let session = self
            .store
            .session_spec(&spec.ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("the session was deleted".into()))?;
        if token.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        // SS-04: a run the user started (and approved) counts as activity, so the vault doesn't lock
        // half-way through a long one. Background reads never do.
        self.vault.note_activity();
        let credentials = crate::sessions::credentials(&*self.vault, &spec.ctx, &session, None).await?;
        // SS-07: each jump host on the way logs in with its own session's credentials.
        let jump_credentials =
            crate::sessions::jump_credentials(&*self.vault, &spec.ctx, &session, &Default::default()).await?;
        let sudo_password = match run.sudo {
            true => Some(self.sudo_password(&spec.ctx, &session, run.sudo_password_id).await?),
            false => None,
        };
        let tuning = locks::read(&self.exec_tuning).clone();
        let options = ConnectOptions {
            connect_timeout: tuning.connect_timeout,
            keepalive_interval: Some(Duration::from_secs(30)),
            agent: tuning.agent,
            ..ConnectOptions::default()
        };
        let verifier = Arc::new(BulkVerifier {
            known_hosts: Arc::clone(&self.known_hosts),
            ctx: spec.ctx,
            target: target.clone(),
            trust_new: run.trust_new_host_keys,
            accepted: Mutex::new(None),
        });
        let exec = self.remote.exec(ExecRequest {
            session: &session,
            credentials,
            jump_credentials,
            script: run.script,
            sudo_password,
            options: &options,
            verifier: Arc::clone(&verifier) as Arc<dyn HostKeyVerifier>,
            max_output: tuning.max_output,
        });
        let limited = async {
            match run.timeout_secs {
                // H9: the command may have started, so its outcome is unknown.
                Some(secs) => tokio::time::timeout(Duration::from_secs(secs), exec)
                    .await
                    .map_err(|_| CoreError::CommandTimedOut { seconds: secs })?,
                None => exec.await,
            }
        };
        // BX-04: cancel closes the connection; the host may still finish the command.
        let result = tokio::select! {
            biased;
            _ = token.cancelled() => Err(CoreError::CancelledRemote),
            result = limited => result,
        };
        // Whatever came of it, the journal says which key the host presented.
        *locks::lock(accepted) = locks::lock(&verifier.accepted).take();
        let result = result?;
        let ok = result.exit_code == Some(0) && result.signal.is_none();
        let failure = match (&result.signal, result.exit_code) {
            (Some(signal), _) => Some(format!("ended by signal {signal}")),
            (None, Some(0)) => None,
            (None, Some(code)) => Some(format!("exit code {code}")),
            (None, None) => Some("the host sent no exit code".to_owned()),
        };
        Ok(TargetOutcome {
            ok,
            exit_code: result.exit_code.map(i64::from),
            output: Some(result.output),
            failure,
            note: None,
            peer_ip: result.peer_ip.map(|ip| ip.to_string()),
        })
    }

    /// BX-07: the password sudo gets on this host: the one chosen for the run, or the session's own
    /// login password.
    async fn sudo_password(
        &self,
        ctx: &Context,
        session: &SessionSpec,
        chosen: Option<SecretId>,
    ) -> Result<SecretString> {
        let id = match (chosen, &session.auth) {
            (Some(id), _) => id,
            (None, AuthMethod::Password(Some(id))) => *id,
            (None, _) => {
                return Err(CoreError::NoSudoPassword(format!(
                    "'{}' has no saved login password for sudo. Choose a sudo password from the vault for the run",
                    session.name
                )))
            }
        };
        self.vault.get(ctx, id).await
    }

    /// VM-02, VM-03: one power operation on one VM, by its hypervisor.
    async fn power(&self, key: &str, op: PowerOp) -> Result<()> {
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => self.vmware_power(Path::new(key), op).await,
            Hypervisor::VirtualBox => self.virtualbox_power(key, op).await,
        }
    }

    /// VM-02, VM-03 on Workstation. A graceful operation that needs VMware Tools fails at once when
    /// they are not running; it never falls back to the hard variant, which the policy engine rates
    /// on its own (a hard stop or reset is Critical).
    async fn vmware_power(&self, vmx: &Path, op: PowerOp) -> Result<()> {
        let needs_tools = match op {
            PowerOp::Stop { mode: StopMode::Soft } => return self.soft_stop(vmx).await,
            PowerOp::Reset { mode: StopMode::Soft } => {
                Some(("restart", "Reset (hard) forces it; that needs its own approval."))
            }
            PowerOp::Suspend => Some(("suspend", "Try again once VMware Tools runs in the guest.")),
            _ => None,
        };
        if let Some((action, advice)) = needs_tools {
            if let Some(tools) = self.tools_missing(vmx).await? {
                return Err(CoreError::ToolsNotRunning {
                    tools: tools.describe().to_owned(),
                    action,
                    advice,
                });
            }
        }
        self.hypervisors.vmware().power(vmx, op).await
    }

    /// VM-18: VM-02 and VM-03 on VirtualBox. A soft stop needs no Guest Additions (the ACPI power
    /// button), so it is tried and waited for; a graceful restart needs them, so a guest without them
    /// fails at once, as VMware's does. Nothing falls back to the hard variant.
    async fn virtualbox_power(&self, uuid: &str, op: PowerOp) -> Result<()> {
        let vbox = self.hypervisors.virtualbox();
        match op {
            PowerOp::Stop { mode: StopMode::Soft } => return self.virtualbox_soft_stop(uuid).await,
            PowerOp::Reset { mode: StopMode::Soft } => {
                let info = vbox.vm_info(uuid).await?;
                if info.power_state().is_on() && info.tools_state() != Some(ToolsState::Running) {
                    return Err(CoreError::ToolsNotRunning {
                        tools: "Guest Additions are not running in the guest".to_owned(),
                        action: "restart",
                        advice: "Reset (hard) forces it; that needs its own approval.",
                    });
                }
            }
            _ => {}
        }
        vbox.power(uuid, op).await
    }

    /// VM-03 on VirtualBox: presses the ACPI power button and waits up to the shutdown wait. A VM
    /// still running then (the guest ignored the button) is [`CoreError::StillRunning`] and left
    /// running.
    async fn virtualbox_soft_stop(&self, uuid: &str) -> Result<()> {
        let vbox = self.hypervisors.virtualbox();
        let wait = self.limits().shutdown_wait;
        let op = PowerOp::Stop { mode: StopMode::Soft };
        let failure = match tokio::time::timeout(wait, vbox.power(uuid, op)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(err)) => err,
            // The guest may still be shutting down; VBoxManage is stopped, the guest is not.
            Err(_) => CoreError::Timeout {
                command: "VBoxManage controlvm acpipowerbutton".into(),
                seconds: wait.as_secs(),
            },
        };
        match vbox.vm_info(uuid).await {
            Ok(info) if info.power_state().is_on() => {
                let reason = match failure {
                    CoreError::Timeout { seconds, .. } => {
                        format!("the guest did not shut down within {seconds} s (its OS may not handle the ACPI power button)")
                    }
                    other => format!("the soft stop failed ({other})"),
                };
                Err(CoreError::StillRunning { reason })
            }
            // It stopped after all, just as the wait ran out.
            Ok(_) if matches!(failure, CoreError::Timeout { .. }) => Ok(()),
            _ => Err(failure),
        }
    }

    /// VM-02, VM-03: the VMware Tools state of a running VM whose Tools are not running, or `None`
    /// when a graceful operation can go ahead. vmrun's soft stop, restart and suspend wait for Tools
    /// instead of failing (on Workstation 26, `suspend soft` waited until the VM was powered off from
    /// outside). A VM that is not running has no Tools to wait for, so vmrun answers for it at once.
    async fn tools_missing(&self, vmx: &Path) -> Result<Option<ToolsState>> {
        let vmware = self.hypervisors.vmware();
        let state = match vmware.tools_state(vmx).await {
            Ok(ToolsState::Running) => return Ok(None),
            other => other,
        };
        let key = path_key(vmx);
        if !vmware.list_running().await?.iter().any(|p| path_key(p) == key) {
            return Ok(None);
        }
        state.map(Some)
    }

    /// VM-03: asks the guest to shut down and waits up to the shutdown wait. A VM that is still
    /// running then (the guest ignored it, or has no VMware Tools) is reported as
    /// [`CoreError::StillRunning`] and left running: forcing it off is a separate command. Without
    /// VMware Tools that is known before asking, so it is reported at once.
    async fn soft_stop(&self, vmx: &Path) -> Result<()> {
        if let Some(tools) = self.tools_missing(vmx).await? {
            return Err(CoreError::StillRunning {
                reason: format!("{}, so it can't be asked to shut down", tools.describe()),
            });
        }
        let wait = self.limits().shutdown_wait;
        let op = PowerOp::Stop { mode: StopMode::Soft };
        let failure = match tokio::time::timeout(wait, self.hypervisors.vmware().power(vmx, op)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(err)) => err,
            // The guest may still be shutting down; vmrun is stopped, the guest is not.
            Err(_) => CoreError::Timeout {
                command: "vmrun stop soft".into(),
                seconds: wait.as_secs(),
            },
        };
        let key = path_key(vmx);
        match self.hypervisors.vmware().list_running().await {
            Ok(running) if running.iter().any(|p| path_key(p) == key) => {
                let reason = match failure {
                    CoreError::Timeout { seconds, .. } => {
                        format!("the guest did not shut down within {seconds} s")
                    }
                    other => format!("the soft stop failed ({other})"),
                };
                Err(CoreError::StillRunning { reason })
            }
            // It stopped after all, just as the wait ran out.
            Ok(_) if matches!(failure, CoreError::Timeout { .. }) => Ok(()),
            _ => Err(failure),
        }
    }

    /// VM-05: a named snapshot before the action, so it can be undone. When it fails the action does
    /// not run on that VM: no safety net, no change.
    async fn take_safety_snapshot(&self, key: &str, name: &str) -> Result<()> {
        let op = SnapshotOp::Take { name: name.to_owned() };
        self.hypervisors
            .snapshot(key, &op)
            .await
            .map_err(|err| CoreError::SafetySnapshotFailed(err.to_string()))
    }

    fn parallelism(&self, command: &Command) -> usize {
        let limits = self.limits();
        let n = match command {
            Command::VmPower {
                op: PowerOp::Start { .. },
                ..
            } => limits.power_on,
            Command::VmPower { .. }
            | Command::VmSnapshot { .. }
            | Command::VmProtect { .. }
            | Command::VmConfig { .. }
            | Command::VmDevice { .. }
            | Command::VmDisk { .. }
            | Command::VmLifecycle { .. } => limits.vm_ops,
            Command::RemoteExec { .. }
            | Command::PushSshKey { .. }
            | Command::RemoveSshKey { .. }
            | Command::Container { .. } => limits.remote,
            Command::AppUpdate { .. } => 1,
            // SS-10: pressing Enter is instant; every terminal at once, so they start together.
            Command::TerminalLine { targets, .. } => targets.len(),
            // SS-08: one terminal, its files one after another. SS-07: one tunnel on one terminal.
            Command::FileUpload { .. } | Command::OpenTunnel { .. } => 1,
            // VM-21: each VM copies or writes whole disks, so two at a time keep this PC's disk usable.
            Command::Deploy { .. } => limits.vm_ops.min(crate::deploy::PARALLEL_VMS),
        };
        n.max(1)
    }

    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        ctx: &Context,
        event: &str,
        summary: &str,
        spec: &JobSpec,
        job_id: Uuid,
        result: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
                    action: summary,
                    tier: Some(spec.decision.tier),
                    job_id: Some(job_id),
                    targets: &spec.decision.targets,
                    approval: spec.approval.as_ref(),
                    result,
                    detail,
                },
            )
            .await
            .map(drop)
    }

    fn emit(&self, event: JobEvent) {
        // No subscribers is fine (e.g. in tests).
        let _ = self.events.send(event);
    }
}

/// Names the action in a safety snapshot's name ("before shut down").
fn safety_verb(command: &Command) -> &'static str {
    match command {
        Command::VmPower { op, .. } => match op {
            PowerOp::Stop { mode: StopMode::Soft } => "shut down",
            PowerOp::Stop { mode: StopMode::Hard } => "power off",
            PowerOp::Reset { mode: StopMode::Soft } => "restart",
            PowerOp::Reset { mode: StopMode::Hard } => "reset",
            PowerOp::Suspend => "suspend",
            PowerOp::Pause => "pause",
            PowerOp::Unpause => "unpause",
            PowerOp::Start { .. } => "start",
        },
        Command::VmSnapshot { op, .. } => match op {
            SnapshotOp::Revert { .. } => "revert",
            SnapshotOp::Delete { .. } => "delete",
            SnapshotOp::Take { .. } => "snapshot",
        },
        Command::VmProtect { .. } => "protect",
        Command::RemoteExec { .. }
        | Command::PushSshKey { .. }
        | Command::RemoveSshKey { .. }
        | Command::TerminalLine { .. } => "command",
        Command::FileUpload { .. } => "upload",
        Command::OpenTunnel { .. } => "tunnel",
        Command::Container { .. } => "container",
        Command::AppUpdate { .. } => "update",
        Command::Deploy { .. } => "deploy",
        Command::VmConfig {
            edit: crate::vm_settings::VmConfigEdit::UpgradeHardware,
            ..
        } => "hardware upgrade",
        Command::VmConfig { .. } => "settings change",
        Command::VmDevice { .. } => "tools install",
        Command::VmDisk { .. } => "disk change",
        Command::VmLifecycle { .. } => "delete",
    }
}

/// The power state a VM is in once `op` has succeeded.
fn state_after(op: PowerOp) -> PowerState {
    match op {
        PowerOp::Start { .. } | PowerOp::Reset { .. } | PowerOp::Unpause => PowerState::Running,
        PowerOp::Stop { .. } => PowerState::NotRunning,
        PowerOp::Suspend => PowerState::Suspended,
        PowerOp::Pause => PowerState::Paused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_says_what_it_may_have_changed() {
        let vm = vec![TargetRef::Vm {
            vmx_path: r"C:\VMs\web01\web01.vmx".into(),
        }];
        let scope = |command: &Command| JobScope::of(command);
        assert_eq!(
            scope(&Command::VmPower {
                targets: vm.clone(),
                op: PowerOp::Suspend
            }),
            JobScope::Vms
        );
        assert_eq!(
            scope(&Command::VmProtect {
                targets: vm.clone(),
                protected: true
            }),
            JobScope::Vms
        );
        assert_eq!(
            scope(&Command::Container {
                targets: Vec::new(),
                op: crate::command_bus::ContainerOp::Restart
            }),
            JobScope::Containers
        );
        assert_eq!(
            scope(&Command::AppUpdate {
                version: "9.9.9".into()
            }),
            JobScope::Other
        );
        let event = JobEvent::Finished {
            job_id: Uuid::nil(),
            status: JobStatus::Succeeded,
            scope: JobScope::Vms,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event"], "finished");
        assert_eq!(json["scope"], "vms");
    }
}
