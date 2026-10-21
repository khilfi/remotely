//! Job runner: runs commands the bus has cleared, against each target, with bounded parallelism.
//!
//! * Parallel limits: power-ons default to 3 (VM-06), remote commands to 10 (BX-02).
//! * Graceful shutdown (VM-03): a soft stop gets a set time; a VM still running after it is reported
//!   ([`JobEvent::StillRunning`]) and left running. Forcing it off is a separate hard-stop command,
//!   which the policy engine puts at Critical, so it gets its own approval.
//! * Graceful power operations (soft stop, restart, suspend) go through VMware Tools, and vmrun waits
//!   for Tools rather than failing when they are not running. So Tools are checked first, and a VM
//!   without them fails at once with the reason (VM-02, VM-03).
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
//! * Every job and target is journaled in the store, and the audit log gets an entry when the job
//!   starts and when it ends (NFR Audit, NFR Reliability).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{broadcast, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::exec_output::{CollectedOutput, OutputCollector, MAX_OUTPUT_PER_STREAM};
use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, ExecRequest, HostKeyVerifier, RemoteAdapter, SessionSpec,
};
use crate::adapters::updater::UpdaterAdapter;
use crate::adapters::vmware::{path_key, ToolsState, VmwareAdapter};
use crate::command_bus::{ApprovalRecord, Command, PowerOp, SnapshotOp, StopMode};
use crate::containers::ContainerActions;
use crate::domain::{Context, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::{HostKey, HostKeyCheck, KnownHosts};
use crate::locks;
use crate::policy::{safety_snapshot_applies, ApprovalStep, Decision, Tier};
use crate::snapshots::safety_snapshot_name;
use crate::ssh_keys;
use crate::store::{NewAuditEntry, NewJob, Store, TargetResult};
use crate::terminal::files::UploadRun;
use crate::terminal::tunnels::TunnelRun;
use crate::terminal::TerminalActions;
use crate::vault::{SecretId, SecretString, Vault};

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
    },
}

struct TargetOutcome {
    ok: bool,
    exit_code: Option<i64>,
    output: Option<CollectedOutput>,
    /// Why it counts as failed although it ran, e.g. "exit code 2".
    failure: Option<String>,
    /// What the end of the job's audit entry says about this target (SS-08: the files uploaded).
    note: Option<String>,
}

impl TargetOutcome {
    fn done() -> Self {
        Self {
            ok: true,
            exit_code: None,
            output: None,
            failure: None,
            note: None,
        }
    }
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
        Self {
            status: TargetStatus::Failed,
            exit_code: None,
            output: None,
            error: Some(err.to_string()),
            error_code: Some(err.code()),
        }
    }

    fn cancelled(err: Option<&CoreError>) -> Self {
        Self {
            status: TargetStatus::Cancelled,
            exit_code: None,
            output: None,
            error: err.map(ToString::to_string),
            error_code: err.map(CoreError::code),
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
/// seen before is trusted (and audited) only when the run says so, since nobody can be asked.
struct BulkVerifier {
    known_hosts: Arc<KnownHosts>,
    ctx: Context,
    target: Target,
    trust_new: bool,
}

#[async_trait]
impl HostKeyVerifier for BulkVerifier {
    async fn verify(&self, key: &HostKey, jump: Option<&str>) -> Result<()> {
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

pub struct JobRunner {
    store: Store,
    vmware: Arc<dyn VmwareAdapter>,
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
    exec_tuning: RwLock<ExecTuning>,
    /// Read when a job starts, so a changed setting applies to the next job.
    limits: RwLock<JobLimits>,
    events: broadcast::Sender<JobEvent>,
    /// Open jobs (queued, in countdown or running) and their cancel tokens.
    running: Mutex<HashMap<Uuid, CancellationToken>>,
    /// Signalled whenever a job closes, for jobs waiting to run alone (FD-14).
    idle: Notify,
}

impl JobRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Store,
        vmware: Arc<dyn VmwareAdapter>,
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
            store,
            vmware,
            remote,
            updater,
            vault,
            known_hosts,
            terminals,
            containers: RwLock::new(None),
            exec_tuning: RwLock::new(ExecTuning::default()),
            limits: RwLock::new(limits),
            events,
            running: Mutex::new(HashMap::new()),
            idle: Notify::new(),
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

    /// BX-02: connect timeout, agent and output cap of bulk runs (tests shorten them).
    pub fn set_exec_tuning(&self, tuning: ExecTuning) {
        *locks::write(&self.exec_tuning) = tuning;
    }

    /// Number of open jobs.
    pub fn open_jobs(&self) -> usize {
        locks::lock(&self.running).len()
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
                    Ok(JobEvent::Finished { job_id: id, status }) if id == job_id => return Ok(status),
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
        tokio::spawn(async move {
            let countdown = countdown.zip(countdown_until);
            if let Err(err) = Arc::clone(&this).run(id, spec, summary, countdown, token).await {
                tracing::error!(%id, error = %err, "job failed to run");
                let _ = this.store.set_job_status(id, JobStatus::Failed).await;
                this.emit(JobEvent::Finished {
                    job_id: id,
                    status: JobStatus::Failed,
                });
            }
            locks::lock(&this.running).remove(&id);
            this.idle.notify_waiters();
        });
        Ok(id)
    }

    async fn run(
        self: Arc<Self>,
        id: Uuid,
        spec: JobSpec,
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
                    self.store.set_job_status(id, JobStatus::Cancelled).await?;
                    self.audit(&ctx, "job_cancelled", &summary, &spec, id, Some("cancelled"),
                        Some("cancelled during the countdown; no target was touched")).await?;
                    self.emit(JobEvent::Finished { job_id: id, status: JobStatus::Cancelled });
                    return Ok(());
                }
            }
        }

        self.store.set_job_status(id, JobStatus::Running).await?;
        let retry = spec
            .retry_of
            .map(|of| format!("retries the failed targets of job {of}"));
        self.audit(&ctx, "job_started", &summary, &spec, id, None, retry.as_deref())
            .await?;
        self.emit(JobEvent::Started { job_id: id });

        let semaphore = Arc::new(Semaphore::new(self.parallelism(&spec.command)));
        // VM-05: named once, when the job starts, so every VM's safety snapshot has the same name.
        let safety_name: Option<Arc<str>> = (spec.safety_snapshot && safety_snapshot_applies(&spec.command))
            .then(|| safety_snapshot_name(safety_verb(&spec.command), time::OffsetDateTime::now_utc(), id).into());
        let spec = Arc::new(spec);
        let mut tasks = JoinSet::new();
        for target in spec.decision.targets.clone() {
            let this = Arc::clone(&self);
            let spec = Arc::clone(&spec);
            let semaphore = Arc::clone(&semaphore);
            let token = token.clone();
            let safety_name = safety_name.clone();
            tasks.spawn(async move {
                let permit = tokio::select! {
                    permit = semaphore.acquire_owned() => permit.ok(),
                    _ = token.cancelled() => None,
                };
                if permit.is_none() || token.is_cancelled() {
                    return (target, Err(None), 0, None, None);
                }
                let key = target.target.key();
                if let Err(err) = this.store.set_target_running(id, &key).await {
                    tracing::warn!(%id, error = %err, "could not journal target start");
                }
                this.emit(JobEvent::TargetStarted {
                    job_id: id,
                    target: key,
                    name: target.name.clone(),
                });
                let started = Instant::now();
                let mut safety_taken = None;
                if let (Some(name), TargetRef::Vm { vmx_path }) = (&safety_name, &target.target) {
                    if let Err(err) = this.take_safety_snapshot(Path::new(vmx_path), name).await {
                        return (target, Err(Some(err)), started.elapsed().as_millis() as u64, None, None);
                    }
                    safety_taken = Some(name.to_string());
                }
                let mut outcome = this.execute(id, &spec, &target, &token).await;
                let note = outcome.as_mut().ok().and_then(|o| o.note.take());
                (
                    target,
                    outcome.map_err(Some),
                    started.elapsed().as_millis() as u64,
                    safety_taken,
                    note,
                )
            });
        }

        let (mut succeeded, mut failed, mut cancelled) = (0usize, 0usize, 0usize);
        let mut still_running = Vec::new();
        let mut cancelled_in_flight = Vec::new();
        let mut safety_snapshots = 0usize;
        let mut notes = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let (target, outcome, duration_ms, safety_snapshot, note) = match joined {
                Ok(v) => v,
                Err(err) => {
                    tracing::error!(%id, error = %err, "target task panicked");
                    failed += 1;
                    continue;
                }
            };
            let done = match outcome {
                Ok(o) => Finished {
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
                },
                Err(Some(CoreError::Cancelled)) | Err(None) => Finished::cancelled(None),
                Err(Some(err @ (CoreError::CancelledInFlight | CoreError::CancelledRemote))) => {
                    cancelled_in_flight.push(target.name.clone());
                    Finished::cancelled(Some(&err))
                }
                Err(Some(err @ CoreError::StillRunning { .. })) => {
                    still_running.push(target.clone());
                    Finished::failed(&err)
                }
                Err(Some(err)) => Finished::failed(&err),
            };
            if let Some(note) = note {
                notes.push(note);
            }
            match done.status {
                TargetStatus::Succeeded => succeeded += 1,
                TargetStatus::Cancelled => cancelled += 1,
                _ => failed += 1,
            }
            let key = target.target.key();
            let out = done.output.as_ref();
            self.store
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
                    },
                )
                .await?;
            safety_snapshots += usize::from(safety_snapshot.is_some());
            self.emit(JobEvent::TargetFinished {
                job_id: id,
                target: key,
                name: target.name.clone(),
                status: done.status,
                message: done.error,
                exit_code: done.exit_code,
                duration_ms,
                safety_snapshot,
            });
        }

        let status = if token.is_cancelled() {
            JobStatus::Cancelled
        } else if failed == 0 {
            JobStatus::Succeeded
        } else if succeeded == 0 {
            JobStatus::Failed
        } else {
            JobStatus::PartiallyFailed
        };
        self.store.set_job_status(id, status).await?;
        let mut detail = format!("{succeeded} succeeded, {failed} failed, {cancelled} cancelled");
        if let (Some(name), true) = (&safety_name, safety_snapshots > 0) {
            detail.push_str(&format!("; safety snapshot '{name}' taken on {safety_snapshots} VM(s)"));
        }
        for note in &notes {
            detail.push_str(&format!("; {note}"));
        }
        if !cancelled_in_flight.is_empty() {
            let what = if matches!(
                spec.command,
                Command::RemoteExec { .. } | Command::PushSshKey { .. } | Command::Container { .. }
            ) {
                "cancelled while the command was running, so the host may still finish it"
            } else {
                "cancelled while vmrun was running, so Workstation may still finish it"
            };
            detail.push_str(&format!("; {what}: {}", cancelled_in_flight.join(", ")));
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
        self.audit(
            &ctx,
            "job_finished",
            &summary,
            &spec,
            id,
            Some(status.as_str()),
            Some(&detail),
        )
        .await?;
        self.emit(JobEvent::Finished { job_id: id, status });
        Ok(())
    }

    async fn execute(
        &self,
        job_id: Uuid,
        spec: &JobSpec,
        target: &Target,
        token: &CancellationToken,
    ) -> Result<TargetOutcome> {
        match (&spec.command, &target.target) {
            (Command::VmPower { op, .. }, TargetRef::Vm { vmx_path }) => {
                let vmx = Path::new(vmx_path);
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                // BX-04: cancel stops waiting. Dropping the call kills vmrun (kill_on_drop).
                tokio::select! {
                    biased;
                    result = self.power(vmx, *op) => result?,
                    _ = token.cancelled() => return Err(CoreError::CancelledInFlight),
                }
                // The VM list shows the new state before the next refresh asks vmrun.
                self.store
                    .set_vm_power_state(&spec.ctx, vmx_path, state_after(*op))
                    .await?;
                Ok(TargetOutcome::done())
            }
            (Command::VmSnapshot { op, .. }, TargetRef::Vm { vmx_path }) => {
                self.vmware.snapshot(Path::new(vmx_path), op).await?;
                Ok(TargetOutcome::done())
            }
            (Command::VmProtect { protected, .. }, TargetRef::Vm { vmx_path }) => {
                // AP-04: the app's own flag; the VM itself is not touched.
                if !self.store.set_vm_protected(&spec.ctx, vmx_path, *protected).await? {
                    return Err(CoreError::UnknownTarget(vmx_path.clone()));
                }
                Ok(TargetOutcome::done())
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
                self.run_remote(spec, target, *session_id, run, token).await
            }
            (
                Command::PushSshKey {
                    public_key,
                    trust_new_host_keys,
                    timeout_secs,
                    ..
                },
                TargetRef::Session { session_id },
            ) => {
                // SS-09: checked again here, so only Remotely's own form of the key reaches a host.
                let key = ssh_keys::parse_public_key(public_key)?;
                let script = ssh_keys::authorized_keys_script(&key);
                let run = RemoteRun {
                    script: &script,
                    sudo: false,
                    sudo_password_id: None,
                    trust_new_host_keys: *trust_new_host_keys,
                    timeout_secs: *timeout_secs,
                };
                self.run_remote(spec, target, *session_id, run, token).await
            }
            (Command::AppUpdate { version }, TargetRef::App) => {
                // FD-14: never update under a running job.
                self.wait_to_run_alone(job_id, token).await?;
                // The private repo's releases need the GitHub update token from the vault.
                let github_token = crate::updates::stored_token(&self.store, self.vault.as_ref(), &spec.ctx)
                    .await?
                    .require()?;
                self.updater.install(&github_token, version).await?;
                Ok(TargetOutcome::done())
            }
            (Command::TerminalLine { keys, .. }, TargetRef::Terminal { terminal_id, .. }) => {
                if token.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                // SS-10: the held Enter (and the rest of a paste of several lines).
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
    ) -> Result<TargetOutcome> {
        let session = self
            .store
            .session_spec(&spec.ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("the session was deleted".into()))?;
        if token.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
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
        });
        let exec = self.remote.exec(ExecRequest {
            session: &session,
            credentials,
            jump_credentials,
            script: run.script,
            sudo_password,
            options: &options,
            verifier,
            max_output: tuning.max_output,
        });
        let limited = async {
            match run.timeout_secs {
                Some(secs) => tokio::time::timeout(Duration::from_secs(secs), exec)
                    .await
                    .map_err(|_| CoreError::Timeout {
                        command: "the command".into(),
                        seconds: secs,
                    })?,
                None => exec.await,
            }
        };
        // BX-04: cancel closes the connection; the host may still finish the command.
        let result = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(CoreError::CancelledRemote),
            result = limited => result?,
        };
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

    /// VM-02, VM-03: one power operation on one VM. A graceful one that needs VMware Tools fails at
    /// once when they are not running; it never falls back to the hard variant, which the policy
    /// engine rates on its own (a hard stop or reset is Critical).
    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()> {
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
        self.vmware.power(vmx, op).await
    }

    /// VM-02, VM-03: the VMware Tools state of a running VM whose Tools are not running, or `None`
    /// when a graceful operation can go ahead. vmrun's soft stop, restart and suspend wait for Tools
    /// instead of failing (on Workstation 26, `suspend soft` waited until the VM was powered off from
    /// outside). A VM that is not running has no Tools to wait for, so vmrun answers for it at once.
    async fn tools_missing(&self, vmx: &Path) -> Result<Option<ToolsState>> {
        let state = match self.vmware.tools_state(vmx).await {
            Ok(ToolsState::Running) => return Ok(None),
            other => other,
        };
        let key = path_key(vmx);
        if !self.vmware.list_running().await?.iter().any(|p| path_key(p) == key) {
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
        let failure = match tokio::time::timeout(wait, self.vmware.power(vmx, op)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(err)) => err,
            // The guest may still be shutting down; vmrun is stopped, the guest is not.
            Err(_) => CoreError::Timeout {
                command: "vmrun stop soft".into(),
                seconds: wait.as_secs(),
            },
        };
        let key = path_key(vmx);
        match self.vmware.list_running().await {
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
    async fn take_safety_snapshot(&self, vmx: &Path, name: &str) -> Result<()> {
        let op = SnapshotOp::Take { name: name.to_owned() };
        self.vmware
            .snapshot(vmx, &op)
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
            Command::VmPower { .. } | Command::VmSnapshot { .. } | Command::VmProtect { .. } => limits.vm_ops,
            Command::RemoteExec { .. } | Command::PushSshKey { .. } | Command::Container { .. } => limits.remote,
            Command::AppUpdate { .. } => 1,
            // SS-10: pressing Enter is instant; every terminal at once, so they start together.
            Command::TerminalLine { targets, .. } => targets.len(),
            // SS-08: one terminal, its files one after another. SS-07: one tunnel on one terminal.
            Command::FileUpload { .. } | Command::OpenTunnel { .. } => 1,
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
        Command::RemoteExec { .. } | Command::PushSshKey { .. } | Command::TerminalLine { .. } => "command",
        Command::FileUpload { .. } => "upload",
        Command::OpenTunnel { .. } => "tunnel",
        Command::Container { .. } => "container",
        Command::AppUpdate { .. } => "update",
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
