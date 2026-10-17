//! Job runner: runs commands the bus has cleared, against each target, with bounded parallelism.
//!
//! * Parallel limits: power-ons default to 3 (VM-06), remote commands to 10 (BX-02).
//! * Countdown with cancel after approval (AP-03); cancel stops targets that have not started (BX-04).
//!   A vmrun call already in flight is left to finish rather than killed halfway.
//! * Safety snapshot before each VM's action when the approval asked for one (VM-05).
//! * Every job and target is journaled in the store, and the audit log gets an entry when the job
//!   starts and when it ends (NFR Audit, NFR Reliability).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{broadcast, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::remote::RemoteAdapter;
use crate::adapters::updater::UpdaterAdapter;
use crate::adapters::vmware::VmwareAdapter;
use crate::command_bus::{ApprovalRecord, Command, PowerOp, SnapshotOp};
use crate::domain::{Context, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::policy::{ApprovalStep, Decision, Tier};
use crate::store::{NewAuditEntry, NewJob, Store, TargetResult};

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
}

impl Default for JobLimits {
    fn default() -> Self {
        Self {
            power_on: 3,
            vm_ops: 4,
            remote: 10,
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
    },
    Countdown {
        job_id: Uuid,
        seconds: u32,
    },
    Started {
        job_id: Uuid,
    },
    TargetFinished {
        job_id: Uuid,
        target: String,
        name: String,
        status: TargetStatus,
        message: Option<String>,
        duration_ms: u64,
    },
    Finished {
        job_id: Uuid,
        status: JobStatus,
    },
}

struct TargetOutcome {
    ok: bool,
    exit_code: Option<i64>,
    output: Option<String>,
}

impl TargetOutcome {
    fn done() -> Self {
        Self {
            ok: true,
            exit_code: None,
            output: None,
        }
    }
}

pub struct JobRunner {
    store: Store,
    vmware: Arc<dyn VmwareAdapter>,
    remote: Arc<dyn RemoteAdapter>,
    updater: Arc<dyn UpdaterAdapter>,
    limits: JobLimits,
    events: broadcast::Sender<JobEvent>,
    /// Open jobs (queued, in countdown or running) and their cancel tokens.
    running: Mutex<HashMap<Uuid, CancellationToken>>,
    /// Signalled whenever a job closes, for jobs waiting to run alone (FD-14).
    idle: Notify,
}

impl JobRunner {
    pub fn new(
        store: Store,
        vmware: Arc<dyn VmwareAdapter>,
        remote: Arc<dyn RemoteAdapter>,
        updater: Arc<dyn UpdaterAdapter>,
        limits: JobLimits,
    ) -> Arc<Self> {
        let (events, _) = broadcast::channel(256);
        Arc::new(Self {
            store,
            vmware,
            remote,
            updater,
            limits,
            events,
            running: Mutex::new(HashMap::new()),
            idle: Notify::new(),
        })
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

    /// BX-04: rerun only the targets that failed, as a new job through the bus.
    pub async fn retry_failed(&self, _job_id: Uuid) -> Result<Uuid> {
        Err(CoreError::NotImplemented("BX-04 retry failed hosts"))
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
        });

        let this = Arc::clone(self);
        tokio::spawn(async move {
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
        countdown: Option<u32>,
        token: CancellationToken,
    ) -> Result<()> {
        let ctx = spec.ctx;

        if let Some(seconds) = countdown {
            self.emit(JobEvent::Countdown { job_id: id, seconds });
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
        self.audit(&ctx, "job_started", &summary, &spec, id, None, None).await?;
        self.emit(JobEvent::Started { job_id: id });

        let semaphore = Arc::new(Semaphore::new(self.parallelism(&spec.command)));
        let spec = Arc::new(spec);
        let mut tasks = JoinSet::new();
        for target in spec.decision.targets.clone() {
            let this = Arc::clone(&self);
            let spec = Arc::clone(&spec);
            let semaphore = Arc::clone(&semaphore);
            let token = token.clone();
            tasks.spawn(async move {
                let permit = tokio::select! {
                    permit = semaphore.acquire_owned() => permit.ok(),
                    _ = token.cancelled() => None,
                };
                if permit.is_none() || token.is_cancelled() {
                    return (target, Err(None), 0);
                }
                let key = target.target.key();
                if let Err(err) = this.store.set_target_running(id, &key).await {
                    tracing::warn!(%id, error = %err, "could not journal target start");
                }
                let started = Instant::now();
                let outcome = this.execute(id, &spec, &target, &token).await;
                (target, outcome.map_err(Some), started.elapsed().as_millis() as u64)
            });
        }

        let (mut succeeded, mut failed, mut cancelled) = (0usize, 0usize, 0usize);
        while let Some(joined) = tasks.join_next().await {
            let (target, outcome, duration_ms) = match joined {
                Ok(v) => v,
                Err(err) => {
                    tracing::error!(%id, error = %err, "target task panicked");
                    failed += 1;
                    continue;
                }
            };
            let (status, exit_code, output, error) = match outcome {
                Ok(o) if o.ok => (TargetStatus::Succeeded, o.exit_code, o.output, None),
                Ok(o) => (
                    TargetStatus::Failed,
                    o.exit_code,
                    o.output,
                    Some("non-zero exit code".to_owned()),
                ),
                Err(Some(CoreError::Cancelled)) | Err(None) => (TargetStatus::Cancelled, None, None, None),
                Err(Some(err)) => (TargetStatus::Failed, None, None, Some(err.to_string())),
            };
            match status {
                TargetStatus::Succeeded => succeeded += 1,
                TargetStatus::Cancelled => cancelled += 1,
                _ => failed += 1,
            }
            let key = target.target.key();
            self.store
                .set_target_result(
                    id,
                    &key,
                    TargetResult {
                        status,
                        exit_code,
                        output: output.as_deref(),
                        error: error.as_deref(),
                        duration_ms: i64::try_from(duration_ms).ok(),
                    },
                )
                .await?;
            self.emit(JobEvent::TargetFinished {
                job_id: id,
                target: key,
                name: target.name.clone(),
                status,
                message: error,
                duration_ms,
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
        let detail = format!("{succeeded} succeeded, {failed} failed, {cancelled} cancelled");
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
                if spec.safety_snapshot && !matches!(op, PowerOp::Start { .. }) {
                    self.safety_snapshot(job_id, vmx).await?;
                }
                self.vmware.power(vmx, *op).await?;
                // The VM list shows the new state before the next refresh asks vmrun.
                self.store
                    .set_vm_power_state(&spec.ctx, vmx_path, state_after(*op))
                    .await?;
                Ok(TargetOutcome::done())
            }
            (Command::VmSnapshot { op, .. }, TargetRef::Vm { vmx_path }) => {
                let vmx = Path::new(vmx_path);
                if spec.safety_snapshot && !matches!(op, SnapshotOp::Take { .. }) {
                    self.safety_snapshot(job_id, vmx).await?;
                }
                self.vmware.snapshot(vmx, op).await?;
                Ok(TargetOutcome::done())
            }
            (Command::VmProtect { protected, .. }, TargetRef::Vm { vmx_path }) => {
                // AP-04: the app's own flag; the VM itself is not touched.
                if !self.store.set_vm_protected(&spec.ctx, vmx_path, *protected).await? {
                    return Err(CoreError::UnknownTarget(vmx_path.clone()));
                }
                Ok(TargetOutcome::done())
            }
            (Command::RemoteExec { script, sudo, .. }, TargetRef::Session { session_id }) => {
                let session = self
                    .store
                    .session_spec(&spec.ctx, *session_id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(session_id.to_string()))?;
                if *sudo {
                    return Err(CoreError::NotImplemented("BX-07 sudo with the vault password"));
                }
                let r = self.remote.exec(&session, script, None).await?;
                Ok(TargetOutcome {
                    ok: r.exit_code == Some(0),
                    exit_code: r.exit_code.map(i64::from),
                    output: Some(r.stdout),
                })
            }
            (Command::AppUpdate { version }, TargetRef::App) => {
                // FD-14: never update under a running job.
                self.wait_to_run_alone(job_id, token).await?;
                self.updater.install(version).await?;
                Ok(TargetOutcome::done())
            }
            (command, other) => Err(CoreError::WrongTargetKind {
                action: command.summary(1),
                target: format!("a {} target", other.kind()),
            }),
        }
    }

    /// VM-05: a named snapshot before the action, so it can be undone.
    async fn safety_snapshot(&self, job_id: Uuid, vmx: &Path) -> Result<()> {
        let name = format!(
            "safety-{}-{}",
            &job_id.simple().to_string()[..8],
            time::OffsetDateTime::now_utc().unix_timestamp()
        );
        self.vmware.snapshot(vmx, &SnapshotOp::Take { name }).await
    }

    fn parallelism(&self, command: &Command) -> usize {
        let n = match command {
            Command::VmPower {
                op: PowerOp::Start { .. },
                ..
            } => self.limits.power_on,
            Command::VmPower { .. } | Command::VmSnapshot { .. } | Command::VmProtect { .. } => self.limits.vm_ops,
            Command::RemoteExec { .. } => self.limits.remote,
            Command::AppUpdate { .. } => 1,
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

/// The power state a VM is in once `op` has succeeded.
fn state_after(op: PowerOp) -> PowerState {
    match op {
        PowerOp::Start { .. } | PowerOp::Reset { .. } | PowerOp::Unpause => PowerState::Running,
        PowerOp::Stop { .. } => PowerState::NotRunning,
        PowerOp::Suspend => PowerState::Suspended,
        PowerOp::Pause => PowerState::Paused,
    }
}
