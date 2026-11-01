//! MO-08: health checks with history and alerts (`Core.checks`).
//!
//! A check is a kind and a target ([`spec`]): ping, a TCP port, HTTP(S), a certificate's days left, a DNS name, or a
//! service over SSH, on a typed address, a saved session or a VM's guest IP, every 30 s to 1 h, with a timeout and how
//! many failed runs in a row make it **down** (2 by default). Runs use F1's probes ([`probe`], [`crate::toolbox`]):
//! from this PC, or through a session's jump host on a kept connection held until the next run, so a check every
//! minute logs in once and doesn't use up [`crate::login_guard`]'s hourly cap; the hold ends once no active check
//! needs it ([`crate::toolbox::Toolbox::release_holds`]).
//!
//! * **Reads.** A run changes nothing: no bus, no tier, not audited, allowed by the read-only lock. Each result (time,
//!   up, down or unknown, the time it took, a one-line detail, a certificate's days left) goes to
//!   `health_check_results`, kept for the dashboard history's retention and pruned with it (MO-06).
//! * **Edits.** Adding, changing, pausing and deleting a check are audited (`check_changed`, no tier) and refused by
//!   FD-03's read-only lock ([`Change::HealthChecks`]).
//! * **Workspaces (FD-02, rule 8).** Checks run for the workspace shown only, like MO-07's alerts: the runner reads
//!   [`Current`] at each tick, lets go of the old workspace's checks (runs in flight are cancelled and their results
//!   dropped) and loads the new one's.
//! * **Alerts (MO-07).** Each metrics round reads the checks' state ([`crate::alerts::CheckReadings`]): a check down,
//!   slow (its last time above a threshold) and a certificate expiring (days left below one), with built-in rules for
//!   down and under 14 days.
//!
//! The runner ticks every second on the wall clock ([`Checks::run`]); tests give a fake clock and call
//! [`Checks::run_due`], so nothing sleeps.

pub mod http;
pub mod probe;
pub mod service;
pub mod spec;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::net_tools::NetworkTools;
use crate::alerts::{AlertTarget, AlertTargetKind, CheckReadings, Reading};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::metrics::history::HistoryRange;
use crate::presentation::Change;
use crate::schedules::{Clock, SystemClock};
use crate::store::{NewAuditEntry, ResultBucket, Store};
use crate::toolbox::{ProbeTarget, Toolbox};
use crate::workspaces::Current;

pub use probe::Probed;
pub use service::{ServiceReader, ServiceRequest, ServiceState, SystemdOverSsh};
pub use spec::{CheckInput, CheckSpec, HealthCheck};

/// How often the runner looks for checks that are due.
const TICK: Duration = Duration::from_secs(1);

/// Checks running at once.
const AT_ONCE: usize = 8;

/// How much longer than its timeout a run may take (a jump host's login has its own limit) before it counts as
/// unknown.
const RUN_SLACK: Duration = Duration::from_secs(60);

/// Points in a sparkline.
const SPARK_POINTS: i64 = 48;

/// The most results a check's history sheet lists.
pub const MAX_HISTORY: u32 = 500;

/// One run's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RunResult {
    Up,
    /// The probe failed.
    Down,
    /// Remotely couldn't check (the vault is locked, a login is parked...).
    Unknown,
}

impl RunResult {
    pub fn as_str(self) -> &'static str {
        match self {
            RunResult::Up => "up",
            RunResult::Down => "down",
            RunResult::Unknown => "unknown",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "up" => Some(RunResult::Up),
            "down" => Some(RunResult::Down),
            "unknown" => Some(RunResult::Unknown),
            _ => None,
        }
    }
}

/// One run, as the history keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    /// Unix time in milliseconds (UTC).
    pub at: i64,
    pub result: RunResult,
    /// How long the probe took, when it got an answer.
    pub took_ms: Option<u64>,
    pub detail: String,
    /// A certificate check's days left (negative once expired).
    pub cert_days: Option<i64>,
}

/// Where a check stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckStatus {
    /// Not run yet since it was added, changed or resumed.
    Pending,
    Up,
    /// The last runs failed, fewer than it allows.
    Failing,
    Down,
    /// The last run couldn't check.
    Unknown,
    Paused,
}

/// The counts the status bar and the Checks tab show.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSummary {
    pub total: usize,
    pub up: usize,
    pub failing: usize,
    pub down: usize,
    pub unknown: usize,
    pub paused: usize,
    pub pending: usize,
}

/// What a check points at, by name, for lists. FD-03: `host` is a field the presentation masker learns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckTargetInfo {
    /// "address", "session" or "vm".
    pub kind: &'static str,
    /// The session's or VM's name, or the host typed.
    pub name: String,
    /// The host or address probed, when known.
    pub host: Option<String>,
    /// The session or VM is no longer in this workspace.
    pub missing: bool,
}

/// A sparkline's point: the runs in a bucket and their average time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SparkPoint {
    /// When the bucket starts (Unix ms).
    pub at: i64,
    pub ms: Option<f64>,
    pub up: u32,
    pub down: u32,
}

/// A check with where it stands, for the Checks tab and the widget.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRow {
    pub check: HealthCheck,
    pub target: CheckTargetInfo,
    pub status: CheckStatus,
    /// Failed runs in a row.
    pub failures: u32,
    pub last: Option<CheckResult>,
    /// Percent of the runs over the range that passed (unknown runs left out); none without runs.
    pub uptime: Option<f64>,
    pub spark: Vec<SparkPoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksOverview {
    pub rows: Vec<CheckRow>,
    pub summary: CheckSummary,
}

/// A check's history sheet.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckHistory {
    pub row: CheckRow,
    /// Newest first, at most [`MAX_HISTORY`].
    pub results: Vec<CheckResult>,
}

/// For the window: a run's result, or the list changed.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum CheckEvent {
    Result {
        check_id: Uuid,
        result: CheckResult,
        status: CheckStatus,
        failures: u32,
        summary: CheckSummary,
    },
    /// A check was added, changed, paused or deleted, or another workspace's checks run now.
    Changed { summary: CheckSummary },
}

/// What the checks need from the rest of the core.
pub struct ChecksParts {
    pub store: Store,
    pub current: Current,
    pub toolbox: Toolbox,
}

/// A check the runner follows.
#[derive(Debug, Clone)]
struct Live {
    check: HealthCheck,
    /// Changes when the check is edited, so a run of the old definition is dropped.
    rev: u64,
    target: CheckTargetInfo,
    next_due: i64,
    running: bool,
    failures: u32,
    status: CheckStatus,
    last: Option<CheckResult>,
    /// The session whose kept connection its last run used.
    held: Option<Uuid>,
}

#[derive(Default)]
struct Board {
    /// The workspace whose checks run.
    ctx: Option<Context>,
    cancel: CancellationToken,
    live: HashMap<Uuid, Live>,
    rev: u64,
}

struct Inner {
    store: Store,
    current: Current,
    toolbox: Toolbox,
    tools: Arc<dyn NetworkTools>,
    services: RwLock<Arc<dyn ServiceReader>>,
    board: Mutex<Board>,
    /// One load or reload at a time.
    loading: tokio::sync::Mutex<()>,
    clock: RwLock<Arc<dyn Clock>>,
    limit: Arc<Semaphore>,
    tx: broadcast::Sender<CheckEvent>,
    /// A failing tick is logged once, not every second.
    failing: Mutex<bool>,
}

/// MO-08's checks. Cloning gives another handle to the same service.
#[derive(Clone)]
pub struct Checks {
    inner: Arc<Inner>,
}

impl Checks {
    pub fn new(parts: ChecksParts) -> Self {
        let (tx, _) = broadcast::channel(256);
        let services: Arc<dyn ServiceReader> = Arc::new(SystemdOverSsh::new(parts.toolbox.clone()));
        Self {
            inner: Arc::new(Inner {
                store: parts.store,
                current: parts.current,
                tools: parts.toolbox.tools(),
                toolbox: parts.toolbox,
                services: RwLock::new(services),
                board: Mutex::new(Board::default()),
                loading: tokio::sync::Mutex::new(()),
                clock: RwLock::new(Arc::new(SystemClock)),
                limit: Arc::new(Semaphore::new(AT_ONCE)),
                tx,
                failing: Mutex::new(false),
            }),
        }
    }

    /// Tests: a clock of their own (a fake one moves only when told).
    pub fn set_clock(&self, clock: Arc<dyn Clock>) {
        *locks::write(&self.inner.clock) = clock;
    }

    /// F4: how service checks read a service (systemd over SSH by default; F4 adds Windows services over WinRM).
    pub fn set_service_reader(&self, reader: Arc<dyn ServiceReader>) {
        *locks::write(&self.inner.services) = reader;
    }

    fn now_ms(&self) -> i64 {
        let now = locks::read(&self.inner.clock).now();
        i64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
    }

    fn ctx(&self) -> Context {
        self.inner.current.get()
    }

    /// Results and changes, as they happen.
    pub fn subscribe(&self) -> broadcast::Receiver<CheckEvent> {
        self.inner.tx.subscribe()
    }

    // ---- Edits ----------------------------------------------------------------------------------------------------

    /// Adds a check. Audited; refused while presenting with the read-only lock.
    pub async fn create(&self, input: CheckInput) -> Result<HealthCheck> {
        self.create_in(self.ctx(), input).await
    }

    /// The same in `ctx`'s workspace (FD-07's import into a new workspace).
    pub(crate) async fn create_in(&self, ctx: Context, input: CheckInput) -> Result<HealthCheck> {
        self.inner.store.read_only().check(Change::HealthChecks)?;
        let input = spec::checked(input)?;
        let (label, targets) = self.check_target(&ctx, &input).await?;
        if self.inner.store.count_checks(&ctx).await? >= spec::MAX_CHECKS {
            return Err(CoreError::InvalidInput(format!(
                "A workspace holds at most {} checks: delete one first.",
                spec::MAX_CHECKS
            )));
        }
        let check = self.inner.store.insert_check(&ctx, &input).await?;
        self.audit(&ctx, "Added a health check", &spec::describe(&input, &label), &targets)
            .await?;
        self.reload(ctx).await?;
        Ok(check)
    }

    /// Changes a check: its runs start again from its next tick. Audited; refused while presenting.
    pub async fn update(&self, id: Uuid, input: CheckInput) -> Result<HealthCheck> {
        self.update_in(self.ctx(), id, input).await
    }

    /// The same in `ctx`'s workspace (FD-07).
    pub(crate) async fn update_in(&self, ctx: Context, id: Uuid, input: CheckInput) -> Result<HealthCheck> {
        self.inner.store.read_only().check(Change::HealthChecks)?;
        let old = self.get(&ctx, id).await?;
        let input = spec::checked(input)?;
        let (label, targets) = self.check_target(&ctx, &input).await?;
        let check = self
            .inner
            .store
            .update_check(&ctx, id, &input)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("check {id}")))?;
        let old_label = self.target_info(&ctx, &old.target).await.name;
        let detail = format!(
            "{} -> {}",
            spec::describe(&old.input(), &old_label),
            spec::describe(&input, &label)
        );
        self.audit(&ctx, "Changed a health check", &detail, &targets).await?;
        self.reload(ctx).await?;
        Ok(check)
    }

    /// Pauses a check (it doesn't run, and its alerts resolve) or resumes it. Audited; refused while presenting.
    pub async fn set_paused(&self, id: Uuid, paused: bool) -> Result<HealthCheck> {
        self.inner.store.read_only().check(Change::HealthChecks)?;
        let ctx = self.ctx();
        let old = self.get(&ctx, id).await?;
        if old.paused == paused {
            return Ok(old);
        }
        let mut input = old.input();
        input.paused = paused;
        let check = self
            .inner
            .store
            .update_check(&ctx, id, &input)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("check {id}")))?;
        let info = self.target_info(&ctx, &old.target).await;
        let action = if paused {
            "Paused a health check"
        } else {
            "Resumed a health check"
        };
        let detail = spec::describe(&input, &info.name);
        self.audit(&ctx, action, &detail, &audit_targets(&old.target, &info))
            .await?;
        self.reload(ctx).await?;
        Ok(check)
    }

    /// Deletes a check with its history. Its alerts stay in the alert list. Audited; refused while presenting.
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        self.inner.store.read_only().check(Change::HealthChecks)?;
        let ctx = self.ctx();
        let old = self.get(&ctx, id).await?;
        let info = self.target_info(&ctx, &old.target).await;
        self.inner.store.delete_check(&ctx, id).await?;
        self.audit(
            &ctx,
            "Deleted a health check",
            &spec::describe(&old.input(), &info.name),
            &audit_targets(&old.target, &info),
        )
        .await?;
        self.reload(ctx).await
    }

    /// The workspace's checks by name.
    pub async fn list(&self) -> Result<Vec<HealthCheck>> {
        self.inner.store.list_checks(&self.ctx()).await
    }

    async fn get(&self, ctx: &Context, id: Uuid) -> Result<HealthCheck> {
        self.inner
            .store
            .get_check(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("check {id}")))
    }

    /// The target is in this workspace and fits the kind; its name for the audit log, and the audit entry's target.
    async fn check_target(&self, ctx: &Context, input: &CheckInput) -> Result<(String, Vec<Target>)> {
        match &input.target {
            ProbeTarget::Address { host } => Ok((host.clone(), Vec::new())),
            ProbeTarget::Session { session_id } => {
                let session = self
                    .inner
                    .store
                    .get_session(ctx, *session_id)
                    .await?
                    .ok_or_else(|| CoreError::InvalidInput("Choose a saved session for the check.".into()))?;
                match &input.spec {
                    // SS-12: an SSH session only (the store refuses other kinds too); F4 adds WinRM sessions'
                    // Windows services.
                    CheckSpec::Service { .. } => {
                        if !session.kind.is_ssh() {
                            return Err(CoreError::WrongSessionKind {
                                session: session.name.clone(),
                                kind: session.kind.label(),
                                needs: "a service check reads a systemd unit over SSH".into(),
                            });
                        }
                        self.inner
                            .store
                            .session_spec(ctx, *session_id)
                            .await?
                            .ok_or_else(|| CoreError::InvalidInput("Choose a saved session for the check.".into()))?;
                    }
                    CheckSpec::Ping => {
                        let route = self.inner.toolbox.route(ctx, &input.target).await?;
                        crate::toolbox::icmp::refuse_jump(&route, "ping")?;
                    }
                    _ => {}
                }
                let target = Target {
                    target: TargetRef::Session { session_id: session.id },
                    name: session.name.clone(),
                    environment: session.environment,
                    protected: false,
                };
                Ok((session.name, vec![target]))
            }
            ProbeTarget::Vm { vm_key } => {
                self.inner.store.require_vm_here(ctx, vm_key).await?;
                let vm = self
                    .inner
                    .store
                    .find_vm(ctx, vm_key)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(vm_key.clone()))?;
                let target = Target {
                    target: TargetRef::Vm {
                        vmx_path: vm.vmx_path.clone(),
                    },
                    name: vm.display_name.clone(),
                    environment: vm.environment,
                    protected: false,
                };
                Ok((vm.display_name, vec![target]))
            }
        }
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: &str, targets: &[Target]) -> Result<()> {
        self.inner
            .store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "check_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets,
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }

    /// What a target is called now.
    async fn target_info(&self, ctx: &Context, target: &ProbeTarget) -> CheckTargetInfo {
        match target {
            ProbeTarget::Address { host } => CheckTargetInfo {
                kind: "address",
                name: host.clone(),
                host: Some(host.clone()),
                missing: false,
            },
            ProbeTarget::Session { session_id } => match self.inner.store.get_session(ctx, *session_id).await {
                Ok(Some(session)) => CheckTargetInfo {
                    kind: "session",
                    name: session.name,
                    host: Some(session.host),
                    missing: false,
                },
                _ => CheckTargetInfo {
                    kind: "session",
                    name: "a deleted session".into(),
                    host: None,
                    missing: true,
                },
            },
            ProbeTarget::Vm { vm_key } => {
                let here = self.inner.store.require_vm_here(ctx, vm_key).await.is_ok();
                match self.inner.store.find_vm(ctx, vm_key).await {
                    Ok(Some(vm)) if here => CheckTargetInfo {
                        kind: "vm",
                        name: vm.display_name,
                        host: vm.ip_address.filter(|ip| !ip.trim().is_empty()),
                        missing: false,
                    },
                    _ => CheckTargetInfo {
                        kind: "vm",
                        name: "a VM no longer here".into(),
                        host: None,
                        missing: true,
                    },
                }
            }
        }
    }

    // ---- The runner -------------------------------------------------------------------------------------------------

    /// Ticks every second until `stop`.
    pub async fn run(&self, stop: CancellationToken) {
        loop {
            let ticked = self.tick().await;
            {
                let mut failing = locks::lock(&self.inner.failing);
                match ticked {
                    Ok(_) => *failing = false,
                    Err(err) if !*failing => {
                        *failing = true;
                        tracing::warn!(error = %err, "health checks could not run; trying again each second");
                    }
                    Err(_) => {}
                }
            }
            tokio::select! {
                () = stop.cancelled() => {
                    self.leave().await;
                    return;
                }
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }

    /// Starts the runs that are due (without waiting for them). Follows the workspace shown first.
    pub async fn tick(&self) -> Result<Vec<JoinHandle<()>>> {
        let ctx = self.ctx();
        self.follow(ctx).await?;
        let now = self.now_ms();
        let due: Vec<(Uuid, HealthCheck, u64, CancellationToken)> = {
            let mut board = locks::lock(&self.inner.board);
            if board.ctx != Some(ctx) {
                return Ok(Vec::new());
            }
            let cancel = board.cancel.clone();
            let mut due = Vec::new();
            for live in board.live.values_mut() {
                if live.check.paused || live.running || live.next_due > now {
                    continue;
                }
                live.running = true;
                let every = i64::try_from(live.check.interval_secs)
                    .unwrap_or(60)
                    .saturating_mul(1000);
                live.next_due = now.saturating_add(every);
                due.push((live.check.id, live.check.clone(), live.rev, cancel.clone()));
            }
            due
        };
        let mut handles = Vec::with_capacity(due.len());
        for (id, check, rev, cancel) in due {
            let this = self.clone();
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = Arc::clone(&this.inner.limit).acquire_owned().await else {
                    return;
                };
                let prober = probe::Prober {
                    toolbox: this.inner.toolbox.clone(),
                    tools: Arc::clone(&this.inner.tools),
                    services: Arc::clone(&locks::read(&this.inner.services)),
                };
                let guard = Duration::from_secs(check.timeout_secs) + RUN_SLACK;
                let probed = tokio::select! {
                    probed = tokio::time::timeout(guard, prober.run(&ctx, &check)) => {
                        probed.unwrap_or_else(|_| Probed::unknown("the run took too long"))
                    }
                    () = cancel.cancelled() => return,
                };
                this.record(ctx, id, rev, now, probed).await;
            }));
        }
        Ok(handles)
    }

    /// "Run now": the check runs at the next tick (within a second), unless it is paused or running. A read: not
    /// audited, allowed by the read-only lock.
    pub async fn run_soon(&self, id: Uuid) -> Result<()> {
        let ctx = self.ctx();
        self.follow(ctx).await?;
        let now = self.now_ms();
        let mut board = locks::lock(&self.inner.board);
        let live = board
            .live
            .get_mut(&id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("check {id}")))?;
        if live.check.paused {
            return Err(CoreError::InvalidInput("Resume the check to run it.".into()));
        }
        live.next_due = live.next_due.min(now);
        Ok(())
    }

    /// Tests: runs every check that is due now and waits for them; how many ran.
    pub async fn run_due(&self) -> Result<usize> {
        let handles = self.tick().await?;
        let n = handles.len();
        for handle in handles {
            let _ = handle.await;
        }
        Ok(n)
    }

    /// FD-02: the checks stop following any workspace (another one is about to be shown, or the app closes): runs in
    /// flight are cancelled, the holds on kept connections end. The next tick loads the workspace shown.
    pub async fn leave(&self) {
        let _loading = self.inner.loading.lock().await;
        {
            let mut board = locks::lock(&self.inner.board);
            board.cancel.cancel();
            board.cancel = CancellationToken::new();
            board.ctx = None;
            board.live.clear();
        }
        self.inner.toolbox.release_holds(&HashSet::new()).await;
    }

    /// Loads `ctx`'s checks when the runner follows another workspace (or none yet).
    async fn follow(&self, ctx: Context) -> Result<()> {
        if locks::lock(&self.inner.board).ctx == Some(ctx) {
            return Ok(());
        }
        let _loading = self.inner.loading.lock().await;
        if locks::lock(&self.inner.board).ctx == Some(ctx) {
            return Ok(());
        }
        let now = self.now_ms();
        let checks = self.inner.store.list_checks(&ctx).await?;
        let mut live = HashMap::with_capacity(checks.len());
        let mut rev = locks::lock(&self.inner.board).rev;
        for (i, check) in checks.into_iter().enumerate() {
            rev += 1;
            let restored = self.restored(&ctx, check, rev, now, i).await?;
            live.insert(restored.check.id, restored);
        }
        {
            let mut board = locks::lock(&self.inner.board);
            board.cancel.cancel();
            board.cancel = CancellationToken::new();
            board.ctx = Some(ctx);
            board.live = live;
            board.rev = rev;
        }
        self.inner.toolbox.release_holds(&HashSet::new()).await;
        self.changed();
        Ok(())
    }

    /// A check as it stood when Remotely last ran it: its last result and failed runs in a row, from the history.
    /// Its first run here is due when its next one would have been, or spread over the first seconds.
    async fn restored(&self, ctx: &Context, check: HealthCheck, rev: u64, now: i64, index: usize) -> Result<Live> {
        let target = self.target_info(ctx, &check.target).await;
        let recent = self
            .inner
            .store
            .check_results(ctx, check.id, 0, check.failures_before_down.max(1))
            .await?;
        let last = recent.first().cloned();
        let failures = u32::try_from(recent.iter().take_while(|r| r.result == RunResult::Down).count()).unwrap_or(0);
        let status = match (&last, check.paused) {
            (_, true) => CheckStatus::Paused,
            (None, false) => CheckStatus::Pending,
            (Some(last), false) => {
                status_after(last.result, failures, check.failures_before_down, CheckStatus::Pending)
            }
        };
        let every = i64::try_from(check.interval_secs).unwrap_or(60).saturating_mul(1000);
        let spread = i64::try_from(index).unwrap_or(0).saturating_mul(997) % every.clamp(1, 15_000);
        let next_due = match &last {
            Some(last) if last.at.saturating_add(every) > now => last.at.saturating_add(every),
            Some(_) => now.saturating_add(spread),
            // Never run: at once.
            None => now,
        };
        Ok(Live {
            check,
            rev,
            target,
            next_due,
            running: false,
            failures,
            status,
            last,
            held: None,
        })
    }

    /// Reads the checks again after an edit: a check whose target, kind, timing or pause changed starts over (it runs
    /// at the next tick); a renamed one keeps its state. Then the holds no active check needs end.
    async fn reload(&self, ctx: Context) -> Result<()> {
        let _loading = self.inner.loading.lock().await;
        if locks::lock(&self.inner.board).ctx != Some(ctx) {
            return Ok(());
        }
        let now = self.now_ms();
        let checks = self.inner.store.list_checks(&ctx).await?;
        let mut targets = HashMap::with_capacity(checks.len());
        for check in &checks {
            targets.insert(check.id, self.target_info(&ctx, &check.target).await);
        }
        let keep = {
            let mut board = locks::lock(&self.inner.board);
            if board.ctx != Some(ctx) {
                return Ok(());
            }
            let mut old = std::mem::take(&mut board.live);
            let mut rev = board.rev;
            for check in checks {
                let target = targets.remove(&check.id).unwrap_or_else(|| CheckTargetInfo {
                    kind: "address",
                    name: String::new(),
                    host: None,
                    missing: true,
                });
                let live = match old.remove(&check.id) {
                    Some(mut live) if same_runs(&live.check, &check) => {
                        live.check = check;
                        live.target = target;
                        live
                    }
                    _ => {
                        rev += 1;
                        Live {
                            status: if check.paused {
                                CheckStatus::Paused
                            } else {
                                CheckStatus::Pending
                            },
                            check,
                            rev,
                            target,
                            next_due: now,
                            running: false,
                            failures: 0,
                            last: None,
                            held: None,
                        }
                    }
                };
                board.live.insert(live.check.id, live);
            }
            board.rev = rev;
            held_sessions(&board)
        };
        self.inner.toolbox.release_holds(&keep).await;
        self.changed();
        Ok(())
    }

    /// Keeps a run's result and moves the check's status on, unless the check changed, went or the workspace switched
    /// while it ran.
    async fn record(&self, ctx: Context, id: Uuid, rev: u64, at: i64, probed: Probed) {
        let current = {
            let board = locks::lock(&self.inner.board);
            board.ctx == Some(ctx) && board.live.get(&id).is_some_and(|l| l.rev == rev)
        };
        if !current {
            return;
        }
        let result = CheckResult {
            at,
            result: probed.result,
            took_ms: probed.took_ms,
            detail: probed.detail,
            cert_days: probed.cert_days,
        };
        if let Err(err) = self.inner.store.insert_check_result(&ctx, id, &result).await {
            tracing::warn!(error = %err, "could not keep a health check's result");
        }
        let event = {
            let mut board = locks::lock(&self.inner.board);
            let Some(live) = board.live.get_mut(&id).filter(|l| l.rev == rev) else {
                return;
            };
            live.running = false;
            live.failures = match result.result {
                RunResult::Up => 0,
                RunResult::Down => live.failures.saturating_add(1),
                RunResult::Unknown => live.failures,
            };
            live.status = status_after(
                result.result,
                live.failures,
                live.check.failures_before_down,
                live.status,
            );
            live.held = probed.held;
            live.last = Some(result.clone());
            let (status, failures) = (live.status, live.failures);
            CheckEvent::Result {
                check_id: id,
                result,
                status,
                failures,
                summary: summarize(&board),
            }
        };
        let _ = self.inner.tx.send(event);
    }

    fn changed(&self) {
        let summary = summarize(&locks::lock(&self.inner.board));
        let _ = self.inner.tx.send(CheckEvent::Changed { summary });
    }

    // ---- Reads -----------------------------------------------------------------------------------------------------

    /// The counts for the status bar: the shown workspace's checks as they stand.
    pub fn summary(&self) -> CheckSummary {
        let board = locks::lock(&self.inner.board);
        if board.ctx != Some(self.ctx()) {
            return CheckSummary::default();
        }
        summarize(&board)
    }

    /// The Checks tab: every check with its status, last result, uptime and a sparkline of its time over `range`.
    pub async fn overview(&self, range: HistoryRange) -> Result<ChecksOverview> {
        let ctx = self.ctx();
        self.follow(ctx).await?;
        let lives: Vec<Live> = {
            let board = locks::lock(&self.inner.board);
            let mut lives: Vec<Live> = board.live.values().cloned().collect();
            lives.sort_by(|a, b| {
                a.check
                    .name
                    .to_lowercase()
                    .cmp(&b.check.name.to_lowercase())
                    .then(a.check.created_at.cmp(&b.check.created_at))
            });
            lives
        };
        let mut rows = Vec::with_capacity(lives.len());
        for live in &lives {
            rows.push(self.row(&ctx, live, range).await?);
        }
        Ok(ChecksOverview {
            rows,
            summary: self.summary(),
        })
    }

    /// A check's history sheet: its row and its results over `range`, newest first.
    pub async fn history(&self, id: Uuid, range: HistoryRange) -> Result<CheckHistory> {
        let ctx = self.ctx();
        self.follow(ctx).await?;
        let live = locks::lock(&self.inner.board).live.get(&id).cloned();
        let live = match live {
            Some(live) => live,
            None => {
                let check = self.get(&ctx, id).await?;
                self.restored(&ctx, check, 0, self.now_ms(), 0).await?
            }
        };
        let row = self.row(&ctx, &live, range).await?;
        let since = self
            .now_ms()
            .saturating_sub(range.span_minutes().saturating_mul(60_000));
        let results = self.inner.store.check_results(&ctx, id, since, MAX_HISTORY).await?;
        Ok(CheckHistory { row, results })
    }

    async fn row(&self, ctx: &Context, live: &Live, range: HistoryRange) -> Result<CheckRow> {
        let span = range.span_minutes().saturating_mul(60_000);
        let bucket = (span / SPARK_POINTS).max(1);
        let now = self.now_ms();
        let since = (now.saturating_sub(span) / bucket) * bucket;
        let buckets = self
            .inner
            .store
            .check_buckets(ctx, live.check.id, since, bucket)
            .await?;
        Ok(CheckRow {
            check: live.check.clone(),
            target: live.target.clone(),
            status: live.status,
            failures: live.failures,
            last: live.last.clone(),
            uptime: uptime(&buckets),
            spark: buckets
                .iter()
                .map(|b| SparkPoint {
                    at: b.start,
                    ms: b.avg_ms,
                    up: b.up,
                    down: b.down,
                })
                .collect(),
        })
    }
}

/// The same runs: only the name differs.
fn same_runs(a: &HealthCheck, b: &HealthCheck) -> bool {
    a.target == b.target
        && a.spec == b.spec
        && a.interval_secs == b.interval_secs
        && a.timeout_secs == b.timeout_secs
        && a.failures_before_down == b.failures_before_down
        && a.paused == b.paused
}

/// A run's result moves the status on: up, failing until it failed `allowed` runs in a row, then down. A run that
/// couldn't check says so.
fn status_after(result: RunResult, failures: u32, allowed: u32, _before: CheckStatus) -> CheckStatus {
    match result {
        RunResult::Up => CheckStatus::Up,
        RunResult::Down if failures >= allowed => CheckStatus::Down,
        RunResult::Down => CheckStatus::Failing,
        RunResult::Unknown => CheckStatus::Unknown,
    }
}

fn summarize(board: &Board) -> CheckSummary {
    let mut summary = CheckSummary {
        total: board.live.len(),
        ..CheckSummary::default()
    };
    for live in board.live.values() {
        match live.status {
            CheckStatus::Up => summary.up += 1,
            CheckStatus::Failing => summary.failing += 1,
            CheckStatus::Down => summary.down += 1,
            CheckStatus::Unknown => summary.unknown += 1,
            CheckStatus::Paused => summary.paused += 1,
            CheckStatus::Pending => summary.pending += 1,
        }
    }
    summary
}

/// The sessions whose kept connections active checks still hold (those that run often enough to hold one).
fn held_sessions(board: &Board) -> HashSet<Uuid> {
    board
        .live
        .values()
        .filter(|l| !l.check.paused && probe::hold_for(l.check.interval_secs).is_some())
        .filter_map(|l| l.held)
        .collect()
}

/// Percent of runs that passed, leaving out those Remotely couldn't check.
fn uptime(buckets: &[ResultBucket]) -> Option<f64> {
    let (up, down) = buckets
        .iter()
        .fold((0u64, 0u64), |(u, d), b| (u + u64::from(b.up), d + u64::from(b.down)));
    #[allow(clippy::cast_precision_loss)]
    (up + down > 0).then(|| up as f64 * 100.0 / (up + down) as f64)
}

fn audit_targets(target: &ProbeTarget, info: &CheckTargetInfo) -> Vec<Target> {
    let target = match target {
        ProbeTarget::Session { session_id } if !info.missing => TargetRef::Session {
            session_id: *session_id,
        },
        ProbeTarget::Vm { vm_key } if !info.missing => TargetRef::Vm {
            vmx_path: vm_key.clone(),
        },
        _ => return Vec::new(),
    };
    vec![Target {
        target,
        name: info.name.clone(),
        environment: crate::domain::Environment::default(),
        protected: false,
    }]
}

impl CheckReadings for Checks {
    fn check_readings(&self, ctx: &Context) -> Vec<Reading> {
        let board = locks::lock(&self.inner.board);
        if board.ctx != Some(*ctx) {
            return Vec::new();
        }
        board
            .live
            .values()
            .filter(|l| !l.check.paused)
            .map(|live| {
                let last = live.last.as_ref();
                Reading {
                    target: AlertTarget {
                        kind: AlertTargetKind::Check,
                        key: live.check.id.to_string(),
                        name: live.check.name.clone(),
                    },
                    check_down: match live.status {
                        CheckStatus::Up | CheckStatus::Failing => Some(false),
                        CheckStatus::Down => Some(true),
                        CheckStatus::Pending | CheckStatus::Unknown | CheckStatus::Paused => None,
                    },
                    check_ms: last
                        .filter(|r| r.result == RunResult::Up)
                        .and_then(|r| r.took_ms)
                        .map(|ms| ms as f64),
                    cert_days: last.and_then(|r| r.cert_days).map(|d| d as f64),
                    check_detail: last.map(|r| r.detail.clone()),
                    ..Reading::default()
                }
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn failed_runs_make_a_check_failing_then_down() {
        assert_eq!(status_after(RunResult::Up, 0, 2, CheckStatus::Down), CheckStatus::Up);
        assert_eq!(
            status_after(RunResult::Down, 1, 2, CheckStatus::Up),
            CheckStatus::Failing
        );
        assert_eq!(
            status_after(RunResult::Down, 2, 2, CheckStatus::Failing),
            CheckStatus::Down
        );
        assert_eq!(status_after(RunResult::Down, 1, 1, CheckStatus::Up), CheckStatus::Down);
        assert_eq!(
            status_after(RunResult::Unknown, 5, 2, CheckStatus::Down),
            CheckStatus::Unknown
        );
    }

    #[test]
    fn uptime_leaves_out_what_remotely_couldnt_check() {
        let bucket = |up, down, unknown| ResultBucket {
            start: 0,
            up,
            down,
            unknown,
            avg_ms: None,
        };
        assert_eq!(uptime(&[]), None);
        assert_eq!(uptime(&[bucket(0, 0, 9)]), None);
        assert_eq!(uptime(&[bucket(3, 1, 5), bucket(4, 0, 0)]), Some(87.5));
    }

    #[test]
    fn results_and_statuses_read_back() {
        for r in [RunResult::Up, RunResult::Down, RunResult::Unknown] {
            assert_eq!(RunResult::parse(r.as_str()), Some(r));
        }
        assert_eq!(RunResult::parse("maybe"), None);
    }
}
