//! VM-14, VM-27: one scheduler for snapshot schedules (take a snapshot, keep the last N), scheduled power (start,
//! shut down, suspend, resume at set times on set days) and auto-suspend of idle VMs (docs/plan-0.5.md, R7).
//!
//! * A schedule has an action, targets (VMs or tags; stacks once R6 adds them) and times (hourly, daily, weekly in
//!   local time, [`timing`]), or "when idle" for auto-suspend ([`idle`]). Rows carry the workspace and the user.
//! * Saving asks for its approval with the same steps as running it then (AP-06 included); retention's snapshot
//!   deletes (High) are part of what is asked. The command bus records the answer as a standing approval bound to
//!   the schedule's content and the rules that rated it ([`crate::command_bus::StandingGrant`]). Each run submits
//!   its commands to the bus under it, and is audited as that approval's run.
//! * A schedule that was edited, whose target became Prod or protected or is new (a VM got the tag), or whose rules
//!   changed, waits to be approved again instead of running (the scheduler checks before each run and every tick;
//!   the bus refuses anything else). The UI shows why.
//! * A run due while the PC slept or was off, or Remotely was closed, is reported once as missed and never caught
//!   up. While the read-only lock is on nothing runs (each due run is reported as skipped). Runs never overlap: a
//!   run due while the last one still goes is skipped and reported.
//! * VM-27 retention deletes only the snapshots its own schedule took, recorded by the hypervisor's id when they
//!   were taken, while the id and the recognisable name still match. Chain warnings ([`chains`]) show on the VM and
//!   in the schedule list.
//!
//! The scheduler ticks on the wall clock ([`Schedules::run`]); tests give a fake clock and call
//! [`Schedules::tick`] instead, so nothing sleeps.

pub mod chains;
pub mod clock;
pub mod idle;
pub mod spec;
pub mod timing;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration as StdDuration, Instant};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vmware::path_key;
use crate::command_bus::{
    ApprovalAnswers, ApprovalRequest, Command, CommandBus, SnapshotOp, StandingAsk, StandingDetails, StandingDraft,
    StandingGrant, StandingRun,
};
use crate::domain::{Context, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::inventory::Inventory;
use crate::jobs::{JobRunner, JobStatus, TargetStatus};
use crate::locks;
use crate::metrics::Metrics;
use crate::policy::Tier;
use crate::presentation::Change;
use crate::snapshots::tree_nodes;
use crate::store::{NewAuditEntry, RunRow, ScheduleRow, SnapshotEnd, Store, TakenSnapshot, VmRecord};

pub use chains::{ChainInfo, ChainLimits, CHAIN_LIMITS_KEY};
pub use clock::{Clock, SystemClock};
pub use spec::{
    clean_schedule_name, snapshot_name, ScheduleAction, ScheduleSpec, ScheduleTarget, MAX_KEEP, MAX_NAME, MAX_TARGETS,
    SNAPSHOT_PREFIX,
};
pub use timing::{Day, Timing, WallTime};

/// How often the scheduler looks at the clock.
pub const TICK: StdDuration = StdDuration::from_secs(15);
/// A run this late is reported as missed (the PC slept or was off, Remotely was closed) and not caught up.
pub const LATE_GRACE: Duration = Duration::minutes(2);
/// VM-14: how often auto-suspend looks for idle VMs.
pub const IDLE_EVERY: Duration = Duration::minutes(1);
/// How long a VM's chain reading is reused.
const CHAIN_FRESH: StdDuration = StdDuration::from_secs(60);
/// The most missed runs one report counts.
const MISSED_CAP: usize = 10_000;

/// Where a schedule stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScheduleState {
    /// Runs when due, under its approval.
    Active,
    /// Paused by the user; keeps its approval.
    Paused,
    /// New, edited, or something changed since it was approved: it runs again once approved.
    NeedsApproval,
}

impl ScheduleState {
    pub fn as_str(self) -> &'static str {
        match self {
            ScheduleState::Active => "active",
            ScheduleState::Paused => "paused",
            ScheduleState::NeedsApproval => "needsApproval",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "active" => Some(ScheduleState::Active),
            "paused" => Some(ScheduleState::Paused),
            "needsApproval" => Some(ScheduleState::NeedsApproval),
            _ => None,
        }
    }
}

/// How a run went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RunOutcome {
    Running,
    Succeeded,
    PartiallyFailed,
    Failed,
    /// Due while Remotely was closed or the PC asleep or off: reported, not caught up.
    Missed,
    /// Due while the read-only lock was on, or while the last run still went.
    Skipped,
    /// Something changed since the approval: the schedule waits to be approved again.
    Paused,
}

impl RunOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            RunOutcome::Running => "running",
            RunOutcome::Succeeded => "succeeded",
            RunOutcome::PartiallyFailed => "partiallyFailed",
            RunOutcome::Failed => "failed",
            RunOutcome::Missed => "missed",
            RunOutcome::Skipped => "skipped",
            RunOutcome::Paused => "paused",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            RunOutcome::Running,
            RunOutcome::Succeeded,
            RunOutcome::PartiallyFailed,
            RunOutcome::Failed,
            RunOutcome::Missed,
            RunOutcome::Skipped,
            RunOutcome::Paused,
        ]
        .into_iter()
        .find(|o| o.as_str() == text)
    }
}

/// A planned run, for the list: when (RFC 3339, UTC), and what daylight saving does to it that day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedRun {
    pub at: String,
    pub note: Option<String>,
}

/// One run, for the run history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleRun {
    pub id: Uuid,
    pub due_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub outcome: RunOutcome,
    pub detail: Option<String>,
    pub job_ids: Vec<Uuid>,
    pub approval_id: Option<Uuid>,
}

impl From<RunRow> for ScheduleRun {
    fn from(row: RunRow) -> Self {
        Self {
            id: row.id,
            due_at: row.due_at,
            started_at: row.started_at,
            finished_at: row.finished_at,
            outcome: row.outcome,
            detail: row.detail,
            job_ids: row.job_ids,
            approval_id: row.approval_id,
        }
    }
}

/// A target as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetView {
    pub target: ScheduleTarget,
    /// The VM's name, or the tag.
    pub name: String,
    /// The VMs it stands for now.
    pub vms: usize,
}

/// The approval a schedule runs under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalInfo {
    pub id: Uuid,
    pub tier: Tier,
    pub granted_at: String,
    pub reason: Option<String>,
    pub safety_snapshot: bool,
}

/// A schedule as the Schedules page and a VM's Schedules tab show it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleView {
    pub id: Uuid,
    pub name: String,
    pub spec: ScheduleSpec,
    /// "Take a snapshot, keep the last 7".
    pub action: String,
    /// "Daily at 02:00".
    pub when: String,
    pub targets: Vec<TargetView>,
    pub state: ScheduleState,
    pub state_reason: Option<String>,
    pub next_run: Option<PlannedRun>,
    pub last_run: Option<ScheduleRun>,
    pub approval: Option<ApprovalInfo>,
    /// What would make its next run ask again (it pauses as soon as the scheduler sees it).
    pub asks_again: Vec<String>,
    /// VM-27: chains of its VMs that are deeper or larger than the limits.
    pub chain_warnings: Vec<String>,
    /// A run is going now.
    pub running: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// What the editor saves.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleInput {
    /// `None` for a new schedule.
    pub id: Option<Uuid>,
    pub name: String,
    pub spec: ScheduleSpec,
}

/// A save, a resume or an approval asked again: the schedule, and the approval to answer if one is needed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveOutcome {
    pub schedule: ScheduleView,
    pub approval: Option<ApprovalRequest>,
}

/// What a schedule would do, before it is saved (the editor's preview).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulePreview {
    pub summary: String,
    pub when: String,
    pub next_runs: Vec<PlannedRun>,
    /// The VMs it would act on now.
    pub vms: Vec<String>,
    pub warnings: Vec<String>,
}

/// A VM's Schedules tab.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSchedules {
    pub schedules: Vec<ScheduleView>,
    pub chain: Option<ChainInfo>,
    pub limits: ChainLimits,
}

/// For the UI (and the notification centre, QL-25): what the scheduler did.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ScheduleEvent {
    /// Saved, edited, approved, paused, resumed or deleted.
    Changed { schedule_id: Uuid },
    RunStarted {
        schedule_id: Uuid,
        run_id: Uuid,
        name: String,
    },
    RunFinished {
        schedule_id: Uuid,
        run_id: Uuid,
        name: String,
        outcome: RunOutcome,
        detail: Option<String>,
    },
    /// Runs due while the PC slept or Remotely was closed; not caught up.
    Missed {
        schedule_id: Uuid,
        run_id: Uuid,
        name: String,
        detail: String,
    },
    /// A run not started: the read-only lock, or the last run still going.
    Skipped {
        schedule_id: Uuid,
        run_id: Uuid,
        name: String,
        detail: String,
    },
    /// Something changed since the approval: it waits to be approved again.
    NeedsApproval {
        schedule_id: Uuid,
        name: String,
        reason: String,
    },
}

/// What one tick did (tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickReport {
    pub started: usize,
    pub missed: usize,
    pub skipped: usize,
    pub paused: usize,
}

/// A schedule's targets looked up now.
#[derive(Debug, Default)]
struct Resolved {
    /// Each VM once, in the schedule's order.
    vms: Vec<VmRecord>,
    /// The tag that brought each VM (lower-case key).
    via_tag: HashMap<String, String>,
    /// "tag 'lab': web01, web02".
    shown: Vec<String>,
    /// Targets not found.
    missing: Vec<String>,
    views: Vec<TargetView>,
}

impl Resolved {
    fn refs(&self) -> Vec<TargetRef> {
        self.vms
            .iter()
            .map(|vm| TargetRef::Vm {
                vmx_path: vm.vmx_path.clone(),
            })
            .collect()
    }

    fn targets(&self) -> Vec<Target> {
        self.vms.iter().map(target_of).collect()
    }
}

fn target_of(vm: &VmRecord) -> Target {
    Target {
        target: TargetRef::Vm {
            vmx_path: vm.vmx_path.clone(),
        },
        name: vm.display_name.clone(),
        environment: vm.environment,
        protected: vm.protected,
    }
}

fn vm_key(key: &str) -> String {
    path_key(std::path::Path::new(key))
}

/// RFC 3339, UTC, whole seconds.
fn stamp(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

fn parse_stamp(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// "Sun 25 Oct 02:00", local time.
fn local_text(at: OffsetDateTime, clock: &dyn Clock) -> String {
    let local = at.to_offset(clock.offset_at(at));
    let day = match local.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][usize::from(u8::from(local.month()) - 1)];
    format!(
        "{day} {} {month} {:02}:{:02}",
        local.day(),
        local.hour(),
        local.minute()
    )
}

fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// How a run ended, and what it says.
struct RunResult {
    outcome: RunOutcome,
    detail: String,
}

impl RunResult {
    fn new(outcome: RunOutcome, detail: impl Into<String>) -> Self {
        Self {
            outcome,
            detail: detail.into(),
        }
    }
}

/// Why a run's command did not start.
enum Stop {
    /// Changes since the approval: the schedule waits for it again.
    Paused(String),
    Skipped(String),
    Failed(String),
}

impl Stop {
    fn result(self, before: &[String]) -> RunResult {
        let (outcome, why) = match self {
            Stop::Paused(why) => (
                RunOutcome::Paused,
                format!("{why} since it was approved: it waits to be approved again"),
            ),
            Stop::Skipped(why) => (RunOutcome::Skipped, why),
            Stop::Failed(why) => (RunOutcome::Failed, why),
        };
        let mut parts = before.to_vec();
        parts.push(why);
        RunResult::new(outcome, parts.join("; "))
    }
}

/// VM-14: a VM auto-suspend found idle.
#[derive(Debug, Clone)]
struct IdleVm {
    key: String,
    name: String,
    avg_pct: f64,
}

/// How a run started: at its time, or for idle VMs.
enum RunKind {
    Timed { note: Option<String> },
    Idle(Vec<IdleVm>),
}

struct Inner {
    ctx: Context,
    store: Store,
    bus: Arc<CommandBus>,
    jobs: Arc<JobRunner>,
    hypervisors: Hypervisors,
    inventory: Arc<Inventory>,
    metrics: Arc<Metrics>,
    clock: RwLock<Arc<dyn Clock>>,
    /// Schedules with a run going, and that run.
    running: Mutex<HashMap<Uuid, Uuid>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    events: broadcast::Sender<ScheduleEvent>,
    /// VM-14: VMs auto-suspend failed on, and when to try again.
    idle_backoff: Mutex<HashMap<String, OffsetDateTime>>,
    last_idle_check: Mutex<Option<OffsetDateTime>>,
    chains: Mutex<HashMap<String, (Instant, ChainInfo)>>,
    /// Runs the app was in when it last stopped are marked once, at the first tick.
    recovered: AtomicBool,
    /// One tick at a time.
    ticking: tokio::sync::Mutex<()>,
}

/// VM-14, VM-27: schedules and the scheduler (`Core.schedules`).
#[derive(Clone)]
pub struct Schedules {
    inner: Arc<Inner>,
}

/// What [`Schedules::new`] needs.
pub struct ScheduleParts {
    pub ctx: Context,
    pub store: Store,
    pub bus: Arc<CommandBus>,
    pub jobs: Arc<JobRunner>,
    pub hypervisors: Hypervisors,
    pub inventory: Arc<Inventory>,
    pub metrics: Arc<Metrics>,
}

impl Schedules {
    pub fn new(parts: ScheduleParts) -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Inner {
                ctx: parts.ctx,
                store: parts.store,
                bus: parts.bus,
                jobs: parts.jobs,
                hypervisors: parts.hypervisors,
                inventory: parts.inventory,
                metrics: parts.metrics,
                clock: RwLock::new(Arc::new(SystemClock)),
                running: Mutex::new(HashMap::new()),
                tasks: Mutex::new(Vec::new()),
                events,
                idle_backoff: Mutex::new(HashMap::new()),
                last_idle_check: Mutex::new(None),
                chains: Mutex::new(HashMap::new()),
                recovered: AtomicBool::new(false),
                ticking: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Tests: a clock of their own (a fake one moves only when told).
    pub fn set_clock(&self, clock: Arc<dyn Clock>) {
        *locks::write(&self.inner.clock) = clock;
    }

    fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&locks::read(&self.inner.clock))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ScheduleEvent> {
        self.inner.events.subscribe()
    }

    fn emit(&self, event: ScheduleEvent) {
        let _ = self.inner.events.send(event);
    }

    fn ctx(&self) -> &Context {
        &self.inner.ctx
    }

    fn store(&self) -> &Store {
        &self.inner.store
    }

    async fn audit(
        &self,
        event: &str,
        action: &str,
        targets: &[Target],
        result: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        self.store()
            .append_audit(
                self.ctx(),
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets,
                    approval: None,
                    result,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }

    /// A failing audit write is logged; the scheduler goes on (QL-15).
    async fn audit_logged(&self, event: &str, action: &str, targets: &[Target], result: Option<&str>, detail: &str) {
        if let Err(err) = self.audit(event, action, targets, result, detail).await {
            tracing::error!(error = %err, event, "could not audit a schedule event");
        }
    }

    // ---- reads ----

    /// Every schedule, by name.
    pub async fn list(&self) -> Result<Vec<ScheduleView>> {
        let mut out = Vec::new();
        for row in self.store().list_schedules(self.ctx()).await? {
            out.push(self.view(row).await?);
        }
        Ok(out)
    }

    pub async fn get(&self, id: Uuid) -> Result<ScheduleView> {
        let row = self.row(id).await?;
        self.view(row).await
    }

    async fn row(&self, id: Uuid) -> Result<ScheduleRow> {
        self.store()
            .schedule(self.ctx(), id)
            .await?
            .ok_or_else(|| CoreError::InvalidInput("That schedule doesn't exist any more.".into()))
    }

    /// A schedule's runs, newest first.
    pub async fn runs(&self, id: Uuid, limit: usize) -> Result<Vec<ScheduleRun>> {
        let limit = i64::try_from(limit.clamp(1, 500)).unwrap_or(50);
        Ok(self
            .store()
            .schedule_runs(self.ctx(), id, limit)
            .await?
            .into_iter()
            .map(ScheduleRun::from)
            .collect())
    }

    /// VM-14, VM-27: the schedules that act on a VM now (directly or by a tag), and its snapshot chain.
    pub async fn for_vm(&self, key: &str) -> Result<VmSchedules> {
        let wanted = vm_key(key);
        let limits = self.chain_limits().await?;
        let mut schedules = Vec::new();
        for row in self.store().list_schedules(self.ctx()).await? {
            let resolved = self.resolve(&row.spec).await?;
            let direct = row
                .spec
                .targets
                .iter()
                .any(|t| matches!(t, ScheduleTarget::Vm { vm_key: k } if vm_key(k) == wanted));
            if direct || resolved.vms.iter().any(|vm| vm_key(&vm.vmx_path) == wanted) {
                schedules.push(self.view(row).await?);
            }
        }
        let vm = self.store().find_vm(self.ctx(), key).await?;
        let chain = match vm {
            Some(vm) => Some(self.chain(&vm, limits, true).await),
            None => None,
        };
        Ok(VmSchedules {
            schedules,
            chain,
            limits,
        })
    }

    async fn view(&self, row: ScheduleRow) -> Result<ScheduleView> {
        let resolved = self.resolve(&row.spec).await?;
        let last_run = self
            .store()
            .schedule_runs(self.ctx(), row.id, 1)
            .await?
            .into_iter()
            .next()
            .map(ScheduleRun::from);
        let grant = match row.approval_id {
            Some(id) => self.inner.bus.standing_grant(self.ctx(), id).await?,
            None => None,
        };
        let asks_again = if row.state == ScheduleState::Active {
            self.changes(&row, &resolved).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut chain_warnings = Vec::new();
        if let ScheduleAction::Snapshot { .. } = row.spec.action {
            let limits = self.chain_limits().await?;
            for vm in &resolved.vms {
                chain_warnings.extend(self.chain(vm, limits, false).await.warnings);
            }
        }
        let next_run = match row.state {
            ScheduleState::Active => row.next_run_at.clone().map(|at| PlannedRun {
                at,
                note: row.next_note.clone(),
            }),
            _ => None,
        };
        Ok(ScheduleView {
            id: row.id,
            name: row.name.clone(),
            action: row.spec.action.label(),
            when: row.spec.timing.describe(),
            targets: resolved.views,
            state: row.state,
            state_reason: row.state_reason.clone(),
            next_run,
            last_run,
            approval: grant.map(|g| ApprovalInfo {
                id: g.id,
                tier: g.tier,
                granted_at: g.granted_at,
                reason: g.record.reason,
                safety_snapshot: g.record.safety_snapshot,
            }),
            asks_again,
            chain_warnings,
            running: locks::lock(&self.inner.running).contains_key(&row.id),
            created_at: row.created_at,
            updated_at: row.updated_at,
            spec: row.spec,
        })
    }

    /// The schedule's VMs now: each VM target that is in the list, and each VM with each tag.
    async fn resolve(&self, spec: &ScheduleSpec) -> Result<Resolved> {
        let all = self.store().list_vms(self.ctx()).await?;
        let mut resolved = Resolved::default();
        let mut seen = HashSet::new();
        for target in &spec.targets {
            match target {
                ScheduleTarget::Vm { vm_key: key } => match all.iter().find(|vm| vm_key(&vm.vmx_path) == vm_key(key)) {
                    Some(vm) => {
                        resolved.views.push(TargetView {
                            target: target.clone(),
                            name: vm.display_name.clone(),
                            vms: 1,
                        });
                        resolved.shown.push(vm.display_name.clone());
                        if seen.insert(vm_key(&vm.vmx_path)) {
                            resolved.vms.push(vm.clone());
                        }
                    }
                    None => {
                        let name = match Hypervisor::of_key(key) {
                            Hypervisor::Vmware => std::path::Path::new(key)
                                .file_stem()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| key.clone()),
                            Hypervisor::VirtualBox => format!("VirtualBox VM {key}"),
                        };
                        resolved.missing.push(format!("{name} is not in the VM list"));
                        resolved.views.push(TargetView {
                            target: target.clone(),
                            name,
                            vms: 0,
                        });
                    }
                },
                ScheduleTarget::Tag { tag } => {
                    let with: Vec<&VmRecord> = all
                        .iter()
                        .filter(|vm| vm.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
                        .collect();
                    resolved.views.push(TargetView {
                        target: target.clone(),
                        name: tag.clone(),
                        vms: with.len(),
                    });
                    let names: Vec<&str> = with.iter().map(|vm| vm.display_name.as_str()).collect();
                    resolved.shown.push(if names.is_empty() {
                        format!("tag '{tag}': no VMs now")
                    } else {
                        format!("tag '{tag}': {}", names.join(", "))
                    });
                    for vm in with {
                        let key = vm_key(&vm.vmx_path);
                        resolved.via_tag.entry(key.clone()).or_insert_with(|| tag.clone());
                        if seen.insert(key) {
                            resolved.vms.push(vm.clone());
                        }
                    }
                }
            }
        }
        Ok(resolved)
    }

    /// What would make the schedule's next run ask again, in words. A read.
    async fn changes(&self, row: &ScheduleRow, resolved: &Resolved) -> Result<Vec<String>> {
        let Some(approval) = row.approval_id else {
            return Ok(vec!["it has no approval".into()]);
        };
        if row.content_hash != row.spec.content_hash() {
            return Ok(vec!["the schedule was edited".into()]);
        }
        let Some(grant) = self.inner.bus.standing_grant(self.ctx(), approval).await? else {
            return Ok(vec!["its approval was withdrawn".into()]);
        };
        let approved: HashSet<String> = grant
            .targets
            .iter()
            .chain(&grant.skipped)
            .map(|t| vm_key(&t.target.key()))
            .collect();
        let mut changes = Vec::new();
        let mut known = Vec::new();
        for vm in &resolved.vms {
            let key = vm_key(&vm.vmx_path);
            if approved.contains(&key) {
                known.push(TargetRef::Vm {
                    vmx_path: vm.vmx_path.clone(),
                });
            } else {
                changes.push(match resolved.via_tag.get(&key) {
                    Some(tag) => format!("{} has the tag '{tag}' now", vm.display_name),
                    None => format!("{} was not among the approved targets", vm.display_name),
                });
            }
        }
        if !known.is_empty() {
            for command in row.spec.commands(known, &spec::example_snapshot_name(&row.name)) {
                for change in self
                    .inner
                    .bus
                    .standing_changes(self.ctx(), approval, &row.content_hash, &command)
                    .await?
                {
                    if !changes.contains(&change) {
                        changes.push(change);
                    }
                }
            }
        }
        Ok(changes)
    }

    // ---- chain warnings (VM-27) ----

    /// The snapshot chain limits (Schedules page).
    pub async fn chain_limits(&self) -> Result<ChainLimits> {
        Ok(self
            .store()
            .get_setting::<ChainLimits>(self.ctx(), CHAIN_LIMITS_KEY)
            .await?
            .unwrap_or_default())
    }

    /// Saves the limits; audited, refused while the read-only lock is on.
    pub async fn set_chain_limits(&self, limits: ChainLimits) -> Result<ChainLimits> {
        self.store().read_only().check(Change::Schedules)?;
        limits.validate()?;
        let old = self.chain_limits().await?;
        if old != limits {
            self.store().put_setting(self.ctx(), CHAIN_LIMITS_KEY, &limits).await?;
            locks::lock(&self.inner.chains).clear();
            let detail = format!(
                "warn about snapshot chains deeper than {} -> {} snapshots or larger than {} -> {} GB",
                old.max_depth, limits.max_depth, old.max_size_gb, limits.max_size_gb
            );
            self.audit(
                "setting_changed",
                "Changed the snapshot chain warnings",
                &[],
                None,
                &detail,
            )
            .await?;
        }
        Ok(limits)
    }

    /// One VM's chain (from MO-13's disk sizes and its snapshot tree), read again when `fresh` or after a minute.
    async fn chain(&self, vm: &VmRecord, limits: ChainLimits, fresh: bool) -> ChainInfo {
        let key = vm_key(&vm.vmx_path);
        if !fresh {
            if let Some((at, info)) = locks::lock(&self.inner.chains).get(&key) {
                if at.elapsed() < CHAIN_FRESH {
                    return info.clone();
                }
            }
        }
        let hardware = self.inner.hypervisors.hardware(&vm.vmx_path).await;
        let tree = self.inner.hypervisors.snapshots(&vm.vmx_path).await;
        let mut info = chains::assess(
            &vm.vmx_path,
            &vm.display_name,
            hardware.as_ref().ok(),
            tree.as_ref().ok(),
            limits,
        );
        if let (Err(err), Err(_)) = (&hardware, &tree) {
            info.error = Some(format!(
                "Could not read {}'s disks or snapshots: {err}",
                vm.display_name
            ));
        }
        locks::lock(&self.inner.chains).insert(key, (Instant::now(), info.clone()));
        info
    }

    // ---- edits ----

    /// What the schedule would do, without saving it: when it runs next, the VMs it finds now, and warnings.
    pub async fn preview(&self, input: ScheduleInput) -> Result<SchedulePreview> {
        let name = clean_schedule_name(&input.name).unwrap_or_else(|_| "new schedule".into());
        let spec = input.spec.normalized()?;
        let resolved = self.resolve(&spec).await?;
        let warnings = self.save_warnings(&spec, &resolved).await?;
        let clock = self.clock();
        Ok(SchedulePreview {
            summary: spec.summary(&name, resolved.vms.len()),
            when: spec.timing.describe(),
            next_runs: self.next_runs(&spec.timing, clock.now(), 3),
            vms: resolved.vms.iter().map(|vm| vm.display_name.clone()).collect(),
            warnings,
        })
    }

    fn next_runs(&self, timing: &Timing, from: OffsetDateTime, n: usize) -> Vec<PlannedRun> {
        let clock = self.clock();
        let mut out = Vec::new();
        let mut cursor = from;
        for _ in 0..n {
            let Some(next) = timing.next_after(cursor, clock.as_ref()) else {
                break;
            };
            cursor = next.at;
            out.push(PlannedRun {
                at: stamp(next.at),
                note: next.note,
            });
        }
        out
    }

    /// Warnings the save's approval shows: missing VMs, chains (VM-27), safety snapshots adding up.
    async fn save_warnings(&self, spec: &ScheduleSpec, resolved: &Resolved) -> Result<Vec<String>> {
        let mut warnings: Vec<String> = resolved.missing.clone();
        if let ScheduleAction::Snapshot { keep } = spec.action {
            let limits = self.chain_limits().await?;
            for vm in &resolved.vms {
                let info = self.chain(vm, limits, false).await;
                if let Some(projected) = chains::projected_warning(&info, keep, limits) {
                    warnings.push(projected);
                } else {
                    warnings.extend(info.warnings);
                }
            }
        }
        Ok(warnings)
    }

    /// Saves a new schedule or an edit. New content (action, targets, times) waits to be approved: the answer is the
    /// returned approval, given with [`Schedules::approve`]. A new name alone keeps the approval.
    pub async fn save(&self, input: ScheduleInput) -> Result<SaveOutcome> {
        self.store().read_only().check(Change::Schedules)?;
        let name = clean_schedule_name(&input.name)?;
        let spec = input.spec.normalized()?;
        let resolved = self.resolve(&spec).await?;
        if !resolved.missing.is_empty() {
            return Err(CoreError::InvalidInput(format!("{}.", resolved.missing.join("; "))));
        }
        if resolved.vms.is_empty() {
            return Err(CoreError::InvalidInput(
                "No VM has that tag now. Tag the VMs first, or choose them by name.".into(),
            ));
        }
        let targets = resolved.targets();
        let summary = spec.summary(&name, resolved.vms.len());
        let row = match input.id {
            None => {
                let id = Uuid::new_v4();
                self.store()
                    .insert_schedule(self.ctx(), id, &name, &spec, "new")
                    .await?;
                self.audit(
                    "schedule_saved",
                    &format!("Created schedule '{name}'"),
                    &targets,
                    None,
                    &summary,
                )
                .await?;
                self.row(id).await?
            }
            Some(id) => {
                let old = self.row(id).await?;
                if old.content_hash == spec.content_hash() {
                    if old.name != name {
                        self.store().update_schedule(self.ctx(), id, &name, &spec, None).await?;
                        let detail = format!("renamed from '{}'; its approval stays", old.name);
                        self.audit(
                            "schedule_saved",
                            &format!("Renamed schedule '{name}'"),
                            &targets,
                            None,
                            &detail,
                        )
                        .await?;
                    }
                } else {
                    self.inner
                        .bus
                        .revoke_standing(self.ctx(), id, "the schedule was edited")
                        .await?;
                    self.store()
                        .update_schedule(self.ctx(), id, &name, &spec, Some("the schedule was edited"))
                        .await?;
                    let detail = format!(
                        "was: {}; now: {summary}; its approval was withdrawn and it waits to be approved again",
                        old.spec.summary(&old.name, self.resolve(&old.spec).await?.vms.len())
                    );
                    self.audit(
                        "schedule_saved",
                        &format!("Edited schedule '{name}'"),
                        &targets,
                        None,
                        &detail,
                    )
                    .await?;
                }
                self.row(id).await?
            }
        };
        self.emit(ScheduleEvent::Changed { schedule_id: row.id });
        let approval = match row.state {
            ScheduleState::NeedsApproval => self.ask(&row).await?,
            _ => None,
        };
        Ok(SaveOutcome {
            schedule: self.get(row.id).await?,
            approval,
        })
    }

    /// Asks the bus for the schedule's approval. `None` when nothing is asked (Low): it is approved and active.
    async fn ask(&self, row: &ScheduleRow) -> Result<Option<ApprovalRequest>> {
        let resolved = self.resolve(&row.spec).await?;
        if resolved.vms.is_empty() {
            return Err(CoreError::InvalidInput(
                "None of the schedule's VMs is in the VM list now, so there is nothing to approve.".into(),
            ));
        }
        let mut warnings = self.save_warnings(&row.spec, &resolved).await?;
        if row.spec.action.power_op().is_some_and(|op| {
            crate::policy::safety_snapshot_applies(&Command::VmPower {
                targets: resolved.refs(),
                op,
            })
        }) {
            warnings.push(
                "If you keep the safety snapshot on, every run takes one on each VM, and they add up: delete the old ones now and then.".into(),
            );
        }
        let clock = self.clock();
        let example = spec::example_snapshot_name(&row.name);
        let keep = match row.spec.action {
            ScheduleAction::Snapshot { keep } => keep,
            _ => None,
        };
        let draft = StandingDraft {
            owner_id: row.id,
            summary: row.spec.summary(&row.name, resolved.vms.len()),
            content_hash: row.content_hash.clone(),
            commands: row.spec.commands(resolved.refs(), &example),
            details: StandingDetails {
                schedule_id: row.id,
                name: row.name.clone(),
                when: row.spec.timing.describe(),
                next_runs: self
                    .next_runs(&row.spec.timing, clock.now(), 3)
                    .into_iter()
                    .map(|r| {
                        let at = parse_stamp(&r.at)
                            .map(|t| local_text(t, clock.as_ref()))
                            .unwrap_or(r.at);
                        match r.note {
                            Some(note) => format!("{at} ({note})"),
                            None => at,
                        }
                    })
                    .collect(),
                resolves: resolved.shown.clone(),
                snapshot_name: matches!(row.spec.action, ScheduleAction::Snapshot { .. }).then_some(example),
                keep,
                countdown_seconds: None,
            },
            warnings,
            again: row.state_reason.clone().filter(|r| r != "new"),
        };
        match self.inner.bus.ask_standing(self.ctx(), draft).await? {
            StandingAsk::Granted(grant) => {
                self.bind(row.id, &grant).await?;
                Ok(None)
            }
            StandingAsk::NeedsApproval(request) => Ok(Some(*request)),
        }
    }

    /// The schedule runs under `grant` from now on, and its next run is planned.
    async fn bind(&self, id: Uuid, grant: &StandingGrant) -> Result<()> {
        if !self
            .store()
            .set_schedule_approval(self.ctx(), id, grant.id, &grant.content_hash)
            .await?
        {
            self.inner
                .bus
                .revoke_standing(self.ctx(), id, "the schedule changed while it was approved")
                .await?;
            return Err(CoreError::InvalidInput(
                "The schedule changed or was deleted while it was approved; approve it again.".into(),
            ));
        }
        let row = self.row(id).await?;
        self.plan_next(&row, self.clock().now()).await?;
        self.emit(ScheduleEvent::Changed { schedule_id: id });
        Ok(())
    }

    async fn plan_next(&self, row: &ScheduleRow, after: OffsetDateTime) -> Result<()> {
        let next = row.spec.timing.next_after(after, self.clock().as_ref());
        self.store()
            .set_schedule_next(
                self.ctx(),
                row.id,
                next.as_ref().map(|n| stamp(n.at)).as_deref(),
                next.as_ref().and_then(|n| n.note.as_deref()),
            )
            .await
    }

    /// The answers to a schedule's approval: once they pass, it runs under it.
    pub async fn approve(&self, request_id: Uuid, answers: ApprovalAnswers) -> Result<ScheduleView> {
        let grant = self.inner.bus.approve_standing(request_id, answers).await?;
        if self.store().schedule(self.ctx(), grant.owner_id).await?.is_none() {
            self.inner
                .bus
                .revoke_standing(self.ctx(), grant.owner_id, "the schedule was deleted")
                .await?;
            return Err(CoreError::InvalidInput("That schedule was deleted.".into()));
        }
        // Older approvals of the schedule are no longer used.
        self.bind(grant.owner_id, &grant).await?;
        self.get(grant.owner_id).await
    }

    /// The approval of a schedule that waits for one, asked again (the list's "Review").
    pub async fn ask_approval(&self, id: Uuid) -> Result<SaveOutcome> {
        self.store().read_only().check(Change::Schedules)?;
        let row = self.row(id).await?;
        let approval = match row.state {
            ScheduleState::Active => None,
            _ => self.ask(&row).await?,
        };
        Ok(SaveOutcome {
            schedule: self.get(id).await?,
            approval,
        })
    }

    /// Stops the schedule's runs until it is resumed; it keeps its approval. Audited.
    pub async fn pause(&self, id: Uuid) -> Result<ScheduleView> {
        self.store().read_only().check(Change::Schedules)?;
        let row = self.row(id).await?;
        if row.state == ScheduleState::Active {
            self.store()
                .set_schedule_state(self.ctx(), id, ScheduleState::Paused, Some("paused"))
                .await?;
            let targets = self.resolve(&row.spec).await?.targets();
            self.audit(
                "schedule_paused",
                &format!("Paused schedule '{}'", row.name),
                &targets,
                None,
                "paused by the user; it keeps its approval",
            )
            .await?;
            self.emit(ScheduleEvent::Changed { schedule_id: id });
        }
        self.get(id).await
    }

    /// Runs it again from its next time. If something changed since its approval, it asks again instead.
    pub async fn resume(&self, id: Uuid) -> Result<SaveOutcome> {
        self.store().read_only().check(Change::Schedules)?;
        let row = self.row(id).await?;
        if row.state != ScheduleState::Paused {
            return self.ask_approval(id).await;
        }
        let resolved = self.resolve(&row.spec).await?;
        let changes = self.changes(&row, &resolved).await?;
        if changes.is_empty() {
            self.store()
                .set_schedule_state(self.ctx(), id, ScheduleState::Active, None)
                .await?;
            self.plan_next(&row, self.clock().now()).await?;
            self.audit(
                "schedule_resumed",
                &format!("Resumed schedule '{}'", row.name),
                &resolved.targets(),
                None,
                "runs again from its next time; runs while it was paused were not caught up",
            )
            .await?;
            self.emit(ScheduleEvent::Changed { schedule_id: id });
            return Ok(SaveOutcome {
                schedule: self.get(id).await?,
                approval: None,
            });
        }
        self.needs_approval(&row, &changes.join("; "), &resolved.targets())
            .await?;
        self.ask_approval(id).await
    }

    /// Deletes the schedule and its approval. The snapshots it took stay on the VMs. Audited.
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        self.store().read_only().check(Change::Schedules)?;
        let row = self.row(id).await?;
        let targets = self.resolve(&row.spec).await?.targets();
        self.inner
            .bus
            .revoke_standing(self.ctx(), id, "the schedule was deleted")
            .await?;
        self.store().delete_schedule(self.ctx(), id).await?;
        let detail = match row.spec.action {
            ScheduleAction::Snapshot { .. } => {
                "its approval was withdrawn; the snapshots it took stay on the VMs, named starting with 'Remotely schedule'"
            }
            _ => "its approval was withdrawn",
        };
        self.audit(
            "schedule_deleted",
            &format!("Deleted schedule '{}'", row.name),
            &targets,
            None,
            detail,
        )
        .await?;
        self.emit(ScheduleEvent::Changed { schedule_id: id });
        Ok(())
    }

    /// Something changed since the approval: the schedule waits for it again (its old approval is withdrawn).
    async fn needs_approval(&self, row: &ScheduleRow, changes: &str, targets: &[Target]) -> Result<()> {
        self.store()
            .set_schedule_state(self.ctx(), row.id, ScheduleState::NeedsApproval, Some(changes))
            .await?;
        self.inner.bus.revoke_standing(self.ctx(), row.id, changes).await?;
        self.audit_logged(
            "schedule_paused",
            &format!("Paused schedule '{}' until it is approved again", row.name),
            targets,
            None,
            &format!("{changes} since it was approved"),
        )
        .await;
        self.emit(ScheduleEvent::NeedsApproval {
            schedule_id: row.id,
            name: row.name.clone(),
            reason: changes.to_owned(),
        });
        Ok(())
    }

    // ---- the scheduler ----

    /// Ticks on the wall clock until `stop`.
    pub async fn run(&self, stop: CancellationToken) {
        loop {
            if let Err(err) = self.tick().await {
                tracing::error!(error = %err, "the scheduler's tick failed");
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }

    /// Waits for the runs going now to end (tests; the app's shutdown).
    pub async fn wait_runs(&self) {
        loop {
            let tasks: Vec<JoinHandle<()>> = std::mem::take(&mut *locks::lock(&self.inner.tasks));
            if tasks.is_empty() {
                return;
            }
            for task in tasks {
                if let Err(err) = task.await {
                    tracing::error!(error = %err, "a schedule's run panicked");
                }
            }
        }
    }

    /// One look at the clock: pauses schedules whose approval no longer fits, reports missed and skipped runs,
    /// starts the runs that are due, and looks for idle VMs (once a minute).
    pub async fn tick(&self) -> Result<TickReport> {
        let _one = self.inner.ticking.lock().await;
        let clock = self.clock();
        let now = clock.now();
        let mut report = TickReport::default();
        if !self.inner.recovered.swap(true, Ordering::SeqCst) {
            let stopped = self.store().mark_interrupted_schedule_runs(self.ctx()).await?;
            if stopped > 0 {
                tracing::warn!(stopped, "schedule runs were going when Remotely last stopped");
            }
        }
        let locked = self.store().read_only().is_locked();
        let mut idle_rows = Vec::new();
        for row in self.store().list_schedules(self.ctx()).await? {
            if row.state != ScheduleState::Active {
                continue;
            }
            let resolved = self.resolve(&row.spec).await?;
            let changes = self.changes(&row, &resolved).await?;
            if !changes.is_empty() {
                self.needs_approval(&row, &changes.join("; "), &resolved.targets())
                    .await?;
                report.paused += 1;
                continue;
            }
            if row.spec.timing.is_idle() {
                idle_rows.push(row);
                continue;
            }
            let Some(due) = row.next_run_at.as_deref().and_then(parse_stamp) else {
                self.plan_next(&row, now).await?;
                continue;
            };
            if due > now {
                continue;
            }
            // Planned on first, so this time never runs twice.
            self.plan_next(&row, now).await?;
            let targets = resolved.targets();
            if now - due > LATE_GRACE {
                let (more, _, last) = row.spec.timing.due_between(due, now, clock.as_ref(), MISSED_CAP);
                let count = 1 + more;
                let span = match last {
                    Some(last) => format!(
                        "{} runs, from {} to {}",
                        count,
                        local_text(due, clock.as_ref()),
                        local_text(last, clock.as_ref())
                    ),
                    None => format!("the run of {}", local_text(due, clock.as_ref())),
                };
                let detail = format!(
                    "Missed {span}: Remotely wasn't running or the PC was asleep or off. Missed runs are not caught up."
                );
                self.record_unrun(&row, due, RunOutcome::Missed, &detail, &targets)
                    .await?;
                report.missed += 1;
                continue;
            }
            if locked {
                let detail = "Not run: the read-only lock was on (presenting). It is not caught up.";
                self.record_unrun(&row, due, RunOutcome::Skipped, detail, &targets)
                    .await?;
                report.skipped += 1;
                continue;
            }
            let going = locks::lock(&self.inner.running).get(&row.id).copied();
            if let Some(going) = going {
                let detail = format!("Not run: the last run (run {}) was still going.", short(going));
                self.record_unrun(&row, due, RunOutcome::Skipped, &detail, &targets)
                    .await?;
                report.skipped += 1;
                continue;
            }
            self.start(
                row.clone(),
                due,
                RunKind::Timed {
                    note: row.next_note.clone(),
                },
            );
            report.started += 1;
        }
        let idle_due = {
            let mut last = locks::lock(&self.inner.last_idle_check);
            let due = last.is_none_or(|at| now - at >= IDLE_EVERY || now < at);
            if due {
                *last = Some(now);
            }
            due
        };
        if idle_due && !locked {
            for row in idle_rows {
                if locks::lock(&self.inner.running).contains_key(&row.id) {
                    continue;
                }
                let idle = self.idle_vms(&row, now).await?;
                if !idle.is_empty() {
                    self.start(row, now, RunKind::Idle(idle));
                    report.started += 1;
                }
            }
        }
        Ok(report)
    }

    /// Records a run that did not start (missed or skipped), audited and announced.
    async fn record_unrun(
        &self,
        row: &ScheduleRow,
        due: OffsetDateTime,
        outcome: RunOutcome,
        detail: &str,
        targets: &[Target],
    ) -> Result<()> {
        let id = Uuid::new_v4();
        let now = stamp(self.clock().now());
        self.store()
            .insert_schedule_run(
                self.ctx(),
                &RunRow {
                    id,
                    schedule_id: row.id,
                    due_at: stamp(due),
                    started_at: None,
                    finished_at: Some(now),
                    outcome,
                    detail: Some(detail.to_owned()),
                    job_ids: Vec::new(),
                    approval_id: row.approval_id,
                },
            )
            .await?;
        let (event, verb) = match outcome {
            RunOutcome::Missed => ("schedule_missed", "Missed"),
            _ => ("schedule_skipped", "Skipped"),
        };
        self.audit_logged(
            event,
            &format!("{verb} a run of schedule '{}'", row.name),
            targets,
            Some(outcome.as_str()),
            detail,
        )
        .await;
        let event = match outcome {
            RunOutcome::Missed => ScheduleEvent::Missed {
                schedule_id: row.id,
                run_id: id,
                name: row.name.clone(),
                detail: detail.to_owned(),
            },
            _ => ScheduleEvent::Skipped {
                schedule_id: row.id,
                run_id: id,
                name: row.name.clone(),
                detail: detail.to_owned(),
            },
        };
        self.emit(event);
        Ok(())
    }

    /// VM-14: the schedule's running VMs that have been idle long enough (and auto-suspend did not just fail on).
    async fn idle_vms(&self, row: &ScheduleRow, now: OffsetDateTime) -> Result<Vec<IdleVm>> {
        let Timing::Idle { minutes, cpu_below_pct } = row.spec.timing else {
            return Ok(Vec::new());
        };
        let resolved = self.resolve(&row.spec).await?;
        let running = self.inner.metrics.hub().running();
        let now_ms = i64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
        let mut idle = Vec::new();
        for vm in &resolved.vms {
            if vm.protected {
                continue;
            }
            let on = match &running {
                Some(keys) => keys.iter().any(|k| vm_key(k) == vm_key(&vm.vmx_path)),
                None => vm.power_state == PowerState::Running,
            };
            if !on {
                continue;
            }
            if locks::lock(&self.inner.idle_backoff)
                .get(&vm_key(&vm.vmx_path))
                .is_some_and(|until| now < *until)
            {
                continue;
            }
            let verdict = idle::idle_verdict(
                self.store(),
                self.ctx(),
                self.inner.metrics.hub(),
                &vm.vmx_path,
                minutes,
                cpu_below_pct,
                now_ms,
            )
            .await?;
            if let idle::IdleVerdict::Idle { avg_pct } = verdict {
                idle.push(IdleVm {
                    key: vm.vmx_path.clone(),
                    name: vm.display_name.clone(),
                    avg_pct,
                });
            }
        }
        Ok(idle)
    }

    /// Starts a run in the background; the schedule counts as running until it ends.
    fn start(&self, row: ScheduleRow, due: OffsetDateTime, kind: RunKind) {
        let run_id = Uuid::new_v4();
        locks::lock(&self.inner.running).insert(row.id, run_id);
        let this = self.clone();
        let schedule = row.id;
        let task = tokio::spawn(async move {
            this.run_once(row, run_id, due, kind).await;
            locks::lock(&this.inner.running).remove(&schedule);
        });
        locks::lock(&self.inner.tasks).push(task);
    }

    async fn run_once(&self, row: ScheduleRow, run_id: Uuid, due: OffsetDateTime, kind: RunKind) {
        let clock = self.clock();
        let started = stamp(clock.now());
        let inserted = self
            .store()
            .insert_schedule_run(
                self.ctx(),
                &RunRow {
                    id: run_id,
                    schedule_id: row.id,
                    due_at: stamp(due),
                    started_at: Some(started),
                    finished_at: None,
                    outcome: RunOutcome::Running,
                    detail: None,
                    job_ids: Vec::new(),
                    approval_id: row.approval_id,
                },
            )
            .await;
        if let Err(err) = inserted {
            tracing::error!(error = %err, "could not journal a schedule's run; it did not start");
            return;
        }
        self.emit(ScheduleEvent::RunStarted {
            schedule_id: row.id,
            run_id,
            name: row.name.clone(),
        });
        let mut jobs = Vec::new();
        let mut notes = Vec::new();
        if let RunKind::Timed { note: Some(note) } = &kind {
            notes.push(note.clone());
        }
        let result = match self.resolve(&row.spec).await {
            Err(err) => RunResult::new(RunOutcome::Failed, format!("could not look the VMs up: {err}")),
            Ok(resolved) => {
                notes.extend(resolved.missing.iter().cloned());
                match (&row.spec.action, kind) {
                    (_, RunKind::Idle(idle)) => self.run_idle(&row, run_id, due, idle, &mut jobs, &notes).await,
                    (ScheduleAction::Snapshot { keep }, RunKind::Timed { .. }) => {
                        self.run_snapshots(&row, run_id, due, *keep, &resolved, &mut jobs, &notes)
                            .await
                    }
                    (action, RunKind::Timed { .. }) => {
                        self.run_power(&row, run_id, due, action, &resolved, &mut jobs, &notes)
                            .await
                    }
                }
            }
        };
        if let Err(err) = self
            .store()
            .finish_schedule_run(run_id, result.outcome, Some(&result.detail), &jobs)
            .await
        {
            tracing::error!(error = %err, "could not journal how a schedule's run ended");
        }
        let targets = match self.resolve(&row.spec).await {
            Ok(resolved) => resolved.targets(),
            Err(_) => Vec::new(),
        };
        let jobs_text = if jobs.is_empty() {
            String::new()
        } else {
            let ids: Vec<String> = jobs.iter().map(|j| short(*j)).collect();
            format!("; job {}", ids.join(", "))
        };
        let detail = format!(
            "run {} due {}: {}{jobs_text}",
            short(run_id),
            local_text(due, clock.as_ref()),
            result.detail
        );
        self.audit_logged(
            "schedule_run",
            &format!("Ran schedule '{}'", row.name),
            &targets,
            Some(result.outcome.as_str()),
            &detail,
        )
        .await;
        self.emit(ScheduleEvent::RunFinished {
            schedule_id: row.id,
            run_id,
            name: row.name.clone(),
            outcome: result.outcome,
            detail: Some(result.detail),
        });
    }

    /// Submits one of the run's commands under the schedule's approval.
    async fn submit(
        &self,
        row: &ScheduleRow,
        run_id: Uuid,
        due: OffsetDateTime,
        command: Command,
    ) -> std::result::Result<Uuid, Stop> {
        let Some(approval_id) = row.approval_id else {
            return Err(Stop::Paused("it has no approval".into()));
        };
        let run = StandingRun {
            approval_id,
            content_hash: row.content_hash.clone(),
            command,
            run_id,
            label: format!("Schedule '{}'", row.name),
            due: local_text(due, self.clock().as_ref()),
        };
        match self.inner.bus.submit_standing(self.ctx(), run).await {
            Ok(job) => Ok(job),
            Err(CoreError::StandingChanged { changes }) => {
                let targets = self.resolve(&row.spec).await.map(|r| r.targets()).unwrap_or_default();
                if let Err(err) = self.needs_approval(row, &changes, &targets).await {
                    tracing::error!(error = %err, "could not pause a schedule whose approval no longer fits");
                }
                Err(Stop::Paused(changes))
            }
            Err(CoreError::ReadOnlyLock { .. }) => Err(Stop::Skipped(
                "not run: the read-only lock is on (presenting); it is not caught up".into(),
            )),
            Err(CoreError::AllTargetsProtected) => Err(Stop::Skipped("not run: every VM is protected".into())),
            Err(err) => Err(Stop::Failed(format!("could not start: {err}"))),
        }
    }

    /// Waits for a job; returns how it ended and each target's status and error, by lower-case key.
    async fn finished(&self, job: Uuid) -> (JobStatus, HashMap<String, (String, String, Option<String>)>) {
        let status = self.inner.jobs.wait(job).await.unwrap_or(JobStatus::Interrupted);
        let targets = self
            .store()
            .job_targets(self.ctx(), job)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|t| (vm_key(&t.target_key), (t.status, t.target_name, t.error)))
            .collect();
        (status, targets)
    }

    /// VM-14: start, shut down, suspend or resume, on the VMs in a state it applies to.
    #[allow(clippy::too_many_arguments)]
    async fn run_power(
        &self,
        row: &ScheduleRow,
        run_id: Uuid,
        due: OffsetDateTime,
        action: &ScheduleAction,
        resolved: &Resolved,
        jobs: &mut Vec<Uuid>,
        notes: &[String],
    ) -> RunResult {
        let Some(op) = action.power_op() else {
            return RunResult::new(RunOutcome::Failed, "not a power action");
        };
        // The states now, not the list's last reading.
        if let Err(err) = self.inner.inventory.refresh(self.ctx()).await {
            tracing::warn!(error = %err, "could not refresh the VM list before a scheduled run");
        }
        let states: HashMap<String, PowerState> = match self.store().list_vms(self.ctx()).await {
            Ok(vms) => vms
                .into_iter()
                .map(|vm| (vm_key(&vm.vmx_path), vm.power_state))
                .collect(),
            Err(_) => HashMap::new(),
        };
        let mut act = Vec::new();
        let mut left: Vec<String> = Vec::new();
        for vm in &resolved.vms {
            let state = states.get(&vm_key(&vm.vmx_path)).copied().unwrap_or(vm.power_state);
            let why = match (action, state) {
                (_, PowerState::Unknown) => None,
                (ScheduleAction::Start, PowerState::Running | PowerState::Paused) => Some("already running"),
                (ScheduleAction::Resume, PowerState::Suspended) => None,
                (ScheduleAction::Resume, PowerState::NotRunning) => Some("off, not suspended"),
                (ScheduleAction::Resume, _) => Some("already running"),
                (ScheduleAction::Stop | ScheduleAction::Suspend, PowerState::Running) => None,
                (ScheduleAction::Stop | ScheduleAction::Suspend, PowerState::Paused) => Some("paused"),
                (ScheduleAction::Stop, _) => Some("not running"),
                (ScheduleAction::Suspend, PowerState::Suspended) => Some("already suspended"),
                (ScheduleAction::Suspend, _) => Some("not running"),
                _ => None,
            };
            match why {
                Some(why) => left.push(format!("{} {why}", vm.display_name)),
                None => act.push(TargetRef::Vm {
                    vmx_path: vm.vmx_path.clone(),
                }),
            }
        }
        let mut before: Vec<String> = notes.to_vec();
        if !left.is_empty() {
            before.push(format!("left alone: {}", left.join(", ")));
        }
        if act.is_empty() {
            before.insert(0, "nothing to do".into());
            return RunResult::new(RunOutcome::Succeeded, before.join("; "));
        }
        let count = act.len();
        let job = match self
            .submit(row, run_id, due, Command::VmPower { targets: act, op })
            .await
        {
            Ok(job) => job,
            Err(stop) => return stop.result(&before),
        };
        jobs.push(job);
        let (status, targets) = self.finished(job).await;
        let verb = match action {
            ScheduleAction::Start => "started",
            ScheduleAction::Stop => "shut down",
            ScheduleAction::Suspend => "suspended",
            ScheduleAction::Resume => "resumed",
            ScheduleAction::Snapshot { .. } => "changed",
        };
        job_result(status, &targets, count, verb, before)
    }

    /// VM-14 auto-suspend: suspends the idle VMs found.
    async fn run_idle(
        &self,
        row: &ScheduleRow,
        run_id: Uuid,
        due: OffsetDateTime,
        idle: Vec<IdleVm>,
        jobs: &mut Vec<Uuid>,
        notes: &[String],
    ) -> RunResult {
        let Timing::Idle { minutes, cpu_below_pct } = row.spec.timing else {
            return RunResult::new(RunOutcome::Failed, "not an auto-suspend schedule");
        };
        let mut before = notes.to_vec();
        before.push(format!(
            "idle for {minutes} minutes with CPU under {cpu_below_pct}%: {}",
            idle.iter()
                .map(|vm| format!("{} ({:.1}% on average)", vm.name, vm.avg_pct))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        let targets: Vec<TargetRef> = idle
            .iter()
            .map(|vm| TargetRef::Vm {
                vmx_path: vm.key.clone(),
            })
            .collect();
        let count = targets.len();
        let job = match self
            .submit(
                row,
                run_id,
                due,
                Command::VmPower {
                    targets,
                    op: crate::command_bus::PowerOp::Suspend,
                },
            )
            .await
        {
            Ok(job) => job,
            Err(stop) => {
                self.back_off(&idle, minutes);
                return stop.result(&before);
            }
        };
        jobs.push(job);
        let (status, results) = self.finished(job).await;
        let failed: Vec<IdleVm> = idle
            .iter()
            .filter(|vm| {
                results
                    .get(&vm_key(&vm.key))
                    .is_none_or(|(status, _, _)| status != TargetStatus::Succeeded.as_str())
            })
            .cloned()
            .collect();
        self.back_off(&failed, minutes);
        job_result(status, &results, count, "suspended", before)
    }

    /// VM-14: auto-suspend waits a whole idle time before it tries these VMs again.
    fn back_off(&self, vms: &[IdleVm], minutes: u32) {
        let until = self.clock().now() + Duration::minutes(i64::from(minutes));
        let mut backoff = locks::lock(&self.inner.idle_backoff);
        for vm in vms {
            backoff.insert(vm_key(&vm.key), until);
        }
    }

    /// VM-27: takes the run's snapshot of each VM, records each one by its id, then deletes the schedule's own
    /// oldest ones beyond `keep` on the VMs where the new one was taken.
    #[allow(clippy::too_many_arguments)]
    async fn run_snapshots(
        &self,
        row: &ScheduleRow,
        run_id: Uuid,
        due: OffsetDateTime,
        keep: Option<u32>,
        resolved: &Resolved,
        jobs: &mut Vec<Uuid>,
        notes: &[String],
    ) -> RunResult {
        let clock = self.clock();
        let local_due = due.to_offset(clock.offset_at(due));
        let name = snapshot_name(&row.name, local_due, run_id);
        let before = notes.to_vec();
        if resolved.vms.is_empty() {
            let mut parts = before;
            parts.insert(0, "nothing to do: none of its VMs is in the VM list".into());
            return RunResult::new(RunOutcome::Succeeded, parts.join("; "));
        }
        let take = Command::VmSnapshot {
            targets: resolved.refs(),
            op: SnapshotOp::Take { name: name.clone() },
        };
        let job = match self.submit(row, run_id, due, take).await {
            Ok(job) => job,
            Err(stop) => return stop.result(&before),
        };
        jobs.push(job);
        let (status, results) = self.finished(job).await;
        let taken: Vec<&VmRecord> = resolved
            .vms
            .iter()
            .filter(|vm| {
                results
                    .get(&vm_key(&vm.vmx_path))
                    .is_some_and(|(status, _, _)| status == TargetStatus::Succeeded.as_str())
            })
            .collect();
        let mut parts = Vec::new();
        let mut problems = Vec::new();
        // Each new snapshot is recorded by the hypervisor's own id for it.
        for vm in &taken {
            match self.inner.hypervisors.snapshots(&vm.vmx_path).await {
                Ok(tree) => match tree.snapshots.iter().find(|s| s.name == name) {
                    Some(info) => {
                        let recorded = self
                            .store()
                            .record_schedule_snapshot(
                                self.ctx(),
                                row.id,
                                run_id,
                                &TakenSnapshot {
                                    vm_key: vm_key(&vm.vmx_path),
                                    snapshot_id: info.id.clone().unwrap_or_else(|| info.uid.to_string()),
                                    name: name.clone(),
                                    taken_at: stamp(clock.now()),
                                },
                            )
                            .await;
                        if let Err(err) = recorded {
                            problems.push(format!(
                                "{}'s new snapshot could not be recorded: {err}",
                                vm.display_name
                            ));
                        }
                    }
                    None => problems.push(format!(
                        "{}'s new snapshot is not in its snapshot list, so retention won't count it",
                        vm.display_name
                    )),
                },
                Err(err) => problems.push(format!(
                    "{}'s snapshots could not be read to record the new one: {err}",
                    vm.display_name
                )),
            }
            locks::lock(&self.inner.chains).remove(&vm_key(&vm.vmx_path));
        }
        let failed: Vec<String> = resolved
            .vms
            .iter()
            .filter(|vm| !taken.iter().any(|t| t.vmx_path == vm.vmx_path))
            .map(|vm| {
                let why = results
                    .get(&vm_key(&vm.vmx_path))
                    .and_then(|(_, _, error)| error.clone())
                    .unwrap_or_else(|| "not taken".into());
                format!("{}: {why}", vm.display_name)
            })
            .collect();
        parts.push(format!("took '{name}' on {}", plural(taken.len(), "VM")));
        if !failed.is_empty() {
            parts.push(format!("failed on {}", failed.join("; ")));
        }
        let mut retention_failed = false;
        if let Some(keep) = keep {
            let (deleted, kept_renamed, errors) = self.retain(row, run_id, due, keep, &taken, jobs).await;
            if deleted > 0 {
                let what = if deleted == 1 { "snapshot" } else { "snapshots" };
                parts.push(format!("deleted {deleted} older {what} (keeping the last {keep})"));
            }
            if kept_renamed > 0 {
                parts.push(format!(
                    "{} renamed since it was taken, so it is kept and no longer counted",
                    plural(kept_renamed, "snapshot")
                ));
            }
            retention_failed = !errors.is_empty();
            problems.extend(errors);
        }
        parts.extend(problems);
        let mut all = before;
        all.extend(parts);
        let outcome = match status {
            _ if taken.is_empty() => RunOutcome::Failed,
            JobStatus::Succeeded if !retention_failed => RunOutcome::Succeeded,
            _ => RunOutcome::PartiallyFailed,
        };
        RunResult::new(outcome, all.join("; "))
    }

    /// VM-27 retention on the VMs a run took a snapshot of. Returns how many were deleted, how many were kept for
    /// being renamed, and what failed.
    async fn retain(
        &self,
        row: &ScheduleRow,
        run_id: Uuid,
        due: OffsetDateTime,
        keep: u32,
        taken: &[&VmRecord],
        jobs: &mut Vec<Uuid>,
    ) -> (usize, usize, Vec<String>) {
        let mut renamed = 0;
        let mut errors = Vec::new();
        // How each excess snapshot is named to its hypervisor -> the VMs and ids.
        let mut deletes: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
        for vm in taken {
            let key = vm_key(&vm.vmx_path);
            let own = match self.store().schedule_snapshots(self.ctx(), row.id, &key).await {
                Ok(own) => own,
                Err(err) => {
                    errors.push(format!(
                        "{}'s snapshots from this schedule could not be read: {err}",
                        vm.display_name
                    ));
                    continue;
                }
            };
            let excess: Vec<&TakenSnapshot> = own.iter().skip(keep as usize).collect();
            if excess.is_empty() {
                continue;
            }
            let tree = match self.inner.hypervisors.snapshots(&vm.vmx_path).await {
                Ok(tree) => tree,
                Err(err) => {
                    errors.push(format!(
                        "{}'s snapshots could not be read for retention: {err}",
                        vm.display_name
                    ));
                    continue;
                }
            };
            let nodes = tree_nodes(&tree, self.clock().now());
            for old in excess {
                let found = tree
                    .snapshots
                    .iter()
                    .find(|s| s.id.clone().unwrap_or_else(|| s.uid.to_string()) == old.snapshot_id);
                let end = match found {
                    None => Some(SnapshotEnd::Gone),
                    Some(info) if info.name != old.name => Some(SnapshotEnd::Renamed),
                    Some(_) => None,
                };
                if let Some(end) = end {
                    if end == SnapshotEnd::Renamed {
                        renamed += 1;
                    }
                    if let Err(err) = self
                        .store()
                        .end_schedule_snapshot(self.ctx(), row.id, &key, &old.snapshot_id, end)
                        .await
                    {
                        errors.push(format!("could not update the record of a snapshot: {err}"));
                    }
                    continue;
                }
                let Some(info) = found else { continue };
                // VirtualBox: its UUID. Workstation: the name when no other snapshot has it, else its path.
                let reference = match (&info.id, tree.snapshots.iter().filter(|s| s.name == info.name).count()) {
                    (Some(id), _) => id.clone(),
                    (None, 1) => info.name.clone(),
                    (None, _) => nodes
                        .iter()
                        .find(|n| n.uid == info.uid)
                        .map(|n| n.path.clone())
                        .unwrap_or_else(|| info.name.clone()),
                };
                deletes.entry(reference).or_default().push((
                    vm.vmx_path.clone(),
                    old.snapshot_id.clone(),
                    vm.display_name.clone(),
                ));
            }
        }
        let mut deleted = 0;
        let mut references: Vec<String> = deletes.keys().cloned().collect();
        references.sort();
        for reference in references {
            let vms = deletes.remove(&reference).unwrap_or_default();
            let command = Command::VmSnapshot {
                targets: vms
                    .iter()
                    .map(|(key, _, _)| TargetRef::Vm { vmx_path: key.clone() })
                    .collect(),
                op: SnapshotOp::Delete {
                    name: reference.clone(),
                },
            };
            let job = match self.submit(row, run_id, due, command).await {
                Ok(job) => job,
                Err(Stop::Paused(why) | Stop::Skipped(why) | Stop::Failed(why)) => {
                    errors.push(format!("retention did not run: {why}"));
                    break;
                }
            };
            jobs.push(job);
            let (_, results) = self.finished(job).await;
            for (key, id, name) in vms {
                match results.get(&vm_key(&key)) {
                    Some((status, _, _)) if status == TargetStatus::Succeeded.as_str() => {
                        deleted += 1;
                        if let Err(err) = self
                            .store()
                            .end_schedule_snapshot(self.ctx(), row.id, &vm_key(&key), &id, SnapshotEnd::Deleted)
                            .await
                        {
                            errors.push(format!("could not update the record of a snapshot: {err}"));
                        }
                    }
                    other => errors.push(format!(
                        "{name}: an older snapshot was not deleted ({})",
                        other
                            .and_then(|(_, _, e)| e.clone())
                            .unwrap_or_else(|| "not started".into())
                    )),
                }
                locks::lock(&self.inner.chains).remove(&vm_key(&key));
            }
        }
        (deleted, renamed, errors)
    }
}

/// The first 8 characters of an id.
fn short(id: Uuid) -> String {
    id.simple().to_string()[..8].to_owned()
}

/// A power job's result in words.
fn job_result(
    status: JobStatus,
    targets: &HashMap<String, (String, String, Option<String>)>,
    count: usize,
    verb: &str,
    mut before: Vec<String>,
) -> RunResult {
    let ok = targets
        .values()
        .filter(|(status, _, _)| status == TargetStatus::Succeeded.as_str())
        .count();
    let mut failed: Vec<String> = targets
        .values()
        .filter(|(status, _, _)| status != TargetStatus::Succeeded.as_str())
        .map(|(status, name, error)| format!("{name}: {}", error.clone().unwrap_or_else(|| status.clone())))
        .collect();
    failed.sort();
    let mut parts = vec![format!("{verb} {} of {count}", ok)];
    if !failed.is_empty() {
        parts.push(format!("failed: {}", failed.join("; ")));
    }
    parts.append(&mut before);
    let outcome = match status {
        JobStatus::Succeeded => RunOutcome::Succeeded,
        JobStatus::PartiallyFailed => RunOutcome::PartiallyFailed,
        JobStatus::Cancelled => {
            parts.push("the job was cancelled".into());
            if ok > 0 {
                RunOutcome::PartiallyFailed
            } else {
                RunOutcome::Failed
            }
        }
        _ if ok > 0 => RunOutcome::PartiallyFailed,
        _ => RunOutcome::Failed,
    };
    RunResult::new(outcome, parts.join("; "))
}
