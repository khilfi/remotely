//! MO-07: alerts on the dashboard's metrics. Desktop only: Windows notifications and an alert list, never
//! email, Teams or Slack.
//!
//! Rules ([`rules`]) watch a metric (CPU, memory, disk, swap, a watched host unreachable, a VM that stopped
//! without a Remotely action) on a scope (every VM, a VM, a tag, a watched SSH host, every watched host, this
//! PC), with a threshold, how long it must hold and a severity. The collector hands each round to [`Alerts`]
//! (a [`RoundObserver`]), which reads the targets as the dashboard's grid shows them (the guest's view where a
//! watched session reads it, else the VM's process) and runs the rules ([`eval`]): firing and resolved alerts
//! go to the alert list (the `alerts` table, pruned with the history) and out as [`AlertEvent`]s, which the
//! shell forwards to the UI for its notifications (masked while presenting, at most one per rule and target in
//! half an hour) and, later, the notification centre (QL-25).
//!
//! Reads only, like the metrics they watch: nothing goes through the command bus. Rule edits and
//! acknowledgements change the app's data, so they are audited and the FD-03 read-only lock refuses them.
//! Alerts firing and resolving are not audited: they are readings, not actions.

pub mod eval;
pub mod rules;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::adapters::hypervisor::Hypervisor;
use crate::domain::{Context, THIS_PC_KEY};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::metrics::history::now_ms;
use crate::metrics::{GuestState, MetricSample, MetricSource, MetricsHub, RecordedRound, RoundObserver};
use crate::presentation::Change;
use crate::sessions::SessionRecord;
use crate::store::{NewAuditEntry, Store, VmRecord};

pub use eval::{Evaluator, Reading, RunningVm, Snapshot, Transition};
pub use rules::{AlertMetric, AlertRule, AlertRuleInput, AlertScope, Severity, BUILTINS};

/// What an alert is about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AlertTargetKind {
    #[default]
    Vm,
    Session,
    ThisPc,
}

impl AlertTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertTargetKind::Vm => "vm",
            AlertTargetKind::Session => "session",
            AlertTargetKind::ThisPc => "thisPc",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "vm" => Some(AlertTargetKind::Vm),
            "session" => Some(AlertTargetKind::Session),
            "thisPc" => Some(AlertTargetKind::ThisPc),
            _ => None,
        }
    }
}

/// A VM (its key), a watched host (its session id) or this PC, with the name it had.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertTarget {
    pub kind: AlertTargetKind,
    pub key: String,
    pub name: String,
}

/// Why an alert stopped firing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Resolution {
    /// The reading went back under the threshold (or the host answers, the VM runs again).
    Cleared,
    /// The target left the rule's scope: the VM stopped running, the host is no longer watched.
    Gone,
    /// The rule was changed, turned off or deleted.
    RuleChanged,
    /// Remotely closed while it fired; a rule still met fires again.
    Restarted,
}

impl Resolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Resolution::Cleared => "cleared",
            Resolution::Gone => "gone",
            Resolution::RuleChanged => "ruleChanged",
            Resolution::Restarted => "restarted",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "cleared" => Some(Resolution::Cleared),
            "gone" => Some(Resolution::Gone),
            "ruleChanged" => Some(Resolution::RuleChanged),
            "restarted" => Some(Resolution::Restarted),
            _ => None,
        }
    }
}

/// One alert in the list: a rule that fired for a target.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub metric: AlertMetric,
    pub severity: Severity,
    pub target: AlertTarget,
    pub threshold: Option<f64>,
    pub for_secs: u64,
    /// The reading when it fired (percent; none for unreachable and stopped).
    pub value: Option<f64>,
    /// The worst reading while it fired, once it resolved.
    pub peak: Option<f64>,
    /// What fired, in words: "CPU at 97%, above 90% for 5 minutes".
    pub message: String,
    pub fired_at: String,
    pub resolved_at: Option<String>,
    pub resolution: Option<Resolution>,
    pub acknowledged_at: Option<String>,
}

/// MO-07, for the UI's notifications and (QL-25) the notification centre: an alert fired, resolved, or was
/// acknowledged.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum AlertEvent {
    /// `notify`: show a Windows notification (the rule notifies, and not within its cooldown).
    Fired {
        alert: Alert,
        notify: bool,
    },
    Resolved {
        alert: Alert,
    },
    Acknowledged {
        ids: Vec<Uuid>,
    },
}

/// Which alerts the list shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertQuery {
    /// Firing ones only; otherwise the history too, newest first.
    #[serde(default)]
    pub open_only: bool,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The alert list and its counts (the badge shows the open, unacknowledged ones).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertList {
    pub alerts: Vec<Alert>,
    pub open: u64,
    pub unacknowledged: u64,
}

/// The list's longest page.
pub const MAX_LIST: u32 = 500;

/// How long the names, tags and links the rules match on are kept before they are read again.
const DIRECTORY_TTL: Duration = Duration::from_secs(60);

/// A stopped VM counts as Remotely's doing when one of its jobs finished this recently (or is still open).
const REMOTELY_WINDOW: time::Duration = time::Duration::minutes(2);

/// The VMs, sessions and links the rules match on, read at most once a minute.
struct Directory {
    vms: Vec<VmRecord>,
    sessions: Vec<SessionRecord>,
    by_vm: HashMap<String, Vec<Uuid>>,
    read_at: Instant,
}

/// MO-07: the rules, the alert list and their evaluation (`Core.alerts`).
pub struct Alerts {
    store: Store,
    /// FD-02: the workspace shown, whose rules run on the rounds ([`Alerts::switch_to`]).
    ctx: RwLock<Context>,
    rules: RwLock<Vec<AlertRule>>,
    eval: tokio::sync::Mutex<Evaluator>,
    directory: tokio::sync::Mutex<Option<Directory>>,
    tx: broadcast::Sender<AlertEvent>,
    /// Errors are logged once per kind, not every round.
    failing: Mutex<bool>,
}

impl Alerts {
    /// Creates the built-in rules this workspace doesn't have yet, and closes the alerts left firing when the
    /// app last stopped (a rule still met fires again).
    pub async fn load(store: Store, ctx: Context) -> Result<Self> {
        store.ensure_builtin_rules(&ctx, &rules::BUILTINS).await?;
        let closed = store
            .close_open_alerts(&ctx, Resolution::Restarted, &eval::rfc3339(now_ms()))
            .await?;
        if closed > 0 {
            tracing::info!(closed, "alerts left firing when Remotely last stopped were closed");
        }
        let rules = store.alert_rules(&ctx).await?;
        let (tx, _) = broadcast::channel(64);
        Ok(Self {
            store,
            ctx: RwLock::new(ctx),
            rules: RwLock::new(rules),
            eval: tokio::sync::Mutex::new(Evaluator::default()),
            directory: tokio::sync::Mutex::new(None),
            tx,
            failing: Mutex::new(false),
        })
    }

    fn ctx(&self) -> Context {
        *locks::read(&self.ctx)
    }

    /// FD-02: another workspace is shown. The old one's alerts still firing close as gone (its targets left the
    /// dashboard), and the new one's rules run from the next round, after its own leftover alerts are closed as at
    /// start. A hidden workspace raises no alerts.
    pub async fn switch_to(&self, ctx: Context) -> Result<()> {
        let mut eval = self.eval.lock().await;
        let old = self.ctx();
        let at = eval::rfc3339(now_ms());
        if old != ctx {
            self.store.close_open_alerts(&old, Resolution::Gone, &at).await?;
        }
        self.store.ensure_builtin_rules(&ctx, &rules::BUILTINS).await?;
        self.store.close_open_alerts(&ctx, Resolution::Restarted, &at).await?;
        let rules = self.store.alert_rules(&ctx).await?;
        *locks::write(&self.ctx) = ctx;
        *locks::write(&self.rules) = rules;
        *eval = Evaluator::default();
        *self.directory.lock().await = None;
        Ok(())
    }

    /// Alerts firing, resolving and acknowledged, as they happen.
    pub fn subscribe(&self) -> broadcast::Receiver<AlertEvent> {
        self.tx.subscribe()
    }

    /// Built-in rules first, then the owner's own.
    pub fn rules(&self) -> Vec<AlertRule> {
        locks::read(&self.rules).clone()
    }

    /// Adds a rule of the owner's own. Audited; refused while presenting with the read-only lock.
    pub async fn create_rule(&self, input: AlertRuleInput) -> Result<AlertRule> {
        self.store.read_only().check(Change::Alerts)?;
        let input = rules::checked(input)?;
        self.check_scope(&input.scope).await?;
        let rule = self.store.insert_alert_rule(&self.ctx(), None, &input).await?;
        self.audit("Added an alert rule", &rules::describe(&input)).await?;
        self.reload().await?;
        Ok(rule)
    }

    /// Changes a rule. A built-in rule keeps its name, metric and scope. Firing alerts of the rule resolve
    /// (the rule changed), and it fires again if it still holds. Audited; refused while presenting.
    pub async fn update_rule(&self, id: Uuid, input: AlertRuleInput) -> Result<AlertRule> {
        self.store.read_only().check(Change::Alerts)?;
        let old = self.rule(id).await?;
        let mut input = rules::checked(input)?;
        if old.builtin.is_some() {
            if input.metric != old.metric || input.scope != old.scope {
                return Err(CoreError::InvalidInput(
                    "A built-in rule's metric and scope can't change. Add a rule of your own instead.".into(),
                ));
            }
            input.name = old.name.clone();
        }
        self.check_scope(&input.scope).await?;
        let rule = self
            .store
            .update_alert_rule(&self.ctx(), id, &input)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(id.to_string()))?;
        let detail = format!("{} -> {}", rules::describe(&old.input()), rules::describe(&input));
        self.audit("Changed an alert rule", &detail).await?;
        self.rule_changed(id).await?;
        Ok(rule)
    }

    /// Deletes a rule of the owner's own (built-in rules are turned off instead). Its alerts stay in the list.
    /// Audited; refused while presenting.
    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Alerts)?;
        let old = self.rule(id).await?;
        if old.builtin.is_some() {
            return Err(CoreError::InvalidInput(
                "A built-in rule can't be deleted. Turn it off instead.".into(),
            ));
        }
        self.store.delete_alert_rule(&self.ctx(), id).await?;
        self.audit("Deleted an alert rule", &rules::describe(&old.input()))
            .await?;
        self.rule_changed(id).await
    }

    /// Puts a built-in rule back as Remotely ships it. Audited; refused while presenting.
    pub async fn reset_rule(&self, id: Uuid) -> Result<AlertRule> {
        self.store.read_only().check(Change::Alerts)?;
        let old = self.rule(id).await?;
        let builtin = old
            .builtin
            .as_deref()
            .and_then(rules::builtin)
            .ok_or_else(|| CoreError::InvalidInput("Only a built-in rule can be reset to its defaults.".into()))?;
        let input = builtin.input();
        let rule = self
            .store
            .update_alert_rule(&self.ctx(), id, &input)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(id.to_string()))?;
        let detail = format!(
            "{} -> {} (the defaults)",
            rules::describe(&old.input()),
            rules::describe(&input)
        );
        self.audit("Reset an alert rule", &detail).await?;
        self.rule_changed(id).await?;
        Ok(rule)
    }

    /// The alert list: firing alerts, or the history too, newest first, with the counts for the badge.
    pub async fn list(&self, query: AlertQuery) -> Result<AlertList> {
        let limit = query.limit.unwrap_or(200).clamp(1, MAX_LIST);
        let alerts = self.store.list_alerts(&self.ctx(), query.open_only, limit).await?;
        let (open, unacknowledged) = self.store.alert_counts(&self.ctx()).await?;
        Ok(AlertList {
            alerts,
            open,
            unacknowledged,
        })
    }

    /// Acknowledges alerts (`ids`; all open ones when empty): they stay in the list until they resolve, marked
    /// as seen. Audited; refused while presenting.
    pub async fn acknowledge(&self, ids: &[Uuid]) -> Result<Vec<Uuid>> {
        self.store.read_only().check(Change::Alerts)?;
        let at = eval::rfc3339(now_ms());
        let acknowledged = self.store.acknowledge_alerts(&self.ctx(), ids, &at).await?;
        if acknowledged.is_empty() {
            return Ok(Vec::new());
        }
        let mut names: Vec<String> = acknowledged
            .iter()
            .take(5)
            .map(|a| format!("{} on {}", a.rule_name, a.target.name))
            .collect();
        if acknowledged.len() > names.len() {
            names.push(format!("and {} more", acknowledged.len() - names.len()));
        }
        let detail = format!(
            "{} alert{}: {}",
            acknowledged.len(),
            if acknowledged.len() == 1 { "" } else { "s" },
            names.join("; ")
        );
        self.store
            .append_audit(
                &self.ctx(),
                NewAuditEntry {
                    event: "alert_acknowledged",
                    action: "Acknowledged alerts",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        let ids: Vec<Uuid> = acknowledged.iter().map(|a| a.id).collect();
        let _ = self.tx.send(AlertEvent::Acknowledged { ids: ids.clone() });
        Ok(ids)
    }

    /// The names, tags and links are read again at the next round (tests, and after edits that change them).
    pub async fn forget_directory(&self) {
        *self.directory.lock().await = None;
    }

    /// One round: the rules against the targets, then what fired and resolved is stored and sent.
    pub async fn evaluate(&self, round: &RecordedRound<'_>) -> Result<()> {
        let rules = self.rules();
        let mut eval = self.eval.lock().await;
        let snapshot = {
            let mut directory = self.directory.lock().await;
            if directory.as_ref().is_none_or(|d| d.read_at.elapsed() >= DIRECTORY_TTL) {
                *directory = Some(Directory {
                    vms: self.store.list_vms(&self.ctx()).await?,
                    sessions: self.store.list_sessions(&self.ctx()).await?,
                    by_vm: self.store.sessions_by_vm(&self.ctx()).await?,
                    read_at: Instant::now(),
                });
            }
            match directory.as_ref() {
                Some(directory) => snapshot(round.t_ms, round.hub, directory),
                None => return Ok(()),
            }
        };
        let mut by_remotely = HashSet::new();
        if rules.iter().any(|r| r.enabled && r.metric == AlertMetric::Stopped) {
            let now = time::OffsetDateTime::from_unix_timestamp(round.t_ms.div_euclid(1000))
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
            for key in eval.stopped_vms(&snapshot) {
                if self
                    .store
                    .vm_job_since(&self.ctx(), &key, now - REMOTELY_WINDOW)
                    .await?
                {
                    by_remotely.insert(key);
                }
            }
        }
        let transitions = eval.evaluate(&rules, &snapshot, &by_remotely);
        self.apply(transitions).await
    }

    async fn apply(&self, transitions: Vec<Transition>) -> Result<()> {
        for transition in transitions {
            match transition {
                Transition::Fired { alert, notify } => {
                    self.store.insert_alert(&self.ctx(), &alert).await?;
                    tracing::info!(rule = %alert.rule_id, metric = alert.metric.as_str(), notify, "an alert fired");
                    let _ = self.tx.send(AlertEvent::Fired { alert: *alert, notify });
                }
                Transition::Resolved {
                    alert_id,
                    resolution,
                    peak,
                    at_ms,
                } => {
                    let resolved = self
                        .store
                        .resolve_alert(&self.ctx(), alert_id, resolution, peak, &eval::rfc3339(at_ms))
                        .await?;
                    if let Some(alert) = resolved {
                        let _ = self.tx.send(AlertEvent::Resolved { alert });
                    }
                }
            }
        }
        Ok(())
    }

    async fn rule(&self, id: Uuid) -> Result<AlertRule> {
        self.store
            .alert_rule(&self.ctx(), id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(id.to_string()))
    }

    /// A watched host rule needs a saved session.
    async fn check_scope(&self, scope: &AlertScope) -> Result<()> {
        if let AlertScope::Host { session_id } = scope {
            if self.store.get_session(&self.ctx(), *session_id).await?.is_none() {
                return Err(CoreError::InvalidInput("Choose a saved session for the rule.".into()));
            }
        }
        Ok(())
    }

    /// A rule changed or went: its firing alerts resolve, and the rules are read again.
    async fn rule_changed(&self, id: Uuid) -> Result<()> {
        let firing = self.eval.lock().await.forget_rule(id);
        let at = now_ms();
        let resolved = firing
            .into_iter()
            .map(|alert_id| Transition::Resolved {
                alert_id,
                resolution: Resolution::RuleChanged,
                peak: None,
                at_ms: at,
            })
            .collect();
        self.apply(resolved).await?;
        self.reload().await
    }

    async fn reload(&self) -> Result<()> {
        let rules = self.store.alert_rules(&self.ctx()).await?;
        *locks::write(&self.rules) = rules;
        Ok(())
    }

    async fn audit(&self, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                &self.ctx(),
                NewAuditEntry {
                    event: "alert_rule_changed",
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
}

#[async_trait]
impl RoundObserver for Alerts {
    async fn after_round(&self, round: &RecordedRound<'_>) {
        let result = self.evaluate(round).await;
        let mut failing = locks::lock(&self.failing);
        match result {
            Ok(()) => *failing = false,
            Err(err) if !*failing => {
                *failing = true;
                tracing::warn!(error = %err, "alert rules could not be evaluated; trying again each round");
            }
            Err(_) => {}
        }
    }
}

fn pct(used: u64, total: Option<u64>) -> Option<f64> {
    #[allow(clippy::cast_precision_loss)]
    total
        .filter(|t| *t > 0)
        .map(|t| (used as f64 * 100.0 / t as f64).clamp(0.0, 100.0))
}

/// One target's readings, as the grid picks them: the guest's view first, then the VM's process.
fn reading(
    target: AlertTarget,
    tags: Vec<String>,
    session: Option<Uuid>,
    host: Option<&MetricSample>,
    guest: Option<&MetricSample>,
    unreachable: Option<bool>,
) -> Reading {
    let cpu = guest.and_then(|g| g.cpu_pct).or_else(|| host.and_then(|h| h.cpu_pct));
    let memory = [guest, host]
        .into_iter()
        .flatten()
        .find_map(|s| s.mem_bytes.map(|used| pct(used, s.mem_total_bytes)))
        .flatten();
    let fullest = guest.and_then(|g| {
        g.mounts
            .iter()
            .max_by(|a, b| a.used_pct.total_cmp(&b.used_pct))
            .map(|m| (m.used_pct, m.mount.clone()))
    });
    let swap = guest.and_then(|g| g.swap_used_bytes.and_then(|used| pct(used, g.swap_total_bytes)));
    Reading {
        target,
        tags,
        session,
        cpu,
        memory,
        disk: fullest.as_ref().map(|(pct, _)| *pct),
        disk_mount: fullest.map(|(_, mount)| mount),
        swap,
        unreachable,
    }
}

/// The round's targets, as the dashboard's grid shows its rows: running VMs (and VMs whose linked session is
/// watched), watched hosts that are not a VM's, and this PC.
fn snapshot(now_ms: i64, hub: &MetricsHub, dir: &Directory) -> Snapshot {
    let statuses = hub.statuses();
    let running_keys = hub.running();
    let running: Option<HashSet<String>> = running_keys
        .as_ref()
        .map(|keys| keys.iter().map(|k| eval::target_key(k)).collect());
    let guest_of = |id: Uuid| {
        statuses
            .get(&id)
            .filter(|s| s.state == GuestState::Ok)
            .and_then(|_| hub.latest(MetricSource::Guest, &id.to_string()))
    };
    let reachable = |id: Uuid| match statuses.get(&id).map(|s| s.state) {
        Some(GuestState::Unreachable) => Some(true),
        Some(GuestState::Ok) => Some(false),
        _ => None,
    };
    let mut readings = Vec::new();
    let mut running_vms = Vec::new();
    let mut on_vm: HashSet<Uuid> = HashSet::new();
    let mut known: HashSet<String> = HashSet::new();
    for vm in &dir.vms {
        let key = eval::target_key(&vm.vmx_path);
        known.insert(key.clone());
        let linked = dir.by_vm.get(&vm.id).map(Vec::as_slice).unwrap_or_default();
        let watched = linked.iter().copied().find(|id| statuses.contains_key(id));
        let is_running = running.as_ref().is_some_and(|r| r.contains(&key));
        if !is_running && watched.is_none() {
            continue;
        }
        on_vm.extend(linked.iter().copied());
        let target = AlertTarget {
            kind: AlertTargetKind::Vm,
            key: vm.vmx_path.clone(),
            name: vm.display_name.clone(),
        };
        let host = is_running
            .then(|| hub.latest(MetricSource::Host, &vm.vmx_path))
            .flatten();
        let guest = watched.and_then(guest_of);
        // A VM that is off isn't "unreachable": the stopped rule says what happened to it.
        let unreachable = if is_running { watched.and_then(reachable) } else { None };
        readings.push(reading(
            target.clone(),
            vm.tags.clone(),
            watched,
            host.as_ref(),
            guest.as_ref(),
            unreachable,
        ));
        if is_running {
            running_vms.push(RunningVm {
                target,
                tags: vm.tags.clone(),
            });
        }
    }
    // Running VMs the inventory has not seen yet.
    for key in running_keys.iter().flatten() {
        if known.contains(&eval::target_key(key)) {
            continue;
        }
        let name = match Hypervisor::of_key(key) {
            Hypervisor::Vmware => Path::new(key)
                .file_stem()
                .map_or_else(|| key.clone(), |s| s.to_string_lossy().into_owned()),
            Hypervisor::VirtualBox => format!("VirtualBox VM {}", key.get(..8).unwrap_or(key)),
        };
        let target = AlertTarget {
            kind: AlertTargetKind::Vm,
            key: key.clone(),
            name,
        };
        let host = hub.latest(MetricSource::Host, key);
        readings.push(reading(target.clone(), Vec::new(), None, host.as_ref(), None, None));
        running_vms.push(RunningVm {
            target,
            tags: Vec::new(),
        });
    }
    for session in &dir.sessions {
        if !statuses.contains_key(&session.id) || on_vm.contains(&session.id) {
            continue;
        }
        let target = AlertTarget {
            kind: AlertTargetKind::Session,
            key: session.id.to_string(),
            name: session.name.clone(),
        };
        let guest = guest_of(session.id);
        readings.push(reading(
            target,
            session.tags.clone(),
            Some(session.id),
            None,
            guest.as_ref(),
            reachable(session.id),
        ));
    }
    let memory = hub.this_pc();
    readings.push(Reading {
        target: AlertTarget {
            kind: AlertTargetKind::ThisPc,
            key: THIS_PC_KEY.to_owned(),
            name: "This PC".to_owned(),
        },
        cpu: hub.host_cpu_pct(),
        memory: memory
            .as_ref()
            .and_then(|m| pct(m.ram_used_bytes, Some(m.ram_total_bytes))),
        swap: memory
            .as_ref()
            .and_then(|m| m.paging.as_ref())
            .and_then(|p| pct(p.used_bytes, Some(p.total_bytes))),
        ..Reading::default()
    });
    Snapshot {
        now_ms,
        readings,
        running: running_keys.map(|_| running_vms),
    }
}
