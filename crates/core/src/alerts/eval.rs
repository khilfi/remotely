//! MO-07: rules evaluated against each round, as a state machine with no I/O (tested on its own).
//!
//! For each enabled rule and each target in its scope, one track:
//! * a reading above the threshold (or unreachable) starts the clock; once it has held for the rule's duration
//!   the alert **fires**;
//! * a reading at or below it (or reachable again) for [`RESOLVE_AFTER_MS`] **resolves** it, so a value
//!   hovering at the threshold doesn't fire and resolve every round;
//! * no reading (a guest that can't be read just now) stops the clock and leaves a firing alert as it is;
//! * a target that left the scope (a VM no longer running, a host no longer watched) resolves its alerts as
//!   gone, and a rule turned off or changed resolves its own.
//!
//! A VM that stopped is noticed by the running list: a VM the last round listed that this one doesn't. The
//! caller says which of those a Remotely job was acting on; the rest fire their rules' "stopped" alerts once
//! they have stayed off for the rule's duration, and resolve when the VM runs again.
//!
//! A rule notifies at most once per target in [`COOLDOWN_MS`], however often it fires.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use super::rules::{message, AlertMetric, AlertRule, AlertScope};
use super::{Alert, AlertTarget, AlertTargetKind, Resolution};
use crate::adapters::vmware::path_key;

/// How long a condition must stay clear before its alert resolves.
pub const RESOLVE_AFTER_MS: i64 = 60_000;

/// The least time between two notifications of one rule for one target.
pub const COOLDOWN_MS: i64 = 30 * 60_000;

/// One target's readings in a round, as the dashboard's grid shows them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Reading {
    pub target: AlertTarget,
    /// Its tags (VM-02, SS-06).
    pub tags: Vec<String>,
    /// The watched session behind its guest readings, if any.
    pub session: Option<Uuid>,
    pub cpu: Option<f64>,
    pub memory: Option<f64>,
    pub disk: Option<f64>,
    /// The fullest disk's mount point.
    pub disk_mount: Option<String>,
    pub swap: Option<f64>,
    /// `Some(true)` while its watched guest can't be reached, `Some(false)` while it answers, `None` otherwise.
    pub unreachable: Option<bool>,
}

/// A VM whose process a round saw.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RunningVm {
    pub target: AlertTarget,
    pub tags: Vec<String>,
}

/// What a round gives the rules.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot {
    pub now_ms: i64,
    pub readings: Vec<Reading>,
    /// The running VMs; `None` until the host side has been read.
    pub running: Option<Vec<RunningVm>>,
}

/// What the caller does after a round.
#[derive(Debug, Clone, PartialEq)]
pub enum Transition {
    /// A new alert: store it, tell the UI, and notify when `notify`.
    Fired { alert: Box<Alert>, notify: bool },
    Resolved {
        alert_id: Uuid,
        resolution: Resolution,
        /// The worst reading while it fired.
        peak: Option<f64>,
        at_ms: i64,
    },
}

#[derive(Debug, Clone, Default)]
struct Firing {
    alert_id: Uuid,
    peak: Option<f64>,
}

#[derive(Debug, Clone)]
struct Track {
    metric: AlertMetric,
    breach_since: Option<i64>,
    clear_since: Option<i64>,
    firing: Option<Firing>,
}

impl Track {
    fn new(metric: AlertMetric) -> Self {
        Self {
            metric,
            breach_since: None,
            clear_since: None,
            firing: None,
        }
    }
}

/// A VM noticed off.
#[derive(Debug, Clone)]
struct Stop {
    vm: RunningVm,
    since_ms: i64,
    /// A Remotely job was acting on it: no alert.
    by_remotely: bool,
}

/// How a rule's condition stands for a target this round.
enum Condition {
    Breach(Option<f64>),
    Clear,
    Unknown,
}

/// The same VM whatever the spelling of its .vmx path (letter case, `/` or `\`); a UUID in lower case.
pub fn target_key(key: &str) -> String {
    path_key(std::path::Path::new(key))
}

/// Whether `scope` covers a target with these tags and watched session.
pub fn covers(scope: &AlertScope, target: &AlertTarget, tags: &[String], session: Option<Uuid>) -> bool {
    match scope {
        AlertScope::AllVms => target.kind == AlertTargetKind::Vm,
        AlertScope::Vm { key } => target.kind == AlertTargetKind::Vm && target_key(key) == target_key(&target.key),
        AlertScope::Tag { tag } => {
            target.kind != AlertTargetKind::ThisPc && tags.iter().any(|t| t.to_lowercase() == tag.to_lowercase())
        }
        AlertScope::Host { session_id } => session == Some(*session_id),
        AlertScope::AllHosts => session.is_some(),
        AlertScope::ThisPc => target.kind == AlertTargetKind::ThisPc,
    }
}

fn condition(rule: &AlertRule, reading: &Reading) -> Condition {
    let value = match rule.metric {
        AlertMetric::Cpu => reading.cpu,
        AlertMetric::Memory => reading.memory,
        AlertMetric::Disk => reading.disk,
        AlertMetric::Swap => reading.swap,
        AlertMetric::Unreachable => {
            return match reading.unreachable {
                Some(true) => Condition::Breach(None),
                Some(false) => Condition::Clear,
                None => Condition::Unknown,
            };
        }
        AlertMetric::Stopped => return Condition::Unknown,
    };
    match (value.filter(|v| v.is_finite()), rule.threshold) {
        (Some(v), Some(t)) if v > t => Condition::Breach(Some(v)),
        (Some(_), Some(_)) => Condition::Clear,
        _ => Condition::Unknown,
    }
}

/// RFC 3339 UTC, to the second.
pub fn rfc3339(ms: i64) -> String {
    let at = time::OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000)).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

fn worse(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// The rules' state between rounds.
#[derive(Debug, Default)]
pub struct Evaluator {
    /// By rule and target key ([`target_key`]).
    tracks: HashMap<(Uuid, String), Track>,
    /// VMs noticed off, by key.
    stops: HashMap<String, Stop>,
    /// The last round's running VMs, by key.
    running: Option<HashMap<String, RunningVm>>,
    /// When each rule last notified for each target.
    notified: HashMap<(Uuid, String), i64>,
}

impl Evaluator {
    /// VMs the last round listed as running that this one doesn't: the caller asks whether a Remotely job was
    /// acting on each before [`Evaluator::evaluate`].
    pub fn stopped_vms(&self, snapshot: &Snapshot) -> Vec<String> {
        let (Some(before), Some(now)) = (&self.running, &snapshot.running) else {
            return Vec::new();
        };
        let now: HashSet<String> = now.iter().map(|vm| target_key(&vm.target.key)).collect();
        let mut gone: Vec<String> = before
            .keys()
            .filter(|key| !now.contains(*key) && !self.stops.contains_key(*key))
            .cloned()
            .collect();
        gone.sort();
        gone
    }

    /// One round: what fires and what resolves. `by_remotely` holds the keys of stopped VMs a Remotely job was
    /// acting on.
    pub fn evaluate(
        &mut self,
        rules: &[AlertRule],
        snapshot: &Snapshot,
        by_remotely: &HashSet<String>,
    ) -> Vec<Transition> {
        let now = snapshot.now_ms;
        self.follow_running(snapshot, by_remotely);
        let mut out = Vec::new();
        let mut seen: HashSet<(Uuid, String)> = HashSet::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            if rule.metric == AlertMetric::Stopped {
                self.evaluate_stops(rule, now, &mut seen, &mut out);
                continue;
            }
            for reading in &snapshot.readings {
                if !covers(&rule.scope, &reading.target, &reading.tags, reading.session) {
                    continue;
                }
                let key = (rule.id, target_key(&reading.target.key));
                seen.insert(key.clone());
                let condition = condition(rule, reading);
                let track = self
                    .tracks
                    .entry(key.clone())
                    .or_insert_with(|| Track::new(rule.metric));
                match condition {
                    Condition::Breach(value) => {
                        track.clear_since = None;
                        let since = *track.breach_since.get_or_insert(now);
                        if let Some(firing) = track.firing.as_mut() {
                            firing.peak = worse(firing.peak, value);
                        } else if now - since >= ms(rule.for_secs) {
                            let alert = Box::new(new_alert(
                                rule,
                                &reading.target,
                                value,
                                reading.disk_mount.as_deref(),
                                now,
                            ));
                            track.firing = Some(Firing {
                                alert_id: alert.id,
                                peak: value,
                            });
                            let notify = self.may_notify(rule, &key, now);
                            out.push(Transition::Fired { alert, notify });
                        }
                    }
                    Condition::Clear => {
                        track.breach_since = None;
                        if track.firing.is_some() {
                            let since = *track.clear_since.get_or_insert(now);
                            if now - since >= RESOLVE_AFTER_MS {
                                if let Some(firing) = track.firing.take() {
                                    out.push(resolved(firing, Resolution::Cleared, now));
                                }
                                track.clear_since = None;
                            }
                        }
                    }
                    Condition::Unknown => {
                        track.breach_since = None;
                        track.clear_since = None;
                    }
                }
            }
        }
        // Tracks no rule looked at this round: their rule is off or changed, or their target left the scope.
        let enabled: HashSet<Uuid> = rules.iter().filter(|r| r.enabled).map(|r| r.id).collect();
        let running: HashSet<String> = snapshot
            .running
            .iter()
            .flatten()
            .map(|vm| target_key(&vm.target.key))
            .collect();
        let gone: Vec<(Uuid, String)> = self.tracks.keys().filter(|k| !seen.contains(*k)).cloned().collect();
        for key in gone {
            let Some(track) = self.tracks.remove(&key) else {
                continue;
            };
            let Some(firing) = track.firing else {
                continue;
            };
            let resolution = if !enabled.contains(&key.0) {
                Resolution::RuleChanged
            } else if track.metric == AlertMetric::Stopped && running.contains(&key.1) {
                Resolution::Cleared
            } else {
                Resolution::Gone
            };
            out.push(resolved(firing, resolution, now));
        }
        out
    }

    /// The firing alerts of `rule_id`, forgotten with its tracks: the rule changed or went.
    pub fn forget_rule(&mut self, rule_id: Uuid) -> Vec<Uuid> {
        let keys: Vec<(Uuid, String)> = self.tracks.keys().filter(|k| k.0 == rule_id).cloned().collect();
        let mut firing = Vec::new();
        for key in keys {
            if let Some(f) = self.tracks.remove(&key).and_then(|t| t.firing) {
                firing.push(f.alert_id);
            }
        }
        self.notified.retain(|k, _| k.0 != rule_id);
        firing
    }

    /// Notes which VMs went off since the last round and which run again.
    fn follow_running(&mut self, snapshot: &Snapshot, by_remotely: &HashSet<String>) {
        let Some(now) = &snapshot.running else {
            return;
        };
        let now: HashMap<String, RunningVm> = now.iter().map(|vm| (target_key(&vm.target.key), vm.clone())).collect();
        if let Some(before) = &self.running {
            for (key, vm) in before {
                if !now.contains_key(key) && !self.stops.contains_key(key) {
                    self.stops.insert(
                        key.clone(),
                        Stop {
                            vm: vm.clone(),
                            since_ms: snapshot.now_ms,
                            by_remotely: by_remotely.contains(key),
                        },
                    );
                }
            }
        }
        self.stops.retain(|key, _| !now.contains_key(key));
        self.running = Some(now);
    }

    fn evaluate_stops(
        &mut self,
        rule: &AlertRule,
        now: i64,
        seen: &mut HashSet<(Uuid, String)>,
        out: &mut Vec<Transition>,
    ) {
        let mut keys: Vec<&String> = self.stops.keys().collect();
        keys.sort();
        let mut fired = Vec::new();
        for key in keys {
            let stop = &self.stops[key];
            if stop.by_remotely || !covers(&rule.scope, &stop.vm.target, &stop.vm.tags, None) {
                continue;
            }
            let track_key = (rule.id, key.clone());
            seen.insert(track_key.clone());
            let track = self
                .tracks
                .entry(track_key.clone())
                .or_insert_with(|| Track::new(rule.metric));
            if track.firing.is_none() && now - stop.since_ms >= ms(rule.for_secs) {
                let alert = Box::new(new_alert(rule, &stop.vm.target, None, None, now));
                track.firing = Some(Firing {
                    alert_id: alert.id,
                    peak: None,
                });
                fired.push((alert, track_key));
            }
        }
        for (alert, key) in fired {
            let notify = self.may_notify(rule, &key, now);
            out.push(Transition::Fired { alert, notify });
        }
    }

    fn may_notify(&mut self, rule: &AlertRule, key: &(Uuid, String), now: i64) -> bool {
        if !rule.notify {
            return false;
        }
        if self.notified.get(key).is_some_and(|at| now - at < COOLDOWN_MS) {
            return false;
        }
        self.notified.insert(key.clone(), now);
        true
    }
}

fn ms(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX)
}

fn resolved(firing: Firing, resolution: Resolution, now: i64) -> Transition {
    Transition::Resolved {
        alert_id: firing.alert_id,
        resolution,
        peak: firing.peak,
        at_ms: now,
    }
}

fn new_alert(rule: &AlertRule, target: &AlertTarget, value: Option<f64>, mount: Option<&str>, now: i64) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        rule_id: rule.id,
        rule_name: rule.name.clone(),
        metric: rule.metric,
        severity: rule.severity,
        target: target.clone(),
        threshold: rule.threshold,
        for_secs: rule.for_secs,
        value,
        peak: value,
        message: message(rule, value, mount),
        fired_at: rfc3339(now),
        resolved_at: None,
        resolution: None,
        acknowledged_at: None,
    }
}

#[cfg(test)]
mod tests;
