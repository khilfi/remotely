use super::*;
use crate::alerts::rules::Severity;

const ROUND: i64 = 5_000;
const T0: i64 = 1_792_000_000_000;

fn rule(metric: AlertMetric, scope: AlertScope, threshold: Option<f64>, for_secs: u64) -> AlertRule {
    AlertRule {
        id: Uuid::new_v4(),
        builtin: None,
        name: format!("{} rule", metric.label()),
        metric,
        scope,
        threshold,
        for_secs,
        severity: Severity::Warning,
        notify: true,
        enabled: true,
        updated_at: String::new(),
    }
}

fn vm(name: &str) -> AlertTarget {
    AlertTarget {
        kind: AlertTargetKind::Vm,
        key: format!(r"C:\VMs\{name}\{name}.vmx"),
        name: name.into(),
    }
}

fn host(id: Uuid) -> AlertTarget {
    AlertTarget {
        kind: AlertTargetKind::Session,
        key: id.to_string(),
        name: "db01".into(),
    }
}

fn cpu(target: AlertTarget, value: Option<f64>) -> Reading {
    Reading {
        target,
        cpu: value,
        ..Reading::default()
    }
}

fn snap(now_ms: i64, readings: Vec<Reading>) -> Snapshot {
    Snapshot {
        now_ms,
        readings,
        running: None,
    }
}

fn fired(out: &[Transition]) -> Vec<(&str, bool)> {
    out.iter()
        .filter_map(|t| match t {
            Transition::Fired { alert, notify } => Some((alert.target.name.as_str(), *notify)),
            Transition::Resolved { .. } => None,
        })
        .collect()
}

fn resolutions(out: &[Transition]) -> Vec<Resolution> {
    out.iter()
        .filter_map(|t| match t {
            Transition::Resolved { resolution, .. } => Some(*resolution),
            Transition::Fired { .. } => None,
        })
        .collect()
}

/// Runs `rounds` rounds of `reading` every 5 s from `start`; returns every transition and the time after.
fn run(
    eval: &mut Evaluator,
    rules: &[AlertRule],
    start: i64,
    rounds: i64,
    reading: impl Fn(i64) -> Vec<Reading>,
) -> (Vec<Transition>, i64) {
    let mut out = Vec::new();
    let mut t = start;
    for _ in 0..rounds {
        out.extend(eval.evaluate(rules, &snap(t, reading(t)), &HashSet::new()));
        t += ROUND;
    }
    (out, t)
}

#[test]
fn a_reading_above_the_threshold_fires_once_it_has_held_for_the_duration() {
    let rules = [rule(AlertMetric::Cpu, AlertScope::AllVms, Some(90.0), 300)];
    let mut eval = Evaluator::default();
    // 4 min 55 s above: not yet. At 5 minutes: fired, once.
    let (out, t) = run(&mut eval, &rules, T0, 60, |_| vec![cpu(vm("web"), Some(95.0))]);
    assert!(out.is_empty(), "{out:?}");
    let (out, t) = run(&mut eval, &rules, t, 10, |_| vec![cpu(vm("web"), Some(97.0))]);
    assert_eq!(fired(&out), [("web", true)]);
    let Transition::Fired { alert, .. } = &out[0] else {
        panic!("not fired")
    };
    assert_eq!(alert.value, Some(97.0));
    assert_eq!(alert.message, "CPU at 97%, above 90% for 5 minutes");
    assert_eq!(alert.fired_at, rfc3339(T0 + 300_000));
    // At the threshold is not above it; one round under resets the clock of a rule not yet fired.
    let mut eval = Evaluator::default();
    let (out, _) = run(&mut eval, &rules, t, 100, |t| {
        let v = if (t / ROUND) % 50 == 0 { 90.0 } else { 99.0 };
        vec![cpu(vm("db"), Some(v))]
    });
    assert!(out.is_empty(), "never 5 minutes in a row above 90%: {out:?}");
}

#[test]
fn an_alert_resolves_after_a_minute_under_the_threshold_and_keeps_its_peak() {
    let rules = [rule(AlertMetric::Memory, AlertScope::AllVms, Some(80.0), 0)];
    let mut eval = Evaluator::default();
    let reading = |v: f64| {
        vec![Reading {
            target: vm("web"),
            memory: Some(v),
            ..Reading::default()
        }]
    };
    let out = eval.evaluate(&rules, &snap(T0, reading(85.0)), &HashSet::new());
    assert_eq!(fired(&out), [("web", true)], "no duration: at once");
    let out = eval.evaluate(&rules, &snap(T0 + ROUND, reading(93.0)), &HashSet::new());
    assert!(out.is_empty());
    // 55 s under, then back above: still the same alert.
    let (out, t) = run(&mut eval, &rules, T0 + 2 * ROUND, 12, |_| reading(50.0));
    assert!(out.is_empty(), "{out:?}");
    let (out, t) = run(&mut eval, &rules, t, 1, |_| reading(81.0));
    assert!(out.is_empty(), "the dip was too short to resolve it");
    // A full minute under: resolved, with the worst reading.
    let (out, _) = run(&mut eval, &rules, t, 13, |_| reading(10.0));
    assert_eq!(resolutions(&out), [Resolution::Cleared]);
    let Transition::Resolved { peak, .. } = out[0] else {
        panic!("not resolved")
    };
    assert_eq!(peak, Some(93.0));
}

#[test]
fn a_missing_reading_stops_the_clock_and_leaves_a_firing_alert_as_it_is() {
    let rules = [rule(AlertMetric::Disk, AlertScope::AllHosts, Some(85.0), 60)];
    let id = Uuid::new_v4();
    let reading = |v: Option<f64>| {
        vec![Reading {
            target: host(id),
            session: Some(id),
            disk: v,
            disk_mount: Some("/var".into()),
            ..Reading::default()
        }]
    };
    let mut eval = Evaluator::default();
    let (out, t) = run(&mut eval, &rules, T0, 6, |_| reading(Some(90.0)));
    assert!(out.is_empty());
    // The host can't be read for a while: the minute starts again afterwards.
    let (out, t) = run(&mut eval, &rules, t, 3, |_| reading(None));
    assert!(out.is_empty());
    let (out, t) = run(&mut eval, &rules, t, 12, |_| reading(Some(90.0)));
    assert!(out.is_empty(), "55 s since the readings came back");
    let (out, t) = run(&mut eval, &rules, t, 1, |_| reading(Some(91.0)));
    assert_eq!(fired(&out), [("db01", true)]);
    let Transition::Fired { alert, .. } = &out[0] else {
        panic!("not fired")
    };
    assert_eq!(alert.message, "Disk 91% full on /var, above 85% for 1 minute");
    // No readings for a long time: it neither resolves nor fires again.
    let (out, _) = run(&mut eval, &rules, t, 100, |_| reading(None));
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn a_rule_notifies_once_per_target_in_half_an_hour() {
    let mut rules = [rule(AlertMetric::Cpu, AlertScope::AllVms, Some(50.0), 0)];
    let mut eval = Evaluator::default();
    let flap = |eval: &mut Evaluator, rules: &[AlertRule], t: i64| {
        let mut out = eval.evaluate(rules, &snap(t, vec![cpu(vm("web"), Some(99.0))]), &HashSet::new());
        let (resolved, after) = run(eval, rules, t + ROUND, 13, |_| vec![cpu(vm("web"), Some(1.0))]);
        out.extend(resolved);
        (out, after)
    };
    let (out, t) = flap(&mut eval, &rules, T0);
    assert_eq!(fired(&out), [("web", true)]);
    assert_eq!(resolutions(&out), [Resolution::Cleared]);
    let (out, _) = flap(&mut eval, &rules, t);
    assert_eq!(
        fired(&out),
        [("web", false)],
        "fired again, listed, but no second notification"
    );
    let (out, t) = flap(&mut eval, &rules, T0 + COOLDOWN_MS);
    assert_eq!(fired(&out), [("web", true)], "half an hour after the first");
    // Another target has its own cooldown; a rule that doesn't notify never does.
    let out = eval.evaluate(&rules, &snap(t, vec![cpu(vm("db"), Some(99.0))]), &HashSet::new());
    assert_eq!(fired(&out), [("db", true)]);
    rules[0].notify = false;
    let mut quiet = Evaluator::default();
    let out = quiet.evaluate(&rules, &snap(T0, vec![cpu(vm("web"), Some(99.0))]), &HashSet::new());
    assert_eq!(fired(&out), [("web", false)]);
}

#[test]
fn an_unreachable_host_fires_after_the_duration_and_resolves_when_it_answers() {
    let rules = [rule(AlertMetric::Unreachable, AlertScope::AllHosts, None, 300)];
    let id = Uuid::new_v4();
    let reading = |down: Option<bool>| {
        vec![Reading {
            target: host(id),
            session: Some(id),
            unreachable: down,
            ..Reading::default()
        }]
    };
    let mut eval = Evaluator::default();
    let (out, t) = run(&mut eval, &rules, T0, 60, |_| reading(Some(true)));
    assert!(out.is_empty());
    let (out, t) = run(&mut eval, &rules, t, 1, |_| reading(Some(true)));
    assert_eq!(fired(&out), [("db01", true)]);
    let Transition::Fired { alert, .. } = &out[0] else {
        panic!("not fired")
    };
    assert_eq!(alert.message, "Not reachable for 5 minutes");
    assert_eq!(alert.value, None);
    // Logging in needs the vault for a while: neither down nor up.
    let (out, t) = run(&mut eval, &rules, t, 30, |_| reading(None));
    assert!(out.is_empty());
    let (out, _) = run(&mut eval, &rules, t, 13, |_| reading(Some(false)));
    assert_eq!(resolutions(&out), [Resolution::Cleared]);
}

fn running(names: &[&str]) -> Option<Vec<RunningVm>> {
    Some(
        names
            .iter()
            .map(|n| RunningVm {
                target: vm(n),
                tags: vec!["web".into()],
            })
            .collect(),
    )
}

#[test]
fn a_vm_that_stops_without_a_remotely_job_fires_and_resolves_when_it_runs_again() {
    let rules = [rule(AlertMetric::Stopped, AlertScope::AllVms, None, 0)];
    let mut eval = Evaluator::default();
    let round = |eval: &mut Evaluator, t: i64, names: &[&str], by_remotely: &[&str]| {
        let snapshot = Snapshot {
            now_ms: t,
            readings: Vec::new(),
            running: running(names),
        };
        let gone = eval.stopped_vms(&snapshot);
        let by: HashSet<String> = gone
            .iter()
            .filter(|k| by_remotely.iter().any(|n| target_key(&vm(n).key) == **k))
            .cloned()
            .collect();
        (gone, eval.evaluate(&rules, &snapshot, &by))
    };
    // The first round only learns what runs.
    let (gone, out) = round(&mut eval, T0, &["web", "db", "ci"], &[]);
    assert!(gone.is_empty() && out.is_empty());
    // db stopped by a Remotely job, web outside the app.
    let (gone, out) = round(&mut eval, T0 + ROUND, &["ci"], &["db"]);
    assert_eq!(gone.len(), 2);
    assert_eq!(fired(&out), [("web", true)]);
    let Transition::Fired { alert, .. } = &out[0] else {
        panic!("not fired")
    };
    assert_eq!(alert.metric, AlertMetric::Stopped);
    assert!(alert.message.starts_with("Stopped without a Remotely action"));
    // Still off: no second alert, and nothing new to ask about.
    let (gone, out) = round(&mut eval, T0 + 2 * ROUND, &["ci"], &[]);
    assert!(gone.is_empty() && out.is_empty());
    // web runs again: resolved.
    let (_, out) = round(&mut eval, T0 + 3 * ROUND, &["ci", "web"], &[]);
    assert_eq!(resolutions(&out), [Resolution::Cleared]);
    // A round where the host side couldn't be read lists nothing: nothing stopped.
    let snapshot = Snapshot {
        now_ms: T0 + 4 * ROUND,
        readings: Vec::new(),
        running: None,
    };
    assert!(eval.stopped_vms(&snapshot).is_empty());
    assert!(eval.evaluate(&rules, &snapshot, &HashSet::new()).is_empty());
}

#[test]
fn a_stopped_rule_with_a_duration_waits_for_the_vm_to_stay_off() {
    let rules = [rule(
        AlertMetric::Stopped,
        AlertScope::Tag { tag: "WEB".into() },
        None,
        120,
    )];
    let mut eval = Evaluator::default();
    let at = |eval: &mut Evaluator, t: i64, names: &[&str]| {
        eval.evaluate(
            &rules,
            &Snapshot {
                now_ms: t,
                readings: Vec::new(),
                running: running(names),
            },
            &HashSet::new(),
        )
    };
    assert!(at(&mut eval, T0, &["web"]).is_empty());
    // Off for a minute, then back: no alert.
    assert!(at(&mut eval, T0 + ROUND, &[]).is_empty());
    assert!(at(&mut eval, T0 + 60_000, &[]).is_empty());
    assert!(at(&mut eval, T0 + 65_000, &["web"]).is_empty());
    // Off for two minutes: fired.
    assert!(at(&mut eval, T0 + 70_000, &[]).is_empty());
    let out = at(&mut eval, T0 + 70_000 + 120_000, &[]);
    assert_eq!(fired(&out), [("web", true)]);
}

#[test]
fn targets_leaving_the_scope_and_rules_turned_off_resolve_their_alerts() {
    let mut rules = vec![
        rule(AlertMetric::Cpu, AlertScope::AllVms, Some(50.0), 0),
        rule(AlertMetric::Cpu, AlertScope::ThisPc, Some(50.0), 0),
    ];
    let this_pc = AlertTarget {
        kind: AlertTargetKind::ThisPc,
        key: "this-pc".into(),
        name: "This PC".into(),
    };
    let mut eval = Evaluator::default();
    let both = vec![
        cpu(vm("web"), Some(99.0)),
        cpu(vm("db"), Some(99.0)),
        cpu(this_pc.clone(), Some(99.0)),
    ];
    let out = eval.evaluate(&rules, &snap(T0, both), &HashSet::new());
    assert_eq!(fired(&out), [("web", true), ("db", true), ("This PC", true)]);
    // db stopped running: gone.
    let out = eval.evaluate(
        &rules,
        &snap(
            T0 + ROUND,
            vec![cpu(vm("web"), Some(99.0)), cpu(this_pc.clone(), Some(99.0))],
        ),
        &HashSet::new(),
    );
    assert_eq!(resolutions(&out), [Resolution::Gone]);
    // This PC's rule turned off: its alert resolves as the rule changed.
    rules[1].enabled = false;
    let out = eval.evaluate(
        &rules,
        &snap(
            T0 + 2 * ROUND,
            vec![cpu(vm("web"), Some(99.0)), cpu(this_pc, Some(99.0))],
        ),
        &HashSet::new(),
    );
    assert_eq!(resolutions(&out), [Resolution::RuleChanged]);
    // An edited rule forgets its firing alerts, which the caller resolves.
    let firing = eval.forget_rule(rules[0].id);
    assert_eq!(firing.len(), 1);
    assert!(eval.forget_rule(rules[0].id).is_empty());
}

#[test]
fn scopes_cover_what_they_name() {
    let id = Uuid::new_v4();
    let web = vm("web");
    let tags = vec!["Web".to_owned()];
    let scope_vm = AlertScope::Vm {
        key: r"c:/vms/WEB/web.vmx".into(),
    };
    assert!(covers(&scope_vm, &web, &[], None), "any spelling of the same .vmx");
    assert!(!covers(&scope_vm, &vm("db"), &[], None));
    assert!(covers(&AlertScope::AllVms, &web, &[], None));
    assert!(!covers(&AlertScope::AllVms, &host(id), &[], Some(id)));
    assert!(covers(&AlertScope::Tag { tag: "web".into() }, &web, &tags, None));
    assert!(!covers(&AlertScope::Tag { tag: "db".into() }, &web, &tags, None));
    assert!(
        covers(&AlertScope::Host { session_id: id }, &web, &[], Some(id)),
        "a VM's watched guest"
    );
    assert!(covers(&AlertScope::AllHosts, &host(id), &[], Some(id)));
    assert!(!covers(&AlertScope::AllHosts, &web, &[], None), "a VM nobody watches");
    let this_pc = AlertTarget {
        kind: AlertTargetKind::ThisPc,
        key: "this-pc".into(),
        name: "This PC".into(),
    };
    assert!(covers(&AlertScope::ThisPc, &this_pc, &[], None));
    assert!(!covers(&AlertScope::Tag { tag: "web".into() }, &this_pc, &tags, None));
}

/// MO-08: a health check as the checks service reads it to the rules.
fn check(name: &str, down: Option<bool>, ms: Option<f64>, days: Option<f64>) -> Reading {
    Reading {
        target: AlertTarget {
            kind: AlertTargetKind::Check,
            key: format!("00000000-0000-0000-0000-00000000000{}", name.len()),
            name: name.into(),
        },
        check_down: down,
        check_ms: ms,
        cert_days: days,
        check_detail: Some("port 443: closed (connection refused)".into()),
        ..Reading::default()
    }
}

#[test]
fn a_check_down_fires_at_once_and_resolves_a_minute_after_it_is_up() {
    let rules = [rule(AlertMetric::CheckDown, AlertScope::AllChecks, None, 0)];
    let mut eval = Evaluator::default();
    let (out, t) = run(&mut eval, &rules, T0, 3, |_| {
        vec![check("web", Some(false), Some(20.0), None)]
    });
    assert!(out.is_empty(), "{out:?}");
    let (out, t) = run(&mut eval, &rules, t, 1, |_| vec![check("web", Some(true), None, None)]);
    assert_eq!(fired(&out), [("web", true)]);
    let Transition::Fired { alert, .. } = &out[0] else {
        panic!("not fired")
    };
    assert_eq!(alert.message, "Down: port 443: closed (connection refused)");
    // No result (Remotely could not check) leaves it as it is.
    let (out, t) = run(&mut eval, &rules, t, 20, |_| vec![check("web", None, None, None)]);
    assert!(out.is_empty(), "{out:?}");
    let (out, _) = run(&mut eval, &rules, t, 13, |_| {
        vec![check("web", Some(false), Some(12.0), None)]
    });
    assert_eq!(resolutions(&out), [Resolution::Cleared]);
    // Rules on VMs and hosts never see a check.
    let vm_rules = [rule(AlertMetric::Unreachable, AlertScope::AllHosts, None, 0)];
    let (out, _) = run(&mut Evaluator::default(), &vm_rules, T0, 3, |_| {
        vec![check("web", Some(true), None, None)]
    });
    assert!(out.is_empty());
}

#[test]
fn slow_checks_fire_above_and_certificates_below_their_threshold() {
    let one = check("web", Some(false), Some(900.0), Some(10.0));
    let rules = [
        rule(AlertMetric::CheckSlow, AlertScope::AllChecks, Some(500.0), 0),
        rule(AlertMetric::CertExpiring, AlertScope::AllChecks, Some(14.0), 0),
    ];
    let mut eval = Evaluator::default();
    let out = eval.evaluate(&rules, &snap(T0, vec![one.clone()]), &HashSet::new());
    assert_eq!(fired(&out).len(), 2);
    // The peak of an expiring certificate is its fewest days left.
    let fewer = check("web", Some(false), Some(100.0), Some(8.0));
    eval.evaluate(&rules, &snap(T0 + ROUND, vec![fewer]), &HashSet::new());
    let renewed = check("web", Some(false), Some(100.0), Some(90.0));
    let (out, _) = run(&mut eval, &rules, T0 + 2 * ROUND, 14, |_| vec![renewed.clone()]);
    let peaks: Vec<Option<f64>> = out
        .iter()
        .filter_map(|t| match t {
            Transition::Resolved { peak, .. } => Some(*peak),
            Transition::Fired { .. } => None,
        })
        .collect();
    assert_eq!(peaks.len(), 2, "{out:?}");
    assert!(peaks.contains(&Some(8.0)), "{peaks:?}");
    assert!(peaks.contains(&Some(900.0)), "{peaks:?}");
}

#[test]
fn a_check_scope_covers_that_check_only_and_a_paused_check_resolves_as_gone() {
    let web = check("web", Some(true), None, None);
    let id = Uuid::parse_str(&web.target.key).unwrap();
    assert!(covers(&AlertScope::Check { check_id: id }, &web.target, &[], None));
    assert!(!covers(
        &AlertScope::Check {
            check_id: Uuid::new_v4()
        },
        &web.target,
        &[],
        None
    ));
    assert!(covers(&AlertScope::AllChecks, &web.target, &[], None));
    assert!(!covers(&AlertScope::AllVms, &web.target, &[], None));
    let rules = [rule(
        AlertMetric::CheckDown,
        AlertScope::Check { check_id: id },
        None,
        0,
    )];
    let mut eval = Evaluator::default();
    assert_eq!(
        fired(&eval.evaluate(&rules, &snap(T0, vec![web]), &HashSet::new())).len(),
        1
    );
    let out = eval.evaluate(&rules, &snap(T0 + ROUND, Vec::new()), &HashSet::new());
    assert_eq!(resolutions(&out), [Resolution::Gone]);
}
