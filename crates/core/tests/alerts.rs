//! MO-07: alert rules evaluated on the metrics rounds, end to end through the core with fakes: VM CPU from
//! the host counters, a VM stopped outside the app or by a Remotely job, a watched host that can't be
//! reached, the alert list, acknowledging, events, the audit log and the read-only lock.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{vm, vmx, wait_finished, Setup};
use remotely_core::adapters::host_counters::VmProcess;
use remotely_core::adapters::remote::AgentSource;
use remotely_core::adapters::virtualbox::VirtualBoxAdapter;
use remotely_core::adapters::vmware::VmwareAdapter;
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::alerts::{
    AlertEvent, AlertMetric, AlertQuery, AlertRuleInput, AlertScope, AlertTargetKind, Resolution, Severity,
};
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SubmitOutcome};
use remotely_core::domain::Environment;
use remotely_core::fakes::{FakeHostCounters, FakeVault, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::metrics::GuestTuning;
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::Store;
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::{Adapters, Core};
use uuid::Uuid;

const GB: u64 = 1024 * 1024 * 1024;
const ROUND: i64 = 5_000;

/// The first round's time: now, so the job journal's times (the wall clock) fall in the alert's window.
fn t0() -> i64 {
    remotely_core::metrics::history::now_ms()
}

fn process(pid: u32, name: &str, host_cpu: f64) -> VmProcess {
    VmProcess {
        pid,
        vmx_path: Some(vmx(name)),
        name: None,
        cpu_pct: Some(host_cpu),
        working_set_bytes: Some(GB),
        read_bps: Some(1_000.0),
        write_bps: Some(2_000.0),
    }
}

/// Workstation with `names` running, each 2 vCPUs and 4 GB, on the fake 16-CPU host.
fn workstation(names: &[&str]) -> FakeVmware {
    let mut fake = FakeVmware::with_running(names.iter().map(|n| vmx(n)));
    for name in names {
        fake = fake.in_library(&vmx(name), Some(name)).with_vmx(
            &vmx(name),
            VmxInfo {
                display_name: Some((*name).into()),
                num_vcpus: Some(2),
                memsize_mb: Some(4096),
                ..Default::default()
            },
        );
    }
    fake
}

async fn core_with(names: &[&str]) -> (Core, Arc<std::sync::Mutex<Vec<VmProcess>>>, Arc<FakeVmware>) {
    let setup = Setup::new(workstation(names));
    let processes = Arc::clone(&setup.host.processes);
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    (core, processes, fake)
}

fn rule_input(metric: AlertMetric, scope: AlertScope, threshold: Option<f64>, for_secs: u64) -> AlertRuleInput {
    AlertRuleInput {
        name: format!("{} test", metric.label()),
        metric,
        scope,
        threshold,
        for_secs,
        severity: Severity::Critical,
        notify: true,
        enabled: true,
    }
}

/// Turns every built-in rule off, so a test sees only its own.
async fn only_my_rules(core: &Core) {
    for rule in core.alerts.rules() {
        if rule.enabled {
            let mut input = rule.input();
            input.enabled = false;
            core.alerts.update_rule(rule.id, input).await.unwrap();
        }
    }
}

async fn rounds(core: &Core, from: i64, count: i64) -> i64 {
    let mut t = from;
    for _ in 0..count {
        core.metrics.collect_once_at(t).await;
        t += ROUND;
    }
    t
}

fn drain(events: &mut tokio::sync::broadcast::Receiver<AlertEvent>) -> Vec<AlertEvent> {
    let mut out = Vec::new();
    while let Ok(event) = events.try_recv() {
        out.push(event);
    }
    out
}

#[tokio::test]
async fn built_in_rules_are_there_once_and_the_quiet_ones_start_off() {
    let (core, _, _) = core_with(&[]).await;
    let rules = core.alerts.rules();
    let keys: Vec<(&str, bool)> = rules
        .iter()
        .map(|r| (r.builtin.as_deref().unwrap(), r.enabled))
        .collect();
    assert_eq!(
        keys,
        [
            ("vm-stopped", true),
            ("host-disk", true),
            ("host-unreachable", true),
            ("this-pc-memory", true),
            ("vm-cpu", false),
            ("vm-memory", false),
            ("host-cpu", false),
        ]
    );
    // A built-in rule keeps its metric and scope, and can't be deleted; reset puts it back.
    let cpu = rules.iter().find(|r| r.builtin.as_deref() == Some("vm-cpu")).unwrap();
    let mut changed = cpu.input();
    changed.scope = AlertScope::ThisPc;
    let err = core.alerts.update_rule(cpu.id, changed).await.unwrap_err();
    assert!(err.to_string().contains("metric and scope"), "{err}");
    let err = core.alerts.delete_rule(cpu.id).await.unwrap_err();
    assert!(err.to_string().contains("Turn it off"), "{err}");
    let mut on = cpu.input();
    on.enabled = true;
    on.threshold = Some(75.0);
    on.name = "renamed".into();
    let updated = core.alerts.update_rule(cpu.id, on).await.unwrap();
    assert_eq!((updated.enabled, updated.threshold), (true, Some(75.0)));
    assert_eq!(updated.name, cpu.name, "a built-in rule keeps its name");
    let reset = core.alerts.reset_rule(cpu.id).await.unwrap();
    assert_eq!((reset.enabled, reset.threshold), (false, Some(90.0)));
    let audit = core.store.recent_audit(&core.ctx(), 2).await.unwrap();
    assert_eq!(audit[0].event, "alert_rule_changed");
    assert_eq!(audit[0].action, "Reset an alert rule");
    assert_eq!(audit[1].action, "Changed an alert rule");
    assert!(
        audit[1].detail.as_deref().unwrap().contains("above 75%"),
        "{:?}",
        audit[1].detail
    );
}

#[tokio::test]
async fn a_vm_above_its_cpu_threshold_fires_one_notification_and_resolves() {
    let (core, processes, _) = core_with(&["web", "db"]).await;
    only_my_rules(&core).await;
    // 2 vCPUs on 16 logical CPUs: 12.5% of the host is 100% of the VM's own CPUs.
    let rule = core
        .alerts
        .create_rule(rule_input(AlertMetric::Cpu, AlertScope::AllVms, Some(90.0), 60))
        .await
        .unwrap();
    let mut events = core.alerts.subscribe();
    *processes.lock().unwrap() = vec![process(1, "web", 12.0), process(2, "db", 1.0)];
    let t = rounds(&core, t0(), 12).await;
    assert!(drain(&mut events).is_empty(), "55 s above 90%: not yet");
    let t = rounds(&core, t, 1).await;
    let fired = drain(&mut events);
    assert_eq!(fired.len(), 1, "{fired:?}");
    let AlertEvent::Fired { alert, notify } = &fired[0] else {
        panic!("not fired: {fired:?}")
    };
    assert!(*notify);
    assert_eq!(alert.rule_id, rule.id);
    assert_eq!(alert.target.kind, AlertTargetKind::Vm);
    assert_eq!(alert.target.key, vmx("web"));
    assert_eq!(alert.target.name, "web");
    assert_eq!(alert.value, Some(96.0));
    assert_eq!(alert.message, "CPU at 96%, above 90% for 1 minute");

    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    assert_eq!((list.open, list.unacknowledged), (1, 1));
    assert_eq!(list.alerts[0].id, alert.id);
    // Reads only: no job, no audit entry for the alert itself.
    assert!(core.store.recent_jobs(&core.ctx(), 10).await.unwrap().is_empty());
    assert_eq!(
        core.store.recent_audit(&core.ctx(), 1).await.unwrap()[0].action,
        "Added an alert rule"
    );

    // Back under for a minute: resolved, with the worst reading.
    *processes.lock().unwrap() = vec![process(1, "web", 13.0), process(2, "db", 1.0)];
    let t = rounds(&core, t, 1).await;
    *processes.lock().unwrap() = vec![process(1, "web", 2.0), process(2, "db", 1.0)];
    rounds(&core, t, 13).await;
    let events = drain(&mut events);
    let AlertEvent::Resolved { alert: resolved } = events.last().unwrap() else {
        panic!("not resolved: {events:?}")
    };
    assert_eq!(resolved.id, alert.id);
    assert_eq!(resolved.resolution, Some(Resolution::Cleared));
    assert_eq!(resolved.peak, Some(100.0), "13% of the host is past its 2 vCPUs");
    let list = core
        .alerts
        .list(AlertQuery {
            open_only: true,
            limit: None,
        })
        .await
        .unwrap();
    assert!(list.alerts.is_empty());
    assert_eq!(core.alerts.list(AlertQuery::default()).await.unwrap().alerts.len(), 1);
}

fn confirm() -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_vm_stopped_outside_the_app_alerts_and_one_stopped_by_a_remotely_job_does_not() {
    let (core, processes, _) = core_with(&["web", "db"]).await;
    let mut alerts = core.alerts.subscribe();
    *processes.lock().unwrap() = vec![process(1, "web", 1.0), process(2, "db", 1.0)];
    let t = rounds(&core, t0(), 2).await;

    // db is suspended through the bus (a Remotely action).
    let mut jobs = core.jobs.subscribe();
    let suspend = Command::VmPower {
        targets: vec![vm("db")],
        op: PowerOp::Suspend,
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx(), suspend).await.unwrap() else {
        panic!("suspending a VM is Medium");
    };
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(wait_finished(&mut jobs, job).await, JobStatus::Succeeded);
    *processes.lock().unwrap() = vec![process(1, "web", 1.0)];
    let t = rounds(&core, t, 2).await;
    assert!(drain(&mut alerts).is_empty(), "db was Remotely's doing");

    // web goes away with no job: the built-in rule fires at once.
    processes.lock().unwrap().clear();
    let t = rounds(&core, t, 1).await;
    let events = drain(&mut alerts);
    let [AlertEvent::Fired { alert, notify: true }] = events.as_slice() else {
        panic!("{events:?}")
    };
    assert_eq!(alert.metric, AlertMetric::Stopped);
    assert_eq!(alert.target.name, "web");
    assert_eq!(alert.rule_name, "A VM stopped without a Remotely action");

    // web runs again: resolved.
    *processes.lock().unwrap() = vec![process(1, "web", 1.0)];
    rounds(&core, t, 1).await;
    let events = drain(&mut alerts);
    let [AlertEvent::Resolved { alert: resolved }] = events.as_slice() else {
        panic!("{events:?}")
    };
    assert_eq!(resolved.resolution, Some(Resolution::Cleared));
}

#[tokio::test]
async fn acknowledging_is_audited_and_the_read_only_lock_refuses_it_and_rule_edits() {
    let (core, processes, _) = core_with(&["web"]).await;
    only_my_rules(&core).await;
    core.alerts
        .create_rule(rule_input(AlertMetric::Cpu, AlertScope::AllVms, Some(50.0), 0))
        .await
        .unwrap();
    *processes.lock().unwrap() = vec![process(1, "web", 12.0)];
    let t = rounds(&core, t0(), 2).await;
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    assert_eq!(list.unacknowledged, 1);

    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let refused = |err: remotely_core::CoreError| assert_eq!(err.code(), "read_only_lock", "{err}");
    refused(core.alerts.acknowledge(&[]).await.unwrap_err());
    refused(
        core.alerts
            .create_rule(rule_input(AlertMetric::Cpu, AlertScope::ThisPc, Some(50.0), 0))
            .await
            .unwrap_err(),
    );
    let rule = core.alerts.rules()[0].clone();
    refused(core.alerts.update_rule(rule.id, rule.input()).await.unwrap_err());
    refused(core.alerts.reset_rule(rule.id).await.unwrap_err());
    // The rules still run while presenting: reads only.
    rounds(&core, t, 1).await;
    core.presentation
        .set(Presentation {
            enabled: false,
            read_only: true,
        })
        .await
        .unwrap();

    let mut events = core.alerts.subscribe();
    let acknowledged = core.alerts.acknowledge(&[]).await.unwrap();
    assert_eq!(acknowledged, [list.alerts[0].id]);
    let events = drain(&mut events);
    let [AlertEvent::Acknowledged { ids }] = events.as_slice() else {
        panic!("no event: {events:?}")
    };
    assert_eq!(ids, &acknowledged);
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    assert_eq!((list.open, list.unacknowledged), (1, 0));
    assert!(list.alerts[0].acknowledged_at.is_some());
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].event, "alert_acknowledged");
    assert_eq!(audit[0].detail.as_deref(), Some("1 alert: CPU test on web"));
    assert!(core.alerts.acknowledge(&[]).await.unwrap().is_empty(), "nothing left");
}

#[tokio::test]
async fn editing_or_deleting_a_rule_resolves_its_alerts_and_a_restart_closes_the_rest() {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let setup = Setup::new(workstation(&["web"]));
    let processes = Arc::clone(&setup.host.processes);
    let adapters = |setup: &Setup| {
        let mut host = FakeHostCounters::default();
        host.processes = Arc::clone(&setup.host.processes);
        let vmware: Arc<dyn VmwareAdapter> = Arc::clone(&setup.vmware) as Arc<dyn VmwareAdapter>;
        let virtualbox: Arc<dyn VirtualBoxAdapter> = Arc::clone(&setup.virtualbox) as Arc<dyn VirtualBoxAdapter>;
        Adapters {
            vmware,
            virtualbox,
            remote: Arc::clone(&setup.remote),
            vault: Arc::new(FakeVault::with_password(common::VAULT_PASSWORD)),
            host_counters: Arc::new(host),
            updater: Arc::clone(&setup.updater),
            network: Arc::clone(&setup.network),
            containers: Arc::clone(&setup.containers),
            disk_tools: Arc::clone(&setup.disk_tools) as _,
            network_tools: Arc::clone(&setup.network_tools) as _,
        }
    };
    let core = Core::assemble(store.clone(), ctx, adapters(&setup), Default::default())
        .await
        .unwrap();
    core.inventory.refresh(&core.ctx()).await.unwrap();
    only_my_rules(&core).await;
    let cpu = core
        .alerts
        .create_rule(rule_input(AlertMetric::Cpu, AlertScope::AllVms, Some(50.0), 0))
        .await
        .unwrap();
    let memory = core
        .alerts
        .create_rule(rule_input(AlertMetric::Memory, AlertScope::ThisPc, Some(10.0), 0))
        .await
        .unwrap();
    *processes.lock().unwrap() = vec![process(1, "web", 12.0)];
    let t = rounds(&core, t0(), 2).await;
    assert_eq!(core.alerts.list(AlertQuery::default()).await.unwrap().open, 2);

    // A higher threshold: the alert resolves as the rule changed, and the rule no longer holds.
    let mut higher = cpu.input();
    higher.threshold = Some(99.0);
    core.alerts.update_rule(cpu.id, higher).await.unwrap();
    rounds(&core, t, 2).await;
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    assert_eq!(list.open, 1);
    let cpu_alert = list.alerts.iter().find(|a| a.rule_id == cpu.id).unwrap();
    assert_eq!(cpu_alert.resolution, Some(Resolution::RuleChanged));
    assert_eq!(cpu_alert.target.kind, AlertTargetKind::Vm);
    // This PC: 8 GB of 32 in use is 25%, above 10%.
    let pc = list.alerts.iter().find(|a| a.rule_id == memory.id).unwrap();
    assert_eq!(pc.target.kind, AlertTargetKind::ThisPc);
    assert_eq!(pc.value, Some(25.0));

    // The app closes and starts again: what was firing is closed, and kept in the list.
    drop(core);
    let core = Core::assemble(store, ctx, adapters(&setup), Default::default())
        .await
        .unwrap();
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    assert_eq!(list.open, 0);
    let pc = list.alerts.iter().find(|a| a.rule_id == memory.id).unwrap();
    assert_eq!(pc.resolution, Some(Resolution::Restarted));
    assert_eq!(core.alerts.rules().len(), 9, "built-in rules are not added twice");

    // A deleted rule's alerts stay in the list.
    core.alerts.delete_rule(memory.id).await.unwrap();
    assert!(core.alerts.rules().iter().all(|r| r.id != memory.id));
    assert_eq!(core.alerts.list(AlertQuery::default()).await.unwrap().alerts.len(), 2);
}

#[tokio::test]
async fn a_tag_scope_covers_tagged_vms_and_a_vm_scope_one_vm() {
    let (core, processes, _) = core_with(&["web", "db", "ci"]).await;
    only_my_rules(&core).await;
    core.store
        .tag_vms(&core.ctx(), &[vmx("web"), vmx("ci")], "Builds")
        .await
        .unwrap();
    core.alerts
        .create_rule(rule_input(
            AlertMetric::Cpu,
            AlertScope::Tag { tag: "builds".into() },
            Some(50.0),
            0,
        ))
        .await
        .unwrap();
    core.alerts
        .create_rule(rule_input(
            AlertMetric::Memory,
            AlertScope::Vm {
                key: vmx("db").to_uppercase(),
            },
            Some(20.0),
            0,
        ))
        .await
        .unwrap();
    core.alerts.forget_directory().await;
    *processes.lock().unwrap() = vec![process(1, "web", 12.0), process(2, "db", 12.0), process(3, "ci", 1.0)];
    rounds(&core, t0(), 2).await;
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    let mut fired: Vec<(String, AlertMetric)> = list.alerts.iter().map(|a| (a.target.name.clone(), a.metric)).collect();
    fired.sort_by(|a, b| a.0.cmp(&b.0));
    // web: tagged and busy; db: 1 GB working set of its 4 GB is 25%; ci: tagged but idle.
    assert_eq!(
        fired,
        [("db".into(), AlertMetric::Memory), ("web".into(), AlertMetric::Cpu)]
    );
}

#[tokio::test]
async fn a_watched_host_that_cant_be_reached_fires_after_its_duration() {
    // A port nothing listens on.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.metrics.guest().set_tuning(GuestTuning {
        connect_timeout: Duration::from_secs(2),
        command_timeout: Duration::from_secs(2),
        round_budget: Duration::from_secs(5),
        backoff_min: Duration::ZERO,
        backoff_max: Duration::ZERO,
        parallel: 4,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
    });
    core.metrics.guest().set_interval(Duration::ZERO);
    let password_id = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "db01 login",
            SecretString::new(format!("pw-{}", Uuid::new_v4().simple())),
        )
        .await
        .unwrap()
        .id;
    let id = core
        .sessions
        .create(
            &core.ctx(),
            SessionInput {
                name: "db01".into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port,
                username: Some("alice".into()),
                auth: SessionAuth::Password {
                    password_id: Some(password_id),
                },
                jump_session_id: None,
                jump_direct: false,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: Environment::Lab,
                color: None,
                tags: vec![],
                vm_id: None,
            },
        )
        .await
        .unwrap()
        .id;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    // The built-in rule waits 5 minutes; this one, for this host only, 10 seconds.
    only_my_rules(&core).await;
    core.alerts
        .create_rule(rule_input(
            AlertMetric::Unreachable,
            AlertScope::Host { session_id: id },
            None,
            10,
        ))
        .await
        .unwrap();
    let mut events = core.alerts.subscribe();
    let t = rounds(&core, t0(), 2).await;
    assert!(drain(&mut events).is_empty(), "5 s unreachable");
    rounds(&core, t, 1).await;
    let events = drain(&mut events);
    let [AlertEvent::Fired { alert, .. }] = events.as_slice() else {
        panic!("{events:?}")
    };
    assert_eq!(alert.target.kind, AlertTargetKind::Session);
    assert_eq!(alert.target.key, id.to_string());
    assert_eq!(alert.message, "Not reachable for 10 seconds");
    // A rule for a session that doesn't exist is refused.
    let err = core
        .alerts
        .create_rule(rule_input(
            AlertMetric::Cpu,
            AlertScope::Host {
                session_id: Uuid::new_v4(),
            },
            Some(90.0),
            0,
        ))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("saved session"), "{err}");
}
