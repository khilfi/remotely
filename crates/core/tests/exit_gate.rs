//! The MVP exit gate (PRD, Roadmap): "Bulk stop of 20 VMs in under 60 s; command on 50 hosts with
//! grouped output; no high-risk action unlogged". The 50-host run is in `bulk.rs`
//! (`fifty_hosts_show_grouped_results_within_five_seconds_of_the_slowest`); this file covers the other
//! two with the fake adapters, so no real VM or host is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{running, vm, vmx, Setup, VAULT_PASSWORD};
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SnapshotOp, StopMode, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::{FakeRemote, FakeVmware};
use remotely_core::jobs::{JobEvent, JobStatus};
use remotely_core::policy::{ApprovalStep, PolicyRules, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::vault::SecretString;
use remotely_core::Core;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

async fn wait(events: &mut Receiver<JobEvent>, job: Uuid, limit: Duration) -> JobStatus {
    tokio::time::timeout(limit, async {
        loop {
            if let JobEvent::Finished { job_id, status, .. } = events.recv().await.unwrap() {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .expect("the job finished in time")
}

fn answers(count: usize) -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(count),
        reason: Some("CHG-1001 lab teardown".into()),
        ..Default::default()
    }
}

fn critical(count: usize) -> ApprovalAnswers {
    ApprovalAnswers {
        vault_password: Some(SecretString::new(VAULT_PASSWORD)),
        ..answers(count)
    }
}

fn power(names: &[String], op: PowerOp) -> Command {
    Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op,
    }
}

fn lab(count: usize) -> Vec<String> {
    (1..=count).map(|i| format!("lab{i:02}")).collect()
}

fn lab_vmware(names: &[String]) -> FakeVmware {
    let mut fake = FakeVmware::with_running(names.iter().map(|n| vmx(n)));
    for name in names {
        fake = fake.in_library(&vmx(name), Some(name));
    }
    fake
}

// ---- "Bulk stop of 20 VMs in under 60 s" ---------------------------------------------------------

/// Times the app's part of a 20-VM shutdown with the default rules: the High approval (impact preview,
/// safety snapshot of each VM, typed count, reason), the 10-second countdown, and the stops, each
/// VM taking a quarter of a second like a quick guest. What is left of the minute is the user's: select
/// all, choose Shut down, type 20 and a reason, press Enter.
#[tokio::test]
async fn bulk_stop_of_twenty_vms_takes_well_under_a_minute_including_approval() {
    let names = lab(20);
    let mut setup = Setup::new(lab_vmware(&names).with_power_delay(Duration::from_millis(250)));
    setup.rules = PolicyRules::default();
    let vmware = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    let mut events = core.jobs.subscribe();

    let started = Instant::now();
    let SubmitOutcome::NeedsApproval { request } = core
        .bus
        .submit(&core.ctx(), power(&names, PowerOp::Stop { mode: StopMode::Soft }))
        .await
        .unwrap()
    else {
        panic!("stopping 20 VMs needs approval");
    };
    assert_eq!(request.tier, Tier::High);
    for step in [
        ApprovalStep::ImpactPreview,
        ApprovalStep::SafetySnapshot { default_on: true },
        ApprovalStep::TypeTargetCount { expected: 20 },
        ApprovalStep::Reason,
        ApprovalStep::Countdown { seconds: 10 },
    ] {
        assert!(request.steps.contains(&step), "{step:?} in {:?}", request.steps);
    }
    assert_eq!(request.impact.len(), 20);
    let dialog = started.elapsed();

    let job = core.bus.approve(request.id, answers(20)).await.unwrap();
    assert_eq!(
        wait(&mut events, job, Duration::from_secs(60)).await,
        JobStatus::Succeeded
    );
    let total = started.elapsed();
    assert!(running(&vmware).is_empty());
    let safety = vmware
        .calls()
        .iter()
        .filter(|c| c.starts_with("snapshot take safety"))
        .count();
    assert_eq!(safety, 20, "VM-05: a safety snapshot of each VM first");
    println!(
        "Exit gate, bulk stop of 20 VMs: dialog ready in {:.0} ms; approved to all stopped in {:.1} s (10 s of it the countdown)",
        dialog.as_secs_f64() * 1000.0,
        (total - dialog).as_secs_f64()
    );
    // Leaves more than half the minute for the user's clicks and typing.
    assert!(total < Duration::from_secs(30), "{total:?}");
}

// ---- "No high-risk action unlogged" ------------------------------------------------------------

fn approval_of(entry: &AuditEntry) -> Option<serde_json::Value> {
    serde_json::from_str(entry.approval_json.as_deref()?).ok()
}

fn is_high_risk(tier: Option<&str>) -> bool {
    matches!(tier, Some("high" | "critical"))
}

/// Gaps in the audit trail of High and Critical work. Every such job needs its approval granted
/// before it, then a start and a finish (or a cancel), each entry carrying the approval record; a
/// Critical one needs the vault password asked again. Every request for approval must end granted
/// or cancelled, and every High or Critical job in the jobs table must be in the log.
fn audit_gaps(entries: &[AuditEntry], high_risk_jobs: &[String]) -> Vec<String> {
    let mut gaps = Vec::new();
    let granted: HashMap<String, i64> = entries
        .iter()
        .filter(|e| e.event == "approval_granted")
        .filter_map(|e| Some((approval_of(e)?["requestId"].as_str()?.to_owned(), e.seq)))
        .collect();
    let mut jobs: HashMap<&str, Vec<&AuditEntry>> = HashMap::new();
    for entry in entries {
        if let Some(job) = entry.job_id.as_deref() {
            jobs.entry(job).or_default().push(entry);
        }
    }
    for job in high_risk_jobs {
        if !jobs.contains_key(job.as_str()) {
            gaps.push(format!("job {job} is High or Critical but has no audit entry"));
        }
    }
    for (job, log) in &jobs {
        if !log.iter().any(|e| is_high_risk(e.tier.as_deref())) {
            continue;
        }
        let events: HashSet<&str> = log.iter().map(|e| e.event.as_str()).collect();
        let cancelled_early = log
            .iter()
            .any(|e| e.event == "job_cancelled" && e.detail.as_deref().is_some_and(|d| d.contains("countdown")));
        if !events.contains("job_started") && !cancelled_early {
            gaps.push(format!("job {job} has no start"));
        }
        if !events.contains("job_finished") && !events.contains("job_cancelled") {
            gaps.push(format!("job {job} has no finish"));
        }
        let requests: HashSet<Option<String>> = log
            .iter()
            .map(|e| approval_of(e).and_then(|a| a["requestId"].as_str().map(str::to_owned)))
            .collect();
        let [Some(request)] = requests.iter().collect::<Vec<_>>()[..] else {
            gaps.push(format!(
                "job {job}: its entries do not all carry one approval ({requests:?})"
            ));
            continue;
        };
        let first = log.iter().map(|e| e.seq).min().unwrap_or(0);
        match granted.get(request) {
            Some(seq) if *seq < first => {}
            _ => gaps.push(format!("job {job}: no approval granted before it")),
        }
        for entry in log {
            let approval = approval_of(entry).unwrap_or_default();
            if entry.tier.as_deref() == Some("critical") && approval["vaultReauth"] != true {
                gaps.push(format!("job {job}: Critical without the vault password"));
            }
            if approval["reason"].as_str().is_none_or(str::is_empty) || approval["typedTargetCount"].is_null() {
                gaps.push(format!("job {job}: no typed count or reason in {}", entry.event));
            }
        }
    }
    let asked = entries
        .iter()
        .filter(|e| e.event == "approval_requested" && is_high_risk(e.tier.as_deref()))
        .count();
    let answered = entries
        .iter()
        .filter(|e| {
            matches!(e.event.as_str(), "approval_granted" | "approval_cancelled") && is_high_risk(e.tier.as_deref())
        })
        .count();
    if asked != answered {
        gaps.push(format!(
            "{asked} High or Critical approvals asked, {answered} granted or cancelled"
        ));
    }
    gaps
}

async fn submit_needing_approval(core: &Core, command: Command) -> remotely_core::command_bus::ApprovalRequest {
    match core.bus.submit(&core.ctx(), command).await.unwrap() {
        SubmitOutcome::NeedsApproval { request } => request,
        SubmitOutcome::Queued { summary, .. } => panic!("{summary} ran without approval"),
    }
}

async fn approve_and_wait(
    core: &Core,
    events: &mut Receiver<JobEvent>,
    command: Command,
    answers: ApprovalAnswers,
) -> (Tier, JobStatus) {
    let request = submit_needing_approval(core, command).await;
    let job = core.bus.approve(request.id, answers).await.unwrap();
    (request.tier, wait(events, job, Duration::from_secs(30)).await)
}

/// Runs every kind of High and Critical action, plus a cancel in the countdown, a closed dialog and
/// a wrong vault password, then checks the audit log from end to end.
#[tokio::test]
async fn every_high_and_critical_action_is_logged_from_approval_to_finish() {
    let names = lab(20);
    let at = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let mut fake = lab_vmware(&names).with_snapshot(&vmx("lab01"), "base", at);
    fake = fake.with_snapshot(&vmx("lab02"), "base", at);
    let mut setup = Setup::new(fake);
    setup.remote = Arc::new(FakeRemote::default());
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    let mut events = core.jobs.subscribe();
    let ctx = core.ctx();

    // High: stop 20 VMs.
    let (tier, status) = approve_and_wait(
        &core,
        &mut events,
        power(&names, PowerOp::Stop { mode: StopMode::Soft }),
        answers(20),
    )
    .await;
    assert_eq!((tier, status), (Tier::High, JobStatus::Succeeded));

    // High: revert two VMs to a snapshot.
    let revert = Command::VmSnapshot {
        targets: vec![vm("lab01"), vm("lab02")],
        op: SnapshotOp::Revert { name: "base".into() },
    };
    let (tier, status) = approve_and_wait(&core, &mut events, revert, answers(2)).await;
    assert_eq!((tier, status), (Tier::High, JobStatus::Succeeded));

    // High: a command the rules call dangerous (BX-06), on two hosts.
    let mut hosts = Vec::new();
    for name in ["web01", "web02"] {
        let session = core
            .sessions
            .create(
                &ctx,
                SessionInput {
                    name: name.into(),
                    folder_id: None,
                    host: format!("{name}.example.com"),
                    port: 22,
                    username: Some("alice".into()),
                    auth: SessionAuth::Agent,
                    jump_session_id: None,
                    jump_direct: false,
                    startup_command: None,
                    startup_on_reconnect: false,
                    prompt_hook: None,
                    environment: Environment::Lab,
                    color: None,
                    tags: vec![],
                    vm_id: None,
                    kind: Default::default(),
                },
            )
            .await
            .unwrap();
        hosts.push(TargetRef::Session { session_id: session.id });
    }
    let dangerous = Command::RemoteExec {
        targets: hosts,
        script: "rm -rf /tmp/build-cache".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: true,
        timeout_secs: None,
        rollout: Default::default(),
    };
    let (tier, status) = approve_and_wait(&core, &mut events, dangerous, answers(2)).await;
    assert_eq!((tier, status), (Tier::High, JobStatus::Succeeded));

    // Critical: hard power-off of a VM that is running again; and a High action on a Prod VM.
    let restart = core
        .bus
        .submit(&ctx, power(&lab(3), PowerOp::Start { gui: false }))
        .await
        .unwrap();
    let SubmitOutcome::Queued { job_id, .. } = restart else {
        panic!("starting is Low");
    };
    wait(&mut events, job_id, Duration::from_secs(30)).await;
    let (tier, status) = approve_and_wait(
        &core,
        &mut events,
        power(&lab(1), PowerOp::Stop { mode: StopMode::Hard }),
        critical(1),
    )
    .await;
    assert_eq!((tier, status), (Tier::Critical, JobStatus::Succeeded));
    core.inventory
        .set_environment(&ctx, &[vmx("lab02")], Environment::Prod)
        .await
        .unwrap();
    let prod = power(&["lab02".to_owned(), "lab03".to_owned()], PowerOp::Suspend);
    let (tier, status) = approve_and_wait(&core, &mut events, prod, critical(2)).await;
    assert_eq!((tier, status), (Tier::Critical, JobStatus::Succeeded));

    // Cancelled in the countdown: approved, logged, nothing touched.
    let mut rules = core.bus.rules();
    rules.countdown_seconds = 5;
    core.bus.set_rules(&ctx, rules).await.unwrap();
    let request = submit_needing_approval(
        &core,
        Command::VmSnapshot {
            targets: vec![vm("lab01"), vm("lab02")],
            op: SnapshotOp::Delete { name: "base".into() },
        },
    )
    .await;
    assert_eq!(request.tier, Tier::Critical, "lab02 is Prod now");
    let job = core.bus.approve(request.id, critical(2)).await.unwrap();
    assert!(core.jobs.cancel(job));
    assert_eq!(
        wait(&mut events, job, Duration::from_secs(30)).await,
        JobStatus::Cancelled
    );

    // A closed dialog, and a wrong vault password before the dialog was closed.
    let request = submit_needing_approval(&core, power(&lab(20)[10..], PowerOp::Reset { mode: StopMode::Soft })).await;
    core.bus.cancel_approval(request.id).await.unwrap();
    let request = submit_needing_approval(&core, power(&lab(1), PowerOp::Stop { mode: StopMode::Hard })).await;
    let wrong = ApprovalAnswers {
        vault_password: Some(SecretString::new("not the password")),
        ..answers(1)
    };
    assert!(core.bus.approve(request.id, wrong).await.is_err());
    core.bus.cancel_approval(request.id).await.unwrap();

    // The log: intact, and with no gap.
    let chain = core.store.verify_audit_chain(&core.ctx()).await.unwrap();
    assert!(chain.ok, "{chain:?}");
    let entries = core.store.audit_for_export(&ctx).await.unwrap();
    let jobs = core.store.recent_jobs(&ctx, 100).await.unwrap();
    let high_risk: Vec<String> = jobs
        .iter()
        .filter(|j| matches!(j.tier.as_str(), "high" | "critical"))
        .map(|j| j.id.clone())
        .collect();
    assert_eq!(high_risk.len(), 6, "{jobs:?}");
    let gaps = audit_gaps(&entries, &high_risk);
    assert!(gaps.is_empty(), "{gaps:#?}");
    assert!(
        entries.iter().any(|e| e.event == "approval_rejected"),
        "the wrong password is logged"
    );
    assert!(
        !entries.iter().any(|e| format!("{e:?}").contains(VAULT_PASSWORD)),
        "no secret in the log"
    );

    // The check finds a gap when one is there: a missing finish, or a job with no approval.
    let finished = entries
        .iter()
        .position(|e| e.event == "job_finished" && is_high_risk(e.tier.as_deref()))
        .unwrap();
    let mut without_finish = entries.clone();
    without_finish.remove(finished);
    assert!(audit_gaps(&without_finish, &high_risk)
        .iter()
        .any(|g| g.contains("no finish")));
    let without_grant: Vec<AuditEntry> = entries
        .iter()
        .filter(|e| e.event != "approval_granted")
        .cloned()
        .collect();
    assert!(audit_gaps(&without_grant, &high_risk)
        .iter()
        .any(|g| g.contains("no approval granted")));
    assert!(
        !audit_gaps(&entries, &[Uuid::new_v4().to_string()]).is_empty(),
        "a job missing from the log"
    );
}
