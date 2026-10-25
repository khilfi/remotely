//! VM-14, VM-27 schedules end to end with the fake hypervisors and a fake clock (nothing sleeps): the approval asked
//! when a schedule is saved, runs submitted to the bus under it, retention of its own snapshots, missed runs,
//! daylight saving, pausing and asking again (Prod, protected, edited, rules, a new tag member), the read-only lock,
//! no overlap, auto-suspend of idle VMs, and the audit log.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::sync::Arc;

use common::{vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::command_bus::{
    ApprovalAnswers, ApprovalRequest, Command, PowerOp, SnapshotOp, StandingRun, StopMode, SubmitOutcome,
};
use remotely_core::domain::{Environment, PowerState};
use remotely_core::fakes::clock::{FakeClock, FakeZone};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobEvent;
use remotely_core::metrics::history::{HistorySource, MinuteRow};
use remotely_core::policy::{ActionKind, ApprovalStep, PolicyRules, Tier, TierRule};
use remotely_core::presentation::Presentation;
use remotely_core::schedules::{
    RunOutcome, ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleState, ScheduleTarget, ScheduleView, Timing,
    WallTime, SNAPSHOT_PREFIX,
};
use remotely_core::vault::SecretString;
use remotely_core::{Core, CoreError};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const VBOX_UUID: &str = "5b1c0000-0000-4000-8000-0000000000aa";

struct Lab {
    core: Core,
    vmware: Arc<FakeVmware>,
    clock: Arc<FakeClock>,
}

/// web01 and db01 in Workstation's library, each with a "base" snapshot, running as asked; the scheduler on a
/// fake clock in Central Europe at `now`.
async fn lab(running: &[&str], now: OffsetDateTime) -> Lab {
    lab_with(Setup::new(vmware(running)), now).await
}

fn vmware(running: &[&str]) -> FakeVmware {
    FakeVmware::with_running(running.iter().map(|n| vmx(n)))
        .in_library(&vmx("web01"), Some("web01"))
        .in_library(&vmx("db01"), Some("db01"))
        .with_snapshot(&vmx("web01"), "base", now_minus_days(40))
        .with_snapshot(&vmx("db01"), "base", now_minus_days(40))
}

fn now_minus_days(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::days(days)
}

async fn lab_with(setup: Setup, now: OffsetDateTime) -> Lab {
    let vmware = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let clock = Arc::new(FakeClock::new(now, FakeZone::central_europe()));
    core.schedules.set_clock(clock.clone());
    Lab { core, vmware, clock }
}

fn daily(hour: u8, minute: u8) -> Timing {
    Timing::Daily {
        at: WallTime::new(hour, minute).unwrap(),
    }
}

fn vms(names: &[&str]) -> Vec<ScheduleTarget> {
    names.iter().map(|n| ScheduleTarget::Vm { vm_key: vmx(n) }).collect()
}

fn input(name: &str, action: ScheduleAction, targets: Vec<ScheduleTarget>, timing: Timing) -> ScheduleInput {
    ScheduleInput {
        id: None,
        name: name.into(),
        spec: ScheduleSpec {
            action,
            targets,
            timing,
        },
    }
}

/// The answers each step asks for; no safety snapshot.
fn answers(request: &ApprovalRequest) -> ApprovalAnswers {
    let mut answers = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => answers.typed_target_count = Some(*expected),
            ApprovalStep::Reason => answers.reason = Some("CHG-7 nightly lab snapshots".into()),
            ApprovalStep::VaultReauth => answers.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            ApprovalStep::SafetySnapshot { .. } => answers.safety_snapshot = Some(false),
            _ => {}
        }
    }
    answers
}

/// Saves the schedule and answers its approval, if it asks one.
async fn save_and_approve(core: &Core, input: ScheduleInput) -> ScheduleView {
    let saved = core.schedules.save(input).await.unwrap();
    match saved.approval {
        Some(request) => core.schedules.approve(request.id, answers(&request)).await.unwrap(),
        None => saved.schedule,
    }
}

async fn tick(lab: &Lab) -> remotely_core::schedules::TickReport {
    let report = lab.core.schedules.tick().await.unwrap();
    lab.core.schedules.wait_runs().await;
    report
}

fn due(view: &ScheduleView) -> OffsetDateTime {
    let at = &view.next_run.as_ref().expect("a next run").at;
    OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).unwrap()
}

async fn audit_events(core: &Core) -> Vec<remotely_core::store::AuditEntry> {
    core.store.recent_audit(&core.ctx, 500).await.unwrap()
}

fn schedule_snapshots(fake: &FakeVmware, name: &str) -> Vec<String> {
    fake.snapshot_names(&vmx(name))
        .into_iter()
        .filter(|n| n.starts_with(SNAPSHOT_PREFIX))
        .collect()
}

// ---- VM-27 snapshot schedules ------------------------------------------------------------------------------------

#[tokio::test]
async fn retention_deletes_snapshots_so_the_save_asks_the_high_steps_without_the_countdown() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let saved = lab
        .core
        .schedules
        .save(input(
            "nightly",
            ScheduleAction::Snapshot { keep: Some(2) },
            vms(&["web01", "db01"]),
            daily(2, 0),
        ))
        .await
        .unwrap();
    assert_eq!(saved.schedule.state, ScheduleState::NeedsApproval);
    let request = saved.approval.expect("retention deletes snapshots: the save asks");
    assert_eq!(request.tier, Tier::High);
    assert_eq!(
        request.steps,
        [
            ApprovalStep::ImpactPreview,
            ApprovalStep::TypeTargetCount { expected: 2 },
            ApprovalStep::Reason
        ]
    );
    assert!(request
        .summary
        .starts_with("Schedule 'nightly': take a snapshot of 2 VMs daily at 02:00"));
    let details = request.standing.as_ref().expect("the schedule's details");
    assert_eq!(details.when, "Daily at 02:00");
    assert_eq!(details.keep, Some(2));
    assert_eq!(details.next_runs.len(), 3);

    // A wrong answer leaves it waiting; the right ones make it active from its next time.
    let mut wrong = answers(&request);
    wrong.typed_target_count = Some(3);
    assert!(lab.core.schedules.approve(request.id, wrong).await.is_err());
    let view = lab.core.schedules.approve(request.id, answers(&request)).await.unwrap();
    assert_eq!(view.state, ScheduleState::Active);
    assert_eq!(view.approval.as_ref().unwrap().tier, Tier::High);
    // 02:00 in Paris in June is 00:00 UTC.
    assert_eq!(due(&view), datetime!(2026-06-11 00:00 UTC));
    // The generic approve refuses a schedule's request id (it is gone now anyway).
    assert!(lab.core.bus.approve(request.id, answers(&request)).await.is_err());
}

#[tokio::test]
async fn snapshot_runs_keep_the_last_n_of_their_own_and_are_audited_as_runs_of_the_approval() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: Some(2) },
            vms(&["web01", "db01"]),
            daily(2, 0),
        ),
    )
    .await;
    let first = due(&view);
    for day in 0..3 {
        lab.clock.set(first + Duration::days(day) + Duration::seconds(20));
        let report = tick(&lab).await;
        assert_eq!(report.started, 1, "day {day}");
    }
    for name in ["web01", "db01"] {
        let names = lab.vmware.snapshot_names(&vmx(name));
        assert_eq!(names[0], "base", "{name}: a snapshot the schedule didn't take stays");
        assert_eq!(schedule_snapshots(&lab.vmware, name).len(), 2, "{name}: {names:?}");
    }
    let runs = lab.core.schedules.runs(view.id, 10).await.unwrap();
    assert_eq!(runs.len(), 3);
    assert!(runs.iter().all(|r| r.outcome == RunOutcome::Succeeded), "{runs:?}");
    let last = runs[0].detail.as_deref().unwrap();
    assert!(
        last.contains("took 'Remotely schedule 'nightly' 2026-06-13 02:00"),
        "{last}"
    );
    assert!(
        last.contains("deleted 2 older snapshots (keeping the last 2)"),
        "{last}"
    );
    assert_eq!(runs[0].job_ids.len(), 2, "the take, then one delete for both VMs");

    let audit = audit_events(&lab.core).await;
    let granted = audit.iter().find(|e| e.event == "approval_granted").unwrap();
    assert!(granted.detail.as_deref().unwrap().contains("standing approval"));
    let used: Vec<_> = audit.iter().filter(|e| e.event == "approval_used").collect();
    assert_eq!(
        used.len(),
        3 + 1,
        "three takes, and one delete (both VMs) at the third run"
    );
    assert!(used
        .iter()
        .all(|e| e.approval_json.as_deref().unwrap().contains("\"standing\"")));
    let started: Vec<_> = audit.iter().filter(|e| e.event == "job_started").collect();
    assert!(started
        .iter()
        .all(|e| e.approval_json.as_deref().unwrap().contains(&view.id.to_string())));
    assert_eq!(audit.iter().filter(|e| e.event == "schedule_run").count(), 3);
    assert!(lab.core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn retention_never_deletes_a_snapshot_its_schedule_did_not_take_even_with_a_lookalike_name() {
    let lookalike = "Remotely schedule 'nightly' 2026-06-01 02:00 (run deadbeef)";
    let setup = Setup::new(vmware(&[]).with_snapshot(&vmx("web01"), lookalike, now_minus_days(9)));
    let lab = lab_with(setup, datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: Some(1) },
            vms(&["web01"]),
            daily(2, 0),
        ),
    )
    .await;
    for day in 0..3 {
        lab.clock.set(due(&view) + Duration::days(day) + Duration::seconds(5));
        tick(&lab).await;
    }
    let names = lab.vmware.snapshot_names(&vmx("web01"));
    assert!(names.contains(&lookalike.to_owned()), "{names:?}");
    assert!(names.contains(&"base".to_owned()));
    assert_eq!(names.len(), 3, "base, the lookalike and the one kept: {names:?}");
}

#[tokio::test]
async fn retention_keeps_a_snapshot_a_linked_clone_is_made_from_until_the_clone_is_gone() {
    // VM-04, VM-21: deleting it would break the clone. The run keeps it, says why, and doesn't fail; its record stays,
    // so a later run deletes it once the clone is gone.
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: Some(1) },
            vms(&["web01", "db01"]),
            daily(2, 0),
        ),
    )
    .await;
    let first = due(&view);
    lab.clock.set(first + Duration::seconds(20));
    tick(&lab).await;
    let cloned = schedule_snapshots(&lab.vmware, "web01");
    assert_eq!(cloned.len(), 1);
    let clone = vmx("web-clone");
    lab.vmware
        .add_linked_clone(Path::new(&vmx("web01")), &cloned[0], Path::new(&clone));
    lab.vmware.set_file(&clone, true);

    lab.clock.set(first + Duration::days(1) + Duration::seconds(20));
    tick(&lab).await;
    assert_eq!(schedule_snapshots(&lab.vmware, "db01").len(), 1);
    let web = schedule_snapshots(&lab.vmware, "web01");
    assert_eq!(web.len(), 2, "the clone's snapshot and the new one: {web:?}");
    assert!(web.contains(&cloned[0]));
    let runs = lab.core.schedules.runs(view.id, 10).await.unwrap();
    assert_eq!(runs[0].outcome, RunOutcome::Succeeded, "{runs:?}");
    let detail = runs[0].detail.as_deref().unwrap();
    assert!(
        detail.contains("kept 1 older snapshot that linked clones are made from, until the clones are deleted"),
        "{detail}"
    );
    assert!(detail.contains(&format!("on web01 (web-clone ({clone}))")), "{detail}");
    assert!(
        detail.contains("deleted 1 older snapshot (keeping the last 1)"),
        "db01's: {detail}"
    );
    assert!(!lab
        .vmware
        .calls()
        .iter()
        .any(|c| c.contains("snapshot delete") && c.contains(&cloned[0]) && c.contains("web01")));

    // The clone is deleted (by hand: its folder is gone): the next run deletes both of web01's older ones.
    lab.vmware.set_file(&clone, false);
    lab.clock.set(first + Duration::days(2) + Duration::seconds(20));
    tick(&lab).await;
    assert_eq!(schedule_snapshots(&lab.vmware, "web01").len(), 1);
    let detail = lab.core.schedules.runs(view.id, 1).await.unwrap()[0]
        .detail
        .clone()
        .unwrap();
    assert!(detail.contains("deleted 3 older snapshots"), "{detail}");
}

#[tokio::test]
async fn virtualbox_snapshots_are_kept_by_their_uuid() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(
        FakeVirtualBox::new()
            .with_vm(VBOX_UUID, "vb01", PowerState::NotRunning)
            .with_snapshot(VBOX_UUID, "base", now_minus_days(3)),
    );
    let virtualbox = Arc::clone(&setup.virtualbox);
    let lab = lab_with(setup, datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "vbox nightly",
            ScheduleAction::Snapshot { keep: Some(1) },
            vec![ScheduleTarget::Vm {
                vm_key: VBOX_UUID.into(),
            }],
            daily(2, 0),
        ),
    )
    .await;
    for day in 0..2 {
        lab.clock.set(due(&view) + Duration::days(day) + Duration::seconds(5));
        tick(&lab).await;
    }
    let names = virtualbox.snapshot_names(VBOX_UUID);
    assert_eq!(names.len(), 2, "{names:?}");
    assert_eq!(names[0], "base");
    assert!(
        virtualbox
            .calls()
            .iter()
            .any(|c| c.starts_with("snapshot delete ") && !c.contains("Remotely schedule")),
        "deleted by UUID: {:?}",
        virtualbox.calls()
    );
}

#[tokio::test]
async fn a_snapshot_schedule_without_retention_is_low_and_approved_without_a_dialog() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let saved = lab
        .core
        .schedules
        .save(input(
            "hourly",
            ScheduleAction::Snapshot { keep: None },
            vms(&["web01"]),
            Timing::Hourly { minute: 15 },
        ))
        .await
        .unwrap();
    assert!(saved.approval.is_none());
    assert_eq!(saved.schedule.state, ScheduleState::Active);
    assert_eq!(saved.schedule.approval.as_ref().unwrap().tier, Tier::Low);
    assert_eq!(due(&saved.schedule), datetime!(2026-06-10 10:15 UTC));
    let audit = audit_events(&lab.core).await;
    assert!(
        audit.iter().any(|e| e.event == "approval_granted"),
        "recorded even with nothing asked"
    );
}

// ---- times: missed runs and daylight saving --------------------------------------------------------------------

#[tokio::test]
async fn missed_runs_are_reported_once_and_not_caught_up() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: None },
            vms(&["web01"]),
            daily(2, 0),
        ),
    )
    .await;
    let mut events = lab.core.schedules.subscribe();
    // Remotely was closed (or the PC asleep) for three and a half days.
    lab.clock.set(due(&view) + Duration::days(3) + Duration::hours(10));
    let report = tick(&lab).await;
    assert_eq!((report.started, report.missed), (0, 1));
    assert!(schedule_snapshots(&lab.vmware, "web01").is_empty(), "nothing caught up");
    let runs = lab.core.schedules.runs(view.id, 10).await.unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].outcome, RunOutcome::Missed);
    let detail = runs[0].detail.as_deref().unwrap();
    assert!(
        detail.contains("Missed 4 runs, from Thu 11 Jun 02:00 to Sun 14 Jun 02:00"),
        "{detail}"
    );
    assert!(detail.contains("not caught up"));
    assert!(matches!(
        events.try_recv(),
        Ok(remotely_core::schedules::ScheduleEvent::Missed { .. })
    ));
    // The next run is the next time from now.
    let view = lab.core.schedules.get(view.id).await.unwrap();
    assert_eq!(due(&view), datetime!(2026-06-15 00:00 UTC));
    assert!(audit_events(&lab.core)
        .await
        .iter()
        .any(|e| e.event == "schedule_missed"));

    // A run a few minutes late (the PC woke up just after) is missed too.
    lab.clock.set(due(&view) + Duration::minutes(5));
    assert_eq!(tick(&lab).await.missed, 1);
    // One just due runs.
    let view = lab.core.schedules.get(view.id).await.unwrap();
    lab.clock.set(due(&view) + Duration::seconds(30));
    assert_eq!(tick(&lab).await.started, 1);
}

#[tokio::test]
async fn a_time_the_clocks_jump_over_runs_once_after_the_jump_and_says_so() {
    let lab = lab(&[], datetime!(2026-03-28 12:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "early",
            ScheduleAction::Snapshot { keep: None },
            vms(&["web01"]),
            daily(2, 30),
        ),
    )
    .await;
    // 29 Mar 2026: 02:00 becomes 03:00 in Paris, at 01:00 UTC.
    assert_eq!(due(&view), datetime!(2026-03-29 01:00 UTC));
    let note = view.next_run.as_ref().unwrap().note.clone().unwrap();
    assert!(
        note.contains("doesn't exist as the clocks go forward: it runs at 03:00"),
        "{note}"
    );
    lab.clock.set(datetime!(2026-03-29 01:00:20 UTC));
    assert_eq!(tick(&lab).await.started, 1);
    let runs = lab.core.schedules.runs(view.id, 5).await.unwrap();
    assert!(
        runs[0].detail.as_deref().unwrap().contains("doesn't exist"),
        "the run says it too"
    );
    let view = lab.core.schedules.get(view.id).await.unwrap();
    assert_eq!(
        due(&view),
        datetime!(2026-03-30 00:30 UTC),
        "02:30 summer time the next day"
    );
}

#[tokio::test]
async fn a_time_the_clocks_repeat_runs_once() {
    let lab = lab(&[], datetime!(2026-10-24 12:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "early",
            ScheduleAction::Snapshot { keep: None },
            vms(&["web01"]),
            daily(2, 30),
        ),
    )
    .await;
    // 25 Oct 2026: 03:00 goes back to 02:00 in Paris, so 02:30 is 00:30 and 01:30 UTC.
    assert_eq!(due(&view), datetime!(2026-10-25 00:30 UTC));
    assert!(view
        .next_run
        .as_ref()
        .unwrap()
        .note
        .as_deref()
        .unwrap()
        .contains("comes twice"));
    lab.clock.set(datetime!(2026-10-25 00:30:10 UTC));
    assert_eq!(tick(&lab).await.started, 1);
    lab.clock.set(datetime!(2026-10-25 01:30:10 UTC));
    assert_eq!(tick(&lab).await.started, 0, "the second 02:30 is not a run of its own");
    assert_eq!(schedule_snapshots(&lab.vmware, "web01").len(), 1);
}

#[tokio::test]
async fn weekly_runs_on_its_days_only() {
    // Wednesday 10 June 2026.
    let lab = lab(&["web01"], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "weekend start",
            ScheduleAction::Start,
            vms(&["db01"]),
            Timing::Weekly {
                days: vec![remotely_core::schedules::Day::Sat],
                at: WallTime::new(8, 0).unwrap(),
            },
        ),
    )
    .await;
    assert_eq!(due(&view), datetime!(2026-06-13 06:00 UTC));
    lab.clock.set(due(&view) + Duration::seconds(10));
    assert_eq!(tick(&lab).await.started, 1);
    assert!(common::running(&lab.vmware).contains(&"db01".to_owned()));
    assert_eq!(
        due(&lab.core.schedules.get(view.id).await.unwrap()),
        datetime!(2026-06-20 06:00 UTC)
    );
}

// ---- VM-14 power -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn resume_starts_only_the_suspended_vms() {
    let fake = vmware(&[]).with_vmx(
        &vmx("web01"),
        remotely_core::adapters::vmware::VmxInfo {
            display_name: Some("web01".into()),
            suspended: true,
            ..Default::default()
        },
    );
    let lab = lab_with(Setup::new(fake), datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input("morning", ScheduleAction::Resume, vms(&["web01", "db01"]), daily(8, 0)),
    )
    .await;
    lab.clock.set(due(&view) + Duration::seconds(10));
    assert_eq!(tick(&lab).await.started, 1);
    assert_eq!(common::running(&lab.vmware), ["web01"]);
    let runs = lab.core.schedules.runs(view.id, 5).await.unwrap();
    let detail = runs[0].detail.as_deref().unwrap();
    assert_eq!(runs[0].outcome, RunOutcome::Succeeded);
    assert!(detail.contains("resumed 1 of 1"), "{detail}");
    assert!(detail.contains("db01 off, not suspended"), "{detail}");
}

#[tokio::test]
async fn a_power_run_leaves_vms_already_in_the_state_alone() {
    let lab = lab(&["web01"], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input("evening", ScheduleAction::Suspend, vms(&["db01"]), daily(19, 0)),
    )
    .await;
    lab.clock.set(due(&view) + Duration::seconds(10));
    tick(&lab).await;
    let runs = lab.core.schedules.runs(view.id, 5).await.unwrap();
    assert_eq!(runs[0].outcome, RunOutcome::Succeeded);
    assert!(runs[0].detail.as_deref().unwrap().starts_with("nothing to do"));
    assert!(runs[0].job_ids.is_empty());
}

// ---- pause and ask again ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_target_labelled_prod_pauses_the_schedule_and_asks_again_with_the_higher_tier() {
    let lab = lab(&["web01"], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input("evening", ScheduleAction::Suspend, vms(&["web01"]), daily(19, 0)),
    )
    .await;
    assert_eq!(view.approval.as_ref().unwrap().tier, Tier::Medium);
    let old_approval = view.approval.as_ref().unwrap().id;
    let mut events = lab.core.schedules.subscribe();
    lab.core
        .inventory
        .set_environment(&lab.core.ctx, &[vmx("web01")], Environment::Prod)
        .await
        .unwrap();
    // The list shows it before the scheduler's next look.
    let listed = lab.core.schedules.get(view.id).await.unwrap();
    assert_eq!(listed.asks_again, ["web01 is labelled Prod now"]);

    let report = tick(&lab).await;
    assert_eq!(report.paused, 1);
    let paused = lab.core.schedules.get(view.id).await.unwrap();
    assert_eq!(paused.state, ScheduleState::NeedsApproval);
    assert_eq!(paused.state_reason.as_deref(), Some("web01 is labelled Prod now"));
    assert!(paused.next_run.is_none());
    assert!(matches!(
        events.try_recv(),
        Ok(remotely_core::schedules::ScheduleEvent::NeedsApproval { .. })
    ));
    assert!(lab
        .core
        .bus
        .standing_grant(&lab.core.ctx, old_approval)
        .await
        .unwrap()
        .is_none());

    // Due: nothing runs while it waits.
    lab.clock.set(due(&view) + Duration::seconds(10));
    assert_eq!(tick(&lab).await.started, 0);
    assert_eq!(common::running(&lab.vmware), ["web01"]);

    // Asked again: Medium plus Prod is High.
    let again = lab.core.schedules.ask_approval(view.id).await.unwrap();
    let request = again.approval.unwrap();
    assert_eq!(request.tier, Tier::High);
    let view = lab.core.schedules.approve(request.id, answers(&request)).await.unwrap();
    assert_eq!(view.state, ScheduleState::Active);
    assert!(audit_events(&lab.core)
        .await
        .iter()
        .any(|e| e.event == "schedule_paused" && e.detail.as_deref().unwrap().contains("Prod")));
}

#[tokio::test]
async fn a_target_protected_since_pauses_the_schedule() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: None },
            vms(&["web01", "db01"]),
            daily(2, 0),
        ),
    )
    .await;
    let mut jobs = lab.core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = lab
        .core
        .bus
        .submit(
            &lab.core.ctx,
            Command::VmProtect {
                targets: vec![vm("db01")],
                protected: true,
            },
        )
        .await
        .unwrap()
    else {
        panic!("protecting is Low");
    };
    wait_finished(&mut jobs, job_id).await;
    lab.clock.set(due(&view) + Duration::seconds(10));
    let report = tick(&lab).await;
    assert_eq!((report.paused, report.started), (1, 0));
    let view = lab.core.schedules.get(view.id).await.unwrap();
    assert_eq!(view.state_reason.as_deref(), Some("db01 is protected now"));
    assert!(schedule_snapshots(&lab.vmware, "web01").is_empty());
}

#[tokio::test]
async fn an_edit_withdraws_the_approval_and_waits_for_a_new_one() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: Some(3) },
            vms(&["web01"]),
            daily(2, 0),
        ),
    )
    .await;
    let old = view.approval.as_ref().unwrap().id;
    // A new name alone keeps it.
    let mut renamed = input(
        "nightly web",
        view.spec.action.clone(),
        view.spec.targets.clone(),
        view.spec.timing.clone(),
    );
    renamed.id = Some(view.id);
    let saved = lab.core.schedules.save(renamed).await.unwrap();
    assert!(saved.approval.is_none());
    assert_eq!(saved.schedule.state, ScheduleState::Active);
    assert_eq!(saved.schedule.approval.as_ref().unwrap().id, old);

    let mut edited = input(
        "nightly web",
        view.spec.action.clone(),
        view.spec.targets.clone(),
        daily(3, 0),
    );
    edited.id = Some(view.id);
    let saved = lab.core.schedules.save(edited).await.unwrap();
    assert_eq!(saved.schedule.state, ScheduleState::NeedsApproval);
    assert_eq!(saved.schedule.state_reason.as_deref(), Some("the schedule was edited"));
    assert!(saved.approval.is_some(), "the dialog opens at once");
    assert!(lab.core.bus.standing_grant(&lab.core.ctx, old).await.unwrap().is_none());
    // The old time comes and goes: nothing runs until it is approved.
    lab.clock.set(due(&view) + Duration::hours(1) + Duration::seconds(5));
    assert_eq!(tick(&lab).await.started, 0);
    assert!(schedule_snapshots(&lab.vmware, "web01").is_empty());
    let audit = audit_events(&lab.core).await;
    assert!(audit
        .iter()
        .any(|e| e.event == "schedule_saved" && e.action == "Edited schedule 'nightly web'"));
}

#[tokio::test]
async fn the_rules_that_rated_it_changing_pauses_it_but_other_rules_dont() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: None },
            vms(&["web01"]),
            daily(2, 0),
        ),
    )
    .await;
    let mut unrelated = lab.core.bus.rules();
    unrelated.tiers.insert(
        ActionKind::VmDelete,
        TierRule {
            single: Tier::Critical,
            bulk: Tier::Critical,
        },
    );
    unrelated.read_only_commands.retain(|c| c != "uptime");
    lab.core.bus.set_rules(&lab.core.ctx, unrelated).await.unwrap();
    assert_eq!(tick(&lab).await.paused, 0);

    let mut stricter = lab.core.bus.rules();
    stricter.tiers.insert(
        ActionKind::SnapshotTake,
        TierRule {
            single: Tier::Medium,
            bulk: Tier::Medium,
        },
    );
    lab.core.bus.set_rules(&lab.core.ctx, stricter).await.unwrap();
    assert_eq!(tick(&lab).await.paused, 1);
    let view = lab.core.schedules.get(view.id).await.unwrap();
    assert_eq!(view.state_reason.as_deref(), Some("the approval rules changed"));
    let request = lab
        .core
        .schedules
        .ask_approval(view.id)
        .await
        .unwrap()
        .approval
        .unwrap();
    assert_eq!(request.tier, Tier::Medium);
}

#[tokio::test]
async fn a_vm_that_gets_the_tag_is_asked_about_before_it_is_touched() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let ctx = lab.core.ctx;
    lab.core.store.tag_vms(&ctx, &[vmx("web01")], "lab").await.unwrap();
    let view = save_and_approve(
        &lab.core,
        input(
            "lab nightly",
            ScheduleAction::Snapshot { keep: None },
            vec![ScheduleTarget::Tag { tag: "lab".into() }],
            daily(2, 0),
        ),
    )
    .await;
    assert_eq!(view.targets[0].vms, 1);
    lab.core.store.tag_vms(&ctx, &[vmx("db01")], "lab").await.unwrap();
    assert_eq!(tick(&lab).await.paused, 1);
    let view = lab.core.schedules.get(view.id).await.unwrap();
    assert_eq!(view.state_reason.as_deref(), Some("db01 has the tag 'lab' now"));
    // Untagging one is fine: it acts on fewer VMs than approved.
    let request = lab.core.schedules.ask_approval(view.id).await.unwrap();
    let view = match request.approval {
        Some(r) => lab.core.schedules.approve(r.id, answers(&r)).await.unwrap(),
        None => request.schedule,
    };
    lab.core.store.untag_vms(&ctx, &[vmx("db01")], "lab").await.unwrap();
    assert_eq!(tick(&lab).await.paused, 0);
    lab.clock.set(due(&view) + Duration::seconds(10));
    assert_eq!(tick(&lab).await.started, 1);
    assert_eq!(schedule_snapshots(&lab.vmware, "web01").len(), 1);
    assert!(schedule_snapshots(&lab.vmware, "db01").is_empty());
}

// ---- read-only lock and overlap ---------------------------------------------------------------------------------

#[tokio::test]
async fn nothing_runs_while_the_read_only_lock_is_on_and_it_is_not_caught_up() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: None },
            vms(&["web01"]),
            daily(2, 0),
        ),
    )
    .await;
    lab.core
        .presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    lab.clock.set(due(&view) + Duration::seconds(10));
    let report = tick(&lab).await;
    assert_eq!((report.started, report.skipped), (0, 1));
    let runs = lab.core.schedules.runs(view.id, 5).await.unwrap();
    assert_eq!(runs[0].outcome, RunOutcome::Skipped);
    assert!(runs[0].detail.as_deref().unwrap().contains("read-only lock"));
    // Edits are refused too.
    let refused = lab
        .core
        .schedules
        .save(input("other", ScheduleAction::Start, vms(&["db01"]), daily(8, 0)))
        .await;
    assert!(matches!(refused, Err(CoreError::ReadOnlyLock { .. })));
    assert!(matches!(
        lab.core.schedules.pause(view.id).await,
        Err(CoreError::ReadOnlyLock { .. })
    ));
    // The bus refuses a scheduled command itself.
    let refused = lab
        .core
        .bus
        .submit_standing(
            &lab.core.ctx,
            StandingRun {
                approval_id: view.approval.as_ref().unwrap().id,
                content_hash: view.spec.content_hash(),
                command: Command::VmSnapshot {
                    targets: vec![vm("web01")],
                    op: SnapshotOp::Take {
                        name: "Remotely schedule 'nightly' now".into(),
                    },
                },
                run_id: Uuid::new_v4(),
                label: "Schedule 'nightly'".into(),
                due: "now".into(),
            },
        )
        .await;
    assert!(matches!(refused, Err(CoreError::ReadOnlyLock { .. })));
    // Unlocked: the skipped run is not caught up.
    lab.core.presentation.set(Presentation::default()).await.unwrap();
    assert_eq!(tick(&lab).await.started, 0);
    assert!(schedule_snapshots(&lab.vmware, "web01").is_empty());
}

#[tokio::test]
async fn runs_never_overlap() {
    // Suspending two VMs is High, so its job waits out a countdown: the run is still going at the next hour.
    let mut setup = Setup::new(vmware(&["web01", "db01"]));
    setup.rules = PolicyRules {
        countdown_seconds: 30,
        ..Default::default()
    };
    let lab = lab_with(setup, datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "hourly",
            ScheduleAction::Suspend,
            vms(&["web01", "db01"]),
            Timing::Hourly { minute: 0 },
        ),
    )
    .await;
    let mut jobs = lab.core.jobs.subscribe();
    lab.clock.set(due(&view) + Duration::seconds(5));
    assert_eq!(lab.core.schedules.tick().await.unwrap().started, 1);
    let job = loop {
        if let JobEvent::Countdown { job_id, .. } = jobs.recv().await.unwrap() {
            break job_id;
        }
    };
    lab.clock.advance(Duration::hours(1));
    let report = lab.core.schedules.tick().await.unwrap();
    assert_eq!((report.started, report.skipped), (0, 1));
    assert!(lab.core.jobs.cancel(job));
    lab.core.schedules.wait_runs().await;
    let runs = lab.core.schedules.runs(view.id, 5).await.unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].outcome, RunOutcome::Skipped);
    assert!(runs[0].detail.as_deref().unwrap().contains("still going"));
    assert_eq!(runs[1].outcome, RunOutcome::Failed);
    assert!(runs[1].detail.as_deref().unwrap().contains("cancelled"));
}

// ---- VM-14 auto-suspend ---------------------------------------------------------------------------------------

fn minutes_of(key: &str, now: OffsetDateTime, count: i64, cpu: f64) -> Vec<MinuteRow> {
    let now_minute = now.unix_timestamp().div_euclid(60);
    (now_minute - count..now_minute)
        .map(|minute| MinuteRow {
            source: HistorySource::Host,
            key: key.to_owned(),
            minute,
            samples: 12,
            cpu_avg: Some(cpu),
            cpu_min: Some(cpu),
            cpu_max: Some(cpu),
            mem_avg: None,
            mem_max: None,
            mem_total: None,
            swap_avg: None,
            swap_total: None,
            read_avg: None,
            write_avg: None,
            rx_avg: None,
            tx_avg: None,
            load_avg: None,
            load_max: None,
            disk_used_max: None,
        })
        .collect()
}

#[tokio::test]
async fn auto_suspend_suspends_the_vms_idle_long_enough_only() {
    let now = datetime!(2026-06-10 10:00 UTC);
    let lab = lab(&["web01", "db01"], now).await;
    let idle = Timing::Idle {
        minutes: 30,
        cpu_below_pct: 5,
    };
    let view = save_and_approve(
        &lab.core,
        input("idle lab", ScheduleAction::Suspend, vms(&["web01", "db01"]), idle),
    )
    .await;
    assert!(view.next_run.is_none(), "auto-suspend has no times");
    let ctx = lab.core.ctx;
    // web01 idle for 30 minutes; db01 busy; neither long enough yet at first.
    lab.core
        .store
        .write_history(&ctx, &minutes_of(&vmx("web01"), now, 20, 1.0))
        .await
        .unwrap();
    lab.core
        .store
        .write_history(&ctx, &minutes_of(&vmx("db01"), now, 30, 40.0))
        .await
        .unwrap();
    assert_eq!(tick(&lab).await.started, 0, "20 minutes is not 30");
    lab.core
        .store
        .write_history(&ctx, &minutes_of(&vmx("web01"), now, 30, 1.0))
        .await
        .unwrap();
    // Within the minute it doesn't look again.
    lab.clock.advance(Duration::seconds(20));
    assert_eq!(tick(&lab).await.started, 0);
    lab.clock.advance(Duration::seconds(45));
    assert_eq!(tick(&lab).await.started, 1);
    assert_eq!(common::running(&lab.vmware), ["db01"]);
    let runs = lab.core.schedules.runs(view.id, 5).await.unwrap();
    assert_eq!(runs[0].outcome, RunOutcome::Succeeded);
    let detail = runs[0].detail.as_deref().unwrap();
    assert!(
        detail.contains("idle for 30 minutes with CPU under 5%: web01 (1.0% on average)"),
        "{detail}"
    );
}

// ---- the bus's side ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_bus_refuses_a_scheduled_command_its_approval_does_not_cover() {
    let lab = lab(&["web01"], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input("evening", ScheduleAction::Suspend, vms(&["web01"]), daily(19, 0)),
    )
    .await;
    let approval_id = view.approval.as_ref().unwrap().id;
    let run = |approval_id: Uuid, command: Command| StandingRun {
        approval_id,
        content_hash: view.spec.content_hash(),
        command,
        run_id: Uuid::new_v4(),
        label: "Schedule 'evening'".into(),
        due: "19:00".into(),
    };
    let hard_stop = Command::VmPower {
        targets: vec![vm("web01")],
        op: PowerOp::Stop { mode: StopMode::Hard },
    };
    let ctx = lab.core.ctx;
    assert!(lab
        .core
        .bus
        .submit_standing(&ctx, run(approval_id, hard_stop))
        .await
        .is_err());
    let suspend = Command::VmPower {
        targets: vec![vm("web01")],
        op: PowerOp::Suspend,
    };
    assert!(lab
        .core
        .bus
        .submit_standing(&ctx, run(Uuid::new_v4(), suspend.clone()))
        .await
        .is_err());
    // Another VM than the approved one asks again rather than running.
    let other = Command::VmPower {
        targets: vec![vm("db01")],
        op: PowerOp::Suspend,
    };
    assert!(matches!(
        lab.core.bus.submit_standing(&ctx, run(approval_id, other)).await,
        Err(CoreError::StandingChanged { .. })
    ));
    assert_eq!(common::running(&lab.vmware), ["web01"]);
    let audit = audit_events(&lab.core).await;
    assert_eq!(audit.iter().filter(|e| e.event == "approval_refused").count(), 2);
    // The right one runs.
    let mut jobs = lab.core.jobs.subscribe();
    let job = lab
        .core
        .bus
        .submit_standing(&ctx, run(approval_id, suspend))
        .await
        .unwrap();
    wait_finished(&mut jobs, job).await;
    assert!(common::running(&lab.vmware).is_empty());
}

// ---- views ----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_vms_tab_lists_the_schedules_that_reach_it_and_its_chain() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let ctx = lab.core.ctx;
    lab.core.store.tag_vms(&ctx, &[vmx("web01")], "lab").await.unwrap();
    save_and_approve(
        &lab.core,
        input(
            "lab nightly",
            ScheduleAction::Snapshot { keep: None },
            vec![ScheduleTarget::Tag { tag: "lab".into() }],
            daily(2, 0),
        ),
    )
    .await;
    save_and_approve(
        &lab.core,
        input("db only", ScheduleAction::Start, vms(&["db01"]), daily(8, 0)),
    )
    .await;
    let tab = lab.core.schedules.for_vm(&vmx("web01")).await.unwrap();
    assert_eq!(tab.schedules.len(), 1);
    assert_eq!(tab.schedules[0].name, "lab nightly");
    let chain = tab.chain.unwrap();
    assert_eq!(chain.snapshots, Some(1));
    assert_eq!(lab.core.schedules.list().await.unwrap().len(), 2);

    // Chain limits: audited, and warn in the list.
    let limits = lab
        .core
        .schedules
        .set_chain_limits(remotely_core::schedules::ChainLimits {
            max_depth: 1,
            max_size_gb: 100,
        })
        .await
        .unwrap();
    assert_eq!(limits.max_depth, 1);
    assert!(audit_events(&lab.core)
        .await
        .iter()
        .any(|e| e.action == "Changed the snapshot chain warnings"));
}

#[tokio::test]
async fn deleting_a_schedule_withdraws_its_approval_and_keeps_its_snapshots() {
    let lab = lab(&[], datetime!(2026-06-10 10:00 UTC)).await;
    let view = save_and_approve(
        &lab.core,
        input(
            "nightly",
            ScheduleAction::Snapshot { keep: Some(5) },
            vms(&["web01"]),
            daily(2, 0),
        ),
    )
    .await;
    lab.clock.set(due(&view) + Duration::seconds(10));
    tick(&lab).await;
    let approval = view.approval.as_ref().unwrap().id;
    lab.core.schedules.delete(view.id).await.unwrap();
    assert!(lab.core.schedules.list().await.unwrap().is_empty());
    assert!(lab
        .core
        .bus
        .standing_grant(&lab.core.ctx, approval)
        .await
        .unwrap()
        .is_none());
    assert_eq!(schedule_snapshots(&lab.vmware, "web01").len(), 1);
    assert!(audit_events(&lab.core)
        .await
        .iter()
        .any(|e| e.event == "schedule_deleted"));
}
