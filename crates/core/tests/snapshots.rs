//! VM-04 snapshot manager and VM-05 safety snapshots, end to end with the fake VMware adapter:
//! reads skip the bus, take/revert/delete go command bus -> policy engine -> job runner -> adapter.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SnapshotOp, StopMode, SubmitOutcome};
use remotely_core::domain::Environment;
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::snapshots::is_safety_name;
use remotely_core::vault::SecretString;
use remotely_core::{Core, CoreError};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn days_ago(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::days(days)
}

/// web01 and db01 in the library, both with a "base" snapshot and a child; web01's base is old.
fn lab() -> FakeVmware {
    lab_running(&[])
}

/// [`lab`] with these VMs running.
fn lab_running(names: &[&str]) -> FakeVmware {
    FakeVmware::with_running(names.iter().map(|n| vmx(n)))
        .in_library(&vmx("web01"), Some("web01"))
        .in_library(&vmx("db01"), Some("db01"))
        .with_snapshot(&vmx("web01"), "base", days_ago(45))
        .with_snapshot(&vmx("web01"), "patched", days_ago(2))
        .with_snapshot(&vmx("db01"), "base", days_ago(10))
        .with_snapshot(&vmx("db01"), "patched", days_ago(1))
}

async fn lab_core(fake: FakeVmware) -> (Core, std::sync::Arc<FakeVmware>) {
    let setup = Setup::new(fake);
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    (core, fake)
}

fn snapshot(names: &[&str], op: SnapshotOp) -> Command {
    Command::VmSnapshot {
        targets: names.iter().map(|n| vm(n)).collect(),
        op,
    }
}

fn high_answers(count: usize, safety_snapshot: Option<bool>) -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(count),
        reason: Some("CHG-42".into()),
        safety_snapshot,
        ..Default::default()
    }
}

/// Submits a command that needs approval, approves it and waits for the job.
async fn approve_and_run(core: &Core, command: Command, answers: ApprovalAnswers) -> (Uuid, JobStatus) {
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, command).await.unwrap() else {
        panic!("expected an approval");
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    (job, wait_finished(&mut events, job).await)
}

// ---- VM-04: reading the tree --------------------------------------------------------------------

#[tokio::test]
async fn the_snapshot_manager_lists_each_vms_tree_and_flags_old_snapshots() {
    let (core, fake) = lab_core(lab()).await;
    let calls_before = fake.calls().len();
    let list = core.snapshots.list(&core.ctx, None).await.unwrap();

    let names: Vec<_> = list.iter().map(|v| v.display_name.as_str()).collect();
    assert_eq!(names, ["db01", "web01"]);
    let web = &list[1];
    let tree: Vec<_> = web
        .snapshots
        .iter()
        .map(|s| (s.depth, s.name.as_str(), s.old, s.current))
        .collect();
    assert_eq!(tree, [(0, "base", true, false), (1, "patched", false, true)]);
    assert_eq!(web.snapshots[1].path, "base/patched");
    assert_eq!(web.old_count, 1);
    assert_eq!(list[0].old_count, 0, "10 days is not old");
    assert!(web.snapshots[0].age_days.unwrap() >= 45);
    assert_eq!(
        fake.calls().len(),
        calls_before,
        "reading snapshots runs no vmrun command"
    );

    let only_db = core.snapshots.list(&core.ctx, Some(&[vmx("DB01")])).await.unwrap();
    assert_eq!(only_db.len(), 1, "paths match in any letter case");
}

#[tokio::test]
async fn a_vm_whose_snapshots_cannot_be_read_shows_the_error_and_the_rest_still_list() {
    let (core, _) = lab_core(lab().unreadable_snapshots(&vmx("db01"))).await;
    let list = core.snapshots.list(&core.ctx, None).await.unwrap();
    assert!(list[0]
        .error
        .as_deref()
        .unwrap()
        .contains("Could not read the snapshot list"));
    assert!(list[0].snapshots.is_empty());
    assert_eq!(list[1].snapshots.len(), 2);
}

// ---- VM-04: take, revert, delete through the bus ------------------------------------------------

#[tokio::test]
async fn taking_a_snapshot_of_many_vms_is_low_and_needs_no_approval() {
    let (core, fake) = lab_core(lab()).await;
    let mut events = core.jobs.subscribe();
    let take = snapshot(
        &["web01", "db01"],
        SnapshotOp::Take {
            name: "before demo".into(),
        },
    );
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bus.submit(&core.ctx, take).await.unwrap() else {
        panic!("taking a snapshot is Low");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    for name in ["web01", "db01"] {
        assert_eq!(fake.current_snapshot(&vmx(name)).as_deref(), Some("before demo"));
    }
    let web = &core.snapshots.list(&core.ctx, Some(&[vmx("web01")])).await.unwrap()[0];
    let new = web.snapshots.iter().find(|s| s.name == "before demo").unwrap();
    assert_eq!(new.path, "base/patched/before demo");
    assert!(!new.old && !new.safety);
}

#[tokio::test]
async fn a_vm_that_already_has_the_name_fails_alone() {
    let (core, fake) = lab_core(lab().with_snapshot(&vmx("db01"), "demo", days_ago(0))).await;
    let mut events = core.jobs.subscribe();
    let take = snapshot(&["web01", "db01"], SnapshotOp::Take { name: "demo".into() });
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, take).await.unwrap() else {
        panic!("Low");
    };
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::PartiallyFailed);
    let targets = core.store.job_targets(&core.ctx, job_id).await.unwrap();
    let db = targets.iter().find(|t| t.target_name == "db01").unwrap();
    assert!(db.error.as_deref().unwrap().contains("already exists"));
    assert_eq!(fake.current_snapshot(&vmx("web01")).as_deref(), Some("demo"));
}

#[tokio::test]
async fn bulk_revert_is_high_and_takes_one_named_safety_snapshot_per_vm_first() {
    let (core, fake) = lab_core(lab()).await;
    let revert = snapshot(&["web01", "db01"], SnapshotOp::Revert { name: "base".into() });
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, revert.clone()).await.unwrap() else {
        panic!("revert is High");
    };
    assert_eq!(request.tier, Tier::High);
    assert!(request
        .steps
        .contains(&ApprovalStep::SafetySnapshot { default_on: true }));
    core.bus.cancel_approval(request.id).await.unwrap();

    let (job, status) = approve_and_run(&core, revert, high_answers(2, None)).await;
    assert_eq!(status, JobStatus::Succeeded);

    // The safety snapshot comes first on each VM, then the revert.
    for name in ["web01", "db01"] {
        let path = vmx(name);
        let calls: Vec<_> = fake.calls().into_iter().filter(|c| c.ends_with(&path)).collect();
        assert_eq!(
            calls,
            [
                format!("snapshot take safety {path}"),
                format!("snapshot revert base {path}")
            ]
        );
        assert_eq!(fake.current_snapshot(&path).as_deref(), Some("base"));
    }

    // One name for the whole job, recorded per target and in the audit log.
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    let names: Vec<_> = targets.iter().map(|t| t.safety_snapshot.clone().unwrap()).collect();
    assert_eq!(names[0], names[1]);
    let safety = &names[0];
    assert!(is_safety_name(safety) && safety.contains("before revert"), "{safety}");
    assert!(safety.contains(&job.simple().to_string()[..8]));
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "job_finished");
    assert!(audit[0].detail.as_deref().unwrap().contains(safety.as_str()));

    // The snapshot manager shows it, flagged, on both VMs; the VM now runs from "base".
    for vm in core.snapshots.list(&core.ctx, None).await.unwrap() {
        let flagged: Vec<_> = vm.snapshots.iter().filter(|s| s.safety).map(|s| &s.name).collect();
        assert_eq!(flagged, [safety], "{}", vm.display_name);
        assert_eq!(vm.safety_count, 1);
        let current: Vec<_> = vm
            .snapshots
            .iter()
            .filter(|s| s.current)
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(current, ["base"]);
    }

    // A single bulk revert to the safety snapshot undoes the job.
    let undo = snapshot(&["web01", "db01"], SnapshotOp::Revert { name: safety.clone() });
    let (_, status) = approve_and_run(&core, undo, high_answers(2, Some(false))).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.current_snapshot(&vmx("db01")).as_deref(), Some(safety.as_str()));
}

#[tokio::test]
async fn deleting_a_snapshot_is_high_without_a_safety_snapshot_and_keeps_its_children() {
    let (core, fake) = lab_core(lab()).await;
    let delete = snapshot(&["web01"], SnapshotOp::Delete { name: "base".into() });
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, delete.clone()).await.unwrap() else {
        panic!("delete is High");
    };
    assert_eq!(request.tier, Tier::High);
    assert!(!request
        .steps
        .iter()
        .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    core.bus.cancel_approval(request.id).await.unwrap();

    let (job, status) = approve_and_run(&core, delete, high_answers(1, None)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.snapshot_names(&vmx("web01")), ["patched"]);
    assert!(!fake.calls().iter().any(|c| c.contains("take safety")));
    let web = &core.snapshots.list(&core.ctx, Some(&[vmx("web01")])).await.unwrap()[0];
    assert_eq!(web.snapshots[0].depth, 0, "the child moved up");
    assert_eq!(
        core.store.job_targets(&core.ctx, job).await.unwrap()[0].safety_snapshot,
        None
    );
}

#[tokio::test]
async fn a_revert_to_a_snapshot_one_vm_lacks_fails_on_that_vm_only() {
    let (core, fake) = lab_core(lab().with_snapshot(&vmx("web01"), "golden", days_ago(3))).await;
    let revert = snapshot(&["web01", "db01"], SnapshotOp::Revert { name: "golden".into() });
    let (job, status) = approve_and_run(&core, revert, high_answers(2, Some(false))).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    let db = targets.iter().find(|t| t.target_name == "db01").unwrap();
    assert_eq!(db.status, "failed");
    assert!(db.error.as_deref().unwrap().contains("does not exist"));
    assert_eq!(fake.current_snapshot(&vmx("web01")).as_deref(), Some("golden"));
}

#[tokio::test]
async fn a_path_names_a_snapshot_whose_name_is_not_unique() {
    // Workstation's own UI allows two snapshots with one name; vmrun's path form tells them apart.
    let fake = lab()
        .with_snapshot(&vmx("web01"), "base", days_ago(1))
        .with_snapshot(&vmx("web01"), "tip", days_ago(0));
    let (core, fake) = lab_core(fake).await;
    let revert = snapshot(
        &["web01"],
        SnapshotOp::Revert {
            name: "base/patched".into(),
        },
    );
    let (_, status) = approve_and_run(&core, revert, high_answers(1, Some(false))).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.current_snapshot(&vmx("web01")).as_deref(), Some("patched"));
}

#[tokio::test]
async fn snapshot_names_are_checked_before_anything_runs() {
    let (core, fake) = lab_core(lab()).await;
    let long = "x".repeat(121);
    for (name, says) in [
        ("", "Give the snapshot a name"),
        ("   ", "Give the snapshot a name"),
        ("a/b", "can't contain '/'"),
        (" padded", "start or end with a space"),
        ("two\nlines", "line breaks"),
        (long.as_str(), "at most 120"),
        ("Remotely safety mine", "kept for safety snapshots"),
    ] {
        let take = snapshot(&["web01"], SnapshotOp::Take { name: name.into() });
        match core.bus.submit(&core.ctx, take).await {
            Err(CoreError::InvalidInput(message)) => assert!(message.contains(says), "{name:?}: {message}"),
            other => panic!("{name:?} was accepted: {other:?}"),
        }
    }
    let delete = snapshot(&["web01"], SnapshotOp::Delete { name: " ".into() });
    assert!(matches!(
        core.bus.submit(&core.ctx, delete).await,
        Err(CoreError::InvalidInput(_))
    ));
    assert!(fake.calls().is_empty());
    assert!(core.store.recent_audit(&core.ctx, 5).await.unwrap().is_empty());
}

// ---- VM-05: every high-risk VM action takes a safety snapshot when the approval keeps it on ----

#[tokio::test]
async fn every_high_risk_vm_action_takes_a_safety_snapshot_before_it_runs() {
    let cases: Vec<(&str, Command, usize)> = vec![
        (
            "shut down 2",
            Command::VmPower {
                targets: vec![vm("web01"), vm("db01")],
                op: PowerOp::Stop { mode: StopMode::Soft },
            },
            2,
        ),
        (
            "restart 2",
            Command::VmPower {
                targets: vec![vm("web01"), vm("db01")],
                op: PowerOp::Reset { mode: StopMode::Soft },
            },
            2,
        ),
        (
            "suspend 2",
            Command::VmPower {
                targets: vec![vm("web01"), vm("db01")],
                op: PowerOp::Suspend,
            },
            2,
        ),
        (
            "power off 1 (Critical)",
            Command::VmPower {
                targets: vec![vm("web01")],
                op: PowerOp::Stop { mode: StopMode::Hard },
            },
            1,
        ),
        (
            "reset 1 (Critical)",
            Command::VmPower {
                targets: vec![vm("web01")],
                op: PowerOp::Reset { mode: StopMode::Hard },
            },
            1,
        ),
        (
            "revert 1",
            snapshot(&["web01"], SnapshotOp::Revert { name: "base".into() }),
            1,
        ),
    ];
    for (label, command, count) in cases {
        let fake = lab_running(&["web01", "db01"]);
        let (core, fake) = lab_core(fake).await;
        let mut answers = high_answers(count, None);
        answers.vault_password = Some(SecretString::new(VAULT_PASSWORD));
        let (job, status) = approve_and_run(&core, command, answers).await;
        assert_eq!(status, JobStatus::Succeeded, "{label}");
        let calls = fake.calls();
        let safety = calls.iter().filter(|c| c.starts_with("snapshot take safety")).count();
        assert_eq!(safety, count, "{label}: {calls:?}");
        // The safety snapshot is taken before the action on each VM.
        for target in core.store.job_targets(&core.ctx, job).await.unwrap() {
            let on_vm: Vec<_> = calls.iter().filter(|c| c.ends_with(&target.target_key)).collect();
            assert!(on_vm[0].starts_with("snapshot take safety"), "{label}: {on_vm:?}");
            assert!(target.safety_snapshot.is_some(), "{label}");
        }
    }
}

#[tokio::test]
async fn a_single_prod_vm_gets_a_safety_snapshot_because_prod_makes_it_high() {
    let (core, fake) = lab_core(lab_running(&["web01"])).await;
    sqlx::query("UPDATE vms SET environment = 'prod' WHERE display_name = 'web01'")
        .execute(core.store.pool())
        .await
        .unwrap();
    let suspend = Command::VmPower {
        targets: vec![vm("web01")],
        op: PowerOp::Suspend,
    };
    let (_, status) = approve_and_run(&core, suspend, high_answers(1, None)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(
        fake.calls(),
        [
            format!("snapshot take safety {}", vmx("web01")),
            format!("power Suspend {}", vmx("web01"))
        ]
    );
}

#[tokio::test]
async fn turning_the_safety_snapshot_off_in_the_approval_skips_it_and_says_so() {
    let (core, fake) = lab_core(lab_running(&["web01", "db01"])).await;
    let stop = Command::VmPower {
        targets: vec![vm("web01"), vm("db01")],
        op: PowerOp::Stop { mode: StopMode::Soft },
    };
    let (job, status) = approve_and_run(&core, stop, high_answers(2, Some(false))).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(!fake.calls().iter().any(|c| c.contains("take safety")));
    assert!(core
        .store
        .job_targets(&core.ctx, job)
        .await
        .unwrap()
        .iter()
        .all(|t| t.safety_snapshot.is_none()));
    let granted = core
        .store
        .recent_audit(&core.ctx, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "approval_granted")
        .unwrap();
    assert!(granted.approval_json.unwrap().contains("\"safetySnapshot\":false"));
}

#[tokio::test]
async fn a_failed_safety_snapshot_leaves_that_vm_untouched() {
    let fake = lab_running(&["web01", "db01"]).failing_snapshots(&vmx("db01"));
    let (core, fake) = lab_core(fake).await;
    let suspend = Command::VmPower {
        targets: vec![vm("web01"), vm("db01")],
        op: PowerOp::Suspend,
    };
    let (job, status) = approve_and_run(&core, suspend, high_answers(2, None)).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    let calls = fake.calls();
    assert!(calls.contains(&format!("power Suspend {}", vmx("web01"))));
    assert!(!calls.contains(&format!("power Suspend {}", vmx("db01"))), "{calls:?}");
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    let db = targets.iter().find(|t| t.target_name == "db01").unwrap();
    assert!(db.error.as_deref().unwrap().starts_with("the safety snapshot failed"));
    assert_eq!(db.safety_snapshot, None);
    assert_eq!(common::running(&fake), ["db01"]);
}

#[tokio::test]
async fn the_snapshot_list_shows_each_vms_label_and_protection() {
    let (core, _) = lab_core(lab()).await;
    sqlx::query("UPDATE vms SET environment = 'lab', protected = 1 WHERE display_name = 'db01'")
        .execute(core.store.pool())
        .await
        .unwrap();
    let list = core.snapshots.list(&core.ctx, None).await.unwrap();
    assert_eq!(list[0].environment, Environment::Lab);
    assert!(list[0].protected);
    assert_eq!(list[0].vmx_path, vmx("db01"));
}
