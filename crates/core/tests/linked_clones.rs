//! VM-04, VM-21, VM-24: linked clones are never broken without a word. A snapshot a linked clone is made from, and a
//! golden VM with linked clones, are not deleted: the command bus refuses before it asks when every VM of the command
//! would be refused, otherwise the approval names the clones (AP-02) and the job refuses that VM; the job runner checks
//! again just before it deletes. End to end through the bus with `FakeVmware` and `FakeVirtualBox`; never a real VM.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::{vbox_vm, vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SnapshotOp, SubmitOutcome};
use remotely_core::domain::PowerState;
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::ApprovalStep;
use remotely_core::vault::SecretString;
use remotely_core::vm_settings::VmLifecycleOp;
use remotely_core::{Core, CoreError};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const GOLDEN: &str = "3f0c1a2b-1111-4222-8333-444455556666";
const CLONE: &str = "9d1e2f3a-0000-4000-8000-0000000000aa";
const OTHER: &str = "5a5a5a5a-2222-4333-8444-555566667777";

fn days_ago(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::days(days)
}

/// golden (snapshot "base", then "patched" on it) and db01 ("base") in the library; web-01, also listed, is a linked
/// clone of golden's "base", as Workstation records it in golden's .vmsd.
fn lab() -> FakeVmware {
    FakeVmware::default()
        .in_library(&vmx("golden"), Some("golden"))
        .in_library(&vmx("db01"), Some("db01"))
        .in_library(&vmx("web-01"), Some("web-01"))
        .with_snapshot(&vmx("golden"), "base", days_ago(40))
        .with_snapshot(&vmx("golden"), "patched", days_ago(5))
        .with_snapshot(&vmx("db01"), "base", days_ago(10))
        .with_linked_clone(&vmx("golden"), "base", &vmx("web-01"))
}

/// VirtualBox: golden (snapshot "base", then "later"), clone a linked clone of its "base", and other with a "base".
fn vbox_lab() -> FakeVirtualBox {
    FakeVirtualBox::new()
        .with_vm(GOLDEN, "golden", PowerState::NotRunning)
        .with_vm(CLONE, "web-02", PowerState::Running)
        .with_vm(OTHER, "other", PowerState::NotRunning)
        .with_snapshot(GOLDEN, "base", days_ago(30))
        .with_snapshot(GOLDEN, "later", days_ago(3))
        .with_snapshot(OTHER, "base", days_ago(3))
        .with_linked_clone(GOLDEN, "base", CLONE)
}

async fn built(setup: Setup) -> Core {
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    core
}

fn delete_snapshot(targets: Vec<remotely_core::domain::TargetRef>, name: &str) -> Command {
    Command::VmSnapshot {
        targets,
        op: SnapshotOp::Delete { name: name.into() },
    }
}

fn delete_vms(targets: Vec<remotely_core::domain::TargetRef>) -> Command {
    Command::VmLifecycle {
        targets,
        op: VmLifecycleOp::Delete,
    }
}

fn asked(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

/// Every step answered; the vault password when the request asks for it.
async fn approve_and_wait(core: &Core, request: &ApprovalRequest) -> (Uuid, JobStatus) {
    let mut rx = core.jobs.subscribe();
    let vault = request.steps.contains(&ApprovalStep::VaultReauth);
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("linked clones test".into()),
        safety_snapshot: Some(false),
        vault_password: vault.then(|| SecretString::new(VAULT_PASSWORD)),
        change_id: None,
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    (job, wait_finished(&mut rx, job).await)
}

/// The refusal's message, for a command every VM of which linked clones stop.
async fn refused(core: &Core, command: Command) -> String {
    match core.bus.submit(&core.ctx(), command).await {
        Err(err @ CoreError::LinkedClones(_)) => {
            assert_eq!(err.code(), "linked_clones");
            err.to_string()
        }
        other => panic!("expected a linked clones refusal, got {other:?}"),
    }
}

async fn target_error(core: &Core, job: Uuid, name: &str) -> String {
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    let target = targets.iter().find(|t| t.target_name == name).unwrap();
    assert_eq!(target.status, "failed", "{target:?}");
    target.error.clone().unwrap_or_default()
}

// ---- VM-04: Workstation snapshot deletes -------------------------------------------------------------

#[tokio::test]
async fn deleting_the_snapshot_a_linked_clone_is_made_from_is_refused_before_anything_is_asked() {
    let setup = Setup::new(lab());
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let audit_before = core.store.recent_audit(&core.ctx(), 100).await.unwrap().len();

    let message = refused(&core, delete_snapshot(vec![vm("golden")], "base")).await;
    assert!(
        message.starts_with(
            "'golden': 1 linked clone depends on its snapshot 'base': web-01 (C:\\VMs\\web-01\\web-01.vmx)."
        ),
        "{message}"
    );
    assert!(message.contains("delete those clones first"), "{message}");
    assert!(!fake.calls().iter().any(|c| c.contains("snapshot delete")));
    assert_eq!(fake.snapshot_names(&vmx("golden")), ["base", "patched"]);
    assert_eq!(
        core.store.recent_audit(&core.ctx(), 100).await.unwrap().len(),
        audit_before,
        "nothing was asked, so nothing is logged"
    );

    // A snapshot taken after the clone's is not the clone's: it is deleted as usual.
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vm("golden")], "base/patched"))
            .await
            .unwrap(),
    );
    assert!(request.warnings.is_empty(), "{:?}", request.warnings);
    assert!(request.impact[0].linked_clones.is_empty());
    let (_, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.snapshot_names(&vmx("golden")), ["base"]);
}

#[tokio::test]
async fn the_parent_of_a_clones_snapshot_is_deleted_as_usual() {
    // Hand check (Workstation 26 and VirtualBox 7.2): deleting the snapshot under the clone's keeps the disk the clone
    // needs, and the clone still starts.
    let fake = FakeVmware::default()
        .in_library(&vmx("golden"), Some("golden"))
        .with_snapshot(&vmx("golden"), "base", days_ago(40))
        .with_snapshot(&vmx("golden"), "patched", days_ago(5))
        .with_linked_clone(&vmx("golden"), "base/patched", &vmx("web-01"));
    let setup = Setup::new(fake);
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vm("golden")], "base"))
            .await
            .unwrap(),
    );
    let (_, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.snapshot_names(&vmx("golden")), ["patched"]);
    refused(&core, delete_snapshot(vec![vm("golden")], "patched")).await;
}

#[tokio::test]
async fn a_bulk_delete_names_the_clones_and_refuses_only_the_vm_they_depend_on() {
    let setup = Setup::new(lab());
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vm("golden"), vm("db01")], "base"))
            .await
            .unwrap(),
    );
    // AP-02: the approval says which VM it refuses and why, and the preview lists the clones by snapshot.
    assert!(
        request
            .warnings
            .iter()
            .any(|w| w.starts_with("'golden': 1 linked clone depends on its snapshot 'base': web-01")),
        "{:?}",
        request.warnings
    );
    let golden = request.impact.iter().find(|i| i.target == vmx("golden")).unwrap();
    assert_eq!(golden.linked_clones.len(), 1);
    assert_eq!(golden.linked_clones[0].snapshot, "base");
    assert_eq!(golden.linked_clones[0].clones[0].name, "web-01");
    assert_eq!(golden.linked_clones[0].clones[0].key, vmx("web-01"));
    let db = request.impact.iter().find(|i| i.target == vmx("db01")).unwrap();
    assert!(db.linked_clones.is_empty());

    let (job, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    let error = target_error(&core, job, "golden").await;
    assert!(
        error.starts_with("1 linked clone depends on the VM's snapshot 'base': web-01"),
        "{error}"
    );
    assert_eq!(fake.snapshot_names(&vmx("golden")), ["base", "patched"]);
    assert_eq!(fake.snapshot_names(&vmx("db01")), Vec::<String>::new());
    assert!(!fake
        .calls()
        .iter()
        .any(|c| c == &format!("snapshot delete base {}", vmx("golden"))));
}

#[tokio::test]
async fn a_linked_clone_made_after_the_approval_stops_the_delete_when_its_turn_comes() {
    let fake = FakeVmware::default()
        .in_library(&vmx("golden"), Some("golden"))
        .with_snapshot(&vmx("golden"), "base", days_ago(40));
    let setup = Setup::new(fake);
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vm("golden")], "base"))
            .await
            .unwrap(),
    );
    assert!(request.warnings.is_empty());
    // A deploy makes a linked clone of "base" while the approval waits.
    fake.add_linked_clone(Path::new(&vmx("golden")), "base", Path::new(&vmx("web-07")));
    fake.set_file(&vmx("web-07"), true);

    let (job, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::Failed);
    let error = target_error(&core, job, "golden").await;
    assert!(error.contains("web-07"), "{error}");
    assert_eq!(fake.snapshot_names(&vmx("golden")), ["base"]);
}

#[tokio::test]
async fn a_clone_gone_from_disk_no_longer_holds_the_snapshot() {
    // Workstation keeps a clone's line in the .vmsd when its folder was deleted by hand; with its .vmx gone it can't
    // break any more.
    let setup = Setup::new(lab());
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = built(setup).await;
    fake.set_file(&vmx("web-01"), false);
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vm("golden")], "base"))
            .await
            .unwrap(),
    );
    assert!(request.warnings.is_empty(), "{:?}", request.warnings);
    let (_, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::Succeeded);
}

#[tokio::test]
async fn a_clone_on_a_share_counts_without_being_opened() {
    // A3: a recorded clone's .vmx on a share is never opened (Windows would send the sign-in there), so it counts as
    // there, named by its file. The fake has no such file: had it been looked for, the clone wouldn't count.
    let fake = FakeVmware::default()
        .in_library(&vmx("golden"), Some("golden"))
        .with_snapshot(&vmx("golden"), "base", days_ago(40));
    fake.add_linked_clone(
        Path::new(&vmx("golden")),
        "base",
        Path::new(r"\\filer.example.com\lab\web-09\web-09.vmx"),
    );
    let core = built(Setup::new(fake)).await;
    let message = refused(&core, delete_snapshot(vec![vm("golden")], "base")).await;
    assert!(
        message.contains(r"web-09 (\\filer.example.com\lab\web-09\web-09.vmx)"),
        "{message}"
    );
}

#[tokio::test]
async fn the_snapshot_list_shows_each_snapshots_linked_clones() {
    let core = built(Setup::new(lab())).await;
    let list = core.snapshots.list(&core.ctx(), Some(&[vmx("golden")])).await.unwrap();
    let nodes: Vec<(&str, Vec<&str>)> = list[0]
        .snapshots
        .iter()
        .map(|n| {
            (
                n.name.as_str(),
                n.linked_clones.iter().map(|c| c.name.as_str()).collect(),
            )
        })
        .collect();
    assert_eq!(nodes, [("base", vec!["web-01"]), ("patched", vec![])]);
}

// ---- VM-24, VM-21: deleting a golden VM ---------------------------------------------------------------

#[tokio::test]
async fn deleting_a_golden_vm_is_refused_with_its_clones_and_a_clone_can_go() {
    let setup = Setup::new(lab());
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let message = refused(&core, delete_vms(vec![vm("golden")])).await;
    assert!(
        message.starts_with(
            "'golden': 1 linked clone depends on its snapshots: 'base' (web-01 (C:\\VMs\\web-01\\web-01.vmx))."
        ),
        "{message}"
    );
    assert!(message.contains("Deleting the VM would delete the disks they are made from"));

    // With another VM: the preview names the clones as golden's problem, and the job deletes only the other one.
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_vms(vec![vm("golden"), vm("db01")]))
            .await
            .unwrap(),
    );
    let change = request.vm_change.as_ref().unwrap();
    let golden = change.targets.iter().find(|t| t.name == "golden").unwrap();
    let problem = golden.problem.as_deref().unwrap();
    assert!(problem.contains("'base' (web-01 ("), "{problem}");
    assert!(request.warnings.iter().any(|w| w.contains("web-01")));
    let impact = request.impact.iter().find(|i| i.target == vmx("golden")).unwrap();
    assert_eq!(impact.linked_clones[0].clones[0].name, "web-01");
    let (job, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    assert!(target_error(&core, job, "golden").await.contains("web-01"));
    let deleted: Vec<String> = fake.calls().into_iter().filter(|c| c.contains("deleteVM")).collect();
    assert_eq!(deleted, [format!("vmrun deleteVM {}", vmx("db01"))]);

    // Deleting the clone itself is fine, and Workstation takes it off golden's .vmsd: golden is free again.
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_vms(vec![vm("web-01")]))
            .await
            .unwrap(),
    );
    let (_, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(fake.linked_clones(&vmx("golden")).is_empty());
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vm("golden")], "base"))
            .await
            .unwrap(),
    );
    core.bus.cancel_approval(request.id).await.unwrap();
}

// ---- VirtualBox ---------------------------------------------------------------------------------------

#[tokio::test]
async fn virtualbox_refuses_deleting_a_snapshot_a_linked_clone_is_made_from() {
    // Hand check (VirtualBox 7.2): with the golden VM moved off the snapshot, `snapshot delete` merges the clone's disk
    // away; so Remotely refuses before VirtualBox is asked.
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(vbox_lab());
    let vbox = std::sync::Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let message = refused(&core, delete_snapshot(vec![vbox_vm(GOLDEN)], "base")).await;
    assert!(
        message.starts_with("'golden': 1 linked clone depends on its snapshot 'base': web-02."),
        "{message}"
    );
    // By the snapshot's UUID too, as the snapshot list names it.
    let base_id = vbox.linked_clones(GOLDEN)[0].0.clone();
    refused(&core, delete_snapshot(vec![vbox_vm(GOLDEN)], &base_id)).await;
    assert!(!vbox.calls().iter().any(|c| c.starts_with("snapshot delete")));

    // In bulk, only golden is refused; "later" (taken after) and other's "base" are deleted.
    let request = asked(
        core.bus
            .submit(
                &core.ctx(),
                delete_snapshot(vec![vbox_vm(GOLDEN), vbox_vm(OTHER)], "base"),
            )
            .await
            .unwrap(),
    );
    assert!(
        request.warnings.iter().any(|w| w.contains("web-02")),
        "{:?}",
        request.warnings
    );
    let golden = request.impact.iter().find(|i| i.target == GOLDEN).unwrap();
    assert_eq!(golden.linked_clones[0].clones[0].key, CLONE);
    let (job, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    assert!(target_error(&core, job, "golden").await.contains("web-02"));
    assert_eq!(vbox.snapshot_names(GOLDEN), ["base", "later"]);
    assert_eq!(vbox.snapshot_names(OTHER), Vec::<String>::new());

    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vbox_vm(GOLDEN)], "later"))
            .await
            .unwrap(),
    );
    let (_, status) = approve_and_wait(&core, &request).await;
    assert_eq!(status, JobStatus::Succeeded);

    // The snapshot list shows the clone under "base".
    let list = core
        .snapshots
        .list(&core.ctx(), Some(&[GOLDEN.to_owned()]))
        .await
        .unwrap();
    let base = list[0].snapshots.iter().find(|n| n.name == "base").unwrap();
    assert_eq!(base.linked_clones[0].name, "web-02");
}

#[tokio::test]
async fn virtualbox_refuses_deleting_a_golden_vm_it_would_half_delete() {
    // Hand check (VirtualBox 7.2): `unregistervm --delete` of a golden VM unregisters it and deletes its current disk,
    // then fails on the disk the clone is made from.
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(vbox_lab());
    let vbox = std::sync::Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let message = refused(&core, delete_vms(vec![vbox_vm(GOLDEN)])).await;
    assert!(
        message.starts_with("'golden': 1 linked clone depends on its snapshots: 'base' (web-02)."),
        "{message}"
    );
    assert!(!vbox.calls().iter().any(|c| c.contains("unregistervm")));
    assert!(vbox.info(GOLDEN).is_some());
}

#[tokio::test]
async fn a_delete_whose_clones_cant_be_checked_is_refused_too() {
    // VirtualBox's media list can't be read: Remotely can't tell whether a clone depends on the snapshot, so it doesn't
    // delete it.
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(vbox_lab());
    let vbox = std::sync::Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    vbox.set_failing("media", true);
    let message = refused(&core, delete_snapshot(vec![vbox_vm(OTHER)], "base")).await;
    assert!(
        message.starts_with("'other': Remotely could not check whether linked clones depend on snapshot 'base'"),
        "{message}"
    );
    vbox.set_failing("media", false);
    let request = asked(
        core.bus
            .submit(&core.ctx(), delete_snapshot(vec![vbox_vm(OTHER)], "base"))
            .await
            .unwrap(),
    );
    core.bus.cancel_approval(request.id).await.unwrap();
}
