//! End-to-end through the public API: command bus -> policy engine -> job runner -> VMware adapter,
//! with a fake adapter so no real VM is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SnapshotOp, StopMode, SubmitOutcome};
use remotely_core::domain::TargetRef;
use remotely_core::fakes::{FakeHostCounters, FakeKeyProtector, FakeRemote, FakeUpdater, FakeVault, FakeVmware};
use remotely_core::jobs::{JobEvent, JobLimits, JobStatus};
use remotely_core::policy::{PolicyRules, Tier};
use remotely_core::store::Store;
use remotely_core::updates::UpdateCheck;
use remotely_core::vault::{LocalVault, SecretString, Vault, VaultOptions};
use remotely_core::{Adapters, Core, CoreError};

fn fake_vmware() -> Arc<FakeVmware> {
    Arc::new(FakeVmware::with_running([r"C:\VMs\a\a.vmx", r"C:\VMs\b\b.vmx"]))
}

async fn core(fake: Arc<FakeVmware>, rules: Option<PolicyRules>) -> Core {
    core_with(fake, rules, None, Arc::new(FakeUpdater::default())).await
}

/// `vault: None` is the app's own vault, not set up yet.
async fn core_with(
    fake: Arc<FakeVmware>,
    rules: Option<PolicyRules>,
    vault: Option<Arc<dyn Vault>>,
    updater: Arc<FakeUpdater>,
) -> Core {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\tester", "Tester").await.unwrap();
    let vault = match vault {
        Some(vault) => vault,
        None => Arc::new(
            LocalVault::open(
                store.clone(),
                ctx,
                Arc::new(FakeKeyProtector::new()),
                VaultOptions::insecure_fast(),
            )
            .await
            .unwrap(),
        ),
    };
    if let Some(rules) = rules {
        store
            .put_setting(&ctx, remotely_core::store::POLICY_RULES_KEY, &rules)
            .await
            .unwrap();
    }
    let adapters = Adapters {
        vmware: fake,
        remote: Arc::new(FakeRemote::default()),
        vault,
        host_counters: Arc::new(FakeHostCounters::default()),
        updater,
    };
    Core::assemble(store, ctx, adapters, JobLimits::default())
        .await
        .unwrap()
}

fn vm(name: &str) -> TargetRef {
    TargetRef::Vm {
        vmx_path: format!(r"C:\VMs\{name}\{name}.vmx"),
    }
}

async fn wait_finished(rx: &mut tokio::sync::broadcast::Receiver<JobEvent>, job: uuid::Uuid) -> JobStatus {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let JobEvent::Finished { job_id, status } = rx.recv().await.unwrap() {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .expect("job finished in time")
}

#[tokio::test]
async fn inventory_refresh_lists_running_vms() {
    let fake = fake_vmware();
    let core = core(fake, None).await;
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    let names: Vec<_> = report.vms.iter().map(|v| v.display_name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
    assert!(report.warnings.is_empty());
}

#[tokio::test]
async fn low_tier_runs_without_approval_and_is_audited() {
    let fake = fake_vmware();
    let core = core(Arc::clone(&fake), None).await;
    let mut events = core.jobs.subscribe();

    let cmd = Command::VmPower {
        targets: vec![vm("a"), vm("b")],
        op: PowerOp::Start { gui: false },
    };
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bus.submit(&core.ctx, cmd).await.unwrap() else {
        panic!("starting VMs should not need approval");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);

    let mut calls = fake.calls();
    calls.sort();
    assert_eq!(
        calls,
        [
            r"power Start { gui: false } C:\VMs\a\a.vmx",
            r"power Start { gui: false } C:\VMs\b\b.vmx"
        ]
    );

    let audit = core.store.recent_audit(&core.ctx, 10).await.unwrap();
    let events: Vec<_> = audit.iter().rev().map(|e| e.event.as_str()).collect();
    assert_eq!(events, ["job_started", "job_finished"]);
    assert!(core.store.verify_audit_chain().await.unwrap().ok);

    let jobs = core.store.recent_jobs(&core.ctx, 5).await.unwrap();
    assert_eq!(jobs[0].status, "succeeded");
    assert_eq!(jobs[0].targets_succeeded, 2);
}

#[tokio::test]
async fn high_tier_waits_for_correct_answers_then_runs_with_safety_snapshot() {
    let fake = fake_vmware();
    // Keep the test fast; the countdown has its own test.
    let rules = PolicyRules {
        countdown_seconds: 0,
        ..Default::default()
    };
    let core = core(Arc::clone(&fake), Some(rules)).await;
    let mut events = core.jobs.subscribe();

    let cmd = Command::VmPower {
        targets: vec![vm("a"), vm("b")],
        op: PowerOp::Suspend,
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, cmd).await.unwrap() else {
        panic!("suspending 2 VMs is High");
    };
    assert_eq!(request.tier, Tier::High);
    assert!(fake.calls().is_empty(), "nothing runs before approval");

    // Wrong count: rejected, request stays pending.
    let wrong = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(3),
        reason: Some("CHG-1234".into()),
        ..Default::default()
    };
    assert!(matches!(
        core.bus.approve(request.id, wrong).await,
        Err(CoreError::ApprovalRejected(_))
    ));

    // Missing reason: rejected.
    let no_reason = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(2),
        reason: Some("   ".into()),
        ..Default::default()
    };
    assert!(core.bus.approve(request.id, no_reason).await.is_err());

    let right = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(2),
        reason: Some("CHG-1234".into()),
        ..Default::default()
    };
    let job_id = core.bus.approve(request.id, right).await.unwrap();
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);

    let mut calls = fake.calls();
    calls.sort();
    assert_eq!(
        calls,
        [
            r"power Suspend C:\VMs\a\a.vmx",
            r"power Suspend C:\VMs\b\b.vmx",
            r"snapshot take safety C:\VMs\a\a.vmx",
            r"snapshot take safety C:\VMs\b\b.vmx",
        ]
    );

    let audit = core.store.recent_audit(&core.ctx, 10).await.unwrap();
    let events: Vec<_> = audit.iter().rev().map(|e| e.event.as_str()).collect();
    assert_eq!(
        events,
        ["approval_requested", "approval_granted", "job_started", "job_finished"]
    );
    assert!(audit[0].approval_json.as_deref().unwrap().contains("CHG-1234"));

    // One-shot: the same request cannot be approved twice.
    assert!(matches!(
        core.bus.approve(request.id, ApprovalAnswers::default()).await,
        Err(CoreError::UnknownApproval(_))
    ));
}

#[tokio::test]
async fn cancelling_during_the_countdown_touches_no_target() {
    let fake = fake_vmware();
    let core = core(Arc::clone(&fake), None).await; // default 10 s countdown
    let mut events = core.jobs.subscribe();

    let cmd = Command::VmSnapshot {
        targets: vec![vm("a")],
        op: SnapshotOp::Revert { name: "base".into() },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, cmd).await.unwrap() else {
        panic!("revert is High");
    };
    let job_id = core
        .bus
        .approve(
            request.id,
            ApprovalAnswers {
                confirmed: true,
                typed_target_count: Some(1),
                reason: Some("lab reset".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(core.jobs.cancel(job_id));
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Cancelled);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn critical_is_refused_until_the_vault_is_set_up() {
    let fake = fake_vmware();
    let core = core(Arc::clone(&fake), None).await;
    let cmd = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Stop { mode: StopMode::Hard },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, cmd).await.unwrap() else {
        panic!("hard power-off is Critical");
    };
    assert_eq!(request.tier, Tier::Critical);
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(1),
        reason: Some("hung VM".into()),
        vault_password: Some(SecretString::new("whatever")),
        ..Default::default()
    };
    // AP-06: no vault, no password to ask for again, so the action can't be approved yet.
    assert!(matches!(
        core.bus.approve(request.id, answers).await,
        Err(CoreError::VaultNotSetUp)
    ));
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn commands_without_targets_are_rejected() {
    let core = core(fake_vmware(), None).await;
    let cmd = Command::VmPower {
        targets: vec![],
        op: PowerOp::Pause,
    };
    assert!(matches!(
        core.bus.submit(&core.ctx, cmd).await,
        Err(CoreError::NoTargets)
    ));
}

#[tokio::test]
async fn critical_runs_after_the_vault_password_is_given_again() {
    let fake = fake_vmware();
    let vault = Arc::new(FakeVault::with_password("correct horse"));
    let rules = PolicyRules {
        countdown_seconds: 0,
        ..Default::default()
    };
    let core = core_with(
        Arc::clone(&fake),
        Some(rules),
        Some(vault),
        Arc::new(FakeUpdater::default()),
    )
    .await;
    let mut events = core.jobs.subscribe();

    let cmd = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Stop { mode: StopMode::Hard },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, cmd).await.unwrap() else {
        panic!("hard power-off is Critical");
    };
    let answers = |password: &str| ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(1),
        reason: Some("hung VM".into()),
        safety_snapshot: Some(false),
        vault_password: Some(SecretString::new(password)),
    };

    // AP-06: a wrong password is refused, nothing runs, and the audit log shows the attempt.
    assert!(matches!(
        core.bus.approve(request.id, answers("wrong")).await,
        Err(CoreError::WrongVaultPassword)
    ));
    assert!(fake.calls().is_empty());
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "approval_rejected");
    assert_eq!(audit[0].detail.as_deref(), Some("wrong vault password"));

    let job_id = core.bus.approve(request.id, answers("correct horse")).await.unwrap();
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    assert_eq!(fake.calls(), [r"power Stop { mode: Hard } C:\VMs\a\a.vmx"]);

    // The password is never written to the audit log.
    let audit = core.store.recent_audit(&core.ctx, 10).await.unwrap();
    assert!(audit.iter().all(|e| !format!("{e:?}").contains("correct horse")));
    assert!(audit.iter().any(|e| e
        .approval_json
        .as_deref()
        .is_some_and(|a| a.contains("\"vaultReauth\":true"))));
}

#[tokio::test]
async fn an_update_installs_only_once_no_other_job_is_open() {
    let fake = fake_vmware();
    let updater = Arc::new(FakeUpdater::offering("0.1.0", "0.1.1"));
    let vault = Arc::new(FakeVault::with_password("correct horse"));
    let core = core_with(Arc::clone(&fake), None, Some(vault), Arc::clone(&updater)).await;
    let mut events = core.jobs.subscribe();

    core.set_update_token(SecretString::new("github_pat_test"))
        .await
        .unwrap();
    let UpdateCheck::Available { update: offered } = core.check_for_update().await.unwrap() else {
        panic!("0.1.1 is offered");
    };
    assert_eq!(offered.version, "0.1.1");

    // A High job sits in its 10-second countdown, so a job is open.
    let revert = Command::VmSnapshot {
        targets: vec![vm("a")],
        op: SnapshotOp::Revert { name: "base".into() },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, revert).await.unwrap() else {
        panic!("revert is High");
    };
    let busy_job = core
        .bus
        .approve(
            request.id,
            ApprovalAnswers {
                confirmed: true,
                typed_target_count: Some(1),
                reason: Some("lab reset".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // FD-14: installing is Medium, one confirm.
    let update = Command::AppUpdate {
        version: offered.version.clone(),
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, update).await.unwrap() else {
        panic!("installing an update is Medium");
    };
    assert_eq!(request.tier, Tier::Medium);
    let update_job = core
        .bus
        .approve(
            request.id,
            ApprovalAnswers {
                confirmed: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(updater.installed().is_empty(), "the update waits for the open job");

    assert!(core.jobs.cancel(busy_job));
    assert_eq!(wait_finished(&mut events, busy_job).await, JobStatus::Cancelled);
    assert_eq!(wait_finished(&mut events, update_job).await, JobStatus::Succeeded);
    assert_eq!(updater.installed(), ["0.1.1"]);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn the_vmrun_path_must_be_a_real_vmrun_exe() {
    let core = core(fake_vmware(), None).await;
    let err = core
        .set_vmrun_path(Some(PathBuf::from(r"C:\Windows\notepad.exe")))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidSetting(_)));
    assert_eq!(core.saved_vmrun_path().await.unwrap(), None);

    // Clearing it ("find automatically") is saved and audited.
    core.set_vmrun_path(None).await.unwrap();
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "setting_changed");
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn update_checks_can_be_turned_off_for_air_gapped_sites() {
    let updater = Arc::new(FakeUpdater::offering("0.1.0", "0.1.1"));
    let vault = Arc::new(FakeVault::with_password("correct horse"));
    let core = core_with(fake_vmware(), None, Some(vault), Arc::clone(&updater)).await;
    core.set_update_token(SecretString::new("github_pat_test"))
        .await
        .unwrap();

    assert!(core.update_checks_enabled().await.unwrap(), "checks are on by default");
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));

    core.set_update_checks(false).await.unwrap();
    assert!(!core.update_checks_enabled().await.unwrap());
    let calls = updater.calls();
    assert_eq!(core.check_for_update().await.unwrap(), UpdateCheck::Off);
    assert_eq!(updater.calls(), calls, "no network call with checks off");

    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "setting_changed");
    assert_eq!(audit[0].detail.as_deref(), Some("off"));
}
