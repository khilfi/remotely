//! QL-15: the app keeps going, and keeps its records straight, when parts of it fail: a job journal or audit write
//! that fails mid-job, settings this version can't read, approvals that wait too long or whose targets
//! changed meanwhile (AP-01), and a window that reloads with work still open. Fake adapters only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, PowerOp, SubmitOutcome};
use remotely_core::domain::Environment;
use remotely_core::fakes::{
    FakeContainers, FakeHostCounters, FakeNetwork, FakeRemote, FakeUpdater, FakeVault, FakeVirtualBox, FakeVmware,
};
use remotely_core::jobs::{JobEvent, JobLimits, JobStatus};
use remotely_core::policy::{PolicyRules, Tier};
use remotely_core::store::{AuditEntry, Store, POLICY_RULES_KEY, POWER_ON_LIMIT_KEY, VMRUN_PATH_KEY};
use remotely_core::terminal::{TerminalSettings, TERMINAL_SETTINGS_KEY};
use remotely_core::vault::SecretString;
use remotely_core::{Adapters, Core, CoreError};

fn lab(names: &[&str]) -> FakeVmware {
    let mut fake = FakeVmware::with_running(names.iter().map(|n| vmx(n)));
    for name in names {
        fake = fake.in_library(&vmx(name), Some(name));
    }
    fake
}

fn pause(names: &[&str]) -> Command {
    Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op: PowerOp::Pause,
    }
}

/// Answers every step any tier can ask for.
fn all_answers(targets: usize) -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(targets),
        reason: Some("CHG-1001".into()),
        safety_snapshot: Some(false),
        vault_password: Some(SecretString::new(VAULT_PASSWORD)),
        change_id: None,
    }
}

async fn lab_core(names: &[&str]) -> (Core, Arc<FakeVmware>) {
    let setup = Setup::new(lab(names).with_power_delay(Duration::from_millis(50)));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    (core, fake)
}

async fn needs_approval(core: &Core, command: Command) -> ApprovalRequest {
    match core.bus.submit(&core.ctx(), command).await.unwrap() {
        SubmitOutcome::NeedsApproval { request } => request,
        SubmitOutcome::Queued { .. } => panic!("expected an approval"),
    }
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx(), 1_000).await.unwrap()
}

fn pauses(fake: &FakeVmware) -> usize {
    fake.calls().iter().filter(|c| c.starts_with("power Pause")).count()
}

// ---- QL-15: the job journal -------------------------------------------------------------------------------------------

/// Every target result fails to reach the journal (say the disk filled up): each target still runs to its end, the
/// job ends with its real result, and the audit log says the journal missed them.
#[tokio::test]
async fn a_journal_that_fails_mid_job_stops_no_target_and_the_job_still_ends_audited() {
    let (core, fake) = lab_core(&["web01", "web02", "web03"]).await;
    sqlx::query(
        "CREATE TRIGGER no_results BEFORE UPDATE ON job_targets WHEN NEW.status <> 'running'
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END",
    )
    .execute(core.store.pool())
    .await
    .unwrap();
    let mut events = core.jobs.subscribe();
    let request = needs_approval(&core, pause(&["web01", "web02", "web03"])).await;
    let job = core.bus.approve(request.id, all_answers(3)).await.unwrap();

    let mut finished_targets = 0;
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await.unwrap() {
                JobEvent::TargetFinished { job_id, .. } if job_id == job => finished_targets += 1,
                JobEvent::Finished { job_id, status, .. } if job_id == job => return status,
                _ => {}
            }
        }
    })
    .await
    .expect("the job ended");
    assert_eq!(status, JobStatus::Succeeded, "the targets did succeed");
    assert_eq!(finished_targets, 3, "no target was dropped");
    assert_eq!(pauses(&fake), 3);
    assert_eq!(core.store.job_status(job).await.unwrap(), Some(JobStatus::Succeeded));
    let entries = audit(&core).await;
    let end = entries
        .iter()
        .find(|e| e.event == "job_finished" && e.job_id.as_deref() == Some(&job.to_string()))
        .expect("the job's end is audited");
    assert_eq!(end.result.as_deref(), Some("succeeded"));
    let detail = end.detail.as_deref().unwrap_or_default();
    assert!(detail.contains("3 succeeded"), "{detail}");
    assert!(detail.contains("could not keep the result of 3 target(s)"), "{detail}");
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
}

/// The audit write at the end fails: the job's result stays what it was, not "failed".
#[tokio::test]
async fn a_failing_final_audit_write_does_not_overwrite_the_result() {
    let (core, fake) = lab_core(&["web01", "web02"]).await;
    sqlx::query(
        "CREATE TRIGGER no_end BEFORE INSERT ON audit_log WHEN NEW.event = 'job_finished'
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END",
    )
    .execute(core.store.pool())
    .await
    .unwrap();
    let mut events = core.jobs.subscribe();
    let request = needs_approval(&core, pause(&["web01", "web02"])).await;
    let job = core.bus.approve(request.id, all_answers(2)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(pauses(&fake), 2);
    assert_eq!(core.store.job_status(job).await.unwrap(), Some(JobStatus::Succeeded));
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    assert!(targets.iter().all(|t| t.status == "succeeded"), "{targets:?}");
    assert!(
        core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok,
        "the chain has no gap"
    );
}

/// The job's start can't be audited, so it never starts; its end is still tried, and says nothing ran.
#[tokio::test]
async fn a_job_that_cant_start_touches_nothing_and_says_so() {
    let (core, fake) = lab_core(&["web01"]).await;
    sqlx::query(
        "CREATE TRIGGER no_start BEFORE INSERT ON audit_log WHEN NEW.event = 'job_started'
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END",
    )
    .execute(core.store.pool())
    .await
    .unwrap();
    let mut events = core.jobs.subscribe();
    let request = needs_approval(&core, pause(&["web01"])).await;
    let job = core.bus.approve(request.id, all_answers(1)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Failed);
    assert_eq!(pauses(&fake), 0, "an action that can't be audited does not run");
    assert_eq!(core.store.job_status(job).await.unwrap(), Some(JobStatus::Failed));
    let entries = audit(&core).await;
    let end = entries
        .iter()
        .find(|e| e.event == "job_finished" && e.job_id.as_deref() == Some(&job.to_string()))
        .expect("the end is still audited");
    assert_eq!(end.result.as_deref(), Some("failed"));
    assert!(end
        .detail
        .as_deref()
        .unwrap_or_default()
        .contains("no target was touched"));
}

// ---- QL-15: unreadable settings --------------------------------------------------------------------------------------

async fn core_on(store: Store) -> Core {
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let adapters = Adapters {
        vmware: Arc::new(FakeVmware::default()),
        virtualbox: Arc::new(FakeVirtualBox::new()),
        remote: Arc::new(FakeRemote::default()),
        vault: Arc::new(FakeVault::with_password(VAULT_PASSWORD)),
        host_counters: Arc::new(FakeHostCounters::default()),
        updater: Arc::new(FakeUpdater::default()),
        network: Arc::new(FakeNetwork::default()),
        containers: Arc::new(FakeContainers::default()),
        disk_tools: Arc::new(remotely_core::fakes::FakeDiskTools::new()),
    };
    Core::assemble(store, ctx, adapters, JobLimits::default())
        .await
        .unwrap()
}

/// A setting written by a newer version (or damaged) no longer stops the start: its default applies, the audit log
/// says so once, and the saved value is kept aside.
#[tokio::test]
async fn unreadable_settings_fall_back_to_their_defaults_and_are_audited_once() {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let unreadable = [
        (POWER_ON_LIMIT_KEY, r#""many""#),
        (TERMINAL_SETTINGS_KEY, r#"{"keepaliveSecs":"often"}"#),
        (POLICY_RULES_KEY, r#""strict""#),
        (VMRUN_PATH_KEY, "42"),
    ];
    for (key, value) in unreadable {
        sqlx::query("INSERT INTO settings (workspace_id, user_id, key, value_json, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(ctx.workspace_id.to_string())
            .bind(ctx.user_id.to_string())
            .bind(key)
            .bind(value)
            .bind("2026-10-22T10:00:00Z")
            .execute(store.pool())
            .await
            .unwrap();
    }

    let core = core_on(store.clone()).await;
    assert_eq!(core.power_on_limit(), JobLimits::default().power_on);
    assert_eq!(core.terminal_settings().await.unwrap(), TerminalSettings::default());
    assert_eq!(core.bus.rules(), PolicyRules::default());
    assert_eq!(core.saved_vmrun_path().await.unwrap(), None);
    let resets: Vec<AuditEntry> = audit(&core)
        .await
        .into_iter()
        .filter(|e| e.action == "Reset an unreadable setting to its default")
        .collect();
    assert_eq!(resets.len(), 4, "{resets:?}");
    for (key, value) in unreadable {
        assert!(
            resets
                .iter()
                .any(|e| e.detail.as_deref().unwrap_or_default().contains(key)),
            "{key} is named"
        );
        let kept: String = sqlx::query_scalar("SELECT value_json FROM settings WHERE key = ?")
            .bind(format!("{key}.unreadable"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(kept, value, "the saved value is kept, not deleted");
    }

    // Changed settings save and read as usual afterwards, and the next start finds nothing to reset.
    core.set_power_on_limit(5).await.unwrap();
    drop(core);
    let again = core_on(store).await;
    assert_eq!(again.power_on_limit(), 5);
    let resets = audit(&again)
        .await
        .iter()
        .filter(|e| e.action == "Reset an unreadable setting to its default")
        .count();
    assert_eq!(resets, 4, "nothing new to reset");
}

// ---- QL-15: approvals that wait -------------------------------------------------------------------------------------

#[tokio::test]
async fn an_approval_expires_after_its_time_to_live_and_nothing_runs() {
    let (core, fake) = lab_core(&["web01", "db01"]).await;
    let first = needs_approval(&core, pause(&["web01"])).await;
    let second = needs_approval(&core, pause(&["db01"])).await;
    core.bus.set_approval_ttl(Duration::from_millis(50));
    tokio::time::sleep(Duration::from_millis(120)).await;

    let err = core.bus.approve(first.id, all_answers(1)).await.unwrap_err();
    assert_eq!(err.code(), "approval_expired");
    assert!(err.to_string().contains("expired"), "{err}");
    assert!(matches!(
        core.bus.approve(first.id, all_answers(1)).await.unwrap_err(),
        CoreError::UnknownApproval(_)
    ));
    // The other one waited just as long: gone too, and audited, though nobody tried to approve it.
    assert!(core.bus.pending_approvals().is_empty());
    assert!(matches!(
        core.bus.approve(second.id, all_answers(1)).await.unwrap_err(),
        CoreError::UnknownApproval(_)
    ));
    assert_eq!(pauses(&fake), 0);
    let expired = audit(&core)
        .await
        .into_iter()
        .filter(|e| e.event == "approval_expired")
        .count();
    assert_eq!(expired, 2);

    // A fresh request within its time goes ahead as before.
    core.bus.set_approval_ttl(Duration::from_secs(60));
    let mut events = core.jobs.subscribe();
    let fresh = needs_approval(&core, pause(&["web01"])).await;
    let job = core.bus.approve(fresh.id, all_answers(1)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(pauses(&fake), 1);
}

/// A target labelled Prod after the approval was asked: approving asks again, at the higher tier, under the same id,
/// and runs only once that is answered.
#[tokio::test]
async fn a_target_labelled_prod_meanwhile_is_asked_again_at_its_new_tier() {
    let (core, fake) = lab_core(&["web01"]).await;
    let asked = needs_approval(&core, pause(&["web01"])).await;
    assert_eq!(asked.tier, Tier::Medium);
    core.inventory
        .set_environment(&core.ctx(), &[vmx("web01")], Environment::Prod)
        .await
        .unwrap();

    let err = core.bus.approve(asked.id, all_answers(1)).await.unwrap_err();
    assert_eq!(err.code(), "approval_changed");
    assert!(err.to_string().contains("web01 is labelled Prod now"), "{err}");
    let CoreError::ApprovalChanged { request, .. } = err else {
        panic!("asked again");
    };
    assert_eq!(
        request.id, asked.id,
        "the same request, so MultiExec and tunnels keep track of it"
    );
    assert_eq!(request.tier, Tier::High, "Prod moves it up one tier");
    assert_eq!(request.targets[0].environment, Environment::Prod);
    assert_eq!(pauses(&fake), 0, "nothing ran on the old approval");
    let again = audit(&core)
        .await
        .into_iter()
        .filter(|e| e.event == "approval_requested")
        .count();
    assert_eq!(again, 2, "asking again is audited");

    let mut events = core.jobs.subscribe();
    let job = core.bus.approve(request.id, all_answers(1)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(pauses(&fake), 1);
}

/// A target protected after the approval was asked (AP-04): approving asks again without it; with every target
/// protected, nothing is left to approve.
#[tokio::test]
async fn a_target_protected_meanwhile_is_left_out_after_asking_again() {
    let (core, fake) = lab_core(&["web01", "db01"]).await;
    let mut events = core.jobs.subscribe();
    let asked = needs_approval(&core, pause(&["web01", "db01"])).await;
    let protect = Command::VmProtect {
        targets: vec![vm("db01")],
        protected: true,
    };
    let job = match core.bus.submit(&core.ctx(), protect).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core.bus.approve(request.id, all_answers(1)).await.unwrap(),
    };
    wait_finished(&mut events, job).await;

    let err = core.bus.approve(asked.id, all_answers(2)).await.unwrap_err();
    let CoreError::ApprovalChanged { request, changes } = err else {
        panic!("asked again");
    };
    assert!(changes.contains("db01 is protected now"), "{changes}");
    assert_eq!(request.targets.len(), 1);
    assert_eq!(request.targets[0].name, "web01");
    assert_eq!(request.skipped[0].name, "db01");
    let job = core.bus.approve(request.id, all_answers(1)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(pauses(&fake), 1);
    assert!(
        fake.calls()
            .iter()
            .all(|c| !c.contains("db01") || !c.starts_with("power")),
        "the protected VM was not touched: {:?}",
        fake.calls()
    );

    // Everything protected: nothing to ask about any more.
    let asked = needs_approval(&core, pause(&["web01"])).await;
    let protect = Command::VmProtect {
        targets: vec![vm("web01")],
        protected: true,
    };
    let job = match core.bus.submit(&core.ctx(), protect).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core.bus.approve(request.id, all_answers(1)).await.unwrap(),
    };
    wait_finished(&mut events, job).await;
    let err = core.bus.approve(asked.id, all_answers(1)).await.unwrap_err();
    assert_eq!(err.code(), "all_targets_protected");
    assert!(core.bus.pending_approvals().is_empty());
}

// ---- QL-15: a window that reloads -------------------------------------------------------------------------------------

/// What the old page had waiting is cancelled (audited); what the new page asked since is left alone.
#[tokio::test]
async fn a_reload_cancels_the_old_pages_approvals_only() {
    let (core, fake) = lab_core(&["web01", "db01"]).await;
    let old = needs_approval(&core, pause(&["web01"])).await;
    let shown = core.ui_snapshot();
    let new = needs_approval(&core, pause(&["db01"])).await;

    let released = core.release_ui(shown).await;
    assert_eq!(released.approvals, 1);
    assert!(matches!(
        core.bus.approve(old.id, all_answers(1)).await.unwrap_err(),
        CoreError::UnknownApproval(_)
    ));
    let cancelled = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "approval_cancelled")
        .expect("audited");
    assert!(cancelled.detail.as_deref().unwrap_or_default().contains("reloaded"));

    let mut events = core.jobs.subscribe();
    let job = core.bus.approve(new.id, all_answers(1)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(pauses(&fake), 1);
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|c| c.contains("web01") && c.starts_with("power"))
            .count(),
        0
    );
}
