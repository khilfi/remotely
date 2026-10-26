//! AP-08 change IDs end to end on the fakes: optional on High and Critical approvals, required for Prod targets when
//! the workspace says so (FD-02: a rule per workspace), cleaned and capped, and kept in the job, the audit log and its
//! CSV, the Compare and MultiExec exports, and a schedule's standing approval and each of its runs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::{listed, vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::bulk::{ExportFormat, GroupOptions, RecordedRun};
use remotely_core::command_bus::{
    ApprovalAnswers, ApprovalRequest, ChangeIdRules, Command, PowerOp, SubmitOutcome, MAX_CHANGE_ID_CHARS,
};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::clock::{FakeClock, FakeZone};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::presentation::Presentation;
use remotely_core::schedules::{
    ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleState, ScheduleTarget, Timing, WallTime,
};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::vault::SecretString;
use remotely_core::workspaces::WorkspaceInput;
use remotely_core::{Core, CoreError};
use time::macros::datetime;
use uuid::Uuid;

const CHG: &str = "CHG0012345";

async fn lab() -> Core {
    Setup::new(listed(FakeVmware::default(), &["web", "db"])).build().await
}

fn suspend(names: &[&str]) -> Command {
    Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op: PowerOp::Suspend,
    }
}

/// Every step answered; the change ID as given.
fn answers(request: &ApprovalRequest, change_id: Option<&str>) -> ApprovalAnswers {
    let mut answers = ApprovalAnswers {
        confirmed: true,
        change_id: change_id.map(str::to_owned),
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => answers.typed_target_count = Some(*expected),
            ApprovalStep::Reason => answers.reason = Some("planned maintenance".into()),
            ApprovalStep::VaultReauth => answers.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            ApprovalStep::SafetySnapshot { .. } => answers.safety_snapshot = Some(false),
            _ => {}
        }
    }
    answers
}

fn change_id_step(request: &ApprovalRequest) -> Option<bool> {
    request.steps.iter().find_map(|s| match s {
        ApprovalStep::ChangeId { required } => Some(*required),
        _ => None,
    })
}

async fn ask(core: &Core, command: Command) -> ApprovalRequest {
    match core.bus.submit(&core.ctx(), command).await.unwrap() {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

async fn approve_and_wait(core: &Core, request: &ApprovalRequest, change_id: Option<&str>) -> Uuid {
    let mut jobs = core.jobs.subscribe();
    let job = core.bus.approve(request.id, answers(request, change_id)).await.unwrap();
    assert_eq!(wait_finished(&mut jobs, job).await, JobStatus::Succeeded);
    job
}

async fn job_change_id(core: &Core, job: Uuid) -> Option<String> {
    core.store
        .job_detail(&core.ctx(), job)
        .await
        .unwrap()
        .expect("the job")
        .0
        .change_id
}

#[tokio::test]
async fn a_change_id_is_optional_on_high_and_critical_and_kept_in_the_job_the_log_and_its_csv() {
    let core = lab().await;
    // Medium: no change ID asked; one given anyway is not kept.
    let medium = ask(&core, suspend(&["web"])).await;
    assert_eq!(medium.tier, Tier::Medium);
    assert_eq!(change_id_step(&medium), None);
    let job = approve_and_wait(&core, &medium, Some(CHG)).await;
    assert_eq!(job_change_id(&core, job).await, None);

    // High: optional.
    let high = ask(&core, suspend(&["web", "db"])).await;
    assert_eq!(high.tier, Tier::High);
    assert_eq!(change_id_step(&high), Some(false));
    let job = approve_and_wait(&core, &high, None).await;
    assert_eq!(job_change_id(&core, job).await, None);

    // Cleaned and capped: too long or more than one line is refused, and the approval waits for a right answer.
    let high = ask(&core, suspend(&["web", "db"])).await;
    for bad in [
        "X".repeat(MAX_CHANGE_ID_CHARS + 1),
        "CHG1\nCHG2".to_owned(),
        "CHG\u{202e}1".to_owned(),
    ] {
        let refused = core.bus.approve(high.id, answers(&high, Some(&bad))).await;
        assert!(
            matches!(refused, Err(CoreError::ApprovalRejected(_))),
            "{bad:?}: {refused:?}"
        );
    }
    let job = approve_and_wait(&core, &high, Some(&format!("  {CHG}  "))).await;
    assert_eq!(job_change_id(&core, job).await.as_deref(), Some(CHG));
    let jobs = core.store.recent_jobs(&core.ctx(), 10).await.unwrap();
    assert_eq!(jobs[0].change_id.as_deref(), Some(CHG), "Activity's list has it");
    let entries = core.store.recent_audit(&core.ctx(), 50).await.unwrap();
    for event in ["approval_granted", "job_started", "job_finished"] {
        let entry = entries
            .iter()
            .find(|e| e.event == event && e.job_id.as_deref().is_none_or(|j| j == job.to_string()))
            .unwrap_or_else(|| panic!("{event}"));
        assert!(
            entry
                .approval_json
                .as_deref()
                .unwrap_or_default()
                .contains(&format!("\"changeId\":\"{CHG}\"")),
            "{event}: {:?}",
            entry.approval_json
        );
    }

    // What looks like a secret is redacted, as in a reason.
    let high = ask(&core, suspend(&["web", "db"])).await;
    let job = approve_and_wait(&core, &high, Some("password=hunter2")).await;
    let kept = job_change_id(&core, job).await.unwrap();
    assert!(!kept.contains("hunter2"), "{kept}");

    // AP-05: the CSV has a change_id column with it.
    let dir = common::temp_folder("change-ids-audit");
    let file = dir.join("audit.csv");
    core.export_audit_csv(&file).await.unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    let header = text.trim_start_matches('\u{FEFF}').lines().next().unwrap();
    assert!(header.contains(",reason,change_id,"), "{header}");
    assert!(text.contains(&format!(",{CHG},")));
    assert!(!text.contains("hunter2"));
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_workspace_can_require_a_change_id_for_prod_targets() {
    let core = lab().await;
    let ctx = core.ctx();
    assert_eq!(core.bus.change_id_rules(&ctx).await.unwrap(), ChangeIdRules::default());
    core.inventory
        .set_environment(&ctx, &[vmx("db")], Environment::Prod)
        .await
        .unwrap();

    // Off: a Prod action asks for it, optional.
    let prod = ask(&core, suspend(&["db"])).await;
    assert_eq!(prod.tier, Tier::High, "Medium, up one tier for Prod");
    assert_eq!(change_id_step(&prod), Some(false));
    core.bus.cancel_approval(prod.id).await.unwrap();

    // On: required for Prod, still optional elsewhere. Audited; refused by the read-only lock.
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    assert!(matches!(
        core.bus
            .set_change_id_rules(
                &ctx,
                ChangeIdRules {
                    required_for_prod: true
                }
            )
            .await,
        Err(CoreError::ReadOnlyLock { .. })
    ));
    core.presentation.set(Presentation::default()).await.unwrap();
    core.bus
        .set_change_id_rules(
            &ctx,
            ChangeIdRules {
                required_for_prod: true,
            },
        )
        .await
        .unwrap();
    let set = core.store.recent_audit(&ctx, 5).await.unwrap();
    assert!(set.iter().any(|e| e.action == "Set the change ID rule"));
    let prod = ask(&core, suspend(&["db"])).await;
    assert_eq!(change_id_step(&prod), Some(true));
    let missing = core.bus.approve(prod.id, answers(&prod, None)).await;
    assert!(
        matches!(&missing, Err(CoreError::ApprovalRejected(m)) if m.contains("change ID")),
        "{missing:?}"
    );
    let job = approve_and_wait(&core, &prod, Some(CHG)).await;
    assert_eq!(job_change_id(&core, job).await.as_deref(), Some(CHG));
    // A High action on a Lab VM only: still optional.
    let lab_only = ask(
        &core,
        Command::VmSnapshot {
            targets: vec![vm("web")],
            op: remotely_core::command_bus::SnapshotOp::Revert { name: "base".into() },
        },
    )
    .await;
    assert_eq!(lab_only.tier, Tier::High);
    assert_eq!(change_id_step(&lab_only), Some(false));
    core.bus.cancel_approval(lab_only.id).await.unwrap();

    // The rule is the workspace's own (FD-02).
    let other = core
        .workspaces
        .create(WorkspaceInput {
            name: "Globex".into(),
            color: None,
        })
        .await
        .unwrap();
    let other_ctx = remotely_core::domain::Context {
        workspace_id: other.id,
        user_id: ctx.user_id,
    };
    assert_eq!(
        core.bus.change_id_rules(&other_ctx).await.unwrap(),
        ChangeIdRules::default()
    );
}

#[tokio::test]
async fn compare_and_multiexec_exports_carry_the_change_id() {
    let core = lab().await;
    let ctx = core.ctx();
    let mut sessions = Vec::new();
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
                },
            )
            .await
            .unwrap();
        sessions.push(session.id);
    }
    let run = Command::RemoteExec {
        targets: sessions
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect(),
        script: "rm -rf /tmp/remotely-test".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Default::default(),
    };
    let request = ask(&core, run).await;
    assert!(request.tier >= Tier::High, "a dangerous command on two hosts");
    let mut jobs = core.jobs.subscribe();
    let job = core
        .bus
        .approve(request.id, answers(&request, Some(CHG)))
        .await
        .unwrap();
    wait_finished(&mut jobs, job).await;

    let opts = GroupOptions::default();
    let (csv, _, _) = core.bulk.render(&ctx, job, ExportFormat::Csv, opts).await.unwrap();
    let header = csv.trim_start_matches('\u{FEFF}').lines().next().unwrap();
    assert!(header.ends_with(",change_id"), "{header}");
    assert_eq!(csv.matches(CHG).count(), 2, "on each host's row: {csv}");
    let (json, _, _) = core.bulk.render(&ctx, job, ExportFormat::Json, opts).await.unwrap();
    assert!(json.contains(&format!("\"changeId\": \"{CHG}\"")), "{json}");
    let (html, _, _) = core.bulk.render(&ctx, job, ExportFormat::Html, opts).await.unwrap();
    assert!(html.contains(&format!("Change ID {CHG}")));

    // QL-12: a recorded MultiExec line's export reads its job's change ID from the journal.
    let dir = common::temp_folder("change-ids-multiexec");
    let path = dir.join("lines.csv");
    let recorded = [RecordedRun {
        line: "rm -rf /tmp/remotely-test".into(),
        tier: Tier::High,
        recorded_at: "2026-10-26T10:00:00Z".into(),
        job_id: Some(job),
        targets: vec![],
        change_id: None,
    }];
    core.bulk
        .export_recorded(&ctx, &recorded, ExportFormat::Csv, opts, &path)
        .await
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.trim_start_matches('\u{FEFF}')
            .starts_with("line,recorded_at,tier,change_id,"),
        "{text}"
    );
    let path = dir.join("lines.json");
    core.bulk
        .export_recorded(&ctx, &recorded, ExportFormat::Json, opts, &path)
        .await
        .unwrap();
    assert!(std::fs::read_to_string(&path).unwrap().contains(CHG));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_schedules_standing_approval_takes_a_change_id_and_each_run_carries_it() {
    let core = Setup::new(
        listed(FakeVmware::default(), &["web", "db"])
            .with_snapshot(&vmx("web"), "base", time::OffsetDateTime::now_utc())
            .with_snapshot(&vmx("db"), "base", time::OffsetDateTime::now_utc()),
    )
    .build()
    .await;
    let clock = Arc::new(FakeClock::new(
        datetime!(2026-10-26 10:00 UTC),
        FakeZone::central_europe(),
    ));
    core.schedules().set_clock(clock.clone());
    let input = |name: &str, targets: &[&str]| ScheduleInput {
        id: None,
        name: name.into(),
        spec: ScheduleSpec {
            action: ScheduleAction::Snapshot { keep: Some(2) },
            targets: targets.iter().map(|n| ScheduleTarget::Vm { vm_key: vmx(n) }).collect(),
            timing: Timing::Daily {
                at: WallTime::new(12, 0).unwrap(),
            },
        },
    };
    // Retention deletes snapshots: High, so the save asks, with an optional change ID.
    let saved = core.schedules().save(input("nightly", &["web", "db"])).await.unwrap();
    let request = saved.approval.expect("the save asks");
    assert_eq!(change_id_step(&request), Some(false));
    let view = core
        .schedules()
        .approve(request.id, answers(&request, Some("CHG-NIGHTLY")))
        .await
        .unwrap();
    assert_eq!(view.state, ScheduleState::Active);

    // Due at 12:00 in Central Europe, 11:00 UTC.
    clock.advance(time::Duration::hours(1));
    let mut jobs = core.jobs.subscribe();
    let report = core.schedules().tick().await.unwrap();
    core.schedules().wait_runs().await;
    assert_eq!(report.started, 1);
    let run = &core.schedules().runs(view.id, 5).await.unwrap()[0];
    assert!(!run.job_ids.is_empty(), "{run:?}");
    for job in &run.job_ids {
        let _ = jobs.try_recv();
        assert_eq!(job_change_id(&core, *job).await.as_deref(), Some("CHG-NIGHTLY"));
    }

    // A Prod schedule approved without one pauses once the workspace requires change IDs for Prod.
    let ctx = core.ctx();
    core.inventory
        .set_environment(&ctx, &[vmx("db")], Environment::Prod)
        .await
        .unwrap();
    let saved = core.schedules().save(input("prod nightly", &["db"])).await.unwrap();
    let request = saved.approval.expect("asks");
    let view = core
        .schedules()
        .approve(request.id, answers(&request, None))
        .await
        .unwrap();
    assert_eq!(view.state, ScheduleState::Active);
    core.bus
        .set_change_id_rules(
            &ctx,
            ChangeIdRules {
                required_for_prod: true,
            },
        )
        .await
        .unwrap();
    // Each tick checks every active schedule's approval, due or not.
    core.schedules().tick().await.unwrap();
    core.schedules().wait_runs().await;
    let paused = core.schedules().get(view.id).await.unwrap();
    assert_eq!(paused.state, ScheduleState::NeedsApproval, "{paused:?}");
    assert!(paused.state_reason.as_deref().unwrap_or_default().contains("change ID"));
}
