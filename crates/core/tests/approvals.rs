//! Approvals and audit, end to end with fake adapters: editable rules (AP-01), the impact preview
//! (AP-02), type-to-confirm, reason and countdown with cancel (AP-03), and the CSV export (AP-05).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use common::{vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SnapshotOp, StopMode, SubmitOutcome};
use remotely_core::domain::PowerState;
use remotely_core::fakes::{FakeHostCounters, FakeRemote, FakeUpdater, FakeVault, FakeVmware};
use remotely_core::jobs::{JobEvent, JobLimits, JobStatus};
use remotely_core::policy::{ActionKind, PolicyRules, Tier, TierRule};
use remotely_core::store::{Store, POLICY_RULES_KEY};
use remotely_core::vault::SecretString;
use remotely_core::{Adapters, Core, CoreError};
use time::{Duration, OffsetDateTime};

fn two_running() -> FakeVmware {
    FakeVmware::with_running([vmx("web01"), vmx("db01")])
        .in_library(&vmx("web01"), Some("web01"))
        .in_library(&vmx("db01"), Some("db01"))
}

fn pause(names: &[&str]) -> Command {
    Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op: PowerOp::Pause,
    }
}

async fn core_on(store: Store, vmware: Arc<FakeVmware>) -> Core {
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let adapters = Adapters {
        vmware,
        remote: Arc::new(FakeRemote::default()),
        vault: Arc::new(FakeVault::with_password(VAULT_PASSWORD)),
        host_counters: Arc::new(FakeHostCounters::default()),
        updater: Arc::new(FakeUpdater::default()),
    };
    Core::assemble(store, ctx, adapters, JobLimits::default())
        .await
        .unwrap()
}

// ---- AP-01: editable tier rules -----------------------------------------------------------------

#[tokio::test]
async fn edited_rules_are_saved_applied_at_once_audited_and_kept_after_a_restart() {
    let setup = Setup::new(two_running());
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;

    let pause_two = pause(&["web01", "db01"]);
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, pause_two.clone()).await.unwrap() else {
        panic!("pausing is Medium by default");
    };
    assert_eq!(request.tier, Tier::Medium);
    core.bus.cancel_approval(request.id).await.unwrap();

    let mut rules = core.bus.rules();
    rules.tiers.insert(
        ActionKind::VmPause,
        TierRule {
            single: Tier::Medium,
            bulk: Tier::High,
        },
    );
    rules.countdown_seconds = 5;
    let changes = core.bus.set_rules(&core.ctx, rules.clone()).await.unwrap();
    assert_eq!(
        changes,
        [
            "Pause VMs: medium for one, medium in bulk -> medium for one, high in bulk",
            "Countdown: 0 -> 5 s"
        ]
    );

    // Applies to the next command.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, pause_two).await.unwrap() else {
        panic!("now High");
    };
    assert_eq!(request.tier, Tier::High);
    core.bus.cancel_approval(request.id).await.unwrap();

    let changed = core
        .store
        .recent_audit(&core.ctx, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "setting_changed")
        .unwrap();
    assert_eq!(changed.action, "Changed the approval rules");
    assert_eq!(changed.detail.as_deref(), Some(changes.join("; ").as_str()));
    assert!(core.store.verify_audit_chain().await.unwrap().ok);

    // Saved: a restart reads them back.
    let again = core_on(core.store.clone(), fake).await;
    assert_eq!(again.bus.rules(), rules);
}

#[tokio::test]
async fn invalid_rules_are_rejected_with_the_reason_and_nothing_changes() {
    let core = Setup::new(two_running()).build().await;
    let before = core.bus.rules();
    let mut rules = before.clone();
    rules.tiers.insert(
        ActionKind::SnapshotRevert,
        TierRule {
            single: Tier::High,
            bulk: Tier::Low,
        },
    );
    let err = core.bus.set_rules(&core.ctx, rules).await.unwrap_err();
    assert!(matches!(err, CoreError::InvalidRule { .. }));
    assert_eq!(err.code(), "invalid_rule");
    assert_eq!(
        err.to_string(),
        "invalid policy rule 'Revert to a snapshot': the tier for 2 or more targets (low) can't be lower than for one target (high)"
    );
    assert_eq!(core.bus.rules(), before);
    assert!(core.store.recent_audit(&core.ctx, 5).await.unwrap().is_empty());
}

#[tokio::test]
async fn saving_the_same_rules_again_changes_and_logs_nothing() {
    let core = Setup::new(two_running()).build().await;
    // Spaces typed around a name are not a change.
    let mut rules = core.bus.rules();
    rules.read_only_commands[0] = format!("  {}  ", rules.read_only_commands[0]);
    assert!(core.bus.set_rules(&core.ctx, rules).await.unwrap().is_empty());
    assert!(core.store.recent_audit(&core.ctx, 5).await.unwrap().is_empty());
}

#[tokio::test]
async fn saved_rules_that_no_longer_pass_the_checks_fall_back_to_the_defaults_and_say_so() {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let broken = PolicyRules {
        countdown_seconds: 9999,
        ..Default::default()
    };
    store.put_setting(&ctx, POLICY_RULES_KEY, &broken).await.unwrap();

    let core = core_on(store, Arc::new(two_running())).await;
    assert_eq!(core.bus.rules(), PolicyRules::default());
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].action, "Reset the approval rules to the defaults");
    assert!(audit[0].detail.as_deref().unwrap().contains("Countdown"));
}

// ---- AP-02: impact preview ----------------------------------------------------------------------

#[tokio::test]
async fn the_approval_shows_each_vms_state_uptime_and_snapshot_count() {
    let now = OffsetDateTime::now_utc();
    let fake = FakeVmware::with_running([vmx("web01")])
        .in_library(&vmx("web01"), Some("web01"))
        .in_library(&vmx("db01"), Some("db01"))
        .with_vmx(
            &vmx("db01"),
            VmxInfo {
                display_name: Some("db01".into()),
                suspended: true,
                ..Default::default()
            },
        )
        .with_started_at(&vmx("web01"), now - Duration::hours(3))
        .with_snapshot(&vmx("web01"), "base", now - Duration::days(40))
        .with_snapshot(&vmx("web01"), "patched", now - Duration::days(1));
    let core = Setup::new(fake).build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();

    let stop = Command::VmPower {
        targets: vec![vm("web01"), vm("db01")],
        op: PowerOp::Stop { mode: StopMode::Soft },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, stop).await.unwrap() else {
        panic!("High");
    };
    let [web, db] = &request.impact[..] else {
        panic!("one entry per VM: {:?}", request.impact);
    };
    assert_eq!(web.target, vmx("web01"));
    assert_eq!(web.power_state, PowerState::Running);
    let uptime = web.uptime_secs.unwrap();
    assert!((3 * 3600..3 * 3600 + 60).contains(&uptime), "{uptime}");
    assert!(web.running_since.is_some());
    assert_eq!((web.snapshot_count, web.old_snapshot_count), (Some(2), Some(1)));
    assert!(web.notes.is_empty(), "{:?}", web.notes);

    assert_eq!(db.power_state, PowerState::Suspended);
    assert_eq!(db.uptime_secs, None, "only a running VM has an uptime");
    assert_eq!(db.snapshot_count, Some(0));
}

#[tokio::test]
async fn a_medium_confirm_shows_the_impact_too() {
    let core = Setup::new(two_running()).build().await;
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, pause(&["web01"])).await.unwrap() else {
        panic!("Medium");
    };
    assert_eq!(request.impact.len(), 1);
    assert_eq!(request.impact[0].power_state, PowerState::Running);
    assert!(
        request.impact[0].notes.iter().any(|n| n.contains("no vmware.log")),
        "a missing uptime is said, not hidden: {:?}",
        request.impact[0].notes
    );
}

#[tokio::test]
async fn without_vmrun_the_preview_uses_the_last_known_state_and_says_so() {
    let core = Setup::new(two_running().without_vmrun()).build().await;
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, pause(&["web01"])).await.unwrap() else {
        panic!("Medium");
    };
    let impact = &request.impact[0];
    assert_eq!(impact.power_state, PowerState::Unknown, "never refreshed");
    assert!(impact
        .notes
        .iter()
        .any(|n| n.starts_with("State from the last refresh")));
}

// ---- AP-03: type-to-confirm, reason, countdown with cancel ---------------------------------------

fn countdown_setup(seconds: u32) -> Setup {
    let mut setup = Setup::new(two_running());
    setup.rules.countdown_seconds = seconds;
    setup
}

fn suspend_two() -> Command {
    Command::VmPower {
        targets: vec![vm("web01"), vm("db01")],
        op: PowerOp::Suspend,
    }
}

#[tokio::test]
async fn type_to_confirm_and_a_reason_are_required_and_a_wrong_answer_can_be_corrected() {
    let setup = countdown_setup(0);
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend_two()).await.unwrap() else {
        panic!("High");
    };
    let answer = |count: Option<usize>, reason: Option<&str>| ApprovalAnswers {
        confirmed: true,
        typed_target_count: count,
        reason: reason.map(String::from),
        ..Default::default()
    };
    for (bad, says) in [
        (answer(None, Some("CHG-1")), "type the number of targets (2)"),
        (answer(Some(1), Some("CHG-1")), "type the number of targets (2)"),
        (answer(Some(2), None), "a reason or ticket number is required"),
        (answer(Some(2), Some(" \t ")), "a reason or ticket number is required"),
        (
            ApprovalAnswers {
                confirmed: false,
                ..answer(Some(2), Some("CHG-1"))
            },
            "not confirmed",
        ),
    ] {
        let err = core.bus.approve(request.id, bad).await.unwrap_err();
        assert!(err.to_string().contains(says), "{err}");
    }
    assert!(fake.calls().is_empty(), "nothing ran");

    let mut events = core.jobs.subscribe();
    let job = core
        .bus
        .approve(request.id, answer(Some(2), Some("  CHG-1 token=abc123  ")))
        .await
        .unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    let granted = core
        .store
        .recent_audit(&core.ctx, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "approval_granted")
        .unwrap();
    let approval = granted.approval_json.unwrap();
    assert!(approval.contains("\"reason\":\"CHG-1 token=[redacted]\""), "{approval}");
    assert!(approval.contains("\"typedTargetCount\":2"));
}

#[tokio::test]
async fn the_countdown_is_visible_and_cancelling_it_touches_no_vm() {
    let setup = countdown_setup(10);
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend_two()).await.unwrap() else {
        panic!("High");
    };
    assert!(request
        .steps
        .contains(&remotely_core::policy::ApprovalStep::Countdown { seconds: 10 }));
    let approved_at = OffsetDateTime::now_utc();
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(2),
        reason: Some("CHG-1".into()),
        ..Default::default()
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();

    // The UI hears when it ends, and Activity can read it from the journal.
    let until = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let JobEvent::Countdown { job_id, seconds, until } = events.recv().await.unwrap() {
                if job_id == job {
                    assert_eq!(seconds, 10);
                    return until;
                }
            }
        }
    })
    .await
    .unwrap();
    let until = OffsetDateTime::parse(&until, &time::format_description::well_known::Rfc3339).unwrap();
    let wait = until - approved_at;
    assert!(wait > Duration::seconds(9) && wait < Duration::seconds(11), "{wait}");
    let listed = &core.store.recent_jobs(&core.ctx, 1).await.unwrap()[0];
    assert_eq!(listed.status, "countdown");
    assert!(listed.countdown_until.is_some());

    assert!(core.jobs.cancel(job), "the open job can be cancelled");
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Cancelled);
    assert!(fake.calls().is_empty(), "no safety snapshot, no suspend");
    assert!(!core.jobs.cancel(job), "a closed job cannot be cancelled again");
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "job_cancelled");
    assert!(core
        .store
        .job_targets(&core.ctx, job)
        .await
        .unwrap()
        .iter()
        .all(|t| t.status == "pending"));
}

#[tokio::test]
async fn the_job_runs_once_the_countdown_ends() {
    let setup = countdown_setup(1);
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend_two()).await.unwrap() else {
        panic!("High");
    };
    let started = std::time::Instant::now();
    let job = core
        .bus
        .approve(
            request.id,
            ApprovalAnswers {
                confirmed: true,
                typed_target_count: Some(2),
                reason: Some("CHG-1".into()),
                safety_snapshot: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert!(started.elapsed() >= StdDuration::from_millis(950));
    assert_eq!(fake.calls().len(), 2);
}

// ---- AP-05: CSV export ----------------------------------------------------------------------------

#[tokio::test]
async fn the_audit_log_exports_to_csv_without_secrets_and_the_export_is_logged() {
    let setup = countdown_setup(0);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();

    // A Critical action: the vault password is given, and must never reach the export.
    let off = Command::VmPower {
        targets: vec![vm("web01")],
        op: PowerOp::Stop { mode: StopMode::Hard },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, off).await.unwrap() else {
        panic!("Critical");
    };
    let job = core
        .bus
        .approve(
            request.id,
            ApprovalAnswers {
                confirmed: true,
                typed_target_count: Some(1),
                reason: Some("hung guest, password=hunter2".into()),
                safety_snapshot: Some(true),
                vault_password: Some(SecretString::new(VAULT_PASSWORD)),
            },
        )
        .await
        .unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    let take = Command::VmSnapshot {
        targets: vec![vm("db01")],
        op: SnapshotOp::Take {
            name: "x, \"quoted\"".into(),
        },
    };
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, take).await.unwrap() else {
        panic!("Low");
    };
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);

    let entries = core.store.audit_for_export(&core.ctx).await.unwrap().len();
    let dir = common::temp_folder("export");
    let path = dir.join("audit.csv");
    let report = core.export_audit_csv(&path).await.unwrap();
    assert_eq!(report.entries, entries);
    assert_eq!(report.redacted, 0, "the reason was redacted before it was stored");

    let csv = std::fs::read_to_string(&path).unwrap();
    for secret in [VAULT_PASSWORD, "hunter2"] {
        assert!(!csv.contains(secret), "the export holds {secret:?}");
    }
    assert!(csv.contains("password=[redacted]"));
    assert_eq!(
        csv.trim_end().split("\r\n").count(),
        entries + 1,
        "a header and one row per entry"
    );
    assert!(csv.contains("\"Take snapshot 'x, \"\"quoted\"\"' on 1 VM\""), "{csv}");

    let last = &core.store.recent_audit(&core.ctx, 1).await.unwrap()[0];
    assert_eq!(last.event, "audit_exported");
    assert_eq!(
        last.detail.as_deref(),
        Some(format!("{entries} entries to audit.csv").as_str())
    );
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// RFC 4180 rows: quoted cells may hold commas, doubled quotes and line breaks.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut cell) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut chars) = (false, text.trim_start_matches('\u{FEFF}').chars().peekable());
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => cell.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut cell)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => cell.push(c),
        }
    }
    rows
}

#[tokio::test]
async fn the_hash_chain_can_be_checked_from_the_exported_file_alone() {
    let setup = countdown_setup(0);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend_two()).await.unwrap() else {
        panic!("High");
    };
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(2),
        reason: Some("CHG-7, \"quoted\"\nnext line".into()),
        ..Default::default()
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);

    let dir = common::temp_folder("verify");
    let path = dir.join("audit.csv");
    core.export_audit_csv(&path).await.unwrap();
    let rows = parse_csv(&std::fs::read_to_string(&path).unwrap());
    let header = &rows[0];
    let col = |row: &[String], name: &str| row[header.iter().position(|h| h == name).unwrap()].clone();
    let opt = |v: String| (!v.is_empty()).then_some(v);

    let mut prev = remotely_core::store::GENESIS_HASH.to_owned();
    for row in &rows[1..] {
        let entry = remotely_core::store::AuditEntry {
            seq: col(row, "seq").parse().unwrap(),
            id: col(row, "id"),
            workspace_id: col(row, "workspace_id"),
            user_id: col(row, "user_id"),
            ts: col(row, "time"),
            event: col(row, "event"),
            action: col(row, "action"),
            tier: opt(col(row, "tier")),
            job_id: opt(col(row, "job_id")),
            targets_json: col(row, "targets_json"),
            approval_json: opt(col(row, "approval_json")),
            result: opt(col(row, "result")),
            detail: opt(col(row, "detail")),
            prev_hash: col(row, "prev_hash"),
            hash: col(row, "hash"),
        };
        assert_eq!(entry.prev_hash, prev, "row {} links to the row before", entry.seq);
        assert_eq!(entry.compute_hash(), entry.hash, "row {} matches its hash", entry.seq);
        prev = entry.hash;
    }
    assert_eq!(rows.len() - 1, 4, "requested, granted, started, finished");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_secret_typed_into_a_command_never_reaches_the_audit_log() {
    let summary = Command::RemoteExec {
        targets: vec![],
        script: "deploy --token s3cr3t\nsecond line".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
    }
    .summary(2);
    assert_eq!(summary, "Run `deploy --token [redacted]` on 2 hosts");
}
