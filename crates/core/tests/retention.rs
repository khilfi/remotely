//! BX-02, BX-05, SS-10, SS-11, AP-05: how much customer data the app keeps, and how long, end to end with fake
//! adapters: the job journal stores scripts without their secrets, the retention purge empties old jobs' outputs
//! and command text (keeping their rows, and the audit chain intact), the setting and "Purge now" are audited and
//! refused while presenting with the lock on (the scheduled purge is not), compacting waits for jobs, and no save
//! path writes into a Git working tree.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::bulk::{ExportFormat, GroupOptions, RecordedRun};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::{FakeRemote, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::presentation::Presentation;
use remotely_core::retention::Retention;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::output::{SaveLayout, TerminalText};
use remotely_core::vault::SecretString;
use remotely_core::{Core, CoreError};
use uuid::Uuid;

const LOCKED: Presentation = Presentation {
    enabled: true,
    read_only: true,
};

fn session(name: &str) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: format!("{name}.example.com"),
        port: 22,
        username: Some("alice".into()),
        auth: SessionAuth::Agent,
        jump_session_id: None,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

fn exec(script: &str, sessions: &[Uuid]) -> Command {
    Command::RemoteExec {
        targets: sessions
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect(),
        script: script.into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Default::default(),
    }
}

fn answers(request: &ApprovalRequest) -> ApprovalAnswers {
    let mut a = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => a.typed_target_count = Some(*expected),
            ApprovalStep::Reason => a.reason = Some("CHG-1234".into()),
            ApprovalStep::VaultReauth => a.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            _ => {}
        }
    }
    a
}

/// Submits, approving whatever it needs, and waits for the end.
async fn run(core: &Core, command: Command) -> Uuid {
    let mut events = core.jobs.subscribe();
    let job = match core.bus.submit(&core.ctx, command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core.bus.approve(request.id, answers(&request)).await.unwrap(),
    };
    wait_finished(&mut events, job).await;
    job
}

/// Two hosts, web02 failing its commands.
async fn core_with_hosts() -> (Core, Vec<Uuid>) {
    let remote = FakeRemote::default()
        .with_output("web01.example.com", "Filesystem Size Used\n/dev/sda1 20G 5G\n")
        .with_exit_code("web02.example.com", 1);
    let core = Setup::new(FakeVmware::default())
        .with_remote(Arc::new(remote))
        .build()
        .await;
    let mut ids = Vec::new();
    for name in ["web01", "web02"] {
        ids.push(core.sessions.create(&core.ctx, session(name)).await.unwrap().id);
    }
    (core, ids)
}

async fn backdate(core: &Core, job: Uuid, days: i64) {
    let at = time::OffsetDateTime::now_utc() - time::Duration::days(days);
    let at = at.format(&time::format_description::well_known::Rfc3339).unwrap();
    sqlx::query("UPDATE jobs SET created_at = ? WHERE id = ?")
        .bind(at)
        .bind(job.to_string())
        .execute(core.store.pool())
        .await
        .unwrap();
}

fn locked_out<T: std::fmt::Debug>(result: remotely_core::Result<T>) {
    match result {
        Err(err @ CoreError::ReadOnlyLock { .. }) => assert_eq!(err.code(), "read_only_lock"),
        other => panic!("expected the read-only lock to refuse, got {other:?}"),
    }
}

fn in_repository(err: CoreError) {
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert!(err.to_string().contains("inside a Git repository"), "{err}");
}

#[tokio::test]
async fn a_run_keeps_no_secret_and_loses_its_outputs_after_the_retention_period() {
    let (core, ids) = core_with_hosts().await;
    let old = run(&core, exec("df -h --password=hunter2", &ids)).await;
    let new = run(&core, exec("df -h", &ids)).await;
    backdate(&core, old, 100).await;

    // Stored without the secret, and marked: it can't be retried as it ran.
    let (summary, command) = core.store.job_detail(&core.ctx, old).await.unwrap().unwrap();
    assert!(summary.command_redacted);
    let Command::RemoteExec { script, .. } = &command else {
        panic!("{command:?}")
    };
    assert_eq!(script, "df -h --password=[redacted]");
    let all_audit = core.store.audit_for_export(&core.ctx).await.unwrap();
    assert!(all_audit.iter().all(|e| !format!("{e:?}").contains("hunter2")));
    // Refused whether or not the retry takes hosts whose outcome is unknown (H9).
    for include_unknown in [false, true] {
        let err = core
            .bus
            .retry_failed(&core.ctx, old, include_unknown)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("looked like a secret"), "{err}");
    }

    // The default keeps 90 days: the purge at start (here, scheduled) removes the old run's outputs and script.
    assert_eq!(core.retention.retention().await.unwrap(), Retention::Days90);
    let report = core.retention.purge_scheduled().await.unwrap();
    assert_eq!(
        (report.removed.jobs, report.removed.outputs, report.removed.commands),
        (1, 2, 1)
    );
    assert!(report.removed.bytes > 0);
    assert!(!report.by_hand);

    // Activity still lists both, with their results.
    let jobs = core.store.recent_jobs(&core.ctx, 10).await.unwrap();
    assert_eq!(jobs.len(), 2);
    let old_row = jobs.iter().find(|j| j.id == old.to_string()).unwrap();
    assert!(old_row.bodies_removed);
    assert_eq!(old_row.status, "partially_failed");
    assert_eq!((old_row.targets_succeeded, old_row.targets_failed), (1, 1));
    assert!(!jobs.iter().find(|j| j.id == new.to_string()).unwrap().bodies_removed);
    for t in core.store.job_targets(&core.ctx, old).await.unwrap() {
        assert_eq!((t.output, t.stderr), (None, None));
    }
    assert!(core.store.job_targets(&core.ctx, new).await.unwrap()[0]
        .output
        .is_some());
    // Compare still groups the old run (by its hashes) and says it is gone.
    let results = core
        .bulk
        .results(&core.ctx, old, GroupOptions::default())
        .await
        .unwrap();
    assert!(results.job.bodies_removed);
    assert_eq!(results.run.as_ref().unwrap().script, "");
    assert_eq!(results.counts.failed, 1);
    // Refused whether or not the retry takes hosts whose outcome is unknown (H9).
    for include_unknown in [false, true] {
        let err = core
            .bus
            .retry_failed(&core.ctx, old, include_unknown)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("retention period"), "{err}");
    }

    // Audited with what went; the chain still verifies.
    let last = &core.store.recent_audit(&core.ctx, 1).await.unwrap()[0];
    assert_eq!(last.event, "journal_purged");
    assert_eq!(last.action, "Removed old job outputs and command text");
    let detail = last.detail.as_deref().unwrap();
    assert!(detail.starts_with("older than 90 days"), "{detail}");
    assert!(detail.contains("removed 2 outputs and 1 script or line"), "{detail}");
    assert!(core.store.verify_audit_chain().await.unwrap().ok);

    // A scheduled purge with nothing to do writes no audit entry; Purge now always does.
    let before = core.store.recent_audit(&core.ctx, 100).await.unwrap().len();
    let quiet = core.retention.purge_scheduled().await.unwrap();
    assert!(!quiet.removed.removed_any());
    assert_eq!(core.store.recent_audit(&core.ctx, 100).await.unwrap().len(), before);
    let by_hand = core.retention.purge_now().await.unwrap();
    assert!(by_hand.by_hand);
    let last = &core.store.recent_audit(&core.ctx, 1).await.unwrap()[0];
    assert_eq!(
        (last.event.as_str(), last.action.as_str()),
        ("journal_purged", "Purged old job outputs and command text")
    );
    assert!(last
        .detail
        .as_deref()
        .unwrap()
        .starts_with("nothing older than 90 days"));
    let info = core.retention.info().await.unwrap();
    assert_eq!(info.last_purge.unwrap().at, by_hand.at);
}

#[tokio::test]
async fn the_setting_is_audited_and_locked_while_presenting_but_the_schedule_is_not() {
    let (core, ids) = core_with_hosts().await;
    let job = run(&core, exec("uptime", &ids)).await;
    backdate(&core, job, 40).await;

    let info = core.retention.set_retention(Retention::Days30).await.unwrap();
    assert_eq!(info.retention, Retention::Days30);
    assert_eq!(core.retention.retention().await.unwrap(), Retention::Days30);
    let last = &core.store.recent_audit(&core.ctx, 1).await.unwrap()[0];
    assert_eq!(last.event, "setting_changed");
    assert_eq!(last.action, "Set how long job outputs and command text are kept");
    assert!(last.detail.as_deref().unwrap().starts_with("90 days -> 30 days"));
    // The same again changes and logs nothing.
    let before = core.store.recent_audit(&core.ctx, 100).await.unwrap().len();
    core.retention.set_retention(Retention::Days30).await.unwrap();
    assert_eq!(core.store.recent_audit(&core.ctx, 100).await.unwrap().len(), before);

    core.presentation.set(LOCKED).await.unwrap();
    locked_out(core.retention.set_retention(Retention::Forever).await);
    locked_out(core.retention.purge_now().await);
    assert_eq!(core.retention.retention().await.unwrap(), Retention::Days30);
    // The schedule goes on: customer data still leaves on time.
    let report = core.retention.purge_scheduled().await.unwrap();
    assert_eq!((report.removed.jobs, report.removed.outputs), (1, 2));
    assert_eq!(
        core.store.recent_audit(&core.ctx, 1).await.unwrap()[0].event,
        "journal_purged"
    );

    core.presentation.set(Presentation::default()).await.unwrap();
    let info = core.retention.set_retention(Retention::Forever).await.unwrap();
    assert_eq!(info.retention, Retention::Forever);
    let report = core.retention.purge_now().await.unwrap();
    assert_eq!(report.before, None);
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn compacting_waits_until_no_job_runs() {
    let remote = FakeRemote::default().with_delay("slow01.example.com", Duration::from_millis(800));
    let core = Setup::new(FakeVmware::default())
        .with_remote(Arc::new(remote))
        .build()
        .await;
    let slow = core.sessions.create(&core.ctx, session("slow01")).await.unwrap().id;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bus.submit(&core.ctx, exec("uptime", &[slow])).await.unwrap()
    else {
        panic!("read-only on one host is Low");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(core.jobs.when_idle(async { "compacted" }).await, None, "a job is open");
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    assert_eq!(core.jobs.when_idle(async { "compacted" }).await, Some("compacted"));
}

#[tokio::test]
async fn no_save_path_writes_into_a_git_working_tree() {
    let (core, ids) = core_with_hosts().await;
    let job = run(&core, exec("uptime", &ids)).await;
    let repo = common::temp_folder("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let inside = repo.join("notes");
    std::fs::create_dir_all(&inside).unwrap();
    let outside = common::temp_folder("plain");

    // AP-05: the audit log CSV.
    in_repository(core.export_audit_csv(&inside.join("audit.csv")).await.unwrap_err());
    // BX-05: Compare results.
    in_repository(
        core.bulk
            .export(
                &core.ctx,
                job,
                ExportFormat::Csv,
                GroupOptions::default(),
                &inside.join("run.csv"),
            )
            .await
            .unwrap_err(),
    );
    // QL-12: recorded MultiExec lines.
    let recorded = [RecordedRun {
        line: "uptime".into(),
        tier: Tier::Low,
        recorded_at: "2026-10-25T08:00:00Z".into(),
        job_id: None,
        targets: vec![],
    }];
    in_repository(
        core.bulk
            .export_recorded(
                &core.ctx,
                &recorded,
                ExportFormat::Json,
                GroupOptions::default(),
                &inside.join("lines.json"),
            )
            .await
            .unwrap_err(),
    );
    // SS-11: saved output, in one file or one per terminal, and session logs.
    let text = || {
        vec![TerminalText {
            terminal_id: None,
            title: "web01".into(),
            text: "alice@web01:~$ uptime\n".into(),
        }]
    };
    in_repository(
        core.terminals
            .save_output(&core.ctx, text(), SaveLayout::OneFile, &inside.join("out.txt"))
            .await
            .unwrap_err(),
    );
    in_repository(
        core.terminals
            .save_output(&core.ctx, text(), SaveLayout::FilePerTerminal, &inside)
            .await
            .unwrap_err(),
    );
    in_repository(
        core.terminals
            .start_log(&core.ctx, Uuid::new_v4(), &inside.join("web01.log"))
            .await
            .unwrap_err(),
    );
    // SS-08: downloads.
    in_repository(
        core.terminals
            .download(&core.ctx, Uuid::new_v4(), &["/etc/hosts".into()], &inside)
            .await
            .unwrap_err(),
    );
    assert_eq!(
        std::fs::read_dir(&inside).unwrap().count(),
        0,
        "nothing was written there"
    );

    // Outside a repository, the same saves work.
    let report = core.export_audit_csv(&outside.join("audit.csv")).await.unwrap();
    assert!(report.entries > 0);
    let csv = std::fs::read_to_string(outside.join("audit.csv")).unwrap();
    assert_eq!(csv.trim_end().split("\r\n").count(), report.entries + 1);
    assert!(
        !outside.join("audit.csv.part").exists(),
        "written next to it, then renamed"
    );
    core.bulk
        .export(
            &core.ctx,
            job,
            ExportFormat::Csv,
            GroupOptions::default(),
            &outside.join("run.csv"),
        )
        .await
        .unwrap();
    core.terminals
        .save_output(&core.ctx, text(), SaveLayout::OneFile, &outside.join("out.txt"))
        .await
        .unwrap();
    std::fs::remove_dir_all(&repo).unwrap();
    std::fs::remove_dir_all(&outside).unwrap();
}
