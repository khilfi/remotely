//! BX-02, BX-05, SS-10, AP-05: the journal's retention purge, redaction of what it stores, secure delete, the
//! Activity query on a long journal, and streaming the audit log.

use super::jobs::{NewJob, PAGE_ANY_SQL, PAGE_OF_TYPE_SQL};
use super::*;
use crate::command_bus::{Command, PowerOp};
use crate::domain::{Environment, Target, TargetRef};
use crate::jobs::{JobStatus, TargetStatus};
use crate::policy::{ActionKind, Tier};
use futures_util::TryStreamExt;
use sqlx::Row;

async fn store_with_identity() -> (Store, Context) {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    (store, ctx)
}

fn session(name: &str) -> Target {
    Target {
        target: TargetRef::Session {
            session_id: Uuid::new_v4(),
        },
        name: name.into(),
        environment: Environment::Lab,
        protected: false,
    }
}

fn exec(script: &str) -> Command {
    Command::RemoteExec {
        targets: vec![],
        script: script.into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
    }
}

fn line(text: &str) -> Command {
    Command::TerminalLine {
        targets: vec![],
        line: text.into(),
        unreliable: false,
        keys: format!("\r{text}\r"),
    }
}

fn power() -> Command {
    Command::VmPower {
        targets: vec![],
        op: PowerOp::Suspend,
    }
}

/// Journals `command` on `targets`, finished, each target with output, `days` days ago.
async fn journal(store: &Store, ctx: &Context, command: &Command, targets: &[Target], days: i64) -> Uuid {
    let id = Uuid::new_v4();
    let summary = command.summary(targets.len());
    store
        .insert_job(
            ctx,
            NewJob {
                id,
                summary: &summary,
                action: ActionKind::ExecReadOnly,
                tier: Tier::Low,
                command,
                approval: None,
                targets,
                status: JobStatus::Queued,
                countdown_until: None,
                retry_of: None,
            },
        )
        .await
        .unwrap();
    for t in targets {
        let key = t.target.key();
        let out = format!("output of {} on {}\n", summary, t.name);
        store
            .set_target_result(
                id,
                &key,
                TargetResult {
                    status: Some(TargetStatus::Succeeded),
                    exit_code: Some(0),
                    output: Some(&out),
                    stderr: Some("warning: example\n"),
                    stdout_bytes: Some(out.len() as i64),
                    stderr_bytes: Some(17),
                    output_hash: Some("hash-exact"),
                    output_hash_loose: Some("hash-loose"),
                    duration_ms: Some(12),
                    ..TargetResult::default()
                },
            )
            .await
            .unwrap();
    }
    store.set_job_status(id, JobStatus::Succeeded).await.unwrap();
    backdate(store, id, days).await;
    id
}

async fn backdate(store: &Store, id: Uuid, days: i64) {
    let at = time::OffsetDateTime::now_utc() - time::Duration::days(days);
    let at = at.format(&time::format_description::well_known::Rfc3339).unwrap();
    sqlx::query("UPDATE jobs SET created_at = ? WHERE id = ?")
        .bind(at)
        .bind(id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
}

fn days_ago(days: i64) -> String {
    let at = time::OffsetDateTime::now_utc() - time::Duration::days(days);
    at.format(&time::format_description::well_known::Rfc3339).unwrap()
}

async fn command_json(store: &Store, id: Uuid) -> String {
    sqlx::query_scalar("SELECT command_json FROM jobs WHERE id = ?")
        .bind(id.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn secure_delete_is_on_for_files_and_memory() {
    let (memory, _) = store_with_identity().await;
    let on: i64 = sqlx::query_scalar("PRAGMA secure_delete")
        .fetch_one(memory.pool())
        .await
        .unwrap();
    assert_eq!(on, 1);

    let path = std::env::temp_dir().join(format!("remotely-secure-{}.db", Uuid::new_v4()));
    let file = Store::open(&path).await.unwrap();
    // Every connection of the pool, not just the first.
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut conn = file.pool().acquire().await.unwrap();
        let on: i64 = sqlx::query_scalar("PRAGMA secure_delete")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(on, 1);
        held.push(conn);
    }
    drop(held);
    file.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn the_journal_stores_scripts_lines_and_summaries_without_their_secrets() {
    let (store, ctx) = store_with_identity().await;
    let targets = [session("web01"), session("web02")];
    let script = "export API_KEY=sk-example-123\nmysql --password=hunter2 -e 'select 1'";
    let run = journal(&store, &ctx, &exec(script), &targets, 0).await;
    let typed = journal(
        &store,
        &ctx,
        &line("curl -H 'Authorization: Bearer abc.def' https://example.com"),
        &targets,
        0,
    )
    .await;
    let plain = journal(&store, &ctx, &exec("uptime"), &targets, 0).await;

    for id in [run, typed] {
        let json = command_json(&store, id).await;
        for secret in ["sk-example-123", "hunter2", "abc.def"] {
            assert!(!json.contains(secret), "{json}");
        }
        assert!(json.contains("[redacted]"), "{json}");
    }
    let (summary, command) = store.job_detail(&ctx, run).await.unwrap().unwrap();
    assert!(summary.command_redacted);
    assert!(!summary.summary.contains("sk-example-123"), "{}", summary.summary);
    let Command::RemoteExec { script, .. } = command else {
        panic!("{command:?}")
    };
    assert_eq!(
        script,
        "export API_KEY=[redacted]\nmysql --password=[redacted] -e 'select 1'"
    );
    let (summary, command) = store.job_detail(&ctx, plain).await.unwrap().unwrap();
    assert!(!summary.command_redacted);
    assert_eq!(command, exec("uptime"));
    let types: Vec<String> = sqlx::query_scalar("SELECT command_type FROM jobs ORDER BY rowid")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert_eq!(types, ["remoteExec", "terminalLine", "remoteExec"]);
}

#[tokio::test]
async fn audit_summaries_and_details_are_stored_redacted_and_still_verify() {
    let (store, ctx) = store_with_identity().await;
    let entry = store
        .append_audit(
            &ctx,
            NewAuditEntry {
                event: "job_started",
                action: "Run `deploy --token=abc123` on 2 hosts",
                tier: Some(Tier::Medium),
                job_id: None,
                targets: &[],
                approval: None,
                result: Some("password: hunter2"),
                detail: Some("curl https://alice:s3cret@example.com/x"),
            },
        )
        .await
        .unwrap();
    assert_eq!(entry.action, "Run `deploy --token=[redacted]` on 2 hosts");
    assert_eq!(entry.result.as_deref(), Some("password: [redacted]"));
    assert_eq!(
        entry.detail.as_deref(),
        Some("curl https://alice:[redacted]@example.com/x")
    );
    let stored = store.recent_audit(&ctx, 1).await.unwrap();
    assert_eq!(stored[0].action, entry.action);
    assert!(store.verify_audit_chain().await.unwrap().ok, "hashed as stored");
}

#[tokio::test]
async fn the_purge_empties_old_bodies_and_keeps_everything_else() {
    let (store, ctx) = store_with_identity().await;
    let targets = [session("web01"), session("db01")];
    let old_run = journal(&store, &ctx, &exec("cat /etc/hosts"), &targets, 120).await;
    let old_line = journal(&store, &ctx, &line("df -h"), &targets[..1], 100).await;
    let old_power = journal(&store, &ctx, &power(), &targets[..1], 95).await;
    let recent = journal(&store, &ctx, &exec("uptime"), &targets, 10).await;
    // Still open: never purged, however old.
    let open = journal(&store, &ctx, &exec("sleep 1000"), &targets[..1], 200).await;
    store.set_job_status(open, JobStatus::Running).await.unwrap();
    for event in ["job_started", "job_finished"] {
        store
            .append_audit(
                &ctx,
                NewAuditEntry {
                    event,
                    action: "Run `cat /etc/hosts` on 2 hosts",
                    tier: Some(Tier::Low),
                    job_id: Some(old_run),
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: None,
                },
            )
            .await
            .unwrap();
    }
    let before_audit = store.recent_audit(&ctx, 10).await.unwrap();
    let mut out_bytes = 0;
    for id in [old_run, old_line, old_power] {
        for t in store.job_targets(&ctx, id).await.unwrap() {
            out_bytes += (t.output.unwrap_or_default().len() + t.stderr.unwrap_or_default().len()) as u64;
        }
    }
    let body_bytes = ("cat /etc/hosts".len() + "df -h".len() + "\rdf -h\r".len()) as u64;

    let purged = store.purge_job_bodies(&ctx, &days_ago(90)).await.unwrap();
    assert_eq!(
        purged,
        PurgedBodies {
            jobs: 3,
            outputs: 4,
            commands: 2,
            bytes: out_bytes + body_bytes,
        }
    );

    // The rows stay, with their summaries, tiers, statuses, counts, hashes and exit codes.
    let jobs = store.recent_jobs(&ctx, 10).await.unwrap();
    assert_eq!(jobs.len(), 5);
    let row = jobs.iter().find(|j| j.id == old_run.to_string()).unwrap();
    assert!(row.bodies_removed);
    assert_eq!(row.summary, "Run `cat /etc/hosts` on 2 hosts");
    assert_eq!((row.tier.as_str(), row.status.as_str()), ("low", "succeeded"));
    assert_eq!((row.targets_total, row.targets_succeeded), (2, 2));
    for t in store.job_targets(&ctx, old_run).await.unwrap() {
        assert_eq!((t.output, t.stderr), (None, None));
        assert_eq!((t.status.as_str(), t.exit_code), ("succeeded", Some(0)));
        assert_eq!(t.output_hash.as_deref(), Some("hash-exact"));
        assert_eq!(t.output_hash_loose.as_deref(), Some("hash-loose"));
        assert!(t.stdout_bytes.is_some());
        assert_eq!(t.duration_ms, Some(12));
    }
    // The script and the line are gone; the commands still read back.
    let (_, command) = store.job_detail(&ctx, old_run).await.unwrap().unwrap();
    assert_eq!(command, exec(""));
    let (_, command) = store.job_detail(&ctx, old_line).await.unwrap().unwrap();
    let Command::TerminalLine { line, keys, .. } = command else {
        panic!("{command:?}")
    };
    assert_eq!((line.as_str(), keys.as_str()), ("", ""));
    assert_eq!(store.job_detail(&ctx, old_power).await.unwrap().unwrap().1, power());

    // Newer and open jobs are untouched.
    for id in [recent, open] {
        let (summary, command) = store.job_detail(&ctx, id).await.unwrap().unwrap();
        assert!(!summary.bodies_removed);
        assert_ne!(command, exec(""));
        assert!(store.job_targets(&ctx, id).await.unwrap()[0].output.is_some());
    }

    // The audit log is not touched, and still verifies.
    assert_eq!(store.recent_audit(&ctx, 10).await.unwrap().len(), before_audit.len());
    assert!(store.verify_audit_chain().await.unwrap().ok);

    // Done once: nothing is read again.
    assert_eq!(
        store.purge_job_bodies(&ctx, &days_ago(90)).await.unwrap(),
        PurgedBodies::default()
    );
    // A shorter limit reaches the newer job.
    let purged = store.purge_job_bodies(&ctx, &days_ago(5)).await.unwrap();
    assert_eq!((purged.jobs, purged.outputs, purged.commands), (1, 2, 1));
}

#[tokio::test]
async fn the_purge_works_in_batches_and_frees_the_space() {
    let (store, ctx) = store_with_identity().await;
    let target = [session("web01")];
    let big = "x".repeat(60 * 1024);
    let mut ids = Vec::new();
    for _ in 0..450 {
        let id = journal(&store, &ctx, &exec("cat big.log"), &target, 400).await;
        sqlx::query("UPDATE job_targets SET output = ? WHERE job_id = ?")
            .bind(&big)
            .bind(id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        ids.push(id);
    }
    let (size, free) = store.space().await.unwrap();
    assert!(size > 25 * 1024 * 1024, "{size}");
    assert_eq!(free, 0);
    let purged = store.purge_job_bodies(&ctx, &days_ago(365)).await.unwrap();
    assert_eq!((purged.jobs, purged.outputs, purged.commands), (450, 450, 450));
    let (_, free) = store.space().await.unwrap();
    assert!(free > 25 * 1024 * 1024, "the outputs' pages are free: {free}");
    store.vacuum().await.unwrap();
    let (after, free) = store.space().await.unwrap();
    assert_eq!(free, 0);
    assert!(after < size / 10, "{after} of {size}");
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(remaining, 450);
}

/// `secure_delete`: what the purge removed is not left in the file's free space or its write-ahead log.
#[tokio::test]
async fn purged_text_is_gone_from_the_database_file() {
    let path = std::env::temp_dir().join(format!("remotely-purge-{}.db", Uuid::new_v4()));
    let store = Store::open(&path).await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let marker = format!("MARKER-{}", Uuid::new_v4().simple());
    let target = [session("web01")];
    for size in [40, 20_000] {
        // The script's first line is its summary, which the job keeps.
        let id = journal(&store, &ctx, &exec(&format!("set -e\necho {marker}")), &target, 200).await;
        sqlx::query("UPDATE job_targets SET output = ?, stderr = ? WHERE job_id = ?")
            .bind(marker.repeat(size / marker.len() + 1))
            .bind(&marker)
            .bind(id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
    }
    store.checkpoint().await.unwrap();
    let contains = |bytes: &[u8]| bytes.windows(marker.len()).any(|w| w == marker.as_bytes());
    assert!(contains(&std::fs::read(&path).unwrap()), "the test's text was written");

    let purged = store.purge_job_bodies(&ctx, &days_ago(90)).await.unwrap();
    assert_eq!((purged.jobs, purged.outputs, purged.commands), (2, 2, 2));
    store.checkpoint().await.unwrap();
    assert!(!contains(&std::fs::read(&path).unwrap()), "overwritten, not just freed");
    let wal = std::fs::read(format!("{}-wal", path.display())).unwrap_or_default();
    assert!(!contains(&wal), "the write-ahead log was emptied");
    store.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn rows_from_before_the_redaction_are_redacted_once() {
    let (store, ctx) = store_with_identity().await;
    let targets = [session("web01")];
    let id = journal(&store, &ctx, &exec("uptime"), &targets, 1).await;
    // As 0.4.2 left it: the script as typed, not checked yet.
    for (job, json) in [
        (
            id,
            serde_json::to_string(&exec("psql postgres://alice:s3cret@db01.example.com/app")).unwrap(),
        ),
        (
            journal(&store, &ctx, &line("ls"), &targets, 1).await,
            serde_json::to_string(&line("export TOKEN=abc123")).unwrap(),
        ),
        (
            journal(&store, &ctx, &exec("df -h"), &targets, 1).await,
            "{not json password=hunter2".to_owned(),
        ),
    ] {
        sqlx::query("UPDATE jobs SET command_json = ?, command_redacted = NULL WHERE id = ?")
            .bind(json)
            .bind(job.to_string())
            .execute(store.pool())
            .await
            .unwrap();
    }
    let unchecked = journal(&store, &ctx, &exec("hostname"), &targets, 1).await;
    sqlx::query("UPDATE jobs SET command_redacted = NULL WHERE id = ?")
        .bind(unchecked.to_string())
        .execute(store.pool())
        .await
        .unwrap();

    assert_eq!(store.redact_old_commands().await.unwrap(), 3);
    assert_eq!(store.redact_old_commands().await.unwrap(), 0, "once");
    let all: Vec<String> = sqlx::query_scalar("SELECT command_json FROM jobs")
        .fetch_all(store.pool())
        .await
        .unwrap();
    for json in &all {
        for secret in ["s3cret", "abc123", "hunter2"] {
            assert!(!json.contains(secret), "{json}");
        }
    }
    let (summary, command) = store.job_detail(&ctx, id).await.unwrap().unwrap();
    assert!(summary.command_redacted);
    assert_eq!(command, exec("psql postgres://alice:[redacted]@db01.example.com/app"));
    let (summary, _) = store.job_detail(&ctx, unchecked).await.unwrap().unwrap();
    assert!(!summary.command_redacted);
}

/// AP-03, BX-03: the Activity and Compare lists on a journal of thousands of jobs: the right page, the right counts,
/// and the page picked on an index.
#[tokio::test]
async fn the_activity_lists_read_a_page_on_an_index_however_long_the_journal() {
    let (store, ctx) = store_with_identity().await;
    let ws = ctx.workspace_id.to_string();
    let user = ctx.user_id.to_string();
    let mut tx = store.pool().begin().await.unwrap();
    let start = time::OffsetDateTime::now_utc() - time::Duration::days(30);
    for i in 0..6000 {
        let (command_type, json) = match i % 3 {
            0 => ("remoteExec", serde_json::to_string(&exec("uptime")).unwrap()),
            1 => ("terminalLine", serde_json::to_string(&line("ls")).unwrap()),
            _ => ("vmPower", serde_json::to_string(&power()).unwrap()),
        };
        let at = (start + time::Duration::seconds(i))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let id = format!("job-{i:05}");
        sqlx::query(
            "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, status, created_at,
                               command_type, command_redacted)
             VALUES (?, ?, ?, ?, 'execReadOnly', 'low', ?, 'succeeded', ?, ?, 0)",
        )
        .bind(&id)
        .bind(&ws)
        .bind(&user)
        .bind(format!("job {i}"))
        .bind(json)
        .bind(at)
        .bind(command_type)
        .execute(&mut *tx)
        .await
        .unwrap();
        for t in 0..3 {
            sqlx::query(
                "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status)
                 VALUES (?, ?, ?, 'session', ?, ?, ?)",
            )
            .bind(&id)
            .bind(&ws)
            .bind(&user)
            .bind(format!("s{t}"))
            .bind(format!("web0{t}"))
            .bind(if t == 2 && i % 2 == 0 { "failed" } else { "succeeded" })
            .execute(&mut *tx)
            .await
            .unwrap();
        }
    }
    tx.commit().await.unwrap();

    let started = std::time::Instant::now();
    let jobs = store.recent_jobs(&ctx, 50).await.unwrap();
    let took = started.elapsed();
    assert_eq!(jobs.len(), 50);
    assert_eq!(jobs[0].id, "job-05999");
    assert_eq!(jobs[49].id, "job-05950");
    assert!(jobs.windows(2).all(|w| w[0].created_at > w[1].created_at));
    let even = jobs.iter().find(|j| j.id == "job-05998").unwrap();
    assert_eq!(
        (even.targets_total, even.targets_succeeded, even.targets_failed),
        (3, 2, 1)
    );
    let odd = jobs.iter().find(|j| j.id == "job-05999").unwrap();
    assert_eq!(
        (odd.targets_total, odd.targets_succeeded, odd.targets_failed),
        (3, 3, 0)
    );
    assert!(took < std::time::Duration::from_secs(2), "{took:?}");

    let runs = store.recent_exec_jobs(&ctx, 20).await.unwrap();
    assert_eq!(runs.len(), 20);
    assert!(runs
        .iter()
        .all(|r| r.id.trim_start_matches("job-").parse::<u32>().unwrap() % 3 == 0));
    assert_eq!(runs[0].id, "job-05997");

    for (sql, index, binds) in [(PAGE_ANY_SQL, "jobs_by_time", 2), (PAGE_OF_TYPE_SQL, "jobs_by_type", 3)] {
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let mut query = sqlx::query(sqlx::AssertSqlSafe(explain)).bind(&ws);
        if binds == 3 {
            query = query.bind("remoteExec");
        }
        let plan: Vec<String> = query
            .bind(50_i64)
            .fetch_all(store.pool())
            .await
            .unwrap()
            .iter()
            .map(|r| r.get::<String, _>("detail"))
            .collect();
        let plan = plan.join(" | ");
        assert!(plan.contains(index), "{plan}");
        assert!(!plan.contains("TEMP B-TREE"), "the index gives the order: {plan}");
    }

    // NFR Reliability: the jobs still open at start are found on their own index.
    let plan: Vec<String> = sqlx::query(
        "EXPLAIN QUERY PLAN UPDATE jobs SET status = 'interrupted', finished_at = ?
         WHERE status IN ('queued', 'countdown', 'running')",
    )
    .bind("x")
    .fetch_all(store.pool())
    .await
    .unwrap()
    .iter()
    .map(|r| r.get::<String, _>("detail"))
    .collect();
    assert!(plan.join(" | ").contains("jobs_open"), "{plan:?}");
    assert_eq!(store.mark_interrupted_jobs().await.unwrap(), 0);
}

#[tokio::test]
async fn verify_and_export_read_the_audit_log_row_by_row() {
    let (store, ctx) = store_with_identity().await;
    for i in 0..2500 {
        store
            .append_audit(
                &ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action: &format!("change {i}"),
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: None,
                },
            )
            .await
            .unwrap();
    }
    let check = store.verify_audit_chain().await.unwrap();
    assert_eq!((check.ok, check.entries), (true, 2500));
    let mut seqs = Vec::new();
    let mut rows = store.audit_entries(&ctx);
    while let Some(entry) = rows.try_next().await.unwrap() {
        seqs.push(entry.seq);
    }
    drop(rows);
    assert_eq!(seqs.len(), 2500);
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "oldest first");

    // A changed row is still found, and the entries before it counted.
    sqlx::query("DROP TRIGGER audit_log_no_update")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE audit_log SET action = 'nothing' WHERE seq = 2000")
        .execute(store.pool())
        .await
        .unwrap();
    let check = store.verify_audit_chain().await.unwrap();
    assert_eq!(
        (check.ok, check.entries, check.first_bad_seq),
        (false, 1999, Some(2000))
    );
}
