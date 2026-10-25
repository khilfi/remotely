//! QL-15: databases with data in them, upgraded or partly unreadable.

use super::*;
use sqlx::Row;

/// Every column of a `job_targets` row as it was at migration 0009.
struct OldTarget {
    job: Uuid,
    kind: &'static str,
    key: &'static str,
    name: &'static str,
    status: &'static str,
    exit_code: Option<i64>,
    output: Option<&'static str>,
    error: Option<&'static str>,
    safety_snapshot: Option<&'static str>,
    truncated: bool,
}

/// Migrations 0010 and 0013 rebuild `job_targets` (SQLite can't change a CHECK constraint in place). A database at
/// 0009 with jobs in it keeps every row and column through both, the foreign key to `jobs` still cascades, and the
/// new target kinds go in.
#[tokio::test]
async fn an_upgrade_from_0009_keeps_the_job_journal_through_both_table_rebuilds() {
    let path = std::env::temp_dir().join(format!("remotely-upgrade-{}.db", Uuid::new_v4()));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run_to(9, &pool).await.unwrap();

    let (user, workspace) = (Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    let at = "2026-10-01T10:00:00Z";
    sqlx::query("INSERT INTO users (id, account, display_name, created_at) VALUES (?, ?, 'Alice', ?)")
        .bind(&user)
        .bind(r"LAB\alice")
        .bind(at)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workspaces (id, user_id, name, created_at) VALUES (?, ?, 'Default', ?)")
        .bind(&workspace)
        .bind(&user)
        .bind(at)
        .execute(&pool)
        .await
        .unwrap();
    let (bulk, update) = (Uuid::new_v4(), Uuid::new_v4());
    for (job, summary, action, status) in [
        (bulk, "Run uptime on 3 targets", "remoteExec", "partially_failed"),
        (update, "Install update 0.3.0", "appUpdate", "succeeded"),
    ] {
        sqlx::query(
            "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, approval_json, status,
                               retry_of, created_at, started_at, finished_at)
             VALUES (?, ?, ?, ?, ?, 'medium', ?, NULL, ?, NULL, ?, ?, ?)",
        )
        .bind(job.to_string())
        .bind(&workspace)
        .bind(&user)
        .bind(summary)
        .bind(action)
        .bind(format!(r#"{{"type":"{action}"}}"#))
        .bind(status)
        .bind(at)
        .bind(at)
        .bind(at)
        .execute(&pool)
        .await
        .unwrap();
    }
    // A mix of kinds and states, NULLs included.
    let rows = [
        OldTarget {
            job: bulk,
            kind: "session",
            key: "11111111-1111-4111-8111-111111111111",
            name: "web01",
            status: "succeeded",
            exit_code: Some(0),
            output: Some(" 10:00 up 3 days\n"),
            error: None,
            safety_snapshot: Some("before uptime"),
            truncated: false,
        },
        OldTarget {
            job: bulk,
            kind: "session",
            key: "22222222-2222-4222-8222-222222222222",
            name: "db01",
            status: "failed",
            exit_code: Some(1),
            output: None,
            error: Some("login failed"),
            safety_snapshot: None,
            truncated: true,
        },
        OldTarget {
            job: bulk,
            kind: "vm",
            key: r"C:\VMs\lab01\lab01.vmx",
            name: "lab01",
            status: "cancelled",
            exit_code: None,
            output: None,
            error: None,
            safety_snapshot: None,
            truncated: false,
        },
        OldTarget {
            job: update,
            kind: "app",
            key: "app",
            name: "Remotely",
            status: "succeeded",
            exit_code: None,
            output: None,
            error: None,
            safety_snapshot: None,
            truncated: false,
        },
    ];
    for row in &rows {
        sqlx::query(
            "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status,
                                      exit_code, output, error, started_at, finished_at, duration_ms, safety_snapshot,
                                      stderr, stdout_bytes, stderr_bytes, output_truncated, output_hash,
                                      output_hash_loose, error_code)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1234, ?, ?, ?, 7, ?, ?, ?, ?)",
        )
        .bind(row.job.to_string())
        .bind(&workspace)
        .bind(&user)
        .bind(row.kind)
        .bind(row.key)
        .bind(row.name)
        .bind(row.status)
        .bind(row.exit_code)
        .bind(row.output)
        .bind(row.error)
        .bind(at)
        .bind(at)
        .bind(row.safety_snapshot)
        .bind(row.error.map(|_| "Permission denied"))
        .bind(row.output.map(|o| o.len() as i64))
        .bind(row.truncated)
        .bind(row.output.map(|_| "hash-exact"))
        .bind(row.output.map(|_| "hash-loose"))
        .bind(row.error.map(|_| "auth_failed"))
        .execute(&pool)
        .await
        .unwrap();
    }
    pool.close().await;

    // The app's own open runs 0010 to the latest.
    let store = Store::open(&path).await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    assert_eq!(ctx.user_id.to_string(), user, "the same user, not a new one");
    let targets = store.job_targets(&ctx, bulk).await.unwrap();
    assert_eq!(targets.len(), 3);
    let web = targets.iter().find(|t| t.target_name == "web01").unwrap();
    assert_eq!(
        (web.target_kind.as_str(), web.status.as_str(), web.exit_code),
        ("session", "succeeded", Some(0))
    );
    assert_eq!(web.output.as_deref(), Some(" 10:00 up 3 days\n"));
    assert_eq!(web.safety_snapshot.as_deref(), Some("before uptime"));
    assert_eq!((web.stdout_bytes, web.stderr_bytes), (Some(17), Some(7)));
    assert_eq!(web.duration_ms, Some(1234));
    assert_eq!(web.started_at.as_deref(), Some(at));
    assert_eq!(web.finished_at.as_deref(), Some(at));
    assert_eq!(web.output_hash.as_deref(), Some("hash-exact"));
    assert_eq!(web.output_hash_loose.as_deref(), Some("hash-loose"));
    assert!(!web.output_truncated);
    let db = targets.iter().find(|t| t.target_name == "db01").unwrap();
    assert_eq!(db.error.as_deref(), Some("login failed"));
    assert_eq!(db.stderr.as_deref(), Some("Permission denied"));
    assert_eq!(db.error_code.as_deref(), Some("auth_failed"));
    assert!(db.output_truncated);
    assert_eq!(db.output, None);
    let lab = targets.iter().find(|t| t.target_kind == "vm").unwrap();
    assert_eq!(
        (lab.target_key.as_str(), lab.status.as_str()),
        (r"C:\VMs\lab01\lab01.vmx", "cancelled")
    );
    assert_eq!(store.job_targets(&ctx, update).await.unwrap().len(), 1);
    assert_eq!(store.recent_jobs(&ctx, 10).await.unwrap().len(), 2);

    let pool = store.pool();
    let problems = sqlx::query("PRAGMA foreign_key_check").fetch_all(pool).await.unwrap();
    assert!(problems.is_empty(), "{} foreign key problems", problems.len());
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(integrity, "ok");
    // The kinds 0010 and 0013 added go in; deleting a job still takes its targets with it.
    for (kind, key) in [("terminal", "t-1"), ("container", "c-1")] {
        sqlx::query(
            "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status)
             VALUES (?, ?, ?, ?, ?, 'new', 'pending')",
        )
        .bind(update.to_string())
        .bind(&workspace)
        .bind(&user)
        .bind(kind)
        .bind(key)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query("DELETE FROM jobs WHERE id = ?")
        .bind(update.to_string())
        .execute(pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_targets")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        left, 3,
        "the deleted job's targets went with it; the other job's stayed"
    );
    store.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

/// QL-15: an unreadable setting is moved to `<key>.unreadable`, replacing an older one there.
#[tokio::test]
async fn a_setting_set_aside_keeps_its_value_under_another_key() {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    store.put_setting(&ctx, "terminal.settings", &"old").await.unwrap();
    assert!(store.set_setting_aside(&ctx, "terminal.settings").await.unwrap());
    store.put_setting(&ctx, "terminal.settings", &"newer").await.unwrap();
    assert!(store.set_setting_aside(&ctx, "terminal.settings").await.unwrap());
    assert_eq!(
        store.get_setting::<String>(&ctx, "terminal.settings").await.unwrap(),
        None
    );
    assert_eq!(
        store
            .get_setting::<String>(&ctx, "terminal.settings.unreadable")
            .await
            .unwrap()
            .as_deref(),
        Some("newer")
    );
    assert!(
        !store.set_setting_aside(&ctx, "terminal.settings").await.unwrap(),
        "nothing left to move"
    );
}

/// QL-15: a database that fails to migrate is closed before the error comes back, so the shell can set the
/// file aside at once.
#[tokio::test]
async fn a_database_that_fails_to_migrate_is_closed_before_the_error() {
    let path = std::env::temp_dir().join(format!("remotely-broken-{}.db", Uuid::new_v4()));
    std::fs::write(
        &path,
        b"this is not a database, but long enough to look like a header to SQLite...",
    )
    .unwrap();
    let err = match Store::open(&path).await {
        Ok(_) => panic!("a file that is not a database does not open"),
        Err(err) => err,
    };
    assert!(err.is_database(), "{err}");
    let aside = path.with_extension("aside");
    std::fs::rename(&path, &aside).expect("nothing holds the file open any more");
    let _ = std::fs::remove_file(&aside);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

/// BX-02, AP-03, BX-03: a 0.4.2 database (migrations to 0015) with jobs in it gets each job's command type, the old
/// scripts and lines to redact, and the new indexes; then the journal lists, redacts and purges as a new one does.
#[tokio::test]
async fn an_upgrade_from_0_4_2_backfills_the_command_types_and_redacts_old_scripts() {
    let path = std::env::temp_dir().join(format!("remotely-upgrade-042-{}.db", Uuid::new_v4()));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run_to(15, &pool).await.unwrap();

    let (user, workspace) = (Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    let old = "2026-06-01T10:00:00Z";
    let new = "2026-10-20T10:00:00Z";
    sqlx::query("INSERT INTO users (id, account, display_name, created_at) VALUES (?, ?, 'Alice', ?)")
        .bind(&user)
        .bind(r"LAB\alice")
        .bind(old)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workspaces (id, user_id, name, created_at) VALUES (?, ?, 'Default', ?)")
        .bind(&workspace)
        .bind(&user)
        .bind(old)
        .execute(&pool)
        .await
        .unwrap();
    let run = serde_json::json!({
        "type": "remoteExec", "targets": [], "script": "mysql --password=hunter2 -e 'select 1'", "sudo": false,
        "sudoPasswordId": null, "trustNewHostKeys": false, "timeoutSecs": null
    });
    let typed = serde_json::json!({
        "type": "terminalLine", "targets": [], "line": "export TOKEN=abc123", "unreliable": false,
        "keys": "\r"
    });
    let power = serde_json::json!({ "type": "vmPower", "targets": [], "op": { "kind": "suspend" } });
    let power_json = power.to_string();
    let jobs = [
        (Uuid::new_v4(), "execOther", run.to_string(), old),
        (Uuid::new_v4(), "execOther", typed.to_string(), new),
        (Uuid::new_v4(), "vmSuspend", power.to_string(), old),
        (Uuid::new_v4(), "execOther", "{damaged".to_owned(), old),
    ];
    for (id, action, json, at) in &jobs {
        sqlx::query(
            "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, status, created_at)
             VALUES (?, ?, ?, 'a job', ?, 'medium', ?, 'succeeded', ?)",
        )
        .bind(id.to_string())
        .bind(&workspace)
        .bind(&user)
        .bind(action)
        .bind(json)
        .bind(at)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status,
                                      output, stderr, output_hash)
             VALUES (?, ?, ?, 'session', 's1', 'web01', 'succeeded', 'some output', 'some error', 'hash')",
        )
        .bind(id.to_string())
        .bind(&workspace)
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    }
    pool.close().await;

    let store = Store::open(&path).await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let rows = sqlx::query("SELECT id, command_type, command_redacted, bodies_removed_at FROM jobs ORDER BY rowid")
        .fetch_all(store.pool())
        .await
        .unwrap();
    let got: Vec<(String, Option<i64>, Option<String>)> = rows
        .iter()
        .map(|r| {
            (
                r.get("command_type"),
                r.get("command_redacted"),
                r.get("bodies_removed_at"),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("remoteExec".to_owned(), None, None),
            ("terminalLine".to_owned(), None, None),
            ("vmPower".to_owned(), Some(0), None),
            (String::new(), None, None),
        ],
        "types backfilled; scripts and lines still to check"
    );
    for index in ["jobs_by_type", "jobs_open", "jobs_to_purge", "jobs_unchecked"] {
        let found: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?")
            .bind(index)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(found, 1, "{index}");
    }

    assert_eq!(store.redact_old_commands().await.unwrap(), 2);
    let all: Vec<String> = sqlx::query_scalar("SELECT command_json FROM jobs")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert!(
        all.iter().all(|j| !j.contains("hunter2") && !j.contains("abc123")),
        "{all:?}"
    );
    assert_eq!(store.recent_jobs(&ctx, 10).await.unwrap().len(), 4);
    let runs = store.recent_exec_jobs(&ctx, 10).await.unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].id, jobs[0].0.to_string());
    assert!(runs[0].command_redacted);

    // Older than 90 days before the new job: the run, the VM job and the damaged one.
    let purged = store.purge_job_bodies(&ctx, "2026-08-01T00:00:00Z").await.unwrap();
    assert_eq!((purged.jobs, purged.outputs, purged.commands), (3, 3, 2));
    let damaged: String = sqlx::query_scalar("SELECT command_json FROM jobs WHERE id = ?")
        .bind(jobs[3].0.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        damaged, r#"{"type":""}"#,
        "JSON that can't be read keeps none of its text"
    );
    let power: String = sqlx::query_scalar("SELECT command_json FROM jobs WHERE id = ?")
        .bind(jobs[2].0.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(power, power_json, "a VM job's command has no script to remove");
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(integrity, "ok");
    store.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

/// VM-11 (R4): migration 0024 rebuilds `job_targets` once more for the target kind 'network'. A database at 0023
/// holding a deploy's 'new_vm' row (R2) keeps it, with every column 0023 has, and both kinds go in afterwards.
#[tokio::test]
async fn an_upgrade_from_0023_keeps_new_vm_targets_through_the_network_rebuild() {
    let path = std::env::temp_dir().join(format!("remotely-upgrade-{}.db", Uuid::new_v4()));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run_to(23, &pool).await.unwrap();

    let (user, workspace) = (Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    let at = "2026-10-20T10:00:00Z";
    sqlx::query("INSERT INTO users (id, account, display_name, created_at) VALUES (?, ?, 'Alice', ?)")
        .bind(&user)
        .bind(r"LAB\alice")
        .bind(at)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workspaces (id, user_id, name, created_at) VALUES (?, ?, 'Default', ?)")
        .bind(&workspace)
        .bind(&user)
        .bind(at)
        .execute(&pool)
        .await
        .unwrap();
    let deploy = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, approval_json, status,
                           retry_of, created_at, started_at, finished_at, command_type)
         VALUES (?, ?, ?, 'Deploy 2 VMs from web', 'deploy', 'medium', '{\"type\":\"deploy\"}', NULL,
                 'partially_failed', NULL, ?, ?, ?, 'deploy')",
    )
    .bind(deploy.to_string())
    .bind(&workspace)
    .bind(&user)
    .bind(at)
    .bind(at)
    .bind(at)
    .execute(&pool)
    .await
    .unwrap();
    // Every column 0023's table has, none left NULL on the first row.
    for (key, name, status, error) in [
        ("new-vm/vmware/web-1", "web-1", "succeeded", None),
        ("new-vm/virtualbox/web-2", "web-2", "failed", Some("ovftool failed")),
    ] {
        sqlx::query(
            "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status,
                                      exit_code, output, error, started_at, finished_at, duration_ms, safety_snapshot,
                                      stderr, stdout_bytes, stderr_bytes, output_truncated, output_hash,
                                      output_hash_loose, error_code, peer_ip, host_key)
             VALUES (?, ?, ?, 'new_vm', ?, ?, ?, 0, 'made', ?, ?, ?, 4321, 'before', 'warn', 4, 4, 1, 'h1', 'h2',
                     ?, '192.0.2.10', 'ssh-ed25519 SHA256:abc')",
        )
        .bind(deploy.to_string())
        .bind(&workspace)
        .bind(&user)
        .bind(key)
        .bind(name)
        .bind(status)
        .bind(error)
        .bind(at)
        .bind(at)
        .bind(error.map(|_| "deploy_failed"))
        .execute(&pool)
        .await
        .unwrap();
    }
    pool.close().await;

    let store = Store::open(&path).await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let targets = store.job_targets(&ctx, deploy).await.unwrap();
    assert_eq!(targets.len(), 2, "both new VMs kept");
    let web = targets.iter().find(|t| t.target_name == "web-1").unwrap();
    assert_eq!(
        (web.target_kind.as_str(), web.target_key.as_str(), web.status.as_str()),
        ("new_vm", "new-vm/vmware/web-1", "succeeded")
    );
    assert_eq!((web.exit_code, web.duration_ms), (Some(0), Some(4321)));
    assert_eq!(web.output.as_deref(), Some("made"));
    assert_eq!(web.started_at.as_deref(), Some(at));
    assert_eq!(web.finished_at.as_deref(), Some(at));
    assert_eq!(web.safety_snapshot.as_deref(), Some("before"));
    assert_eq!(web.stderr.as_deref(), Some("warn"));
    assert_eq!((web.stdout_bytes, web.stderr_bytes), (Some(4), Some(4)));
    assert!(web.output_truncated);
    assert_eq!(web.output_hash.as_deref(), Some("h1"));
    assert_eq!(web.output_hash_loose.as_deref(), Some("h2"));
    assert_eq!(web.peer_ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(web.host_key.as_deref(), Some("ssh-ed25519 SHA256:abc"));
    let failed = targets.iter().find(|t| t.target_name == "web-2").unwrap();
    assert_eq!(failed.error.as_deref(), Some("ovftool failed"));
    assert_eq!(failed.error_code.as_deref(), Some("deploy_failed"));

    let pool = store.pool();
    let problems = sqlx::query("PRAGMA foreign_key_check").fetch_all(pool).await.unwrap();
    assert!(problems.is_empty(), "{} foreign key problems", problems.len());
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(integrity, "ok");
    let index: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'job_targets_by_key'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(index, 1, "the Timeline's index");
    // Both kinds go in after 0024; deleting the job still takes its targets with it.
    for (kind, key) in [("new_vm", "new-vm/vmware/web-3"), ("network", "vmware:vmnet8")] {
        sqlx::query(
            "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status)
             VALUES (?, ?, ?, ?, ?, 'new', 'pending')",
        )
        .bind(deploy.to_string())
        .bind(&workspace)
        .bind(&user)
        .bind(kind)
        .bind(key)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query("DELETE FROM jobs WHERE id = ?")
        .bind(deploy.to_string())
        .execute(pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_targets")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(left, 0, "the deleted job's targets went with it");
    store.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
