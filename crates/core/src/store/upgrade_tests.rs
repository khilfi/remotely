//! QL-15: databases with data in them, upgraded or partly unreadable.

use super::*;

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
