//! FD-02: a database from before workspaces (migration 0028), with data in its tables, upgraded by migration 0029.

use super::*;
use crate::store::audit::{chain_start, AuditEntry, GENESIS_HASH};
use sqlx::Row;

const AT: &str = "2026-10-20T09:00:00Z";

async fn exec(pool: &SqlitePool, sql: &'static str, binds: &[&str]) {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(pool).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
}

/// Rows per table that carries `workspace_id`, and how many of them are in `workspace`.
async fn counts(pool: &SqlitePool, workspace: &str) -> Vec<(String, i64, i64)> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT m.name FROM sqlite_master m WHERE m.type = 'table'
           AND EXISTS (SELECT 1 FROM pragma_table_info(m.name) p WHERE p.name = 'workspace_id')
         ORDER BY m.name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out = Vec::new();
    for table in tables {
        // Table names come from sqlite_master, never from input.
        let all: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM \"{table}\"")))
            .fetch_one(pool)
            .await
            .unwrap();
        let here: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM \"{table}\" WHERE workspace_id = ?"
        )))
        .bind(workspace)
        .fetch_one(pool)
        .await
        .unwrap();
        out.push((table, all, here));
    }
    out
}

#[tokio::test]
async fn a_database_from_before_workspaces_becomes_the_default_workspace_with_everything_in_it() {
    let path = std::env::temp_dir().join(format!("remotely-0029-{}.db", Uuid::new_v4()));
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
    sqlx::migrate!("./migrations").run_to(28, &pool).await.unwrap();

    let user = Uuid::new_v4().to_string();
    let ws = Uuid::new_v4().to_string();
    exec(
        &pool,
        "INSERT INTO users (id, account, display_name, created_at) VALUES (?, 'LAB\\alice', 'Alice', ?)",
        &[&user, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO workspaces (id, user_id, name, created_at) VALUES (?, ?, 'Default', ?)",
        &[&ws, &user, AT],
    )
    .await;
    // Settings: one of this PC's and one of the engagement's.
    exec(
        &pool,
        "INSERT INTO settings (workspace_id, user_id, key, value_json, updated_at) VALUES (?, ?, ?, ?, ?)",
        &[&ws, &user, SCAN_FOLDERS_KEY, r#"["D:\\VMs"]"#, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO settings (workspace_id, user_id, key, value_json, updated_at) VALUES (?, ?, ?, ?, ?)",
        &[&ws, &user, crate::dashboard::LAYOUT_KEY, "null", AT],
    )
    .await;
    // The vault, a secret, a folder, a session with a forward and a container mark, a trusted key.
    exec(
        &pool,
        "INSERT INTO vault_meta (workspace_id, user_id, unlock_method, wrapped_key, created_at, updated_at)
         VALUES (?, ?, 'master_password', X'00', ?, ?)",
        &[&ws, &user, AT, AT],
    )
    .await;
    let secret = Uuid::new_v4().to_string();
    exec(
        &pool,
        "INSERT INTO vault_items (id, workspace_id, user_id, kind, label, nonce, ciphertext, created_at, updated_at)
         VALUES (?, ?, ?, 'password', 'web root', X'00', X'00', ?, ?)",
        &[&secret, &ws, &user, AT, AT],
    )
    .await;
    let folder = Uuid::new_v4().to_string();
    exec(
        &pool,
        "INSERT INTO session_folders (id, workspace_id, user_id, name, created_at, updated_at)
         VALUES (?, ?, ?, 'Lab', ?, ?)",
        &[&folder, &ws, &user, AT, AT],
    )
    .await;
    let session = Uuid::new_v4().to_string();
    exec(
        &pool,
        "INSERT INTO sessions (id, workspace_id, user_id, folder_id, name, host, port, username, auth_method,
                               credential_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'web01', 'web01.example.com', 22, 'alice', 'password', ?, ?, ?)",
        &[&session, &ws, &user, &folder, &secret, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO port_forwards (id, workspace_id, user_id, session_id, position, kind, bind_address, bind_port,
                                    dest_host, dest_port, created_at, updated_at)
         VALUES (?, ?, ?, ?, 0, 'local', '127.0.0.1', 8080, 'localhost', 80, ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, &session, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO container_hosts (workspace_id, user_id, session_id, engine, created_at, updated_at)
         VALUES (?, ?, ?, 'docker', ?, ?)",
        &[&ws, &user, &session, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO known_hosts (id, workspace_id, user_id, host, port, key_type, fingerprint_sha256, first_seen_at,
                                  last_seen_at)
         VALUES (?, ?, ?, 'web01.example.com', 22, 'ssh-ed25519', 'SHA256:abc', ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO quick_connect_history (id, workspace_id, user_id, host, port, username, auth_method, used_at)
         VALUES (?, ?, ?, '192.0.2.10', 22, 'bob', 'agent', ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO command_favourites (id, workspace_id, user_id, position, name, command, created_at, updated_at)
         VALUES (?, ?, ?, 0, 'disk', 'df -h', ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    // Two VMs, one of them tagged.
    let (vm1, vm2) = (Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    exec(
        &pool,
        "INSERT INTO vms (id, workspace_id, user_id, vmx_path, display_name, power_state, created_at, updated_at)
         VALUES (?, ?, ?, 'C:\\VMs\\web\\web.vmx', 'web', 'not_running', ?, ?)",
        &[&vm1, &ws, &user, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO vms (id, workspace_id, user_id, vmx_path, hypervisor, display_name, power_state, created_at,
                          updated_at)
         VALUES (?, ?, ?, '3f0c1a2b-1111-4222-8333-444455556666', 'virtualbox', 'db', 'running', ?, ?)",
        &[&vm2, &ws, &user, AT, AT],
    )
    .await;
    let tag = Uuid::new_v4().to_string();
    exec(
        &pool,
        "INSERT INTO tags (id, workspace_id, user_id, name, created_at) VALUES (?, ?, ?, 'lab-a', ?)",
        &[&tag, &ws, &user, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO target_tags (workspace_id, user_id, tag_id, target_kind, target_id, created_at)
         VALUES (?, ?, ?, 'vm', ?, ?)",
        &[&ws, &user, &tag, &vm1, AT],
    )
    .await;
    // A job with its target.
    let job = Uuid::new_v4().to_string();
    exec(
        &pool,
        "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, status, created_at,
                           command_type, command_redacted)
         VALUES (?, ?, ?, 'Start 1 VM', 'vmStart', 'low', '{\"type\":\"vmPower\"}', 'succeeded', ?, 'vmPower', 0)",
        &[&job, &ws, &user, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status)
         VALUES (?, ?, ?, 'vm', 'C:\\VMs\\web\\web.vmx', 'web', 'succeeded')",
        &[&job, &ws, &user],
    )
    .await;
    // The catalogue, a stack, a schedule, an alert rule and a MultiExec group.
    exec(
        &pool,
        "INSERT INTO catalog_sizes (id, workspace_id, user_id, name, sockets, cores_per_socket, memory_mb, disks,
                                    created_at, updated_at)
         VALUES (?, ?, ?, 'lab.tiny', 1, 1, 512, '[]', ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO stacks (id, workspace_id, user_id, name, steps, created_at, updated_at)
         VALUES (?, ?, ?, 'web tier', '[]', ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO schedules (id, workspace_id, user_id, name, spec_json, content_hash, state, created_at, updated_at)
         VALUES (?, ?, ?, 'nightly', '{}', 'h', 'paused', ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO alert_rules (id, workspace_id, user_id, name, metric, scope_kind, for_secs, severity, notify,
                                  enabled, created_at, updated_at)
         VALUES (?, ?, ?, 'busy', 'cpu', 'allVms', 300, 'warning', 1, 1, ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO multiexec_groups (id, workspace_id, user_id, name, created_at, updated_at)
         VALUES (?, ?, ?, 'web', ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    // Three audit entries in the old single chain.
    let mut prev = GENESIS_HASH.to_owned();
    let mut last = String::new();
    for (i, event) in ["approval_requested", "job_started", "job_finished"].iter().enumerate() {
        let mut entry = AuditEntry {
            seq: 0,
            id: Uuid::new_v4().to_string(),
            workspace_id: ws.clone(),
            user_id: user.clone(),
            ts: format!("2026-10-20T09:00:0{i}Z"),
            event: (*event).to_owned(),
            action: "Start 1 VM".into(),
            tier: Some("low".into()),
            job_id: Some(job.clone()),
            targets_json: "[]".into(),
            approval_json: None,
            result: None,
            detail: None,
            prev_hash: prev.clone(),
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        sqlx::query(
            "INSERT INTO audit_log (id, workspace_id, user_id, ts, event, action, tier, job_id, targets_json,
                                    approval_json, result, detail, prev_hash, hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&entry.id)
        .bind(&entry.workspace_id)
        .bind(&entry.user_id)
        .bind(&entry.ts)
        .bind(&entry.event)
        .bind(&entry.action)
        .bind(&entry.tier)
        .bind(&entry.job_id)
        .bind(&entry.targets_json)
        .bind(&entry.approval_json)
        .bind(&entry.result)
        .bind(&entry.detail)
        .bind(&entry.prev_hash)
        .bind(&entry.hash)
        .execute(&pool)
        .await
        .unwrap();
        prev = entry.hash.clone();
        last = entry.hash;
    }
    let before = counts(&pool, &ws).await;
    assert!(
        before.iter().filter(|(_, all, _)| *all > 0).count() >= 20,
        "data in many tables: {before:?}"
    );
    pool.close().await;

    // The app opens it: migration 0029 runs.
    let store = Store::open(&path).await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    assert_eq!(ctx.workspace_id.to_string(), ws, "the old workspace is the home one");
    let home = store.workspace(ctx.user_id, ctx.workspace_id).await.unwrap().unwrap();
    assert_eq!(
        (home.name.as_str(), home.is_home, home.archived_at.is_none()),
        ("Default", true, true)
    );

    // Every row is still there, in the same workspace (the new tables aside).
    let after = counts(store.pool(), &ws).await;
    for (table, all, here) in &before {
        let now = after.iter().find(|(t, _, _)| t == table).unwrap();
        assert_eq!((now.1, now.2), (*all, *here), "{table}");
        assert_eq!(all, here, "{table}: one workspace only");
    }
    let assigned = after.iter().find(|(t, _, _)| t == "vm_assignments").unwrap();
    assert_eq!(
        (assigned.1, assigned.2),
        (2, 2),
        "both VMs belong to the Default workspace"
    );
    assert!(
        store.vm_in_workspace(&ctx, r"c:\vms\WEB\web.vmx").await.unwrap(),
        "any letter case"
    );
    assert_eq!(store.list_vms(&ctx).await.unwrap().len(), 2);
    let tagged = store.find_vm(&ctx, r"C:\VMs\web\web.vmx").await.unwrap().unwrap();
    assert_eq!(tagged.tags, ["lab-a"]);

    // The old chain verifies, and the next entry links to the workspace's chain start from it.
    let check = store.verify_audit_chain(&ctx).await.unwrap();
    assert!(check.ok && check.entries == 3, "{check:?}");
    let next = store
        .append_audit(
            &ctx,
            NewAuditEntry {
                event: "setting_changed",
                action: "Set update checks",
                tier: None,
                job_id: None,
                targets: &[],
                approval: None,
                result: None,
                detail: Some("off"),
            },
        )
        .await
        .unwrap();
    assert_eq!(next.prev_hash, chain_start(&ws, Some(&last)));
    let check = store.verify_audit_chain(&ctx).await.unwrap();
    assert!(check.ok && check.entries == 4, "{check:?}");

    // The job journal reads as before, with no change ID.
    let jobs = store.recent_jobs(&ctx, 10).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].change_id, None);
    let column: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pragma_table_info('jobs') WHERE name = 'change_id'")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(column, 1);

    // A second workspace: this PC's settings are the same there, the engagement's are not; its chain is its own.
    let other = Context {
        workspace_id: new_workspace_id(),
        user_id: ctx.user_id,
    };
    store
        .insert_workspace(ctx.user_id, other.workspace_id, "Acme", "blue")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_setting::<Vec<String>>(&other, SCAN_FOLDERS_KEY)
            .await
            .unwrap(),
        Some(vec![r"D:\VMs".to_owned()])
    );
    assert_eq!(
        store
            .get_setting::<Option<crate::dashboard::DashboardLayout>>(&other, crate::dashboard::LAYOUT_KEY)
            .await
            .unwrap(),
        None
    );
    let first = store
        .append_audit(
            &other,
            NewAuditEntry {
                event: "workspace_created",
                action: "Created this workspace",
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
    assert_eq!(first.prev_hash, chain_start(&other.workspace_id.to_string(), None));
    assert!(store.verify_audit_chain(&other).await.unwrap().ok);
    let mine = store.verify_audit_chain(&ctx).await.unwrap();
    assert!(
        mine.ok && mine.entries == 4,
        "the other workspace's entry is not in it: {mine:?}"
    );
    let exported: Vec<AuditEntry> = store.audit_for_export(&ctx).await.unwrap();
    assert!(exported.iter().all(|e| e.workspace_id == ws));

    // The legacy rows stay bound: an edit to one shows in the old workspace's check.
    let row = sqlx::query("SELECT seq FROM audit_log WHERE workspace_id = ? ORDER BY seq LIMIT 1")
        .bind(&ws)
        .fetch_one(store.pool())
        .await
        .unwrap();
    let seq: i64 = row.try_get("seq").unwrap();
    assert!(seq >= 1);
    store.close().await;
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
