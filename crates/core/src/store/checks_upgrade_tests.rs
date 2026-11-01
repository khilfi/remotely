//! MO-08: a database at migration 0029 with alert rules and alerts, upgraded by migration 0030, which rebuilds both
//! tables for the checks' metrics, scopes and target kind: every row survives as it was, and the new values are taken.

use super::*;
use sqlx::Row;

const AT: &str = "2026-10-30T09:00:00Z";

async fn exec(pool: &SqlitePool, sql: &'static str, binds: &[&str]) -> std::result::Result<(), sqlx::Error> {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(pool).await.map(drop)
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn alert_rows_survive_the_rebuild_and_checks_metrics_are_taken() {
    let path = std::env::temp_dir().join(format!("remotely-0030-{}.db", Uuid::new_v4()));
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
    sqlx::migrate!("./migrations").run_to(29, &pool).await.unwrap();
    let user = Uuid::new_v4().to_string();
    let ws = Uuid::new_v4().to_string();
    let rule = Uuid::new_v4().to_string();
    let alert = Uuid::new_v4().to_string();
    exec(
        &pool,
        "INSERT INTO users (id, account, display_name, created_at) VALUES (?, 'LAB\\alice', 'Alice', ?)",
        &[&user, AT],
    )
    .await
    .unwrap();
    exec(
        &pool,
        "INSERT INTO workspaces (id, user_id, name, created_at) VALUES (?, ?, 'Default', ?)",
        &[&ws, &user, AT],
    )
    .await
    .unwrap();
    exec(
        &pool,
        "INSERT INTO alert_rules (id, workspace_id, user_id, builtin, name, metric, scope_kind, scope_key, threshold,
                                  for_secs, severity, notify, enabled, created_at, updated_at)
         VALUES (?, ?, ?, NULL, 'web busy', 'cpu', 'tag', 'web', 90, 300, 'warning', 1, 1, ?, ?)",
        &[&rule, &ws, &user, AT, AT],
    )
    .await
    .unwrap();
    exec(
        &pool,
        "INSERT INTO alerts (id, workspace_id, user_id, rule_id, rule_name, metric, severity, target_kind, target_key,
                             target_name, threshold, for_secs, value, peak, message, fired_at, resolved_at, resolution,
                             acknowledged_at)
         VALUES (?, ?, ?, ?, 'web busy', 'cpu', 'warning', 'vm', 'C:\\VMs\\web\\web.vmx', 'web', 90, 300, 97, 99,
                 'CPU at 97%', ?, ?, 'cleared', ?)",
        &[&alert, &ws, &user, &rule, AT, AT, AT],
    )
    .await
    .unwrap();
    // Before 0030, a check's metric doesn't fit.
    let refused = exec(
        &pool,
        "INSERT INTO alert_rules (id, workspace_id, user_id, name, metric, scope_kind, for_secs, severity, notify,
                                  enabled, created_at, updated_at)
         VALUES (?, ?, ?, 'down', 'checkDown', 'allChecks', 0, 'critical', 1, 1, ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await;
    assert!(refused.is_err());

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let row =
        sqlx::query("SELECT name, metric, scope_kind, scope_key, threshold, for_secs FROM alert_rules WHERE id = ?")
            .bind(&rule)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.get::<String, _>("name"), "web busy");
    assert_eq!(row.get::<String, _>("scope_key"), "web");
    assert_eq!(row.get::<f64, _>("threshold"), 90.0);
    let row = sqlx::query("SELECT target_key, peak, resolution, acknowledged_at FROM alerts WHERE id = ?")
        .bind(&alert)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("target_key"), r"C:\VMs\web\web.vmx");
    assert_eq!(row.get::<f64, _>("peak"), 99.0);
    assert_eq!(row.get::<String, _>("resolution"), "cleared");
    // The checks' metrics, scopes and target kind fit now; other values still don't.
    for (metric, scope) in [
        ("checkDown", "allChecks"),
        ("checkSlow", "check"),
        ("certExpiring", "allChecks"),
    ] {
        sqlx::query(
            "INSERT INTO alert_rules (id, workspace_id, user_id, name, metric, scope_kind, for_secs, severity, notify,
                                      enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 0, 'critical', 1, 1, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&ws)
        .bind(&user)
        .bind(metric)
        .bind(metric)
        .bind(scope)
        .bind(AT)
        .bind(AT)
        .execute(&pool)
        .await
        .unwrap();
    }
    exec(
        &pool,
        "INSERT INTO alerts (id, workspace_id, user_id, rule_id, rule_name, metric, severity, target_kind, target_key,
                             target_name, for_secs, message, fired_at)
         VALUES (?, ?, ?, ?, 'down', 'checkDown', 'critical', 'check', ?, 'web', 0, 'Down', ?)",
        &[
            &Uuid::new_v4().to_string(),
            &ws,
            &user,
            &rule,
            &Uuid::new_v4().to_string(),
            AT,
        ],
    )
    .await
    .unwrap();
    assert!(exec(
        &pool,
        "INSERT INTO alert_rules (id, workspace_id, user_id, name, metric, scope_kind, for_secs, severity, notify,
                                  enabled, created_at, updated_at)
         VALUES (?, ?, ?, 'odd', 'temperature', 'allVms', 0, 'critical', 1, 1, ?, ?)",
        &[&Uuid::new_v4().to_string(), &ws, &user, AT, AT],
    )
    .await
    .is_err());
    // The alert list's indexes came back with the table.
    let indexes: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'alerts' ORDER BY name")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(indexes.contains(&"alerts_by_time".to_owned()));
    assert!(indexes.contains(&"alerts_open".to_owned()));
    pool.close().await;
    let _ = std::fs::remove_file(&path);
}
