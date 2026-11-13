//! SS-14 (0.8.0 G3): a database at migration 0033 (0.7.x) opened by everything up to 0039. 0034 (file bookmarks) was
//! numbered first but merged after 0035 and 0039, so this checks the whole chain from a released database: every
//! trash row kept, the new table's workspace, user and session columns, and each rebuilt CHECK.

use super::*;

async fn scalar(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_0033_database_opens_with_bookmarks_install_configs_and_remote_paths() {
    let path = std::env::temp_dir().join(format!("remotely-0034-{}.db", Uuid::new_v4()));
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
    sqlx::migrate!("./migrations").run_to(33, &pool).await.unwrap();
    let user = Uuid::new_v4().to_string();
    let home = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, account, display_name, created_at) VALUES (?, 'LAB\\alice', 'Alice', '2026-11-01T00:00:00Z')",
    )
    .bind(&user)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO workspaces (id, user_id, name, created_at, is_home) VALUES (?, ?, 'Default', '2026-11-01T00:00:00Z', 1)",
    )
    .bind(&home)
    .bind(&user)
    .execute(&pool)
    .await
    .unwrap();
    // A deleted session in the trash, as 0.7.x kept it (no bookmarks in its rows).
    let trashed = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO trash (id, workspace_id, user_id, kind, item_id, name, place, detail, snapshot, deleted_at)
         VALUES (?, ?, ?, 'session', ?, 'web01', 'Sessions', '', '{\"row\":{},\"attached\":[]}', '2026-11-02T09:00:00Z')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&home)
    .bind(&user)
    .bind(&trashed)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let store = Store::open(&path).await.unwrap();
    let pool = store.pool();
    assert_eq!(
        scalar(pool, "SELECT COUNT(*) FROM trash").await,
        1,
        "the trash row is kept"
    );
    assert_eq!(
        scalar(pool, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'file_bookmarks'").await,
        1
    );
    for column in ["workspace_id", "user_id", "session_id", "path", "name"] {
        let not_null = scalar(
            pool,
            &format!("SELECT \"notnull\" FROM pragma_table_info('file_bookmarks') WHERE name = '{column}'"),
        )
        .await;
        assert_eq!(not_null, 1, "file_bookmarks.{column}");
    }
    // The session column is a foreign key that goes with the session.
    let cascade: String = sqlx::query_scalar(
        "SELECT on_delete FROM pragma_foreign_key_list('file_bookmarks') WHERE \"table\" = 'sessions'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(cascade, "CASCADE");
    // 0035's and 0039's rebuilds ran after 0034, and took what they were for.
    assert_eq!(
        scalar(
            pool,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'install_configs'"
        )
        .await,
        1
    );
    let job_targets: String =
        sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'job_targets'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(job_targets.contains("'remote_path'"), "{job_targets}");
    let trash: String = sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'trash'")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(trash.contains("'install_config'"), "{trash}");
    let broken: Vec<String> = sqlx::query_scalar("SELECT \"table\" FROM pragma_foreign_key_check")
        .fetch_all(pool)
        .await
        .unwrap();
    assert!(broken.is_empty(), "{broken:?}");
    // Every migration is recorded once, 0034 among them.
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .unwrap();
    assert!(
        applied.contains(&34) && applied.contains(&35) && applied.contains(&39),
        "{applied:?}"
    );
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    assert_eq!(ctx.workspace_id.to_string(), home);
    assert!(store.list_bookmarks(&ctx, None).await.unwrap().is_empty());
    drop(store);
    let _ = std::fs::remove_file(&path);
}
