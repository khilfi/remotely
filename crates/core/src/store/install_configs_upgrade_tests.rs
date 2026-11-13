//! VM-28: a database at migration 0033 (0034 is G3's) with trash rows of every earlier kind in two workspaces, opened
//! by 0035, which rebuilds `trash` to take the kind `install_config`: every row and column is kept (review of #88).

use super::*;

const COLS: &str = "id, workspace_id, user_id, kind, item_id, name, place, detail, snapshot, deleted_at";

async fn rows(pool: &SqlitePool) -> Vec<Vec<String>> {
    use sqlx::Row;
    sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {COLS} FROM trash ORDER BY id")))
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|r| (0..10).map(|i| r.try_get::<String, _>(i).unwrap()).collect())
        .collect()
}

#[tokio::test]
async fn the_trash_keeps_every_row_through_0035_and_takes_install_configs() {
    let path = std::env::temp_dir().join(format!("remotely-0035-{}.db", Uuid::new_v4()));
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
    let other = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, account, display_name, created_at) VALUES (?, 'LAB\\alice', 'Alice', '2026-11-01T00:00:00Z')",
    )
    .bind(&user)
    .execute(&pool)
    .await
    .unwrap();
    for (w, name, is_home) in [(&home, "Default", 1), (&other, "Other", 0)] {
        sqlx::query(
            "INSERT INTO workspaces (id, user_id, name, created_at, is_home) VALUES (?, ?, ?, '2026-11-01T00:00:00Z', ?)",
        )
        .bind(w)
        .bind(&user)
        .bind(name)
        .bind(is_home)
        .execute(&pool)
        .await
        .unwrap();
    }
    for (i, kind) in ["session", "command", "size", "image", "template", "stack"]
        .iter()
        .enumerate()
    {
        let w = if i % 2 == 0 { &home } else { &other };
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO trash ({COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )))
        .bind(Uuid::new_v4().to_string())
        .bind(w)
        .bind(&user)
        .bind(*kind)
        .bind(format!("item-{i}"))
        .bind(format!("name {i} é ✓"))
        .bind("Templates › Sizes")
        .bind(if i == 3 { String::new() } else { format!("detail {i}") })
        .bind(format!("{{\"row\":{{\"n\":{i}}},\"text\":\"line\\nbreak\"}}"))
        .bind(format!("2026-11-0{}T09:00:00Z", i + 1))
        .execute(&pool)
        .await
        .unwrap();
    }
    let before = rows(&pool).await;
    assert_eq!(before.len(), 6);
    pool.close().await;

    let store = Store::open(&path).await.unwrap();
    assert_eq!(rows(store.pool()).await, before, "every trash row and column kept");
    let leftover: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name = 'trash_new'")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(leftover, 0);
    let indexes: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'trash' ORDER BY name")
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert!(indexes.iter().any(|i| i == "trash_by_workspace"), "{indexes:?}");
    let broken: Vec<String> = sqlx::query_scalar("SELECT \"table\" FROM pragma_foreign_key_check")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert!(broken.is_empty(), "{broken:?}");
    // The new kind is taken; an unknown one still isn't.
    let insert = |id: &'static str, kind: &'static str| {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO trash ({COLS}) VALUES (?, ?, ?, ?, 'i', 'n', 'p', '', '{{}}', 't')"
        )))
        .bind(id)
        .bind(home.clone())
        .bind(user.clone())
        .bind(kind)
    };
    assert!(insert("x", "bogus").execute(store.pool()).await.is_err());
    assert!(insert("y", "install_config").execute(store.pool()).await.is_ok());
    // The new tables carry workspace and user (rule 5), and launch templates their new column.
    for (table, column) in [("install_configs", "workspace_id"), ("install_configs", "user_id")] {
        let not_null: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT \"notnull\" FROM pragma_table_info('{table}') WHERE name = '{column}'"
        )))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(not_null, 1, "{table}.{column}");
    }
    let config_column: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('catalog_templates') WHERE name = 'install_config_id'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(config_column, 1);
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    assert_eq!(
        ctx.workspace_id.to_string(),
        home,
        "the home workspace is still the one opened"
    );
    drop(store);
    let _ = std::fs::remove_file(&path);
}
