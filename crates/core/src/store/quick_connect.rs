//! QL-02 quick-connect history rows: where unsaved quick connections went and how they logged in
//! (vault IDs, never a typed password). Checks live in `crate::terminal::quick`.

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::sessions::SessionAuth;
use crate::terminal::quick::QuickConnectEntry;
use crate::vault::SecretId;

/// History entries kept; the oldest go first.
pub const MAX_QUICK_CONNECT_HISTORY: i64 = 20;

fn optional_uuid(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Option<Uuid>> {
    let value: Option<String> = row.try_get(column)?;
    value.as_deref().map(parse_uuid).transpose()
}

fn row_to_entry(row: &sqlx::sqlite::SqliteRow) -> Result<QuickConnectEntry> {
    let id: String = row.try_get("id")?;
    let credential = optional_uuid(row, "credential_id")?.map(SecretId);
    let passphrase = optional_uuid(row, "key_passphrase_id")?.map(SecretId);
    let method: String = row.try_get("auth_method")?;
    let auth = match method.as_str() {
        "key" => SessionAuth::Key {
            key_id: credential,
            passphrase_id: passphrase,
        },
        "agent" => SessionAuth::Agent,
        _ => SessionAuth::Password {
            password_id: credential,
        },
    };
    let port: i64 = row.try_get("port")?;
    let username: String = row.try_get("username")?;
    Ok(QuickConnectEntry {
        id: parse_uuid(&id)?,
        host: row.try_get("host")?,
        port: u16::try_from(port).unwrap_or(22),
        username: Some(username).filter(|u| !u.is_empty()),
        auth,
        used_at: row.try_get("used_at")?,
    })
}

impl Store {
    /// Adds a quick connection to the history, or moves it to the top; keeps the newest
    /// [`MAX_QUICK_CONNECT_HISTORY`]. `host`, `port` and `username` must already be checked.
    pub(crate) async fn remember_quick_connect(
        &self,
        ctx: &Context,
        host: &str,
        port: u16,
        username: Option<&str>,
        auth: &SessionAuth,
    ) -> Result<()> {
        let ws = ctx.workspace_id.to_string();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO quick_connect_history (id, workspace_id, user_id, host, port, username, auth_method,
                                                credential_id, key_passphrase_id, used_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, host, port, username) DO UPDATE SET
                 host = excluded.host, auth_method = excluded.auth_method, credential_id = excluded.credential_id,
                 key_passphrase_id = excluded.key_passphrase_id, user_id = excluded.user_id,
                 used_at = excluded.used_at",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&ws)
        .bind(ctx.user_id.to_string())
        .bind(host)
        .bind(i64::from(port))
        .bind(username.unwrap_or(""))
        .bind(auth.method())
        .bind(auth.credential_id().map(|s| s.0.to_string()))
        .bind(auth.passphrase_id().map(|s| s.0.to_string()))
        .bind(now_rfc3339())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM quick_connect_history WHERE workspace_id = ? AND id NOT IN
                 (SELECT id FROM quick_connect_history WHERE workspace_id = ? ORDER BY used_at DESC LIMIT ?)",
        )
        .bind(&ws)
        .bind(&ws)
        .bind(MAX_QUICK_CONNECT_HISTORY)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Newest first.
    pub async fn quick_connect_history(&self, ctx: &Context) -> Result<Vec<QuickConnectEntry>> {
        let rows = sqlx::query(
            "SELECT id, host, port, username, auth_method, credential_id, key_passphrase_id, used_at
             FROM quick_connect_history WHERE workspace_id = ? ORDER BY used_at DESC, rowid DESC",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_entry).collect()
    }

    /// `None` clears the whole history. Returns how many entries went.
    pub(crate) async fn forget_quick_connects(&self, ctx: &Context, id: Option<Uuid>) -> Result<u64> {
        let done = match id {
            Some(id) => {
                sqlx::query("DELETE FROM quick_connect_history WHERE workspace_id = ? AND id = ?")
                    .bind(ctx.workspace_id.to_string())
                    .bind(id.to_string())
                    .execute(&self.pool)
                    .await?
            }
            None => {
                sqlx::query("DELETE FROM quick_connect_history WHERE workspace_id = ?")
                    .bind(ctx.workspace_id.to_string())
                    .execute(&self.pool)
                    .await?
            }
        };
        Ok(done.rows_affected())
    }
}
