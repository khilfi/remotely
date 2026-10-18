//! Known host keys (SS-05): one SHA-256 fingerprint per host, port and key type. Decisions about
//! trusting a key live in `crate::known_hosts`; this module only reads and writes.

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::known_hosts::KnownHost;

macro_rules! known_host_columns {
    () => {
        "id, host, port, key_type, fingerprint_sha256, first_seen_at, last_seen_at"
    };
}

fn row_to_known_host(row: &sqlx::sqlite::SqliteRow) -> Result<KnownHost> {
    let id: String = row.try_get("id")?;
    let port: i64 = row.try_get("port")?;
    Ok(KnownHost {
        id: parse_uuid(&id)?,
        host: row.try_get("host")?,
        port: u16::try_from(port).unwrap_or(22),
        key_type: row.try_get("key_type")?,
        fingerprint: row.try_get("fingerprint_sha256")?,
        first_seen_at: row.try_get("first_seen_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}

impl Store {
    /// Every known host key in the workspace, by host, port and key type.
    pub async fn list_known_hosts(&self, ctx: &Context) -> Result<Vec<KnownHost>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            known_host_columns!(),
            " FROM known_hosts WHERE workspace_id = ? ORDER BY host COLLATE NOCASE, port, key_type"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_known_host).collect()
    }

    /// The keys saved for one host and port (host compared without letter case).
    pub async fn known_host_keys(&self, ctx: &Context, host: &str, port: u16) -> Result<Vec<KnownHost>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            known_host_columns!(),
            " FROM known_hosts WHERE workspace_id = ? AND host = ? AND port = ? ORDER BY key_type"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(host)
        .bind(i64::from(port))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_known_host).collect()
    }

    pub async fn get_known_host(&self, ctx: &Context, id: Uuid) -> Result<Option<KnownHost>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            known_host_columns!(),
            " FROM known_hosts WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_known_host).transpose()
    }

    /// Saves a fingerprint for the host, port and key type, replacing the one saved before (with a new
    /// first-seen time). The caller has decided to trust it.
    pub(crate) async fn put_known_host(
        &self,
        ctx: &Context,
        host: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO known_hosts (id, workspace_id, user_id, host, port, key_type, fingerprint_sha256,
                                      first_seen_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, host, port, key_type) DO UPDATE SET
                 fingerprint_sha256 = excluded.fingerprint_sha256, user_id = excluded.user_id,
                 first_seen_at = excluded.first_seen_at, last_seen_at = excluded.last_seen_at",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(host)
        .bind(i64::from(port))
        .bind(key_type)
        .bind(fingerprint)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A trusted key was seen again.
    pub(crate) async fn touch_known_host(&self, ctx: &Context, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE known_hosts SET last_seen_at = ? WHERE workspace_id = ? AND id = ?")
            .bind(now_rfc3339())
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// False when there was no such entry.
    pub(crate) async fn delete_known_host(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM known_hosts WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}
