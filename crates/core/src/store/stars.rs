//! QL-26 star and recent rows. The checks are `crate::stars`'s; this module only reads and writes.

use sqlx::Row;

use super::Store;
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::stars::{Recent, RecentKind, Star, StarKind, MAX_RECENTS};

/// UX-20 (0.9.0): the kind 0.8.x kept command stars under (`favourite:<id>`, `library:<id>`). Nothing makes one now;
/// [`crate::snippets::Snippets::move_command_stars`] moves those left into the favourites once and deletes them.
const COMMAND_STAR_KIND: &str = "command";

/// The kinds of recent items ([`RecentKind`]): sessions, VMs and pages, each kept to [`MAX_RECENTS`].
const RECENT_KINDS: usize = 3;

impl Store {
    /// UX-20: the workspace's command stars left from 0.8.x, by key, oldest first.
    pub(crate) async fn command_stars(&self, ctx: &Context) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT item_key FROM stars WHERE workspace_id = ? AND kind = ? ORDER BY created_at, rowid",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(COMMAND_STAR_KIND)
        .fetch_all(&self.pool)
        .await?)
    }

    /// UX-20: deletes every starred favourite's star (`favourite:<id>`) at once, after their folders were put in order.
    /// Returns how many went.
    pub(crate) async fn delete_favourite_command_stars(&self, ctx: &Context) -> Result<u64> {
        let done = sqlx::query("DELETE FROM stars WHERE workspace_id = ? AND kind = ? AND item_key LIKE 'favourite:%'")
            .bind(ctx.workspace_id.to_string())
            .bind(COMMAND_STAR_KIND)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    /// UX-20: deletes one command star, once it is in the favourites.
    pub(crate) async fn delete_command_star(&self, ctx: &Context, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM stars WHERE workspace_id = ? AND kind = ? AND item_key = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(COMMAND_STAR_KIND)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// UX-20 (tests): a command star as 0.8.x wrote one.
    #[cfg(test)]
    pub(crate) async fn insert_command_star(&self, ctx: &Context, key: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO stars (workspace_id, user_id, kind, item_key, created_at) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, kind, item_key) DO NOTHING",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(COMMAND_STAR_KIND)
        .bind(key)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The workspace's stars, oldest first.
    pub(crate) async fn list_stars(&self, ctx: &Context) -> Result<Vec<Star>> {
        let rows =
            sqlx::query("SELECT kind, item_key, created_at FROM stars WHERE workspace_id = ? ORDER BY created_at")
                .bind(ctx.workspace_id.to_string())
                .fetch_all(&self.pool)
                .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let kind: String = row.try_get("kind")?;
            let Some(kind) = StarKind::parse(&kind) else {
                continue;
            };
            out.push(Star {
                kind,
                key: row.try_get("item_key")?,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(out)
    }

    pub(crate) async fn count_stars(&self, ctx: &Context) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM stars WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_one(&self.pool)
            .await?)
    }

    /// Stars or unstars. True when that changed something.
    pub(crate) async fn set_star(&self, ctx: &Context, kind: StarKind, key: &str, starred: bool) -> Result<bool> {
        let done = if starred {
            sqlx::query(
                "INSERT INTO stars (workspace_id, user_id, kind, item_key, created_at) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(workspace_id, kind, item_key) DO NOTHING",
            )
            .bind(ctx.workspace_id.to_string())
            .bind(ctx.user_id.to_string())
            .bind(kind.as_str())
            .bind(key)
            .bind(now_rfc3339())
            .execute(&self.pool)
            .await?
        } else {
            sqlx::query("DELETE FROM stars WHERE workspace_id = ? AND kind = ? AND item_key = ?")
                .bind(ctx.workspace_id.to_string())
                .bind(kind.as_str())
                .bind(key)
                .execute(&self.pool)
                .await?
        };
        Ok(done.rows_affected() > 0)
    }

    /// The workspace's recently opened items, newest first: at most [`MAX_RECENTS`] of each kind.
    pub(crate) async fn list_recents(&self, ctx: &Context) -> Result<Vec<Recent>> {
        let rows = sqlx::query(
            "SELECT kind, item_key, opened_at FROM recent_items WHERE workspace_id = ?
             ORDER BY opened_at DESC, rowid DESC LIMIT ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(i64::try_from(MAX_RECENTS * RECENT_KINDS).unwrap_or(60))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let kind: String = row.try_get("kind")?;
            let Some(kind) = RecentKind::parse(&kind) else {
                continue;
            };
            out.push(Recent {
                kind,
                key: row.try_get("item_key")?,
                opened_at: row.try_get("opened_at")?,
            });
        }
        Ok(out)
    }

    /// Notes that `key` was opened now, and keeps the [`MAX_RECENTS`] newest of its kind (UX-22: pages and VMs never
    /// push sessions out of the session tree's and the New terminal dialog's Recent).
    pub(crate) async fn note_recent(&self, ctx: &Context, kind: RecentKind, key: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO recent_items (workspace_id, user_id, kind, item_key, opened_at) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, kind, item_key) DO UPDATE SET
                 opened_at = excluded.opened_at, user_id = excluded.user_id",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(kind.as_str())
        .bind(key)
        .bind(now_rfc3339())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM recent_items WHERE workspace_id = ? AND kind = ? AND rowid NOT IN
                 (SELECT rowid FROM recent_items WHERE workspace_id = ? AND kind = ?
                  ORDER BY opened_at DESC, rowid DESC LIMIT ?)",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(kind.as_str())
        .bind(ctx.workspace_id.to_string())
        .bind(kind.as_str())
        .bind(i64::try_from(MAX_RECENTS).unwrap_or(20))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
