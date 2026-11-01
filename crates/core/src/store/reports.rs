//! FD-05, BX-12, FD-08: the reads the exports need that no other feature makes.

use super::audit::row_to_entry;
use super::{AuditEntry, Store};
use crate::domain::Context;
use crate::error::Result;

impl Store {
    /// FD-08: the workspace's audit entries written from `from` up to `to` (RFC 3339 text, UTC as stored), oldest
    /// first. The handover pack's range is days, so it is read whole.
    pub async fn audit_between(&self, ctx: &Context, from: &str, to: &str) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query("SELECT * FROM audit_log WHERE workspace_id = ? AND ts >= ? AND ts < ? ORDER BY seq")
            .bind(ctx.workspace_id.to_string())
            .bind(from)
            .bind(to)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_entry).collect()
    }

    /// FD-08: the name the user goes by (the handover pack's "prepared by" until they type another).
    pub async fn user_display_name(&self, ctx: &Context) -> Result<Option<String>> {
        Ok(sqlx::query_scalar("SELECT display_name FROM users WHERE id = ?")
            .bind(ctx.user_id.to_string())
            .fetch_optional(&self.pool)
            .await?)
    }

    /// FD-08: the workspace's name, for a report's cover and its file name.
    pub async fn workspace_name(&self, ctx: &Context) -> Result<String> {
        Ok(self
            .workspace(ctx.user_id, ctx.workspace_id)
            .await?
            .map_or_else(|| "Workspace".to_owned(), |w| w.name))
    }
}
