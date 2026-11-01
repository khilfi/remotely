//! FD-06 note rows. Checks and the audit log are `crate::notes`'s; this module only reads and writes.

use sqlx::Row;

use super::Store;
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::notes::{NoteKind, NoteRow};

fn row_to_note(row: &sqlx::sqlite::SqliteRow) -> Result<NoteRow> {
    let kind: String = row.try_get("target_kind")?;
    let handover: i64 = row.try_get("handover")?;
    Ok(NoteRow {
        kind: NoteKind::parse(&kind).unwrap_or(NoteKind::Session),
        key: row.try_get("target_key")?,
        body: row.try_get("body")?,
        handover: handover != 0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

impl Store {
    pub(crate) async fn note(&self, ctx: &Context, kind: NoteKind, key: &str) -> Result<Option<NoteRow>> {
        let row = sqlx::query(
            "SELECT target_kind, target_key, body, handover, created_at, updated_at FROM notes
             WHERE workspace_id = ? AND target_kind = ? AND target_key = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(kind.as_str())
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_note).transpose()
    }

    /// Every note in the workspace, newest first.
    pub(crate) async fn list_notes(&self, ctx: &Context) -> Result<Vec<NoteRow>> {
        let rows = sqlx::query(
            "SELECT target_kind, target_key, body, handover, created_at, updated_at FROM notes
             WHERE workspace_id = ? ORDER BY updated_at DESC",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_note).collect()
    }

    /// Writes the note (new, or over the one there). `created_at`: kept from the note there, else now.
    pub(crate) async fn put_note(
        &self,
        ctx: &Context,
        kind: NoteKind,
        key: &str,
        body: &str,
        handover: bool,
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO notes (workspace_id, user_id, target_kind, target_key, body, handover, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, target_kind, target_key) DO UPDATE SET
                 body = excluded.body, handover = excluded.handover, user_id = excluded.user_id,
                 updated_at = excluded.updated_at",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(kind.as_str())
        .bind(key)
        .bind(body)
        .bind(i64::from(handover))
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// False when there was none.
    pub(crate) async fn delete_note(&self, ctx: &Context, kind: NoteKind, key: &str) -> Result<bool> {
        let done = sqlx::query("DELETE FROM notes WHERE workspace_id = ? AND target_kind = ? AND target_key = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(kind.as_str())
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}
