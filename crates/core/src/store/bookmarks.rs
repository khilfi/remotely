//! SS-14 (0.8.0 G3): file bookmark rows (migration 0034). The checks are `crate::bookmarks`'s; this module only reads
//! and writes, always within the workspace of `ctx`.

use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::bookmarks::Bookmark;
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};

fn bookmark(row: &sqlx::sqlite::SqliteRow) -> Result<Bookmark> {
    let id: String = row.try_get("id")?;
    let session: String = row.try_get("session_id")?;
    Ok(Bookmark {
        id: Uuid::parse_str(&id).map_err(|_| CoreError::InvalidInput("a bookmark's id can't be read".into()))?,
        session_id: Uuid::parse_str(&session)
            .map_err(|_| CoreError::InvalidInput("a bookmark's session can't be read".into()))?,
        name: row.try_get("name")?,
        path: row.try_get("path")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

impl Store {
    /// A session's bookmarks in their order, or (`None`) every one of the workspace, by session then order.
    pub(crate) async fn list_bookmarks(&self, ctx: &Context, session_id: Option<Uuid>) -> Result<Vec<Bookmark>> {
        let rows = match session_id {
            Some(session) => sqlx::query(
                "SELECT * FROM file_bookmarks WHERE workspace_id = ? AND session_id = ? ORDER BY position, created_at",
            )
            .bind(ctx.workspace_id.to_string())
            .bind(session.to_string())
            .fetch_all(&self.pool)
            .await?,
            None => {
                sqlx::query(
                    "SELECT * FROM file_bookmarks WHERE workspace_id = ? ORDER BY session_id, position, created_at",
                )
                .bind(ctx.workspace_id.to_string())
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(bookmark).collect()
    }

    pub(crate) async fn get_bookmark(&self, ctx: &Context, id: Uuid) -> Result<Option<Bookmark>> {
        let row = sqlx::query("SELECT * FROM file_bookmarks WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(bookmark).transpose()
    }

    pub(crate) async fn insert_bookmark(
        &self,
        ctx: &Context,
        session_id: Uuid,
        name: &str,
        path: &str,
        position: i64,
    ) -> Result<Bookmark> {
        let id = Uuid::new_v4();
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO file_bookmarks (id, workspace_id, user_id, session_id, name, path, position, created_at,
                                         updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(session_id.to_string())
        .bind(name)
        .bind(path)
        .bind(position)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(Bookmark {
            id,
            session_id,
            name: name.to_owned(),
            path: path.to_owned(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub(crate) async fn rename_bookmark(&self, ctx: &Context, id: Uuid, name: &str) -> Result<()> {
        sqlx::query("UPDATE file_bookmarks SET name = ?, updated_at = ? WHERE workspace_id = ? AND id = ?")
            .bind(name)
            .bind(now_rfc3339())
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn delete_bookmark(&self, ctx: &Context, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM file_bookmarks WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
