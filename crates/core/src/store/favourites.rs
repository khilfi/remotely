//! BX-08 favourite command rows. Checks live in `crate::snippets`.

use sqlx::{Row, SqliteConnection};
use uuid::Uuid;

use super::{parse_uuid, NewAuditEntry, Store};
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;

/// A favourite as stored, before the policy engine looks at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FavouriteRow {
    pub id: Uuid,
    /// `""` for none.
    pub folder: String,
    pub position: i64,
    pub name: String,
    pub command: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// What [`Store::insert_favourite`] and [`Store::update_favourite`] write. Already checked.
pub(crate) struct FavouriteFields<'a> {
    pub folder: &'a str,
    pub name: &'a str,
    pub command: &'a str,
    pub description: Option<&'a str>,
}

/// Adds a favourite at the end of its folder, on `conn` (a transaction's, when its audit entry goes with it).
async fn insert_favourite_on(
    conn: &mut SqliteConnection,
    ctx: &Context,
    id: Uuid,
    fields: &FavouriteFields<'_>,
) -> Result<()> {
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO command_favourites (id, workspace_id, user_id, folder, position, name, command, description,
                                         created_at, updated_at)
         VALUES (?, ?, ?, ?,
                 (SELECT COALESCE(MAX(position), -1) + 1 FROM command_favourites
                  WHERE workspace_id = ? AND folder = ?),
                 ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(ctx.workspace_id.to_string())
    .bind(ctx.user_id.to_string())
    .bind(fields.folder)
    .bind(ctx.workspace_id.to_string())
    .bind(fields.folder)
    .bind(fields.name)
    .bind(fields.command)
    .bind(fields.description)
    .bind(&now)
    .bind(&now)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn order_favourites_on(conn: &mut SqliteConnection, ctx: &Context, ids: &[Uuid]) -> Result<()> {
    for (position, id) in ids.iter().enumerate() {
        sqlx::query("UPDATE command_favourites SET position = ? WHERE workspace_id = ? AND id = ?")
            .bind(i64::try_from(position).unwrap_or(i64::MAX))
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

fn row_to_favourite(row: &sqlx::sqlite::SqliteRow) -> Result<FavouriteRow> {
    let id: String = row.try_get("id")?;
    Ok(FavouriteRow {
        id: parse_uuid(&id)?,
        folder: row.try_get("folder")?,
        position: row.try_get("position")?,
        name: row.try_get("name")?,
        command: row.try_get("command")?,
        description: row.try_get("description")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

impl Store {
    /// Folders by name (none first), then each folder's order.
    pub(crate) async fn list_favourites(&self, ctx: &Context) -> Result<Vec<FavouriteRow>> {
        let rows = sqlx::query(
            "SELECT id, folder, position, name, command, description, created_at, updated_at
             FROM command_favourites WHERE workspace_id = ?
             ORDER BY folder COLLATE NOCASE, position, rowid",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_favourite).collect()
    }

    pub(crate) async fn favourite(&self, ctx: &Context, id: Uuid) -> Result<Option<FavouriteRow>> {
        let row = sqlx::query(
            "SELECT id, folder, position, name, command, description, created_at, updated_at
             FROM command_favourites WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_favourite).transpose()
    }

    /// Adds it at the end of its folder.
    pub(crate) async fn insert_favourite(&self, ctx: &Context, id: Uuid, fields: &FavouriteFields<'_>) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        insert_favourite_on(&mut conn, ctx, id, fields).await
    }

    /// UX-20: [`Self::insert_favourite`] and its audit entry in one transaction, so neither lands without the other
    /// (the one-time move of command stars, and a library row's "Add to favourites").
    pub(crate) async fn insert_favourite_audited(
        &self,
        ctx: &Context,
        id: Uuid,
        fields: &FavouriteFields<'_>,
        entry: NewAuditEntry<'_>,
    ) -> Result<()> {
        let _chain = self.lock_audit_chain().await;
        let mut tx = self.pool.begin().await?;
        insert_favourite_on(&mut tx, ctx, id, fields).await?;
        Store::append_audit_on(&mut tx, ctx, entry).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A favourite moved to another folder goes to that folder's end.
    pub(crate) async fn update_favourite(&self, ctx: &Context, id: Uuid, fields: &FavouriteFields<'_>) -> Result<()> {
        sqlx::query(
            "UPDATE command_favourites SET
                 position = CASE WHEN folder = ? THEN position ELSE
                     (SELECT COALESCE(MAX(position), -1) + 1 FROM command_favourites
                      WHERE workspace_id = ? AND folder = ?) END,
                 folder = ?, name = ?, command = ?, description = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(fields.folder)
        .bind(ctx.workspace_id.to_string())
        .bind(fields.folder)
        .bind(fields.folder)
        .bind(fields.name)
        .bind(fields.command)
        .bind(fields.description)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Numbers the favourites 0, 1, 2… in the order given (one folder's, checked by the caller).
    pub(crate) async fn order_favourites(&self, ctx: &Context, ids: &[Uuid]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        order_favourites_on(&mut tx, ctx, ids).await?;
        tx.commit().await?;
        Ok(())
    }

    /// UX-20: [`Self::order_favourites`] and its audit entry in one transaction.
    pub(crate) async fn order_favourites_audited(
        &self,
        ctx: &Context,
        ids: &[Uuid],
        entry: NewAuditEntry<'_>,
    ) -> Result<()> {
        let _chain = self.lock_audit_chain().await;
        let mut tx = self.pool.begin().await?;
        order_favourites_on(&mut tx, ctx, ids).await?;
        Store::append_audit_on(&mut tx, ctx, entry).await?;
        tx.commit().await?;
        Ok(())
    }
}
