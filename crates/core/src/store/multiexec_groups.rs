//! QL-19 saved MultiExec group rows (migration 0021). Checks and the audit log live in
//! `crate::multiexec_groups`.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;

/// A group as stored, with its members in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupRow {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<MemberRow>,
    pub created_at: String,
    pub updated_at: String,
}

/// A member: a saved session of the workspace, with its name now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberRow {
    pub session_id: Uuid,
    pub name: String,
}

impl Store {
    /// Every group of the workspace by name, each with its members in the user's order. A deleted
    /// session is no member any more (the database dropped it with the session).
    pub(crate) async fn list_multiexec_groups(&self, ctx: &Context) -> Result<Vec<GroupRow>> {
        let workspace = ctx.workspace_id.to_string();
        let rows = sqlx::query(
            "SELECT id, name, created_at, updated_at FROM multiexec_groups
             WHERE workspace_id = ? ORDER BY name COLLATE NOCASE, rowid",
        )
        .bind(&workspace)
        .fetch_all(&self.pool)
        .await?;
        let mut groups = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.try_get("id")?;
            groups.push(GroupRow {
                id: parse_uuid(&id)?,
                name: row.try_get("name")?,
                members: Vec::new(),
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            });
        }
        let members = sqlx::query(
            "SELECT m.group_id, m.session_id, s.name
             FROM multiexec_group_members m
             JOIN sessions s ON s.id = m.session_id AND s.workspace_id = m.workspace_id
             WHERE m.workspace_id = ?
             ORDER BY m.group_id, m.position, m.rowid",
        )
        .bind(&workspace)
        .fetch_all(&self.pool)
        .await?;
        let index: HashMap<Uuid, usize> = groups.iter().enumerate().map(|(i, g)| (g.id, i)).collect();
        for row in &members {
            let group: String = row.try_get("group_id")?;
            let session: String = row.try_get("session_id")?;
            if let Some(i) = index.get(&parse_uuid(&group)?) {
                groups[*i].members.push(MemberRow {
                    session_id: parse_uuid(&session)?,
                    name: row.try_get("name")?,
                });
            }
        }
        Ok(groups)
    }

    /// Saves a new group with these members (checked by the caller), in this order.
    pub(crate) async fn insert_multiexec_group(
        &self,
        ctx: &Context,
        id: Uuid,
        name: &str,
        members: &[Uuid],
    ) -> Result<()> {
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO multiexec_groups (id, workspace_id, user_id, name, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(name)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        insert_members(&mut tx, ctx, id, members).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Renames the group and replaces its members (checked by the caller). False when it is not there.
    pub(crate) async fn update_multiexec_group(
        &self,
        ctx: &Context,
        id: Uuid,
        name: &str,
        members: &[Uuid],
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query(
            "UPDATE multiexec_groups SET name = ?, user_id = ?, updated_at = ? WHERE workspace_id = ? AND id = ?",
        )
        .bind(name)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        sqlx::query("DELETE FROM multiexec_group_members WHERE workspace_id = ? AND group_id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        insert_members(&mut tx, ctx, id, members).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Its members go with it. False when it was not there.
    pub(crate) async fn delete_multiexec_group(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM multiexec_groups WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

async fn insert_members(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ctx: &Context,
    group: Uuid,
    members: &[Uuid],
) -> Result<()> {
    for (position, session) in members.iter().enumerate() {
        sqlx::query(
            "INSERT INTO multiexec_group_members (group_id, workspace_id, user_id, session_id, position)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(group.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(session.to_string())
        .bind(i64::try_from(position).unwrap_or(i64::MAX))
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
