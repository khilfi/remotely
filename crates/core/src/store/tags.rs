//! Tags and saved filters for picking VMs (VM-02) and sessions (SS-01; BX-01 reuses them). These are
//! the app's own labels: they change no VM or host, so they skip the command bus.

use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};
use crate::inventory::VmFilter;
use crate::presentation::Change;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tag {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    /// VMs carrying the tag.
    pub vm_count: i64,
    /// Sessions carrying the tag (SS-01).
    pub session_count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedFilter {
    pub id: String,
    pub name: String,
    pub filter: VmFilter,
    pub updated_at: String,
}

pub(crate) const MAX_TAG_LEN: usize = 40;
const MAX_FILTER_NAME_LEN: usize = 60;

/// Trims a tag or filter name and checks it is 1 to `max` characters with no control characters.
pub(crate) fn clean_name(what: &str, name: &str, max: usize) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput(format!("a {what} name cannot be empty")));
    }
    if name.chars().count() > max {
        return Err(CoreError::InvalidInput(format!(
            "a {what} name can be at most {max} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(format!(
            "a {what} name cannot contain control characters"
        )));
    }
    Ok(name.to_owned())
}

impl Store {
    /// Every tag in the workspace, by name.
    pub async fn list_tags(&self, ctx: &Context) -> Result<Vec<Tag>> {
        let rows = sqlx::query(
            "SELECT t.id, t.name, t.color,
                    (SELECT COUNT(*) FROM target_tags tt JOIN vms v ON v.id = tt.target_id
                     WHERE tt.tag_id = t.id AND tt.target_kind = 'vm' AND v.missing = 0) AS vm_count,
                    (SELECT COUNT(*) FROM target_tags tt
                     WHERE tt.tag_id = t.id AND tt.target_kind = 'session') AS session_count
             FROM tags t WHERE t.workspace_id = ? ORDER BY t.name COLLATE NOCASE",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Tag {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    color: r.try_get("color")?,
                    vm_count: r.try_get("vm_count")?,
                    session_count: r.try_get("session_count")?,
                })
            })
            .collect()
    }

    /// Adds the tag (created on first use, matched without regard to letter case) to each VM.
    pub async fn tag_vms(&self, ctx: &Context, vmx_paths: &[String], name: &str) -> Result<()> {
        self.read_only().check(Change::VmLabels)?;
        let name = clean_name("tag", name, MAX_TAG_LEN)?;
        if vmx_paths.is_empty() {
            return Err(CoreError::NoTargets);
        }
        let ws = ctx.workspace_id.to_string();
        let user = ctx.user_id.to_string();
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO tags (id, workspace_id, user_id, name, created_at) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, name) DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&ws)
        .bind(&user)
        .bind(&name)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        let tag_id: String = sqlx::query_scalar("SELECT id FROM tags WHERE workspace_id = ? AND name = ?")
            .bind(&ws)
            .bind(&name)
            .fetch_one(&mut *tx)
            .await?;
        for path in vmx_paths {
            let vm_id: Option<String> =
                sqlx::query_scalar("SELECT id FROM vms WHERE workspace_id = ? AND vmx_path = ?")
                    .bind(&ws)
                    .bind(path)
                    .fetch_optional(&mut *tx)
                    .await?;
            let vm_id = vm_id.ok_or_else(|| CoreError::UnknownTarget(path.clone()))?;
            sqlx::query(
                "INSERT INTO target_tags (workspace_id, user_id, tag_id, target_kind, target_id, created_at)
                 VALUES (?, ?, ?, 'vm', ?, ?)
                 ON CONFLICT(tag_id, target_kind, target_id) DO NOTHING",
            )
            .bind(&ws)
            .bind(&user)
            .bind(&tag_id)
            .bind(&vm_id)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Removes the tag from each VM. A tag left on nothing is deleted.
    pub async fn untag_vms(&self, ctx: &Context, vmx_paths: &[String], name: &str) -> Result<()> {
        self.read_only().check(Change::VmLabels)?;
        let ws = ctx.workspace_id.to_string();
        let mut tx = self.pool.begin().await?;
        let tag_id: Option<String> = sqlx::query_scalar("SELECT id FROM tags WHERE workspace_id = ? AND name = ?")
            .bind(&ws)
            .bind(name.trim())
            .fetch_optional(&mut *tx)
            .await?;
        let Some(tag_id) = tag_id else {
            return Ok(());
        };
        for path in vmx_paths {
            sqlx::query(
                "DELETE FROM target_tags WHERE tag_id = ? AND target_kind = 'vm'
                 AND target_id IN (SELECT id FROM vms WHERE workspace_id = ? AND vmx_path = ?)",
            )
            .bind(&tag_id)
            .bind(&ws)
            .bind(path)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DELETE FROM tags WHERE id = ? AND NOT EXISTS (SELECT 1 FROM target_tags WHERE tag_id = ?)")
            .bind(&tag_id)
            .bind(&tag_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes a tag from every VM.
    pub async fn delete_tag(&self, ctx: &Context, name: &str) -> Result<()> {
        self.read_only().check(Change::VmLabels)?;
        sqlx::query("DELETE FROM tags WHERE workspace_id = ? AND name = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(name.trim())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_saved_filters(&self, ctx: &Context) -> Result<Vec<SavedFilter>> {
        let rows = sqlx::query(
            "SELECT id, name, filter_json, updated_at FROM saved_filters
             WHERE workspace_id = ? AND target_kind = 'vm' ORDER BY name COLLATE NOCASE",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let json: String = r.try_get("filter_json")?;
                Ok(SavedFilter {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    filter: serde_json::from_str(&json)?,
                    updated_at: r.try_get("updated_at")?,
                })
            })
            .collect()
    }

    /// Saves a VM filter under a name; saving under an existing name replaces it.
    pub async fn save_filter(&self, ctx: &Context, name: &str, filter: &VmFilter) -> Result<SavedFilter> {
        self.read_only().check(Change::VmLabels)?;
        let name = clean_name("filter", name, MAX_FILTER_NAME_LEN)?;
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO saved_filters (id, workspace_id, user_id, name, target_kind, filter_json, created_at,
                                        updated_at)
             VALUES (?, ?, ?, ?, 'vm', ?, ?, ?)
             ON CONFLICT(workspace_id, name) DO UPDATE SET
                 filter_json = excluded.filter_json, user_id = excluded.user_id, updated_at = excluded.updated_at",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&name)
        .bind(serde_json::to_string(filter)?)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        self.list_saved_filters(ctx)
            .await?
            .into_iter()
            .find(|f| f.name == name)
            .ok_or_else(|| CoreError::UnknownTarget(format!("saved filter {name}")))
    }

    pub async fn delete_saved_filter(&self, ctx: &Context, id: &str) -> Result<()> {
        self.read_only().check(Change::VmLabels)?;
        sqlx::query("DELETE FROM saved_filters WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
