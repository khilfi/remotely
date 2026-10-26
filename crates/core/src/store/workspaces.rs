//! FD-02 workspace rows (migration 0029) and which workspace each VM belongs to. Checks and the audit log live in
//! `crate::workspaces`.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::domain::{now_rfc3339, Context, UserId, WorkspaceId};
use crate::error::Result;

/// A workspace as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceRow {
    pub id: WorkspaceId,
    pub name: String,
    pub color: String,
    pub archived_at: Option<String>,
    pub is_home: bool,
    pub created_at: String,
    /// AP-05: entries up to this seq keep the single chain they were written in (store::audit).
    pub audit_legacy_until: i64,
}

/// The columns of a [`WorkspaceRow`].
macro_rules! workspace_columns {
    () => {
        "id, name, color, archived_at, is_home, created_at, audit_legacy_until"
    };
}

fn row_to_workspace(row: &sqlx::sqlite::SqliteRow) -> Result<WorkspaceRow> {
    let id: String = row.try_get("id")?;
    Ok(WorkspaceRow {
        id: WorkspaceId(parse_uuid(&id)?),
        name: row.try_get("name")?,
        color: row.try_get("color")?,
        archived_at: row.try_get("archived_at")?,
        is_home: row.try_get::<i64, _>("is_home")? == 1,
        created_at: row.try_get("created_at")?,
        audit_legacy_until: row.try_get("audit_legacy_until")?,
    })
}

impl Store {
    /// The user's workspace that holds this PC's settings ([`crate::settings::MACHINE_KEYS`]), once
    /// [`Store::ensure_identity`] has found it.
    pub fn home_workspace(&self) -> Option<WorkspaceId> {
        *crate::locks::read(&self.home)
    }

    /// Every workspace of the user: the home workspace first, then by name.
    pub(crate) async fn list_workspaces(&self, user: UserId) -> Result<Vec<WorkspaceRow>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            workspace_columns!(),
            " FROM workspaces WHERE user_id = ? ORDER BY is_home DESC, name COLLATE NOCASE, rowid"
        ))
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_workspace).collect()
    }

    /// One workspace of the user's, archived or not.
    pub(crate) async fn workspace(&self, user: UserId, id: WorkspaceId) -> Result<Option<WorkspaceRow>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            workspace_columns!(),
            " FROM workspaces WHERE user_id = ? AND id = ?"
        ))
        .bind(user.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_workspace).transpose()
    }

    /// Whether another workspace of the user has this name, letter case aside (archived ones too).
    pub(crate) async fn workspace_name_taken(
        &self,
        user: UserId,
        name: &str,
        except: Option<WorkspaceId>,
    ) -> Result<bool> {
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM workspaces WHERE user_id = ? AND name = ? COLLATE NOCASE AND id <> ? LIMIT 1",
        )
        .bind(user.to_string())
        .bind(name)
        .bind(except.map(|w| w.to_string()).unwrap_or_default())
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    pub(crate) async fn insert_workspace(&self, user: UserId, id: WorkspaceId, name: &str, color: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO workspaces (id, user_id, name, created_at, color, is_home, audit_legacy_until)
             VALUES (?, ?, ?, ?, ?, 0, 0)",
        )
        .bind(id.to_string())
        .bind(user.to_string())
        .bind(name)
        .bind(now_rfc3339())
        .bind(color)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn rename_workspace(&self, user: UserId, id: WorkspaceId, name: &str) -> Result<bool> {
        let done = sqlx::query("UPDATE workspaces SET name = ? WHERE user_id = ? AND id = ?")
            .bind(name)
            .bind(user.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    pub(crate) async fn set_workspace_color(&self, user: UserId, id: WorkspaceId, color: &str) -> Result<bool> {
        let done = sqlx::query("UPDATE workspaces SET color = ? WHERE user_id = ? AND id = ?")
            .bind(color)
            .bind(user.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Archives (`true`) or restores the workspace.
    pub(crate) async fn set_workspace_archived(&self, user: UserId, id: WorkspaceId, archived: bool) -> Result<bool> {
        let done = sqlx::query("UPDATE workspaces SET archived_at = ? WHERE user_id = ? AND id = ?")
            .bind(archived.then(now_rfc3339))
            .bind(user.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// The user's workspaces that aren't archived.
    pub(crate) async fn active_workspaces(&self, user: UserId) -> Result<Vec<Context>> {
        Ok(self
            .list_workspaces(user)
            .await?
            .into_iter()
            .filter(|w| w.archived_at.is_none())
            .map(|w| Context {
                workspace_id: w.id,
                user_id: user,
            })
            .collect())
    }

    /// FD-02: whether any workspace has a session with this id (ids are unique in the file, not per workspace).
    pub(crate) async fn session_id_taken(&self, id: Uuid) -> Result<bool> {
        let found: Option<String> = sqlx::query_scalar("SELECT id FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(found.is_some())
    }

    // ---- VM assignments ----------------------------------------------------------------------------------------

    /// Every VM key assigned to a workspace, lower case, with its workspace and that workspace's user.
    pub(crate) async fn vm_assignments(&self) -> Result<HashMap<String, (WorkspaceId, UserId)>> {
        let rows = sqlx::query("SELECT vm_key, workspace_id, user_id FROM vm_assignments")
            .fetch_all(&self.pool)
            .await?;
        let mut owners = HashMap::with_capacity(rows.len());
        for row in &rows {
            let key: String = row.try_get("vm_key")?;
            let workspace: String = row.try_get("workspace_id")?;
            let user: String = row.try_get("user_id")?;
            owners.insert(
                key.to_lowercase(),
                (WorkspaceId(parse_uuid(&workspace)?), UserId(parse_uuid(&user)?)),
            );
        }
        Ok(owners)
    }

    /// The workspace the VM belongs to, if any.
    pub async fn vm_owner(&self, vm_key: &str) -> Result<Option<WorkspaceId>> {
        let found: Option<String> = sqlx::query_scalar("SELECT workspace_id FROM vm_assignments WHERE vm_key = ?")
            .bind(vm_key)
            .fetch_optional(&self.pool)
            .await?;
        found.map(|w| parse_uuid(&w).map(WorkspaceId)).transpose()
    }

    /// Whether the VM belongs to the context's workspace.
    pub async fn vm_in_workspace(&self, ctx: &Context, vm_key: &str) -> Result<bool> {
        Ok(self.vm_owner(vm_key).await? == Some(ctx.workspace_id))
    }

    /// FD-02: refuses a VM the context's workspace doesn't have, for actions on it (the command bus) and reads of one
    /// VM by its key. One no workspace has must be added first (`VmUnassigned`); another workspace's is only "not in
    /// this workspace", which says nothing of that workspace.
    pub async fn require_vm_here(&self, ctx: &Context, vm_key: &str) -> Result<()> {
        let name = || crate::inventory::vm_named(vm_key);
        match self.vm_owner(vm_key).await? {
            Some(owner) if owner == ctx.workspace_id => Ok(()),
            Some(_) => Err(crate::error::CoreError::NotInWorkspace(name())),
            None => Err(crate::error::CoreError::VmUnassigned(name())),
        }
    }

    /// Assigns the VM to the context's workspace. False when a workspace has it already (this one included).
    pub(crate) async fn assign_vm(&self, ctx: &Context, vm_key: &str) -> Result<bool> {
        let done = sqlx::query(
            "INSERT INTO vm_assignments (vm_key, workspace_id, user_id, assigned_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(vm_key) DO NOTHING",
        )
        .bind(vm_key)
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Takes the VM out of the context's workspace: it is no longer assigned, and the workspace's row for it is
    /// marked missing (kept with its label and tags, which come back if the VM joins the workspace again). False when
    /// the workspace didn't have it.
    pub(crate) async fn release_vm(&self, ctx: &Context, vm_key: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query("DELETE FROM vm_assignments WHERE vm_key = ? AND workspace_id = ?")
            .bind(vm_key)
            .bind(ctx.workspace_id.to_string())
            .execute(&mut *tx)
            .await?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        sqlx::query("UPDATE vms SET missing = 1, updated_at = ? WHERE workspace_id = ? AND vmx_path = ?")
            .bind(now_rfc3339())
            .bind(ctx.workspace_id.to_string())
            .bind(vm_key)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }
}

/// The id a new workspace gets.
pub(crate) fn new_workspace_id() -> WorkspaceId {
    WorkspaceId(Uuid::new_v4())
}
