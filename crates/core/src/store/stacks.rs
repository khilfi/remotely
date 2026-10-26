//! VM-08 stack, instance and member rows (migration 0028). Checks and the audit log live in `crate::stacks`.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::stacks::{InstanceStep, StackInput, StackStep};

/// A stack as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StackRow {
    pub id: Uuid,
    pub input: StackInput,
    pub created_at: String,
    pub updated_at: String,
}

/// How a VM came to be in an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MemberOrigin {
    /// The instance's deploy made it: its teardown deletes it.
    Deploy,
    /// The user added it: a teardown keeps it unless picked on purpose.
    Hand,
}

impl MemberOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberOrigin::Deploy => "deploy",
            MemberOrigin::Hand => "hand",
        }
    }

    fn parse(text: &str) -> Self {
        if text == "deploy" {
            MemberOrigin::Deploy
        } else {
            MemberOrigin::Hand
        }
    }
}

/// One VM of an instance, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StackMemberRow {
    pub instance_id: Uuid,
    pub vm_key: String,
    pub vm_name: String,
    pub step: u32,
    pub origin: MemberOrigin,
    pub added_at: String,
}

/// An instance as stored, with its VMs in step order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstanceRow {
    pub id: Uuid,
    pub stack_id: Uuid,
    pub stack_name: String,
    pub name: String,
    pub steps: Vec<InstanceStep>,
    pub job_id: Option<Uuid>,
    pub created_at: String,
    pub members: Vec<StackMemberRow>,
}

/// A new instance's row.
pub(crate) struct NewInstance<'a> {
    pub id: Uuid,
    pub stack_id: Uuid,
    pub stack_name: &'a str,
    pub name: &'a str,
    pub steps: &'a [InstanceStep],
    pub job_id: Option<Uuid>,
}

fn row_to_stack(row: &sqlx::sqlite::SqliteRow) -> Result<StackRow> {
    let id: String = row.try_get("id")?;
    let steps: String = row.try_get("steps")?;
    Ok(StackRow {
        id: parse_uuid(&id)?,
        input: StackInput {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            steps: serde_json::from_str::<Vec<StackStep>>(&steps)?,
        },
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_member(row: &sqlx::sqlite::SqliteRow) -> Result<StackMemberRow> {
    let instance: String = row.try_get("instance_id")?;
    let step: i64 = row.try_get("step")?;
    let origin: String = row.try_get("origin")?;
    Ok(StackMemberRow {
        instance_id: parse_uuid(&instance)?,
        vm_key: row.try_get("vm_key")?,
        vm_name: row.try_get("vm_name")?,
        step: u32::try_from(step).unwrap_or(0),
        origin: MemberOrigin::parse(&origin),
        added_at: row.try_get("added_at")?,
    })
}

macro_rules! member_columns {
    () => {
        "instance_id, vm_key, vm_name, step, origin, added_at"
    };
}

impl Store {
    // ---- Stacks ------------------------------------------------------------------------------------------------

    pub(crate) async fn list_stacks(&self, ctx: &Context) -> Result<Vec<StackRow>> {
        let rows = sqlx::query(
            "SELECT id, name, description, steps, created_at, updated_at FROM stacks
             WHERE workspace_id = ? ORDER BY name COLLATE NOCASE, rowid",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_stack).collect()
    }

    pub(crate) async fn stack(&self, ctx: &Context, id: Uuid) -> Result<Option<StackRow>> {
        let row = sqlx::query(
            "SELECT id, name, description, steps, created_at, updated_at FROM stacks
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_stack).transpose()
    }

    /// Saves a new stack (checked by the caller).
    pub(crate) async fn insert_stack(&self, ctx: &Context, id: Uuid, input: &StackInput) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO stacks (id, workspace_id, user_id, name, description, steps, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&input.name)
        .bind(&input.description)
        .bind(serde_json::to_string(&input.steps)?)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Replaces a stack's content (checked by the caller). False when it is not there.
    pub(crate) async fn update_stack(&self, ctx: &Context, id: Uuid, input: &StackInput) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE stacks SET name = ?, description = ?, steps = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(&input.name)
        .bind(&input.description)
        .bind(serde_json::to_string(&input.steps)?)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Its instances stay: they are VMs on this PC. False when it was not there.
    pub(crate) async fn delete_stack(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM stacks WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    // ---- Instances ---------------------------------------------------------------------------------------------

    /// Every instance with its VMs, newest first.
    pub(crate) async fn list_stack_instances(&self, ctx: &Context) -> Result<Vec<InstanceRow>> {
        let workspace = ctx.workspace_id.to_string();
        let rows = sqlx::query(
            "SELECT id, stack_id, stack_name, name, steps, job_id, created_at FROM stack_instances
             WHERE workspace_id = ? ORDER BY created_at DESC, rowid DESC",
        )
        .bind(&workspace)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(row_to_instance(row)?);
        }
        let members = sqlx::query(concat!(
            "SELECT ",
            member_columns!(),
            " FROM stack_instance_vms WHERE workspace_id = ? ORDER BY step, added_at, rowid"
        ))
        .bind(&workspace)
        .fetch_all(&self.pool)
        .await?;
        let index: HashMap<Uuid, usize> = out.iter().enumerate().map(|(i, r)| (r.id, i)).collect();
        for row in &members {
            let member = row_to_member(row)?;
            if let Some(i) = index.get(&member.instance_id) {
                out[*i].members.push(member);
            }
        }
        Ok(out)
    }

    pub(crate) async fn stack_instance(&self, ctx: &Context, id: Uuid) -> Result<Option<InstanceRow>> {
        let row = sqlx::query(
            "SELECT id, stack_id, stack_name, name, steps, job_id, created_at FROM stack_instances
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut instance = row_to_instance(&row)?;
        let members = sqlx::query(concat!(
            "SELECT ",
            member_columns!(),
            " FROM stack_instance_vms WHERE workspace_id = ? AND instance_id = ?
             ORDER BY step, added_at, rowid"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_all(&self.pool)
        .await?;
        instance.members = members.iter().map(row_to_member).collect::<Result<_>>()?;
        Ok(Some(instance))
    }

    /// Makes the instance unless it is there (a retry's). Its name is made unique within the workspace with
    /// " (2)", " (3)"... when another instance took it since it was checked. Returns the name it has.
    pub(crate) async fn insert_stack_instance(&self, ctx: &Context, new: &NewInstance<'_>) -> Result<String> {
        if let Some(there) = self.stack_instance(ctx, new.id).await? {
            return Ok(there.name);
        }
        let taken: Vec<String> = sqlx::query("SELECT name FROM stack_instances WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|r| r.try_get::<String, _>("name").map(|n| n.to_lowercase()))
            .collect::<std::result::Result<_, _>>()?;
        let mut name = new.name.to_owned();
        let mut n = 2;
        while taken.contains(&name.to_lowercase()) {
            name = format!("{} ({n})", new.name);
            n += 1;
        }
        sqlx::query(
            "INSERT INTO stack_instances (id, workspace_id, user_id, stack_id, stack_name, name, steps, job_id,
                                          created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(new.id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(new.stack_id.to_string())
        .bind(new.stack_name)
        .bind(&name)
        .bind(serde_json::to_string(new.steps)?)
        .bind(new.job_id.map(|j| j.to_string()))
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(name)
    }

    /// Its VMs leave it (they stay on this PC). False when it was not there.
    pub(crate) async fn delete_stack_instance(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM stack_instances WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// The VM joins the instance at `step` (it leaves any other instance: a VM belongs to one at most).
    pub(crate) async fn add_stack_vm(
        &self,
        ctx: &Context,
        instance_id: Uuid,
        vm_key: &str,
        vm_name: &str,
        step: u32,
        origin: MemberOrigin,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO stack_instance_vms (instance_id, workspace_id, user_id, vm_key, vm_name, step, origin, added_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (workspace_id, vm_key) DO UPDATE SET
                instance_id = excluded.instance_id, user_id = excluded.user_id, vm_name = excluded.vm_name,
                step = excluded.step, origin = excluded.origin, added_at = excluded.added_at",
        )
        .bind(instance_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(vm_key)
        .bind(vm_name)
        .bind(i64::from(step))
        .bind(origin.as_str())
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The VM leaves its instance. False when it was in none.
    pub(crate) async fn remove_stack_vm(&self, ctx: &Context, vm_key: &str) -> Result<bool> {
        let done = sqlx::query("DELETE FROM stack_instance_vms WHERE workspace_id = ? AND vm_key = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(vm_key)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

fn row_to_instance(row: &sqlx::sqlite::SqliteRow) -> Result<InstanceRow> {
    let id: String = row.try_get("id")?;
    let stack: String = row.try_get("stack_id")?;
    let steps: String = row.try_get("steps")?;
    let job: Option<String> = row.try_get("job_id")?;
    Ok(InstanceRow {
        id: parse_uuid(&id)?,
        stack_id: parse_uuid(&stack)?,
        stack_name: row.try_get("stack_name")?,
        name: row.try_get("name")?,
        steps: serde_json::from_str(&steps)?,
        job_id: job.as_deref().map(parse_uuid).transpose()?,
        created_at: row.try_get("created_at")?,
        members: Vec::new(),
    })
}
