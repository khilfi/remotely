//! VM-14, VM-27 schedule rows, their runs, the snapshots they took, and the command bus's standing approvals
//! (migration 0025). Checks, approvals and the audit log live in `crate::schedules` and `crate::command_bus`.

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::command_bus::{ApprovalRecord, Command, StandingGrant};
use crate::domain::{now_rfc3339, Context, Target};
use crate::error::{CoreError, Result};
use crate::policy::ActionKind;
use crate::schedules::{RunOutcome, ScheduleSpec, ScheduleState};

/// The runs kept per schedule; older ones are removed as new ones come.
pub const MAX_RUNS_KEPT: i64 = 200;

/// A schedule as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleRow {
    pub id: Uuid,
    pub name: String,
    pub spec: ScheduleSpec,
    pub content_hash: String,
    pub state: ScheduleState,
    pub state_reason: Option<String>,
    pub approval_id: Option<Uuid>,
    pub next_run_at: Option<String>,
    pub next_note: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// One run as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunRow {
    pub id: Uuid,
    pub schedule_id: Uuid,
    pub due_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub outcome: RunOutcome,
    pub detail: Option<String>,
    pub job_ids: Vec<Uuid>,
    pub approval_id: Option<Uuid>,
}

/// A snapshot a schedule took, still counted by its retention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TakenSnapshot {
    pub vm_key: String,
    pub snapshot_id: String,
    pub name: String,
    pub taken_at: String,
}

/// Why a taken snapshot stopped counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotEnd {
    Deleted,
    Gone,
    Renamed,
}

impl SnapshotEnd {
    fn as_str(self) -> &'static str {
        match self {
            SnapshotEnd::Deleted => "deleted",
            SnapshotEnd::Gone => "gone",
            SnapshotEnd::Renamed => "renamed",
        }
    }
}

fn row_to_schedule(row: &sqlx::sqlite::SqliteRow) -> Result<ScheduleRow> {
    let id: String = row.try_get("id")?;
    let spec: String = row.try_get("spec_json")?;
    let state: String = row.try_get("state")?;
    let approval: Option<String> = row.try_get("approval_id")?;
    Ok(ScheduleRow {
        id: parse_uuid(&id)?,
        name: row.try_get("name")?,
        spec: serde_json::from_str(&spec)?,
        content_hash: row.try_get("content_hash")?,
        state: ScheduleState::parse(&state)
            .ok_or_else(|| CoreError::InvalidInput(format!("unknown schedule state '{state}'")))?,
        state_reason: row.try_get("state_reason")?,
        approval_id: approval.as_deref().map(parse_uuid).transpose()?,
        next_run_at: row.try_get("next_run_at")?,
        next_note: row.try_get("next_note")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_run(row: &sqlx::sqlite::SqliteRow) -> Result<RunRow> {
    let id: String = row.try_get("id")?;
    let schedule: String = row.try_get("schedule_id")?;
    let outcome: String = row.try_get("outcome")?;
    let jobs: String = row.try_get("job_ids")?;
    let approval: Option<String> = row.try_get("approval_id")?;
    Ok(RunRow {
        id: parse_uuid(&id)?,
        schedule_id: parse_uuid(&schedule)?,
        due_at: row.try_get("due_at")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
        outcome: RunOutcome::parse(&outcome)
            .ok_or_else(|| CoreError::InvalidInput(format!("unknown run outcome '{outcome}'")))?,
        detail: row.try_get("detail")?,
        job_ids: serde_json::from_str(&jobs)?,
        approval_id: approval.as_deref().map(parse_uuid).transpose()?,
    })
}

macro_rules! schedule_columns {
    () => {
        "id, name, spec_json, content_hash, state, state_reason, approval_id, next_run_at, next_note, created_at, \
         updated_at"
    };
}

impl Store {
    pub(crate) async fn list_schedules(&self, ctx: &Context) -> Result<Vec<ScheduleRow>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            schedule_columns!(),
            " FROM schedules WHERE workspace_id = ? ORDER BY name COLLATE NOCASE, id"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_schedule).collect()
    }

    pub(crate) async fn schedule(&self, ctx: &Context, id: Uuid) -> Result<Option<ScheduleRow>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            schedule_columns!(),
            " FROM schedules WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_schedule).transpose()
    }

    /// A new schedule, waiting for its approval.
    pub(crate) async fn insert_schedule(
        &self,
        ctx: &Context,
        id: Uuid,
        name: &str,
        spec: &ScheduleSpec,
        reason: &str,
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO schedules (id, workspace_id, user_id, name, spec_json, content_hash, state, state_reason,
                                    created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 'needsApproval', ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(name)
        .bind(serde_json::to_string(spec)?)
        .bind(spec.content_hash())
        .bind(reason)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// An edit: the new name and content. New content waits for a new approval (the old one is dropped here).
    pub(crate) async fn update_schedule(
        &self,
        ctx: &Context,
        id: Uuid,
        name: &str,
        spec: &ScheduleSpec,
        needs_approval: Option<&str>,
    ) -> Result<bool> {
        let done = match needs_approval {
            Some(reason) => {
                sqlx::query(
                    "UPDATE schedules SET name = ?, spec_json = ?, content_hash = ?, state = 'needsApproval',
                         state_reason = ?, approval_id = NULL, next_run_at = NULL, next_note = NULL, updated_at = ?
                     WHERE workspace_id = ? AND id = ?",
                )
                .bind(name)
                .bind(serde_json::to_string(spec)?)
                .bind(spec.content_hash())
                .bind(reason)
                .bind(now_rfc3339())
                .bind(ctx.workspace_id.to_string())
                .bind(id.to_string())
                .execute(&self.pool)
                .await?
            }
            None => {
                sqlx::query("UPDATE schedules SET name = ?, updated_at = ? WHERE workspace_id = ? AND id = ?")
                    .bind(name)
                    .bind(now_rfc3339())
                    .bind(ctx.workspace_id.to_string())
                    .bind(id.to_string())
                    .execute(&self.pool)
                    .await?
            }
        };
        Ok(done.rows_affected() > 0)
    }

    /// Active (with its approval), paused, or waiting for approval, and why.
    pub(crate) async fn set_schedule_state(
        &self,
        ctx: &Context,
        id: Uuid,
        state: ScheduleState,
        reason: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE schedules SET state = ?, state_reason = ?, updated_at = ? WHERE workspace_id = ? AND id = ?",
        )
        .bind(state.as_str())
        .bind(reason)
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The schedule runs under this approval from now on, if its content is still the one approved.
    pub(crate) async fn set_schedule_approval(
        &self,
        ctx: &Context,
        id: Uuid,
        approval_id: Uuid,
        content_hash: &str,
    ) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE schedules SET approval_id = ?, state = 'active', state_reason = NULL, updated_at = ?
             WHERE workspace_id = ? AND id = ? AND content_hash = ?",
        )
        .bind(approval_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .bind(content_hash)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    pub(crate) async fn set_schedule_next(
        &self,
        ctx: &Context,
        id: Uuid,
        next_run_at: Option<&str>,
        note: Option<&str>,
    ) -> Result<()> {
        sqlx::query("UPDATE schedules SET next_run_at = ?, next_note = ? WHERE workspace_id = ? AND id = ?")
            .bind(next_run_at)
            .bind(note)
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Deletes the schedule, its runs and its record of the snapshots it took (the snapshots stay on the VMs).
    pub(crate) async fn delete_schedule(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM schedules WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    // ---- runs ----

    pub(crate) async fn insert_schedule_run(&self, ctx: &Context, run: &RunRow) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO schedule_runs (id, schedule_id, workspace_id, user_id, due_at, started_at, finished_at,
                                        outcome, detail, job_ids, approval_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(run.id.to_string())
        .bind(run.schedule_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&run.due_at)
        .bind(&run.started_at)
        .bind(&run.finished_at)
        .bind(run.outcome.as_str())
        .bind(&run.detail)
        .bind(serde_json::to_string(&run.job_ids)?)
        .bind(run.approval_id.map(|id| id.to_string()))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM schedule_runs WHERE schedule_id = ? AND id NOT IN
                (SELECT id FROM schedule_runs WHERE schedule_id = ? ORDER BY due_at DESC, rowid DESC LIMIT ?)",
        )
        .bind(run.schedule_id.to_string())
        .bind(run.schedule_id.to_string())
        .bind(MAX_RUNS_KEPT)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn finish_schedule_run(
        &self,
        id: Uuid,
        outcome: RunOutcome,
        detail: Option<&str>,
        job_ids: &[Uuid],
    ) -> Result<()> {
        sqlx::query("UPDATE schedule_runs SET outcome = ?, detail = ?, job_ids = ?, finished_at = ? WHERE id = ?")
            .bind(outcome.as_str())
            .bind(detail)
            .bind(serde_json::to_string(job_ids)?)
            .bind(now_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// A schedule's runs, newest first.
    pub(crate) async fn schedule_runs(&self, ctx: &Context, schedule_id: Uuid, limit: i64) -> Result<Vec<RunRow>> {
        let rows = sqlx::query(
            "SELECT id, schedule_id, due_at, started_at, finished_at, outcome, detail, job_ids, approval_id
             FROM schedule_runs WHERE workspace_id = ? AND schedule_id = ?
             ORDER BY due_at DESC, rowid DESC LIMIT ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(schedule_id.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_run).collect()
    }

    /// Runs the app was in the middle of when it stopped: they ended without an outcome.
    pub(crate) async fn mark_interrupted_schedule_runs(&self, ctx: &Context) -> Result<u64> {
        let done = sqlx::query(
            "UPDATE schedule_runs SET outcome = 'failed', finished_at = ?,
                 detail = COALESCE(detail || '; ', '') || 'Remotely stopped while it ran'
             WHERE workspace_id = ? AND outcome = 'running'",
        )
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    // ---- snapshots a schedule took ----

    pub(crate) async fn record_schedule_snapshot(
        &self,
        ctx: &Context,
        schedule_id: Uuid,
        run_id: Uuid,
        taken: &TakenSnapshot,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO schedule_snapshots (schedule_id, workspace_id, user_id, vm_key, snapshot_id, name,
                                                       run_id, taken_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(schedule_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&taken.vm_key)
        .bind(&taken.snapshot_id)
        .bind(&taken.name)
        .bind(run_id.to_string())
        .bind(&taken.taken_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The snapshots a schedule took on a VM that still count, newest first.
    pub(crate) async fn schedule_snapshots(
        &self,
        ctx: &Context,
        schedule_id: Uuid,
        vm_key: &str,
    ) -> Result<Vec<TakenSnapshot>> {
        let rows = sqlx::query(
            "SELECT vm_key, snapshot_id, name, taken_at FROM schedule_snapshots
             WHERE workspace_id = ? AND schedule_id = ? AND vm_key = ? AND ended_at IS NULL
             ORDER BY taken_at DESC, rowid DESC",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(schedule_id.to_string())
        .bind(vm_key)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(TakenSnapshot {
                    vm_key: r.try_get("vm_key")?,
                    snapshot_id: r.try_get("snapshot_id")?,
                    name: r.try_get("name")?,
                    taken_at: r.try_get("taken_at")?,
                })
            })
            .collect()
    }

    pub(crate) async fn end_schedule_snapshot(
        &self,
        ctx: &Context,
        schedule_id: Uuid,
        vm_key: &str,
        snapshot_id: &str,
        why: SnapshotEnd,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE schedule_snapshots SET ended_at = ?, ended_why = ?
             WHERE workspace_id = ? AND schedule_id = ? AND vm_key = ? AND snapshot_id = ? AND ended_at IS NULL",
        )
        .bind(now_rfc3339())
        .bind(why.as_str())
        .bind(ctx.workspace_id.to_string())
        .bind(schedule_id.to_string())
        .bind(vm_key)
        .bind(snapshot_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---- standing approvals (the command bus's) ----

    pub(crate) async fn insert_standing_approval(&self, ctx: &Context, grant: &StandingGrant) -> Result<()> {
        sqlx::query(
            "INSERT INTO standing_approvals (id, workspace_id, user_id, owner_id, content_hash, rules_hash, tier,
                                             commands_json, targets_json, record_json, granted_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(grant.id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(grant.owner_id.to_string())
        .bind(&grant.content_hash)
        .bind(&grant.rules_hash)
        .bind(grant.tier.as_str())
        .bind(serde_json::to_string(&(&grant.kinds, &grant.commands))?)
        .bind(serde_json::to_string(&(&grant.targets, &grant.skipped))?)
        .bind(serde_json::to_string(&grant.record)?)
        .bind(&grant.granted_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A standing approval that was not revoked.
    pub(crate) async fn standing_approval(&self, ctx: &Context, id: Uuid) -> Result<Option<StandingGrant>> {
        let row = sqlx::query(
            "SELECT id, owner_id, content_hash, rules_hash, tier, commands_json, targets_json, record_json, granted_at
             FROM standing_approvals WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: String = row.try_get("id")?;
        let owner: String = row.try_get("owner_id")?;
        let tier: String = row.try_get("tier")?;
        let commands: String = row.try_get("commands_json")?;
        let targets: String = row.try_get("targets_json")?;
        let record: String = row.try_get("record_json")?;
        let (kinds, commands): (Vec<ActionKind>, Vec<Command>) = serde_json::from_str(&commands)?;
        let (targets, skipped): (Vec<Target>, Vec<Target>) = serde_json::from_str(&targets)?;
        let record: ApprovalRecord = serde_json::from_str(&record)?;
        Ok(Some(StandingGrant {
            id: parse_uuid(&id)?,
            owner_id: parse_uuid(&owner)?,
            content_hash: row.try_get("content_hash")?,
            rules_hash: row.try_get("rules_hash")?,
            tier: serde_json::from_value(serde_json::Value::String(tier))?,
            kinds,
            commands,
            targets,
            skipped,
            record,
            granted_at: row.try_get("granted_at")?,
        }))
    }

    /// No command runs under these approvals any more.
    pub(crate) async fn revoke_standing_approvals(&self, ctx: &Context, owner_id: Uuid, why: &str) -> Result<u64> {
        let done = sqlx::query(
            "UPDATE standing_approvals SET revoked_at = ?, revoked_why = ?
             WHERE workspace_id = ? AND owner_id = ? AND revoked_at IS NULL",
        )
        .bind(now_rfc3339())
        .bind(why)
        .bind(ctx.workspace_id.to_string())
        .bind(owner_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedules::{ScheduleAction, ScheduleTarget, Timing, WallTime};

    fn spec() -> ScheduleSpec {
        ScheduleSpec {
            action: ScheduleAction::Snapshot { keep: Some(2) },
            targets: vec![ScheduleTarget::Tag { tag: "lab".into() }],
            timing: Timing::Daily {
                at: WallTime::new(2, 0).unwrap(),
            },
        }
    }

    async fn store() -> (Store, Context) {
        let store = Store::open_in_memory().await.unwrap();
        let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
        (store, ctx)
    }

    #[tokio::test]
    async fn a_schedule_waits_for_approval_and_an_edit_drops_its_approval() {
        let (store, ctx) = store().await;
        let id = Uuid::new_v4();
        store
            .insert_schedule(&ctx, id, "nightly", &spec(), "new")
            .await
            .unwrap();
        let row = store.schedule(&ctx, id).await.unwrap().unwrap();
        assert_eq!(row.state, ScheduleState::NeedsApproval);
        assert_eq!(row.content_hash, spec().content_hash());

        let approval = Uuid::new_v4();
        assert!(!store
            .set_schedule_approval(&ctx, id, approval, "another content")
            .await
            .unwrap());
        assert!(store
            .set_schedule_approval(&ctx, id, approval, &spec().content_hash())
            .await
            .unwrap());
        let row = store.schedule(&ctx, id).await.unwrap().unwrap();
        assert_eq!((row.state, row.approval_id), (ScheduleState::Active, Some(approval)));

        // A new name alone keeps the approval; new content drops it.
        store
            .update_schedule(&ctx, id, "nightly 2", &spec(), None)
            .await
            .unwrap();
        assert_eq!(
            store.schedule(&ctx, id).await.unwrap().unwrap().approval_id,
            Some(approval)
        );
        let mut edited = spec();
        edited.action = ScheduleAction::Snapshot { keep: Some(3) };
        store
            .update_schedule(&ctx, id, "nightly 2", &edited, Some("edited"))
            .await
            .unwrap();
        let row = store.schedule(&ctx, id).await.unwrap().unwrap();
        assert_eq!(row.state, ScheduleState::NeedsApproval);
        assert_eq!(row.approval_id, None);
        assert_eq!(row.state_reason.as_deref(), Some("edited"));
    }

    #[tokio::test]
    async fn only_the_newest_runs_are_kept() {
        let (store, ctx) = store().await;
        let id = Uuid::new_v4();
        store.insert_schedule(&ctx, id, "hourly", &spec(), "new").await.unwrap();
        for n in 0..(MAX_RUNS_KEPT + 5) {
            let run = RunRow {
                id: Uuid::new_v4(),
                schedule_id: id,
                due_at: format!("2026-10-{:02}T{:02}:00:00Z", 1 + n / 24, n % 24),
                started_at: None,
                finished_at: None,
                outcome: RunOutcome::Succeeded,
                detail: None,
                job_ids: vec![],
                approval_id: None,
            };
            store.insert_schedule_run(&ctx, &run).await.unwrap();
        }
        let runs = store.schedule_runs(&ctx, id, 1000).await.unwrap();
        assert_eq!(runs.len() as i64, MAX_RUNS_KEPT);
        assert!(runs[0].due_at > runs[1].due_at, "newest first");
    }
}
