//! Job journal: each job and each of its targets is written before work starts and updated as it
//! goes, so after a crash the app can show which targets finished (NFR Reliability).

use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use super::{serde_name, Store};
use crate::command_bus::{ApprovalRecord, Command};
use crate::domain::{now_rfc3339, Context, Target};
use crate::error::Result;
use crate::jobs::{JobStatus, TargetStatus};
use crate::policy::{ActionKind, Tier};

pub(crate) struct NewJob<'a> {
    pub id: Uuid,
    pub summary: &'a str,
    pub action: ActionKind,
    pub tier: Tier,
    pub command: &'a Command,
    pub approval: Option<&'a ApprovalRecord>,
    pub targets: &'a [Target],
    pub status: JobStatus,
}

pub struct TargetResult<'a> {
    pub status: TargetStatus,
    pub exit_code: Option<i64>,
    pub output: Option<&'a str>,
    pub error: Option<&'a str>,
    pub duration_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSummary {
    pub id: String,
    pub summary: String,
    pub action: String,
    pub tier: String,
    pub status: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub targets_total: i64,
    pub targets_succeeded: i64,
    pub targets_failed: i64,
}

impl Store {
    pub(crate) async fn insert_job(&self, ctx: &Context, job: NewJob<'_>) -> Result<()> {
        let ws = ctx.workspace_id.to_string();
        let user = ctx.user_id.to_string();
        let id = job.id.to_string();
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, approval_json, status,
                               created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&ws)
        .bind(&user)
        .bind(job.summary)
        .bind(serde_name(&job.action)?)
        .bind(job.tier.as_str())
        .bind(serde_json::to_string(job.command)?)
        .bind(job.approval.map(serde_json::to_string).transpose()?)
        .bind(job.status.as_str())
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        for t in job.targets {
            sqlx::query(
                "INSERT INTO job_targets (job_id, workspace_id, user_id, target_kind, target_key, target_name, status)
                 VALUES (?, ?, ?, ?, ?, ?, 'pending')",
            )
            .bind(&id)
            .bind(&ws)
            .bind(&user)
            .bind(t.target.kind())
            .bind(t.target.key())
            .bind(&t.name)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn set_job_status(&self, id: Uuid, status: JobStatus) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "UPDATE jobs SET status = ?,
                 started_at  = CASE WHEN ? = 'running' AND started_at IS NULL THEN ? ELSE started_at END,
                 finished_at = CASE WHEN ? THEN ? ELSE finished_at END
             WHERE id = ?",
        )
        .bind(status.as_str())
        .bind(status.as_str())
        .bind(&now)
        .bind(status.is_terminal())
        .bind(&now)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn set_target_running(&self, id: Uuid, target_key: &str) -> Result<()> {
        sqlx::query("UPDATE job_targets SET status = 'running', started_at = ? WHERE job_id = ? AND target_key = ?")
            .bind(now_rfc3339())
            .bind(id.to_string())
            .bind(target_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn set_target_result(&self, id: Uuid, target_key: &str, r: TargetResult<'_>) -> Result<()> {
        sqlx::query(
            "UPDATE job_targets SET status = ?, exit_code = ?, output = ?, error = ?, duration_ms = ?, finished_at = ?
             WHERE job_id = ? AND target_key = ?",
        )
        .bind(r.status.as_str())
        .bind(r.exit_code)
        .bind(r.output)
        .bind(r.error)
        .bind(r.duration_ms)
        .bind(now_rfc3339())
        .bind(id.to_string())
        .bind(target_key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Newest first, with per-status target counts.
    pub async fn recent_jobs(&self, ctx: &Context, limit: u32) -> Result<Vec<JobSummary>> {
        let rows = sqlx::query(
            "SELECT j.id, j.summary, j.action, j.tier, j.status, j.created_at, j.started_at, j.finished_at,
                    COUNT(t.target_key) AS total,
                    COALESCE(SUM(t.status = 'succeeded'), 0) AS succeeded,
                    COALESCE(SUM(t.status = 'failed'), 0) AS failed
             FROM jobs j LEFT JOIN job_targets t ON t.job_id = j.id
             WHERE j.workspace_id = ?
             GROUP BY j.id
             ORDER BY j.created_at DESC
             LIMIT ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(JobSummary {
                    id: r.try_get("id")?,
                    summary: r.try_get("summary")?,
                    action: r.try_get("action")?,
                    tier: r.try_get("tier")?,
                    status: r.try_get("status")?,
                    created_at: r.try_get("created_at")?,
                    started_at: r.try_get("started_at")?,
                    finished_at: r.try_get("finished_at")?,
                    targets_total: r.try_get("total")?,
                    targets_succeeded: r.try_get("succeeded")?,
                    targets_failed: r.try_get("failed")?,
                })
            })
            .collect()
    }

    /// At startup: jobs that were still open when the app last stopped are marked interrupted. Their
    /// target rows are left as they were, which is the record of what finished.
    pub async fn mark_interrupted_jobs(&self) -> Result<u64> {
        let done = sqlx::query(
            "UPDATE jobs SET status = 'interrupted', finished_at = ?
             WHERE status IN ('queued', 'countdown', 'running')",
        )
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }
}
