//! Job journal: each job and each of its targets is written before work starts and updated as it
//! goes, so after a crash the app can show which targets finished (NFR Reliability).
//!
//! It keeps no more customer data than it needs, for no longer than it needs (BX-02, SS-10): a script or
//! a typed line is stored with what looks like a secret replaced by `[redacted]`
//! ([`Command::for_journal`]), and the retention purge ([`Store::purge_job_bodies`], run by
//! [`crate::retention`]) empties old jobs' outputs and their script or line text, keeping the rest.

use serde::Serialize;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use super::{serde_name, Store};
use crate::command_bus::{ApprovalRecord, Command};
use crate::domain::{now_rfc3339, Context, Target, TargetRef};
use crate::error::Result;
use crate::export::redact_secrets;
use crate::jobs::{JobStatus, TargetStatus};
use crate::policy::{ActionKind, Tier};

/// How many jobs one purge or redaction transaction takes, so a long journal never holds the database
/// for long.
const BATCH: i64 = 200;

/// The free text in a command's JSON that the journal redacts and the purge removes, by command type.
const BODY_FIELDS: [(&str, &[&str]); 2] = [("remoteExec", &["script"]), ("terminalLine", &["line", "keys"])];

/// The same, as the purge's SQL: for each type, how many non-empty bodies a batch (a JSON list of job ids)
/// holds and their bytes, then emptying them. JSON that can't be read, of any type, keeps only its type, so
/// none of its text is left either.
const PURGE_BODIES: [(&str, &str); 3] = [
    (
        "SELECT COUNT(*) AS commands,
                COALESCE(SUM(LENGTH(CAST(IFNULL(json_extract(command_json, '$.script'), '') AS BLOB))), 0) AS bytes
         FROM jobs
         WHERE id IN (SELECT value FROM json_each(?)) AND command_type = 'remoteExec' AND json_valid(command_json)
           AND LENGTH(IFNULL(json_extract(command_json, '$.script'), '')) > 0",
        "UPDATE jobs SET command_json = json_set(command_json, '$.script', '')
         WHERE id IN (SELECT value FROM json_each(?)) AND command_type = 'remoteExec' AND json_valid(command_json)",
    ),
    (
        "SELECT COUNT(*) AS commands,
                COALESCE(SUM(LENGTH(CAST(IFNULL(json_extract(command_json, '$.line'), '') AS BLOB))
                           + LENGTH(CAST(IFNULL(json_extract(command_json, '$.keys'), '') AS BLOB))), 0) AS bytes
         FROM jobs
         WHERE id IN (SELECT value FROM json_each(?)) AND command_type = 'terminalLine' AND json_valid(command_json)
           AND LENGTH(IFNULL(json_extract(command_json, '$.line'), '') || IFNULL(json_extract(command_json, '$.keys'), ''))
               > 0",
        "UPDATE jobs SET command_json = json_set(command_json, '$.line', '', '$.keys', '')
         WHERE id IN (SELECT value FROM json_each(?)) AND command_type = 'terminalLine' AND json_valid(command_json)",
    ),
    (
        "SELECT COUNT(*) AS commands, COALESCE(SUM(LENGTH(CAST(command_json AS BLOB))), 0) AS bytes
         FROM jobs WHERE id IN (SELECT value FROM json_each(?)) AND NOT json_valid(command_json)",
        "UPDATE jobs SET command_json = json_object('type', command_type)
         WHERE id IN (SELECT value FROM json_each(?)) AND NOT json_valid(command_json)",
    ),
];

pub(crate) struct NewJob<'a> {
    pub id: Uuid,
    pub summary: &'a str,
    pub action: ActionKind,
    pub tier: Tier,
    pub command: &'a Command,
    pub approval: Option<&'a ApprovalRecord>,
    pub targets: &'a [Target],
    pub status: JobStatus,
    /// AP-03: when the countdown ends (RFC 3339), for a job that has one.
    pub countdown_until: Option<&'a str>,
    /// BX-04: the job whose failed targets this one retries.
    pub retry_of: Option<Uuid>,
}

#[derive(Default)]
pub struct TargetResult<'a> {
    /// `None` counts as failed.
    pub status: Option<TargetStatus>,
    pub exit_code: Option<i64>,
    /// stdout, capped (BX-02).
    pub output: Option<&'a str>,
    pub stderr: Option<&'a str>,
    pub stdout_bytes: Option<i64>,
    pub stderr_bytes: Option<i64>,
    pub truncated: bool,
    /// BX-03: hashes of the whole output, exact and with trailing whitespace ignored.
    pub output_hash: Option<&'a str>,
    pub output_hash_loose: Option<&'a str>,
    pub error: Option<&'a str>,
    /// BX-03: [`crate::CoreError::code`] of the error, so failures group by cause.
    pub error_code: Option<&'a str>,
    pub duration_ms: Option<i64>,
    /// VM-05: the safety snapshot taken on the target before the action, if one was.
    pub safety_snapshot: Option<&'a str>,
    /// The address this PC connected to, for a remote target reached directly.
    pub peer_ip: Option<&'a str>,
    /// The host key the target presented and the run accepted: `ssh-ed25519 SHA256:...`.
    pub host_key: Option<&'a str>,
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
    /// H9: targets that timed out or were cancelled while their command ran.
    pub targets_unknown: i64,
    /// AP-03: when the countdown ends (RFC 3339), while the job is in it.
    pub countdown_until: Option<String>,
    /// BX-04: the job whose failed targets this one retries.
    pub retry_of: Option<String>,
    /// BX-02: the retention purge removed the job's outputs and its script or line text.
    pub bodies_removed: bool,
    /// BX-04: the stored script or line had something that looked like a secret, now `[redacted]`, so it
    /// can't run again as it was.
    pub command_redacted: bool,
}

impl JobSummary {
    /// Queued, in its countdown or running.
    pub fn is_open(&self) -> bool {
        matches!(self.status.as_str(), "queued" | "countdown" | "running")
    }
}

/// BX-02: what a retention purge removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgedBodies {
    /// Jobs older than the limit that the purge went through (each is marked, so it is never read again).
    pub jobs: u64,
    /// Targets whose output or stderr was emptied.
    pub outputs: u64,
    /// Scripts and typed lines emptied.
    pub commands: u64,
    /// Bytes of text removed (UTF-8).
    pub bytes: u64,
}

impl PurgedBodies {
    /// Something was removed (not only jobs marked that had nothing).
    pub fn removed_any(&self) -> bool {
        self.outputs > 0 || self.commands > 0
    }

    fn add(&mut self, other: PurgedBodies) {
        self.jobs += other.jobs;
        self.outputs += other.outputs;
        self.commands += other.commands;
        self.bytes += other.bytes;
    }
}

/// One target of a job and how it went (job results in Activity).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobTargetRecord {
    pub target_kind: String,
    pub target_key: String,
    pub target_name: String,
    pub status: String,
    pub exit_code: Option<i64>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<i64>,
    /// VM-05: the safety snapshot taken before the action, if one was.
    pub safety_snapshot: Option<String>,
    /// BX-02: stderr, capped like `output` (stdout).
    pub stderr: Option<String>,
    /// BX-02: bytes each stream sent; more than is stored when `output_truncated`.
    pub stdout_bytes: Option<i64>,
    pub stderr_bytes: Option<i64>,
    pub output_truncated: bool,
    /// BX-03: hashes of the whole output, exact and with trailing whitespace ignored.
    #[serde(skip)]
    pub output_hash: Option<String>,
    #[serde(skip)]
    pub output_hash_loose: Option<String>,
    /// BX-03: why it failed, as a stable code.
    pub error_code: Option<String>,
    /// The address this PC connected to (a remote target reached directly).
    pub peer_ip: Option<String>,
    /// The host key the target presented and the run accepted.
    pub host_key: Option<String>,
}

impl JobTargetRecord {
    /// The target as commands name it (BX-04 retry).
    pub fn target_ref(&self) -> Option<TargetRef> {
        match self.target_kind.as_str() {
            "vm" => Some(TargetRef::Vm {
                vmx_path: self.target_key.clone(),
            }),
            "session" => Uuid::parse_str(&self.target_key)
                .ok()
                .map(|session_id| TargetRef::Session { session_id }),
            "app" => Some(TargetRef::App),
            // SS-10: a MultiExec line's terminal; it is gone once closed, and lines are never retried.
            "terminal" => Uuid::parse_str(&self.target_key)
                .ok()
                .map(|terminal_id| TargetRef::Terminal {
                    terminal_id,
                    session_id: None,
                }),
            "container" => TargetRef::container_from_key(&self.target_key),
            "network" => TargetRef::network_from_key(&self.target_key),
            // VM-21: a deploy's retry rebuilds its targets from the deploy, with their label.
            "new_vm" => TargetRef::new_vm_from_key(&self.target_key),
            // CV-03: a conversion's new image.
            "disk_image" => TargetRef::disk_image_from_key(&self.target_key),
            _ => None,
        }
    }
}

/// Every `job_targets` column but the two output texts.
macro_rules! target_columns {
    () => {
        "target_kind, target_key, target_name, status, exit_code, error, error_code, started_at, finished_at,
         duration_ms, safety_snapshot, stdout_bytes, stderr_bytes, output_truncated, output_hash, output_hash_loose,
         peer_ip, host_key"
    };
}

/// The columns of a [`JobSummary`] but its target counts, from `jobs j`.
macro_rules! job_columns {
    () => {
        "j.id, j.summary, j.action, j.tier, j.status, j.created_at, j.started_at, j.finished_at, j.countdown_until,
         j.retry_of, j.bodies_removed_at, j.command_redacted"
    };
}

fn row_to_target(r: &sqlx::sqlite::SqliteRow, with_output: bool) -> Result<JobTargetRecord> {
    let truncated: i64 = r.try_get("output_truncated")?;
    Ok(JobTargetRecord {
        target_kind: r.try_get("target_kind")?,
        target_key: r.try_get("target_key")?,
        target_name: r.try_get("target_name")?,
        status: r.try_get("status")?,
        exit_code: r.try_get("exit_code")?,
        output: if with_output { r.try_get("output")? } else { None },
        error: r.try_get("error")?,
        started_at: r.try_get("started_at")?,
        finished_at: r.try_get("finished_at")?,
        duration_ms: r.try_get("duration_ms")?,
        safety_snapshot: r.try_get("safety_snapshot")?,
        stderr: if with_output { r.try_get("stderr")? } else { None },
        stdout_bytes: r.try_get("stdout_bytes")?,
        stderr_bytes: r.try_get("stderr_bytes")?,
        output_truncated: truncated != 0,
        output_hash: r.try_get("output_hash")?,
        output_hash_loose: r.try_get("output_hash_loose")?,
        error_code: r.try_get("error_code")?,
        peer_ip: r.try_get("peer_ip")?,
        host_key: r.try_get("host_key")?,
    })
}

/// A [`JobSummary`] from [`job_columns`] and `total`, `succeeded` and `failed`.
fn row_to_summary(r: &sqlx::sqlite::SqliteRow) -> Result<JobSummary> {
    let removed: Option<String> = r.try_get("bodies_removed_at")?;
    let redacted: Option<i64> = r.try_get("command_redacted")?;
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
        targets_unknown: r.try_get("unknown")?,
        countdown_until: r.try_get("countdown_until")?,
        retry_of: r.try_get("retry_of")?,
        bodies_removed: removed.is_some(),
        command_redacted: redacted == Some(1),
    })
}

/// A journaled command's free text redacted in place (rows from before migration 0017). Returns whether
/// anything changed.
fn redact_body(command_type: &str, value: &mut Value) -> bool {
    let Some((_, fields)) = BODY_FIELDS.iter().find(|(ty, _)| *ty == command_type) else {
        return false;
    };
    let mut changed = false;
    for field in *fields {
        if let Some(Value::String(text)) = value.get_mut(*field) {
            let (clean, was) = redact_secrets(text);
            if was {
                *text = clean;
                changed = true;
            }
        }
    }
    changed
}

/// AP-03, BX-03: the ids of the page of jobs a list shows, newest first. Bound: the workspace, the command type for
/// `page_of_type`, then the limit.
macro_rules! page_any {
    () => {
        "SELECT id FROM jobs WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ?"
    };
}
macro_rules! page_of_type {
    () => {
        "SELECT id FROM jobs WHERE workspace_id = ? AND command_type = ? ORDER BY created_at DESC LIMIT ?"
    };
}

/// A page of jobs with their target counts: only the page's targets are read.
macro_rules! recent_jobs_sql {
    ($page:expr) => {
        concat!(
            "SELECT ",
            job_columns!(),
            ", COUNT(t.target_key) AS total,
                    COALESCE(SUM(t.status = 'succeeded'), 0) AS succeeded,
                    COALESCE(SUM(t.status = 'failed'), 0) AS failed,
                    COALESCE(SUM(t.status = 'unknown'), 0) AS unknown
             FROM (",
            $page,
            ") AS page
             JOIN jobs j ON j.id = page.id
             LEFT JOIN job_targets t ON t.job_id = j.id
             GROUP BY j.id
             ORDER BY j.created_at DESC"
        )
    };
}

/// AP-03, BX-03: the page queries, for tests that check their plans.
#[cfg(test)]
pub(crate) const PAGE_ANY_SQL: &str = page_any!();
#[cfg(test)]
pub(crate) const PAGE_OF_TYPE_SQL: &str = page_of_type!();

impl Store {
    pub(crate) async fn insert_job(&self, ctx: &Context, job: NewJob<'_>) -> Result<()> {
        let ws = ctx.workspace_id.to_string();
        let user = ctx.user_id.to_string();
        let id = job.id.to_string();
        let now = now_rfc3339();
        // BX-02, SS-10: a script or a line is never stored with a secret in it.
        let (kept, redacted) = job.command.for_journal();
        let (summary, _) = redact_secrets(job.summary);
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, approval_json, status,
                               created_at, countdown_until, retry_of, command_type, command_redacted)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&ws)
        .bind(&user)
        .bind(&summary)
        .bind(serde_name(&job.action)?)
        .bind(job.tier.as_str())
        .bind(serde_json::to_string(&kept)?)
        .bind(job.approval.map(serde_json::to_string).transpose()?)
        .bind(job.status.as_str())
        .bind(&now)
        .bind(job.countdown_until)
        .bind(job.retry_of.map(|r| r.to_string()))
        .bind(kept.type_name())
        .bind(redacted)
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
        let status = r.status.unwrap_or(TargetStatus::Failed);
        sqlx::query(
            "UPDATE job_targets SET status = ?, exit_code = ?, output = ?, stderr = ?, stdout_bytes = ?, stderr_bytes = ?,
                                    output_truncated = ?, output_hash = ?, output_hash_loose = ?, error = ?, error_code = ?,
                                    duration_ms = ?, safety_snapshot = ?, peer_ip = ?, host_key = ?, finished_at = ?
             WHERE job_id = ? AND target_key = ?",
        )
        .bind(status.as_str())
        .bind(r.exit_code)
        .bind(r.output)
        .bind(r.stderr)
        .bind(r.stdout_bytes)
        .bind(r.stderr_bytes)
        .bind(r.truncated)
        .bind(r.output_hash)
        .bind(r.output_hash_loose)
        .bind(r.error)
        .bind(r.error_code)
        .bind(r.duration_ms)
        .bind(r.safety_snapshot)
        .bind(r.peer_ip)
        .bind(r.host_key)
        .bind(now_rfc3339())
        .bind(id.to_string())
        .bind(target_key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Newest first, with per-status target counts.
    pub async fn recent_jobs(&self, ctx: &Context, limit: u32) -> Result<Vec<JobSummary>> {
        self.recent_jobs_of(ctx, None, limit).await
    }

    /// BX-02, BX-03: the newest remote command jobs (Compare runs), newest first. MultiExec lines are
    /// rated like them but typed into terminals, so they are left out.
    pub async fn recent_exec_jobs(&self, ctx: &Context, limit: u32) -> Result<Vec<JobSummary>> {
        self.recent_jobs_of(ctx, Some("remoteExec"), limit).await
    }

    /// When the job ended, how; `None` for a job that is not in the journal.
    pub async fn job_status(&self, id: Uuid) -> Result<Option<JobStatus>> {
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM jobs WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(status.as_deref().and_then(JobStatus::parse))
    }

    /// The newest jobs, of one command type or any. The page's jobs are picked first, on an index
    /// (`jobs_by_time`, or `jobs_by_type` for one type), and only their targets are counted, so a long journal
    /// costs no more to list than a short one (AP-03, BX-03).
    async fn recent_jobs_of(&self, ctx: &Context, command_type: Option<&str>, limit: u32) -> Result<Vec<JobSummary>> {
        let workspace = ctx.workspace_id.to_string();
        let query = match command_type {
            None => sqlx::query(recent_jobs_sql!(page_any!())).bind(workspace),
            Some(command_type) => sqlx::query(recent_jobs_sql!(page_of_type!()))
                .bind(workspace)
                .bind(command_type.to_owned()),
        };
        let rows = query.bind(i64::from(limit)).fetch_all(&self.pool).await?;
        rows.iter().map(row_to_summary).collect()
    }

    /// One job and the command it ran, or `None` for a job of another workspace.
    pub async fn job_detail(&self, ctx: &Context, id: Uuid) -> Result<Option<(JobSummary, Command)>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            job_columns!(),
            ", j.command_json,
                    (SELECT COUNT(*) FROM job_targets t WHERE t.job_id = j.id) AS total,
                    (SELECT COUNT(*) FROM job_targets t WHERE t.job_id = j.id AND t.status = 'succeeded') AS succeeded,
                    (SELECT COUNT(*) FROM job_targets t WHERE t.job_id = j.id AND t.status = 'failed') AS failed,
                    (SELECT COUNT(*) FROM job_targets t WHERE t.job_id = j.id AND t.status = 'unknown') AS unknown
             FROM jobs j WHERE j.workspace_id = ? AND j.id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else {
            return Ok(None);
        };
        let command: String = r.try_get("command_json")?;
        Ok(Some((row_to_summary(&r)?, serde_json::from_str(&command)?)))
    }

    /// A job's targets in the order they were journaled, with their output. Empty for a job of another
    /// workspace.
    pub async fn job_targets(&self, ctx: &Context, job_id: Uuid) -> Result<Vec<JobTargetRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            target_columns!(),
            ", output, stderr FROM job_targets WHERE job_id = ? AND workspace_id = ? ORDER BY rowid"
        ))
        .bind(job_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| row_to_target(r, true)).collect()
    }

    /// BX-03: a job's targets without their output, for a big bulk run's live view.
    pub async fn job_targets_brief(&self, ctx: &Context, job_id: Uuid) -> Result<Vec<JobTargetRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            target_columns!(),
            " FROM job_targets WHERE job_id = ? AND workspace_id = ? ORDER BY rowid"
        ))
        .bind(job_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| row_to_target(r, false)).collect()
    }

    /// One target of a job, with its output.
    pub async fn job_target(&self, ctx: &Context, job_id: Uuid, target_key: &str) -> Result<Option<JobTargetRecord>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            target_columns!(),
            ", output, stderr FROM job_targets WHERE job_id = ? AND workspace_id = ? AND target_key = ?"
        ))
        .bind(job_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(target_key)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(|r| row_to_target(r, true)).transpose()
    }

    /// At startup: jobs that were still open when the app last stopped are marked interrupted. Their
    /// target rows are left as they were, which is the record of what finished. The partial index `jobs_open`
    /// holds only open jobs, so this reads none of the others (NFR Reliability: it runs at every start).
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

    /// BX-02 retention: empties the outputs (`job_targets.output` and `stderr`) and the script or line text in
    /// `command_json` of the workspace's jobs created before `before` (RFC 3339) that have ended, and marks them
    /// (`bodies_removed_at`), [`BATCH`] jobs per transaction. The job rows, summaries, tiers, targets, results,
    /// exit codes, output sizes and hashes stay, so Activity still lists them and Compare still groups them.
    pub async fn purge_job_bodies(&self, ctx: &Context, before: &str) -> Result<PurgedBodies> {
        let mut total = PurgedBodies::default();
        loop {
            let batch = self.purge_batch(ctx, before).await?;
            if batch.jobs == 0 {
                return Ok(total);
            }
            total.add(batch);
        }
    }

    async fn purge_batch(&self, ctx: &Context, before: &str) -> Result<PurgedBodies> {
        let mut tx = self.pool.begin().await?;
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM jobs
             WHERE workspace_id = ? AND created_at < ? AND bodies_removed_at IS NULL
               AND status NOT IN ('queued', 'countdown', 'running')
             ORDER BY created_at LIMIT ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(before)
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await?;
        if ids.is_empty() {
            return Ok(PurgedBodies::default());
        }
        let ids_json = serde_json::to_string(&ids)?;
        let outputs = sqlx::query(
            "SELECT COUNT(*) AS outputs,
                    COALESCE(SUM(LENGTH(CAST(IFNULL(output, '') AS BLOB)) + LENGTH(CAST(IFNULL(stderr, '') AS BLOB))), 0)
                        AS bytes
             FROM job_targets
             WHERE job_id IN (SELECT value FROM json_each(?)) AND (output IS NOT NULL OR stderr IS NOT NULL)",
        )
        .bind(&ids_json)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE job_targets SET output = NULL, stderr = NULL
             WHERE job_id IN (SELECT value FROM json_each(?)) AND (output IS NOT NULL OR stderr IS NOT NULL)",
        )
        .bind(&ids_json)
        .execute(&mut *tx)
        .await?;
        let mut purged = PurgedBodies {
            jobs: ids.len() as u64,
            outputs: outputs.try_get::<i64, _>("outputs")?.unsigned_abs(),
            commands: 0,
            bytes: outputs.try_get::<i64, _>("bytes")?.unsigned_abs(),
        };
        for (count, empty) in PURGE_BODIES {
            let bodies = sqlx::query(count).bind(&ids_json).fetch_one(&mut *tx).await?;
            purged.commands += bodies.try_get::<i64, _>("commands")?.unsigned_abs();
            purged.bytes += bodies.try_get::<i64, _>("bytes")?.unsigned_abs();
            sqlx::query(empty).bind(&ids_json).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE jobs SET bodies_removed_at = ? WHERE id IN (SELECT value FROM json_each(?))")
            .bind(now_rfc3339())
            .bind(&ids_json)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(purged)
    }

    /// BX-02, SS-10: scripts and lines journaled before migration 0017 were stored as typed. Redacts them once
    /// (`command_redacted` NULL becomes 0 or 1), [`BATCH`] at a time. Returns how many had something redacted.
    pub async fn redact_old_commands(&self) -> Result<u64> {
        let mut redacted = 0;
        loop {
            let mut tx = self.pool.begin().await?;
            let rows =
                sqlx::query("SELECT id, command_type, command_json FROM jobs WHERE command_redacted IS NULL LIMIT ?")
                    .bind(BATCH)
                    .fetch_all(&mut *tx)
                    .await?;
            if rows.is_empty() {
                tx.commit().await?;
                return Ok(redacted);
            }
            for row in &rows {
                let id: String = row.try_get("id")?;
                let command_type: String = row.try_get("command_type")?;
                let json: String = row.try_get("command_json")?;
                let (json, changed) = match serde_json::from_str::<Value>(&json) {
                    Ok(mut value) => {
                        if redact_body(&command_type, &mut value) {
                            (value.to_string(), true)
                        } else {
                            (json, false)
                        }
                    }
                    // Not JSON after all: the whole text, as the audit export does.
                    Err(_) => redact_secrets(&json),
                };
                sqlx::query("UPDATE jobs SET command_json = ?, command_redacted = ? WHERE id = ?")
                    .bind(&json)
                    .bind(changed)
                    .bind(&id)
                    .execute(&mut *tx)
                    .await?;
                redacted += u64::from(changed);
            }
            tx.commit().await?;
        }
    }

    /// BX-02: the database file's size and the free space inside it, in bytes.
    pub async fn space(&self) -> Result<(u64, u64)> {
        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size").fetch_one(&self.pool).await?;
        let pages: i64 = sqlx::query_scalar("PRAGMA page_count").fetch_one(&self.pool).await?;
        let free: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(&self.pool)
            .await?;
        Ok(((pages * page_size).unsigned_abs(), (free * page_size).unsigned_abs()))
    }

    /// BX-02: writes the write-ahead log into the database and empties it, so text just removed is not left in
    /// the `-wal` file. Best effort: while a reader holds an old snapshot, the log stays until a later one.
    pub async fn checkpoint(&self) -> Result<()> {
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// BX-02: rebuilds the database file without its free pages (`VACUUM`), then empties the write-ahead log.
    /// Only while no job runs ([`crate::jobs::JobRunner::when_idle`]).
    pub async fn vacuum(&self) -> Result<()> {
        sqlx::query("VACUUM").execute(&self.pool).await?;
        self.checkpoint().await
    }
}
