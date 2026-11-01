//! MO-08: health checks and their results (migration 0030). The rules and the audit log live in [`crate::checks`];
//! results are pruned with the dashboard's history ([`Store::prune_history`]).

use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::checks::spec::{CheckInput, CheckSpec, HealthCheck};
use crate::checks::{CheckResult, RunResult};
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};
use crate::toolbox::ProbeTarget;

fn corrupt(what: &str) -> CoreError {
    sqlx::Error::Decode(format!("unreadable {what} in the health check tables").into()).into()
}

fn target_parts(target: &ProbeTarget) -> (&'static str, String) {
    match target {
        ProbeTarget::Address { host } => ("address", host.clone()),
        ProbeTarget::Session { session_id } => ("session", session_id.to_string()),
        ProbeTarget::Vm { vm_key } => ("vm", vm_key.clone()),
    }
}

fn target_from(kind: &str, key: String) -> Result<ProbeTarget> {
    Ok(match kind {
        "address" => ProbeTarget::Address { host: key },
        "session" => ProbeTarget::Session {
            session_id: parse_uuid(&key)?,
        },
        "vm" => ProbeTarget::Vm { vm_key: key },
        _ => return Err(corrupt("target")),
    })
}

fn check_from(row: &SqliteRow) -> Result<HealthCheck> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let options: String = row.try_get("options")?;
    let spec: CheckSpec = serde_json::from_str(&options).map_err(|_| corrupt("options"))?;
    if spec.kind_str() != kind {
        return Err(corrupt("kind"));
    }
    let target_kind: String = row.try_get("target_kind")?;
    Ok(HealthCheck {
        id: parse_uuid(&id)?,
        name: row.try_get("name")?,
        target: target_from(&target_kind, row.try_get("target_key")?)?,
        spec,
        interval_secs: u64::try_from(row.try_get::<i64, _>("interval_secs")?).unwrap_or(60),
        timeout_secs: u64::try_from(row.try_get::<i64, _>("timeout_secs")?).unwrap_or(10),
        failures_before_down: u32::try_from(row.try_get::<i64, _>("failures_before_down")?).unwrap_or(2),
        paused: row.try_get("paused")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn result_from(row: &SqliteRow) -> Result<CheckResult> {
    let result: String = row.try_get("result")?;
    Ok(CheckResult {
        at: row.try_get("at")?,
        result: RunResult::parse(&result).ok_or_else(|| corrupt("result"))?,
        took_ms: row
            .try_get::<Option<i64>, _>("took_ms")?
            .and_then(|ms| u64::try_from(ms).ok()),
        detail: row.try_get("detail")?,
        cert_days: row.try_get("cert_days")?,
    })
}

macro_rules! check_columns {
    () => {
        "id, name, kind, target_kind, target_key, options, interval_secs, timeout_secs, failures_before_down, paused,
         created_at, updated_at"
    };
}

/// One bucket of a check's results: when it starts (Unix ms), the runs in it and their average time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResultBucket {
    pub start: i64,
    pub up: u32,
    pub down: u32,
    pub unknown: u32,
    /// The average time of the runs that passed.
    pub avg_ms: Option<f64>,
}

/// MO-08, for F6's inventory and handover pack: a check's runs between two times, and its uptime.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckUptime {
    pub check_id: Uuid,
    pub name: String,
    pub up: u64,
    pub down: u64,
    /// Runs Remotely couldn't make (left out of the uptime).
    pub unknown: u64,
    /// Percent of the runs that passed; none without runs.
    pub uptime: Option<f64>,
}

impl Store {
    /// MO-08: each check of `ctx`'s workspace with its runs from `from` up to `to` (Unix ms, `to` not included) and
    /// its uptime over them, by name. Any range the history still holds (`metrics.historyRetention`), for any
    /// workspace: an export reads the workspace it exports, shown or not (rule 8).
    pub async fn check_uptime(&self, ctx: &Context, from: i64, to: i64) -> Result<Vec<CheckUptime>> {
        let mut out = Vec::new();
        for check in self.list_checks(ctx).await? {
            let row = sqlx::query(
                "SELECT SUM(result = 'up') AS up, SUM(result = 'down') AS down, SUM(result = 'unknown') AS unknown
                 FROM health_check_results WHERE check_id = ? AND workspace_id = ? AND at >= ? AND at < ?",
            )
            .bind(check.id.to_string())
            .bind(ctx.workspace_id.to_string())
            .bind(from)
            .bind(to)
            .fetch_one(&self.pool)
            .await?;
            let count = |column: &str| -> Result<u64> {
                Ok(u64::try_from(row.try_get::<Option<i64>, _>(column)?.unwrap_or(0)).unwrap_or(0))
            };
            let (up, down, unknown) = (count("up")?, count("down")?, count("unknown")?);
            #[allow(clippy::cast_precision_loss)]
            let uptime = (up + down > 0).then(|| up as f64 * 100.0 / (up + down) as f64);
            out.push(CheckUptime {
                check_id: check.id,
                name: check.name,
                up,
                down,
                unknown,
                uptime,
            });
        }
        Ok(out)
    }

    /// MO-08: the workspace's checks by name.
    pub async fn list_checks(&self, ctx: &Context) -> Result<Vec<HealthCheck>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            check_columns!(),
            " FROM health_checks WHERE workspace_id = ? ORDER BY name COLLATE NOCASE, created_at"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(check_from).collect()
    }

    pub async fn get_check(&self, ctx: &Context, id: Uuid) -> Result<Option<HealthCheck>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            check_columns!(),
            " FROM health_checks WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(check_from).transpose()
    }

    pub async fn count_checks(&self, ctx: &Context) -> Result<usize> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM health_checks WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }

    /// Saves a new check (already checked by [`crate::checks::spec::checked`]).
    pub async fn insert_check(&self, ctx: &Context, input: &CheckInput) -> Result<HealthCheck> {
        let id = Uuid::new_v4();
        let now = now_rfc3339();
        let (target_kind, target_key) = target_parts(&input.target);
        sqlx::query(
            "INSERT INTO health_checks (id, workspace_id, user_id, name, kind, target_kind, target_key, options,
                                        interval_secs, timeout_secs, failures_before_down, paused, created_at,
                                        updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&input.name)
        .bind(input.spec.kind_str())
        .bind(target_kind)
        .bind(target_key)
        .bind(serde_json::to_string(&input.spec)?)
        .bind(i64::try_from(input.interval_secs).unwrap_or(60))
        .bind(i64::try_from(input.timeout_secs).unwrap_or(10))
        .bind(i64::from(input.failures_before_down))
        .bind(input.paused)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        self.get_check(ctx, id).await?.ok_or_else(|| corrupt("new check"))
    }

    /// Replaces a check's definition; `None` when the workspace has no such check.
    pub async fn update_check(&self, ctx: &Context, id: Uuid, input: &CheckInput) -> Result<Option<HealthCheck>> {
        let (target_kind, target_key) = target_parts(&input.target);
        let done = sqlx::query(
            "UPDATE health_checks SET name = ?, kind = ?, target_kind = ?, target_key = ?, options = ?,
                                      interval_secs = ?, timeout_secs = ?, failures_before_down = ?, paused = ?,
                                      updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(&input.name)
        .bind(input.spec.kind_str())
        .bind(target_kind)
        .bind(target_key)
        .bind(serde_json::to_string(&input.spec)?)
        .bind(i64::try_from(input.interval_secs).unwrap_or(60))
        .bind(i64::try_from(input.timeout_secs).unwrap_or(10))
        .bind(i64::from(input.failures_before_down))
        .bind(input.paused)
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        if done.rows_affected() == 0 {
            return Ok(None);
        }
        self.get_check(ctx, id).await
    }

    /// Deletes a check with its results; false when the workspace has no such check.
    pub async fn delete_check(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM health_checks WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Keeps one run's result. A second result at the same millisecond replaces the first.
    pub async fn insert_check_result(&self, ctx: &Context, id: Uuid, result: &CheckResult) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO health_check_results (check_id, at, workspace_id, user_id, result, took_ms, detail,
                                                          cert_days)
             SELECT id, ?, workspace_id, user_id, ?, ?, ?, ? FROM health_checks WHERE workspace_id = ? AND id = ?",
        )
        .bind(result.at)
        .bind(result.result.as_str())
        .bind(result.took_ms.and_then(|ms| i64::try_from(ms).ok()))
        .bind(&result.detail)
        .bind(result.cert_days)
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A check's results from `since` (Unix ms), newest first, at most `limit`.
    pub async fn check_results(&self, ctx: &Context, id: Uuid, since: i64, limit: u32) -> Result<Vec<CheckResult>> {
        let rows = sqlx::query(
            "SELECT at, result, took_ms, detail, cert_days FROM health_check_results
             WHERE check_id = ? AND workspace_id = ? AND at >= ? ORDER BY at DESC LIMIT ?",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(since)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(result_from).collect()
    }

    /// A check's results from `since` (Unix ms) in buckets of `bucket_ms`, oldest first.
    pub async fn check_buckets(
        &self,
        ctx: &Context,
        id: Uuid,
        since: i64,
        bucket_ms: i64,
    ) -> Result<Vec<ResultBucket>> {
        let bucket_ms = bucket_ms.max(1);
        let rows = sqlx::query(
            "SELECT (at / ?) * ? AS start,
                    SUM(result = 'up') AS up, SUM(result = 'down') AS down, SUM(result = 'unknown') AS unknown,
                    AVG(CASE WHEN result = 'up' THEN took_ms END) AS avg_ms
             FROM health_check_results
             WHERE check_id = ? AND workspace_id = ? AND at >= ?
             GROUP BY start ORDER BY start",
        )
        .bind(bucket_ms)
        .bind(bucket_ms)
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        let count = |row: &SqliteRow, column: &str| -> Result<u32> {
            Ok(u32::try_from(row.try_get::<Option<i64>, _>(column)?.unwrap_or(0)).unwrap_or(0))
        };
        rows.iter()
            .map(|row| {
                Ok(ResultBucket {
                    start: row.try_get("start")?,
                    up: count(row, "up")?,
                    down: count(row, "down")?,
                    unknown: count(row, "unknown")?,
                    avg_ms: row.try_get("avg_ms")?,
                })
            })
            .collect()
    }
}
