//! MO-06: the dashboard's history on disk, one row per series per minute ([`crate::metrics::history`]).
//! Written once a minute in one transaction, read back by series and time, pruned daily with the alert list's
//! resolved alerts.

use serde::Serialize;
use sqlx::Row;

use super::Store;
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::metrics::history::{HistorySource, MinuteRow};

/// What a prune removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPruned {
    /// One-minute rows.
    pub minutes: u64,
    /// Series left with no minutes (a VM gone, a host no longer watched).
    pub series: u64,
    /// Resolved alerts.
    pub alerts: u64,
}

impl HistoryPruned {
    pub fn removed_any(&self) -> bool {
        self.minutes > 0 || self.series > 0 || self.alerts > 0
    }
}

/// What the history holds, for Settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistorySize {
    pub series: u64,
    pub minutes: u64,
    /// The oldest minute kept (RFC 3339).
    pub oldest: Option<String>,
    /// What its tables take in the database file, when SQLite can say.
    pub bytes: Option<u64>,
}

fn int(value: Option<u64>) -> Option<i64> {
    value.and_then(|v| i64::try_from(v).ok())
}

fn uint(value: Option<i64>) -> Option<u64> {
    value.and_then(|v| u64::try_from(v).ok())
}

/// A minute already written for the series (the app closed and started again within it) takes the new
/// rounds in: averages weighted by their rounds, the lowest and highest over both.
const WRITE_MINUTE: &str =
    "INSERT INTO metric_minutes (series_id, minute, workspace_id, user_id, samples, cpu_avg, cpu_min,
        cpu_max, mem_avg, mem_max, mem_total, swap_avg, swap_total, read_avg, write_avg, rx_avg, tx_avg, load_avg,
        load_max, disk_used_max)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (series_id, minute) DO UPDATE SET
        samples = samples + excluded.samples,
        cpu_avg = CASE WHEN cpu_avg IS NULL THEN excluded.cpu_avg WHEN excluded.cpu_avg IS NULL THEN cpu_avg
            ELSE (cpu_avg * samples + excluded.cpu_avg * excluded.samples) / (samples + excluded.samples) END,
        cpu_min = MIN(COALESCE(cpu_min, excluded.cpu_min), COALESCE(excluded.cpu_min, cpu_min)),
        cpu_max = MAX(COALESCE(cpu_max, excluded.cpu_max), COALESCE(excluded.cpu_max, cpu_max)),
        mem_avg = CAST(ROUND(CASE WHEN mem_avg IS NULL THEN excluded.mem_avg WHEN excluded.mem_avg IS NULL THEN mem_avg
            ELSE (mem_avg * samples + excluded.mem_avg * excluded.samples) * 1.0 / (samples + excluded.samples) END)
            AS INTEGER),
        mem_max = MAX(COALESCE(mem_max, excluded.mem_max), COALESCE(excluded.mem_max, mem_max)),
        mem_total = COALESCE(excluded.mem_total, mem_total),
        swap_avg = CAST(ROUND(CASE WHEN swap_avg IS NULL THEN excluded.swap_avg WHEN excluded.swap_avg IS NULL
            THEN swap_avg ELSE (swap_avg * samples + excluded.swap_avg * excluded.samples) * 1.0
            / (samples + excluded.samples) END) AS INTEGER),
        swap_total = COALESCE(excluded.swap_total, swap_total),
        read_avg = CAST(ROUND(CASE WHEN read_avg IS NULL THEN excluded.read_avg WHEN excluded.read_avg IS NULL
            THEN read_avg ELSE (read_avg * samples + excluded.read_avg * excluded.samples) * 1.0
            / (samples + excluded.samples) END) AS INTEGER),
        write_avg = CAST(ROUND(CASE WHEN write_avg IS NULL THEN excluded.write_avg WHEN excluded.write_avg IS NULL
            THEN write_avg ELSE (write_avg * samples + excluded.write_avg * excluded.samples) * 1.0
            / (samples + excluded.samples) END) AS INTEGER),
        rx_avg = CAST(ROUND(CASE WHEN rx_avg IS NULL THEN excluded.rx_avg WHEN excluded.rx_avg IS NULL
            THEN rx_avg ELSE (rx_avg * samples + excluded.rx_avg * excluded.samples) * 1.0
            / (samples + excluded.samples) END) AS INTEGER),
        tx_avg = CAST(ROUND(CASE WHEN tx_avg IS NULL THEN excluded.tx_avg WHEN excluded.tx_avg IS NULL
            THEN tx_avg ELSE (tx_avg * samples + excluded.tx_avg * excluded.samples) * 1.0
            / (samples + excluded.samples) END) AS INTEGER),
        load_avg = CASE WHEN load_avg IS NULL THEN excluded.load_avg WHEN excluded.load_avg IS NULL THEN load_avg
            ELSE (load_avg * samples + excluded.load_avg * excluded.samples) / (samples + excluded.samples) END,
        load_max = MAX(COALESCE(load_max, excluded.load_max), COALESCE(excluded.load_max, load_max)),
        disk_used_max = MAX(COALESCE(disk_used_max, excluded.disk_used_max),
            COALESCE(excluded.disk_used_max, disk_used_max))";

impl Store {
    /// MO-06: writes finished minutes, every series' in one transaction. A series seen for the first time gets
    /// its row.
    pub async fn write_history(&self, ctx: &Context, rows: &[MinuteRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let ws = ctx.workspace_id.to_string();
        let user = ctx.user_id.to_string();
        let now = now_rfc3339();
        let mut ids: std::collections::HashMap<(HistorySource, String), i64> = std::collections::HashMap::new();
        let mut tx = self.pool.begin().await?;
        for row in rows {
            let series = (row.source, row.key.to_lowercase());
            let id = match ids.get(&series) {
                Some(id) => *id,
                None => {
                    let id: i64 = sqlx::query_scalar(
                        "INSERT INTO metric_series (workspace_id, user_id, source, target_key, created_at)
                         VALUES (?, ?, ?, ?, ?)
                         ON CONFLICT (workspace_id, source, target_key) DO UPDATE SET user_id = excluded.user_id
                         RETURNING id",
                    )
                    .bind(&ws)
                    .bind(&user)
                    .bind(row.source.as_str())
                    .bind(&row.key)
                    .bind(&now)
                    .fetch_one(&mut *tx)
                    .await?;
                    ids.insert(series, id);
                    id
                }
            };
            sqlx::query(WRITE_MINUTE)
                .bind(id)
                .bind(row.minute)
                .bind(&ws)
                .bind(&user)
                .bind(i64::from(row.samples.max(1)))
                .bind(row.cpu_avg)
                .bind(row.cpu_min)
                .bind(row.cpu_max)
                .bind(int(row.mem_avg))
                .bind(int(row.mem_max))
                .bind(int(row.mem_total))
                .bind(int(row.swap_avg))
                .bind(int(row.swap_total))
                .bind(int(row.read_avg))
                .bind(int(row.write_avg))
                .bind(int(row.rx_avg))
                .bind(int(row.tx_avg))
                .bind(row.load_avg)
                .bind(row.load_max)
                .bind(row.disk_used_max)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// MO-06: one series' minutes from `from_minute` (inclusive) to `to_minute` (exclusive), oldest first.
    pub async fn read_history(
        &self,
        ctx: &Context,
        source: HistorySource,
        key: &str,
        from_minute: i64,
        to_minute: i64,
    ) -> Result<Vec<MinuteRow>> {
        let rows = sqlx::query(
            "SELECT m.minute, m.samples, m.cpu_avg, m.cpu_min, m.cpu_max, m.mem_avg, m.mem_max, m.mem_total,
                    m.swap_avg, m.swap_total, m.read_avg, m.write_avg, m.rx_avg, m.tx_avg, m.load_avg, m.load_max,
                    m.disk_used_max
             FROM metric_series s JOIN metric_minutes m ON m.series_id = s.id
             WHERE s.workspace_id = ? AND s.source = ? AND s.target_key = ? AND m.workspace_id = s.workspace_id
               AND m.minute >= ? AND m.minute < ?
             ORDER BY m.minute",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(source.as_str())
        .bind(key)
        .bind(from_minute)
        .bind(to_minute)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(MinuteRow {
                    source,
                    key: key.to_owned(),
                    minute: r.try_get("minute")?,
                    samples: u32::try_from(r.try_get::<i64, _>("samples")?).unwrap_or(1),
                    cpu_avg: r.try_get("cpu_avg")?,
                    cpu_min: r.try_get("cpu_min")?,
                    cpu_max: r.try_get("cpu_max")?,
                    mem_avg: uint(r.try_get("mem_avg")?),
                    mem_max: uint(r.try_get("mem_max")?),
                    mem_total: uint(r.try_get("mem_total")?),
                    swap_avg: uint(r.try_get("swap_avg")?),
                    swap_total: uint(r.try_get("swap_total")?),
                    read_avg: uint(r.try_get("read_avg")?),
                    write_avg: uint(r.try_get("write_avg")?),
                    rx_avg: uint(r.try_get("rx_avg")?),
                    tx_avg: uint(r.try_get("tx_avg")?),
                    load_avg: r.try_get("load_avg")?,
                    load_max: r.try_get("load_max")?,
                    disk_used_max: r.try_get("disk_used_max")?,
                })
            })
            .collect()
    }

    /// MO-06, MO-07: removes the minutes before `before_minute`, series left with none, and alerts resolved
    /// before `before` (RFC 3339). Alerts still open stay, however old. Series by series, so a long prune never
    /// holds the database for long.
    pub async fn prune_history(&self, ctx: &Context, before_minute: i64, before: &str) -> Result<HistoryPruned> {
        let ws = ctx.workspace_id.to_string();
        let series: Vec<i64> = sqlx::query_scalar("SELECT id FROM metric_series WHERE workspace_id = ?")
            .bind(&ws)
            .fetch_all(&self.pool)
            .await?;
        let mut pruned = HistoryPruned::default();
        for id in series {
            let done = sqlx::query("DELETE FROM metric_minutes WHERE series_id = ? AND minute < ?")
                .bind(id)
                .bind(before_minute)
                .execute(&self.pool)
                .await?;
            pruned.minutes += done.rows_affected();
        }
        pruned.series = sqlx::query(
            "DELETE FROM metric_series WHERE workspace_id = ?
               AND NOT EXISTS (SELECT 1 FROM metric_minutes m WHERE m.series_id = metric_series.id)",
        )
        .bind(&ws)
        .execute(&self.pool)
        .await?
        .rows_affected();
        pruned.alerts =
            sqlx::query("DELETE FROM alerts WHERE workspace_id = ? AND resolved_at IS NOT NULL AND resolved_at < ?")
                .bind(&ws)
                .bind(before)
                .execute(&self.pool)
                .await?
                .rows_affected();
        Ok(pruned)
    }

    /// MO-06: how many series and minutes the history holds, since when, and what it takes on disk.
    pub async fn history_size(&self, ctx: &Context) -> Result<HistorySize> {
        let ws = ctx.workspace_id.to_string();
        let series: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM metric_series WHERE workspace_id = ?")
            .bind(&ws)
            .fetch_one(&self.pool)
            .await?;
        let row =
            sqlx::query("SELECT COUNT(*) AS minutes, MIN(minute) AS oldest FROM metric_minutes WHERE workspace_id = ?")
                .bind(&ws)
                .fetch_one(&self.pool)
                .await?;
        let minutes: i64 = row.try_get("minutes")?;
        let oldest: Option<i64> = row.try_get("oldest")?;
        // SQLite's own page count per table; every workspace's, which is the file's share either way.
        let bytes: Option<i64> = sqlx::query_scalar(
            "SELECT SUM(pgsize) FROM dbstat WHERE name IN ('metric_minutes', 'metric_series', 'sqlite_autoindex_metric_series_1')",
        )
        .fetch_one(&self.pool)
        .await
        .ok()
        .flatten();
        Ok(HistorySize {
            series: series.unsigned_abs(),
            minutes: minutes.unsigned_abs(),
            oldest: oldest.and_then(|m| {
                time::OffsetDateTime::from_unix_timestamp(m.saturating_mul(60))
                    .ok()
                    .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
            }),
            bytes: bytes.and_then(|b| u64::try_from(b).ok()),
        })
    }
}
