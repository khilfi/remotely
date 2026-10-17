//! Metric samples (MO-01, MO-02). Retention and 1-minute rollups are MO-06 (v2).

use super::Store;
use crate::domain::Context;
use crate::error::Result;
use crate::metrics::MetricSample;

impl Store {
    pub async fn insert_metric_samples(&self, ctx: &Context, samples: &[MetricSample]) -> Result<()> {
        let ws = ctx.workspace_id.to_string();
        let user = ctx.user_id.to_string();
        let mut tx = self.pool.begin().await?;
        for s in samples {
            sqlx::query(
                "INSERT INTO metric_samples (workspace_id, user_id, source, target_kind, target_key, ts, cpu_pct,
                                             mem_bytes, disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps,
                                             load1, uptime_secs)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&ws)
            .bind(&user)
            .bind(s.source.as_str())
            .bind(s.target.kind())
            .bind(s.target.key())
            .bind(&s.ts)
            .bind(s.cpu_pct)
            .bind(s.mem_bytes.and_then(|v| i64::try_from(v).ok()))
            .bind(s.disk_read_bps)
            .bind(s.disk_write_bps)
            .bind(s.net_rx_bps)
            .bind(s.net_tx_bps)
            .bind(s.load1)
            .bind(s.uptime_secs.and_then(|v| i64::try_from(v).ok()))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
