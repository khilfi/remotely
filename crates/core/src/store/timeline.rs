//! VM-25: a VM's Timeline: the audit entries that name it, newest first, and its own row of each job.
//!
//! An entry names the VM when its targets (`targets_json`, the [`crate::domain::Target`]s as JSON) hold the VM's
//! key as `"vmxPath":"<key>"`, compared without letter case. The audit log has no index by target (it is
//! append-only and kept for good), so a page reads the workspace's entries newest first until it has enough; the
//! text search is a plain substring match, not a JSON parse, so a long log stays quick. A job's row for the VM
//! comes from `job_targets` by its key (migration 0024's index).

use std::collections::HashMap;

use sqlx::Row;

use super::{AuditEntry, Store};
use crate::domain::Context;
use crate::error::Result;

/// The VM's own row of a job, from the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobTargetBrief {
    pub status: String,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub safety_snapshot: Option<String>,
    pub finished_at: Option<String>,
}

/// What a VM's key looks like inside `targets_json`.
pub fn vm_needle(key: &str) -> String {
    let quoted = serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\""));
    format!("\"vmxPath\":{quoted}").to_lowercase()
}

impl Store {
    /// VM-25: the workspace's audit entries whose targets hold `needle` (lower case), newest first, before `before`
    /// (a `seq`; `None`: from the newest), at most `limit`.
    pub async fn audit_naming(
        &self,
        ctx: &Context,
        needle: &str,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT * FROM audit_log
             WHERE workspace_id = ? AND seq < ? AND instr(lower(targets_json), ?) > 0
             ORDER BY seq DESC LIMIT ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(before.unwrap_or(i64::MAX))
        .bind(needle)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(super::audit::row_to_entry).collect()
    }

    /// VM-25: the target `key`'s row of each of these jobs, by job id.
    pub async fn job_rows_for(
        &self,
        ctx: &Context,
        job_ids: &[String],
        key: &str,
    ) -> Result<HashMap<String, JobTargetBrief>> {
        if job_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows = sqlx::query(
            "SELECT job_id, status, error, duration_ms, safety_snapshot, finished_at FROM job_targets
             WHERE workspace_id = ? AND target_key = ? AND job_id IN (SELECT value FROM json_each(?))",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(key)
        .bind(serde_json::to_string(job_ids)?)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get::<String, _>("job_id")?,
                    JobTargetBrief {
                        status: r.try_get("status")?,
                        error: r.try_get("error")?,
                        duration_ms: r.try_get("duration_ms")?,
                        safety_snapshot: r.try_get("safety_snapshot")?,
                        finished_at: r.try_get("finished_at")?,
                    },
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_needle_matches_the_key_as_json_writes_it() {
        assert_eq!(
            vm_needle(r"C:\VMs\Web01\web01.vmx"),
            r#""vmxpath":"c:\\vms\\web01\\web01.vmx""#
        );
        assert_eq!(
            vm_needle("00000000-0000-4000-8000-0000000000aa"),
            r#""vmxpath":"00000000-0000-4000-8000-0000000000aa""#
        );
    }
}
