//! Append-only, hash-chained audit log (AP-05).
//!
//! Each entry's hash is SHA-256 over its content plus the previous entry's hash, so changing or
//! removing any row breaks every hash after it. Triggers in the schema refuse UPDATE and DELETE;
//! [`Store::verify_audit_chain`] catches edits made by going around them (e.g. editing the file).

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::command_bus::ApprovalRecord;
use crate::domain::{now_rfc3339, Context, Target};
use crate::error::Result;
use crate::policy::Tier;

/// prev_hash of the first entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What a caller logs. Never put secrets in here.
pub struct NewAuditEntry<'a> {
    /// approval_requested, approval_granted, approval_cancelled, job_started, job_finished, ...
    pub event: &'a str,
    pub action: &'a str,
    pub tier: Option<Tier>,
    pub job_id: Option<Uuid>,
    pub targets: &'a [Target],
    pub approval: Option<&'a ApprovalRecord>,
    pub result: Option<&'a str>,
    pub detail: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub seq: i64,
    pub id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub ts: String,
    pub event: String,
    pub action: String,
    pub tier: Option<String>,
    pub job_id: Option<String>,
    pub targets_json: String,
    pub approval_json: Option<String>,
    pub result: Option<String>,
    pub detail: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEntry {
    /// SHA-256 (hex) over the previous hash and every content field, in a fixed order.
    pub fn compute_hash(&self) -> String {
        let canonical = serde_json::json!([
            self.prev_hash,
            self.id,
            self.workspace_id,
            self.user_id,
            self.ts,
            self.event,
            self.action,
            self.tier,
            self.job_id,
            self.targets_json,
            self.approval_json,
            self.result,
            self.detail,
        ]);
        hex::encode(Sha256::digest(canonical.to_string().as_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCheck {
    pub entries: u64,
    pub ok: bool,
    /// First entry whose link or content does not check out.
    pub first_bad_seq: Option<i64>,
    pub problem: Option<String>,
}

impl Store {
    pub async fn append_audit(&self, ctx: &Context, e: NewAuditEntry<'_>) -> Result<AuditEntry> {
        let _chain = self.audit_lock.lock().await;
        let prev: Option<String> = sqlx::query_scalar("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;

        let mut entry = AuditEntry {
            seq: 0,
            id: Uuid::new_v4().to_string(),
            workspace_id: ctx.workspace_id.to_string(),
            user_id: ctx.user_id.to_string(),
            ts: now_rfc3339(),
            event: e.event.to_owned(),
            action: e.action.to_owned(),
            tier: e.tier.map(|t| t.as_str().to_owned()),
            job_id: e.job_id.map(|j| j.to_string()),
            targets_json: serde_json::to_string(e.targets)?,
            approval_json: e.approval.map(serde_json::to_string).transpose()?,
            result: e.result.map(str::to_owned),
            detail: e.detail.map(str::to_owned),
            prev_hash: prev.unwrap_or_else(|| GENESIS_HASH.to_owned()),
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();

        let seq: i64 = sqlx::query_scalar(
            "INSERT INTO audit_log (id, workspace_id, user_id, ts, event, action, tier, job_id, targets_json,
                                    approval_json, result, detail, prev_hash, hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             RETURNING seq",
        )
        .bind(&entry.id)
        .bind(&entry.workspace_id)
        .bind(&entry.user_id)
        .bind(&entry.ts)
        .bind(&entry.event)
        .bind(&entry.action)
        .bind(&entry.tier)
        .bind(&entry.job_id)
        .bind(&entry.targets_json)
        .bind(&entry.approval_json)
        .bind(&entry.result)
        .bind(&entry.detail)
        .bind(&entry.prev_hash)
        .bind(&entry.hash)
        .fetch_one(&self.pool)
        .await?;
        entry.seq = seq;
        Ok(entry)
    }

    /// Newest first.
    pub async fn recent_audit(&self, ctx: &Context, limit: u32) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query("SELECT * FROM audit_log WHERE workspace_id = ? ORDER BY seq DESC LIMIT ?")
            .bind(ctx.workspace_id.to_string())
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_entry).collect()
    }

    /// Walks the whole chain and recomputes every hash.
    pub async fn verify_audit_chain(&self) -> Result<ChainCheck> {
        // TODO: stream rows instead of loading them all once the log gets large.
        let rows = sqlx::query("SELECT * FROM audit_log ORDER BY seq")
            .fetch_all(&self.pool)
            .await?;
        let mut expected_prev = GENESIS_HASH.to_owned();
        for (i, row) in rows.iter().enumerate() {
            let entry = row_to_entry(row)?;
            let problem = if entry.prev_hash != expected_prev {
                Some("link to the previous entry is broken (an entry was removed or reordered)")
            } else if entry.compute_hash() != entry.hash {
                Some("entry content does not match its hash (it was modified)")
            } else {
                None
            };
            if let Some(problem) = problem {
                return Ok(ChainCheck {
                    entries: i as u64,
                    ok: false,
                    first_bad_seq: Some(entry.seq),
                    problem: Some(problem.to_owned()),
                });
            }
            expected_prev = entry.hash;
        }
        Ok(ChainCheck {
            entries: rows.len() as u64,
            ok: true,
            first_bad_seq: None,
            problem: None,
        })
    }
}

fn row_to_entry(row: &sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    Ok(AuditEntry {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        workspace_id: row.try_get("workspace_id")?,
        user_id: row.try_get("user_id")?,
        ts: row.try_get("ts")?,
        event: row.try_get("event")?,
        action: row.try_get("action")?,
        tier: row.try_get("tier")?,
        job_id: row.try_get("job_id")?,
        targets_json: row.try_get("targets_json")?,
        approval_json: row.try_get("approval_json")?,
        result: row.try_get("result")?,
        detail: row.try_get("detail")?,
        prev_hash: row.try_get("prev_hash")?,
        hash: row.try_get("hash")?,
    })
}
