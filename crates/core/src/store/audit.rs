//! Append-only, hash-chained audit log (AP-05).
//!
//! Each entry's hash is SHA-256 over its content plus the previous entry's hash, so changing or
//! removing any row breaks every hash after it. Triggers in the schema refuse UPDATE and DELETE;
//! [`Store::verify_audit_chain`] catches edits made by going around them (e.g. editing the file).
//!
//! Entries are kept for good, so their free text (the action, result and detail) is redacted before it is
//! hashed and stored ([`redact_secrets`]): a secret typed into a command never lands in the log. Verifying
//! and exporting read the log row by row, however long it is.
//!
//! FD-02: each workspace has its own chain, so its log verifies and exports on its own entries and never holds
//! another's. A workspace's first entry links to its own start hash ([`chain_start`]); entries written before
//! workspaces (migration 0029) keep the single chain they were written in.

use futures_util::{Stream, StreamExt, TryStreamExt};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::command_bus::ApprovalRecord;
use crate::domain::{now_rfc3339, Context, Target};
use crate::error::Result;
use crate::export::redact_secrets;
use crate::policy::Tier;

/// prev_hash of the first entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What a caller logs. Never put secrets in here; what looks like one in the text is redacted anyway.
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
    /// FD-02: what a workspace's next entry links to: its last entry's hash, or, before its first entry since
    /// workspaces (migration 0029), its chain's start ([`chain_start`]).
    async fn chain_head(&self, ctx: &Context) -> Result<String> {
        let legacy_until: i64 = sqlx::query_scalar("SELECT audit_legacy_until FROM workspaces WHERE id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(0);
        let last: Option<(i64, String)> =
            sqlx::query_as("SELECT seq, hash FROM audit_log WHERE workspace_id = ? ORDER BY seq DESC LIMIT 1")
                .bind(ctx.workspace_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        Ok(match last {
            Some((seq, hash)) if seq > legacy_until => hash,
            last => chain_start(
                &ctx.workspace_id.to_string(),
                last.as_ref().map(|(_, hash)| hash.as_str()),
            ),
        })
    }

    pub async fn append_audit(&self, ctx: &Context, e: NewAuditEntry<'_>) -> Result<AuditEntry> {
        let _chain = self.audit_lock.lock().await;
        let prev_hash = self.chain_head(ctx).await?;

        // AP-05: kept for good, so no secret typed into a command or a reason stays in it.
        let clean = |text: &str| redact_secrets(text).0;
        let mut entry = AuditEntry {
            seq: 0,
            id: Uuid::new_v4().to_string(),
            workspace_id: ctx.workspace_id.to_string(),
            user_id: ctx.user_id.to_string(),
            ts: now_rfc3339(),
            event: e.event.to_owned(),
            action: clean(e.action),
            tier: e.tier.map(|t| t.as_str().to_owned()),
            job_id: e.job_id.map(|j| j.to_string()),
            targets_json: serde_json::to_string(e.targets)?,
            approval_json: e.approval.map(serde_json::to_string).transpose()?,
            result: e.result.map(clean),
            detail: e.detail.map(clean),
            prev_hash,
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

    /// AP-05: every entry of the workspace, oldest first. Use [`Store::audit_entries`] for a long log.
    pub async fn audit_for_export(&self, ctx: &Context) -> Result<Vec<AuditEntry>> {
        self.audit_entries(ctx).try_collect().await
    }

    /// AP-05: every entry of the workspace, oldest first, read as they are taken (the export writes each one
    /// as it comes, so a long log is never all in memory). It holds one of the database's connections until
    /// it is dropped.
    pub fn audit_entries(&self, ctx: &Context) -> impl Stream<Item = Result<AuditEntry>> + Send + '_ {
        sqlx::query("SELECT * FROM audit_log WHERE workspace_id = ? ORDER BY seq")
            .bind(ctx.workspace_id.to_string())
            .fetch(&self.pool)
            .map(|row| row.map_err(Into::into).and_then(|row| row_to_entry(&row)))
    }

    /// AP-05, FD-02: walks the workspace's chain and recomputes every hash of its entries, one row at a time.
    ///
    /// Entries written before workspaces (up to the workspace's `audit_legacy_until`) were one chain for the whole
    /// file: each links to the entry just before it, whichever workspace that was, so for those the walk reads the
    /// other entries' hashes (never their content, which isn't checked or returned here). From then on each entry
    /// links to its workspace's previous one, the first to the workspace's chain start.
    pub async fn verify_audit_chain(&self, ctx: &Context) -> Result<ChainCheck> {
        let workspace = ctx.workspace_id.to_string();
        let legacy_until: i64 = sqlx::query_scalar("SELECT audit_legacy_until FROM workspaces WHERE id = ?")
            .bind(&workspace)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(0);
        let mut checked: u64 = 0;
        let bad = |checked: u64, seq: i64, problem: &str| ChainCheck {
            entries: checked,
            ok: false,
            first_bad_seq: Some(seq),
            problem: Some(problem.to_owned()),
        };
        let mut tail: Option<String> = None;
        if legacy_until > 0 {
            let mut rows = sqlx::query("SELECT * FROM audit_log WHERE seq <= ? ORDER BY seq")
                .bind(legacy_until)
                .fetch(&self.pool);
            let mut before = GENESIS_HASH.to_owned();
            while let Some(row) = rows.try_next().await? {
                let entry = row_to_entry(&row)?;
                if entry.workspace_id == workspace {
                    if let Some(problem) = check_link(&entry, &before) {
                        return Ok(bad(checked, entry.seq, problem));
                    }
                    checked += 1;
                    tail = Some(entry.hash.clone());
                }
                before = entry.hash;
            }
        }
        let mut expected_prev = chain_start(&workspace, tail.as_deref());
        let mut rows = sqlx::query("SELECT * FROM audit_log WHERE workspace_id = ? AND seq > ? ORDER BY seq")
            .bind(&workspace)
            .bind(legacy_until)
            .fetch(&self.pool);
        while let Some(row) = rows.try_next().await? {
            let entry = row_to_entry(&row)?;
            if let Some(problem) = check_link(&entry, &expected_prev) {
                return Ok(bad(checked, entry.seq, problem));
            }
            expected_prev = entry.hash;
            checked += 1;
        }
        Ok(ChainCheck {
            entries: checked,
            ok: true,
            first_bad_seq: None,
            problem: None,
        })
    }
}

/// What is wrong with an entry that should link to `prev`, if anything.
fn check_link(entry: &AuditEntry, prev: &str) -> Option<&'static str> {
    if entry.prev_hash != prev {
        Some("link to the previous entry is broken (an entry was removed or reordered)")
    } else if entry.compute_hash() != entry.hash {
        Some("entry content does not match its hash (it was modified)")
    } else {
        None
    }
}

/// FD-02, AP-05: what a workspace's first entry since workspaces links to: SHA-256 (hex) over the workspace's id and
/// its last entry from before (none for a workspace made since). Each workspace's is its own, so no two entries share
/// a previous hash, and the old entries stay bound to the new ones.
pub fn chain_start(workspace_id: &str, last_before: Option<&str>) -> String {
    let text = format!(
        "remotely/audit-chain/v1/{workspace_id}/{}",
        last_before.unwrap_or_default()
    );
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub(super) fn row_to_entry(row: &sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
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
