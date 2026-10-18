//! SSH key rows (SS-09): the public half of private keys in the vault. Nothing here is secret; the
//! private halves stay in `vault_items`. Decisions live in `crate::ssh_keys`.

use std::collections::HashMap;

use sqlx::Row;

use super::{parse_uuid, Store};
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::ssh_keys::PublicKeyInfo;
use crate::vault::SecretId;

/// A key's public half as stored, and whether Remotely generated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshKeyRow {
    pub public: PublicKeyInfo,
    pub generated: bool,
}

fn row_to_key(row: &sqlx::sqlite::SqliteRow) -> Result<(SecretId, SshKeyRow)> {
    let id: String = row.try_get("secret_id")?;
    let line: String = row.try_get("public_key")?;
    let bits: Option<i64> = row.try_get("bits")?;
    let generated: i64 = row.try_get("generated")?;
    let comment = line.splitn(3, ' ').nth(2).unwrap_or_default().to_owned();
    Ok((
        SecretId(parse_uuid(&id)?),
        SshKeyRow {
            public: PublicKeyInfo {
                algorithm: row.try_get("algorithm")?,
                line,
                fingerprint: row.try_get("fingerprint")?,
                comment,
                bits: bits.and_then(|b| u32::try_from(b).ok()),
            },
            generated: generated != 0,
        },
    ))
}

impl Store {
    /// Every known public half in the workspace, by vault item.
    pub(crate) async fn ssh_key_rows(&self, ctx: &Context) -> Result<HashMap<SecretId, SshKeyRow>> {
        let rows = sqlx::query(
            "SELECT secret_id, algorithm, public_key, fingerprint, bits, generated FROM ssh_keys WHERE workspace_id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_key).collect()
    }

    /// Saves (or replaces) the public half of a vault item's private key.
    pub(crate) async fn put_ssh_key(
        &self,
        ctx: &Context,
        id: SecretId,
        public: &PublicKeyInfo,
        generated: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO ssh_keys (secret_id, workspace_id, user_id, algorithm, public_key, fingerprint, bits,
                                   generated, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(secret_id) DO UPDATE SET
                 algorithm = excluded.algorithm, public_key = excluded.public_key,
                 fingerprint = excluded.fingerprint, bits = excluded.bits, generated = excluded.generated,
                 user_id = excluded.user_id",
        )
        .bind(id.0.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&public.algorithm)
        .bind(&public.line)
        .bind(&public.fingerprint)
        .bind(public.bits.map(i64::from))
        .bind(i64::from(generated))
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
