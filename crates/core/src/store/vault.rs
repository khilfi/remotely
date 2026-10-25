//! Vault rows (SS-04): `vault_meta` holds the wrapped data key, `vault_items` the ciphertext of each
//! secret. Nothing here ever sees a plaintext secret or an unwrapped key.

use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};
use crate::vault::{KdfParams, SecretId, SecretKind, SecretMeta};

/// The workspace's vault, as stored.
pub(crate) struct VaultMetaRow {
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
    /// The data key wrapped by the master key.
    pub wrapped_key: Vec<u8>,
    /// The data key protected by DPAPI, when the Windows login unlocks the vault.
    pub dpapi_key: Option<Vec<u8>>,
}

/// One secret's ciphertext and what its AAD is built from.
pub(crate) struct VaultCipher {
    pub kind: SecretKind,
    pub label: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

fn kind_of(row: &sqlx::sqlite::SqliteRow) -> Result<SecretKind> {
    let kind: String = row.try_get("kind")?;
    SecretKind::parse(&kind).ok_or_else(|| CoreError::Vault(format!("unknown secret kind '{kind}'")))
}

fn unlock_method(dpapi_key: Option<&[u8]>) -> &'static str {
    if dpapi_key.is_some() {
        "dpapi"
    } else {
        "master_password"
    }
}

impl Store {
    pub(crate) async fn vault_meta(&self, ctx: &Context) -> Result<Option<VaultMetaRow>> {
        let row =
            sqlx::query("SELECT kdf_salt, kdf_params, wrapped_key, dpapi_key FROM vault_meta WHERE workspace_id = ?")
                .bind(ctx.workspace_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        row.map(|r| -> Result<_> {
            let salt: Option<Vec<u8>> = r.try_get("kdf_salt")?;
            let params: Option<String> = r.try_get("kdf_params")?;
            let (Some(kdf_salt), Some(params)) = (salt, params) else {
                return Err(CoreError::Vault("the vault has no master-password key".into()));
            };
            Ok(VaultMetaRow {
                kdf_salt,
                kdf_params: serde_json::from_str(&params)?,
                wrapped_key: r.try_get("wrapped_key")?,
                dpapi_key: r.try_get("dpapi_key")?,
            })
        })
        .transpose()
    }

    /// Fails if the workspace already has a vault.
    pub(crate) async fn insert_vault_meta(
        &self,
        ctx: &Context,
        kdf_salt: &[u8],
        kdf_params: &KdfParams,
        wrapped_key: &[u8],
        dpapi_key: Option<&[u8]>,
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO vault_meta (workspace_id, user_id, unlock_method, kdf_salt, kdf_params, wrapped_key,
                                     dpapi_key, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(unlock_method(dpapi_key))
        .bind(kdf_salt)
        .bind(serde_json::to_string(kdf_params)?)
        .bind(wrapped_key)
        .bind(dpapi_key)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// `None` stops the Windows login from unlocking the vault.
    pub(crate) async fn set_vault_dpapi_key(&self, ctx: &Context, dpapi_key: Option<&[u8]>) -> Result<()> {
        sqlx::query(
            "UPDATE vault_meta SET unlock_method = ?, dpapi_key = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ?",
        )
        .bind(unlock_method(dpapi_key))
        .bind(dpapi_key)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// SS-04: a new data key. The master-password copy, the DPAPI copy (`None` leaves the vault
    /// without one) and every item's ciphertext change in one transaction, so the vault is never half
    /// under one key and half under the other. `items` must hold every item: a count that differs (an
    /// item added since they were read) rolls everything back.
    pub(crate) async fn rotate_vault_key(
        &self,
        ctx: &Context,
        kdf_salt: &[u8],
        kdf_params: &KdfParams,
        wrapped_key: &[u8],
        dpapi_key: Option<&[u8]>,
        items: &[(SecretId, [u8; 12], Vec<u8>)],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_items WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
        if usize::try_from(count).ok() != Some(items.len()) {
            return Err(CoreError::Vault(
                "the vault changed while its key was being replaced; nothing was changed, try again".into(),
            ));
        }
        let now = now_rfc3339();
        sqlx::query(
            "UPDATE vault_meta SET kdf_salt = ?, kdf_params = ?, wrapped_key = ?, unlock_method = ?, dpapi_key = ?,
                                   user_id = ?, updated_at = ?
             WHERE workspace_id = ?",
        )
        .bind(kdf_salt)
        .bind(serde_json::to_string(kdf_params)?)
        .bind(wrapped_key)
        .bind(unlock_method(dpapi_key))
        .bind(dpapi_key)
        .bind(ctx.user_id.to_string())
        .bind(&now)
        .bind(ctx.workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
        for (id, nonce, ciphertext) in items {
            // `updated_at` stays: the secret's value did not change, only the key it is sealed with.
            let done =
                sqlx::query("UPDATE vault_items SET nonce = ?, ciphertext = ? WHERE workspace_id = ? AND id = ?")
                    .bind(&nonce[..])
                    .bind(ciphertext)
                    .bind(ctx.workspace_id.to_string())
                    .bind(id.0.to_string())
                    .execute(&mut *tx)
                    .await?;
            if done.rows_affected() != 1 {
                return Err(CoreError::Vault(
                    "the vault changed while its key was being replaced; nothing was changed, try again".into(),
                ));
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Every item's ciphertext, for a new data key.
    pub(crate) async fn vault_ciphers(&self, ctx: &Context) -> Result<Vec<(SecretId, VaultCipher)>> {
        let rows = sqlx::query("SELECT id, kind, label, nonce, ciphertext FROM vault_items WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                let id: String = r.try_get("id")?;
                Ok((
                    SecretId(super::parse_uuid(&id)?),
                    VaultCipher {
                        kind: kind_of(r)?,
                        label: r.try_get("label")?,
                        nonce: r.try_get("nonce")?,
                        ciphertext: r.try_get("ciphertext")?,
                    },
                ))
            })
            .collect()
    }

    /// SS-04: after a vault change, the write-ahead log is folded into the database file and emptied
    /// ([`Store::checkpoint`]), so an old wrapped key or ciphertext does not linger in `-wal` (secure_delete
    /// overwrites the pages in the file itself). Best effort: a busy reader only delays it.
    pub(crate) async fn vault_checkpoint(&self) {
        if let Err(err) = self.checkpoint().await {
            tracing::warn!(error = %err, "could not checkpoint the database after a vault change");
        }
    }

    /// SS-04, AP-06: whether `secret` already goes to the place `host`, `port` and `jump` describe: a saved
    /// session there (other than `except`) logs in with it, gives it to sudo as a container host, or was
    /// allowed to use it.
    pub(crate) async fn secret_allowed_at(
        &self,
        ctx: &Context,
        secret: SecretId,
        host: &str,
        port: u16,
        jump: Option<Uuid>,
        except: Option<Uuid>,
    ) -> Result<bool> {
        let secret = secret.0.to_string();
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM sessions s
             WHERE s.workspace_id = ? AND s.host = ? COLLATE NOCASE AND s.port = ? AND s.jump_session_id IS ?
               AND s.id != ?
               AND ((s.auth_method = 'password' AND s.credential_id = ?)
                    OR EXISTS (SELECT 1 FROM container_hosts c
                               WHERE c.session_id = s.id AND c.sudo = 'password' AND c.sudo_password_id = ?)
                    OR EXISTS (SELECT 1 FROM session_secret_grants g WHERE g.session_id = s.id AND g.secret_id = ?))
             LIMIT 1",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(host)
        .bind(i64::from(port))
        .bind(jump.map(|j| j.to_string()))
        .bind(except.map(|id| id.to_string()).unwrap_or_default())
        .bind(&secret)
        .bind(&secret)
        .bind(&secret)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    /// SS-04, AP-06: the vault passwords a saved session sends to its host: its login password, its
    /// container marks' sudo passwords and the ones it was allowed to use.
    pub(crate) async fn session_sent_secrets(&self, ctx: &Context, session_id: Uuid) -> Result<Vec<SecretId>> {
        let session = session_id.to_string();
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT credential_id FROM sessions
             WHERE workspace_id = ? AND id = ? AND auth_method = 'password' AND credential_id IS NOT NULL
             UNION
             SELECT sudo_password_id FROM container_hosts
             WHERE workspace_id = ? AND session_id = ? AND sudo = 'password' AND sudo_password_id IS NOT NULL
             UNION
             SELECT secret_id FROM session_secret_grants WHERE workspace_id = ? AND session_id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(&session)
        .bind(ctx.workspace_id.to_string())
        .bind(&session)
        .bind(ctx.workspace_id.to_string())
        .bind(&session)
        .fetch_all(&self.pool)
        .await?;
        ids.iter().map(|id| Ok(SecretId(super::parse_uuid(id)?))).collect()
    }

    /// SS-04, AP-06: lets a saved session use a vault password from now on. False when it already could.
    pub(crate) async fn grant_secret(&self, ctx: &Context, session_id: Uuid, secret: SecretId) -> Result<bool> {
        let done = sqlx::query(
            "INSERT OR IGNORE INTO session_secret_grants (workspace_id, user_id, session_id, secret_id, granted_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(session_id.to_string())
        .bind(secret.0.to_string())
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Every secret's label and kind, by label, with the number of sessions using it (logging in with it,
    /// giving it to sudo, or allowed to use it).
    pub async fn vault_items(&self, ctx: &Context) -> Result<Vec<SecretMeta>> {
        let rows = sqlx::query(
            "SELECT v.id, v.kind, v.label, v.created_at, v.updated_at,
                    (SELECT COUNT(*) FROM sessions s
                     WHERE s.credential_id = v.id OR s.key_passphrase_id = v.id
                        OR EXISTS (SELECT 1 FROM container_hosts c
                                   WHERE c.session_id = s.id AND c.sudo_password_id = v.id)
                        OR EXISTS (SELECT 1 FROM session_secret_grants g
                                   WHERE g.session_id = s.id AND g.secret_id = v.id)) AS used_by
             FROM vault_items v WHERE v.workspace_id = ? ORDER BY v.label COLLATE NOCASE",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let id: String = r.try_get("id")?;
                Ok(SecretMeta {
                    id: SecretId(super::parse_uuid(&id)?),
                    kind: kind_of(r)?,
                    label: r.try_get("label")?,
                    used_by: r.try_get("used_by")?,
                    created_at: r.try_get("created_at")?,
                    updated_at: r.try_get("updated_at")?,
                })
            })
            .collect()
    }

    /// Whether another secret has this label (letter case ignored).
    pub(crate) async fn vault_label_taken(&self, ctx: &Context, label: &str, except: Option<SecretId>) -> Result<bool> {
        let taken: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vault_items WHERE workspace_id = ? AND label = ? COLLATE NOCASE AND id != ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(label)
        .bind(except.map(|id| id.0.to_string()).unwrap_or_default())
        .fetch_optional(&self.pool)
        .await?;
        Ok(taken.is_some())
    }

    pub(crate) async fn insert_vault_item(
        &self,
        ctx: &Context,
        id: Uuid,
        kind: SecretKind,
        label: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO vault_items (id, workspace_id, user_id, kind, label, nonce, ciphertext, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(kind.as_str())
        .bind(label)
        .bind(nonce)
        .bind(ciphertext)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn vault_item_cipher(&self, ctx: &Context, id: SecretId) -> Result<Option<VaultCipher>> {
        let row =
            sqlx::query("SELECT kind, label, nonce, ciphertext FROM vault_items WHERE workspace_id = ? AND id = ?")
                .bind(ctx.workspace_id.to_string())
                .bind(id.0.to_string())
                .fetch_optional(&self.pool)
                .await?;
        row.map(|r| -> Result<_> {
            Ok(VaultCipher {
                kind: kind_of(&r)?,
                label: r.try_get("label")?,
                nonce: r.try_get("nonce")?,
                ciphertext: r.try_get("ciphertext")?,
            })
        })
        .transpose()
    }

    /// The kind of a secret in this workspace, if there is one with that id.
    pub async fn vault_item_kind(&self, ctx: &Context, id: SecretId) -> Result<Option<SecretKind>> {
        let row = sqlx::query("SELECT kind FROM vault_items WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(kind_of).transpose()
    }

    /// CT-01: a secret's label (never its value), if there is one with that id.
    pub(crate) async fn vault_item_label(&self, ctx: &Context, id: SecretId) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT label FROM vault_items WHERE workspace_id = ? AND id = ?")
                .bind(ctx.workspace_id.to_string())
                .bind(id.0.to_string())
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// A new value for a secret. The public half saved for a private key (SS-09) no longer matches,
    /// so it is dropped and read again from the new key when needed.
    pub(crate) async fn update_vault_item_cipher(
        &self,
        ctx: &Context,
        id: SecretId,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query(
            "UPDATE vault_items SET nonce = ?, ciphertext = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(nonce)
        .bind(ciphertext)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM ssh_keys WHERE workspace_id = ? AND secret_id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(done.rows_affected() > 0)
    }

    pub(crate) async fn rename_vault_item(&self, ctx: &Context, id: SecretId, label: &str) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE vault_items SET label = ?, user_id = ?, updated_at = ? WHERE workspace_id = ? AND id = ?",
        )
        .bind(label)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.0.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Sessions that used it lose it (the foreign keys set NULL).
    pub(crate) async fn delete_vault_item(&self, ctx: &Context, id: SecretId) -> Result<bool> {
        let done = sqlx::query("DELETE FROM vault_items WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}
