//! What the UI may do with the vault (SS-04), each change audited like a setting: no approval tier,
//! since the vault is the app's own data. Labels and kinds reach the audit log, values never do.
//! Failed password checks are audited too, so guessing shows.

use std::sync::Arc;

use tokio::sync::watch;

use super::{SecretId, SecretKind, SecretMeta, SecretString, UnlockMethod, Vault, VaultInfo, VaultStatus};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};

pub struct VaultService {
    vault: Arc<dyn Vault>,
    store: Store,
}

impl VaultService {
    pub fn new(vault: Arc<dyn Vault>, store: Store) -> Self {
        Self { vault, store }
    }

    /// For the command bus (AP-06) and, from SS-03, the adapters.
    pub fn vault(&self) -> &Arc<dyn Vault> {
        &self.vault
    }

    pub fn info(&self) -> VaultInfo {
        self.vault.info()
    }

    pub fn watch(&self) -> watch::Receiver<VaultStatus> {
        self.vault.watch()
    }

    pub async fn setup(&self, ctx: &Context, password: SecretString, windows_login: bool) -> Result<VaultInfo> {
        self.store.read_only().check(Change::Vault)?;
        self.vault.setup(ctx, password, windows_login).await?;
        let detail = if windows_login {
            "unlocks with the Windows login or the vault password"
        } else {
            "unlocks with the vault password"
        };
        self.audit(ctx, "vault_changed", "Set up the vault", Some(detail))
            .await?;
        Ok(self.info())
    }

    pub async fn unlock(&self, ctx: &Context, method: UnlockMethod) -> Result<VaultInfo> {
        let how = match method {
            UnlockMethod::WindowsLogin => "with the Windows login",
            UnlockMethod::MasterPassword(_) => "with the vault password",
        };
        match self.vault.unlock(method).await {
            Ok(()) => {
                self.audit(ctx, "vault_unlocked", "Unlocked the vault", Some(how))
                    .await?;
                Ok(self.info())
            }
            Err(err) => Err(self.failed(ctx, "Failed to unlock the vault", how, err).await),
        }
    }

    /// Locks now. Audited only when it was unlocked.
    pub async fn lock(&self, ctx: &Context) -> Result<VaultInfo> {
        let was_unlocked = self.vault.status() == VaultStatus::Unlocked;
        self.vault.lock();
        if was_unlocked {
            self.audit(ctx, "vault_locked", "Locked the vault", Some("on demand"))
                .await?;
        }
        Ok(self.info())
    }

    pub async fn change_password(&self, ctx: &Context, current: &SecretString, new: SecretString) -> Result<VaultInfo> {
        self.store.read_only().check(Change::Vault)?;
        match self.vault.change_password(current, new).await {
            Ok(()) => {
                self.audit(ctx, "vault_changed", "Changed the vault password", None)
                    .await?;
                Ok(self.info())
            }
            Err(err) => Err(self.failed(ctx, "Failed to change the vault password", "", err).await),
        }
    }

    pub async fn set_windows_login(&self, ctx: &Context, password: &SecretString, enabled: bool) -> Result<VaultInfo> {
        self.store.read_only().check(Change::Vault)?;
        let action = if enabled {
            "Let the Windows login unlock the vault"
        } else {
            "Stopped the Windows login from unlocking the vault"
        };
        match self.vault.set_windows_login(password, enabled).await {
            Ok(()) => {
                self.audit(ctx, "vault_changed", action, None).await?;
                Ok(self.info())
            }
            Err(err) => Err(self.failed(ctx, &format!("Failed: {action}"), "", err).await),
        }
    }

    pub async fn list(&self, ctx: &Context) -> Result<Vec<SecretMeta>> {
        self.vault.list(ctx).await
    }

    pub async fn add(&self, ctx: &Context, kind: SecretKind, label: &str, secret: SecretString) -> Result<SecretMeta> {
        self.store.read_only().check(Change::Vault)?;
        let id = self.vault.put(ctx, kind, label, secret).await?;
        let meta = self.meta(ctx, id).await?;
        let action = format!("Added the {} '{}' to the vault", kind.label(), meta.label);
        self.audit(ctx, "vault_changed", &action, None).await?;
        Ok(meta)
    }

    pub async fn replace(&self, ctx: &Context, id: SecretId, secret: SecretString) -> Result<SecretMeta> {
        self.store.read_only().check(Change::Vault)?;
        self.vault.replace(ctx, id, secret).await?;
        let meta = self.meta(ctx, id).await?;
        let action = format!("Replaced the {} '{}'", meta.kind.label(), meta.label);
        let detail = uses(meta.used_by, "now use the new value");
        self.audit(ctx, "vault_changed", &action, detail.as_deref()).await?;
        Ok(meta)
    }

    pub async fn rename(&self, ctx: &Context, id: SecretId, label: &str) -> Result<SecretMeta> {
        self.store.read_only().check(Change::Vault)?;
        let before = self.meta(ctx, id).await?;
        self.vault.rename(ctx, id, label).await?;
        let meta = self.meta(ctx, id).await?;
        if meta.label != before.label {
            let action = format!(
                "Renamed the {} '{}' to '{}'",
                meta.kind.label(),
                before.label,
                meta.label
            );
            self.audit(ctx, "vault_changed", &action, None).await?;
        }
        Ok(meta)
    }

    /// Sessions that used it keep their other settings and lose this credential.
    pub async fn delete(&self, ctx: &Context, id: SecretId) -> Result<()> {
        self.store.read_only().check(Change::Vault)?;
        let meta = self.meta(ctx, id).await?;
        self.vault.delete(ctx, id).await?;
        let action = format!("Deleted the {} '{}' from the vault", meta.kind.label(), meta.label);
        let detail = uses(meta.used_by, "no longer have it");
        self.audit(ctx, "vault_changed", &action, detail.as_deref()).await
    }

    async fn meta(&self, ctx: &Context, id: SecretId) -> Result<SecretMeta> {
        self.vault
            .list(ctx)
            .await?
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {id}")))
    }

    /// Audits a failed password check, then hands the error back. Other failures are not audited.
    async fn failed(&self, ctx: &Context, action: &str, how: &str, err: CoreError) -> CoreError {
        if matches!(err, CoreError::WrongVaultPassword) {
            let detail = if how.is_empty() {
                err.to_string()
            } else {
                format!("{how}: {err}")
            };
            if let Err(audit_err) = self.audit(ctx, "vault_auth_failed", action, Some(&detail)).await {
                tracing::error!(error = %audit_err, "could not audit a failed vault password");
            }
        }
        err
    }

    async fn audit(&self, ctx: &Context, event: &str, action: &str, detail: Option<&str>) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail,
                },
            )
            .await
            .map(drop)
    }
}

/// "2 sessions no longer have it", or nothing when no session used it.
fn uses(count: i64, what: &str) -> Option<String> {
    match count {
        0 => None,
        1 => Some(format!("1 session: {what}")),
        n => Some(format!("{n} sessions: {what}")),
    }
}
