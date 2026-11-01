//! What the UI may do with the vault (SS-04), each change audited like a setting: no approval tier,
//! since the vault is the app's own data. Labels and kinds reach the audit log, values never do.
//! Failed password checks are audited too, so guessing shows.

use std::sync::Arc;

use tokio::sync::watch;

use super::{
    SecretBindings, SecretId, SecretKind, SecretMeta, SecretString, UnlockMethod, Vault, VaultInfo, VaultStatus,
};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::login_guard::LoginGuard;
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};

pub struct VaultService {
    vault: Arc<dyn Vault>,
    store: Store,
    /// MO-02, CT-01: unlocking and changing secrets give parked background logins one more try.
    guard: Option<LoginGuard>,
    /// SS-04, AP-06: a secret added here goes to its first place without the master password.
    bindings: Option<SecretBindings>,
}

impl VaultService {
    pub fn new(vault: Arc<dyn Vault>, store: Store) -> Self {
        Self {
            vault,
            store,
            guard: None,
            bindings: None,
        }
    }

    pub fn with_bindings(mut self, bindings: SecretBindings) -> Self {
        self.bindings = Some(bindings);
        self
    }

    /// SS-04: the user typed, clicked or started something; the idle lock counts from now.
    pub fn note_activity(&self) {
        self.vault.note_activity();
    }

    pub fn with_login_guard(mut self, guard: LoginGuard) -> Self {
        self.guard = Some(guard);
        self
    }

    /// A secret was added: parked logins get one more try, but no account gate is reopened (an unrelated new secret is
    /// not a changed password).
    fn credentials_changed(&self) {
        if let Some(guard) = &self.guard {
            guard.credentials_changed();
        }
    }

    /// A secret was replaced or deleted: also reopen the WinRM account gates that use it, so a run re-verifies it.
    fn secret_changed(&self, id: SecretId) {
        if let Some(guard) = &self.guard {
            guard.secret_changed(id);
        }
    }

    /// The vault was unlocked: also reopen every WinRM account gate.
    fn vault_unlocked(&self) {
        if let Some(guard) = &self.guard {
            guard.vault_unlocked();
        }
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

    /// `windows_login` is off unless the user turns it on: a DPAPI copy of the key opens the vault for any
    /// program running as this Windows user, without the master password.
    pub async fn setup(&self, ctx: &Context, password: SecretString, windows_login: bool) -> Result<VaultInfo> {
        self.store.read_only().check(Change::Vault)?;
        self.vault.setup(ctx, password, windows_login).await?;
        let detail = if windows_login {
            "unlocks with the Windows login or the vault password"
        } else {
            "unlocks with the vault password only"
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
                self.vault_unlocked();
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
                self.audit(
                    ctx,
                    "vault_changed",
                    "Changed the vault password",
                    Some("a new data key; every secret was sealed with it again"),
                )
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

    /// SS-04: the Windows login stops unlocking the vault; its DPAPI copy of the key is deleted and
    /// overwritten on disk. One click, no password: it only removes a way in. Audited when it was on.
    pub async fn turn_off_windows_login(&self, ctx: &Context) -> Result<VaultInfo> {
        self.store.read_only().check(Change::Vault)?;
        if self.vault.turn_off_windows_login().await? {
            self.audit(
                ctx,
                "vault_changed",
                "Stopped the Windows login from unlocking the vault",
                Some("the vault password unlocks it from now on; its Windows-protected key was deleted"),
            )
            .await?;
        }
        Ok(self.info())
    }

    pub async fn list(&self, ctx: &Context) -> Result<Vec<SecretMeta>> {
        self.vault.list(ctx).await
    }

    pub async fn add(&self, ctx: &Context, kind: SecretKind, label: &str, secret: SecretString) -> Result<SecretMeta> {
        self.store.read_only().check(Change::Vault)?;
        let id = self.vault.put(ctx, kind, label, secret).await?;
        if let Some(bindings) = &self.bindings {
            bindings.note_added(id);
        }
        self.credentials_changed();
        let meta = self.meta(ctx, id).await?;
        let action = format!("Added the {} '{}' to the vault", kind.label(), meta.label);
        self.audit(ctx, "vault_changed", &action, None).await?;
        Ok(meta)
    }

    pub async fn replace(&self, ctx: &Context, id: SecretId, secret: SecretString) -> Result<SecretMeta> {
        self.store.read_only().check(Change::Vault)?;
        self.vault.replace(ctx, id, secret).await?;
        self.secret_changed(id);
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
        self.secret_changed(id);
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
