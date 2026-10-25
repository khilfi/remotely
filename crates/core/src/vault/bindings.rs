//! SS-04, AP-06: where a vault password may go without the master password being asked again.
//!
//! An unlocked vault must not let whoever sits at the PC send any stored password to any host, for
//! instance by quick-connecting to a server of their own with a customer's password as the login. So a
//! password or passphrase from the vault goes, without asking, only where it already goes: to the
//! place (host, port and jump host) of a saved session that logs in with it, gives it to sudo as a
//! container host (CT-01), or was allowed to use it (`session_secret_grants`). Anywhere else — another
//! session, a quick connection, a Compare run's sudo, a terminal it is typed into (QL-06), a session
//! moved to another host — needs the master password first, as Critical actions do (AP-06), and for a
//! saved session the answer lets it use the secret from now on (audited `vault_secret_allowed`).
//!
//! * A secret added since the vault was last unlocked (the session editor's "new password", the Vault
//!   page) goes to its first place without asking: it is the user's own new value, not one the vault
//!   already held. Locking forgets which those were.
//! * Private keys and key passphrases are not checked: a login only signs with them on this PC, so no
//!   host ever receives them.
//! * Failed answers are audited (`vault_auth_failed`), so guessing shows.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use super::{SecretId, SecretKind, SecretString, Vault, VaultStatus};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::store::{NewAuditEntry, Store};

/// Where a secret goes when a session logs in: the host as the session names it, its port and the jump
/// host on the way (the same name can mean another machine behind another jump host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub jump: Option<Uuid>,
}

impl Destination {
    pub fn new(host: &str, port: u16, jump: Option<Uuid>) -> Self {
        Self {
            host: host.trim().to_owned(),
            port,
            jump,
        }
    }

    /// Letter case aside, the same host, port and jump host.
    pub fn same(&self, other: &Destination) -> bool {
        self.host.eq_ignore_ascii_case(&other.host) && self.port == other.port && self.jump == other.jump
    }
}

/// The checks every module that sends a vault password to a host makes first. Cloning gives another
/// handle to the same state.
#[derive(Clone)]
pub struct SecretBindings {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    vault: Arc<dyn Vault>,
    /// Secrets added since the app started and not yet given to anything.
    fresh: Mutex<HashSet<SecretId>>,
}

impl SecretBindings {
    pub fn new(store: Store, vault: Arc<dyn Vault>) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                vault,
                fresh: Mutex::default(),
            }),
        }
    }

    /// The Vault page or the session editor added `id`: its first place needs no master password.
    pub(crate) fn note_added(&self, id: SecretId) {
        locks::lock(&self.inner.fresh).insert(id);
    }

    fn take_fresh(&self, id: SecretId) -> bool {
        locks::lock(&self.inner.fresh).remove(&id)
    }

    fn is_fresh(&self, id: SecretId) -> bool {
        locks::lock(&self.inner.fresh).contains(&id)
    }

    /// SS-04: the vault locked, so whoever unlocks it next may not be who added them: secrets added
    /// before ask like any other from now on.
    pub(crate) fn forget_fresh(&self) {
        locks::lock(&self.inner.fresh).clear();
    }

    /// `ids` went somewhere: a secret added since the app started asks like any other from now on.
    pub(crate) fn settle(&self, ids: &[SecretId]) {
        let mut fresh = locks::lock(&self.inner.fresh);
        for id in ids {
            fresh.remove(id);
        }
    }

    /// Whether a password or passphrase the host would receive. Keys never leave this PC; an id the
    /// vault doesn't have is left to the caller's own check.
    pub(crate) async fn reaches_hosts(&self, ctx: &Context, id: SecretId) -> Result<bool> {
        Ok(matches!(
            self.inner.store.vault_item_kind(ctx, id).await?,
            Some(SecretKind::Password | SecretKind::Passphrase)
        ))
    }

    /// Whether `secret` already goes to `place`, through a saved session other than `except`.
    pub async fn goes_to(
        &self,
        ctx: &Context,
        secret: SecretId,
        place: &Destination,
        except: Option<Uuid>,
    ) -> Result<bool> {
        self.inner
            .store
            .secret_allowed_at(ctx, secret, &place.host, place.port, place.jump, except)
            .await
    }

    /// Whether `secret` may go to `place` without asking: it already goes there, or it was added since
    /// the app started and goes nowhere yet. The caller [`Self::settle`]s it once it is given, so the
    /// next new place asks.
    pub async fn may_go(
        &self,
        ctx: &Context,
        secret: SecretId,
        place: &Destination,
        except: Option<Uuid>,
    ) -> Result<bool> {
        if self.is_fresh(secret) || !self.reaches_hosts(ctx, secret).await? {
            return Ok(true);
        }
        self.goes_to(ctx, secret, place, except).await
    }

    /// The vault passwords a saved session sends to its host now.
    pub(crate) async fn sent_by(&self, ctx: &Context, session_id: Uuid) -> Result<Vec<SecretId>> {
        self.inner.store.session_sent_secrets(ctx, session_id).await
    }

    /// AP-06: checks the master password before a step that needs it. `None` (or empty) asks for it with
    /// `reason`; a wrong one is audited under `action` and refused. Works locked or unlocked.
    pub async fn confirm(
        &self,
        ctx: &Context,
        password: Option<&SecretString>,
        action: &str,
        reason: &str,
    ) -> Result<()> {
        // No vault, no password to ask for (as for Critical actions): set it up first.
        if self.inner.vault.status() == VaultStatus::NotSetUp {
            return Err(CoreError::VaultNotSetUp);
        }
        let Some(password) = password.filter(|p| !p.is_empty()) else {
            return Err(CoreError::ReauthRequired {
                reason: reason.to_owned(),
            });
        };
        if self.inner.vault.verify_password(password).await? {
            return Ok(());
        }
        self.audit(ctx, "vault_auth_failed", action, "wrong vault password", &[])
            .await?;
        Err(CoreError::WrongVaultPassword)
    }

    /// Lets a saved session use `secret` from now on, after the master password was given. Audited when
    /// it is new.
    pub async fn allow(&self, ctx: &Context, session_id: Uuid, session_name: &str, secret: SecretId) -> Result<()> {
        self.take_fresh(secret);
        if !self.inner.store.grant_secret(ctx, session_id, secret).await? {
            return Ok(());
        }
        let action = format!(
            "Let session '{session_name}' use the {} from now on",
            self.describe(ctx, secret).await?
        );
        let target = crate::domain::Target {
            target: crate::domain::TargetRef::Session { session_id },
            name: session_name.to_owned(),
            environment: crate::domain::Environment::None,
            protected: false,
        };
        self.audit(
            ctx,
            "vault_secret_allowed",
            &action,
            "the vault password was asked again (AP-06)",
            std::slice::from_ref(&target),
        )
        .await
    }

    /// "password 'web root'": kind and label, never the value.
    pub(crate) async fn describe(&self, ctx: &Context, secret: SecretId) -> Result<String> {
        let kind = self.inner.store.vault_item_kind(ctx, secret).await?;
        let label = self.inner.store.vault_item_label(ctx, secret).await?;
        Ok(match (kind, label) {
            (Some(kind), Some(label)) => format!("{} '{label}'", kind.label()),
            _ => "vault secret".to_owned(),
        })
    }

    async fn audit(
        &self,
        ctx: &Context,
        event: &str,
        action: &str,
        detail: &str,
        targets: &[crate::domain::Target],
    ) -> Result<()> {
        self.inner
            .store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets,
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_compare_without_letter_case() {
        let a = Destination::new("Web01.Example.com ", 22, None);
        assert!(a.same(&Destination::new("web01.example.com", 22, None)));
        assert!(!a.same(&Destination::new("web01.example.com", 2222, None)));
        assert!(!a.same(&Destination::new("web01.example.com", 22, Some(Uuid::nil()))));
    }
}
