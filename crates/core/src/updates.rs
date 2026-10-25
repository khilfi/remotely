//! FD-14: update checks from the repository's GitHub Releases, which are public, with an optional
//! read-only GitHub update token kept in the vault.
//!
//! * Without a token, or with the vault locked, a check reads the public releases without one. If
//!   GitHub doesn't show them (the repository went private again), the check says a token is needed,
//!   or that the vault holds one but is locked ([`UpdateCheck`]), instead of failing quietly.
//! * With a token (it has a higher API limit, and reads a private repository), every check and
//!   install uses it, as while the repository was private from 0.2.0 to 0.4.0.
//! * A used-up API limit is a state of its own ([`UpdateCheck::RateLimited`]): no call goes to GitHub
//!   until the time it named.
//! * The token is a vault secret ([`UPDATE_TOKEN_LABEL`]), so it is encrypted at rest and readable
//!   only while the vault is unlocked. Settings keep its id and the expiry date GitHub reports, never
//!   the value. The UI can store, replace, test and remove it, never read it back.
//! * Saving, replacing and removing the token are audited like other vault changes, without the value.

use serde::Serialize;

use crate::adapters::github::clean_token;
use crate::adapters::updater::{TokenReport, UpdateInfo};
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretId, SecretKind, SecretString, Vault};
use crate::Core;

/// The token's label in the vault.
pub const UPDATE_TOKEN_LABEL: &str = "GitHub update token";
/// Setting: the token's vault id.
pub const UPDATE_TOKEN_KEY: &str = "updates.tokenId";
/// Setting: when the token expires (`YYYY-MM-DD`), from GitHub's last answer.
pub const UPDATE_TOKEN_EXPIRES_KEY: &str = "updates.tokenExpiresOn";

/// What Settings shows about the token. Never the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTokenInfo {
    /// A token is in the vault.
    pub stored: bool,
    /// When it expires (`YYYY-MM-DD`), as GitHub last reported it. `None` before it was first used,
    /// and for a token with no expiry.
    pub expires_on: Option<String>,
}

/// What an update check found, or why it found nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum UpdateCheck {
    /// Update checks are turned off in Settings.
    Off,
    /// GitHub doesn't show the releases without a token (the repository is private again), and there
    /// is none in the vault.
    TokenNeeded {
        /// `owner/name`.
        repository: String,
    },
    /// GitHub doesn't show the releases without a token, and the token is in the vault, which is
    /// locked. The UI checks again once it is unlocked.
    VaultLocked,
    /// GitHub's API limit is used up. No call goes to GitHub before `until`.
    #[serde(rename_all = "camelCase")]
    RateLimited {
        /// RFC 3339, UTC.
        until: String,
        /// The token's limit, not the one for calls without a token.
        with_token: bool,
    },
    UpToDate,
    Available {
        update: UpdateInfo,
    },
}

/// The token as the vault holds it.
pub(crate) enum StoredToken {
    Missing,
    Locked,
    Present(SecretString),
}

impl StoredToken {
    /// For Settings' Test: the token, or why there is none.
    pub(crate) fn require(self) -> Result<SecretString> {
        match self {
            StoredToken::Present(token) => Ok(token),
            StoredToken::Locked => Err(CoreError::VaultLocked),
            StoredToken::Missing => Err(CoreError::UpdateTokenMissing),
        }
    }

    /// For checking and installing: the token when it can be read, else `None` to go without one.
    pub(crate) fn usable(&self) -> Option<&SecretString> {
        match self {
            StoredToken::Present(token) => Some(token),
            StoredToken::Locked | StoredToken::Missing => None,
        }
    }

    /// GitHub didn't show the releases without a token: with the token in the locked vault, that
    /// means unlocking it.
    pub(crate) fn explain(&self, err: CoreError) -> CoreError {
        match (self, err) {
            (StoredToken::Locked, CoreError::UpdateTokenNeeded { .. }) => CoreError::VaultLocked,
            (_, err) => err,
        }
    }
}

/// The token's vault id, when it is still in the vault (it can be deleted on the Vault page).
async fn token_id(store: &Store, vault: &dyn Vault, ctx: &Context) -> Result<Option<SecretId>> {
    let Some(id) = store
        .get_setting::<Option<SecretId>>(ctx, UPDATE_TOKEN_KEY)
        .await?
        .flatten()
    else {
        return Ok(None);
    };
    let listed = vault.list(ctx).await?;
    Ok(listed.iter().any(|m| m.id == id).then_some(id))
}

/// Reads the token from the vault. Shared by update checks and the `AppUpdate` job.
pub(crate) async fn stored_token(store: &Store, vault: &dyn Vault, ctx: &Context) -> Result<StoredToken> {
    let Some(id) = token_id(store, vault, ctx).await? else {
        return Ok(StoredToken::Missing);
    };
    match vault.get(ctx, id).await {
        Ok(token) => Ok(StoredToken::Present(token)),
        Err(CoreError::VaultLocked) => Ok(StoredToken::Locked),
        Err(CoreError::UnknownTarget(_)) => Ok(StoredToken::Missing),
        Err(err) => Err(err),
    }
}

impl Core {
    /// FD-14: a read, so it skips the bus. Installing is [`crate::command_bus::Command::AppUpdate`].
    /// With checks off it makes no network call. With the token readable it asks GitHub with it,
    /// else without one.
    pub async fn check_for_update(&self) -> Result<UpdateCheck> {
        if !self.update_checks_enabled().await? {
            return Ok(UpdateCheck::Off);
        }
        let stored = stored_token(&self.store, self.vault.vault().as_ref(), &self.ctx).await?;
        let token = stored.usable();
        let checked = match self.updater.check(token).await {
            Ok(checked) => checked,
            Err(CoreError::UpdateRateLimited { until, with_token }) => {
                return Ok(UpdateCheck::RateLimited { until, with_token });
            }
            Err(CoreError::UpdateTokenNeeded { repo }) => {
                return Ok(match stored {
                    StoredToken::Locked => UpdateCheck::VaultLocked,
                    _ => UpdateCheck::TokenNeeded { repository: repo },
                });
            }
            Err(err) => return Err(self.explain_token_error(err).await),
        };
        // Only an answer to the token says when it expires.
        if token.is_some() {
            self.remember_expiry(checked.token_expires_on).await?;
        }
        Ok(match checked.update {
            Some(update) => UpdateCheck::Available { update },
            None => UpdateCheck::UpToDate,
        })
    }

    /// FD-14: whether a token is stored, and when it expires.
    pub async fn update_token_info(&self) -> Result<UpdateTokenInfo> {
        let stored = token_id(&self.store, self.vault.vault().as_ref(), &self.ctx)
            .await?
            .is_some();
        let expires_on = match stored {
            true => self.saved_expiry().await?,
            false => None,
        };
        Ok(UpdateTokenInfo { stored, expires_on })
    }

    /// FD-14: saves the token in the vault, replacing the one there. Needs the vault unlocked.
    /// Audited without the value.
    pub async fn set_update_token(&self, token: SecretString) -> Result<UpdateTokenInfo> {
        self.store.read_only().check(Change::Settings)?;
        let token = clean_token(&token)?;
        let vault = self.vault.vault();
        let action = match token_id(&self.store, vault.as_ref(), &self.ctx).await? {
            Some(id) => {
                vault.replace(&self.ctx, id, token).await?;
                "Replaced the GitHub update token in the vault"
            }
            None => {
                let id = vault
                    .put(&self.ctx, SecretKind::Password, UPDATE_TOKEN_LABEL, token)
                    .await?;
                self.store.put_setting(&self.ctx, UPDATE_TOKEN_KEY, &Some(id)).await?;
                "Saved the GitHub update token in the vault"
            }
        };
        // GitHub reports the new token's expiry on its first use.
        self.remember_expiry(None).await?;
        self.audit_token(action).await?;
        self.update_token_info().await
    }

    /// FD-14: deletes the token from the vault. Update checks then go without one. Audited.
    pub async fn remove_update_token(&self) -> Result<UpdateTokenInfo> {
        self.store.read_only().check(Change::Settings)?;
        let vault = self.vault.vault();
        if let Some(id) = token_id(&self.store, vault.as_ref(), &self.ctx).await? {
            vault.delete(&self.ctx, id).await?;
            self.audit_token("Removed the GitHub update token from the vault")
                .await?;
        }
        self.store
            .put_setting(&self.ctx, UPDATE_TOKEN_KEY, &None::<SecretId>)
            .await?;
        self.remember_expiry(None).await?;
        self.update_token_info().await
    }

    /// FD-14: Settings' "Test": asks GitHub whether the stored token can read the releases. A read;
    /// works with update checks turned off, since the user asked.
    pub async fn test_update_token(&self) -> Result<TokenReport> {
        let token = stored_token(&self.store, self.vault.vault().as_ref(), &self.ctx)
            .await?
            .require()?;
        match self.updater.test_token(&token).await {
            Ok(report) => {
                self.remember_expiry(report.expires_on.clone()).await?;
                Ok(report)
            }
            Err(err) => Err(self.explain_token_error(err).await),
        }
    }

    async fn saved_expiry(&self) -> Result<Option<String>> {
        Ok(self
            .store
            .get_setting::<Option<String>>(&self.ctx, UPDATE_TOKEN_EXPIRES_KEY)
            .await?
            .flatten())
    }

    async fn remember_expiry(&self, expires_on: Option<String>) -> Result<()> {
        if self.saved_expiry().await? != expires_on {
            self.store
                .put_setting(&self.ctx, UPDATE_TOKEN_EXPIRES_KEY, &expires_on)
                .await?;
        }
        Ok(())
    }

    /// A refused token whose remembered expiry date has passed has expired; say so.
    pub(crate) async fn explain_token_error(&self, err: CoreError) -> CoreError {
        let CoreError::UpdateTokenRefused { .. } = err else {
            return err;
        };
        let expired_on = match self.saved_expiry().await {
            Ok(Some(date)) if date.as_str() < today().as_str() => Some(date),
            _ => None,
        };
        CoreError::UpdateTokenRefused { expired_on }
    }

    async fn audit_token(&self, action: &str) -> Result<()> {
        self.store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event: "vault_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some("FD-14: read-only token for update checks"),
                },
            )
            .await
            .map(drop)
    }
}

/// Today in UTC, `YYYY-MM-DD`, like the dates GitHub reports.
fn today() -> String {
    now_rfc3339().chars().take(10).collect()
}
