//! Known hosts (SS-05): the SSH host keys the user has trusted, checked on every connection.
//!
//! On the first connection to a host and port, the terminal shows the server's key fingerprint
//! (SHA-256) and asks before trusting it. A key that differs from the saved one of the same type
//! blocks the connection: the terminal warns, and only an explicit replace trusts the new key.
//! Trusting, replacing and removing keys change the app's own data, so they skip the command bus and
//! have no approval tier; each is audited, and so is every blocked connection.

use serde::Serialize;
use uuid::Uuid;

use crate::domain::{Context, Target};
use crate::error::{CoreError, Result};
use crate::store::{NewAuditEntry, Store};

/// The key a server presented, as the remote adapter saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKey {
    pub host: String,
    pub port: u16,
    /// The key's algorithm, e.g. `ssh-ed25519` or `ecdsa-sha2-nistp256`.
    pub key_type: String,
    /// `SHA256:` and the base64 digest, as OpenSSH prints it.
    pub fingerprint: String,
}

impl HostKey {
    /// `host:port`, with brackets around an IPv6 address.
    pub fn address(&self) -> String {
        address(&self.host, self.port)
    }
}

/// A saved host key (the `known_hosts` table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    pub id: Uuid,
    pub host: String,
    pub port: u16,
    pub key_type: String,
    pub fingerprint: String,
    /// When it was trusted.
    pub first_seen_at: String,
    /// The last connection that presented it.
    pub last_seen_at: String,
}

/// What the saved keys say about a presented key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum HostKeyCheck {
    Trusted,
    /// Not seen before. `other_key_types` lists the types saved for this host and port, if any: the
    /// server may have changed its keys, so the prompt says so.
    Unknown {
        other_key_types: Vec<String>,
    },
    /// The saved key of this type has another fingerprint. The connection is blocked.
    Changed {
        previous: KnownHost,
    },
}

pub(crate) fn address(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub struct KnownHosts {
    store: Store,
}

impl KnownHosts {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub async fn list(&self, ctx: &Context) -> Result<Vec<KnownHost>> {
        self.store.list_known_hosts(ctx).await
    }

    /// Compares the key with the saved ones. A trusted key's last-seen time moves on.
    pub async fn check(&self, ctx: &Context, key: &HostKey) -> Result<HostKeyCheck> {
        let saved = self.store.known_host_keys(ctx, &key.host, key.port).await?;
        match saved.iter().find(|k| k.key_type == key.key_type) {
            Some(known) if known.fingerprint == key.fingerprint => {
                self.store.touch_known_host(ctx, known.id).await?;
                Ok(HostKeyCheck::Trusted)
            }
            Some(known) => Ok(HostKeyCheck::Changed {
                previous: known.clone(),
            }),
            None => Ok(HostKeyCheck::Unknown {
                other_key_types: saved.into_iter().map(|k| k.key_type).collect(),
            }),
        }
    }

    /// Saves the key as trusted for its host and port, after the user said so. Replacing a different
    /// key of the same type is audited as a re-trust, with both fingerprints. `via`: the session the
    /// user was connecting to.
    pub async fn trust(&self, ctx: &Context, key: &HostKey, via: Option<&Target>) -> Result<()> {
        check_key(key)?;
        let saved = self.store.known_host_keys(ctx, &key.host, key.port).await?;
        let previous = saved.into_iter().find(|k| k.key_type == key.key_type);
        if previous.as_ref().is_some_and(|p| p.fingerprint == key.fingerprint) {
            return Ok(());
        }
        self.store
            .put_known_host(ctx, &key.host, key.port, &key.key_type, &key.fingerprint)
            .await?;
        let (event, action, detail) = match previous {
            None => (
                "host_key_trusted",
                format!("Trusted the host key of {}", key.address()),
                format!("{} {}", key.key_type, key.fingerprint),
            ),
            Some(previous) => (
                "host_key_retrusted",
                format!("Replaced the trusted host key of {}", key.address()),
                format!(
                    "{}: {} -> {} (trusted since {})",
                    key.key_type, previous.fingerprint, key.fingerprint, previous.first_seen_at
                ),
            ),
        };
        self.audit(ctx, event, &action, via, &detail).await
    }

    /// SS-05: audits a connection that was blocked because the host key changed.
    pub async fn record_blocked(
        &self,
        ctx: &Context,
        key: &HostKey,
        previous: &KnownHost,
        via: Option<&Target>,
    ) -> Result<()> {
        let action = format!("Blocked the connection to {}: its host key changed", key.address());
        let detail = format!(
            "{}: trusted {}, presented {}",
            key.key_type, previous.fingerprint, key.fingerprint
        );
        self.audit(ctx, "host_key_changed", &action, via, &detail).await
    }

    /// Forgets a key, so the next connection asks again.
    pub async fn remove(&self, ctx: &Context, id: Uuid) -> Result<()> {
        let known = self
            .store
            .get_known_host(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("known host {id}")))?;
        self.store.delete_known_host(ctx, id).await?;
        let action = format!("Removed the trusted host key of {}", address(&known.host, known.port));
        let detail = format!(
            "{} {} (trusted since {})",
            known.key_type, known.fingerprint, known.first_seen_at
        );
        self.audit(ctx, "host_key_removed", &action, None, &detail).await
    }

    async fn audit(&self, ctx: &Context, event: &str, action: &str, via: Option<&Target>, detail: &str) -> Result<()> {
        let targets: Vec<Target> = via.cloned().into_iter().collect();
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

/// The adapter builds keys, so these only guard against an empty row ever being saved.
fn check_key(key: &HostKey) -> Result<()> {
    if key.host.trim().is_empty() || key.key_type.trim().is_empty() || !key.fingerprint.starts_with("SHA256:") {
        return Err(CoreError::InvalidInput(
            "That host key is incomplete, so it was not saved.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_bracket_ipv6_hosts() {
        assert_eq!(address("web01.example.com", 22), "web01.example.com:22");
        assert_eq!(address("192.0.2.10", 2222), "192.0.2.10:2222");
        assert_eq!(address("2001:db8::1", 22), "[2001:db8::1]:22");
        assert_eq!(address("[2001:db8::1]", 22), "[2001:db8::1]:22");
    }

    #[test]
    fn incomplete_keys_are_refused() {
        let key = HostKey {
            host: "web01.example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: "SHA256:abc".into(),
        };
        assert!(check_key(&key).is_ok());
        assert!(check_key(&HostKey {
            fingerprint: "MD5:ab:cd".into(),
            ..key.clone()
        })
        .is_err());
        assert!(check_key(&HostKey {
            host: " ".into(),
            ..key
        })
        .is_err());
    }
}
