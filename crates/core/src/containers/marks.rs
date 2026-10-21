//! CT-01: which saved sessions are container hosts, with which engines, and how each engine's CLI runs
//! (as the login user, or under sudo). The app's own data: edits are audited like session edits, the
//! read-only lock refuses them, and FD-07 carries them between laptops.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::containers::EngineKind;
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretId, SecretKind};

/// How sudo runs a host's engine (BX-07's sudo, as Compare uses it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SudoMode {
    /// As the login user: in the `docker` group, or rootless Podman.
    #[default]
    Off,
    /// `sudo -S` with a password on stdin: this vault item, or the session's login password (`None`).
    Password {
        #[serde(default)]
        password_id: Option<SecretId>,
    },
    /// `sudo -n`: sudoers lets the user in without a password.
    NoPassword,
}

impl SudoMode {
    pub fn uses_sudo(self) -> bool {
        !matches!(self, SudoMode::Off)
    }
}

/// One engine on one marked session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerMark {
    pub session_id: Uuid,
    pub engine: EngineKind,
    #[serde(default)]
    pub sudo: SudoMode,
}

/// What the UI sends for one engine of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkInput {
    pub engine: EngineKind,
    #[serde(default)]
    pub sudo: SudoMode,
}

/// The marks in the store. The [`super::Containers`] service and FD-07's import both edit them here.
#[derive(Clone)]
pub struct ContainerMarks {
    store: Store,
}

impl ContainerMarks {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub async fn list(&self, ctx: &Context, session_id: Option<Uuid>) -> Result<Vec<ContainerMark>> {
        self.store.container_marks(ctx, session_id).await
    }

    /// Replaces a session's engines (none: it is no container host any more). Each engine once; a chosen
    /// sudo password must be a password in the vault. Audited with what changed; no change, no entry.
    pub async fn set(&self, ctx: &Context, session_id: Uuid, inputs: &[MarkInput]) -> Result<Vec<ContainerMark>> {
        self.save(ctx, session_id, inputs, None).await
    }

    /// FD-07: the marks of a session imported from another laptop. `source` names where they came from.
    pub async fn restore(
        &self,
        ctx: &Context,
        session_id: Uuid,
        inputs: &[MarkInput],
        source: &str,
    ) -> Result<Vec<ContainerMark>> {
        self.save(ctx, session_id, inputs, Some(source)).await
    }

    async fn save(
        &self,
        ctx: &Context,
        session_id: Uuid,
        inputs: &[MarkInput],
        source: Option<&str>,
    ) -> Result<Vec<ContainerMark>> {
        self.store.read_only().check(Change::ContainerHosts)?;
        let session = self
            .store
            .get_session(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
        let mut after: Vec<ContainerMark> = Vec::new();
        for input in inputs {
            if after.iter().any(|m| m.engine == input.engine) {
                return Err(CoreError::InvalidInput(format!(
                    "{} is listed twice for '{}'.",
                    input.engine.label(),
                    session.name
                )));
            }
            if let SudoMode::Password { password_id: Some(id) } = input.sudo {
                match self.store.vault_item_kind(ctx, id).await? {
                    Some(SecretKind::Password) => {}
                    Some(other) => {
                        return Err(CoreError::InvalidInput(format!(
                            "sudo needs a password, and that vault item is a {}.",
                            other.label()
                        )))
                    }
                    None => return Err(CoreError::InvalidInput("The sudo password is not in the vault.".into())),
                }
            }
            after.push(ContainerMark {
                session_id,
                engine: input.engine,
                sudo: input.sudo,
            });
        }
        after.sort_by_key(|m| m.engine);
        let before = self.list(ctx, Some(session_id)).await?;
        let changed = self.changes(ctx, &before, &after).await?;
        if changed.is_empty() {
            return Ok(before);
        }
        self.store.replace_container_marks(ctx, session_id, &after).await?;
        let action = match (source, before.is_empty(), after.is_empty()) {
            (Some(_), _, _) => format!("Imported the container engines of '{}'", session.name),
            (None, true, false) => format!("Marked '{}' as a container host", session.name),
            (None, false, true) => format!("Removed '{}' from the container hosts", session.name),
            (None, _, _) => format!("Changed the container engines of '{}'", session.name),
        };
        let mut detail = changed.join("; ");
        if let Some(source) = source {
            detail.push_str(&format!("; from {source}"));
        }
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action: &action,
                    tier: None,
                    job_id: None,
                    targets: &[session.target()],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        self.list(ctx, Some(session_id)).await
    }

    /// How a mark's sudo reads in the audit log and the UI. Vault items by label, never their value.
    pub async fn describe_sudo(&self, ctx: &Context, sudo: SudoMode) -> Result<String> {
        Ok(match sudo {
            SudoMode::Off => "as the login user".to_owned(),
            SudoMode::NoPassword => "with sudo, no password".to_owned(),
            SudoMode::Password { password_id: None } => "with sudo (the login password)".to_owned(),
            SudoMode::Password { password_id: Some(id) } => {
                let label = self.store.vault_item_label(ctx, id).await?;
                match label {
                    Some(label) => format!("with sudo (vault password '{label}')"),
                    None => "with sudo (a vault password that is gone: the login password)".to_owned(),
                }
            }
        })
    }

    async fn changes(&self, ctx: &Context, before: &[ContainerMark], after: &[ContainerMark]) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for mark in after {
            match before.iter().find(|m| m.engine == mark.engine) {
                None => out.push(format!(
                    "{} added, {}",
                    mark.engine.label(),
                    self.describe_sudo(ctx, mark.sudo).await?
                )),
                Some(old) if old.sudo != mark.sudo => out.push(format!(
                    "{}: {} -> {}",
                    mark.engine.label(),
                    self.describe_sudo(ctx, old.sudo).await?,
                    self.describe_sudo(ctx, mark.sudo).await?
                )),
                Some(_) => {}
            }
        }
        for mark in before {
            if !after.iter().any(|m| m.engine == mark.engine) {
                out.push(format!("{} removed", mark.engine.label()));
            }
        }
        Ok(out)
    }
}
