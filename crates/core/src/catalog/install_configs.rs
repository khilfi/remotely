//! VM-28: the catalogue's install configs (`Core.catalog`): the starters and the workspace's own, each checked; the
//! editor's live check, form and masked preview; and the edits, audited `catalog_changed` with no tier, refused by the
//! read-only lock, deletes to the trash (QL-27). A config never holds a secret, so neither does its audit entry: the
//! file is named by its SHA-256.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::install::{self, starters, CheckFacts, ConfigCheck, InstallConfig, InstallConfigInput, SecretRefKind};
use super::{invalid, Catalog};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::InstallConfigRow;
use crate::trash::TrashKind;
use crate::vault::SecretKind;

/// The VM a preview renders for: what the editor or the deploy dialog fills in; the rest takes samples.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewVm {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub n: Option<u32>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

/// A check off the runtime's threads: a 256 KB file can take a while to read (review of #88).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| CoreError::InvalidInput(format!("the install config couldn't be checked: {err}")))
}

fn body_hash(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

fn describe(spec: &InstallConfigInput) -> String {
    let picked = spec.secrets.iter().filter(|s| s.secret_id.is_some()).count();
    let variables: Vec<&str> = spec.variables.iter().map(|v| v.name.as_str()).collect();
    format!(
        "{}; file {} bytes, SHA-256 {}; variables {}; vault items picked {picked} of {}",
        spec.kind.label(),
        spec.body.len(),
        body_hash(&spec.body),
        if variables.is_empty() {
            "none".to_owned()
        } else {
            variables.join(", ")
        },
        spec.secrets.len()
    )
}

fn changes(before: &InstallConfigInput, after: &InstallConfigInput) -> Vec<String> {
    let mut out = Vec::new();
    if before.name != after.name {
        out.push(format!("renamed to '{}'", after.name));
    }
    if before.kind != after.kind {
        out.push(format!("kind {} -> {}", before.kind.label(), after.kind.label()));
    }
    if before.body != after.body {
        out.push(format!("file changed (SHA-256 {})", body_hash(&after.body)));
    }
    if before.variables != after.variables {
        let names: Vec<&str> = after.variables.iter().map(|v| v.name.as_str()).collect();
        out.push(format!(
            "variables -> {}",
            if names.is_empty() {
                "none".to_owned()
            } else {
                names.join(", ")
            }
        ));
    }
    if before.secrets != after.secrets {
        out.push("vault picks changed".into());
    }
    if before.notes != after.notes {
        out.push("notes changed".into());
    }
    out
}

impl Catalog {
    /// What a check needs of the vault (ids only) and, when asked, a size's boot disk.
    pub(crate) async fn check_facts(&self, ctx: &Context, size_id: Option<&str>) -> Result<CheckFacts> {
        let items = self.store.vault_items(ctx).await?;
        let read = self.store.ssh_key_rows(ctx).await?;
        let mut facts = CheckFacts::default();
        for item in items {
            match item.kind {
                SecretKind::Password => {
                    facts.passwords.insert(item.id);
                }
                SecretKind::PrivateKey => {
                    facts
                        .keys
                        .insert(item.id, read.get(&item.id).map(|k| k.public.line.clone()));
                }
                SecretKind::Passphrase => {}
            }
        }
        if let Some(id) = size_id.map(str::trim).filter(|s| !s.is_empty()) {
            let size = self.size(ctx, id).await?;
            let boot = size.disks.first().map_or(0, |d| d.size_gb);
            facts.size = Some((size.name, boot));
        }
        Ok(facts)
    }

    fn checked(row: InstallConfigRow, facts: &CheckFacts) -> InstallConfig {
        let problems = install::check(&row.spec, facts);
        let disk_need_mb = install::sample_text(&row.spec)
            .ok()
            .and_then(|t| install::disk_need(row.spec.kind, &t));
        InstallConfig {
            id: row.id.to_string(),
            built_in: false,
            spec: row.spec,
            created_at: Some(row.created_at),
            updated_at: Some(row.updated_at),
            problems,
            disk_need_mb,
        }
    }

    /// The workspace's own configs, by name, each checked.
    pub(crate) async fn own_install_configs(&self, ctx: &Context) -> Result<Vec<InstallConfig>> {
        let facts = self.check_facts(ctx, None).await?;
        let rows = self.store.list_install_configs(ctx).await?;
        blocking(move || rows.into_iter().map(|row| Self::checked(row, &facts)).collect()).await
    }

    /// The starters, then the workspace's own by name.
    pub async fn install_configs(&self, ctx: &Context) -> Result<Vec<InstallConfig>> {
        let mut all = starters::all();
        all.extend(self.own_install_configs(ctx).await?);
        Ok(all)
    }

    /// A starter by its id, or an own config by its UUID.
    pub async fn install_config(&self, ctx: &Context, id: &str) -> Result<InstallConfig> {
        if starters::is_starter(id) {
            return starters::all()
                .into_iter()
                .find(|c| c.id == id)
                .ok_or_else(|| CoreError::UnknownTarget(format!("install config {id}")));
        }
        let uuid = Uuid::parse_str(id.trim()).map_err(|_| CoreError::UnknownTarget(format!("install config {id}")))?;
        let row = self.config_row(ctx, uuid).await?;
        let facts = self.check_facts(ctx, None).await?;
        blocking(move || Self::checked(row, &facts)).await
    }

    async fn config_row(&self, ctx: &Context, id: Uuid) -> Result<InstallConfigRow> {
        self.store
            .install_config_row(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("install config {id}")))
    }

    /// The editor's check while the file is written: problems, the form's values, the placeholders, and (with
    /// `size_id`) whether the disk layout fits that size.
    pub async fn check_install_config(
        &self,
        ctx: &Context,
        input: &InstallConfigInput,
        size_id: Option<&str>,
    ) -> Result<ConfigCheck> {
        if input.body.len() > install::MAX_BODY_BYTES {
            return invalid("An install config's file can be at most 256 KB.");
        }
        let facts = self.check_facts(ctx, size_id).await?;
        let body = input.body.replace("\r\n", "\n");
        let spec = InstallConfigInput { body, ..input.clone() };
        blocking(move || install::check_all(&spec, &facts)).await
    }

    /// One VM's file as the editor and the deploy dialog show it: every value written and every secret masked
    /// (`$6$••••••••`); SSH keys' public halves as the vault's keys have them.
    pub async fn preview_install_config(
        &self,
        ctx: &Context,
        input: &InstallConfigInput,
        vm: &PreviewVm,
    ) -> Result<String> {
        if input.body.len() > install::MAX_BODY_BYTES {
            return invalid("An install config's file can be at most 256 KB.");
        }
        let keys = self.store.ssh_key_rows(ctx).await?;
        let public: HashMap<String, String> = input
            .secrets
            .iter()
            .filter(|s| s.kind == SecretRefKind::SshKey)
            .filter_map(|s| Some((s.name.clone(), keys.get(&s.secret_id?)?.public.line.clone())))
            .collect();
        let values = install::render::VmValues {
            hostname: vm
                .hostname
                .clone()
                .map(|h| h.trim().to_owned())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "web-1".into()),
            ip: vm.ip.clone().filter(|i| !i.trim().is_empty()),
            n: vm.n.unwrap_or(1),
            template: vm.template.clone().unwrap_or_else(|| "template".into()),
            date: super::today(),
            values: vm.values.clone(),
        };
        let spec = InstallConfigInput {
            body: input.body.replace("\r\n", "\n"),
            ..input.clone()
        };
        blocking(move || install::render::preview(&spec, &values, &public)).await?
    }

    pub async fn add_install_config(&self, ctx: &Context, input: InstallConfigInput) -> Result<InstallConfig> {
        self.store.read_only().check(Change::Catalog)?;
        self.save_install_config(ctx, None, input, "Added").await
    }

    /// Starters are read only.
    pub async fn update_install_config(
        &self,
        ctx: &Context,
        id: Uuid,
        input: InstallConfigInput,
    ) -> Result<InstallConfig> {
        self.store.read_only().check(Change::Catalog)?;
        self.save_install_config(ctx, Some(id), input, "Changed").await
    }

    /// Checks, refuses a secret written into the file, saves and audits.
    async fn save_install_config(
        &self,
        ctx: &Context,
        id: Option<Uuid>,
        input: InstallConfigInput,
        verb: &str,
    ) -> Result<InstallConfig> {
        let spec = install::check_input(&input)?;
        let facts = self.check_facts(ctx, None).await?;
        let checked = {
            let (spec, facts) = (spec.clone(), facts.clone());
            blocking(move || install::check(&spec, &facts)).await?
        };
        let secrets: Vec<String> = checked
            .into_iter()
            .filter(|p| p.blocks_saving)
            .map(|p| match p.line {
                Some(line) => format!("Line {line}: {}", p.message),
                None => p.message,
            })
            .collect();
        if !secrets.is_empty() {
            return invalid(secrets.join(" "));
        }
        // A vault pick must be a vault item of its kind, in this workspace.
        for s in &spec.secrets {
            if let Some(secret) = s.secret_id {
                let fits = match s.kind {
                    SecretRefKind::Password => facts.passwords.contains(&secret),
                    SecretRefKind::SshKey => facts.keys.contains_key(&secret),
                };
                if !fits {
                    return invalid(format!(
                        "{} names a vault item that isn't a {} here: pick another.",
                        s.placeholder().text(),
                        if s.kind == SecretRefKind::Password {
                            "password"
                        } else {
                            "private key"
                        }
                    ));
                }
            }
        }
        if starters::STARTERS
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(&spec.name))
        {
            return invalid(format!("A starter is named '{}': give yours another name.", spec.name));
        }
        let rows = self.store.list_install_configs(ctx).await?;
        if rows
            .iter()
            .any(|r| r.spec.name.eq_ignore_ascii_case(&spec.name) && Some(r.id) != id)
        {
            return invalid(format!("An install config named '{}' exists already.", spec.name));
        }
        let (id, detail) = match id {
            Some(id) => {
                let before = rows
                    .iter()
                    .find(|r| r.id == id)
                    .ok_or_else(|| CoreError::UnknownTarget(format!("install config {id}")))?;
                let changed = changes(&before.spec, &spec);
                if changed.is_empty() {
                    let (row, facts) = (before.clone(), facts.clone());
                    return blocking(move || Self::checked(row, &facts)).await;
                }
                self.store.update_install_config(ctx, id, &spec).await?;
                (id, changed.join("; "))
            }
            None => {
                if rows.len() >= install::MAX_CONFIGS {
                    return invalid(format!(
                        "A workspace keeps at most {} install configs.",
                        install::MAX_CONFIGS
                    ));
                }
                let id = Uuid::new_v4();
                self.store.insert_install_config(ctx, id, &spec).await?;
                (id, describe(&spec))
            }
        };
        self.audit(ctx, &format!("{verb} the install config '{}'", spec.name), &detail)
            .await?;
        let row = self.config_row(ctx, id).await?;
        blocking(move || Self::checked(row, &facts)).await
    }

    /// To the trash; launch templates that use it say so until they get another.
    pub async fn delete_install_config(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Catalog)?;
        let row = self.config_row(ctx, id).await?;
        let used = self.templates_using(ctx, |t| t.install_config_id == Some(id)).await?;
        self.to_trash(
            ctx,
            TrashKind::InstallConfig,
            &id.to_string(),
            &row.spec.name,
            "Templates › Install configs",
        )
        .await?;
        self.audit(
            ctx,
            &format!("Deleted the install config '{}'", row.spec.name),
            &format!("{}; {}", super::used_by(&used), super::in_trash()),
        )
        .await
    }

    /// FD-07: a config from an export, new or over `replace`, its vault picks already mapped to this laptop's (the
    /// ones that didn't come along are unpicked). Audited as imported.
    pub(crate) async fn import_install_config(
        &self,
        ctx: &Context,
        replace: Option<Uuid>,
        input: InstallConfigInput,
    ) -> Result<InstallConfig> {
        let facts = self.check_facts(ctx, None).await?;
        let mut input = input;
        for s in &mut input.secrets {
            let here = match s.kind {
                SecretRefKind::Password => s.secret_id.is_some_and(|id| facts.passwords.contains(&id)),
                SecretRefKind::SshKey => s.secret_id.is_some_and(|id| facts.keys.contains_key(&id)),
            };
            if !here {
                s.secret_id = None;
            }
        }
        let verb = if replace.is_some() { "Replaced" } else { "Imported" };
        let saved = self.save_install_config(ctx, replace, input, verb).await?;
        Ok(saved)
    }

    /// VM-28: the configs a template check reads, by id.
    pub(crate) async fn install_config_facts(&self, ctx: &Context) -> Result<Vec<InstallConfig>> {
        self.own_install_configs(ctx).await
    }

    /// Names of every config (starters' too), for FD-07's keep-both names.
    pub(crate) async fn install_config_names(&self, ctx: &Context) -> Result<HashSet<String>> {
        let mut names: HashSet<String> = starters::STARTERS.iter().map(|s| s.name.to_lowercase()).collect();
        names.extend(
            self.store
                .list_install_configs(ctx)
                .await?
                .into_iter()
                .map(|r| r.spec.name.to_lowercase()),
        );
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_audit_names_the_file_by_its_hash_and_never_its_text() {
        let spec = InstallConfigInput {
            name: "web".into(),
            kind: install::InstallKind::CloudInit,
            body: "#cloud-config\nhostname: \"{{hostname}}\"\n".into(),
            variables: vec![],
            secrets: vec![],
            notes: None,
        };
        let text = describe(&spec);
        assert!(
            text.starts_with(&format!(
                "cloud-init user data; file {} bytes, SHA-256 ",
                spec.body.len()
            )),
            "{text}"
        );
        assert!(!text.contains("hostname"), "{text}");
        let after = InstallConfigInput {
            body: "#cloud-config\n".into(),
            name: "web2".into(),
            ..spec.clone()
        };
        let c = changes(&spec, &after);
        assert_eq!(c[0], "renamed to 'web2'");
        assert!(c[1].starts_with("file changed (SHA-256 "));
        assert!(changes(&spec, &spec).is_empty());
    }
}
