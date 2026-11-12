//! VM-28 install configs: the answer files an unattended install reads, as a catalogue kind beside sizes, images and
//! launch templates (`docs/plan-0.8.md`, G5). Delivering one to a VM (seeds, ISO copies, the install watcher) is G6's;
//! this module makes the configs, checks them, and renders one file per VM ([`render::render`]) for G6 to deliver.
//!
//! * Kinds ([`InstallKind`]): Ubuntu autoinstall (YAML), Kickstart (RHEL, Rocky, Alma, Oracle Linux, Fedora, CentOS
//!   Stream), Debian preseed, cloud-init user data (for cloud images, as VM-22's first boot), and Windows unattend.
//! * The file is what is saved: [`InstallConfigInput::body`], with Remotely's placeholders ([`vars`]). The editor's form
//!   is read from it and written back into it ([`read_form`], [`apply_form`]), changing only the fields that changed.
//! * [`check`]: placeholders, then the kind's own syntax and schema (YAML and Ubuntu's published autoinstall schema,
//!   kickstart and preseed lines, unattend XML read as untrusted), then lint for what locks you out (no user, password
//!   logins off and no key, no SSH or WinRM) and a disk layout bigger than a size's boot disk.
//! * Secrets are never in a config: a password is `{{password.<name>}}`, picked from the vault ([`SecretRef`]), and
//!   [`check`] refuses a file that holds a password or a hash itself. Rule 7: the rendered file (which holds hashes) is
//!   a [`crate::vault::SecretString`] and never reaches a log, the journal, the audit log or the UI.

pub mod autoinstall;
pub mod cloud_init;
pub mod form;
pub mod kickstart;
pub mod preseed;
pub mod render;
pub mod starters;
pub mod unattend;
pub mod vars;
pub mod xml;
pub mod yaml;

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub use self::form::{FieldState, FormField, FormRead, InstallForm};
pub use self::vars::{Placeholder, VariableDef};
use crate::error::{CoreError, Result};
use crate::untrusted;
use crate::vault::SecretId;

pub const MAX_CONFIG_NAME: usize = 60;
/// A file's size: unattend files run to tens of KB, the others to a few.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_NOTES: usize = 1000;
pub const MAX_VARIABLES: usize = 40;
pub const MAX_SECRETS: usize = 20;
/// Install configs one workspace keeps.
pub const MAX_CONFIGS: usize = 200;

/// The sample a check writes for `{{password.<name>}}` in a Linux file: the shape of the real hash.
pub(crate) const SAMPLE_HASH: &str = "$6$rounds=5000$remotelysample00$Hn3uE8b2YmPp4Xq1Lw7Zr0Tt5Vs9Kk6Jj2Ff8Dd4Ss1Aa3Gg7Hh5Ll0Mm9Nn2Bb6Cc4Ee8Ii1Oo3Uu7Yy5Ww0Qq9Rr2Zz6";
/// The sample for a Windows file's one-time password.
pub(crate) const SAMPLE_ONE_TIME: &str = "Remotely-Sample-0ne-Time!";
/// The sample for `{{ssh_key.<name>}}`.
pub(crate) const SAMPLE_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRemotelySampleKeyForChecksOnly0000000000 remotely-sample";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InstallKind {
    /// Ubuntu Server's autoinstall (Subiquity), YAML under `autoinstall:` in cloud-init user data.
    Autoinstall,
    /// Anaconda's kickstart: RHEL, Rocky, Alma, Oracle Linux, Fedora, CentOS Stream.
    Kickstart,
    /// debian-installer's preseed.
    Preseed,
    /// cloud-init user data (`#cloud-config`), for cloud images' first boot.
    CloudInit,
    /// Windows Setup's `autounattend.xml`.
    Unattend,
}

impl InstallKind {
    pub const ALL: [InstallKind; 5] = [
        InstallKind::Autoinstall,
        InstallKind::Kickstart,
        InstallKind::Preseed,
        InstallKind::CloudInit,
        InstallKind::Unattend,
    ];

    /// The `install_configs.kind` value.
    pub fn as_str(self) -> &'static str {
        match self {
            InstallKind::Autoinstall => "autoinstall",
            InstallKind::Kickstart => "kickstart",
            InstallKind::Preseed => "preseed",
            InstallKind::CloudInit => "cloud_init",
            InstallKind::Unattend => "unattend",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == text)
    }

    pub fn label(self) -> &'static str {
        match self {
            InstallKind::Autoinstall => "Ubuntu autoinstall",
            InstallKind::Kickstart => "Kickstart",
            InstallKind::Preseed => "Debian preseed",
            InstallKind::CloudInit => "cloud-init user data",
            InstallKind::Unattend => "Windows unattend",
        }
    }

    /// The file's name as the installer looks for it.
    pub fn file_name(self) -> &'static str {
        match self {
            InstallKind::Autoinstall | InstallKind::CloudInit => "user-data",
            InstallKind::Kickstart => "ks.cfg",
            InstallKind::Preseed => "preseed.cfg",
            InstallKind::Unattend => "autounattend.xml",
        }
    }

    /// An installer reads it from an ISO; cloud-init's runs on a cloud image (or a golden VM's clone).
    pub fn installs_from_iso(self) -> bool {
        self != InstallKind::CloudInit
    }

    pub fn windows(self) -> bool {
        self == InstallKind::Unattend
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecretRefKind {
    /// A vault password, written as a SHA-512 crypt hash (Windows: a one-time password).
    Password,
    /// A vault private key, whose public half is written.
    SshKey,
}

/// A `{{password.<name>}}` or `{{ssh_key.<name>}}` and the vault item it is, once picked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    pub name: String,
    pub kind: SecretRefKind,
    #[serde(default)]
    pub secret_id: Option<SecretId>,
}

impl SecretRef {
    pub fn placeholder(&self) -> Placeholder {
        match self.kind {
            SecretRefKind::Password => Placeholder::Password(self.name.clone()),
            SecretRefKind::SshKey => Placeholder::SshKey(self.name.clone()),
        }
    }
}

/// An install config's fields, as the editor sends them and the store keeps them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallConfigInput {
    pub name: String,
    pub kind: InstallKind,
    pub body: String,
    #[serde(default)]
    pub variables: Vec<VariableDef>,
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Error,
    Warning,
}

/// What a check found. Errors mean it can't deploy; warnings are worth a look.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigProblem {
    pub severity: Severity,
    /// The file's line, from 1.
    pub line: Option<u32>,
    pub message: String,
    /// A password or hash in the file itself: never saved.
    #[serde(skip)]
    pub blocks_saving: bool,
}

impl ConfigProblem {
    pub fn error(line: Option<u32>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            line,
            message: message.into(),
            blocks_saving: false,
        }
    }

    pub fn warning(line: Option<u32>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            line,
            message: message.into(),
            blocks_saving: false,
        }
    }

    /// A secret written into the file: an error that refuses saving.
    pub fn secret(line: Option<u32>, message: impl Into<String>) -> Self {
        Self {
            blocks_saving: true,
            ..Self::error(line, message)
        }
    }
}

/// A saved config (or a starter), with what a check finds now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallConfig {
    /// A UUID, or a starter's own id (`starter.ubuntu-24.04-minimal`).
    pub id: String,
    /// A starter: read only, copied to change.
    pub built_in: bool,
    #[serde(flatten)]
    pub spec: InstallConfigInput,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub problems: Vec<ConfigProblem>,
    /// What the disk layout needs at least, in MB, when the file says.
    pub disk_need_mb: Option<u64>,
}

impl InstallConfig {
    /// No error: it renders and can deploy.
    pub fn can_deploy(&self) -> bool {
        !self.problems.iter().any(|p| p.severity == Severity::Error)
    }
}

/// What a check knows of this workspace's vault and the size it checks the disk against.
#[derive(Debug, Clone, Default)]
pub struct CheckFacts {
    /// Vault passwords.
    pub passwords: HashSet<SecretId>,
    /// Vault private keys, with their public line once read.
    pub keys: HashMap<SecretId, Option<String>>,
    /// The size's name and its boot disk in GB.
    pub size: Option<(String, u32)>,
}

/// The placeholders a file uses, for the editor's variables and vault picks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsedPlaceholders {
    pub built_ins: Vec<String>,
    pub variables: Vec<String>,
    pub passwords: Vec<String>,
    pub ssh_keys: Vec<String>,
}

/// What the editor shows beside the file: problems, the form, the placeholders, the disk the layout needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCheck {
    pub problems: Vec<ConfigProblem>,
    pub form: FormRead,
    pub used: UsedPlaceholders,
    pub disk_need_mb: Option<u64>,
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

pub(crate) fn clean_config_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return invalid("Give the install config a name, such as Ubuntu web server.");
    }
    if name.chars().count() > MAX_CONFIG_NAME {
        return invalid(format!(
            "An install config's name can be at most {MAX_CONFIG_NAME} characters."
        ));
    }
    if name.chars().any(|c| c.is_control() || untrusted::is_format_char(c)) {
        return invalid("An install config's name can't hold control or invisible characters.");
    }
    Ok(name.to_owned())
}

/// Checks and tidies what the editor sends before it is saved: the name, notes, the file's size, each variable and
/// vault reference. What the file says is [`check`]'s business; only a secret written into it refuses saving.
pub fn check_input(input: &InstallConfigInput) -> Result<InstallConfigInput> {
    let name = clean_config_name(&input.name)?;
    let notes = match input.notes.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        None => None,
        Some(n) if n.chars().count() > MAX_NOTES => {
            return invalid(format!("Notes can be at most {MAX_NOTES} characters."))
        }
        Some(n) => Some(n.to_owned()),
    };
    if input.body.len() > MAX_BODY_BYTES {
        return invalid("An install config's file can be at most 256 KB.");
    }
    if input.body.contains('\0') {
        return invalid("The file holds a NUL character.");
    }
    if input.variables.len() > MAX_VARIABLES {
        return invalid(format!("An install config has at most {MAX_VARIABLES} variables."));
    }
    let mut variables: Vec<VariableDef> = Vec::new();
    for v in &input.variables {
        let name = v.name.trim();
        if !vars::valid_name(name) {
            return invalid(format!(
                "'{name}' can't be a variable's name: a lower case letter, then letters, digits and _, at most {}.",
                vars::MAX_NAME
            ));
        }
        if vars::BUILT_INS.contains(&name) || name == "password" || name == "ssh_key" {
            return invalid(format!(
                "{{{{{name}}}}} is Remotely's own: give the variable another name."
            ));
        }
        if variables.iter().any(|x| x.name == name) {
            return invalid(format!("The variable {name} is there twice."));
        }
        let default = v.default.as_deref().map(str::trim).filter(|d| !d.is_empty());
        if let Some(d) = default {
            if let Some(why) = vars::check_value(input.kind, d) {
                return invalid(format!("{name}'s default {why}."));
            }
        }
        variables.push(VariableDef {
            name: name.to_owned(),
            default: default.map(str::to_owned),
        });
    }
    if input.secrets.len() > MAX_SECRETS {
        return invalid(format!("An install config names at most {MAX_SECRETS} vault items."));
    }
    let mut secrets: Vec<SecretRef> = Vec::new();
    for s in &input.secrets {
        let name = s.name.trim();
        if !vars::valid_name(name) {
            return invalid(format!(
                "'{name}' can't name a vault item here: a lower case letter, then letters, digits and _."
            ));
        }
        if secrets.iter().any(|x| x.name == name && x.kind == s.kind) {
            return invalid(format!("{} is picked twice.", s.placeholder().text()));
        }
        secrets.push(SecretRef {
            name: name.to_owned(),
            kind: s.kind,
            secret_id: s.secret_id,
        });
    }
    // Normalise line endings: the installers read LF (Windows Setup takes either).
    let body = input.body.replace("\r\n", "\n");
    let clean = InstallConfigInput {
        name,
        kind: input.kind,
        body,
        variables,
        secrets,
        notes,
    };
    // A reference the file uses and the list lacks is added, unpicked.
    let mut clean = clean;
    if let Ok(pieces) = vars::split(&clean.body) {
        for used in vars::used(&pieces) {
            let (name, kind) = match used {
                Placeholder::Password(n) => (n, SecretRefKind::Password),
                Placeholder::SshKey(n) => (n, SecretRefKind::SshKey),
                _ => continue,
            };
            if !clean.secrets.iter().any(|s| s.name == name && s.kind == kind) && clean.secrets.len() < MAX_SECRETS {
                clean.secrets.push(SecretRef {
                    name,
                    kind,
                    secret_id: None,
                });
            }
        }
    }
    Ok(clean)
}

/// A placeholder's sample, for checking what a rendered file would be.
fn sample(kind: InstallKind, spec: &InstallConfigInput, p: &Placeholder) -> String {
    match p {
        Placeholder::BuiltIn("hostname") => "vm-1".into(),
        Placeholder::BuiltIn("ip") => "192.0.2.10".into(),
        Placeholder::BuiltIn("n") => "1".into(),
        Placeholder::BuiltIn("date") => "20260101".into(),
        Placeholder::BuiltIn(_) => "template".into(),
        Placeholder::Own(name) => spec
            .variables
            .iter()
            .find(|v| v.name == *name)
            .and_then(|v| v.default.clone())
            .unwrap_or_else(|| "value".into()),
        Placeholder::Password(_) if kind.windows() => SAMPLE_ONE_TIME.into(),
        Placeholder::Password(_) => SAMPLE_HASH.into(),
        Placeholder::SshKey(_) => SAMPLE_KEY.into(),
    }
}

/// The file as a deploy would render it, with samples for every value; or the placeholder problems.
pub(crate) fn sample_text(spec: &InstallConfigInput) -> std::result::Result<String, Vec<ConfigProblem>> {
    let pieces = vars::split(&spec.body).map_err(|errors| {
        errors
            .into_iter()
            .map(|e| ConfigProblem::error(Some(e.line), e.message))
            .collect::<Vec<_>>()
    })?;
    Ok(vars::join(&pieces, |p| Some(sample(spec.kind, spec, p))))
}

/// Whether a value written where a password goes is Remotely's own (a placeholder's sample) or empty.
pub(crate) fn is_sample_secret(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']);
    v == SAMPLE_HASH || v == SAMPLE_ONE_TIME
}

/// A crypt(3) hash's shape: `$1$`, `$5$`, `$6$`, `$y$`, `$2b$`...
pub(crate) fn looks_hashed(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']);
    v.starts_with('$') && v.len() > 12 && v.matches('$').count() >= 3
}

/// Everything a check finds in `spec`'s file, in line order.
pub fn check(spec: &InstallConfigInput, facts: &CheckFacts) -> Vec<ConfigProblem> {
    let mut problems = Vec::new();
    let pieces = match vars::split(&spec.body) {
        Ok(pieces) => pieces,
        Err(errors) => {
            problems.extend(
                errors
                    .into_iter()
                    .map(|e| ConfigProblem::error(Some(e.line), e.message)),
            );
            sort(&mut problems);
            return problems;
        }
    };
    let used = vars::used(&pieces);
    // Own variables: used ones must be declared; declared ones should be used.
    for p in &used {
        let line = vars::first_line(&pieces, p);
        match p {
            Placeholder::Own(name) if !spec.variables.iter().any(|v| v.name == *name) => {
                problems.push(ConfigProblem::error(
                    line,
                    format!("{{{{{name}}}}} isn't one of this config's variables: add it under Variables."),
                ));
            }
            Placeholder::Password(_) | Placeholder::SshKey(_) => {
                let r = spec.secrets.iter().find(|s| s.placeholder() == *p);
                let shown = p.text();
                match r.and_then(|r| r.secret_id) {
                    None => problems.push(ConfigProblem::warning(
                        line,
                        format!("{shown} isn't picked from the vault yet: pick it before a deploy."),
                    )),
                    Some(id) => {
                        let there = match p {
                            Placeholder::Password(_) => facts.passwords.contains(&id),
                            _ => facts.keys.contains_key(&id),
                        };
                        if !there {
                            problems.push(ConfigProblem::error(
                                line,
                                format!("{shown}'s vault item is no longer in the vault: pick another."),
                            ));
                        } else if matches!(p, Placeholder::SshKey(_))
                            && facts.keys.get(&id).is_some_and(Option::is_none)
                        {
                            problems.push(ConfigProblem::warning(
                                line,
                                format!("Remotely hasn't read {shown}'s public half yet: unlock the vault and open the key on the Vault page once."),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for v in &spec.variables {
        if !used.contains(&Placeholder::Own(v.name.clone())) {
            problems.push(ConfigProblem::warning(
                None,
                format!("The variable {} isn't used in the file.", v.name),
            ));
        }
    }
    if spec.kind == InstallKind::CloudInit || spec.kind.installs_from_iso() {
        // A deploy names each VM: a file that sets no hostname gives every VM the same one.
        let names_host = used.contains(&Placeholder::BuiltIn("hostname"));
        if !names_host {
            problems.push(ConfigProblem::warning(
                None,
                "The file doesn't use {{hostname}}, so every VM gets the same name.",
            ));
        }
    }
    let text = vars::join(&pieces, |p| Some(sample(spec.kind, spec, p)));
    problems.extend(match spec.kind {
        InstallKind::Autoinstall => autoinstall::check(&text),
        InstallKind::CloudInit => cloud_init::check(&text),
        InstallKind::Kickstart => kickstart::check(&text),
        InstallKind::Preseed => preseed::check(&text),
        InstallKind::Unattend => unattend::check(&text),
    });
    if let (Some(need), Some((size, disk_gb))) = (disk_need(spec.kind, &text), &facts.size) {
        let have = u64::from(*disk_gb) * 1024;
        if need > have {
            problems.push(ConfigProblem::error(
                None,
                format!(
                    "The disk layout needs at least {} GB, and the size {size}'s boot disk is {disk_gb} GB.",
                    need.div_ceil(1024)
                ),
            ));
        }
    }
    sort(&mut problems);
    problems
}

fn sort(problems: &mut [ConfigProblem]) {
    problems.sort_by_key(|p| (p.line.unwrap_or(u32::MAX), p.severity == Severity::Warning));
}

/// What the disk layout needs at least, in MB: the partitions it sizes, when it sizes any.
pub fn disk_need(kind: InstallKind, text: &str) -> Option<u64> {
    match kind {
        InstallKind::Autoinstall => autoinstall::disk_need_mb(text),
        InstallKind::Kickstart => kickstart::disk_need_mb(text),
        InstallKind::Preseed => preseed::disk_need_mb(text),
        InstallKind::Unattend => unattend::disk_need_mb(text),
        InstallKind::CloudInit => None,
    }
}

/// The placeholders `body` uses, sorted by kind.
pub fn used_placeholders(body: &str) -> UsedPlaceholders {
    let mut out = UsedPlaceholders::default();
    let Ok(pieces) = vars::split(body) else {
        return out;
    };
    for p in vars::used(&pieces) {
        match p {
            Placeholder::BuiltIn(n) => out.built_ins.push(n.to_owned()),
            Placeholder::Own(n) => out.variables.push(n),
            Placeholder::Password(n) => out.passwords.push(n),
            Placeholder::SshKey(n) => out.ssh_keys.push(n),
        }
    }
    out
}

/// The editor's whole check: problems, the form, the placeholders and the disk the layout needs.
pub fn check_all(spec: &InstallConfigInput, facts: &CheckFacts) -> ConfigCheck {
    let disk_need_mb = sample_text(spec).ok().and_then(|t| disk_need(spec.kind, &t));
    ConfigCheck {
        problems: check(spec, facts),
        form: read_form(spec.kind, &spec.body),
        used: used_placeholders(&spec.body),
        disk_need_mb,
    }
}

// ---- The form ------------------------------------------------------------------------------------------------------

/// Placeholders swapped for private-use tokens a parser reads as plain text, so `{{x}}` unquoted in YAML doesn't read
/// as a flow mapping; [`restore`] puts them back.
pub(crate) fn protect(text: &str) -> Option<(String, Vec<String>)> {
    if text.contains(['\u{e000}', '\u{e001}']) {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut table = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}").filter(|c| !after[..*c].contains('\n')) else {
            out.push_str(&rest[..open + 2]);
            rest = after;
            continue;
        };
        out.push_str(&rest[..open]);
        out.push('\u{e000}');
        out.push_str(&table.len().to_string());
        out.push('\u{e001}');
        table.push(format!("{{{{{}}}}}", &after[..close]));
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Some((out, table))
}

pub(crate) fn restore(text: &str, table: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('\u{e000}') {
        out.push_str(&rest[..open]);
        let after = &rest[open + '\u{e000}'.len_utf8()..];
        match after.find('\u{e001}') {
            Some(close) => {
                let index: Option<usize> = after[..close].parse().ok();
                match index.and_then(|i| table.get(i)) {
                    Some(original) => out.push_str(original),
                    None => out.push_str(&after[..close]),
                }
                rest = &after[close + '\u{e001}'.len_utf8()..];
            }
            None => {
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The form's values and fields for `body`.
pub fn read_form(kind: InstallKind, body: &str) -> FormRead {
    match kind {
        InstallKind::Autoinstall => autoinstall::read_form(body),
        InstallKind::CloudInit => cloud_init::read_form(body),
        InstallKind::Kickstart => kickstart::read_form(body),
        InstallKind::Preseed => preseed::read_form(body),
        InstallKind::Unattend => unattend::read_form(body),
    }
}

/// `body` with the fields that differ between `before` and `after` written into it; every other line stays.
pub fn apply_form(kind: InstallKind, body: &str, after: &InstallForm) -> Result<String> {
    let read = read_form(kind, body);
    if let Some(why) = &read.unreadable {
        return invalid(why.clone());
    }
    let before = &read.form;
    let changed = changed_fields(before, after);
    for field in &changed {
        if !read.editable(*field) {
            return invalid("The form can't change that part of this file: edit the file instead.");
        }
    }
    if let Some(max) = read.max_users {
        if after.users.len() > usize::from(max) {
            return invalid(format!("The form takes {max} user here; add more in the file."));
        }
    }
    check_form(kind, after)?;
    let out = match kind {
        InstallKind::Autoinstall => autoinstall::apply_form(body, before, after, &changed),
        InstallKind::CloudInit => cloud_init::apply_form(body, before, after, &changed),
        InstallKind::Kickstart => kickstart::apply_form(body, before, after, &changed),
        InstallKind::Preseed => preseed::apply_form(body, before, after, &changed),
        InstallKind::Unattend => unattend::apply_form(body, before, after, &changed),
    };
    out.map_err(CoreError::InvalidInput)
}

/// The fields whose values differ.
pub fn changed_fields(a: &InstallForm, b: &InstallForm) -> Vec<FormField> {
    let mut out = Vec::new();
    let mut push = |same: bool, f: FormField| {
        if !same {
            out.push(f);
        }
    };
    push(a.hostname == b.hostname, FormField::Hostname);
    push(a.locale == b.locale, FormField::Locale);
    push(a.keyboard == b.keyboard, FormField::Keyboard);
    push(a.timezone == b.timezone, FormField::Timezone);
    push(a.storage == b.storage, FormField::Storage);
    push(a.network == b.network, FormField::Network);
    push(a.users == b.users, FormField::Users);
    push(a.ssh == b.ssh, FormField::Ssh);
    push(a.packages == b.packages, FormField::Packages);
    push(a.updates == b.updates, FormField::Updates);
    push(a.proxy == b.proxy, FormField::Proxy);
    push(a.mirror == b.mirror, FormField::Mirror);
    push(a.late_commands == b.late_commands, FormField::LateCommands);
    out
}

/// One line each, no control characters; the values a form field takes.
fn check_form(kind: InstallKind, form: &InstallForm) -> Result<()> {
    let one_line = |what: &str, v: &str| -> Result<()> {
        if v.chars().any(|c| c.is_control() || untrusted::is_format_char(c)) || v.chars().count() > 2000 {
            return invalid(format!("{what} has to be one line of text."));
        }
        Ok(())
    };
    for (what, v) in [
        ("The hostname", &form.hostname),
        ("The locale", &form.locale),
        ("The keyboard", &form.keyboard),
        ("The time zone", &form.timezone),
        ("The proxy", &form.proxy),
        ("The mirror", &form.mirror),
    ] {
        if let Some(v) = v {
            one_line(what, v)?;
        }
    }
    for p in &form.packages {
        if vars::split(p).is_ok_and(|pieces| vars::used(&pieces).is_empty()) {
            crate::catalog::templates::check_packages(std::slice::from_ref(p))?;
        }
    }
    for c in &form.late_commands {
        if c.contains('\0') || c.chars().count() > 4000 {
            return invalid("A command after the install is at most 4,000 characters.");
        }
        if kind != InstallKind::Autoinstall && kind != InstallKind::CloudInit && c.contains('\n') {
            return invalid("Each command after the install is one line here.");
        }
    }
    for u in &form.users {
        one_line("A user's name", &u.name)?;
        if u.name.trim().is_empty() {
            return invalid("Give each user a name.");
        }
        for k in &u.ssh_keys {
            one_line("An SSH key", k)?;
        }
    }
    if let Some(form::NetworkForm::Static {
        address,
        prefix,
        gateway,
        dns,
    }) = &form.network
    {
        one_line("The address", address)?;
        if *prefix == 0 || *prefix > 32 {
            return invalid("The prefix length is 1 to 32.");
        }
        if let Some(g) = gateway {
            one_line("The gateway", g)?;
        }
        for d in dns {
            one_line("A DNS server", d)?;
        }
    }
    Ok(())
}

/// The placeholder in a form value, when it is one: `{{password.admin}}` → `admin`.
#[cfg(test)]
pub(crate) fn ref_name(value: &str, prefix: &str) -> Option<String> {
    let inner = value.trim().strip_prefix("{{")?.strip_suffix("}}")?.trim();
    inner
        .strip_prefix(prefix)
        .filter(|n| vars::valid_name(n))
        .map(str::to_owned)
}

/// Every placeholder a starter names, sorted.
pub fn placeholders_of(body: &str) -> BTreeSet<Placeholder> {
    vars::split(body).map(|p| vars::used(&p)).unwrap_or_default()
}

#[cfg(test)]
mod tests;
