//! VM-21 launch templates: an image and a size, with the hypervisor, VM folder, network, SSH key (SS-09, its public
//! half only), naming pattern, default count, environment label, tags and after-deploy steps.
//!
//! * [`check_template`] checks what the editor sends before it is saved: names, the pattern's tokens, the folder,
//!   the network's name, tags and steps. A template whose image, size or key went away later, or whose image moved
//!   to another hypervisor, is still saved and listed: [`problems`] says why it can't deploy.
//! * [`resolve`] is what deploy (R2) runs a template through: a template, what it names, a count and the VM names
//!   already taken, into one [`DeployPlan`] with each VM's name and hostname and the size's and OS profile's values
//!   for the template's hypervisor. Pure, so it is tested without a VM.
//!
//! Naming patterns take `{n}` (the VM's number, from 1, skipping names already taken), `{template}` (the template's
//! name) and `{date}` (today, `YYYYMMDD`): `web-{n}`, `{template}-{date}`.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use time::Date;
use uuid::Uuid;

use super::images::{folder_problem, Image, ImageFormat, QCOW2_NEEDS_CONVERSION};
use super::profiles::{profile, Firmware, OsProfile};
use super::sizes::{DiskController, Provisioning, Size};
use crate::adapters::hypervisor::Hypervisor;
use crate::domain::Environment;
use crate::error::{CoreError, Result};
use crate::ssh_keys::PublicKeyInfo;
use crate::store::{clean_name, MAX_TAG_LEN};
use crate::untrusted;
use crate::vault::SecretId;

pub const MAX_TEMPLATE_NAME: usize = 60;
pub const MAX_PATTERN: usize = 80;
/// Longest VM name a pattern may make (a folder and file name on this PC).
pub const MAX_VM_NAME: usize = 80;
/// Most VMs one deploy makes.
pub const MAX_DEPLOY_COUNT: u32 = 50;
pub const MAX_TEMPLATE_TAGS: usize = 20;
pub const MAX_NETWORK_NAME: usize = 64;
/// Workstation's custom networks: vmnet0 to vmnet19.
pub const MAX_VMNET: u8 = 19;
/// Launch templates one workspace keeps.
pub const MAX_TEMPLATES: usize = 500;
/// The snapshot the after-deploy step takes.
pub const CLEAN_SNAPSHOT_NAME: &str = "clean";
/// What a new template is named by.
pub const DEFAULT_PATTERN: &str = "{template}-{n}";

/// The network a deployed VM's first card joins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Network {
    /// Shares this PC's address (Workstation's vmnet8, VirtualBox's NAT).
    Nat,
    /// A private network with this PC (vmnet1, VirtualBox's host-only adapter).
    HostOnly,
    /// On the physical network beside this PC.
    Bridged,
    /// Workstation: a custom vmnet.
    Vmnet { number: u8 },
    /// VirtualBox: a NAT network by name.
    NatNetwork { name: String },
    /// VirtualBox: an internal network by name.
    Internal { name: String },
}

impl Network {
    /// The hypervisor a network belongs to, when only one has it.
    pub fn only_on(&self) -> Option<Hypervisor> {
        match self {
            Network::Vmnet { .. } => Some(Hypervisor::Vmware),
            Network::NatNetwork { .. } | Network::Internal { .. } => Some(Hypervisor::VirtualBox),
            Network::Nat | Network::HostOnly | Network::Bridged => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Network::Nat => "NAT".into(),
            Network::HostOnly => "host-only".into(),
            Network::Bridged => "bridged".into(),
            Network::Vmnet { number } => format!("vmnet{number}"),
            Network::NatNetwork { name } => format!("NAT network '{name}'"),
            Network::Internal { name } => format!("internal network '{name}'"),
        }
    }
}

/// What runs after each VM is deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AfterDeploy {
    /// Save an SSH session to the guest's IP once it shows.
    pub create_session: bool,
    /// QL-01: link that session to the VM.
    pub link_session: bool,
    /// Take a snapshot named [`CLEAN_SNAPSHOT_NAME`].
    pub clean_snapshot: bool,
    /// Open the hypervisor's console window.
    pub open_console: bool,
}

impl Default for AfterDeploy {
    fn default() -> Self {
        Self {
            create_session: true,
            link_session: true,
            clean_snapshot: false,
            open_console: false,
        }
    }
}

impl AfterDeploy {
    pub fn describe(&self) -> String {
        let mut steps = Vec::new();
        if self.create_session {
            steps.push("create the SSH session");
        }
        if self.link_session {
            steps.push("link it to the VM");
        }
        if self.clean_snapshot {
            steps.push("take a 'clean' snapshot");
        }
        if self.open_console {
            steps.push("open the console");
        }
        if steps.is_empty() {
            "none".into()
        } else {
            steps.join(", ")
        }
    }
}

/// VM-21 (R2): how a golden VM image is cloned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloneMode {
    /// A copy that stands alone (the default).
    #[default]
    Full,
    /// Shares the golden VM's snapshot disk: quicker and smaller, but it needs that snapshot, and its disk can't
    /// grow to the size's.
    Linked,
}

impl CloneMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CloneMode::Full => "full",
            CloneMode::Linked => "linked",
        }
    }

    /// Unknown values read as full, the safe kind.
    pub fn parse(s: &str) -> Self {
        match s {
            "linked" => CloneMode::Linked,
            _ => CloneMode::Full,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CloneMode::Full => "full clone",
            CloneMode::Linked => "linked clone",
        }
    }
}

/// VM-22: the most packages cloud-init installs for one template.
pub const MAX_PACKAGES: usize = 50;
pub const MAX_PACKAGE_NAME: usize = 100;
/// VM-22: Linux user names are at most 32 characters.
pub const MAX_GUEST_USER: usize = 32;

/// VM-22: a user name cloud-init can make: a lower case letter or `_` first, then lower case letters, digits, `_`
/// and `-`, at most [`MAX_GUEST_USER`]; never root.
pub fn check_guest_user(user: Option<&str>) -> Result<Option<String>> {
    let Some(user) = user.map(str::trim).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    let mut chars = user.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
    if !first_ok || !rest_ok || user.len() > MAX_GUEST_USER {
        return invalid(format!(
            "'{user}' can't be a Linux user name: use lower case letters, digits, _ and -, starting with a letter, at most {MAX_GUEST_USER}."
        ));
    }
    if user == "root" {
        return invalid("The guest user can't be root: cloud-init makes a user of its own, with sudo.");
    }
    Ok(Some(user.to_owned()))
}

/// VM-22: package names as apt and dnf take them (letters, digits and `+ . _ -`, a letter or digit first), each
/// once, at most [`MAX_PACKAGES`].
pub fn check_packages(packages: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for package in packages {
        let package = package.trim();
        if package.is_empty() {
            continue;
        }
        let ok = package.len() <= MAX_PACKAGE_NAME
            && package.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && package
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '_' | '-'));
        if !ok {
            return invalid(format!(
                "'{package}' isn't a package name: use letters, digits and + . _ -, at most {MAX_PACKAGE_NAME}."
            ));
        }
        if !out.iter().any(|p| p == package) {
            out.push(package.to_owned());
        }
    }
    if out.len() > MAX_PACKAGES {
        return invalid(format!("A template installs at most {MAX_PACKAGES} packages."));
    }
    Ok(out)
}

/// A launch template's fields, as the editor sends them and the store keeps them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateInput {
    pub name: String,
    pub image_id: Uuid,
    /// A built-in size's name, or an own size's UUID.
    pub size_id: String,
    pub hypervisor: Hypervisor,
    /// Where the VMs' folders go; `None`: the hypervisor's own default folder.
    #[serde(default)]
    pub vm_folder: Option<String>,
    pub network: Network,
    /// SS-09: a vault key whose public half goes to the VMs (never the private key).
    #[serde(default)]
    pub ssh_key_id: Option<SecretId>,
    pub naming_pattern: String,
    pub default_count: u32,
    #[serde(default)]
    pub environment: Environment,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub after_deploy: AfterDeploy,
    /// VM-22 (R2): the user cloud-init makes on first boot, with sudo and the SSH key. `None`: the image's own
    /// default user gets the key.
    #[serde(default)]
    pub guest_user: Option<String>,
    /// VM-22 (R2): packages cloud-init installs on first boot.
    #[serde(default)]
    pub packages: Vec<String>,
    /// VM-21 (R2): how a golden VM image is cloned.
    #[serde(default)]
    pub clone_mode: CloneMode,
}

/// Why a template can't deploy now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProblemCode {
    ImageGone,
    ImageUnavailable,
    NeedsConversion,
    UnknownProfile,
    SizeGone,
    HypervisorMismatch,
    NotOnHypervisor,
    NetworkMismatch,
    KeyGone,
    KeyNotRead,
    PatternNeedsNumber,
    CountOutOfRange,
    NameTaken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub code: ProblemCode,
    pub message: String,
}

impl Problem {
    fn new(code: ProblemCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// A saved launch template, with why it can't deploy (empty when it can).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchTemplate {
    pub id: Uuid,
    #[serde(flatten)]
    pub spec: TemplateInput,
    pub created_at: String,
    pub updated_at: String,
    pub problems: Vec<Problem>,
}

impl LaunchTemplate {
    pub fn can_deploy(&self) -> bool {
        self.problems.is_empty()
    }
}

/// The template's SSH key, as the catalogue found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    /// The template names none.
    None,
    /// No such key in the vault (deleted, or not imported with the template).
    Gone,
    /// A key in the vault whose public half Remotely hasn't read yet (it needs the vault unlocked once).
    NotRead,
    Ready(PublicKeyInfo),
}

/// What a template names, as the catalogue found it: `None` when it is gone.
pub struct Refs<'a> {
    pub image: Option<&'a Image>,
    pub size: Option<&'a Size>,
    pub key: KeyState,
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// Characters a VM name (a folder and file on this PC) can't hold.
const NOT_IN_NAMES: [char; 11] = ['\\', '/', ':', '*', '?', '"', '<', '>', '|', '{', '}'];

pub(crate) fn clean_template_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return invalid("Give the template a name, such as web.");
    }
    if name.chars().count() > MAX_TEMPLATE_NAME {
        return invalid(format!(
            "A template's name can be at most {MAX_TEMPLATE_NAME} characters."
        ));
    }
    if name
        .chars()
        .any(|c| c.is_control() || untrusted::is_format_char(c) || NOT_IN_NAMES.contains(&c))
    {
        return invalid("A template's name can't hold \\ / : * ? \" < > | { } or invisible characters (its VMs may be named after it).");
    }
    Ok(name.to_owned())
}

/// A piece of a naming pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Number,
    Template,
    Date,
}

fn parse_pattern(pattern: &str) -> Result<Vec<Piece>> {
    let mut pieces = Vec::new();
    let mut text = String::new();
    let mut rest = pattern;
    while let Some(c) = rest.chars().next() {
        if c == '{' {
            let Some(end) = rest.find('}') else {
                return invalid("A naming pattern's { needs its }: use {n}, {template} or {date}.");
            };
            let token = &rest[1..end];
            let piece = match token {
                "n" => Piece::Number,
                "template" => Piece::Template,
                "date" => Piece::Date,
                other => {
                    return invalid(format!(
                        "{{{other}}} isn't a naming token: use {{n}}, {{template}} or {{date}}."
                    ))
                }
            };
            if !text.is_empty() {
                pieces.push(Piece::Text(std::mem::take(&mut text)));
            }
            pieces.push(piece);
            rest = &rest[end + 1..];
            continue;
        }
        if c == '}' {
            return invalid("A naming pattern has a } without its {.");
        }
        if c.is_control() || untrusted::is_format_char(c) || NOT_IN_NAMES.contains(&c) {
            return invalid("A naming pattern can't hold \\ / : * ? \" < > | or invisible characters.");
        }
        text.push(c);
        rest = &rest[c.len_utf8()..];
    }
    if !text.is_empty() {
        pieces.push(Piece::Text(text));
    }
    Ok(pieces)
}

/// Whether the pattern numbers its VMs.
pub fn pattern_numbers(pattern: &str) -> bool {
    parse_pattern(pattern).is_ok_and(|p| p.contains(&Piece::Number))
}

/// `YYYYMMDD`.
pub fn date_token(date: Date) -> String {
    format!("{:04}{:02}{:02}", date.year(), u8::from(date.month()), date.day())
}

/// The VM name `pattern` makes for VM number `n` of the template `template`, checked as a name on this PC.
pub fn expand(pattern: &str, template: &str, n: u32, today: Date) -> Result<String> {
    let mut name = String::new();
    for piece in parse_pattern(pattern)? {
        match piece {
            Piece::Text(text) => name.push_str(&text),
            Piece::Number => name.push_str(&n.to_string()),
            Piece::Template => name.push_str(template),
            Piece::Date => name.push_str(&date_token(today)),
        }
    }
    check_vm_name(&name)?;
    Ok(name)
}

/// A VM name as a folder and file name on this PC.
fn check_vm_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return invalid("The naming pattern makes an empty name.");
    }
    if name != name.trim() || name.ends_with('.') {
        return invalid(format!(
            "'{name}' starts or ends with a space, or ends with a dot, which Windows doesn't keep in folder names."
        ));
    }
    if name.chars().count() > MAX_VM_NAME {
        return invalid(format!("The pattern makes names longer than {MAX_VM_NAME} characters."));
    }
    if untrusted::is_device_name(name) {
        return invalid(format!("'{name}' is a Windows device name, which can't be a folder."));
    }
    Ok(())
}

/// A guest hostname from a VM name: lower case letters, digits and hyphens, at most 63, as cloud-init sets it.
pub fn hostname(name: &str, n: u32) -> String {
    let mut out = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let mut out: String = out.trim_matches('-').chars().take(63).collect();
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        format!("vm-{n}")
    } else {
        out
    }
}

fn network_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NETWORK_NAME {
        return invalid(format!(
            "A VirtualBox network's name is 1 to {MAX_NETWORK_NAME} characters."
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
    {
        return invalid("A VirtualBox network's name can hold letters, digits, spaces, dots, hyphens and underscores.");
    }
    Ok(name.to_owned())
}

/// Checks and tidies what the editor sends. Whether what it names exists is [`problems`]' business.
pub fn check_template(input: &TemplateInput) -> Result<TemplateInput> {
    let name = clean_template_name(&input.name)?;
    let pattern = input.naming_pattern.trim().to_owned();
    if pattern.is_empty() {
        return invalid("Give the template a naming pattern, such as web-{n}.");
    }
    if pattern.chars().count() > MAX_PATTERN {
        return invalid(format!("A naming pattern can be at most {MAX_PATTERN} characters."));
    }
    // Any day: a date is always eight digits.
    expand(&pattern, &name, 1, time::macros::date!(2026 - 01 - 01))?;
    if !(1..=MAX_DEPLOY_COUNT).contains(&input.default_count) {
        return invalid(format!("The default count is 1 to {MAX_DEPLOY_COUNT} VMs."));
    }
    let size_id = input.size_id.trim().to_owned();
    if size_id.is_empty() {
        return invalid("Pick the template's size.");
    }
    let vm_folder = match input.vm_folder.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
        None => None,
        Some(folder) => {
            if let Some(problem) = folder_problem(folder) {
                return invalid(problem);
            }
            Some(folder.to_owned())
        }
    };
    let network = match &input.network {
        Network::Vmnet { number } if *number > MAX_VMNET => {
            return invalid(format!("Workstation's custom networks are vmnet0 to vmnet{MAX_VMNET}."))
        }
        Network::NatNetwork { name } => Network::NatNetwork {
            name: network_name(name)?,
        },
        Network::Internal { name } => Network::Internal {
            name: network_name(name)?,
        },
        other => other.clone(),
    };
    let mut tags: Vec<String> = Vec::new();
    for tag in &input.tags {
        let tag = clean_name("tag", tag, MAX_TAG_LEN)?;
        if !tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)) {
            tags.push(tag);
        }
    }
    if tags.len() > MAX_TEMPLATE_TAGS {
        return invalid(format!("A template can give its VMs at most {MAX_TEMPLATE_TAGS} tags."));
    }
    if input.after_deploy.link_session && !input.after_deploy.create_session {
        return invalid("Linking a session to the VM needs the session: tick \"Create the SSH session\" too.");
    }
    let guest_user = check_guest_user(input.guest_user.as_deref())?;
    let packages = check_packages(&input.packages)?;
    Ok(TemplateInput {
        name,
        image_id: input.image_id,
        size_id,
        hypervisor: input.hypervisor,
        vm_folder,
        network,
        ssh_key_id: input.ssh_key_id,
        naming_pattern: pattern,
        default_count: input.default_count,
        environment: input.environment,
        tags,
        after_deploy: input.after_deploy,
        guest_user,
        packages,
        clone_mode: input.clone_mode,
    })
}

/// Why `template` can't deploy with what it names now, in the order a user fixes them; empty when it can.
pub fn problems(template: &TemplateInput, refs: &Refs) -> Vec<Problem> {
    use ProblemCode as C;
    let mut out = Vec::new();
    let hv = template.hypervisor;
    match refs.image {
        None => out.push(Problem::new(C::ImageGone, "Its image was deleted. Pick another image.")),
        Some(image) => {
            if let Some(problem) = &image.problem {
                out.push(Problem::new(
                    C::ImageUnavailable,
                    format!("Image '{}': {problem}", image.name),
                ));
            }
            if image.source.format() == Some(ImageFormat::Qcow2) {
                out.push(Problem::new(
                    C::NeedsConversion,
                    format!("Image '{}': {QCOW2_NEEDS_CONVERSION}", image.name),
                ));
            }
            if !image.hypervisors.contains(&hv) {
                let on: Vec<&str> = image.hypervisors.iter().map(|h| hypervisor_label(*h)).collect();
                out.push(Problem::new(
                    C::HypervisorMismatch,
                    format!(
                        "Image '{}' deploys on {} only, and this template is for {}.",
                        image.name,
                        on.join(" and "),
                        hypervisor_label(hv)
                    ),
                ));
            }
            match profile(&image.os_profile) {
                None => out.push(Problem::new(
                    C::UnknownProfile,
                    format!(
                        "Image '{}' names the OS profile '{}', which this version of Remotely doesn't have.",
                        image.name, image.os_profile
                    ),
                )),
                Some(p) => {
                    if let Some(why) = p.refusal(hv) {
                        out.push(Problem::new(C::NotOnHypervisor, why));
                    }
                }
            }
        }
    }
    if refs.size.is_none() {
        out.push(Problem::new(C::SizeGone, "Its size was deleted. Pick another size."));
    }
    if let Some(only) = template.network.only_on() {
        if only != hv {
            out.push(Problem::new(
                C::NetworkMismatch,
                format!(
                    "The network {} is {}'s; pick one {} has.",
                    template.network.describe(),
                    hypervisor_label(only),
                    hypervisor_label(hv)
                ),
            ));
        }
    }
    match refs.key {
        KeyState::Gone => out.push(Problem::new(
            C::KeyGone,
            "Its SSH key is no longer in the vault. Pick another key, or none.",
        )),
        KeyState::NotRead => out.push(Problem::new(
            C::KeyNotRead,
            "Remotely hasn't read its SSH key's public half yet: unlock the vault and open the key on the Vault page once.",
        )),
        KeyState::None | KeyState::Ready(_) => {}
    }
    if template.default_count > 1 && !pattern_numbers(&template.naming_pattern) {
        out.push(Problem::new(
            C::PatternNeedsNumber,
            "Its naming pattern has no {n}, so it names one VM only; add {n} to deploy more.",
        ));
    }
    out
}

pub fn hypervisor_label(h: Hypervisor) -> &'static str {
    match h {
        Hypervisor::Vmware => "Workstation",
        Hypervisor::VirtualBox => "VirtualBox",
    }
}

// ---- Resolution: a template and a count into one plan per VM (R2) ----------------------------------------------

/// The OS profile's values on the template's hypervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileValues {
    pub id: &'static str,
    pub name: &'static str,
    pub firmware: Firmware,
    /// Workstation's `guestOS`, or VirtualBox's `--ostype`.
    pub guest_os: &'static str,
    /// Workstation's `virtualHW.version`; `None` on VirtualBox.
    pub hardware_version: Option<u32>,
    pub nic: &'static str,
    /// VirtualBox's `--tpm-type`, when the guest needs one.
    pub tpm: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedDisk {
    pub size_gb: u32,
    pub provisioning: Provisioning,
    pub controller: DiskController,
    /// The hypervisor's model for that controller: `pvscsi`, `nvme`, `IntelAhci`...
    pub controller_model: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeValues {
    pub id: String,
    pub name: String,
    pub sockets: u32,
    pub cores_per_socket: u32,
    pub vcpus: u32,
    pub memory_mb: u32,
    /// The first is the boot disk.
    pub disks: Vec<PlannedDisk>,
    /// Every disk at its full size (thin disks at the most they may take).
    pub total_disk_gb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedVm {
    /// What `{n}` was (1 when the pattern has none).
    pub number: u32,
    pub name: String,
    /// For first-boot setup: the name in lower case letters, digits and hyphens.
    pub hostname: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanKey {
    pub id: SecretId,
    /// The `authorized_keys` line.
    pub public_key: String,
    pub fingerprint: String,
}

/// Everything a deploy needs, for every VM it makes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployPlan {
    pub template_id: Uuid,
    pub template_name: String,
    pub hypervisor: Hypervisor,
    pub image: Image,
    pub profile: ProfileValues,
    pub size: SizeValues,
    /// `None`: the hypervisor's default folder.
    pub vm_folder: Option<String>,
    pub network: Network,
    pub ssh_key: Option<PlanKey>,
    pub environment: Environment,
    pub tags: Vec<String>,
    pub after_deploy: AfterDeploy,
    /// [`CLEAN_SNAPSHOT_NAME`] when the template takes one.
    pub clean_snapshot: Option<&'static str>,
    pub vms: Vec<PlannedVm>,
    /// VM-22 (R2): the user cloud-init makes; `None`: the image's default user.
    pub guest_user: Option<String>,
    /// VM-22 (R2): packages cloud-init installs.
    pub packages: Vec<String>,
    /// VM-21 (R2): how a golden VM image is cloned.
    pub clone_mode: CloneMode,
}

impl DeployPlan {
    /// Disk the VMs may take in all, thin disks at their full size.
    pub fn total_disk_gb(&self) -> u64 {
        self.size.total_disk_gb.saturating_mul(self.vms.len() as u64)
    }
}

/// The hypervisor's model for a controller: the profile's own when it is the profile's controller.
pub fn controller_model(hypervisor: Hypervisor, controller: DiskController, profile: &OsProfile) -> &'static str {
    match hypervisor {
        Hypervisor::Vmware => match controller {
            DiskController::Scsi => profile.workstation.and_then(|w| w.scsi_adapter).unwrap_or("lsisas1068"),
            DiskController::Sata => "ahci",
            DiskController::Nvme => "nvme",
            DiskController::Ide => "ide",
        },
        Hypervisor::VirtualBox => match controller {
            DiskController::Sata => "IntelAhci",
            DiskController::Scsi => "LsiLogic",
            DiskController::Nvme => "NVMe",
            DiskController::Ide => "PIIX4",
        },
    }
}

/// Resolves a saved template, what it names, `count` VMs and the VM names already taken (any letter case) into a
/// plan: each VM's name (`{n}` skips taken names and counts on), hostname, and the size's and profile's values on
/// the template's hypervisor. Every problem is returned instead when it can't deploy.
pub fn resolve(
    id: Uuid,
    template: &TemplateInput,
    refs: &Refs,
    count: u32,
    taken: &[String],
    today: Date,
) -> std::result::Result<DeployPlan, Vec<Problem>> {
    use ProblemCode as C;
    let mut found = problems(template, refs);
    // The template's default count is its own business; the count asked for now is checked instead.
    found.retain(|p| p.code != C::PatternNeedsNumber);
    if !(1..=MAX_DEPLOY_COUNT).contains(&count) {
        found.push(Problem::new(
            C::CountOutOfRange,
            format!("A deploy makes 1 to {MAX_DEPLOY_COUNT} VMs."),
        ));
    }
    let numbered = pattern_numbers(&template.naming_pattern);
    if count > 1 && !numbered {
        found.push(Problem::new(
            C::PatternNeedsNumber,
            "Its naming pattern has no {n}, so it names one VM only; add {n} to deploy more.",
        ));
    }
    let (Some(image), Some(size)) = (refs.image, refs.size) else {
        return Err(found);
    };
    let Some(os) = profile(&image.os_profile) else {
        return Err(found);
    };
    let vms = if found.is_empty() {
        match plan_names(template, count, numbered, taken, today) {
            Ok(vms) => vms,
            Err(problem) => {
                found.push(problem);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    if !found.is_empty() {
        return Err(found);
    }
    let hv = template.hypervisor;
    let profile_values = match (hv, os.workstation) {
        (Hypervisor::Vmware, Some(ws)) => ProfileValues {
            id: os.id,
            name: os.name,
            firmware: os.firmware,
            guest_os: ws.guest_os,
            hardware_version: Some(ws.hardware_version),
            nic: ws.nic,
            tpm: None,
        },
        _ => ProfileValues {
            id: os.id,
            name: os.name,
            firmware: os.firmware,
            guest_os: os.virtualbox.os_type,
            hardware_version: None,
            nic: os.virtualbox.nic,
            tpm: os.virtualbox.tpm,
        },
    };
    let disks = size
        .disks
        .iter()
        .map(|d| {
            let controller = d.controller.unwrap_or_else(|| os.controller(hv));
            PlannedDisk {
                size_gb: d.size_gb,
                provisioning: d.provisioning,
                controller,
                controller_model: controller_model(hv, controller, &os),
            }
        })
        .collect();
    let ssh_key = match &refs.key {
        KeyState::Ready(public) => template.ssh_key_id.map(|id| PlanKey {
            id,
            public_key: public.line.clone(),
            fingerprint: public.fingerprint.clone(),
        }),
        _ => None,
    };
    Ok(DeployPlan {
        template_id: id,
        template_name: template.name.clone(),
        hypervisor: hv,
        image: image.clone(),
        profile: profile_values,
        size: SizeValues {
            id: size.id.clone(),
            name: size.name.clone(),
            sockets: size.sockets,
            cores_per_socket: size.cores_per_socket,
            vcpus: size.vcpus(),
            memory_mb: size.memory_mb,
            disks,
            total_disk_gb: size.total_disk_gb(),
        },
        vm_folder: template.vm_folder.clone(),
        network: template.network.clone(),
        ssh_key,
        environment: template.environment,
        tags: template.tags.clone(),
        after_deploy: template.after_deploy,
        clean_snapshot: template.after_deploy.clean_snapshot.then_some(CLEAN_SNAPSHOT_NAME),
        vms,
        guest_user: template.guest_user.clone(),
        packages: template.packages.clone(),
        clone_mode: template.clone_mode,
    })
}

fn plan_names(
    template: &TemplateInput,
    count: u32,
    numbered: bool,
    taken: &[String],
    today: Date,
) -> std::result::Result<Vec<PlannedVm>, Problem> {
    let to_problem = |err: CoreError| Problem::new(ProblemCode::NameTaken, err.to_string());
    let mut used: HashSet<String> = taken.iter().map(|t| t.to_lowercase()).collect();
    let mut vms = Vec::with_capacity(count as usize);
    if !numbered {
        let name = expand(&template.naming_pattern, &template.name, 1, today).map_err(to_problem)?;
        if used.contains(&name.to_lowercase()) {
            return Err(Problem::new(
                ProblemCode::NameTaken,
                format!("A VM named '{name}' is here already; the pattern has no {{n}} to number another."),
            ));
        }
        vms.push(PlannedVm {
            number: 1,
            hostname: hostname(&name, 1),
            name,
        });
        return Ok(vms);
    }
    // Each taken name can push the numbers on by one at most.
    let last = count.saturating_add(u32::try_from(taken.len()).unwrap_or(u32::MAX));
    for n in 1..=last {
        if vms.len() == count as usize {
            break;
        }
        let name = expand(&template.naming_pattern, &template.name, n, today).map_err(to_problem)?;
        if used.insert(name.to_lowercase()) {
            vms.push(PlannedVm {
                number: n,
                hostname: hostname(&name, n),
                name,
            });
        }
    }
    if vms.len() < count as usize {
        return Err(Problem::new(
            ProblemCode::NameTaken,
            "The naming pattern makes the same name for more than one VM.",
        ));
    }
    Ok(vms)
}

/// What changed between two versions of a template, for the audit log. Names of the image and size come from the
/// caller (`describe_ref`).
pub(crate) fn template_changes(
    before: &TemplateInput,
    after: &TemplateInput,
    describe_image: &dyn Fn(Uuid) -> String,
    describe_size: &dyn Fn(&str) -> String,
) -> Vec<String> {
    let mut out = Vec::new();
    if before.name != after.name {
        out.push(format!("renamed to '{}'", after.name));
    }
    if before.image_id != after.image_id {
        out.push(format!(
            "image {} -> {}",
            describe_image(before.image_id),
            describe_image(after.image_id)
        ));
    }
    if before.size_id != after.size_id {
        out.push(format!(
            "size {} -> {}",
            describe_size(&before.size_id),
            describe_size(&after.size_id)
        ));
    }
    if before.hypervisor != after.hypervisor {
        out.push(format!(
            "hypervisor {} -> {}",
            hypervisor_label(before.hypervisor),
            hypervisor_label(after.hypervisor)
        ));
    }
    if before.vm_folder != after.vm_folder {
        out.push(format!(
            "VM folder -> {}",
            after.vm_folder.as_deref().unwrap_or("the hypervisor's default")
        ));
    }
    if before.network != after.network {
        out.push(format!(
            "network {} -> {}",
            before.network.describe(),
            after.network.describe()
        ));
    }
    if before.ssh_key_id != after.ssh_key_id {
        out.push(if after.ssh_key_id.is_some() {
            "SSH key changed".to_owned()
        } else {
            "SSH key removed".to_owned()
        });
    }
    if before.naming_pattern != after.naming_pattern {
        out.push(format!("naming {} -> {}", before.naming_pattern, after.naming_pattern));
    }
    if before.default_count != after.default_count {
        out.push(format!(
            "default count {} -> {}",
            before.default_count, after.default_count
        ));
    }
    if before.environment != after.environment {
        out.push(format!(
            "environment {} -> {}",
            before.environment.as_str(),
            after.environment.as_str()
        ));
    }
    if before.tags != after.tags {
        out.push(format!("tags -> {}", tags_text(&after.tags)));
    }
    if before.after_deploy != after.after_deploy {
        out.push(format!("after deploy -> {}", after.after_deploy.describe()));
    }
    if before.guest_user != after.guest_user {
        out.push(format!(
            "guest user -> {}",
            after.guest_user.as_deref().unwrap_or("the image's default")
        ));
    }
    if before.packages != after.packages {
        out.push(format!("packages -> {}", tags_text(&after.packages)));
    }
    if before.clone_mode != after.clone_mode {
        out.push(format!("golden VMs: {}", after.clone_mode.label()));
    }
    out
}

pub(crate) fn tags_text(tags: &[String]) -> String {
    if tags.is_empty() {
        "none".into()
    } else {
        tags.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use time::macros::date;

    use super::super::images::ImageSource;
    use super::super::sizes::{built_in, DiskSpec};
    use super::*;

    const TODAY: Date = date!(2026 - 10 - 25);

    fn image(hypervisors: &[Hypervisor], os_profile: &str) -> Image {
        Image {
            id: Uuid::from_u128(7),
            name: "Ubuntu 24.04 cloud".into(),
            source: ImageSource::CloudImage {
                path: r"C:\Images\noble.vmdk".into(),
                format: ImageFormat::Vmdk,
            },
            hypervisors: hypervisors.to_vec(),
            os_profile: os_profile.into(),
            sha256: Some("ab".repeat(32)),
            size_bytes: Some(600 * 1024 * 1024),
            notes: None,
            created_at: "2026-10-25T09:00:00Z".into(),
            updated_at: "2026-10-25T09:00:00Z".into(),
            problem: None,
            vm_name: None,
        }
    }

    fn template(pattern: &str, hypervisor: Hypervisor) -> TemplateInput {
        TemplateInput {
            name: "web".into(),
            image_id: Uuid::from_u128(7),
            size_id: "gp.medium".into(),
            hypervisor,
            vm_folder: Some(r"C:\VMs\lab".into()),
            network: Network::Nat,
            ssh_key_id: None,
            naming_pattern: pattern.into(),
            default_count: 3,
            environment: Environment::Lab,
            tags: vec!["web".into(), "Web".into(), "frontend".into()],
            after_deploy: AfterDeploy::default(),
            guest_user: Some("alice".into()),
            packages: vec!["nginx".into()],
            clone_mode: CloneMode::Full,
        }
    }

    fn codes(problems: &[Problem]) -> Vec<ProblemCode> {
        problems.iter().map(|p| p.code).collect()
    }

    #[test]
    fn naming_patterns_expand() {
        assert_eq!(expand("web-{n}", "web", 3, TODAY).unwrap(), "web-3");
        assert_eq!(
            expand("{template}-{date}", "db tier", 1, TODAY).unwrap(),
            "db tier-20261025"
        );
        assert_eq!(expand("{template}{n}.lab", "app", 12, TODAY).unwrap(), "app12.lab");
        assert!(pattern_numbers("web-{n}"));
        assert!(!pattern_numbers("{template}-{date}"));
        for (pattern, why) in [
            ("web-{x}", "isn't a naming token"),
            ("web-{n", "needs its }"),
            ("web-}", "without its {"),
            ("web/{n}", "can't hold"),
            ("web\u{202e}{n}", "can't hold"),
            (" {n}", "starts or ends with a space"),
            ("web.", "ends with a dot"),
            ("NUL", "Windows device name"),
            ("{template}", "empty name"),
        ] {
            let template = if pattern == "{template}" { "" } else { "web" };
            let err = expand(pattern, template, 1, TODAY).unwrap_err().to_string();
            assert!(err.contains(why), "{pattern}: {err}");
        }
        assert!(expand(&"x".repeat(81), "web", 1, TODAY).is_err());
    }

    #[test]
    fn hostnames_are_safe_for_cloud_init() {
        assert_eq!(hostname("web-3", 3), "web-3");
        assert_eq!(hostname("DB Tier_20261025", 1), "db-tier-20261025");
        assert_eq!(hostname("--Ünïcode--", 2), "n-code");
        assert_eq!(hostname("___", 4), "vm-4");
        assert_eq!(hostname(&"a".repeat(70), 1).len(), 63);
    }

    #[test]
    fn a_template_is_checked_before_it_is_saved() {
        let ok = check_template(&template(" web-{n} ", Hypervisor::Vmware)).unwrap();
        assert_eq!(ok.naming_pattern, "web-{n}");
        assert_eq!(ok.tags, ["web", "frontend"], "tags without repeats in any case");
        let bad = |change: &dyn Fn(&mut TemplateInput), why: &str| {
            let mut input = template("web-{n}", Hypervisor::Vmware);
            change(&mut input);
            let err = check_template(&input).unwrap_err().to_string();
            assert!(err.contains(why), "{why}: {err}");
        };
        bad(&|t| t.name = " ".into(), "Give the template a name");
        bad(&|t| t.name = "web/db".into(), "can't hold");
        bad(&|t| t.naming_pattern = "web-{id}".into(), "isn't a naming token");
        bad(&|t| t.naming_pattern = String::new(), "naming pattern");
        bad(&|t| t.default_count = 0, "1 to 50");
        bad(&|t| t.default_count = 51, "1 to 50");
        bad(&|t| t.size_id = " ".into(), "Pick the template's size");
        bad(
            &|t| t.vm_folder = Some(r"\\fileserver.example.com\vms".into()),
            "That folder is on a network share",
        );
        bad(&|t| t.vm_folder = Some("VMs".into()), "full path");
        bad(&|t| t.network = Network::Vmnet { number: 20 }, "vmnet0 to vmnet19");
        bad(
            &|t| t.network = Network::Internal { name: "lab;rm".into() },
            "can hold letters",
        );
        bad(&|t| t.tags = vec!["a\tb".into()], "control characters");
        bad(
            &|t| t.tags = (0..21).map(|i| format!("t{i}")).collect(),
            "at most 20 tags",
        );
        bad(
            &|t| {
                t.after_deploy = AfterDeploy {
                    create_session: false,
                    link_session: true,
                    clean_snapshot: false,
                    open_console: false,
                }
            },
            "needs the session",
        );
        let none = TemplateInput {
            vm_folder: Some("  ".into()),
            ..template("web-{n}", Hypervisor::Vmware)
        };
        assert_eq!(check_template(&none).unwrap().vm_folder, None);
    }

    #[test]
    fn first_boot_settings_are_checked() {
        assert_eq!(check_guest_user(None).unwrap(), None);
        assert_eq!(check_guest_user(Some("  ")).unwrap(), None);
        assert_eq!(check_guest_user(Some(" alice ")).unwrap().as_deref(), Some("alice"));
        assert_eq!(check_guest_user(Some("_svc-01")).unwrap().as_deref(), Some("_svc-01"));
        for bad in ["Alice", "1bob", "bob smith", "bob;id", "b\u{202e}ob", &"a".repeat(33)] {
            assert!(check_guest_user(Some(bad)).is_err(), "{bad}");
        }
        assert!(check_guest_user(Some("root"))
            .unwrap_err()
            .to_string()
            .contains("can't be root"));

        let packages = |list: &[&str]| check_packages(&list.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>());
        assert_eq!(
            packages(&[" nginx ", "", "libstdc++6", "python3.12", "nginx", "NetworkManager"]).unwrap(),
            ["nginx", "libstdc++6", "python3.12", "NetworkManager"],
            "trimmed, each once"
        );
        for bad in ["-rf", "a b", "curl|sh", "x;y", "$(id)", "\"q\"", "pkg\n- runcmd"] {
            assert!(packages(&[bad]).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..51).map(|i| format!("p{i}")).collect();
        assert!(check_packages(&many).unwrap_err().to_string().contains("at most 50"));

        let input = TemplateInput {
            guest_user: Some("Bob".into()),
            ..template("web-{n}", Hypervisor::Vmware)
        };
        assert!(check_template(&input).is_err());
        assert_eq!(CloneMode::parse("linked"), CloneMode::Linked);
        assert_eq!(CloneMode::parse("something new"), CloneMode::Full);
        assert_eq!(serde_json::to_value(CloneMode::Linked).unwrap(), "linked");
    }

    #[test]
    fn problems_say_why_a_template_cant_deploy() {
        let size = built_in("gp.medium").unwrap();
        let both = image(&Hypervisor::ALL, "ubuntu");
        let t = template("web-{n}", Hypervisor::Vmware);
        let refs = |image, size| Refs {
            image,
            size,
            key: KeyState::None,
        };
        assert!(problems(&t, &refs(Some(&both), Some(&size))).is_empty());

        // The image or size is gone.
        assert_eq!(
            codes(&problems(&t, &refs(None, None))),
            [ProblemCode::ImageGone, ProblemCode::SizeGone]
        );
        // Hypervisor mismatch.
        let vbox_only = image(&[Hypervisor::VirtualBox], "ubuntu");
        let found = problems(&t, &refs(Some(&vbox_only), Some(&size)));
        assert_eq!(codes(&found), [ProblemCode::HypervisorMismatch]);
        assert_eq!(
            found[0].message,
            "Image 'Ubuntu 24.04 cloud' deploys on VirtualBox only, and this template is for Workstation."
        );
        // Windows 11 on Workstation.
        let w11 = image(&Hypervisor::ALL, "windows-11");
        let found = problems(&t, &refs(Some(&w11), Some(&size)));
        assert_eq!(codes(&found), [ProblemCode::NotOnHypervisor]);
        assert!(found[0].message.contains("Windows 11 deploys on VirtualBox only"));
        let on_vbox = TemplateInput {
            hypervisor: Hypervisor::VirtualBox,
            ..t.clone()
        };
        assert!(problems(&on_vbox, &refs(Some(&w11), Some(&size))).is_empty());
        // A file that went away, a qcow2, a profile from a newer version.
        let mut gone = both.clone();
        gone.problem = Some(r"C:\Images\noble.vmdk isn't on this PC.".into());
        assert_eq!(
            codes(&problems(&t, &refs(Some(&gone), Some(&size)))),
            [ProblemCode::ImageUnavailable]
        );
        let mut qcow2 = both.clone();
        qcow2.source = ImageSource::CloudImage {
            path: r"C:\Images\rocky.qcow2".into(),
            format: ImageFormat::Qcow2,
        };
        assert_eq!(
            codes(&problems(&t, &refs(Some(&qcow2), Some(&size)))),
            [ProblemCode::NeedsConversion]
        );
        let newer = image(&Hypervisor::ALL, "beos");
        assert_eq!(
            codes(&problems(&t, &refs(Some(&newer), Some(&size)))),
            [ProblemCode::UnknownProfile]
        );
        // A network of the other hypervisor, a key that is gone or not read, a pattern without {n}.
        let vmnet_on_vbox = TemplateInput {
            network: Network::Vmnet { number: 2 },
            ..on_vbox.clone()
        };
        assert_eq!(
            codes(&problems(&vmnet_on_vbox, &refs(Some(&both), Some(&size)))),
            [ProblemCode::NetworkMismatch]
        );
        let internal_on_ws = TemplateInput {
            network: Network::Internal { name: "lab".into() },
            ..t.clone()
        };
        assert_eq!(
            codes(&problems(&internal_on_ws, &refs(Some(&both), Some(&size)))),
            [ProblemCode::NetworkMismatch]
        );
        for (key, code) in [
            (KeyState::Gone, ProblemCode::KeyGone),
            (KeyState::NotRead, ProblemCode::KeyNotRead),
        ] {
            let found = problems(
                &t,
                &Refs {
                    image: Some(&both),
                    size: Some(&size),
                    key,
                },
            );
            assert_eq!(codes(&found), [code]);
        }
        let single = template("{template}-{date}", Hypervisor::Vmware);
        assert_eq!(
            codes(&problems(&single, &refs(Some(&both), Some(&size)))),
            [ProblemCode::PatternNeedsNumber]
        );
        let one = TemplateInput {
            default_count: 1,
            ..single
        };
        assert!(problems(&one, &refs(Some(&both), Some(&size))).is_empty());
    }

    fn public_key() -> PublicKeyInfo {
        PublicKeyInfo {
            algorithm: "ssh-ed25519".into(),
            line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com".into(),
            fingerprint: "SHA256:example".into(),
            comment: "alice@example.com".into(),
            bits: None,
        }
    }

    #[test]
    fn a_template_resolves_into_one_plan_per_vm() {
        let size = built_in("disk.large").unwrap();
        let img = image(&Hypervisor::ALL, "ubuntu");
        let key = SecretId(Uuid::from_u128(9));
        let t = TemplateInput {
            ssh_key_id: Some(key),
            after_deploy: AfterDeploy {
                clean_snapshot: true,
                ..AfterDeploy::default()
            },
            ..template("web-{n}", Hypervisor::Vmware)
        };
        let refs = Refs {
            image: Some(&img),
            size: Some(&size),
            key: KeyState::Ready(public_key()),
        };
        let taken = ["WEB-2".to_owned(), "db-1".to_owned()];
        let plan = resolve(Uuid::from_u128(1), &t, &refs, 3, &taken, TODAY).unwrap();
        let names: Vec<(u32, &str)> = plan.vms.iter().map(|v| (v.number, v.name.as_str())).collect();
        assert_eq!(names, [(1, "web-1"), (3, "web-3"), (4, "web-4")], "web-2 is taken");
        assert_eq!(plan.vms[0].hostname, "web-1");
        assert_eq!(plan.hypervisor, Hypervisor::Vmware);
        assert_eq!(plan.profile.guest_os, "ubuntu-64");
        assert_eq!(plan.profile.hardware_version, Some(20));
        assert_eq!(plan.profile.nic, "vmxnet3");
        assert_eq!(plan.profile.firmware, Firmware::Efi);
        assert_eq!((plan.size.vcpus, plan.size.memory_mb), (2, 4096));
        assert_eq!(
            plan.size.disks,
            [
                PlannedDisk {
                    size_gb: 40,
                    provisioning: Provisioning::Thin,
                    controller: DiskController::Scsi,
                    controller_model: "pvscsi",
                },
                PlannedDisk {
                    size_gb: 500,
                    provisioning: Provisioning::Thin,
                    controller: DiskController::Scsi,
                    controller_model: "pvscsi",
                },
            ]
        );
        assert_eq!(plan.size.total_disk_gb, 540);
        assert_eq!(plan.total_disk_gb(), 1620);
        assert_eq!(plan.ssh_key.as_ref().map(|k| k.id), Some(key));
        assert!(plan.ssh_key.as_ref().unwrap().public_key.starts_with("ssh-ed25519 "));
        assert_eq!(plan.clean_snapshot, Some("clean"));
        assert_eq!(plan.tags, t.tags);
        assert_eq!(plan.environment, Environment::Lab);
        assert_eq!(plan.vm_folder.as_deref(), Some(r"C:\VMs\lab"));

        // The same on VirtualBox: its own values, and a disk that names its own controller keeps it.
        let mut own = size.clone();
        own.disks[1] = DiskSpec {
            size_gb: 500,
            provisioning: Provisioning::Thick,
            controller: Some(DiskController::Nvme),
        };
        let vbox = TemplateInput {
            hypervisor: Hypervisor::VirtualBox,
            ..t.clone()
        };
        let refs = Refs {
            image: Some(&img),
            size: Some(&own),
            key: KeyState::Ready(public_key()),
        };
        let plan = resolve(Uuid::from_u128(1), &vbox, &refs, 1, &[], TODAY).unwrap();
        assert_eq!(plan.profile.guest_os, "Ubuntu_64");
        assert_eq!(plan.profile.hardware_version, None);
        assert_eq!(plan.profile.nic, "virtio");
        assert_eq!(plan.size.disks[0].controller_model, "IntelAhci");
        assert_eq!(
            (
                plan.size.disks[1].controller,
                plan.size.disks[1].controller_model,
                plan.size.disks[1].provisioning
            ),
            (DiskController::Nvme, "NVMe", Provisioning::Thick)
        );
        assert_eq!(plan.vms.len(), 1);
    }

    #[test]
    fn windows_11_resolves_on_virtualbox_with_its_tpm() {
        let size = built_in("gp.large").unwrap();
        let img = image(&[Hypervisor::VirtualBox], "windows-11");
        let t = TemplateInput {
            hypervisor: Hypervisor::VirtualBox,
            ..template("win-{n}", Hypervisor::VirtualBox)
        };
        let refs = Refs {
            image: Some(&img),
            size: Some(&size),
            key: KeyState::None,
        };
        let plan = resolve(Uuid::from_u128(1), &t, &refs, 2, &[], TODAY).unwrap();
        assert_eq!(plan.profile.tpm, Some("2.0"));
        assert_eq!(plan.profile.firmware, Firmware::EfiSecureBoot);
        assert_eq!(plan.profile.nic, "82540EM");
        assert_eq!(plan.ssh_key, None);
        assert_eq!(plan.clean_snapshot, None);
        let on_ws = TemplateInput {
            hypervisor: Hypervisor::Vmware,
            ..t
        };
        let both = image(&Hypervisor::ALL, "windows-11");
        let refs = Refs {
            image: Some(&both),
            size: Some(&size),
            key: KeyState::None,
        };
        let err = resolve(Uuid::from_u128(1), &on_ws, &refs, 1, &[], TODAY).unwrap_err();
        assert_eq!(codes(&err), [ProblemCode::NotOnHypervisor]);
    }

    #[test]
    fn resolution_refuses_what_cant_deploy() {
        let size = built_in("gp.small").unwrap();
        let img = image(&Hypervisor::ALL, "debian");
        let refs = Refs {
            image: Some(&img),
            size: Some(&size),
            key: KeyState::None,
        };
        let single = template("{template}-{date}", Hypervisor::Vmware);
        // One VM is fine even though the template's default count is 3.
        let plan = resolve(Uuid::from_u128(1), &single, &refs, 1, &[], TODAY).unwrap();
        assert_eq!(plan.vms[0].name, "web-20261025");
        let err = resolve(Uuid::from_u128(1), &single, &refs, 2, &[], TODAY).unwrap_err();
        assert_eq!(codes(&err), [ProblemCode::PatternNeedsNumber]);
        let err = resolve(Uuid::from_u128(1), &single, &refs, 1, &["Web-20261025".into()], TODAY).unwrap_err();
        assert_eq!(codes(&err), [ProblemCode::NameTaken]);
        let numbered = template("web-{n}", Hypervisor::Vmware);
        for count in [0, 51] {
            let err = resolve(Uuid::from_u128(1), &numbered, &refs, count, &[], TODAY).unwrap_err();
            assert_eq!(codes(&err), [ProblemCode::CountOutOfRange], "{count}");
        }
        let gone = Refs {
            image: None,
            size: Some(&size),
            key: KeyState::None,
        };
        let err = resolve(Uuid::from_u128(1), &numbered, &gone, 1, &[], TODAY).unwrap_err();
        assert_eq!(codes(&err), [ProblemCode::ImageGone]);
        // Many taken names push the numbers on, never past what the pattern can name.
        let taken: Vec<String> = (1..=10).map(|n| format!("web-{n}")).collect();
        let plan = resolve(Uuid::from_u128(1), &numbered, &refs, 2, &taken, TODAY).unwrap();
        assert_eq!(plan.vms.iter().map(|v| v.number).collect::<Vec<_>>(), [11, 12]);
    }

    #[test]
    fn template_changes_name_what_changed() {
        let before = template("web-{n}", Hypervisor::Vmware);
        let after = TemplateInput {
            name: "web2".into(),
            size_id: "gp.large".into(),
            network: Network::Vmnet { number: 3 },
            default_count: 5,
            after_deploy: AfterDeploy {
                open_console: true,
                ..AfterDeploy::default()
            },
            ..before.clone()
        };
        let changes = template_changes(&before, &after, &|id| id.to_string(), &|s| s.to_owned());
        assert_eq!(
            changes,
            [
                "renamed to 'web2'",
                "size gp.medium -> gp.large",
                "network NAT -> vmnet3",
                "default count 3 -> 5",
                "after deploy -> create the SSH session, link it to the VM, open the console"
            ]
        );
        assert!(template_changes(&before, &before, &|id| id.to_string(), &|s| s.to_owned()).is_empty());
    }
}
