//! What a deploy makes and how: [`DeploySpec`], which [`crate::command_bus::Command::Deploy`] carries, so what
//! the user approved is what runs (and what the job journal keeps). The deploy service builds it from a resolved
//! [`DeployPlan`] (VM-21: a launch template or Custom) or from the VMs picked for a bulk clone (VM-10); the UI
//! never sends one (`Command::check_from_ui`). [`DeploySpec::validate`] checks it again on the bus.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::images::{ImageFormat, ImageSource};
use crate::catalog::profiles::{Firmware, GuestFamily};
use crate::catalog::sizes::{DiskController, Provisioning};
use crate::catalog::templates::{
    self, check_guest_user, check_packages, AfterDeploy, CloneMode, DeployPlan, Network, MAX_DEPLOY_COUNT,
};
use crate::domain::{Environment, TargetRef};
use crate::error::{CoreError, Result};
use crate::untrusted;
use crate::vault::SecretId;

/// Where a deploy came from, for the dialog, the job and the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DeployOrigin {
    /// A saved launch template.
    Template { id: Uuid, name: String },
    /// Every value chosen by hand in the Deploy dialog.
    Custom { name: String },
    /// VM-10: the VMs picked on the VMs page, each cloned.
    BulkClone,
    /// CV-01: a foreign VM or disk imported from Image tools or the VMs page; `name` is the file picked.
    Import { name: String },
}

impl DeployOrigin {
    pub fn describe(&self) -> String {
        match self {
            DeployOrigin::Template { name, .. } => format!("launch template '{name}'"),
            DeployOrigin::Custom { name } => format!("custom settings ('{name}')"),
            DeployOrigin::BulkClone => "a bulk clone".into(),
            DeployOrigin::Import { name } => format!("an import of {name}"),
        }
    }
}

/// CV-01: one disk an import converts into the new VM's folder (the first boots).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportDisk {
    pub path: String,
    pub format: crate::convert::formats::DiskFormat,
}

/// The most disks one import brings.
pub const MAX_IMPORT_DISKS: usize = crate::convert::import::MAX_IMPORT_DISKS;

/// Where each VM's OS comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DeploySource {
    /// VM-20, VM-21: a clone of a golden VM's snapshot, full or linked.
    GoldenVm {
        vm_key: String,
        vm_name: String,
        /// Workstation's `snapshotN.uid` as text, or VirtualBox's snapshot UUID: it stays when it is renamed.
        snapshot_id: String,
        snapshot_name: String,
        linked: bool,
    },
    /// A cloud image file, copied (never changed) into each VM's folder as its boot disk.
    CloudImage { path: String, format: ImageFormat },
    /// A blank VM that boots this ISO first.
    Iso { path: String },
    /// An OVA or OVF, imported as it is.
    Appliance { path: String, format: ImageFormat },
    /// VM-10: each VM is a full clone of its own source VM ([`DeployVm::clone_of`]), as that VM is now.
    BulkClone,
    /// CV-01: a foreign VM's disks (or one disk image), each converted (never changed) into the new VM's folder,
    /// the first its boot disk; `description` is the libvirt XML or Proxmox `.conf` they came with.
    Import {
        disks: Vec<ImportDisk>,
        #[serde(default)]
        description: Option<String>,
    },
}

impl DeploySource {
    pub fn describe(&self) -> String {
        match self {
            DeploySource::GoldenVm {
                vm_name,
                snapshot_name,
                linked,
                ..
            } => format!(
                "{} of '{vm_name}' at its snapshot '{snapshot_name}'",
                if *linked { "a linked clone" } else { "a full clone" }
            ),
            DeploySource::CloudImage { path, format } => format!("the {} cloud image {path}", format.label()),
            DeploySource::Iso { path } => format!("a blank VM booting {path}"),
            DeploySource::Appliance { path, format } => format!("the {} appliance {path}", format.label()),
            DeploySource::BulkClone => "a full clone of each VM as it is now".into(),
            DeploySource::Import { disks, description } => {
                let files: Vec<String> = disks
                    .iter()
                    .map(|d| format!("{} ({})", d.path, d.format.label()))
                    .collect();
                let mut text = format!(
                    "the imported disk{} {}",
                    if disks.len() == 1 { "" } else { "s" },
                    files.join(", ")
                );
                if let Some(description) = description {
                    text.push_str(&format!(", described by {description}"));
                }
                text
            }
        }
    }

    /// The file it reads, for the kinds that are one (an import's boot disk).
    pub fn path(&self) -> Option<&str> {
        match self {
            DeploySource::CloudImage { path, .. }
            | DeploySource::Iso { path }
            | DeploySource::Appliance { path, .. } => Some(path),
            DeploySource::Import { disks, .. } => disks.first().map(|d| d.path.as_str()),
            DeploySource::GoldenVm { .. } | DeploySource::BulkClone => None,
        }
    }

    pub fn is_linked(&self) -> bool {
        matches!(self, DeploySource::GoldenVm { linked: true, .. })
    }
}

/// The OS profile's values on the deploy's hypervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSpec {
    pub id: String,
    pub name: String,
    pub family: GuestFamily,
    pub firmware: Firmware,
    /// Workstation's `guestOS`, or VirtualBox's `--ostype`.
    pub guest_os: String,
    /// Workstation's `virtualHW.version`.
    pub hardware_version: Option<u32>,
    pub nic: String,
    /// VirtualBox's `--tpm-type`.
    pub tpm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskPlan {
    pub size_gb: u32,
    pub provisioning: Provisioning,
    pub controller: DiskController,
    /// The hypervisor's model for the controller: `pvscsi`, `IntelAhci`...
    pub controller_model: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeSpec {
    pub id: String,
    pub name: String,
    pub sockets: u32,
    pub cores_per_socket: u32,
    pub memory_mb: u32,
    /// The first is the boot disk.
    pub disks: Vec<DiskPlan>,
}

impl SizeSpec {
    pub fn vcpus(&self) -> u32 {
        self.sockets.saturating_mul(self.cores_per_socket)
    }

    pub fn boot_disk_gb(&self) -> u32 {
        self.disks.first().map_or(0, |d| d.size_gb)
    }

    pub fn describe(&self) -> String {
        let disks: Vec<String> = self
            .disks
            .iter()
            .map(|d| format!("{} GB {}", d.size_gb, d.provisioning.as_str()))
            .collect();
        format!(
            "{} ({} vCPU, {} MB, {})",
            self.name,
            self.vcpus(),
            self.memory_mb,
            disks.join(" + ")
        )
    }
}

/// VM-22: what cloud-init sets on first boot. Public key only; never a password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirstBootSpec {
    /// `None`: the image's default user gets the key.
    pub user: Option<String>,
    /// The `authorized_keys` line.
    pub public_key: Option<String>,
    pub packages: Vec<String>,
}

/// VirtualBox's unattended install of an ISO: the user it makes and the vault password it gets. Only the vault
/// item's id is here; the job reads the password from the vault into a file only this Windows user can read,
/// which VBoxManage reads (`--password-file`) and Remotely deletes at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnattendedSpec {
    pub user: String,
    pub password_id: SecretId,
}

/// One VM the deploy makes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployVm {
    /// What `{n}` was.
    pub number: u32,
    pub name: String,
    pub hostname: String,
    /// VM-10: the VM it is a clone of (its key) and that VM's name.
    #[serde(default)]
    pub clone_of: Option<(String, String)>,
}

/// Everything a deploy needs, for every VM it makes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploySpec {
    pub origin: DeployOrigin,
    pub hypervisor: Hypervisor,
    pub source: DeploySource,
    /// The folder each VM's own folder (`<folder>\<name>`) goes in: the template's, or the hypervisor's default
    /// as it was when the deploy was planned.
    pub folder: String,
    /// The OS profile's values; `None` for a bulk clone (each VM keeps its source's).
    pub profile: Option<ProfileSpec>,
    /// The size; `None` for a bulk clone.
    pub size: Option<SizeSpec>,
    /// The first network card's network; `None`: a clone or an import keeps its own.
    pub network: Option<Network>,
    /// VirtualBox's host-only or bridged adapter, when the network needs one (`None`: the first VirtualBox lists).
    #[serde(default)]
    pub host_adapter: Option<String>,
    /// VM-22: cloud-init's first-boot setup; `None` when the guest has none (Windows, an ISO install, a bulk clone).
    pub first_boot: Option<FirstBootSpec>,
    /// SS-09: the vault key whose public half is in `first_boot`, for the SSH session made after deploy.
    pub ssh_key_id: Option<SecretId>,
    pub environment: Environment,
    pub tags: Vec<String>,
    pub after_deploy: AfterDeploy,
    /// How long the after-deploy steps wait for a guest IP, in seconds.
    pub ip_wait_secs: u32,
    /// VirtualBox: an ISO it installs by itself (`unattended install`), as this user with a vault password.
    #[serde(default)]
    pub unattended: Option<UnattendedSpec>,
    pub vms: Vec<DeployVm>,
    /// VM-08: a step of a stack deploy: each VM made joins this stack instance, at this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<crate::stacks::StackTag>,
}

/// How long after-deploy steps wait for the guest's IP by default: first boots with cloud-init take a minute or
/// two before the guest tools report one.
pub const DEFAULT_IP_WAIT_SECS: u32 = 5 * 60;
pub const MAX_IP_WAIT_SECS: u32 = 60 * 60;
/// Longest folder path a deploy takes (Windows' own limit is 260 without long paths).
pub const MAX_FOLDER_CHARS: usize = 200;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

impl DeploySpec {
    /// A template's (or Custom) plan, into the folder `folder` (absolute), with `host_adapter` for VirtualBox.
    pub fn from_plan(plan: &DeployPlan, origin: DeployOrigin, folder: String, host_adapter: Option<String>) -> Self {
        let source = match &plan.image.source {
            ImageSource::GoldenVm {
                vm_key,
                snapshot_id,
                snapshot_name,
            } => DeploySource::GoldenVm {
                vm_key: vm_key.clone(),
                vm_name: plan.image.vm_name.clone().unwrap_or_else(|| plan.image.name.clone()),
                snapshot_id: snapshot_id.clone(),
                snapshot_name: snapshot_name.clone(),
                linked: plan.clone_mode == CloneMode::Linked,
            },
            ImageSource::CloudImage { path, format } => DeploySource::CloudImage {
                path: path.clone(),
                format: *format,
            },
            ImageSource::Iso { path } => DeploySource::Iso { path: path.clone() },
            ImageSource::Appliance { path, format } => DeploySource::Appliance {
                path: path.clone(),
                format: *format,
            },
        };
        let family = crate::catalog::profiles::profile(plan.profile.id).map_or(GuestFamily::Linux, |p| p.family);
        // VM-22: cloud-init is a Linux guest's, and an ISO install has no guest yet.
        let first_boot =
            (family == GuestFamily::Linux && !matches!(source, DeploySource::Iso { .. })).then(|| FirstBootSpec {
                user: plan.guest_user.clone(),
                public_key: plan.ssh_key.as_ref().map(|k| k.public_key.clone()),
                packages: plan.packages.clone(),
            });
        Self {
            origin,
            hypervisor: plan.hypervisor,
            source,
            folder,
            profile: Some(ProfileSpec {
                id: plan.profile.id.to_owned(),
                name: plan.profile.name.to_owned(),
                family,
                firmware: plan.profile.firmware,
                guest_os: plan.profile.guest_os.to_owned(),
                hardware_version: plan.profile.hardware_version,
                nic: plan.profile.nic.to_owned(),
                tpm: plan.profile.tpm.map(str::to_owned),
            }),
            size: Some(SizeSpec {
                id: plan.size.id.clone(),
                name: plan.size.name.clone(),
                sockets: plan.size.sockets,
                cores_per_socket: plan.size.cores_per_socket,
                memory_mb: plan.size.memory_mb,
                disks: plan
                    .size
                    .disks
                    .iter()
                    .map(|d| DiskPlan {
                        size_gb: d.size_gb,
                        provisioning: d.provisioning,
                        controller: d.controller,
                        controller_model: d.controller_model.to_owned(),
                    })
                    .collect(),
            }),
            network: Some(plan.network.clone()),
            host_adapter,
            first_boot,
            ssh_key_id: plan.ssh_key.as_ref().map(|k| k.id),
            environment: plan.environment,
            tags: plan.tags.clone(),
            after_deploy: plan.after_deploy,
            ip_wait_secs: DEFAULT_IP_WAIT_SECS,
            unattended: None,
            stack: None,
            vms: plan
                .vms
                .iter()
                .map(|vm| DeployVm {
                    number: vm.number,
                    name: vm.name.clone(),
                    hostname: vm.hostname.clone(),
                    clone_of: None,
                })
                .collect(),
        }
    }

    /// The command's targets: one new VM each, labelled as it will be.
    pub fn targets(&self) -> Vec<TargetRef> {
        self.vms
            .iter()
            .map(|vm| TargetRef::NewVm {
                hypervisor: self.hypervisor,
                name: vm.name.clone(),
                environment: self.environment,
            })
            .collect()
    }

    /// The VM a target names.
    pub fn vm(&self, name: &str) -> Option<&DeployVm> {
        self.vms.iter().find(|vm| vm.name.eq_ignore_ascii_case(name))
    }

    /// `<folder>\<name>`: the folder the VM's files go in, which the deploy makes and nothing else may have.
    pub fn vm_folder(&self, vm: &DeployVm) -> std::path::PathBuf {
        std::path::Path::new(&self.folder).join(&vm.name)
    }

    /// Disk each VM may take, thin disks at their full size (the worst case); `None` when the deploy doesn't
    /// decide it (a clone keeps its source's disks; see the preview).
    pub fn disk_gb_per_vm(&self) -> Option<u64> {
        let size = self.size.as_ref()?;
        Some(size.disks.iter().map(|d| u64::from(d.size_gb)).sum())
    }

    /// For the job's summary.
    pub fn summary(&self) -> String {
        let n = self.vms.len();
        let noun = if n == 1 { "VM" } else { "VMs" };
        match &self.origin {
            DeployOrigin::BulkClone => format!("Clone {n} {noun}"),
            DeployOrigin::Template { name, .. } => format!("Deploy {n} {noun} from '{name}'"),
            DeployOrigin::Custom { .. } => format!("Deploy {n} {noun} (custom)"),
            DeployOrigin::Import { name } => match self.vms.as_slice() {
                [vm] => format!("Import {} from {name}", vm.name),
                _ => format!("Import {n} {noun} from {name}"),
            },
        }
    }

    /// What the audit log says the deploy is.
    pub fn describe(&self) -> String {
        let mut parts = vec![
            format!("from {}", self.origin.describe()),
            format!("on {}", templates::hypervisor_label(self.hypervisor)),
            self.source.describe(),
            format!("in {}", self.folder),
        ];
        if let Some(size) = &self.size {
            parts.push(format!("size {}", size.describe()));
        }
        if let Some(network) = &self.network {
            parts.push(format!("network {}", network.describe()));
        }
        if let Some(first_boot) = &self.first_boot {
            let user = first_boot.user.as_deref().unwrap_or("the image's default user");
            let key = if first_boot.public_key.is_some() {
                "with the SSH key"
            } else {
                "without an SSH key"
            };
            parts.push(format!(
                "cloud-init: {user} {key}, packages {}",
                templates::tags_text(&first_boot.packages)
            ));
        }
        parts.push(format!("environment {}", self.environment.as_str()));
        parts.push(format!("after deploy: {}", self.after_deploy.describe()));
        parts.join("; ")
    }

    /// Checked on the bus, whoever built it: names a folder can hold once each, paths Remotely may open, cloud-init
    /// values it can write, and a source that fits the hypervisor.
    pub fn validate(&self) -> Result<()> {
        if self.vms.is_empty() || self.vms.len() > MAX_DEPLOY_COUNT as usize {
            return invalid(format!("A deploy makes 1 to {MAX_DEPLOY_COUNT} VMs."));
        }
        let mut names = std::collections::HashSet::new();
        for vm in &self.vms {
            templates::expand(&vm.name, "", 1, time::macros::date!(2026 - 01 - 01))
                .map_err(|_| CoreError::InvalidInput(format!("'{}' can't be a VM's name.", vm.name)))?;
            if vm.name.contains(['{', '}']) {
                return invalid(format!("'{}' can't be a VM's name.", vm.name));
            }
            if !names.insert(vm.name.to_lowercase()) {
                return invalid(format!("Two VMs are named '{}'.", vm.name));
            }
            if templates::hostname(&vm.hostname, vm.number) != vm.hostname {
                return invalid(format!("'{}' can't be a hostname.", vm.hostname));
            }
            if vm.clone_of.is_some() != matches!(self.source, DeploySource::BulkClone) {
                return invalid("A bulk clone names each VM's source; other deploys name none.");
            }
        }
        let folder = std::path::Path::new(&self.folder);
        if !folder.is_absolute() || self.folder.chars().count() > MAX_FOLDER_CHARS {
            return invalid(format!("'{}' isn't a full path to a folder on this PC.", self.folder));
        }
        if let Some(refusal) = untrusted::path_refusal(&self.folder) {
            return invalid(format!("The VM folder {} {}.", self.folder, refusal.describe()));
        }
        if let Some(path) = self.source.path() {
            if let Some(refusal) = untrusted::path_refusal(path) {
                return invalid(format!("The image {path} {}.", refusal.describe()));
            }
        }
        if let DeploySource::Import { disks, description } = &self.source {
            if disks.is_empty() || disks.len() > MAX_IMPORT_DISKS {
                return invalid(format!("An import brings 1 to {MAX_IMPORT_DISKS} disks."));
            }
            for path in disks.iter().map(|d| d.path.as_str()).chain(description.as_deref()) {
                if !std::path::Path::new(path).is_absolute() {
                    return invalid(format!("'{path}' isn't a full path on this PC."));
                }
                if let Some(refusal) = untrusted::path_refusal(path) {
                    return invalid(format!("The disk {path} {}.", refusal.describe()));
                }
            }
            if self.size.as_ref().is_some_and(|s| s.disks.len() < disks.len()) {
                return invalid("The size has fewer disks than the import brings.");
            }
        }
        if let Some(network) = &self.network {
            if network.only_on().is_some_and(|only| only != self.hypervisor) {
                return invalid(format!(
                    "The network {} isn't {}'s.",
                    network.describe(),
                    templates::hypervisor_label(self.hypervisor)
                ));
            }
        }
        match (&self.source, &self.size, &self.profile) {
            (DeploySource::BulkClone, None, None) => {}
            (DeploySource::BulkClone, _, _) => return invalid("A bulk clone keeps each VM's own size."),
            (_, Some(size), Some(_)) => {
                if size.disks.is_empty() || size.vcpus() == 0 || size.memory_mb == 0 {
                    return invalid("The size has no CPU, memory or disk.");
                }
            }
            _ => return invalid("A deploy needs a size and an OS profile."),
        }
        if let Some(first_boot) = &self.first_boot {
            if check_guest_user(first_boot.user.as_deref())? != first_boot.user {
                return invalid("The guest user isn't one cloud-init can make.");
            }
            if check_packages(&first_boot.packages)? != first_boot.packages {
                return invalid("The package list isn't one cloud-init can install.");
            }
            if let Some(key) = &first_boot.public_key {
                crate::ssh_keys::parse_public_key(key)?;
            }
        }
        if let Some(adapter) = &self.host_adapter {
            if adapter.is_empty() || adapter.len() > 200 || adapter.chars().any(char::is_control) {
                return invalid("The VirtualBox host adapter's name is damaged.");
            }
        }
        if let Some(unattended) = &self.unattended {
            if self.hypervisor != Hypervisor::VirtualBox || !matches!(self.source, DeploySource::Iso { .. }) {
                return invalid("Only VirtualBox installs an ISO unattended.");
            }
            if check_guest_user(Some(&unattended.user))?.as_deref() != Some(unattended.user.as_str()) {
                return invalid("The unattended install's user isn't one VirtualBox can make.");
            }
        }
        if self.ip_wait_secs > MAX_IP_WAIT_SECS {
            return invalid("The wait for the guest's IP is at most an hour.");
        }
        if self.after_deploy.link_session && !self.after_deploy.create_session {
            return invalid("Linking a session to the VM needs the session.");
        }
        if self.stack.is_some() && matches!(self.source, DeploySource::BulkClone) {
            return invalid("A stack deploys launch templates, not bulk clones.");
        }
        Ok(())
    }

    /// The same deploy for only these targets (BX-04: retry the VMs that failed).
    pub fn only(&self, targets: &[TargetRef]) -> Self {
        let keep: std::collections::HashSet<String> = targets.iter().map(TargetRef::key).collect();
        let mut spec = self.clone();
        let targets = self.targets();
        spec.vms = self
            .vms
            .iter()
            .zip(targets)
            .filter(|(_, target)| keep.contains(&target.key()))
            .map(|(vm, _)| vm.clone())
            .collect();
        spec
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::catalog::images::Image;
    use crate::catalog::sizes::built_in;
    use crate::catalog::templates::{resolve, KeyState, Refs, TemplateInput};
    use crate::ssh_keys::PublicKeyInfo;

    pub(crate) fn plan(source: ImageSource, profile: &str, hypervisor: Hypervisor, count: u32) -> DeployPlan {
        let image = Image {
            id: Uuid::from_u128(7),
            name: "noble".into(),
            source,
            hypervisors: Hypervisor::ALL.to_vec(),
            os_profile: profile.into(),
            sha256: None,
            size_bytes: None,
            notes: None,
            created_at: String::new(),
            updated_at: String::new(),
            problem: None,
            vm_name: Some("golden".into()),
        };
        let size = built_in("disk.large").unwrap();
        let template = TemplateInput {
            name: "web".into(),
            image_id: image.id,
            size_id: "disk.large".into(),
            hypervisor,
            vm_folder: None,
            network: Network::HostOnly,
            ssh_key_id: Some(SecretId(Uuid::from_u128(9))),
            naming_pattern: "web-{n}".into(),
            default_count: 1,
            environment: Environment::Lab,
            tags: vec!["web".into()],
            after_deploy: AfterDeploy::default(),
            guest_user: Some("alice".into()),
            packages: vec!["nginx".into()],
            clone_mode: CloneMode::Linked,
        };
        let key = PublicKeyInfo {
            algorithm: "ssh-ed25519".into(),
            line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsCAmNoAwH4cIJF5qbX0yLzXMLEMY8EW8HXBfvbiJmW alice@example.com"
                .into(),
            fingerprint: "SHA256:example".into(),
            comment: "alice@example.com".into(),
            bits: None,
        };
        let refs = Refs {
            image: Some(&image),
            size: Some(&size),
            key: KeyState::Ready(key),
        };
        resolve(
            Uuid::from_u128(1),
            &template,
            &refs,
            count,
            &[],
            time::macros::date!(2026 - 10 - 25),
        )
        .unwrap()
    }

    pub(crate) fn cloud() -> ImageSource {
        ImageSource::CloudImage {
            path: r"C:\Images\noble.vmdk".into(),
            format: ImageFormat::Vmdk,
        }
    }

    fn make(source: ImageSource, profile: &str) -> DeploySpec {
        DeploySpec::from_plan(
            &plan(source, profile, Hypervisor::Vmware, 2),
            DeployOrigin::Template {
                id: Uuid::from_u128(1),
                name: "web".into(),
            },
            r"C:\VMs\lab".into(),
            None,
        )
    }

    #[test]
    fn a_plan_becomes_a_spec_with_its_first_boot_setup() {
        let spec = make(cloud(), "ubuntu");
        assert_eq!(
            spec.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            ["web-1", "web-2"]
        );
        let first_boot = spec.first_boot.as_ref().unwrap();
        assert_eq!(first_boot.user.as_deref(), Some("alice"));
        assert!(first_boot.public_key.as_deref().unwrap().starts_with("ssh-ed25519 "));
        assert_eq!(first_boot.packages, ["nginx"]);
        assert_eq!(spec.disk_gb_per_vm(), Some(540));
        assert_eq!(spec.size.as_ref().unwrap().boot_disk_gb(), 40);
        assert_eq!(spec.vm_folder(&spec.vms[0]), std::path::Path::new(r"C:\VMs\lab\web-1"));
        spec.validate().unwrap();
        assert_eq!(spec.summary(), "Deploy 2 VMs from 'web'");
        let text = spec.describe();
        assert!(
            text.contains("cloud-init: alice with the SSH key, packages nginx"),
            "{text}"
        );
        assert!(
            !text.contains("AAAA"),
            "the audit log names the key, not its data: {text}"
        );

        // Windows has no cloud-init; neither has an ISO install.
        assert_eq!(
            super::DeploySpec::from_plan(
                &plan(cloud(), "windows-server", Hypervisor::Vmware, 1),
                DeployOrigin::Custom { name: "w".into() },
                r"C:\VMs".into(),
                None
            )
            .first_boot,
            None
        );
        let iso = spec_iso();
        assert_eq!(iso.first_boot, None);
        // A golden VM's clone mode.
        let golden = make(
            ImageSource::GoldenVm {
                vm_key: r"C:\VMs\golden\golden.vmx".into(),
                snapshot_id: "3".into(),
                snapshot_name: "base".into(),
            },
            "ubuntu",
        );
        assert!(golden.source.is_linked());
        assert!(golden
            .source
            .describe()
            .contains("a linked clone of 'golden' at its snapshot 'base'"));
    }

    fn spec_iso() -> DeploySpec {
        make(
            ImageSource::Iso {
                path: r"C:\ISOs\noble.iso".into(),
            },
            "ubuntu",
        )
    }

    #[test]
    fn targets_are_new_vms_with_the_deploys_label() {
        let mut spec = make(cloud(), "ubuntu");
        spec.environment = Environment::Prod;
        let targets = spec.targets();
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[0],
            TargetRef::NewVm {
                hypervisor: Hypervisor::Vmware,
                name: "web-1".into(),
                environment: Environment::Prod
            }
        );
        let only = spec.only(&targets[1..]);
        assert_eq!(only.vms.len(), 1);
        assert_eq!(only.vms[0].name, "web-2");
    }

    #[test]
    fn a_damaged_spec_is_refused() {
        let ok = make(cloud(), "ubuntu");
        let bad = |change: &dyn Fn(&mut DeploySpec), why: &str| {
            let mut s = ok.clone();
            change(&mut s);
            let err = s.validate().unwrap_err().to_string();
            assert!(err.contains(why), "{why}: {err}");
        };
        bad(&|s| s.vms.clear(), "1 to 50");
        bad(&|s| s.vms[1].name = "WEB-1".into(), "Two VMs are named");
        bad(&|s| s.vms[0].name = r"..\x".into(), "can't be a VM's name");
        bad(&|s| s.vms[0].name = "NUL".into(), "can't be a VM's name");
        bad(&|s| s.vms[0].hostname = "Web 1".into(), "can't be a hostname");
        bad(&|s| s.folder = "VMs".into(), "full path");
        bad(&|s| s.folder = r"\\fileserver.example.com\vms".into(), "network share");
        bad(
            &|s| {
                s.source = DeploySource::Iso {
                    path: r"\\?\C:\x.iso".into(),
                }
            },
            "The image",
        );
        bad(
            &|s| s.network = Some(Network::Internal { name: "lab".into() }),
            "isn't Workstation's",
        );
        bad(&|s| s.size = None, "needs a size");
        bad(
            &|s| s.first_boot.as_mut().unwrap().packages = vec!["x;reboot".into()],
            "isn't a package name",
        );
        bad(
            &|s| s.first_boot.as_mut().unwrap().public_key = Some("not a key".into()),
            "",
        );
        bad(&|s| s.vms[0].clone_of = Some(("k".into(), "n".into())), "bulk clone");
        bad(&|s| s.ip_wait_secs = 7200, "at most an hour");
        // A round trip through the journal keeps it whole.
        let text = serde_json::to_string(&ok).unwrap();
        assert_eq!(serde_json::from_str::<DeploySpec>(&text).unwrap(), ok);
    }
}
