//! VM-11, VM-12, VM-15, VM-16, VM-23, VM-24: what a VM settings or lifecycle command asks for, the checks
//! that need no VM (sizes, names, what each hypervisor has at all), and how it reads in dialogs, jobs and the
//! audit log. The policy engine rates each kind ([`crate::policy::ActionKind`]); [`super::VmEditor`] carries
//! them out.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vm_hardware::normal_mac;
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};
use crate::untrusted::path_refusal;

/// VM-23, VM-12, VM-11: a change to a powered-off VM's settings, or (VMware) its hardware version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum VmConfigEdit {
    /// VM-12, VM-23: vCPUs, cores per socket (Workstation only), memory and nested virtualization. A field
    /// left out keeps its value; bulk resize sends the same values to every VM.
    Resources {
        #[serde(default)]
        vcpus: Option<u32>,
        #[serde(default)]
        cores_per_socket: Option<u32>,
        #[serde(default)]
        memory_mb: Option<u32>,
        #[serde(default)]
        nested_virtualization: Option<bool>,
    },
    /// VM-23: BIOS or UEFI, Secure Boot (UEFI only), and on VirtualBox a TPM 2.0.
    Firmware {
        firmware: Firmware,
        #[serde(default)]
        secure_boot: bool,
        /// VirtualBox: a TPM 2.0 (Windows 11). `None` keeps what the VM has. Workstation's needs the VM
        /// encrypted, which Remotely doesn't do.
        #[serde(default)]
        tpm: Option<bool>,
    },
    /// VM-24: the name Workstation and VirtualBox show (VirtualBox renames the VM's folder and files too).
    Rename {
        name: String,
    },
    /// VM-23: the guest OS the VM is set up for: Workstation's `guestOS` id (`ubuntu-64`), VirtualBox's OS type
    /// id (`Ubuntu_64`).
    GuestOs {
        os_type: String,
    },
    /// VM-11: a new network adapter.
    AddNic {
        network: NicNetwork,
        /// The emulated card (`vmxnet3`, `e1000e`; VirtualBox `virtio`, `82540EM`). `None`: the hypervisor's
        /// default.
        #[serde(default)]
        model: Option<String>,
    },
    /// VM-11: one adapter's network, card, MAC or whether it is plugged in when the VM starts.
    EditNic {
        slot: String,
        #[serde(default)]
        network: Option<NicNetwork>,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        mac: Option<MacAddress>,
        #[serde(default)]
        connect_at_power_on: Option<bool>,
    },
    RemoveNic {
        slot: String,
    },
    /// VM-23: shares a folder of this PC with the guest. The path comes from a folder dialog in the shell,
    /// never from the UI ([`crate::command_bus::Command::check_from_ui`]): the guest can read what is in it.
    AddSharedFolder {
        name: String,
        host_path: String,
        #[serde(default)]
        writable: bool,
    },
    RemoveSharedFolder {
        name: String,
    },
    /// VM-23: `vmrun upgradevm`, to the newest hardware version this Workstation has. It can't be undone.
    UpgradeHardware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Firmware {
    Bios,
    Efi,
}

impl Firmware {
    pub fn label(self) -> &'static str {
        match self {
            Firmware::Bios => "BIOS",
            Firmware::Efi => "UEFI",
        }
    }
}

/// VM-11: what a network adapter is attached to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum NicNetwork {
    Nat,
    /// The guest joins this PC's network. VirtualBox names the host adapter; Workstation picks it (VMnet0).
    Bridged {
        #[serde(default)]
        adapter: Option<String>,
    },
    /// A network of this PC and its VMs only. VirtualBox names the host-only adapter.
    HostOnly {
        #[serde(default)]
        adapter: Option<String>,
    },
    /// Workstation: a virtual network by name (`VMnet2`).
    Custom {
        vnet: String,
    },
    /// VirtualBox: a NAT network by name.
    NatNetwork {
        name: String,
    },
    /// VirtualBox: an internal network by name.
    Internal {
        name: String,
    },
}

impl NicNetwork {
    pub fn describe(&self) -> String {
        match self {
            NicNetwork::Nat => "NAT".into(),
            NicNetwork::Bridged { adapter: None } => "bridged".into(),
            NicNetwork::Bridged { adapter: Some(a) } => format!("bridged to {a}"),
            NicNetwork::HostOnly { adapter: None } => "host-only".into(),
            NicNetwork::HostOnly { adapter: Some(a) } => format!("host-only ({a})"),
            NicNetwork::Custom { vnet } => format!("custom ({vnet})"),
            NicNetwork::NatNetwork { name } => format!("NAT network {name}"),
            NicNetwork::Internal { name } => format!("internal network {name}"),
        }
    }
}

/// VM-11: a network adapter's MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum MacAddress {
    /// The hypervisor makes one (a new one, for a VM copied from another).
    Generated,
    Static {
        mac: String,
    },
}

/// VM-23, VM-11, VM-15: devices that change while the VM runs too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum VmDeviceOp {
    /// An ISO image into a CD/DVD drive (`slot`, or the VM's first). From a file dialog or a drop in the
    /// shell, never from the UI: the guest can read the file.
    AttachIso {
        #[serde(default)]
        slot: Option<String>,
        path: String,
    },
    EjectIso {
        #[serde(default)]
        slot: Option<String>,
    },
    /// VM-11: plug a network adapter in: now on a running VM, at power-on on one that is off.
    ConnectNic {
        slot: String,
    },
    DisconnectNic {
        slot: String,
    },
    /// VM-15: `vmrun installTools` (VMware Tools' installer in the guest), or VirtualBox's
    /// `VBoxGuestAdditions.iso` in the VM's CD/DVD drive. The VM must run.
    InstallTools,
}

/// VM-16: virtual disks. The VM must be off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum VmDiskOp {
    /// A new disk file in the VM's folder, on the boot disk's controller (or `bus`).
    Add {
        size_mb: u64,
        /// Grows as the guest writes; thick allocates it all now.
        #[serde(default = "thin_by_default")]
        thin: bool,
        /// Workstation `scsi0`, `sata0`, `nvme0`; VirtualBox a controller's name. `None`: the boot disk's.
        #[serde(default)]
        bus: Option<String>,
    },
    /// Grows a disk; it can't be shrunk back. The guest's partition still has to be grown in the guest.
    Expand { slot: String, size_mb: u64 },
    /// Gives back the space the guest freed (`vdiskmanager -k`, `modifymedium --compact`).
    Compact { slot: String },
    /// Workstation only: `vdiskmanager -d`.
    Defragment { slot: String },
    /// Takes the disk off the VM and deletes its files.
    Remove { slot: String },
}

fn thin_by_default() -> bool {
    true
}

/// VM-24: a VM as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum VmLifecycleOp {
    /// `vmrun deleteVM`, `unregistervm --delete`: the VM and its files go.
    Delete,
    /// Adds an existing VM: a `.vmx` to the VMs Remotely lists, a `.vbox` to VirtualBox (`registervm`). Built
    /// by the core from a file dialog, never by the UI; the target is the VM it adds.
    Register { path: String },
}

/// Most vCPUs a VM may be given (Workstation's and VirtualBox's own limits are lower on most PCs; they say).
pub const MAX_VCPUS: u32 = 64;
/// Most memory: 1 TB.
pub const MAX_MEMORY_MB: u32 = 1024 * 1024;
/// Largest disk: 8 TB, vdiskmanager's limit.
pub const MAX_DISK_MB: u64 = 8 * 1024 * 1024;
pub const MAX_NAME: usize = 80;

/// "4 GB", "1.5 GB", "512 MB" (binary, as the hypervisors count memory and disks).
pub fn size_mb(mb: u64) -> String {
    if mb >= 1024 * 1024 && mb.is_multiple_of(1024 * 1024) {
        format!("{} TB", mb / (1024 * 1024))
    } else if mb >= 1024 {
        let gb = mb as f64 / 1024.0;
        if mb.is_multiple_of(1024) {
            format!("{gb:.0} GB")
        } else {
            format!("{gb:.1} GB")
        }
    } else {
        format!("{mb} MB")
    }
}

fn invalid(message: impl Into<String>) -> Result<()> {
    Err(CoreError::InvalidInput(message.into()))
}

/// Every target a VM, each once; the hypervisors of the targets.
fn vm_hypervisors(targets: &[TargetRef]) -> Result<Vec<Hypervisor>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for target in targets {
        let TargetRef::Vm { vmx_path } = target else {
            return Err(CoreError::InvalidInput("VM settings change VMs only.".into()));
        };
        if !seen.insert(vmx_path.to_lowercase()) {
            return Err(CoreError::InvalidInput("A VM is listed twice.".into()));
        }
        out.push(Hypervisor::of_key(vmx_path));
    }
    Ok(out)
}

/// A name either hypervisor takes, and that VirtualBox can make a folder of.
pub fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return invalid("Give the VM a name.");
    }
    if name.trim() != name {
        return invalid("A VM's name can't start or end with a space.");
    }
    if name.chars().count() > MAX_NAME {
        return invalid(format!("A VM's name can be at most {MAX_NAME} characters."));
    }
    if name.chars().any(|c| c.is_control() || r#"\/:*?"<>|"#.contains(c)) {
        return invalid(
            r#"A VM's name can't hold \ / : * ? " < > | or line breaks: VirtualBox names its folder after it."#,
        );
    }
    Ok(())
}

/// A slot as the hypervisors name them: `ethernet0`, `nic1`, `scsi0:1`, `SATA-0-0`.
fn validate_slot(slot: &str) -> Result<()> {
    if slot.is_empty() || slot.len() > 128 || slot.chars().any(char::is_control) {
        return invalid(format!("'{slot}' is not a device slot."));
    }
    Ok(())
}

fn validate_nic_slot(slot: &str, hypervisor: Hypervisor) -> Result<()> {
    let ok = match hypervisor {
        Hypervisor::Vmware => slot
            .strip_prefix("ethernet")
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| n < 10),
        Hypervisor::VirtualBox => slot
            .strip_prefix("nic")
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| (1..=8).contains(&n)),
    };
    if ok {
        Ok(())
    } else {
        invalid(format!(
            "'{slot}' is not a network adapter of a {} VM.",
            hypervisor.label()
        ))
    }
}

/// A name for a network, a folder or an OS type: letters, digits, spaces and `_ . - ( )`.
fn validate_word(what: &str, text: &str, spaces: bool) -> Result<()> {
    let ok = !text.trim().is_empty()
        && text.len() <= 128
        && text
            .chars()
            .all(|c| c.is_alphanumeric() || "_.-()".contains(c) || (spaces && c == ' '));
    if ok {
        Ok(())
    } else {
        invalid(format!("'{text}' can't be {what}."))
    }
}

fn validate_model(model: &Option<String>) -> Result<()> {
    match model {
        Some(m) => validate_word("a network card type", m, false),
        None => Ok(()),
    }
}

/// VM-11: a network a hypervisor has.
fn validate_network(network: &NicNetwork, hypervisor: Hypervisor) -> Result<()> {
    match (network, hypervisor) {
        (NicNetwork::Custom { vnet }, Hypervisor::Vmware) => {
            let n = vnet
                .strip_prefix("VMnet")
                .or_else(|| vnet.strip_prefix("vmnet"))
                .and_then(|n| n.parse::<u32>().ok());
            if n.is_some_and(|n| n <= 19) {
                Ok(())
            } else {
                invalid(format!(
                    "'{vnet}' is not a Workstation virtual network (VMnet0 to VMnet19)."
                ))
            }
        }
        (NicNetwork::Custom { .. }, Hypervisor::VirtualBox) => {
            invalid("VirtualBox has no VMnet networks: use a host-only adapter, a NAT network or an internal network.")
        }
        (NicNetwork::NatNetwork { .. } | NicNetwork::Internal { .. }, Hypervisor::Vmware) => invalid(
            "NAT networks and internal networks are VirtualBox's: on Workstation use NAT, host-only or a VMnet.",
        ),
        (NicNetwork::NatNetwork { name } | NicNetwork::Internal { name }, Hypervisor::VirtualBox) => {
            validate_word("a network's name", name, true)
        }
        (NicNetwork::Bridged { adapter } | NicNetwork::HostOnly { adapter }, _) => match adapter {
            Some(a) => validate_word("a host adapter's name", a, true).or_else(|_| {
                // Host adapters are named by Windows ("Intel(R) Ethernet Connection #2").
                if a.trim().is_empty() || a.len() > 256 || a.chars().any(char::is_control) || a.contains('"') {
                    invalid(format!("'{a}' can't be a host adapter's name."))
                } else {
                    Ok(())
                }
            }),
            None => Ok(()),
        },
        (NicNetwork::Nat, _) => Ok(()),
    }
}

/// VM-11: Workstation takes a hand-picked MAC only from VMware's own range, 00:50:56:00:00:00 to
/// 00:50:56:3F:FF:FF; VirtualBox takes any unicast MAC.
pub fn check_mac(mac: &str, hypervisor: Hypervisor) -> Result<String> {
    let normal = normal_mac(mac).ok_or_else(|| CoreError::InvalidInput(format!("'{mac}' is not a MAC address.")))?;
    let first = u8::from_str_radix(&normal[..2], 16).unwrap_or(1);
    if first & 1 == 1 {
        return Err(CoreError::InvalidInput(format!(
            "{normal} is a multicast address; a network adapter needs a unicast one."
        )));
    }
    if hypervisor == Hypervisor::Vmware {
        let fourth = u8::from_str_radix(&normal[9..11], 16).unwrap_or(0xff);
        if !normal.starts_with("00:50:56:") || fourth > 0x3f {
            return Err(CoreError::InvalidInput(format!(
                "Workstation takes a hand-picked MAC only from 00:50:56:00:00:00 to 00:50:56:3F:FF:FF; {normal} is outside it."
            )));
        }
    }
    Ok(normal)
}

/// A local path the hypervisor may open: absolute, not on a share or a device path (A3).
fn validate_host_path(what: &str, path: &str) -> Result<()> {
    if path.chars().any(char::is_control) || path.contains('"') {
        return invalid(format!("'{path}' can't be {what}."));
    }
    if let Some(refusal) = path_refusal(path) {
        return invalid(format!(
            "{what} {path} {}, so Remotely doesn't use it: copy it to this PC first.",
            refusal.describe()
        ));
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return invalid(format!("'{path}' is not a full path on this PC."));
    }
    Ok(())
}

pub fn validate_config(targets: &[TargetRef], edit: &VmConfigEdit) -> Result<()> {
    for hypervisor in vm_hypervisors(targets)? {
        match edit {
            VmConfigEdit::Resources {
                vcpus,
                cores_per_socket,
                memory_mb,
                nested_virtualization,
            } => {
                if vcpus.is_none()
                    && cores_per_socket.is_none()
                    && memory_mb.is_none()
                    && nested_virtualization.is_none()
                {
                    return invalid("Choose the vCPUs, the cores per socket, the memory or nested virtualization.");
                }
                if let Some(n) = vcpus {
                    if !(1..=MAX_VCPUS).contains(n) {
                        return invalid(format!("A VM can have 1 to {MAX_VCPUS} vCPUs."));
                    }
                }
                if let Some(cores) = cores_per_socket {
                    if hypervisor == Hypervisor::VirtualBox {
                        return invalid(
                            "VirtualBox gives a VM vCPUs, not sockets and cores: leave the cores per socket out.",
                        );
                    }
                    if *cores == 0 || vcpus.is_some_and(|n| !n.is_multiple_of(*cores)) {
                        return invalid("The cores per socket must divide the vCPUs.");
                    }
                }
                if let Some(mb) = memory_mb {
                    if !(4..=MAX_MEMORY_MB).contains(mb) {
                        return invalid(format!(
                            "A VM can have 4 MB to {} of memory.",
                            size_mb(MAX_MEMORY_MB.into())
                        ));
                    }
                    if hypervisor == Hypervisor::Vmware && mb % 4 != 0 {
                        return invalid("Workstation takes memory in steps of 4 MB.");
                    }
                }
            }
            VmConfigEdit::Firmware {
                firmware,
                secure_boot,
                tpm,
            } => {
                if *secure_boot && *firmware == Firmware::Bios {
                    return invalid("Secure Boot needs UEFI firmware.");
                }
                if tpm.is_some_and(|on| on) && hypervisor == Hypervisor::Vmware {
                    return invalid(
                        "Workstation's virtual TPM needs the VM encrypted with a password of its own, which Remotely doesn't do: add it in Workstation.",
                    );
                }
                if tpm.is_some_and(|on| on) && *firmware == Firmware::Bios {
                    return invalid("A TPM 2.0 needs UEFI firmware.");
                }
            }
            VmConfigEdit::Rename { name } => validate_name(name)?,
            VmConfigEdit::GuestOs { os_type } => validate_word("a guest OS type", os_type, false)?,
            VmConfigEdit::AddNic { network, model } => {
                validate_network(network, hypervisor)?;
                validate_model(model)?;
            }
            VmConfigEdit::EditNic {
                slot,
                network,
                model,
                mac,
                connect_at_power_on,
            } => {
                validate_nic_slot(slot, hypervisor)?;
                if network.is_none() && model.is_none() && mac.is_none() && connect_at_power_on.is_none() {
                    return invalid("Choose what to change on the network adapter.");
                }
                if let Some(network) = network {
                    validate_network(network, hypervisor)?;
                }
                validate_model(model)?;
                if let Some(MacAddress::Static { mac }) = mac {
                    check_mac(mac, hypervisor)?;
                }
            }
            VmConfigEdit::RemoveNic { slot } => validate_nic_slot(slot, hypervisor)?,
            VmConfigEdit::AddSharedFolder { name, host_path, .. } => {
                validate_word("a shared folder's name", name, true)?;
                validate_host_path("the shared folder", host_path)?;
            }
            VmConfigEdit::RemoveSharedFolder { name } => validate_word("a shared folder's name", name, true)?,
            VmConfigEdit::UpgradeHardware => {
                if hypervisor == Hypervisor::VirtualBox {
                    return invalid("VirtualBox VMs have no hardware version to upgrade.");
                }
            }
        }
    }
    Ok(())
}

pub fn validate_device(targets: &[TargetRef], op: &VmDeviceOp) -> Result<()> {
    for hypervisor in vm_hypervisors(targets)? {
        match op {
            VmDeviceOp::AttachIso { slot, path } => {
                if let Some(slot) = slot {
                    validate_slot(slot)?;
                }
                validate_host_path("the ISO image", path)?;
                let iso = Path::new(path)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("iso"));
                if !iso {
                    return invalid(format!("'{path}' is not an ISO image (.iso)."));
                }
            }
            VmDeviceOp::EjectIso { slot } => {
                if let Some(slot) = slot {
                    validate_slot(slot)?;
                }
            }
            VmDeviceOp::ConnectNic { slot } | VmDeviceOp::DisconnectNic { slot } => {
                validate_nic_slot(slot, hypervisor)?;
            }
            VmDeviceOp::InstallTools => {}
        }
    }
    Ok(())
}

pub fn validate_disk(targets: &[TargetRef], op: &VmDiskOp) -> Result<()> {
    for hypervisor in vm_hypervisors(targets)? {
        match op {
            VmDiskOp::Add { size_mb: mb, bus, .. } => {
                if !(1..=MAX_DISK_MB).contains(mb) {
                    return invalid(format!("A disk can be 1 MB to {}.", size_mb(MAX_DISK_MB)));
                }
                if let Some(bus) = bus {
                    validate_slot(bus)?;
                    if hypervisor == Hypervisor::Vmware
                        && !["scsi", "sata", "nvme", "ide"]
                            .iter()
                            .any(|f| bus.strip_prefix(f).is_some_and(|n| n.parse::<u32>().is_ok()))
                    {
                        return invalid(format!(
                            "'{bus}' is not a Workstation disk controller (scsi0, sata0, nvme0, ide0)."
                        ));
                    }
                }
            }
            VmDiskOp::Expand { slot, size_mb: mb } => {
                validate_slot(slot)?;
                if !(1..=MAX_DISK_MB).contains(mb) {
                    return invalid(format!("A disk can be 1 MB to {}.", size_mb(MAX_DISK_MB)));
                }
            }
            VmDiskOp::Compact { slot } | VmDiskOp::Remove { slot } => validate_slot(slot)?,
            VmDiskOp::Defragment { slot } => {
                validate_slot(slot)?;
                if hypervisor == Hypervisor::VirtualBox {
                    return invalid("VirtualBox has no defragment for its disks: compact the disk instead.");
                }
            }
        }
    }
    Ok(())
}

pub fn validate_lifecycle(targets: &[TargetRef], op: &VmLifecycleOp) -> Result<()> {
    let hypervisors = vm_hypervisors(targets)?;
    if let VmLifecycleOp::Register { path } = op {
        validate_host_path("the VM's file", path)?;
        let [TargetRef::Vm { vmx_path }] = targets else {
            return invalid("Add one VM at a time.");
        };
        let ext = Path::new(path)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase());
        match (ext.as_deref(), hypervisors.first()) {
            (Some("vmx"), Some(Hypervisor::Vmware)) if vmx_path.eq_ignore_ascii_case(path) => {}
            (Some("vbox"), Some(Hypervisor::VirtualBox)) => {}
            (Some("vmx" | "vbox"), _) => return invalid("The VM to add doesn't match its file."),
            _ => {
                return invalid(format!(
                    "'{path}' is not a Workstation .vmx or a VirtualBox .vbox file."
                ))
            }
        }
    }
    Ok(())
}

fn noun(count: usize, kind: &str) -> String {
    if count == 1 {
        format!("1 {kind}")
    } else {
        format!("{count} {kind}s")
    }
}

/// The file name of a path, for summaries (the whole path is in the preview).
fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map_or_else(|| path.to_owned(), |n| n.to_string_lossy().into_owned())
}

impl VmConfigEdit {
    pub fn summary(&self, targets: usize) -> String {
        let vms = noun(targets, "VM");
        match self {
            VmConfigEdit::Resources {
                vcpus,
                cores_per_socket,
                memory_mb,
                nested_virtualization,
            } => {
                let mut parts = Vec::new();
                if let Some(n) = vcpus {
                    parts.push(if *n == 1 {
                        "1 vCPU".to_owned()
                    } else {
                        format!("{n} vCPUs")
                    });
                }
                if let Some(cores) = cores_per_socket {
                    parts.push(format!("{cores} cores per socket"));
                }
                if let Some(mb) = memory_mb {
                    parts.push(format!("{} of memory", size_mb((*mb).into())));
                }
                if let Some(on) = nested_virtualization {
                    parts.push(format!("nested virtualization {}", if *on { "on" } else { "off" }));
                }
                format!("Set {} on {vms}", parts.join(", "))
            }
            VmConfigEdit::Firmware {
                firmware,
                secure_boot,
                tpm,
            } => {
                let mut what = format!("{} firmware", firmware.label());
                if *firmware == Firmware::Efi {
                    what.push_str(if *secure_boot {
                        " with Secure Boot"
                    } else {
                        " without Secure Boot"
                    });
                }
                match tpm {
                    Some(true) => what.push_str(" and a TPM 2.0"),
                    Some(false) => what.push_str(", no TPM"),
                    None => {}
                }
                format!("Set {what} on {vms}")
            }
            VmConfigEdit::Rename { name } => format!("Rename {vms} to '{name}'"),
            VmConfigEdit::GuestOs { os_type } => format!("Set the guest OS type of {vms} to {os_type}"),
            VmConfigEdit::AddNic { network, .. } => {
                format!("Add a network adapter ({}) to {vms}", network.describe())
            }
            VmConfigEdit::EditNic { slot, .. } => format!("Change network adapter {slot} of {vms}"),
            VmConfigEdit::RemoveNic { slot } => format!("Remove network adapter {slot} from {vms}"),
            VmConfigEdit::AddSharedFolder { name, writable, .. } => {
                let how = if *writable { "read and write" } else { "read only" };
                format!("Share a folder as '{name}' ({how}) with {vms}")
            }
            VmConfigEdit::RemoveSharedFolder { name } => format!("Stop sharing '{name}' with {vms}"),
            VmConfigEdit::UpgradeHardware => format!("Upgrade the hardware version of {vms}"),
        }
    }
}

impl VmDeviceOp {
    pub fn summary(&self, targets: usize) -> String {
        let vms = noun(targets, "VM");
        match self {
            VmDeviceOp::AttachIso { path, .. } => format!("Attach {} to {vms}", file_name(path)),
            VmDeviceOp::EjectIso { .. } => format!("Eject the CD/DVD of {vms}"),
            VmDeviceOp::ConnectNic { slot } => format!("Connect network adapter {slot} of {vms}"),
            VmDeviceOp::DisconnectNic { slot } => format!("Disconnect network adapter {slot} of {vms}"),
            VmDeviceOp::InstallTools => format!("Install or upgrade the guest tools on {vms}"),
        }
    }
}

impl VmDiskOp {
    pub fn summary(&self, targets: usize) -> String {
        let vms = noun(targets, "VM");
        match self {
            VmDiskOp::Add { size_mb: mb, thin, .. } => {
                let how = if *thin { "thin" } else { "thick" };
                format!("Add a {} disk ({how}) to {vms}", size_mb(*mb))
            }
            VmDiskOp::Expand { slot, size_mb: mb } => format!("Expand disk {slot} of {vms} to {}", size_mb(*mb)),
            VmDiskOp::Compact { slot } => format!("Compact disk {slot} of {vms}"),
            VmDiskOp::Defragment { slot } => format!("Defragment disk {slot} of {vms}"),
            VmDiskOp::Remove { slot } => format!("Remove disk {slot} from {vms} and delete its files"),
        }
    }

    pub fn slot(&self) -> Option<&str> {
        match self {
            VmDiskOp::Add { .. } => None,
            VmDiskOp::Expand { slot, .. }
            | VmDiskOp::Compact { slot }
            | VmDiskOp::Defragment { slot }
            | VmDiskOp::Remove { slot } => Some(slot),
        }
    }
}

impl VmLifecycleOp {
    pub fn summary(&self, targets: usize) -> String {
        match self {
            VmLifecycleOp::Delete if targets == 1 => "Delete 1 VM and its files".to_owned(),
            VmLifecycleOp::Delete => format!("Delete {targets} VMs and their files"),
            VmLifecycleOp::Register { path } => format!("Add an existing VM: {}", file_name(path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB: &str = r"C:\VMs\web01\web01.vmx";
    const VBOX: &str = "3f0c1a2b-1111-4222-8333-444455556666";

    fn vm(key: &str) -> Vec<TargetRef> {
        vec![TargetRef::Vm { vmx_path: key.into() }]
    }

    fn resources(vcpus: Option<u32>, cores: Option<u32>, memory: Option<u32>) -> VmConfigEdit {
        VmConfigEdit::Resources {
            vcpus,
            cores_per_socket: cores,
            memory_mb: memory,
            nested_virtualization: None,
        }
    }

    #[test]
    fn resources_stay_within_what_the_hypervisors_take() {
        assert!(validate_config(&vm(WEB), &resources(Some(4), Some(2), Some(8192))).is_ok());
        assert!(validate_config(&vm(WEB), &resources(Some(0), None, None)).is_err());
        assert!(validate_config(&vm(WEB), &resources(Some(65), None, None)).is_err());
        assert!(
            validate_config(&vm(WEB), &resources(Some(6), Some(4), None)).is_err(),
            "4 doesn't divide 6"
        );
        assert!(
            validate_config(&vm(WEB), &resources(None, None, Some(1026))).is_err(),
            "steps of 4 MB"
        );
        assert!(validate_config(&vm(VBOX), &resources(None, None, Some(1026))).is_ok());
        assert!(
            validate_config(&vm(VBOX), &resources(Some(2), Some(1), None)).is_err(),
            "no sockets"
        );
        assert!(
            validate_config(&vm(WEB), &resources(None, None, None)).is_err(),
            "nothing to change"
        );
        let both = vec![
            TargetRef::Vm { vmx_path: WEB.into() },
            TargetRef::Vm {
                vmx_path: WEB.to_uppercase(),
            },
        ];
        assert!(
            validate_config(&both, &resources(Some(2), None, None)).is_err(),
            "listed twice"
        );
    }

    #[test]
    fn each_hypervisor_is_asked_only_for_what_it_has() {
        let upgrade = VmConfigEdit::UpgradeHardware;
        assert!(validate_config(&vm(WEB), &upgrade).is_ok());
        assert!(validate_config(&vm(VBOX), &upgrade).is_err());
        let tpm = VmConfigEdit::Firmware {
            firmware: Firmware::Efi,
            secure_boot: true,
            tpm: Some(true),
        };
        assert!(validate_config(&vm(VBOX), &tpm).is_ok());
        assert!(
            validate_config(&vm(WEB), &tpm).is_err(),
            "Workstation's vTPM needs encryption"
        );
        let bios_secure = VmConfigEdit::Firmware {
            firmware: Firmware::Bios,
            secure_boot: true,
            tpm: None,
        };
        assert!(validate_config(&vm(WEB), &bios_secure).is_err());
        let defrag = VmDiskOp::Defragment {
            slot: "SATA-0-0".into(),
        };
        assert!(validate_disk(&vm(VBOX), &defrag).is_err());
        assert!(validate_disk(&vm(WEB), &VmDiskOp::Defragment { slot: "scsi0:0".into() }).is_ok());
        let vnet = VmConfigEdit::AddNic {
            network: NicNetwork::Custom { vnet: "VMnet2".into() },
            model: Some("vmxnet3".into()),
        };
        assert!(validate_config(&vm(WEB), &vnet).is_ok());
        assert!(validate_config(&vm(VBOX), &vnet).is_err());
        let intnet = VmConfigEdit::AddNic {
            network: NicNetwork::Internal { name: "lab net".into() },
            model: None,
        };
        assert!(validate_config(&vm(VBOX), &intnet).is_ok());
        assert!(validate_config(&vm(WEB), &intnet).is_err());
        assert!(validate_device(&vm(WEB), &VmDeviceOp::ConnectNic { slot: "nic1".into() }).is_err());
        assert!(validate_device(&vm(VBOX), &VmDeviceOp::ConnectNic { slot: "nic1".into() }).is_ok());
        assert!(validate_device(&vm(VBOX), &VmDeviceOp::ConnectNic { slot: "nic9".into() }).is_err());
    }

    #[test]
    fn workstation_takes_hand_picked_macs_from_its_own_range_only() {
        assert_eq!(
            check_mac("00:50:56:3F:00:01", Hypervisor::Vmware).unwrap(),
            "00:50:56:3f:00:01"
        );
        assert!(check_mac("00:50:56:40:00:01", Hypervisor::Vmware).is_err());
        assert!(check_mac("08:00:27:00:00:01", Hypervisor::Vmware).is_err());
        assert_eq!(
            check_mac("080027000001", Hypervisor::VirtualBox).unwrap(),
            "08:00:27:00:00:01"
        );
        assert!(
            check_mac("01:00:5e:00:00:01", Hypervisor::VirtualBox).is_err(),
            "multicast"
        );
        assert!(check_mac("not a mac", Hypervisor::VirtualBox).is_err());
    }

    #[test]
    fn names_isos_and_shared_folders_are_checked() {
        assert!(validate_name("web 02").is_ok());
        assert!(validate_name(" web").is_err());
        assert!(validate_name("web/02").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name(&"x".repeat(81)).is_err());
        let iso = |path: &str| VmDeviceOp::AttachIso {
            slot: None,
            path: path.into(),
        };
        assert!(validate_device(&vm(WEB), &iso(r"C:\ISOs\ubuntu-24.04.iso")).is_ok());
        assert!(validate_device(&vm(WEB), &iso(r"C:\ISOs\notes.txt")).is_err());
        assert!(validate_device(&vm(WEB), &iso(r"\\nas.example.com\isos\ubuntu.iso")).is_err());
        assert!(validate_device(&vm(WEB), &iso(r"\\?\C:\ISOs\ubuntu.iso")).is_err());
        assert!(
            validate_device(&vm(WEB), &iso("ubuntu.iso")).is_err(),
            "not a full path"
        );
        let share = |path: &str| VmConfigEdit::AddSharedFolder {
            name: "data".into(),
            host_path: path.into(),
            writable: false,
        };
        assert!(validate_config(&vm(WEB), &share(r"C:\Shared\data")).is_ok());
        assert!(validate_config(&vm(WEB), &share(r"\\nas.example.com\data")).is_err());
        let disk = |mb| VmDiskOp::Add {
            size_mb: mb,
            thin: true,
            bus: None,
        };
        assert!(validate_disk(&vm(WEB), &disk(20 * 1024)).is_ok());
        assert!(validate_disk(&vm(WEB), &disk(0)).is_err());
        assert!(validate_disk(&vm(WEB), &disk(MAX_DISK_MB + 1)).is_err());
    }

    #[test]
    fn an_added_vm_matches_its_file() {
        let vmx = VmLifecycleOp::Register { path: WEB.into() };
        assert!(validate_lifecycle(&vm(WEB), &vmx).is_ok());
        assert!(validate_lifecycle(&vm(r"C:\VMs\other\other.vmx"), &vmx).is_err());
        let vbox = VmLifecycleOp::Register {
            path: r"C:\VirtualBox VMs\db01\db01.vbox".into(),
        };
        assert!(validate_lifecycle(&vm(VBOX), &vbox).is_ok());
        assert!(validate_lifecycle(&vm(WEB), &vbox).is_err());
        let share = VmLifecycleOp::Register {
            path: r"\\nas.example.com\vms\web.vmx".into(),
        };
        assert!(validate_lifecycle(&vm(r"\\nas.example.com\vms\web.vmx"), &share).is_err());
    }

    #[test]
    fn summaries_say_what_changes() {
        assert_eq!(
            resources(Some(4), None, Some(8192)).summary(3),
            "Set 4 vCPUs, 8 GB of memory on 3 VMs"
        );
        assert_eq!(
            VmDiskOp::Add {
                size_mb: 20 * 1024,
                thin: true,
                bus: None
            }
            .summary(1),
            "Add a 20 GB disk (thin) to 1 VM"
        );
        assert_eq!(VmLifecycleOp::Delete.summary(2), "Delete 2 VMs and their files");
        assert_eq!(
            VmDeviceOp::AttachIso {
                slot: None,
                path: r"C:\ISOs\ubuntu.iso".into()
            }
            .summary(1),
            "Attach ubuntu.iso to 1 VM"
        );
        assert_eq!(size_mb(1536), "1.5 GB");
        assert_eq!(size_mb(512), "512 MB");
        assert_eq!(size_mb(2 * 1024 * 1024), "2 TB");
    }
}
