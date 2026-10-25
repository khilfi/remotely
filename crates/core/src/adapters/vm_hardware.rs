//! MO-13: a VM's virtual hardware, read from the hypervisor's own files on this PC. Reads only; nothing
//! here starts a program or changes a file.
//!
//! * VMware: the `.vmx` (vCPUs, cores per socket, memory, firmware, hardware version, the guest OS chosen
//!   for the VM and what VMware Tools reported in `guestInfo.detailed.data`, each virtual disk on a
//!   `scsiX:Y`, `sataX:Y`, `nvmeX:Y` or `ideX:Y` slot, each network adapter and its MAC).
//! * VirtualBox: what `showvminfo` printed (VM-18's [`VboxVmInfo`]: OS type, CPUs, memory, firmware,
//!   disks and adapters) and the Guest Additions' OS properties.
//! * Each virtual disk's provisioned size comes from its own header or descriptor: a VMDK's text
//!   descriptor (its extents' sectors) or sparse header (`KDMV`, capacity in sectors), a VDI header,
//!   a VHD footer or a qcow2 header. Its size on disk is what its files take on this PC; for a
//!   VMware snapshot's delta disk that is the whole chain down to the base disk, through
//!   `parentFileNameHint`.
//!
//! Hostile files (A3, A9): the .vmx, VMDK descriptors and `showvminfo` name disk files, and any of
//! them may come from someone else (a VM copied from a customer, an appliance). A disk, extent or
//! parent whose path (after it is resolved against its folder) is on a network share or a device path
//! ([`path_refusal`]) is never opened, since Windows would send the user's sign-in to that server: the
//! disk shows its path, no sizes and a note. So a .vmx the user keeps on a share is read (its place is
//! the user's choice), but its disks there are not. The .vmx is read whole only up to
//! [`MAX_VM_CONFIG_BYTES`], a text VMDK descriptor up to [`MAX_DESCRIPTOR`]; a larger one is reported,
//! never read in part.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::virtualbox::VboxVmInfo;
use crate::untrusted::{path_refusal, read_capped, size_words, ReadError, MAX_VM_CONFIG_BYTES};

/// A VM's virtual hardware as its hypervisor's files describe it. VM-23 reads all of it into the Settings tab;
/// facts read before 0.5.0 (stored as JSON, migration 0014) lack the newer fields, which then read as empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmHardware {
    /// The guest OS chosen for the VM: Workstation's id (`ubuntu-64`) or VirtualBox's OS type
    /// ("Ubuntu (64-bit)").
    pub guest_os: Option<String>,
    /// What the guest tools report, e.g. "Ubuntu 24.04.1 LTS" or "Windows 11 Pro".
    pub guest_os_name: Option<String>,
    /// The guest's kernel, when its tools report one ("6.8.0-45-generic").
    pub guest_kernel: Option<String>,
    pub vcpus: Option<u32>,
    pub cores_per_socket: Option<u32>,
    pub memory_mb: Option<u32>,
    /// "BIOS" or "UEFI".
    pub firmware: Option<String>,
    /// VMware's virtual hardware version, e.g. "21".
    pub hardware_version: Option<String>,
    pub disks: Vec<VirtualDisk>,
    pub nics: Vec<VirtualNic>,
    /// VM-23: hardware virtualization passed on to the guest (VMware `vhv.enable`, VirtualBox `nested-hw-virt`).
    pub nested_virtualization: Option<bool>,
    /// VM-23: UEFI Secure Boot; `None` for BIOS firmware.
    pub secure_boot: Option<bool>,
    /// VM-23: the virtual TPM, e.g. "TPM 2.0"; `None` when the VM has none.
    pub tpm: Option<String>,
    /// VM-23: storage controllers (`scsi0`, `sata0`, VirtualBox's `SATA`) and their kind.
    pub controllers: Vec<StorageController>,
    /// VM-23: CD/DVD drives.
    pub cdroms: Vec<VirtualCdrom>,
    /// VM-23: USB controllers, e.g. "USB 2.0", "USB 3.x"; empty when the VM has no USB.
    pub usb: Vec<String>,
    /// VM-23: the sound card, e.g. "HD Audio"; `None` when the VM has none.
    pub sound: Option<String>,
    pub display: Option<VirtualDisplay>,
    pub serial_ports: Vec<SerialPort>,
    pub shared_folders: Vec<SharedFolder>,
    /// VM-23: VirtualBox's Guest Additions version, as they report it.
    pub tools_version: Option<String>,
    /// VM-23: every address the guest tools report (VirtualBox's Guest Additions list each adapter's; for
    /// Workstation the inventory's one address).
    pub guest_ips: Vec<String>,
}

/// VM-23: a storage controller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StorageController {
    /// `scsi0`, `sata0`, `nvme0`, `ide1` (VMware) or the controller's name (VirtualBox, e.g. `SATA`).
    pub name: String,
    /// `pvscsi`, `lsisas1068`, `lsilogic`, `SATA (AHCI)`, `NVMe`, `IDE`; VirtualBox's `IntelAhci`, `PIIX4`...
    pub kind: Option<String>,
    /// VirtualBox: the ports it has now.
    pub ports: Option<u32>,
}

/// VM-23: a CD/DVD drive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VirtualCdrom {
    /// `sata0:1` (VMware) or `SATA-1-0` (VirtualBox).
    pub slot: String,
    /// The ISO image in it.
    pub image: Option<String>,
    /// A drive of this PC instead of an image ("auto detect", `D:`).
    pub host_drive: Option<String>,
    /// VMware: connected when the VM powers on.
    pub connected: Option<bool>,
}

/// VM-23: the virtual display.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VirtualDisplay {
    pub video_memory_mb: Option<u32>,
    pub accelerate_3d: Option<bool>,
    pub monitors: Option<u32>,
    /// VirtualBox's graphics controller (`vmsvga`, `vboxsvga`).
    pub controller: Option<String>,
}

/// VM-23: a serial port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SerialPort {
    /// `serial0` (VMware) or `COM1` (VirtualBox).
    pub slot: String,
    /// `file`, `pipe`, `device`, `tcp`, `disconnected`...
    pub kind: String,
    /// The file, pipe, device or address it uses.
    pub target: Option<String>,
}

/// VM-23: a folder of this PC shared with the guest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SharedFolder {
    /// The name the guest sees.
    pub name: String,
    pub host_path: String,
    pub writable: Option<bool>,
    /// VMware: on; VirtualBox: mounted by itself in the guest.
    pub enabled: Option<bool>,
}

impl VmHardware {
    /// Sockets, when the cores per socket divide the vCPUs.
    pub fn sockets(&self) -> Option<u32> {
        let (vcpus, cores) = (self.vcpus?, self.cores_per_socket?);
        (cores > 0 && vcpus % cores == 0).then(|| vcpus / cores)
    }
}

/// One virtual disk attached to a VM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VirtualDisk {
    /// Where it is attached: `scsi0:0`, `nvme0:1` (VMware) or `SATA-0-0` (VirtualBox).
    pub slot: String,
    /// The disk file, as a full path on this PC.
    pub path: String,
    /// What kind of file: `monolithicSparse`, `twoGbMaxExtentSparse`, `VDI (dynamic)`, `VHD`...
    pub format: Option<String>,
    /// The size the guest sees.
    pub provisioned_bytes: Option<u64>,
    /// What the disk's files take on this PC.
    pub on_disk_bytes: Option<u64>,
    /// Files counted in `on_disk_bytes`: extents, and a delta disk's parents down to its base.
    pub files: u32,
    /// A snapshot's delta disk (VMware) or differencing image (VirtualBox).
    pub delta: bool,
    /// Why a size is missing, in words for the user.
    pub problem: Option<String>,
    /// VM-23: the kind of controller it is on (`pvscsi`, `SATA (AHCI)`, `NVMe`, VirtualBox's `IntelAhci`).
    pub controller: Option<String>,
    /// VM-23: thin (grows as the guest writes) or thick (allocated in full), when its format says.
    pub thin: Option<bool>,
    /// VM-23: a snapshot delta's parents down to the base disk, nearest first, as their files are named.
    pub chain: Vec<String>,
}

/// One network adapter of a VM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VirtualNic {
    /// `ethernet0` (VMware) or `nic1` (VirtualBox).
    pub slot: String,
    /// `nat`, `bridged`, `hostonly`, `custom (VMnet2)`, VirtualBox's `natnetwork`, `intnet`...
    pub connection: Option<String>,
    /// The emulated card: `vmxnet3`, `e1000e`, VirtualBox's `82540EM` or `virtio`.
    pub model: Option<String>,
    /// `00:0c:29:ab:cd:ef`, lower case with colons.
    pub mac: Option<String>,
    /// VMware's `startConnected`: plugged in when the VM powers on.
    pub connected: Option<bool>,
    /// VM-11: the network by name: VMware's vnet (`VMnet2`), VirtualBox's bridged or host-only adapter, NAT
    /// network or internal network.
    pub network_name: Option<String>,
    /// VM-11: plugged in right now (VirtualBox's virtual cable). Workstation can't be asked.
    pub connected_now: Option<bool>,
    /// VM-11: a MAC chosen by hand (VMware `addressType = "static"`).
    pub static_mac: bool,
}

/// Bytes of a disk header read at most. Descriptors are a few hundred bytes; a sparse VMDK's
/// embedded descriptor is at most a few kilobytes.
const MAX_HEADER: u64 = 64 * 1024;
/// A text VMDK descriptor longer than [`MAX_HEADER`] (thousands of 2 GB extents) is read whole up to
/// this; a larger one is not read.
pub const MAX_DESCRIPTOR: u64 = 1024 * 1024;
/// Delta disks followed at most, down to the base disk.
const MAX_CHAIN: usize = 32;

/// How MO-13 reads a VM's files: this PC's file system in the app ([`LocalFiles`]), memory in tests, so
/// a test can show that a refused path is never asked for.
pub(crate) trait VmFiles: Sync {
    /// The whole file, when it is at most `cap` bytes.
    async fn read(&self, path: &Path, cap: u64) -> Result<Vec<u8>, ReadError>;
    /// The first `max` bytes of a file, and its size.
    async fn head(&self, path: &Path, max: u64) -> std::io::Result<(Vec<u8>, u64)>;
    /// The last 512 bytes of a file of `size` bytes (a fixed VHD's footer).
    async fn tail(&self, path: &Path, size: u64) -> std::io::Result<Vec<u8>>;
    /// A file's size.
    async fn len(&self, path: &Path) -> std::io::Result<u64>;
}

/// The files on this PC.
pub(crate) struct LocalFiles;

impl VmFiles for LocalFiles {
    async fn read(&self, path: &Path, cap: u64) -> Result<Vec<u8>, ReadError> {
        read_capped(path, cap).await
    }

    async fn head(&self, path: &Path, max: u64) -> std::io::Result<(Vec<u8>, u64)> {
        let mut file = tokio::fs::File::open(path).await?;
        let size = file.metadata().await?.len();
        let mut head = Vec::new();
        (&mut file).take(max).read_to_end(&mut head).await?;
        Ok((head, size))
    }

    async fn tail(&self, path: &Path, size: u64) -> std::io::Result<Vec<u8>> {
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(size.saturating_sub(512))).await?;
        let mut tail = Vec::new();
        file.take(512).read_to_end(&mut tail).await?;
        Ok(tail)
    }

    async fn len(&self, path: &Path) -> std::io::Result<u64> {
        tokio::fs::metadata(path).await.map(|meta| meta.len())
    }
}

// ---- VMware .vmx ----

/// One `key = "value"` line of a .vmx, with the key in lower case and `|XX` escapes undone.
fn vmx_pairs(text: &str) -> BTreeMap<String, String> {
    let mut pairs = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        pairs.insert(key.trim().to_ascii_lowercase(), unescape(value));
    }
    pairs
}

/// VMware config files write some bytes as `|XX` (hex).
fn unescape(value: &str) -> String {
    if !value.contains('|') {
        return value.to_owned();
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'|' && i + 2 < bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn truthy(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// `key='value'` pairs of VMware Tools' `guestInfo.detailed.data`.
pub fn detailed_data(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = text;
    while let Some(eq) = rest.find("='") {
        let key = rest[..eq].trim().rsplit(' ').next().unwrap_or("").to_owned();
        let after = &rest[eq + 2..];
        let Some(end) = after.find('\'') else {
            break;
        };
        if !key.is_empty() {
            out.insert(key, after[..end].trim().to_owned());
        }
        rest = &after[end + 1..];
    }
    out
}

/// A .vmx's virtual disk on one slot, before its files are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmxDisk {
    pub slot: String,
    /// As written in the .vmx: usually relative to its folder.
    pub file_name: String,
    /// VM-23: the kind of controller its bus is ([`vmx_controller_kind`]).
    pub controller: Option<String>,
}

/// What a .vmx says about the VM's hardware. Disk sizes come from [`read_disk`].
pub fn parse_vmx_hardware(text: &str) -> (VmHardware, Vec<VmxDisk>) {
    let pairs = vmx_pairs(text);
    let get = |key: &str| pairs.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());
    let detailed = get("guestinfo.detailed.data")
        .or_else(|| get("guestos.detailed.data"))
        .map(detailed_data)
        .unwrap_or_default();
    let on = |key: &str| get(key).and_then(truthy).unwrap_or(false);
    let efi = get("firmware").is_some_and(|f| f.eq_ignore_ascii_case("efi"));
    let mut hardware = VmHardware {
        guest_os: get("guestos").map(str::to_owned),
        guest_os_name: detailed.get("prettyName").filter(|v| !v.is_empty()).cloned(),
        guest_kernel: detailed.get("kernelVersion").filter(|v| !v.is_empty()).cloned(),
        vcpus: get("numvcpus").and_then(|v| v.parse().ok()).or(Some(1)),
        cores_per_socket: get("cpuid.corespersocket").and_then(|v| v.parse().ok()),
        memory_mb: get("memsize").and_then(|v| v.parse().ok()),
        firmware: Some(if efi { "UEFI".to_owned() } else { "BIOS".to_owned() }),
        hardware_version: get("virtualhw.version").map(str::to_owned),
        nested_virtualization: Some(on("vhv.enable")),
        secure_boot: efi.then(|| on("uefi.secureboot.enabled")),
        tpm: on("vtpm.present").then(|| "TPM 2.0".to_owned()),
        ..VmHardware::default()
    };
    hardware.controllers = vmx_controllers(&pairs);
    hardware.cdroms = vmx_cdroms(&pairs);
    hardware.usb = [
        ("usb.present", "USB 1.1"),
        ("ehci.present", "USB 2.0"),
        ("usb_xhci.present", "USB 3.x"),
    ]
    .into_iter()
    .filter(|(key, _)| on(key))
    .map(|(_, name)| name.to_owned())
    .collect();
    hardware.sound =
        on("sound.present").then(
            || match get("sound.virtualdev").map(str::to_ascii_lowercase).as_deref() {
                Some("hdaudio") => "HD Audio".to_owned(),
                Some("es1371") => "Sound Blaster AudioPCI".to_owned(),
                Some("sb16") => "Sound Blaster 16".to_owned(),
                Some(other) => other.to_owned(),
                None => "Sound card".to_owned(),
            },
        );
    let video_kb: Option<u64> = get("svga.graphicsmemorykb").and_then(|v| v.parse().ok());
    let vram_bytes: Option<u64> = get("svga.vramsize").and_then(|v| v.parse().ok());
    hardware.display = Some(VirtualDisplay {
        video_memory_mb: video_kb
            .map(|kb| kb / 1024)
            .or(vram_bytes.map(|b| b / (1024 * 1024)))
            .and_then(|mb| u32::try_from(mb).ok()),
        accelerate_3d: Some(on("mks.enable3d")),
        monitors: get("svga.numdisplays").and_then(|v| v.parse().ok()),
        controller: None,
    });
    hardware.serial_ports = numbered(&pairs, "serial")
        .into_iter()
        .filter(|n| on(&format!("serial{n}.present")))
        .map(|n| SerialPort {
            slot: format!("serial{n}"),
            kind: get(&format!("serial{n}.filetype")).unwrap_or("device").to_owned(),
            target: get(&format!("serial{n}.filename")).map(str::to_owned),
        })
        .collect();
    let folders_off = on("isolation.tools.hgfs.disable");
    hardware.shared_folders = numbered(&pairs, "sharedfolder")
        .into_iter()
        .filter(|n| on(&format!("sharedfolder{n}.present")))
        .map(|n| {
            let field = |name: &str| get(&format!("sharedfolder{n}.{name}")).map(str::to_owned);
            SharedFolder {
                name: field("guestname").unwrap_or_default(),
                host_path: field("hostpath").unwrap_or_default(),
                writable: field("writeaccess").and_then(|v| truthy(&v)),
                enabled: Some(!folders_off && field("enabled").and_then(|v| truthy(&v)).unwrap_or(false)),
            }
        })
        .collect();

    // Disks: `<bus><n>:<m>.fileName` on a present device that is not a CD/DVD.
    let mut disks = Vec::new();
    for (key, value) in &pairs {
        let Some(slot) = key.strip_suffix(".filename") else {
            continue;
        };
        let bus_ok = ["scsi", "sata", "nvme", "ide"].iter().any(|bus| {
            slot.strip_prefix(bus)
                .and_then(|r| r.split_once(':'))
                .is_some_and(|(a, b)| is_digits(a) && is_digits(b))
        });
        if !bus_ok {
            continue;
        }
        if pairs
            .get(&format!("{slot}.present"))
            .and_then(|v| truthy(v))
            .is_some_and(|p| !p)
        {
            continue;
        }
        let device = pairs
            .get(&format!("{slot}.devicetype"))
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_default();
        let file = value.trim();
        if device.contains("cdrom") || !file.to_ascii_lowercase().ends_with(".vmdk") {
            continue;
        }
        disks.push(VmxDisk {
            slot: slot.to_owned(),
            file_name: file.to_owned(),
            controller: vmx_controller_kind(&pairs, slot_bus(slot)),
        });
    }
    disks.sort_by_key(|d| slot_order(&d.slot));

    // Network adapters: `ethernet<n>.present = "TRUE"`.
    let mut nics: Vec<(u32, VirtualNic)> = Vec::new();
    for (key, value) in &pairs {
        let Some(n) = key
            .strip_prefix("ethernet")
            .and_then(|r| r.strip_suffix(".present"))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if truthy(value) != Some(true) {
            continue;
        }
        let field = |name: &str| get(&format!("ethernet{n}.{name}")).map(str::to_owned);
        let connection = match field("connectiontype").map(|c| c.to_ascii_lowercase()).as_deref() {
            // Workstation leaves the type out for a bridged adapter.
            None => Some("bridged".to_owned()),
            Some("custom") => Some(match field("vnet") {
                Some(vnet) => format!("custom ({vnet})"),
                None => "custom".to_owned(),
            }),
            Some(other) => Some(other.to_owned()),
        };
        let static_mac = field("addresstype").is_some_and(|t| t.eq_ignore_ascii_case("static"));
        let mac = if static_mac {
            field("address")
        } else {
            field("generatedaddress").or_else(|| field("address"))
        };
        let network_name = field("connectiontype")
            .filter(|c| c.eq_ignore_ascii_case("custom"))
            .and_then(|_| field("vnet"));
        nics.push((
            n,
            VirtualNic {
                slot: format!("ethernet{n}"),
                connection,
                model: field("virtualdev"),
                mac: mac.as_deref().and_then(normal_mac),
                connected: field("startconnected").and_then(|v| truthy(&v)),
                network_name,
                connected_now: None,
                static_mac,
            },
        ));
    }
    nics.sort_by_key(|(n, _)| *n);
    hardware.nics = nics.into_iter().map(|(_, nic)| nic).collect();
    (hardware, disks)
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The numbers `n` of `<prefix><n>.` keys, in order (`serial0`, `serial1`...).
fn numbered(pairs: &BTreeMap<String, String>, prefix: &str) -> Vec<u32> {
    let mut found: Vec<u32> = pairs
        .keys()
        .filter_map(|key| key.strip_prefix(prefix)?.split_once('.')?.0.parse().ok())
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// The bus of a `scsi0:1`-style slot: `scsi0`.
pub fn slot_bus(slot: &str) -> &str {
    slot.split_once(':').map_or(slot, |(bus, _)| bus)
}

/// VM-23: what kind of controller a .vmx bus is: `scsi0.virtualDev` (Workstation's default for SCSI is LSI
/// Logic), or the bus itself.
pub fn vmx_controller_kind(pairs: &BTreeMap<String, String>, bus: &str) -> Option<String> {
    let family: String = bus.chars().take_while(char::is_ascii_alphabetic).collect();
    match family.as_str() {
        "scsi" => Some(
            pairs
                .get(&format!("{bus}.virtualdev"))
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "lsilogic".to_owned()),
        ),
        "sata" => Some("SATA (AHCI)".to_owned()),
        "nvme" => Some("NVMe".to_owned()),
        "ide" => Some("IDE".to_owned()),
        _ => None,
    }
}

/// VM-23: the .vmx's storage controllers: each `<bus><n>.present = "TRUE"`, and the IDE buses its devices use
/// (Workstation writes `ide1:0.present` without `ide1.present`).
fn vmx_controllers(pairs: &BTreeMap<String, String>) -> Vec<StorageController> {
    let mut buses: Vec<String> = Vec::new();
    for (key, value) in pairs {
        for family in ["scsi", "sata", "nvme", "ide"] {
            let Some(rest) = key.strip_prefix(family) else {
                continue;
            };
            let (n, field) = match rest.split_once(['.', ':']) {
                Some((n, field)) if is_digits(n) => (n, field),
                _ => continue,
            };
            let controller_present =
                !rest[n.len()..].starts_with(':') && field == "present" && truthy(value) == Some(true);
            let device_on_ide = family == "ide" && rest[n.len()..].starts_with(':');
            if controller_present || device_on_ide {
                let bus = format!("{family}{n}");
                if !buses.contains(&bus) {
                    buses.push(bus);
                }
            }
        }
    }
    buses.sort_by_key(|bus| slot_order(bus));
    buses
        .into_iter()
        .map(|bus| StorageController {
            kind: vmx_controller_kind(pairs, &bus),
            name: bus,
            ports: None,
        })
        .collect()
}

/// VM-23: the .vmx's CD/DVD drives: devices whose `deviceType` is `cdrom-image` (an ISO), `cdrom-raw` or
/// `atapi-cdrom` (a drive of this PC).
fn vmx_cdroms(pairs: &BTreeMap<String, String>) -> Vec<VirtualCdrom> {
    let mut drives: Vec<VirtualCdrom> = Vec::new();
    for (key, value) in pairs {
        let Some(slot) = key.strip_suffix(".devicetype") else {
            continue;
        };
        let kind = value.trim().to_ascii_lowercase();
        if !kind.contains("cdrom") {
            continue;
        }
        if pairs.get(&format!("{slot}.present")).and_then(|v| truthy(v)) == Some(false) {
            continue;
        }
        let file = pairs
            .get(&format!("{slot}.filename"))
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
        let (image, host_drive) = if kind == "cdrom-image" {
            (file, None)
        } else {
            (None, Some(file.unwrap_or_else(|| "auto detect".to_owned())))
        };
        drives.push(VirtualCdrom {
            slot: slot.to_owned(),
            image,
            host_drive,
            connected: pairs.get(&format!("{slot}.startconnected")).and_then(|v| truthy(v)),
        });
    }
    drives.sort_by_key(|d| slot_order(&d.slot));
    drives
}

/// VM-23: thin or thick, from a disk's format.
pub fn thin_format(format: &str) -> Option<bool> {
    let f = format.to_ascii_lowercase();
    if f.contains("sparse") || f.contains("streamoptimized") || f.contains("dynamic") || f.contains("qcow") {
        Some(true)
    } else if f.contains("flat") || f.contains("fixed") || f.contains("vmfs") || f.contains("preallocated") {
        Some(false)
    } else {
        None
    }
}

/// `scsi0:1` sorts by bus name, then the numbers as numbers.
fn slot_order(slot: &str) -> (String, u32, u32) {
    let bus: String = slot.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
    let rest = &slot[bus.len()..];
    let (a, b) = rest.split_once(':').unwrap_or((rest, "0"));
    (bus, a.parse().unwrap_or(0), b.parse().unwrap_or(0))
}

/// `00:0C:29:AB:CD:EF`, `00-0c-29-ab-cd-ef` or VirtualBox's `080027AABB01`, as `00:0c:29:ab:cd:ef`.
pub fn normal_mac(text: &str) -> Option<String> {
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let others = text.chars().any(|c| !c.is_ascii_hexdigit() && c != ':' && c != '-');
    if hex.len() != 12 || others {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    Some((0..6).map(|i| &hex[i * 2..i * 2 + 2]).collect::<Vec<_>>().join(":"))
}

/// MO-13: a VMware VM's hardware, from its .vmx (at most [`MAX_VM_CONFIG_BYTES`]) and each disk's files.
pub async fn read_vmware(vmx: &Path) -> crate::error::Result<VmHardware> {
    read_vmware_with(&LocalFiles, vmx).await
}

async fn read_vmware_with(files: &impl VmFiles, vmx: &Path) -> crate::error::Result<VmHardware> {
    let bytes = files.read(vmx, MAX_VM_CONFIG_BYTES).await?;
    let (mut hardware, disks) = parse_vmx_hardware(&String::from_utf8_lossy(&bytes));
    let folder = vmx.parent().unwrap_or(Path::new(""));
    for disk in disks {
        let path = resolve(folder, &disk.file_name);
        let mut read = read_disk_with(files, &path).await;
        read.slot = disk.slot;
        read.controller = disk.controller;
        hardware.disks.push(read);
    }
    Ok(hardware)
}

/// MO-13: a VirtualBox VM's hardware, from `showvminfo` and each disk image's header. `os_name` and
/// `kernel` come from the Guest Additions, when they run.
pub async fn read_virtualbox(info: &VboxVmInfo, os_name: Option<String>, kernel: Option<String>) -> VmHardware {
    read_virtualbox_with(&LocalFiles, info, os_name, kernel).await
}

async fn read_virtualbox_with(
    files: &impl VmFiles,
    info: &VboxVmInfo,
    os_name: Option<String>,
    kernel: Option<String>,
) -> VmHardware {
    let mut hardware = VmHardware {
        guest_os: info.os_type.clone(),
        guest_os_name: os_name,
        guest_kernel: kernel,
        vcpus: info.cpus,
        cores_per_socket: None,
        memory_mb: info.memory_mb,
        firmware: info.firmware.as_deref().map(|f| {
            if f.to_ascii_uppercase().starts_with("EFI") {
                "UEFI".to_owned()
            } else {
                "BIOS".to_owned()
            }
        }),
        hardware_version: None,
        disks: Vec::new(),
        nics: info
            .nics
            .iter()
            .filter(|n| n.enabled())
            .map(|n| VirtualNic {
                slot: format!("nic{}", n.slot),
                connection: Some(n.attachment.clone()),
                model: n.model.clone(),
                mac: n.mac.as_deref().and_then(normal_mac),
                // VirtualBox's cable is both: plugged in now, and at the next start.
                connected: n.cable_connected,
                network_name: n.network_name.clone(),
                connected_now: n.cable_connected.filter(|_| info.power_state().is_on()),
                static_mac: false,
            })
            .collect(),
        nested_virtualization: info.nested_hw_virt,
        secure_boot: info
            .firmware
            .as_deref()
            .filter(|f| f.to_ascii_uppercase().starts_with("EFI"))
            .map(|_| info.secure_boot.unwrap_or(false)),
        tpm: None,
        controllers: info
            .controllers
            .iter()
            .map(|c| StorageController {
                name: c.name.clone(),
                kind: c.kind.clone(),
                ports: c.ports,
            })
            .collect(),
        cdroms: info
            .dvds
            .iter()
            .map(|d| VirtualCdrom {
                slot: d.slot.clone(),
                image: d.image.as_ref().map(|p| p.display().to_string()),
                host_drive: d.host_drive.clone(),
                connected: None,
            })
            .collect(),
        usb: info.usb.clone(),
        sound: info
            .audio
            .as_deref()
            .filter(|a| !a.eq_ignore_ascii_case("none"))
            .map(|_| "Sound card".to_owned()),
        display: Some(VirtualDisplay {
            video_memory_mb: info.video_memory_mb,
            accelerate_3d: info.accelerate_3d,
            monitors: info.monitors,
            controller: info.graphics_controller.clone(),
        }),
        serial_ports: info
            .uarts
            .iter()
            .map(|u| {
                let (kind, target) = match u.mode.split_once(',') {
                    Some((kind, target)) => (kind.to_owned(), Some(target.to_owned())),
                    None => (u.mode.clone(), None),
                };
                SerialPort {
                    slot: format!("COM{}", u.slot),
                    kind,
                    target,
                }
            })
            .collect(),
        shared_folders: info
            .shared_folders
            .iter()
            .map(|(name, path)| SharedFolder {
                name: name.clone(),
                host_path: path.display().to_string(),
                writable: None,
                enabled: None,
            })
            .collect(),
        tools_version: info.additions_version.clone(),
        guest_ips: Vec::new(),
    };
    let controller_of = |slot: &str| {
        let name = slot.rsplitn(3, '-').nth(2)?;
        info.controllers
            .iter()
            .find(|c| c.name == name)
            .and_then(|c| c.kind.clone())
    };
    for disk in &info.disks {
        let mut read = read_disk_with(files, &disk.path).await;
        read.slot = disk.slot.clone();
        read.controller = controller_of(&disk.slot);
        hardware.disks.push(read);
    }
    hardware
}

/// VM-23: what the `.vbox` file adds to a VirtualBox VM's hardware (TPM, shared folders' flags, the sound
/// card), and the guest's addresses.
pub fn add_virtualbox_extras(
    hardware: &mut VmHardware,
    extras: Option<&super::virtualbox::VboxSettingsExtras>,
    guest_ips: Vec<String>,
) {
    hardware.guest_ips = guest_ips;
    let Some(extras) = extras else {
        return;
    };
    hardware.tpm = extras.tpm.as_deref().map(|t| match t.to_ascii_lowercase().as_str() {
        "v2_0" => "TPM 2.0".to_owned(),
        "v1_2" => "TPM 1.2".to_owned(),
        "host" => "This PC's TPM".to_owned(),
        "swtpm" => "Software TPM".to_owned(),
        other => other.to_owned(),
    });
    for folder in &mut hardware.shared_folders {
        if let Some((writable, auto_mount)) = extras.shared_folders.get(&folder.name) {
            folder.writable = *writable;
            folder.enabled = *auto_mount;
        }
    }
    if hardware.sound.is_some() {
        if let Some(controller) = &extras.audio_controller {
            hardware.sound = Some(match controller.to_ascii_uppercase().as_str() {
                "HDA" => "HD Audio".to_owned(),
                "AC97" => "AC'97".to_owned(),
                "SB16" => "Sound Blaster 16".to_owned(),
                other => other.to_owned(),
            });
        }
    }
}

/// A disk file named in a .vmx or descriptor: relative names are in `folder`.
fn resolve(folder: &Path, name: &str) -> PathBuf {
    let path = Path::new(name);
    if path.is_absolute() || name.starts_with(['\\', '/']) || name.get(1..2) == Some(":") {
        path.to_path_buf()
    } else {
        folder.join(path)
    }
}

/// What a disk file's first bytes say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskHeader {
    /// A VMDK text descriptor, or the one embedded in a sparse VMDK.
    Vmdk(VmdkDescriptor),
    /// A sparse VMDK whose descriptor could not be read: its capacity only.
    SparseVmdk {
        capacity_bytes: u64,
    },
    Vdi {
        capacity_bytes: u64,
        kind: String,
        differencing: bool,
    },
    Vhd {
        capacity_bytes: u64,
        kind: String,
        differencing: bool,
    },
    Qcow2 {
        capacity_bytes: u64,
    },
    Unknown,
}

/// A VMDK descriptor: `createType`, its extents and its parent (a delta disk's).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmdkDescriptor {
    pub create_type: Option<String>,
    /// (sectors, file name) per extent; a sparse VMDK's own descriptor names its own file.
    pub extents: Vec<(u64, Option<String>)>,
    pub parent: Option<String>,
}

impl VmdkDescriptor {
    pub fn capacity_bytes(&self) -> Option<u64> {
        let sectors: u64 = self.extents.iter().map(|(s, _)| *s).sum();
        (sectors > 0).then(|| sectors.saturating_mul(512))
    }
}

/// Parses a VMDK descriptor:
///
/// ```text
/// # Disk DescriptorFile
/// createType="twoGbMaxExtentSparse"
/// parentFileNameHint="web01.vmdk"
/// RW 8323072 SPARSE "web01-s001.vmdk"
/// RW 4194304 FLAT "web01-flat.vmdk" 0
/// ```
pub fn parse_vmdk_descriptor(text: &str) -> VmdkDescriptor {
    let mut descriptor = VmdkDescriptor::default();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if matches!(words.first(), Some(&("RW" | "RDONLY" | "NOACCESS"))) {
            if let Some(sectors) = words.get(1).and_then(|s| s.parse::<u64>().ok()) {
                let file = line.find('"').and_then(|start| {
                    let rest = &line[start + 1..];
                    rest.find('"').map(|end| rest[..end].to_owned())
                });
                descriptor.extents.push((sectors, file));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"').to_owned();
            match key.trim().to_ascii_lowercase().as_str() {
                "createtype" => descriptor.create_type = Some(value),
                "parentfilenamehint" if !value.is_empty() => descriptor.parent = Some(value),
                _ => {}
            }
        }
    }
    descriptor
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_be(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// VDI: "<<< Oracle VM VirtualBox Disk Image >>>", signature 0xbeda107f at 0x40, then a 1.x header
/// with the image type at 0x4c and the disk size at 0x170.
fn parse_vdi(head: &[u8]) -> Option<DiskHeader> {
    if u32_le(head, 0x40)? != 0xbeda_107f || u32_le(head, 0x44)? >> 16 != 1 {
        return None;
    }
    let (kind, differencing) = match u32_le(head, 0x4c)? {
        1 => ("VDI (dynamic)", false),
        2 => ("VDI (fixed)", false),
        3 => ("VDI (undo)", true),
        4 => ("VDI (differencing)", true),
        _ => ("VDI", false),
    };
    Some(DiskHeader::Vdi {
        capacity_bytes: u64_le(head, 0x170)?,
        kind: kind.to_owned(),
        differencing,
    })
}

/// VHD footer (512 bytes, big-endian): "conectix", current size at 48, disk type at 60. Dynamic and
/// differencing disks keep a copy at the start; a fixed one only at the end.
fn parse_vhd(footer: &[u8]) -> Option<DiskHeader> {
    if footer.get(..8)? != b"conectix" {
        return None;
    }
    let (kind, differencing) = match u32_be(footer, 60)? {
        2 => ("VHD (fixed)", false),
        3 => ("VHD (dynamic)", false),
        4 => ("VHD (differencing)", true),
        _ => ("VHD", false),
    };
    Some(DiskHeader::Vhd {
        capacity_bytes: u64_be(footer, 48)?,
        kind: kind.to_owned(),
        differencing,
    })
}

/// What a disk file's first bytes (and, for a sparse VMDK, the descriptor it points at) say.
pub fn parse_header(head: &[u8]) -> DiskHeader {
    if head.starts_with(b"KDMV") {
        // Sparse VMDK header: capacity (sectors) at 12, descriptor offset and size (sectors) at 28, 36.
        let capacity = u64_le(head, 12).unwrap_or(0).saturating_mul(512);
        let offset = u64_le(head, 28).unwrap_or(0).saturating_mul(512);
        let size = u64_le(head, 36).unwrap_or(0).saturating_mul(512);
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let end = usize::try_from(offset.saturating_add(size)).unwrap_or(usize::MAX);
        if let Some(text) = head.get(start..end.min(head.len())).filter(|t| !t.is_empty()) {
            let text = String::from_utf8_lossy(text);
            let text = text.trim_end_matches('\0');
            let mut descriptor = parse_vmdk_descriptor(text);
            if descriptor.extents.is_empty() {
                descriptor.extents.push((capacity / 512, None));
            }
            return DiskHeader::Vmdk(descriptor);
        }
        return DiskHeader::SparseVmdk {
            capacity_bytes: capacity,
        };
    }
    if head.starts_with(b"QFI\xfb") {
        return u64_be(head, 24).map_or(DiskHeader::Unknown, |capacity_bytes| DiskHeader::Qcow2 {
            capacity_bytes,
        });
    }
    if let Some(vdi) = parse_vdi(head) {
        return vdi;
    }
    if let Some(vhd) = parse_vhd(head) {
        return vhd;
    }
    // Told apart by its start; the whole descriptor is parsed, every extent counts.
    if is_text_descriptor(head) {
        return DiskHeader::Vmdk(parse_vmdk_descriptor(&String::from_utf8_lossy(head)));
    }
    DiskHeader::Unknown
}

/// A VMDK text descriptor, by its first 4 KB.
fn is_text_descriptor(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&head[..head.len().min(4096)]);
    text.contains("Disk DescriptorFile") || text.lines().any(|l| l.trim_start().starts_with("createType"))
}

/// Why a disk file's header could not be read.
enum HeaderError {
    Io(std::io::Error),
    /// A text descriptor larger than [`MAX_DESCRIPTOR`].
    DescriptorTooLarge,
}

/// What a disk file's header says, and the file's size. A text VMDK descriptor longer than
/// [`MAX_HEADER`] is read whole when it is at most [`MAX_DESCRIPTOR`], and refused when larger, so a
/// descriptor is never parsed in part into a wrong capacity. A fixed VHD has its footer only in its
/// last 512 bytes.
async fn read_header(files: &impl VmFiles, path: &Path) -> Result<(DiskHeader, u64), HeaderError> {
    let (head, size) = files.head(path, MAX_HEADER).await.map_err(HeaderError::Io)?;
    let mut header = parse_header(&head);
    let text = !head.starts_with(b"KDMV") && matches!(header, DiskHeader::Vmdk(_));
    if text && size > head.len() as u64 {
        if size > MAX_DESCRIPTOR {
            return Err(HeaderError::DescriptorTooLarge);
        }
        let whole = match files.read(path, MAX_DESCRIPTOR).await {
            Ok(whole) => whole,
            Err(ReadError::TooLarge { .. }) => return Err(HeaderError::DescriptorTooLarge),
            Err(ReadError::Io(err)) => return Err(HeaderError::Io(err)),
        };
        header = DiskHeader::Vmdk(parse_vmdk_descriptor(&String::from_utf8_lossy(&whole)));
    }
    if header == DiskHeader::Unknown && is_extension(path, "vhd") {
        if let Ok(tail) = files.tail(path, size).await {
            header = parse_header(&tail);
        }
    }
    Ok((header, size))
}

/// Reads one virtual disk's sizes from its files. Never fails: what could not be read is said in
/// [`VirtualDisk::problem`].
pub async fn read_disk(path: &Path) -> VirtualDisk {
    read_disk_with(&LocalFiles, path).await
}

async fn read_disk_with(files: &impl VmFiles, path: &Path) -> VirtualDisk {
    let mut disk = VirtualDisk {
        path: path.display().to_string(),
        ..VirtualDisk::default()
    };
    // A3: never opened, not even to see whether it is there.
    if let Some(refusal) = path_refusal(path) {
        disk.problem = Some(format!(
            "the disk file {}, so Remotely didn't read it",
            refusal.describe()
        ));
        return disk;
    }
    let (header, size) = match read_header(files, path).await {
        Ok(read) => read,
        Err(HeaderError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            disk.problem = Some("the disk file is not there".into());
            return disk;
        }
        Err(HeaderError::Io(err)) => {
            disk.problem = Some(format!("the disk file could not be read: {err}"));
            return disk;
        }
        Err(HeaderError::DescriptorTooLarge) => {
            disk.problem = Some(format!(
                "the disk's descriptor is larger than {}, so Remotely didn't read it",
                size_words(MAX_DESCRIPTOR)
            ));
            return disk;
        }
    };
    match header {
        DiskHeader::Vmdk(descriptor) => {
            let folder = path.parent().unwrap_or(Path::new(""));
            disk.format = descriptor.create_type.clone();
            disk.provisioned_bytes = descriptor.capacity_bytes();
            disk.delta = descriptor.parent.is_some();
            let mut chain = Vec::new();
            let (bytes, count, problem) = vmdk_chain_size(files, path, size, &descriptor, folder, &mut chain).await;
            disk.on_disk_bytes = Some(bytes);
            disk.files = count;
            disk.problem = problem;
            disk.chain = chain;
        }
        DiskHeader::SparseVmdk { capacity_bytes } => {
            disk.format = Some("monolithicSparse".into());
            disk.provisioned_bytes = Some(capacity_bytes);
            disk.on_disk_bytes = Some(size);
            disk.files = 1;
        }
        DiskHeader::Vdi {
            capacity_bytes,
            kind,
            differencing,
        }
        | DiskHeader::Vhd {
            capacity_bytes,
            kind,
            differencing,
        } => {
            disk.format = Some(kind);
            disk.provisioned_bytes = Some(capacity_bytes);
            disk.on_disk_bytes = Some(size);
            disk.files = 1;
            disk.delta = differencing;
            if differencing {
                disk.problem = Some("a snapshot's differencing image: the size on disk leaves out its parents".into());
            }
        }
        DiskHeader::Qcow2 { capacity_bytes } => {
            disk.format = Some("qcow2".into());
            disk.provisioned_bytes = Some(capacity_bytes);
            disk.on_disk_bytes = Some(size);
            disk.files = 1;
        }
        DiskHeader::Unknown => {
            disk.on_disk_bytes = Some(size);
            disk.files = 1;
            disk.problem = Some("the provisioned size is not in a header Remotely reads".into());
        }
    }
    // A snapshot's delta is always sparse, whatever its base disk is, so it says nothing about how the disk was made.
    disk.thin = if disk.delta {
        None
    } else {
        disk.format.as_deref().and_then(thin_format)
    };
    disk
}

/// VM-16: a disk's own files with their sizes: the file itself and, for a text descriptor, its extents in
/// other files (not its parents, which belong to snapshots). An extent on a share or a device path is left
/// out unopened (A3); the disk itself there is refused.
pub async fn disk_own_files(path: &Path) -> crate::error::Result<Vec<(PathBuf, u64)>> {
    disk_own_files_with(&LocalFiles, path).await
}

async fn disk_own_files_with(files: &impl VmFiles, path: &Path) -> crate::error::Result<Vec<(PathBuf, u64)>> {
    if let Some(refusal) = path_refusal(path) {
        return Err(crate::error::CoreError::VmSettingRefused(format!(
            "the disk file {} {}, so Remotely doesn't touch it",
            path.display(),
            refusal.describe()
        )));
    }
    let (header, size) = match read_header(files, path).await {
        Ok(read) => read,
        Err(HeaderError::Io(err)) => return Err(err.into()),
        Err(HeaderError::DescriptorTooLarge) => {
            return Err(crate::error::CoreError::VmSettingRefused(format!(
                "the disk's descriptor is larger than {}, so Remotely didn't read it",
                size_words(MAX_DESCRIPTOR)
            )))
        }
    };
    let mut out = vec![(path.to_path_buf(), size)];
    if let DiskHeader::Vmdk(descriptor) = header {
        let folder = path.parent().unwrap_or(Path::new(""));
        for name in descriptor.extents.iter().filter_map(|(_, name)| name.as_deref()) {
            let extent = resolve(folder, name);
            if extent == path || path_refusal(&extent).is_some() || out.iter().any(|(p, _)| *p == extent) {
                continue;
            }
            if let Ok(len) = files.len(&extent).await {
                out.push((extent, len));
            }
        }
    }
    Ok(out)
}

fn is_extension(path: &Path, ext: &str) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// What a VMDK and the disks under it take on this PC: its descriptor and extents, then each parent's
/// down to the base disk. Returns (bytes, files, why something was left out). An extent or parent on a
/// network share or a device path is not opened (A3).
async fn vmdk_chain_size(
    vm_files: &impl VmFiles,
    path: &Path,
    size: u64,
    descriptor: &VmdkDescriptor,
    folder: &Path,
    chain: &mut Vec<String>,
) -> (u64, u32, Option<String>) {
    let mut total = 0u64;
    let mut files = 0u32;
    let mut problem = None;
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut current = (path.to_path_buf(), size, descriptor.clone(), folder.to_path_buf());
    for _ in 0..MAX_CHAIN {
        let (path, size, descriptor, folder) = current;
        seen.push(path.clone());
        // The file itself (a text descriptor, or a sparse disk with its data), then extents in other files.
        total = total.saturating_add(size);
        files += 1;
        for (_, extent) in &descriptor.extents {
            let Some(name) = extent else {
                continue;
            };
            let extent_path = resolve(&folder, name);
            if extent_path == path {
                continue;
            }
            if let Some(refusal) = path_refusal(&extent_path) {
                problem.get_or_insert_with(|| {
                    format!("the extent {name} {}, so Remotely didn't count it", refusal.describe())
                });
                continue;
            }
            match vm_files.len(&extent_path).await {
                Ok(len) => {
                    total = total.saturating_add(len);
                    files += 1;
                }
                Err(_) => {
                    problem.get_or_insert_with(|| format!("the extent {name} is not there"));
                }
            }
        }
        let Some(parent) = &descriptor.parent else {
            return (total, files, problem);
        };
        let parent_path = resolve(&folder, parent);
        if seen.contains(&parent_path) {
            return (total, files, problem);
        }
        chain.push(parent.clone());
        if let Some(refusal) = path_refusal(&parent_path) {
            problem.get_or_insert_with(|| {
                format!(
                    "the parent disk {parent} {}, so Remotely didn't read it",
                    refusal.describe()
                )
            });
            return (total, files, problem);
        }
        let (parent_header, parent_size) = match read_header(vm_files, &parent_path).await {
            Ok(read) => read,
            Err(HeaderError::DescriptorTooLarge) => {
                problem.get_or_insert_with(|| {
                    format!(
                        "the parent disk {parent} has a descriptor larger than {}, so Remotely didn't read it",
                        size_words(MAX_DESCRIPTOR)
                    )
                });
                return (total, files, problem);
            }
            Err(HeaderError::Io(_)) => {
                problem.get_or_insert_with(|| format!("the parent disk {parent} is not there"));
                return (total, files, problem);
            }
        };
        let DiskHeader::Vmdk(parent_descriptor) = parent_header else {
            return (total.saturating_add(parent_size), files + 1, problem);
        };
        let parent_folder = parent_path.parent().unwrap_or(Path::new("")).to_path_buf();
        current = (parent_path, parent_size, parent_descriptor, parent_folder);
    }
    problem.get_or_insert_with(|| format!("only the first {MAX_CHAIN} disks of the snapshot chain are counted"));
    (total, files, problem)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VMX: &str = r#".encoding = "UTF-8"
displayName = "web01"
guestOS = "ubuntu-64"
virtualHW.version = "21"
firmware = "efi"
numvcpus = "4"
cpuid.coresPerSocket = "2"
memsize = "8192"
scsi0.present = "TRUE"
scsi0.virtualDev = "pvscsi"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "web01-000001.vmdk"
scsi0:1.present = "FALSE"
scsi0:1.fileName = "old.vmdk"
nvme0:0.present = "TRUE"
nvme0:0.fileName = "D:\VMs\data\data.vmdk"
sata0:1.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "C:\ISOs\ubuntu.iso"
scsi0:10.fileName = "ten.vmdk"
scsi0:2.fileName = "two.vmdk"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "vmxnet3"
ethernet0.addressType = "generated"
ethernet0.generatedAddress = "00:0C:29:AB:CD:EF"
ethernet1.present = "TRUE"
ethernet1.connectionType = "custom"
ethernet1.vnet = "VMnet2"
ethernet1.addressType = "static"
ethernet1.address = "00:50:56:01:02:03"
ethernet1.startConnected = "FALSE"
ethernet2.present = "TRUE"
ethernet2.generatedAddress = "00:0c:29:00:00:02"
ethernet3.present = "FALSE"
guestInfo.detailed.data = "architecture='X86' bitness='64' distroName='Ubuntu' distroVersion='24.04' familyName='Linux' kernelVersion='6.8.0-45-generic' prettyName='Ubuntu 24.04.1 LTS'"
"#;

    #[test]
    fn a_vmx_names_cpus_memory_firmware_disks_and_adapters() {
        let (hardware, disks) = parse_vmx_hardware(VMX);
        assert_eq!(hardware.guest_os.as_deref(), Some("ubuntu-64"));
        assert_eq!(hardware.guest_os_name.as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(hardware.guest_kernel.as_deref(), Some("6.8.0-45-generic"));
        assert_eq!((hardware.vcpus, hardware.cores_per_socket), (Some(4), Some(2)));
        assert_eq!(hardware.sockets(), Some(2));
        assert_eq!(hardware.memory_mb, Some(8192));
        assert_eq!(hardware.firmware.as_deref(), Some("UEFI"));
        assert_eq!(hardware.hardware_version.as_deref(), Some("21"));
        let slots: Vec<(&str, &str)> = disks.iter().map(|d| (d.slot.as_str(), d.file_name.as_str())).collect();
        assert_eq!(
            slots,
            [
                ("nvme0:0", r"D:\VMs\data\data.vmdk"),
                ("scsi0:0", "web01-000001.vmdk"),
                ("scsi0:2", "two.vmdk"),
                ("scsi0:10", "ten.vmdk"),
            ],
            "not the absent disk or the ISO; slots in number order"
        );
        type NicRow<'a> = (&'a str, Option<&'a str>, Option<&'a str>, Option<&'a str>, Option<bool>);
        let nics: Vec<NicRow> = hardware
            .nics
            .iter()
            .map(|n| {
                (
                    n.slot.as_str(),
                    n.connection.as_deref(),
                    n.model.as_deref(),
                    n.mac.as_deref(),
                    n.connected,
                )
            })
            .collect();
        assert_eq!(
            nics,
            [
                (
                    "ethernet0",
                    Some("nat"),
                    Some("vmxnet3"),
                    Some("00:0c:29:ab:cd:ef"),
                    None
                ),
                (
                    "ethernet1",
                    Some("custom (VMnet2)"),
                    None,
                    Some("00:50:56:01:02:03"),
                    Some(false)
                ),
                ("ethernet2", Some("bridged"), None, Some("00:0c:29:00:00:02"), None),
            ]
        );
    }

    /// VM-23: what the Settings tab shows from a .vmx, in the shape Workstation 26 writes.
    #[test]
    fn a_vmx_gives_the_settings_tab_every_device() {
        let vmx = r#"firmware = "efi"
uefi.secureBoot.enabled = "TRUE"
vhv.enable = "TRUE"
vtpm.present = "TRUE"
numvcpus = "2"
scsi0.present = "TRUE"
scsi0.virtualDev = "pvscsi"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "web01.vmdk"
sata0.present = "TRUE"
sata0:1.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "C:\ISOs\ubuntu.iso"
sata0:1.startConnected = "TRUE"
ide1:0.present = "TRUE"
ide1:0.deviceType = "atapi-cdrom"
ide1:0.fileName = "auto detect"
usb.present = "TRUE"
ehci.present = "TRUE"
usb_xhci.present = "TRUE"
sound.present = "TRUE"
sound.virtualDev = "hdaudio"
svga.graphicsMemoryKB = "8388608"
mks.enable3d = "TRUE"
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "\\.\pipe\com_1"
serial1.present = "FALSE"
isolation.tools.hgfs.disable = "FALSE"
sharedFolder0.present = "TRUE"
sharedFolder0.enabled = "TRUE"
sharedFolder0.writeAccess = "FALSE"
sharedFolder0.hostPath = "C:\Shared\data"
sharedFolder0.guestName = "data"
sharedFolder1.present = "FALSE"
ethernet0.present = "TRUE"
ethernet0.connectionType = "custom"
ethernet0.vnet = "VMnet3"
ethernet0.addressType = "static"
ethernet0.address = "00:50:56:01:02:03"
"#;
        let (hardware, disks) = parse_vmx_hardware(vmx);
        assert_eq!(hardware.secure_boot, Some(true));
        assert_eq!(hardware.nested_virtualization, Some(true));
        assert_eq!(hardware.tpm.as_deref(), Some("TPM 2.0"));
        assert_eq!(disks[0].controller.as_deref(), Some("pvscsi"));
        let controllers: Vec<(&str, Option<&str>)> = hardware
            .controllers
            .iter()
            .map(|c| (c.name.as_str(), c.kind.as_deref()))
            .collect();
        assert_eq!(
            controllers,
            [
                ("ide1", Some("IDE")),
                ("sata0", Some("SATA (AHCI)")),
                ("scsi0", Some("pvscsi"))
            ]
        );
        assert_eq!(hardware.cdroms.len(), 2);
        assert_eq!(hardware.cdroms[0].slot, "ide1:0");
        assert_eq!(hardware.cdroms[0].host_drive.as_deref(), Some("auto detect"));
        assert_eq!(hardware.cdroms[1].image.as_deref(), Some(r"C:\ISOs\ubuntu.iso"));
        assert_eq!(hardware.usb, ["USB 1.1", "USB 2.0", "USB 3.x"]);
        assert_eq!(hardware.sound.as_deref(), Some("HD Audio"));
        let display = hardware.display.unwrap();
        assert_eq!(
            (display.video_memory_mb, display.accelerate_3d),
            (Some(8192), Some(true))
        );
        assert_eq!(hardware.serial_ports.len(), 1);
        assert_eq!(hardware.serial_ports[0].kind, "pipe");
        assert_eq!(hardware.shared_folders.len(), 1);
        assert_eq!(hardware.shared_folders[0].writable, Some(false));
        assert_eq!(hardware.shared_folders[0].enabled, Some(true));
        assert_eq!(hardware.nics[0].network_name.as_deref(), Some("VMnet3"));
        assert!(hardware.nics[0].static_mac);
        let bios = parse_vmx_hardware("numvcpus = \"1\"\n").0;
        assert_eq!((bios.secure_boot, bios.tpm.as_deref()), (None, None));
        assert_eq!(thin_format("monolithicSparse"), Some(true));
        assert_eq!(thin_format("monolithicFlat"), Some(false));
        assert_eq!(thin_format("VDI (fixed)"), Some(false));
        // Facts stored before 0.5.0 read with the newer fields empty.
        let old: VmHardware = serde_json::from_str(
            r#"{"vcpus":2,"disks":[{"slot":"scsi0:0","path":"x","files":1,"delta":false}],"nics":[]}"#,
        )
        .unwrap();
        assert_eq!(old.vcpus, Some(2));
        assert!(old.cdroms.is_empty() && old.disks[0].chain.is_empty());
    }

    #[tokio::test]
    async fn a_disks_own_files_are_its_descriptor_and_extents_not_its_parents() {
        let descriptor = "# Disk DescriptorFile\ncreateType=\"twoGbMaxExtentSparse\"\nparentFileNameHint=\"base.vmdk\"\nRW 100 SPARSE \"web01-s001.vmdk\"\nRW 100 SPARSE \"\\\\nas.example.com\\x\\web01-s002.vmdk\"\n";
        let files = MemFiles::default()
            .with(r"C:\VMs\web01\web01.vmdk", descriptor)
            .with(r"C:\VMs\web01\web01-s001.vmdk", vec![0u8; 3000]);
        let own = disk_own_files_with(&files, Path::new(r"C:\VMs\web01\web01.vmdk"))
            .await
            .unwrap();
        let names: Vec<String> = own.iter().map(|(p, _)| p.display().to_string()).collect();
        assert_eq!(names, [r"C:\VMs\web01\web01.vmdk", r"C:\VMs\web01\web01-s001.vmdk"]);
        assert_eq!(own[1].1, 3000);
        let share = disk_own_files_with(&files, Path::new(r"\\nas.example.com\x\web01.vmdk"))
            .await
            .unwrap_err();
        assert_eq!(share.code(), "vm_setting_refused");
    }

    #[test]
    fn a_minimal_vmx_has_one_vcpu_and_bios() {
        let (hardware, disks) = parse_vmx_hardware("memsize = \"2048\"\n");
        assert_eq!(hardware.vcpus, Some(1), "Workstation leaves numvcpus out for one");
        assert_eq!(hardware.firmware.as_deref(), Some("BIOS"));
        assert_eq!(hardware.sockets(), None);
        assert!(disks.is_empty() && hardware.nics.is_empty());
    }

    #[test]
    fn macs_read_the_same_whatever_their_form() {
        assert_eq!(normal_mac("080027AABB01").as_deref(), Some("08:00:27:aa:bb:01"));
        assert_eq!(normal_mac("00-50-56-C0-00-08").as_deref(), Some("00:50:56:c0:00:08"));
        assert_eq!(normal_mac("00:0c:29"), None);
        assert_eq!(normal_mac("not a mac at all!"), None);
    }

    #[test]
    fn a_descriptor_lists_extents_and_its_parent() {
        let descriptor = parse_vmdk_descriptor(
            "# Disk DescriptorFile\nversion=1\nencoding=\"UTF-8\"\nCID=fffffffe\nparentCID=12345678\ncreateType=\"twoGbMaxExtentSparse\"\nparentFileNameHint=\"web01.vmdk\"\n\n# Extent description\nRW 8323072 SPARSE \"web01-000001-s001.vmdk\"\nRW 8323072 SPARSE \"web01-000001-s002.vmdk\"\nRW 4096 SPARSE \"web01-000001-s003.vmdk\"\n\nddb.virtualHWVersion = \"21\"\n",
        );
        assert_eq!(descriptor.create_type.as_deref(), Some("twoGbMaxExtentSparse"));
        assert_eq!(descriptor.parent.as_deref(), Some("web01.vmdk"));
        assert_eq!(descriptor.extents.len(), 3);
        assert_eq!(descriptor.capacity_bytes(), Some((8_323_072 * 2 + 4096) * 512));
        let flat = parse_vmdk_descriptor("createType=\"monolithicFlat\"\nRW 41943040 FLAT \"db-flat.vmdk\" 0\n");
        assert_eq!(flat.extents, [(41_943_040, Some("db-flat.vmdk".to_owned()))]);
        assert_eq!(flat.parent, None);
    }

    /// A sparse VMDK's header with its embedded descriptor right after it.
    fn sparse_vmdk(capacity_sectors: u64, descriptor: &str) -> Vec<u8> {
        let mut head = vec![0u8; 512];
        head[..4].copy_from_slice(b"KDMV");
        head[4..8].copy_from_slice(&1u32.to_le_bytes());
        head[12..20].copy_from_slice(&capacity_sectors.to_le_bytes());
        head[28..36].copy_from_slice(&1u64.to_le_bytes());
        head[36..44].copy_from_slice(&20u64.to_le_bytes());
        let mut text = descriptor.as_bytes().to_vec();
        text.resize(20 * 512, 0);
        head.extend_from_slice(&text);
        head.extend_from_slice(&[7u8; 4096]);
        head
    }

    fn vdi(capacity: u64, kind: u32) -> Vec<u8> {
        let mut head = vec![0u8; 0x200];
        head[..39].copy_from_slice(b"<<< Oracle VM VirtualBox Disk Image >>>");
        head[0x40..0x44].copy_from_slice(&0xbeda_107fu32.to_le_bytes());
        head[0x44..0x48].copy_from_slice(&0x0001_0001u32.to_le_bytes());
        head[0x4c..0x50].copy_from_slice(&kind.to_le_bytes());
        head[0x170..0x178].copy_from_slice(&capacity.to_le_bytes());
        head
    }

    fn vhd_footer(capacity: u64, kind: u32) -> Vec<u8> {
        let mut footer = vec![0u8; 512];
        footer[..8].copy_from_slice(b"conectix");
        footer[48..56].copy_from_slice(&capacity.to_be_bytes());
        footer[60..64].copy_from_slice(&kind.to_be_bytes());
        footer
    }

    #[test]
    fn headers_give_each_format_its_provisioned_size() {
        let sparse = sparse_vmdk(
            41_943_040,
            "# Disk DescriptorFile\ncreateType=\"monolithicSparse\"\nRW 41943040 SPARSE \"web01.vmdk\"\n",
        );
        let DiskHeader::Vmdk(descriptor) = parse_header(&sparse) else {
            panic!("a sparse VMDK");
        };
        assert_eq!(descriptor.capacity_bytes(), Some(20 * 1024 * 1024 * 1024));
        assert_eq!(
            parse_header(&vdi(10 << 30, 1)),
            DiskHeader::Vdi {
                capacity_bytes: 10 << 30,
                kind: "VDI (dynamic)".into(),
                differencing: false
            }
        );
        assert!(matches!(
            parse_header(&vdi(10 << 30, 4)),
            DiskHeader::Vdi { differencing: true, .. }
        ));
        assert_eq!(
            parse_header(&vhd_footer(1 << 30, 3)),
            DiskHeader::Vhd {
                capacity_bytes: 1 << 30,
                kind: "VHD (dynamic)".into(),
                differencing: false
            }
        );
        let mut qcow = b"QFI\xfb".to_vec();
        qcow.resize(32, 0);
        qcow[24..32].copy_from_slice(&(5u64 << 30).to_be_bytes());
        assert_eq!(
            parse_header(&qcow),
            DiskHeader::Qcow2 {
                capacity_bytes: 5 << 30
            }
        );
        assert_eq!(parse_header(b"just some bytes"), DiskHeader::Unknown);
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("remotely-disks-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_snapshot_delta_counts_its_extents_and_parents_on_disk() {
        let dir = temp_dir();
        // Base: a split sparse disk with two extents.
        std::fs::write(
            dir.join("web01.vmdk"),
            "# Disk DescriptorFile\ncreateType=\"twoGbMaxExtentSparse\"\nRW 8323072 SPARSE \"web01-s001.vmdk\"\nRW 8323072 SPARSE \"web01-s002.vmdk\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("web01-s001.vmdk"), vec![0u8; 3000]).unwrap();
        std::fs::write(dir.join("web01-s002.vmdk"), vec![0u8; 2000]).unwrap();
        // Delta: a monolithic sparse file whose descriptor names the base.
        let delta = sparse_vmdk(
            16_646_144,
            "# Disk DescriptorFile\ncreateType=\"monolithicSparse\"\nparentFileNameHint=\"web01.vmdk\"\nRW 16646144 SPARSE \"web01-000001.vmdk\"\n",
        );
        std::fs::write(dir.join("web01-000001.vmdk"), &delta).unwrap();
        let base_descriptor = std::fs::metadata(dir.join("web01.vmdk")).unwrap().len();

        let disk = read_disk(&dir.join("web01-000001.vmdk")).await;
        assert_eq!(disk.provisioned_bytes, Some(16_646_144 * 512));
        assert!(disk.delta);
        assert_eq!(disk.files, 4, "delta, base descriptor and two extents");
        assert_eq!(disk.on_disk_bytes, Some(delta.len() as u64 + base_descriptor + 5000));
        assert_eq!(disk.problem, None);

        // A .vmx naming it, read the way the adapter does.
        std::fs::write(
            dir.join("web01.vmx"),
            "numvcpus = \"2\"\nmemsize = \"4096\"\nscsi0:0.present = \"TRUE\"\nscsi0:0.fileName = \"web01-000001.vmdk\"\nsata0:0.present = \"TRUE\"\nsata0:0.fileName = \"gone.vmdk\"\n",
        )
        .unwrap();
        let hardware = read_vmware(&dir.join("web01.vmx")).await.unwrap();
        assert_eq!(hardware.disks.len(), 2);
        assert_eq!(hardware.disks[0].slot, "sata0:0");
        assert_eq!(hardware.disks[0].problem.as_deref(), Some("the disk file is not there"));
        assert_eq!(hardware.disks[1].slot, "scsi0:0");
        assert_eq!(hardware.disks[1].on_disk_bytes, disk.on_disk_bytes);

        // A fixed VHD has its footer at the end only.
        let mut fixed = vec![0u8; 4096];
        fixed.extend_from_slice(&vhd_footer(4096, 2));
        std::fs::write(dir.join("fixed.vhd"), &fixed).unwrap();
        let vhd = read_disk(&dir.join("fixed.vhd")).await;
        assert_eq!(vhd.provisioned_bytes, Some(4096));
        assert_eq!(vhd.format.as_deref(), Some("VHD (fixed)"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A VM's files in memory, so these tests touch no file system. Asked for a path that must be
    /// refused (a share, a device), it fails the test instead of opening anything; `chosen` is the
    /// .vmx the user picked, which may be anywhere.
    #[derive(Default)]
    struct MemFiles {
        files: std::collections::HashMap<PathBuf, Vec<u8>>,
        chosen: Option<PathBuf>,
        asked: std::sync::Mutex<Vec<PathBuf>>,
    }

    impl MemFiles {
        fn with(mut self, path: &str, bytes: impl Into<Vec<u8>>) -> Self {
            self.files.insert(PathBuf::from(path), bytes.into());
            self
        }

        fn chosen(mut self, vmx: &str, text: &str) -> Self {
            self.chosen = Some(PathBuf::from(vmx));
            self.with(vmx, text)
        }

        fn ask(&self, path: &Path) -> std::io::Result<&Vec<u8>> {
            if self.chosen.as_deref() != Some(path) {
                assert_eq!(path_refusal(path), None, "asked for {}", path.display());
            }
            self.asked.lock().unwrap().push(path.to_path_buf());
            self.files
                .get(path)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }

        fn asked(&self) -> Vec<String> {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .map(|p| p.display().to_string())
                .collect()
        }
    }

    impl VmFiles for MemFiles {
        async fn read(&self, path: &Path, cap: u64) -> Result<Vec<u8>, ReadError> {
            let bytes = self.ask(path)?;
            if bytes.len() as u64 > cap {
                return Err(ReadError::TooLarge {
                    path: path.display().to_string(),
                    cap,
                });
            }
            Ok(bytes.clone())
        }

        async fn head(&self, path: &Path, max: u64) -> std::io::Result<(Vec<u8>, u64)> {
            let bytes = self.ask(path)?;
            let end = bytes.len().min(max as usize);
            Ok((bytes[..end].to_vec(), bytes.len() as u64))
        }

        async fn tail(&self, path: &Path, _: u64) -> std::io::Result<Vec<u8>> {
            let bytes = self.ask(path)?;
            Ok(bytes[bytes.len().saturating_sub(512)..].to_vec())
        }

        async fn len(&self, path: &Path) -> std::io::Result<u64> {
            Ok(self.ask(path)?.len() as u64)
        }
    }

    #[tokio::test]
    async fn disks_on_shares_or_device_paths_are_never_opened() {
        let vmx = r#"numvcpus = "2"
memsize = "4096"
scsi0:0.fileName = "\\nas.example.com\vms\data.vmdk"
scsi0:1.fileName = "//nas.example.com/vms/logs.vmdk"
scsi0:2.fileName = "|5C|5Cnas.example.com|5Cvms|5Cescaped.vmdk"
scsi0:3.fileName = "\\?\C:\VMs\web01\device.vmdk"
scsi0:4.fileName = "\??\C:\VMs\web01\nt.vmdk"
scsi0:5.fileName = "web01.vmdk"
"#;
        // A local descriptor whose second extent and parent are on a share.
        let descriptor = "# Disk DescriptorFile\ncreateType=\"twoGbMaxExtentSparse\"\nparentFileNameHint=\"\\\\nas.example.com\\base\\base.vmdk\"\nRW 100 SPARSE \"web01-s001.vmdk\"\nRW 100 SPARSE \"\\\\nas.example.com\\x\\web01-s002.vmdk\"\n";
        let files = MemFiles::default()
            .with(r"C:\VMs\web01\web01.vmx", vmx)
            .with(r"C:\VMs\web01\web01.vmdk", descriptor)
            .with(r"C:\VMs\web01\web01-s001.vmdk", vec![0u8; 3000]);
        let hardware = read_vmware_with(&files, Path::new(r"C:\VMs\web01\web01.vmx"))
            .await
            .unwrap();
        assert_eq!(hardware.vcpus, Some(2));
        assert_eq!(hardware.disks.len(), 6);
        for disk in &hardware.disks[..5] {
            assert_eq!(
                (disk.provisioned_bytes, disk.on_disk_bytes, disk.files),
                (None, None, 0),
                "{disk:?}"
            );
            let problem = disk.problem.as_deref().unwrap();
            assert!(problem.ends_with("so Remotely didn't read it"), "{problem}");
        }
        assert_eq!(
            hardware.disks[0].path, r"\\nas.example.com\vms\data.vmdk",
            "the path is still shown"
        );
        assert!(hardware.disks[0]
            .problem
            .as_deref()
            .unwrap()
            .contains("is on a network share"));
        assert!(hardware.disks[2]
            .problem
            .as_deref()
            .unwrap()
            .contains("is on a network share"));
        assert!(hardware.disks[3].problem.as_deref().unwrap().contains("device path"));
        assert!(hardware.disks[4].problem.as_deref().unwrap().contains("device path"));

        let local = &hardware.disks[5];
        assert_eq!(local.provisioned_bytes, Some(200 * 512));
        assert_eq!(local.on_disk_bytes, Some(descriptor.len() as u64 + 3000));
        assert_eq!(local.files, 2);
        assert_eq!(
            local.problem.as_deref(),
            Some(r"the extent \\nas.example.com\x\web01-s002.vmdk is on a network share, so Remotely didn't count it")
        );
        assert_eq!(
            files.asked(),
            [
                r"C:\VMs\web01\web01.vmx",
                r"C:\VMs\web01\web01.vmdk",
                r"C:\VMs\web01\web01-s001.vmdk"
            ],
            "nothing on the share was asked for, not even the parent"
        );
    }

    #[tokio::test]
    async fn a_vmx_kept_on_a_share_is_read_but_its_disks_there_are_not() {
        let vmx = r"\\nas.example.com\vms\web01\web01.vmx";
        let files = MemFiles::default()
            .chosen(vmx, "numvcpus = \"4\"\nscsi0:0.fileName = \"web01.vmdk\"\n")
            .with(r"\\nas.example.com\vms\web01\web01.vmdk", "# Disk DescriptorFile\n");
        let hardware = read_vmware_with(&files, Path::new(vmx)).await.unwrap();
        assert_eq!(hardware.vcpus, Some(4));
        assert_eq!(hardware.disks[0].path, r"\\nas.example.com\vms\web01\web01.vmdk");
        assert_eq!(
            hardware.disks[0].problem.as_deref(),
            Some("the disk file is on a network share, so Remotely didn't read it")
        );
        assert_eq!(files.asked(), [vmx], "only the .vmx the user keeps there");
    }

    #[tokio::test]
    async fn virtualbox_disks_on_shares_are_never_opened() {
        let info = VboxVmInfo {
            disks: vec![
                crate::adapters::virtualbox::VboxDisk {
                    slot: "SATA-0-0".into(),
                    path: PathBuf::from(r"\\nas.example.com\vbox\web01.vdi"),
                },
                crate::adapters::virtualbox::VboxDisk {
                    slot: "SATA-0-1".into(),
                    path: PathBuf::from(r"C:\VirtualBox VMs\web01\data.vdi"),
                },
            ],
            ..VboxVmInfo::default()
        };
        let files = MemFiles::default().with(r"C:\VirtualBox VMs\web01\data.vdi", vdi(1 << 30, 1));
        let hardware = read_virtualbox_with(&files, &info, None, None).await;
        assert_eq!(hardware.disks[0].slot, "SATA-0-0");
        assert_eq!(hardware.disks[0].provisioned_bytes, None);
        assert!(hardware.disks[0].problem.as_deref().unwrap().contains("network share"));
        assert_eq!(hardware.disks[1].provisioned_bytes, Some(1 << 30));
        assert_eq!(files.asked(), [r"C:\VirtualBox VMs\web01\data.vdi"]);
    }

    #[tokio::test]
    async fn oversized_vmx_and_descriptors_are_refused_not_read_in_part() {
        let mut huge = "numvcpus = \"2\"\n".to_owned().into_bytes();
        huge.resize(MAX_VM_CONFIG_BYTES as usize + 1, b'#');
        let files = MemFiles::default().with(r"C:\VMs\big\big.vmx", huge);
        let err = read_vmware_with(&files, Path::new(r"C:\VMs\big\big.vmx"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert_eq!(
            err.to_string(),
            r"C:\VMs\big\big.vmx is larger than 4 MB, so Remotely didn't read it"
        );

        // A descriptor of 3000 2 GB extents is longer than the header read: read whole, every extent counted.
        let mut long = "# Disk DescriptorFile\ncreateType=\"twoGbMaxExtentSparse\"\n".to_owned();
        for n in 1..=3000 {
            long.push_str(&format!("RW 4192256 SPARSE \"web01-s{n:04}.vmdk\"\n"));
        }
        assert!(long.len() as u64 > MAX_HEADER);
        let files = MemFiles::default().with(r"C:\VMs\web01\web01.vmdk", long.clone());
        let disk = read_disk_with(&files, Path::new(r"C:\VMs\web01\web01.vmdk")).await;
        assert_eq!(disk.provisioned_bytes, Some(3000 * 4_192_256 * 512));

        let mut too_long = long.into_bytes();
        too_long.resize(MAX_DESCRIPTOR as usize + 1, b'\n');
        let files = MemFiles::default().with(r"C:\VMs\web01\web01.vmdk", too_long);
        let disk = read_disk_with(&files, Path::new(r"C:\VMs\web01\web01.vmdk")).await;
        assert_eq!(disk.provisioned_bytes, None);
        assert_eq!(
            disk.problem.as_deref(),
            Some("the disk's descriptor is larger than 1 MB, so Remotely didn't read it")
        );
    }

    #[test]
    fn detailed_data_reads_every_quoted_pair() {
        let data =
            detailed_data("architecture='X86' bitness='64' prettyName='Windows 11 Pro, 64-bit' familyName='Windows'");
        assert_eq!(
            data.get("prettyName").map(String::as_str),
            Some("Windows 11 Pro, 64-bit")
        );
        assert_eq!(data.get("bitness").map(String::as_str), Some("64"));
        assert_eq!(data.len(), 4);
    }
}
