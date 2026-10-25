//! VM-21: the `.vmx` of a new Workstation VM, written from the plan: the OS profile's guest OS type, firmware,
//! hardware version, network card and disk controller, and the size's CPU, memory and disks. Pure, so it is
//! tested without Workstation.
//!
//! It has what Workstation's own new-VM wizard writes and a VM needs to power on: the PCI bridges (without them
//! Workstation refuses a `.vmx` that names a pvscsi or vmxnet3 device), VMCI, the HPET, the disks on their
//! controller, a network card, and for an ISO install the CD/DVD drive with the ISO, connected at power-on.
//! Workstation adds the rest (UUIDs, MAC addresses, PCI slots) at the first power-on.

use crate::catalog::profiles::Firmware;
use crate::catalog::sizes::DiskController;
use crate::catalog::templates::Network;

/// One disk of a new VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmxDisk {
    /// The disk's file name, beside the `.vmx`.
    pub file_name: String,
    pub controller: DiskController,
    /// `pvscsi`, `lsisas1068`... for a SCSI controller.
    pub controller_model: String,
}

/// What the `.vmx` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVmx {
    pub display_name: String,
    pub guest_os: String,
    pub hardware_version: u32,
    pub firmware: Firmware,
    pub sockets: u32,
    pub cores_per_socket: u32,
    pub memory_mb: u32,
    pub disks: Vec<VmxDisk>,
    /// An ISO in the CD/DVD drive, connected at power-on, which the VM boots from first.
    pub iso: Option<String>,
    pub network: Network,
    /// `ethernet0.virtualDev`: `vmxnet3`, `e1000e`.
    pub nic: String,
    /// More keys at the end (VM-22: cloud-init's `guestinfo.*`).
    pub extra: Vec<(String, String)>,
}

/// A `.vmx` value: `"` and `|` and control characters as `|XX`, as Workstation writes them.
pub fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' | '|' => out.push_str(&format!("|{:02X}", c as u32)),
            c if (c as u32) < 0x20 => out.push_str(&format!("|{:02X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Workstation's `ethernet0.connectionType` and, for a custom network, its `ethernet0.vnet`. `None` for a network
/// Workstation doesn't have (the plan never sends one).
pub fn connection(network: &Network) -> Option<(&'static str, Option<String>)> {
    Some(match network {
        Network::Nat => ("nat", None),
        Network::HostOnly => ("hostonly", None),
        Network::Bridged => ("bridged", None),
        Network::Vmnet { number } => ("custom", Some(format!("VMnet{number}"))),
        Network::NatNetwork { .. } | Network::Internal { .. } => return None,
    })
}

/// The device slots disks get on each controller: `scsi0:0`... (SCSI skips 7, the controller's own), `sata0:0`...,
/// `nvme0:0`..., `ide0:0`, `ide0:1`, `ide1:0`, `ide1:1`.
pub fn disk_slots(disks: &[VmxDisk]) -> Vec<String> {
    let (mut scsi, mut sata, mut nvme, mut ide) = (0u32, 0u32, 0u32, 0u32);
    disks
        .iter()
        .map(|disk| match disk.controller {
            DiskController::Scsi => {
                if scsi == 7 {
                    scsi += 1;
                }
                let slot = format!("scsi0:{scsi}");
                scsi += 1;
                slot
            }
            DiskController::Sata => {
                let slot = format!("sata0:{sata}");
                sata += 1;
                slot
            }
            DiskController::Nvme => {
                let slot = format!("nvme0:{nvme}");
                nvme += 1;
                slot
            }
            DiskController::Ide => {
                let slot = format!("ide{}:{}", ide / 2, ide % 2);
                ide += 1;
                slot
            }
        })
        .collect()
}

/// The `.vmx` text, with Windows line ends as Workstation writes them.
pub fn render(vmx: &NewVmx) -> String {
    let mut lines: Vec<(String, String)> = Vec::new();
    let mut set = |key: &str, value: String| lines.push((key.to_owned(), value));
    set(".encoding", "UTF-8".into());
    set("config.version", "8".into());
    set("virtualHW.version", vmx.hardware_version.to_string());
    set("displayName", vmx.display_name.clone());
    set("guestOS", vmx.guest_os.clone());
    set("nvram", format!("{}.nvram", vmx.display_name));
    match vmx.firmware {
        Firmware::Bios => {
            if vmx.iso.is_some() {
                set("bios.bootOrder", "cdrom,hdd".into());
            }
        }
        Firmware::Efi => set("firmware", "efi".into()),
        Firmware::EfiSecureBoot => {
            set("firmware", "efi".into());
            set("uefi.secureBoot.enabled", "TRUE".into());
        }
    }
    let vcpus = vmx.sockets.max(1) * vmx.cores_per_socket.max(1);
    set("numvcpus", vcpus.to_string());
    set("cpuid.coresPerSocket", vmx.cores_per_socket.max(1).to_string());
    set("memsize", vmx.memory_mb.to_string());
    set("pciBridge0.present", "TRUE".into());
    for bridge in 4..=7 {
        set(&format!("pciBridge{bridge}.present"), "TRUE".into());
        set(&format!("pciBridge{bridge}.virtualDev"), "pcieRootPort".into());
        set(&format!("pciBridge{bridge}.functions"), "8".into());
    }
    set("vmci0.present", "TRUE".into());
    set("hpet0.present", "TRUE".into());
    set("floppy0.present", "FALSE".into());

    let slots = disk_slots(&vmx.disks);
    let has = |c: DiskController| vmx.disks.iter().any(|d| d.controller == c);
    if let Some(scsi) = vmx.disks.iter().find(|d| d.controller == DiskController::Scsi) {
        set("scsi0.present", "TRUE".into());
        set("scsi0.virtualDev", scsi.controller_model.clone());
    }
    if has(DiskController::Sata) || vmx.iso.is_some() {
        set("sata0.present", "TRUE".into());
    }
    if has(DiskController::Nvme) {
        set("nvme0.present", "TRUE".into());
    }
    for (disk, slot) in vmx.disks.iter().zip(&slots) {
        set(&format!("{slot}.present"), "TRUE".into());
        set(&format!("{slot}.fileName"), disk.file_name.clone());
    }
    if let Some(iso) = &vmx.iso {
        let next = vmx
            .disks
            .iter()
            .filter(|d| d.controller == DiskController::Sata)
            .count();
        let slot = format!("sata0:{next}");
        set(&format!("{slot}.present"), "TRUE".into());
        set(&format!("{slot}.deviceType"), "cdrom-image".into());
        set(&format!("{slot}.fileName"), iso.clone());
        set(&format!("{slot}.startConnected"), "TRUE".into());
    }
    if let Some((kind, vnet)) = connection(&vmx.network) {
        set("ethernet0.present", "TRUE".into());
        set("ethernet0.connectionType", kind.into());
        if let Some(vnet) = vnet {
            set("ethernet0.vnet", vnet);
        }
        set("ethernet0.virtualDev", vmx.nic.clone());
        set("ethernet0.addressType", "generated".into());
        set("ethernet0.startConnected", "TRUE".into());
    }
    for (key, value) in &vmx.extra {
        set(key, value.clone());
    }
    let mut out = String::new();
    for (key, value) in lines {
        out.push_str(&format!("{key} = \"{}\"\r\n", escape_value(&value)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::vmware::parse_vmx;

    fn ubuntu() -> NewVmx {
        NewVmx {
            display_name: "web-1".into(),
            guest_os: "ubuntu-64".into(),
            hardware_version: 20,
            firmware: Firmware::Efi,
            sockets: 1,
            cores_per_socket: 2,
            memory_mb: 4096,
            disks: vec![
                VmxDisk {
                    file_name: "web-1.vmdk".into(),
                    controller: DiskController::Scsi,
                    controller_model: "pvscsi".into(),
                },
                VmxDisk {
                    file_name: "web-1-1.vmdk".into(),
                    controller: DiskController::Scsi,
                    controller_model: "pvscsi".into(),
                },
            ],
            iso: None,
            network: Network::Vmnet { number: 3 },
            nic: "vmxnet3".into(),
            extra: vec![("guestinfo.userdata.encoding".into(), "base64".into())],
        }
    }

    fn keys(text: &str) -> Vec<(String, String)> {
        text.lines()
            .filter_map(|l| l.split_once(" = "))
            .map(|(k, v)| (k.to_owned(), v.trim_matches('"').to_owned()))
            .collect()
    }

    fn get<'a>(keys: &'a [(String, String)], key: &str) -> Option<&'a str> {
        keys.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_new_vmx_has_the_profile_and_size() {
        let text = render(&ubuntu());
        assert!(text.ends_with("\r\n") && text.contains("\r\n"));
        let k = keys(&text);
        for (key, value) in [
            ("virtualHW.version", "20"),
            ("displayName", "web-1"),
            ("guestOS", "ubuntu-64"),
            ("firmware", "efi"),
            ("numvcpus", "2"),
            ("cpuid.coresPerSocket", "2"),
            ("memsize", "4096"),
            ("pciBridge4.virtualDev", "pcieRootPort"),
            ("pciBridge7.functions", "8"),
            ("scsi0.present", "TRUE"),
            ("scsi0.virtualDev", "pvscsi"),
            ("scsi0:0.fileName", "web-1.vmdk"),
            ("scsi0:1.fileName", "web-1-1.vmdk"),
            ("ethernet0.connectionType", "custom"),
            ("ethernet0.vnet", "VMnet3"),
            ("ethernet0.virtualDev", "vmxnet3"),
            ("ethernet0.startConnected", "TRUE"),
            ("guestinfo.userdata.encoding", "base64"),
        ] {
            assert_eq!(get(&k, key), Some(value), "{key}");
        }
        assert_eq!(get(&k, "uefi.secureBoot.enabled"), None);
        assert_eq!(get(&k, "sata0.present"), None, "no SATA without a SATA disk or a CD");
        // What the inventory reads back.
        let info = parse_vmx(&text);
        assert_eq!(info.display_name.as_deref(), Some("web-1"));
        assert_eq!((info.num_vcpus, info.memsize_mb), (Some(2), Some(4096)));
        assert!(!info.suspended);
    }

    #[test]
    fn an_iso_install_boots_its_cd_and_windows_gets_secure_boot() {
        let windows = NewVmx {
            display_name: "win-1".into(),
            guest_os: "windows2019srvNext-64".into(),
            firmware: Firmware::EfiSecureBoot,
            disks: vec![VmxDisk {
                file_name: "win-1.vmdk".into(),
                controller: DiskController::Nvme,
                controller_model: "nvme".into(),
            }],
            iso: Some(r"C:\ISOs\server.iso".into()),
            network: Network::Bridged,
            nic: "e1000e".into(),
            extra: Vec::new(),
            ..ubuntu()
        };
        let k = keys(&render(&windows));
        assert_eq!(get(&k, "uefi.secureBoot.enabled"), Some("TRUE"));
        assert_eq!(get(&k, "nvme0.present"), Some("TRUE"));
        assert_eq!(get(&k, "nvme0:0.fileName"), Some("win-1.vmdk"));
        assert_eq!(get(&k, "sata0.present"), Some("TRUE"));
        assert_eq!(get(&k, "sata0:0.deviceType"), Some("cdrom-image"));
        assert_eq!(get(&k, "sata0:0.fileName"), Some(r"C:\ISOs\server.iso"));
        assert_eq!(get(&k, "sata0:0.startConnected"), Some("TRUE"));
        assert_eq!(get(&k, "ethernet0.connectionType"), Some("bridged"));
        assert_eq!(get(&k, "ethernet0.vnet"), None);

        let bios = NewVmx {
            firmware: Firmware::Bios,
            disks: vec![VmxDisk {
                file_name: "x.vmdk".into(),
                controller: DiskController::Sata,
                controller_model: "ahci".into(),
            }],
            iso: Some(r"C:\ISOs\x.iso".into()),
            ..ubuntu()
        };
        let k = keys(&render(&bios));
        assert_eq!(get(&k, "bios.bootOrder"), Some("cdrom,hdd"));
        assert_eq!(get(&k, "firmware"), None);
        assert_eq!(get(&k, "sata0:0.fileName"), Some("x.vmdk"));
        assert_eq!(
            get(&k, "sata0:1.deviceType"),
            Some("cdrom-image"),
            "the CD after the SATA disk"
        );
    }

    #[test]
    fn slots_follow_each_controller() {
        let disk = |controller| VmxDisk {
            file_name: "d.vmdk".into(),
            controller,
            controller_model: "x".into(),
        };
        let scsi: Vec<VmxDisk> = (0..9).map(|_| disk(DiskController::Scsi)).collect();
        assert_eq!(
            disk_slots(&scsi),
            ["scsi0:0", "scsi0:1", "scsi0:2", "scsi0:3", "scsi0:4", "scsi0:5", "scsi0:6", "scsi0:8", "scsi0:9"],
            "7 is the SCSI controller's own"
        );
        let ide: Vec<VmxDisk> = (0..3).map(|_| disk(DiskController::Ide)).collect();
        assert_eq!(disk_slots(&ide), ["ide0:0", "ide0:1", "ide1:0"]);
        let mixed = vec![
            disk(DiskController::Nvme),
            disk(DiskController::Sata),
            disk(DiskController::Nvme),
        ];
        assert_eq!(disk_slots(&mixed), ["nvme0:0", "sata0:0", "nvme0:1"]);
    }

    #[test]
    fn values_are_escaped_as_workstation_writes_them() {
        assert_eq!(escape_value(r#"a "b" | c"#), "a |22b|22 |7C c");
        assert_eq!(escape_value("line\nbreak"), "line|0Abreak");
        assert_eq!(escape_value("Ünïcode web"), "Ünïcode web");
        let named = NewVmx {
            display_name: "lab \"blue\"".into(),
            ..ubuntu()
        };
        assert_eq!(
            parse_vmx(&render(&named)).display_name.as_deref(),
            Some("lab \"blue\""),
            "reads back"
        );
        assert_eq!(connection(&Network::Internal { name: "x".into() }), None);
    }
}
