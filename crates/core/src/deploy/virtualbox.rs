//! VM-21, VM-22, VM-10: the VBoxManage calls a VirtualBox deploy makes, as pure functions tested without
//! VirtualBox. Each is a list of arguments for one `VBoxManage` run; none holds a password (the unattended
//! install's goes through `--password-file`).
//!
//! * A new VM: `createvm --name --uuid --ostype --basefolder --register`, `modifyvm` (CPU, memory, firmware, TPM,
//!   network card, boot order), Secure Boot through `modifynvram`, one `storagectl` per controller, `createmedium`
//!   per disk and `storageattach` for each disk and the DVD.
//! * A cloud image becomes the boot disk with `clonemedium` (VMDK) or `convertfromraw` (raw), copied, then grown
//!   with `modifymedium --resize`.
//! * Clones: `clonevm <uuid> [--snapshot <uuid>] [--options=Link] --name --uuid --register --basefolder`.
//! * OVA/OVF: `import <file> --vsys 0 --vmname --basefolder --cpus --memory`.
//! * ISOs VirtualBox can install: `unattended install <uuid> --iso --user --password-file --hostname`.
//! * Cleanup: `unregistervm <uuid> --delete`.

use std::path::Path;

use super::spec::{DiskPlan, ProfileSpec, SizeSpec};
use crate::catalog::profiles::Firmware;
use crate::catalog::sizes::{DiskController, Provisioning};
use crate::catalog::templates::Network;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|a| (*a).to_owned()).collect()
}

fn path(p: &Path) -> String {
    p.display().to_string()
}

pub fn createvm_args(name: &str, uuid: &str, os_type: &str, base_folder: &Path) -> Vec<String> {
    vec![
        "createvm".into(),
        "--name".into(),
        name.into(),
        "--uuid".into(),
        uuid.into(),
        "--ostype".into(),
        os_type.into(),
        "--basefolder".into(),
        path(base_folder),
        "--register".into(),
    ]
}

/// `--nic1` and the option naming its network, as VirtualBox 7 takes them.
pub fn nic_args(network: &Network, host_adapter: Option<&str>, nic: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (kind, option) = match network {
        Network::Nat => ("nat", None),
        Network::HostOnly => ("hostonly", host_adapter.map(|a| ("--hostonlyadapter1", a.to_owned()))),
        Network::Bridged => ("bridged", host_adapter.map(|a| ("--bridgeadapter1", a.to_owned()))),
        Network::NatNetwork { name } => ("natnetwork", Some(("--nat-network1", name.clone()))),
        Network::Internal { name } => ("intnet", Some(("--intnet1", name.clone()))),
        // Workstation's only; the plan never sends one here.
        Network::Vmnet { .. } => ("nat", None),
    };
    out.push("--nic1".into());
    out.push(kind.into());
    if let Some((name, value)) = option {
        out.push(name.into());
        out.push(value);
    }
    out.push("--nictype1".into());
    out.push(nic.into());
    out.push("--cableconnected1".into());
    out.push("on".into());
    out
}

/// `modifyvm` for a new VM: the size's CPU and memory, the profile's firmware and TPM, the network card, the
/// boot order (the DVD first for an ISO install) and a display that works for every guest.
pub fn modifyvm_args(
    uuid: &str,
    size: &SizeSpec,
    profile: &ProfileSpec,
    network: &Network,
    host_adapter: Option<&str>,
    boot_dvd_first: bool,
) -> Vec<String> {
    let mut out = vec![
        "modifyvm".into(),
        uuid.into(),
        "--cpus".into(),
        size.vcpus().to_string(),
        "--memory".into(),
        size.memory_mb.to_string(),
        "--firmware".into(),
        match profile.firmware {
            Firmware::Bios => "bios",
            Firmware::Efi | Firmware::EfiSecureBoot => "efi",
        }
        .into(),
        "--ioapic".into(),
        "on".into(),
        "--graphicscontroller".into(),
        "vmsvga".into(),
        "--vram".into(),
        "16".into(),
    ];
    if let Some(tpm) = &profile.tpm {
        out.push("--tpm-type".into());
        out.push(tpm.clone());
    }
    out.extend(nic_args(network, host_adapter, &profile.nic));
    let (first, second) = if boot_dvd_first {
        ("dvd", "disk")
    } else {
        ("disk", "dvd")
    };
    out.extend(args(&[
        "--boot1", first, "--boot2", second, "--boot3", "none", "--boot4", "none",
    ]));
    out
}

/// Secure Boot on an EFI VM: a UEFI variable store with Microsoft's and Oracle's keys, then on.
pub fn secure_boot_calls(uuid: &str) -> Vec<Vec<String>> {
    vec![
        args(&["modifynvram", uuid, "inituefivarstore"]),
        args(&["modifynvram", uuid, "enrollmssignatures"]),
        args(&["modifynvram", uuid, "enrollorclpk"]),
        args(&["modifynvram", uuid, "secureboot", "--enable"]),
    ]
}

/// The storage controller's name in the VM (VirtualBox shows it) and its `--add` bus.
pub fn controller_name(controller: DiskController) -> &'static str {
    match controller {
        DiskController::Sata => "SATA",
        DiskController::Scsi => "SCSI",
        DiskController::Nvme => "NVMe",
        DiskController::Ide => "IDE",
    }
}

fn bus(controller: DiskController) -> &'static str {
    match controller {
        DiskController::Sata => "sata",
        DiskController::Scsi => "scsi",
        DiskController::Nvme => "pcie",
        DiskController::Ide => "ide",
    }
}

pub fn storagectl_args(uuid: &str, controller: DiskController, model: &str, ports: u32) -> Vec<String> {
    let mut out = args(&[
        "storagectl",
        uuid,
        "--name",
        controller_name(controller),
        "--add",
        bus(controller),
        "--controller",
        model,
    ]);
    if matches!(controller, DiskController::Sata | DiskController::Nvme) {
        out.push("--portcount".into());
        out.push(ports.max(1).to_string());
    }
    out
}

/// `--variant`: Standard grows as the guest writes (thin), Fixed takes its size at once (thick).
pub fn variant(provisioning: Provisioning) -> &'static str {
    match provisioning {
        Provisioning::Thin => "Standard",
        Provisioning::Thick => "Fixed",
    }
}

pub fn createmedium_args(file: &Path, size_gb: u32, provisioning: Provisioning) -> Vec<String> {
    vec![
        "createmedium".into(),
        "disk".into(),
        "--filename".into(),
        path(file),
        "--size".into(),
        (u64::from(size_gb) * 1024).to_string(),
        "--format".into(),
        "VDI".into(),
        "--variant".into(),
        variant(provisioning).into(),
    ]
}

/// A cloud image's copy as the new VM's boot disk: `clonemedium` for a VMDK, `convertfromraw` for a raw image.
pub fn copy_image_args(image: &Path, raw: bool, target: &Path, provisioning: Provisioning) -> Vec<String> {
    let mut out = if raw {
        vec!["convertfromraw".into(), path(image), path(target)]
    } else {
        vec!["clonemedium".into(), "disk".into(), path(image), path(target)]
    };
    out.extend(args(&["--format", "VDI", "--variant", variant(provisioning)]));
    out
}

/// Grows a disk to `size_gb` (VirtualBox never shrinks one this way).
pub fn resize_args(disk: &str, size_gb: u32) -> Vec<String> {
    vec![
        "modifymedium".into(),
        "disk".into(),
        disk.into(),
        "--resize".into(),
        (u64::from(size_gb) * 1024).to_string(),
    ]
}

pub fn attach_args(uuid: &str, controller: DiskController, port: u32, dvd: bool, medium: &str) -> Vec<String> {
    attach_named(uuid, controller_name(controller), port, 0, dvd, medium)
}

/// `storageattach` on a controller by its name in the VM (a clone's or an import's own).
pub fn attach_named(uuid: &str, controller: &str, port: u32, device: u32, dvd: bool, medium: &str) -> Vec<String> {
    vec![
        "storageattach".into(),
        uuid.into(),
        "--storagectl".into(),
        controller.into(),
        "--port".into(),
        port.to_string(),
        "--device".into(),
        device.to_string(),
        "--type".into(),
        if dvd { "dvddrive" } else { "hdd" }.into(),
        "--medium".into(),
        medium.into(),
    ]
}

/// A `<controller>-<port>-<device>` slot (`SATA-1-0`) as its parts.
pub fn parse_slot(slot: &str) -> Option<(String, u32, u32)> {
    let mut parts = slot.rsplitn(3, '-');
    let device = parts.next()?.parse().ok()?;
    let port = parts.next()?.parse().ok()?;
    let controller = parts.next()?.to_owned();
    Some((controller, port, device))
}

/// Where each disk of a size goes: its controller and port, one controller of each kind (IDE takes ports 0 and 1
/// on its first channel and the device stays 0, so at most two IDE disks).
pub fn disk_ports(disks: &[DiskPlan]) -> Vec<(DiskController, u32)> {
    let mut used: Vec<(DiskController, u32)> = Vec::new();
    disks
        .iter()
        .map(|disk| {
            let port = used.iter().filter(|(c, _)| *c == disk.controller).count() as u32;
            used.push((disk.controller, port));
            (disk.controller, port)
        })
        .collect()
}

/// The port the DVD drive gets: the next free one on the boot disk's controller.
pub fn dvd_port(disks: &[DiskPlan]) -> (DiskController, u32) {
    let controller = disks.first().map_or(DiskController::Sata, |d| d.controller);
    let taken = disks.iter().filter(|d| d.controller == controller).count() as u32;
    (controller, taken)
}

pub fn clonevm_args(
    source: &str,
    snapshot: Option<&str>,
    linked: bool,
    name: &str,
    uuid: &str,
    base_folder: &Path,
) -> Vec<String> {
    let mut out = vec!["clonevm".into(), source.into()];
    if let Some(snapshot) = snapshot {
        out.push("--snapshot".into());
        out.push(snapshot.into());
    }
    if linked {
        out.push("--options=Link".into());
    }
    out.extend([
        "--name".into(),
        name.into(),
        "--uuid".into(),
        uuid.into(),
        "--basefolder".into(),
        path(base_folder),
        "--register".into(),
    ]);
    out
}

pub fn import_args(source: &Path, name: &str, base_folder: &Path, size: Option<&SizeSpec>) -> Vec<String> {
    let mut out = vec![
        "import".into(),
        path(source),
        "--vsys".into(),
        "0".into(),
        "--vmname".into(),
        name.into(),
        "--basefolder".into(),
        path(base_folder),
    ];
    if let Some(size) = size {
        out.extend([
            "--cpus".into(),
            size.vcpus().to_string(),
            "--memory".into(),
            size.memory_mb.to_string(),
        ]);
    }
    out
}

/// After a clone or an import: the size's CPU and memory, and the network when the deploy sets one.
pub fn resize_vm_args(uuid: &str, size: &SizeSpec, network: Option<(&Network, Option<&str>, &str)>) -> Vec<String> {
    let mut out = vec![
        "modifyvm".into(),
        uuid.into(),
        "--cpus".into(),
        size.vcpus().to_string(),
        "--memory".into(),
        size.memory_mb.to_string(),
    ];
    if let Some((network, adapter, nic)) = network {
        out.extend(nic_args(network, adapter, nic));
    }
    out
}

/// An unattended install: the user and the hostname (VirtualBox wants a domain in it), the password from a file
/// only this Windows user can read.
pub fn unattended_args(uuid: &str, iso: &Path, user: &str, password_file: &Path, hostname: &str) -> Vec<String> {
    vec![
        "unattended".into(),
        "install".into(),
        uuid.into(),
        "--iso".into(),
        path(iso),
        "--user".into(),
        user.into(),
        "--password-file".into(),
        path(password_file),
        "--hostname".into(),
        format!("{hostname}.localdomain"),
        "--install-additions".into(),
    ]
}

pub fn unregister_args(uuid: &str) -> Vec<String> {
    args(&["unregistervm", uuid, "--delete"])
}

/// The seed's DVD out once the first boot has read it (a running VM takes it).
pub fn eject_args(uuid: &str, controller: DiskController, port: u32) -> Vec<String> {
    attach_args(uuid, controller, port, true, "emptydrive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::profiles::GuestFamily;

    fn size() -> SizeSpec {
        SizeSpec {
            id: "disk.large".into(),
            name: "disk.large".into(),
            sockets: 1,
            cores_per_socket: 2,
            memory_mb: 4096,
            disks: vec![
                DiskPlan {
                    size_gb: 40,
                    provisioning: Provisioning::Thin,
                    controller: DiskController::Sata,
                    controller_model: "IntelAhci".into(),
                },
                DiskPlan {
                    size_gb: 500,
                    provisioning: Provisioning::Thick,
                    controller: DiskController::Sata,
                    controller_model: "IntelAhci".into(),
                },
            ],
        }
    }

    fn profile(firmware: Firmware, tpm: Option<&str>) -> ProfileSpec {
        ProfileSpec {
            id: "ubuntu".into(),
            name: "Ubuntu".into(),
            family: GuestFamily::Linux,
            firmware,
            guest_os: "Ubuntu_64".into(),
            hardware_version: None,
            nic: "virtio".into(),
            tpm: tpm.map(str::to_owned),
        }
    }

    #[test]
    fn a_new_vm_is_created_and_set_up() {
        let uuid = "3f0c1a2b-1111-4222-8333-444455556666";
        assert_eq!(
            createvm_args("web-1", uuid, "Ubuntu_64", Path::new(r"C:\VMs\lab")),
            [
                "createvm",
                "--name",
                "web-1",
                "--uuid",
                uuid,
                "--ostype",
                "Ubuntu_64",
                "--basefolder",
                r"C:\VMs\lab",
                "--register"
            ]
        );
        let modify = modifyvm_args(
            uuid,
            &size(),
            &profile(Firmware::Efi, None),
            &Network::HostOnly,
            Some("VirtualBox Host-Only Ethernet Adapter"),
            false,
        );
        let joined = modify.join(" ");
        for part in [
            "--cpus 2",
            "--memory 4096",
            "--firmware efi",
            "--nic1 hostonly --hostonlyadapter1 VirtualBox Host-Only Ethernet Adapter",
            "--nictype1 virtio",
            "--boot1 disk --boot2 dvd",
        ] {
            assert!(joined.contains(part), "{part} in {joined}");
        }
        assert!(!joined.contains("--tpm-type"));
        let windows = modifyvm_args(
            uuid,
            &size(),
            &profile(Firmware::EfiSecureBoot, Some("2.0")),
            &Network::Internal { name: "lab".into() },
            None,
            true,
        )
        .join(" ");
        assert!(windows.contains("--tpm-type 2.0"), "{windows}");
        assert!(windows.contains("--nic1 intnet --intnet1 lab"), "{windows}");
        assert!(
            windows.contains("--boot1 dvd --boot2 disk"),
            "an ISO install boots the DVD first"
        );
        assert_eq!(secure_boot_calls(uuid).len(), 4);
        assert_eq!(
            secure_boot_calls(uuid)[3],
            ["modifynvram", uuid, "secureboot", "--enable"]
        );
    }

    #[test]
    fn disks_go_on_their_controllers() {
        let s = size();
        assert_eq!(
            disk_ports(&s.disks),
            [(DiskController::Sata, 0), (DiskController::Sata, 1)]
        );
        assert_eq!(dvd_port(&s.disks), (DiskController::Sata, 2));
        assert_eq!(
            storagectl_args("u", DiskController::Sata, "IntelAhci", 3),
            [
                "storagectl",
                "u",
                "--name",
                "SATA",
                "--add",
                "sata",
                "--controller",
                "IntelAhci",
                "--portcount",
                "3"
            ]
        );
        assert_eq!(
            storagectl_args("u", DiskController::Nvme, "NVMe", 1)[5],
            "pcie",
            "VirtualBox's NVMe controller is on the PCIe bus"
        );
        assert_eq!(
            createmedium_args(Path::new(r"C:\VMs\web-1\web-1-1.vdi"), 500, Provisioning::Thick),
            [
                "createmedium",
                "disk",
                "--filename",
                r"C:\VMs\web-1\web-1-1.vdi",
                "--size",
                "512000",
                "--format",
                "VDI",
                "--variant",
                "Fixed"
            ]
        );
        assert_eq!(
            attach_args("u", DiskController::Sata, 2, true, r"C:\VMs\web-1\web-1-cidata.iso"),
            [
                "storageattach",
                "u",
                "--storagectl",
                "SATA",
                "--port",
                "2",
                "--device",
                "0",
                "--type",
                "dvddrive",
                "--medium",
                r"C:\VMs\web-1\web-1-cidata.iso"
            ]
        );
        assert_eq!(eject_args("u", DiskController::Sata, 2).last().unwrap(), "emptydrive");
    }

    #[test]
    fn cloud_images_are_copied_then_grown() {
        assert_eq!(
            copy_image_args(
                Path::new(r"C:\Images\noble.vmdk"),
                false,
                Path::new(r"C:\VMs\a\a.vdi"),
                Provisioning::Thin
            ),
            [
                "clonemedium",
                "disk",
                r"C:\Images\noble.vmdk",
                r"C:\VMs\a\a.vdi",
                "--format",
                "VDI",
                "--variant",
                "Standard"
            ]
        );
        assert_eq!(
            copy_image_args(
                Path::new(r"C:\Images\noble.img"),
                true,
                Path::new(r"C:\VMs\a\a.vdi"),
                Provisioning::Thin
            )[0],
            "convertfromraw"
        );
        assert_eq!(
            resize_args(r"C:\VMs\a\a.vdi", 40),
            ["modifymedium", "disk", r"C:\VMs\a\a.vdi", "--resize", "40960"]
        );
    }

    #[test]
    fn clones_imports_and_unattended_installs() {
        let clone = clonevm_args(
            "aaaaaaaa-1111-4222-8333-444455556666",
            Some("bbbbbbbb-1111-4222-8333-444455556666"),
            true,
            "web-1",
            "cccccccc-1111-4222-8333-444455556666",
            Path::new(r"C:\VMs"),
        );
        assert_eq!(
            clone.join(" "),
            "clonevm aaaaaaaa-1111-4222-8333-444455556666 --snapshot bbbbbbbb-1111-4222-8333-444455556666 \
             --options=Link --name web-1 --uuid cccccccc-1111-4222-8333-444455556666 --basefolder C:\\VMs --register"
        );
        let full = clonevm_args("a", None, false, "b", "c", Path::new(r"C:\VMs")).join(" ");
        assert!(!full.contains("--snapshot") && !full.contains("Link"), "{full}");
        assert_eq!(
            import_args(
                Path::new(r"C:\Images\app.ova"),
                "app-1",
                Path::new(r"C:\VMs"),
                Some(&size())
            )
            .join(" "),
            r"import C:\Images\app.ova --vsys 0 --vmname app-1 --basefolder C:\VMs --cpus 2 --memory 4096"
        );
        let unattended = unattended_args(
            "u",
            Path::new(r"C:\ISOs\noble.iso"),
            "alice",
            Path::new(r"C:\Users\alice\AppData\Local\Temp\pw"),
            "web-1",
        );
        assert!(unattended
            .windows(2)
            .any(|w| w == ["--password-file", r"C:\Users\alice\AppData\Local\Temp\pw"]));
        assert!(unattended.windows(2).any(|w| w == ["--hostname", "web-1.localdomain"]));
        assert!(
            !unattended.iter().any(|a| a == "--password"),
            "never the password itself"
        );
        assert_eq!(unregister_args("u"), ["unregistervm", "u", "--delete"]);
    }
}
