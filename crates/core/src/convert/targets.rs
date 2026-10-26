//! VM-17, CV-02: what an export writes besides its disks, as pure functions: a README for the target (how to import,
//! and the driver changes the guest may need there), a libvirt domain XML for KVM and a Proxmox VE script.
//!
//! Every name that goes into the XML or the script is Remotely's own [`slug`] of the VM's name, never the name as
//! typed, so neither can be broken out of; the README shows the name only as text.

use serde::Serialize;

use super::formats::{size_text, OutputKind};
use super::spec::ExportTarget;
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vm_hardware::VmHardware;

/// The guest's family, as far as its hypervisor names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Family {
    Linux,
    Windows,
    Other,
}

/// What an export knows about the VM it writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedVm {
    pub name: String,
    pub hypervisor: Hypervisor,
    pub vcpus: u32,
    pub cores_per_socket: u32,
    pub memory_mb: u32,
    pub efi: bool,
    pub secure_boot: bool,
    pub family: Family,
    /// The guest OS as the hypervisor or its tools name it.
    pub os: Option<String>,
}

/// A disk file an export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedDisk {
    /// Its file name in the export's folder.
    pub file: String,
    pub kind: OutputKind,
    pub virtual_bytes: u64,
}

impl ExportedVm {
    pub fn from_hardware(name: &str, hypervisor: Hypervisor, hardware: &VmHardware) -> Self {
        let os = hardware.guest_os_name.clone().or_else(|| hardware.guest_os.clone());
        let named = format!(
            "{} {}",
            hardware.guest_os.as_deref().unwrap_or(""),
            hardware.guest_os_name.as_deref().unwrap_or("")
        )
        .to_ascii_lowercase();
        // Workstation's ids (`windows2019srv-64`, `winxppro`) and VirtualBox's names ("Windows 2022 (64-bit)").
        let windows = named
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| word.starts_with("win"));
        let family = if windows {
            Family::Windows
        } else if [
            "linux", "ubuntu", "debian", "rhel", "centos", "rocky", "alma", "fedora", "suse", "oracle", "arch",
        ]
        .iter()
        .any(|w| named.contains(w))
        {
            Family::Linux
        } else {
            Family::Other
        };
        let vcpus = hardware.vcpus.unwrap_or(1).max(1);
        let cores = hardware
            .cores_per_socket
            .filter(|c| *c > 0 && vcpus.is_multiple_of(*c))
            .unwrap_or(vcpus);
        Self {
            name: name.to_owned(),
            hypervisor,
            vcpus,
            cores_per_socket: cores,
            memory_mb: hardware.memory_mb.unwrap_or(1024).max(4),
            efi: hardware
                .firmware
                .as_deref()
                .is_some_and(|f| f.eq_ignore_ascii_case("uefi") || f.eq_ignore_ascii_case("efi")),
            secure_boot: hardware.secure_boot == Some(true),
            family,
            os,
        }
    }

    fn sockets(&self) -> u32 {
        (self.vcpus / self.cores_per_socket.max(1)).max(1)
    }
}

/// A name for files, the libvirt domain and Proxmox: letters, digits and `-` (others become `-`), at most 60.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        let c = if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '-'
        };
        if c == '-' && (out.is_empty() || out.ends_with('-')) {
            continue;
        }
        out.push(c);
        if out.len() >= 60 {
            break;
        }
    }
    let out = out.trim_end_matches('-').to_owned();
    if out.is_empty() {
        "vm".into()
    } else {
        out
    }
}

/// A disk's file name in an export: `<slug>.<ext>` for one disk, `<slug>-disk<N>.<ext>` for several.
pub fn disk_file(vm: &str, index: usize, count: usize, kind: OutputKind) -> String {
    if count == 1 {
        format!("{}.{}", slug(vm), kind.extension())
    } else {
        format!("{}-disk{}.{}", slug(vm), index + 1, kind.extension())
    }
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The libvirt domain for KVM: q35, the firmware the VM had, virtio disks and network for Linux (SATA and e1000e for
/// Windows, which has no virtio drivers until they are installed). The disks are looked for in libvirt's image folder.
pub fn libvirt_xml(vm: &ExportedVm, disks: &[ExportedDisk]) -> String {
    let windows = vm.family == Family::Windows;
    let mut out = String::new();
    out.push_str(
        "<!-- Made by Remotely. Copy the disks to /var/lib/libvirt/images, then: virsh define this file -->\n",
    );
    out.push_str("<domain type='kvm'>\n");
    out.push_str(&format!("  <name>{}</name>\n", xml(&slug(&vm.name))));
    out.push_str(&format!("  <memory unit='MiB'>{}</memory>\n", vm.memory_mb));
    out.push_str(&format!("  <vcpu placement='static'>{}</vcpu>\n", vm.vcpus));
    out.push_str(&format!(
        "  <cpu mode='host-passthrough' check='none'>\n    <topology sockets='{}' cores='{}' threads='1'/>\n  </cpu>\n",
        vm.sockets(),
        vm.cores_per_socket
    ));
    if vm.efi {
        out.push_str("  <os firmware='efi'>\n");
        if vm.secure_boot {
            out.push_str("    <firmware>\n      <feature enabled='yes' name='secure-boot'/>\n    </firmware>\n");
        }
    } else {
        out.push_str("  <os>\n");
    }
    out.push_str("    <type arch='x86_64' machine='q35'>hvm</type>\n    <boot dev='hd'/>\n  </os>\n");
    out.push_str("  <features>\n    <acpi/>\n    <apic/>\n");
    if vm.secure_boot {
        out.push_str("    <smm state='on'/>\n");
    }
    out.push_str("  </features>\n");
    out.push_str(&format!(
        "  <clock offset='{}'/>\n",
        if windows { "localtime" } else { "utc" }
    ));
    out.push_str("  <devices>\n");
    for (i, disk) in disks.iter().enumerate() {
        let (dev, bus) = if windows {
            (format!("sd{}", (b'a' + i as u8) as char), "sata")
        } else {
            (format!("vd{}", (b'a' + i as u8) as char), "virtio")
        };
        out.push_str(&format!(
            "    <disk type='file' device='disk'>\n      <driver name='qemu' type='{}'/>\n      <source file='/var/lib/libvirt/images/{}'/>\n      <target dev='{dev}' bus='{bus}'/>\n    </disk>\n",
            disk.kind.format().qemu_name(),
            xml(&disk.file)
        ));
    }
    out.push_str(&format!(
        "    <interface type='network'>\n      <source network='default'/>\n      <model type='{}'/>\n    </interface>\n",
        if windows { "e1000e" } else { "virtio" }
    ));
    out.push_str("    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n");
    out.push_str(&format!(
        "    <video>\n      <model type='{}'/>\n    </video>\n",
        if windows { "vga" } else { "virtio" }
    ));
    out.push_str("    <console type='pty'/>\n");
    out.push_str(
        "    <channel type='unix'>\n      <target type='virtio' name='org.qemu.guest_agent.0'/>\n    </channel>\n",
    );
    out.push_str("  </devices>\n</domain>\n");
    out
}

/// Proxmox's `--ostype`.
fn proxmox_ostype(vm: &ExportedVm) -> &'static str {
    match vm.family {
        Family::Linux => "l26",
        Family::Windows => {
            let os = vm.os.as_deref().unwrap_or("").to_ascii_lowercase();
            if ["11", "2022", "2025"].iter().any(|v| os.contains(v)) {
                "win11"
            } else {
                "win10"
            }
        }
        Family::Other => "other",
    }
}

/// The script that makes the VM on a Proxmox VE host: `sh import-to-proxmox.sh [VMID] [STORAGE]` in the folder with
/// the disks. `qm importdisk` imports each disk as an unused disk; `qm set` attaches it (SCSI for Linux, SATA for
/// Windows until it has virtio drivers) and boots the first.
pub fn proxmox_script(vm: &ExportedVm, disks: &[ExportedDisk]) -> String {
    let windows = vm.family == Family::Windows;
    let name = slug(&vm.name);
    let mut out = String::new();
    out.push_str("#!/bin/sh\n");
    out.push_str(&format!(
        "# Made by Remotely: makes the VM {name} on Proxmox VE from the disks in this folder.\n"
    ));
    out.push_str("# Run it on the Proxmox host, in this folder: sh import-to-proxmox.sh [VMID] [STORAGE]\n");
    out.push_str(
        "# VMID: the new VM's ID (the next free one by default); STORAGE: where its disks go (local-lvm by default).\n",
    );
    out.push_str("set -eu\ncd \"$(dirname \"$0\")\"\n");
    out.push_str("VMID=\"${1:-$(pvesh get /cluster/nextid)}\"\nSTORAGE=\"${2:-local-lvm}\"\n\n");
    let bios = if vm.efi { "ovmf" } else { "seabios" };
    out.push_str(&format!(
        "qm create \"$VMID\" --name {name} --memory {} --sockets {} --cores {} --cpu x86-64-v2-AES --ostype {} --machine q35 --bios {bios} --net0 {},bridge=vmbr0 --scsihw virtio-scsi-single\n",
        vm.memory_mb,
        vm.sockets(),
        vm.cores_per_socket,
        proxmox_ostype(vm),
        if windows { "e1000" } else { "virtio" },
    ));
    if vm.efi {
        let keys = if vm.secure_boot { 1 } else { 0 };
        out.push_str(&format!(
            "qm set \"$VMID\" --efidisk0 \"$STORAGE:1,efitype=4m,pre-enrolled-keys={keys}\"\n"
        ));
    }
    let bus = if windows { "sata" } else { "scsi" };
    for (i, disk) in disks.iter().enumerate() {
        out.push_str(&format!(
            "\nqm importdisk \"$VMID\" '{}' \"$STORAGE\"\n",
            disk.file.replace('\'', "")
        ));
        out.push_str(&format!(
            "DISK=\"$(qm config \"$VMID\" | sed -n 's/^unused[0-9]*: //p' | head -n 1)\"\nqm set \"$VMID\" --{bus}{i} \"$DISK\"\n"
        ));
    }
    out.push_str(&format!("\nqm set \"$VMID\" --boot order={bus}0\n"));
    out.push_str("echo \"Made VM $VMID. Start it with: qm start $VMID\"\n");
    out
}

/// The README's "how to import" for a target.
fn import_steps(target: ExportTarget, vm: &ExportedVm, disks: &[ExportedDisk]) -> Vec<String> {
    let first = disks.first().map_or("the disk", |d| d.file.as_str());
    let gen = if vm.efi { "2" } else { "1" };
    match target {
        ExportTarget::Appliance { ova, .. } => vec![
            format!(
                "VMware ESXi or vCenter: Deploy OVF Template, and pick the {}.",
                if ova { ".ova file" } else { ".ovf file and the files beside it" }
            ),
            "VirtualBox: File, Import Appliance. Workstation: File, Open. Other tools that read OVF take it as well; the .mf file holds each file's SHA-256 to check the copy.".into(),
        ],
        ExportTarget::Esxi { thick: false } => vec![
            format!("Upload {first} to a datastore (the datastore browser, or scp to the host)."),
            format!(
                "A stream-optimized disk can't run as it is: on the ESXi host, convert it into the VM's folder with `vmkfstools -i {first} -d thin <vm>.vmdk`."
            ),
            format!(
                "Make a VM with {} vCPU and {} MB, {} firmware, and attach the converted disk as an existing hard disk.",
                vm.vcpus,
                vm.memory_mb,
                if vm.efi { "EFI" } else { "BIOS" }
            ),
        ],
        ExportTarget::Esxi { thick: true } => vec![
            "Upload each .vmdk with its -flat.vmdk to the same datastore folder (both files, same names).".into(),
            format!(
                "Make a VM with {} vCPU and {} MB, {} firmware, and attach {first} as an existing hard disk.",
                vm.vcpus,
                vm.memory_mb,
                if vm.efi { "EFI" } else { "BIOS" }
            ),
        ],
        ExportTarget::HyperV => vec![
            "Copy the .vhdx files to the Hyper-V host (Hyper-V's own folder for virtual disks is a good place).".into(),
            format!(
                "Make a Generation {gen} VM ({}) with {} MB, attach {first} as its hard disk, then give it {} virtual processors. In PowerShell: `New-VM -Name {} -Generation {gen} -MemoryStartupBytes {}MB -VHDPath <path to {first}>`, then `Set-VMProcessor -VMName {} -Count {}`.",
                if vm.efi { "UEFI" } else { "BIOS" },
                vm.memory_mb,
                vm.vcpus,
                slug(&vm.name),
                vm.memory_mb,
                slug(&vm.name),
                vm.vcpus
            ),
        ],
        ExportTarget::Azure => vec![
            "Upload the .vhd as a page blob (AzCopy: `azcopy copy <file>.vhd \"<container URL with SAS>\" --blob-type PageBlob`), or upload it straight into a managed disk with `az disk create --upload-type Upload`.".into(),
            format!(
                "Make a managed disk from it and a VM from that disk, as Hyper-V generation V{gen} ({}): `az disk create --source <blob URL> --os-type {} --hyper-v-generation V{gen}`.",
                if vm.efi { "UEFI" } else { "BIOS" },
                if vm.family == Family::Windows { "Windows" } else { "Linux" }
            ),
            "Azure takes a fixed VHD whose size is a whole number of megabytes: this one is.".into(),
        ],
        ExportTarget::Kvm => vec![
            "Copy the .qcow2 files to /var/lib/libvirt/images on the KVM host (or change the paths in the XML).".into(),
            format!("`virsh define {}.xml`, then `virsh start {}`.", slug(&vm.name), slug(&vm.name)),
        ],
        ExportTarget::Proxmox => vec![
            "Copy this folder to the Proxmox VE host (scp).".into(),
            "On the host, in that folder: `sh import-to-proxmox.sh [VMID] [STORAGE]` (the next free ID and local-lvm by default). It makes the VM, imports each disk with `qm importdisk` and attaches it with `qm set`.".into(),
        ],
        ExportTarget::Raw => vec![
            "Upload the .raw files as the cloud asks: OpenStack `openstack image create --disk-format raw --container-format bare --file <file>.raw <name>`; Google Cloud wants the disk named disk.raw in a .tar.gz.".into(),
        ],
    }
}

/// The README's driver changes for a target.
fn driver_notes(target: ExportTarget, vm: &ExportedVm) -> Vec<String> {
    let mut out = Vec::new();
    let tools = match vm.hypervisor {
        Hypervisor::Vmware => "VMware Tools",
        Hypervisor::VirtualBox => "VirtualBox Guest Additions",
    };
    let to_vmware = matches!(target, ExportTarget::Esxi { .. } | ExportTarget::Appliance { .. });
    if !(to_vmware && vm.hypervisor == Hypervisor::Vmware) {
        out.push(format!(
            "Uninstall the {tools} in the guest once it runs there: they do nothing on another hypervisor."
        ));
    }
    let virtio = matches!(target, ExportTarget::Kvm | ExportTarget::Proxmox);
    let hyperv = matches!(target, ExportTarget::HyperV | ExportTarget::Azure);
    match vm.family {
        Family::Windows => {
            if virtio {
                out.push("Windows needs its storage driver before it moves: install the virtio-win drivers (viostor, vioscsi, NetKVM) in the guest first, or it stops with INACCESSIBLE_BOOT_DEVICE on a virtio disk. The XML and the script attach the disks as SATA and the network as e1000 so it boots without them; switch to virtio once the drivers are in.".into());
            }
            if hyperv {
                out.push(format!(
                    "Windows has Hyper-V's drivers built in. A Generation {} VM needs the disk's partition style to match: {}.",
                    if vm.efi { "2" } else { "1" },
                    if vm.efi { "GPT with UEFI" } else { "MBR with BIOS" }
                ));
            }
            if matches!(target, ExportTarget::Esxi { .. } | ExportTarget::Appliance { .. })
                && vm.hypervisor == Hypervisor::VirtualBox
            {
                out.push("Windows boots from the disk controller it had (VirtualBox's SATA): keep SATA on ESXi, or install the PVSCSI driver from VMware Tools before switching.".into());
            }
            out.push("Windows may ask to be activated again on the new hardware.".into());
        }
        Family::Linux | Family::Other => {
            if virtio {
                out.push("Most Linux kernels have virtio built in. If it doesn't find its disk, add virtio_blk, virtio_scsi, virtio_net and virtio_pci to its initramfs before exporting (`dracut -f --add-drivers \"virtio_blk virtio_scsi virtio_net virtio_pci\"` on RHEL-like systems; list them in /etc/initramfs-tools/modules and run `update-initramfs -u` on Debian and Ubuntu).".into());
            }
            if hyperv {
                out.push("Hyper-V and Azure need hv_vmbus, hv_storvsc and hv_netvsc in the initramfs (built into most current kernels).".into());
            }
            if target == ExportTarget::Azure {
                out.push("Azure also wants the Azure Linux Agent (waagent) or cloud-init, the serial console on (console=ttyS0 on the kernel line) and no swap partition on the OS disk.".into());
            }
            out.push("The network card's name and MAC change (ens33 may become eth0 or ens3): network settings tied to the old name or MAC need updating.".into());
        }
    }
    out
}

/// The README written beside an export's files.
pub fn readme(
    target: ExportTarget,
    vm: &ExportedVm,
    disks: &[ExportedDisk],
    extra_files: &[String],
    made_on: &str,
) -> String {
    let source = match vm.hypervisor {
        Hypervisor::Vmware => "VMware Workstation",
        Hypervisor::VirtualBox => "VirtualBox",
    };
    let mut out = format!("# {} as {}\n\n", vm.name, target.label());
    out.push_str(&format!(
        "Exported by Remotely on {made_on} from the {source} VM \"{}\", as it was then: powered off, with its snapshots merged into its disks. The VM itself wasn't changed.\n\n",
        vm.name
    ));
    out.push_str(&format!(
        "The VM: {} vCPU ({} socket{} of {} core{}), {} MB of memory, {} firmware{}{}.\n\n",
        vm.vcpus,
        vm.sockets(),
        if vm.sockets() == 1 { "" } else { "s" },
        vm.cores_per_socket,
        if vm.cores_per_socket == 1 { "" } else { "s" },
        vm.memory_mb,
        if vm.efi { "UEFI" } else { "BIOS" },
        if vm.secure_boot { " with Secure Boot" } else { "" },
        vm.os.as_deref().map(|os| format!(", {os}")).unwrap_or_default()
    ));
    if !disks.is_empty() || !extra_files.is_empty() {
        out.push_str("## Files\n\n");
        for disk in disks {
            out.push_str(&format!(
                "- `{}`: {}, {}\n",
                disk.file,
                disk.kind.label(),
                size_text(disk.virtual_bytes)
            ));
        }
        for file in extra_files {
            out.push_str(&format!("- `{file}`\n"));
        }
        out.push('\n');
    }
    out.push_str("## Import\n\n");
    for (i, step) in import_steps(target, vm, disks).iter().enumerate() {
        out.push_str(&format!("{}. {step}\n", i + 1));
    }
    out.push_str("\n## Before and after it first boots there\n\n");
    for note in driver_notes(target, vm) {
        out.push_str(&format!("- {note}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux() -> ExportedVm {
        ExportedVm::from_hardware(
            "Web 01 <prod>",
            Hypervisor::Vmware,
            &VmHardware {
                guest_os: Some("ubuntu-64".into()),
                guest_os_name: Some("Ubuntu 24.04.1 LTS".into()),
                vcpus: Some(4),
                cores_per_socket: Some(2),
                memory_mb: Some(4096),
                firmware: Some("UEFI".into()),
                ..Default::default()
            },
        )
    }

    fn windows() -> ExportedVm {
        ExportedVm::from_hardware(
            "dc01",
            Hypervisor::VirtualBox,
            &VmHardware {
                guest_os: Some("Windows 2022 (64-bit)".into()),
                vcpus: Some(2),
                memory_mb: Some(8192),
                firmware: Some("BIOS".into()),
                ..Default::default()
            },
        )
    }

    fn disks(kind: OutputKind) -> Vec<ExportedDisk> {
        vec![
            ExportedDisk {
                file: disk_file("Web 01 <prod>", 0, 2, kind),
                kind,
                virtual_bytes: 40 << 30,
            },
            ExportedDisk {
                file: disk_file("Web 01 <prod>", 1, 2, kind),
                kind,
                virtual_bytes: 500 << 30,
            },
        ]
    }

    #[test]
    fn names_in_files_scripts_and_xml_are_slugs() {
        assert_eq!(slug("Web 01 <prod>"), "web-01-prod");
        assert_eq!(slug("'; rm -rf /; '"), "rm-rf");
        assert_eq!(slug("ÄÖÜ"), "vm");
        assert_eq!(disk_file("web01", 0, 1, OutputKind::Qcow2), "web01.qcow2");
        assert_eq!(disk_file("web01", 1, 2, OutputKind::VhdFixed), "web01-disk2.vhd");
        let vm = linux();
        assert_eq!(vm.family, Family::Linux);
        assert!(vm.efi);
        assert_eq!((vm.sockets(), vm.cores_per_socket), (2, 2));
        assert_eq!(windows().family, Family::Windows);
    }

    #[test]
    fn the_libvirt_xml_fits_the_guest() {
        let text = libvirt_xml(&linux(), &disks(OutputKind::Qcow2));
        assert!(text.contains("<name>web-01-prod</name>"), "{text}");
        assert!(text.contains("<memory unit='MiB'>4096</memory>"));
        assert!(text.contains("<os firmware='efi'>"));
        assert!(text.contains("<topology sockets='2' cores='2' threads='1'/>"));
        assert!(text.contains("<source file='/var/lib/libvirt/images/web-01-prod-disk2.qcow2'/>"));
        assert!(text.contains("<target dev='vdb' bus='virtio'/>"));
        assert!(text.contains("<driver name='qemu' type='qcow2'/>"));
        assert!(!text.contains("<prod>"));
        let text = libvirt_xml(&windows(), &disks(OutputKind::Qcow2));
        assert!(text.contains("bus='sata'") && text.contains("<model type='e1000e'/>"));
        assert!(text.contains("<os>\n") && text.contains("offset='localtime'"));
    }

    #[test]
    fn the_proxmox_script_imports_and_attaches_each_disk() {
        let text = proxmox_script(&linux(), &disks(OutputKind::Qcow2));
        assert!(text.starts_with("#!/bin/sh\n"));
        assert!(
            text.contains("qm create \"$VMID\" --name web-01-prod --memory 4096 --sockets 2 --cores 2"),
            "{text}"
        );
        assert!(text.contains("--ostype l26") && text.contains("--bios ovmf"));
        assert!(text.contains("--efidisk0 \"$STORAGE:1,efitype=4m,pre-enrolled-keys=0\""));
        assert!(text.contains("qm importdisk \"$VMID\" 'web-01-prod-disk1.qcow2' \"$STORAGE\""));
        assert!(text.contains("qm set \"$VMID\" --scsi1 \"$DISK\""));
        assert!(text.contains("--boot order=scsi0"));
        let text = proxmox_script(&windows(), &disks(OutputKind::VmdkSparse));
        assert!(text.contains("--ostype win11") && text.contains("--net0 e1000,bridge=vmbr0"));
        assert!(text.contains("--sata0") && text.contains("--bios seabios"));
        assert!(!text.contains("efidisk0"));
    }

    #[test]
    fn each_readme_says_how_to_import_and_what_drivers_need() {
        let vm = linux();
        let d = disks(OutputKind::VhdFixed);
        let text = readme(ExportTarget::Azure, &vm, &d, &[], "2026-10-25");
        assert!(text.starts_with("# Web 01 <prod> as fixed VHD for Azure\n"));
        assert!(text.contains("4 vCPU (2 sockets of 2 cores), 4096 MB of memory, UEFI firmware, Ubuntu 24.04.1 LTS"));
        assert!(text.contains("`web-01-prod-disk1.vhd`: VHD, fixed, 40 GB"));
        assert!(text.contains("--blob-type PageBlob") && text.contains("V2"));
        assert!(text.contains("waagent") && text.contains("Uninstall the VMware Tools"));
        let w = windows();
        let text = readme(
            ExportTarget::Kvm,
            &w,
            &disks(OutputKind::Qcow2),
            &["dc01.xml".into()],
            "2026-10-25",
        );
        assert!(text.contains("virtio-win") && text.contains("INACCESSIBLE_BOOT_DEVICE"));
        assert!(text.contains("VirtualBox Guest Additions") && text.contains("`dc01.xml`"));
        let text = readme(
            ExportTarget::HyperV,
            &w,
            &disks(OutputKind::VhdxDynamic),
            &[],
            "2026-10-25",
        );
        assert!(text.contains("Generation 1") && text.contains("MBR with BIOS"));
        for target in [
            ExportTarget::Esxi { thick: false },
            ExportTarget::Esxi { thick: true },
            ExportTarget::Proxmox,
            ExportTarget::Raw,
            ExportTarget::Appliance {
                ova: true,
                version: super::super::args::OvfVersion::V1,
            },
        ] {
            let text = readme(target, &vm, &d, &[], "2026-10-25");
            assert!(text.contains("## Import\n\n1. "), "{target:?}");
        }
        // Workstation to ESXi keeps VMware Tools.
        let text = readme(ExportTarget::Esxi { thick: false }, &vm, &d, &[], "2026-10-25");
        assert!(!text.contains("Uninstall the VMware Tools") && text.contains("vmkfstools -i"));
    }
}
