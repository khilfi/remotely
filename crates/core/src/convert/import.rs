//! CV-01: what a file picked for an import is, and what it brings: an OVA or OVF from any vendor, a disk image
//! (VHD and VHDX from Hyper-V or Azure; qcow2, raw and `.img` from KVM, Proxmox or OpenStack; a VDI for Workstation
//! or a VMDK for VirtualBox), or a VM's own description (a libvirt domain XML, a Proxmox `.conf`) with its disks
//! beside it. A read: the deploy that makes the VM goes through R2's deploy ([`crate::deploy`]), with its preview,
//! tiers and cleanup.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::describe::{self, Described, MAX_DESCRIPTION_BYTES};
use super::formats::{DiskFormat, OutputKind};
use super::inspect::{inspect, ImageInfo};
use super::plan::{self, NoPlan, Source};
use crate::adapters::disk_tools::{Tool, ToolPaths};
use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::images::ImageFormat;
use crate::catalog::profiles::GuestFamily;
use crate::error::{CoreError, Result};
use crate::untrusted;

/// What the picked file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ImportKind {
    /// An OVA or OVF: the hypervisor's own import (ovftool, `VBoxManage import`).
    Appliance,
    /// One disk image.
    Disk,
    /// A libvirt domain XML, its disks beside it.
    Libvirt,
    /// A Proxmox VE `.conf`, its disks beside it.
    Proxmox,
}

/// One disk an import brings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportDiskView {
    /// The name the description gives it (or the file's own).
    pub name: String,
    /// The file on this PC, when it was found.
    pub path: Option<String>,
    pub info: Option<ImageInfo>,
    pub virtual_bytes: Option<u64>,
    /// Why it can't be imported.
    pub problem: Option<String>,
}

/// What Import shows about a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportAnalysis {
    pub path: String,
    pub kind: ImportKind,
    /// The appliance's format, for an OVA or OVF.
    pub appliance: Option<ImageFormat>,
    pub described: Described,
    pub disks: Vec<ImportDiskView>,
    /// The VM's name to start from.
    pub suggested_name: String,
    /// The OS profile that fits the guest best, when it can be told.
    pub profile: Option<&'static str>,
    /// Why it can't be imported at all.
    pub problems: Vec<String>,
    /// Why it can't be imported on each hypervisor here (tools), `None` when it can.
    pub on_workstation: Option<String>,
    pub on_virtualbox: Option<String>,
    /// qemu-img would make an import possible that isn't now.
    pub needs_qemu_img: bool,
    pub notes: Vec<String>,
}

impl ImportAnalysis {
    /// Why it can't be imported on `hypervisor`, or `None`.
    pub fn refusal(&self, hypervisor: Hypervisor) -> Option<String> {
        if let Some(problem) = self.problems.first() {
            return Some(problem.clone());
        }
        match hypervisor {
            Hypervisor::Vmware => self.on_workstation.clone(),
            Hypervisor::VirtualBox => self.on_virtualbox.clone(),
        }
    }

    /// The disks found, each with its format, in order.
    pub fn found_disks(&self) -> Vec<(PathBuf, DiskFormat, u64)> {
        self.disks
            .iter()
            .filter_map(|d| {
                let info = d.info.as_ref()?;
                Some((
                    PathBuf::from(d.path.as_ref()?),
                    info.format,
                    info.virtual_bytes.unwrap_or(0),
                ))
            })
            .collect()
    }
}

/// What a new VM's disk is on each hypervisor: Workstation's VMDK, VirtualBox's VDI.
pub fn native_kind(hypervisor: Hypervisor, thin: bool) -> OutputKind {
    match hypervisor {
        Hypervisor::Vmware => OutputKind::of(DiskFormat::Vmdk, thin),
        Hypervisor::VirtualBox => OutputKind::of(DiskFormat::Vdi, thin),
    }
}

/// The formats R2's deploy copies with the hypervisor's own call (vdiskmanager `-r`; `clonemedium` or
/// `convertfromraw`); the others go through the conversion plan.
pub fn copied_by_deploy(hypervisor: Hypervisor, format: DiskFormat) -> bool {
    match hypervisor {
        Hypervisor::Vmware => matches!(format, DiskFormat::Vmdk | DiskFormat::Raw),
        Hypervisor::VirtualBox => matches!(
            format,
            DiskFormat::Vmdk | DiskFormat::Raw | DiskFormat::Vdi | DiskFormat::Vhd
        ),
    }
}

/// Why `hypervisor` can't take this disk with the tools here, or `None`.
fn disk_refusal(hypervisor: Hypervisor, info: &ImageInfo, tools: &ToolPaths) -> (Option<String>, bool) {
    let kind = native_kind(hypervisor, true);
    if copied_by_deploy(hypervisor, info.format) && !info.has_parent() {
        let tool = match hypervisor {
            Hypervisor::Vmware => Tool::VdiskManager,
            Hypervisor::VirtualBox => Tool::VBoxManage,
        };
        return if tools.has(tool) {
            (None, false)
        } else {
            (Some(format!("{} isn't on this PC", tool.label())), false)
        };
    }
    match plan::plan(Source::file(info.format), kind, None, tools) {
        Ok(_) => (None, false),
        Err(why) => (Some(why.describe(info.format, kind)), why == NoPlan::NeedsQemuImg),
    }
}

/// The OS profile a description's words suggest.
pub fn profile_for(family: Option<GuestFamily>, os: Option<&str>) -> Option<&'static str> {
    let os = os.unwrap_or("").to_ascii_lowercase();
    match family? {
        GuestFamily::Windows => Some(
            if ["2012", "2016", "2019", "2022", "2025", "srv", "server"]
                .iter()
                .any(|w| os.contains(w))
            {
                "windows-server"
            } else if os.contains("11") {
                "windows-11"
            } else {
                "windows-10"
            },
        ),
        GuestFamily::Linux => Some(if os.contains("ubuntu") {
            "ubuntu"
        } else if os.contains("debian") {
            "debian"
        } else if ["rhel", "redhat", "rocky", "alma", "centos", "fedora", "oracle"]
            .iter()
            .any(|w| os.contains(w))
        {
            "rhel"
        } else {
            "other-linux"
        }),
    }
}

/// A VM name from a description or a file name: what deploys take (letters, digits, `-`, `_`, `.`, spaces).
pub fn vm_name(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || " -_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned
        .trim()
        .trim_matches(['.', '-'])
        .chars()
        .take(60)
        .collect::<String>();
    if trimmed.is_empty() {
        "imported".into()
    } else {
        trimmed
    }
}

/// A disk a description names, looked for beside it: by its file name, or (Proxmox's volume names) a file of that
/// name with a disk image's extension.
async fn beside(folder: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains(['\\', '/']) || untrusted::path_refusal(name).is_some() {
        return None;
    }
    let exact = folder.join(name);
    if tokio::fs::metadata(&exact).await.is_ok_and(|m| m.is_file()) {
        return Some(exact);
    }
    for ext in ["qcow2", "raw", "img", "vmdk", "vdi", "vhd", "vhdx"] {
        let candidate = folder.join(format!("{name}.{ext}"));
        if tokio::fs::metadata(&candidate).await.is_ok_and(|m| m.is_file()) {
            return Some(candidate);
        }
    }
    None
}

/// The format a description writes for a disk, as Remotely names it.
fn described_format(text: &str) -> Option<DiskFormat> {
    Some(match text.to_ascii_lowercase().as_str() {
        "qcow2" => DiskFormat::Qcow2,
        "raw" => DiskFormat::Raw,
        "vmdk" => DiskFormat::Vmdk,
        "vdi" => DiskFormat::Vdi,
        "vpc" | "vhd" => DiskFormat::Vhd,
        "vhdx" => DiskFormat::Vhdx,
        _ => return None,
    })
}

/// Reads what the file at `path` (picked by the user) is and what it brings.
pub async fn analyze(path: &Path, tools: &ToolPaths) -> Result<ImportAnalysis> {
    if let Some(refusal) = untrusted::path_refusal(path) {
        return Err(CoreError::InvalidInput(format!(
            "{} {}, so Remotely doesn't open it.",
            path.display(),
            refusal.describe()
        )));
    }
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let folder = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut out = ImportAnalysis {
        path: path.display().to_string(),
        kind: ImportKind::Disk,
        appliance: None,
        described: Described::default(),
        disks: Vec::new(),
        suggested_name: vm_name(&stem),
        profile: None,
        problems: Vec::new(),
        on_workstation: None,
        on_virtualbox: None,
        needs_qemu_img: false,
        notes: Vec::new(),
    };
    let read_text = |p: &Path| {
        let p = p.to_path_buf();
        async move {
            let bytes = untrusted::read_capped(&p, MAX_DESCRIPTION_BYTES)
                .await
                .map_err(|err| match err {
                    untrusted::ReadError::TooLarge { .. } => CoreError::InvalidInput(format!(
                        "{} is larger than a VM's description is ({} at most), so Remotely didn't read it.",
                        p.display(),
                        untrusted::size_words(MAX_DESCRIPTION_BYTES)
                    )),
                    untrusted::ReadError::Io(err) => CoreError::Io(err),
                })?;
            Ok::<_, CoreError>(String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    match ext.as_str() {
        "ova" | "ovf" => {
            let format = if ext == "ova" {
                ImageFormat::Ova
            } else {
                ImageFormat::Ovf
            };
            out.kind = ImportKind::Appliance;
            out.appliance = Some(format);
            let descriptor = crate::deploy::ovf::appliance_descriptor(&out.path, format).await?;
            match descriptor.as_deref().and_then(describe::parse_ovf) {
                Some(described) => out.described = described,
                None => out.notes.push(
                    "Its OVF descriptor couldn't be read, so its CPU, memory and disks come from the size you pick."
                        .into(),
                ),
            }
            for disk in &out.described.disks {
                out.disks.push(ImportDiskView {
                    name: disk.file.clone(),
                    path: None,
                    info: None,
                    virtual_bytes: disk.capacity_bytes,
                    problem: None,
                });
            }
            if !tools.has(Tool::Ovftool) {
                out.on_workstation = Some("ovftool isn't on this PC (it comes with Workstation)".into());
            }
            if !tools.has(Tool::VBoxManage) {
                out.on_virtualbox = Some("VirtualBox isn't on this PC".into());
            }
        }
        "xml" | "conf" => {
            let text = read_text(path).await?;
            let (kind, described) = if ext == "xml" {
                (ImportKind::Libvirt, describe::parse_libvirt(&text))
            } else {
                (ImportKind::Proxmox, describe::parse_proxmox(&text))
            };
            out.kind = kind;
            let Some(described) = described else {
                return Err(CoreError::InvalidInput(format!(
                    "{} isn't a {} Remotely can read.",
                    path.display(),
                    if ext == "xml" {
                        "libvirt domain XML"
                    } else {
                        "Proxmox VM .conf"
                    }
                )));
            };
            out.described = described;
            if out.described.disks.is_empty() {
                out.problems.push("It names no disk.".into());
            }
            for disk in out.described.disks.clone() {
                let mut view = ImportDiskView {
                    name: disk.file.clone(),
                    path: None,
                    info: None,
                    virtual_bytes: disk.capacity_bytes,
                    problem: None,
                };
                match beside(&folder, &disk.file).await {
                    None => {
                        view.problem = Some(match kind {
                            ImportKind::Proxmox => format!(
                                "{} isn't in this folder: export it on the Proxmox host (qemu-img convert -O qcow2 <its volume> {}.qcow2) and copy it here",
                                disk.file, disk.file
                            ),
                            _ => format!("{} isn't in this folder: copy it from the KVM host beside the XML", disk.file),
                        });
                    }
                    Some(found) => match inspect(&found).await {
                        Ok(info) => {
                            let said = disk.format.as_deref().and_then(described_format);
                            if said.is_some_and(|f| f != info.format)
                                && !(said == Some(DiskFormat::Raw) && kind == ImportKind::Proxmox)
                            {
                                view.problem = Some(format!(
                                    "{} is a {}, not the {} the description says",
                                    found.display(),
                                    info.format.label(),
                                    disk.format.as_deref().unwrap_or("")
                                ));
                            } else if let Some(problem) = info.problems.first() {
                                view.problem = Some(problem.clone());
                            }
                            view.virtual_bytes = info.virtual_bytes.or(view.virtual_bytes);
                            view.path = Some(found.display().to_string());
                            view.info = Some(info);
                        }
                        Err(err) => view.problem = Some(err.to_string()),
                    },
                }
                out.disks.push(view);
            }
        }
        _ => {
            let info = inspect(path).await?;
            out.disks.push(ImportDiskView {
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: Some(out.path.clone()),
                virtual_bytes: info.virtual_bytes,
                problem: info.problems.first().cloned(),
                info: Some(info),
            });
            out.notes.push(
                "A disk alone says nothing of its VM: CPU and memory come from the size you pick, and the OS profile and firmware from your choice."
                    .into(),
            );
        }
    }
    if let Some(name) = out.described.name.as_deref().filter(|n| !n.trim().is_empty()) {
        out.suggested_name = vm_name(name);
    }
    out.profile = profile_for(out.described.family, out.described.os.as_deref());
    for (i, disk) in out.disks.iter().enumerate() {
        if let Some(problem) = &disk.problem {
            out.problems.push(format!("Disk {} ({}): {problem}.", i + 1, disk.name));
        }
    }
    if out.disks.len() > MAX_IMPORT_DISKS {
        out.problems
            .push(format!("An import takes at most {MAX_IMPORT_DISKS} disks."));
    }
    if out.kind != ImportKind::Appliance {
        let mut ws = None;
        let mut vb = None;
        for disk in &out.disks {
            let Some(info) = &disk.info else { continue };
            let (w, wq) = disk_refusal(Hypervisor::Vmware, info, tools);
            let (v, vq) = disk_refusal(Hypervisor::VirtualBox, info, tools);
            out.needs_qemu_img |= wq || vq;
            ws = ws.or(w);
            vb = vb.or(v);
        }
        out.on_workstation = ws;
        out.on_virtualbox = vb;
    }
    if out.described.family == Some(GuestFamily::Windows) && out.kind != ImportKind::Appliance {
        out.notes.push("A Windows guest boots only with a storage driver for its new disk controller: if it stops with INACCESSIBLE_BOOT_DEVICE, give the VM a SATA disk or install the driver where it came from.".into());
    }
    Ok(out)
}

/// The most disks one import brings.
pub const MAX_IMPORT_DISKS: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::disk_images::{self as img, TempFolder};

    fn no_qemu() -> ToolPaths {
        ToolPaths {
            qemu_img: None,
            ..ToolPaths::all()
        }
    }

    #[tokio::test]
    async fn a_disk_alone_is_one_disk_and_qcow2_needs_qemu_img() {
        let dir = TempFolder::new("import-disk");
        let path = dir.write("rocky.qcow2", &img::qcow2(64 << 20, None));
        let a = analyze(&path, &no_qemu()).await.unwrap();
        assert_eq!(a.kind, ImportKind::Disk);
        assert_eq!(a.suggested_name, "rocky");
        assert_eq!(a.found_disks().len(), 1);
        assert!(a.problems.is_empty());
        assert!(a.needs_qemu_img);
        assert!(a.refusal(Hypervisor::Vmware).unwrap().contains("qemu-img"));
        let a = analyze(&path, &ToolPaths::all()).await.unwrap();
        assert_eq!(a.refusal(Hypervisor::Vmware), None);
        assert_eq!(a.refusal(Hypervisor::VirtualBox), None);
        // A VHD from Hyper-V: VirtualBox copies it itself; Workstation converts it through VBoxManage.
        let vhd = dir.write("dc01.vhd", &img::vhd_fixed(1 << 20));
        let a = analyze(&vhd, &no_qemu()).await.unwrap();
        assert_eq!(a.refusal(Hypervisor::VirtualBox), None);
        assert_eq!(a.refusal(Hypervisor::Vmware), None);
        let ws_only = ToolPaths {
            qemu_img: None,
            vboxmanage: None,
            ..ToolPaths::all()
        };
        assert!(analyze(&vhd, &ws_only)
            .await
            .unwrap()
            .refusal(Hypervisor::Vmware)
            .unwrap()
            .contains("qemu-img"));
    }

    #[tokio::test]
    async fn a_libvirt_xml_brings_the_disks_beside_it() {
        let dir = TempFolder::new("import-libvirt");
        dir.write("db01.qcow2", &img::qcow2(64 << 20, None));
        let xml = "<domain type='kvm'><name>db01</name><memory unit='MiB'>2048</memory><vcpu>2</vcpu><os firmware='efi'/><metadata><libosinfo:os xmlns:libosinfo='x' id='http://ubuntu.com/ubuntu/24.04'/></metadata><devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/var/lib/libvirt/images/db01.qcow2'/></disk><disk type='file' device='disk'><driver type='raw'/><source file='/srv/db01-data.img'/></disk></devices></domain>";
        let path = dir.write("db01.xml", xml.as_bytes());
        let a = analyze(&path, &ToolPaths::all()).await.unwrap();
        assert_eq!(a.kind, ImportKind::Libvirt);
        assert_eq!(a.suggested_name, "db01");
        assert_eq!(a.profile, Some("ubuntu"));
        assert_eq!(a.described.efi, Some(true));
        assert_eq!(a.disks.len(), 2);
        assert!(a.disks[0].path.as_deref().unwrap().ends_with("db01.qcow2"));
        assert!(
            a.problems[0].contains("db01-data.img isn't in this folder"),
            "{:?}",
            a.problems
        );
        // Once it is there (raw), the import can go on.
        dir.write("db01-data.img", &img::raw_mbr(1 << 20));
        let a = analyze(&path, &ToolPaths::all()).await.unwrap();
        assert!(a.problems.is_empty(), "{:?}", a.problems);
        assert_eq!(a.found_disks().len(), 2);
        // A disk that isn't what the XML says.
        dir.write("x.qcow2", &img::vdi(1 << 20, 1));
        let p = dir.write(
            "x.xml",
            b"<domain><name>x</name><devices><disk device='disk'><driver type='qcow2'/><source file='x.qcow2'/></disk></devices></domain>",
        );
        let a = analyze(&p, &ToolPaths::all()).await.unwrap();
        assert!(a.problems[0].contains("is a VDI, not the qcow2"), "{:?}", a.problems);
    }

    #[tokio::test]
    async fn a_proxmox_conf_finds_its_volumes_by_name() {
        let dir = TempFolder::new("import-proxmox");
        dir.write("vm-100-disk-0.qcow2", &img::qcow2(64 << 20, None));
        let path = dir.write(
            "100.conf",
            b"name: web01\ncores: 2\nmemory: 2048\nostype: win11\nscsi0: local-lvm:vm-100-disk-0,size=64M\n",
        );
        let a = analyze(&path, &ToolPaths::all()).await.unwrap();
        assert_eq!(a.kind, ImportKind::Proxmox);
        assert_eq!(a.profile, Some("windows-11"));
        assert!(a.problems.is_empty(), "{:?}", a.problems);
        assert!(a.notes.iter().any(|n| n.contains("INACCESSIBLE_BOOT_DEVICE")));
        let missing = dir.write("101.conf", b"name: gone\nscsi0: local-lvm:vm-101-disk-0,size=8G\n");
        let a = analyze(&missing, &ToolPaths::all()).await.unwrap();
        assert!(a.problems[0].contains("qemu-img convert -O qcow2"), "{:?}", a.problems);
        // A volume name that tries to leave the folder is never looked for.
        assert_eq!(beside(dir.path(), r"..\..\Windows\win.ini").await, None);
    }

    #[tokio::test]
    async fn an_ova_says_its_vm_and_large_descriptions_are_refused() {
        let dir = TempFolder::new("import-ova");
        let ovf = img::ovf(
            "app01",
            2,
            4096,
            false,
            "debian11_64Guest",
            &[("app01-disk1.vmdk", 64 << 20)],
        );
        let disk = img::vmdk_sparse("app01-disk1.vmdk", 64 << 20, true);
        let path = dir.write(
            "app01.ova",
            &img::tar(&[("app01.ovf", ovf.as_bytes()), ("app01-disk1.vmdk", &disk)]),
        );
        let a = analyze(&path, &ToolPaths::all()).await.unwrap();
        assert_eq!(a.kind, ImportKind::Appliance);
        assert_eq!(a.appliance, Some(ImageFormat::Ova));
        assert_eq!(a.described.memory_mb, Some(4096));
        assert_eq!(a.profile, Some("debian"));
        assert_eq!(a.disks[0].virtual_bytes, Some(64 << 20));
        let no_ovftool = ToolPaths {
            ovftool: None,
            ..ToolPaths::all()
        };
        assert!(analyze(&path, &no_ovftool)
            .await
            .unwrap()
            .refusal(Hypervisor::Vmware)
            .is_some());
        let big = dir.write("big.xml", &vec![b' '; (MAX_DESCRIPTION_BYTES + 1) as usize]);
        let err = analyze(&big, &ToolPaths::all()).await.unwrap_err().to_string();
        assert!(err.contains("larger than a VM's description"), "{err}");
        assert_eq!(vm_name("Web 01 (prod)!"), "Web 01 -prod");
        assert_eq!(vm_name("///"), "imported");
    }
}
