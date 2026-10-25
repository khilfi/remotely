//! What a conversion or an export is, as the bus approves it and the job runs it: [`ConvertSpec`]
//! ([`crate::command_bus::Command::ImageConvert`], CV-03) and [`ExportSpec`] ([`crate::command_bus::Command::VmExport`],
//! VM-17 and CV-02). The conversion service builds them from a file the user picked and a place the shell's save
//! dialog chose; the UI never sends one (`Command::check_from_ui`). [`ConvertSpec::validate`] and
//! [`ExportSpec::validate`] check them again on the bus.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::args::OvfVersion;
use super::formats::{DiskFormat, OutputKind};
use crate::adapters::hypervisor::Hypervisor;
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};
use crate::untrusted;

/// The longest path a conversion writes (Windows' own limit is 260 without long paths).
pub const MAX_PATH_CHARS: usize = 240;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

fn check_path(what: &str, path: &str) -> Result<()> {
    if !Path::new(path).is_absolute() || path.chars().count() > MAX_PATH_CHARS || path.chars().any(char::is_control) {
        return invalid(format!("{what} '{path}' isn't a full path on this PC."));
    }
    if let Some(refusal) = untrusted::path_refusal(path) {
        return invalid(format!("{what} {path} {}.", refusal.describe()));
    }
    Ok(())
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map_or_else(|| path.to_owned(), |n| n.to_string_lossy().into_owned())
}

/// CV-03: one disk image converted into a new one. The source is never changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvertSpec {
    pub source: String,
    /// Its format when the conversion was asked: the job refuses a source that isn't that any more.
    pub source_format: DiskFormat,
    /// The new image; a file of that name (or a flat VMDK's extent) must not be there.
    pub output: String,
    pub kind: OutputKind,
    /// Azure: the size rounded up to a whole megabyte first, when it isn't one.
    #[serde(default)]
    pub whole_megabytes: bool,
}

impl ConvertSpec {
    pub fn targets(&self) -> Vec<TargetRef> {
        vec![TargetRef::DiskImage {
            path: self.output.clone(),
        }]
    }

    pub fn summary(&self) -> String {
        format!(
            "Convert {} to {} ({})",
            file_name(&self.source),
            file_name(&self.output),
            self.kind.label()
        )
    }

    pub fn describe(&self) -> String {
        let mut text = format!(
            "{} ({}) into {} ({})",
            self.source,
            self.source_format.label(),
            self.output,
            self.kind.label()
        );
        if self.whole_megabytes {
            text.push_str(", its size rounded up to a whole MB");
        }
        text
    }

    pub fn validate(&self) -> Result<()> {
        check_path("The source", &self.source)?;
        check_path("The new image", &self.output)?;
        let ext = Path::new(&self.output)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase());
        let fits = match self.kind.format() {
            DiskFormat::Raw => matches!(ext.as_deref(), Some("raw" | "img")),
            _ => ext.as_deref() == Some(self.kind.extension()),
        };
        if !fits {
            return invalid(format!(
                "A {} image is named .{}.",
                self.kind.label(),
                self.kind.extension()
            ));
        }
        let key = |p: &str| crate::adapters::vmware::path_key(Path::new(p));
        if self
            .kind
            .files(Path::new(&self.output))
            .iter()
            .any(|f| key(&f.display().to_string()) == key(&self.source))
        {
            return invalid("A conversion writes a new image; it never writes over its source.");
        }
        Ok(())
    }
}

/// VM-17, CV-02: where an exported VM goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ExportTarget {
    /// An OVA (one file) or OVF (a descriptor, a manifest and the disks), OVF 1.0 or 2.0.
    Appliance { ova: bool, version: OvfVersion },
    /// VMDK for ESXi: stream-optimized (compressed; `vmkfstools -i` it on the host) or preallocated in ESXi's own
    /// layout (`vmfs`, a descriptor and its `-flat.vmdk`, for a datastore).
    Esxi { thick: bool },
    /// VHDX (dynamic) for Hyper-V.
    HyperV,
    /// A fixed VHD for Azure, its size a whole number of megabytes.
    Azure,
    /// qcow2 with a libvirt domain XML for KVM.
    Kvm,
    /// A disk with a script that makes the VM on Proxmox VE (`qm create`, `qm importdisk`, `qm set`).
    Proxmox,
    /// Raw disks, for clouds that take them.
    Raw,
}

impl ExportTarget {
    pub fn label(self) -> &'static str {
        match self {
            ExportTarget::Appliance { ova: true, .. } => "OVA",
            ExportTarget::Appliance { ova: false, .. } => "OVF",
            ExportTarget::Esxi { thick: false } => "VMDK for ESXi (stream-optimized)",
            ExportTarget::Esxi { thick: true } => "VMDK for ESXi (preallocated)",
            ExportTarget::HyperV => "VHDX for Hyper-V",
            ExportTarget::Azure => "fixed VHD for Azure",
            ExportTarget::Kvm => "qcow2 and libvirt XML for KVM",
            ExportTarget::Proxmox => "Proxmox VE import script",
            ExportTarget::Raw => "raw disks",
        }
    }

    /// The folder name's ending: `web01-hyperv`.
    pub fn suffix(self) -> &'static str {
        match self {
            ExportTarget::Appliance { ova: true, .. } => "ova",
            ExportTarget::Appliance { ova: false, .. } => "ovf",
            ExportTarget::Esxi { thick: false } => "esxi",
            ExportTarget::Esxi { thick: true } => "esxi-thick",
            ExportTarget::HyperV => "hyperv",
            ExportTarget::Azure => "azure",
            ExportTarget::Kvm => "kvm",
            ExportTarget::Proxmox => "proxmox",
            ExportTarget::Raw => "raw",
        }
    }

    /// What each disk becomes (`None`: the hypervisor's own export writes the whole VM). Proxmox takes qcow2 when
    /// qemu-img is here, else a growable VMDK (Proxmox's own qemu-img reads it).
    pub fn disk_kind(self, qemu_img: bool) -> Option<OutputKind> {
        Some(match self {
            ExportTarget::Appliance { .. } => return None,
            ExportTarget::Esxi { thick: false } => OutputKind::VmdkStream,
            ExportTarget::Esxi { thick: true } => OutputKind::VmdkEsx,
            ExportTarget::HyperV => OutputKind::VhdxDynamic,
            ExportTarget::Azure => OutputKind::VhdFixed,
            ExportTarget::Kvm => OutputKind::Qcow2,
            ExportTarget::Proxmox if qemu_img => OutputKind::Qcow2,
            ExportTarget::Proxmox => OutputKind::VmdkSparse,
            ExportTarget::Raw => OutputKind::Raw,
        })
    }
}

/// VM-17, CV-02: a powered-off VM exported as it is now (a snapshot chain flattened) into a new folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSpec {
    pub vm_key: String,
    pub vm_name: String,
    pub hypervisor: Hypervisor,
    pub target: ExportTarget,
    /// The folder the export's own folder goes in.
    pub folder: String,
    /// The export's own folder, which the job makes (it must not be there): `<vm>-<target>`.
    pub name: String,
    /// What each disk becomes, decided when it was asked (`None` for an appliance).
    pub disk_kind: Option<OutputKind>,
}

/// A folder name Windows takes and the export can make.
pub fn check_folder_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name.chars().count() > 100
        || name.trim() != name
        || name.ends_with('.')
        || name == "."
        || name == ".."
        || name.chars().any(|c| c.is_control() || r#"\/:*?"<>|"#.contains(c))
        || untrusted::is_device_name(name);
    if bad {
        return invalid(format!("'{name}' can't be a folder's name."));
    }
    Ok(())
}

impl ExportSpec {
    pub fn targets(&self) -> Vec<TargetRef> {
        vec![TargetRef::Vm {
            vmx_path: self.vm_key.clone(),
        }]
    }

    /// `<folder>\<name>`.
    pub fn out_folder(&self) -> std::path::PathBuf {
        Path::new(&self.folder).join(&self.name)
    }

    pub fn summary(&self) -> String {
        format!("Export {} as {}", self.vm_name, self.target.label())
    }

    pub fn describe(&self) -> String {
        let mut text = format!(
            "{} ({}) into {}",
            self.vm_name,
            self.target.label(),
            self.out_folder().display()
        );
        if let ExportTarget::Appliance { version, .. } = self.target {
            text.push_str(match version {
                OvfVersion::V1 => ", OVF 1.0",
                OvfVersion::V2 => ", OVF 2.0",
            });
        }
        if let Some(kind) = self.disk_kind {
            text.push_str(&format!(", disks as {}", kind.label()));
        }
        text
    }

    pub fn validate(&self) -> Result<()> {
        check_path("The export folder", &self.folder)?;
        check_folder_name(&self.name)?;
        if self.out_folder().display().to_string().chars().count() > MAX_PATH_CHARS - 40 {
            return invalid("The export folder's path is too long.");
        }
        if Hypervisor::of_key(&self.vm_key) != self.hypervisor {
            return invalid("The VM's key doesn't name its hypervisor.");
        }
        let ovf2 = matches!(
            self.target,
            ExportTarget::Appliance {
                version: OvfVersion::V2,
                ..
            }
        );
        if ovf2 && self.hypervisor == Hypervisor::Vmware {
            return invalid("Workstation's ovftool writes OVF 1.0 only.");
        }
        match (self.target.disk_kind(true), self.disk_kind) {
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => return invalid("The export's disk format doesn't fit its target."),
            (Some(want), Some(kind)) => {
                let fits = kind == want || (self.target == ExportTarget::Proxmox && kind == OutputKind::VmdkSparse);
                if !fits {
                    return invalid("The export's disk format doesn't fit its target.");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert() -> ConvertSpec {
        ConvertSpec {
            source: r"C:\Images\rocky.qcow2".into(),
            source_format: DiskFormat::Qcow2,
            output: r"C:\Images\rocky.vmdk".into(),
            kind: OutputKind::VmdkSparse,
            whole_megabytes: false,
        }
    }

    #[test]
    fn a_conversion_names_a_new_file_of_its_kind() {
        let ok = convert();
        ok.validate().unwrap();
        assert_eq!(
            ok.summary(),
            "Convert rocky.qcow2 to rocky.vmdk (VMDK, growable (monolithicSparse))"
        );
        assert_eq!(
            ok.targets(),
            [TargetRef::DiskImage {
                path: r"C:\Images\rocky.vmdk".into()
            }]
        );
        let bad = |change: &dyn Fn(&mut ConvertSpec), why: &str| {
            let mut s = convert();
            change(&mut s);
            let err = s.validate().unwrap_err().to_string();
            assert!(err.contains(why), "{why}: {err}");
        };
        bad(&|s| s.output = "rocky.vmdk".into(), "full path");
        bad(
            &|s| s.output = r"\\fileserver.example.com\out\rocky.vmdk".into(),
            "network share",
        );
        bad(&|s| s.source = r"\\?\C:\Images\rocky.qcow2".into(), "device path");
        bad(&|s| s.output = r"C:\Images\rocky.vhd".into(), "is named .vmdk");
        bad(
            &|s| {
                s.source = r"C:\Images\web.vmdk".into();
                s.output = r"C:\IMAGES\WEB.vmdk".into();
            },
            "never writes over its source",
        );
        // A flat VMDK's extent can't be the source either.
        bad(
            &|s| {
                s.source = r"C:\Images\web-flat.vmdk".into();
                s.output = r"C:\Images\web.vmdk".into();
                s.kind = OutputKind::VmdkFlat;
            },
            "never writes over its source",
        );
        let mut raw = convert();
        raw.output = r"C:\Images\rocky.img".into();
        raw.kind = OutputKind::Raw;
        raw.validate().unwrap();
        let text = serde_json::to_string(&ok).unwrap();
        assert_eq!(serde_json::from_str::<ConvertSpec>(&text).unwrap(), ok);
    }

    fn export(target: ExportTarget, disk_kind: Option<OutputKind>) -> ExportSpec {
        ExportSpec {
            vm_key: r"C:\VMs\web01\web01.vmx".into(),
            vm_name: "web01".into(),
            hypervisor: Hypervisor::Vmware,
            target,
            folder: r"C:\Exports".into(),
            name: format!("web01-{}", target.suffix()),
            disk_kind,
        }
    }

    #[test]
    fn an_export_fits_its_target_and_its_hypervisor() {
        let kvm = export(ExportTarget::Kvm, Some(OutputKind::Qcow2));
        kvm.validate().unwrap();
        assert_eq!(kvm.out_folder(), Path::new(r"C:\Exports\web01-kvm"));
        assert_eq!(kvm.summary(), "Export web01 as qcow2 and libvirt XML for KVM");
        assert_eq!(kvm.targets()[0].key(), r"C:\VMs\web01\web01.vmx");
        export(ExportTarget::Proxmox, Some(OutputKind::VmdkSparse))
            .validate()
            .unwrap();
        export(ExportTarget::Proxmox, Some(OutputKind::Qcow2))
            .validate()
            .unwrap();
        let ova1 = ExportTarget::Appliance {
            ova: true,
            version: OvfVersion::V1,
        };
        export(ova1, None).validate().unwrap();
        let ova2 = ExportTarget::Appliance {
            ova: true,
            version: OvfVersion::V2,
        };
        let err = export(ova2, None).validate().unwrap_err().to_string();
        assert!(err.contains("OVF 1.0 only"), "{err}");
        let mut vbox = export(ova2, None);
        vbox.vm_key = "11111111-2222-4333-8444-555555555555".into();
        vbox.hypervisor = Hypervisor::VirtualBox;
        vbox.validate().unwrap();
        assert!(export(ExportTarget::Kvm, Some(OutputKind::Raw)).validate().is_err());
        assert!(export(ExportTarget::Kvm, None).validate().is_err());
        let mut bad = export(ExportTarget::Raw, Some(OutputKind::Raw));
        bad.name = "web01:raw".into();
        assert!(bad.validate().unwrap_err().to_string().contains("folder's name"));
        bad.name = "NUL".into();
        assert!(bad.validate().is_err());
        assert_eq!(ExportTarget::Azure.disk_kind(false), Some(OutputKind::VhdFixed));
        assert_eq!(ExportTarget::Proxmox.disk_kind(false), Some(OutputKind::VmdkSparse));
        assert_eq!(ExportTarget::Proxmox.disk_kind(true), Some(OutputKind::Qcow2));
    }
}
