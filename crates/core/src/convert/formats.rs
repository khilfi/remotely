//! CV-01 to CV-03: the disk image formats Remotely reads and writes, and the kinds of image a conversion makes.
//!
//! * [`DiskFormat`]: what a file is (VMDK, VDI, VHD, VHDX, qcow2, raw), told by its bytes, never by its name alone.
//! * [`OutputKind`]: what a conversion writes: the format and how it is laid out (a growable or preallocated disk,
//!   VMware's stream-optimized and ESXi layouts), which decides which tools can write it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A disk image's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskFormat {
    Vmdk,
    Vdi,
    /// Microsoft's VHD (Virtual PC): fixed, dynamic or differencing.
    Vhd,
    /// Hyper-V's VHDX.
    Vhdx,
    /// QEMU's qcow2 (KVM, Proxmox, OpenStack).
    Qcow2,
    /// The disk's bytes as they are: `.raw`, `.img`.
    Raw,
}

impl DiskFormat {
    pub const ALL: [DiskFormat; 6] = [
        DiskFormat::Vmdk,
        DiskFormat::Vdi,
        DiskFormat::Vhd,
        DiskFormat::Vhdx,
        DiskFormat::Qcow2,
        DiskFormat::Raw,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DiskFormat::Vmdk => "vmdk",
            DiskFormat::Vdi => "vdi",
            DiskFormat::Vhd => "vhd",
            DiskFormat::Vhdx => "vhdx",
            DiskFormat::Qcow2 => "qcow2",
            DiskFormat::Raw => "raw",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DiskFormat::Vmdk => "VMDK",
            DiskFormat::Vdi => "VDI",
            DiskFormat::Vhd => "VHD",
            DiskFormat::Vhdx => "VHDX",
            DiskFormat::Qcow2 => "qcow2",
            DiskFormat::Raw => "raw",
        }
    }

    /// qemu-img's name for it (`-f` and `-O`): VHD is `vpc`.
    pub fn qemu_name(self) -> &'static str {
        match self {
            DiskFormat::Vhd => "vpc",
            other => other.as_str(),
        }
    }

    /// The format a file's extension suggests. `.img` is raw or qcow2, which only its bytes tell; the caller
    /// checks them ([`super::inspect`]).
    pub fn from_extension(path: &Path) -> Option<DiskFormat> {
        let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
        Some(match ext.as_str() {
            "vmdk" => DiskFormat::Vmdk,
            "vdi" => DiskFormat::Vdi,
            "vhd" => DiskFormat::Vhd,
            "vhdx" => DiskFormat::Vhdx,
            "qcow2" => DiskFormat::Qcow2,
            "raw" | "img" | "dd" | "bin" => DiskFormat::Raw,
            _ => return None,
        })
    }
}

/// What a conversion writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OutputKind {
    /// VMDK, one growable file (`monolithicSparse`): Workstation's own.
    VmdkSparse,
    /// VMDK, preallocated: a descriptor and its `-flat.vmdk` (`monolithicFlat`).
    VmdkFlat,
    /// VMDK, compressed and stream-optimized (`streamOptimized`): what OVAs carry and ESXi imports.
    VmdkStream,
    /// VMDK, preallocated in ESXi's own layout (`vmfs`): a descriptor and its `-flat.vmdk` for a datastore.
    VmdkEsx,
    VdiDynamic,
    VdiFixed,
    VhdDynamic,
    /// VHD, preallocated: what Azure takes.
    VhdFixed,
    VhdxDynamic,
    VhdxFixed,
    /// qcow2, growing as the guest writes.
    Qcow2,
    /// qcow2, preallocated.
    Qcow2Thick,
    /// The disk's bytes, the whole size.
    Raw,
}

impl OutputKind {
    pub const ALL: [OutputKind; 13] = [
        OutputKind::VmdkSparse,
        OutputKind::VmdkFlat,
        OutputKind::VmdkStream,
        OutputKind::VmdkEsx,
        OutputKind::VdiDynamic,
        OutputKind::VdiFixed,
        OutputKind::VhdDynamic,
        OutputKind::VhdFixed,
        OutputKind::VhdxDynamic,
        OutputKind::VhdxFixed,
        OutputKind::Qcow2,
        OutputKind::Qcow2Thick,
        OutputKind::Raw,
    ];

    pub fn format(self) -> DiskFormat {
        match self {
            OutputKind::VmdkSparse | OutputKind::VmdkFlat | OutputKind::VmdkStream | OutputKind::VmdkEsx => {
                DiskFormat::Vmdk
            }
            OutputKind::VdiDynamic | OutputKind::VdiFixed => DiskFormat::Vdi,
            OutputKind::VhdDynamic | OutputKind::VhdFixed => DiskFormat::Vhd,
            OutputKind::VhdxDynamic | OutputKind::VhdxFixed => DiskFormat::Vhdx,
            OutputKind::Qcow2 | OutputKind::Qcow2Thick => DiskFormat::Qcow2,
            OutputKind::Raw => DiskFormat::Raw,
        }
    }

    /// Takes only what the guest wrote (thin), or its whole size at once (thick).
    pub fn thin(self) -> bool {
        matches!(
            self,
            OutputKind::VmdkSparse
                | OutputKind::VmdkStream
                | OutputKind::VdiDynamic
                | OutputKind::VhdDynamic
                | OutputKind::VhdxDynamic
                | OutputKind::Qcow2
        )
    }

    /// The thin or thick kind of a format, as a deploy's disk asks for.
    pub fn of(format: DiskFormat, thin: bool) -> OutputKind {
        match (format, thin) {
            (DiskFormat::Vmdk, true) => OutputKind::VmdkSparse,
            (DiskFormat::Vmdk, false) => OutputKind::VmdkFlat,
            (DiskFormat::Vdi, true) => OutputKind::VdiDynamic,
            (DiskFormat::Vdi, false) => OutputKind::VdiFixed,
            (DiskFormat::Vhd, true) => OutputKind::VhdDynamic,
            (DiskFormat::Vhd, false) => OutputKind::VhdFixed,
            (DiskFormat::Vhdx, true) => OutputKind::VhdxDynamic,
            (DiskFormat::Vhdx, false) => OutputKind::VhdxFixed,
            (DiskFormat::Qcow2, true) => OutputKind::Qcow2,
            (DiskFormat::Qcow2, false) => OutputKind::Qcow2Thick,
            (DiskFormat::Raw, _) => OutputKind::Raw,
        }
    }

    pub fn extension(self) -> &'static str {
        match self.format() {
            DiskFormat::Raw => "raw",
            other => other.as_str(),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            OutputKind::VmdkSparse => "VMDK, growable (monolithicSparse)",
            OutputKind::VmdkFlat => "VMDK, preallocated (monolithicFlat)",
            OutputKind::VmdkStream => "VMDK, stream-optimized (for OVAs and ESXi)",
            OutputKind::VmdkEsx => "VMDK, preallocated for an ESXi datastore (vmfs)",
            OutputKind::VdiDynamic => "VDI, dynamic",
            OutputKind::VdiFixed => "VDI, fixed",
            OutputKind::VhdDynamic => "VHD, dynamic",
            OutputKind::VhdFixed => "VHD, fixed",
            OutputKind::VhdxDynamic => "VHDX, dynamic",
            OutputKind::VhdxFixed => "VHDX, fixed",
            OutputKind::Qcow2 => "qcow2",
            OutputKind::Qcow2Thick => "qcow2, preallocated",
            OutputKind::Raw => "raw",
        }
    }

    /// The files it makes at `path`: a flat VMDK's descriptor and its `-flat.vmdk` extent; one file otherwise.
    pub fn files(self, path: &Path) -> Vec<PathBuf> {
        match self {
            OutputKind::VmdkFlat | OutputKind::VmdkEsx => vec![path.to_path_buf(), flat_extent(path)],
            _ => vec![path.to_path_buf()],
        }
    }
}

/// `<name>-flat.vmdk` beside `<name>.vmdk`: the extent vdiskmanager, VBoxManage and qemu-img write for a flat VMDK.
pub fn flat_extent(path: &Path) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!("{stem}-flat.vmdk"))
}

/// "1.2 GB" (powers of 1024, as hypervisors size disks), for notes and READMEs.
pub fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} bytes"),
        _ if (value - value.round()).abs() < 0.05 => format!("{:.0} {}", value.round(), UNITS[unit]),
        _ => format!("{value:.1} {}", UNITS[unit]),
    }
}

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_output_kind_has_its_format_extension_and_files() {
        for kind in OutputKind::ALL {
            assert_eq!(OutputKind::of(kind.format(), kind.thin()).format(), kind.format());
            assert!(!kind.label().is_empty());
        }
        assert_eq!(OutputKind::VhdFixed.extension(), "vhd");
        assert_eq!(OutputKind::Raw.extension(), "raw");
        assert!(!OutputKind::VhdFixed.thin());
        assert!(OutputKind::VmdkStream.thin());
        assert_eq!(
            OutputKind::VmdkEsx.files(Path::new(r"C:\Out\web.vmdk")),
            [PathBuf::from(r"C:\Out\web.vmdk"), PathBuf::from(r"C:\Out\web-flat.vmdk")]
        );
        assert_eq!(OutputKind::Qcow2.files(Path::new("a.qcow2")).len(), 1);
        assert_eq!(DiskFormat::Vhd.qemu_name(), "vpc");
        assert_eq!(
            DiskFormat::from_extension(Path::new("noble.IMG")),
            Some(DiskFormat::Raw)
        );
        assert_eq!(DiskFormat::from_extension(Path::new("a.ova")), None);
    }

    #[test]
    fn sizes_read_as_hypervisors_size_disks() {
        assert_eq!(size_text(512), "512 bytes");
        assert_eq!(size_text(20 * GIB), "20 GB");
        assert_eq!(size_text(1536 * MIB), "1.5 GB");
        assert_eq!(size_text(64 * MIB), "64 MB");
    }
}
