//! CV-01 to CV-03, VM-17: the command lines the conversion tools get, as pure functions tested without them.
//!
//! * qemu-img always gets the input's format (`-f`, and `-F` for `compare`): it never probes a file, so a raw
//!   disk that happens to start like a qcow2 header is never read as one.
//! * vmware-vdiskmanager: `-r <source> -t <type> <target>`; types 0 (growable), 2 (preallocated), 4 (ESXi's
//!   preallocated `vmfs`), 5 (stream-optimized).
//! * VBoxManage: `clonemedium disk <source> <target> --format --variant`, `convertfromraw <source> <target>`,
//!   `modifymedium disk <file> --resize <MB>`, `closemedium disk <file>` (unregisters; the file stays), `export`.
//! * ovftool: `--shaAlgorithm=SHA256 <vmx> <target.ova|.ovf>`.

use std::ffi::OsString;
use std::path::Path;

use super::formats::{DiskFormat, OutputKind};

/// `qemu-img convert -p -f <in> -O <out> [-o <options>] <source> <target>`.
pub fn qemu_convert(source: &Path, from: DiskFormat, target: &Path, out: OutputKind) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "convert".into(),
        "-p".into(),
        "-f".into(),
        from.qemu_name().into(),
        "-O".into(),
        out.format().qemu_name().into(),
    ];
    let options = match out {
        OutputKind::VmdkSparse => Some("subformat=monolithicSparse"),
        OutputKind::VmdkFlat => Some("subformat=monolithicFlat"),
        OutputKind::VmdkStream => Some("subformat=streamOptimized"),
        OutputKind::VdiFixed => Some("static=on"),
        // force_size keeps the exact size instead of rounding it to a CHS geometry (Azure needs it).
        OutputKind::VhdDynamic => Some("subformat=dynamic,force_size=on"),
        OutputKind::VhdFixed => Some("subformat=fixed,force_size=on"),
        OutputKind::VhdxDynamic => Some("subformat=dynamic"),
        OutputKind::VhdxFixed => Some("subformat=fixed"),
        OutputKind::Qcow2Thick => Some("preallocation=full"),
        OutputKind::VmdkEsx | OutputKind::VdiDynamic | OutputKind::Qcow2 | OutputKind::Raw => None,
    };
    if let Some(options) = options {
        args.push("-o".into());
        args.push(options.into());
    }
    args.push(source.into());
    args.push(target.into());
    args
}

/// `qemu-img compare -p -f <a> -F <b> <a> <b>`: the guest-visible contents (exit 0: identical, 1: they differ).
pub fn qemu_compare(a: &Path, a_format: DiskFormat, b: &Path, b_format: DiskFormat) -> Vec<OsString> {
    vec![
        "compare".into(),
        "-p".into(),
        "-f".into(),
        a_format.qemu_name().into(),
        "-F".into(),
        b_format.qemu_name().into(),
        a.into(),
        b.into(),
    ]
}

/// `qemu-img resize -f <format> <file> <bytes>`: grows a qcow2 (never shrinks: Remotely only asks for more).
pub fn qemu_resize(path: &Path, format: DiskFormat, bytes: u64) -> Vec<OsString> {
    vec![
        "resize".into(),
        "-f".into(),
        format.qemu_name().into(),
        path.into(),
        bytes.to_string().into(),
    ]
}

/// vdiskmanager's `-t` for an output kind (raw: the `-flat.vmdk` of a preallocated disk).
pub fn vdisk_type(out: OutputKind) -> Option<&'static str> {
    Some(match out {
        OutputKind::VmdkSparse => "0",
        OutputKind::VmdkFlat | OutputKind::Raw => "2",
        OutputKind::VmdkEsx => "4",
        OutputKind::VmdkStream => "5",
        _ => return None,
    })
}

/// `vmware-vdiskmanager -r <source> -t <type> <target>`.
pub fn vdisk_convert(source: &Path, target: &Path, out: OutputKind) -> Option<Vec<OsString>> {
    Some(vec![
        "-r".into(),
        source.into(),
        "-t".into(),
        vdisk_type(out)?.into(),
        target.into(),
    ])
}

/// VBoxManage's `--format` and `--variant` for an output kind.
pub fn vbox_format(out: OutputKind) -> Option<(&'static str, Option<&'static str>)> {
    Some(match out {
        OutputKind::VdiDynamic => ("VDI", Some("Standard")),
        OutputKind::VdiFixed => ("VDI", Some("Fixed")),
        OutputKind::VhdDynamic => ("VHD", Some("Standard")),
        OutputKind::VhdFixed => ("VHD", Some("Fixed")),
        OutputKind::VmdkSparse => ("VMDK", Some("Standard")),
        OutputKind::VmdkFlat => ("VMDK", Some("Fixed")),
        OutputKind::VmdkStream => ("VMDK", Some("Stream")),
        OutputKind::Raw => ("RAW", None),
        _ => return None,
    })
}

fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

/// `VBoxManage clonemedium disk <source> <target> --format <F> [--variant <V>]`, or `convertfromraw` for a raw
/// source. Arguments are strings: VirtualBoxAdapter's calls are.
pub fn vbox_convert(source: &Path, from: DiskFormat, target: &Path, out: OutputKind) -> Option<Vec<String>> {
    let (format, variant) = vbox_format(out)?;
    let mut args = if from == DiskFormat::Raw {
        vec!["convertfromraw".to_owned(), path_arg(source), path_arg(target)]
    } else {
        vec![
            "clonemedium".to_owned(),
            "disk".to_owned(),
            path_arg(source),
            path_arg(target),
        ]
    };
    args.push("--format".into());
    args.push(format.into());
    if let Some(variant) = variant {
        args.push("--variant".into());
        args.push(variant.into());
    }
    Some(args)
}

/// `VBoxManage modifymedium disk <file> --resize <MB>`.
pub fn vbox_resize(path: &Path, bytes: u64) -> Vec<String> {
    vec![
        "modifymedium".into(),
        "disk".into(),
        path_arg(path),
        "--resize".into(),
        bytes.div_ceil(1 << 20).to_string(),
    ]
}

/// `VBoxManage closemedium disk <file>`: VirtualBox forgets a medium `clonemedium` registered (the file stays).
pub fn vbox_close(path: &Path) -> Vec<String> {
    vec!["closemedium".into(), "disk".into(), path_arg(path)]
}

pub fn vbox_list_hdds() -> Vec<String> {
    vec!["list".into(), "hdds".into()]
}

/// The media `VBoxManage list hdds` names: each `Location:`.
pub fn parse_hdd_locations(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("Location:"))
        .map(|rest| rest.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// OVF's version for an appliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OvfVersion {
    V1,
    V2,
}

/// `VBoxManage export <uuid> --output <file> --ovf10|--ovf20 --manifest`: the VM as it is now (its snapshots'
/// differencing images merged).
pub fn vbox_export(uuid: &str, target: &Path, version: OvfVersion) -> Vec<String> {
    vec![
        "export".into(),
        uuid.into(),
        "--output".into(),
        path_arg(target),
        match version {
            OvfVersion::V1 => "--ovf10",
            OvfVersion::V2 => "--ovf20",
        }
        .into(),
        "--manifest".into(),
    ]
}

/// `ovftool --shaAlgorithm=SHA256 --noImageFiles <vmx> <target>`: OVF 1.0 (ovftool has no 2.0). An ISO the VM has
/// attached stays out of the package.
pub fn ovftool_export(vmx: &Path, target: &Path) -> Vec<OsString> {
    vec![
        "--shaAlgorithm=SHA256".into(),
        "--noImageFiles".into(),
        vmx.into(),
        target.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter().map(|a| a.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn qemu_img_always_gets_the_input_format() {
        let args = qemu_convert(
            Path::new(r"C:\In\rocky.qcow2"),
            DiskFormat::Qcow2,
            Path::new(r"C:\Out\rocky.vhd"),
            OutputKind::VhdFixed,
        );
        assert_eq!(
            strings(&args),
            [
                "convert",
                "-p",
                "-f",
                "qcow2",
                "-O",
                "vpc",
                "-o",
                "subformat=fixed,force_size=on",
                r"C:\In\rocky.qcow2",
                r"C:\Out\rocky.vhd"
            ]
        );
        for out in OutputKind::ALL {
            for from in DiskFormat::ALL {
                let args = strings(&qemu_convert(Path::new("a"), from, Path::new("b"), out));
                assert_eq!(args[2], "-f", "{from:?} to {out:?}");
                assert_eq!(args[3], from.qemu_name());
            }
        }
        assert_eq!(
            strings(&qemu_compare(Path::new("a.vmdk"), DiskFormat::Vmdk, Path::new("b.vhd"), DiskFormat::Vhd)),
            ["compare", "-p", "-f", "vmdk", "-F", "vpc", "a.vmdk", "b.vhd"]
        );
        assert_eq!(
            strings(&qemu_resize(Path::new("t.qcow2"), DiskFormat::Qcow2, 1 << 30)),
            ["resize", "-f", "qcow2", "t.qcow2", "1073741824"]
        );
    }

    #[test]
    fn vdiskmanager_and_vboxmanage_get_their_types() {
        assert_eq!(
            strings(
                &vdisk_convert(Path::new("a.vmdk"), Path::new("e.vmdk"), OutputKind::VmdkEsx).unwrap()
            ),
            ["-r", "a.vmdk", "-t", "4", "e.vmdk"]
        );
        assert_eq!(vdisk_type(OutputKind::VmdkStream), Some("5"));
        assert_eq!(vdisk_type(OutputKind::Qcow2), None);
        assert_eq!(
            vbox_convert(Path::new("a.vhd"), DiskFormat::Vhd, Path::new("b.vdi"), OutputKind::VdiFixed).unwrap(),
            ["clonemedium", "disk", "a.vhd", "b.vdi", "--format", "VDI", "--variant", "Fixed"]
        );
        assert_eq!(
            vbox_convert(Path::new("d.img"), DiskFormat::Raw, Path::new("d.vmdk"), OutputKind::VmdkStream).unwrap(),
            ["convertfromraw", "d.img", "d.vmdk", "--format", "VMDK", "--variant", "Stream"]
        );
        assert_eq!(
            vbox_convert(Path::new("a.vdi"), DiskFormat::Vdi, Path::new("a.raw"), OutputKind::Raw).unwrap(),
            ["clonemedium", "disk", "a.vdi", "a.raw", "--format", "RAW"]
        );
        assert_eq!(vbox_resize(Path::new("t.vdi"), (1 << 30) + 1)[4], "1025");
        assert_eq!(vbox_close(Path::new("t.vdi")), ["closemedium", "disk", "t.vdi"]);
        let listed = "UUID:           25ba7a0f-4c5c-9445-b550-d1231443ea02\nParent UUID:    base\nLocation:       C:\\Images\\a.vhd\n\nUUID:  x\nLocation: C:\\VMs\\b.vdi\n";
        assert_eq!(parse_hdd_locations(listed), [r"C:\Images\a.vhd", r"C:\VMs\b.vdi"]);
    }

    #[test]
    fn appliances_are_exported_by_the_vms_hypervisor() {
        assert_eq!(
            vbox_export("0d8b2c9e-4a8f-4c55-9f0e-5c1b2a3d4e5f", Path::new(r"C:\Out\web.ova"), OvfVersion::V2),
            [
                "export",
                "0d8b2c9e-4a8f-4c55-9f0e-5c1b2a3d4e5f",
                "--output",
                r"C:\Out\web.ova",
                "--ovf20",
                "--manifest"
            ]
        );
        assert_eq!(
            strings(&ovftool_export(Path::new(r"C:\VMs\web\web.vmx"), Path::new(r"C:\Out\web.ova"))),
            ["--shaAlgorithm=SHA256", "--noImageFiles", r"C:\VMs\web\web.vmx", r"C:\Out\web.ova"]
        );
    }
}
