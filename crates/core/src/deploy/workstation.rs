//! VM-21, VM-10: the command lines a Workstation deploy runs, as pure functions tested without Workstation.
//!
//! * Clones: `vmrun -T ws clone <vmx> <new vmx> full|linked [-snapshot=<path>] [-cloneName=<name>]`; a snapshot's
//!   path is vmrun's (`base/child` for a snapshot whose name another snapshot shares).
//! * Cloud images: `vmware-vdiskmanager -r <image> -t 0|2 <new disk>` copies the image (never changing it) into a
//!   growable (`0`) or preallocated (`2`) disk Workstation boots; a raw image is read through a VMDK descriptor
//!   Remotely writes beside the new disk ([`raw_descriptor`]) and deletes after.
//! * OVA/OVF: `ovftool --name=<name> --diskMode=<mode> <source> <new vmx>`.
//! * After a clone or an import, the size's CPU and memory and cloud-init's `guestinfo` keys go into the new
//!   `.vmx` ([`vmx_settings`]).

use std::ffi::OsString;
use std::path::Path;

use super::spec::{DeploySpec, SizeSpec};
use crate::catalog::sizes::Provisioning;
use crate::catalog::templates::Network;

/// `vmrun clone`'s arguments (after `-T ws`).
pub fn clone_args(source: &Path, target: &Path, linked: bool, snapshot: Option<&str>, name: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "clone".into(),
        source.into(),
        target.into(),
        if linked { "linked" } else { "full" }.into(),
    ];
    if let Some(snapshot) = snapshot {
        args.push(format!("-snapshot={snapshot}").into());
    }
    args.push(format!("-cloneName={name}").into());
    args
}

/// vdiskmanager's `-t`: 0 a growable single file (thin), 2 a preallocated single file (thick).
pub fn disk_type(provisioning: Provisioning) -> &'static str {
    match provisioning {
        Provisioning::Thin => "0",
        Provisioning::Thick => "2",
    }
}

/// `vmware-vdiskmanager -r <source> -t <type> <target>`: a copy of the source disk in the type Workstation boots.
pub fn convert_args(source: &Path, target: &Path, provisioning: Provisioning) -> Vec<OsString> {
    vec![
        "-r".into(),
        source.into(),
        "-t".into(),
        disk_type(provisioning).into(),
        target.into(),
    ]
}

/// A VMDK descriptor that reads a raw image as a flat extent, so vdiskmanager can copy it into a VMDK. `bytes` is
/// the raw file's size (whole 512-byte sectors).
pub fn raw_descriptor(raw: &Path, bytes: u64) -> String {
    let sectors = bytes / 512;
    // The geometry Workstation writes for a disk of this size: 255 heads, 63 sectors a track.
    let cylinders = (sectors / (255 * 63)).clamp(1, 65535);
    let raw = raw.display().to_string().replace('"', "");
    format!(
        "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\n\n\
         RW {sectors} FLAT \"{raw}\" 0\n\n\
         ddb.adapterType = \"lsilogic\"\nddb.geometry.cylinders = \"{cylinders}\"\nddb.geometry.heads = \"255\"\n\
         ddb.geometry.sectors = \"63\"\nddb.virtualHWVersion = \"20\"\n"
    )
}

/// ovftool's disk mode for the boot disk's provisioning.
pub fn ovftool_disk_mode(provisioning: Provisioning) -> &'static str {
    match provisioning {
        Provisioning::Thin => "monolithicSparse",
        Provisioning::Thick => "monolithicFlat",
    }
}

/// `ovftool --name=<name> --diskMode=<mode> <source> <new vmx>`. ovftool never asks: a licence the appliance
/// wants accepted makes it fail, and the job says so.
pub fn ovftool_args(source: &Path, target_vmx: &Path, name: &str, provisioning: Provisioning) -> Vec<OsString> {
    vec![
        format!("--name={name}").into(),
        format!("--diskMode={}", ovftool_disk_mode(provisioning)).into(),
        "--noSSLVerify".into(),
        source.into(),
        target_vmx.into(),
    ]
}

/// The new VM's `.vmx` and disk names: `<folder>\<name>\<name>.vmx`, `<name>.vmdk`, `<name>-1.vmdk`...
pub fn vmx_path(spec: &DeploySpec, name: &str) -> std::path::PathBuf {
    Path::new(&spec.folder).join(name).join(format!("{name}.vmx"))
}

pub fn disk_file_name(name: &str, index: usize) -> String {
    if index == 0 {
        format!("{name}.vmdk")
    } else {
        format!("{name}-{index}.vmdk")
    }
}

/// What a clone's or an import's `.vmx` gets: its name, the size's CPU and memory, the network when the deploy
/// sets one, and cloud-init's `guestinfo` keys.
pub fn vmx_settings(
    name: &str,
    size: Option<&SizeSpec>,
    network: Option<&Network>,
    guestinfo: &[(&'static str, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![("displayName".into(), name.to_owned())];
    if let Some(size) = size {
        out.push(("numvcpus".into(), size.vcpus().to_string()));
        out.push(("cpuid.coresPerSocket".into(), size.cores_per_socket.max(1).to_string()));
        out.push(("memsize".into(), size.memory_mb.to_string()));
    }
    if let Some((kind, vnet)) = network.and_then(super::vmx::connection) {
        out.push(("ethernet0.connectionType".into(), kind.to_owned()));
        if let Some(vnet) = vnet {
            out.push(("ethernet0.vnet".into(), vnet));
        }
    }
    for (key, value) in guestinfo {
        out.push(((*key).to_owned(), value.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter().map(|a| a.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn clone_arguments_name_the_snapshot_and_the_clone() {
        let args = clone_args(
            Path::new(r"C:\VMs\golden\golden.vmx"),
            Path::new(r"C:\VMs\lab\web-1\web-1.vmx"),
            true,
            Some("base/after updates"),
            "web-1",
        );
        assert_eq!(
            strings(&args),
            [
                "clone",
                r"C:\VMs\golden\golden.vmx",
                r"C:\VMs\lab\web-1\web-1.vmx",
                "linked",
                "-snapshot=base/after updates",
                "-cloneName=web-1"
            ]
        );
        let full = clone_args(Path::new("a.vmx"), Path::new("b.vmx"), false, None, "b");
        assert_eq!(strings(&full), ["clone", "a.vmx", "b.vmx", "full", "-cloneName=b"]);
    }

    #[test]
    fn a_cloud_image_is_copied_into_a_disk_workstation_boots() {
        assert_eq!(
            strings(&convert_args(
                Path::new(r"C:\Images\noble.vmdk"),
                Path::new(r"C:\VMs\web-1\web-1.vmdk"),
                Provisioning::Thin
            )),
            ["-r", r"C:\Images\noble.vmdk", "-t", "0", r"C:\VMs\web-1\web-1.vmdk"]
        );
        assert_eq!(disk_type(Provisioning::Thick), "2");
        let descriptor = raw_descriptor(Path::new(r"C:\Images\noble.img"), 3 * 1024 * 1024 * 1024);
        assert!(
            descriptor.contains("RW 6291456 FLAT \"C:\\Images\\noble.img\" 0"),
            "{descriptor}"
        );
        assert!(descriptor.contains("createType=\"monolithicFlat\""));
        assert!(descriptor.contains("ddb.geometry.cylinders = \"391\""), "{descriptor}");
    }

    #[test]
    fn ovftool_imports_into_the_new_vmx() {
        assert_eq!(
            strings(&ovftool_args(
                Path::new(r"C:\Images\app.ova"),
                Path::new(r"C:\VMs\app-1\app-1.vmx"),
                "app-1",
                Provisioning::Thin
            )),
            [
                "--name=app-1",
                "--diskMode=monolithicSparse",
                "--noSSLVerify",
                r"C:\Images\app.ova",
                r"C:\VMs\app-1\app-1.vmx"
            ]
        );
        assert_eq!(ovftool_disk_mode(Provisioning::Thick), "monolithicFlat");
        assert_eq!(disk_file_name("web-1", 0), "web-1.vmdk");
        assert_eq!(disk_file_name("web-1", 2), "web-1-2.vmdk");
    }

    #[test]
    fn a_clone_gets_the_size_network_and_guestinfo() {
        let size = SizeSpec {
            id: "gp.medium".into(),
            name: "gp.medium".into(),
            sockets: 1,
            cores_per_socket: 2,
            memory_mb: 4096,
            disks: Vec::new(),
        };
        let settings = vmx_settings(
            "web-1",
            Some(&size),
            Some(&Network::Vmnet { number: 3 }),
            &[("guestinfo.metadata.encoding", "base64".into())],
        );
        let get = |key: &str| settings.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        assert_eq!(get("displayName"), Some("web-1"));
        assert_eq!(get("numvcpus"), Some("2"));
        assert_eq!(get("cpuid.coresPerSocket"), Some("2"));
        assert_eq!(get("memsize"), Some("4096"));
        assert_eq!(get("ethernet0.connectionType"), Some("custom"));
        assert_eq!(get("ethernet0.vnet"), Some("VMnet3"));
        assert_eq!(get("guestinfo.metadata.encoding"), Some("base64"));
        // A bulk clone keeps its own size and network.
        assert_eq!(
            vmx_settings("c", None, None, &[]),
            [("displayName".to_owned(), "c".to_owned())]
        );
    }
}
