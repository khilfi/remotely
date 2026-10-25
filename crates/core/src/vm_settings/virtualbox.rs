//! VM-23, VM-11, VM-15, VM-16, VM-24 on VirtualBox: each edit as the VBoxManage calls that make it, from what
//! `showvminfo` said about the VM (pure functions, tested without VirtualBox). [`super::VmEditor`] runs them in
//! order through [`crate::adapters::virtualbox::VirtualBoxAdapter::change`].
//!
//! Calls used (VirtualBox 7): `modifyvm <uuid> --cpus --memory --nested-hw-virt --firmware --tpm-type --name
//! --ostype --nicN --nictypeN --macaddressN --cableconnectedN --bridgeadapterN --hostonlyadapterN
//! --nat-networkN --intnetN`; `modifynvram <uuid> inituefivarstore | enrollmssignatures | enrollorclpk |
//! secureboot --enable|--disable`; `sharedfolder add|remove`; `storagectl`; `storageattach`; `createmedium`;
//! `modifymedium --resize|--compact`; `closemedium --delete`; `controlvm <uuid> setlinkstateN on|off`;
//! `unregistervm --delete`; `registervm`. Never `guestcontrol`, which puts guest credentials on a command line.

use std::path::{Path, PathBuf};

use super::ops::{check_mac, size_mb, Firmware, MacAddress, NicNetwork, VmConfigEdit};
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::virtualbox::{VboxController, VboxVmInfo};
use crate::error::{CoreError, Result};

/// One VBoxManage call's arguments.
pub type Call = Vec<String>;

fn refused(message: impl Into<String>) -> CoreError {
    CoreError::VmSettingRefused(message.into())
}

fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

fn args(parts: &[&str]) -> Call {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

/// `nic2` → 2.
fn nic_number(slot: &str) -> Result<u32> {
    slot.strip_prefix("nic")
        .and_then(|n| n.parse::<u32>().ok())
        .filter(|n| (1..=8).contains(n))
        .ok_or_else(|| refused(format!("'{slot}' is not a VirtualBox network adapter.")))
}

fn nic_in_use(info: &VboxVmInfo, n: u32) -> bool {
    info.nics.iter().any(|nic| nic.slot == n && nic.enabled())
}

/// The `--nicN` attachment and the option that names its network, if it has one.
fn attachment(network: &NicNetwork, n: u32) -> Result<(String, Option<(String, String)>)> {
    Ok(match network {
        NicNetwork::Nat => ("nat".to_owned(), None),
        NicNetwork::Bridged { adapter } => (
            "bridged".to_owned(),
            adapter.clone().map(|a| (format!("--bridgeadapter{n}"), a)),
        ),
        NicNetwork::HostOnly { adapter } => (
            "hostonly".to_owned(),
            adapter.clone().map(|a| (format!("--hostonlyadapter{n}"), a)),
        ),
        NicNetwork::NatNetwork { name } => (
            "natnetwork".to_owned(),
            Some((format!("--nat-network{n}"), name.clone())),
        ),
        NicNetwork::Internal { name } => ("intnet".to_owned(), Some((format!("--intnet{n}"), name.clone()))),
        NicNetwork::Custom { .. } => {
            return Err(refused(
                "VirtualBox has no VMnet networks: use a host-only adapter, a NAT network or an internal network.",
            ))
        }
    })
}

/// VM-23, VM-12, VM-11: a settings edit as VBoxManage calls, and what changes, one line each.
pub fn config_calls(uuid: &str, info: &VboxVmInfo, edit: &VmConfigEdit) -> Result<(Vec<Call>, Vec<String>)> {
    let mut calls: Vec<Call> = Vec::new();
    let mut changes: Vec<String> = Vec::new();
    let mut modify = args(&["modifyvm", uuid]);
    let opt = |modify: &mut Call, name: &str, value: &str| {
        modify.push(name.to_owned());
        modify.push(value.to_owned());
    };
    match edit {
        VmConfigEdit::Resources {
            vcpus,
            cores_per_socket,
            memory_mb,
            nested_virtualization,
        } => {
            if cores_per_socket.is_some() {
                return Err(refused(
                    "VirtualBox gives a VM vCPUs, not sockets and cores: leave the cores per socket out.",
                ));
            }
            if let Some(n) = vcpus {
                opt(&mut modify, "--cpus", &n.to_string());
                changes.push(format!(
                    "vCPUs: {} → {n}",
                    info.cpus.map_or_else(|| "not set".to_owned(), |c| c.to_string())
                ));
            }
            if let Some(mb) = memory_mb {
                opt(&mut modify, "--memory", &mb.to_string());
                changes.push(format!(
                    "Memory: {} → {}",
                    info.memory_mb
                        .map_or_else(|| "not set".to_owned(), |m| size_mb(m.into())),
                    size_mb((*mb).into())
                ));
            }
            if let Some(on) = nested_virtualization {
                opt(&mut modify, "--nested-hw-virt", on_off(*on));
                changes.push(format!(
                    "Nested virtualization: {} → {}",
                    on_off(info.nested_hw_virt.unwrap_or(false)),
                    on_off(*on)
                ));
            }
        }
        VmConfigEdit::Firmware {
            firmware,
            secure_boot,
            tpm,
        } => {
            let was_efi = info
                .firmware
                .as_deref()
                .is_some_and(|f| f.to_ascii_uppercase().starts_with("EFI"));
            opt(
                &mut modify,
                "--firmware",
                match firmware {
                    Firmware::Bios => "bios",
                    Firmware::Efi => "efi",
                },
            );
            changes.push(format!(
                "Firmware: {} → {}",
                if was_efi { "UEFI" } else { "BIOS" },
                firmware.label()
            ));
            if let Some(on) = tpm {
                opt(&mut modify, "--tpm-type", if *on { "2.0" } else { "none" });
                changes.push(format!("TPM: {}", if *on { "TPM 2.0" } else { "none" }));
            }
            calls.push(std::mem::take(&mut modify));
            let secure_now = info.secure_boot.unwrap_or(false);
            if *firmware == Firmware::Efi && *secure_boot && !secure_now {
                // A VM made with BIOS has no UEFI variable store yet; one made with UEFI keeps the one it has.
                if info.secure_boot.is_none() {
                    calls.push(args(&["modifynvram", uuid, "inituefivarstore"]));
                    calls.push(args(&["modifynvram", uuid, "enrollmssignatures"]));
                    calls.push(args(&["modifynvram", uuid, "enrollorclpk"]));
                }
                calls.push(args(&["modifynvram", uuid, "secureboot", "--enable"]));
                changes.push("Secure Boot: off → on".to_owned());
            } else if secure_now && (!*secure_boot || *firmware == Firmware::Bios) && was_efi {
                // Before the firmware changes: modifynvram needs the UEFI variable store.
                calls.insert(0, args(&["modifynvram", uuid, "secureboot", "--disable"]));
                changes.push("Secure Boot: on → off".to_owned());
            }
            return Ok((calls, changes));
        }
        VmConfigEdit::Rename { name } => {
            opt(&mut modify, "--name", name);
            changes.push(format!("Name: {} → {name}", info.name));
        }
        VmConfigEdit::GuestOs { os_type } => {
            opt(&mut modify, "--ostype", os_type);
            changes.push(format!(
                "Guest OS type: {} → {os_type}",
                info.os_type.as_deref().unwrap_or("not set")
            ));
        }
        VmConfigEdit::AddNic { network, model } => {
            let n = (1..=8u32)
                .find(|n| !nic_in_use(info, *n))
                .ok_or_else(|| refused("The VM has 8 network adapters, VirtualBox's most."))?;
            let (kind, named) = attachment(network, n)?;
            opt(&mut modify, &format!("--nic{n}"), &kind);
            if let Some((option, name)) = named {
                opt(&mut modify, &option, &name);
            }
            if let Some(model) = model {
                opt(&mut modify, &format!("--nictype{n}"), model);
            }
            opt(&mut modify, &format!("--cableconnected{n}"), "on");
            changes.push(format!("New network adapter nic{n}: {}", network.describe()));
        }
        VmConfigEdit::EditNic {
            slot,
            network,
            model,
            mac,
            connect_at_power_on,
        } => {
            let n = nic_number(slot)?;
            if !nic_in_use(info, n) {
                return Err(refused(format!("The VM has no network adapter {slot}.")));
            }
            if let Some(network) = network {
                let (kind, named) = attachment(network, n)?;
                opt(&mut modify, &format!("--nic{n}"), &kind);
                if let Some((option, name)) = named {
                    opt(&mut modify, &option, &name);
                }
                changes.push(format!("{slot} network: → {}", network.describe()));
            }
            if let Some(model) = model {
                opt(&mut modify, &format!("--nictype{n}"), model);
                changes.push(format!("{slot} card: → {model}"));
            }
            match mac {
                Some(MacAddress::Static { mac }) => {
                    let mac = check_mac(mac, Hypervisor::VirtualBox)?;
                    let hex: String = mac.chars().filter(char::is_ascii_hexdigit).collect();
                    opt(&mut modify, &format!("--macaddress{n}"), &hex.to_ascii_uppercase());
                    changes.push(format!("{slot} MAC: → {mac}"));
                }
                Some(MacAddress::Generated) => {
                    opt(&mut modify, &format!("--macaddress{n}"), "auto");
                    changes.push(format!("{slot} MAC: a new one, made by VirtualBox"));
                }
                None => {}
            }
            if let Some(on) = connect_at_power_on {
                opt(&mut modify, &format!("--cableconnected{n}"), on_off(*on));
                changes.push(format!(
                    "{slot} cable: {}",
                    if *on { "connected" } else { "disconnected" }
                ));
            }
        }
        VmConfigEdit::RemoveNic { slot } => {
            let n = nic_number(slot)?;
            if !nic_in_use(info, n) {
                return Err(refused(format!("The VM has no network adapter {slot}.")));
            }
            opt(&mut modify, &format!("--nic{n}"), "none");
            changes.push(format!("Network adapter {slot} removed"));
        }
        VmConfigEdit::AddSharedFolder {
            name,
            host_path,
            writable,
        } => {
            if info.shared_folders.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                return Err(refused(format!("The VM already shares a folder as '{name}'.")));
            }
            let mut add = args(&["sharedfolder", "add", uuid, "--name", name, "--hostpath", host_path]);
            if !*writable {
                add.push("--readonly".to_owned());
            }
            add.push("--automount".to_owned());
            let how = if *writable { "read and write" } else { "read only" };
            changes.push(format!("Shares {host_path} as '{name}' ({how})"));
            return Ok((vec![add], changes));
        }
        VmConfigEdit::RemoveSharedFolder { name } => {
            let (found, _) = info
                .shared_folders
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .ok_or_else(|| refused(format!("The VM shares no folder as '{name}'.")))?;
            changes.push(format!("No longer shares '{found}'"));
            return Ok((vec![args(&["sharedfolder", "remove", uuid, "--name", found])], changes));
        }
        VmConfigEdit::UpgradeHardware => {
            return Err(refused("VirtualBox VMs have no hardware version to upgrade."));
        }
    }
    calls.push(modify);
    Ok((calls, changes))
}

/// A `SATA-1-0` slot as (controller, port, device).
pub fn split_slot(slot: &str) -> Option<(&str, u32, u32)> {
    let mut parts = slot.rsplitn(3, '-');
    let device = parts.next()?.parse().ok()?;
    let port = parts.next()?.parse().ok()?;
    let controller = parts.next()?;
    Some((controller, port, device))
}

fn attach_call(uuid: &str, slot: &str, kind: &str, medium: &str) -> Result<Call> {
    let (controller, port, device) =
        split_slot(slot).ok_or_else(|| refused(format!("'{slot}' is not a VirtualBox storage slot.")))?;
    Ok(args(&[
        "storageattach",
        uuid,
        "--storagectl",
        controller,
        "--port",
        &port.to_string(),
        "--device",
        &device.to_string(),
        "--type",
        kind,
        "--medium",
        medium,
    ]))
}

/// The DVD drive an ISO goes into: `slot`, or the VM's first.
pub fn dvd_slot(info: &VboxVmInfo, slot: Option<&str>) -> Option<String> {
    match slot {
        Some(slot) => info.dvds.iter().find(|d| d.slot == slot).map(|d| d.slot.clone()),
        None => info.dvds.first().map(|d| d.slot.clone()),
    }
}

/// Slots in use on a controller.
fn used_ports(info: &VboxVmInfo, controller: &str) -> Vec<u32> {
    info.disks
        .iter()
        .map(|d| d.slot.as_str())
        .chain(info.dvds.iter().map(|d| d.slot.as_str()))
        .filter_map(split_slot)
        .filter(|(c, _, _)| *c == controller)
        .map(|(_, port, _)| port)
        .collect()
}

/// IDE controllers have two ports with two devices each; the others one device per port.
fn is_ide(controller: &VboxController) -> bool {
    controller
        .kind
        .as_deref()
        .is_some_and(|k| matches!(k.to_ascii_uppercase().as_str(), "PIIX3" | "PIIX4" | "ICH6"))
}

/// Where a new device goes on a VM: a free port on `controller` (or the controller of its first disk, else
/// its first), adding a port to a SATA controller when all are used (VirtualBox's most is 30). Returns the
/// calls that make room, and the slot.
pub fn free_slot(uuid: &str, info: &VboxVmInfo, controller: Option<&str>) -> Result<(Vec<Call>, String)> {
    let first_disk = info
        .disks
        .first()
        .and_then(|d| split_slot(&d.slot))
        .map(|(c, _, _)| c.to_owned());
    let chosen = match controller.map(str::to_owned).or(first_disk) {
        Some(name) => info.controllers.iter().find(|c| c.name == name).cloned(),
        None => info.controllers.first().cloned(),
    };
    let Some(controller) = chosen else {
        // No controller at all: a SATA one, as VirtualBox's own wizard adds.
        let add = args(&[
            "storagectl",
            uuid,
            "--name",
            "SATA",
            "--add",
            "sata",
            "--controller",
            "IntelAhci",
            "--portcount",
            "2",
        ]);
        return Ok((vec![add], "SATA-0-0".to_owned()));
    };
    let used = used_ports(info, &controller.name);
    if is_ide(&controller) {
        for port in 0..2u32 {
            for device in 0..2u32 {
                let slot = format!("{}-{port}-{device}", controller.name);
                let taken = info.disks.iter().any(|d| d.slot == slot) || info.dvds.iter().any(|d| d.slot == slot);
                if !taken {
                    return Ok((Vec::new(), slot));
                }
            }
        }
        return Err(refused(format!("The IDE controller {} is full.", controller.name)));
    }
    let ports = controller.ports.unwrap_or(1);
    if let Some(port) = (0..ports).find(|p| !used.contains(p)) {
        return Ok((Vec::new(), format!("{}-{port}-0", controller.name)));
    }
    let sata = controller
        .kind
        .as_deref()
        .is_some_and(|k| k.eq_ignore_ascii_case("IntelAhci"));
    if sata && ports < 30 {
        let grow = args(&[
            "storagectl",
            uuid,
            "--name",
            &controller.name,
            "--portcount",
            &(ports + 1).to_string(),
        ]);
        return Ok((vec![grow], format!("{}-{ports}-0", controller.name)));
    }
    Err(refused(format!("The controller {} has no free port.", controller.name)))
}

/// VM-23: an ISO into a DVD drive (a new drive on a VM that is off and has none).
pub fn attach_iso_calls(
    uuid: &str,
    info: &VboxVmInfo,
    slot: Option<&str>,
    iso: &str,
    off: bool,
) -> Result<(Vec<Call>, Vec<String>)> {
    match dvd_slot(info, slot) {
        Some(slot) => {
            let old = info
                .dvds
                .iter()
                .find(|d| d.slot == slot)
                .and_then(|d| d.image.as_ref())
                .map_or_else(|| "empty".to_owned(), |p| p.display().to_string());
            Ok((
                vec![attach_call(uuid, &slot, "dvddrive", iso)?],
                vec![format!("CD/DVD {slot}: {old} → {iso}")],
            ))
        }
        None if slot.is_some() => Err(refused(format!(
            "The VM has no DVD drive {}.",
            slot.unwrap_or_default()
        ))),
        None if !off => Err(refused(
            "The VM has no DVD drive, and VirtualBox adds one only while the VM is off: shut it down first.",
        )),
        None => {
            let (mut calls, slot) = free_slot(uuid, info, None)?;
            calls.push(attach_call(uuid, &slot, "dvddrive", iso)?);
            Ok((calls, vec![format!("New DVD drive {slot} with {iso}")]))
        }
    }
}

pub fn eject_calls(uuid: &str, info: &VboxVmInfo, slot: Option<&str>) -> Result<(Vec<Call>, Vec<String>)> {
    let slot = dvd_slot(info, slot).ok_or_else(|| refused("The VM has no DVD drive."))?;
    Ok((
        vec![attach_call(uuid, &slot, "dvddrive", "emptydrive")?],
        vec![format!("CD/DVD {slot}: → empty")],
    ))
}

/// VM-11: a running VM's cable now (`controlvm setlinkstateN`), or a VM that is off at its next start.
pub fn link_calls(
    uuid: &str,
    info: &VboxVmInfo,
    slot: &str,
    on: bool,
    running: bool,
) -> Result<(Vec<Call>, Vec<String>)> {
    let n = nic_number(slot)?;
    if !nic_in_use(info, n) {
        return Err(refused(format!("The VM has no network adapter {slot}.")));
    }
    let call = if running {
        args(&["controlvm", uuid, &format!("setlinkstate{n}"), on_off(on)])
    } else {
        args(&["modifyvm", uuid, &format!("--cableconnected{n}"), on_off(on)])
    };
    let state = if on { "connected" } else { "disconnected" };
    Ok((vec![call], vec![format!("{slot} cable: {state}")]))
}

/// VM-16: a new VDI in the VM's folder, attached to a free port.
pub fn add_disk_calls(
    uuid: &str,
    info: &VboxVmInfo,
    file: &Path,
    size: u64,
    thin: bool,
    controller: Option<&str>,
) -> Result<(Vec<Call>, Vec<String>, String)> {
    let (mut calls, slot) = free_slot(uuid, info, controller)?;
    let path = file.display().to_string();
    let mut create = args(&[
        "createmedium",
        "disk",
        "--filename",
        &path,
        "--size",
        &size.to_string(),
        "--format",
        "VDI",
    ]);
    if !thin {
        create.push("--variant".to_owned());
        create.push("Fixed".to_owned());
    }
    calls.insert(0, create);
    calls.push(attach_call(uuid, &slot, "hdd", &path)?);
    let how = if thin { "thin" } else { "thick" };
    Ok((
        calls,
        vec![format!("New {} disk ({how}) {path} on {slot}", size_mb(size))],
        slot,
    ))
}

/// VM-16: the disk on `slot`, if the VM has one there.
pub fn disk_on(info: &VboxVmInfo, slot: &str) -> Result<PathBuf> {
    info.disks
        .iter()
        .find(|d| d.slot == slot)
        .map(|d| d.path.clone())
        .ok_or_else(|| refused(format!("The VM has no virtual disk on {slot}.")))
}

pub fn resize_call(path: &Path, size: u64) -> Call {
    args(&[
        "modifymedium",
        "disk",
        &path.display().to_string(),
        "--resize",
        &size.to_string(),
    ])
}

pub fn compact_call(path: &Path) -> Call {
    args(&["modifymedium", "disk", &path.display().to_string(), "--compact"])
}

/// VM-16: off the VM, then the file deleted.
pub fn remove_disk_calls(uuid: &str, slot: &str, path: &Path) -> Result<Vec<Call>> {
    Ok(vec![
        attach_call(uuid, slot, "hdd", "none")?,
        args(&["closemedium", "disk", &path.display().to_string(), "--delete"]),
    ])
}

/// VM-15: the Guest Additions ISO into the VM's first DVD drive.
pub fn guest_additions_calls(uuid: &str, info: &VboxVmInfo, iso: &Path) -> Result<Vec<Call>> {
    let slot = dvd_slot(info, None).ok_or_else(|| {
        refused("The VM has no DVD drive for the Guest Additions ISO: add one while the VM is off (attach an ISO).")
    })?;
    Ok(vec![attach_call(uuid, &slot, "dvddrive", &iso.display().to_string())?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::virtualbox::parse_showvminfo;

    const UUID: &str = "3f0c1a2b-1111-4222-8333-444455556666";

    /// What VirtualBox 7.2 printed for the hand check's it- VM (paths and MACs changed).
    fn info() -> VboxVmInfo {
        parse_showvminfo(
            r#"name="it-web"
ostype="Ubuntu (64-bit)"
UUID="3f0c1a2b-1111-4222-8333-444455556666"
memory=1024
firmware="EFI"
cpus=2
nested-hw-virt="on"
VMState="poweroff"
storagecontrollername0="SATA"
storagecontrollertype0="IntelAhci"
storagecontrollerportcount0="2"
"SATA-0-0"="C:\\VMs\\it-web\\disk1.vdi"
"SATA-ImageUUID-0-0"="a484220b-bbf1-4768-9502-d32e9a1eb6d2"
"SATA-1-0"="emptydrive"
"SATA-IsEjected-1-0"="off"
nic1="nat"
nictype1="virtio"
macaddress1="080027000001"
cableconnected1="on"
nic2="none"
SharedFolderNameMachineMapping1="hostshare"
SharedFolderPathMachineMapping1="C:\\Shared"
"#,
        )
    }

    #[test]
    fn resources_and_firmware_become_modifyvm_and_modifynvram() {
        let (calls, changes) = config_calls(
            UUID,
            &info(),
            &VmConfigEdit::Resources {
                vcpus: Some(4),
                cores_per_socket: None,
                memory_mb: Some(4096),
                nested_virtualization: Some(false),
            },
        )
        .unwrap();
        assert_eq!(
            calls,
            [args(&[
                "modifyvm",
                UUID,
                "--cpus",
                "4",
                "--memory",
                "4096",
                "--nested-hw-virt",
                "off"
            ])]
        );
        assert_eq!(
            changes,
            ["vCPUs: 2 → 4", "Memory: 1 GB → 4 GB", "Nested virtualization: on → off"]
        );

        // No UEFI variable store yet: one is made, with Microsoft's and Oracle's keys, before Secure Boot.
        let (calls, _) = config_calls(
            UUID,
            &info(),
            &VmConfigEdit::Firmware {
                firmware: Firmware::Efi,
                secure_boot: true,
                tpm: Some(true),
            },
        )
        .unwrap();
        assert_eq!(
            calls,
            [
                args(&["modifyvm", UUID, "--firmware", "efi", "--tpm-type", "2.0"]),
                args(&["modifynvram", UUID, "inituefivarstore"]),
                args(&["modifynvram", UUID, "enrollmssignatures"]),
                args(&["modifynvram", UUID, "enrollorclpk"]),
                args(&["modifynvram", UUID, "secureboot", "--enable"]),
            ]
        );
        let mut secure = info();
        secure.secure_boot = Some(true);
        let (calls, _) = config_calls(
            UUID,
            &secure,
            &VmConfigEdit::Firmware {
                firmware: Firmware::Bios,
                secure_boot: false,
                tpm: None,
            },
        )
        .unwrap();
        assert_eq!(
            calls[0],
            args(&["modifynvram", UUID, "secureboot", "--disable"]),
            "while the store is there"
        );
        assert_eq!(calls[1], args(&["modifyvm", UUID, "--firmware", "bios"]));
    }

    #[test]
    fn adapters_take_the_first_free_slot_and_name_their_network() {
        let add = VmConfigEdit::AddNic {
            network: NicNetwork::Internal { name: "lab".into() },
            model: Some("virtio".into()),
        };
        let (calls, changes) = config_calls(UUID, &info(), &add).unwrap();
        assert_eq!(
            calls,
            [args(&[
                "modifyvm",
                UUID,
                "--nic2",
                "intnet",
                "--intnet2",
                "lab",
                "--nictype2",
                "virtio",
                "--cableconnected2",
                "on"
            ])]
        );
        assert_eq!(changes, ["New network adapter nic2: internal network lab"]);
        let mac = VmConfigEdit::EditNic {
            slot: "nic1".into(),
            network: None,
            model: None,
            mac: Some(MacAddress::Static {
                mac: "08:00:27:aa:bb:cc".into(),
            }),
            connect_at_power_on: Some(false),
        };
        let (calls, _) = config_calls(UUID, &info(), &mac).unwrap();
        assert_eq!(
            calls,
            [args(&[
                "modifyvm",
                UUID,
                "--macaddress1",
                "080027AABBCC",
                "--cableconnected1",
                "off"
            ])]
        );
        assert!(config_calls(UUID, &info(), &VmConfigEdit::RemoveNic { slot: "nic2".into() }).is_err());
        let (calls, _) = config_calls(UUID, &info(), &VmConfigEdit::RemoveNic { slot: "nic1".into() }).unwrap();
        assert_eq!(calls, [args(&["modifyvm", UUID, "--nic1", "none"])]);
    }

    #[test]
    fn shared_folders_and_renames() {
        let add = VmConfigEdit::AddSharedFolder {
            name: "data".into(),
            host_path: r"C:\Data".into(),
            writable: false,
        };
        let (calls, _) = config_calls(UUID, &info(), &add).unwrap();
        assert_eq!(
            calls,
            [args(&[
                "sharedfolder",
                "add",
                UUID,
                "--name",
                "data",
                "--hostpath",
                r"C:\Data",
                "--readonly",
                "--automount"
            ])]
        );
        let twice = VmConfigEdit::AddSharedFolder {
            name: "HostShare".into(),
            host_path: r"C:\Data".into(),
            writable: true,
        };
        assert!(config_calls(UUID, &info(), &twice).is_err());
        let (calls, _) = config_calls(
            UUID,
            &info(),
            &VmConfigEdit::RemoveSharedFolder {
                name: "HOSTSHARE".into(),
            },
        )
        .unwrap();
        assert_eq!(calls, [args(&["sharedfolder", "remove", UUID, "--name", "hostshare"])]);
        let (calls, changes) = config_calls(
            UUID,
            &info(),
            &VmConfigEdit::Rename {
                name: "it-web02".into(),
            },
        )
        .unwrap();
        assert_eq!(calls, [args(&["modifyvm", UUID, "--name", "it-web02"])]);
        assert_eq!(changes, ["Name: it-web → it-web02"]);
    }

    #[test]
    fn isos_disks_and_cables() {
        let (calls, _) = attach_iso_calls(UUID, &info(), None, r"C:\ISOs\ubuntu.iso", false).unwrap();
        assert_eq!(
            calls,
            [args(&[
                "storageattach",
                UUID,
                "--storagectl",
                "SATA",
                "--port",
                "1",
                "--device",
                "0",
                "--type",
                "dvddrive",
                "--medium",
                r"C:\ISOs\ubuntu.iso"
            ])]
        );
        let (calls, _) = eject_calls(UUID, &info(), None).unwrap();
        assert_eq!(calls[0].last().map(String::as_str), Some("emptydrive"));
        let mut no_dvd = info();
        no_dvd.dvds.clear();
        assert!(
            attach_iso_calls(UUID, &no_dvd, None, r"C:\ISOs\x.iso", false).is_err(),
            "running: can't add a drive"
        );
        let (calls, changes) = attach_iso_calls(UUID, &no_dvd, None, r"C:\ISOs\x.iso", true).unwrap();
        assert_eq!(calls.len(), 1, "port 1 is free on the 2-port controller");
        assert_eq!(changes, [r"New DVD drive SATA-1-0 with C:\ISOs\x.iso"]);

        // Both ports used: a third is added.
        let (calls, _, slot) = add_disk_calls(
            UUID,
            &info(),
            Path::new(r"C:\VMs\it-web\it-web-disk2.vdi"),
            2048,
            false,
            None,
        )
        .unwrap();
        assert_eq!(slot, "SATA-2-0");
        assert_eq!(
            calls,
            [
                args(&[
                    "createmedium",
                    "disk",
                    "--filename",
                    r"C:\VMs\it-web\it-web-disk2.vdi",
                    "--size",
                    "2048",
                    "--format",
                    "VDI",
                    "--variant",
                    "Fixed"
                ]),
                args(&["storagectl", UUID, "--name", "SATA", "--portcount", "3"]),
                args(&[
                    "storageattach",
                    UUID,
                    "--storagectl",
                    "SATA",
                    "--port",
                    "2",
                    "--device",
                    "0",
                    "--type",
                    "hdd",
                    "--medium",
                    r"C:\VMs\it-web\it-web-disk2.vdi"
                ]),
            ]
        );
        assert_eq!(
            disk_on(&info(), "SATA-0-0").unwrap(),
            PathBuf::from(r"C:\VMs\it-web\disk1.vdi")
        );
        assert!(disk_on(&info(), "SATA-1-0").is_err(), "the DVD drive is no disk");
        let (calls, _) = link_calls(UUID, &info(), "nic1", false, true).unwrap();
        assert_eq!(calls, [args(&["controlvm", UUID, "setlinkstate1", "off"])]);
        let (calls, _) = link_calls(UUID, &info(), "nic1", true, false).unwrap();
        assert_eq!(calls, [args(&["modifyvm", UUID, "--cableconnected1", "on"])]);
        assert_eq!(split_slot("SATA Controller-0-1"), Some(("SATA Controller", 0, 1)));
    }
}
