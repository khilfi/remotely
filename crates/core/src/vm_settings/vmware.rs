//! VM-23, VM-11, VM-16, VM-24 on Workstation: each edit as changes to the `.vmx` (pure functions on a
//! [`VmxFile`], tested without a VM), and the slots, file names and vdiskmanager arguments a disk change needs.
//! [`super::VmEditor`] reads the file, applies these, and writes it back after a backup.
//!
//! Keys used (Workstation 17 to 26): `numvcpus`, `cpuid.coresPerSocket`, `memsize`, `vhv.enable`, `firmware`,
//! `uefi.secureBoot.enabled`, `displayName`, `guestOS`; `ethernetN.present`, `.connectionType` (`nat`,
//! `bridged`, `hostonly`, `custom` with `.vnet`), `.virtualDev`, `.addressType` (`generated` or `static` with
//! `.address`), `.startConnected`; `sharedFolderN.present`, `.enabled`, `.readAccess`, `.writeAccess`,
//! `.hostPath`, `.guestName`, `.expiration`, `sharedFolder.maxNum`, `isolation.tools.hgfs.disable`; a CD/DVD
//! drive's `<slot>.deviceType = "cdrom-image"`, `.fileName`, `.startConnected`; a disk's `<slot>.present`,
//! `.fileName`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::ops::{check_mac, size_mb, Firmware, MacAddress, NicNetwork, VmConfigEdit};
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vm_hardware::slot_bus;
use crate::adapters::vmx_file::VmxFile;
use crate::error::{CoreError, Result};

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

/// `old -> new` for the preview, with "not set" for a key that was missing.
fn change(what: &str, old: Option<&str>, new: &str) -> String {
    format!("{what}: {} → {new}", old.unwrap_or("not set"))
}

/// The adapters' numbers (`ethernetN.present = "TRUE"`), in order.
pub fn nic_numbers(file: &VmxFile) -> Vec<u32> {
    let mut found: Vec<u32> = file
        .pairs()
        .filter_map(|(key, value)| {
            let n = key.strip_prefix("ethernet")?.strip_suffix(".present")?.parse().ok()?;
            value.eq_ignore_ascii_case("true").then_some(n)
        })
        .collect();
    found.sort_unstable();
    found
}

fn nic_exists(file: &VmxFile, slot: &str) -> Result<()> {
    if file.is_true(&format!("{slot}.present")) {
        Ok(())
    } else {
        Err(refused(format!("The VM has no network adapter {slot}.")))
    }
}

/// Workstation's `connectionType` for a network, and its vnet for a custom one.
fn connection_of(network: &NicNetwork) -> Result<(&'static str, Option<String>)> {
    match network {
        NicNetwork::Nat => Ok(("nat", None)),
        NicNetwork::Bridged { .. } => Ok(("bridged", None)),
        NicNetwork::HostOnly { .. } => Ok(("hostonly", None)),
        NicNetwork::Custom { vnet } => {
            let n = vnet.trim_start_matches(|c: char| c.is_ascii_alphabetic());
            Ok(("custom", Some(format!("VMnet{n}"))))
        }
        NicNetwork::NatNetwork { .. } | NicNetwork::Internal { .. } => Err(refused(
            "NAT networks and internal networks are VirtualBox's: on Workstation use NAT, host-only or a VMnet.",
        )),
    }
}

fn set_network(file: &mut VmxFile, slot: &str, network: &NicNetwork, changes: &mut Vec<String>) -> Result<()> {
    let (kind, vnet) = connection_of(network)?;
    let key = format!("{slot}.connectionType");
    let old = file.get(&key).map(str::to_owned);
    file.set(&key, kind)?;
    match vnet {
        Some(vnet) => file.set(&format!("{slot}.vnet"), &vnet)?,
        None => {
            file.remove(&format!("{slot}.vnet"));
        }
    }
    changes.push(format!(
        "{slot} network: {} → {}",
        old.as_deref().unwrap_or("bridged"),
        network.describe()
    ));
    Ok(())
}

/// Where shared folder `name` is (`sharedFolderN`), if the VM shares one by that name.
fn shared_folder_number(file: &VmxFile, name: &str) -> Option<u32> {
    file.pairs().find_map(|(key, value)| {
        let n = key.strip_prefix("sharedfolder")?.strip_suffix(".guestname")?;
        (value.eq_ignore_ascii_case(name) && file.is_true(&format!("sharedFolder{n}.present")))
            .then(|| n.parse().ok())
            .flatten()
    })
}

/// VM-23, VM-12, VM-11: applies a settings edit to the .vmx. Returns what changed, one line each. Fails
/// (and the file is not written) when the VM doesn't have what the edit names.
pub fn apply_config(file: &mut VmxFile, edit: &VmConfigEdit) -> Result<Vec<String>> {
    let mut changes = Vec::new();
    match edit {
        VmConfigEdit::Resources {
            vcpus,
            cores_per_socket,
            memory_mb,
            nested_virtualization,
        } => {
            if let Some(n) = vcpus {
                let old = file.get("numvcpus").unwrap_or("1").to_owned();
                file.set("numvcpus", &n.to_string())?;
                changes.push(change("vCPUs", Some(&old), &n.to_string()));
            }
            let current_cores: Option<u32> = file.get("cpuid.coresPerSocket").and_then(|c| c.parse().ok());
            let vcpus_now: u32 = file.get("numvcpus").and_then(|n| n.parse().ok()).unwrap_or(1);
            let cores = match cores_per_socket {
                Some(cores) => Some(*cores),
                // The old layout no longer fits the new count: one core per socket always does.
                None if current_cores.is_some_and(|c| c > 1 && !vcpus_now.is_multiple_of(c)) => Some(1),
                None => None,
            };
            if let Some(cores) = cores {
                if cores == 0 || !vcpus_now.is_multiple_of(cores) {
                    return Err(refused(format!(
                        "{cores} cores per socket don't divide {vcpus_now} vCPUs."
                    )));
                }
                let old = current_cores.map(|c| c.to_string());
                file.set("cpuid.coresPerSocket", &cores.to_string())?;
                changes.push(change(
                    "Cores per socket",
                    old.as_deref().or(Some("1")),
                    &cores.to_string(),
                ));
            }
            if let Some(mb) = memory_mb {
                let old = file.get("memsize").and_then(|m| m.parse::<u64>().ok()).map(size_mb);
                file.set("memsize", &mb.to_string())?;
                changes.push(change("Memory", old.as_deref(), &size_mb((*mb).into())));
            }
            if let Some(on) = nested_virtualization {
                let old = on_off(file.is_true("vhv.enable"));
                file.set_bool("vhv.enable", *on)?;
                changes.push(change("Nested virtualization", Some(old), on_off(*on)));
            }
        }
        VmConfigEdit::Firmware {
            firmware,
            secure_boot,
            tpm,
        } => {
            if tpm.is_some_and(|on| on) {
                return Err(refused(
                    "Workstation's virtual TPM needs the VM encrypted with a password of its own, which Remotely doesn't do: add it in Workstation.",
                ));
            }
            let was_efi = file.get("firmware").is_some_and(|f| f.eq_ignore_ascii_case("efi"));
            let was = if was_efi { "UEFI" } else { "BIOS" };
            match firmware {
                Firmware::Efi => file.set("firmware", "efi")?,
                Firmware::Bios => {
                    file.remove("firmware");
                }
            }
            changes.push(change("Firmware", Some(was), firmware.label()));
            let secure_was = was_efi && file.is_true("uefi.secureBoot.enabled");
            if *firmware == Firmware::Efi {
                file.set_bool("uefi.secureBoot.enabled", *secure_boot)?;
            } else {
                file.remove("uefi.secureBoot.enabled");
            }
            let secure_now = *firmware == Firmware::Efi && *secure_boot;
            if secure_was != secure_now {
                changes.push(change("Secure Boot", Some(on_off(secure_was)), on_off(secure_now)));
            }
        }
        VmConfigEdit::Rename { name } => {
            let old = file.get("displayName").map(str::to_owned);
            file.set("displayName", name)?;
            changes.push(change("Name", old.as_deref(), name));
        }
        VmConfigEdit::GuestOs { os_type } => {
            let old = file.get("guestOS").map(str::to_owned);
            file.set("guestOS", os_type)?;
            changes.push(change("Guest OS type", old.as_deref(), os_type));
        }
        VmConfigEdit::AddNic { network, model } => {
            let used = nic_numbers(file);
            let n = (0..10u32)
                .find(|n| !used.contains(n))
                .ok_or_else(|| refused("The VM has 10 network adapters, Workstation's most."))?;
            let slot = format!("ethernet{n}");
            // A removed adapter's keys may linger (Workstation leaves some); they would mix with the new one.
            file.remove_prefix(&format!("{slot}."));
            let model = model.clone().unwrap_or_else(|| {
                used.first()
                    .and_then(|first| file.get(&format!("ethernet{first}.virtualDev")))
                    .unwrap_or("e1000e")
                    .to_owned()
            });
            file.set_bool(&format!("{slot}.present"), true)?;
            let (kind, vnet) = connection_of(network)?;
            file.set(&format!("{slot}.connectionType"), kind)?;
            if let Some(vnet) = vnet {
                file.set(&format!("{slot}.vnet"), &vnet)?;
            }
            file.set(&format!("{slot}.virtualDev"), &model)?;
            file.set(&format!("{slot}.addressType"), "generated")?;
            file.set_bool(&format!("{slot}.startConnected"), true)?;
            changes.push(format!("New network adapter {slot}: {}, {model}", network.describe()));
        }
        VmConfigEdit::EditNic {
            slot,
            network,
            model,
            mac,
            connect_at_power_on,
        } => {
            nic_exists(file, slot)?;
            if let Some(network) = network {
                set_network(file, slot, network, &mut changes)?;
            }
            if let Some(model) = model {
                let key = format!("{slot}.virtualDev");
                let old = file.get(&key).map(str::to_owned);
                file.set(&key, model)?;
                changes.push(change(&format!("{slot} card"), old.as_deref(), model));
            }
            match mac {
                Some(MacAddress::Static { mac }) => {
                    let mac = check_mac(mac, Hypervisor::Vmware)?;
                    let old = file
                        .get(&format!("{slot}.generatedAddress"))
                        .or_else(|| file.get(&format!("{slot}.address")))
                        .map(str::to_owned);
                    file.set(&format!("{slot}.addressType"), "static")?;
                    file.set(&format!("{slot}.address"), &mac)?;
                    file.remove(&format!("{slot}.generatedAddress"));
                    file.remove(&format!("{slot}.generatedAddressOffset"));
                    changes.push(change(&format!("{slot} MAC"), old.as_deref(), &mac));
                }
                Some(MacAddress::Generated) => {
                    file.set(&format!("{slot}.addressType"), "generated")?;
                    file.remove(&format!("{slot}.address"));
                    // Workstation makes a new one at the next start.
                    file.remove(&format!("{slot}.generatedAddress"));
                    file.remove(&format!("{slot}.generatedAddressOffset"));
                    changes.push(format!("{slot} MAC: a new one, made by Workstation at the next start"));
                }
                None => {}
            }
            if let Some(on) = connect_at_power_on {
                let key = format!("{slot}.startConnected");
                let old = file.get(&key).map(|v| on_off(v.eq_ignore_ascii_case("true")));
                file.set_bool(&key, *on)?;
                changes.push(change(
                    &format!("{slot} connected at power-on"),
                    old.or(Some("on")),
                    on_off(*on),
                ));
            }
        }
        VmConfigEdit::RemoveNic { slot } => {
            nic_exists(file, slot)?;
            file.remove_prefix(&format!("{slot}."));
            changes.push(format!("Network adapter {slot} removed"));
        }
        VmConfigEdit::AddSharedFolder {
            name,
            host_path,
            writable,
        } => {
            if shared_folder_number(file, name).is_some() {
                return Err(refused(format!("The VM already shares a folder as '{name}'.")));
            }
            let used: Vec<u32> = file
                .pairs()
                .filter_map(|(key, _)| key.strip_prefix("sharedfolder")?.split_once('.')?.0.parse().ok())
                .collect();
            let n = (0..).find(|n| !used.contains(n)).unwrap_or(0);
            let prefix = format!("sharedFolder{n}");
            file.set_bool("isolation.tools.hgfs.disable", false)?;
            file.set_bool(&format!("{prefix}.present"), true)?;
            file.set_bool(&format!("{prefix}.enabled"), true)?;
            file.set_bool(&format!("{prefix}.readAccess"), true)?;
            file.set_bool(&format!("{prefix}.writeAccess"), *writable)?;
            file.set(&format!("{prefix}.hostPath"), host_path)?;
            file.set(&format!("{prefix}.guestName"), name)?;
            file.set(&format!("{prefix}.expiration"), "never")?;
            let max: u32 = file
                .get("sharedFolder.maxNum")
                .and_then(|m| m.parse().ok())
                .unwrap_or(0);
            file.set("sharedFolder.maxNum", &max.max(n + 1).to_string())?;
            let how = if *writable { "read and write" } else { "read only" };
            changes.push(format!("Shares {host_path} as '{name}' ({how})"));
        }
        VmConfigEdit::RemoveSharedFolder { name } => {
            let n = shared_folder_number(file, name)
                .ok_or_else(|| refused(format!("The VM shares no folder as '{name}'.")))?;
            file.remove_prefix(&format!("sharedFolder{n}."));
            changes.push(format!("No longer shares '{name}'"));
        }
        VmConfigEdit::UpgradeHardware => {
            return Err(refused("A hardware upgrade is vmrun's to do, not an edit of the .vmx."));
        }
    }
    Ok(changes)
}

/// A device slot's bus and unit: `sata0:1` is (`sata0`, 1).
fn split_slot(slot: &str) -> Option<(&str, u32)> {
    let (bus, unit) = slot.split_once(':')?;
    Some((bus, unit.parse().ok()?))
}

/// Units a bus takes: SCSI 0 to 15 without 7 (the controller's own), SATA 0 to 29, NVMe 0 to 14, IDE 0 and 1.
fn bus_units(bus: &str) -> Vec<u32> {
    let family: String = bus.chars().take_while(char::is_ascii_alphabetic).collect();
    match family.as_str() {
        "scsi" => (0..16).filter(|u| *u != 7).collect(),
        "sata" => (0..30).collect(),
        "nvme" => (0..15).collect(),
        "ide" => (0..2).collect(),
        _ => Vec::new(),
    }
}

fn slot_used(file: &VmxFile, slot: &str) -> bool {
    file.is_true(&format!("{slot}.present"))
}

/// VM-23: the VM's CD/DVD drives, in slot order.
pub fn cdrom_slots(file: &VmxFile) -> Vec<String> {
    let mut slots: Vec<String> = file
        .pairs()
        .filter_map(|(key, value)| {
            let slot = key.strip_suffix(".devicetype")?;
            (value.to_ascii_lowercase().contains("cdrom") && slot.contains(':')).then(|| slot.to_owned())
        })
        .filter(|slot| {
            file.get(&format!("{slot}.present"))
                .is_none_or(|p| p.eq_ignore_ascii_case("true"))
        })
        .collect();
    slots.sort_by_key(|s| {
        let (bus, unit) = split_slot(s).unwrap_or(("", 0));
        (bus.to_owned(), unit)
    });
    slots.dedup();
    slots
}

/// The CD/DVD drive an ISO goes into: `slot`, or the VM's first.
pub fn cdrom_slot(file: &VmxFile, slot: Option<&str>) -> Option<String> {
    let drives = cdrom_slots(file);
    match slot {
        Some(slot) => drives.into_iter().find(|d| d.eq_ignore_ascii_case(slot)),
        None => drives.into_iter().next(),
    }
}

/// VM-23: where a new CD/DVD drive goes on a VM without one: a free SATA unit, else a free IDE one.
fn new_cdrom_slot(file: &VmxFile) -> Option<String> {
    if file.is_true("sata0.present") {
        if let Some(unit) = bus_units("sata0")
            .into_iter()
            .find(|u| !slot_used(file, &format!("sata0:{u}")))
        {
            return Some(format!("sata0:{unit}"));
        }
    }
    ["ide1:0", "ide0:1", "ide1:1", "ide0:0"]
        .into_iter()
        .find(|slot| !slot_used(file, slot))
        .map(str::to_owned)
}

/// VM-23: an ISO into a powered-off VM's CD/DVD drive (a new drive when it has none), connected at power-on.
pub fn attach_iso_off(file: &mut VmxFile, slot: Option<&str>, iso: &str) -> Result<Vec<String>> {
    let (slot, new) = match cdrom_slot(file, slot) {
        Some(found) => (found, false),
        None if slot.is_some() => {
            return Err(refused(format!(
                "The VM has no CD/DVD drive {}.",
                slot.unwrap_or_default()
            )))
        }
        None => (
            new_cdrom_slot(file).ok_or_else(|| refused("The VM has no free slot for a CD/DVD drive."))?,
            true,
        ),
    };
    let old = file
        .get(&format!("{slot}.fileName"))
        .filter(|f| !f.is_empty())
        .map(str::to_owned);
    file.set_bool(&format!("{slot}.present"), true)?;
    file.set(&format!("{slot}.deviceType"), "cdrom-image")?;
    file.set(&format!("{slot}.fileName"), iso)?;
    file.set_bool(&format!("{slot}.startConnected"), true)?;
    Ok(vec![if new {
        format!("New CD/DVD drive {slot} with {iso}")
    } else {
        change(&format!("CD/DVD {slot}"), old.as_deref().or(Some("empty")), iso)
    }])
}

/// VM-23: a powered-off VM's CD/DVD drive emptied and left unconnected at power-on.
pub fn eject_off(file: &mut VmxFile, slot: Option<&str>) -> Result<Vec<String>> {
    let slot = cdrom_slot(file, slot).ok_or_else(|| refused("The VM has no CD/DVD drive."))?;
    let old = file
        .get(&format!("{slot}.fileName"))
        .filter(|f| !f.is_empty())
        .map(str::to_owned);
    file.set_bool(&format!("{slot}.startConnected"), false)?;
    if file
        .get(&format!("{slot}.deviceType"))
        .is_some_and(|t| t.eq_ignore_ascii_case("cdrom-image"))
    {
        file.set(&format!("{slot}.fileName"), "")?;
    }
    Ok(vec![change(
        &format!("CD/DVD {slot}"),
        old.as_deref().or(Some("empty")),
        "empty",
    )])
}

/// VM-11: a powered-off VM's adapter plugged in (or not) when it powers on.
pub fn connect_nic_off(file: &mut VmxFile, slot: &str, on: bool) -> Result<Vec<String>> {
    nic_exists(file, slot)?;
    let key = format!("{slot}.startConnected");
    let old = file.get(&key).map(|v| on_off(v.eq_ignore_ascii_case("true")));
    file.set_bool(&key, on)?;
    Ok(vec![change(
        &format!("{slot} connected at power-on"),
        old.or(Some("on")),
        on_off(on),
    )])
}

/// VM-16: a disk's slot in the .vmx (`scsi0:1`), and its file as written there.
pub fn disk_file(file: &VmxFile, slot: &str) -> Result<String> {
    let name = file
        .get(&format!("{slot}.fileName"))
        .filter(|f| f.to_ascii_lowercase().ends_with(".vmdk"))
        .filter(|_| {
            file.get(&format!("{slot}.present"))
                .is_none_or(|p| p.eq_ignore_ascii_case("true"))
        })
        .filter(|_| {
            !file
                .get(&format!("{slot}.deviceType"))
                .is_some_and(|t| t.to_ascii_lowercase().contains("cdrom"))
        })
        .ok_or_else(|| refused(format!("The VM has no virtual disk on {slot}.")))?;
    Ok(name.to_owned())
}

/// A file named in a .vmx: relative names are in the VM's folder.
pub fn resolve(folder: &Path, name: &str) -> PathBuf {
    let path = Path::new(name);
    if path.is_absolute() || name.starts_with(['\\', '/']) || name.get(1..2) == Some(":") {
        path.to_path_buf()
    } else {
        folder.join(path)
    }
}

/// VM-16: the buses with disks on them, the boot disk's first.
fn disk_buses(file: &VmxFile) -> Vec<String> {
    let mut slots: Vec<(String, u32)> = file
        .pairs()
        .filter_map(|(key, value)| {
            let slot = key.strip_suffix(".filename")?;
            let (bus, unit) = split_slot(slot)?;
            value
                .to_ascii_lowercase()
                .ends_with(".vmdk")
                .then(|| (bus.to_owned(), unit))
        })
        .filter(|(bus, unit)| slot_used(file, &format!("{bus}:{unit}")))
        .collect();
    slots.sort();
    let mut buses: Vec<String> = Vec::new();
    for (bus, _) in slots {
        if !buses.contains(&bus) {
            buses.push(bus);
        }
    }
    buses
}

/// VM-16: a new disk's place: its slot, whether its controller must be added, and the `-a` adapter type
/// vdiskmanager takes (`ide`, `buslogic`; `lsilogic` for every other kind, which vdiskmanager's help says).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDisk {
    pub slot: String,
    pub add_controller: bool,
    pub adapter: &'static str,
    /// The file name, in the VM's folder.
    pub file_name: String,
}

/// VM-16: where a new disk goes: on `bus`, else on the boot disk's bus, else a new LSI Logic SAS controller
/// (`scsi0`, which every guest Workstation supports has a driver for); the first free unit; a file name that is
/// not taken (`taken` says which are, on disk or in the .vmx).
pub fn plan_new_disk(
    file: &VmxFile,
    vm_stem: &str,
    bus: Option<&str>,
    taken: &dyn Fn(&str) -> bool,
) -> Result<NewDisk> {
    let (bus, add_controller) = match bus {
        Some(bus) => {
            let present = file.is_true(&format!("{bus}.present")) || bus.starts_with("ide");
            (bus.to_ascii_lowercase(), !present)
        }
        None => match disk_buses(file).into_iter().next() {
            Some(bus) => (bus, false),
            None if file.is_true("scsi0.present") => ("scsi0".to_owned(), false),
            None if file.is_true("sata0.present") => ("sata0".to_owned(), false),
            None => ("scsi0".to_owned(), true),
        },
    };
    let unit = bus_units(&bus)
        .into_iter()
        .find(|u| !slot_used(file, &format!("{bus}:{u}")))
        .ok_or_else(|| refused(format!("{bus} has no free slot for another disk.")))?;
    let adapter = if bus.starts_with("ide") {
        "ide"
    } else if file
        .get(&format!("{bus}.virtualDev"))
        .is_some_and(|d| d.eq_ignore_ascii_case("buslogic"))
    {
        "buslogic"
    } else {
        "lsilogic"
    };
    let file_name = (1..1000)
        .map(|n| format!("{vm_stem}-{n}.vmdk"))
        .find(|name| !taken(name))
        .ok_or_else(|| refused("No free name for a new disk file in the VM's folder."))?;
    Ok(NewDisk {
        slot: format!("{bus}:{unit}"),
        add_controller,
        adapter,
        file_name,
    })
}

/// VM-16: the new disk in the .vmx.
pub fn attach_disk(file: &mut VmxFile, disk: &NewDisk) -> Result<Vec<String>> {
    let bus = slot_bus(&disk.slot).to_owned();
    if disk.add_controller && !bus.starts_with("ide") {
        file.set_bool(&format!("{bus}.present"), true)?;
        if bus.starts_with("scsi") {
            file.set(&format!("{bus}.virtualDev"), "lsisas1068")?;
        }
    }
    file.remove_prefix(&format!("{}.", disk.slot));
    file.set_bool(&format!("{}.present", disk.slot), true)?;
    file.set(&format!("{}.fileName", disk.slot), &disk.file_name)?;
    let mut changes = vec![format!("New disk {} on {}", disk.file_name, disk.slot)];
    if disk.add_controller {
        changes.push(format!("New controller {bus}"));
    }
    Ok(changes)
}

/// VM-16: a disk off the VM (its keys gone).
pub fn detach_disk(file: &mut VmxFile, slot: &str) -> Result<Vec<String>> {
    let name = disk_file(file, slot)?;
    file.remove_prefix(&format!("{slot}."));
    Ok(vec![format!("Disk {name} on {slot} removed")])
}

/// vdiskmanager's arguments: `-c -s <size>MB -a <adapter> -t <0 thin | 2 thick> <file>`.
pub fn create_args(path: &Path, size: u64, adapter: &str, thin: bool) -> Vec<OsString> {
    vec![
        "-c".into(),
        "-s".into(),
        format!("{size}MB").into(),
        "-a".into(),
        adapter.into(),
        "-t".into(),
        if thin { "0" } else { "2" }.into(),
        path.into(),
    ]
}

/// `-x <size>MB <file>`, `-k <file>`, `-d <file>`.
pub fn expand_args(path: &Path, size: u64) -> Vec<OsString> {
    vec!["-x".into(), format!("{size}MB").into(), path.into()]
}

pub fn shrink_args(path: &Path) -> Vec<OsString> {
    vec!["-k".into(), path.into()]
}

pub fn defragment_args(path: &Path) -> Vec<OsString> {
    vec!["-d".into(), path.into()]
}

/// VM-24: the base name a disk's files share: `web01-000002.vmdk` (a snapshot's delta), `web01-s003.vmdk` (an
/// extent) and `web01-flat.vmdk` all come from `web01`.
pub fn disk_stem(name: &str) -> String {
    let name = Path::new(name)
        .file_name()
        .map_or_else(|| name.to_owned(), |n| n.to_string_lossy().into_owned());
    let mut stem = name
        .strip_suffix(".vmdk")
        .or_else(|| name.strip_suffix(".VMDK"))
        .unwrap_or(&name)
        .to_owned();
    for _ in 0..2 {
        if let Some((base, tail)) = stem.rsplit_once('-') {
            let delta = tail.len() == 6 && tail.bytes().all(|b| b.is_ascii_digit());
            let extent = (tail.starts_with('s') || tail.starts_with('f'))
                && tail.len() == 4
                && tail[1..].bytes().all(|b| b.is_ascii_digit());
            if delta || extent || tail.eq_ignore_ascii_case("flat") {
                stem = base.to_owned();
            }
        }
    }
    stem
}

/// The extensions of a Workstation VM's own files.
const VM_FILE_EXTENSIONS: [&str; 10] = [
    "vmx",
    "vmxf",
    "vmsd",
    "vmsn",
    "vmss",
    "vmem",
    "nvram",
    "scoreboard",
    "vmtx",
    "log",
];

/// VM-24: what `vmrun deleteVM` deletes, as far as Remotely can tell from the folder: the VM's own files (its
/// .vmx, .vmxf, .vmsd, snapshot states, NVRAM, logs and the disks it uses, with their extents and snapshot
/// deltas), and what it leaves (disks outside the folder, files of other kinds). Workstation 26 deletes only
/// the VM's files and keeps the folder when anything else is in it.
pub fn vm_files_going(
    vmx: &Path,
    file: &VmxFile,
    folder_files: &[(PathBuf, u64)],
) -> (Vec<(PathBuf, u64)>, Vec<String>) {
    let folder = vmx.parent().unwrap_or(Path::new(""));
    let vm_stem = vmx
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mut disk_stems: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    let disks: BTreeMap<String, String> = file
        .pairs()
        .filter(|(key, value)| key.ends_with(".filename") && value.to_ascii_lowercase().ends_with(".vmdk"))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    for name in disks.values() {
        let path = resolve(folder, name);
        if path
            .parent()
            .is_some_and(|p| crate::adapters::vmware::path_key(p) == crate::adapters::vmware::path_key(folder))
        {
            disk_stems.push(disk_stem(name).to_ascii_lowercase());
        } else {
            kept.push(format!(
                "{}: a disk outside the VM's folder, which Workstation keeps",
                path.display()
            ));
            // Its snapshot deltas live in the VM's folder and go with the VM.
            disk_stems.push(disk_stem(name).to_ascii_lowercase());
        }
    }
    let mut going = Vec::new();
    let mut others = 0usize;
    for (path, size) in folder_files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let own = name == "nvram"
            || (name.starts_with("vmware") && ext == "log")
            || (name.starts_with(&vm_stem) && VM_FILE_EXTENSIONS.contains(&ext.as_str()))
            || (ext == "vmdk" && disk_stems.iter().any(|stem| name.starts_with(stem.as_str())))
            || (name.starts_with(&vm_stem) && ext == "vmdk");
        if own && !name.ends_with(".remotely-backup") {
            going.push((path.clone(), *size));
        } else {
            others += 1;
        }
    }
    if others > 0 {
        kept.push(format!(
            "{others} other file(s) in {}, which are not the VM's",
            folder.display()
        ));
    }
    (going, kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VMX: &str = r#".encoding = "UTF-8"
config.version = "8"
virtualHW.version = "21"
displayName = "web01"
guestOS = "ubuntu-64"
numvcpus = "4"
cpuid.coresPerSocket = "2"
memsize = "4096"
scsi0.present = "TRUE"
scsi0.virtualDev = "pvscsi"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "web01.vmdk"
sata0.present = "TRUE"
sata0:1.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = ""
sata0:1.startConnected = "FALSE"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "vmxnet3"
ethernet0.addressType = "generated"
ethernet0.generatedAddress = "00:0c:29:ab:cd:ef"
ethernet0.generatedAddressOffset = "0"
vendor.unknown = "kept"
"#;

    fn file() -> VmxFile {
        VmxFile::from_text(VMX)
    }

    fn resources(vcpus: Option<u32>, cores: Option<u32>, memory: Option<u32>) -> VmConfigEdit {
        VmConfigEdit::Resources {
            vcpus,
            cores_per_socket: cores,
            memory_mb: memory,
            nested_virtualization: Some(true),
        }
    }

    #[test]
    fn resizing_sets_cpus_memory_and_a_layout_that_fits() {
        let mut f = file();
        let changes = apply_config(&mut f, &resources(Some(3), None, Some(8192))).unwrap();
        assert_eq!(f.get("numvcpus"), Some("3"));
        assert_eq!(f.get("cpuid.coresPerSocket"), Some("1"), "2 doesn't divide 3");
        assert_eq!(f.get("memsize"), Some("8192"));
        assert_eq!(f.get("vhv.enable"), Some("TRUE"));
        assert_eq!(
            changes,
            [
                "vCPUs: 4 → 3",
                "Cores per socket: 2 → 1",
                "Memory: 4 GB → 8 GB",
                "Nested virtualization: off → on"
            ]
        );
        assert!(f.to_text().contains("vendor.unknown = \"kept\""));
        let mut layout = file();
        apply_config(&mut layout, &resources(Some(8), Some(4), None)).unwrap();
        assert_eq!(layout.get("cpuid.coresPerSocket"), Some("4"));
        assert!(apply_config(&mut file(), &resources(Some(6), Some(4), None)).is_err());
    }

    #[test]
    fn firmware_and_secure_boot_go_together() {
        let mut f = file();
        let efi = VmConfigEdit::Firmware {
            firmware: Firmware::Efi,
            secure_boot: true,
            tpm: None,
        };
        let changes = apply_config(&mut f, &efi).unwrap();
        assert_eq!(f.get("firmware"), Some("efi"));
        assert_eq!(f.get("uefi.secureBoot.enabled"), Some("TRUE"));
        assert_eq!(changes, ["Firmware: BIOS → UEFI", "Secure Boot: off → on"]);
        let bios = VmConfigEdit::Firmware {
            firmware: Firmware::Bios,
            secure_boot: false,
            tpm: None,
        };
        apply_config(&mut f, &bios).unwrap();
        assert_eq!(f.get("firmware"), None);
        assert_eq!(f.get("uefi.secureBoot.enabled"), None);
        let tpm = VmConfigEdit::Firmware {
            firmware: Firmware::Efi,
            secure_boot: true,
            tpm: Some(true),
        };
        assert_eq!(apply_config(&mut f, &tpm).unwrap_err().code(), "vm_setting_refused");
    }

    #[test]
    fn adapters_are_added_changed_and_removed() {
        let mut f = file();
        let add = VmConfigEdit::AddNic {
            network: NicNetwork::Custom { vnet: "vmnet2".into() },
            model: None,
        };
        let changes = apply_config(&mut f, &add).unwrap();
        assert_eq!(changes, ["New network adapter ethernet1: custom (vmnet2), vmxnet3"]);
        assert_eq!(f.get("ethernet1.connectionType"), Some("custom"));
        assert_eq!(f.get("ethernet1.vnet"), Some("VMnet2"));
        assert_eq!(f.get("ethernet1.virtualDev"), Some("vmxnet3"), "like the first adapter");
        assert_eq!(nic_numbers(&f), [0, 1]);

        let edit = VmConfigEdit::EditNic {
            slot: "ethernet0".into(),
            network: Some(NicNetwork::HostOnly { adapter: None }),
            model: Some("e1000e".into()),
            mac: Some(MacAddress::Static {
                mac: "00:50:56:01:02:03".into(),
            }),
            connect_at_power_on: Some(false),
        };
        apply_config(&mut f, &edit).unwrap();
        assert_eq!(f.get("ethernet0.connectionType"), Some("hostonly"));
        assert_eq!(f.get("ethernet0.addressType"), Some("static"));
        assert_eq!(f.get("ethernet0.address"), Some("00:50:56:01:02:03"));
        assert_eq!(f.get("ethernet0.generatedAddress"), None);
        assert_eq!(f.get("ethernet0.startConnected"), Some("FALSE"));

        apply_config(
            &mut f,
            &VmConfigEdit::RemoveNic {
                slot: "ethernet1".into(),
            },
        )
        .unwrap();
        assert!(!f.to_text().contains("ethernet1"));
        let missing = VmConfigEdit::RemoveNic {
            slot: "ethernet5".into(),
        };
        assert_eq!(
            apply_config(&mut f, &missing).unwrap_err().to_string(),
            "The VM has no network adapter ethernet5."
        );
        let vbox_only = VmConfigEdit::AddNic {
            network: NicNetwork::Internal { name: "x".into() },
            model: None,
        };
        assert!(apply_config(&mut f, &vbox_only).is_err());
    }

    #[test]
    fn shared_folders_are_added_once_and_removed_by_name() {
        let mut f = file();
        let add = VmConfigEdit::AddSharedFolder {
            name: "data".into(),
            host_path: r"C:\Shared\data".into(),
            writable: false,
        };
        apply_config(&mut f, &add).unwrap();
        assert_eq!(f.get("sharedFolder0.hostPath"), Some(r"C:\Shared\data"));
        assert_eq!(f.get("sharedFolder0.writeAccess"), Some("FALSE"));
        assert_eq!(f.get("sharedFolder.maxNum"), Some("1"));
        assert_eq!(f.get("isolation.tools.hgfs.disable"), Some("FALSE"));
        assert!(apply_config(&mut f, &add).is_err(), "twice");
        apply_config(&mut f, &VmConfigEdit::RemoveSharedFolder { name: "DATA".into() }).unwrap();
        assert_eq!(f.get("sharedFolder0.hostPath"), None);
        assert!(apply_config(&mut f, &VmConfigEdit::RemoveSharedFolder { name: "data".into() }).is_err());
    }

    #[test]
    fn an_iso_goes_into_the_first_drive_or_a_new_one() {
        let mut f = file();
        let changes = attach_iso_off(&mut f, None, r"C:\ISOs\ubuntu.iso").unwrap();
        assert_eq!(changes, [r"CD/DVD sata0:1: empty → C:\ISOs\ubuntu.iso"]);
        assert_eq!(f.get("sata0:1.startConnected"), Some("TRUE"));
        eject_off(&mut f, None).unwrap();
        assert_eq!(f.get("sata0:1.fileName"), Some(""));
        assert_eq!(f.get("sata0:1.startConnected"), Some("FALSE"));

        let mut bare = VmxFile::from_text(
            "memsize = \"1024\"\nsata0.present = \"TRUE\"\nsata0:0.present = \"TRUE\"\nsata0:0.fileName = \"a.vmdk\"\n",
        );
        let changes = attach_iso_off(&mut bare, None, r"C:\ISOs\x.iso").unwrap();
        assert_eq!(changes, [r"New CD/DVD drive sata0:1 with C:\ISOs\x.iso"]);
        assert_eq!(bare.get("sata0:1.deviceType"), Some("cdrom-image"));
        let mut ide = VmxFile::from_text("memsize = \"1024\"\n");
        attach_iso_off(&mut ide, None, r"C:\ISOs\x.iso").unwrap();
        assert_eq!(ide.get("ide1:0.fileName"), Some(r"C:\ISOs\x.iso"));
        assert!(attach_iso_off(&mut file(), Some("sata0:5"), r"C:\ISOs\x.iso").is_err());
    }

    #[test]
    fn a_new_disk_takes_the_boot_disks_bus_and_a_free_name() {
        let f = file();
        let taken = |name: &str| name == "web01-1.vmdk";
        let disk = plan_new_disk(&f, "web01", None, &taken).unwrap();
        assert_eq!(
            disk,
            NewDisk {
                slot: "scsi0:1".into(),
                add_controller: false,
                adapter: "lsilogic",
                file_name: "web01-2.vmdk".into(),
            }
        );
        let mut g = f.clone();
        attach_disk(&mut g, &disk).unwrap();
        assert_eq!(g.get("scsi0:1.fileName"), Some("web01-2.vmdk"));
        assert_eq!(disk_file(&g, "scsi0:1").unwrap(), "web01-2.vmdk");
        assert!(disk_file(&g, "sata0:1").is_err(), "a CD/DVD drive is no disk");
        detach_disk(&mut g, "scsi0:1").unwrap();
        assert!(disk_file(&g, "scsi0:1").is_err());

        // SCSI unit 7 is the controller's own.
        let mut full = VmxFile::from_text("scsi0.present = \"TRUE\"\n");
        for unit in 0..7 {
            full.set_bool(&format!("scsi0:{unit}.present"), true).unwrap();
            full.set(&format!("scsi0:{unit}.fileName"), &format!("d{unit}.vmdk"))
                .unwrap();
        }
        assert_eq!(plan_new_disk(&full, "x", None, &|_| false).unwrap().slot, "scsi0:8");
        let none = plan_new_disk(&VmxFile::from_text(""), "x", None, &|_| false).unwrap();
        assert!(none.add_controller);
        assert_eq!(none.slot, "scsi0:0");
        let ide = plan_new_disk(&VmxFile::from_text(""), "x", Some("ide0"), &|_| false).unwrap();
        assert_eq!((ide.slot.as_str(), ide.adapter), ("ide0:0", "ide"));
        assert_eq!(
            create_args(Path::new(r"C:\VMs\x\x-1.vmdk"), 20480, "lsilogic", true),
            ["-c", "-s", "20480MB", "-a", "lsilogic", "-t", "0", r"C:\VMs\x\x-1.vmdk"]
                .map(OsString::from)
                .to_vec()
        );
    }

    #[test]
    fn deleting_a_vm_lists_its_own_files_and_what_stays() {
        let vmx = Path::new(r"C:\VMs\web01\web01.vmx");
        let f = VmxFile::from_text(
            "scsi0:0.present = \"TRUE\"\nscsi0:0.fileName = \"web01-000001.vmdk\"\nscsi0:1.present = \"TRUE\"\nscsi0:1.fileName = \"D:\\disks\\shared.vmdk\"\n",
        );
        let folder = |name: &str, size: u64| (PathBuf::from(format!(r"C:\VMs\web01\{name}")), size);
        let files = vec![
            folder("web01.vmx", 3000),
            folder("web01.vmxf", 300),
            folder("web01.vmsd", 600),
            folder("web01-Snapshot1.vmsn", 30_000),
            folder("web01.vmdk", 1000),
            folder("web01-s001.vmdk", 5_000_000),
            folder("web01-000001.vmdk", 2_000_000),
            folder("shared-000001.vmdk", 1_000_000),
            folder("nvram", 8000),
            folder("vmware.log", 70_000),
            folder("vmware-0.log", 70_000),
            folder("notes.txt", 10),
            folder("web01.vmx.ab12cd34.remotely-backup", 3000),
        ];
        let (going, kept) = vm_files_going(vmx, &f, &files);
        let names: Vec<String> = going
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "web01.vmx",
                "web01.vmxf",
                "web01.vmsd",
                "web01-Snapshot1.vmsn",
                "web01.vmdk",
                "web01-s001.vmdk",
                "web01-000001.vmdk",
                "shared-000001.vmdk",
                "nvram",
                "vmware.log",
                "vmware-0.log"
            ]
        );
        assert_eq!(kept.len(), 2);
        assert!(kept[0].starts_with(r"D:\disks\shared.vmdk"));
        assert!(kept[1].starts_with("2 other file(s)"));
        assert_eq!(disk_stem("web01-000002.vmdk"), "web01");
        assert_eq!(disk_stem("web01-000002-s003.vmdk"), "web01");
        assert_eq!(disk_stem("db-flat.vmdk"), "db");
        assert_eq!(disk_stem("my-disk.vmdk"), "my-disk");
    }
}
