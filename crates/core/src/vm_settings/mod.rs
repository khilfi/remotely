//! VM settings and lifecycle (VM-11, VM-12, VM-15, VM-16, VM-23, VM-24): changes to a VM's hardware, devices
//! and disks, deleting a VM and adding an existing one, on Workstation and VirtualBox.
//!
//! Every change is a command on the bus ([`crate::command_bus::Command::VmConfig`], `VmDevice`, `VmDisk`,
//! `VmLifecycle`), rated by the policy engine and run by the job runner, which hands each VM to
//! [`VmEditor::run`]. The same planning gives the approval dialog its preview ([`VmEditor::preview`]): what
//! changes on each VM (before and after), the files that go, and why a VM would be refused.
//!
//! * Workstation: the `.vmx` is changed only while the VM is off. A copy of it is written beside it first
//!   (`web01.vmx.<job>.remotely-backup`), the new text is written whole to a new file that then replaces the
//!   .vmx, and on any failure the copy is put back; the copy is deleted once the change ends well. Unknown
//!   keys, their order and comments are kept ([`crate::adapters::vmx_file`]). Disks go through
//!   `vmware-vdiskmanager` (create, `-x` expand, `-k` shrink, `-d` defragment); hardware upgrades, Tools,
//!   device connections and deletes through vmrun. A running VM's ISO and network cable change through
//!   `writeVariable runtimeConfig` and `connectNamedDevice`; Workstation keeps those until it powers off.
//! * VirtualBox: `modifyvm`, `storageattach`, `modifymedium` and the rest ([`virtualbox`]); a running VM's
//!   DVD and cable change live.
//! * Refused with the reason: settings and disks of a VM that is running or suspended; expanding, compacting,
//!   defragmenting or removing a disk of a VM with snapshots (the snapshots' deltas depend on the disk, and a
//!   resized base under them leaves the guest seeing its old size); removing a disk outside the VM's folder
//!   (another VM may use it).

pub mod ops;
pub mod service;
pub mod virtualbox;
pub mod vmware;

pub use service::{ConsoleOutcome, GuestOsType, VmSettings};

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

pub use ops::{
    Firmware, MacAddress, NicNetwork, VmConfigEdit, VmDeviceOp, VmDiskOp, VmLifecycleOp, MAX_DISK_MB, MAX_MEMORY_MB,
    MAX_VCPUS,
};

use crate::adapters::hypervisor::{Hypervisor, Hypervisors, RunningVms};
use crate::adapters::vm_hardware::VmHardware;
use crate::adapters::vmware::path_key;
use crate::adapters::vmx_file::VmxFile;
use crate::command_bus::Command;
use crate::domain::{Context, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::store::Store;

/// VM-24: `.vmx` files added by hand (Add existing VM), which inventory refreshes list like the library's.
pub const ADDED_VMS_KEY: &str = "vmware.addedVms";

/// vmrun's and VBoxManage's limits for a settings change, a hardware upgrade or Tools, and a disk.
const CHANGE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// A thick disk is written in full, and compacting a large one takes long.
const DISK_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
const DELETE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// AP-02: what a VM settings or lifecycle command does to each VM, for the approval dialog.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmChangePreview {
    pub targets: Vec<VmChangeTarget>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmChangeTarget {
    /// The target's key.
    pub target: String,
    pub name: String,
    /// What changes, before and after: "vCPUs: 2 → 4".
    pub changes: Vec<String>,
    /// VM-24, VM-16: every file that is deleted, with its size.
    pub deletes: Vec<GoingFile>,
    /// What stays that one might expect to go (a disk outside the VM's folder).
    pub keeps: Vec<String>,
    /// Why this VM would be refused now (running, snapshots...): it fails if approved as it is.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoingFile {
    pub path: String,
    pub bytes: Option<u64>,
}

/// What Remotely does to one VM, worked out from its files and state before anything changes.
enum Action {
    /// The .vmx's new text, written after a backup.
    WriteVmx(VmxFile),
    /// `vmrun` calls, in order; with `backup`, the .vmx is backed up first and put back if one fails.
    Vmrun {
        calls: Vec<Vec<OsString>>,
        backup: bool,
        timeout: Duration,
    },
    /// vdiskmanager on a disk.
    Vdisk { args: Vec<OsString> },
    /// VM-16: a new disk: created, then attached in the .vmx; deleted again if that fails.
    NewDisk {
        create: Vec<OsString>,
        path: PathBuf,
        file: VmxFile,
    },
    /// VM-16: the disk off the .vmx, then its files deleted.
    DropDisk { file: VmxFile, delete: Vec<PathBuf> },
    /// VBoxManage calls, in order.
    Vbox { calls: Vec<Vec<String>>, timeout: Duration },
    /// VM-16: a new VirtualBox disk: `calls` create and attach it; on a failure after `createmedium` the new
    /// file is closed and deleted again.
    NewVboxDisk { calls: Vec<Vec<String>>, path: PathBuf },
    /// VM-24: `vmrun deleteVM`, then the VM leaves the added list.
    DeleteVmware,
    /// VM-24: a .vmx joins the added list.
    AddVmx,
}

struct Plan {
    actions: Vec<Action>,
    changes: Vec<String>,
    deletes: Vec<(PathBuf, u64)>,
    keeps: Vec<String>,
}

impl Plan {
    fn one(action: Action, changes: Vec<String>) -> Self {
        Self {
            actions: vec![action],
            changes,
            deletes: Vec::new(),
            keeps: Vec::new(),
        }
    }
}

/// A VM's power state and snapshot count right now.
struct VmState {
    power: PowerState,
    snapshots: usize,
}

fn refused(message: impl Into<String>) -> CoreError {
    CoreError::VmSettingRefused(message.into())
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// Settings and disks change only on a VM that is off.
fn require_off(state: &VmState, hypervisor: Hypervisor) -> Result<()> {
    match state.power {
        PowerState::Running | PowerState::Paused => Err(refused(format!(
            "The VM is running: {} changes this only while it is off. Shut it down first.",
            hypervisor.label()
        ))),
        PowerState::Suspended => Err(refused(
            "The VM is suspended: its saved state would not fit the changed hardware. Start it and shut it down first.",
        )),
        PowerState::Unknown => Err(refused(format!(
            "{} could not say whether the VM is running, so nothing was changed.",
            hypervisor.label()
        ))),
        PowerState::NotRunning => Ok(()),
    }
}

fn require_running(state: &VmState, what: &str) -> Result<()> {
    match state.power {
        PowerState::Running => Ok(()),
        PowerState::Paused => Err(refused(format!("The VM is paused: unpause it to {what}."))),
        _ => Err(refused(format!("The VM is not running: start it to {what}."))),
    }
}

fn require_no_snapshots(state: &VmState, what: &str) -> Result<()> {
    if state.snapshots == 0 {
        return Ok(());
    }
    Err(refused(format!(
        "The VM has {}: a disk can't be {what} while snapshots depend on it. Delete the snapshots first.",
        plural(state.snapshots, "snapshot")
    )))
}

/// VM-16: a new size must be larger than the disk is.
fn check_growth(hardware: &VmHardware, slot: &str, size_mb: u64) -> Result<String> {
    let disk = hardware
        .disks
        .iter()
        .find(|d| d.slot.eq_ignore_ascii_case(slot))
        .ok_or_else(|| refused(format!("The VM has no virtual disk on {slot}.")))?;
    let new_bytes = size_mb.saturating_mul(1024 * 1024);
    if let Some(now) = disk.provisioned_bytes {
        if new_bytes <= now {
            return Err(refused(format!(
                "Disk {slot} is {} already: a disk can only grow, so choose a larger size.",
                ops::size_mb(now / (1024 * 1024))
            )));
        }
        return Ok(format!(
            "Disk {slot}: {} → {} (it can't be shrunk back; grow the partition in the guest afterwards)",
            ops::size_mb(now / (1024 * 1024)),
            ops::size_mb(size_mb)
        ));
    }
    Ok(format!("Disk {slot}: → {}", ops::size_mb(size_mb)))
}

/// The job's id in a backup's name (`ab12cd34`).
fn tag_of(job_id: Uuid) -> String {
    job_id.simple().to_string()[..8].to_owned()
}

/// VM-23 to VM-24: plans and carries out VM settings and lifecycle changes. The job runner calls
/// [`VmEditor::run`] for each target of an approved command; the bus calls [`VmEditor::preview`].
#[derive(Clone)]
pub struct VmEditor {
    hypervisors: Hypervisors,
    store: Store,
}

impl VmEditor {
    pub fn new(hypervisors: Hypervisors, store: Store) -> Self {
        Self { hypervisors, store }
    }

    /// Carries out `command` on one VM. Returns a line for the job's end in the audit log: the VM and what
    /// changed.
    pub async fn run(&self, ctx: &Context, job_id: Uuid, command: &Command, target: &Target) -> Result<String> {
        let TargetRef::Vm { vmx_path } = &target.target else {
            return Err(CoreError::WrongTargetKind {
                action: command.type_name().to_owned(),
                target: target.target.kind().to_owned(),
            });
        };
        let state = self.state_for(command, vmx_path, None).await?;
        let plan = self.plan(vmx_path, command, &state).await?;
        let tag = tag_of(job_id);
        let mut changes = plan.changes.clone();
        for action in plan.actions {
            if let Some(more) = self.execute(ctx, vmx_path, &tag, action).await? {
                changes.push(more);
            }
        }
        Ok(format!("'{}': {}", target.name, changes.join("; ")))
    }

    /// AP-02: what `command` would do to each VM target now. `None` for other commands.
    pub async fn preview(&self, command: &Command, targets: &[Target]) -> Option<VmChangePreview> {
        if !matches!(
            command,
            Command::VmConfig { .. } | Command::VmDevice { .. } | Command::VmDisk { .. } | Command::VmLifecycle { .. }
        ) {
            return None;
        }
        // One `vmrun list` for every Workstation VM, not one each.
        let running = if targets.iter().any(
            |t| matches!(&t.target, TargetRef::Vm { vmx_path } if Hypervisor::of_key(vmx_path) == Hypervisor::Vmware),
        ) {
            Some(self.hypervisors.running().await)
        } else {
            None
        };
        let mut out = VmChangePreview::default();
        for target in targets {
            let TargetRef::Vm { vmx_path } = &target.target else {
                continue;
            };
            let mut row = VmChangeTarget {
                target: vmx_path.clone(),
                name: target.name.clone(),
                ..VmChangeTarget::default()
            };
            let planned = match self.state_for(command, vmx_path, running.as_ref()).await {
                Ok(state) => self.plan(vmx_path, command, &state).await,
                Err(err) => Err(err),
            };
            match planned {
                Ok(plan) => {
                    row.changes = plan.changes;
                    row.keeps = plan.keeps;
                    row.deletes = plan
                        .deletes
                        .into_iter()
                        .map(|(path, bytes)| GoingFile {
                            path: path.display().to_string(),
                            bytes: Some(bytes),
                        })
                        .collect();
                }
                Err(err) => row.problem = Some(err.to_string()),
            }
            out.targets.push(row);
        }
        Some(out)
    }

    /// The VM's power state and snapshots. `running`: a `vmrun list` read once for many VMs. A VM about to be
    /// added isn't known to its hypervisor yet, and needs neither.
    async fn state_for(&self, command: &Command, key: &str, running: Option<&RunningVms>) -> Result<VmState> {
        if let Command::VmLifecycle {
            op: VmLifecycleOp::Register { .. },
            ..
        } = command
        {
            return Ok(VmState {
                power: PowerState::NotRunning,
                snapshots: 0,
            });
        }
        self.state(key, running).await
    }

    async fn state(&self, key: &str, running: Option<&RunningVms>) -> Result<VmState> {
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => {
                let vmware = self.hypervisors.vmware();
                let vmx = Path::new(key);
                let on = match running.and_then(|r| r.contains(key)) {
                    Some(on) => on,
                    None => {
                        let list = vmware.list_running().await?;
                        list.iter().any(|p| path_key(p) == path_key(vmx))
                    }
                };
                let power = if on {
                    PowerState::Running
                } else if vmware.read_vmx(vmx).await?.suspended {
                    PowerState::Suspended
                } else {
                    PowerState::NotRunning
                };
                let snapshots = vmware.snapshots(vmx).await?.snapshots.len();
                Ok(VmState { power, snapshots })
            }
            Hypervisor::VirtualBox => {
                let info = self.hypervisors.virtualbox().vm_info(key).await?;
                Ok(VmState {
                    power: info.power_state(),
                    snapshots: info.snapshots.snapshots.len(),
                })
            }
        }
    }

    async fn plan(&self, key: &str, command: &Command, state: &VmState) -> Result<Plan> {
        match (command, Hypervisor::of_key(key)) {
            (Command::VmConfig { edit, .. }, Hypervisor::Vmware) => {
                self.vmware_config(Path::new(key), edit, state).await
            }
            (Command::VmConfig { edit, .. }, Hypervisor::VirtualBox) => self.vbox_config(key, edit, state).await,
            (Command::VmDevice { op, .. }, Hypervisor::Vmware) => self.vmware_device(Path::new(key), op, state).await,
            (Command::VmDevice { op, .. }, Hypervisor::VirtualBox) => self.vbox_device(key, op, state).await,
            (Command::VmDisk { op, .. }, Hypervisor::Vmware) => self.vmware_disk(Path::new(key), op, state).await,
            (Command::VmDisk { op, .. }, Hypervisor::VirtualBox) => self.vbox_disk(key, op, state).await,
            (Command::VmLifecycle { op, .. }, Hypervisor::Vmware) => {
                self.vmware_lifecycle(Path::new(key), op, state).await
            }
            (Command::VmLifecycle { op, .. }, Hypervisor::VirtualBox) => self.vbox_lifecycle(key, op, state).await,
            _ => Err(CoreError::WrongTargetKind {
                action: command.type_name().to_owned(),
                target: "vm".to_owned(),
            }),
        }
    }

    async fn vmx(&self, vmx: &Path) -> Result<VmxFile> {
        VmxFile::parse(&self.hypervisors.vmware().vmx_bytes(vmx).await?)
    }

    async fn vmware_config(&self, vmx: &Path, edit: &VmConfigEdit, state: &VmState) -> Result<Plan> {
        require_off(state, Hypervisor::Vmware)?;
        let file = self.vmx(vmx).await?;
        if let VmConfigEdit::UpgradeHardware = edit {
            let now = file.get("virtualHW.version").unwrap_or("not set");
            let call = vec!["upgradevm".into(), vmx.into()];
            return Ok(Plan::one(
                Action::Vmrun {
                    calls: vec![call],
                    backup: true,
                    timeout: UPGRADE_TIMEOUT,
                },
                vec![format!(
                    "Hardware version: {now} → the newest this Workstation has (it can't be undone, and older Workstation versions won't open the VM)"
                )],
            ));
        }
        if let VmConfigEdit::AddSharedFolder { host_path, .. } = edit {
            if !self.hypervisors.vmware().file_exists(Path::new(host_path)).await {
                return Err(refused(format!("{host_path} is not there.")));
            }
        }
        let mut file = file;
        let changes = vmware::apply_config(&mut file, edit)?;
        Ok(Plan::one(Action::WriteVmx(file), changes))
    }

    async fn vbox_config(&self, uuid: &str, edit: &VmConfigEdit, state: &VmState) -> Result<Plan> {
        require_off(state, Hypervisor::VirtualBox)?;
        let vbox = self.hypervisors.virtualbox();
        let info = vbox.vm_info(uuid).await?;
        if let VmConfigEdit::AddSharedFolder { host_path, .. } = edit {
            if !vbox.file_exists(Path::new(host_path)).await {
                return Err(refused(format!("{host_path} is not there.")));
            }
        }
        let (calls, changes) = virtualbox::config_calls(uuid, &info, edit)?;
        Ok(Plan::one(
            Action::Vbox {
                calls,
                timeout: CHANGE_TIMEOUT,
            },
            changes,
        ))
    }

    async fn vmware_device(&self, vmx: &Path, op: &VmDeviceOp, state: &VmState) -> Result<Plan> {
        let vmware = self.hypervisors.vmware();
        if let VmDeviceOp::InstallTools = op {
            require_running(state, "install VMware Tools")?;
            return Ok(Plan::one(
                Action::Vmrun {
                    calls: vec![vec!["installTools".into(), vmx.into()]],
                    backup: false,
                    timeout: UPGRADE_TIMEOUT,
                },
                vec!["VMware Tools: the installer starts in the guest (open-vm-tools guests update through their own packages)".into()],
            ));
        }
        if let VmDeviceOp::AttachIso { path, .. } = op {
            if !vmware.file_exists(Path::new(path)).await {
                return Err(refused(format!("{path} is not there.")));
            }
        }
        if state.power == PowerState::Suspended || state.power == PowerState::Unknown {
            require_off(state, Hypervisor::Vmware)?;
        }
        let mut file = self.vmx(vmx).await?;
        let running = state.power.is_on();
        if !running {
            let changes = match op {
                VmDeviceOp::AttachIso { slot, path } => vmware::attach_iso_off(&mut file, slot.as_deref(), path)?,
                VmDeviceOp::EjectIso { slot } => vmware::eject_off(&mut file, slot.as_deref())?,
                VmDeviceOp::ConnectNic { slot } => vmware::connect_nic_off(&mut file, slot, true)?,
                VmDeviceOp::DisconnectNic { slot } => vmware::connect_nic_off(&mut file, slot, false)?,
                VmDeviceOp::InstallTools => Vec::new(),
            };
            return Ok(Plan::one(Action::WriteVmx(file), changes));
        }
        if state.power == PowerState::Paused {
            return Err(refused("The VM is paused: unpause it first."));
        }
        let device = |verb: &str, slot: &str| vec![OsString::from(verb), vmx.into(), slot.into()];
        let (calls, changes) = match op {
            VmDeviceOp::AttachIso { slot, path } => {
                let slot = vmware::cdrom_slot(&file, slot.as_deref())
                    .ok_or_else(|| refused("The VM has no CD/DVD drive: add one (attach an ISO) while it is off."))?;
                let image = file
                    .get(&format!("{slot}.deviceType"))
                    .is_some_and(|t| t.eq_ignore_ascii_case("cdrom-image"));
                if !image {
                    return Err(refused(format!(
                        "The CD/DVD drive {slot} uses a drive of this PC: switch it to an ISO while the VM is off."
                    )));
                }
                let write = vec![
                    OsString::from("writeVariable"),
                    vmx.into(),
                    "runtimeConfig".into(),
                    format!("{slot}.fileName").into(),
                    path.into(),
                ];
                (
                    vec![write, device("connectNamedDevice", &slot)],
                    vec![format!(
                        "CD/DVD {slot}: → {path} (until the VM powers off; attach it while the VM is off to keep it)"
                    )],
                )
            }
            VmDeviceOp::EjectIso { slot } => {
                let slot =
                    vmware::cdrom_slot(&file, slot.as_deref()).ok_or_else(|| refused("The VM has no CD/DVD drive."))?;
                (
                    vec![device("disconnectNamedDevice", &slot)],
                    vec![format!("CD/DVD {slot}: disconnected")],
                )
            }
            VmDeviceOp::ConnectNic { slot } | VmDeviceOp::DisconnectNic { slot } => {
                // vmrun says nothing about a device the VM doesn't have, so Remotely checks first.
                if !vmware::nic_numbers(&file)
                    .iter()
                    .any(|n| format!("ethernet{n}") == *slot)
                {
                    return Err(refused(format!("The VM has no network adapter {slot}.")));
                }
                let connect = matches!(op, VmDeviceOp::ConnectNic { .. });
                let verb = if connect {
                    "connectNamedDevice"
                } else {
                    "disconnectNamedDevice"
                };
                let state = if connect { "connected" } else { "disconnected" };
                (vec![device(verb, slot)], vec![format!("{slot}: {state} now")])
            }
            VmDeviceOp::InstallTools => (Vec::new(), Vec::new()),
        };
        Ok(Plan::one(
            Action::Vmrun {
                calls,
                backup: false,
                timeout: CHANGE_TIMEOUT,
            },
            changes,
        ))
    }

    async fn vbox_device(&self, uuid: &str, op: &VmDeviceOp, state: &VmState) -> Result<Plan> {
        let vbox = self.hypervisors.virtualbox();
        let info = vbox.vm_info(uuid).await?;
        let running = state.power.is_on();
        let (calls, changes) = match op {
            VmDeviceOp::InstallTools => {
                require_running(state, "install the Guest Additions")?;
                let iso = vbox.guest_additions_iso().ok_or_else(|| {
                    refused("VBoxGuestAdditions.iso is not in VirtualBox's folder: repair the VirtualBox install.")
                })?;
                let calls = virtualbox::guest_additions_calls(uuid, &info, &iso)?;
                (
                    calls,
                    vec!["Guest Additions: their ISO goes into the DVD drive; run its installer in the guest".into()],
                )
            }
            VmDeviceOp::AttachIso { slot, path } => {
                if !vbox.file_exists(Path::new(path)).await {
                    return Err(refused(format!("{path} is not there.")));
                }
                virtualbox::attach_iso_calls(
                    uuid,
                    &info,
                    slot.as_deref(),
                    path,
                    state.power == PowerState::NotRunning,
                )?
            }
            VmDeviceOp::EjectIso { slot } => virtualbox::eject_calls(uuid, &info, slot.as_deref())?,
            VmDeviceOp::ConnectNic { slot } => virtualbox::link_calls(uuid, &info, slot, true, running)?,
            VmDeviceOp::DisconnectNic { slot } => virtualbox::link_calls(uuid, &info, slot, false, running)?,
        };
        if state.power == PowerState::Suspended && !matches!(op, VmDeviceOp::InstallTools) {
            require_off(state, Hypervisor::VirtualBox)?;
        }
        Ok(Plan::one(
            Action::Vbox {
                calls,
                timeout: CHANGE_TIMEOUT,
            },
            changes,
        ))
    }

    async fn vmware_disk(&self, vmx: &Path, op: &VmDiskOp, state: &VmState) -> Result<Plan> {
        require_off(state, Hypervisor::Vmware)?;
        let vmware = self.hypervisors.vmware();
        let folder = vmx.parent().unwrap_or(Path::new("")).to_path_buf();
        let mut file = self.vmx(vmx).await?;
        match op {
            VmDiskOp::Add { size_mb, thin, bus } => {
                let stem = vmx
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "disk".into());
                let present: Vec<String> = vmware
                    .folder_files(&folder)
                    .await?
                    .into_iter()
                    .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()))
                    .collect();
                let named: Vec<String> = file
                    .pairs()
                    .filter(|(k, _)| k.ends_with(".filename"))
                    .map(|(_, v)| v.to_ascii_lowercase())
                    .collect();
                let taken = |name: &str| {
                    let name = name.to_ascii_lowercase();
                    let stem = name.trim_end_matches(".vmdk");
                    present
                        .iter()
                        .chain(&named)
                        .any(|p| p == &name || p.starts_with(&format!("{stem}-s")))
                };
                let disk = vmware::plan_new_disk(&file, &stem, bus.as_deref(), &taken)?;
                let path = folder.join(&disk.file_name);
                let mut changes = vmware::attach_disk(&mut file, &disk)?;
                changes[0] = format!(
                    "New {} disk ({}) {} on {}",
                    ops::size_mb(*size_mb),
                    if *thin { "thin" } else { "thick" },
                    path.display(),
                    disk.slot
                );
                Ok(Plan::one(
                    Action::NewDisk {
                        create: vmware::create_args(&path, *size_mb, disk.adapter, *thin),
                        path,
                        file,
                    },
                    changes,
                ))
            }
            VmDiskOp::Expand { slot, size_mb } => {
                require_no_snapshots(state, "expanded")?;
                let path = vmware::resolve(&folder, &vmware::disk_file(&file, slot)?);
                let change = check_growth(&vmware.hardware(vmx).await?, slot, *size_mb)?;
                Ok(Plan::one(
                    Action::Vdisk {
                        args: vmware::expand_args(&path, *size_mb),
                    },
                    vec![change],
                ))
            }
            VmDiskOp::Compact { slot } | VmDiskOp::Defragment { slot } => {
                let compact = matches!(op, VmDiskOp::Compact { .. });
                require_no_snapshots(state, if compact { "compacted" } else { "defragmented" })?;
                let path = vmware::resolve(&folder, &vmware::disk_file(&file, slot)?);
                let (args, what) = if compact {
                    (
                        vmware::shrink_args(&path),
                        "compacted: the space the guest freed goes back to this PC",
                    )
                } else {
                    (vmware::defragment_args(&path), "defragmented")
                };
                Ok(Plan::one(Action::Vdisk { args }, vec![format!("Disk {slot} {what}")]))
            }
            VmDiskOp::Remove { slot } => {
                require_no_snapshots(state, "removed")?;
                let path = vmware::resolve(&folder, &vmware::disk_file(&file, slot)?);
                if path.parent().map(path_key) != Some(path_key(&folder)) {
                    return Err(refused(format!(
                        "{} is outside the VM's folder, where another VM may use it, so Remotely doesn't delete it.",
                        path.display()
                    )));
                }
                let deletes = vmware.disk_files(&path).await?;
                let changes = vmware::detach_disk(&mut file, slot)?;
                Ok(Plan {
                    actions: vec![Action::DropDisk {
                        file,
                        delete: deletes.iter().map(|(p, _)| p.clone()).collect(),
                    }],
                    changes,
                    deletes,
                    keeps: Vec::new(),
                })
            }
        }
    }

    async fn vbox_disk(&self, uuid: &str, op: &VmDiskOp, state: &VmState) -> Result<Plan> {
        require_off(state, Hypervisor::VirtualBox)?;
        let vbox = self.hypervisors.virtualbox();
        let info = vbox.vm_info(uuid).await?;
        match op {
            VmDiskOp::Add { size_mb, thin, bus } => {
                let folder = info
                    .config_file
                    .as_ref()
                    .and_then(|f| f.parent())
                    .ok_or_else(|| refused("VirtualBox didn't say where the VM's folder is."))?
                    .to_path_buf();
                let mut path = None;
                for n in 2..1000 {
                    let candidate = folder.join(format!("{}-disk{n}.vdi", info.name));
                    if !vbox.file_exists(&candidate).await && !info.disks.iter().any(|d| d.path == candidate) {
                        path = Some(candidate);
                        break;
                    }
                }
                let path = path.ok_or_else(|| refused("No free name for a new disk file in the VM's folder."))?;
                let (calls, changes, _) =
                    virtualbox::add_disk_calls(uuid, &info, &path, *size_mb, *thin, bus.as_deref())?;
                Ok(Plan::one(Action::NewVboxDisk { calls, path }, changes))
            }
            VmDiskOp::Expand { slot, size_mb } => {
                require_no_snapshots(state, "expanded")?;
                let path = virtualbox::disk_on(&info, slot)?;
                let change = check_growth(&vbox.hardware(uuid).await?, slot, *size_mb)?;
                Ok(Plan::one(
                    Action::Vbox {
                        calls: vec![virtualbox::resize_call(&path, *size_mb)],
                        timeout: DISK_TIMEOUT,
                    },
                    vec![change],
                ))
            }
            VmDiskOp::Compact { slot } => {
                require_no_snapshots(state, "compacted")?;
                let path = virtualbox::disk_on(&info, slot)?;
                Ok(Plan::one(
                    Action::Vbox {
                        calls: vec![virtualbox::compact_call(&path)],
                        timeout: DISK_TIMEOUT,
                    },
                    vec![format!(
                        "Disk {slot} compacted: the space the guest freed goes back to this PC"
                    )],
                ))
            }
            VmDiskOp::Defragment { .. } => Err(refused(
                "VirtualBox has no defragment for its disks: compact the disk instead.",
            )),
            VmDiskOp::Remove { slot } => {
                require_no_snapshots(state, "removed")?;
                let path = virtualbox::disk_on(&info, slot)?;
                let size = vbox
                    .hardware(uuid)
                    .await
                    .ok()
                    .and_then(|h| h.disks.into_iter().find(|d| d.slot == *slot))
                    .and_then(|d| d.on_disk_bytes)
                    .unwrap_or(0);
                Ok(Plan {
                    actions: vec![Action::Vbox {
                        calls: virtualbox::remove_disk_calls(uuid, slot, &path)?,
                        timeout: CHANGE_TIMEOUT,
                    }],
                    changes: vec![format!("Disk {} on {slot} removed", path.display())],
                    deletes: vec![(path, size)],
                    keeps: Vec::new(),
                })
            }
        }
    }

    async fn vmware_lifecycle(&self, vmx: &Path, op: &VmLifecycleOp, state: &VmState) -> Result<Plan> {
        let vmware = self.hypervisors.vmware();
        match op {
            VmLifecycleOp::Delete => {
                if state.power.is_on() {
                    return Err(refused(
                        "The VM is running: shut it down (or power it off) before it is deleted.",
                    ));
                }
                let file = self.vmx(vmx).await?;
                let folder = vmx.parent().unwrap_or(Path::new(""));
                let listing = vmware.folder_files(folder).await?;
                let (deletes, keeps) = vmware::vm_files_going(vmx, &file, &listing);
                let total: u64 = deletes.iter().map(|(_, size)| size).sum();
                Ok(Plan {
                    actions: vec![Action::DeleteVmware],
                    changes: vec![format!(
                        "Deleted with {} ({})",
                        plural(deletes.len(), "file"),
                        crate::command_bus::human_size(total)
                    )],
                    deletes,
                    keeps,
                })
            }
            VmLifecycleOp::Register { path } => {
                if !vmware.file_exists(Path::new(path)).await {
                    return Err(refused(format!("{path} is not there.")));
                }
                // Reads as a .vmx (A9: capped), so a file of another kind is refused here.
                let info = vmware.read_vmx(Path::new(path)).await?;
                let name = info.display_name.unwrap_or_else(|| path.clone());
                Ok(Plan::one(
                    Action::AddVmx,
                    vec![format!("Lists '{name}' from {path} with the other VMs")],
                ))
            }
        }
    }

    async fn vbox_lifecycle(&self, uuid: &str, op: &VmLifecycleOp, state: &VmState) -> Result<Plan> {
        let vbox = self.hypervisors.virtualbox();
        match op {
            VmLifecycleOp::Delete => {
                if state.power.is_on() {
                    return Err(refused(
                        "The VM is running: shut it down (or power it off) before it is deleted.",
                    ));
                }
                let info = vbox.vm_info(uuid).await?;
                let mut deletes: Vec<(PathBuf, u64)> = Vec::new();
                let mut keeps = Vec::new();
                if let Some(cfg) = &info.config_file {
                    let folder = cfg.parent().unwrap_or(Path::new(""));
                    let stem = cfg
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_ascii_lowercase())
                        .unwrap_or_default();
                    let mut others = 0usize;
                    for (path, size) in vbox.folder_files(folder).await.unwrap_or_default() {
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_ascii_lowercase())
                            .unwrap_or_default();
                        let own = [".vbox", ".vbox-prev", ".nvram"]
                            .iter()
                            .any(|ext| name == format!("{stem}{ext}"))
                            || info.disks.iter().any(|d| path_key(&d.path) == path_key(&path));
                        if own {
                            deletes.push((path, size));
                        } else {
                            others += 1;
                        }
                    }
                    for sub in ["Logs", "Snapshots"] {
                        deletes.extend(vbox.folder_files(&folder.join(sub)).await.unwrap_or_default());
                    }
                    if others > 0 {
                        keeps.push(format!(
                            "{others} other file(s) in {}, which are not the VM's",
                            folder.display()
                        ));
                    }
                }
                for disk in &info.disks {
                    if !deletes.iter().any(|(p, _)| path_key(p) == path_key(&disk.path)) {
                        deletes.push((disk.path.clone(), 0));
                    }
                }
                if info.snapshots.snapshots.is_empty() {
                    keeps.push("ISO images in its DVD drives (VirtualBox only lets go of them)".into());
                } else {
                    keeps.push(
                        "ISO images in its DVD drives (VirtualBox only lets go of them); the base disks its snapshots use go too".into(),
                    );
                }
                let total: u64 = deletes.iter().map(|(_, size)| size).sum();
                Ok(Plan {
                    actions: vec![Action::Vbox {
                        calls: vec![vec!["unregistervm".into(), uuid.into(), "--delete".into()]],
                        timeout: DELETE_TIMEOUT,
                    }],
                    changes: vec![format!(
                        "Unregistered and deleted with {} ({})",
                        plural(deletes.len(), "file"),
                        crate::command_bus::human_size(total)
                    )],
                    deletes,
                    keeps,
                })
            }
            VmLifecycleOp::Register { path } => {
                if !vbox.file_exists(Path::new(path)).await {
                    return Err(refused(format!("{path} is not there.")));
                }
                Ok(Plan::one(
                    Action::Vbox {
                        calls: vec![vec!["registervm".into(), path.clone()]],
                        timeout: CHANGE_TIMEOUT,
                    },
                    vec![format!("Registers {path} with VirtualBox")],
                ))
            }
        }
    }

    /// One planned action. Returns a line to add to what changed, if it has one.
    async fn execute(&self, ctx: &Context, key: &str, tag: &str, action: Action) -> Result<Option<String>> {
        let vmware = self.hypervisors.vmware();
        let vbox = self.hypervisors.virtualbox();
        let vmx = Path::new(key);
        match action {
            Action::WriteVmx(file) => {
                let bytes = file.to_bytes();
                self.with_backup(vmx, tag, async { vmware.write_vmx(vmx, &bytes).await })
                    .await?;
            }
            Action::Vmrun { calls, backup, timeout } => {
                let run = async {
                    for call in calls {
                        vmware.vmrun_change(call, timeout).await?;
                    }
                    Ok(())
                };
                if backup {
                    self.with_backup(vmx, tag, run).await?;
                } else {
                    run.await?;
                }
            }
            Action::Vdisk { args } => {
                vmware.vdiskmanager(args, DISK_TIMEOUT).await?;
            }
            Action::NewDisk { create, path, file } => {
                vmware.vdiskmanager(create, DISK_TIMEOUT).await?;
                let bytes = file.to_bytes();
                if let Err(err) = self
                    .with_backup(vmx, tag, async { vmware.write_vmx(vmx, &bytes).await })
                    .await
                {
                    // The VM doesn't name the new disk: its files go again.
                    let made: Vec<PathBuf> = match vmware.disk_files(&path).await {
                        Ok(files) => files.into_iter().map(|(p, _)| p).collect(),
                        Err(_) => vec![path.clone()],
                    };
                    if let Err(cleanup) = vmware.delete_files(&made).await {
                        tracing::warn!(error = %cleanup, "could not delete a new disk the VM didn't take");
                    }
                    return Err(err);
                }
            }
            Action::DropDisk { file, delete } => {
                let bytes = file.to_bytes();
                self.with_backup(vmx, tag, async { vmware.write_vmx(vmx, &bytes).await })
                    .await?;
                if let Err(err) = vmware.delete_files(&delete).await {
                    let names: Vec<String> = delete.iter().map(|p| p.display().to_string()).collect();
                    return Err(refused(format!(
                        "The disk is off the VM, but its files could not be deleted ({err}): {}. Delete them by hand.",
                        names.join(", ")
                    )));
                }
                return Ok(Some(format!("deleted {}", plural(delete.len(), "file"))));
            }
            Action::Vbox { calls, timeout } => {
                for call in calls {
                    vbox.change(call, timeout).await?;
                }
            }
            Action::NewVboxDisk { calls, path } => {
                let mut created = false;
                for call in calls {
                    let creates = call.first().is_some_and(|c| c == "createmedium");
                    if let Err(err) = vbox.change(call, DISK_TIMEOUT).await {
                        if created {
                            let close = vec![
                                "closemedium".into(),
                                "disk".into(),
                                path.display().to_string(),
                                "--delete".into(),
                            ];
                            if let Err(cleanup) = vbox.change(close, CHANGE_TIMEOUT).await {
                                tracing::warn!(error = %cleanup, "could not delete a new disk the VM didn't take");
                            }
                        }
                        return Err(err);
                    }
                    created |= creates;
                }
            }
            Action::DeleteVmware => {
                vmware
                    .vmrun_change(vec!["deleteVM".into(), vmx.into()], DELETE_TIMEOUT)
                    .await?;
                self.forget_added(ctx, vmx).await?;
            }
            Action::AddVmx => self.remember_added(ctx, vmx).await?,
        }
        Ok(None)
    }

    /// VM-23: `work` with the .vmx backed up beside it first. On success the copy is deleted; on failure it is
    /// put back in the .vmx's place (and then deleted), and if that fails too, the error says where it is.
    async fn with_backup<T>(
        &self,
        vmx: &Path,
        tag: &str,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let vmware = self.hypervisors.vmware();
        let backup = vmware.backup_vmx(vmx, tag).await?;
        match work.await {
            Ok(done) => {
                if let Err(err) = vmware.discard_backup(&backup).await {
                    tracing::warn!(error = %err, "could not delete a .vmx backup after the change went well");
                }
                Ok(done)
            }
            Err(err) => match vmware.restore_vmx(vmx, &backup).await {
                Ok(()) => {
                    if let Err(discard) = vmware.discard_backup(&backup).await {
                        tracing::warn!(error = %discard, "could not delete a .vmx backup after putting it back");
                    }
                    Err(err)
                }
                Err(restore) => Err(refused(format!(
                    "{err}. Putting the .vmx back failed too ({restore}): its copy from before the change is {}",
                    backup.display()
                ))),
            },
        }
    }

    /// VM-24: the .vmx files added by hand.
    pub async fn added(&self, ctx: &Context) -> Result<Vec<String>> {
        Ok(self
            .store
            .get_setting::<Vec<String>>(ctx, ADDED_VMS_KEY)
            .await?
            .unwrap_or_default())
    }

    async fn remember_added(&self, ctx: &Context, vmx: &Path) -> Result<()> {
        let mut added = self.added(ctx).await?;
        let key = path_key(vmx);
        if !added.iter().any(|p| path_key(Path::new(p)) == key) {
            added.push(vmx.display().to_string());
            self.store.put_setting(ctx, ADDED_VMS_KEY, &added).await?;
        }
        Ok(())
    }

    async fn forget_added(&self, ctx: &Context, vmx: &Path) -> Result<()> {
        let mut added = self.added(ctx).await?;
        let key = path_key(vmx);
        let before = added.len();
        added.retain(|p| path_key(Path::new(p)) != key);
        if added.len() != before {
            self.store.put_setting(ctx, ADDED_VMS_KEY, &added).await?;
        }
        Ok(())
    }
}
