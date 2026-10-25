//! Oracle VirtualBox adapter (VM-18): every call to VirtualBox goes through here.
//!
//! It drives `VBoxManage.exe` (VirtualBox 7.0 or later) as a child process without a console window
//! and reads each VM's settings file (`.vbox`) for snapshot times, which VBoxManage does not print.
//! A VM is named by its UUID, which stays the same when the VM is renamed or moved.
//!
//! * Inventory: `list vms`, then `showvminfo <uuid> --machinereadable` for the name, state, OS type,
//!   CPUs, memory, disks, network adapters, settings file, Guest Additions run level and snapshots.
//! * Guest IP and OS name: one `guestproperty enumerate` of the Guest Additions'
//!   `/VirtualBox/GuestInfo/...` properties ([`guest_ip`], [`guest_os_name`]), not one `get` each.
//! * Power: `startvm --type headless|gui`, and `controlvm` `acpipowerbutton` (soft stop: the guest
//!   OS must handle ACPI, no Guest Additions needed), `poweroff`, `reset`, `reboot` (soft restart:
//!   needs Guest Additions), `savestate` (suspend), `pause`, `resume`. Each call has the same time
//!   limit as its vmrun counterpart ([`crate::adapters::vmware::power_timeout`]) and is killed when the
//!   job is cancelled.
//! * Snapshots: `snapshot <uuid> take|restore|delete`. VirtualBox restores only a VM that is not
//!   running, so a revert powers a running VM off first (the approval dialog says so).
//!
//! Never puts guest credentials on a command line; no guest-control operation is used.

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::hypervisor::virtualbox_key;
use super::vm_hardware::VmHardware;
use super::vmware::{power_timeout, SnapshotInfo, SnapshotTree, ToolsState};
use crate::command_bus::{PowerOp, SnapshotOp, StopMode};
use crate::domain::PowerState;
use crate::error::{CoreError, Result};
use crate::locks;

/// Where the VirtualBox installer puts VBoxManage by default.
pub const DEFAULT_VBOXMANAGE: &str = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe";

/// A VM that `VBoxManage list vms` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VboxListedVm {
    pub name: String,
    /// [`virtualbox_key`] form.
    pub uuid: String,
}

/// One network adapter slot from `showvminfo` (`nicN`, `macaddressN`, `nictypeN`, `cableconnectedN`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxNic {
    /// 1 to 8, as VirtualBox numbers them.
    pub slot: u32,
    /// `nat`, `natnetwork`, `hostonly`, `bridged`, `intnet`, `generic`, `null` or `none`.
    pub attachment: String,
    /// 12 hex digits, upper case, as VirtualBox prints them.
    pub mac: Option<String>,
    /// MO-13: the emulated card, e.g. `82540EM` or `virtio`.
    pub model: Option<String>,
    /// MO-13: the virtual cable is plugged in.
    pub cable_connected: Option<bool>,
    /// VM-11: the bridged or host-only adapter (`bridgeadapterN`, `hostonlyadapterN`), NAT network
    /// (`nat-networkN`) or internal network (`intnetN`) it is attached to.
    pub network_name: Option<String>,
}

/// VM-23: a storage controller (`storagecontrollernameN`, `...typeN`, `...portcountN`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxController {
    pub name: String,
    /// `IntelAhci`, `PIIX4`, `LsiLogic`, `NVMe`, `VirtioSCSI`...
    pub kind: Option<String>,
    pub ports: Option<u32>,
}

/// VM-23: a DVD drive: a `<controller>-<port>-<device>` slot that has an `-IsEjected-` key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxDvd {
    pub slot: String,
    /// The image in it; `None` when it is empty.
    pub image: Option<PathBuf>,
    /// A drive of this PC (`host:D:`).
    pub host_drive: Option<String>,
}

/// VM-23: a serial port: `uartN` (`off`, or `0x03f8,4`) and `uartmodeN` (`disconnected`, `file,<path>`,
/// `server,<pipe>`, `client,<pipe>`, `tcpserver,<port>`, `tcpclient,<address>`, or a device).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxUart {
    pub slot: u32,
    pub mode: String,
}

/// VM-23: settings `showvminfo` doesn't print, from the VM's `.vbox` file: its TPM, each shared folder's
/// flags and the sound card.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxSettingsExtras {
    /// `v1_2`, `v2_0`, `Host`, `Swtpm`; `None` without a TPM.
    pub tpm: Option<String>,
    /// By shared folder name: (writable, mounted by itself).
    pub shared_folders: HashMap<String, (Option<bool>, Option<bool>)>,
    /// `HDA`, `AC97`, `SB16`.
    pub audio_controller: Option<String>,
    /// VM-24: the hard disk images the VM uses now or in a snapshot (a snapshot keeps the base disk, the VM its
    /// differencing image), by their `location` in the media registry: relative to the .vbox's folder, or whole.
    /// `unregistervm --delete` deletes them with the VM.
    pub hard_disks: Vec<String>,
}

/// MO-13: a hard disk image attached to a VM, and where (`SATA-0-0`: controller, port, device).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxDisk {
    pub slot: String,
    pub path: PathBuf,
}

impl VboxNic {
    /// The host can't reach a guest behind VirtualBox's NAT (or a NAT network) at the guest's
    /// address; only through port forwards.
    pub fn behind_nat(&self) -> bool {
        matches!(self.attachment.as_str(), "nat" | "natnetwork")
    }

    pub fn enabled(&self) -> bool {
        !matches!(self.attachment.as_str(), "none" | "null" | "")
    }
}

/// What `showvminfo --machinereadable` says about a VM (VM-01, VM-18).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxVmInfo {
    pub uuid: String,
    pub name: String,
    /// `accessible="off"`: VirtualBox can't read the VM's settings file (moved or deleted).
    pub accessible: bool,
    /// The OS type chosen for the VM, e.g. "Ubuntu (64-bit)".
    pub os_type: Option<String>,
    pub cpus: Option<u32>,
    pub memory_mb: Option<u32>,
    /// `VMState`, e.g. `running`, `poweroff`, `saved`, `paused`, `aborted`.
    pub state: String,
    /// `VMStateChangeTime`: when the VM last changed state (for a running VM, its start or resume).
    pub state_changed_at: Option<OffsetDateTime>,
    /// The `.vbox` settings file (`CfgFile`).
    pub config_file: Option<PathBuf>,
    /// Hard disk images attached to the VM (DVD images and empty drives left out).
    pub disks: Vec<VboxDisk>,
    /// MO-13: `BIOS`, `EFI`, `EFI32` or `EFI64`.
    pub firmware: Option<String>,
    /// 0 none, 1 system (VBoxService), 2 user, 3 desktop. Missing while the Guest Additions don't run.
    pub additions_run_level: Option<u32>,
    pub additions_version: Option<String>,
    pub nics: Vec<VboxNic>,
    /// The snapshot tree, without creation times (see [`VirtualBoxAdapter::snapshots`]).
    pub snapshots: SnapshotTree,
    /// VM-23: `nested-hw-virt`.
    pub nested_hw_virt: Option<bool>,
    /// VM-23: `SecureBoot`, printed once the VM has a UEFI variable store.
    pub secure_boot: Option<bool>,
    /// VM-23: `vram` (MB), `accelerate3d`, `monitorcount`, `graphicscontroller`.
    pub video_memory_mb: Option<u32>,
    pub accelerate_3d: Option<bool>,
    pub monitors: Option<u32>,
    pub graphics_controller: Option<String>,
    /// VM-23: `usb`, `ehci` and `xhci` that are on, as "USB 1.1", "USB 2.0", "USB 3.x".
    pub usb: Vec<String>,
    /// VM-23: `audio`: the host driver, or `none` for no sound card.
    pub audio: Option<String>,
    pub uarts: Vec<VboxUart>,
    /// VM-23: `SharedFolderNameMachineMappingN` and `SharedFolderPathMachineMappingN`.
    pub shared_folders: Vec<(String, PathBuf)>,
    pub controllers: Vec<VboxController>,
    pub dvds: Vec<VboxDvd>,
}

impl VboxVmInfo {
    pub fn power_state(&self) -> PowerState {
        power_state_of(&self.state)
    }

    /// The Guest Additions while the VM is on; `None` when it is off.
    pub fn tools_state(&self) -> Option<ToolsState> {
        let state = match self.additions_run_level {
            Some(level) if level >= 1 => ToolsState::Running,
            _ => ToolsState::NotRunning,
        };
        self.power_state().is_on().then_some(state)
    }

    /// AP-02: when the running VM started or resumed. `None` when it is off.
    pub fn running_since(&self) -> Option<OffsetDateTime> {
        self.state_changed_at.filter(|_| self.power_state().is_on())
    }
}

/// `VMState` as a power state. Busy states count as what the VM is while in them: a VM saving its
/// state or taking a live snapshot still runs; one restoring a snapshot offline is off.
pub fn power_state_of(vm_state: &str) -> PowerState {
    match vm_state.trim().to_ascii_lowercase().as_str() {
        "running"
        | "starting"
        | "stopping"
        | "saving"
        | "restoring"
        | "gurumeditation"
        | "teleporting"
        | "teleportingin"
        | "livesnapshotting"
        | "onlinesnapshotting"
        | "deletingsnapshotlive" => PowerState::Running,
        "paused" | "teleportingpausedvm" | "deletingsnapshotlivepaused" => PowerState::Paused,
        "saved" | "aborted-saved" | "abortedsaved" => PowerState::Suspended,
        "poweroff" | "powered off" | "aborted" | "teleported" | "snapshotting" | "restoringsnapshot"
        | "deletingsnapshot" | "settingup" => PowerState::NotRunning,
        _ => PowerState::Unknown,
    }
}

#[async_trait]
pub trait VirtualBoxAdapter: Send + Sync {
    /// Path of VBoxManage in use, for diagnostics. `None` when VirtualBox was not found.
    fn tool_path(&self) -> Option<PathBuf>;
    /// VM-01: `list vms`, every registered VM. [`CoreError::VboxManageNotFound`] without VirtualBox.
    async fn list_vms(&self) -> Result<Vec<VboxListedVm>>;
    /// `list runningvms`: the UUIDs of running (and paused) VMs.
    async fn list_running(&self) -> Result<Vec<String>>;
    /// `showvminfo <uuid> --machinereadable`.
    async fn vm_info(&self, uuid: &str) -> Result<VboxVmInfo>;
    /// VM-01: `guestproperty enumerate <uuid>`: every property the guest has set, by name. One
    /// VBoxManage run for the address and the OS, where a `get` each took up to seven.
    async fn guest_properties(&self, uuid: &str) -> Result<GuestProperties>;
    /// VM-02, VM-03. Only the job runner calls this. A soft stop presses the ACPI power button and
    /// waits until the VM is off.
    async fn power(&self, uuid: &str, op: PowerOp) -> Result<()>;
    /// VM-04, VM-05. Only the job runner calls this. A name may be a snapshot's UUID.
    async fn snapshot(&self, uuid: &str, op: &SnapshotOp) -> Result<()>;
    /// VM-04: the tree from `showvminfo`, with each snapshot's time from the VM's .vbox file.
    async fn snapshots(&self, uuid: &str) -> Result<SnapshotTree>;
    /// MO-13: the VM's virtual hardware: `showvminfo`, each disk image's header, and while the VM runs,
    /// the OS its Guest Additions report. Linux guests report only "Linux" and the kernel: the kernel is
    /// kept, and the OS type chosen for the VM ("Ubuntu (64-bit)") says more than "Linux".
    async fn hardware(&self, uuid: &str) -> Result<VmHardware> {
        let info = self.vm_info(uuid).await?;
        let (mut os_name, mut kernel, mut ips) = (None, None, Vec::new());
        if info.power_state().is_on() {
            let props = self.guest_properties(uuid).await.unwrap_or_default();
            (os_name, kernel) = guest_os_and_kernel(&props);
            ips = guest_ips(&props);
        }
        let extras = self.settings_extras(&info).await;
        let mut hardware = super::vm_hardware::read_virtualbox(&info, os_name, kernel).await;
        super::vm_hardware::add_virtualbox_extras(&mut hardware, extras.as_ref(), ips);
        Ok(hardware)
    }

    /// VM-23: what the VM's `.vbox` file says that `showvminfo` doesn't (TPM, shared folders' flags, the sound
    /// card). `None` when it can't be read. A9: at most [`crate::untrusted::MAX_VM_CONFIG_BYTES`].
    async fn settings_extras(&self, info: &VboxVmInfo) -> Option<VboxSettingsExtras> {
        let file = info.config_file.as_ref()?;
        match crate::untrusted::read_capped(file, crate::untrusted::MAX_VM_CONFIG_BYTES).await {
            Ok(bytes) => Some(parse_vbox_settings_extras(&String::from_utf8_lossy(&bytes))),
            Err(err) => {
                tracing::debug!(file = %file.display(), error = %err, "could not read a .vbox file");
                None
            }
        }
    }

    /// VM-11, VM-12, VM-15, VM-16, VM-23, VM-24: a VBoxManage call that changes something (`modifyvm`,
    /// `storagectl`, `storageattach`, `createmedium`, `modifymedium`, `closemedium`, `controlvm setlinkstateN`,
    /// `sharedfolder`, `modifynvram`, `unregistervm`, `registervm`). Only the job runner calls this, with
    /// arguments [`crate::vm_settings`] builds; never guest credentials.
    async fn change(&self, _args: Vec<String>, _timeout: Duration) -> Result<String> {
        Err(CoreError::VboxManageNotFound)
    }

    /// VM-23: the guest OS types VirtualBox knows (`list ostypes`).
    async fn os_types(&self) -> Result<Vec<VboxOsType>> {
        Err(CoreError::VboxManageNotFound)
    }

    /// VM-23: a running VM's screen as PNG (`controlvm screenshotpng`). A read: nothing changes.
    async fn screenshot(&self, _uuid: &str) -> Result<Vec<u8>> {
        Err(CoreError::VboxManageNotFound)
    }

    /// VM-24: VirtualBox's own window on a running VM (`VirtualBoxVM --startvm <uuid> --separate`).
    async fn open_console(&self, _uuid: &str) -> Result<()> {
        Err(CoreError::VboxManageNotFound)
    }

    /// VM-15: `VBoxGuestAdditions.iso` in VirtualBox's folder, when it is there.
    fn guest_additions_iso(&self) -> Option<PathBuf> {
        None
    }

    /// VM-16, VM-23: whether a file or folder is there. A path on a share or a device path reads as not
    /// there, unopened (A3).
    async fn file_exists(&self, path: &Path) -> bool {
        crate::untrusted::path_refusal(path).is_none() && tokio::fs::metadata(path).await.is_ok()
    }

    /// VM-24: the files directly in a folder, with their sizes (the delete preview).
    async fn folder_files(&self, folder: &Path) -> Result<Vec<(PathBuf, u64)>> {
        super::vmware::files::list(folder).await
    }

    /// VM-11, VM-16, VM-25 (R4): VBoxManage with these arguments: `list hostonlyifs`, `list --long natnets`,
    /// `list systemproperties` and `showvminfo <uuid> --machinereadable` (reads: NAT rules, log and state files),
    /// and from the job runner only `natnetwork modify ... --port-forward-4`, `modifyvm <uuid> --natpfN` and
    /// `controlvm <uuid> natpfN`, built by [`crate::host_networks`]. Never guest credentials.
    async fn vboxmanage_host(&self, _args: Vec<String>, _timeout: Duration) -> Result<String> {
        Err(CoreError::VboxManageNotFound)
    }
}

/// VM-23: a guest OS type VirtualBox knows: the id `modifyvm --ostype` takes and its description.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VboxOsType {
    pub id: String,
    pub description: String,
    pub family: Option<String>,
}

/// Parses `list ostypes`: VirtualBox 7.1 and later print `ID / Description: Ubuntu_64 -- Ubuntu (64-bit)` and
/// `Family: Linux (Linux)`; 7.0 printed `ID:` and `Description:` lines.
pub fn parse_os_types(out: &str) -> Vec<VboxOsType> {
    let mut types: Vec<VboxOsType> = Vec::new();
    for line in out.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("ID / Description:") {
            if let Some((id, description)) = rest.split_once(" -- ") {
                types.push(VboxOsType {
                    id: id.trim().to_owned(),
                    description: description.trim().to_owned(),
                    family: None,
                });
            }
        } else if let Some(id) = line.strip_prefix("ID:") {
            types.push(VboxOsType {
                id: id.trim().to_owned(),
                description: id.trim().to_owned(),
                family: None,
            });
        } else if let Some(description) = line.strip_prefix("Description:") {
            if let Some(last) = types.last_mut() {
                description.trim().clone_into(&mut last.description);
            }
        } else if let Some(family) = line.strip_prefix("Family:").or_else(|| line.strip_prefix("Family ID:")) {
            if let Some(last) = types.last_mut() {
                let family = family.trim();
                let name = family.split(" (").next().unwrap_or(family);
                last.family = Some(name.to_owned());
            }
        }
    }
    types.retain(|t| !t.id.is_empty());
    types
}

/// MO-13: the guest's OS name and kernel from its Guest Additions. Linux guests report only "Linux" and the kernel:
/// the kernel is kept, and the OS type chosen for the VM says more than "Linux".
pub fn guest_os_and_kernel(props: &GuestProperties) -> (Option<String>, Option<String>) {
    let read = |name: &str| props.get(name).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    match (read(GUEST_OS_PRODUCT), read(GUEST_OS_RELEASE)) {
        (Some(p), Some(r)) if p.eq_ignore_ascii_case("linux") => (None, Some(r)),
        (Some(p), None) if p.eq_ignore_ascii_case("linux") => (None, None),
        (Some(p), Some(r)) => (Some(format!("{p} {r}")), None),
        (Some(p), None) => (Some(p), None),
        _ => (None, None),
    }
}

/// VM-23: every IPv4 address the Guest Additions report, one per adapter, in their order.
pub fn guest_ips(props: &GuestProperties) -> Vec<String> {
    let count = props
        .get(GUEST_NET_COUNT)
        .and_then(|c| c.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .min(MAX_GUEST_NICS);
    let mut ips: Vec<String> = Vec::new();
    for index in 0..count {
        if let Some(ip) = props.get(&guest_net(index, "V4/IP")).and_then(|ip| usable_ip(ip)) {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

/// Builds the adapter for this machine. Without VirtualBox the app still starts, with no VirtualBox
/// VMs; an action on one says [`CoreError::VboxManageNotFound`].
pub fn connect(vboxmanage_override: Option<PathBuf>) -> Box<dyn VirtualBoxAdapter> {
    match locate_vboxmanage(vboxmanage_override) {
        Some(path) => {
            tracing::info!(vboxmanage = %path.display(), "using VBoxManage");
            Box::new(VBoxManageCli::new(path))
        }
        None => {
            tracing::info!("VBoxManage.exe not found; no VirtualBox VMs");
            Box::new(MissingVirtualBox)
        }
    }
}

/// Finds VBoxManage.exe: explicit override (Settings), then `REMOTELY_VBOXMANAGE`, then the install
/// folder in the registry (and the installer's `VBOX_MSI_INSTALL_PATH`), then the default folder.
pub fn locate_vboxmanage(override_path: Option<PathBuf>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(override_path);
    candidates.extend(std::env::var_os("REMOTELY_VBOXMANAGE").map(PathBuf::from));
    candidates.extend(registry_install_dirs().into_iter().map(|d| d.join("VBoxManage.exe")));
    candidates.extend(
        std::env::var_os("VBOX_MSI_INSTALL_PATH")
            .filter(|dir| !dir.is_empty())
            .map(|dir| PathBuf::from(dir).join("VBoxManage.exe")),
    );
    candidates.push(PathBuf::from(DEFAULT_VBOXMANAGE));
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(windows)]
fn registry_install_dirs() -> Vec<PathBuf> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Oracle\VirtualBox")
        .and_then(|key| key.get_value::<String, _>("InstallDir"))
        .map(|dir| vec![PathBuf::from(dir)])
        .unwrap_or_default()
}

#[cfg(not(windows))]
fn registry_install_dirs() -> Vec<PathBuf> {
    Vec::new()
}

/// Checks a user-chosen VBoxManage path before it is saved: an existing file named VBoxManage.exe.
pub fn validate_vboxmanage_path(path: &Path) -> Result<()> {
    let named = path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("VBoxManage.exe"));
    if !named {
        return Err(CoreError::InvalidSetting(format!(
            "{} is not VBoxManage.exe",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(CoreError::InvalidSetting(format!("{} does not exist", path.display())));
    }
    Ok(())
}

const LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// showvminfo and guestproperty: quick reads, run for every VM on each refresh.
const QUERY_TIMEOUT: Duration = Duration::from_secs(20);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How often a soft stop asks whether the guest has shut down.
const SHUTDOWN_POLL: Duration = Duration::from_secs(2);

pub struct VBoxManageCli {
    vboxmanage: PathBuf,
}

impl VBoxManageCli {
    pub fn new(vboxmanage: PathBuf) -> Self {
        Self { vboxmanage }
    }

    /// Runs `VBoxManage <args>` without a console window and returns stdout. `label` names the call
    /// in errors (`showvminfo`, `controlvm poweroff`).
    async fn run(&self, label: &str, args: Vec<OsString>, timeout: Duration) -> Result<String> {
        let mut cmd = tokio::process::Command::new(&self.vboxmanage);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let output = tokio::time::timeout(timeout, cmd.output())
            .await
            .map_err(|_| CoreError::Timeout {
                command: format!("VBoxManage {label}"),
                seconds: timeout.as_secs(),
            })??;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success() {
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(CoreError::VboxManage {
                command: label.to_owned(),
                message: error_message(&stdout, &stderr),
            })
        }
    }

    async fn controlvm(&self, uuid: &str, verb: &str, op: PowerOp) -> Result<()> {
        let label = format!("controlvm {verb}");
        self.run(
            &label,
            vec!["controlvm".into(), uuid.into(), verb.into()],
            power_timeout(op),
        )
        .await
        .map(drop)
        .map_err(no_answer)
    }

    /// VM-03: waits until the guest has shut down after the ACPI power button.
    async fn wait_until_off(&self, uuid: &str) -> Result<()> {
        loop {
            if !self.vm_info(uuid).await?.power_state().is_on() {
                return Ok(());
            }
            tokio::time::sleep(SHUTDOWN_POLL).await;
        }
    }
}

/// A power call that timed out says why it may have hung.
fn no_answer(err: CoreError) -> CoreError {
    match err {
        CoreError::Timeout { command, seconds } => CoreError::VboxPowerTimeout {
            command: command.trim_start_matches("VBoxManage ").to_owned(),
            seconds,
        },
        other => other,
    }
}

/// VBoxManage's own words from a failed call: its `error:` lines without the program prefix, leaving
/// out the `Details:` and `Context:` lines meant for VirtualBox's developers.
pub fn error_message(stdout: &str, stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let errors: Vec<&str> = lines
        .iter()
        .filter_map(|line| line.split_once("error: ").map(|(_, rest)| rest.trim()))
        .filter(|rest| !rest.starts_with("Details:") && !rest.starts_with("Context:"))
        .collect();
    if errors.is_empty() {
        lines.join(" ")
    } else {
        errors.join(" ")
    }
}

#[async_trait]
impl VirtualBoxAdapter for VBoxManageCli {
    fn tool_path(&self) -> Option<PathBuf> {
        Some(self.vboxmanage.clone())
    }

    async fn list_vms(&self) -> Result<Vec<VboxListedVm>> {
        let out = self
            .run("list vms", vec!["list".into(), "vms".into()], LIST_TIMEOUT)
            .await?;
        Ok(parse_list_vms(&out))
    }

    async fn list_running(&self) -> Result<Vec<String>> {
        let out = self
            .run(
                "list runningvms",
                vec!["list".into(), "runningvms".into()],
                LIST_TIMEOUT,
            )
            .await?;
        Ok(parse_list_vms(&out).into_iter().map(|vm| vm.uuid).collect())
    }

    async fn vm_info(&self, uuid: &str) -> Result<VboxVmInfo> {
        let args = vec!["showvminfo".into(), uuid.into(), "--machinereadable".into()];
        let out = self.run("showvminfo", args, QUERY_TIMEOUT).await?;
        Ok(parse_showvminfo(&out))
    }

    async fn guest_properties(&self, uuid: &str) -> Result<GuestProperties> {
        let args = vec!["guestproperty".into(), "enumerate".into(), uuid.into()];
        let out = self.run("guestproperty enumerate", args, QUERY_TIMEOUT).await?;
        Ok(parse_guest_properties(&out))
    }

    async fn power(&self, uuid: &str, op: PowerOp) -> Result<()> {
        match op {
            PowerOp::Start { gui } => {
                let front = if gui { "gui" } else { "headless" };
                let args = vec!["startvm".into(), uuid.into(), "--type".into(), front.into()];
                self.run("startvm", args, power_timeout(op))
                    .await
                    .map(drop)
                    .map_err(no_answer)
            }
            PowerOp::Stop { mode: StopMode::Soft } => {
                // The button returns at once; the guest shuts down in its own time. The job runner
                // stops waiting after the shutdown wait (VM-03), within this call's own limit.
                self.controlvm(uuid, "acpipowerbutton", op).await?;
                tokio::time::timeout(power_timeout(op), self.wait_until_off(uuid))
                    .await
                    .map_err(|_| CoreError::VboxPowerTimeout {
                        command: "controlvm acpipowerbutton".into(),
                        seconds: power_timeout(op).as_secs(),
                    })?
            }
            PowerOp::Stop { mode: StopMode::Hard } => self.controlvm(uuid, "poweroff", op).await,
            PowerOp::Reset { mode: StopMode::Soft } => self.controlvm(uuid, "reboot", op).await,
            PowerOp::Reset { mode: StopMode::Hard } => self.controlvm(uuid, "reset", op).await,
            PowerOp::Suspend => self.controlvm(uuid, "savestate", op).await,
            PowerOp::Pause => self.controlvm(uuid, "pause", op).await,
            PowerOp::Unpause => self.controlvm(uuid, "resume", op).await,
        }
    }

    async fn snapshot(&self, uuid: &str, op: &SnapshotOp) -> Result<()> {
        let (verb, name) = match op {
            SnapshotOp::Take { name } => ("take", name),
            SnapshotOp::Revert { name } => ("restore", name),
            SnapshotOp::Delete { name } => ("delete", name),
        };
        let info = self.vm_info(uuid).await?;
        check_snapshot_op(&info, op)?;
        if matches!(op, SnapshotOp::Revert { .. }) && info.power_state().is_on() {
            // VirtualBox restores only a VM that is not running.
            let off = PowerOp::Stop { mode: StopMode::Hard };
            self.controlvm(uuid, "poweroff", off).await?;
        }
        let label = format!("snapshot {verb}");
        let args = vec!["snapshot".into(), uuid.into(), verb.into(), name.into()];
        self.run(&label, args, SNAPSHOT_TIMEOUT).await.map(drop)
    }

    async fn snapshots(&self, uuid: &str) -> Result<SnapshotTree> {
        let info = self.vm_info(uuid).await?;
        let mut tree = info.snapshots;
        if let (false, Some(file)) = (tree.snapshots.is_empty(), &info.config_file) {
            // A9: at most MAX_VM_CONFIG_BYTES; a larger one leaves the times out.
            match crate::untrusted::read_capped(file, crate::untrusted::MAX_VM_CONFIG_BYTES).await {
                Ok(bytes) => {
                    add_snapshot_times(&mut tree, &parse_vbox_snapshot_times(&String::from_utf8_lossy(&bytes)))
                }
                Err(err) => tracing::debug!(file = %file.display(), error = %err, "could not read a .vbox file"),
            }
        }
        Ok(tree)
    }

    async fn change(&self, args: Vec<String>, timeout: Duration) -> Result<String> {
        let label = change_label(&args);
        self.run(&label, args.into_iter().map(OsString::from).collect(), timeout)
            .await
    }

    async fn vboxmanage_host(&self, args: Vec<String>, timeout: Duration) -> Result<String> {
        let label = change_label(&args);
        self.run(&label, args.into_iter().map(OsString::from).collect(), timeout)
            .await
    }

    async fn os_types(&self) -> Result<Vec<VboxOsType>> {
        let out = self
            .run("list ostypes", vec!["list".into(), "ostypes".into()], LIST_TIMEOUT)
            .await?;
        Ok(parse_os_types(&out))
    }

    async fn screenshot(&self, uuid: &str) -> Result<Vec<u8>> {
        // VBoxManage writes the PNG to a file; Remotely reads it and deletes it at once.
        let file = std::env::temp_dir().join(format!("remotely-screen-{}.png", uuid::Uuid::new_v4()));
        let args = vec![
            "controlvm".into(),
            uuid.into(),
            "screenshotpng".into(),
            file.clone().into_os_string(),
        ];
        let taken = self.run("controlvm screenshotpng", args, QUERY_TIMEOUT).await;
        let read = match taken {
            Ok(_) => crate::untrusted::read_capped(&file, MAX_SCREENSHOT_BYTES)
                .await
                .map_err(CoreError::from),
            Err(err) => Err(err),
        };
        if let Err(err) = tokio::fs::remove_file(&file).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(error = %err, "could not delete a screenshot's temporary file");
            }
        }
        read
    }

    async fn open_console(&self, uuid: &str) -> Result<()> {
        let window = self
            .vboxmanage
            .parent()
            .map(|dir| dir.join("VirtualBoxVM.exe"))
            .filter(|p| p.is_file())
            .ok_or_else(|| {
                CoreError::VmSettingRefused(
                    "VirtualBoxVM.exe is not next to VBoxManage.exe, so Remotely can't open the VM's window".into(),
                )
            })?;
        // VirtualBox's own window for a VM that already runs (headless, say); nothing about the VM changes.
        std::process::Command::new(window)
            .args(["--startvm", uuid, "--separate"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(drop)
            .map_err(CoreError::from)
    }

    fn guest_additions_iso(&self) -> Option<PathBuf> {
        self.vboxmanage
            .parent()
            .map(|dir| dir.join("VBoxGuestAdditions.iso"))
            .filter(|p| p.is_file())
    }
}

/// A screenshot of a 4K screen is a few MB; more than this is refused, never read in part (A9).
pub const MAX_SCREENSHOT_BYTES: u64 = 64 * 1024 * 1024;

/// How a VBoxManage change is named in errors: `modifyvm`, `storageattach`, `controlvm setlinkstate1`,
/// `modifymedium`... (the subcommand, and for `controlvm`, `modifynvram` and `sharedfolder` its verb).
pub fn change_label(args: &[String]) -> String {
    match args.first().map(String::as_str) {
        Some(sub @ ("controlvm" | "modifynvram" | "sharedfolder")) => {
            let verb_at = if sub == "sharedfolder" { 1 } else { 2 };
            match args.get(verb_at) {
                Some(verb) => format!("{sub} {verb}"),
                None => sub.to_owned(),
            }
        }
        Some(sub) => sub.to_owned(),
        None => "(nothing)".to_owned(),
    }
}

/// What a snapshot change needs before VBoxManage runs, the same for the real adapter and the fake:
/// a snapshot to revert to or delete must exist (by name or UUID), and a new name must be one the VM
/// does not have yet, since VirtualBox would take a second snapshot with the same name.
pub fn check_snapshot_op(info: &VboxVmInfo, op: &SnapshotOp) -> Result<()> {
    let failed = |command: &str, message: String| CoreError::VboxManage {
        command: command.to_owned(),
        message,
    };
    match op {
        SnapshotOp::Take { name } if info.snapshots.snapshots.iter().any(|s| &s.name == name) => Err(failed(
            "snapshot take",
            format!("the VM already has a snapshot named '{name}'"),
        )),
        SnapshotOp::Take { .. } => Ok(()),
        SnapshotOp::Revert { name } | SnapshotOp::Delete { name } => {
            if find_snapshot(&info.snapshots, name).is_some() {
                Ok(())
            } else {
                let verb = if matches!(op, SnapshotOp::Revert { .. }) {
                    "restore"
                } else {
                    "delete"
                };
                Err(failed(
                    &format!("snapshot {verb}"),
                    format!("the VM has no snapshot named '{name}'"),
                ))
            }
        }
    }
}

/// A snapshot by its UUID, else by name (the first in tree order, as VirtualBox finds it).
pub fn find_snapshot<'a>(tree: &'a SnapshotTree, name: &str) -> Option<&'a SnapshotInfo> {
    let id = virtualbox_key(name);
    tree.snapshots
        .iter()
        .find(|s| id.is_some() && s.id == id)
        .or_else(|| tree.snapshots.iter().find(|s| s.name == name))
}

/// Stand-in when VirtualBox is not installed: there are no VirtualBox VMs, and anything else fails
/// with [`CoreError::VboxManageNotFound`].
struct MissingVirtualBox;

#[async_trait]
impl VirtualBoxAdapter for MissingVirtualBox {
    fn tool_path(&self) -> Option<PathBuf> {
        None
    }
    async fn list_vms(&self) -> Result<Vec<VboxListedVm>> {
        Err(CoreError::VboxManageNotFound)
    }
    async fn list_running(&self) -> Result<Vec<String>> {
        Err(CoreError::VboxManageNotFound)
    }
    async fn vm_info(&self, _: &str) -> Result<VboxVmInfo> {
        Err(CoreError::VboxManageNotFound)
    }
    async fn guest_properties(&self, _: &str) -> Result<GuestProperties> {
        Err(CoreError::VboxManageNotFound)
    }
    async fn power(&self, _: &str, _: PowerOp) -> Result<()> {
        Err(CoreError::VboxManageNotFound)
    }
    async fn snapshot(&self, _: &str, _: &SnapshotOp) -> Result<()> {
        Err(CoreError::VboxManageNotFound)
    }
    async fn snapshots(&self, _: &str) -> Result<SnapshotTree> {
        Err(CoreError::VboxManageNotFound)
    }
}

/// The adapter the rest of the core holds. Changing the VBoxManage path in Settings swaps what is
/// inside without restarting; a call already in flight finishes on the adapter it started with.
pub struct SwitchableVirtualBox {
    inner: RwLock<Arc<dyn VirtualBoxAdapter>>,
}

impl SwitchableVirtualBox {
    pub fn new(adapter: Arc<dyn VirtualBoxAdapter>) -> Self {
        Self {
            inner: RwLock::new(adapter),
        }
    }

    pub fn replace(&self, adapter: Arc<dyn VirtualBoxAdapter>) {
        *locks::write(&self.inner) = adapter;
    }

    fn current(&self) -> Arc<dyn VirtualBoxAdapter> {
        Arc::clone(&locks::read(&self.inner))
    }
}

#[async_trait]
impl VirtualBoxAdapter for SwitchableVirtualBox {
    fn tool_path(&self) -> Option<PathBuf> {
        self.current().tool_path()
    }
    async fn list_vms(&self) -> Result<Vec<VboxListedVm>> {
        self.current().list_vms().await
    }
    async fn list_running(&self) -> Result<Vec<String>> {
        self.current().list_running().await
    }
    async fn vm_info(&self, uuid: &str) -> Result<VboxVmInfo> {
        self.current().vm_info(uuid).await
    }
    async fn guest_properties(&self, uuid: &str) -> Result<GuestProperties> {
        self.current().guest_properties(uuid).await
    }
    async fn power(&self, uuid: &str, op: PowerOp) -> Result<()> {
        self.current().power(uuid, op).await
    }
    async fn snapshot(&self, uuid: &str, op: &SnapshotOp) -> Result<()> {
        self.current().snapshot(uuid, op).await
    }
    async fn snapshots(&self, uuid: &str) -> Result<SnapshotTree> {
        self.current().snapshots(uuid).await
    }
    async fn hardware(&self, uuid: &str) -> Result<VmHardware> {
        self.current().hardware(uuid).await
    }
    async fn settings_extras(&self, info: &VboxVmInfo) -> Option<VboxSettingsExtras> {
        self.current().settings_extras(info).await
    }
    async fn change(&self, args: Vec<String>, timeout: Duration) -> Result<String> {
        self.current().change(args, timeout).await
    }
    async fn os_types(&self) -> Result<Vec<VboxOsType>> {
        self.current().os_types().await
    }
    async fn screenshot(&self, uuid: &str) -> Result<Vec<u8>> {
        self.current().screenshot(uuid).await
    }
    async fn open_console(&self, uuid: &str) -> Result<()> {
        self.current().open_console(uuid).await
    }
    fn guest_additions_iso(&self) -> Option<PathBuf> {
        self.current().guest_additions_iso()
    }
    async fn file_exists(&self, path: &Path) -> bool {
        self.current().file_exists(path).await
    }
    async fn folder_files(&self, folder: &Path) -> Result<Vec<(PathBuf, u64)>> {
        self.current().folder_files(folder).await
    }
    async fn vboxmanage_host(&self, args: Vec<String>, timeout: Duration) -> Result<String> {
        self.current().vboxmanage_host(args, timeout).await
    }
}

/// VM-01: the guest's properties by name, as `guestproperty enumerate` lists them.
pub type GuestProperties = HashMap<String, String>;

/// The Guest Additions' count of network adapters, and each one's address and MAC.
pub const GUEST_NET_COUNT: &str = "/VirtualBox/GuestInfo/Net/Count";
pub const GUEST_OS_PRODUCT: &str = "/VirtualBox/GuestInfo/OS/Product";
pub const GUEST_OS_RELEASE: &str = "/VirtualBox/GuestInfo/OS/Release";
/// Adapters read at most; VirtualBox gives a VM up to 8.
const MAX_GUEST_NICS: u32 = 8;

fn guest_net(index: u32, what: &str) -> String {
    format!("/VirtualBox/GuestInfo/Net/{index}/{what}")
}

/// QL-01: the guest's IPv4 address from its Guest Additions, the one the host can reach. A guest
/// behind VirtualBox's NAT has an address (10.0.2.15 in every VM, by default) that the host can't
/// reach, so when the VM also has another kind of adapter (host-only, bridged), its address wins: the
/// guest's adapters are matched to the VM's by MAC address. `None` when the guest reports none.
pub fn guest_ip(props: &GuestProperties, nics: &[VboxNic]) -> Option<String> {
    let count = props
        .get(GUEST_NET_COUNT)
        .and_then(|c| c.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .min(MAX_GUEST_NICS);
    let found: Vec<(u32, String)> = (0..count)
        .filter_map(|index| {
            let ip = props.get(&guest_net(index, "V4/IP")).and_then(|ip| usable_ip(ip))?;
            Some((index, ip))
        })
        .collect();
    let enabled: Vec<&VboxNic> = nics.iter().filter(|n| n.enabled()).collect();
    let mixed = enabled.iter().any(|n| n.behind_nat()) && enabled.iter().any(|n| !n.behind_nat());
    if found.len() < 2 || !mixed {
        return found.into_iter().next().map(|(_, ip)| ip);
    }
    let mut first_unknown = None;
    for (index, ip) in &found {
        let mac = props.get(&guest_net(*index, "MAC"));
        let nic = mac.and_then(|mac| {
            enabled
                .iter()
                .find(|n| n.mac.as_deref().is_some_and(|m| same_mac(m, mac)))
        });
        match nic {
            Some(nic) if !nic.behind_nat() => return Some(ip.clone()),
            Some(_) => {}
            None => {
                first_unknown.get_or_insert_with(|| ip.clone());
            }
        }
    }
    first_unknown.or_else(|| found.into_iter().next().map(|(_, ip)| ip))
}

fn usable_ip(text: &str) -> Option<String> {
    let ip: IpAddr = text.trim().parse().ok()?;
    (!ip.is_loopback() && !ip.is_unspecified()).then(|| ip.to_string())
}

fn same_mac(a: &str, b: &str) -> bool {
    let clean = |m: &str| {
        m.chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_lowercase()
    };
    clean(a) == clean(b)
}

/// What the guest calls its OS through the Guest Additions, e.g. "Windows 11 10.0.22631" or
/// "Linux 6.8.0-45-generic" (Linux guests report the kernel, not the distribution).
pub fn guest_os_name(props: &GuestProperties) -> Option<String> {
    let product = props.get(GUEST_OS_PRODUCT)?;
    let name = match props.get(GUEST_OS_RELEASE).map(|r| r.trim()).filter(|r| !r.is_empty()) {
        Some(release) => format!("{} {release}", product.trim()),
        None => product.trim().to_owned(),
    };
    Some(name).filter(|n| !n.is_empty())
}

/// Parses `VBoxManage list vms` (and `list runningvms`):
///
/// ```text
/// "web01" {3f0c1a2b-1111-4222-8333-444455556666}
/// "<inaccessible>" {9d1e2f3a-...}
/// ```
pub fn parse_list_vms(out: &str) -> Vec<VboxListedVm> {
    out.lines()
        .filter_map(|line| {
            let line = line.trim();
            let open = line.rfind('{')?;
            let uuid = virtualbox_key(&line[open..])?;
            let name = line[..open].trim();
            let name = name.strip_prefix('"').and_then(|n| n.strip_suffix('"')).unwrap_or(name);
            Some(VboxListedVm {
                name: name.to_owned(),
                uuid,
            })
        })
        .collect()
}

/// Parses `guestproperty enumerate`. VirtualBox 7 prints one property a line: the name, padded, then
/// its value in single quotes and after it the time it was set and its flags:
///
/// ```text
/// /VirtualBox/GuestInfo/Net/0/V4/IP = '192.0.2.15' @ 2026-10-25T08:00:00.000000000Z (TRANSIENT, TRANSRESET)
/// ```
///
/// Before 7.0 (and with `--old-format`) a line is `Name: <name>, value: <value>, timestamp: <ns>,
/// flags: <flags>`. Both are read; `No properties found.` and anything else are skipped.
pub fn parse_guest_properties(out: &str) -> GuestProperties {
    out.lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            if let Some(rest) = line.trim_start().strip_prefix("Name: ") {
                let (name, rest) = rest.split_once(", value: ")?;
                let value = rest.rsplit_once(", timestamp: ").map_or(rest, |(value, _)| value);
                return Some((name.trim().to_owned(), value.to_owned()));
            }
            let (name, rest) = line.split_once(" = '")?;
            // The value ends at the last quote: the time and flags after it have none.
            let value = rest.rfind('\'').map_or(rest, |end| &rest[..end]);
            let name = name.trim();
            name.starts_with('/').then(|| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Splits VBoxManage's machine-readable output into `key=value` pairs, in order. Keys may be quoted
/// (`"SATA-0-0"="..."`); values are quoted strings or bare numbers and words. VirtualBox 7 escapes `"`
/// and `\` inside quoted values with a backslash; a quoted value may run over several lines (a
/// snapshot description).
pub fn parse_machine_readable(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        rest = rest.trim_start_matches(['\r', '\n', ' ', '\t']);
        if rest.is_empty() {
            break;
        }
        let (key, after_key) = if let Some(quoted) = rest.strip_prefix('"') {
            let (key, after) = read_quoted(quoted);
            (key, after)
        } else {
            let end = rest.find(['=', '\n']).unwrap_or(rest.len());
            (rest[..end].trim().to_owned(), &rest[end..])
        };
        let Some(after_eq) = after_key.strip_prefix('=') else {
            // Not a key=value line: skip it.
            rest = after_key.find('\n').map_or("", |i| &after_key[i + 1..]);
            continue;
        };
        let (value, after_value) = if let Some(quoted) = after_eq.strip_prefix('"') {
            read_quoted(quoted)
        } else {
            let end = after_eq.find('\n').unwrap_or(after_eq.len());
            (after_eq[..end].trim().to_owned(), &after_eq[end..])
        };
        if !key.is_empty() {
            pairs.push((key, value));
        }
        rest = after_value.find('\n').map_or("", |i| &after_value[i + 1..]);
    }
    pairs
}

/// Reads a quoted string up to its closing quote (`text` starts after the opening one). `\"` and
/// `\\` are a quote and a backslash; any other backslash is kept as it is.
fn read_quoted(text: &str) -> (String, &str) {
    let mut out = String::new();
    let mut chars = text.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => match text[i + 1..].chars().next() {
                Some(next @ ('"' | '\\')) => {
                    out.push(next);
                    chars.next();
                }
                _ => out.push('\\'),
            },
            '"' => return (out, &text[i + 1..]),
            c => out.push(c),
        }
    }
    (out, "")
}

/// Hard disk image extensions VirtualBox opens; DVD and floppy images are left out of a VM's disks.
const DISK_EXTENSIONS: [&str; 8] = ["vdi", "vmdk", "vhd", "vhdx", "hdd", "qcow", "qcow2", "qed"];

/// Parses `showvminfo --machinereadable`:
///
/// ```text
/// name="web01"
/// ostype="Ubuntu (64-bit)"
/// UUID="3f0c1a2b-1111-4222-8333-444455556666"
/// CfgFile="C:\\Users\\alice\\VirtualBox VMs\\web01\\web01.vbox"
/// memory=4096
/// cpus=2
/// VMState="running"
/// VMStateChangeTime="2026-10-20T08:15:00.123000000"
/// "SATA-0-0"="C:\\Users\\alice\\VirtualBox VMs\\web01\\web01.vdi"
/// nic1="nat"
/// macaddress1="080027AABB01"
/// GuestAdditionsRunLevel=2
/// SnapshotName="base"
/// SnapshotUUID="..."
/// SnapshotName-1="child"
/// CurrentSnapshotNode="SnapshotName-1"
/// ```
pub fn parse_showvminfo(text: &str) -> VboxVmInfo {
    let pairs = parse_machine_readable(text);
    let mut info = VboxVmInfo {
        accessible: true,
        ..Default::default()
    };
    let mut nics: HashMap<u32, VboxNic> = HashMap::new();
    let mut networks: HashMap<(String, u32), String> = HashMap::new();
    let mut uart_modes: HashMap<u32, String> = HashMap::new();
    let mut uarts: Vec<u32> = Vec::new();
    let mut controllers: HashMap<u32, VboxController> = HashMap::new();
    let mut folder_names: HashMap<u32, String> = HashMap::new();
    let mut folder_paths: HashMap<u32, PathBuf> = HashMap::new();
    let mut dvd_slots: Vec<String> = Vec::new();
    for (key, value) in &pairs {
        let present = || Some(value.clone()).filter(|v| !v.trim().is_empty());
        match key.as_str() {
            "name" => info.name = value.clone(),
            "UUID" => info.uuid = virtualbox_key(value).unwrap_or_else(|| value.to_lowercase()),
            "ostype" => info.os_type = present(),
            "memory" => info.memory_mb = value.trim().parse().ok(),
            "cpus" => info.cpus = value.trim().parse().ok(),
            "VMState" => info.state = value.clone(),
            "VMStateChangeTime" => info.state_changed_at = parse_vbox_time(value),
            "CfgFile" => info.config_file = present().map(PathBuf::from),
            "accessible" => info.accessible = !value.eq_ignore_ascii_case("off"),
            "GuestAdditionsRunLevel" => info.additions_run_level = value.trim().parse().ok(),
            "GuestAdditionsVersion" => info.additions_version = present(),
            "firmware" => info.firmware = present(),
            "nested-hw-virt" => info.nested_hw_virt = Some(is_on(value)),
            "SecureBoot" => info.secure_boot = Some(is_on(value)),
            "vram" => info.video_memory_mb = value.trim().parse().ok(),
            "accelerate3d" => info.accelerate_3d = Some(is_on(value)),
            "monitorcount" => info.monitors = value.trim().parse().ok(),
            "graphicscontroller" => info.graphics_controller = present(),
            "usb" | "ehci" | "xhci" if is_on(value) => info.usb.push(
                match key.as_str() {
                    "usb" => "USB 1.1",
                    "ehci" => "USB 2.0",
                    _ => "USB 3.x",
                }
                .to_owned(),
            ),
            "audio" => info.audio = present(),
            _ => {
                let numbered = |prefix: &str| key.strip_prefix(prefix).and_then(|n| n.parse::<u32>().ok());
                if let Some(slot) = numbered("nic") {
                    nic_slot(&mut nics, slot).attachment = value.to_ascii_lowercase();
                } else if let Some(slot) = numbered("macaddress") {
                    nic_slot(&mut nics, slot).mac = present();
                } else if let Some(slot) = numbered("nictype") {
                    nic_slot(&mut nics, slot).model = present();
                } else if let Some(slot) = numbered("cableconnected") {
                    nic_slot(&mut nics, slot).cable_connected = Some(value.eq_ignore_ascii_case("on"));
                } else if let Some(slot) = numbered("bridgeadapter")
                    .or_else(|| numbered("hostonlyadapter"))
                    .or_else(|| numbered("nat-network"))
                    .or_else(|| numbered("intnet"))
                {
                    networks.insert((key.trim_end_matches(char::is_numeric).to_owned(), slot), value.clone());
                } else if let Some(slot) = numbered("uartmode") {
                    uart_modes.insert(slot, value.clone());
                } else if let Some(slot) = numbered("uart") {
                    if !value.eq_ignore_ascii_case("off") {
                        uarts.push(slot);
                    }
                } else if let Some(n) = numbered("storagecontrollername") {
                    controller(&mut controllers, n).name = value.clone();
                } else if let Some(n) = numbered("storagecontrollertype") {
                    controller(&mut controllers, n).kind = present();
                } else if let Some(n) = numbered("storagecontrollerportcount") {
                    controller(&mut controllers, n).ports = value.trim().parse().ok();
                } else if let Some(n) = numbered("SharedFolderNameMachineMapping") {
                    folder_names.insert(n, value.clone());
                } else if let Some(n) = numbered("SharedFolderPathMachineMapping") {
                    folder_paths.insert(n, PathBuf::from(value));
                } else if key.contains("-IsEjected-") {
                    dvd_slots.push(key.replacen("IsEjected-", "", 1));
                } else if is_disk_attachment(key, value) {
                    info.disks.push(VboxDisk {
                        slot: key.clone(),
                        path: PathBuf::from(value),
                    });
                }
            }
        }
    }
    let mut nics: Vec<VboxNic> = nics.into_values().collect();
    nics.sort_by_key(|n| n.slot);
    for nic in &mut nics {
        // The name that goes with how it is attached.
        let wanted = match nic.attachment.as_str() {
            "bridged" => "bridgeadapter",
            "hostonly" => "hostonlyadapter",
            "natnetwork" => "nat-network",
            "intnet" => "intnet",
            _ => continue,
        };
        nic.network_name = networks
            .get(&(wanted.to_owned(), nic.slot))
            .filter(|n| !n.trim().is_empty())
            .cloned();
    }
    info.nics = nics;
    info.snapshots = snapshot_tree(&pairs);
    let values: HashMap<&str, &str> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    info.dvds = dvd_slots
        .into_iter()
        .filter_map(|slot| {
            let value = values.get(slot.as_str())?.trim();
            let (image, host_drive) = match value {
                "emptydrive" | "" => (None, None),
                "none" => return None,
                host if host.starts_with("host:") => (None, Some(host["host:".len()..].to_owned())),
                path => (Some(PathBuf::from(path)), None),
            };
            Some(VboxDvd {
                slot,
                image,
                host_drive,
            })
        })
        .collect();
    let mut controllers: Vec<(u32, VboxController)> = controllers.into_iter().collect();
    controllers.sort_by_key(|(n, _)| *n);
    info.controllers = controllers
        .into_iter()
        .map(|(_, c)| c)
        .filter(|c| !c.name.is_empty())
        .collect();
    uarts.sort_unstable();
    info.uarts = uarts
        .into_iter()
        .map(|slot| VboxUart {
            slot,
            mode: uart_modes
                .get(&slot)
                .cloned()
                .unwrap_or_else(|| "disconnected".to_owned()),
        })
        .collect();
    let mut folders: Vec<(u32, String)> = folder_names.into_iter().collect();
    folders.sort_by_key(|(n, _)| *n);
    info.shared_folders = folders
        .into_iter()
        .map(|(n, name)| (name, folder_paths.remove(&n).unwrap_or_default()))
        .collect();
    info
}

fn is_on(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("on")
}

fn controller(controllers: &mut HashMap<u32, VboxController>, n: u32) -> &mut VboxController {
    controllers.entry(n).or_default()
}

/// VM-23: what a VM's `.vbox` file says that `showvminfo` doesn't: its TPM type, each shared folder's flags,
/// and its sound card. A tag-by-tag read of the attributes used (no entity in them); anything else is ignored.
pub fn parse_vbox_settings_extras(xml: &str) -> VboxSettingsExtras {
    let mut extras = VboxSettingsExtras::default();
    let tags = |name: &str| {
        let open = format!("<{name}");
        let mut found = Vec::new();
        let mut rest = xml;
        while let Some(start) = rest.find(&open) {
            let after = &rest[start + open.len()..];
            if after.starts_with([' ', '\t', '\r', '\n', '/', '>']) {
                let end = after.find('>').unwrap_or(after.len());
                found.push(after[..end].to_owned());
            }
            rest = after;
        }
        found
    };
    let flag = |tag: &str, name: &str| xml_attribute(tag, name).map(|v| v.eq_ignore_ascii_case("true"));
    extras.tpm = tags("TrustedPlatformModule")
        .first()
        .and_then(|tag| xml_attribute(tag, "type"))
        .filter(|t| !t.eq_ignore_ascii_case("none"));
    for tag in tags("SharedFolder") {
        if let Some(name) = xml_attribute(&tag, "name") {
            extras
                .shared_folders
                .insert(name, (flag(&tag, "writable"), flag(&tag, "autoMount")));
        }
    }
    extras.audio_controller = tags("AudioAdapter")
        .first()
        .filter(|tag| flag(tag, "enabled") != Some(false))
        .and_then(|tag| xml_attribute(tag, "controller"));
    extras.hard_disks = attached_hard_disks(xml);
    extras
}

/// VM-24: each `<Image uuid>` inside an `<AttachedDevice type="HardDisk">`, in the machine's hardware or a
/// snapshot's, by the `location` its `<HardDisk>` has in the media registry. An image registered in another VM's
/// file has no location here and is left out.
fn attached_hard_disks(xml: &str) -> Vec<String> {
    let key = |uuid: &str| uuid.trim_matches(['{', '}']).to_ascii_lowercase();
    let mut locations: HashMap<String, String> = HashMap::new();
    let mut attached: Vec<String> = Vec::new();
    let mut hard_disk_attachment = false;
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let end = after.find('>').unwrap_or(after.len());
        let tag = &after[..end];
        let name: String = tag.chars().take_while(char::is_ascii_alphanumeric).collect();
        match name.as_str() {
            "HardDisk" => {
                if let (Some(uuid), Some(location)) = (xml_attribute(tag, "uuid"), xml_attribute(tag, "location")) {
                    locations.insert(key(&uuid), xml_unescape(&location));
                }
            }
            "AttachedDevice" => {
                hard_disk_attachment = xml_attribute(tag, "type").is_some_and(|t| t.eq_ignore_ascii_case("HardDisk"))
                    && !tag.ends_with('/');
            }
            "Image" if hard_disk_attachment => {
                if let Some(uuid) = xml_attribute(tag, "uuid") {
                    attached.push(key(&uuid));
                }
            }
            _ if tag.starts_with("/AttachedDevice") => hard_disk_attachment = false,
            _ => {}
        }
        rest = &after[end..];
    }
    let mut disks: Vec<String> = Vec::new();
    for uuid in attached {
        if let Some(location) = locations.get(&uuid) {
            if !disks.contains(location) {
                disks.push(location.clone());
            }
        }
    }
    disks
}

/// The five predefined XML entities, as VirtualBox writes them in attribute values.
fn xml_unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn nic_slot(nics: &mut HashMap<u32, VboxNic>, slot: u32) -> &mut VboxNic {
    nics.entry(slot).or_insert_with(|| VboxNic {
        slot,
        ..VboxNic::default()
    })
}

/// `"<controller>-<port>-<device>"="<image path>"` with a hard disk image's extension.
fn is_disk_attachment(key: &str, value: &str) -> bool {
    let mut parts = key.rsplitn(3, '-');
    let (Some(device), Some(port), Some(_controller)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if device.parse::<u32>().is_err() || port.parse::<u32>().is_err() || key.contains("ImageUUID") {
        return false;
    }
    Path::new(value)
        .extension()
        .is_some_and(|ext| DISK_EXTENSIONS.iter().any(|d| ext.eq_ignore_ascii_case(d)))
}

/// The snapshot keys of `showvminfo` (and `snapshot list`) in machine-readable form: the first
/// snapshot is `SnapshotName`, its children `SnapshotName-1`, `SnapshotName-2`, theirs
/// `SnapshotName-1-1`, with `SnapshotUUID…` and `SnapshotDescription…` alike, and
/// `CurrentSnapshotNode` naming the current one's key. Each gets a uid in output order.
pub fn snapshot_tree(pairs: &[(String, String)]) -> SnapshotTree {
    let mut order: Vec<String> = Vec::new();
    let mut names: HashMap<String, String> = HashMap::new();
    let mut ids: HashMap<String, String> = HashMap::new();
    let mut descriptions: HashMap<String, String> = HashMap::new();
    let mut current_node: Option<String> = None;
    for (key, value) in pairs {
        if key == "CurrentSnapshotNode" {
            current_node = value.strip_prefix("SnapshotName").map(str::to_owned);
        } else if let Some(suffix) = key.strip_prefix("SnapshotName") {
            if suffix.is_empty() || suffix.starts_with('-') {
                if !names.contains_key(suffix) {
                    order.push(suffix.to_owned());
                }
                names.insert(suffix.to_owned(), value.clone());
            }
        } else if let Some(suffix) = key.strip_prefix("SnapshotUUID") {
            ids.insert(suffix.to_owned(), value.clone());
        } else if let Some(suffix) = key.strip_prefix("SnapshotDescription") {
            descriptions.insert(suffix.to_owned(), value.clone());
        }
    }
    let uid_of: HashMap<&str, u32> = order
        .iter()
        .enumerate()
        .map(|(i, suffix)| (suffix.as_str(), u32::try_from(i + 1).unwrap_or(u32::MAX)))
        .collect();
    let snapshots = order
        .iter()
        .map(|suffix| {
            let parent = suffix.rfind('-').map(|cut| &suffix[..cut]);
            SnapshotInfo {
                uid: uid_of[suffix.as_str()],
                parent_uid: parent.and_then(|p| uid_of.get(p).copied()),
                name: names.get(suffix).cloned().unwrap_or_default(),
                description: descriptions.get(suffix).cloned().filter(|d| !d.trim().is_empty()),
                created_at: None,
                id: ids.get(suffix).and_then(|id| virtualbox_key(id)),
            }
        })
        .collect();
    SnapshotTree {
        snapshots,
        current_uid: current_node.and_then(|n| uid_of.get(n.as_str()).copied()),
    }
}

/// Each snapshot's `timeStamp` in a .vbox settings file, by snapshot UUID:
///
/// ```text
/// <Snapshot uuid="{5b1c...}" name="base" timeStamp="2026-10-18T01:59:23Z" stateFile="...">
/// ```
pub fn parse_vbox_snapshot_times(xml: &str) -> HashMap<String, OffsetDateTime> {
    let mut times = HashMap::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Snapshot") {
        let tag_rest = &rest[start + "<Snapshot".len()..];
        // `<Snapshots>` and the like are other elements.
        if !tag_rest.starts_with([' ', '\t', '\r', '\n']) {
            rest = tag_rest;
            continue;
        }
        let end = tag_rest.find('>').unwrap_or(tag_rest.len());
        let tag = &tag_rest[..end];
        let id = xml_attribute(tag, "uuid").and_then(|u| virtualbox_key(&u));
        let at = xml_attribute(tag, "timeStamp").and_then(|t| parse_vbox_time(&t));
        if let (Some(id), Some(at)) = (id, at) {
            times.insert(id, at);
        }
        rest = &tag_rest[end..];
    }
    times
}

/// The value of ` name="value"` in a start tag (no entity in the attributes read here).
fn xml_attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let tag = tag.replace(['\t', '\r', '\n'], " ");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_owned())
}

pub fn add_snapshot_times(tree: &mut SnapshotTree, times: &HashMap<String, OffsetDateTime>) {
    for snapshot in &mut tree.snapshots {
        if let Some(at) = snapshot.id.as_ref().and_then(|id| times.get(id)) {
            snapshot.created_at = Some(*at);
        }
    }
}

/// VirtualBox's times: RFC 3339, with `Z` (settings files) or without an offset (UTC, `showvminfo`).
pub fn parse_vbox_time(text: &str) -> Option<OffsetDateTime> {
    let text = text.trim();
    OffsetDateTime::parse(text, &Rfc3339)
        .or_else(|_| OffsetDateTime::parse(&format!("{text}Z"), &Rfc3339))
        .ok()
}

/// MO-01: which VM a `VirtualBoxVM.exe` or `VBoxHeadless.exe` process runs, from its command line:
/// the UUID after `--startvm`, and the name after `--comment`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxProcessVm {
    pub uuid: Option<String>,
    /// `--comment`, or a `--startvm` that names the VM rather than giving its UUID.
    pub name: Option<String>,
}

pub fn vbox_vm_from_args(args: &[String]) -> VboxProcessVm {
    let value = |option: &str| {
        args.iter().enumerate().find_map(|(i, arg)| {
            if arg.eq_ignore_ascii_case(option) {
                args.get(i + 1).cloned()
            } else {
                arg.strip_prefix(option)
                    .and_then(|rest| rest.strip_prefix('='))
                    .map(str::to_owned)
            }
        })
    };
    let start = value("--startvm");
    let uuid = start.as_deref().and_then(virtualbox_key);
    let name = value("--comment").or_else(|| start.filter(|_| uuid.is_none()));
    VboxProcessVm { uuid, name }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB01: &str = "3f0c1a2b-1111-4222-8333-444455556666";

    /// The shape VirtualBox 7 prints for a running VM with two adapters, a disk, a DVD drive and a
    /// snapshot tree: "base", its children "before upgrade" (current) and "branch", and a grandchild.
    const SHOWVMINFO: &str = r#"name="web01"
Encryption="disabled"
groups="/"
ostype="Ubuntu (64-bit)"
UUID="3f0c1a2b-1111-4222-8333-444455556666"
CfgFile="C:\\Users\\alice\\VirtualBox VMs\\web01\\web01.vbox"
SnapFldr="C:\\Users\\alice\\VirtualBox VMs\\web01\\Snapshots"
hardwareuuid="3f0c1a2b-1111-4222-8333-444455556666"
memory=4096
firmware="EFI"
pagefusion="off"
vram=16
cpus=2
VMState="running"
VMStateChangeTime="2026-10-20T08:15:00.123000000"
storagecontrollername0="SATA"
"SATA-0-0"="C:\\Users\\alice\\VirtualBox VMs\\web01\\web01.vdi"
"SATA-ImageUUID-0-0"="7a7a7a7a-0000-4000-8000-000000000001"
"SATA-1-0"="C:\\ISOs\\ubuntu-24.04.iso"
"SATA-2-0"="emptydrive"
"SATA-3-0"="none"
nic1="nat"
nictype1="82540EM"
cableconnected1="on"
nicspeed1="0"
macaddress1="080027AABB01"
nic2="hostonly"
hostonlyadapter2="VirtualBox Host-Only Ethernet Adapter"
macaddress2="080027AABB02"
nic3="none"
GuestAdditionsRunLevel=2
GuestAdditionsVersion="7.2.22 r175245"
GuestOSType="Linux26_64"
SnapshotName="base"
SnapshotUUID="5b1c0000-0000-4000-8000-000000000001"
SnapshotName-1="before upgrade"
SnapshotUUID-1="5b1c0000-0000-4000-8000-000000000002"
SnapshotDescription-1="kernel 6.8 \"stable\"
second line"
SnapshotName-1-1="grandchild"
SnapshotUUID-1-1="5b1c0000-0000-4000-8000-000000000003"
SnapshotName-2="branch"
SnapshotUUID-2="5b1c0000-0000-4000-8000-000000000004"
CurrentSnapshotName="before upgrade"
CurrentSnapshotUUID="5b1c0000-0000-4000-8000-000000000002"
CurrentSnapshotNode="SnapshotName-1"
"#;

    #[test]
    fn parses_showvminfo() {
        let info = parse_showvminfo(SHOWVMINFO);
        assert_eq!(info.name, "web01");
        assert_eq!(info.uuid, WEB01);
        assert!(info.accessible);
        assert_eq!(info.os_type.as_deref(), Some("Ubuntu (64-bit)"));
        assert_eq!(info.memory_mb, Some(4096));
        assert_eq!(info.cpus, Some(2));
        assert_eq!(info.power_state(), PowerState::Running);
        assert_eq!(
            info.config_file,
            Some(PathBuf::from(r"C:\Users\alice\VirtualBox VMs\web01\web01.vbox"))
        );
        assert_eq!(
            info.disks,
            [VboxDisk {
                slot: "SATA-0-0".into(),
                path: PathBuf::from(r"C:\Users\alice\VirtualBox VMs\web01\web01.vdi")
            }],
            "the DVD image and empty drives are not disks"
        );
        assert_eq!(info.firmware.as_deref(), Some("EFI"));
        assert_eq!(info.additions_run_level, Some(2));
        assert_eq!(info.tools_state(), Some(ToolsState::Running));
        assert_eq!(
            info.running_since(),
            Some(time::macros::datetime!(2026-10-20 08:15:00.123 UTC))
        );
        assert_eq!(
            info.nics,
            [
                VboxNic {
                    slot: 1,
                    attachment: "nat".into(),
                    mac: Some("080027AABB01".into()),
                    model: Some("82540EM".into()),
                    cable_connected: Some(true),
                    network_name: None,
                },
                VboxNic {
                    slot: 2,
                    attachment: "hostonly".into(),
                    network_name: Some("VirtualBox Host-Only Ethernet Adapter".into()),
                    mac: Some("080027AABB02".into()),
                    ..VboxNic::default()
                },
                VboxNic {
                    slot: 3,
                    attachment: "none".into(),
                    ..VboxNic::default()
                },
            ]
        );
    }

    #[test]
    fn parses_the_snapshot_tree_from_its_numbered_keys() {
        let tree = parse_showvminfo(SHOWVMINFO).snapshots;
        let summary: Vec<_> = tree
            .snapshots
            .iter()
            .map(|s| (s.uid, s.parent_uid, s.name.as_str(), s.description.as_deref()))
            .collect();
        assert_eq!(
            summary,
            [
                (1, None, "base", None),
                (2, Some(1), "before upgrade", Some("kernel 6.8 \"stable\"\nsecond line")),
                (3, Some(2), "grandchild", None),
                (4, Some(1), "branch", None),
            ]
        );
        assert_eq!(tree.current_uid, Some(2));
        assert_eq!(
            tree.snapshots[3].id.as_deref(),
            Some("5b1c0000-0000-4000-8000-000000000004")
        );
    }

    #[test]
    fn a_vm_without_snapshots_or_guest_additions_is_read_too() {
        let info = parse_showvminfo(
            "name=\"db01\"\nUUID=\"{9D1E2F3A-0000-4000-8000-0000000000AA}\"\nVMState=\"saved\"\nmemory=2048\ncpus=1\n",
        );
        assert_eq!(info.uuid, "9d1e2f3a-0000-4000-8000-0000000000aa");
        assert_eq!(info.power_state(), PowerState::Suspended);
        assert_eq!(info.tools_state(), None, "off: no Guest Additions state");
        assert!(info.snapshots.snapshots.is_empty());
        assert_eq!(info.snapshots.current_uid, None);

        let running = parse_showvminfo("name=\"db01\"\nVMState=\"running\"\n");
        assert_eq!(running.tools_state(), Some(ToolsState::NotRunning));

        let lost = parse_showvminfo(
            "name=\"<inaccessible>\"\nUUID=\"9d1e2f3a-0000-4000-8000-0000000000aa\"\naccessible=\"off\"\n",
        );
        assert!(!lost.accessible);
    }

    #[test]
    fn machine_readable_values_are_unescaped() {
        let pairs = parse_machine_readable(
            "a=\"C:\\\\x\\\\y\"\r\n\"SATA Controller-0-0\"=\"q \\\"r\\\" s\"\r\nb=12\r\nnot a pair\r\nc=\"old \\x kept\"\r\n",
        );
        assert_eq!(
            pairs,
            [
                ("a".to_owned(), r"C:\x\y".to_owned()),
                ("SATA Controller-0-0".to_owned(), "q \"r\" s".to_owned()),
                ("b".to_owned(), "12".to_owned()),
                ("c".to_owned(), r"old \x kept".to_owned()),
            ]
        );
    }

    #[test]
    fn vm_states_map_to_power_states() {
        for (state, want) in [
            ("running", PowerState::Running),
            ("stopping", PowerState::Running),
            ("saving", PowerState::Running),
            ("livesnapshotting", PowerState::Running),
            ("paused", PowerState::Paused),
            ("saved", PowerState::Suspended),
            ("aborted-saved", PowerState::Suspended),
            ("poweroff", PowerState::NotRunning),
            ("aborted", PowerState::NotRunning),
            ("restoringsnapshot", PowerState::NotRunning),
            ("something new", PowerState::Unknown),
        ] {
            assert_eq!(power_state_of(state), want, "{state}");
        }
    }

    #[test]
    fn parses_list_vms() {
        let out = "\"web01\" {3f0c1a2b-1111-4222-8333-444455556666}\r\n\"lab \"x\" db\" {9D1E2F3A-0000-4000-8000-0000000000AA}\r\n\r\ngarbage\r\n";
        assert_eq!(
            parse_list_vms(out),
            [
                VboxListedVm {
                    name: "web01".into(),
                    uuid: WEB01.into()
                },
                VboxListedVm {
                    name: "lab \"x\" db".into(),
                    uuid: "9d1e2f3a-0000-4000-8000-0000000000aa".into()
                },
            ]
        );
        assert!(parse_list_vms("").is_empty());
    }

    #[test]
    fn parses_guest_properties_in_both_formats() {
        let new =
            "/VirtualBox/GuestInfo/Net/Count      = '2' @ 2026-10-25T08:00:00.000000000Z (TRANSIENT, TRANSRESET)\r\n\
/VirtualBox/GuestInfo/Net/0/V4/IP    = '10.0.2.15' @ 2026-10-25T08:00:00.000000000Z (TRANSIENT, TRANSRESET)\r\n\
/VirtualBox/GuestInfo/OS/Product     = 'Linux' @ 2026-10-25T08:00:00.000000000Z\r\n\
/VirtualBox/GuestInfo/User/Note      = 'it's a \\ fine note'\r\n\
/VirtualBox/GuestInfo/Empty          = ''\r\n";
        let props = parse_guest_properties(new);
        let get = |props: &GuestProperties, name: &str| props.get(name).cloned();
        assert_eq!(get(&props, GUEST_NET_COUNT).as_deref(), Some("2"));
        assert_eq!(
            get(&props, "/VirtualBox/GuestInfo/Net/0/V4/IP").as_deref(),
            Some("10.0.2.15")
        );
        assert_eq!(get(&props, GUEST_OS_PRODUCT).as_deref(), Some("Linux"));
        assert_eq!(
            get(&props, "/VirtualBox/GuestInfo/User/Note").as_deref(),
            Some("it's a \\ fine note")
        );
        assert_eq!(get(&props, "/VirtualBox/GuestInfo/Empty").as_deref(), Some(""));

        let old = "Name: /VirtualBox/GuestInfo/OS/Release, value: 6.8.0-45-generic, timestamp: 1761379200000000000, flags: \r\n\
Name: /VirtualBox/GuestInfo/Net/0/MAC, value: 080027000001, timestamp: 1761379200000000000, flags: TRANSIENT\r\n";
        let props = parse_guest_properties(old);
        assert_eq!(get(&props, GUEST_OS_RELEASE).as_deref(), Some("6.8.0-45-generic"));
        assert_eq!(
            get(&props, "/VirtualBox/GuestInfo/Net/0/MAC").as_deref(),
            Some("080027000001")
        );

        assert!(parse_guest_properties("No properties found.\r\n").is_empty());
        assert!(parse_guest_properties("").is_empty());
    }

    #[test]
    fn the_guest_address_and_os_come_from_one_enumeration() {
        let props: GuestProperties = [
            (GUEST_NET_COUNT, "2"),
            ("/VirtualBox/GuestInfo/Net/0/V4/IP", "10.0.2.15"),
            ("/VirtualBox/GuestInfo/Net/0/MAC", "080027000001"),
            ("/VirtualBox/GuestInfo/Net/1/V4/IP", "192.0.2.31"),
            ("/VirtualBox/GuestInfo/Net/1/MAC", "08:00:27:00:00:02"),
            (GUEST_OS_PRODUCT, "Windows 11"),
            (GUEST_OS_RELEASE, "10.0.22631"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let nic = |slot, attachment: &str, mac: &str| VboxNic {
            slot,
            attachment: attachment.into(),
            mac: Some(mac.into()),
            ..Default::default()
        };
        let nat_and_host_only = [nic(1, "nat", "080027000001"), nic(2, "hostonly", "080027000002")];
        assert_eq!(guest_ip(&props, &nat_and_host_only).as_deref(), Some("192.0.2.31"));
        // Only NAT: its address is all there is.
        assert_eq!(
            guest_ip(&props, &[nic(1, "nat", "080027000001")]).as_deref(),
            Some("10.0.2.15")
        );
        assert_eq!(guest_os_name(&props).as_deref(), Some("Windows 11 10.0.22631"));
        assert_eq!(guest_ip(&GuestProperties::new(), &nat_and_host_only), None);
        assert_eq!(guest_os_name(&GuestProperties::new()), None);
    }

    #[test]
    fn reads_snapshot_times_from_the_vbox_file() {
        let xml = r#"<?xml version="1.0"?>
<VirtualBox xmlns="http://www.virtualbox.org/" version="1.19-windows">
  <Machine uuid="{3f0c1a2b-1111-4222-8333-444455556666}" name="web01" currentSnapshot="{5b1c0000-0000-4000-8000-000000000002}">
    <Snapshot uuid="{5B1C0000-0000-4000-8000-000000000001}" name="base" timeStamp="2026-10-18T01:59:23Z">
      <Snapshots>
        <Snapshot
          uuid="{5b1c0000-0000-4000-8000-000000000002}" name="before upgrade" timeStamp="2026-10-19T07:00:00Z" stateFile="x.sav">
          <Description>kernel</Description>
        </Snapshot>
      </Snapshots>
    </Snapshot>
  </Machine>
</VirtualBox>"#;
        let times = parse_vbox_snapshot_times(xml);
        assert_eq!(times.len(), 2);
        let mut tree = parse_showvminfo(SHOWVMINFO).snapshots;
        add_snapshot_times(&mut tree, &times);
        assert_eq!(
            tree.snapshots[0].created_at,
            Some(time::macros::datetime!(2026-10-18 01:59:23 UTC))
        );
        assert_eq!(
            tree.snapshots[1].created_at,
            Some(time::macros::datetime!(2026-10-19 07:00:00 UTC))
        );
        assert_eq!(tree.snapshots[2].created_at, None, "not in the file");
    }

    /// What VirtualBox 7.2.22 printed for the hand check's it- VM (UEFI with Secure Boot, nested
    /// virtualization, xHCI, a serial port to a file, a shared folder, a SATA disk and an empty DVD drive),
    /// with its paths and MACs changed.
    const SHOWVMINFO_72: &str = r#"name="it-r3-capture"
ostype="Ubuntu (64-bit)"
UUID="d1853388-a060-4eed-8bbe-cc2fe0ecc7e6"
CfgFile="C:\\VMs\\it-r3-capture\\it-r3-capture.vbox"
memory=1024
vram=32
firmware="EFI"
cpus=2
nested-hw-virt="on"
VMState="poweroff"
graphicscontroller="vmsvga"
monitorcount=1
accelerate3d="off"
storagecontrollername0="SATA"
storagecontrollertype0="IntelAhci"
storagecontrollerinstance0="0"
storagecontrollermaxportcount0="30"
storagecontrollerportcount0="4"
storagecontrollerbootable0="on"
"SATA-0-0"="C:\\VMs\\it-r3-capture\\disk1.vdi"
"SATA-ImageUUID-0-0"="a484220b-bbf1-4768-9502-d32e9a1eb6d2"
"SATA-hot-pluggable-0-0"="off"
"SATA-nonrotational-0-0"="off"
"SATA-discard-0-0"="off"
"SATA-1-0"="emptydrive"
"SATA-IsEjected-1-0"="off"
"SATA-2-0"="none"
natnet1="nat"
macaddress1="080027000001"
cableconnected1="on"
nic1="nat"
nictype1="virtio"
hostonlyadapter2=""
macaddress2="080027000002"
cableconnected2="off"
nic2="hostonly"
nictype2="82540EM"
nic3="none"
uart1="0x03f8,4"
uartmode1="file,C:\VMs\com1.txt"
uarttype1="16550A"
uart2="off"
audio="default"
usb="off"
ehci="off"
xhci="on"
SharedFolderNameMachineMapping1="hostshare"
SharedFolderPathMachineMapping1="C:\\Shared"
 rec_screen0
rec_screen_enabled="on"
SecureBoot="on"
"#;

    #[test]
    fn showvminfo_gives_the_settings_tab_its_devices() {
        let info = parse_showvminfo(SHOWVMINFO_72);
        assert_eq!(info.nested_hw_virt, Some(true));
        assert_eq!(info.secure_boot, Some(true));
        assert_eq!(
            (info.video_memory_mb, info.monitors, info.accelerate_3d),
            (Some(32), Some(1), Some(false))
        );
        assert_eq!(info.usb, ["USB 3.x"]);
        assert_eq!(info.audio.as_deref(), Some("default"));
        assert_eq!(
            info.controllers,
            [VboxController {
                name: "SATA".into(),
                kind: Some("IntelAhci".into()),
                ports: Some(4)
            }]
        );
        assert_eq!(info.disks.len(), 1, "flags and the empty slots are no disks");
        assert_eq!(
            info.dvds,
            [VboxDvd {
                slot: "SATA-1-0".into(),
                image: None,
                host_drive: None
            }]
        );
        assert_eq!(
            info.uarts,
            [VboxUart {
                slot: 1,
                mode: r"file,C:\VMs\com1.txt".into()
            }]
        );
        assert_eq!(
            info.shared_folders,
            [("hostshare".to_owned(), PathBuf::from(r"C:\Shared"))]
        );
        assert_eq!(info.nics[1].network_name, None, "no host-only adapter chosen");
        assert_eq!(info.nics[1].cable_connected, Some(false));
    }

    #[test]
    fn the_vbox_file_adds_the_tpm_shared_folder_flags_and_sound_card() {
        let xml = r#"<Machine uuid="{d1853388-a060-4eed-8bbe-cc2fe0ecc7e6}" name="it-r3-capture" OSType="Ubuntu_64">
      <TrustedPlatformModule type="v2_0" location=""/>
      <AudioAdapter controller="HDA" useDefault="true" driver="WAS" enabled="true"/>
      <SharedFolders>
        <SharedFolder name="hostshare" hostPath="C:\Shared" writable="false" autoMount="true"/>
      </SharedFolders>
      <SharedFoldersExtra/>"#;
        let extras = parse_vbox_settings_extras(xml);
        assert_eq!(extras.tpm.as_deref(), Some("v2_0"));
        assert_eq!(extras.audio_controller.as_deref(), Some("HDA"));
        assert_eq!(extras.shared_folders.get("hostshare"), Some(&(Some(false), Some(true))));
        assert_eq!(
            parse_vbox_settings_extras("<TrustedPlatformModule type=\"None\"/>").tpm,
            None
        );
    }

    #[test]
    fn the_disks_a_vm_uses_include_the_base_disks_its_snapshots_keep() {
        // VM-24, from VirtualBox 7.2 after a snapshot: the machine is on differencing images, the snapshot on the
        // base disks, and `unregistervm --delete` deletes all four. An image only in the registry (another VM's,
        // registered here first) and a DVD's are not the VM's disks.
        let xml = r#"<Machine uuid="{7eeedfae-8668-460f-9a40-71b160d82799}" name="it-r3-hvbox">
    <MediaRegistry>
      <HardDisks>
        <HardDisk uuid="{9fe5365d-533e-46e6-a058-8c2404a68ca9}" location="it-r3-hvbox.vdi" format="VDI" type="Normal">
          <HardDisk uuid="{157a4207-b28b-4ae2-a0b7-fc64b88eb5ae}" location="Snapshots/{157a4207-b28b-4ae2-a0b7-fc64b88eb5ae}.vdi" format="VDI"/>
        </HardDisk>
        <HardDisk uuid="{fe8e614d-c7bc-44f0-83af-ad4162cdf3d0}" location="D:\Disks\data &amp; logs.vdi" format="VDI" type="Normal"/>
        <HardDisk uuid="{0b3d1c9e-0000-4000-8000-000000000001}" location="other-vm.vdi" format="VDI" type="Normal"/>
      </HardDisks>
      <DVDImages>
        <Image uuid="{0b3d1c9e-0000-4000-8000-000000000002}" location="C:\ISOs\ubuntu.iso"/>
      </DVDImages>
    </MediaRegistry>
    <Snapshot uuid="{5ffddc23-5eea-46a8-ad71-2df104ee9506}" name="before">
      <Hardware>
        <StorageControllers>
          <StorageController name="SATA" type="AHCI" PortCount="3">
            <AttachedDevice type="HardDisk" hotpluggable="false" port="0" device="0">
              <Image uuid="{9fe5365d-533e-46e6-a058-8c2404a68ca9}"/>
            </AttachedDevice>
            <AttachedDevice passthrough="false" type="DVD" hotpluggable="false" port="1" device="0">
              <Image uuid="{0b3d1c9e-0000-4000-8000-000000000002}"/>
            </AttachedDevice>
          </StorageController>
        </StorageControllers>
      </Hardware>
    </Snapshot>
    <Hardware>
      <StorageControllers>
        <StorageController name="SATA" type="AHCI" PortCount="3">
          <AttachedDevice type="HardDisk" hotpluggable="false" port="0" device="0">
            <Image uuid="{157A4207-B28B-4AE2-A0B7-FC64B88EB5AE}"/>
          </AttachedDevice>
          <AttachedDevice passthrough="false" type="DVD" hotpluggable="false" port="1" device="0"/>
          <AttachedDevice type="HardDisk" hotpluggable="false" port="2" device="0">
            <Image uuid="{fe8e614d-c7bc-44f0-83af-ad4162cdf3d0}"/>
          </AttachedDevice>
        </StorageController>
      </StorageControllers>
    </Hardware>"#;
        assert_eq!(
            parse_vbox_settings_extras(xml).hard_disks,
            [
                "it-r3-hvbox.vdi",
                "Snapshots/{157a4207-b28b-4ae2-a0b7-fc64b88eb5ae}.vdi",
                r"D:\Disks\data & logs.vdi"
            ]
        );
    }

    #[test]
    fn os_types_read_in_both_formats() {
        let new = "Supported guest OS types:\n\nID / Description: Ubuntu_64 -- Ubuntu (64-bit)\nFamily:           Linux (Linux)\nArchitecture:     x86 (64-bit)\n\nID / Description: Windows11_64 -- Windows 11 (64-bit)\nFamily:           Windows (Microsoft Windows)\n";
        let types = parse_os_types(new);
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].id, "Ubuntu_64");
        assert_eq!(types[0].description, "Ubuntu (64-bit)");
        assert_eq!(types[1].family.as_deref(), Some("Windows"));
        let old = "ID:          Debian_64\nDescription: Debian (64-bit)\nFamily ID:   Linux\n";
        assert_eq!(parse_os_types(old)[0].description, "Debian (64-bit)");
        assert_eq!(
            change_label(&["controlvm".into(), "x".into(), "setlinkstate1".into(), "off".into()]),
            "controlvm setlinkstate1"
        );
        assert_eq!(change_label(&["sharedfolder".into(), "add".into()]), "sharedfolder add");
        assert_eq!(change_label(&["modifyvm".into()]), "modifyvm");
    }

    #[test]
    fn every_guest_address_is_listed() {
        let props: GuestProperties = [
            (GUEST_NET_COUNT, "3"),
            ("/VirtualBox/GuestInfo/Net/0/V4/IP", "10.0.2.15"),
            ("/VirtualBox/GuestInfo/Net/1/V4/IP", "192.0.2.31"),
            ("/VirtualBox/GuestInfo/Net/2/V4/IP", "0.0.0.0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(guest_ips(&props), ["10.0.2.15", "192.0.2.31"]);
    }

    #[test]
    fn errors_keep_virtualbox_own_words() {
        let stderr = "VBoxManage.exe: error: Could not find a registered machine named 'it-nope'\r\nVBoxManage.exe: error: Details: code VBOX_E_OBJECT_NOT_FOUND (0x80bb0001), component VirtualBoxWrap\r\nVBoxManage.exe: error: Context: \"FindMachine\" at line 3249\r\n";
        assert_eq!(
            error_message("", stderr),
            "Could not find a registered machine named 'it-nope'"
        );
        assert_eq!(error_message("odd output", ""), "odd output");
    }

    #[test]
    fn power_timeouts_say_virtualbox_may_be_busy() {
        let err = no_answer(CoreError::Timeout {
            command: "VBoxManage controlvm pause".into(),
            seconds: 60,
        });
        assert_eq!(err.code(), "power_timeout");
        assert!(err
            .to_string()
            .starts_with("VBoxManage controlvm pause got no answer within 60 s."));
    }

    #[test]
    fn finds_the_vm_of_a_virtualbox_process() {
        let args = |line: &str| line.split_whitespace().map(String::from).collect::<Vec<_>>();
        let gui = vbox_vm_from_args(&args(
            "VirtualBoxVM.exe --comment web01 --startvm 3F0C1A2B-1111-4222-8333-444455556666 --no-startvm-errormsgbox",
        ));
        assert_eq!(gui.uuid.as_deref(), Some(WEB01));
        assert_eq!(gui.name.as_deref(), Some("web01"));
        let headless = vbox_vm_from_args(&args("VBoxHeadless.exe --startvm=db01 --vrde config"));
        assert_eq!(
            headless,
            VboxProcessVm {
                uuid: None,
                name: Some("db01".into())
            }
        );
        assert_eq!(vbox_vm_from_args(&args("VirtualBoxVM.exe")), VboxProcessVm::default());
    }

    #[test]
    fn vboxmanage_path_must_name_vboxmanage_exe() {
        let err = validate_vboxmanage_path(Path::new(r"C:\Windows\System32\notepad.exe")).unwrap_err();
        assert!(matches!(err, CoreError::InvalidSetting(_)));
        let missing = validate_vboxmanage_path(Path::new(r"C:\does-not-exist\VBoxManage.exe")).unwrap_err();
        assert!(matches!(missing, CoreError::InvalidSetting(_)));
    }

    #[test]
    fn snapshot_changes_need_a_snapshot_to_act_on_and_a_new_name_to_take() {
        let info = parse_showvminfo(SHOWVMINFO);
        let take = |name: &str| SnapshotOp::Take { name: name.into() };
        assert!(check_snapshot_op(&info, &take("new one")).is_ok());
        assert!(
            check_snapshot_op(&info, &take("base")).is_err(),
            "VirtualBox would make a twin"
        );
        let revert = |name: &str| SnapshotOp::Revert { name: name.into() };
        assert!(check_snapshot_op(&info, &revert("branch")).is_ok());
        assert!(check_snapshot_op(&info, &revert("{5B1C0000-0000-4000-8000-000000000003}")).is_ok());
        assert!(check_snapshot_op(&info, &SnapshotOp::Delete { name: "gone".into() }).is_err());
    }
}
