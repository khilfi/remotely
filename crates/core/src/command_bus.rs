//! Command bus: the one way in for changes.
//!
//! The UI (and later the CLI, plugins and AI helper, FD-12/FD-13) submit a [`Command`] here. The bus
//! resolves the targets, asks the [`PolicyEngine`] for a tier, collects approval answers when the tier
//! needs them (AP-02, AP-03, AP-06), writes the audit log (AP-05) and hands the work to the
//! [`JobRunner`]. Nothing else can enqueue a job, so approvals and audit cannot be skipped.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::containers::{EngineKind, ImageRef, PruneWhat};
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::remote::forward::ForwardKind;
use crate::capacity::CapacityChecker;
use crate::domain::{now_rfc3339, ContainerHost, Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::forwards::PortForward;
use crate::host_networks::{ops as net_ops, HostNetworkOp};
use crate::impact::{ImpactPreviewer, TargetImpact};
use crate::jobs::{JobRunner, JobSpec, TargetStatus};
use crate::linked_clones::Blocked;
use crate::locks;
use crate::policy::{ActionKind, ApprovalStep, DangerousMatch, Decision, PolicyEngine, PolicyRules, Tier};
use crate::presentation::Change;
use crate::snapshots::{is_safety_name, SAFETY_PREFIX};
use crate::ssh_keys;
use crate::store::{NewAuditEntry, Store};
use crate::terminal::multiexec::{self, RunKey};
use crate::vault::{Destination, SecretBindings, SecretId, SecretKind, SecretString, Vault};
use crate::vm_settings::{ops as vm_ops, VmChangePreview, VmConfigEdit, VmDeviceOp, VmDiskOp, VmLifecycleOp};

// VM-14, VM-27: schedules are approved when they are saved; each run submits under that standing approval.
mod change_id;
pub use change_id::{clean_change_id, ChangeIdRules, CHANGE_ID_KEY, MAX_CHANGE_ID_CHARS};
mod standing;
pub use standing::{StandingAsk, StandingDetails, StandingDraft, StandingGrant, StandingRun, StandingUse};

/// A state-changing request. Reads (inventory, metrics) do not go through the bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Command {
    /// VM-02 bulk power actions; VM-03 soft-then-hard stop is two commands.
    VmPower { targets: Vec<TargetRef>, op: PowerOp },
    /// VM-04 bulk snapshot take, revert and delete.
    VmSnapshot { targets: Vec<TargetRef>, op: SnapshotOp },
    /// AP-04 mark VMs "do not touch" (`protected: true`) or unlock them. Other actions skip
    /// protected targets; this one is the way to change that, so it never skips them.
    VmProtect { targets: Vec<TargetRef>, protected: bool },
    /// BX-02 run a command or script on many hosts; BX-07 with sudo from the vault.
    RemoteExec {
        targets: Vec<TargetRef>,
        script: String,
        #[serde(default)]
        sudo: bool,
        /// BX-07: the vault password sudo gets. `None`: each session's own login password.
        #[serde(default)]
        sudo_password_id: Option<SecretId>,
        /// SS-05 for bulk runs: trust (and save, audited) the key of a host never seen before. A bulk
        /// run can't ask; without this such a host fails. A changed key always blocks.
        #[serde(default)]
        trust_new_host_keys: bool,
        /// Seconds each host may take; one that takes longer ends with its outcome unknown (H9: the
        /// command may still run there). `None`: no limit.
        #[serde(default)]
        timeout_secs: Option<u64>,
        /// H9: how far the run spreads before the user sees a result: one host first, and a stop after
        /// failures. Both off unless asked.
        #[serde(default)]
        rollout: Rollout,
    },
    /// FD-14 install a checked, signed update. Runs once no other job is open.
    AppUpdate { version: String },
    /// SS-09 add a public key to `~/.ssh/authorized_keys` on many hosts, unless it is there already
    /// (see [`ssh_keys::authorized_keys_script`]).
    PushSshKey {
        targets: Vec<TargetRef>,
        /// The public key in OpenSSH's one-line form. Checked, and written to the hosts in Remotely's
        /// own form, never as typed.
        public_key: String,
        /// As for [`Command::RemoteExec`]: a run can't ask about a host key it has not seen.
        #[serde(default)]
        trust_new_host_keys: bool,
        #[serde(default)]
        timeout_secs: Option<u64>,
        /// SS-09: restrictions written before the key (`expiry-time`, `from`).
        #[serde(default)]
        options: ssh_keys::KeyOptions,
    },
    /// SS-09 remove a public key from `~/.ssh/authorized_keys` on many hosts: every line holding its
    /// data (see [`ssh_keys::remove_key_script`]).
    RemoveSshKey {
        targets: Vec<TargetRef>,
        /// The public key in OpenSSH's one-line form; only its data is looked for.
        public_key: String,
        #[serde(default)]
        trust_new_host_keys: bool,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// SS-10 MultiExec: Enter on a line typed into several open terminals at once
    /// ([`crate::terminal::multiexec`]). The line's keys went to each terminal as they were typed; Enter
    /// was held so the policy engine could rate the line first, and this command sends it.
    TerminalLine {
        /// [`TargetRef::Terminal`]s.
        targets: Vec<TargetRef>,
        /// What was typed, as far as Remotely could follow it; several lines for a paste of several.
        line: String,
        /// Keys were typed that Remotely can't follow (Tab completion, arrow keys, history, Ctrl+R) or
        /// text was on the line before MultiExec, so the shell may run something else: the line counts
        /// as at least "other", never Low.
        #[serde(default)]
        unreliable: bool,
        /// What each terminal gets: the held key that runs the line (Enter, Ctrl+O, Esc then Enter...:
        /// [`RunKey`]), and after an Enter, for a paste of several lines, the lines after the first,
        /// each with its Enter. The bus takes nothing else ([`crate::terminal::multiexec::check_keys`]).
        keys: String,
    },
    /// SS-08 upload files into a folder on the host of one open terminal, over SFTP on that terminal's
    /// own connection ([`crate::terminal::files`]). A file already there is replaced only when its
    /// `replace` says so, and the policy engine rates that higher. Never built by the UI: the shell
    /// builds it from files chosen in a dialog or dropped on the terminal.
    FileUpload {
        /// One [`TargetRef::Terminal`].
        targets: Vec<TargetRef>,
        /// The host folder, absolute.
        folder: String,
        files: Vec<UploadFile>,
    },
    /// SS-07 open a saved port forward on one open terminal's connection
    /// ([`crate::terminal::tunnels`]): it listens until it is stopped or the terminal closes, and
    /// opens again by itself after a reconnect. Never built by the UI: the terminal builds it from
    /// the session's saved forward, when its terminal connects or the user starts it.
    OpenTunnel {
        /// One [`TargetRef::Terminal`].
        targets: Vec<TargetRef>,
        /// The forward as saved when it was asked for: what is approved is what opens.
        forward: PortForward,
    },
    /// CT-01, CT-02: start, stop, restart, pause, unpause or remove containers, remove images or volumes,
    /// pull an image or prune, on container hosts ([`crate::containers`]). Every target is a
    /// [`TargetRef::Container`] whose object fits the op: containers for the container ops, images,
    /// volumes, or the engine itself for a pull or a prune (one per host).
    Container { targets: Vec<TargetRef>, op: ContainerOp },
    /// VM-23, VM-12, VM-11: settings of powered-off VMs (CPU, memory, firmware, network adapters, shared
    /// folders, name, guest OS type), or a Workstation VM's hardware version ([`crate::vm_settings`]).
    VmConfig {
        targets: Vec<TargetRef>,
        edit: VmConfigEdit,
    },
    /// VM-23, VM-11, VM-15: CD/DVD images, network cables and the guest tools, on running VMs too.
    VmDevice { targets: Vec<TargetRef>, op: VmDeviceOp },
    /// VM-16: virtual disks of powered-off VMs.
    VmDisk { targets: Vec<TargetRef>, op: VmDiskOp },
    /// VM-24: deleting VMs, and adding an existing one.
    VmLifecycle { targets: Vec<TargetRef>, op: VmLifecycleOp },
    /// VM-11: add or remove a NAT port forward on a Workstation vmnet or a VirtualBox NAT network
    /// ([`TargetRef::Network`]), or on a VirtualBox VM's NAT adapter ([`TargetRef::Vm`]); one target
    /// ([`crate::host_networks`]).
    HostNetwork { targets: Vec<TargetRef>, op: HostNetworkOp },
    /// VM-21, VM-22, VM-10: make new VMs, from a launch template or the Deploy dialog's own values (a clone of a
    /// golden VM, a cloud image with cloud-init, an ISO install or an OVA/OVF import), or clones of the VMs
    /// picked on the VMs page. Every target is one of the spec's [`TargetRef::NewVm`]s. Never built by the UI:
    /// the deploy service ([`crate::deploy`]) builds it from the catalogue, so what is approved is what was
    /// resolved there.
    Deploy {
        targets: Vec<TargetRef>,
        spec: Box<crate::deploy::DeploySpec>,
    },
    /// VM-08: a stack instance: deployed (each step's VMs made by the deploy runner, step by step in boot order,
    /// with the stack's readiness checks and delays between steps), started, shut down or suspended in boot order
    /// (the power commands' own work and tiers), or torn down (R3's delete on each of its VMs, Critical). Never
    /// built by the UI: the stacks service ([`crate::stacks`]) builds it from the stack or the instance.
    Stack {
        targets: Vec<TargetRef>,
        op: crate::stacks::StackOp,
    },
    /// CV-03: convert a disk image into a new one on this PC. The one target is the new image
    /// ([`TargetRef::DiskImage`]). Never built by the UI: the conversion service builds it from the file the user
    /// picked and the place the shell's save dialog chose.
    ImageConvert {
        targets: Vec<TargetRef>,
        spec: Box<crate::convert::spec::ConvertSpec>,
    },
    /// VM-17, CV-02: export a powered-off VM for another hypervisor into a new folder. The one target is the VM.
    /// Never built by the UI: the folder comes from the shell's folder dialog.
    VmExport {
        targets: Vec<TargetRef>,
        spec: Box<crate::convert::spec::ExportSpec>,
    },
    /// FD-04: collect the same commands' output and files from many hosts (saved sessions) into one zip
    /// ([`crate::support_bundle`]). Its commands are rated as a Compare hosts run's. Never built by the UI: the zip's
    /// place comes from the shell's save dialog.
    SupportBundle {
        targets: Vec<TargetRef>,
        spec: Box<crate::support_bundle::BundleSpec>,
    },
}

/// CT-01, CT-02: what a [`Command::Container`] does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ContainerOp {
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    /// `force`: a running container is killed first (`rm -f`).
    Remove {
        #[serde(default)]
        force: bool,
    },
    RemoveImage,
    /// Deletes the volume and every file in it.
    RemoveVolume,
    /// Pulls an image reference, checked against the reference grammar.
    Pull {
        reference: String,
    },
    Prune {
        what: PruneWhat,
    },
}

impl ContainerOp {
    /// "Start", "Remove the volume"... for messages.
    pub fn label(&self) -> &'static str {
        match self {
            ContainerOp::Start => "Start",
            ContainerOp::Stop => "Stop",
            ContainerOp::Restart => "Restart",
            ContainerOp::Pause => "Pause",
            ContainerOp::Unpause => "Unpause",
            ContainerOp::Remove { force: false } => "Remove",
            ContainerOp::Remove { force: true } => "Force-remove",
            ContainerOp::RemoveImage => "Remove the image",
            ContainerOp::RemoveVolume => "Remove the volume",
            ContainerOp::Pull { .. } => "Pull",
            ContainerOp::Prune { .. } => "Prune",
        }
    }

    /// What its targets are: `container`, `image`, `volume` or `engine` ([`crate::domain::ContainerObject::kind`]).
    pub fn object_kind(&self) -> &'static str {
        match self {
            ContainerOp::Start
            | ContainerOp::Stop
            | ContainerOp::Restart
            | ContainerOp::Pause
            | ContainerOp::Unpause
            | ContainerOp::Remove { .. } => "container",
            ContainerOp::RemoveImage => "image",
            ContainerOp::RemoveVolume => "volume",
            ContainerOp::Pull { .. } | ContainerOp::Prune { .. } => "engine",
        }
    }
}

/// CT-01, CT-02: every target a container object of the kind the op acts on, each once; this PC only
/// with Docker; an image reference that passes the grammar.
fn validate_container(targets: &[TargetRef], op: &ContainerOp) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    let wanted = op.object_kind();
    let mut keys = std::collections::HashSet::new();
    for target in targets {
        let TargetRef::Container { host, engine, object } = target else {
            return invalid(
                "Container actions go to containers, images, volumes or engines on container hosts.".into(),
            );
        };
        if object.kind() != wanted {
            return invalid(format!("{} acts on {wanted}s, not on a {}.", op.label(), object.kind()));
        }
        if *host == ContainerHost::ThisPc && *engine != EngineKind::Docker {
            return invalid("Only Docker Desktop runs on this PC.".into());
        }
        if *engine == EngineKind::Podman
            && *op
                == (ContainerOp::Prune {
                    what: PruneWhat::BuildCache,
                })
        {
            return invalid(
                "Podman keeps no build cache of its own: its build layers are images (prune those).".into(),
            );
        }
        if !keys.insert(target.key()) {
            return invalid("A target is listed twice.".into());
        }
    }
    if let ContainerOp::Pull { reference } = op {
        ImageRef::parse(reference)?;
    }
    Ok(())
}

/// SS-08: one file of a [`Command::FileUpload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadFile {
    /// The file on this PC.
    pub local_path: String,
    /// Its name in the host folder.
    pub name: String,
    pub size: u64,
    /// A file of that name is there, and this upload replaces it.
    #[serde(default)]
    pub replace: bool,
}

/// SS-08: the most files one upload takes.
pub const MAX_UPLOAD_FILES: usize = 1000;

/// The one target of commands that act on the app itself.
const APP_TARGET: &[TargetRef] = &[TargetRef::App];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PowerOp {
    Start {
        /// Open a console window (vmrun `gui`) instead of running headless (`nogui`).
        #[serde(default)]
        gui: bool,
    },
    Stop {
        mode: StopMode,
    },
    Reset {
        mode: StopMode,
    },
    Suspend,
    Pause,
    Unpause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StopMode {
    /// Ask the guest OS to shut down (needs VMware Tools).
    Soft,
    /// Power off immediately. Critical tier (VM-03).
    Hard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SnapshotOp {
    Take {
        name: String,
    },
    /// `name` may be vmrun's path form (`base/child`) when the VM has two snapshots with that name.
    Revert {
        name: String,
    },
    /// Deletes that one snapshot; its children stay and move up to its parent.
    Delete {
        name: String,
    },
}

/// Longest snapshot name the app takes (VM-04).
pub const MAX_SNAPSHOT_NAME: usize = 120;
/// BX-02: the longest script a bulk run takes.
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
/// BX-02: the longest per-host time limit, a day.
pub const MAX_EXEC_TIMEOUT_SECS: u64 = 24 * 60 * 60;

impl SnapshotOp {
    pub fn name(&self) -> &str {
        match self {
            SnapshotOp::Take { name } | SnapshotOp::Revert { name } | SnapshotOp::Delete { name } => name,
        }
    }

    /// VM-04: a name the hypervisors will take and the snapshot manager can find again. vmrun reads
    /// `/` as a path, so a new name for any VMware target can't hold one (VM-18: VBoxManage takes it).
    fn validate(&self, targets: &[TargetRef]) -> Result<()> {
        let name = self.name();
        let invalid = |message: String| Err(CoreError::InvalidInput(message));
        if name.trim().is_empty() {
            return invalid("Give the snapshot a name.".into());
        }
        if name.chars().any(char::is_control) {
            return invalid("A snapshot name can't hold line breaks or tabs.".into());
        }
        if name.chars().count() > MAX_SNAPSHOT_NAME {
            return invalid(format!(
                "A snapshot name can be at most {MAX_SNAPSHOT_NAME} characters."
            ));
        }
        if let SnapshotOp::Take { name } = self {
            if name.trim() != name {
                return invalid("A snapshot name can't start or end with a space.".into());
            }
            let vmware = targets
                .iter()
                .any(|t| matches!(t, TargetRef::Vm { vmx_path } if Hypervisor::of_key(vmx_path) == Hypervisor::Vmware));
            if vmware && name.contains('/') {
                return invalid(
                    "A snapshot name can't contain '/': vmrun reads it as the path to a child snapshot.".into(),
                );
            }
            // VM-05: the prefix marks Remotely's own safety snapshots.
            if is_safety_name(name) {
                return invalid(format!(
                    "Names starting with '{SAFETY_PREFIX}' are kept for safety snapshots."
                ));
            }
        }
        Ok(())
    }
}

/// SS-10: a MultiExec line: something to run (an empty line only when the shell may hold more than
/// Remotely saw, e.g. a command recalled from its history), and keys that send exactly that: the key
/// that runs it, and after Enter only the later lines of a paste, which `line` holds.
fn validate_line(line: &str, keys: &str, unreliable: bool) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    if !unreliable && line.trim().is_empty() {
        return invalid("The line is empty.".into());
    }
    if line.len() > MAX_SCRIPT_BYTES || keys.len() > MAX_SCRIPT_BYTES {
        return invalid(format!("A line can be at most {} KB.", MAX_SCRIPT_BYTES / 1024));
    }
    multiexec::check_keys(line, keys.as_bytes(), unreliable).map_err(CoreError::InvalidInput)
}

/// SS-10: the key a MultiExec line runs with, when it is not Enter.
fn run_key(keys: &str) -> Option<RunKey> {
    RunKey::parse(keys.as_bytes())
        .map(|(key, _)| key)
        .filter(|key| !key.is_enter())
}

/// SS-08: an upload Remotely can carry out: one open terminal, an absolute host folder, plain file
/// names (no folder parts) once each, and files on this PC given by their full path.
fn validate_upload(targets: &[TargetRef], folder: &str, files: &[UploadFile]) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    match targets {
        [TargetRef::Terminal { .. }] => {}
        [_] => return invalid("Files are uploaded through an open terminal.".into()),
        _ => return invalid("Files are uploaded to one terminal at a time.".into()),
    }
    if !folder.starts_with('/') || folder.contains(['\0', '\n', '\r']) {
        return invalid(format!(
            "'{folder}' is not a folder on the host (it must start with /)."
        ));
    }
    if files.is_empty() {
        return invalid("Choose at least one file to upload.".into());
    }
    if files.len() > MAX_UPLOAD_FILES {
        return invalid(format!("One upload takes at most {MAX_UPLOAD_FILES} files."));
    }
    let mut names = std::collections::HashSet::new();
    for file in files {
        let name = file.name.as_str();
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0', '\n', '\r']) {
            return invalid(format!("'{name}' can't be a file name on the host."));
        }
        if !names.insert(name) {
            return invalid(format!("Two files are named '{name}'; upload them one at a time."));
        }
        if !std::path::Path::new(&file.local_path).is_absolute() {
            return invalid(format!("'{}' is not a full path on this PC.", file.local_path));
        }
    }
    Ok(())
}

/// SS-07: a tunnel rides one open terminal's connection.
fn validate_tunnel(targets: &[TargetRef]) -> Result<()> {
    match targets {
        [TargetRef::Terminal { .. }] => Ok(()),
        [_] => Err(CoreError::InvalidInput(
            "A tunnel opens on an open terminal's connection.".into(),
        )),
        _ => Err(CoreError::InvalidInput(
            "A tunnel opens on one terminal at a time.".into(),
        )),
    }
}

/// VM-18: a VirtualBox VM target.
fn is_virtualbox(target: &Target) -> bool {
    matches!(&target.target, TargetRef::Vm { vmx_path } if Hypervisor::of_key(vmx_path) == Hypervisor::VirtualBox)
}

/// VM-18: the VirtualBox targets of a revert that are running (or paused) now, which VirtualBox can
/// only restore once they are powered off.
fn virtualbox_revert_warnings(targets: &[Target], impact: &[TargetImpact]) -> Vec<String> {
    let names: Vec<&str> = targets
        .iter()
        .filter(|t| is_virtualbox(t))
        .filter(|t| {
            impact
                .iter()
                .any(|i| i.target == t.target.key() && i.power_state.is_on())
        })
        .map(|t| t.name.as_str())
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    vec![format!(
        "VirtualBox restores a snapshot only on a VM that is not running, so Remotely powers off {} first, without shutting the guest down.",
        names.join(", ")
    )]
}

/// "1.2 MB", for summaries and messages.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} B"),
        _ if value < 10.0 => format!("{value:.1} {}", UNITS[unit]),
        _ => format!("{value:.0} {}", UNITS[unit]),
    }
}

/// BX-02: a script the hosts' shells can take.
fn validate_script(script: &str, timeout_secs: Option<u64>) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    if script.trim().is_empty() {
        return invalid("Type a command or script to run.".into());
    }
    if script.len() > MAX_SCRIPT_BYTES {
        return invalid(format!("A script can be at most {} KB.", MAX_SCRIPT_BYTES / 1024));
    }
    if script.contains('\0') {
        return invalid("A script can't hold NUL characters.".into());
    }
    validate_timeout(timeout_secs)
}

/// H9: the most failures a run may be told to stop after.
pub const MAX_STOP_AFTER_FAILURES: u32 = 1000;

/// H9: a bulk run's blast-radius controls (BX-01, BX-02).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Rollout {
    /// A canary: the first host runs alone, and the others wait until the user, who sees its result,
    /// says to go on ([`CommandBus::go_on`]); a canary that fails stops the run. With one host it
    /// changes nothing.
    pub canary: bool,
    /// Start no more hosts once this many failed or ended with their outcome unknown; the hosts
    /// already running finish. `None`: off.
    pub stop_after_failures: Option<u32>,
}

impl Rollout {
    pub(crate) fn validate(&self) -> Result<()> {
        match self.stop_after_failures {
            Some(n) if !(1..=MAX_STOP_AFTER_FAILURES).contains(&n) => Err(CoreError::InvalidInput(format!(
                "Stop after 1 to {MAX_STOP_AFTER_FAILURES} failures, or turn the stop off."
            ))),
            _ => Ok(()),
        }
    }

    /// For the job's start in the audit log; `None` when both are off.
    pub fn describe(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.canary {
            parts.push("one host first, then the rest once confirmed".to_owned());
        }
        match self.stop_after_failures {
            Some(1) => parts.push("stops after the first failure".to_owned()),
            Some(n) => parts.push(format!("stops after {n} failures")),
            None => {}
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// BX-02: a per-host time limit within bounds.
pub(crate) fn validate_timeout(timeout_secs: Option<u64>) -> Result<()> {
    if let Some(secs) = timeout_secs {
        if !(1..=MAX_EXEC_TIMEOUT_SECS).contains(&secs) {
            return Err(CoreError::InvalidInput(format!(
                "The time limit must be 1 to {MAX_EXEC_TIMEOUT_SECS} seconds (a day)."
            )));
        }
    }
    Ok(())
}

impl Command {
    /// Refuses the commands only Remotely itself builds, never the UI (or anything else that can call
    /// IPC): an upload names files on this PC (SS-08: `files_upload` builds it from a dialog or a drop),
    /// a tunnel opens a saved forward (SS-07: the terminal builds it), and a MultiExec line sends keys
    /// that only MultiExec held and rated (SS-10).
    pub fn check_from_ui(&self) -> Result<()> {
        let refused = match self {
            Command::FileUpload { .. } => "Uploads start from a terminal: its upload button, or files dropped on it.",
            Command::OpenTunnel { .. } => {
                "Tunnels start from a terminal's Tunnels panel, from the session's saved port forwards."
            }
            Command::TerminalLine { .. } => {
                "MultiExec lines start from what is typed into a terminal with MultiExec on, which holds and rates them."
            }
            // VM-21: the paths and values a deploy uses come from the catalogue.
            Command::Deploy { .. } => "Deploys start from the Deploy dialog, a launch template or Clone on the VMs page.",
            // VM-08: a stack's steps, an instance's VMs and their order come from the stacks the core keeps.
            Command::Stack { .. } => "Stacks deploy, start, stop and tear down from the Stacks tab or the VMs page.",
            // VM-23, VM-24: a file or folder of this PC the guest (or the VM list) gets comes from a dialog or a
            // drop in the shell, never from the UI: an attached file or a shared folder is the guest's to read.
            Command::VmDevice {
                op: VmDeviceOp::AttachIso { .. },
                ..
            } => "ISO images are attached from a file dialog or dropped on a VM.",
            Command::VmConfig {
                edit: VmConfigEdit::AddSharedFolder { .. },
                ..
            } => "Shared folders are chosen in a folder dialog.",
            Command::VmLifecycle {
                op: VmLifecycleOp::Register { .. },
                ..
            } => "An existing VM is added from a file dialog.",
            // CV-03, VM-17: the new files' place comes from a save or folder dialog.
            Command::ImageConvert { .. } => "Conversions start from Image tools, which asks where the new image goes.",
            Command::VmExport { .. } => "Exports start from a VM's Export, which asks for the folder.",
            // FD-04: the zip's place comes from a save dialog.
            Command::SupportBundle { .. } => {
                "Support bundles start from the support bundle dialog, which asks where to save the zip."
            }
            _ => return Ok(()),
        };
        Err(CoreError::InvalidInput(refused.into()))
    }

    /// Checks what the caller typed, before any target is looked up.
    pub fn validate(&self) -> Result<()> {
        match self {
            Command::VmSnapshot { op, targets } => op.validate(targets),
            Command::RemoteExec {
                script,
                timeout_secs,
                rollout,
                ..
            } => {
                rollout.validate()?;
                validate_script(script, *timeout_secs)
            }
            Command::PushSshKey {
                public_key,
                timeout_secs,
                options,
                ..
            } => {
                ssh_keys::parse_public_key(public_key)?;
                options.validate(time::OffsetDateTime::now_utc().date())?;
                validate_timeout(*timeout_secs)
            }
            Command::RemoveSshKey {
                public_key,
                timeout_secs,
                ..
            } => {
                ssh_keys::parse_public_key(public_key)?;
                validate_timeout(*timeout_secs)
            }
            Command::TerminalLine {
                targets,
                line,
                keys,
                unreliable,
            } => {
                if targets.iter().any(|t| !matches!(t, TargetRef::Terminal { .. })) {
                    return Err(CoreError::InvalidInput(
                        "A MultiExec line goes to open terminals only.".into(),
                    ));
                }
                validate_line(line, keys, *unreliable)
            }
            Command::FileUpload { targets, folder, files } => validate_upload(targets, folder, files),
            Command::OpenTunnel { targets, .. } => validate_tunnel(targets),
            Command::Container { targets, op } => validate_container(targets, op),
            Command::Deploy { targets, spec } => {
                spec.validate()?;
                if *targets != spec.targets() {
                    return Err(CoreError::InvalidInput(
                        "A deploy's targets are the VMs it makes.".into(),
                    ));
                }
                Ok(())
            }
            Command::ImageConvert { targets, spec } => {
                spec.validate()?;
                if *targets != spec.targets() {
                    return Err(CoreError::InvalidInput(
                        "A conversion's target is the image it makes.".into(),
                    ));
                }
                Ok(())
            }
            Command::VmExport { targets, spec } => {
                spec.validate()?;
                if *targets != spec.targets() {
                    return Err(CoreError::InvalidInput("An export's target is its VM.".into()));
                }
                Ok(())
            }
            Command::VmConfig { targets, edit } => vm_ops::validate_config(targets, edit),
            Command::VmDevice { targets, op } => vm_ops::validate_device(targets, op),
            Command::VmDisk { targets, op } => vm_ops::validate_disk(targets, op),
            Command::VmLifecycle { targets, op } => vm_ops::validate_lifecycle(targets, op),
            Command::Stack { targets, op } => op.validate(targets),
            Command::HostNetwork { targets, op } => net_ops::validate(targets, op),
            Command::SupportBundle { targets, spec } => spec.validate(targets),
            _ => Ok(()),
        }
    }

    /// BX-06: the shell text the policy engine rates: a run's script, a MultiExec line, a support bundle's commands
    /// (FD-04), one per line. `None` for the rest.
    pub fn rated_script(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Command::RemoteExec { script, .. } => Some(script.as_str().into()),
            Command::TerminalLine { line, .. } => Some(line.as_str().into()),
            Command::SupportBundle { spec, .. } => Some(spec.rated_script().into()),
            _ => None,
        }
    }

    /// BX-07: the vault password sudo gets, when the command runs with sudo and one was chosen (a run's or a support
    /// bundle's). `None`: no sudo, or each session's own login password.
    pub fn sudo_password_id(&self) -> Option<SecretId> {
        match self {
            Command::RemoteExec {
                sudo: true,
                sudo_password_id,
                ..
            } => *sudo_password_id,
            Command::SupportBundle { spec, .. } if spec.sudo => spec.sudo_password_id,
            _ => None,
        }
    }

    /// The same command on other targets (BX-04 retry). `None` for commands with a fixed target.
    pub fn with_targets(&self, new: Vec<TargetRef>) -> Option<Command> {
        let mut command = self.clone();
        match &mut command {
            Command::VmPower { targets, .. }
            | Command::VmSnapshot { targets, .. }
            | Command::VmProtect { targets, .. }
            | Command::RemoteExec { targets, .. }
            | Command::PushSshKey { targets, .. }
            | Command::RemoveSshKey { targets, .. }
            | Command::FileUpload { targets, .. }
            | Command::Container { targets, .. }
            | Command::VmConfig { targets, .. }
            | Command::VmDevice { targets, .. }
            | Command::VmDisk { targets, .. }
            | Command::VmLifecycle {
                targets,
                op: VmLifecycleOp::Delete,
            } => *targets = new,
            // VM-21: the VMs that failed, made again with the labels the deploy gives them.
            Command::Deploy { targets, spec } => {
                **spec = spec.only(&new);
                *targets = spec.targets();
            }
            // VM-08: the instance's VMs that failed or never started, in their steps and order.
            Command::Stack { targets, op } => {
                *op = op.only(&new);
                *targets = op.targets().unwrap_or(new);
            }
            // CV-03, VM-17: one target, the same file or VM; a failed job left nothing behind, so it runs again as asked.
            Command::ImageConvert { targets, .. } | Command::VmExport { targets, .. } => {
                if *targets != new {
                    return None;
                }
            }
            // SS-10: a line belongs to the moment it was typed; pressing Enter again later could run it
            // after something else. SS-07: a tunnel belongs to its terminal. VM-24: an added VM is its file.
            // VM-11: a forward belongs to its network or VM.
            // FD-04: a bundle belongs to its zip; the hosts that failed go into a new one, with its own save dialog.
            Command::AppUpdate { .. }
            | Command::TerminalLine { .. }
            | Command::OpenTunnel { .. }
            | Command::HostNetwork { .. }
            | Command::SupportBundle { .. }
            | Command::VmLifecycle {
                op: VmLifecycleOp::Register { .. },
                ..
            } => return None,
        }
        Some(command)
    }

    pub fn targets(&self) -> &[TargetRef] {
        match self {
            Command::VmPower { targets, .. }
            | Command::VmSnapshot { targets, .. }
            | Command::VmProtect { targets, .. }
            | Command::RemoteExec { targets, .. }
            | Command::PushSshKey { targets, .. }
            | Command::RemoveSshKey { targets, .. }
            | Command::TerminalLine { targets, .. }
            | Command::FileUpload { targets, .. }
            | Command::OpenTunnel { targets, .. }
            | Command::Container { targets, .. }
            | Command::VmConfig { targets, .. }
            | Command::VmDevice { targets, .. }
            | Command::VmDisk { targets, .. }
            | Command::VmLifecycle { targets, .. }
            | Command::Deploy { targets, .. }
            | Command::HostNetwork { targets, .. }
            | Command::Stack { targets, .. } => targets,
            Command::ImageConvert { targets, .. }
            | Command::VmExport { targets, .. }
            | Command::SupportBundle { targets, .. } => targets,
            Command::AppUpdate { .. } => APP_TARGET,
        }
    }

    /// The command's type as the journal names it (serde's `type` tag): `remoteExec`, `terminalLine`...
    pub fn type_name(&self) -> &'static str {
        match self {
            Command::VmPower { .. } => "vmPower",
            Command::VmSnapshot { .. } => "vmSnapshot",
            Command::VmProtect { .. } => "vmProtect",
            Command::RemoteExec { .. } => "remoteExec",
            Command::AppUpdate { .. } => "appUpdate",
            Command::PushSshKey { .. } => "pushSshKey",
            Command::RemoveSshKey { .. } => "removeSshKey",
            Command::TerminalLine { .. } => "terminalLine",
            Command::FileUpload { .. } => "fileUpload",
            Command::OpenTunnel { .. } => "openTunnel",
            Command::Container { .. } => "container",
            Command::Deploy { .. } => "deploy",
            Command::VmConfig { .. } => "vmConfig",
            Command::VmDevice { .. } => "vmDevice",
            Command::VmDisk { .. } => "vmDisk",
            Command::VmLifecycle { .. } => "vmLifecycle",
            Command::Stack { .. } => "stack",
            Command::HostNetwork { .. } => "hostNetwork",
            Command::ImageConvert { .. } => "imageConvert",
            Command::VmExport { .. } => "vmExport",
            Command::SupportBundle { .. } => "supportBundle",
        }
    }

    /// BX-02, SS-10: the command as the job journal keeps it. What looks like a secret in a script or a typed line
    /// (`--password=...`, a token, a password in a URL) is `[redacted]`, as in the audit export
    /// ([`redact_secrets`]). Returns whether anything was. The job itself runs the command as it was given.
    pub fn for_journal(&self) -> (Command, bool) {
        fn clean(text: &mut String) -> bool {
            let (redacted, changed) = redact_secrets(text);
            if changed {
                *text = redacted;
            }
            changed
        }
        let mut kept = self.clone();
        let changed = match &mut kept {
            Command::RemoteExec { script, .. } => clean(script),
            // The keys hold a paste's later lines too.
            Command::TerminalLine { line, keys, .. } => clean(line) | clean(keys),
            // FD-04: every command of a bundle.
            Command::SupportBundle { spec, .. } => {
                let (redacted, changed) = spec.for_journal();
                **spec = redacted;
                changed
            }
            _ => false,
        };
        (kept, changed)
    }

    /// Short human summary for dialogs, job lists and the audit log.
    pub fn summary(&self, target_count: usize) -> String {
        let noun = |kind: &str| {
            if target_count == 1 {
                format!("1 {kind}")
            } else {
                format!("{target_count} {kind}s")
            }
        };
        match self {
            Command::VmPower { op, .. } => {
                let verb = match op {
                    PowerOp::Start { .. } => "Start",
                    PowerOp::Stop { mode: StopMode::Soft } => "Shut down",
                    PowerOp::Stop { mode: StopMode::Hard } => "Power off (hard)",
                    PowerOp::Reset { mode: StopMode::Soft } => "Restart",
                    PowerOp::Reset { mode: StopMode::Hard } => "Reset (hard)",
                    PowerOp::Suspend => "Suspend",
                    PowerOp::Pause => "Pause",
                    PowerOp::Unpause => "Unpause",
                };
                format!("{verb} {}", noun("VM"))
            }
            Command::VmSnapshot { op, .. } => match op {
                SnapshotOp::Take { name } => format!("Take snapshot '{name}' on {}", noun("VM")),
                SnapshotOp::Revert { name } => format!("Revert {} to '{name}'", noun("VM")),
                SnapshotOp::Delete { name } => format!("Delete snapshot '{name}' on {}", noun("VM")),
            },
            Command::VmProtect { protected: true, .. } => format!("Protect {}", noun("VM")),
            Command::VmProtect { protected: false, .. } => format!("Unprotect {}", noun("VM")),
            Command::RemoteExec { script, sudo, .. } => {
                // The summary is stored in the audit log for good: no secret typed into a command.
                let (first_line, _) = redact_secrets(script.lines().next().unwrap_or_default());
                let sudo = if *sudo { "sudo " } else { "" };
                format!("Run `{sudo}{first_line}` on {}", noun("host"))
            }
            Command::AppUpdate { version } => format!("Install update {version}"),
            Command::PushSshKey {
                public_key, options, ..
            } => {
                let with = options.describe().map(|o| format!(" ({o})")).unwrap_or_default();
                match ssh_keys::parse_public_key(public_key) {
                    Ok(key) => format!("Add the SSH key {}{with} to {}", key.describe(), noun("host")),
                    Err(_) => format!("Add an SSH key{with} to {}", noun("host")),
                }
            }
            Command::RemoveSshKey { public_key, .. } => match ssh_keys::parse_public_key(public_key) {
                Ok(key) => format!("Remove the SSH key {} from {}", key.describe(), noun("host")),
                Err(_) => format!("Remove an SSH key from {}", noun("host")),
            },
            Command::TerminalLine { line, keys, .. } => {
                // Kept in the audit log for good, like a bulk run's summary: no secret typed into it.
                let mut lines = line.lines().filter(|l| !l.trim().is_empty());
                let (first, _) = redact_secrets(lines.next().unwrap_or_default().trim());
                let more = match lines.count() {
                    0 => String::new(),
                    1 => " (and 1 more line)".to_owned(),
                    n => format!(" (and {n} more lines)"),
                };
                // SS-10: a line run with another key than Enter says which.
                let key = run_key(keys);
                if first.is_empty() {
                    // A line recalled from the shell's history: Remotely saw only Enter.
                    let key = key.map_or("Enter", RunKey::label);
                    format!("MultiExec: press {key} in {}", noun("terminal"))
                } else {
                    let with = key.map_or_else(String::new, |key| format!(" with {}", key.label()));
                    format!("MultiExec: run `{first}`{more}{with} in {}", noun("terminal"))
                }
            }
            Command::FileUpload { folder, files, .. } => {
                let size = human_size(files.iter().map(|f| f.size).sum());
                let what = match files.as_slice() {
                    [one] => format!("'{}' ({size})", one.name),
                    several => format!("{} files ({size})", several.len()),
                };
                let replaced = files.iter().filter(|f| f.replace).count();
                let replacing = match (replaced, files.len()) {
                    (0, _) => String::new(),
                    (1, 1) => ", replacing the file there".to_owned(),
                    (1, _) => ", replacing 1 file there".to_owned(),
                    (n, _) => format!(", replacing {n} files there"),
                };
                format!("Upload {what} to {folder}{replacing}")
            }
            Command::OpenTunnel { forward, .. } => format!("Open a tunnel: {}", forward.describe()),
            Command::Container { op, .. } => match op {
                ContainerOp::Pull { reference } => {
                    let reference =
                        ImageRef::parse(reference).map_or_else(|_| "an image".to_owned(), |r| r.to_string());
                    format!("Pull {reference} on {}", noun("host"))
                }
                ContainerOp::Prune { what } => format!("Prune {} on {}", what.label(), noun("host")),
                ContainerOp::RemoveImage => format!("Remove {}", noun("image")),
                ContainerOp::RemoveVolume => {
                    let what = if target_count == 1 { "its" } else { "their" };
                    format!("Remove {} and {what} data", noun("volume"))
                }
                other => format!("{} {}", other.label(), noun("container")),
            },
            Command::Deploy { spec, .. } => spec.summary(),
            Command::VmConfig { edit, .. } => edit.summary(target_count),
            Command::VmDevice { op, .. } => op.summary(target_count),
            Command::VmDisk { op, .. } => op.summary(target_count),
            Command::VmLifecycle { op, .. } => op.summary(target_count),
            Command::Stack { op, .. } => op.summary(target_count),
            Command::HostNetwork { targets, op } => op.summary(targets),
            Command::ImageConvert { spec, .. } => spec.summary(),
            Command::VmExport { spec, .. } => spec.summary(),
            Command::SupportBundle { spec, .. } => spec.summary(target_count),
        }
    }
}

/// Looks targets up in the inventory so the policy engine knows their labels.
#[async_trait]
pub trait TargetDirectory: Send + Sync {
    async fn resolve(&self, ctx: &Context, target: &TargetRef) -> Result<Target>;
}

/// What happened to a submitted command.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SubmitOutcome {
    /// Low tier: logged and queued straight away. `skipped` are protected targets left alone (AP-04).
    Queued {
        job_id: Uuid,
        tier: Tier,
        summary: String,
        skipped: Vec<Target>,
    },
    /// Medium and above: collect the answers for `steps`, then call [`CommandBus::approve`].
    NeedsApproval { request: ApprovalRequest },
}

/// Everything the UI needs to draw the approval dialog and impact preview (AP-02).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub action: ActionKind,
    pub tier: Tier,
    pub summary: String,
    pub steps: Vec<ApprovalStep>,
    pub targets: Vec<Target>,
    pub skipped: Vec<Target>,
    pub reasons: Vec<String>,
    /// Problems to read before approving, e.g. the capacity check before a power-on (VM-07).
    pub warnings: Vec<String>,
    /// AP-02: each VM target's state, uptime and snapshot count right now.
    pub impact: Vec<TargetImpact>,
    /// BX-02, BX-06, BX-07: for a remote command, what will run and how.
    pub exec: Option<Box<ExecDetails>>,
    /// SS-08: for an upload, the folder and the files (which ones replace a file there).
    pub upload: Option<Box<UploadDetails>>,
    /// SS-07: for a tunnel, where it listens, where it leads and who can use it.
    pub tunnel: Option<Box<TunnelDetails>>,
    /// VM-21: for a deploy, each VM it makes, where, and the disk space it may take (AP-02).
    pub deploy: Option<Box<crate::deploy::preview::DeployPreview>>,
    /// VM-23, VM-24: for a VM settings or lifecycle change, what changes on each VM, every file that is
    /// deleted, and why a VM would be refused.
    pub vm_change: Option<Box<VmChangePreview>>,
    /// VM-08: for a stack command, the instance and its steps in the order they run (a deploy's with each
    /// step's deploy preview, a teardown's with the VMs it keeps).
    pub stack: Option<Box<crate::stacks::StackDetails>>,
    /// VM-26: for a deploy, RAM, CPU and disk on this PC after it, next to now.
    pub capacity: Option<Box<crate::capacity_plan::DeployCapacity>>,
    /// VM-14, VM-27: for a schedule's approval, when it runs and what each run does.
    pub standing: Option<Box<StandingDetails>>,
    /// FD-04: for a support bundle, the files each host gives and where the zip goes (its commands are in `exec`).
    pub bundle: Option<Box<BundleDetails>>,
}

/// FD-04: a support bundle as the approval dialog shows it, besides its commands.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleDetails {
    /// The presets' names.
    pub presets: Vec<String>,
    /// Files read over SFTP as the login user.
    pub files: Vec<String>,
    /// Where the zip is saved.
    pub output: String,
    pub limits: crate::support_bundle::BundleLimits,
}

impl BundleDetails {
    fn of(command: &Command) -> Option<Box<Self>> {
        let Command::SupportBundle { spec, .. } = command else {
            return None;
        };
        Some(Box::new(Self {
            presets: spec
                .presets
                .iter()
                .map(|id| crate::support_bundle::presets::preset(*id).label.to_owned())
                .collect(),
            files: spec.files().map(str::to_owned).collect(),
            output: spec.output.clone(),
            limits: crate::support_bundle::LIMITS,
        }))
    }
}

/// What [`CommandBus`] read about the targets before asking (AP-02).
#[derive(Default)]
struct Previews {
    impact: Option<Vec<TargetImpact>>,
    vm_change: Option<VmChangePreview>,
    stack: Option<crate::stacks::StackDetails>,
    capacity: Option<crate::capacity_plan::DeployCapacity>,
    /// VM-04, VM-21, VM-24: the VM targets a snapshot or VM delete must not touch, for linked clones.
    linked_clones: Vec<Blocked>,
}

/// SS-07: a tunnel as the approval dialog shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelDetails {
    pub forward: PortForward,
    /// Where it listens, e.g. `127.0.0.1:8080`, or `localhost:9000 on the host`.
    pub listens: String,
    /// Where its connections go.
    pub leads: String,
    /// Who can use it, in words.
    pub exposes: String,
}

impl TunnelDetails {
    fn of(command: &Command) -> Option<Box<Self>> {
        let Command::OpenTunnel { forward, .. } = command else {
            return None;
        };
        let spec = &forward.spec;
        let (listens, leads, exposes) = match spec.kind {
            ForwardKind::Local | ForwardKind::Dynamic => {
                let leads = match spec.kind {
                    ForwardKind::Dynamic => "wherever each program that uses it asks, reached from the host".to_owned(),
                    _ => format!("{}, reached from the host", spec.destination()),
                };
                let exposes = if spec.loopback_only() {
                    // Loopback is per computer, not per user.
                    match spec.kind {
                        ForwardKind::Dynamic => "Programs on this PC can use it to reach anything the host reaches: every user signed in to this PC, not only you.".to_owned(),
                        _ => "Programs on this PC can use it: every user signed in to this PC, not only you.".to_owned(),
                    }
                } else {
                    format!(
                        "It listens on {}, so other computers that can reach this PC can use it to reach what the host reaches, without logging in.",
                        spec.bind_address
                    )
                };
                (spec.listen_address(), leads, exposes)
            }
            ForwardKind::Remote => {
                let exposes = if spec.loopback_only() {
                    // sshd ignores the address asked for when its GatewayPorts is yes.
                    format!(
                        "Programs on the host can reach {} through it, as if they were on this PC. If the host's SSH server has GatewayPorts yes, it listens on every address there instead, so other computers that reach the host can use it too.",
                        spec.destination()
                    )
                } else {
                    format!(
                        "The host listens on {}, so other computers that reach the host can reach {} through it, as if they were on this PC.",
                        spec.bind_address,
                        spec.destination()
                    )
                };
                (
                    format!("{} on the host", spec.listen_address()),
                    format!("{}, reached from this PC", spec.destination()),
                    exposes,
                )
            }
        };
        Some(Box::new(Self {
            forward: forward.clone(),
            listens,
            leads,
            exposes,
        }))
    }
}

/// SS-08: an upload as the approval dialog shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadDetails {
    pub folder: String,
    pub files: Vec<UploadFileDetails>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadFileDetails {
    pub name: String,
    pub size: u64,
    pub replace: bool,
}

impl UploadDetails {
    fn of(command: &Command) -> Option<Box<Self>> {
        let Command::FileUpload { folder, files, .. } = command else {
            return None;
        };
        Some(Box::new(Self {
            folder: folder.clone(),
            files: files
                .iter()
                .map(|f| UploadFileDetails {
                    name: f.name.clone(),
                    size: f.size,
                    replace: f.replace,
                })
                .collect(),
        }))
    }
}

/// A remote command as the approval dialog and the bulk run editor show it (BX-02, BX-06, BX-07).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecDetails {
    /// The whole script, as typed.
    pub script: String,
    pub sudo: bool,
    /// The vault item sudo gets, by label. `None` with sudo: each session's login password.
    pub sudo_password_label: Option<String>,
    pub trust_new_host_keys: bool,
    pub timeout_secs: Option<u64>,
    /// BX-06: the dangerous-command rules the script matched, and what matched.
    pub dangerous: Vec<DangerousMatch>,
    /// BX-04: the job whose failed hosts this one retries.
    pub retry_of: Option<Uuid>,
    /// SS-10: a line typed into open terminals (MultiExec): Enter is sent once approved.
    pub multi_exec: bool,
    /// SS-10: the line was edited with keys Remotely can't follow, so the terminals may run something
    /// other than `script`.
    pub unreliable: bool,
    /// SS-10: the key that runs the line when it is not Enter ("Ctrl+O", "Esc then A"...: [`RunKey::label`]).
    pub run_key: Option<String>,
    /// H9: one host first, and a stop after failures.
    pub rollout: Rollout,
}

/// What a command would need, without submitting it (BX-06: the bulk run editor shows the tier and
/// the matched rules before anything runs). A read: nothing is audited or queued.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandPreview {
    pub action: ActionKind,
    pub tier: Tier,
    pub steps: Vec<ApprovalStep>,
    /// Targets it would run on (protected ones left out).
    pub targets: usize,
    pub skipped: Vec<Target>,
    pub reasons: Vec<String>,
    pub dangerous: Vec<DangerousMatch>,
}

/// The user's answers to the approval steps (AP-03, AP-06).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalAnswers {
    #[serde(default)]
    pub confirmed: bool,
    pub typed_target_count: Option<usize>,
    pub reason: Option<String>,
    /// Overrides the safety snapshot default (VM-05). `None` keeps the default.
    pub safety_snapshot: Option<bool>,
    /// Only for Critical. Checked against the vault, never stored or logged.
    pub vault_password: Option<SecretString>,
    /// AP-08: the ticket or change number, for High and Critical (ignored below). Cleaned and redacted
    /// ([`clean_change_id`]) before it is kept.
    #[serde(default)]
    pub change_id: Option<String>,
}

/// What gets journaled with the job and written to the audit log. No secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    pub request_id: Uuid,
    pub tier: Tier,
    pub typed_target_count: Option<usize>,
    pub reason: Option<String>,
    pub safety_snapshot: bool,
    pub vault_reauth: bool,
    pub approved_at: String,
    /// VM-14, VM-27: a scheduled run's job: the standing approval it runs under, and which run it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standing: Option<StandingUse>,
    /// AP-08: the ticket or change number given with a High or Critical approval (a schedule's runs carry the one
    /// given when it was approved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
}

/// AP-01: how long an approval waits for its answer. After that the targets' state, labels and protection
/// the dialog showed may be out of date, so the request expires and the action has to be started again.
pub const APPROVAL_TTL: Duration = Duration::from_secs(15 * 60);

struct Pending {
    ctx: Context,
    command: Command,
    decision: Decision,
    request: ApprovalRequest,
    retry_of: Option<Uuid>,
    /// When it was asked (or asked again), for [`APPROVAL_TTL`].
    asked: Instant,
    /// VM-14, VM-27: a schedule's approval, answered with [`CommandBus::approve_standing`].
    standing: Option<Box<StandingDraft>>,
}

impl Pending {
    fn expired(&self, ttl: Duration) -> bool {
        self.asked.elapsed() > ttl
    }
}

pub struct CommandBus {
    /// Shared with the command panel (BX-08), which shows how each saved command classifies.
    policy: Arc<RwLock<PolicyEngine>>,
    directory: Arc<dyn TargetDirectory>,
    jobs: Arc<JobRunner>,
    store: Store,
    vault: Arc<dyn Vault>,
    capacity: CapacityChecker,
    impact: ImpactPreviewer,
    pending: Mutex<HashMap<Uuid, Pending>>,
    /// [`APPROVAL_TTL`]; tests shorten it.
    approval_ttl: RwLock<Duration>,
    /// SS-04, AP-06: where vault passwords already go (BX-07's sudo password), shared with the rest of the
    /// core once it is put together.
    bindings: OnceLock<SecretBindings>,
}

impl CommandBus {
    pub fn new(
        policy: PolicyEngine,
        directory: Arc<dyn TargetDirectory>,
        jobs: Arc<JobRunner>,
        store: Store,
        vault: Arc<dyn Vault>,
        capacity: CapacityChecker,
        impact: ImpactPreviewer,
    ) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            directory,
            jobs,
            store,
            vault,
            capacity,
            impact,
            pending: Mutex::new(HashMap::new()),
            approval_ttl: RwLock::new(APPROVAL_TTL),
            bindings: OnceLock::new(),
        }
    }

    /// SS-04, AP-06: the core's checks of where vault passwords go.
    pub fn set_bindings(&self, bindings: SecretBindings) {
        let _ = self.bindings.set(bindings);
    }

    fn bindings(&self) -> SecretBindings {
        self.bindings
            .get()
            .cloned()
            .unwrap_or_else(|| SecretBindings::new(self.store.clone(), Arc::clone(&self.vault)))
    }

    /// SS-04, AP-06 (BX-07): the sessions among `targets` that sudo would give the vault password
    /// `secret` to for the first time: no saved session at their host logs in with it, gives it to sudo
    /// or was allowed to use it.
    async fn new_sudo_places(
        &self,
        ctx: &Context,
        secret: SecretId,
        targets: &[Target],
    ) -> Result<Vec<(Uuid, String)>> {
        let bindings = self.bindings();
        let mut new = Vec::new();
        for target in targets {
            let TargetRef::Session { session_id } = target.target else {
                continue;
            };
            let Some(spec) = self.store.session_spec(ctx, session_id).await? else {
                continue;
            };
            let place = Destination::new(&spec.host, spec.port, spec.jump.as_ref().map(|j| j.id));
            if bindings.sent_by(ctx, session_id).await?.contains(&secret)
                || bindings.goes_to(ctx, secret, &place, None).await?
            {
                continue;
            }
            new.push((session_id, target.name.clone()));
        }
        Ok(new)
    }

    /// SS-04, AP-06: a run whose sudo would send a vault password to hosts that don't get it yet asks for
    /// the vault password in its approval (one confirm and the password, even for a Low command), and
    /// says so. Approved, those sessions may use it from now on.
    async fn ask_for_sudo_places(&self, ctx: &Context, command: &Command, decision: &mut Decision) -> Result<()> {
        let Some(secret) = command.sudo_password_id() else {
            return Ok(());
        };
        let new = self.new_sudo_places(ctx, secret, &decision.targets).await?;
        if new.is_empty() {
            return Ok(());
        }
        let what = self.bindings().describe(ctx, secret).await?;
        let names: Vec<String> = new.iter().take(5).map(|(_, name)| format!("'{name}'")).collect();
        let more = new.len().saturating_sub(names.len());
        let names = if more > 0 {
            format!("{} and {more} more", names.join(", "))
        } else {
            names.join(", ")
        };
        decision.add_warnings(vec![format!(
            "sudo would get the {what} on {names}, where no saved session sends it yet. Approving asks for the vault password, and lets them use it from now on"
        )]);
        if !decision.steps.contains(&ApprovalStep::VaultReauth) {
            decision.steps.push(ApprovalStep::VaultReauth);
        }
        Ok(())
    }

    /// SS-04, AP-06 (VM-21): an unattended install gives a vault password to new VMs, which no saved session reaches
    /// yet, so the approval asks for the vault password, and says so.
    async fn ask_for_guest_password(&self, ctx: &Context, command: &Command, decision: &mut Decision) -> Result<()> {
        let Command::Deploy { spec, .. } = command else {
            return Ok(());
        };
        let Some(unattended) = &spec.unattended else {
            return Ok(());
        };
        let what = self.bindings().describe(ctx, unattended.password_id).await?;
        let vms = match spec.vms.len() {
            1 => "the new VM".to_owned(),
            n => format!("{n} new VMs"),
        };
        decision.add_warnings(vec![format!(
            "VirtualBox's unattended install gives the {what} to {vms} (user {}), and writes it into their install files in each VM's folder. Approving asks for the vault password",
            unattended.user
        )]);
        if !decision.steps.contains(&ApprovalStep::VaultReauth) {
            decision.steps.push(ApprovalStep::VaultReauth);
        }
        Ok(())
    }

    /// SS-04, AP-06: after an approval that asked for the vault password, the sessions the run's sudo
    /// password was new to may use it from now on (audited `vault_secret_allowed`).
    async fn allow_sudo_places(&self, ctx: &Context, command: &Command, targets: &[Target]) -> Result<()> {
        let Some(secret) = command.sudo_password_id() else {
            return Ok(());
        };
        let bindings = self.bindings();
        for (session_id, name) in self.new_sudo_places(ctx, secret, targets).await? {
            bindings
                .allow(ctx, session_id, &name, secret, crate::vault::bindings::ASKED_NOW)
                .await?;
        }
        Ok(())
    }

    /// AP-08: whether the decision's change ID is required, by the workspace's rule (Prod targets).
    pub(crate) async fn apply_change_id_rule(&self, ctx: &Context, decision: &mut Decision) -> Result<()> {
        if !decision
            .steps
            .iter()
            .any(|s| matches!(s, ApprovalStep::ChangeId { .. }))
        {
            return Ok(());
        }
        let required = ChangeIdRules::load(&self.store, ctx).await?.requires(&decision.targets);
        for step in &mut decision.steps {
            if let ApprovalStep::ChangeId { required: r } = step {
                *r = required;
            }
        }
        Ok(())
    }

    /// AP-08: the workspace's change ID rule.
    pub async fn change_id_rules(&self, ctx: &Context) -> Result<ChangeIdRules> {
        ChangeIdRules::load(&self.store, ctx).await
    }

    /// AP-08: makes a change ID required, or optional again, for High and Critical actions on the workspace's Prod
    /// targets. A setting of the workspace (FD-02), audited there; refused by the read-only lock. Approvals asked
    /// from now on follow it.
    pub async fn set_change_id_rules(&self, ctx: &Context, rules: ChangeIdRules) -> Result<ChangeIdRules> {
        self.store.read_only().check(Change::Settings)?;
        if ChangeIdRules::load(&self.store, ctx).await? == rules {
            return Ok(rules);
        }
        self.store.put_setting(ctx, CHANGE_ID_KEY, &rules).await?;
        let detail = if rules.required_for_prod {
            "a change ID is required for High and Critical actions on Prod targets"
        } else {
            "a change ID is optional"
        };
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action: "Set the change ID rule",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await?;
        Ok(rules)
    }

    /// AP-01: how long approvals wait (tests shorten it). Applies to the ones open now too.
    pub fn set_approval_ttl(&self, ttl: Duration) {
        *locks::write(&self.approval_ttl) = ttl;
    }

    fn approval_ttl(&self) -> Duration {
        *locks::read(&self.approval_ttl)
    }

    /// The ids of the approvals waiting for an answer now (QL-15: the window that asked them went away).
    pub fn pending_approvals(&self) -> Vec<Uuid> {
        locks::lock(&self.pending).keys().copied().collect()
    }

    /// AP-01: drops the approvals that waited too long, each audited as expired. A failing audit write is
    /// logged; the approval is gone all the same.
    async fn expire_stale(&self) {
        let ttl = self.approval_ttl();
        let expired: Vec<Pending> = {
            let mut pending = locks::lock(&self.pending);
            let ids: Vec<Uuid> = pending
                .iter()
                .filter(|(_, p)| p.expired(ttl))
                .map(|(id, _)| *id)
                .collect();
            ids.iter().filter_map(|id| pending.remove(id)).collect()
        };
        for p in expired {
            self.audit_expired(&p, ttl).await;
        }
    }

    async fn audit_expired(&self, p: &Pending, ttl: Duration) {
        let detail = format!(
            "not answered within {}; nothing ran",
            crate::error::in_minutes(ttl.as_secs().div_ceil(60))
        );
        let written = self
            .store
            .append_audit(
                &p.ctx,
                NewAuditEntry {
                    event: "approval_expired",
                    action: &p.request.summary,
                    tier: Some(p.decision.tier),
                    job_id: None,
                    targets: &p.decision.targets,
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await;
        if let Err(err) = written {
            tracing::error!(error = %err, "could not audit an approval expiring");
        }
    }

    /// QL-15: cancels these approvals if they still wait (audited like a closed dialog, saying why), when the window
    /// that would answer them has gone. Returns how many were cancelled.
    pub async fn cancel_approvals(&self, ids: &[Uuid], why: &str) -> usize {
        let all: Vec<Pending> = {
            let mut pending = locks::lock(&self.pending);
            ids.iter().filter_map(|id| pending.remove(id)).collect()
        };
        for p in &all {
            let written = self
                .store
                .append_audit(
                    &p.ctx,
                    NewAuditEntry {
                        event: "approval_cancelled",
                        action: &p.request.summary,
                        tier: Some(p.decision.tier),
                        job_id: None,
                        targets: &p.decision.targets,
                        approval: None,
                        result: None,
                        detail: Some(why),
                    },
                )
                .await;
            if let Err(err) = written {
                tracing::error!(error = %err, "could not audit an approval being cancelled");
            }
        }
        all.len()
    }

    pub fn rules(&self) -> PolicyRules {
        locks::read(&self.policy).rules().clone()
    }

    /// FD-03: presentation mode's read-only lock, which refuses every command here while it is on.
    pub fn read_only(&self) -> &crate::presentation::ReadOnlyLock {
        self.store.read_only()
    }

    /// The engine itself, for readers that classify without submitting (BX-08's command panel).
    pub(crate) fn policy(&self) -> Arc<RwLock<PolicyEngine>> {
        Arc::clone(&self.policy)
    }

    /// AP-01: tier rules are editable. Invalid rules are rejected with the reason and the old ones
    /// stay. A change is saved, applies to the next command, and is audited with what changed;
    /// returns those changes (none: nothing saved or logged). Approvals already open keep the steps
    /// they were asked with.
    pub async fn set_rules(&self, ctx: &Context, rules: PolicyRules) -> Result<Vec<String>> {
        self.set_rules_with(ctx, rules, None).await
    }

    /// [`Self::set_rules`], with the vault password: AP-06 asks for it before any change that loosens
    /// the rules (a lower tier, the Prod rule off, a dangerous-command rule removed or changed, a new
    /// read-only command, a higher bulk threshold, a shorter countdown, safety snapshots off by
    /// default), so whoever sits at an unlocked PC can't wave risky actions through. Tightening never asks.
    pub async fn set_rules_with(
        &self,
        ctx: &Context,
        rules: PolicyRules,
        vault_password: Option<&SecretString>,
    ) -> Result<Vec<String>> {
        self.store.read_only().check(Change::ApprovalRules)?;
        let rules = rules.normalized();
        let engine = PolicyEngine::new(rules.clone())?;
        let before = self.rules();
        let changes = before.changes(&rules);
        if changes.is_empty() {
            return Ok(changes);
        }
        let loosened = before.loosened(&rules);
        let mut asked = None;
        if !loosened.is_empty() {
            let shown: Vec<&str> = loosened.iter().take(3).map(String::as_str).collect();
            let more = loosened.len().saturating_sub(shown.len());
            let reason = if more > 0 {
                format!(
                    "This loosens the approval rules ({}, and {more} more)",
                    shown.join("; ")
                )
            } else {
                format!("This loosens the approval rules ({})", shown.join("; "))
            };
            asked = Some(
                self.bindings()
                    .confirm(ctx, vault_password, "Failed to change the approval rules", &reason)
                    .await?,
            );
        }
        self.store
            .put_setting(ctx, crate::store::POLICY_RULES_KEY, &rules)
            .await?;
        *locks::write(&self.policy) = engine;
        let mut detail = changes.join("; ");
        if let Some(how) = asked {
            detail.push_str(&format!("; looser, so {how}"));
        }
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action: "Changed the approval rules",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        Ok(changes)
    }

    pub async fn submit(&self, ctx: &Context, command: Command) -> Result<SubmitOutcome> {
        self.submit_job(ctx, command, None).await
    }

    /// H9: the user saw the canary host's result and says to run on the other hosts. The run was
    /// approved for all of them; this only lets the rest start. Refused while the read-only lock is
    /// on (FD-03), and audited by the job runner. False when the job is not waiting.
    pub async fn go_on(&self, ctx: &Context, job_id: Uuid) -> Result<bool> {
        crate::policy::read_only_refusal(self.store.read_only().is_locked(), ActionKind::ExecOther)?;
        Ok(self.jobs.go_on(ctx, job_id))
    }

    /// BX-04: runs the same command again on the targets that failed in `job_id`, as a new job that
    /// points back at it. It goes through the policy engine like any command, so its tier and approval
    /// steps are decided again for the targets it has now. H9: targets whose outcome is unknown (they
    /// timed out, or were cancelled while the command ran, so it may have run) are left out unless
    /// `include_unknown` says otherwise: running them again may run the command twice.
    pub async fn retry_failed(&self, ctx: &Context, job_id: Uuid, include_unknown: bool) -> Result<SubmitOutcome> {
        let (job, command) = self
            .store
            .job_detail(ctx, job_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("job {job_id}")))?;
        if job.is_open() {
            return Err(CoreError::InvalidInput(
                "That job is still running. Retry its failed targets once it has ended.".into(),
            ));
        }
        // BX-02: what the journal no longer holds can't run again as it ran.
        if job.bodies_removed && matches!(command, Command::RemoteExec { .. }) {
            return Err(CoreError::InvalidInput(
                "That run's script was removed from the journal when it got older than the retention period (Settings, General), so it can't be retried. Run it again from Compare.".into(),
            ));
        }
        if job.command_redacted {
            return Err(CoreError::InvalidInput(
                "That run's script had something that looked like a secret, which the journal doesn't keep, so it can't be retried as it ran. Run it again from Compare.".into(),
            ));
        }
        let targets = self.store.job_targets(ctx, job_id).await?;
        let unknown = targets
            .iter()
            .filter(|t| t.status == TargetStatus::Unknown.as_str())
            .count();
        // VM-08: a stack's steps that never started (an earlier step failed or wasn't ready) go again with the
        // ones that failed: they never ran.
        let stack = matches!(command, Command::Stack { .. });
        let failed: Vec<TargetRef> = targets
            .iter()
            .filter(|t| {
                t.status == TargetStatus::Failed.as_str()
                    || (include_unknown && t.status == TargetStatus::Unknown.as_str())
                    || (stack && t.status == TargetStatus::Skipped.as_str())
            })
            .filter_map(|t| t.target_ref())
            .collect();
        if failed.is_empty() {
            let message = if unknown > 0 {
                format!(
                    "No target failed in that job. {unknown} ended with their outcome unknown (the command may have run there); retry them only on purpose."
                )
            } else {
                "No target failed in that job.".to_owned()
            };
            return Err(CoreError::InvalidInput(message));
        }
        let retry = command
            .with_targets(failed)
            .ok_or_else(|| CoreError::InvalidInput("That job can't be retried.".into()))?;
        self.submit_job(ctx, retry, Some(job_id)).await
    }

    /// BX-06: the tier, steps and matched dangerous-command rules the command would get now. Targets
    /// may be empty while the user is still choosing them.
    pub async fn preview(&self, ctx: &Context, command: &Command) -> Result<CommandPreview> {
        let targets = self.resolve_targets(ctx, command).await?;
        self.note_signed_in(command).await;
        let (mut decision, dangerous) = {
            let policy = locks::read(&self.policy);
            let decision = policy.evaluate(command, &targets);
            let dangerous = command
                .rated_script()
                .map(|script| policy.dangerous_details(&script))
                .unwrap_or_default();
            (decision, dangerous)
        };
        self.apply_change_id_rule(ctx, &mut decision).await?;
        Ok(CommandPreview {
            action: decision.action,
            tier: decision.tier,
            steps: decision.steps,
            targets: decision.targets.len(),
            skipped: decision.skipped,
            reasons: decision.reasons,
            dangerous,
        })
    }

    /// For a remote command: what the approval dialog shows about it.
    async fn exec_details(
        &self,
        ctx: &Context,
        command: &Command,
        retry_of: Option<Uuid>,
    ) -> Result<Option<Box<ExecDetails>>> {
        let key_script = match command {
            Command::PushSshKey {
                public_key,
                trust_new_host_keys,
                timeout_secs,
                options,
                ..
            } => Some((
                ssh_keys::authorized_keys_script(&ssh_keys::parse_public_key(public_key)?, options),
                trust_new_host_keys,
                timeout_secs,
            )),
            Command::RemoveSshKey {
                public_key,
                trust_new_host_keys,
                timeout_secs,
                ..
            } => Some((
                ssh_keys::remove_key_script(&ssh_keys::parse_public_key(public_key)?),
                trust_new_host_keys,
                timeout_secs,
            )),
            _ => None,
        };
        if let Some((script, trust_new_host_keys, timeout_secs)) = key_script {
            // SS-09: the dialog shows the script each host runs.
            return Ok(Some(Box::new(ExecDetails {
                script,
                sudo: false,
                sudo_password_label: None,
                trust_new_host_keys: *trust_new_host_keys,
                timeout_secs: *timeout_secs,
                dangerous: Vec::new(),
                retry_of,
                multi_exec: false,
                unreliable: false,
                run_key: None,
                rollout: Rollout::default(),
            })));
        }
        if let Command::TerminalLine {
            line, unreliable, keys, ..
        } = command
        {
            return Ok(Some(Box::new(ExecDetails {
                script: line.clone(),
                sudo: false,
                sudo_password_label: None,
                trust_new_host_keys: false,
                timeout_secs: None,
                dangerous: locks::read(&self.policy).dangerous_details(line),
                retry_of: None,
                multi_exec: true,
                unreliable: *unreliable,
                run_key: run_key(keys).map(|key| key.label().to_owned()),
                rollout: Rollout::default(),
            })));
        }
        // FD-04: a bundle's commands, one per line, run on each host like a run's script.
        let (script, sudo, trust_new_host_keys, timeout_secs, rollout) = match command {
            Command::RemoteExec {
                script,
                sudo,
                trust_new_host_keys,
                timeout_secs,
                rollout,
                ..
            } => (script.clone(), *sudo, *trust_new_host_keys, *timeout_secs, *rollout),
            Command::SupportBundle { spec, .. } => (
                spec.rated_script(),
                spec.sudo,
                spec.trust_new_host_keys,
                spec.timeout_secs,
                spec.rollout,
            ),
            _ => return Ok(None),
        };
        let sudo_password_label = match command.sudo_password_id() {
            Some(id) => self
                .vault
                .list(ctx)
                .await?
                .into_iter()
                .find(|s| s.id == id)
                .map(|s| s.label),
            None => None,
        };
        Ok(Some(Box::new(ExecDetails {
            dangerous: locks::read(&self.policy).dangerous_details(&script),
            script,
            sudo,
            sudo_password_label,
            trust_new_host_keys,
            timeout_secs,
            retry_of,
            multi_exec: false,
            unreliable: false,
            run_key: None,
            rollout,
        })))
    }

    /// SS-07: before a SOCKS tunnel on loopback is rated, how many other users are signed in to this
    /// PC. A failed read counts as nobody else (the tunnel is rated as before).
    async fn note_signed_in(&self, command: &Command) {
        let Command::OpenTunnel { forward, .. } = command else {
            return;
        };
        if forward.spec.kind != ForwardKind::Dynamic || !forward.spec.loopback_only() {
            return;
        }
        let others = match self.capacity.host().other_users_signed_in().await {
            Ok(n) => n,
            Err(err) => {
                tracing::debug!(error = %err, "could not read who is signed in to this PC");
                0
            }
        };
        locks::write(&self.policy).set_other_users(others);
    }

    /// BX-07: a sudo password chosen from the vault must be a password that is there.
    async fn check_sudo_password(&self, ctx: &Context, command: &Command) -> Result<()> {
        if let Some(id) = command.sudo_password_id() {
            match self.store.vault_item_kind(ctx, id).await? {
                Some(SecretKind::Password) => {}
                Some(other) => {
                    return Err(CoreError::InvalidInput(format!(
                        "sudo needs a password, and that vault item is a {}.",
                        other.label()
                    )))
                }
                None => return Err(CoreError::InvalidInput("The sudo password is not in the vault.".into())),
            }
        }
        Ok(())
    }

    async fn submit_job(&self, ctx: &Context, command: Command, retry_of: Option<Uuid>) -> Result<SubmitOutcome> {
        // FD-03: nothing is checked, logged or asked while the read-only lock is on.
        locks::read(&self.policy).check_read_only(self.store.read_only().is_locked(), &command)?;
        self.expire_stale().await;
        if command.targets().is_empty() {
            return Err(CoreError::NoTargets);
        }
        command.validate()?;
        // VM-11: what this PC can't do at all (Workstation's NAT forwards need administrator rights) is refused
        // before anything is asked.
        if let Some(why) = self.impact.refusal(&command) {
            return Err(CoreError::HostNetworkRefused(why));
        }
        self.check_sudo_password(ctx, &command).await?;
        let targets = self.resolve_targets(ctx, &command).await?;

        self.note_signed_in(&command).await;
        let mut decision = locks::read(&self.policy).evaluate(&command, &targets);
        self.apply_change_id_rule(ctx, &mut decision).await?;
        if decision.targets.is_empty() {
            return Err(CoreError::AllTargetsProtected);
        }
        let impact = self.add_warnings(ctx, &command, &mut decision).await;
        // VM-04, VM-21, VM-24: a snapshot or VM delete that linked clones stop on every VM is refused before anything is
        // asked; with other VMs left, the approval says which it refuses, and each of those fails when its turn comes.
        if !impact.linked_clones.is_empty() && impact.linked_clones.len() >= decision.targets.len() {
            let reasons: Vec<&str> = impact.linked_clones.iter().map(|b| b.reason.as_str()).collect();
            return Err(CoreError::LinkedClones(reasons.join(" ")));
        }
        self.ask_for_sudo_places(ctx, &command, &mut decision).await?;
        self.ask_for_guest_password(ctx, &command, &mut decision).await?;
        let summary = command.summary(decision.targets.len());

        if decision.steps.is_empty() {
            // Low tier: no approval, logged only.
            let tier = decision.tier;
            let skipped = decision.skipped.clone();
            let job_id = self
                .jobs
                .enqueue(JobSpec {
                    ctx: *ctx,
                    command,
                    decision,
                    approval: None,
                    safety_snapshot: false,
                    retry_of,
                })
                .await?;
            return Ok(SubmitOutcome::Queued {
                job_id,
                tier,
                summary,
                skipped,
            });
        }

        let request = self
            .request_for(ctx, Uuid::new_v4(), &command, &decision, impact, retry_of)
            .await?;
        self.audit_requested(ctx, &decision, &summary, None).await?;
        locks::lock(&self.pending).insert(
            request.id,
            Pending {
                ctx: *ctx,
                command,
                decision,
                request: request.clone(),
                retry_of,
                asked: Instant::now(),
                standing: None,
            },
        );
        Ok(SubmitOutcome::NeedsApproval { request })
    }

    async fn resolve_targets(&self, ctx: &Context, command: &Command) -> Result<Vec<Target>> {
        // FD-02: a deploy's targets are the new VMs; the VMs it clones from must be this workspace's too.
        let deploys: Vec<&crate::deploy::DeploySpec> = match command {
            Command::Deploy { spec, .. } => vec![spec.as_ref()],
            Command::Stack {
                op: crate::stacks::StackOp::Deploy { spec },
                ..
            } => spec.steps.iter().map(|step| &step.spec).collect(),
            _ => Vec::new(),
        };
        for spec in deploys {
            spec.require_sources_here(&self.store, ctx).await?;
        }
        let mut targets = Vec::with_capacity(command.targets().len());
        let adding = matches!(
            command,
            Command::VmLifecycle {
                op: VmLifecycleOp::Register { .. },
                ..
            }
        );
        for target in command.targets() {
            match target {
                // FD-02, VM-24: a VM being added joins this workspace, so no other workspace may have it.
                TargetRef::Vm { vmx_path } if adding => {
                    if let Some(owner) = self.store.vm_owner(vmx_path).await? {
                        if owner != ctx.workspace_id {
                            return Err(CoreError::NotInWorkspace(crate::inventory::vm_named(vmx_path)));
                        }
                    }
                    targets.push(Target {
                        target: target.clone(),
                        name: crate::inventory::unlisted_name(vmx_path),
                        environment: Environment::None,
                        protected: false,
                    });
                }
                _ => targets.push(self.directory.resolve(ctx, target).await?),
            }
        }
        Ok(targets)
    }

    /// Warnings found before the action (SS-10 a MultiExec line's run key, VM-07 capacity, VM-18 a VirtualBox
    /// revert powering a VM off, VM-23 a VM a settings change would be refused on), and the previews read for
    /// them. Asking again (AP-01) adds them too.
    async fn add_warnings(&self, ctx: &Context, command: &Command, decision: &mut Decision) -> Previews {
        // VM-04, VM-21: a snapshot delete says which VMs it refuses for linked clones (VM-24's VM delete says it as the
        // VM's problem in its own preview, below).
        let linked_clones = self.impact.linked_clones(command, &decision.targets).await;
        if matches!(command, Command::VmSnapshot { .. }) {
            decision.add_warnings(linked_clones.iter().map(|b| b.reason.clone()).collect());
        }
        let vm_change = self.impact.vm_change(command, &decision.targets).await;
        if let Some(preview) = &vm_change {
            // VM-23: a Low change (an ISO, a cable) gets a confirm too when a VM would refuse it, so it is seen.
            let mut problems: Vec<String> = preview
                .targets
                .iter()
                .filter_map(|t| t.problem.as_ref().map(|p| format!("{}: {p}", t.name)))
                .collect();
            // VM-23: Workstation's window is open while a Workstation VM's .vmx or disks change.
            problems.extend(preview.warnings.iter().cloned());
            decision.add_warnings(problems);
        }
        let (stack, capacity) = self.add_deploy_warnings(ctx, command, decision).await;
        // VM-11: who can reach a forward, whose address it leads to, and the VMs on the network.
        decision.add_warnings(self.impact.network_warnings(ctx, command).await);
        Previews {
            impact: self.add_power_warnings(ctx, command, decision).await,
            vm_change,
            stack,
            capacity,
            linked_clones,
        }
    }

    /// VM-08: a stack command's details, and its steps' warnings and refusals (what changed since the stacks service
    /// checked it: those VMs fail when their turn comes). VM-26: for a deploy (R2's or a stack's), this PC after it;
    /// when it won't fit, why, and which running VMs to suspend.
    async fn add_deploy_warnings(
        &self,
        ctx: &Context,
        command: &Command,
        decision: &mut Decision,
    ) -> (
        Option<crate::stacks::StackDetails>,
        Option<crate::capacity_plan::DeployCapacity>,
    ) {
        let host = self.capacity.host().as_ref();
        let stack = self.impact.stack(command, &decision.targets, host).await;
        let demands = match (command, &stack) {
            (Command::Deploy { spec, .. }, _) => self
                .impact
                .deploy(command, host)
                .await
                .map(|preview| crate::capacity_plan::deploy_demands(spec, &preview)),
            (
                Command::Stack {
                    op: crate::stacks::StackOp::Deploy { spec },
                    ..
                },
                Some(details),
            ) => {
                decision.add_warnings(details.warnings.iter().chain(&details.refusals).cloned().collect());
                Some(
                    spec.steps
                        .iter()
                        .zip(&details.steps)
                        .filter_map(|(step, shown)| {
                            shown
                                .deploy
                                .as_ref()
                                .map(|preview| crate::capacity_plan::deploy_demands(&step.spec, preview))
                        })
                        .flatten()
                        .collect::<Vec<_>>(),
                )
            }
            _ => None,
        };
        let capacity = match demands {
            Some(demands) => Some(self.capacity.deploy_capacity(ctx, &demands).await),
            None => None,
        };
        if let Some(capacity) = &capacity {
            decision.add_warnings(capacity.approval_warnings());
        }
        (stack, capacity)
    }

    async fn add_power_warnings(
        &self,
        ctx: &Context,
        command: &Command,
        decision: &mut Decision,
    ) -> Option<Vec<TargetImpact>> {
        // SS-10: what a key other than Enter does in the shells, for the dialog. A Low line runs as is.
        if let Command::TerminalLine { keys, .. } = command {
            decision.warnings.extend(run_key(keys).and_then(RunKey::note));
        }
        // VM-21: thin disks that might not fit, and what changed since the deploy service checked it (a folder that
        // is there now, thick disks that don't fit any more: those VMs fail when their turn comes).
        if let Some(deploy) = self.impact.deploy(command, self.capacity.host().as_ref()).await {
            decision.add_warnings(deploy.warnings.into_iter().chain(deploy.refusals).collect());
        }
        let starts = match command {
            Command::VmPower {
                op: PowerOp::Start { .. },
                ..
            } => true,
            // VM-08: an instance's start is the same power-on.
            Command::Stack {
                op: crate::stacks::StackOp::Power { spec },
                ..
            } => spec.starts(),
            _ => false,
        };
        if starts {
            // VM-07: capacity check before power-on.
            let warnings = self.capacity.check_power_on(ctx, &decision.targets).await;
            let mut messages: Vec<String> = warnings.iter().map(|w| w.message()).collect();
            // VM-26: which other running VMs to suspend to make room.
            for warning in &warnings {
                if let crate::capacity::CapacityWarning::Ram {
                    assigned_mb,
                    physical_mb,
                } = warning
                {
                    let starting: Vec<String> = decision.targets.iter().map(|t| t.target.key()).collect();
                    if let Some(advice) = self
                        .capacity
                        .suspend_advice(ctx, assigned_mb.saturating_sub(*physical_mb), &starting)
                        .await
                    {
                        messages.push(advice.describe());
                    }
                }
            }
            decision.add_warnings(messages);
            // VM-02: VMs that join this PC's own network when they start.
            let bridged = self.capacity.bridged(ctx, &decision.targets).await;
            decision.add_warnings(bridged);
        }
        // VM-18: VirtualBox restores a snapshot only on a VM that is not running, so the revert powers
        // a running one off first; the preview says which, and the user confirms it.
        if let Command::VmSnapshot {
            op: SnapshotOp::Revert { .. },
            ..
        } = command
        {
            if decision.targets.iter().any(is_virtualbox) {
                let preview = self.impact.preview(ctx, &decision.targets).await;
                decision.add_warnings(virtualbox_revert_warnings(&decision.targets, &preview));
                return Some(preview);
            }
        }
        None
    }

    /// What the approval dialog shows for `decision` (AP-02).
    async fn request_for(
        &self,
        ctx: &Context,
        id: Uuid,
        command: &Command,
        decision: &Decision,
        previews: Previews,
        retry_of: Option<Uuid>,
    ) -> Result<ApprovalRequest> {
        let Previews {
            impact,
            vm_change,
            stack,
            capacity,
            linked_clones,
        } = previews;
        let mut impact = match impact {
            Some(impact) => impact,
            // CT-01, CT-02: container targets are previewed by the containers service.
            None => self.impact.preview_for(ctx, command, &decision.targets).await,
        };
        // VM-04, VM-21, VM-24: the clones each refused VM's delete would break.
        for row in &mut impact {
            if let Some(blocked) = linked_clones.iter().find(|b| b.target == row.target) {
                row.linked_clones = blocked.snapshots.clone();
            }
        }
        Ok(ApprovalRequest {
            id,
            action: decision.action,
            tier: decision.tier,
            summary: command.summary(decision.targets.len()),
            steps: decision.steps.clone(),
            targets: decision.targets.clone(),
            skipped: decision.skipped.clone(),
            reasons: decision.reasons.clone(),
            warnings: decision.warnings.clone(),
            impact,
            exec: self.exec_details(ctx, command, retry_of).await?,
            upload: UploadDetails::of(command),
            tunnel: TunnelDetails::of(command),
            deploy: self
                .impact
                .deploy(command, self.capacity.host().as_ref())
                .await
                .map(Box::new),
            vm_change: vm_change.map(Box::new),
            stack: stack.map(Box::new),
            capacity: capacity.map(Box::new),
            standing: None,
            bundle: BundleDetails::of(command),
        })
    }

    /// `again`: what changed when an approval is asked again.
    async fn audit_requested(
        &self,
        ctx: &Context,
        decision: &Decision,
        summary: &str,
        again: Option<&str>,
    ) -> Result<()> {
        let detail = again
            .map(|changes| format!("asked again: {changes}"))
            .into_iter()
            .chain(decision.reasons.iter().chain(&decision.warnings).cloned())
            .collect::<Vec<_>>()
            .join("; ");
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "approval_requested",
                    action: summary,
                    tier: Some(decision.tier),
                    job_id: None,
                    targets: &decision.targets,
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await
            .map(drop)
    }

    /// AP-01: each target as it is now, and what makes the approval out of date: a target labelled Prod, or
    /// protected (AP-04), since it was asked. A label that went the other way leaves the approval as strict as it
    /// was, so it needs nothing.
    async fn label_changes(&self, pending: &Pending) -> Result<(Vec<Target>, Vec<String>)> {
        let now = self.resolve_targets(&pending.ctx, &pending.command).await?;
        let before: HashMap<String, &Target> = pending
            .decision
            .targets
            .iter()
            .chain(&pending.decision.skipped)
            .map(|t| (t.target.key(), t))
            .collect();
        let mut changes = Vec::new();
        for target in &now {
            let Some(was) = before.get(&target.target.key()) else {
                continue;
            };
            if target.protected && !was.protected {
                changes.push(format!("{} is protected now", target.name));
            } else if target.environment == Environment::Prod && was.environment != Environment::Prod {
                changes.push(format!("{} is labelled Prod now", target.name));
            }
        }
        Ok((now, changes))
    }

    /// AP-01: the approval again, for the targets as they are now, under the same id. Nothing runs; the
    /// error carries the new request for the dialog to show.
    async fn ask_again(&self, request_id: Uuid, pending: Pending, now: Vec<Target>, changes: Vec<String>) -> CoreError {
        let ctx = pending.ctx;
        self.note_signed_in(&pending.command).await;
        let mut decision = locks::read(&self.policy).evaluate(&pending.command, &now);
        if let Err(err) = self.apply_change_id_rule(&ctx, &mut decision).await {
            return err;
        }
        let changes = changes.join("; ");
        if decision.targets.is_empty() {
            // Every target is protected now: nothing left to ask about.
            let detail = format!("{changes}; every target is protected now, so nothing ran");
            let written = self
                .store
                .append_audit(
                    &ctx,
                    NewAuditEntry {
                        event: "approval_cancelled",
                        action: &pending.request.summary,
                        tier: Some(pending.decision.tier),
                        job_id: None,
                        targets: &pending.decision.targets,
                        approval: None,
                        result: None,
                        detail: Some(&detail),
                    },
                )
                .await;
            if let Err(err) = written {
                tracing::error!(error = %err, "could not audit an approval whose targets are all protected now");
            }
            return CoreError::AllTargetsProtected;
        }
        let impact = self.add_warnings(&ctx, &pending.command, &mut decision).await;
        if let Err(err) = self.ask_for_sudo_places(&ctx, &pending.command, &mut decision).await {
            return err;
        }
        if let Err(err) = self.ask_for_guest_password(&ctx, &pending.command, &mut decision).await {
            return err;
        }
        let request = match self
            .request_for(&ctx, request_id, &pending.command, &decision, impact, pending.retry_of)
            .await
        {
            Ok(request) => request,
            Err(err) => return err,
        };
        if let Err(err) = self
            .audit_requested(&ctx, &decision, &request.summary, Some(&changes))
            .await
        {
            return err;
        }
        locks::lock(&self.pending).insert(
            request_id,
            Pending {
                ctx,
                command: pending.command,
                decision,
                request: request.clone(),
                retry_of: pending.retry_of,
                asked: Instant::now(),
                standing: None,
            },
        );
        CoreError::ApprovalChanged {
            changes,
            request: Box::new(request),
        }
    }

    /// Checks the answers against every required step. On a wrong answer the request stays pending
    /// so the user can correct it; on success the job is queued.
    ///
    /// QL-15: an approval that waited longer than [`APPROVAL_TTL`] has expired. One whose targets became Prod or
    /// protected since it was asked is asked again ([`CoreError::ApprovalChanged`]) rather than run.
    pub async fn approve(&self, request_id: Uuid, answers: ApprovalAnswers) -> Result<Uuid> {
        let pending = locks::lock(&self.pending)
            .remove(&request_id)
            .ok_or(CoreError::UnknownApproval(request_id))?;
        // VM-14, VM-27: a schedule's approval is answered on its own way, which records the grant instead of a job.
        if pending.standing.is_some() {
            locks::lock(&self.pending).insert(request_id, pending);
            return Err(CoreError::InvalidInput(
                "That approval is for a schedule: answer it from the Schedules page.".into(),
            ));
        }
        let ttl = self.approval_ttl();
        if pending.expired(ttl) {
            self.audit_expired(&pending, ttl).await;
            self.expire_stale().await;
            return Err(CoreError::ApprovalExpired {
                minutes: ttl.as_secs().div_ceil(60),
            });
        }
        // FD-03: a request asked before the read-only lock came on waits; the user can cancel it, or approve it
        // once the lock is off.
        let locked = self.store.read_only().is_locked();
        if let Err(err) = locks::read(&self.policy).check_read_only(locked, &pending.command) {
            locks::lock(&self.pending).insert(request_id, pending);
            return Err(err);
        }
        let (now, changes) = match self.label_changes(&pending).await {
            Ok(found) => found,
            Err(err) => {
                // A target can't be looked up any more (deleted, say): the user can still cancel it.
                locks::lock(&self.pending).insert(request_id, pending);
                return Err(err);
            }
        };
        if !changes.is_empty() {
            return Err(self.ask_again(request_id, pending, now, changes).await);
        }

        match self.check_answers(&pending, &answers).await {
            Ok(record) => {
                let summary = pending.request.summary.clone();
                self.store
                    .append_audit(
                        &pending.ctx,
                        NewAuditEntry {
                            event: "approval_granted",
                            action: &summary,
                            tier: Some(pending.decision.tier),
                            job_id: None,
                            targets: &pending.decision.targets,
                            approval: Some(&record),
                            result: None,
                            detail: None,
                        },
                    )
                    .await?;
                if record.vault_reauth {
                    self.allow_sudo_places(&pending.ctx, &pending.command, &pending.decision.targets)
                        .await?;
                }
                let safety_snapshot = record.safety_snapshot;
                self.jobs
                    .enqueue(JobSpec {
                        ctx: pending.ctx,
                        command: pending.command,
                        decision: pending.decision,
                        approval: Some(record),
                        safety_snapshot,
                        retry_of: pending.retry_of,
                    })
                    .await
            }
            Err(err) => {
                let ctx = pending.ctx;
                let summary = pending.request.summary.clone();
                let tier = pending.decision.tier;
                let targets = pending.decision.targets.clone();
                locks::lock(&self.pending).insert(request_id, pending);
                if matches!(err, CoreError::WrongVaultPassword) {
                    // AP-06: failed re-authentication shows in the audit log, so guessing does too.
                    self.store
                        .append_audit(
                            &ctx,
                            NewAuditEntry {
                                event: "approval_rejected",
                                action: &summary,
                                tier: Some(tier),
                                job_id: None,
                                targets: &targets,
                                approval: None,
                                result: None,
                                detail: Some("wrong vault password"),
                            },
                        )
                        .await?;
                }
                Err(err)
            }
        }
    }

    /// The user closed the dialog. Logged so the audit trail shows abandoned high-impact actions.
    pub async fn cancel_approval(&self, request_id: Uuid) -> Result<()> {
        let pending = locks::lock(&self.pending).remove(&request_id);
        if let Some(p) = pending {
            self.store
                .append_audit(
                    &p.ctx,
                    NewAuditEntry {
                        event: "approval_cancelled",
                        action: &p.request.summary,
                        tier: Some(p.decision.tier),
                        job_id: None,
                        targets: &p.decision.targets,
                        approval: None,
                        result: None,
                        detail: None,
                    },
                )
                .await?;
        }
        Ok(())
    }

    async fn check_answers(&self, pending: &Pending, answers: &ApprovalAnswers) -> Result<ApprovalRecord> {
        check_answers_with(self.vault.as_ref(), &pending.decision, pending.request.id, answers).await
    }
}

/// The answers to a decision's steps, as the approval record keeps them (also for a schedule's standing approval).
pub(crate) async fn check_answers_with(
    vault: &dyn Vault,
    decision: &Decision,
    request_id: Uuid,
    answers: &ApprovalAnswers,
) -> Result<ApprovalRecord> {
    {
        let mut safety_snapshot = false;
        let mut vault_reauth = false;
        let mut change_id = None;
        for step in &decision.steps {
            match step {
                ApprovalStep::Confirm | ApprovalStep::ImpactPreview => {
                    if !answers.confirmed {
                        return Err(CoreError::ApprovalRejected("the action was not confirmed".into()));
                    }
                }
                ApprovalStep::TypeTargetCount { expected } => {
                    if answers.typed_target_count != Some(*expected) {
                        return Err(CoreError::ApprovalRejected(format!(
                            "type the number of targets ({expected}) to confirm"
                        )));
                    }
                }
                ApprovalStep::Reason => {
                    if answers.reason.as_deref().map(str::trim).unwrap_or_default().is_empty() {
                        return Err(CoreError::ApprovalRejected(
                            "a reason or ticket number is required".into(),
                        ));
                    }
                }
                ApprovalStep::SafetySnapshot { default_on } => {
                    safety_snapshot = answers.safety_snapshot.unwrap_or(*default_on);
                }
                // AP-08: optional, unless the workspace requires one for Prod targets.
                ApprovalStep::ChangeId { required } => {
                    change_id = clean_change_id(answers.change_id.as_deref())?;
                    if *required && change_id.is_none() {
                        return Err(CoreError::ApprovalRejected(
                            "this workspace needs a change ID for actions on Prod targets".into(),
                        ));
                    }
                }
                // Enforced by the job runner: the job waits this long and can be cancelled meanwhile.
                ApprovalStep::Countdown { .. } => {}
                // AP-06: the vault's master password, whichever way the vault is unlocked day to day. A
                // vault that is not set up has no password, so the action cannot be approved yet.
                ApprovalStep::VaultReauth => {
                    let password = answers
                        .vault_password
                        .as_ref()
                        .filter(|p| !p.is_empty())
                        .ok_or_else(|| CoreError::ApprovalRejected("the vault password is required".into()))?;
                    if !vault.verify_password(password).await? {
                        return Err(CoreError::WrongVaultPassword);
                    }
                    vault_reauth = true;
                }
            }
        }
        Ok(ApprovalRecord {
            request_id,
            tier: decision.tier,
            typed_target_count: answers.typed_target_count,
            // Kept in the audit log for good, so a secret typed into it by mistake is not.
            reason: answers.reason.as_ref().map(|r| redact_secrets(r.trim()).0),
            safety_snapshot,
            vault_reauth,
            approved_at: now_rfc3339(),
            standing: None,
            change_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::remote::forward::ForwardSpec;

    fn every_kind() -> Vec<Command> {
        let terminal = TargetRef::Terminal {
            terminal_id: Uuid::nil(),
            session_id: None,
        };
        vec![
            Command::VmPower {
                targets: vec![],
                op: PowerOp::Suspend,
            },
            Command::VmSnapshot {
                targets: vec![],
                op: SnapshotOp::Take { name: "base".into() },
            },
            Command::VmProtect {
                targets: vec![],
                protected: true,
            },
            Command::RemoteExec {
                targets: vec![],
                script: "uptime".into(),
                sudo: false,
                sudo_password_id: None,
                trust_new_host_keys: false,
                timeout_secs: None,
                rollout: Rollout {
                    canary: true,
                    stop_after_failures: Some(2),
                },
            },
            Command::AppUpdate {
                version: "1.0.0".into(),
            },
            Command::PushSshKey {
                targets: vec![],
                public_key: "ssh-ed25519 AAAA alice@example.com".into(),
                trust_new_host_keys: false,
                timeout_secs: None,
                options: ssh_keys::KeyOptions::default(),
            },
            Command::RemoveSshKey {
                targets: vec![],
                public_key: "ssh-ed25519 AAAA alice@example.com".into(),
                trust_new_host_keys: false,
                timeout_secs: None,
            },
            Command::TerminalLine {
                targets: vec![terminal.clone()],
                line: "uptime".into(),
                unreliable: false,
                keys: "\r".into(),
            },
            Command::FileUpload {
                targets: vec![terminal.clone()],
                folder: "/tmp".into(),
                files: vec![],
            },
            Command::OpenTunnel {
                targets: vec![terminal],
                forward: PortForward {
                    id: Uuid::nil(),
                    session_id: Uuid::nil(),
                    label: None,
                    spec: ForwardSpec {
                        kind: ForwardKind::Local,
                        bind_address: "127.0.0.1".into(),
                        bind_port: 0,
                        dest_host: "db01.example.com".into(),
                        dest_port: 5432,
                    },
                    auto_start: false,
                },
            },
            Command::Container {
                targets: vec![],
                op: ContainerOp::Start,
            },
            Command::HostNetwork {
                targets: vec![],
                op: HostNetworkOp::RemoveForward {
                    forward: crate::host_networks::NatForward {
                        name: Some("web".into()),
                        protocol: crate::adapters::host_networks::ForwardProtocol::Tcp,
                        host_ip: None,
                        host_port: 8080,
                        guest_ip: Some("203.0.113.10".into()),
                        guest_port: 80,
                        slot: None,
                    },
                },
            },
            Command::SupportBundle {
                targets: vec![],
                spec: Box::new(crate::support_bundle::BundleSpec {
                    presets: vec![crate::support_bundle::PresetId::System],
                    items: vec![
                        crate::support_bundle::BundleItem::command("uname -a"),
                        crate::support_bundle::BundleItem::file("/etc/os-release"),
                    ],
                    sudo: false,
                    sudo_password_id: None,
                    trust_new_host_keys: false,
                    timeout_secs: None,
                    rollout: Rollout::default(),
                    output: r"C:\Users\alice\Documents\bundle.zip".into(),
                    workspace: "Lab".into(),
                }),
            },
        ]
    }

    #[test]
    fn a_support_bundle_only_comes_from_its_dialog_and_is_never_retried() {
        let bundle = every_kind().pop().unwrap();
        assert!(matches!(bundle, Command::SupportBundle { .. }));
        assert!(
            bundle.check_from_ui().is_err(),
            "the zip's place comes from a save dialog"
        );
        assert!(bundle.with_targets(vec![]).is_none());
        assert_eq!(bundle.rated_script().as_deref(), Some("uname -a"));
    }

    #[test]
    fn the_type_name_is_serdes_tag() {
        for command in every_kind() {
            let value = serde_json::to_value(&command).unwrap();
            assert_eq!(value["type"], command.type_name(), "{command:?}");
        }
    }

    #[test]
    fn the_journal_keeps_scripts_and_lines_without_their_secrets() {
        let exec = Command::RemoteExec {
            targets: vec![],
            script: "mysql --password=hunter2 -e 'select 1'\ncurl https://alice:s3cret@example.com/x".into(),
            sudo: false,
            sudo_password_id: None,
            trust_new_host_keys: false,
            timeout_secs: None,
            rollout: Rollout::default(),
        };
        let (kept, redacted) = exec.for_journal();
        assert!(redacted);
        let Command::RemoteExec { script, .. } = &kept else {
            panic!("{kept:?}")
        };
        assert_eq!(
            script,
            "mysql --password=[redacted] -e 'select 1'\ncurl https://alice:[redacted]@example.com/x"
        );
        // Every line, not just the first one the summary shows.
        assert!(!script.contains("s3cret"));

        let line = Command::TerminalLine {
            targets: vec![],
            line: "export TOKEN=abc123\nrun --api-key xyz".into(),
            unreliable: false,
            keys: "\rrun --api-key xyz\r".into(),
        };
        let (kept, redacted) = line.for_journal();
        assert!(redacted);
        let text = serde_json::to_string(&kept).unwrap();
        assert!(!text.contains("abc123") && !text.contains("xyz"), "{text}");

        for plain in every_kind() {
            assert_eq!(plain.for_journal(), (plain.clone(), false), "{plain:?}");
        }
    }
}
