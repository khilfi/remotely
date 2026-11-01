//! Policy engine (AP-01): classes every state-changing command into a risk tier, and the tier decides
//! the approval steps.
//!
//! | Tier     | Steps before it runs                                                                  |
//! |----------|---------------------------------------------------------------------------------------|
//! | Low      | none; logged only                                                                     |
//! | Medium   | one confirm showing the impact summary                                               |
//! | High     | impact preview, safety snapshot (VMs, on by default), type the target count, reason, |
//! |          | 10-second countdown with cancel                                                       |
//! | Critical | all High steps, then the vault password again                                         |
//!
//! A target labelled Prod moves the action up one tier. Protected targets (AP-04) are skipped.
//! The rules are data ([`PolicyRules`]) so they can be edited and saved.

#[cfg(test)]
mod bundle_tests;
pub(crate) mod commands;
#[cfg(test)]
mod convert_tests;
#[cfg(test)]
mod deploy_tests;
#[cfg(test)]
mod file_server_tests;
#[cfg(test)]
mod host_networks_tests;
pub(crate) mod powershell;
#[cfg(test)]
mod powershell_engine_tests;
#[cfg(test)]
mod stack_tests;
mod standing;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vm_settings_tests;
#[cfg(test)]
mod wake_tests;

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::adapters::containers::PruneWhat;
use crate::adapters::remote::forward::ForwardKind;
use crate::adapters::remote::ScriptKind;
use crate::command_bus::{Command, ContainerOp, PowerOp, SnapshotOp, StopMode};
use crate::domain::{Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::host_networks::HostNetworkOp;
use crate::presentation::Change;
use crate::stacks::StackOp;
use crate::vm_settings::{VmConfigEdit, VmDeviceOp, VmDiskOp, VmLifecycleOp};

pub use commands::{default_dangerous_patterns, default_read_only_commands, DangerousPattern};
pub use powershell::PowerShellRules;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Tier {
    Low,
    Medium,
    High,
    Critical,
}

impl Tier {
    /// One tier up, capped at Critical (the Prod rule).
    pub fn bump(self) -> Tier {
        match self {
            Tier::Low => Tier::Medium,
            Tier::Medium => Tier::High,
            Tier::High | Tier::Critical => Tier::Critical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Low => "low",
            Tier::Medium => "medium",
            Tier::High => "high",
            Tier::Critical => "critical",
        }
    }
}

/// What the action is, independent of how many targets it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActionKind {
    VmStart,
    VmUnpause,
    VmPause,
    VmSuspend,
    VmResetSoft,
    VmResetHard,
    VmStopSoft,
    VmStopHard,
    SnapshotTake,
    SnapshotRevert,
    SnapshotDelete,
    /// Mark VMs "do not touch" (AP-04).
    VmProtect,
    /// Unlock protected VMs (AP-04), so other actions reach them again.
    VmUnprotect,
    /// Every part of the command starts with a word on the read-only list.
    ExecReadOnly,
    /// Not read-only, not dangerous.
    ExecOther,
    /// Matches a dangerous-command rule (BX-06).
    ExecDangerous,
    /// Install an app update (FD-14).
    AppUpdate,
    /// Add a public key to hosts' `~/.ssh/authorized_keys` (SS-09): it grants a login.
    SshKeyPush,
    /// SS-09: remove a public key from hosts' `authorized_keys`.
    SshKeyRemove,
    /// Upload files into a folder on a terminal's host (SS-08), adding new files only.
    FileUpload,
    /// Upload files that replace files on the host (SS-08). Never below Medium: replacing asks.
    FileReplace,
    /// Open a local or SOCKS tunnel only this PC can use (SS-07).
    TunnelLocal,
    /// Open a remote tunnel: the host listens, and connections to it reach a host this PC reaches
    /// (SS-07).
    TunnelRemote,
    /// Open a tunnel that listens on a network address, so other computers can use it (SS-07). Never
    /// below Medium.
    TunnelShared,
    // CT-01, CT-02: containers, images and volumes on container hosts. The PRD's VM rules applied to
    // containers: starting is Low, stopping, restarting or pausing is Medium for one and High for more,
    // removing and pruning are High, and removing volumes (their data with them) is Critical.
    /// Start containers.
    ContainerStart,
    /// Unpause containers (like unpausing a VM).
    ContainerUnpause,
    /// Pause containers: their processes freeze.
    ContainerPause,
    ContainerRestart,
    ContainerStop,
    /// Remove containers (force: running ones are killed first).
    ContainerRemove,
    /// Pull an image: adds or updates a tag; running containers keep their image.
    ImagePull,
    ImageRemove,
    /// Remove volumes, which deletes their data.
    VolumeRemove,
    /// Prune stopped containers.
    PruneContainers,
    /// Prune dangling images.
    PruneImages,
    /// Prune Docker's build cache.
    PruneBuildCache,
    /// Prune volumes no container uses, which deletes their data.
    PruneVolumes,
    // VM-11, VM-12, VM-15, VM-16, VM-23, VM-24 (docs/plan-0.5.md, "Approval tiers").
    /// Change a powered-off VM's CPU, memory, firmware, network adapters, shared folders, name or guest OS
    /// type (VM-23, VM-12 bulk resize, VM-11).
    VmConfigure,
    /// Upgrade a Workstation VM's hardware version: it can't be undone.
    VmUpgradeHardware,
    /// Attach an ISO to a VM's CD/DVD drive, or eject it.
    VmIso,
    /// Plug a network adapter's cable in (VM-11).
    VmNicConnect,
    /// Pull a network adapter's cable out: the VM drops off its network. Critical for two or more VMs (the
    /// PRD's "bulk network disconnect").
    VmNicDisconnect,
    /// Install or upgrade VMware Tools or the Guest Additions (VM-15).
    VmToolsInstall,
    /// Add a virtual disk (VM-16).
    VmDiskAdd,
    /// Compact or defragment a virtual disk (VM-16).
    VmDiskCompact,
    /// Expand a virtual disk: it can't be shrunk back (VM-16).
    VmDiskExpand,
    /// Remove a virtual disk, which deletes its files (VM-16).
    VmDiskRemove,
    /// Delete VMs and their files (VM-24).
    VmDelete,
    /// Add an existing VM to the list (a .vmx) or to VirtualBox (a .vbox) (VM-24).
    VmRegister,
    /// Add a NAT port forward: a port of this PC reaches a guest, for every VM on the network to share (VM-11).
    NatForwardAdd,
    /// Remove a NAT port forward: connections through it stop (VM-11).
    NatForwardRemove,
    /// VM-21, VM-10 (docs/plan-0.5.md, "Approval tiers"): make new VMs (create, clone, import). Its bulk tier
    /// applies from [`PolicyRules::deploy_bulk_threshold`] VMs.
    VmDeploy,
    /// VM-08 (docs/plan-0.5.md, "Approval tiers"): delete a stack instance's VMs and their files.
    StackTeardown,
    /// CV-03: convert a disk image into a new one (reads the source, writes a new file only).
    ImageConvert,
    /// VM-17, CV-02: export a powered-off VM for another hypervisor (reads the VM, writes new files only).
    VmExport,
    /// FD-09: send a Wake-on-LAN magic packet from this PC.
    WakeOnLan,
    /// FD-09: run the quick file server (TFTP, HTTP) on an address of this PC, serving only: other computers on its
    /// network can fetch the chosen file or folder.
    FileServer,
    /// FD-09: the same, accepting uploads into an empty folder of this PC.
    FileServerUploads,
}

impl ActionKind {
    /// Every action, in the order Settings lists them (AP-01).
    pub const ALL: [ActionKind; 58] = [
        ActionKind::VmStart,
        ActionKind::VmUnpause,
        ActionKind::VmPause,
        ActionKind::VmSuspend,
        ActionKind::VmResetSoft,
        ActionKind::VmStopSoft,
        ActionKind::VmResetHard,
        ActionKind::VmStopHard,
        ActionKind::SnapshotTake,
        ActionKind::SnapshotRevert,
        ActionKind::SnapshotDelete,
        ActionKind::VmProtect,
        ActionKind::VmUnprotect,
        ActionKind::VmIso,
        ActionKind::VmNicConnect,
        ActionKind::VmNicDisconnect,
        ActionKind::VmToolsInstall,
        ActionKind::VmConfigure,
        ActionKind::VmUpgradeHardware,
        ActionKind::VmDiskAdd,
        ActionKind::VmDiskCompact,
        ActionKind::VmDiskExpand,
        ActionKind::VmDiskRemove,
        ActionKind::VmRegister,
        ActionKind::VmDelete,
        ActionKind::NatForwardAdd,
        ActionKind::NatForwardRemove,
        ActionKind::VmDeploy,
        ActionKind::StackTeardown,
        ActionKind::VmExport,
        ActionKind::ImageConvert,
        ActionKind::ExecReadOnly,
        ActionKind::ExecOther,
        ActionKind::ExecDangerous,
        ActionKind::SshKeyPush,
        ActionKind::SshKeyRemove,
        ActionKind::FileUpload,
        ActionKind::FileReplace,
        ActionKind::TunnelLocal,
        ActionKind::TunnelRemote,
        ActionKind::TunnelShared,
        ActionKind::ContainerStart,
        ActionKind::ContainerUnpause,
        ActionKind::ContainerPause,
        ActionKind::ContainerRestart,
        ActionKind::ContainerStop,
        ActionKind::ContainerRemove,
        ActionKind::ImagePull,
        ActionKind::ImageRemove,
        ActionKind::VolumeRemove,
        ActionKind::PruneContainers,
        ActionKind::PruneImages,
        ActionKind::PruneBuildCache,
        ActionKind::PruneVolumes,
        ActionKind::WakeOnLan,
        ActionKind::FileServer,
        ActionKind::FileServerUploads,
        ActionKind::AppUpdate,
    ];

    /// What the user sees in Settings, approval reasons and the audit log.
    pub fn label(self) -> &'static str {
        match self {
            ActionKind::VmStart => "Start VMs",
            ActionKind::VmUnpause => "Unpause VMs",
            ActionKind::VmPause => "Pause VMs",
            ActionKind::VmSuspend => "Suspend VMs",
            ActionKind::VmResetSoft => "Restart VMs",
            ActionKind::VmStopSoft => "Shut down VMs",
            ActionKind::VmResetHard => "Reset VMs (hard)",
            ActionKind::VmStopHard => "Power off VMs (hard)",
            ActionKind::SnapshotTake => "Take a snapshot",
            ActionKind::SnapshotRevert => "Revert to a snapshot",
            ActionKind::SnapshotDelete => "Delete a snapshot",
            ActionKind::VmProtect => "Protect VMs",
            ActionKind::VmUnprotect => "Unprotect VMs",
            ActionKind::ExecReadOnly => "Run a read-only command",
            ActionKind::ExecOther => "Run any other command",
            ActionKind::ExecDangerous => "Run a dangerous command",
            ActionKind::AppUpdate => "Install an app update",
            ActionKind::SshKeyPush => "Add an SSH key to hosts",
            ActionKind::SshKeyRemove => "Remove an SSH key from hosts",
            ActionKind::FileUpload => "Upload files",
            ActionKind::FileReplace => "Upload files that replace files on the host",
            ActionKind::TunnelLocal => "Open a tunnel for this PC only",
            ActionKind::TunnelRemote => "Open a remote tunnel (the host listens)",
            ActionKind::TunnelShared => "Open a tunnel other computers can use",
            ActionKind::ContainerStart => "Start containers",
            ActionKind::ContainerUnpause => "Unpause containers",
            ActionKind::ContainerPause => "Pause containers",
            ActionKind::ContainerRestart => "Restart containers",
            ActionKind::ContainerStop => "Stop containers",
            ActionKind::ContainerRemove => "Remove containers",
            ActionKind::ImagePull => "Pull an image",
            ActionKind::ImageRemove => "Remove images",
            ActionKind::VolumeRemove => "Remove volumes (deletes their data)",
            ActionKind::PruneContainers => "Prune stopped containers",
            ActionKind::PruneImages => "Prune unused images",
            ActionKind::PruneBuildCache => "Prune the build cache",
            ActionKind::PruneVolumes => "Prune unused volumes (deletes their data)",
            ActionKind::VmConfigure => "Change VM settings (VM off)",
            ActionKind::VmUpgradeHardware => "Upgrade a VM's hardware version",
            ActionKind::VmIso => "Attach or eject an ISO",
            ActionKind::VmNicConnect => "Connect a VM's network adapter",
            ActionKind::VmNicDisconnect => "Disconnect a VM's network adapter",
            ActionKind::VmToolsInstall => "Install or upgrade the guest tools",
            ActionKind::VmDiskAdd => "Add a virtual disk",
            ActionKind::VmDiskCompact => "Compact or defragment a virtual disk",
            ActionKind::VmDiskExpand => "Expand a virtual disk",
            ActionKind::VmDiskRemove => "Remove a virtual disk (deletes its files)",
            ActionKind::VmDelete => "Delete VMs (deletes their files)",
            ActionKind::VmRegister => "Add an existing VM",
            ActionKind::NatForwardAdd => "Add a NAT port forward",
            ActionKind::NatForwardRemove => "Remove a NAT port forward",
            ActionKind::VmDeploy => "Deploy VMs (create, clone or import)",
            ActionKind::StackTeardown => "Tear down a stack instance (deletes its VMs)",
            ActionKind::ImageConvert => "Convert a disk image (writes a new file)",
            ActionKind::VmExport => "Export a VM (writes new files)",
            ActionKind::WakeOnLan => "Wake a machine up (Wake-on-LAN)",
            ActionKind::FileServer => "Run the file server (serving only)",
            ActionKind::FileServerUploads => "Run the file server accepting uploads",
        }
    }

    /// BX-06: a command run on hosts (Compare and MultiExec). Its bulk tier applies from
    /// [`PolicyRules::exec_bulk_threshold`] hosts, not [`PolicyRules::bulk_threshold`].
    pub fn is_exec(self) -> bool {
        matches!(
            self,
            ActionKind::ExecReadOnly | ActionKind::ExecOther | ActionKind::ExecDangerous
        )
    }
}

/// Tier for one target and for a bulk action (from [`PolicyRules::threshold`] targets on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierRule {
    pub single: Tier,
    pub bulk: Tier,
}

impl TierRule {
    const fn same(tier: Tier) -> Self {
        Self {
            single: tier,
            bulk: tier,
        }
    }
}

/// An approval step the user must pass before the job runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ApprovalStep {
    /// Medium: one confirm showing the impact summary.
    Confirm,
    /// High: targets with their current state (AP-02).
    ImpactPreview,
    /// High, VM targets only: snapshot each VM first (VM-05).
    SafetySnapshot { default_on: bool },
    /// High: type the number of targets (AP-03).
    TypeTargetCount { expected: usize },
    /// High: a reason or ticket number (AP-03).
    Reason,
    /// AP-08, High and Critical: a ticket or change number, kept with the approval. Optional, unless the
    /// workspace requires one for Prod targets (the command bus sets `required` from that rule).
    ChangeId { required: bool },
    /// High: the job waits this long after approval and can be cancelled meanwhile (AP-03).
    Countdown { seconds: u32 },
    /// Critical: the vault password again (AP-06).
    VaultReauth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRules {
    pub tiers: BTreeMap<ActionKind, TierRule>,
    /// Target count from which `TierRule::bulk` applies (the PRD says "2 or more VMs"), for every
    /// action but commands on hosts.
    pub bulk_threshold: usize,
    /// BX-06: host count from which `TierRule::bulk` applies to commands on hosts (Compare and
    /// MultiExec), so a command that changes something asks for the full approval on many hosts at
    /// once. Rules saved before it existed get the default.
    #[serde(default = "default_exec_bulk_threshold")]
    pub exec_bulk_threshold: usize,
    /// VM-21: VM count from which a deploy's bulk tier applies (the plan: 5 or more VMs are High). Rules saved
    /// before it existed get the default.
    #[serde(default = "default_deploy_bulk_threshold")]
    pub deploy_bulk_threshold: usize,
    /// A target labelled Prod moves the action up one tier.
    pub prod_bump: bool,
    /// BX-06: editable list of dangerous-command patterns.
    pub dangerous_commands: Vec<DangerousPattern>,
    /// Commands (first words) treated as read-only.
    pub read_only_commands: Vec<String>,
    pub countdown_seconds: u32,
    pub safety_snapshot_default: bool,
    /// BX-13: the rules for PowerShell on WinRM hosts and PowerShell tabs. Rules saved before them get the defaults.
    #[serde(default)]
    pub powershell: PowerShellRules,
}

/// SS-08: replacing a file on a host always asks at least for a confirm.
pub const MIN_REPLACE_TIER: Tier = Tier::Medium;
/// SS-07: a tunnel other computers can use always asks at least for a confirm, which says so.
pub const MIN_SHARED_TUNNEL_TIER: Tier = Tier::Medium;

/// AP-01: the editable numbers stay within these bounds (both bulk thresholds: 2 to the maximum).
pub const MAX_BULK_THRESHOLD: usize = 1000;
pub const MAX_COUNTDOWN_SECONDS: u32 = 300;

/// BX-06: the default [`PolicyRules::exec_bulk_threshold`]. From 5 hosts on, a command that changes
/// something is High: one confirm is too little for a mistake made on that many hosts at once.
pub const DEFAULT_EXEC_BULK_THRESHOLD: usize = 5;

fn default_exec_bulk_threshold() -> usize {
    DEFAULT_EXEC_BULK_THRESHOLD
}

/// VM-21: the default [`PolicyRules::deploy_bulk_threshold`]: 1 to 4 new VMs are one confirm, 5 or more the
/// full approval (`docs/plan-0.5.md`, "Approval tiers").
pub const DEFAULT_DEPLOY_BULK_THRESHOLD: usize = 5;

fn default_deploy_bulk_threshold() -> usize {
    DEFAULT_DEPLOY_BULK_THRESHOLD
}

/// Characters that join or redirect shell commands. A read-only entry holding one would let a
/// writing command ride along on a read-only one.
const SHELL_SPECIAL: &[char] = &[';', '&', '|', '>', '<', '`', '$', '(', ')', '\n', '\r'];

/// AP-01: programs that run whatever they are given: shells, interpreters and programs that start
/// another command. As a read-only entry any of them would let every command through as a read
/// (`bash -c 'rm -rf /'`, `xargs rm`, `sudo -s`), so none can be one. `env` alone (print the
/// environment) can; `env` with a command can't.
const RUNS_ANYTHING: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "pwsh",
    "powershell",
    "ruby",
    "irb",
    "node",
    "nodejs",
    "deno",
    "bun",
    "tclsh",
    "wish",
    "expect",
    "rscript",
    "julia",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "xargs",
    "parallel",
    "sudo",
    "doas",
    "su",
    "pkexec",
    "runuser",
    "sudoedit",
    "exec",
    "eval",
    "source",
    ".",
    "command",
    "builtin",
    "nohup",
    "timeout",
    "nice",
    "ionice",
    "stdbuf",
    "time",
    "chroot",
    "nsenter",
    "setsid",
    "unshare",
    "watch",
    "strace",
    "ltrace",
    "flock",
    "unbuffer",
    "script",
    "ssh",
    "socat",
    "vi",
    "vim",
    "nvim",
    "ex",
    "ed",
    "emacs",
    "gdb",
];

/// Families named by a prefix: `python3.12`, `perl5.36`, `lua5.4`, `php8.2`, `pypy3`.
const RUNS_ANYTHING_PREFIXES: &[&str] = &["python", "perl", "lua", "php", "pypy"];

/// Why a read-only entry is refused for running other commands, if it is.
fn runs_anything(entry: &str) -> Option<String> {
    let words: Vec<&str> = entry.split_whitespace().collect();
    let first = words.first()?;
    // `/bin/bash` is bash.
    let program = first.rsplit('/').next().unwrap_or(first).to_ascii_lowercase();
    if program == "env" {
        return words[1..]
            .iter()
            .any(|w| !w.starts_with('-'))
            .then(|| format!("'{entry}' runs another command through env"));
    }
    let named = RUNS_ANYTHING.contains(&program.as_str())
        || RUNS_ANYTHING_PREFIXES.iter().any(|prefix| program.starts_with(prefix));
    named.then(|| format!("'{entry}' starts {program}, which runs any command it is given"))
}

impl PolicyRules {
    /// Target count from which an action's bulk tier applies: [`Self::exec_bulk_threshold`] hosts for
    /// commands on hosts, [`Self::bulk_threshold`] targets for the rest.
    pub fn threshold(&self, kind: ActionKind) -> usize {
        if kind.is_exec() {
            self.exec_bulk_threshold
        } else if kind == ActionKind::VmDeploy {
            self.deploy_bulk_threshold
        } else {
            self.bulk_threshold
        }
    }

    /// The tier `kind` gets on `targets` targets, before the Prod rule.
    fn tier_for(&self, kind: ActionKind, targets: usize) -> Tier {
        let rule = self.tiers[&kind];
        if targets >= self.threshold(kind) {
            rule.bulk
        } else {
            rule.single
        }
    }

    /// Trims names and patterns and collapses the spaces in read-only entries, so the same rule
    /// typed twice compares equal. Changes nothing else.
    pub fn normalized(mut self) -> Self {
        for p in &mut self.dangerous_commands {
            p.name = p.name.trim().to_owned();
            p.pattern = p.pattern.trim().to_owned();
        }
        for entry in &mut self.read_only_commands {
            *entry = entry.split_whitespace().collect::<Vec<_>>().join(" ");
        }
        for p in &mut self.powershell.dangerous_commands {
            p.name = p.name.trim().to_owned();
            p.pattern = p.pattern.trim().to_owned();
        }
        for entry in &mut self.powershell.read_only_commands {
            *entry = powershell::squeeze(entry);
        }
        self
    }

    /// AP-01: every problem that makes the rules unusable, or unsafe to save. Reported one at a time,
    /// so the message names the rule to fix.
    pub fn validate(&self) -> Result<()> {
        let invalid = |name: &str, message: String| {
            Err(CoreError::InvalidRule {
                name: name.to_owned(),
                message,
            })
        };
        for kind in ActionKind::ALL {
            let Some(rule) = self.tiers.get(&kind) else {
                return invalid(kind.label(), "no tier set for this action".into());
            };
            if kind == ActionKind::FileReplace && rule.single < MIN_REPLACE_TIER {
                return invalid(
                    kind.label(),
                    format!(
                        "replacing a file always asks first, so this can't be lower than {}",
                        MIN_REPLACE_TIER.as_str()
                    ),
                );
            }
            if kind == ActionKind::TunnelShared && rule.single < MIN_SHARED_TUNNEL_TIER {
                return invalid(
                    kind.label(),
                    format!(
                        "a tunnel other computers can use always asks first, so this can't be lower than {}",
                        MIN_SHARED_TUNNEL_TIER.as_str()
                    ),
                );
            }
            if rule.bulk < rule.single {
                return invalid(
                    kind.label(),
                    format!(
                        "the tier for {} or more targets ({}) can't be lower than for one target ({})",
                        self.threshold(kind),
                        rule.bulk.as_str(),
                        rule.single.as_str()
                    ),
                );
            }
        }
        if !(2..=MAX_BULK_THRESHOLD).contains(&self.bulk_threshold) {
            return invalid("Bulk threshold", format!("must be 2 to {MAX_BULK_THRESHOLD} targets"));
        }
        if !(2..=MAX_BULK_THRESHOLD).contains(&self.exec_bulk_threshold) {
            return invalid(
                "Bulk threshold for commands on hosts",
                format!("must be 2 to {MAX_BULK_THRESHOLD} hosts"),
            );
        }
        if !(2..=MAX_BULK_THRESHOLD).contains(&self.deploy_bulk_threshold) {
            return invalid(
                "Bulk threshold for deploys",
                format!("must be 2 to {MAX_BULK_THRESHOLD} VMs"),
            );
        }
        if self.countdown_seconds > MAX_COUNTDOWN_SECONDS {
            return invalid("Countdown", format!("must be 0 to {MAX_COUNTDOWN_SECONDS} seconds"));
        }
        validate_patterns(&self.dangerous_commands, "Dangerous command", "")?;
        // BX-13: the PowerShell rules, checked the same way; their messages say which list.
        validate_patterns(
            &self.powershell.dangerous_commands,
            "Dangerous PowerShell command",
            "another dangerous PowerShell rule has this name",
        )?;
        let mut ps_entries = std::collections::HashSet::new();
        for entry in &self.powershell.read_only_commands {
            if let Some(why) = powershell::entry_problem(entry) {
                return invalid("Read-only PowerShell commands", why);
            }
            if !ps_entries.insert(powershell::squeeze(entry).to_lowercase()) {
                return invalid(
                    "Read-only PowerShell commands",
                    format!("'{}' is listed twice", entry.trim()),
                );
            }
        }
        let mut entries = std::collections::HashSet::new();
        for entry in &self.read_only_commands {
            let shown = entry.trim();
            if shown.is_empty() {
                return invalid("Read-only commands", "an entry is empty".into());
            }
            if shown.contains(SHELL_SPECIAL) {
                return invalid(
                    "Read-only commands",
                    format!("'{shown}' holds a shell operator (; & | > < ` $ or brackets)"),
                );
            }
            if let Some(why) = runs_anything(shown) {
                return invalid("Read-only commands", format!("{why}, so it can't be read-only"));
            }
            if !entries.insert(shown.split_whitespace().collect::<Vec<_>>().join(" ")) {
                return invalid("Read-only commands", format!("'{shown}' is listed twice"));
            }
        }
        Ok(())
    }

    /// AP-01, AP-06: how `new` is looser than `self`, one line per way: an action's tier lowered, the
    /// Prod rule off, a dangerous-command rule removed or changed, a command added to the read-only list,
    /// a bulk threshold raised, a shorter countdown, safety snapshots off by default. Empty when it only
    /// tightens or changes nothing.
    pub fn loosened(&self, new: &PolicyRules) -> Vec<String> {
        let mut out = Vec::new();
        for kind in ActionKind::ALL {
            let (Some(before), Some(after)) = (self.tiers.get(&kind), new.tiers.get(&kind)) else {
                continue;
            };
            if after.single < before.single || after.bulk < before.bulk {
                out.push(format!("{} asks less", kind.label()));
            }
        }
        if self.prod_bump && !new.prod_bump {
            out.push("Prod no longer raises the tier".into());
        }
        for p in &self.dangerous_commands {
            match new.dangerous_commands.iter().find(|n| n.name == p.name) {
                None => out.push(format!("dangerous command '{}' removed", p.name)),
                Some(n) if n.pattern != p.pattern => out.push(format!("dangerous command '{}' changed", p.name)),
                Some(_) => {}
            }
        }
        let squeeze = |e: &str| e.split_whitespace().collect::<Vec<_>>().join(" ");
        let known: std::collections::HashSet<String> = self.read_only_commands.iter().map(|e| squeeze(e)).collect();
        for entry in &new.read_only_commands {
            if !known.contains(&squeeze(entry)) {
                out.push(format!("'{}' counts as read-only", entry.trim()));
            }
        }
        // BX-13: the PowerShell lists loosen the same ways.
        for p in &self.powershell.dangerous_commands {
            match new.powershell.dangerous_commands.iter().find(|n| n.name == p.name) {
                None => out.push(format!("dangerous PowerShell command '{}' removed", p.name)),
                Some(n) if n.pattern != p.pattern => {
                    out.push(format!("dangerous PowerShell command '{}' changed", p.name))
                }
                Some(_) => {}
            }
        }
        let known_ps: std::collections::HashSet<String> = self
            .powershell
            .read_only_commands
            .iter()
            .map(|e| powershell::squeeze(e).to_lowercase())
            .collect();
        for entry in &new.powershell.read_only_commands {
            if !known_ps.contains(&powershell::squeeze(entry).to_lowercase()) {
                out.push(format!("'{}' counts as read-only in PowerShell", entry.trim()));
            }
        }
        if new.bulk_threshold > self.bulk_threshold {
            out.push("a higher bulk threshold".into());
        }
        if new.exec_bulk_threshold > self.exec_bulk_threshold {
            out.push("a higher bulk threshold for commands on hosts".into());
        }
        if new.deploy_bulk_threshold > self.deploy_bulk_threshold {
            out.push("a higher bulk threshold for deploys".into());
        }
        if new.countdown_seconds < self.countdown_seconds {
            out.push("a shorter countdown".into());
        }
        if self.safety_snapshot_default && !new.safety_snapshot_default {
            out.push("no safety snapshot by default".into());
        }
        out
    }

    /// What changed from `self` to `new`, one line per change, for the audit log (AP-01).
    pub fn changes(&self, new: &PolicyRules) -> Vec<String> {
        let mut out = Vec::new();
        for kind in ActionKind::ALL {
            let (before, after) = (self.tiers.get(&kind), new.tiers.get(&kind));
            if before == after {
                continue;
            }
            let show = |r: Option<&TierRule>| {
                r.map_or_else(
                    || "none".to_owned(),
                    |r| format!("{} for one, {} in bulk", r.single.as_str(), r.bulk.as_str()),
                )
            };
            out.push(format!("{}: {} -> {}", kind.label(), show(before), show(after)));
        }
        if self.bulk_threshold != new.bulk_threshold {
            out.push(format!(
                "Bulk threshold: {} -> {} targets",
                self.bulk_threshold, new.bulk_threshold
            ));
        }
        if self.exec_bulk_threshold != new.exec_bulk_threshold {
            out.push(format!(
                "Bulk threshold for commands on hosts: {} -> {} hosts",
                self.exec_bulk_threshold, new.exec_bulk_threshold
            ));
        }
        if self.deploy_bulk_threshold != new.deploy_bulk_threshold {
            out.push(format!(
                "Bulk threshold for deploys: {} -> {} VMs",
                self.deploy_bulk_threshold, new.deploy_bulk_threshold
            ));
        }
        if self.prod_bump != new.prod_bump {
            out.push(format!(
                "Prod raises the tier: {} -> {}",
                on_off(self.prod_bump),
                on_off(new.prod_bump)
            ));
        }
        if self.countdown_seconds != new.countdown_seconds {
            out.push(format!(
                "Countdown: {} -> {} s",
                self.countdown_seconds, new.countdown_seconds
            ));
        }
        if self.safety_snapshot_default != new.safety_snapshot_default {
            out.push(format!(
                "Safety snapshot by default: {} -> {}",
                on_off(self.safety_snapshot_default),
                on_off(new.safety_snapshot_default)
            ));
        }
        for p in &new.dangerous_commands {
            match self.dangerous_commands.iter().find(|old| old.name == p.name) {
                None => out.push(format!("Dangerous command added: {} = {}", p.name, p.pattern)),
                Some(old) if old.pattern != p.pattern => out.push(format!(
                    "Dangerous command changed: {} = {} -> {}",
                    p.name, old.pattern, p.pattern
                )),
                Some(_) => {}
            }
        }
        for p in &self.dangerous_commands {
            if !new.dangerous_commands.iter().any(|n| n.name == p.name) {
                out.push(format!("Dangerous command removed: {}", p.name));
            }
        }
        for entry in &new.read_only_commands {
            if !self.read_only_commands.contains(entry) {
                out.push(format!("Read-only command added: {entry}"));
            }
        }
        for entry in &self.read_only_commands {
            if !new.read_only_commands.contains(entry) {
                out.push(format!("Read-only command removed: {entry}"));
            }
        }
        let (old_ps, new_ps) = (&self.powershell, &new.powershell);
        for p in &new_ps.dangerous_commands {
            match old_ps.dangerous_commands.iter().find(|old| old.name == p.name) {
                None => out.push(format!(
                    "Dangerous PowerShell command added: {} = {}",
                    p.name, p.pattern
                )),
                Some(old) if old.pattern != p.pattern => out.push(format!(
                    "Dangerous PowerShell command changed: {} = {} -> {}",
                    p.name, old.pattern, p.pattern
                )),
                Some(_) => {}
            }
        }
        for p in &old_ps.dangerous_commands {
            if !new_ps.dangerous_commands.iter().any(|n| n.name == p.name) {
                out.push(format!("Dangerous PowerShell command removed: {}", p.name));
            }
        }
        for entry in &new_ps.read_only_commands {
            if !old_ps.read_only_commands.contains(entry) {
                out.push(format!("Read-only PowerShell command added: {entry}"));
            }
        }
        for entry in &old_ps.read_only_commands {
            if !new_ps.read_only_commands.contains(entry) {
                out.push(format!("Read-only PowerShell command removed: {entry}"));
            }
        }
        out
    }

    /// Rules saved before an action existed have no tier for it; give those the default tier, so an
    /// update that adds an action does not stop the app from loading the user's rules.
    pub fn fill_missing_tiers(&mut self) {
        for (kind, rule) in PolicyRules::default().tiers {
            self.tiers.entry(kind).or_insert(rule);
        }
    }
}

/// AP-01, BX-06, BX-13: a list of dangerous-command rules: each named once, with a pattern that compiles and doesn't
/// match every command. `label` names an unnamed rule; `taken` says a name is used twice (the shell list's words when
/// empty).
fn validate_patterns(patterns: &[DangerousPattern], label: &str, taken: &str) -> Result<()> {
    let invalid = |name: &str, message: String| {
        Err(CoreError::InvalidRule {
            name: name.to_owned(),
            message,
        })
    };
    let mut names = std::collections::HashSet::new();
    for p in patterns {
        let shown = if p.name.trim().is_empty() {
            label
        } else {
            p.name.as_str()
        };
        if p.name.trim().is_empty() {
            return invalid(shown, "give the pattern a name".into());
        }
        if !names.insert(p.name.trim().to_lowercase()) {
            let message = if taken.is_empty() {
                "another dangerous-command rule has this name"
            } else {
                taken
            };
            return invalid(shown, message.into());
        }
        if p.pattern.trim().is_empty() {
            return invalid(shown, "the pattern is empty".into());
        }
        match Regex::new(&p.pattern) {
            Err(err) => return invalid(shown, format!("not a valid regular expression: {err}")),
            // A pattern that matches the empty string matches every command.
            Ok(re) if re.is_match("") => {
                return invalid(shown, "the pattern matches every command".into());
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

/// The severity order of the three exec actions (BX-06): dangerous, then other, then read-only.
fn exec_rank(kind: ActionKind) -> u8 {
    match kind {
        ActionKind::ExecDangerous => 2,
        ActionKind::ExecOther => 1,
        _ => 0,
    }
}

/// An exec action in one word, for reasons.
fn exec_word(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::ExecDangerous => "dangerous",
        ActionKind::ExecReadOnly => "read-only",
        _ => "other",
    }
}

fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

impl Default for PolicyRules {
    fn default() -> Self {
        use ActionKind::*;
        use Tier::*;
        let tiers = BTreeMap::from([
            (VmStart, TierRule::same(Low)),
            (VmUnpause, TierRule::same(Low)),
            (VmPause, TierRule::same(Medium)),
            (
                VmSuspend,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (
                VmResetSoft,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (
                VmStopSoft,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (VmResetHard, TierRule::same(Critical)),
            (VmStopHard, TierRule::same(Critical)),
            (SnapshotTake, TierRule::same(Low)),
            (SnapshotRevert, TierRule::same(High)),
            (SnapshotDelete, TierRule::same(High)),
            (VmProtect, TierRule::same(Low)),
            (VmUnprotect, TierRule::same(Medium)),
            (ExecReadOnly, TierRule::same(Low)),
            // BX-06: a change on one host or a few is one confirm; on `exec_bulk_threshold` hosts or
            // more it is the full approval (type the count, a reason, the countdown).
            (
                ExecOther,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (ExecDangerous, TierRule::same(High)),
            (AppUpdate, TierRule::same(Medium)),
            // A key in authorized_keys lets its holder log in: a change like any other command.
            (SshKeyPush, TierRule::same(Medium)),
            // Taking a key away can lock its holder out of a host: a change like adding one.
            (SshKeyRemove, TierRule::same(Medium)),
            // SS-08: a new file in a folder the user can write to anyway; replacing one asks first.
            (FileUpload, TierRule::same(Low)),
            (FileReplace, TierRule::same(Medium)),
            // SS-07: a tunnel only this PC can use reaches what the terminal reaches anyway (the PRD:
            // Medium on a Prod host, which the Prod rule gives). A remote one opens a port on the host
            // into this PC's network; a shared one lets other computers in without logging in.
            (TunnelLocal, TierRule::same(Low)),
            (TunnelRemote, TierRule::same(Medium)),
            (TunnelShared, TierRule::same(Medium)),
            // CT-01, CT-02 (docs/plan-0.4.md, Q6): the VM rules applied to containers.
            (ContainerStart, TierRule::same(Low)),
            (ContainerUnpause, TierRule::same(Low)),
            (
                ContainerPause,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (
                ContainerRestart,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (
                ContainerStop,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (ContainerRemove, TierRule::same(High)),
            // Adds or moves a tag; nothing running changes, like starting.
            (ImagePull, TierRule::same(Low)),
            (ImageRemove, TierRule::same(High)),
            // The data goes with the volume.
            (VolumeRemove, TierRule::same(Critical)),
            (PruneContainers, TierRule::same(High)),
            (PruneImages, TierRule::same(High)),
            (PruneBuildCache, TierRule::same(High)),
            (PruneVolumes, TierRule::same(Critical)),
            // docs/plan-0.5.md, "Approval tiers". VM-12: a bulk resize is one confirm for all the VMs.
            (VmConfigure, TierRule::same(Medium)),
            // Can't be undone, and older Workstation versions won't open the VM.
            (VmUpgradeHardware, TierRule::same(High)),
            (VmIso, TierRule::same(Low)),
            (VmNicConnect, TierRule::same(Low)),
            // The PRD: a bulk network disconnect is Critical.
            (
                VmNicDisconnect,
                TierRule {
                    single: Medium,
                    bulk: Critical,
                },
            ),
            (VmToolsInstall, TierRule::same(Medium)),
            (VmDiskAdd, TierRule::same(Medium)),
            (VmDiskCompact, TierRule::same(Medium)),
            // Can't be shrunk back.
            (VmDiskExpand, TierRule::same(High)),
            // The files go with it.
            (VmDiskRemove, TierRule::same(Critical)),
            (VmDelete, TierRule::same(Critical)),
            // Lists a VM (or registers it with VirtualBox); nothing in it changes.
            (VmRegister, TierRule::same(Low)),
            // VM-11: a forward opens a port of this PC to a guest, or closes one, for the whole network.
            (NatForwardAdd, TierRule::same(High)),
            (NatForwardRemove, TierRule::same(High)),
            // VM-21, VM-10 (docs/plan-0.5.md): 1 to 4 VMs are one confirm, 5 or more (deploy_bulk_threshold) the
            // full approval; a Prod label moves it up one, as for every action.
            (
                VmDeploy,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            // VM-08: its VMs and their files go, like deleting them.
            (StackTeardown, TierRule::same(Critical)),
            // CV-03, VM-17, CV-02 (docs/plan-0.5.md): read the source, write new files only. A Prod VM's export is
            // Medium (its data leaves the VM).
            (ImageConvert, TierRule::same(Low)),
            (VmExport, TierRule::same(Low)),
            // FD-09 (docs/plan-0.7.md): one packet that wakes a machine; a Prod target's is Medium.
            (WakeOnLan, TierRule::same(Low)),
            // FD-09: other computers on the network can fetch what it serves; with uploads they can also write files
            // onto this PC.
            (FileServer, TierRule::same(Medium)),
            (FileServerUploads, TierRule::same(High)),
        ]);
        Self {
            tiers,
            bulk_threshold: 2,
            exec_bulk_threshold: DEFAULT_EXEC_BULK_THRESHOLD,
            deploy_bulk_threshold: DEFAULT_DEPLOY_BULK_THRESHOLD,
            prod_bump: true,
            dangerous_commands: default_dangerous_patterns(),
            read_only_commands: default_read_only_commands(),
            countdown_seconds: 10,
            safety_snapshot_default: true,
            powershell: PowerShellRules::default(),
        }
    }
}

/// BX-06: a dangerous-command rule a script matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DangerousMatch {
    /// The rule's name, as in Settings.
    pub rule: String,
    /// The script line it first matched, trimmed (at most 200 characters).
    pub text: String,
    /// That line's number, from 1.
    pub line: usize,
}

/// The engine's answer for one command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub action: ActionKind,
    pub tier: Tier,
    pub steps: Vec<ApprovalStep>,
    /// Targets the action will run on.
    pub targets: Vec<Target>,
    /// Protected targets that will be left alone (AP-04).
    pub skipped: Vec<Target>,
    /// Why the tier is what it is, for the impact preview and the audit log.
    pub reasons: Vec<String>,
    /// Problems found before the action, e.g. not enough host RAM (VM-07). The user must see them.
    pub warnings: Vec<String>,
    /// BX-13: the language each target's script was rated in, by target key (`targets` only; none for actions without
    /// a script). The job runner checks the connection runs that language before it runs anything.
    #[serde(skip)]
    pub script_kinds: BTreeMap<String, ScriptKind>,
}

impl Decision {
    /// VM-07: warnings must reach the user before the action runs, so an action that would run
    /// without a dialog gets one confirm. The tier, and the steps of a tier that has a dialog anyway,
    /// stay as they are.
    pub fn add_warnings(&mut self, warnings: Vec<String>) {
        if warnings.is_empty() {
            return;
        }
        if self.steps.is_empty() {
            self.steps.push(ApprovalStep::Confirm);
        }
        self.warnings.extend(warnings);
    }
}

pub struct PolicyEngine {
    rules: PolicyRules,
    dangerous: Vec<(String, Regex)>,
    /// BX-13: the PowerShell rules' dangerous commands, compiled.
    ps_dangerous: Vec<(String, Regex)>,
    /// SS-07: other users signed in to this PC, as last read ([`PolicyEngine::set_other_users`]).
    other_users: usize,
}

fn compile_patterns(patterns: &[DangerousPattern]) -> Result<Vec<(String, Regex)>> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(&p.pattern)
                .map(|re| (p.name.clone(), re))
                .map_err(|e| CoreError::InvalidRule {
                    name: p.name.clone(),
                    message: e.to_string(),
                })
        })
        .collect()
}

/// BX-13: the languages a command's scripts are rated in, each once: POSIX when nothing says otherwise.
fn languages(kinds: &[ScriptKind]) -> Vec<ScriptKind> {
    let set: BTreeSet<ScriptKind> = kinds.iter().copied().collect();
    if set.is_empty() {
        vec![ScriptKind::Posix]
    } else {
        set.into_iter().collect()
    }
}

impl PolicyEngine {
    /// Fails with the first problem [`PolicyRules::validate`] finds.
    pub fn new(rules: PolicyRules) -> Result<Self> {
        rules.validate()?;
        let dangerous = compile_patterns(&rules.dangerous_commands)?;
        let ps_dangerous = compile_patterns(&rules.powershell.dangerous_commands)?;
        Ok(Self {
            rules,
            dangerous,
            ps_dangerous,
            other_users: 0,
        })
    }

    /// SS-07: how many other users are signed in to this PC; the bus reads it just before it rates a
    /// SOCKS tunnel on loopback, which they could all use.
    pub fn set_other_users(&mut self, count: usize) {
        self.other_users = count;
    }

    pub fn rules(&self) -> &PolicyRules {
        &self.rules
    }

    /// Names of the dangerous-command rules the script matches (BX-06): as typed, or in one of its
    /// commands as the shell reads them (`\rm -rf /`, `"rm" -rf /`, `sh -c 'rm -rf /'`).
    pub fn dangerous_matches(&self, script: &str) -> Vec<String> {
        let lines = Self::command_lines(script);
        self.dangerous
            .iter()
            .filter(|(_, re)| Self::first_match(re, script, &lines).is_some())
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Each command of the script as the shell reads it, one per line, with where it starts.
    fn command_lines(script: &str) -> Vec<(usize, String)> {
        commands::shell_commands(script)
            .into_iter()
            .map(|c| (c.at, c.line()))
            .collect()
    }

    /// Where in the script `re` first matches: the start of its text as typed, or the start of the
    /// command it matches as the shell reads it, whichever comes first.
    fn first_match(re: &Regex, script: &str, lines: &[(usize, String)]) -> Option<usize> {
        // A match may start on the separator before the command (`\n`, `;`), so it starts where
        // its text begins.
        let typed = re
            .find(script)
            .map(|found| found.start() + (found.as_str().len() - found.as_str().trim_start().len()));
        let read = lines
            .iter()
            .filter(|(_, line)| re.is_match(line))
            .map(|(at, _)| *at)
            .min();
        typed.into_iter().chain(read).min()
    }

    /// BX-13: each PowerShell command of the script on one line, as the parser reads it, with where its statement starts.
    fn ps_command_lines(script: &str) -> Vec<(usize, String)> {
        powershell::commands(script)
            .into_iter()
            .map(|c| (c.at, c.line()))
            .collect()
    }

    /// BX-13: the dangerous-command rules of the language `kind` the script matches.
    pub fn dangerous_matches_as(&self, script: &str, kind: ScriptKind) -> Vec<String> {
        match kind {
            ScriptKind::Posix => self.dangerous_matches(script),
            ScriptKind::PowerShell => {
                let lines = Self::ps_command_lines(script);
                self.ps_dangerous
                    .iter()
                    .filter(|(_, re)| Self::first_match(re, script, &lines).is_some())
                    .map(|(name, _)| name.clone())
                    .collect()
            }
        }
    }

    /// BX-06: each rule the script matches, with the line of its first match, so the editor and the
    /// approval dialog can show why the command needs approval.
    pub fn dangerous_details(&self, script: &str) -> Vec<DangerousMatch> {
        let lines = Self::command_lines(script);
        Self::details(&self.dangerous, script, &lines)
    }

    /// BX-13: the same for the rules of the language `kind`.
    pub fn dangerous_details_as(&self, script: &str, kind: ScriptKind) -> Vec<DangerousMatch> {
        match kind {
            ScriptKind::Posix => self.dangerous_details(script),
            ScriptKind::PowerShell => Self::details(&self.ps_dangerous, script, &Self::ps_command_lines(script)),
        }
    }

    fn details(rules: &[(String, Regex)], script: &str, lines: &[(usize, String)]) -> Vec<DangerousMatch> {
        rules
            .iter()
            .filter_map(|(name, re)| {
                let start = Self::first_match(re, script, lines)?;
                let line_start = script[..start].rfind('\n').map_or(0, |i| i + 1);
                let line_end = script[start..].find('\n').map_or(script.len(), |i| start + i);
                let text: String = script[line_start..line_end].trim().chars().take(200).collect();
                Some(DangerousMatch {
                    rule: name.clone(),
                    text,
                    line: script[..line_start].matches('\n').count() + 1,
                })
            })
            .collect()
    }

    pub fn classify(&self, command: &Command) -> ActionKind {
        self.classify_on(command, &[])
    }

    /// BX-13: as [`Self::classify`], with a command's script rated in each language among `kinds` (its targets': shell
    /// for SSH hosts and tabs, PowerShell for WinRM hosts and PowerShell tabs), the highest result counting. Empty:
    /// the shell's.
    pub fn classify_on(&self, command: &Command, kinds: &[ScriptKind]) -> ActionKind {
        if command.rated_script().is_some() {
            return languages(kinds)
                .into_iter()
                .map(|kind| self.classify_script_command(command, kind))
                .max_by_key(|kind| exec_rank(*kind))
                .unwrap_or(ActionKind::ExecOther);
        }
        self.classify_action(command)
    }

    /// A command with a script (a Compare hosts run, a Type in all tabs line, a support bundle), rated in one language.
    fn classify_script_command(&self, command: &Command, kind: ScriptKind) -> ActionKind {
        match command {
            Command::RemoteExec { script, .. } => self.classify_script_as(script, kind),
            // SS-10: a MultiExec line is rated like a bulk run's command. When Remotely could not follow what was typed,
            // the shells may run something else, so it is never read-only; nor is a pager or editor in a shell, which
            // stays open in every terminal and runs `!command` typed into it.
            Command::TerminalLine { line, unreliable, .. } => match self.classify_script_as(line, kind) {
                ActionKind::ExecReadOnly
                    if *unreliable || (kind == ScriptKind::Posix && commands::interactive_program(line).is_some()) =>
                {
                    ActionKind::ExecOther
                }
                rated => rated,
            },
            // FD-04: its commands; its files are read as the login user, which only reads, so a bundle of files alone is
            // read-only. BX-13: a Windows host's commands are its own. Review C1: each item runs on its own on the host,
            // so each is rated on its own and the highest counts (joined, one could hide another).
            Command::SupportBundle { .. } => command
                .rated_scripts_for(kind)
                .iter()
                .map(|script| self.classify_script_as(script, kind))
                .max_by_key(|action| exec_rank(*action))
                .unwrap_or(ActionKind::ExecReadOnly),
            _ => self.classify_action(command),
        }
    }

    fn classify_action(&self, command: &Command) -> ActionKind {
        match command {
            Command::VmPower { op, .. } => power_kind(op),
            // VM-08: an instance's deploy is a deploy of all its VMs, its start or stop the power action on them.
            Command::Stack { op, .. } => match op {
                StackOp::Deploy { .. } => ActionKind::VmDeploy,
                StackOp::Power { spec } => power_kind(&spec.op),
                StackOp::Teardown { .. } => ActionKind::StackTeardown,
            },
            Command::VmSnapshot { op, .. } => match op {
                SnapshotOp::Take { .. } => ActionKind::SnapshotTake,
                SnapshotOp::Revert { .. } => ActionKind::SnapshotRevert,
                SnapshotOp::Delete { .. } => ActionKind::SnapshotDelete,
            },
            Command::VmProtect { protected: true, .. } => ActionKind::VmProtect,
            Command::VmProtect { protected: false, .. } => ActionKind::VmUnprotect,
            Command::RemoteExec { .. } | Command::TerminalLine { .. } | Command::SupportBundle { .. } => {
                self.classify_script_command(command, ScriptKind::Posix)
            }
            Command::AppUpdate { .. } => ActionKind::AppUpdate,
            Command::PushSshKey { .. } => ActionKind::SshKeyPush,
            Command::RemoveSshKey { .. } => ActionKind::SshKeyRemove,
            // SS-08: replacing a file loses what was there; adding one does not.
            Command::FileUpload { files, .. } if files.iter().any(|f| f.replace) => ActionKind::FileReplace,
            Command::FileUpload { .. } => ActionKind::FileUpload,
            // SS-07: who can use the tunnel decides, then which way it goes.
            Command::OpenTunnel { forward, .. } if !forward.spec.loopback_only() => ActionKind::TunnelShared,
            Command::OpenTunnel { forward, .. } if forward.spec.kind == ForwardKind::Remote => ActionKind::TunnelRemote,
            Command::OpenTunnel { .. } => ActionKind::TunnelLocal,
            Command::Container { op, .. } => match op {
                ContainerOp::Start => ActionKind::ContainerStart,
                ContainerOp::Unpause => ActionKind::ContainerUnpause,
                ContainerOp::Pause => ActionKind::ContainerPause,
                ContainerOp::Restart => ActionKind::ContainerRestart,
                ContainerOp::Stop => ActionKind::ContainerStop,
                ContainerOp::Remove { .. } => ActionKind::ContainerRemove,
                ContainerOp::Pull { .. } => ActionKind::ImagePull,
                ContainerOp::RemoveImage => ActionKind::ImageRemove,
                ContainerOp::RemoveVolume => ActionKind::VolumeRemove,
                ContainerOp::Prune { what } => match what {
                    PruneWhat::Containers => ActionKind::PruneContainers,
                    PruneWhat::Images => ActionKind::PruneImages,
                    PruneWhat::BuildCache => ActionKind::PruneBuildCache,
                    PruneWhat::Volumes => ActionKind::PruneVolumes,
                },
            },
            Command::VmConfig {
                edit: VmConfigEdit::UpgradeHardware,
                ..
            } => ActionKind::VmUpgradeHardware,
            Command::VmConfig { .. } => ActionKind::VmConfigure,
            Command::VmDevice { op, .. } => match op {
                VmDeviceOp::AttachIso { .. } | VmDeviceOp::EjectIso { .. } => ActionKind::VmIso,
                VmDeviceOp::ConnectNic { .. } => ActionKind::VmNicConnect,
                VmDeviceOp::DisconnectNic { .. } => ActionKind::VmNicDisconnect,
                VmDeviceOp::InstallTools => ActionKind::VmToolsInstall,
            },
            Command::VmDisk { op, .. } => match op {
                VmDiskOp::Add { .. } => ActionKind::VmDiskAdd,
                VmDiskOp::Compact { .. } | VmDiskOp::Defragment { .. } => ActionKind::VmDiskCompact,
                VmDiskOp::Expand { .. } => ActionKind::VmDiskExpand,
                VmDiskOp::Remove { .. } => ActionKind::VmDiskRemove,
            },
            Command::VmLifecycle { op, .. } => match op {
                VmLifecycleOp::Delete => ActionKind::VmDelete,
                VmLifecycleOp::Register { .. } => ActionKind::VmRegister,
            },
            Command::HostNetwork { op, .. } => match op {
                HostNetworkOp::AddForward { .. } => ActionKind::NatForwardAdd,
                HostNetworkOp::RemoveForward { .. } => ActionKind::NatForwardRemove,
            },
            Command::Deploy { .. } => ActionKind::VmDeploy,
            Command::ImageConvert { .. } => ActionKind::ImageConvert,
            Command::VmExport { .. } => ActionKind::VmExport,
            Command::WakeOnLan { .. } => ActionKind::WakeOnLan,
            // FD-09: accepting uploads lets other computers write files onto this PC.
            Command::FileServer { spec, .. } if spec.uploads.is_some() => ActionKind::FileServerUploads,
            Command::FileServer { .. } => ActionKind::FileServer,
        }
    }

    /// FD-03: refuses the command while presenting with the read-only lock on (see [`read_only_refusal`]).
    pub fn check_read_only(&self, locked: bool, command: &Command) -> Result<()> {
        read_only_refusal(locked, self.classify(command))
    }

    /// A shell command on its own: dangerous (BX-06), read-only, or other. Bulk runs use it, and the
    /// command panel (BX-08) shows it for each saved and built-in command.
    pub fn classify_script(&self, script: &str) -> ActionKind {
        if !self.dangerous_matches(script).is_empty() {
            ActionKind::ExecDangerous
        } else if commands::is_read_only(script, &self.rules.read_only_commands) {
            ActionKind::ExecReadOnly
        } else {
            ActionKind::ExecOther
        }
    }

    /// BX-13: a script on its own in the language `kind` runs in: the shell's rules for POSIX, the PowerShell rules for
    /// PowerShell (dangerous, read-only, or other; anything the parser can't read is other).
    pub fn classify_script_as(&self, script: &str, kind: ScriptKind) -> ActionKind {
        match kind {
            ScriptKind::Posix => self.classify_script(script),
            ScriptKind::PowerShell => {
                if !self.dangerous_matches_as(script, kind).is_empty() {
                    ActionKind::ExecDangerous
                } else if powershell::is_read_only(script, &self.rules.powershell.read_only_commands) {
                    ActionKind::ExecReadOnly
                } else {
                    ActionKind::ExecOther
                }
            }
        }
    }

    /// `targets` are the command's targets after lookup, in the same order.
    pub fn evaluate(&self, command: &Command, targets: &[Target]) -> Decision {
        self.evaluate_on(command, targets, &[])
    }

    /// BX-13: as [`Self::evaluate`], with `kinds[i]` the language `targets[i]` runs scripts in (a WinRM host or a
    /// PowerShell tab: PowerShell). Each target's script is rated by its own language's rules and the highest counts.
    /// Empty: every target's is the shell's.
    pub fn evaluate_on(&self, command: &Command, targets: &[Target], kinds: &[ScriptKind]) -> Decision {
        let kind_of = |i: usize| kinds.get(i).copied().unwrap_or_default();
        let action = self.classify_on(command, kinds);
        // AP-04: actions skip protected targets, except the one that changes protection.
        let skips_protected = !matches!(action, ActionKind::VmProtect | ActionKind::VmUnprotect);
        let mut skipped = Vec::new();
        let mut active = Vec::new();
        let mut active_kinds = Vec::new();
        for (i, target) in targets.iter().enumerate() {
            if skips_protected && target.protected {
                skipped.push(target.clone());
            } else {
                active.push(target.clone());
                active_kinds.push(kind_of(i));
            }
        }
        let scripted = command.rated_script().is_some();
        // The protected targets left out may have been the only ones of a language: rate what runs.
        let action = if scripted && !kinds.is_empty() {
            self.classify_on(command, &active_kinds)
        } else {
            action
        };
        let script_kinds: BTreeMap<String, ScriptKind> = if scripted {
            active
                .iter()
                .zip(&active_kinds)
                .map(|(t, k)| (t.target.key(), *k))
                .collect()
        } else {
            BTreeMap::new()
        };
        let langs = languages(if scripted { &active_kinds } else { &[] });
        let mut reasons = Vec::new();

        let mut tier = self.rules.tier_for(action, active.len());
        let count = match active.len() {
            1 => "1 target".to_owned(),
            n => format!("{n} targets"),
        };
        reasons.push(format!("{} on {count}: {}", action.label(), tier.as_str()));
        // BX-06: say when the bulk tier for commands on hosts applies, since it differs from the rest.
        if action.is_exec() && active.len() >= self.rules.exec_bulk_threshold {
            let rule = self.rules.tiers[&action];
            if rule.bulk != rule.single {
                reasons.push(format!(
                    "{} or more hosts: the bulk tier for commands on hosts applies",
                    self.rules.exec_bulk_threshold
                ));
            }
        }

        // VM-21: the same for a deploy, whose bulk tier has its own threshold.
        if action == ActionKind::VmDeploy && active.len() >= self.rules.deploy_bulk_threshold {
            let rule = self.rules.tiers[&action];
            if rule.bulk != rule.single {
                reasons.push(format!(
                    "{} or more new VMs: the bulk tier for deploys applies",
                    self.rules.deploy_bulk_threshold
                ));
            }
        }

        // FD-04: what a support bundle does on each host, for the dialog and the audit log.
        if let Command::SupportBundle { spec, .. } = command {
            let commands = spec.commands().count();
            let files = spec.files().count();
            let mut what = Vec::new();
            if commands > 0 {
                what.push(match commands {
                    1 => "its 1 command is rated as a Compare hosts run".to_owned(),
                    // Review C1: each item runs on its own, so each is rated on its own and the highest counts.
                    n => format!("its {n} commands are each rated as a Compare hosts run"),
                });
            }
            if files > 0 {
                what.push(match files {
                    1 => "its 1 file is read over SFTP as the login user, never with sudo".to_owned(),
                    n => format!("its {n} files are read over SFTP as the login user, never with sudo"),
                });
            }
            // BX-13: a Windows host's own items.
            let windows_commands = spec.windows_commands().count();
            let windows_files = spec.windows_files().count();
            if windows_commands > 0 {
                what.push(match windows_commands {
                    1 => "its 1 Windows command is rated by the PowerShell rules".to_owned(),
                    n => format!("its {n} Windows commands are each rated by the PowerShell rules"),
                });
            }
            if windows_files > 0 {
                what.push(match windows_files {
                    1 => "its 1 Windows file is read by PowerShell as the sign-in user".to_owned(),
                    n => format!("its {n} Windows files are read by PowerShell as the sign-in user"),
                });
            }
            reasons.push(format!("support bundle: {}", what.join("; ")));
        }

        // BX-13: which rules rated the script, when PowerShell's did.
        if scripted && langs.contains(&ScriptKind::PowerShell) {
            let count = |kind: ScriptKind| active_kinds.iter().filter(|k| **k == kind).count();
            let noun = |n: usize| {
                if n == 1 {
                    "1 target".to_owned()
                } else {
                    format!("{n} targets")
                }
            };
            let rated = |kind: ScriptKind| exec_word(self.classify_script_command(command, kind));
            if langs.len() == 1 {
                reasons.push("rated by the PowerShell rules".into());
            } else {
                reasons.push(format!(
                    "each target is rated by its own rules, the highest counting: the shell's for {} ({}), PowerShell's \
                     for {} ({})",
                    noun(count(ScriptKind::Posix)),
                    rated(ScriptKind::Posix),
                    noun(count(ScriptKind::PowerShell)),
                    rated(ScriptKind::PowerShell)
                ));
            }
        }

        let mut hits: Vec<String> = Vec::new();
        let mut found_actions = Vec::new();
        for lang in if scripted { langs.clone() } else { Vec::new() } {
            // Review C1: a support bundle's items each run on their own, so each is rated on its own here too.
            for script in command.rated_scripts_for(lang) {
                let script = script.as_ref();
                for hit in self.dangerous_matches_as(script, lang) {
                    if !hits.contains(&hit) {
                        hits.push(hit);
                    }
                }
                let shell_commands = match lang {
                    ScriptKind::Posix => commands::shell_commands(script),
                    // BX-13: a PowerShell command as words, so `docker volume prune` on a Windows host is found too.
                    ScriptKind::PowerShell => powershell::commands(script)
                        .into_iter()
                        .map(|c| commands::ShellCommand {
                            at: c.at,
                            words: std::iter::once(c.name)
                                .chain(c.args.into_iter().map(|a| a.text))
                                .collect(),
                        })
                        .collect(),
                };
                for found in commands::container_actions(&shell_commands) {
                    if !found_actions
                        .iter()
                        .any(|f: &commands::ContainerAction| f.what == found.what)
                    {
                        found_actions.push(found);
                    }
                }
            }
        }
        if !hits.is_empty() {
            reasons.push(format!("flagged dangerous: {}", hits.join(", ")));
        }
        {
            // CT-01, BX-06: a prune or a volume removal is rated at least like the same action on the
            // Containers page, so editing that rule changes both.
            for found in found_actions {
                let Some((kind, floor)) = found
                    .kinds
                    .iter()
                    .map(|&kind| (kind, self.rules.tier_for(kind, active.len())))
                    .max_by_key(|(_, t)| *t)
                else {
                    continue;
                };
                let like = format!(
                    "`{}` is rated like \"{}\" on the Containers page",
                    found.what,
                    kind.label()
                );
                if floor > tier {
                    reasons.push(format!("{like}: {} -> {}", tier.as_str(), floor.as_str()));
                    tier = floor;
                } else {
                    reasons.push(format!("{like} ({})", floor.as_str()));
                }
            }
        }

        // SS-07: say why a tunnel is rated as one other computers can use, for the dialog and the audit log.
        if let Command::OpenTunnel { forward, .. } = command {
            if !forward.spec.loopback_only() {
                let side = match forward.spec.kind {
                    ForwardKind::Remote => "the host listens",
                    ForwardKind::Local | ForwardKind::Dynamic => "it listens",
                };
                reasons.push(format!(
                    "{side} on {}, which other computers can reach",
                    forward.spec.listen_address()
                ));
            }
        }

        // FD-09: say who can reach the file server and what it lets them do, for the dialog and the audit log.
        if let Command::FileServer { spec, .. } = command {
            if spec.address.is_loopback() {
                reasons.push(format!("it listens on {}, which only this PC reaches", spec.address));
            } else {
                reasons.push(format!(
                    "it listens on {}, which other computers on that network can reach without logging in",
                    spec.address
                ));
            }
            if let Some(uploads) = &spec.uploads {
                reasons.push(format!(
                    "files they send are saved in {} (at most {} MB each, {} MB in all)",
                    uploads.folder, uploads.max_file_mb, uploads.max_total_mb
                ));
            }
        }

        // CT-01: say what is lost, for the dialog and the audit log.
        if let Command::Container { op, .. } = command {
            match op {
                ContainerOp::RemoveVolume
                | ContainerOp::Prune {
                    what: PruneWhat::Volumes,
                } => reasons.push("the volumes' data is deleted with them".into()),
                ContainerOp::Remove { force: true } => {
                    reasons.push("forced: running containers are killed first".into());
                }
                _ => {}
            }
        }

        // VM-16, VM-23, VM-24: say what can't be undone, for the dialog and the audit log.
        match command {
            Command::VmDisk {
                op: VmDiskOp::Remove { .. },
                ..
            } => reasons.push("the disk's files are deleted".into()),
            Command::VmDisk {
                op: VmDiskOp::Expand { .. },
                ..
            } => reasons.push("a disk can't be shrunk back after it grows".into()),
            Command::VmLifecycle {
                op: VmLifecycleOp::Delete,
                ..
            } => reasons.push("the VMs' files are deleted with them".into()),
            // VM-08: what a stack command does as a whole, for the dialog and the audit log.
            Command::Stack { op, .. } => match op {
                StackOp::Deploy { spec } => reasons.push(format!(
                    "stack '{}': {} in {} step(s), made in boot order",
                    spec.stack_name,
                    match spec.vm_count() {
                        1 => "1 new VM".to_owned(),
                        n => format!("{n} new VMs"),
                    },
                    spec.steps.len()
                )),
                StackOp::Power { spec } if spec.starts() => reasons.push(format!(
                    "stack instance '{}': started in boot order",
                    spec.instance_name
                )),
                StackOp::Power { spec } => {
                    reasons.push(format!("stack instance '{}': its last step first", spec.instance_name))
                }
                StackOp::Teardown { spec } => {
                    reasons.push("the stack instance's VMs are deleted with their files".into());
                    if !spec.kept.is_empty() {
                        reasons.push(format!(
                            "{} VM(s) of the instance are kept (added by hand, or gone already)",
                            spec.kept.len()
                        ));
                    }
                }
            },
            Command::VmConfig {
                edit: VmConfigEdit::UpgradeHardware,
                ..
            } => {
                reasons.push("a hardware upgrade can't be undone (older Workstation versions won't open the VM)".into())
            }
            _ => {}
        }

        // SS-10: say why a pager or editor in a MultiExec line is not read-only.
        if let Command::TerminalLine { line, .. } = command {
            if let Some(program) = commands::interactive_program(line) {
                reasons.push(format!(
                    "{program} stays open in each terminal, and what is typed into it there passes straight through \
                     unrated (a pager's or editor's !command runs commands)"
                ));
            }
        }

        // SS-10: a line Remotely could not follow gets at least a confirm, whatever the rules say for
        // "other" commands: the approval shows what is known of it.
        if let Command::TerminalLine { unreliable: true, .. } = command {
            reasons.push(
                "the line was edited with keys Remotely can't follow (Tab, arrow keys, history) or had text on it \
                 already, so the terminals may run something else"
                    .into(),
            );
            if tier < Tier::Medium {
                reasons.push(format!("{} -> {}", tier.as_str(), Tier::Medium.as_str()));
                tier = Tier::Medium;
            }
        }

        // SS-07: loopback belongs to everyone signed in to this PC, so on a shared jump server a SOCKS tunnel on
        // 127.0.0.1 lets any of them reach whatever the host reaches. At least Medium while others are signed in.
        if let Command::OpenTunnel { forward, .. } = command {
            if forward.spec.kind == ForwardKind::Dynamic && forward.spec.loopback_only() && self.other_users > 0 {
                let who = match self.other_users {
                    1 => "1 other user is".to_owned(),
                    n => format!("{n} other users are"),
                };
                reasons.push(format!(
                    "{who} signed in to this PC, and a SOCKS tunnel on its loopback is theirs to use too"
                ));
                if tier < Tier::Medium {
                    reasons.push(format!("{} -> {}", tier.as_str(), Tier::Medium.as_str()));
                    tier = Tier::Medium;
                }
            }
        }

        if self.rules.prod_bump && active.iter().any(|t| t.environment == Environment::Prod) {
            let bumped = tier.bump();
            if bumped != tier {
                reasons.push(format!(
                    "a target is labelled Prod: {} -> {}",
                    tier.as_str(),
                    bumped.as_str()
                ));
            }
            tier = bumped;
        }

        if !skipped.is_empty() {
            reasons.push(format!("{} protected target(s) skipped", skipped.len()));
        }

        let steps = self.steps_for(tier, command, active.len());
        Decision {
            action,
            tier,
            steps,
            targets: active,
            skipped,
            reasons,
            warnings: Vec::new(),
            script_kinds,
        }
    }

    fn steps_for(&self, tier: Tier, command: &Command, target_count: usize) -> Vec<ApprovalStep> {
        match tier {
            Tier::Low => vec![],
            Tier::Medium => vec![ApprovalStep::Confirm],
            Tier::High | Tier::Critical => {
                let mut steps = vec![ApprovalStep::ImpactPreview];
                if safety_snapshot_applies(command) {
                    steps.push(ApprovalStep::SafetySnapshot {
                        default_on: self.rules.safety_snapshot_default,
                    });
                }
                steps.push(ApprovalStep::TypeTargetCount { expected: target_count });
                steps.push(ApprovalStep::Reason);
                steps.push(ApprovalStep::ChangeId { required: false });
                steps.push(ApprovalStep::Countdown {
                    seconds: self.rules.countdown_seconds,
                });
                if tier == Tier::Critical {
                    steps.push(ApprovalStep::VaultReauth);
                }
                steps
            }
        }
    }
}

/// VM-02, VM-03 (and VM-08's instance power): the action a power operation is.
pub fn power_kind(op: &PowerOp) -> ActionKind {
    match op {
        PowerOp::Start { .. } => ActionKind::VmStart,
        PowerOp::Unpause => ActionKind::VmUnpause,
        PowerOp::Pause => ActionKind::VmPause,
        PowerOp::Suspend => ActionKind::VmSuspend,
        PowerOp::Reset { mode: StopMode::Soft } => ActionKind::VmResetSoft,
        PowerOp::Reset { mode: StopMode::Hard } => ActionKind::VmResetHard,
        PowerOp::Stop { mode: StopMode::Soft } => ActionKind::VmStopSoft,
        PowerOp::Stop { mode: StopMode::Hard } => ActionKind::VmStopHard,
    }
}

/// FD-03: while presenting with the read-only lock on, the bus refuses every command, whatever its tier, targets or
/// labels: each one changes a VM, a host or the app (reads never reach the bus). That includes read-only remote
/// commands, which run programs on customer hosts, and MultiExec lines. The refusal names the action as Settings
/// does. With the lock off, nothing changes here and the tiers apply as usual.
pub fn read_only_refusal(locked: bool, action: ActionKind) -> Result<()> {
    if locked {
        return Err(CoreError::ReadOnlyLock {
            what: action.label().to_owned(),
        });
    }
    Ok(())
}

/// FD-03: the same for edits of the app's own data, which skip the bus (sessions, settings, the vault, imports...).
pub fn read_only_edit_refusal(locked: bool, change: Change) -> Result<()> {
    if locked {
        return Err(CoreError::ReadOnlyLock {
            what: change.label().to_owned(),
        });
    }
    Ok(())
}

/// VM-05: a safety snapshot is offered (when the tier is High or Critical) for the VM actions that
/// can lose what the guest is doing: stop, reset, suspend and revert. The rest have nothing to undo
/// (start, pause, unpause), are snapshots themselves (take), would undo their own purpose (deleting
/// snapshots to free space would add one per VM; the deleted snapshot is not in it anyway) or do not
/// touch the VM (protect). The job runner asks this too, so the dialog and the job always agree.
///
/// VM-23, VM-15: a snapshot keeps a VM's settings too, so it undoes a settings change (a hardware upgrade
/// included) and an install of the guest tools; renaming has nothing to undo. Disk changes are refused while
/// the VM has snapshots (expand, compact, remove) or don't need one (add), a deleted VM takes its snapshots
/// with it, and ISOs and cables change nothing a snapshot would keep.
pub fn safety_snapshot_applies(command: &Command) -> bool {
    let on_vms = command.targets().iter().any(|t| matches!(t, TargetRef::Vm { .. }));
    let can_lose_state = match command {
        Command::VmPower { op, .. } => matches!(op, PowerOp::Stop { .. } | PowerOp::Reset { .. } | PowerOp::Suspend),
        // VM-08: an instance's shut down or suspend is the power action on its VMs; a deploy's VMs don't exist yet,
        // and a teardown deletes the VMs with their snapshots.
        Command::Stack {
            op: StackOp::Power { spec },
            ..
        } => matches!(spec.op, PowerOp::Stop { .. } | PowerOp::Suspend),
        Command::Stack { .. } => false,
        Command::VmSnapshot { op, .. } => matches!(op, SnapshotOp::Revert { .. }),
        Command::VmConfig { edit, .. } => !matches!(edit, VmConfigEdit::Rename { .. }),
        Command::VmDevice { op, .. } => matches!(op, VmDeviceOp::InstallTools),
        Command::VmDisk { .. } | Command::VmLifecycle { .. } => false,
        Command::VmProtect { .. }
        | Command::RemoteExec { .. }
        | Command::AppUpdate { .. }
        | Command::PushSshKey { .. }
        | Command::RemoveSshKey { .. }
        | Command::TerminalLine { .. }
        | Command::FileUpload { .. }
        | Command::OpenTunnel { .. }
        | Command::Container { .. }
        // VM-11: a forward is the network's (or a NAT adapter's) setting; a snapshot of the guest wouldn't undo it.
        | Command::HostNetwork { .. }
        // VM-21: the VMs don't exist yet, and a clone's source is only read.
        | Command::Deploy { .. }
        // CV-03, VM-17: the source is only read.
        | Command::ImageConvert { .. }
        | Command::VmExport { .. }
        // FD-04: commands on hosts, never VMs.
        | Command::SupportBundle { .. }
        // FD-09: a wake-up starts a machine that is off; there is nothing in it to lose. The file server runs on this
        // PC.
        | Command::WakeOnLan { .. }
        | Command::FileServer { .. } => false,
    };
    on_vms && can_lose_state
}
