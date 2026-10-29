use uuid::Uuid;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(
        "vmrun.exe was not found. Install VMware Workstation Pro 17 or later, or set REMOTELY_VMRUN to its full path."
    )]
    VmrunNotFound,

    #[error("vmrun {command} failed: {message}")]
    Vmrun { command: String, message: String },

    #[error("{command} timed out after {seconds}s")]
    Timeout { command: String, seconds: u64 },

    /// VM-02: a vmrun power call did not return in time. Workstation holds a VM's power calls while
    /// that VM waits for an answer to a question or message.
    #[error(
        "vmrun {command} got no answer within {seconds} s. The VM may be waiting for a reply to a message in Workstation: open it there to check"
    )]
    PowerTimeout { command: String, seconds: u64 },

    /// VM-02: a graceful restart or suspend goes through VMware Tools, and vmrun waits for Tools
    /// rather than failing when they are not running, so the job runner checks first.
    #[error("{tools}, so it can't {action} gracefully. {advice}")]
    ToolsNotRunning {
        /// What Workstation says about VMware Tools in the guest.
        tools: String,
        action: &'static str,
        /// What the user can do instead.
        advice: &'static str,
    },

    /// VM-18: VirtualBox is not installed, or VBoxManage.exe is not where Settings says. The VM list
    /// just has no VirtualBox VMs then; only an action on one says this.
    #[error(
        "VBoxManage.exe was not found. Install Oracle VirtualBox 7.0 or later, or set its path in Settings (or REMOTELY_VBOXMANAGE)."
    )]
    VboxManageNotFound,

    /// VM-18: VBoxManage answered with an error; `message` is its own text.
    #[error("VBoxManage {command} failed: {message}")]
    VboxManage { command: String, message: String },

    /// VM-18: a VBoxManage power call did not return in time.
    #[error(
        "VBoxManage {command} got no answer within {seconds} s. The VM may be busy or waiting for an answer in VirtualBox: open it there to check"
    )]
    VboxPowerTimeout { command: String, seconds: u64 },

    /// VM-18, BX-04: cancelled while its VBoxManage power call was running. VBoxManage is stopped, but
    /// VirtualBox may still carry out what it was asked.
    #[error("cancelled while VBoxManage was running; VirtualBox may still finish the action, so check the VM's state")]
    VboxCancelledInFlight,

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("database migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid policy rule '{name}': {message}")]
    InvalidRule { name: String, message: String },

    #[error("the command has no targets")]
    NoTargets,

    #[error("every target is Protected; remove Protected from one first")]
    AllTargetsProtected,

    #[error("unknown target: {0}")]
    UnknownTarget(String),

    #[error("{action} cannot run on {target}")]
    WrongTargetKind { action: String, target: String },

    #[error("no pending approval with id {0}")]
    UnknownApproval(Uuid),

    #[error("approval rejected: {0}")]
    ApprovalRejected(String),

    /// AP-01: the approval waited longer than [`crate::command_bus::APPROVAL_TTL`], so what it showed may be
    /// out of date. Nothing ran; start the action again.
    #[error(
        "this approval waited more than {}, so it expired and nothing ran. Start the action again to see what it would do now",
        in_minutes(*.minutes)
    )]
    ApprovalExpired { minutes: u64 },

    /// AP-01: a target became Prod or protected after the approval was asked, so it is asked again. `request`
    /// is the new approval (same id); nothing ran.
    #[error("{changes} since this approval was asked, so it needs approving again. Check the updated approval")]
    ApprovalChanged {
        changes: String,
        request: Box<crate::command_bus::ApprovalRequest>,
    },

    /// VM-14, VM-27: something changed since a schedule was approved (it was edited, a target became Prod or
    /// protected or is new, the approval rules changed), so its run did not start and it waits to be approved again.
    #[error("{changes} since the schedule was approved, so it waits to be approved again")]
    StandingChanged { changes: String },

    #[error("the vault is locked. Unlock it on the Vault page")]
    VaultLocked,

    /// SS-04, AP-06: no vault yet, so there is no password for Critical actions to ask for.
    #[error("the vault is not set up yet. Set it up on the Vault page: Critical actions ask for its password")]
    VaultNotSetUp,

    #[error("wrong vault password")]
    WrongVaultPassword,

    /// SS-04, AP-06: the step would send a vault password somewhere it has not gone before (or loosen
    /// the approval rules), so the master password is asked again. The UI asks for it and sends the
    /// same request again with it. `reason` names what would happen, never a value.
    #[error("{reason}. Enter the vault password to go ahead")]
    ReauthRequired { reason: String },

    /// FD-07: an export file did not open. AES-GCM can't tell a wrong passphrase from a changed file.
    #[error("the passphrase is wrong, or the file was changed or damaged after it was exported")]
    WrongPassphrase,

    /// Never holds a secret: only what went wrong.
    #[error("vault: {0}")]
    Vault(String),

    #[error("invalid setting: {0}")]
    InvalidSetting(String),

    #[error("{0}")]
    InvalidInput(String),

    /// VM-03: a soft stop did not shut the VM down. Forcing it off is a separate, Critical command.
    #[error("still running: {reason}. Power it off (hard) to force it; that needs its own approval")]
    StillRunning { reason: String },

    /// VM-05: the safety snapshot could not be taken, so the action did not run on this VM.
    #[error("the safety snapshot failed, so nothing else was done to this VM: {0}")]
    SafetySnapshotFailed(String),

    #[error("cancelled")]
    Cancelled,

    /// BX-04: cancelled while its vmrun power call was running. vmrun is stopped, but Workstation
    /// may still carry out what it was asked.
    #[error("cancelled while vmrun was running; Workstation may still finish the action, so check the VM's state")]
    CancelledInFlight,

    #[error("update failed: {0}")]
    Update(String),
    /// FD-14: GitHub refused the update token (401): expired, revoked or mistyped. Never holds it.
    #[error("{}", token_refused(.expired_on.as_deref()))]
    UpdateTokenRefused {
        /// When the token's remembered expiry date has passed, so the message can say so.
        expired_on: Option<String>,
    },
    /// FD-14: the token works, but can't read the releases of `repo`.
    #[error(
        "the GitHub update token can't read the releases of {repo}. Make a fine-grained token for that repository with Contents: Read-only and replace it in Settings, under Updates, or remove it there to check without a token"
    )]
    UpdateTokenNoAccess { repo: String },
    /// FD-14: Settings' Test needs a token to test.
    #[error("there is no GitHub update token in the vault. Add one in Settings, under Updates")]
    UpdateTokenMissing,
    /// FD-14: without a token GitHub doesn't show the releases of `repo` (404), so it is private again (or gone).
    #[error(
        "GitHub doesn't show the releases of {repo} without a token, so the repository may be private again. Add a GitHub update token in Settings, under Updates"
    )]
    UpdateTokenNeeded { repo: String },
    /// FD-14: GitHub's API limit is used up (403 or 429). No call goes to GitHub before `until` (RFC 3339, UTC).
    #[error("{}", rate_limited(.until, *.with_token))]
    UpdateRateLimited {
        until: String,
        /// The token's limit (5,000 calls an hour), not the one for calls without a token (60 an hour per
        /// internet address).
        with_token: bool,
    },

    /// SS-03: reaching or talking to an SSH server failed. Never holds a secret.
    #[error("{0}")]
    Ssh(String),

    /// SS-03: the server refused the login. Names the method and user, never a secret.
    #[error("login failed: {0}")]
    AuthFailed(String),

    /// SS-03: agent login, but no agent (or no key in it).
    #[error("{0}")]
    AgentUnavailable(String),

    /// SS-05: the server presented a different key than the one trusted for it. Blocked. `jump`: SS-07,
    /// the jump host that presented it, when it was one on the way.
    #[error(
        "the host key of {} has changed, so Remotely did not connect. Someone may be intercepting the connection, or the host was reinstalled",
        key_place(address, jump.as_deref())
    )]
    HostKeyChanged { address: String, jump: Option<String> },

    /// SS-05: the user did not trust a new host key.
    #[error("the host key of {} was not trusted, so Remotely did not connect", key_place(address, jump.as_deref()))]
    HostKeyRejected { address: String, jump: Option<String> },

    /// BX-02: a bulk run can't ask about a host key it has not seen, and the run did not say to trust
    /// new ones.
    #[error(
        "the host key of {} is not trusted yet. Connect to it once in a terminal to check and trust it, or tick 'Trust new host keys' for the run",
        key_place(address, jump.as_deref())
    )]
    HostKeyUnknown { address: String, jump: Option<String> },

    /// BX-07: sudo did not take the password from the vault. Never holds the password.
    #[error("sudo refused the password from the vault")]
    SudoPasswordRefused,

    /// BX-07: a sudo run, but no password to give sudo for this session.
    #[error("{0}")]
    NoSudoPassword(String),

    /// MO-02, CT-01: a background login (or sudo) failed in a way retrying can't fix, so it is not
    /// tried again until something changes or the user presses Retry ([`crate::login_guard`]). The
    /// message ends by saying so. Never holds a secret.
    #[error("{message}")]
    LoginParked { message: String },

    /// MO-02, CT-01: the hourly cap on background logins to one host was reached.
    #[error("{message}")]
    LoginsCapped { message: String, wait_secs: u64 },

    /// BX-04: cancelled while the command was running on the host. The connection is closed, but the
    /// host may still finish the command.
    #[error("cancelled while the command was running; it may still finish on the host")]
    CancelledRemote,

    /// H9: a bulk run's host did not finish within the run's time limit. The connection is closed, but
    /// the command may have started and may still finish, so its outcome is unknown.
    #[error("the command did not finish within {seconds} s; it may have run, or may still finish, on the host")]
    CommandTimedOut { seconds: u64 },

    /// SS-07: a session's jump hosts lead back to one of them, or go on for too many hops.
    #[error("{0}")]
    JumpChain(String),

    /// SS-07: a port forward could not start: its port is taken on this PC, or the host refused to
    /// listen. Never holds traffic.
    #[error("{0}")]
    Tunnel(String),

    /// QL-06: the terminal's last line is no password prompt, so a vault password was not typed: at a
    /// shell prompt it would run as a command and land in the shell's history.
    #[error(
        "the terminal is not showing a password prompt, so the password was not typed: at a shell prompt it would land on the command line"
    )]
    NoPasswordPrompt,

    /// QL-03, QL-04: a DNS lookup or a reachability probe failed. Never holds a secret.
    #[error("{0}")]
    Network(String),

    /// SS-08: the host refused a file operation for the logged-in user. Transfers never use sudo.
    #[error("{user} can't {what} {path} on the host (permission denied).{advice}")]
    RemotePermissionDenied {
        user: String,
        /// "write to", "read", "open the folder".
        what: &'static str,
        path: String,
        /// What to do instead, starting with a space; may be empty.
        advice: &'static str,
    },

    /// SS-08: an upload that was not asked to replace found a file there.
    #[error(
        "{path} already exists on the host, so it was not replaced. Upload it again to choose whether to replace it"
    )]
    RemoteFileExists { path: String },

    /// SS-08: nothing at that path on the host.
    #[error("{path} doesn't exist on the host")]
    RemoteNotFound { path: String },

    /// SS-08: SFTP failed: the host has no SFTP server, the channel closed, or the host reported an
    /// error. Never holds a secret or file content.
    #[error("{0}")]
    Sftp(String),

    /// FD-03: presentation mode's read-only lock refused a change. `what` is the action or edit, as Settings and the
    /// audit log name it.
    #[error("read-only while presenting: \"{what}\" is blocked until the read-only lock is turned off")]
    ReadOnlyLock { what: String },

    #[error("not implemented yet ({0})")]
    NotImplemented(&'static str),

    /// VM-16: vmware-vdiskmanager.exe is not beside vmrun.exe (nor where `REMOTELY_VDISKMANAGER` says).
    #[error(
        "vmware-vdiskmanager.exe was not found next to vmrun.exe. It comes with VMware Workstation Pro: repair the install, or set REMOTELY_VDISKMANAGER to its full path"
    )]
    VdiskManagerNotFound,

    /// VM-16: vmware-vdiskmanager answered with an error; `message` is its own text.
    #[error("vmware-vdiskmanager {command} failed: {message}")]
    VdiskManager { command: String, message: String },

    /// VM-23, VM-24: a VM setting or lifecycle change that can't be done on this VM now, and why in words:
    /// it is running, it has snapshots, the hypervisor has no such setting, a file is not there...
    #[error("{0}")]
    VmSettingRefused(String),

    /// VM-11: a port forward change that can't be made here or now, and why in words: Workstation's NAT forwards
    /// need administrator rights, the host port is taken, the rule is gone...
    #[error("{0}")]
    HostNetworkRefused(String),

    /// VM-04, VM-21, VM-24: deleting a snapshot or a VM would break the linked clones made from it (they share its
    /// disk as it was at the snapshot); the message names the VM, what would go and the clones.
    #[error("{0}")]
    LinkedClones(String),

    /// FD-02: a VM, session, terminal or other record that belongs to another workspace or to none, named the way
    /// the caller named it. Nothing of another workspace is said.
    #[error("{0} is not in this workspace")]
    NotInWorkspace(String),

    /// FD-02: a VM no workspace has (the VMs page's Unassigned, or one Remotely never found). Nothing acts on it, or
    /// reads it by its key, until a workspace adds it; nothing adds it by itself.
    #[error("{0} isn't in any workspace: add it to this workspace first (VMs page: Unassigned, or Add VM…)")]
    VmUnassigned(String),

    /// FD-02: no workspace of this user has that id.
    #[error("that workspace doesn't exist")]
    UnknownWorkspace,

    /// FD-02: a workspace can't be switched while jobs started from it are still open; the message says how many.
    #[error(
        "{open} still open in this workspace: wait for {them} to finish, or cancel {them} in Activity, then switch"
    )]
    WorkspaceBusy { open: String, them: &'static str },

    /// VM-21: ovftool.exe (the OVFTool folder next to vmrun.exe, `REMOTELY_OVFTOOL` or the Settings path) is not
    /// there, so an OVA or OVF can't be imported into Workstation.
    #[error("ovftool.exe was not found: it comes with Workstation, in its OVFTool folder. Set its path in Settings, or import the appliance into VirtualBox")]
    OvftoolNotFound,

    /// VM-21: ovftool answered with an error; `message` is its own text.
    #[error("ovftool failed: {message}")]
    Ovftool { message: String },

    /// VM-21: a VM a deploy was making failed; `message` says why and what was removed of what it had made.
    #[error("{vm} was not made: {message}")]
    DeployFailed { vm: String, message: String },

    /// CT-01, CT-02: a container CLI could not do what was asked. The message says why in words and
    /// never holds a secret, a log line or an environment value.
    #[error("{message}")]
    Container { problem: ContainerProblem, message: String },

    /// CV-01 to CV-03: a conversion needs qemu-img (qcow2, VHDX), which isn't installed. Remotely never ships it
    /// (it is GPL-licensed): the owner installs QEMU for Windows and Remotely finds it.
    #[error(
        "this needs qemu-img, which isn't installed: install QEMU for Windows (Image tools links to its download page), or set qemu-img.exe's path in Settings"
    )]
    QemuImgNotFound,

    /// CV-01 to CV-03, VM-17: a conversion tool answered with an error; `message` is its own text.
    #[error("{tool} failed: {message}")]
    ConversionTool { tool: String, message: String },

    /// CV-01 to CV-03, VM-17: a conversion or export that can't be done as asked, and why in words.
    #[error("{0}")]
    ConversionRefused(String),
}

/// CT-01, CT-02: why a container CLI failed, for the UI to offer what helps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerProblem {
    /// No `docker` or `podman` on the host (or no docker.exe on this PC).
    CliMissing,
    /// The daemon refused the user: not in the `docker` group, so it needs sudo.
    NeedsSudo,
    /// The daemon is not running (or Docker Desktop is not started).
    DaemonDown,
    /// No such container, image or volume (any more).
    NotFound,
    /// The CLI printed something Remotely can't read.
    Unreadable,
    /// Anything else the CLI reported.
    Failed,
}

impl ContainerProblem {
    pub fn code(self) -> &'static str {
        match self {
            ContainerProblem::CliMissing => "container_cli_missing",
            ContainerProblem::NeedsSudo => "container_needs_sudo",
            ContainerProblem::DaemonDown => "container_daemon_down",
            ContainerProblem::NotFound => "container_not_found",
            ContainerProblem::Unreadable => "container_unreadable",
            ContainerProblem::Failed => "container_failed",
        }
    }
}

impl CoreError {
    /// QL-15: the database could not be opened, read or migrated (at start, the shell offers to set it aside).
    pub fn is_database(&self) -> bool {
        matches!(self, CoreError::Db(_) | CoreError::Migrate(_))
    }

    /// QL-15: the database was last opened by a newer version of Remotely, which added migrations this one
    /// doesn't have (a downgrade).
    pub fn is_newer_database(&self) -> bool {
        matches!(self, CoreError::Migrate(sqlx::migrate::MigrateError::VersionMissing(_)))
    }

    /// Stable machine-readable code for the UI.
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::VmrunNotFound => "vmrun_not_found",
            CoreError::Vmrun { .. } => "vmrun_failed",
            CoreError::Timeout { .. } => "timeout",
            CoreError::PowerTimeout { .. } => "power_timeout",
            CoreError::ToolsNotRunning { .. } => "tools_not_running",
            CoreError::VboxManageNotFound => "vboxmanage_not_found",
            CoreError::VboxManage { .. } => "vboxmanage_failed",
            CoreError::VboxPowerTimeout { .. } => "power_timeout",
            CoreError::VboxCancelledInFlight => "cancelled_in_flight",
            CoreError::Db(_) | CoreError::Migrate(_) => "database",
            CoreError::Io(_) => "io",
            CoreError::Json(_) => "json",
            CoreError::InvalidRule { .. } => "invalid_rule",
            CoreError::NoTargets => "no_targets",
            CoreError::AllTargetsProtected => "all_targets_protected",
            CoreError::UnknownTarget(_) => "unknown_target",
            CoreError::WrongTargetKind { .. } => "wrong_target_kind",
            CoreError::UnknownApproval(_) => "unknown_approval",
            CoreError::ApprovalRejected(_) => "approval_rejected",
            CoreError::ApprovalExpired { .. } => "approval_expired",
            CoreError::ApprovalChanged { .. } => "approval_changed",
            CoreError::StandingChanged { .. } => "standing_changed",
            CoreError::VaultLocked => "vault_locked",
            CoreError::VaultNotSetUp => "vault_not_set_up",
            CoreError::WrongVaultPassword => "wrong_vault_password",
            CoreError::ReauthRequired { .. } => "reauth_required",
            CoreError::WrongPassphrase => "wrong_passphrase",
            CoreError::Vault(_) => "vault",
            CoreError::InvalidSetting(_) => "invalid_setting",
            CoreError::InvalidInput(_) => "invalid_input",
            CoreError::StillRunning { .. } => "still_running",
            CoreError::SafetySnapshotFailed(_) => "safety_snapshot_failed",
            CoreError::Cancelled => "cancelled",
            CoreError::CancelledInFlight => "cancelled_in_flight",
            CoreError::Update(_) => "update_failed",
            CoreError::UpdateTokenRefused { .. } => "update_token_refused",
            CoreError::UpdateTokenNoAccess { .. } => "update_token_no_access",
            CoreError::UpdateTokenMissing => "update_token_missing",
            CoreError::UpdateTokenNeeded { .. } => "update_token_needed",
            CoreError::UpdateRateLimited { .. } => "update_rate_limited",
            CoreError::Ssh(_) => "ssh",
            CoreError::AuthFailed(_) => "auth_failed",
            CoreError::AgentUnavailable(_) => "agent_unavailable",
            CoreError::HostKeyChanged { .. } => "host_key_changed",
            CoreError::HostKeyRejected { .. } => "host_key_rejected",
            CoreError::HostKeyUnknown { .. } => "host_key_unknown",
            CoreError::SudoPasswordRefused => "sudo_password_refused",
            CoreError::NoSudoPassword(_) => "no_sudo_password",
            CoreError::LoginParked { .. } => "login_parked",
            CoreError::LoginsCapped { .. } => "logins_capped",
            CoreError::CancelledRemote => "cancelled_remote",
            CoreError::CommandTimedOut { .. } => "command_timed_out",
            CoreError::JumpChain(_) => "jump_chain",
            CoreError::Tunnel(_) => "tunnel",
            CoreError::NoPasswordPrompt => "no_password_prompt",
            CoreError::Network(_) => "network",
            CoreError::RemotePermissionDenied { .. } => "permission_denied",
            CoreError::RemoteFileExists { .. } => "file_exists",
            CoreError::RemoteNotFound { .. } => "not_found",
            CoreError::Sftp(_) => "sftp",
            CoreError::ReadOnlyLock { .. } => "read_only_lock",
            CoreError::NotImplemented(_) => "not_implemented",
            CoreError::VdiskManagerNotFound => "vdiskmanager_not_found",
            CoreError::VdiskManager { .. } => "vdiskmanager_failed",
            CoreError::VmSettingRefused(_) => "vm_setting_refused",
            CoreError::LinkedClones(_) => "linked_clones",
            CoreError::NotInWorkspace(_) => "not_in_workspace",
            CoreError::VmUnassigned(_) => "vm_unassigned",
            CoreError::UnknownWorkspace => "unknown_workspace",
            CoreError::WorkspaceBusy { .. } => "workspace_busy",
            CoreError::HostNetworkRefused(_) => "host_network_refused",
            CoreError::OvftoolNotFound => "ovftool_not_found",
            CoreError::Ovftool { .. } => "ovftool_failed",
            CoreError::DeployFailed { .. } => "deploy_failed",
            CoreError::Container { problem, .. } => problem.code(),
            CoreError::QemuImgNotFound => "qemu_img_not_found",
            CoreError::ConversionTool { .. } => "conversion_failed",
            CoreError::ConversionRefused(_) => "conversion_refused",
        }
    }
}

/// AP-01: `1 minute`, `15 minutes`.
pub(crate) fn in_minutes(n: u64) -> String {
    if n == 1 {
        "1 minute".to_owned()
    } else {
        format!("{n} minutes")
    }
}

/// SS-07: `bastion.example.com:22`, or `the jump host 'bastion' (bastion.example.com:22)`.
fn key_place(address: &str, jump: Option<&str>) -> String {
    match jump {
        Some(name) => format!("the jump host '{name}' ({address})"),
        None => address.to_owned(),
    }
}

/// FD-14: GitHub answers 401 for an expired, revoked or mistyped token alike; the expiry date GitHub
/// reported earlier tells the first apart.
fn token_refused(expired_on: Option<&str>) -> String {
    match expired_on {
        Some(date) => format!(
            "the GitHub update token expired on {date}. Make a new one and replace it in Settings, under Updates, or remove it there to check without a token"
        ),
        None => "GitHub refused the update token: it was revoked, has expired or was mistyped. Make a new one and replace it in Settings, under Updates, or remove it there to check without a token".into(),
    }
}

/// `until` is RFC 3339 in UTC; the message names its time of day.
fn rate_limited(until: &str, with_token: bool) -> String {
    let at = match until.get(11..16) {
        Some(time) => format!("until {time} UTC"),
        None => "for now".into(),
    };
    match with_token {
        true => format!("GitHub's API limit for the update token is used up {at}. Remotely checks again after that"),
        false => format!(
            "GitHub's limit for update checks without a token (60 an hour from one internet address) is used up {at}. Remotely checks again after that; a GitHub update token, in Settings under Updates, has a limit of its own"
        ),
    }
}
