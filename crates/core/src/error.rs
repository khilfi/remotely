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

    #[error("every target is protected (AP-04); unlock one first")]
    AllTargetsProtected,

    #[error("unknown target: {0}")]
    UnknownTarget(String),

    #[error("{action} cannot run on {target}")]
    WrongTargetKind { action: String, target: String },

    #[error("no pending approval with id {0}")]
    UnknownApproval(Uuid),

    #[error("approval rejected: {0}")]
    ApprovalRejected(String),

    #[error("the vault is locked. Unlock it on the Vault page")]
    VaultLocked,

    /// SS-04, AP-06: no vault yet, so there is no password for Critical actions to ask for.
    #[error("the vault is not set up yet. Set it up on the Vault page: Critical actions ask for its password")]
    VaultNotSetUp,

    #[error("wrong vault password")]
    WrongVaultPassword,

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
        "the GitHub update token can't read the releases of {repo}. Make a fine-grained token for that repository with Contents: Read-only, and replace it in Settings, under Updates"
    )]
    UpdateTokenNoAccess { repo: String },
    /// FD-14: checking and installing updates read the private repo's releases with a token.
    #[error("there is no GitHub update token in the vault. Add one in Settings, under Updates")]
    UpdateTokenMissing,

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

    /// BX-04: cancelled while the command was running on the host. The connection is closed, but the
    /// host may still finish the command.
    #[error("cancelled while the command was running; it may still finish on the host")]
    CancelledRemote,

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

    /// CT-01, CT-02: a container CLI could not do what was asked. The message says why in words and
    /// never holds a secret, a log line or an environment value.
    #[error("{message}")]
    Container { problem: ContainerProblem, message: String },
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
    /// Stable machine-readable code for the UI.
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::VmrunNotFound => "vmrun_not_found",
            CoreError::Vmrun { .. } => "vmrun_failed",
            CoreError::Timeout { .. } => "timeout",
            CoreError::PowerTimeout { .. } => "power_timeout",
            CoreError::ToolsNotRunning { .. } => "tools_not_running",
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
            CoreError::VaultLocked => "vault_locked",
            CoreError::VaultNotSetUp => "vault_not_set_up",
            CoreError::WrongVaultPassword => "wrong_vault_password",
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
            CoreError::Ssh(_) => "ssh",
            CoreError::AuthFailed(_) => "auth_failed",
            CoreError::AgentUnavailable(_) => "agent_unavailable",
            CoreError::HostKeyChanged { .. } => "host_key_changed",
            CoreError::HostKeyRejected { .. } => "host_key_rejected",
            CoreError::HostKeyUnknown { .. } => "host_key_unknown",
            CoreError::SudoPasswordRefused => "sudo_password_refused",
            CoreError::NoSudoPassword(_) => "no_sudo_password",
            CoreError::CancelledRemote => "cancelled_remote",
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
            CoreError::Container { problem, .. } => problem.code(),
        }
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
            "the GitHub update token expired on {date}. Make a new one and replace it in Settings, under Updates"
        ),
        None => "GitHub refused the update token: it was revoked, has expired or was mistyped. Make a new one and replace it in Settings, under Updates".into(),
    }
}
