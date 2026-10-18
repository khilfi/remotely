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

    /// SS-03: reaching or talking to an SSH server failed. Never holds a secret.
    #[error("{0}")]
    Ssh(String),

    /// SS-03: the server refused the login. Names the method and user, never a secret.
    #[error("login failed: {0}")]
    AuthFailed(String),

    /// SS-03: agent login, but no agent (or no key in it).
    #[error("{0}")]
    AgentUnavailable(String),

    /// SS-05: the server presented a different key than the one trusted for it. Blocked.
    #[error(
        "the host key of {address} has changed, so Remotely did not connect. Someone may be intercepting the connection, or the host was reinstalled"
    )]
    HostKeyChanged { address: String },

    /// SS-05: the user did not trust a new host key.
    #[error("the host key of {address} was not trusted, so Remotely did not connect")]
    HostKeyRejected { address: String },

    /// SS-07 is v2: a session with a jump host is not connected directly.
    #[error(
        "this session connects through the jump host '{jump}'. Jump hosts arrive in a later version (SS-07), so Remotely doesn't connect to it directly"
    )]
    JumpHostUnsupported { jump: String },

    #[error("not implemented yet ({0})")]
    NotImplemented(&'static str),
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
            CoreError::Vault(_) => "vault",
            CoreError::InvalidSetting(_) => "invalid_setting",
            CoreError::InvalidInput(_) => "invalid_input",
            CoreError::StillRunning { .. } => "still_running",
            CoreError::SafetySnapshotFailed(_) => "safety_snapshot_failed",
            CoreError::Cancelled => "cancelled",
            CoreError::CancelledInFlight => "cancelled_in_flight",
            CoreError::Update(_) => "update_failed",
            CoreError::Ssh(_) => "ssh",
            CoreError::AuthFailed(_) => "auth_failed",
            CoreError::AgentUnavailable(_) => "agent_unavailable",
            CoreError::HostKeyChanged { .. } => "host_key_changed",
            CoreError::HostKeyRejected { .. } => "host_key_rejected",
            CoreError::JumpHostUnsupported { .. } => "jump_host_unsupported",
            CoreError::NotImplemented(_) => "not_implemented",
        }
    }
}
