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

    #[error("the vault is locked")]
    VaultLocked,

    #[error("invalid setting: {0}")]
    InvalidSetting(String),

    #[error("cancelled")]
    Cancelled,

    #[error("update failed: {0}")]
    Update(String),

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
            CoreError::InvalidSetting(_) => "invalid_setting",
            CoreError::Cancelled => "cancelled",
            CoreError::Update(_) => "update_failed",
            CoreError::NotImplemented(_) => "not_implemented",
        }
    }
}
