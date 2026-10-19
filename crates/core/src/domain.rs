//! Types shared by every module.
//!
//! Every persisted record carries a [`Context`] (workspace + user) from day one, so customer
//! workspaces (FD-02) need no data migration later.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Who is acting, and in which workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Context {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
}

/// Environment label on a session or VM (SS-06). Prod raises the approval tier by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    #[default]
    None,
    Lab,
    Staging,
    Prod,
}

impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::None => "none",
            Environment::Lab => "lab",
            Environment::Staging => "staging",
            Environment::Prod => "prod",
        }
    }

    /// Unknown labels map to `None` rather than failing a read.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "lab" => Environment::Lab,
            "staging" => Environment::Staging,
            "prod" => Environment::Prod,
            _ => Environment::None,
        }
    }
}

/// A VM's power state as the inventory last saw it (VM-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    /// vmrun could not be asked (Workstation not found).
    #[default]
    Unknown,
    Running,
    NotRunning,
    Suspended,
    /// Running but paused. vmrun cannot report it, so it comes from the app's own pause jobs.
    Paused,
}

impl PowerState {
    pub fn as_str(self) -> &'static str {
        match self {
            PowerState::Unknown => "unknown",
            PowerState::Running => "running",
            PowerState::NotRunning => "not_running",
            PowerState::Suspended => "suspended",
            PowerState::Paused => "paused",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "running" => PowerState::Running,
            "not_running" => PowerState::NotRunning,
            "suspended" => PowerState::Suspended,
            "paused" => PowerState::Paused,
            _ => PowerState::Unknown,
        }
    }

    /// Running or paused: the VM holds its assigned RAM (VM-07).
    pub fn is_on(self) -> bool {
        matches!(self, PowerState::Running | PowerState::Paused)
    }
}

/// Something the app can act on, as a caller names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TargetRef {
    /// A Workstation VM, identified by its .vmx path (what vmrun takes).
    Vm { vmx_path: String },
    /// A saved SSH session (SS-01).
    Session { session_id: Uuid },
    /// This app itself, e.g. installing an update (FD-14).
    App,
    /// SS-10: an open terminal pane, for a MultiExec line typed into several at once. The command bus
    /// fills in `session_id` (the saved session behind it, `None` for a quick connection that was not
    /// saved), so the audit log names the sessions; the key is the terminal.
    Terminal {
        terminal_id: Uuid,
        #[serde(default)]
        session_id: Option<Uuid>,
    },
}

impl TargetRef {
    pub fn kind(&self) -> &'static str {
        match self {
            TargetRef::Vm { .. } => "vm",
            TargetRef::Session { .. } => "session",
            TargetRef::App => "app",
            TargetRef::Terminal { .. } => "terminal",
        }
    }

    /// Stable key for journals and the audit log.
    pub fn key(&self) -> String {
        match self {
            TargetRef::Vm { vmx_path } => vmx_path.clone(),
            TargetRef::Session { session_id } => session_id.to_string(),
            TargetRef::App => "app".to_owned(),
            TargetRef::Terminal { terminal_id, .. } => terminal_id.to_string(),
        }
    }
}

/// A target after the command bus has looked it up: what the policy engine needs to pick a tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub target: TargetRef,
    pub name: String,
    pub environment: Environment,
    /// "Do not touch" (AP-04): actions skip it until it is unlocked.
    pub protected: bool,
}

pub(crate) fn now_rfc3339() -> String {
    let now = time::OffsetDateTime::now_utc();
    // Formatting the current UTC time as RFC 3339 does not fail; fall back to Unix seconds if it ever did.
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}
