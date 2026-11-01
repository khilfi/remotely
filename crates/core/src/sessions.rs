//! Session library (SS-01, SS-06): saved sessions in folders, with tags, colours, search and an
//! environment label. SS-12: each session has a kind ([`kinds::SessionKind`]): SSH, RDP, VNC, Telnet or serial.
//!
//! A session stores where to connect and how to log in: host, port, user, auth method (a password or
//! a private key from the vault, or the SSH agent), a jump host (another session) and a startup
//! command. Credentials are vault IDs, never values. Creating, editing and organising sessions changes
//! only the app's own data, so it skips the command bus and has no approval tier; every change is
//! audited like a setting. Connecting comes with the terminal (SS-03).
//!
//! The environment label (SS-06) is what the policy engine reads for a session target: Prod raises
//! the approval tier by one (see `inventory::StoreDirectory`).
//!
//! The VM a session reaches (BX-01) is chosen in the editor or linked automatically by IP address
//! (QL-01, [`crate::vm_links`]): a new session, or one whose host changed, is linked right after it
//! is saved.
//!
//! The Terminal page shows the same library as a tree ([`tree`], QL-04), and each session keeps what
//! its last connection saw (QL-03) and when it was last opened (QL-02 Recent sessions).

pub mod defaults;
pub mod kinds;
pub mod tree;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::remote::{AuthMethod, Credentials, SessionSpec};
use crate::command_bus::Command;
use crate::domain::{Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::policy::{ActionKind, PolicyEngine, Tier};
use crate::presentation::Change;
use crate::store::{clean_name, NewAuditEntry, Store, MAX_TAG_LEN};
use crate::vault::{Destination, SecretBindings, SecretId, SecretKind, SecretString, Vault};
use crate::vm_links::{AutoLinkReport, VmLink, VmLinks};
pub use defaults::{Effective, FolderDefaults, Folders, FromFolder, Inherited, InheritedTag, OwnValues};
pub use kinds::SessionKind;
use tree::{SessionTree, TreeGrouping};

/// Colour of a session's tab and list entry (SS-01). Named, so each theme can draw it legibly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionColor {
    Red,
    Orange,
    Amber,
    Green,
    Teal,
    Blue,
    Violet,
    Pink,
    Slate,
}

impl SessionColor {
    pub const ALL: [SessionColor; 9] = [
        SessionColor::Red,
        SessionColor::Orange,
        SessionColor::Amber,
        SessionColor::Green,
        SessionColor::Teal,
        SessionColor::Blue,
        SessionColor::Violet,
        SessionColor::Pink,
        SessionColor::Slate,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SessionColor::Red => "red",
            SessionColor::Orange => "orange",
            SessionColor::Amber => "amber",
            SessionColor::Green => "green",
            SessionColor::Teal => "teal",
            SessionColor::Blue => "blue",
            SessionColor::Violet => "violet",
            SessionColor::Pink => "pink",
            SessionColor::Slate => "slate",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// How a session logs in. Credentials are vault IDs; the values stay in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SessionAuth {
    /// A password from the vault. Without one, the terminal asks when it connects (SS-03).
    Password { password_id: Option<SecretId> },
    /// A private key from the vault, and its passphrase if it has one.
    Key {
        key_id: Option<SecretId>,
        passphrase_id: Option<SecretId>,
    },
    /// Keys from a running SSH agent or Pageant.
    Agent,
    /// QL-16: as the session's folders say (the nearest one that sets a login), else a password asked when
    /// connecting. Only a session's own choice: what applies to it is never this.
    Folder,
}

impl SessionAuth {
    /// The `sessions.auth_method` value; `folder` is kept as `sessions.auth_from_folder`.
    pub fn method(&self) -> &'static str {
        match self {
            SessionAuth::Password { .. } => "password",
            SessionAuth::Key { .. } => "key",
            SessionAuth::Agent => "agent",
            SessionAuth::Folder => "folder",
        }
    }

    /// The password or private key (`sessions.credential_id`).
    pub fn credential_id(&self) -> Option<SecretId> {
        match self {
            SessionAuth::Password { password_id } => *password_id,
            SessionAuth::Key { key_id, .. } => *key_id,
            SessionAuth::Agent | SessionAuth::Folder => None,
        }
    }

    /// SS-04: the vault password a host receives when this logs in (keys never leave this PC).
    pub(crate) fn sent_secret(&self) -> Option<SecretId> {
        match self {
            SessionAuth::Password { password_id } => *password_id,
            _ => None,
        }
    }

    pub fn passphrase_id(&self) -> Option<SecretId> {
        match self {
            SessionAuth::Key { passphrase_id, .. } => *passphrase_id,
            _ => None,
        }
    }

    /// For the audit log: the method and what it uses, never a value.
    fn describe(&self) -> String {
        match self {
            SessionAuth::Password { password_id: Some(_) } => "password from the vault".into(),
            SessionAuth::Password { password_id: None } => "password, asked when connecting".into(),
            SessionAuth::Key {
                key_id: Some(_),
                passphrase_id: Some(_),
            } => "key from the vault, with its passphrase".into(),
            SessionAuth::Key { key_id: Some(_), .. } => "key from the vault".into(),
            SessionAuth::Key { key_id: None, .. } => "key (none chosen)".into(),
            SessionAuth::Agent => "SSH agent".into(),
            SessionAuth::Folder => "as its folders say".into(),
        }
    }
}

/// What the session editor sends. Checked and tidied by [`SessionLibrary`] before it is saved.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInput {
    /// Empty: the host is used.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    pub auth: SessionAuth,
    /// `None`: as its folders say (QL-16), unless `jump_direct`.
    #[serde(default)]
    pub jump_session_id: Option<Uuid>,
    /// QL-16: no jump host, whatever its folders set.
    #[serde(default)]
    pub jump_direct: bool,
    #[serde(default)]
    pub startup_command: Option<String>,
    /// SS-01: type the startup command again after an automatic reconnect (off: only on connections
    /// the user opens).
    #[serde(default)]
    pub startup_on_reconnect: bool,
    /// SS-08: the folder prompt hook. `None` follows Settings (off for a Prod-labelled session).
    #[serde(default)]
    pub prompt_hook: Option<bool>,
    #[serde(default)]
    pub environment: Environment,
    #[serde(default)]
    pub color: Option<SessionColor>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// BX-01: the VM this session reaches (its `vms.id`), so a bulk run can pick the VM. A Prod or
    /// protected VM makes the session count as Prod or protected too. SSH sessions only.
    #[serde(default)]
    pub vm_id: Option<String>,
    /// SS-12: what it opens, with that kind's own fields (SSH when not given).
    #[serde(default)]
    pub kind: SessionKind,
}

fn default_port() -> u16 {
    22
}

/// A saved session. QL-16: `username`, `auth`, `jump_session_id`, `environment` and `tags` are what applies to it
/// (its own values, then its folders', then the app's defaults: [`defaults::Folders::resolve`]); `own` is what it
/// sets itself, which the editor edits, and `inherited` says which folder gives the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub id: Uuid,
    pub folder_id: Option<Uuid>,
    pub name: String,
    /// The `sessions.protocol` column: `kind`'s protocol (`ssh`, `rdp`, `vnc`, `telnet`, `serial`).
    pub protocol: String,
    /// SS-12: what it opens, with that kind's own fields.
    pub kind: SessionKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Never [`SessionAuth::Folder`].
    pub auth: SessionAuth,
    pub jump_session_id: Option<Uuid>,
    pub startup_command: Option<String>,
    /// SS-01: type the startup command again after an automatic reconnect.
    pub startup_on_reconnect: bool,
    /// SS-08: the folder prompt hook; `None` follows Settings.
    pub prompt_hook: Option<bool>,
    pub environment: Environment,
    pub color: Option<SessionColor>,
    /// AP-04: bulk actions skip it until it is unlocked.
    pub protected: bool,
    /// Tag names, sorted.
    pub tags: Vec<String>,
    /// BX-01: the VM this session reaches, if one was chosen or linked.
    pub vm_id: Option<String>,
    /// QL-01: how `vm_id` was set. `None`: no decision yet, so auto-linking may link it.
    pub vm_link: Option<VmLink>,
    /// SS-02: where it was imported from, if it was.
    pub imported_from: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// QL-03: the IP address the last connection reached.
    pub last_ip: Option<String>,
    /// QL-03: the server's own name at the last connection (`hostname`), or its DNS name when the
    /// server did not say.
    pub last_hostname: Option<String>,
    /// QL-03: when `last_ip` and `last_hostname` were seen.
    pub last_seen_at: Option<String>,
    /// QL-02: when a terminal to it was last opened (the Recent sessions list).
    pub last_opened_at: Option<String>,
    /// QL-16: what the session sets itself, of what a folder can set too.
    pub own: OwnValues,
    /// QL-16: which folder gives each value the session doesn't set itself.
    pub inherited: Inherited,
}

impl SessionRecord {
    /// QL-16: applies `effective` (from [`Folders::resolve`]) over the session's own values.
    pub(crate) fn apply(&mut self, effective: Effective) {
        self.username = effective.username;
        self.auth = effective.auth;
        self.jump_session_id = effective.jump_session_id;
        self.environment = effective.environment;
        self.tags = effective.tags;
        self.inherited = effective.inherited;
    }

    /// QL-16: what applies to it in `folders` (the session's own values first).
    pub(crate) fn resolve_in(&self, folders: &Folders) -> Effective {
        folders.resolve(Some(self.id), &self.own, self.folder_id)
    }

    /// As a command target, with the label the policy engine reads (SS-06).
    pub fn target(&self) -> Target {
        Target {
            target: TargetRef::Session { session_id: self.id },
            name: self.name.clone(),
            environment: self.environment,
            protected: self.protected,
        }
    }

    /// `alice@web01.example.com:22`; a serial session's COM port alone (`COM3`).
    pub fn address(&self) -> String {
        if !self.kind.has_port() {
            return self.host.clone();
        }
        let user = self.username.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
        format!("{user}{}:{}", self.host, self.port)
    }

    /// SS-12: refused unless the session is SSH: `needs` says what wants it ("Compare hosts runs over SSH only").
    pub fn require_ssh(&self, needs: &str) -> Result<()> {
        if self.kind.is_ssh() {
            return Ok(());
        }
        Err(CoreError::WrongSessionKind {
            session: self.name.clone(),
            kind: self.kind.label(),
            needs: needs.to_owned(),
        })
    }

    /// The editor's view of this session, to start a copy or compare an edit: what it sets itself (QL-16: not
    /// what it has from its folders).
    pub fn input(&self) -> SessionInput {
        SessionInput {
            name: self.name.clone(),
            folder_id: self.folder_id,
            host: self.host.clone(),
            port: self.port,
            username: self.own.username.clone(),
            auth: self.own.auth.clone(),
            jump_session_id: self.own.jump_session_id,
            jump_direct: self.own.jump_direct,
            startup_command: self.startup_command.clone(),
            startup_on_reconnect: self.startup_on_reconnect,
            prompt_hook: self.prompt_hook,
            environment: self.own.environment,
            color: self.color,
            tags: self.own.tags.clone(),
            vm_id: self.vm_id.clone(),
            kind: self.kind,
        }
    }
}

impl SessionInput {
    /// QL-16: the values a folder can set too, as this input sets them.
    pub fn own(&self) -> OwnValues {
        OwnValues {
            username: self.username.clone(),
            auth: self.auth.clone(),
            jump_session_id: self.jump_session_id,
            jump_direct: self.jump_direct,
            environment: self.environment,
            tags: self.tags.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionFolder {
    pub id: Uuid,
    /// `None`: at the top level.
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub sort_order: i64,
    /// QL-16: what it sets for the sessions in it and in its subfolders.
    pub defaults: FolderDefaults,
}

/// Which sessions to show (SS-01 search). Empty fields match everything; a session must match every
/// field that is set, and any one of the values listed in a field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SessionFilter {
    /// Case-insensitive text in the name, host, user, startup command or a tag.
    pub text: String,
    pub tags: Vec<String>,
    pub environments: Vec<Environment>,
    /// Only sessions in this folder or the folders under it.
    pub folder_id: Option<Uuid>,
}

impl SessionFilter {
    /// Text, tags and environment. The folder is checked by [`SessionLibrary::list`], which knows the tree.
    pub fn matches(&self, s: &SessionRecord) -> bool {
        let text = self.text.trim().to_lowercase();
        if !text.is_empty() {
            let fields = [
                Some(&s.name),
                Some(&s.host),
                s.username.as_ref(),
                s.startup_command.as_ref(),
            ];
            let hit = fields
                .into_iter()
                .flatten()
                .chain(&s.tags)
                .any(|f| f.to_lowercase().contains(&text));
            if !hit {
                return false;
            }
        }
        if !self.tags.is_empty()
            && !self
                .tags
                .iter()
                .any(|want| s.tags.iter().any(|t| t.eq_ignore_ascii_case(want.trim())))
        {
            return false;
        }
        self.environments.is_empty() || self.environments.contains(&s.environment)
    }
}

/// QL-28: the folder a bulk edit moves sessions to (`None`: the top level).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderChoice {
    #[serde(default)]
    pub folder_id: Option<Uuid>,
}

/// QL-28: the user a bulk edit sets (`None`: as their folders say).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserChoice {
    #[serde(default)]
    pub username: Option<String>,
}

/// QL-28: the jump host a bulk edit sets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum JumpChoice {
    /// As their folders say.
    Folder,
    /// No jump host, whatever their folders set.
    Direct,
    /// This saved session.
    Session { id: Uuid },
}

/// QL-28: what the Sessions page's bulk Edit changes. A field left out stays as each session has it; tags are added
/// and taken off, the others set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BulkEdit {
    pub folder: Option<FolderChoice>,
    pub port: Option<u16>,
    pub username: Option<UserChoice>,
    /// [`SessionAuth::Folder`]: as their folders say.
    pub auth: Option<SessionAuth>,
    pub jump: Option<JumpChoice>,
    /// [`Environment::None`]: none of their own (their folders' label applies).
    pub environment: Option<Environment>,
    pub tags_add: Vec<String>,
    pub tags_remove: Vec<String>,
}

/// QL-28: one field a bulk edit changes on a session, as the preview shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldChange {
    pub field: String,
    pub before: String,
    pub after: String,
}

/// QL-28: a session in the preview; `changes` is empty when the edit leaves it as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkEditRow {
    pub id: Uuid,
    pub name: String,
    pub changes: Vec<FieldChange>,
    /// SS-12: the edit's fields its kind doesn't take, which stay as they are ("Login stays as it is: a Telnet
    /// session takes none"): only SSH logs in with a login of the app's, Telnet and serial take no jump host, serial
    /// has no port.
    pub skipped: Vec<String>,
}

/// QL-28: before and after for each picked session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkEditPreview {
    pub rows: Vec<BulkEditRow>,
    /// How many sessions it changes.
    pub changed: usize,
}

/// QL-28: a bulk edit worked out.
struct BulkPlan {
    tree: Folders,
    before: Vec<SessionRecord>,
    after: Vec<SessionRecord>,
    inputs: Vec<(Uuid, SessionInput)>,
    preview: BulkEditPreview,
}

pub const MAX_SESSION_NAME: usize = 100;
pub const MAX_FOLDER_NAME: usize = 60;
pub const MAX_HOST_LEN: usize = 253;
pub const MAX_USERNAME_LEN: usize = 100;
pub const MAX_STARTUP_COMMAND: usize = 4096;
pub const MAX_TAGS: usize = 20;
/// SS-07: the most jump hosts a chain may have.
pub const MAX_JUMP_DEPTH: usize = 8;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// Trims every field and checks what can be checked without the database.
fn tidy(mut input: SessionInput) -> Result<SessionInput> {
    input.host = input.host.trim().to_owned();
    if input.host.is_empty() {
        return invalid(if input.kind.has_port() {
            "Enter the host name or IP address."
        } else {
            "Choose the COM port."
        });
    }
    // SS-12: the kind's own fields; a serial session's host is its COM port.
    let kind = input.kind;
    kind.tidy(&mut input.host, &mut input.port)?;
    if !kind.is_ssh() {
        // The startup command and prompt hook are SSH's.
        input.startup_command = None;
        input.startup_on_reconnect = false;
        input.prompt_hook = None;
        if !kind.links_to_vms() {
            input.vm_id = None;
        }
        if !kind.logs_in_with_vault() {
            // Its own program or the remote side asks for the login (or, for WinRM with "my Windows sign-in",
            // Windows signs in as the user of this PC): no vault password goes anywhere through it (QL-16: not a
            // folder's either).
            input.auth = SessionAuth::Password { password_id: None };
            if kind.is_winrm() {
                input.username = None;
            }
        } else if !kind.takes_keys() && matches!(input.auth, SessionAuth::Key { .. } | SessionAuth::Agent) {
            // F4: WinRM signs in with a user and password only.
            return invalid(format!(
                "A {} session signs in with a user and password from the vault, not a key or the SSH agent.",
                kind.label()
            ));
        }
    }
    if !kind.takes_jump_host() {
        // Telnet and serial never go through a jump host, not even a folder's.
        input.jump_session_id = None;
        input.jump_direct = true;
    }
    if input.host.contains('@') {
        return invalid("Put the user name in the User field, not in the host.");
    }
    if input.host.chars().count() > MAX_HOST_LEN {
        return invalid(format!("A host name can be at most {MAX_HOST_LEN} characters."));
    }
    let host_ok = input
        .host
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%' | '[' | ']'));
    if !host_ok {
        return invalid("A host can only hold letters, digits and . - _ : (for IPv6) [ ] %.");
    }
    if input.port == 0 {
        return invalid("The port must be 1 to 65535.");
    }

    input.name = input.name.trim().to_owned();
    if input.name.is_empty() {
        input.name = input.host.clone();
    }
    if input.name.chars().count() > MAX_SESSION_NAME {
        return invalid(format!("A session name can be at most {MAX_SESSION_NAME} characters."));
    }
    if input.name.chars().any(char::is_control) {
        return invalid("A session name can't hold line breaks or tabs.");
    }

    input.username = clean_username(input.username)?;

    input.startup_command = input
        .startup_command
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty());
    if let Some(command) = &input.startup_command {
        if command.chars().count() > MAX_STARTUP_COMMAND {
            return invalid(format!(
                "A startup command can be at most {MAX_STARTUP_COMMAND} characters."
            ));
        }
        if command.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\t')) {
            return invalid("A startup command can't hold control characters.");
        }
    }

    if let SessionAuth::Key {
        key_id: None,
        passphrase_id: Some(_),
    } = input.auth
    {
        return invalid("Choose the private key the passphrase is for.");
    }

    input.vm_id = input.vm_id.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    // QL-16: "no jump host" only means something without one chosen.
    if input.jump_session_id.is_some() {
        input.jump_direct = false;
    }
    input.tags = clean_tags(&input.tags, "A session")?;
    Ok(input)
}

/// Tag names checked, without repeats (letter case aside), sorted. `whose`: "A session", "A folder".
fn clean_tags(tags: &[String], whose: &str) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for tag in tags {
        let tag = clean_name("tag", tag, MAX_TAG_LEN)?;
        if seen.insert(tag.to_lowercase()) {
            out.push(tag);
        }
    }
    if out.len() > MAX_TAGS {
        return invalid(format!("{whose} can have at most {MAX_TAGS} tags."));
    }
    out.sort_by_key(|t| t.to_lowercase());
    Ok(out)
}

/// A user name as typed: trimmed, `None` when empty, and checked.
fn clean_username(user: Option<String>) -> Result<Option<String>> {
    let user = user.map(|u| u.trim().to_owned()).filter(|u| !u.is_empty());
    if let Some(user) = &user {
        if user.chars().count() > MAX_USERNAME_LEN {
            return invalid(format!("A user name can be at most {MAX_USERNAME_LEN} characters."));
        }
        if user.chars().any(char::is_control) {
            return invalid("A user name can't hold line breaks or tabs.");
        }
    }
    Ok(user)
}

fn clean_folder_name(name: &str) -> Result<String> {
    clean_name("folder", name, MAX_FOLDER_NAME)
}

/// "web01" with quotes, for audit actions.
fn quoted(name: &str) -> String {
    format!("'{name}'")
}

/// What `spec` logs in with, read from the vault just before a connection (SS-03, BX-02). Only the
/// remote adapter gets it. `typed`: a password typed in the terminal earlier, for a session with no
/// saved one (a bulk run has none, so such a login fails there with what to do).
pub(crate) async fn credentials(
    vault: &dyn Vault,
    ctx: &Context,
    spec: &SessionSpec,
    typed: Option<SecretString>,
) -> Result<Credentials> {
    Ok(match &spec.auth {
        AuthMethod::Password(Some(id)) => Credentials::Password(Some(vault.get(ctx, *id).await?)),
        AuthMethod::Password(None) => Credentials::Password(typed),
        AuthMethod::PrivateKey { key, passphrase } => {
            let label = vault
                .list(ctx)
                .await?
                .into_iter()
                .find(|m| m.id == *key)
                .map_or_else(|| "key".to_owned(), |m| m.label);
            let passphrase = match passphrase {
                Some(id) => Some(vault.get(ctx, *id).await?),
                None => None,
            };
            Credentials::PrivateKey {
                key: vault.get(ctx, *key).await?,
                passphrase,
                label,
            }
        }
        AuthMethod::Agent => Credentials::Agent,
    })
}

/// SS-07: what each jump host on the way to `spec` logs in with, in the order they are connected
/// ([`SessionSpec::jumps`]). `typed`: passwords typed in the terminal earlier, by session, for jump
/// hosts with no saved one.
pub(crate) async fn jump_credentials(
    vault: &dyn Vault,
    ctx: &Context,
    spec: &SessionSpec,
    typed: &HashMap<Uuid, SecretString>,
) -> Result<Vec<Credentials>> {
    let mut all = Vec::new();
    for jump in spec.jumps() {
        all.push(credentials(vault, ctx, jump, typed.get(&jump.id).cloned()).await?);
    }
    Ok(all)
}

/// SS-01: what the policy engine makes of a startup command, as if it were run on the session by hand
/// (BX-06): it is typed into the shell without asking, so the editor and the import preview show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupRating {
    /// [`ActionKind::ExecReadOnly`], [`ActionKind::ExecOther`] or [`ActionKind::ExecDangerous`].
    pub action: ActionKind,
    /// The tier a command like it gets on this session (a Prod session raises it).
    pub tier: Tier,
    /// The dangerous-command rules it matches, by name.
    pub dangerous: Vec<String>,
}

impl StartupRating {
    /// "Medium: other", "High: dangerous (rm -rf)".
    pub fn describe(&self) -> String {
        let kind = match self.action {
            ActionKind::ExecReadOnly => "read-only".to_owned(),
            ActionKind::ExecDangerous => format!("dangerous ({})", self.dangerous.join(", ")),
            _ => "other".to_owned(),
        };
        format!("{:?}: {kind}", self.tier)
    }
}

/// SS-01: rates a startup command the way a bulk run on this one session would be rated.
pub fn rate_startup(policy: &PolicyEngine, command: &str, environment: Environment) -> StartupRating {
    let session_id = Uuid::nil();
    let run = Command::RemoteExec {
        targets: vec![TargetRef::Session { session_id }],
        script: command.to_owned(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Default::default(),
    };
    let target = Target {
        target: TargetRef::Session { session_id },
        name: String::new(),
        environment,
        protected: false,
    };
    StartupRating {
        action: policy.classify_script(command),
        tier: policy.evaluate(&run, &[target]).tier,
        dangerous: policy.dangerous_matches(command),
    }
}

/// One "name: before -> after" entry when they differ.
fn field_text(out: &mut Vec<String>, name: &str, before: &str, after: &str) {
    if before != after {
        out.push(format!("{name}: {before} -> {after}"));
    }
}

pub struct SessionLibrary {
    store: Store,
    links: Arc<VmLinks>,
    /// SS-01: the bus's engine, to rate startup commands in the audit log.
    policy: Option<Arc<RwLock<PolicyEngine>>>,
    /// SS-04, AP-06: a session that would send a vault password somewhere it doesn't go yet asks for
    /// the master password first.
    bindings: Option<SecretBindings>,
    /// MO-08, QL-27: a deleted session's health checks go to the trash with it; the runner then reads them again.
    checks: Option<crate::checks::Checks>,
}

impl SessionLibrary {
    pub fn new(store: Store, links: Arc<VmLinks>) -> Self {
        Self {
            store,
            links,
            policy: None,
            bindings: None,
            checks: None,
        }
    }

    /// MO-08: the health checks, read again once a deleted session's checks went to the trash with it.
    pub fn with_checks(mut self, checks: crate::checks::Checks) -> Self {
        self.checks = Some(checks);
        self
    }

    /// SS-04, AP-06: the checks before a session sends a vault password to a new place.
    pub fn with_bindings(mut self, bindings: SecretBindings) -> Self {
        self.bindings = Some(bindings);
        self
    }

    /// AP-06: the vault passwords in `secrets` may go to `place` (through this session, `except` when it is
    /// an edit), or the master password must come with the request. How it was confirmed, when it was
    /// needed (for the audit entry).
    #[allow(clippy::too_many_arguments)]
    async fn confirm_place(
        &self,
        ctx: &Context,
        place: &Destination,
        secrets: &[SecretId],
        except: Option<Uuid>,
        already: &[SecretId],
        reauth: Reauth<'_>,
        action: &str,
    ) -> Result<Option<&'static str>> {
        let Some(bindings) = &self.bindings else {
            return Ok(None);
        };
        let mut new = Vec::new();
        for secret in secrets {
            if already.contains(secret) || bindings.may_go(ctx, *secret, place, except).await? {
                continue;
            }
            new.push(bindings.describe(ctx, *secret).await?);
        }
        if new.is_empty() {
            return Ok(None);
        }
        let vault_password = match reauth {
            Reauth::Given => return Ok(Some(crate::vault::bindings::ASKED_NOW)),
            Reauth::Ask(password) => password,
        };
        let reason = format!(
            "This would send the {} to {}:{}, where no saved session sends it yet",
            new.join(" and the "),
            place.host,
            place.port
        );
        Ok(Some(bindings.confirm(ctx, vault_password, action, &reason).await?))
    }

    fn settle(&self, secrets: &[SecretId]) {
        if let Some(bindings) = &self.bindings {
            bindings.settle(secrets);
        }
    }

    /// The command bus's policy engine, so a startup command is rated with the current rules.
    pub fn with_policy(mut self, policy: Arc<RwLock<PolicyEngine>>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// SS-01: a startup command's rating on a session with `environment`, with the current rules.
    pub fn rate_startup(&self, command: &str, environment: Environment) -> Option<StartupRating> {
        let policy = self.policy.as_ref()?;
        Some(rate_startup(&locks::read(policy), command, environment))
    }

    /// QL-01: links every session it can to the VM whose guest IP it reaches. The importer calls it
    /// once after saving a batch.
    pub async fn auto_link(&self, ctx: &Context) -> Result<AutoLinkReport> {
        self.links.auto_link(ctx).await
    }

    /// Auto-linking one session after a save. A failure is logged; the save itself stands.
    async fn auto_link_quietly(&self, ctx: &Context, id: Uuid) {
        if let Err(err) = self.links.auto_link_session(ctx, id).await {
            tracing::warn!(error = %err, "could not link a session to a VM automatically");
        }
    }

    /// The sessions that match `filter`, by name.
    pub async fn list(&self, ctx: &Context, filter: &SessionFilter) -> Result<Vec<SessionRecord>> {
        let mut sessions = self.store.list_sessions(ctx).await?;
        let in_scope = match filter.folder_id {
            Some(folder) => Some(self.subtree(ctx, folder).await?),
            None => None,
        };
        sessions.retain(|s| {
            filter.matches(s)
                && in_scope
                    .as_ref()
                    .is_none_or(|scope| s.folder_id.is_some_and(|f| scope.contains(&f)))
        });
        Ok(sessions)
    }

    /// QL-04: the Terminal page's session tree, grouped by folder, tag or label, holding the sessions
    /// that match `filter`. While filtering, groups left empty are dropped.
    pub async fn tree(&self, ctx: &Context, grouping: TreeGrouping, filter: &SessionFilter) -> Result<SessionTree> {
        let sessions = self.list(ctx, filter).await?;
        let folders = self.folders(ctx).await?;
        let filtering = *filter != SessionFilter::default();
        Ok(tree::build(grouping, &folders, sessions, filtering))
    }

    /// QL-02: the sessions opened most recently, newest first.
    pub async fn recent(&self, ctx: &Context, limit: u32) -> Result<Vec<SessionRecord>> {
        self.store.recent_sessions(ctx, limit).await
    }

    pub async fn get(&self, ctx: &Context, id: Uuid) -> Result<SessionRecord> {
        self.store
            .get_session(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {id}")))
    }

    pub async fn folders(&self, ctx: &Context) -> Result<Vec<SessionFolder>> {
        self.store.list_session_folders(ctx).await
    }

    /// Saves a new session. Without a VM chosen, it is linked automatically when its host is a VM's
    /// IP address (QL-01).
    pub async fn create(&self, ctx: &Context, input: SessionInput) -> Result<SessionRecord> {
        self.create_with(ctx, input, None).await
    }

    /// [`Self::create`], with the master password for a login password that goes nowhere near this host
    /// yet (SS-04, AP-06: otherwise it fails with [`CoreError::ReauthRequired`]).
    pub async fn create_with(
        &self,
        ctx: &Context,
        input: SessionInput,
        vault_password: Option<&SecretString>,
    ) -> Result<SessionRecord> {
        self.store.read_only().check(Change::Sessions)?;
        let input = self.check(ctx, None, input).await?;
        // QL-16: where it goes and what it sends are what applies to it, its folders' values included.
        let effective = self
            .store
            .session_folders(ctx)
            .await?
            .resolve(None, &input.own(), input.folder_id);
        let place = Destination::new(&input.host, input.port, effective.jump_session_id);
        let sent = effective.sent_secret().into_iter().collect::<Vec<_>>();
        let action = format!("Failed to create session {}", quoted(&display_name(&input)));
        let asked = self
            .confirm_place(ctx, &place, &sent, None, &[], Reauth::Ask(vault_password), &action)
            .await?;
        let id = Uuid::new_v4();
        self.store.insert_session(ctx, id, &input, None).await?;
        self.settle(&sent);
        if input.vm_id.is_some() {
            self.store.set_vm_link_kind(ctx, id, Some(VmLink::Manual)).await?;
        }
        let session = self.get(ctx, id).await?;
        let mut detail = self.describe(ctx, &session).await?;
        if let Some(how) = asked {
            detail.push_str(&format!("; {how}"));
        }
        self.audit(
            ctx,
            &format!("Created session {}", quoted(&session.name)),
            &session,
            Some(&detail),
        )
        .await?;
        if input.vm_id.is_none() {
            self.auto_link_quietly(ctx, id).await;
        }
        self.get(ctx, id).await
    }

    /// SS-02: saves an imported session, checked like an edit, with where it came from.
    /// `imported_from` is the stable source name (`putty`, `mobaxterm`, `openssh`, `csv`); `source`
    /// is how the audit log names it.
    pub async fn import(
        &self,
        ctx: &Context,
        input: SessionInput,
        imported_from: &str,
        source: &str,
    ) -> Result<SessionRecord> {
        let input = self.check(ctx, None, input).await?;
        let id = Uuid::new_v4();
        self.store.insert_session(ctx, id, &input, Some(imported_from)).await?;
        if input.vm_id.is_some() {
            self.store.set_vm_link_kind(ctx, id, Some(VmLink::Manual)).await?;
        }
        let session = self.get(ctx, id).await?;
        let detail = self.describe(ctx, &session).await?;
        self.audit(
            ctx,
            &format!("Imported session {} from {source}", quoted(&session.name)),
            &session,
            Some(&detail),
        )
        .await?;
        Ok(session)
    }

    /// FD-07: saves a session from a Remotely export under `id` (the one it had on the other laptop,
    /// when that is free here, so a later import finds it again), checked like an edit and audited
    /// like an SS-02 import. `imported_from` keeps where it first came from, if anywhere; `link` is how
    /// its VM link was made there (QL-01), for a session that reaches a VM here too.
    ///
    /// QL-16, SS-04: a session that logs in as its folders say and would send a folder's vault password to its host,
    /// where it doesn't go yet, needs the master password (`reauth`: the import asked for it once, or not). Its own
    /// login is checked by the import before anything is saved.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn restore(
        &self,
        ctx: &Context,
        id: Uuid,
        input: SessionInput,
        imported_from: Option<&str>,
        link: VmLink,
        source: &str,
        reauth: Reauth<'_>,
    ) -> Result<SessionRecord> {
        let input = self.check(ctx, None, input).await?;
        let mut asked = None;
        let mut sent = Vec::new();
        if input.auth == SessionAuth::Folder {
            let effective = self
                .store
                .session_folders(ctx)
                .await?
                .resolve(Some(id), &input.own(), input.folder_id);
            let place = Destination::new(&input.host, input.port, effective.jump_session_id);
            sent.extend(effective.sent_secret());
            let action = format!("Failed to import session {}", quoted(&display_name(&input)));
            asked = self
                .confirm_place(ctx, &place, &sent, None, &[], reauth, &action)
                .await?;
        }
        self.store.insert_session(ctx, id, &input, imported_from).await?;
        self.settle(&sent);
        if input.vm_id.is_some() {
            self.store.set_vm_link_kind(ctx, id, Some(link)).await?;
        }
        let session = self.get(ctx, id).await?;
        let mut detail = self.describe(ctx, &session).await?;
        if let Some(how) = asked {
            detail.push_str(&format!("; {how}"));
        }
        self.audit(
            ctx,
            &format!("Imported session {} from {source}", quoted(&session.name)),
            &session,
            Some(&detail),
        )
        .await?;
        Ok(session)
    }

    /// Saves an edit. Audited with what changed; an edit that changes nothing writes nothing.
    ///
    /// QL-01: a VM chosen (or removed) in the editor is the user's choice, which auto-linking never
    /// changes. A new host makes an automatic link, or the removal of one, out of date: the session
    /// is linked again by its new address.
    pub async fn update(&self, ctx: &Context, id: Uuid, input: SessionInput) -> Result<SessionRecord> {
        self.update_with(ctx, id, input, None).await
    }

    /// [`Self::update`], with the master password for an edit that sends a vault password somewhere it
    /// doesn't go yet: another login password, or a new host, port or jump host for a session that sends
    /// vault passwords (its login, its container hosts' sudo, the ones it was allowed). SS-04, AP-06.
    pub async fn update_with(
        &self,
        ctx: &Context,
        id: Uuid,
        input: SessionInput,
        vault_password: Option<&SecretString>,
    ) -> Result<SessionRecord> {
        self.update_checked(ctx, id, input, Reauth::Ask(vault_password)).await
    }

    /// FD-07: an import replacing a session, after it asked for the master password itself (or not).
    pub(crate) async fn update_checked(
        &self,
        ctx: &Context,
        id: Uuid,
        input: SessionInput,
        reauth: Reauth<'_>,
    ) -> Result<SessionRecord> {
        self.store.read_only().check(Change::Sessions)?;
        let before = self.get(ctx, id).await?;
        let mut input = self.check(ctx, Some(id), input).await?;
        if input == before.input() {
            return Ok(before);
        }
        // QL-16: the place and login that apply, before and after (its folders' values included).
        let effective = self
            .store
            .session_folders(ctx)
            .await?
            .resolve(Some(id), &input.own(), input.folder_id);
        let place = Destination::new(&input.host, input.port, effective.jump_session_id);
        let moved = !place.same(&Destination::new(&before.host, before.port, before.jump_session_id));
        let (sent, already) = match &self.bindings {
            Some(bindings) => {
                let now = bindings.sent_by(ctx, id).await?;
                let old_login = before.auth.sent_secret();
                let mut sent: Vec<SecretId> = if moved {
                    now.iter().copied().filter(|s| Some(*s) != old_login).collect()
                } else {
                    Vec::new()
                };
                if let Some(login) = effective.sent_secret() {
                    if !sent.contains(&login) {
                        sent.push(login);
                    }
                }
                // Without a move, what the session sends already may stay.
                let already = if moved { Vec::new() } else { now };
                (sent, already)
            }
            None => (Vec::new(), Vec::new()),
        };
        let action = format!("Failed to change session {}", quoted(&before.name));
        let asked = self
            .confirm_place(ctx, &place, &sent, Some(id), &already, reauth, &action)
            .await?;
        let host_changed = !input.host.eq_ignore_ascii_case(&before.host);
        let decided_without_vm = before.vm_link == Some(VmLink::Manual) && before.vm_id.is_none();
        let link = if input.vm_id != before.vm_id {
            Some(VmLink::Manual)
        } else if host_changed && (before.vm_link == Some(VmLink::Auto) || decided_without_vm) {
            input.vm_id = None;
            None
        } else {
            before.vm_link
        };
        if !self.store.update_session(ctx, id, &input).await? {
            return Err(CoreError::UnknownTarget(format!("session {id}")));
        }
        if link != before.vm_link {
            self.store.set_vm_link_kind(ctx, id, link).await?;
        }
        self.settle(&sent);
        let after = self.get(ctx, id).await?;
        let mut changes = self.changes(ctx, &before, &after).await?;
        if let Some(how) = asked {
            changes.push(how.into());
        }
        self.audit(
            ctx,
            &format!("Changed session {}", quoted(&after.name)),
            &after,
            Some(&changes.join("; ")),
        )
        .await?;
        if host_changed && link != Some(VmLink::Manual) {
            self.auto_link_quietly(ctx, id).await;
            return self.get(ctx, id).await;
        }
        Ok(after)
    }

    /// A copy named "<name> (copy)" in the same folder, with the same credentials and tags.
    pub async fn duplicate(&self, ctx: &Context, id: Uuid) -> Result<SessionRecord> {
        self.store.read_only().check(Change::Sessions)?;
        let original = self.get(ctx, id).await?;
        let mut input = original.input();
        // An automatic link is made again for the copy, so it stays automatic.
        if original.vm_link == Some(VmLink::Auto) {
            input.vm_id = None;
        }
        let suffix = " (copy)";
        let keep = MAX_SESSION_NAME - suffix.len();
        input.name = format!("{}{suffix}", original.name.chars().take(keep).collect::<String>());
        self.create(ctx, input).await
    }

    /// Sessions that jumped through it lose their jump host; the vault keeps its credentials. QL-27: it goes to the
    /// trash with its port forwards, container marks, group places and note, and can be restored for 30 days.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Sessions)?;
        let session = self.get(ctx, id).await?;
        // QL-16: sessions whose own jump host it is; a folder's is named apart.
        let jumper_names: Vec<String> = self
            .store
            .list_sessions(ctx)
            .await?
            .iter()
            .filter(|s| s.own.jump_session_id == Some(id))
            .map(|s| quoted(&s.name))
            .collect();
        let jumpers = jumper_names.len();
        let folders_using: Vec<String> = self
            .folders(ctx)
            .await?
            .into_iter()
            .filter(|f| f.defaults.jump_session_id == Some(id))
            .map(|f| quoted(&f.name))
            .collect();
        // QL-27: into the trash, with what hangs off it, where it went and what it sent (for its restore).
        let tree = self.store.session_folders(ctx).await?;
        let sent = match &self.bindings {
            Some(bindings) => bindings.sent_by(ctx, id).await?,
            None => session.auth.sent_secret().into_iter().collect(),
        };
        let place = Destination::new(&session.host, session.port, session.jump_session_id);
        let item = crate::trash::TrashItem {
            kind: crate::trash::TrashKind::Session,
            item_id: &id.to_string(),
            name: &session.name,
            place: crate::trash::session_place(&tree, session.folder_id),
            sent: Some((place, sent)),
            jump_users: jumper_names
                .iter()
                .cloned()
                .chain(folders_using.iter().map(|f| format!("folder {f}")))
                .collect(),
        };
        let Some(trashed) = crate::trash::move_to_trash(&self.store, ctx, item).await? else {
            return Err(CoreError::UnknownTarget(format!("session {id}")));
        };
        // MO-08: its checks are in the trash now, so the runner stops running them.
        if let Some(checks) = &self.checks {
            if let Err(err) = checks.reload(*ctx).await {
                tracing::warn!(error = %err, "could not reload the health checks after a delete");
            }
        }
        let mut detail = session.address();
        if !trashed.detail.is_empty() {
            detail.push_str(&format!("; with {}", trashed.detail));
        }
        detail.push_str(&format!("; moved to the trash for {} days", crate::trash::KEEP_DAYS));
        match jumpers {
            0 => {}
            1 => detail.push_str("; 1 session used it as its jump host and now has none"),
            n => detail.push_str(&format!("; {n} sessions used it as their jump host and now have none")),
        }
        if !folders_using.is_empty() {
            detail.push_str(&format!(
                "; it was the jump host of folder {}, whose sessions now go as the folders above say",
                folders_using.join(", ")
            ));
        }
        self.audit(
            ctx,
            &format!("Deleted session {}", quoted(&session.name)),
            &session,
            Some(&detail),
        )
        .await
    }

    /// Moves sessions into a folder, or to the top level with `None`.
    pub async fn move_to(&self, ctx: &Context, ids: &[Uuid], folder: Option<Uuid>) -> Result<()> {
        self.move_to_with(ctx, ids, folder, None).await
    }

    /// [`Self::move_to`], with the master password for a move that makes sessions send a vault password their new
    /// folder sets (QL-16) somewhere it doesn't go yet (SS-04, AP-06: otherwise [`CoreError::ReauthRequired`]).
    pub async fn move_to_with(
        &self,
        ctx: &Context,
        ids: &[Uuid],
        folder: Option<Uuid>,
        vault_password: Option<&SecretString>,
    ) -> Result<()> {
        self.store.read_only().check(Change::Sessions)?;
        if ids.is_empty() {
            return Err(CoreError::NoTargets);
        }
        let folders = self.folders(ctx).await?;
        let place = self.folder_place(&folders, folder)?;
        let mut targets = Vec::with_capacity(ids.len());
        for id in ids {
            targets.push(self.get(ctx, *id).await?.target());
        }
        // QL-16: what the moved sessions get from their new folders, checked like an edit of each.
        let tree = self.store.session_folders(ctx).await?;
        let before = self.store.list_sessions_in(ctx, &tree).await?;
        let after = resolved_after(
            &before,
            &tree,
            |s| if ids.contains(&s.id) { folder } else { s.folder_id },
        );
        check_jump_loops(&after, |s| ids.contains(&s.id))?;
        let what = match ids.len() {
            1 => format!("session {}", quoted(&targets[0].name)),
            n => format!("{n} sessions"),
        };
        let action = format!("Failed to move {what} to {place}");
        let (asked, sent) = self
            .confirm_folder_change(ctx, &tree, &before, &after, Reauth::Ask(vault_password), &action)
            .await?;
        self.store.move_sessions(ctx, ids, folder).await?;
        self.settle(&sent);
        let targets: Vec<Target> = after
            .iter()
            .filter(|s| ids.contains(&s.id))
            .map(SessionRecord::target)
            .collect();
        let detail = asked.map(str::to_owned);
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action: &format!("Moved {what} to {place}"),
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: detail.as_deref(),
                },
            )
            .await
            .map(drop)
    }

    /// QL-28: what a bulk edit would change on each session, before and after, without saving anything.
    pub async fn bulk_preview(&self, ctx: &Context, ids: &[Uuid], edit: &BulkEdit) -> Result<BulkEditPreview> {
        let plan = self.plan_bulk(ctx, ids, edit).await?;
        Ok(plan.preview)
    }

    /// QL-28: changes folder, port, user, login, jump host, environment and tags of several sessions at once, each
    /// checked like an edit of it, in one transaction, with one audit entry naming every session changed. A change
    /// that would send a vault password somewhere it doesn't go yet asks for the vault password once for all of them
    /// (SS-04, AP-06: otherwise [`CoreError::ReauthRequired`]).
    pub async fn bulk_edit(
        &self,
        ctx: &Context,
        ids: &[Uuid],
        edit: &BulkEdit,
        vault_password: Option<&SecretString>,
    ) -> Result<BulkEditPreview> {
        self.store.read_only().check(Change::Sessions)?;
        let plan = self.plan_bulk(ctx, ids, edit).await?;
        let changed: Vec<Uuid> = plan
            .preview
            .rows
            .iter()
            .filter(|r| !r.changes.is_empty())
            .map(|r| r.id)
            .collect();
        if changed.is_empty() {
            return Ok(plan.preview);
        }
        let what = match changed.len() {
            1 => format!(
                "session {}",
                quoted(
                    plan.preview
                        .rows
                        .iter()
                        .find(|r| r.id == changed[0])
                        .map_or("", |r| &r.name)
                )
            ),
            n => format!("{n} sessions"),
        };
        let action = format!("Failed to change {what}");
        let (asked, sent) = self
            .confirm_folder_change(
                ctx,
                &plan.tree,
                &plan.before,
                &plan.after,
                Reauth::Ask(vault_password),
                &action,
            )
            .await?;
        let edits: Vec<(Uuid, SessionInput)> = plan.inputs.into_iter().filter(|(id, _)| changed.contains(id)).collect();
        self.store.update_sessions(ctx, &edits).await?;
        self.settle(&sent);
        let targets: Vec<Target> = plan
            .after
            .iter()
            .filter(|s| changed.contains(&s.id))
            .map(SessionRecord::target)
            .collect();
        let mut detail = self.describe_bulk(ctx, edit).await?;
        detail.push(format!("{} changed", plural(changed.len(), "session")));
        let skipped = plan.preview.rows.iter().filter(|r| !r.skipped.is_empty()).count();
        if skipped > 0 {
            detail.push(format!(
                "{} kept a field its kind doesn't take",
                plural(skipped, "session")
            ));
        }
        if let Some(how) = asked {
            detail.push(how.into());
        }
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action: &format!("Changed {what} at once"),
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: Some(&detail.join("; ")),
                },
            )
            .await?;
        Ok(plan.preview)
    }

    /// QL-28: each session's input after the edit, checked; every session before and after; and the preview.
    async fn plan_bulk(&self, ctx: &Context, ids: &[Uuid], edit: &BulkEdit) -> Result<BulkPlan> {
        let mut unique: Vec<Uuid> = Vec::new();
        for id in ids {
            if !unique.contains(id) {
                unique.push(*id);
            }
        }
        if unique.is_empty() {
            return Err(CoreError::NoTargets);
        }
        if let Some(0) = edit.port {
            return invalid("The port must be 1 to 65535.");
        }
        let username = match &edit.username {
            Some(choice) => Some(clean_username(choice.username.clone())?),
            None => None,
        };
        let add = clean_tags(&edit.tags_add, "A session")?;
        let remove = clean_tags(&edit.tags_remove, "A session")?;
        let tree = self.store.session_folders(ctx).await?;
        if let Some(FolderChoice {
            folder_id: Some(folder),
        }) = &edit.folder
        {
            if tree.get(*folder).is_none() {
                return Err(CoreError::UnknownTarget(format!("folder {folder}")));
            }
        }
        let before = self.store.list_sessions_in(ctx, &tree).await?;
        let mut inputs = Vec::with_capacity(unique.len());
        for id in &unique {
            let session = before
                .iter()
                .find(|s| s.id == *id)
                .ok_or_else(|| CoreError::UnknownTarget(format!("session {id}")))?;
            let mut input = session.input();
            if let Some(choice) = &edit.folder {
                input.folder_id = choice.folder_id;
            }
            if let Some(port) = edit.port {
                input.port = port;
            }
            if let Some(user) = &username {
                input.username.clone_from(user);
            }
            if let Some(auth) = edit.auth.as_ref().filter(|auth| takes_login(&session.kind, auth)) {
                input.auth = auth.clone();
            }
            match &edit.jump {
                None => {}
                Some(JumpChoice::Folder) => {
                    input.jump_session_id = None;
                    input.jump_direct = false;
                }
                Some(JumpChoice::Direct) => {
                    input.jump_session_id = None;
                    input.jump_direct = true;
                }
                Some(JumpChoice::Session { id: jump }) => {
                    input.jump_session_id = Some(*jump);
                    input.jump_direct = false;
                }
            }
            if let Some(environment) = edit.environment {
                input.environment = environment;
            }
            if !add.is_empty() || !remove.is_empty() {
                let mut tags: Vec<String> = input
                    .tags
                    .iter()
                    .filter(|t| !remove.iter().any(|r| r.eq_ignore_ascii_case(t)))
                    .cloned()
                    .collect();
                for tag in &add {
                    if !tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                        tags.push(tag.clone());
                    }
                }
                input.tags = tags;
            }
            let checked = self.check(ctx, Some(*id), input).await.map_err(|err| match err {
                CoreError::InvalidInput(message) => {
                    CoreError::InvalidInput(format!("{}: {message}", quoted(&session.name)))
                }
                other => other,
            })?;
            inputs.push((*id, checked));
        }
        let after: Vec<SessionRecord> = before
            .iter()
            .map(|s| {
                let mut s = s.clone();
                if let Some((_, input)) = inputs.iter().find(|(id, _)| *id == s.id) {
                    s.folder_id = input.folder_id;
                    s.port = input.port;
                    s.own = input.own();
                    let effective = s.resolve_in(&tree);
                    s.apply(effective);
                }
                s
            })
            .collect();
        check_jump_loops(&after, |s| unique.contains(&s.id))?;
        let (folders, sessions) = self.names(ctx).await?;
        // The preview compares the saved sessions with the checked inputs, so it shows what `tidy` keeps of the edit
        // for each kind, not what was asked.
        let rows = unique
            .iter()
            .filter_map(|id| {
                let a = before.iter().find(|s| s.id == *id)?;
                let b = after.iter().find(|s| s.id == *id)?;
                Some(BulkEditRow {
                    id: *id,
                    name: a.name.clone(),
                    changes: bulk_changes(&folders, &sessions, a, b),
                    skipped: skipped_for_kind(&a.kind, edit),
                })
            })
            .collect::<Vec<_>>();
        let changed = rows.iter().filter(|r| !r.changes.is_empty()).count();
        Ok(BulkPlan {
            tree,
            before,
            after,
            inputs,
            preview: BulkEditPreview { rows, changed },
        })
    }

    /// QL-28: what a bulk edit sets, for its audit entry.
    async fn describe_bulk(&self, ctx: &Context, edit: &BulkEdit) -> Result<Vec<String>> {
        let (folders, sessions) = self.names(ctx).await?;
        let mut out = Vec::new();
        if let Some(choice) = &edit.folder {
            out.push(format!(
                "folder -> {}",
                choice
                    .folder_id
                    .and_then(|f| folders.get(&f))
                    .map_or_else(|| "top level".to_owned(), |n| quoted(n))
            ));
        }
        if let Some(port) = edit.port {
            out.push(format!("port -> {port}"));
        }
        if let Some(choice) = &edit.username {
            out.push(format!(
                "user -> {}",
                choice
                    .username
                    .as_deref()
                    .map(str::trim)
                    .filter(|u| !u.is_empty())
                    .unwrap_or("as its folders say")
            ));
        }
        if let Some(auth) = &edit.auth {
            out.push(format!("login -> {}", auth.describe()));
        }
        if let Some(jump) = &edit.jump {
            out.push(format!(
                "jump host -> {}",
                match jump {
                    JumpChoice::Folder => "as its folders say".to_owned(),
                    JumpChoice::Direct => "none".to_owned(),
                    JumpChoice::Session { id } => sessions
                        .get(id)
                        .map_or_else(|| "a deleted session".to_owned(), |n| quoted(n)),
                }
            ));
        }
        if let Some(environment) = edit.environment {
            out.push(format!("environment -> {}", environment.as_str()));
        }
        if !edit.tags_add.is_empty() {
            out.push(format!(
                "tags added: {}",
                clean_tags(&edit.tags_add, "A session")?.join(", ")
            ));
        }
        if !edit.tags_remove.is_empty() {
            out.push(format!(
                "tags removed: {}",
                clean_tags(&edit.tags_remove, "A session")?.join(", ")
            ));
        }
        Ok(out)
    }

    pub async fn create_folder(&self, ctx: &Context, name: &str, parent: Option<Uuid>) -> Result<SessionFolder> {
        self.store.read_only().check(Change::Sessions)?;
        let name = clean_folder_name(name)?;
        let folders = self.folders(ctx).await?;
        let place = self.folder_place(&folders, parent)?;
        Self::check_unique_name(&folders, None, parent, &name)?;
        let id = Uuid::new_v4();
        self.store.insert_session_folder(ctx, id, &name, parent).await?;
        let detail = if parent.is_some() {
            format!("in {place}")
        } else {
            "at the top level".to_owned()
        };
        self.audit_folder(ctx, &format!("Created folder {}", quoted(&name)), Some(&detail))
            .await?;
        self.folder(ctx, id).await
    }

    pub async fn rename_folder(&self, ctx: &Context, id: Uuid, name: &str) -> Result<SessionFolder> {
        self.store.read_only().check(Change::Sessions)?;
        let name = clean_folder_name(name)?;
        let folders = self.folders(ctx).await?;
        let folder = Self::find_folder(&folders, id)?;
        if folder.name == name {
            return Ok(folder.clone());
        }
        Self::check_unique_name(&folders, Some(id), folder.parent_id, &name)?;
        self.store
            .update_session_folder(ctx, id, &name, folder.parent_id)
            .await?;
        self.audit_folder(
            ctx,
            &format!("Renamed folder {} to {}", quoted(&folder.name), quoted(&name)),
            None,
        )
        .await?;
        self.folder(ctx, id).await
    }

    /// Moves a folder, with everything in it, under another folder or to the top level.
    pub async fn move_folder(&self, ctx: &Context, id: Uuid, parent: Option<Uuid>) -> Result<SessionFolder> {
        self.move_folder_with(ctx, id, parent, None).await
    }

    /// [`Self::move_folder`], with the master password for a move that makes its sessions send a vault password
    /// the folders above set (QL-16) somewhere it doesn't go yet (SS-04, AP-06).
    pub async fn move_folder_with(
        &self,
        ctx: &Context,
        id: Uuid,
        parent: Option<Uuid>,
        vault_password: Option<&SecretString>,
    ) -> Result<SessionFolder> {
        self.store.read_only().check(Change::Sessions)?;
        let folders = self.folders(ctx).await?;
        let folder = Self::find_folder(&folders, id)?.clone();
        if folder.parent_id == parent {
            return Ok(folder);
        }
        let place = self.folder_place(&folders, parent)?;
        if let Some(parent) = parent {
            if Self::descendants(&folders, id).contains(&parent) {
                return invalid("A folder can't move into itself or a folder inside it.");
            }
        }
        Self::check_unique_name(&folders, Some(id), parent, &folder.name)?;
        // QL-16: its sessions get what the folders above their new place set.
        let tree = Folders::new(folders);
        let moved = tree.with_parent(id, parent);
        let before = self.store.list_sessions_in(ctx, &tree).await?;
        let after = resolved_after(&before, &moved, |s| s.folder_id);
        check_jump_loops(&after, |s| moved.is_within(s.folder_id, id))?;
        let action = format!("Failed to move folder {} to {place}", quoted(&folder.name));
        let (asked, sent) = self
            .confirm_folder_change(ctx, &tree, &before, &after, Reauth::Ask(vault_password), &action)
            .await?;
        self.store.update_session_folder(ctx, id, &folder.name, parent).await?;
        self.settle(&sent);
        self.audit_folder(ctx, &format!("Moved folder {} to {place}", quoted(&folder.name)), asked)
            .await?;
        self.folder(ctx, id).await
    }

    /// Deletes a folder only: its sessions and subfolders move up to its parent.
    pub async fn delete_folder(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.delete_folder_with(ctx, id, None).await
    }

    /// [`Self::delete_folder`], with the master password for when its sessions, moved up, would send a vault
    /// password the folders above set (QL-16) somewhere it doesn't go yet (SS-04, AP-06).
    pub async fn delete_folder_with(
        &self,
        ctx: &Context,
        id: Uuid,
        vault_password: Option<&SecretString>,
    ) -> Result<()> {
        self.store.read_only().check(Change::Sessions)?;
        let folders = self.folders(ctx).await?;
        let folder = Self::find_folder(&folders, id)?.clone();
        let place = self.folder_place(&folders, folder.parent_id)?;
        let sessions = self
            .store
            .list_sessions(ctx)
            .await?
            .iter()
            .filter(|s| s.folder_id == Some(id))
            .count();
        let subfolders = folders.iter().filter(|f| f.parent_id == Some(id)).count();
        if subfolders > 0 {
            // Two folders with one name side by side would be confusing; ask for a rename first.
            for child in folders.iter().filter(|f| f.parent_id == Some(id)) {
                Self::check_unique_name(&folders, Some(child.id), folder.parent_id, &child.name).map_err(|_| {
                    CoreError::InvalidInput(format!(
                        "{} already has a folder named {}; rename one of them first.",
                        place,
                        quoted(&child.name)
                    ))
                })?;
            }
        }
        // QL-16: its sessions lose its defaults and get what the folders above set.
        let tree = Folders::new(folders.clone());
        let gone = tree.without(id);
        let before = self.store.list_sessions_in(ctx, &tree).await?;
        let after = resolved_after(&before, &gone, |s| {
            if s.folder_id == Some(id) {
                folder.parent_id
            } else {
                s.folder_id
            }
        });
        check_jump_loops(&after, |s| {
            s.folder_id == folder.parent_id || tree.is_within(s.folder_id, id)
        })?;
        let action = format!("Failed to delete folder {}", quoted(&folder.name));
        let (asked, sent) = self
            .confirm_folder_change(ctx, &tree, &before, &after, Reauth::Ask(vault_password), &action)
            .await?;
        self.store.delete_session_folder(ctx, id, folder.parent_id).await?;
        self.settle(&sent);
        // FD-06: a folder's note goes with it.
        let had_note = self
            .store
            .delete_note(ctx, crate::notes::NoteKind::Folder, &id.to_string())
            .await?;
        let mut detail = format!(
            "{} and {} moved to {place}",
            plural(sessions, "session"),
            plural(subfolders, "folder")
        );
        if !folder.defaults.is_empty() {
            detail.push_str("; its defaults no longer apply");
        }
        if had_note {
            detail.push_str("; its note was deleted");
        }
        if let Some(how) = asked {
            detail.push_str(&format!("; {how}"));
        }
        self.audit_folder(ctx, &format!("Deleted folder {}", quoted(&folder.name)), Some(&detail))
            .await
    }

    /// QL-16: what a session in `folder` gets when it sets nothing itself (the editor's "from folder X"). `session`:
    /// the session being edited, so a folder whose jump host it is doesn't send it through itself.
    pub async fn inherited(&self, ctx: &Context, folder: Option<Uuid>, session: Option<Uuid>) -> Result<Effective> {
        let folders = self.store.session_folders(ctx).await?;
        if let Some(folder) = folder {
            if folders.get(folder).is_none() {
                return Err(CoreError::UnknownTarget(format!("folder {folder}")));
            }
        }
        Ok(folders.resolve(session, &OwnValues::from_folders(), folder))
    }

    /// QL-16: sets what a folder gives the sessions in it and in its subfolders (user, login, jump host, label,
    /// tags). Audited like a session edit, with the sessions whose values change as targets.
    pub async fn set_folder_defaults(
        &self,
        ctx: &Context,
        id: Uuid,
        defaults: FolderDefaults,
    ) -> Result<SessionFolder> {
        self.set_folder_defaults_with(ctx, id, defaults, None).await
    }

    /// [`Self::set_folder_defaults`], with the master password for defaults that would send a vault password to a
    /// host it doesn't go to yet: a password login, or a jump host that moves sessions sending vault passwords
    /// (SS-04, AP-06: otherwise [`CoreError::ReauthRequired`]), the same check as editing each session.
    pub async fn set_folder_defaults_with(
        &self,
        ctx: &Context,
        id: Uuid,
        defaults: FolderDefaults,
        vault_password: Option<&SecretString>,
    ) -> Result<SessionFolder> {
        self.set_folder_defaults_checked(ctx, id, defaults, Reauth::Ask(vault_password))
            .await
    }

    /// FD-07: [`Self::set_folder_defaults_with`] after the import asked for the master password itself (or not).
    pub(crate) async fn set_folder_defaults_checked(
        &self,
        ctx: &Context,
        id: Uuid,
        defaults: FolderDefaults,
        reauth: Reauth<'_>,
    ) -> Result<SessionFolder> {
        self.store.read_only().check(Change::Sessions)?;
        let tree = self.store.session_folders(ctx).await?;
        let folder = tree
            .get(id)
            .cloned()
            .ok_or_else(|| CoreError::UnknownTarget(format!("folder {id}")))?;
        let defaults = self.check_defaults(ctx, defaults).await?;
        if defaults == folder.defaults {
            return Ok(folder);
        }
        let changed_tree = tree.with_defaults(id, defaults.clone());
        let before = self.store.list_sessions_in(ctx, &tree).await?;
        let after = resolved_after(&before, &changed_tree, |s| s.folder_id);
        check_jump_loops(&after, |s| changed_tree.is_within(s.folder_id, id))?;
        let action = format!("Failed to change the defaults of folder {}", quoted(&folder.name));
        let (asked, sent) = self
            .confirm_folder_change(ctx, &tree, &before, &after, reauth, &action)
            .await?;
        self.store.set_folder_defaults(ctx, id, &defaults).await?;
        self.settle(&sent);
        let targets: Vec<Target> = after
            .iter()
            .zip(&before)
            .filter(|(a, b)| a != b)
            .map(|(a, _)| a.target())
            .collect();
        let mut detail = self.defaults_changes(ctx, &folder.defaults, &defaults).await?;
        detail.push(format!("{} affected", plural(targets.len(), "session")));
        if let Some(how) = asked {
            detail.push(how.into());
        }
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action: &format!("Changed the defaults of folder {}", quoted(&folder.name)),
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: Some(&detail.join("; ")),
                },
            )
            .await?;
        self.folder(ctx, id).await
    }

    /// QL-16: folder defaults tidied and checked like a session's own values.
    async fn check_defaults(&self, ctx: &Context, mut d: FolderDefaults) -> Result<FolderDefaults> {
        d.username = clean_username(d.username)?;
        if d.auth == Some(SessionAuth::Folder) {
            d.auth = None;
        }
        if let Some(auth) = &d.auth {
            self.check_auth(ctx, auth).await?;
        }
        if let Some(jump) = d.jump_session_id {
            match self.store.get_session(ctx, jump).await? {
                None => return invalid("The chosen jump host is not a saved session."),
                // SS-12: a jump host is an SSH session.
                Some(hop) if !hop.kind.is_ssh() => {
                    return invalid(format!(
                        "'{}' is a {} session, and a jump host is an SSH session.",
                        hop.name,
                        hop.kind.label()
                    ))
                }
                Some(_) => {}
            }
            d.jump_direct = false;
        }
        if d.environment == Some(Environment::None) {
            d.environment = None;
        }
        d.tags = clean_tags(&d.tags, "A folder")?;
        Ok(d)
    }

    /// QL-16, SS-04, AP-06: a change of folders (their defaults or places) or of which folder sessions are in, as
    /// `after` (every session resolved after it; `before` and `tree` as things are). A session that would send a
    /// vault password somewhere it doesn't go yet (its login from a folder, or every password it sends when its
    /// place moves) needs the master password, asked once for the whole change, as editing the session would.
    /// Returns how it was confirmed, when it was needed, and the passwords to settle once it is saved.
    async fn confirm_folder_change(
        &self,
        ctx: &Context,
        tree: &Folders,
        before: &[SessionRecord],
        after: &[SessionRecord],
        reauth: Reauth<'_>,
        action: &str,
    ) -> Result<(Option<&'static str>, Vec<SecretId>)> {
        let Some(bindings) = &self.bindings else {
            return Ok((None, Vec::new()));
        };
        let old: HashMap<Uuid, &SessionRecord> = before.iter().map(|s| (s.id, s)).collect();
        let places = bindings.places_in(ctx, tree).await?;
        let mut sent = Vec::new();
        let mut new: Vec<(String, Destination)> = Vec::new();
        for s in after {
            let Some(b) = old.get(&s.id) else {
                continue;
            };
            let place = Destination::new(&s.host, s.port, s.jump_session_id);
            let moved = !place.same(&Destination::new(&b.host, b.port, b.jump_session_id));
            let old_login = b.auth.sent_secret();
            let login = s.auth.sent_secret();
            let mut check: Vec<SecretId> = Vec::new();
            if moved {
                check.extend(places.sent_by(s.id).into_iter().filter(|x| Some(*x) != old_login));
            }
            if let Some(login) = login {
                if (moved || Some(login) != old_login) && !check.contains(&login) {
                    check.push(login);
                }
            }
            for secret in check {
                sent.push(secret);
                if !bindings.may_go_in(ctx, &places, secret, &place, Some(s.id)).await? {
                    let what = bindings.describe(ctx, secret).await?;
                    if !new.iter().any(|(w, p)| *w == what && p.same(&place)) {
                        new.push((what, place.clone()));
                    }
                }
            }
        }
        if new.is_empty() {
            return Ok((None, sent));
        }
        let vault_password = match reauth {
            Reauth::Given => return Ok((Some(crate::vault::bindings::ASKED_NOW), sent)),
            Reauth::Ask(password) => password,
        };
        let (what, place) = &new[0];
        let more = match new.len() - 1 {
            0 => String::new(),
            1 => " and one more place".to_owned(),
            n => format!(" and {n} more places"),
        };
        let reason = format!(
            "This would send the {what} to {}:{}{more}, where no saved session sends it yet",
            place.host, place.port
        );
        let how = bindings.confirm(ctx, vault_password, action, &reason).await?;
        Ok((Some(how), sent))
    }

    /// QL-16: what a change of a folder's defaults changed, for the audit log.
    async fn defaults_changes(&self, ctx: &Context, a: &FolderDefaults, b: &FolderDefaults) -> Result<Vec<String>> {
        let (_, sessions) = self.names(ctx).await?;
        let not_set = || "not set".to_owned();
        let user = |d: &FolderDefaults| d.username.clone().unwrap_or_else(not_set);
        let login = |d: &FolderDefaults| d.auth.as_ref().map_or_else(not_set, SessionAuth::describe);
        let jump = |d: &FolderDefaults| {
            if d.jump_direct {
                "no jump host".to_owned()
            } else {
                d.jump_session_id
                    .map(|j| {
                        sessions
                            .get(&j)
                            .map_or_else(|| "a deleted session".to_owned(), |n| quoted(n))
                    })
                    .unwrap_or_else(not_set)
            }
        };
        let label = |d: &FolderDefaults| d.environment.map_or_else(not_set, |e| e.as_str().to_owned());
        let tags = |d: &FolderDefaults| {
            if d.tags.is_empty() {
                "none".to_owned()
            } else {
                d.tags.join(", ")
            }
        };
        let mut out = Vec::new();
        field_text(&mut out, "user", &user(a), &user(b));
        field_text(&mut out, "login", &login(a), &login(b));
        if a.auth != b.auth && login(a) == login(b) {
            out.push("login: another vault item".into());
        }
        field_text(&mut out, "jump host", &jump(a), &jump(b));
        field_text(&mut out, "environment", &label(a), &label(b));
        field_text(&mut out, "tags", &tags(a), &tags(b));
        Ok(out)
    }

    async fn folder(&self, ctx: &Context, id: Uuid) -> Result<SessionFolder> {
        let folders = self.folders(ctx).await?;
        Self::find_folder(&folders, id).cloned()
    }

    fn find_folder(folders: &[SessionFolder], id: Uuid) -> Result<&SessionFolder> {
        folders
            .iter()
            .find(|f| f.id == id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("folder {id}")))
    }

    /// "folder 'Customer A'" or "the top level", after checking the folder exists.
    fn folder_place(&self, folders: &[SessionFolder], folder: Option<Uuid>) -> Result<String> {
        match folder {
            None => Ok("the top level".into()),
            Some(id) => Ok(format!("folder {}", quoted(&Self::find_folder(folders, id)?.name))),
        }
    }

    fn check_unique_name(
        folders: &[SessionFolder],
        except: Option<Uuid>,
        parent: Option<Uuid>,
        name: &str,
    ) -> Result<()> {
        let taken = folders
            .iter()
            .any(|f| Some(f.id) != except && f.parent_id == parent && f.name.eq_ignore_ascii_case(name));
        if taken {
            return invalid(format!("There is already a folder named {} there.", quoted(name)));
        }
        Ok(())
    }

    /// The folder and every folder under it.
    fn descendants(folders: &[SessionFolder], root: Uuid) -> HashSet<Uuid> {
        let mut found = HashSet::from([root]);
        let mut grew = true;
        while grew {
            grew = false;
            for f in folders {
                if f.parent_id.is_some_and(|p| found.contains(&p)) && found.insert(f.id) {
                    grew = true;
                }
            }
        }
        found
    }

    async fn subtree(&self, ctx: &Context, root: Uuid) -> Result<HashSet<Uuid>> {
        let folders = self.folders(ctx).await?;
        Self::find_folder(&folders, root)?;
        Ok(Self::descendants(&folders, root))
    }

    /// Everything that needs the database: the folder exists, credentials are in the vault with the
    /// right kind, and the jump host exists and does not lead back to this session. QL-02 checks a
    /// quick connection with it too, saved or not.
    pub(crate) async fn check(&self, ctx: &Context, id: Option<Uuid>, input: SessionInput) -> Result<SessionInput> {
        let input = tidy(input)?;
        let folders = self.store.session_folders(ctx).await?;
        if let Some(folder) = input.folder_id {
            if folders.get(folder).is_none() {
                return Err(CoreError::UnknownTarget(format!("folder {folder}")));
            }
        }
        self.check_auth(ctx, &input.auth).await?;
        if let Some(vm) = &input.vm_id {
            if self.store.vm_by_id(ctx, vm).await?.is_none() {
                return invalid("The chosen VM is not in the VM list. Refresh the VMs and choose it again.");
            }
        }
        if let Some(jump) = input.jump_session_id {
            if Some(jump) == id {
                return invalid("A session can't be its own jump host.");
            }
        }
        // SS-12: a jump host is an SSH session, so one that others go through stays SSH.
        if let (Some(id), false) = (id, input.kind.is_ssh()) {
            let jumpers = self
                .store
                .list_sessions_in(ctx, &folders)
                .await?
                .into_iter()
                .filter(|s| s.jump_session_id == Some(id))
                .count();
            let in_folders = folders.all().any(|f| f.defaults.jump_session_id == Some(id));
            if jumpers > 0 || in_folders {
                return invalid(format!(
                    "This session is the jump host of {}, and a jump host is an SSH session. Choose another jump \
                     host for them first.",
                    if jumpers > 0 {
                        plural(jumpers, "session")
                    } else {
                        "a folder".to_owned()
                    }
                ));
            }
        }
        // QL-16: the jump host that applies, its own or its folders'.
        let effective = folders.resolve(id, &input.own(), input.folder_id);
        if let Some(jump) = effective.jump_session_id {
            let jumps = self.store.session_jumps_in(ctx, &folders).await?;
            if !jumps.contains_key(&jump) {
                return invalid("The chosen jump host is not a saved session.");
            }
            // SS-12: only an SSH session can carry the connection on.
            if let Some(hop) = self.store.get_session_in(ctx, jump, &folders).await? {
                if !hop.kind.is_ssh() {
                    return invalid(format!(
                        "'{}' is a {} session, and a jump host is an SSH session.",
                        hop.name,
                        hop.kind.label()
                    ));
                }
            }
            let from_folder = input.jump_session_id.is_none();
            let mut next = Some(jump);
            for _ in 0..MAX_JUMP_DEPTH {
                match next {
                    None => break,
                    Some(hop) if Some(hop) == id => {
                        return invalid(if from_folder {
                            "The jump host its folder sets reaches this session through its own jump host. Choose \
                             another jump host for it, or no jump host."
                        } else {
                            "That jump host reaches this session through its own jump host."
                        });
                    }
                    Some(hop) => next = jumps.get(&hop).copied().flatten(),
                }
            }
            if next.is_some() {
                return invalid(format!("That jump host chain is longer than {MAX_JUMP_DEPTH} hops."));
            }
        }
        Ok(input)
    }

    /// The vault items a login names exist and have the right kind (a password, a private key, its passphrase).
    async fn check_auth(&self, ctx: &Context, auth: &SessionAuth) -> Result<()> {
        if let SessionAuth::Key {
            key_id: None,
            passphrase_id: Some(_),
        } = auth
        {
            return invalid("Choose the private key the passphrase is for.");
        }
        let wanted = [
            (auth.credential_id(), auth_kind(auth)),
            (auth.passphrase_id(), Some(SecretKind::Passphrase)),
        ];
        for (secret, kind) in wanted {
            let (Some(secret), Some(kind)) = (secret, kind) else {
                continue;
            };
            match self.store.vault_item_kind(ctx, secret).await? {
                Some(found) if found == kind => {}
                Some(found) => {
                    return invalid(format!(
                        "That vault item is a {}, not a {}.",
                        found.label(),
                        kind.label()
                    ))
                }
                None => return invalid(format!("The chosen {} is not in the vault.", kind.label())),
            }
        }
        Ok(())
    }

    async fn names(&self, ctx: &Context) -> Result<(HashMap<Uuid, String>, HashMap<Uuid, String>)> {
        let folders = self.folders(ctx).await?.into_iter().map(|f| (f.id, f.name)).collect();
        let sessions = self
            .store
            .list_sessions(ctx)
            .await?
            .into_iter()
            .map(|s| (s.id, s.name))
            .collect();
        Ok((folders, sessions))
    }

    async fn vm_name(&self, ctx: &Context, id: Option<&str>) -> Result<Option<String>> {
        match id {
            Some(id) => Ok(self.store.vm_by_id(ctx, id).await?.map(|vm| vm.display_name)),
            None => Ok(None),
        }
    }

    /// One line for the audit log: where it connects and how, without any secret.
    async fn describe(&self, ctx: &Context, s: &SessionRecord) -> Result<String> {
        let (folders, sessions) = self.names(ctx).await?;
        let mut parts = vec![s.address()];
        // SS-12: what it opens; only SSH logs in with a login of the app's.
        parts.extend(s.kind.describe());
        if s.kind.is_ssh() {
            parts.push(s.auth.describe());
        }
        if s.environment != Environment::None {
            parts.push(format!("environment {}", s.environment.as_str()));
        }
        if let Some(folder) = s.folder_id.and_then(|f| folders.get(&f)) {
            parts.push(format!("in folder {}", quoted(folder)));
        }
        if let Some(jump) = s.jump_session_id.and_then(|j| sessions.get(&j)) {
            parts.push(format!("via {}", quoted(jump)));
        }
        if let Some(vm) = self.vm_name(ctx, s.vm_id.as_deref()).await? {
            parts.push(format!("reaches VM {}", quoted(&vm)));
        }
        if let Some(command) = &s.startup_command {
            parts.push(format!("with a startup command{}", self.rating(command, s.environment)));
            if s.startup_on_reconnect {
                parts.push("typed again after automatic reconnects".into());
            }
        }
        if let Some(hook) = s.prompt_hook {
            parts.push(format!("folder prompt hook {}", if hook { "on" } else { "off" }));
        }
        if !s.tags.is_empty() {
            parts.push(format!("tags {}", s.tags.join(", ")));
        }
        // QL-16: which of these come from its folders.
        let inherited = s.inherited.describe();
        if !inherited.is_empty() {
            parts.push(inherited);
        }
        Ok(parts.join(", "))
    }

    /// What an edit changed, one entry per field. The startup command's text is left out: it may
    /// hold something private, and the audit log is kept for good.
    async fn changes(&self, ctx: &Context, a: &SessionRecord, b: &SessionRecord) -> Result<Vec<String>> {
        let (folders, sessions) = self.names(ctx).await?;
        let folder = |f: Option<Uuid>| {
            f.and_then(|f| folders.get(&f))
                .map_or_else(|| "top level".to_owned(), |n| quoted(n))
        };
        let jump = |j: Option<Uuid>| {
            j.and_then(|j| sessions.get(&j))
                .map_or_else(|| "none".to_owned(), |n| quoted(n))
        };
        let none = |v: &Option<String>| v.clone().unwrap_or_else(|| "none".to_owned());
        // QL-16: "alice (from folder 'A')" for a value the session has from a folder.
        let shown = |value: String, from: &Option<FromFolder>| match from {
            Some(f) => format!("{value} (from folder {})", quoted(&f.name)),
            None => value,
        };
        let mut out = Vec::new();
        let mut field = |name: &str, before: String, after: String| {
            if before != after {
                out.push(format!("{name}: {before} -> {after}"));
            }
        };
        field("name", a.name.clone(), b.name.clone());
        // SS-12: the kind and its fields.
        let kind = |s: &SessionRecord| s.kind.describe().unwrap_or_else(|| "SSH".to_owned());
        field("kind", kind(a), kind(b));
        field("folder", folder(a.folder_id), folder(b.folder_id));
        field("host", a.host.clone(), b.host.clone());
        field("port", a.port.to_string(), b.port.to_string());
        field(
            "user",
            shown(none(&a.username), &a.inherited.username),
            shown(none(&b.username), &b.inherited.username),
        );
        field(
            "login",
            shown(a.auth.describe(), &a.inherited.auth),
            shown(b.auth.describe(), &b.inherited.auth),
        );
        field(
            "jump host",
            shown(jump(a.jump_session_id), &a.inherited.jump),
            shown(jump(b.jump_session_id), &b.inherited.jump),
        );
        field(
            "environment",
            shown(a.environment.as_str().to_owned(), &a.inherited.environment),
            shown(b.environment.as_str().to_owned(), &b.inherited.environment),
        );
        field(
            "colour",
            a.color.map_or("none", SessionColor::as_str).to_owned(),
            b.color.map_or("none", SessionColor::as_str).to_owned(),
        );
        let tags = |t: &[String]| if t.is_empty() { "none".to_owned() } else { t.join(", ") };
        field("tags", tags(&a.tags), tags(&b.tags));
        if a.vm_id != b.vm_id {
            let vm = |name: Option<String>| name.map_or_else(|| "none".to_owned(), |n| quoted(&n));
            let before = vm(self.vm_name(ctx, a.vm_id.as_deref()).await?);
            let after = vm(self.vm_name(ctx, b.vm_id.as_deref()).await?);
            out.push(format!("VM: {before} -> {after}"));
        }
        if a.auth.method() == b.auth.method() && a.auth != b.auth && a.auth.describe() == b.auth.describe() {
            out.push("login: another vault item".into());
        }
        if a.startup_command != b.startup_command {
            out.push(match (&a.startup_command, &b.startup_command) {
                (None, Some(c)) => format!("startup command added{}", self.rating(c, b.environment)),
                (Some(_), None) => "startup command removed".into(),
                (_, Some(c)) => format!("startup command changed{}", self.rating(c, b.environment)),
                _ => "startup command changed".into(),
            });
        }
        if a.startup_on_reconnect != b.startup_on_reconnect {
            out.push(if b.startup_on_reconnect {
                "startup command typed again after automatic reconnects".into()
            } else {
                "startup command no longer typed after automatic reconnects".into()
            });
        }
        let hook = |h: Option<bool>| match h {
            None => "as in Settings",
            Some(true) => "on",
            Some(false) => "off",
        };
        field_text(&mut out, "folder prompt hook", hook(a.prompt_hook), hook(b.prompt_hook));
        Ok(out)
    }

    /// SS-01: " (rated Medium: other)" for the audit log, when the library knows the rules.
    fn rating(&self, command: &str, environment: Environment) -> String {
        self.rate_startup(command, environment)
            .map(|rating| format!(" (rated {})", rating.describe()))
            .unwrap_or_default()
    }

    async fn audit(&self, ctx: &Context, action: &str, session: &SessionRecord, detail: Option<&str>) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[session.target()],
                    approval: None,
                    result: None,
                    detail,
                },
            )
            .await
            .map(drop)
    }

    async fn audit_folder(&self, ctx: &Context, action: &str, detail: Option<&str>) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail,
                },
            )
            .await
            .map(drop)
    }
}

/// SS-04, AP-06: how an edit that sends a vault password to a new place is confirmed.
#[derive(Clone, Copy)]
pub(crate) enum Reauth<'a> {
    /// With this master password, or by asking for it (`None`).
    Ask(Option<&'a SecretString>),
    /// The caller asked for it already (FD-07, once for a whole import).
    Given,
}

/// The name a session will have: its own, or the host's.
fn display_name(input: &SessionInput) -> String {
    if input.name.trim().is_empty() {
        input.host.clone()
    } else {
        input.name.clone()
    }
}

impl SessionInput {
    /// SS-04: the vault password the host receives when the session logs in with its own login (keys never leave
    /// this PC). QL-16: a login from its folders is [`Effective::sent_secret`].
    pub(crate) fn sent_secret(&self) -> Option<SecretId> {
        self.auth.sent_secret()
    }
}

/// The vault kind a login's credential must have.
fn auth_kind(auth: &SessionAuth) -> Option<SecretKind> {
    match auth {
        SessionAuth::Password { .. } => Some(SecretKind::Password),
        SessionAuth::Key { .. } => Some(SecretKind::PrivateKey),
        SessionAuth::Agent | SessionAuth::Folder => None,
    }
}

/// QL-16: every session as it would be after a change: in the folder `folder_of` says, resolved against `folders`.
fn resolved_after(
    before: &[SessionRecord],
    folders: &Folders,
    folder_of: impl Fn(&SessionRecord) -> Option<Uuid>,
) -> Vec<SessionRecord> {
    before
        .iter()
        .map(|s| {
            let mut s = s.clone();
            s.folder_id = folder_of(&s);
            let effective = s.resolve_in(folders);
            s.apply(effective);
            s
        })
        .collect()
}

/// QL-28, F4: whether a session of `kind` takes `auth` as its login: SSH any; WinRM a password (or its folders');
/// the rest none.
fn takes_login(kind: &SessionKind, auth: &SessionAuth) -> bool {
    kind.logs_in_with_vault()
        && (kind.takes_keys() || matches!(auth, SessionAuth::Password { .. } | SessionAuth::Folder))
}

/// QL-28: what a bulk edit changes on one session (`a` before, `b` after, both resolved), field by field; a value it
/// has from a folder says which.
/// QL-28, SS-12: the fields of a bulk edit a session of this kind doesn't take, which [`tidy`] leaves as they are.
fn skipped_for_kind(kind: &SessionKind, edit: &BulkEdit) -> Vec<String> {
    let mut out = Vec::new();
    for (asked, applies, field, verb) in [
        (edit.port.is_some(), kind.has_port(), "Port", "has"),
        (
            edit.auth.is_some(),
            edit.auth.as_ref().is_some_and(|auth| takes_login(kind, auth)),
            "Login",
            "takes",
        ),
        (edit.jump.is_some(), kind.takes_jump_host(), "Jump host", "takes"),
    ] {
        if asked && !applies {
            out.push(format!(
                "{field} stays as it is: a {} session {verb} none",
                kind.label()
            ));
        }
    }
    out
}

fn bulk_changes(
    folders: &HashMap<Uuid, String>,
    sessions: &HashMap<Uuid, String>,
    a: &SessionRecord,
    b: &SessionRecord,
) -> Vec<FieldChange> {
    let folder = |f: Option<Uuid>| {
        f.and_then(|f| folders.get(&f))
            .map_or_else(|| "top level".to_owned(), |n| n.clone())
    };
    let jump = |j: Option<Uuid>| {
        j.and_then(|j| sessions.get(&j))
            .map_or_else(|| "none".to_owned(), |n| n.clone())
    };
    let shown = |value: String, from: &Option<FromFolder>| match from {
        Some(f) => format!("{value} (from folder {})", quoted(&f.name)),
        None => value,
    };
    let tags = |t: &[String]| if t.is_empty() { "none".to_owned() } else { t.join(", ") };
    let mut out = Vec::new();
    let mut field = |name: &str, before: String, after: String| {
        if before != after {
            out.push(FieldChange {
                field: name.to_owned(),
                before,
                after,
            });
        }
    };
    field("Folder", folder(a.folder_id), folder(b.folder_id));
    field("Port", a.port.to_string(), b.port.to_string());
    field(
        "User",
        shown(
            a.username.clone().unwrap_or_else(|| "none".into()),
            &a.inherited.username,
        ),
        shown(
            b.username.clone().unwrap_or_else(|| "none".into()),
            &b.inherited.username,
        ),
    );
    let mut login_a = shown(a.auth.describe(), &a.inherited.auth);
    let mut login_b = shown(b.auth.describe(), &b.inherited.auth);
    if a.auth != b.auth && login_a == login_b {
        login_a.push_str(" (one vault item)");
        login_b.push_str(" (another vault item)");
    }
    field("Login", login_a, login_b);
    field(
        "Jump host",
        shown(jump(a.jump_session_id), &a.inherited.jump),
        shown(jump(b.jump_session_id), &b.inherited.jump),
    );
    field(
        "Environment",
        shown(a.environment.as_str().to_owned(), &a.inherited.environment),
        shown(b.environment.as_str().to_owned(), &b.inherited.environment),
    );
    field("Tags", tags(&a.tags), tags(&b.tags));
    out
}

/// SS-07, QL-16: no session `which` picks reaches itself through its jump hosts, or through more than
/// [`MAX_JUMP_DEPTH`] of them, once a change gives it its folders' jump host.
fn check_jump_loops(after: &[SessionRecord], which: impl Fn(&SessionRecord) -> bool) -> Result<()> {
    let jumps: HashMap<Uuid, Option<Uuid>> = after.iter().map(|s| (s.id, s.jump_session_id)).collect();
    for s in after.iter().filter(|s| which(s)) {
        let mut next = s.jump_session_id;
        for _ in 0..MAX_JUMP_DEPTH {
            match next {
                None => break,
                Some(hop) if hop == s.id => {
                    return invalid(format!(
                        "With that change, {} would reach itself through its jump hosts. Choose another jump host, \
                         or no jump host for it.",
                        quoted(&s.name)
                    ));
                }
                Some(hop) => next = jumps.get(&hop).copied().flatten(),
            }
        }
        if next.is_some() {
            return invalid(format!(
                "With that change, {} would go through more than {MAX_JUMP_DEPTH} jump hosts.",
                quoted(&s.name)
            ));
        }
    }
    Ok(())
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(host: &str) -> SessionInput {
        SessionInput {
            name: String::new(),
            folder_id: None,
            host: host.into(),
            port: 22,
            username: Some("alice".into()),
            auth: SessionAuth::Agent,
            jump_session_id: None,
            jump_direct: false,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: Environment::None,
            color: None,
            tags: vec![],
            vm_id: None,
            kind: Default::default(),
        }
    }

    fn record(name: &str) -> SessionRecord {
        SessionRecord {
            id: Uuid::new_v4(),
            folder_id: None,
            name: name.into(),
            protocol: "ssh".into(),
            host: format!("{name}.example.com"),
            port: 22,
            username: Some("alice".into()),
            auth: SessionAuth::Agent,
            jump_session_id: None,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: Environment::Lab,
            color: None,
            protected: false,
            tags: vec![],
            vm_id: None,
            vm_link: None,
            imported_from: None,
            created_at: String::new(),
            updated_at: String::new(),
            last_ip: None,
            last_hostname: None,
            last_seen_at: None,
            last_opened_at: None,
            own: OwnValues {
                username: Some("alice".into()),
                auth: SessionAuth::Agent,
                jump_session_id: None,
                jump_direct: false,
                environment: Environment::Lab,
                tags: vec![],
            },
            inherited: Inherited::default(),
            kind: Default::default(),
        }
    }

    #[test]
    fn tidy_trims_and_names_a_session_after_its_host() {
        let mut i = input("  web01.example.com ");
        i.username = Some("   ".into());
        i.startup_command = Some("  \n ".into());
        i.tags = vec![" lab ".into(), "LAB".into(), "web".into()];
        let t = tidy(i).unwrap();
        assert_eq!(t.host, "web01.example.com");
        assert_eq!(t.name, "web01.example.com");
        assert_eq!(t.username, None);
        assert_eq!(t.startup_command, None);
        assert_eq!(t.tags, ["lab", "web"]);
    }

    #[test]
    fn hosts_ports_and_names_are_checked() {
        for ok in [
            "192.0.2.10",
            "web01.example.com",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "db_1.test",
        ] {
            assert!(tidy(input(ok)).is_ok(), "{ok}");
        }
        for bad in ["", "   ", "alice@web01.example.com", "web 01", "web01;rm", "web\n01"] {
            assert!(tidy(input(bad)).is_err(), "{bad:?}");
        }
        let mut zero = input("web01.example.com");
        zero.port = 0;
        assert!(tidy(zero).is_err());
        let mut long = input("web01.example.com");
        long.name = "x".repeat(MAX_SESSION_NAME + 1);
        assert!(tidy(long).is_err());
        let mut tab = input("web01.example.com");
        tab.name = "web\t01".into();
        assert!(tidy(tab).is_err());
    }

    #[test]
    fn startup_commands_may_span_lines_but_hold_no_other_control_characters() {
        let mut multi = input("web01.example.com");
        multi.startup_command = Some("cd /srv\n\tls -la".into());
        assert!(tidy(multi).is_ok());
        let mut escape = input("web01.example.com");
        escape.startup_command = Some("echo \u{1b}[31m".into());
        assert!(tidy(escape).is_err());
        let mut long = input("web01.example.com");
        long.startup_command = Some("x".repeat(MAX_STARTUP_COMMAND + 1));
        assert!(tidy(long).is_err());
    }

    #[test]
    fn a_passphrase_needs_its_key() {
        let mut i = input("web01.example.com");
        i.auth = SessionAuth::Key {
            key_id: None,
            passphrase_id: Some(SecretId(Uuid::new_v4())),
        };
        assert!(tidy(i).is_err());
    }

    #[test]
    fn too_many_tags_are_refused() {
        let mut i = input("web01.example.com");
        i.tags = (0..=MAX_TAGS).map(|n| format!("t{n}")).collect();
        assert!(tidy(i).is_err());
    }

    #[test]
    fn filters_match_text_tags_and_environments() {
        let mut web = record("web01");
        web.tags = vec!["Frontend".into()];
        web.startup_command = Some("tail -f /var/log/syslog".into());
        assert!(SessionFilter::default().matches(&web));
        for text in ["WEB0", "example.com", "ALICE", "frontend", "syslog"] {
            let f = SessionFilter {
                text: text.into(),
                ..Default::default()
            };
            assert!(f.matches(&web), "{text}");
        }
        let miss = SessionFilter {
            text: "db".into(),
            ..Default::default()
        };
        assert!(!miss.matches(&web));
        let tag_or = SessionFilter {
            tags: vec!["backend".into(), "FRONTEND".into()],
            ..Default::default()
        };
        assert!(tag_or.matches(&web));
        let prod = SessionFilter {
            environments: vec![Environment::Prod],
            ..Default::default()
        };
        assert!(!prod.matches(&web), "web01 is Lab");
        web.environment = Environment::Prod;
        assert!(prod.matches(&web));
    }

    #[test]
    fn auth_round_trips_through_json() {
        let id = SecretId(Uuid::new_v4());
        let auth = SessionAuth::Key {
            key_id: Some(id),
            passphrase_id: None,
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"method":"key","keyId":"{id}","passphraseId":null}}"#)
        );
        assert_eq!(serde_json::from_str::<SessionAuth>(&json).unwrap(), auth);
        let agent: SessionAuth = serde_json::from_str(r#"{"method":"agent"}"#).unwrap();
        assert_eq!(agent, SessionAuth::Agent);
        assert_eq!(auth.credential_id(), Some(id));
        assert_eq!(auth.method(), "key");
    }

    #[test]
    fn colours_round_trip_through_their_names() {
        for c in SessionColor::ALL {
            assert_eq!(SessionColor::parse(c.as_str()), Some(c));
        }
        assert_eq!(SessionColor::parse("#ff0000"), None);
    }

    #[test]
    fn descendants_cover_the_whole_subtree() {
        let folder = |id: Uuid, parent: Option<Uuid>| SessionFolder {
            id,
            parent_id: parent,
            name: id.to_string(),
            sort_order: 0,
            defaults: FolderDefaults::default(),
        };
        let (a, b, c, d) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let folders = [folder(a, None), folder(b, Some(a)), folder(c, Some(b)), folder(d, None)];
        assert_eq!(SessionLibrary::descendants(&folders, a), HashSet::from([a, b, c]));
        assert_eq!(SessionLibrary::descendants(&folders, d), HashSet::from([d]));
    }
}
