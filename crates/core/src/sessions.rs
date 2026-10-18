//! Session library (SS-01, SS-06): saved SSH sessions in folders, with tags, colours, search and an
//! environment label.
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

pub mod tree;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::remote::{AuthMethod, Credentials, SessionSpec};
use crate::domain::{Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::store::{clean_name, NewAuditEntry, Store, MAX_TAG_LEN};
use crate::vault::{SecretId, SecretKind, SecretString, Vault};
use crate::vm_links::{AutoLinkReport, VmLink, VmLinks};
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
}

impl SessionAuth {
    /// The `sessions.auth_method` value.
    pub fn method(&self) -> &'static str {
        match self {
            SessionAuth::Password { .. } => "password",
            SessionAuth::Key { .. } => "key",
            SessionAuth::Agent => "agent",
        }
    }

    /// The password or private key (`sessions.credential_id`).
    pub fn credential_id(&self) -> Option<SecretId> {
        match self {
            SessionAuth::Password { password_id } => *password_id,
            SessionAuth::Key { key_id, .. } => *key_id,
            SessionAuth::Agent => None,
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
    #[serde(default)]
    pub jump_session_id: Option<Uuid>,
    #[serde(default)]
    pub startup_command: Option<String>,
    #[serde(default)]
    pub environment: Environment,
    #[serde(default)]
    pub color: Option<SessionColor>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// BX-01: the VM this session reaches (its `vms.id`), so a bulk run can pick the VM. A Prod or
    /// protected VM makes the session count as Prod or protected too.
    #[serde(default)]
    pub vm_id: Option<String>,
}

fn default_port() -> u16 {
    22
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub id: Uuid,
    pub folder_id: Option<Uuid>,
    pub name: String,
    /// `ssh` in the MVP; RDP, VNC, serial and WinRM come in v3 (SS-12).
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub auth: SessionAuth,
    pub jump_session_id: Option<Uuid>,
    pub startup_command: Option<String>,
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
}

impl SessionRecord {
    /// As a command target, with the label the policy engine reads (SS-06).
    pub fn target(&self) -> Target {
        Target {
            target: TargetRef::Session { session_id: self.id },
            name: self.name.clone(),
            environment: self.environment,
            protected: self.protected,
        }
    }

    fn address(&self) -> String {
        let user = self.username.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
        format!("{user}{}:{}", self.host, self.port)
    }

    /// The editor's view of this session, to start a copy or compare an edit.
    fn input(&self) -> SessionInput {
        SessionInput {
            name: self.name.clone(),
            folder_id: self.folder_id,
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            auth: self.auth.clone(),
            jump_session_id: self.jump_session_id,
            startup_command: self.startup_command.clone(),
            environment: self.environment,
            color: self.color,
            tags: self.tags.clone(),
            vm_id: self.vm_id.clone(),
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

pub const MAX_SESSION_NAME: usize = 100;
pub const MAX_FOLDER_NAME: usize = 60;
pub const MAX_HOST_LEN: usize = 253;
pub const MAX_USERNAME_LEN: usize = 100;
pub const MAX_STARTUP_COMMAND: usize = 4096;
pub const MAX_TAGS: usize = 20;
/// Jump hosts followed before a chain counts as too long (SS-07 chains are v2).
const MAX_JUMP_DEPTH: usize = 8;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// Trims every field and checks what can be checked without the database.
fn tidy(mut input: SessionInput) -> Result<SessionInput> {
    input.host = input.host.trim().to_owned();
    if input.host.is_empty() {
        return invalid("Enter the host name or IP address.");
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

    input.username = input.username.map(|u| u.trim().to_owned()).filter(|u| !u.is_empty());
    if let Some(user) = &input.username {
        if user.chars().count() > MAX_USERNAME_LEN {
            return invalid(format!("A user name can be at most {MAX_USERNAME_LEN} characters."));
        }
        if user.chars().any(char::is_control) {
            return invalid("A user name can't hold line breaks or tabs.");
        }
    }

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

    let mut seen = HashSet::new();
    let mut tags = Vec::new();
    for tag in &input.tags {
        let tag = clean_name("tag", tag, MAX_TAG_LEN)?;
        if seen.insert(tag.to_lowercase()) {
            tags.push(tag);
        }
    }
    if tags.len() > MAX_TAGS {
        return invalid(format!("A session can have at most {MAX_TAGS} tags."));
    }
    tags.sort_by_key(|t| t.to_lowercase());
    input.tags = tags;
    Ok(input)
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

pub struct SessionLibrary {
    store: Store,
    links: Arc<VmLinks>,
}

impl SessionLibrary {
    pub fn new(store: Store, links: Arc<VmLinks>) -> Self {
        Self { store, links }
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
        let input = self.check(ctx, None, input).await?;
        let id = Uuid::new_v4();
        self.store.insert_session(ctx, id, &input, None).await?;
        if input.vm_id.is_some() {
            self.store.set_vm_link_kind(ctx, id, Some(VmLink::Manual)).await?;
        }
        let session = self.get(ctx, id).await?;
        let detail = self.describe(ctx, &session).await?;
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

    /// Saves an edit. Audited with what changed; an edit that changes nothing writes nothing.
    ///
    /// QL-01: a VM chosen (or removed) in the editor is the user's choice, which auto-linking never
    /// changes. A new host makes an automatic link, or the removal of one, out of date: the session
    /// is linked again by its new address.
    pub async fn update(&self, ctx: &Context, id: Uuid, input: SessionInput) -> Result<SessionRecord> {
        let before = self.get(ctx, id).await?;
        let mut input = self.check(ctx, Some(id), input).await?;
        if input == before.input() {
            return Ok(before);
        }
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
        let after = self.get(ctx, id).await?;
        let changes = self.changes(ctx, &before, &after).await?;
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

    /// Sessions that jumped through it lose their jump host; the vault keeps its credentials.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        let session = self.get(ctx, id).await?;
        let jumpers = self
            .store
            .session_jumps(ctx)
            .await?
            .values()
            .filter(|jump| **jump == Some(id))
            .count();
        if !self.store.delete_session(ctx, id).await? {
            return Err(CoreError::UnknownTarget(format!("session {id}")));
        }
        let mut detail = session.address();
        match jumpers {
            0 => {}
            1 => detail.push_str("; 1 session used it as its jump host and now has none"),
            n => detail.push_str(&format!("; {n} sessions used it as their jump host and now have none")),
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
        if ids.is_empty() {
            return Err(CoreError::NoTargets);
        }
        let folders = self.folders(ctx).await?;
        let place = self.folder_place(&folders, folder)?;
        let mut targets = Vec::with_capacity(ids.len());
        for id in ids {
            targets.push(self.get(ctx, *id).await?.target());
        }
        self.store.move_sessions(ctx, ids, folder).await?;
        let what = match ids.len() {
            1 => format!("session {}", quoted(&targets[0].name)),
            n => format!("{n} sessions"),
        };
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
                    detail: None,
                },
            )
            .await
            .map(drop)
    }

    pub async fn create_folder(&self, ctx: &Context, name: &str, parent: Option<Uuid>) -> Result<SessionFolder> {
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
        self.store.update_session_folder(ctx, id, &folder.name, parent).await?;
        self.audit_folder(ctx, &format!("Moved folder {} to {place}", quoted(&folder.name)), None)
            .await?;
        self.folder(ctx, id).await
    }

    /// Deletes a folder only: its sessions and subfolders move up to its parent.
    pub async fn delete_folder(&self, ctx: &Context, id: Uuid) -> Result<()> {
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
        self.store.delete_session_folder(ctx, id, folder.parent_id).await?;
        let detail = format!(
            "{} and {} moved to {place}",
            plural(sessions, "session"),
            plural(subfolders, "folder")
        );
        self.audit_folder(ctx, &format!("Deleted folder {}", quoted(&folder.name)), Some(&detail))
            .await
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
        if let Some(folder) = input.folder_id {
            Self::find_folder(&self.folders(ctx).await?, folder)?;
        }
        let wanted = [
            (input.auth.credential_id(), input.auth_kind()),
            (input.auth.passphrase_id(), Some(SecretKind::Passphrase)),
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
        if let Some(vm) = &input.vm_id {
            if self.store.vm_by_id(ctx, vm).await?.is_none() {
                return invalid("The chosen VM is not in the VM list. Refresh the VMs and choose it again.");
            }
        }
        if let Some(jump) = input.jump_session_id {
            if Some(jump) == id {
                return invalid("A session can't be its own jump host.");
            }
            let jumps = self.store.session_jumps(ctx).await?;
            if !jumps.contains_key(&jump) {
                return invalid("The chosen jump host is not a saved session.");
            }
            let mut next = Some(jump);
            for _ in 0..MAX_JUMP_DEPTH {
                match next {
                    None => break,
                    Some(hop) if Some(hop) == id => {
                        return invalid("That jump host reaches this session through its own jump host.");
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
        let mut parts = vec![s.address(), s.auth.describe()];
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
        if s.startup_command.is_some() {
            parts.push("with a startup command".into());
        }
        if !s.tags.is_empty() {
            parts.push(format!("tags {}", s.tags.join(", ")));
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
        let mut out = Vec::new();
        let mut field = |name: &str, before: String, after: String| {
            if before != after {
                out.push(format!("{name}: {before} -> {after}"));
            }
        };
        field("name", a.name.clone(), b.name.clone());
        field("folder", folder(a.folder_id), folder(b.folder_id));
        field("host", a.host.clone(), b.host.clone());
        field("port", a.port.to_string(), b.port.to_string());
        field("user", none(&a.username), none(&b.username));
        field("login", a.auth.describe(), b.auth.describe());
        field("jump host", jump(a.jump_session_id), jump(b.jump_session_id));
        field(
            "environment",
            a.environment.as_str().to_owned(),
            b.environment.as_str().to_owned(),
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
                (None, Some(_)) => "startup command added".into(),
                (Some(_), None) => "startup command removed".into(),
                _ => "startup command changed".into(),
            });
        }
        Ok(out)
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

impl SessionInput {
    /// The vault kind the credential must have.
    fn auth_kind(&self) -> Option<SecretKind> {
        match self.auth {
            SessionAuth::Password { .. } => Some(SecretKind::Password),
            SessionAuth::Key { .. } => Some(SecretKind::PrivateKey),
            SessionAuth::Agent => None,
        }
    }
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
            startup_command: None,
            environment: Environment::None,
            color: None,
            tags: vec![],
            vm_id: None,
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
        };
        let (a, b, c, d) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let folders = [folder(a, None), folder(b, Some(a)), folder(c, Some(b)), folder(d, None)];
        assert_eq!(SessionLibrary::descendants(&folders, a), HashSet::from([a, b, c]));
        assert_eq!(SessionLibrary::descendants(&folders, d), HashSet::from([d]));
    }
}
