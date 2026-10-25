//! FD-07: encrypted export and import of the session library, so sessions move between the owner's
//! laptops (and, later, to a teammate).
//!
//! * Export writes one file (see [`file`]) with the session folders (QL-16: with their defaults), the sessions
//!   (with their tags, environment labels and colours: what each sets itself, so it takes the rest from its folders
//!   again), the trusted host keys, the favourite commands (BX-08) and, only
//!   when the user ticks it, the vault's secrets with their values. The user chooses the passphrase; Argon2id turns it into the
//!   AES-256-GCM key. The passphrase passes the same strength check as a new vault password (SS-04) and
//!   may not be the vault password itself. The vault's labels always go along (they are not secret), so
//!   on the other laptop sessions find secrets with the same label even when the values stayed behind. Exporting secret
//!   values asks for the vault password again, as Critical actions do (AP-06): otherwise anyone at an
//!   unlocked laptop could carry every secret away under a passphrase of their own.
//! * Import opens the file with its passphrase, compares it with this laptop's library and shows a
//!   preview: each session, known host and secret is new, already here, or in conflict with something
//!   here (the same session changed, the same user, host and port, the same name; another key trusted
//!   for the host; another value under the label; another command under the favourite's folder and
//!   name). The user chooses per item: skip, replace, or keep
//!   both. The opened file stays in the core under an id until it is imported or closed, so the commit
//!   names rows only, and no path or secret comes back from the UI.
//! * Every change goes through the module that owns the data (session library, vault, known hosts,
//!   the command panel's favourites),
//!   so it is checked and audited as if the user had made it there. Export and import themselves are
//!   audited with counts and the file path, never the contents.
//! * SS-04, AP-06: an import whose sessions would send passwords already in this vault (found by label,
//!   for a file without values or a secret skipped), or that moves a session that sends vault passwords
//!   to another host, asks for the vault password once: otherwise a crafted file could point a session
//!   at a server of someone's choosing with a customer's password. QL-16: so does one whose sessions would
//!   log in with a folder's password already here, or whose folder defaults give one to sessions, or change
//!   the jump host or login of a folder here whose sessions send vault passwords. When the vault locks, an
//!   opened file (which may hold secret values) is closed.
//! * QL-16: a folder's defaults come along with it. A folder new here gets the file's; one here already with
//!   other defaults is a choice (keep this laptop's, the default, or take the file's).
//! * An export is never written into a Git working tree (the default folder is Documents), so it can't
//!   end up in a commit by mistake.
//!
//! Nothing here touches a VM or a remote host, so it skips the command bus, like the session library.

pub mod file;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::adapters::containers::EngineKind;
use crate::adapters::remote::forward::ForwardKind;
use crate::containers::{ContainerMarks, MarkInput, SudoMode};
use crate::domain::{now_rfc3339, Context, Environment};
use crate::error::{CoreError, Result};
use crate::forwards::{ForwardInput, Forwards};
use crate::known_hosts::{address, HostKey, KnownHost, KnownHosts};
use crate::locks;
use crate::policy::PolicyEngine;
use crate::presentation::Change;
use crate::sessions::{
    rate_startup, FolderDefaults, Folders, OwnValues, Reauth, SessionAuth, SessionColor, SessionFolder, SessionInput,
    SessionLibrary, SessionRecord, StartupRating,
};
use crate::snippets::{FavouriteInput, Snippets};
use crate::ssh_keys::PublicKeyInfo;
use crate::store::{FavouriteRow, NewAuditEntry, Store};
use crate::vault::{
    check_new_password, Destination, KdfParams, SecretBindings, SecretId, SecretKind, SecretMeta, SecretString,
    VaultService, VaultStatus, MAX_LABEL_LEN,
};
use crate::vm_links::VmLink;

pub use file::{FORMAT, FORMAT_VERSION, MAX_FILE_BYTES};

/// The export file's extension.
pub const FILE_EXTENSION: &str = "remotely";

/// `remotely-export-2026-10-19.remotely` (the local date), the name the save dialog suggests.
pub fn default_file_name() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let date = now.date();
    format!("remotely-export-{date}.{FILE_EXTENSION}")
}

/// The `imported_from` values the database takes (SS-02's sources); anything else in a file is dropped.
const IMPORTED_FROM: [&str; 4] = ["putty", "mobaxterm", "openssh", "csv"];

/// How the audit log and the session audit entries name the source.
const SOURCE: &str = "a Remotely export";

// ---- The payload (encrypted in the file) ---------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    exported_at: String,
    /// The app and version that wrote it, for the preview.
    #[serde(default)]
    exported_by: String,
    #[serde(default)]
    folders: Vec<FolderEntry>,
    #[serde(default)]
    sessions: Vec<SessionEntry>,
    #[serde(default)]
    known_hosts: Vec<KnownHostEntry>,
    /// Every vault item's label and kind; values only when the user ticked "include secrets".
    #[serde(default)]
    secrets: Vec<SecretEntry>,
    /// BX-08, in the order the panel shows them.
    #[serde(default)]
    favourites: Vec<FavouriteEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FavouriteEntry {
    /// `""`: the top level.
    #[serde(default)]
    folder: String,
    name: String,
    command: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderEntry {
    id: Uuid,
    #[serde(default)]
    parent_id: Option<Uuid>,
    name: String,
    /// QL-16: what it sets for its sessions, with vault items and the jump host by their ids in this file. Files
    /// from before 0.5.0 have none.
    #[serde(default, skip_serializing_if = "FolderDefaults::is_empty")]
    defaults: FolderDefaults,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionEntry {
    id: Uuid,
    #[serde(default)]
    folder_id: Option<Uuid>,
    name: String,
    host: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    auth: SessionAuth,
    #[serde(default)]
    jump_session_id: Option<Uuid>,
    /// QL-16: no jump host, whatever its folders set. Files from before 0.5.0 have none.
    #[serde(default)]
    jump_direct: bool,
    #[serde(default)]
    startup_command: Option<String>,
    #[serde(default)]
    environment: Environment,
    #[serde(default)]
    color: Option<SessionColor>,
    #[serde(default)]
    tags: Vec<String>,
    /// The VM it reached on the exporting laptop. Linked again here when a VM has the same .vmx path.
    #[serde(default)]
    vm: Option<VmHint>,
    #[serde(default)]
    imported_from: Option<String>,
    /// SS-07: its saved port forwards, in order. Files from before 0.3.0 have none.
    #[serde(default)]
    forwards: Vec<ForwardEntry>,
    /// CT-01: the container engines it is marked with. Files from before 0.4.0 have none.
    #[serde(default)]
    containers: Vec<ContainerEntry>,
}

impl SessionEntry {
    /// QL-16: what it sets itself, as in the file.
    fn own(&self) -> OwnValues {
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

/// QL-16: the file's folders with their defaults (ids as in the file), to see what applies to its sessions.
fn file_folders(payload: &Payload) -> Folders {
    Folders::new(payload.folders.iter().map(|f| SessionFolder {
        id: f.id,
        parent_id: f.parent_id,
        name: f.name.clone(),
        sort_order: 0,
        defaults: f.defaults.clone(),
    }))
}

/// CT-01: one engine of a session marked as a container host.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerEntry {
    engine: EngineKind,
    /// A chosen sudo password is a vault item in the file, by id; one that did not come along means the
    /// login password here.
    #[serde(default)]
    sudo: SudoMode,
}

impl ContainerEntry {
    fn input(&self, secrets: &HashMap<SecretId, SecretId>) -> MarkInput {
        let sudo = match self.sudo {
            SudoMode::Password { password_id: Some(id) } => SudoMode::Password {
                password_id: secrets.get(&id).copied(),
            },
            other => other,
        };
        MarkInput {
            engine: self.engine,
            sudo,
        }
    }
}

/// SS-07: one saved port forward of a session.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForwardEntry {
    #[serde(default)]
    label: Option<String>,
    kind: ForwardKind,
    bind_address: String,
    bind_port: u16,
    #[serde(default)]
    dest_host: String,
    #[serde(default)]
    dest_port: u16,
    #[serde(default)]
    auto_start: bool,
}

impl ForwardEntry {
    /// "local 127.0.0.1:8080 -> db01.example.com:5432, starts with the terminal", for the preview.
    fn describe(&self) -> String {
        let bind = address(&self.bind_address, self.bind_port);
        let dest = address(&self.dest_host, self.dest_port);
        let what = match self.kind {
            ForwardKind::Local => format!("local {bind} -> {dest}"),
            ForwardKind::Remote => format!("remote {bind} on the host -> {dest}"),
            ForwardKind::Dynamic => format!("SOCKS proxy on {bind}"),
        };
        if self.auto_start {
            format!("{what}, starts with the terminal")
        } else {
            what
        }
    }

    fn input(&self) -> ForwardInput {
        ForwardInput {
            id: None,
            label: self.label.clone(),
            kind: self.kind,
            bind_address: self.bind_address.clone(),
            bind_port: self.bind_port,
            dest_host: self.dest_host.clone(),
            dest_port: self.dest_port,
            auto_start: self.auto_start,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VmHint {
    vmx_path: String,
    name: String,
    /// QL-01: auto-linking made the link (and keeps it up to date); otherwise the user chose it.
    #[serde(default)]
    auto: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KnownHostEntry {
    host: String,
    port: u16,
    key_type: String,
    fingerprint: String,
    #[serde(default)]
    first_seen_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretEntry {
    id: SecretId,
    kind: SecretKind,
    label: String,
    #[serde(default, serialize_with = "expose", skip_serializing_if = "Option::is_none")]
    value: Option<SecretString>,
    /// SS-09: a private key's public half, when it is known.
    #[serde(default)]
    public_key: Option<PublicKeyInfo>,
    #[serde(default)]
    generated: bool,
}

/// Secret values are written only into the payload, which is encrypted before it leaves memory.
fn expose<S: Serializer>(value: &Option<SecretString>, serializer: S) -> std::result::Result<S::Ok, S::Error> {
    match value {
        Some(secret) => serializer.serialize_some(secret.expose()),
        None => serializer.serialize_none(),
    }
}

// ---- What the UI sees and sends --------------------------------------------------------------------

/// What the export dialog sends.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    /// Encrypts the file. The other laptop needs it to import.
    pub passphrase: SecretString,
    #[serde(default = "yes")]
    pub include_known_hosts: bool,
    /// Also the vault's secret values. Needs `vault_password`.
    #[serde(default)]
    pub include_secrets: bool,
    #[serde(default)]
    pub vault_password: Option<SecretString>,
}

fn yes() -> bool {
    true
}

/// What an export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReport {
    pub path: String,
    pub folders: usize,
    pub sessions: usize,
    pub known_hosts: usize,
    /// Vault items named in the file (labels and kinds).
    pub secrets: usize,
    /// Their values are in the file too.
    pub secret_values: bool,
    /// BX-08 favourite commands.
    pub favourites: usize,
    /// SS-07 saved port forwards, over all sessions.
    pub forwards: usize,
    /// CT-01 sessions marked as container hosts.
    pub container_hosts: usize,
    /// QL-16 folders with defaults.
    pub folder_defaults: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemStatus {
    /// Not here yet.
    New,
    /// Here already, the same.
    Same,
    /// Something here matches it but differs; the user decides.
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemAction {
    /// Add it (new items).
    Import,
    Skip,
    /// Overwrite what it conflicts with here, keeping that item's identity.
    Replace,
    /// Add it beside what it conflicts with, renamed when the name is taken.
    KeepBoth,
}

impl ItemAction {
    fn label(self) -> &'static str {
        match self {
            ItemAction::Import => "imported",
            ItemAction::Skip => "skipped",
            ItemAction::Replace => "replaced",
            ItemAction::KeepBoth => "kept as a second copy",
        }
    }
}

/// One session, known host or secret of the file, compared with this laptop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewItem {
    /// Its place in the file; the commit names items by it.
    pub index: usize,
    pub name: String,
    pub detail: String,
    pub status: ItemStatus,
    /// What it matches here, and how.
    pub conflict: Option<String>,
    pub choices: Vec<ItemAction>,
    pub default_action: ItemAction,
    /// What importing it means, e.g. which saved password a session would log in with.
    pub notes: Vec<String>,
    /// SS-01: a session's startup command, typed into its shell at every connection. Left out unless
    /// the user ticks it ([`TransferCommit::keep_startup`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_rating: Option<StartupRating>,
    /// SS-07: a session's saved port forwards, described. Left out unless the user ticks them
    /// ([`TransferCommit::keep_forwards`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferPreview {
    pub id: Uuid,
    /// The file's name.
    pub file: String,
    pub exported_at: String,
    pub exported_by: String,
    pub folders: usize,
    /// Folders not here yet. Created when a session imported into them needs them.
    pub new_folders: usize,
    pub sessions: Vec<PreviewItem>,
    pub known_hosts: Vec<PreviewItem>,
    /// Secrets whose values are in the file.
    pub secrets: Vec<PreviewItem>,
    pub secret_values: bool,
    /// BX-08 favourite commands.
    pub favourites: Vec<PreviewItem>,
    /// QL-16: the file's folders that set defaults, compared with the folder at the same place here.
    pub folder_defaults: Vec<PreviewItem>,
    pub warnings: Vec<String>,
}

/// What the user chose for one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemChoice {
    pub index: usize,
    pub action: ItemAction,
}

/// The import button: the preview and the user's choices. Items not listed get their default.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCommit {
    pub preview_id: Uuid,
    #[serde(default)]
    pub sessions: Vec<ItemChoice>,
    #[serde(default)]
    pub known_hosts: Vec<ItemChoice>,
    #[serde(default)]
    pub secrets: Vec<ItemChoice>,
    #[serde(default)]
    pub favourites: Vec<ItemChoice>,
    /// SS-01: sessions (by index) whose startup command comes along. The others come without it (a
    /// replaced session keeps the one it has here).
    #[serde(default)]
    pub keep_startup: Vec<usize>,
    /// SS-07: sessions (by index) whose port forwards come along. The others come without them (a
    /// replaced session keeps the ones it has here).
    #[serde(default)]
    pub keep_forwards: Vec<usize>,
    /// SS-04, AP-06: the master password, when the import would send passwords already in this vault
    /// to the file's hosts (the core asks with `reauth_required`).
    #[serde(default)]
    pub vault_password: Option<SecretString>,
    /// QL-16: what to do with each folder's defaults (by its index in `folder_defaults`).
    #[serde(default)]
    pub folder_defaults: Vec<ItemChoice>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub added: usize,
    pub replaced: usize,
    pub kept_both: usize,
    pub skipped: usize,
}

impl Counts {
    fn count(&mut self, action: ItemAction) {
        match action {
            ItemAction::Import => self.added += 1,
            ItemAction::Replace => self.replaced += 1,
            ItemAction::KeepBoth => self.kept_both += 1,
            ItemAction::Skip => self.skipped += 1,
        }
    }

    fn describe(&self) -> String {
        let both = match self.kept_both {
            0 => String::new(),
            n => format!(", {n} kept both"),
        };
        format!(
            "{} added, {} replaced{both}, {} skipped",
            self.added, self.replaced, self.skipped
        )
    }
}

/// An item that was not imported, or imported with something missing, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemProblem {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferReport {
    pub sessions: Counts,
    pub known_hosts: Counts,
    pub secrets: Counts,
    pub favourites: Counts,
    /// SS-07: port forwards saved with the imported sessions.
    pub forwards: usize,
    /// SS-01: startup commands in the file that were not ticked, so left out.
    pub startup_left_out: usize,
    /// SS-07: port forwards in the file that were not ticked, so left out.
    pub forwards_left_out: usize,
    /// CT-01: imported sessions marked as container hosts.
    pub container_hosts: usize,
    pub folders_added: usize,
    /// QL-16: folder defaults taken from the file.
    pub folder_defaults: Counts,
    /// Sessions imported without the password or key they used (not in the file, not here).
    pub without_credentials: usize,
    pub problems: Vec<ItemProblem>,
}

// ---- Comparing with this laptop -------------------------------------------------------------------

/// This laptop's library, read once per preview or commit.
struct Local {
    sessions: Vec<SessionRecord>,
    folders: Vec<SessionFolder>,
    folder_paths: HashMap<Uuid, Vec<String>>,
    known_hosts: Vec<KnownHost>,
    secrets: Vec<SecretMeta>,
    vault: VaultStatus,
    favourites: Vec<FavouriteRow>,
}

impl Local {
    async fn read(store: &Store, ctx: &Context, vault: &VaultService) -> Result<Self> {
        let folders = store.list_session_folders(ctx).await?;
        let folder_paths = paths(folders.iter().map(|f| (f.id, f.parent_id, f.name.as_str())));
        Ok(Self {
            sessions: store.list_sessions(ctx).await?,
            folders,
            folder_paths,
            known_hosts: store.list_known_hosts(ctx).await?,
            secrets: vault.list(ctx).await?,
            vault: vault.info().status,
            favourites: store.list_favourites(ctx).await?,
        })
    }

    fn secret(&self, label: &str, kind: SecretKind) -> Option<&SecretMeta> {
        self.secrets
            .iter()
            .find(|m| m.kind == kind && m.label.eq_ignore_ascii_case(label))
    }
}

/// Each folder's path from the top, by id. A broken parent chain (a cycle) stops where it repeats.
fn paths<'a>(folders: impl Iterator<Item = (Uuid, Option<Uuid>, &'a str)>) -> HashMap<Uuid, Vec<String>> {
    let folders: Vec<(Uuid, Option<Uuid>, &str)> = folders.collect();
    let by_id: HashMap<Uuid, (Option<Uuid>, &str)> = folders.iter().map(|(id, p, n)| (*id, (*p, *n))).collect();
    folders
        .iter()
        .map(|(id, _, _)| {
            let mut path = Vec::new();
            let mut seen = HashSet::new();
            let mut next = Some(*id);
            while let Some(current) = next.filter(|c| seen.insert(*c)) {
                let Some((parent, name)) = by_id.get(&current) else {
                    break;
                };
                path.push((*name).to_owned());
                next = *parent;
            }
            path.reverse();
            (*id, path)
        })
        .collect()
}

fn same_path(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn shown_path(path: &[String]) -> String {
    if path.is_empty() {
        "the top level".to_owned()
    } else {
        path.join(" / ")
    }
}

fn session_address(username: Option<&str>, host: &str, port: u16) -> String {
    let user = username.map(|u| format!("{u}@")).unwrap_or_default();
    format!("{user}{}", address(host, port))
}

/// One row's comparison: its status, the item here it matches, and what the user may do.
struct RowPlan<T> {
    index: usize,
    status: ItemStatus,
    local: Option<T>,
    conflict: Option<String>,
    choices: Vec<ItemAction>,
    default_action: ItemAction,
}

impl<T> RowPlan<T> {
    fn new(index: usize) -> Self {
        Self {
            index,
            status: ItemStatus::New,
            local: None,
            conflict: None,
            choices: vec![ItemAction::Import, ItemAction::Skip],
            default_action: ItemAction::Import,
        }
    }

    fn same(index: usize, local: T, text: String) -> Self {
        Self {
            index,
            status: ItemStatus::Same,
            local: Some(local),
            conflict: Some(text),
            choices: vec![ItemAction::Skip],
            default_action: ItemAction::Skip,
        }
    }

    fn conflict(index: usize, local: T, text: String, choices: Vec<ItemAction>) -> Self {
        Self {
            index,
            status: ItemStatus::Conflict,
            local: Some(local),
            conflict: Some(text),
            choices,
            default_action: ItemAction::Skip,
        }
    }

    /// The user's choice for this row, or its default; an action the row does not offer is refused.
    fn action(&self, chosen: &HashMap<usize, ItemAction>, name: &str) -> Result<ItemAction> {
        let action = chosen.get(&self.index).copied().unwrap_or(self.default_action);
        if self.choices.contains(&action) {
            Ok(action)
        } else {
            Err(CoreError::InvalidInput(format!(
                "'{name}' can't be {} (the library changed since the file was opened?). Open the file again.",
                action.label()
            )))
        }
    }
}

const CONFLICT_CHOICES: [ItemAction; 3] = [ItemAction::Skip, ItemAction::Replace, ItemAction::KeepBoth];

fn plan_sessions(payload: &Payload, local: &Local) -> Vec<RowPlan<Uuid>> {
    let file_paths = paths(payload.folders.iter().map(|f| (f.id, f.parent_id, f.name.as_str())));
    let tree = file_folders(payload);
    let no_path = Vec::new();
    payload
        .sessions
        .iter()
        .enumerate()
        .map(|(index, s)| {
            let path = s.folder_id.and_then(|f| file_paths.get(&f)).unwrap_or(&no_path);
            // QL-16: what each sets itself (both take the rest from their folders).
            let same = |l: &SessionRecord| {
                let mut a: Vec<String> = s.tags.iter().map(|t| t.to_lowercase()).collect();
                let mut b: Vec<String> = l.own.tags.iter().map(|t| t.to_lowercase()).collect();
                a.sort();
                b.sort();
                let local_path = l.folder_id.and_then(|f| local.folder_paths.get(&f)).unwrap_or(&no_path);
                s.name == l.name
                    && s.host.eq_ignore_ascii_case(&l.host)
                    && s.port == l.port
                    && s.username == l.own.username
                    && s.auth.method() == l.own.auth.method()
                    && s.jump_direct == l.own.jump_direct
                    && s.startup_command == l.startup_command
                    && s.environment == l.own.environment
                    && s.color == l.color
                    && a == b
                    && same_path(path, local_path)
            };
            if let Some(l) = local.sessions.iter().find(|l| l.id == s.id) {
                return if same(l) {
                    RowPlan::same(index, l.id, format!("Already here as '{}', unchanged.", l.name))
                } else {
                    RowPlan::conflict(
                        index,
                        l.id,
                        format!(
                            "An earlier copy of this session is here as '{}', with other settings.",
                            l.name
                        ),
                        CONFLICT_CHOICES.to_vec(),
                    )
                };
            }
            // QL-16: the user that applies on each side, its folders' included.
            let user = tree.resolve(Some(s.id), &s.own(), s.folder_id).username;
            let same_address =
                |l: &&SessionRecord| l.host.eq_ignore_ascii_case(&s.host) && l.port == s.port && l.username == user;
            if let Some(l) = local.sessions.iter().find(same_address) {
                return if same(l) {
                    RowPlan::same(index, l.id, format!("Already here as '{}'.", l.name))
                } else {
                    RowPlan::conflict(
                        index,
                        l.id,
                        format!("'{}' here connects to the same user, host and port.", l.name),
                        CONFLICT_CHOICES.to_vec(),
                    )
                };
            }
            if let Some(l) = local.sessions.iter().find(|l| l.name.eq_ignore_ascii_case(&s.name)) {
                let there = session_address(l.username.as_deref(), &l.host, l.port);
                return RowPlan::conflict(
                    index,
                    l.id,
                    format!("A session named '{}' is here; it connects to {there}.", l.name),
                    CONFLICT_CHOICES.to_vec(),
                );
            }
            RowPlan::new(index)
        })
        .collect()
}

/// QL-16: a folder's defaults in words, with vault items by label and the jump host by name, so the file's and this
/// laptop's compare without their ids.
fn describe_defaults(
    d: &FolderDefaults,
    secret_label: impl Fn(SecretId) -> Option<String>,
    session_name: impl Fn(Uuid) -> Option<String>,
) -> String {
    let mut parts = Vec::new();
    if let Some(user) = &d.username {
        parts.push(format!("user {user}"));
    }
    let label = |id: Option<SecretId>| {
        id.map(|id| secret_label(id).map_or_else(|| "a vault item not here".to_owned(), |l| format!("'{l}'")))
    };
    match &d.auth {
        Some(SessionAuth::Password { password_id }) => parts.push(match label(*password_id) {
            Some(l) => format!("password {l}"),
            None => "password asked when connecting".to_owned(),
        }),
        Some(SessionAuth::Key { key_id, .. }) => parts.push(match label(*key_id) {
            Some(l) => format!("key {l}"),
            None => "key (none chosen)".to_owned(),
        }),
        Some(SessionAuth::Agent) => parts.push("SSH agent".to_owned()),
        Some(SessionAuth::Folder) | None => {}
    }
    if d.jump_direct {
        parts.push("no jump host".to_owned());
    } else if let Some(jump) = d.jump_session_id {
        parts.push(format!(
            "via '{}'",
            session_name(jump).unwrap_or_else(|| "a session not in the file".to_owned())
        ));
    }
    if let Some(env) = d.environment {
        parts.push(format!("label {}", env.as_str()));
    }
    if !d.tags.is_empty() {
        parts.push(format!("tags {}", d.tags.join(", ")));
    }
    if parts.is_empty() {
        "no defaults".to_owned()
    } else {
        parts.join(", ")
    }
}

/// QL-16: the file's folders that set defaults, against the folder at the same place here.
fn plan_folder_defaults(payload: &Payload, local: &Local) -> Vec<RowPlan<Uuid>> {
    let file_paths = paths(payload.folders.iter().map(|f| (f.id, f.parent_id, f.name.as_str())));
    payload
        .folders
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.defaults.is_empty())
        .map(|(index, f)| {
            let path = file_paths.get(&f.id).cloned().unwrap_or_default();
            let here = local
                .folder_paths
                .iter()
                .find(|(_, p)| same_path(p, &path))
                .and_then(|(id, _)| local.folders.iter().find(|l| l.id == *id));
            let Some(here) = here else {
                return RowPlan::new(index);
            };
            let theirs = file_defaults_text(&f.defaults, payload);
            let ours = local_defaults_text(&here.defaults, local);
            if theirs == ours {
                RowPlan::same(index, here.id, "The folder here has the same defaults.".to_owned())
            } else {
                RowPlan::conflict(
                    index,
                    here.id,
                    format!("The folder here has other defaults: {ours}."),
                    vec![ItemAction::Skip, ItemAction::Replace],
                )
            }
        })
        .collect()
}

fn file_defaults_text(d: &FolderDefaults, payload: &Payload) -> String {
    describe_defaults(
        d,
        |id| payload.secrets.iter().find(|e| e.id == id).map(|e| e.label.clone()),
        |id| payload.sessions.iter().find(|e| e.id == id).map(|e| e.name.clone()),
    )
}

fn local_defaults_text(d: &FolderDefaults, local: &Local) -> String {
    describe_defaults(
        d,
        |id| local.secrets.iter().find(|m| m.id == id).map(|m| m.label.clone()),
        |id| local.sessions.iter().find(|s| s.id == id).map(|s| s.name.clone()),
    )
}

/// QL-16: the folder here a file folder's sessions land in: the one at the same place, else the nearest one above
/// that is here (new folders are made under it). `None`: the top level.
fn landing_folder(path: &[String], local: &Local) -> Option<Uuid> {
    (1..=path.len()).rev().find_map(|len| {
        local
            .folder_paths
            .iter()
            .find(|(_, p)| same_path(p, &path[..len]))
            .map(|(id, _)| *id)
    })
}

/// A login with the file's vault items mapped to the ones here; `true` when it named one that is not here.
fn map_auth(auth: &SessionAuth, secrets: &HashMap<SecretId, SecretId>) -> (SessionAuth, bool) {
    let map_secret = |id: Option<SecretId>| id.and_then(|id| secrets.get(&id).copied());
    match *auth {
        SessionAuth::Password { password_id } => {
            let mapped = map_secret(password_id);
            (
                SessionAuth::Password { password_id: mapped },
                password_id.is_some() && mapped.is_none(),
            )
        }
        SessionAuth::Key { key_id, passphrase_id } => {
            let key = map_secret(key_id);
            let passphrase = key.and(map_secret(passphrase_id));
            (
                SessionAuth::Key {
                    key_id: key,
                    passphrase_id: passphrase,
                },
                key_id.is_some() && key.is_none(),
            )
        }
        SessionAuth::Agent => (SessionAuth::Agent, false),
        SessionAuth::Folder => (SessionAuth::Folder, false),
    }
}

fn plan_known_hosts(payload: &Payload, local: &Local) -> Vec<RowPlan<Uuid>> {
    payload
        .known_hosts
        .iter()
        .enumerate()
        .map(|(index, k)| {
            let here = local
                .known_hosts
                .iter()
                .find(|l| l.host.eq_ignore_ascii_case(&k.host) && l.port == k.port && l.key_type == k.key_type);
            // SS-05: a new key type for a host that has a trusted key here is what a man in the middle
            // would present, so it is a conflict, skipped unless the user picks it.
            let other_types: Vec<&KnownHost> = local
                .known_hosts
                .iter()
                .filter(|l| l.host.eq_ignore_ascii_case(&k.host) && l.port == k.port)
                .collect();
            match here {
                None => match other_types.first() {
                    None => RowPlan::new(index),
                    Some(first) => RowPlan::conflict(
                        index,
                        first.id,
                        format!(
                            "This is a {} key, and this host has another kind trusted here ({}). A host that presents a new kind of key may be someone intercepting the connection: import it only if you know the host's keys changed.",
                            k.key_type,
                            other_types
                                .iter()
                                .map(|l| format!("{} {}", l.key_type, l.fingerprint))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        vec![ItemAction::Skip, ItemAction::Import],
                    ),
                },
                Some(l) if l.fingerprint == k.fingerprint => {
                    RowPlan::same(index, l.id, "Already trusted here.".to_owned())
                }
                Some(l) => RowPlan::conflict(
                    index,
                    l.id,
                    format!(
                        "Another {} key is trusted here for this host ({}). Replace it only if you know the host's key changed.",
                        l.key_type, l.fingerprint
                    ),
                    vec![ItemAction::Skip, ItemAction::Replace],
                ),
            }
        })
        .collect()
}

/// BX-08: a favourite matches the one here with the same folder and name (any letter case).
fn plan_favourites(payload: &Payload, local: &Local) -> Vec<RowPlan<Uuid>> {
    payload
        .favourites
        .iter()
        .enumerate()
        .map(|(index, f)| {
            let here = local
                .favourites
                .iter()
                .find(|l| l.folder.eq_ignore_ascii_case(f.folder.trim()) && l.name.eq_ignore_ascii_case(f.name.trim()));
            match here {
                None => RowPlan::new(index),
                Some(l) if l.command == f.command && l.description == f.description => {
                    RowPlan::same(index, l.id, "Already a favourite here.".to_owned())
                }
                Some(l) => {
                    let what = if l.command == f.command {
                        "another description"
                    } else {
                        "another command"
                    };
                    RowPlan::conflict(
                        index,
                        l.id,
                        format!(
                            "A favourite with this name in {} has {what}.",
                            favourite_place(&l.folder)
                        ),
                        CONFLICT_CHOICES.to_vec(),
                    )
                }
            }
        })
        .collect()
}

fn favourite_place(folder: &str) -> String {
    if folder.is_empty() {
        "the top level".to_owned()
    } else {
        format!("'{folder}'")
    }
}

/// The command's first line, cut short, for the preview.
fn command_preview(command: &str) -> String {
    let first = command.lines().next().unwrap_or("");
    let mut shown: String = first.chars().take(80).collect();
    if shown.len() < first.len() || command.lines().count() > 1 {
        shown.push('…');
    }
    shown
}

/// Secrets whose values are in the file. With the vault unlocked, a value under a label that is here
/// already is compared with the one here; locked, it can't be.
async fn plan_secrets(
    payload: &Payload,
    local: &Local,
    vault: &VaultService,
    ctx: &Context,
) -> Result<Vec<RowPlan<SecretId>>> {
    let unlocked = local.vault == VaultStatus::Unlocked;
    let mut rows = Vec::new();
    for (index, e) in payload.secrets.iter().enumerate() {
        let Some(value) = &e.value else { continue };
        let here = local.secrets.iter().find(|m| m.label.eq_ignore_ascii_case(&e.label));
        let mut row = match here {
            None => RowPlan::new(index),
            Some(m) if m.kind != e.kind => RowPlan::conflict(
                index,
                m.id,
                format!("'{}' here is a {}, not a {}.", m.label, m.kind.label(), e.kind.label()),
                vec![ItemAction::Skip, ItemAction::KeepBoth],
            ),
            Some(m) if unlocked => {
                if vault.vault().get(ctx, m.id).await?.expose() == value.expose() {
                    RowPlan::same(index, m.id, "Already in the vault.".to_owned())
                } else {
                    RowPlan::conflict(
                        index,
                        m.id,
                        format!("'{}' is in the vault with another value.", m.label),
                        CONFLICT_CHOICES.to_vec(),
                    )
                }
            }
            Some(m) => RowPlan::conflict(
                index,
                m.id,
                format!(
                    "A {} labelled '{}' is in the vault. Unlock the vault to compare them.",
                    m.kind.label(),
                    m.label
                ),
                CONFLICT_CHOICES.to_vec(),
            ),
        };
        if !unlocked && row.status == ItemStatus::New {
            // Nothing can go into a locked vault; the preview says so.
            row.default_action = ItemAction::Skip;
        }
        rows.push(row);
    }
    Ok(rows)
}

/// What a session would log in with after a default import.
fn credential_note(entry: &SessionEntry, payload: &Payload, local: &Local) -> Option<String> {
    let (id, kind) = match entry.auth {
        SessionAuth::Password { password_id: Some(id) } => (id, SecretKind::Password),
        SessionAuth::Key { key_id: Some(id), .. } => (id, SecretKind::PrivateKey),
        _ => return None,
    };
    let what = kind.label();
    let Some(secret) = payload.secrets.iter().find(|s| s.id == id) else {
        return Some(format!("Its saved {what} is not in the file."));
    };
    let label = &secret.label;
    Some(if local.secret(label, kind).is_some() {
        format!("Logs in with the {what} '{label}' in this vault.")
    } else if secret.value.is_some() {
        format!("Logs in with the {what} '{label}' from the file.")
    } else if kind == SecretKind::Password {
        format!("Asks for its password when connecting: '{label}' is not in the file or this vault.")
    } else {
        format!("Needs a key: '{label}' is not in the file or this vault. Choose one after importing.")
    })
}

/// FD-07: as long and as hard to guess as a new vault password (SS-04): the file can be attacked offline
/// by anyone who gets a copy.
fn check_passphrase(passphrase: &SecretString) -> Result<()> {
    check_new_password(passphrase, "passphrase")
}

/// FD-07: an export is never written into a Git working tree, where it could be committed by mistake
/// ([`crate::save_guard`], which every other save path uses too).
pub fn refuse_repository(path: &Path) -> Result<()> {
    crate::save_guard::refuse_repository(path, crate::save_guard::Saved::Transfer)
}

/// Writes next to the target first, then renames, so a failed export never leaves half a file.
async fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| CoreError::InvalidInput("Choose a file name for the export.".into()))?;
    let temp = path.with_file_name(format!("{}.part", name.to_string_lossy()));
    tokio::fs::write(&temp, bytes).await?;
    if let Err(err) = tokio::fs::rename(&temp, path).await {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(err.into());
    }
    Ok(())
}

/// Runs slow work (Argon2id) off the async threads.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| CoreError::Vault(format!("the export task stopped: {err}")))?
}

/// `name (2)`, `name (3)`, ...: the first not in `taken` (lower case), at most `max` characters.
fn free_name(name: &str, taken: &HashSet<String>, max: usize) -> String {
    for n in 2..10_000 {
        let suffix = format!(" ({n})");
        let keep = max.saturating_sub(suffix.chars().count());
        let candidate = format!("{}{suffix}", name.chars().take(keep).collect::<String>());
        if !taken.contains(&candidate.to_lowercase()) {
            return candidate;
        }
    }
    format!("{name} ({})", Uuid::new_v4().simple())
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// The library as a commit found it, and what the user chose for each item.
struct Decided {
    local: Local,
    secret_rows: Vec<RowPlan<SecretId>>,
    secret_actions: Vec<ItemAction>,
    session_rows: Vec<RowPlan<Uuid>>,
    session_actions: Vec<ItemAction>,
    host_rows: Vec<RowPlan<Uuid>>,
    host_actions: Vec<ItemAction>,
    favourite_rows: Vec<RowPlan<Uuid>>,
    favourite_actions: Vec<ItemAction>,
    /// QL-16.
    folder_rows: Vec<RowPlan<Uuid>>,
    folder_actions: Vec<ItemAction>,
}

/// SS-04: closes an opened file, which may hold secret values, when the vault locks: its secrets are
/// zeroized, and the import starts again from the file once the vault is unlocked.
pub struct Closer {
    chosen: Arc<Mutex<Option<PathBuf>>>,
    opened: Arc<Mutex<Option<Opened>>>,
}

impl Closer {
    /// True when a file was open.
    pub fn close(&self) -> bool {
        locks::lock(&self.chosen).take();
        locks::lock(&self.opened).take().is_some()
    }
}

/// An opened export, kept until it is imported or closed. Its secrets are zeroized when it is dropped.
struct Opened {
    id: Uuid,
    path: PathBuf,
    payload: Payload,
}

pub struct Transfer {
    store: Store,
    /// SS-01: the bus's engine, to rate startup commands in the preview.
    policy: Option<Arc<RwLock<PolicyEngine>>>,
    kdf: Mutex<KdfParams>,
    /// The file the user picked to import, until its passphrase opens it.
    chosen: Arc<Mutex<Option<PathBuf>>>,
    opened: Arc<Mutex<Option<Opened>>>,
    /// SS-04, AP-06: imported sessions that use passwords already here ask for the master password.
    bindings: Option<SecretBindings>,
}

impl Transfer {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            policy: None,
            kdf: Mutex::new(file::KDF),
            chosen: Arc::default(),
            opened: Arc::default(),
            bindings: None,
        }
    }

    pub fn with_bindings(mut self, bindings: SecretBindings) -> Self {
        self.bindings = Some(bindings);
        self
    }

    /// SS-04: what closes an opened file when the vault locks.
    pub fn closer(&self) -> Closer {
        Closer {
            chosen: Arc::clone(&self.chosen),
            opened: Arc::clone(&self.opened),
        }
    }

    /// The command bus's policy engine, so the preview rates startup commands with the current rules.
    pub fn with_policy(mut self, policy: Arc<RwLock<PolicyEngine>>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Remembers the file the user picked in the shell's dialog, so the passphrase can be typed (and
    /// retyped) without the path ever coming from the UI. Returns its name.
    pub fn choose(&self, path: PathBuf) -> String {
        let name = path
            .file_name()
            .map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned());
        *locks::lock(&self.chosen) = Some(path);
        name
    }

    /// [`Transfer::open`] on the file picked last.
    pub async fn open_chosen(
        &self,
        ctx: &Context,
        passphrase: SecretString,
        vault: &VaultService,
    ) -> Result<TransferPreview> {
        let path = locks::lock(&self.chosen)
            .clone()
            .ok_or_else(|| CoreError::InvalidInput("Choose the export file first.".into()))?;
        self.open(ctx, &path, passphrase, vault).await
    }

    /// Fast key derivation for exports made in tests. Never in the app.
    #[cfg(any(test, feature = "fakes"))]
    pub fn use_insecure_fast_kdf(&self) {
        *locks::lock(&self.kdf) = KdfParams::INSECURE_FAST;
    }

    /// FD-07: writes the library to `path`, encrypted with the request's passphrase. `exported_by`
    /// names the app and version in the file. Audited with the counts and the path.
    pub async fn export(
        &self,
        ctx: &Context,
        path: &Path,
        request: ExportRequest,
        vault: &VaultService,
        exported_by: &str,
    ) -> Result<ExportReport> {
        let ExportRequest {
            passphrase,
            include_known_hosts,
            include_secrets,
            vault_password,
        } = request;
        check_passphrase(&passphrase)?;
        refuse_repository(path)?;
        let status = vault.info().status;
        // Not the vault password: whoever gets the file and learns its passphrase would then also know the
        // password that unlocks this vault and confirms Critical actions (AP-06). One Argon2id run.
        if status != VaultStatus::NotSetUp && vault.vault().verify_password(&passphrase).await? {
            return Err(CoreError::InvalidInput(
                "Choose a passphrase that is not your vault password: anyone who learns it from the file would then know your vault password too.".into(),
            ));
        }
        if include_secrets {
            match status {
                VaultStatus::Unlocked => {}
                VaultStatus::Locked => return Err(CoreError::VaultLocked),
                VaultStatus::NotSetUp => {
                    return Err(CoreError::InvalidInput(
                        "This computer has no vault, so there are no secrets to export.".into(),
                    ))
                }
            }
            let password = vault_password
                .filter(|p| !p.is_empty())
                .ok_or_else(|| CoreError::InvalidInput("Enter the vault password to export secrets.".into()))?;
            if !vault.vault().verify_password(&password).await? {
                self.audit(
                    ctx,
                    "vault_auth_failed",
                    "Failed to export the vault's secrets",
                    "wrong vault password",
                )
                .await?;
                return Err(CoreError::WrongVaultPassword);
            }
        }

        let folders = self.store.list_session_folders(ctx).await?;
        let sessions = self.store.list_sessions(ctx).await?;
        let known_hosts = if include_known_hosts {
            self.store.list_known_hosts(ctx).await?
        } else {
            Vec::new()
        };
        let keys = self.store.ssh_key_rows(ctx).await?;
        let favourites = self.store.list_favourites(ctx).await?;
        let update_token = self.update_token(ctx).await?;
        let mut secrets = Vec::new();
        for meta in vault.list(ctx).await? {
            if Some(meta.id) == update_token {
                continue;
            }
            let value = match include_secrets {
                true => Some(vault.vault().get(ctx, meta.id).await?),
                false => None,
            };
            let key = keys.get(&meta.id);
            secrets.push(SecretEntry {
                id: meta.id,
                kind: meta.kind,
                label: meta.label,
                value,
                public_key: key.map(|k| k.public.clone()),
                generated: key.is_some_and(|k| k.generated),
            });
        }
        let mut forwards = self.store.all_forwards(ctx).await?;
        let mut container_marks = self.store.container_marks_by_session(ctx).await?;
        let mut entries = Vec::with_capacity(sessions.len());
        for s in sessions {
            let vm = match &s.vm_id {
                Some(id) => self.store.vm_by_id(ctx, id).await?.map(|vm| VmHint {
                    vmx_path: vm.vmx_path,
                    name: vm.display_name,
                    auto: s.vm_link == Some(VmLink::Auto),
                }),
                None => None,
            };
            entries.push(SessionEntry {
                id: s.id,
                folder_id: s.folder_id,
                name: s.name,
                host: s.host,
                port: s.port,
                // QL-16: what it sets itself; the rest comes from its folders again on the other laptop.
                username: s.own.username,
                auth: s.own.auth,
                jump_session_id: s.own.jump_session_id,
                jump_direct: s.own.jump_direct,
                startup_command: s.startup_command,
                environment: s.own.environment,
                color: s.color,
                tags: s.own.tags,
                vm,
                imported_from: s.imported_from,
                forwards: forwards
                    .remove(&s.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|f| ForwardEntry {
                        label: f.label,
                        kind: f.spec.kind,
                        bind_address: f.spec.bind_address,
                        bind_port: f.spec.bind_port,
                        dest_host: f.spec.dest_host,
                        dest_port: f.spec.dest_port,
                        auto_start: f.auto_start,
                    })
                    .collect(),
                containers: container_marks
                    .remove(&s.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|m| ContainerEntry {
                        engine: m.engine,
                        sudo: m.sudo,
                    })
                    .collect(),
            });
        }
        let payload = Payload {
            exported_at: now_rfc3339(),
            exported_by: exported_by.to_owned(),
            folders: folders
                .iter()
                .map(|f| FolderEntry {
                    id: f.id,
                    parent_id: f.parent_id,
                    name: f.name.clone(),
                    defaults: f.defaults.clone(),
                })
                .collect(),
            sessions: entries,
            known_hosts: known_hosts
                .iter()
                .map(|k| KnownHostEntry {
                    host: k.host.clone(),
                    port: k.port,
                    key_type: k.key_type.clone(),
                    fingerprint: k.fingerprint.clone(),
                    first_seen_at: k.first_seen_at.clone(),
                })
                .collect(),
            secrets,
            favourites: favourites
                .into_iter()
                .map(|f| FavouriteEntry {
                    folder: f.folder,
                    name: f.name,
                    command: f.command,
                    description: f.description,
                })
                .collect(),
        };
        let report = ExportReport {
            path: path.display().to_string(),
            folders: payload.folders.len(),
            sessions: payload.sessions.len(),
            known_hosts: payload.known_hosts.len(),
            secrets: payload.secrets.len(),
            secret_values: include_secrets,
            favourites: payload.favourites.len(),
            forwards: payload.sessions.iter().map(|s| s.forwards.len()).sum(),
            container_hosts: payload.sessions.iter().filter(|s| !s.containers.is_empty()).count(),
            folder_defaults: payload.folders.iter().filter(|f| !f.defaults.is_empty()).count(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&payload)?);
        drop(payload);
        let kdf = *locks::lock(&self.kdf);
        let sealed = blocking(move || file::seal(&plain, &passphrase, &kdf)).await?;
        write_atomically(path, &sealed).await?;

        let secrets = if include_secrets {
            format!("{} with their values", plural(report.secrets, "vault secret"))
        } else {
            format!("{} (labels only, no values)", plural(report.secrets, "vault secret"))
        };
        let detail = format!(
            "{}, {}, {}, {secrets}, {}, {}, {}, to {}",
            plural(report.sessions, "session"),
            plural(report.folders, "folder"),
            plural(report.known_hosts, "known host key"),
            plural(report.favourites, "favourite command"),
            plural(report.forwards, "port forward"),
            plural(report.container_hosts, "container host"),
            report.path
        );
        self.audit(
            ctx,
            "data_exported",
            "Exported the session library to an encrypted file",
            &detail,
        )
        .await?;
        Ok(report)
    }

    /// FD-07: opens an export with its passphrase and compares it with this laptop's library. The
    /// opened file is kept for [`Transfer::commit`] (one at a time) until it is imported or closed.
    pub async fn open(
        &self,
        ctx: &Context,
        path: &Path,
        passphrase: SecretString,
        vault: &VaultService,
    ) -> Result<TransferPreview> {
        if passphrase.is_empty() {
            return Err(CoreError::InvalidInput("Enter the file's passphrase.".into()));
        }
        let size = tokio::fs::metadata(path).await?.len();
        if size > MAX_FILE_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "That file is larger than {} MB, so it is not a Remotely export.",
                MAX_FILE_BYTES / (1024 * 1024)
            )));
        }
        let bytes = tokio::fs::read(path).await?;
        let plain = blocking(move || file::open(&bytes, &passphrase)).await?;
        let payload: Payload = serde_json::from_slice(&plain).map_err(|_| {
            CoreError::InvalidInput(
                "The file opened, but what it holds is damaged or from an incompatible version of Remotely.".into(),
            )
        })?;
        drop(plain);
        let preview = self.preview(ctx, Uuid::new_v4(), path, &payload, vault).await?;
        *locks::lock(&self.opened) = Some(Opened {
            id: preview.id,
            path: path.to_owned(),
            payload,
        });
        Ok(preview)
    }

    /// The opened file compared with the library again, e.g. after the vault was unlocked, without
    /// asking for its passphrase again.
    pub async fn refresh(&self, ctx: &Context, preview_id: Uuid, vault: &VaultService) -> Result<TransferPreview> {
        let opened = {
            let mut slot = locks::lock(&self.opened);
            match slot.take() {
                Some(o) if o.id == preview_id => o,
                other => {
                    *slot = other;
                    return Err(CoreError::InvalidInput(
                        "That file is no longer open. Open it again.".into(),
                    ));
                }
            }
        };
        let preview = self
            .preview(ctx, preview_id, &opened.path, &opened.payload, vault)
            .await;
        let mut slot = locks::lock(&self.opened);
        if slot.is_none() {
            *slot = Some(opened);
        }
        preview
    }

    /// Forgets the opened file (the dialog was closed). False when it was not open.
    /// SS-04, AP-06: whether the import needs the master password, and if so that it came and is right.
    /// It does when a session it saves would send a password already in this vault (found by label: the
    /// file has no value for it, or its secret is skipped), or when a replaced session that sends vault
    /// passwords would move to another host or port. True when it was asked and given.
    async fn confirm_secrets_here(
        &self,
        ctx: &Context,
        payload: &Payload,
        decided: &Decided,
        vault_password: Option<&SecretString>,
        file: &str,
    ) -> Result<bool> {
        let Some(bindings) = &self.bindings else {
            return Ok(false);
        };
        let local = &decided.local;
        let mut here_ids: HashMap<SecretId, SecretId> = HashMap::new();
        for e in payload.secrets.iter().filter(|e| e.value.is_none()) {
            if let Some(here) = local.secret(&e.label, e.kind) {
                here_ids.insert(e.id, here.id);
            }
        }
        for (row, action) in decided.secret_rows.iter().zip(&decided.secret_actions) {
            let e = &payload.secrets[row.index];
            if e.value.is_some() && *action == ItemAction::Skip {
                if let Some(here) = local.secret(&e.label, e.kind) {
                    here_ids.insert(e.id, here.id);
                }
            }
        }
        // QL-16: the file's folders and this laptop's, to see which login a session gets from its folders.
        let tree = file_folders(payload);
        let file_paths = paths(payload.folders.iter().map(|f| (f.id, f.parent_id, f.name.as_str())));
        let local_tree = Folders::new(local.folders.clone());
        let mut sessions = Vec::new();
        for (index, entry) in payload.sessions.iter().enumerate() {
            let action = decided.session_actions[index];
            if action == ItemAction::Skip {
                continue;
            }
            let mut sends: Vec<SecretId> = Vec::new();
            if let SessionAuth::Password { password_id: Some(id) } = entry.auth {
                sends.extend(here_ids.get(&id));
            }
            if entry.auth == SessionAuth::Folder {
                let in_file = tree.resolve(Some(entry.id), &entry.own(), entry.folder_id);
                if in_file.inherited.auth.is_some() {
                    // The file's folders set its login: a password of theirs that is here already.
                    if let SessionAuth::Password { password_id: Some(id) } = in_file.auth {
                        sends.extend(here_ids.get(&id));
                    }
                } else {
                    // Otherwise the folders here where it lands decide: their password goes to the file's host.
                    let path = entry
                        .folder_id
                        .and_then(|f| file_paths.get(&f))
                        .cloned()
                        .unwrap_or_default();
                    let here = local_tree.resolve(None, &OwnValues::from_folders(), landing_folder(&path, local));
                    sends.extend(here.auth.sent_secret());
                }
            }
            for c in &entry.containers {
                if let SudoMode::Password { password_id: Some(id) } = c.sudo {
                    sends.extend(here_ids.get(&id));
                }
            }
            let here = decided.session_rows[index]
                .local
                .and_then(|id| local.sessions.iter().find(|s| s.id == id));
            if let (ItemAction::Replace, Some(here)) = (action, here) {
                let moved = !Destination::new(&entry.host, entry.port, None)
                    .same(&Destination::new(&here.host, here.port, None));
                if moved {
                    sends.extend(bindings.sent_by(ctx, here.id).await?);
                }
            }
            let mut reaches = false;
            for secret in sends {
                if bindings.reaches_hosts(ctx, secret).await? {
                    reaches = true;
                    break;
                }
            }
            if reaches {
                sessions.push(entry.name.clone());
            }
        }
        // QL-16: folder defaults that give their sessions a password already here, or that change the login or
        // jump host of a folder here whose sessions send vault passwords.
        let places = bindings.places_in(ctx, &local_tree).await?;
        for (row, action) in decided.folder_rows.iter().zip(&decided.folder_actions) {
            if !matches!(action, ItemAction::Import | ItemAction::Replace) {
                continue;
            }
            let f = &payload.folders[row.index];
            let mut reaches = false;
            if let Some(SessionAuth::Password { password_id: Some(id) }) = f.defaults.auth {
                if let Some(here) = here_ids.get(&id) {
                    reaches = bindings.reaches_hosts(ctx, *here).await?;
                }
            }
            // Taking the file's defaults for a folder here may change the jump host or login of its sessions.
            if let (ItemAction::Replace, Some(here), false) = (action, row.local, reaches) {
                for s in local
                    .sessions
                    .iter()
                    .filter(|s| local_tree.is_within(s.folder_id, here))
                {
                    for secret in places.sent_by(s.id) {
                        if bindings.reaches_hosts(ctx, secret).await? {
                            reaches = true;
                        }
                    }
                }
            }
            if reaches {
                sessions.push(format!("folder {}", f.name));
            }
        }
        if sessions.is_empty() {
            return Ok(false);
        }
        let shown: Vec<String> = sessions.iter().take(3).map(|n| format!("'{n}'")).collect();
        let more = sessions.len().saturating_sub(shown.len());
        let names = if more > 0 {
            format!("{} and {more} more", shown.join(", "))
        } else {
            shown.join(", ")
        };
        let reason = format!(
            "{} from this file would send passwords already in this vault to the file's hosts ({names})",
            plural(sessions.len(), "session")
        );
        bindings
            .confirm(ctx, vault_password, &format!("Failed to import from {file}"), &reason)
            .await?;
        Ok(true)
    }

    pub fn close(&self, preview_id: Uuid) -> bool {
        let mut opened = locks::lock(&self.opened);
        if opened.as_ref().is_some_and(|o| o.id == preview_id) {
            *opened = None;
            true
        } else {
            false
        }
    }

    async fn preview(
        &self,
        ctx: &Context,
        id: Uuid,
        path: &Path,
        payload: &Payload,
        vault: &VaultService,
    ) -> Result<TransferPreview> {
        let local = Local::read(&self.store, ctx, vault).await?;
        let file_paths = paths(payload.folders.iter().map(|f| (f.id, f.parent_id, f.name.as_str())));
        let local_paths: Vec<&Vec<String>> = local.folder_paths.values().collect();
        let new_folders = file_paths
            .values()
            .filter(|p| !local_paths.iter().any(|l| same_path(l, p)))
            .count();
        let no_path = Vec::new();
        // QL-16: what applies to each of the file's sessions, its folders' values included.
        let tree = file_folders(payload);

        let sessions = plan_sessions(payload, &local)
            .into_iter()
            .map(|row| {
                let s = &payload.sessions[row.index];
                let path = s.folder_id.and_then(|f| file_paths.get(&f)).unwrap_or(&no_path);
                let effective = tree.resolve(Some(s.id), &s.own(), s.folder_id);
                let mut detail = format!(
                    "{}, in {}",
                    session_address(effective.username.as_deref(), &s.host, s.port),
                    shown_path(path)
                );
                if effective.environment != Environment::None {
                    detail.push_str(&format!(", {}", effective.environment.as_str()));
                }
                let mut notes: Vec<String> = credential_note(s, payload, &local).into_iter().collect();
                if effective.jump_session_id.is_some() {
                    notes.push("Connects through a jump host.".into());
                }
                let inherited = effective.inherited.describe();
                if !inherited.is_empty() {
                    notes.push(format!("From its folders: {inherited}."));
                }
                let mut shown = item(row, s.name.clone(), detail, notes);
                shown.startup_command.clone_from(&s.startup_command);
                shown.startup_rating = match (&self.policy, &s.startup_command) {
                    (Some(policy), Some(command)) => {
                        Some(rate_startup(&locks::read(policy), command, effective.environment))
                    }
                    _ => None,
                };
                shown.forwards = s.forwards.iter().map(ForwardEntry::describe).collect();
                shown
            })
            .collect();
        let known_hosts = plan_known_hosts(payload, &local)
            .into_iter()
            .map(|row| {
                let k = &payload.known_hosts[row.index];
                item(
                    row,
                    address(&k.host, k.port),
                    format!("{} {}", k.key_type, k.fingerprint),
                    Vec::new(),
                )
            })
            .collect();
        let secrets: Vec<PreviewItem> = plan_secrets(payload, &local, vault, ctx)
            .await?
            .into_iter()
            .map(|row| {
                let e = &payload.secrets[row.index];
                let used = payload
                    .sessions
                    .iter()
                    .map(|s| tree.resolve(Some(s.id), &s.own(), s.folder_id).auth)
                    .filter(|auth| auth.credential_id() == Some(e.id) || auth.passphrase_id() == Some(e.id))
                    .count();
                let detail = match used {
                    0 => e.kind.label().to_owned(),
                    n => format!("{}, used by {}", e.kind.label(), plural(n, "session")),
                };
                item(row, e.label.clone(), detail, Vec::new())
            })
            .collect();
        let favourites = plan_favourites(payload, &local)
            .into_iter()
            .map(|row| {
                let f = &payload.favourites[row.index];
                let detail = format!("in {}: {}", favourite_place(&f.folder), command_preview(&f.command));
                item(row, f.name.clone(), detail, Vec::new())
            })
            .collect();

        let folder_defaults = plan_folder_defaults(payload, &local)
            .into_iter()
            .map(|row| {
                let f = &payload.folders[row.index];
                let path = file_paths.get(&f.id).unwrap_or(&no_path);
                let detail = file_defaults_text(&f.defaults, payload);
                let notes = match row.status {
                    ItemStatus::Conflict => vec!["Replacing them changes the sessions in that folder here too.".into()],
                    _ => Vec::new(),
                };
                item(row, shown_path(path), detail, notes)
            })
            .collect();

        let secret_values = payload.secrets.iter().any(|s| s.value.is_some());
        let mut warnings = Vec::new();
        if secret_values {
            match local.vault {
                VaultStatus::Unlocked => {}
                VaultStatus::Locked => warnings.push(format!(
                    "The file holds {}. Unlock the vault to import them; sessions can be imported either way.",
                    plural(secrets.len(), "vault secret")
                )),
                VaultStatus::NotSetUp => warnings.push(format!(
                    "The file holds {}. Set up the vault to import them; sessions can be imported either way.",
                    plural(secrets.len(), "vault secret")
                )),
            }
        } else if !payload.secrets.is_empty() {
            warnings.push(
                "The file was exported without vault secrets. Sessions use the secrets with the same labels in this vault, when it has them."
                    .into(),
            );
        }
        Ok(TransferPreview {
            id,
            file: path
                .file_name()
                .map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned()),
            exported_at: payload.exported_at.clone(),
            exported_by: payload.exported_by.clone(),
            folders: payload.folders.len(),
            new_folders,
            sessions,
            known_hosts,
            secrets,
            secret_values,
            favourites,
            folder_defaults,
            warnings,
        })
    }

    /// FD-07: imports the opened file with the user's choices. Each change is made, checked and
    /// audited by the module that owns the data; an item that fails is reported and the rest go on.
    /// A summary entry with the counts and the file path closes the import in the audit log.
    pub async fn commit(
        &self,
        ctx: &Context,
        request: TransferCommit,
        library: &SessionLibrary,
        vault: &VaultService,
        known_hosts: &KnownHosts,
        snippets: &Snippets,
    ) -> Result<TransferReport> {
        self.store.read_only().check(Change::Transfer)?;
        let opened = {
            let mut slot = locks::lock(&self.opened);
            match slot.take() {
                Some(o) if o.id == request.preview_id => o,
                other => {
                    *slot = other;
                    return Err(CoreError::InvalidInput(
                        "That file is no longer open. Open it again to import it.".into(),
                    ));
                }
            }
        };
        // Every choice is checked before anything changes; a refused one keeps the file open.
        let decided = match self.decide(ctx, &opened.payload, &request, vault).await {
            Ok(decided) => decided,
            Err(err) => {
                let mut slot = locks::lock(&self.opened);
                if slot.is_none() {
                    *slot = Some(opened);
                }
                return Err(err);
            }
        };
        let path_name = opened.path.display().to_string();
        let confirmed = match self
            .confirm_secrets_here(
                ctx,
                &opened.payload,
                &decided,
                request.vault_password.as_ref(),
                &path_name,
            )
            .await
        {
            Ok(confirmed) => confirmed,
            Err(err) => {
                let mut slot = locks::lock(&self.opened);
                if slot.is_none() {
                    *slot = Some(opened);
                }
                return Err(err);
            }
        };
        let Opened { path, payload, .. } = opened;
        let Decided {
            mut local,
            secret_rows,
            secret_actions,
            session_rows,
            session_actions,
            host_rows,
            host_actions,
            favourite_rows,
            favourite_actions,
            folder_rows,
            folder_actions,
        } = decided;
        let mut report = TransferReport::default();

        // 1. Secrets, so sessions can point at them.
        let mut secret_map: HashMap<SecretId, SecretId> = HashMap::new();
        for e in payload.secrets.iter().filter(|e| e.value.is_none()) {
            if let Some(here) = local.secret(&e.label, e.kind) {
                secret_map.insert(e.id, here.id);
            }
        }
        for (row, action) in secret_rows.iter().zip(&secret_actions) {
            let e = &payload.secrets[row.index];
            let Some(value) = e.value.clone() else { continue };
            let done = match action {
                ItemAction::Skip => {
                    if let Some(here) = local.secret(&e.label, e.kind) {
                        secret_map.insert(e.id, here.id);
                    }
                    Ok(None)
                }
                ItemAction::Import => vault.add(ctx, e.kind, &e.label, value).await.map(|m| Some(m.id)),
                ItemAction::KeepBoth => {
                    let taken: HashSet<String> = local.secrets.iter().map(|m| m.label.to_lowercase()).collect();
                    let label = free_name(&e.label, &taken, MAX_LABEL_LEN);
                    vault.add(ctx, e.kind, &label, value).await.map(|m| Some(m.id))
                }
                ItemAction::Replace => match row.local {
                    Some(id) => vault.replace(ctx, id, value).await.map(|m| Some(m.id)),
                    None => Ok(None),
                },
            };
            match done {
                Ok(Some(id)) => {
                    secret_map.insert(e.id, id);
                    if let (SecretKind::PrivateKey, Some(public)) = (e.kind, &e.public_key) {
                        self.store.put_ssh_key(ctx, id, public, e.generated).await?;
                    }
                    report.secrets.count(*action);
                }
                Ok(None) => report.secrets.count(ItemAction::Skip),
                Err(err) => report.problems.push(ItemProblem {
                    name: e.label.clone(),
                    reason: err.to_string(),
                }),
            }
        }
        local.secrets = vault.list(ctx).await?;

        // 2. Folders: those the imported sessions go into, and the file's empty folders.
        let folder_map = self
            .folders(ctx, &payload, &session_actions, &local, library, &mut report)
            .await?;

        // 3. Sessions, jump hosts first (so each keeps its jump host link), with their port forwards.
        let forwards = Forwards::new(self.store.clone());
        let marks = ContainerMarks::new(self.store.clone());
        let mut session_map: HashMap<Uuid, Uuid> = HashMap::new();
        let mut taken_names: HashSet<String> = local.sessions.iter().map(|s| s.name.to_lowercase()).collect();
        let mut used_ids: HashSet<Uuid> = local.sessions.iter().map(|s| s.id).collect();
        for index in jump_order(&payload.sessions) {
            let entry = &payload.sessions[index];
            let row = &session_rows[index];
            let action = session_actions[index];
            let here = row.local.and_then(|id| local.sessions.iter().find(|s| s.id == id));
            if action == ItemAction::Skip {
                if let Some(here) = here {
                    session_map.insert(entry.id, here.id);
                }
                report.sessions.count(action);
                continue;
            }
            let (mut input, missing) = self
                .session_input(ctx, entry, &folder_map, &secret_map, &session_map, &local)
                .await?;
            // SS-01: the file's startup command only when ticked; a replaced session keeps its own,
            // and its own terminal choices.
            let keep_startup = request.keep_startup.contains(&index);
            if !keep_startup {
                if input.startup_command.is_some() {
                    report.startup_left_out += 1;
                }
                input.startup_command = None;
            }
            if let (ItemAction::Replace, Some(here)) = (action, here) {
                if !keep_startup {
                    input.startup_command.clone_from(&here.startup_command);
                }
                input.startup_on_reconnect = here.startup_on_reconnect;
                input.prompt_hook = here.prompt_hook;
            }
            let keep_forwards = request.keep_forwards.contains(&index);
            if !keep_forwards {
                report.forwards_left_out += entry.forwards.len();
            }
            let link = match &entry.vm {
                Some(vm) if vm.auto => VmLink::Auto,
                _ => VmLink::Manual,
            };
            let result = match (action, here) {
                (ItemAction::Replace, Some(here)) => {
                    // A credential that did not come along doesn't wipe a working one here.
                    if missing && input.auth.method() == here.own.auth.method() {
                        input.auth = here.own.auth.clone();
                    }
                    input.vm_id = input.vm_id.or_else(|| here.vm_id.clone());
                    let reauth = if confirmed { Reauth::Given } else { Reauth::Ask(None) };
                    library.update_checked(ctx, here.id, input, reauth).await
                }
                (ItemAction::KeepBoth, _) => {
                    if taken_names.contains(&input.name.to_lowercase()) {
                        input.name = free_name(&input.name, &taken_names, crate::sessions::MAX_SESSION_NAME);
                    }
                    let reauth = if confirmed { Reauth::Given } else { Reauth::Ask(None) };
                    library
                        .restore(ctx, Uuid::new_v4(), input, imported_from(entry), link, SOURCE, reauth)
                        .await
                }
                _ => {
                    let id = if used_ids.contains(&entry.id) {
                        Uuid::new_v4()
                    } else {
                        entry.id
                    };
                    let reauth = if confirmed { Reauth::Given } else { Reauth::Ask(None) };
                    library
                        .restore(ctx, id, input, imported_from(entry), link, SOURCE, reauth)
                        .await
                }
            };
            match result {
                Ok(saved) => {
                    taken_names.insert(saved.name.to_lowercase());
                    used_ids.insert(saved.id);
                    session_map.insert(entry.id, saved.id);
                    let still_missing = match &saved.auth {
                        SessionAuth::Password { password_id } => password_id.is_none(),
                        SessionAuth::Key { key_id, .. } => key_id.is_none(),
                        SessionAuth::Agent | SessionAuth::Folder => false,
                    };
                    if missing && still_missing {
                        report.without_credentials += 1;
                    }
                    report.sessions.count(action);
                    // SS-07: a file without forwards (or from before 0.3.0), or forwards not ticked, leave
                    // this laptop's alone.
                    if keep_forwards && !entry.forwards.is_empty() {
                        let inputs: Vec<ForwardInput> = entry.forwards.iter().map(ForwardEntry::input).collect();
                        match forwards.restore(ctx, saved.id, &inputs).await {
                            Ok(saved_forwards) => report.forwards += saved_forwards.len(),
                            Err(err) => report.problems.push(ItemProblem {
                                name: format!("{} (port forwards)", entry.name),
                                reason: err.to_string(),
                            }),
                        }
                    }
                    // CT-01: likewise, a file without container marks leaves this laptop's alone.
                    if !entry.containers.is_empty() {
                        let inputs: Vec<MarkInput> = entry.containers.iter().map(|c| c.input(&secret_map)).collect();
                        match marks.restore(ctx, saved.id, &inputs, SOURCE).await {
                            Ok(_) => report.container_hosts += 1,
                            Err(err) => report.problems.push(ItemProblem {
                                name: format!("{} (container engines)", entry.name),
                                reason: err.to_string(),
                            }),
                        }
                    }
                }
                Err(err) => report.problems.push(ItemProblem {
                    name: entry.name.clone(),
                    reason: err.to_string(),
                }),
            }
        }

        // 3b. QL-16: folder defaults, once the sessions they name as jump host are here. Each is set, checked and
        // audited by the session library, as if the user had set it.
        for (row, action) in folder_rows.iter().zip(&folder_actions) {
            let f = &payload.folders[row.index];
            let target = match action {
                ItemAction::Import => folder_map.get(&f.id).copied(),
                ItemAction::Replace => row.local,
                _ => None,
            };
            let Some(target) = target else {
                report.folder_defaults.count(ItemAction::Skip);
                continue;
            };
            let (auth, _) = match &f.defaults.auth {
                Some(auth) => {
                    let (auth, missing) = map_auth(auth, &secret_map);
                    (Some(auth), missing)
                }
                None => (None, false),
            };
            let jump = f.defaults.jump_session_id.and_then(|j| {
                session_map
                    .get(&j)
                    .copied()
                    .or_else(|| local.sessions.iter().find(|s| s.id == j).map(|s| s.id))
            });
            let defaults = FolderDefaults {
                username: f.defaults.username.clone(),
                auth,
                jump_session_id: jump,
                jump_direct: f.defaults.jump_direct,
                environment: f.defaults.environment,
                tags: f.defaults.tags.clone(),
            };
            let reauth = if confirmed { Reauth::Given } else { Reauth::Ask(None) };
            match library.set_folder_defaults_checked(ctx, target, defaults, reauth).await {
                Ok(_) => report.folder_defaults.count(*action),
                Err(err) => report.problems.push(ItemProblem {
                    name: format!("defaults of folder '{}'", f.name),
                    reason: err.to_string(),
                }),
            }
        }

        // 4. Known host keys: trusting one is audited by the known hosts module.
        for (row, action) in host_rows.iter().zip(&host_actions) {
            let k = &payload.known_hosts[row.index];
            if *action == ItemAction::Skip {
                report.known_hosts.count(*action);
                continue;
            }
            let key = HostKey {
                host: k.host.clone(),
                port: k.port,
                key_type: k.key_type.clone(),
                fingerprint: k.fingerprint.clone(),
            };
            match check_host_key(&key) {
                Ok(()) => match known_hosts.trust(ctx, &key, None).await {
                    Ok(()) => report.known_hosts.count(*action),
                    Err(err) => report.problems.push(ItemProblem {
                        name: key.address(),
                        reason: err.to_string(),
                    }),
                },
                Err(err) => report.problems.push(ItemProblem {
                    name: key.address(),
                    reason: err.to_string(),
                }),
            }
        }

        // 5. Favourite commands (BX-08), each saved and audited by the command panel's module.
        for (row, action) in favourite_rows.iter().zip(&favourite_actions) {
            let f = &payload.favourites[row.index];
            let mut input = FavouriteInput {
                folder: Some(f.folder.clone()).filter(|folder| !folder.trim().is_empty()),
                name: f.name.clone(),
                command: f.command.clone(),
                description: f.description.clone(),
            };
            let result = match (action, row.local) {
                (ItemAction::Skip, _) => {
                    report.favourites.count(*action);
                    continue;
                }
                (ItemAction::Replace, Some(id)) => snippets.update(ctx, id, input).await,
                (ItemAction::KeepBoth, _) => {
                    let names: HashSet<String> = snippets
                        .favourites(ctx)
                        .await?
                        .iter()
                        .filter(|here| {
                            here.folder
                                .as_deref()
                                .unwrap_or("")
                                .eq_ignore_ascii_case(f.folder.trim())
                        })
                        .map(|here| here.name.to_lowercase())
                        .collect();
                    input.name = free_name(&f.name, &names, crate::snippets::MAX_NAME);
                    snippets.add(ctx, input).await
                }
                _ => snippets.add(ctx, input).await,
            };
            match result {
                Ok(_) => report.favourites.count(*action),
                Err(err) => report.problems.push(ItemProblem {
                    name: f.name.clone(),
                    reason: err.to_string(),
                }),
            }
        }

        let mut detail = format!(
            "from {}: sessions {}; folders {} added; folder defaults {}; known host keys {}; vault secrets {}; favourite commands {}",
            path.display(),
            report.sessions.describe(),
            report.folders_added,
            report.folder_defaults.describe(),
            report.known_hosts.describe(),
            report.secrets.describe(),
            report.favourites.describe()
        );
        if report.forwards > 0 {
            detail.push_str(&format!(
                "; {} saved with them",
                plural(report.forwards, "port forward")
            ));
        }
        if report.startup_left_out > 0 {
            detail.push_str(&format!(
                "; {} left out",
                plural(report.startup_left_out, "startup command")
            ));
        }
        if report.forwards_left_out > 0 {
            detail.push_str(&format!(
                "; {} left out",
                plural(report.forwards_left_out, "port forward")
            ));
        }
        if report.container_hosts > 0 {
            detail.push_str(&format!(
                "; {} marked as container hosts",
                plural(report.container_hosts, "session")
            ));
        }
        if report.without_credentials > 0 {
            detail.push_str(&format!(
                "; {} without their saved password or key",
                plural(report.without_credentials, "session")
            ));
        }
        if !report.problems.is_empty() {
            detail.push_str(&format!("; {} not imported", plural(report.problems.len(), "item")));
        }
        self.audit(ctx, "data_imported", "Imported a Remotely export", &detail)
            .await?;
        // QL-01: new sessions are linked to the VMs they reach here, in one pass for the whole import.
        if report.sessions.added + report.sessions.kept_both > 0 {
            if let Err(err) = library.auto_link(ctx).await {
                tracing::warn!(error = %err, "could not link imported sessions to VMs automatically");
            }
        }
        Ok(report)
    }

    /// Compares the file with the library as it is now and checks the user's choice for every item.
    async fn decide(
        &self,
        ctx: &Context,
        payload: &Payload,
        request: &TransferCommit,
        vault: &VaultService,
    ) -> Result<Decided> {
        let chosen =
            |list: &[ItemChoice]| -> HashMap<usize, ItemAction> { list.iter().map(|c| (c.index, c.action)).collect() };
        let local = Local::read(&self.store, ctx, vault).await?;
        let secret_rows = plan_secrets(payload, &local, vault, ctx).await?;
        let secret_choices = chosen(&request.secrets);
        let mut secret_actions = Vec::with_capacity(secret_rows.len());
        for row in &secret_rows {
            secret_actions.push(row.action(&secret_choices, &payload.secrets[row.index].label)?);
        }
        let session_rows = plan_sessions(payload, &local);
        let session_choices = chosen(&request.sessions);
        let mut session_actions = Vec::with_capacity(session_rows.len());
        for row in &session_rows {
            session_actions.push(row.action(&session_choices, &payload.sessions[row.index].name)?);
        }
        let host_rows = plan_known_hosts(payload, &local);
        let host_choices = chosen(&request.known_hosts);
        let mut host_actions = Vec::with_capacity(host_rows.len());
        for row in &host_rows {
            let k = &payload.known_hosts[row.index];
            host_actions.push(row.action(&host_choices, &address(&k.host, k.port))?);
        }
        let favourite_rows = plan_favourites(payload, &local);
        let favourite_choices = chosen(&request.favourites);
        let mut favourite_actions = Vec::with_capacity(favourite_rows.len());
        for row in &favourite_rows {
            favourite_actions.push(row.action(&favourite_choices, &payload.favourites[row.index].name)?);
        }
        let folder_rows = plan_folder_defaults(payload, &local);
        let folder_choices = chosen(&request.folder_defaults);
        let mut folder_actions = Vec::with_capacity(folder_rows.len());
        for row in &folder_rows {
            folder_actions.push(row.action(&folder_choices, &payload.folders[row.index].name)?);
        }
        if secret_actions.iter().any(|a| *a != ItemAction::Skip) {
            match local.vault {
                VaultStatus::Unlocked => {}
                VaultStatus::Locked => return Err(CoreError::VaultLocked),
                VaultStatus::NotSetUp => return Err(CoreError::VaultNotSetUp),
            }
        }
        Ok(Decided {
            local,
            secret_rows,
            secret_actions,
            session_rows,
            session_actions,
            host_rows,
            host_actions,
            favourite_rows,
            favourite_actions,
            folder_rows,
            folder_actions,
        })
    }

    /// Finds or creates the folders the import needs; returns the file's folder ids mapped to the
    /// folders here. A folder that can't be created is reported, and its sessions go to its parent.
    async fn folders(
        &self,
        ctx: &Context,
        payload: &Payload,
        session_actions: &[ItemAction],
        local: &Local,
        library: &SessionLibrary,
        report: &mut TransferReport,
    ) -> Result<HashMap<Uuid, Uuid>> {
        let parents: HashMap<Uuid, Option<Uuid>> = payload.folders.iter().map(|f| (f.id, f.parent_id)).collect();
        let ancestors = |id: Uuid| {
            let mut chain = Vec::new();
            let mut next = Some(id);
            while let Some(current) = next.filter(|c| !chain.contains(c) && parents.contains_key(c)) {
                chain.push(current);
                next = parents.get(&current).copied().flatten();
            }
            chain
        };
        let mut wanted: HashSet<Uuid> = HashSet::new();
        let mut holds_sessions: HashSet<Uuid> = HashSet::new();
        for (entry, action) in payload.sessions.iter().zip(session_actions) {
            let Some(folder) = entry.folder_id else { continue };
            let chain = ancestors(folder);
            holds_sessions.extend(chain.iter().copied());
            if *action != ItemAction::Skip {
                wanted.extend(chain);
            }
        }
        // Folders with no session anywhere below them are structure the user made: they come along.
        for f in &payload.folders {
            if !holds_sessions.contains(&f.id) {
                wanted.extend(ancestors(f.id));
            }
        }

        let mut here: HashMap<(Option<Uuid>, String), Uuid> = local
            .folders
            .iter()
            .map(|f| ((f.parent_id, f.name.to_lowercase()), f.id))
            .collect();
        let mut map: HashMap<Uuid, Uuid> = HashMap::new();
        let mut order: Vec<&FolderEntry> = payload.folders.iter().filter(|f| wanted.contains(&f.id)).collect();
        order.sort_by_key(|f| ancestors(f.id).len());
        let mut failed: HashSet<Uuid> = HashSet::new();
        for f in order {
            let parent_here = match f.parent_id {
                Some(p) if failed.contains(&p) => {
                    failed.insert(f.id);
                    if let Some(id) = map.get(&p).copied() {
                        map.insert(f.id, id);
                    }
                    continue;
                }
                Some(p) => map.get(&p).copied(),
                None => None,
            };
            let key = (parent_here, f.name.trim().to_lowercase());
            if let Some(id) = here.get(&key) {
                map.insert(f.id, *id);
                continue;
            }
            match library.create_folder(ctx, &f.name, parent_here).await {
                Ok(created) => {
                    here.insert(key, created.id);
                    map.insert(f.id, created.id);
                    report.folders_added += 1;
                }
                Err(err) => {
                    failed.insert(f.id);
                    if let Some(parent) = parent_here {
                        map.insert(f.id, parent);
                    }
                    report.problems.push(ItemProblem {
                        name: format!("folder '{}'", f.name),
                        reason: format!("{err}; its sessions go one level up"),
                    });
                }
            }
        }
        Ok(map)
    }

    /// The session as this laptop's library takes it: folders, secrets and the jump host mapped to
    /// the ones here, and the VM linked again when one here has the same .vmx path. `true` when the
    /// session used a saved password or key that is not here.
    async fn session_input(
        &self,
        ctx: &Context,
        entry: &SessionEntry,
        folders: &HashMap<Uuid, Uuid>,
        secrets: &HashMap<SecretId, SecretId>,
        sessions: &HashMap<Uuid, Uuid>,
        local: &Local,
    ) -> Result<(SessionInput, bool)> {
        let (auth, missing) = map_auth(&entry.auth, secrets);
        let jump = entry.jump_session_id.and_then(|j| {
            sessions
                .get(&j)
                .copied()
                .or_else(|| local.sessions.iter().find(|s| s.id == j).map(|s| s.id))
        });
        let vm_id = match &entry.vm {
            Some(vm) => self.store.find_vm(ctx, &vm.vmx_path).await?.map(|vm| vm.id),
            None => None,
        };
        Ok((
            SessionInput {
                name: entry.name.clone(),
                folder_id: entry.folder_id.and_then(|f| folders.get(&f).copied()),
                host: entry.host.clone(),
                port: entry.port,
                username: entry.username.clone(),
                auth,
                jump_session_id: jump,
                jump_direct: entry.jump_direct,
                startup_command: entry.startup_command.clone(),
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: entry.environment,
                color: entry.color,
                tags: entry.tags.clone(),
                vm_id,
            },
            missing,
        ))
    }

    /// FD-14's GitHub update token, if this laptop has one: it stays behind, since each laptop gets
    /// its own (they expire and are revoked one by one).
    async fn update_token(&self, ctx: &Context) -> Result<Option<SecretId>> {
        Ok(self
            .store
            .get_setting::<Option<SecretId>>(ctx, crate::updates::UPDATE_TOKEN_KEY)
            .await?
            .flatten())
    }

    async fn audit(&self, ctx: &Context, event: &str, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

fn item<T>(row: RowPlan<T>, name: String, detail: String, notes: Vec<String>) -> PreviewItem {
    PreviewItem {
        index: row.index,
        name,
        detail,
        status: row.status,
        conflict: row.conflict,
        choices: row.choices,
        default_action: row.default_action,
        notes,
        startup_command: None,
        startup_rating: None,
        forwards: Vec::new(),
    }
}

fn imported_from(entry: &SessionEntry) -> Option<&str> {
    entry.imported_from.as_deref().filter(|f| IMPORTED_FROM.contains(f))
}

/// A host key from a file: a sane host and key type, a SHA-256 fingerprint.
fn check_host_key(key: &HostKey) -> Result<()> {
    let host_ok = !key.host.is_empty()
        && key.host.len() <= crate::sessions::MAX_HOST_LEN
        && key
            .host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%' | '[' | ']'));
    let type_ok = !key.key_type.is_empty()
        && key.key_type.len() <= 100
        && key
            .key_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '@'));
    let fingerprint_ok = key.fingerprint.starts_with("SHA256:")
        && key.fingerprint.len() <= 100
        && key.fingerprint[7..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
    if host_ok && type_ok && fingerprint_ok && key.port != 0 {
        Ok(())
    } else {
        Err(CoreError::InvalidInput(
            "That host key entry is damaged, so it was not trusted.".into(),
        ))
    }
}

/// Sessions in an order where each one's jump host (when it is in the file) comes first. Sessions in
/// a jump cycle come last; their jump host is left out.
fn jump_order(sessions: &[SessionEntry]) -> Vec<usize> {
    let in_file: HashSet<Uuid> = sessions.iter().map(|s| s.id).collect();
    let mut done: HashSet<Uuid> = HashSet::new();
    let mut order = Vec::with_capacity(sessions.len());
    let mut remaining: Vec<usize> = (0..sessions.len()).collect();
    loop {
        let before = remaining.len();
        remaining.retain(|&i| {
            let s = &sessions[i];
            let ready = s
                .jump_session_id
                .is_none_or(|j| !in_file.contains(&j) || done.contains(&j));
            if ready {
                order.push(i);
                done.insert(s.id);
            }
            !ready
        });
        if remaining.is_empty() || remaining.len() == before {
            break;
        }
    }
    order.extend(remaining);
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, jump: Option<Uuid>) -> SessionEntry {
        SessionEntry {
            id: Uuid::new_v4(),
            folder_id: None,
            name: name.into(),
            host: format!("{name}.example.com"),
            port: 22,
            username: Some("alice".into()),
            auth: SessionAuth::Agent,
            jump_session_id: jump,
            jump_direct: false,
            startup_command: None,
            environment: Environment::None,
            color: None,
            tags: vec![],
            vm: None,
            imported_from: None,
            forwards: vec![],
            containers: vec![],
        }
    }

    #[test]
    fn files_from_before_port_forwards_still_read() {
        // A session as 0.2.x wrote it: no `forwards`.
        let old = r#"{"id":"7d1f0f0e-63f8-4a5b-9f3a-2f9d8f1d2c3b","name":"web01","host":"web01.example.com",
            "port":22,"auth":{"method":"agent"},"jumpSessionId":null}"#;
        let entry: SessionEntry = serde_json::from_str(old).unwrap();
        assert!(entry.forwards.is_empty());
        assert_eq!(entry.name, "web01");
    }

    #[test]
    fn jump_hosts_come_before_the_sessions_that_use_them() {
        let bastion = entry("bastion", None);
        let inner = entry("inner", Some(bastion.id));
        let deeper = entry("deeper", Some(inner.id));
        let outside = entry("outside", Some(Uuid::new_v4()));
        let sessions = vec![deeper, inner, outside, bastion];
        let order: Vec<&str> = jump_order(&sessions)
            .iter()
            .map(|&i| sessions[i].name.as_str())
            .collect();
        let at = |n: &str| order.iter().position(|o| *o == n).unwrap();
        assert!(at("bastion") < at("inner") && at("inner") < at("deeper"), "{order:?}");
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn a_jump_cycle_does_not_lose_sessions() {
        let mut a = entry("a", None);
        let b = entry("b", Some(a.id));
        a.jump_session_id = Some(b.id);
        let sessions = vec![a, b];
        let mut order = jump_order(&sessions);
        order.sort_unstable();
        assert_eq!(order, [0, 1]);
    }

    #[test]
    fn folder_paths_follow_parents_and_survive_a_cycle() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let folders = [(a, None, "Customer A"), (b, Some(a), "Web"), (c, Some(c), "Loop")];
        let p = paths(folders.into_iter());
        assert_eq!(p[&b], ["Customer A", "Web"]);
        assert_eq!(p[&c], ["Loop"]);
        assert!(same_path(&p[&b], &["customer a".into(), "WEB".into()]));
    }

    #[test]
    fn free_names_count_up_and_stay_short() {
        let taken: HashSet<String> = ["web01".into(), "web01 (2)".into()].into();
        assert_eq!(free_name("web01", &taken, 100), "web01 (3)");
        let long = "x".repeat(100);
        assert_eq!(free_name(&long, &HashSet::new(), 100).chars().count(), 100);
    }

    #[test]
    fn host_keys_from_a_file_are_checked() {
        let key = HostKey {
            host: "web01.example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: "SHA256:AbC+/0=".into(),
        };
        assert!(check_host_key(&key).is_ok());
        for bad in [
            HostKey {
                host: "web 01".into(),
                ..key.clone()
            },
            HostKey {
                key_type: "ssh-ed25519\n".into(),
                ..key.clone()
            },
            HostKey {
                fingerprint: "MD5:aa:bb".into(),
                ..key.clone()
            },
            HostKey { port: 0, ..key.clone() },
        ] {
            assert!(check_host_key(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn exports_are_never_written_into_a_git_repository() {
        let root = std::env::temp_dir().join(format!("remotely-repo-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        let err = refuse_repository(&root.join("docs").join("export.remotely")).unwrap_err();
        assert!(err.to_string().contains("Git repository"), "{err}");
        let outside = std::env::temp_dir().join(format!("remotely-plain-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&outside).unwrap();
        assert!(refuse_repository(&outside.join("export.remotely")).is_ok());
        // A bare file name is relative to the working folder: here, the repository itself.
        assert!(refuse_repository(Path::new("export.remotely")).is_err());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn the_default_file_name_has_the_date_and_extension() {
        let name = default_file_name();
        assert!(name.starts_with("remotely-export-20"), "{name}");
        assert!(name.ends_with(".remotely"), "{name}");
    }

    #[test]
    fn secret_values_are_written_only_when_present() {
        let with = SecretEntry {
            id: SecretId(Uuid::new_v4()),
            kind: SecretKind::Password,
            label: "web root".into(),
            value: Some(SecretString::new("hunter2")),
            public_key: None,
            generated: false,
        };
        let json = serde_json::to_string(&with).unwrap();
        assert!(json.contains(r#""value":"hunter2""#), "{json}");
        let without = SecretEntry { value: None, ..with };
        let json = serde_json::to_string(&without).unwrap();
        assert!(!json.contains("value"), "{json}");
        // And back.
        let back: SecretEntry = serde_json::from_str(&json).unwrap();
        assert!(back.value.is_none());
    }
}
