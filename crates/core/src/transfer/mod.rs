//! FD-07: encrypted export and import of the session library, so sessions move between the owner's
//! laptops (and, later, to a teammate).
//!
//! * Export writes one file (see [`file`]) with the session folders, the sessions (with their tags,
//!   environment labels and colours), the trusted host keys and, only when the user ticks it, the
//!   vault's secrets with their values. The user chooses the passphrase; Argon2id turns it into the
//!   AES-256-GCM key. The vault's labels always go along (they are not secret), so on the other laptop
//!   sessions find secrets with the same label even when the values stayed behind. Exporting secret
//!   values asks for the vault password again, as Critical actions do (AP-06): otherwise anyone at an
//!   unlocked laptop could carry every secret away under a passphrase of their own.
//! * Import opens the file with its passphrase, compares it with this laptop's library and shows a
//!   preview: each session, known host and secret is new, already here, or in conflict with something
//!   here (the same session changed, the same user, host and port, the same name; another key trusted
//!   for the host; another value under the label). The user chooses per item: skip, replace, or keep
//!   both. The opened file stays in the core under an id until it is imported or closed, so the commit
//!   names rows only, and no path or secret comes back from the UI.
//! * Every change goes through the module that owns the data (session library, vault, known hosts),
//!   so it is checked and audited as if the user had made it there. Export and import themselves are
//!   audited with counts and the file path, never the contents.
//! * An export is never written into a Git working tree (the default folder is Documents), so it can't
//!   end up in a commit by mistake.
//!
//! Nothing here touches a VM or a remote host, so it skips the command bus, like the session library.

pub mod file;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::{now_rfc3339, Context, Environment};
use crate::error::{CoreError, Result};
use crate::known_hosts::{address, HostKey, KnownHost, KnownHosts};
use crate::locks;
use crate::sessions::{SessionAuth, SessionColor, SessionFolder, SessionInput, SessionLibrary, SessionRecord};
use crate::ssh_keys::PublicKeyInfo;
use crate::store::{NewAuditEntry, Store};
use crate::vault::{
    check_master_password, KdfParams, SecretId, SecretKind, SecretMeta, SecretString, VaultService, VaultStatus,
    MAX_LABEL_LEN,
};

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

/// The setting that names FD-14's update token in the vault. That token is never exported.
const UPDATE_TOKEN_SETTING: &str = "updates.tokenId";

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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderEntry {
    id: Uuid,
    #[serde(default)]
    parent_id: Option<Uuid>,
    name: String,
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VmHint {
    vmx_path: String,
    name: String,
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
    pub folders_added: usize,
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
    let no_path = Vec::new();
    payload
        .sessions
        .iter()
        .enumerate()
        .map(|(index, s)| {
            let path = s.folder_id.and_then(|f| file_paths.get(&f)).unwrap_or(&no_path);
            let same = |l: &SessionRecord| {
                let mut a: Vec<String> = s.tags.iter().map(|t| t.to_lowercase()).collect();
                let mut b: Vec<String> = l.tags.iter().map(|t| t.to_lowercase()).collect();
                a.sort();
                b.sort();
                let local_path = l.folder_id.and_then(|f| local.folder_paths.get(&f)).unwrap_or(&no_path);
                s.name == l.name
                    && s.host.eq_ignore_ascii_case(&l.host)
                    && s.port == l.port
                    && s.username == l.username
                    && s.auth.method() == l.auth.method()
                    && s.startup_command == l.startup_command
                    && s.environment == l.environment
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
            let same_address = |l: &&SessionRecord| {
                l.host.eq_ignore_ascii_case(&s.host) && l.port == s.port && l.username == s.username
            };
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
            match here {
                None => RowPlan::new(index),
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

fn check_passphrase(passphrase: &SecretString) -> Result<()> {
    check_master_password(passphrase).map_err(|_| {
        CoreError::InvalidInput(
            "The passphrase needs at least 10 characters. A few unrelated words make a good one.".into(),
        )
    })
}

/// FD-07: an export is never written into a Git working tree, where it could be committed by mistake.
pub fn refuse_repository(path: &Path) -> Result<()> {
    let folder = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let folder = std::path::absolute(folder)?;
    for ancestor in folder.ancestors() {
        if ancestor.join(".git").exists() {
            return Err(CoreError::InvalidInput(format!(
                "{} is inside a Git repository ({}). An export holds your sessions, and maybe your secrets, and could end up in a commit there. Choose a folder outside it, such as Documents.",
                folder.display(),
                ancestor.display()
            )));
        }
    }
    Ok(())
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
}

/// An opened export, kept until it is imported or closed. Its secrets are zeroized when it is dropped.
struct Opened {
    id: Uuid,
    path: PathBuf,
    payload: Payload,
}

pub struct Transfer {
    store: Store,
    kdf: Mutex<KdfParams>,
    /// The file the user picked to import, until its passphrase opens it.
    chosen: Mutex<Option<PathBuf>>,
    opened: Mutex<Option<Opened>>,
}

impl Transfer {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            kdf: Mutex::new(KdfParams::DEFAULT),
            chosen: Mutex::new(None),
            opened: Mutex::new(None),
        }
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
        let mut entries = Vec::with_capacity(sessions.len());
        for s in sessions {
            let vm = match &s.vm_id {
                Some(id) => self.store.vm_by_id(ctx, id).await?.map(|vm| VmHint {
                    vmx_path: vm.vmx_path,
                    name: vm.display_name,
                }),
                None => None,
            };
            entries.push(SessionEntry {
                id: s.id,
                folder_id: s.folder_id,
                name: s.name,
                host: s.host,
                port: s.port,
                username: s.username,
                auth: s.auth,
                jump_session_id: s.jump_session_id,
                startup_command: s.startup_command,
                environment: s.environment,
                color: s.color,
                tags: s.tags,
                vm,
                imported_from: s.imported_from,
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
        };
        let report = ExportReport {
            path: path.display().to_string(),
            folders: payload.folders.len(),
            sessions: payload.sessions.len(),
            known_hosts: payload.known_hosts.len(),
            secrets: payload.secrets.len(),
            secret_values: include_secrets,
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
            "{}, {}, {}, {secrets}, to {}",
            plural(report.sessions, "session"),
            plural(report.folders, "folder"),
            plural(report.known_hosts, "known host key"),
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

        let sessions = plan_sessions(payload, &local)
            .into_iter()
            .map(|row| {
                let s = &payload.sessions[row.index];
                let path = s.folder_id.and_then(|f| file_paths.get(&f)).unwrap_or(&no_path);
                let mut detail = format!(
                    "{}, in {}",
                    session_address(s.username.as_deref(), &s.host, s.port),
                    shown_path(path)
                );
                if s.environment != Environment::None {
                    detail.push_str(&format!(", {}", s.environment.as_str()));
                }
                let mut notes: Vec<String> = credential_note(s, payload, &local).into_iter().collect();
                if s.jump_session_id.is_some() {
                    notes.push("Connects through a jump host.".into());
                }
                item(row, s.name.clone(), detail, notes)
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
                    .filter(|s| s.auth.credential_id() == Some(e.id) || s.auth.passphrase_id() == Some(e.id))
                    .count();
                let detail = match used {
                    0 => e.kind.label().to_owned(),
                    n => format!("{}, used by {}", e.kind.label(), plural(n, "session")),
                };
                item(row, e.label.clone(), detail, Vec::new())
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
    ) -> Result<TransferReport> {
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
        let Opened { path, payload, .. } = opened;
        let Decided {
            mut local,
            secret_rows,
            secret_actions,
            session_rows,
            session_actions,
            host_rows,
            host_actions,
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

        // 3. Sessions, jump hosts first.
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
            let result = match (action, here) {
                (ItemAction::Replace, Some(here)) => {
                    // A credential that did not come along doesn't wipe a working one here.
                    if missing && input.auth.method() == here.auth.method() {
                        input.auth = here.auth.clone();
                    }
                    input.vm_id = input.vm_id.or_else(|| here.vm_id.clone());
                    library.update(ctx, here.id, input).await
                }
                (ItemAction::KeepBoth, _) => {
                    input.name = free_name(&input.name, &taken_names, crate::sessions::MAX_SESSION_NAME);
                    library
                        .restore(ctx, Uuid::new_v4(), input, imported_from(entry), SOURCE)
                        .await
                }
                _ => {
                    let id = if used_ids.contains(&entry.id) {
                        Uuid::new_v4()
                    } else {
                        entry.id
                    };
                    library.restore(ctx, id, input, imported_from(entry), SOURCE).await
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
                        SessionAuth::Agent => false,
                    };
                    if missing && still_missing {
                        report.without_credentials += 1;
                    }
                    report.sessions.count(action);
                }
                Err(err) => report.problems.push(ItemProblem {
                    name: entry.name.clone(),
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

        let mut detail = format!(
            "from {}: sessions {}; folders {} added; known host keys {}; vault secrets {}",
            path.display(),
            report.sessions.describe(),
            report.folders_added,
            report.known_hosts.describe(),
            report.secrets.describe()
        );
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
        let map_secret = |id: Option<SecretId>| id.and_then(|id| secrets.get(&id).copied());
        let (auth, missing) = match entry.auth {
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
        };
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
                startup_command: entry.startup_command.clone(),
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
        let saved = self
            .store
            .get_setting::<serde_json::Value>(ctx, UPDATE_TOKEN_SETTING)
            .await?;
        Ok(saved
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
            .map(SecretId))
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
            startup_command: None,
            environment: Environment::None,
            color: None,
            tags: vec![],
            vm: None,
            imported_from: None,
        }
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
