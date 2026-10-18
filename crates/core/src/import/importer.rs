//! SS-02, the second half: compares what a parser found with the library, shows it as a preview
//! (new, duplicate, name conflict), then saves the rows the user picked.
//!
//! The preview stays in the core under an id, so the commit step only names rows: file paths (the
//! source, key files) never come from the UI. Saving goes through the session library, so imported
//! sessions are checked like edited ones and each is audited ("Imported session 'web01' from PuTTY"),
//! with `imported_from` set; a summary entry closes the import. Key files the user chose to keep go
//! into the vault (audited there too). Passwords are never imported.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{split_address, text, Candidate, CandidateAuth, Parsed, Skipped};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::sessions::{SessionAuth, SessionInput, SessionLibrary, SessionRecord, MAX_SESSION_NAME};
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretId, SecretKind, SecretString, VaultService, VaultStatus, MAX_SECRET_BYTES};

/// Largest source file read: far more than any real session list.
pub const MAX_SOURCE_BYTES: u64 = 10 * 1024 * 1024;
/// Previews kept for a commit; older ones are dropped.
const KEPT_PREVIEWS: usize = 4;

/// Where sessions come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ImportSource {
    /// PuTTY's saved sessions in this Windows user's registry.
    Putty,
    /// A regedit export of PuTTY's sessions (`.reg`), e.g. from another computer.
    PuttyFile,
    /// A MobaXterm `.mxtsessions` export.
    Mobaxterm,
    /// An OpenSSH client config, `~/.ssh/config` by default.
    Openssh,
    Csv,
}

impl ImportSource {
    /// The stable `sessions.imported_from` value.
    pub fn imported_from(self) -> &'static str {
        match self {
            ImportSource::Putty | ImportSource::PuttyFile => "putty",
            ImportSource::Mobaxterm => "mobaxterm",
            ImportSource::Openssh => "openssh",
            ImportSource::Csv => "csv",
        }
    }

    /// How the audit log and the UI name it.
    pub fn label(self) -> &'static str {
        match self {
            ImportSource::Putty | ImportSource::PuttyFile => "PuTTY",
            ImportSource::Mobaxterm => "MobaXterm",
            ImportSource::Openssh => "the OpenSSH config",
            ImportSource::Csv => "CSV",
        }
    }
}

/// How a found session relates to the library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum RowStatus {
    New,
    /// The library already has a session to the same user, host and port. Left out by default.
    Duplicate {
        session_id: Uuid,
        session_name: String,
    },
    /// An earlier row of this import has the same user, host and port. Left out by default.
    DuplicateInImport {
        row: usize,
    },
    /// A session with this name exists but connects elsewhere; imported under `rename_to`.
    NameConflict {
        session_id: Uuid,
        rename_to: String,
    },
}

/// A key file a found session uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyFile {
    pub path: String,
    /// The file's name, used as the vault label.
    pub label: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewRow {
    pub index: usize,
    pub candidate: Candidate,
    pub status: RowStatus,
    /// Ticked in the preview by default.
    pub selected: bool,
    pub key_file: Option<KeyFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub id: Uuid,
    pub source: ImportSource,
    /// The file read (its name only), when the source is a file.
    pub file: Option<String>,
    pub rows: Vec<PreviewRow>,
    /// Entries the source has that can't be imported, and why.
    pub skipped: Vec<Skipped>,
    pub warnings: Vec<String>,
}

/// What the user picked in the preview.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub preview_id: Uuid,
    /// Row indexes to import.
    pub rows: Vec<usize>,
    /// Folder to import into (`None`: the top level). The source's own folders are made under it.
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    /// Add the rows' key files to the vault and log in with them.
    #[serde(default)]
    pub add_keys: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub created: usize,
    pub keys_added: usize,
    pub folders_created: usize,
    /// Sessions that were not saved, or saved with something missing, and why.
    pub problems: Vec<Skipped>,
}

struct Stored {
    id: Uuid,
    source: ImportSource,
    rows: Vec<PreviewRow>,
}

pub struct Importer {
    store: Store,
    previews: Mutex<VecDeque<Stored>>,
}

/// The user's home folder, where `~` and MobaXterm's `_ProfileDir_` point.
pub fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// `~/.ssh/config`.
pub fn default_openssh_config() -> PathBuf {
    home_dir().join(".ssh").join("config")
}

/// Same user, host and port: the same place to log in.
fn address_key(host: &str, port: u16, user: Option<&str>) -> (String, u16, Option<String>) {
    (host.to_lowercase(), port, user.map(str::to_owned))
}

/// `name (2)`, `name (3)`, ... the first that is not taken (names compared without letter case).
fn free_name(name: &str, taken: &HashSet<String>) -> String {
    for n in 2.. {
        let suffix = format!(" ({n})");
        let keep = MAX_SESSION_NAME.saturating_sub(suffix.chars().count());
        let candidate = format!("{}{suffix}", name.chars().take(keep).collect::<String>());
        if !taken.contains(&candidate.to_lowercase()) {
            return candidate;
        }
    }
    name.to_owned()
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

impl Importer {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            previews: Mutex::default(),
        }
    }

    /// PuTTY's sessions from this Windows user's registry.
    pub async fn preview_putty(&self, ctx: &Context) -> Result<ImportPreview> {
        #[cfg(windows)]
        {
            let parsed = tokio::task::spawn_blocking(super::putty::read_registry)
                .await
                .map_err(|err| CoreError::Io(std::io::Error::other(err)))??;
            self.preview(ctx, ImportSource::Putty, None, parsed).await
        }
        #[cfg(not(windows))]
        {
            let _ = ctx;
            Err(CoreError::InvalidInput(
                "PuTTY's registry exists on Windows only.".into(),
            ))
        }
    }

    /// Reads a source file (at most [`MAX_SOURCE_BYTES`]) and previews it.
    pub async fn preview_file(&self, ctx: &Context, source: ImportSource, path: &Path) -> Result<ImportPreview> {
        if source == ImportSource::Putty {
            return self.preview_putty(ctx).await;
        }
        let size = tokio::fs::metadata(path)
            .await
            .map_err(|err| CoreError::InvalidInput(format!("can't read {}: {err}", path.display())))?
            .len();
        if size > MAX_SOURCE_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "{} is larger than {} MB, too large for a session list.",
                path.display(),
                MAX_SOURCE_BYTES / 1024 / 1024
            )));
        }
        let bytes = tokio::fs::read(path).await?;
        let content = text::decode_text(&bytes);
        let home = home_dir();
        let parsed = match source {
            ImportSource::Putty | ImportSource::PuttyFile => super::putty::parse_reg(&content),
            ImportSource::Mobaxterm => super::mobaxterm::parse(&content, &home),
            ImportSource::Csv => super::csv::parse(&content),
            ImportSource::Openssh => {
                let user = std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_default();
                tokio::task::spawn_blocking(move || {
                    let read = |p: &Path| std::fs::read(p).ok().map(|b| text::decode_text(&b));
                    super::openssh::parse(&content, &home, &user, &read)
                })
                .await
                .map_err(|err| CoreError::Io(std::io::Error::other(err)))?
            }
        };
        let file = path.file_name().map(|f| f.to_string_lossy().into_owned());
        self.preview(ctx, source, file, parsed).await
    }

    /// Compares parsed sessions with the library and keeps the result for [`Importer::commit`].
    pub async fn preview(
        &self,
        ctx: &Context,
        source: ImportSource,
        file: Option<String>,
        parsed: Parsed,
    ) -> Result<ImportPreview> {
        let existing = self.store.list_sessions(ctx).await?;
        let mut by_address: HashMap<(String, u16, Option<String>), &SessionRecord> = HashMap::new();
        let mut by_name: HashMap<String, &SessionRecord> = HashMap::new();
        for s in &existing {
            by_address
                .entry(address_key(&s.host, s.port, s.username.as_deref()))
                .or_insert(s);
            by_name.entry(s.name.to_lowercase()).or_insert(s);
        }
        let mut taken: HashSet<String> = existing.iter().map(|s| s.name.to_lowercase()).collect();
        let mut seen: HashMap<(String, u16, Option<String>), usize> = HashMap::new();
        let mut rows = Vec::with_capacity(parsed.candidates.len());
        for (index, candidate) in parsed.candidates.into_iter().enumerate() {
            let key = address_key(&candidate.host, candidate.port, candidate.username.as_deref());
            let status = if let Some(s) = by_address.get(&key) {
                RowStatus::Duplicate {
                    session_id: s.id,
                    session_name: s.name.clone(),
                }
            } else if let Some(row) = seen.get(&key) {
                RowStatus::DuplicateInImport { row: *row }
            } else if let Some(s) = by_name.get(&candidate.name.to_lowercase()) {
                let rename_to = free_name(&candidate.name, &taken);
                taken.insert(rename_to.to_lowercase());
                RowStatus::NameConflict {
                    session_id: s.id,
                    rename_to,
                }
            } else {
                taken.insert(candidate.name.to_lowercase());
                RowStatus::New
            };
            seen.entry(key).or_insert(index);
            let key_file = match &candidate.auth {
                CandidateAuth::KeyFile { path } => Some(KeyFile {
                    path: path.clone(),
                    label: Path::new(path)
                        .file_name()
                        .map_or_else(|| path.clone(), |f| f.to_string_lossy().into_owned()),
                    exists: Path::new(path).is_file(),
                }),
                _ => None,
            };
            rows.push(PreviewRow {
                index,
                selected: matches!(status, RowStatus::New | RowStatus::NameConflict { .. }),
                candidate,
                status,
                key_file,
            });
        }
        let preview = ImportPreview {
            id: Uuid::new_v4(),
            source,
            file,
            rows,
            skipped: parsed.skipped,
            warnings: parsed.warnings,
        };
        let mut kept = locks::lock(&self.previews);
        kept.push_back(Stored {
            id: preview.id,
            source,
            rows: preview.rows.clone(),
        });
        while kept.len() > KEPT_PREVIEWS {
            kept.pop_front();
        }
        Ok(preview)
    }

    /// Saves the picked rows. Nothing is saved when the request can't be carried out as a whole
    /// (an unknown preview or row, a missing folder, a locked vault while keys are to be added); a
    /// row the library refuses is reported and the others are saved.
    pub async fn commit(
        &self,
        ctx: &Context,
        request: &ImportRequest,
        sessions: &SessionLibrary,
        vault: &VaultService,
    ) -> Result<ImportReport> {
        let (source, rows) = {
            let kept = locks::lock(&self.previews);
            let stored = kept.iter().find(|p| p.id == request.preview_id).ok_or_else(|| {
                CoreError::InvalidInput("That preview is no longer available. Read the source again.".into())
            })?;
            let mut picked = Vec::with_capacity(request.rows.len());
            let mut seen = HashSet::new();
            for index in &request.rows {
                let row = stored
                    .rows
                    .iter()
                    .find(|r| r.index == *index)
                    .ok_or_else(|| CoreError::InvalidInput(format!("The preview has no row {index}.")))?;
                if seen.insert(*index) {
                    picked.push(row.clone());
                }
            }
            (stored.source, picked)
        };
        if rows.is_empty() {
            return Err(CoreError::InvalidInput("Choose at least one session to import.".into()));
        }
        let folders = sessions.folders(ctx).await?;
        if let Some(folder) = request.folder_id {
            if !folders.iter().any(|f| f.id == folder) {
                return Err(CoreError::UnknownTarget(format!("folder {folder}")));
            }
        }
        let wants_keys = request.add_keys && rows.iter().any(|r| r.key_file.is_some());
        if wants_keys && vault.info().status != VaultStatus::Unlocked {
            return Err(CoreError::VaultLocked);
        }

        let mut report = ImportReport::default();
        let keys = if wants_keys {
            self.add_keys(ctx, &rows, vault, &mut report).await?
        } else {
            HashMap::new()
        };

        // The source's folders, made under the chosen one as needed.
        let mut folder_ids: HashMap<Vec<String>, Option<Uuid>> = HashMap::new();
        folder_ids.insert(Vec::new(), request.folder_id);
        let mut known_folders = folders;
        for row in &rows {
            let path = &row.candidate.folder;
            for depth in 1..=path.len() {
                let prefix = path[..depth].to_vec();
                if folder_ids.contains_key(&prefix) {
                    continue;
                }
                let parent = folder_ids.get(&path[..depth - 1]).copied().flatten();
                let name = &path[depth - 1];
                let found = known_folders
                    .iter()
                    .find(|f| f.parent_id == parent && f.name.eq_ignore_ascii_case(name))
                    .map(|f| f.id);
                let id = match found {
                    Some(id) => id,
                    None => {
                        let folder = sessions.create_folder(ctx, name, parent).await?;
                        report.folders_created += 1;
                        let id = folder.id;
                        known_folders.push(folder);
                        id
                    }
                };
                folder_ids.insert(prefix, Some(id));
            }
        }

        // Rows whose jump host is another row of this import are saved after it, so the link can
        // be kept for SS-07 (the terminal says jump hosts are not supported yet).
        let existing = self.store.list_sessions(ctx).await?;
        let mut created: Vec<(usize, SessionRecord)> = Vec::new();
        let mut pending = rows;
        loop {
            let mut waiting = Vec::new();
            let mut progressed = false;
            let unsaved = pending.clone();
            for row in std::mem::take(&mut pending) {
                let jump = match &row.candidate.jump {
                    None => Some(None),
                    Some(text) => {
                        let saved = created.iter().map(|(_, s)| s).chain(existing.iter());
                        match find_jump(text, saved) {
                            Some(id) => Some(Some(id)),
                            None if refers_to_row(text, &unsaved, &row) => None,
                            None => Some(None),
                        }
                    }
                };
                let Some(jump) = jump else {
                    waiting.push(row);
                    continue;
                };
                progressed = true;
                self.save(
                    ctx,
                    source,
                    &row,
                    jump,
                    &folder_ids,
                    &keys,
                    sessions,
                    &mut report,
                    &mut created,
                )
                .await?;
            }
            if waiting.is_empty() {
                break;
            }
            if !progressed {
                // A loop of jump hosts: save them without the link.
                for row in waiting {
                    self.save(
                        ctx,
                        source,
                        &row,
                        None,
                        &folder_ids,
                        &keys,
                        sessions,
                        &mut report,
                        &mut created,
                    )
                    .await?;
                }
                break;
            }
            pending = waiting;
        }

        self.audit_summary(ctx, source, &report).await?;
        locks::lock(&self.previews).retain(|p| p.id != request.preview_id);
        Ok(report)
    }

    /// Adds each distinct key file to the vault once. A key the vault already holds under that
    /// label is reused; another key with the same label gets "name (2)".
    async fn add_keys(
        &self,
        ctx: &Context,
        rows: &[PreviewRow],
        vault: &VaultService,
        report: &mut ImportReport,
    ) -> Result<HashMap<String, SecretId>> {
        let mut keys = HashMap::new();
        let mut failed = HashSet::new();
        for row in rows {
            let Some(file) = &row.key_file else { continue };
            if keys.contains_key(&file.path) || failed.contains(&file.path) {
                continue;
            }
            let key = match read_key_file(Path::new(&file.path)).await {
                Ok(key) => key,
                Err(err) => {
                    failed.insert(file.path.clone());
                    report.problems.push(Skipped::new(
                        row.candidate.name.clone(),
                        format!("the key file {} was not added: {err}", file.path),
                    ));
                    continue;
                }
            };
            let labels = vault.list(ctx).await?;
            let mut reuse = None;
            for meta in labels.iter().filter(|m| m.kind == SecretKind::PrivateKey) {
                if meta.label.eq_ignore_ascii_case(&file.label)
                    && vault.vault().get(ctx, meta.id).await?.expose() == key.expose()
                {
                    reuse = Some(meta.id);
                }
            }
            let id = match reuse {
                Some(id) => id,
                None => {
                    let taken: HashSet<String> = labels.iter().map(|m| m.label.to_lowercase()).collect();
                    let label = if taken.contains(&file.label.to_lowercase()) {
                        free_name(&file.label, &taken)
                    } else {
                        file.label.clone()
                    };
                    match vault.add(ctx, SecretKind::PrivateKey, &label, key).await {
                        Ok(meta) => {
                            report.keys_added += 1;
                            meta.id
                        }
                        Err(err) => {
                            failed.insert(file.path.clone());
                            report.problems.push(Skipped::new(
                                row.candidate.name.clone(),
                                format!("the key file {} was not added: {err}", file.path),
                            ));
                            continue;
                        }
                    }
                }
            };
            keys.insert(file.path.clone(), id);
        }
        Ok(keys)
    }

    #[allow(clippy::too_many_arguments)]
    async fn save(
        &self,
        ctx: &Context,
        source: ImportSource,
        row: &PreviewRow,
        jump: Option<Uuid>,
        folders: &HashMap<Vec<String>, Option<Uuid>>,
        keys: &HashMap<String, SecretId>,
        sessions: &SessionLibrary,
        report: &mut ImportReport,
        created: &mut Vec<(usize, SessionRecord)>,
    ) -> Result<()> {
        let c = &row.candidate;
        let auth = match &c.auth {
            CandidateAuth::Password => SessionAuth::Password { password_id: None },
            CandidateAuth::Agent => SessionAuth::Agent,
            CandidateAuth::KeyFile { path } => {
                let key_id = keys.get(path).copied();
                if key_id.is_none() {
                    report.problems.push(Skipped::new(
                        c.name.clone(),
                        "imported without its key: choose one in the session editor before connecting",
                    ));
                }
                SessionAuth::Key {
                    key_id,
                    passphrase_id: None,
                }
            }
        };
        if let (Some(text), None) = (&c.jump, jump) {
            report.problems.push(Skipped::new(
                c.name.clone(),
                format!("imported without its jump host '{text}', which is not among the sessions"),
            ));
        }
        let name = match &row.status {
            RowStatus::NameConflict { rename_to, .. } => rename_to.clone(),
            _ => c.name.clone(),
        };
        let input = SessionInput {
            name,
            folder_id: folders.get(&c.folder).copied().flatten(),
            host: c.host.clone(),
            port: c.port,
            username: c.username.clone(),
            auth,
            jump_session_id: jump,
            startup_command: c.startup_command.clone(),
            environment: c.environment,
            color: c.color,
            tags: c.tags.clone(),
        };
        match sessions
            .import(ctx, input, source.imported_from(), source.label())
            .await
        {
            Ok(session) => {
                report.created += 1;
                created.push((row.index, session));
            }
            Err(CoreError::InvalidInput(reason)) => report.problems.push(Skipped::new(c.name.clone(), reason)),
            Err(err) => return Err(err),
        }
        Ok(())
    }

    async fn audit_summary(&self, ctx: &Context, source: ImportSource, report: &ImportReport) -> Result<()> {
        let action = format!("Imported {} from {}", plural(report.created, "session"), source.label());
        let mut parts = Vec::new();
        if report.keys_added > 0 {
            parts.push(format!(
                "{} added to the vault",
                plural(report.keys_added, "private key")
            ));
        }
        if report.folders_created > 0 {
            parts.push(format!("{} created", plural(report.folders_created, "folder")));
        }
        if !report.problems.is_empty() {
            parts.push(plural(report.problems.len(), "problem"));
        }
        let detail = parts.join("; ");
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "sessions_imported",
                    action: &action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: (!detail.is_empty()).then_some(detail.as_str()),
                },
            )
            .await
            .map(drop)
    }
}

/// A saved session that a jump host text names: by name, or by host (and port, when given).
fn find_jump<'a>(text: &str, sessions: impl Iterator<Item = &'a SessionRecord>) -> Option<Uuid> {
    let address = split_address(text);
    let port = address.port.as_deref().and_then(|p| p.parse::<u16>().ok());
    let mut by_host = None;
    for s in sessions {
        if s.name.eq_ignore_ascii_case(text.trim()) {
            return Some(s.id);
        }
        if by_host.is_none()
            && s.host.eq_ignore_ascii_case(&address.host)
            && port.is_none_or(|p| p == s.port)
            && address.user.as_ref().is_none_or(|u| Some(u) == s.username.as_ref())
        {
            by_host = Some(s.id);
        }
    }
    by_host
}

/// The jump host is another picked row that was not saved when this pass started.
fn refers_to_row(text: &str, unsaved: &[PreviewRow], row: &PreviewRow) -> bool {
    let address = split_address(text);
    unsaved.iter().any(|other| {
        other.index != row.index
            && (other.candidate.name.eq_ignore_ascii_case(text.trim())
                || other.candidate.host.eq_ignore_ascii_case(&address.host))
    })
}

/// Reads a key file of at most [`MAX_SECRET_BYTES`] into a zeroizing secret.
async fn read_key_file(path: &Path) -> Result<SecretString> {
    let size = tokio::fs::metadata(path).await?.len();
    if size > MAX_SECRET_BYTES as u64 {
        return Err(CoreError::InvalidInput(format!(
            "it is larger than {} KB, too large for a private key",
            MAX_SECRET_BYTES / 1024
        )));
    }
    let bytes = zeroize::Zeroizing::new(tokio::fs::read(path).await?);
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(SecretString::new(text)),
        Err(_) => Err(CoreError::InvalidInput(
            "it is not a text key file (OpenSSH, PEM or PuTTY .ppk)".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_names_count_up_and_fit() {
        let taken: HashSet<String> = ["web01", "web01 (2)"].iter().map(|s| s.to_string()).collect();
        assert_eq!(free_name("web01", &taken), "web01 (3)");
        assert_eq!(free_name("db01", &taken), "db01 (2)");
        let long = "x".repeat(MAX_SESSION_NAME);
        let renamed = free_name(&long, &HashSet::new());
        assert_eq!(renamed.chars().count(), MAX_SESSION_NAME);
        assert!(renamed.ends_with(" (2)"));
    }

    #[test]
    fn sources_name_themselves() {
        assert_eq!(ImportSource::PuttyFile.imported_from(), "putty");
        assert_eq!(ImportSource::Openssh.label(), "the OpenSSH config");
        let parsed: ImportSource = serde_json::from_str(r#""puttyFile""#).unwrap();
        assert_eq!(parsed, ImportSource::PuttyFile);
    }
}
