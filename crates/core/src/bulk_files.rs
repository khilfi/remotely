//! BX-10 (0.8.0 G3): files to and from many hosts at once, BX-01's targets (saved SSH sessions; VMs through their
//! linked sessions, tags, filters, picked tabs), as one [`Command::BulkFiles`] job with a step per host.
//!
//! * **Push** sends files of this PC into one folder on every host, over SFTP on a connection the job runner makes for
//!   each host (logged in like a Compare hosts run: SS-05's host key check, never a typed password). A file that is
//!   there already is replaced only when the push says so. Each file's SHA-256 is taken as it is sent, and again on the
//!   host (its own `sha256sum`, or the file read back), so the result says whether every host got the same bytes.
//!   Medium, and High from the bulk threshold for commands on hosts (5 hosts); as any change, Prod raises it.
//! * **Fetch** brings the same file from every host into a folder of this PC, `<folder>\<session name>\<file>` (each
//!   host's own folder, with the start of its session's id when two names would be one folder on Windows; a number
//!   added to a file name that is there; never a file Git takes as its own), with the Mark of the Web, audited like
//!   any download.
//!   Low, as it changes nothing on the hosts; Prod raises it (the data leaves the host, as for a Prod VM's export).
//! * **Results** are Compare hosts' (BX-03): each host's output is the same for the same bytes (nothing host-specific
//!   in it), so hosts group by what they got or hold, and two groups diff. A fetched file's output is its SHA-256 line,
//!   then its text when it is text (a NUL byte makes it binary), so the diff shows how a config differs between hosts.
//! * Never built by the UI ([`Command::check_from_ui`]): the files come from a dialog, a drop or the Files page's local
//!   pane (by listing), the folder of this PC from there too, and both are checked first (`save_guard`, Remotely's own
//!   data folder).
//!
//! [`Command::BulkFiles`]: crate::command_bus::Command::BulkFiles
//! [`Command::check_from_ui`]: crate::command_bus::Command::check_from_ui

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::adapters::exec_output::human_bytes;
use crate::adapters::remote::{paths_script, via_sh, EntryKind, ExecSession, RemoteFiles};
use crate::bulk::{BulkRuns, Reach, ResolvedTargets, TargetPicks};
use crate::command_bus::{Command, CommandBus, SubmitOutcome, UploadFile};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::policy::Tier;
use crate::store::{NewAuditEntry, Store};
use crate::terminal::file_ops::{check_name, check_path, last_part};
use crate::terminal::file_reads::{parse_sha256sum, read_sha256};
use crate::terminal::files::{git_data_refused, is_git_name, join, local_name};

/// Files one push sends.
pub const MAX_PUSH_FILES: usize = 100;
/// A fetched file's text kept as its host's output, at most (the output's hash covers all of it).
const MAX_FETCH_TEXT: usize = 1024 * 1024;
/// Bytes read or written at a time.
const CHUNK: usize = 256 * 1024;

/// BX-10: what a [`Command::BulkFiles`](crate::command_bus::Command::BulkFiles) does on each host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkFilesSpec {
    pub op: BulkFilesOp,
    /// SS-05: a run can't ask about a host key it has never seen; without this such a host fails.
    #[serde(default)]
    pub trust_new_host_keys: bool,
    /// Seconds each host may take; `None`: no limit.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum BulkFilesOp {
    /// Files of this PC into `folder` on every host, by their names. `replace`: a file of that name there is replaced
    /// (never a folder).
    Push {
        folder: String,
        files: Vec<UploadFile>,
        #[serde(default)]
        replace: bool,
    },
    /// The file at `path` on every host, into `dest` on this PC, each host's in a folder of its own.
    Fetch { path: String, dest: String },
}

impl BulkFilesSpec {
    /// Every path and name checked as given (never resolved), and the time limit within bounds.
    pub fn validate(&self, targets: &[TargetRef]) -> Result<()> {
        let invalid = |message: String| Err(CoreError::InvalidInput(message));
        if targets.is_empty() {
            return invalid("Pick at least one host.".into());
        }
        let mut seen = std::collections::HashSet::new();
        for target in targets {
            if !matches!(target, TargetRef::Session { .. }) {
                return invalid("Files go to and from saved sessions' hosts.".into());
            }
            if !seen.insert(target.key()) {
                return invalid("A host is picked twice.".into());
            }
        }
        crate::command_bus::validate_timeout(self.timeout_secs)?;
        match &self.op {
            BulkFilesOp::Push { folder, files, .. } => {
                check_path(folder)?;
                if files.is_empty() {
                    return invalid("Choose at least one file to push.".into());
                }
                if files.len() > MAX_PUSH_FILES {
                    return invalid(format!("One push sends at most {MAX_PUSH_FILES} files."));
                }
                let mut names = std::collections::HashSet::new();
                for file in files {
                    check_name(&file.name)?;
                    if !names.insert(file.name.as_str()) {
                        return invalid(format!("Two files are named '{}'.", file.name));
                    }
                    if !Path::new(&file.local_path).is_absolute() {
                        return invalid(format!("'{}' is not a full path on this PC.", file.local_path));
                    }
                }
            }
            BulkFilesOp::Fetch { path, dest } => {
                check_path(path)?;
                if path == "/" {
                    return invalid("Choose a file, not the top folder.".into());
                }
                if is_git_name(last_part(path)) {
                    return Err(git_data_refused(path));
                }
                if !Path::new(dest).is_absolute() {
                    return invalid(format!("'{dest}' is not a full path on this PC."));
                }
            }
        }
        Ok(())
    }

    /// Whether a push may replace files on the hosts.
    pub fn replaces(&self) -> bool {
        matches!(self.op, BulkFilesOp::Push { replace: true, .. })
    }

    /// For dialogs, job lists and the audit log.
    pub fn summary(&self, hosts: usize) -> String {
        let hosts = if hosts == 1 {
            "1 host".to_owned()
        } else {
            format!("{hosts} hosts")
        };
        match &self.op {
            BulkFilesOp::Push { folder, files, replace } => {
                let size = crate::command_bus::human_size(files.iter().map(|f| f.size).sum());
                let what = match files.as_slice() {
                    [one] => format!("'{}' ({size})", one.name),
                    several => format!("{} files ({size})", several.len()),
                };
                let replacing = if *replace { ", replacing files there" } else { "" };
                format!("Push {what} to {folder} on {hosts}{replacing}")
            }
            BulkFilesOp::Fetch { path, dest } => format!("Fetch {path} from {hosts} into {dest}"),
        }
    }
}

/// BX-10: one host's part, on a connection the job runner made and checked. Returns the host's output (the same for
/// the same bytes) and whether it counts as done.
pub(crate) struct HostRun<'a> {
    pub ctx: Context,
    pub job_id: Uuid,
    pub tier: Tier,
    pub target: &'a Target,
    /// Every host of the job, so a fetch names each one's folder apart ([`host_folder`]).
    pub all_targets: &'a [Target],
    pub spec: &'a BulkFilesSpec,
    pub store: &'a Store,
}

/// BX-10: the folder of this PC a host's fetched file goes in: its session's name as Windows can hold it, with the
/// start of the session's id added when another host of the job would get the same folder (Windows compares names
/// without letter case: `web/01` and `web_01`, `Web01` and `web01`) or when the name is one Git takes as its own.
pub(crate) fn host_folder(target: &Target, all: &[Target]) -> String {
    let name = local_name(&target.name);
    let folded = name.to_lowercase();
    let shared = all
        .iter()
        .any(|other| other.target != target.target && local_name(&other.name).to_lowercase() == folded);
    if !shared && !is_git_name(&name) {
        return name;
    }
    let id = match &target.target {
        TargetRef::Session { session_id } => session_id.simple().to_string(),
        other => other.key(),
    };
    let short: String = id.chars().take(8).collect();
    local_name(&format!("{name} ({short})"))
}

/// How one host's part went: its output lines and whether everything went.
pub(crate) struct HostDone {
    pub output: String,
    pub ok: bool,
    pub failure: Option<String>,
    /// Worth a line in the job's end (the Mark of the Web not written).
    pub note: Option<String>,
}

impl HostDone {
    fn failed(why: String) -> Self {
        Self {
            output: String::new(),
            ok: false,
            failure: Some(why),
            note: None,
        }
    }
}

/// BX-10: pushes or fetches on one host.
pub(crate) async fn run_host(
    run: HostRun<'_>,
    exec: &dyn ExecSession,
    files: Arc<dyn RemoteFiles>,
) -> Result<HostDone> {
    match &run.spec.op {
        BulkFilesOp::Push {
            folder,
            files: sent,
            replace,
        } => push(&run, exec, files.as_ref(), folder, sent, *replace).await,
        BulkFilesOp::Fetch { path, dest } => fetch(&run, files.as_ref(), path, Path::new(dest)).await,
    }
}

async fn audit(run: &HostRun<'_>, event: &str, action: &str, detail: &str) -> Result<()> {
    run.store
        .append_audit(
            &run.ctx,
            NewAuditEntry {
                event,
                action,
                tier: Some(run.tier),
                job_id: Some(run.job_id),
                targets: std::slice::from_ref(run.target),
                approval: None,
                result: None,
                detail: Some(detail),
            },
        )
        .await
        .map(drop)
}

/// The host's SHA-256 of a file: its own `sha256sum`, else read back.
async fn host_sha256(exec: &dyn ExecSession, files: &dyn RemoteFiles, path: &str) -> Result<String> {
    if let Ok(done) = exec.run(&via_sh(&paths_script("sha256sum", &[path])), 4096).await {
        if done.exit_code == Some(0) {
            if let Some(hash) = parse_sha256sum(&done.output.stdout) {
                return Ok(hash);
            }
        }
    }
    read_sha256(files, path).await
}

async fn push(
    run: &HostRun<'_>,
    exec: &dyn ExecSession,
    files: &dyn RemoteFiles,
    folder: &str,
    sent: &[UploadFile],
    replace: bool,
) -> Result<HostDone> {
    match files.stat(folder).await? {
        Some(entry) if entry.kind == EntryKind::Folder => {}
        Some(_) => return Ok(HostDone::failed(format!("{folder} is not a folder on this host"))),
        None => return Ok(HostDone::failed(format!("{folder} is not on this host"))),
    }
    let mut lines = Vec::new();
    let mut failed = Vec::new();
    for file in sent {
        let path = join(folder, &file.name);
        match push_one(run, exec, files, &path, file, replace).await {
            Ok(line) => lines.push(line),
            Err(err) => {
                lines.push(format!("{}  not sent: {}", file.name, plain_reason(&err)));
                failed.push(format!("{}: {err}", file.name));
            }
        }
    }
    Ok(HostDone {
        output: lines.join("\n"),
        ok: failed.is_empty(),
        failure: match failed.as_slice() {
            [] => None,
            [one] => Some(one.clone()),
            several => Some(format!("{} files failed: {}", several.len(), several.join("; "))),
        },
        note: None,
    })
}

/// A reason without the host's own words in it, so hosts that failed alike group together.
fn plain_reason(err: &CoreError) -> &'static str {
    match err {
        CoreError::RemoteFileExists { .. } | CoreError::RemotePathTaken { .. } => "a file of that name is there",
        CoreError::RemotePermissionDenied { .. } => "permission denied",
        CoreError::RemoteNotFound { .. } => "its folder is gone",
        CoreError::InvalidInput(_) => "refused",
        _ => "it failed",
    }
}

async fn push_one(
    run: &HostRun<'_>,
    exec: &dyn ExecSession,
    files: &dyn RemoteFiles,
    path: &str,
    file: &UploadFile,
    replace: bool,
) -> Result<String> {
    let there = files.lstat(path).await?;
    match &there {
        Some(entry) if entry.kind == EntryKind::Folder && !entry.link => {
            return Err(CoreError::InvalidInput(format!(
                "{path} is a folder on this host, so a file can't replace it"
            )))
        }
        Some(_) if !replace => return Err(CoreError::RemotePathTaken { path: path.to_owned() }),
        _ => {}
    }
    let mut local = tokio::fs::File::open(&file.local_path)
        .await
        .map_err(|err| CoreError::InvalidInput(format!("'{}' can't be read on this PC: {err}", file.local_path)))?;
    let mut writer = files.write(path, there.is_some()).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    let pumped: Result<()> = async {
        use tokio::io::AsyncReadExt;
        loop {
            let n = local.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            writer.write_all(&buf[..n]).await?;
            size += n as u64;
        }
        Ok(())
    }
    .await;
    if let Err(err) = pumped {
        let _ = writer.abort().await;
        return Err(err);
    }
    let written = writer.finish().await?;
    let sent = hex::encode(hasher.finalize());
    let on_host = host_sha256(exec, files, path).await?;
    let matches = on_host == sent;
    let replaced = if there.is_some() {
        ", replacing the file there"
    } else {
        ""
    };
    let note = written.note();
    let note = if note.is_empty() {
        String::new()
    } else {
        format!("; {note}")
    };
    audit(
        run,
        "file_uploaded",
        &format!("Pushed '{}' to {} on '{}'", file.name, path, run.target.name),
        &format!("{size} bytes sent, SHA-256 {sent}; the host's copy {on_host}{replaced}{note}"),
    )
    .await?;
    if !matches {
        return Err(CoreError::InvalidInput(format!(
            "the host's copy of {} has another SHA-256 ({on_host}) than what was sent ({sent})",
            file.name
        )));
    }
    Ok(format!(
        "{}  {}  SHA-256 {sent}  the host's copy matches",
        file.name,
        human_bytes(usize::try_from(size).unwrap_or(usize::MAX))
    ))
}

async fn fetch(run: &HostRun<'_>, files: &dyn RemoteFiles, path: &str, dest: &Path) -> Result<HostDone> {
    let entry = match files.stat(path).await? {
        Some(entry) => entry,
        None => return Ok(HostDone::failed(format!("{path} is not on this host"))),
    };
    if entry.kind != EntryKind::File {
        return Ok(HostDone::failed(format!("{path} is not a regular file on this host")));
    }
    // Each host's file in a folder of its own, named after its session (apart from any other host's).
    let folder = dest.join(host_folder(run.target, run.all_targets));
    tokio::fs::create_dir_all(&folder).await?;
    let (saved_at, mut file) = crate::terminal::files::claim_file(&folder, last_part(path)).await?;
    let mut cleanup = RemoveOnDrop(Some(saved_at.clone()));
    let mut reader = files.read(path).await?;
    let mut hasher = Sha256::new();
    let mut kept: Vec<u8> = Vec::new();
    let mut binary = false;
    let mut size = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        file.write_all(chunk).await?;
        size += n as u64;
        binary |= chunk.contains(&0);
        if !binary && kept.len() < MAX_FETCH_TEXT {
            let room = MAX_FETCH_TEXT - kept.len();
            kept.extend_from_slice(&chunk[..n.min(room)]);
        }
    }
    file.flush().await?;
    file.sync_all().await?;
    drop(file);
    drop(reader);
    let mark = crate::terminal::files::mark_downloaded(&saved_at).await;
    cleanup.0 = None;
    let sha = hex::encode(hasher.finalize());
    let shown = saved_at.display().to_string();
    audit(
        run,
        "file_downloaded",
        &format!("Fetched '{}' from '{}'", last_part(path), run.target.name),
        &format!("{path}, {size} bytes, SHA-256 {sha}; saved to {shown}"),
    )
    .await?;
    let mut output = format!(
        "SHA-256 {sha}  {}",
        human_bytes(usize::try_from(size).unwrap_or(usize::MAX))
    );
    if binary {
        output.push_str("  (binary: not shown)");
    } else if !kept.is_empty() {
        let (text, _, _) = crate::terminal::file_reads::preview_text(&kept);
        if let Some(text) = text {
            output.push('\n');
            output.push_str(&text);
        }
        if size as usize > MAX_FETCH_TEXT {
            output.push_str("\n(only the first 1 MB is shown and compared)");
        }
    }
    Ok(HostDone {
        output,
        ok: true,
        failure: None,
        note: mark.map(|why| format!("'{}': {why}", run.target.name)),
    })
}

/// Deletes a half-written fetch unless it was finished.
struct RemoveOnDrop(Option<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// BX-10: what submitting a push or fetch gave: the hosts it goes to (BX-01's resolution, with its notes) and the
/// bus's answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkFilesStart {
    pub resolved: ResolvedTargets,
    pub outcome: SubmitOutcome,
}

/// BX-10: the service the window's many-hosts transfers go through (`Core.bulk_files`).
pub struct BulkFiles {
    workspace: crate::workspaces::Current,
    bus: Arc<CommandBus>,
    bulk: BulkRuns,
    protected: Arc<dyn Fn() -> Vec<PathBuf> + Send + Sync>,
}

impl BulkFiles {
    pub fn new(
        workspace: crate::workspaces::Current,
        bus: Arc<CommandBus>,
        bulk: BulkRuns,
        protected: Arc<dyn Fn() -> Vec<PathBuf> + Send + Sync>,
    ) -> Self {
        Self {
            workspace,
            bus,
            bulk,
            protected,
        }
    }

    async fn targets(&self, ctx: &Context, picks: &TargetPicks) -> Result<(ResolvedTargets, Vec<TargetRef>)> {
        let resolved = self.bulk.resolve_reaching(ctx, picks, Reach::Ssh).await?;
        if resolved.hosts.is_empty() {
            return Err(CoreError::InvalidInput(
                "None of what is picked reaches a host over SSH; pick sessions, or VMs with a linked session.".into(),
            ));
        }
        let targets = resolved
            .hosts
            .iter()
            .map(|h| TargetRef::Session {
                session_id: h.session_id,
            })
            .collect();
        Ok((resolved, targets))
    }

    /// BX-10: pushes files of this PC (picked in a dialog, dropped, or picked in the local pane) into `folder` on every
    /// picked host. Folders are refused: a push sends files.
    pub async fn push(
        &self,
        picks: &TargetPicks,
        paths: Vec<PathBuf>,
        folder: &str,
        replace: bool,
        trust_new_host_keys: bool,
    ) -> Result<BulkFilesStart> {
        let ctx = self.workspace.get();
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let meta = std::fs::metadata(&path)
                .map_err(|err| CoreError::InvalidInput(format!("'{}' can't be read: {err}", path.display())))?;
            if !meta.is_file() {
                return Err(CoreError::InvalidInput(format!(
                    "'{}' is a folder; a push sends files.",
                    path.display()
                )));
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            files.push(UploadFile {
                local_path: path.display().to_string(),
                name,
                size: meta.len(),
                replace,
                modified: meta
                    .modified()
                    .ok()
                    .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            });
        }
        let spec = BulkFilesSpec {
            op: BulkFilesOp::Push {
                folder: folder.trim().to_owned(),
                files,
                replace,
            },
            trust_new_host_keys,
            timeout_secs: None,
        };
        self.submit(&ctx, picks, spec).await
    }

    /// BX-10: fetches `path` from every picked host into `dest` on this PC (a folder the shell chose or the local pane
    /// showed), checked like any download's: never a Git working tree, never Remotely's own data folder.
    pub async fn fetch(
        &self,
        picks: &TargetPicks,
        path: &str,
        dest: &Path,
        trust_new_host_keys: bool,
    ) -> Result<BulkFilesStart> {
        let ctx = self.workspace.get();
        crate::save_guard::refuse_repository_folder(dest, crate::save_guard::Saved::Download)?;
        if !dest.is_dir() {
            return Err(CoreError::InvalidInput(format!("{} is not a folder.", dest.display())));
        }
        let real = crate::toolbox::file_server::final_place(dest).unwrap_or_else(|| dest.to_owned());
        if crate::local_files::lands_in(&real, &(self.protected)()) {
            return Err(CoreError::InvalidInput(format!(
                "{} is Remotely's own data folder, so nothing is fetched into it. Choose another folder.",
                dest.display()
            )));
        }
        let spec = BulkFilesSpec {
            op: BulkFilesOp::Fetch {
                path: path.trim().to_owned(),
                dest: dest.display().to_string(),
            },
            trust_new_host_keys,
            timeout_secs: None,
        };
        self.submit(&ctx, picks, spec).await
    }

    async fn submit(&self, ctx: &Context, picks: &TargetPicks, spec: BulkFilesSpec) -> Result<BulkFilesStart> {
        let (resolved, targets) = self.targets(ctx, picks).await?;
        spec.validate(&targets)?;
        let command = Command::BulkFiles {
            targets,
            spec: Box::new(spec),
        };
        let outcome = self.bus.submit(ctx, command).await?;
        Ok(BulkFilesStart { resolved, outcome })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> TargetRef {
        TargetRef::Session {
            session_id: Uuid::new_v4(),
        }
    }

    fn push(files: Vec<UploadFile>) -> BulkFilesSpec {
        BulkFilesSpec {
            op: BulkFilesOp::Push {
                folder: "/etc/app".into(),
                files,
                replace: false,
            },
            trust_new_host_keys: false,
            timeout_secs: None,
        }
    }

    fn file(name: &str) -> UploadFile {
        UploadFile {
            local_path: format!(r"C:\Users\alice\{name}"),
            name: name.into(),
            size: 10,
            replace: false,
            modified: None,
        }
    }

    #[test]
    fn pushes_and_fetches_are_checked_as_given() {
        let targets = vec![session(), session()];
        assert!(push(vec![file("app.conf")]).validate(&targets).is_ok());
        assert!(push(vec![]).validate(&targets).is_err());
        assert!(push(vec![file("../x")]).validate(&targets).is_err());
        assert!(push(vec![file("a"), file("a")]).validate(&targets).is_err());
        let mut relative = file("b");
        relative.local_path = "b".into();
        assert!(push(vec![relative]).validate(&targets).is_err());
        let twice = vec![targets[0].clone(), targets[0].clone()];
        assert!(push(vec![file("a")]).validate(&twice).is_err());
        assert!(push(vec![file("a")]).validate(&[TargetRef::App]).is_err());
        let fetch = |path: &str, dest: &str| BulkFilesSpec {
            op: BulkFilesOp::Fetch {
                path: path.into(),
                dest: dest.into(),
            },
            trust_new_host_keys: false,
            timeout_secs: None,
        };
        assert!(fetch("/etc/ssh/sshd_config", r"C:\Users\alice\Downloads")
            .validate(&targets)
            .is_ok());
        for bad in ["/", "etc/hosts", "/etc/../shadow", "/etc/a\u{202E}b"] {
            assert!(fetch(bad, r"C:\x").validate(&targets).is_err(), "{bad}");
        }
        assert!(fetch("/etc/hosts", "Downloads").validate(&targets).is_err());
        // A file Git would take as its own data on this PC, as Windows saves the name.
        for git in ["/srv/app/.git", "/srv/app/.git.", "/srv/app/.git ", "/srv/app/.GIT."] {
            assert!(fetch(git, r"C:\x").validate(&targets).is_err(), "{git:?}");
        }
        assert!(fetch("/srv/app/.gitignore", r"C:\x").validate(&targets).is_ok());
    }

    #[test]
    fn each_host_fetches_into_a_folder_of_its_own() {
        let host = |name: &str| Target {
            target: session(),
            name: name.into(),
            environment: crate::domain::Environment::Lab,
            protected: false,
        };
        let short = |t: &Target| match &t.target {
            TargetRef::Session { session_id } => session_id.simple().to_string()[..8].to_owned(),
            _ => unreachable!(),
        };
        let (a, b, c, d) = (host("web/01"), host("web_01"), host("Db01"), host("db01"));
        let solo = host("web02");
        let git = host(".git.");
        let all = vec![a.clone(), b.clone(), c.clone(), d.clone(), solo.clone(), git.clone()];
        assert_eq!(host_folder(&solo, &all), "web02");
        assert_eq!(host_folder(&a, &all), format!("web_01 ({})", short(&a)));
        assert_eq!(host_folder(&b, &all), format!("web_01 ({})", short(&b)));
        assert_eq!(host_folder(&c, &all), format!("Db01 ({})", short(&c)));
        assert_eq!(host_folder(&d, &all), format!("db01 ({})", short(&d)));
        let named = host_folder(&git, &all);
        assert_eq!(named, format!(".git ({})", short(&git)));
        assert!(!is_git_name(&named));
        // Alone in its job, a name keeps its plain folder.
        assert_eq!(host_folder(&a, std::slice::from_ref(&a)), "web_01");
    }

    #[test]
    fn summaries_name_what_goes_where() {
        assert_eq!(
            push(vec![file("app.conf")]).summary(3),
            "Push 'app.conf' (10 B) to /etc/app on 3 hosts"
        );
        let fetch = BulkFilesSpec {
            op: BulkFilesOp::Fetch {
                path: "/etc/hosts".into(),
                dest: r"C:\Users\alice\Downloads".into(),
            },
            trust_new_host_keys: false,
            timeout_secs: None,
        };
        assert_eq!(
            fetch.summary(1),
            r"Fetch /etc/hosts from 1 host into C:\Users\alice\Downloads"
        );
    }
}
