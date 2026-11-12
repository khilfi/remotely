//! SS-14 (0.8.0 G2): changes to a terminal's host's files, each a [`Command::FileOp`] on the command bus: new folders
//! and empty files, rename, move, copy within the host, delete (a file, a link, an empty folder, or a folder with
//! what is in it), permissions and owner. Reads (listing, downloads) stay off the bus, as before.
//!
//! * **One job per user action, a step per path.** Each path is a [`TargetRef::RemotePath`] by its place in the
//!   operation ([`FileOpSpec::targets`]); the path itself stays in the spec, so the audit log's targets name it only in
//!   the target's name, which is redacted like other free text, and the journal keeps the spec with its paths redacted
//!   ([`FileOpSpec::for_journal`]). A retry runs the failed steps again ([`FileOpSpec::only`]).
//! * **Tiers** (`docs/plan-0.8.md`, "Approval tiers"): a new folder or file, and a rename or move that replaces
//!   nothing, are Low; one that replaces, permissions or owner, a copy, and deleting a file or an empty folder are
//!   Medium; deleting a folder with what is in it is High. As root, one tier higher; Prod raises it one more.
//! * **Nothing the window sends is trusted.** Every path is checked as given ([`check_path`]), never resolved: no
//!   `.` or `..` part, no empty part, no control or invisible formatting character (A8: what the approval shows is
//!   what changes), no `/` itself; names are one part ([`check_name`]); a folder can't move or be copied into itself;
//!   a recursive delete never takes `/` or a top-level folder. The job runner checks again before each step
//!   ([`FileOpSpec::validate`]), and looks at what is there right before it changes it.
//! * **How.** Over the terminal's own SFTP channel (as the login user), or with `as_root` over its root SFTP server
//!   ([`super::root_files`]). A copy is `cp -a` on an exec channel of the same connection (with sudo as root),
//!   rated by the shell rules as well as by its own tier. A recursive delete walks the folder over SFTP and never
//!   follows a link: a link is deleted as a link.

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::files::{join, parent};
use super::{audit_entry, quoted_name, Control, Terminals};
use crate::adapters::remote::{sh_quote, EntryKind, RemoteFiles, SetAttrs};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::policy::Tier;
use crate::untrusted::is_format_char;

/// The most paths one operation takes.
pub const MAX_FILE_OP_PATHS: usize = 1000;
/// Linux's longest path and name.
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_NAME_BYTES: usize = 255;
/// A recursive delete stops after this many files and folders (A9: a folder that never ends).
pub const MAX_DELETE_ENTRIES: u64 = 1_000_000;
/// What `cp -a` may print before it counts as failed.
const MAX_COPY_OUTPUT: usize = 64 * 1024;

/// SS-14: one user action on a host's files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileOpSpec {
    /// The open terminal whose connection it goes through.
    pub terminal_id: Uuid,
    pub op: FileOp,
    /// Through the terminal's root SFTP server (root browsing): every step runs as root.
    #[serde(default)]
    pub as_root: bool,
}

/// SS-14: what changes. Paths are the host's: absolute and `/`-separated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum FileOp {
    /// A new, empty folder.
    NewFolder { path: String },
    /// A new, empty file.
    NewFile { path: String },
    /// One file or folder renamed in its own folder. `replace`: a file of the new name is replaced (never a folder).
    Rename {
        path: String,
        name: String,
        #[serde(default)]
        replace: bool,
    },
    /// Files and folders moved into another folder, keeping their names. `replace`: files of those names there are
    /// replaced (never folders).
    Move {
        paths: Vec<String>,
        into: String,
        #[serde(default)]
        replace: bool,
    },
    /// Copied into another folder with `cp -a` (modes, times and links as they are; owners where the user may). Never
    /// replaces anything.
    Copy { paths: Vec<String>, into: String },
    /// Files, links and empty folders deleted; with `recursive`, folders with everything in them.
    Delete {
        paths: Vec<String>,
        #[serde(default)]
        recursive: bool,
    },
    /// Permission bits set, on each path itself (not what is in a folder).
    Mode { paths: Vec<String>, mode: u32 },
    /// Owner and group set by number, on each path itself. One of them may stay as it is.
    Owner {
        paths: Vec<String>,
        #[serde(default)]
        uid: Option<u32>,
        #[serde(default)]
        gid: Option<u32>,
    },
}

impl FileOp {
    /// The paths it changes, one step each, in order.
    pub fn paths(&self) -> Vec<&str> {
        match self {
            FileOp::NewFolder { path } | FileOp::NewFile { path } | FileOp::Rename { path, .. } => vec![path.as_str()],
            FileOp::Move { paths, .. }
            | FileOp::Copy { paths, .. }
            | FileOp::Delete { paths, .. }
            | FileOp::Mode { paths, .. }
            | FileOp::Owner { paths, .. } => paths.iter().map(String::as_str).collect(),
        }
    }

    fn paths_mut(&mut self) -> Vec<&mut String> {
        match self {
            FileOp::NewFolder { path } | FileOp::NewFile { path } => vec![path],
            FileOp::Rename { path, name, .. } => vec![path, name],
            FileOp::Move { paths, into, .. } | FileOp::Copy { paths, into } => {
                let mut all: Vec<&mut String> = paths.iter_mut().collect();
                all.push(into);
                all
            }
            FileOp::Delete { paths, .. } | FileOp::Mode { paths, .. } | FileOp::Owner { paths, .. } => {
                paths.iter_mut().collect()
            }
        }
    }

    /// Where a step's path ends up: the new name of a rename, the path in the folder moved or copied into.
    pub fn destination(&self, path: &str) -> Option<String> {
        match self {
            FileOp::Rename { name, .. } => Some(join(&parent(path).unwrap_or_else(|| "/".into()), name)),
            FileOp::Move { into, .. } | FileOp::Copy { into, .. } => Some(join(into, last_part(path))),
            _ => None,
        }
    }

    /// The folder it moves or copies into, if any.
    pub fn into_folder(&self) -> Option<&str> {
        match self {
            FileOp::Move { into, .. } | FileOp::Copy { into, .. } => Some(into),
            _ => None,
        }
    }
}

/// The last part of an absolute path: `b` for `/a/b`.
pub fn last_part(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// SS-14: a path the window sent: absolute, at most [`MAX_PATH_BYTES`], every part a plain name. Never resolved, so
/// `..` tricks are refused instead of followed. `/` itself passes; the operations that can't take it say so.
pub fn check_path(path: &str) -> Result<()> {
    let invalid = |why: &str| {
        Err(CoreError::InvalidInput(format!(
            "'{}' can't be changed on the host: {why}.",
            shown(path)
        )))
    };
    if !path.starts_with('/') {
        return invalid("it is not a full path (it must start with /)");
    }
    if path.len() > MAX_PATH_BYTES {
        return invalid("it is longer than any path on Linux");
    }
    if path == "/" {
        return Ok(());
    }
    if path.ends_with('/') {
        return invalid("it ends with /");
    }
    for part in path[1..].split('/') {
        if let Err(why) = name_problem(part) {
            return invalid(why);
        }
    }
    Ok(())
}

/// SS-14: a new name: one part of a path, as [`check_path`] takes them.
pub fn check_name(name: &str) -> Result<()> {
    name_problem(name)
        .map_err(|why| CoreError::InvalidInput(format!("'{}' can't be a name on the host: {why}.", shown(name))))
}

fn name_problem(part: &str) -> std::result::Result<(), &'static str> {
    if part.is_empty() {
        return Err("it has an empty part (//)");
    }
    if part == "." || part == ".." {
        return Err("it has a . or .. part");
    }
    if part.contains('/') {
        return Err("it holds a /");
    }
    if part.len() > MAX_NAME_BYTES {
        return Err("a part is longer than 255 bytes");
    }
    // A8: what the approval dialog and the audit log show must be what changes on the host.
    if part
        .chars()
        .any(|c| c.is_control() || is_format_char(c) || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err("it holds a control or invisible formatting character; rename it in the terminal");
    }
    Ok(())
}

/// A path for a message: without control or formatting characters, and not too long.
fn shown(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() || is_format_char(c) { '?' } else { c })
        .take(300)
        .collect()
}

/// `inner` is `outer` or inside it.
fn within(inner: &str, outer: &str) -> bool {
    inner == outer || outer == "/" || inner.starts_with(&format!("{outer}/"))
}

impl FileOpSpec {
    /// One [`TargetRef::RemotePath`] per path, in order.
    pub fn targets(&self) -> Vec<TargetRef> {
        (0..self.op.paths().len())
            .map(|step| TargetRef::RemotePath {
                terminal_id: self.terminal_id,
                session_id: None,
                step,
            })
            .collect()
    }

    /// The path of a step.
    pub fn path(&self, step: usize) -> Option<&str> {
        self.op.paths().get(step).copied()
    }

    /// Everything [`check_path`] and [`check_name`] check, and what each operation can't take.
    pub fn validate(&self) -> Result<()> {
        let invalid = |message: String| Err(CoreError::InvalidInput(message));
        let paths = self.op.paths();
        if paths.is_empty() {
            return invalid("Choose at least one file or folder.".into());
        }
        if paths.len() > MAX_FILE_OP_PATHS {
            return invalid(format!(
                "One change takes at most {MAX_FILE_OP_PATHS} files and folders."
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for path in &paths {
            check_path(path)?;
            if *path == "/" {
                return invalid("The top folder (/) can't be changed.".into());
            }
            if !seen.insert(*path) {
                return invalid(format!("'{}' is listed twice.", shown(path)));
            }
        }
        match &self.op {
            FileOp::Rename { path, name, .. } => {
                check_name(name)?;
                if last_part(path) == name {
                    return invalid(format!("'{}' has that name already.", shown(name)));
                }
            }
            FileOp::Move { paths, into, .. } | FileOp::Copy { paths, into } => {
                check_path(into)?;
                let mut names = std::collections::HashSet::new();
                for path in paths {
                    if within(into, path) {
                        return invalid(format!("'{}' can't go into itself or a folder inside it.", shown(path)));
                    }
                    if parent(path).as_deref() == Some(into.as_str()) {
                        return invalid(format!("'{}' is in {} already.", shown(path), shown(into)));
                    }
                    if !names.insert(last_part(path)) {
                        return invalid(format!(
                            "Two of them are named '{}', and one folder can't hold both.",
                            shown(last_part(path))
                        ));
                    }
                }
            }
            FileOp::Delete { paths, recursive: true } => {
                for path in paths {
                    // A top-level folder (/etc, /home, /usr) with everything in it is too much for one click.
                    if !path[1..].contains('/') {
                        return invalid(format!(
                            "{} is a top-level folder, so Remotely won't delete it with what is in it. Delete what is \
                             in it instead.",
                            shown(path)
                        ));
                    }
                }
            }
            FileOp::Mode { mode, .. } => {
                if *mode > 0o7777 {
                    return invalid(format!("{mode:o} is not a permission mode (at most 7777)."));
                }
            }
            FileOp::Owner { uid, gid, .. } => {
                if uid.is_none() && gid.is_none() {
                    return invalid("Choose an owner, a group or both.".into());
                }
            }
            FileOp::NewFolder { .. } | FileOp::NewFile { .. } | FileOp::Delete { .. } => {}
        }
        Ok(())
    }

    /// BX-04: the same operation for the steps among `targets` (a retry of the failed ones), numbered again from 0.
    /// `None` when none of them is one of its steps.
    pub fn only(&self, targets: &[TargetRef]) -> Option<FileOpSpec> {
        let steps: std::collections::BTreeSet<usize> = targets
            .iter()
            .filter_map(|t| match t {
                TargetRef::RemotePath { terminal_id, step, .. } if *terminal_id == self.terminal_id => Some(*step),
                _ => None,
            })
            .collect();
        if steps.is_empty() {
            return None;
        }
        let keep = |paths: &[String]| -> Vec<String> {
            paths
                .iter()
                .enumerate()
                .filter(|(i, _)| steps.contains(i))
                .map(|(_, p)| p.clone())
                .collect()
        };
        let op = match &self.op {
            FileOp::NewFolder { .. } | FileOp::NewFile { .. } | FileOp::Rename { .. } => self.op.clone(),
            FileOp::Move { paths, into, replace } => FileOp::Move {
                paths: keep(paths),
                into: into.clone(),
                replace: *replace,
            },
            FileOp::Copy { paths, into } => FileOp::Copy {
                paths: keep(paths),
                into: into.clone(),
            },
            FileOp::Delete { paths, recursive } => FileOp::Delete {
                paths: keep(paths),
                recursive: *recursive,
            },
            FileOp::Mode { paths, mode } => FileOp::Mode {
                paths: keep(paths),
                mode: *mode,
            },
            FileOp::Owner { paths, uid, gid } => FileOp::Owner {
                paths: keep(paths),
                uid: *uid,
                gid: *gid,
            },
        };
        Some(FileOpSpec { op, ..self.clone() })
    }

    /// BX-02: the spec as the journal keeps it, every path and name through [`redact_secrets`]; whether any changed.
    pub fn for_journal(&self) -> (FileOpSpec, bool) {
        let mut kept = self.clone();
        let mut changed = false;
        for text in kept.op.paths_mut() {
            let (redacted, was) = redact_secrets(text);
            if was {
                *text = redacted;
                changed = true;
            }
        }
        (kept, changed)
    }

    /// The `cp -a` lines a copy runs, one per path (the shell rules rate them). `None` for every other operation.
    pub fn copy_script(&self) -> Option<String> {
        let FileOp::Copy { paths, .. } = &self.op else {
            return None;
        };
        let lines: Vec<String> = paths
            .iter()
            .filter_map(|p| self.op.destination(p).map(|to| copy_line(p, &to)))
            .collect();
        Some(lines.join("\n"))
    }

    /// For dialogs, job lists and the audit log (redacted again when it is stored).
    pub fn summary(&self) -> String {
        let name = |path: &str| format!("'{}'", shown(last_part(path)));
        let items = |paths: &[String]| match paths {
            [one] => name(one),
            several => format!("{} items", several.len()),
        };
        let folder_of = |paths: &[String]| {
            paths
                .first()
                .and_then(|p| parent(p))
                .map(|f| shown(&f))
                .unwrap_or_else(|| "/".into())
        };
        let text = match &self.op {
            FileOp::NewFolder { path } => format!("Make the folder {}", shown(path)),
            FileOp::NewFile { path } => format!("Make the empty file {}", shown(path)),
            FileOp::Rename {
                path,
                name: new,
                replace,
            } => format!(
                "Rename {} to '{}'{}",
                shown(path),
                shown(new),
                if *replace { ", replacing the file there" } else { "" }
            ),
            FileOp::Move { paths, into, replace } => format!(
                "Move {} from {} to {}{}",
                items(paths),
                folder_of(paths),
                shown(into),
                if *replace { ", replacing files there" } else { "" }
            ),
            FileOp::Copy { paths, into } => {
                format!("Copy {} from {} to {}", items(paths), folder_of(paths), shown(into))
            }
            FileOp::Delete { paths, recursive } => format!(
                "Delete {} in {}{}",
                items(paths),
                folder_of(paths),
                if *recursive { ", with everything in them" } else { "" }
            ),
            FileOp::Mode { paths, mode } => format!(
                "Set the permissions of {} in {} to {mode:04o}",
                items(paths),
                folder_of(paths)
            ),
            FileOp::Owner { paths, uid, gid } => format!(
                "Set the {} of {} in {} to {}",
                match (uid, gid) {
                    (Some(_), Some(_)) => "owner and group",
                    (Some(_), None) => "owner",
                    _ => "group",
                },
                items(paths),
                folder_of(paths),
                owner_text(*uid, *gid)
            ),
        };
        if self.as_root {
            format!("{text}, as root")
        } else {
            text
        }
    }
}

/// `1000:33`, `1000`, `:33`.
fn owner_text(uid: Option<u32>, gid: Option<u32>) -> String {
    match (uid, gid) {
        (Some(u), Some(g)) => format!("{u}:{g}"),
        (Some(u), None) => u.to_string(),
        (None, Some(g)) => format!(":{g}"),
        (None, None) => String::new(),
    }
}

/// One copy as the shell runs it: never reads a path as an option.
pub fn copy_line(from: &str, to: &str) -> String {
    format!("cp -a -- {} {}", sh_quote(from), sh_quote(to))
}

/// SS-14: a file operation as the approval dialog shows it, besides its targets (each path).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileOpDetails {
    /// `newFolder`, `rename`, `delete`...: the operation's kind.
    pub kind: &'static str,
    /// Where they go (a move or a copy), or the new name (a rename).
    pub into: Option<String>,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub replace: bool,
    pub recursive: bool,
    pub as_root: bool,
    /// A copy's `cp -a` lines.
    pub script: Option<String>,
}

impl FileOpDetails {
    pub fn of(spec: &FileOpSpec) -> Self {
        let (kind, into, replace, recursive) = match &spec.op {
            FileOp::NewFolder { .. } => ("newFolder", None, false, false),
            FileOp::NewFile { .. } => ("newFile", None, false, false),
            FileOp::Rename { name, replace, .. } => ("rename", Some(name.clone()), *replace, false),
            FileOp::Move { into, replace, .. } => ("move", Some(into.clone()), *replace, false),
            FileOp::Copy { into, .. } => ("copy", Some(into.clone()), false, false),
            FileOp::Delete { recursive, .. } => ("delete", None, false, *recursive),
            FileOp::Mode { .. } => ("mode", None, false, false),
            FileOp::Owner { .. } => ("owner", None, false, false),
        };
        Self {
            kind,
            into,
            mode: match &spec.op {
                FileOp::Mode { mode, .. } => Some(format!("{mode:04o}")),
                _ => None,
            },
            owner: match &spec.op {
                FileOp::Owner { uid, gid, .. } => Some(owner_text(*uid, *gid)),
                _ => None,
            },
            replace,
            recursive,
            as_root: spec.as_root,
            script: spec.copy_script(),
        }
    }
}

/// SS-14: one step of a [`Command::FileOp`] the job runner hands to the terminal it goes through.
///
/// [`Command::FileOp`]: crate::command_bus::Command::FileOp
pub struct FileOpRun<'a> {
    pub ctx: Context,
    pub job_id: Uuid,
    pub tier: Tier,
    pub target: &'a Target,
    pub spec: &'a FileOpSpec,
    pub step: usize,
}

/// What a recursive delete took.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Deleted {
    files: u64,
    folders: u64,
}

impl Deleted {
    fn note(self) -> String {
        let count = |n: u64, one: &str, many: &str| {
            if n == 1 {
                format!("1 {one}")
            } else {
                format!("{n} {many}")
            }
        };
        format!(
            "with {} and {} in it",
            count(self.files, "file", "files"),
            count(self.folders.saturating_sub(1), "folder", "folders")
        )
    }
}

impl Terminals {
    /// SS-14: the files a step goes through: the login's SFTP, or the root SFTP server for `as_root`.
    pub(super) fn files_for(
        &self,
        id: Uuid,
        as_root: bool,
    ) -> Result<(std::sync::Arc<Control>, std::sync::Arc<dyn RemoteFiles>)> {
        if as_root {
            let control = self
                .control(id)
                .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id} has closed")))?;
            let root = crate::locks::lock(&control.root)
                .as_ref()
                .map(|r| std::sync::Arc::clone(&r.files));
            let root = root.ok_or_else(|| {
                CoreError::InvalidInput(format!(
                    "{} is not browsing as root (any more), so nothing was changed as root. Browse as root again.",
                    quoted_name(&control)
                ))
            })?;
            return Ok((control, root));
        }
        self.live(id)
    }

    /// SS-14: the job runner's half of [`crate::command_bus::Command::FileOp`]: one step, audited when it is done.
    /// Returns what the job's audit entry says about it.
    pub(crate) async fn run_file_op(&self, run: FileOpRun<'_>, cancel: &CancellationToken) -> Result<String> {
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        // Checked again here: the job runs what the bus approved, never anything else.
        run.spec.validate()?;
        let path = run
            .spec
            .path(run.step)
            .ok_or_else(|| CoreError::InvalidInput(format!("step {} is not part of this change", run.step)))?
            .to_owned();
        let (control, files) = self.files_for(run.spec.terminal_id, run.spec.as_root)?;
        let (action, note) = self.file_op_step(&control, &files, run.spec, &path, cancel).await?;
        let root = if run.spec.as_root { " as root" } else { "" };
        let action = format!("{action} on {}{root}", quoted_name(&control));
        audit_entry(
            &self.inner.store,
            &run.ctx,
            "file_changed",
            &action,
            Some(run.tier),
            Some(run.job_id),
            std::slice::from_ref(run.target),
            &note,
        )
        .await?;
        Ok(note)
    }

    /// One step's work: (the audit entry's action, its note).
    async fn file_op_step(
        &self,
        control: &Control,
        files: &std::sync::Arc<dyn RemoteFiles>,
        spec: &FileOpSpec,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<(String, String)> {
        let p = shown(path);
        match &spec.op {
            FileOp::NewFolder { .. } => {
                files.make_folder(path).await?;
                Ok((format!("Made the folder {p}"), "made".into()))
            }
            FileOp::NewFile { .. } => {
                if files.lstat(path).await?.is_some() {
                    return Err(CoreError::RemotePathTaken { path: path.to_owned() });
                }
                let writer = files.write(path, false).await?;
                writer.finish().await?;
                Ok((format!("Made the empty file {p}"), "made".into()))
            }
            FileOp::Rename { replace, .. } | FileOp::Move { replace, .. } => {
                let to = spec.op.destination(path).unwrap_or_default();
                let entry = files
                    .lstat(path)
                    .await?
                    .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
                if let Some(into) = spec.op.into_folder() {
                    require_folder(files, into).await?;
                }
                let there = files.lstat(&to).await?;
                match there {
                    Some(_) if !*replace => return Err(CoreError::RemotePathTaken { path: to }),
                    Some(t) if t.kind == EntryKind::Folder && !t.link => {
                        return Err(CoreError::InvalidInput(format!(
                            "{} is a folder, so nothing was replaced.",
                            shown(&to)
                        )))
                    }
                    Some(_) if entry.kind == EntryKind::Folder && !entry.link => {
                        return Err(CoreError::InvalidInput(format!(
                            "{p} is a folder and {} a file, so nothing was replaced.",
                            shown(&to)
                        )))
                    }
                    _ => {}
                }
                let replacing = there.is_some();
                files.rename(path, &to, replacing).await?;
                let verb = if matches!(spec.op, FileOp::Rename { .. }) {
                    "Renamed"
                } else {
                    "Moved"
                };
                let note = if replacing {
                    format!("now {}, replacing the file there", shown(&to))
                } else {
                    format!("now {}", shown(&to))
                };
                Ok((format!("{verb} {p} to {}", shown(&to)), note))
            }
            FileOp::Copy { into, .. } => {
                let to = spec.op.destination(path).unwrap_or_default();
                if files.lstat(path).await?.is_none() {
                    return Err(CoreError::RemoteNotFound { path: path.to_owned() });
                }
                require_folder(files, into).await?;
                if files.lstat(&to).await?.is_some() {
                    return Err(CoreError::RemotePathTaken { path: to });
                }
                self.copy_on_host(control, path, &to, spec.as_root, cancel).await?;
                Ok((
                    format!("Copied {p} to {}", shown(&to)),
                    format!("copied to {}", shown(&to)),
                ))
            }
            FileOp::Delete { recursive, .. } => {
                let entry = files
                    .lstat(path)
                    .await?
                    .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
                if entry.kind != EntryKind::Folder || entry.link {
                    files.remove(path).await?;
                    let what = if entry.link { "link" } else { "file" };
                    return Ok((format!("Deleted the {what} {p}"), "deleted".into()));
                }
                if !*recursive {
                    files.remove_folder(path).await?;
                    return Ok((format!("Deleted the empty folder {p}"), "deleted".into()));
                }
                let deleted = delete_tree(files.as_ref(), path, cancel).await?;
                let note = deleted.note();
                Ok((format!("Deleted the folder {p} {note}"), format!("deleted, {note}")))
            }
            FileOp::Mode { mode, .. } => {
                let before = files
                    .lstat(path)
                    .await?
                    .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
                files
                    .set_attrs(
                        path,
                        SetAttrs {
                            mode: Some(*mode),
                            ..SetAttrs::default()
                        },
                    )
                    .await?;
                let was = before.mode.map(|m| format!(" (was {m:04o})")).unwrap_or_default();
                Ok((
                    format!("Set the permissions of {p} to {mode:04o}"),
                    format!("{mode:04o}{was}"),
                ))
            }
            FileOp::Owner { uid, gid, .. } => {
                let before = files
                    .lstat(path)
                    .await?
                    .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
                let owner = match (uid.or(before.uid), gid.or(before.gid)) {
                    (Some(u), Some(g)) => (u, g),
                    _ => {
                        return Err(CoreError::Sftp(format!(
                            "the host didn't say who owns {p}, so give both the owner and the group"
                        )))
                    }
                };
                files
                    .set_attrs(
                        path,
                        SetAttrs {
                            owner: Some(owner),
                            ..SetAttrs::default()
                        },
                    )
                    .await?;
                let was = owner_text(before.uid, before.gid);
                let now = format!("{}:{}", owner.0, owner.1);
                Ok((
                    format!("Set the owner of {p} to {now}"),
                    if was.is_empty() {
                        now
                    } else {
                        format!("{now} (was {was})")
                    },
                ))
            }
        }
    }

    /// `cp -a` on an exec channel of the terminal's connection; with sudo as root (the root browsing's password).
    async fn copy_on_host(
        &self,
        control: &Control,
        from: &str,
        to: &str,
        as_root: bool,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let commands = crate::locks::lock(&control.commands).clone().ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "{} is not connected, so nothing can be copied on its host. Reconnect it first.",
                quoted_name(control)
            ))
        })?;
        let line = copy_line(from, to);
        let run = async {
            if as_root {
                let password = crate::locks::lock(&control.root)
                    .as_ref()
                    .map(|r| r.password.clone())
                    .ok_or_else(|| CoreError::InvalidInput("Root browsing ended; browse as root again.".into()))?;
                match password {
                    Some(password) => commands.run_sudo(&line, &password, MAX_COPY_OUTPUT).await,
                    // sudo let root browsing start without a password: it does so for the copy too.
                    None => commands.run(&format!("sudo -n {line}"), MAX_COPY_OUTPUT).await,
                }
            } else {
                commands.run(&line, MAX_COPY_OUTPUT).await
            }
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(CoreError::CancelledRemote),
            result = run => result?,
        };
        if result.exit_code == Some(0) {
            return Ok(());
        }
        let said: String = result
            .output
            .stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .chars()
            .take(300)
            .collect();
        Err(CoreError::Sftp(match (result.exit_code, said.is_empty()) {
            (Some(code), true) => format!("cp -a ended with exit code {code}; {} may be incomplete", shown(to)),
            (Some(code), false) => format!("cp -a ended with exit code {code}: {said}"),
            (None, _) => format!("cp -a did not finish; {} may be incomplete", shown(to)),
        }))
    }
}

/// SS-14: what the Files drawer asks for. Paths are the host's, absolute; nothing here is trusted: each is checked
/// ([`check_path`], [`check_name`]) and looked at on the host before the command is built.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum FileChange {
    NewFolder {
        folder: String,
        name: String,
    },
    NewFile {
        folder: String,
        name: String,
    },
    Rename {
        path: String,
        name: String,
        /// Replace a file of the new name (asked after [`CoreError::RemotePathTaken`]).
        #[serde(default)]
        replace: bool,
    },
    Move {
        paths: Vec<String>,
        into: String,
        #[serde(default)]
        replace: bool,
    },
    Copy {
        paths: Vec<String>,
        into: String,
    },
    /// A folder that holds something is deleted with what is in it (and so rated High).
    Delete {
        paths: Vec<String>,
    },
    Mode {
        paths: Vec<String>,
        mode: u32,
    },
    Owner {
        paths: Vec<String>,
        #[serde(default)]
        uid: Option<u32>,
        #[serde(default)]
        gid: Option<u32>,
    },
}

impl super::files::FileTransfers {
    /// SS-14: a change to files on the terminal's host, as a [`crate::command_bus::Command::FileOp`] on the bus: what
    /// is there is looked at first, so a rename or move that would replace something says so
    /// ([`CoreError::RemotePathTaken`]) unless `replace` was asked, a copy never replaces, and a folder that holds
    /// something is deleted with what is in it. As root when `as_root` (root browsing must be on).
    pub async fn change(
        &self,
        terminal_id: Uuid,
        change: FileChange,
        as_root: bool,
    ) -> Result<crate::command_bus::SubmitOutcome> {
        let (_, files) = self.terminals.files_for(terminal_id, as_root)?;
        let files = files.as_ref();
        let op = match change {
            FileChange::NewFolder { folder, name } => FileOp::NewFolder {
                path: new_path(files, &folder, &name).await?,
            },
            FileChange::NewFile { folder, name } => FileOp::NewFile {
                path: new_path(files, &folder, &name).await?,
            },
            FileChange::Rename { path, name, replace } => {
                check_path(&path)?;
                check_name(&name)?;
                let to = join(&parent(&path).unwrap_or_else(|| "/".into()), &name);
                let there = taken(files, &to, replace).await?;
                FileOp::Rename {
                    path,
                    name,
                    replace: there,
                }
            }
            FileChange::Move { paths, into, replace } => {
                check_path(&into)?;
                let mut any = false;
                for path in &paths {
                    check_path(path)?;
                    any |= taken(files, &join(&into, last_part(path)), replace).await?;
                }
                FileOp::Move {
                    paths,
                    into,
                    replace: any,
                }
            }
            FileChange::Copy { paths, into } => {
                check_path(&into)?;
                for path in &paths {
                    check_path(path)?;
                    taken(files, &join(&into, last_part(path)), false).await?;
                }
                FileOp::Copy { paths, into }
            }
            FileChange::Delete { paths } => {
                let mut recursive = false;
                for path in &paths {
                    check_path(path)?;
                    if path == "/" {
                        continue;
                    }
                    let entry = files
                        .lstat(path)
                        .await?
                        .ok_or_else(|| CoreError::RemoteNotFound { path: path.clone() })?;
                    if entry.kind == EntryKind::Folder && !entry.link {
                        let inside = files.list(path).await?;
                        recursive |= !inside.entries.is_empty() || inside.more;
                    }
                }
                FileOp::Delete { paths, recursive }
            }
            FileChange::Mode { paths, mode } => FileOp::Mode { paths, mode },
            FileChange::Owner { paths, uid, gid } => FileOp::Owner { paths, uid, gid },
        };
        let spec = FileOpSpec {
            terminal_id,
            op,
            as_root,
        };
        spec.validate()?;
        let command = crate::command_bus::Command::FileOp {
            targets: spec.targets(),
            spec: Box::new(spec),
        };
        self.bus.submit(&self.workspace.get(), command).await
    }
}

/// A new folder's or file's path, checked, with nothing there yet.
async fn new_path(files: &dyn RemoteFiles, folder: &str, name: &str) -> Result<String> {
    check_path(folder)?;
    check_name(name)?;
    let path = join(folder, name);
    if files.lstat(&path).await?.is_some() {
        return Err(CoreError::RemotePathTaken { path });
    }
    Ok(path)
}

/// Whether something is at `to` that a change would replace: an error unless `replace` (never a folder).
async fn taken(files: &dyn RemoteFiles, to: &str, replace: bool) -> Result<bool> {
    match files.lstat(to).await? {
        None => Ok(false),
        Some(_) if !replace => Err(CoreError::RemotePathTaken { path: to.to_owned() }),
        Some(entry) if entry.kind == EntryKind::Folder && !entry.link => Err(CoreError::InvalidInput(format!(
            "{} is a folder, so it can't be replaced.",
            shown(to)
        ))),
        Some(_) => Ok(true),
    }
}

/// The folder a move or copy goes into is there, and a folder.
async fn require_folder(files: &std::sync::Arc<dyn RemoteFiles>, into: &str) -> Result<()> {
    match files.stat(into).await? {
        Some(entry) if entry.kind == EntryKind::Folder => Ok(()),
        Some(_) => Err(CoreError::InvalidInput(format!("{} is not a folder.", shown(into)))),
        None => Err(CoreError::RemoteNotFound { path: into.to_owned() }),
    }
}

/// Deletes `root` and everything in it over SFTP, deepest first. A link is deleted as a link, never followed; a folder
/// that lists more than one listing holds is listed again once what was listed is gone.
async fn delete_tree(files: &dyn RemoteFiles, root: &str, cancel: &CancellationToken) -> Result<Deleted> {
    let mut deleted = Deleted::default();
    // (folder, listed already): a listed folder is deleted when it comes up again, once what was in it is gone.
    let mut stack = vec![(root.to_owned(), false)];
    while let Some((folder, listed)) = stack.pop() {
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        if deleted.files + deleted.folders > MAX_DELETE_ENTRIES {
            return Err(CoreError::Sftp(format!(
                "{} holds more than {MAX_DELETE_ENTRIES} files and folders; what was deleted so far is gone. Delete \
                 the rest in the terminal",
                shown(root)
            )));
        }
        if listed {
            files.remove_folder(&folder).await?;
            deleted.folders += 1;
            continue;
        }
        let listing = files.list(&folder).await?;
        stack.push((folder.clone(), true));
        if listing.more {
            // Listed again after what is listed now is gone.
            stack.push((folder.clone(), false));
        }
        for entry in listing.entries {
            let path = join(&folder, &entry.name);
            if entry.kind == EntryKind::Folder && !entry.link {
                stack.push((path, false));
            } else {
                if cancel.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                files.remove(&path).await?;
                deleted.files += 1;
            }
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(op: FileOp) -> FileOpSpec {
        FileOpSpec {
            terminal_id: Uuid::nil(),
            op,
            as_root: false,
        }
    }

    fn paths(list: &[&str]) -> Vec<String> {
        list.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn paths_are_checked_as_given_never_resolved() {
        for ok in [
            "/",
            "/srv",
            "/srv/www/index.html",
            "/home/alice/notes 2026.txt",
            "/srv/отчёт.pdf",
            "/a/..b",
            "/a/b.",
        ] {
            assert!(check_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "srv/www",
            "~/notes",
            "/srv/../etc/shadow",
            "/srv/./www",
            "/srv//www",
            "/srv/www/",
            "/srv/a\nb",
            "/srv/a\0b",
            "/srv/a\rb",
            "/srv/invoice\u{202E}fdp.exe",
            "/srv/zero\u{200B}width",
            "/srv/a\u{1b}[31mred",
            "/srv/a\u{2028}b",
        ] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        assert!(
            check_path(&format!("/{}", "a".repeat(256))).is_err(),
            "a name over 255 bytes"
        );
        assert!(check_path(&"/a".repeat(2100)).is_err(), "a path over 4096 bytes");
        for bad in ["", ".", "..", "a/b", "a\0", "\u{202E}x"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_name("new name.txt").is_ok());
    }

    #[test]
    fn each_operation_refuses_what_it_cant_take() {
        let refused = |op: FileOp| spec(op).validate().unwrap_err().to_string();
        assert!(refused(FileOp::Delete {
            paths: vec![],
            recursive: false
        })
        .contains("at least one"));
        assert!(refused(FileOp::Delete {
            paths: paths(&["/"]),
            recursive: false
        })
        .contains("top folder"));
        assert!(refused(FileOp::Delete {
            paths: paths(&["/a/b", "/a/b"]),
            recursive: false
        })
        .contains("twice"));
        assert!(refused(FileOp::Delete {
            paths: paths(&["/etc"]),
            recursive: true
        })
        .contains("top-level"));
        assert!(spec(FileOp::Delete {
            paths: paths(&["/etc"]),
            recursive: false
        })
        .validate()
        .is_ok());
        assert!(spec(FileOp::Delete {
            paths: paths(&["/srv/old"]),
            recursive: true
        })
        .validate()
        .is_ok());
        assert!(refused(FileOp::Move {
            paths: paths(&["/srv/a"]),
            into: "/srv/a/b".into(),
            replace: false
        })
        .contains("into itself"));
        assert!(refused(FileOp::Move {
            paths: paths(&["/srv/a"]),
            into: "/srv/a".into(),
            replace: false
        })
        .contains("into itself"));
        assert!(refused(FileOp::Copy {
            paths: paths(&["/srv/a"]),
            into: "/srv".into()
        })
        .contains("already"));
        assert!(refused(FileOp::Copy {
            paths: paths(&["/x/a", "/y/a"]),
            into: "/srv".into()
        })
        .contains("Two of them"));
        assert!(refused(FileOp::Move {
            paths: paths(&["/srv/a"]),
            into: "/srv/../etc".into(),
            replace: false
        })
        .contains("."));
        assert!(refused(FileOp::Rename {
            path: "/srv/a".into(),
            name: "../b".into(),
            replace: false
        })
        .contains("can't be a name"));
        assert!(refused(FileOp::Rename {
            path: "/srv/a".into(),
            name: "a".into(),
            replace: false
        })
        .contains("already"));
        assert!(refused(FileOp::Mode {
            paths: paths(&["/srv/a"]),
            mode: 0o10000
        })
        .contains("permission mode"));
        assert!(refused(FileOp::Owner {
            paths: paths(&["/srv/a"]),
            uid: None,
            gid: None
        })
        .contains("owner"));
        assert!(refused(FileOp::NewFolder {
            path: "relative".into()
        })
        .contains("full path"));
        let many = (0..=MAX_FILE_OP_PATHS).map(|n| format!("/srv/{n}")).collect();
        assert!(refused(FileOp::Delete {
            paths: many,
            recursive: false
        })
        .contains("at most"));
    }

    #[test]
    fn a_step_per_path_and_a_retry_keeps_the_failed_ones() {
        let s = spec(FileOp::Delete {
            paths: paths(&["/srv/a", "/srv/b", "/srv/c"]),
            recursive: false,
        });
        let targets = s.targets();
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[2].key(), format!("remote-path/{}/2", Uuid::nil()));
        assert_eq!(
            TargetRef::remote_path_from_key(&targets[2].key()),
            Some(targets[2].clone())
        );
        let retry = s.only(&[targets[0].clone(), targets[2].clone()]).unwrap();
        assert_eq!(retry.op.paths(), vec!["/srv/a", "/srv/c"]);
        assert_eq!(retry.targets().len(), 2);
        assert!(s.only(&[TargetRef::App]).is_none());
    }

    #[test]
    fn the_journal_keeps_paths_redacted() {
        let s = spec(FileOp::Rename {
            path: "/srv/password=hunter2.txt".into(),
            name: "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789".into(),
            replace: false,
        });
        let (kept, changed) = s.for_journal();
        assert!(changed);
        let json = serde_json::to_string(&kept).unwrap();
        assert!(!json.contains("hunter2") && !json.contains("ghp_abc"), "{json}");
        let (same, unchanged) = spec(FileOp::NewFolder {
            path: "/srv/www".into(),
        })
        .for_journal();
        assert!(!unchanged);
        assert_eq!(
            same.op,
            FileOp::NewFolder {
                path: "/srv/www".into()
            }
        );
    }

    #[test]
    fn summaries_say_what_changes_and_how() {
        let s = |op| spec(op).summary();
        assert_eq!(
            s(FileOp::NewFolder {
                path: "/srv/new".into()
            }),
            "Make the folder /srv/new"
        );
        assert_eq!(
            s(FileOp::Rename {
                path: "/srv/a.txt".into(),
                name: "b.txt".into(),
                replace: true
            }),
            "Rename /srv/a.txt to 'b.txt', replacing the file there"
        );
        assert_eq!(
            s(FileOp::Move {
                paths: paths(&["/srv/a", "/srv/b"]),
                into: "/tmp".into(),
                replace: false
            }),
            "Move 2 items from /srv to /tmp"
        );
        assert_eq!(
            s(FileOp::Delete {
                paths: paths(&["/srv/old"]),
                recursive: true
            }),
            "Delete 'old' in /srv, with everything in them"
        );
        assert_eq!(
            s(FileOp::Mode {
                paths: paths(&["/srv/run.sh"]),
                mode: 0o755
            }),
            "Set the permissions of 'run.sh' in /srv to 0755"
        );
        assert_eq!(
            s(FileOp::Owner {
                paths: paths(&["/srv/a"]),
                uid: Some(33),
                gid: None
            }),
            "Set the owner of 'a' in /srv to 33"
        );
        let mut root = spec(FileOp::NewFile {
            path: "/etc/motd.d/x".into(),
        });
        root.as_root = true;
        assert_eq!(root.summary(), "Make the empty file /etc/motd.d/x, as root");
    }

    #[test]
    fn a_copy_is_cp_a_with_each_path_quoted() {
        let s = spec(FileOp::Copy {
            paths: paths(&["/srv/it's here", "/srv/-rf"]),
            into: "/backup".into(),
        });
        assert_eq!(
            s.copy_script().unwrap(),
            "cp -a -- '/srv/it'\\''s here' '/backup/it'\\''s here'\ncp -a -- '/srv/-rf' '/backup/-rf'"
        );
        assert!(spec(FileOp::NewFolder { path: "/a".into() }).copy_script().is_none());
    }

    #[test]
    fn a_recursive_delete_counts_what_was_in_it() {
        assert_eq!(
            Deleted { files: 1, folders: 1 }.note(),
            "with 1 file and 0 folders in it"
        );
        assert_eq!(
            Deleted { files: 12, folders: 4 }.note(),
            "with 12 files and 3 folders in it"
        );
    }
}
