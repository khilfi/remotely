//! VM-16: what the waste finder reads from this PC's file system: folder sizes, and VM folders and disks no VM in
//! the list knows about.
//!
//! Only the folders Remotely was given are searched (the scanned folders, Workstation's and VirtualBox's default VM
//! folders, launch templates' VM folders), never a whole disk: at most [`MAX_DEPTH`] levels down and
//! [`MAX_DIRS`] folders per search. A3: a folder on a share or a device path is refused before anything is opened;
//! links and junctions are not followed, nor Workstation's lock folders (`*.lck`). Blocking: run on a blocking
//! thread.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::rules::is_vm_file;
use crate::adapters::vmware::path_key;
use crate::untrusted::path_refusal;

/// Folder levels searched below a root.
pub const MAX_DEPTH: usize = 4;
/// Folders visited per root at most.
pub const MAX_DIRS: usize = 20_000;
/// File names shown per folder.
const EXAMPLES: usize = 6;

/// What an unknown folder holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OrphanKind {
    /// A .vmx no library or scanned folder lists.
    WorkstationVm,
    /// A .vbox VirtualBox hasn't registered.
    VirtualBoxVm,
    /// Disks and VM files without a VM's settings file.
    Disks,
}

/// A folder with VM files that no VM in the list uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrphanFolder {
    pub path: String,
    pub kind: OrphanKind,
    /// Its files' sizes together (the folders under it too, unless a known VM is in one of them).
    pub bytes: u64,
    pub files: usize,
    /// When a file in it was last written.
    pub newest: Option<String>,
    /// Some of its VM files, by name.
    pub examples: Vec<String>,
}

/// A root that was not searched, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedFolder {
    pub path: String,
    pub reason: String,
}

/// Sizes of the files in a folder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FolderSize {
    pub bytes: u64,
    pub files: usize,
    pub newest: Option<SystemTime>,
}

pub fn rfc3339(time: SystemTime) -> Option<String> {
    OffsetDateTime::from(time).format(&Rfc3339).ok()
}

/// Why a folder can't be searched: refused by its text (a share, a device path), or not a folder.
pub fn refusal(folder: &Path) -> Option<String> {
    if let Some(refused) = path_refusal(folder) {
        return Some(format!("it {}, so Remotely doesn't open it", refused.describe()));
    }
    if !folder.is_dir() {
        return Some("it is not a folder on this PC (any more)".into());
    }
    None
}

/// The files directly in `folder` (not in folders under it), with their sizes and times.
fn direct_files(folder: &Path) -> Vec<(String, u64, Option<SystemTime>)> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else { continue };
        if !kind.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        out.push((
            entry.file_name().to_string_lossy().into_owned(),
            meta.len(),
            meta.modified().ok(),
        ));
    }
    out.sort();
    out
}

/// Every file under `folder` (links, junctions and `*.lck` folders left out), at most [`MAX_DEPTH`] levels down,
/// skipping the folders `skip` names (by [`path_key`]). Refused folders read as empty.
pub fn folder_size(folder: &Path, skip: &HashSet<String>) -> FolderSize {
    let mut total = FolderSize::default();
    if path_refusal(folder).is_some() {
        return total;
    }
    let mut pending = vec![(folder.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = pending.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_dir() {
                let lock = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lck"));
                if !lock && depth < MAX_DEPTH && !skip.contains(&path_key(&path)) {
                    pending.push((path, depth + 1));
                }
            } else if kind.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total.bytes += meta.len();
                    total.files += 1;
                    let modified = meta.modified().ok();
                    if modified > total.newest {
                        total.newest = modified;
                    }
                }
            }
        }
    }
    total
}

/// Whether a known VM folder is `dir` or under it.
fn holds_known(dir_key: &str, known: &HashSet<String>) -> bool {
    let prefix = format!("{}\\", dir_key.trim_end_matches('\\'));
    known.iter().any(|k| k == dir_key || k.starts_with(&prefix))
}

/// VM-16: the folders under `root` with VM files that no known VM uses. `known` holds the known VMs' folders (by
/// [`path_key`]): those and everything under them are left alone, since a snapshot's files there are the VM's even
/// when its current state doesn't use them.
pub fn orphans(root: &Path, known: &HashSet<String>) -> Vec<OrphanFolder> {
    let mut found = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = pending.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            tracing::warn!(root = %root.display(), "the waste finder stopped after {MAX_DIRS} folders");
            break;
        }
        let key = path_key(&dir);
        if known.contains(&key) {
            continue;
        }
        let files = direct_files(&dir);
        let vm_files: Vec<&(String, u64, Option<SystemTime>)> =
            files.iter().filter(|(n, _, _)| is_vm_file(n)).collect();
        let known_below = holds_known(&key, known);
        if !vm_files.is_empty() {
            let lower: Vec<String> = vm_files.iter().map(|(n, _, _)| n.to_ascii_lowercase()).collect();
            let kind = if lower.iter().any(|n| n.ends_with(".vmx")) {
                OrphanKind::WorkstationVm
            } else if lower.iter().any(|n| n.ends_with(".vbox")) {
                OrphanKind::VirtualBoxVm
            } else {
                OrphanKind::Disks
            };
            let size = if known_below {
                // A folder that also holds known VMs: only its own VM files.
                FolderSize {
                    bytes: vm_files.iter().map(|(_, s, _)| s).sum(),
                    files: vm_files.len(),
                    newest: vm_files.iter().filter_map(|(_, _, t)| *t).max(),
                }
            } else {
                folder_size(&dir, &HashSet::new())
            };
            found.push(OrphanFolder {
                path: dir.display().to_string(),
                kind,
                bytes: size.bytes,
                files: size.files,
                newest: size.newest.and_then(rfc3339),
                examples: vm_files.iter().take(EXAMPLES).map(|(n, _, _)| n.clone()).collect(),
            });
            if !known_below {
                // The whole folder is the orphan; nothing under it is reported again.
                continue;
            }
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut subdirs: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|k| k.is_dir()))
            .map(|e| e.path())
            .filter(|p| !p.extension().is_some_and(|e| e.eq_ignore_ascii_case("lck")))
            .collect();
        subdirs.sort();
        pending.extend(subdirs.into_iter().rev().map(|p| (p, depth + 1)));
    }
    found.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(PathBuf);

    impl Temp {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("remotely-waste-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, rel: &str, bytes: usize) -> PathBuf {
            let path = self.0.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, vec![b'x'; bytes]).unwrap();
            path
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn finds_folders_no_known_vm_uses_and_leaves_known_ones_alone() {
        let t = Temp::new();
        t.file("web01/web01.vmx", 10);
        t.file("web01/web01.vmdk", 100);
        t.file("web01/web01-000001.vmdk", 50);
        t.file("old/old.vmx", 10);
        t.file("old/old.vmdk", 1000);
        t.file("old/sub/extra.vmdk", 5);
        t.file("lab/lab.vbox", 3);
        t.file("lab/Snapshots/s.sav", 30);
        t.file("disks/spare.vdi", 200);
        t.file("notes/readme.txt", 1);
        t.file("loose.vmdk", 7);
        let known: HashSet<String> = [path_key(&t.0.join("web01"))].into();
        let found = orphans(&t.0, &known);
        let by_path = |rel: &str| found.iter().find(|o| o.path == t.0.join(rel).display().to_string());
        let old = by_path("old").unwrap();
        assert_eq!((old.kind, old.bytes, old.files), (OrphanKind::WorkstationVm, 1015, 3));
        assert!(
            found.iter().all(|o| !o.path.ends_with("sub")),
            "inside an orphan, not again"
        );
        assert_eq!(by_path("lab").unwrap().kind, OrphanKind::VirtualBoxVm);
        assert_eq!(by_path("lab").unwrap().bytes, 33);
        assert_eq!(by_path("disks").unwrap().kind, OrphanKind::Disks);
        assert!(by_path("web01").is_none());
        assert!(by_path("notes").is_none());
        // The root holds a loose disk and a known VM below: only its own VM files count.
        let root = found.iter().find(|o| o.path == t.0.display().to_string()).unwrap();
        assert_eq!(
            (root.bytes, root.files, root.examples.clone()),
            (7, 1, vec!["loose.vmdk".to_owned()])
        );
        assert_eq!(found[0].path, t.0.join("old").display().to_string(), "largest first");
    }

    #[test]
    fn folder_sizes_skip_lock_folders_and_named_folders() {
        let t = Temp::new();
        t.file("a.vmx", 10);
        t.file("web01.vmx.lck/M12345.lck", 999);
        t.file("Snapshots/x.sav", 20);
        assert_eq!(folder_size(&t.0, &HashSet::new()).bytes, 30);
        let skip: HashSet<String> = [path_key(&t.0.join("Snapshots"))].into();
        assert_eq!(folder_size(&t.0, &skip).bytes, 10);
    }

    #[test]
    fn shares_and_device_paths_are_refused_unopened() {
        assert!(refusal(Path::new(r"\\server\vms")).unwrap().contains("network share"));
        assert!(refusal(Path::new(r"\\?\C:\VMs")).is_some());
        assert_eq!(
            folder_size(Path::new(r"\\server\vms"), &HashSet::new()),
            FolderSize::default()
        );
        let t = Temp::new();
        assert!(refusal(&t.0).is_none());
        assert!(refusal(&t.0.join("missing")).unwrap().contains("not a folder"));
    }
}
