//! Files Remotely saves on this PC never go into a Git working tree, where they could be committed by mistake
//! (FD-07, BX-05, SS-08, SS-11, AP-05). Every save path checks first: FD-07 exports, the audit log CSV, Compare
//! and MultiExec exports, saved terminal output, session logs and downloads. They all hold customer data
//! (host names, what ran, what the hosts printed), so the check refuses and says why; the user picks another
//! folder.

use std::future::Future;
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};

/// What is being saved, for the refusal's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Saved {
    /// FD-07: the encrypted export of sessions, known hosts and maybe secrets.
    Transfer,
    /// AP-05: the audit log as CSV.
    AuditLog,
    /// BX-05, QL-12: Compare results or recorded MultiExec lines.
    Results,
    /// SS-11: a terminal's output, saved once.
    Output,
    /// SS-11: a session log, written as the terminal goes.
    SessionLog,
    /// SS-08: files downloaded from a host.
    Download,
    /// CV-03: a converted disk image.
    Image,
    /// VM-17, CV-02: an exported VM (its disks, descriptors and README).
    Export,
    /// FD-04: a support bundle (what hosts printed, their logs and files).
    Bundle,
    /// FD-05: the inventory as an Excel file.
    Inventory,
    /// BX-12: an Ansible inventory.
    Ansible,
    /// FD-08: a handover pack.
    Handover,
}

impl Saved {
    fn holds(self) -> &'static str {
        match self {
            Saved::Transfer => "An export holds your sessions, and maybe your secrets,",
            Saved::AuditLog => "The audit log names your hosts and what was done on them,",
            Saved::Results => "The results hold what your hosts printed,",
            Saved::Output => "Saved output holds what the terminal showed,",
            Saved::SessionLog => "A session log holds everything the terminal shows,",
            Saved::Download => "A downloaded file holds the host's data,",
            Saved::Image => "A disk image holds everything on the disk it came from,",
            Saved::Export => "An exported VM holds its disks and everything on them,",
            Saved::Bundle => "A support bundle holds your hosts' logs, settings and what they printed,",
            Saved::Inventory => "The inventory names your VMs and hosts, their addresses and what runs on them,",
            Saved::Ansible => "An Ansible inventory names your hosts, their addresses and users,",
            Saved::Handover => "A handover pack holds your inventory, what was done and your notes,",
        }
    }
}

/// Refuses a file at `path` when its folder is inside a Git working tree. A bare file name counts as in the
/// working folder.
pub fn refuse_repository(path: &Path, saved: Saved) -> Result<()> {
    let folder = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    refuse_repository_folder(folder, saved)
}

/// Refuses files saved into `folder` when it is inside a Git working tree (a `.git` folder or file in it or a
/// folder above: a worktree or submodule has a `.git` file).
pub fn refuse_repository_folder(folder: &Path, saved: Saved) -> Result<()> {
    let folder = std::path::absolute(folder)?;
    for ancestor in folder.ancestors() {
        if ancestor.join(".git").exists() {
            return Err(CoreError::InvalidInput(format!(
                "{} is inside a Git repository ({}). {} and could end up in a commit there. Choose a folder outside it, such as Documents.",
                folder.display(),
                ancestor.display(),
                saved.holds()
            )));
        }
    }
    Ok(())
}

/// The file a save writes before it takes `path`'s name: `<name>.part` beside it.
fn part_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| CoreError::InvalidInput("Choose a file name.".into()))?;
    Ok(path.with_file_name(format!("{}.part", name.to_string_lossy())))
}

/// Writes `path` through a file next to it (`<name>.part`) that takes its name once `write` has succeeded. A
/// failed write removes it, so no half file is left behind.
pub async fn write_atomically<T, F, Fut>(path: &Path, write: F) -> Result<T>
where
    F: FnOnce(tokio::fs::File) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let temp = part_path(path)?;
    let file = tokio::fs::File::create(&temp).await?;
    let written = match write(file).await {
        Ok(value) => tokio::fs::rename(&temp, path).await.map(|()| value).map_err(Into::into),
        Err(err) => Err(err),
    };
    if written.is_err() {
        let _ = tokio::fs::remove_file(&temp).await;
    }
    written
}

/// [`write_atomically`] for a file written bit by bit over a long time (FD-04: a support bundle's zip, as each host
/// gives its files): the same `<name>.part` beside `path`, which takes its name on [`AtomicFile::commit`]. Whatever
/// else happens (dropped without a commit by a failed or cancelled job, or a commit that fails: the disk is full, or
/// the old file of that name is open in another program), the `.part` is removed, so no half file and no copy of the
/// data is left behind. Blocking I/O: use it on a blocking thread.
pub struct AtomicFile {
    path: PathBuf,
    temp: PathBuf,
    file: Option<std::fs::File>,
    /// The `.part` took its name: nothing is left to remove.
    committed: bool,
}

impl AtomicFile {
    pub fn create(path: &Path) -> Result<Self> {
        let temp = part_path(path)?;
        let file = std::fs::File::create(&temp)?;
        Ok(Self {
            path: path.to_owned(),
            temp,
            file: Some(file),
            committed: false,
        })
    }

    fn file(&mut self) -> std::io::Result<&mut std::fs::File> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("the file was closed"))
    }

    /// Writes what is buffered to the disk and gives the file its name (replacing a file of that name, which the save
    /// dialog asked about). On an error the `.part` is removed when this is dropped.
    pub fn commit(mut self) -> Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all()?;
            // Closed before the rename: Windows doesn't rename an open file.
            drop(file);
        }
        std::fs::rename(&self.temp, &self.path)?;
        self.committed = true;
        Ok(())
    }
}

impl std::io::Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file()?.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file()?.flush()
    }
}

impl std::io::Seek for AtomicFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file()?.seek(pos)
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        // Not committed, or the commit failed: the `.part` goes (closed first, so Windows lets it go).
        drop(self.file.take());
        if !self.committed {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn a_folder_in_a_repository_or_a_worktree_is_refused_for_every_kind() {
        let root = std::env::temp_dir().join(format!("remotely-repo-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("docs").join("logs")).unwrap();
        // A worktree's .git is a file.
        let worktree = std::env::temp_dir().join(format!("remotely-worktree-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(worktree.join(".git"), "gitdir: elsewhere").unwrap();
        let outside = std::env::temp_dir().join(format!("remotely-plain-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&outside).unwrap();

        for saved in [
            Saved::Transfer,
            Saved::AuditLog,
            Saved::Results,
            Saved::Output,
            Saved::SessionLog,
            Saved::Download,
            Saved::Bundle,
            Saved::Inventory,
            Saved::Ansible,
            Saved::Handover,
        ] {
            let err = refuse_repository(&root.join("docs").join("logs").join("x.txt"), saved).unwrap_err();
            assert!(err.to_string().contains("inside a Git repository"), "{err}");
            assert!(err.to_string().contains(saved.holds()), "{err}");
            assert!(refuse_repository_folder(&root, saved).is_err());
            assert!(refuse_repository(&worktree.join("x.csv"), saved).is_err());
            assert!(refuse_repository(&outside.join("x.csv"), saved).is_ok());
            assert!(refuse_repository_folder(&outside, saved).is_ok());
        }
        // A bare file name is relative to the working folder: here, the repository itself.
        assert!(refuse_repository(Path::new("x.csv"), Saved::AuditLog).is_err());
        for dir in [root, worktree, outside] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_file_written_bit_by_bit_takes_its_name_only_when_committed() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("remotely-atomic-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundle.zip");
        let part = dir.join("bundle.zip.part");

        let mut file = AtomicFile::create(&path).unwrap();
        file.write_all(b"half").unwrap();
        assert!(part.exists() && !path.exists());
        drop(file);
        assert!(
            !part.exists() && !path.exists(),
            "dropped without a commit: nothing is left"
        );

        let mut file = AtomicFile::create(&path).unwrap();
        file.write_all(b"whole").unwrap();
        file.commit().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"whole");
        assert!(!part.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_commit_that_fails_leaves_no_part_behind() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("remotely-atomic-fail-{}", Uuid::new_v4()));
        // A folder where the file should go: the rename fails, as it does over a file another program holds open.
        let path = dir.join("bundle.zip");
        std::fs::create_dir_all(&path).unwrap();
        let mut file = AtomicFile::create(&path).unwrap();
        file.write_all(b"every host's logs").unwrap();
        assert!(file.commit().is_err());
        assert!(
            !dir.join("bundle.zip.part").exists(),
            "the copy of the data went with the failure"
        );
        assert!(path.is_dir(), "what was there is left as it was");
        let _ = std::fs::remove_dir_all(dir);
    }
}
