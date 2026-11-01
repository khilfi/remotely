//! Files Remotely saves on this PC never go into a Git working tree, where they could be committed by mistake
//! (FD-07, BX-05, SS-08, SS-11, AP-05). Every save path checks first: FD-07 exports, the audit log CSV, Compare
//! and MultiExec exports, saved terminal output, session logs, downloads and the file server's uploads (FD-09). They
//! all hold customer data (host names, what ran, what the hosts printed), so the check refuses and says why; the
//! user picks another folder.

use std::future::Future;
use std::path::Path;

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
    /// FD-09: files other computers upload to the quick file server.
    Upload,
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
            Saved::Upload => "Uploaded files hold whatever other computers sent,",
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

/// Writes `path` through a file next to it (`<name>.part`) that takes its name once `write` has succeeded. A
/// failed write removes it, so no half file is left behind.
pub async fn write_atomically<T, F, Fut>(path: &Path, write: F) -> Result<T>
where
    F: FnOnce(tokio::fs::File) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let name = path
        .file_name()
        .ok_or_else(|| CoreError::InvalidInput("Choose a file name.".into()))?;
    let temp = path.with_file_name(format!("{}.part", name.to_string_lossy()));
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
}
