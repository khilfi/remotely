//! FD-09: uploads (TFTP write requests, HTTP PUT) into the one folder chosen for them, which was empty when the
//! server started and is outside any Git working tree (`save_guard`).
//!
//! * A file is created only when its name is free (`create_new`), so an upload never replaces a file, whatever the
//!   name maps onto (another letter case, an 8.3 short name).
//! * Each file and all of them together are capped; a client that sends more is cut off and its file deleted.
//! * A file that doesn't arrive whole (the client went away, the server stopped) is deleted.
//! * A finished file gets the Mark of the Web (SS-08's `Zone.Identifier`, A8), so Windows treats it as from the
//!   internet.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;

use super::served::{display_path, real_path};
use crate::locks;

/// The most files one server takes.
pub const MAX_UPLOAD_FILES: usize = 1000;

/// One MB, as the caps are given.
pub const MB: u64 = 1024 * 1024;

/// Why an upload was refused or cut off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadRefused {
    /// A file of that name (or one it maps onto) is there.
    Exists,
    /// Over the cap for one file (in bytes).
    FileTooLarge(u64),
    /// Over the cap for all of them (in bytes).
    TotalTooLarge(u64),
    /// [`MAX_UPLOAD_FILES`] files arrived already.
    TooManyFiles,
    /// The new file's real place isn't in the folder (it was swapped for a link).
    Outside,
    /// Writing failed.
    Io(String),
}

impl UploadRefused {
    pub fn describe(&self) -> String {
        match self {
            UploadRefused::Exists => "a file of that name is there already, and uploads never replace one".into(),
            UploadRefused::FileTooLarge(cap) => format!("larger than the {} a file may be", size_text(*cap)),
            UploadRefused::TotalTooLarge(cap) => format!("over the {} uploads may take in all", size_text(*cap)),
            UploadRefused::TooManyFiles => format!("{MAX_UPLOAD_FILES} files arrived already"),
            UploadRefused::Outside => "the upload folder changed (a link or junction)".into(),
            UploadRefused::Io(err) => format!("could not write the file: {err}"),
        }
    }
}

/// A file that arrived whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub name: String,
    pub bytes: u64,
    /// The client's address.
    pub ip: String,
    /// When Windows could not mark it as from the internet, why.
    pub note: Option<String>,
}

#[derive(Default)]
struct State {
    /// Bytes written or set aside for uploads under way (a declared size counts at once).
    used: u64,
    /// Files claimed so far, finished or not.
    claimed: usize,
    /// The real paths (lower case) being written now, which nothing may serve yet.
    writing: HashSet<String>,
    done: Vec<Uploaded>,
}

/// The upload folder and its caps, shared by the server's TFTP and HTTP sides.
pub struct Uploads {
    folder: PathBuf,
    max_file: u64,
    max_total: u64,
    state: Mutex<State>,
}

impl Uploads {
    /// `folder` is its final path (`canonicalize`), checked empty and outside Git when the server started.
    pub fn new(folder: PathBuf, max_file: u64, max_total: u64) -> Self {
        Self {
            folder,
            max_file,
            max_total,
            state: Mutex::default(),
        }
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn max_file(&self) -> u64 {
        self.max_file
    }

    pub fn max_total(&self) -> u64 {
        self.max_total
    }

    /// Bytes taken by finished uploads and those under way.
    pub fn used(&self) -> u64 {
        locks::lock(&self.state).used
    }

    /// The files that arrived whole, in order.
    pub fn done(&self) -> Vec<Uploaded> {
        locks::lock(&self.state).done.clone()
    }

    /// An upload is writing this file now (the served folder may be the upload folder).
    pub fn is_writing(&self, real: &Path) -> bool {
        locks::lock(&self.state)
            .writing
            .contains(&real.to_string_lossy().to_lowercase())
    }

    /// Creates `name` (already checked by [`super::paths::upload_name`]) in the folder, setting `expected` bytes
    /// aside when the client said how many it sends.
    pub async fn claim(self: &Arc<Self>, name: &str, expected: Option<u64>) -> Result<Upload, UploadRefused> {
        let reserved = expected.unwrap_or(0);
        if reserved > self.max_file {
            return Err(UploadRefused::FileTooLarge(self.max_file));
        }
        {
            let mut state = locks::lock(&self.state);
            if state.claimed >= MAX_UPLOAD_FILES {
                return Err(UploadRefused::TooManyFiles);
            }
            if state.used.saturating_add(reserved) > self.max_total {
                return Err(UploadRefused::TotalTooLarge(self.max_total));
            }
            state.used += reserved;
            state.claimed += 1;
        }
        // From here, giving back what was set aside is the guard's job.
        let mut upload = Upload {
            uploads: Arc::clone(self),
            name: name.to_owned(),
            path: self.folder.join(name),
            key: None,
            file: None,
            written: 0,
            reserved,
            finished: false,
            created: false,
        };
        let path = upload.path.clone();
        let created = tokio::task::spawn_blocking(move || {
            let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
            let real = real_path(&file, &path)?;
            Ok::<_, std::io::Error>((file, real))
        })
        .await
        .map_err(|err| UploadRefused::Io(err.to_string()))?;
        let (file, real) = match created {
            Ok(created) => created,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Err(UploadRefused::Exists),
            Err(err) => return Err(UploadRefused::Io(err.to_string())),
        };
        upload.created = true;
        // The new file must sit in the folder itself, where its name says.
        let parent = real.parent().map(|p| p.to_string_lossy().to_lowercase());
        if parent != Some(self.folder.to_string_lossy().to_lowercase()) {
            return Err(UploadRefused::Outside);
        }
        let key = real.to_string_lossy().to_lowercase();
        locks::lock(&self.state).writing.insert(key.clone());
        upload.key = Some(key);
        upload.file = Some(tokio::fs::File::from_std(file));
        Ok(upload)
    }
}

/// An upload under way. Dropped before [`Upload::finish`], its file is deleted and what it set aside given back.
pub struct Upload {
    uploads: Arc<Uploads>,
    name: String,
    path: PathBuf,
    key: Option<String>,
    file: Option<tokio::fs::File>,
    written: u64,
    reserved: u64,
    finished: bool,
    created: bool,
}

impl Upload {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Writes the next bytes, within the caps.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), UploadRefused> {
        let len = data.len() as u64;
        let after = self.written.saturating_add(len);
        if after > self.uploads.max_file {
            return Err(UploadRefused::FileTooLarge(self.uploads.max_file));
        }
        let extra = after.saturating_sub(self.reserved);
        if extra > 0 {
            let mut state = locks::lock(&self.uploads.state);
            if state.used.saturating_add(extra) > self.uploads.max_total {
                return Err(UploadRefused::TotalTooLarge(self.uploads.max_total));
            }
            state.used += extra;
            self.reserved += extra;
        }
        let Some(file) = self.file.as_mut() else {
            return Err(UploadRefused::Io("the file is closed".into()));
        };
        file.write_all(data)
            .await
            .map_err(|err| UploadRefused::Io(err.to_string()))?;
        self.written = after;
        Ok(())
    }

    /// The whole file arrived: written out, closed and marked as from the internet.
    pub async fn finish(mut self, ip: &str) -> Result<Uploaded, UploadRefused> {
        if let Some(mut file) = self.file.take() {
            let flushed = async {
                file.flush().await?;
                file.sync_all().await
            }
            .await;
            drop(file);
            flushed.map_err(|err| UploadRefused::Io(err.to_string()))?;
        }
        let note = crate::terminal::files::mark_downloaded(&self.path).await;
        self.finished = true;
        let uploaded = Uploaded {
            name: self.name.clone(),
            bytes: self.written,
            ip: ip.to_owned(),
            note,
        };
        let mut state = locks::lock(&self.uploads.state);
        // A client that declared more than it sent: only what arrived counts.
        state.used = state.used.saturating_sub(self.reserved.saturating_sub(self.written));
        self.reserved = self.written;
        if let Some(key) = self.key.take() {
            state.writing.remove(&key);
        }
        state.done.push(uploaded.clone());
        Ok(uploaded)
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Rust opens files shareable for delete, so this works while a write still holds the handle; Windows removes
        // the file once it is closed.
        drop(self.file.take());
        if self.created {
            if let Err(err) = std::fs::remove_file(&self.path) {
                tracing::warn!(path = %display_path(&self.path), error = %err, "could not delete an upload that didn't arrive whole");
            }
        }
        let mut state = locks::lock(&self.uploads.state);
        state.used = state.used.saturating_sub(self.reserved);
        // A refused name or a deleted part takes no place among the files a server takes.
        state.claimed = state.claimed.saturating_sub(1);
        if let Some(key) = self.key.take() {
            state.writing.remove(&key);
        }
    }
}

/// `12 MB`, `512 KB`, `100 bytes`, `1.5 GB`.
pub fn size_text(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if b < KB * KB {
        format!("{:.0} KB", b / KB)
    } else if b < KB * KB * KB {
        format!("{:.1} MB", b / (KB * KB)).replace(".0 MB", " MB")
    } else {
        format!("{:.1} GB", b / (KB * KB * KB)).replace(".0 GB", " GB")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn folder() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("remotely-uploads-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(dir).unwrap()
    }

    #[tokio::test]
    async fn an_upload_never_replaces_a_file_and_a_cut_off_one_is_deleted() {
        let dir = folder();
        std::fs::write(dir.join("taken.bin"), b"keep").unwrap();
        let uploads = Arc::new(Uploads::new(dir.clone(), 10, 15));
        assert_eq!(
            uploads.claim("taken.bin", None).await.err(),
            Some(UploadRefused::Exists)
        );
        assert_eq!(
            uploads.claim("TAKEN.BIN", None).await.err(),
            Some(UploadRefused::Exists)
        );
        assert_eq!(std::fs::read(dir.join("taken.bin")).unwrap(), b"keep");

        let mut upload = uploads.claim("new.bin", None).await.unwrap();
        assert!(uploads.is_writing(&dir.join("new.bin")));
        upload.write(b"12345").await.unwrap();
        assert_eq!(
            upload.write(b"123456").await.err(),
            Some(UploadRefused::FileTooLarge(10))
        );
        drop(upload);
        assert!(!dir.join("new.bin").exists(), "a cut-off upload is deleted");
        assert_eq!(uploads.used(), 0);

        let mut one = uploads.claim("one.bin", Some(8)).await.unwrap();
        one.write(b"12345678").await.unwrap();
        let done = one.finish("192.0.2.7").await.unwrap();
        assert_eq!(done.bytes, 8);
        assert_eq!(std::fs::read(dir.join("one.bin")).unwrap(), b"12345678");
        // 8 of 15 taken: a declared 8 more doesn't fit, and neither do 8 more written.
        assert_eq!(
            uploads.claim("two.bin", Some(8)).await.err(),
            Some(UploadRefused::TotalTooLarge(15))
        );
        let mut two = uploads.claim("two.bin", None).await.unwrap();
        two.write(b"1234567").await.unwrap();
        assert_eq!(two.write(b"8").await.err(), Some(UploadRefused::TotalTooLarge(15)));
        drop(two);
        assert_eq!(uploads.used(), 8);
        assert_eq!(uploads.done().len(), 1);
        #[cfg(windows)]
        {
            let mut stream = dir.join("one.bin").into_os_string();
            stream.push(":Zone.Identifier");
            let mark = std::fs::read_to_string(PathBuf::from(stream)).unwrap();
            assert!(mark.contains("ZoneId=3"), "{mark}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sizes_read_well() {
        assert_eq!(size_text(100), "100 bytes");
        assert_eq!(size_text(2048), "2 KB");
        assert_eq!(size_text(12 * MB), "12 MB");
        assert_eq!(size_text(3 * MB / 2), "1.5 MB");
        assert_eq!(size_text(4 * 1024 * MB), "4 GB");
    }
}
