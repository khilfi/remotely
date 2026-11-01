//! FD-09: uploads (TFTP write requests, HTTP PUT) into the one folder chosen for them, which was empty when the
//! server started and is outside any Git working tree (`save_guard`).
//!
//! * A file is created only when its name is free (`create_new`), so an upload never replaces a file, whatever the
//!   name maps onto (another letter case, an 8.3 short name).
//! * Each file and all of them together are capped. A declared size (`Content-Length`, `tsize`) that can't fit is
//!   refused before any byte, but only the bytes that arrive count against the caps, so a client that declares a
//!   large file and then sends nothing holds no quota.
//! * One client address holds at most [`UploadLimits::per_client`] uploads at once, and every upload must move at
//!   least [`UploadLimits::min_bytes`] in each [`UploadLimits::window`], or it is cut off.
//! * A file that doesn't arrive whole (the client went away or was too slow, the server stopped) is deleted.
//! * A finished file gets the Mark of the Web (SS-08's `Zone.Identifier`, A8), so Windows treats it as from the
//!   internet.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;

use super::served::{display_path, real_path};
use crate::locks;

/// The most files one server takes.
pub const MAX_UPLOAD_FILES: usize = 1000;

/// One MB, as the caps are given.
pub const MB: u64 = 1024 * 1024;

/// How hard a client may lean on the upload folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// Uploads one client address may have under way at once (TFTP and HTTP together).
    pub per_client: usize,
    /// Each window of this long must bring at least [`UploadLimits::min_bytes`].
    pub window: Duration,
    pub min_bytes: u64,
}

impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            per_client: 2,
            window: Duration::from_secs(60),
            // 1 KB/s over each minute: a link far slower than any switch's.
            min_bytes: 60 * 1024,
        }
    }
}

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
    /// This client has [`UploadLimits::per_client`] uploads under way already.
    ClientBusy(usize),
    /// Less than [`UploadLimits::min_bytes`] arrived in a window.
    TooSlow { bytes: u64, window: Duration },
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
            UploadRefused::ClientBusy(n) => format!("this address has {n} uploads under way already"),
            UploadRefused::TooSlow { bytes, window } => format!(
                "too slow: less than {} arrived in {} seconds",
                size_text(*bytes),
                window.as_secs().max(1)
            ),
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
    /// Bytes that arrived, in finished uploads and those under way.
    used: u64,
    /// Files claimed so far, finished or under way.
    claimed: usize,
    /// Uploads under way per client address.
    clients: HashMap<IpAddr, usize>,
    /// The real paths (lower case) being written now, which nothing may serve yet.
    writing: HashSet<String>,
    done: Vec<Uploaded>,
}

/// The upload folder and its caps, shared by the server's TFTP and HTTP sides.
pub struct Uploads {
    folder: PathBuf,
    max_file: u64,
    max_total: u64,
    limits: UploadLimits,
    state: Mutex<State>,
}

impl Uploads {
    /// `folder` is its final path (`canonicalize`), checked empty and outside Git when the server started.
    pub fn new(folder: PathBuf, max_file: u64, max_total: u64, limits: UploadLimits) -> Self {
        Self {
            folder,
            max_file,
            max_total,
            limits,
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

    /// Bytes that arrived (finished uploads and those under way).
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

    /// Creates `name` (already checked by [`super::paths::upload_name`]) in the folder for `client`. `expected` is
    /// the size the client declared: one that can't fit now is refused at once, but nothing is set aside for it.
    pub async fn claim(
        self: &Arc<Self>,
        name: &str,
        expected: Option<u64>,
        client: IpAddr,
    ) -> Result<Upload, UploadRefused> {
        let declared = expected.unwrap_or(0);
        if declared > self.max_file {
            return Err(UploadRefused::FileTooLarge(self.max_file));
        }
        {
            let mut state = locks::lock(&self.state);
            if state.claimed >= MAX_UPLOAD_FILES {
                return Err(UploadRefused::TooManyFiles);
            }
            if state.used.saturating_add(declared) > self.max_total {
                return Err(UploadRefused::TotalTooLarge(self.max_total));
            }
            let mine = state.clients.get(&client).copied().unwrap_or(0);
            if mine >= self.limits.per_client {
                return Err(UploadRefused::ClientBusy(mine));
            }
            state.clients.insert(client, mine + 1);
            state.claimed += 1;
        }
        // From here, giving the client's slot and the file's place back is the guard's job.
        let mut upload = Upload {
            uploads: Arc::clone(self),
            name: name.to_owned(),
            path: self.folder.join(name),
            client,
            key: None,
            file: None,
            written: 0,
            window_start: Instant::now(),
            window_bytes: 0,
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
        // The minimum rate counts from when the file is ready to take bytes, not from when its creation was asked.
        upload.window_start = Instant::now();
        Ok(upload)
    }
}

/// An upload under way. Dropped before [`Upload::finish`], its file is deleted and its bytes, file and client slot
/// given back.
pub struct Upload {
    uploads: Arc<Uploads>,
    name: String,
    path: PathBuf,
    client: IpAddr,
    key: Option<String>,
    file: Option<tokio::fs::File>,
    written: u64,
    /// The minimum rate: when the current window started, and what arrived in it.
    window_start: Instant,
    window_bytes: u64,
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

    /// Writes the next bytes, within the caps and the minimum rate.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), UploadRefused> {
        let limits = self.uploads.limits;
        let now = Instant::now();
        if now.duration_since(self.window_start) >= limits.window {
            if self.window_bytes < limits.min_bytes {
                return Err(UploadRefused::TooSlow {
                    bytes: limits.min_bytes,
                    window: limits.window,
                });
            }
            self.window_start = now;
            self.window_bytes = 0;
        }
        let len = data.len() as u64;
        let after = self.written.saturating_add(len);
        if after > self.uploads.max_file {
            return Err(UploadRefused::FileTooLarge(self.uploads.max_file));
        }
        {
            let mut state = locks::lock(&self.uploads.state);
            if state.used.saturating_add(len) > self.uploads.max_total {
                return Err(UploadRefused::TotalTooLarge(self.uploads.max_total));
            }
            state.used += len;
        }
        // Counted before the write, so a failing write is given back by the guard with the rest.
        self.written = after;
        self.window_bytes = self.window_bytes.saturating_add(len);
        let Some(file) = self.file.as_mut() else {
            return Err(UploadRefused::Io("the file is closed".into()));
        };
        file.write_all(data)
            .await
            .map_err(|err| UploadRefused::Io(err.to_string()))
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
        release_client(&mut state, self.client);
        if let Some(key) = self.key.take() {
            state.writing.remove(&key);
        }
        state.done.push(uploaded.clone());
        Ok(uploaded)
    }
}

fn release_client(state: &mut State, client: IpAddr) {
    if let Some(n) = state.clients.get_mut(&client) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            state.clients.remove(&client);
        }
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
        state.used = state.used.saturating_sub(self.written);
        // A refused name or a deleted part takes no place among the files a server takes.
        state.claimed = state.claimed.saturating_sub(1);
        release_client(&mut state, self.client);
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

    fn client(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    #[tokio::test]
    async fn an_upload_never_replaces_a_file_and_a_cut_off_one_is_deleted() {
        let dir = folder();
        std::fs::write(dir.join("taken.bin"), b"keep").unwrap();
        let uploads = Arc::new(Uploads::new(dir.clone(), 10, 15, UploadLimits::default()));
        let me = client(7);
        assert_eq!(
            uploads.claim("taken.bin", None, me).await.err(),
            Some(UploadRefused::Exists)
        );
        assert_eq!(
            uploads.claim("TAKEN.BIN", None, me).await.err(),
            Some(UploadRefused::Exists)
        );
        assert_eq!(std::fs::read(dir.join("taken.bin")).unwrap(), b"keep");

        let mut upload = uploads.claim("new.bin", None, me).await.unwrap();
        assert!(uploads.is_writing(&dir.join("new.bin")));
        upload.write(b"12345").await.unwrap();
        assert_eq!(
            upload.write(b"123456").await.err(),
            Some(UploadRefused::FileTooLarge(10))
        );
        drop(upload);
        assert!(!dir.join("new.bin").exists(), "a cut-off upload is deleted");
        assert_eq!(uploads.used(), 0);

        let mut one = uploads.claim("one.bin", Some(8), me).await.unwrap();
        one.write(b"12345678").await.unwrap();
        let done = one.finish("192.0.2.7").await.unwrap();
        assert_eq!(done.bytes, 8);
        assert_eq!(std::fs::read(dir.join("one.bin")).unwrap(), b"12345678");
        // 8 of 15 arrived: a declared 8 more doesn't fit, and neither do 8 more written.
        assert_eq!(
            uploads.claim("two.bin", Some(8), me).await.err(),
            Some(UploadRefused::TotalTooLarge(15))
        );
        let mut two = uploads.claim("two.bin", None, me).await.unwrap();
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

    #[tokio::test]
    async fn a_declared_size_holds_no_quota_and_one_client_holds_few_slots() {
        let dir = folder();
        let uploads = Arc::new(Uploads::new(dir.clone(), 10, 10, UploadLimits::default()));
        let (slow, other) = (client(7), client(8));
        // Declares the whole quota, then sends a byte: only that byte counts.
        let mut big = uploads.claim("big.bin", Some(10), slow).await.unwrap();
        big.write(b"x").await.unwrap();
        assert_eq!(uploads.used(), 1);
        let mut fits = uploads.claim("fits.bin", Some(9), other).await.unwrap();
        fits.write(b"123456789").await.unwrap();
        fits.finish("192.0.2.8").await.unwrap();
        // Two uploads under way per address, then refused; one ending frees its slot.
        let second = uploads.claim("b.bin", None, slow).await.unwrap();
        assert_eq!(
            uploads.claim("c.bin", None, slow).await.err(),
            Some(UploadRefused::ClientBusy(2))
        );
        assert!(
            uploads.claim("d.bin", None, other).await.is_ok(),
            "another address has its own"
        );
        drop(second);
        assert!(uploads.claim("e.bin", None, slow).await.is_ok());
        drop(big);
        assert_eq!(uploads.used(), 9, "a deleted part gives its bytes back");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_upload_slower_than_the_minimum_rate_is_cut_off() {
        let dir = folder();
        let limits = UploadLimits {
            per_client: 2,
            window: Duration::from_millis(300),
            min_bytes: 1000,
        };
        let uploads = Arc::new(Uploads::new(dir.clone(), MB, MB, limits));
        let mut fast = uploads.claim("fast.bin", None, client(7)).await.unwrap();
        fast.write(&[0u8; 2000]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
        fast.write(&[0u8; 10]).await.unwrap();
        let mut slow = uploads.claim("slow.bin", None, client(7)).await.unwrap();
        slow.write(b"x").await.unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(matches!(slow.write(b"x").await, Err(UploadRefused::TooSlow { .. })));
        drop(slow);
        assert!(!dir.join("slow.bin").exists());
        drop(fast);
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
