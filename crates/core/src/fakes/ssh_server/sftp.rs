//! SS-08: the test server's SFTP subsystem (russh-sftp's server side). Host paths map into a temp
//! folder made for each server (`/home/alice` is `<root>/home/alice`), deleted when the server is
//! dropped. Writes into protected folders (`/etc`, `/root`, `/usr` and any a test adds) are refused
//! with "permission denied", like folders the user may not write to; an exclusive create that finds a
//! file answers "failure", as OpenSSH does. A delay per read or write makes transfers slow enough to
//! cancel. The log says what was opened and removed, never what was in a file.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};

use super::State;
use crate::locks;
use crate::terminal::files::resolve;

/// Folders every toy host has under its SFTP root.
pub(super) const SFTP_DIRS: [&str; 7] = ["/home", "/root", "/tmp", "/etc", "/usr", "/srv", "/var/log"];

enum Open {
    File { file: std::fs::File, path: String },
    Folder { entries: Option<Vec<File>> },
}

pub(super) struct SftpServer {
    state: Arc<State>,
    root: PathBuf,
    home: String,
    handles: HashMap<String, Open>,
    next: u64,
}

impl SftpServer {
    pub(super) fn new(state: Arc<State>, root: PathBuf, user: &str) -> Self {
        let home = if user == "root" {
            "/root".to_owned()
        } else {
            format!("/home/{user}")
        };
        let _ = std::fs::create_dir_all(local(&root, &home));
        Self {
            state,
            root,
            home,
            handles: HashMap::new(),
            next: 1,
        }
    }

    fn path(&self, path: &str) -> String {
        if path.is_empty() || path == "." {
            return self.home.clone();
        }
        resolve(&self.home, &self.home, path)
    }

    fn local(&self, path: &str) -> PathBuf {
        local(&self.root, &self.path(path))
    }

    fn protected(&self, path: &str) -> bool {
        let path = self.path(path);
        let folder = match path.rsplit_once('/') {
            Some(("", _)) | None => "/".to_owned(),
            Some((folder, _)) => folder.to_owned(),
        };
        folder == "/"
            || locks::lock(&self.state.sftp_protected)
                .iter()
                .any(|p| folder == *p || folder.starts_with(&format!("{p}/")))
    }

    fn handle(&mut self, open: Open) -> String {
        let handle = format!("h{}", self.next);
        self.next += 1;
        self.handles.insert(handle.clone(), open);
        handle
    }

    async fn pause(&self) {
        let delay = *locks::lock(&self.state.sftp_delay);
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
    }
}

/// `<root>/a/b` for the host path `/a/b`.
pub(super) fn local(root: &Path, path: &str) -> PathBuf {
    let mut out = root.to_owned();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        out.push(part);
    }
    out
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn io_status(err: &std::io::Error) -> StatusCode {
    match err.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn attrs(meta: &std::fs::Metadata) -> FileAttributes {
    let kind = if meta.is_dir() { 0o040_000 } else { 0o100_000 };
    let mode = if meta.is_dir() { 0o755 } else { 0o644 };
    FileAttributes {
        size: Some(meta.len()),
        uid: Some(1000),
        user: None,
        gid: Some(1000),
        group: None,
        permissions: Some(kind | mode),
        atime: None,
        mtime: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .and_then(|d| u32::try_from(d.as_secs()).ok()),
    }
}

impl russh_sftp::server::Handler for SftpServer {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _version: u32, _extensions: HashMap<String, String>) -> Result<Version, Self::Error> {
        self.state.note("sftp start");
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![File::dummy(self.path(&path))],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::metadata(self.local(&path)).map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: attrs(&meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::symlink_metadata(self.local(&path)).map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: attrs(&meta),
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(self.local(&path)).map_err(|e| io_status(&e))? {
            let entry = entry.map_err(|e| io_status(&e))?;
            let meta = entry.metadata().map_err(|e| io_status(&e))?;
            entries.push(File::new(entry.file_name().to_string_lossy(), attrs(&meta)));
        }
        let handle = self.handle(Open::Folder { entries: Some(entries) });
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(Open::Folder { entries }) => match entries.take() {
                Some(files) => Ok(Name { id, files }),
                None => Err(StatusCode::Eof),
            },
            _ => Err(StatusCode::Failure),
        }
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.path(&filename);
        let writes = pflags.intersects(OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::APPEND);
        if writes && self.protected(&path) {
            self.state.note(format!("sftp refused {path}"));
            return Err(StatusCode::PermissionDenied);
        }
        let options: std::fs::OpenOptions = pflags.into();
        let file = options.open(local(&self.root, &path)).map_err(|e| io_status(&e))?;
        self.state
            .note(format!("sftp open {path}{}", if writes { " for writing" } else { "" }));
        let handle = self.handle(Open::File { file, path });
        Ok(Handle { id, handle })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        self.pause().await;
        let Some(Open::File { file, .. }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset)).map_err(|e| io_status(&e))?;
        let mut data = vec![0u8; len.min(256 * 1024) as usize];
        let n = file.read(&mut data).map_err(|e| io_status(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(n);
        Ok(Data { id, data })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        self.pause().await;
        let Some(Open::File { file, .. }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset)).map_err(|e| io_status(&e))?;
        file.write_all(&data).map_err(|e| io_status(&e))?;
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        match self.handles.remove(&handle) {
            Some(Open::File { file, path }) => {
                let _ = file.sync_all();
                self.state.note(format!("sftp close {path}"));
            }
            Some(Open::Folder { .. }) => {}
            None => return Err(StatusCode::Failure),
        }
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let path = self.path(&filename);
        if self.protected(&path) {
            return Err(StatusCode::PermissionDenied);
        }
        std::fs::remove_file(local(&self.root, &path)).map_err(|e| io_status(&e))?;
        self.state.note(format!("sftp remove {path}"));
        Ok(ok(id))
    }
}
