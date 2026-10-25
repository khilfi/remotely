//! SS-08: the test server's SFTP subsystem (russh-sftp's server side). Host paths map into a temp
//! folder made for each server (`/home/alice` is `<root>/home/alice`), deleted when the server is
//! dropped. Writes into protected folders (`/etc`, `/root`, `/usr` and any a test adds) are refused
//! with "permission denied", like folders the user may not write to; an exclusive create that finds a
//! file answers "failure", as OpenSSH does. Unreadable folders (QL-09) can't be opened at all, nor
//! anything in them looked at, like another user's private folder. A delay per read or write makes
//! transfers slow enough to cancel. The log says what was opened and removed, never what was in a file.
//!
//! H8: renames work as OpenSSH's do: a plain rename refuses to replace a file, and
//! `posix-rename@openssh.com` (announced unless [`super::TestSshServer::without_posix_rename`]) does.
//! Modes and owners set through SFTP are kept in memory per host path (the temp folder has none), and
//! the login user can't give a file another owner than 1000:1000. A9: an endless folder answers every
//! read with another batch of names.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use std::sync::atomic::Ordering;

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};

use super::State;
use crate::locks;
use crate::terminal::files::resolve;

/// Folders every toy host has under its SFTP root.
pub(super) const SFTP_DIRS: [&str; 7] = ["/home", "/root", "/tmp", "/etc", "/usr", "/srv", "/var/log"];

enum Open {
    File {
        file: std::fs::File,
        path: String,
    },
    Folder {
        entries: Option<Vec<File>>,
    },
    /// A9: an endless folder: how many names it sent so far.
    Endless {
        sent: u64,
    },
}

/// The login user's uid and gid.
const LOGIN_ID: u32 = 1000;

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

    /// QL-09: `path` is an unreadable folder or in one; `inside` only counts what is in one.
    fn unreadable(&self, path: &str, inside: bool) -> bool {
        let path = self.path(path);
        locks::lock(&self.state.sftp_unreadable)
            .iter()
            .any(|u| (!inside && path == *u) || path.starts_with(&format!("{u}/")))
    }

    fn handle(&mut self, open: Open) -> String {
        let handle = format!("h{}", self.next);
        self.next += 1;
        self.handles.insert(handle.clone(), open);
        handle
    }

    /// The attributes of host `path` (absolute), with what SFTP set for it.
    fn attrs_of(&self, path: &str, meta: &std::fs::Metadata) -> FileAttributes {
        attrs_with(meta, locks::lock(&self.state.sftp_meta).get(path).copied())
    }

    /// H8: sets a mode, or an owner the login user may give (its own).
    fn apply(&self, path: &str, set: &FileAttributes) -> Result<(), StatusCode> {
        let meta = std::fs::metadata(local(&self.root, path)).map_err(|e| io_status(&e))?;
        let now = self.attrs_of(path, &meta);
        let (mut mode, mut uid, mut gid) = (
            now.permissions.unwrap_or(0o644) & 0o7777,
            now.uid.unwrap_or(LOGIN_ID),
            now.gid.unwrap_or(LOGIN_ID),
        );
        if let (Some(new_uid), Some(new_gid)) = (set.uid, set.gid) {
            if (new_uid, new_gid) != (uid, gid) && (new_uid, new_gid) != (LOGIN_ID, LOGIN_ID) {
                self.state.note(format!("sftp chown refused {path}"));
                return Err(StatusCode::PermissionDenied);
            }
            (uid, gid) = (new_uid, new_gid);
        }
        if let Some(permissions) = set.permissions {
            mode = permissions & 0o7777;
        }
        locks::lock(&self.state.sftp_meta).insert(path.to_owned(), (mode, uid, gid));
        Ok(())
    }

    /// H8: moves `from` to `to`, and what SFTP kept for it.
    fn move_file(&self, from: &str, to: &str, replace: bool) -> Result<(), StatusCode> {
        if self.protected(from) || self.protected(to) {
            return Err(StatusCode::PermissionDenied);
        }
        let (old, new) = (local(&self.root, from), local(&self.root, to));
        if !replace && new.exists() {
            // OpenSSH links the new name first, which fails when it is taken.
            return Err(StatusCode::Failure);
        }
        std::fs::rename(&old, &new).map_err(|e| io_status(&e))?;
        let mut meta = locks::lock(&self.state.sftp_meta);
        meta.remove(to);
        if let Some(kept) = meta.remove(from) {
            meta.insert(to.to_owned(), kept);
        }
        Ok(())
    }

    fn open_path(&self, handle: &str) -> Result<String, StatusCode> {
        match self.handles.get(handle) {
            Some(Open::File { path, .. }) => Ok(path.clone()),
            _ => Err(StatusCode::Failure),
        }
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
    attrs_with(meta, None)
}

/// `set`: the mode, uid and gid kept for the path, if any.
fn attrs_with(meta: &std::fs::Metadata, set: Option<(u32, u32, u32)>) -> FileAttributes {
    let kind = if meta.is_dir() { 0o040_000 } else { 0o100_000 };
    let mode = if meta.is_dir() { 0o755 } else { 0o644 };
    let (mode, uid, gid) = set.unwrap_or((mode, LOGIN_ID, LOGIN_ID));
    FileAttributes {
        size: Some(meta.len()),
        uid: Some(uid),
        user: None,
        gid: Some(gid),
        group: None,
        permissions: Some(kind | (mode & 0o7777)),
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
        let mut version = Version::new();
        if !self.state.sftp_no_posix_rename.load(Ordering::SeqCst) {
            version.extensions.insert("posix-rename@openssh.com".into(), "1".into());
        }
        Ok(version)
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![File::dummy(self.path(&path))],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        if self.unreadable(&path, true) {
            return Err(StatusCode::PermissionDenied);
        }
        let meta = std::fs::metadata(self.local(&path)).map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: self.attrs_of(&self.path(&path), &meta),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let path = self.open_path(&handle)?;
        let meta = std::fs::metadata(local(&self.root, &path)).map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: self.attrs_of(&path, &meta),
        })
    }

    async fn fsetstat(&mut self, id: u32, handle: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        let path = self.open_path(&handle)?;
        self.apply(&path, &attrs)?;
        Ok(ok(id))
    }

    async fn setstat(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        let path = self.path(&path);
        if self.protected(&path) {
            return Err(StatusCode::PermissionDenied);
        }
        self.apply(&path, &attrs)?;
        Ok(ok(id))
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        let (from, to) = (self.path(&oldpath), self.path(&newpath));
        self.move_file(&from, &to, false)?;
        self.state.note(format!("sftp rename {from} {to}"));
        Ok(ok(id))
    }

    async fn extended(&mut self, id: u32, request: String, data: Vec<u8>) -> Result<Packet, Self::Error> {
        if request != "posix-rename@openssh.com" || self.state.sftp_no_posix_rename.load(Ordering::SeqCst) {
            return Err(StatusCode::OpUnsupported);
        }
        let (from, to) = two_strings(&data).ok_or(StatusCode::BadMessage)?;
        let (from, to) = (self.path(&from), self.path(&to));
        self.move_file(&from, &to, true)?;
        self.state.note(format!("sftp posix-rename {from} {to}"));
        Ok(Packet::Status(ok(id)))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        if self.unreadable(&path, true) {
            return Err(StatusCode::PermissionDenied);
        }
        let meta = std::fs::symlink_metadata(self.local(&path)).map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: attrs(&meta),
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if self.unreadable(&path, false) {
            self.state.note(format!("sftp refused {}", self.path(&path)));
            return Err(StatusCode::PermissionDenied);
        }
        if locks::lock(&self.state.sftp_endless).contains(&self.path(&path)) {
            let handle = self.handle(Open::Endless { sent: 0 });
            return Ok(Handle { id, handle });
        }
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
            Some(Open::Endless { sent }) => {
                let files = (0..100)
                    .map(|n| {
                        let mut attrs = FileAttributes::empty();
                        attrs.permissions = Some(0o100_644);
                        attrs.size = Some(0);
                        File::new(format!("flood-{}", *sent + n), attrs)
                    })
                    .collect();
                *sent += 100;
                Ok(Name { id, files })
            }
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
        if (writes && self.protected(&path)) || self.unreadable(&path, true) {
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
            Some(Open::Folder { .. } | Open::Endless { .. }) => {}
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
        locks::lock(&self.state.sftp_meta).remove(&path);
        self.state.note(format!("sftp remove {path}"));
        Ok(ok(id))
    }
}

/// Two SSH strings (a 32-bit length, then the bytes), as an extension's request holds them.
fn two_strings(data: &[u8]) -> Option<(String, String)> {
    fn one(data: &[u8]) -> Option<(String, &[u8])> {
        let len = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
        let text = data.get(4..4 + len)?;
        Some((String::from_utf8(text.to_vec()).ok()?, &data[4 + len..]))
    }
    let (first, rest) = one(data)?;
    let (second, _) = one(rest)?;
    Some((first, second))
}
