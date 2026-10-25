//! SS-08: SFTP on a channel of a terminal's own SSH connection, through russh-sftp. The connection
//! is already logged in, so nothing is asked again and no secret is needed here. One SFTP session per
//! connection, opened when first used and opened again after it broke, and a second one at the
//! protocol level ([`Raw`]) for what the first can't do: listings that stop at [`MAX_LISTING`] (A9)
//! and OpenSSH's `posix-rename` (H8). Errors name the path and the user, never a file's content.
//!
//! H8: a replaced file is never left half written. The new content goes to a hidden temporary file in
//! the same folder (`.<name>.remotely-<id>.part`, which `*.conf`-style globs and `.d` folders skip),
//! gets the old file's permissions and owner, and then takes its place in one step with
//! `posix-rename@openssh.com`. A server without that extension can't rename over a file, so the old
//! one is renamed to `<name>.<time>.bak` first and kept. A failed or cancelled upload deletes the
//! temporary file and leaves the old one as it was. Through a link, the file it points to is replaced,
//! so the link stays. Only when a replacement can't keep the file as it was (no temporary file can be
//! made in the folder, or the old owner can't be given to it) is the file written over in place, as
//! before, and the result says why ([`Written::InPlace`]). Extended attributes, ACLs and other hard
//! links of the old file are not carried over by a rename.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use russh::client;
use russh::ChannelMsg;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::fs::{File, Metadata};
use russh_sftp::client::{Config as SftpConfig, RawSftpSession, SftpSession};
use russh_sftp::extensions::HardlinkExtension;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags, Packet, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    disconnect_reason, EntryKind, Handler, RemoteEntry, RemoteFiles, RemoteListing, RemoteRead, RemoteWrite, Shared,
    Written, MAX_LISTING,
};
use crate::error::{CoreError, Result};

/// Each SFTP request may take this long before it counts as failed (a slow disk on the host).
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// What a refused upload says to do instead.
const WRITE_ADVICE: &str = " Remotely transfers files as the logged-in user and never uses sudo: upload to a folder you can write to (your home folder, /tmp), then move the file with sudo in the terminal.";

/// H8: OpenSSH's rename that replaces a file that is there; a plain SFTP rename refuses to.
const POSIX_RENAME: &str = "posix-rename@openssh.com";

/// A9: the names of one listing may take this many bytes together. Linux allows 255 per name.
const MAX_LISTING_BYTES: usize = 8 * 1024 * 1024;

/// A9: a listing follows at most this many links to see what they point to; the rest show as links
/// to something unknown.
const MAX_LINKS_FOLLOWED: usize = 2_000;

/// The SFTP sessions of one connection. Clones share them.
#[derive(Clone)]
pub(super) struct SftpFiles {
    inner: Arc<Inner>,
}

struct Inner {
    handle: Arc<client::Handle<Handler>>,
    shared: Arc<Mutex<Shared>>,
    /// The logged-in user, for messages.
    user: String,
    session: tokio::sync::Mutex<Option<Arc<SftpSession>>>,
    raw: tokio::sync::Mutex<Option<Arc<Raw>>>,
}

/// The second SFTP session, at the protocol level.
struct Raw {
    session: RawSftpSession,
    /// The server announced `posix-rename@openssh.com`.
    posix_rename: bool,
}

fn config() -> SftpConfig {
    SftpConfig {
        request_timeout_secs: REQUEST_TIMEOUT_SECS,
        ..SftpConfig::default()
    }
}

impl SftpFiles {
    pub(super) fn new(handle: Arc<client::Handle<Handler>>, shared: Arc<Mutex<Shared>>, user: String) -> Self {
        Self {
            inner: Arc::new(Inner {
                handle,
                shared,
                user,
                session: tokio::sync::Mutex::new(None),
                raw: tokio::sync::Mutex::new(None),
            }),
        }
    }

    async fn lost(&self) -> CoreError {
        let reason = disconnect_reason(&self.inner.shared).await;
        CoreError::Ssh(format!("the connection was lost: {reason}"))
    }

    /// A new channel with the host's SFTP server on it.
    async fn open_stream(&self) -> Result<russh::ChannelStream<client::Msg>> {
        if self.inner.handle.is_closed() {
            return Err(self.lost().await);
        }
        let mut channel = self
            .inner
            .handle
            .channel_open_session()
            .await
            .map_err(|err| CoreError::Sftp(format!("the host did not open a channel for file transfers: {err}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|err| CoreError::Sftp(format!("asking the host for SFTP failed: {err}")))?;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    return Err(CoreError::Sftp(
                        "the host has no SFTP server, so files can't be transferred in this terminal (OpenSSH needs a `Subsystem sftp` line in sshd_config)".into(),
                    ))
                }
                Some(_) => {}
                None => return Err(self.lost().await),
            }
        }
        Ok(channel.into_stream())
    }

    /// The SFTP session, opened on a new channel when there is none yet.
    async fn sftp(&self) -> Result<Arc<SftpSession>> {
        let mut slot = self.inner.session.lock().await;
        if let Some(session) = slot.as_ref() {
            return Ok(Arc::clone(session));
        }
        let stream = self.open_stream().await?;
        let session = SftpSession::new_with_config(stream, config())
            .await
            .map_err(|err| CoreError::Sftp(format!("SFTP did not start on the host: {err}")))?;
        let session = Arc::new(session);
        *slot = Some(Arc::clone(&session));
        Ok(session)
    }

    /// The protocol-level session, opened on a channel of its own when there is none yet.
    async fn raw(&self) -> Result<Arc<Raw>> {
        let mut slot = self.inner.raw.lock().await;
        if let Some(raw) = slot.as_ref() {
            return Ok(Arc::clone(raw));
        }
        let stream = self.open_stream().await?;
        let session = RawSftpSession::new_with_config(stream, config());
        let version = session
            .init()
            .await
            .map_err(|err| CoreError::Sftp(format!("SFTP did not start on the host: {err}")))?;
        let posix_rename = version.extensions.get(POSIX_RENAME).is_some_and(|v| v == "1");
        let raw = Arc::new(Raw { session, posix_rename });
        *slot = Some(Arc::clone(&raw));
        Ok(raw)
    }

    /// After a failure that broke the sessions (not a refusal), the next call opens new ones.
    async fn forget_if_broken(&self, err: &SftpError) {
        let broken = match err {
            SftpError::Status(status) => {
                matches!(
                    status.status_code,
                    StatusCode::ConnectionLost | StatusCode::NoConnection
                )
            }
            SftpError::IO(_) | SftpError::Timeout | SftpError::UnexpectedBehavior(_) => true,
            SftpError::Limited(_) | SftpError::UnexpectedPacket => false,
        };
        if broken {
            self.inner.session.lock().await.take();
            self.inner.raw.lock().await.take();
        }
    }

    /// A plain error for a failed operation on `path`.
    async fn error(&self, err: SftpError, what: &'static str, path: &str) -> CoreError {
        self.forget_if_broken(&err).await;
        if self.inner.handle.is_closed() {
            return self.lost().await;
        }
        match err {
            SftpError::Status(status) => match status.status_code {
                StatusCode::PermissionDenied => CoreError::RemotePermissionDenied {
                    user: self.inner.user.clone(),
                    what,
                    path: path.to_owned(),
                    advice: if what == "write to" { WRITE_ADVICE } else { "" },
                },
                StatusCode::NoSuchFile => CoreError::RemoteNotFound { path: path.to_owned() },
                code => {
                    let said = status.error_message.trim();
                    let said = if said.is_empty() {
                        code.to_string()
                    } else {
                        said.to_owned()
                    };
                    CoreError::Sftp(format!("the host could not {what} {path}: {said}"))
                }
            },
            SftpError::Timeout => CoreError::Sftp(format!(
                "the host did not answer within {REQUEST_TIMEOUT_SECS} s while Remotely tried to {what} {path}"
            )),
            other => CoreError::Sftp(format!("could not {what} {path}: {other}")),
        }
    }

    /// H8: an upload over the file at `path`, through a temporary file where it can keep the old
    /// file as it was ([`Plan::Swap`]), else in place ([`Plan::InPlace`]).
    async fn replace(&self, path: &str) -> Result<Box<dyn RemoteWrite>> {
        let session = self.sftp().await?;
        // Through a link, the file it points to is replaced, so the link stays a link.
        let target = match session.symlink_metadata(path).await {
            Ok(meta) if meta.file_type() == FileType::Symlink => match session.canonicalize(path).await {
                Ok(real) if real != path && real.starts_with('/') => real,
                _ => {
                    return self
                        .in_place(&session, path, "it is a link Remotely could not follow".into())
                        .await
                }
            },
            Ok(_) => path.to_owned(),
            // Gone since the question: a new file after all.
            Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => {
                return self.create(&session, path).await
            }
            Err(err) => return Err(self.error(err, "look at", path).await),
        };
        let old = match session.metadata(&target).await {
            Ok(meta) => meta,
            Err(err) => return Err(self.error(err, "look at", &target).await),
        };
        let (folder, name) = split(&target);
        let temp = join(folder, &temp_name(name));
        let mut attrs = FileAttributes::empty();
        // Only the login can read it until it is complete.
        attrs.permissions = Some(0o600);
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        let file = match session.open_with_flags_and_attributes(&temp, flags, attrs).await {
            Ok(file) => file,
            Err(SftpError::Status(status)) if status.status_code == StatusCode::PermissionDenied => {
                let why = format!(
                    "{} can't create a temporary file in {folder}, so a broken transfer leaves it incomplete",
                    self.inner.user
                );
                return self.in_place(&session, path, why).await;
            }
            Err(err) => return Err(self.error(err, "write to", &temp).await),
        };
        // The temporary file is the login's: give it the old file's owner and group where they differ.
        if let Some((uid, gid)) = owner_to_keep(&old, file.metadata().await.ok().as_ref()) {
            let mut owner = FileAttributes::empty();
            owner.uid = Some(uid);
            owner.gid = Some(gid);
            if file.set_metadata(owner).await.is_err() {
                drop(file);
                let _ = session.remove_file(&temp).await;
                let why = format!(
                    "it belongs to another user or group (uid {uid}, gid {gid}), which a replacement made by {} can't keep, so a broken transfer leaves it incomplete",
                    self.inner.user
                );
                return self.in_place(&session, path, why).await;
            }
        }
        Ok(Box::new(SftpWrite::new(
            self.clone(),
            file,
            temp,
            Plan::Swap {
                target,
                mode: old.permissions.map(|p| p & 0o7777),
            },
        )))
    }

    /// A new file at `path`; fails when one is there.
    async fn create(&self, session: &SftpSession, path: &str) -> Result<Box<dyn RemoteWrite>> {
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        match session.open_with_flags(path, flags).await {
            Ok(file) => Ok(Box::new(SftpWrite::new(
                self.clone(),
                file,
                path.to_owned(),
                Plan::Create,
            ))),
            Err(err) => {
                // OpenSSH answers a plain "failure" when an exclusive create finds a file there.
                let refused = matches!(&err, SftpError::Status(s) if s.status_code == StatusCode::Failure);
                if refused && session.metadata(path).await.is_ok() {
                    return Err(CoreError::RemoteFileExists { path: path.to_owned() });
                }
                Err(self.error(err, "write to", path).await)
            }
        }
    }

    /// The file at `path` written over where it is: emptied, then filled, keeping its owner and
    /// permissions.
    async fn in_place(&self, session: &SftpSession, path: &str, why: String) -> Result<Box<dyn RemoteWrite>> {
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
        match session.open_with_flags(path, flags).await {
            Ok(file) => Ok(Box::new(SftpWrite::new(
                self.clone(),
                file,
                path.to_owned(),
                Plan::InPlace { why },
            ))),
            Err(err) => Err(self.error(err, "write to", path).await),
        }
    }

    /// `from` takes the place of `to` in one step.
    async fn posix_rename(&self, raw: &Raw, from: &str, to: &str) -> std::result::Result<(), SftpError> {
        // The extension's request is two strings, like OpenSSH's hardlink extension.
        let data: Vec<u8> = HardlinkExtension {
            oldpath: from.to_owned(),
            newpath: to.to_owned(),
        }
        .try_into()?;
        match raw.session.extended(POSIX_RENAME, data).await? {
            Packet::Status(status) if status.status_code == StatusCode::Ok => Ok(()),
            Packet::Status(status) => Err(SftpError::Status(status)),
            _ => Err(SftpError::UnexpectedPacket),
        }
    }

    async fn entry(&self, raw: &Raw, folder: &str, name: String, meta: Metadata, follow: bool) -> RemoteEntry {
        let link = meta.file_type() == FileType::Symlink;
        let meta = if !link {
            Some(meta)
        } else if follow {
            // What the link points to; one that points nowhere is "other".
            raw.session.stat(join(folder, &name)).await.ok().map(|a| a.attrs)
        } else {
            None
        };
        to_entry(name, meta.as_ref(), link)
    }
}

/// `(folder, name)` of an absolute path; `/` for a file at the top.
fn split(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some((folder, name)) => (folder, name),
        None => (".", path),
    }
}

/// H8: a hidden name in the same folder, unlikely to be taken. Linux names hold 255 bytes; a long
/// name is shortened (on a character boundary) so the temporary one fits.
fn temp_name(name: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let mut base = name;
    while base.len() > 200 {
        let mut end = 200.min(base.len());
        while !base.is_char_boundary(end) {
            end -= 1;
        }
        base = &base[..end];
    }
    format!(".{base}.remotely-{}.part", &id[..12])
}

/// H8: the backup of `name` for a server without `posix-rename`: `<name>.<UTC time>.bak`.
fn backup_name(name: &str, at: time::OffsetDateTime) -> String {
    let stamp = at
        .format(time::macros::format_description!(
            "[year][month][day]-[hour][minute][second]"
        ))
        .unwrap_or_else(|_| "backup".into());
    format!("{name}.{stamp}.bak")
}

/// H8: the owner and group to give a replacement, when they differ from what the login made.
fn owner_to_keep(old: &Metadata, made: Option<&Metadata>) -> Option<(u32, u32)> {
    let (uid, gid) = (old.uid?, old.gid?);
    match made {
        Some(made) if made.uid == Some(uid) && made.gid == Some(gid) => None,
        _ => Some((uid, gid)),
    }
}

/// `folder/name`, with one `/` between them.
fn join(folder: &str, name: &str) -> String {
    if folder.ends_with('/') {
        format!("{folder}{name}")
    } else {
        format!("{folder}/{name}")
    }
}

fn to_entry(name: String, meta: Option<&Metadata>, link: bool) -> RemoteEntry {
    let kind = match meta.map(Metadata::file_type) {
        Some(FileType::File) => EntryKind::File,
        Some(FileType::Dir) => EntryKind::Folder,
        _ => EntryKind::Other,
    };
    RemoteEntry {
        name,
        kind,
        link,
        size: meta.map_or(0, Metadata::len),
        modified: meta.and_then(|m| m.mtime).map(u64::from),
        mode: meta.and_then(|m| m.permissions).map(|p| p & 0o7777),
    }
}

/// The last part of a path, for an entry's name.
fn file_name(path: &str) -> String {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or(path).to_owned()
}

/// A9: what a listing keeps of the names a host sent: never `.`, `..`, or a name that can't be one
/// (a `/` or NUL in it, or longer than any file system allows), and no more than the caps.
struct Gather {
    names: Vec<(String, Metadata)>,
    bytes: usize,
    more: bool,
}

impl Gather {
    fn new() -> Self {
        Self {
            names: Vec::new(),
            bytes: 0,
            more: false,
        }
    }

    /// False once full.
    fn take(&mut self, name: String, meta: Metadata) -> bool {
        if name == "." || name == ".." || name.is_empty() || name.len() > 4096 || name.contains(['/', '\0']) {
            return true;
        }
        if self.names.len() >= MAX_LISTING || self.bytes + name.len() > MAX_LISTING_BYTES {
            self.more = true;
            return false;
        }
        self.bytes += name.len();
        self.names.push((name, meta));
        true
    }
}

#[async_trait]
impl RemoteFiles for SftpFiles {
    fn user(&self) -> String {
        self.inner.user.clone()
    }

    async fn home(&self) -> Result<String> {
        let session = self.sftp().await?;
        match session.canonicalize(".").await {
            Ok(home) => Ok(home),
            Err(err) => Err(self.error(err, "find the home folder", "").await),
        }
    }

    async fn list(&self, folder: &str) -> Result<RemoteListing> {
        let raw = self.raw().await?;
        let handle = match raw.session.opendir(folder).await {
            Ok(handle) => handle.handle,
            Err(err) => return Err(self.error(err, "open the folder", folder).await),
        };
        let mut gather = Gather::new();
        let read = loop {
            match raw.session.readdir(handle.as_str()).await {
                Ok(batch) => {
                    let full = !batch
                        .files
                        .into_iter()
                        .all(|file| gather.take(file.filename, file.attrs));
                    if full {
                        break Ok(());
                    }
                }
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => break Ok(()),
                Err(err) => break Err(err),
            }
        };
        let _ = raw.session.close(handle).await;
        if let Err(err) = read {
            return Err(self.error(err, "open the folder", folder).await);
        }
        let mut entries = Vec::with_capacity(gather.names.len());
        let mut followed = 0;
        for (name, meta) in gather.names {
            let follow = followed < MAX_LINKS_FOLLOWED;
            if meta.file_type() == FileType::Symlink {
                followed += 1;
            }
            entries.push(self.entry(&raw, folder, name, meta, follow).await);
        }
        Ok(RemoteListing {
            entries,
            more: gather.more,
        })
    }

    async fn stat(&self, path: &str) -> Result<Option<RemoteEntry>> {
        let session = self.sftp().await?;
        match session.metadata(path).await {
            Ok(meta) => Ok(Some(to_entry(file_name(path), Some(&meta), false))),
            Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => Ok(None),
            Err(err) => Err(self.error(err, "look at", path).await),
        }
    }

    async fn read(&self, path: &str) -> Result<Box<dyn RemoteRead>> {
        let session = self.sftp().await?;
        match session.open(path).await {
            Ok(file) => Ok(Box::new(SftpRead {
                file,
                path: path.to_owned(),
            })),
            Err(err) => Err(self.error(err, "read", path).await),
        }
    }

    async fn write(&self, path: &str, replace: bool) -> Result<Box<dyn RemoteWrite>> {
        if replace {
            return self.replace(path).await;
        }
        let session = self.sftp().await?;
        self.create(&session, path).await
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let session = self.sftp().await?;
        match session.remove_file(path).await {
            Ok(()) => Ok(()),
            Err(err) => Err(self.error(err, "delete", path).await),
        }
    }
}

struct SftpRead {
    file: File,
    path: String,
}

#[async_trait]
impl RemoteRead for SftpRead {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.file
            .read(buf)
            .await
            .map_err(|err| CoreError::Sftp(format!("reading {} on the host failed: {err}", self.path)))
    }
}

/// H8: what an upload's file becomes once written.
enum Plan {
    /// A new file, made exclusively at its own name.
    Create,
    /// Written to a temporary file that then replaces `target`, given `mode`.
    Swap { target: String, mode: Option<u32> },
    /// Written over where it is.
    InPlace { why: String },
}

struct SftpWrite {
    files: SftpFiles,
    file: Option<File>,
    /// What is written to: the temporary file of a [`Plan::Swap`].
    path: String,
    plan: Plan,
    /// Finished or aborted; until then, dropping it deletes what it made.
    settled: bool,
}

impl SftpWrite {
    fn new(files: SftpFiles, file: File, path: String, plan: Plan) -> Self {
        Self {
            files,
            file: Some(file),
            path,
            plan,
            settled: false,
        }
    }

    /// Deletes what this write made (a new file, or the temporary one); `Err` says why it stayed.
    async fn remove_made(&self) -> std::result::Result<(), String> {
        let session = self.files.sftp().await.map_err(|err| err.to_string())?;
        match session.remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => Ok(()),
            Err(err) => Err(self.files.error(err, "delete", &self.path).await.to_string()),
        }
    }

    /// The temporary file takes the target's place.
    async fn swap(&self, target: &str, mode: Option<u32>) -> Result<Written> {
        let files = &self.files;
        let session = files.sftp().await?;
        if let Some(mode) = mode {
            let mut attrs = FileAttributes::empty();
            attrs.permissions = Some(mode);
            if let Err(err) = session.set_metadata(&self.path, attrs).await {
                return Err(files.error(err, "set the permissions of", &self.path).await);
            }
        }
        let raw = files.raw().await?;
        if raw.posix_rename {
            return match files.posix_rename(&raw, &self.path, target).await {
                Ok(()) => Ok(Written::Replaced),
                Err(err) => Err(files.error(err, "replace", target).await),
            };
        }
        // No rename over a file: the old one steps aside first, and stays as the backup.
        let (folder, name) = split(target);
        let at = time::OffsetDateTime::now_utc();
        let mut backup = join(folder, &backup_name(name, at));
        let mut n = 1;
        while session.try_exists(&backup).await.unwrap_or(false) && n < 100 {
            backup = join(folder, &format!("{}.{n}", backup_name(name, at)));
            n += 1;
        }
        if let Err(err) = session.rename(target, &backup).await {
            return Err(files.error(err, "rename", target).await);
        }
        if let Err(err) = session.rename(&self.path, target).await {
            let err = files.error(err, "replace", target).await;
            // Put the old file back.
            let back = match files.sftp().await {
                Ok(session) => session.rename(&backup, target).await.is_ok(),
                Err(_) => false,
            };
            return Err(if back {
                err
            } else {
                CoreError::Sftp(format!("{err}; the old file is at {backup} now"))
            });
        }
        Ok(Written::ReplacedKeepingBackup { backup })
    }
}

#[async_trait]
impl RemoteWrite for SftpWrite {
    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Err(CoreError::Sftp(format!("{} is closed", self.path)));
        };
        file.write_all(data)
            .await
            .map_err(|err| CoreError::Sftp(format!("writing {} on the host failed: {err}", self.path)))
    }

    async fn finish(mut self: Box<Self>) -> Result<Written> {
        let closed = match self.file.take() {
            Some(mut file) => file.shutdown().await,
            None => Ok(()),
        };
        let result = match closed {
            Err(err) => Err(CoreError::Sftp(format!(
                "finishing {} on the host failed: {err}",
                self.path
            ))),
            Ok(()) => match &self.plan {
                Plan::Create => Ok(Written::Created),
                Plan::InPlace { why } => Ok(Written::InPlace { why: why.clone() }),
                Plan::Swap { target, mode } => {
                    let (target, mode) = (target.clone(), *mode);
                    self.swap(&target, mode).await
                }
            },
        };
        if result.is_err() && !matches!(self.plan, Plan::InPlace { .. }) {
            // A new file that could not be finished, or a temporary one that did not take the old one's
            // place: neither stays.
            if let Err(why) = self.remove_made().await {
                tracing::warn!(path = %self.path, error = %why, "could not delete an unfinished upload");
            }
        }
        self.settled = true;
        result
    }

    async fn abort(mut self: Box<Self>) -> String {
        // Closed without waiting for the host: the connection may be gone.
        drop(self.file.take());
        self.settled = true;
        match &self.plan {
            Plan::Create => match self.remove_made().await {
                Ok(()) => "nothing was left on the host".to_owned(),
                Err(why) => format!("the partial file could not be deleted: {why}"),
            },
            Plan::Swap { target, .. } => match self.remove_made().await {
                Ok(()) => format!("{target} on the host is as it was"),
                Err(why) => format!(
                    "{target} on the host is as it was, but the temporary file {} could not be deleted: {why}",
                    self.path
                ),
            },
            Plan::InPlace { .. } => format!(
                "{} on the host is incomplete now; upload it again to replace it",
                self.path
            ),
        }
    }
}

impl Drop for SftpWrite {
    /// Neither finished nor aborted (the upload's task ended some other way): what this write made is
    /// deleted in the background, as far as the connection still allows.
    fn drop(&mut self) {
        if self.settled || matches!(self.plan, Plan::InPlace { .. }) {
            return;
        }
        drop(self.file.take());
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let files = self.files.clone();
        let path = std::mem::take(&mut self.path);
        runtime.spawn(async move {
            if let Ok(session) = files.sftp().await {
                let _ = session.remove_file(&path).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_and_name_their_last_part() {
        assert_eq!(join("/srv/www", "index.html"), "/srv/www/index.html");
        assert_eq!(join("/", "etc"), "/etc");
        assert_eq!(file_name("/var/log/syslog"), "syslog");
        assert_eq!(file_name("/home/alice/"), "alice");
        assert_eq!(file_name("notes.txt"), "notes.txt");
        assert_eq!(split("/etc/nginx/nginx.conf"), ("/etc/nginx", "nginx.conf"));
        assert_eq!(split("/motd"), ("/", "motd"));
    }

    #[test]
    fn a_temporary_name_is_hidden_beside_the_file_and_fits() {
        let name = temp_name("nginx.conf");
        assert!(name.starts_with(".nginx.conf.remotely-"), "{name}");
        assert!(name.ends_with(".part"), "{name}");
        assert_ne!(temp_name("nginx.conf"), name, "each one is new");
        let long = "é".repeat(127); // 254 bytes
        let made = temp_name(&long);
        assert!(made.len() <= 255, "{}", made.len());
    }

    #[test]
    fn a_backup_is_named_by_the_time() {
        let at = time::macros::datetime!(2026-10-25 14:30:05 UTC);
        assert_eq!(backup_name("nginx.conf", at), "nginx.conf.20261025-143005.bak");
    }

    #[test]
    fn the_owner_is_given_only_where_it_differs() {
        let mut old = FileAttributes::empty();
        old.uid = Some(0);
        old.gid = Some(33);
        let mut made = FileAttributes::empty();
        made.uid = Some(1000);
        made.gid = Some(1000);
        assert_eq!(owner_to_keep(&old, Some(&made)), Some((0, 33)));
        made.uid = Some(0);
        made.gid = Some(33);
        assert_eq!(owner_to_keep(&old, Some(&made)), None);
        assert_eq!(owner_to_keep(&old, None), Some((0, 33)), "unknown: tried");
        assert_eq!(
            owner_to_keep(&FileAttributes::empty(), None),
            None,
            "the host did not say"
        );
    }

    #[test]
    fn a_listing_skips_impossible_names_and_stops_at_its_caps() {
        let meta = FileAttributes::empty;
        let mut gather = Gather::new();
        for name in [".", "..", "", "a/b", "nul\0", "ok"] {
            assert!(gather.take(name.into(), meta()));
        }
        assert_eq!(gather.names.len(), 1);
        for n in 1..MAX_LISTING {
            assert!(gather.take(format!("f{n}"), meta()));
        }
        assert!(!gather.take("one too many".into(), meta()));
        assert!(gather.more);
        assert_eq!(gather.names.len(), MAX_LISTING);

        let mut gather = Gather::new();
        let big = "x".repeat(4000);
        let mut kept = 0;
        while gather.take(big.clone(), meta()) {
            kept += 1;
        }
        assert!(gather.more);
        assert_eq!(kept, MAX_LISTING_BYTES / 4000);
    }
}
