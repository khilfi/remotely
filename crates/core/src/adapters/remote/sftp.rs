//! SS-08: SFTP on a channel of a terminal's own SSH connection, through russh-sftp. The connection
//! is already logged in, so nothing is asked again and no secret is needed here. One SFTP session per
//! connection, opened when first used and opened again after it broke. Errors name the path and the
//! user, never a file's content.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use russh::client;
use russh::ChannelMsg;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::fs::{File, Metadata};
use russh_sftp::client::{Config as SftpConfig, SftpSession};
use russh_sftp::protocol::{FileType, OpenFlags, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{disconnect_reason, EntryKind, Handler, RemoteEntry, RemoteFiles, RemoteRead, RemoteWrite, Shared};
use crate::error::{CoreError, Result};

/// Each SFTP request may take this long before it counts as failed (a slow disk on the host).
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// What a refused upload says to do instead.
const WRITE_ADVICE: &str = " Remotely transfers files as the logged-in user and never uses sudo: upload to a folder you can write to (your home folder, /tmp), then move the file with sudo in the terminal.";

pub(super) struct SftpFiles {
    handle: Arc<client::Handle<Handler>>,
    shared: Arc<Mutex<Shared>>,
    /// The logged-in user, for messages.
    user: String,
    session: tokio::sync::Mutex<Option<Arc<SftpSession>>>,
}

impl SftpFiles {
    pub(super) fn new(handle: Arc<client::Handle<Handler>>, shared: Arc<Mutex<Shared>>, user: String) -> Self {
        Self {
            handle,
            shared,
            user,
            session: tokio::sync::Mutex::new(None),
        }
    }

    async fn lost(&self) -> CoreError {
        let reason = disconnect_reason(&self.shared).await;
        CoreError::Ssh(format!("the connection was lost: {reason}"))
    }

    /// The SFTP session, opened on a new channel when there is none yet.
    async fn sftp(&self) -> Result<Arc<SftpSession>> {
        let mut slot = self.session.lock().await;
        if let Some(session) = slot.as_ref() {
            return Ok(Arc::clone(session));
        }
        if self.handle.is_closed() {
            return Err(self.lost().await);
        }
        let mut channel = self
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
        let config = SftpConfig {
            request_timeout_secs: REQUEST_TIMEOUT_SECS,
            ..SftpConfig::default()
        };
        let session = SftpSession::new_with_config(channel.into_stream(), config)
            .await
            .map_err(|err| CoreError::Sftp(format!("SFTP did not start on the host: {err}")))?;
        let session = Arc::new(session);
        *slot = Some(Arc::clone(&session));
        Ok(session)
    }

    /// After a failure that broke the session (not a refusal), the next call opens a new one.
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
            self.session.lock().await.take();
        }
    }

    /// A plain error for a failed operation on `path`.
    async fn error(&self, err: SftpError, what: &'static str, path: &str) -> CoreError {
        self.forget_if_broken(&err).await;
        if self.handle.is_closed() {
            return self.lost().await;
        }
        match err {
            SftpError::Status(status) => match status.status_code {
                StatusCode::PermissionDenied => CoreError::RemotePermissionDenied {
                    user: self.user.clone(),
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

    async fn entry(&self, session: &SftpSession, folder: &str, name: String, meta: Metadata) -> RemoteEntry {
        let link = meta.file_type() == FileType::Symlink;
        let meta = if link {
            // What the link points to; one that points nowhere is "other".
            session.metadata(join(folder, &name)).await.ok()
        } else {
            Some(meta)
        };
        to_entry(name, meta.as_ref(), link)
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

#[async_trait]
impl RemoteFiles for SftpFiles {
    async fn home(&self) -> Result<String> {
        let session = self.sftp().await?;
        match session.canonicalize(".").await {
            Ok(home) => Ok(home),
            Err(err) => Err(self.error(err, "find the home folder", "").await),
        }
    }

    async fn list(&self, folder: &str) -> Result<Vec<RemoteEntry>> {
        let session = self.sftp().await?;
        let read = match session.read_dir(folder).await {
            Ok(read) => read,
            Err(err) => return Err(self.error(err, "open the folder", folder).await),
        };
        let mut entries = Vec::new();
        for item in read {
            entries.push(self.entry(&session, folder, item.file_name(), item.metadata()).await);
        }
        Ok(entries)
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
        let session = self.sftp().await?;
        let flags = OpenFlags::WRITE
            | OpenFlags::CREATE
            | if replace {
                OpenFlags::TRUNCATE
            } else {
                OpenFlags::EXCLUDE
            };
        match session.open_with_flags(path, flags).await {
            Ok(file) => Ok(Box::new(SftpWrite {
                file,
                path: path.to_owned(),
            })),
            Err(err) => {
                // OpenSSH answers a plain "failure" when an exclusive create finds a file there.
                let refused = matches!(&err, SftpError::Status(s) if s.status_code == StatusCode::Failure);
                if refused && !replace && session.metadata(path).await.is_ok() {
                    return Err(CoreError::RemoteFileExists { path: path.to_owned() });
                }
                Err(self.error(err, "write to", path).await)
            }
        }
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

struct SftpWrite {
    file: File,
    path: String,
}

#[async_trait]
impl RemoteWrite for SftpWrite {
    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.file
            .write_all(data)
            .await
            .map_err(|err| CoreError::Sftp(format!("writing {} on the host failed: {err}", self.path)))
    }

    async fn finish(mut self: Box<Self>) -> Result<()> {
        let path = std::mem::take(&mut self.path);
        self.file
            .shutdown()
            .await
            .map_err(|err| CoreError::Sftp(format!("finishing {path} on the host failed: {err}")))
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
    }
}
