//! FD-09: what the file server serves: one file, or a folder and what is under it. A request's checked parts
//! ([`super::paths`]) are looked up from the root down without following links, and a file is served only once the
//! real path of the opened file (its handle's final path) is still under the root.

use std::path::{Path, PathBuf};

use super::paths::{self, Refused, RequestPath};
use crate::error::{CoreError, Result};

/// The most entries a folder's listing shows.
pub const MAX_LISTING: usize = 1000;

/// The root, as resolved when the server started.
#[derive(Debug, Clone)]
pub enum Served {
    /// A folder (its final path) and everything under it.
    Folder { root: PathBuf },
    /// One file (its final path), served under its own name.
    File { path: PathBuf, name: String },
}

/// What a request found.
#[derive(Debug)]
pub enum Found {
    File {
        file: std::fs::File,
        size: u64,
        /// Its name, for the download's file name.
        name: String,
        /// Where it really is (an upload may be writing it: nothing serves it before it is whole).
        real: PathBuf,
    },
    /// A folder (or the one file at `/`), for HTTP's listing.
    Folder { path: PathBuf },
}

/// One entry of a folder's listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub name: String,
    pub folder: bool,
    pub size: u64,
}

/// A folder's entries, and how many more there were past [`MAX_LISTING`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<ListEntry>,
    pub more: usize,
}

impl Served {
    /// Resolves the chosen file or folder (the user's own choice, from a dialog or the saved settings).
    pub fn open(root: &Path) -> Result<Served> {
        let meta = std::fs::metadata(root)
            .map_err(|err| CoreError::InvalidInput(format!("{} can't be served: {err}", root.display())))?;
        let real = std::fs::canonicalize(root)?;
        if meta.is_dir() {
            Ok(Served::Folder { root: real })
        } else if meta.is_file() {
            let name = real
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| CoreError::InvalidInput(format!("{} has no file name.", root.display())))?;
            Ok(Served::File { path: real, name })
        } else {
            Err(CoreError::InvalidInput(format!(
                "{} is neither a file nor a folder.",
                root.display()
            )))
        }
    }

    /// The served file's or folder's name, for the status.
    pub fn label(&self) -> String {
        match self {
            Served::Folder { root } => display_path(root),
            Served::File { path, .. } => display_path(path),
        }
    }

    pub fn is_folder(&self) -> bool {
        matches!(self, Served::Folder { .. })
    }

    /// Looks the request up and opens what it names. Blocking: run it on a blocking thread.
    pub fn find(&self, request: &RequestPath) -> std::result::Result<Found, Refused> {
        match self {
            Served::File { path, name } => {
                match request.parts.as_slice() {
                    // The one file, by its name (without case, as Windows names are).
                    [one] if !request.folder && one.to_lowercase() == name.to_lowercase() => {}
                    // `/`: HTTP lists the one file.
                    [] if request.folder => return Ok(Found::Folder { path: path.clone() }),
                    _ => return Err(Refused::NotFound),
                }
                let meta = std::fs::symlink_metadata(path).map_err(|_| Refused::NotFound)?;
                if meta.file_type().is_symlink() {
                    return Err(Refused::Link);
                }
                open_regular(path, path, name)
            }
            Served::Folder { root } => {
                let mut current = root.clone();
                let count = request.parts.len();
                for (i, part) in request.parts.iter().enumerate() {
                    current.push(part);
                    let meta = std::fs::symlink_metadata(&current).map_err(|_| Refused::NotFound)?;
                    // A symbolic link or junction (any name-surrogate reparse point) is never followed. Cloud
                    // placeholders (OneDrive) are reparse points too, but not links, so they are served.
                    if meta.file_type().is_symlink() {
                        return Err(Refused::Link);
                    }
                    let last = i + 1 == count;
                    if !last && !meta.is_dir() {
                        return Err(Refused::NotFound);
                    }
                    if last && meta.is_file() && !request.folder {
                        return open_regular(root, &current, part);
                    }
                    if last && !meta.is_dir() {
                        return Err(Refused::NotFound);
                    }
                }
                // The root itself, or a folder under it.
                let real = std::fs::canonicalize(&current).map_err(|_| Refused::NotFound)?;
                if !paths::is_under(root, &real) {
                    return Err(Refused::Link);
                }
                Ok(Found::Folder { path: real })
            }
        }
    }

    /// The names under a folder [`Served::find`] found: folders first, then files, by name without case; links,
    /// devices and names a request couldn't name are left out. Blocking.
    pub fn list(&self, folder: &Path) -> std::io::Result<Listing> {
        let mut entries = Vec::new();
        let mut more = 0usize;
        let names: Vec<ListEntry> = match self {
            Served::File { path, name } => {
                let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                vec![ListEntry {
                    name: name.clone(),
                    folder: false,
                    size,
                }]
            }
            Served::Folder { .. } => {
                let mut found = Vec::new();
                for entry in std::fs::read_dir(folder)? {
                    let Ok(entry) = entry else {
                        continue;
                    };
                    let Ok(kind) = entry.file_type() else {
                        continue;
                    };
                    if kind.is_symlink() || !(kind.is_dir() || kind.is_file()) {
                        continue;
                    }
                    let name = entry.file_name().to_string_lossy().into_owned();
                    // Only what a request can name: a link to it must work.
                    let check = RequestPath {
                        parts: vec![name.clone()],
                        folder: false,
                    };
                    if paths::http_path(&check.encoded()).is_err() {
                        continue;
                    }
                    if found.len() >= MAX_LISTING {
                        more += 1;
                        continue;
                    }
                    let size = if kind.is_file() {
                        entry.metadata().map(|m| m.len()).unwrap_or(0)
                    } else {
                        0
                    };
                    found.push(ListEntry {
                        name,
                        folder: kind.is_dir(),
                        size,
                    });
                }
                found
            }
        };
        entries.extend(names);
        entries.sort_by(|a, b| {
            b.folder
                .cmp(&a.folder)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(Listing { entries, more })
    }
}

/// Opens `path` and serves it only when it is a regular file whose real place is under `root`.
fn open_regular(root: &Path, path: &Path, name: &str) -> std::result::Result<Found, Refused> {
    let file = std::fs::File::open(path).map_err(|_| Refused::NotFound)?;
    let meta = file.metadata().map_err(|_| Refused::NotFound)?;
    if !meta.is_file() {
        return Err(Refused::NotFound);
    }
    let real = real_path(&file, path).map_err(|_| Refused::NotFound)?;
    if !paths::is_under(root, &real) {
        return Err(Refused::Link);
    }
    Ok(Found::File {
        file,
        size: meta.len(),
        name: name.to_owned(),
        real,
    })
}

/// The path Windows has for an open file (its handle's final path, `\\?\C:\...`), the form `canonicalize` gives.
#[cfg(windows)]
pub(crate) fn final_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};

    let handle = HANDLE(file.as_raw_handle());
    let mut buf = vec![0u16; 512];
    for _ in 0..4 {
        // SAFETY: the handle is the open file's, alive for this call; the buffer is ours and its length is passed.
        let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) } as usize;
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len < buf.len() {
            buf.truncate(len);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        buf.resize(len + 1, 0);
    }
    Err(std::io::Error::other("the file's path kept growing"))
}

/// Where an opened file really is: its handle's final path on Windows (no window between the open and the check),
/// the path's canonical form elsewhere (Remotely runs on Windows; this keeps the core building).
pub(crate) fn real_path(file: &std::fs::File, path: &Path) -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    {
        let _ = path;
        final_path(file)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        std::fs::canonicalize(path)
    }
}

/// A final path as people read it: without Windows' `\\?\` in front.
pub fn display_path(path: &Path) -> String {
    let text = path.display().to_string();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        text
    }
}
