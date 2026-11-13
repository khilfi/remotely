//! SS-14 (0.8.0 G3): the Files page's left pane, this PC's folders. It only reads: Remotely changes no file on this PC
//! from the Files page in 0.8.0. A folder here is a transfer's source (an upload) or its destination (a download, which
//! keeps every check it has: `save_guard`, Remotely's data folder, the Mark of the Web).
//!
//! * **No path from the window is trusted.** Each listing is kept under an id ([`LocalListing::id`]), and the window
//!   names what it wants by that id and an entry's name ([`LocalAsk::Child`], [`LocalFiles::stage_from`],
//!   [`LocalFiles::folder_of`]): a name must be one the listing found, so `..\` and the like are never joined. A typed
//!   folder is refused when it names a share or a device path (A3, [`path_refusal`]) or isn't a full path, and is
//!   resolved to its final path before anything else is read.
//! * Links, junctions and other reparse points are listed but never opened from here (they may lead anywhere,
//!   another drive or a share), and never staged for an upload. Remotely's own data folder (the database, the vault,
//!   the logs) is never opened either.
//! * Listings are capped like a host's ([`MAX_LISTING`]); hidden files (Windows' hidden attribute or a leading dot)
//!   say so, for the pane's "Hidden files" switch.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapters::remote::{EntryKind, MAX_LISTING};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::untrusted::{path_refusal, PathRefusal};

/// A listing's entries by name: their kind, and whether each is a link.
type Names = HashMap<String, (EntryKind, bool)>;

/// Listings kept for the window's answers, at most, and for how long.
const KEEP_LISTINGS: usize = 400;
const KEEP_FOR: Duration = Duration::from_secs(4 * 3600);

/// What the window asks the local pane to show.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum LocalAsk {
    /// The user's profile folder (the shell knows where it is).
    Home,
    /// The Downloads folder.
    Downloads,
    /// This PC's drives.
    Drives,
    /// A folder typed in the address bar: a full path, checked (A3) and resolved.
    Typed { path: String },
    /// A folder of a listing, by its name there.
    Child { listing: Uuid, name: String },
    /// The folder above a listing's (the drives above a drive's root).
    Parent { listing: Uuid },
    /// A listing's folder again (Refresh).
    Again { listing: Uuid },
}

/// One file or folder on this PC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEntry {
    pub name: String,
    pub kind: EntryKind,
    /// A link, junction or other reparse point: listed, never opened or staged from here.
    pub link: bool,
    /// Windows' hidden attribute, or a name starting with a dot.
    pub hidden: bool,
    pub size: u64,
    /// Seconds since 1970.
    pub modified: Option<u64>,
    /// In the drives view: what kind of drive (`fixed`, `removable`, `network`, `cd`, `ram`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive: Option<&'static str>,
}

/// A folder of this PC as the pane shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalListing {
    /// What the window names this listing by.
    pub id: Uuid,
    /// The folder, as Windows shows it (`C:\Users\alice`); `None` for the drives view.
    pub path: Option<String>,
    /// There is a folder (or the drives) above.
    pub has_parent: bool,
    pub entries: Vec<LocalEntry>,
    /// Why the folder could not be opened; it still has a path, so Up and typed paths go on from there.
    pub error: Option<String>,
    /// More is in it than is listed.
    pub more: bool,
}

/// What a listing remembers for the window's answers.
struct Listed {
    /// `None`: the drives view.
    folder: Option<PathBuf>,
    /// The names found, and whether each is a folder that may be opened (not a link).
    names: Names,
    at: Instant,
}

/// SS-14: this PC's folders for the Files page (`Core.local_files`).
#[derive(Clone)]
pub struct LocalFiles {
    listings: Arc<Mutex<HashMap<Uuid, Listed>>>,
    /// Remotely's own data folder, the logs, as final paths (shared with the terminals' downloads).
    protected: Arc<dyn Fn() -> Vec<PathBuf> + Send + Sync>,
}

/// Seconds since 1970 of a time on this PC.
fn unix_secs(at: SystemTime) -> Option<u64> {
    at.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// A link, a junction or another reparse point.
fn is_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn is_hidden(name: &str, meta: &std::fs::Metadata) -> bool {
    if name.starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        if meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0 {
            return true;
        }
    }
    #[cfg(not(windows))]
    let _ = meta;
    false
}

/// A final path as Windows shows it: without the `\\?\` that `canonicalize` puts in front. A final path on a share
/// (`\\?\UNC\...`, a link that leads to one) is refused.
fn shown_path(real: &Path) -> Result<PathBuf> {
    let text = real.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        if rest.len() >= 3 && rest.as_bytes()[1] == b':' {
            return Ok(PathBuf::from(rest));
        }
        return Err(refused(PathRefusal::NetworkShare));
    }
    if let Some(why) = path_refusal(real) {
        return Err(refused(why));
    }
    Ok(real.to_owned())
}

fn refused(why: PathRefusal) -> CoreError {
    CoreError::InvalidInput(format!(
        "That folder {}, so the Files page doesn't open it.",
        why.describe()
    ))
}

/// `name` is a plain name of an entry: one part, nothing a path could be made of.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['\\', '/', ':', '\0'])
}

/// `path` is `folder` or inside it, compared as Windows compares names (without letter case).
pub(crate) fn lands_in(path: &Path, protected: &[PathBuf]) -> bool {
    let parts = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let at = parts(path);
    protected.iter().any(|folder| {
        let folder = parts(folder);
        at.len() >= folder.len() && at[..folder.len()] == folder[..]
    })
}

impl LocalFiles {
    /// `protected`: Remotely's own data folders, as final paths, read at each listing.
    pub fn new(protected: Arc<dyn Fn() -> Vec<PathBuf> + Send + Sync>) -> Self {
        Self {
            listings: Arc::default(),
            protected,
        }
    }

    fn remember(&self, folder: Option<PathBuf>, entries: &[LocalEntry]) -> Uuid {
        let id = Uuid::new_v4();
        let names = entries.iter().map(|e| (e.name.clone(), (e.kind, e.link))).collect();
        let mut listings = locks::lock(&self.listings);
        listings.retain(|_, l| l.at.elapsed() < KEEP_FOR);
        while listings.len() >= KEEP_LISTINGS {
            let Some(oldest) = listings.iter().min_by_key(|(_, l)| l.at).map(|(id, _)| *id) else {
                break;
            };
            listings.remove(&oldest);
        }
        listings.insert(
            id,
            Listed {
                folder,
                names,
                at: Instant::now(),
            },
        );
        id
    }

    /// The folder a listing showed, and whether `name` (if given) is one of its entries, with its kind and link flag.
    fn listed(&self, listing: Uuid) -> Result<(Option<PathBuf>, Names)> {
        let listings = locks::lock(&self.listings);
        let listed = listings.get(&listing).ok_or_else(|| {
            CoreError::InvalidInput("That folder of this PC is no longer known here; open it again.".into())
        })?;
        Ok((listed.folder.clone(), listed.names.clone()))
    }

    /// SS-14: what the pane shows for `ask`. `home` and `downloads` are the shell's.
    pub fn list(&self, ask: LocalAsk, home: &Path, downloads: &Path) -> Result<LocalListing> {
        let folder = match ask {
            LocalAsk::Home => Some(home.to_owned()),
            LocalAsk::Downloads => Some(downloads.to_owned()),
            LocalAsk::Drives => None,
            LocalAsk::Typed { path } => {
                let path = path.trim().trim_matches('"').trim();
                if path.is_empty() {
                    return Err(CoreError::InvalidInput("Type a folder of this PC.".into()));
                }
                if let Some(why) = path_refusal(path) {
                    return Err(refused(why));
                }
                let path = PathBuf::from(path);
                if !path.is_absolute() {
                    return Err(CoreError::InvalidInput(
                        "Type a full path, starting with a drive (C:\\...).".into(),
                    ));
                }
                Some(path)
            }
            LocalAsk::Child { listing, name } => {
                let (folder, names) = self.listed(listing)?;
                if !plain_name(&name) {
                    return Err(CoreError::InvalidInput("That is not a folder here.".into()));
                }
                match names.get(&name) {
                    Some((EntryKind::Folder, false)) => {}
                    Some((_, true)) => {
                        return Err(CoreError::InvalidInput(format!(
                            "'{name}' is a link or junction, so the Files page doesn't open it: type the folder it \
                             leads to instead."
                        )))
                    }
                    _ => return Err(CoreError::InvalidInput(format!("'{name}' is not a folder here."))),
                }
                Some(match folder {
                    Some(folder) => folder.join(&name),
                    // The drives view's names are `C:` and the like.
                    None => PathBuf::from(format!("{name}\\")),
                })
            }
            LocalAsk::Parent { listing } => {
                let (folder, _) = self.listed(listing)?;
                folder.as_deref().and_then(Path::parent).map(Path::to_owned)
            }
            LocalAsk::Again { listing } => self.listed(listing)?.0,
        };
        match folder {
            None => Ok(self.drives()),
            Some(folder) => self.folder(&folder),
        }
    }

    /// This PC's drives.
    fn drives(&self) -> LocalListing {
        let entries = drive_entries();
        LocalListing {
            id: self.remember(None, &entries),
            path: None,
            has_parent: false,
            entries,
            error: None,
            more: false,
        }
    }

    /// One folder, by any path to it: resolved to its final path, refused for a share or Remotely's data folder.
    fn folder(&self, folder: &Path) -> Result<LocalListing> {
        let real = match std::fs::canonicalize(folder) {
            Ok(real) => real,
            Err(err) => {
                // Not there, or not readable: shown with its path and why, so the pane goes on from there.
                let shown = folder.to_owned();
                if let Some(why) = path_refusal(&shown) {
                    return Err(refused(why));
                }
                let entries = Vec::new();
                return Ok(LocalListing {
                    id: self.remember(Some(shown.clone()), &entries),
                    path: Some(shown.display().to_string()),
                    has_parent: true,
                    entries,
                    error: Some(format!("{} can't be opened: {err}", shown.display())),
                    more: false,
                });
            }
        };
        let shown = shown_path(&real)?;
        if lands_in(&real, &(self.protected)()) {
            return Err(CoreError::InvalidInput(format!(
                "{} is Remotely's own data folder, so the Files page doesn't open it.",
                shown.display()
            )));
        }
        let (entries, more, error) = match read_folder(&shown) {
            Ok((entries, more)) => (entries, more, None),
            Err(err) => (
                Vec::new(),
                false,
                Some(format!("{} can't be opened: {err}", shown.display())),
            ),
        };
        if error.is_none() && !shown.is_dir() {
            return Err(CoreError::InvalidInput(format!("{} is not a folder.", shown.display())));
        }
        Ok(LocalListing {
            id: self.remember(Some(shown.clone()), &entries),
            has_parent: true,
            path: Some(shown.display().to_string()),
            entries,
            error,
            more,
        })
    }

    /// SS-14: the folder a listing showed, for a download into it (the download checks it again: `save_guard`,
    /// Remotely's data folder).
    pub fn folder_of(&self, listing: Uuid) -> Result<PathBuf> {
        self.listed(listing)?.0.ok_or_else(|| {
            CoreError::InvalidInput("Open a folder of this PC first; a drive list holds no files.".into())
        })
    }

    /// SS-14: the files and folders of a listing picked by name, as paths to stage for an upload. Links and what is
    /// neither a file nor a folder are refused.
    pub fn paths_of(&self, listing: Uuid, names: &[String]) -> Result<Vec<PathBuf>> {
        let (folder, found) = self.listed(listing)?;
        let folder = folder.ok_or_else(|| CoreError::InvalidInput("A drive can't be uploaded whole.".into()))?;
        if names.is_empty() {
            return Err(CoreError::InvalidInput("Choose a file or folder of this PC.".into()));
        }
        let mut paths = Vec::with_capacity(names.len());
        for name in names {
            if !plain_name(name) {
                return Err(CoreError::InvalidInput(format!("'{name}' is not in that folder.")));
            }
            match found.get(name) {
                Some((_, true)) => {
                    return Err(CoreError::InvalidInput(format!(
                        "'{name}' is a link or junction, so it isn't uploaded from here: pick what it leads to."
                    )))
                }
                Some((EntryKind::File | EntryKind::Folder, false)) => paths.push(folder.join(name)),
                Some((EntryKind::Other, _)) => {
                    return Err(CoreError::InvalidInput(format!("'{name}' is not a file or a folder.")))
                }
                None => return Err(CoreError::InvalidInput(format!("'{name}' is not in that folder."))),
            }
        }
        Ok(paths)
    }

    /// SS-14: the SHA-256 of a file of a listing, read on a blocking thread.
    pub async fn sha256(&self, listing: Uuid, name: &str) -> Result<String> {
        let path = self
            .paths_of(listing, std::slice::from_ref(&name.to_owned()))?
            .remove(0);
        if !path.is_file() {
            return Err(CoreError::InvalidInput(format!("'{name}' is not a file.")));
        }
        tokio::task::spawn_blocking(move || file_sha256(&path))
            .await
            .map_err(|err| CoreError::InvalidInput(format!("the checksum stopped: {err}")))?
    }
}

/// The SHA-256 of a file on this PC.
pub(crate) fn file_sha256(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// A folder's entries, links not followed, sorted by name; at most [`MAX_LISTING`].
fn read_folder(folder: &Path) -> std::io::Result<(Vec<LocalEntry>, bool)> {
    let mut entries = Vec::new();
    let mut more = false;
    for item in std::fs::read_dir(folder)? {
        let Ok(item) = item else {
            continue;
        };
        if entries.len() >= MAX_LISTING {
            more = true;
            break;
        }
        let name = item.file_name().to_string_lossy().into_owned();
        let Ok(meta) = std::fs::symlink_metadata(item.path()) else {
            continue;
        };
        let link = is_reparse(&meta);
        let kind = if meta.is_dir() {
            EntryKind::Folder
        } else if meta.is_file() {
            EntryKind::File
        } else if link {
            // A link to a folder shows as one; it is never opened from here.
            match std::fs::metadata(item.path()) {
                Ok(target) if target.is_dir() => EntryKind::Folder,
                Ok(target) if target.is_file() => EntryKind::File,
                _ => EntryKind::Other,
            }
        } else {
            EntryKind::Other
        };
        entries.push(LocalEntry {
            hidden: is_hidden(&name, &meta),
            name,
            kind,
            link,
            size: if kind == EntryKind::File { meta.len() } else { 0 },
            modified: meta.modified().ok().and_then(unix_secs),
            drive: None,
        });
    }
    entries.sort_by_key(|e| e.name.to_lowercase());
    Ok((entries, more))
}

/// This PC's drives, by letter.
#[cfg(windows)]
fn drive_entries() -> Vec<LocalEntry> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    // SAFETY: GetLogicalDrives takes nothing and returns a bit mask.
    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for (bit, letter) in (b'A'..=b'Z').enumerate() {
        if mask & (1 << bit) == 0 {
            continue;
        }
        let root: Vec<u16> = format!("{}:\\", char::from(letter))
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `root` is a NUL-terminated UTF-16 string that lives for the call.
        let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
        let drive = match kind {
            2 => "removable",
            3 => "fixed",
            4 => "network",
            5 => "cd",
            6 => "ram",
            _ => continue,
        };
        out.push(LocalEntry {
            name: format!("{}:", char::from(letter)),
            kind: EntryKind::Folder,
            link: false,
            hidden: false,
            size: 0,
            modified: None,
            drive: Some(drive),
        });
    }
    out
}

#[cfg(not(windows))]
fn drive_entries() -> Vec<LocalEntry> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> LocalFiles {
        LocalFiles::new(Arc::new(Vec::new))
    }

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("remotely-local-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("site/css")).unwrap();
        std::fs::write(dir.join("site/index.html"), b"<p>hi</p>").unwrap();
        std::fs::write(dir.join(".env.example"), b"A=1").unwrap();
        dir
    }

    #[test]
    fn a_folder_lists_and_its_children_open_by_name_only() {
        let dir = temp();
        let local = files();
        let top = local
            .list(
                LocalAsk::Typed {
                    path: dir.display().to_string(),
                },
                &dir,
                &dir,
            )
            .unwrap();
        let names: Vec<&str> = top.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec![".env.example", "site"]);
        assert!(top.entries[0].hidden && !top.entries[1].hidden);
        let site = local
            .list(
                LocalAsk::Child {
                    listing: top.id,
                    name: "site".into(),
                },
                &dir,
                &dir,
            )
            .unwrap();
        assert!(site.path.unwrap().ends_with("site"));
        for bad in ["..", "site\\..", "C:\\Windows", "nope", ".env.example"] {
            assert!(
                local
                    .list(
                        LocalAsk::Child {
                            listing: top.id,
                            name: bad.into()
                        },
                        &dir,
                        &dir
                    )
                    .is_err(),
                "{bad}"
            );
        }
        let paths = local.paths_of(top.id, &["site".into(), ".env.example".into()]).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(local.paths_of(top.id, &["..\\x".into()]).is_err());
        assert!(local.paths_of(Uuid::new_v4(), &["site".into()]).is_err());
        let up = local.list(LocalAsk::Parent { listing: site.id }, &dir, &dir).unwrap();
        assert_eq!(up.entries.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn typed_paths_are_checked_before_anything_is_read() {
        let local = files();
        let dir = std::env::temp_dir();
        for bad in [
            r"\\server\share",
            "//server/share",
            r"\\?\C:\Windows",
            r"\\.\PhysicalDrive0",
            "relative\\x",
            "NUL",
        ] {
            assert!(
                local.list(LocalAsk::Typed { path: bad.into() }, &dir, &dir).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn remotelys_own_folder_is_never_opened() {
        let dir = temp();
        let real = std::fs::canonicalize(&dir).unwrap();
        let local = LocalFiles::new(Arc::new(move || vec![real.clone()]));
        let refused = local
            .list(
                LocalAsk::Typed {
                    path: dir.display().to_string(),
                },
                &dir,
                &dir,
            )
            .unwrap_err();
        assert!(refused.to_string().contains("Remotely's own data folder"), "{refused}");
        assert!(local
            .list(
                LocalAsk::Typed {
                    path: dir.join("site").display().to_string()
                },
                &dir,
                &dir
            )
            .is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_files_checksum_is_its_sha256() {
        let dir = temp();
        let local = files();
        let site = local
            .list(
                LocalAsk::Typed {
                    path: dir.join("site").display().to_string(),
                },
                &dir,
                &dir,
            )
            .unwrap();
        let sum = local.sha256(site.id, "index.html").await.unwrap();
        assert_eq!(sum, hex::encode(Sha256::digest(b"<p>hi</p>")));
        assert!(local.sha256(site.id, "css").await.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
