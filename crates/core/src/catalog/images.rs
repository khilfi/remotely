//! VM-20 images: where a new VM's OS comes from.
//!
//! * A **golden VM** and one of its snapshots (for linked clones): by the VM's key and the snapshot's id, which stays
//!   the same when the snapshot is renamed (Workstation's `snapshotN.uid`, VirtualBox's snapshot UUID).
//! * A **cloud image** file that boots with cloud-init: VMDK, OVA or raw; qcow2 too (Rocky and Alma publish only
//!   qcow2), which deploys once the conversion package (CV-03) has turned it into a VMDK or VDI.
//! * An **ISO** to install from.
//! * An **OVA or OVF** appliance, imported as it is.
//!
//! A file's format comes from its extension and is checked against its first bytes (`KDMV` or a disk descriptor for
//! a VMDK, `QFI\xfb` for qcow2, a tar header for an OVA, `CD001` for an ISO); a `.img` is qcow2 or raw by its bytes.
//! Its SHA-256 is taken when it is added, on a blocking thread with progress, since images can be many GB.
//!
//! Paths are refused when [`untrusted::path_refusal`] refuses them (network shares, device paths), before the file
//! system sees them: opening `\\server\share` would send the user's sign-in there. Remotely downloads nothing: the
//! Images tab links to the official download pages in [`IMAGE_SITES`], opened through the desktop shell only when
//! [`checked_site`] allows the address.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};
use uuid::Uuid;

use crate::adapters::hypervisor::Hypervisor;
use crate::error::{CoreError, Result};
use crate::untrusted;

pub const MAX_IMAGE_NAME: usize = 80;
pub const MAX_IMAGE_NOTES: usize = 2000;
pub const MAX_PATH_CHARS: usize = 1024;
/// Images one workspace keeps.
pub const MAX_IMAGES: usize = 500;

/// Where an image's OS comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ImageKind {
    GoldenVm,
    CloudImage,
    Iso,
    Appliance,
}

impl ImageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ImageKind::GoldenVm => "golden_vm",
            ImageKind::CloudImage => "cloud_image",
            ImageKind::Iso => "iso",
            ImageKind::Appliance => "appliance",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "golden_vm" => ImageKind::GoldenVm,
            "cloud_image" => ImageKind::CloudImage,
            "iso" => ImageKind::Iso,
            "appliance" => ImageKind::Appliance,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            ImageKind::GoldenVm => "golden VM",
            ImageKind::CloudImage => "cloud image",
            ImageKind::Iso => "ISO",
            ImageKind::Appliance => "OVA/OVF appliance",
        }
    }

    /// "a cloud image", "an ISO".
    pub fn with_article(self) -> String {
        match self {
            ImageKind::Iso | ImageKind::Appliance => format!("an {}", self.label()),
            ImageKind::GoldenVm | ImageKind::CloudImage => format!("a {}", self.label()),
        }
    }
}

/// An image file's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    Vmdk,
    Ova,
    Ovf,
    Raw,
    Qcow2,
    Iso,
}

impl ImageFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ImageFormat::Vmdk => "vmdk",
            ImageFormat::Ova => "ova",
            ImageFormat::Ovf => "ovf",
            ImageFormat::Raw => "raw",
            ImageFormat::Qcow2 => "qcow2",
            ImageFormat::Iso => "iso",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "vmdk" => ImageFormat::Vmdk,
            "ova" => ImageFormat::Ova,
            "ovf" => ImageFormat::Ovf,
            "raw" => ImageFormat::Raw,
            "qcow2" => ImageFormat::Qcow2,
            "iso" => ImageFormat::Iso,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            ImageFormat::Vmdk => "VMDK",
            ImageFormat::Ova => "OVA",
            ImageFormat::Ovf => "OVF",
            ImageFormat::Raw => "raw",
            ImageFormat::Qcow2 => "qcow2",
            ImageFormat::Iso => "ISO",
        }
    }

    /// The formats an image of `kind` may have.
    pub fn allowed(kind: ImageKind) -> &'static [ImageFormat] {
        match kind {
            ImageKind::GoldenVm => &[],
            ImageKind::CloudImage => &[
                ImageFormat::Vmdk,
                ImageFormat::Ova,
                ImageFormat::Raw,
                ImageFormat::Qcow2,
            ],
            ImageKind::Iso => &[ImageFormat::Iso],
            ImageKind::Appliance => &[ImageFormat::Ova, ImageFormat::Ovf],
        }
    }
}

/// Why a qcow2 image can't deploy yet.
pub const QCOW2_NEEDS_CONVERSION: &str =
    "qcow2 images deploy once they are converted to VMDK or VDI, which arrives with the conversion package (CV-03).";

/// Where an image's OS comes from, with what names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ImageSource {
    /// A VM and one of its snapshots.
    GoldenVm {
        /// The VM's key: its .vmx path, or its VirtualBox UUID.
        vm_key: String,
        /// Workstation's `snapshotN.uid` (as text), or VirtualBox's snapshot UUID.
        snapshot_id: String,
        /// The snapshot's name when the image was added, to say which one it was if it is gone.
        snapshot_name: String,
    },
    CloudImage {
        path: String,
        format: ImageFormat,
    },
    Iso {
        path: String,
    },
    Appliance {
        path: String,
        format: ImageFormat,
    },
}

impl ImageSource {
    pub fn kind(&self) -> ImageKind {
        match self {
            ImageSource::GoldenVm { .. } => ImageKind::GoldenVm,
            ImageSource::CloudImage { .. } => ImageKind::CloudImage,
            ImageSource::Iso { .. } => ImageKind::Iso,
            ImageSource::Appliance { .. } => ImageKind::Appliance,
        }
    }

    /// The file, for the kinds that are one.
    pub fn path(&self) -> Option<&str> {
        match self {
            ImageSource::GoldenVm { .. } => None,
            ImageSource::CloudImage { path, .. } | ImageSource::Iso { path } | ImageSource::Appliance { path, .. } => {
                Some(path)
            }
        }
    }

    pub fn format(&self) -> Option<ImageFormat> {
        match self {
            ImageSource::GoldenVm { .. } => None,
            ImageSource::CloudImage { format, .. } | ImageSource::Appliance { format, .. } => Some(*format),
            ImageSource::Iso { .. } => Some(ImageFormat::Iso),
        }
    }

    /// `cloud image C:\Images\noble.vmdk (VMDK)`, `golden VM ... at snapshot 'base'`, for the audit log.
    pub fn describe(&self, vm_name: Option<&str>) -> String {
        match self {
            ImageSource::GoldenVm {
                vm_key, snapshot_name, ..
            } => format!("golden VM {} at snapshot '{snapshot_name}'", vm_name.unwrap_or(vm_key)),
            other => format!(
                "{} {} ({})",
                other.kind().label(),
                other.path().unwrap_or_default(),
                other.format().map_or("", ImageFormat::label)
            ),
        }
    }
}

/// An image as the Templates page and deploy see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub id: Uuid,
    pub name: String,
    pub source: ImageSource,
    /// The hypervisors it deploys on. A golden VM's is its own.
    pub hypervisors: Vec<Hypervisor>,
    /// An [`super::profiles::OsProfile`] id.
    pub os_profile: String,
    /// Of the file, taken when it was added (lower-case hex). `None` for a golden VM, whose disks change while it
    /// runs; its snapshot is what stays.
    pub sha256: Option<String>,
    /// The file's size when it was added.
    pub size_bytes: Option<u64>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Why it can't deploy now (the file is gone or changed, the VM or snapshot is gone); `None` when it can.
    pub problem: Option<String>,
    /// For a golden VM: the VM's name as the inventory knows it.
    pub vm_name: Option<String>,
}

impl Image {
    pub fn kind(&self) -> ImageKind {
        self.source.kind()
    }
}

/// What the image editor sends to add one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SourceInput {
    /// `snapshot`: the snapshot's path as the VM's snapshot list shows it (VirtualBox: its UUID), or its id.
    GoldenVm {
        vm_key: String,
        snapshot: String,
    },
    CloudImage {
        path: String,
    },
    Iso {
        path: String,
    },
    Appliance {
        path: String,
    },
}

impl SourceInput {
    pub fn kind(&self) -> ImageKind {
        match self {
            SourceInput::GoldenVm { .. } => ImageKind::GoldenVm,
            SourceInput::CloudImage { .. } => ImageKind::CloudImage,
            SourceInput::Iso { .. } => ImageKind::Iso,
            SourceInput::Appliance { .. } => ImageKind::Appliance,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageInput {
    pub name: String,
    pub source: SourceInput,
    /// Empty: every hypervisor the kind allows (a golden VM: its own).
    #[serde(default)]
    pub hypervisors: Vec<Hypervisor>,
    pub os_profile: String,
    #[serde(default)]
    pub notes: Option<String>,
}

/// What can change once an image is added. Its file or VM stays: another one is another image (with its own
/// checksum).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageEdit {
    pub name: String,
    pub hypervisors: Vec<Hypervisor>,
    pub os_profile: String,
    #[serde(default)]
    pub notes: Option<String>,
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

pub(crate) fn clean_image_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return invalid("Give the image a name, such as Ubuntu 24.04 cloud.");
    }
    if name.chars().count() > MAX_IMAGE_NAME {
        return invalid(format!("An image's name can be at most {MAX_IMAGE_NAME} characters."));
    }
    if name.chars().any(|c| c.is_control() || untrusted::is_format_char(c)) {
        return invalid("An image's name can't hold line breaks, tabs or invisible characters.");
    }
    Ok(name.to_owned())
}

pub(crate) fn clean_notes(notes: Option<&str>) -> Result<Option<String>> {
    let Some(notes) = notes.map(str::trim).filter(|n| !n.is_empty()) else {
        return Ok(None);
    };
    if notes.chars().count() > MAX_IMAGE_NOTES {
        return invalid(format!("Notes can be at most {MAX_IMAGE_NOTES} characters."));
    }
    let notes = notes.replace("\r\n", "\n");
    if notes
        .chars()
        .any(|c| (c.is_control() && c != '\n' && c != '\t') || untrusted::is_format_char(c))
    {
        return invalid("Notes can't hold control or invisible characters.");
    }
    Ok(Some(notes))
}

/// The hypervisors an image deploys on: the ones asked for, without repeats, in the app's order; none asked
/// means every one `allowed`.
pub(crate) fn clean_hypervisors(asked: &[Hypervisor], allowed: &[Hypervisor]) -> Result<Vec<Hypervisor>> {
    if asked.is_empty() {
        return Ok(allowed.to_vec());
    }
    let mut out: Vec<Hypervisor> = Hypervisor::ALL.into_iter().filter(|h| asked.contains(h)).collect();
    out.retain(|h| allowed.contains(h));
    if out.len() != Hypervisor::ALL.iter().filter(|h| asked.contains(h)).count() {
        return invalid("A golden VM's image deploys only on the VM's own hypervisor.");
    }
    if out.is_empty() {
        return invalid("Pick the hypervisors the image deploys on.");
    }
    Ok(out)
}

/// Why `path` (one the user picked, or one an FD-07 file names) can't be an image's file, checked before the file
/// system sees it: empty, too long, on a network share or a device path, or not a full path.
pub fn path_problem(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Some("Choose the image's file.".into());
    }
    if trimmed.chars().count() > MAX_PATH_CHARS {
        return Some(format!("A path can be at most {MAX_PATH_CHARS} characters."));
    }
    if let Some(refusal) = untrusted::path_refusal(trimmed) {
        return Some(format!(
            "Remotely doesn't use images that {}: copy it to this PC first.",
            refusal.describe()
        ));
    }
    if trimmed.chars().any(|c| c.is_control() || untrusted::is_format_char(c)) {
        return Some("The path holds control or invisible characters.".into());
    }
    if !is_absolute(trimmed) {
        return Some("Use the file's full path, such as C:\\Images\\noble.vmdk.".into());
    }
    None
}

/// `C:\...` or `C:/...` (the app's paths are Windows paths, whatever runs the tests).
fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/');
    drive || Path::new(path).is_absolute()
}

/// The format a file's extension names, for `kind`. `.img` is qcow2 or raw, which only its bytes tell.
fn format_by_extension(path: &str, kind: ImageKind) -> Result<Option<ImageFormat>> {
    let ext = Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let format = match ext.as_str() {
        "vmdk" => Some(ImageFormat::Vmdk),
        "ova" => Some(ImageFormat::Ova),
        "ovf" => Some(ImageFormat::Ovf),
        "raw" => Some(ImageFormat::Raw),
        "qcow2" => Some(ImageFormat::Qcow2),
        "iso" => Some(ImageFormat::Iso),
        "img" if kind == ImageKind::CloudImage => None,
        _ => {
            return invalid(match kind {
                ImageKind::CloudImage => "A cloud image is a .vmdk, .ova, .img, .raw or .qcow2 file.",
                ImageKind::Iso => "An ISO image is an .iso file.",
                ImageKind::Appliance => "An appliance is an .ova or .ovf file.",
                ImageKind::GoldenVm => "A golden VM has no file.",
            })
        }
    };
    if let Some(format) = format {
        if !ImageFormat::allowed(kind).contains(&format) {
            return invalid(format!(
                "A .{ext} file isn't {}. Pick the kind that matches it.",
                kind.with_article()
            ));
        }
    }
    Ok(format)
}

/// How many bytes [`detect_format`] looks at: an ISO's volume descriptor is at 32 KB.
pub const HEAD_BYTES: usize = 0x8800;

fn starts_with_at(head: &[u8], at: usize, magic: &[u8]) -> bool {
    head.get(at..at + magic.len()) == Some(magic)
}

/// Checks the file's first bytes against the format its extension names (`None`: `.img`, qcow2 or raw by its
/// bytes), and returns the format.
pub fn detect_format(name: &str, by_extension: Option<ImageFormat>, head: &[u8]) -> Result<ImageFormat> {
    let qcow2 = starts_with_at(head, 0, b"QFI\xfb");
    let Some(format) = by_extension else {
        return Ok(if qcow2 { ImageFormat::Qcow2 } else { ImageFormat::Raw });
    };
    let text_start = |h: &[u8]| {
        let h = h.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h);
        let first = h.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(h.len());
        h[first..].to_vec()
    };
    let ok = match format {
        ImageFormat::Vmdk => {
            starts_with_at(head, 0, b"KDMV")
                || starts_with_at(head, 0, b"COWD")
                || String::from_utf8_lossy(&head[..head.len().min(2048)]).contains("Disk DescriptorFile")
        }
        ImageFormat::Qcow2 => qcow2,
        ImageFormat::Ova => starts_with_at(head, 257, b"ustar"),
        ImageFormat::Ovf => {
            let start = text_start(head);
            start.starts_with(b"<") && String::from_utf8_lossy(&start[..start.len().min(4096)]).contains("Envelope")
        }
        ImageFormat::Iso => starts_with_at(head, 0x8001, b"CD001") || starts_with_at(head, 0x8001, b"BEA01"),
        // Raw has no header; a qcow2 named .raw would boot nothing.
        ImageFormat::Raw => !qcow2,
    };
    if ok {
        Ok(format)
    } else {
        invalid(format!(
            "{name} doesn't look like {} file: its first bytes aren't what that format starts with.",
            match format {
                ImageFormat::Ova | ImageFormat::Ovf | ImageFormat::Iso => format!("an {}", format.label()),
                _ => format!("a {}", format.label()),
            }
        ))
    }
}

/// Progress of hashing an image file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashProgress {
    pub done: u64,
    pub total: u64,
}

/// What reading the file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedFile {
    pub path: PathBuf,
    pub format: ImageFormat,
    pub sha256: String,
    pub size_bytes: u64,
}

/// How often progress is reported, at most.
const PROGRESS_EVERY: Duration = Duration::from_millis(200);
const CHUNK: usize = 1024 * 1024;

/// Reads an image file of `kind` once: checks its format and takes its SHA-256, reporting progress and stopping
/// when `cancel` fires. Blocking: run it on a blocking thread. `path` must have passed [`path_problem`].
pub fn hash_file(
    path: &Path,
    kind: ImageKind,
    cancel: &CancellationToken,
    progress: &(dyn Fn(HashProgress) + Send + Sync),
) -> Result<HashedFile> {
    let text = path.to_string_lossy();
    if let Some(problem) = path_problem(&text) {
        return invalid(problem);
    }
    let by_extension = format_by_extension(&text, kind)?;
    let meta = std::fs::metadata(path).map_err(|err| {
        CoreError::InvalidInput(if err.kind() == std::io::ErrorKind::NotFound {
            format!("{} isn't there.", path.display())
        } else {
            format!("{} can't be read: {err}", path.display())
        })
    })?;
    if !meta.is_file() {
        return invalid(format!("{} isn't a file.", path.display()));
    }
    let total = meta.len();
    let mut file = std::fs::File::open(path)
        .map_err(|err| CoreError::InvalidInput(format!("{} can't be opened: {err}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut head: Vec<u8> = Vec::with_capacity(HEAD_BYTES);
    let mut format = None;
    let mut done: u64 = 0;
    let mut last = Instant::now();
    progress(HashProgress { done, total });
    loop {
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return invalid(format!("{} couldn't be read to the end: {err}", path.display())),
        };
        let chunk = &buffer[..read];
        if format.is_none() {
            let want = HEAD_BYTES - head.len();
            head.extend_from_slice(&chunk[..read.min(want)]);
            if head.len() >= HEAD_BYTES {
                format = Some(detect_format(&file_name(path), by_extension, &head)?);
            }
        }
        hasher.update(chunk);
        done += read as u64;
        if last.elapsed() >= PROGRESS_EVERY {
            last = Instant::now();
            progress(HashProgress { done, total });
        }
    }
    let format = match format {
        Some(format) => format,
        None => detect_format(&file_name(path), by_extension, &head)?,
    };
    progress(HashProgress { done, total: done });
    Ok(HashedFile {
        path: path.to_owned(),
        format,
        sha256: hex::encode(hasher.finalize()),
        size_bytes: done,
    })
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

/// Why an added image's file can't be used now, from a quick look (no hashing): refused paths are never looked at.
pub fn file_problem(path: &str, size_bytes: Option<u64>) -> Option<String> {
    if let Some(problem) = path_problem(path) {
        return Some(problem);
    }
    match std::fs::metadata(path) {
        Ok(meta) if !meta.is_file() => Some(format!("{path} isn't a file any more.")),
        Ok(meta) => match size_bytes {
            Some(size) if size != meta.len() => Some(format!(
                "{path} changed since it was added (its size is not the same), so its checksum no longer matches. Add it again."
            )),
            _ => None,
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Some(format!("{path} isn't on this PC.")),
        Err(err) => Some(format!("{path} can't be read: {err}")),
    }
}

// ---- Download pages (an allow-list, like QL-13's manual sites) --------------------------------------------------

/// An official page with cloud images to download.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageSite {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    /// What to pick there.
    pub hint: &'static str,
}

pub const IMAGE_SITES: [ImageSite; 4] = [
    ImageSite {
        id: "ubuntu",
        name: "Ubuntu cloud images",
        url: "https://cloud-images.ubuntu.com/",
        hint: "Each release's current folder has a .vmdk and an .ova (server-cloudimg-amd64).",
    },
    ImageSite {
        id: "debian",
        name: "Debian cloud images",
        url: "https://cloud.debian.org/images/cloud/",
        hint: "The genericcloud images, raw or qcow2, under each release.",
    },
    ImageSite {
        id: "rocky",
        name: "Rocky Linux cloud images",
        url: "https://dl.rockylinux.org/pub/rocky/",
        hint: "A version's images/x86_64 folder: the GenericCloud qcow2.",
    },
    ImageSite {
        id: "alma",
        name: "AlmaLinux cloud images",
        url: "https://repo.almalinux.org/almalinux/",
        hint: "A version's cloud/x86_64/images folder: the GenericCloud qcow2.",
    },
];

/// The download sites a link may open, exactly as named (no other subdomain).
pub const IMAGE_HOSTS: [&str; 4] = [
    "cloud-images.ubuntu.com",
    "cloud.debian.org",
    "dl.rockylinux.org",
    "repo.almalinux.org",
];

/// `url` when it is a page the app may open: https, on one of [`IMAGE_HOSTS`], on the usual port, with no user name
/// or password in it. Anything else is refused, so the link can only ever open those download pages.
pub fn checked_site(url: &str) -> Result<Url> {
    let refused = || CoreError::InvalidInput("Remotely opens only the official cloud image pages on its list.".into());
    let parsed = Url::parse(url.trim()).map_err(|_| refused())?;
    let allowed_host = match parsed.host() {
        Some(Host::Domain(host)) => IMAGE_HOSTS.contains(&host),
        _ => false,
    };
    if parsed.scheme() != "https"
        || !allowed_host
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(refused());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn network_shares_and_device_paths_are_refused_before_the_file_system() {
        for (path, why) in [
            (r"\\fileserver.example.com\images\noble.vmdk", "network share"),
            ("//fileserver.example.com/images/noble.vmdk", "network share"),
            (r"\\?\UNC\fileserver.example.com\images\noble.vmdk", "network share"),
            (r"\\?\C:\Images\noble.vmdk", "device path"),
            (r"\\.\PhysicalDrive0", "device path"),
            (r"C:\Images\NUL", "names a Windows device"),
            ("", "Choose the image's file"),
            (r"Images\noble.vmdk", "full path"),
        ] {
            let problem = path_problem(path).expect(path);
            assert!(problem.contains(why), "{path}: {problem}");
            // The quick check and hashing refuse it the same way; neither looks at the file system (a test must
            // never send a share path there, so a refused path returns before any metadata call).
            assert!(file_problem(path, None).unwrap().contains(why), "{path}");
        }
        let cancel = CancellationToken::new();
        let err = hash_file(
            Path::new(r"\\fileserver.example.com\images\noble.vmdk"),
            ImageKind::CloudImage,
            &cancel,
            &|_| panic!("no progress for a refused path"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("network share"), "{err}");
        assert_eq!(path_problem(r"C:\Images\noble.vmdk"), None);
        assert_eq!(path_problem("C:/Images/noble.vmdk"), None);
    }

    fn head_with(at: usize, magic: &[u8]) -> Vec<u8> {
        let mut head = vec![0u8; HEAD_BYTES];
        head[at..at + magic.len()].copy_from_slice(magic);
        head
    }

    #[test]
    fn formats_are_checked_against_their_first_bytes() {
        let vmdk = head_with(0, b"KDMV");
        assert_eq!(
            detect_format("a.vmdk", Some(ImageFormat::Vmdk), &vmdk).unwrap(),
            ImageFormat::Vmdk
        );
        let descriptor = b"# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicFlat\"\n".to_vec();
        assert_eq!(
            detect_format("a.vmdk", Some(ImageFormat::Vmdk), &descriptor).unwrap(),
            ImageFormat::Vmdk
        );
        let qcow2 = head_with(0, b"QFI\xfb");
        // A .img is what its bytes say: Ubuntu's .img files are qcow2.
        assert_eq!(detect_format("noble.img", None, &qcow2).unwrap(), ImageFormat::Qcow2);
        assert_eq!(detect_format("disk.img", None, &vmdk).unwrap(), ImageFormat::Raw);
        assert_eq!(
            detect_format("a.qcow2", Some(ImageFormat::Qcow2), &qcow2).unwrap(),
            ImageFormat::Qcow2
        );
        let ova = head_with(257, b"ustar");
        assert_eq!(
            detect_format("a.ova", Some(ImageFormat::Ova), &ova).unwrap(),
            ImageFormat::Ova
        );
        let ovf = b"\xef\xbb\xbf  <?xml version=\"1.0\"?>\n<Envelope xmlns=\"http://schemas.dmtf.org/ovf/envelope/1\">"
            .to_vec();
        assert_eq!(
            detect_format("a.ovf", Some(ImageFormat::Ovf), &ovf).unwrap(),
            ImageFormat::Ovf
        );
        let iso = head_with(0x8001, b"CD001");
        assert_eq!(
            detect_format("a.iso", Some(ImageFormat::Iso), &iso).unwrap(),
            ImageFormat::Iso
        );
        assert!(detect_format("a.iso", Some(ImageFormat::Iso), &head_with(0x8001, b"BEA01")).is_ok());

        for (name, format, head, why) in [
            ("a.vmdk", ImageFormat::Vmdk, qcow2.clone(), "doesn't look like a VMDK"),
            ("a.qcow2", ImageFormat::Qcow2, vmdk.clone(), "doesn't look like a qcow2"),
            ("a.ova", ImageFormat::Ova, vmdk.clone(), "doesn't look like an OVA"),
            ("a.iso", ImageFormat::Iso, vec![0u8; 100], "doesn't look like an ISO"),
            ("a.raw", ImageFormat::Raw, qcow2.clone(), "doesn't look like a raw"),
            ("a.ovf", ImageFormat::Ovf, b"hello".to_vec(), "doesn't look like an OVF"),
        ] {
            let err = detect_format(name, Some(format), &head).unwrap_err().to_string();
            assert!(err.contains(why), "{name}: {err}");
        }
    }

    #[test]
    fn extensions_must_match_the_kind() {
        assert_eq!(
            format_by_extension(r"C:\i\a.VMDK", ImageKind::CloudImage).unwrap(),
            Some(ImageFormat::Vmdk)
        );
        assert_eq!(format_by_extension(r"C:\i\a.img", ImageKind::CloudImage).unwrap(), None);
        assert_eq!(
            format_by_extension(r"C:\i\a.ova", ImageKind::Appliance).unwrap(),
            Some(ImageFormat::Ova)
        );
        for (path, kind, why) in [
            (r"C:\i\a.iso", ImageKind::CloudImage, "isn't a cloud image"),
            (r"C:\i\a.vmdk", ImageKind::Iso, "A .vmdk file isn't an ISO"),
            (r"C:\i\a.exe", ImageKind::Iso, "An ISO image is an .iso file"),
            (
                r"C:\i\a.img",
                ImageKind::Appliance,
                "An appliance is an .ova or .ovf file",
            ),
            (r"C:\i\a.vhdx", ImageKind::CloudImage, "A cloud image is a .vmdk"),
            (r"C:\i\a.ovf", ImageKind::CloudImage, "isn't a cloud image"),
        ] {
            let err = format_by_extension(path, kind).unwrap_err().to_string();
            assert!(err.contains(why), "{path}: {err}");
        }
    }

    fn temp_file(name: &str, bytes: &[u8]) -> (PathBuf, impl Drop) {
        struct Gone(PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = std::env::temp_dir().join(format!("remotely-image-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::File::create(&path).unwrap().write_all(bytes).unwrap();
        (path, Gone(dir))
    }

    #[test]
    fn a_file_is_hashed_with_progress_and_its_format_checked() {
        let mut bytes = head_with(0, b"KDMV");
        bytes.extend(std::iter::repeat_n(7u8, 3 * CHUNK + 5));
        let (path, _gone) = temp_file("noble.vmdk", &bytes);
        let seen = Mutex::new(Vec::new());
        let hashed = hash_file(&path, ImageKind::CloudImage, &CancellationToken::new(), &|p| {
            seen.lock().unwrap().push(p);
        })
        .unwrap();
        assert_eq!(hashed.format, ImageFormat::Vmdk);
        assert_eq!(hashed.size_bytes, bytes.len() as u64);
        assert_eq!(hashed.sha256, hex::encode(Sha256::digest(&bytes)));
        let seen = seen.into_inner().unwrap();
        assert_eq!(seen.first().map(|p| p.done), Some(0));
        assert_eq!(
            seen.last(),
            Some(&HashProgress {
                done: bytes.len() as u64,
                total: bytes.len() as u64
            })
        );
        assert_eq!(file_problem(&path.to_string_lossy(), Some(hashed.size_bytes)), None);
        assert!(file_problem(&path.to_string_lossy(), Some(1))
            .unwrap()
            .contains("changed since it was added"));
        let gone = path.with_file_name("gone.vmdk");
        assert!(file_problem(&gone.to_string_lossy(), None)
            .unwrap()
            .contains("isn't on this PC"));

        // A small file is checked on what it has.
        let (iso, _gone_iso) = temp_file("tiny.iso", b"not an iso");
        let err = hash_file(&iso, ImageKind::Iso, &CancellationToken::new(), &|_| {}).unwrap_err();
        assert!(err.to_string().contains("doesn't look like an ISO"), "{err}");
    }

    #[test]
    fn hashing_stops_when_cancelled() {
        let (path, _gone) = temp_file("disk.raw", &vec![1u8; 2 * CHUNK]);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = hash_file(&path, ImageKind::CloudImage, &cancel, &|_| {}).unwrap_err();
        assert!(matches!(err, CoreError::Cancelled), "{err}");
    }

    #[test]
    fn only_the_listed_download_pages_open() {
        for site in IMAGE_SITES {
            assert!(checked_site(site.url).is_ok(), "{}", site.url);
            let host = Url::parse(site.url).unwrap().host_str().unwrap().to_owned();
            assert!(IMAGE_HOSTS.contains(&host.as_str()), "{host}");
        }
        assert_eq!(
            IMAGE_SITES.iter().map(|s| s.id).collect::<Vec<_>>(),
            ["ubuntu", "debian", "rocky", "alma"]
        );
        assert!(checked_site("https://cloud-images.ubuntu.com/noble/current/").is_ok());
        for url in [
            "http://cloud-images.ubuntu.com/",
            "https://example.com/",
            "https://cloud-images.ubuntu.com.example.com/",
            "https://ubuntu.com/",
            "https://www.cloud.debian.org/",
            "https://cloud-images.ubuntu.com@example.com/",
            "https://alice:secret@repo.almalinux.org/",
            "https://dl.rockylinux.org:8443/",
            "file:///C:/Windows/System32/calc.exe",
            "https://192.0.2.10/",
            "",
        ] {
            let err = checked_site(url).expect_err(url);
            assert_eq!(err.code(), "invalid_input", "{url}");
        }
    }

    #[test]
    fn hypervisors_and_text_are_tidied() {
        let both = [Hypervisor::VirtualBox, Hypervisor::Vmware, Hypervisor::Vmware];
        assert_eq!(
            clean_hypervisors(&both, &Hypervisor::ALL).unwrap(),
            [Hypervisor::Vmware, Hypervisor::VirtualBox]
        );
        assert_eq!(
            clean_hypervisors(&[], &[Hypervisor::VirtualBox]).unwrap(),
            [Hypervisor::VirtualBox]
        );
        assert!(clean_hypervisors(&[Hypervisor::Vmware], &[Hypervisor::VirtualBox]).is_err());
        assert!(clean_image_name("noble\u{202e}kdmv").is_err());
        assert_eq!(clean_image_name("  Ubuntu 24.04  ").unwrap(), "Ubuntu 24.04");
        assert_eq!(clean_notes(Some(" a\r\nb ")).unwrap().as_deref(), Some("a\nb"));
        assert_eq!(clean_notes(Some("   ")).unwrap(), None);
        assert!(clean_notes(Some("bell\u{7}")).is_err());
    }
}
