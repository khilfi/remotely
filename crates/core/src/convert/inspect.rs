//! CV-03 Inspect: what a disk image is, from its own bytes. MO-13's header readers
//! ([`crate::adapters::vm_hardware`]) give VMDK (descriptor, extents, parents), VDI, VHD and qcow2 sizes; this adds
//! VHDX (its region table and metadata), qcow2's backing file and encryption, and a raw disk's partition table.
//!
//! Reads only, and only headers: a few hundred KB at most, never the data. The file is one the user picked; the
//! paths named inside it (a VMDK's extents and parent, a qcow2's backing file) are only opened after
//! [`crate::untrusted::path_refusal`] (A3), and those [`crate::adapters::vm_hardware::read_disk`] opens are
//! checked there already.

use std::io::SeekFrom;
use std::path::Path;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::formats::{size_text, DiskFormat};
use crate::adapters::vm_hardware::{self, DiskHeader};
use crate::error::{CoreError, Result};
use crate::untrusted;

/// What Inspect shows about an image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageInfo {
    pub path: String,
    pub format: DiskFormat,
    /// How it is laid out: `monolithicSparse`, `streamOptimized`, `VDI (dynamic)`, `VHD (fixed)`, `qcow2 v3`...
    pub subformat: Option<String>,
    /// Grows as the guest writes (thin) or takes its whole size (thick), when its format says.
    pub thin: Option<bool>,
    /// The size the guest sees.
    pub virtual_bytes: Option<u64>,
    /// What its files take on this PC (a VMDK's extents and parents included).
    pub on_disk_bytes: Option<u64>,
    /// A VMDK's extents in other files.
    pub extents: Vec<String>,
    /// The disk it was made on (a snapshot's or differencing disk's parent, a qcow2's backing file).
    pub parent: Option<String>,
    /// A VMDK's parents down to its base disk, nearest first.
    pub chain: Vec<String>,
    pub encrypted: bool,
    /// A raw disk's partition table (`MBR`, `GPT`), when it has one.
    pub partition_table: Option<String>,
    /// Why it can't be converted as it is.
    pub problems: Vec<String>,
    /// What else to know.
    pub notes: Vec<String>,
}

impl ImageInfo {
    /// A delta, differencing or backed disk: only the whole chain is the disk.
    pub fn has_parent(&self) -> bool {
        self.parent.is_some()
    }

    /// One line for job notes and the audit log: "VMDK monolithicSparse, 20 GB".
    pub fn describe(&self) -> String {
        let mut text = self.format.label().to_owned();
        if let Some(sub) = &self.subformat {
            if !sub.starts_with(self.format.label()) {
                text.push(' ');
                text.push_str(sub);
            } else {
                text = sub.clone();
            }
        }
        if let Some(bytes) = self.virtual_bytes {
            text.push_str(&format!(", {}", size_text(bytes)));
        }
        text
    }
}

/// The most read of a VHDX's region table and metadata table (64 KB each by the spec).
const VHDX_TABLE: u64 = 64 * 1024;
/// A qcow2 backing file name is at most 1023 bytes (QEMU's own limit).
const MAX_BACKING_NAME: u32 = 1023;

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// A GUID as VHDX stores it: the first three fields little-endian.
fn guid(text: &str) -> [u8; 16] {
    let hex: Vec<u8> = text
        .bytes()
        .filter(|b| *b != b'-')
        .collect::<Vec<u8>>()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0))
        .collect();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&hex[..16]);
    let mut out = raw;
    out[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
    out[4..6].copy_from_slice(&[raw[5], raw[4]]);
    out[6..8].copy_from_slice(&[raw[7], raw[6]]);
    out
}

const METADATA_REGION: &str = "8B7CA206-4790-4B9A-B8FE-575F050F886E";
const FILE_PARAMETERS: &str = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B";
const VIRTUAL_DISK_SIZE: &str = "2FA54224-CD1B-4876-B211-5DBED83BF4B8";

/// What a VHDX's metadata says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdxInfo {
    pub virtual_bytes: u64,
    /// "Leave blocks allocated": a fixed VHDX.
    pub fixed: bool,
    /// A differencing VHDX.
    pub has_parent: bool,
}

async fn read_at(file: &mut tokio::fs::File, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).await?;
    let mut buf = Vec::new();
    file.take(len).read_to_end(&mut buf).await?;
    Ok(buf)
}

/// The metadata region's place, from one region table (`regi` at 192 KB or its copy at 256 KB).
fn metadata_region(table: &[u8]) -> Option<(u64, u32)> {
    if table.get(0..4)? != b"regi" {
        return None;
    }
    let count = le_u32(table, 8)?.min(2047) as usize;
    let wanted = guid(METADATA_REGION);
    (0..count).find_map(|i| {
        let at = 16 + i * 32;
        let entry = table.get(at..at + 32)?;
        (entry[..16] == wanted).then(|| (le_u64(entry, 16).unwrap_or(0), le_u32(entry, 24).unwrap_or(0)))
    })
}

/// Reads a VHDX's virtual size and parameters through its region table and metadata table.
pub async fn read_vhdx(path: &Path) -> Result<VhdxInfo> {
    let unreadable = || CoreError::InvalidInput(format!("{} is not a VHDX Remotely can read.", path.display()));
    let mut file = tokio::fs::File::open(path).await?;
    let mut region = None;
    for at in [0x30000u64, 0x40000] {
        let table = read_at(&mut file, at, VHDX_TABLE).await?;
        if let Some(found) = metadata_region(&table) {
            region = Some(found);
            break;
        }
    }
    let (offset, length) = region.ok_or_else(unreadable)?;
    let table = read_at(&mut file, offset, VHDX_TABLE.min(u64::from(length))).await?;
    if table.get(0..8) != Some(b"metadata".as_slice()) {
        return Err(unreadable());
    }
    let count = usize::from(u16::from_le_bytes([table[10], table[11]])).min(2047);
    let item = |wanted: &str| -> Option<(u32, u32)> {
        let wanted = guid(wanted);
        (0..count).find_map(|i| {
            let at = 32 + i * 32;
            let entry = table.get(at..at + 32)?;
            (entry[..16] == wanted).then(|| (le_u32(entry, 16).unwrap_or(0), le_u32(entry, 20).unwrap_or(0)))
        })
    };
    let (params_at, _) = item(FILE_PARAMETERS).ok_or_else(unreadable)?;
    let (size_at, _) = item(VIRTUAL_DISK_SIZE).ok_or_else(unreadable)?;
    if params_at >= length || size_at >= length {
        return Err(unreadable());
    }
    let params = read_at(&mut file, offset + u64::from(params_at), 8).await?;
    let size = read_at(&mut file, offset + u64::from(size_at), 8).await?;
    let flags = le_u32(&params, 4).ok_or_else(unreadable)?;
    Ok(VhdxInfo {
        virtual_bytes: le_u64(&size, 0).ok_or_else(unreadable)?,
        fixed: flags & 1 != 0,
        has_parent: flags & 2 != 0,
    })
}

/// What a qcow2 header says beyond its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2Info {
    pub version: u32,
    pub backing: Option<String>,
    pub encrypted: bool,
    /// qcow2 v3's external data file (the data is in another file): not converted.
    pub external_data: bool,
}

pub fn parse_qcow2(head: &[u8]) -> Option<Qcow2Info> {
    if head.get(0..4)? != b"QFI\xfb" {
        return None;
    }
    let version = be_u32(head, 4)?;
    let backing_at = be_u64(head, 8)?;
    let backing_len = be_u32(head, 16)?.min(MAX_BACKING_NAME);
    let backing = if backing_at > 0 && backing_len > 0 {
        let start = usize::try_from(backing_at).ok()?;
        let end = start.checked_add(backing_len as usize)?;
        Some(
            head.get(start..end)
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_else(|| "(a backing file)".into()),
        )
    } else {
        None
    };
    let incompatible = if version >= 3 { be_u64(head, 72).unwrap_or(0) } else { 0 };
    Some(Qcow2Info {
        version,
        backing,
        encrypted: be_u32(head, 32).unwrap_or(0) != 0,
        external_data: incompatible & 0b100 != 0,
    })
}

/// A raw disk's partition table: GPT (`EFI PART` in sector 1) or MBR (0x55AA at 510).
pub fn partition_table(head: &[u8]) -> Option<&'static str> {
    if head.get(512..520) == Some(b"EFI PART".as_slice()) {
        return Some("GPT");
    }
    (head.get(510..512) == Some([0x55, 0xaa].as_slice())).then_some("MBR")
}

/// What isn't a disk image, by its bytes: an ISO, an OVA (a tar file) or an OVF.
fn not_a_disk(head: &[u8]) -> Option<&'static str> {
    if head.get(0x8001..0x8006) == Some(b"CD001".as_slice()) {
        return Some("an ISO image (attach it to a VM as a CD/DVD instead)");
    }
    if head.get(257..262) == Some(b"ustar".as_slice()) {
        return Some("an OVA appliance (import it as a VM instead)");
    }
    let text = String::from_utf8_lossy(&head[..head.len().min(2048)]);
    if text.contains("<Envelope") || text.contains("<ovf:Envelope") {
        return Some("an OVF descriptor (import it as a VM instead)");
    }
    None
}

/// The first 64 KB of a file and its size.
async fn head_of(path: &Path) -> Result<(Vec<u8>, u64)> {
    let mut file = tokio::fs::File::open(path).await?;
    let size = file.metadata().await?.len();
    let mut head = Vec::new();
    (&mut file).take(64 * 1024).read_to_end(&mut head).await?;
    Ok((head, size))
}

async fn tail_of(path: &Path, size: u64) -> Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(path).await?;
    Ok(read_at(&mut file, size.saturating_sub(512), 512).await?)
}

/// Inspects the disk image at `path`, which the user picked. An error for a path Remotely won't open, a file that
/// isn't there, or one that isn't a disk image it knows; what keeps a readable image from converting is in
/// [`ImageInfo::problems`].
pub async fn inspect(path: &Path) -> Result<ImageInfo> {
    if let Some(refusal) = untrusted::path_refusal(path) {
        return Err(CoreError::InvalidInput(format!(
            "{} {}, so Remotely doesn't open it.",
            path.display(),
            refusal.describe()
        )));
    }
    let (head, size) = match head_of(path).await {
        Ok(read) => read,
        Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::InvalidInput(format!("{} is not there.", path.display())))
        }
        Err(err) => return Err(err),
    };
    let mut info = ImageInfo {
        path: path.display().to_string(),
        format: DiskFormat::Raw,
        subformat: None,
        thin: None,
        virtual_bytes: None,
        on_disk_bytes: Some(size),
        extents: Vec::new(),
        parent: None,
        chain: Vec::new(),
        encrypted: false,
        partition_table: None,
        problems: Vec::new(),
        notes: Vec::new(),
    };
    if head.starts_with(b"vhdxfile") {
        info.format = DiskFormat::Vhdx;
        match read_vhdx(path).await {
            Ok(vhdx) => {
                info.virtual_bytes = Some(vhdx.virtual_bytes);
                info.thin = Some(!vhdx.fixed);
                info.subformat = Some(if vhdx.fixed { "VHDX (fixed)" } else { "VHDX (dynamic)" }.into());
                if vhdx.has_parent {
                    info.subformat = Some("VHDX (differencing)".into());
                    info.parent = Some("its parent VHDX".into());
                }
            }
            Err(err) => info.problems.push(format!("its metadata can't be read: {err}")),
        }
        finish(&mut info);
        return Ok(info);
    }
    let mut header = vm_hardware::parse_header(&head);
    if header == DiskHeader::Unknown {
        if let Ok(tail) = tail_of(path, size).await {
            if let vhd @ DiskHeader::Vhd { .. } = vm_hardware::parse_header(&tail) {
                header = vhd;
            }
        }
    }
    match header {
        DiskHeader::Vmdk(_) | DiskHeader::SparseVmdk { .. } => {
            info.format = DiskFormat::Vmdk;
            let disk = vm_hardware::read_disk(path).await;
            info.subformat = disk.format.clone();
            info.virtual_bytes = disk.provisioned_bytes;
            info.on_disk_bytes = disk.on_disk_bytes.or(Some(size));
            info.thin = disk.thin;
            info.chain = disk.chain.clone();
            info.parent = disk.chain.first().cloned();
            if let DiskHeader::Vmdk(descriptor) = &header {
                let own = path.file_name().map(|n| n.to_string_lossy().to_lowercase());
                info.extents = descriptor
                    .extents
                    .iter()
                    .filter_map(|(_, name)| name.clone())
                    .filter(|name| Some(name.to_lowercase()) != own)
                    .collect();
                if info.parent.is_none() {
                    info.parent = descriptor.parent.clone();
                }
            }
            if let Some(problem) = disk.problem {
                info.problems.push(problem);
            }
            if head.starts_with(b"KDMV") && info.subformat.is_none() {
                info.subformat = Some("monolithicSparse".into());
            }
        }
        DiskHeader::Vdi {
            capacity_bytes,
            kind,
            differencing,
        } => {
            info.format = DiskFormat::Vdi;
            info.thin = Some(kind != "VDI (fixed)");
            info.subformat = Some(kind);
            info.virtual_bytes = Some(capacity_bytes);
            if differencing {
                info.parent = Some("its parent VDI".into());
            }
        }
        DiskHeader::Vhd {
            capacity_bytes,
            kind,
            differencing,
        } => {
            info.format = DiskFormat::Vhd;
            info.thin = Some(kind != "VHD (fixed)");
            info.subformat = Some(kind);
            info.virtual_bytes = Some(capacity_bytes);
            if differencing {
                info.parent = Some("its parent VHD".into());
            }
        }
        DiskHeader::Qcow2 { capacity_bytes } => {
            info.format = DiskFormat::Qcow2;
            info.virtual_bytes = Some(capacity_bytes);
            info.thin = Some(true);
            match parse_qcow2(&head) {
                Some(qcow) => {
                    info.subformat = Some(format!("qcow2 v{}", qcow.version));
                    info.parent = qcow.backing;
                    info.encrypted = qcow.encrypted;
                    if qcow.external_data {
                        info.problems
                            .push("its data is in an external data file, which Remotely doesn't convert".into());
                    }
                }
                None => info.problems.push("its qcow2 header can't be read".into()),
            }
        }
        DiskHeader::Unknown => {
            if let Some(what) = not_a_disk(&head) {
                return Err(CoreError::InvalidInput(format!(
                    "{} is {what}, not a disk image.",
                    path.display()
                )));
            }
            if DiskFormat::from_extension(path) != Some(DiskFormat::Raw) {
                return Err(CoreError::InvalidInput(format!(
                    "{} isn't a disk image Remotely knows: VMDK, VDI, VHD, VHDX, qcow2 or raw (.raw, .img).",
                    path.display()
                )));
            }
            info.format = DiskFormat::Raw;
            info.virtual_bytes = Some(size);
            info.thin = Some(false);
            info.partition_table = partition_table(&head).map(str::to_owned);
            if info.partition_table.is_none() {
                info.notes.push(
                    "no partition table at its start: check it is a whole disk, not one partition".into(),
                );
            }
            if size % 512 != 0 {
                info.problems
                    .push("its size isn't a whole number of 512-byte sectors, so it isn't a whole disk".into());
            }
        }
    }
    finish(&mut info);
    Ok(info)
}

/// Problems every format shares: a parent (only the whole chain is the disk) and encryption.
fn finish(info: &mut ImageInfo) {
    if info.encrypted {
        info.problems
            .push("it is encrypted: decrypt it where it was made first (Remotely never asks for its key)".into());
    }
    if let Some(parent) = &info.parent {
        // A Workstation snapshot's VMDK delta is flattened with vmware-vdiskmanager (the planner decides); the
        // others need their parent, which a file names by a path Remotely doesn't follow.
        if info.format != DiskFormat::Vmdk {
            info.problems.push(format!(
                "it is a differencing disk on {parent}: convert the whole chain where it was made (or flatten it there first)"
            ));
        }
    }
    if info.virtual_bytes.is_none() && info.problems.is_empty() {
        info.problems.push("its size can't be read from its header".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::disk_images::{self as img, TempFolder};

    const MB: u64 = 1 << 20;

    #[tokio::test]
    async fn every_format_reads_its_size_and_layout() {
        let dir = TempFolder::new("inspect");
        let cases: Vec<(&str, Vec<u8>, DiskFormat, Option<&str>, Option<bool>)> = vec![
            (
                "a.vmdk",
                img::vmdk_sparse("a.vmdk", 64 * MB, false),
                DiskFormat::Vmdk,
                Some("monolithicSparse"),
                Some(true),
            ),
            (
                "s.vmdk",
                img::vmdk_sparse("s.vmdk", 64 * MB, true),
                DiskFormat::Vmdk,
                Some("streamOptimized"),
                Some(true),
            ),
            ("a.vdi", img::vdi(64 * MB, 1), DiskFormat::Vdi, Some("VDI (dynamic)"), Some(true)),
            ("f.vdi", img::vdi(64 * MB, 2), DiskFormat::Vdi, Some("VDI (fixed)"), Some(false)),
            ("f.vhd", img::vhd_fixed(2 * MB), DiskFormat::Vhd, Some("VHD (fixed)"), Some(false)),
            (
                "d.vhd",
                img::vhd_dynamic(64 * MB, false),
                DiskFormat::Vhd,
                Some("VHD (dynamic)"),
                Some(true),
            ),
            ("a.vhdx", img::vhdx(64 * MB, false, false), DiskFormat::Vhdx, Some("VHDX (dynamic)"), Some(true)),
            ("f.vhdx", img::vhdx(64 * MB, true, false), DiskFormat::Vhdx, Some("VHDX (fixed)"), Some(false)),
            ("a.qcow2", img::qcow2(64 * MB, None), DiskFormat::Qcow2, Some("qcow2 v3"), Some(true)),
            ("noble.img", img::qcow2(64 * MB, None), DiskFormat::Qcow2, Some("qcow2 v3"), Some(true)),
            ("disk.raw", img::raw_mbr(2 * MB), DiskFormat::Raw, None, Some(false)),
        ];
        for (name, bytes, format, sub, thin) in cases {
            let path = dir.write(name, &bytes);
            let info = inspect(&path).await.unwrap();
            assert_eq!(info.format, format, "{name}");
            assert_eq!(info.subformat.as_deref(), sub, "{name}");
            assert_eq!(info.thin, thin, "{name}");
            let want = if name.ends_with(".raw") || name == "f.vhd" { 2 * MB } else { 64 * MB };
            assert_eq!(info.virtual_bytes, Some(want), "{name}");
            assert!(info.problems.is_empty(), "{name}: {:?}", info.problems);
            assert!(info.on_disk_bytes.is_some());
        }
        let raw = inspect(&dir.join("disk.raw")).await.unwrap();
        assert_eq!(raw.partition_table.as_deref(), Some("MBR"));
        assert_eq!(raw.describe(), "raw, 2 MB");
        let vhd = inspect(&dir.join("f.vhd")).await.unwrap();
        assert_eq!(vhd.describe(), "VHD (fixed), 2 MB");
    }

    #[tokio::test]
    async fn parents_backing_files_and_encryption_are_problems() {
        let dir = TempFolder::new("inspect-parents");
        let backed = dir.write("child.qcow2", &img::qcow2(64 * MB, Some("base.qcow2")));
        let info = inspect(&backed).await.unwrap();
        assert_eq!(info.parent.as_deref(), Some("base.qcow2"));
        assert!(info.problems[0].contains("differencing disk on base.qcow2"), "{:?}", info.problems);

        let mut encrypted = img::qcow2(64 * MB, None);
        encrypted[35] = 1;
        let info = inspect(&dir.write("enc.qcow2", &encrypted)).await.unwrap();
        assert!(info.encrypted);
        assert!(info.problems[0].contains("encrypted"));

        let info = inspect(&dir.write("diff.vhdx", &img::vhdx(64 * MB, false, true)))
            .await
            .unwrap();
        assert_eq!(info.subformat.as_deref(), Some("VHDX (differencing)"));
        assert!(!info.problems.is_empty());
        let info = inspect(&dir.write("diff.vdi", &img::vdi(64 * MB, 4))).await.unwrap();
        assert!(info.has_parent() && !info.problems.is_empty());
        let info = inspect(&dir.write("diff.vhd", &img::vhd_dynamic(64 * MB, true)))
            .await
            .unwrap();
        assert!(info.has_parent() && !info.problems.is_empty());

        // A Workstation snapshot delta: its chain is read (the planner flattens it with vdiskmanager).
        dir.write("base.vmdk", &img::vmdk_sparse("base.vmdk", 64 * MB, false));
        let delta = img::vmdk_descriptor(
            "monolithicSparse",
            &[(131072, "SPARSE", "base-000001.vmdk")],
            Some("base.vmdk"),
        );
        let path = dir.write("base-000001.vmdk", delta.as_bytes());
        let info = inspect(&path).await.unwrap();
        assert_eq!(info.chain, ["base.vmdk"]);
        assert_eq!(info.parent.as_deref(), Some("base.vmdk"));
        assert_eq!(info.virtual_bytes, Some(64 * MB));
    }

    #[tokio::test]
    async fn what_isnt_a_disk_is_refused_and_shares_are_never_opened() {
        let dir = TempFolder::new("inspect-refused");
        let mut iso = vec![0u8; 0x9000];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        let err = inspect(&dir.write("x.raw", &iso)).await.unwrap_err().to_string();
        assert!(err.contains("an ISO image"), "{err}");
        let err = inspect(&dir.write("notes.txt", b"hello")).await.unwrap_err().to_string();
        assert!(err.contains("isn't a disk image"), "{err}");
        let err = inspect(Path::new(r"\\fileserver.example.com\images\a.vmdk"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("network share"), "{err}");
        let err = inspect(&dir.join("gone.vmdk")).await.unwrap_err().to_string();
        assert!(err.contains("is not there"), "{err}");
        // A raw file that isn't whole sectors.
        let info = inspect(&dir.write("odd.img", &[0u8; 1000])).await.unwrap();
        assert!(info.problems[0].contains("512-byte sectors"));
    }

    #[test]
    fn qcow2_headers_name_their_backing_file() {
        let head = img::qcow2(1 << 30, Some("/var/lib/libvirt/images/base.qcow2"));
        let info = parse_qcow2(&head).unwrap();
        assert_eq!(info.version, 3);
        assert_eq!(info.backing.as_deref(), Some("/var/lib/libvirt/images/base.qcow2"));
        assert!(!info.encrypted && !info.external_data);
        assert_eq!(parse_qcow2(b"nope"), None);
    }
}
