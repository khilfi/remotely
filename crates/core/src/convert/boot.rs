//! CV-04 (G1): the first sectors the guest sees on a disk image, read through its format's own map, and what its
//! partition table says about how it boots. A cloud server's export is one image per disk of a server built for
//! KVM; whether its system disk boots with BIOS or UEFI is in its partition table: a GPT with an EFI system
//! partition boots with UEFI (it may have a BIOS boot partition too, as Ubuntu's cloud images do: UEFI still works),
//! an MBR with an EFI system partition (type 0xEF) too, anything else with BIOS.
//!
//! Reads only, and only what maps the disk's first [`BOOT_BYTES`] (LBA 0 to 33: the MBR, the GPT header and 128
//! partition entries): a VMDK's grain directory, grain table and first grain (inflated for a stream-optimized one),
//! a qcow2's L1 and L2 entries and first cluster (inflated when compressed), a VHD's or VDI's block map entry and
//! first block, or a raw disk's start. A disk with a parent (a delta, a differencing or a backed disk), a VHDX,
//! an encrypted disk, or a layout this doesn't follow gives `None`: Remotely can't tell, and the OS profile's
//! firmware stands. The extents a VMDK descriptor names are opened only after [`untrusted::path_refusal`] (A3).

use std::io::{Read, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::formats::DiskFormat;
use crate::catalog::profiles::Firmware;
use crate::untrusted;

/// LBA 0 to 33 at 512 bytes a sector: the MBR, the GPT header and its 128 entries of 128 bytes.
pub const BOOT_BYTES: usize = 34 * 512;
/// A grain, cluster or block read whole is at most this: VMDK grains are 64 KB, qcow2 clusters 64 KB (2 MB at
/// most), VHD and VDI blocks 2 MB (VDI's 1 MB).
const MAX_CHUNK: u64 = 4 << 20;
/// A compressed grain or cluster is at most this many bytes before it is inflated.
const MAX_COMPRESSED: u64 = 8 << 20;

/// What a disk's partition table is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartitionTable {
    /// `GPT` or `MBR`.
    pub kind: &'static str,
    /// An EFI system partition: GPT type C12A7328-F81F-11D2-BA4B-00A0C93EC93B, or MBR type 0xEF.
    pub efi_system: bool,
    /// A GPT BIOS boot partition (GRUB's, for booting a GPT disk with BIOS).
    pub bios_boot: bool,
    /// Partitions in use.
    pub partitions: usize,
    /// A protective MBR whose GPT wasn't where 512-byte sectors put it (a 4K-sector disk): its partitions unread.
    pub unread_gpt: bool,
}

impl PartitionTable {
    /// The firmware the disk boots with, when its table tells: UEFI with an EFI system partition, else BIOS.
    pub fn firmware(&self) -> Option<Firmware> {
        if self.unread_gpt || self.partitions == 0 {
            return None;
        }
        Some(if self.efi_system { Firmware::Efi } else { Firmware::Bios })
    }

    /// "GPT with an EFI system partition", for Inspect and the import's notes.
    pub fn describe(&self) -> String {
        let mut text = self.kind.to_owned();
        if self.efi_system && self.bios_boot {
            text.push_str(" with an EFI system partition and a BIOS boot partition");
        } else if self.efi_system {
            text.push_str(" with an EFI system partition");
        } else if self.bios_boot {
            text.push_str(" with a BIOS boot partition");
        } else if self.partitions == 0 {
            text.push_str(", no partitions");
        }
        text
    }
}

/// The ESP's type GUID as GPT stores it (the first three fields little-endian).
const ESP_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
/// 21686148-6449-6E6F-744E-656564454649 ("Hah!IdontNeedEFI").
const BIOS_BOOT_GUID: [u8; 16] = *b"Hah!IdontNeedEFI";

fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

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

/// Reads the partition table in a disk's first sectors (at least the MBR; [`BOOT_BYTES`] for a GPT's entries).
pub fn read_table(sectors: &[u8]) -> Option<PartitionTable> {
    if sectors.get(512..520) == Some(b"EFI PART".as_slice()) {
        let entries_lba = le_u64(sectors, 512 + 72)?;
        let count = le_u32(sectors, 512 + 80)?.min(1024) as usize;
        let size = le_u32(sectors, 512 + 84)? as usize;
        if !(128..=4096).contains(&size) {
            return None;
        }
        let start = usize::try_from(entries_lba).ok()?.checked_mul(512)?;
        let mut table = PartitionTable {
            kind: "GPT",
            efi_system: false,
            bios_boot: false,
            partitions: 0,
            unread_gpt: false,
        };
        for i in 0..count {
            let at = start.checked_add(i.checked_mul(size)?)?;
            let Some(kind) = sectors.get(at..at.checked_add(16)?) else {
                break;
            };
            if kind.iter().all(|b| *b == 0) {
                continue;
            }
            table.partitions += 1;
            table.efi_system |= kind == ESP_GUID;
            table.bios_boot |= kind == BIOS_BOOT_GUID;
        }
        return Some(table);
    }
    if sectors.get(510..512) != Some([0x55, 0xaa].as_slice()) {
        return None;
    }
    let types: Vec<u8> = (0..4).filter_map(|i| sectors.get(446 + 16 * i + 4).copied()).collect();
    if types.contains(&0xee) {
        // A protective MBR, but no GPT header in sector 1: a disk with 4 KB sectors, whose GPT this doesn't read.
        return Some(PartitionTable {
            kind: "GPT",
            efi_system: false,
            bios_boot: false,
            partitions: 0,
            unread_gpt: true,
        });
    }
    Some(PartitionTable {
        kind: "MBR",
        efi_system: types.contains(&0xef),
        bios_boot: false,
        partitions: types.iter().filter(|t| **t != 0).count(),
        unread_gpt: false,
    })
}

/// One open image file, read at offsets.
struct Image {
    file: tokio::fs::File,
    len: u64,
}

impl Image {
    async fn open(path: &Path) -> Option<Self> {
        if untrusted::path_refusal(path).is_some() {
            return None;
        }
        let file = tokio::fs::File::open(path).await.ok()?;
        let len = file.metadata().await.ok()?.len();
        Some(Self { file, len })
    }

    /// Up to `len` bytes at `offset` (fewer at the file's end).
    async fn at(&mut self, offset: u64, len: u64) -> Option<Vec<u8>> {
        if len > MAX_COMPRESSED {
            return None;
        }
        self.file.seek(SeekFrom::Start(offset)).await.ok()?;
        let mut buf = Vec::new();
        (&mut self.file).take(len).read_to_end(&mut buf).await.ok()?;
        Some(buf)
    }

    /// Exactly `len` bytes at `offset`, or `None`.
    async fn exact(&mut self, offset: u64, len: u64) -> Option<Vec<u8>> {
        let buf = self.at(offset, len).await?;
        (buf.len() as u64 == len).then_some(buf)
    }
}

/// What holds one chunk (a grain, a cluster, a block) of the guest's disk.
enum Chunk {
    /// Never written: zeros.
    Zero,
    /// `len` bytes at this offset of the image file.
    At(u64, u64),
    /// Compressed: `len` bytes at this offset, zlib (`true`, a VMDK grain) or raw deflate (a qcow2 cluster).
    Deflated { offset: u64, len: u64, zlib: bool },
}

/// `base * unit + index * width`, the offset of a table's entry; `None` when a hostile header makes it overflow.
fn entry_at(base: u64, unit: u64, index: u64, width: u64) -> Option<u64> {
    base.checked_mul(unit)?.checked_add(index.checked_mul(width)?)
}

/// How many chunks of `chunk` bytes hold the first [`BOOT_BYTES`]; `None` for a size no format has.
fn chunks_needed(chunk: u64) -> Option<u64> {
    (chunk > 0 && chunk <= MAX_CHUNK).then(|| (BOOT_BYTES as u64).div_ceil(chunk))
}

/// The guest's first [`BOOT_BYTES`] from `chunks`, each `chunk` bytes of the guest's disk, in order.
async fn fill(image: &mut Image, chunk: u64, chunks: Vec<Chunk>) -> Option<Vec<u8>> {
    let size = usize::try_from(chunk).ok()?;
    let mut out = Vec::with_capacity(BOOT_BYTES + size);
    for found in chunks {
        let mut data = match found {
            Chunk::Zero => vec![0u8; size],
            Chunk::At(offset, len) => image.at(offset, len.min(chunk)).await?,
            Chunk::Deflated { offset, len, zlib } => {
                let packed = image.at(offset, len).await?;
                inflate(&packed, zlib, chunk)?
            }
        };
        data.resize(size, 0);
        out.extend_from_slice(&data);
    }
    if out.len() < BOOT_BYTES {
        return None;
    }
    out.truncate(BOOT_BYTES);
    Some(out)
}

/// At most `limit` bytes inflated from `packed`.
fn inflate(packed: &[u8], zlib: bool, limit: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let read = if zlib {
        flate2::read::ZlibDecoder::new(packed).take(limit).read_to_end(&mut out)
    } else {
        flate2::read::DeflateDecoder::new(packed)
            .take(limit)
            .read_to_end(&mut out)
    };
    // A truncated stream still gives what came before the cut, which is all a partition table needs.
    if read.is_err() && out.is_empty() {
        return None;
    }
    Some(out)
}

/// A sparse VMDK's header (`KDMV`), as VMware's spec lays it out.
#[derive(Debug, Clone, Copy)]
struct SparseHeader {
    flags: u32,
    grain_sectors: u64,
    gtes_per_gt: u32,
    rgd_sector: u64,
    gd_sector: u64,
    compression: u16,
}

const GD_AT_END: u64 = u64::MAX;

fn sparse_header(head: &[u8]) -> Option<SparseHeader> {
    if head.get(0..4)? != b"KDMV" {
        return None;
    }
    Some(SparseHeader {
        flags: le_u32(head, 8)?,
        grain_sectors: le_u64(head, 20)?,
        gtes_per_gt: le_u32(head, 44)?,
        rgd_sector: le_u64(head, 48)?,
        gd_sector: le_u64(head, 56)?,
        compression: le_u16(head, 77)?,
    })
}

/// A sparse VMDK extent (monolithicSparse, streamOptimized, twoGbMaxExtentSparse's first extent).
async fn sparse_vmdk(mut image: Image) -> Option<Vec<u8>> {
    let mut header = sparse_header(&image.exact(0, 512).await?)?;
    if header.gd_sector == GD_AT_END {
        // Stream-optimized: the real grain directory is named in the footer, a copy of the header 1 KB before
        // the file's end (then the end-of-stream marker).
        let footer = image.exact(image.len.checked_sub(1024)?, 512).await?;
        header = sparse_header(&footer)?;
    }
    let gd = if header.gd_sector != 0 && header.gd_sector != GD_AT_END {
        header.gd_sector
    } else {
        header.rgd_sector
    };
    if gd == 0 || gd == GD_AT_END || header.gtes_per_gt == 0 || header.gtes_per_gt > 1 << 16 {
        return None;
    }
    // Grains compressed with deflate (a stream-optimized VMDK); another algorithm isn't read.
    let compressed = header.flags & 0x1_0000 != 0;
    if compressed && header.compression != 1 {
        return None;
    }
    let grain = header.grain_sectors.checked_mul(512)?;
    let gtes = u64::from(header.gtes_per_gt);
    let mut chunks = Vec::new();
    for index in 0..chunks_needed(grain)? {
        let gd_entry = image.exact(entry_at(gd, 512, index / gtes, 4)?, 4).await?;
        let gt = u64::from(le_u32(&gd_entry, 0)?);
        if gt == 0 {
            chunks.push(Chunk::Zero);
            continue;
        }
        let gte = image.exact(entry_at(gt, 512, index % gtes, 4)?, 4).await?;
        let sector = u64::from(le_u32(&gte, 0)?);
        let at = sector.checked_mul(512)?;
        // 0: never written; 1: a zero grain (version 2 and on).
        chunks.push(if sector <= 1 {
            Chunk::Zero
        } else if compressed {
            // A grain marker: its LBA (8 bytes) and the compressed size (4), then the data.
            let marker = image.exact(at, 12).await?;
            Chunk::Deflated {
                offset: at.checked_add(12)?,
                len: u64::from(le_u32(&marker, 8)?),
                zlib: true,
            }
        } else {
            Chunk::At(at, grain)
        });
    }
    fill(&mut image, grain, chunks).await
}

/// One extent line of a VMDK descriptor: `RW 41943040 FLAT "web-flat.vmdk" 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Extent {
    sectors: u64,
    kind: String,
    file: Option<String>,
    offset: u64,
}

fn descriptor_extents(text: &str) -> Option<Vec<Extent>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = ["RW ", "RDONLY ", "NOACCESS "]
            .iter()
            .find_map(|p| line.strip_prefix(p))
        else {
            continue;
        };
        let mut words = rest.split_whitespace();
        let sectors = words.next()?.parse().ok()?;
        let kind = words.next()?.to_ascii_uppercase();
        let (file, tail) = match rest.find('"') {
            Some(open) => {
                let after = &rest[open + 1..];
                let close = after.find('"')?;
                (Some(after[..close].to_owned()), &after[close + 1..])
            }
            None => (None, ""),
        };
        let offset = tail.split_whitespace().next().and_then(|o| o.parse().ok()).unwrap_or(0);
        out.push(Extent {
            sectors,
            kind,
            file,
            offset,
        });
    }
    Some(out)
}

/// A VMDK text descriptor: its first extent, when it covers the disk's first sectors and the disk has no parent.
async fn descriptor_vmdk(path: &Path, text: &str) -> Option<Vec<u8>> {
    let has_parent = text.lines().any(|l| {
        let l = l.trim();
        l.starts_with("parentFileNameHint") || (l.starts_with("parentCID") && !l.contains("ffffffff"))
    });
    if has_parent {
        return None;
    }
    let first = descriptor_extents(text)?.into_iter().next()?;
    if first.sectors < (BOOT_BYTES / 512) as u64 {
        return None;
    }
    if first.kind == "ZERO" {
        return Some(vec![0u8; BOOT_BYTES]);
    }
    let folder = path.parent().unwrap_or(Path::new(""));
    let file: PathBuf = crate::vm_settings::vmware::resolve(folder, first.file.as_deref()?);
    if untrusted::path_refusal(&file).is_some() {
        return None;
    }
    let mut image = Image::open(&file).await?;
    match first.kind.as_str() {
        "FLAT" | "VMFS" => {
            let mut data = image.at(first.offset.checked_mul(512)?, BOOT_BYTES as u64).await?;
            data.resize(BOOT_BYTES, 0);
            Some(data)
        }
        "SPARSE" => sparse_vmdk(image).await,
        _ => None,
    }
}

async fn vmdk(path: &Path) -> Option<Vec<u8>> {
    let mut image = Image::open(path).await?;
    let head = image.at(0, 512).await?;
    if head.starts_with(b"KDMV") {
        return sparse_vmdk(image).await;
    }
    // A text descriptor: small (MO-13 reads up to 1 MB of one).
    let text = image.at(0, 1 << 20).await?;
    descriptor_vmdk(path, &String::from_utf8_lossy(&text)).await
}

async fn raw(path: &Path) -> Option<Vec<u8>> {
    let mut image = Image::open(path).await?;
    let mut data = image.at(0, BOOT_BYTES as u64).await?;
    data.resize(BOOT_BYTES, 0);
    Some(data)
}

async fn qcow2(path: &Path) -> Option<Vec<u8>> {
    let mut image = Image::open(path).await?;
    let head = image.exact(0, 112).await?;
    if head.get(0..4)? != b"QFI\xfb" {
        return None;
    }
    let version = be_u32(&head, 4)?;
    // A backing file (the rest is in another file), or encryption: can't tell.
    if be_u64(&head, 8)? != 0 || be_u32(&head, 32)? != 0 {
        return None;
    }
    if version >= 3 {
        let incompatible = be_u64(&head, 72)?;
        // External data file (bit 2), a compression type other than zlib (bit 3), extended L2 entries (bit 4).
        if incompatible & 0b1_1100 != 0 {
            return None;
        }
    }
    let cluster_bits = be_u32(&head, 20)?;
    if !(9..=21).contains(&cluster_bits) {
        return None;
    }
    let l1_offset = be_u64(&head, 40)?;
    let l1_size = u64::from(be_u32(&head, 36)?);
    let cluster = 1u64 << cluster_bits;
    let l2_bits = cluster_bits - 3;
    const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
    let mut chunks = Vec::new();
    for index in 0..chunks_needed(cluster)? {
        let l1_index = index >> l2_bits;
        if l1_index >= l1_size {
            chunks.push(Chunk::Zero);
            continue;
        }
        let l1 = be_u64(&image.exact(entry_at(l1_offset, 1, l1_index, 8)?, 8).await?, 0)?;
        let l2_offset = l1 & OFFSET_MASK;
        if l2_offset == 0 {
            chunks.push(Chunk::Zero);
            continue;
        }
        let l2_index = index & ((1 << l2_bits) - 1);
        let l2 = be_u64(&image.exact(entry_at(l2_offset, 1, l2_index, 8)?, 8).await?, 0)?;
        let host = l2 & OFFSET_MASK;
        chunks.push(if l2 & (1 << 62) != 0 {
            // Compressed: the host offset in the low x bits, then the count of 512-byte sectors less one.
            let x = 62 - (cluster_bits - 8);
            let host = l2 & ((1u64 << x) - 1);
            let sectors = ((l2 >> x) & ((1u64 << (cluster_bits - 8)) - 1)) + 1;
            Chunk::Deflated {
                offset: host,
                len: (sectors * 512).saturating_sub(host & 511),
                zlib: false,
            }
        } else if host == 0 || l2 & 1 != 0 {
            // 0: unallocated; bit 0 (version 3): reads as zeros.
            Chunk::Zero
        } else {
            Chunk::At(host, cluster)
        });
    }
    fill(&mut image, cluster, chunks).await
}

async fn vhd(path: &Path) -> Option<Vec<u8>> {
    let mut image = Image::open(path).await?;
    let head = image.at(0, 512).await?;
    let footer = if head.starts_with(b"conectix") {
        head
    } else {
        image.exact(image.len.checked_sub(512)?, 512).await?
    };
    if footer.get(0..8)? != b"conectix" {
        return None;
    }
    match be_u32(&footer, 60)? {
        // Fixed: the data from the file's start, then the footer.
        2 => raw(path).await,
        3 => {
            let dynamic = image.exact(be_u64(&footer, 16)?, 1024).await?;
            if dynamic.get(0..8)? != b"cxsparse" {
                return None;
            }
            let table = be_u64(&dynamic, 16)?;
            let entries = u64::from(be_u32(&dynamic, 28)?);
            let block = u64::from(be_u32(&dynamic, 32)?);
            // Each block starts with its sector bitmap, a whole number of sectors.
            let bitmap = (block / 512).div_ceil(8).div_ceil(512) * 512;
            let mut chunks = Vec::new();
            for index in 0..chunks_needed(block)? {
                let entry = if index < entries {
                    be_u32(&image.exact(entry_at(table, 1, index, 4)?, 4).await?, 0)?
                } else {
                    u32::MAX
                };
                chunks.push(if entry == u32::MAX {
                    Chunk::Zero
                } else {
                    Chunk::At(entry_at(bitmap, 1, u64::from(entry), 512)?, block)
                });
            }
            fill(&mut image, block, chunks).await
        }
        // Differencing: its parent holds what it doesn't.
        _ => None,
    }
}

async fn vdi(path: &Path) -> Option<Vec<u8>> {
    let mut image = Image::open(path).await?;
    let head = image.exact(0, 0x190).await?;
    if le_u32(&head, 0x40)? != 0xbeda_107f {
        return None;
    }
    // 4: a snapshot's differencing image.
    if le_u32(&head, 0x4c)? == 4 {
        return None;
    }
    let blocks_at = u64::from(le_u32(&head, 0x154)?);
    let data_at = u64::from(le_u32(&head, 0x158)?);
    let block = u64::from(le_u32(&head, 0x178)?);
    let extra = u64::from(le_u32(&head, 0x17c)?);
    let count = u64::from(le_u32(&head, 0x180)?);
    let mut chunks = Vec::new();
    for index in 0..chunks_needed(block)? {
        let entry = if index < count {
            le_u32(&image.exact(entry_at(blocks_at, 1, index, 4)?, 4).await?, 0)?
        } else {
            u32::MAX
        };
        // 0xFFFFFFFF: never written; 0xFFFFFFFE: zeroed.
        chunks.push(if entry >= 0xffff_fffe {
            Chunk::Zero
        } else {
            let stride = block.checked_add(extra)?;
            Chunk::At(
                entry_at(extra, 1, u64::from(entry), stride)?.checked_add(data_at)?,
                block,
            )
        });
    }
    fill(&mut image, block, chunks).await
}

/// The guest's first [`BOOT_BYTES`] of the image at `path`, of `format`; `None` when Remotely can't read them
/// cheaply (see the module's notes).
pub async fn first_sectors(path: &Path, format: DiskFormat) -> Option<Vec<u8>> {
    match format {
        DiskFormat::Raw => raw(path).await,
        DiskFormat::Vmdk => vmdk(path).await,
        DiskFormat::Qcow2 => qcow2(path).await,
        DiskFormat::Vhd => vhd(path).await,
        DiskFormat::Vdi => vdi(path).await,
        DiskFormat::Vhdx => None,
    }
}

/// The partition table at the start of the guest's disk, when it can be read.
pub async fn partition_table(path: &Path, format: DiskFormat) -> Option<PartitionTable> {
    read_table(&first_sectors(path, format).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::disk_images::{self as img, TempFolder};

    const MB: u64 = 1 << 20;

    #[test]
    fn a_gpt_with_an_esp_boots_with_uefi_and_an_mbr_with_bios() {
        let uefi = read_table(&img::boot_sectors(img::Table::GptEsp)).unwrap();
        assert_eq!((uefi.kind, uefi.efi_system), ("GPT", true));
        assert_eq!(uefi.firmware(), Some(Firmware::Efi));
        assert_eq!(uefi.describe(), "GPT with an EFI system partition");
        let hybrid = read_table(&img::boot_sectors(img::Table::GptHybrid)).unwrap();
        assert_eq!(
            hybrid.firmware(),
            Some(Firmware::Efi),
            "Ubuntu's cloud images have both"
        );
        assert!(hybrid.bios_boot);
        let gpt_bios = read_table(&img::boot_sectors(img::Table::GptBiosBoot)).unwrap();
        assert_eq!(gpt_bios.firmware(), Some(Firmware::Bios));
        let mbr = read_table(&img::boot_sectors(img::Table::Mbr)).unwrap();
        assert_eq!((mbr.kind, mbr.firmware()), ("MBR", Some(Firmware::Bios)));
        let mbr_esp = read_table(&img::boot_sectors(img::Table::MbrEsp)).unwrap();
        assert_eq!(mbr_esp.firmware(), Some(Firmware::Efi));
        assert_eq!(read_table(&vec![0u8; BOOT_BYTES]), None, "zeros: no table");
        // A protective MBR whose GPT isn't in sector 1 (4 KB sectors): can't tell.
        let mut protective = vec![0u8; BOOT_BYTES];
        protective[446 + 4] = 0xee;
        protective[510] = 0x55;
        protective[511] = 0xaa;
        assert_eq!(read_table(&protective).unwrap().firmware(), None);
    }

    #[tokio::test]
    async fn the_first_sectors_are_read_through_each_format() {
        let dir = TempFolder::new("boot-sectors");
        let sectors = img::boot_sectors(img::Table::GptEsp);
        let cases: Vec<(&str, Vec<u8>, DiskFormat)> = vec![
            ("disk.raw", img::raw_with(&sectors, 4 * MB), DiskFormat::Raw),
            (
                "sparse.vmdk",
                img::vmdk_sparse_with("sparse.vmdk", &sectors, 64 * MB, false),
                DiskFormat::Vmdk,
            ),
            (
                "stream.vmdk",
                img::vmdk_sparse_with("stream.vmdk", &sectors, 64 * MB, true),
                DiskFormat::Vmdk,
            ),
            (
                "disk.qcow2",
                img::qcow2_with(&sectors, 64 * MB, false),
                DiskFormat::Qcow2,
            ),
            (
                "packed.qcow2",
                img::qcow2_with(&sectors, 64 * MB, true),
                DiskFormat::Qcow2,
            ),
            ("fixed.vhd", img::vhd_fixed_with(&sectors, 2 * MB), DiskFormat::Vhd),
            ("dynamic.vhd", img::vhd_dynamic_with(&sectors, 64 * MB), DiskFormat::Vhd),
            ("disk.vdi", img::vdi_with(&sectors, 64 * MB), DiskFormat::Vdi),
        ];
        for (name, bytes, format) in cases {
            let path = dir.write(name, &bytes);
            let table = partition_table(&path, format).await;
            assert_eq!(
                table.and_then(|t| t.firmware()),
                Some(Firmware::Efi),
                "{name}: {table:?}"
            );
        }
        // A flat VMDK: its descriptor names the extent beside it.
        dir.write("flat-flat.vmdk", &img::raw_with(&sectors, 4 * MB));
        let descriptor = img::vmdk_descriptor("monolithicFlat", &[(8192, "FLAT", "flat-flat.vmdk")], None);
        let path = dir.write("flat.vmdk", descriptor.as_bytes());
        assert_eq!(
            partition_table(&path, DiskFormat::Vmdk)
                .await
                .and_then(|t| t.firmware()),
            Some(Firmware::Efi)
        );
        // A delta names its parent: what it doesn't hold is there, so Remotely can't tell.
        let delta = img::vmdk_descriptor("monolithicFlat", &[(8192, "FLAT", "flat-flat.vmdk")], Some("base.vmdk"));
        let path = dir.write("delta.vmdk", delta.as_bytes());
        assert_eq!(partition_table(&path, DiskFormat::Vmdk).await, None);
        // The fakes' header-only images have nothing written: no table.
        let empty = dir.write("empty.vmdk", &img::vmdk_sparse("empty.vmdk", 64 * MB, false));
        assert_eq!(partition_table(&empty, DiskFormat::Vmdk).await, None);
        let vhdx = dir.write("disk.vhdx", &img::vhdx(64 * MB, false, false));
        assert_eq!(first_sectors(&vhdx, DiskFormat::Vhdx).await, None);
    }

    /// Review of PR #86, P7: offsets from a hostile header overflow in debug builds (and wrap to wrong reads in
    /// release ones). They must read as "can't tell", never panic.
    #[tokio::test]
    async fn hostile_offsets_read_as_cant_tell() {
        let dir = TempFolder::new("boot-hostile");
        let mut sparse = img::vmdk_sparse("h.vmdk", 8 * MB, false);
        sparse[44..48].copy_from_slice(&512u32.to_le_bytes());
        sparse[56..64].copy_from_slice(&(u64::MAX / 256).to_le_bytes());
        let path = dir.write("h.vmdk", &sparse);
        assert_eq!(first_sectors(&path, DiskFormat::Vmdk).await, None);
        let info = crate::convert::inspect::inspect(&path)
            .await
            .expect("Inspect still answers");
        assert_eq!(info.firmware_hint, None);
        // A VDI whose block map points past what a u64 holds.
        let mut vdi = img::vdi_with(&img::boot_sectors(img::Table::GptEsp), 64 * MB);
        vdi[0x178..0x17c].copy_from_slice(&u32::MAX.to_le_bytes());
        vdi[0x17c..0x180].copy_from_slice(&u32::MAX.to_le_bytes());
        let map_at = u32::from_le_bytes(vdi[0x154..0x158].try_into().unwrap()) as usize;
        vdi[map_at..map_at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let path = dir.write("h.vdi", &vdi);
        assert_eq!(first_sectors(&path, DiskFormat::Vdi).await, None);
        // A qcow2 whose L1 table sits at the end of the address space.
        let mut qcow = img::qcow2_with(&img::boot_sectors(img::Table::GptEsp), 64 * MB, false);
        qcow[40..48].copy_from_slice(&(u64::MAX - 3).to_be_bytes());
        let path = dir.write("h.qcow2", &qcow);
        assert_eq!(first_sectors(&path, DiskFormat::Qcow2).await, None);
    }

    #[test]
    fn descriptor_lines_give_each_extent() {
        let text = "createType=\"twoGbMaxExtentFlat\"\nRW 4192256 FLAT \"web-f001.vmdk\" 0\nRW 2048 FLAT \"web f002.vmdk\" 16\nRW 100 ZERO\n";
        let extents = descriptor_extents(text).unwrap();
        assert_eq!(extents.len(), 3);
        assert_eq!(extents[1].file.as_deref(), Some("web f002.vmdk"));
        assert_eq!(extents[1].offset, 16);
        assert_eq!((extents[2].kind.as_str(), extents[2].file.as_deref()), ("ZERO", None));
    }
}
