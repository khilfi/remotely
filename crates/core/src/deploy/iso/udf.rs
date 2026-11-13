//! UDF (ECMA-167 with OSTA's UDF), as Windows ISOs keep every file in it (S3: the ISO 9660 tree holds only
//! README.TXT). Read as untrusted input, only what a lookup needs:
//!
//! * the Anchor Volume Descriptor Pointer (tag 2) at sector 256 and its main volume descriptor sequence (at most
//!   [`MAX_VDS_SECTORS`]): Partition Descriptors (tag 5: number at 22, start at 188, length at 192) and the Logical
//!   Volume Descriptor (tag 6: block size at 212, the File Set Descriptor's long_ad at 248, type 1 partition maps
//!   at 440), up to the Terminating Descriptor (tag 8);
//! * the File Set Descriptor (tag 256), whose root folder's ICB is the long_ad at 400;
//! * File Entries (tag 261) and Extended File Entries (tag 266) with short or long allocation descriptors, or
//!   their data embedded; File Identifier Descriptors (tag 257) with OSTA compressed Unicode names (8 or 16 bits),
//!   matched in any letter case.
//!
//! Every descriptor's tag checksum and location are checked, every block resolved through a partition map and
//! its partition's length, folders capped at [`MAX_DIR_BYTES`], a lookup walks one folder per path part, and
//! allocation descriptor continuations, extended descriptors and unrecorded extents are refused, not followed.

use std::io::{Read, Seek};

use super::{damaged, le16, le32, le64, path_parts, Image, SECTOR};
use crate::error::{CoreError, Result};
use crate::untrusted::size_words;

/// Where the Anchor Volume Descriptor Pointer is (the other copies, at the end, aren't read).
pub const ANCHOR_SECTOR: u64 = 256;
/// The most sectors of the volume descriptor sequence read (Windows ISOs have 16, ending at the sixth).
pub const MAX_VDS_SECTORS: u64 = 64;
/// The largest UDF folder read.
pub const MAX_DIR_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PARTITION_MAPS: u32 = 16;

const TAG_ANCHOR: u16 = 2;
const TAG_POINTER: u16 = 3;
const TAG_PARTITION: u16 = 5;
const TAG_LOGICAL_VOLUME: u16 = 6;
const TAG_TERMINATING: u16 = 8;
const TAG_FILE_SET: u16 = 256;
const TAG_FILE_ID: u16 = 257;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;

/// A block of a partition, as a long_ad names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAddress {
    pub block: u32,
    pub partition_ref: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Partition {
    number: u16,
    start: u32,
    length: u32,
}

/// A UDF volume's partitions and its root folder.
#[derive(Debug, Clone)]
pub struct Udf {
    partitions: Vec<Partition>,
    /// Partition reference -> partition number (type 1 maps only).
    maps: Vec<u16>,
    root: BlockAddress,
}

/// A recorded extent: its first sector in the image and its length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub sector: u64,
    pub bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdfData {
    Extents(Vec<Extent>),
    Embedded(Vec<u8>),
}

/// A file or folder's entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdfFile {
    pub is_dir: bool,
    /// The information length: the file's size.
    pub length: u64,
    pub data: UdfData,
}

/// The tag's checksum: bytes 0 to 15 but byte 4, summed modulo 256.
pub fn tag_checksum(d: &[u8]) -> u8 {
    (0..16)
        .filter(|&i| i != 4)
        .fold(0u8, |sum, i| sum.wrapping_add(d.get(i).copied().unwrap_or(0)))
}

/// A descriptor tag with this id, a right checksum and this location.
fn tag_is(d: &[u8], id: u16, location: u32) -> bool {
    d.len() >= 16 && le16(d, 0) == id && tag_checksum(d) == d[4] && le32(d, 12) == location
}

impl Udf {
    /// Opens the volume: `None` when there is no anchor at sector 256 (not a UDF image).
    pub fn open<R: Read + Seek>(image: &mut Image<R>) -> Result<Option<Udf>> {
        if !image.has_sector(ANCHOR_SECTOR) {
            return Ok(None);
        }
        let anchor = image.sector(ANCHOR_SECTOR, "UDF's anchor")?;
        if !tag_is(&anchor, TAG_ANCHOR, ANCHOR_SECTOR as u32) {
            return Ok(None);
        }
        let vds_bytes = u64::from(le32(&anchor, 16));
        let vds_start = u64::from(le32(&anchor, 20));
        let mut partitions = Vec::new();
        let mut logical: Option<Vec<u8>> = None;
        for i in 0..(vds_bytes / SECTOR).min(MAX_VDS_SECTORS) {
            let n = vds_start + i;
            let d = image.sector(n, "a UDF volume descriptor")?;
            let id = le16(&d, 0);
            if !tag_is(&d, id, n as u32) {
                return Err(damaged("a UDF volume descriptor's tag is damaged"));
            }
            match id {
                TAG_TERMINATING => break,
                TAG_POINTER => return Err(damaged("its UDF volume descriptors continue elsewhere")),
                TAG_PARTITION => partitions.push(Partition {
                    number: le16(&d, 22),
                    start: le32(&d, 188),
                    length: le32(&d, 192),
                }),
                TAG_LOGICAL_VOLUME if logical.is_none() => logical = Some(d),
                _ => {}
            }
        }
        let logical = logical.ok_or_else(|| damaged("its UDF volume has no logical volume descriptor"))?;
        if partitions.is_empty() {
            return Err(damaged("its UDF volume has no partition"));
        }
        let block = le32(&logical, 212);
        if u64::from(block) != SECTOR {
            return Err(damaged(format!("its UDF block size is {block} bytes, not 2048")));
        }
        let table_len = le32(&logical, 264) as usize;
        let count = le32(&logical, 268);
        if count == 0 || count > MAX_PARTITION_MAPS {
            return Err(damaged("its UDF volume has no partition map Remotely reads"));
        }
        let table = logical
            .get(440..440usize.saturating_add(table_len))
            .ok_or_else(|| damaged("its UDF partition maps run past their descriptor"))?;
        let mut maps = Vec::new();
        let mut pos = 0usize;
        for _ in 0..count {
            let (kind, len) = match table.get(pos..pos + 2) {
                Some(b) => (b[0], usize::from(b[1])),
                None => return Err(damaged("its UDF partition maps run past their table")),
            };
            if kind != 1 || len != 6 || pos + len > table.len() {
                return Err(damaged(format!(
                    "it has a UDF partition map of type {kind}, which Remotely doesn't read"
                )));
            }
            maps.push(le16(table, pos + 4));
            pos += len;
        }
        let mut volume = Udf {
            partitions,
            maps,
            root: BlockAddress {
                block: 0,
                partition_ref: 0,
            },
        };
        let file_set = BlockAddress {
            block: le32(&logical, 252),
            partition_ref: le16(&logical, 256),
        };
        let d = volume.block(image, file_set, "UDF's file set descriptor")?;
        if !tag_is(&d, TAG_FILE_SET, file_set.block) {
            return Err(damaged("UDF's file set descriptor is damaged"));
        }
        volume.root = BlockAddress {
            block: le32(&d, 404),
            partition_ref: le16(&d, 408),
        };
        Ok(Some(volume))
    }

    /// The image sector of `address`.
    pub fn sector_of(&self, address: BlockAddress) -> Result<u64> {
        let number = self
            .maps
            .get(usize::from(address.partition_ref))
            .ok_or_else(|| damaged("a UDF address names a partition the volume doesn't have"))?;
        let partition = self
            .partitions
            .iter()
            .find(|p| p.number == *number)
            .ok_or_else(|| damaged("a UDF partition map names a partition the volume doesn't have"))?;
        if address.block >= partition.length {
            return Err(damaged("a UDF address lies past the end of its partition"));
        }
        Ok(u64::from(partition.start) + u64::from(address.block))
    }

    fn block<R: Read + Seek>(&self, image: &mut Image<R>, address: BlockAddress, what: &str) -> Result<Vec<u8>> {
        let sector = self.sector_of(address)?;
        image.sector(sector, what)
    }

    /// The entry (File Entry or Extended File Entry) at `address`.
    pub fn entry<R: Read + Seek>(&self, image: &mut Image<R>, address: BlockAddress) -> Result<UdfFile> {
        let d = self.block(image, address, "a UDF file entry")?;
        let id = le16(&d, 0);
        if (id != TAG_FILE_ENTRY && id != TAG_EXTENDED_FILE_ENTRY) || !tag_is(&d, id, address.block) {
            return Err(damaged("a UDF folder points at something that isn't a file entry"));
        }
        let is_dir = d[27] == 4;
        let ad_type = le16(&d, 34) & 7;
        let length = le64(&d, 56);
        let (ea_len, ad_len, base) = if id == TAG_FILE_ENTRY {
            (le32(&d, 168), le32(&d, 172), 176usize)
        } else {
            (le32(&d, 208), le32(&d, 212), 216usize)
        };
        let start = base.checked_add(ea_len as usize);
        let end = start.and_then(|s| s.checked_add(ad_len as usize));
        let ads = match (start, end) {
            (Some(start), Some(end)) if end <= d.len() => &d[start..end],
            _ => return Err(damaged("a UDF file entry's allocation descriptors run past it")),
        };
        let data = match ad_type {
            0 | 1 => {
                let step = if ad_type == 0 { 8 } else { 16 };
                let mut extents = Vec::new();
                for ad in ads.chunks_exact(step) {
                    let raw = le32(ad, 0);
                    let bytes = raw & 0x3FFF_FFFF;
                    if bytes == 0 {
                        break;
                    }
                    if raw >> 30 != 0 {
                        return Err(damaged(
                            "a UDF file has an extent that isn't recorded data, which Remotely doesn't read",
                        ));
                    }
                    let at = if ad_type == 0 {
                        BlockAddress {
                            block: le32(ad, 4),
                            partition_ref: address.partition_ref,
                        }
                    } else {
                        BlockAddress {
                            block: le32(ad, 4),
                            partition_ref: le16(ad, 8),
                        }
                    };
                    extents.push(Extent {
                        sector: self.sector_of(at)?,
                        bytes,
                    });
                }
                let recorded: u64 = extents.iter().map(|e| u64::from(e.bytes)).sum();
                if recorded < length {
                    return Err(damaged("a UDF file's extents are shorter than the file"));
                }
                UdfData::Extents(extents)
            }
            3 => {
                let len = usize::try_from(length).unwrap_or(usize::MAX);
                match ads.get(..len) {
                    Some(bytes) => UdfData::Embedded(bytes.to_vec()),
                    None => return Err(damaged("a UDF file's embedded data is shorter than the file")),
                }
            }
            _ => {
                return Err(damaged(
                    "a UDF file uses extended allocation descriptors, which Remotely doesn't read",
                ))
            }
        };
        Ok(UdfFile { is_dir, length, data })
    }

    /// A file's bytes, at most `cap`.
    pub fn read<R: Read + Seek>(&self, image: &mut Image<R>, file: &UdfFile, cap: u64) -> Result<Vec<u8>> {
        if file.length > cap {
            return Err(CoreError::InvalidInput(format!(
                "A file on the ISO is larger than {}, so Remotely didn't read it.",
                size_words(cap)
            )));
        }
        match &file.data {
            UdfData::Embedded(bytes) => Ok(bytes.clone()),
            UdfData::Extents(extents) => {
                let mut out = Vec::new();
                let mut left = file.length;
                for extent in extents {
                    if left == 0 {
                        break;
                    }
                    let take = left.min(u64::from(extent.bytes));
                    let offset = extent
                        .sector
                        .checked_mul(SECTOR)
                        .ok_or_else(|| damaged("a UDF extent lies past the end of the image"))?;
                    out.extend(image.read_at(offset, take, "a UDF file's data")?);
                    left -= take;
                }
                Ok(out)
            }
        }
    }

    /// A folder's entries: (name, its entry's address, is a folder). Deleted and parent entries are left out, and
    /// so are names that aren't 8- or 16-bit compressed Unicode.
    pub fn list<R: Read + Seek>(
        &self,
        image: &mut Image<R>,
        folder: &UdfFile,
    ) -> Result<Vec<(String, BlockAddress, bool)>> {
        if folder.length > MAX_DIR_BYTES {
            return Err(damaged(format!(
                "a UDF folder is larger than the {} Remotely reads",
                size_words(MAX_DIR_BYTES)
            )));
        }
        let data = self.read(image, folder, MAX_DIR_BYTES)?;
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 38 <= data.len() {
            let fid = &data[pos..];
            if le16(fid, 0) != TAG_FILE_ID || tag_checksum(fid) != fid[4] {
                return Err(damaged("a UDF folder holds something that isn't a file identifier"));
            }
            let characteristics = fid[18];
            let name_len = usize::from(fid[19]);
            let address = BlockAddress {
                block: le32(fid, 24),
                partition_ref: le16(fid, 28),
            };
            let use_len = usize::from(le16(fid, 36));
            let name_end = 38 + use_len + name_len;
            if name_end > fid.len() {
                return Err(damaged("a UDF file identifier runs past its folder"));
            }
            let name = &fid[38 + use_len..name_end];
            pos += name_end.div_ceil(4) * 4;
            // Deleted (4) and parent (8) entries.
            if characteristics & 0x0C != 0 {
                continue;
            }
            if let Some(name) = compressed_unicode(name) {
                out.push((name, address, characteristics & 0x02 != 0));
            }
        }
        Ok(out)
    }

    /// The file or folder at `path` (absolute, `/`-separated, matched in any letter case), or `None`.
    pub fn lookup<R: Read + Seek>(&self, image: &mut Image<R>, path: &str) -> Result<Option<UdfFile>> {
        let parts = path_parts(path)?;
        let mut current = self.entry(image, self.root)?;
        for part in parts {
            if !current.is_dir {
                return Ok(None);
            }
            let wanted = part.to_lowercase();
            let entries = self.list(image, &current)?;
            let Some((_, address, _)) = entries.into_iter().find(|(name, _, _)| name.to_lowercase() == wanted) else {
                return Ok(None);
            };
            current = self.entry(image, address)?;
        }
        Ok(Some(current))
    }
}

/// OSTA compressed Unicode: a first byte of 8 (one byte a character) or 16 (two, big-endian); anything else, or an
/// empty name, is `None`.
fn compressed_unicode(raw: &[u8]) -> Option<String> {
    let (&kind, rest) = raw.split_first()?;
    let text = match kind {
        8 => rest.iter().map(|&b| char::from(b)).collect::<String>(),
        16 if rest.len().is_multiple_of(2) => {
            let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        _ => return None,
    };
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_compressed_unicode() {
        assert_eq!(compressed_unicode(b"\x08efi").as_deref(), Some("efi"));
        assert_eq!(compressed_unicode(b"\x10\x00b\x00o\x00o\x00t").as_deref(), Some("boot"));
        assert_eq!(compressed_unicode(b"\x10\x00b\x00"), None, "an odd 16-bit name");
        assert_eq!(compressed_unicode(b"\xFEx"), None);
        assert_eq!(compressed_unicode(b""), None);
        assert_eq!(compressed_unicode(b"\x08"), None);
    }

    #[test]
    fn the_tag_checksum_skips_its_own_byte() {
        let mut tag = [0u8; 16];
        tag[0] = 2;
        tag[12] = 1;
        tag[4] = tag_checksum(&tag);
        assert_eq!(tag[4], 3);
        tag[4] = 0xFF;
        assert_eq!(tag_checksum(&tag), 3);
    }
}
