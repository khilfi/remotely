//! ISO 9660 (ECMA-119) as an install ISO has it, read as untrusted input: the volume descriptors from sector 16
//! (the primary one, a Joliet supplementary one with escape `%/@`, `%/C` or `%/E`, and El Torito's boot record),
//! directory records, and Rock Ridge names (SUSP's `SP` in the root's `.` record, `NM` entries, followed through
//! `CE` continuation areas). Every directory is capped at [`MAX_DIR_BYTES`], every record checked against its
//! sector, every continuation followed a bounded number of times; a lookup walks one directory per path part.

use std::io::{Read, Seek};

use super::{damaged, le16, le32, path_parts, printable, Image, IsoWrite, Tree, SECTOR};
use crate::error::{CoreError, Result};
use crate::untrusted::size_words;

/// The largest directory Remotely reads (install ISOs' are a few sectors).
pub const MAX_DIR_BYTES: u64 = 4 * 1024 * 1024;
const FIRST_DESCRIPTOR: u64 = 16;
const MAX_DESCRIPTORS: u64 = 64;
/// Continuation areas followed for one record's name.
pub const MAX_CE_HOPS: usize = 8;
/// The most continuation areas [`Volume::walk`] collects.
pub const MAX_WALK_CE_AREAS: usize = 65_536;
/// Continuation areas read for one directory listing.
const MAX_CE_READS: usize = 512;
const MAX_CE_BYTES: u32 = 2048;
const MAX_NAME_BYTES: usize = 1024;
const EL_TORITO: &[u8] = b"EL TORITO SPECIFICATION";
/// The most folders [`Volume::walk`] reads (Debian's DVD-1 has a few thousand).
pub const MAX_WALK_FOLDERS: usize = 100_000;
/// The most folder bytes [`Volume::walk`] reads.
pub const MAX_WALK_BYTES: u64 = 256 * 1024 * 1024;

/// A directory's extent and size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dir {
    pub extent: u32,
    pub size: u32,
}

/// What the volume descriptors say.
#[derive(Debug, Clone)]
pub struct Volume {
    pub primary_root: Dir,
    pub joliet_root: Option<Dir>,
    /// The primary descriptor's volume label, printable.
    pub volume_id: String,
    /// The root's `.` record opens with SUSP's `SP` entry: records have Rock Ridge names.
    pub rock_ridge: bool,
    /// `SP`'s LEN_SKP: bytes of each record's system use area before its entries.
    rr_skip: usize,
    /// El Torito's boot catalog sector, from the boot record.
    pub boot_catalog: Option<u32>,
    /// Sectors the volume's own structures take, `[start, end)` with what they are: the system area and the
    /// volume descriptors, each descriptor's path tables, and the roots' folders (no record names those).
    pub reserved: Vec<Reserved>,
}

/// Sectors `[start, end)` of the volume's own structures, and what they are, in words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reserved {
    pub start: u64,
    pub end: u64,
    pub what: &'static str,
}

/// One directory record, where it is in the image, and the name it was found by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's own offset in the image (its size is at `offset + 10`).
    pub offset: u64,
    pub extent: u32,
    pub size: u32,
    pub flags: u8,
    pub ext_attr_len: u8,
    pub unit_size: u8,
    pub gap: u8,
    /// Bytes 2..10 and 10..18: the extent and size, little- then big-endian.
    pub extent_field: [u8; 8],
    pub size_field: [u8; 8],
    /// The Rock Ridge name, the Joliet name, or the plain name without its `;1` and trailing dot.
    pub name: String,
    /// `name` is a Rock Ridge `NM` name.
    pub by_rock_ridge: bool,
}

impl Record {
    pub fn is_dir(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Why this isn't one plain extent of data whose two byte orders agree, the only kind read or changed.
    pub fn plain_file_problem(&self) -> Option<&'static str> {
        if self.is_dir() {
            Some("is a folder")
        } else if self.flags & 0x80 != 0 {
            Some("is split into several extents")
        } else if self.unit_size != 0 || self.gap != 0 {
            Some("is interleaved")
        } else if self.ext_attr_len != 0 {
            Some("has an extended attribute record")
        } else if !halves_agree(&self.extent_field) || !halves_agree(&self.size_field) {
            Some("has a directory record whose two byte orders disagree")
        } else {
            None
        }
    }

    /// The change that gives this record the size `size`, both byte orders.
    pub fn size_write(&self, size: u32) -> IsoWrite {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&size.to_be_bytes());
        IsoWrite {
            offset: self.offset + 10,
            bytes,
            replaces: self.size_field.to_vec(),
        }
    }

    /// Where its data starts in the image.
    pub fn data_offset(&self) -> u64 {
        u64::from(self.extent) * SECTOR
    }

    /// The sectors its data takes, `[start, end)`; empty for an empty file.
    pub fn sectors(&self) -> (u64, u64) {
        let start = u64::from(self.extent);
        (start, start + u64::from(self.size).div_ceil(SECTOR))
    }
}

/// `[start, end)` sector ranges that share at least one sector.
pub fn overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < a.1 && b.0 < b.1 && a.0 < b.1 && b.0 < a.1
}

/// A descriptor's path tables: type L at 140 (and 144), type M at 148 (and 152), each the size at 132.
fn path_tables(descriptor: &[u8], tree: &'static str) -> Vec<Reserved> {
    let sectors = u64::from(le32(descriptor, 132)).div_ceil(SECTOR);
    [
        le32(descriptor, 140),
        le32(descriptor, 144),
        be32(descriptor, 148),
        be32(descriptor, 152),
    ]
    .into_iter()
    .filter(|&at| at != 0 && sectors > 0)
    .map(|at| Reserved {
        start: u64::from(at),
        end: u64::from(at) + sectors,
        what: tree,
    })
    .collect()
}

fn be32(d: &[u8], at: usize) -> u32 {
    match d.get(at..at + 4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

fn halves_agree(field: &[u8; 8]) -> bool {
    field[..4].iter().eq(field[4..].iter().rev())
}

impl Volume {
    /// Reads the volume descriptor set (at most 64 descriptors from sector 16, up to the terminator).
    pub fn read<R: Read + Seek>(image: &mut Image<R>) -> Result<Volume> {
        if !image.has_sector(FIRST_DESCRIPTOR) {
            return Err(damaged("it is too small to be an ISO image"));
        }
        let mut primary: Option<Vec<u8>> = None;
        let mut joliet: Option<Vec<u8>> = None;
        let mut boot_catalog = None;
        let mut descriptors_end = FIRST_DESCRIPTOR;
        for n in FIRST_DESCRIPTOR..FIRST_DESCRIPTOR + MAX_DESCRIPTORS {
            if !image.has_sector(n) {
                break;
            }
            let d = image.sector(n, "a volume descriptor")?;
            if &d[1..6] != b"CD001" {
                break;
            }
            descriptors_end = n + 1;
            match d[0] {
                0 if boot_catalog.is_none() && d[7..7 + EL_TORITO.len()] == *EL_TORITO => {
                    boot_catalog = Some(le32(&d, 71));
                }
                1 if primary.is_none() => primary = Some(d),
                2 if joliet.is_none() && matches!(&d[88..91], b"%/@" | b"%/C" | b"%/E") => joliet = Some(d),
                255 => break,
                _ => {}
            }
        }
        let primary = primary.ok_or_else(|| damaged("it has no ISO 9660 primary volume descriptor"))?;
        let primary_root = root_of(&primary)?;
        let joliet_root = match &joliet {
            Some(d) => Some(root_of(d)?),
            None => None,
        };
        let mut reserved = vec![Reserved {
            start: 0,
            end: descriptors_end,
            what: "the system area and volume descriptors",
        }];
        reserved.extend(path_tables(&primary, "a path table"));
        if let Some(d) = &joliet {
            reserved.extend(path_tables(d, "a Joliet path table"));
        }
        for root in std::iter::once(primary_root).chain(joliet_root) {
            reserved.push(Reserved {
                start: u64::from(root.extent),
                end: u64::from(root.extent) + u64::from(root.size).div_ceil(SECTOR),
                what: "a root folder",
            });
        }
        let mut volume = Volume {
            primary_root,
            joliet_root,
            volume_id: printable(&primary[40..72], 32),
            rock_ridge: false,
            rr_skip: 0,
            boot_catalog,
            reserved,
        };
        // SUSP: `SP` (with check bytes BE EF) opens the system use area of the root's first record, `.`.
        let first = image.sector(u64::from(primary_root.extent), "the root folder")?;
        let len = usize::from(first[0]);
        if len >= 34 {
            let name_len = usize::from(first[32]);
            let su_start = 33 + name_len + usize::from(name_len.is_multiple_of(2));
            if let Some(su) = first.get(su_start..len) {
                if su.len() >= 7 && &su[..2] == b"SP" && su[2] >= 7 && su[4] == 0xBE && su[5] == 0xEF {
                    volume.rock_ridge = true;
                    volume.rr_skip = usize::from(su[6]);
                }
            }
        }
        Ok(volume)
    }

    /// The record at `path` (absolute, `/`-separated) in `tree`, or `None`. In the primary tree a record with a
    /// Rock Ridge name matches it exactly; one without matches its plain name in any letter case. Joliet names
    /// match exactly first, then in any letter case.
    pub fn lookup<R: Read + Seek>(&self, image: &mut Image<R>, path: &str, tree: Tree) -> Result<Option<Record>> {
        let root = match tree {
            Tree::RockRidge => self.primary_root,
            Tree::Joliet => self.joliet_root.ok_or_else(|| damaged("it has no Joliet tree"))?,
            Tree::Udf => {
                return Err(CoreError::InvalidInput(
                    "UDF isn't one of an ISO 9660 volume's trees.".into(),
                ))
            }
        };
        let parts = path_parts(path)?;
        let mut dir = root;
        for (i, part) in parts.iter().enumerate() {
            let records = self.list(image, dir, tree)?;
            let Some(found) = pick(records, part) else {
                return Ok(None);
            };
            if i + 1 == parts.len() {
                return Ok(Some(found));
            }
            if !found.is_dir() {
                return Ok(None);
            }
            dir = Dir {
                extent: found.extent,
                size: found.size,
            };
        }
        Ok(None)
    }

    /// Every record of `dir` but `.` and `..`, in order.
    pub fn list<R: Read + Seek>(&self, image: &mut Image<R>, dir: Dir, tree: Tree) -> Result<Vec<Record>> {
        self.list_named(image, dir, tree, true, None)
    }

    /// Every record of every folder of `tree` but `.` and `..`, folders included, each folder read once (a folder
    /// whose record points back up isn't read again), at most [`MAX_WALK_FOLDERS`] folders and
    /// [`MAX_WALK_BYTES`] of them; names are the plain or Joliet ones. `visit` sees each record; its error ends
    /// the walk. Returns the byte ranges `[start, end)` of every Rock Ridge continuation area (`CE`) the primary
    /// tree's records point at, `.` and `..` included, each chain followed [`MAX_CE_HOPS`] deep and at most
    /// [`MAX_WALK_CE_AREAS`] in all.
    pub fn walk<R: Read + Seek>(
        &self,
        image: &mut Image<R>,
        tree: Tree,
        mut visit: impl FnMut(&Record) -> Result<()>,
    ) -> Result<Vec<(u64, u64)>> {
        let root = match tree {
            Tree::Joliet => self.joliet_root.ok_or_else(|| damaged("it has no Joliet tree"))?,
            _ => self.primary_root,
        };
        let mut areas = Vec::new();
        let mut queue = std::collections::VecDeque::from([root]);
        let mut seen = std::collections::HashSet::from([root.extent]);
        let (mut folders, mut bytes) = (0usize, 0u64);
        while let Some(dir) = queue.pop_front() {
            folders += 1;
            bytes += u64::from(dir.size);
            if folders > MAX_WALK_FOLDERS || bytes > MAX_WALK_BYTES {
                return Err(damaged("it has more folders than Remotely checks"));
            }
            for record in self.list_named(image, dir, tree, false, Some(&mut areas))? {
                visit(&record)?;
                if record.is_dir() && seen.insert(record.extent) {
                    queue.push_back(Dir {
                        extent: record.extent,
                        size: record.size,
                    });
                }
            }
        }
        Ok(areas)
    }

    /// Adds the continuation areas `su` (a record's system use area) points at to `areas`, following each chain.
    fn continuation_areas<R: Read + Seek>(
        &self,
        image: &mut Image<R>,
        su: &[u8],
        areas: &mut Vec<(u64, u64)>,
    ) -> Result<()> {
        let mut area: Vec<u8> = su.get(self.rr_skip..).unwrap_or_default().to_vec();
        for _ in 0..MAX_CE_HOPS {
            let Some((block, offset, length)) = first_continuation(&area) else {
                return Ok(());
            };
            if areas.len() >= MAX_WALK_CE_AREAS {
                return Err(damaged(
                    "it has more Rock Ridge continuation areas than Remotely checks",
                ));
            }
            if length > MAX_CE_BYTES {
                return Err(damaged("a Rock Ridge continuation area is larger than a sector"));
            }
            let at = u64::from(block) * SECTOR + u64::from(offset);
            areas.push((at, at + u64::from(length)));
            area = image.read_at(at, u64::from(length), "a Rock Ridge continuation area")?;
        }
        Ok(())
    }

    fn list_named<R: Read + Seek>(
        &self,
        image: &mut Image<R>,
        dir: Dir,
        tree: Tree,
        rock_ridge_names: bool,
        mut areas: Option<&mut Vec<(u64, u64)>>,
    ) -> Result<Vec<Record>> {
        let size = u64::from(dir.size);
        if size > MAX_DIR_BYTES {
            return Err(damaged(format!(
                "a folder is larger than the {} Remotely reads",
                size_words(MAX_DIR_BYTES)
            )));
        }
        let base = u64::from(dir.extent) * SECTOR;
        let data = image.read_at(base, size, "a folder")?;
        let sector = SECTOR as usize;
        let mut records = Vec::new();
        let mut ce_reads = 0usize;
        let mut pos = 0usize;
        while pos < data.len() {
            let len = usize::from(data[pos]);
            if len == 0 {
                // The rest of this sector is padding.
                pos = (pos / sector + 1) * sector;
                continue;
            }
            let sector_end = ((pos / sector + 1) * sector).min(data.len());
            if len < 34 || pos + len > sector_end {
                return Err(damaged("a folder holds a directory record that runs past its sector"));
            }
            let rec = &data[pos..pos + len];
            let name_len = usize::from(rec[32]);
            if 33 + name_len > len {
                return Err(damaged("a directory record's name runs past the record"));
            }
            let id = &rec[33..33 + name_len];
            let offset = base + pos as u64;
            pos += len;
            let su_start = (33 + name_len + usize::from(name_len.is_multiple_of(2))).min(len);
            if let Some(areas) = areas.as_deref_mut() {
                if self.rock_ridge && tree == Tree::RockRidge {
                    self.continuation_areas(image, &rec[su_start..], areas)?;
                }
            }
            if name_len == 1 && (id[0] == 0 || id[0] == 1) {
                continue;
            }
            let (name, by_rock_ridge) = match tree {
                Tree::Joliet => (joliet_name(id), false),
                _ if self.rock_ridge && rock_ridge_names => {
                    match rr_name(image, &rec[su_start..], self.rr_skip, &mut ce_reads)? {
                        Some(name) => (name, true),
                        None => (plain_name(id), false),
                    }
                }
                _ => (plain_name(id), false),
            };
            let mut extent_field = [0u8; 8];
            extent_field.copy_from_slice(&rec[2..10]);
            let mut size_field = [0u8; 8];
            size_field.copy_from_slice(&rec[10..18]);
            records.push(Record {
                offset,
                extent: le32(rec, 2),
                size: le32(rec, 10),
                flags: rec[25],
                ext_attr_len: rec[1],
                unit_size: rec[26],
                gap: rec[27],
                extent_field,
                size_field,
                name,
                by_rock_ridge,
            });
        }
        Ok(records)
    }
}

fn root_of(descriptor: &[u8]) -> Result<Dir> {
    let block = le16(descriptor, 128);
    if u64::from(block) != SECTOR {
        return Err(damaged(format!("its logical block size is {block} bytes, not 2048")));
    }
    let record = &descriptor[156..190];
    if usize::from(record[0]) < 34 || record[25] & 0x02 == 0 {
        return Err(damaged("its root folder's record is damaged"));
    }
    Ok(Dir {
        extent: le32(record, 2),
        size: le32(record, 10),
    })
}

/// The first record named `part` exactly, else (plain and Joliet names only) the first in any letter case.
/// Associated files (flag 0x04) never match.
fn pick(records: Vec<Record>, part: &str) -> Option<Record> {
    let wanted = part.to_lowercase();
    let mut loose = None;
    for record in records {
        if record.flags & 0x04 != 0 {
            continue;
        }
        if record.name == part {
            return Some(record);
        }
        if loose.is_none() && !record.by_rock_ridge && record.name.to_lowercase() == wanted {
            loose = Some(record);
        }
    }
    loose
}

/// A Rock Ridge name from the record's system use area (after `skip` bytes), following `CE` while the name isn't
/// complete. `None` when there is no usable `NM` (none, too long, empty, or holding `/` or NUL).
fn rr_name<R: Read + Seek>(
    image: &mut Image<R>,
    su: &[u8],
    skip: usize,
    ce_reads: &mut usize,
) -> Result<Option<String>> {
    let mut area: Vec<u8> = su.get(skip..).unwrap_or_default().to_vec();
    let mut name: Vec<u8> = Vec::new();
    let mut saw_nm = false;
    let mut complete = false;
    let mut hops = 0usize;
    loop {
        let mut next = None;
        let mut i = 0usize;
        while i + 4 <= area.len() {
            let len = usize::from(area[i + 2]);
            if len < 4 || i + len > area.len() {
                break;
            }
            let entry = &area[i..i + len];
            match &entry[..2] {
                b"NM" if len >= 5 && !complete => {
                    let flags = entry[4];
                    // CURRENT (2) and PARENT (4) name `.` and `..`, never a file.
                    if flags & 0x06 == 0 {
                        saw_nm = true;
                        name.extend_from_slice(&entry[5..]);
                        if name.len() > MAX_NAME_BYTES {
                            return Ok(None);
                        }
                        if flags & 0x01 == 0 {
                            complete = true;
                        }
                    }
                }
                b"CE" if len >= 28 => next = Some((le32(entry, 4), le32(entry, 12), le32(entry, 20))),
                b"ST" => break,
                _ => {}
            }
            i += len;
        }
        match next {
            Some((block, offset, length)) if !complete && hops < MAX_CE_HOPS => {
                hops += 1;
                *ce_reads += 1;
                if *ce_reads > MAX_CE_READS {
                    return Err(damaged(
                        "a folder has more Rock Ridge continuation areas than Remotely follows",
                    ));
                }
                if length > MAX_CE_BYTES {
                    return Err(damaged("a Rock Ridge continuation area is larger than a sector"));
                }
                let at = u64::from(block) * SECTOR + u64::from(offset);
                area = image.read_at(at, u64::from(length), "a Rock Ridge continuation area")?;
            }
            _ => break,
        }
    }
    if !saw_nm || name.is_empty() || name.contains(&b'/') || name.contains(&0) {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&name).into_owned()))
}

/// The first `CE` entry of a system use area (block, offset, length), before any `ST`.
fn first_continuation(area: &[u8]) -> Option<(u32, u32, u32)> {
    let mut i = 0usize;
    while i + 4 <= area.len() {
        let len = usize::from(area[i + 2]);
        if len < 4 || i + len > area.len() {
            return None;
        }
        let entry = &area[i..i + len];
        match &entry[..2] {
            b"CE" if len >= 28 => return Some((le32(entry, 4), le32(entry, 12), le32(entry, 20))),
            b"ST" => return None,
            _ => {}
        }
        i += len;
    }
    None
}

/// `NAME.EXT;1` -> `NAME.EXT`; `NAME.;1` -> `NAME`.
fn plain_name(id: &[u8]) -> String {
    let text = String::from_utf8_lossy(id);
    let stem = strip_version(&text);
    stem.strip_suffix('.').unwrap_or(stem).to_owned()
}

fn joliet_name(id: &[u8]) -> String {
    let units: Vec<u16> = id.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
    let text = String::from_utf16_lossy(&units);
    strip_version(&text).to_owned()
}

fn strip_version(name: &str) -> &str {
    match name.rsplit_once(';') {
        Some((stem, version)) if version.bytes().all(|b| b.is_ascii_digit()) => stem,
        _ => name,
    }
}

/// The data of `record`, at most `cap` bytes; only one plain extent is read.
pub fn read_record<R: Read + Seek>(image: &mut Image<R>, record: &Record, cap: u64) -> Result<Vec<u8>> {
    let name = printable(record.name.as_bytes(), 80);
    if let Some(problem) = record.plain_file_problem() {
        return Err(damaged(format!("{name} {problem}")));
    }
    if u64::from(record.size) > cap {
        return Err(CoreError::InvalidInput(format!(
            "{name} on the ISO is larger than {}, so Remotely didn't read it.",
            size_words(cap)
        )));
    }
    image.read_at(record.data_offset(), u64::from(record.size), "a file's data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_lose_their_version_and_trailing_dot() {
        assert_eq!(plain_name(b"GRUB.CFG;1"), "GRUB.CFG");
        assert_eq!(plain_name(b"UBUNTU.;1"), "UBUNTU");
        assert_eq!(plain_name(b"BOOT"), "BOOT");
        assert_eq!(plain_name(b"A;B"), "A;B", "only a number is a version");
        let wide: Vec<u8> = "grub.cfg;1".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(joliet_name(&wide), "grub.cfg");
        assert_eq!(joliet_name(&[0, b'a', 0]), "a", "an odd last byte is dropped");
    }

    #[test]
    fn halves_must_mirror() {
        let mut field = [0u8; 8];
        field[..4].copy_from_slice(&573u32.to_le_bytes());
        field[4..].copy_from_slice(&573u32.to_be_bytes());
        assert!(halves_agree(&field));
        field[7] ^= 1;
        assert!(!halves_agree(&field));
    }
}
