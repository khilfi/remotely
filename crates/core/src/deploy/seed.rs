//! VM-22: the NoCloud seed a VirtualBox VM boots with: an ISO 9660 image labelled `cidata` that holds `user-data`
//! and `meta-data`, which cloud-init's NoCloud datasource finds by its label and mounts.
//!
//! Plain ISO 9660 names are upper case 8.3 (`USER_DAT.;1`), which cloud-init would not find, so the image also has
//! a Joliet tree (UCS-2 names, as `genisoimage -volid cidata -joliet` writes): Linux reads the Joliet names when
//! there are no Rock Ridge ones. Remotely writes the image itself, a few sectors in all, rather than shipping
//! genisoimage or a FAT library; [`read_joliet`] reads it back (tests, and the hand check).
//!
//! Layout, in 2048-byte sectors: 0-15 empty (the system area), 16 the primary volume descriptor, 17 the Joliet
//! supplementary one, 18 the set terminator, 19-22 the four path tables (each tree's little- and big-endian
//! one), 23 the primary root directory, 24 the Joliet root directory, then each file's data. Both trees point at
//! the same data.

use time::OffsetDateTime;

pub const SECTOR: usize = 2048;
/// The volume label NoCloud looks for (it also takes `CIDATA`).
pub const LABEL: &str = "cidata";
/// The most a seed's files may take together, well above what Remotely writes (a few KB).
pub const MAX_SEED_BYTES: usize = 1024 * 1024;

const PVD_SECTOR: u32 = 16;
const PATH_TABLES: u32 = 19;
const PVD_ROOT: u32 = 23;
const JOLIET_ROOT: u32 = 24;
const FIRST_FILE: u32 = 25;

fn both_u32(out: &mut [u8], value: u32) {
    out[..4].copy_from_slice(&value.to_le_bytes());
    out[4..8].copy_from_slice(&value.to_be_bytes());
}

fn both_u16(out: &mut [u8], value: u16) {
    out[..2].copy_from_slice(&value.to_le_bytes());
    out[2..4].copy_from_slice(&value.to_be_bytes());
}

fn sectors(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(SECTOR).max(1)).unwrap_or(u32::MAX)
}

/// A volume descriptor's 17-byte date: `YYYYMMDDHHMMSScc` digits and the offset from UTC in 15-minute steps.
fn descriptor_date(at: OffsetDateTime) -> [u8; 17] {
    let at = at.to_offset(time::UtcOffset::UTC);
    let text = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}00",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    );
    let mut out = [0u8; 17];
    out[..16].copy_from_slice(&text.as_bytes()[..16]);
    out
}

/// A directory record's 7-byte date: years since 1900, month, day, hour, minute, second, offset.
fn record_date(at: OffsetDateTime) -> [u8; 7] {
    let at = at.to_offset(time::UtcOffset::UTC);
    let years = u8::try_from(at.year() - 1900).unwrap_or(0);
    [
        years,
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        0,
    ]
}

fn ucs2(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// A directory record for `id` (already encoded), padded to an even length.
fn record(id: &[u8], extent: u32, length: u32, directory: bool, at: OffsetDateTime) -> Vec<u8> {
    let id_len = id.len();
    let len = 33 + id_len + usize::from(id_len.is_multiple_of(2));
    let mut out = vec![0u8; len];
    out[0] = u8::try_from(len).unwrap_or(u8::MAX);
    both_u32(&mut out[2..10], extent);
    both_u32(&mut out[10..18], length);
    out[18..25].copy_from_slice(&record_date(at));
    out[25] = if directory { 0x02 } else { 0x00 };
    both_u16(&mut out[28..32], 1);
    out[32] = u8::try_from(id_len).unwrap_or(u8::MAX);
    out[33..33 + id_len].copy_from_slice(id);
    out
}

/// `text` in `width` bytes: ASCII padded with spaces, or (Joliet) UCS-2 padded with UCS-2 spaces.
fn padded(text: &str, width: usize, joliet: bool) -> Vec<u8> {
    let mut out = if joliet { ucs2(text) } else { text.as_bytes().to_vec() };
    out.truncate(width);
    while out.len() < width {
        if joliet && width - out.len() >= 2 {
            out.extend_from_slice(&[0x00, 0x20]);
        } else {
            out.push(b' ');
        }
    }
    out
}

/// The 8.3 name a plain ISO 9660 reader sees: `user-data` is `USER_DAT.;1`.
fn level1_name(name: &str) -> String {
    let (stem, ext) = name.rsplit_once('.').unwrap_or((name, ""));
    let clean = |s: &str, max: usize| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .take(max)
            .collect()
    };
    format!("{}.{};1", clean(stem, 8), clean(ext, 3))
}

fn volume_descriptor(
    joliet: bool,
    total: u32,
    path_table_size: u32,
    l_table: u32,
    m_table: u32,
    root: u32,
    at: OffsetDateTime,
) -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    d[0] = if joliet { 2 } else { 1 };
    d[1..6].copy_from_slice(b"CD001");
    d[6] = 1;
    d[8..40].copy_from_slice(&padded("", 32, joliet));
    let label = if joliet {
        LABEL.to_owned()
    } else {
        LABEL.to_ascii_uppercase()
    };
    d[40..72].copy_from_slice(&padded(&label, 32, joliet));
    both_u32(&mut d[80..88], total);
    if joliet {
        // UCS-2 level 3.
        d[88..91].copy_from_slice(b"%/E");
    }
    both_u16(&mut d[120..124], 1);
    both_u16(&mut d[124..128], 1);
    both_u16(&mut d[128..132], SECTOR as u16);
    both_u32(&mut d[132..140], path_table_size);
    d[140..144].copy_from_slice(&l_table.to_le_bytes());
    d[148..152].copy_from_slice(&m_table.to_be_bytes());
    let root_record = record(&[0], root, SECTOR as u32, true, at);
    d[156..156 + root_record.len()].copy_from_slice(&root_record);
    d[190..318].copy_from_slice(&padded("", 128, joliet));
    d[318..446].copy_from_slice(&padded("", 128, joliet));
    d[446..574].copy_from_slice(&padded("", 128, joliet));
    d[574..702].copy_from_slice(&padded("REMOTELY", 128, joliet));
    d[702..813].copy_from_slice(&padded("", 111, joliet));
    let date = descriptor_date(at);
    d[813..830].copy_from_slice(&date);
    d[830..847].copy_from_slice(&date);
    d[847..863].copy_from_slice(b"0000000000000000");
    d[864..881].copy_from_slice(&date);
    d[881] = 1;
    d
}

/// The one-directory path table: the root, in either byte order.
fn path_table(root: u32, big_endian: bool) -> Vec<u8> {
    let mut t = vec![0u8; 10];
    t[0] = 1;
    let (extent, parent) = if big_endian {
        (root.to_be_bytes(), 1u16.to_be_bytes())
    } else {
        (root.to_le_bytes(), 1u16.to_le_bytes())
    };
    t[2..6].copy_from_slice(&extent);
    t[6..8].copy_from_slice(&parent);
    t
}

fn directory(own: u32, entries: &[(Vec<u8>, u32, u32)], at: OffsetDateTime) -> Vec<u8> {
    let mut d = Vec::with_capacity(SECTOR);
    d.extend(record(&[0], own, SECTOR as u32, true, at));
    d.extend(record(&[1], own, SECTOR as u32, true, at));
    for (id, extent, length) in entries {
        d.extend(record(id, *extent, *length, false, at));
    }
    d.resize(SECTOR, 0);
    d
}

/// A NoCloud seed holding `files` (name, content), e.g. `user-data` and `meta-data`. Names are plain ASCII;
/// the files together are at most [`MAX_SEED_BYTES`] and fit one directory sector.
pub fn write_seed(files: &[(&str, &[u8])], at: OffsetDateTime) -> crate::error::Result<Vec<u8>> {
    let total_bytes: usize = files.iter().map(|(_, data)| data.len()).sum();
    if total_bytes > MAX_SEED_BYTES || files.len() > 16 || files.iter().any(|(n, _)| n.is_empty() || !n.is_ascii()) {
        return Err(crate::error::CoreError::InvalidInput(
            "The cloud-init seed is too large.".into(),
        ));
    }
    // Directory records are kept in name order.
    let mut sorted: Vec<&(&str, &[u8])> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut next = FIRST_FILE;
    let mut placed = Vec::new();
    for (name, data) in &sorted {
        placed.push((*name, *data, next));
        next += sectors(data.len());
    }
    let total = next;
    let pvd_entries: Vec<(Vec<u8>, u32, u32)> = {
        let mut e: Vec<_> = placed
            .iter()
            .map(|(name, data, at)| (level1_name(name).into_bytes(), *at, data.len() as u32))
            .collect();
        e.sort_by(|a, b| a.0.cmp(&b.0));
        e
    };
    let joliet_entries: Vec<(Vec<u8>, u32, u32)> = placed
        .iter()
        .map(|(name, data, at)| (ucs2(name), *at, data.len() as u32))
        .collect();

    let mut image = vec![0u8; total as usize * SECTOR];
    let mut put = |sector: u32, bytes: &[u8]| {
        let start = sector as usize * SECTOR;
        image[start..start + bytes.len()].copy_from_slice(bytes);
    };
    put(
        PVD_SECTOR,
        &volume_descriptor(false, total, 10, PATH_TABLES, PATH_TABLES + 1, PVD_ROOT, at),
    );
    put(
        PVD_SECTOR + 1,
        &volume_descriptor(true, total, 10, PATH_TABLES + 2, PATH_TABLES + 3, JOLIET_ROOT, at),
    );
    let mut terminator = vec![0u8; SECTOR];
    terminator[0] = 255;
    terminator[1..6].copy_from_slice(b"CD001");
    terminator[6] = 1;
    put(PVD_SECTOR + 2, &terminator);
    put(PATH_TABLES, &path_table(PVD_ROOT, false));
    put(PATH_TABLES + 1, &path_table(PVD_ROOT, true));
    put(PATH_TABLES + 2, &path_table(JOLIET_ROOT, false));
    put(PATH_TABLES + 3, &path_table(JOLIET_ROOT, true));
    put(PVD_ROOT, &directory(PVD_ROOT, &pvd_entries, at));
    put(JOLIET_ROOT, &directory(JOLIET_ROOT, &joliet_entries, at));
    for (_, data, sector) in &placed {
        put(*sector, data);
    }
    Ok(image)
}

/// What an ISO says about itself, as Linux reads it with Joliet: the volume labels and the root's files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedContents {
    pub primary_label: String,
    pub joliet_label: String,
    /// (name, content) from the Joliet tree.
    pub files: Vec<(String, Vec<u8>)>,
    /// The primary tree's names (`USER_DAT.;1`).
    pub primary_names: Vec<String>,
}

fn sector_of(image: &[u8], sector: u32) -> Option<&[u8]> {
    let start = sector as usize * SECTOR;
    image.get(start..start + SECTOR)
}

fn root_files(image: &[u8], descriptor: &[u8], joliet: bool) -> Option<Vec<(String, Vec<u8>)>> {
    let root = descriptor.get(156..190)?;
    let extent = u32::from_le_bytes(root.get(2..6)?.try_into().ok()?);
    let length = u32::from_le_bytes(root.get(10..14)?.try_into().ok()?) as usize;
    let dir = image.get(extent as usize * SECTOR..extent as usize * SECTOR + length)?;
    let mut out = Vec::new();
    let mut at = 0;
    while at < dir.len() && dir[at] != 0 {
        let len = dir[at] as usize;
        let rec = dir.get(at..at + len)?;
        let id_len = rec[32] as usize;
        let id = rec.get(33..33 + id_len)?;
        if rec[25] & 0x02 == 0 {
            let name = if joliet {
                let units: Vec<u16> = id.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                String::from_utf16(&units).ok()?
            } else {
                String::from_utf8_lossy(id).into_owned()
            };
            let file_extent = u32::from_le_bytes(rec.get(2..6)?.try_into().ok()?) as usize;
            let file_len = u32::from_le_bytes(rec.get(10..14)?.try_into().ok()?) as usize;
            let data = image
                .get(file_extent * SECTOR..file_extent * SECTOR + file_len)?
                .to_vec();
            out.push((name, data));
        }
        at += len;
    }
    Some(out)
}

/// Reads an ISO's labels and root files the way Linux mounts it: through the Joliet tree. `None` when it isn't
/// an ISO 9660 image with one.
pub fn read_joliet(image: &[u8]) -> Option<SeedContents> {
    let mut primary = None;
    let mut joliet = None;
    for n in PVD_SECTOR..PVD_SECTOR + 16 {
        let d = sector_of(image, n)?;
        if &d[1..6] != b"CD001" {
            return None;
        }
        match d[0] {
            1 => primary = Some(d),
            2 if &d[88..91] == b"%/E" || &d[88..91] == b"%/C" || &d[88..91] == b"%/@" => joliet = Some(d),
            255 => break,
            _ => {}
        }
    }
    let (primary, joliet) = (primary?, joliet?);
    let label = |d: &[u8], wide: bool| -> String {
        let raw = &d[40..72];
        if wide {
            let units: Vec<u16> = raw.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units).trim_end().to_owned()
        } else {
            String::from_utf8_lossy(raw).trim_end().to_owned()
        }
    };
    Some(SeedContents {
        primary_label: label(primary, false),
        joliet_label: label(joliet, true),
        files: root_files(image, joliet, true)?,
        primary_names: root_files(image, primary, false)?.into_iter().map(|(n, _)| n).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: OffsetDateTime = time::macros::datetime!(2026-10-25 09:30:00 UTC);

    #[test]
    fn the_seed_reads_back_with_its_label_and_names() {
        let user = b"#cloud-config\nhostname: \"web-1\"\n".to_vec();
        let meta = b"instance-id: \"iid-1\"\nlocal-hostname: \"web-1\"\n".to_vec();
        let image = write_seed(&[("user-data", &user), ("meta-data", &meta)], AT).unwrap();
        assert_eq!(image.len() % SECTOR, 0);
        assert_eq!(image.len(), 27 * SECTOR, "25 sectors of structure, one per small file");
        let read = read_joliet(&image).unwrap();
        assert_eq!(read.joliet_label, "cidata");
        assert_eq!(read.primary_label, "CIDATA");
        assert_eq!(
            read.files,
            [("meta-data".to_owned(), meta), ("user-data".to_owned(), user)],
            "Joliet names, lower case with their hyphen, in order"
        );
        assert_eq!(read.primary_names, ["META_DAT.;1", "USER_DAT.;1"]);
        // The volume's size in sectors, both byte orders.
        let pvd = &image[16 * SECTOR..17 * SECTOR];
        assert_eq!(u32::from_le_bytes(pvd[80..84].try_into().unwrap()), 27);
        assert_eq!(u32::from_be_bytes(pvd[84..88].try_into().unwrap()), 27);
        assert_eq!(&pvd[813..827], b"20261025093000");
    }

    #[test]
    fn a_larger_file_spans_sectors() {
        let big = vec![b'x'; 5000];
        let image = write_seed(&[("user-data", &big), ("meta-data", b"m")], AT).unwrap();
        let read = read_joliet(&image).unwrap();
        assert_eq!(read.files[1].1.len(), 5000);
        assert_eq!(image.len(), (25 + 1 + 3) * SECTOR);
        assert!(write_seed(&[("user-data", &vec![0u8; MAX_SEED_BYTES + 1])], AT).is_err());
        assert_eq!(read_joliet(&[0u8; 100]), None, "not an ISO");
    }

    #[test]
    fn plain_names_are_eight_dot_three() {
        assert_eq!(level1_name("user-data"), "USER_DAT.;1");
        assert_eq!(level1_name("network-config"), "NETWORK_.;1");
        assert_eq!(level1_name("vendor.data"), "VENDOR.DAT;1");
    }
}
