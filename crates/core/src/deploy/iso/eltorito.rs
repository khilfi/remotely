//! El Torito's boot catalog (one sector): the validation entry (its 16-bit words sum to zero, then 55 AA), the
//! default entry (BIOS on Windows ISOs), then section headers (0x90, or 0x91 for the last) each followed by their
//! entries and any extension records (0x44). S3: Windows ISOs have one final section for platform 0xEF (UEFI)
//! with one no-emulation entry whose load RBA (entry bytes 8..12) names the boot image's sector.

use std::io::{Read, Seek};

use super::{damaged, le16, le32, Image, SECTOR};
use crate::error::Result;

const ENTRY: usize = 32;

/// One boot entry and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry's offset in the image; its load RBA is at `offset + 8`.
    pub offset: u64,
    /// 0 x86 (BIOS), 0xEF UEFI; the default entry has the validation entry's platform.
    pub platform: u8,
    /// Boot indicator 0x88.
    pub bootable: bool,
    /// Low nibble of the media type: 0 is no emulation.
    pub media: u8,
    /// Virtual 512-byte sectors loaded.
    pub sector_count: u16,
    pub load_rba: u32,
    /// The load RBA's four bytes as they are.
    pub rba_field: [u8; 4],
}

/// The catalog's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    pub sector: u32,
    pub default: Entry,
    /// Section entries in order, each with its section's platform.
    pub sections: Vec<Entry>,
}

impl Catalog {
    /// Reads the catalog at `sector`; a damaged validation entry or a section running past the sector is an error.
    pub fn read<R: Read + Seek>(image: &mut Image<R>, sector: u32) -> Result<Catalog> {
        let d = image.sector(u64::from(sector), "El Torito's boot catalog")?;
        let base = u64::from(sector) * SECTOR;
        let sum = (0..16).fold(0u16, |sum, i| sum.wrapping_add(le16(&d, i * 2)));
        if d[0] != 1 || d[30] != 0x55 || d[31] != 0xAA || sum != 0 {
            return Err(damaged("El Torito's boot catalog has a damaged validation entry"));
        }
        let platform = d[1];
        let default = entry(&d, ENTRY, base, platform)?;
        let mut sections = Vec::new();
        let mut pos = 2 * ENTRY;
        while pos + ENTRY <= d.len() {
            let header = d[pos];
            if header != 0x90 && header != 0x91 {
                break;
            }
            let section_platform = d[pos + 1];
            let count = le16(&d, pos + 2);
            pos += ENTRY;
            for _ in 0..count {
                if pos + ENTRY > d.len() {
                    return Err(damaged("El Torito's boot catalog runs past its sector"));
                }
                sections.push(entry(&d, pos, base, section_platform)?);
                pos += ENTRY;
                // Extension records belong to the entry before them.
                while pos + ENTRY <= d.len() && d[pos] == 0x44 {
                    pos += ENTRY;
                }
            }
            if header == 0x91 {
                break;
            }
        }
        Ok(Catalog {
            sector,
            default,
            sections,
        })
    }

    /// The first section entry for `platform`.
    pub fn first_for(&self, platform: u8) -> Option<&Entry> {
        self.sections.iter().find(|e| e.platform == platform)
    }
}

fn entry(d: &[u8], pos: usize, base: u64, platform: u8) -> Result<Entry> {
    let e = &d[pos..pos + ENTRY];
    if e[0] != 0x88 && e[0] != 0x00 {
        return Err(damaged(
            "El Torito's boot catalog has an entry that is neither bootable nor not",
        ));
    }
    let mut rba_field = [0u8; 4];
    rba_field.copy_from_slice(&e[8..12]);
    Ok(Entry {
        offset: base + pos as u64,
        platform,
        bootable: e[0] == 0x88,
        media: e[1] & 0x0F,
        sector_count: le16(e, 6),
        load_rba: le32(e, 8),
        rba_field,
    })
}
