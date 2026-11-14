//! S3: Windows Server Setup's ISOs (2022 and 2025 evaluation media seen). With El Torito's UEFI entry on
//! `efisys.bin`'s copy, firmware shows "Press any key to boot from CD or DVD" and, with no key, boots nothing. The
//! ISO also holds `efisys_noprompt.bin`, the same 1.44 MB FAT boot image without the prompt, in its UDF tree only
//! (the ISO 9660 tree has just README.TXT). The copy's UEFI entry (the first of the final section for platform
//! 0xEF) gets that file's sector as its load RBA (catalog entry bytes 8..12); the sector count stays 1, as
//! Microsoft's entry has it. Nothing checksums the catalog. BIOS needs nothing: `etfsboot.com` starts Setup on a
//! blank disk by itself. The answer file (`autounattend.xml`) is on its own CD, never in the copy.

use std::io::{Read, Seek};

use super::eltorito::Catalog;
use super::iso9660::Volume;
use super::udf::{Udf, UdfData};
use super::{le16, unexpected, Flavor, Image, IsoWrite, SECTOR};
use crate::error::Result;

pub const NOPROMPT_PATH: &str = "/efi/microsoft/boot/efisys_noprompt.bin";
/// Setup's image file: its presence says this is Windows Setup media.
pub const INSTALL_WIM: &str = "/sources/install.wim";
/// A 1.44 MB floppy image: 2,880 sectors of 512 bytes.
pub const EFI_IMAGE_BYTES: u64 = 1_474_560;
/// El Torito's platform id for UEFI.
pub const EFI_PLATFORM: u8 = 0xEF;

/// A FAT boot sector of a 1.44 MB floppy: 55 AA, 512-byte sectors, 2,880 of them.
pub fn is_floppy_image(boot: &[u8]) -> bool {
    boot.len() >= 512 && boot[510] == 0x55 && boot[511] == 0xAA && le16(boot, 11) == 512 && le16(boot, 19) == 2880
}

pub(crate) fn plan<R: Read + Seek>(image: &mut Image<R>) -> Result<(Vec<IsoWrite>, Vec<String>)> {
    let flavor = Flavor::WindowsServer;
    let volume = Volume::read(image)?;
    let catalog_sector = volume
        .boot_catalog
        .ok_or_else(|| unexpected(flavor, "it has no El Torito boot record"))?;
    let catalog = Catalog::read(image, catalog_sector)?;
    let entry = catalog
        .first_for(EFI_PLATFORM)
        .ok_or_else(|| unexpected(flavor, "its boot catalog has no UEFI entry"))?
        .clone();
    if !entry.bootable || entry.media != 0 {
        return Err(unexpected(
            flavor,
            "its UEFI boot entry isn't a bootable no-emulation entry",
        ));
    }
    let Some(udf) = Udf::open(image)? else {
        return Err(unexpected(
            flavor,
            "it has no UDF file system, where Windows Setup keeps its files",
        ));
    };
    match udf.lookup(image, INSTALL_WIM)? {
        Some(file) if !file.is_dir => {}
        _ => return Err(unexpected(flavor, "sources/install.wim isn't on it")),
    }
    let file = udf
        .lookup(image, NOPROMPT_PATH)?
        .filter(|f| !f.is_dir)
        .ok_or_else(|| unexpected(flavor, "efi/microsoft/boot/efisys_noprompt.bin isn't on it"))?;
    if file.length != EFI_IMAGE_BYTES {
        return Err(unexpected(
            flavor,
            format!(
                "efisys_noprompt.bin is {} bytes, not the {EFI_IMAGE_BYTES} of a 1.44 MB boot image",
                file.length
            ),
        ));
    }
    let sector = match &file.data {
        UdfData::Extents(extents) if extents.len() == 1 && u64::from(extents[0].bytes) >= EFI_IMAGE_BYTES => {
            extents[0].sector
        }
        _ => return Err(unexpected(flavor, "efisys_noprompt.bin isn't stored in one piece")),
    };
    let rba = u32::try_from(sector)
        .map_err(|_| unexpected(flavor, "efisys_noprompt.bin lies past where El Torito reaches"))?;
    if !image.has_sector(sector + EFI_IMAGE_BYTES / SECTOR - 1) {
        return Err(unexpected(flavor, "efisys_noprompt.bin lies past the end of the image"));
    }
    let noprompt = image.read_at(sector * SECTOR, 512, "efisys_noprompt.bin")?;
    if !is_floppy_image(&noprompt) {
        return Err(unexpected(flavor, "efisys_noprompt.bin isn't a 1.44 MB FAT boot image"));
    }
    let current = image.read_at(u64::from(entry.load_rba) * SECTOR, 512, "the UEFI entry's boot image")?;
    if !is_floppy_image(&current) {
        return Err(unexpected(
            flavor,
            "its UEFI entry's image isn't the 1.44 MB FAT boot image Windows ISOs have",
        ));
    }
    let write = IsoWrite {
        offset: entry.offset + 8,
        bytes: rba.to_le_bytes().to_vec(),
        replaces: entry.rba_field.to_vec(),
    };
    let summary = vec![
        format!("Volume label: {}.", volume.volume_id),
        if entry.load_rba == rba {
            format!(
                "UEFI boot: the El Torito entry already loads efisys_noprompt.bin (sector {rba}), so Setup starts \
                 without \"Press any key\"; it is a copy Remotely made."
            )
        } else {
            format!(
                "UEFI boot: the El Torito entry now loads efisys_noprompt.bin (sector {rba}) instead of the image at \
                 sector {}, so Setup starts without \"Press any key\".",
                entry.load_rba
            )
        },
        "BIOS boot: left as it is (Setup starts on a blank disk without a key).".to_owned(),
    ];
    Ok((vec![write], summary))
}
