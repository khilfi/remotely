//! Hostile and damaged images: cut short, bytes flipped, sizes and extents absurd, folders and continuation areas
//! that point back at themselves, UDF addresses outside the image or its partition. Every plan and read returns
//! (an error or a plan whose writes fit), never panics, and finishes quickly.

use std::io::Cursor;
use std::ops::Range;
use std::time::{Duration, Instant};

use super::udf::tag_checksum;
use super::*;
use crate::fakes::install_isos::{self as fake, LinuxIso};

const READS: [(&str, Tree); 7] = [
    ("/boot/grub/grub.cfg", Tree::RockRidge),
    ("/boot/grub/grub.cfg", Tree::Joliet),
    ("/isolinux/isolinux.cfg", Tree::RockRidge),
    ("/md5sum.txt", Tree::RockRidge),
    ("/readme.txt", Tree::RockRidge),
    ("/efi/microsoft/boot/efisys_noprompt.bin", Tree::Udf),
    ("/sources/ei.cfg", Tree::Udf),
];

/// Every plan and read of `image`; a plan that succeeds has its writes inside the image.
fn everything(image: &[u8]) {
    for flavor in Flavor::ALL {
        if let Ok(plan) = plan(&mut Cursor::new(image), flavor) {
            assert_eq!(plan.iso_bytes, image.len() as u64);
            for write in &plan.writes {
                assert!(write.offset + write.bytes.len() as u64 <= image.len() as u64);
            }
        }
    }
    for (path, tree) in READS {
        let _ = read_file(&mut Cursor::new(image), path, tree);
    }
}

/// xorshift64*: the same bytes every run, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn s(n: usize) -> usize {
    n * 2048
}

/// A fake's name, its image, and the byte ranges its structures are in.
type Fake = (&'static str, Vec<u8>, Vec<Range<usize>>);

/// The fakes.
fn images() -> Vec<Fake> {
    let linux = |image: Vec<u8>| {
        let len = image.len();
        let structures = s(16)..len.min(s(64));
        (image, vec![structures, 0..len])
    };
    let (ubuntu, ubuntu_hot) = linux(fake::ubuntu_24_04());
    let continued = LinuxIso {
        nm_in_continuation: Some("/boot/grub/grub.cfg".into()),
        joliet_versions: true,
        ..fake::ubuntu_26_04_iso()
    };
    let (continued, continued_hot) = linux(continued.build());
    let (debian, debian_hot) = linux(fake::debian());
    let windows = fake::windows_server();
    let windows_hot = vec![s(16)..s(26), s(256)..s(263), s(304)..s(330)];
    vec![
        ("ubuntu 24.04", ubuntu, ubuntu_hot),
        ("ubuntu 26.04 continued", continued, continued_hot),
        ("debian", debian, debian_hot),
        ("windows", windows, windows_hot),
    ]
}

#[test]
fn every_fake_plans_as_exactly_its_own_flavor() {
    for (name, image, _) in images() {
        let planned: Vec<Flavor> = Flavor::ALL
            .into_iter()
            .filter(|f| plan(&mut Cursor::new(&image), *f).is_ok())
            .collect();
        assert_eq!(planned.len(), 1, "{name}: {planned:?}");
    }
}

#[test]
fn cut_short_images_are_refused_not_read_past() {
    let started = Instant::now();
    for (name, image, _) in images() {
        let mut lengths: Vec<usize> = (0..image.len().min(s(340))).step_by(997).collect();
        lengths.extend((0..image.len()).step_by(image.len() / 50 + 1));
        lengths.extend([s(16), s(17) - 1, s(17), s(257), image.len() - 1]);
        lengths.retain(|&len| len < image.len());
        for len in lengths {
            everything(&image[..len]);
        }
        eprintln!("{name}: cut short, {:?} so far", started.elapsed());
    }
    assert!(started.elapsed() < Duration::from_secs(120));
}

#[test]
fn flipped_bytes_never_panic() {
    let started = Instant::now();
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    for (name, mut image, hot) in images() {
        let original = image.clone();
        let rounds = if name == "windows" { 300 } else { 600 };
        for _ in 0..rounds {
            let mut saved = Vec::new();
            for _ in 0..1 + rng.below(4) {
                let range = &hot[rng.below(hot.len())];
                let at = range.start + rng.below(range.len());
                saved.push((at, image[at]));
                image[at] ^= (rng.next() as u8) | 1;
            }
            if name == "windows" {
                // Give UDF descriptors whose sector changed a right checksum again, so the reader goes deeper.
                let starts: Vec<usize> = saved.iter().map(|&(at, _)| at / 2048 * 2048).collect();
                for start in starts {
                    if start >= s(256) {
                        saved.push((start + 4, image[start + 4]));
                        image[start + 4] = tag_checksum(&image[start..start + 16]);
                    }
                }
            }
            everything(&image);
            for (at, byte) in saved.into_iter().rev() {
                image[at] = byte;
            }
        }
        assert_eq!(image, original);
        eprintln!("{name}: flipped, {:?} so far", started.elapsed());
    }
    assert!(started.elapsed() < Duration::from_secs(120));
}

fn both(value: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&value.to_le_bytes());
    out[4..].copy_from_slice(&value.to_be_bytes());
    out
}

fn record(image: &[u8], path: &str, tree: Tree) -> iso9660::Record {
    let mut cursor = Cursor::new(image);
    let mut img = Image::new(&mut cursor).unwrap();
    let volume = iso9660::Volume::read(&mut img).unwrap();
    volume.lookup(&mut img, path, tree).unwrap().unwrap()
}

fn with(image: &[u8], at: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = image.to_vec();
    out[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    out
}

#[test]
fn absurd_sizes_and_extents_are_refused() {
    let image = fake::ubuntu_24_04();
    let grub = record(&image, "/boot/grub/grub.cfg", Tree::RockRidge);
    let boot = record(&image, "/boot", Tree::RockRidge);
    let md5sum = record(&image, "/md5sum.txt", Tree::RockRidge);
    let root = s(16) as u64 + 156;
    for (at, value) in [
        (grub.offset + 10, u32::MAX),
        (grub.offset + 2, u32::MAX),
        (grub.offset + 10, 0),
        (boot.offset + 10, u32::MAX),
        (boot.offset + 2, 0xFFFF_FFF0),
        (md5sum.offset + 10, 0x7FFF_FFFF),
        (root + 10, u32::MAX),
        (root + 2, u32::MAX),
    ] {
        let bad = with(&image, at, &both(value));
        everything(&bad);
        assert!(plan(&mut Cursor::new(&bad), Flavor::Ubuntu).is_err(), "{at} = {value}");
    }
    // Byte orders that disagree on a record the copy changes.
    let bad = with(&image, grub.offset + 14, &[0, 0, 0, 1]);
    let err = plan(&mut Cursor::new(&bad), Flavor::Ubuntu).unwrap_err().to_string();
    assert!(err.contains("two byte orders disagree"), "{err}");
    // A block size that isn't 2048.
    let bad = with(&image, s(16) as u64 + 128, &[0, 2, 2, 0]);
    let err = plan(&mut Cursor::new(&bad), Flavor::Ubuntu).unwrap_err().to_string();
    assert!(err.contains("logical block size is 512 bytes, not 2048"), "{err}");
    // A record longer than it is: whatever it then reads, it returns.
    everything(&with(&image, boot.offset, &[255]));
    everything(&with(&image, boot.offset, &[1]));
    // A name longer than its record.
    let bad = with(&image, boot.offset + 32, &[250]);
    assert!(plan(&mut Cursor::new(&bad), Flavor::Ubuntu).is_err());
}

#[test]
fn folders_that_point_at_themselves_end() {
    let image = fake::ubuntu_24_04();
    let boot = record(&image, "/boot", Tree::RockRidge);
    let mut cursor = Cursor::new(&image);
    let mut img = Image::new(&mut cursor).unwrap();
    let root = iso9660::Volume::read(&mut img).unwrap().primary_root;
    // /boot is the root again: a lookup still walks one folder a part.
    let mut looped = with(&image, boot.offset + 2, &both(root.extent));
    looped = with(&looped, boot.offset + 10, &both(root.size));
    let deep = format!("{}/md5sum.txt", "/boot".repeat(MAX_PATH_PARTS - 1));
    assert!(read_file(&mut Cursor::new(&looped), &deep, Tree::RockRidge)
        .unwrap()
        .is_some());
    let too_deep = format!("{}/md5sum.txt", "/boot".repeat(MAX_PATH_PARTS));
    assert!(read_file(&mut Cursor::new(&looped), &too_deep, Tree::RockRidge).is_err());
    assert!(
        plan(&mut Cursor::new(&looped), Flavor::Ubuntu).is_err(),
        "no /boot/grub any more"
    );
    everything(&looped);
    // /boot/grub is /boot.
    let grub_dir = record(&image, "/boot/grub", Tree::RockRidge);
    let looped = with(&image, grub_dir.offset + 2, &both(boot.extent));
    let err = plan(&mut Cursor::new(&looped), Flavor::Ubuntu).unwrap_err().to_string();
    assert!(err.contains("/boot/grub/grub.cfg isn't on it"), "{err}");
}

fn find(image: &[u8], needle: &[u8]) -> usize {
    image.windows(needle.len()).position(|w| w == needle).unwrap()
}

#[test]
fn rock_ridge_continuations_that_loop_or_lie_are_bounded() {
    let image = LinuxIso {
        nm_in_continuation: Some("/boot/grub/grub.cfg".into()),
        ..fake::ubuntu_24_04_iso()
    }
    .build();
    // The continuation area: the rest of the name, then ST.
    let area = find(&image, b"NM\x09\x01\x00.cfgST\x04\x01");
    let area_sector = (area / 2048) as u32;
    // The record's CE entry.
    let entry = find(&image, &[b'C', b'E', 28, 1]);
    // A continuation area that continues into itself, never finishing the name.
    let mut looped = image.clone();
    let mut again = vec![b'N', b'M', 6, 1, 1, b'x'];
    again.extend([b'C', b'E', 28, 1]);
    again.extend(both(area_sector));
    again.extend(both(0));
    again.extend(both(34));
    looped[area..area + again.len()].copy_from_slice(&again);
    let started = Instant::now();
    let err = plan(&mut Cursor::new(&looped), Flavor::Ubuntu).unwrap_err().to_string();
    assert!(err.contains("/boot/grub/grub.cfg isn't on it"), "{err}");
    everything(&looped);
    assert!(started.elapsed() < Duration::from_secs(5));
    // Continuation areas past the end, or larger than a sector.
    for (field, value) in [
        (4, u32::MAX),
        (12, u32::MAX),
        (20, u32::MAX),
        (20, 4096),
        (4, (image.len() / 2048) as u32),
    ] {
        let bad = with(&image, (entry + field) as u64, &both(value));
        assert!(
            plan(&mut Cursor::new(&bad), Flavor::Ubuntu).is_err(),
            "{field} = {value}"
        );
        everything(&bad);
    }
    // An NM entry whose length runs past its area is left unread.
    let nm = find(&image, b"NM\x09\x01\x00.cfg");
    let bad = with(&image, (nm + 2) as u64, &[200]);
    everything(&bad);
}

fn retag(image: &mut [u8], start: usize) {
    image[start + 4] = tag_checksum(&image[start..start + 16]);
}

#[test]
fn udf_addresses_outside_the_image_or_partition_are_refused() {
    let image = fake::windows_server();
    let partition = fake::UDF_PARTITION_START;
    let root_entry = s(partition + 2);
    for (at, bytes, tag) in [
        (s(256) + 20, 0xFFFF_FF00u32.to_le_bytes().to_vec(), s(256)),
        (s(258) + 252, 0xFFFF_FFF0u32.to_le_bytes().to_vec(), s(258)),
        (s(258) + 256, 7u16.to_le_bytes().to_vec(), s(258)),
        (s(258) + 264, u32::MAX.to_le_bytes().to_vec(), s(258)),
        (s(258) + 268, 1000u32.to_le_bytes().to_vec(), s(258)),
        (s(258) + 440, vec![2, 64], s(258)),
        (s(258) + 212, 512u32.to_le_bytes().to_vec(), s(258)),
        (s(259) + 188, 0xFFFF_FF00u32.to_le_bytes().to_vec(), s(259)),
        (s(259) + 22, 1u16.to_le_bytes().to_vec(), s(259)),
        (s(partition) + 404, 0xFFFF_FFF0u32.to_le_bytes().to_vec(), s(partition)),
        (
            root_entry + 176,
            [0xFF, 0xFF, 0xFF, 0x3F, 0xF0, 0xFF, 0xFF, 0xFF].to_vec(),
            root_entry,
        ),
        (root_entry + 56, u64::MAX.to_le_bytes().to_vec(), root_entry),
        (root_entry + 172, u32::MAX.to_le_bytes().to_vec(), root_entry),
        (root_entry + 34, 2u16.to_le_bytes().to_vec(), root_entry),
        (root_entry + 176, [0x00, 0x08, 0x00, 0x80].to_vec(), root_entry),
        (root_entry, 999u16.to_le_bytes().to_vec(), root_entry),
    ] {
        let mut bad = with(&image, at as u64, &bytes);
        retag(&mut bad, tag);
        let started = Instant::now();
        assert!(plan(&mut Cursor::new(&bad), Flavor::WindowsServer).is_err(), "{at}");
        everything(&bad);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    // A wrong checksum is refused where it matters.
    let bad = with(&image, (s(258) + 4) as u64, &[image[s(258) + 4] ^ 1]);
    assert!(plan(&mut Cursor::new(&bad), Flavor::WindowsServer).is_err());
}

#[test]
fn a_udf_folder_that_points_at_itself_ends() {
    let image = fake::windows_server();
    // The root's identifier of `efi` (16-bit name) is made to point at the root's own entry.
    let name: Vec<u8> = [16u8]
        .into_iter()
        .chain("efi".encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    let at = find(&image, &name) - 38;
    let root_entry = 2u32;
    let mut looped = with(&image, (at + 24) as u64, &root_entry.to_le_bytes());
    retag(&mut looped, at);
    let deep = "/efi".repeat(MAX_PATH_PARTS);
    let started = Instant::now();
    assert!(
        read_file(&mut Cursor::new(&looped), &deep, Tree::Udf).is_err(),
        "a folder, however deep"
    );
    let err = plan(&mut Cursor::new(&looped), Flavor::WindowsServer)
        .unwrap_err()
        .to_string();
    assert!(err.contains("efisys_noprompt.bin isn't on it"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_damaged_boot_catalog_is_refused() {
    let image = fake::windows_server();
    let catalog = s(fake::BOOT_CATALOG_SECTOR);
    for (at, bytes) in [
        (catalog + 28, vec![0, 0]),
        (catalog + 31, vec![0]),
        (catalog + 96, vec![0x77]),
        (catalog + 66, vec![0xFF, 0xFF]),
        (s(17) + 71, 0xFFFF_FFF0u32.to_le_bytes().to_vec()),
        (catalog + 104, 0xFFFF_FFF0u32.to_le_bytes().to_vec()),
        (catalog + 97, vec![2]),
    ] {
        let bad = with(&image, at as u64, &bytes);
        assert!(plan(&mut Cursor::new(&bad), Flavor::WindowsServer).is_err(), "{at}");
        everything(&bad);
    }
}
