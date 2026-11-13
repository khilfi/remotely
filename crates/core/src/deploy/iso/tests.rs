//! Plans and copies of the fake install ISOs (`fakes::install_isos`), read back through every tree.

use std::cell::Cell;
use std::io::Cursor;
use std::sync::atomic::AtomicBool;

use super::udf::{Udf, UdfData};
use super::*;
use crate::fakes::disk_images::TempFolder;
use crate::fakes::install_isos::{self as fake, LinuxIso, WindowsIso};

fn plan_of(image: &[u8], flavor: Flavor) -> Result<IsoPlan> {
    plan(&mut Cursor::new(image), flavor)
}

fn refusal(image: &[u8], flavor: Flavor) -> String {
    match plan_of(image, flavor) {
        Ok(plan) => panic!("{flavor:?} planned: {:?}", plan.summary),
        Err(err) => {
            assert_eq!(err.code(), "invalid_input", "{err}");
            err.to_string()
        }
    }
}

/// The image with the plan's writes in, checking each replaces what is there.
fn patched(image: &[u8], plan: &IsoPlan) -> Vec<u8> {
    let mut out = image.to_vec();
    for write in &plan.writes {
        let range = write.offset as usize..write.offset as usize + write.bytes.len();
        assert_eq!(out[range.clone()], write.replaces[..], "at {}", write.offset);
        out[range].copy_from_slice(&write.bytes);
    }
    out
}

fn read(image: &[u8], path: &str, tree: Tree) -> Option<Vec<u8>> {
    read_file(&mut Cursor::new(image), path, tree).unwrap()
}

fn text(bytes: Option<Vec<u8>>) -> String {
    String::from_utf8(bytes.unwrap()).unwrap()
}

fn md5sum_has(image: &[u8], path: &str, content: &[u8]) -> bool {
    let md5sum = text(read(image, "/md5sum.txt", Tree::RockRidge));
    md5sum
        .lines()
        .any(|line| line == format!("{}  {path}", fake::md5_hex(content)))
}

const LINE_24: &str = "\tlinux\t/casper/vmlinuz  autoinstall console=tty0 console=ttyS0,115200n8 --- console=tty0 \
                       console=ttyS0,115200n8";
const HWE_24: &str = "\tlinux\t/casper/hwe-vmlinuz  autoinstall console=tty0 console=ttyS0,115200n8 --- \
                      console=tty0 console=ttyS0,115200n8";
const LINE_26: &str = "    linux  /casper/vmlinuz  autoinstall console=tty0 console=ttyS0,115200n8 --- console=tty0 \
                       console=ttyS0,115200n8 ";

#[test]
fn grub_24_04_gets_s1s_lines_and_keeps_its_tabs() {
    let patched = ubuntu::patch_grub(fake::UBUNTU_24_04_GRUB).unwrap();
    let expected = fake::UBUNTU_24_04_GRUB
        .replace("set timeout=30", "set timeout=1")
        .replace("\tlinux\t/casper/vmlinuz  ---", LINE_24)
        .replace("\tlinux\t/casper/hwe-vmlinuz  ---", HWE_24);
    assert_eq!(patched.text, expected);
    assert_eq!(patched.entries, 2);
    assert_eq!(patched.kernels, ["/casper/vmlinuz", "/casper/hwe-vmlinuz"]);
    assert_eq!(patched.old_timeout, "30");
    assert!(
        patched.text.contains("\tlinux16 /boot/memtest86+x64.bin\n"),
        "memtest left alone"
    );
}

#[test]
fn grub_26_04_keeps_its_spaces_and_trailing_space() {
    let patched = ubuntu::patch_grub(fake::UBUNTU_26_04_GRUB).unwrap();
    let expected = fake::UBUNTU_26_04_GRUB
        .replace("set timeout=30", "set timeout=1")
        .replace("    linux  /casper/vmlinuz  --- ", LINE_26);
    assert_eq!(patched.text, expected);
    assert_eq!(patched.entries, 1);
    // Windows line ends stay as they are.
    let crlf = fake::UBUNTU_26_04_GRUB.replace('\n', "\r\n");
    let patched = ubuntu::patch_grub(&crlf).unwrap();
    assert_eq!(patched.text, expected.replace('\n', "\r\n"));
}

#[test]
fn grub_texts_remotely_doesnt_know_are_refused() {
    let refuse = |text: &str, words: &str| {
        let err = ubuntu::patch_grub(text).unwrap_err().to_string();
        assert!(err.contains(words), "{err}");
        assert!(err.starts_with("This isn't an Ubuntu Server install ISO"), "{err}");
    };
    refuse(
        "set timeout=5\nmenuentry x {\n linux /boot/vmlinuz ---\n}\n",
        "no `linux /casper/vmlinuz",
    );
    refuse(
        "set timeout=5\nlinux /casper/vmlinuz quiet\n",
        "no `linux /casper/vmlinuz",
    );
    refuse("linux /casper/vmlinuz ---\n", "no `set timeout=`");
    refuse(
        "set timeout=5\nlinux /casper/vmlinuz autoinstall ---\n",
        "already has autoinstall",
    );
    refuse(
        "set timeout=x\nlinux /casper/vmlinuz ---\n",
        "timeout Remotely doesn't read",
    );
    refuse(
        "set timeout=5\nset default=1\nlinux /casper/vmlinuz ---\n",
        "another entry than the first",
    );
    refuse(
        "set timeout=5\nlinux /boot/other ---\nlinux /casper/vmlinuz ---\n",
        "first menu entry doesn't boot the casper installer",
    );
    assert!(ubuntu::patch_grub("set default=0\nset timeout=5\nlinux /casper/vmlinuz ---\n").is_ok());
}

#[test]
fn ubuntu_copies_change_grub_cfg_in_both_trees_and_its_checksum() {
    for (builder, original, line) in [
        (fake::ubuntu_24_04_iso(), fake::UBUNTU_24_04_GRUB, LINE_24),
        (fake::ubuntu_26_04_iso(), fake::UBUNTU_26_04_GRUB, LINE_26),
    ] {
        let image = builder.build();
        let plan = plan_of(&image, Flavor::Ubuntu).unwrap();
        assert_eq!(plan.iso_bytes, image.len() as u64);
        assert_eq!(plan.writes.len(), 4, "the sector, two sizes, the md5sum line");
        let copy = patched(&image, &plan);
        let new = ubuntu::patch_grub(original).unwrap().text;
        assert!(new.contains(line));
        for tree in [Tree::RockRidge, Tree::Joliet] {
            assert_eq!(text(read(&copy, "/boot/grub/grub.cfg", tree)), new, "{tree:?}");
        }
        assert!(md5sum_has(&copy, "./boot/grub/grub.cfg", new.as_bytes()));
        assert!(md5sum_has(&image, "./boot/grub/grub.cfg", original.as_bytes()));
        assert_eq!(
            read(&copy, "/casper/vmlinuz", Tree::RockRidge),
            read(&image, "/casper/vmlinuz", Tree::Joliet)
        );
        assert!(
            plan.summary[0].starts_with("Release: Ubuntu-Server 2"),
            "{:?}",
            plan.summary
        );
        assert!(plan.summary[1].contains("menu entr"), "{:?}", plan.summary);
        assert!(
            plan.summary[1].contains("waits 1 s instead of 30 s"),
            "{:?}",
            plan.summary
        );
        assert!(plan.summary[2].contains("checksum updated"), "{:?}", plan.summary);
        // The rest of the file's sector is zeroed.
        let data = plan.writes.iter().find(|w| w.bytes.len() == 2048).unwrap();
        assert!(data.bytes[new.len()..].iter().all(|b| *b == 0));
    }
}

#[test]
fn a_copy_of_a_copy() {
    let ubuntu = fake::ubuntu_24_04();
    let copy = patched(&ubuntu, &plan_of(&ubuntu, Flavor::Ubuntu).unwrap());
    assert!(refusal(&copy, Flavor::Ubuntu).contains("already has autoinstall"));

    let debian = fake::debian();
    let copy = patched(&debian, &plan_of(&debian, Flavor::Debian).unwrap());
    let again = plan_of(&copy, Flavor::Debian).unwrap();
    assert_eq!(patched(&copy, &again), copy, "the same menus again");
    assert!(again.summary.iter().any(|s| s.contains("already had these menus")));

    let windows = fake::windows_server();
    let copy = patched(&windows, &plan_of(&windows, Flavor::WindowsServer).unwrap());
    let again = plan_of(&copy, Flavor::WindowsServer).unwrap();
    assert_eq!(patched(&copy, &again), copy);
    assert!(again.summary[1].contains("already loads"), "{:?}", again.summary);
}

#[test]
fn debian_copies_replace_both_menus() {
    let builder = fake::debian_iso();
    let image = builder.build();
    let plan = plan_of(&image, Flavor::Debian).unwrap();
    let copy = patched(&image, &plan);
    for tree in [Tree::RockRidge, Tree::Joliet] {
        assert_eq!(
            text(read(&copy, "/isolinux/isolinux.cfg", tree)),
            debian::isolinux_cfg(),
            "{tree:?}"
        );
        assert_eq!(
            text(read(&copy, "/boot/grub/grub.cfg", tree)),
            debian::grub_cfg(),
            "{tree:?}"
        );
    }
    assert!(md5sum_has(&copy, "./boot/grub/grub.cfg", debian::grub_cfg().as_bytes()));
    assert!(
        md5sum_has(&copy, "./install.amd/initrd.gz", b"initrd stand-in"),
        "other lines kept"
    );
    // grub.cfg's three sectors: the new text, then zeros.
    let grub_len = builder.file("/boot/grub/grub.cfg").unwrap().len();
    assert!(grub_len > 2 * 2048);
    let data = plan.writes.iter().find(|w| w.bytes.len() == 3 * 2048).unwrap();
    assert!(data.bytes[debian::grub_cfg().len()..].iter().all(|b| *b == 0));
    assert_eq!(
        read(&copy, "/install.amd/initrd.gz", Tree::RockRidge),
        read(&image, "/install.amd/initrd.gz", Tree::RockRidge)
    );
    assert!(
        plan.summary[0].starts_with("Release: Debian GNU/Linux 13"),
        "{:?}",
        plan.summary
    );
    assert!(plan.summary.iter().any(|s| s.starts_with("isolinux.cfg (BIOS)")));
    assert!(plan
        .summary
        .iter()
        .any(|s| s == "md5sum.txt: grub.cfg's checksum updated, so the installer's media check passes."));
    assert_eq!(
        plan.summary.len(),
        4,
        "isolinux.cfg has no md5sum line: {:?}",
        plan.summary
    );
}

fn noprompt_sector(image: &[u8]) -> u64 {
    let mut cursor = Cursor::new(image);
    let mut img = Image::new(&mut cursor).unwrap();
    let udf = Udf::open(&mut img).unwrap().unwrap();
    let file = udf.lookup(&mut img, windows::NOPROMPT_PATH).unwrap().unwrap();
    match file.data {
        UdfData::Extents(extents) => extents[0].sector,
        UdfData::Embedded(_) => panic!("embedded"),
    }
}

#[test]
fn windows_copies_point_uefi_at_the_noprompt_image() {
    let image = fake::windows_server();
    let plan = plan_of(&image, Flavor::WindowsServer).unwrap();
    assert_eq!(plan.writes.len(), 1);
    let entry = (fake::BOOT_CATALOG_SECTOR * 2048 + 96) as u64;
    assert_eq!(plan.writes[0].offset, entry + 8);
    let copy = patched(&image, &plan);
    let sector = noprompt_sector(&image);
    let rba = u32::from_le_bytes(copy[entry as usize + 8..entry as usize + 12].try_into().unwrap());
    assert_eq!(u64::from(rba), sector);
    let boot = &copy[rba as usize * 2048..rba as usize * 2048 + 512];
    assert_eq!(&boot[43..51], b"NOPROMPT");
    let differing: Vec<usize> = (0..image.len()).filter(|&i| image[i] != copy[i]).collect();
    assert!(!differing.is_empty() && differing.len() <= 4, "{differing:?}");
    assert!(differing
        .iter()
        .all(|&i| (entry as usize + 8..entry as usize + 12).contains(&i)));
    // The sector count stays 1.
    assert_eq!(&copy[entry as usize + 6..entry as usize + 8], &[1, 0]);
    assert!(
        plan.summary[1].contains(&format!("efisys_noprompt.bin (sector {rba})")),
        "{:?}",
        plan.summary
    );
    assert_eq!(plan.summary[0], "Volume label: SSS_X64FREE_EN-US_DV9.");
    // UDF reads every kind of entry the fake has.
    let noprompt = read(&copy, "/EFI/Microsoft/Boot/efisys_noprompt.bin", Tree::Udf).unwrap();
    assert_eq!(noprompt.len(), windows::EFI_IMAGE_BYTES as usize);
    assert_eq!(
        read(&copy, "/sources/ei.cfg", Tree::Udf).unwrap(),
        b"[Channel]\r\nRetail\r\n"
    );
    assert_eq!(read(&copy, "/sources/missing.wim", Tree::Udf), None);
    assert!(
        read_file(&mut Cursor::new(&copy), "/efi", Tree::Udf).is_err(),
        "a folder"
    );
    assert_eq!(
        text(read(&copy, "/readme.txt", Tree::RockRidge)),
        "This disc holds a test image, not Windows.\r\n"
    );
    assert!(
        read_file(&mut Cursor::new(&copy), "/readme.txt", Tree::Joliet).is_err(),
        "no Joliet tree"
    );
}

#[test]
fn refusals_name_what_did_not_match() {
    let ubuntu = fake::ubuntu_24_04();
    let debian = fake::debian();
    let windows = fake::windows_server();
    for (image, flavor, words) in [
        (&debian, Flavor::Ubuntu, "has no `linux /casper/vmlinuz ... ---` line"),
        (&windows, Flavor::Ubuntu, "it has no Rock Ridge names"),
        (&ubuntu, Flavor::Debian, "/install.amd/vmlinuz isn't on it"),
        (&windows, Flavor::Debian, "it has no Rock Ridge names"),
        (&ubuntu, Flavor::WindowsServer, "it has no El Torito boot record"),
        (&debian, Flavor::WindowsServer, "it has no El Torito boot record"),
    ] {
        let err = refusal(image, flavor);
        assert!(err.contains(words), "{flavor:?}: {err}");
    }
    let cases: Vec<(Vec<u8>, Flavor, &str)> = vec![
        (
            WindowsIso {
                efi_entry: false,
                ..WindowsIso::default()
            }
            .build(),
            Flavor::WindowsServer,
            "its boot catalog has no UEFI entry",
        ),
        (
            WindowsIso {
                noprompt: false,
                ..WindowsIso::default()
            }
            .build(),
            Flavor::WindowsServer,
            "efi/microsoft/boot/efisys_noprompt.bin isn't on it",
        ),
        (
            WindowsIso {
                noprompt_bytes: 1_474_560 - 2048,
                ..WindowsIso::default()
            }
            .build(),
            Flavor::WindowsServer,
            "efisys_noprompt.bin is 1472512 bytes, not the 1474560",
        ),
        (
            WindowsIso {
                install_wim: false,
                ..WindowsIso::default()
            }
            .build(),
            Flavor::WindowsServer,
            "sources/install.wim isn't on it",
        ),
        (
            LinuxIso {
                joliet: false,
                ..fake::ubuntu_24_04_iso()
            }
            .build(),
            Flavor::Ubuntu,
            "it has no Joliet tree",
        ),
        (
            LinuxIso {
                rock_ridge: false,
                ..fake::debian_iso()
            }
            .build(),
            Flavor::Debian,
            "it has no Rock Ridge names",
        ),
        (
            LinuxIso {
                joliet_own_copy: Some("/boot/grub/grub.cfg".into()),
                ..fake::ubuntu_26_04_iso()
            }
            .build(),
            Flavor::Ubuntu,
            "Rock Ridge and Joliet records of /boot/grub/grub.cfg point at different data",
        ),
        (
            fake::ubuntu_24_04_iso().without_file("/casper/hwe-vmlinuz").build(),
            Flavor::Ubuntu,
            "/casper/hwe-vmlinuz isn't on it",
        ),
        (
            fake::debian_iso().without_file("/isolinux/isolinux.cfg").build(),
            Flavor::Debian,
            "/isolinux/isolinux.cfg isn't on it",
        ),
        (
            fake::debian_iso().without_file("/install.amd/initrd.gz").build(),
            Flavor::Debian,
            "/install.amd/initrd.gz isn't on it",
        ),
        (
            vec![0u8; 100 * 2048],
            Flavor::Ubuntu,
            "it has no ISO 9660 primary volume descriptor",
        ),
        (
            vec![0u8; 1000],
            Flavor::WindowsServer,
            "it is too small to be an ISO image",
        ),
    ];
    for (image, flavor, words) in cases {
        let err = refusal(&image, flavor);
        assert!(err.contains(words), "{flavor:?}: {err}");
    }
}

#[test]
fn a_grub_cfg_the_new_lines_dont_fit_is_refused() {
    // Exactly one sector, so the 166 bytes the two lines get have no room.
    let mut grub = fake::UBUNTU_24_04_GRUB.to_owned();
    while grub.len() < 2048 {
        grub.push_str("#\n");
    }
    grub.truncate(2047);
    grub.push('\n');
    let image = fake::ubuntu_24_04_iso().with_file("/boot/grub/grub.cfg", grub).build();
    let err = refusal(&image, Flavor::Ubuntu);
    assert!(
        err.contains("doesn't fit the 2048 bytes of the sectors the file has"),
        "{err}"
    );
}

#[test]
fn md5sum_txt_is_updated_when_it_lists_grub_cfg() {
    let missing = fake::ubuntu_24_04_iso().without_file("/md5sum.txt").build();
    let plan = plan_of(&missing, Flavor::Ubuntu).unwrap();
    assert_eq!(plan.writes.len(), 3);
    assert!(
        plan.summary[2].contains("md5sum.txt isn't on the ISO"),
        "{:?}",
        plan.summary
    );

    let unlisted = fake::ubuntu_24_04_iso()
        .with_file(
            "/md5sum.txt",
            fake::md5sum_txt(&[("./casper/vmlinuz", b"kernel stand-in")]),
        )
        .build();
    let plan = plan_of(&unlisted, Flavor::Ubuntu).unwrap();
    assert_eq!(plan.writes.len(), 3);
    assert!(
        plan.summary[2].contains("has no line for grub.cfg"),
        "{:?}",
        plan.summary
    );

    let upper = String::from_utf8(fake::md5sum_txt(&[(
        "./boot/grub/grub.cfg",
        fake::UBUNTU_24_04_GRUB.as_bytes(),
    )]))
    .unwrap();
    let (digest, rest) = upper.split_at(32);
    let upper = format!("{}{rest}", digest.to_ascii_uppercase()).replace('\n', "\r\n");
    let image = fake::ubuntu_24_04_iso().with_file("/md5sum.txt", upper).build();
    let plan = plan_of(&image, Flavor::Ubuntu).unwrap();
    let copy = patched(&image, &plan);
    let new = ubuntu::patch_grub(fake::UBUNTU_24_04_GRUB).unwrap().text;
    assert_eq!(
        text(read(&copy, "/md5sum.txt", Tree::RockRidge)),
        format!(
            "{}  ./boot/grub/grub.cfg\r\n",
            fake::md5_hex(new.as_bytes()).to_ascii_uppercase()
        )
    );
}

#[test]
fn rock_ridge_names_are_followed_into_continuation_areas() {
    let builder = LinuxIso {
        nm_in_continuation: Some("/boot/grub/grub.cfg".into()),
        joliet_versions: true,
        ..fake::ubuntu_24_04_iso()
    };
    let image = builder.build();
    assert_eq!(
        text(read(&image, "/boot/grub/grub.cfg", Tree::RockRidge)),
        fake::UBUNTU_24_04_GRUB
    );
    assert_eq!(
        text(read(&image, "/boot/grub/grub.cfg", Tree::Joliet)),
        fake::UBUNTU_24_04_GRUB
    );
    assert!(plan_of(&image, Flavor::Ubuntu).is_ok());
    // Rock Ridge names are matched exactly; the plain names in any letter case.
    assert_eq!(read(&image, "/BOOT/GRUB/GRUB.CFG", Tree::RockRidge), None);
    let plain = LinuxIso {
        rock_ridge: false,
        ..fake::ubuntu_24_04_iso()
    }
    .build();
    assert_eq!(
        text(read(&plain, "/BOOT/grub/Grub.Cfg", Tree::RockRidge)),
        fake::UBUNTU_24_04_GRUB
    );
    assert_eq!(
        text(read(&image, "/BOOT/GRUB/GRUB.CFG", Tree::Joliet)),
        fake::UBUNTU_24_04_GRUB
    );
}

#[test]
fn paths_are_checked_before_anything_is_read() {
    let image = fake::ubuntu_24_04();
    for path in ["", "/", "/boot/../md5sum.txt", &"/a".repeat(MAX_PATH_PARTS + 1)] {
        assert!(
            read_file(&mut Cursor::new(&image), path, Tree::RockRidge).is_err(),
            "{path}"
        );
    }
    assert!(
        read_file(&mut Cursor::new(&image), "/boot", Tree::RockRidge).is_err(),
        "a folder"
    );
    assert_eq!(read(&image, "/boot/grub/missing.cfg", Tree::RockRidge), None);
    assert_eq!(
        read(&image, "/md5sum.txt/x", Tree::RockRidge),
        None,
        "a file isn't a folder"
    );
}

#[test]
fn writes_are_sorted_merged_and_checked() {
    let w = |offset: u64, bytes: &[u8]| IsoWrite {
        offset,
        bytes: bytes.to_vec(),
        replaces: vec![0; bytes.len()],
    };
    let writes = finish_writes(vec![w(10, b"ab"), w(0, b"x"), w(10, b"ab")], 100).unwrap();
    assert_eq!(writes, [w(0, b"x"), w(10, b"ab")]);
    assert!(finish_writes(vec![w(10, b"ab"), w(11, b"c")], 100).is_err(), "overlap");
    assert!(finish_writes(vec![w(99, b"ab")], 100).is_err(), "past the end");
    assert!(finish_writes(vec![w(u64::MAX, b"a")], 100).is_err());
    assert!(finish_writes(vec![w(0, b"")], 100).is_err());
    let mut uneven = w(0, b"ab");
    uneven.replaces.pop();
    assert!(finish_writes(vec![uneven], 100).is_err());
}

#[test]
fn text_from_the_iso_is_made_printable() {
    assert_eq!(printable(b"Ubuntu\x1b[31m 24.04\n\t(x)", 80), "Ubuntu [31m 24.04 (x)");
    assert_eq!(printable("a\u{202E}b".as_bytes(), 80), "ab");
    assert_eq!(printable(b"abcdef", 3), "abc…");
    assert_eq!(printable(b"   ", 3), "");
}

fn plan_file_of(folder: &TempFolder, name: &str, image: &[u8], flavor: Flavor) -> (std::path::PathBuf, IsoPlan) {
    let path = folder.write(name, image);
    let plan = plan_file(&path, flavor).unwrap();
    (path, plan)
}

#[test]
fn make_copy_writes_the_planned_copy_and_reports_progress() {
    let folder = TempFolder::new("iso-copy");
    for (image, flavor) in [
        (fake::ubuntu_26_04(), Flavor::Ubuntu),
        (fake::debian(), Flavor::Debian),
        (fake::windows_server(), Flavor::WindowsServer),
    ] {
        let (source, plan) = plan_file_of(&folder, &format!("{flavor:?}.iso"), &image, flavor);
        let target = folder.join(&format!("{flavor:?}-copy.iso"));
        let calls = Cell::new(0u32);
        let last = Cell::new((0u64, 0u64));
        let progress = |done: u64, total: u64| {
            assert!(done <= total);
            assert!(done >= last.get().0);
            calls.set(calls.get() + 1);
            last.set((done, total));
        };
        make_copy(&source, &target, &plan, &progress, &AtomicBool::new(false)).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), patched(&image, &plan), "{flavor:?}");
        assert_eq!(last.get(), (image.len() as u64, image.len() as u64));
        assert!(calls.get() >= 2);
        assert_eq!(std::fs::read(&source).unwrap(), image, "the original is untouched");
    }
}

#[test]
fn make_copy_never_replaces_a_file_and_deletes_what_it_stopped() {
    let folder = TempFolder::new("iso-copy-stops");
    let image = fake::windows_server();
    let (source, plan) = plan_file_of(&folder, "windows.iso", &image, Flavor::WindowsServer);
    let none = |_: u64, _: u64| {};

    let taken = folder.write("taken.iso", b"mine");
    let err = make_copy(&source, &taken, &plan, &none, &AtomicBool::new(false)).unwrap_err();
    assert!(err.to_string().contains("is there already"), "{err}");
    assert_eq!(std::fs::read(&taken).unwrap(), b"mine");

    let target = folder.join("cancelled.iso");
    let err = make_copy(&source, &target, &plan, &none, &AtomicBool::new(true)).unwrap_err();
    assert!(matches!(err, CoreError::Cancelled), "{err}");
    assert!(!target.exists());

    // Cancelled part-way: the second progress call sets the flag.
    let cancel = AtomicBool::new(false);
    let calls = Cell::new(0);
    let stop = |_: u64, _: u64| {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    };
    let err = make_copy(&source, &target, &plan, &stop, &cancel).unwrap_err();
    assert!(matches!(err, CoreError::Cancelled), "{err}");
    assert!(!target.exists());

    // The source changed where the plan writes: refused, nothing left.
    let mut changed_image = image.clone();
    changed_image[plan.writes[0].offset as usize] ^= 0xFF;
    std::fs::write(&source, &changed_image).unwrap();
    let err = make_copy(&source, &target, &plan, &none, &AtomicBool::new(false)).unwrap_err();
    assert!(err.to_string().contains("changed after Remotely checked it"), "{err}");
    assert!(!target.exists());

    // Or its size did: refused before the copy is made.
    std::fs::write(&source, &image[..image.len() - 2048]).unwrap();
    let err = make_copy(&source, &target, &plan, &none, &AtomicBool::new(false)).unwrap_err();
    assert!(err.to_string().contains("changed after Remotely checked it"), "{err}");
    assert!(!target.exists());

    // A device name is refused unopened, either way round.
    let device = folder.join("nul.iso");
    let err = make_copy(&source, &device, &plan, &none, &AtomicBool::new(false)).unwrap_err();
    assert!(err.to_string().contains("names a Windows device"), "{err}");
    assert!(plan_file(&device, Flavor::Ubuntu)
        .unwrap_err()
        .to_string()
        .contains("names a Windows device"));
}
