//! Opt-in checks against real install ISOs on this PC (CLAUDE.md "Development safety": opt-in, read only).
//!
//! * `REMOTELY_IT=1` and `REMOTELY_IT_ISO_DIR` (one folder, or several separated as the PATH is): every `*.iso`
//!   directly in them must plan as exactly one flavor. The originals are only opened for reading.
//! * Also `REMOTELY_IT_ISO_COPY_DIR` (a folder outside any repository, with room for a few GB): for each flavor,
//!   the smallest ISO that plans is copied there with [`make_copy`], the changed files are read back through each
//!   tree, the copy is compared with the original byte for byte (every difference must be a planned write), and the
//!   copy is deleted.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use super::eltorito::Catalog;
use super::udf::{Udf, UdfData};
use super::*;

fn iso_dirs() -> Option<Vec<PathBuf>> {
    if std::env::var("REMOTELY_IT").as_deref() != Ok("1") {
        return None;
    }
    let dirs = std::env::var_os("REMOTELY_IT_ISO_DIR")?;
    Some(std::env::split_paths(&dirs).collect())
}

fn isos(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in dirs {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("iso")) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_real_iso_plans_as_exactly_one_flavor() {
    let Some(dirs) = iso_dirs() else {
        return;
    };
    let isos = isos(&dirs);
    assert!(!isos.is_empty(), "no ISO in {dirs:?}");
    for iso in &isos {
        let mut planned = Vec::new();
        eprintln!("{}", iso.display());
        for flavor in Flavor::ALL {
            match plan_file(iso, flavor) {
                Ok(plan) => {
                    eprintln!(
                        "  {flavor:?}: {} writes, {} bytes",
                        plan.writes.len(),
                        plan.changed_bytes()
                    );
                    for line in &plan.summary {
                        eprintln!("    {line}");
                    }
                    planned.push(flavor);
                }
                Err(err) => eprintln!("  {flavor:?} refused: {err}"),
            }
        }
        assert_eq!(planned.len(), 1, "{}: {planned:?}", iso.display());
    }
}

/// Deletes the copy however the test ends.
struct Remove(PathBuf);

impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn differences(original: &Path, copy: &Path) -> Vec<u64> {
    let (mut a, mut b) = (File::open(original).unwrap(), File::open(copy).unwrap());
    assert_eq!(a.metadata().unwrap().len(), b.metadata().unwrap().len());
    let mut out = Vec::new();
    let (mut x, mut y) = (vec![0u8; 8 << 20], vec![0u8; 8 << 20]);
    let mut at = 0u64;
    loop {
        let n = a.read(&mut x).unwrap();
        if n == 0 {
            break;
        }
        b.read_exact(&mut y[..n]).unwrap();
        if x[..n] != y[..n] {
            out.extend((0..n).filter(|&i| x[i] != y[i]).map(|i| at + i as u64));
        }
        at += n as u64;
    }
    out
}

fn check_copy(copy: &Path, plan: &IsoPlan) {
    let mut file = File::open(copy).unwrap();
    match plan.flavor {
        Flavor::Ubuntu => {
            let rr = read_file(&mut file, ubuntu::GRUB_CFG, Tree::RockRidge)
                .unwrap()
                .unwrap();
            let joliet = read_file(&mut file, ubuntu::GRUB_CFG, Tree::Joliet).unwrap().unwrap();
            assert_eq!(rr, joliet);
            let text = String::from_utf8(rr).unwrap();
            eprintln!("grub.cfg now:\n{text}");
            assert!(text.contains(ubuntu::BEFORE_DASHES) && text.contains("set timeout=1"));
            let md5sum = read_file(&mut file, "/md5sum.txt", Tree::RockRidge).unwrap().unwrap();
            let line = format!("{}  ./boot/grub/grub.cfg", md5::md5_hex(text.as_bytes()));
            assert!(String::from_utf8_lossy(&md5sum).lines().any(|l| l == line));
        }
        Flavor::Debian => {
            for (path, expected) in [
                (debian::ISOLINUX_CFG, debian::isolinux_cfg()),
                (debian::GRUB_CFG, debian::grub_cfg()),
            ] {
                for tree in [Tree::RockRidge, Tree::Joliet] {
                    let got = read_file(&mut file, path, tree).unwrap().unwrap();
                    assert_eq!(String::from_utf8(got).unwrap(), expected, "{path} {tree:?}");
                }
            }
            let md5sum = read_file(&mut file, "/md5sum.txt", Tree::RockRidge).unwrap().unwrap();
            let line = format!("{}  ./boot/grub/grub.cfg", md5::md5_hex(debian::grub_cfg().as_bytes()));
            assert!(String::from_utf8_lossy(&md5sum).lines().any(|l| l == line));
        }
        Flavor::WindowsServer => {
            let mut img = Image::new(&mut file).unwrap();
            let volume = iso9660::Volume::read(&mut img).unwrap();
            let catalog = Catalog::read(&mut img, volume.boot_catalog.unwrap()).unwrap();
            let entry = catalog.first_for(windows::EFI_PLATFORM).unwrap();
            let udf = Udf::open(&mut img).unwrap().unwrap();
            let noprompt = udf.lookup(&mut img, windows::NOPROMPT_PATH).unwrap().unwrap();
            let UdfData::Extents(extents) = noprompt.data else {
                panic!("embedded")
            };
            eprintln!("UEFI entry at sector {} (count {})", entry.load_rba, entry.sector_count);
            assert_eq!(u64::from(entry.load_rba), extents[0].sector);
            assert_eq!(entry.sector_count, 1);
        }
    }
}

#[test]
fn real_iso_copies_change_only_the_planned_bytes() {
    let Some(dirs) = iso_dirs() else {
        return;
    };
    let Some(out) = std::env::var_os("REMOTELY_IT_ISO_COPY_DIR").map(PathBuf::from) else {
        return;
    };
    let mut by_size = isos(&dirs);
    by_size.sort_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(u64::MAX));
    for flavor in Flavor::ALL {
        let Some((iso, plan)) = by_size
            .iter()
            .find_map(|iso| plan_file(iso, flavor).ok().map(|plan| (iso.clone(), plan)))
        else {
            eprintln!("{flavor:?}: no ISO plans");
            continue;
        };
        let copy = out.join(format!("remotely-iso-copy-{flavor:?}.iso"));
        let _remove = Remove(copy.clone());
        let started = std::time::Instant::now();
        make_copy(&iso, &copy, &plan, &|_, _| {}, &AtomicBool::new(false)).unwrap();
        eprintln!("{flavor:?}: {} copied in {:?}", iso.display(), started.elapsed());
        check_copy(&copy, &plan);
        let differing = differences(&iso, &copy);
        eprintln!("{flavor:?}: {} bytes differ", differing.len());
        assert!(differing.iter().all(|at| plan
            .writes
            .iter()
            .any(|w| (w.offset..w.offset + w.bytes.len() as u64).contains(at))));
        if flavor == Flavor::WindowsServer {
            assert!(differing.len() <= 4);
        }
    }
}
