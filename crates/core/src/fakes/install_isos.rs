//! VM-29 (0.8.0 G6) in tests: small install ISOs made in memory at run time, laid out like the ones the spikes used
//! (CLAUDE.md "Unattended installs", S1 to S3), so `deploy::iso` plans and copies them. A few hundred KB for the
//! Linux ones and about 5 MB for Windows (its two 1.44 MB boot images are full size, mostly zeros). Never a real
//! ISO, never downloaded.
//!
//! * [`LinuxIso`]: ISO 9660 with Rock Ridge names (`SP` in the root's `.`, `PX` and `NM` on each record) and a
//!   Joliet tree pointing at the same data, as xorriso writes Ubuntu's and Debian's. Options take a part away or
//!   bend it for the refusal tests: no Rock Ridge, no Joliet, Joliet names with `;1`, one file's Rock Ridge name
//!   split into a continuation area, one file's Joliet record on its own copy of the data.
//! * [`ubuntu_24_04`] (tabs, an HWE entry), [`ubuntu_26_04`] (four spaces, a space after `---`) and [`debian`]
//!   (isolinux.cfg of one sector, grub.cfg of three).
//! * [`WindowsIso`]: an ISO 9660 tree holding only README.TXT; El Torito's boot record at 17 and catalog at 22
//!   (a BIOS default entry, a final 0xEF section with one entry on a copy of `efisys.bin`); the UDF volume
//!   recognition sequence at 19 to 21; UDF's anchor at 256, its descriptors from 257, a partition from 304 with
//!   type 1 map 2989 (Microsoft's), File Entries with short allocation descriptors, `efi/` an Extended File Entry
//!   with long ones, 16-bit names in the root and 8-bit ones below, and `sources/ei.cfg` embedded in its entry.

use md5::{Digest, Md5};

pub const SECTOR: usize = 2048;
/// A 1.44 MB floppy image, as `efisys.bin` and `efisys_noprompt.bin` are.
pub const EFI_IMAGE_BYTES: usize = 1_474_560;
/// Where the Windows image's UDF partition starts, as on Microsoft's ISOs.
pub const UDF_PARTITION_START: usize = 304;
/// The Windows image's boot catalog sector.
pub const BOOT_CATALOG_SECTOR: usize = 22;

/// `md5sum` of `data`, by the md-5 crate (not Remotely's own MD5, so each checks the other).
pub fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// An `md5sum.txt` listing `(./path, content)`.
pub fn md5sum_txt(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = String::new();
    for (path, content) in entries {
        out.push_str(&md5_hex(content));
        out.push_str("  ");
        out.push_str(path);
        out.push('\n');
    }
    out.into_bytes()
}

fn both32(v: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&v.to_le_bytes());
    out[4..].copy_from_slice(&v.to_be_bytes());
    out
}

fn both16(v: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[..2].copy_from_slice(&v.to_le_bytes());
    out[2..].copy_from_slice(&v.to_be_bytes());
    out
}

fn to_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

fn sectors_for(len: usize) -> usize {
    len.div_ceil(SECTOR).max(1)
}

fn put(image: &mut [u8], at: usize, bytes: &[u8]) {
    image[at..at + bytes.len()].copy_from_slice(bytes);
}

fn ucs2(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// A directory record: `name` already encoded, `su` its system use area. Padded to an even length.
fn dir_record(name: &[u8], extent: u32, size: u32, dir: bool, su: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 33];
    out[2..10].copy_from_slice(&both32(extent));
    out[10..18].copy_from_slice(&both32(size));
    out[18..25].copy_from_slice(&[126, 11, 13, 9, 0, 0, 0]);
    out[25] = if dir { 0x02 } else { 0x00 };
    out[28..32].copy_from_slice(&both16(1));
    out[32] = u8::try_from(name.len()).unwrap_or(u8::MAX);
    out.extend_from_slice(name);
    if name.len().is_multiple_of(2) {
        out.push(0);
    }
    out.extend_from_slice(su);
    if out.len() % 2 == 1 {
        out.push(0);
    }
    if out.len() > 255 {
        panic!("a directory record longer than 255 bytes in a test ISO");
    }
    out[0] = u8::try_from(out.len()).unwrap_or(u8::MAX);
    out
}

/// Records packed into sectors: a record never crosses one; at least one sector.
fn pack(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut used = 0usize;
    for record in records {
        if used + record.len() > SECTOR {
            out.resize(out.len() + SECTOR - used, 0);
            used = 0;
        }
        out.extend_from_slice(record);
        used += record.len();
    }
    out.resize(sectors_for(out.len()) * SECTOR, 0);
    out
}

fn susp(signature: &[u8; 2], body: &[u8]) -> Vec<u8> {
    let mut out = vec![
        signature[0],
        signature[1],
        u8::try_from(4 + body.len()).unwrap_or(u8::MAX),
        1,
    ];
    out.extend_from_slice(body);
    out
}

/// Rock Ridge's `PX`: mode, links, uid, gid (RRIP 1.10, as xorriso writes it).
fn px(dir: bool) -> Vec<u8> {
    let mode: u32 = if dir { 0o40555 } else { 0o100444 };
    let mut body = Vec::new();
    body.extend_from_slice(&both32(mode));
    body.extend_from_slice(&both32(if dir { 2 } else { 1 }));
    body.extend_from_slice(&both32(0));
    body.extend_from_slice(&both32(0));
    susp(b"PX", &body)
}

fn nm(flags: u8, name: &[u8]) -> Vec<u8> {
    let mut body = vec![flags];
    body.extend_from_slice(name);
    susp(b"NM", &body)
}

fn ce(block: u32, offset: u32, length: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&both32(block));
    body.extend_from_slice(&both32(offset));
    body.extend_from_slice(&both32(length));
    susp(b"CE", &body)
}

/// ISO 9660's plain names: upper case, `_` for what level 1 doesn't allow; files get `.EXT;1`.
fn plain_name(name: &str, dir: bool) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    };
    if dir {
        return clean(name);
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{}.{};1", clean(stem), clean(ext)),
        _ => format!("{}.;1", clean(name)),
    }
}

/// A primary or supplementary volume descriptor.
fn volume_descriptor(kind: u8, label: &str, joliet: bool, total: u32, root: (u32, u32)) -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    d[0] = kind;
    d[1..6].copy_from_slice(b"CD001");
    d[6] = 1;
    let pad = |text: &str, width: usize| -> Vec<u8> {
        let mut out = if joliet { ucs2(text) } else { text.as_bytes().to_vec() };
        out.truncate(width);
        while out.len() < width {
            if joliet && width - out.len() >= 2 {
                out.extend_from_slice(&[0, b' ']);
            } else {
                out.push(b' ');
            }
        }
        out
    };
    d[8..40].copy_from_slice(&pad("", 32));
    d[40..72].copy_from_slice(&pad(label, 32));
    d[80..88].copy_from_slice(&both32(total));
    if joliet {
        d[88..91].copy_from_slice(b"%/E");
    }
    d[120..124].copy_from_slice(&both16(1));
    d[124..128].copy_from_slice(&both16(1));
    d[128..132].copy_from_slice(&both16(2048));
    let root_record = dir_record(&[0], root.0, root.1, true, &[]);
    d[156..156 + root_record.len()].copy_from_slice(&root_record);
    d[881] = 1;
    d
}

fn terminator() -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    d[0] = 255;
    d[1..6].copy_from_slice(b"CD001");
    d[6] = 1;
    d
}

/// A Linux install ISO: Rock Ridge and Joliet trees over the same data.
#[derive(Debug, Clone)]
pub struct LinuxIso {
    pub volume_id: String,
    /// (absolute path, content), folders made as needed.
    pub files: Vec<(String, Vec<u8>)>,
    pub rock_ridge: bool,
    pub joliet: bool,
    /// Joliet file names end in `;1`.
    pub joliet_versions: bool,
    /// This file's Rock Ridge name is split: its first half in the record, the rest in a continuation area.
    pub nm_in_continuation: Option<String>,
    /// This file's Joliet record points at its own copy of the data, not the Rock Ridge record's.
    pub joliet_own_copy: Option<String>,
}

#[derive(Debug, Default)]
struct Folder {
    name: String,
    parent: usize,
    folders: Vec<usize>,
    /// (name, index in `files`)
    files: Vec<(String, usize)>,
    path: String,
}

impl LinuxIso {
    pub fn new(volume_id: &str) -> Self {
        Self {
            volume_id: volume_id.to_owned(),
            files: Vec::new(),
            rock_ridge: true,
            joliet: true,
            joliet_versions: false,
            nm_in_continuation: None,
            joliet_own_copy: None,
        }
    }

    /// Adds `path` with `data`, or replaces what it held.
    pub fn with_file(mut self, path: &str, data: impl Into<Vec<u8>>) -> Self {
        let data = data.into();
        match self.files.iter_mut().find(|(p, _)| p == path) {
            Some(entry) => entry.1 = data,
            None => self.files.push((path.to_owned(), data)),
        }
        self
    }

    pub fn without_file(mut self, path: &str) -> Self {
        self.files.retain(|(p, _)| p != path);
        self
    }

    /// The content of `path`, if the image has it.
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.iter().find(|(p, _)| p == path).map(|(_, d)| d.as_slice())
    }

    fn folders(&self) -> Vec<Folder> {
        let mut folders = vec![Folder {
            path: String::new(),
            ..Folder::default()
        }];
        for (index, (path, _)) in self.files.iter().enumerate() {
            let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
            let Some((name, dirs)) = parts.split_last() else {
                continue;
            };
            let mut at = 0usize;
            for dir in dirs {
                let found = folders[at].folders.iter().copied().find(|&f| folders[f].name == *dir);
                at = match found {
                    Some(f) => f,
                    None => {
                        let path = format!("{}/{dir}", folders[at].path);
                        folders.push(Folder {
                            name: (*dir).to_owned(),
                            parent: at,
                            path,
                            ..Folder::default()
                        });
                        let new = folders.len() - 1;
                        folders[at].folders.push(new);
                        new
                    }
                };
            }
            folders[at].files.push(((*name).to_owned(), index));
        }
        folders
    }

    /// The image.
    pub fn build(&self) -> Vec<u8> {
        let folders = self.folders();
        let count = folders.len();
        let mut layout = Layout {
            primary: vec![(0, 0); count],
            joliet: vec![(0, 0); count],
            files: vec![0; self.files.len()],
            ce_sector: 0,
            joliet_copy: 0,
        };
        // Sizes first (they don't depend on where things are), then places, then the records again.
        let primary_sizes: Vec<usize> = (0..count)
            .map(|f| pack(&self.records(&folders, f, false, &layout)).len())
            .collect();
        let joliet_sizes: Vec<usize> = (0..count)
            .map(|f| pack(&self.records(&folders, f, true, &layout)).len())
            .collect();
        let mut next = 16usize;
        let pvd = next;
        next += 1;
        let svd = next;
        if self.joliet {
            next += 1;
        }
        let term = next;
        next += 1;
        for (f, size) in primary_sizes.iter().enumerate() {
            layout.primary[f] = (to_u32(next), to_u32(*size));
            next += size / SECTOR;
        }
        if self.joliet {
            for (f, size) in joliet_sizes.iter().enumerate() {
                layout.joliet[f] = (to_u32(next), to_u32(*size));
                next += size / SECTOR;
            }
        }
        if self.nm_in_continuation.is_some() {
            layout.ce_sector = to_u32(next);
            next += 1;
        }
        for (i, (_, data)) in self.files.iter().enumerate() {
            layout.files[i] = to_u32(next);
            next += sectors_for(data.len());
        }
        if let Some(copy) = &self.joliet_own_copy {
            layout.joliet_copy = to_u32(next);
            next += sectors_for(self.file(copy).map_or(0, <[u8]>::len));
        }
        let total = next;
        let mut image = vec![0u8; total * SECTOR];
        put(
            &mut image,
            pvd * SECTOR,
            &volume_descriptor(1, &self.volume_id, false, to_u32(total), layout.primary[0]),
        );
        if self.joliet {
            put(
                &mut image,
                svd * SECTOR,
                &volume_descriptor(2, &self.volume_id, true, to_u32(total), layout.joliet[0]),
            );
        }
        put(&mut image, term * SECTOR, &terminator());
        for f in 0..count {
            let primary = pack(&self.records(&folders, f, false, &layout));
            put(&mut image, layout.primary[f].0 as usize * SECTOR, &primary);
            if self.joliet {
                let joliet = pack(&self.records(&folders, f, true, &layout));
                put(&mut image, layout.joliet[f].0 as usize * SECTOR, &joliet);
            }
        }
        if let Some(path) = &self.nm_in_continuation {
            let name = path.rsplit('/').next().unwrap_or(path);
            let rest = &name.as_bytes()[name.len() / 2..];
            let mut area = nm(0, rest);
            area.extend(susp(b"ST", &[]));
            put(&mut image, layout.ce_sector as usize * SECTOR, &area);
        }
        for (i, (_, data)) in self.files.iter().enumerate() {
            put(&mut image, layout.files[i] as usize * SECTOR, data);
        }
        if let Some(copy) = &self.joliet_own_copy {
            if let Some(data) = self.file(copy) {
                let data = data.to_vec();
                put(&mut image, layout.joliet_copy as usize * SECTOR, &data);
            }
        }
        image
    }

    fn records(&self, folders: &[Folder], f: usize, joliet: bool, layout: &Layout) -> Vec<Vec<u8>> {
        let places = if joliet { &layout.joliet } else { &layout.primary };
        let folder = &folders[f];
        let rr = self.rock_ridge && !joliet;
        let mut dot_su = Vec::new();
        if rr {
            if f == 0 {
                dot_su.extend(susp(b"SP", &[0xBE, 0xEF, 0]));
            }
            dot_su.extend(px(true));
        }
        let dotdot_su = if rr { px(true) } else { Vec::new() };
        let own = places[f];
        let parent = places[folder.parent];
        let mut records = vec![
            dir_record(&[0], own.0, own.1, true, &dot_su),
            dir_record(&[1], parent.0, parent.1, true, &dotdot_su),
        ];
        // (sort key, record)
        let mut children: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for &sub in &folder.folders {
            let name = &folders[sub].name;
            let id = if joliet {
                ucs2(name)
            } else {
                plain_name(name, true).into_bytes()
            };
            let su = if rr {
                let mut su = px(true);
                su.extend(nm(0, name.as_bytes()));
                su
            } else {
                Vec::new()
            };
            let place = places[sub];
            children.push((id.clone(), dir_record(&id, place.0, place.1, true, &su)));
        }
        for (name, index) in &folder.files {
            let path = format!("{}/{name}", folder.path);
            let id = if joliet {
                ucs2(&if self.joliet_versions {
                    format!("{name};1")
                } else {
                    name.clone()
                })
            } else {
                plain_name(name, false).into_bytes()
            };
            let su = if rr {
                let mut su = px(false);
                if self.nm_in_continuation.as_deref() == Some(path.as_str()) {
                    let half = name.len() / 2;
                    su.extend(nm(1, &name.as_bytes()[..half]));
                    let rest = name.len() - half;
                    su.extend(ce(layout.ce_sector, 0, to_u32(5 + rest + 4)));
                } else {
                    su.extend(nm(0, name.as_bytes()));
                }
                su
            } else {
                Vec::new()
            };
            let size = to_u32(self.files[*index].1.len());
            let extent = if joliet && self.joliet_own_copy.as_deref() == Some(path.as_str()) {
                layout.joliet_copy
            } else {
                layout.files[*index]
            };
            children.push((id.clone(), dir_record(&id, extent, size, false, &su)));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));
        records.extend(children.into_iter().map(|(_, r)| r));
        records
    }
}

struct Layout {
    primary: Vec<(u32, u32)>,
    joliet: Vec<(u32, u32)>,
    files: Vec<u32>,
    ce_sector: u32,
    joliet_copy: u32,
}

/// 24.04.5's grub.cfg shape: tabs, the HWE entry, memtest on BIOS only.
pub const UBUNTU_24_04_GRUB: &str = "set timeout=30\n\nloadfont unicode\n\nset menu_color_normal=white/black\n\
set menu_color_highlight=black/light-gray\n\nmenuentry \"Try or Install Ubuntu Server\" {\n\tset gfxpayload=keep\n\
\tlinux\t/casper/vmlinuz  ---\n\tinitrd\t/casper/initrd\n}\nmenuentry \"Ubuntu Server with the HWE kernel\" {\n\
\tset gfxpayload=keep\n\tlinux\t/casper/hwe-vmlinuz  ---\n\tinitrd\t/casper/hwe-initrd\n}\ngrub_platform\n\
if [ \"$grub_platform\" = \"efi\" ]; then\nmenuentry 'Boot from next volume' {\n\texit 1\n}\n\
menuentry 'UEFI Firmware Settings' {\n\tfwsetup\n}\nelse\nmenuentry 'Test memory' {\n\
\tlinux16 /boot/memtest86+x64.bin\n}\nfi\n";

/// 26.04.1's grub.cfg shape: four spaces, two after `linux`, a space after `---`, one entry. (Every line break of
/// the literal is inside a line of the file, never before an indent, which a `\` continuation would eat.)
pub const UBUNTU_26_04_GRUB: &str = "set timeout=30\n\nloadfont unicode\n\nset menu_color_normal=white/black\n\
set menu_color_highlight=black/light-gray\n\nmenuentry \"Try or Install Ubuntu Server\" {\n    set gfxpayload=keep\n    \
linux  /casper/vmlinuz  --- \n    initrd /casper/initrd\n}\ngrub_platform\n\
if [ \"$grub_platform\" = \"efi\" ]; then\nmenuentry 'Boot from next volume' {\n    exit 1\n}\n\
menuentry 'UEFI Firmware Settings' {\n    fwsetup\n}\nfi\n";

fn ubuntu(volume_id: &str, release: &str, grub: &str, hwe: bool) -> LinuxIso {
    let info = format!("Ubuntu-Server {release} LTS (test image) - Release amd64");
    let mut iso = LinuxIso::new(volume_id)
        .with_file("/.disk/info", info.clone())
        .with_file("/boot/grub/grub.cfg", grub)
        .with_file("/boot/grub/i386-pc/eltorito.img", vec![0xEB; 4096])
        .with_file("/EFI/boot/bootx64.efi", b"MZ shim stand-in".to_vec())
        .with_file("/casper/vmlinuz", b"kernel stand-in".to_vec())
        .with_file("/casper/initrd", b"initrd stand-in".to_vec());
    if hwe {
        iso = iso
            .with_file("/casper/hwe-vmlinuz", b"hwe kernel stand-in".to_vec())
            .with_file("/casper/hwe-initrd", b"hwe initrd stand-in".to_vec());
    }
    let md5sum = md5sum_txt(&[
        ("./.disk/info", info.as_bytes()),
        ("./boot/grub/grub.cfg", grub.as_bytes()),
        ("./casper/vmlinuz", b"kernel stand-in"),
    ]);
    iso.with_file("/md5sum.txt", md5sum)
}

/// An Ubuntu Server 24.04-like ISO's builder.
pub fn ubuntu_24_04_iso() -> LinuxIso {
    ubuntu("Ubuntu-Server 24.04 LTS amd64", "24.04", UBUNTU_24_04_GRUB, true)
}

/// An Ubuntu Server 26.04-like ISO's builder.
pub fn ubuntu_26_04_iso() -> LinuxIso {
    ubuntu("Ubuntu-Server 26.04 LTS amd64", "26.04", UBUNTU_26_04_GRUB, false)
}

pub fn ubuntu_24_04() -> Vec<u8> {
    ubuntu_24_04_iso().build()
}

pub fn ubuntu_26_04() -> Vec<u8> {
    ubuntu_26_04_iso().build()
}

/// D-I's isolinux.cfg shape: no wait, a menu.
pub const DEBIAN_ISOLINUX: &str = "# D-I config version 2.0\n# search path for the c32 support libraries\npath \n\
prompt 0\ntimeout 0\ninclude menu.cfg\ndefault vesamenu.c32\n";

/// D-I's grub.cfg shape, over two sectors long (three sectors, as on the ISOs seen).
pub fn debian_grub() -> String {
    let mut text = String::from(
        "if loadfont $prefix/font.pf2 ; then\n  set gfxmode=800x600\n  insmod gfxterm\n  terminal_output gfxterm\nfi\n\n",
    );
    let entries = [
        ("Graphical install", "vga=788 --- quiet", "/install.amd/gtk/initrd.gz"),
        ("Install", "vga=788 --- quiet", "/install.amd/initrd.gz"),
        (
            "... Expert install",
            "priority=low vga=788 ---",
            "/install.amd/initrd.gz",
        ),
        (
            "... Rescue mode",
            "vga=788 rescue/enable=true --- quiet",
            "/install.amd/initrd.gz",
        ),
        (
            "... Automated install",
            "auto=true priority=critical vga=788 --- quiet",
            "/install.amd/initrd.gz",
        ),
    ];
    let mut round = 0;
    while text.len() <= 2 * SECTOR + 100 {
        for (label, words, initrd) in entries {
            text.push_str(&format!(
                "menuentry '{label} ({round})' {{\n    set background_color=black\n    linux    /install.amd/vmlinuz \
                 {words} \n    initrd   {initrd}\n}}\n"
            ));
        }
        round += 1;
    }
    text
}

/// A Debian-like ISO's builder (netinst-sized structure).
pub fn debian_iso() -> LinuxIso {
    let grub = debian_grub();
    let info = "Debian GNU/Linux 13 \"Trixie\" - test amd64 NETINST";
    let x86_64 = "source /boot/grub/grub.cfg\n";
    let initrd = b"initrd stand-in".to_vec();
    let md5sum = md5sum_txt(&[
        ("./.disk/info", info.as_bytes()),
        ("./boot/grub/grub.cfg", grub.as_bytes()),
        ("./boot/grub/x86_64-efi/grub.cfg", x86_64.as_bytes()),
        ("./install.amd/initrd.gz", &initrd),
    ]);
    LinuxIso::new("Debian 13 amd64 n")
        .with_file("/.disk/info", info)
        .with_file("/boot/grub/grub.cfg", grub)
        .with_file("/boot/grub/x86_64-efi/grub.cfg", x86_64)
        .with_file("/install.amd/vmlinuz", b"kernel stand-in".to_vec())
        .with_file("/install.amd/initrd.gz", initrd)
        .with_file("/install.amd/gtk/initrd.gz", b"gtk initrd stand-in".to_vec())
        .with_file("/isolinux/isolinux.cfg", DEBIAN_ISOLINUX)
        .with_file("/isolinux/menu.cfg", "include gtk.cfg\ninclude txt.cfg\n")
        .with_file(
            "/isolinux/txt.cfg",
            "label install\n\tmenu label ^Install\n\tkernel /install.amd/vmlinuz\n\tappend vga=788 \
             initrd=/install.amd/initrd.gz --- quiet \n",
        )
        .with_file("/md5sum.txt", md5sum)
}

pub fn debian() -> Vec<u8> {
    debian_iso().build()
}

/// A 1.44 MB FAT12 floppy image of `bytes` bytes (normally [`EFI_IMAGE_BYTES`]) whose boot sector carries
/// `label`, so a test can tell the images apart.
pub fn floppy_image(label: &str, bytes: usize) -> Vec<u8> {
    let mut image = vec![0u8; bytes.max(512)];
    image[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    image[3..11].copy_from_slice(b"MSDOS5.0");
    image[11..13].copy_from_slice(&512u16.to_le_bytes());
    image[13] = 1;
    image[14..16].copy_from_slice(&1u16.to_le_bytes());
    image[16] = 2;
    image[17..19].copy_from_slice(&224u16.to_le_bytes());
    image[19..21].copy_from_slice(&2880u16.to_le_bytes());
    image[21] = 0xF0;
    image[22..24].copy_from_slice(&9u16.to_le_bytes());
    image[38] = 0x29;
    let mut padded = label.as_bytes().to_vec();
    padded.resize(11, b' ');
    image[43..54].copy_from_slice(&padded[..11]);
    image[54..62].copy_from_slice(b"FAT12   ");
    image[510] = 0x55;
    image[511] = 0xAA;
    image.truncate(bytes);
    image
}

/// A Windows Server-like ISO.
#[derive(Debug, Clone)]
pub struct WindowsIso {
    pub volume_id: String,
    /// The boot catalog has its final 0xEF section.
    pub efi_entry: bool,
    /// `efi/microsoft/boot/efisys_noprompt.bin` is in the UDF tree.
    pub noprompt: bool,
    /// Its size.
    pub noprompt_bytes: usize,
    /// `sources/install.wim` is in the UDF tree.
    pub install_wim: bool,
}

impl Default for WindowsIso {
    fn default() -> Self {
        Self {
            volume_id: "SSS_X64FREE_EN-US_DV9".to_owned(),
            efi_entry: true,
            noprompt: true,
            noprompt_bytes: EFI_IMAGE_BYTES,
            install_wim: true,
        }
    }
}

pub fn windows_server() -> Vec<u8> {
    WindowsIso::default().build()
}

enum UdfKind {
    Folder(Vec<usize>),
    File(Vec<u8>),
    Embedded(Vec<u8>),
}

struct UdfNode {
    name: String,
    kind: UdfKind,
    parent: usize,
    /// An Extended File Entry with long allocation descriptors.
    extended: bool,
    /// Its children's names are 16-bit compressed Unicode.
    wide_names: bool,
    entry: u32,
    data: u32,
}

impl UdfNode {
    fn new(name: &str, kind: UdfKind, parent: usize) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            parent,
            extended: false,
            wide_names: false,
            entry: 0,
            data: 0,
        }
    }
}

/// A UDF descriptor tag at the start of `d`: version 2, no CRC, the checksum last.
fn udf_tag(d: &mut [u8], id: u16, location: u32) {
    d[0..2].copy_from_slice(&id.to_le_bytes());
    d[2..4].copy_from_slice(&2u16.to_le_bytes());
    d[4] = 0;
    d[12..16].copy_from_slice(&location.to_le_bytes());
    d[4] = (0..16).filter(|&i| i != 4).fold(0u8, |sum, i| sum.wrapping_add(d[i]));
}

fn cs0(name: &str, wide: bool) -> Vec<u8> {
    if wide {
        let mut out = vec![16];
        out.extend(ucs2(name));
        out
    } else {
        let mut out = vec![8];
        out.extend(name.bytes());
        out
    }
}

impl WindowsIso {
    fn udf_tree(&self) -> Vec<UdfNode> {
        fn add(nodes: &mut Vec<UdfNode>, parent: usize, node: UdfNode) -> usize {
            nodes.push(node);
            let index = nodes.len() - 1;
            if let UdfKind::Folder(children) = &mut nodes[parent].kind {
                children.push(index);
            }
            index
        }
        let mut nodes: Vec<UdfNode> = Vec::new();
        let mut root = UdfNode::new("", UdfKind::Folder(Vec::new()), 0);
        root.wide_names = true;
        nodes.push(root);
        let boot = add(&mut nodes, 0, UdfNode::new("boot", UdfKind::Folder(Vec::new()), 0));
        add(
            &mut nodes,
            boot,
            UdfNode::new("etfsboot.com", UdfKind::File(vec![0xFA; 4096]), boot),
        );
        let mut efi_node = UdfNode::new("efi", UdfKind::Folder(Vec::new()), 0);
        efi_node.extended = true;
        let efi = add(&mut nodes, 0, efi_node);
        let microsoft = add(
            &mut nodes,
            efi,
            UdfNode::new("microsoft", UdfKind::Folder(Vec::new()), efi),
        );
        let efi_boot = add(
            &mut nodes,
            microsoft,
            UdfNode::new("boot", UdfKind::Folder(Vec::new()), microsoft),
        );
        add(
            &mut nodes,
            efi_boot,
            UdfNode::new("cdboot.efi", UdfKind::File(b"MZ cdboot".to_vec()), efi_boot),
        );
        add(
            &mut nodes,
            efi_boot,
            UdfNode::new(
                "cdboot_noprompt.efi",
                UdfKind::File(b"MZ cdboot noprompt".to_vec()),
                efi_boot,
            ),
        );
        add(
            &mut nodes,
            efi_boot,
            UdfNode::new(
                "efisys.bin",
                UdfKind::File(floppy_image("EFISYS", EFI_IMAGE_BYTES)),
                efi_boot,
            ),
        );
        if self.noprompt {
            add(
                &mut nodes,
                efi_boot,
                UdfNode::new(
                    "efisys_noprompt.bin",
                    UdfKind::File(floppy_image("NOPROMPT", self.noprompt_bytes)),
                    efi_boot,
                ),
            );
        }
        add(
            &mut nodes,
            0,
            UdfNode::new("setup.exe", UdfKind::File(b"MZ setup".to_vec()), 0),
        );
        let sources = add(&mut nodes, 0, UdfNode::new("sources", UdfKind::Folder(Vec::new()), 0));
        if self.install_wim {
            let mut wim = b"MSWIM\0\0\0".to_vec();
            wim.resize(8192, 0);
            add(
                &mut nodes,
                sources,
                UdfNode::new("install.wim", UdfKind::File(wim), sources),
            );
        }
        add(
            &mut nodes,
            sources,
            UdfNode::new(
                "ei.cfg",
                UdfKind::Embedded(b"[Channel]\r\nRetail\r\n".to_vec()),
                sources,
            ),
        );
        nodes
    }

    fn folder_data(nodes: &[UdfNode], index: usize) -> Vec<u8> {
        let UdfKind::Folder(children) = &nodes[index].kind else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let parent_entry = nodes[nodes[index].parent].entry;
        out.extend(fid(0x0A, &[], parent_entry, nodes[index].data, 0));
        for &child in children {
            let node = &nodes[child];
            let characteristics = if matches!(node.kind, UdfKind::Folder(_)) {
                0x02
            } else {
                0
            };
            let name = cs0(&node.name, nodes[index].wide_names);
            let at = out.len();
            out.extend(fid(characteristics, &name, node.entry, nodes[index].data, at));
        }
        out
    }

    /// The image.
    pub fn build(&self) -> Vec<u8> {
        let mut nodes = self.udf_tree();
        // Places: the file set descriptor at block 0, its terminator at 1, then each entry and its data.
        let mut next = 2u32;
        for node in nodes.iter_mut() {
            node.entry = next;
            next += 1;
        }
        let sizes: Vec<usize> = (0..nodes.len())
            .map(|i| match &nodes[i].kind {
                UdfKind::Folder(_) => Self::folder_data(&nodes, i).len(),
                UdfKind::File(data) => data.len(),
                UdfKind::Embedded(_) => 0,
            })
            .collect();
        for (i, node) in nodes.iter_mut().enumerate() {
            if !matches!(node.kind, UdfKind::Embedded(_)) {
                node.data = next;
                next += to_u32(sectors_for(sizes[i]));
            }
        }
        let etfsboot_copy = next;
        next += 2;
        let efisys_copy = next;
        next += to_u32(EFI_IMAGE_BYTES / SECTOR);
        let partition_length = next;
        let total = UDF_PARTITION_START + partition_length as usize;
        let mut image = vec![0u8; total * SECTOR];

        // ISO 9660: README.TXT alone.
        let readme = b"This disc holds a test image, not Windows.\r\n";
        put(
            &mut image,
            16 * SECTOR,
            &volume_descriptor(1, &self.volume_id, false, to_u32(total), (24, 2048)),
        );
        let mut boot_record = vec![0u8; SECTOR];
        boot_record[1..6].copy_from_slice(b"CD001");
        boot_record[6] = 1;
        boot_record[7..30].copy_from_slice(b"EL TORITO SPECIFICATION");
        boot_record[71..75].copy_from_slice(&to_u32(BOOT_CATALOG_SECTOR).to_le_bytes());
        put(&mut image, 17 * SECTOR, &boot_record);
        put(&mut image, 18 * SECTOR, &terminator());
        for (n, id) in [(19, b"BEA01"), (20, b"NSR02"), (21, b"TEA01")] {
            let mut d = vec![0u8; 8];
            d[1..6].copy_from_slice(id);
            d[6] = 1;
            put(&mut image, n * SECTOR, &d);
        }
        let root = pack(&[
            dir_record(&[0], 24, 2048, true, &[]),
            dir_record(&[1], 24, 2048, true, &[]),
            dir_record(b"README.TXT", 25, to_u32(readme.len()), false, &[]),
        ]);
        put(&mut image, 24 * SECTOR, &root);
        put(&mut image, 25 * SECTOR, readme);

        // El Torito's catalog: validation entry, BIOS default entry, then the UEFI section.
        let mut catalog = vec![0u8; SECTOR];
        catalog[0] = 1;
        catalog[4..25].copy_from_slice(b"Microsoft Corporation");
        catalog[30] = 0x55;
        catalog[31] = 0xAA;
        let sum = (0..16).fold(0u16, |sum, i| {
            sum.wrapping_add(u16::from_le_bytes([catalog[2 * i], catalog[2 * i + 1]]))
        });
        catalog[28..30].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
        catalog[32] = 0x88;
        catalog[38..40].copy_from_slice(&8u16.to_le_bytes());
        let absolute = |block: u32| to_u32(UDF_PARTITION_START) + block;
        catalog[40..44].copy_from_slice(&absolute(etfsboot_copy).to_le_bytes());
        if self.efi_entry {
            catalog[64] = 0x91;
            catalog[65] = 0xEF;
            catalog[66..68].copy_from_slice(&1u16.to_le_bytes());
            catalog[96] = 0x88;
            catalog[102..104].copy_from_slice(&1u16.to_le_bytes());
            catalog[104..108].copy_from_slice(&absolute(efisys_copy).to_le_bytes());
        }
        put(&mut image, BOOT_CATALOG_SECTOR * SECTOR, &catalog);

        // UDF: anchor, volume descriptors, file set, entries and data.
        let mut anchor = vec![0u8; 512];
        anchor[16..20].copy_from_slice(&to_u32(16 * SECTOR).to_le_bytes());
        anchor[20..24].copy_from_slice(&257u32.to_le_bytes());
        anchor[24..28].copy_from_slice(&to_u32(16 * SECTOR).to_le_bytes());
        anchor[28..32].copy_from_slice(&257u32.to_le_bytes());
        udf_tag(&mut anchor, 2, 256);
        put(&mut image, 256 * SECTOR, &anchor);
        let mut descriptors: Vec<(u16, Vec<u8>)> = Vec::new();
        descriptors.push((1, vec![0u8; 512]));
        let mut logical = vec![0u8; 512];
        logical[212..216].copy_from_slice(&2048u32.to_le_bytes());
        logical[217..236].copy_from_slice(b"*OSTA UDF Compliant");
        logical[248..252].copy_from_slice(&2048u32.to_le_bytes());
        logical[264..268].copy_from_slice(&6u32.to_le_bytes());
        logical[268..272].copy_from_slice(&1u32.to_le_bytes());
        logical[440..446].copy_from_slice(&[1, 6, 1, 0, 0xAD, 0x0B]);
        descriptors.push((6, logical));
        let mut partition = vec![0u8; 512];
        partition[20..22].copy_from_slice(&1u16.to_le_bytes());
        partition[22..24].copy_from_slice(&2989u16.to_le_bytes());
        partition[25..31].copy_from_slice(b"+NSR02");
        partition[184..188].copy_from_slice(&1u32.to_le_bytes());
        partition[188..192].copy_from_slice(&to_u32(UDF_PARTITION_START).to_le_bytes());
        partition[192..196].copy_from_slice(&partition_length.to_le_bytes());
        descriptors.push((5, partition));
        descriptors.push((7, vec![0u8; 512]));
        descriptors.push((4, vec![0u8; 512]));
        descriptors.push((8, vec![0u8; 512]));
        for (i, (id, mut d)) in descriptors.into_iter().enumerate() {
            let sector = 257 + to_u32(i);
            udf_tag(&mut d, id, sector);
            put(&mut image, sector as usize * SECTOR, &d);
        }
        let block = |b: u32| (UDF_PARTITION_START + b as usize) * SECTOR;
        let mut file_set = vec![0u8; 512];
        file_set[400..404].copy_from_slice(&2048u32.to_le_bytes());
        file_set[404..408].copy_from_slice(&nodes[0].entry.to_le_bytes());
        udf_tag(&mut file_set, 256, 0);
        put(&mut image, block(0), &file_set);
        let mut file_set_end = vec![0u8; 512];
        udf_tag(&mut file_set_end, 8, 1);
        put(&mut image, block(1), &file_set_end);
        for i in 0..nodes.len() {
            let node = &nodes[i];
            let (data, is_dir) = match &node.kind {
                UdfKind::Folder(_) => (Self::folder_data(&nodes, i), true),
                UdfKind::File(data) | UdfKind::Embedded(data) => (data.clone(), false),
            };
            let embedded = matches!(node.kind, UdfKind::Embedded(_));
            let entry = file_entry(node, &data, is_dir, embedded);
            put(&mut image, block(node.entry), &entry);
            if !embedded {
                put(&mut image, block(node.data), &data);
            }
        }
        put(&mut image, block(etfsboot_copy), &[0xFA; 4096]);
        put(&mut image, block(efisys_copy), &floppy_image("EFISYS", EFI_IMAGE_BYTES));
        image
    }
}

/// A File Identifier Descriptor at byte `at` of a folder whose data starts at block `folder_block`.
fn fid(characteristics: u8, name: &[u8], entry: u32, folder_block: u32, at: usize) -> Vec<u8> {
    let len = (38 + name.len()).div_ceil(4) * 4;
    let mut d = vec![0u8; len];
    d[16..18].copy_from_slice(&1u16.to_le_bytes());
    d[18] = characteristics;
    d[19] = u8::try_from(name.len()).unwrap_or(u8::MAX);
    d[20..24].copy_from_slice(&2048u32.to_le_bytes());
    d[24..28].copy_from_slice(&entry.to_le_bytes());
    d[38..38 + name.len()].copy_from_slice(name);
    udf_tag(&mut d, 257, folder_block + to_u32(at / SECTOR));
    d
}

/// A File Entry (or, for `node.extended`, an Extended File Entry with long allocation descriptors).
fn file_entry(node: &UdfNode, data: &[u8], is_dir: bool, embedded: bool) -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    d[20..22].copy_from_slice(&4u16.to_le_bytes());
    d[24..26].copy_from_slice(&1u16.to_le_bytes());
    d[27] = if is_dir { 4 } else { 5 };
    let ad_type: u16 = if embedded {
        3
    } else if node.extended {
        1
    } else {
        0
    };
    d[34..36].copy_from_slice(&ad_type.to_le_bytes());
    d[48..50].copy_from_slice(&1u16.to_le_bytes());
    d[56..64].copy_from_slice(&(data.len() as u64).to_le_bytes());
    let ads: Vec<u8> = if embedded {
        data.to_vec()
    } else if node.extended {
        let mut ad = vec![0u8; 16];
        ad[0..4].copy_from_slice(&to_u32(data.len()).to_le_bytes());
        ad[4..8].copy_from_slice(&node.data.to_le_bytes());
        ad
    } else {
        let mut ad = vec![0u8; 8];
        ad[0..4].copy_from_slice(&to_u32(data.len()).to_le_bytes());
        ad[4..8].copy_from_slice(&node.data.to_le_bytes());
        ad
    };
    let (id, lengths, base) = if node.extended {
        (266u16, 208, 216)
    } else {
        (261u16, 168, 176)
    };
    d[lengths + 4..lengths + 8].copy_from_slice(&to_u32(ads.len()).to_le_bytes());
    d[base..base + ads.len()].copy_from_slice(&ads);
    udf_tag(&mut d, id, node.entry);
    d
}
