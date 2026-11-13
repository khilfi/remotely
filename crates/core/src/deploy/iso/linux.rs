//! What the Ubuntu (S1) and Debian (S2) copies share. Both ISOs have Rock Ridge names and a Joliet tree, and a
//! menu file is changed the same way: found in both trees, whose records must point at the same data; the new
//! text written over the file's own sectors, the rest of them zeroed; the new size in both records (bytes 10..18,
//! both byte orders); its line in `/md5sum.txt` given the new MD5 in place. `/.disk/info` names the release.
//! Before that, [`LinuxIso::check_alone`] makes sure no other file, folder or structure uses those sectors.

use std::io::{Read, Seek};

use super::eltorito::Catalog;
use super::iso9660::{overlap, read_record, Record, Volume};
use super::md5::md5_hex;
use super::{printable, unexpected, Flavor, Image, IsoWrite, Tree, SECTOR};
use crate::error::Result;
use crate::untrusted::size_words;

/// The largest `md5sum.txt` read (Debian's DVD-1 has about 600 KB).
const MAX_MD5SUM_BYTES: u64 = 8 * 1024 * 1024;
const MAX_INFO_BYTES: u64 = 1024;

/// A Linux install ISO's volume, checked to have Rock Ridge names and a Joliet tree.
pub(crate) struct LinuxIso {
    pub volume: Volume,
    flavor: Flavor,
}

/// A text file found in both trees.
pub(crate) struct TextFile {
    pub path: &'static str,
    rock_ridge: Record,
    joliet: Record,
    pub content: Vec<u8>,
}

/// What `md5sum.txt` got.
pub(crate) struct Md5Update {
    /// `md5sum.txt` is on the ISO.
    pub present: bool,
    pub writes: Vec<IsoWrite>,
    /// Lines updated, one count per changed file asked about.
    pub lines: Vec<usize>,
}

/// `md5sum.txt`'s lines for the files a copy changes, found before their new content is known.
pub(crate) struct Md5Lines {
    /// Its sectors and records, when it lists any of the files (so it will be edited).
    pub rewritten: Option<Rewritten>,
    present: bool,
    /// Per file asked about: each line's digest, its offset in the image and the bytes it has there.
    found: Vec<Vec<(u64, Vec<u8>)>>,
}

impl Md5Lines {
    /// The edits that give each line its file's new digest (`contents` in the order the files were asked about),
    /// in the letter case the line had.
    pub fn update(&self, contents: &[&[u8]]) -> Md5Update {
        let mut writes = Vec::new();
        for (lines, content) in self.found.iter().zip(contents) {
            let digest = md5_hex(content);
            for (offset, old) in lines {
                let new = if old.iter().any(u8::is_ascii_uppercase) {
                    digest.to_ascii_uppercase()
                } else {
                    digest.clone()
                };
                writes.push(IsoWrite {
                    offset: *offset,
                    bytes: new.into_bytes(),
                    replaces: old.clone(),
                });
            }
        }
        Md5Update {
            present: self.present,
            writes,
            lines: self.found.iter().map(Vec::len).collect(),
        }
    }
}

/// A file whose bytes the copy changes: its sectors `[start, end)` and the offsets of its own directory records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rewritten {
    pub path: &'static str,
    pub sectors: (u64, u64),
    pub own: Vec<u64>,
}

impl LinuxIso {
    pub fn open<R: Read + Seek>(image: &mut Image<R>, flavor: Flavor) -> Result<LinuxIso> {
        let volume = Volume::read(image)?;
        if !volume.rock_ridge {
            return Err(unexpected(flavor, "it has no Rock Ridge names"));
        }
        if volume.joliet_root.is_none() {
            return Err(unexpected(flavor, "it has no Joliet tree"));
        }
        Ok(LinuxIso { volume, flavor })
    }

    /// Refuses when anything else uses a sector of `files`, whose bytes the copy changes (a menu file written over
    /// whole, `md5sum.txt` edited in place): another record in either tree (a file or folder anywhere, such as an
    /// identical file mkisofs or xorriso stored once), a Rock Ridge continuation area (names and attributes of
    /// other records), the system area, the volume descriptors, a path table, a root folder, El Torito's boot
    /// catalog or a boot image it names. The whole of both trees is walked (bounded:
    /// [`super::iso9660::MAX_WALK_FOLDERS`]).
    pub fn check_alone<R: Read + Seek>(&self, image: &mut Image<R>, files: &[Rewritten]) -> Result<()> {
        let flavor = self.flavor;
        let shared = |file: &Rewritten, what: &str| {
            unexpected(
                flavor,
                format!(
                    "{} shares its sectors with {what}, so changing it would change that too",
                    file.path
                ),
            )
        };
        let mut others: Vec<((u64, u64), String)> = self
            .volume
            .reserved
            .iter()
            .map(|r| ((r.start, r.end), r.what.to_owned()))
            .collect();
        if let Some(sector) = self.volume.boot_catalog {
            let catalog = Catalog::read(image, sector)?;
            others.push((
                (u64::from(sector), u64::from(sector) + 1),
                "El Torito's boot catalog".to_owned(),
            ));
            for entry in std::iter::once(&catalog.default).chain(&catalog.sections) {
                // Virtual 512-byte sectors; at least the one sector the firmware reads.
                let sectors = (u64::from(entry.sector_count) * 512).div_ceil(SECTOR).max(1);
                let start = u64::from(entry.load_rba);
                others.push(((start, start + sectors), "an El Torito boot image".to_owned()));
            }
        }
        for file in files {
            if let Some((_, what)) = others.iter().find(|(range, _)| overlap(file.sectors, *range)) {
                return Err(shared(file, what));
            }
        }
        for tree in [Tree::RockRidge, Tree::Joliet] {
            let areas = self.volume.walk(image, tree, |record| {
                for file in files {
                    if !file.own.contains(&record.offset) && overlap(file.sectors, record.sectors()) {
                        let name = printable(record.name.as_bytes(), 60);
                        let kind = if record.is_dir() { "the folder" } else { "the file" };
                        return Err(shared(file, &format!("{kind} {name}")));
                    }
                }
                Ok(())
            })?;
            for (start, end) in areas {
                let sectors = (start / SECTOR, end.div_ceil(SECTOR));
                if let Some(file) = files.iter().find(|f| overlap(f.sectors, sectors)) {
                    return Err(shared(file, "a Rock Ridge continuation area"));
                }
            }
        }
        Ok(())
    }

    /// A non-empty plain file at `path`, by its Rock Ridge name.
    pub fn require_file<R: Read + Seek>(&self, image: &mut Image<R>, path: &str) -> Result<Record> {
        let record = self
            .volume
            .lookup(image, path, Tree::RockRidge)?
            .filter(|r| r.by_rock_ridge)
            .ok_or_else(|| unexpected(self.flavor, format!("{path} isn't on it")))?;
        if let Some(problem) = record.plain_file_problem() {
            return Err(unexpected(self.flavor, format!("{path} {problem}")));
        }
        if record.size == 0 {
            return Err(unexpected(self.flavor, format!("{path} is empty")));
        }
        Ok(record)
    }

    /// The text file at `path`, read when it is at most `cap` bytes, after checking its Rock Ridge and Joliet
    /// records point at the same data.
    pub fn text_file<R: Read + Seek>(&self, image: &mut Image<R>, path: &'static str, cap: u64) -> Result<TextFile> {
        let rock_ridge = self.require_file(image, path)?;
        let joliet = self
            .volume
            .lookup(image, path, Tree::Joliet)?
            .ok_or_else(|| unexpected(self.flavor, format!("{path} isn't in its Joliet tree")))?;
        if let Some(problem) = joliet.plain_file_problem() {
            return Err(unexpected(self.flavor, format!("{path} in its Joliet tree {problem}")));
        }
        if joliet.extent != rock_ridge.extent || joliet.size != rock_ridge.size {
            return Err(unexpected(
                self.flavor,
                format!("its Rock Ridge and Joliet records of {path} point at different data"),
            ));
        }
        if u64::from(rock_ridge.size) > cap {
            return Err(unexpected(
                self.flavor,
                format!("{path} is larger than the {} such a file has", size_words(cap)),
            ));
        }
        let content = read_record(image, &rock_ridge, cap)?;
        Ok(TextFile {
            path,
            rock_ridge,
            joliet,
            content,
        })
    }

    /// The release `/.disk/info` names, printable, or `None`.
    pub fn release<R: Read + Seek>(&self, image: &mut Image<R>) -> Result<Option<String>> {
        let Some(record) = self.volume.lookup(image, "/.disk/info", Tree::RockRidge)? else {
            return Ok(None);
        };
        if record.plain_file_problem().is_some() || u64::from(record.size) > MAX_INFO_BYTES {
            return Ok(None);
        }
        let text = printable(&read_record(image, &record, MAX_INFO_BYTES)?, 160);
        Ok((!text.is_empty()).then_some(text))
    }

    /// `md5sum.txt`'s `<32 hex digits>  ./path` lines for `paths` (each `./path` as md5sum.txt lists it), to be
    /// given new digests by [`Md5Lines::update`] once the new contents are known.
    pub fn md5_lines<R: Read + Seek>(&self, image: &mut Image<R>, paths: &[&str]) -> Result<Md5Lines> {
        let Some(record) = self.volume.lookup(image, "/md5sum.txt", Tree::RockRidge)? else {
            return Ok(Md5Lines {
                rewritten: None,
                present: false,
                found: vec![Vec::new(); paths.len()],
            });
        };
        if let Some(problem) = record.plain_file_problem() {
            return Err(unexpected(self.flavor, format!("/md5sum.txt {problem}")));
        }
        if u64::from(record.size) > MAX_MD5SUM_BYTES {
            return Err(unexpected(
                self.flavor,
                format!("/md5sum.txt is larger than {}", size_words(MAX_MD5SUM_BYTES)),
            ));
        }
        let text = read_record(image, &record, MAX_MD5SUM_BYTES)?;
        let base = record.data_offset();
        let mut found = Vec::new();
        for path in paths {
            let mut lines = Vec::new();
            let mut start = 0usize;
            while start < text.len() {
                let end = text[start..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(text.len(), |p| start + p);
                let line = text[start..end].strip_suffix(b"\r").unwrap_or(&text[start..end]);
                if is_line_for(line, path) {
                    lines.push((base + start as u64, line[..32].to_vec()));
                }
                start = end + 1;
            }
            found.push(lines);
        }
        let rewritten = if found.iter().all(Vec::is_empty) {
            None
        } else {
            // Its Joliet record is its own when it names the same data.
            let joliet = self
                .volume
                .lookup(image, "/md5sum.txt", Tree::Joliet)?
                .filter(|j| j.extent == record.extent);
            Some(Rewritten {
                path: "/md5sum.txt",
                sectors: record.sectors(),
                own: std::iter::once(record.offset).chain(joliet.map(|j| j.offset)).collect(),
            })
        };
        Ok(Md5Lines {
            rewritten,
            present: true,
            found,
        })
    }
}

/// `<32 hex digits>  <path>`, as md5sum writes it.
fn is_line_for(line: &[u8], path: &str) -> bool {
    line.len() == 34 + path.len()
        && line[..32].iter().all(u8::is_ascii_hexdigit)
        && &line[32..34] == b"  "
        && &line[34..] == path.as_bytes()
}

impl TextFile {
    /// The changes that make this file `new`: its sectors (the rest zeroed) and both records' sizes. Refused when
    /// `new` doesn't fit the sectors the file has.
    pub fn rewrite<R: Read + Seek>(&self, image: &mut Image<R>, new: &[u8], flavor: Flavor) -> Result<Vec<IsoWrite>> {
        let room = u64::from(self.rock_ridge.size).div_ceil(SECTOR) * SECTOR;
        if new.len() as u64 > room {
            return Err(unexpected(
                flavor,
                format!(
                    "the new {} ({} bytes) doesn't fit the {room} bytes of the sectors the file has",
                    self.path,
                    new.len()
                ),
            ));
        }
        let size = u32::try_from(new.len()).unwrap_or(u32::MAX);
        let start = self.rock_ridge.data_offset();
        let replaces = image.read_at(start, room, "a file's sectors")?;
        let mut bytes = new.to_vec();
        bytes.resize(replaces.len(), 0);
        Ok(vec![
            IsoWrite {
                offset: start,
                bytes,
                replaces,
            },
            self.rock_ridge.size_write(size),
            self.joliet.size_write(size),
        ])
    }

    /// Its sectors and its two records, for [`LinuxIso::check_alone`].
    pub fn rewritten(&self) -> Rewritten {
        Rewritten {
            path: self.path,
            sectors: self.rock_ridge.sectors(),
            own: vec![self.rock_ridge.offset, self.joliet.offset],
        }
    }

    /// The file's name alone (`grub.cfg`).
    pub fn name(&self) -> &'static str {
        self.path.rsplit('/').next().unwrap_or(self.path)
    }
}

/// The summary line for `md5sum.txt` and a changed file.
pub(crate) fn md5_words(update: &Md5Update, index: usize, name: &str) -> String {
    match update.lines.get(index).copied().unwrap_or(0) {
        _ if !update.present => "md5sum.txt isn't on the ISO, so no checksum needed updating.".to_owned(),
        0 => format!(
            "md5sum.txt has no line for {name}, so it was left as it is (the installer's media check only reports a \
             mismatch)."
        ),
        _ => format!("md5sum.txt: {name}'s checksum updated, so the installer's media check passes."),
    }
}
