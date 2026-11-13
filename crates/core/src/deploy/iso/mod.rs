//! VM-29 (0.8.0 G6): the copy of an install ISO an unattended install boots from, its boot menu changed so the
//! installer starts by itself and finds the seed (CLAUDE.md "Unattended installs", S1 to S3: only what those
//! spikes saw working is built here).
//!
//! The original ISO is untrusted input and is never opened for writing. [`plan`] reads a few sectors and small
//! files of it (every offset and length checked against the image and capped, loops bounded) and returns the
//! bytes a copy needs changed, each with the bytes it replaces; it refuses an ISO whose layout isn't what the
//! spikes saw, naming what didn't match, and never guesses. [`make_copy`] copies the ISO (never over a file that
//! is there), changes those bytes on the way, checks the source still held what the plan read, and reads the
//! changes back; a failure or a cancel deletes the partial copy.
//!
//! * [`Flavor::Ubuntu`] (S1): `/boot/grub/grub.cfg`, which BIOS, UEFI and Secure Boot all read, gets
//!   `autoinstall` and the serial console on each casper `linux` line and a 1 s menu ([`ubuntu::patch_grub`]),
//!   written over its own sectors; its new size goes into its Rock Ridge and Joliet directory records, its MD5
//!   into `/md5sum.txt`.
//! * [`Flavor::Debian`] (S2, "a2"): `/isolinux/isolinux.cfg` (BIOS) and `/boot/grub/grub.cfg` (UEFI) replaced by
//!   a one-entry menu whose `preseed/early_command` finds the seed CD, copies `preseed.cfg` to `/tmp` and drops
//!   the drive ([`debian::isolinux_cfg`], [`debian::grub_cfg`]). The copy holds nothing of a VM.
//! * [`Flavor::WindowsServer`] (S3): El Torito's UEFI entry pointed at `efisys_noprompt.bin`, found through UDF,
//!   so Setup starts without "Press any key"; BIOS needs nothing.
//!
//! Readers: [`iso9660`] (volume descriptors, directory records, Rock Ridge names, Joliet), [`udf`], [`eltorito`];
//! [`md5`] for `md5sum.txt`. [`read_file`] reads a file back through any of the three trees.

pub mod debian;
pub mod eltorito;
pub mod iso9660;
mod linux;
pub mod md5;
pub mod ubuntu;
pub mod udf;
pub mod windows;

use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{CoreError, Result};
use crate::untrusted;

/// An ISO's logical block, the only size Remotely reads.
pub const SECTOR: u64 = 2048;
/// The most [`read_file`] reads of one file.
pub const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;
/// The most one read of the image takes (a directory, `md5sum.txt`, a file read back).
const MAX_SINGLE_READ: u64 = MAX_READ_BYTES;
/// How much [`make_copy`] copies at a time between progress calls and cancel checks.
const COPY_CHUNK: usize = 4 * 1024 * 1024;

/// Which installer an ISO holds, so which change its copy gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flavor {
    /// Ubuntu Server's live installer (subiquity), 24.04 and 26.04 seen.
    Ubuntu,
    /// Debian's installer (d-i), 12 and 13, netinst and DVD-1 seen.
    Debian,
    /// Windows Server Setup, 2022 and 2025 evaluation media seen.
    WindowsServer,
}

impl Flavor {
    pub const ALL: [Flavor; 3] = [Flavor::Ubuntu, Flavor::Debian, Flavor::WindowsServer];

    /// "Ubuntu Server", "Debian", "Windows Server".
    pub fn name(self) -> &'static str {
        match self {
            Flavor::Ubuntu => "Ubuntu Server",
            Flavor::Debian => "Debian",
            Flavor::WindowsServer => "Windows Server",
        }
    }

    /// "an Ubuntu Server", "a Debian", "a Windows Server".
    pub fn with_article(self) -> &'static str {
        match self {
            Flavor::Ubuntu => "an Ubuntu Server",
            Flavor::Debian => "a Debian",
            Flavor::WindowsServer => "a Windows Server",
        }
    }
}

/// The file system tree [`read_file`] looks a path up in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tree {
    /// ISO 9660's primary tree, by Rock Ridge names where a record has one (Linux reads these), else by the plain
    /// name without its `;1`, in any letter case.
    RockRidge,
    /// The Joliet tree (Windows reads it).
    Joliet,
    /// UDF, where Windows ISOs keep every file.
    Udf,
}

/// Bytes a copy gets at `offset` in place of `replaces`, what the original held there when it was planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoWrite {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub replaces: Vec<u8>,
}

/// The changes a copy of one ISO needs, planned from the original read as untrusted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoPlan {
    pub flavor: Flavor,
    /// In offset order, none overlapping, all inside the image.
    pub writes: Vec<IsoWrite>,
    /// The original's size: [`make_copy`] refuses a source of another size.
    pub iso_bytes: u64,
    /// What the ISO is and what changes, in words for the deploy's preview and job note. Text read from the ISO
    /// (a release name, a volume label) has its control and format characters taken out.
    pub summary: Vec<String>,
}

impl IsoPlan {
    /// How many bytes the copy changes.
    pub fn changed_bytes(&self) -> u64 {
        self.writes.iter().map(|w| w.bytes.len() as u64).sum()
    }
}

/// Plans the copy of `iso` for `flavor`. Reads only what it needs; refuses (`InvalidInput`, in words naming what
/// didn't match) an ISO that isn't laid out as the spikes saw, and one that is damaged.
pub fn plan<R: Read + Seek>(iso: &mut R, flavor: Flavor) -> Result<IsoPlan> {
    let mut image = Image::new(iso)?;
    let (writes, summary) = match flavor {
        Flavor::Ubuntu => ubuntu::plan(&mut image)?,
        Flavor::Debian => debian::plan(&mut image)?,
        Flavor::WindowsServer => windows::plan(&mut image)?,
    };
    let writes = finish_writes(writes, image.len())?;
    Ok(IsoPlan {
        flavor,
        writes,
        iso_bytes: image.len(),
        summary,
    })
}

/// [`plan`] for the ISO at `path`, opened read-only. A network share or device path is refused unopened.
pub fn plan_file(path: &Path, flavor: Flavor) -> Result<IsoPlan> {
    refuse_path(path, "The ISO")?;
    let mut file = File::open(path)?;
    plan(&mut file, flavor)
}

/// Copies `source` to `target` (created new: a file already there is never replaced) a chunk at a time, calling
/// `progress(done, total)` and stopping with [`CoreError::Cancelled`] once `cancel` is set. Each chunk gets the
/// plan's writes after the source's bytes there are checked against what the plan read (a source changed since
/// is refused); then the copy is flushed to disk and the written ranges read back. Any failure or cancel deletes
/// the partial `target`. Blocking: run it on a blocking thread.
pub fn make_copy(
    source: &Path,
    target: &Path,
    plan: &IsoPlan,
    progress: &dyn Fn(u64, u64),
    cancel: &AtomicBool,
) -> Result<()> {
    refuse_path(source, "The ISO")?;
    refuse_path(target, "The ISO's copy")?;
    check_writes(&plan.writes, plan.iso_bytes)?;
    let mut src = File::open(source)?;
    if src.metadata()?.len() != plan.iso_bytes {
        return Err(changed());
    }
    let dst = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                CoreError::InvalidInput(format!(
                    "{} is there already, so Remotely didn't replace it.",
                    target.display()
                ))
            } else {
                CoreError::Io(err)
            }
        })?;
    let result = copy_and_patch(&mut src, dst, plan, progress, cancel);
    if result.is_err() {
        // The copy is closed by now (copy_and_patch owns it), so Windows lets it go.
        if let Err(err) = std::fs::remove_file(target) {
            tracing::warn!(error = %err, "the partial ISO copy could not be deleted");
        }
    }
    result
}

fn copy_and_patch(
    src: &mut File,
    mut dst: File,
    plan: &IsoPlan,
    progress: &dyn Fn(u64, u64),
    cancel: &AtomicBool,
) -> Result<()> {
    let total = plan.iso_bytes;
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut done = 0u64;
    progress(0, total);
    while done < total {
        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled);
        }
        let n = usize::try_from((total - done).min(COPY_CHUNK as u64)).unwrap_or(COPY_CHUNK);
        let chunk = &mut buf[..n];
        src.read_exact(chunk).map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                changed()
            } else {
                CoreError::Io(err)
            }
        })?;
        apply_writes(&plan.writes, done, chunk)?;
        dst.write_all(chunk)?;
        done += n as u64;
        progress(done, total);
    }
    let mut probe = [0u8; 1];
    if src.read(&mut probe)? != 0 {
        return Err(changed());
    }
    dst.flush()?;
    dst.sync_all()?;
    for write in &plan.writes {
        dst.seek(SeekFrom::Start(write.offset))?;
        let mut back = vec![0u8; write.bytes.len()];
        dst.read_exact(&mut back)?;
        if back != write.bytes {
            return Err(CoreError::InvalidInput(
                "The ISO's copy didn't read back as it was written, so it was deleted.".into(),
            ));
        }
    }
    Ok(())
}

/// Puts the writes that fall in `chunk` (which starts at `chunk_start` of the image) into it, after checking the
/// bytes there are the ones each write replaces.
fn apply_writes(writes: &[IsoWrite], chunk_start: u64, chunk: &mut [u8]) -> Result<()> {
    let chunk_end = chunk_start + chunk.len() as u64;
    for write in writes {
        let write_end = write.offset + write.bytes.len() as u64;
        let from = write.offset.max(chunk_start);
        let to = write_end.min(chunk_end);
        if from >= to {
            continue;
        }
        let in_chunk = (from - chunk_start) as usize..(to - chunk_start) as usize;
        let in_write = (from - write.offset) as usize..(to - write.offset) as usize;
        if chunk[in_chunk.clone()] != write.replaces[in_write.clone()] {
            return Err(changed());
        }
        chunk[in_chunk].copy_from_slice(&write.bytes[in_write]);
    }
    Ok(())
}

/// Reads the file at `path` (absolute, `/`-separated) from `iso` through `tree`. `None` when it isn't there; an
/// error for a folder, a file over [`MAX_READ_BYTES`], or a damaged image.
pub fn read_file<R: Read + Seek>(iso: &mut R, path: &str, tree: Tree) -> Result<Option<Vec<u8>>> {
    let mut image = Image::new(iso)?;
    match tree {
        Tree::Udf => {
            let Some(volume) = udf::Udf::open(&mut image)? else {
                return Err(damaged("it has no UDF file system"));
            };
            match volume.lookup(&mut image, path)? {
                None => Ok(None),
                Some(file) if file.is_dir => Err(folder(path)),
                Some(file) => Ok(Some(volume.read(&mut image, &file, MAX_READ_BYTES)?)),
            }
        }
        Tree::RockRidge | Tree::Joliet => {
            let volume = iso9660::Volume::read(&mut image)?;
            match volume.lookup(&mut image, path, tree)? {
                None => Ok(None),
                Some(record) if record.is_dir() => Err(folder(path)),
                Some(record) => Ok(Some(iso9660::read_record(&mut image, &record, MAX_READ_BYTES)?)),
            }
        }
    }
}

fn folder(path: &str) -> CoreError {
    CoreError::InvalidInput(format!("{path} is a folder on the ISO, not a file."))
}

fn refuse_path(path: &Path, what: &str) -> Result<()> {
    match untrusted::path_refusal(path) {
        Some(refusal) => Err(CoreError::InvalidInput(format!(
            "{what} {} {}, so Remotely didn't open it.",
            path.display(),
            refusal.describe()
        ))),
        None => Ok(()),
    }
}

fn changed() -> CoreError {
    CoreError::InvalidInput(
        "The ISO changed after Remotely checked it, so its copy was stopped and deleted. Check the ISO again.".into(),
    )
}

/// The image is damaged or isn't what it claims to be.
pub(crate) fn damaged(detail: impl Display) -> CoreError {
    CoreError::InvalidInput(format!("The ISO can't be read: {detail}."))
}

/// The image reads, but isn't laid out as the spikes saw for `flavor`.
pub(crate) fn unexpected(flavor: Flavor, detail: impl Display) -> CoreError {
    CoreError::InvalidInput(format!(
        "This isn't {} install ISO Remotely knows how to change: {detail}.",
        flavor.with_article()
    ))
}

/// Sorts the writes, drops exact repeats (one record reached twice), and refuses any that overlap, are empty, or
/// fall outside the image.
pub(crate) fn finish_writes(mut writes: Vec<IsoWrite>, len: u64) -> Result<Vec<IsoWrite>> {
    writes.sort_by(|a, b| (a.offset, &a.bytes, &a.replaces).cmp(&(b.offset, &b.bytes, &b.replaces)));
    writes.dedup();
    check_writes(&writes, len)?;
    Ok(writes)
}

fn check_writes(writes: &[IsoWrite], len: u64) -> Result<()> {
    let mut previous_end = 0u64;
    for (i, write) in writes.iter().enumerate() {
        let end = write.offset.checked_add(write.bytes.len() as u64);
        let fits = end.is_some_and(|end| end <= len);
        if write.bytes.is_empty() || write.bytes.len() != write.replaces.len() || !fits {
            return Err(damaged("a planned change doesn't fit the image"));
        }
        if i > 0 && write.offset < previous_end {
            return Err(damaged(
                "two planned changes overlap, so its structures share bytes they shouldn't",
            ));
        }
        previous_end = end.unwrap_or(u64::MAX);
    }
    Ok(())
}

/// Text read from the ISO, fit to show: control and format characters out, white space runs as one space, at most
/// `max` characters.
pub(crate) fn printable(raw: &[u8], max: usize) -> String {
    let text: String = String::from_utf8_lossy(raw)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .filter(|c| !untrusted::is_format_char(*c))
        .collect();
    let words: Vec<&str> = text.split_whitespace().collect();
    let joined = words.join(" ");
    if joined.chars().count() > max {
        let mut cut: String = joined.chars().take(max).collect();
        cut.push('…');
        cut
    } else {
        joined
    }
}

/// The image under a reader: its length, and reads that are checked against it and capped before anything is
/// allocated. The readers ([`iso9660`], [`udf`], [`eltorito`]) take one.
pub struct Image<'a, R> {
    inner: &'a mut R,
    len: u64,
}

impl<'a, R: Read + Seek> Image<'a, R> {
    pub fn new(inner: &'a mut R) -> Result<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        Ok(Self { inner, len })
    }

    /// The image's size in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `len` bytes at `offset`; `what` names them in the error when they aren't all in the image.
    pub fn read_at(&mut self, offset: u64, len: u64, what: &str) -> Result<Vec<u8>> {
        if len > MAX_SINGLE_READ {
            return Err(damaged(format!("{what} is larger than Remotely reads")));
        }
        match offset.checked_add(len) {
            Some(end) if end <= self.len => {}
            _ => return Err(damaged(format!("{what} lies past the end of the image"))),
        }
        self.inner.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; usize::try_from(len).map_err(|_| damaged(format!("{what} is too large")))?];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Sector `n` (2048 bytes).
    pub fn sector(&mut self, n: u64, what: &str) -> Result<Vec<u8>> {
        let offset = n
            .checked_mul(SECTOR)
            .ok_or_else(|| damaged(format!("{what} lies past the end of the image")))?;
        self.read_at(offset, SECTOR, what)
    }

    /// Whether sector `n` is wholly in the image.
    pub fn has_sector(&self, n: u64) -> bool {
        n.checked_add(1)
            .and_then(|end| end.checked_mul(SECTOR))
            .is_some_and(|end| end <= self.len)
    }
}

/// The parts of an absolute `/`-separated path on the ISO: never empty, never `..`, at most [`MAX_PATH_PARTS`].
pub(crate) fn path_parts(path: &str) -> Result<Vec<&str>> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if parts.is_empty() || parts.len() > MAX_PATH_PARTS || parts.contains(&"..") {
        return Err(CoreError::InvalidInput(format!(
            "{} isn't a path Remotely looks up on an ISO.",
            printable(path.as_bytes(), 120)
        )));
    }
    Ok(parts)
}

/// The deepest path [`read_file`] looks up.
pub const MAX_PATH_PARTS: usize = 16;

pub(crate) fn le16(d: &[u8], at: usize) -> u16 {
    match d.get(at..at + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

pub(crate) fn le32(d: &[u8], at: usize) -> u32 {
    match d.get(at..at + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

pub(crate) fn le64(d: &[u8], at: usize) -> u64 {
    match d.get(at..at + 8) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod robustness_tests;

#[cfg(test)]
mod it_tests;
