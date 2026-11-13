//! S1: Ubuntu Server's live ISO (24.04.5 and 26.04.1 seen). BIOS, UEFI and Secure Boot all read
//! `/boot/grub/grub.cfg`, so one change covers them: each `linux` line booting `/casper/vmlinuz` or
//! `/casper/hwe-vmlinuz` gets [`BEFORE_DASHES`] before its `---` (the installer's words: `autoinstall` stops
//! subiquity's "Continue with autoinstall?" question, the consoles put its progress on the serial port) and
//! [`AFTER_DASHES`] after it (copied to the installed system's command line), and `set timeout=30` becomes
//! `set timeout=1`. Lines are matched by their words, so 24.04's tabs and 26.04's four spaces and trailing space
//! both work and keep their white space. The seed (`user-data`, `meta-data`) is on its own CD, never in the copy.

use std::io::{Read, Seek};

use super::linux::{md5_words, LinuxIso};
use super::{unexpected, Flavor, Image, IsoWrite};
use crate::error::Result;

pub const GRUB_CFG: &str = "/boot/grub/grub.cfg";
/// Inserted before `---` (S1: the line that worked, in this order).
pub const BEFORE_DASHES: &str = "autoinstall console=tty0 console=ttyS0,115200n8";
/// Inserted after `---`.
pub const AFTER_DASHES: &str = "console=tty0 console=ttyS0,115200n8";
/// The kernels whose `linux` lines are changed.
pub const KERNELS: [&str; 2] = ["/casper/vmlinuz", "/casper/hwe-vmlinuz"];
/// The menu's new wait, in seconds.
pub const MENU_TIMEOUT: &str = "1";
/// grub.cfg is a few hundred bytes on the ISOs seen.
const MAX_GRUB_BYTES: u64 = 64 * 1024;

/// grub.cfg after [`patch_grub`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchedGrub {
    pub text: String,
    /// `linux` lines changed.
    pub entries: usize,
    /// The kernels those lines boot, each once, in order.
    pub kernels: Vec<String>,
    /// What `set timeout=` was.
    pub old_timeout: String,
}

/// A line's words and where each starts.
fn words(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in line.char_indices() {
        match (c.is_ascii_whitespace(), start) {
            (true, Some(s)) => {
                out.push((s, &line[s..i]));
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, &line[s..]));
    }
    out
}

/// Changes grub.cfg's text as S1 did. Refused (naming why) when no casper `linux` line has a `---`, when the
/// first `linux` line isn't one (the first entry is the one GRUB starts), when a line already has `autoinstall`
/// (a copy of a copy: start from the original ISO instead), when another entry is made the default, and when there
/// is no `set timeout=` line (GRUB would wait for a key).
pub fn patch_grub(text: &str) -> Result<PatchedGrub> {
    patch(text).map_err(|problem| unexpected(Flavor::Ubuntu, problem))
}

fn patch(text: &str) -> std::result::Result<PatchedGrub, String> {
    let mut out = String::with_capacity(text.len() + 512);
    let mut entries = 0usize;
    let mut kernels: Vec<String> = Vec::new();
    let mut old_timeout = None;
    let mut first_linux_changed = None;
    for line in text.split_inclusive('\n') {
        let body_len = line.trim_end_matches(['\r', '\n']).len();
        let (body, ending) = line.split_at(body_len);
        let tokens = words(body);
        let first = tokens.first().map(|t| t.1);
        if first == Some("linux") {
            let kernel = tokens.get(1).map(|t| t.1).filter(|k| KERNELS.contains(k));
            let dashes = tokens.iter().find(|t| t.1 == "---");
            if let (Some(kernel), Some(&(at, _))) = (kernel, dashes) {
                if tokens.iter().any(|t| t.1 == "autoinstall") {
                    return Err(
                        "its grub.cfg already has autoinstall, so it looks like a copy Remotely made; pick the \
                         original ISO"
                            .into(),
                    );
                }
                out.push_str(&body[..at]);
                out.push_str(BEFORE_DASHES);
                out.push_str(" --- ");
                out.push_str(AFTER_DASHES);
                out.push_str(&body[at + 3..]);
                out.push_str(ending);
                entries += 1;
                if !kernels.iter().any(|k| k == kernel) {
                    kernels.push(kernel.to_owned());
                }
                first_linux_changed.get_or_insert(true);
                continue;
            }
            first_linux_changed.get_or_insert(false);
        }
        if first == Some("set") && tokens.len() == 2 {
            let (at, setting) = tokens[1];
            if let Some(value) = setting.strip_prefix("timeout=") {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("its grub.cfg sets a timeout Remotely doesn't read ({setting})"));
                }
                old_timeout.get_or_insert_with(|| value.to_owned());
                out.push_str(&body[..at]);
                out.push_str("timeout=");
                out.push_str(MENU_TIMEOUT);
                out.push_str(&body[at + setting.len()..]);
                out.push_str(ending);
                continue;
            }
            if let Some(value) = setting.strip_prefix("default=") {
                if value != "0" && value != "\"0\"" {
                    return Err(format!("its grub.cfg starts another entry than the first ({setting})"));
                }
            }
        }
        out.push_str(line);
    }
    if entries == 0 {
        return Err("its grub.cfg has no `linux /casper/vmlinuz ... ---` line".into());
    }
    if first_linux_changed != Some(true) {
        return Err("its grub.cfg's first menu entry doesn't boot the casper installer".into());
    }
    let Some(old_timeout) = old_timeout else {
        return Err("its grub.cfg has no `set timeout=` line, so the menu would wait for a key".into());
    };
    Ok(PatchedGrub {
        text: out,
        entries,
        kernels,
        old_timeout,
    })
}

pub(crate) fn plan<R: Read + Seek>(image: &mut Image<R>) -> Result<(Vec<IsoWrite>, Vec<String>)> {
    let flavor = Flavor::Ubuntu;
    let iso = LinuxIso::open(image, flavor)?;
    let grub = iso.text_file(image, GRUB_CFG, MAX_GRUB_BYTES)?;
    let text = std::str::from_utf8(&grub.content)
        .map_err(|_| unexpected(flavor, "its /boot/grub/grub.cfg isn't UTF-8 text"))?;
    let patched = patch_grub(text)?;
    for kernel in &patched.kernels {
        iso.require_file(image, kernel)?;
    }
    let mut writes = grub.rewrite(image, patched.text.as_bytes(), flavor)?;
    let md5 = iso.md5_update(image, &[("./boot/grub/grub.cfg", patched.text.as_bytes())])?;
    writes.extend(md5.writes.iter().cloned());
    let release = iso.release(image)?;
    let summary = vec![
        match release {
            Some(release) => format!("Release: {release}."),
            None => "Release: not named on the ISO (no /.disk/info).".to_owned(),
        },
        format!(
            "grub.cfg (BIOS and UEFI): autoinstall and the serial console added to {} menu {}; the menu waits {} s \
             instead of {} s.",
            patched.entries,
            if patched.entries == 1 { "entry" } else { "entries" },
            MENU_TIMEOUT,
            patched.old_timeout
        ),
        md5_words(&md5, 0, grub.name()),
    ];
    Ok((writes, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_keep_their_offsets() {
        assert_eq!(
            words("\tlinux\t/casper/vmlinuz  ---"),
            [(1, "linux"), (7, "/casper/vmlinuz"), (24, "---")]
        );
        assert_eq!(
            words("    linux  /casper/vmlinuz  --- "),
            [(4, "linux"), (11, "/casper/vmlinuz"), (28, "---")]
        );
        assert!(words(" \t ").is_empty());
    }
}
