//! S1: Ubuntu Server's live ISO (24.04.5 and 26.04.1 seen). BIOS, UEFI and Secure Boot all read
//! `/boot/grub/grub.cfg`, so one change covers them: each `linux` line booting `/casper/vmlinuz` or
//! `/casper/hwe-vmlinuz` gets [`BEFORE_DASHES`] before its `---` (the installer's words: `autoinstall` stops
//! subiquity's "Continue with autoinstall?" question, the consoles put its progress on the serial port) and
//! [`AFTER_DASHES`] after it (copied to the installed system's command line), and `set timeout=30` becomes
//! `set timeout=1`. Lines are matched by their words, so 24.04's tabs and 26.04's four spaces and trailing space
//! both work and keep their white space. The seed (`user-data`, `meta-data`) is on its own CD, never in the copy.

use std::io::{Read, Seek};

use super::linux::{md5_words, LinuxIso};
use super::{printable, unexpected, Flavor, Image, IsoWrite};
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

/// One word of a grub.cfg line: where it starts, its text as written, and its text as GRUB reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Word<'a> {
    start: usize,
    raw: &'a str,
    text: String,
}

/// A line's words as GRUB's lexer splits and unquotes them: white space and `;` outside quotes end a word (`;` is
/// a word of its own), `'...'` is literal, `"..."` takes `\` before `"`, `\` and `$`, `\x` outside quotes is `x`,
/// and `#` at the start of a word starts a comment. So `set "default=1"`, `set 'default=1'` and `set default\=1`
/// all read as `default=1`. A line that ends inside a quote or with a `\` (GRUB would read on into the next line)
/// is refused rather than followed.
fn words(line: &str) -> std::result::Result<Vec<Word<'_>>, String> {
    #[derive(PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }
    fn end_word<'a>(line: &'a str, out: &mut Vec<Word<'a>>, current: &mut Option<(usize, String)>, end: usize) {
        if let Some((start, text)) = current.take() {
            out.push(Word {
                start,
                raw: &line[start..end],
                text,
            });
        }
    }
    let mut out = Vec::new();
    let mut quote = Quote::None;
    let mut current: Option<(usize, String)> = None;
    let mut chars = line.char_indices().peekable();
    let continued = || "its grub.cfg continues a line into the next, which Remotely doesn't read".to_owned();
    while let Some((i, c)) = chars.next() {
        match quote {
            Quote::Single => match c {
                '\'' => quote = Quote::None,
                _ => current.get_or_insert((i, String::new())).1.push(c),
            },
            Quote::Double => match c {
                '"' => quote = Quote::None,
                '\\' => match chars.peek() {
                    Some(&(_, next @ ('"' | '\\' | '$'))) => {
                        chars.next();
                        current.get_or_insert((i, String::new())).1.push(next);
                    }
                    Some(_) => current.get_or_insert((i, String::new())).1.push('\\'),
                    None => return Err(continued()),
                },
                _ => current.get_or_insert((i, String::new())).1.push(c),
            },
            Quote::None => match c {
                c if c.is_ascii_whitespace() => end_word(line, &mut out, &mut current, i),
                ';' => {
                    end_word(line, &mut out, &mut current, i);
                    out.push(Word {
                        start: i,
                        raw: &line[i..i + 1],
                        text: ";".to_owned(),
                    });
                }
                '#' if current.is_none() => break,
                '\'' => {
                    current.get_or_insert((i, String::new()));
                    quote = Quote::Single;
                }
                '"' => {
                    current.get_or_insert((i, String::new()));
                    quote = Quote::Double;
                }
                '\\' => match chars.next() {
                    Some((_, next)) => current.get_or_insert((i, String::new())).1.push(next),
                    None => return Err(continued()),
                },
                _ => current.get_or_insert((i, String::new())).1.push(c),
            },
        }
    }
    if quote != Quote::None {
        return Err("its grub.cfg has a quote that runs past its line, which Remotely doesn't read".into());
    }
    // (A comment ends the loop only between words, so nothing is open then.)
    end_word(line, &mut out, &mut current, line.len());
    Ok(out)
}

/// Changes grub.cfg's text as S1 did. GRUB starts the first top-level menu entry after the timeout, so that entry
/// must be a `menuentry` outside any `if`, holding only `set`, one `linux` line this changes, and `initrd` (as S1's
/// both did). Refused, naming why: no casper `linux` line with a `---`; a first entry that is anything else (a
/// `submenu`, memtest's `linux16`, a `chainloader`, `linuxefi`, a conditional entry); a `default=` other than 0,
/// with or without `set`; `load_env`, `configfile` or `source` outside an entry; braces that don't match; a line
/// that already has `autoinstall` (a copy of a copy: start from the original ISO); and no `set timeout=` (GRUB would
/// wait for a key). Words are read as GRUB's lexer reads them ([`words`]: `set "default=1"` is `default=1`), a line
/// GRUB would continue into the next is refused, and so is a line of the first entry with more than one command.
/// Words quoted from the file are made printable and cut short.
pub fn patch_grub(text: &str) -> Result<PatchedGrub> {
    patch(text).map_err(|problem| unexpected(Flavor::Ubuntu, problem))
}

const FIRST_ENTRY: &str = "its grub.cfg's first menu entry doesn't boot the casper installer";

/// The first top-level menu entry, as the lines go by.
#[derive(Clone, Copy, PartialEq, Eq)]
enum First {
    NotYet,
    Inside { linux: usize, changed: usize },
    Done { linux: usize, changed: usize },
}

/// A word of grub.cfg, fit to quote in a refusal.
fn quoted(word: &str) -> String {
    printable(word.as_bytes(), 60)
}

fn patch(text: &str) -> std::result::Result<PatchedGrub, String> {
    let mut out = String::with_capacity(text.len() + 512);
    let mut entries = 0usize;
    let mut kernels: Vec<String> = Vec::new();
    let mut old_timeout = None;
    // Menu entries' braces, `if` blocks, and the first entry.
    let mut depth = 0usize;
    let mut ifs = 0i64;
    let mut first = First::NotYet;
    for line in text.split_inclusive('\n') {
        let body_len = line.trim_end_matches(['\r', '\n']).len();
        let (body, ending) = line.split_at(body_len);
        let tokens = words(body)?;
        let Some(command) = tokens.first().map(|w| w.text.as_str()) else {
            // Empty, or a comment.
            out.push_str(line);
            continue;
        };
        let in_first = matches!(first, First::Inside { .. });
        if in_first && tokens.iter().any(|w| w.raw == ";") {
            return Err("its grub.cfg's first menu entry runs more than one command on a line".into());
        }
        match command {
            "menuentry" | "submenu" => {
                if tokens.last().map(|w| w.raw) != Some("{") {
                    return Err("its grub.cfg has a menu entry whose line doesn't end in `{`".into());
                }
                if in_first {
                    return Err(FIRST_ENTRY.into());
                }
                if depth == 0 && first == First::NotYet {
                    if command == "submenu" || ifs != 0 {
                        return Err(FIRST_ENTRY.into());
                    }
                    first = First::Inside { linux: 0, changed: 0 };
                }
                depth += 1;
                out.push_str(line);
                continue;
            }
            "}" => {
                if tokens.len() != 1 || tokens[0].raw != "}" || depth == 0 {
                    return Err("its grub.cfg's braces don't match".into());
                }
                depth -= 1;
                if let (0, First::Inside { linux, changed }) = (depth, first) {
                    first = First::Done { linux, changed };
                }
                out.push_str(line);
                continue;
            }
            "if" => {
                ifs += 1;
                if tokens.iter().any(|w| w.text == "fi") {
                    ifs -= 1;
                }
            }
            "fi" => ifs -= 1,
            "load_env" | "configfile" | "source" | "." if depth == 0 => {
                return Err(format!(
                    "its grub.cfg loads other settings or menus (`{}`)",
                    quoted(command)
                ));
            }
            _ => {}
        }
        if in_first && !matches!(command, "set" | "linux" | "initrd") {
            return Err(format!(
                "its grub.cfg's first menu entry runs `{}`, which the ISOs Remotely knows don't",
                quoted(command)
            ));
        }
        if command == "linux" {
            let kernel = tokens.get(1).map(|w| w.text.as_str()).filter(|k| KERNELS.contains(k));
            let dashes = tokens.iter().find(|w| w.text == "---");
            let changed = if let (Some(kernel), Some(dashes)) = (kernel, dashes) {
                if tokens.iter().any(|w| w.text == "autoinstall") {
                    return Err(
                        "its grub.cfg already has autoinstall, so it looks like a copy Remotely made; pick the \
                         original ISO"
                            .into(),
                    );
                }
                out.push_str(&body[..dashes.start]);
                out.push_str(BEFORE_DASHES);
                out.push_str(" --- ");
                out.push_str(AFTER_DASHES);
                out.push_str(&body[dashes.start + dashes.raw.len()..]);
                out.push_str(ending);
                entries += 1;
                if !kernels.iter().any(|k| k == kernel) {
                    kernels.push(kernel.to_owned());
                }
                1
            } else {
                0
            };
            if let First::Inside { linux, changed: done } = &mut first {
                *linux += 1;
                *done += changed;
            }
            if changed == 1 {
                continue;
            }
        }
        // `set name=value`, or `name=value` alone (GRUB takes both), matched as GRUB reads the word.
        let assignment = match (command, tokens.len()) {
            ("set", 2) => tokens.get(1),
            (_, 1) if command.contains('=') => tokens.first(),
            _ => None,
        };
        if let Some(word) = assignment {
            if let Some(value) = word.text.strip_prefix("timeout=") {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!(
                        "its grub.cfg sets a timeout Remotely doesn't read ({})",
                        quoted(&word.text)
                    ));
                }
                old_timeout.get_or_insert_with(|| value.to_owned());
                out.push_str(&body[..word.start]);
                out.push_str("timeout=");
                out.push_str(MENU_TIMEOUT);
                out.push_str(&body[word.start + word.raw.len()..]);
                out.push_str(ending);
                continue;
            }
        }
        // Any `default=` but 0, wherever it is and however it is quoted, starts another entry; so does a timeout
        // set any other way than the line above takes.
        for word in &tokens {
            if let Some(value) = word.text.strip_prefix("default=") {
                if value != "0" {
                    return Err(format!(
                        "its grub.cfg starts another entry than the first ({})",
                        quoted(&word.text)
                    ));
                }
            }
            if word.text.starts_with("timeout=") {
                return Err(format!(
                    "its grub.cfg sets a timeout Remotely doesn't read ({})",
                    quoted(&word.text)
                ));
            }
        }
        out.push_str(line);
    }
    if depth != 0 {
        return Err("its grub.cfg's braces don't match".into());
    }
    if entries == 0 {
        return Err("its grub.cfg has no `linux /casper/vmlinuz ... ---` line".into());
    }
    if first != (First::Done { linux: 1, changed: 1 }) {
        return Err(FIRST_ENTRY.into());
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
    let md5_lines = iso.md5_lines(image, &["./boot/grub/grub.cfg"])?;
    let mut changed = vec![grub.rewritten()];
    changed.extend(md5_lines.rewritten.clone());
    iso.check_alone(image, &changed)?;
    let text = std::str::from_utf8(&grub.content)
        .map_err(|_| unexpected(flavor, "its /boot/grub/grub.cfg isn't UTF-8 text"))?;
    let patched = patch_grub(text)?;
    for kernel in &patched.kernels {
        iso.require_file(image, kernel)?;
    }
    let mut writes = grub.rewrite(image, patched.text.as_bytes(), flavor)?;
    let md5 = md5_lines.update(&[patched.text.as_bytes()]);
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
        let plain = |line: &str| -> Vec<(usize, String)> {
            words(line).unwrap().into_iter().map(|w| (w.start, w.text)).collect()
        };
        let owned = |list: &[(usize, &str)]| -> Vec<(usize, String)> {
            list.iter().map(|(at, text)| (*at, (*text).to_owned())).collect()
        };
        assert_eq!(
            plain("\tlinux\t/casper/vmlinuz  ---"),
            owned(&[(1, "linux"), (7, "/casper/vmlinuz"), (24, "---")])
        );
        assert_eq!(
            plain("    linux  /casper/vmlinuz  --- "),
            owned(&[(4, "linux"), (11, "/casper/vmlinuz"), (28, "---")])
        );
        assert!(plain(" \t ").is_empty());
        assert!(plain("  # set default=1").is_empty(), "a comment");
    }

    #[test]
    fn words_are_unquoted_as_grub_reads_them() {
        let texts = |line: &str| -> Vec<String> { words(line).unwrap().into_iter().map(|w| w.text).collect() };
        assert_eq!(texts("set \"default=1\""), ["set", "default=1"]);
        assert_eq!(texts("set 'default=1'"), ["set", "default=1"]);
        assert_eq!(texts("set de'fault'=\"1\""), ["set", "default=1"]);
        assert_eq!(texts("set default\\=1"), ["set", "default=1"]);
        assert_eq!(texts("echo \"a \\\"b\\\" \\x\" 'c d'"), ["echo", "a \"b\" \\x", "c d"]);
        assert_eq!(texts("if true; then"), ["if", "true", ";", "then"]);
        assert_eq!(texts("a#b # c"), ["a#b"], "`#` starts a comment only at a word's start");
        let quoted = words("set \"timeout=30\" ").unwrap();
        assert_eq!((quoted[1].start, quoted[1].raw), (4, "\"timeout=30\""));
        for line in ["set default=\\", "set \"default=1", "set 'default=1", "echo \"a\\"] {
            assert!(words(line).is_err(), "{line}");
        }
    }
}
