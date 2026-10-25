//! VM-23: a Workstation `.vmx` file as its lines, for edits that change only the keys Remotely sets.
//!
//! Every line Remotely does not change is written back byte for byte: keys it does not know, their order,
//! comments, blank lines, the file's line endings and its byte-order mark. A changed key keeps its place and
//! the spelling of its name (`displayName`, `memsize`); a new key goes at the end, as Workstation itself adds
//! keys. Values are written the way Workstation writes them: `key = "value"`, with `"`, `|`, `#` and control
//! characters as `|XX` (hex), which [`crate::adapters::vm_hardware`] and Workstation read back.
//!
//! A `.vmx` that is not UTF-8 (one written in a Windows code page by a very old Workstation) is refused:
//! reading it as UTF-8 and writing it back would change its other values.
//!
//! The file on disk is changed only by the adapter ([`crate::adapters::vmware::VmwareAdapter::write_vmx`]):
//! after a backup copy beside it, written in full to a new file that then replaces it.

use crate::error::{CoreError, Result};

/// One line of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    /// `key = value`: the key as written, in lower case for lookups, and the value unescaped.
    Pair {
        key: String,
        lower: String,
        value: String,
        /// The line as read; `None` once Remotely changed it (it is then written in Workstation's form).
        raw: Option<String>,
    },
    /// A comment, a blank line, or anything else: written back as read.
    Other(String),
}

/// A `.vmx` file Remotely can change and write back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmxFile {
    lines: Vec<Line>,
    /// `\r\n` when the file used it, else `\n`.
    newline: &'static str,
    /// The file ended with a line break.
    final_newline: bool,
    bom: bool,
}

/// A key Remotely may set: letters, digits and `_ . : -`, as in every key Workstation writes.
pub fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// Workstation's form of a value: `"`, `|`, `#` and control characters as `|XX`. Everything else, other
/// languages' letters included, is kept as UTF-8.
pub fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' | '|' | '#' => out.push_str(&format!("|{:02X}", c as u32)),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("|{:02X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Undoes [`escape_value`]: `|XX` (two hex digits) is that byte.
pub fn unescape_value(value: &str) -> String {
    if !value.contains('|') {
        return value.to_owned();
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'|' && i + 2 < bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_line(line: &str) -> Line {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.is_empty() {
        return Line::Other(line.to_owned());
    }
    let Some((key, value)) = trimmed.split_once('=') else {
        return Line::Other(line.to_owned());
    };
    let key = key.trim();
    if key.is_empty() {
        return Line::Other(line.to_owned());
    }
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    Line::Pair {
        key: key.to_owned(),
        lower: key.to_ascii_lowercase(),
        value: unescape_value(value),
        raw: Some(line.to_owned()),
    }
}

impl VmxFile {
    /// Reads the file's bytes. Fails on a file that is not UTF-8.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (bom, bytes) = match bytes.strip_prefix(b"\xef\xbb\xbf") {
            Some(rest) => (true, rest),
            None => (false, bytes),
        };
        let text = std::str::from_utf8(bytes).map_err(|_| {
            CoreError::VmSettingRefused(
                "the .vmx is not UTF-8 text (a very old Workstation wrote it in a Windows code page), so Remotely \
                 doesn't change it: open the VM once in Workstation, which writes it as UTF-8, then try again"
                    .into(),
            )
        })?;
        Ok(Self::parse_text(text, bom))
    }

    /// The file from text already known to be UTF-8 (tests, and files Remotely writes itself).
    pub fn from_text(text: &str) -> Self {
        Self::parse_text(text, false)
    }

    fn parse_text(text: &str, bom: bool) -> Self {
        let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let final_newline = text.ends_with('\n');
        let body = text.strip_suffix('\n').unwrap_or(text);
        let body = body.strip_suffix('\r').unwrap_or(body);
        let lines = if text.is_empty() {
            Vec::new()
        } else {
            body.split('\n')
                .map(|l| parse_line(l.strip_suffix('\r').unwrap_or(l)))
                .collect()
        };
        Self {
            lines,
            newline,
            final_newline: final_newline || text.is_empty(),
            bom,
        }
    }

    /// The value of `key` (any letter case). When a key is written twice, Workstation takes the last.
    pub fn get(&self, key: &str) -> Option<&str> {
        let lower = key.to_ascii_lowercase();
        self.lines.iter().rev().find_map(|line| match line {
            Line::Pair { lower: l, value, .. } if *l == lower => Some(value.as_str()),
            _ => None,
        })
    }

    /// Whether `key` is set to something Workstation reads as true.
    pub fn is_true(&self, key: &str) -> bool {
        self.get(key)
            .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "yes" | "1"))
    }

    /// Every key and value, in file order (lower-case keys).
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.lines.iter().filter_map(|line| match line {
            Line::Pair { lower, value, .. } => Some((lower.as_str(), value.as_str())),
            Line::Other(_) => None,
        })
    }

    /// Sets `key` to `value`: in place when the key is there (a second copy of it is removed, so the file
    /// says one thing), else at the end. A key Remotely builds is always valid; anything else is refused.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        if !is_valid_key(key) {
            return Err(CoreError::InvalidInput(format!("'{key}' is not a .vmx key")));
        }
        let lower = key.to_ascii_lowercase();
        let mut found = false;
        self.lines.retain_mut(|line| match line {
            Line::Pair {
                lower: l,
                value: v,
                raw,
                ..
            } if *l == lower => {
                if found {
                    return false;
                }
                found = true;
                if v != value {
                    value.clone_into(v);
                    *raw = None;
                }
                true
            }
            _ => true,
        });
        if !found {
            self.lines.push(Line::Pair {
                key: key.to_owned(),
                lower,
                value: value.to_owned(),
                raw: None,
            });
        }
        Ok(())
    }

    /// Sets a key to `TRUE` or `FALSE`, as Workstation writes them.
    pub fn set_bool(&mut self, key: &str, on: bool) -> Result<()> {
        self.set(key, if on { "TRUE" } else { "FALSE" })
    }

    /// Removes `key` (every copy). Returns whether it was there.
    pub fn remove(&mut self, key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        let before = self.lines.len();
        self.lines
            .retain(|line| !matches!(line, Line::Pair { lower: l, .. } if *l == lower));
        self.lines.len() != before
    }

    /// Removes every key that starts with `prefix` (any letter case), e.g. `ethernet1.` for one adapter.
    /// Returns how many lines went.
    pub fn remove_prefix(&mut self, prefix: &str) -> usize {
        let prefix = prefix.to_ascii_lowercase();
        let before = self.lines.len();
        self.lines
            .retain(|line| !matches!(line, Line::Pair { lower, .. } if lower.starts_with(&prefix)));
        before - self.lines.len()
    }

    /// The file's text: lines Remotely did not change exactly as read, the others as Workstation writes them.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        if self.bom {
            out.push('\u{feff}');
        }
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push_str(self.newline);
            }
            match line {
                Line::Other(raw) | Line::Pair { raw: Some(raw), .. } => out.push_str(raw),
                Line::Pair {
                    key, value, raw: None, ..
                } => {
                    out.push_str(key);
                    out.push_str(" = \"");
                    out.push_str(&escape_value(value));
                    out.push('"');
                }
            }
        }
        if self.final_newline && !self.lines.is_empty() {
            out.push_str(self.newline);
        }
        out
    }

    /// The file's bytes, as [`Self::to_text`] (the byte-order mark included when it had one).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_text().into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::vm_hardware::parse_vmx_hardware;

    const VMX: &str = ".encoding = \"UTF-8\"\r\n\
# a comment Workstation never writes, kept anyway\r\n\
config.version = \"8\"\r\n\
virtualHW.version = \"21\"\r\n\
displayName = \"web |22one|22\"\r\n\
numvcpus = \"2\"\r\n\
memsize = \"4096\"\r\n\
\r\n\
someVendor.unknownKey = \"keep me\"\r\n\
bare.value = 42\r\n\
ethernet0.present = \"TRUE\"\r\n\
ethernet0.connectionType = \"nat\"\r\n\
ethernet1.present = \"TRUE\"\r\n\
ethernet1.connectionType = \"custom\"\r\n\
ethernet1.vnet = \"VMnet2\"\r\n";

    #[test]
    fn an_unchanged_file_is_written_back_byte_for_byte() {
        let file = VmxFile::parse(VMX.as_bytes()).unwrap();
        assert_eq!(file.to_text(), VMX);
        let lf = VMX.replace("\r\n", "\n");
        assert_eq!(VmxFile::from_text(&lf).to_text(), lf);
        let no_final = lf.trim_end_matches('\n');
        assert_eq!(VmxFile::from_text(no_final).to_text(), no_final);
        let with_bom = [b"\xef\xbb\xbf".as_slice(), VMX.as_bytes()].concat();
        assert_eq!(VmxFile::parse(&with_bom).unwrap().to_bytes()[..3], with_bom[..3]);
        assert_eq!(VmxFile::from_text("").to_text(), "");
    }

    #[test]
    fn a_change_keeps_every_other_line_and_the_keys_place_and_spelling() {
        let mut file = VmxFile::parse(VMX.as_bytes()).unwrap();
        file.set("NUMVCPUS", "4").unwrap();
        file.set("memsize", "8192").unwrap();
        file.set("cpuid.coresPerSocket", "2").unwrap();
        let text = file.to_text();
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines[5], "numvcpus = \"4\"", "in place, as the file spells it");
        assert_eq!(lines[6], "memsize = \"8192\"");
        assert_eq!(lines[1], "# a comment Workstation never writes, kept anyway");
        assert_eq!(lines[8], "someVendor.unknownKey = \"keep me\"");
        assert_eq!(lines[9], "bare.value = 42", "an unquoted value is kept as written");
        assert_eq!(lines[15], "cpuid.coresPerSocket = \"2\"", "a new key at the end");
        assert!(text.ends_with("\r\n"));
        // Setting a key to what it already holds rewrites nothing.
        let mut same = VmxFile::parse(VMX.as_bytes()).unwrap();
        same.set("displayName", "web \"one\"").unwrap();
        assert_eq!(same.to_text(), VMX);
    }

    #[test]
    fn values_are_escaped_as_workstation_writes_them_and_read_back() {
        let mut file = VmxFile::from_text("displayName = \"x\"\n");
        let name = "lab \"blue\" | #1\tweb — ünïcode";
        file.set("displayName", name).unwrap();
        let text = file.to_text();
        assert_eq!(text, "displayName = \"lab |22blue|22 |7C |231|09web — ünïcode\"\n");
        assert_eq!(VmxFile::from_text(&text).get("displayname"), Some(name));
        // The MO-13 reader agrees.
        let mut cpu = VmxFile::from_text(&text);
        cpu.set("numvcpus", "6").unwrap();
        let (hardware, _) = parse_vmx_hardware(&cpu.to_text());
        assert_eq!(hardware.vcpus, Some(6));
        assert_eq!(unescape_value("50|"), "50|");
        assert_eq!(escape_value("C:\\VMs\\a.iso"), "C:\\VMs\\a.iso", "backslashes stay");
    }

    #[test]
    fn keys_are_removed_one_at_a_time_or_by_prefix() {
        let mut file = VmxFile::parse(VMX.as_bytes()).unwrap();
        assert!(file.remove("bare.value"));
        assert!(!file.remove("bare.value"));
        assert_eq!(file.remove_prefix("ETHERNET1."), 3);
        let text = file.to_text();
        assert!(!text.contains("ethernet1"));
        assert!(text.contains("ethernet0.connectionType"));
        assert!(!text.contains("bare.value"));
    }

    #[test]
    fn a_doubled_key_reads_as_its_last_copy_and_is_set_once() {
        let mut file = VmxFile::from_text("memsize = \"1024\"\nother = \"1\"\nmemsize = \"2048\"\n");
        assert_eq!(file.get("memsize"), Some("2048"));
        file.set("memsize", "4096").unwrap();
        assert_eq!(file.to_text(), "memsize = \"4096\"\nother = \"1\"\n");
    }

    #[test]
    fn a_file_that_is_not_utf8_and_a_bad_key_are_refused() {
        let latin1 = b"displayName = \"caf\xe9\"\n";
        let err = VmxFile::parse(latin1).unwrap_err();
        assert_eq!(err.code(), "vm_setting_refused");
        let mut file = VmxFile::from_text("");
        assert!(file.set("bad key", "1").is_err());
        assert!(file.set("a\nb", "1").is_err());
        assert!(file.set("", "1").is_err());
        file.set("scsi0:1.fileName", "web-1.vmdk").unwrap();
        assert_eq!(file.to_text(), "scsi0:1.fileName = \"web-1.vmdk\"\n");
        assert!(!file.is_true("missing"));
    }
}
