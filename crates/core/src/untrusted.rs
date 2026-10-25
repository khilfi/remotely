//! Input Remotely doesn't trust: paths named inside files it reads, files that may be huge, and text
//! with invisible format characters in it.
//!
//! * **Paths named inside untrusted files** (SS-02 import files, MO-13 .vmx, VMDK and .vbox content,
//!   VBoxManage's `showvminfo`): Windows sends the user's sign-in (an NTLM hash) to any server whose
//!   `\\server\share` it opens, so such a path is never touched at all (no `is_file`, `metadata` or
//!   open) when [`path_refusal`] refuses it. The rules are pure string rules, the same on every
//!   platform:
//!   - two separators at the start, `\` and `/` in any mix: `\\server\share`, `//server/share`,
//!     `\/server`, and the Win32 device prefixes `\\?\` and `\\.\` (`\\?\UNC\server\share` is a share);
//!   - the NT object namespace `\??\` (any separators);
//!   - a last part that is a DOS device name (`CON`, `NUL`, `COM1`, `nul.txt`...: see [`is_device_name`]).
//!
//!   Leading whitespace is ignored for the check. A path the user chose themselves (a .vmx in
//!   Workstation's library or a scanned folder, the import file picked in a dialog) is the user's
//!   choice and is not checked; paths found inside those files are, after they are resolved, so a
//!   relative disk name in a .vmx that lives on a share is refused too.
//! * **Capped reads** ([`read_capped`]): a settings file, descriptor or included file is read whole only
//!   when it is at most its cap; a larger one is an error that names the path, never read partly into
//!   wrong values.
//! * **Unicode format characters** ([`is_format_char`]): General Category Cf, such as U+202E
//!   RIGHT-TO-LEFT OVERRIDE, which makes `invoice\u{202E}fdp.exe` show as `invoiceexe.pdf`.

use std::ffi::OsStr;
use std::path::Path;

use tokio::io::AsyncReadExt;

use crate::error::CoreError;

/// Why a path named inside an untrusted file is not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRefusal {
    /// `\\server\share`, `//server/share`, `\\?\UNC\server\share`: opening it sends the user's sign-in
    /// to that server.
    NetworkShare,
    /// `\\?\`, `\\.\` or `\??\`: a Win32 or NT device path, which can name any device or volume.
    DevicePath,
    /// A DOS device such as `CON`, `NUL` or `COM1`, which Windows opens instead of a file.
    DeviceName,
}

impl PathRefusal {
    /// Finishes "the key file ... ": "is on a network share", "has a Windows device path"...
    pub fn describe(self) -> &'static str {
        match self {
            PathRefusal::NetworkShare => "is on a network share",
            PathRefusal::DevicePath => "has a Windows device path (\\\\?\\, \\\\.\\ or \\??\\)",
            PathRefusal::DeviceName => "names a Windows device (such as CON, NUL or COM1)",
        }
    }
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

/// Why `path` (named inside a file Remotely doesn't trust) must not be opened, or `None` when it may
/// be. Pure: looks at the text only, never at the file system. See the module notes for the rules.
pub fn path_refusal(path: impl AsRef<OsStr>) -> Option<PathRefusal> {
    text_refusal(&path.as_ref().to_string_lossy())
}

fn text_refusal(path: &str) -> Option<PathRefusal> {
    let text = path.trim_start();
    let mut chars = text.chars();
    let (first, second) = (chars.next(), chars.next());
    if first.is_some_and(is_separator) && second.is_some_and(is_separator) {
        // Both separators are ASCII, so byte 2 starts the rest.
        let rest = &text[2..];
        return Some(match device_prefix(rest) {
            Some(after) if names_unc(after) => PathRefusal::NetworkShare,
            Some(_) => PathRefusal::DevicePath,
            None => PathRefusal::NetworkShare,
        });
    }
    // `\??\`: the NT object namespace, which the Win32 file functions pass straight through.
    if first.is_some_and(is_separator) {
        let rest = &text[1..];
        if let Some(after) = rest
            .strip_prefix("??")
            .filter(|a| a.starts_with(is_separator) || a.is_empty())
        {
            let after = after.trim_start_matches(is_separator);
            return Some(if names_unc(after) {
                PathRefusal::NetworkShare
            } else {
                PathRefusal::DevicePath
            });
        }
    }
    let last = text.rsplit(is_separator).next().unwrap_or(text);
    // `C:NUL` names the device too.
    let last = match last.as_bytes() {
        [letter, b':', ..] if letter.is_ascii_alphabetic() => &last[2..],
        _ => last,
    };
    is_device_name(last).then_some(PathRefusal::DeviceName)
}

/// After `\\`: the rest past `?\` or `.\` (any separator), when it is a device prefix.
fn device_prefix(rest: &str) -> Option<&str> {
    let after = rest.strip_prefix('?').or_else(|| rest.strip_prefix('.'))?;
    if after.is_empty() {
        return Some(after);
    }
    after.strip_prefix(is_separator)
}

/// `UNC\server\share` (or `UNC` alone) after a device prefix.
fn names_unc(after: &str) -> bool {
    let first = after.split(is_separator).next().unwrap_or(after);
    first.eq_ignore_ascii_case("UNC")
}

/// Windows opens a device for these names, with or without an extension (`nul`, `nul.txt`, `Com1`),
/// on Windows 10 and 11 alike: CON, PRN, AUX, NUL, CONIN$, CONOUT$, and COM or LPT with one digit,
/// superscript ¹ ² ³ included. Only the part before the first `.` counts, its trailing spaces, dots
/// and colon dropped; names that only start with one (`console.log`, `nullable.txt`) are files.
pub fn is_device_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name).trim_end_matches([' ', '.', ':']);
    let upper = base.to_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    ["COM", "LPT"].iter().any(|port| {
        upper.strip_prefix(port).is_some_and(|rest| {
            let mut chars = rest.chars();
            matches!((chars.next(), chars.next()), (Some('0'..='9' | '¹' | '²' | '³'), None))
        })
    })
}

/// VM settings files read whole: a .vmx, a .vmsd, a .vbox and Workstation's library
/// (`inventory.vmls`). A .vmx is a few KB, and a .vbox with hundreds of snapshots well under 1 MB.
pub const MAX_VM_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// A file read whole that is too large, or could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("{path} is larger than {}, so Remotely didn't read it", size_words(*cap))]
    TooLarge { path: String, cap: u64 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ReadError {
    /// Nothing at that path.
    pub fn is_not_found(&self) -> bool {
        matches!(self, ReadError::Io(err) if err.kind() == std::io::ErrorKind::NotFound)
    }
}

impl From<ReadError> for CoreError {
    fn from(err: ReadError) -> Self {
        match err {
            ReadError::TooLarge { .. } => CoreError::InvalidInput(err.to_string()),
            ReadError::Io(err) => CoreError::Io(err),
        }
    }
}

/// `4 MB`, `64 KB`, `100 bytes`.
pub fn size_words(bytes: u64) -> String {
    const KB: u64 = 1024;
    if bytes >= KB * KB && bytes.is_multiple_of(KB * KB) {
        format!("{} MB", bytes / (KB * KB))
    } else if bytes >= KB && bytes.is_multiple_of(KB) {
        format!("{} KB", bytes / KB)
    } else {
        format!("{bytes} bytes")
    }
}

fn too_large(path: &Path, cap: u64) -> ReadError {
    ReadError::TooLarge {
        path: path.display().to_string(),
        cap,
    }
}

/// The whole file at `path` when it is at most `cap` bytes. A larger one (also one that grows while it
/// is read) is [`ReadError::TooLarge`]; never more than `cap + 1` bytes are read.
pub async fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, ReadError> {
    let file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    if len > cap {
        return Err(too_large(path, cap));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(cap.saturating_add(1)).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > cap {
        return Err(too_large(path, cap));
    }
    Ok(bytes)
}

/// [`read_capped`] for blocking code.
pub fn read_capped_blocking(path: &Path, cap: u64) -> Result<Vec<u8>, ReadError> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > cap {
        return Err(too_large(path, cap));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(too_large(path, cap));
    }
    Ok(bytes)
}

/// Unicode's format characters (General Category Cf), as inclusive ranges, from Unicode 16.0's
/// `DerivedGeneralCategory.txt` (170 code points; 15.0 and 15.1 have the same set).
const FORMAT_CHARS: [(u32, u32); 21] = [
    (0x00AD, 0x00AD),   // SOFT HYPHEN
    (0x0600, 0x0605),   // ARABIC NUMBER SIGN..ARABIC NUMBER MARK ABOVE
    (0x061C, 0x061C),   // ARABIC LETTER MARK
    (0x06DD, 0x06DD),   // ARABIC END OF AYAH
    (0x070F, 0x070F),   // SYRIAC ABBREVIATION MARK
    (0x0890, 0x0891),   // ARABIC POUND MARK ABOVE..ARABIC PIASTRE MARK ABOVE
    (0x08E2, 0x08E2),   // ARABIC DISPUTED END OF AYAH
    (0x180E, 0x180E),   // MONGOLIAN VOWEL SEPARATOR
    (0x200B, 0x200F),   // ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),   // LEFT-TO-RIGHT EMBEDDING..RIGHT-TO-LEFT OVERRIDE
    (0x2060, 0x2064),   // WORD JOINER..INVISIBLE PLUS
    (0x2066, 0x206F),   // LEFT-TO-RIGHT ISOLATE..NOMINAL DIGIT SHAPES
    (0xFEFF, 0xFEFF),   // ZERO WIDTH NO-BREAK SPACE (byte order mark)
    (0xFFF9, 0xFFFB),   // INTERLINEAR ANNOTATION ANCHOR..TERMINATOR
    (0x110BD, 0x110BD), // KAITHI NUMBER SIGN
    (0x110CD, 0x110CD), // KAITHI NUMBER SIGN ABOVE
    (0x13430, 0x1343F), // EGYPTIAN HIEROGLYPH VERTICAL JOINER..END WALLED ENCLOSURE
    (0x1BCA0, 0x1BCA3), // SHORTHAND FORMAT LETTER OVERLAP..UP STEP
    (0x1D173, 0x1D17A), // MUSICAL SYMBOL BEGIN BEAM..END PHRASE
    (0xE0001, 0xE0001), // LANGUAGE TAG
    (0xE0020, 0xE007F), // TAG SPACE..CANCEL TAG
];

/// A Unicode format character (General Category Cf): invisible, and some (U+202E, U+2066..U+2069)
/// reorder the text around them.
pub fn is_format_char(c: char) -> bool {
    let c = u32::from(c);
    FORMAT_CHARS.iter().any(|&(from, to)| (from..=to).contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_shares_are_refused_whatever_the_slashes() {
        for path in [
            r"\\server.example.com\share\id_ed25519",
            r"//server.example.com/share/id_ed25519",
            r"\/server.example.com/share",
            r"/\server.example.com\share",
            r"\\192.0.2.10\c$\keys\id_rsa",
            r"\\server.example.com@SSL\DavWWWRoot\x.conf",
            r"\\server.example.com",
            r"\\",
            r"  \\server.example.com\share\x",
            r"\\?\UNC\server.example.com\share\x.vmdk",
            r"//?/unc/server.example.com/share/x.vmdk",
            r"\\.\UNC\server.example.com\share",
            r"\??\UNC\server.example.com\share\x",
            r"\\?abc\share",
        ] {
            assert_eq!(path_refusal(path), Some(PathRefusal::NetworkShare), "{path}");
        }
    }

    #[test]
    fn device_paths_and_names_are_refused() {
        for path in [
            r"\\?\C:\VMs\web01\web01.vmdk",
            r"//?/C:/VMs/web01.vmdk",
            r"\\.\PhysicalDrive0",
            r"\\.\pipe\remotely",
            r"//./COM1",
            r"\\?\GLOBALROOT\Device\Mup\server.example.com\share",
            r"\\?",
            r"\??\C:\keys\id_rsa",
            r"/??/C:/keys/id_rsa",
            r"\??",
        ] {
            assert_eq!(path_refusal(path), Some(PathRefusal::DevicePath), "{path}");
        }
        for path in [
            "CON",
            "nul",
            r"C:\Users\alice\.ssh\NUL",
            r"C:\keys\com1.ppk",
            "lpt³",
            "C:NUL",
            "CONIN$",
            "aux.conf",
            "nul:",
            r"C:\keys\nul .txt",
        ] {
            assert_eq!(path_refusal(path), Some(PathRefusal::DeviceName), "{path}");
        }
    }

    #[test]
    fn local_paths_pass() {
        for path in [
            r"C:\Users\alice\.ssh\id_ed25519",
            "C:/Users/alice/.ssh/id_ed25519",
            r"D:\VMs\web01\web01.vmdk",
            r"\VMs\web01.vmdk",
            "/home/alice/.ssh/config",
            "web01-000001.vmdk",
            r"keys\id_rsa",
            r"C:\\server\share",
            r"C:\keys\console.log",
            r"C:\keys\nullable",
            r"C:\keys\com10",
            r"C:\a\?\b",
            "?",
            "",
        ] {
            assert_eq!(path_refusal(path), None, "{path}");
        }
        assert_eq!(
            path_refusal(Path::new(r"\\server.example.com\x")),
            Some(PathRefusal::NetworkShare)
        );
        assert!(PathRefusal::NetworkShare.describe().contains("network share"));
    }

    #[test]
    fn the_format_table_is_unicodes_cf_set() {
        let count: u32 = FORMAT_CHARS.iter().map(|(from, to)| to - from + 1).sum();
        assert_eq!(count, 170, "Unicode 16.0 has 170 Cf code points");
        assert!(
            FORMAT_CHARS.windows(2).all(|w| w[0].1 < w[1].0),
            "sorted, not overlapping"
        );
        for c in [
            '\u{202E}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{200E}',
            '\u{200F}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{061C}',
            '\u{E0041}',
        ] {
            assert!(is_format_char(c), "U+{:04X}", u32::from(c));
        }
        for c in ['a', ' ', '\u{00A0}', '\u{2028}', '\u{FFFD}', 'é', '\u{1F600}'] {
            assert!(!is_format_char(c), "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn sizes_read_in_round_units() {
        assert_eq!(size_words(4 * 1024 * 1024), "4 MB");
        assert_eq!(size_words(64 * 1024), "64 KB");
        assert_eq!(size_words(100), "100 bytes");
    }

    #[tokio::test]
    async fn capped_reads_refuse_a_larger_file_and_never_read_it_partly() {
        let dir = std::env::temp_dir().join(format!("remotely-capped-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("web01.vmx");
        std::fs::write(&path, vec![b'x'; 100]).unwrap();
        assert_eq!(read_capped(&path, 100).await.unwrap().len(), 100);
        assert_eq!(read_capped_blocking(&path, 100).unwrap().len(), 100);
        let err = read_capped(&path, 99).await.unwrap_err();
        assert!(matches!(err, ReadError::TooLarge { cap: 99, .. }), "{err}");
        assert_eq!(
            err.to_string(),
            format!("{} is larger than 99 bytes, so Remotely didn't read it", path.display())
        );
        assert!(matches!(
            read_capped_blocking(&path, 10),
            Err(ReadError::TooLarge { .. })
        ));
        let missing = read_capped(&dir.join("gone.vmx"), 100).await.unwrap_err();
        assert!(missing.is_not_found());
        assert_eq!(CoreError::from(err).code(), "invalid_input");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
