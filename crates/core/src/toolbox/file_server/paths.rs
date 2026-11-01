//! FD-09: what a TFTP or HTTP client asks for, turned into checked parts of a path under the served root, and the
//! name an upload may take. Every request is hostile:
//!
//! * **Text first.** A path is refused for `.` and `..` parts, a `\` anywhere, an absolute path (`//`, a drive
//!   letter), a `:` (drive letters and alternate data streams, `name:stream`), a part ending in a dot or a space
//!   (Windows drops those, so `a.txt.` would open `a.txt`), control and Unicode format characters, the characters
//!   Windows can't hold in a name, DOS device names (`NUL`, `com1.txt`), and anything [`path_refusal`] refuses.
//!   HTTP paths are percent-decoded once; a `%` that still encodes something after that (`%252e`) is refused, as is a
//!   decoding that isn't UTF-8.
//! * **Then the file system.** Each part is looked up from the root down without following links: a symbolic link
//!   or junction on the way is refused. Only a regular file is served, and only once the path of the opened file
//!   (Windows' final path of its handle) is still under the root.
//!
//! Upload names are one part, checked the same way, except that Unicode format characters become `_` (as A8 does
//! for downloads), so `invoice\u{202E}fdp.exe` arrives as `invoice_fdp.exe`.

use std::path::{Path, PathBuf};

use crate::untrusted::{is_device_name, is_format_char, path_refusal};

/// The most parts a request path may have.
pub const MAX_PARTS: usize = 32;
/// The longest request path, in characters (after decoding).
pub const MAX_PATH_CHARS: usize = 1024;
/// The longest name of one part, in characters.
pub const MAX_PART_CHARS: usize = 255;
/// The longest upload name, in characters (Windows takes 255 UTF-16 units in a name; this leaves room).
pub const MAX_UPLOAD_NAME_CHARS: usize = 200;

/// Why a request's path was refused. The words go into the request log and the client's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Nothing named (an upload without a name).
    Empty,
    /// `.` or `..`, or a `\`.
    Traversal,
    /// `//server`, `C:`, a leading `\`.
    Absolute,
    /// A percent-encoding that doesn't decode, decodes to something that isn't UTF-8, or still encodes after one
    /// decoding (`%252e`).
    Encoding,
    /// `name:stream`.
    Stream,
    /// A part ending in a dot or a space.
    TrailingDotOrSpace,
    /// A control or format character, or one of `<>"|?*`.
    Character,
    /// `NUL`, `com1.txt`...
    Device,
    /// Too long, or too many parts.
    TooLong,
    /// A symbolic link or junction on the way, or a file whose real place is outside the root.
    Link,
    /// Not there, or not a regular file or folder.
    NotFound,
    /// An upload into a subfolder: uploads go into the one folder.
    Subfolder,
    /// An upload named like a file Windows Explorer reads by itself when it shows the folder (a `.url`'s or `.lnk`'s
    /// icon, `desktop.ini`): one naming a `\\server\share` would send the user's sign-in there.
    ShellFile,
}

/// Extensions of files Windows Explorer opens by itself, or that point it at another place, when it shows or opens a
/// folder: shortcuts, Internet shortcuts, Explorer commands, libraries, search connectors, themes, setting links.
const SHELL_EXTENSIONS: &[&str] = &[
    "lnk",
    "url",
    "website",
    "scf",
    "library-ms",
    "searchconnector-ms",
    "search-ms",
    "settingcontent-ms",
    "appref-ms",
    "pif",
    "theme",
    "themepack",
    "deskthemepack",
    "ms-shortcut",
];

/// Names Explorer reads by itself in a folder.
const SHELL_NAMES: &[&str] = &["desktop.ini", "autorun.inf", "folder.htt", "thumbs.db"];

/// Whether Windows Explorer acts on a file of this name by itself (see [`Refused::ShellFile`]). Without case.
pub fn is_shell_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    if SHELL_NAMES.contains(&lower.as_str()) {
        return true;
    }
    lower
        .rsplit_once('.')
        .is_some_and(|(_, extension)| SHELL_EXTENSIONS.contains(&extension))
}

impl Refused {
    /// "the path leaves the served folder"... for the request log.
    pub fn describe(self) -> &'static str {
        match self {
            Refused::ShellFile => {
                "a file type Windows Explorer acts on by itself (a shortcut, an Internet shortcut, desktop.ini...)"
            }
            Refused::Empty => "no file named",
            Refused::Traversal => "the path leaves the served folder (. or .., or a backslash)",
            Refused::Absolute => "an absolute path, a drive or a share",
            Refused::Encoding => "a percent-encoding that doesn't decode once to UTF-8",
            Refused::Stream => "a colon (a drive or an alternate data stream)",
            Refused::TrailingDotOrSpace => "a name ending in a dot or a space",
            Refused::Character => "a control, format or reserved character",
            Refused::Device => "a Windows device name",
            Refused::TooLong => "the path is too long",
            Refused::Link => "a link or junction, or a file outside the served folder",
            Refused::NotFound => "not found",
            Refused::Subfolder => "uploads go into the upload folder itself, not a subfolder",
        }
    }
}

/// Decodes `%XX` once. Refuses a `%` not followed by two hex digits, bytes that aren't UTF-8, and a result that still
/// holds an encoding (double encoding).
pub fn percent_decode(text: &str) -> Result<String, Refused> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = bytes.get(i + 1).and_then(|b| hex_value(*b));
                let lo = bytes.get(i + 2).and_then(|b| hex_value(*b));
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(Refused::Encoding);
                };
                out.push(hi * 16 + lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    let decoded = String::from_utf8(out).map_err(|_| Refused::Encoding)?;
    if holds_encoding(&decoded) {
        return Err(Refused::Encoding);
    }
    Ok(decoded)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `%` followed by two hex digits.
fn holds_encoding(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .windows(3)
        .any(|w| w[0] == b'%' && hex_value(w[1]).is_some() && hex_value(w[2]).is_some())
}

/// One part of a path, checked as a Windows file name a request may name.
fn check_part(part: &str) -> Result<(), Refused> {
    if part == "." || part == ".." {
        return Err(Refused::Traversal);
    }
    if part.chars().any(|c| {
        c.is_control() || is_format_char(c) || matches!(c, '<' | '>' | '"' | '|' | '?' | '*' | '\u{2028}' | '\u{2029}')
    }) {
        return Err(Refused::Character);
    }
    if part.contains('\\') {
        return Err(Refused::Traversal);
    }
    if part.contains(':') {
        return Err(Refused::Stream);
    }
    if part.chars().count() > MAX_PART_CHARS {
        return Err(Refused::TooLong);
    }
    // Windows drops trailing dots and spaces, so `secret.txt.` or `...` would open another name.
    if part.ends_with('.') || part.ends_with(' ') {
        return Err(Refused::TrailingDotOrSpace);
    }
    if is_device_name(part) {
        return Err(Refused::Device);
    }
    Ok(())
}

/// What a request names under the root: its parts, and whether it ended in `/` (a folder, for HTTP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPath {
    pub parts: Vec<String>,
    pub folder: bool,
}

impl RequestPath {
    /// The parts joined with `/`, for the log: `sub/firmware.bin`.
    pub fn display(&self) -> String {
        let mut text = self.parts.join("/");
        if self.folder && !text.is_empty() {
            text.push('/');
        }
        text
    }

    /// The path percent-encoded again, from `/`, for a link or a redirect: only unreserved characters stay.
    pub fn encoded(&self) -> String {
        let mut text = String::from("/");
        for (i, part) in self.parts.iter().enumerate() {
            if i > 0 {
                text.push('/');
            }
            text.push_str(&percent_encode(part));
        }
        if self.folder && !self.parts.is_empty() {
            text.push('/');
        }
        text
    }
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Checks a path that is already text (TFTP's file name, or HTTP's after decoding). One leading `/` means the root;
/// a second one (or a `\` first) is an absolute path or a share. `trailing_slash` lets the last part be empty (an
/// HTTP folder).
fn check_text(text: &str, trailing_slash: bool) -> Result<RequestPath, Refused> {
    if text.chars().count() > MAX_PATH_CHARS {
        return Err(Refused::TooLong);
    }
    if text.starts_with('\\') {
        return Err(Refused::Absolute);
    }
    let rest = text.strip_prefix('/').unwrap_or(text);
    if rest.starts_with('/') || rest.starts_with('\\') {
        return Err(Refused::Absolute);
    }
    // `C:` and `C:\...`: a drive.
    let mut chars = rest.chars();
    if let (Some(letter), Some(':')) = (chars.next(), chars.next()) {
        if letter.is_ascii_alphabetic() {
            return Err(Refused::Absolute);
        }
    }
    // Belt and braces: the rules the rest of the app applies to untrusted paths.
    if path_refusal(text).is_some() || path_refusal(rest).is_some() {
        return Err(if rest.contains(':') || rest.starts_with(['/', '\\']) {
            Refused::Absolute
        } else {
            Refused::Device
        });
    }
    if rest.is_empty() {
        return Ok(RequestPath {
            parts: Vec::new(),
            folder: true,
        });
    }
    let mut pieces: Vec<&str> = rest.split('/').collect();
    let folder = pieces.last() == Some(&"");
    if folder {
        if !trailing_slash {
            return Err(Refused::NotFound);
        }
        pieces.pop();
    }
    if pieces.len() > MAX_PARTS {
        return Err(Refused::TooLong);
    }
    let mut parts = Vec::with_capacity(pieces.len());
    for piece in pieces {
        // `a//b`: an empty part.
        if piece.is_empty() {
            return Err(Refused::Absolute);
        }
        check_part(piece)?;
        parts.push(piece.to_owned());
    }
    Ok(RequestPath { parts, folder })
}

/// An HTTP request target (origin form: `/path?query`). The query and fragment are dropped; the path is decoded once.
pub fn http_path(target: &str) -> Result<RequestPath, Refused> {
    if !target.starts_with('/') {
        // `*`, `http://host/...`, `example.com:80`: not the origin form.
        return Err(Refused::Absolute);
    }
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let decoded = percent_decode(path)?;
    check_text(&decoded, true)
}

/// A TFTP file name as the client sent it (bytes, NUL-terminated in the packet).
pub fn tftp_path(name: &[u8]) -> Result<RequestPath, Refused> {
    let text = std::str::from_utf8(name).map_err(|_| Refused::Encoding)?;
    if text.is_empty() {
        return Err(Refused::Empty);
    }
    check_text(text, false)
}

/// The name an upload takes in the upload folder, from what the client sent (HTTP's path decoded, or TFTP's name):
/// one part, Unicode format characters turned into `_`, then checked like any part, at most
/// [`MAX_UPLOAD_NAME_CHARS`] characters, and never a file Explorer acts on by itself ([`is_shell_file`]).
pub fn upload_name(path: &RequestPath) -> Result<String, Refused> {
    match path.parts.as_slice() {
        [] => Err(Refused::Empty),
        [one] if !path.folder => {
            // A8: invisible characters that change how a name reads become `_`.
            let name: String = one.chars().map(|c| if is_format_char(c) { '_' } else { c }).collect();
            if name.chars().count() > MAX_UPLOAD_NAME_CHARS || name.encode_utf16().count() > 255 {
                return Err(Refused::TooLong);
            }
            check_part(&name)?;
            if is_shell_file(&name) {
                return Err(Refused::ShellFile);
            }
            Ok(name)
        }
        _ => Err(Refused::Subfolder),
    }
}

/// [`upload_name`] for an HTTP PUT's target. Format characters may arrive percent-encoded or raw.
pub fn http_upload_name(target: &str) -> Result<String, Refused> {
    let path = http_upload_path(target)?;
    upload_name(&path)
}

/// [`upload_name`] for a TFTP write request's name.
pub fn tftp_upload_name(name: &[u8]) -> Result<String, Refused> {
    let text = std::str::from_utf8(name).map_err(|_| Refused::Encoding)?;
    if text.is_empty() {
        return Err(Refused::Empty);
    }
    upload_name(&check_upload_text(text)?)
}

fn http_upload_path(target: &str) -> Result<RequestPath, Refused> {
    if !target.starts_with('/') {
        return Err(Refused::Absolute);
    }
    let path = target.split(['?', '#']).next().unwrap_or(target);
    check_upload_text(&percent_decode(path)?)
}

/// As [`check_text`], but format characters are let through to [`upload_name`], which turns them into `_`.
fn check_upload_text(text: &str) -> Result<RequestPath, Refused> {
    let cleaned: String = text.chars().map(|c| if is_format_char(c) { '_' } else { c }).collect();
    check_text(&cleaned, false)
}

/// Whether `inner` (a final path from the file system) is `root` or under it. Both come from Windows' final path of a
/// handle (or `canonicalize`), so they have the same form; letters are compared without case, as NTFS does.
pub fn is_under(root: &Path, inner: &Path) -> bool {
    let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
    lower(inner).starts_with(lower(root))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn http(target: &str) -> Result<Vec<String>, Refused> {
        http_path(target).map(|p| p.parts)
    }

    #[test]
    fn plain_paths_are_split_into_parts() {
        assert_eq!(http("/").unwrap(), Vec::<String>::new());
        assert_eq!(http("/firmware.bin").unwrap(), ["firmware.bin"]);
        assert_eq!(
            http("/images/switch%20v2.bin?x=1#y").unwrap(),
            ["images", "switch v2.bin"]
        );
        assert!(http_path("/images/").unwrap().folder);
        assert_eq!(tftp_path(b"firmware.bin").unwrap().parts, ["firmware.bin"]);
        assert_eq!(tftp_path(b"/configs/sw1.cfg").unwrap().parts, ["configs", "sw1.cfg"]);
        assert_eq!(http("/100%25.txt").unwrap(), ["100%.txt"]);
        assert_eq!(http("/caf%C3%A9.txt").unwrap(), ["café.txt"]);
    }

    #[test]
    fn every_traversal_form_is_refused_over_http() {
        for target in [
            "/..",
            "/../secret.txt",
            "/a/../../secret.txt",
            "/a/./b",
            "/%2e%2e/secret.txt",
            "/%2E%2E%2Fsecret.txt",
            "/..%2fsecret.txt",
            "/..%5csecret.txt",
            "/..\\secret.txt",
            "/a\\..\\..\\secret.txt",
        ] {
            assert_eq!(http(target), Err(Refused::Traversal), "{target}");
        }
        // Double-encoded: %25 is %, so %252e%252e is %2e%2e after one decoding.
        for target in ["/%252e%252e/secret.txt", "/%252e%252e%252fsecret.txt", "/%25%32%65"] {
            assert_eq!(http(target), Err(Refused::Encoding), "{target}");
        }
        for target in ["/%zz", "/%2", "/%", "/%ff%fe", "/%c0%ae%c0%ae/secret.txt"] {
            assert_eq!(http(target), Err(Refused::Encoding), "{target}");
        }
        for target in [
            "//server/share/file",
            "/%2f%2fserver/share",
            "/\\\\server\\share",
            "/%5c%5c%3f%5cC:%5cWindows",
            "/C:/Windows/win.ini",
            "/c:%5cwindows%5cwin.ini",
            "/%43:/x",
            "*",
            "http://example.com/x",
            "example.com:80",
        ] {
            assert!(
                matches!(
                    http(target),
                    Err(Refused::Absolute | Refused::Traversal | Refused::Stream)
                ),
                "{target}: {:?}",
                http(target)
            );
        }
    }

    #[test]
    fn every_traversal_form_is_refused_over_tftp() {
        for name in [
            &b".."[..],
            b"../secret.txt",
            b"a/../../secret.txt",
            b"..\\secret.txt",
            b"a\\b.txt",
            b"./a",
        ] {
            assert_eq!(tftp_path(name), Err(Refused::Traversal), "{name:?}");
        }
        for name in [
            &b"//server/share/f"[..],
            b"\\\\server\\share\\f",
            b"\\\\?\\C:\\Windows\\win.ini",
            b"\\\\.\\PhysicalDrive0",
            b"\\??\\C:\\x",
            b"C:\\Windows\\win.ini",
            b"C:/Windows/win.ini",
            b"c:win.ini",
            b"/C:/x",
            b"\\x",
        ] {
            assert_eq!(tftp_path(name), Err(Refused::Absolute), "{name:?}");
        }
        // TFTP names are taken as sent: no percent-decoding, so `%2e%2e` is a (missing) file of that name.
        assert_eq!(tftp_path(b"%2e%2e").unwrap().parts, ["%2e%2e"]);
        assert_eq!(tftp_path(&[0xff, 0xfe]), Err(Refused::Encoding));
        assert_eq!(tftp_path(b""), Err(Refused::Empty));
        assert_eq!(tftp_path(b"sub/"), Err(Refused::NotFound), "no folder names over TFTP");
    }

    #[test]
    fn devices_streams_and_odd_names_are_refused() {
        for (target, why) in [
            ("/NUL", Refused::Device),
            ("/nul.txt", Refused::Device),
            ("/a/CON", Refused::Device),
            ("/com1.bin", Refused::Device),
            ("/LPT9", Refused::Device),
            ("/conin$", Refused::Device),
            ("/file.txt:Zone.Identifier", Refused::Stream),
            ("/file.txt::$DATA", Refused::Stream),
            ("/file.txt%3a%24DATA", Refused::Stream),
            ("/secret.txt.", Refused::TrailingDotOrSpace),
            ("/secret.txt%20", Refused::TrailingDotOrSpace),
            ("/...", Refused::TrailingDotOrSpace),
            ("/a%00b", Refused::Character),
            ("/a%0d%0aSet-Cookie:x", Refused::Character),
            ("/a%e2%80%aeb", Refused::Character),
            ("/a%3c%3e", Refused::Character),
            ("/a*b", Refused::Character),
        ] {
            assert_eq!(http(target), Err(why), "{target}");
        }
        for name in [&b"NUL"[..], b"aux.cfg", b"f.txt:stream", b"f.txt.", b"f.txt "] {
            assert!(tftp_path(name).is_err(), "{name:?}");
        }
        let long = format!("/{}", "a".repeat(MAX_PART_CHARS + 1));
        assert_eq!(http(&long), Err(Refused::TooLong));
        let deep = "/a".repeat(MAX_PARTS + 1);
        assert_eq!(http(&deep), Err(Refused::TooLong));
        assert_eq!(http("/a//b"), Err(Refused::Absolute));
    }

    #[test]
    fn upload_names_are_one_clean_part() {
        assert_eq!(http_upload_name("/sw1-confg").unwrap(), "sw1-confg");
        assert_eq!(tftp_upload_name(b"sw1-confg").unwrap(), "sw1-confg");
        assert_eq!(tftp_upload_name(b"/sw1-confg").unwrap(), "sw1-confg");
        // A8: format characters become `_`, raw or encoded.
        assert_eq!(http_upload_name("/invoice%E2%80%AEfdp.exe").unwrap(), "invoice_fdp.exe");
        assert_eq!(
            tftp_upload_name("invoice\u{202E}fdp.exe".as_bytes()).unwrap(),
            "invoice_fdp.exe"
        );
        assert_eq!(tftp_upload_name("a\u{200B}b".as_bytes()).unwrap(), "a_b");
        for (target, why) in [
            ("/", Refused::Empty),
            ("/sub/x.bin", Refused::Subfolder),
            ("/sub/", Refused::NotFound),
            ("/../x.bin", Refused::Traversal),
            ("/%2e%2e%2fx.bin", Refused::Traversal),
            ("/x.bin:evil", Refused::Stream),
            ("/x.bin.", Refused::TrailingDotOrSpace),
            ("/NUL", Refused::Device),
            ("/a%0ab", Refused::Character),
        ] {
            assert_eq!(http_upload_name(target), Err(why), "{target}");
        }
        let long = format!("/{}", "a".repeat(MAX_UPLOAD_NAME_CHARS + 1));
        assert_eq!(http_upload_name(&long), Err(Refused::TooLong));
        assert_eq!(tftp_upload_name(b"..\\x"), Err(Refused::Traversal));
        assert_eq!(tftp_upload_name(b"C:\\x"), Err(Refused::Absolute));
    }

    #[test]
    fn files_explorer_acts_on_by_itself_are_never_uploaded() {
        for name in [
            "readme.url",
            "README.URL",
            "Report.lnk",
            "x.scf",
            "Docs.library-ms",
            "share.searchConnector-ms",
            "desktop.ini",
            "Desktop.INI",
            "autorun.inf",
            "a.website",
            "dark.theme",
            "s.settingcontent-ms",
        ] {
            assert_eq!(
                http_upload_name(&format!("/{}", percent_encode(name))),
                Err(Refused::ShellFile),
                "{name}"
            );
            assert_eq!(tftp_upload_name(name.as_bytes()), Err(Refused::ShellFile), "{name}");
        }
        // The same names are fine to serve, and look-alikes are fine to upload.
        assert!(http_path("/readme.url").is_ok());
        for name in ["url.txt", "readme.url.txt", "lnk", "desktop.ini.bak", "sw1-confg"] {
            assert!(tftp_upload_name(name.as_bytes()).is_ok(), "{name}");
        }
    }

    #[test]
    fn paths_are_encoded_again_for_links() {
        let path = http_path("/my%20images/caf%C3%A9%2Bv2.bin").unwrap();
        assert_eq!(path.encoded(), "/my%20images/caf%C3%A9%2Bv2.bin");
        assert_eq!(path.display(), "my images/café+v2.bin");
        let folder = http_path("/my%20images/").unwrap();
        assert_eq!(folder.encoded(), "/my%20images/");
        assert_eq!(percent_encode("a\"<b>\r\n"), "a%22%3Cb%3E%0D%0A");
    }

    #[cfg(windows)]
    #[test]
    fn under_the_root_is_by_component_without_case() {
        let root = Path::new(r"\\?\C:\Served");
        assert!(is_under(root, Path::new(r"\\?\C:\served\a.bin")));
        assert!(is_under(root, Path::new(r"\\?\c:\SERVED")));
        assert!(!is_under(root, Path::new(r"\\?\C:\Served2\a.bin")));
        assert!(!is_under(root, Path::new(r"\\?\C:\Other\a.bin")));
    }
}
