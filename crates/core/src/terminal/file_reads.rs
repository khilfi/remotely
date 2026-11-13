//! SS-14 (0.8.0 G3): the Files page's reads on a terminal's host: find files, a text preview of a small file, and a
//! file's SHA-256. Reads skip the command bus and aren't audited (`docs/plan-0.8.md`, "Approval tiers"; downloads stay
//! audited reads). They run on the terminal's own connection, as the login user or, with root browsing on, as root.
//!
//! * **Find** is `find` under a folder with a name pattern (`-name`, or `-iname` without letter case), on an exec
//!   channel. The folder and the pattern reach `/bin/sh` as printf octal escapes ([`printf_escaped`]), like G2's
//!   `cp -a` and `rm -rf`, so no login shell (fish, csh) parses them; the pattern is one name's glob, never a path. It
//!   stays on the folder's file system (`-xdev`: no `/proc` from `/`), stops after [`FIND_SECONDS`] (with `timeout`
//!   where the host has it, and a time limit here too) and keeps at most [`MAX_FIND_RESULTS`] hits of at most
//!   [`MAX_FIND_OUTPUT`] bytes (A9). A host whose `find` has no `-printf` (BusyBox) gives paths only.
//! * **Preview** reads at most [`MAX_PREVIEW_BYTES`] of a regular file over SFTP and gives it as text, never anything
//!   the window renders: a file with a NUL byte is binary and shows nothing; control characters show as Unicode's
//!   control pictures (␛ for ESC) and invisible formatting characters (Cf, such as U+202E) as `⟨U+202E⟩`, each counted.
//! * **Checksum** is the host's own `sha256sum` (the bytes never cross the network); where that fails, the file is
//!   read over SFTP and hashed here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::file_ops::check_path;
use super::Terminals;
use crate::adapters::remote::{printf_escaped, EntryKind, RemoteFiles};
use crate::error::{CoreError, Result};
use crate::untrusted::is_format_char;

/// Hits a find keeps.
pub const MAX_FIND_RESULTS: usize = 2000;
/// What `find` may print, at most.
pub const MAX_FIND_OUTPUT: usize = 2 * 1024 * 1024;
/// How long a find may run on the host.
pub const FIND_SECONDS: u64 = 55;
/// The most of a file a preview reads.
pub const MAX_PREVIEW_BYTES: usize = 256 * 1024;
/// A pattern's longest form.
const MAX_PATTERN: usize = 255;

/// What the Files page's find asks.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindRequest {
    /// The folder to look under, absolute.
    pub folder: String,
    /// One name's glob: `*.conf`, `access.log*`.
    pub pattern: String,
    /// `-iname`: without letter case.
    #[serde(default)]
    pub ignore_case: bool,
    #[serde(default)]
    pub as_root: bool,
}

/// One file or folder a find found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindHit {
    /// The path, absolute, as the host gave it (for opening its folder).
    pub path: String,
    /// The same with control and invisible formatting characters made visible, for showing.
    pub shown: String,
    /// `None` where the host's find gave paths only.
    pub kind: Option<EntryKind>,
    pub link: bool,
    pub size: Option<u64>,
    pub modified: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindResult {
    pub hits: Vec<FindHit>,
    /// More was found than is kept, or the host printed more than is read.
    pub more: bool,
    /// It stopped at its time limit; what it found by then is here.
    pub timed_out: bool,
    /// Folders under it the user (or root) couldn't read.
    pub unreadable: usize,
    /// The host's find gave no types, sizes or times (no `-printf`).
    pub paths_only: bool,
    pub as_root: bool,
}

/// A file's first bytes as text.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePreview {
    pub path: String,
    pub size: u64,
    /// `None`: binary (a NUL byte), so nothing is shown.
    pub text: Option<String>,
    /// Only the first [`MAX_PREVIEW_BYTES`] were read.
    pub truncated: bool,
    /// The bytes aren't UTF-8; what is shown is a best reading.
    pub not_utf8: bool,
    /// Control and invisible formatting characters shown as pictures or `⟨U+XXXX⟩`.
    pub marked: usize,
}

/// A file's SHA-256.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileChecksum {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// `host`: the host's `sha256sum`; `read`: read over SFTP and hashed on this PC.
    pub by: &'static str,
}

/// A find pattern the window sent: one name's glob, no `/`, no control or invisible formatting character.
pub fn check_pattern(pattern: &str) -> Result<()> {
    let invalid = |why: &str| {
        Err(CoreError::InvalidInput(format!(
            "That pattern can't be looked for: {why}."
        )))
    };
    if pattern.is_empty() {
        return invalid("it is empty");
    }
    if pattern.len() > MAX_PATTERN {
        return invalid("it is longer than a name");
    }
    if pattern.contains('/') {
        return invalid("it holds a /, and a pattern matches one name (look under another folder instead)");
    }
    if pattern
        .chars()
        .any(|c| c.is_control() || is_format_char(c) || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return invalid("it holds a control or invisible formatting character");
    }
    Ok(())
}

/// The find script: the folder, the pattern and the output format each from printf's octal escapes.
pub fn find_script(folder: &str, pattern: &str, ignore_case: bool, printf: bool) -> String {
    let name = if ignore_case { "-iname" } else { "-name" };
    let format = r"%y\t%s\t%T@\t%p\0";
    let out = if printf { "-printf \"$f\"" } else { "-print0" };
    let find = format!("find \"$p0\" -xdev {name} \"$p1\" {out}");
    // `exec` ends the script, so the second find runs only where the host has no `timeout`.
    format!(
        "p0=$(printf '{}'); p1=$(printf '{}'); f=$(printf '{}'); \
         command -v timeout >/dev/null 2>&1 && exec timeout {FIND_SECONDS} {find}; exec {find}",
        printf_escaped(folder),
        printf_escaped(pattern),
        printf_escaped(format),
    )
}

/// `text` for showing: C0 controls (but tab and line breaks) as control pictures, DEL as ␡, C1 controls, invisible
/// formatting characters and the line and paragraph separators as `⟨U+XXXX⟩`. Returns how many were marked.
pub fn mark_specials(text: &str, keep_breaks: bool) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut marked = 0;
    for c in text.chars() {
        match c {
            '\n' | '\t' if keep_breaks => out.push(c),
            '\r' if keep_breaks => {}
            c if (c as u32) < 0x20 => {
                marked += 1;
                out.push(char::from_u32(0x2400 + c as u32).unwrap_or('\u{FFFD}'));
            }
            '\u{7F}' => {
                marked += 1;
                out.push('\u{2421}');
            }
            c if c.is_control() || is_format_char(c) || matches!(c, '\u{2028}' | '\u{2029}') => {
                marked += 1;
                out.push_str(&format!("\u{27E8}U+{:04X}\u{27E9}", c as u32));
            }
            c => out.push(c),
        }
    }
    (out, marked)
}

/// Bytes as preview text: `None` for binary (a NUL byte). A character cut at the end of what was read is left off.
pub fn preview_text(bytes: &[u8]) -> (Option<String>, bool, usize) {
    if bytes.contains(&0) {
        return (None, false, 0);
    }
    let (text, not_utf8) = match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_owned(), false),
        // Only the read's end cut a character: what came before is UTF-8.
        Err(err) if err.error_len().is_none() => {
            (String::from_utf8_lossy(&bytes[..err.valid_up_to()]).into_owned(), false)
        }
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    };
    let (text, marked) = mark_specials(&text, true);
    (Some(text), not_utf8, marked)
}

/// One record of `-printf '%y\t%s\t%T@\t%p\0'`, or of `-print0` (a path).
fn parse_hit(record: &str, printf: bool) -> Option<FindHit> {
    let (kind, link, size, modified, path) = if printf {
        let mut parts = record.splitn(4, '\t');
        let (y, s, t, p) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        let kind = match y {
            "f" => EntryKind::File,
            "d" => EntryKind::Folder,
            _ => EntryKind::Other,
        };
        let modified = t.split('.').next().and_then(|secs| secs.parse::<u64>().ok());
        (Some(kind), y == "l", s.parse::<u64>().ok(), modified, p)
    } else {
        (None, false, None, None, record)
    };
    if !path.starts_with('/') {
        return None;
    }
    Some(FindHit {
        shown: mark_specials(path, false).0,
        path: path.to_owned(),
        kind,
        link,
        size,
        modified,
    })
}

/// A find's output as hits, at most [`MAX_FIND_RESULTS`]: whether more were found.
pub fn parse_find(stdout: &str, printf: bool) -> (Vec<FindHit>, bool) {
    let mut hits = Vec::new();
    let records: Vec<&str> = stdout.split('\0').filter(|r| !r.is_empty()).collect();
    let more = records.len() > MAX_FIND_RESULTS;
    for record in records.into_iter().take(MAX_FIND_RESULTS) {
        if let Some(hit) = parse_hit(record, printf) {
            hits.push(hit);
        }
    }
    (hits, more)
}

/// The SHA-256 in what `sha256sum` printed: its first 64 hex digits (a `\` in front for an escaped name).
pub fn parse_sha256sum(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?.trim_start_matches('\\');
    let hash: String = line.chars().take(64).collect();
    (hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())).then(|| hash.to_ascii_lowercase())
}

/// A file's SHA-256, read over SFTP.
pub(crate) async fn read_sha256(files: &dyn RemoteFiles, path: &str) -> Result<String> {
    let mut reader = files.read(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

impl Terminals {
    /// SS-14: files and folders under a folder whose names match a pattern (see the module's notes).
    pub async fn find(&self, id: Uuid, request: FindRequest) -> Result<FindResult> {
        check_path(&request.folder)?;
        check_pattern(&request.pattern)?;
        let (control, _) = self.files_for(id, request.as_root)?;
        let run = |printf: bool| {
            let script = find_script(&request.folder, &request.pattern, request.ignore_case, printf);
            let control = std::sync::Arc::clone(&control);
            async move {
                let limit = std::time::Duration::from_secs(FIND_SECONDS + 10);
                match tokio::time::timeout(
                    limit,
                    self.run_script(&control, &script, request.as_root, MAX_FIND_OUTPUT),
                )
                .await
                {
                    Ok(result) => result.map(Some),
                    Err(_) => Ok(None),
                }
            }
        };
        let mut printf = true;
        let mut result = run(true).await?;
        if let Some(done) = &result {
            // BusyBox's find has no -printf: paths only, then.
            if done.output.stdout.is_empty() && done.output.stderr.contains("printf") {
                printf = false;
                result = run(false).await?;
            }
        }
        let Some(done) = result else {
            return Ok(FindResult {
                hits: Vec::new(),
                more: false,
                timed_out: true,
                unreadable: 0,
                paths_only: !printf,
                as_root: request.as_root,
            });
        };
        let (hits, more) = parse_find(&done.output.stdout, printf);
        let unreadable = done
            .output
            .stderr
            .lines()
            .filter(|l| l.contains("Permission denied"))
            .count();
        // `timeout` ends with 124 when the time ran out.
        let timed_out = done.exit_code == Some(124);
        if hits.is_empty() && !timed_out && unreadable == 0 && done.exit_code.is_some_and(|c| c != 0) {
            let said: String = done
                .output
                .stderr
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("")
                .chars()
                .take(300)
                .collect();
            if !said.is_empty() {
                return Err(CoreError::InvalidInput(format!("find on the host said: {said}")));
            }
        }
        Ok(FindResult {
            hits,
            more: more || done.output.truncated,
            timed_out,
            unreadable,
            paths_only: !printf,
            as_root: request.as_root,
        })
    }

    /// SS-14: the first [`MAX_PREVIEW_BYTES`] of a regular file, as text (see the module's notes).
    pub async fn preview(&self, id: Uuid, path: &str, as_root: bool) -> Result<FilePreview> {
        check_path(path)?;
        let (_, files) = self.files_for(id, as_root)?;
        let entry = files
            .stat(path)
            .await?
            .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
        if entry.kind != EntryKind::File {
            return Err(CoreError::InvalidInput(format!(
                "{path} is not a regular file, so it has no preview."
            )));
        }
        let mut reader = files.read(path).await?;
        let mut bytes = Vec::with_capacity(entry.size.min(MAX_PREVIEW_BYTES as u64) as usize);
        let mut buf = vec![0u8; 64 * 1024];
        let mut truncated = false;
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let room = MAX_PREVIEW_BYTES - bytes.len();
            if n > room {
                bytes.extend_from_slice(&buf[..room]);
                truncated = true;
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            if bytes.len() == MAX_PREVIEW_BYTES {
                truncated = entry.size > MAX_PREVIEW_BYTES as u64;
                break;
            }
        }
        let (text, not_utf8, marked) = preview_text(&bytes);
        Ok(FilePreview {
            path: path.to_owned(),
            size: entry.size,
            text,
            truncated,
            not_utf8,
            marked,
        })
    }

    /// SS-14: a regular file's SHA-256: the host's `sha256sum`, else read over SFTP.
    pub async fn checksum(&self, id: Uuid, path: &str, as_root: bool) -> Result<FileChecksum> {
        check_path(path)?;
        let (control, files) = self.files_for(id, as_root)?;
        let entry = files
            .stat(path)
            .await?
            .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
        if entry.kind != EntryKind::File {
            return Err(CoreError::InvalidInput(format!(
                "{path} is not a regular file, so it has no checksum."
            )));
        }
        let script = crate::adapters::remote::paths_script("sha256sum", &[path]);
        if let Ok(done) = self.run_script(&control, &script, as_root, 4096).await {
            if done.exit_code == Some(0) {
                if let Some(sha256) = parse_sha256sum(&done.output.stdout) {
                    return Ok(FileChecksum {
                        path: path.to_owned(),
                        sha256,
                        size: entry.size,
                        by: "host",
                    });
                }
            }
        }
        let sha256 = read_sha256(files.as_ref(), path).await?;
        Ok(FileChecksum {
            path: path.to_owned(),
            sha256,
            size: entry.size,
            by: "read",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_are_one_name() {
        for ok in ["*.conf", "access.log*", "[Rr]eadme*", "nginx.conf", "a b?"] {
            assert!(check_pattern(ok).is_ok(), "{ok}");
        }
        for bad in ["", "etc/*.conf", "a\nb", "x\u{202E}", &"a".repeat(256)] {
            assert!(check_pattern(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_find_script_passes_folder_pattern_and_format_as_escapes() {
        let script = find_script("/srv/it's; rm -rf ~", "*.conf'; touch /tmp/p #", true, true);
        assert!(!script.contains("rm -rf"), "{script}");
        assert!(!script.contains("touch /tmp"), "{script}");
        assert!(!script.contains('\''.to_string().repeat(2).as_str()));
        assert!(script.contains("-iname \"$p1\" -printf \"$f\""), "{script}");
        assert!(script.contains("exec timeout 55 find \"$p0\" -xdev"), "{script}");
        // Every quoted printf argument holds only escapes and plain characters.
        for arg in script.split("printf '").skip(1) {
            let arg = arg.split('\'').next().unwrap();
            assert!(
                arg.chars().all(|c| c.is_ascii_alphanumeric() || "/._-\\".contains(c)),
                "{arg}"
            );
        }
        let plain = find_script("/srv", "*.log", false, false);
        assert!(plain.contains("-name \"$p1\" -print0"), "{plain}");
    }

    #[test]
    fn find_output_is_read_record_by_record() {
        let out = "f\t120\t1700000000.5\t/srv/a.conf\0d\t4096\t1700000001.0\t/srv/conf.d\0l\t9\t1700000002\t/srv/x\tlink.conf\0";
        let (hits, more) = parse_find(out, true);
        assert!(!more);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].kind, Some(EntryKind::File));
        assert_eq!(hits[0].size, Some(120));
        assert_eq!(hits[0].modified, Some(1_700_000_000));
        assert_eq!(hits[1].kind, Some(EntryKind::Folder));
        assert!(hits[2].link);
        assert_eq!(hits[2].path, "/srv/x\tlink.conf", "a tab in a name stays in the path");
        let (paths, _) = parse_find("/srv/a\0/srv/b\u{202E}c\0", false);
        assert_eq!(paths[1].shown, "/srv/b\u{27E8}U+202E\u{27E9}c");
        assert_eq!(paths[1].kind, None);
        let many: String = (0..=MAX_FIND_RESULTS).map(|n| format!("/srv/{n}\0")).collect();
        let (hits, more) = parse_find(&many, false);
        assert!(more);
        assert_eq!(hits.len(), MAX_FIND_RESULTS);
    }

    #[test]
    fn previews_are_text_with_specials_made_visible() {
        let (text, not_utf8, marked) = preview_text(b"server {\r\n\tlisten 80;\x1b[31m\n}\n");
        assert_eq!(text.unwrap(), "server {\n\tlisten 80;\u{241B}[31m\n}\n");
        assert!(!not_utf8);
        assert_eq!(marked, 1);
        assert_eq!(preview_text(b"\x7fELF\0\0").0, None, "a NUL byte is binary");
        let (text, _, marked) = preview_text("invoice\u{202E}fdp.exe".as_bytes());
        assert_eq!(text.unwrap(), "invoice\u{27E8}U+202E\u{27E9}fdp.exe");
        assert_eq!(marked, 1);
        // A character cut at the end of what was read is left off, and isn't "not UTF-8".
        let bytes = "é".as_bytes();
        let (text, not_utf8, _) = preview_text(&[b'a', bytes[0]]);
        assert_eq!(text.unwrap(), "a");
        assert!(!not_utf8);
        let (_, not_utf8, _) = preview_text(&[b'a', 0xff, b'b']);
        assert!(not_utf8);
    }

    #[test]
    fn sha256sum_lines_give_their_hash() {
        let hash = "a".repeat(64);
        assert_eq!(parse_sha256sum(&format!("{hash}  /srv/x\n")), Some(hash.clone()));
        assert_eq!(parse_sha256sum(&format!("\\{hash}  /srv/a\\nb\n")), Some(hash));
        assert_eq!(parse_sha256sum("sha256sum: /srv/x: No such file"), None);
    }
}
