//! Session-list import (SS-02): parsers that turn another tool's saved sessions into [`Candidate`]s.
//!
//! Sources: PuTTY (the live registry or a regedit `.reg` export), MobaXterm (a `.mxtsessions`
//! export), OpenSSH (`~/.ssh/config`) and CSV. Each parser is a pure function from text (or registry
//! values) to a [`Parsed`]: the candidates, the entries it left out and why, and source-wide warnings.
//! The parsers touch neither the library, the vault nor the audit log; [`Importer`] checks their
//! candidates against the library (a preview with duplicates and name conflicts) and saves the rows
//! the user picks.
//!
//! Passwords are never imported, even where the source stores them (MobaXterm's `[Passwords]`, a CSV
//! password column). The parsers do not read those values; a warning says they were left out.
//!
//! Every candidate passes [`finish`], which applies the library's rules for names and hosts (see
//! `sessions::tidy`), so the preview shows what would really be saved.

pub mod csv;
mod importer;
pub mod mobaxterm;
pub mod openssh;
pub mod putty;
pub mod text;

use std::collections::HashSet;

use serde::Serialize;

use crate::domain::Environment;
use crate::sessions::{
    SessionColor, MAX_FOLDER_NAME, MAX_HOST_LEN, MAX_SESSION_NAME, MAX_STARTUP_COMMAND, MAX_TAGS, MAX_USERNAME_LEN,
};
use crate::store::MAX_TAG_LEN;

pub use importer::{
    default_openssh_config, home_dir, ImportPreview, ImportReport, ImportRequest, ImportSource, Importer, KeyFile,
    PreviewRow, RowStatus, MAX_SOURCE_BYTES,
};

/// SSH's port, used when the source gives none.
pub const DEFAULT_PORT: u16 = 22;

/// One session found in an import source, before it is checked against the library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    /// Trimmed; empty -> the host.
    pub name: String,
    /// Trimmed, no user@ and no :port.
    pub host: String,
    /// Default 22.
    pub port: u16,
    pub username: Option<String>,
    /// Folder path inside the source, outermost first (MobaXterm SubRep, CSV folder column). Empty: top level.
    pub folder: Vec<String>,
    pub auth: CandidateAuth,
    pub startup_command: Option<String>,
    /// Raw jump host / gateway text as the source gives it (e.g. "bastion", "bob@bastion.example.org:2222").
    /// Jump hosts are v2 (SS-07); the commit step decides what to do with it.
    pub jump: Option<String>,
    pub environment: Environment,
    pub color: Option<SessionColor>,
    pub tags: Vec<String>,
    /// What the import left out or changed, shown in the preview, e.g. "the proxy setting was not imported".
    pub notes: Vec<String>,
}

impl Candidate {
    /// A candidate with the defaults: port 22, password asked when connecting, top level, no label.
    pub fn new(name: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port: DEFAULT_PORT,
            username: None,
            folder: Vec::new(),
            auth: CandidateAuth::Password,
            startup_command: None,
            jump: None,
            environment: Environment::None,
            color: None,
            tags: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// How an imported session logs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "method", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum CandidateAuth {
    /// Password, asked when connecting. Stored passwords are NEVER imported.
    Password,
    /// A private key file on this computer, path already expanded (no ~, no %d, no _ProfileDir_).
    KeyFile {
        path: String,
    },
    Agent,
}

/// An entry the source has that is not imported, and why ("telnet session", "no host name").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

impl Skipped {
    pub fn new(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            reason: reason.into(),
        }
    }
}

/// What a parser found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Parsed {
    pub candidates: Vec<Candidate>,
    pub skipped: Vec<Skipped>,
    /// Source-wide remarks, e.g. "MobaXterm's saved passwords were not imported".
    pub warnings: Vec<String>,
}

impl Parsed {
    /// Adds a parser's verdict on one entry.
    pub fn push(&mut self, entry: Result<Candidate, Skipped>) {
        match entry {
            Ok(candidate) => self.candidates.push(candidate),
            Err(skipped) => self.skipped.push(skipped),
        }
    }

    /// Adds a warning once.
    pub fn warn(&mut self, warning: impl Into<String>) {
        let warning = warning.into();
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    /// Nothing found at all, not even a skipped entry.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty() && self.skipped.is_empty()
    }
}

/// Applies the library's rules to a candidate, the way `sessions::tidy` checks the editor's input:
/// trims every field, drops control characters from names, names it after its host when it has no
/// name and shortens what is too long (with a note). A candidate the library could not save at all
/// (no host, or a host with spaces, `@` or other characters a host can't have) is skipped instead.
pub fn finish(mut c: Candidate) -> Result<Candidate, Skipped> {
    c.host = c.host.trim().to_owned();
    c.name = clean(&c.name);
    let label = if !c.name.is_empty() {
        shorten(&c.name, MAX_SESSION_NAME)
    } else if !c.host.is_empty() {
        shorten(&c.host, MAX_SESSION_NAME)
    } else {
        "(no name)".to_owned()
    };
    let skip = |reason: String| Err(Skipped::new(label.clone(), reason));

    if c.host.is_empty() {
        return skip("no host name".into());
    }
    if c.host.chars().any(char::is_whitespace) {
        return skip("the host name has spaces in it".into());
    }
    if c.host.contains('@') {
        return skip("the host name has an @ in it".into());
    }
    let host_ok = c
        .host
        .chars()
        .all(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':' | '%' | '[' | ']'));
    if !host_ok {
        return skip(format!(
            "the host name {} has characters a host name can't have",
            c.host
        ));
    }
    if c.host.chars().count() > MAX_HOST_LEN {
        return skip(format!("the host name is longer than {MAX_HOST_LEN} characters"));
    }
    if c.port == 0 {
        return skip("port 0 is not valid".into());
    }

    if c.name.is_empty() {
        c.name = c.host.clone();
    }
    if c.name.chars().count() > MAX_SESSION_NAME {
        c.name = shorten(&c.name, MAX_SESSION_NAME);
        c.notes
            .push(format!("the name was shortened to {MAX_SESSION_NAME} characters"));
    }

    c.username = c.username.map(|u| clean(&u)).filter(|u| !u.is_empty());
    if c.username
        .as_ref()
        .is_some_and(|u| u.chars().count() > MAX_USERNAME_LEN)
    {
        c.username = None;
        c.notes.push(format!(
            "the user name was not imported: it is longer than {MAX_USERNAME_LEN} characters"
        ));
    }

    // Windows line ends in a multi-line command; other control characters are refused, as in the editor.
    c.startup_command = c
        .startup_command
        .map(|cmd| cmd.replace('\r', "").trim().to_owned())
        .filter(|cmd| !cmd.is_empty());
    if let Some(cmd) = &c.startup_command {
        let problem = if cmd.chars().count() > MAX_STARTUP_COMMAND {
            Some(format!("it is longer than {MAX_STARTUP_COMMAND} characters"))
        } else if cmd.chars().any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t')) {
            Some("it has control characters in it".to_owned())
        } else {
            None
        };
        if let Some(problem) = problem {
            c.startup_command = None;
            c.notes.push(format!("the startup command was not imported: {problem}"));
        }
    }

    let mut folder = Vec::with_capacity(c.folder.len());
    for part in &c.folder {
        let part = clean(part);
        if part.is_empty() {
            continue;
        }
        if part.chars().count() > MAX_FOLDER_NAME {
            c.notes.push(format!(
                "the folder name {part} was shortened to {MAX_FOLDER_NAME} characters"
            ));
            folder.push(shorten(&part, MAX_FOLDER_NAME));
        } else {
            folder.push(part);
        }
    }
    c.folder = folder;

    let mut seen = HashSet::new();
    let mut tags = Vec::new();
    for tag in &c.tags {
        let mut tag = clean(tag);
        if tag.chars().count() > MAX_TAG_LEN {
            c.notes
                .push(format!("the tag {tag} was shortened to {MAX_TAG_LEN} characters"));
            tag = shorten(&tag, MAX_TAG_LEN);
        }
        if !tag.is_empty() && seen.insert(tag.to_lowercase()) {
            tags.push(tag);
        }
    }
    if tags.len() > MAX_TAGS {
        c.notes.push(format!(
            "only the first {MAX_TAGS} of {} tags were imported",
            tags.len()
        ));
        tags.truncate(MAX_TAGS);
    }
    c.tags = tags;

    c.jump = c.jump.map(|j| clean(&j)).filter(|j| !j.is_empty());
    if let CandidateAuth::KeyFile { path } = &c.auth {
        let path = path.trim();
        c.auth = if path.is_empty() {
            CandidateAuth::Password
        } else {
            CandidateAuth::KeyFile { path: path.to_owned() }
        };
    }
    Ok(c)
}

/// Without control characters, trimmed.
fn clean(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The first `max` characters.
fn shorten(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// A trimmed value, `None` when empty.
fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// A host as several sources write it, split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
    pub user: Option<String>,
    pub host: String,
    /// As written, so the caller can report one that is not a number.
    pub port: Option<String>,
}

/// Splits `user@host`, `host:port`, `[2001:db8::1]:port` and plain hosts. The user is everything
/// before the last `@`. A bare IPv6 address (more than one `:`) has no port; brackets are removed.
pub(crate) fn split_address(text: &str) -> Address {
    let text = text.trim();
    let (user, rest) = match text.rsplit_once('@') {
        Some((user, host)) => (non_empty(user), host.trim()),
        None => (None, text),
    };
    if let Some(inner) = rest.strip_prefix('[') {
        if let Some((host, after)) = inner.split_once(']') {
            return Address {
                user,
                host: host.trim().to_owned(),
                port: after.strip_prefix(':').and_then(non_empty),
            };
        }
    }
    match rest.split_once(':') {
        Some((host, port)) if !port.contains(':') => Address {
            user,
            host: host.trim().to_owned(),
            port: non_empty(port),
        },
        _ => Address {
            user,
            host: rest.to_owned(),
            port: None,
        },
    }
}

/// A port number from text; the error is the reason to skip the entry.
pub(crate) fn parse_port(text: &str) -> Result<u16, String> {
    let text = text.trim();
    match text.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(format!("port {text} is not valid")),
    }
}

/// `n entry` or `n entries`-style counts for notes.
fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_trims_and_names_after_the_host() {
        let mut c = Candidate::new("  \tweb\u{7}01 ", " web01.example.com ");
        c.username = Some("  ".into());
        c.startup_command = Some(" cd /srv\r\nls \r\n".into());
        c.folder = vec![" Customer A ".into(), "".into(), " Lab".into()];
        c.tags = vec![" web ".into(), "WEB".into(), "".into(), "lab".into()];
        c.jump = Some("  ".into());
        let c = finish(c).unwrap();
        assert_eq!(c.name, "web01");
        assert_eq!(c.host, "web01.example.com");
        assert_eq!(c.username, None);
        assert_eq!(c.startup_command.as_deref(), Some("cd /srv\nls"));
        assert_eq!(c.folder, ["Customer A", "Lab"]);
        assert_eq!(c.tags, ["web", "lab"]);
        assert_eq!(c.jump, None);
        assert!(c.notes.is_empty());

        let unnamed = finish(Candidate::new("", "192.0.2.10")).unwrap();
        assert_eq!(unnamed.name, "192.0.2.10");
    }

    #[test]
    fn finish_skips_hosts_the_library_refuses() {
        let reason = |host: &str| finish(Candidate::new("web01", host)).unwrap_err().reason;
        assert_eq!(reason("  "), "no host name");
        assert_eq!(reason("web 01.example.com"), "the host name has spaces in it");
        assert_eq!(reason("alice@web01.example.com"), "the host name has an @ in it");
        assert!(reason("web01;rm").contains("characters a host name can't have"));
        assert!(reason(&"a".repeat(MAX_HOST_LEN + 1)).contains("longer than"));
        let skipped = finish(Candidate::new("", "web 01")).unwrap_err();
        assert_eq!(skipped.name, "web 01");
        let mut zero = Candidate::new("web01", "web01.example.com");
        zero.port = 0;
        assert_eq!(finish(zero).unwrap_err().reason, "port 0 is not valid");
        for ok in ["192.0.2.10", "2001:db8::1", "fe80::1%eth0", "db_1.test"] {
            assert!(finish(Candidate::new("", ok)).is_ok(), "{ok}");
        }
    }

    #[test]
    fn finish_shortens_long_values_with_a_note() {
        let mut c = Candidate::new("n".repeat(MAX_SESSION_NAME + 5), "web01.example.com");
        c.folder = vec!["f".repeat(MAX_FOLDER_NAME + 1)];
        c.tags = (0..=MAX_TAGS).map(|n| format!("t{n}")).collect();
        c.tags.push("x".repeat(MAX_TAG_LEN + 1));
        c.startup_command = Some("echo \u{1b}[31m".into());
        let c = finish(c).unwrap();
        assert_eq!(c.name.chars().count(), MAX_SESSION_NAME);
        assert_eq!(c.folder[0].chars().count(), MAX_FOLDER_NAME);
        assert_eq!(c.tags.len(), MAX_TAGS);
        assert_eq!(c.startup_command, None);
        assert_eq!(c.notes.len(), 5, "{:?}", c.notes);
    }

    #[test]
    fn finish_turns_an_empty_key_path_into_a_password() {
        let mut c = Candidate::new("web01", "web01.example.com");
        c.auth = CandidateAuth::KeyFile { path: "  ".into() };
        assert_eq!(finish(c).unwrap().auth, CandidateAuth::Password);
    }

    #[test]
    fn addresses_split_into_user_host_and_port() {
        let a = split_address(" alice@web01.example.com:2222 ");
        assert_eq!(a.user.as_deref(), Some("alice"));
        assert_eq!(a.host, "web01.example.com");
        assert_eq!(a.port.as_deref(), Some("2222"));
        let v6 = split_address("[2001:db8::1]:2200");
        assert_eq!((v6.host.as_str(), v6.port.as_deref()), ("2001:db8::1", Some("2200")));
        let bare = split_address("2001:db8::1");
        assert_eq!((bare.host.as_str(), bare.port), ("2001:db8::1", None));
        let plain = split_address("192.0.2.10");
        assert_eq!(
            (plain.user, plain.host.as_str(), plain.port),
            (None, "192.0.2.10", None)
        );
        let empty_user = split_address("@web01.example.com");
        assert_eq!(empty_user.user, None);
        assert_eq!(parse_port("2222"), Ok(2222));
        assert!(parse_port("0").is_err());
        assert!(parse_port("70000").is_err());
        assert!(parse_port("ssh").is_err());
    }

    #[test]
    fn candidates_serialize_for_the_preview() {
        let mut c = Candidate::new("web01", "web01.example.com");
        c.auth = CandidateAuth::KeyFile {
            path: r"C:\Users\alice\.ssh\id_ed25519".into(),
        };
        c.startup_command = Some("uptime".into());
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["auth"]["method"], "keyFile");
        assert_eq!(json["auth"]["path"], r"C:\Users\alice\.ssh\id_ed25519");
        assert_eq!(json["startupCommand"], "uptime");
        assert_eq!(json["environment"], "none");
        let agent = serde_json::to_value(CandidateAuth::Agent).unwrap();
        assert_eq!(agent, serde_json::json!({"method": "agent"}));
    }
}
