//! MobaXterm sessions (SS-02), from a `.mxtsessions` export (an INI file; `MobaXterm.ini` has the same
//! sections).
//!
//! Sessions live in `[Bookmarks]`, `[Bookmarks_1]`, `[Bookmarks_2]`, ... Each section has
//! `SubRep=Folder\Sub` (its folder, empty at the top level) and `ImgNum=`; every other line is
//! `name=value`, one session. The value is split on `#`: segment 1 is the icon, segment 2 the
//! connection settings, split on `%`:
//!
//! ```text
//! [0] type (0 = SSH)   [1] host   [2] port   [3] user   [7] command to run after login
//! [8] SSH gateway host   [9] gateway port   [10] gateway user   [14] private key path
//! ```
//!
//! Only SSH sessions are imported. `[Passwords]` and `[Credentials]` hold saved passwords: their
//! values are never read, and a warning says they were not imported.

use std::path::Path;

use super::{finish, non_empty, parse_port, Candidate, CandidateAuth, Parsed, Skipped, DEFAULT_PORT};

/// MobaXterm's session type for SSH.
const SSH: &str = "0";

/// QL-10: where each setting is among a session line's `%`-separated connection settings, and what
/// the import makes of it (the format guide lists these).
pub(crate) const TYPE: usize = 0;
pub(crate) const HOST: usize = 1;
pub(crate) const PORT: usize = 2;
pub(crate) const USER: usize = 3;
pub(crate) const COMMAND: usize = 7;
pub(crate) const GATEWAY_HOST: usize = 8;
pub(crate) const GATEWAY_PORT: usize = 9;
pub(crate) const GATEWAY_USER: usize = 10;
pub(crate) const KEY_PATH: usize = 14;
pub(crate) const FIELDS: [(usize, &str); 9] = [
    (
        TYPE,
        "The session type: 0 is SSH; other types (RDP, Telnet, ...) are left out",
    ),
    (HOST, "The host"),
    (PORT, "The port (empty: 22)"),
    (USER, "The user"),
    (COMMAND, "The command run after login: the startup command"),
    (GATEWAY_HOST, "The SSH gateway: the jump host"),
    (GATEWAY_PORT, "The gateway's port"),
    (GATEWAY_USER, "The gateway's user"),
    (
        KEY_PATH,
        "The private key file: key login (_ProfileDir_, _CurrentDrive_ and _MyDocuments_ are filled in)",
    ),
];

/// QL-10: MobaXterm's escapes for characters that would break its `#` and `%` format, and what they
/// stand for.
pub(crate) const ESCAPES: [(&str, &str); 5] = [
    ("__DIEZE__", "#"),
    ("__PERCENT__", "%"),
    ("__PTVIRG__", ";"),
    ("__DBLQUO__", "\""),
    ("__PIPE__", "|"),
];

/// The sessions in a MobaXterm export. `home` is the Windows profile folder (`C:\Users\alice`), for
/// key paths that start with `_ProfileDir_`.
pub fn parse(text: &str, home: &Path) -> Parsed {
    let mut parsed = Parsed::default();
    let mut sections: Vec<Bookmarks> = Vec::new();
    let mut place = Place::Other;
    let mut saved_passwords = false;
    for line in text.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            place = match name.trim().to_ascii_lowercase().as_str() {
                "passwords" | "credentials" => Place::Secrets,
                n if is_bookmarks(n) => {
                    sections.push(Bookmarks::default());
                    Place::Bookmarks
                }
                _ => Place::Other,
            };
            continue;
        }
        match place {
            // Only that there is something; the values are never looked at.
            Place::Secrets => saved_passwords = true,
            Place::Bookmarks => {
                let (Some(section), Some((key, value))) = (sections.last_mut(), line.split_once('=')) else {
                    continue;
                };
                let key = key.trim();
                if key.eq_ignore_ascii_case("SubRep") {
                    section.folder = value.split('\\').map(str::to_owned).collect();
                } else if !key.eq_ignore_ascii_case("ImgNum") {
                    section.sessions.push((key.to_owned(), value.to_owned()));
                }
            }
            Place::Other => {}
        }
    }

    for section in &sections {
        for (name, value) in &section.sessions {
            parsed.push(session(name, value, &section.folder, home));
        }
    }
    if saved_passwords {
        parsed.warn("MobaXterm's saved passwords were not imported");
    }
    if parsed.is_empty() {
        parsed.warn("The file has no MobaXterm sessions ([Bookmarks] sections)");
    }
    parsed
}

enum Place {
    Bookmarks,
    Secrets,
    Other,
}

#[derive(Default)]
struct Bookmarks {
    /// SubRep, split on `\`. `finish` drops the empty parts.
    folder: Vec<String>,
    sessions: Vec<(String, String)>,
}

/// `bookmarks` or `bookmarks_<n>`, lower case.
fn is_bookmarks(section: &str) -> bool {
    match section.strip_prefix("bookmarks") {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('_')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
}

fn session(name: &str, value: &str, folder: &[String], home: &Path) -> Result<Candidate, Skipped> {
    let name = name.trim();
    let skip = |reason: String| Skipped::new(name, reason);
    let Some(connection) = value.split('#').nth(2) else {
        return Err(skip("not a MobaXterm session line".into()));
    };
    let fields: Vec<String> = connection.split('%').map(unescape).collect();
    let field = |i: usize| fields.get(i).map_or("", |f| f.trim());
    match field(TYPE) {
        SSH => {}
        "" => return Err(skip("not a MobaXterm session line".into())),
        other => return Err(skip(format!("not an SSH session (MobaXterm type {other})"))),
    }
    if field(HOST).is_empty() {
        return Err(skip("no host name".into()));
    }
    let port = match field(PORT) {
        "" => DEFAULT_PORT,
        port => parse_port(port).map_err(skip)?,
    };

    let mut c = Candidate::new(name, field(HOST));
    c.port = port;
    c.folder = folder.to_vec();
    c.username = non_empty(field(USER));
    c.startup_command = non_empty(field(COMMAND));
    if !field(GATEWAY_HOST).is_empty() {
        c.jump = Some(gateway(field(GATEWAY_USER), field(GATEWAY_HOST), field(GATEWAY_PORT)));
    }
    c.auth = match field(KEY_PATH) {
        "" => CandidateAuth::Password,
        path => CandidateAuth::KeyFile {
            path: expand_path(path, home),
        },
    };
    finish(c)
}

/// `user@host:port`, leaving out an empty user and port 22 (or a port that is not a number).
fn gateway(user: &str, host: &str, port: &str) -> String {
    let mut jump = String::new();
    if !user.is_empty() {
        jump.push_str(user);
        jump.push('@');
    }
    jump.push_str(host);
    if let Ok(port) = parse_port(port) {
        if port != DEFAULT_PORT {
            jump.push_str(&format!(":{port}"));
        }
    }
    jump
}

/// MobaXterm's escapes for characters that would break its `#` and `%` format.
fn unescape(field: &str) -> String {
    ESCAPES
        .iter()
        .fold(field.to_owned(), |text, (escape, means)| text.replace(escape, means))
}

/// Expands MobaXterm's path placeholders: `_ProfileDir_` (the profile folder), `_CurrentDrive_` (its
/// drive, e.g. `C:`; MobaXterm may write it as `_CurrentDrive_:`) and `_MyDocuments_`.
fn expand_path(path: &str, home: &Path) -> String {
    let home = home.to_string_lossy();
    let home = home.trim_end_matches(['\\', '/']);
    let drive = match home.as_bytes() {
        [letter, b':', ..] if letter.is_ascii_alphabetic() => home.get(..2).unwrap_or("C:"),
        _ => "C:",
    };
    path.replace("_ProfileDir_", home)
        .replace("_CurrentDrive_:", drive)
        .replace("_CurrentDrive_", drive)
        .replace("_MyDocuments_", &format!("{home}\\Documents"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> &'static Path {
        Path::new(r"C:\Users\alice")
    }

    const EXPORT: &str = r"[Bookmarks]
SubRep=
ImgNum=42
web01=#109#0%web01.example.com%22%alice%%-1%-1%%%22%%0%0%0%_ProfileDir_\.ssh\id_ed25519%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%1%-1%-1#0# #-1

[Bookmarks_1]
SubRep=Customer A\Lab
ImgNum=41
db01= #109#0%192.0.2.30%2222%bob%%-1%-1%sudo -i__PTVIRG__ uptime%bastion.example.org%2200%alice%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
rdp01= #91#4%192.0.2.40%3389%alice%0%-1%-1#MobaFont%10#0# #-1
gw01=#109#0%192.0.2.50%%%%-1%-1%%bastion.example.org%22%%0%0%0%_CurrentDrive_:\keys\id_rsa%%-1#MobaFont#0# #-1

[Bookmarks_2]
ImgNum=41
SubRep=Customer B
odd=just text
short=#109#
noport=#109#0%192.0.2.60%ssh%alice#MobaFont#0# #-1
nohost=#109#0%%22%alice#MobaFont#0# #-1

[Misc]
web99=#109#0%web99.example.com%22%alice#MobaFont#0# #-1
";

    #[test]
    fn an_export_with_folders() {
        let parsed = parse(EXPORT, home());
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let names: Vec<_> = parsed.candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["web01", "db01", "gw01"]);

        let web = &parsed.candidates[0];
        assert_eq!(web.host, "web01.example.com");
        assert_eq!(web.port, 22);
        assert_eq!(web.username.as_deref(), Some("alice"));
        assert!(web.folder.is_empty());
        assert_eq!(
            web.auth,
            CandidateAuth::KeyFile {
                path: r"C:\Users\alice\.ssh\id_ed25519".into()
            }
        );
        assert_eq!(web.jump, None);
        assert_eq!(web.startup_command, None);

        let db = &parsed.candidates[1];
        assert_eq!((db.host.as_str(), db.port), ("192.0.2.30", 2222));
        assert_eq!(db.username.as_deref(), Some("bob"));
        assert_eq!(db.folder, ["Customer A", "Lab"]);
        assert_eq!(db.auth, CandidateAuth::Password);
        assert_eq!(db.startup_command.as_deref(), Some("sudo -i; uptime"));
        assert_eq!(db.jump.as_deref(), Some("alice@bastion.example.org:2200"));

        let gw = &parsed.candidates[2];
        assert_eq!(gw.port, 22);
        assert_eq!(gw.username, None);
        assert_eq!(gw.jump.as_deref(), Some("bastion.example.org"));
        assert_eq!(
            gw.auth,
            CandidateAuth::KeyFile {
                path: r"C:\keys\id_rsa".into()
            }
        );
    }

    #[test]
    fn other_types_and_odd_lines_are_skipped_with_a_reason() {
        let parsed = parse(EXPORT, home());
        let skipped: Vec<_> = parsed
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            skipped,
            [
                ("rdp01", "not an SSH session (MobaXterm type 4)"),
                ("odd", "not a MobaXterm session line"),
                ("short", "not a MobaXterm session line"),
                ("noport", "port ssh is not valid"),
                ("nohost", "no host name"),
            ]
        );
    }

    #[test]
    fn saved_passwords_are_never_imported() {
        let text = "[Bookmarks]\nSubRep=\nweb01=#109#0%web01.example.com%22%alice#MobaFont#0# #-1\n\n[Passwords]\nssh22:alice@web01.example.com=_not_a_real_value_\n\n[Credentials]\nlab=alice:_not_a_real_value_\n";
        let parsed = parse(text, home());
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(parsed.candidates[0].auth, CandidateAuth::Password);
        assert_eq!(parsed.warnings, ["MobaXterm's saved passwords were not imported"]);
        let json = serde_json::to_string(&parsed).unwrap();
        assert!(!json.contains("_not_a_real_value_"));

        // Empty password sections say nothing.
        let empty = parse("[Bookmarks]\nweb01=#109#0%web01.example.com#\n[Passwords]\n", home());
        assert!(empty.warnings.is_empty(), "{:?}", empty.warnings);
    }

    #[test]
    fn placeholders_in_key_paths_are_expanded() {
        assert_eq!(
            expand_path(r"_MyDocuments_\keys\id_ed25519", home()),
            r"C:\Users\alice\Documents\keys\id_ed25519"
        );
        assert_eq!(
            expand_path(r"_CurrentDrive_\keys\id_ed25519", Path::new(r"D:\Users\alice\")),
            r"D:\keys\id_ed25519"
        );
        assert_eq!(
            expand_path(r"_CurrentDrive_:\keys\id_ed25519", Path::new("/home/alice")),
            r"C:\keys\id_ed25519"
        );
        assert_eq!(expand_path(r"E:\keys\id_ed25519", home()), r"E:\keys\id_ed25519");
    }

    #[test]
    fn section_names_and_empty_files() {
        assert!(is_bookmarks("bookmarks"));
        assert!(is_bookmarks("bookmarks_12"));
        assert!(!is_bookmarks("bookmarks_"));
        assert!(!is_bookmarks("bookmarksx"));
        assert!(!is_bookmarks("bookmarks_1a"));
        let empty = parse("", home());
        assert!(empty.is_empty());
        assert_eq!(empty.warnings.len(), 1);
        // A session line with an `=` in its command keeps the whole value.
        let eq = parse(
            "[Bookmarks]\nweb01=#109#0%web01.example.com%22%alice%%-1%-1%export A=1\n",
            home(),
        );
        assert_eq!(eq.candidates[0].startup_command.as_deref(), Some("export A=1"));
    }
}
