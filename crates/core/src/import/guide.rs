//! QL-10: a short format guide and a sample file for each source the import reads from a file (CSV,
//! a PuTTY `.reg` export, a MobaXterm `.mxtsessions` export, an OpenSSH config).
//!
//! * The CSV guide is made from the parser's own tables ([`csv::COLUMNS`], [`csv::ENVIRONMENTS`],
//!   [`csv::AUTH_METHODS`], [`SessionColor::ALL`], the separators), so it lists exactly the columns,
//!   header names and values that are read. MobaXterm's fields and escapes come from its parser too.
//!   The PuTTY and OpenSSH guides name the values and keywords their parsers read; the sample test in
//!   `tests/import.rs` imports every sample through the real parser and checks the preview shows what
//!   the guides say.
//! * Samples hold reserved examples only (`example.com`, `example.org` and `.test` names,
//!   192.0.2.0/24-style addresses, users alice and bob) and no secret of any kind. The app saves them
//!   where the user picks in a save dialog (Documents by default), never in its own folders.

use serde::Serialize;

use super::{csv, mobaxterm, ImportSource};
use crate::sessions::SessionColor;

/// QL-10: what the import dialog shows for one format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatGuide {
    pub source: ImportSource,
    pub title: String,
    /// Paragraphs before the sections.
    pub intro: Vec<String>,
    pub sections: Vec<GuideSection>,
    /// The sample file's name, as the save dialog suggests it.
    pub sample_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuideSection {
    pub heading: String,
    pub text: Vec<String>,
    pub table: Option<GuideTable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuideTable {
    pub headings: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// QL-10: a sample file for one format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub file_name: &'static str,
    /// The save dialog's filter: its name and extension.
    pub filter: &'static str,
    pub extension: &'static str,
    pub text: String,
}

fn section(heading: &str, text: &[&str], table: Option<GuideTable>) -> GuideSection {
    GuideSection {
        heading: heading.to_owned(),
        text: text.iter().map(|t| (*t).to_owned()).collect(),
        table,
    }
}

fn table(headings: &[&str], rows: Vec<Vec<String>>) -> Option<GuideTable> {
    Some(GuideTable {
        headings: headings.iter().map(|h| (*h).to_owned()).collect(),
        rows,
    })
}

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|c| (*c).to_owned()).collect()
}

/// `; | or ,`: characters, which commas between them would only muddle.
fn char_list(chars: &[char]) -> String {
    match chars {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => {
            let rest: Vec<String> = rest.iter().map(char::to_string).collect();
            format!("{} or {last}", rest.join(" "))
        }
    }
}

/// QL-10: the format guide for `source`. PuTTY's registry and a PuTTY `.reg` export hold the same
/// values, so they share one.
pub fn guide(source: ImportSource) -> FormatGuide {
    let sample_name = sample(source).file_name.to_owned();
    let (title, intro, sections) = match source {
        ImportSource::Csv => csv_guide(),
        ImportSource::Putty | ImportSource::PuttyFile => putty_guide(),
        ImportSource::Mobaxterm => mobaxterm_guide(),
        ImportSource::Openssh => openssh_guide(),
    };
    FormatGuide {
        source,
        title: title.to_owned(),
        intro: intro.iter().map(|t| (*t).to_owned()).collect(),
        sections,
        sample_name,
    }
}

/// The values a CSV column takes, from the parser's tables.
fn csv_values(column: csv::Column) -> String {
    match column {
        csv::Column::Port => "1 to 65535".to_owned(),
        csv::Column::Environment => {
            let words: Vec<String> = csv::ENVIRONMENTS
                .iter()
                .map(|(_, words)| match words {
                    [one] => (*one).to_owned(),
                    [first, rest @ ..] => format!("{first} ({})", rest.join(", ")),
                    [] => String::new(),
                })
                .collect();
            words.join(", ")
        }
        csv::Column::Auth => {
            let names: Vec<&str> = csv::AUTH_METHODS.iter().map(|(_, name, _)| *name).collect();
            names.join(", ")
        }
        csv::Column::Color => {
            let names: Vec<&str> = SessionColor::ALL.iter().map(|c| c.as_str()).collect();
            names.join(", ")
        }
        csv::Column::Tags => format!("separated by {}", char_list(&csv::TAG_SEPARATORS)),
        csv::Column::Folder => format!("{} between folders", char_list(&csv::FOLDER_SEPARATORS)),
        _ => String::new(),
    }
}

fn csv_guide() -> (&'static str, &'static [&'static str], Vec<GuideSection>) {
    let columns = csv::COLUMNS
        .iter()
        .map(|spec| {
            vec![
                spec.headers[0].to_owned(),
                spec.headers[1..].join(", "),
                spec.holds.to_owned(),
                csv_values(spec.column),
            ]
        })
        .collect();
    let auth = csv::AUTH_METHODS
        .iter()
        .map(|(_, name, means)| row(&[name, means]))
        .collect();
    let passwords = format!(
        "A password column ({}) is never read: passwords are never imported. Other columns are left out, with a warning that names them.",
        csv::PASSWORD_HEADERS.join(", ")
    );
    let sections = vec![
        GuideSection {
            heading: "Columns".to_owned(),
            text: vec![
                "Only host is required. Header names are matched ignoring letter case, spaces, _ and -, so Key File and key_file are the same column.".to_owned(),
                passwords,
            ],
            table: table(&["Column", "Also accepted", "What it holds", "Values"], columns),
        },
        section("Logging in (the auth column)", &[], table(&["Value", "Logs in with"], auth)),
        section(
            "Folders, tags and jump hosts",
            &[
                "Folder: Customer A/Web is the folder Web inside Customer A, made if it is new, under the folder you import into.",
                "Tags: web;frontend gives the session two tags.",
                "Jump host: the name or host of another session, saved already or in the same file (that one is saved first). user@host:port matches by host, port and user.",
            ],
            None,
        ),
    ];
    (
        "CSV file",
        &["One session per row, below a header row. The delimiter is a comma, a semicolon or a tab, whichever the header row uses; quote a cell that holds one."],
        sections,
    )
}

fn putty_guide() -> (&'static str, &'static [&'static str], Vec<GuideSection>) {
    let values = vec![
        row(&["HostName", "The host; user@host gives the user too"]),
        row(&["PortNumber", "The port (a dword)"]),
        row(&[
            "Protocol",
            "Only ssh is imported; telnet, serial and the others are left out",
        ]),
        row(&["UserName", "The user"]),
        row(&["PublicKeyFile", "Despite the name, the private key (.ppk): key login"]),
        row(&["RemoteCommand", "The startup command, typed in the shell after login"]),
        row(&[
            "ProxyMethod 6 with ProxyHost, ProxyPort, ProxyUsername",
            "The jump host (PuTTY's \"SSH to proxy\"); other proxy types are not imported",
        ]),
    ];
    let sections = vec![
        section(
            "What is read",
            &["Each session is a key under HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions, named after the session with %20 for a space."],
            table(&["Value", "Becomes"], values),
        ),
        section(
            "Left out",
            &[
                "Default Settings is PuTTY's template, not a session. PuTTY has no folders and saves no passwords.",
                "Import the sample here, under \"PuTTY export from another computer\". Double-clicking it would add its sample sessions to PuTTY.",
            ],
            None,
        ),
    ];
    (
        "PuTTY sessions (.reg)",
        &["\"PuTTY on this computer\" reads PuTTY's sessions from the registry. For another computer's, export the key HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions there with regedit (File, Export) and choose that .reg file."],
        sections,
    )
}

fn mobaxterm_guide() -> (&'static str, &'static [&'static str], Vec<GuideSection>) {
    let fields = mobaxterm::FIELDS
        .iter()
        .map(|(at, holds)| vec![at.to_string(), (*holds).to_owned()])
        .collect();
    let escapes = mobaxterm::ESCAPES
        .iter()
        .map(|(escape, means)| row(&[escape, means]))
        .collect();
    let sections = vec![
        section(
            "Sections and folders",
            &[
                "Sessions are in [Bookmarks], [Bookmarks_1], [Bookmarks_2] and so on. Each section's SubRep= line is its folder: Customer A\\DB is the folder DB inside Customer A; empty is the top level.",
                "Every other line is one session: its name, =, then parts separated by #. The third part holds the connection settings, separated by %.",
            ],
            None,
        ),
        section(
            "Settings read (by position, from 0)",
            &[],
            table(&["Position", "Holds"], fields),
        ),
        section(
            "Escapes",
            &["MobaXterm writes these characters as codes, which the import turns back:"],
            table(&["Written", "Means"], escapes),
        ),
        section(
            "Left out",
            &["[Passwords] and [Credentials] hold saved passwords: they are never read."],
            None,
        ),
    ];
    (
        "MobaXterm sessions (.mxtsessions)",
        &["An export of MobaXterm's sessions: an INI file (MobaXterm.ini has the same sections). Only SSH sessions are imported, with their folders."],
        sections,
    )
}

fn openssh_guide() -> (&'static str, &'static [&'static str], Vec<GuideSection>) {
    let keywords = vec![
        row(&[
            "Host",
            "Each name without *, ? or ! is a session; names with them only carry settings",
        ]),
        row(&[
            "HostName",
            "The host (%h is the Host name); without it, the Host name itself",
        ]),
        row(&["User", "The user"]),
        row(&["Port", "The port"]),
        row(&[
            "IdentityFile",
            "Key login with the first one (~, %d, %u, %h and %r are filled in); without any, the SSH agent",
        ]),
        row(&["ProxyJump", "The jump host (the first hop)"]),
        row(&["RemoteCommand", "The startup command, typed in the shell after login"]),
        row(&["Include", "The included files are read too"]),
    ];
    let sections = vec![
        section(
            "Keywords read",
            &["A session's settings come from every block that applies to it, in file order: settings before the first Host, and Host blocks with wildcards that match its name. The first value of each setting wins, as in ssh."],
            table(&["Keyword", "Becomes"], keywords),
        ),
        section(
            "Left out",
            &["ProxyCommand, and Match blocks (they depend on what is only known when connecting): a note or warning says so."],
            None,
        ),
    ];
    (
        "OpenSSH config",
        &["The file ssh reads, ~/.ssh/config: \"OpenSSH config\" reads yours, and \"Choose another OpenSSH config file\" any other."],
        sections,
    )
}

/// QL-10: the sample file for `source` (PuTTY's registry and its `.reg` export share one).
pub fn sample(source: ImportSource) -> Sample {
    match source {
        ImportSource::Csv => Sample {
            file_name: "remotely-sample-sessions.csv",
            filter: "CSV",
            extension: "csv",
            text: csv_sample(),
        },
        ImportSource::Putty | ImportSource::PuttyFile => Sample {
            file_name: "remotely-sample-putty-sessions.reg",
            filter: "Registry export",
            extension: "reg",
            text: crlf(PUTTY_SAMPLE),
        },
        ImportSource::Mobaxterm => Sample {
            file_name: "remotely-sample-sessions.mxtsessions",
            filter: "MobaXterm sessions",
            extension: "mxtsessions",
            text: crlf(MOBAXTERM_SAMPLE),
        },
        ImportSource::Openssh => Sample {
            file_name: "remotely-sample-ssh-config",
            filter: "All files",
            extension: "*",
            text: OPENSSH_SAMPLE.to_owned(),
        },
    }
}

/// Windows line ends, as regedit, MobaXterm and spreadsheets write them.
fn crlf(text: &str) -> String {
    text.replace('\n', "\r\n")
}

/// The CSV sample: the header is every column the import reads, by its first name, in [`csv::COLUMNS`]
/// order; the rows fill them in that order.
fn csv_sample() -> String {
    let header: Vec<&str> = csv::COLUMNS.iter().map(|spec| spec.headers[0]).collect();
    let mut text = header.join(",");
    text.push('\n');
    text.push_str(CSV_ROWS);
    crlf(&text)
}

/// name, host, port, user, folder, tags, environment, auth, key_file, startup_command, color, jump_host.
const CSV_ROWS: &str = r#"web01,web01.example.com,,alice,Customer A/Web,web;frontend,prod,password,,,red,
db01,192.0.2.20,2222,bob,Customer A/DB,db|postgres,staging,key,C:\Users\alice\.ssh\id_ed25519,"cd /var/lib; ls",amber,bastion
bastion,bastion.example.org,,alice,Customer A,jump,prod,agent,,,slate,
lab01,alice@lab01.test:2200,,,Lab,lab,lab,,,,teal,
,198.51.100.7,,,,,,,,,,
"#;

const PUTTY_SAMPLE: &str = r#"Windows Registry Editor Version 5.00

; A Remotely sample: import it in Remotely (Import sessions, PuTTY export from another computer).
; Double-clicking it would add these sample sessions to PuTTY.

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"Protocol"="ssh"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web01]
"HostName"="web01.example.com"
"PortNumber"=dword:00000016
"Protocol"="ssh"
"UserName"="alice"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\db01%20(Customer%20A)]
"HostName"="bob@192.0.2.20"
"PortNumber"=dword:000008ae
"Protocol"="ssh"
"PublicKeyFile"="C:\\Users\\alice\\.ssh\\db01.ppk"
"RemoteCommand"="uptime"
"ProxyMethod"=dword:00000006
"ProxyHost"="bastion.example.org"
"ProxyPort"=dword:00000016
"ProxyUsername"="alice"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\bastion]
"HostName"="bastion.example.org"
"PortNumber"=dword:00000016
"Protocol"="ssh"
"UserName"="alice"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\switch01]
"HostName"="switch01.test"
"PortNumber"=dword:00000017
"Protocol"="telnet"
"#;

const MOBAXTERM_SAMPLE: &str = r#"[Bookmarks]
SubRep=
ImgNum=42
web01=#109#0%web01.example.com%22%alice%%-1%-1%%%22%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%1%-1%-1#0# #-1

[Bookmarks_1]
SubRep=Customer A
ImgNum=41
bastion=#109#0%bastion.example.org%22%alice%%-1%-1%%%22%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1

[Bookmarks_2]
SubRep=Customer A\DB
ImgNum=41
db01=#109#0%192.0.2.20%2222%bob%%-1%-1%sudo -i__PTVIRG__ uptime%bastion.example.org%22%alice%0%0%0%_ProfileDir_\.ssh\id_ed25519%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
rdp01=#91#4%198.51.100.30%3389%alice%0%-1%-1#MobaFont%10#0# #-1
"#;

const OPENSSH_SAMPLE: &str = "# A Remotely sample OpenSSH config. Every Host without wildcards becomes a session.

Host web01
    HostName web01.example.com

Host db01
    HostName 192.0.2.20
    Port 2222
    User bob
    ProxyJump bastion
    RemoteCommand uptime

Host bastion
    HostName bastion.example.org

Host lab01
    HostName lab01.test

# Wildcards: these settings apply to every host whose name matches; the first value wins.
Host web* db* bastion*
    IdentityFile ~/.ssh/id_ed25519

Host *
    User alice
";

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCES: [ImportSource; 5] = [
        ImportSource::Putty,
        ImportSource::PuttyFile,
        ImportSource::Mobaxterm,
        ImportSource::Openssh,
        ImportSource::Csv,
    ];

    #[test]
    fn the_csv_guide_lists_every_column_and_value_the_parser_reads() {
        let guide = guide(ImportSource::Csv);
        let columns = guide.sections[0].table.as_ref().unwrap();
        assert_eq!(columns.rows.len(), csv::COLUMNS.len());
        for (row, spec) in columns.rows.iter().zip(csv::COLUMNS) {
            assert_eq!(row[0], spec.headers[0]);
            for alias in &spec.headers[1..] {
                assert!(row[1].contains(alias), "{alias}");
            }
        }
        let text = serde_json::to_string(&guide).unwrap();
        for (_, words) in csv::ENVIRONMENTS {
            for word in *words {
                assert!(text.contains(word), "{word}");
            }
        }
        for (_, name, _) in csv::AUTH_METHODS {
            assert!(text.contains(name), "{name}");
        }
        for colour in SessionColor::ALL {
            assert!(text.contains(colour.as_str()), "{}", colour.as_str());
        }
        for header in csv::PASSWORD_HEADERS {
            assert!(text.contains(header), "{header}");
        }
        assert!(text.contains("separated by ; | or ,"), "{text}");
        assert!(text.contains(r"/ or \\ between folders"), "{text}");
    }

    #[test]
    fn the_mobaxterm_guide_lists_the_parsers_fields_and_escapes() {
        let guide = guide(ImportSource::Mobaxterm);
        let text = serde_json::to_string(&guide).unwrap();
        for (at, _) in mobaxterm::FIELDS {
            assert!(guide.sections[1]
                .table
                .as_ref()
                .unwrap()
                .rows
                .iter()
                .any(|r| r[0] == at.to_string()));
        }
        for (escape, _) in mobaxterm::ESCAPES {
            assert!(text.contains(escape), "{escape}");
        }
    }

    #[test]
    fn every_source_has_a_guide_and_a_sample_named_for_its_dialog() {
        for source in SOURCES {
            let guide = guide(source);
            let sample = sample(source);
            assert_eq!(guide.sample_name, sample.file_name);
            assert!(!guide.intro.is_empty() && !guide.sections.is_empty());
            if sample.extension != "*" {
                assert!(sample.file_name.ends_with(&format!(".{}", sample.extension)));
            }
            assert!(!sample.text.is_empty());
        }
    }

    /// Reserved examples only (CLAUDE.md, "Public repository rules"): example.com/.org and .test names,
    /// documentation addresses, users alice and bob, and no secret.
    #[test]
    fn samples_hold_reserved_examples_only() {
        let addresses = regex::Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\b").unwrap();
        let names = regex::Regex::new(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(com|org|net|io|local|lan|test)\b").unwrap();
        for source in SOURCES {
            let text = sample(source).text.to_lowercase();
            for caps in addresses.captures_iter(&text) {
                let net = format!("{}.{}.{}", &caps[1], &caps[2], &caps[3]);
                assert!(
                    ["192.0.2", "198.51.100", "203.0.113"].contains(&net.as_str()),
                    "{source:?}: {}",
                    &caps[0]
                );
            }
            for found in names.find_iter(&text) {
                let name = found.as_str();
                assert!(
                    name.ends_with(".example.com") || name.ends_with(".example.org") || name.ends_with(".test"),
                    "{source:?}: {name}"
                );
            }
            for word in ["password=", "pass=", "secret", "token", "begin openssh", "-----begin"] {
                assert!(!text.contains(word), "{source:?}: {word}");
            }
        }
    }
}
