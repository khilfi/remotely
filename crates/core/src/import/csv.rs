//! CSV session lists (SS-02), e.g. exported from a spreadsheet or another tool.
//!
//! A header row is required; the delimiter (`,`, `;` or tab) is taken from it. Columns are matched
//! ignoring letter case, spaces, `_` and `-`:
//!
//! ```text
//! name | session | label                  host | hostname | address | ip   (required)
//! port                                    user | username | login
//! folder | group | path   ("A/B")         tags | tag   ("a;b", "a|b" or "a,b")
//! environment | env   (lab, staging, prod, none)
//! auth | authmethod | method   (password, key, agent)
//! key | keyfile | identityfile | privatekey   (path of a private key file)
//! startupcommand | command                color | colour                jump | jumphost | proxyjump
//! ```
//!
//! The host cell may be `user@host`, `host:port` or `[2001:db8::1]:port`; the user and port columns
//! win over those. A password column (password, pass, secret) is ignored: its cells are never read,
//! and a warning says passwords are never imported.

use ::csv::StringRecord;

use super::{finish, non_empty, parse_port, split_address, Candidate, CandidateAuth, Parsed, Skipped, DEFAULT_PORT};
use crate::domain::Environment;
use crate::sessions::SessionColor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Column {
    Name,
    Host,
    Port,
    User,
    Folder,
    Tags,
    Environment,
    Auth,
    Key,
    StartupCommand,
    Color,
    Jump,
    /// Never read: only noticed, to warn.
    Password,
}

fn column(header: &str) -> Option<Column> {
    let key = header
        .chars()
        .filter(|c| !matches!(c, ' ' | '_' | '-'))
        .collect::<String>()
        .to_lowercase();
    Some(match key.as_str() {
        "name" | "session" | "label" => Column::Name,
        "host" | "hostname" | "address" | "ip" => Column::Host,
        "port" => Column::Port,
        "user" | "username" | "login" => Column::User,
        "folder" | "group" | "path" => Column::Folder,
        "tags" | "tag" => Column::Tags,
        "environment" | "env" => Column::Environment,
        "auth" | "authmethod" | "method" => Column::Auth,
        "key" | "keyfile" | "identityfile" | "privatekey" => Column::Key,
        "startupcommand" | "command" => Column::StartupCommand,
        "color" | "colour" => Column::Color,
        "jump" | "jumphost" | "proxyjump" => Column::Jump,
        "password" | "pass" | "secret" => Column::Password,
        _ => return None,
    })
}

/// Which column of the file holds what. The password column is not in it, so it cannot be read.
struct Layout(Vec<(Column, usize)>);

impl Layout {
    fn has(&self, column: Column) -> bool {
        self.0.iter().any(|(c, _)| *c == column)
    }

    fn cell<'r>(&self, record: &'r StringRecord, column: Column) -> &'r str {
        self.0
            .iter()
            .find(|(c, _)| *c == column)
            .and_then(|(_, index)| record.get(*index))
            .map_or("", str::trim)
    }

    /// Every column the import reads is empty.
    fn is_blank(&self, record: &StringRecord) -> bool {
        self.0.iter().all(|(column, _)| self.cell(record, *column).is_empty())
    }
}

/// The sessions in a CSV file with a header row.
pub fn parse(text: &str) -> Parsed {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut parsed = Parsed::default();
    let Some(header) = text.lines().find(|line| !line.trim().is_empty()) else {
        parsed.warn("The file is empty");
        return parsed;
    };
    let mut reader = ::csv::ReaderBuilder::new()
        .delimiter(delimiter(header))
        .flexible(true)
        .trim(::csv::Trim::All)
        .from_reader(text.as_bytes());
    let headers = match reader.headers() {
        Ok(headers) => headers.clone(),
        Err(_) => {
            parsed.warn("The header row could not be read");
            return parsed;
        }
    };

    let mut layout = Layout(Vec::new());
    let mut password = false;
    let mut ignored = Vec::new();
    for (index, header) in headers.iter().enumerate() {
        let header = header.trim();
        if header.is_empty() {
            continue;
        }
        match column(header) {
            Some(Column::Password) => password = true,
            Some(c) if !layout.has(c) => layout.0.push((c, index)),
            // Unknown, or a second column for the same thing.
            _ => ignored.push(header.to_owned()),
        }
    }
    if password {
        parsed.warn("The password column was ignored: passwords are never imported");
    }
    if !ignored.is_empty() {
        parsed.warn(format!("These columns were not imported: {}", ignored.join(", ")));
    }
    if !layout.has(Column::Host) {
        parsed.warn("The file has no host column (host, hostname, address or ip)");
        return parsed;
    }

    for (n, record) in reader.records().enumerate() {
        // The line in the file, as a spreadsheet numbers it (the header is row 1).
        let fallback = n + 2;
        let line = |position: Option<&::csv::Position>| {
            position.map_or(fallback, |p| usize::try_from(p.line()).unwrap_or(fallback))
        };
        match record {
            Ok(record) if layout.is_blank(&record) => {}
            Ok(record) => {
                let row = line(record.position());
                parsed.push(row_candidate(&layout, &record, row));
            }
            Err(err) => {
                let row = line(err.position());
                parsed.push(Err(Skipped::new(
                    format!("row {row}"),
                    format!("row {row}: it could not be read"),
                )));
            }
        }
    }
    if parsed.is_empty() {
        parsed.warn("The file has no sessions below its header row");
    }
    parsed
}

/// `,`, `;` or tab, whichever the header row has most of outside quotes. A comma on a tie.
fn delimiter(header: &str) -> u8 {
    let (mut comma, mut semicolon, mut tab) = (0, 0, 0);
    let mut quoted = false;
    for c in header.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => comma += 1,
            ';' if !quoted => semicolon += 1,
            '\t' if !quoted => tab += 1,
            _ => {}
        }
    }
    if tab > comma && tab >= semicolon {
        b'\t'
    } else if semicolon > comma {
        b';'
    } else {
        b','
    }
}

fn row_candidate(layout: &Layout, record: &StringRecord, row: usize) -> Result<Candidate, Skipped> {
    let cell = |column| layout.cell(record, column);
    let name = cell(Column::Name);
    let label = if name.is_empty() {
        format!("row {row}")
    } else {
        name.to_owned()
    };
    let skip = |reason: String| Skipped::new(label.clone(), format!("row {row}: {reason}"));

    let address = split_address(cell(Column::Host));
    if address.host.is_empty() {
        return Err(skip("no host".into()));
    }
    let port = match non_empty(cell(Column::Port)).or(address.port) {
        Some(port) => parse_port(&port).map_err(skip)?,
        None => DEFAULT_PORT,
    };

    let mut c = Candidate::new(name, address.host);
    c.port = port;
    c.username = non_empty(cell(Column::User)).or(address.user);
    c.folder = cell(Column::Folder).split(['/', '\\']).map(str::to_owned).collect();
    c.tags = cell(Column::Tags).split([';', '|', ',']).map(str::to_owned).collect();
    c.environment = environment(cell(Column::Environment), &mut c.notes);
    c.auth = auth(cell(Column::Auth), cell(Column::Key), &mut c.notes);
    c.startup_command = non_empty(cell(Column::StartupCommand));
    c.color = color(cell(Column::Color), &mut c.notes);
    c.jump = non_empty(cell(Column::Jump));
    finish(c).map_err(|s| Skipped::new(s.name, format!("row {row}: {}", s.reason)))
}

fn environment(text: &str, notes: &mut Vec<String>) -> Environment {
    match text.to_lowercase().as_str() {
        "" | "none" => Environment::None,
        "lab" => Environment::Lab,
        "staging" | "stage" => Environment::Staging,
        "prod" | "production" => Environment::Prod,
        _ => {
            notes.push(format!(
                "the environment {text} is not lab, staging or prod, so none was set"
            ));
            Environment::None
        }
    }
}

/// The auth column decides; without one, a key file means key login and no key file a password.
fn auth(method: &str, key: &str, notes: &mut Vec<String>) -> CandidateAuth {
    let key_file = non_empty(key).map(|path| CandidateAuth::KeyFile { path });
    let unused_key = |notes: &mut Vec<String>, method: &str| {
        notes.push(format!(
            "the key file was not used, since the auth column says {method}"
        ));
    };
    match method.to_lowercase().as_str() {
        "" => key_file.unwrap_or(CandidateAuth::Password),
        "password" => {
            if key_file.is_some() {
                unused_key(notes, "password");
            }
            CandidateAuth::Password
        }
        "key" => key_file.unwrap_or_else(|| {
            notes.push("the auth column says key but no key file is given, so the password will be asked".into());
            CandidateAuth::Password
        }),
        "agent" => {
            if key_file.is_some() {
                unused_key(notes, "agent");
            }
            CandidateAuth::Agent
        }
        _ => {
            notes.push(format!("the auth method {method} is not password, key or agent"));
            key_file.unwrap_or(CandidateAuth::Password)
        }
    }
}

fn color(text: &str, notes: &mut Vec<String>) -> Option<SessionColor> {
    if text.is_empty() {
        return None;
    }
    let color = SessionColor::parse(&text.to_lowercase());
    if color.is_none() {
        let names: Vec<&str> = SessionColor::ALL.iter().map(|c| c.as_str()).collect();
        notes.push(format!(
            "the color {text} is not one of {}, so none was set",
            names.join(", ")
        ));
    }
    color
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comma_separated_list() {
        let parsed = parse(
            "Name,Host,Port,User,Folder,Tags,Environment,Auth,Key File,Startup Command,Color,Jump Host
web01,web01.example.com,,alice,Customer A/Lab,web;frontend,lab,,,,Blue,
db01,bob@192.0.2.30:2222,,,Customer A\\DB,db|prod,PROD,key,C:\\Users\\alice\\.ssh\\id_ed25519,\"cd /srv; ls\",green,bastion.example.org
,192.0.2.40,2200,bob,,,,agent,,,,
",
        );
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert!(parsed.skipped.is_empty(), "{:?}", parsed.skipped);
        assert_eq!(parsed.candidates.len(), 3);

        let web = &parsed.candidates[0];
        assert_eq!(
            (web.name.as_str(), web.host.as_str(), web.port),
            ("web01", "web01.example.com", 22)
        );
        assert_eq!(web.username.as_deref(), Some("alice"));
        assert_eq!(web.folder, ["Customer A", "Lab"]);
        assert_eq!(web.tags, ["web", "frontend"]);
        assert_eq!(web.environment, Environment::Lab);
        assert_eq!(web.auth, CandidateAuth::Password);
        assert_eq!(web.color, Some(SessionColor::Blue));
        assert!(web.notes.is_empty());

        let db = &parsed.candidates[1];
        assert_eq!((db.host.as_str(), db.port), ("192.0.2.30", 2222));
        assert_eq!(db.username.as_deref(), Some("bob"));
        assert_eq!(db.folder, ["Customer A", "DB"]);
        assert_eq!(db.tags, ["db", "prod"]);
        assert_eq!(db.environment, Environment::Prod);
        assert_eq!(
            db.auth,
            CandidateAuth::KeyFile {
                path: r"C:\Users\alice\.ssh\id_ed25519".into()
            }
        );
        assert_eq!(db.startup_command.as_deref(), Some("cd /srv; ls"));
        assert_eq!(db.color, Some(SessionColor::Green));
        assert_eq!(db.jump.as_deref(), Some("bastion.example.org"));

        let unnamed = &parsed.candidates[2];
        assert_eq!(unnamed.name, "192.0.2.40");
        assert_eq!(unnamed.port, 2200);
        assert_eq!(unnamed.username.as_deref(), Some("bob"));
        assert_eq!(unnamed.auth, CandidateAuth::Agent);
    }

    #[test]
    fn semicolons_and_quoting() {
        let parsed = parse("name;host;tags;command\n\"web;01\";web01.example.com;\"a;b\";\"echo \"\"hi\"\"\"\n");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let c = &parsed.candidates[0];
        assert_eq!(c.name, "web;01");
        assert_eq!(c.tags, ["a", "b"]);
        assert_eq!(c.startup_command.as_deref(), Some(r#"echo "hi""#));
    }

    #[test]
    fn tabs_ipv6_and_header_spelling() {
        let parsed = parse("\u{feff}Session\tIP_Address\tLog-In\n");
        // "IP_Address" is not a known column.
        assert!(parsed.candidates.is_empty());

        let parsed = parse("Session\tAddress\tLog-In\tuser name\nweb01\t[2001:db8::1]:2200\talice\tbob\n");
        assert_eq!(parsed.warnings, ["These columns were not imported: user name"]);
        let c = &parsed.candidates[0];
        assert_eq!((c.host.as_str(), c.port), ("2001:db8::1", 2200));
        assert_eq!(c.username.as_deref(), Some("alice"));
    }

    #[test]
    fn the_user_and_port_columns_win_over_the_host_cell() {
        let parsed = parse("host,user,port\nbob@web01.example.com:2222,alice,2200\n");
        let c = &parsed.candidates[0];
        assert_eq!((c.username.as_deref(), c.port), (Some("alice"), 2200));
    }

    #[test]
    fn passwords_are_never_read_and_unknown_columns_are_listed() {
        let parsed = parse("Host,Password,Notes,Owner\nweb01.example.com,_not_a_real_value_,first,alice\n");
        assert_eq!(
            parsed.warnings,
            [
                "The password column was ignored: passwords are never imported",
                "These columns were not imported: Notes, Owner"
            ]
        );
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(parsed.candidates[0].auth, CandidateAuth::Password);
        let json = serde_json::to_string(&parsed).unwrap();
        assert!(!json.contains("_not_a_real_value_"));
        // A row with nothing but a password is blank.
        let only = parse("host,secret\n,_not_a_real_value_\n");
        assert!(only.skipped.is_empty());
    }

    #[test]
    fn rows_without_a_host_and_other_bad_rows_are_skipped_by_row() {
        let parsed = parse(
            "name,host,port
web01,web01.example.com,22

,,
nohost,,22
badport,web02.example.com,99999
spaced,web 03.example.com,
,  ,
",
        );
        assert_eq!(parsed.candidates.len(), 1);
        let skipped: Vec<_> = parsed
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            skipped,
            [
                ("nohost", "row 5: no host"),
                ("badport", "row 6: port 99999 is not valid"),
                ("spaced", "row 7: the host name has spaces in it"),
            ]
        );
        let unnamed = parse("name,host,port\n,,22\n");
        assert_eq!(unnamed.skipped, [Skipped::new("row 2", "row 2: no host")]);
    }

    #[test]
    fn unknown_labels_become_notes() {
        let parsed = parse("host,env,color,auth\nweb01.example.com,qa,#ff0000,key\n");
        let c = &parsed.candidates[0];
        assert_eq!(c.environment, Environment::None);
        assert_eq!(c.color, None);
        assert_eq!(c.auth, CandidateAuth::Password);
        assert_eq!(c.notes.len(), 3, "{:?}", c.notes);

        let parsed = parse("host,method,identity_file\nweb01.example.com,agent,C:\\Users\\alice\\.ssh\\id_ed25519\n");
        assert_eq!(parsed.candidates[0].auth, CandidateAuth::Agent);
        assert_eq!(parsed.candidates[0].notes.len(), 1);
    }

    #[test]
    fn files_without_a_host_column_or_rows_warn() {
        let empty = parse("  \n");
        assert_eq!(empty.warnings, ["The file is empty"]);
        let no_host = parse("name,port\nweb01,22\n");
        assert!(no_host.is_empty());
        assert_eq!(
            no_host.warnings,
            ["The file has no host column (host, hostname, address or ip)"]
        );
        let header_only = parse("name,host\n");
        assert_eq!(header_only.warnings, ["The file has no sessions below its header row"]);
    }

    #[test]
    fn delimiters_come_from_the_header() {
        assert_eq!(delimiter("name,host"), b',');
        assert_eq!(delimiter("name;host;\"a,b\""), b';');
        assert_eq!(delimiter("name\thost"), b'\t');
        assert_eq!(delimiter("host"), b',');
        assert_eq!(delimiter("a,b;c"), b',');
    }
}
