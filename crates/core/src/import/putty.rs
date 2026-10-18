//! PuTTY sessions (SS-02), from the live registry or a regedit `.reg` export.
//!
//! PuTTY keeps each saved session under `HKCU\Software\SimonTatham\PuTTY\Sessions\<name>`, with the
//! name percent-encoded (`%20` is a space). Only SSH sessions are imported. PuTTY never stores
//! passwords; its proxy password is not read.

use super::text::utf8_or_ansi;
use super::{finish, split_address, Candidate, CandidateAuth, Parsed, Skipped};

/// PuTTY's template for new sessions. Not a session, so it is left out without a mention.
const DEFAULT_SETTINGS: &str = "Default Settings";
/// Where the sessions are, lower case, to find in a `.reg` key path.
const SESSIONS_PATH: &str = r"\software\simontatham\putty\sessions\";
/// PuTTY's proxy type "SSH to proxy and use port forwarding": a jump host.
const PROXY_SSH: u32 = 6;
#[cfg(windows)]
const NO_SESSIONS: &str = "PuTTY has no saved sessions for this Windows user";

/// The values of one session's registry key that the import reads. Missing or wrongly typed values
/// are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PuttyValues {
    /// `HostName`, possibly `user@host`.
    pub host_name: Option<String>,
    /// `PortNumber`.
    pub port: Option<u32>,
    /// `Protocol`: ssh, telnet, rlogin, raw, serial, ... Missing means ssh.
    pub protocol: Option<String>,
    /// `UserName`.
    pub user_name: Option<String>,
    /// `PublicKeyFile`: despite the name, the private key (.ppk).
    pub public_key_file: Option<String>,
    /// `RemoteCommand`.
    pub remote_command: Option<String>,
    /// `ProxyMethod`: 0 none, 1 SOCKS 4, 2 SOCKS 5, 3 HTTP, 4 Telnet, 5 local command, 6 SSH.
    pub proxy_method: Option<u32>,
    /// `ProxyHost`.
    pub proxy_host: Option<String>,
    /// `ProxyPort`.
    pub proxy_port: Option<u32>,
    /// `ProxyUsername`.
    pub proxy_username: Option<String>,
}

/// A session key name as PuTTY shows it: every `%XX` decoded (UTF-8, or the ANSI code page).
pub fn decode_key_name(key_name: &str) -> String {
    let bytes = key_name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(decoded) = hex {
                out.push(decoded);
                i += 3;
                continue;
            }
        }
        out.push(byte);
        i += 1;
    }
    utf8_or_ansi(&out)
}

/// One saved session. `key_name` is the registry key name, still percent-encoded.
pub fn candidate(key_name: &str, values: &PuttyValues) -> Result<Candidate, Skipped> {
    let name = decode_key_name(key_name);
    let skip = |reason: String| Skipped::new(name.clone(), reason);
    if name == DEFAULT_SETTINGS {
        return Err(skip("PuTTY's default settings, not a session".into()));
    }
    let protocol = value(&values.protocol).unwrap_or("ssh");
    if !protocol.eq_ignore_ascii_case("ssh") {
        return Err(skip(format!("{protocol} session: only SSH is imported")));
    }
    // PuTTY reads `user@host` in the host name (the last @) and that user wins over UserName. It
    // trims a `:port` off rather than using it.
    let address = split_address(value(&values.host_name).unwrap_or(""));
    if address.host.is_empty() {
        return Err(skip("no host name".into()));
    }
    let port = match values.port {
        None => super::DEFAULT_PORT,
        Some(port) => u16::try_from(port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| skip(format!("port {port} is not valid")))?,
    };

    let mut c = Candidate::new(name.clone(), address.host);
    c.port = port;
    c.username = address.user.or_else(|| value(&values.user_name).map(str::to_owned));
    c.auth = match value(&values.public_key_file) {
        Some(path) => CandidateAuth::KeyFile { path: path.to_owned() },
        None => CandidateAuth::Password,
    };
    if let Some(command) = value(&values.remote_command) {
        c.startup_command = Some(command.to_owned());
        c.notes.push(
            "PuTTY's remote command was imported as the startup command, which runs in the shell after login".into(),
        );
    }
    match values.proxy_method.unwrap_or(0) {
        0 => {}
        PROXY_SSH => match jump_host(values) {
            Some(jump) => c.jump = Some(jump),
            None => c
                .notes
                .push("PuTTY's SSH proxy has no host name, so it was not imported".into()),
        },
        _ => c.notes.push("PuTTY's proxy setting was not imported".into()),
    }
    finish(c)
}

/// `user@host:port` for an SSH proxy, leaving out an empty user and port 22. The host may also be
/// `user@host` or the name of another saved session; it is kept as PuTTY has it.
fn jump_host(values: &PuttyValues) -> Option<String> {
    let host = value(&values.proxy_host)?;
    let mut jump = String::new();
    if let Some(user) = value(&values.proxy_username).filter(|_| !host.contains('@')) {
        jump.push_str(user);
        jump.push('@');
    }
    jump.push_str(host);
    if let Some(port) = values
        .proxy_port
        .filter(|p| *p != 0 && *p != 22 && *p <= u32::from(u16::MAX))
    {
        jump.push_str(&format!(":{port}"));
    }
    Some(jump)
}

/// A trimmed value, `None` when missing or empty.
fn value(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// A regedit export (`Windows Registry Editor Version 5.00`). Only keys directly under
/// `...\SimonTatham\PuTTY\Sessions\` count, matched in any letter case; other keys (such as
/// `SshHostKeys`) and value types the import does not need (`hex:`, `hex(2):`) are ignored.
pub fn parse_reg(text: &str) -> Parsed {
    let mut sessions: Vec<(String, PuttyValues)> = Vec::new();
    let mut current: Option<usize> = None;
    for line in logical_lines(text) {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(path) = line.strip_prefix('[') {
            current = path.strip_suffix(']').and_then(session_key_name).map(|name| {
                // A key listed twice adds to the first one, as regedit would.
                match sessions.iter().position(|(n, _)| n.eq_ignore_ascii_case(name)) {
                    Some(index) => index,
                    None => {
                        sessions.push((name.to_owned(), PuttyValues::default()));
                        sessions.len() - 1
                    }
                }
            });
            continue;
        }
        let Some(values) = current.and_then(|index| sessions.get_mut(index)).map(|(_, v)| v) else {
            continue;
        };
        if let Some((name, data)) = value_line(line) {
            apply(values, &name, data);
        }
    }

    let mut parsed = Parsed::default();
    for (key_name, values) in &sessions {
        if decode_key_name(key_name) != DEFAULT_SETTINGS {
            parsed.push(candidate(key_name, values));
        }
    }
    if parsed.is_empty() {
        parsed.warn(
            r"The file has no PuTTY sessions. Export the key HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions with regedit.",
        );
    }
    parsed
}

/// The session's key name if `path` is a key directly under PuTTY's Sessions key. `[-...]` deletes a
/// key and does not count.
fn session_key_name(path: &str) -> Option<&str> {
    if path.starts_with('-') {
        return None;
    }
    // ASCII lower case keeps byte offsets, so the index applies to `path` too.
    let start = path.to_ascii_lowercase().find(SESSIONS_PATH)? + SESSIONS_PATH.len();
    let name = path.get(start..)?;
    (!name.is_empty() && !name.contains('\\')).then_some(name)
}

/// The lines of a `.reg` file, with `hex:` values that run over several lines (each ending in `\`)
/// joined into one.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for line in text.lines() {
        let end = line.trim_end();
        let continues = end.ends_with('\\') && (!pending.is_empty() || is_hex_value(end));
        pending.push_str(if pending.is_empty() { end } else { end.trim_start() });
        if continues {
            pending.pop();
        } else {
            lines.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        lines.push(pending);
    }
    lines
}

fn is_hex_value(line: &str) -> bool {
    line.to_ascii_lowercase().contains("\"=hex")
}

enum RegData {
    Text(String),
    Dword(u32),
    /// A type the import does not read, or a value it could not parse.
    Other,
}

/// `"Name"="text"`, `"Name"=dword:00000016` or another type.
fn value_line(line: &str) -> Option<(String, RegData)> {
    let (name, rest) = quoted(line.strip_prefix('"')?)?;
    let data = rest.trim_start().strip_prefix('=')?.trim_start();
    let data = if let Some(text) = data.strip_prefix('"') {
        quoted(text).map_or(RegData::Other, |(text, _)| RegData::Text(text))
    } else if let Some(hex) = data.strip_prefix("dword:") {
        u32::from_str_radix(hex.trim(), 16).map_or(RegData::Other, RegData::Dword)
    } else {
        RegData::Other
    };
    Some((name, data))
}

/// A string after its opening quote, with regedit's `\\` and `\"` escapes, and what follows it.
fn quoted(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, s.get(i + 1..).unwrap_or(""))),
            '\\' => match chars.next() {
                Some((_, escaped @ ('\\' | '"'))) => out.push(escaped),
                Some((_, other)) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            _ => out.push(c),
        }
    }
    None
}

fn apply(values: &mut PuttyValues, name: &str, data: RegData) {
    let (text, dword) = match data {
        RegData::Text(text) => (Some(text), None),
        RegData::Dword(dword) => (None, Some(dword)),
        RegData::Other => (None, None),
    };
    // Registry value names ignore letter case.
    match name.to_ascii_lowercase().as_str() {
        "hostname" => values.host_name = text,
        "portnumber" => values.port = dword,
        "protocol" => values.protocol = text,
        "username" => values.user_name = text,
        "publickeyfile" => values.public_key_file = text,
        "remotecommand" => values.remote_command = text,
        "proxymethod" => values.proxy_method = dword,
        "proxyhost" => values.proxy_host = text,
        "proxyport" => values.proxy_port = dword,
        "proxyusername" => values.proxy_username = text,
        _ => {}
    }
}

/// The current Windows user's saved sessions, from the registry. No Sessions key is not an error:
/// the result is empty, with a warning.
#[cfg(windows)]
pub fn read_registry() -> std::io::Result<Parsed> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let mut parsed = Parsed::default();
    let sessions = match RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\SimonTatham\PuTTY\Sessions") {
        Ok(key) => key,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            parsed.warn(NO_SESSIONS);
            return Ok(parsed);
        }
        Err(err) => return Err(err),
    };
    for key_name in sessions.enum_keys() {
        let Ok(key_name) = key_name else {
            parsed.warn("A PuTTY session whose name could not be read was left out");
            continue;
        };
        if decode_key_name(&key_name) == DEFAULT_SETTINGS {
            continue;
        }
        let Ok(key) = sessions.open_subkey(&key_name) else {
            parsed.push(Err(Skipped::new(
                decode_key_name(&key_name),
                "its settings could not be read from the registry",
            )));
            continue;
        };
        let text = |name: &str| key.get_value::<String, _>(name).ok();
        let dword = |name: &str| key.get_value::<u32, _>(name).ok();
        let values = PuttyValues {
            host_name: text("HostName"),
            port: dword("PortNumber"),
            protocol: text("Protocol"),
            user_name: text("UserName"),
            public_key_file: text("PublicKeyFile"),
            remote_command: text("RemoteCommand"),
            proxy_method: dword("ProxyMethod"),
            proxy_host: text("ProxyHost"),
            proxy_port: dword("ProxyPort"),
            proxy_username: text("ProxyUsername"),
        };
        parsed.push(candidate(&key_name, &values));
    }
    if parsed.is_empty() {
        parsed.warn(NO_SESSIONS);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(host: &str) -> PuttyValues {
        PuttyValues {
            host_name: Some(host.into()),
            protocol: Some("ssh".into()),
            ..Default::default()
        }
    }

    #[test]
    fn key_names_are_percent_decoded() {
        assert_eq!(decode_key_name("web%2001"), "web 01");
        assert_eq!(decode_key_name("Customer%20A%2Fdb%2501"), "Customer A/db%01");
        assert_eq!(decode_key_name("%2Ehidden"), ".hidden");
        // ANSI bytes (e9 = e-acute) and UTF-8 sequences.
        assert_eq!(decode_key_name("caf%E9"), "caf\u{e9}");
        assert_eq!(decode_key_name("caf%C3%A9"), "caf\u{e9}");
        // Not an escape: kept as written.
        assert_eq!(decode_key_name("50%"), "50%");
        assert_eq!(decode_key_name("a%zz%+1"), "a%zz%+1");
    }

    #[test]
    fn a_plain_ssh_session() {
        let c = candidate("web%2001", &values("web01.example.com")).unwrap();
        assert_eq!(c.name, "web 01");
        assert_eq!(c.host, "web01.example.com");
        assert_eq!(c.port, 22);
        assert_eq!(c.username, None);
        assert_eq!(c.auth, CandidateAuth::Password);
        assert_eq!(c.jump, None);
        assert!(c.folder.is_empty() && c.notes.is_empty());
    }

    #[test]
    fn user_key_port_and_command() {
        let v = PuttyValues {
            host_name: Some("192.0.2.10".into()),
            port: Some(2222),
            user_name: Some("alice".into()),
            public_key_file: Some(r"C:\Users\alice\.ssh\id_ed25519.ppk".into()),
            remote_command: Some("tmux attach".into()),
            ..Default::default()
        };
        let c = candidate("db01", &v).unwrap();
        assert_eq!(c.port, 2222);
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(
            c.auth,
            CandidateAuth::KeyFile {
                path: r"C:\Users\alice\.ssh\id_ed25519.ppk".into()
            }
        );
        assert_eq!(c.startup_command.as_deref(), Some("tmux attach"));
        assert_eq!(c.notes.len(), 1);
        assert!(c.notes[0].contains("remote command"));
    }

    #[test]
    fn the_user_in_the_host_name_wins() {
        let c = candidate("web01", &values("bob@web01.example.com")).unwrap();
        assert_eq!(
            (c.username.as_deref(), c.host.as_str()),
            (Some("bob"), "web01.example.com")
        );
        let mut both = values("bob@web01.example.com");
        both.user_name = Some("alice".into());
        assert_eq!(candidate("web01", &both).unwrap().username.as_deref(), Some("bob"));
        let mut empty = values("web01.example.com");
        empty.user_name = Some("  ".into());
        assert_eq!(candidate("web01", &empty).unwrap().username, None);
    }

    #[test]
    fn other_protocols_defaults_and_bad_entries_are_skipped() {
        let mut telnet = values("192.0.2.20");
        telnet.protocol = Some("telnet".into());
        let skipped = candidate("switch%2001", &telnet).unwrap_err();
        assert_eq!(skipped.name, "switch 01");
        assert_eq!(skipped.reason, "telnet session: only SSH is imported");

        let mut no_protocol = values("web01.example.com");
        no_protocol.protocol = None;
        assert!(candidate("web01", &no_protocol).is_ok(), "missing protocol means ssh");

        assert_eq!(candidate("empty", &values("  ")).unwrap_err().reason, "no host name");
        assert_eq!(
            candidate("empty", &PuttyValues::default()).unwrap_err().reason,
            "no host name"
        );
        let mut port = values("web01.example.com");
        port.port = Some(70000);
        assert_eq!(candidate("web01", &port).unwrap_err().reason, "port 70000 is not valid");
        port.port = Some(0);
        assert!(candidate("web01", &port).is_err());
        assert!(candidate("Default%20Settings", &values("web01.example.com")).is_err());
        assert_eq!(
            candidate("bad", &values("web 01.example.com")).unwrap_err().reason,
            "the host name has spaces in it"
        );
    }

    #[test]
    fn an_ssh_proxy_becomes_the_jump_host_and_others_a_note() {
        let mut v = values("db01.example.com");
        v.proxy_method = Some(6);
        v.proxy_host = Some("bastion.example.org".into());
        v.proxy_port = Some(2222);
        v.proxy_username = Some("bob".into());
        let c = candidate("db01", &v).unwrap();
        assert_eq!(c.jump.as_deref(), Some("bob@bastion.example.org:2222"));
        assert!(c.notes.is_empty());

        v.proxy_port = Some(22);
        v.proxy_username = None;
        assert_eq!(
            candidate("db01", &v).unwrap().jump.as_deref(),
            Some("bastion.example.org")
        );

        v.proxy_host = Some(" ".into());
        let c = candidate("db01", &v).unwrap();
        assert_eq!(c.jump, None);
        assert_eq!(c.notes.len(), 1);

        for method in [1, 2, 3, 4, 5] {
            let mut v = values("db01.example.com");
            v.proxy_method = Some(method);
            v.proxy_host = Some("proxy.example.org".into());
            let c = candidate("db01", &v).unwrap();
            assert_eq!(c.jump, None);
            assert_eq!(c.notes, ["PuTTY's proxy setting was not imported"]);
        }
    }

    const REG: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions]

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"=""
"Protocol"="ssh"
"PortNumber"=dword:00000016

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web%2001]
"Present"=dword:00000001
"HostName"="alice@web01.example.com"
"LogFileName"="putty.log"
"Protocol"="ssh"
"PortNumber"=dword:00000016
"Environment"=""
"Colour0"="187,187,187"
"BellWaveFile"=hex(2):00,00
"WinTitle"=hex:41,00,42,00,43,00,44,00,45,00,46,00,47,00,48,00,49,00,4a,00,4b,\
  00,4c,00,4d,00,00,00
"PublicKeyFile"="C:\\Users\\alice\\.ssh\\id_ed25519.ppk"
"RemoteCommand"="echo \"hello\""

[hkey_current_user\software\simontatham\putty\sessions\DB%20Lab]
"HostName"="192.0.2.30"
"PortNumber"=dword:000008ae
"UserName"="bob"
"ProxyMethod"=dword:00000006
"ProxyHost"="bastion.example.org"
"ProxyPort"=dword:00000016

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\switch]
"HostName"="192.0.2.40"
"Protocol"="telnet"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys]
"ssh-ed25519@22:web01.example.com"="0x1234"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web%2001\Nested]
"HostName"="nested.example.com"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\bad%20port]
"HostName"="web02.example.com"
"PortNumber"="22"
"#;

    #[test]
    fn a_reg_export() {
        let parsed = parse_reg(REG);
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let names: Vec<_> = parsed.candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["web 01", "DB Lab", "bad port"]);

        let web = &parsed.candidates[0];
        assert_eq!(web.host, "web01.example.com");
        assert_eq!(web.username.as_deref(), Some("alice"));
        assert_eq!(
            web.auth,
            CandidateAuth::KeyFile {
                path: r"C:\Users\alice\.ssh\id_ed25519.ppk".into()
            }
        );
        assert_eq!(web.startup_command.as_deref(), Some(r#"echo "hello""#));

        let db = &parsed.candidates[1];
        assert_eq!((db.host.as_str(), db.port), ("192.0.2.30", 2222));
        assert_eq!(db.username.as_deref(), Some("bob"));
        assert_eq!(db.jump.as_deref(), Some("bastion.example.org"));

        // A wrongly typed port counts as missing.
        assert_eq!(parsed.candidates[2].port, 22);

        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].name, "switch");
        assert_eq!(parsed.skipped[0].reason, "telnet session: only SSH is imported");
    }

    #[test]
    fn a_reg_file_without_sessions_warns() {
        let parsed = parse_reg(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\Default%20Settings]\r\n\"HostName\"=\"\"\r\n",
        );
        assert!(parsed.is_empty());
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parse_reg("").warnings.len() == 1);
        assert!(parse_reg("not a registry file\n[\n\"x\n").is_empty());
    }

    #[test]
    fn a_key_listed_twice_is_merged_and_deletions_are_ignored() {
        let reg = r#"[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web01]
"HostName"="web01.example.com"
[-HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\gone]
"HostName"="gone.example.com"
[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\WEB01]
"PortNumber"=dword:00000050
"#;
        let parsed = parse_reg(reg);
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(parsed.candidates[0].port, 80);
        assert!(parsed.skipped.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn reading_the_registry_does_not_fail() {
        // Reads only; works with or without PuTTY installed. Prints nothing it found.
        assert!(read_registry().is_ok());
    }
}
