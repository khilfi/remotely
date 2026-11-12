//! VM-28: the `{{placeholders}}` of an install config.
//!
//! * Built-ins, per VM: `{{hostname}}`, `{{ip}}`, `{{n}}`, `{{template}}` and `{{date}}` (`YYYYMMDD`), as VM-21's
//!   naming patterns name them.
//! * The config's own variables, each with a default the deploy dialog can change per VM: `{{domain}}`.
//! * What comes from the vault: `{{password.<name>}}` (a SHA-512 crypt hash on Linux, a one-time password on Windows)
//!   and `{{ssh_key.<name>}}` (an SS-09 key's public half).
//!
//! A placeholder sits on one line; `\{{` writes `{{` itself (for cloud-init's own Jinja templates). Values are one line
//! too, and checked for the file's kind before they go in ([`check_value`]): a value can't break out of the line or
//! the string it is written into.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::InstallKind;
use crate::untrusted;

pub const BUILT_INS: [&str; 5] = ["hostname", "ip", "n", "template", "date"];
pub const PASSWORD_PREFIX: &str = "password.";
pub const SSH_KEY_PREFIX: &str = "ssh_key.";
/// A variable's or reference's name.
pub const MAX_NAME: usize = 32;
/// A value's length.
pub const MAX_VALUE: usize = 500;

/// What a placeholder names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Placeholder {
    BuiltIn(&'static str),
    Own(String),
    Password(String),
    SshKey(String),
}

impl Placeholder {
    pub fn text(&self) -> String {
        match self {
            Placeholder::BuiltIn(name) => format!("{{{{{name}}}}}"),
            Placeholder::Own(name) => format!("{{{{{name}}}}}"),
            Placeholder::Password(name) => format!("{{{{{PASSWORD_PREFIX}{name}}}}}"),
            Placeholder::SshKey(name) => format!("{{{{{SSH_KEY_PREFIX}{name}}}}}"),
        }
    }
}

/// A piece of a file: text, or a placeholder on line `line`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Text(String),
    Var { name: Placeholder, line: u32 },
}

/// A placeholder the file can't hold, and its line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarError {
    pub line: u32,
    pub message: String,
}

/// A name for an own variable or a vault reference: a lower case letter, then letters, digits and `_`.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && name.len() <= MAX_NAME
}

fn name_of(inner: &str) -> Option<Placeholder> {
    let inner = inner.trim();
    if let Some(name) = BUILT_INS.iter().find(|b| **b == inner) {
        return Some(Placeholder::BuiltIn(name));
    }
    if let Some(rest) = inner.strip_prefix(PASSWORD_PREFIX) {
        return valid_name(rest).then(|| Placeholder::Password(rest.to_owned()));
    }
    if let Some(rest) = inner.strip_prefix(SSH_KEY_PREFIX) {
        return valid_name(rest).then(|| Placeholder::SshKey(rest.to_owned()));
    }
    valid_name(inner).then(|| Placeholder::Own(inner.to_owned()))
}

/// Most placeholder problems one check reports; the rest wait until these are fixed.
pub const MAX_ERRORS: usize = 50;

/// The file as text and placeholders, or the placeholders it can't hold (at most [`MAX_ERRORS`]). Linear in the
/// file's length: an unclosed `{{` ends the line's scan, since no later `{{` on it can be closed either.
pub fn split(text: &str) -> Result<Vec<Piece>, Vec<VarError>> {
    let mut pieces = Vec::new();
    let mut errors = Vec::new();
    for (index, raw_line) in text.split_inclusive('\n').enumerate() {
        if errors.len() >= MAX_ERRORS {
            break;
        }
        let line = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let mut rest = raw_line;
        let mut plain = String::new();
        while let Some(open) = rest.find("{{") {
            if open > 0 && rest.as_bytes()[open - 1] == b'\\' {
                plain.push_str(&rest[..open - 1]);
                plain.push_str("{{");
                rest = &rest[open + 2..];
                continue;
            }
            plain.push_str(&rest[..open]);
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else {
                errors.push(VarError {
                    line,
                    message: "A {{ has no }} on its line: write \\{{ for the characters themselves.".into(),
                });
                plain.push_str("{{");
                plain.push_str(after);
                rest = "";
                break;
            };
            let inner = &after[..close];
            match name_of(inner) {
                Some(name) => {
                    if !plain.is_empty() {
                        pieces.push(Piece::Text(std::mem::take(&mut plain)));
                    }
                    pieces.push(Piece::Var { name, line });
                }
                None => {
                    let shown: String = inner.trim().chars().take(40).collect();
                    errors.push(VarError {
                        line,
                        message: format!(
                            "{{{{{shown}}}}} isn't a placeholder Remotely knows: use {{{{hostname}}}}, {{{{ip}}}}, \
                             {{{{n}}}}, {{{{template}}}}, {{{{date}}}}, a variable's name, {{{{password.<name>}}}} or \
                             {{{{ssh_key.<name>}}}} (write \\{{{{ for the characters themselves)."
                        ),
                    });
                    if errors.len() >= MAX_ERRORS {
                        break;
                    }
                }
            }
            rest = &after[close + 2..];
        }
        plain.push_str(rest);
        if !plain.is_empty() {
            pieces.push(Piece::Text(plain));
        }
    }
    if errors.is_empty() {
        Ok(merge(pieces))
    } else {
        Err(errors)
    }
}

fn merge(pieces: Vec<Piece>) -> Vec<Piece> {
    let mut out: Vec<Piece> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        match (out.last_mut(), piece) {
            (Some(Piece::Text(a)), Piece::Text(b)) => a.push_str(&b),
            (_, piece) => out.push(piece),
        }
    }
    out
}

/// Every placeholder the pieces use, each once.
pub fn used(pieces: &[Piece]) -> BTreeSet<Placeholder> {
    pieces
        .iter()
        .filter_map(|p| match p {
            Piece::Var { name, .. } => Some(name.clone()),
            Piece::Text(_) => None,
        })
        .collect()
}

/// The first line each placeholder is on.
pub fn first_line(pieces: &[Piece], wanted: &Placeholder) -> Option<u32> {
    pieces.iter().find_map(|p| match p {
        Piece::Var { name, line } if name == wanted => Some(*line),
        _ => None,
    })
}

/// The pieces joined with each placeholder's value; `None` from `value` keeps the placeholder as written.
pub fn join(pieces: &[Piece], mut value: impl FnMut(&Placeholder) -> Option<String>) -> String {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Var { name, .. } => match value(name) {
                Some(v) => out.push_str(&v),
                None => out.push_str(&name.text()),
            },
        }
    }
    out
}

/// Characters a value can't hold in a text file (YAML, kickstart, preseed): each could end the string or the
/// shell word it is written into, or start a comment or a command.
const NOT_IN_TEXT_VALUES: [char; 14] = ['"', '\'', '`', '$', '\\', ';', '&', '|', '<', '>', '#', '{', '}', '%'];

/// Why `value` can't go into a file of `kind` (`None` when it can). Windows' XML takes any one-line text: it is
/// escaped as it goes in.
pub fn check_value(kind: InstallKind, value: &str) -> Option<String> {
    if value.chars().count() > MAX_VALUE {
        return Some(format!("is longer than {MAX_VALUE} characters"));
    }
    // Every white space but a plain space: PyYAML and Python read U+0085, U+2028 and U+2029 as line breaks, which
    // would let a value add lines only the installer sees.
    if value
        .chars()
        .any(|c| c.is_control() || untrusted::is_format_char(c) || (c.is_whitespace() && c != ' '))
    {
        return Some("holds a line break, a tab, a non-breaking space or an invisible character".into());
    }
    if kind != InstallKind::Unattend {
        if let Some(c) = value.chars().find(|c| NOT_IN_TEXT_VALUES.contains(c)) {
            return Some(format!("holds {c}, which could end the text it is written into"));
        }
        if value.contains(": ") {
            return Some("holds \": \", which YAML reads as a key".into());
        }
    }
    if matches!(kind, InstallKind::Autoinstall | InstallKind::CloudInit) {
        // Written unquoted, a value starting with one of these is a tag, an alias, a list... (review of #88: `!x`).
        if let Some(c) = value.chars().next().filter(|c| "-?:,[]!*@".contains(*c)) {
            return Some(format!("starts with {c}, which YAML reads as syntax there"));
        }
    }
    None
}

/// A hostname a VM can have: lower case letters, digits and hyphens, 1 to 63, not starting or ending with a hyphen.
pub fn check_hostname(name: &str) -> Option<String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    (!ok).then(|| format!("'{name}' isn't a hostname: lower case letters, digits and hyphens, at most 63"))
}

/// An own variable as the config declares it, with the default each VM starts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VariableDef {
    pub name: String,
    #[serde(default)]
    pub default: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn placeholders_split_the_file() {
        let pieces = split(
            "host: \"{{hostname}}\"\npw: {{ password.admin }}\nkey: {{ssh_key.admin}} {{domain}}\nraw: \\{{ v1.x }}\n",
        )
        .unwrap();
        let names: Vec<Placeholder> = used(&pieces).into_iter().collect();
        assert_eq!(
            names,
            [
                Placeholder::BuiltIn("hostname"),
                Placeholder::Own("domain".into()),
                Placeholder::Password("admin".into()),
                Placeholder::SshKey("admin".into()),
            ]
        );
        assert_eq!(first_line(&pieces, &Placeholder::SshKey("admin".into())), Some(3));
        let out = join(&pieces, |p| match p {
            Placeholder::BuiltIn("hostname") => Some("web-1".into()),
            _ => None,
        });
        assert_eq!(
            out,
            "host: \"web-1\"\npw: {{password.admin}}\nkey: {{ssh_key.admin}} {{domain}}\nraw: {{ v1.x }}\n"
        );
    }

    #[test]
    fn a_file_full_of_open_braces_is_split_in_linear_time_with_capped_errors() {
        // Review of #88: 240 KB of `{{` took 25 s and gave 120,000 problems.
        let one_line = format!("a: {}\n", "{{".repeat(120_000));
        let many_lines = "{{\n".repeat(80_000);
        let closed_far = format!("{}}}}}\n", "{{".repeat(120_000));
        for text in [one_line, many_lines, closed_far] {
            let started = std::time::Instant::now();
            let errors = split(&text).unwrap_err();
            assert!(errors.len() <= MAX_ERRORS, "{}", errors.len());
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "{:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn unknown_or_open_placeholders_name_their_line() {
        let errors = split("a: 1\nb: {{ v1.local_hostname }}\nc: {{hostname\nd: {{Password.x}}\n").unwrap_err();
        let lines: Vec<u32> = errors.iter().map(|e| e.line).collect();
        assert_eq!(lines, [2, 3, 4]);
        assert!(errors[0].message.contains("isn't a placeholder Remotely knows"));
        assert!(errors[1].message.contains("has no }}"));
    }

    #[test]
    fn values_are_checked_for_the_kind_they_go_into() {
        assert_eq!(check_value(InstallKind::Autoinstall, "example.com"), None);
        assert_eq!(
            check_value(InstallKind::Kickstart, "http://proxy.example.com:3128/"),
            None
        );
        for bad in ["a\nb", "$(id)", "x\" y", "a; reboot", "a: b", "a\u{202e}b", "{{n}}"] {
            assert!(check_value(InstallKind::Autoinstall, bad).is_some(), "{bad}");
        }
        assert_eq!(check_value(InstallKind::Unattend, "Example & Co <IT>"), None);
        assert!(check_value(InstallKind::Unattend, "a\nb").is_some());
        // Review of #88: what PyYAML or Python reads as a line break, and other white space, never goes in.
        for kind in InstallKind::ALL {
            for sep in [
                '\u{2028}', '\u{2029}', '\u{0085}', '\u{00a0}', '\t', '\u{000b}', '\u{000c}', '\u{3000}',
            ] {
                let value = format!("en_US.UTF-8{sep}  injected:{sep}  - marker");
                assert!(check_value(kind, &value).is_some(), "{kind:?} {:?}", sep);
            }
            assert_eq!(check_value(kind, "a b"), None, "a plain space is fine");
        }
        assert!(check_value(InstallKind::Preseed, &"x".repeat(501)).is_some());
        assert_eq!(check_hostname("web-1"), None);
        for bad in ["", "Web", "-web", "web-", "web_1", &"a".repeat(64)] {
            assert!(check_hostname(bad).is_some(), "{bad}");
        }
        assert!(valid_name("domain_2"));
        for bad in ["", "2x", "Domain", "a-b", &"a".repeat(33)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
