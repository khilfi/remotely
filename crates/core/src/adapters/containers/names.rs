//! CT-01, CT-02: what may reach a container CLI.
//!
//! Container ids, image ids and volume names come from the engine's own output and are checked here
//! before they go into a command line; an image reference to pull is typed by the user and checked
//! against the reference grammar. None of them can start with `-`, so none reads as an option. On a
//! host the command line is also shell-quoted word by word ([`shell_line`]), so even a checked value
//! is never read by the shell.

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};

use crate::adapters::remote::sh_quote;
use crate::error::{CoreError, Result};

/// The longest name, reference or id taken.
pub const MAX_NAME: usize = 255;

fn invalid(message: String) -> CoreError {
    CoreError::InvalidInput(message)
}

/// What a value looks like in a message: at most 60 characters, control characters shown as `?`.
pub(crate) fn shown(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(60)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if text.chars().count() > 60 {
        out.push('…');
    }
    out
}

fn is_hex(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A container id: 12 to 64 lower-case hex digits (both engines print 64 with `--no-trunc`; Podman's
/// stats print 12).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ContainerId(String);

impl ContainerId {
    pub fn parse(text: &str) -> Result<Self> {
        if (12..=64).contains(&text.len()) && is_hex(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(invalid(format!("'{}' is not a container id", shown(text))))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first 12 digits, as `docker ps` shows them.
    pub fn short(&self) -> &str {
        &self.0[..12]
    }

    /// The same container: one id is the start of the other (Podman's stats give 12 digits).
    pub fn same_as(&self, other: &ContainerId) -> bool {
        self.0.starts_with(&other.0) || other.0.starts_with(&self.0)
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContainerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// An image id: `sha256:` and 64 hex digits as Docker prints it, or 12 to 64 hex digits (Podman).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ImageId(String);

impl ImageId {
    pub fn parse(text: &str) -> Result<Self> {
        let digits = text.strip_prefix("sha256:").unwrap_or(text);
        if (12..=64).contains(&digits.len()) && is_hex(digits) {
            Ok(Self(text.to_owned()))
        } else {
            Err(invalid(format!("'{}' is not an image id", shown(text))))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The hex digits without `sha256:`.
    pub fn digits(&self) -> &str {
        self.0.strip_prefix("sha256:").unwrap_or(&self.0)
    }

    /// The first 12 digits, as `docker images` shows them.
    pub fn short(&self) -> &str {
        &self.digits()[..12]
    }

    /// The same image, with or without `sha256:`, or one id the start of the other.
    pub fn same_as(&self, other: &ImageId) -> bool {
        let (a, b) = (self.digits(), other.digits());
        a.starts_with(b) || b.starts_with(a)
    }
}

impl fmt::Display for ImageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ImageId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Docker's rule for container and volume names: a letter or digit, then letters, digits, `_`, `.`
/// and `-`.
pub fn is_valid_name(text: &str) -> bool {
    let mut chars = text.chars();
    text.len() <= MAX_NAME
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A volume name ([`is_valid_name`]). Volumes have no id; the CLI takes the name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct VolumeName(String);

impl VolumeName {
    pub fn parse(text: &str) -> Result<Self> {
        if is_valid_name(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(invalid(format!("'{}' is not a volume name", shown(text))))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// An anonymous volume: Docker names it with 64 hex digits.
    pub fn is_anonymous(&self) -> bool {
        self.0.len() == 64 && is_hex(&self.0)
    }
}

impl fmt::Display for VolumeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for VolumeName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// The image reference grammar of the distribution project (Docker and Podman use it):
/// `[domain[:port]/]path[:tag][@digest]`, path components in lower case.
// A constant pattern, compiled by the tests below; `expect` cannot fire on user input here.
#[allow(clippy::expect_used)]
static IMAGE_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    let domain_component = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])";
    let domain = format!(r"{domain_component}(?:\.{domain_component})*(?::[0-9]+)?");
    let path_component = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
    let tag = r"[\w][\w.-]{0,127}";
    let digest = r"[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}";
    let pattern = format!(r"^(?:{domain}/)?{path_component}(?:/{path_component})*(?::{tag})?(?:@{digest})?$");
    Regex::new(&pattern).expect("valid image reference pattern")
});

/// An image reference to pull, e.g. `nginx:1.27`, `registry.example.com:5000/team/app@sha256:…`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ImageRef(String);

impl ImageRef {
    pub fn parse(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(invalid("Type the image to pull, e.g. nginx:1.27.".into()));
        }
        if trimmed.len() > MAX_NAME || !IMAGE_REFERENCE.is_match(trimmed) {
            return Err(invalid(format!(
                "'{}' is not an image reference. Use a name like nginx:1.27 or registry.example.com/team/app:2.1.",
                shown(trimmed)
            )));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A log timestamp to read from (`--since`), as the engine printed it with `--timestamps`:
/// RFC 3339 with up to nanoseconds.
// A constant pattern, compiled by the tests below.
#[allow(clippy::expect_used)]
static LOG_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$")
        .expect("valid log time pattern")
});

pub fn is_log_time(text: &str) -> bool {
    LOG_TIME.is_match(text)
}

/// A command line for a POSIX shell: every word in single quotes.
pub fn shell_line(argv: &[String]) -> String {
    argv.iter().map(|word| sh_quote(word)).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    #[test]
    fn container_ids_are_hex_only() {
        assert_eq!(ContainerId::parse(ID).unwrap().short(), "4f1e2d3c4b5a");
        assert!(ContainerId::parse(&ID[..12]).is_ok());
        for bad in [
            "",
            "4f1e2d3c4b5",
            "web-1",
            "-rf",
            "4F1E2D3C4B5A",
            "4f1e2d3c4b5a; reboot",
            "$(reboot)4f1e2d3c4b5a",
            "4f1e2d3c4b5a\n",
            &format!("{ID}0"),
        ] {
            assert!(ContainerId::parse(bad).is_err(), "{bad:?}");
        }
        let short = ContainerId::parse(&ID[..12]).unwrap();
        assert!(ContainerId::parse(ID).unwrap().same_as(&short));
    }

    #[test]
    fn image_ids_take_docker_and_podman_forms() {
        let docker = ImageId::parse(&format!("sha256:{ID}")).unwrap();
        let podman = ImageId::parse(ID).unwrap();
        assert_eq!(docker.short(), "4f1e2d3c4b5a");
        assert!(docker.same_as(&podman));
        for bad in [
            "sha256:",
            "nginx:latest",
            "sha256:xyz",
            "--force",
            &format!("sha512:{ID}"),
        ] {
            assert!(ImageId::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_follow_dockers_rule() {
        for good in ["web-1", "db_data", "shop.cache", "a", "0abc"] {
            assert!(is_valid_name(good), "{good}");
            assert!(VolumeName::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "-v",
            ".hidden",
            "_x",
            "a b",
            "a;b",
            "a/b",
            "a:b",
            "x$(reboot)",
            "x`id`",
            "x'y",
            "ü",
            "a\nb",
            &"a".repeat(MAX_NAME + 1),
        ] {
            assert!(!is_valid_name(bad), "{bad:?}");
            assert!(VolumeName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(VolumeName::parse(ID).unwrap().is_anonymous());
        assert!(!VolumeName::parse("pgdata").unwrap().is_anonymous());
    }

    #[test]
    fn image_references_follow_the_grammar() {
        for good in [
            "nginx",
            "nginx:1.27",
            "nginx:1.27-alpine",
            "library/nginx:latest",
            "registry.example.com/team/app:2.1",
            "registry.example.com:5000/team/app",
            "localhost:5000/app",
            "ghcr.io/example-org/tool_x:v1.2.3",
            &format!("nginx@sha256:{ID}"),
            &format!("registry.example.com/app:1.0@sha256:{ID}"),
            "a/b__c/d-e",
            "  nginx:1.27  ",
        ] {
            assert!(ImageRef::parse(good).is_ok(), "{good}");
        }
        assert_eq!(ImageRef::parse(" nginx ").unwrap().as_str(), "nginx");
        for bad in [
            "",
            "   ",
            "Nginx",
            "-q",
            "--help",
            "nginx:",
            "nginx:-x",
            "nginx latest",
            "nginx;reboot",
            "nginx$(id)",
            "nginx`id`",
            "nginx|sh",
            "nginx&&id",
            "nginx\nid",
            "nginx'x",
            "/nginx",
            "nginx/",
            "nginx@sha256:short",
            &format!("{}:1", "a".repeat(MAX_NAME)),
        ] {
            assert!(ImageRef::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn log_times_are_rfc3339() {
        assert!(is_log_time("2026-10-21T10:00:00.123456789Z"));
        assert!(is_log_time("2026-10-21T10:00:00Z"));
        assert!(is_log_time("2026-10-21T10:00:00.5+02:00"));
        for bad in [
            "",
            "yesterday",
            "2026-10-21",
            "2026-10-21T10:00:00Z; id",
            "-1h",
            "1700000000",
        ] {
            assert!(!is_log_time(bad), "{bad}");
        }
    }

    #[test]
    fn command_lines_quote_every_word() {
        let line = shell_line(&["docker".into(), "logs".into(), "it's".into(), "{{json .}}".into()]);
        assert_eq!(line, r"'docker' 'logs' 'it'\''s' '{{json .}}'");
    }

    #[test]
    fn messages_show_values_without_control_characters() {
        assert_eq!(shown("a\x1b[31mb"), "a?[31mb");
        assert!(shown(&"x".repeat(100)).ends_with('…'));
    }
}
