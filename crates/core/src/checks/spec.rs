//! MO-08: what a health check is, and what every check passes before it is saved.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::net_tools::RecordType;
use crate::error::{CoreError, Result};
use crate::toolbox::ProbeTarget;

/// The shortest time between two runs.
pub const MIN_INTERVAL_SECS: u64 = 30;
/// The longest time between two runs.
pub const MAX_INTERVAL_SECS: u64 = 3600;
pub const DEFAULT_INTERVAL_SECS: u64 = 60;
/// The longest one run may wait for an answer.
pub const MAX_TIMEOUT_SECS: u64 = 60;
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
/// The most failed runs in a row a check may wait for before it counts as down.
pub const MAX_FAILURES: u32 = 10;
pub const DEFAULT_FAILURES: u32 = 2;
pub const MAX_NAME: usize = 80;
/// The most checks a workspace holds.
pub const MAX_CHECKS: usize = 200;
/// An HTTP check's path and query, at most.
pub const MAX_PATH: usize = 2048;
/// The text an HTTP check looks for in the body, at most.
pub const MAX_BODY_TEXT: usize = 200;
/// A systemd unit's name, at most (systemd's own limit).
pub const MAX_UNIT: usize = 255;

fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}
fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}
fn default_failures() -> u32 {
    DEFAULT_FAILURES
}
fn default_true() -> bool {
    true
}
fn default_status_min() -> u16 {
    200
}
fn default_status_max() -> u16 {
    399
}
fn default_record() -> RecordType {
    RecordType::A
}

/// What a check does, with the kind's own fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum CheckSpec {
    /// One ICMP echo from this PC (not through a jump host).
    Ping,
    /// A TCP connection to a port.
    Tcp { port: u16 },
    /// A GET request; up when the status is in the range (and the body holds the text, if one is given).
    Http {
        /// HTTPS: TLS, with the certificate checked against Windows' trust store and the name unless
        /// `allow_invalid_cert`.
        #[serde(default)]
        https: bool,
        /// None: 80, or 443 for HTTPS.
        #[serde(default)]
        port: Option<u16>,
        /// The path and query, starting with `/`.
        #[serde(default)]
        path: String,
        #[serde(default = "default_status_min")]
        status_min: u16,
        #[serde(default = "default_status_max")]
        status_max: u16,
        /// Text the body must hold (the first 256 KB are read).
        #[serde(default)]
        body_contains: Option<String>,
        /// Follow up to 5 redirects (else a redirect's status is the answer).
        #[serde(default = "default_true")]
        follow_redirects: bool,
        /// Certificate errors (not trusted, another name, expired) don't fail the check.
        #[serde(default)]
        allow_invalid_cert: bool,
    },
    /// A TLS server's certificate: down when the handshake fails or it expired, isn't trusted or names another host
    /// (unless `allow_untrusted`); its days left go to MO-07's "certificate expiring" rules.
    Certificate {
        port: u16,
        /// The name sent and checked; none: the host.
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        allow_untrusted: bool,
    },
    /// A DNS lookup from this PC: up when the name has an A (or AAAA) record, and the expected address among them.
    Dns {
        #[serde(default = "default_record")]
        record_type: RecordType,
        /// An IP address of the server to ask; none: Windows' resolver.
        #[serde(default)]
        server: Option<String>,
        /// An IP address the name must resolve to.
        #[serde(default)]
        expect: Option<String>,
    },
    /// A service on a session's host: a systemd unit over SSH (`systemctl is-active`). F4 adds Windows services
    /// over WinRM, chosen by the session's kind ([`super::service::ServiceReader`]).
    Service { unit: String },
}

impl CheckSpec {
    pub fn kind_str(&self) -> &'static str {
        match self {
            CheckSpec::Ping => "ping",
            CheckSpec::Tcp { .. } => "tcp",
            CheckSpec::Http { .. } => "http",
            CheckSpec::Certificate { .. } => "certificate",
            CheckSpec::Dns { .. } => "dns",
            CheckSpec::Service { .. } => "service",
        }
    }

    /// In a line, for the audit log and lists: "HTTPS GET /health (200-399)", "TCP port 22".
    pub fn describe(&self) -> String {
        match self {
            CheckSpec::Ping => "ping".into(),
            CheckSpec::Tcp { port } => format!("TCP port {port}"),
            CheckSpec::Http {
                https,
                port,
                path,
                status_min,
                status_max,
                body_contains,
                ..
            } => {
                let scheme = if *https { "HTTPS" } else { "HTTP" };
                let port = port.map(|p| format!(" port {p}")).unwrap_or_default();
                let text = if body_contains.is_some() {
                    ", with text in the body"
                } else {
                    ""
                };
                format!("{scheme}{port} GET {path} ({status_min}-{status_max}{text})")
            }
            CheckSpec::Certificate { port, .. } => format!("certificate on port {port}"),
            CheckSpec::Dns {
                record_type, expect, ..
            } => match expect {
                Some(ip) => format!("DNS {} record, expecting {ip}", record_type.as_str()),
                None => format!("DNS {} record", record_type.as_str()),
            },
            CheckSpec::Service { unit } => format!("service {unit}"),
        }
    }
}

/// A check as the editor sends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckInput {
    pub name: String,
    pub target: ProbeTarget,
    pub spec: CheckSpec,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_failures")]
    pub failures_before_down: u32,
    #[serde(default)]
    pub paused: bool,
}

/// A saved check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    pub id: Uuid,
    pub name: String,
    pub target: ProbeTarget,
    pub spec: CheckSpec,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub failures_before_down: u32,
    pub paused: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl HealthCheck {
    pub fn input(&self) -> CheckInput {
        CheckInput {
            name: self.name.clone(),
            target: self.target.clone(),
            spec: self.spec.clone(),
            interval_secs: self.interval_secs,
            timeout_secs: self.timeout_secs,
            failures_before_down: self.failures_before_down,
            paused: self.paused,
        }
    }
}

/// The text a check may keep: no control or format characters (Unicode Cf), trimmed.
fn clean_line(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() && !crate::untrusted::is_format_char(*c))
        .collect::<String>()
        .trim()
        .to_owned()
}

/// A systemd unit name Remotely puts on a command line: a letter or digit first, then letters, digits and `:_.@-`
/// only (so nothing a shell reads, and never an option), at most 255 characters.
pub fn check_unit(unit: &str) -> Result<String> {
    let unit = unit.trim();
    let mut chars = unit.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '@' | '-'));
    if !first_ok || !rest_ok || unit.len() > MAX_UNIT {
        return Err(CoreError::InvalidInput(
            "A unit's name is letters, digits and : _ . @ - (like nginx.service), starting with a letter or digit."
                .into(),
        ));
    }
    Ok(unit.to_owned())
}

/// The check as it is saved: the name and fields trimmed, numbers in range. Refused with a reason the editor shows.
/// The target's existence and kind are checked by the service ([`super::Checks`]), which reads the store.
pub fn checked(mut input: CheckInput) -> Result<CheckInput> {
    let invalid = |why: &str| Err(CoreError::InvalidInput(why.to_owned()));
    input.name = clean_line(&input.name);
    if input.name.is_empty() {
        return invalid("A check needs a name.");
    }
    if input.name.chars().count() > MAX_NAME {
        return Err(CoreError::InvalidInput(format!(
            "A check's name can be at most {MAX_NAME} characters."
        )));
    }
    if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&input.interval_secs) {
        return invalid("A check runs every 30 seconds to 1 hour.");
    }
    if !(1..=MAX_TIMEOUT_SECS).contains(&input.timeout_secs) {
        return invalid("A run's timeout is 1 to 60 seconds.");
    }
    if input.timeout_secs >= input.interval_secs {
        return invalid("A run's timeout must be shorter than the time between runs.");
    }
    if !(1..=MAX_FAILURES).contains(&input.failures_before_down) {
        return invalid("A check counts as down after 1 to 10 failed runs in a row.");
    }
    if let ProbeTarget::Address { host } = &mut input.target {
        *host = crate::toolbox::check_host(host)?;
    }
    let target = input.target.clone();
    match &mut input.spec {
        CheckSpec::Ping => {}
        CheckSpec::Tcp { port } => {
            if *port == 0 {
                return invalid("Choose a port from 1 to 65535.");
            }
        }
        CheckSpec::Http {
            port,
            path,
            status_min,
            status_max,
            body_contains,
            ..
        } => {
            if *port == Some(0) {
                return invalid("Choose a port from 1 to 65535.");
            }
            let trimmed = path.trim();
            *path = if trimmed.is_empty() {
                "/".to_owned()
            } else if trimmed.starts_with('/') {
                trimmed.to_owned()
            } else {
                format!("/{trimmed}")
            };
            let fits = path.len() <= MAX_PATH && path.chars().all(|c| c.is_ascii_graphic());
            if !fits || path.starts_with("//") {
                return invalid("The path is like /health or /status?full=1: no spaces, at most 2,048 characters.");
            }
            if !(100..=599).contains(status_min) || !(100..=599).contains(status_max) || status_min > status_max {
                return invalid("The expected status is a range from 100 to 599, like 200-399.");
            }
            *body_contains = body_contains.as_deref().map(clean_line).filter(|t| !t.is_empty());
            if body_contains
                .as_ref()
                .is_some_and(|t| t.chars().count() > MAX_BODY_TEXT)
            {
                return Err(CoreError::InvalidInput(format!(
                    "The text to find can be at most {MAX_BODY_TEXT} characters."
                )));
            }
        }
        CheckSpec::Certificate { port, server_name, .. } => {
            if *port == 0 {
                return invalid("Choose a port from 1 to 65535.");
            }
            *server_name = match server_name.as_deref().map(str::trim) {
                None | Some("") => None,
                Some(name) => Some(crate::toolbox::check_host(name)?),
            };
        }
        CheckSpec::Dns {
            record_type,
            server,
            expect,
        } => {
            if !matches!(record_type, RecordType::A | RecordType::Aaaa) {
                return invalid("A DNS check looks for an A or AAAA record.");
            }
            match &target {
                ProbeTarget::Address { host } if crate::adapters::network::ip_literal(host).is_some() => {
                    return invalid("A DNS check looks up a name: type a host name, not an address.");
                }
                ProbeTarget::Vm { .. } => {
                    return invalid("A DNS check looks up a name: choose a session or type a host name.");
                }
                _ => {}
            }
            *server = clean_ip(server.as_deref(), "the DNS server")?;
            *expect = clean_ip(expect.as_deref(), "the expected address")?;
            if let Some(ip) = expect.as_deref().and_then(crate::adapters::network::ip_literal) {
                let wrong = match record_type {
                    RecordType::A => ip.is_ipv6(),
                    _ => ip.is_ipv4(),
                };
                if wrong {
                    return invalid("The expected address must match the record: IPv4 for A, IPv6 for AAAA.");
                }
            }
        }
        CheckSpec::Service { unit } => {
            if !matches!(target, ProbeTarget::Session { .. }) {
                return invalid("A service check reads a session's host: choose a session.");
            }
            *unit = check_unit(unit)?;
        }
    }
    Ok(input)
}

fn clean_ip(text: Option<&str>, what: &str) -> Result<Option<String>> {
    match text.map(str::trim) {
        None | Some("") => Ok(None),
        Some(text) => match crate::adapters::network::ip_literal(text) {
            Some(ip) => Ok(Some(ip.to_string())),
            None => Err(CoreError::InvalidInput(format!(
                "'{text}' isn't an IP address: type {what} as one."
            ))),
        },
    }
}

/// "every 1 minute", "every 30 seconds".
pub fn every_text(secs: u64) -> String {
    format!("every {}", crate::alerts::rules::duration_text(secs))
}

/// A check in a line, for the audit log: "'web': HTTPS GET /health (200-399) on web01, every 1 minute, timeout 10 s,
/// down after 2 failed runs, paused".
pub fn describe(input: &CheckInput, target: &str) -> String {
    format!(
        "'{}': {} on {target}, {}, timeout {} s, down after {} failed run{}{}",
        input.name,
        input.spec.describe(),
        every_text(input.interval_secs),
        input.timeout_secs,
        input.failures_before_down,
        if input.failures_before_down == 1 { "" } else { "s" },
        if input.paused { ", paused" } else { "" }
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn input(spec: CheckSpec) -> CheckInput {
        CheckInput {
            name: " web \u{202e} ".into(),
            target: ProbeTarget::Address {
                host: " web01.example.com ".into(),
            },
            spec,
            interval_secs: 60,
            timeout_secs: 10,
            failures_before_down: 2,
            paused: false,
        }
    }

    fn http(path: &str) -> CheckSpec {
        CheckSpec::Http {
            https: true,
            port: None,
            path: path.into(),
            status_min: 200,
            status_max: 399,
            body_contains: Some("  ok \u{7} ".into()),
            follow_redirects: true,
            allow_invalid_cert: false,
        }
    }

    #[test]
    fn a_check_is_trimmed_and_cleaned() {
        let saved = checked(input(http("health"))).unwrap();
        assert_eq!(saved.name, "web", "control and format characters go");
        assert_eq!(
            saved.target,
            ProbeTarget::Address {
                host: "web01.example.com".into()
            }
        );
        let CheckSpec::Http {
            path, body_contains, ..
        } = saved.spec
        else {
            panic!("not HTTP")
        };
        assert_eq!(path, "/health");
        assert_eq!(body_contains.as_deref(), Some("ok"));
    }

    #[test]
    fn numbers_out_of_range_are_refused_with_a_reason() {
        let refused = |change: &dyn Fn(&mut CheckInput)| {
            let mut i = input(CheckSpec::Tcp { port: 22 });
            change(&mut i);
            checked(i).unwrap_err().to_string()
        };
        assert!(refused(&|i| i.interval_secs = 29).contains("30 seconds"));
        assert!(refused(&|i| i.interval_secs = 3601).contains("1 hour"));
        assert!(refused(&|i| i.timeout_secs = 0).contains("timeout"));
        assert!(refused(&|i| i.timeout_secs = 61).contains("timeout"));
        assert!(refused(&|i| {
            i.interval_secs = 30;
            i.timeout_secs = 30;
        })
        .contains("shorter"));
        assert!(refused(&|i| i.failures_before_down = 0).contains("1 to 10"));
        assert!(refused(&|i| i.failures_before_down = 11).contains("1 to 10"));
        assert!(refused(&|i| i.name = "\t".into()).contains("name"));
        assert!(refused(&|i| i.name = "x".repeat(MAX_NAME + 1)).contains("at most"));
        assert!(refused(&|i| i.spec = CheckSpec::Tcp { port: 0 }).contains("port"));
        assert!(refused(&|i| i.target = ProbeTarget::Address {
            host: "$(reboot)".into()
        })
        .contains("host name"));
    }

    #[test]
    fn http_fields_are_checked() {
        let refused = |spec: CheckSpec| checked(input(spec)).unwrap_err().to_string();
        assert!(refused(http("/a b")).contains("path"));
        assert!(refused(http("//evil.example.com/")).contains("path"));
        assert!(refused(http(&format!("/{}", "a".repeat(MAX_PATH)))).contains("path"));
        let mut range = http("/");
        if let CheckSpec::Http { status_min, .. } = &mut range {
            *status_min = 500;
        }
        if let CheckSpec::Http { status_max, .. } = &mut range {
            *status_max = 200;
        }
        assert!(refused(range).contains("range"));
        let mut long = http("/");
        if let CheckSpec::Http { body_contains, .. } = &mut long {
            *body_contains = Some("x".repeat(MAX_BODY_TEXT + 1));
        }
        assert!(refused(long).contains("at most"));
    }

    #[test]
    fn dns_checks_look_up_names_and_expect_matching_addresses() {
        let dns = |record_type, expect: Option<&str>| CheckSpec::Dns {
            record_type,
            server: Some(" 192.0.2.53 ".into()),
            expect: expect.map(str::to_owned),
        };
        let saved = checked(input(dns(RecordType::A, Some("192.0.2.10")))).unwrap();
        assert_eq!(
            saved.spec,
            CheckSpec::Dns {
                record_type: RecordType::A,
                server: Some("192.0.2.53".into()),
                expect: Some("192.0.2.10".into())
            }
        );
        let refused = |i: CheckInput| checked(i).unwrap_err().to_string();
        assert!(refused(input(dns(RecordType::A, Some("2001:db8::1")))).contains("IPv4 for A"));
        assert!(refused(input(dns(RecordType::Mx, None))).contains("A or AAAA"));
        assert!(refused(input(dns(RecordType::A, Some("web01")))).contains("IP address"));
        let mut by_ip = input(dns(RecordType::A, None));
        by_ip.target = ProbeTarget::Address {
            host: "192.0.2.10".into(),
        };
        assert!(refused(by_ip).contains("not an address"));
        let mut vm = input(dns(RecordType::A, None));
        vm.target = ProbeTarget::Vm { vm_key: "x".into() };
        assert!(refused(vm).contains("session"));
    }

    #[test]
    fn service_checks_take_a_session_and_a_plain_unit_name() {
        let session = ProbeTarget::Session {
            session_id: Uuid::new_v4(),
        };
        let mut ok = input(CheckSpec::Service {
            unit: " nginx.service ".into(),
        });
        ok.target = session.clone();
        assert_eq!(
            checked(ok).unwrap().spec,
            CheckSpec::Service {
                unit: "nginx.service".into()
            }
        );
        assert!(checked(input(CheckSpec::Service { unit: "nginx".into() }))
            .unwrap_err()
            .to_string()
            .contains("session"));
        for bad in [
            "",
            "-h",
            "--all",
            "nginx; reboot",
            "nginx service",
            "$(id)",
            "a'b",
            "ngin\\x2dx",
            "über.service",
        ] {
            assert!(check_unit(bad).is_err(), "{bad}");
        }
        for good in [
            "nginx",
            "sshd.service",
            "getty@tty1.service",
            "dev-sda1.device",
            "a:b_c",
        ] {
            assert!(check_unit(good).is_ok(), "{good}");
        }
        assert!(check_unit(&"a".repeat(MAX_UNIT + 1)).is_err());
    }

    #[test]
    fn a_check_says_what_it_is_in_words() {
        let saved = checked(input(http("/health"))).unwrap();
        assert_eq!(
            describe(&saved, "web01"),
            "'web': HTTPS GET /health (200-399, with text in the body) on web01, every 1 minute, timeout 10 s, \
             down after 2 failed runs"
        );
        let mut paused = input(CheckSpec::Tcp { port: 22 });
        paused.failures_before_down = 1;
        paused.paused = true;
        assert_eq!(
            describe(&checked(paused).unwrap(), "web01"),
            "'web': TCP port 22 on web01, every 1 minute, timeout 10 s, down after 1 failed run, paused"
        );
    }
}
