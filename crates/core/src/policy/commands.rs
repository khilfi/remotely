//! Classifying shell commands for bulk execution: dangerous (BX-06) or read-only.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// A named regex. A command that matches any of them goes to the approval flow as High.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DangerousPattern {
    pub name: String,
    pub pattern: String,
}

/// Start of a command word: line start, whitespace, a shell separator, `(` or a path slash.
const W: &str = r"(?:^|[\s;&|(/`])";

pub fn default_dangerous_patterns() -> Vec<DangerousPattern> {
    let p = |name: &str, pattern: String| DangerousPattern {
        name: name.into(),
        pattern,
    };
    vec![
        p(
            "rm -r / rm -rf",
            format!(r"{W}rm\s+(?:[^;&|\n]*\s)?(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(?:\s|$)"),
        ),
        p("mkfs", format!(r"{W}mkfs(?:\.[a-z0-9]+)?(?:\s|$)")),
        p("dd", format!(r"{W}dd\s")),
        p(
            "shutdown / reboot",
            format!(r"{W}(?:shutdown|reboot|poweroff|halt)(?:\s|$)|{W}init\s+[06](?:\s|$)"),
        ),
        p(
            "iptables -F",
            format!(r"{W}ip6?tables(?:-legacy|-nft)?\s+(?:[^;&|\n]*\s)?(?:-F|--flush)(?:\s|$)"),
        ),
        p("DROP DATABASE", r"(?i)\bdrop\s+(?:database|schema)\b".into()),
    ]
}

/// First words of commands that only read. Multi-word entries match as a prefix ("systemctl status").
pub fn default_read_only_commands() -> Vec<String> {
    [
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "grep",
        "egrep",
        "zgrep",
        "ls",
        "ll",
        "pwd",
        "stat",
        "file",
        "wc",
        "sort",
        "uniq",
        "cut",
        "tr",
        "echo",
        "printf",
        "date",
        "uptime",
        "uname",
        "hostname",
        "hostnamectl status",
        "whoami",
        "id",
        "groups",
        "w",
        "who",
        "last",
        "df",
        "du",
        "free",
        "vmstat",
        "iostat",
        "lscpu",
        "lsblk",
        "blkid",
        "lsof",
        "lspci",
        "lsusb",
        "ps",
        "pgrep",
        "top -b",
        "ss",
        "netstat",
        "ip a",
        "ip addr",
        "ip -br a",
        "ip route",
        "ip r",
        "ip link",
        "ping -c",
        "dig",
        "nslookup",
        "host",
        "env",
        "printenv",
        "which",
        "type",
        "dmesg",
        "journalctl",
        "systemctl status",
        "systemctl is-active",
        "systemctl is-enabled",
        "systemctl list-units",
        "systemctl --failed",
        "dpkg -l",
        "rpm -q",
        "apt list",
        "dnf list",
        "yum list",
        "docker ps",
        "docker images",
        "kubectl get",
        "kubectl describe",
        "getenforce",
        "timedatectl",
        "nproc",
        "sha256sum",
        "md5sum",
        // BX-08: what the command panel's library uses that only reads, whatever follows.
        "systemd-detect-virt",
        "findmnt",
        "mpstat",
        "tracepath",
        "ip neigh show",
        "systemctl list-unit-files",
        "systemctl list-timers",
        "systemctl cat",
        "systemd-analyze blame",
        "apt-cache policy",
        "dpkg -S",
        "rpm -qa",
        "rpm -qf",
        "dnf check-update",
        "dnf info",
        "dnf repolist",
        "dnf history list",
        "getent",
        "chage -l",
        "lastb",
        "ufw status",
        "firewall-cmd --list-all",
        "firewall-cmd --state",
        "iptables -L",
        "iptables -S",
        "nft list ruleset",
        "docker logs",
        "docker stats",
        "docker inspect",
        "docker system df",
        "docker network ls",
        "docker compose ps",
        "kubectl logs",
        "kubectl top",
        "kubectl config get-contexts",
        "kubectl cluster-info",
        "kubectl version",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

// The three patterns below are constants, and the tests compile them; `expect` cannot fire on user
// input here, so it is allowed despite the no-expect rule.
#[allow(clippy::expect_used)]
static REDIRECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d*>>?\s*(&?[^\s;&|]+)").expect("valid redirect regex"));
#[allow(clippy::expect_used)]
static SEPARATOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\r?\n|;|&&|\|\||\||&").expect("valid separator regex"));
#[allow(clippy::expect_used)]
static ENV_ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$").expect("valid assignment regex"));

/// True when every part of the script starts with a read-only command and nothing writes a file.
pub(crate) fn is_read_only(script: &str, read_only: &[String]) -> bool {
    // Command substitution can hide anything.
    if script.contains("$(") || script.contains('`') {
        return false;
    }
    for cap in REDIRECT.captures_iter(script) {
        let to = &cap[1];
        if !(to.starts_with('&') || to == "/dev/null") {
            return false;
        }
    }
    let without_redirects = REDIRECT.replace_all(script, " ");

    let mut segments = 0;
    for segment in SEPARATOR.split(&without_redirects) {
        let words = command_words(segment);
        if words.is_empty() {
            continue;
        }
        segments += 1;
        let line = words.join(" ");
        let allowed = read_only.iter().any(|entry| {
            let entry = entry.split_whitespace().collect::<Vec<_>>().join(" ");
            line == entry || line.starts_with(&format!("{entry} "))
        });
        if !allowed {
            return false;
        }
    }
    segments > 0
}

/// Words of one command with leading `VAR=value` assignments and `sudo [flags]` removed.
fn command_words(segment: &str) -> Vec<&str> {
    let mut words: Vec<&str> = segment.split_whitespace().collect();
    while words.first().is_some_and(|w| ENV_ASSIGN.is_match(w)) {
        words.remove(0);
    }
    if words.first() == Some(&"sudo") {
        words.remove(0);
        while words.first().is_some_and(|w| w.starts_with('-')) {
            words.remove(0);
        }
    }
    words
}
