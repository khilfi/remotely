//! Classifying shell commands for bulk execution: dangerous (BX-06) or read-only.

mod writes;

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
/// The forms of these commands that change something (`ip link set`, `date -s`, `journalctl --vacuum-…`)
/// are never read-only, whatever the list says (`commands/writes.rs`).
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
        // BX-08 (extended library): more commands whose listed forms only read. Pure-read binaries
        // (they have no writing form) are added bare; commands that also write have either a
        // multi-word prefix here that only matches a reading form, or a rule in `commands/writes.rs`.
        // --- Storage: LVM reporting (display only; no writing form) ---
        "pvs",
        "vgs",
        "lvs",
        "pvdisplay",
        "vgdisplay",
        "lvdisplay",
        // --- Storage: filesystem and SAN (read-only tools / reading prefixes) ---
        "xfs_info",
        "dumpe2fs",
        "showmount",
        "nfsstat",
        "multipath -ll",
        "multipath -l",
        // --- Memory and processes (sysstat and read-only tools) ---
        "slabtop",
        "smem",
        "pidstat",
        "iotop",
        "swapon --show",
        // --- Network (read-only tools and reading prefixes) ---
        "traceroute",
        "mtr",
        "resolvectl status",
        "resolvectl query",
        // --- System info, services and logs ---
        "lshw",
        "lsmod",
        "localectl status",
        "ip -s link",
        "systemctl show",
        "systemctl get-default",
        "systemctl list-dependencies",
        "systemd-analyze time",
        "systemd-analyze critical-chain",
        // --- Packages (apt/dpkg reading prefixes; apt-cache only reads) ---
        "apt-cache",
        "apt-get check",
        "dpkg -C",
        "dpkg --audit",
        "dpkg -V",
        "dpkg --verify",
        "dpkg --get-selections",
        "apt-mark showhold",
        "apt-mark showmanual",
        "apt-mark showauto",
        // --- Packages (dnf/rpm reading prefixes) ---
        "dnf repoquery",
        "dnf search",
        "dnf provides",
        "dnf grouplist",
        "dnf group list",
        "dnf updateinfo",
        "needs-restarting",
        "rpm -V",
        "rpm --verify",
        "rpm -K",
        // --- Users ---
        "lslogins",
        "loginctl list-sessions",
        "loginctl session-status",
        "loginctl user-status",
        "loginctl list-users",
        // --- Security and access ---
        "sestatus",
        "getsebool",
        "aa-status",
        "apparmor_status",
        "ausearch",
        "aureport",
        "auditctl -l",
        "auditctl -s",
        "sshd -T",
        "sshd -t",
        "visudo -c",
        "fail2ban-client status",
        "fail2ban-client get",
        "klist",
        // --- Firewall (firewall-cmd reading options are narrowed by firewall_cmd_writes) ---
        "firewall-cmd --get-services",
        "firewall-cmd --list-all-zones",
        "nft list",
        "nft describe",
        // --- Web servers (validate/dump only; never start or signal the server) ---
        "nginx -t",
        "nginx -T",
        "nginx -v",
        "nginx -V",
        "apachectl configtest",
        "apachectl -t",
        "apachectl -S",
        "apachectl -M",
        "apachectl -v",
        "apache2ctl configtest",
        "apache2ctl -t",
        "apache2ctl -S",
        "apache2ctl -M",
        "apache2ctl -v",
        "httpd -t",
        "httpd -S",
        "httpd -M",
        "httpd -v",
        // --- Databases (bare mysqladmin: every command word must read, see writes.rs; version strings) ---
        "mysqladmin",
        "mysql --version",
        "mariadb --version",
        "psql --version",
        "pg_isready",
        "pg_lsclusters",
        // --- Scheduling ---
        "crontab -l",
        "atq",
        // --- Time sync (chrony/ntp reading subcommands; hwclock show) ---
        "chronyc tracking",
        "chronyc sources",
        "chronyc sourcestats",
        "chronyc activity",
        "chronyc ntpdata",
        "chronyc serverstats",
        "chronyc clients",
        "ntpq -p",
        "hwclock --show",
        "hwclock -r",
        // --- Identity (AD/LDAP, SSSD reading subcommands) ---
        "realm list",
        "realm discover",
        "sssctl domain-list",
        "sssctl domain-status",
        "sssctl config-check",
        "sssctl user-checks",
        "adcli info",
        // --- VMware Tools in the guest (reading subcommands only) ---
        "vmware-toolbox-cmd -v",
        "vmware-toolbox-cmd stat",
        "vmware-toolbox-cmd device list",
        "vmware-toolbox-cmd timesync status",
        // --- Podman (read-only prefixes; the writing verbs are not listed) ---
        "podman ps",
        "podman images",
        "podman logs",
        "podman stats",
        "podman inspect",
        "podman info",
        "podman version",
        "podman pod ps",
        "podman volume ls",
        "podman system df",
        "podman port",
        "podman top",
        // --- Docker (more read-only prefixes) ---
        "docker version",
        "docker info",
        "docker top",
        "docker port",
        "docker volume ls",
        "docker compose logs",
        // --- Kubernetes (more read-only prefixes) ---
        "kubectl api-resources",
        "kubectl explain",
        "kubectl rollout status",
        "kubectl rollout history",
        "kubectl auth can-i",
        "kubectl config view",
        // --- Helm (read-only subcommands; install/upgrade/rollback/uninstall are not listed) ---
        "helm list",
        "helm status",
        "helm history",
        "helm get",
        "helm show",
        "helm repo list",
        "helm search",
        "helm version",
        "helm env",
        // --- Commands that also write: classified read-only here but narrowed in writes.rs ---
        "smartctl",
        "openssl",
        "sysctl",
        // BX-08 (0.4.0): finding files, iSCSI, time. Each has a rule in writes.rs: find without its
        // actions that delete, run or write; locate without slocate's update; iscsiadm showing only;
        // chronyd only printing its configuration.
        "find",
        "locate",
        "plocate",
        "iscsiadm",
        "chronyd -p",
        "systemd-analyze cat-config",
        // MO-14 (0.4.0): services on hosts without systemd. Both only show each service's state:
        // SysV and Upstart's `service --status-all`, OpenRC's `rc-status`.
        "service --status-all",
        "rc-status",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

// The three patterns below are constants, and the tests compile them; `expect` cannot fire on user
// input here, so it is allowed despite the no-expect rule.
#[allow(clippy::expect_used)]
static REDIRECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d*(&>>?|>\||>>?&?)\s*([^\s;&|<>()]*)").expect("valid redirect regex"));
#[allow(clippy::expect_used)]
static SEPARATOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\r?\n|;|&&|\|\||\||&").expect("valid separator regex"));
#[allow(clippy::expect_used)]
static ENV_ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").expect("valid assignment regex"));

/// True when every part of the script starts with a read-only command, none of them is a form of it
/// that writes, and nothing writes a file.
pub(crate) fn is_read_only(script: &str, read_only: &[String]) -> bool {
    // Command and process substitution can hide anything.
    if ["$(", "`", "<(", ">("].iter().any(|s| script.contains(s)) {
        return false;
    }
    for cap in REDIRECT.captures_iter(script) {
        let (op, to) = (&cap[1], &cap[2]);
        // `2>&1`, `>&2` and `>&-` point at another stream; `>&file` writes a file, as `>|file` does.
        let stream = op.ends_with('&') && (to == "-" || (!to.is_empty() && to.bytes().all(|b| b.is_ascii_digit())));
        if !(stream || to == "/dev/null") {
            return false;
        }
    }
    let without_redirects = REDIRECT.replace_all(script, " ");

    let mut segments = 0;
    for segment in SEPARATOR.split(&without_redirects) {
        let Some(words) = command_words(segment) else {
            return false;
        };
        if words.is_empty() {
            continue;
        }
        segments += 1;
        let line = words.join(" ");
        let allowed = read_only.iter().any(|entry| {
            let entry = entry.split_whitespace().collect::<Vec<_>>().join(" ");
            line == entry || line.starts_with(&format!("{entry} "))
        });
        // An entry matches the first words only: "ip link" matches `ip link set eth0 down` too.
        if !allowed || writes::writes(&words) {
            return false;
        }
    }
    segments > 0
}

/// Words of the command one segment runs, without what only sets up how it runs: `VAR=value`
/// assignments, `sudo [flags]` and `env` with the options and settings it stays read-only with
/// (`writes::env_command`). None when an assignment can make the command do more than read, such as
/// `LD_PRELOAD=…` or `PAGER=…` (`writes::harmless_assignment`).
fn command_words(segment: &str) -> Option<Vec<String>> {
    let words = shell_words(segment);
    let mut rest = words.as_slice();
    while let Some((first, tail)) = rest.split_first() {
        if is_assignment(first) {
            if !writes::harmless_assignment(first) {
                return None;
            }
            rest = tail;
        } else if first == "sudo" {
            rest = &tail[tail.iter().take_while(|w| w.starts_with('-')).count()..];
        } else if let Some(command) = (first == "env").then(|| writes::env_command(tail)).flatten() {
            rest = command;
        } else {
            break;
        }
    }
    Some(rest.to_vec())
}

fn is_assignment(word: &str) -> bool {
    ENV_ASSIGN.is_match(word)
}

/// SS-10: programs that stay open and read keys in the terminal: pagers, whose `!command` runs a
/// command (less, more, pg; less's `v` and most's `E` open an editor), man (it shows its page in one),
/// editors (`:!command`) and fc (it runs what is saved in its editor). In MultiExec they open in every
/// terminal, where keys pass straight through unrated, so a line that starts one is never read-only.
/// A Compare run has no terminal to type into, so there they stay as the read-only list says.
const INTERACTIVE: &[&str] = &[
    "less", "more", "most", "pg", "man", "vi", "vim", "view", "nvim", "vimdiff", "ex", "nano", "emacs", "ed", "fc",
];

/// SS-10: the first program in the script that stays open and reads keys ([`INTERACTIVE`]), as the
/// command of any part of it (after `sudo`, `env` and assignments; `/usr/bin/less` is less).
pub(crate) fn interactive_program(script: &str) -> Option<&'static str> {
    let without_redirects = REDIRECT.replace_all(script, " ");
    SEPARATOR.split(&without_redirects).find_map(|segment| {
        let words = command_words(segment).unwrap_or_else(|| shell_words(segment));
        let first = words.first()?;
        let name = first.rsplit('/').next().unwrap_or(first);
        INTERACTIVE.iter().find(|program| **program == name).copied()
    })
}

/// The words of one command as the shell splits them: quotes (`'…'`, `"…"`, `$'…'`) and backslashes
/// removed, a `#` comment dropped. Expansions stay as written: `$HOME` is still `$HOME`.
fn shell_words(segment: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = segment.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => words.extend(word.take()),
            '#' if word.is_none() => break,
            // `$'…'` and `$"…"` are quotes too; the next round reads them.
            '$' if matches!(chars.peek(), Some('\'' | '"')) => {}
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                w.extend(chars.by_ref().take_while(|&c| c != '\''));
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' if matches!(chars.peek(), Some('"' | '\\' | '$' | '`')) => w.extend(chars.next()),
                        c => w.push(c),
                    }
                }
            }
            '\\' => {
                let w = word.get_or_insert_with(String::new);
                w.extend(chars.next());
            }
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    words
}
