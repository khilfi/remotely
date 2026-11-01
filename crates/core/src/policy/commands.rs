//! Classifying shell commands for bulk execution: dangerous (BX-06) or read-only.

mod writes;

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::ActionKind;

/// A named regex. A command that matches any of them goes to the approval flow as High. It is tested
/// against the script as typed and against each of its commands as the shell reads them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DangerousPattern {
    pub name: String,
    pub pattern: String,
}

/// Start of a command word: line start, whitespace, a shell separator, `(` or a path slash.
const W: &str = r"(?:^|[\s;&|(/`])";
/// The words between a command and the one a pattern looks for, within the same command.
const A: &str = r"(?:[^;&|\n]*\s)?";
/// End of a word: whitespace, the end, or a shell separator.
const E: &str = r"(?:$|[\s;&|)`])";
/// A disk or a volume on one, as `/dev` names it (a partition's name goes on from these).
const DISK: &str = r"/dev/(?:sd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|hd[a-z]|mmcblk\d|dm-\d|md\d|mapper/|disk/)";
/// `/` itself, everything in it (`/*`), or one of the folders the system runs from.
const SYSTEM_DIR: &str = r"/(?:(?:etc|usr|var|bin|sbin|lib|lib32|lib64|libx32|boot|home|dev)/?)?\*?";

/// BX-06: the default rules. Each is a regular expression tested against the script as typed and
/// against each command as the shell reads it (quotes and backslashes removed, `sudo`, `env` and
/// `NAME=value` in front dropped, see `shell_commands`), so `\rm -rf /` and `"rm" -rf /` match like
/// `rm -rf /`. Saved rules keep their own list: these apply to new and default rules.
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
        // 0.4.1. Disks: signatures, partition tables, discards, LVM and RAID metadata. Each leaves
        // the forms that only show alone (`wipefs` lists, `parted -l`, `sfdisk -l`, `mdadm --detail`).
        p(
            "wipefs -a",
            format!(r"{W}wipefs\s+{A}(?:-[a-zA-Z]*[ao]\S*|--all|--offset)(?:[\s=]|$)"),
        ),
        p(
            "sgdisk zap / new / delete",
            format!(
                r"{W}sgdisk\s+{A}(?:-[a-zA-Z]*[ZzondNl]\S*|--(?:zap-all|zap|clear|new|largest-new|delete|load-backup)(?:=\S*)?)(?:\s|$)"
            ),
        ),
        p(
            "parted mklabel / mkpart / rm",
            format!(r"{W}parted\s+{A}(?:mklabel|mktable|mkpart|mkpartfs|rm|resizepart){E}"),
        ),
        // sfdisk writes the partition table unless it only lists, dumps, shows, verifies or does a dry
        // run: every word up to the end of the command is anything but one of those options.
        p(
            "sfdisk (writes)",
            format!(
                r"{W}sfdisk(?:[ \t]+(?:[^\s;&|\-][^\s;&|]*|-[^\s;&|\-ldsVJgFThvGn][^\s;&|ldsVJgFThvGn]*|--(?:[abcefgikmopqrtuwxyzA-Z]|d[ei]|l[ao]|no-[rt]|se)[^\s;&|]*))*[ \t]*(?:$|[;&|\r\n)])"
            ),
        ),
        p("blkdiscard", format!(r"{W}blkdiscard{E}")),
        p("pvremove / vgremove / lvremove", format!(r"{W}(?:pv|vg|lv)remove{E}")),
        p(
            "mdadm --create / --zero-superblock",
            format!(r"{W}mdadm\s+{A}(?:--zero[-a-z]*|--create|-[a-zA-Z]*C[a-zA-Z]*)(?:[\s=]|$)"),
        ),
        // Firewalls and SSH: what can lock everyone out of the host, this app included.
        p(
            "iptables -P … DROP",
            format!(r"{W}ip6?tables(?:-legacy|-nft)?\s+{A}(?:-P|--policy)\s+\S+\s+DROP{E}"),
        ),
        p(
            "nft flush ruleset",
            format!(r#"{W}nft\s+(?:[^;&|\n]*[\s'"])?flush\s+ruleset(?:$|[\s;&|)'"])"#),
        ),
        p(
            "ufw enable / default deny",
            format!(r"{W}ufw\s+{A}(?:enable{E}|default\s+(?:deny|reject)(?:\s+incoming{E}|[ \t]*(?:$|[;&|)\r\n])))"),
        ),
        p(
            "firewall-cmd --panic-on",
            format!(r"{W}firewall-cmd\s+{A}--panic-on{E}"),
        ),
        p(
            "stop sshd",
            format!(
                r"{W}systemctl\s+{A}(?:stop|disable|mask|kill)\s+{A}sshd?(?:\.service|\.socket)?{E}|{W}(?:service|rc-service)\s+sshd?\s+stop{E}|init\.d/sshd?\s+stop{E}"
            ),
        ),
        p(
            "network interface down",
            format!(r"{W}ip\s+{A}l(?:i(?:nk?)?)?\s+s(?:et?)?\s+{A}down{E}|{W}ifdown{E}|{W}ifconfig\s+\S+\s+down{E}"),
        ),
        // `kill -9 -1`, `kill -s KILL -1`, `kill -- -1`: a signal to every process the user may signal.
        p("kill -1 (every process)", format!(r"{W}kill\s+{A}-\S+\s+{A}-1{E}")),
        p(
            "chmod / chown -R on a system folder",
            format!(
                r"{W}ch(?:mod|own|grp)\s+{A}(?:(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)\s+{A}{SYSTEM_DIR}|{SYSTEM_DIR}\s+{A}(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)){E}"
            ),
        ),
        p(
            "write to a disk device",
            format!(
                r#">\|?\s*['"]?{DISK}|{W}(?:tee|shred)\s+{A}['"]?{DISK}|{W}cp\s+{A}['"]?{DISK}\S*[ \t]*(?:$|[;&|)\r\n])"#
            ),
        ),
        p("fork bomb", r"\(\s*\)\s*\{\s*[\w:.-]+\s*\|\s*[\w:.-]+\s*&\s*\}".into()),
        // SQL: TABLE needs a name after it, so `echo "drop table"` is not flagged. A TRUNCATE without
        // TABLE is SQL too; the `truncate` program takes options first (`truncate -s 0 file`).
        p(
            "DROP TABLE / TRUNCATE",
            r#"(?i)\bdrop\s+table\s+[\w"`\[]|\btruncate\s+(?:table\s+)?[\w"`\[]"#.into(),
        ),
        p("kubectl delete", format!(r"{W}(?:kubectl|oc)\s+{A}delete{E}")),
        // Containers: rated like the same action on the Containers page, where pruning is High and
        // removing volumes is Critical (`container_actions` gives the tier; these mark them dangerous).
        p(
            "docker / podman prune",
            format!(r"{W}(?:docker|podman)\s+{A}(?:system|container|image|volume|builder|buildx)\s+prune{E}"),
        ),
        p(
            "docker / podman volume rm",
            format!(r"{W}(?:docker|podman)\s+{A}volume\s+(?:rm|remove){E}"),
        ),
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
        // FD-05: the inventory's package list. dpkg-query only reads the package database: it has no writing form.
        "dpkg-query",
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

/// BX-06: one command of a script as the shell reads it, for the dangerous-command rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShellCommand {
    /// Where the part of the script it comes from starts (a byte offset), for the line it is on.
    pub at: usize,
    /// The command and its arguments: quotes and backslashes removed, and `sudo`, `doas`, `env` and
    /// `NAME=value` settings in front of it dropped.
    pub words: Vec<String>,
}

impl ShellCommand {
    /// The words on one line, for the rules' regular expressions. A word holding a space (a quoted
    /// argument) is put back in single quotes, so `echo "rm -rf /"` does not read as `rm -rf /`.
    pub fn line(&self) -> String {
        self.words
            .iter()
            .map(|w| {
                if w.is_empty() || w.contains(char::is_whitespace) {
                    format!("'{w}'")
                } else {
                    w.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Programs that run a script given as one argument (`sh -c '…'`, `su -c '…'`, `ssh host '…'`,
/// `eval '…'`, `env -S '…'`). After one of them, an argument with spaces is read as a script too.
const SCRIPT_RUNNERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "busybox", "su", "runuser", "eval", "ssh", "watch",
    "env",
];

/// How deep `sh -c "bash -c '…'"` is followed.
const MAX_NESTING: usize = 3;

/// BX-06: the commands a script runs, split where the shell splits them, each with its words as the
/// shell reads them. An argument of `sh -c`, `su -c`, `ssh`, `eval`… that holds a script adds that
/// script's commands (at the same place). Dangerous-command rules are tested against these as well as
/// against the script as typed.
pub(crate) fn shell_commands(script: &str) -> Vec<ShellCommand> {
    let mut out = Vec::new();
    add_commands(script, None, 0, &mut out);
    out
}

fn add_commands(script: &str, at: Option<usize>, depth: usize, out: &mut Vec<ShellCommand>) {
    let mut start = 0;
    let mut ends: Vec<(usize, usize)> = SEPARATOR.find_iter(script).map(|m| (m.start(), m.end())).collect();
    ends.push((script.len(), script.len()));
    for (end, next) in ends {
        let segment = &script[start..end];
        let here = at.unwrap_or(start + (segment.len() - segment.trim_start().len()));
        start = next;
        let all = shell_words(segment);
        let words = command_and_args(&all);
        if words.is_empty() {
            continue;
        }
        out.push(ShellCommand {
            at: here,
            words: words.to_vec(),
        });
        if depth >= MAX_NESTING {
            continue;
        }
        if let Some(runner) = all.iter().position(|w| SCRIPT_RUNNERS.contains(&base_name(w))) {
            for inner in all[runner + 1..].iter().filter(|w| w.contains(char::is_whitespace)) {
                add_commands(inner, Some(here), depth + 1, out);
            }
        }
    }
}

/// `/usr/bin/rm` is `rm`.
pub(crate) fn base_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Options of `sudo` and `doas` that take the next word as their value (`-u alice`, `--user alice`).
const SUDO_SHORT_VALUES: &str = "CDRTUcghprtu";
const SUDO_LONG_VALUES: &[&str] = &[
    "chdir",
    "chroot",
    "close-from",
    "command-timeout",
    "group",
    "host",
    "login-class",
    "other-user",
    "prompt",
    "role",
    "type",
    "user",
];
/// Options of `env` that take the next word as their value (`-u NAME`, `-C DIR`).
const ENV_SHORT_VALUES: &str = "uC";
const ENV_LONG_VALUES: &[&str] = &["unset", "chdir"];

/// The command a segment runs and its arguments, without what only sets up how it runs: `NAME=value`
/// settings, `sudo` or `doas` and their options, `env` and its options. Unlike [`command_words`], any
/// setting is dropped: this finds what runs, it does not judge whether it only reads.
fn command_and_args(words: &[String]) -> &[String] {
    let mut rest = words;
    while let Some((first, tail)) = rest.split_first() {
        rest = if is_assignment(first) {
            tail
        } else {
            match base_name(first) {
                "sudo" | "doas" => skip_options(tail, SUDO_SHORT_VALUES, SUDO_LONG_VALUES),
                "env" => skip_options(tail, ENV_SHORT_VALUES, ENV_LONG_VALUES),
                _ => break,
            }
        };
    }
    rest
}

/// `words` after the options in front of them (and the values of those that take one), and after `--`.
fn skip_options<'a>(words: &'a [String], short_values: &str, long_values: &[&str]) -> &'a [String] {
    let mut at = 0;
    while let Some(word) = words.get(at) {
        if word == "--" {
            return &words[at + 1..];
        }
        if !word.starts_with('-') {
            break;
        }
        at += 1;
        let takes_value = match word.strip_prefix("--") {
            Some(name) => !name.contains('=') && long_values.contains(&name),
            None => {
                // In a cluster (`-iu alice`) the first letter that takes a value takes the rest of the
                // word, or the next word when it ends the cluster.
                let cluster = &word[1..];
                cluster
                    .char_indices()
                    .find(|(_, c)| short_values.contains(*c))
                    .is_some_and(|(i, c)| i + c.len_utf8() == cluster.len())
            }
        };
        if takes_value {
            at += 1;
        }
    }
    &words[at.min(words.len())..]
}

/// CT-01, BX-06: a command that prunes or removes what the Containers page does, found in a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerAction {
    /// What was found, as `docker volume prune` or `podman system prune --volumes`.
    pub what: String,
    /// The Containers page's actions it does: `system prune` is three (four with `--volumes`).
    pub kinds: Vec<ActionKind>,
}

/// CT-01, BX-06: the prunes and volume removals among a script's commands, so Compare and MultiExec
/// rate them like the Containers page does (`docker volume prune` deletes data: Critical there).
pub(crate) fn container_actions(commands: &[ShellCommand]) -> Vec<ContainerAction> {
    let mut out: Vec<ContainerAction> = Vec::new();
    for command in commands {
        let words = &command.words;
        // `docker`, `/usr/bin/podman`, or after `nohup`, `timeout 60`, `xargs`...
        let Some(engine_at) = words
            .iter()
            .position(|w| matches!(base_name(w), "docker" | "podman" | "docker.exe" | "podman.exe"))
        else {
            continue;
        };
        let engine = base_name(&words[engine_at]).trim_end_matches(".exe");
        let args = &words[engine_at + 1..];
        for (i, pair) in args.windows(2).enumerate() {
            let after = &args[i + 2..];
            let volumes = after
                .iter()
                .any(|w| w == "--volumes" || w == "--volumes=true" || w == "--volumes=1");
            let (kinds, flag) = match (pair[0].as_str(), pair[1].as_str()) {
                ("volume", "prune") => (vec![ActionKind::PruneVolumes], ""),
                ("volume", "rm" | "remove") => (vec![ActionKind::VolumeRemove], ""),
                ("system", "prune") if volumes => (
                    vec![
                        ActionKind::PruneContainers,
                        ActionKind::PruneImages,
                        ActionKind::PruneBuildCache,
                        ActionKind::PruneVolumes,
                    ],
                    " --volumes",
                ),
                ("system", "prune") => (
                    vec![
                        ActionKind::PruneContainers,
                        ActionKind::PruneImages,
                        ActionKind::PruneBuildCache,
                    ],
                    "",
                ),
                ("container", "prune") => (vec![ActionKind::PruneContainers], ""),
                ("image", "prune") => (vec![ActionKind::PruneImages], ""),
                ("builder" | "buildx", "prune") => (vec![ActionKind::PruneBuildCache], ""),
                _ => continue,
            };
            let what = format!("{engine} {} {}{flag}", pair[0], pair[1]);
            if !out.iter().any(|a| a.what == what) {
                out.push(ContainerAction { what, kinds });
            }
            break;
        }
    }
    out
}

/// SS-10: programs that stay open and read keys in the terminal: pagers, whose `!command` runs a
/// command (less, more, pg; less's `v` and most's `E` open an editor), man (it shows its page in one),
/// editors (`:!command`) and fc (it runs what is saved in its editor). In MultiExec they open in every
/// terminal, where keys pass straight through unrated, so a line that starts one is never read-only.
/// A Compare run has no terminal to type into, so there they stay as the read-only list says.
const INTERACTIVE: &[&str] = &[
    "less", "more", "most", "pg", "man", "vi", "vim", "view", "nvim", "vimdiff", "ex", "nano", "emacs", "ed", "fc",
];

/// SS-10 (review B7): programs that take over the whole screen (xterm's alternate buffer) and read keys, beyond the
/// editors and pagers of [`INTERACTIVE`]: the monitors and multiplexers. MultiExec trusts a tab's alternate-screen flag
/// (keys pass straight through unrated) only after it released a line that started one of these, so this list need not
/// match the policy engine's rating list. It is not exhaustive; a program missing from it is only rated as usual.
const FULL_SCREEN: &[&str] = &[
    "top",
    "htop",
    "btop",
    "atop",
    "glances",
    "watch",
    "tmux",
    "screen",
    "mc",
    "ncdu",
    "tig",
    "lazygit",
    "lazydocker",
    "nmon",
    "iotop",
    "iftop",
    "nethogs",
    "ranger",
    "vifm",
    "gdb",
    "k9s",
];

/// The first program in the script drawn from `list`, as the command of any part of it (after `sudo`, `env` and
/// assignments; `/usr/bin/less` is less).
fn first_program_in<'a>(script: &str, list: &'a [&'a str]) -> Option<&'a str> {
    let without_redirects = REDIRECT.replace_all(script, " ");
    SEPARATOR.split(&without_redirects).find_map(|segment| {
        let words = command_words(segment).unwrap_or_else(|| shell_words(segment));
        let first = words.first()?;
        let name = first.rsplit('/').next().unwrap_or(first);
        list.iter().find(|program| **program == name).copied()
    })
}

/// SS-10: the first program in the script that stays open and reads keys ([`INTERACTIVE`]), used by the policy engine
/// to rate a line that opens one as not read-only.
pub(crate) fn interactive_program(script: &str) -> Option<&'static str> {
    first_program_in(script, INTERACTIVE)
}

/// SS-10 (review B7): the first full-screen program the script starts — an editor or pager ([`INTERACTIVE`]) or a
/// monitor or multiplexer ([`FULL_SCREEN`]). MultiExec uses it to decide whether a tab's alternate-screen flag is real.
pub(crate) fn full_screen_program(script: &str) -> Option<&'static str> {
    first_program_in(script, INTERACTIVE).or_else(|| first_program_in(script, FULL_SCREEN))
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
