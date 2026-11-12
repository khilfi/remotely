//! VM-28: Anaconda's kickstart (RHEL, Rocky, Alma, Oracle Linux, Fedora, CentOS Stream).
//!
//! A kickstart is one command a line, split as pykickstart splits it (shell-style quotes; `#` at a word's start begins
//! a comment), and sections (`%packages`, `%pre`, `%post`...) that end with `%end`. Anaconda stops on a command it
//! doesn't know, so an unknown one is an error here too. The form changes single lines (and the users' and keys' lines,
//! the `%packages` list, the first `%post`), so every other line stays as it was.

use super::form::{
    netmask, prefix_of, FieldState, FormField, FormRead, InstallForm, NetworkForm, StorageForm, StorageLayout, Swap,
    UserForm,
};
use super::{is_sample_secret, looks_hashed, ConfigProblem, Severity};

/// Anaconda's commands (RHEL 9, Fedora).
const COMMANDS: &[&str] = &[
    "authselect",
    "autopart",
    "autostep",
    "bootc",
    "bootloader",
    "btrfs",
    "cdrom",
    "clearpart",
    "cmdline",
    "device",
    "driverdisk",
    "eula",
    "fcoe",
    "firewall",
    "firstboot",
    "graphical",
    "group",
    "halt",
    "harddrive",
    "hmc",
    "ignoredisk",
    "iscsi",
    "iscsiname",
    "keyboard",
    "lang",
    "liveimg",
    "logging",
    "logvol",
    "mediacheck",
    "module",
    "mount",
    "network",
    "nfs",
    "nvdimm",
    "ostreecontainer",
    "ostreesetup",
    "part",
    "partition",
    "poweroff",
    "raid",
    "realm",
    "reboot",
    "repo",
    "reqpart",
    "rescue",
    "rhsm",
    "rootpw",
    "selinux",
    "services",
    "shutdown",
    "skipx",
    "snapshot",
    "sshkey",
    "sshpw",
    "syspurpose",
    "text",
    "timesource",
    "timezone",
    "updates",
    "url",
    "user",
    "vnc",
    "volgroup",
    "xconfig",
    "zerombr",
    "zfcp",
    "zipl",
];

/// Commands older Anacondas took and RHEL 9's refuses.
const REMOVED: &[&str] = &[
    "auth",
    "authconfig",
    "deviceprobe",
    "dmraid",
    "install",
    "interactive",
    "langsupport",
    "method",
    "monitor",
    "multipath",
    "upgrade",
];

const SECTIONS: &[&str] = &[
    "%packages",
    "%pre",
    "%pre-install",
    "%post",
    "%onerror",
    "%traceback",
    "%addon",
    "%anaconda",
    "%certificate",
];

/// Options that take the next word as their value when written without `=`.
const VALUE_OPTIONS: &[&str] = &[
    "name",
    "password",
    "groups",
    "bootproto",
    "ip",
    "netmask",
    "gateway",
    "nameserver",
    "hostname",
    "device",
    "type",
    "url",
    "proxy",
    "mirrorlist",
    "metalink",
    "xlayouts",
    "vckeymap",
    "username",
    "size",
    "fstype",
    "vgname",
    "ondisk",
    "maxsize",
    "label",
    "ntpservers",
    "enabled",
    "disabled",
    "uid",
    "gid",
    "homedir",
    "shell",
    "gecos",
    "addsupport",
    "location",
    "append",
    "timeout",
    "baseurl",
    "dir",
    "server",
    "drives",
    "only-use",
    "fsoptions",
    "onpart",
];

/// Single commands: written twice, Anaconda takes the last.
const SINGLE: &[&str] = &[
    "lang",
    "keyboard",
    "timezone",
    "rootpw",
    "bootloader",
    "autopart",
    "clearpart",
    "selinux",
    "firewall",
];

const SOURCES: &[&str] = &[
    "cdrom",
    "url",
    "harddrive",
    "nfs",
    "liveimg",
    "ostreesetup",
    "ostreecontainer",
    "bootc",
];

/// Options without a value.
const FLAG_OPTIONS: &[&str] = &[
    "iscrypted",
    "plaintext",
    "lock",
    "allow-ssh",
    "sshkey",
    "activate",
    "noswap",
    "utc",
    "nochroot",
    "grow",
    "encrypted",
    "all",
    "initlabel",
    "eject",
    "noipv6",
    "nodefroute",
    "nontp",
    "disable",
    "enable",
    "erroronfail",
];

/// An option as Anaconda reads it: pykickstart's argparse takes an unambiguous prefix of a known option (`--pa` is
/// `--password`), so the checks read it whole too (review of #88). An unknown or ambiguous one stays as written.
fn full_option(name: &str) -> String {
    if name.len() < 2 || VALUE_OPTIONS.contains(&name) || FLAG_OPTIONS.contains(&name) {
        return name.to_owned();
    }
    let mut matches = VALUE_OPTIONS.iter().chain(FLAG_OPTIONS).filter(|o| o.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(only), None) => (*only).to_owned(),
        _ => name.to_owned(),
    }
}

/// A line split into words as pykickstart does; an unclosed quote is an error.
pub(crate) fn words(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some('"') => match c {
                '\\' => match chars.next() {
                    Some(n @ ('"' | '\\' | '$' | '`')) => cur.push(n),
                    Some(n) => {
                        cur.push('\\');
                        cur.push(n);
                    }
                    None => cur.push('\\'),
                },
                '"' => quote = None,
                c => cur.push(c),
            },
            Some(_) => {
                if c == '\'' {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c.is_whitespace() {
                    if in_word {
                        out.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                } else if c == '#' && !in_word {
                    break;
                } else if c == '"' || c == '\'' {
                    quote = Some(c);
                    in_word = true;
                } else if c == '\\' {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                    in_word = true;
                } else {
                    cur.push(c);
                    in_word = true;
                }
            }
        }
    }
    if quote.is_some() {
        return Err("A quote isn't closed on this line.".into());
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
}

/// A word as a kickstart line writes it: bare when safe, else double-quoted (a placeholder is always quoted, as its
/// value may hold spaces).
pub(crate) fn word(text: &str) -> String {
    let safe = !text.is_empty()
        && !text.contains("{{")
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:=,@+%-$^".contains(c));
    if safe {
        return text.to_owned();
    }
    if let Some((opt, value)) = text.split_once('=').filter(|(o, _)| o.starts_with("--")) {
        return format!("{opt}={}", quote(value));
    }
    quote(text)
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        if matches!(c, '"' | '\\' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// A command's options and positional words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Args {
    pub options: Vec<(String, Option<String>)>,
    pub positional: Vec<String>,
}

impl Args {
    pub fn parse(words: &[String]) -> Self {
        let mut out = Args::default();
        let mut i = 0;
        while i < words.len() {
            let w = &words[i];
            if let Some(opt) = w.strip_prefix("--") {
                match opt.split_once('=') {
                    Some((name, value)) => out.options.push((full_option(name), Some(value.to_owned()))),
                    None if VALUE_OPTIONS.contains(&full_option(opt).as_str())
                        && words.get(i + 1).is_some_and(|n| !n.starts_with("--")) =>
                    {
                        out.options.push((full_option(opt), words.get(i + 1).cloned()));
                        i += 1;
                    }
                    None => out.options.push((full_option(opt), None)),
                }
            } else {
                out.positional.push(w.clone());
            }
            i += 1;
        }
        out
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    pub fn has(&self, name: &str) -> bool {
        self.options.iter().any(|(n, _)| n == name)
    }

    pub fn set(&mut self, name: &str, value: Option<&str>) {
        self.options.retain(|(n, _)| n != name);
        if let Some(v) = value {
            self.options.push((name.to_owned(), Some(v.to_owned())));
        }
    }

    pub fn flag(&mut self, name: &str, on: bool) {
        self.options.retain(|(n, _)| n != name);
        if on {
            self.options.push((name.to_owned(), None));
        }
    }

    /// `command --opt=value ... positional`.
    pub fn line(&self, command: &str) -> String {
        let mut out = vec![command.to_owned()];
        for (name, value) in &self.options {
            out.push(match value {
                Some(v) => word(&format!("--{name}={v}")),
                None => format!("--{name}"),
            });
        }
        out.extend(self.positional.iter().map(|p| word(p)));
        out.join(" ")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Command {
    /// The line, from 0.
    pub at: usize,
    pub name: String,
    pub args: Args,
}

#[derive(Debug, Clone)]
pub(crate) struct Section {
    pub at: usize,
    pub name: String,
    pub args: Args,
    /// The `%end` line.
    pub end: Option<usize>,
}

pub(crate) struct Scan {
    pub lines: Vec<String>,
    pub commands: Vec<Command>,
    pub sections: Vec<Section>,
    pub problems: Vec<ConfigProblem>,
}

fn line_no(at: usize) -> Option<u32> {
    u32::try_from(at + 1).ok()
}

pub(crate) fn scan(text: &str) -> Scan {
    let lines: Vec<String> = text.split('\n').map(|l| l.trim_end_matches('\r').to_owned()).collect();
    let mut commands = Vec::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut problems = Vec::new();
    let mut open: Option<usize> = None;
    for (at, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(i) = open {
            if trimmed == "%end" {
                sections[i].end = Some(at);
                open = None;
            } else if trimmed.starts_with('%') && SECTIONS.iter().any(|s| trimmed.split_whitespace().next() == Some(*s))
            {
                problems.push(ConfigProblem::error(
                    line_no(sections[i].at),
                    format!("{} isn't closed with %end before the next section.", sections[i].name),
                ));
                open = None;
            } else {
                continue;
            }
            if open.is_none() && trimmed == "%end" {
                continue;
            }
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let ws = match words(line) {
            Ok(ws) => ws,
            Err(why) => {
                problems.push(ConfigProblem::error(line_no(at), why));
                continue;
            }
        };
        let Some((first, rest)) = ws.split_first() else {
            continue;
        };
        if first.starts_with('%') {
            match first.as_str() {
                "%end" => problems.push(ConfigProblem::error(line_no(at), "%end without a section to end.")),
                "%include" | "%ksappend" => problems.push(ConfigProblem::warning(
                    line_no(at),
                    format!("{first} reads another file, which Remotely can't check or deliver with this one."),
                )),
                name if SECTIONS.contains(&name) => {
                    sections.push(Section {
                        at,
                        name: name.to_owned(),
                        args: Args::parse(rest),
                        end: None,
                    });
                    open = Some(sections.len() - 1);
                }
                other => problems.push(ConfigProblem::error(
                    line_no(at),
                    format!("{other} isn't a kickstart section: use %packages, %pre, %post and the like."),
                )),
            }
            continue;
        }
        commands.push(Command {
            at,
            name: first.clone(),
            args: Args::parse(rest),
        });
    }
    if let Some(i) = open {
        problems.push(ConfigProblem::error(
            line_no(sections[i].at),
            format!("{} isn't closed with %end.", sections[i].name),
        ));
    }
    Scan {
        lines,
        commands,
        sections,
        problems,
    }
}

/// Line syntax: sections closed, quotes closed, every command one Anaconda knows.
pub fn syntax(text: &str) -> Vec<ConfigProblem> {
    let scan = scan(text);
    let mut out = scan.problems;
    for c in &scan.commands {
        if REMOVED.contains(&c.name.as_str()) {
            out.push(ConfigProblem::error(
                line_no(c.at),
                format!("{} was removed from Anaconda (RHEL 9): it stops the install.", c.name),
            ));
        } else if !COMMANDS.contains(&c.name.as_str()) {
            out.push(ConfigProblem::error(
                line_no(c.at),
                format!("Anaconda doesn't know the command {}: it stops the install.", c.name),
            ));
        }
    }
    out
}

/// Syntax, each command's required pieces, secrets in the file and lock-outs.
pub fn check(text: &str) -> Vec<ConfigProblem> {
    let mut out = syntax(text);
    let scan = scan(text);
    let cmds = |name: &'static str| {
        scan.commands
            .iter()
            .filter(move |c| c.name == name || (name == "part" && c.name == "partition"))
    };
    for name in SINGLE {
        let all: Vec<&Command> = cmds(name).collect();
        if all.len() > 1 {
            out.push(ConfigProblem::warning(
                line_no(all[1].at),
                format!("{name} is written twice: Anaconda takes the last."),
            ));
        }
    }
    let sources: Vec<&Command> = scan
        .commands
        .iter()
        .filter(|c| SOURCES.contains(&c.name.as_str()))
        .collect();
    if sources.len() > 1 {
        out.push(ConfigProblem::error(
            line_no(sources[1].at),
            "The file names more than one installation source (cdrom, url...): keep one.",
        ));
    }
    for c in &scan.commands {
        let at = line_no(c.at);
        match c.name.as_str() {
            "lang" | "timezone" if c.args.positional.is_empty() => {
                out.push(ConfigProblem::error(
                    at,
                    format!(
                        "{} needs its value, such as {}.",
                        c.name,
                        if c.name == "lang" {
                            "lang en_US.UTF-8"
                        } else {
                            "timezone Etc/UTC"
                        }
                    ),
                ));
            }
            "user" if c.args.get("name").is_none() => out.push(ConfigProblem::error(at, "user needs --name.")),
            "network" => {
                if let Some(bp) = c.args.get("bootproto") {
                    if !["dhcp", "bootp", "static", "ibft", "query"].contains(&bp) {
                        out.push(ConfigProblem::error(
                            at,
                            format!("network --bootproto takes dhcp or static, not {bp}."),
                        ));
                    }
                    if bp == "static" && (c.args.get("ip").is_none() || c.args.get("netmask").is_none()) {
                        out.push(ConfigProblem::error(at, "A static network needs --ip and --netmask."));
                    }
                }
            }
            "autopart" => {
                if let Some(t) = c.args.get("type") {
                    if !["lvm", "btrfs", "plain", "thinp"].contains(&t) {
                        out.push(ConfigProblem::error(
                            at,
                            format!("autopart --type takes lvm, btrfs, plain or thinp, not {t}."),
                        ));
                    }
                }
            }
            "part" | "partition" if c.args.positional.is_empty() => {
                out.push(ConfigProblem::error(
                    at,
                    "part needs its mount point, such as part / or part swap.",
                ));
            }
            _ => {}
        }
    }
    let manual = scan
        .commands
        .iter()
        .find(|c| matches!(c.name.as_str(), "part" | "partition" | "logvol" | "volgroup" | "raid"));
    if let (Some(auto), Some(m)) = (cmds("autopart").next(), manual) {
        out.push(ConfigProblem::error(
            line_no(auto.at.max(m.at)),
            format!(
                "autopart can't be used with {}: keep one way of laying the disk out.",
                m.name
            ),
        ));
    }
    if !scan
        .commands
        .iter()
        .any(|c| matches!(c.name.as_str(), "reboot" | "poweroff" | "shutdown" | "halt"))
    {
        out.push(ConfigProblem::warning(
            None,
            "Anaconda waits at the end of the install: add reboot so the VM starts the system by itself.",
        ));
    }
    if scan.commands.iter().any(|c| c.name == "graphical") {
        out.push(ConfigProblem::warning(
            None,
            "graphical runs the installer's window; text is quicker and needs nothing from you.",
        ));
    }
    // Secrets.
    for c in &scan.commands {
        let at = line_no(c.at);
        let crypted = c.args.has("iscrypted");
        let (what, value) = match c.name.as_str() {
            // Locked or not, a password written here is kept in the file (review of #88).
            "rootpw" => ("rootpw", c.args.positional.first().map(String::as_str)),
            "user" => ("user's --password", c.args.get("password")),
            "sshpw" if !c.args.has("sshkey") => ("sshpw", c.args.positional.first().map(String::as_str)),
            "bootloader" => ("bootloader's --password", c.args.get("password")),
            _ => continue,
        };
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            continue;
        };
        if is_sample_secret(value) {
            if !crypted {
                out.push(ConfigProblem::error(
                    at,
                    format!("{what} needs --iscrypted: Remotely writes the password as a hash."),
                ));
            }
            continue;
        }
        let why = if looks_hashed(value) {
            format!("{what} holds a password hash: a config never keeps one. Pick the password from the vault in the form, or write --iscrypted --password=\"{{{{password.<name>}}}}\".")
        } else {
            format!("{what} holds a password: a config never keeps one. Pick it from the vault in the form, or write --iscrypted with {{{{password.<name>}}}}.")
        };
        out.push(ConfigProblem::secret(at, why));
    }
    // Lock-outs.
    let users: Vec<&Command> = cmds("user").collect();
    let root = cmds("rootpw").next_back();
    let keys: Vec<&Command> = cmds("sshkey").collect();
    if users.is_empty() && root.is_none() {
        out.push(ConfigProblem::error(
            None,
            "No user and no root password: Anaconda stops to ask for one. Add a user.",
        ));
    }
    let any_password = users
        .iter()
        .any(|u| u.args.get("password").is_some() && !u.args.has("lock"))
        || root.is_some_and(|r| !r.args.has("lock") && !r.args.positional.is_empty());
    if keys.is_empty() && !any_password && (!users.is_empty() || root.is_some()) {
        out.push(ConfigProblem::warning(
            None,
            "No password works and no SSH key is set: nobody can sign in. Give a user a key or a password.",
        ));
    }
    if users.is_empty() {
        if let Some(r) = root {
            let root_key = keys.iter().any(|k| k.args.get("username") == Some("root"));
            if !root_key && !r.args.has("allow-ssh") && !r.args.has("lock") {
                out.push(ConfigProblem::warning(line_no(r.at), "Only root can sign in, and RHEL 9 doesn't let root sign in over SSH with a password: add a user, root's key, or rootpw --allow-ssh."));
            }
        }
    }
    for s in cmds("services") {
        if s.args
            .get("disabled")
            .is_some_and(|d| d.split(',').any(|x| x.trim() == "sshd"))
        {
            out.push(ConfigProblem::warning(
                line_no(s.at),
                "sshd is turned off: nobody can sign in over SSH.",
            ));
        }
    }
    out.sort_by_key(|p| (p.line.unwrap_or(u32::MAX), p.severity == Severity::Warning));
    out
}

/// The partitions `part` sizes, in MB.
pub fn disk_need_mb(text: &str) -> Option<u64> {
    let scan = scan(text);
    let sizes: Vec<u64> = scan
        .commands
        .iter()
        .filter(|c| c.name == "part" || c.name == "partition")
        .filter_map(|c| c.args.get("size").and_then(|s| s.parse().ok()))
        .collect();
    (!sizes.is_empty()).then(|| sizes.iter().sum())
}

// ---- The form -------------------------------------------------------------------------------------------------------

fn fields() -> Vec<FieldState> {
    vec![
        FieldState::on(FormField::Hostname),
        FieldState::on(FormField::Locale),
        FieldState::on(FormField::Keyboard),
        FieldState::on(FormField::Timezone),
        FieldState::noted(FormField::Storage, "autopart chooses swap's size, or none."),
        FieldState::on(FormField::Network),
        FieldState::on(FormField::Users),
        FieldState::off(FormField::Ssh, "Anaconda installs and starts sshd itself."),
        FieldState::on(FormField::Packages),
        FieldState::off(
            FormField::Updates,
            "A kickstart installs what the mirror has: add dnf -y upgrade to the commands after the install.",
        ),
        FieldState::on(FormField::Proxy),
        FieldState::on(FormField::Mirror),
        FieldState::on(FormField::LateCommands),
    ]
}

/// The first `%post` that runs in the new system.
fn post(scan: &Scan) -> Option<&Section> {
    scan.sections
        .iter()
        .find(|s| s.name == "%post" && !s.args.has("nochroot"))
}

fn body(scan: &Scan, s: &Section) -> Vec<String> {
    let end = s.end.unwrap_or(scan.lines.len());
    let mut lines: Vec<String> = scan.lines[s.at + 1..end].to_vec();
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    lines
}

fn is_package_line(line: &str) -> bool {
    let t = line.trim();
    !(t.is_empty() || t.starts_with(['@', '-', '#', '%']))
}

pub fn read_form(body_text: &str) -> FormRead {
    let scan = scan(body_text);
    if let Some(p) = scan.problems.iter().find(|p| p.severity == Severity::Error) {
        return FormRead::unreadable(format!("Line {}: {}", p.line.unwrap_or(1), p.message));
    }
    let last = |name: &str| scan.commands.iter().rev().find(|c| c.name == name);
    let mut fields = fields();
    let manual = scan
        .commands
        .iter()
        .any(|c| matches!(c.name.as_str(), "part" | "partition" | "logvol" | "volgroup" | "raid"));
    let storage = if manual {
        super::cloud_init::set_off(
            &mut fields,
            FormField::Storage,
            "The file lays the disk out itself: edit its part lines.",
        );
        Some(StorageForm {
            layout: StorageLayout::Custom,
            swap: Swap::Auto,
        })
    } else {
        last("autopart").map(|a| StorageForm {
            layout: if a.args.get("type") == Some("plain") {
                StorageLayout::Plain
            } else {
                StorageLayout::Lvm
            },
            swap: if a.args.has("noswap") { Swap::None } else { Swap::Auto },
        })
    };
    let net = scan.commands.iter().find(|c| c.name == "network");
    let network = net.map(|n| match n.args.get("bootproto") {
        Some("static") => NetworkForm::Static {
            address: n.args.get("ip").unwrap_or_default().to_owned(),
            prefix: n.args.get("netmask").and_then(prefix_of).unwrap_or(24),
            gateway: n.args.get("gateway").map(str::to_owned),
            dns: n
                .args
                .get("nameserver")
                .map(|d| {
                    d.split(',')
                        .map(|x| x.trim().to_owned())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        },
        _ => NetworkForm::Dhcp,
    });
    let keys_of = |name: &str| -> Vec<String> {
        scan.commands
            .iter()
            .filter(|c| c.name == "sshkey" && c.args.get("username") == Some(name))
            .filter_map(|c| c.args.positional.first().cloned())
            .collect()
    };
    let users = scan
        .commands
        .iter()
        .filter(|c| c.name == "user")
        .filter_map(|u| {
            let name = u.args.get("name")?.to_owned();
            Some(UserForm {
                password: u
                    .args
                    .get("password")
                    .filter(|_| !u.args.has("lock"))
                    .map(str::to_owned),
                ssh_keys: keys_of(&name),
                sudo: u
                    .args
                    .get("groups")
                    .is_some_and(|g| g.split(',').any(|x| x.trim() == "wheel")),
                name,
            })
        })
        .collect();
    let packages = scan
        .sections
        .iter()
        .find(|s| s.name == "%packages")
        .map(|s| {
            body(&scan, s)
                .into_iter()
                .filter(|l| is_package_line(l))
                .map(|l| l.trim().to_owned())
                .collect()
        })
        .unwrap_or_default();
    let url = last("url");
    let form = InstallForm {
        hostname: scan
            .commands
            .iter()
            .rev()
            .find_map(|c| (c.name == "network").then(|| c.args.get("hostname")).flatten())
            .map(str::to_owned),
        locale: last("lang").and_then(|c| c.args.positional.first().cloned()),
        keyboard: last("keyboard").and_then(|c| {
            c.args
                .get("xlayouts")
                .and_then(|x| x.split(',').next())
                .map(|x| x.trim().to_owned())
                .or_else(|| c.args.positional.first().cloned())
                .or_else(|| c.args.get("vckeymap").map(str::to_owned))
        }),
        timezone: last("timezone").and_then(|c| c.args.positional.first().cloned()),
        storage,
        network,
        users,
        ssh: None,
        packages,
        updates: None,
        proxy: url.and_then(|u| u.args.get("proxy").map(str::to_owned)),
        mirror: url.and_then(|u| {
            u.args
                .get("url")
                .or_else(|| u.args.get("mirrorlist"))
                .map(str::to_owned)
        }),
        late_commands: post(&scan).map(|s| body(&scan, s)).unwrap_or_default(),
    };
    FormRead {
        form,
        fields,
        max_users: None,
        unreadable: None,
    }
}

/// Lines being edited; inserts go before the first section.
struct Edit {
    lines: Vec<String>,
}

impl Edit {
    fn insert_at(&self, scan: &Scan) -> usize {
        let first_section = scan.sections.first().map_or(self.lines.len(), |s| s.at);
        // After the last command before the sections, so new lines sit with the others.
        scan.commands
            .iter()
            .filter(|c| c.at < first_section)
            .map(|c| c.at + 1)
            .max()
            .unwrap_or(first_section.min(self.lines.len()))
    }
}

fn single(lines: &mut Vec<String>, scan: &Scan, name: &str, new: Option<String>) {
    match (scan.commands.iter().rev().find(|c| c.name == name), new) {
        (Some(c), Some(line)) => lines[c.at] = line,
        (Some(c), None) => lines[c.at] = String::from("\u{0}"),
        (None, Some(line)) => {
            let at = Edit { lines: lines.clone() }.insert_at(scan);
            lines.insert(at, line);
        }
        (None, None) => {}
    }
}

fn args_of(scan: &Scan, name: &str) -> Args {
    scan.commands
        .iter()
        .rev()
        .find(|c| c.name == name)
        .map(|c| c.args.clone())
        .unwrap_or_default()
}

/// Writes one field at a time, scanning again between them, so each line's position is right.
fn apply_one(text: &str, field: FormField, after: &InstallForm) -> Result<String, String> {
    let scan = scan(text);
    let mut lines = scan.lines.clone();
    let trimmed = |v: &Option<String>| v.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned);
    match field {
        FormField::Hostname => match scan.commands.iter().find(|c| c.name == "network") {
            Some(n) => {
                let mut args = n.args.clone();
                args.set("hostname", trimmed(&after.hostname).as_deref());
                lines[n.at] = args.line("network");
            }
            None => {
                if let Some(h) = trimmed(&after.hostname) {
                    let mut args = Args::default();
                    args.set("hostname", Some(&h));
                    single(&mut lines, &scan, "network", Some(args.line("network")));
                }
            }
        },
        FormField::Locale => {
            let mut args = args_of(&scan, "lang");
            args.positional = trimmed(&after.locale).into_iter().collect();
            single(
                &mut lines,
                &scan,
                "lang",
                (!args.positional.is_empty()).then(|| args.line("lang")),
            );
        }
        FormField::Keyboard => {
            let mut args = args_of(&scan, "keyboard");
            args.positional.clear();
            args.set("xlayouts", trimmed(&after.keyboard).as_deref());
            single(
                &mut lines,
                &scan,
                "keyboard",
                trimmed(&after.keyboard).map(|_| args.line("keyboard")),
            );
        }
        FormField::Timezone => {
            let mut args = args_of(&scan, "timezone");
            args.positional = trimmed(&after.timezone).into_iter().collect();
            single(
                &mut lines,
                &scan,
                "timezone",
                (!args.positional.is_empty()).then(|| args.line("timezone")),
            );
        }
        FormField::Storage => match &after.storage {
            None => single(&mut lines, &scan, "autopart", None),
            Some(s) => {
                let mut args = args_of(&scan, "autopart");
                args.set(
                    "type",
                    Some(match s.layout {
                        StorageLayout::Lvm => "lvm",
                        StorageLayout::Plain => "plain",
                        StorageLayout::Custom => {
                            return Err("The form doesn't lay disks out by hand: write part lines in the file.".into())
                        }
                    }),
                );
                match s.swap {
                    Swap::Auto => args.flag("noswap", false),
                    Swap::None => args.flag("noswap", true),
                    Swap::SizeMb { .. } => {
                        return Err(
                            "autopart chooses swap's size: write a part swap line in the file for your own.".into(),
                        )
                    }
                }
                single(&mut lines, &scan, "autopart", Some(args.line("autopart")));
            }
        },
        FormField::Network => {
            let existing = scan.commands.iter().find(|c| c.name == "network");
            let mut args = existing.map(|c| c.args.clone()).unwrap_or_default();
            for o in ["bootproto", "ip", "netmask", "gateway", "nameserver"] {
                args.set(o, None);
            }
            match &after.network {
                None => {
                    if let Some(n) = existing {
                        if args.get("hostname").is_some() {
                            lines[n.at] = args.line("network");
                        } else {
                            lines[n.at] = String::from("\u{0}");
                        }
                    }
                }
                Some(net) => {
                    if args.get("device").is_none() {
                        args.set("device", Some("link"));
                    }
                    match net {
                        NetworkForm::Dhcp => args.set("bootproto", Some("dhcp")),
                        NetworkForm::Static {
                            address,
                            prefix,
                            gateway,
                            dns,
                        } => {
                            args.set("bootproto", Some("static"));
                            args.set("ip", Some(address.trim()));
                            args.set("netmask", Some(&netmask(*prefix)));
                            args.set("gateway", gateway.as_deref().map(str::trim).filter(|g| !g.is_empty()));
                            let dns: Vec<&str> = dns.iter().map(|d| d.trim()).filter(|d| !d.is_empty()).collect();
                            args.set("nameserver", (!dns.is_empty()).then(|| dns.join(",")).as_deref());
                        }
                    }
                    if !args.has("activate") {
                        args.flag("activate", true);
                    }
                    match existing {
                        Some(n) => lines[n.at] = args.line("network"),
                        None => single(&mut lines, &scan, "network", Some(args.line("network"))),
                    }
                }
            }
        }
        FormField::Users => {
            let old: Vec<&Command> = scan.commands.iter().filter(|c| c.name == "user").collect();
            let old_keys: Vec<&Command> = scan
                .commands
                .iter()
                .filter(|c| c.name == "sshkey" && c.args.get("username") != Some("root"))
                .collect();
            let at = old.iter().chain(old_keys.iter()).map(|c| c.at).min();
            let mut new_lines = Vec::new();
            for (i, user) in after.users.iter().enumerate() {
                let mut args = old.get(i).map(|c| c.args.clone()).unwrap_or_default();
                args.positional.clear();
                args.set("name", Some(user.name.trim()));
                let mut groups: Vec<String> = args
                    .get("groups")
                    .map(|g| {
                        g.split(',')
                            .map(|x| x.trim().to_owned())
                            .filter(|x| !x.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                groups.retain(|g| g != "wheel");
                if user.sudo {
                    groups.insert(0, "wheel".into());
                }
                args.set("groups", (!groups.is_empty()).then(|| groups.join(",")).as_deref());
                match user.password.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
                    Some(p) => {
                        args.flag("lock", false);
                        args.flag("plaintext", false);
                        args.flag("iscrypted", true);
                        args.set("password", Some(p));
                    }
                    None => {
                        args.set("password", None);
                        args.flag("iscrypted", false);
                        args.flag("lock", true);
                    }
                }
                new_lines.push(args.line("user"));
                for key in user.ssh_keys.iter().map(|k| k.trim()).filter(|k| !k.is_empty()) {
                    let mut k = Args::default();
                    k.set("username", Some(user.name.trim()));
                    k.positional.push(key.to_owned());
                    new_lines.push(k.line("sshkey"));
                }
            }
            for c in old.iter().chain(old_keys.iter()) {
                lines[c.at] = String::from("\u{0}");
            }
            let at = at.unwrap_or_else(|| Edit { lines: lines.clone() }.insert_at(&scan));
            for (i, l) in new_lines.into_iter().enumerate() {
                lines.insert(at + i, l);
            }
        }
        FormField::Packages => {
            let wanted: Vec<String> = after
                .packages
                .iter()
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .collect();
            match scan.sections.iter().find(|s| s.name == "%packages") {
                Some(s) => {
                    let end = s.end.ok_or("%packages isn't closed with %end.")?;
                    let kept: Vec<String> = lines[s.at + 1..end]
                        .iter()
                        .filter(|l| !is_package_line(l))
                        .cloned()
                        .collect();
                    let mut kept = kept;
                    while kept.last().is_some_and(|l| l.trim().is_empty()) {
                        kept.pop();
                    }
                    kept.extend(wanted);
                    lines.splice(s.at + 1..end, kept);
                }
                None if !wanted.is_empty() => {
                    while lines.last().is_some_and(|l| l.trim().is_empty()) {
                        lines.pop();
                    }
                    lines.push(String::new());
                    lines.push("%packages".into());
                    lines.extend(wanted);
                    lines.push("%end".into());
                    lines.push(String::new());
                }
                None => {}
            }
        }
        FormField::Proxy | FormField::Mirror => {
            let mirror = trimmed(&after.mirror);
            let proxy = trimmed(&after.proxy);
            let url = scan.commands.iter().rev().find(|c| c.name == "url");
            match (mirror, url) {
                (None, Some(u)) => {
                    if proxy.is_some() {
                        return Err("A proxy goes with a mirror: give the mirror's address too.".into());
                    }
                    lines[u.at] = String::from("cdrom");
                }
                (None, None) => {
                    if proxy.is_some() {
                        return Err("A proxy goes with a mirror: give the mirror's address too.".into());
                    }
                }
                (Some(m), existing) => {
                    let mut args = existing.map(|u| u.args.clone()).unwrap_or_default();
                    args.set("mirrorlist", None);
                    args.set("metalink", None);
                    args.set("url", Some(&m));
                    args.set("proxy", proxy.as_deref());
                    let line = args.line("url");
                    match existing {
                        Some(u) => lines[u.at] = line,
                        None => match scan.commands.iter().find(|c| c.name == "cdrom") {
                            Some(c) => lines[c.at] = line,
                            None => single(&mut lines, &scan, "url", Some(line)),
                        },
                    }
                }
            }
        }
        FormField::LateCommands => {
            let wanted: Vec<String> = after.late_commands.iter().map(|c| c.trim_end().to_owned()).collect();
            let mut wanted = wanted;
            while wanted.last().is_some_and(|l| l.trim().is_empty()) {
                wanted.pop();
            }
            match post(&scan) {
                Some(s) => {
                    let end = s.end.ok_or("%post isn't closed with %end.")?;
                    if wanted.is_empty() {
                        for l in &mut lines[s.at..=end] {
                            *l = String::from("\u{0}");
                        }
                    } else {
                        lines.splice(s.at + 1..end, wanted);
                    }
                }
                None if !wanted.is_empty() => {
                    while lines.last().is_some_and(|l| l.trim().is_empty()) {
                        lines.pop();
                    }
                    lines.push(String::new());
                    lines.push("%post".into());
                    lines.extend(wanted);
                    lines.push("%end".into());
                    lines.push(String::new());
                }
                None => {}
            }
        }
        FormField::Ssh | FormField::Updates => return Err("The form doesn't set that in a kickstart.".into()),
    }
    lines.retain(|l| l != "\u{0}");
    Ok(lines.join("\n"))
}

pub fn apply_form(
    body_text: &str,
    _before: &InstallForm,
    after: &InstallForm,
    changed: &[FormField],
) -> Result<String, String> {
    let mut text = body_text.to_owned();
    let mut done_url = false;
    for field in changed {
        if matches!(field, FormField::Proxy | FormField::Mirror) {
            if done_url {
                continue;
            }
            done_url = true;
        }
        text = apply_one(&text, *field, after)?;
    }
    if let Some(p) = scan(&text).problems.into_iter().find(|p| p.severity == Severity::Error) {
        return Err(format!("The form's change would break the file: {}", p.message));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::catalog::install::SAMPLE_HASH;

    fn messages(problems: &[ConfigProblem]) -> String {
        problems
            .iter()
            .map(|p| p.message.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn words_split_like_pykickstart() {
        assert_eq!(
            words("user --name=alice --gecos=\"Alice A\" # admin").unwrap(),
            ["user", "--name=alice", "--gecos=Alice A"]
        );
        assert_eq!(
            words("sshkey --username=alice 'ssh-ed25519 AAAA a@example.com'").unwrap()[2],
            "ssh-ed25519 AAAA a@example.com"
        );
        assert!(words("rootpw \"open").is_err());
        assert_eq!(
            word("--password={{password.admin}}"),
            "--password=\"{{password.admin}}\""
        );
        assert_eq!(word("Etc/UTC"), "Etc/UTC");
        assert_eq!(word("a \"b\""), "\"a \\\"b\\\"\"");
        let args = Args::parse(&words("network --bootproto static --ip=192.0.2.10 --activate").unwrap()[1..]);
        assert_eq!(args.get("bootproto"), Some("static"));
        assert!(args.has("activate"));
    }

    fn good() -> String {
        format!("text\nlang en_US.UTF-8\nkeyboard --xlayouts='us'\ntimezone Etc/UTC --utc\nnetwork --bootproto=dhcp --device=link --activate --hostname=vm-1\nrootpw --lock\nuser --name=alice --groups=wheel --iscrypted --password=\"{SAMPLE_HASH}\"\nsshkey --username=alice \"ssh-ed25519 AAAA alice@example.com\"\nurl --url=https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/\nzerombr\nclearpart --all --initlabel\nautopart --type=lvm\nreboot\n\n%packages\n@^minimal-environment\nopenssh-server\n%end\n\n%post\necho done\n%end\n")
    }

    #[test]
    fn a_good_kickstart_passes() {
        let problems = check(&good());
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn syntax_and_commands_are_checked() {
        let text = messages(&check("lang\nfrobnicate --x\ninstall\n%packages\ncurl\n%pre\nexit 0\n%end\n%end\n%bogus\nuser\nnetwork --bootproto=magic\nautopart --type=zfs\npart / --size=1000\nautopart\ncdrom\nurl --url=http://mirror.example.com/\n"));
        for want in [
            "lang needs its value",
            "doesn't know the command frobnicate",
            "install was removed",
            "%packages isn't closed with %end before the next section",
            "%end without a section",
            "%bogus isn't a kickstart section",
            "user needs --name",
            "takes dhcp or static",
            "lvm, btrfs, plain or thinp",
            "autopart can't be used with part",
            "more than one installation source",
            "add reboot",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        assert!(messages(&check("text\nrootpw \"open\n")).contains("quote isn't closed"));
        assert!(messages(&check("text\nlang en_US.UTF-8\ntimezone Etc/UTC\nreboot\n"))
            .contains("No user and no root password"));
    }

    #[test]
    fn secrets_and_lock_outs() {
        let plain = good().replace("--lock", "--plaintext letmein");
        assert!(check(&plain)
            .iter()
            .any(|p| p.blocks_saving && p.message.contains("rootpw holds a password")));
        let hashed = good().replace(&format!("\"{SAMPLE_HASH}\""), "$6$abcdefgh$ijklmnopqrstuvwxyz");
        assert!(check(&hashed)
            .iter()
            .any(|p| p.blocks_saving && p.message.contains("password hash")));
        let no_crypt = good().replace("--iscrypted ", "");
        assert!(messages(&check(&no_crypt)).contains("needs --iscrypted"));
        let locked = good()
            .replace("--iscrypted --password=", "--lock --x=")
            .replace("sshkey --username=alice \"ssh-ed25519 AAAA alice@example.com\"\n", "");
        assert!(messages(&check(&locked)).contains("nobody can sign in"));
        let root_only =
            format!("text\nlang en_US.UTF-8\ntimezone Etc/UTC\nrootpw --iscrypted \"{SAMPLE_HASH}\"\nreboot\n");
        assert!(messages(&check(&root_only)).contains("RHEL 9 doesn't let root sign in"));
        assert!(messages(&check(&format!("{}services --disabled=sshd\n", good()))).contains("sshd is turned off"));
    }

    #[test]
    fn the_disk_a_layout_needs() {
        assert_eq!(
            disk_need_mb("part /boot --size=1024\npart swap --size=4096\npart / --size=20000 --grow\n"),
            Some(25120)
        );
        assert_eq!(disk_need_mb(&good()), None);
    }

    #[test]
    fn the_form_reads_and_writes_lines() {
        let body = good()
            .replace(&format!("\"{SAMPLE_HASH}\""), "\"{{password.admin}}\"")
            .replace("vm-1", "{{hostname}}");
        let read = read_form(&body);
        assert_eq!(read.unreadable, None);
        let form = read.form.clone();
        assert_eq!(form.hostname.as_deref(), Some("{{hostname}}"));
        assert_eq!(form.locale.as_deref(), Some("en_US.UTF-8"));
        assert_eq!(form.keyboard.as_deref(), Some("us"));
        assert_eq!(form.timezone.as_deref(), Some("Etc/UTC"));
        assert_eq!(
            form.storage,
            Some(StorageForm {
                layout: StorageLayout::Lvm,
                swap: Swap::Auto
            })
        );
        assert_eq!(form.network, Some(NetworkForm::Dhcp));
        assert_eq!(form.users[0].password.as_deref(), Some("{{password.admin}}"));
        assert!(form.users[0].sudo);
        assert_eq!(form.users[0].ssh_keys, ["ssh-ed25519 AAAA alice@example.com"]);
        assert_eq!(form.packages, ["openssh-server"]);
        assert_eq!(form.late_commands, ["echo done"]);
        let mut after = form.clone();
        after.timezone = Some("Europe/Berlin".into());
        after.network = Some(NetworkForm::Static {
            address: "{{ip}}".into(),
            prefix: 24,
            gateway: Some("192.0.2.1".into()),
            dns: vec!["192.0.2.53".into(), "192.0.2.54".into()],
        });
        after.users.push(UserForm {
            name: "bob".into(),
            password: None,
            ssh_keys: vec!["{{ssh_key.bob}}".into()],
            sudo: false,
        });
        after.packages.push("tmux".into());
        after.late_commands.push("dnf -y upgrade".into());
        let changed = crate::catalog::install::changed_fields(&form, &after);
        let out = apply_form(&body, &form, &after, &changed).unwrap();
        assert!(out.contains("\ntimezone --utc Europe/Berlin\n"), "{out}");
        assert!(out.contains("\nnetwork --device=link --activate --hostname=\"{{hostname}}\" --bootproto=static --ip=\"{{ip}}\" --netmask=255.255.255.0 --gateway=192.0.2.1 --nameserver=192.0.2.53,192.0.2.54\n"), "{out}");
        assert!(out.contains("\nuser --name=alice --groups=wheel --iscrypted --password=\"{{password.admin}}\"\nsshkey --username=alice \"ssh-ed25519 AAAA alice@example.com\"\nuser --name=bob --lock\nsshkey --username=bob \"{{ssh_key.bob}}\"\n"), "{out}");
        assert!(
            out.contains("%packages\n@^minimal-environment\nopenssh-server\ntmux\n%end"),
            "{out}"
        );
        assert!(out.contains("%post\necho done\ndnf -y upgrade\n%end"), "{out}");
        assert!(
            out.contains("\nlang en_US.UTF-8\nkeyboard --xlayouts='us'\n"),
            "untouched lines stay as written: {out}"
        );
        let back = read_form(&out).form;
        assert_eq!(back.network, after.network);
        assert_eq!(back.users, after.users);
        assert_eq!(back.timezone, after.timezone);
    }
}
