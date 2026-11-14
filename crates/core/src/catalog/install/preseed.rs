//! VM-28: debian-installer's preseed (Debian 12 and 13).
//!
//! Each line is `<owner> <question> <type> <value>` (`d-i passwd/username string alice`); `#` starts a comment and a
//! line ending in `\` goes on on the next. A question the installer isn't given, it asks, which stops an unattended
//! install: the lint names the ones that do (root's password, the user's, partitioning's confirmations).

use super::form::{
    netmask, prefix_of, FieldState, FormField, FormRead, InstallForm, NetworkForm, StorageForm, StorageLayout, Swap,
    Updates, UserForm,
};
use super::{is_sample_secret, looks_hashed, ConfigProblem, Severity};

const TYPES: &[&str] = &[
    "string",
    "boolean",
    "select",
    "multiselect",
    "note",
    "text",
    "password",
    "error",
    "title",
];

/// Questions that take a password in plain text.
const PLAIN_PASSWORDS: &[&str] = &[
    "passwd/root-password",
    "passwd/root-password-again",
    "passwd/user-password",
    "passwd/user-password-again",
    "grub-installer/password",
    "grub-installer/password-again",
    "netcfg/wireless_wpa",
];

const CRYPTED: &[&str] = &[
    "passwd/root-password-crypted",
    "passwd/user-password-crypted",
    "grub-installer/password-crypted",
];

/// One preseed line (continuations joined).
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    /// Physical lines `start..=end`, from 0.
    pub start: usize,
    pub end: usize,
    pub owner: String,
    pub question: String,
    pub value: String,
}

pub(crate) struct Scan {
    pub entries: Vec<Entry>,
    pub problems: Vec<ConfigProblem>,
}

fn line_no(at: usize) -> Option<u32> {
    u32::try_from(at + 1).ok()
}

pub(crate) fn scan(text: &str) -> Scan {
    let lines: Vec<String> = text.split('\n').map(|l| l.trim_end_matches('\r').to_owned()).collect();
    let mut entries = Vec::new();
    let mut problems = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let mut logical = String::new();
        loop {
            let line = &lines[i];
            match line.strip_suffix('\\') {
                Some(head) if i + 1 < lines.len() => {
                    logical.push_str(head);
                    logical.push(' ');
                    i += 1;
                }
                _ => {
                    logical.push_str(line);
                    break;
                }
            }
        }
        let end = i;
        i += 1;
        let t = logical.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut parts = t.split_whitespace();
        let owner = parts.next().unwrap_or_default().to_owned();
        let question = parts.next().unwrap_or_default().to_owned();
        let kind = parts.next().unwrap_or_default().to_owned();
        // The value keeps its own spacing.
        let value = after_fields(t, 3).map(|v| v.trim().to_owned()).unwrap_or_default();
        if kind.is_empty() {
            problems.push(ConfigProblem::error(
                line_no(start),
                "A preseed line needs an owner, a question and a type: d-i passwd/username string alice.",
            ));
            continue;
        }
        if !TYPES.contains(&kind.as_str()) {
            problems.push(ConfigProblem::error(
                line_no(start),
                format!("{kind} isn't a preseed type: use string, boolean, select, multiselect, note or password."),
            ));
        } else if kind == "boolean" && !matches!(value.as_str(), "true" | "false") {
            problems.push(ConfigProblem::error(
                line_no(start),
                format!("{question} is a boolean: true or false."),
            ));
        }
        if !question.contains('/') {
            problems.push(ConfigProblem::error(
                line_no(start),
                format!("{question} isn't a question's name, such as passwd/username."),
            ));
        }
        entries.push(Entry {
            start,
            end,
            owner,
            question,
            value,
        });
    }
    Scan { entries, problems }
}

/// The text after the first `n` whitespace-separated fields.
fn after_fields(text: &str, n: usize) -> Option<&str> {
    let mut rest = text;
    for _ in 0..n {
        rest = rest.trim_start();
        let at = rest.find(char::is_whitespace)?;
        rest = &rest[at..];
    }
    Some(rest)
}

impl Scan {
    fn get(&self, question: &str) -> Option<&Entry> {
        self.entries.iter().rev().find(|e| e.question == question)
    }

    fn value(&self, question: &str) -> Option<&str> {
        self.get(question).map(|e| e.value.as_str())
    }

    fn bool(&self, question: &str) -> Option<bool> {
        self.value(question).map(|v| v == "true")
    }
}

pub fn syntax(text: &str) -> Vec<ConfigProblem> {
    scan(text).problems
}

pub fn check(text: &str) -> Vec<ConfigProblem> {
    let scan = scan(text);
    let mut out = scan.problems.clone();
    let mut seen: Vec<&str> = Vec::new();
    for e in &scan.entries {
        if seen.contains(&e.question.as_str()) && e.question != "preseed/late_command" {
            out.push(ConfigProblem::warning(
                line_no(e.start),
                format!("{} is set twice: the installer takes the last.", e.question),
            ));
        }
        seen.push(&e.question);
        let at = line_no(e.start);
        if PLAIN_PASSWORDS.contains(&e.question.to_ascii_lowercase().as_str()) && !e.value.is_empty() {
            out.push(ConfigProblem::secret(at, format!("{} holds a password in plain text: a config never keeps one. Use the -crypted question with {{{{password.<name>}}}}.", e.question)));
        }
        if CRYPTED.contains(&e.question.to_ascii_lowercase().as_str())
            && !e.value.is_empty()
            && !is_sample_secret(&e.value)
            && e.value != "!"
        {
            let what = if looks_hashed(&e.value) {
                "a password hash"
            } else {
                "a password"
            };
            out.push(ConfigProblem::secret(at, format!("{} holds {what}: a config never keeps one. Pick the password from the vault in the form, or write {{{{password.<name>}}}}.", e.question)));
        }
    }
    let root_login = scan.bool("passwd/root-login").unwrap_or(true);
    let make_user = scan.bool("passwd/make-user").unwrap_or(true);
    if !root_login && !make_user {
        out.push(ConfigProblem::error(
            None,
            "No user: root can't sign in and no user is made. Turn one on.",
        ));
    }
    if root_login && scan.get("passwd/root-password-crypted").is_none() {
        out.push(ConfigProblem::error(
            None,
            "The installer stops to ask for root's password: set passwd/root-login false, or pick root's password.",
        ));
    }
    if make_user {
        if scan.get("passwd/username").is_none() {
            out.push(ConfigProblem::error(
                None,
                "The installer stops to ask for the user's name: set passwd/username.",
            ));
        }
        if scan.get("passwd/user-password-crypted").is_none() {
            out.push(ConfigProblem::error(
                None,
                "The installer stops to ask for the user's password: pick it in the form.",
            ));
        }
    }
    let include = scan.value("pkgsel/include").unwrap_or_default();
    let tasks = scan.value("tasksel/first").unwrap_or_default();
    if !include
        .split_whitespace()
        .any(|p| p.trim_matches(',') == "openssh-server")
        && !tasks.contains("ssh-server")
    {
        out.push(ConfigProblem::warning(
            None,
            "No SSH server: add openssh-server to the packages, or ssh-server to tasksel/first.",
        ));
    }
    // VM-29 (S2): each of these was seen to stop a Debian 13 install at auto=true priority=critical, asking on its
    // console where an unattended deploy has no one to answer.
    if make_user && scan.get("passwd/user-fullname").is_none() {
        out.push(ConfigProblem::error(
            None,
            "The installer stops to ask for the user's full name: set passwd/user-fullname.",
        ));
    }
    for (question, ask, fix) in [
        (
            "debian-installer/locale",
            "to pick a language",
            "d-i debian-installer/locale string en_US.UTF-8",
        ),
        (
            "keyboard-configuration/xkb-keymap",
            "to pick a keyboard",
            "d-i keyboard-configuration/xkb-keymap select us",
        ),
        (
            "grub-installer/only_debian",
            "where to install GRUB on a BIOS VM",
            "d-i grub-installer/only_debian boolean true",
        ),
        (
            "grub-installer/bootdev",
            "where to install GRUB on a BIOS VM",
            "d-i grub-installer/bootdev string default",
        ),
        (
            "finish-install/reboot_in_progress",
            "before it restarts, once the install is done",
            "d-i finish-install/reboot_in_progress note",
        ),
    ] {
        if scan.get(question).is_none() {
            out.push(ConfigProblem::error(
                None,
                format!("The installer stops {ask}: add {fix}."),
            ));
        }
    }
    if scan.get("tasksel/first").is_none() {
        out.push(ConfigProblem::warning(
            None,
            "No tasksel/first: Debian 13 then installs a desktop (over a thousand packages). Add tasksel tasksel/first multiselect standard, ssh-server.",
        ));
    }
    if scan.get("partman-auto/method").is_some() {
        for q in [
            "partman/confirm",
            "partman/confirm_nooverwrite",
            "partman-partitioning/confirm_write_new_label",
        ] {
            if scan.bool(q) != Some(true) {
                out.push(ConfigProblem::warning(
                    None,
                    format!("The installer asks before it writes the disk: add d-i {q} boolean true."),
                ));
            }
        }
        if scan.value("partman-auto/method") == Some("lvm") && scan.bool("partman-lvm/confirm") != Some(true) {
            out.push(ConfigProblem::warning(
                None,
                "The installer asks before it sets up LVM: add d-i partman-lvm/confirm boolean true.",
            ));
        }
    }
    out.sort_by_key(|p| (p.line.unwrap_or(u32::MAX), p.severity == Severity::Warning));
    out
}

/// The smallest sizes an expert recipe gives its partitions, in MB.
pub fn disk_need_mb(text: &str) -> Option<u64> {
    let scan = scan(text);
    let recipe = scan.value("partman-auto/expert_recipe")?;
    let body = recipe.split_once("::").map_or(recipe, |(_, b)| b);
    let total: u64 = body
        .split(" . ")
        .filter_map(|block| block.split_whitespace().next()?.parse::<u64>().ok())
        .sum();
    (total > 0).then_some(total)
}

// ---- The form -------------------------------------------------------------------------------------------------------

fn fields() -> Vec<FieldState> {
    vec![
        FieldState::on(FormField::Hostname),
        FieldState::on(FormField::Locale),
        FieldState::on(FormField::Keyboard),
        FieldState::on(FormField::Timezone),
        FieldState::noted(FormField::Storage, "The installer chooses swap's size."),
        FieldState::on(FormField::Network),
        FieldState::noted(FormField::Users, "A preseed makes one user, who gets sudo when root can't sign in. SSH keys go in a late command (the starter shows how)."),
        FieldState::off(FormField::Ssh, "Debian's SSH server takes passwords unless a late command changes it."),
        FieldState::on(FormField::Packages),
        FieldState::on(FormField::Updates),
        FieldState::on(FormField::Proxy),
        FieldState::on(FormField::Mirror),
        FieldState::on(FormField::LateCommands),
    ]
}

pub fn read_form(body: &str) -> FormRead {
    let scan = scan(body);
    if let Some(p) = scan.problems.first() {
        return FormRead::unreadable(format!("Line {}: {}", p.line.unwrap_or(1), p.message));
    }
    let mut fields = fields();
    let opt = |q: &str| {
        scan.value(q)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    let storage = scan.value("partman-auto/method").map(|m| {
        let custom = scan.get("partman-auto/expert_recipe").is_some() || !matches!(m, "lvm" | "regular");
        StorageForm {
            layout: if custom {
                StorageLayout::Custom
            } else if m == "lvm" {
                StorageLayout::Lvm
            } else {
                StorageLayout::Plain
            },
            swap: Swap::Auto,
        }
    });
    if storage.is_some_and(|s| s.layout == StorageLayout::Custom) {
        super::cloud_init::set_off(
            &mut fields,
            FormField::Storage,
            "The file lays the disk out itself (a recipe or encryption): edit it in the file.",
        );
    }
    let network = if scan.bool("netcfg/disable_autoconfig") == Some(true) {
        Some(NetworkForm::Static {
            address: opt("netcfg/get_ipaddress").unwrap_or_default(),
            prefix: scan.value("netcfg/get_netmask").and_then(prefix_of).unwrap_or(24),
            gateway: opt("netcfg/get_gateway"),
            dns: scan
                .value("netcfg/get_nameservers")
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        })
    } else if scan.get("netcfg/choose_interface").is_some() || scan.get("netcfg/disable_autoconfig").is_some() {
        Some(NetworkForm::Dhcp)
    } else {
        None
    };
    let users = opt("passwd/username")
        .map(|name| {
            vec![UserForm {
                name,
                password: opt("passwd/user-password-crypted").filter(|p| p != "!"),
                ssh_keys: Vec::new(),
                sudo: scan.bool("passwd/root-login") == Some(false),
            }]
        })
        .unwrap_or_default();
    let mirror = opt("mirror/http/hostname").map(|host| {
        let dir = opt("mirror/http/directory").unwrap_or_else(|| "/debian".into());
        let dir = if dir.starts_with('/') { dir } else { format!("/{dir}") };
        format!("http://{host}{dir}")
    });
    let form = InstallForm {
        hostname: opt("netcfg/get_hostname").or_else(|| opt("netcfg/hostname")),
        locale: opt("debian-installer/locale"),
        keyboard: opt("keyboard-configuration/xkb-keymap"),
        timezone: opt("time/zone"),
        storage,
        network,
        users,
        ssh: None,
        packages: scan
            .value("pkgsel/include")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        updates: match scan.value("pkgsel/upgrade") {
            Some("none") => Some(Updates::None),
            Some("safe-upgrade") => Some(Updates::Security),
            Some("full-upgrade") => Some(Updates::All),
            _ => None,
        },
        proxy: opt("mirror/http/proxy"),
        mirror,
        late_commands: scan
            .value("preseed/late_command")
            .map(|v| {
                v.split("; ")
                    .map(|c| c.trim().to_owned())
                    .filter(|c| !c.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    };
    FormRead {
        form,
        fields,
        max_users: Some(1),
        unreadable: None,
    }
}

struct Edit {
    lines: Vec<String>,
}

impl Edit {
    /// Sets (or with `None` removes) a question, keeping its owner; a new one goes at the end as `d-i`.
    fn set(&mut self, question: &str, kind: &str, value: Option<&str>) {
        let text = self.lines.join("\n");
        let scan = scan(&text);
        let same: Vec<&Entry> = scan.entries.iter().filter(|e| e.question == question).collect();
        match (same.last(), value) {
            (Some(e), Some(v)) => {
                let line = format!("{} {question} {kind} {v}", e.owner).trim_end().to_owned();
                self.lines.splice(e.start..=e.end, [line]);
            }
            (Some(_), None) => {
                for e in same.iter().rev() {
                    self.lines.drain(e.start..=e.end);
                }
            }
            (None, Some(v)) => {
                let at = self
                    .lines
                    .iter()
                    .rposition(|l| !l.trim().is_empty())
                    .map_or(0, |i| i + 1);
                self.lines
                    .insert(at, format!("d-i {question} {kind} {v}").trim_end().to_owned());
            }
            (None, None) => {}
        }
    }
}

pub fn apply_form(
    body: &str,
    _before: &InstallForm,
    after: &InstallForm,
    changed: &[FormField],
) -> Result<String, String> {
    let mut edit = Edit {
        lines: body.split('\n').map(|l| l.trim_end_matches('\r').to_owned()).collect(),
    };
    let trimmed = |v: &Option<String>| v.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned);
    for field in changed {
        match field {
            FormField::Hostname => {
                let h = trimmed(&after.hostname);
                edit.set("netcfg/get_hostname", "string", h.as_deref());
                let has_hostname = scan(&edit.lines.join("\n")).get("netcfg/hostname").is_some();
                if has_hostname {
                    edit.set("netcfg/hostname", "string", h.as_deref());
                }
            }
            FormField::Locale => edit.set("debian-installer/locale", "string", trimmed(&after.locale).as_deref()),
            FormField::Keyboard => edit.set(
                "keyboard-configuration/xkb-keymap",
                "select",
                trimmed(&after.keyboard).as_deref(),
            ),
            FormField::Timezone => edit.set("time/zone", "string", trimmed(&after.timezone).as_deref()),
            FormField::Storage => match &after.storage {
                None => edit.set("partman-auto/method", "string", None),
                Some(s) => {
                    let method = match s.layout {
                        StorageLayout::Lvm => "lvm",
                        StorageLayout::Plain => "regular",
                        StorageLayout::Custom => {
                            return Err("The form doesn't lay disks out by hand: write a recipe in the file.".into())
                        }
                    };
                    if s.swap != Swap::Auto {
                        return Err(
                            "The installer chooses swap's size: write an expert recipe in the file for your own."
                                .into(),
                        );
                    }
                    edit.set("partman-auto/method", "string", Some(method));
                }
            },
            FormField::Network => {
                for q in [
                    "netcfg/get_ipaddress",
                    "netcfg/get_netmask",
                    "netcfg/get_gateway",
                    "netcfg/get_nameservers",
                    "netcfg/confirm_static",
                ] {
                    edit.set(q, "string", None);
                }
                match &after.network {
                    None => edit.set("netcfg/disable_autoconfig", "boolean", None),
                    Some(NetworkForm::Dhcp) => {
                        edit.set("netcfg/disable_autoconfig", "boolean", Some("false"));
                        if scan(&edit.lines.join("\n")).get("netcfg/choose_interface").is_none() {
                            edit.set("netcfg/choose_interface", "select", Some("auto"));
                        }
                    }
                    Some(NetworkForm::Static {
                        address,
                        prefix,
                        gateway,
                        dns,
                    }) => {
                        edit.set("netcfg/disable_autoconfig", "boolean", Some("true"));
                        edit.set("netcfg/get_ipaddress", "string", Some(address.trim()));
                        edit.set("netcfg/get_netmask", "string", Some(&netmask(*prefix)));
                        edit.set(
                            "netcfg/get_gateway",
                            "string",
                            gateway.as_deref().map(str::trim).filter(|g| !g.is_empty()),
                        );
                        let dns: Vec<&str> = dns.iter().map(|d| d.trim()).filter(|d| !d.is_empty()).collect();
                        edit.set(
                            "netcfg/get_nameservers",
                            "string",
                            (!dns.is_empty()).then(|| dns.join(" ")).as_deref(),
                        );
                        edit.set("netcfg/confirm_static", "boolean", Some("true"));
                    }
                }
            }
            FormField::Users => match after.users.first() {
                None => {
                    edit.set("passwd/username", "string", None);
                    edit.set("passwd/user-password-crypted", "password", None);
                    edit.set("passwd/make-user", "boolean", Some("false"));
                }
                Some(user) => {
                    if !user.ssh_keys.is_empty() {
                        return Err("A preseed has no SSH key setting: write the key in a late command (the starter shows how).".into());
                    }
                    edit.set("passwd/make-user", "boolean", None);
                    edit.set("passwd/username", "string", Some(user.name.trim()));
                    let pw = user
                        .password
                        .as_deref()
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .unwrap_or("!");
                    edit.set("passwd/user-password-crypted", "password", Some(pw));
                    if user.sudo {
                        edit.set("passwd/root-login", "boolean", Some("false"));
                    } else if scan(&edit.lines.join("\n")).bool("passwd/root-login") == Some(false) {
                        edit.set("passwd/root-login", "boolean", None);
                    }
                }
            },
            FormField::Packages => {
                let p: Vec<&str> = after
                    .packages
                    .iter()
                    .map(|p| p.trim())
                    .filter(|p| !p.is_empty())
                    .collect();
                edit.set(
                    "pkgsel/include",
                    "string",
                    (!p.is_empty()).then(|| p.join(" ")).as_deref(),
                );
            }
            FormField::Updates => edit.set(
                "pkgsel/upgrade",
                "select",
                after.updates.map(|u| match u {
                    Updates::None => "none",
                    Updates::Security => "safe-upgrade",
                    Updates::All => "full-upgrade",
                }),
            ),
            FormField::Proxy => edit.set("mirror/http/proxy", "string", trimmed(&after.proxy).as_deref()),
            FormField::Mirror => match trimmed(&after.mirror) {
                None => {
                    edit.set("mirror/http/hostname", "string", None);
                    edit.set("mirror/http/directory", "string", None);
                }
                Some(m) => {
                    let rest = m.strip_prefix("http://").or_else(|| m.strip_prefix("https://")).ok_or(
                        "A Debian mirror's address starts with http://, such as http://deb.debian.org/debian.",
                    )?;
                    let (host, dir) = rest
                        .split_once('/')
                        .map_or((rest, "/debian".to_owned()), |(h, d)| (h, format!("/{d}")));
                    edit.set("mirror/country", "string", Some("manual"));
                    edit.set("mirror/http/hostname", "string", Some(host));
                    edit.set("mirror/http/directory", "string", Some(&dir));
                }
            },
            FormField::LateCommands => {
                let c: Vec<&str> = after
                    .late_commands
                    .iter()
                    .map(|c| c.trim())
                    .filter(|c| !c.is_empty())
                    .collect();
                edit.set(
                    "preseed/late_command",
                    "string",
                    (!c.is_empty()).then(|| c.join("; ")).as_deref(),
                );
            }
            FormField::Ssh => return Err("The form doesn't set that in a preseed.".into()),
        }
    }
    let text = edit.lines.join("\n");
    if let Some(p) = scan(&text).problems.first() {
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

    fn good() -> String {
        format!("d-i debian-installer/locale string en_US.UTF-8\nd-i keyboard-configuration/xkb-keymap select us\nd-i netcfg/choose_interface select auto\nd-i netcfg/get_hostname string vm-1\nd-i passwd/root-login boolean false\nd-i passwd/user-fullname string Alice\nd-i passwd/username string alice\nd-i passwd/user-password-crypted password {SAMPLE_HASH}\nd-i time/zone string Etc/UTC\nd-i partman-auto/method string lvm\nd-i partman-lvm/confirm boolean true\nd-i partman/confirm boolean true\nd-i partman/confirm_nooverwrite boolean true\nd-i partman-partitioning/confirm_write_new_label boolean true\ntasksel tasksel/first multiselect standard, ssh-server\nd-i pkgsel/include string curl\nd-i preseed/late_command string \\\n    in-target true; echo done\nd-i grub-installer/only_debian boolean true\nd-i grub-installer/bootdev string default\nd-i finish-install/reboot_in_progress note\n")
    }

    #[test]
    fn a_good_preseed_passes() {
        let problems = check(&good());
        assert!(problems.is_empty(), "{problems:?}");
        let read = read_form(&good()).form;
        assert_eq!(
            read.late_commands,
            ["in-target true", "echo done"],
            "a continued line reads whole"
        );
    }

    #[test]
    fn lines_types_secrets_and_what_the_installer_would_ask() {
        let text = messages(&check("d-i passwd/username\nd-i x/y strin z\nd-i a/b boolean yes\nd-i nonsense string x\nd-i passwd/root-password password letmein\nd-i passwd/user-password-crypted password $6$abcdefgh$ijklmnopqrstuvwxyz\n"));
        for want in [
            "needs an owner, a question and a type",
            "strin isn't a preseed type",
            "a/b is a boolean",
            "nonsense isn't a question's name",
            "passwd/root-password holds a password in plain text",
            "holds a password hash",
            "stops to ask for root's password",
            "No SSH server",
            "stops before it restarts",
            "stops to pick a language",
            "stops to ask for the user's full name",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        let none = messages(&check(
            "d-i passwd/root-login boolean false\nd-i passwd/make-user boolean false\n",
        ));
        assert!(none.contains("No user"), "{none}");
        let unconfirmed = messages(&check(&good().replace("d-i partman/confirm boolean true\n", "")));
        assert!(unconfirmed.contains("partman/confirm boolean true"), "{unconfirmed}");
    }

    #[test]
    fn the_disk_an_expert_recipe_needs() {
        let text = "d-i partman-auto/expert_recipe string \\\n  boot-root :: \\\n  512 512 1024 ext4 $primary{ } mountpoint{ /boot } . \\\n  20000 10000 -1 ext4 $lvmok{ } mountpoint{ / } . \\\n  2048 2048 4096 linux-swap $lvmok{ } method{ swap } .\n";
        assert_eq!(disk_need_mb(text), Some(512 + 20000 + 2048));
        assert_eq!(disk_need_mb(&good()), None);
    }

    #[test]
    fn the_form_reads_and_writes_questions() {
        let body = good()
            .replace(SAMPLE_HASH, "{{password.admin}}")
            .replace("vm-1", "{{hostname}}");
        let read = read_form(&body);
        assert_eq!(read.unreadable, None);
        let form = read.form.clone();
        assert_eq!(form.hostname.as_deref(), Some("{{hostname}}"));
        assert_eq!(
            form.users,
            [UserForm {
                name: "alice".into(),
                password: Some("{{password.admin}}".into()),
                ssh_keys: vec![],
                sudo: true
            }]
        );
        assert_eq!(form.network, Some(NetworkForm::Dhcp));
        assert_eq!(
            form.storage,
            Some(StorageForm {
                layout: StorageLayout::Lvm,
                swap: Swap::Auto
            })
        );
        let mut after = form.clone();
        after.network = Some(NetworkForm::Static {
            address: "{{ip}}".into(),
            prefix: 24,
            gateway: Some("192.0.2.1".into()),
            dns: vec!["192.0.2.53".into()],
        });
        after.packages = vec!["curl".into(), "openssh-server".into()];
        after.updates = Some(Updates::Security);
        after.mirror = Some("http://deb.debian.org/debian".into());
        after.late_commands = vec!["in-target true".into()];
        let changed = crate::catalog::install::changed_fields(&form, &after);
        let out = apply_form(&body, &form, &after, &changed).unwrap();
        assert!(out.contains("d-i netcfg/disable_autoconfig boolean true\n"), "{out}");
        assert!(out.contains("d-i netcfg/get_ipaddress string {{ip}}\n"), "{out}");
        assert!(out.contains("d-i netcfg/get_netmask string 255.255.255.0\n"), "{out}");
        assert!(out.contains("d-i pkgsel/include string curl openssh-server\n"), "{out}");
        assert!(out.contains("d-i pkgsel/upgrade select safe-upgrade\n"), "{out}");
        assert!(
            out.contains("d-i mirror/http/hostname string deb.debian.org\nd-i mirror/http/directory string /debian"),
            "{out}"
        );
        assert!(
            out.contains("d-i preseed/late_command string in-target true\n"),
            "{out}"
        );
        assert!(
            out.starts_with(
                "d-i debian-installer/locale string en_US.UTF-8\nd-i keyboard-configuration/xkb-keymap select us\n"
            ),
            "{out}"
        );
        let back = read_form(&out).form;
        assert_eq!(back.network, after.network);
        assert_eq!(back.mirror, after.mirror);
        assert_eq!(back.updates, after.updates);
        assert_eq!(back.late_commands, after.late_commands);
    }
}
