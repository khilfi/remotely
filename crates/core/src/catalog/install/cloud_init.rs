//! VM-28: cloud-init user data (`#cloud-config`), for a cloud image's first boot (VM-22's kind of setup, as a config
//! of its own). Its checks of users and secrets also serve Ubuntu autoinstall's `user-data` section.
//!
//! cloud-init reads YAML with PyYAML. A user's `lock_passwd` defaults to true, so a password works only with
//! `lock_passwd: false`; `ssh_pwauth` decides password logins over SSH.

use super::form::{FieldState, FormField, FormRead, InstallForm, SshForm, Updates, UserForm};
use super::yaml::{self, Node, Value};
use super::{is_sample_secret, looks_hashed, protect, restore, ConfigProblem};

/// cloud-init's modules and settings that may sit at the top of user data.
const KNOWN_KEYS: &[&str] = &[
    "ansible",
    "apk_repos",
    "apt",
    "apt_pipelining",
    "apt_reboot_if_required",
    "apt_update",
    "apt_upgrade",
    "autoinstall",
    "bootcmd",
    "byobu_by_default",
    "ca_certs",
    "ca-certs",
    "chef",
    "chpasswd",
    "cloud_config_modules",
    "cloud_final_modules",
    "cloud_init_modules",
    "create_hostname_file",
    "device_aliases",
    "disable_ec2_metadata",
    "disable_root",
    "disable_root_opts",
    "disk_setup",
    "drivers",
    "fan",
    "final_message",
    "fqdn",
    "fs_setup",
    "groups",
    "growpart",
    "hostname",
    "keyboard",
    "landscape",
    "locale",
    "locale_configfile",
    "lxd",
    "manage_etc_hosts",
    "manage_resolv_conf",
    "mcollective",
    "merge_how",
    "merge_type",
    "mounts",
    "mount_default_fields",
    "no_ssh_fingerprints",
    "ntp",
    "output",
    "package_reboot_if_required",
    "package_update",
    "package_upgrade",
    "packages",
    "password",
    "phone_home",
    "power_state",
    "prefer_fqdn_over_hostname",
    "preserve_hostname",
    "puppet",
    "random_seed",
    "reporting",
    "resize_rootfs",
    "resolv_conf",
    "rh_subscription",
    "rsyslog",
    "runcmd",
    "salt_minion",
    "seed_random",
    "snap",
    "spacewalk",
    "ssh",
    "ssh_authorized_keys",
    "ssh_deletekeys",
    "ssh_fp_console_blacklist",
    "ssh_genkeytypes",
    "ssh_import_id",
    "ssh_key_console_blacklist",
    "ssh_keys",
    "ssh_publish_hostkeys",
    "ssh_pwauth",
    "ssh_quiet_keygen",
    "swap",
    "system_info",
    "timezone",
    "ubuntu_advantage",
    "ubuntu_pro",
    "updates",
    "user",
    "users",
    "vendor_data",
    "wireguard",
    "write_files",
    "yum_repo_dir",
    "yum_repos",
    "zypper",
];

/// The user data's own lines: its header and YAML.
pub fn syntax(text: &str) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let header_ok = first.trim_end() == "#cloud-config"
        || (first.starts_with("## template:") && text.lines().nth(1).is_some_and(|l| l.trim_end() == "#cloud-config"));
    if !header_ok {
        out.push(ConfigProblem::error(
            Some(1),
            "cloud-init reads user data as settings only when its first line is #cloud-config.",
        ));
    }
    match yaml::parse(text) {
        Err(err) => out.push(ConfigProblem::error(Some(err.line), err.message)),
        Ok(parsed) => {
            if parsed.docs.len() > 1 {
                out.push(ConfigProblem::error(
                    None,
                    "cloud-init reads one YAML document: remove the others.",
                ));
            }
            if let Some(root) = parsed.docs.first() {
                if !root.is_map() && !root.is_null() {
                    out.push(ConfigProblem::error(
                        Some(root.line),
                        "The user data's settings need to be a mapping.",
                    ));
                }
            }
        }
    }
    out
}

/// What cloud-init would make of the file: syntax, its keys and types, secrets written into it, and lock-outs.
pub fn check(text: &str) -> Vec<ConfigProblem> {
    let mut out = syntax(text);
    if out
        .iter()
        .any(|p| p.severity == super::Severity::Error && p.line != Some(1))
    {
        return out;
    }
    let Ok(parsed) = yaml::parse(text) else {
        return out;
    };
    out.extend(unread_shapes(&parsed));
    for (line, key) in &parsed.duplicates {
        out.push(ConfigProblem::warning(
            Some(*line),
            format!("{key} is set twice: cloud-init takes the last."),
        ));
    }
    let Some(root) = parsed.docs.first().filter(|r| r.is_map()) else {
        return out;
    };
    for (key, value) in root.entries() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            out.push(ConfigProblem::warning(
                Some(value.line),
                format!("cloud-init doesn't know the setting {key}: it is left alone."),
            ));
        }
    }
    out.extend(types(root));
    out.extend(user_data_checks(root, "", true));
    out
}

fn types(root: &Node) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    let want = |out: &mut Vec<ConfigProblem>, key: &str, ok: bool, what: &str| {
        if !ok {
            let line = root.get(key).map(|n| n.line);
            out.push(ConfigProblem::error(line, format!("{key} has to be {what}.")));
        }
    };
    for key in ["hostname", "fqdn", "timezone", "final_message"] {
        if let Some(n) = root.get(key) {
            want(&mut out, key, n.as_str().is_some() || n.text().is_some(), "text");
        }
    }
    for key in [
        "ssh_pwauth",
        "package_update",
        "package_upgrade",
        "package_reboot_if_required",
        "preserve_hostname",
        "disable_root",
        "ssh_deletekeys",
    ] {
        if let Some(n) = root.get(key) {
            want(&mut out, key, n.as_bool().is_some(), "true or false");
        }
    }
    for key in [
        "packages",
        "runcmd",
        "bootcmd",
        "ssh_authorized_keys",
        "write_files",
        "users",
    ] {
        if let Some(n) = root.get(key) {
            want(&mut out, key, n.is_seq() || n.is_null(), "a list");
        }
    }
    if let Some(k) = root.get("keyboard") {
        if !k.is_map() || k.get("layout").is_none() {
            out.push(ConfigProblem::error(
                Some(k.line),
                "keyboard needs its layout, such as layout: us.",
            ));
        }
    }
    for user in root.get("users").map(Node::items).unwrap_or_default() {
        if user.is_map() && user.get("name").and_then(Node::text).is_none() {
            out.push(ConfigProblem::error(Some(user.line), "Each user needs a name."));
        }
    }
    out
}

fn private_key_in(text: &str) -> bool {
    text.contains("PRIVATE KEY-----")
}

/// YAML that PyYAML reads differently from this tree (review of #88): a `<<` merge key, which PyYAML folds into its
/// mapping (so a password behind one escaped the lint), and tags (`!!binary`, `!!python/...`, `!x`), which name types
/// the checks don't know. Both refuse saving.
pub(crate) fn unread_shapes(parsed: &yaml::Parsed) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    if let Some(line) = parsed.merges.first() {
        out.push(ConfigProblem::secret(
            Some(*line),
            "A << merge key folds keys in that Remotely's checks can't see: write the keys out.",
        ));
    }
    if let Some(line) = parsed.tags.first() {
        out.push(ConfigProblem::secret(
            Some(*line),
            "A YAML tag (!...) names a type Remotely's checks don't read: write the value plainly (for write_files, \
             use encoding: b64).",
        ));
    }
    out
}

/// Secrets written into user data, and lock-outs. `prefix` names where the user data sits (`user-data.` inside an
/// autoinstall); `whole` is false there, where the installer's identity may be the user that signs in.
pub(crate) fn user_data_checks(root: &Node, prefix: &str, whole: bool) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    let pw_place = |out: &mut Vec<ConfigProblem>, node: &Node, what: &str| {
        let value = node.text().unwrap_or_default();
        if value.is_empty() || is_sample_secret(value) || matches!(value.trim(), "!" | "*" | "!*") {
            return;
        }
        let why = if looks_hashed(value) {
            format!("{what} holds a password hash: a config never keeps one. Pick the password from the vault in the form, or write {{{{password.<name>}}}}.")
        } else {
            format!("{what} holds a password: a config never keeps one. Pick it from the vault in the form, or write {{{{password.<name>}}}}.")
        };
        out.push(ConfigProblem::secret(Some(node.line), why));
    };
    if let Some(p) = root.get("password") {
        out.push(ConfigProblem::secret(
            Some(p.line),
            format!("{prefix}password sets a plain text password, which a config never keeps: give a user passwd: \"{{{{password.<name>}}}}\" instead."),
        ));
    }
    if let Some(ch) = root.get("chpasswd") {
        if let Some(list) = ch.get("list") {
            out.push(ConfigProblem::secret(
                Some(list.line),
                format!(
                    "{prefix}chpasswd's list holds passwords: give a user passwd: \"{{{{password.<name>}}}}\" instead."
                ),
            ));
        }
        for u in ch.get("users").map(Node::items).unwrap_or_default() {
            if let Some(p) = u.get("password") {
                pw_place(&mut out, p, &format!("{prefix}chpasswd's users"));
            }
        }
    }
    if let Some(keys) = root.get("ssh_keys") {
        if keys
            .entries()
            .iter()
            .any(|(k, v)| k.contains("private") || v.text().is_some_and(private_key_in))
        {
            out.push(ConfigProblem::secret(
                Some(keys.line),
                format!("{prefix}ssh_keys holds a private host key: a config never keeps one."),
            ));
        }
    }
    for f in root.get("write_files").map(Node::items).unwrap_or_default() {
        let content = f.get("content").and_then(Node::text).unwrap_or_default();
        let encoding = f
            .get("encoding")
            .and_then(Node::text)
            .unwrap_or_default()
            .to_ascii_lowercase();
        // Review of #88: base64 content is decoded before it is looked at; gzip content can't be checked, so refused.
        let decoded = match encoding.as_str() {
            "b64" | "base64" => {
                use base64::Engine;
                let compact: String = content.chars().filter(|c| !c.is_whitespace()).collect();
                Some(
                    base64::engine::general_purpose::STANDARD
                        .decode(compact.as_bytes())
                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                        .unwrap_or_default(),
                )
            }
            "gz" | "gzip" | "gz+base64" | "gzip+base64" | "gz+b64" | "gzip+b64" => {
                out.push(ConfigProblem::secret(
                    Some(f.line),
                    format!(
                        "{prefix}write_files has gzip content, which Remotely can't check for a private key: write it plain or as b64."
                    ),
                ));
                continue;
            }
            _ => None,
        };
        if private_key_in(content) || decoded.as_deref().is_some_and(private_key_in) {
            out.push(ConfigProblem::secret(
                Some(f.line),
                format!("{prefix}write_files writes a private key: a config never keeps one."),
            ));
        }
    }
    let users: Vec<&Node> = root.get("users").map(Node::items).unwrap_or_default().iter().collect();
    let mut any_key = root.get("ssh_authorized_keys").is_some_and(|k| !k.items().is_empty());
    let mut any_password = false;
    let mut has_users = false;
    for u in &users {
        if u.text() == Some("default") {
            has_users = true;
            continue;
        }
        if !u.is_map() {
            continue;
        }
        has_users = true;
        let name = u.get("name").and_then(Node::text).unwrap_or("a user").to_owned();
        if let Some(p) = u.get("plain_text_passwd") {
            out.push(ConfigProblem::secret(Some(p.line), format!("{name}'s plain_text_passwd holds a password: use passwd: \"{{{{password.<name>}}}}\", which Remotely writes as a hash.")));
        }
        let mut password = None;
        for key in ["passwd", "hashed_passwd"] {
            if let Some(p) = u.get(key) {
                pw_place(&mut out, p, &format!("{name}'s {key}"));
                if p.text().is_some_and(|t| !t.is_empty()) {
                    password = Some(p);
                }
            }
        }
        let locked = u.get("lock_passwd").and_then(Node::as_bool).unwrap_or(true);
        if let Some(p) = password {
            if locked {
                out.push(ConfigProblem::warning(
                    Some(p.line),
                    format!("{name}'s password is locked, as lock_passwd is true (cloud-init's default): add lock_passwd: false to sign in with it."),
                ));
            } else {
                any_password = true;
            }
        }
        if u.get("ssh_authorized_keys").is_some_and(|k| !k.items().is_empty()) || u.get("ssh_import_id").is_some() {
            any_key = true;
        }
    }
    let pwauth = root.get("ssh_pwauth").and_then(Node::as_bool);
    if whole {
        if !has_users && !any_key {
            out.push(ConfigProblem::warning(
                None,
                "No user gets an SSH key, and the image's default user has no password: you can't sign in. Add a user with a key.",
            ));
        } else if has_users && !any_key && !any_password {
            out.push(ConfigProblem::warning(
                None,
                "No user has an SSH key or a password that works: you can't sign in. Give a user a key.",
            ));
        } else if !any_key && pwauth == Some(false) {
            out.push(ConfigProblem::warning(
                root.get("ssh_pwauth").map(|n| n.line),
                "Password logins over SSH are off and no user has a key: you can only sign in at the console.",
            ));
        }
    }
    out
}

// ---- The form -------------------------------------------------------------------------------------------------------

fn fields() -> Vec<FieldState> {
    vec![
        FieldState::on(FormField::Hostname),
        FieldState::on(FormField::Locale),
        FieldState::on(FormField::Keyboard),
        FieldState::on(FormField::Timezone),
        FieldState::off(
            FormField::Storage,
            "A cloud image's disk is already laid out; cloud-init grows it to the size.",
        ),
        FieldState::off(
            FormField::Network,
            "cloud-init's network settings go in its network config, not the user data.",
        ),
        FieldState::on(FormField::Users),
        FieldState::noted(
            FormField::Ssh,
            "A cloud image runs an SSH server; this sets whether passwords work over it.",
        ),
        FieldState::on(FormField::Packages),
        FieldState::noted(FormField::Updates, "cloud-init upgrades every package or none."),
        FieldState::on(FormField::Proxy),
        FieldState::on(FormField::Mirror),
        FieldState::on(FormField::LateCommands),
    ]
}

pub(crate) fn texts(node: Option<&Node>) -> Vec<String> {
    node.map(Node::items)
        .unwrap_or_default()
        .iter()
        .filter_map(|n| n.text().map(str::to_owned))
        .collect()
}

pub(crate) fn opt_text(node: Option<&Node>) -> Option<String> {
    node.and_then(Node::text).map(str::to_owned).filter(|t| !t.is_empty())
}

/// A user from a `users:` item.
pub(crate) fn user_of(u: &Node) -> Option<UserForm> {
    let name = u.get("name").and_then(Node::text)?.to_owned();
    let locked = u.get("lock_passwd").and_then(Node::as_bool).unwrap_or(true);
    let password = opt_text(u.get("passwd")).or_else(|| opt_text(u.get("hashed_passwd")));
    let sudo = match u.get("sudo") {
        None => false,
        Some(s) => s.as_bool() != Some(false) && !s.is_null(),
    };
    Some(UserForm {
        name,
        password: password.filter(|_| !locked),
        ssh_keys: texts(u.get("ssh_authorized_keys")),
        sudo,
    })
}

/// A `users:` item for `user`, keeping what `old` had that the form doesn't know.
pub(crate) fn user_node(user: &UserForm, old: Option<&Node>) -> Node {
    let mut entries: Vec<(String, Node)> = Vec::new();
    let put = |entries: &mut Vec<(String, Node)>, key: &str, value: Option<Node>| {
        let at = entries.iter().position(|(k, _)| k == key);
        match (at, value) {
            (Some(i), Some(v)) => entries[i].1 = v,
            (None, Some(v)) => entries.push((key.to_owned(), v)),
            (Some(i), None) => {
                entries.remove(i);
            }
            (None, None) => {}
        }
    };
    if let Some(old) = old {
        entries = old.entries().to_vec();
    }
    put(&mut entries, "name", Some(Node::str(user.name.trim())));
    let had_sudo = entries.iter().any(|(k, _)| k == "sudo");
    if user.sudo && !had_sudo {
        put(&mut entries, "sudo", Some(Node::str("ALL=(ALL) NOPASSWD:ALL")));
    } else if !user.sudo {
        put(&mut entries, "sudo", None);
    }
    if !entries.iter().any(|(k, _)| k == "shell") {
        put(&mut entries, "shell", Some(Node::str("/bin/bash")));
    }
    put(&mut entries, "hashed_passwd", None);
    put(&mut entries, "plain_text_passwd", None);
    match user.password.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => {
            put(&mut entries, "lock_passwd", Some(Node::bool(false)));
            put(&mut entries, "passwd", Some(Node::quoted(p)));
        }
        None => {
            put(&mut entries, "lock_passwd", Some(Node::bool(true)));
            put(&mut entries, "passwd", None);
        }
    }
    let keys: Vec<Node> = user
        .ssh_keys
        .iter()
        .map(|k| k.trim())
        .filter(|k| !k.is_empty())
        .map(Node::quoted)
        .collect();
    put(
        &mut entries,
        "ssh_authorized_keys",
        (!keys.is_empty()).then(|| Node::seq(keys)),
    );
    Node::new(Value::Map(entries))
}

pub(crate) fn primary_uri(apt: Option<&Node>) -> Option<String> {
    let apt = apt?;
    let list = apt
        .get("primary")
        .or_else(|| apt.at(&["mirror-selection", "primary"]))?;
    list.items().iter().find_map(|i| opt_text(i.get("uri")))
}

pub(crate) fn primary_node(uri: &str) -> Node {
    Node::seq(vec![Node::map(vec![
        ("arches", Node::seq(vec![Node::str("default")])),
        ("uri", Node::str(uri.trim())),
    ])])
}

pub(crate) fn command_texts(node: Option<&Node>) -> (Vec<String>, bool) {
    let items = node.map(Node::items).unwrap_or_default();
    let simple = items.iter().all(|i| i.text().is_some());
    (texts(node), simple)
}

pub fn read_form(body: &str) -> FormRead {
    let Some((protected, table)) = protect(body) else {
        return FormRead::unreadable("The file holds a private-use character the form can't follow.");
    };
    let root = match yaml::parse(&protected) {
        Err(err) => return FormRead::unreadable(format!("Line {}: {}", err.line, err.message)),
        Ok(parsed) => parsed
            .docs
            .into_iter()
            .next()
            .unwrap_or(Node::new(Value::Map(Vec::new()))),
    };
    if !root.is_map() && !root.is_null() {
        return FormRead::unreadable("The user data isn't a mapping of settings.");
    }
    let r = |s: Option<String>| s.map(|s| restore(&s, &table));
    let rl = |v: Vec<String>| v.into_iter().map(|s| restore(&s, &table)).collect::<Vec<_>>();
    let users: Vec<UserForm> = root
        .get("users")
        .map(Node::items)
        .unwrap_or_default()
        .iter()
        .filter_map(user_of)
        .map(|u| UserForm {
            name: restore(&u.name, &table),
            password: r(u.password),
            ssh_keys: rl(u.ssh_keys),
            sudo: u.sudo,
        })
        .collect();
    let (late, simple) = command_texts(root.get("runcmd"));
    let mut fields = fields();
    if !simple {
        set_off(
            &mut fields,
            FormField::LateCommands,
            "Some commands are written as lists: edit runcmd in the file.",
        );
    }
    if root
        .get("users")
        .map(Node::items)
        .unwrap_or_default()
        .iter()
        .any(|u| u.is_map() && u.get("name").is_none())
    {
        set_off(
            &mut fields,
            FormField::Users,
            "A user has no name: fix users in the file.",
        );
    }
    let updates = match (
        root.get("package_upgrade").and_then(Node::as_bool),
        root.get("package_update"),
    ) {
        (Some(true), _) => Some(Updates::All),
        (Some(false), _) => Some(Updates::None),
        (None, Some(_)) => Some(Updates::None),
        (None, None) => None,
    };
    let apt = root.get("apt");
    let form = InstallForm {
        hostname: r(opt_text(root.get("hostname"))),
        locale: r(opt_text(root.get("locale"))),
        keyboard: r(opt_text(root.at(&["keyboard", "layout"]))),
        timezone: r(opt_text(root.get("timezone"))),
        storage: None,
        network: None,
        users,
        ssh: root.get("ssh_pwauth").and_then(Node::as_bool).map(|pw| SshForm {
            install_server: true,
            password_logins: pw,
        }),
        packages: rl(texts(root.get("packages"))),
        updates,
        proxy: r(apt.and_then(|a| opt_text(a.get("proxy")).or_else(|| opt_text(a.get("http_proxy"))))),
        mirror: r(primary_uri(apt)),
        late_commands: rl(late),
    };
    FormRead {
        form,
        fields,
        max_users: None,
        unreadable: None,
    }
}

pub(crate) fn set_off(fields: &mut [FieldState], field: FormField, why: &str) {
    if let Some(f) = fields.iter_mut().find(|f| f.field == field) {
        f.editable = false;
        f.note = Some(why.to_owned());
    }
}

pub(crate) fn opt_str(value: &Option<String>) -> Option<Node> {
    value.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(Node::str)
}

pub(crate) fn list(values: &[String]) -> Option<Node> {
    let items: Vec<Node> = values
        .iter()
        .map(|v| v.trim_end_matches('\n'))
        .filter(|v| !v.trim().is_empty())
        .map(Node::str)
        .collect();
    (!items.is_empty()).then(|| Node::seq(items))
}

/// Sets one key on the protected text, as an error message the form shows.
pub(crate) fn set(text: &mut String, path: &[&str], value: Option<Node>) -> Result<(), String> {
    *text = yaml::set(text, path, value.as_ref()).map_err(|e| e.0)?;
    Ok(())
}

pub fn apply_form(
    body: &str,
    _before: &InstallForm,
    after: &InstallForm,
    changed: &[FormField],
) -> Result<String, String> {
    let (mut text, table) = protect(body).ok_or("The file holds a private-use character the form can't follow.")?;
    let root = yaml::parse(&text)
        .map_err(|e| e.message)?
        .docs
        .into_iter()
        .next()
        .unwrap_or(Node::new(Value::Null));
    for field in changed {
        match field {
            FormField::Hostname => set(&mut text, &["hostname"], opt_str(&after.hostname))?,
            FormField::Locale => set(&mut text, &["locale"], opt_str(&after.locale))?,
            FormField::Keyboard => match opt_str(&after.keyboard) {
                Some(layout) => set(&mut text, &["keyboard", "layout"], Some(layout))?,
                None => set(&mut text, &["keyboard"], None)?,
            },
            FormField::Timezone => set(&mut text, &["timezone"], opt_str(&after.timezone))?,
            FormField::Users => {
                let old: Vec<&Node> = root.get("users").map(Node::items).unwrap_or_default().iter().collect();
                let mut items: Vec<Node> = old
                    .iter()
                    .filter(|u| u.text() == Some("default"))
                    .map(|u| (*u).clone())
                    .collect();
                let named: Vec<&&Node> = old.iter().filter(|u| u.is_map()).collect();
                for (i, user) in after.users.iter().enumerate() {
                    items.push(user_node(user, named.get(i).map(|n| **n)));
                }
                set(&mut text, &["users"], (!items.is_empty()).then(|| Node::seq(items)))?;
            }
            FormField::Ssh => set(
                &mut text,
                &["ssh_pwauth"],
                after.ssh.map(|s| Node::bool(s.password_logins)),
            )?,
            FormField::Packages => set(&mut text, &["packages"], list(&after.packages))?,
            FormField::Updates => match after.updates {
                Some(Updates::All) => {
                    set(&mut text, &["package_update"], Some(Node::bool(true)))?;
                    set(&mut text, &["package_upgrade"], Some(Node::bool(true)))?;
                }
                Some(Updates::None) => set(&mut text, &["package_upgrade"], Some(Node::bool(false)))?,
                None => set(&mut text, &["package_upgrade"], None)?,
                Some(Updates::Security) => return Err("cloud-init upgrades every package or none.".into()),
            },
            FormField::Proxy => {
                let has_http = root.at(&["apt", "http_proxy"]).is_some();
                set(
                    &mut text,
                    &["apt", if has_http { "http_proxy" } else { "proxy" }],
                    opt_str(&after.proxy),
                )?;
            }
            FormField::Mirror => set(
                &mut text,
                &["apt", "primary"],
                after
                    .mirror
                    .as_deref()
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(primary_node),
            )?,
            FormField::LateCommands => set(&mut text, &["runcmd"], list(&after.late_commands))?,
            FormField::Storage | FormField::Network => {
                return Err("The form doesn't set that in cloud-init user data.".into())
            }
        }
    }
    Ok(restore(&text, &table))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::catalog::install::{Severity, SAMPLE_HASH};

    fn messages(problems: &[ConfigProblem]) -> String {
        problems
            .iter()
            .map(|p| p.message.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn the_header_and_yaml_are_checked() {
        assert!(syntax("#cloud-config\nhostname: a\n").is_empty());
        assert!(messages(&syntax("hostname: a\n")).contains("#cloud-config"));
        let bad = syntax("#cloud-config\nusers: [\n");
        assert!(
            bad.iter().any(|p| p.message.starts_with("This isn't valid YAML")),
            "{bad:?}"
        );
    }

    #[test]
    fn secrets_in_the_file_refuse_saving() {
        let text = format!(
            "#cloud-config\npassword: x\nusers:\n  - name: alice\n    passwd: $6$abc$def$ghijklmnop\n  - name: bob\n    plain_text_passwd: x\n  - name: carol\n    passwd: \"{SAMPLE_HASH}\"\n    lock_passwd: false\nssh_keys:\n  rsa_private: |\n    -----BEGIN RSA PRIVATE KEY-----\n"
        );
        let problems = check(&text);
        let secrets: Vec<&ConfigProblem> = problems.iter().filter(|p| p.blocks_saving).collect();
        assert_eq!(secrets.len(), 4, "{problems:?}");
        assert!(messages(&problems).contains("password hash"));
    }

    #[test]
    fn lock_outs_are_warned_about() {
        let warn = |text: &str| messages(&check(text));
        assert!(warn("#cloud-config\nhostname: a\n").contains("can't sign in"));
        assert!(warn("#cloud-config\nusers:\n  - name: alice\n").contains("can't sign in"));
        assert!(warn(&format!(
            "#cloud-config\nusers:\n  - name: alice\n    passwd: \"{SAMPLE_HASH}\"\n"
        ))
        .contains("is locked"));
        let fine = check("#cloud-config\nusers:\n  - name: alice\n    ssh_authorized_keys: [\"ssh-ed25519 AAAA alice@example.com\"]\nssh_pwauth: false\n");
        assert!(!fine.iter().any(|p| p.severity == Severity::Error), "{fine:?}");
        assert!(!messages(&fine).contains("sign in"), "{fine:?}");
        assert!(warn(
            "#cloud-config\nusers:\n  - name: alice\n    passwd: \"x\"\n    lock_passwd: false\nssh_pwauth: false\n"
        )
        .contains("holds a password"));
        assert!(warn("#cloud-config\nfoo: 1\n").contains("doesn't know the setting foo"));
    }

    const FILE: &str = "#cloud-config\n# Kept.\nhostname: \"{{hostname}}\"\nusers:\n  - default\n  - name: alice\n    groups: [docker]\n    lock_passwd: false\n    passwd: \"{{password.admin}}\"\n    ssh_authorized_keys:\n      - \"{{ssh_key.admin}}\"\npackages:\n  - curl\nruncmd:\n  - echo {{n}}\n";

    #[test]
    fn the_form_reads_the_file_and_writes_only_what_changed() {
        let read = read_form(FILE);
        assert_eq!(read.unreadable, None);
        let form = read.form.clone();
        assert_eq!(form.hostname.as_deref(), Some("{{hostname}}"));
        assert_eq!(form.users.len(), 1);
        assert_eq!(form.users[0].password.as_deref(), Some("{{password.admin}}"));
        assert_eq!(form.users[0].ssh_keys, ["{{ssh_key.admin}}"]);
        assert_eq!(form.late_commands, ["echo {{n}}"]);
        let mut after = form.clone();
        after.packages.push("nginx".into());
        after.users[0].sudo = true;
        after.users.push(UserForm {
            name: "bob".into(),
            password: None,
            ssh_keys: vec!["{{ssh_key.bob}}".into()],
            sudo: false,
        });
        let changed = super::super::changed_fields(&form, &after);
        let out = apply_form(FILE, &form, &after, &changed).unwrap();
        assert!(
            out.starts_with("#cloud-config\n# Kept.\nhostname: \"{{hostname}}\"\n"),
            "{out}"
        );
        assert!(
            out.contains("  - default\n  - name: alice\n    groups:\n      - docker\n"),
            "{out}"
        );
        assert!(out.contains("    sudo: ALL=(ALL) NOPASSWD:ALL\n"), "{out}");
        assert!(out.contains("  - name: bob\n    shell: /bin/bash\n    lock_passwd: true\n    ssh_authorized_keys:\n      - \"{{ssh_key.bob}}\"\n"), "{out}");
        assert!(
            out.contains("packages:\n  - curl\n  - nginx\nruncmd:\n  - echo {{n}}\n"),
            "{out}"
        );
        let again = read_form(&out).form;
        assert_eq!(again.users, after.users);
        assert_eq!(again.packages, after.packages);
    }
}
