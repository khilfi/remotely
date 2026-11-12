//! VM-28: Ubuntu Server's autoinstall (Subiquity), as cloud-init user data with an `autoinstall:` section (how a
//! `cidata` seed carries it), or a bare autoinstall document (`version: 1` at the top).
//!
//! [`SCHEMA`] is the part of Ubuntu's published autoinstall schema (`autoinstall-schema.json`, Ubuntu 24.04's
//! Subiquity) that Remotely checks, written as code rather than fetched: each section's type, its required keys, and the
//! values of its enumerations. Subiquity reads YAML with PyYAML, so `yes` and `no` are booleans here too. Keys the
//! schema doesn't list are warned about, not refused, as newer installers add sections.

use super::cloud_init::{
    command_texts, list, opt_str, opt_text, primary_node, primary_uri, set, set_off, texts, user_data_checks,
};
use super::form::{
    FieldState, FormField, FormRead, InstallForm, NetworkForm, SshForm, StorageForm, StorageLayout, Swap, Updates,
    UserForm,
};
use super::yaml::{self, Node, Value};
use super::{is_sample_secret, looks_hashed, protect, restore, ConfigProblem, Severity};

/// A schema type.
#[derive(Debug, Clone, Copy)]
enum T {
    Str,
    Bool,
    Int,
    StrList,
    /// A list of commands, each a string or a list of arguments.
    Commands,
    StrOrNull,
    BoolOrNull,
    /// `true`, `false` or `"auto"`.
    BoolOrAuto,
    /// An integer or a size such as `4G`.
    Size,
    Enum(&'static [&'static str]),
    Obj(&'static [F]),
    ObjList(&'static [F]),
    /// A mapping the schema leaves open (netplan, curtin, cloud-init).
    AnyMap,
    Any,
}

#[derive(Debug, Clone, Copy)]
struct F {
    name: &'static str,
    t: T,
    required: bool,
}

const fn f(name: &'static str, t: T) -> F {
    F {
        name,
        t,
        required: false,
    }
}

const fn req(name: &'static str, t: T) -> F {
    F {
        name,
        t,
        required: true,
    }
}

/// Ubuntu 24.04's autoinstall schema, the parts Remotely checks.
const SCHEMA: &[F] = &[
    req("version", T::Int),
    f("interactive-sections", T::StrList),
    f("early-commands", T::Commands),
    f("locale", T::Str),
    f(
        "refresh-installer",
        T::Obj(&[f("update", T::Bool), f("channel", T::Str)]),
    ),
    f(
        "keyboard",
        T::Obj(&[req("layout", T::Str), f("variant", T::Str), f("toggle", T::StrOrNull)]),
    ),
    f("source", T::Obj(&[f("search_drivers", T::Bool), f("id", T::Str)])),
    f("network", T::AnyMap),
    f("proxy", T::StrOrNull),
    f(
        "apt",
        T::Obj(&[
            f("preserve_sources_list", T::Bool),
            f("primary", T::Any),
            f("mirror-selection", T::AnyMap),
            f("geoip", T::Bool),
            f("sources", T::AnyMap),
            f("disable_components", T::StrList),
            f("disable_suites", T::StrList),
            f("fallback", T::Enum(&["abort", "continue-anyway", "offline-install"])),
            f("proxy", T::Str),
            f("http_proxy", T::Str),
            f("https_proxy", T::Str),
            f("conf", T::Str),
            f("debconf_selections", T::AnyMap),
            f("security", T::Any),
            f("sources_list", T::Str),
        ]),
    ),
    f(
        "storage",
        T::Obj(&[
            f(
                "layout",
                T::Obj(&[
                    req("name", T::Enum(&["lvm", "direct", "zfs", "hybrid"])),
                    f("match", T::AnyMap),
                    f("sizing-policy", T::Enum(&["scaled", "all"])),
                    f("reset-partition", T::Any),
                    f("password", T::Str),
                ]),
            ),
            f("config", T::Any),
            f(
                "swap",
                T::Obj(&[f("size", T::Size), f("filename", T::Str), f("maxsize", T::Size)]),
            ),
            f("grub", T::AnyMap),
            f("version", T::Int),
        ]),
    ),
    f(
        "identity",
        T::Obj(&[
            f("realname", T::Str),
            req("username", T::Str),
            req("hostname", T::Str),
            req("password", T::Str),
        ]),
    ),
    f(
        "active-directory",
        T::Obj(&[f("admin-name", T::Str), f("domain-name", T::Str)]),
    ),
    f("ubuntu-pro", T::Obj(&[f("token", T::Str)])),
    f("ubuntu-advantage", T::Obj(&[f("token", T::Str)])),
    f(
        "ssh",
        T::Obj(&[
            f("install-server", T::Bool),
            f("authorized-keys", T::StrList),
            f("allow-pw", T::Bool),
        ]),
    ),
    f("codecs", T::Obj(&[f("install", T::Bool)])),
    f("drivers", T::Obj(&[f("install", T::Bool)])),
    f("oem", T::Obj(&[f("install", T::BoolOrAuto)])),
    f(
        "snaps",
        T::ObjList(&[req("name", T::Str), f("channel", T::Str), f("classic", T::Bool)]),
    ),
    f("debconf-selections", T::Str),
    f("packages", T::StrList),
    f("kernel", T::Obj(&[f("package", T::Str), f("flavor", T::Str)])),
    f("kernel-crash-dumps", T::Obj(&[f("enabled", T::BoolOrNull)])),
    f("timezone", T::Str),
    f("updates", T::Enum(&["security", "all"])),
    f("late-commands", T::Commands),
    f("error-commands", T::Commands),
    f("reporting", T::AnyMap),
    f("user-data", T::AnyMap),
    f("shutdown", T::Enum(&["reboot", "poweroff"])),
    f("zdevs", T::Any),
];

fn type_name(t: T) -> String {
    match t {
        T::Str => "text".into(),
        T::Bool => "true or false".into(),
        T::Int => "a whole number".into(),
        T::StrList => "a list of text".into(),
        T::Commands => "a list of commands".into(),
        T::StrOrNull => "text or nothing".into(),
        T::BoolOrNull => "true, false or nothing".into(),
        T::BoolOrAuto => "true, false or auto".into(),
        T::Size => "a size such as 4G".into(),
        T::Enum(values) => format!("one of {}", values.join(", ")),
        T::Obj(_) | T::AnyMap => "a mapping".into(),
        T::ObjList(_) => "a list of mappings".into(),
        T::Any => "a value".into(),
    }
}

fn fits(node: &Node, t: T) -> bool {
    match t {
        T::Str => node.as_str().is_some() || matches!(node.value, Value::Str(..)),
        T::Bool => node.as_bool().is_some(),
        T::Int => node.as_int().is_some(),
        T::StrList => node.is_seq() && node.items().iter().all(|i| i.text().is_some()),
        T::Commands => {
            node.is_seq()
                && node
                    .items()
                    .iter()
                    .all(|i| i.text().is_some() || (i.is_seq() && i.items().iter().all(|a| a.text().is_some())))
        }
        T::StrOrNull => node.is_null() || node.text().is_some(),
        T::BoolOrNull => node.is_null() || node.as_bool().is_some(),
        T::BoolOrAuto => node.as_bool().is_some() || node.text() == Some("auto"),
        T::Size => node.as_int().is_some() || node.text().is_some_and(|t| size_mb(t).is_some()),
        T::Enum(values) => node.text().is_some_and(|v| values.contains(&v)),
        T::Obj(_) | T::AnyMap => node.is_map(),
        T::ObjList(_) => node.is_seq() && node.items().iter().all(Node::is_map),
        T::Any => true,
    }
}

fn check_fields(node: &Node, fields: &[F], at: &str, out: &mut Vec<ConfigProblem>) {
    for field in fields {
        if field.required && node.get(field.name).is_none() {
            let where_ = if at.is_empty() {
                "autoinstall".to_owned()
            } else {
                at.to_owned()
            };
            out.push(ConfigProblem::error(
                Some(node.line),
                format!("{where_} needs {}: Ubuntu's schema requires it.", field.name),
            ));
        }
    }
    for (key, value) in node.entries() {
        let path = if at.is_empty() {
            key.clone()
        } else {
            format!("{at}.{key}")
        };
        let Some(field) = fields.iter().find(|f| f.name == key) else {
            out.push(ConfigProblem::warning(
                Some(value.line),
                format!("Ubuntu's autoinstall schema has no {path}: the installer may stop on it."),
            ));
            continue;
        };
        if !fits(value, field.t) {
            out.push(ConfigProblem::error(
                Some(value.line),
                format!("{path} has to be {} (Ubuntu's schema).", type_name(field.t)),
            ));
            continue;
        }
        match field.t {
            T::Obj(inner) => check_fields(value, inner, &path, out),
            T::ObjList(inner) => {
                for item in value.items() {
                    check_fields(item, inner, &path, out);
                }
            }
            _ => {}
        }
    }
}

/// The autoinstall section and the path to it: under `autoinstall:` in user data, or the document itself.
fn section(doc: &Node) -> Option<(&Node, &'static [&'static str])> {
    match doc.get("autoinstall") {
        Some(node) if node.is_map() => Some((node, &["autoinstall"])),
        Some(_) => None,
        None if doc.get("version").is_some() => Some((doc, &[])),
        None => None,
    }
}

/// The YAML, the `#cloud-config` header when it is user data, and an autoinstall section to read.
pub fn syntax(text: &str) -> Vec<ConfigProblem> {
    let parsed = match yaml::parse(text) {
        Err(err) => return vec![ConfigProblem::error(Some(err.line), err.message)],
        Ok(parsed) => parsed,
    };
    let Some(doc) = parsed.docs.first() else {
        return vec![ConfigProblem::error(
            Some(1),
            "The file is empty: it needs an autoinstall section.",
        )];
    };
    let mut out = Vec::new();
    if parsed.docs.len() > 1 {
        out.push(ConfigProblem::error(
            None,
            "The installer reads one YAML document: remove the others.",
        ));
    }
    match section(doc) {
        None => out.push(ConfigProblem::error(
            Some(doc.line.max(1)),
            "The file needs an autoinstall: section with version: 1.",
        )),
        Some((_, path)) if !path.is_empty() => {
            let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            if first.trim_end() != "#cloud-config" {
                out.push(ConfigProblem::error(
                    Some(1),
                    "User data starts with #cloud-config, or cloud-init passes nothing to the installer.",
                ));
            }
        }
        Some(_) => {}
    }
    out
}

/// Syntax, Ubuntu's schema, secrets in the file and lock-outs.
pub fn check(text: &str) -> Vec<ConfigProblem> {
    let mut out = syntax(text);
    if out.iter().any(|p| p.severity == Severity::Error) {
        return out;
    }
    let Ok(parsed) = yaml::parse(text) else {
        return out;
    };
    out.extend(super::cloud_init::unread_shapes(&parsed));
    for (line, key) in &parsed.duplicates {
        out.push(ConfigProblem::warning(
            Some(*line),
            format!("{key} is set twice: the installer takes the last."),
        ));
    }
    let Some((ai, _)) = parsed.docs.first().and_then(section) else {
        return out;
    };
    check_fields(ai, SCHEMA, "", &mut out);
    if let Some(v) = ai.get("version") {
        if v.as_int().is_some_and(|n| n != 1) {
            out.push(ConfigProblem::error(
                Some(v.line),
                "version has to be 1: the only autoinstall version there is.",
            ));
        }
    }
    out.extend(lint(ai));
    out
}

fn lint(ai: &Node) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    let interactive = cloud_init_texts(ai.get("interactive-sections"));
    if !interactive.is_empty() {
        out.push(ConfigProblem::warning(
            ai.get("interactive-sections").map(|n| n.line),
            format!(
                "The installer stops to ask about {}: an unattended deploy would wait.",
                interactive.join(", ")
            ),
        ));
    }
    // Secrets.
    if let Some(p) = ai.at(&["identity", "password"]) {
        let value = p.text().unwrap_or_default();
        if !value.is_empty() && !is_sample_secret(value) {
            let what = if looks_hashed(value) {
                "a password hash"
            } else {
                "a password"
            };
            out.push(ConfigProblem::secret(
                Some(p.line),
                format!("identity's password holds {what}: a config never keeps one. Pick it from the vault in the form, or write \"{{{{password.<name>}}}}\"."),
            ));
        }
    }
    if let Some(p) = ai.at(&["storage", "layout", "password"]) {
        out.push(ConfigProblem::secret(
            Some(p.line),
            "The disk's encryption passphrase would sit in the file in plain text: Remotely's configs can't hold one.",
        ));
    }
    for key in ["ubuntu-pro", "ubuntu-advantage"] {
        if let Some(t) = ai.at(&[key, "token"]) {
            out.push(ConfigProblem::warning(
                Some(t.line),
                "An Ubuntu Pro token is your account's: it travels with the config in exports.",
            ));
        }
    }
    let user_data = ai.get("user-data").filter(|u| u.is_map());
    if let Some(ud) = user_data {
        out.extend(user_data_checks(ud, "user-data.", false));
    }
    // Lock-outs.
    let identity = ai.get("identity");
    let ud_users = user_data
        .and_then(|u| u.get("users"))
        .is_some_and(|u| !u.items().is_empty());
    if identity.is_none() && !ud_users && !interactive.iter().any(|s| s == "identity") {
        out.push(ConfigProblem::error(
            None,
            "No user: add one under Users (identity), or users in user-data.",
        ));
    }
    let keys = cloud_init_texts(ai.at(&["ssh", "authorized-keys"]));
    let install_server = ai
        .at(&["ssh", "install-server"])
        .and_then(Node::as_bool)
        .unwrap_or(false);
    if !install_server {
        out.push(ConfigProblem::warning(
            ai.get("ssh").map(|n| n.line),
            "No SSH server: ssh.install-server isn't true, so nobody can sign in over SSH after the install.",
        ));
    }
    let allow_pw = ai
        .at(&["ssh", "allow-pw"])
        .and_then(Node::as_bool)
        .unwrap_or(keys.is_empty());
    let ud_keys = user_data.is_some_and(|ud| {
        ud.get("ssh_authorized_keys").is_some()
            || ud
                .get("users")
                .map(Node::items)
                .unwrap_or_default()
                .iter()
                .any(|u| u.get("ssh_authorized_keys").is_some())
    });
    if install_server && !allow_pw && keys.is_empty() && !ud_keys {
        out.push(ConfigProblem::warning(
            ai.at(&["ssh", "allow-pw"]).map(|n| n.line),
            "Password logins over SSH are off and no SSH key is set: you can only sign in at the console.",
        ));
    }
    if identity.is_some_and(|i| {
        i.get("password")
            .and_then(Node::text)
            .is_some_and(|p| p.starts_with('!'))
    }) && keys.is_empty()
        && !ud_keys
    {
        out.push(ConfigProblem::warning(
            identity.map(|n| n.line),
            "The user's password is locked and no SSH key is set: nobody can sign in.",
        ));
    }
    out
}

fn cloud_init_texts(node: Option<&Node>) -> Vec<String> {
    texts(node)
}

/// A size such as `512M`, `20G` or `1T` (or bytes) in MB.
pub(crate) fn size_mb(text: &str) -> Option<u64> {
    let t = text.trim();
    let (number, unit) = match t.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(i) => (&t[..i], t[i..].trim()),
        None => (t, ""),
    };
    let n: f64 = number.parse().ok()?;
    let mb = match unit.to_ascii_uppercase().trim_end_matches('B') {
        "" => n / (1024.0 * 1024.0),
        "K" => n / 1024.0,
        "M" => n,
        "G" => n * 1024.0,
        "T" => n * 1024.0 * 1024.0,
        _ => return None,
    };
    // Whole MB, rounded up; sizes are far below f64's exact range.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(mb.ceil().max(0.0) as u64)
}

/// The partitions `storage.config` sizes, and the swap file, in MB.
pub fn disk_need_mb(text: &str) -> Option<u64> {
    let parsed = yaml::parse(text).ok()?;
    let (ai, _) = parsed.docs.first().and_then(section)?;
    let storage = ai.get("storage")?;
    let mut total = 0u64;
    let mut any = false;
    for action in storage.get("config").map(Node::items).unwrap_or_default() {
        if action.get("type").and_then(Node::text) == Some("partition") {
            if let Some(mb) = action.get("size").and_then(Node::text).and_then(size_mb) {
                total += mb;
                any = true;
            }
        }
    }
    if let Some(mb) = storage.at(&["swap", "size"]).and_then(Node::text).and_then(size_mb) {
        total += mb;
        any = any || mb > 0;
    }
    any.then_some(total)
}

// ---- The form -------------------------------------------------------------------------------------------------------

fn network_of(node: &Node) -> Option<NetworkForm> {
    let net = node.get("network").filter(|n| n.is_map()).unwrap_or(node);
    let (_, eth) = net.get("ethernets")?.entries().first()?;
    if eth.get("dhcp4").and_then(Node::as_bool) == Some(true) {
        return Some(NetworkForm::Dhcp);
    }
    let first = eth.get("addresses")?.items().first()?.text()?.to_owned();
    let (address, prefix) = first.split_once('/')?;
    let gateway = eth
        .get("routes")
        .map(Node::items)
        .unwrap_or_default()
        .iter()
        .find(|r| matches!(r.get("to").and_then(Node::text), Some("default" | "0.0.0.0/0")))
        .and_then(|r| opt_text(r.get("via")))
        .or_else(|| opt_text(eth.get("gateway4")));
    Some(NetworkForm::Static {
        address: address.to_owned(),
        prefix: prefix.parse().ok()?,
        gateway,
        dns: texts(eth.at(&["nameservers", "addresses"])),
    })
}

/// Netplan for the form's network: one entry matching any `en*` or `eth*` card, as each hypervisor names it.
pub(crate) fn network_node(network: &NetworkForm) -> Node {
    let mut eth = vec![("match", Node::map(vec![("name", Node::quoted("e*"))]))];
    match network {
        NetworkForm::Dhcp => eth.push(("dhcp4", Node::bool(true))),
        NetworkForm::Static {
            address,
            prefix,
            gateway,
            dns,
        } => {
            eth.push((
                "addresses",
                Node::seq(vec![Node::quoted(format!("{}/{prefix}", address.trim()))]),
            ));
            if let Some(g) = gateway.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
                eth.push((
                    "routes",
                    Node::seq(vec![Node::map(vec![
                        ("to", Node::str("default")),
                        ("via", Node::quoted(g)),
                    ])]),
                ));
            }
            let dns: Vec<Node> = dns
                .iter()
                .map(|d| d.trim())
                .filter(|d| !d.is_empty())
                .map(Node::quoted)
                .collect();
            if !dns.is_empty() {
                eth.push(("nameservers", Node::map(vec![("addresses", Node::seq(dns))])));
            }
        }
    }
    Node::map(vec![
        ("version", Node::int(2)),
        ("ethernets", Node::map(vec![("any", Node::map(eth))])),
    ])
}

fn fields() -> Vec<FieldState> {
    vec![
        FieldState::on(FormField::Hostname),
        FieldState::on(FormField::Locale),
        FieldState::on(FormField::Keyboard),
        FieldState::on(FormField::Timezone),
        FieldState::on(FormField::Storage),
        FieldState::on(FormField::Network),
        FieldState::noted(
            FormField::Users,
            "Ubuntu's identity is one user; add more under user-data in the file.",
        ),
        FieldState::on(FormField::Ssh),
        FieldState::on(FormField::Packages),
        FieldState::on(FormField::Updates),
        FieldState::on(FormField::Proxy),
        FieldState::on(FormField::Mirror),
        FieldState::on(FormField::LateCommands),
    ]
}

pub fn read_form(body: &str) -> FormRead {
    let Some((protected, table)) = protect(body) else {
        return FormRead::unreadable("The file holds a private-use character the form can't follow.");
    };
    let doc = match yaml::parse(&protected) {
        Err(err) => return FormRead::unreadable(format!("Line {}: {}", err.line, err.message)),
        Ok(parsed) => parsed.docs.into_iter().next(),
    };
    let empty = Node::new(Value::Map(vec![(
        "autoinstall".into(),
        Node::new(Value::Map(Vec::new())),
    )]));
    let doc = doc.filter(|d| !d.is_null()).unwrap_or(empty);
    let Some((ai, _)) = section(&doc) else {
        return FormRead::unreadable("The file has no autoinstall section yet: add autoinstall: with version: 1.");
    };
    let r = |s: Option<String>| s.map(|s| restore(&s, &table));
    let rl = |v: Vec<String>| v.into_iter().map(|s| restore(&s, &table)).collect::<Vec<_>>();
    let mut fields = fields();
    let storage = ai.get("storage").map(|s| {
        let layout = if s.get("config").is_some() {
            StorageLayout::Custom
        } else {
            match s.at(&["layout", "name"]).and_then(Node::text) {
                Some("direct") => StorageLayout::Plain,
                Some("lvm") | None => StorageLayout::Lvm,
                Some(_) => StorageLayout::Custom,
            }
        };
        let swap = match s.at(&["swap", "size"]).and_then(Node::text).and_then(size_mb) {
            None => Swap::Auto,
            Some(0) => Swap::None,
            Some(mb) => Swap::SizeMb {
                mb: u32::try_from(mb).unwrap_or(u32::MAX),
            },
        };
        StorageForm { layout, swap }
    });
    if storage.is_some_and(|s| s.layout == StorageLayout::Custom) {
        set_off(
            &mut fields,
            FormField::Storage,
            "The file lays the disk out itself: edit storage in the file.",
        );
    }
    let network = ai.get("network").and_then(network_of);
    if ai.get("network").is_some() && network.is_none() {
        set_off(
            &mut fields,
            FormField::Network,
            "The file's network settings go beyond the form: edit them in the file.",
        );
    }
    let users = ai
        .get("identity")
        .map(|id| {
            vec![UserForm {
                name: restore(id.get("username").and_then(Node::text).unwrap_or_default(), &table),
                password: r(opt_text(id.get("password"))),
                ssh_keys: rl(texts(ai.at(&["ssh", "authorized-keys"]))),
                sudo: true,
            }]
        })
        .unwrap_or_default();
    let keys = texts(ai.at(&["ssh", "authorized-keys"]));
    let ssh = ai.get("ssh").map(|s| SshForm {
        install_server: s.get("install-server").and_then(Node::as_bool).unwrap_or(false),
        password_logins: s.get("allow-pw").and_then(Node::as_bool).unwrap_or(keys.is_empty()),
    });
    let (late, simple) = command_texts(ai.get("late-commands"));
    if !simple {
        set_off(
            &mut fields,
            FormField::LateCommands,
            "Some commands are written as lists: edit late-commands in the file.",
        );
    }
    let form = InstallForm {
        hostname: r(opt_text(ai.at(&["identity", "hostname"]))),
        locale: r(opt_text(ai.get("locale"))),
        keyboard: r(opt_text(ai.at(&["keyboard", "layout"]))),
        timezone: r(opt_text(ai.get("timezone"))),
        storage,
        network: network.map(|n| match n {
            NetworkForm::Static {
                address,
                prefix,
                gateway,
                dns,
            } => NetworkForm::Static {
                address: restore(&address, &table),
                prefix,
                gateway: r(gateway),
                dns: rl(dns),
            },
            dhcp => dhcp,
        }),
        users,
        ssh,
        packages: rl(texts(ai.get("packages"))),
        updates: match ai.get("updates").and_then(Node::text) {
            Some("all") => Some(Updates::All),
            Some("security") => Some(Updates::Security),
            _ => None,
        },
        proxy: r(opt_text(ai.get("proxy"))),
        mirror: r(primary_uri(ai.get("apt"))),
        late_commands: rl(late),
    };
    FormRead {
        form,
        fields,
        max_users: Some(1),
        unreadable: None,
    }
}

pub fn apply_form(
    body: &str,
    _before: &InstallForm,
    after: &InstallForm,
    changed: &[FormField],
) -> Result<String, String> {
    let (mut text, table) = protect(body).ok_or("The file holds a private-use character the form can't follow.")?;
    let doc = yaml::parse(&text).map_err(|e| e.message)?.docs.into_iter().next();
    let prefix: &[&str] = match doc.as_ref().and_then(section) {
        Some((_, path)) => path,
        None => &["autoinstall"],
    };
    let p = |rest: &[&'static str]| -> Vec<&'static str> {
        let mut v: Vec<&'static str> = prefix.to_vec();
        v.extend_from_slice(rest);
        v
    };
    if doc.as_ref().and_then(section).is_none() {
        set(&mut text, &p(&["version"]), Some(Node::int(1)))?;
    }
    for field in changed {
        match field {
            FormField::Hostname => set(&mut text, &p(&["identity", "hostname"]), opt_str(&after.hostname))?,
            FormField::Locale => set(&mut text, &p(&["locale"]), opt_str(&after.locale))?,
            FormField::Keyboard => match opt_str(&after.keyboard) {
                Some(layout) => set(&mut text, &p(&["keyboard", "layout"]), Some(layout))?,
                None => set(&mut text, &p(&["keyboard"]), None)?,
            },
            FormField::Timezone => set(&mut text, &p(&["timezone"]), opt_str(&after.timezone))?,
            FormField::Storage => match &after.storage {
                None => set(&mut text, &p(&["storage"]), None)?,
                Some(s) => {
                    let name = match s.layout {
                        StorageLayout::Lvm => "lvm",
                        StorageLayout::Plain => "direct",
                        StorageLayout::Custom => {
                            return Err("The form doesn't lay disks out by hand: edit storage in the file.".into())
                        }
                    };
                    set(&mut text, &p(&["storage", "layout", "name"]), Some(Node::str(name)))?;
                    let swap = match s.swap {
                        Swap::Auto => None,
                        Swap::None => Some(Node::int(0)),
                        Swap::SizeMb { mb } => Some(Node::str(format!("{mb}M"))),
                    };
                    set(
                        &mut text,
                        &p(&["storage", "swap"]),
                        swap.map(|size| Node::map(vec![("size", size)])),
                    )?;
                }
            },
            FormField::Network => set(&mut text, &p(&["network"]), after.network.as_ref().map(network_node))?,
            FormField::Users => match after.users.first() {
                None => set(&mut text, &p(&["identity"]), None)?,
                Some(user) => {
                    set(
                        &mut text,
                        &p(&["identity", "username"]),
                        Some(Node::str(user.name.trim())),
                    )?;
                    let password = user
                        .password
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(Node::quoted);
                    set(&mut text, &p(&["identity", "password"]), password)?;
                    let keys: Vec<Node> = user
                        .ssh_keys
                        .iter()
                        .map(|k| k.trim())
                        .filter(|k| !k.is_empty())
                        .map(Node::quoted)
                        .collect();
                    set(
                        &mut text,
                        &p(&["ssh", "authorized-keys"]),
                        (!keys.is_empty()).then(|| Node::seq(keys)),
                    )?;
                }
            },
            FormField::Ssh => match after.ssh {
                None => {
                    set(&mut text, &p(&["ssh", "install-server"]), None)?;
                    set(&mut text, &p(&["ssh", "allow-pw"]), None)?;
                }
                Some(s) => {
                    set(
                        &mut text,
                        &p(&["ssh", "install-server"]),
                        Some(Node::bool(s.install_server)),
                    )?;
                    set(&mut text, &p(&["ssh", "allow-pw"]), Some(Node::bool(s.password_logins)))?;
                }
            },
            FormField::Packages => set(&mut text, &p(&["packages"]), list(&after.packages))?,
            FormField::Updates => {
                let value = match after.updates {
                    Some(Updates::All) => Some(Node::str("all")),
                    Some(Updates::Security) => Some(Node::str("security")),
                    Some(Updates::None) | None => None,
                };
                set(&mut text, &p(&["updates"]), value)?;
            }
            FormField::Proxy => set(&mut text, &p(&["proxy"]), opt_str(&after.proxy))?,
            FormField::Mirror => set(
                &mut text,
                &p(&["apt", "primary"]),
                after
                    .mirror
                    .as_deref()
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(primary_node),
            )?,
            FormField::LateCommands => set(&mut text, &p(&["late-commands"]), list(&after.late_commands))?,
        }
    }
    Ok(restore(&text, &table))
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

    fn file(rest: &str) -> String {
        format!("#cloud-config\nautoinstall:\n  version: 1\n  identity:\n    hostname: vm-1\n    username: alice\n    password: \"{SAMPLE_HASH}\"\n  ssh:\n    install-server: true\n    authorized-keys: [\"ssh-ed25519 AAAA alice@example.com\"]\n{rest}")
    }

    #[test]
    fn a_good_file_passes_the_schema() {
        let problems = check(&file(
            "  locale: en_US.UTF-8\n  updates: security\n  storage:\n    layout:\n      name: lvm\n",
        ));
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn the_schema_names_wrong_types_missing_keys_and_unknown_sections() {
        let problems = check(&file("  updates: everything\n  keyboard: {variant: intl}\n  packages: curl\n  frobnicate: true\n  ssh-extra: 1\n  storage:\n    layout:\n      name: raid\n"));
        let text = messages(&problems);
        assert!(text.contains("updates has to be one of security, all"), "{text}");
        assert!(text.contains("keyboard needs layout"), "{text}");
        assert!(text.contains("packages has to be a list of text"), "{text}");
        assert!(text.contains("schema has no frobnicate"), "{text}");
        assert!(
            text.contains("storage.layout.name has to be one of lvm, direct, zfs, hybrid"),
            "{text}"
        );
        let errors: Vec<_> = problems.iter().filter(|p| p.severity == Severity::Error).collect();
        assert!(errors.iter().all(|p| p.line.is_some()), "{errors:?}");
        // Missing pieces.
        let text = messages(&check(
            "#cloud-config\nautoinstall:\n  version: 2\n  identity:\n    username: alice\n",
        ));
        assert!(text.contains("version has to be 1"), "{text}");
        assert!(text.contains("identity needs hostname"), "{text}");
        assert!(text.contains("identity needs password"), "{text}");
        let text = messages(&check("autoinstall:\n  version: 1\n"));
        assert!(text.contains("#cloud-config"), "{text}");
        let text = messages(&check("#cloud-config\nhostname: x\n"));
        assert!(text.contains("needs an autoinstall: section"), "{text}");
    }

    #[test]
    fn lock_outs_and_secrets() {
        let text = messages(&check("#cloud-config\nautoinstall:\n  version: 1\n"));
        assert!(text.contains("No user"), "{text}");
        assert!(text.contains("No SSH server"), "{text}");
        let locked = file("").replace(
            "authorized-keys: [\"ssh-ed25519 AAAA alice@example.com\"]",
            "allow-pw: false",
        );
        assert!(messages(&check(&locked)).contains("Password logins over SSH are off and no SSH key"));
        let plain = file("").replace(&format!("\"{SAMPLE_HASH}\""), "letmein");
        let problems = check(&plain);
        assert!(
            problems
                .iter()
                .any(|p| p.blocks_saving && p.message.contains("holds a password")),
            "{problems:?}"
        );
        let hashed = file("").replace(&format!("\"{SAMPLE_HASH}\""), "\"$6$abcdefgh$ijklmnopqrstuvwxyz\"");
        assert!(check(&hashed)
            .iter()
            .any(|p| p.blocks_saving && p.message.contains("password hash")));
        let luks = file("  storage:\n    layout:\n      name: lvm\n      password: x\n");
        assert!(check(&luks).iter().any(|p| p.blocks_saving));
        let ud = file("  user-data:\n    users:\n      - name: bob\n        plain_text_passwd: x\n");
        assert!(check(&ud)
            .iter()
            .any(|p| p.blocks_saving && p.message.contains("plain_text_passwd")));
        let interactive = file("  interactive-sections: [network]\n");
        assert!(messages(&check(&interactive)).contains("stops to ask about network"));
    }

    #[test]
    fn sizes_and_the_disk_a_layout_needs() {
        assert_eq!(size_mb("512M"), Some(512));
        assert_eq!(size_mb("20G"), Some(20 * 1024));
        assert_eq!(size_mb("1T"), Some(1024 * 1024));
        assert_eq!(size_mb("1048576"), Some(1));
        assert_eq!(size_mb("4GB"), Some(4096));
        assert_eq!(size_mb("lots"), None);
        let text = file("  storage:\n    swap:\n      size: 4G\n    config:\n      - {type: disk, id: d0}\n      - {type: partition, id: p1, device: d0, size: 1G}\n      - {type: partition, id: p2, device: d0, size: 30G}\n      - {type: partition, id: p3, device: d0, size: -1}\n");
        assert_eq!(disk_need_mb(&text), Some((1 + 30 + 4) * 1024));
        assert_eq!(disk_need_mb(&file("")), None);
    }

    const BODY: &str = "#cloud-config\n# Ubuntu, kept as written.\nautoinstall:\n  version: 1\n  locale: en_US.UTF-8\n  identity:\n    realname: Alice\n    hostname: \"{{hostname}}\"\n    username: alice\n    password: \"{{password.admin}}\"\n  ssh:\n    install-server: true\n    authorized-keys:\n      - \"{{ssh_key.admin}}\"\n  late-commands:\n    - curtin in-target -- systemctl enable ssh\n";

    #[test]
    fn the_form_reads_and_writes_the_file_in_place() {
        let read = read_form(BODY);
        assert_eq!(read.unreadable, None, "{read:?}");
        let form = read.form.clone();
        assert_eq!(form.hostname.as_deref(), Some("{{hostname}}"));
        assert_eq!(form.users[0].name, "alice");
        assert_eq!(form.users[0].password.as_deref(), Some("{{password.admin}}"));
        assert_eq!(form.users[0].ssh_keys, ["{{ssh_key.admin}}"]);
        assert_eq!(
            form.ssh,
            Some(SshForm {
                install_server: true,
                password_logins: false
            })
        );
        let mut after = form.clone();
        after.timezone = Some("Etc/UTC".into());
        after.network = Some(NetworkForm::Static {
            address: "{{ip}}".into(),
            prefix: 24,
            gateway: Some("192.0.2.1".into()),
            dns: vec!["192.0.2.53".into()],
        });
        after.storage = Some(StorageForm {
            layout: StorageLayout::Lvm,
            swap: Swap::None,
        });
        after.packages = vec!["docker.io".into()];
        after.updates = Some(Updates::All);
        after.mirror = Some("http://archive.ubuntu.com/ubuntu".into());
        let changed = crate::catalog::install::changed_fields(&form, &after);
        let out = apply_form(BODY, &form, &after, &changed).unwrap();
        assert!(
            out.starts_with(&BODY[..BODY.find("  late-commands").unwrap()]),
            "untouched lines stay:\n{out}"
        );
        assert!(out.contains("  timezone: Etc/UTC\n"), "{out}");
        assert!(out.contains("        addresses:\n          - \"{{ip}}/24\"\n"), "{out}");
        assert!(
            out.contains("  storage:\n    layout:\n      name: lvm\n    swap:\n      size: 0\n"),
            "{out}"
        );
        let back = read_form(&out).form;
        assert_eq!(back.network, after.network);
        assert_eq!(back.storage, after.storage);
        assert_eq!(back.updates, Some(Updates::All));
        assert_eq!(back.mirror, after.mirror);
        assert_eq!(back.users, form.users);
        // The rendered sample passes Ubuntu's schema.
        let spec = crate::catalog::install::InstallConfigInput {
            name: "t".into(),
            kind: crate::catalog::install::InstallKind::Autoinstall,
            body: out,
            variables: vec![],
            secrets: vec![],
            notes: None,
        };
        let sample = crate::catalog::install::sample_text(&spec).unwrap();
        let errors: Vec<_> = check(&sample)
            .into_iter()
            .filter(|p| p.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
    }
}
