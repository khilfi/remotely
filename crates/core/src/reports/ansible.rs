//! BX-12: an Ansible inventory, YAML or INI, from BX-01's targets. Remotely only writes the file: it never runs a
//! playbook (CLAUDE.md, locked decisions).
//!
//! * **Hosts**: each saved SSH session, named after the session (made valid for Ansible), with `ansible_host`,
//!   `ansible_port`, `ansible_user`, and its SS-07 jump hosts as `-o ProxyJump=...` in `ansible_ssh_common_args`.
//!   Never a password, key, passphrase or vault item: the header says to give those to Ansible yourself.
//! * **Groups**: by folder (nested, `folder_customer_web` a child of `folder_customer`), tag, environment and
//!   workspace, as chosen; `protected` holds the protected sessions, so `--limit '!protected'` keeps a playbook off
//!   them as Remotely's bulk runs are.
//! * **Safe values**: every name is made of letters, digits and `_` (hosts also `.` and `-`), every YAML key and string
//!   is double-quoted with escapes (so `no`, `1.0` or `a: b` stay names and text), a YAML string holding Jinja markers
//!   (`{{`, `{%`, `{#`) is tagged `!unsafe` so Ansible never templates it, and INI values are quoted for its shlex
//!   parser (a value with Jinja markers can't be made inert in INI, so it is left out with a note). Text was already
//!   cleaned by [`super::table::clean`] (secrets redacted, no line breaks or control characters). A host or user that
//!   ssh could read as an option (`-oProxyCommand=...`) or that holds anything ProxyJump can't carry is refused: that
//!   would run commands on the machine that runs the playbook.
//!
//! Only SSH sessions go in. **F4 hook**: WinRM sessions (`SessionKind::Winrm`) belong here too, with
//! `ansible_connection: winrm`, `ansible_port` and `ansible_winrm_transport`: add them in [`connection_vars`] (and let
//! BX-01's resolve keep WinRM sessions for this export), whichever of F4 and F6 merges second.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::table::clean;
use crate::domain::Environment;
use crate::sessions::{SessionFolder, SessionKind, SessionRecord};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AnsibleFormat {
    #[default]
    Yaml,
    Ini,
}

impl AnsibleFormat {
    pub fn extension(self) -> &'static str {
        match self {
            AnsibleFormat::Yaml => "yml",
            AnsibleFormat::Ini => "ini",
        }
    }
}

/// Which groups the inventory gets, besides `all` (and `protected` when a host is).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GroupBy {
    pub folder: bool,
    pub tag: bool,
    pub environment: bool,
    pub workspace: bool,
}

impl Default for GroupBy {
    fn default() -> Self {
        Self {
            folder: true,
            tag: true,
            environment: true,
            workspace: false,
        }
    }
}

/// A host variable's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Int(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The inventory name.
    pub name: String,
    pub session_id: Uuid,
    pub vars: Vec<(&'static str, Value)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Group {
    pub hosts: BTreeSet<String>,
    pub children: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Comment lines at the top of the file.
    pub header: Vec<String>,
    pub hosts: Vec<Host>,
    pub groups: BTreeMap<String, Group>,
    /// What was left out, and why.
    pub notes: Vec<String>,
}

/// Jump hosts followed at most, as SS-07's chains go.
const MAX_JUMPS: usize = 8;

/// A group name: lower-case letters, digits and `_`, after its prefix (so it starts with a letter and is never `all`
/// or `ungrouped`).
pub fn group_name(prefix: &str, text: &str) -> String {
    let mut out = String::from(prefix);
    out.push('_');
    let body = word(text, |c| c.is_ascii_alphanumeric(), true);
    out.push_str(if body.is_empty() { "unnamed" } else { &body });
    out
}

/// A host's inventory name: letters, digits, `.`, `-` and `_`, starting with a letter, digit or `_`.
pub fn host_name(text: &str) -> String {
    let body = word(text, |c| c.is_ascii_alphanumeric() || c == '.' || c == '-', false);
    let body = body.trim_start_matches(['.', '-']).to_owned();
    if body.is_empty() {
        "host".to_owned()
    } else {
        body
    }
}

/// `text` with every character `keep` refuses as `_`, runs of `_` made one, none at either end.
fn word(text: &str, keep: impl Fn(char) -> bool, lower: bool) -> String {
    let mut out = String::new();
    for c in clean(text).chars() {
        let c = if keep(c) { c } else { '_' };
        if c == '_' && (out.is_empty() || out.ends_with('_')) {
            continue;
        }
        out.push(if lower { c.to_ascii_lowercase() } else { c });
    }
    out.trim_end_matches('_').chars().take(100).collect()
}

/// `name`, or `name_2`, `name_3`... when it is taken.
fn unique(name: String, taken: &mut HashSet<String>) -> String {
    if taken.insert(name.clone()) {
        return name;
    }
    let mut n = 2;
    loop {
        let candidate = format!("{name}_{n}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

/// A host ssh takes as a host and nothing else: no leading `-` (an option), only what a session's host may hold.
fn safe_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%' | '[' | ']'))
}

/// A user ssh takes as a user: no leading `-`, no `@`, space, quote or anything ProxyJump would split on.
fn safe_user(user: &str) -> bool {
    !user.is_empty()
        && !user.starts_with('-')
        && user
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '$'))
}

/// One ProxyJump hop: `user@host:port`, an IPv6 address in brackets.
fn hop(session: &SessionRecord) -> Option<String> {
    let host = session.host.trim_matches(['[', ']']);
    if !safe_host(host) || host.contains(['[', ']', '%']) {
        return None;
    }
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let user = match session.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(user) if safe_user(user) => format!("{user}@"),
        Some(_) => return None,
        None => String::new(),
    };
    Some(format!("{user}{host}:{}", session.port))
}

/// A host's variables, in the order they are written.
type Vars = Vec<(&'static str, Value)>;

/// The variables a host connects with, or why it is left out. BX-12 takes SSH sessions. **F4**: a WinRM session
/// (`SessionKind::Winrm`) gets `ansible_connection: winrm`, `ansible_port` and `ansible_winrm_transport` here.
fn connection_vars(
    session: &SessionRecord,
    by_id: &HashMap<Uuid, &SessionRecord>,
) -> Result<(Vars, Option<String>), String> {
    if !matches!(session.kind, SessionKind::Ssh) {
        return Err(format!(
            "{} is a {} session, so it was left out: the inventory takes SSH sessions.",
            clean(&session.name),
            session.kind.label()
        ));
    }
    let host = clean(&session.host);
    if !safe_host(&host) {
        return Err(format!(
            "{} was left out: its host can't be written safely for ssh.",
            clean(&session.name)
        ));
    }
    let mut vars = vec![
        ("ansible_host", Value::Text(host)),
        ("ansible_port", Value::Int(i64::from(session.port))),
    ];
    if let Some(user) = session.username.as_deref().map(clean).filter(|u| !u.is_empty()) {
        if !safe_user(&user) {
            return Err(format!(
                "{} was left out: its user name can't be written safely for ssh.",
                clean(&session.name)
            ));
        }
        vars.push(("ansible_user", Value::Text(user)));
    }
    // SS-07: the jump hosts, the first one reached first.
    let mut chain: Vec<&SessionRecord> = Vec::new();
    let mut seen = HashSet::from([session.id]);
    let mut next = session.jump_session_id;
    let mut note = None;
    while let Some(id) = next {
        let Some(jump) = by_id.get(&id) else {
            note = Some(format!(
                "{}: its jump host is not in this workspace.",
                clean(&session.name)
            ));
            break;
        };
        if !seen.insert(id) || chain.len() >= MAX_JUMPS {
            break;
        }
        chain.push(jump);
        next = jump.jump_session_id;
    }
    if note.is_none() && !chain.is_empty() {
        chain.reverse();
        let hops: Option<Vec<String>> = chain.iter().map(|j| hop(j)).collect();
        match hops {
            Some(hops) => vars.push((
                "ansible_ssh_common_args",
                Value::Text(format!("-o ProxyJump={}", hops.join(","))),
            )),
            None => {
                note = Some(format!(
                    "{}: a jump host's address can't be written safely for ProxyJump, so set ansible_ssh_common_args yourself.",
                    clean(&session.name)
                ));
            }
        }
    }
    Ok((vars, note))
}

/// Each folder's path from the top, by id.
fn folder_paths(folders: &[SessionFolder]) -> HashMap<Uuid, Vec<Uuid>> {
    let by_id: HashMap<Uuid, &SessionFolder> = folders.iter().map(|f| (f.id, f)).collect();
    folders
        .iter()
        .map(|f| {
            let mut path = vec![f.id];
            let mut next = f.parent_id;
            while let Some(id) = next {
                if path.contains(&id) || path.len() > 64 {
                    break;
                }
                path.push(id);
                next = by_id.get(&id).and_then(|p| p.parent_id);
            }
            path.reverse();
            (f.id, path)
        })
        .collect()
}

/// The inventory of `hosts` (BX-01's resolved sessions, in their order). `all` resolves jump hosts.
pub fn build(
    hosts: &[&SessionRecord],
    all: &[SessionRecord],
    folders: &[SessionFolder],
    workspace: &str,
    group_by: GroupBy,
    made_at: &str,
) -> Inventory {
    let by_id: HashMap<Uuid, &SessionRecord> = all.iter().map(|s| (s.id, s)).collect();
    let mut inventory = Inventory {
        header: vec![
            format!("Ansible inventory from Remotely: workspace \"{}\", {made_at}.", clean(workspace)),
            "No passwords, keys or vault items are in it: give them to Ansible yourself (ansible-vault, an SSH agent, --ask-pass).".into(),
        ],
        ..Inventory::default()
    };
    let mut taken_hosts = HashSet::new();
    let mut taken_groups: HashSet<String> = ["all".to_owned(), "ungrouped".to_owned()].into();
    let paths = folder_paths(folders);
    let folder_by_id: HashMap<Uuid, &SessionFolder> = folders.iter().map(|f| (f.id, f)).collect();
    let mut folder_groups: HashMap<Uuid, String> = HashMap::new();
    let mut named: HashMap<String, String> = HashMap::new();
    let mut group_of = |key: String, name: String, taken: &mut HashSet<String>| -> String {
        named.entry(key).or_insert_with(|| unique(name, taken)).clone()
    };
    let workspace_group = group_by.workspace.then(|| {
        group_of(
            "workspace".into(),
            group_name("workspace", workspace),
            &mut taken_groups,
        )
    });

    for session in hosts {
        let (vars, note) = match connection_vars(session, &by_id) {
            Ok(found) => found,
            Err(why) => {
                inventory.notes.push(why);
                continue;
            }
        };
        inventory.notes.extend(note);
        let name = unique(host_name(&session.name), &mut taken_hosts);
        let member = |group: String, inventory: &mut Inventory| {
            inventory.groups.entry(group).or_default().hosts.insert(name.clone());
        };
        if group_by.folder {
            if let Some(path) = session.folder_id.and_then(|f| paths.get(&f)) {
                let mut parent: Option<String> = None;
                let mut words: Vec<String> = Vec::new();
                for id in path {
                    let Some(folder) = folder_by_id.get(id) else { break };
                    words.push(folder.name.clone());
                    let group = folder_groups
                        .entry(*id)
                        .or_insert_with(|| unique(group_name("folder", &words.join(" ")), &mut taken_groups))
                        .clone();
                    inventory.groups.entry(group.clone()).or_default();
                    if let Some(parent) = &parent {
                        inventory
                            .groups
                            .entry(parent.clone())
                            .or_default()
                            .children
                            .insert(group.clone());
                    }
                    parent = Some(group);
                }
                if let Some(leaf) = parent {
                    member(leaf, &mut inventory);
                }
            }
        }
        if group_by.tag {
            for tag in &session.tags {
                let group = group_of(format!("tag:{tag}"), group_name("tag", tag), &mut taken_groups);
                member(group, &mut inventory);
            }
        }
        if group_by.environment && session.environment != Environment::None {
            let env = session.environment.as_str();
            let group = group_of(format!("env:{env}"), group_name("env", env), &mut taken_groups);
            member(group, &mut inventory);
        }
        if let Some(group) = &workspace_group {
            member(group.clone(), &mut inventory);
        }
        if session.protected {
            let group = group_of("protected".into(), "protected".into(), &mut taken_groups);
            member(group, &mut inventory);
        }
        inventory.hosts.push(Host {
            name,
            session_id: session.id,
            vars,
        });
    }
    inventory
}

/// Jinja markers Ansible would template.
fn templated(text: &str) -> bool {
    text.contains("{{") || text.contains("{%") || text.contains("{#")
}

/// A YAML double-quoted scalar: `"` and `\` escaped, anything that isn't plain printable text as `\u` escapes.
fn yaml_quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control()
                || crate::untrusted::is_format_char(c)
                || matches!(c, '\u{2028}' | '\u{2029}' | '\u{FEFF}') =>
            {
                out.push_str(&format!("\\u{:04X}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn yaml_value(value: &Value) -> String {
    match value {
        Value::Int(n) => n.to_string(),
        Value::Text(text) if templated(text) => format!("!unsafe {}", yaml_quoted(text)),
        Value::Text(text) => yaml_quoted(text),
    }
}

/// A comment line: text only, nothing after it can become YAML or INI.
fn comment(line: &str) -> String {
    format!("# {}\n", clean(line))
}

/// The inventory as Ansible's YAML inventory format.
pub fn yaml(inventory: &Inventory) -> String {
    let mut out = String::new();
    for line in &inventory.header {
        out.push_str(&comment(line));
    }
    out.push_str("all:\n");
    if inventory.hosts.is_empty() {
        out.push_str("  hosts: {}\n");
    } else {
        out.push_str("  hosts:\n");
        for host in &inventory.hosts {
            out.push_str(&format!("    {}:\n", yaml_quoted(&host.name)));
            for (key, value) in &host.vars {
                out.push_str(&format!("      {key}: {}\n", yaml_value(value)));
            }
        }
    }
    if !inventory.groups.is_empty() {
        out.push_str("  children:\n");
        for (name, group) in &inventory.groups {
            out.push_str(&format!("    {}:\n", yaml_quoted(name)));
            if group.hosts.is_empty() && group.children.is_empty() {
                out.push_str("      hosts: {}\n");
            }
            if !group.hosts.is_empty() {
                out.push_str("      hosts:\n");
                for host in &group.hosts {
                    out.push_str(&format!("        {}: {{}}\n", yaml_quoted(host)));
                }
            }
            if !group.children.is_empty() {
                out.push_str("      children:\n");
                for child in &group.children {
                    out.push_str(&format!("        {}: {{}}\n", yaml_quoted(child)));
                }
            }
        }
    }
    out
}

/// A value for INI's shlex split: double-quoted, `\` and `"` escaped. `None`: it can't be made inert there.
fn ini_value(value: &Value) -> Option<String> {
    match value {
        Value::Int(n) => Some(n.to_string()),
        Value::Text(text) if templated(text) => None,
        Value::Text(text) => {
            let mut out = String::from("\"");
            for c in text.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c if c.is_control() || crate::untrusted::is_format_char(c) => {}
                    c => out.push(c),
                }
            }
            out.push('"');
            Some(out)
        }
    }
}

/// The inventory as Ansible's INI format, and what INI couldn't carry.
pub fn ini(inventory: &Inventory) -> (String, Vec<String>) {
    let mut out = String::new();
    let mut notes = Vec::new();
    for line in &inventory.header {
        out.push_str(&comment(line));
    }
    for host in &inventory.hosts {
        let mut line = host.name.clone();
        for (key, value) in &host.vars {
            match ini_value(value) {
                Some(v) => line.push_str(&format!(" {key}={v}")),
                None => notes.push(format!(
                    "{}: {key} holds {{{{ or {{%, which INI can't keep from being templated, so it was left out. Use YAML for it.",
                    host.name
                )),
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    for (name, group) in &inventory.groups {
        out.push_str(&format!("\n[{name}]\n"));
        for host in &group.hosts {
            out.push_str(host);
            out.push('\n');
        }
        if !group.children.is_empty() {
            out.push_str(&format!("\n[{name}:children]\n"));
            for child in &group.children {
                out.push_str(child);
                out.push('\n');
            }
        }
    }
    (out, notes)
}

/// The file's text in `format`, with every note (what BX-01 and the format left out).
pub fn render(inventory: &Inventory, format: AnsibleFormat) -> (String, Vec<String>) {
    match format {
        AnsibleFormat::Yaml => (yaml(inventory), inventory.notes.clone()),
        AnsibleFormat::Ini => {
            let (text, more) = ini(inventory);
            let mut notes = inventory.notes.clone();
            notes.extend(more);
            (text, notes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{Inherited, OwnValues, SessionAuth};

    fn session(name: &str, host: &str, user: Option<&str>) -> SessionRecord {
        SessionRecord {
            id: Uuid::new_v4(),
            folder_id: None,
            name: name.into(),
            protocol: "ssh".into(),
            kind: SessionKind::Ssh,
            host: host.into(),
            port: 22,
            username: user.map(str::to_owned),
            auth: SessionAuth::Agent,
            jump_session_id: None,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: Environment::None,
            color: None,
            protected: false,
            tags: Vec::new(),
            vm_id: None,
            vm_link: None,
            imported_from: None,
            created_at: String::new(),
            updated_at: String::new(),
            last_ip: None,
            last_hostname: None,
            last_seen_at: None,
            last_opened_at: None,
            own: OwnValues {
                username: user.map(str::to_owned),
                auth: SessionAuth::Agent,
                jump_session_id: None,
                jump_direct: false,
                environment: Environment::None,
                tags: Vec::new(),
            },
            inherited: Inherited::default(),
        }
    }

    fn folder(name: &str, parent: Option<Uuid>) -> SessionFolder {
        SessionFolder {
            id: Uuid::new_v4(),
            parent_id: parent,
            name: name.into(),
            sort_order: 0,
            defaults: Default::default(),
        }
    }

    fn inventory_of(sessions: &[SessionRecord], folders: &[SessionFolder], by: GroupBy) -> Inventory {
        let refs: Vec<&SessionRecord> = sessions.iter().collect();
        build(&refs, sessions, folders, "Acme lab", by, "2026-11-01 10:00 UTC")
    }

    #[test]
    fn names_are_made_valid_for_ansible() {
        assert_eq!(host_name("web 01 (prod)"), "web_01_prod");
        assert_eq!(host_name("db01.example.com"), "db01.example.com");
        assert_eq!(host_name("-oProxyCommand=x"), "oProxyCommand_x");
        assert_eq!(host_name("\u{202E}"), "host");
        assert_eq!(group_name("tag", "Web Servers!"), "tag_web_servers");
        assert_eq!(group_name("folder", "Customer: a/b #1"), "folder_customer_a_b_1");
        assert_eq!(group_name("tag", "{{ x }}"), "tag_x");
        assert_eq!(group_name("env", ""), "env_unnamed");
    }

    #[test]
    fn hosts_get_their_address_port_user_and_jump_chain() {
        let mut outer = session("bastion", "203.0.113.5", Some("bob"));
        outer.port = 2222;
        let mut inner = session("hop", "10.0.0.5", Some("alice"));
        inner.jump_session_id = Some(outer.id);
        let mut web = session("web01", "web01.test", Some("alice"));
        web.jump_session_id = Some(inner.id);
        let all = vec![outer, inner, web.clone()];
        let inv = build(&[&web], &all, &[], "Acme", GroupBy::default(), "now");
        assert_eq!(inv.hosts.len(), 1);
        assert_eq!(
            inv.hosts[0].vars,
            vec![
                ("ansible_host", Value::Text("web01.test".into())),
                ("ansible_port", Value::Int(22)),
                ("ansible_user", Value::Text("alice".into())),
                (
                    "ansible_ssh_common_args",
                    Value::Text("-o ProxyJump=bob@203.0.113.5:2222,alice@10.0.0.5:22".into())
                ),
            ]
        );
        let text = yaml(&inv);
        assert!(
            text.contains("      ansible_ssh_common_args: \"-o ProxyJump=bob@203.0.113.5:2222,alice@10.0.0.5:22\"\n"),
            "{text}"
        );
        let (ini_text, notes) = ini(&inv);
        assert!(notes.is_empty());
        assert!(ini_text.contains("web01 ansible_host=\"web01.test\" ansible_port=22 ansible_user=\"alice\" ansible_ssh_common_args=\"-o ProxyJump=bob@203.0.113.5:2222,alice@10.0.0.5:22\"\n"), "{ini_text}");
    }

    #[test]
    fn an_ipv6_jump_host_is_bracketed_and_an_unsafe_one_is_refused() {
        let v6 = session("v6", "2001:db8::1", None);
        let mut a = session("a", "a.test", None);
        a.jump_session_id = Some(v6.id);
        let mut bad = session("bad", "-oProxyCommand=calc", Some("alice"));
        bad.id = Uuid::new_v4();
        let mut b = session("b", "b.test", None);
        b.jump_session_id = Some(bad.id);
        let mut evil_user = session("c", "c.test", Some("-oProxyCommand=calc"));
        evil_user.id = Uuid::new_v4();
        let all = vec![v6, a.clone(), bad.clone(), b.clone(), evil_user.clone()];
        let inv = build(&[&a, &b, &bad, &evil_user], &all, &[], "W", GroupBy::default(), "now");
        let a_vars = &inv.hosts.iter().find(|h| h.name == "a").unwrap().vars;
        assert!(a_vars.contains(&(
            "ansible_ssh_common_args",
            Value::Text("-o ProxyJump=[2001:db8::1]:22".into())
        )));
        let b_vars = &inv.hosts.iter().find(|h| h.name == "b").unwrap().vars;
        assert!(
            b_vars.iter().all(|(k, _)| *k != "ansible_ssh_common_args"),
            "{b_vars:?}"
        );
        assert!(
            inv.hosts.iter().all(|h| h.name != "bad" && h.name != "c"),
            "unsafe host and user left out"
        );
        assert_eq!(inv.notes.len(), 3, "{:?}", inv.notes);
        assert!(!yaml(&inv).contains("ProxyCommand"));
        assert!(!ini(&inv).0.contains("ProxyCommand"));
    }

    #[test]
    fn groups_by_folder_tag_environment_workspace_and_protected() {
        let customer = folder("Customer", None);
        let web_folder = folder("Web tier", Some(customer.id));
        let mut web = session("web01", "web01.test", None);
        web.folder_id = Some(web_folder.id);
        web.tags = vec!["web".into(), "nginx".into()];
        web.environment = Environment::Prod;
        web.protected = true;
        let mut db = session("db01", "db01.test", None);
        db.folder_id = Some(customer.id);
        let by = GroupBy {
            folder: true,
            tag: true,
            environment: true,
            workspace: true,
        };
        let inv = inventory_of(&[web, db], &[customer, web_folder], by);
        let names: Vec<&str> = inv.groups.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "env_prod",
                "folder_customer",
                "folder_customer_web_tier",
                "protected",
                "tag_nginx",
                "tag_web",
                "workspace_acme_lab"
            ]
        );
        let customer = &inv.groups["folder_customer"];
        assert_eq!(customer.hosts.iter().collect::<Vec<_>>(), ["db01"]);
        assert_eq!(
            customer.children.iter().collect::<Vec<_>>(),
            ["folder_customer_web_tier"]
        );
        assert_eq!(inv.groups["workspace_acme_lab"].hosts.len(), 2);
        let (text, _) = ini(&inv);
        assert!(
            text.contains("\n[folder_customer:children]\nfolder_customer_web_tier\n"),
            "{text}"
        );

        let none = inventory_of(
            &inv_sessions(),
            &[],
            GroupBy {
                folder: false,
                tag: false,
                environment: false,
                workspace: false,
            },
        );
        assert!(none.groups.is_empty());
        assert!(yaml(&none).contains("all:\n  hosts:\n"));
    }

    fn inv_sessions() -> Vec<SessionRecord> {
        vec![session("x", "x.test", None)]
    }

    #[test]
    fn hostile_names_tags_and_folders_stay_names() {
        let evil = folder("a: b\n- c", None);
        let mut s = session("no", "x.test", Some("alice"));
        s.folder_id = Some(evil.id);
        s.tags = vec!["{{ lookup('pipe','id') }}".into(), "x\"]\n[evil]".into()];
        let mut t = session("web #1 \" ' {{ x }}", "y.test", None);
        t.tags = vec!["true".into()];
        let mut same = session("no", "z.test", None);
        same.tags = vec!["#comment".into()];
        let inv = inventory_of(&[s, t, same], &[evil], GroupBy::default());
        let names: Vec<&String> = inv.hosts.iter().map(|h| &h.name).collect();
        assert_eq!(names, ["no", "web_1_x", "no_2"]);
        let text = yaml(&inv);
        // Every key is quoted, so `no` stays a name and not false.
        assert!(text.contains("    \"no\":\n"), "{text}");
        assert!(!text.contains("('pipe'") && !text.contains("{{"), "{text}");
        assert!(!text.contains("\n[evil]"), "{text}");
        for line in text.lines() {
            let line = line.trim_start();
            assert!(
                line.starts_with('#')
                    || line.starts_with('"')
                    || line.starts_with("all:")
                    || line.starts_with("hosts")
                    || line.starts_with("children")
                    || line.starts_with("ansible_"),
                "{line}"
            );
        }
        let (ini_text, _) = ini(&inv);
        for line in ini_text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
            assert!(
                line.starts_with('[') && line.ends_with(']')
                    || line
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{line}"
            );
            if line.starts_with('[') {
                let name = line.trim_start_matches('[').trim_end_matches(']');
                assert!(
                    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':'),
                    "{line}"
                );
            }
        }
    }

    #[test]
    fn values_are_quoted_and_jinja_is_never_templated() {
        let hosts = vec![Host {
            name: "h".into(),
            session_id: Uuid::nil(),
            vars: vec![
                ("ansible_user", Value::Text("a\"b\\c # d: e".into())),
                ("ansible_host", Value::Text("{{ lookup('pipe', 'id') }}".into())),
                ("ansible_port", Value::Int(22)),
            ],
        }];
        let inv = Inventory {
            header: vec!["Workspace \"x\"\n[evil]\nall:".into()],
            hosts,
            ..Inventory::default()
        };
        let text = yaml(&inv);
        assert!(text.starts_with("# Workspace \"x\" [evil] all:\nall:\n"), "{text}");
        assert!(text.contains("      ansible_user: \"a\\\"b\\\\c # d: e\"\n"), "{text}");
        assert!(
            text.contains("      ansible_host: !unsafe \"{{ lookup('pipe', 'id') }}\"\n"),
            "{text}"
        );
        let (ini_text, notes) = ini(&inv);
        assert!(
            ini_text.contains("h ansible_user=\"a\\\"b\\\\c # d: e\" ansible_port=22\n"),
            "{ini_text}"
        );
        assert!(!ini_text.contains("lookup"));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert_eq!(yaml_quoted("a\u{2028}b\u{7}"), "\"a\\u2028b\\u0007\"");
    }

    #[test]
    fn other_kinds_are_left_out_with_a_note() {
        let mut rdp = session("desk", "desk.test", None);
        rdp.kind = SessionKind::Rdp(Default::default());
        let inv = inventory_of(&[rdp], &[], GroupBy::default());
        assert!(inv.hosts.is_empty());
        assert_eq!(inv.notes.len(), 1);
        assert!(inv.notes[0].contains("SSH sessions"), "{}", inv.notes[0]);
        assert!(yaml(&inv).contains("  hosts: {}\n"));
    }
}
