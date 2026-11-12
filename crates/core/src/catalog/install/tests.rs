#![allow(clippy::unwrap_used)]

use super::form::UserForm;
use super::*;

fn spec(kind: InstallKind, body: &str) -> InstallConfigInput {
    InstallConfigInput {
        name: " Web servers ".into(),
        kind,
        body: body.into(),
        variables: vec![VariableDef {
            name: "domain".into(),
            default: Some(" example.com ".into()),
        }],
        secrets: vec![],
        notes: Some("  ".into()),
    }
}

#[test]
fn input_is_tidied_and_references_are_listed() {
    let clean = check_input(&spec(
        InstallKind::CloudInit,
        "#cloud-config\r\nhostname: \"{{hostname}}.{{domain}}\"\r\nusers:\r\n  - name: alice\r\n    passwd: \"{{password.admin}}\"\r\n",
    ))
    .unwrap();
    assert_eq!(clean.name, "Web servers");
    assert_eq!(clean.notes, None);
    assert_eq!(clean.variables[0].default.as_deref(), Some("example.com"));
    assert!(!clean.body.contains('\r'), "line endings are LF");
    assert_eq!(
        clean.secrets,
        [SecretRef {
            name: "admin".into(),
            kind: SecretRefKind::Password,
            secret_id: None
        }]
    );
    let bad = |change: &dyn Fn(&mut InstallConfigInput), why: &str| {
        let mut input = spec(InstallKind::CloudInit, "#cloud-config\n");
        change(&mut input);
        let err = check_input(&input).unwrap_err().to_string();
        assert!(err.contains(why), "{why}: {err}");
    };
    bad(&|i| i.name = " ".into(), "Give the install config a name");
    bad(&|i| i.name = "a\u{202e}b".into(), "invisible");
    bad(&|i| i.body = "x".repeat(MAX_BODY_BYTES + 1), "256 KB");
    bad(&|i| i.variables[0].name = "Domain".into(), "can't be a variable's name");
    bad(&|i| i.variables[0].name = "hostname".into(), "Remotely's own");
    bad(&|i| i.variables.push(i.variables[0].clone()), "twice");
    bad(&|i| i.variables[0].default = Some("$(id)".into()), "default holds $");
    bad(
        &|i| {
            i.secrets = vec![
                SecretRef {
                    name: "a".into(),
                    kind: SecretRefKind::Password,
                    secret_id: None,
                };
                2
            ]
        },
        "picked twice",
    );
}

#[test]
fn checks_name_unknown_variables_unpicked_secrets_and_vault_items_gone() {
    let id = SecretId(uuid::Uuid::from_u128(5));
    let key = SecretId(uuid::Uuid::from_u128(6));
    let mut s = spec(
        InstallKind::CloudInit,
        "#cloud-config\nhostname: \"{{hostname}}\"\nfqdn: \"{{hostname}}.{{zone}}\"\nusers:\n  - name: alice\n    lock_passwd: false\n    passwd: \"{{password.admin}}\"\n    ssh_authorized_keys:\n      - \"{{ssh_key.admin}}\"\n",
    );
    let messages = |s: &InstallConfigInput, facts: &CheckFacts| {
        check(s, facts)
            .into_iter()
            .map(|p| p.message)
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let text = messages(&s, &CheckFacts::default());
    assert!(text.contains("{{zone}} isn't one of this config's variables"), "{text}");
    assert!(text.contains("The variable domain isn't used"), "{text}");
    assert!(
        text.contains("{{password.admin}} isn't picked from the vault yet"),
        "{text}"
    );
    s.secrets = vec![
        SecretRef {
            name: "admin".into(),
            kind: SecretRefKind::Password,
            secret_id: Some(id),
        },
        SecretRef {
            name: "admin".into(),
            kind: SecretRefKind::SshKey,
            secret_id: Some(key),
        },
    ];
    let text = messages(&s, &CheckFacts::default());
    assert!(
        text.contains("{{password.admin}}'s vault item is no longer in the vault"),
        "{text}"
    );
    let facts = CheckFacts {
        passwords: [id].into(),
        keys: [(key, None)].into(),
        size: None,
    };
    let text = messages(&s, &facts);
    assert!(
        text.contains("hasn't read {{ssh_key.admin}}'s public half yet"),
        "{text}"
    );
    assert!(!text.contains("password.admin"), "{text}");
    // Problems carry their lines, sorted.
    let problems = check(&s, &facts);
    let lines: Vec<u32> = problems.iter().filter_map(|p| p.line).collect();
    let mut sorted = lines.clone();
    sorted.sort_unstable();
    assert_eq!(lines, sorted);
}

#[test]
fn a_layout_bigger_than_the_size_is_an_error() {
    let body = "text\nlang en_US.UTF-8\ntimezone Etc/UTC\nnetwork --hostname=\"{{hostname}}\"\nrootpw --lock\nuser --name=alice --lock\nsshkey --username=alice \"{{ssh_key.admin}}\"\npart /boot --size=1024\npart / --size=40000\nreboot\n";
    let mut s = spec(InstallKind::Kickstart, body);
    s.variables.clear();
    let small = CheckFacts {
        size: Some(("gp.small".into(), 20)),
        ..CheckFacts::default()
    };
    let problems = check(&s, &small);
    assert!(
        problems.iter().any(|p| p.severity == Severity::Error
            && p.message
                .contains("needs at least 41 GB, and the size gp.small's boot disk is 20 GB")),
        "{problems:?}"
    );
    let big = CheckFacts {
        size: Some(("gp.large".into(), 80)),
        ..CheckFacts::default()
    };
    assert!(!check(&s, &big).iter().any(|p| p.message.contains("needs at least")));
    let all = check_all(&s, &big);
    assert_eq!(all.disk_need_mb, Some(41_024));
    assert_eq!(all.used.ssh_keys, ["admin"]);
    assert_eq!(all.used.built_ins, ["hostname"]);
}

#[test]
fn placeholders_are_protected_from_the_yaml_reader_and_put_back() {
    let (text, table) = protect("a: {{x}}\nb: \"{{password.y}}\" {{\nc: \\{{z}}\n").unwrap();
    assert!(!text.contains("{{x}}"), "{text}");
    assert!(text.contains("b: \""), "{text}");
    assert_eq!(table.len(), 3);
    assert_eq!(
        restore(&text, &table),
        "a: {{x}}\nb: \"{{password.y}}\" {{\nc: \\{{z}}\n"
    );
    assert!(protect("a\u{e000}").is_none());
}

#[test]
fn the_form_is_applied_only_where_the_kind_allows() {
    let body = "#cloud-config\nhostname: a\n";
    let mut form = read_form(InstallKind::CloudInit, body).form;
    form.network = Some(form::NetworkForm::Dhcp);
    let err = apply_form(InstallKind::CloudInit, body, &form).unwrap_err().to_string();
    assert!(err.contains("can't change that part"), "{err}");
    let ubuntu = include_str!("starters/ubuntu-24.04-minimal.yaml");
    let mut form = read_form(InstallKind::Autoinstall, ubuntu).form;
    form.users.push(UserForm {
        name: "bob".into(),
        ..UserForm::default()
    });
    let err = apply_form(InstallKind::Autoinstall, ubuntu, &form)
        .unwrap_err()
        .to_string();
    assert!(err.contains("takes 1 user"), "{err}");
    let mut form = read_form(InstallKind::Autoinstall, ubuntu).form;
    form.hostname = Some("web\nlate-commands: [reboot]".into());
    assert!(apply_form(InstallKind::Autoinstall, ubuntu, &form).is_err());
    // Nothing changed: the file comes back as it was.
    let form = read_form(InstallKind::Autoinstall, ubuntu).form;
    assert_eq!(apply_form(InstallKind::Autoinstall, ubuntu, &form).unwrap(), ubuntu);
    let mut form = read_form(InstallKind::Autoinstall, ubuntu).form;
    form.locale = Some("de_DE.UTF-8".into());
    let out = apply_form(InstallKind::Autoinstall, ubuntu, &form).unwrap();
    assert_eq!(out, ubuntu.replace("locale: en_US.UTF-8", "locale: de_DE.UTF-8"));
}

#[test]
fn a_secret_written_into_any_kind_refuses_saving() {
    for (kind, body) in [
        (InstallKind::Autoinstall, "#cloud-config\nautoinstall:\n  version: 1\n  identity:\n    hostname: a\n    username: b\n    password: x\n"),
        (InstallKind::CloudInit, "#cloud-config\npassword: x\n"),
        (InstallKind::Kickstart, "rootpw --plaintext x\n"),
        (InstallKind::Preseed, "d-i passwd/root-password password x\n"),
        (InstallKind::Unattend, "<unattend><a><AdministratorPassword><Value>x</Value></AdministratorPassword></a></unattend>"),
    ] {
        let problems = check(&spec(kind, body), &CheckFacts::default());
        assert!(problems.iter().any(|p| p.blocks_saving), "{kind:?}: {problems:?}");
    }
    assert!(looks_hashed("$6$rounds=5000$abc$def"));
    assert!(!looks_hashed("$6"));
    assert!(is_sample_secret(&format!("\"{SAMPLE_HASH}\"")));
}

#[test]
fn kinds_round_trip_their_names() {
    for kind in InstallKind::ALL {
        assert_eq!(InstallKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(InstallKind::Unattend.file_name(), "autounattend.xml");
    assert!(!InstallKind::CloudInit.installs_from_iso());
    assert_eq!(serde_json::to_value(InstallKind::CloudInit).unwrap(), "cloudInit");
    assert_eq!(
        ref_name("{{password.admin}}", vars::PASSWORD_PREFIX).as_deref(),
        Some("admin")
    );
    assert_eq!(ref_name("x", vars::PASSWORD_PREFIX), None);
}
