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

// ---- Review of #88: the reviewer's probes, as regression tests ------------------------------------------------------

fn render_vm() -> render::VmValues {
    render::VmValues {
        hostname: "web-1".into(),
        ip: Some("192.0.2.21".into()),
        n: 1,
        template: "web".into(),
        date: time::macros::date!(2026 - 11 - 12),
        values: std::collections::BTreeMap::new(),
    }
}

fn render_secrets() -> render::RenderSecrets {
    let mut s = render::RenderSecrets::default();
    s.passwords.insert(
        "admin".into(),
        crate::vault::SecretString::new(format!("Pw-{}", uuid::Uuid::new_v4().simple())),
    );
    s.ssh_keys.insert(
        "admin".into(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com".into(),
    );
    s
}

fn with_var(kind: InstallKind, body: &str, var: &str, default: &str) -> InstallConfigInput {
    InstallConfigInput {
        name: "probe".into(),
        kind,
        body: body.into(),
        variables: vec![VariableDef {
            name: var.into(),
            default: Some(default.into()),
        }],
        secrets: vec![
            SecretRef {
                name: "admin".into(),
                kind: SecretRefKind::Password,
                secret_id: None,
            },
            SecretRef {
                name: "admin".into(),
                kind: SecretRefKind::SshKey,
                secret_id: None,
            },
        ],
        notes: None,
    }
}

#[test]
fn a_unicode_line_separator_in_a_value_never_adds_lines_for_the_installer() {
    // HIGH: PyYAML (Subiquity, cloud-init) and Python's splitlines read U+2028 as a line break; saphyr doesn't.
    let ls = '\u{2028}';
    let cases = [
        (
            InstallKind::CloudInit,
            "#cloud-config\nhostname: \"{{hostname}}\"\nfqdn: {{v}}\n",
            format!("example.com{ls}injected_key:{ls}- marker"),
        ),
        (
            InstallKind::Autoinstall,
            "#cloud-config\nautoinstall:\n  version: 1\n  locale: {{v}}\n  identity:\n    hostname: \"{{hostname}}\"\n    username: sysadmin\n    password: \"{{password.admin}}\"\n  ssh:\n    install-server: true\n    authorized-keys:\n      - \"{{ssh_key.admin}}\"\n",
            format!("en_US.UTF-8{ls}  late-commands:{ls}  - marker"),
        ),
        (
            InstallKind::Kickstart,
            "text\nlang en_US.UTF-8\ntimezone {{v}} --utc\nrootpw --lock\nuser --name=sysadmin --iscrypted --password=\"{{password.admin}}\"\nreboot\n",
            format!("Etc/UTC{ls}lang en_GB.UTF-8"),
        ),
    ];
    for (kind, body, value) in cases {
        // As a default, it is refused when saved.
        let spec = with_var(kind, body, "v", &value);
        assert!(check_input(&spec).is_err(), "{kind:?}: the default is refused");
        // As a VM's own value, render refuses it.
        let plain = with_var(kind, body, "v", "x");
        let mut vm = render_vm();
        vm.values.insert("v".into(), value.clone());
        let err = render::render(&plain, &vm, &render_secrets(), &mut render::OsRandom).unwrap_err();
        assert!(err.to_string().contains("line break"), "{kind:?}: {err}");
    }
    // Through the form, too.
    let ubuntu = include_str!("starters/ubuntu-24.04-minimal.yaml");
    let mut form = read_form(InstallKind::Autoinstall, ubuntu).form;
    form.timezone = Some(format!("Etc/UTC{ls}late-commands: [reboot]"));
    assert!(apply_form(InstallKind::Autoinstall, ubuntu, &form).is_err());
    form.timezone = Some("Etc/UTC".into());
    form.late_commands = vec![format!("echo a{ls}reboot")];
    assert!(apply_form(InstallKind::Autoinstall, ubuntu, &form).is_err());
}

#[test]
fn a_line_break_only_python_sees_in_the_file_refuses_saving() {
    for sep in ['\u{2028}', '\u{2029}', '\u{0085}', '\u{000b}', '\u{000c}', '\r'] {
        for kind in [
            InstallKind::Autoinstall,
            InstallKind::CloudInit,
            InstallKind::Kickstart,
            InstallKind::Preseed,
        ] {
            let body = format!("#cloud-config\nhostname: \"{{{{hostname}}}}\"\nruncmd:\n  - echo a{sep}  - reboot\n");
            let problems = check(&spec(kind, &body), &CheckFacts::default());
            assert_eq!(problems.len(), 1, "{kind:?} {sep:?}: {problems:?}");
            assert!(
                problems[0].blocks_saving && problems[0].line == Some(4),
                "{kind:?} {sep:?}: {problems:?}"
            );
        }
    }
    // Windows' XML reads them as text.
    let xml = "<unattend xmlns=\"urn:schemas-microsoft-com:unattend\"><a>x\u{2028}y</a></unattend>";
    assert!(!check(&spec(InstallKind::Unattend, xml), &CheckFacts::default())
        .iter()
        .any(|p| p.blocks_saving));
}

#[test]
fn every_way_of_writing_a_password_into_the_file_is_refused() {
    // MEDIUM: merge keys and separators hid a password from the lint, and FD-07's import goes through the same gate.
    let ci = |rest: &str| format!("#cloud-config\nhostname: \"{{{{hostname}}}}\"\n{rest}");
    let ai = |rest: &str| format!("#cloud-config\nautoinstall:\n  version: 1\n{rest}");
    let xml = |inner: &str| {
        format!("<unattend xmlns=\"urn:schemas-microsoft-com:unattend\"><settings pass=\"oobeSystem\"><component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\">{inner}</component></settings></unattend>")
    };
    let cases: Vec<(&str, InstallKind, String)> = vec![
        ("cloud-init plain_text_passwd", InstallKind::CloudInit, ci("users:\n  - name: bob\n    plain_text_passwd: probe-pw\n")),
        ("cloud-init flow", InstallKind::CloudInit, ci("users: [{name: bob, plain_text_passwd: probe-pw}]\n")),
        ("cloud-init merge key", InstallKind::CloudInit, ci("users:\n  - name: bob\n    <<: {plain_text_passwd: probe-pw}\n")),
        ("cloud-init U+2028", InstallKind::CloudInit, ci("users:\n  - name: bob\n    shell: /bin/bash\u{2028}    plain_text_passwd:\u{2028}      probe-pw\n")),
        ("cloud-init tag", InstallKind::CloudInit, ci("write_files:\n  - path: /x\n    content: !!binary |\n      LS0tLS1CRUdJTg==\n")),
        // The marker is put together at run time, so no private key's header sits in the repo.
        ("cloud-init private key", InstallKind::CloudInit, ci(&format!("write_files:\n  - path: /x\n    content: \"-----BEGIN OPENSSH {}-----\"\n", "PRIVATE KEY"))),
        ("cloud-init private key b64", InstallKind::CloudInit, ci("write_files:\n  - path: /x\n    encoding: b64\n    content: LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0=\n")),
        ("cloud-init gzip", InstallKind::CloudInit, ci("write_files:\n  - path: /x\n    encoding: gz+b64\n    content: H4sIAAAAAAAAAwMAAAAAAAAAAAA=\n")),
        ("autoinstall identity merge", InstallKind::Autoinstall, ai("  identity:\n    hostname: \"{{hostname}}\"\n    username: u\n    <<: {password: probe-pw}\n")),
        ("kickstart rootpw plaintext", InstallKind::Kickstart, "text\nlang en_US.UTF-8\nrootpw --plaintext probe-pw\nreboot\n".into()),
        ("kickstart rootpw locked plaintext", InstallKind::Kickstart, "text\nlang en_US.UTF-8\nrootpw --lock --plaintext probe-pw\nreboot\n".into()),
        ("kickstart --pa abbreviation", InstallKind::Kickstart, "text\nlang en_US.UTF-8\nuser --name=bob --plaintext --pa=probe-pw\nreboot\n".into()),
        ("kickstart --password and a space", InstallKind::Kickstart, "text\nlang en_US.UTF-8\nuser --name=bob --plaintext --password probe-pw\nreboot\n".into()),
        ("preseed plain", InstallKind::Preseed, "d-i passwd/root-password password probe-pw\n".into()),
        ("preseed letter case", InstallKind::Preseed, "d-i passwd/Root-Password password probe-pw\n".into()),
        ("unattend administrator", InstallKind::Unattend, xml("<UserAccounts><AdministratorPassword><Value>probe-pw</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>")),
        ("unattend local account", InstallKind::Unattend, xml("<UserAccounts><LocalAccounts><LocalAccount><Password><Value>probe-pw</Value><PlainText>true</PlainText></Password><Name>bob</Name></LocalAccount></LocalAccounts></UserAccounts>")),
        ("unattend auto logon", InstallKind::Unattend, xml("<AutoLogon><Password><Value>probe-pw</Value><PlainText>true</PlainText></Password><Enabled>true</Enabled><Username>Administrator</Username></AutoLogon>")),
        ("unattend domain join", InstallKind::Unattend, "<unattend xmlns=\"urn:schemas-microsoft-com:unattend\"><settings pass=\"specialize\"><component name=\"Microsoft-Windows-UnattendedJoin\" processorArchitecture=\"amd64\"><Identification><Credentials><Domain>example.com</Domain><Password>probe-pw</Password><Username>joiner</Username></Credentials></Identification></component></settings></unattend>".into()),
    ];
    for (what, kind, body) in cases {
        let problems = check(&spec(kind, &body), &CheckFacts::default());
        assert!(problems.iter().any(|p| p.blocks_saving), "{what}: {problems:?}");
    }
    // A locked root without a password is fine; a tag-free, merge-free file is too.
    let ks = "text\nlang en_US.UTF-8\ntimezone Etc/UTC\nrootpw --lock\nuser --name=bob --lock\nsshkey --username=bob \"ssh-ed25519 AAAA bob@example.com\"\nreboot\n";
    assert!(!check(&spec(InstallKind::Kickstart, ks), &CheckFacts::default())
        .iter()
        .any(|p| p.blocks_saving));
}

#[test]
fn a_syntax_error_elsewhere_never_lets_a_password_be_saved() {
    // Re-review of #88: autoinstall and cloud-init returned before their secret lint on any syntax error.
    let cases: Vec<(&str, InstallKind, String)> = vec![
        (
            "autoinstall without its header, a merge key",
            InstallKind::Autoinstall,
            "autoinstall:\n  version: 1\n  identity:\n    hostname: h\n    username: u\n    <<: {password: probe-pw}\n".into(),
        ),
        (
            "autoinstall without its header, user-data's password",
            InstallKind::Autoinstall,
            "autoinstall:\n  version: 1\n  user-data:\n    password: probe-pw\n".into(),
        ),
        (
            "autoinstall with its header, a merge key",
            InstallKind::Autoinstall,
            "#cloud-config\nautoinstall:\n  version: 1\n  identity:\n    hostname: h\n    username: u\n    <<: {password: probe-pw}\n".into(),
        ),
        (
            "autoinstall with no section, identity's password",
            InstallKind::Autoinstall,
            "#cloud-config\nidentity:\n  hostname: h\n  username: u\n  password: probe-pw\n".into(),
        ),
        (
            "autoinstall's second document",
            InstallKind::Autoinstall,
            "#cloud-config\nautoinstall:\n  version: 1\n---\nautoinstall:\n  identity:\n    password: probe-pw\n".into(),
        ),
        (
            "the installer's own user data around the section",
            InstallKind::Autoinstall,
            "autoinstall:\n  version: 1\npassword: probe-pw\n".into(),
        ),
        (
            "cloud-init in two documents",
            InstallKind::CloudInit,
            "#cloud-config\nusers:\n  - name: bob\n    plain_text_passwd: probe-pw\n---\nx: 1\n".into(),
        ),
        (
            "cloud-init's second document",
            InstallKind::CloudInit,
            "#cloud-config\nx: 1\n---\nusers:\n  - name: bob\n    plain_text_passwd: probe-pw\n".into(),
        ),
        (
            "cloud-init without its header",
            InstallKind::CloudInit,
            "users:\n  - name: bob\n    plain_text_passwd: probe-pw\n".into(),
        ),
        (
            "kickstart with a bad line",
            InstallKind::Kickstart,
            "text\nlang \"unclosed\nrootpw --plaintext probe-pw\nreboot\n".into(),
        ),
        (
            "preseed with a bad line",
            InstallKind::Preseed,
            "d-i\nd-i passwd/root-password password probe-pw\n".into(),
        ),
        (
            "unattend with another root",
            InstallKind::Unattend,
            "<answers><AdministratorPassword><Value>probe-pw</Value></AdministratorPassword></answers>".into(),
        ),
    ];
    for (what, kind, body) in cases {
        let problems = check(&spec(kind, &body), &CheckFacts::default());
        assert!(problems.iter().any(|p| p.blocks_saving), "{what}: {problems:?}");
    }
    // YAML or XML that doesn't read at all can't be checked, so it isn't saved either.
    for (kind, body) in [
        (
            InstallKind::Autoinstall,
            "#cloud-config\nautoinstall:\n  version: 1\n  identity: [\n    password: probe-pw\n",
        ),
        (
            InstallKind::CloudInit,
            "#cloud-config\nusers: [\n  - plain_text_passwd: probe-pw\n",
        ),
        (InstallKind::Unattend, "<unattend><Password>probe-pw</unattend>"),
    ] {
        let problems = check(&spec(kind, body), &CheckFacts::default());
        assert!(
            problems
                .iter()
                .any(|p| p.blocks_saving && p.message.contains("can't read this file")),
            "{kind:?}: {problems:?}"
        );
    }
}

#[test]
fn hostile_files_check_quickly() {
    // MEDIUM: 240 KB of `{{` took 25 s and gave 120,000 problems.
    for (kind, body) in [
        (
            InstallKind::CloudInit,
            format!("#cloud-config\na: {}\n", "{{".repeat(120_000)),
        ),
        (InstallKind::Kickstart, format!("lang {}\n", "{{".repeat(120_000))),
        (
            InstallKind::CloudInit,
            format!("#cloud-config\n{}", "a: {{\n".repeat(40_000)),
        ),
    ] {
        let started = std::time::Instant::now();
        let problems = check(&spec(kind, &body), &CheckFacts::default());
        let _ = read_form(kind, &body);
        assert!(problems.len() <= vars::MAX_ERRORS, "{kind:?}: {}", problems.len());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "{kind:?}: {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn values_starting_with_yaml_syntax_are_refused_in_yaml_files() {
    let body = "#cloud-config\nhostname: \"{{hostname}}\"\nfqdn: {{d}}\n";
    for value in ["!probe x", "*alias", "[a, b]", "- item", "@x"] {
        let mut vm = render_vm();
        vm.values.insert("d".into(), value.into());
        let spec = with_var(InstallKind::CloudInit, body, "d", "example.com");
        assert!(
            render::render(&spec, &vm, &render_secrets(), &mut render::OsRandom).is_err(),
            "{value}"
        );
    }
}

#[test]
fn an_unattend_default_with_an_ampersand_checks_as_render_writes_it() {
    // LOW: the sample wrote `Example & Co` raw, which the strict XML reader refused.
    let body = include_str!("starters/windows-server-2022.xml");
    let mut s = starters::spec(starters::find("starter.windows-server-2022").unwrap());
    s.body = body.replace("\r\n", "\n");
    for v in &mut s.variables {
        if v.name == "organization" {
            v.default = Some("Example & Co <IT>".into());
        }
    }
    let errors: Vec<ConfigProblem> = check(&s, &CheckFacts::default())
        .into_iter()
        .filter(|p| p.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}
