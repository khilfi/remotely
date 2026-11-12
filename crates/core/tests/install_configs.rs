//! VM-28: install configs end to end, on a core with fake adapters and a real vault: the starters, a copy that picks
//! its password and key from the vault, the editor's check and masked preview, a secret written into the file refused,
//! launch templates that name a config, the audit log (the file named by its SHA-256 only), the read-only lock, the
//! trash, and FD-07 between two laptops. Nothing is installed: delivering a config is G6's.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::catalog::install::render::{render, OsRandom, RenderSecrets, VmValues};
use remotely_core::catalog::install::{starters, InstallConfigInput, InstallKind, SecretRef, SecretRefKind, Severity};
use remotely_core::catalog::{
    AfterDeploy, CloneMode, HashProgress, Image, ImageInput, Network, PreviewVm, ProblemCode, SourceInput,
    TemplateInput,
};
use remotely_core::domain::Environment;
use remotely_core::fakes::FakeVmware;
use remotely_core::presentation::Presentation;
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::store::AuditEntry;
use remotely_core::transfer::{ExportRequest, ItemStatus, TransferCommit};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use uuid::Uuid;

/// A password made at run time, never a literal in the repo.
fn password() -> String {
    format!("Pw-{}", Uuid::new_v4().simple())
}

fn iso_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x9000];
    bytes[0x8001..0x8006].copy_from_slice(b"CD001");
    bytes
}

fn vmdk_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x8800];
    bytes[..4].copy_from_slice(b"KDMV");
    bytes
}

fn write(folder: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = folder.join(name);
    std::fs::File::create(&path).unwrap().write_all(bytes).unwrap();
    path
}

async fn add_image(core: &Core, name: &str, source: SourceInput, os_profile: &str) -> Image {
    core.catalog
        .add_image(
            &core.ctx(),
            Uuid::new_v4(),
            ImageInput {
                name: name.into(),
                source,
                hypervisors: vec![],
                os_profile: os_profile.into(),
                notes: None,
            },
            Arc::new(|_: HashProgress| {}),
        )
        .await
        .unwrap()
}

fn template(name: &str, image: &Image, config: Option<Uuid>) -> TemplateInput {
    TemplateInput {
        name: name.into(),
        image_id: image.id,
        size_id: "gp.small".into(),
        hypervisor: Hypervisor::Vmware,
        vm_folder: None,
        network: Network::Nat,
        ssh_key_id: None,
        naming_pattern: "{template}-{n}".into(),
        default_count: 2,
        environment: Environment::Lab,
        tags: vec![],
        after_deploy: AfterDeploy::default(),
        guest_user: None,
        packages: vec![],
        clone_mode: CloneMode::Full,
        install_config_id: config,
    }
}

async fn catalog_audit(core: &Core) -> Vec<AuditEntry> {
    core.store
        .recent_audit(&core.ctx(), 500)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "catalog_changed")
        .collect()
}

/// The Ubuntu starter copied, its password and key picked from the vault.
async fn ubuntu_copy(core: &Core, name: &str) -> (InstallConfigInput, String) {
    let ctx = &core.ctx();
    let secret = password();
    let pw = core
        .vault
        .add(
            ctx,
            SecretKind::Password,
            &format!("{name} admin"),
            SecretString::new(secret.clone()),
        )
        .await
        .unwrap();
    let key = core
        .keys
        .generate(
            ctx,
            GenerateKey {
                label: format!("{name} key"),
                key_type: KeyType::Ed25519,
                comment: "alice@example.com".into(),
            },
        )
        .await
        .unwrap();
    let starter = starters::find("starter.ubuntu-24.04-minimal").unwrap();
    let mut spec = starters::spec(starter);
    spec.name = name.into();
    spec.secrets = vec![
        SecretRef {
            name: "admin".into(),
            kind: SecretRefKind::Password,
            secret_id: Some(pw.id),
        },
        SecretRef {
            name: "admin".into(),
            kind: SecretRefKind::SshKey,
            secret_id: Some(key.id),
        },
    ];
    (spec, secret)
}

#[tokio::test]
async fn starters_are_listed_read_only_and_a_copy_picks_from_the_vault() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let ctx = &core.ctx();
    let all = core.catalog.install_configs(ctx).await.unwrap();
    assert_eq!(all.len(), starters::STARTERS.len());
    assert!(all
        .iter()
        .all(|c| c.built_in && c.problems.iter().all(|p| p.severity == Severity::Warning)));
    let one = core
        .catalog
        .install_config(ctx, "starter.debian-12-minimal")
        .await
        .unwrap();
    assert_eq!(one.spec.kind, InstallKind::Preseed);

    let (spec, secret) = ubuntu_copy(&core, "Web servers").await;
    let saved = core.catalog.add_install_config(ctx, spec.clone()).await.unwrap();
    assert!(!saved.built_in);
    assert!(
        saved.problems.is_empty(),
        "picked, so nothing to warn about: {:?}",
        saved.problems
    );
    assert!(saved.can_deploy());
    let listed = core.catalog.install_configs(ctx).await.unwrap();
    assert_eq!(listed.len(), starters::STARTERS.len() + 1);

    // The editor's check: the form, the placeholders, and a size the layout must fit.
    let check = core
        .catalog
        .check_install_config(ctx, &spec, Some("gp.small"))
        .await
        .unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    assert_eq!(check.form.form.hostname.as_deref(), Some("{{hostname}}"));
    assert_eq!(check.used.passwords, ["admin"]);

    // The preview masks the password; the key is the vault key's public half.
    let preview = core
        .catalog
        .preview_install_config(
            ctx,
            &spec,
            &PreviewVm {
                hostname: Some("web-7".into()),
                ..PreviewVm::default()
            },
        )
        .await
        .unwrap();
    assert!(preview.contains("hostname: \"web-7\""), "{preview}");
    assert!(preview.contains("password: \"$6$••••••••\""), "{preview}");
    assert!(preview.contains("- \"ssh-ed25519 "), "{preview}");
    assert!(!preview.contains(&secret));

    // What G6 renders for a VM: the hash of the vault's password.
    let keys = core.keys.list(ctx).await.unwrap();
    let mut secrets = RenderSecrets::default();
    secrets
        .passwords
        .insert("admin".into(), SecretString::new(secret.clone()));
    secrets
        .ssh_keys
        .insert("admin".into(), keys[0].public.as_ref().unwrap().line.clone());
    let vm = VmValues {
        hostname: "web-7".into(),
        ip: None,
        n: 7,
        template: "web".into(),
        date: time::macros::date!(2026 - 11 - 12),
        values: Default::default(),
    };
    let rendered = render(&saved.spec, &vm, &secrets, &mut OsRandom).unwrap();
    assert!(rendered.text.expose().contains("password: \"$6$rounds=5000$"));
    assert!(!rendered.text.expose().contains(&secret));
}

#[tokio::test]
async fn a_secret_in_the_file_is_never_saved_and_the_audit_names_only_the_files_hash() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let ctx = &core.ctx();
    let (spec, _) = ubuntu_copy(&core, "Web servers").await;
    let literal = password();
    let mut leaky = spec.clone();
    leaky.body = leaky.body.replace("\"{{password.admin}}\"", &format!("\"{literal}\""));
    let err = core.catalog.add_install_config(ctx, leaky).await.unwrap_err();
    assert!(err.to_string().contains("a config never keeps one"), "{err}");
    let mut hashed = spec.clone();
    hashed.body = hashed
        .body
        .replace("\"{{password.admin}}\"", "\"$6$abcdefgh$ijklmnopqrstuvwxyz0123\"");
    assert!(core.catalog.add_install_config(ctx, hashed).await.is_err());
    // Review of #88: behind a YAML merge key, or a line break only the installer sees (FD-07's import saves the same way).
    let mut merged = spec.clone();
    merged.body = merged.body.replace(
        "    password: \"{{password.admin}}\"",
        &format!("    <<: {{password: \"{literal}\"}}"),
    );
    assert!(core.catalog.add_install_config(ctx, merged).await.is_err());
    let mut hidden = spec.clone();
    hidden.body = hidden.body.replace(
        "  updates: security",
        "  updates: security\u{2028}  late-commands: [reboot]",
    );
    let err = core.catalog.add_install_config(ctx, hidden).await.unwrap_err();
    assert!(err.to_string().contains("U+2028"), "{err}");
    // A pick that isn't a vault password here.
    let mut stray = spec.clone();
    stray.secrets[0].secret_id = Some(remotely_core::vault::SecretId(Uuid::new_v4()));
    assert!(core
        .catalog
        .add_install_config(ctx, stray)
        .await
        .unwrap_err()
        .to_string()
        .contains("isn't a password here"));
    // A starter's name is taken.
    let mut starter_name = spec.clone();
    starter_name.name = "Debian 12, minimal".into();
    assert!(core.catalog.add_install_config(ctx, starter_name).await.is_err());

    let saved = core.catalog.add_install_config(ctx, spec.clone()).await.unwrap();
    let mut edit = spec.clone();
    edit.body = edit.body.replace("timezone: Etc/UTC", "timezone: Europe/Berlin");
    let id = Uuid::parse_str(&saved.id).unwrap();
    core.catalog.update_install_config(ctx, id, edit.clone()).await.unwrap();
    // Saving the same again changes nothing and audits nothing.
    core.catalog.update_install_config(ctx, id, edit.clone()).await.unwrap();
    let audit = catalog_audit(&core).await;
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions.iter().filter(|a| a.contains("install config")).count(),
        2,
        "{actions:?}"
    );
    assert!(
        actions.contains(&"Added the install config 'Web servers'"),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"Changed the install config 'Web servers'"),
        "{actions:?}"
    );
    for entry in &audit {
        let detail = entry.detail.clone().unwrap_or_default();
        assert!(
            !detail.contains("sysadmin") && !detail.contains("Europe/Berlin"),
            "no file text: {detail}"
        );
    }
    let changed = audit
        .iter()
        .find(|e| e.action.starts_with("Changed the install config"))
        .unwrap();
    assert!(changed
        .detail
        .as_deref()
        .unwrap_or_default()
        .starts_with("file changed (SHA-256 "));
}

#[tokio::test]
async fn templates_name_a_config_that_fits_their_image_and_size() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let ctx = &core.ctx();
    let folder = temp_folder("install-configs-templates");
    let iso = add_image(
        &core,
        "Ubuntu 24.04 ISO",
        SourceInput::Iso {
            path: write(&folder, "ubuntu.iso", &iso_bytes()).display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let cloud = add_image(
        &core,
        "Noble cloud",
        SourceInput::CloudImage {
            path: write(&folder, "noble.vmdk", &vmdk_bytes()).display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let (spec, _) = ubuntu_copy(&core, "Web servers").await;
    let config = core.catalog.add_install_config(ctx, spec).await.unwrap();
    let config_id = Uuid::parse_str(&config.id).unwrap();

    let web = core
        .catalog
        .add_template(ctx, template("web", &iso, Some(config_id)))
        .await
        .unwrap();
    assert!(web.problems.is_empty(), "{:?}", web.problems);
    assert!(core.catalog.plan(ctx, web.id, 2).await.unwrap().is_ok());
    // An autoinstall installs from an ISO: a cloud image is refused when saved.
    let err = core
        .catalog
        .add_template(ctx, template("cloud", &cloud, Some(config_id)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("installs from an ISO"), "{err}");
    // A config that isn't here.
    let err = core
        .catalog
        .add_template(ctx, template("stray", &iso, Some(Uuid::new_v4())))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("install config was deleted"), "{err}");

    // A layout bigger than the size: the template says so and can't deploy.
    let mut big = starters::spec(starters::find("starter.rocky-9-minimal").unwrap());
    big.name = "Big disk".into();
    big.body = big.body.replace("autopart --type=lvm", "part / --size=60000");
    let big = core.catalog.add_install_config(ctx, big).await.unwrap();
    let rhel_iso = add_image(
        &core,
        "Rocky 9 ISO",
        SourceInput::Iso {
            path: write(&folder, "rocky.iso", &iso_bytes()).display().to_string(),
        },
        "rhel",
    )
    .await;
    let small = core
        .catalog
        .add_template(
            ctx,
            template("rocky", &rhel_iso, Some(Uuid::parse_str(&big.id).unwrap())),
        )
        .await
        .unwrap();
    let codes: Vec<ProblemCode> = small.problems.iter().map(|p| p.code).collect();
    assert!(codes.contains(&ProblemCode::InstallConfigDisk), "{codes:?}");
    assert!(core.catalog.plan(ctx, small.id, 1).await.unwrap().is_err());

    // Deleted: to the trash, and the template says so until the config comes back.
    core.catalog.delete_install_config(ctx, config_id).await.unwrap();
    let after = core.catalog.template(ctx, web.id).await.unwrap();
    assert_eq!(after.problems[0].code, ProblemCode::InstallConfigGone);
    let trash = core.trash.list(ctx).await.unwrap();
    let entry = trash.iter().find(|e| e.name == "Web servers").unwrap();
    core.trash.restore(ctx, entry.id, None).await.unwrap();
    assert!(core.catalog.template(ctx, web.id).await.unwrap().problems.is_empty());
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn the_read_only_lock_refuses_install_config_edits() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let ctx = &core.ctx();
    let (spec, _) = ubuntu_copy(&core, "Web servers").await;
    let saved = core.catalog.add_install_config(ctx, spec.clone()).await.unwrap();
    let id = Uuid::parse_str(&saved.id).unwrap();
    let before = catalog_audit(&core).await.len();
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let mut other = spec.clone();
    other.name = "Other".into();
    for err in [
        core.catalog.add_install_config(ctx, other.clone()).await.err(),
        core.catalog.update_install_config(ctx, id, other).await.err(),
        core.catalog.delete_install_config(ctx, id).await.err(),
    ] {
        assert_eq!(err.expect("refused").code(), "read_only_lock");
    }
    // Reads, checks and previews go on.
    assert!(core.catalog.check_install_config(ctx, &spec, None).await.is_ok());
    assert!(core
        .catalog
        .preview_install_config(ctx, &spec, &PreviewVm::default())
        .await
        .is_ok());
    assert_eq!(catalog_audit(&core).await.len(), before);
}

const PASSPHRASE: &str = "tulip anvil orbit";

async fn laptop() -> Core {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    core.transfer.use_insecure_fast_kdf();
    core
}

fn commit(preview_id: Uuid) -> TransferCommit {
    TransferCommit {
        preview_id,
        catalog: Default::default(),
        sessions: vec![],
        known_hosts: vec![],
        secrets: vec![],
        favourites: vec![],
        keep_startup: vec![],
        keep_forwards: vec![],
        vault_password: None,
        folder_defaults: vec![],
        groups: vec![],
        checks: vec![],
    }
}

#[tokio::test]
async fn install_configs_travel_to_another_laptop_without_a_secret() {
    let folder = temp_folder("install-configs-transfer");
    let a = laptop().await;
    let ctx = &a.ctx();
    let iso = add_image(
        &a,
        "Ubuntu 24.04 ISO",
        SourceInput::Iso {
            path: write(&folder, "ubuntu.iso", &iso_bytes()).display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let (spec, secret) = ubuntu_copy(&a, "Web servers").await;
    let config = a.catalog.add_install_config(ctx, spec.clone()).await.unwrap();
    a.catalog
        .add_template(ctx, template("web", &iso, Some(Uuid::parse_str(&config.id).unwrap())))
        .await
        .unwrap();

    // Without the vault's items: the file holds the config, never the password, and the picks come back unpicked.
    let file = folder.join("export.remotely");
    let report = a
        .transfer
        .export(
            ctx,
            &file,
            ExportRequest {
                passphrase: SecretString::new(PASSPHRASE),
                include_known_hosts: false,
                include_secrets: false,
                vault_password: None,
            },
            &a.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    assert_eq!(report.catalog.install_configs, 1);
    let raw = std::fs::read(&file).unwrap();
    assert!(
        !raw.windows(secret.len()).any(|w| w == secret.as_bytes()),
        "the password never goes in"
    );

    let b = laptop().await;
    let preview = b
        .transfer
        .open(&b.ctx(), &file, SecretString::new(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    assert_eq!(preview.catalog.install_configs.len(), 1);
    assert_eq!(preview.catalog.install_configs[0].status, ItemStatus::New);
    assert!(preview.catalog.install_configs[0]
        .detail
        .starts_with("Ubuntu autoinstall"));
    let done = b
        .transfer
        .commit(
            &b.ctx(),
            commit(preview.id),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert!(done.problems.is_empty(), "{:?}", done.problems);
    assert_eq!(done.catalog.install_configs.added, 1);
    let b_configs = b.catalog.install_configs(&b.ctx()).await.unwrap();
    let b_config = b_configs.iter().find(|c| c.spec.name == "Web servers").unwrap();
    assert_eq!(b_config.spec.body, spec.body);
    assert!(
        b_config.spec.secrets.iter().all(|s| s.secret_id.is_none()),
        "picked again here"
    );
    assert!(b_config
        .problems
        .iter()
        .any(|p| p.message.contains("isn't picked from the vault yet")));
    // The template points at the config as it is on this laptop.
    let b_templates = b.catalog.templates(&b.ctx()).await.unwrap();
    let b_web = b_templates.iter().find(|t| t.spec.name == "web").unwrap();
    assert_eq!(
        b_web.spec.install_config_id.map(|i| i.to_string()),
        Some(b_config.id.clone())
    );

    // With the vault's items, the picks map to this laptop's copies; importing again finds it the same.
    let file2 = folder.join("export-secrets.remotely");
    a.transfer
        .export(
            ctx,
            &file2,
            ExportRequest {
                passphrase: SecretString::new(PASSPHRASE),
                include_known_hosts: false,
                include_secrets: true,
                vault_password: Some(SecretString::new(VAULT_PASSWORD)),
            },
            &a.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    let c = laptop().await;
    let preview = c
        .transfer
        .open(&c.ctx(), &file2, SecretString::new(PASSPHRASE), &c.vault)
        .await
        .unwrap();
    let done = c
        .transfer
        .commit(
            &c.ctx(),
            commit(preview.id),
            &c.sessions,
            &c.vault,
            &c.known_hosts,
            &c.snippets,
        )
        .await
        .unwrap();
    assert!(done.problems.is_empty(), "{:?}", done.problems);
    let c_config = c
        .catalog
        .install_configs(&c.ctx())
        .await
        .unwrap()
        .into_iter()
        .find(|cfg| cfg.spec.name == "Web servers")
        .unwrap();
    assert!(
        c_config.spec.secrets.iter().all(|s| s.secret_id.is_some()),
        "{:?}",
        c_config.spec.secrets
    );
    assert!(c_config.problems.is_empty(), "{:?}", c_config.problems);
    let again = c
        .transfer
        .open(&c.ctx(), &file2, SecretString::new(PASSPHRASE), &c.vault)
        .await
        .unwrap();
    assert_eq!(again.catalog.install_configs[0].status, ItemStatus::Same);
    std::fs::remove_dir_all(folder).unwrap();
}
