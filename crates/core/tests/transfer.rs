//! FD-07 encrypted export and import, end to end between two "laptops": two cores, each with its own
//! database and its own vault (fake DPAPI, fast key derivation). Files go to a fresh temp folder and
//! are deleted afterwards; passwords and keys are made at run time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{temp_folder, vmx, Setup, VAULT_PASSWORD};
use remotely_core::domain::Environment;
use remotely_core::fakes::FakeVmware;
use remotely_core::known_hosts::HostKey;
use remotely_core::sessions::{SessionAuth, SessionColor, SessionFilter, SessionInput, SessionRecord};
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::store::AuditEntry;
use remotely_core::transfer::{
    ExportRequest, ItemAction, ItemChoice, ItemStatus, TransferCommit, TransferPreview, TransferReport,
};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::vm_links::VmLink;
use remotely_core::Core;
use uuid::Uuid;

const PASSPHRASE: &str = "tulip anvil orbit";

async fn laptop() -> Core {
    laptop_with(FakeVmware::default()).await
}

async fn laptop_with(vmware: FakeVmware) -> Core {
    let core = Setup::new(vmware).with_real_vault().build().await;
    core.transfer.use_insecure_fast_kdf();
    core
}

fn input(name: &str, host: &str) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: Some("alice".into()),
        auth: SessionAuth::Agent,
        jump_session_id: None,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::None,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

fn host_key(host: &str, fingerprint: &str) -> HostKey {
    HostKey {
        host: host.into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        fingerprint: fingerprint.into(),
    }
}

/// What the owner's first laptop has: folders, sessions with a saved password, a key with its
/// passphrase, the agent, a jump host, tags, labels and colours, trusted host keys.
struct Library {
    password: String,
    passphrase: String,
    web: Uuid,
    db: Uuid,
    bastion: Uuid,
}

async fn fill(core: &Core) -> Library {
    let ctx = &core.ctx;
    let customer = core.sessions.create_folder(ctx, "Customer A", None).await.unwrap();
    let web_folder = core
        .sessions
        .create_folder(ctx, "Web", Some(customer.id))
        .await
        .unwrap();
    core.sessions.create_folder(ctx, "Empty", None).await.unwrap();
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let passphrase = format!("pp-{}", Uuid::new_v4().simple());
    let pw = core
        .vault
        .add(ctx, SecretKind::Password, "web root", SecretString::new(&password))
        .await
        .unwrap()
        .id;
    let key = core
        .keys
        .generate(
            ctx,
            GenerateKey {
                label: "laptop key".into(),
                key_type: KeyType::Ed25519,
                comment: "alice@laptop".into(),
            },
        )
        .await
        .unwrap();
    let pp = core
        .vault
        .add(
            ctx,
            SecretKind::Passphrase,
            "laptop key passphrase",
            SecretString::new(&passphrase),
        )
        .await
        .unwrap()
        .id;

    let mut web = input("web01", "web01.example.com");
    web.folder_id = Some(web_folder.id);
    web.auth = SessionAuth::Password { password_id: Some(pw) };
    web.environment = Environment::Prod;
    web.color = Some(SessionColor::Red);
    web.tags = vec!["frontend".into(), "nginx".into()];
    web.startup_command = Some("cd /srv/www".into());
    let web = core.sessions.create(ctx, web).await.unwrap();

    let mut bastion = input("bastion", "bastion.example.org");
    bastion.port = 2222;
    let bastion = core.sessions.create(ctx, bastion).await.unwrap();

    let mut db = input("db01", "192.0.2.10");
    db.folder_id = Some(customer.id);
    db.auth = SessionAuth::Key {
        key_id: Some(key.id),
        passphrase_id: Some(pp),
    };
    db.jump_session_id = Some(bastion.id);
    db.environment = Environment::Staging;
    let db = core.sessions.create(ctx, db).await.unwrap();

    core.known_hosts
        .trust(ctx, &host_key("web01.example.com", "SHA256:webwebwebwebweb"), None)
        .await
        .unwrap();
    core.known_hosts
        .trust(ctx, &host_key("192.0.2.10", "SHA256:dbdbdbdbdbdbdb"), None)
        .await
        .unwrap();
    Library {
        password,
        passphrase,
        web: web.id,
        db: db.id,
        bastion: bastion.id,
    }
}

fn request(include_secrets: bool) -> ExportRequest {
    ExportRequest {
        passphrase: SecretString::new(PASSPHRASE),
        include_known_hosts: true,
        include_secrets,
        vault_password: include_secrets.then(|| SecretString::new(VAULT_PASSWORD)),
    }
}

async fn export(core: &Core, dir: &Path, include_secrets: bool) -> PathBuf {
    let path = dir.join(format!("export-{}.remotely", Uuid::new_v4().simple()));
    core.transfer
        .export(&core.ctx, &path, request(include_secrets), &core.vault, "Remotely test")
        .await
        .unwrap();
    path
}

async fn open(core: &Core, path: &Path) -> TransferPreview {
    core.transfer
        .open(&core.ctx, path, SecretString::new(PASSPHRASE), &core.vault)
        .await
        .unwrap()
}

async fn commit(core: &Core, preview: &TransferPreview, sessions: &[(usize, ItemAction)]) -> TransferReport {
    let choices = |list: &[(usize, ItemAction)]| {
        list.iter()
            .map(|&(index, action)| ItemChoice { index, action })
            .collect()
    };
    core.transfer
        .commit(
            &core.ctx,
            TransferCommit {
                preview_id: preview.id,
                keep_startup: vec![],
                keep_forwards: vec![],
                favourites: vec![],
                sessions: choices(sessions),
                known_hosts: vec![],
                secrets: vec![],
            },
            &core.sessions,
            &core.vault,
            &core.known_hosts,
            &core.snippets,
        )
        .await
        .unwrap()
}

/// Like [`commit`], with the sessions whose startup command and port forwards come along (SS-01, SS-07).
async fn commit_keeping(
    core: &Core,
    preview: &TransferPreview,
    keep_startup: &[usize],
    keep_forwards: &[usize],
) -> TransferReport {
    core.transfer
        .commit(
            &core.ctx,
            TransferCommit {
                preview_id: preview.id,
                keep_startup: keep_startup.to_vec(),
                keep_forwards: keep_forwards.to_vec(),
                favourites: vec![],
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
            },
            &core.sessions,
            &core.vault,
            &core.known_hosts,
            &core.snippets,
        )
        .await
        .unwrap()
}

async fn sessions(core: &Core) -> Vec<SessionRecord> {
    core.sessions.list(&core.ctx, &SessionFilter::default()).await.unwrap()
}

async fn by_name(core: &Core, name: &str) -> SessionRecord {
    sessions(core)
        .await
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no session {name}"))
}

async fn folder_path(core: &Core, session: &SessionRecord) -> String {
    let folders = core.sessions.folders(&core.ctx).await.unwrap();
    let mut path = Vec::new();
    let mut next = session.folder_id;
    while let Some(id) = next {
        let f = folders.iter().find(|f| f.id == id).unwrap();
        path.push(f.name.clone());
        next = f.parent_id;
    }
    path.reverse();
    path.join("/")
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 1000).await.unwrap()
}

fn status_of(preview: &TransferPreview, name: &str) -> ItemStatus {
    preview.sessions.iter().find(|s| s.name == name).unwrap().status
}

fn index_of(preview: &TransferPreview, name: &str) -> usize {
    preview.sessions.iter().find(|s| s.name == name).unwrap().index
}

// ---- Round trips -----------------------------------------------------------------------------------

#[tokio::test]
async fn sessions_folders_tags_labels_and_host_keys_move_without_secrets() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    let lib = fill(&a).await;
    let path = export(&a, &dir, false).await;

    // The file holds no readable session, host or secret.
    let text = std::fs::read_to_string(&path).unwrap();
    for hidden in [
        "web01",
        "example.com",
        "192.0.2.10",
        "Customer A",
        "web root",
        &lib.password,
    ] {
        assert!(!text.contains(hidden), "{hidden} is readable in the file");
    }
    assert!(text.contains("\"format\": \"remotely-export\""));

    // A second laptop with nothing on it.
    let b = laptop().await;
    let preview = open(&b, &path).await;
    assert_eq!(preview.sessions.len(), 3);
    assert!(preview.sessions.iter().all(|s| s.status == ItemStatus::New));
    assert!(preview.sessions.iter().all(|s| s.default_action == ItemAction::Import));
    assert_eq!(preview.known_hosts.len(), 2);
    assert!(preview.secrets.is_empty());
    assert!(!preview.secret_values);
    assert_eq!(preview.folders, 3);
    assert_eq!(preview.new_folders, 3);
    assert_eq!(preview.exported_by, "Remotely test");
    assert!(preview.warnings.iter().any(|w| w.contains("without vault secrets")));
    let web_row = preview.sessions.iter().find(|s| s.name == "web01").unwrap();
    assert!(web_row.detail.contains("alice@web01.example.com:22"));
    assert!(web_row.detail.contains("Customer A / Web"));
    assert!(
        web_row.notes.iter().any(|n| n.contains("Asks for its password")),
        "{:?}",
        web_row.notes
    );
    // SS-01: the startup command is shown and rated (other, raised for Prod), and left out unless ticked.
    assert_eq!(web_row.startup_command.as_deref(), Some("cd /srv/www"));
    let rating = web_row.startup_rating.as_ref().unwrap();
    assert_eq!(rating.tier, remotely_core::policy::Tier::High, "{rating:?}");

    let report = commit(&b, &preview, &[]).await;
    assert_eq!(report.startup_left_out, 1);
    assert_eq!(report.sessions.added, 3);
    assert_eq!(report.known_hosts.added, 2);
    assert_eq!(report.folders_added, 3, "Customer A, Web and the empty folder");
    assert_eq!(
        report.without_credentials, 2,
        "web01's password and db01's key stayed behind"
    );
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    let web = by_name(&b, "web01").await;
    assert_eq!(web.id, lib.web, "a session keeps its id, so a later import finds it");
    assert_eq!(web.host, "web01.example.com");
    assert_eq!(web.environment, Environment::Prod);
    assert_eq!(web.color, Some(SessionColor::Red));
    assert_eq!(web.tags, ["frontend", "nginx"]);
    assert_eq!(web.startup_command, None, "not ticked");
    assert_eq!(web.auth, SessionAuth::Password { password_id: None });
    assert_eq!(folder_path(&b, &web).await, "Customer A/Web");
    let db = by_name(&b, "db01").await;
    assert_eq!(db.port, 22);
    assert_eq!(db.environment, Environment::Staging);
    assert_eq!(db.jump_session_id, Some(lib.bastion));
    assert_eq!(by_name(&b, "bastion").await.port, 2222);
    let hosts = b.known_hosts.list(&b.ctx).await.unwrap();
    assert_eq!(hosts.len(), 2);
    assert!(hosts
        .iter()
        .any(|h| h.host == "192.0.2.10" && h.fingerprint == "SHA256:dbdbdbdbdbdbdb"));

    // Audited with counts and the path on both sides; each imported session is audited too.
    let exported = audit(&a)
        .await
        .into_iter()
        .find(|e| e.event == "data_exported")
        .unwrap();
    let detail = exported.detail.unwrap();
    assert!(detail.contains("3 sessions, 3 folders, 2 known host keys"), "{detail}");
    assert!(detail.contains("labels only"), "{detail}");
    assert!(detail.contains(&path.display().to_string()), "{detail}");
    let b_audit = audit(&b).await;
    let imported = b_audit.iter().find(|e| e.event == "data_imported").unwrap();
    let detail = imported.detail.clone().unwrap();
    assert!(detail.contains(&path.display().to_string()), "{detail}");
    assert!(detail.contains("sessions 3 added"), "{detail}");
    assert_eq!(
        b_audit
            .iter()
            .filter(|e| e.action.starts_with("Imported session") && e.action.ends_with("from a Remotely export"))
            .count(),
        3
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn secrets_move_only_when_ticked_and_with_the_vault_password() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    let lib = fill(&a).await;
    let path = dir.join("with-secrets.remotely");

    // No vault password, or a wrong one: no file, and the wrong one is audited.
    let mut no_password = request(true);
    no_password.vault_password = None;
    let err = a
        .transfer
        .export(&a.ctx, &path, no_password, &a.vault, "Remotely test")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
    let mut wrong = request(true);
    wrong.vault_password = Some(SecretString::new("not the vault password"));
    let err = a
        .transfer
        .export(&a.ctx, &path, wrong, &a.vault, "Remotely test")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "wrong_vault_password");
    assert!(!path.exists());
    assert!(audit(&a).await.iter().any(|e| e.event == "vault_auth_failed"));

    a.transfer
        .export(&a.ctx, &path, request(true), &a.vault, "Remotely test")
        .await
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains(&lib.password) && !text.contains(&lib.passphrase));

    let b = laptop().await;
    let preview = open(&b, &path).await;
    assert!(preview.secret_values);
    assert_eq!(preview.secrets.len(), 3);
    assert!(preview.secrets.iter().all(|s| s.status == ItemStatus::New));
    let web_row = preview.sessions.iter().find(|s| s.name == "web01").unwrap();
    assert!(
        web_row.notes.iter().any(|n| n.contains("from the file")),
        "{:?}",
        web_row.notes
    );
    let report = commit(&b, &preview, &[]).await;
    assert_eq!(report.secrets.added, 3);
    assert_eq!(report.without_credentials, 0);

    // Sessions point at the new vault items, and the values arrived intact.
    let web = by_name(&b, "web01").await;
    let SessionAuth::Password { password_id: Some(pw) } = web.auth else {
        panic!("web01 has its password: {:?}", web.auth);
    };
    assert_eq!(b.vault.vault().get(&b.ctx, pw).await.unwrap().expose(), lib.password);
    let db = by_name(&b, "db01").await;
    let SessionAuth::Key {
        key_id: Some(key),
        passphrase_id: Some(pp),
    } = db.auth
    else {
        panic!("db01 has its key and passphrase: {:?}", db.auth);
    };
    assert_eq!(b.vault.vault().get(&b.ctx, pp).await.unwrap().expose(), lib.passphrase);
    let a_key = a.keys.list(&a.ctx).await.unwrap().remove(0);
    let b_key = b.keys.get(&b.ctx, key).await.unwrap();
    assert_eq!(b_key.public, a_key.public, "the SSH key's public half came along");
    assert!(b_key.generated);
    assert_eq!(
        b.vault.vault().get(&b.ctx, key).await.unwrap().expose(),
        a.vault.vault().get(&a.ctx, a_key.id).await.unwrap().expose()
    );

    // The audit logs name the secrets' count, never their values.
    let exported = audit(&a)
        .await
        .into_iter()
        .find(|e| e.event == "data_exported")
        .unwrap();
    assert!(exported.detail.unwrap().contains("3 vault secrets with their values"));
    for core in [&a, &b] {
        for entry in audit(core).await {
            let text = format!("{entry:?}");
            assert!(
                !text.contains(&lib.password) && !text.contains(&lib.passphrase),
                "{text}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_update_token_stays_on_its_laptop() {
    // FD-14 keeps one GitHub update token per laptop, named by a setting.
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let token = a
        .vault
        .add(
            &a.ctx,
            SecretKind::Password,
            "GitHub update token",
            SecretString::new(format!("tok-{}", Uuid::new_v4().simple())),
        )
        .await
        .unwrap();
    a.store
        .put_setting(&a.ctx, remotely_core::updates::UPDATE_TOKEN_KEY, &Some(token.id))
        .await
        .unwrap();
    let path = export(&a, &dir, true).await;
    let b = laptop().await;
    let preview = open(&b, &path).await;
    assert_eq!(preview.secrets.len(), 3);
    assert!(!preview.secrets.iter().any(|s| s.name == "GitHub update token"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn without_secret_values_sessions_use_the_same_labels_in_this_vault() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let path = export(&a, &dir, false).await;
    let b = laptop().await;
    let here = b
        .vault
        .add(
            &b.ctx,
            SecretKind::Password,
            "Web Root",
            SecretString::new("already here"),
        )
        .await
        .unwrap()
        .id;
    let preview = open(&b, &path).await;
    let web_row = preview.sessions.iter().find(|s| s.name == "web01").unwrap();
    assert!(
        web_row.notes.iter().any(|n| n.contains("in this vault")),
        "{:?}",
        web_row.notes
    );
    let report = commit(&b, &preview, &[]).await;
    assert_eq!(report.without_credentials, 1, "only db01's key is missing");
    assert_eq!(
        by_name(&b, "web01").await.auth,
        SessionAuth::Password {
            password_id: Some(here)
        }
    );
    let _ = std::fs::remove_dir_all(dir);
}

// ---- Files that don't open ---------------------------------------------------------------------------

#[tokio::test]
async fn a_wrong_passphrase_or_a_changed_file_imports_nothing() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let path = export(&a, &dir, true).await;
    let b = laptop().await;

    let err = b
        .transfer
        .open(&b.ctx, &path, SecretString::new("tulip anvil orbiT"), &b.vault)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "wrong_passphrase");

    // One character of the ciphertext changed.
    let mut envelope: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let ciphertext = envelope["ciphertext"].as_str().unwrap().to_owned();
    let middle = ciphertext.len() / 2;
    let swapped = if &ciphertext[middle..=middle] == "A" { "B" } else { "A" };
    envelope["ciphertext"] = format!("{}{swapped}{}", &ciphertext[..middle], &ciphertext[middle + 1..]).into();
    let tampered = dir.join("tampered.remotely");
    std::fs::write(&tampered, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let err = b
        .transfer
        .open(&b.ctx, &tampered, SecretString::new(PASSPHRASE), &b.vault)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "wrong_passphrase");

    // Not an export at all.
    let csv = dir.join("sessions.csv");
    std::fs::write(&csv, "name,host\nweb01,web01.example.com\n").unwrap();
    let err = b
        .transfer
        .open(&b.ctx, &csv, SecretString::new(PASSPHRASE), &b.vault)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a Remotely export"), "{err}");

    assert!(sessions(&b).await.is_empty());
    assert!(!audit(&b).await.iter().any(|e| e.event == "data_imported"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_closed_preview_can_not_be_imported() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let path = export(&a, &dir, false).await;
    let b = laptop().await;
    let preview = open(&b, &path).await;
    assert!(b.transfer.close(preview.id));
    let err = b
        .transfer
        .commit(
            &b.ctx,
            TransferCommit {
                preview_id: preview.id,
                keep_startup: vec![],
                keep_forwards: vec![],
                favourites: vec![],
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
            },
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no longer open"), "{err}");
    assert!(sessions(&b).await.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_export_is_never_written_into_a_git_repository_or_with_a_short_passphrase() {
    let dir = temp_folder("transfer");
    std::fs::create_dir_all(dir.join("repo").join(".git")).unwrap();
    let a = laptop().await;
    fill(&a).await;
    let inside = dir.join("repo").join("export.remotely");
    let err = a
        .transfer
        .export(&a.ctx, &inside, request(false), &a.vault, "Remotely test")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Git repository"), "{err}");
    assert!(!inside.exists());

    let mut short = request(false);
    short.passphrase = SecretString::new("short");
    let outside = dir.join("export.remotely");
    let err = a
        .transfer
        .export(&a.ctx, &outside, short, &a.vault, "Remotely test")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("at least 10 characters"), "{err}");
    assert!(!outside.exists());
    assert!(!audit(&a).await.iter().any(|e| e.event == "data_exported"));
    let _ = std::fs::remove_dir_all(dir);
}

// ---- Conflicts -----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_second_import_finds_what_is_there_and_the_user_decides_each_conflict() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    let lib = fill(&a).await;
    let first = export(&a, &dir, true).await;
    let b = laptop().await;
    let preview = open(&b, &first).await;
    commit(&b, &preview, &[]).await;

    // Laptop A changes web01 and db01; laptop B has a session of its own to bastion's address and one
    // named like a session of A's, and trusts another key for web01.
    let mut web = a.sessions.get(&a.ctx, lib.web).await.unwrap();
    let mut change = input(&web.name, &web.host);
    change.folder_id = web.folder_id;
    change.auth = web.auth.clone();
    change.port = 2200;
    change.tags = web.tags.clone();
    change.environment = web.environment;
    change.color = web.color;
    change.startup_command = web.startup_command.take();
    a.sessions.update(&a.ctx, lib.web, change).await.unwrap();
    let mut db = a.sessions.get(&a.ctx, lib.db).await.unwrap();
    let mut db_change = input(&db.name, &db.host);
    db_change.folder_id = db.folder_id;
    db_change.auth = db.auth.clone();
    db_change.jump_session_id = db.jump_session_id;
    db_change.environment = db.environment;
    db_change.startup_command = db.startup_command.take();
    db_change.port = 2201;
    a.sessions.update(&a.ctx, lib.db, db_change).await.unwrap();
    let mut extra = input("app01", "app01.example.com");
    extra.username = Some("bob".into());
    a.sessions.create(&a.ctx, extra).await.unwrap();
    let second = export(&a, &dir, true).await;

    b.sessions.delete(&b.ctx, lib.bastion).await.unwrap();
    let mut own_bastion = input("jump box", "bastion.example.org");
    own_bastion.port = 2222;
    b.sessions.create(&b.ctx, own_bastion).await.unwrap();
    b.sessions
        .create(&b.ctx, input("app01", "elsewhere.example.org"))
        .await
        .unwrap();
    b.known_hosts
        .trust(&b.ctx, &host_key("web01.example.com", "SHA256:otherotherother"), None)
        .await
        .unwrap();
    let pw = b
        .vault
        .list(&b.ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.label == "web root")
        .unwrap();
    b.vault
        .replace(&b.ctx, pw.id, SecretString::new("changed on b"))
        .await
        .unwrap();

    let preview = open(&b, &second).await;
    assert_eq!(status_of(&preview, "web01"), ItemStatus::Conflict);
    assert_eq!(status_of(&preview, "db01"), ItemStatus::Conflict);
    assert_eq!(
        status_of(&preview, "bastion"),
        ItemStatus::Conflict,
        "same user, host and port"
    );
    assert_eq!(status_of(&preview, "app01"), ItemStatus::Conflict, "same name");
    let web_row = preview.sessions.iter().find(|s| s.name == "web01").unwrap();
    assert!(
        web_row.conflict.as_deref().unwrap().contains("earlier copy"),
        "{web_row:?}"
    );
    assert_eq!(web_row.default_action, ItemAction::Skip);
    assert_eq!(
        web_row.choices,
        [ItemAction::Skip, ItemAction::Replace, ItemAction::KeepBoth]
    );
    let host_row = preview
        .known_hosts
        .iter()
        .find(|k| k.name == "web01.example.com:22")
        .unwrap();
    assert_eq!(host_row.status, ItemStatus::Conflict);
    assert_eq!(host_row.choices, [ItemAction::Skip, ItemAction::Replace]);
    let db_host = preview.known_hosts.iter().find(|k| k.name == "192.0.2.10:22").unwrap();
    assert_eq!(db_host.status, ItemStatus::Same);
    let secret_row = preview.secrets.iter().find(|s| s.name == "web root").unwrap();
    assert_eq!(secret_row.status, ItemStatus::Conflict);
    let key_row = preview.secrets.iter().find(|s| s.name == "laptop key").unwrap();
    assert_eq!(key_row.status, ItemStatus::Same);

    // A choice an item does not offer is refused, and nothing changes.
    let refused = b
        .transfer
        .commit(
            &b.ctx,
            TransferCommit {
                preview_id: preview.id,
                keep_startup: vec![],
                keep_forwards: vec![],
                favourites: vec![],
                sessions: vec![],
                known_hosts: vec![ItemChoice {
                    index: host_row.index,
                    action: ItemAction::KeepBoth,
                }],
                secrets: vec![],
            },
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap_err();
    assert_eq!(refused.code(), "invalid_input");
    assert_eq!(by_name(&b, "web01").await.port, 22);

    // Replace web01, keep both db01 and app01, skip bastion (db01 then jumps through B's own box);
    // replace the host key, keep both secrets.
    let preview = open(&b, &second).await;
    let report = b
        .transfer
        .commit(
            &b.ctx,
            TransferCommit {
                preview_id: preview.id,
                keep_startup: vec![],
                keep_forwards: vec![],
                favourites: vec![],
                sessions: vec![
                    ItemChoice {
                        index: index_of(&preview, "web01"),
                        action: ItemAction::Replace,
                    },
                    ItemChoice {
                        index: index_of(&preview, "db01"),
                        action: ItemAction::KeepBoth,
                    },
                    ItemChoice {
                        index: index_of(&preview, "app01"),
                        action: ItemAction::KeepBoth,
                    },
                ],
                known_hosts: vec![ItemChoice {
                    index: host_row.index,
                    action: ItemAction::Replace,
                }],
                secrets: vec![ItemChoice {
                    index: secret_row.index,
                    action: ItemAction::KeepBoth,
                }],
            },
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(report.sessions.replaced, 1);
    assert_eq!(report.sessions.kept_both, 2);
    assert_eq!(report.sessions.skipped, 1);
    assert_eq!(report.known_hosts.replaced, 1);
    assert_eq!(report.secrets.kept_both, 1);

    // web01 is replaced in place (same id, new port). Its password came in beside B's own as
    // "web root (2)", and the session uses it; B's value is untouched.
    let web = by_name(&b, "web01").await;
    assert_eq!(web.id, lib.web);
    assert_eq!(web.port, 2200);
    let labels: Vec<String> = b
        .vault
        .list(&b.ctx)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.label)
        .collect();
    assert!(labels.contains(&"web root".to_owned()) && labels.contains(&"web root (2)".to_owned()));
    let SessionAuth::Password { password_id: Some(pw2) } = web.auth else {
        panic!("{:?}", web.auth)
    };
    assert_eq!(b.vault.vault().get(&b.ctx, pw2).await.unwrap().expose(), lib.password);
    assert_eq!(
        b.vault.vault().get(&b.ctx, pw.id).await.unwrap().expose(),
        "changed on b",
        "B's own value is untouched"
    );

    // db01 kept twice: the original (port 22) and the copy under a new name and id.
    let dbs: Vec<SessionRecord> = sessions(&b)
        .await
        .into_iter()
        .filter(|s| s.name.starts_with("db01"))
        .collect();
    assert_eq!(dbs.len(), 2);
    let copy = dbs.iter().find(|s| s.name == "db01 (2)").unwrap();
    assert_ne!(copy.id, lib.db);
    assert_eq!(copy.port, 2201);
    let own_box = by_name(&b, "jump box").await;
    assert_eq!(
        copy.jump_session_id,
        Some(own_box.id),
        "the skipped bastion maps to B's own box"
    );
    assert!(by_name(&b, "app01 (2)").await.host == "app01.example.com");
    assert_eq!(by_name(&b, "app01").await.host, "elsewhere.example.org");

    let hosts = b.known_hosts.list(&b.ctx).await.unwrap();
    let web_key = hosts.iter().find(|h| h.host == "web01.example.com").unwrap();
    assert_eq!(web_key.fingerprint, "SHA256:webwebwebwebweb");
    assert!(audit(&b).await.iter().any(|e| e.event == "host_key_retrusted"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_vm_link_comes_along_when_the_same_vm_is_here() {
    // QL-01: a session reaches a VM by its .vmx path; another laptop with that VM links it again.
    let dir = temp_folder("transfer");
    let with_vm = || FakeVmware::default().in_library(&vmx("build"), Some("build"));
    let a = laptop_with(with_vm()).await;
    a.inventory.refresh(&a.ctx).await.unwrap();
    let vm_a = a.store.find_vm(&a.ctx, &vmx("build")).await.unwrap().unwrap();
    let mut linked = input("build01", "build01.example.com");
    linked.vm_id = Some(vm_a.id.clone());
    a.sessions.create(&a.ctx, linked).await.unwrap();
    let path = export(&a, &dir, false).await;

    let b = laptop_with(with_vm()).await;
    b.inventory.refresh(&b.ctx).await.unwrap();
    let vm_b = b.store.find_vm(&b.ctx, &vmx("build")).await.unwrap().unwrap();
    let preview = open(&b, &path).await;
    commit(&b, &preview, &[]).await;
    let build = by_name(&b, "build01").await;
    assert_eq!(build.vm_id.as_deref(), Some(vm_b.id.as_str()));
    assert_eq!(
        build.vm_link,
        Some(VmLink::Manual),
        "chosen by hand on the first laptop"
    );

    let c = laptop().await;
    let preview = open(&c, &path).await;
    commit(&c, &preview, &[]).await;
    let build = by_name(&c, "build01").await;
    assert_eq!((build.vm_id, build.vm_link), (None, None), "no such VM here");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn keeping_both_renames_only_a_taken_name() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let path = export(&a, &dir, false).await;
    let b = laptop().await;
    // B reaches bastion's user, host and port under another name.
    let mut own = input("jump box", "bastion.example.org");
    own.port = 2222;
    b.sessions.create(&b.ctx, own).await.unwrap();
    let preview = open(&b, &path).await;
    assert_eq!(status_of(&preview, "bastion"), ItemStatus::Conflict);
    commit(&b, &preview, &[(index_of(&preview, "bastion"), ItemAction::KeepBoth)]).await;
    assert_eq!(by_name(&b, "bastion").await.port, 2222);
    assert_eq!(by_name(&b, "jump box").await.port, 2222);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_unchanged_library_imports_as_already_there() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let path = export(&a, &dir, false).await;
    // Importing into the laptop it came from: everything is the same.
    let preview = open(&a, &path).await;
    assert!(
        preview.sessions.iter().all(|s| s.status == ItemStatus::Same),
        "{:#?}",
        preview.sessions
    );
    assert!(preview.known_hosts.iter().all(|k| k.status == ItemStatus::Same));
    assert_eq!(preview.new_folders, 0);
    let report = commit(&a, &preview, &[]).await;
    assert_eq!(report.sessions.skipped, 3);
    assert_eq!(
        report.sessions.added + report.sessions.replaced + report.sessions.kept_both,
        0
    );
    assert_eq!(report.folders_added, 0);
    assert_eq!(sessions(&a).await.len(), 3);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn secrets_wait_for_an_unlocked_vault_but_sessions_import_either_way() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let path = export(&a, &dir, true).await;
    let b = laptop().await;
    b.vault.lock(&b.ctx).await.unwrap();
    let preview = open(&b, &path).await;
    assert!(
        preview.warnings.iter().any(|w| w.contains("Unlock the vault")),
        "{:?}",
        preview.warnings
    );
    assert!(preview.secrets.iter().all(|s| s.default_action == ItemAction::Skip));

    // Asking for a secret while locked is refused before anything changes.
    let err = b
        .transfer
        .commit(
            &b.ctx,
            TransferCommit {
                preview_id: preview.id,
                keep_startup: vec![],
                keep_forwards: vec![],
                favourites: vec![],
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![ItemChoice {
                    index: preview.secrets[0].index,
                    action: ItemAction::Import,
                }],
            },
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "vault_locked");
    assert!(sessions(&b).await.is_empty());

    let preview = open(&b, &path).await;
    let report = commit(&b, &preview, &[]).await;
    assert_eq!(report.sessions.added, 3);
    assert_eq!(report.secrets.skipped, 3);
    assert_eq!(report.without_credentials, 2);
    let _ = std::fs::remove_dir_all(dir);
}

/// SS-07: saved port forwards travel with their sessions, and a two-hop chain keeps its jump host
/// links on the other laptop.
#[tokio::test]
async fn port_forwards_and_jump_host_chains_move_with_their_sessions() {
    use remotely_core::adapters::remote::forward::ForwardKind;
    use remotely_core::forwards::ForwardInput;

    let dir = temp_folder("transfer-forwards");
    let a = laptop().await;
    let lib = fill(&a).await;
    // A second hop: app01 goes through db01, which goes through the bastion.
    let mut app = input("app01", "app01.test");
    app.jump_session_id = Some(lib.db);
    let app = a.sessions.create(&a.ctx, app).await.unwrap();
    let forward = |kind, port, dest: &str, dest_port, auto_start| ForwardInput {
        id: None,
        label: (kind == ForwardKind::Local).then(|| "Postgres".to_owned()),
        kind,
        bind_address: String::new(),
        bind_port: port,
        dest_host: dest.into(),
        dest_port,
        auto_start,
    };
    let saved = a
        .forwards
        .save(
            &a.ctx,
            app.id,
            &[
                forward(ForwardKind::Local, 15432, "pg.test", 5432, true),
                forward(ForwardKind::Dynamic, 1080, "", 0, false),
            ],
        )
        .await
        .unwrap();
    let path = export(&a, &dir, false).await;
    let exported = audit(&a)
        .await
        .into_iter()
        .find(|e| e.event == "data_exported")
        .unwrap();
    assert!(exported.detail.unwrap().contains("2 port forwards"));

    let b = laptop().await;
    let preview = open(&b, &path).await;
    // SS-07: shown, and only imported when ticked.
    let app_row = preview.sessions.iter().find(|s| s.name == "app01").unwrap();
    assert_eq!(app_row.forwards.len(), 2, "{app_row:?}");
    assert!(
        app_row.forwards[0].contains("pg.test:5432") && app_row.forwards[0].contains("starts with the terminal"),
        "{:?}",
        app_row.forwards
    );
    assert!(app_row.forwards[1].contains("SOCKS"), "{:?}", app_row.forwards);
    let web_index = preview.sessions.iter().find(|s| s.name == "web01").unwrap().index;
    let report = commit_keeping(&b, &preview, &[web_index], &[app_row.index]).await;
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(report.forwards, 2);
    assert_eq!(report.startup_left_out, 0);
    assert_eq!(
        by_name(&b, "web01").await.startup_command.as_deref(),
        Some("cd /srv/www"),
        "ticked"
    );
    let app_b = by_name(&b, "app01").await;
    let db_b = by_name(&b, "db01").await;
    assert_eq!(app_b.jump_session_id, Some(db_b.id));
    assert_eq!(db_b.jump_session_id, Some(by_name(&b, "bastion").await.id));
    let moved = b.forwards.list(&b.ctx, app_b.id).await.unwrap();
    assert_eq!(moved.len(), 2);
    for (here, there) in moved.iter().zip(&saved) {
        assert_eq!(here.spec, there.spec);
        assert_eq!((&here.label, here.auto_start), (&there.label, there.auto_start));
    }
    assert_eq!(moved[0].spec.bind_address, "127.0.0.1", "loopback, as saved");
    let b_audit = audit(&b).await;
    assert!(b_audit
        .iter()
        .any(|e| e.event == "session_changed" && e.action == "Imported the port forwards of 'app01'"));
    let imported = b_audit.iter().find(|e| e.event == "data_imported").unwrap();
    assert!(imported
        .detail
        .as_deref()
        .unwrap()
        .contains("2 port forwards saved with them"));
    let _ = std::fs::remove_dir_all(dir);
}

/// SS-05: a key of a new type for a host that has a trusted key here is what a man in the middle
/// would present, so an import shows it as a conflict and skips it unless the user picks it.
#[tokio::test]
async fn a_new_key_type_for_a_host_trusted_here_is_a_conflict_skipped_by_default() {
    let dir = temp_folder("transfer");
    let a = laptop().await;
    fill(&a).await;
    let path = export(&a, &dir, false).await;

    let b = laptop().await;
    let rsa = HostKey {
        key_type: "ssh-rsa".into(),
        ..host_key("web01.example.com", "SHA256:rsarsarsarsarsa")
    };
    b.known_hosts.trust(&b.ctx, &rsa, None).await.unwrap();
    let preview = open(&b, &path).await;
    let row = preview
        .known_hosts
        .iter()
        .find(|k| k.name == "web01.example.com:22")
        .unwrap();
    assert_eq!(row.status, ItemStatus::Conflict, "{row:?}");
    assert_eq!(row.default_action, ItemAction::Skip);
    assert_eq!(row.choices, [ItemAction::Skip, ItemAction::Import]);
    let why = row.conflict.as_deref().unwrap();
    assert!(
        why.contains("another kind trusted here") && why.contains("ssh-rsa"),
        "{why}"
    );
    let other = preview.known_hosts.iter().find(|k| k.name == "192.0.2.10:22").unwrap();
    assert_eq!(
        other.status,
        ItemStatus::New,
        "a host with no key here is new as before"
    );

    // Imported with the defaults: the new type stays out.
    let report = commit(&b, &preview, &[]).await;
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let web: Vec<String> = b
        .known_hosts
        .list(&b.ctx)
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.host == "web01.example.com")
        .map(|k| k.key_type)
        .collect();
    assert_eq!(web, ["ssh-rsa"]);
}

/// SS-07: port forwards that were not ticked stay behind and are counted.
#[tokio::test]
async fn port_forwards_stay_behind_unless_ticked() {
    use remotely_core::adapters::remote::forward::ForwardKind;
    use remotely_core::forwards::ForwardInput;

    let dir = temp_folder("transfer-forwards-default");
    let a = laptop().await;
    fill(&a).await;
    let app = a.sessions.create(&a.ctx, input("app01", "app01.test")).await.unwrap();
    a.forwards
        .save(
            &a.ctx,
            app.id,
            &[ForwardInput {
                id: None,
                label: None,
                kind: ForwardKind::Remote,
                bind_address: String::new(),
                bind_port: 9000,
                dest_host: "127.0.0.1".into(),
                dest_port: 22,
                auto_start: true,
            }],
        )
        .await
        .unwrap();
    let path = export(&a, &dir, false).await;
    let b = laptop().await;
    let preview = open(&b, &path).await;
    let report = commit(&b, &preview, &[]).await;
    assert_eq!(report.forwards, 0);
    assert_eq!(report.forwards_left_out, 1);
    let app_b = by_name(&b, "app01").await;
    assert!(b.forwards.list(&b.ctx, app_b.id).await.unwrap().is_empty());
    let imported = audit(&b)
        .await
        .into_iter()
        .find(|e| e.event == "data_imported")
        .unwrap();
    assert!(
        imported.detail.as_deref().unwrap().contains("1 port forward left out"),
        "{imported:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
