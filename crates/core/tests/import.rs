//! SS-02 imports, end to end: parse, preview against the library, save the picked rows. Fixtures are
//! inline strings with example.com names and documentation addresses; key files are made at run time
//! in a temp folder. No real session export or key is committed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{temp_folder, Setup};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::{generate_key, private_key_text};
use remotely_core::fakes::FakeVmware;
use remotely_core::import::{self, ImportRequest, ImportSource, RowStatus};
use remotely_core::policy::{ActionKind, Tier};
use remotely_core::sessions::{SessionAuth, SessionFilter, SessionInput};
use remotely_core::{Core, CoreError};

async fn core() -> Core {
    Setup::new(FakeVmware::default()).with_real_vault().build().await
}

fn existing(name: &str, host: &str, user: &str) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: Some(user.into()),
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

const PUTTY_REG: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web01]
"HostName"="web01.example.com"
"PortNumber"=dword:00000016
"UserName"="alice"
"Protocol"="ssh"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\db%20primary]
"HostName"="bob@db01.example.org"
"PortNumber"=dword:00000896
"Protocol"="ssh"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web01%20again]
"HostName"="web01.example.com"
"PortNumber"=dword:00000016
"UserName"="alice"
"Protocol"="ssh"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\router]
"HostName"="192.0.2.1"
"Protocol"="telnet"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\jump]
"HostName"="192.0.2.20"
"PortNumber"=dword:00000016
"UserName"="bob"
"Protocol"="ssh"
"#;

#[tokio::test]
async fn a_putty_list_previews_with_duplicates_and_conflicts_then_imports_the_picked_rows() {
    let core = core().await;
    let ctx = &core.ctx;
    // Already in the library: the same login as "jump", and a session named like the web server.
    core.sessions
        .create(ctx, existing("old jump", "192.0.2.20", "bob"))
        .await
        .unwrap();
    core.sessions
        .create(ctx, existing("web01", "web02.example.com", "alice"))
        .await
        .unwrap();

    let preview = core
        .import
        .preview(
            ctx,
            ImportSource::PuttyFile,
            Some("putty.reg".into()),
            import::putty::parse_reg(PUTTY_REG),
        )
        .await
        .unwrap();
    assert_eq!(preview.skipped.len(), 1, "{:?}", preview.skipped);
    assert!(preview.skipped[0].reason.contains("telnet"));
    let row = |name: &str| preview.rows.iter().find(|r| r.candidate.name == name).unwrap();
    assert!(matches!(&row("web01").status, RowStatus::NameConflict { rename_to, .. } if rename_to == "web01 (2)"));
    assert!(row("web01").selected);
    assert_eq!(row("db primary").status, RowStatus::New);
    assert_eq!(row("db primary").candidate.port, 2198);
    assert_eq!(row("db primary").candidate.username.as_deref(), Some("bob"));
    assert!(
        matches!(row("web01 again").status, RowStatus::DuplicateInImport { row } if row == row_index(&preview, "web01"))
    );
    assert!(!row("web01 again").selected);
    assert!(matches!(&row("jump").status, RowStatus::Duplicate { session_name, .. } if session_name == "old jump"));
    assert!(!row("jump").selected);

    // Import what the preview ticked, into a folder.
    let folder = core.sessions.create_folder(ctx, "Imported", None).await.unwrap();
    let picked: Vec<usize> = preview.rows.iter().filter(|r| r.selected).map(|r| r.index).collect();
    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: picked,
                folder_id: Some(folder.id),
                add_keys: false,
                keep_startup: vec![],
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, 2);
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    let imported = core
        .sessions
        .list(
            ctx,
            &SessionFilter {
                folder_id: Some(folder.id),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let names: Vec<&str> = imported.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["db primary", "web01 (2)"]);
    for s in &imported {
        assert_eq!(s.imported_from.as_deref(), Some("putty"));
        assert_eq!(s.auth, SessionAuth::Password { password_id: None });
    }

    let audit = core.store.recent_audit(ctx, 10).await.unwrap();
    assert_eq!(audit[0].event, "sessions_imported");
    assert_eq!(audit[0].action, "Imported 2 sessions from PuTTY");
    assert!(audit
        .iter()
        .any(|e| e.action == "Imported session 'db primary' from PuTTY"));

    // A preview is used once.
    let again = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: vec![0],
                folder_id: None,
                add_keys: false,
                keep_startup: vec![],
            },
            &core.sessions,
            &core.vault,
        )
        .await;
    assert!(matches!(again, Err(CoreError::InvalidInput(_))));
}

fn row_index(preview: &import::ImportPreview, name: &str) -> usize {
    preview.rows.iter().find(|r| r.candidate.name == name).unwrap().index
}

#[tokio::test]
async fn an_openssh_config_imports_patterns_key_files_and_jump_hosts() {
    let core = core().await;
    let ctx = &core.ctx;
    let dir = temp_folder("import-openssh");
    let key_path = dir.join("id_ed25519");
    std::fs::write(&key_path, private_key_text(&generate_key(), None).expose()).unwrap();
    let config = format!(
        "Host web*\n  User alice\n  IdentityFile {key}\n\nHost web01 web02\n  HostName %h.example.com\n\nHost inner\n  HostName 198.51.100.7\n  ProxyJump bastion\n  IdentityFile {key}\n\nHost bastion\n  HostName bastion.example.com\n  Port 2222\n\nHost *\n  User bob\n",
        key = key_path.display()
    );
    let config_path = dir.join("config");
    std::fs::write(&config_path, config).unwrap();

    let preview = core
        .import
        .preview_file(ctx, ImportSource::Openssh, &config_path)
        .await
        .unwrap();
    assert_eq!(preview.file.as_deref(), Some("config"));
    let names: Vec<&str> = preview.rows.iter().map(|r| r.candidate.name.as_str()).collect();
    assert_eq!(names, ["web01", "web02", "inner", "bastion"]);
    let web01 = &preview.rows[0];
    assert_eq!(web01.candidate.host, "web01.example.com");
    assert_eq!(web01.candidate.username.as_deref(), Some("alice"));
    let key_file = web01.key_file.as_ref().unwrap();
    assert!(key_file.exists);
    assert_eq!(key_file.label, "id_ed25519");
    assert_eq!(preview.rows[2].candidate.username.as_deref(), Some("bob"));

    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: preview.rows.iter().map(|r| r.index).collect(),
                folder_id: None,
                add_keys: true,
                keep_startup: vec![],
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, 4);
    // Three sessions use the key file; the vault gets it once.
    assert_eq!(report.keys_added, 1);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let secrets = core.vault.list(ctx).await.unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].label, "id_ed25519");
    assert_eq!(secrets[0].used_by, 3);

    let sessions = core.sessions.list(ctx, &SessionFilter::default()).await.unwrap();
    let by_name = |name: &str| sessions.iter().find(|s| s.name == name).unwrap();
    assert_eq!(
        by_name("web01").auth,
        SessionAuth::Key {
            key_id: Some(secrets[0].id),
            passphrase_id: None
        }
    );
    // The jump host link is kept for SS-07 (the terminal says it's not supported yet), whatever the
    // order in the file.
    assert_eq!(by_name("inner").jump_session_id, Some(by_name("bastion").id));
    assert_eq!(by_name("bastion").port, 2222);
    assert!(sessions.iter().all(|s| s.imported_from.as_deref() == Some("openssh")));

    // Importing the same file again finds only duplicates.
    let again = core
        .import
        .preview_file(ctx, ImportSource::Openssh, &config_path)
        .await
        .unwrap();
    assert!(again
        .rows
        .iter()
        .all(|r| matches!(r.status, RowStatus::Duplicate { .. }) && !r.selected));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn adding_keys_needs_an_unlocked_vault_and_saves_nothing_otherwise() {
    let core = core().await;
    let ctx = &core.ctx;
    let dir = temp_folder("import-locked");
    let key_path = dir.join("lab.ppk");
    std::fs::write(&key_path, private_key_text(&generate_key(), None).expose()).unwrap();
    let csv = format!(
        "name,host,user,key_file,password,tags,environment,folder\nlab01,192.0.2.31,alice,{},hunter-placeholder,lab;linux,lab,Customers/Acme\n",
        key_path.display()
    );
    let preview = core
        .import
        .preview(ctx, ImportSource::Csv, None, import::csv::parse(&csv))
        .await
        .unwrap();
    assert!(
        preview.warnings.iter().any(|w| w.to_lowercase().contains("password")),
        "{:?}",
        preview.warnings
    );
    assert!(!format!("{preview:?}").contains("hunter-placeholder"));
    core.vault.lock(ctx).await.unwrap();
    let request = ImportRequest {
        preview_id: preview.id,
        rows: vec![0],
        folder_id: None,
        add_keys: true,
        keep_startup: vec![],
    };
    let err = core
        .import
        .commit(ctx, &request, &core.sessions, &core.vault)
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::VaultLocked));
    assert!(core
        .sessions
        .list(ctx, &SessionFilter::default())
        .await
        .unwrap()
        .is_empty());

    // Without the keys it goes through, and the session asks for its key in the editor.
    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                add_keys: false,
                ..request
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, 1);
    assert_eq!(report.folders_created, 2);
    assert!(report.problems[0].reason.contains("choose one in the session editor"));
    let session = &core.sessions.list(ctx, &SessionFilter::default()).await.unwrap()[0];
    assert_eq!(session.environment, Environment::Lab);
    assert_eq!(session.tags, ["lab", "linux"]);
    assert_eq!(session.imported_from.as_deref(), Some("csv"));
    let folders = core.sessions.folders(ctx).await.unwrap();
    let acme = folders.iter().find(|f| f.name == "Acme").unwrap();
    assert_eq!(session.folder_id, Some(acme.id));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_mobaxterm_export_keeps_its_folders_and_leaves_passwords_out() {
    let core = core().await;
    let ctx = &core.ctx;
    let text = "[Bookmarks]\nSubRep=\nImgNum=42\nweb01=#109#0%web01.example.com%22%alice%%-1%-1%%%22%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%1%-1%-1#0# #-1\n\n[Bookmarks_1]\nSubRep=Customers\\Acme\nImgNum=41\ndb01=#109#0%db01.example.org%2222%bob%%-1%-1%%%22%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1\n\n[Passwords]\nssh22:alice@web01.example.com=placeholder-not-real\n";
    let preview = core
        .import
        .preview(
            ctx,
            ImportSource::Mobaxterm,
            None,
            import::mobaxterm::parse(text, &import::home_dir()),
        )
        .await
        .unwrap();
    assert_eq!(preview.rows.len(), 2);
    assert!(preview.warnings.iter().any(|w| w.contains("password")));
    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: vec![0, 1],
                folder_id: None,
                add_keys: false,
                keep_startup: vec![],
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, 2);
    let sessions = core.sessions.list(ctx, &SessionFilter::default()).await.unwrap();
    let db = sessions.iter().find(|s| s.name == "db01").unwrap();
    assert_eq!(db.port, 2222);
    let folders = core.sessions.folders(ctx).await.unwrap();
    assert_eq!(db.folder_id, folders.iter().find(|f| f.name == "Acme").map(|f| f.id));
    let audit = format!("{:?}", core.store.recent_audit(ctx, 50).await.unwrap());
    assert!(!audit.contains("placeholder-not-real"));
}

// ---- QL-10: the sample files behind the format guides ------------------------------------------------

/// A preview row as the guide describes it: name, address, folder, tags, environment, login, colour,
/// jump host, startup command.
fn described(row: &import::PreviewRow) -> String {
    let c = &row.candidate;
    let user = c.username.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
    let login = match &c.auth {
        import::CandidateAuth::Password => "password".to_owned(),
        import::CandidateAuth::KeyFile { path } => format!("key {path}"),
        import::CandidateAuth::Agent => "agent".to_owned(),
    };
    let colour = c.color.map(|c| c.as_str()).unwrap_or("-");
    format!(
        "{} | {user}{}:{} | {} | {} | {:?} | {login} | {colour} | {} | {}",
        c.name,
        c.host,
        c.port,
        c.folder.join("/"),
        c.tags.join(","),
        c.environment,
        c.jump.as_deref().unwrap_or("-"),
        c.startup_command.as_deref().unwrap_or("-"),
    )
}

/// Saves the sample to a temp folder, previews it through the real parser, imports every row and
/// returns the preview.
async fn import_sample(core: &Core, source: ImportSource) -> import::ImportPreview {
    let ctx = &core.ctx;
    let sample = import::guide::sample(source);
    let dir = temp_folder("import-sample");
    let path = dir.join(sample.file_name);
    std::fs::write(&path, &sample.text).unwrap();
    let preview = core.import.preview_file(ctx, source, &path).await.unwrap();
    assert_eq!(preview.file.as_deref(), Some(sample.file_name));
    assert!(preview.warnings.is_empty(), "{source:?}: {:?}", preview.warnings);
    assert!(
        preview.rows.iter().all(|r| r.selected),
        "{source:?}: every sample row is new"
    );
    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: preview.rows.iter().map(|r| r.index).collect(),
                folder_id: None,
                add_keys: false,
                keep_startup: preview.rows.iter().map(|r| r.index).collect(),
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, preview.rows.len(), "{source:?}: {:?}", report.problems);
    // The jump host the guide promises: another session of the same file, linked once saved.
    let sessions = core.sessions.list(ctx, &SessionFilter::default()).await.unwrap();
    let id = |name: &str| sessions.iter().find(|s| s.name.starts_with(name)).unwrap();
    assert_eq!(
        id("db01").jump_session_id,
        Some(id("bastion").id),
        "{source:?}: db01 goes through bastion"
    );
    std::fs::remove_dir_all(&dir).unwrap();
    preview
}

#[tokio::test]
async fn the_csv_sample_imports_as_its_guide_says() {
    let core = core().await;
    let preview = import_sample(&core, ImportSource::Csv).await;
    let rows: Vec<String> = preview.rows.iter().map(described).collect();
    assert_eq!(
        rows,
        [
            "web01 | alice@web01.example.com:22 | Customer A/Web | web,frontend | Prod | password | red | - | -",
            r"db01 | bob@192.0.2.20:2222 | Customer A/DB | db,postgres | Staging | key C:\Users\alice\.ssh\id_ed25519 | amber | bastion | cd /var/lib; ls",
            "bastion | alice@bastion.example.org:22 | Customer A | jump | Prod | agent | slate | - | -",
            "lab01 | alice@lab01.test:2200 | Lab | lab | Lab | password | teal | - | -",
            "198.51.100.7 | 198.51.100.7:22 |  |  | None | password | - | - | -",
        ]
    );
    assert!(preview.skipped.is_empty());
    assert!(preview.rows.iter().all(|r| r.candidate.notes.is_empty()));
    // The folders the folder column names were made, one inside the other.
    let folders = core.sessions.folders(&core.ctx).await.unwrap();
    let customer = folders.iter().find(|f| f.name == "Customer A").unwrap();
    let web = folders.iter().find(|f| f.name == "Web").unwrap();
    assert_eq!(web.parent_id, Some(customer.id));
}

#[tokio::test]
async fn the_putty_sample_imports_as_its_guide_says() {
    let core = core().await;
    let preview = import_sample(&core, ImportSource::PuttyFile).await;
    let rows: Vec<String> = preview.rows.iter().map(described).collect();
    assert_eq!(
        rows,
        [
            "web01 | alice@web01.example.com:22 |  |  | None | password | - | - | -",
            r"db01 (Customer A) | bob@192.0.2.20:2222 |  |  | None | key C:\Users\alice\.ssh\db01.ppk | - | alice@bastion.example.org | uptime",
            "bastion | alice@bastion.example.org:22 |  |  | None | password | - | - | -",
        ],
        "Default Settings is no session"
    );
    let skipped: Vec<(&str, &str)> = preview
        .skipped
        .iter()
        .map(|s| (s.name.as_str(), s.reason.as_str()))
        .collect();
    assert_eq!(skipped, [("switch01", "telnet session: only SSH is imported")]);
}

#[tokio::test]
async fn the_mobaxterm_sample_imports_as_its_guide_says() {
    let core = core().await;
    let preview = import_sample(&core, ImportSource::Mobaxterm).await;
    let home = import::home_dir().display().to_string();
    let home = home.trim_end_matches(['\\', '/']);
    let rows: Vec<String> = preview.rows.iter().map(described).collect();
    assert_eq!(
        rows,
        [
            "web01 | alice@web01.example.com:22 |  |  | None | password | - | - | -".to_owned(),
            "bastion | alice@bastion.example.org:22 | Customer A |  | None | password | - | - | -".to_owned(),
            format!(
                r"db01 | bob@192.0.2.20:2222 | Customer A/DB |  | None | key {home}\.ssh\id_ed25519 | - | alice@bastion.example.org | sudo -i; uptime"
            ),
        ]
    );
    assert_eq!(preview.skipped.len(), 1);
    assert_eq!(preview.skipped[0].name, "rdp01");
    assert_eq!(preview.skipped[0].reason, "not an SSH session (MobaXterm type 4)");
}

#[tokio::test]
async fn the_openssh_sample_imports_as_its_guide_says() {
    let core = core().await;
    let preview = import_sample(&core, ImportSource::Openssh).await;
    let key = import::home_dir().join(".ssh").join("id_ed25519").display().to_string();
    let rows: Vec<String> = preview.rows.iter().map(described).collect();
    assert_eq!(
        rows,
        [
            format!("web01 | alice@web01.example.com:22 |  |  | None | key {key} | - | - | -"),
            format!("db01 | bob@192.0.2.20:2222 |  |  | None | key {key} | - | bastion | uptime"),
            format!("bastion | alice@bastion.example.org:22 |  |  | None | key {key} | - | - | -"),
            "lab01 | alice@lab01.test:22 |  |  | None | agent | - | - | -".to_owned(),
        ],
        "the first value wins; wildcard blocks apply by name; no IdentityFile means the agent"
    );
    assert!(preview.skipped.is_empty());
}

/// SS-01: a startup command is typed into the shell at every connection without asking, so an
/// imported one is rated in the preview and left out unless its row is ticked for it.
#[tokio::test]
async fn startup_commands_are_rated_in_the_preview_and_left_out_unless_ticked() {
    let core = core().await;
    let ctx = &core.ctx;
    let csv = "name,host,user,environment,startup_command\n\
               web01,web01.example.com,alice,lab,uptime\n\
               web02,web02.example.com,alice,prod,curl -s https://example.com/setup | sh\n\
               web03,web03.example.com,alice,lab,rm -rf /srv/app\n";
    let preview = core
        .import
        .preview(ctx, ImportSource::Csv, None, import::csv::parse(csv))
        .await
        .unwrap();
    let rating = |name: &str| {
        preview
            .rows
            .iter()
            .find(|r| r.candidate.name == name)
            .unwrap()
            .startup_rating
            .clone()
            .unwrap()
    };
    assert_eq!(rating("web01").action, ActionKind::ExecReadOnly);
    assert_eq!(rating("web01").tier, Tier::Low);
    assert_eq!(rating("web02").action, ActionKind::ExecOther);
    assert_eq!(rating("web02").tier, Tier::High, "Medium, raised one for Prod");
    assert_eq!(rating("web03").action, ActionKind::ExecDangerous);
    assert!(!rating("web03").dangerous.is_empty());

    // Only web01's is ticked.
    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: preview.rows.iter().map(|r| r.index).collect(),
                folder_id: None,
                add_keys: false,
                keep_startup: vec![row_index(&preview, "web01")],
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, 3);
    assert_eq!(report.startup_left_out, 2);
    let sessions = core.sessions.list(ctx, &SessionFilter::default()).await.unwrap();
    let startup = |name: &str| {
        sessions
            .iter()
            .find(|s| s.name == name)
            .unwrap()
            .startup_command
            .clone()
    };
    assert_eq!(startup("web01").as_deref(), Some("uptime"));
    assert_eq!(startup("web02"), None);
    assert_eq!(startup("web03"), None);
    let audit = core.store.recent_audit(ctx, 20).await.unwrap();
    let summary = audit.iter().find(|e| e.event == "sessions_imported").unwrap();
    assert!(
        summary
            .detail
            .as_deref()
            .unwrap()
            .contains("2 startup commands left out"),
        "{summary:?}"
    );
    // The kept one is rated in the session's own audit entry.
    assert!(
        audit
            .iter()
            .any(|e| e.event == "session_changed"
                && e.detail.as_deref().is_some_and(|d| d.contains("rated Low: read-only"))),
        "{audit:#?}"
    );
}
