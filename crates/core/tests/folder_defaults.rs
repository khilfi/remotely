//! QL-16 folder defaults, end to end: a folder can set the user, the login, the jump host, the environment label and
//! tags; a session uses its own value first, then the nearest folder up the path, then the app's default. One
//! resolver serves every place a session is used (connection details for terminals, quick connect, MultiExec,
//! Compare and bulk runs, key pushes, containers, dashboard polling and host details; the Prod tier bump;
//! reachability's jump host; FD-07; SS-02). SS-04: a folder default that would start sending a vault password to a
//! host asks for the vault password like editing the session would. Fakes and the local test SSH server only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{temp_folder, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AuthMethod, PtySize};
use remotely_core::command_bus::{Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::FakeVmware;
use remotely_core::import::{self, ImportRequest, ImportSource};
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::Tier;
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{FolderDefaults, SessionAuth, SessionFilter, SessionInput, SessionRecord};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::TerminalEvent;
use remotely_core::transfer::{ExportRequest, ItemAction, ItemChoice, ItemStatus, TransferCommit};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::{Core, CoreError};
use tokio::time::timeout;
use uuid::Uuid;

const PASSPHRASE: &str = "tulip anvil orbit";

fn pw(text: &str) -> SecretString {
    SecretString::new(text)
}

/// The app's own vault, unlocked; every vault password step asks (no grace period).
async fn core() -> Core {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    core.secret_bindings().set_grace(Duration::ZERO);
    core.transfer.use_insecure_fast_kdf();
    core
}

/// A password that was in the vault before this run, so sending it somewhere new asks.
async fn existing(core: &Core, label: &str) -> SecretId {
    core.vault
        .vault()
        .put(&core.ctx(), SecretKind::Password, label, pw(&format!("{label}-value")))
        .await
        .unwrap()
}

async fn key(core: &Core, label: &str) -> SecretId {
    core.vault
        .vault()
        .put(
            &core.ctx(),
            SecretKind::PrivateKey,
            label,
            pw(&common::fake_private_key()),
        )
        .await
        .unwrap()
}

fn session(name: &str, host: &str) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: None,
        auth: SessionAuth::Folder,
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::None,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

fn in_folder(name: &str, host: &str, folder: Uuid) -> SessionInput {
    SessionInput {
        folder_id: Some(folder),
        ..session(name, host)
    }
}

fn password_login(id: SecretId) -> SessionAuth {
    SessionAuth::Password { password_id: Some(id) }
}

fn reauth_required<T: std::fmt::Debug>(result: &Result<T, CoreError>) -> bool {
    matches!(result, Err(CoreError::ReauthRequired { .. }))
}

async fn get(core: &Core, id: Uuid) -> SessionRecord {
    core.sessions.get(&core.ctx(), id).await.unwrap()
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx(), 300).await.unwrap()
}

async fn set_defaults(core: &Core, folder: Uuid, defaults: FolderDefaults) {
    core.sessions
        .set_folder_defaults_with(&core.ctx(), folder, defaults, Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_session_value_wins_then_its_folder_then_the_folder_above_then_the_app_default() {
    let core = core().await;
    let ctx = &core.ctx();
    let k1 = key(&core, "customer key").await;
    let p2 = existing(&core, "web password").await;
    let outer = core
        .sessions
        .create(ctx, session("bastion", "bastion.example.org"))
        .await
        .unwrap();

    let top = core.sessions.create_folder(ctx, "Customer A", None).await.unwrap();
    let web = core.sessions.create_folder(ctx, "Web", Some(top.id)).await.unwrap();
    let low = core
        .sessions
        .create_folder(ctx, "Frontend", Some(web.id))
        .await
        .unwrap();
    set_defaults(
        &core,
        top.id,
        FolderDefaults {
            username: Some("alice".into()),
            auth: Some(SessionAuth::Key {
                key_id: Some(k1),
                passphrase_id: None,
            }),
            jump_session_id: Some(outer.id),
            environment: Some(Environment::Prod),
            tags: vec!["acme".into()],
            ..FolderDefaults::default()
        },
    )
    .await;
    set_defaults(
        &core,
        web.id,
        FolderDefaults {
            auth: Some(password_login(p2)),
            tags: vec!["web".into()],
            ..FolderDefaults::default()
        },
    )
    .await;

    // Nothing set on the session: each value from the nearest folder that sets it.
    let s1 = core
        .sessions
        .create_with(
            ctx,
            in_folder("web01", "web01.example.com", low.id),
            Some(&pw(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    assert_eq!(s1.username.as_deref(), Some("alice"));
    assert_eq!(s1.auth, password_login(p2));
    assert_eq!(s1.jump_session_id, Some(outer.id));
    assert_eq!(s1.environment, Environment::Prod);
    assert_eq!(s1.tags, vec!["acme".to_owned(), "web".to_owned()]);
    assert_eq!(s1.inherited.username.as_ref().unwrap().name, "Customer A");
    assert_eq!(s1.inherited.auth.as_ref().unwrap().name, "Web");
    assert_eq!(s1.own.auth, SessionAuth::Folder);
    assert_eq!(s1.own.username, None);

    // Its own values win, and its tags add to the folders'.
    let s2 = core
        .sessions
        .create(
            ctx,
            SessionInput {
                username: Some("bob".into()),
                auth: SessionAuth::Agent,
                jump_direct: true,
                environment: Environment::Lab,
                tags: vec!["db".into()],
                ..in_folder("db01", "db01.example.com", low.id)
            },
        )
        .await
        .unwrap();
    assert_eq!(s2.username.as_deref(), Some("bob"));
    assert_eq!(s2.auth, SessionAuth::Agent);
    assert_eq!(s2.jump_session_id, None);
    assert_eq!(s2.environment, Environment::Lab);
    assert_eq!(s2.tags, vec!["acme".to_owned(), "db".to_owned(), "web".to_owned()]);

    // Outside every folder: the app's defaults (no user, a password asked when connecting, no label).
    let s3 = core
        .sessions
        .create(ctx, session("loose", "loose.example.com"))
        .await
        .unwrap();
    assert_eq!(s3.username, None);
    assert_eq!(s3.auth, SessionAuth::Password { password_id: None });
    assert_eq!(s3.environment, Environment::None);

    // The connection details every module uses (terminals, MultiExec, Compare, bulk runs, key pushes, containers,
    // dashboard polling, host details) are built from the same values, the jump host's included.
    let spec = core.store.session_spec(ctx, s1.id).await.unwrap().unwrap();
    assert_eq!(spec.username, "alice");
    assert_eq!(spec.auth, AuthMethod::Password(Some(p2)));
    assert_eq!(spec.environment, Environment::Prod);
    assert_eq!(spec.jump.as_ref().unwrap().id, outer.id);
    // The jump host outside the folder: its own (app) defaults.
    assert_eq!(spec.jump.as_ref().unwrap().username, "");
    let spec = core.store.session_spec(ctx, s2.id).await.unwrap().unwrap();
    assert_eq!(spec.username, "bob");
    assert!(spec.jump.is_none());

    // A filter on tags and labels sees the inherited ones.
    let tagged = core
        .sessions
        .list(
            ctx,
            &SessionFilter {
                tags: vec!["acme".into()],
                environments: vec![Environment::Prod],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(tagged.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["web01"]);
}

#[tokio::test]
async fn the_editor_keeps_what_a_session_sets_itself_and_sees_what_a_folder_would_give() {
    let core = core().await;
    let ctx = &core.ctx();
    let folder = core.sessions.create_folder(ctx, "Lab", None).await.unwrap();
    set_defaults(
        &core,
        folder.id,
        FolderDefaults {
            username: Some("alice".into()),
            environment: Some(Environment::Staging),
            ..FolderDefaults::default()
        },
    )
    .await;
    let s = core
        .sessions
        .create(ctx, in_folder("app01", "app01.example.com", folder.id))
        .await
        .unwrap();
    // Saving the editor's view back changes nothing and bakes nothing in.
    let again = core.sessions.update(ctx, s.id, s.input()).await.unwrap();
    assert_eq!(again.own, s.own);
    assert_eq!(again.input().username, None);
    // A copy keeps taking its values from the folder.
    let copy = core.sessions.duplicate(ctx, s.id).await.unwrap();
    assert_eq!(copy.own.username, None);
    assert_eq!(copy.username.as_deref(), Some("alice"));
    // The folder's values change: the session follows.
    set_defaults(
        &core,
        folder.id,
        FolderDefaults {
            username: Some("bob".into()),
            ..FolderDefaults::default()
        },
    )
    .await;
    let after = get(&core, s.id).await;
    assert_eq!(after.username.as_deref(), Some("bob"));
    assert_eq!(after.environment, Environment::None);
    // What a new session in the folder would get, for the editor's "from folder X".
    let inherited = core.sessions.inherited(ctx, Some(folder.id), None).await.unwrap();
    assert_eq!(inherited.username.as_deref(), Some("bob"));
    assert_eq!(inherited.inherited.username.unwrap().name, "Lab");
    assert!(core.sessions.inherited(ctx, Some(Uuid::new_v4()), None).await.is_err());
}

#[tokio::test]
async fn a_prod_label_from_a_folder_raises_the_tier_like_the_sessions_own() {
    let core = core().await;
    let ctx = &core.ctx();
    let prod = core.sessions.create_folder(ctx, "Production", None).await.unwrap();
    set_defaults(
        &core,
        prod.id,
        FolderDefaults {
            environment: Some(Environment::Prod),
            ..FolderDefaults::default()
        },
    )
    .await;
    let s = core
        .sessions
        .create(
            ctx,
            SessionInput {
                username: Some("alice".into()),
                auth: SessionAuth::Agent,
                ..in_folder("prod01", "prod01.example.com", prod.id)
            },
        )
        .await
        .unwrap();
    let (_, environment, _) = core.store.find_session_target(ctx, s.id).await.unwrap().unwrap();
    assert_eq!(environment, Environment::Prod);
    let run = Command::RemoteExec {
        targets: vec![TargetRef::Session { session_id: s.id }],
        script: "uptime".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Default::default(),
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(ctx, run).await.unwrap() else {
        panic!("an inherited Prod label raises the tier");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(request.targets[0].environment, Environment::Prod);
    core.bus.cancel_approval(request.id).await.unwrap();

    // A label of its own wins: the session chose Lab.
    let mut lab = s.input();
    lab.environment = Environment::Lab;
    core.sessions.update(ctx, s.id, lab).await.unwrap();
    let (_, environment, _) = core.store.find_session_target(ctx, s.id).await.unwrap().unwrap();
    assert_eq!(environment, Environment::Lab);
}

#[tokio::test]
async fn a_folder_password_for_new_hosts_asks_for_the_vault_password_like_editing_each_session() {
    let core = core().await;
    let ctx = &core.ctx();
    let root = existing(&core, "customer root").await;
    let folder = core.sessions.create_folder(ctx, "Customer", None).await.unwrap();
    let a = core
        .sessions
        .create(ctx, in_folder("a", "a.example.com", folder.id))
        .await
        .unwrap();
    core.sessions
        .create(ctx, in_folder("b", "b.example.com", folder.id))
        .await
        .unwrap();

    // Setting the folder's password would send it to two hosts that never got it.
    let defaults = FolderDefaults {
        auth: Some(password_login(root)),
        ..FolderDefaults::default()
    };
    let err = core
        .sessions
        .set_folder_defaults(ctx, folder.id, defaults.clone())
        .await;
    assert!(reauth_required(&err), "{err:?}");
    let message = err.unwrap_err().to_string();
    assert!(message.contains("password 'customer root'"), "{message}");
    assert!(message.contains("and one more place"), "{message}");
    assert!(!message.contains("customer root-value"));
    assert_eq!(get(&core, a.id).await.auth, SessionAuth::Password { password_id: None });

    let wrong = core
        .sessions
        .set_folder_defaults_with(ctx, folder.id, defaults.clone(), Some(&pw("not the one at all")))
        .await;
    assert!(matches!(wrong, Err(CoreError::WrongVaultPassword)), "{wrong:?}");
    let failed = audit(&core).await;
    assert!(failed
        .iter()
        .any(|e| e.event == "vault_auth_failed" && e.action == "Failed to change the defaults of folder 'Customer'"));

    core.sessions
        .set_folder_defaults_with(ctx, folder.id, defaults, Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();
    assert_eq!(get(&core, a.id).await.auth, password_login(root));
    let entries = audit(&core).await;
    let changed = entries
        .iter()
        .find(|e| e.action == "Changed the defaults of folder 'Customer'")
        .unwrap();
    assert_eq!(changed.event, "session_changed");
    let detail = changed.detail.as_deref().unwrap();
    assert!(detail.contains("login: not set -> password from the vault"), "{detail}");
    assert!(detail.contains("2 sessions affected"), "{detail}");
    assert!(
        detail.contains("the vault password was asked again (AP-06)"),
        "{detail}"
    );
    let targets: Vec<serde_json::Value> = serde_json::from_str(&changed.targets_json).unwrap();
    assert_eq!(targets.len(), 2);

    // A new session in the folder sends it to a third host: asked again, as creating it with that login would.
    let err = core
        .sessions
        .create(ctx, in_folder("c", "c.example.com", folder.id))
        .await;
    assert!(reauth_required(&err), "{err:?}");
    // Where it already goes (a's host), nothing is asked.
    core.sessions
        .create(ctx, in_folder("a again", "A.example.com", folder.id))
        .await
        .unwrap();

    // A session elsewhere that switches its login to "as its folders say" asks like any other new login.
    let loose = core
        .sessions
        .create(
            ctx,
            SessionInput {
                auth: SessionAuth::Agent,
                ..session("d", "d.example.com")
            },
        )
        .await
        .unwrap();
    let mut moved = loose.input();
    moved.folder_id = Some(folder.id);
    moved.auth = SessionAuth::Folder;
    let err = core.sessions.update(ctx, loose.id, moved.clone()).await;
    assert!(reauth_required(&err), "{err:?}");
    core.sessions
        .update_with(ctx, loose.id, moved, Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();

    // The vault counts the sessions that log in with it through the folder.
    let used = core
        .store
        .vault_items(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.id == root)
        .unwrap()
        .used_by;
    assert_eq!(used, 4);
}

#[tokio::test]
async fn moving_sessions_or_folders_under_a_folder_password_asks_like_editing_them() {
    let core = core().await;
    let ctx = &core.ctx();
    let root = existing(&core, "customer root").await;
    let secured = core.sessions.create_folder(ctx, "Secured", None).await.unwrap();
    set_defaults(
        &core,
        secured.id,
        FolderDefaults {
            auth: Some(password_login(root)),
            ..FolderDefaults::default()
        },
    )
    .await;

    // A session moved in: the folder's password would go to its host.
    let s = core
        .sessions
        .create(ctx, session("web", "web.example.com"))
        .await
        .unwrap();
    let err = core.sessions.move_to(ctx, &[s.id], Some(secured.id)).await;
    assert!(reauth_required(&err), "{err:?}");
    assert_eq!(get(&core, s.id).await.folder_id, None, "nothing moved");
    core.sessions
        .move_to_with(ctx, &[s.id], Some(secured.id), Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();
    assert_eq!(get(&core, s.id).await.auth, password_login(root));
    let moved = audit(&core).await;
    let moved = moved
        .iter()
        .find(|e| e.action == "Moved session 'web' to folder 'Secured'")
        .unwrap();
    assert!(moved.detail.as_deref().unwrap().contains("asked again"));

    // A folder of sessions moved under it.
    let other = core.sessions.create_folder(ctx, "Other", None).await.unwrap();
    core.sessions
        .create(ctx, in_folder("db", "db.example.com", other.id))
        .await
        .unwrap();
    let err = core.sessions.move_folder(ctx, other.id, Some(secured.id)).await;
    assert!(reauth_required(&err), "{err:?}");
    core.sessions
        .move_folder_with(ctx, other.id, Some(secured.id), Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();

    // A folder deleted, its sessions moving up under the password.
    let inner = core
        .sessions
        .create_folder(ctx, "Inner", Some(secured.id))
        .await
        .unwrap();
    set_defaults(
        &core,
        inner.id,
        FolderDefaults {
            auth: Some(SessionAuth::Agent),
            ..FolderDefaults::default()
        },
    )
    .await;
    let cache = core
        .sessions
        .create(ctx, in_folder("cache", "cache.example.com", inner.id))
        .await
        .unwrap();
    assert_eq!(cache.auth, SessionAuth::Agent);
    let err = core.sessions.delete_folder(ctx, inner.id).await;
    assert!(reauth_required(&err), "{err:?}");
    core.sessions
        .delete_folder_with(ctx, inner.id, Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();
    let cache = get(&core, cache.id).await;
    assert_eq!(cache.folder_id, Some(secured.id));
    assert_eq!(cache.auth, password_login(root));

    // A key or the agent never leaves this PC: moving under a key login asks nothing.
    let k = key(&core, "lab key").await;
    let keyed = core.sessions.create_folder(ctx, "Keyed", None).await.unwrap();
    set_defaults(
        &core,
        keyed.id,
        FolderDefaults {
            auth: Some(SessionAuth::Key {
                key_id: Some(k),
                passphrase_id: None,
            }),
            ..FolderDefaults::default()
        },
    )
    .await;
    let t = core
        .sessions
        .create(ctx, session("tools", "tools.example.com"))
        .await
        .unwrap();
    core.sessions.move_to(ctx, &[t.id], Some(keyed.id)).await.unwrap();
}

#[tokio::test]
async fn a_folder_jump_host_that_moves_sessions_sending_vault_passwords_asks() {
    let core = core().await;
    let ctx = &core.ctx();
    let root = existing(&core, "customer root").await;
    let folder = core.sessions.create_folder(ctx, "Behind", None).await.unwrap();
    let s = core
        .sessions
        .create_with(
            ctx,
            SessionInput {
                auth: password_login(root),
                ..in_folder("app", "app.internal.test", folder.id)
            },
            Some(&pw(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    let bastion = core
        .sessions
        .create(
            ctx,
            SessionInput {
                auth: SessionAuth::Agent,
                ..session("bastion", "bastion.example.org")
            },
        )
        .await
        .unwrap();
    // Behind a jump host, app.internal.test is another place: its password would go somewhere new.
    let via = FolderDefaults {
        jump_session_id: Some(bastion.id),
        ..FolderDefaults::default()
    };
    let err = core.sessions.set_folder_defaults(ctx, folder.id, via.clone()).await;
    assert!(reauth_required(&err), "{err:?}");
    set_defaults(&core, folder.id, via).await;
    assert_eq!(get(&core, s.id).await.jump_session_id, Some(bastion.id));
    // Changing only the user moves nothing and sends nothing new.
    core.sessions
        .set_folder_defaults(
            ctx,
            folder.id,
            FolderDefaults {
                username: Some("alice".into()),
                jump_session_id: Some(bastion.id),
                ..FolderDefaults::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn folder_defaults_are_checked_audited_and_refused_by_the_read_only_lock() {
    let core = core().await;
    let ctx = &core.ctx();
    let folder = core.sessions.create_folder(ctx, "Lab", None).await.unwrap();
    // Checked like a session's own values.
    let long = "x".repeat(101);
    let err = core
        .sessions
        .set_folder_defaults(
            ctx,
            folder.id,
            FolderDefaults {
                username: Some(long),
                ..FolderDefaults::default()
            },
        )
        .await;
    assert!(matches!(err, Err(CoreError::InvalidInput(_))), "{err:?}");
    let err = core
        .sessions
        .set_folder_defaults(
            ctx,
            folder.id,
            FolderDefaults {
                jump_session_id: Some(Uuid::new_v4()),
                ..FolderDefaults::default()
            },
        )
        .await;
    assert!(matches!(err, Err(CoreError::InvalidInput(_))), "{err:?}");
    let err = core
        .sessions
        .set_folder_defaults(
            ctx,
            folder.id,
            FolderDefaults {
                auth: Some(SessionAuth::Password {
                    password_id: Some(SecretId(Uuid::new_v4())),
                }),
                ..FolderDefaults::default()
            },
        )
        .await;
    assert!(matches!(err, Err(CoreError::InvalidInput(_))), "{err:?}");
    // Tidied: tags without repeats, sorted; "no label" means "not set".
    let saved = core
        .sessions
        .set_folder_defaults(
            ctx,
            folder.id,
            FolderDefaults {
                username: Some("  alice ".into()),
                environment: Some(Environment::None),
                tags: vec!["web".into(), " Lab".into(), "WEB".into()],
                ..FolderDefaults::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(saved.defaults.username.as_deref(), Some("alice"));
    assert_eq!(saved.defaults.environment, None);
    assert_eq!(saved.defaults.tags, vec!["Lab".to_owned(), "web".to_owned()]);
    let entries = audit(&core).await;
    let entry = entries
        .iter()
        .find(|e| e.action == "Changed the defaults of folder 'Lab'")
        .unwrap();
    let detail = entry.detail.as_deref().unwrap();
    assert!(detail.contains("user: not set -> alice"), "{detail}");
    assert!(detail.contains("tags: none -> Lab, web"), "{detail}");
    assert!(detail.contains("0 sessions affected"), "{detail}");

    // The read-only lock refuses folder default edits like any other edit.
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let err = core
        .sessions
        .set_folder_defaults(ctx, folder.id, FolderDefaults::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    assert_eq!(
        core.sessions.folders(ctx).await.unwrap()[0]
            .defaults
            .username
            .as_deref(),
        Some("alice")
    );
}

#[tokio::test]
async fn a_folder_jump_host_never_loops_and_reachability_checks_it_first() {
    let core = core().await;
    let ctx = &core.ctx();
    let dmz = core.sessions.create_folder(ctx, "DMZ", None).await.unwrap();
    let inner = core
        .sessions
        .create(
            ctx,
            SessionInput {
                auth: SessionAuth::Agent,
                ..in_folder("inner bastion", "inner.example.org", dmz.id)
            },
        )
        .await
        .unwrap();
    let app = core
        .sessions
        .create(
            ctx,
            SessionInput {
                auth: SessionAuth::Agent,
                ..in_folder("app", "app.internal.test", dmz.id)
            },
        )
        .await
        .unwrap();
    set_defaults(
        &core,
        dmz.id,
        FolderDefaults {
            jump_session_id: Some(inner.id),
            ..FolderDefaults::default()
        },
    )
    .await;
    // The jump host in its own folder goes direct; the others go through it.
    assert_eq!(get(&core, inner.id).await.jump_session_id, None);
    assert_eq!(get(&core, app.id).await.jump_session_id, Some(inner.id));
    let spec = core.store.session_spec(ctx, app.id).await.unwrap().unwrap();
    assert_eq!(spec.jump.unwrap().id, inner.id);

    // QL-04: reachability checks the first jump host for a session behind one.
    core.reachability.set_watched([app.id]);
    let states = core.reachability.check_once().await.unwrap();
    let state = states.iter().find(|s| s.session_id == app.id).unwrap();
    assert_eq!(state.via.as_deref(), Some("inner bastion"));

    // The inner jump host told to go through the app (which goes through it): refused.
    let mut looping = inner.input();
    looping.jump_session_id = Some(app.id);
    let err = core.sessions.update(ctx, inner.id, looping).await;
    assert!(matches!(err, Err(CoreError::InvalidInput(_))), "{err:?}");
    // A folder default that would make a loop is refused too.
    let other = core.sessions.create_folder(ctx, "Other", None).await.unwrap();
    let out = core
        .sessions
        .create(
            ctx,
            SessionInput {
                auth: SessionAuth::Agent,
                jump_session_id: Some(app.id),
                ..in_folder("out", "out.example.org", other.id)
            },
        )
        .await
        .unwrap();
    let mut inner_moved = get(&core, inner.id).await.input();
    inner_moved.jump_session_id = Some(out.id);
    let err = core.sessions.update(ctx, inner.id, inner_moved).await;
    assert!(matches!(err, Err(CoreError::InvalidInput(_))), "{err:?}");

    // Deleting the folder's jump host leaves its sessions to the folders above (here: direct).
    core.sessions.delete(ctx, inner.id).await.unwrap();
    assert_eq!(get(&core, app.id).await.jump_session_id, None);
    assert_eq!(
        core.sessions.folders(ctx).await.unwrap()[0].defaults.jump_session_id,
        None
    );
}

#[tokio::test]
async fn an_import_into_a_folder_takes_its_user_label_and_key() {
    let core = core().await;
    let ctx = &core.ctx();
    let k = key(&core, "customer key").await;
    let folder = core.sessions.create_folder(ctx, "Customer", None).await.unwrap();
    set_defaults(
        &core,
        folder.id,
        FolderDefaults {
            username: Some("alice".into()),
            auth: Some(SessionAuth::Key {
                key_id: Some(k),
                passphrase_id: None,
            }),
            environment: Some(Environment::Prod),
            ..FolderDefaults::default()
        },
    )
    .await;
    let csv =
        "name,host,user,auth,folder\nweb01,web01.example.com,,password,Site 1\ndb01,db01.example.com,bob,agent,\n";
    let preview = core
        .import
        .preview(ctx, ImportSource::Csv, Some("list.csv".into()), import::csv::parse(csv))
        .await
        .unwrap();
    let rows: Vec<usize> = preview.rows.iter().map(|r| r.index).collect();
    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows,
                folder_id: Some(folder.id),
                add_keys: false,
                keep_startup: vec![],
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, 2, "{:?}", report.problems);
    let all = core.sessions.list(ctx, &Default::default()).await.unwrap();
    let web = all.iter().find(|s| s.name == "web01").unwrap();
    // In a new subfolder of the chosen one: the folder's user, key and label apply.
    assert_ne!(web.folder_id, Some(folder.id));
    assert_eq!(web.username.as_deref(), Some("alice"));
    assert_eq!(web.own.auth, SessionAuth::Folder);
    assert!(matches!(web.auth, SessionAuth::Key { key_id: Some(id), .. } if id == k));
    assert_eq!(web.environment, Environment::Prod);
    // The source's own values win.
    let db = all.iter().find(|s| s.name == "db01").unwrap();
    assert_eq!(db.username.as_deref(), Some("bob"));
    assert_eq!(db.auth, SessionAuth::Agent);
    assert_eq!(db.environment, Environment::Prod);
}

#[tokio::test]
async fn an_imported_session_never_takes_a_folders_vault_password_without_asking() {
    let core = core().await;
    let ctx = &core.ctx();
    let root = existing(&core, "customer root").await;
    let folder = core.sessions.create_folder(ctx, "Customer", None).await.unwrap();
    set_defaults(
        &core,
        folder.id,
        FolderDefaults {
            auth: Some(password_login(root)),
            ..FolderDefaults::default()
        },
    )
    .await;
    let csv = "name,host,user\nweb01,web01.example.com,alice\n";
    let preview = core
        .import
        .preview(ctx, ImportSource::Csv, None, import::csv::parse(csv))
        .await
        .unwrap();
    core.import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: vec![0],
                folder_id: Some(folder.id),
                add_keys: false,
                keep_startup: vec![],
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    let all = core.sessions.list(ctx, &Default::default()).await.unwrap();
    assert_eq!(
        all[0].auth,
        SessionAuth::Password { password_id: None },
        "still asks at login"
    );
}

async fn export(core: &Core, dir: &Path) -> std::path::PathBuf {
    let path = dir.join(format!("export-{}.remotely", Uuid::new_v4().simple()));
    core.transfer
        .export(
            &core.ctx(),
            &path,
            ExportRequest {
                passphrase: pw(PASSPHRASE),
                include_known_hosts: false,
                include_secrets: true,
                vault_password: Some(pw(VAULT_PASSWORD)),
            },
            &core.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    path
}

/// The file format an export says (its envelope's `version`), read without the passphrase.
fn format_of(path: &Path) -> u64 {
    let envelope: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    envelope["version"].as_u64().unwrap()
}

#[tokio::test]
async fn an_export_says_format_2_only_when_it_uses_folder_defaults() {
    let core = core().await;
    let ctx = &core.ctx();
    let dir = temp_folder("folder-defaults-format");
    let folder = core.sessions.create_folder(ctx, "Customer", None).await.unwrap();
    let s = core
        .sessions
        .create(
            ctx,
            SessionInput {
                username: Some("alice".into()),
                auth: SessionAuth::Agent,
                ..in_folder("web01", "web01.example.com", folder.id)
            },
        )
        .await
        .unwrap();
    // Nothing from QL-16 in it: 0.4.x reads it whole, so it says the format 0.4.x knows.
    assert_eq!(
        format_of(&export(&core, &dir).await),
        u64::from(remotely_core::transfer::FORMAT_VERSION_PLAIN)
    );
    // A session that takes its login from its folders would lose it on 0.4.x: format 2, which 0.4.x refuses.
    let mut from_folder = s.input();
    from_folder.auth = SessionAuth::Folder;
    core.sessions.update(ctx, s.id, from_folder).await.unwrap();
    assert_eq!(
        format_of(&export(&core, &dir).await),
        u64::from(remotely_core::transfer::FORMAT_VERSION)
    );
    // So does a folder with defaults.
    let mut own = get(&core, s.id).await.input();
    own.auth = SessionAuth::Agent;
    core.sessions.update(ctx, s.id, own).await.unwrap();
    set_defaults(
        &core,
        folder.id,
        FolderDefaults {
            environment: Some(Environment::Prod),
            ..FolderDefaults::default()
        },
    )
    .await;
    let path = export(&core, &dir).await;
    assert_eq!(format_of(&path), 2);
    // Either opens here.
    let preview = core
        .transfer
        .open(ctx, &path, pw(PASSPHRASE), &core.vault)
        .await
        .unwrap();
    assert_eq!(preview.folder_defaults.len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

fn commit_all(
    preview: &remotely_core::transfer::TransferPreview,
    folder_defaults: Vec<ItemChoice>,
    vault_password: Option<&str>,
) -> TransferCommit {
    TransferCommit {
        preview_id: preview.id,
        sessions: vec![],
        known_hosts: vec![],
        secrets: vec![],
        favourites: vec![],
        keep_startup: vec![],
        keep_forwards: vec![],
        vault_password: vault_password.map(pw),
        folder_defaults,
        groups: vec![],
        catalog: Default::default(),
    }
}

#[tokio::test]
async fn folder_defaults_go_with_an_export_and_sessions_resolve_the_same_on_the_other_laptop() {
    let a = core().await;
    let ctx = &a.ctx();
    let k = a
        .vault
        .add(
            ctx,
            SecretKind::PrivateKey,
            "customer key",
            pw(&common::fake_private_key()),
        )
        .await
        .unwrap()
        .id;
    let bastion = a
        .sessions
        .create(
            ctx,
            SessionInput {
                auth: SessionAuth::Agent,
                ..session("bastion", "bastion.example.org")
            },
        )
        .await
        .unwrap();
    let customer = a.sessions.create_folder(ctx, "Customer A", None).await.unwrap();
    let site = a
        .sessions
        .create_folder(ctx, "Site 1", Some(customer.id))
        .await
        .unwrap();
    set_defaults(
        &a,
        customer.id,
        FolderDefaults {
            username: Some("alice".into()),
            auth: Some(SessionAuth::Key {
                key_id: Some(k),
                passphrase_id: None,
            }),
            jump_session_id: Some(bastion.id),
            environment: Some(Environment::Prod),
            tags: vec!["acme".into()],
            ..FolderDefaults::default()
        },
    )
    .await;
    set_defaults(
        &a,
        site.id,
        FolderDefaults {
            jump_direct: true,
            ..FolderDefaults::default()
        },
    )
    .await;
    a.sessions
        .create(ctx, in_folder("web01", "web01.example.com", customer.id))
        .await
        .unwrap();
    a.sessions
        .create(ctx, in_folder("db01", "db01.example.com", site.id))
        .await
        .unwrap();
    let dir = temp_folder("folder-defaults");
    let path = export(&a, &dir).await;

    let b = core().await;
    let preview = b
        .transfer
        .open(&b.ctx(), &path, pw(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    assert_eq!(preview.folder_defaults.len(), 2);
    assert!(preview.folder_defaults.iter().all(|f| f.status == ItemStatus::New));
    let web_row = preview.sessions.iter().find(|s| s.name == "web01").unwrap();
    assert!(
        web_row.detail.starts_with("alice@web01.example.com"),
        "{}",
        web_row.detail
    );
    assert!(web_row.detail.ends_with(", prod"), "{}", web_row.detail);
    assert!(
        web_row.notes.iter().any(|n| n.contains("from folder 'Customer A'")),
        "{:?}",
        web_row.notes
    );
    let report = b
        .transfer
        .commit(
            &b.ctx(),
            commit_all(&preview, vec![], None),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert_eq!(report.folder_defaults.added, 2, "{:?}", report.problems);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let on_b = b.sessions.list(&b.ctx(), &Default::default()).await.unwrap();
    let web = on_b.iter().find(|s| s.name == "web01").unwrap();
    let db = on_b.iter().find(|s| s.name == "db01").unwrap();
    let bastion_b = on_b.iter().find(|s| s.name == "bastion").unwrap();
    assert_eq!(
        web.own.auth,
        SessionAuth::Folder,
        "the session still takes its login from its folder"
    );
    assert_eq!(web.username.as_deref(), Some("alice"));
    assert!(matches!(web.auth, SessionAuth::Key { key_id: Some(_), .. }));
    assert_eq!(web.jump_session_id, Some(bastion_b.id));
    assert_eq!(web.environment, Environment::Prod);
    assert_eq!(web.tags, vec!["acme".to_owned()]);
    assert_eq!(db.jump_session_id, None, "Site 1 goes direct");
    assert_eq!(db.environment, Environment::Prod);

    // Opened again: the same defaults here. Changed here: a choice, keeping this laptop's by default.
    let again = b
        .transfer
        .open(&b.ctx(), &path, pw(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    assert!(
        again.folder_defaults.iter().all(|f| f.status == ItemStatus::Same),
        "{:?}",
        again.folder_defaults
    );
    b.transfer.close(again.id);
    let customer_b = b
        .sessions
        .folders(&b.ctx())
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.name == "Customer A")
        .unwrap();
    let mut changed = customer_b.defaults.clone();
    changed.username = Some("bob".into());
    changed.environment = Some(Environment::Staging);
    set_defaults(&b, customer_b.id, changed).await;
    let preview = b
        .transfer
        .open(&b.ctx(), &path, pw(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    let row = preview
        .folder_defaults
        .iter()
        .find(|f| f.name == "Customer A")
        .unwrap()
        .clone();
    assert_eq!(row.status, ItemStatus::Conflict);
    assert_eq!(row.default_action, ItemAction::Skip);
    b.transfer
        .commit(
            &b.ctx(),
            commit_all(&preview, vec![], None),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    let web = b.sessions.get(&b.ctx(), web.id).await.unwrap();
    assert_eq!(web.username.as_deref(), Some("bob"), "kept this laptop's");
    let preview = b
        .transfer
        .open(&b.ctx(), &path, pw(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    let row = preview.folder_defaults.iter().find(|f| f.name == "Customer A").unwrap();
    let choice = vec![ItemChoice {
        index: row.index,
        action: ItemAction::Replace,
    }];
    let report = b
        .transfer
        .commit(
            &b.ctx(),
            commit_all(&preview, choice, None),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert_eq!(report.folder_defaults.replaced, 1, "{:?}", report.problems);
    let web = b.sessions.get(&b.ctx(), web.id).await.unwrap();
    assert_eq!(web.username.as_deref(), Some("alice"));
    assert_eq!(web.environment, Environment::Prod);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_import_whose_folder_gives_a_password_already_here_asks_for_the_vault_password() {
    let a = core().await;
    let ctx = &a.ctx();
    let root = existing(&a, "customer root").await;
    let folder = a.sessions.create_folder(ctx, "Customer", None).await.unwrap();
    set_defaults(
        &a,
        folder.id,
        FolderDefaults {
            auth: Some(password_login(root)),
            ..FolderDefaults::default()
        },
    )
    .await;
    a.sessions
        .create_with(
            ctx,
            in_folder("web01", "web01.example.com", folder.id),
            Some(&pw(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    let dir = temp_folder("folder-defaults-reauth");
    let path = dir.join("no-secrets.remotely");
    a.transfer
        .export(
            ctx,
            &path,
            ExportRequest {
                passphrase: pw(PASSPHRASE),
                include_known_hosts: false,
                include_secrets: false,
                vault_password: None,
            },
            &a.vault,
            "Remotely test",
        )
        .await
        .unwrap();

    // The other laptop has a password with that label: the file's folder would give it to web01's host.
    let b = core().await;
    existing(&b, "customer root").await;
    let preview = b
        .transfer
        .open(&b.ctx(), &path, pw(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    let err = b
        .transfer
        .commit(
            &b.ctx(),
            commit_all(&preview, vec![], None),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await;
    assert!(reauth_required(&err), "{err:?}");
    let report = b
        .transfer
        .commit(
            &b.ctx(),
            commit_all(&preview, vec![], Some(VAULT_PASSWORD)),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let web = b.sessions.list(&b.ctx(), &Default::default()).await.unwrap();
    assert!(matches!(web[0].auth, SessionAuth::Password { password_id: Some(_) }));
    let _ = std::fs::remove_dir_all(dir);
}

/// A terminal and a Compare run on the local test server log in with the user and vault password the session's
/// folder sets (the session sets neither).
#[tokio::test]
async fn a_terminal_and_a_compare_run_log_in_as_the_folder_says() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    let ctx = &core.ctx();
    let secret = core
        .vault
        .add(ctx, SecretKind::Password, "lab alice", pw(&password))
        .await
        .unwrap()
        .id;
    let folder = core.sessions.create_folder(ctx, "Lab", None).await.unwrap();
    core.sessions
        .set_folder_defaults(
            ctx,
            folder.id,
            FolderDefaults {
                username: Some("alice".into()),
                auth: Some(password_login(secret)),
                environment: Some(Environment::Lab),
                ..FolderDefaults::default()
            },
        )
        .await
        .unwrap();
    let s = core
        .sessions
        .create(
            ctx,
            SessionInput {
                port: server.port(),
                ..in_folder("lab box", "127.0.0.1", folder.id)
            },
        )
        .await
        .unwrap();
    core.known_hosts
        .trust(
            ctx,
            &HostKey {
                host: "127.0.0.1".into(),
                port: server.port(),
                key_type: "ssh-ed25519".into(),
                fingerprint: server.host_key_fingerprint(),
            },
            None,
        )
        .await
        .unwrap();

    let mut handle = core
        .terminals
        .open(ctx, s.id, PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    let mut seen = String::new();
    timeout(Duration::from_secs(15), async {
        while !seen.contains("Welcome, alice") {
            tokio::select! {
                Some(chunk) = handle.output.recv() => seen.push_str(&String::from_utf8_lossy(&chunk)),
                Some(event) = handle.events.recv() => {
                    if let TerminalEvent::HostKeyUnknown { .. } = event {
                        panic!("the host key was trusted");
                    }
                }
            }
        }
    })
    .await
    .expect("the terminal logged in");
    assert!(
        server.log().contains(&"password alice ok".to_owned()),
        "{:?}",
        server.log()
    );
    core.terminals.close(handle.id).await;

    let mut events = core.jobs.subscribe();
    let run = Command::RemoteExec {
        targets: vec![TargetRef::Session { session_id: s.id }],
        script: "whoami".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Default::default(),
    };
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bus.submit(ctx, run).await.unwrap() else {
        panic!("a read-only command on a Lab session runs");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    let targets = core.store.job_targets(ctx, job_id).await.unwrap();
    assert_eq!(targets[0].output.as_deref().map(str::trim), Some("alice"));
}
