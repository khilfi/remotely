//! SS-01 session library and SS-06 environment labels, end to end with the app's own vault (fake
//! DPAPI) and the fake remote adapter. No real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{fake_private_key, wait_finished, Setup};
use remotely_core::command_bus::{ApprovalAnswers, Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionColor, SessionFilter, SessionInput};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::{Core, CoreError};
use uuid::Uuid;

async fn core() -> Core {
    Setup::new(FakeVmware::default()).with_real_vault().build().await
}

fn session(name: &str, host: &str) -> SessionInput {
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

async fn secret(core: &Core, kind: SecretKind, label: &str, value: &str) -> remotely_core::vault::SecretId {
    core.vault
        .add(&core.ctx, kind, label, SecretString::new(value))
        .await
        .unwrap()
        .id
}

async fn last_audit(core: &Core) -> remotely_core::store::AuditEntry {
    core.store.recent_audit(&core.ctx, 1).await.unwrap().remove(0)
}

#[tokio::test]
async fn a_session_stores_where_and_how_to_connect() {
    let core = core().await;
    let ctx = &core.ctx;
    let password = secret(&core, SecretKind::Password, "web01 alice", "pw-value-1").await;
    let bastion = core
        .sessions
        .create(ctx, session("bastion", "bastion.example.com"))
        .await
        .unwrap();
    let folder = core.sessions.create_folder(ctx, "Customer A", None).await.unwrap();

    let input = SessionInput {
        folder_id: Some(folder.id),
        port: 2222,
        auth: SessionAuth::Password {
            password_id: Some(password),
        },
        jump_session_id: Some(bastion.id),
        startup_command: Some("cd /srv/app\nexport TOKEN=abc123".into()),
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Staging,
        color: Some(SessionColor::Teal),
        tags: vec!["web".into(), "Customer-A".into()],
        ..session("web01", " web01.example.com ")
    };
    let web = core.sessions.create(ctx, input).await.unwrap();
    assert_eq!(web.host, "web01.example.com");
    assert_eq!(web.port, 2222);
    assert_eq!(web.username.as_deref(), Some("alice"));
    assert_eq!(web.folder_id, Some(folder.id));
    assert_eq!(web.jump_session_id, Some(bastion.id));
    assert_eq!(web.environment, Environment::Staging);
    assert_eq!(web.color, Some(SessionColor::Teal));
    assert_eq!(web.tags, ["Customer-A", "web"]);
    assert_eq!(web.protocol, "ssh");
    assert_eq!(
        web.auth,
        SessionAuth::Password {
            password_id: Some(password)
        }
    );
    assert_eq!(core.sessions.get(ctx, web.id).await.unwrap(), web);

    // The audit entry says what was created, never the secret or the startup command's text.
    let audit = last_audit(&core).await;
    assert_eq!(audit.event, "session_changed");
    assert_eq!(audit.action, "Created session 'web01'");
    let detail = audit.detail.unwrap();
    assert!(detail.contains("alice@web01.example.com:2222"), "{detail}");
    assert!(detail.contains("password from the vault"), "{detail}");
    assert!(detail.contains("via 'bastion'"), "{detail}");
    assert!(detail.contains("in folder 'Customer A'"), "{detail}");
    assert!(!detail.contains("abc123") && !detail.contains("pw-value-1"), "{detail}");
    assert!(audit.targets_json.contains("\"environment\":\"staging\""));

    // The vault knows the session uses its password.
    let list = core.vault.list(ctx).await.unwrap();
    assert_eq!(list[0].used_by, 1);
    // Tags are shared with VMs, counted per kind.
    let tags = core.store.list_tags(ctx).await.unwrap();
    assert!(tags.iter().all(|t| t.session_count == 1 && t.vm_count == 0));
}

#[tokio::test]
async fn keys_and_passphrases_must_be_vault_items_of_the_right_kind() {
    let core = core().await;
    let ctx = &core.ctx;
    let key = secret(&core, SecretKind::PrivateKey, "deploy key", &fake_private_key()).await;
    let phrase = secret(&core, SecretKind::Passphrase, "deploy key passphrase", "pass phrase").await;
    let password = secret(&core, SecretKind::Password, "root", "pw").await;

    let with_key = SessionInput {
        auth: SessionAuth::Key {
            key_id: Some(key),
            passphrase_id: Some(phrase),
        },
        ..session("db01", "db01.example.com")
    };
    let db = core.sessions.create(ctx, with_key).await.unwrap();
    assert_eq!(db.auth.credential_id(), Some(key));
    assert!(last_audit(&core)
        .await
        .detail
        .unwrap()
        .contains("key from the vault, with its passphrase"));

    let wrong_kind = [
        SessionAuth::Key {
            key_id: Some(password),
            passphrase_id: None,
        },
        SessionAuth::Key {
            key_id: Some(key),
            passphrase_id: Some(password),
        },
        SessionAuth::Password { password_id: Some(key) },
        SessionAuth::Password {
            password_id: Some(remotely_core::vault::SecretId(Uuid::new_v4())),
        },
    ];
    for auth in wrong_kind {
        let input = SessionInput {
            auth: auth.clone(),
            ..session("db02", "db02.example.com")
        };
        assert!(
            matches!(core.sessions.create(ctx, input).await, Err(CoreError::InvalidInput(_))),
            "{auth:?}"
        );
    }
}

#[tokio::test]
async fn deleting_a_secret_leaves_its_sessions_without_it_and_says_so() {
    let core = core().await;
    let ctx = &core.ctx;
    let password = secret(&core, SecretKind::Password, "web root", "pw").await;
    let input = SessionInput {
        auth: SessionAuth::Password {
            password_id: Some(password),
        },
        ..session("web01", "web01.example.com")
    };
    let web = core.sessions.create(ctx, input).await.unwrap();
    core.vault.delete(ctx, password).await.unwrap();
    let audit = last_audit(&core).await;
    assert_eq!(audit.action, "Deleted the password 'web root' from the vault");
    assert_eq!(audit.detail.as_deref(), Some("1 session: no longer have it"));
    assert_eq!(
        core.sessions.get(ctx, web.id).await.unwrap().auth,
        SessionAuth::Password { password_id: None }
    );
}

#[tokio::test]
async fn edits_are_audited_field_by_field_and_an_edit_that_changes_nothing_writes_nothing() {
    let core = core().await;
    let ctx = &core.ctx;
    let created = core
        .sessions
        .create(ctx, session("web01", "web01.example.com"))
        .await
        .unwrap();
    let audit_count = core.store.recent_audit(ctx, 100).await.unwrap().len();

    let same = SessionInput {
        name: "web01 ".into(),
        ..session("web01", "web01.example.com")
    };
    let unchanged = core.sessions.update(ctx, created.id, same).await.unwrap();
    assert_eq!(unchanged.updated_at, created.updated_at);
    assert_eq!(core.store.recent_audit(ctx, 100).await.unwrap().len(), audit_count);

    let edit = SessionInput {
        port: 2200,
        username: None,
        environment: Environment::Prod,
        startup_command: Some("export TOKEN=abc123".into()),
        startup_on_reconnect: false,
        prompt_hook: None,
        tags: vec!["web".into()],
        ..session("web01", "web01.example.com")
    };
    let edited = core.sessions.update(ctx, created.id, edit).await.unwrap();
    assert_eq!(edited.port, 2200);
    assert_eq!(edited.environment, Environment::Prod);
    let audit = last_audit(&core).await;
    assert_eq!(audit.action, "Changed session 'web01'");
    assert_eq!(
        audit.detail.as_deref(),
        Some("port: 22 -> 2200; user: alice -> none; environment: none -> prod; tags: none -> web; startup command added (rated High: other)")
    );
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn a_jump_host_must_be_another_session_and_never_lead_back() {
    let core = core().await;
    let ctx = &core.ctx;
    let a = core.sessions.create(ctx, session("a", "a.example.com")).await.unwrap();
    let b = core
        .sessions
        .create(
            ctx,
            SessionInput {
                jump_session_id: Some(a.id),
                ..session("b", "b.example.com")
            },
        )
        .await
        .unwrap();

    let via = |jump: Uuid| SessionInput {
        jump_session_id: Some(jump),
        ..session("a", "a.example.com")
    };
    // a via a, and a via b (which goes via a): both refused.
    for jump in [a.id, b.id] {
        assert!(matches!(
            core.sessions.update(ctx, a.id, via(jump)).await,
            Err(CoreError::InvalidInput(_))
        ));
    }
    assert!(matches!(
        core.sessions.update(ctx, a.id, via(Uuid::new_v4())).await,
        Err(CoreError::InvalidInput(_))
    ));

    // Deleting a jump host leaves the sessions behind it without one.
    core.sessions.delete(ctx, a.id).await.unwrap();
    assert_eq!(core.sessions.get(ctx, b.id).await.unwrap().jump_session_id, None);
    let audit = last_audit(&core).await;
    assert_eq!(audit.action, "Deleted session 'a'");
    assert!(audit.detail.unwrap().contains("1 session used it as its jump host"));
    assert!(matches!(
        core.sessions.get(ctx, a.id).await,
        Err(CoreError::UnknownTarget(_))
    ));
}

#[tokio::test]
async fn search_matches_text_tags_labels_and_folders_with_their_subfolders() {
    let core = core().await;
    let ctx = &core.ctx;
    let customer = core.sessions.create_folder(ctx, "Customer A", None).await.unwrap();
    let site = core
        .sessions
        .create_folder(ctx, "Site 1", Some(customer.id))
        .await
        .unwrap();
    let make = |name: &str, folder, env, tags: &[&str]| SessionInput {
        folder_id: folder,
        environment: env,
        tags: tags.iter().map(|t| t.to_string()).collect(),
        ..session(name, &format!("{name}.example.com"))
    };
    for input in [
        make("web01", Some(customer.id), Environment::Prod, &["web"]),
        make("db01", Some(site.id), Environment::Prod, &["db"]),
        make("lab01", None, Environment::Lab, &["web"]),
    ] {
        core.sessions.create(ctx, input).await.unwrap();
    }
    let names = |filter: SessionFilter| {
        let core = &core;
        async move {
            core.sessions
                .list(&core.ctx, &filter)
                .await
                .unwrap()
                .into_iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(names(SessionFilter::default()).await, ["db01", "lab01", "web01"]);
    assert_eq!(
        names(SessionFilter {
            text: "DB01.example".into(),
            ..Default::default()
        })
        .await,
        ["db01"]
    );
    assert_eq!(
        names(SessionFilter {
            tags: vec!["WEB".into()],
            ..Default::default()
        })
        .await,
        ["lab01", "web01"]
    );
    assert_eq!(
        names(SessionFilter {
            environments: vec![Environment::Prod],
            ..Default::default()
        })
        .await,
        ["db01", "web01"]
    );
    assert_eq!(
        names(SessionFilter {
            folder_id: Some(customer.id),
            ..Default::default()
        })
        .await,
        ["db01", "web01"],
        "a folder includes its subfolders"
    );
    assert_eq!(
        names(SessionFilter {
            folder_id: Some(site.id),
            tags: vec!["web".into()],
            ..Default::default()
        })
        .await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn folders_nest_rename_move_and_delete_without_losing_sessions() {
    let core = core().await;
    let ctx = &core.ctx;
    let a = core.sessions.create_folder(ctx, "A", None).await.unwrap();
    let b = core.sessions.create_folder(ctx, "B", Some(a.id)).await.unwrap();
    let c = core.sessions.create_folder(ctx, "C", Some(b.id)).await.unwrap();
    assert!(matches!(
        core.sessions.create_folder(ctx, "b", Some(a.id)).await,
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        core.sessions.create_folder(ctx, "  ", None).await,
        Err(CoreError::InvalidInput(_))
    ));

    // A folder can't move into itself or below itself.
    for target in [a.id, b.id, c.id] {
        assert!(matches!(
            core.sessions.move_folder(ctx, a.id, Some(target)).await,
            Err(CoreError::InvalidInput(_))
        ));
    }
    let moved = core.sessions.move_folder(ctx, c.id, None).await.unwrap();
    assert_eq!(moved.parent_id, None);
    let renamed = core.sessions.rename_folder(ctx, b.id, "Bee").await.unwrap();
    assert_eq!(renamed.name, "Bee");

    let s = core
        .sessions
        .create(
            ctx,
            SessionInput {
                folder_id: Some(b.id),
                ..session("web01", "web01.example.com")
            },
        )
        .await
        .unwrap();
    core.sessions.move_folder(ctx, c.id, Some(b.id)).await.unwrap();

    // Deleting B moves its session and its subfolder up into A.
    core.sessions.delete_folder(ctx, b.id).await.unwrap();
    assert_eq!(core.sessions.get(ctx, s.id).await.unwrap().folder_id, Some(a.id));
    let folders = core.sessions.folders(ctx).await.unwrap();
    assert_eq!(folders.len(), 2);
    assert_eq!(folders.iter().find(|f| f.id == c.id).unwrap().parent_id, Some(a.id));
    let audit = last_audit(&core).await;
    assert_eq!(audit.action, "Deleted folder 'Bee'");
    assert_eq!(
        audit.detail.as_deref(),
        Some("1 session and 1 folder moved to folder 'A'")
    );

    // Sessions move between folders, or to the top level.
    core.sessions.move_to(ctx, &[s.id], None).await.unwrap();
    assert_eq!(core.sessions.get(ctx, s.id).await.unwrap().folder_id, None);
    assert_eq!(last_audit(&core).await.action, "Moved session 'web01' to the top level");
    assert!(matches!(
        core.sessions.move_to(ctx, &[s.id], Some(Uuid::new_v4())).await,
        Err(CoreError::UnknownTarget(_))
    ));
}

#[tokio::test]
async fn duplicating_copies_everything_but_the_name() {
    let core = core().await;
    let ctx = &core.ctx;
    let original = core
        .sessions
        .create(
            ctx,
            SessionInput {
                environment: Environment::Prod,
                tags: vec!["web".into()],
                ..session("web01", "web01.example.com")
            },
        )
        .await
        .unwrap();
    let copy = core.sessions.duplicate(ctx, original.id).await.unwrap();
    assert_ne!(copy.id, original.id);
    assert_eq!(copy.name, "web01 (copy)");
    assert_eq!(copy.host, original.host);
    assert_eq!(copy.environment, Environment::Prod);
    assert_eq!(copy.tags, original.tags);
}

#[tokio::test]
async fn deleting_sessions_cleans_up_tags_left_on_nothing() {
    let core = core().await;
    let ctx = &core.ctx;
    let s = core
        .sessions
        .create(
            ctx,
            SessionInput {
                tags: vec!["only-here".into()],
                ..session("web01", "web01.example.com")
            },
        )
        .await
        .unwrap();
    assert_eq!(core.store.list_tags(ctx).await.unwrap().len(), 1);
    core.sessions.delete(ctx, s.id).await.unwrap();
    assert!(core.store.list_tags(ctx).await.unwrap().is_empty());
}

// ---- SS-06: session targets carry their environment label to the policy engine ---------------

fn exec(script: &str, sessions: &[Uuid]) -> Command {
    Command::RemoteExec {
        targets: sessions
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect(),
        script: script.into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Default::default(),
    }
}

#[tokio::test]
async fn a_prod_session_raises_the_tier_and_a_lab_one_does_not() {
    let core = core().await;
    let ctx = &core.ctx;
    let mut events = core.jobs.subscribe();
    let lab = core
        .sessions
        .create(
            ctx,
            SessionInput {
                environment: Environment::Lab,
                ..session("lab01", "lab01.example.com")
            },
        )
        .await
        .unwrap();
    let prod = core
        .sessions
        .create(
            ctx,
            SessionInput {
                environment: Environment::Prod,
                ..session("prod01", "prod01.example.com")
            },
        )
        .await
        .unwrap();

    // A read-only command on a Lab session is Low: it runs straight away.
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bus.submit(ctx, exec("uptime", &[lab.id])).await.unwrap()
    else {
        panic!("read-only on Lab is Low");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);

    // The same command on a Prod session moves up to Medium.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(ctx, exec("uptime", &[prod.id])).await.unwrap()
    else {
        panic!("Prod raises the tier");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(request.targets[0].environment, Environment::Prod);
    assert!(request
        .reasons
        .iter()
        .any(|r| r == "a target is labelled Prod: low -> medium"));
    core.bus.cancel_approval(request.id).await.unwrap();

    // One Prod target among several is enough.
    let SubmitOutcome::NeedsApproval { request } =
        core.bus.submit(ctx, exec("uptime", &[lab.id, prod.id])).await.unwrap()
    else {
        panic!("a Prod target raises the tier");
    };
    assert_eq!(request.tier, Tier::Medium);
    core.bus.cancel_approval(request.id).await.unwrap();

    // A dangerous command on Prod goes from High to Critical, so it asks for the vault password.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(ctx, exec("reboot", &[prod.id])).await.unwrap()
    else {
        panic!("dangerous on Prod");
    };
    assert_eq!(request.tier, Tier::Critical);
    assert_eq!(request.steps.last(), Some(&ApprovalStep::VaultReauth));
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(1),
        reason: Some("CHG-1234".into()),
        vault_password: Some(SecretString::new(common::VAULT_PASSWORD)),
        ..Default::default()
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
}

#[tokio::test]
async fn relabelling_a_session_changes_the_tier_of_the_next_command_and_is_audited() {
    let core = core().await;
    let ctx = &core.ctx;
    let s = core
        .sessions
        .create(
            ctx,
            SessionInput {
                environment: Environment::Prod,
                ..session("web01", "web01.example.com")
            },
        )
        .await
        .unwrap();
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(ctx, exec("uptime", &[s.id])).await.unwrap() else {
        panic!("Prod raises the tier");
    };
    core.bus.cancel_approval(request.id).await.unwrap();

    core.sessions
        .update(
            ctx,
            s.id,
            SessionInput {
                environment: Environment::Lab,
                ..session("web01", "web01.example.com")
            },
        )
        .await
        .unwrap();
    let audit = last_audit(&core).await;
    assert_eq!(audit.detail.as_deref(), Some("environment: prod -> lab"));

    assert!(matches!(
        core.bus.submit(ctx, exec("uptime", &[s.id])).await.unwrap(),
        SubmitOutcome::Queued { tier: Tier::Low, .. }
    ));
}

#[tokio::test]
async fn an_unknown_session_target_is_refused() {
    let core = core().await;
    assert!(matches!(
        core.bus.submit(&core.ctx, exec("uptime", &[Uuid::new_v4()])).await,
        Err(CoreError::UnknownTarget(_))
    ));
}
