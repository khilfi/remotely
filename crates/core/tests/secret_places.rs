//! SS-04, AP-06: a vault password goes, without the vault password being asked again, only where it already
//! goes: the host of a saved session that logs in with it, gives it to sudo, or was allowed to use it. Anywhere
//! else — another session, a moved session, a quick connection, a container host's sudo, a Compare run's sudo —
//! needs the vault password, and every answer is audited. Approval rules that get looser ask too. End to end
//! with the app's own vault (fake DPAPI) and the fake remote adapter: no real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{fake_private_key, Setup, VAULT_PASSWORD};
use remotely_core::adapters::containers::EngineKind;
use remotely_core::adapters::remote::PtySize;
use remotely_core::command_bus::{ApprovalAnswers, Command, SubmitOutcome};
use remotely_core::containers::{MarkInput, SudoMode};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::FakeVmware;
use remotely_core::policy::{ApprovalStep, PolicyRules};
use remotely_core::sessions::{SessionAuth, SessionInput, SessionRecord};
use remotely_core::terminal::quick::QuickConnect;
use remotely_core::vault::{SecretId, SecretKind, SecretString, UnlockMethod, REAUTH_GRACE};
use remotely_core::{Core, CoreError};

const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

fn pw(text: &str) -> SecretString {
    SecretString::new(text)
}

/// Asks every time: no grace period after a right answer (that has its own test).
async fn core() -> Core {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    core.secret_bindings().set_grace(Duration::ZERO);
    core
}

/// A password that was in the vault before this run (not just added on the Vault page), like every customer
/// password an attacker at an unlocked PC would be after.
async fn existing(core: &Core, label: &str) -> SecretId {
    core.vault
        .vault()
        .put(&core.ctx, SecretKind::Password, label, pw(&format!("{label}-value-1")))
        .await
        .unwrap()
}

fn session(name: &str, host: &str, auth: SessionAuth) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: Some("alice".into()),
        auth,
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

fn with_password(name: &str, host: &str, id: SecretId) -> SessionInput {
    session(name, host, SessionAuth::Password { password_id: Some(id) })
}

fn reauth_required(result: &Result<impl std::fmt::Debug, CoreError>) -> bool {
    matches!(result, Err(CoreError::ReauthRequired { .. }))
}

async fn saved(core: &Core, input: SessionInput) -> SessionRecord {
    core.sessions
        .create_with(&core.ctx, input, Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap()
}

async fn audit_events(core: &Core) -> Vec<remotely_core::store::AuditEntry> {
    core.store.recent_audit(&core.ctx, 200).await.unwrap()
}

#[tokio::test]
async fn a_password_sent_to_a_new_host_needs_the_vault_password_and_each_answer_is_audited() {
    let core = core().await;
    let ctx = &core.ctx;
    let root = existing(&core, "customer root").await;

    let err = core
        .sessions
        .create(ctx, with_password("evil", "attacker.example.org", root))
        .await;
    assert!(reauth_required(&err), "{err:?}");
    let message = err.unwrap_err().to_string();
    assert!(message.contains("password 'customer root'"), "{message}");
    assert!(message.contains("attacker.example.org:22"), "{message}");
    assert!(!message.contains("customer root-value-1"));

    let wrong = core
        .sessions
        .create_with(
            ctx,
            with_password("evil", "attacker.example.org", root),
            Some(&pw("not it at all")),
        )
        .await;
    assert!(matches!(wrong, Err(CoreError::WrongVaultPassword)), "{wrong:?}");
    let failed = audit_events(&core).await;
    let failed = failed.iter().find(|e| e.event == "vault_auth_failed").unwrap();
    assert_eq!(failed.action, "Failed to create session 'evil'");
    assert!(
        core.sessions.list(ctx, &Default::default()).await.unwrap().is_empty(),
        "nothing was saved"
    );

    let web = saved(&core, with_password("web01", "web01.example.com", root)).await;
    let created = audit_events(&core).await;
    let created = created.iter().find(|e| e.event == "session_changed").unwrap();
    assert!(
        created
            .detail
            .as_deref()
            .unwrap()
            .contains("the vault password was asked again (AP-06)"),
        "{created:?}"
    );

    // Where it already goes, nothing is asked: another session to the same host and port, or a copy.
    core.sessions
        .create(ctx, with_password("web01 again", "WEB01.example.com", root))
        .await
        .unwrap();
    core.sessions.duplicate(ctx, web.id).await.unwrap();
    // Another port is another place.
    let mut other_port = with_password("web01 ssh2", "web01.example.com", root);
    other_port.port = 2222;
    assert!(reauth_required(&core.sessions.create(ctx, other_port).await));
}

#[tokio::test]
async fn a_new_secret_goes_to_its_first_session_without_asking() {
    let core = core().await;
    let ctx = &core.ctx;
    // The session editor's "new password": added on the spot, then picked for the session being saved.
    let fresh = core
        .vault
        .add(ctx, SecretKind::Password, "db01 alice", pw("fresh-value-1"))
        .await
        .unwrap()
        .id;
    core.sessions
        .create(ctx, with_password("db01", "db01.example.com", fresh))
        .await
        .unwrap();
    // Its second place asks like any other.
    let second = core
        .sessions
        .create(ctx, with_password("db02", "db02.example.com", fresh))
        .await;
    assert!(reauth_required(&second), "{second:?}");
}

#[tokio::test]
async fn moving_a_session_that_sends_a_vault_password_asks_first() {
    let core = core().await;
    let ctx = &core.ctx;
    let root = existing(&core, "web root").await;
    let web = saved(&core, with_password("web01", "web01.example.com", root)).await;

    // Everyday edits ask nothing.
    let mut renamed = web.input();
    renamed.name = "web01 (prod)".into();
    renamed.environment = Environment::Prod;
    core.sessions.update(ctx, web.id, renamed.clone()).await.unwrap();

    let mut moved = renamed.clone();
    moved.host = "attacker.example.org".into();
    assert!(reauth_required(&core.sessions.update(ctx, web.id, moved.clone()).await));
    let mut new_port = renamed.clone();
    new_port.port = 2200;
    assert!(reauth_required(&core.sessions.update(ctx, web.id, new_port).await));
    let after = core
        .sessions
        .update_with(ctx, web.id, moved, Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();
    assert_eq!(after.host, "attacker.example.org");

    // Pointing a session at another vault password asks too.
    let other = existing(&core, "db root").await;
    let mut swapped = after.input();
    swapped.auth = SessionAuth::Password {
        password_id: Some(other),
    };
    assert!(reauth_required(&core.sessions.update(ctx, web.id, swapped).await));

    // A session that sends no vault password moves freely.
    let agent = core
        .sessions
        .create(ctx, session("bastion", "bastion.example.com", SessionAuth::Agent))
        .await
        .unwrap();
    let mut agent_moved = agent.input();
    agent_moved.host = "bastion2.example.com".into();
    core.sessions.update(ctx, agent.id, agent_moved).await.unwrap();
}

#[tokio::test]
async fn keys_and_their_passphrases_never_leave_this_pc_so_they_never_ask() {
    let core = core().await;
    let ctx = &core.ctx;
    let key = core
        .vault
        .vault()
        .put(ctx, SecretKind::PrivateKey, "deploy key", pw(&fake_private_key()))
        .await
        .unwrap();
    let phrase = core
        .vault
        .vault()
        .put(
            ctx,
            SecretKind::Passphrase,
            "deploy key passphrase",
            pw("phrase-value-1"),
        )
        .await
        .unwrap();
    for host in ["app01.example.com", "app02.example.com", "203.0.113.20"] {
        core.sessions
            .create(
                ctx,
                session(
                    host,
                    host,
                    SessionAuth::Key {
                        key_id: Some(key),
                        passphrase_id: Some(phrase),
                    },
                ),
            )
            .await
            .unwrap();
    }
}

fn quick(host: &str, id: SecretId, vault_password: Option<&str>) -> QuickConnect {
    QuickConnect {
        host: format!("alice@{host}"),
        port: None,
        username: None,
        auth: SessionAuth::Password { password_id: Some(id) },
        password: None,
        save: None,
        vault_password: vault_password.map(pw),
    }
}

#[tokio::test]
async fn a_quick_connection_with_a_vault_password_for_a_new_host_asks_first() {
    let core = core().await;
    let ctx = &core.ctx;
    let root = existing(&core, "customer root").await;

    let err = core
        .terminals
        .quick_connect(ctx, quick("192.0.2.66", root, None), SIZE)
        .await
        .err()
        .expect("asked for the vault password");
    assert_eq!(err.code(), "reauth_required");
    assert!(core.terminals.open_ids().is_empty(), "no terminal opened");
    let wrong = core
        .terminals
        .quick_connect(ctx, quick("192.0.2.66", root, Some("guess-guess-guess")), SIZE)
        .await
        .err()
        .expect("a wrong password is refused");
    assert_eq!(wrong.code(), "wrong_vault_password");
    assert!(core.terminals.open_ids().is_empty());

    let opened = core
        .terminals
        .quick_connect(ctx, quick("192.0.2.66", root, Some(VAULT_PASSWORD)), SIZE)
        .await
        .unwrap();
    core.terminals.close(opened.handle.id).await;
    let entries = audit_events(&core).await;
    let entry = entries.iter().find(|e| e.event == "terminal_opened").unwrap();
    assert!(entry.detail.as_deref().unwrap().contains("asked again"), "{entry:?}");

    // To a host a saved session already sends it to, a quick connection asks nothing.
    saved(&core, with_password("web01", "192.0.2.10", root)).await;
    let opened = core
        .terminals
        .quick_connect(ctx, quick("192.0.2.10", root, None), SIZE)
        .await
        .unwrap();
    core.terminals.close(opened.handle.id).await;
}

#[tokio::test]
async fn a_container_hosts_sudo_password_for_a_new_host_asks_first() {
    let core = core().await;
    let ctx = &core.ctx;
    let login = existing(&core, "web login").await;
    let sudo = existing(&core, "customer root").await;
    let web = saved(&core, with_password("web01", "web01.example.com", login)).await;
    let marks = |password_id| {
        vec![MarkInput {
            engine: EngineKind::Docker,
            sudo: SudoMode::Password { password_id },
        }]
    };

    // The login password for sudo goes where it goes already.
    core.containers.marks().set(ctx, web.id, &marks(None)).await.unwrap();
    // Another vault password doesn't.
    let err = core.containers.marks().set(ctx, web.id, &marks(Some(sudo))).await;
    assert!(reauth_required(&err), "{err:?}");
    core.containers
        .marks()
        .set_with(ctx, web.id, &marks(Some(sudo)), Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();
    let entries = audit_events(&core).await;
    let changed = entries.iter().find(|e| e.event == "session_changed").unwrap();
    assert!(
        changed.detail.as_deref().unwrap().contains("asked again"),
        "{changed:?}"
    );

    // From now on the mark is where it goes: a session there may log in with it without asking.
    core.sessions
        .create(ctx, with_password("web01 root", "web01.example.com", sudo))
        .await
        .unwrap();
}

fn compare(targets: &[SessionRecord], sudo_password: SecretId) -> Command {
    Command::RemoteExec {
        targets: targets
            .iter()
            .map(|s| TargetRef::Session { session_id: s.id })
            .collect(),
        script: "uptime".into(),
        sudo: true,
        sudo_password_id: Some(sudo_password),
        trust_new_host_keys: false,
        timeout_secs: Some(30),
        rollout: Default::default(),
    }
}

#[tokio::test]
async fn a_compare_run_whose_sudo_password_is_new_to_its_hosts_asks_for_the_vault_password() {
    let core = core().await;
    let ctx = &core.ctx;
    let sudo = existing(&core, "customer root").await;
    let mut hosts = Vec::new();
    for name in ["web01", "web02"] {
        hosts.push(
            core.sessions
                .create(ctx, session(name, &format!("{name}.example.com"), SessionAuth::Agent))
                .await
                .unwrap(),
        );
    }

    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(ctx, compare(&hosts, sudo)).await.unwrap() else {
        panic!("a sudo password new to these hosts can't go without asking");
    };
    assert!(
        request.steps.contains(&ApprovalStep::VaultReauth),
        "{:?}",
        request.steps
    );
    assert!(
        request
            .warnings
            .iter()
            .any(|w| w.contains("password 'customer root'") && w.contains("'web01'")),
        "{:?}",
        request.warnings
    );
    let no_password = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    assert!(core.bus.approve(request.id, no_password).await.is_err());
    core.bus
        .approve(
            request.id,
            ApprovalAnswers {
                confirmed: true,
                vault_password: Some(pw(VAULT_PASSWORD)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let allowed = audit_events(&core)
        .await
        .into_iter()
        .filter(|e| e.event == "vault_secret_allowed")
        .count();
    assert_eq!(allowed, 2, "both sessions may use it from now on");

    // The next run on them asks nothing more for it.
    match core.bus.submit(ctx, compare(&hosts, sudo)).await.unwrap() {
        SubmitOutcome::Queued { .. } => {}
        SubmitOutcome::NeedsApproval { request } => {
            assert!(
                !request.steps.contains(&ApprovalStep::VaultReauth),
                "{:?}",
                request.steps
            );
        }
    }
}

#[tokio::test]
async fn loosening_the_approval_rules_needs_the_vault_password_and_tightening_does_not() {
    let core = core().await;
    let ctx = &core.ctx;
    let mut tighter: PolicyRules = core.bus.rules();
    tighter.countdown_seconds = 20;
    tighter.prod_bump = true;
    core.bus.set_rules(ctx, tighter.clone()).await.unwrap();

    let mut looser = tighter.clone();
    looser.countdown_seconds = 5;
    let err = core.bus.set_rules(ctx, looser.clone()).await;
    assert!(reauth_required(&err), "{err:?}");
    assert!(err.unwrap_err().to_string().contains("a shorter countdown"));
    assert!(matches!(
        core.bus
            .set_rules_with(ctx, looser.clone(), Some(&pw("guess-guess-guess")))
            .await,
        Err(CoreError::WrongVaultPassword)
    ));
    assert_eq!(core.bus.rules().countdown_seconds, 20, "nothing changed");
    core.bus
        .set_rules_with(ctx, looser, Some(&pw(VAULT_PASSWORD)))
        .await
        .unwrap();
    let entries = audit_events(&core).await;
    let changed = entries
        .iter()
        .find(|e| e.event == "setting_changed" && e.action == "Changed the approval rules")
        .unwrap();
    assert!(changed.detail.as_deref().unwrap().contains("looser"), "{changed:?}");

    // A new read-only command loosens; a shell can't be one, password or not.
    let mut read_only = core.bus.rules();
    read_only.read_only_commands.push("lsattr".into());
    assert!(reauth_required(&core.bus.set_rules(ctx, read_only).await));
    let mut shell = core.bus.rules();
    shell.read_only_commands.push("bash".into());
    assert!(matches!(
        core.bus.set_rules_with(ctx, shell, Some(&pw(VAULT_PASSWORD))).await,
        Err(CoreError::InvalidRule { .. })
    ));
}

#[tokio::test]
async fn one_right_answer_covers_the_next_five_minutes_until_the_vault_locks() {
    assert_eq!(REAUTH_GRACE, Duration::from_secs(5 * 60));
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let ctx = &core.ctx;
    let shared = existing(&core, "customer root").await;

    // Setting up several sessions that share a password asks once.
    saved(&core, with_password("web01", "web01.example.com", shared)).await;
    core.sessions
        .create(ctx, with_password("web02", "web02.example.com", shared))
        .await
        .unwrap();
    let entries = audit_events(&core).await;
    let created = entries
        .iter()
        .find(|e| e.event == "session_changed" && e.action.contains("web02"))
        .unwrap();
    assert!(
        created
            .detail
            .as_deref()
            .unwrap()
            .contains("given in the last 5 minutes"),
        "{created:?}"
    );

    // Locking ends it: whoever unlocks next is asked again.
    core.vault.lock(ctx).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    core.vault
        .unlock(ctx, UnlockMethod::MasterPassword(pw(VAULT_PASSWORD)))
        .await
        .unwrap();
    let after = core
        .sessions
        .create(ctx, with_password("web03", "web03.example.com", shared))
        .await;
    assert!(reauth_required(&after), "{after:?}");
}
