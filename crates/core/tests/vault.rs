//! SS-04 vault and AP-06 re-authentication, end to end through the store. DPAPI is faked (the real
//! one is tested in `vault::protector` against this Windows account), and key derivation uses the
//! fast test parameters.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{fake_private_key, temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, StopMode, SubmitOutcome};
use remotely_core::domain::{Context, TargetRef};
use remotely_core::fakes::{FakeKeyProtector, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::store::Store;
use remotely_core::vault::{
    KeyProtector, LocalVault, SecretKind, SecretString, UnlockMethod, Vault, VaultOptions, VaultService, VaultStatus,
    IDLE_TIMEOUT,
};
use remotely_core::CoreError;

const PASSWORD: &str = "violet harbor anvil kettle";

fn pw(p: &str) -> SecretString {
    SecretString::new(p)
}

async fn store() -> (Store, Context) {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    (store, ctx)
}

async fn open(store: &Store, ctx: Context, protector: Arc<dyn KeyProtector>) -> LocalVault {
    LocalVault::open(store.clone(), ctx, protector, VaultOptions::insecure_fast())
        .await
        .unwrap()
}

/// A vault set up with [`PASSWORD`] and the Windows login, unlocked.
async fn ready() -> (Store, Context, Arc<FakeKeyProtector>, LocalVault) {
    let (store, ctx) = store().await;
    let protector = Arc::new(FakeKeyProtector::new());
    let vault = open(&store, ctx, protector.clone()).await;
    vault.setup(&ctx, pw(PASSWORD), true).await.unwrap();
    (store, ctx, protector, vault)
}

#[tokio::test]
async fn a_new_vault_starts_unlocked_and_a_restarted_app_finds_it_locked() {
    let (store, ctx) = store().await;
    let protector = Arc::new(FakeKeyProtector::new());
    let vault = open(&store, ctx, protector.clone()).await;
    assert_eq!(vault.status(), VaultStatus::NotSetUp);
    assert!(matches!(
        vault.put(&ctx, SecretKind::Password, "web", pw("x")).await,
        Err(CoreError::VaultNotSetUp)
    ));
    assert!(matches!(
        vault.verify_password(&pw(PASSWORD)).await,
        Err(CoreError::VaultNotSetUp)
    ));

    vault.setup(&ctx, pw(PASSWORD), true).await.unwrap();
    let info = vault.info();
    assert_eq!(info.status, VaultStatus::Unlocked);
    assert!(info.windows_login);
    assert_eq!(info.idle_lock_minutes, 15);
    let id = vault
        .put(&ctx, SecretKind::Password, "web01 root", pw("s3cret-1"))
        .await
        .unwrap();

    // Setting it up again would replace the key and lose every secret.
    assert!(matches!(
        vault.setup(&ctx, pw("another long password"), false).await,
        Err(CoreError::InvalidInput(_))
    ));

    let restarted = open(&store, ctx, protector).await;
    assert_eq!(restarted.status(), VaultStatus::Locked);
    assert!(matches!(restarted.get(&ctx, id).await, Err(CoreError::VaultLocked)));
    restarted.unlock(UnlockMethod::WindowsLogin).await.unwrap();
    assert_eq!(restarted.get(&ctx, id).await.unwrap().expose(), "s3cret-1");
}

#[tokio::test]
async fn every_kind_round_trips_and_is_encrypted_at_rest() {
    let dir = temp_folder("vault-at-rest");
    let path = dir.join("remotely.db");
    let store = Store::open(&path).await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let vault = open(&store, ctx, Arc::new(FakeKeyProtector::new())).await;
    vault.setup(&ctx, pw(PASSWORD), false).await.unwrap();

    let key = fake_private_key();
    let values = [
        (
            SecretKind::Password,
            "db password",
            "Plain-Password-Marker-1".to_owned(),
        ),
        (SecretKind::PrivateKey, "deploy key", key.clone()),
        (
            SecretKind::Passphrase,
            "deploy key passphrase",
            "Passphrase Marker Two".to_owned(),
        ),
    ];
    let mut ids = Vec::new();
    for (kind, label, value) in &values {
        ids.push(vault.put(&ctx, *kind, label, pw(value)).await.unwrap());
    }
    for (id, (_, _, value)) in ids.iter().zip(&values) {
        assert_eq!(vault.get(&ctx, *id).await.unwrap().expose(), value);
    }

    // Nothing in the database file or its WAL is a plaintext secret or the master password.
    let mut on_disk = std::fs::read(&path).unwrap();
    if let Ok(wal) = std::fs::read(dir.join("remotely.db-wal")) {
        on_disk.extend(wal);
    }
    let body = key.lines().nth(1).unwrap().to_owned();
    for needle in [
        "Plain-Password-Marker-1",
        "Passphrase Marker Two",
        body.as_str(),
        PASSWORD,
    ] {
        assert!(
            !on_disk.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} is on disk in the clear"
        );
    }
    let labels: Vec<_> = vault.list(&ctx).await.unwrap().into_iter().map(|m| m.label).collect();
    assert_eq!(labels, ["db password", "deploy key", "deploy key passphrase"]);
    drop(vault);
    drop(store);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_wrong_master_password_does_not_unlock_and_the_attempt_is_audited() {
    let (store, ctx, protector, vault) = ready().await;
    vault.lock();
    let service = VaultService::new(Arc::new(open(&store, ctx, protector).await), store.clone());

    let err = service
        .unlock(&ctx, UnlockMethod::MasterPassword(pw("violet harbor anvil kettl")))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongVaultPassword));
    assert!(!err.to_string().contains("stapl"));
    assert_eq!(service.info().status, VaultStatus::Locked);
    let audit = store.recent_audit(&ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "vault_auth_failed");
    assert_eq!(audit[0].action, "Failed to unlock the vault");

    assert!(matches!(
        service.unlock(&ctx, UnlockMethod::MasterPassword(pw(""))).await,
        Err(CoreError::WrongVaultPassword)
    ));
    service
        .unlock(&ctx, UnlockMethod::MasterPassword(pw(PASSWORD)))
        .await
        .unwrap();
    assert_eq!(service.info().status, VaultStatus::Unlocked);
    let audit = store.recent_audit(&ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "vault_unlocked");
    assert_eq!(audit[0].detail.as_deref(), Some("with the vault password"));
    assert!(store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn the_windows_login_unlocks_only_for_the_same_windows_user() {
    let (store, ctx, _protector, vault) = ready().await;
    let id = vault
        .put(&ctx, SecretKind::Password, "web", pw("s3cret"))
        .await
        .unwrap();

    // Another Windows account (or this one after an administrator reset its password) has another
    // DPAPI key: the Windows login fails there, and the master password still opens the vault.
    let elsewhere = open(&store, ctx, Arc::new(FakeKeyProtector::new())).await;
    let err = elsewhere.unlock(UnlockMethod::WindowsLogin).await.unwrap_err();
    assert_eq!(err.code(), "vault");
    assert!(err.to_string().contains("use the vault password"), "{err}");
    elsewhere
        .unlock(UnlockMethod::MasterPassword(pw(PASSWORD)))
        .await
        .unwrap();
    assert_eq!(elsewhere.get(&ctx, id).await.unwrap().expose(), "s3cret");
}

#[tokio::test]
async fn the_windows_login_can_be_turned_off_and_on_again_with_the_password() {
    let (store, ctx, protector, vault) = ready().await;
    assert!(matches!(
        vault.set_windows_login(&pw("not the password"), false).await,
        Err(CoreError::WrongVaultPassword)
    ));
    vault.set_windows_login(&pw(PASSWORD), false).await.unwrap();
    assert!(!vault.info().windows_login);

    let restarted = open(&store, ctx, protector.clone()).await;
    assert!(!restarted.info().windows_login);
    assert!(matches!(
        restarted.unlock(UnlockMethod::WindowsLogin).await,
        Err(CoreError::InvalidInput(_))
    ));

    restarted.set_windows_login(&pw(PASSWORD), true).await.unwrap();
    let again = open(&store, ctx, protector).await;
    again.unlock(UnlockMethod::WindowsLogin).await.unwrap();
    assert_eq!(again.status(), VaultStatus::Unlocked);
}

#[tokio::test]
async fn without_dpapi_only_the_master_password_unlocks() {
    let (store, ctx) = store().await;
    let vault = open(&store, ctx, Arc::new(FakeKeyProtector::unavailable())).await;
    assert!(!vault.info().windows_login_available);
    assert!(matches!(
        vault.setup(&ctx, pw(PASSWORD), true).await,
        Err(CoreError::InvalidInput(_))
    ));
    assert_eq!(
        vault.status(),
        VaultStatus::NotSetUp,
        "a failed setup leaves nothing behind"
    );
    vault.setup(&ctx, pw(PASSWORD), false).await.unwrap();
    vault.lock();
    assert!(matches!(
        vault.unlock(UnlockMethod::WindowsLogin).await,
        Err(CoreError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn a_short_or_guessable_master_password_is_refused() {
    let (store, ctx) = store().await;
    let vault = open(&store, ctx, Arc::new(FakeKeyProtector::new())).await;
    for weak in [
        "hunter2",
        "Password123!",
        "aaaaaaaaaaaa",
        "qwertyuiop12",
        "Remotely2026!",
    ] {
        let err = vault.setup(&ctx, pw(weak), true).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)), "{weak}: {err}");
        assert!(!err.to_string().contains(weak), "{err}");
        assert_eq!(vault.status(), VaultStatus::NotSetUp);
    }
    // SS-04: a passphrase Remotely made up always passes.
    let generated = remotely_core::vault::generate_passphrase().unwrap();
    vault.setup(&ctx, generated.clone(), false).await.unwrap();
    assert!(vault.verify_password(&generated).await.unwrap());
}

/// A vault that locks after `idle` instead of 15 minutes. (Tokio's paused clock can't stand in:
/// sqlx's pool times out as soon as the clock jumps.)
async fn quick_to_lock(idle: Duration) -> (Context, LocalVault) {
    let (store, ctx) = store().await;
    let options = VaultOptions {
        idle_timeout: idle,
        ..VaultOptions::insecure_fast()
    };
    let vault = LocalVault::open(store, ctx, Arc::new(FakeKeyProtector::new()), options)
        .await
        .unwrap();
    vault.setup(&ctx, pw(PASSWORD), true).await.unwrap();
    (ctx, vault)
}

#[tokio::test]
async fn it_locks_after_the_idle_time_without_use() {
    assert_eq!(IDLE_TIMEOUT, Duration::from_secs(15 * 60), "SS-04: 15 minutes");
    assert_eq!(VaultOptions::default().idle_timeout, IDLE_TIMEOUT);

    let idle = Duration::from_secs(2);
    let (ctx, vault) = quick_to_lock(idle).await;
    let id = vault
        .put(&ctx, SecretKind::Password, "web", pw("s3cret"))
        .await
        .unwrap();

    tokio::time::sleep(idle / 2).await;
    assert_eq!(vault.status(), VaultStatus::Unlocked);
    // Use resets the clock.
    assert_eq!(vault.get(&ctx, id).await.unwrap().expose(), "s3cret");
    tokio::time::sleep(idle / 2).await;
    assert_eq!(vault.status(), VaultStatus::Unlocked, "used half the idle time ago");

    // Listing labels is not use: it needs no key.
    vault.list(&ctx).await.unwrap();
    tokio::time::sleep(idle / 2 + Duration::from_millis(200)).await;
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert!(matches!(vault.get(&ctx, id).await, Err(CoreError::VaultLocked)));
}

#[tokio::test]
async fn the_idle_lock_happens_on_its_own_and_is_announced() {
    let (_ctx, vault) = quick_to_lock(Duration::from_millis(300)).await;
    let mut status = vault.watch();
    assert_eq!(*status.borrow_and_update(), VaultStatus::Unlocked);

    // Nothing calls the vault: the background check locks it and tells whoever listens.
    tokio::time::timeout(Duration::from_secs(10), status.changed())
        .await
        .expect("locked on its own")
        .unwrap();
    assert_eq!(*status.borrow(), VaultStatus::Locked);
}

#[tokio::test]
async fn locking_on_demand_keeps_the_labels_readable_but_not_the_values() {
    let (_store, ctx, _protector, vault) = ready().await;
    let id = vault
        .put(&ctx, SecretKind::Password, "web", pw("s3cret"))
        .await
        .unwrap();
    let mut status = vault.watch();
    vault.lock();
    assert_eq!(*status.borrow_and_update(), VaultStatus::Locked);
    assert!(matches!(vault.get(&ctx, id).await, Err(CoreError::VaultLocked)));
    for result in [
        vault.put(&ctx, SecretKind::Password, "db", pw("x")).await.map(drop),
        vault.replace(&ctx, id, pw("y")).await,
        vault.rename(&ctx, id, "web2").await,
        vault.delete(&ctx, id).await,
    ] {
        assert!(matches!(result, Err(CoreError::VaultLocked)), "{result:?}");
    }
    assert_eq!(vault.list(&ctx).await.unwrap()[0].label, "web");
    // AP-06 works locked too: the password check does not need the vault open.
    assert!(vault.verify_password(&pw(PASSWORD)).await.unwrap());
    assert_eq!(vault.status(), VaultStatus::Locked, "verifying does not unlock");
}

#[tokio::test]
async fn changing_the_master_password_needs_the_current_one_and_keeps_every_secret() {
    let (store, ctx, protector, vault) = ready().await;
    let id = vault
        .put(&ctx, SecretKind::Passphrase, "key pass", pw("phrase"))
        .await
        .unwrap();
    assert!(matches!(
        vault
            .change_password(&pw("wrong password!"), pw("a new long password"))
            .await,
        Err(CoreError::WrongVaultPassword)
    ));
    assert!(matches!(
        vault.change_password(&pw(PASSWORD), pw("short")).await,
        Err(CoreError::InvalidInput(_))
    ));
    vault
        .change_password(&pw(PASSWORD), pw("a new long password"))
        .await
        .unwrap();
    assert!(!vault.verify_password(&pw(PASSWORD)).await.unwrap());
    assert!(vault.verify_password(&pw("a new long password")).await.unwrap());

    let restarted = open(&store, ctx, protector).await;
    assert!(matches!(
        restarted.unlock(UnlockMethod::MasterPassword(pw(PASSWORD))).await,
        Err(CoreError::WrongVaultPassword)
    ));
    restarted
        .unlock(UnlockMethod::MasterPassword(pw("a new long password")))
        .await
        .unwrap();
    assert_eq!(restarted.get(&ctx, id).await.unwrap().expose(), "phrase");
}

#[tokio::test]
async fn replace_rename_and_delete() {
    let (store, ctx, _protector, vault) = ready().await;
    let service = VaultService::new(Arc::new(vault), store.clone());
    let web = service
        .add(&ctx, SecretKind::Password, " web root ", pw("one"))
        .await
        .unwrap();
    assert_eq!(web.label, "web root");
    assert!(matches!(
        service.add(&ctx, SecretKind::Password, "WEB ROOT", pw("two")).await,
        Err(CoreError::InvalidInput(_))
    ));

    service.replace(&ctx, web.id, pw("two")).await.unwrap();
    assert_eq!(service.vault().get(&ctx, web.id).await.unwrap().expose(), "two");
    let renamed = service.rename(&ctx, web.id, "web01 root").await.unwrap();
    assert_eq!(renamed.label, "web01 root");
    assert!(matches!(
        service.replace(&ctx, web.id, pw("")).await,
        Err(CoreError::InvalidInput(_))
    ));

    service.delete(&ctx, web.id).await.unwrap();
    assert!(service.list(&ctx).await.unwrap().is_empty());
    assert!(matches!(
        service.delete(&ctx, web.id).await,
        Err(CoreError::UnknownTarget(_))
    ));

    let actions: Vec<_> = store
        .recent_audit(&ctx, 4)
        .await
        .unwrap()
        .into_iter()
        .rev()
        .map(|e| e.action)
        .collect();
    assert_eq!(
        actions,
        [
            "Added the password 'web root' to the vault",
            "Replaced the password 'web root'",
            "Renamed the password 'web root' to 'web01 root'",
            "Deleted the password 'web01 root' from the vault",
        ]
    );
}

#[tokio::test]
async fn ciphertext_moved_to_another_row_does_not_decrypt() {
    let (store, ctx, _protector, vault) = ready().await;
    let a = vault.put(&ctx, SecretKind::Password, "a", pw("value-a")).await.unwrap();
    let b = vault.put(&ctx, SecretKind::Password, "b", pw("value-b")).await.unwrap();
    // Someone with the database file copies a's ciphertext over b's.
    sqlx::query(
        "UPDATE vault_items SET nonce = (SELECT nonce FROM vault_items WHERE id = ?1),
                ciphertext = (SELECT ciphertext FROM vault_items WHERE id = ?1) WHERE id = ?2",
    )
    .bind(a.0.to_string())
    .bind(b.0.to_string())
    .execute(store.pool())
    .await
    .unwrap();
    let err = vault.get(&ctx, b).await.unwrap_err();
    assert_eq!(err.code(), "vault");
    assert!(!err.to_string().contains("value-a"));
    assert_eq!(vault.get(&ctx, a).await.unwrap().expose(), "value-a");
}

#[tokio::test]
async fn no_secret_reaches_debug_output_the_audit_log_errors_or_what_the_ui_receives() {
    let (store, ctx, _protector, vault) = ready().await;
    let service = VaultService::new(Arc::new(vault), store.clone());
    let key = fake_private_key();
    let secrets = ["Marker-Password-Value", "Marker Passphrase Value"];

    let meta = service
        .add(&ctx, SecretKind::Password, "db", pw(secrets[0]))
        .await
        .unwrap();
    service
        .add(&ctx, SecretKind::Passphrase, "phrase", pw(secrets[1]))
        .await
        .unwrap();
    service
        .add(&ctx, SecretKind::PrivateKey, "key", pw(&key))
        .await
        .unwrap();
    service.replace(&ctx, meta.id, pw(secrets[0])).await.unwrap();
    let errors = [
        service
            .add(&ctx, SecretKind::Password, "db", pw(secrets[0]))
            .await
            .unwrap_err(),
        service
            .add(&ctx, SecretKind::PrivateKey, "bad", pw(secrets[0]))
            .await
            .unwrap_err(),
        service
            .unlock(&ctx, UnlockMethod::MasterPassword(pw(secrets[1])))
            .await
            .unwrap_err(),
        service
            .change_password(&ctx, &pw(secrets[1]), pw(secrets[0]))
            .await
            .unwrap_err(),
    ];
    service.lock(&ctx).await.unwrap();
    service.unlock(&ctx, UnlockMethod::WindowsLogin).await.unwrap();

    let list = service.list(&ctx).await.unwrap();
    let mut seen = vec![
        format!("{list:?}"),
        serde_json::to_string(&list).unwrap(),
        format!("{:?}", service.info()),
        serde_json::to_string(&service.info()).unwrap(),
        format!("{:?}", pw(secrets[0])),
    ];
    seen.extend(errors.iter().map(|e| format!("{e} {e:?}")));
    for entry in store.recent_audit(&ctx, 100).await.unwrap() {
        seen.push(format!("{entry:?}"));
    }
    let body = key.lines().nth(1).unwrap().to_owned();
    for text in &seen {
        for secret in secrets.iter().copied().chain([body.as_str(), PASSWORD]) {
            assert!(!text.contains(secret), "{secret} leaked into: {text}");
        }
    }
    assert!(store.verify_audit_chain().await.unwrap().ok);
}

// ---- AP-06 through the command bus, with the real vault ----------------------------------------

fn hard_stop(name: &str) -> Command {
    Command::VmPower {
        targets: vec![TargetRef::Vm {
            vmx_path: common::vmx(name),
        }],
        op: PowerOp::Stop { mode: StopMode::Hard },
    }
}

fn critical_answers(password: &str) -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(1),
        reason: Some("hung VM".into()),
        safety_snapshot: Some(false),
        vault_password: Some(pw(password)),
    }
}

#[tokio::test]
async fn critical_actions_ask_for_the_master_password_even_when_windows_unlocked_the_vault() {
    let setup = Setup::new(FakeVmware::with_running([common::vmx("web01").as_str()])).with_real_vault();
    let vmware = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    assert!(core.vault.info().windows_login);
    core.vault.lock(&core.ctx).await.unwrap();
    core.vault.unlock(&core.ctx, UnlockMethod::WindowsLogin).await.unwrap();
    let mut events = core.jobs.subscribe();

    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, hard_stop("web01")).await.unwrap() else {
        panic!("a hard power-off is Critical");
    };
    // The Windows login is not enough: no password, a wrong one, then the right one.
    assert!(matches!(
        core.bus
            .approve(
                request.id,
                ApprovalAnswers {
                    vault_password: None,
                    ..critical_answers("")
                }
            )
            .await,
        Err(CoreError::ApprovalRejected(_))
    ));
    assert!(matches!(
        core.bus.approve(request.id, critical_answers("not it at all")).await,
        Err(CoreError::WrongVaultPassword)
    ));
    let job = core
        .bus
        .approve(request.id, critical_answers(VAULT_PASSWORD))
        .await
        .unwrap();
    assert_eq!(common::wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(
        vmware.calls(),
        [format!("power Stop {{ mode: Hard }} {}", common::vmx("web01"))]
    );

    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    assert!(audit.iter().any(|e| e.event == "approval_rejected"));
    assert!(audit.iter().any(|e| e
        .approval_json
        .as_deref()
        .is_some_and(|a| a.contains("\"vaultReauth\":true"))));
    assert!(audit.iter().all(|e| !format!("{e:?}").contains(VAULT_PASSWORD)));
}

#[tokio::test]
async fn a_locked_vault_still_lets_a_critical_action_through_with_the_password() {
    let fake = FakeVmware::with_running([common::vmx("web01").as_str()]);
    let core = Setup::new(fake).with_real_vault().build().await;
    core.vault.lock(&core.ctx).await.unwrap();
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, hard_stop("web01")).await.unwrap() else {
        panic!("a hard power-off is Critical");
    };
    let job = core
        .bus
        .approve(request.id, critical_answers(VAULT_PASSWORD))
        .await
        .unwrap();
    assert_eq!(common::wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(core.vault.info().status, VaultStatus::Locked);
}
