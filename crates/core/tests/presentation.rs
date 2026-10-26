//! FD-03 presentation mode's read-only lock, end to end with fake adapters: the command bus refuses every command and
//! the services refuse every edit of the app's data while presenting with the lock on; reads, the vault's lock and
//! unlock, and turning the lock off stay possible. The setting is saved (fail closed) and audited.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{running, vm, wait_finished, Setup};
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::policy::PolicyRules;
use remotely_core::presentation::{Presentation, PresentationMode, PRESENTATION_KEY};
use remotely_core::sessions::{SessionAuth, SessionFilter, SessionInput};
use remotely_core::snippets::FavouriteInput;
use remotely_core::vault::{SecretKind, SecretString, UnlockMethod};
use remotely_core::workspaces::Current;
use remotely_core::{Core, CoreError};

const LOCKED: Presentation = Presentation {
    enabled: true,
    read_only: true,
};
const PRESENTING: Presentation = Presentation {
    enabled: true,
    read_only: false,
};

async fn core() -> Core {
    Setup::new(FakeVmware::with_running([common::vmx("a"), common::vmx("b")]))
        .with_real_vault()
        .build()
        .await
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

fn locked_out<T: std::fmt::Debug>(result: remotely_core::Result<T>, what: &str) {
    match result {
        Err(err @ CoreError::ReadOnlyLock { .. }) => {
            assert_eq!(err.code(), "read_only_lock");
            assert!(err.to_string().contains(what), "{err} names {what}");
        }
        other => panic!("expected the read-only lock to refuse {what}, got {other:?}"),
    }
}

#[tokio::test]
async fn the_bus_refuses_every_command_while_locked_and_runs_them_again_after() {
    let fake = FakeVmware::with_running(Vec::<String>::new());
    let setup = Setup::new(fake);
    let fake = std::sync::Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();
    let start = || Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Start { gui: false },
    };

    core.presentation.set(LOCKED).await.unwrap();
    assert!(core.store.read_only().is_locked());
    // Low tier, which runs without a dialog: refused too, and nothing reached the VM or the audit log.
    let before = core.store.recent_audit(&core.ctx(), 50).await.unwrap().len();
    locked_out(core.bus.submit(&core.ctx(), start()).await, "Start VMs");
    let exec = Command::RemoteExec {
        targets: vec![TargetRef::Session {
            session_id: uuid::Uuid::new_v4(),
        }],
        script: "uptime".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Default::default(),
    };
    locked_out(core.bus.submit(&core.ctx(), exec).await, "Run a read-only command");
    locked_out(
        core.bus
            .submit(
                &core.ctx(),
                Command::AppUpdate {
                    version: "9.9.9".into(),
                },
            )
            .await,
        "Install an app update",
    );
    assert!(fake.calls().is_empty());
    assert!(running(&fake).is_empty());
    assert_eq!(core.store.recent_audit(&core.ctx(), 50).await.unwrap().len(), before);

    // Presenting without the lock: commands go as usual.
    core.presentation.set(PRESENTING).await.unwrap();
    assert!(!core.store.read_only().is_locked());
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx(), start()).await.unwrap() else {
        panic!("starting a VM needs no approval");
    };
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    assert_eq!(running(&fake), ["a"]);
}

#[tokio::test]
async fn an_approval_asked_before_the_lock_waits_until_the_lock_is_off() {
    let core = core().await;
    let suspend = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Suspend,
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx(), suspend).await.unwrap() else {
        panic!("suspending is Medium");
    };
    core.presentation.set(LOCKED).await.unwrap();
    let confirmed = || ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    locked_out(core.bus.approve(request.id, confirmed()).await, "Suspend VMs");
    // Still waiting: once the lock is off, the same request can be approved.
    core.presentation.set(Presentation::default()).await.unwrap();
    core.bus.approve(request.id, confirmed()).await.unwrap();
}

#[tokio::test]
async fn the_lock_refuses_edits_of_the_apps_data_and_changes_nothing() {
    let core = core().await;
    let ctx = &core.ctx();
    let kept = core
        .sessions
        .create(ctx, session("web01", "web01.example.com"))
        .await
        .unwrap();
    core.presentation.set(LOCKED).await.unwrap();

    locked_out(
        core.sessions.create(ctx, session("db01", "db01.example.com")).await,
        "Edit sessions",
    );
    locked_out(core.sessions.delete(ctx, kept.id).await, "Edit sessions");
    locked_out(
        core.sessions.create_folder(ctx, "Customer A", None).await,
        "Edit sessions",
    );
    locked_out(core.forwards.save(ctx, kept.id, &[]).await, "Edit port forwards");
    locked_out(
        core.vault
            .add(ctx, SecretKind::Password, "db01 bob", SecretString::new("pw-value-2"))
            .await,
        "Change the vault",
    );
    locked_out(
        core.snippets
            .add(
                ctx,
                FavouriteInput {
                    folder: None,
                    name: "Disk".into(),
                    command: "df -h".into(),
                    description: None,
                },
            )
            .await,
        "Edit favourite commands",
    );
    locked_out(core.set_power_on_limit(5).await, "Change settings");
    locked_out(core.set_update_checks(false).await, "Change settings");
    locked_out(
        core.bus.set_rules(ctx, PolicyRules::default()).await,
        "Change the approval rules",
    );
    locked_out(
        core.store.tag_vms(ctx, &[common::vmx("a")], "web").await,
        "Change VM labels",
    );
    locked_out(
        core.inventory
            .set_environment(ctx, &[common::vmx("a")], Environment::Prod)
            .await,
        "Change VM labels",
    );
    locked_out(
        core.multiexec.set_targets(vec![uuid::Uuid::new_v4()]).await,
        "Turn MultiExec on",
    );

    // Nothing changed.
    let sessions = core.sessions.list(ctx, &SessionFilter::default()).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert!(core.sessions.folders(ctx).await.unwrap().is_empty());
    assert!(core.snippets.favourites(ctx).await.unwrap().is_empty());
    assert_eq!(
        core.power_on_limit(),
        remotely_core::jobs::JobLimits::default().power_on
    );

    // Reads and the vault's lock stay open: they change nothing.
    core.vault.lock(ctx).await.unwrap();
    core.vault
        .unlock(
            ctx,
            UnlockMethod::MasterPassword(SecretString::new(common::VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    assert_eq!(core.vault.list(ctx).await.unwrap().len(), 0);
    core.inventory.refresh(ctx).await.unwrap();
    let folder = common::temp_folder("presentation-export");
    let export = core.export_audit_csv(&folder.join("audit.csv")).await.unwrap();
    assert!(export.entries > 0);
    std::fs::remove_dir_all(folder).unwrap();

    // Turning the lock off is never refused, and then edits work.
    core.presentation.set(PRESENTING).await.unwrap();
    core.sessions
        .create(ctx, session("db01", "db01.example.com"))
        .await
        .unwrap();
}

#[tokio::test]
async fn presentation_is_saved_audited_and_read_back_failing_closed() {
    let core = core().await;
    let ctx = core.ctx();
    assert_eq!(core.presentation.get(), Presentation::default());
    core.presentation.set(PRESENTING).await.unwrap();
    core.presentation.set(LOCKED).await.unwrap();
    // The same again changes nothing and logs nothing.
    let count = core.store.recent_audit(&ctx, 50).await.unwrap().len();
    core.presentation.set(LOCKED).await.unwrap();
    assert_eq!(core.store.recent_audit(&ctx, 50).await.unwrap().len(), count);

    let audit = core.store.recent_audit(&ctx, 2).await.unwrap();
    let actions: Vec<_> = audit.iter().rev().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["Started presenting", "Turned the read-only lock on"]);
    assert!(audit.iter().all(|e| e.event == "setting_changed"));

    // The app starts as it closed: presenting, locked.
    let restarted = PresentationMode::load(core.store.clone(), Current::new(ctx)).await;
    assert_eq!(restarted.get(), LOCKED);
    assert!(core.store.read_only().is_locked());

    // A saved value that can't be read starts presenting, locked.
    core.store
        .put_setting(&ctx, PRESENTATION_KEY, &"presenting, maybe")
        .await
        .unwrap();
    let unreadable = PresentationMode::load(core.store.clone(), Current::new(ctx)).await;
    assert_eq!(unreadable.get(), Presentation::FAIL_CLOSED);

    core.presentation.set(Presentation::default()).await.unwrap();
    let audit = core.store.recent_audit(&ctx, 2).await.unwrap();
    let actions: Vec<_> = audit.iter().rev().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["Stopped presenting", "Turned the read-only lock off"]);
    assert!(!core.store.read_only().is_locked());
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
}
