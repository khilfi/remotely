//! FD-02 customer workspaces end to end, on the fakes (and the test SSH server for terminals): what is made in one
//! workspace is invisible, unusable and unexportable from another; VMs belong to one workspace at most and the bus
//! refuses the others; switching closes what the old workspace had open and waits for its jobs; each workspace's
//! audit log is its own chain; schedules of a hidden workspace still run, audited in it. No real host or VM.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{listed, vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::alerts::{AlertMetric, AlertRuleInput, AlertScope, Severity};
use remotely_core::catalog::sizes::{DiskSpec, Provisioning, SizeInput};
use remotely_core::command_bus::{Command, PowerOp, SubmitOutcome};
use remotely_core::containers::{MarkInput, SudoMode};
use remotely_core::domain::{Context, Environment};
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeContainers, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::multiexec_groups::GroupInput;
use remotely_core::notifications::{NotificationInput, NotificationLevel, NotificationSource};
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionFilter, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::rules::{RuleScope, RuleStyle, TerminalRuleInput};
use remotely_core::terminal::{TerminalEvent, TerminalStatus, TerminalTuning};
use remotely_core::transfer::{ExportRequest, ItemAction, ItemChoice, TransferCommit};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::workspaces::{Workspace, WorkspaceInput};
use remotely_core::{Core, CoreError};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const PASSPHRASE: &str = "violet harbor anvil kettle mosaic";

async fn create(core: &Core, name: &str) -> Workspace {
    core.workspaces
        .create(WorkspaceInput {
            name: name.into(),
            color: Some("teal".into()),
        })
        .await
        .unwrap()
}

/// Shows `to`, as the top bar's switcher does.
async fn switch(core: &Core, to: &Workspace) {
    core.switch_workspace(to.id).await.unwrap();
    assert_eq!(core.ctx().workspace_id, to.id);
}

fn ctx_of(core: &Core, w: &Workspace) -> Context {
    Context {
        workspace_id: w.id,
        user_id: core.ctx().user_id,
    }
}

async fn audit_of(core: &Core, ctx: &Context) -> Vec<AuditEntry> {
    core.store.recent_audit(ctx, 500).await.unwrap()
}

fn session_input(name: &str, host: &str, port: u16, password_id: Option<SecretId>) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port,
        username: Some("alice".into()),
        auth: SessionAuth::Password { password_id },
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: Default::default(),
    }
}

const LOCKED: Presentation = Presentation {
    enabled: true,
    read_only: true,
};

// ---- the workspaces themselves --------------------------------------------------------------------------------------

#[tokio::test]
async fn workspaces_are_made_renamed_coloured_archived_and_restored_each_audited_in_its_own_log() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let home = core.workspaces.shown().await.unwrap();
    assert_eq!(
        (home.name.as_str(), home.current, home.archived),
        ("Default", true, false)
    );
    let home_ctx = core.ctx();

    let globex = create(&core, "Globex").await;
    assert!(!globex.current, "made, not shown");
    assert_eq!(globex.color, "teal");
    let globex_ctx = ctx_of(&core, &globex);
    let theirs = audit_of(&core, &globex_ctx).await;
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0].event, "workspace_created");
    assert!(theirs[0].action.contains("Globex"));
    assert!(
        audit_of(&core, &home_ctx)
            .await
            .iter()
            .all(|e| !e.action.contains("Globex")),
        "no workspace's log names another"
    );

    // Names are unique, letter case aside; checked like the UI checks them.
    for bad in ["globex", "  ", "Line\nbreak"] {
        assert!(matches!(
            core.workspaces
                .create(WorkspaceInput {
                    name: bad.into(),
                    color: None
                })
                .await,
            Err(CoreError::InvalidInput(_))
        ));
    }
    let renamed = core.workspaces.rename(globex.id, "Globex Retail").await.unwrap();
    assert_eq!(renamed.name, "Globex Retail");
    core.workspaces.set_color(globex.id, "Amber").await.unwrap();
    assert!(core.workspaces.set_color(globex.id, "#ff0000").await.is_err());
    let events: Vec<String> = audit_of(&core, &globex_ctx)
        .await
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert_eq!(events, ["workspace_changed", "workspace_changed", "workspace_created"]);

    // The shown workspace can't be archived; an archived one can't be shown until it is restored.
    assert!(core.workspaces.archive(home.id).await.is_err());
    core.workspaces.archive(globex.id).await.unwrap();
    assert!(matches!(
        core.switch_workspace(globex.id).await,
        Err(CoreError::InvalidInput(_))
    ));
    let listed: Vec<(String, bool)> = core
        .workspaces
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|w| (w.name, w.archived))
        .collect();
    assert_eq!(
        listed,
        [("Default".to_owned(), false), ("Globex Retail".to_owned(), true)]
    );
    core.workspaces.restore(globex.id).await.unwrap();
    switch(&core, &globex).await;

    // FD-03: the read-only lock refuses workspace edits and switching (a switch closes terminals).
    core.presentation.set(LOCKED).await.unwrap();
    assert!(matches!(
        create_err(&core, "Initech").await,
        CoreError::ReadOnlyLock { .. }
    ));
    assert!(matches!(
        core.switch_workspace(home.id).await,
        Err(CoreError::ReadOnlyLock { .. })
    ));
    core.presentation.set(Presentation::default()).await.unwrap();
    switch(&core, &home).await;
    assert!(core.store.verify_audit_chain(&home_ctx).await.unwrap().ok);
    assert!(core.store.verify_audit_chain(&globex_ctx).await.unwrap().ok);
}

async fn create_err(core: &Core, name: &str) -> CoreError {
    core.workspaces
        .create(WorkspaceInput {
            name: name.into(),
            color: None,
        })
        .await
        .unwrap_err()
}

// ---- the engagement's data -----------------------------------------------------------------------------------------

#[tokio::test]
async fn sessions_folders_known_hosts_and_vault_items_stay_in_their_workspace() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let acme = core.ctx();
    let secret = core
        .vault
        .add(
            &acme,
            SecretKind::Password,
            "root on web01",
            SecretString::new("pw-acme-only"),
        )
        .await
        .unwrap()
        .id;
    let folder = core.sessions.create_folder(&acme, "Acme lab", None).await.unwrap();
    let mut input = session_input("web01", "web01.example.com", 22, Some(secret));
    input.folder_id = Some(folder.id);
    let web = core.sessions.create(&acme, input).await.unwrap();
    let key = HostKey {
        host: "web01.example.com".into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        fingerprint: "SHA256:acme".into(),
    };
    core.known_hosts.trust(&acme, &key, None).await.unwrap();

    let globex = create(&core, "Globex").await;
    switch(&core, &globex).await;
    let b = core.ctx();
    assert!(core
        .sessions
        .list(&b, &SessionFilter::default())
        .await
        .unwrap()
        .is_empty());
    assert!(core.sessions.folders(&b).await.unwrap().is_empty());
    assert!(core.vault.list(&b).await.unwrap().is_empty());
    assert!(core.known_hosts.list(&b).await.unwrap().is_empty());
    assert!(core.sessions.get(&b, web.id).await.is_err(), "Acme's session by its id");

    // A password bound in Acme can't be picked, read or sent in Globex.
    assert!(core.vault.vault().get(&b, secret).await.is_err());
    let picked = core
        .sessions
        .create(&b, session_input("web01", "web01.example.com", 22, Some(secret)))
        .await;
    assert!(matches!(picked, Err(CoreError::InvalidInput(_))), "{picked:?}");
    // The same host in Globex's own network is another machine: its key isn't trusted from Acme's.
    assert!(core.known_hosts.list(&b).await.unwrap().is_empty());

    // Acme's data is all there when it is shown again.
    let home = core
        .workspaces
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.name == "Default")
        .unwrap();
    switch(&core, &home).await;
    assert_eq!(
        core.sessions
            .list(&core.ctx(), &SessionFilter::default())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(core.vault.list(&core.ctx()).await.unwrap().len(), 1);
    assert_eq!(
        core.vault.vault().get(&core.ctx(), secret).await.unwrap().expose(),
        "pw-acme-only"
    );
}

#[tokio::test]
async fn the_catalogue_rules_groups_container_marks_and_notifications_are_per_workspace() {
    let core = Setup::new(FakeVmware::default())
        .with_containers(Arc::new(FakeContainers::default()))
        .build()
        .await;
    let acme = core.ctx();
    let builtins = core.catalog.sizes(&acme).await.unwrap().len();
    core.catalog
        .add_size(
            &acme,
            SizeInput {
                name: "acme.web".into(),
                sockets: 1,
                cores_per_socket: 2,
                memory_mb: 4096,
                disks: vec![DiskSpec {
                    size_gb: 40,
                    provisioning: Provisioning::Thin,
                    controller: None,
                }],
                description: None,
            },
        )
        .await
        .unwrap();
    let custom_alerts = |core: &Core| core.alerts.rules().into_iter().filter(|r| r.builtin.is_none()).count();
    core.alerts
        .create_rule(AlertRuleInput {
            name: "acme busy".into(),
            metric: AlertMetric::Cpu,
            scope: AlertScope::AllVms,
            threshold: Some(80.0),
            for_secs: 60,
            severity: Severity::Warning,
            notify: true,
            enabled: true,
        })
        .await
        .unwrap();
    assert_eq!(custom_alerts(&core), 1);
    core.terminal_rules
        .create(
            &acme,
            TerminalRuleInput {
                name: "acme errors".into(),
                pattern: "ACME-E\\d+".into(),
                case_sensitive: false,
                color: None,
                style: RuleStyle::Text,
                alert: true,
                scope: RuleScope::Global,
                enabled: true,
            },
        )
        .await
        .unwrap();
    let own_rules =
        |rules: Vec<remotely_core::terminal::rules::TerminalRule>| rules.into_iter().filter(|r| !r.builtin).count();
    let web = core
        .sessions
        .create(&acme, session_input("web01", "web01.example.com", 22, None))
        .await
        .unwrap();
    core.groups
        .create(
            &acme,
            GroupInput {
                name: "acme web".into(),
                session_ids: vec![web.id],
            },
        )
        .await
        .unwrap();
    core.containers
        .marks()
        .set(
            &acme,
            web.id,
            &[MarkInput {
                engine: remotely_core::adapters::containers::EngineKind::Docker,
                sudo: SudoMode::Off,
            }],
        )
        .await
        .unwrap();
    core.notifications
        .add(
            &acme,
            NotificationInput {
                source: NotificationSource::Job,
                level: NotificationLevel::Info,
                title: "Acme's job finished".into(),
                body: None,
                link: None,
                group: None,
                once: None,
            },
        )
        .unwrap();

    let globex = create(&core, "Globex").await;
    switch(&core, &globex).await;
    let b = core.ctx();
    assert_eq!(
        core.catalog.sizes(&b).await.unwrap().len(),
        builtins,
        "only the built-in sizes"
    );
    assert_eq!(custom_alerts(&core), 0, "Globex's own alert rules: none yet");
    assert_eq!(own_rules(core.terminal_rules.list(&b).await.unwrap()), 0);
    assert!(core.groups.list(&b).await.unwrap().is_empty());
    assert!(core.containers.marks().list(&b, None).await.unwrap().is_empty());
    assert!(
        core.containers
            .marks()
            .set(
                &b,
                web.id,
                &[MarkInput {
                    engine: remotely_core::adapters::containers::EngineKind::Docker,
                    sudo: SudoMode::Off,
                }],
            )
            .await
            .is_err(),
        "Acme's session can't be marked from Globex"
    );
    assert_eq!(core.notifications.list(&b).unread, 0);
    assert!(core.notifications.list(&b).entries.is_empty());

    let home = core
        .workspaces
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|w| !w.current)
        .unwrap();
    switch(&core, &home).await;
    assert_eq!(custom_alerts(&core), 1, "Acme's rule is back with Acme");
    assert_eq!(own_rules(core.terminal_rules.list(&acme).await.unwrap()), 1);
    assert_eq!(core.notifications.list(&acme).entries.len(), 1);
}

// ---- VMs -------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_vm_belongs_to_one_workspace_and_the_bus_refuses_it_from_any_other() {
    let scanned = common::temp_folder("workspaces-scan");
    let late = scanned.join("late").join("late.vmx").display().to_string();
    let fake = listed(FakeVmware::default(), &["web", "db"]).in_folder(&scanned.display().to_string(), &late);
    let setup = Setup::new(fake);
    let vmware = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let acme = core.ctx();
    // One workspace: every VM the refresh found joined it.
    let names =
        |vms: Vec<remotely_core::store::VmRecord>| -> Vec<String> { vms.into_iter().map(|v| v.display_name).collect() };
    assert_eq!(names(core.store.list_vms(&acme).await.unwrap()), ["db", "web"]);

    // With two workspaces, a VM found now waits in Unassigned.
    let globex = create(&core, "Globex").await;
    core.set_scan_folders(vec![scanned.clone()]).await.unwrap();
    let report = core.inventory.refresh(&acme).await.unwrap();
    assert_eq!(names(report.vms), ["db", "web"]);
    let waiting: Vec<String> = report.unassigned.iter().map(|v| v.vmx_path.clone()).collect();
    assert_eq!(waiting, std::slice::from_ref(&late));
    let refused = core
        .bus
        .submit(
            &acme,
            Command::VmPower {
                targets: vec![remotely_core::domain::TargetRef::Vm { vmx_path: late.clone() }],
                op: PowerOp::Start { gui: false },
            },
        )
        .await;
    assert!(matches!(refused, Err(CoreError::VmUnassigned(_))), "{refused:?}");

    // Globex sees none of Acme's VMs, and the bus refuses them there.
    switch(&core, &globex).await;
    let b = core.ctx();
    let report = core.inventory.refresh(&b).await.unwrap();
    assert!(report.vms.is_empty());
    assert_eq!(
        report.unassigned.len(),
        1,
        "Unassigned is the PC's, seen from any workspace"
    );
    let start_web = Command::VmPower {
        targets: vec![vm("web")],
        op: PowerOp::Start { gui: false },
    };
    assert!(matches!(
        core.bus.submit(&b, start_web.clone()).await,
        Err(CoreError::NotInWorkspace(_))
    ));
    assert!(core.snapshots.list(&b, None).await.unwrap().is_empty());
    assert!(matches!(
        core.host_details.vm_specs(&b, &vmx("web")).await,
        Err(CoreError::NotInWorkspace(_))
    ));
    assert!(matches!(
        core.insight.timeline(&vmx("web"), None, None).await,
        Err(CoreError::NotInWorkspace(_))
    ));
    assert!(
        vmware.calls().iter().all(|c| !c.contains("web.vmx")),
        "nothing ran on web"
    );

    // Globex adds the late VM; Acme gives db up and Globex takes it.
    core.inventory.claim(&b, std::slice::from_ref(&late)).await.unwrap();
    let home = core
        .workspaces
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.name == "Default")
        .unwrap();
    switch(&core, &home).await;
    core.inventory
        .set_environment(&acme, &[vmx("web")], Environment::Prod)
        .await
        .unwrap();
    assert!(
        matches!(core.inventory.release(&acme, &[vmx("web")]).await, Err(CoreError::InvalidInput(m)) if m.contains("Prod")),
        "a Prod VM stays until its label changes"
    );
    core.inventory.release(&acme, &[vmx("db")]).await.unwrap();
    assert_eq!(names(core.store.list_vms(&acme).await.unwrap()), ["web"]);
    // Taken out, db is unassigned: Acme must add it again before acting on it.
    assert!(matches!(
        core.bus
            .submit(
                &acme,
                Command::VmPower {
                    targets: vec![vm("db")],
                    op: PowerOp::Start { gui: false },
                },
            )
            .await,
        Err(CoreError::VmUnassigned(_))
    ));
    let events: Vec<String> = audit_of(&core, &acme).await.into_iter().map(|e| e.event).collect();
    assert!(events.contains(&"vm_released".to_owned()));
    switch(&core, &globex).await;
    core.inventory.claim(&b, &[vmx("db")]).await.unwrap();
    assert_eq!(names(core.store.list_vms(&b).await.unwrap()), ["db", "late"]);
    let mut jobs = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = core
        .bus
        .submit(
            &b,
            Command::VmPower {
                targets: vec![vm("db")],
                op: PowerOp::Start { gui: false },
            },
        )
        .await
        .unwrap()
    else {
        panic!("starting one VM is Low");
    };
    assert_eq!(wait_finished(&mut jobs, job_id).await, JobStatus::Succeeded);
    assert_eq!(core.jobs.workspace_of(job_id), Some(globex.id));
    let theirs: Vec<String> = audit_of(&core, &b).await.into_iter().map(|e| e.event).collect();
    assert!(theirs.contains(&"vm_assigned".to_owned()) && theirs.contains(&"job_finished".to_owned()));
    // The job is Globex's: Acme's journal and log don't have it.
    assert!(core
        .store
        .recent_jobs(&acme, 50)
        .await
        .unwrap()
        .iter()
        .all(|j| j.id != job_id.to_string()));
    assert!(audit_of(&core, &acme)
        .await
        .iter()
        .all(|e| e.job_id.as_deref() != Some(&job_id.to_string())));
    let _ = std::fs::remove_dir_all(&scanned);
}

// ---- the audit log ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn each_workspace_exports_and_verifies_its_own_audit_log() {
    let core = Setup::new(listed(FakeVmware::default(), &["web"])).build().await;
    let acme = core.ctx();
    let mut jobs = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = core
        .bus
        .submit(
            &acme,
            Command::VmPower {
                targets: vec![vm("web")],
                op: PowerOp::Start { gui: false },
            },
        )
        .await
        .unwrap()
    else {
        panic!("Low");
    };
    wait_finished(&mut jobs, job_id).await;
    let globex = create(&core, "Globex").await;
    switch(&core, &globex).await;

    let dir = common::temp_folder("workspaces-audit");
    let file = dir.join("globex-audit.csv");
    let exported = core.export_audit_csv(&file).await.unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains(&job_id.to_string()), "nothing of Acme's");
    assert!(!text.contains(&acme.workspace_id.to_string()));
    assert!(text.contains("workspace_created") && text.contains("workspace_opened"));
    assert!(exported.entries >= 2);
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
    let acme_check = core.store.verify_audit_chain(&acme).await.unwrap();
    assert!(acme_check.ok, "{acme_check:?}");
    // Acme's log has the job and the switch away, never Globex's name.
    let acme_log = audit_of(&core, &acme).await;
    assert!(acme_log.iter().any(|e| e.event == "workspace_left"));
    assert!(acme_log.iter().all(|e| !e.action.contains("Globex")));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- FD-07 ------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_export_holds_one_workspace_and_imports_into_the_shown_one_or_a_new_one() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    core.transfer.use_insecure_fast_kdf();
    let acme = core.ctx();
    core.sessions
        .create(&acme, session_input("acme-web", "web01.example.com", 22, None))
        .await
        .unwrap();
    let globex = create(&core, "Globex").await;
    switch(&core, &globex).await;
    let b = core.ctx();
    core.sessions
        .create(&b, session_input("globex-db", "db01.example.org", 22, None))
        .await
        .unwrap();

    let dir = common::temp_folder("workspaces-fd07");
    let path = dir.join("globex.remotely");
    core.transfer
        .export(
            &b,
            &path,
            ExportRequest {
                passphrase: SecretString::new(PASSPHRASE),
                include_known_hosts: true,
                include_secrets: false,
                vault_password: None,
            },
            &core.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    let preview = core
        .transfer
        .open(&b, &path, SecretString::new(PASSPHRASE), &core.vault)
        .await
        .unwrap();
    assert_eq!(preview.workspace.as_deref(), Some("Globex"));
    let names: Vec<&str> = preview.sessions.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["globex-db"], "only the shown workspace's");

    // Into a new workspace: everything is new there; the shown workspace and Acme don't change.
    let made = core
        .import_into_new_workspace(
            WorkspaceInput {
                name: "Globex copy".into(),
                color: None,
            },
            TransferCommit {
                preview_id: preview.id,
                sessions: vec![ItemChoice {
                    index: 0,
                    action: ItemAction::Import,
                }],
                known_hosts: vec![],
                secrets: vec![],
                favourites: vec![],
                groups: vec![],
                catalog: Default::default(),
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
                folder_defaults: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(made.report.sessions.added, 1, "{:?}", made.report);
    assert!(!made.workspace.current, "the shown workspace doesn't change");
    let copy = ctx_of(&core, &made.workspace);
    let copied: Vec<String> = core
        .sessions
        .list(&copy, &SessionFilter::default())
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(copied, ["globex-db"]);
    assert_eq!(
        core.sessions.list(&b, &SessionFilter::default()).await.unwrap().len(),
        1
    );
    assert_eq!(
        core.sessions
            .list(&acme, &SessionFilter::default())
            .await
            .unwrap()
            .len(),
        1
    );
    let copy_log = audit_of(&core, &copy).await;
    assert!(copy_log.iter().any(|e| e.event == "workspace_created"));
    assert!(copy_log
        .iter()
        .any(|e| e.event == "transfer_imported" || e.event == "session_changed"));
    assert!(core.store.verify_audit_chain(&copy).await.unwrap().ok);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- switching ----------------------------------------------------------------------------------------------------

async fn ssh_core(vmware: FakeVmware) -> Core {
    let core = Setup::new(vmware).with_real_vault().with_ssh().build().await;
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 5,
        slow_retry: Duration::from_millis(200),
        slow_attempts: 0,
        wake_spread: Duration::from_millis(50),
        keepalive_interval: None,
        keepalive_max: 2,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    });
    core
}

/// A session in the shown workspace to `server`, logging in with a password saved there; the server's key trusted.
async fn session_to(core: &Core, server: &TestSshServer, password: &str, name: &str) -> (Uuid, SecretId) {
    let ctx = core.ctx();
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&ctx, &key, None).await.unwrap();
    let secret = core
        .vault
        .add(
            &ctx,
            SecretKind::Password,
            &format!("alice on {name}"),
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    let session = core
        .sessions
        .create(&ctx, session_input(name, "127.0.0.1", server.port(), Some(secret)))
        .await
        .unwrap()
        .id;
    (session, secret)
}

async fn open_connected(core: &Core, session: Uuid) -> (Uuid, tokio::sync::mpsc::Receiver<TerminalEvent>) {
    let handle = core
        .terminals
        .open(&core.ctx(), session, PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    let mut output = handle.output;
    tokio::spawn(async move { while output.recv().await.is_some() {} });
    let mut events = handle.events;
    timeout(WAIT, async {
        loop {
            if let TerminalEvent::Status { status } = events.recv().await.expect("events") {
                if status == TerminalStatus::Connected {
                    return;
                }
            }
        }
    })
    .await
    .expect("connected in time");
    (handle.id, events)
}

#[tokio::test]
async fn switching_waits_for_running_jobs_then_closes_terminals_multiexec_and_approvals() {
    let fake = listed(FakeVmware::default(), &["web", "db"]).with_power_delay(Duration::from_millis(800));
    let core = ssh_core(fake).await;
    let acme = core.ctx();
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start().await.with_password("alice", &password);
    let (session, acme_secret) = session_to(&core, &server, &password, "acme01").await;
    let (pane, _events) = open_connected(&core, session).await;
    core.multiexec.set_targets(vec![pane]).await.unwrap();
    assert!(core.multiexec.status().await.unwrap().on);
    // An approval waiting for its answer: suspending 2 VMs is High.
    let SubmitOutcome::NeedsApproval { request } = core
        .bus
        .submit(
            &acme,
            Command::VmPower {
                targets: vec![vm("web"), vm("db")],
                op: PowerOp::Suspend,
            },
        )
        .await
        .unwrap()
    else {
        panic!("High");
    };

    // A job still running refuses the switch, and says so.
    let globex = create(&core, "Globex").await;
    let mut jobs = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = core
        .bus
        .submit(
            &acme,
            Command::VmPower {
                targets: vec![vm("web")],
                op: PowerOp::Start { gui: false },
            },
        )
        .await
        .unwrap()
    else {
        panic!("Low");
    };
    let preview = core.switch_preview(globex.id).await.unwrap();
    assert_eq!(
        (
            preview.open_jobs,
            preview.terminals,
            preview.multiexec,
            preview.approvals
        ),
        (1, 1, true, 1)
    );
    let busy = core.switch_workspace(globex.id).await;
    assert!(matches!(busy, Err(CoreError::WorkspaceBusy { .. })), "{busy:?}");
    assert_eq!(core.ctx(), acme, "nothing changed");
    assert_eq!(core.terminals.open_count(), 1);
    // Only the workspace a job was started in can cancel it.
    assert!(!core.jobs.cancel_in(globex.id, job_id));
    wait_finished(&mut jobs, job_id).await;

    switch(&core, &globex).await;
    assert_eq!(core.terminals.open_count(), 0, "Acme's terminal closed");
    assert!(!core.multiexec.status().await.unwrap().on);
    assert!(core.bus.pending_approvals().is_empty());
    assert!(matches!(
        core.bus
            .approve(request.id, remotely_core::command_bus::ApprovalAnswers::default())
            .await,
        Err(CoreError::UnknownApproval(_))
    ));
    let acme_log = audit_of(&core, &acme).await;
    for event in ["terminal_closed", "approval_cancelled", "workspace_left"] {
        assert!(acme_log.iter().any(|e| e.event == event), "{event} in Acme's log");
    }
    let globex_log: Vec<String> = audit_of(&core, &core.ctx())
        .await
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert_eq!(globex_log, ["workspace_opened", "workspace_created"]);

    // In Globex, Acme's password can't be typed into a terminal, even with the vault password.
    let (globex_session, _) = session_to(&core, &server, &password, "globex01").await;
    let (globex_pane, _globex_events) = open_connected(&core, globex_session).await;
    let typed = core
        .terminals
        .type_secret(
            &core.ctx(),
            globex_pane,
            acme_secret,
            true,
            Some(&SecretString::new(VAULT_PASSWORD)),
        )
        .await;
    assert!(typed.is_err(), "{typed:?}");
    // Nor can Acme's closed pane be a target from Globex.
    assert!(core.terminals.target(&core.ctx(), pane).await.is_err());
    core.terminals.close_all().await;
}

// ---- schedules ----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_hidden_workspaces_schedules_run_audited_in_it_and_its_events_name_it() {
    use remotely_core::fakes::clock::{FakeClock, FakeZone};
    use remotely_core::schedules::{ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleTarget, Timing, WallTime};
    use time::macros::datetime;

    let core = Setup::new(listed(FakeVmware::default(), &["web"])).build().await;
    let acme = core.ctx();
    let clock = Arc::new(FakeClock::new(
        datetime!(2026-10-26 10:00 UTC),
        FakeZone::central_europe(),
    ));
    core.schedules().set_clock(clock.clone());
    let saved = core
        .schedules()
        .save(ScheduleInput {
            id: None,
            name: "hourly snapshot".into(),
            spec: ScheduleSpec {
                action: ScheduleAction::Snapshot { keep: None },
                targets: vec![ScheduleTarget::Vm { vm_key: vmx("web") }],
                timing: Timing::Daily {
                    at: WallTime::new(12, 0).unwrap(),
                },
            },
        })
        .await
        .unwrap();
    assert!(saved.approval.is_none(), "taking a snapshot of one VM is Low");

    let globex = create(&core, "Globex").await;
    switch(&core, &globex).await;
    assert!(core.schedules().list().await.unwrap().is_empty(), "Globex has none");
    let mut scoped = core.schedules().subscribe_scoped();
    clock.advance(time::Duration::hours(1));
    let report = core.schedules().tick().await.unwrap();
    core.schedules().wait_runs().await;
    assert_eq!(report.started, 1, "Acme's schedule ran while Globex is shown");
    let acme_log = audit_of(&core, &acme).await;
    assert!(acme_log
        .iter()
        .any(|e| e.event == "schedule_run_started" || e.event == "job_started"));
    assert!(audit_of(&core, &core.ctx())
        .await
        .iter()
        .all(|e| !e.event.starts_with("schedule") && e.event != "job_started"));
    let (workspace, _) = scoped.try_recv().unwrap();
    assert_eq!(workspace, acme.workspace_id, "the UI filters the events by workspace");

    // An archived workspace's schedules don't run.
    let home = core
        .workspaces
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.name == "Default")
        .unwrap();
    core.workspaces.archive(home.id).await.unwrap();
    clock.advance(time::Duration::days(1));
    assert_eq!(core.schedules().tick().await.unwrap().started, 0);
}

#[tokio::test]
async fn a_hidden_workspaces_vms_keep_their_host_history_so_its_idle_auto_suspend_still_works() {
    use remotely_core::adapters::host_counters::VmProcess;
    use remotely_core::adapters::vmware::VmxInfo;
    use remotely_core::command_bus::ApprovalAnswers;
    use remotely_core::fakes::clock::{FakeClock, FakeZone};
    use remotely_core::metrics::history::{HistorySource, MINUTE_MS};
    use remotely_core::metrics::MetricSource;
    use remotely_core::policy::ApprovalStep;
    use remotely_core::schedules::{ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleTarget, Timing};
    use time::macros::datetime;

    let mut fake = listed(FakeVmware::with_running([vmx("web"), vmx("db")]), &["web", "db"]);
    for name in ["web", "db"] {
        fake = fake.with_vmx(
            &vmx(name),
            VmxInfo {
                display_name: Some(name.into()),
                num_vcpus: Some(2),
                memsize_mb: Some(2048),
                ..Default::default()
            },
        );
    }
    let setup = Setup::new(fake);
    let vmware = Arc::clone(&setup.vmware);
    let processes = Arc::clone(&setup.host.processes);
    let core = setup.build().await;
    let acme = core.ctx();
    let now = datetime!(2026-10-26 10:00 UTC);
    let clock = Arc::new(FakeClock::new(now, FakeZone::central_europe()));
    core.schedules().set_clock(clock.clone());

    // Acme suspends its VMs once they have been idle for 30 minutes (2 VMs: High, approved at the save).
    let saved = core
        .schedules()
        .save(ScheduleInput {
            id: None,
            name: "idle lab".into(),
            spec: ScheduleSpec {
                action: ScheduleAction::Suspend,
                targets: vec![
                    ScheduleTarget::Vm { vm_key: vmx("web") },
                    ScheduleTarget::Vm { vm_key: vmx("db") },
                ],
                timing: Timing::Idle {
                    minutes: 30,
                    cpu_below_pct: 5,
                },
            },
        })
        .await
        .unwrap();
    let request = saved.approval.expect("High");
    let mut answers = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => answers.typed_target_count = Some(*expected),
            ApprovalStep::Reason => answers.reason = Some("idle lab VMs".into()),
            ApprovalStep::SafetySnapshot { .. } => answers.safety_snapshot = Some(false),
            _ => {}
        }
    }
    core.schedules().approve(request.id, answers).await.unwrap();

    // Globex is shown while the collector runs for 31 minutes: web idle (0.1% of this PC is 0.8% of its 2 vCPUs),
    // db busy (40%).
    let globex = create(&core, "Globex").await;
    switch(&core, &globex).await;
    let globex_ctx = core.ctx();
    let process = |name: &str, host_cpu: f64| VmProcess {
        pid: 1,
        vmx_path: Some(vmx(name)),
        name: None,
        cpu_pct: Some(host_cpu),
        working_set_bytes: Some(1 << 30),
        read_bps: Some(0.0),
        write_bps: Some(0.0),
    };
    *processes.lock().unwrap() = vec![process("web", 0.1), process("db", 5.0)];
    let start = (now.unix_timestamp() * 1000) - 31 * MINUTE_MS;
    for round in 0..=62 {
        core.metrics.collect_once_at(start + round * 30_000).await;
    }

    // Acme's history has both VMs' minutes; Globex's has none of them, and its dashboard shows neither.
    let from = start / MINUTE_MS;
    let to = from + 40;
    for name in ["web", "db"] {
        let key = vmx(name);
        let rows = core
            .store
            .read_history(&acme, HistorySource::Host, &key, from, to)
            .await
            .unwrap();
        assert!(rows.len() >= 30, "{name}: {} minutes in Acme", rows.len());
        assert!(core
            .store
            .read_history(&globex_ctx, HistorySource::Host, &key, from, to)
            .await
            .unwrap()
            .is_empty());
        assert!(core.metrics.hub().latest(MetricSource::Host, &key).is_none());
        assert!(core
            .metrics
            .hub()
            .latest(MetricSource::Host, &key.to_lowercase())
            .is_none());
    }

    // Acme's schedule suspends the idle VM, audited in Acme, while Globex is still shown.
    let report = core.schedules().tick().await.unwrap();
    core.schedules().wait_runs().await;
    assert_eq!(report.started, 1);
    assert_eq!(common::running(&vmware), ["db"]);
    assert!(audit_of(&core, &acme)
        .await
        .iter()
        .any(|e| e.event == "job_started" && e.action.to_lowercase().contains("suspend")));
    assert!(audit_of(&core, &globex_ctx)
        .await
        .iter()
        .all(|e| e.event != "job_started"));
}

#[tokio::test]
async fn nothing_acts_on_an_unassigned_vm_until_a_workspace_adds_it() {
    use remotely_core::command_bus::SnapshotOp;
    use remotely_core::deploy::service::CloneRequest;
    use remotely_core::domain::TargetRef;
    use remotely_core::vm_settings::{VmConfigEdit, VmLifecycleOp};

    let scanned = common::temp_folder("workspaces-unassigned");
    let late = scanned.join("late").join("late.vmx").display().to_string();
    let fake = listed(FakeVmware::default(), &["web"]).in_folder(&scanned.display().to_string(), &late);
    let setup = Setup::new(fake);
    let vmware = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let acme = core.ctx();
    // Two workspaces: a VM found now waits in Unassigned.
    create(&core, "Globex").await;
    core.set_scan_folders(vec![scanned.clone()]).await.unwrap();
    let report = core.inventory.refresh(&acme).await.unwrap();
    assert_eq!(report.unassigned.len(), 1);

    let target = || vec![TargetRef::Vm { vmx_path: late.clone() }];
    let power = Command::VmPower {
        targets: target(),
        op: PowerOp::Start { gui: false },
    };
    let commands = [
        ("power", power.clone()),
        (
            "snapshot",
            Command::VmSnapshot {
                targets: target(),
                op: SnapshotOp::Take { name: "before".into() },
            },
        ),
        (
            "settings",
            Command::VmConfig {
                targets: target(),
                edit: VmConfigEdit::Resources {
                    vcpus: Some(4),
                    cores_per_socket: None,
                    memory_mb: None,
                    nested_virtualization: None,
                },
            },
        ),
        (
            "delete",
            Command::VmLifecycle {
                targets: target(),
                op: VmLifecycleOp::Delete,
            },
        ),
        (
            "protect",
            Command::VmProtect {
                targets: target(),
                protected: true,
            },
        ),
    ];
    for (what, command) in commands {
        match core.bus.submit(&acme, command.clone()).await {
            Err(err @ CoreError::VmUnassigned(_)) => {
                let message = err.to_string();
                assert!(
                    message.contains("'late'") && message.contains("add it to this workspace first"),
                    "{what}: {message}"
                );
                assert_eq!(err.code(), "vm_unassigned");
            }
            other => panic!("{what}: {other:?}"),
        }
        assert!(
            matches!(core.bus.preview(&acme, &command).await, Err(CoreError::VmUnassigned(_))),
            "{what}: the approval preview is refused too"
        );
    }
    // Reads by its key, and a clone of it, are refused the same way.
    assert!(matches!(
        core.host_details.vm_specs(&acme, &late).await,
        Err(CoreError::VmUnassigned(_))
    ));
    assert!(matches!(
        core.insight.timeline(&late, None, None).await,
        Err(CoreError::VmUnassigned(_))
    ));
    let clone = CloneRequest {
        vm_keys: vec![late.clone()],
        naming_pattern: "{template}-clone".into(),
        folder: None,
        environment: None,
    };
    assert!(matches!(
        core.deploy.check_clone(&acme, &clone).await,
        Err(CoreError::VmUnassigned(_))
    ));
    assert!(matches!(
        core.deploy.submit_clone(&acme, &clone).await,
        Err(CoreError::VmUnassigned(_))
    ));
    // Nothing ran on it, and nothing added it on the way.
    assert!(
        vmware.calls().iter().all(|c| !c.contains("late")),
        "{:?}",
        vmware.calls()
    );
    assert_eq!(core.inventory.unassigned().len(), 1);
    assert!(audit_of(&core, &acme).await.iter().all(|e| e.event != "vm_assigned"));

    // Once Acme adds it (audited), the same start goes through.
    core.inventory.claim(&acme, std::slice::from_ref(&late)).await.unwrap();
    assert!(audit_of(&core, &acme).await.iter().any(|e| e.event == "vm_assigned"));
    let mut jobs = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&acme, power).await.unwrap() else {
        panic!("starting one VM is Low");
    };
    assert_eq!(wait_finished(&mut jobs, job_id).await, JobStatus::Succeeded);

    // A VM taken out of a workspace is unassigned again, there too: Acme can no longer clone it.
    core.inventory
        .release(&acme, std::slice::from_ref(&late))
        .await
        .unwrap();
    let ask = CloneRequest {
        vm_keys: vec![late.clone()],
        ..clone
    };
    assert!(matches!(
        core.deploy.check_clone(&acme, &ask).await,
        Err(CoreError::VmUnassigned(_))
    ));
}
