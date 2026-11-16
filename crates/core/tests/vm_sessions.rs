//! QL-29: SSH sessions made from VMs, end to end on a core with fake hypervisors. A VM Remotely deployed gets the
//! deploy's user and key from the job journal; any other VM its name, address and labels. The refusals (a session
//! linked already, not running, no address), the bulk save (each session audited and linked by hand), the read-only
//! lock and another workspace's VM. Image files and VM folders are made at run time in the system temp folder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::catalog::{
    AfterDeploy, CloneMode, HashProgress, Image, ImageInput, Network, SourceInput, TemplateInput,
};
use remotely_core::command_bus::{ApprovalAnswers, SubmitOutcome};
use remotely_core::deploy::runner::DeployTuning;
use remotely_core::deploy::service::{DeployFrom, DeployRequest};
use remotely_core::domain::{Environment, PowerState};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::ApprovalStep;
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::vault::SecretString;
use remotely_core::vm_links::VmLink;
use remotely_core::vm_sessions::VmSessionDraft;
use remotely_core::workspaces::WorkspaceInput;
use remotely_core::{Core, CoreError};
use uuid::Uuid;

const LOCKED: Presentation = Presentation {
    enabled: true,
    read_only: true,
};

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

fn no_progress() -> Arc<dyn Fn(HashProgress) + Send + Sync> {
    Arc::new(|_| {})
}

fn fast(core: &Core) {
    core.set_deploy_tuning(DeployTuning {
        ip_poll: Duration::from_millis(10),
        ip_wait_cap: Some(Duration::from_millis(200)),
        cleanup_tries: 3,
        cleanup_pause: Duration::from_millis(10),
        ..DeployTuning::default()
    });
}

/// Deploys one VM, `web-1`, from a cloud image template with alice, a generated key, Lab and `web`; its deploy makes
/// no session. Returns the key.
async fn deploy_web(core: &Core, lab: &Path, image_file: &Path) -> remotely_core::vault::SecretId {
    let ctx = &core.ctx();
    let image: Image = core
        .catalog
        .add_image(
            ctx,
            Uuid::new_v4(),
            ImageInput {
                name: "Noble".into(),
                source: SourceInput::CloudImage {
                    path: image_file.display().to_string(),
                },
                hypervisors: vec![],
                os_profile: "ubuntu".into(),
                notes: None,
            },
            no_progress(),
        )
        .await
        .unwrap();
    let key = core
        .keys
        .generate(
            ctx,
            GenerateKey {
                label: "deploy key".into(),
                key_type: KeyType::Ed25519,
                comment: "alice@example.com".into(),
            },
        )
        .await
        .unwrap()
        .id;
    let template = core
        .catalog
        .add_template(
            ctx,
            TemplateInput {
                name: "web".into(),
                image_id: image.id,
                size_id: "gp.medium".into(),
                hypervisor: Hypervisor::Vmware,
                vm_folder: Some(lab.display().to_string()),
                network: Network::Vmnet { number: 3 },
                ssh_key_id: Some(key),
                naming_pattern: "web-{n}".into(),
                default_count: 1,
                environment: Environment::Lab,
                tags: vec!["web".into()],
                after_deploy: AfterDeploy {
                    create_session: false,
                    link_session: false,
                    clean_snapshot: false,
                    open_console: false,
                },
                guest_user: Some("alice".into()),
                packages: vec![],
                clone_mode: CloneMode::Full,
                install_config_id: None,
            },
        )
        .await
        .unwrap();
    let request = DeployRequest {
        from: DeployFrom::Template { id: template.id },
        count: 1,
        naming_pattern: None,
        host_adapter: None,
        guest_password_id: None,
        vm_values: Vec::new(),
        address_pool_id: None,
        install_minutes: None,
    };
    let SubmitOutcome::NeedsApproval { request } = core.deploy.submit(ctx, &request).await.unwrap() else {
        panic!("a deploy asks for approval");
    };
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("lab build".into()),
        safety_snapshot: None,
        vault_password: request
            .steps
            .contains(&ApprovalStep::VaultReauth)
            .then(|| SecretString::new(VAULT_PASSWORD)),
        change_id: None,
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), core.jobs.wait(job))
        .await
        .expect("the deploy finished in time")
        .unwrap();
    assert_eq!(status, JobStatus::Succeeded);
    key
}

async fn vm_id(core: &Core, key: &str) -> String {
    core.store.find_vm(&core.ctx(), key).await.unwrap().unwrap().id
}

fn one(drafts: &[VmSessionDraft], vm_id: &str) -> VmSessionDraft {
    drafts.iter().find(|d| d.vm_id == vm_id).cloned().unwrap()
}

fn session(name: &str, host: &str) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: Some("bob".into()),
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
        kind: Default::default(),
    }
}

#[tokio::test]
async fn a_deployed_vm_gets_its_deploys_user_and_key_and_its_own_labels() {
    let dir = temp_folder("vm-sessions-deploy");
    let lab = dir.join("lab");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let web1 = lab.join("web-1").join("web-1.vmx").display().to_string();
    let core = Setup::new(FakeVmware::default().with_ip(&web1, "192.0.2.21"))
        .with_real_vault()
        .build()
        .await;
    fast(&core);
    let ctx = &core.ctx();
    let key = deploy_web(&core, &lab, &image_file).await;
    assert!(
        core.sessions.list(ctx, &Default::default()).await.unwrap().is_empty(),
        "the deploy made no session"
    );
    core.inventory.refresh(ctx).await.unwrap();
    let id = vm_id(&core, &web1).await;

    // The draft: the VM's name, its address, port 22, the deploy's user and key, the VM's labels.
    let drafts = core.vm_session_drafts(std::slice::from_ref(&id)).await.unwrap();
    assert_eq!(drafts.len(), 1);
    let draft = drafts[0].session.clone().expect("a draft");
    assert_eq!(draft.name, "web-1");
    assert_eq!(draft.host, "192.0.2.21");
    assert_eq!(draft.port, 22);
    assert_eq!(draft.username.as_deref(), Some("alice"));
    assert_eq!(
        draft.auth,
        SessionAuth::Key {
            key_id: Some(key),
            passphrase_id: None
        }
    );
    assert_eq!(draft.environment, Environment::Lab);
    assert_eq!(draft.tags, ["web"]);
    assert_eq!(draft.vm_id, id);
    assert_eq!(draft.deploy.as_deref(), Some("launch template 'web'"));

    // Saved together: audited as any session, linked to the VM by hand.
    let audit_before = core.store.recent_audit(ctx, 1000).await.unwrap().len();
    let made = core.create_vm_sessions(std::slice::from_ref(&id)).await.unwrap();
    assert_eq!(made.len(), 1);
    assert_eq!(made[0].error, None);
    let saved = core.sessions.get(ctx, made[0].session_id.unwrap()).await.unwrap();
    assert_eq!(saved.name, "web-1");
    assert_eq!(saved.host, "192.0.2.21");
    assert_eq!(saved.username.as_deref(), Some("alice"));
    assert_eq!(saved.vm_id.as_deref(), Some(id.as_str()));
    assert_eq!(saved.vm_link, Some(VmLink::Manual));
    assert_eq!(saved.environment, Environment::Lab);
    let audit = core.store.recent_audit(ctx, 1000).await.unwrap();
    assert!(audit.len() > audit_before);
    assert!(
        audit
            .iter()
            .any(|e| e.action.contains("Created session") && e.action.contains("web-1")),
        "{:?}",
        audit.iter().map(|e| &e.action).collect::<Vec<_>>()
    );

    // Once linked, it gets no second one.
    let again = core.vm_session_drafts(std::slice::from_ref(&id)).await.unwrap();
    assert!(again[0].session.is_none());
    assert!(
        again[0]
            .refused
            .as_deref()
            .unwrap()
            .contains("SSH session already: 'web-1'"),
        "{:?}",
        again[0].refused
    );
    let again = core.create_vm_sessions(std::slice::from_ref(&id)).await.unwrap();
    assert_eq!(again[0].session_id, None);
    assert_eq!(core.sessions.list(ctx, &Default::default()).await.unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_key_the_vault_no_longer_has_is_left_out() {
    let dir = temp_folder("vm-sessions-key");
    let lab = dir.join("lab");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let web1 = lab.join("web-1").join("web-1.vmx").display().to_string();
    let core = Setup::new(FakeVmware::default().with_ip(&web1, "192.0.2.21"))
        .with_real_vault()
        .build()
        .await;
    fast(&core);
    let ctx = &core.ctx();
    let key = deploy_web(&core, &lab, &image_file).await;
    core.inventory.refresh(ctx).await.unwrap();
    core.vault.delete(ctx, key).await.unwrap();

    let id = vm_id(&core, &web1).await;
    let drafts = core.vm_session_drafts(std::slice::from_ref(&id)).await.unwrap();
    let draft = drafts[0].session.clone().unwrap();
    assert_eq!(
        draft.username.as_deref(),
        Some("alice"),
        "the user still comes from the deploy"
    );
    assert_eq!(draft.auth, SessionAuth::Password { password_id: None });
    assert!(
        drafts[0].notes.iter().any(|n| n.contains("no longer in the vault")),
        "{:?}",
        drafts[0].notes
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// web reports an address; db's is a saved session's host (linked on the first refresh); bare runs without one
/// (no open-vm-tools); off isn't running.
fn lab() -> FakeVmware {
    let mut fake = FakeVmware::with_running([vmx("web"), vmx("db"), vmx("bare")]);
    for name in ["web", "db", "bare", "off"] {
        fake = fake.in_library(&vmx(name), Some(name));
    }
    fake.with_ip(&vmx("web"), "192.0.2.10")
        .with_ip(&vmx("db"), "192.0.2.20")
}

#[tokio::test]
async fn any_vm_gets_its_name_address_and_labels_and_the_rest_says_why_not() {
    let core = Setup::new(lab()).unlisted().build().await;
    let ctx = &core.ctx();
    core.sessions.create(ctx, session("db", "192.0.2.20")).await.unwrap();
    core.inventory.refresh(ctx).await.unwrap();
    core.inventory
        .set_environment(ctx, &[vmx("web")], Environment::Staging)
        .await
        .unwrap();
    let [web, db, bare, off] = [
        vm_id(&core, &vmx("web")).await,
        vm_id(&core, &vmx("db")).await,
        vm_id(&core, &vmx("bare")).await,
        vm_id(&core, &vmx("off")).await,
    ];
    let asked = [
        web.clone(),
        db.clone(),
        bare.clone(),
        off.clone(),
        "no-such-vm".to_owned(),
        web.clone(),
    ];
    let drafts = core.vm_session_drafts(&asked).await.unwrap();
    assert_eq!(drafts.len(), 5, "a VM asked twice once");
    assert_eq!(
        drafts.iter().map(|d| d.vm_id.as_str()).collect::<Vec<_>>(),
        [web.as_str(), db.as_str(), bare.as_str(), off.as_str(), "no-such-vm"],
        "in the order asked"
    );

    // Not deployed by Remotely: the user and login are left to fill in.
    let draft = one(&drafts, &web).session.unwrap();
    assert_eq!(
        (draft.name.as_str(), draft.host.as_str(), draft.port),
        ("web", "192.0.2.10", 22)
    );
    assert_eq!(draft.username, None);
    assert_eq!(draft.auth, SessionAuth::Password { password_id: None });
    assert_eq!(draft.environment, Environment::Staging);
    assert_eq!(draft.deploy, None);

    let why = |id: &str| one(&drafts, id).refused.unwrap();
    assert!(why(&db).contains("SSH session already: 'db'"), "{}", why(&db));
    assert!(why(&bare).contains("install open-vm-tools"), "{}", why(&bare));
    assert!(why(&off).contains("isn't running"), "{}", why(&off));
    assert!(why("no-such-vm").contains("isn't in this workspace"));
    assert!(drafts
        .iter()
        .filter(|d| d.refused.is_some())
        .all(|d| d.session.is_none()));

    // The read-only lock refuses the save; the drafts are reads.
    core.presentation.set(LOCKED).await.unwrap();
    assert!(core.vm_session_drafts(std::slice::from_ref(&web)).await.is_ok());
    assert!(matches!(
        core.create_vm_sessions(std::slice::from_ref(&web)).await,
        Err(CoreError::ReadOnlyLock { .. })
    ));
    assert_eq!(core.sessions.list(ctx, &Default::default()).await.unwrap().len(), 1);
    core.presentation.set(Presentation::default()).await.unwrap();

    // Saved together: the ones that get a session, and why the others don't.
    let made = core.create_vm_sessions(&[web.clone(), bare.clone()]).await.unwrap();
    assert_eq!(made.len(), 2);
    let web_made = made.iter().find(|m| m.vm_id == web).unwrap();
    assert_eq!(web_made.session_name.as_deref(), Some("web"));
    let bare_made = made.iter().find(|m| m.vm_id == bare).unwrap();
    assert_eq!(bare_made.session_id, None);
    assert!(bare_made.error.as_deref().unwrap().contains("open-vm-tools"));
    let saved = core.sessions.get(ctx, web_made.session_id.unwrap()).await.unwrap();
    assert_eq!(saved.vm_id.as_deref(), Some(web.as_str()));
    assert_eq!(saved.vm_link, Some(VmLink::Manual));
    assert!(saved.username.is_none());
}

#[tokio::test]
async fn a_virtualbox_guest_without_an_address_needs_the_guest_additions() {
    const WEB: &str = "3f0c1a2b-1111-4222-8333-444455556666";
    const BARE: &str = "6b6b6b6b-3333-4444-8555-666677778888";
    let core = Setup::new(FakeVmware::default())
        .with_virtualbox(
            FakeVirtualBox::new()
                .with_vm(WEB, "vbox-web", PowerState::Running)
                .with_ip(WEB, "192.0.2.30")
                .with_vm(BARE, "vbox-bare", PowerState::Running),
        )
        .build()
        .await;
    let (web, bare) = (vm_id(&core, WEB).await, vm_id(&core, BARE).await);
    let drafts = core.vm_session_drafts(&[web.clone(), bare.clone()]).await.unwrap();
    let draft = one(&drafts, &web).session.unwrap();
    assert_eq!((draft.name.as_str(), draft.host.as_str()), ("vbox-web", "192.0.2.30"));
    let why = one(&drafts, &bare).refused.unwrap();
    assert!(why.contains("Guest Additions"), "{why}");
}

#[tokio::test]
async fn another_workspaces_vm_gets_no_session_here() {
    let core = Setup::new(lab()).build().await;
    let home_ctx = core.ctx();
    let web = vm_id(&core, &vmx("web")).await;
    let globex = core
        .workspaces
        .create(WorkspaceInput {
            name: "Globex".into(),
            color: Some("teal".into()),
        })
        .await
        .unwrap();
    core.switch_workspace(globex.id).await.unwrap();
    assert_eq!(core.ctx().workspace_id, globex.id);

    let drafts = core.vm_session_drafts(std::slice::from_ref(&web)).await.unwrap();
    assert!(drafts[0].session.is_none());
    assert!(drafts[0].refused.is_some());
    let made = core.create_vm_sessions(std::slice::from_ref(&web)).await.unwrap();
    assert_eq!(made[0].session_id, None);
    assert!(core
        .sessions
        .list(&core.ctx(), &Default::default())
        .await
        .unwrap()
        .is_empty());
    assert!(core
        .sessions
        .list(&home_ctx, &Default::default())
        .await
        .unwrap()
        .is_empty());
}
