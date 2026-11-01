//! Containers (CT-01, CT-02) end to end on fake engines: marking hosts, reads, and every change through
//! the command bus with its tier, Prod, protected hosts, the impact preview, the audit log, the
//! read-only lock, sudo, and FD-07 carrying the marks. No real container, host or Docker Desktop is
//! touched: [`FakeContainers`] holds the engines (tests over SSH are in `containers_ssh.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::{vbox_vm, vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::containers::{
    ContainerId, ContainerState, EngineKind, ImageId, LogQuery, PruneWhat, VolumeName,
};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, ContainerOp, SubmitOutcome};
use remotely_core::containers::{MarkInput, SudoMode};
use remotely_core::domain::{ContainerHost, ContainerObject, Environment, PowerState, TargetRef};
use remotely_core::fakes::containers::{FakeContainer, Fixture};
use remotely_core::fakes::{FakeContainers, FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use uuid::Uuid;

const DOCKER: EngineKind = EngineKind::Docker;
const PODMAN: EngineKind = EngineKind::Podman;

async fn core_with(containers: FakeContainers) -> Core {
    Setup::new(FakeVmware::default().in_library(&vmx("web"), Some("web")))
        .with_real_vault()
        .with_containers(Arc::new(containers))
        .build()
        .await
}

fn input(name: &str, env: Environment, auth: SessionAuth) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: format!("{name}.example.com"),
        port: 22,
        username: Some("alice".into()),
        auth,
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: env,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: Default::default(),
    }
}

async fn session(core: &Core, name: &str, env: Environment) -> Uuid {
    core.sessions
        .create(&core.ctx(), input(name, env, SessionAuth::Agent))
        .await
        .unwrap()
        .id
}

async fn mark(core: &Core, id: Uuid, engine: EngineKind, sudo: SudoMode) {
    core.containers
        .marks()
        .set(&core.ctx(), id, &[MarkInput { engine, sudo }])
        .await
        .unwrap();
}

/// A session `name` marked as a Docker host whose engine holds the sample fixture.
async fn docker_host(name: &str, env: Environment) -> (Core, FakeContainers, Uuid) {
    let fake = FakeContainers::default().with_host(name, DOCKER, Fixture::sample());
    let core = core_with(fake.clone()).await;
    let id = session(&core, name, env).await;
    mark(&core, id, DOCKER, SudoMode::Off).await;
    (core, fake, id)
}

fn host(session_id: Uuid) -> ContainerHost {
    ContainerHost::Session { session_id }
}

fn id_of(fake: &FakeContainers, host: &str, name: &str) -> String {
    fake.fixture(host, DOCKER).container(name).unwrap().id.clone()
}

fn container(session_id: Uuid, id: &str) -> TargetRef {
    TargetRef::Container {
        host: host(session_id),
        engine: DOCKER,
        object: ContainerObject::Container {
            id: ContainerId::parse(id).unwrap(),
        },
    }
}

fn engine_of(session_id: Uuid, engine: EngineKind) -> TargetRef {
    TargetRef::Container {
        host: host(session_id),
        engine,
        object: ContainerObject::Engine,
    }
}

fn op(targets: Vec<TargetRef>, op: ContainerOp) -> Command {
    Command::Container { targets, op }
}

fn answers(request: &ApprovalRequest) -> ApprovalAnswers {
    let mut a = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => a.typed_target_count = Some(*expected),
            ApprovalStep::Reason => a.reason = Some("CHG-1234".into()),
            ApprovalStep::VaultReauth => a.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            _ => {}
        }
    }
    a
}

/// Submits, approving whatever it asks, and waits for the job.
async fn run(core: &Core, command: Command) -> (Uuid, JobStatus) {
    let mut events = core.jobs.subscribe();
    let job = match core.bus.submit(&core.ctx(), command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core.bus.approve(request.id, answers(&request)).await.unwrap(),
    };
    (job, wait_finished(&mut events, job).await)
}

async fn needs_approval(core: &Core, command: Command) -> ApprovalRequest {
    match core.bus.submit(&core.ctx(), command).await.unwrap() {
        SubmitOutcome::NeedsApproval { request } => request,
        SubmitOutcome::Queued { summary, .. } => panic!("{summary} ran without asking"),
    }
}

// ---- Hosts and marks -----------------------------------------------------------------------------

#[tokio::test]
async fn marking_a_session_as_a_container_host_is_checked_and_audited_like_a_session_edit() {
    let core = core_with(FakeContainers::default()).await;
    let ctx = &core.ctx();
    let web = session(&core, "web01", Environment::Lab).await;
    let marks = core.containers.marks();
    assert!(
        core.containers.hosts(ctx).await.unwrap().is_empty(),
        "nothing marked yet"
    );

    let sudo_pw = core
        .vault
        .add(ctx, SecretKind::Password, "web01 sudo", SecretString::new("pw-example"))
        .await
        .unwrap()
        .id;
    marks
        .set(
            ctx,
            web,
            &[
                MarkInput {
                    engine: PODMAN,
                    sudo: SudoMode::Off,
                },
                MarkInput {
                    engine: DOCKER,
                    sudo: SudoMode::Password {
                        password_id: Some(sudo_pw),
                    },
                },
            ],
        )
        .await
        .unwrap();
    let hosts = core.containers.hosts(ctx).await.unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].name, "web01");
    assert_eq!(hosts[0].hostname.as_deref(), Some("web01.example.com"));
    let engines: Vec<(EngineKind, &str)> = hosts[0].engines.iter().map(|e| (e.engine, e.runs.as_str())).collect();
    assert_eq!(
        engines,
        [
            (DOCKER, "with sudo (vault password 'web01 sudo')"),
            (PODMAN, "as the login user")
        ]
    );
    let audit = core.store.recent_audit(ctx, 5).await.unwrap();
    let entry = &audit[0];
    assert_eq!(entry.event, "session_changed");
    assert_eq!(entry.action, "Marked 'web01' as a container host");
    let detail = entry.detail.as_deref().unwrap();
    assert!(
        detail.contains("Docker added, with sudo (vault password 'web01 sudo')"),
        "{detail}"
    );
    assert!(detail.contains("Podman added, as the login user"), "{detail}");
    assert!(!detail.contains("pw-example"), "never the password");
    assert!(entry.targets_json.contains(&web.to_string()));

    // The same again: nothing changes, nothing is logged.
    let before = core.store.recent_audit(ctx, 100).await.unwrap().len();
    marks
        .set(
            ctx,
            web,
            &[
                MarkInput {
                    engine: DOCKER,
                    sudo: SudoMode::Password {
                        password_id: Some(sudo_pw),
                    },
                },
                MarkInput {
                    engine: PODMAN,
                    sudo: SudoMode::Off,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(core.store.recent_audit(ctx, 100).await.unwrap().len(), before);

    // Each engine once; sudo takes a password, not a key.
    let twice = marks
        .set(
            ctx,
            web,
            &[
                MarkInput {
                    engine: DOCKER,
                    sudo: SudoMode::Off,
                },
                MarkInput {
                    engine: DOCKER,
                    sudo: SudoMode::NoPassword,
                },
            ],
        )
        .await
        .unwrap_err();
    assert_eq!(twice.code(), "invalid_input");
    let key = core
        .vault
        .add(
            ctx,
            SecretKind::PrivateKey,
            "a key",
            SecretString::new(common::fake_private_key()),
        )
        .await
        .unwrap()
        .id;
    let not_a_password = marks
        .set(
            ctx,
            web,
            &[MarkInput {
                engine: DOCKER,
                sudo: SudoMode::Password { password_id: Some(key) },
            }],
        )
        .await
        .unwrap_err();
    assert!(
        not_a_password.to_string().contains("needs a password"),
        "{not_a_password}"
    );

    // Unmarking says so.
    marks.set(ctx, web, &[]).await.unwrap();
    assert!(core.containers.hosts(ctx).await.unwrap().is_empty());
    let audit = core.store.recent_audit(ctx, 1).await.unwrap();
    assert_eq!(audit[0].action, "Removed 'web01' from the container hosts");
    assert_eq!(audit[0].detail.as_deref(), Some("Docker removed; Podman removed"));

    // Deleting a session drops its marks with it.
    mark(&core, web, DOCKER, SudoMode::Off).await;
    core.sessions.delete(ctx, web).await.unwrap();
    assert!(marks.list(ctx, None).await.unwrap().is_empty());
}

#[tokio::test]
async fn reads_list_containers_images_volumes_networks_details_and_logs() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    let ctx = &core.ctx();
    let list = core.containers.containers(ctx, host(web), DOCKER).await.unwrap();
    let names: Vec<&str> = list.containers.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "cache",
            "old-job",
            "shop-api-1",
            "shop-db-1",
            "shop-web-1",
            "shop-worker-1"
        ]
    );
    assert!(!list.sudo);
    let web_1 = list.containers.iter().find(|c| c.name == "shop-web-1").unwrap();
    assert_eq!(web_1.state, ContainerState::Running);
    assert_eq!(web_1.project.as_deref(), Some("shop"));
    let cache = list.containers.iter().find(|c| c.name == "cache").unwrap();
    assert_eq!(
        cache.command.as_deref(),
        Some("redis-server --requirepass [redacted]"),
        "CT-01: as the parser gives it"
    );
    let stats = core.containers.stats(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(stats.len(), 4, "running and paused ones");
    let images = core.containers.images(ctx, host(web), DOCKER).await.unwrap();
    assert!(images.iter().any(|i| i.dangling));
    let volumes = core.containers.volumes(ctx, host(web), DOCKER).await.unwrap();
    assert!(volumes.iter().any(|v| v.anonymous));
    let networks = core.containers.networks(ctx, host(web), DOCKER).await.unwrap();
    assert!(networks.iter().any(|n| n.name == "shop_default"));

    let db = ContainerId::parse(&id_of(&fake, "web01", "shop-db-1")).unwrap();
    let details = core.containers.details(ctx, host(web), DOCKER, &db).await.unwrap();
    assert!(details.env_names.contains(&"POSTGRES_PASSWORD".to_owned()));
    let shown = serde_json::to_string(&details).unwrap();
    assert!(!shown.contains("hunter2"), "env values never leave the engine: {shown}");
    let logs = core
        .containers
        .logs(ctx, host(web), DOCKER, &db, &LogQuery { tail: 100, since: None })
        .await
        .unwrap();
    assert_eq!(logs.lines.len(), 1);

    // Reads never go through the bus, so nothing is audited.
    let actions: Vec<String> = core
        .store
        .recent_audit(ctx, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert!(actions.iter().all(|e| e == "session_changed"), "{actions:?}");
    assert!(fake.changes().is_empty(), "{:?}", fake.changes());
}

#[tokio::test]
async fn an_engine_a_host_is_not_marked_with_cant_be_read() {
    let (core, _fake, web) = docker_host("web01", Environment::Lab).await;
    let err = core
        .containers
        .containers(&core.ctx(), host(web), PODMAN)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not marked as a Podman host"), "{err}");
    let unmarked = session(&core, "db01", Environment::Lab).await;
    let err = core
        .containers
        .containers(&core.ctx(), host(unmarked), DOCKER)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("'db01' is not marked as a Docker host"),
        "{err}"
    );
}

// ---- Changes through the bus ---------------------------------------------------------------------

#[tokio::test]
async fn starting_a_container_is_low_and_audited_with_host_engine_name_and_id() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    let worker = id_of(&fake, "web01", "shop-worker-1");
    let (job, status) = run(&core, op(vec![container(web, &worker)], ContainerOp::Start)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(
        fake.fixture("web01", DOCKER).container("shop-worker-1").unwrap().state,
        ContainerState::Running
    );
    assert_eq!(fake.changes(), [format!("web01/docker: start {worker}")]);

    let audit = core.store.recent_audit(&core.ctx(), 10).await.unwrap();
    let started = audit.iter().find(|e| e.event == "job_started").unwrap();
    assert_eq!(started.action, "Start 1 container");
    assert_eq!(started.tier.as_deref(), Some("low"));
    assert_eq!(started.job_id.as_deref(), Some(job.to_string().as_str()));
    // The target names the container and the host, and carries the engine and the id.
    assert!(
        started.targets_json.contains("shop-worker-1 on web01 (Docker)"),
        "{}",
        started.targets_json
    );
    assert!(started.targets_json.contains(&worker), "{}", started.targets_json);
    assert!(
        started.targets_json.contains("\"engine\":\"docker\""),
        "{}",
        started.targets_json
    );
    let finished = audit.iter().find(|e| e.event == "job_finished").unwrap();
    assert_eq!(finished.result.as_deref(), Some("succeeded"));
    // Never the engine's output or a log line.
    for entry in &audit {
        let all = format!("{} {:?} {}", entry.action, entry.detail, entry.targets_json);
        assert!(!all.contains("unreachable"), "{all}");
    }
}

#[tokio::test]
async fn stopping_one_container_asks_once_and_two_need_the_high_steps_with_their_state_and_image() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    let api = id_of(&fake, "web01", "shop-api-1");
    let site = id_of(&fake, "web01", "shop-web-1");

    let one = needs_approval(&core, op(vec![container(web, &api)], ContainerOp::Stop)).await;
    assert_eq!(one.tier, Tier::Medium);
    assert_eq!(one.steps, vec![ApprovalStep::Confirm]);
    core.bus.cancel_approval(one.id).await.unwrap();

    let two = needs_approval(
        &core,
        op(vec![container(web, &api), container(web, &site)], ContainerOp::Stop),
    )
    .await;
    assert_eq!(two.tier, Tier::High);
    assert!(two.steps.contains(&ApprovalStep::TypeTargetCount { expected: 2 }));
    // AP-02: each container's state, image and uptime, read now.
    let impacts: Vec<_> = two.impact.iter().filter_map(|i| i.container.as_ref()).collect();
    assert_eq!(impacts.len(), 2);
    let shop_web = impacts.iter().find(|i| i.name == "shop-web-1").unwrap();
    assert_eq!(shop_web.state, Some(ContainerState::Running));
    assert_eq!(shop_web.image.as_deref(), Some("nginx:1.27"));
    assert!(
        shop_web.status.as_deref().unwrap().starts_with("Up "),
        "{:?}",
        shop_web.status
    );
    assert_eq!(shop_web.ports, ["0.0.0.0:8080->80/tcp"]);
    core.bus.approve(two.id, answers(&two)).await.unwrap();
    let mut events = core.jobs.subscribe();
    // The job may have finished already; wait on the fixture instead.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let f = fake.fixture("web01", DOCKER);
            if f.container("shop-web-1").unwrap().state == ContainerState::Exited
                && f.container("shop-api-1").unwrap().state == ContainerState::Exited
            {
                break;
            }
            let _ = tokio::time::timeout(std::time::Duration::from_millis(50), events.recv()).await;
        }
    })
    .await;
    let f = fake.fixture("web01", DOCKER);
    assert_eq!(f.container("shop-web-1").unwrap().state, ContainerState::Exited);
    assert_eq!(f.container("shop-api-1").unwrap().state, ContainerState::Exited);
}

#[tokio::test]
async fn a_prod_host_raises_the_tier_and_a_protected_host_is_skipped() {
    let fake = FakeContainers::default()
        .with_host("prod01", DOCKER, Fixture::sample())
        .with_host("web", DOCKER, Fixture::sample());
    let core = core_with(fake.clone()).await;
    let ctx = &core.ctx();
    let prod = session(&core, "prod01", Environment::Prod).await;
    mark(&core, prod, DOCKER, SudoMode::Off).await;
    let worker = id_of(&fake, "prod01", "shop-worker-1");
    let request = needs_approval(&core, op(vec![container(prod, &worker)], ContainerOp::Start)).await;
    assert_eq!(request.tier, Tier::Medium, "Low, raised by Prod");
    assert!(
        request.reasons.iter().any(|r| r.contains("Prod")),
        "{:?}",
        request.reasons
    );
    core.bus.cancel_approval(request.id).await.unwrap();

    // AP-04: a session that reaches a protected VM is protected: its containers are skipped.
    core.inventory.refresh(ctx).await.unwrap();
    let vm_id = core.store.find_vm(ctx, &vmx("web")).await.unwrap().unwrap().id;
    let guarded = core
        .sessions
        .create(
            ctx,
            SessionInput {
                vm_id: Some(vm_id),
                ..input("web", Environment::Lab, SessionAuth::Agent)
            },
        )
        .await
        .unwrap()
        .id;
    mark(&core, guarded, DOCKER, SudoMode::Off).await;
    run(
        &core,
        Command::VmProtect {
            targets: vec![vm("web")],
            protected: true,
        },
    )
    .await;
    let guarded_worker = id_of(&fake, "web", "shop-worker-1");
    let err = core
        .bus
        .submit(ctx, op(vec![container(guarded, &guarded_worker)], ContainerOp::Start))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "all_targets_protected");
    let mixed = needs_approval(
        &core,
        op(
            vec![container(guarded, &guarded_worker), container(prod, &worker)],
            ContainerOp::Start,
        ),
    )
    .await;
    assert_eq!(mixed.targets.len(), 1);
    assert_eq!(mixed.skipped.len(), 1);
    assert!(
        mixed.skipped[0].name.contains("on web (Docker)"),
        "{}",
        mixed.skipped[0].name
    );
    core.bus.cancel_approval(mixed.id).await.unwrap();
    assert!(fake.changes().is_empty());
}

/// AP-04 with VM-18: a session that reaches a protected VirtualBox VM is a protected container host,
/// as with a Workstation VM, and a Prod label on the VM raises its containers' tier.
#[tokio::test]
async fn a_session_reaching_a_virtualbox_vm_takes_its_protection_and_prod_label() {
    const UUID: &str = "4f4f4f4f-1111-4222-8333-444455556666";
    let fake = FakeContainers::default().with_host("vbox-web", DOCKER, Fixture::sample());
    let core = Setup::new(FakeVmware::default())
        .with_virtualbox(FakeVirtualBox::new().with_vm(UUID, "vbox-web", PowerState::Running))
        .with_real_vault()
        .with_containers(Arc::new(fake.clone()))
        .build()
        .await;
    let ctx = &core.ctx();
    core.inventory.refresh(ctx).await.unwrap();
    let vm_id = core.store.find_vm(ctx, UUID).await.unwrap().unwrap().id;
    let linked = core
        .sessions
        .create(
            ctx,
            SessionInput {
                vm_id: Some(vm_id),
                ..input("vbox-web", Environment::Lab, SessionAuth::Agent)
            },
        )
        .await
        .unwrap()
        .id;
    mark(&core, linked, DOCKER, SudoMode::Off).await;
    let worker = id_of(&fake, "vbox-web", "shop-worker-1");

    core.inventory
        .set_environment(ctx, &[UUID.to_owned()], Environment::Prod)
        .await
        .unwrap();
    let request = needs_approval(&core, op(vec![container(linked, &worker)], ContainerOp::Start)).await;
    assert_eq!(request.tier, Tier::Medium, "Low, raised by the VM's Prod label");
    core.bus.cancel_approval(request.id).await.unwrap();

    run(
        &core,
        Command::VmProtect {
            targets: vec![vbox_vm(UUID)],
            protected: true,
        },
    )
    .await;
    let err = core
        .bus
        .submit(ctx, op(vec![container(linked, &worker)], ContainerOp::Start))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "all_targets_protected");
    assert!(fake.changes().is_empty());
}

#[tokio::test]
async fn removing_a_volume_is_critical_and_names_the_containers_using_it() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    core.containers.volumes(&core.ctx(), host(web), DOCKER).await.unwrap();
    let pgdata = TargetRef::Container {
        host: host(web),
        engine: DOCKER,
        object: ContainerObject::Volume {
            name: VolumeName::parse("pgdata").unwrap(),
        },
    };
    let request = needs_approval(&core, op(vec![pgdata.clone()], ContainerOp::RemoveVolume)).await;
    assert_eq!(request.tier, Tier::Critical);
    assert!(request.steps.contains(&ApprovalStep::VaultReauth));
    assert_eq!(request.summary, "Remove 1 volume and its data");
    let impact = request.impact[0].container.as_ref().unwrap();
    assert_eq!(impact.used_by, ["shop-db-1 (running)"]);
    assert!(impact.removes[0].contains("every file in the volume pgdata"));
    // A wrong vault password is refused and audited.
    let mut wrong = answers(&request);
    wrong.vault_password = Some(SecretString::new("not it"));
    assert_eq!(
        core.bus.approve(request.id, wrong).await.unwrap_err().code(),
        "wrong_vault_password"
    );
    let mut events = core.jobs.subscribe();
    let job = core.bus.approve(request.id, answers(&request)).await.unwrap();
    // In use: the engine refuses, and the job says so.
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Failed);
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    assert!(
        targets[0].error.as_deref().unwrap().contains("volume is in use"),
        "{:?}",
        targets[0].error
    );
    assert!(fake.fixture("web01", DOCKER).volumes.iter().any(|v| v.name == "pgdata"));

    // An unused one goes.
    let old = TargetRef::Container {
        host: host(web),
        engine: DOCKER,
        object: ContainerObject::Volume {
            name: VolumeName::parse("old_cache").unwrap(),
        },
    };
    let (_, status) = run(&core, op(vec![old], ContainerOp::RemoveVolume)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(!fake
        .fixture("web01", DOCKER)
        .volumes
        .iter()
        .any(|v| v.name == "old_cache"));
}

#[tokio::test]
async fn prunes_preview_what_they_remove_and_say_what_they_freed() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    let request = needs_approval(
        &core,
        op(
            vec![engine_of(web, DOCKER)],
            ContainerOp::Prune {
                what: PruneWhat::Containers,
            },
        ),
    )
    .await;
    assert_eq!(request.tier, Tier::High);
    assert_eq!(request.summary, "Prune stopped containers on 1 host");
    let removes = &request.impact[0].container.as_ref().unwrap().removes;
    assert_eq!(removes.len(), 2, "{removes:?}");
    assert!(removes.iter().any(|r| r.starts_with("container old-job")));
    assert!(removes.iter().any(|r| r.starts_with("container shop-worker-1")));
    let mut events = core.jobs.subscribe();
    let job = core.bus.approve(request.id, answers(&request)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert!(fake.fixture("web01", DOCKER).container("old-job").is_none());
    let finished = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    let detail = finished[0].detail.as_deref().unwrap();
    assert!(detail.contains("Docker on web01: reclaimed 20MB"), "{detail}");
    // The CLI's output stays with the job.
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    assert!(targets[0]
        .output
        .as_deref()
        .unwrap_or_default()
        .contains("Total reclaimed space"));

    let volumes = needs_approval(
        &core,
        op(
            vec![engine_of(web, DOCKER)],
            ContainerOp::Prune {
                what: PruneWhat::Volumes,
            },
        ),
    )
    .await;
    assert_eq!(volumes.tier, Tier::Critical);
    let impact = volumes.impact[0].container.as_ref().unwrap();
    // Docker 27 prunes anonymous volumes only: the unused named one stays, the one in use too.
    assert_eq!(impact.removes.len(), 1, "{:?}", impact.removes);
    assert!(
        impact.removes[0].starts_with("anonymous volume"),
        "{:?}",
        impact.removes
    );
    core.bus.cancel_approval(volumes.id).await.unwrap();
}

#[tokio::test]
async fn an_older_docker_prunes_every_unused_volume_and_the_preview_says_so() {
    let mut fixture = Fixture::sample();
    fixture.version = "20.10.24".into();
    let fake = FakeContainers::default().with_host("web01", DOCKER, fixture);
    let core = core_with(fake).await;
    let web = session(&core, "web01", Environment::Lab).await;
    mark(&core, web, DOCKER, SudoMode::Off).await;
    let request = needs_approval(
        &core,
        op(
            vec![engine_of(web, DOCKER)],
            ContainerOp::Prune {
                what: PruneWhat::Volumes,
            },
        ),
    )
    .await;
    let removes = &request.impact[0].container.as_ref().unwrap().removes;
    assert_eq!(removes.len(), 2, "{removes:?}");
    assert!(removes.iter().any(|r| r.contains("old_cache")));
    assert!(!removes.iter().any(|r| r.contains("pgdata")), "in use");
    core.bus.cancel_approval(request.id).await.unwrap();
}

#[tokio::test]
async fn only_what_the_engine_lists_can_be_a_target() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    // Hex, but no container has it.
    let ghost = "0123456789ab0123456789ab0123456789ab0123456789ab0123456789abcdef";
    let err = core
        .bus
        .submit(&core.ctx(), op(vec![container(web, ghost)], ContainerOp::Start))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unknown_target");
    let image = TargetRef::Container {
        host: host(web),
        engine: DOCKER,
        object: ContainerObject::Image {
            id: ImageId::parse(&format!("sha256:{ghost}")).unwrap(),
        },
    };
    let err = core
        .bus
        .submit(&core.ctx(), op(vec![image], ContainerOp::RemoveImage))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unknown_target");
    // The op must fit the object.
    let worker = id_of(&fake, "web01", "shop-worker-1");
    let err = core
        .bus
        .submit(
            &core.ctx(),
            op(vec![container(web, &worker)], ContainerOp::RemoveVolume),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
    assert!(fake.changes().is_empty());
}

#[tokio::test]
async fn pulling_an_image_is_low_and_takes_only_a_reference_that_passes_the_grammar() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    let (_, status) = run(
        &core,
        op(
            vec![engine_of(web, DOCKER)],
            ContainerOp::Pull {
                reference: "registry.example.com/team/app:2.1".into(),
            },
        ),
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(fake
        .fixture("web01", DOCKER)
        .images
        .iter()
        .any(|i| i.tags.contains(&"registry.example.com/team/app:2.1".to_owned())));
    for bad in ["nginx; reboot", "$(reboot)", "-q", "NGINX"] {
        let err = core
            .bus
            .submit(
                &core.ctx(),
                op(
                    vec![engine_of(web, DOCKER)],
                    ContainerOp::Pull { reference: bad.into() },
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{bad}");
    }
    assert_eq!(fake.changes().len(), 1);
}

#[tokio::test]
async fn the_read_only_lock_refuses_container_changes_and_mark_edits_but_reads_go_on() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    let ctx = &core.ctx();
    core.presentation
        .set(remotely_core::presentation::Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let worker = id_of(&fake, "web01", "shop-worker-1");
    let err = core
        .bus
        .submit(ctx, op(vec![container(web, &worker)], ContainerOp::Start))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    assert!(err.to_string().contains("Start containers"), "{err}");
    let err = core.containers.marks().set(ctx, web, &[]).await.unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    assert!(err.to_string().contains("Mark container hosts"), "{err}");
    // Reads are not changes.
    assert!(!core
        .containers
        .containers(ctx, host(web), DOCKER)
        .await
        .unwrap()
        .containers
        .is_empty());
    assert!(fake.changes().is_empty());
}

#[tokio::test]
async fn a_host_outside_the_docker_group_runs_docker_with_sudo_and_its_password_from_the_vault() {
    let fake = FakeContainers::default()
        .with_host("web01", DOCKER, Fixture::sample())
        .needing_sudo("web01", DOCKER)
        .with_sudo_password("login-pw-example");
    let core = core_with(fake.clone()).await;
    let ctx = &core.ctx();
    let login = core
        .vault
        .add(
            ctx,
            SecretKind::Password,
            "web01 login",
            SecretString::new("login-pw-example"),
        )
        .await
        .unwrap()
        .id;
    let web = core
        .sessions
        .create(
            ctx,
            input(
                "web01",
                Environment::Lab,
                SessionAuth::Password {
                    password_id: Some(login),
                },
            ),
        )
        .await
        .unwrap()
        .id;
    mark(&core, web, DOCKER, SudoMode::Off).await;
    let err = core.containers.containers(ctx, host(web), DOCKER).await.unwrap_err();
    assert_eq!(err.code(), "container_needs_sudo");

    // The session's own login password.
    mark(&core, web, DOCKER, SudoMode::Password { password_id: None }).await;
    let list = core.containers.containers(ctx, host(web), DOCKER).await.unwrap();
    assert!(list.sudo, "the page says sudo is used");
    assert!(fake.calls().last().unwrap().ends_with("[sudo]"));
    let worker = id_of(&fake, "web01", "shop-worker-1");
    let (_, status) = run(&core, op(vec![container(web, &worker)], ContainerOp::Start)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.changes(), [format!("web01/docker: start {worker} [sudo]")]);

    // A chosen password that sudo refuses.
    let wrong = core
        .vault
        .add(ctx, SecretKind::Password, "old sudo", SecretString::new("stale"))
        .await
        .unwrap()
        .id;
    mark(
        &core,
        web,
        DOCKER,
        SudoMode::Password {
            password_id: Some(wrong),
        },
    )
    .await;
    let err = core.containers.containers(ctx, host(web), DOCKER).await.unwrap_err();
    // MO-02, CT-01: parked, so the next polls do not try it again.
    assert_eq!(err.code(), "login_parked");
    assert!(err.to_string().contains("refused the password"), "{err}");
    for entry in core.store.recent_audit(ctx, 100).await.unwrap() {
        let all = format!("{:?}", entry);
        assert!(!all.contains("login-pw-example") && !all.contains("stale"), "{all}");
    }

    // A key login has no password for sudo unless one is chosen.
    let keyed = core
        .sessions
        .create(ctx, input("keyed", Environment::Lab, SessionAuth::Agent))
        .await
        .unwrap()
        .id;
    mark(&core, keyed, DOCKER, SudoMode::Password { password_id: None }).await;
    let err = core.containers.containers(ctx, host(keyed), DOCKER).await.unwrap_err();
    assert_eq!(err.code(), "no_sudo_password");
}

#[tokio::test]
async fn failed_container_targets_can_be_retried_and_rated_again() {
    let (core, fake, web) = docker_host("web01", Environment::Lab).await;
    let cache = id_of(&fake, "web01", "cache");
    let worker = id_of(&fake, "web01", "shop-worker-1");
    // Pausing a paused container and a stopped one both fail.
    let (job, status) = run(
        &core,
        op(
            vec![container(web, &cache), container(web, &worker)],
            ContainerOp::Pause,
        ),
    )
    .await;
    assert_eq!(status, JobStatus::Failed);
    let request = match core.bus.retry_failed(&core.ctx(), job, false).await.unwrap() {
        SubmitOutcome::NeedsApproval { request } => request,
        SubmitOutcome::Queued { .. } => panic!("pausing 2 asks"),
    };
    assert_eq!(request.targets.len(), 2);
    assert_eq!(request.tier, Tier::High);
    core.bus.cancel_approval(request.id).await.unwrap();
}

// ---- CT-02: Docker Desktop on this PC -------------------------------------------------------------

#[tokio::test]
async fn docker_desktop_on_this_pc_is_a_host_with_the_same_rules() {
    let path = std::env::temp_dir().join("remotely-test-not-real").join("docker.exe");
    let fake = FakeContainers::default().with_this_pc(&path, Fixture::sample());
    let core = core_with(fake.clone()).await;
    let ctx = &core.ctx();
    let hosts = core.containers.hosts(ctx).await.unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host, ContainerHost::ThisPc);
    assert_eq!(hosts[0].name, "This PC");
    assert_eq!(hosts[0].cli_path.as_deref(), Some(path.display().to_string().as_str()));
    let list = core
        .containers
        .containers(ctx, ContainerHost::ThisPc, DOCKER)
        .await
        .unwrap();
    assert_eq!(list.containers.len(), 6);
    assert!(core
        .containers
        .containers(ctx, ContainerHost::ThisPc, PODMAN)
        .await
        .is_err());
    let worker = fake.this_pc_fixture().container("shop-worker-1").unwrap().id.clone();
    let target = TargetRef::Container {
        host: ContainerHost::ThisPc,
        engine: DOCKER,
        object: ContainerObject::Container {
            id: ContainerId::parse(&worker).unwrap(),
        },
    };
    let (_, status) = run(&core, op(vec![target.clone()], ContainerOp::Start)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.changes(), [format!("this-pc/docker: start {worker}")]);
    let stop = needs_approval(&core, op(vec![target], ContainerOp::Stop)).await;
    assert_eq!(stop.tier, Tier::Medium);
    assert_eq!(stop.targets[0].name, "shop-worker-1 on This PC (Docker)");
    core.bus.cancel_approval(stop.id).await.unwrap();
}

#[tokio::test]
async fn without_docker_desktop_this_pc_is_no_host() {
    let core = core_with(FakeContainers::default()).await;
    assert!(core.containers.hosts(&core.ctx()).await.unwrap().is_empty());
    let err = core
        .containers
        .containers(&core.ctx(), ContainerHost::ThisPc, DOCKER)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "container_cli_missing");
    assert!(core.docker_path().is_none());
    // A path in Settings must be docker.exe.
    let err = core
        .set_docker_path(Some(std::env::temp_dir().join("not-docker.exe")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_setting");
}

// ---- FD-07: the marks go with the sessions ----------------------------------------------------------

async fn laptop() -> Core {
    Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_containers(Arc::new(FakeContainers::default()))
        .build()
        .await
}

#[tokio::test]
async fn an_export_carries_container_marks_to_another_laptop() {
    let core = laptop().await;
    let ctx = &core.ctx();
    let web = session(&core, "web01", Environment::Lab).await;
    let sudo = core
        .vault
        .add(ctx, SecretKind::Password, "web01 sudo", SecretString::new("pw-example"))
        .await
        .unwrap()
        .id;
    core.containers
        .marks()
        .set(
            ctx,
            web,
            &[
                MarkInput {
                    engine: DOCKER,
                    sudo: SudoMode::Password {
                        password_id: Some(sudo),
                    },
                },
                MarkInput {
                    engine: PODMAN,
                    sudo: SudoMode::NoPassword,
                },
            ],
        )
        .await
        .unwrap();
    session(&core, "plain", Environment::Lab).await;
    let dir = common::temp_folder("ct-export");
    let file = dir.join("laptop.remotely");
    let report = core
        .transfer
        .export(
            ctx,
            &file,
            remotely_core::transfer::ExportRequest {
                passphrase: SecretString::new("export passphrase example"),
                include_known_hosts: true,
                include_secrets: true,
                vault_password: Some(SecretString::new(VAULT_PASSWORD)),
            },
            &core.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    assert_eq!(report.container_hosts, 1);

    let other = laptop().await;
    let preview = other
        .transfer
        .open(
            &other.ctx(),
            &file,
            SecretString::new("export passphrase example"),
            &other.vault,
        )
        .await
        .unwrap();
    let done = other
        .transfer
        .commit(
            &other.ctx(),
            remotely_core::transfer::TransferCommit {
                preview_id: preview.id,
                catalog: Default::default(),
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
                folder_defaults: vec![],
                favourites: vec![],
                groups: vec![],
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
            },
            &other.sessions,
            &other.vault,
            &other.known_hosts,
            &other.snippets,
        )
        .await
        .unwrap();
    assert_eq!(done.container_hosts, 1);
    let marks = other.containers.marks().list(&other.ctx(), None).await.unwrap();
    assert_eq!(marks.len(), 2);
    let docker = marks.iter().find(|m| m.engine == DOCKER).unwrap();
    let SudoMode::Password { password_id: Some(id) } = docker.sudo else {
        panic!("sudo with a chosen password: {:?}", docker.sudo);
    };
    assert_ne!(id, sudo, "the secret has this laptop's id");
    let labels = other.vault.list(&other.ctx()).await.unwrap();
    assert!(labels.iter().any(|s| s.id == id && s.label == "web01 sudo"));
    assert_eq!(
        marks.iter().find(|m| m.engine == PODMAN).unwrap().sudo,
        SudoMode::NoPassword
    );
    let audit = other.store.recent_audit(&other.ctx(), 20).await.unwrap();
    assert!(audit
        .iter()
        .any(|e| e.action == "Imported the container engines of 'web01'"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn containers_with_hostile_names_are_shown_and_acted_on_by_id_only() {
    let fake = FakeContainers::default().with_host("web01", DOCKER, Fixture::hostile());
    let core = core_with(fake.clone()).await;
    let web = session(&core, "web01", Environment::Lab).await;
    mark(&core, web, DOCKER, SudoMode::Off).await;
    let list = core
        .containers
        .containers(&core.ctx(), host(web), DOCKER)
        .await
        .unwrap();
    let evil = list.containers.iter().find(|c| c.name.contains("touch")).unwrap();
    let request = needs_approval(&core, op(vec![container(web, evil.id.as_str())], ContainerOp::Stop)).await;
    assert_eq!(request.targets[0].name, format!("{} on web01 (Docker)", evil.name));
    core.bus.approve(request.id, answers(&request)).await.unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while fake.changes().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(fake.changes(), [format!("web01/docker: stop {}", evil.id)]);
}

/// FakeContainer is public so other tests can build fixtures; check it stays usable.
#[test]
fn fixtures_can_be_extended() {
    let fixture = Fixture::empty().with(FakeContainer::new("one", "busybox", ContainerState::Created));
    assert_eq!(fixture.containers[0].status(), "Created");
}
