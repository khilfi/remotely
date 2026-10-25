//! Containers over SSH (CT-01), end to end: the real russh adapter and CLI engine against toy SSH servers
//! on 127.0.0.1 whose `docker` and `podman` programs answer in each CLI's own JSON from a fixture
//! (`fakes::containers`). Sudo from the vault, detection, a jump host chain, hostile names that must never
//! reach a shell, and "Open a shell" in a container. No real host or container is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::containers::{ContainerId, ContainerState, EngineKind, LogQuery, LogStream};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, ContainerOp, SubmitOutcome};
use remotely_core::containers::{ContainerTuning, MarkInput, SudoMode};
use remotely_core::domain::{ContainerHost, ContainerObject, Environment, TargetRef};
use remotely_core::fakes::containers::Fixture;
use remotely_core::fakes::ssh_server::{SudoMode as ServerSudo, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::ApprovalStep;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::{TerminalHandle, TerminalTuning};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::Core;
use uuid::Uuid;

const DOCKER: EngineKind = EngineKind::Docker;
const PODMAN: EngineKind = EngineKind::Podman;
const WAIT: Duration = Duration::from_secs(15);

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn no_agent() -> AgentSource {
    AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4()))
}

async fn core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.containers.set_tuning(ContainerTuning {
        connect_timeout: Duration::from_secs(5),
        agent: no_agent(),
        ..ContainerTuning::default()
    });
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 3,
        slow_retry: Duration::from_millis(200),
        slow_attempts: 0,
        wake_spread: Duration::from_millis(50),
        keepalive_interval: None,
        keepalive_max: 2,
        agent: no_agent(),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    });
    core
}

async fn saved(core: &Core, label: &str, password: &str) -> SecretId {
    core.vault
        .add(&core.ctx, SecretKind::Password, label, SecretString::new(password))
        .await
        .unwrap()
        .id
}

async fn trust(core: &Core, host: &str, port: u16, server: &TestSshServer) {
    let key = HostKey {
        host: host.into(),
        port,
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
}

fn input(name: &str, host: &str, port: u16, user: &str, password: SecretId, jump: Option<Uuid>) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port,
        username: Some(user.into()),
        auth: SessionAuth::Password {
            password_id: Some(password),
        },
        jump_session_id: jump,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

/// A server on 127.0.0.1 with `engine` holding `fixture`, a trusted key, and a session to it marked
/// with that engine run as `sudo` says.
async fn container_host(
    core: &Core,
    engine: EngineKind,
    fixture: Fixture,
    sudo: SudoMode,
    edit: impl FnOnce(TestSshServer) -> TestSshServer,
) -> (TestSshServer, Uuid, String) {
    let password = new_password();
    let server = edit(
        TestSshServer::start()
            .await
            .with_password("alice", &password)
            .with_containers(engine, fixture),
    );
    trust(core, "127.0.0.1", server.port(), &server).await;
    let login = saved(core, "web01 login", &password).await;
    let id = core
        .sessions
        .create(
            &core.ctx,
            input("web01", "127.0.0.1", server.port(), "alice", login, None),
        )
        .await
        .unwrap()
        .id;
    core.containers
        .marks()
        .set(&core.ctx, id, &[MarkInput { engine, sudo }])
        .await
        .unwrap();
    (server, id, password)
}

fn host(session_id: Uuid) -> ContainerHost {
    ContainerHost::Session { session_id }
}

fn target(session_id: Uuid, engine: EngineKind, id: &str) -> TargetRef {
    TargetRef::Container {
        host: host(session_id),
        engine,
        object: ContainerObject::Container {
            id: ContainerId::parse(id).unwrap(),
        },
    }
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

async fn run(core: &Core, command: Command) -> (Uuid, JobStatus) {
    let mut events = core.jobs.subscribe();
    let job = match core.bus.submit(&core.ctx, command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core.bus.approve(request.id, answers(&request)).await.unwrap(),
    };
    (
        job,
        tokio::time::timeout(WAIT, wait_finished(&mut events, job))
            .await
            .unwrap(),
    )
}

/// The toy server's log lines for the container CLIs and what reached exec channels.
fn cli_lines(server: &TestSshServer) -> Vec<String> {
    server
        .log()
        .into_iter()
        .filter(|l| l.starts_with("docker ") || l.starts_with("podman ") || l.starts_with("exec "))
        .collect()
}

#[tokio::test]
async fn docker_over_ssh_reads_every_list_from_its_json() {
    let core = core().await;
    let (server, web, _) = container_host(&core, DOCKER, Fixture::sample(), SudoMode::Off, |s| s).await;
    let ctx = &core.ctx;
    let version = core.containers.version(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(version.server.as_deref(), Some("27.3.1"));
    let list = core.containers.containers(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(list.containers.len(), 6);
    let site = list.containers.iter().find(|c| c.name == "shop-web-1").unwrap();
    assert_eq!(site.state, ContainerState::Running);
    assert_eq!(site.health.as_deref(), Some("healthy"));
    assert_eq!(site.image, "nginx:1.27");
    assert_eq!(site.project.as_deref(), Some("shop"));
    let ports: Vec<String> = site.ports.iter().map(|p| p.describe()).collect();
    assert_eq!(ports, ["0.0.0.0:8080->80/tcp"]);
    assert_eq!(site.mounts, ["shop_static"]);
    let cache = list.containers.iter().find(|c| c.name == "cache").unwrap();
    assert_eq!(cache.state, ContainerState::Paused);
    // CT-01: the password on its command line never reaches the page.
    assert_eq!(cache.command.as_deref(), Some("redis-server --requirepass [redacted]"));
    let worker = list.containers.iter().find(|c| c.name == "shop-worker-1").unwrap();
    assert!(worker.status.starts_with("Exited (1)"), "{}", worker.status);

    let stats = core.containers.stats(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(stats.len(), 4);
    assert!(stats.iter().all(|s| s.cpu_pct.is_some() && s.mem_bytes.is_some()));
    let images = core.containers.images(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(images.len(), 7);
    assert!(images.iter().any(|i| i.dangling));
    let volumes = core.containers.volumes(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(volumes.iter().filter(|v| v.anonymous).count(), 1);
    let networks = core.containers.networks(ctx, host(web), DOCKER).await.unwrap();
    assert!(networks.iter().any(|n| n.name == "shop_default"));

    let db = list.containers.iter().find(|c| c.name == "shop-db-1").unwrap();
    let details = core.containers.details(ctx, host(web), DOCKER, &db.id).await.unwrap();
    assert!(details.env_names.contains(&"POSTGRES_PASSWORD".to_owned()));
    assert!(!serde_json::to_string(&details).unwrap().contains("hunter2"));
    assert_eq!(details.mounts[0].name.as_deref(), Some("pgdata"));
    let cache_details = core
        .containers
        .details(ctx, host(web), DOCKER, &cache.id)
        .await
        .unwrap();
    assert_eq!(
        cache_details.command.as_deref(),
        Some("redis-server --requirepass [redacted]")
    );
    assert!(!serde_json::to_string(&cache_details).unwrap().contains("hunter2"));

    // Logs: both streams by time; following asks only for what came after.
    let id = site.id.clone();
    let logs = core
        .containers
        .logs(ctx, host(web), DOCKER, &id, &LogQuery { tail: 100, since: None })
        .await
        .unwrap();
    assert!(logs.lines.iter().any(|l| l.stream == LogStream::Stderr));
    let last = logs.lines.last().unwrap().at.clone().unwrap();
    let more = core
        .containers
        .logs(
            ctx,
            host(web),
            DOCKER,
            &id,
            &LogQuery {
                tail: 100,
                since: Some(last.clone()),
            },
        )
        .await
        .unwrap();
    assert_eq!(more.lines.len(), 1, "one new line since the last: {:?}", more.lines);
    assert!(more.lines[0].at.as_deref().unwrap() > last.as_str());

    // One login for all of it, every word quoted, nothing run under sudo.
    assert_eq!(server.connections(), 1);
    let lines = cli_lines(&server);
    assert!(
        lines
            .iter()
            .any(|l| l == "exec 'docker' 'ps' '-a' '--no-trunc' '--format' '{{json .}}'"),
        "{lines:#?}"
    );
    assert!(!lines.iter().any(|l| l.contains("sudo")));
}

#[tokio::test]
async fn podman_over_ssh_reads_its_own_json() {
    let core = core().await;
    let (_server, web, _) = container_host(&core, PODMAN, Fixture::sample(), SudoMode::Off, |s| s).await;
    let ctx = &core.ctx;
    let version = core.containers.version(ctx, host(web), PODMAN).await.unwrap();
    assert_eq!(version.client.as_deref(), Some("4.9.3"));
    let list = core.containers.containers(ctx, host(web), PODMAN).await.unwrap();
    assert_eq!(list.containers.len(), 6);
    let redis = list.containers.iter().find(|c| c.name == "cache").unwrap();
    assert_eq!(redis.state, ContainerState::Paused);
    assert_eq!(redis.image, "docker.io/library/redis:7");
    assert_eq!(redis.ports[0].describe(), "6379->6379/tcp");
    assert_eq!(redis.command.as_deref(), Some("redis-server --requirepass [redacted]"));
    let api = list.containers.iter().find(|c| c.name == "shop-api-1").unwrap();
    assert_eq!(api.image, "registry.example.com/shop/api:2.3");
    assert!(api.started_at.is_some(), "Podman says when it started");
    let stats = core.containers.stats(ctx, host(web), PODMAN).await.unwrap();
    assert_eq!(stats.len(), 4);
    assert!(stats.iter().all(|s| s.id.as_str().len() == 12), "Podman's short ids");
    let images = core.containers.images(ctx, host(web), PODMAN).await.unwrap();
    assert!(images
        .iter()
        .any(|i| i.tags == ["docker.io/library/postgres:16"] && i.containers == Some(1)));
    let networks = core.containers.networks(ctx, host(web), PODMAN).await.unwrap();
    let shop = networks.iter().find(|n| n.name == "shop_default").unwrap();
    assert_eq!(shop.subnets, ["172.18.0.0/16"]);
    let db = list.containers.iter().find(|c| c.name == "shop-db-1").unwrap();
    let details = core.containers.details(ctx, host(web), PODMAN, &db.id).await.unwrap();
    assert_eq!(details.name, "shop-db-1");
    assert!(!serde_json::to_string(&details).unwrap().contains("hunter2"));
}

#[tokio::test]
async fn changes_run_on_the_host_through_the_bus_with_every_word_quoted() {
    let core = core().await;
    let (server, web, _) = container_host(&core, DOCKER, Fixture::sample(), SudoMode::Off, |s| s).await;
    let ids: Vec<(String, String)> = server
        .containers(DOCKER)
        .containers
        .iter()
        .map(|c| (c.name.clone(), c.id.clone()))
        .collect();
    let id = |name: &str| ids.iter().find(|(n, _)| n == name).unwrap().1.clone();
    core.containers.containers(&core.ctx, host(web), DOCKER).await.unwrap();

    let (_, status) = run(
        &core,
        Command::Container {
            targets: vec![target(web, DOCKER, &id("shop-api-1"))],
            op: ContainerOp::Stop,
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(
        server.containers(DOCKER).container("shop-api-1").unwrap().state,
        ContainerState::Exited
    );
    let (_, status) = run(
        &core,
        Command::Container {
            targets: vec![target(web, DOCKER, &id("old-job"))],
            op: ContainerOp::Remove { force: false },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(server.containers(DOCKER).container("old-job").is_none());
    // Removing a running container without force fails, and the engine's reason reaches the job.
    let (job, status) = run(
        &core,
        Command::Container {
            targets: vec![target(web, DOCKER, &id("shop-web-1"))],
            op: ContainerOp::Remove { force: false },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Failed);
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    assert!(
        targets[0].error.as_deref().unwrap().contains("container is running"),
        "{:?}",
        targets[0].error
    );

    let lines = cli_lines(&server);
    let api = id("shop-api-1");
    assert!(lines.contains(&format!("exec 'docker' 'stop' '{api}'")), "{lines:#?}");
    assert!(lines.contains(&format!("docker stop {api}")), "{lines:#?}");
}

#[tokio::test]
async fn outside_the_docker_group_docker_runs_with_sudo_and_the_password_never_shows() {
    let core = core().await;
    let (server, web, password) = container_host(&core, DOCKER, Fixture::sample(), SudoMode::Off, |s| {
        s.without_docker_group()
    })
    .await;
    let server = server.with_sudo(ServerSudo::Password(password.clone()));
    let ctx = &core.ctx;
    let err = core.containers.containers(ctx, host(web), DOCKER).await.unwrap_err();
    assert_eq!(err.code(), "container_needs_sudo");
    assert!(err.to_string().contains("docker group"), "{err}");

    // Detection finds docker needs sudo, and that the login password works for it.
    let found = core.containers.detect(ctx, web, None).await.unwrap();
    let docker = found.engines.iter().find(|e| e.engine == DOCKER).unwrap();
    assert!(docker.installed);
    assert_eq!(docker.suggested, Some(SudoMode::Password { password_id: None }));
    let podman = found.engines.iter().find(|e| e.engine == PODMAN).unwrap();
    assert!(!podman.installed);

    core.containers
        .marks()
        .set(
            ctx,
            web,
            &[MarkInput {
                engine: DOCKER,
                sudo: SudoMode::Password { password_id: None },
            }],
        )
        .await
        .unwrap();
    let list = core.containers.containers(ctx, host(web), DOCKER).await.unwrap();
    assert!(list.sudo);
    assert_eq!(list.containers.len(), 6);
    let worker = server.containers(DOCKER).container("shop-worker-1").unwrap().id.clone();
    let (_, status) = run(
        &core,
        Command::Container {
            targets: vec![target(web, DOCKER, &worker)],
            op: ContainerOp::Start,
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(
        server.containers(DOCKER).container("shop-worker-1").unwrap().state,
        ContainerState::Running
    );
    let log = server.log();
    assert!(log.iter().any(|l| l == "sudo ok"), "{log:#?}");
    assert!(
        !log.iter().any(|l| l.contains(&password)),
        "the password never reaches a log"
    );
    for entry in core.store.recent_audit(ctx, 200).await.unwrap() {
        assert!(!format!("{entry:?}").contains(&password));
    }
}

#[tokio::test]
async fn detection_suggests_nopasswd_sudo_and_finds_podman() {
    let core = core().await;
    let (server, web, _) = container_host(&core, DOCKER, Fixture::sample(), SudoMode::Off, |s| {
        s.without_docker_group()
            .with_sudo(ServerSudo::NoPassword)
            .with_containers(PODMAN, Fixture::empty())
    })
    .await;
    let found = core.containers.detect(&core.ctx, web, None).await.unwrap();
    let docker = found.engines.iter().find(|e| e.engine == DOCKER).unwrap();
    assert_eq!(docker.suggested, Some(SudoMode::NoPassword));
    let podman = found.engines.iter().find(|e| e.engine == PODMAN).unwrap();
    assert!(podman.installed);
    assert_eq!(podman.suggested, Some(SudoMode::Off), "rootless");
    assert!(server
        .log()
        .iter()
        .any(|l| l.starts_with("exec sudo -n 'docker' 'version'")));
    // A read: nothing was marked or audited.
    let marks = core.containers.marks().list(&core.ctx, Some(web)).await.unwrap();
    assert_eq!(marks.len(), 1);
}

#[tokio::test]
async fn hostile_container_names_are_shown_but_only_ids_reach_the_host() {
    let core = core().await;
    let (server, web, _) = container_host(&core, DOCKER, Fixture::hostile(), SudoMode::Off, |s| s).await;
    let list = core.containers.containers(&core.ctx, host(web), DOCKER).await.unwrap();
    let evil = list.containers.iter().find(|c| c.name.contains("touch")).unwrap();
    assert_eq!(evil.name, "x'; touch /tmp/pwned; echo '");
    assert_eq!(evil.image, "evil$(touch /tmp/pwned)");
    let quiet = list.containers.iter().find(|c| c.name == "$(reboot)").unwrap();
    let (_, status) = run(
        &core,
        Command::Container {
            targets: vec![target(web, DOCKER, evil.id.as_str())],
            op: ContainerOp::Stop,
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    let (_, status) = run(
        &core,
        Command::Container {
            targets: vec![target(web, DOCKER, quiet.id.as_str())],
            op: ContainerOp::Remove { force: false },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    core.containers
        .details(&core.ctx, host(web), DOCKER, &evil.id)
        .await
        .unwrap();
    for line in cli_lines(&server) {
        assert!(
            !line.contains("touch") && !line.contains("reboot") && !line.contains('$'),
            "{line}"
        );
    }
    assert!(server.file("/tmp/pwned").is_none(), "nothing ran");
    // The audit names the container as text.
    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    assert!(audit.iter().any(|e| e.targets_json.contains("touch /tmp/pwned")));
}

#[tokio::test]
async fn a_host_behind_jump_hosts_is_read_through_the_chain() {
    let core = core().await;
    let (inner_password, bastion_password) = (new_password(), new_password());
    let inner = TestSshServer::start()
        .await
        .with_password("alice", &inner_password)
        .with_containers(DOCKER, Fixture::sample());
    let bastion = TestSshServer::start()
        .await
        .with_password("bob", &bastion_password)
        .with_route("docker01.test", inner.port());
    trust(&core, "127.0.0.1", bastion.port(), &bastion).await;
    trust(&core, "docker01.test", 22, &inner).await;
    let bastion_login = saved(&core, "bastion bob", &bastion_password).await;
    let inner_login = saved(&core, "docker01 alice", &inner_password).await;
    let bastion_id = core
        .sessions
        .create(
            &core.ctx,
            input("bastion", "127.0.0.1", bastion.port(), "bob", bastion_login, None),
        )
        .await
        .unwrap()
        .id;
    let docker01 = core
        .sessions
        .create(
            &core.ctx,
            input("docker01", "docker01.test", 22, "alice", inner_login, Some(bastion_id)),
        )
        .await
        .unwrap()
        .id;
    core.containers
        .marks()
        .set(
            &core.ctx,
            docker01,
            &[MarkInput {
                engine: DOCKER,
                sudo: SudoMode::Off,
            }],
        )
        .await
        .unwrap();
    let hosts = core.containers.hosts(&core.ctx).await.unwrap();
    assert_eq!(hosts[0].via, ["bastion"]);
    let list = core
        .containers
        .containers(&core.ctx, host(docker01), DOCKER)
        .await
        .unwrap();
    assert_eq!(list.containers.len(), 6);
    assert!(bastion.log().iter().any(|l| l == "direct-tcpip docker01.test:22"));
}

#[tokio::test]
async fn open_a_shell_runs_docker_exec_in_a_terminal_and_is_audited_with_the_container() {
    let core = core().await;
    let (server, web, _) = container_host(&core, DOCKER, Fixture::sample(), SudoMode::Off, |s| s).await;
    let fixture = server.containers(DOCKER);
    let site = fixture.container("shop-web-1").unwrap();
    let id = ContainerId::parse(&site.id).unwrap();
    let shell = core.containers.shell(&core.ctx, web, DOCKER, &id).await.unwrap();
    assert_eq!(shell.title, "shop-web-1 (web01)");
    assert_eq!(
        shell.command,
        format!(
            "exec docker exec -it {} sh -c 'command -v bash >/dev/null && exec bash || exec sh'",
            site.id
        )
    );
    let handle: TerminalHandle = core
        .terminals
        .open_container_shell(&core.ctx, web, shell, PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    let mut output = handle.output;
    let prompt = format!("root@{}:/# ", site.short_id());
    let mut seen = String::new();
    tokio::time::timeout(WAIT, async {
        while !seen.contains(&prompt) {
            match output.recv().await {
                Some(bytes) => seen.push_str(&String::from_utf8_lossy(&bytes)),
                None => break,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no container prompt in {seen:?}"));
    assert!(server
        .log()
        .iter()
        .any(|l| l == &format!("container shell docker {}", site.short_id())));
    let audit = core.store.recent_audit(&core.ctx, 20).await.unwrap();
    let opened = audit.iter().find(|e| e.event == "terminal_opened").unwrap();
    assert_eq!(
        opened.action,
        "Opened a shell in container 'shop-web-1' on 'web01' (Docker)"
    );
    let detail = opened.detail.as_deref().unwrap();
    assert!(detail.contains(&format!("container {}", site.short_id())), "{detail}");
    assert!(detail.contains("image nginx:1.27"), "{detail}");
    core.terminals.close(handle.id).await;

    // Only a running container has a shell to open.
    let worker = ContainerId::parse(&fixture.container("shop-worker-1").unwrap().id).unwrap();
    let err = core
        .containers
        .shell(&core.ctx, web, DOCKER, &worker)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("is not running"), "{err}");
}

/// MO-02, CT-01: the page polls every few seconds, so a refused sudo password, a refused login or a
/// changed host key must not be tried again at every poll: each try is a failed sudo or login in the
/// host's logs, which pam_faillock, AD or fail2ban count. They park until Retry or a change.
#[tokio::test]
async fn refused_sudo_logins_and_changed_keys_are_not_retried_at_every_poll() {
    let core = core().await;
    let ctx = &core.ctx;
    let (server, web, password) = container_host(&core, DOCKER, Fixture::sample(), SudoMode::Off, |s| {
        s.without_docker_group()
    })
    .await;
    let server = server.with_sudo(ServerSudo::Password(password.clone()));
    let wrong = saved(&core, "old sudo password", "not-the-password").await;
    let sudo_with = |password_id| MarkInput {
        engine: DOCKER,
        sudo: SudoMode::Password { password_id },
    };
    core.containers
        .marks()
        .set(ctx, web, &[sudo_with(Some(wrong))])
        .await
        .unwrap();
    let refused = |server: &TestSshServer| server.log().iter().filter(|l| *l == "sudo refused").count();

    for _ in 0..3 {
        let err = core.containers.containers(ctx, host(web), DOCKER).await.unwrap_err();
        assert_eq!(err.code(), "login_parked", "{err}");
        assert!(err.to_string().contains("refused the password"), "{err}");
        assert!(err.to_string().contains("press Retry"), "{err}");
        // The stats poll and the details panel stop too.
        assert_eq!(
            core.containers.stats(ctx, host(web), DOCKER).await.unwrap_err().code(),
            "login_parked"
        );
    }
    let tried = refused(&server);
    assert!(tried >= 1);
    let after_first = server.log().len();

    // Retry: one more sudo, refused again.
    core.retry_background_logins(web);
    assert_eq!(
        core.containers
            .containers(ctx, host(web), DOCKER)
            .await
            .unwrap_err()
            .code(),
        "login_parked"
    );
    assert_eq!(refused(&server), tried * 2);
    assert!(server.log().len() > after_first);

    // Choosing the login password for sudo is a change: it runs.
    core.containers.marks().set(ctx, web, &[sudo_with(None)]).await.unwrap();
    assert_eq!(
        core.containers
            .containers(ctx, host(web), DOCKER)
            .await
            .unwrap()
            .containers
            .len(),
        6
    );

    // A login the host refuses parks every read of the host, without a new connection.
    let other = TestSshServer::start()
        .await
        .with_password("alice", &new_password())
        .with_containers(DOCKER, Fixture::sample());
    trust(&core, "127.0.0.1", other.port(), &other).await;
    let stale = saved(&core, "db01 login", "rotated-away").await;
    let db = core
        .sessions
        .create(ctx, input("db01", "127.0.0.1", other.port(), "alice", stale, None))
        .await
        .unwrap()
        .id;
    core.containers
        .marks()
        .set(
            ctx,
            db,
            &[MarkInput {
                engine: DOCKER,
                sudo: SudoMode::Off,
            }],
        )
        .await
        .unwrap();
    for _ in 0..3 {
        let err = core.containers.containers(ctx, host(db), DOCKER).await.unwrap_err();
        assert_eq!(err.code(), "login_parked", "{err}");
        assert!(err.to_string().contains("login failed"), "{err}");
    }
    assert_eq!(other.connections(), 1);

    // A changed host key: blocked, audited once, and not tried again at every poll.
    let moved = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_containers(DOCKER, Fixture::sample());
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: moved.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    core.known_hosts.trust(ctx, &key, None).await.unwrap();
    let login = saved(&core, "app01 login", &password).await;
    let app = core
        .sessions
        .create(ctx, input("app01", "127.0.0.1", moved.port(), "alice", login, None))
        .await
        .unwrap()
        .id;
    core.containers
        .marks()
        .set(
            ctx,
            app,
            &[MarkInput {
                engine: DOCKER,
                sudo: SudoMode::Off,
            }],
        )
        .await
        .unwrap();
    for _ in 0..3 {
        let err = core.containers.containers(ctx, host(app), DOCKER).await.unwrap_err();
        assert_eq!(err.code(), "login_parked", "{err}");
        assert!(err.to_string().contains("has changed"), "{err}");
    }
    assert_eq!(moved.connections(), 1);
    let blocked = core
        .store
        .recent_audit(ctx, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "host_key_changed")
        .count();
    assert_eq!(blocked, 1, "audited once per park");
}

#[tokio::test]
async fn locking_the_vault_closes_the_kept_connection_that_logged_in_with_its_secrets() {
    let core = core().await;
    let ctx = &core.ctx;
    let (server, web, _password) = container_host(&core, DOCKER, Fixture::sample(), SudoMode::Off, |s| s).await;
    core.containers.containers(ctx, host(web), DOCKER).await.unwrap();
    core.containers.containers(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(server.connections(), 1, "kept between reads");

    // SS-04: the kept connection holds the login password (to scrub output); locking closes it.
    core.vault.lock(ctx).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    core.vault
        .unlock(
            ctx,
            remotely_core::vault::UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    core.containers.containers(ctx, host(web), DOCKER).await.unwrap();
    assert_eq!(server.connections(), 2, "logged in again after the lock");
}
