//! CT-01, CT-02 fakes: a fixture of containers, images, volumes and networks that changes the way the
//! CLIs would (start, stop, remove, prune...), used two ways:
//!
//! * [`FakeContainers`]: the engines in memory, behind [`ContainerEngines`], for tests of the command
//!   bus, the policy engine and the job runner without SSH.
//! * The test SSH server's `docker` and `podman` programs (`ssh_server::docker`), which print the same
//!   fixture as each CLI's JSON, so the real CLI engine and parser run end to end over russh.
//!
//! Names and data are made up: `example.com` and `.test` hosts, users like alice. No `it-` names (those are
//! for opt-in tests against a real Workstation).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::adapters::containers::{
    ChangeOutput, ContainerDetails, ContainerEngine, ContainerEngines, ContainerId, ContainerState, ContainerStats,
    ContainerSummary, EngineChange, EngineKind, EngineVersion, HealthInfo, ImageId, ImageSummary, LogLine, LogQuery,
    LogStream, Logs, MountInfo, NetworkAttachment, NetworkSummary, PortMapping, PruneWhat, SudoRun, VolumeName,
    VolumeSummary,
};
use crate::adapters::remote::ExecSession;
use crate::error::{ContainerProblem, CoreError, Result};
use crate::locks;

/// 64 hex digits made from `seed`, the same every run.
pub fn hex_id(seed: &str) -> String {
    hex::encode(Sha256::digest(seed.as_bytes()))
}

/// Unix seconds `hours` before now.
fn hours_ago(hours: i64) -> i64 {
    OffsetDateTime::now_utc().unix_timestamp() - hours * 3600
}

pub fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeMount {
    /// The volume's name; `None` for a bind mount.
    pub volume: Option<String>,
    pub source: String,
    pub destination: String,
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct FakeContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_id: String,
    pub command: Vec<String>,
    pub state: ContainerState,
    pub exit_code: i64,
    pub created: i64,
    pub started: Option<i64>,
    pub ports: Vec<PortMapping>,
    /// `NAME=value`: the values are what must never reach the UI.
    pub env: Vec<String>,
    pub mounts: Vec<FakeMount>,
    pub networks: Vec<String>,
    pub project: Option<String>,
    pub health: Option<String>,
    pub restart_policy: String,
    /// (Unix seconds, stream, text).
    pub logs: Vec<(i64, LogStream, String)>,
    /// A new log line at every read while it runs, so following a log shows something.
    pub live_logs: bool,
    pub cpu_pct: f64,
    pub mem_bytes: u64,
}

impl FakeContainer {
    pub fn new(name: &str, image: &str, state: ContainerState) -> Self {
        let created = hours_ago(30);
        Self {
            id: hex_id(&format!("container {name}")),
            name: name.to_owned(),
            image: image.to_owned(),
            image_id: hex_id(&format!("image {image}")),
            command: vec!["/entrypoint.sh".into()],
            state,
            exit_code: 0,
            created,
            started: state.is_up().then(|| hours_ago(26)),
            ports: Vec::new(),
            env: vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()],
            mounts: Vec::new(),
            networks: vec!["bridge".into()],
            project: None,
            health: None,
            restart_policy: "unless-stopped".into(),
            logs: Vec::new(),
            live_logs: false,
            cpu_pct: 0.0,
            mem_bytes: 0,
        }
    }

    pub fn short_id(&self) -> &str {
        &self.id[..12]
    }

    /// Docker's status text.
    pub fn status(&self) -> String {
        let up = |since: Option<i64>| {
            let secs = OffsetDateTime::now_utc().unix_timestamp() - since.unwrap_or(self.created);
            match secs / 3600 {
                0 => format!("{} minutes", (secs / 60).max(1)),
                1 => "About an hour".to_owned(),
                h if h < 48 => format!("{h} hours"),
                h => format!("{} days", h / 24),
            }
        };
        match self.state {
            ContainerState::Running => {
                let health = match self.health.as_deref() {
                    Some("starting") => " (health: starting)".to_owned(),
                    Some(h) => format!(" ({h})"),
                    None => String::new(),
                };
                format!("Up {}{health}", up(self.started))
            }
            ContainerState::Paused => format!("Up {} (Paused)", up(self.started)),
            ContainerState::Restarting => "Restarting (1) 5 seconds ago".to_owned(),
            ContainerState::Exited | ContainerState::Dead => format!("Exited ({}) {} ago", self.exit_code, up(None)),
            ContainerState::Created => "Created".to_owned(),
            ContainerState::Removing => "Removal In Progress".to_owned(),
            ContainerState::Unknown => String::new(),
        }
    }

    fn port(mut self, host_ip: &str, host: u16, inside: u16) -> Self {
        self.ports.push(PortMapping {
            host_ip: Some(host_ip.to_owned()),
            host_port: Some(host),
            container_port: inside,
            protocol: "tcp".into(),
        });
        self
    }

    fn volume(mut self, name: &str, destination: &str, read_only: bool) -> Self {
        self.mounts.push(FakeMount {
            volume: Some(name.to_owned()),
            source: format!("/var/lib/docker/volumes/{name}/_data"),
            destination: destination.to_owned(),
            read_only,
        });
        self
    }

    fn in_project(mut self, project: &str) -> Self {
        self.project = Some(project.to_owned());
        self.networks = vec![format!("{project}_default")];
        self
    }

    fn log(mut self, hours: i64, stream: LogStream, text: &str) -> Self {
        self.logs.push((hours_ago(hours), stream, text.to_owned()));
        self
    }
}

#[derive(Debug, Clone)]
pub struct FakeImage {
    pub id: String,
    pub tags: Vec<String>,
    pub size: u64,
    pub created: i64,
}

#[derive(Debug, Clone)]
pub struct FakeVolume {
    pub name: String,
    pub driver: String,
    pub project: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FakeNetwork {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub subnet: Option<String>,
}

/// One engine's containers, images, volumes and networks.
#[derive(Debug, Clone, Default)]
pub struct Fixture {
    pub containers: Vec<FakeContainer>,
    pub images: Vec<FakeImage>,
    pub volumes: Vec<FakeVolume>,
    pub networks: Vec<FakeNetwork>,
    pub version: String,
}

impl Fixture {
    pub fn empty() -> Self {
        Self {
            version: "27.3.1".into(),
            networks: vec![
                network("bridge", "bridge", Some("172.17.0.0/16")),
                network("host", "host", None),
                network("none", "null", None),
            ],
            ..Self::default()
        }
    }

    /// A small shop: web, api, db and worker from one Compose project, a paused cache and an old job,
    /// with their images (one dangling), volumes (one anonymous, one unused) and networks.
    pub fn sample() -> Self {
        let mut f = Self::empty();
        let mut web = FakeContainer::new("shop-web-1", "nginx:1.27", ContainerState::Running)
            .in_project("shop")
            .port("0.0.0.0", 8080, 80)
            .volume("shop_static", "/usr/share/nginx/html", true)
            .log(
                25,
                LogStream::Stdout,
                "/docker-entrypoint.sh: Configuration complete; ready for start up",
            )
            .log(2, LogStream::Stdout, "192.0.2.10 - - \"GET / HTTP/1.1\" 200 615")
            .log(
                1,
                LogStream::Stderr,
                "2026/10/21 09:00:00 [warn] 29#29: an upstream response is buffered",
            );
        web.health = Some("healthy".into());
        web.command = vec!["nginx".into(), "-g".into(), "daemon off;".into()];
        web.env.push("NGINX_HOST=shop.example.com".into());
        web.live_logs = true;
        web.cpu_pct = 0.4;
        web.mem_bytes = 12_582_912;
        let mut api = FakeContainer::new(
            "shop-api-1",
            "registry.example.com/shop/api:2.3",
            ContainerState::Running,
        )
        .in_project("shop")
        .port("127.0.0.1", 9000, 9000)
        .log(26, LogStream::Stdout, "api listening on :9000")
        .log(3, LogStream::Stderr, "warning: slow query (812 ms)");
        api.env
            .push("DATABASE_URL=postgres://alice:not-a-real-password@shop-db-1/shop".into());
        api.env.push("API_TOKEN=tok_example_0000".into());
        api.cpu_pct = 2.5;
        api.mem_bytes = 104_857_600;
        let mut db = FakeContainer::new("shop-db-1", "postgres:16", ContainerState::Running)
            .in_project("shop")
            .volume("pgdata", "/var/lib/postgresql/data", false)
            .log(26, LogStream::Stdout, "database system is ready to accept connections");
        db.env.push("POSTGRES_PASSWORD=hunter2-example".into());
        db.cpu_pct = 1.1;
        db.mem_bytes = 62_914_560;
        let mut worker = FakeContainer::new(
            "shop-worker-1",
            "registry.example.com/shop/worker:2.3",
            ContainerState::Exited,
        )
        .in_project("shop")
        .log(5, LogStream::Stderr, "fatal: queue shop.example.com:5672 unreachable");
        worker.exit_code = 1;
        let mut cache = FakeContainer::new("cache", "redis:7", ContainerState::Paused).port("0.0.0.0", 6379, 6379);
        cache.mem_bytes = 8_388_608;
        let old = FakeContainer::new("old-job", "busybox:latest", ContainerState::Exited);
        f.containers = vec![web, api, db, worker, cache, old];
        f.images = vec![
            image("nginx:1.27", 192_000_000),
            image("registry.example.com/shop/api:2.3", 245_000_000),
            image("postgres:16", 438_000_000),
            image("registry.example.com/shop/worker:2.3", 245_000_000),
            image("redis:7", 117_000_000),
            image("busybox:latest", 4_300_000),
            FakeImage {
                id: hex_id("image dangling"),
                tags: Vec::new(),
                size: 245_000_000,
                created: hours_ago(24 * 9),
            },
        ];
        f.volumes = vec![
            volume("pgdata", Some("shop")),
            volume("shop_static", Some("shop")),
            volume(&hex_id("volume anonymous"), None),
            volume("old_cache", None),
        ];
        f.networks
            .push(network("shop_default", "bridge", Some("172.18.0.0/16")));
        f
    }

    /// Containers whose names, images and commands are shell syntax: they must only ever be shown.
    pub fn hostile() -> Self {
        let mut f = Self::empty();
        let mut evil = FakeContainer::new(
            "x'; touch /tmp/pwned; echo '",
            "evil$(touch /tmp/pwned)",
            ContainerState::Running,
        );
        evil.command = vec!["sh".into(), "-c".into(), "`reboot`".into()];
        let quiet = FakeContainer::new("$(reboot)", "busybox", ContainerState::Exited);
        f.containers = vec![evil, quiet];
        f
    }

    pub fn with(mut self, container: FakeContainer) -> Self {
        self.containers.push(container);
        self
    }

    /// Containers whose id starts with `id` (the CLIs take any unique start).
    fn find(&mut self, id: &str) -> std::result::Result<usize, String> {
        let hits: Vec<usize> = self
            .containers
            .iter()
            .enumerate()
            .filter(|(_, c)| !id.is_empty() && c.id.starts_with(id))
            .map(|(i, _)| i)
            .collect();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("Error response from daemon: No such container: {id}")),
            _ => Err(format!(
                "Error response from daemon: multiple IDs found with provided prefix: {id}"
            )),
        }
    }

    pub fn container(&self, name: &str) -> Option<&FakeContainer> {
        self.containers.iter().find(|c| c.name == name)
    }

    fn in_use_by_image(&self, image: &FakeImage) -> Option<String> {
        self.containers
            .iter()
            .find(|c| c.image_id == image.id || image.tags.contains(&c.image))
            .map(|c| c.short_id().to_owned())
    }

    fn volume_users(&self, name: &str) -> Vec<&FakeContainer> {
        self.containers
            .iter()
            .filter(|c| c.mounts.iter().any(|m| m.volume.as_deref() == Some(name)))
            .collect()
    }

    /// Carries out a change like the CLI: `Ok(stdout)` or `Err(stderr)`.
    pub fn apply(&mut self, change: &FakeChange) -> std::result::Result<String, String> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        match change {
            FakeChange::Start(id) => {
                let i = self.find(id)?;
                let c = &mut self.containers[i];
                if c.state == ContainerState::Paused {
                    return Err(
                        "Error response from daemon: cannot start a paused container, try unpause instead".to_owned(),
                    );
                }
                if c.state != ContainerState::Running {
                    c.state = ContainerState::Running;
                    c.started = Some(now);
                }
                Ok(format!("{id}\n"))
            }
            FakeChange::Stop(id) => {
                let i = self.find(id)?;
                let c = &mut self.containers[i];
                if c.state.is_up() {
                    c.state = ContainerState::Exited;
                    c.exit_code = 0;
                }
                Ok(format!("{id}\n"))
            }
            FakeChange::Restart(id) => {
                let i = self.find(id)?;
                let c = &mut self.containers[i];
                c.state = ContainerState::Running;
                c.started = Some(now);
                Ok(format!("{id}\n"))
            }
            FakeChange::Pause(id) => {
                let i = self.find(id)?;
                let c = &mut self.containers[i];
                match c.state {
                    ContainerState::Running => {
                        c.state = ContainerState::Paused;
                        Ok(format!("{id}\n"))
                    }
                    ContainerState::Paused => {
                        Err(format!("Error response from daemon: container {id} is already paused"))
                    }
                    _ => Err(format!("Error response from daemon: container {id} is not running")),
                }
            }
            FakeChange::Unpause(id) => {
                let i = self.find(id)?;
                let c = &mut self.containers[i];
                if c.state != ContainerState::Paused {
                    return Err(format!("Error response from daemon: container {id} is not paused"));
                }
                c.state = ContainerState::Running;
                Ok(format!("{id}\n"))
            }
            FakeChange::Remove { id, force } => {
                let i = self.find(id)?;
                if self.containers[i].state.is_up() && !force {
                    return Err(format!(
                        "Error response from daemon: cannot remove container \"/{}\": container is running: stop the container before removing or force remove",
                        self.containers[i].name
                    ));
                }
                self.containers.remove(i);
                Ok(format!("{id}\n"))
            }
            FakeChange::RemoveImage(id) => {
                let digits = id.strip_prefix("sha256:").unwrap_or(id);
                let Some(i) = self.images.iter().position(|img| img.id.starts_with(digits)) else {
                    return Err(format!("Error response from daemon: No such image: {id}"));
                };
                if let Some(user) = self.in_use_by_image(&self.images[i]) {
                    return Err(format!(
                        "Error response from daemon: conflict: unable to delete {} (must be forced) - image is being used by stopped container {user}",
                        &digits[..12.min(digits.len())]
                    ));
                }
                let gone = self.images.remove(i);
                let mut out: String = gone.tags.iter().map(|t| format!("Untagged: {t}\n")).collect();
                out.push_str(&format!("Deleted: sha256:{}\n", gone.id));
                Ok(out)
            }
            FakeChange::RemoveVolume(name) => {
                let Some(i) = self.volumes.iter().position(|v| v.name == *name) else {
                    return Err(format!("Error response from daemon: get {name}: no such volume"));
                };
                let users: Vec<String> = self.volume_users(name).iter().map(|c| c.id.clone()).collect();
                if !users.is_empty() {
                    return Err(format!(
                        "Error response from daemon: remove {name}: volume is in use - [{}]",
                        users.join(", ")
                    ));
                }
                self.volumes.remove(i);
                Ok(format!("{name}\n"))
            }
            FakeChange::Pull(reference) => {
                let tag = if reference.rsplit('/').next().is_some_and(|last| last.contains(':')) {
                    reference.clone()
                } else {
                    format!("{reference}:latest")
                };
                if !self.images.iter().any(|i| i.tags.contains(&tag)) {
                    self.images.push(image(&tag, 50_000_000));
                }
                Ok(format!("docker.io/{tag}\n"))
            }
            FakeChange::Prune(what) => {
                let mut removed = Vec::new();
                match what {
                    PruneWhat::Containers => {
                        self.containers.retain(|c| {
                            let gone = matches!(
                                c.state,
                                ContainerState::Exited | ContainerState::Created | ContainerState::Dead
                            );
                            if gone {
                                removed.push(c.id.clone());
                            }
                            !gone
                        });
                    }
                    PruneWhat::Images => self.images.retain(|i| {
                        let gone = i.tags.is_empty();
                        if gone {
                            removed.push(format!("sha256:{}", i.id));
                        }
                        !gone
                    }),
                    PruneWhat::Volumes => {
                        let used: HashSet<String> = self
                            .containers
                            .iter()
                            .flat_map(|c| c.mounts.iter().filter_map(|m| m.volume.clone()))
                            .collect();
                        // Docker 23 and later: anonymous volumes only.
                        self.volumes.retain(|v| {
                            let anonymous = v.name.len() == 64;
                            let gone = anonymous && !used.contains(&v.name);
                            if gone {
                                removed.push(v.name.clone());
                            }
                            !gone
                        });
                    }
                    PruneWhat::BuildCache => {}
                }
                let mut out = String::new();
                if !removed.is_empty() {
                    out.push_str("Deleted:\n");
                    for r in &removed {
                        out.push_str(&format!("{r}\n"));
                    }
                    out.push('\n');
                }
                out.push_str(&format!("Total reclaimed space: {}MB\n", removed.len() * 10));
                Ok(out)
            }
        }
    }
}

fn image(tag: &str, size: u64) -> FakeImage {
    FakeImage {
        id: hex_id(&format!("image {tag}")),
        tags: vec![tag.to_owned()],
        size,
        created: hours_ago(24 * 20),
    }
}

fn volume(name: &str, project: Option<&str>) -> FakeVolume {
    FakeVolume {
        name: name.to_owned(),
        driver: "local".into(),
        project: project.map(str::to_owned),
    }
}

fn network(name: &str, driver: &str, subnet: Option<&str>) -> FakeNetwork {
    FakeNetwork {
        id: hex_id(&format!("network {name}")),
        name: name.to_owned(),
        driver: driver.to_owned(),
        subnet: subnet.map(str::to_owned),
    }
}

/// A change by the ids and names the CLI takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeChange {
    Start(String),
    Stop(String),
    Restart(String),
    Pause(String),
    Unpause(String),
    Remove { id: String, force: bool },
    RemoveImage(String),
    RemoveVolume(String),
    Pull(String),
    Prune(PruneWhat),
}

impl FakeChange {
    fn of(change: &EngineChange) -> Self {
        match change {
            EngineChange::Start(id) => FakeChange::Start(id.to_string()),
            EngineChange::Stop(id) => FakeChange::Stop(id.to_string()),
            EngineChange::Restart(id) => FakeChange::Restart(id.to_string()),
            EngineChange::Pause(id) => FakeChange::Pause(id.to_string()),
            EngineChange::Unpause(id) => FakeChange::Unpause(id.to_string()),
            EngineChange::Remove { id, force } => FakeChange::Remove {
                id: id.to_string(),
                force: *force,
            },
            EngineChange::RemoveImage(id) => FakeChange::RemoveImage(id.to_string()),
            EngineChange::RemoveVolume(name) => FakeChange::RemoveVolume(name.to_string()),
            EngineChange::Pull(reference) => FakeChange::Pull(reference.to_string()),
            EngineChange::Prune(what) => FakeChange::Prune(*what),
        }
    }

    fn describe(&self) -> String {
        match self {
            FakeChange::Start(id) => format!("start {id}"),
            FakeChange::Stop(id) => format!("stop {id}"),
            FakeChange::Restart(id) => format!("restart {id}"),
            FakeChange::Pause(id) => format!("pause {id}"),
            FakeChange::Unpause(id) => format!("unpause {id}"),
            FakeChange::Remove { id, force: false } => format!("rm {id}"),
            FakeChange::Remove { id, force: true } => format!("rm -f {id}"),
            FakeChange::RemoveImage(id) => format!("rmi {id}"),
            FakeChange::RemoveVolume(name) => format!("volume rm {name}"),
            FakeChange::Pull(reference) => format!("pull {reference}"),
            FakeChange::Prune(what) => format!("prune {what:?}"),
        }
    }
}

// ---- Typed views of a fixture, as the parser would give them ----------------------------------------

pub fn summary(c: &FakeContainer) -> Option<ContainerSummary> {
    Some(ContainerSummary {
        id: ContainerId::parse(&c.id).ok()?,
        name: c.name.clone(),
        image: c.image.clone(),
        command: Some(c.command.join(" ")),
        state: c.state,
        status: c.status(),
        created_at: Some(rfc3339(c.created)),
        started_at: c.started.map(rfc3339),
        ports: c.ports.clone(),
        networks: c.networks.clone(),
        mounts: c
            .mounts
            .iter()
            .map(|m| m.volume.clone().unwrap_or_else(|| m.source.clone()))
            .collect(),
        project: c.project.clone(),
        health: c.health.clone(),
    })
}

fn details(c: &FakeContainer) -> Option<ContainerDetails> {
    Some(ContainerDetails {
        id: ContainerId::parse(&c.id).ok()?,
        name: c.name.clone(),
        image: c.image.clone(),
        image_id: Some(format!("sha256:{}", c.image_id)),
        created_at: Some(rfc3339(c.created)),
        started_at: c.started.map(rfc3339),
        finished_at: None,
        state: c.state,
        exit_code: Some(c.exit_code),
        error: None,
        oom_killed: false,
        health: c.health.clone().map(|status| HealthInfo {
            status,
            failing_streak: Some(0),
        }),
        restart_policy: Some(c.restart_policy.clone()),
        restart_count: Some(0),
        command: Some(c.command.join(" ")),
        entrypoint: None,
        working_dir: None,
        user: None,
        hostname: Some(c.short_id().to_owned()),
        // Names only, as the parser gives them.
        env_names: c
            .env
            .iter()
            .map(|e| e.split('=').next().unwrap_or_default().to_owned())
            .collect(),
        mounts: c
            .mounts
            .iter()
            .map(|m| MountInfo {
                kind: if m.volume.is_some() { "volume" } else { "bind" }.into(),
                name: m.volume.clone(),
                source: Some(m.source.clone()),
                destination: m.destination.clone(),
                read_only: m.read_only,
            })
            .collect(),
        networks: c
            .networks
            .iter()
            .enumerate()
            .map(|(i, n)| NetworkAttachment {
                name: n.clone(),
                ip_address: c.state.is_up().then(|| format!("172.18.0.{}", i + 2)),
                gateway: Some("172.18.0.1".into()),
            })
            .collect(),
        ports: c.ports.clone(),
        project: c.project.clone(),
        platform: Some("linux".into()),
    })
}

fn image_summary(i: &FakeImage, containers: &[FakeContainer]) -> Option<ImageSummary> {
    Some(ImageSummary {
        id: ImageId::parse(&format!("sha256:{}", i.id)).ok()?,
        tags: i.tags.clone(),
        digest: None,
        created_at: Some(rfc3339(i.created)),
        size_bytes: Some(i.size),
        containers: Some(containers.iter().filter(|c| i.tags.contains(&c.image)).count() as u64),
        dangling: i.tags.is_empty(),
    })
}

/// One fake host's engine state, shared by every engine handed out for it.
#[derive(Default)]
struct HostState {
    fixture: Fixture,
    /// Refuses the login user: needs sudo.
    needs_sudo: bool,
    /// Every call fails as if the daemon were down.
    down: bool,
}

#[derive(Default)]
struct Shared {
    hosts: HashMap<(String, EngineKind), HostState>,
    this_pc: Option<(PathBuf, HostState)>,
    /// The sudo password the hosts take; any other is refused.
    sudo_password: Option<String>,
    calls: Vec<String>,
}

/// Container engines in memory: one per (session name, engine), and Docker Desktop on this PC when
/// given. Records every call as `<host>/<engine>: <what>`, with ` [sudo]` under sudo; never a password.
#[derive(Clone, Default)]
pub struct FakeContainers {
    shared: Arc<Mutex<Shared>>,
}

impl FakeContainers {
    /// `host` is the session's name.
    pub fn with_host(self, host: &str, engine: EngineKind, fixture: Fixture) -> Self {
        locks::lock(&self.shared).hosts.insert(
            (host.to_owned(), engine),
            HostState {
                fixture,
                ..HostState::default()
            },
        );
        self
    }

    /// This host's engine refuses the login user (not in the docker group).
    pub fn needing_sudo(self, host: &str, engine: EngineKind) -> Self {
        if let Some(state) = locks::lock(&self.shared).hosts.get_mut(&(host.to_owned(), engine)) {
            state.needs_sudo = true;
        }
        self
    }

    pub fn with_sudo_password(self, password: &str) -> Self {
        locks::lock(&self.shared).sudo_password = Some(password.to_owned());
        self
    }

    /// CT-02: Docker Desktop on this PC, "installed" at `path`.
    pub fn with_this_pc(self, path: &Path, fixture: Fixture) -> Self {
        locks::lock(&self.shared).this_pc = Some((
            path.to_path_buf(),
            HostState {
                fixture,
                ..HostState::default()
            },
        ));
        self
    }

    pub fn set_down(&self, host: &str, engine: EngineKind, down: bool) {
        if let Some(state) = locks::lock(&self.shared).hosts.get_mut(&(host.to_owned(), engine)) {
            state.down = down;
        }
    }

    /// A host's fixture as it is now.
    pub fn fixture(&self, host: &str, engine: EngineKind) -> Fixture {
        locks::lock(&self.shared)
            .hosts
            .get(&(host.to_owned(), engine))
            .map(|s| s.fixture.clone())
            .unwrap_or_default()
    }

    pub fn this_pc_fixture(&self) -> Fixture {
        locks::lock(&self.shared)
            .this_pc
            .as_ref()
            .map(|(_, s)| s.fixture.clone())
            .unwrap_or_default()
    }

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.shared).calls.clone()
    }

    /// The calls that changed something (not the reads).
    pub fn changes(&self) -> Vec<String> {
        const READS: [&str; 8] = [
            "version", "ps", "stats", "inspect", "logs", "images", "volumes", "networks",
        ];
        self.calls()
            .into_iter()
            .filter(|c| {
                let what = c.split(": ").nth(1).unwrap_or_default();
                !READS.iter().any(|r| what.starts_with(r))
            })
            .collect()
    }
}

impl ContainerEngines for FakeContainers {
    fn over_ssh(
        &self,
        kind: EngineKind,
        host: &str,
        _connection: Arc<dyn ExecSession>,
        sudo: SudoRun,
    ) -> Arc<dyn ContainerEngine> {
        Arc::new(FakeEngine {
            shared: Arc::clone(&self.shared),
            place: Place::Host(host.to_owned()),
            kind,
            sudo,
        })
    }

    fn this_pc(&self) -> Option<Arc<dyn ContainerEngine>> {
        locks::lock(&self.shared).this_pc.as_ref()?;
        Some(Arc::new(FakeEngine {
            shared: Arc::clone(&self.shared),
            place: Place::ThisPc,
            kind: EngineKind::Docker,
            sudo: SudoRun::No,
        }))
    }

    fn this_pc_cli(&self) -> Option<PathBuf> {
        locks::lock(&self.shared).this_pc.as_ref().map(|(p, _)| p.clone())
    }

    fn find_this_pc_cli(&self, _saved: Option<&Path>) {}
}

#[derive(Clone)]
enum Place {
    Host(String),
    ThisPc,
}

struct FakeEngine {
    shared: Arc<Mutex<Shared>>,
    place: Place,
    kind: EngineKind,
    sudo: SudoRun,
}

impl FakeEngine {
    fn label(&self) -> String {
        match &self.place {
            Place::Host(host) => format!("{host}/{}", self.kind.as_str()),
            Place::ThisPc => "this-pc/docker".to_owned(),
        }
    }

    /// Records the call, checks access, and runs `f` on the host's state.
    fn with_state<T>(&self, what: &str, f: impl FnOnce(&mut HostState) -> Result<T>) -> Result<T> {
        let mut shared = locks::lock(&self.shared);
        let sudo = if matches!(self.sudo, SudoRun::No) {
            ""
        } else {
            " [sudo]"
        };
        shared.calls.push(format!("{}: {what}{sudo}", self.label()));
        if let SudoRun::Password(given) = &self.sudo {
            if shared.sudo_password.as_deref() != Some(given.expose()) {
                return Err(CoreError::SudoPasswordRefused);
            }
        }
        let place = match &self.place {
            Place::Host(host) => host.clone(),
            Place::ThisPc => "this PC".to_owned(),
        };
        let label = self.kind.label();
        let program = self.kind.program();
        let state = match &self.place {
            Place::Host(host) => shared.hosts.get_mut(&(host.clone(), self.kind)),
            Place::ThisPc => shared.this_pc.as_mut().map(|(_, s)| s),
        };
        let Some(state) = state else {
            return Err(CoreError::Container {
                problem: ContainerProblem::CliMissing,
                message: format!("{label} is not installed on {place}: there is no {program} command"),
            });
        };
        if state.down {
            return Err(CoreError::Container {
                problem: ContainerProblem::DaemonDown,
                message: format!("the {label} service on {place} is not running"),
            });
        }
        if state.needs_sudo && matches!(self.sudo, SudoRun::No) {
            return Err(CoreError::Container {
                problem: ContainerProblem::NeedsSudo,
                message: format!(
                    "the Docker daemon on {place} refused the user (permission denied). Use sudo for this host, or add the user to the docker group"
                ),
            });
        }
        f(state)
    }
}

#[async_trait]
impl ContainerEngine for FakeEngine {
    fn kind(&self) -> EngineKind {
        self.kind
    }

    async fn version(&self) -> Result<EngineVersion> {
        self.with_state("version", |s| {
            Ok(EngineVersion {
                client: Some(s.fixture.version.clone()),
                server: Some(s.fixture.version.clone()),
                api: Some("1.47".into()),
                platform: Some("linux/amd64".into()),
            })
        })
    }

    async fn containers(&self) -> Result<Vec<ContainerSummary>> {
        self.with_state("ps", |s| {
            let mut list: Vec<ContainerSummary> = s.fixture.containers.iter().filter_map(summary).collect();
            list.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(list)
        })
    }

    async fn stats(&self) -> Result<Vec<ContainerStats>> {
        self.with_state("stats", |s| {
            Ok(s.fixture
                .containers
                .iter()
                .filter(|c| c.state.is_up())
                .filter_map(|c| {
                    Some(ContainerStats {
                        id: ContainerId::parse(&c.id).ok()?,
                        name: Some(c.name.clone()),
                        cpu_pct: Some(c.cpu_pct),
                        mem_bytes: Some(c.mem_bytes),
                        mem_limit_bytes: Some(2_147_483_648),
                        mem_pct: Some(c.mem_bytes as f64 / 2_147_483_648.0 * 100.0),
                        net_rx_bytes: Some(1200),
                        net_tx_bytes: Some(648),
                        block_read_bytes: Some(0),
                        block_write_bytes: Some(0),
                        pids: Some(2),
                    })
                })
                .collect())
        })
    }

    async fn inspect(&self, id: &ContainerId) -> Result<ContainerDetails> {
        self.with_state(&format!("inspect {id}"), |s| {
            let found = s.fixture.containers.iter().find(|c| c.id.starts_with(id.as_str()));
            found.and_then(details).ok_or_else(|| CoreError::Container {
                problem: ContainerProblem::NotFound,
                message: format!("No such container: {id}"),
            })
        })
    }

    async fn logs(&self, id: &ContainerId, query: &LogQuery) -> Result<Logs> {
        self.with_state(&format!("logs {id}"), |s| {
            let Some(c) = s.fixture.containers.iter().find(|c| c.id.starts_with(id.as_str())) else {
                return Err(CoreError::Container {
                    problem: ContainerProblem::NotFound,
                    message: format!("No such container: {id}"),
                });
            };
            let mut lines: Vec<LogLine> = c
                .logs
                .iter()
                .map(|(at, stream, text)| LogLine {
                    at: Some(rfc3339(*at)),
                    stream: *stream,
                    text: text.clone(),
                })
                .filter(|l| query.since.as_deref().is_none_or(|since| l.at.as_deref() > Some(since)))
                .collect();
            let over = lines.len().saturating_sub(query.tail as usize);
            lines.drain(..over);
            Ok(Logs {
                lines,
                truncated: over > 0,
            })
        })
    }

    async fn images(&self) -> Result<Vec<ImageSummary>> {
        self.with_state("images", |s| {
            Ok(s.fixture
                .images
                .iter()
                .filter_map(|i| image_summary(i, &s.fixture.containers))
                .collect())
        })
    }

    async fn volumes(&self) -> Result<Vec<VolumeSummary>> {
        self.with_state("volumes", |s| {
            Ok(s.fixture
                .volumes
                .iter()
                .filter_map(|v| {
                    let name = VolumeName::parse(&v.name).ok()?;
                    Some(VolumeSummary {
                        anonymous: name.is_anonymous(),
                        driver: Some(v.driver.clone()),
                        mountpoint: Some(format!("/var/lib/docker/volumes/{}/_data", v.name)),
                        scope: Some("local".into()),
                        created_at: None,
                        project: v.project.clone(),
                        name,
                    })
                })
                .collect())
        })
    }

    async fn networks(&self) -> Result<Vec<NetworkSummary>> {
        self.with_state("networks", |s| {
            Ok(s.fixture
                .networks
                .iter()
                .map(|n| NetworkSummary {
                    id: n.id.clone(),
                    name: n.name.clone(),
                    driver: Some(n.driver.clone()),
                    scope: Some("local".into()),
                    internal: Some(false),
                    ipv6: Some(false),
                    subnets: n.subnet.iter().cloned().collect(),
                    created_at: None,
                })
                .collect())
        })
    }

    async fn change(&self, change: &EngineChange) -> Result<ChangeOutput> {
        if let (EngineChange::Prune(PruneWhat::BuildCache), EngineKind::Podman) = (change, self.kind) {
            return Err(CoreError::InvalidInput("Podman keeps no build cache of its own".into()));
        }
        let fake = FakeChange::of(change);
        let label = self.kind.label();
        let place = match &self.place {
            Place::Host(host) => host.clone(),
            Place::ThisPc => "this PC".to_owned(),
        };
        self.with_state(&fake.describe(), |s| match s.fixture.apply(&fake) {
            Ok(stdout) => Ok(ChangeOutput {
                note: match change {
                    EngineChange::Prune(_) => crate::adapters::containers::parse::prune_note(&stdout),
                    EngineChange::Pull(reference) => Some(format!("pulled {reference}")),
                    _ => None,
                },
                stdout,
                stderr: String::new(),
            }),
            Err(stderr) => Err(CoreError::Container {
                problem: if stderr.contains("No such") {
                    ContainerProblem::NotFound
                } else {
                    ContainerProblem::Failed
                },
                message: format!(
                    "{label} on {place} could not do it: {}",
                    stderr.trim_start_matches("Error response from daemon: ")
                ),
            }),
        })
    }
}
