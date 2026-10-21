//! Containers (CT-01, CT-02): Docker and Podman on the saved sessions marked as container hosts, and
//! Docker Desktop on this PC.
//!
//! * Hosts: the user marks sessions ([`marks`]), or asks Remotely to detect which CLIs a host has
//!   ([`Containers::detect`]). Nothing polls every session: a host is read only when the Containers page
//!   asks, and its SSH connection is kept for a few minutes for the next read, then closed.
//! * Reads (lists, details, logs, stats, images, volumes, networks) skip the command bus (architecture
//!   rule 3). They log in like the dashboard does: the saved login only, host keys trusted already
//!   (unknown fails, changed blocks and is audited), each jump host on the way with its own login.
//! * Changes (start, stop, restart, pause, unpause, remove, pull, prune) are [`Command::Container`] on
//!   the bus: the policy engine rates them, the approval dialog previews them ([`Containers::impact`]),
//!   and the job runner carries them out here ([`ContainerActions`]). Only ids the engine itself listed
//!   can be named ([`Containers::target`]).
//! * "Open a shell": a terminal to the session that runs `docker exec -it` (or podman) in the container
//!   ([`Containers::shell`]), opened and audited like any terminal.
//!
//! Secrets (the login, the sudo password) come from the vault for each new connection and go only to
//! the adapter. Logs and command output are shown, never audited.

pub mod marks;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use uuid::Uuid;

pub use marks::{ContainerMark, ContainerMarks, MarkInput, SudoMode};

use crate::adapters::containers::{
    ChangeOutput, ContainerDetails, ContainerEngine, ContainerEngines, ContainerId, ContainerState, ContainerStats,
    ContainerSummary, EngineChange, EngineKind, EngineVersion, ImageRef, ImageSummary, LogQuery, Logs, NetworkSummary,
    PruneWhat, SudoRun, VolumeSummary,
};
use crate::adapters::remote::{
    sh_quote, AgentSource, AuthMethod, ConnectOptions, ConnectRequest, ExecSession, RemoteAdapter, SessionSpec,
};
use crate::command_bus::ContainerOp;
use crate::domain::{now_rfc3339, ContainerHost, ContainerObject, Context, Environment, Target, TargetRef};
use crate::error::{ContainerProblem, CoreError, Result};
use crate::impact::{ContainerImpact, TargetImpact};
use crate::known_hosts::KnownHosts;
use crate::locks;
use crate::metrics::guest::{spec_key, GuestVerifier};
use crate::store::Store;
use crate::vault::{Vault, VaultStatus};

/// CT-02: Settings key for the docker.exe path (`None`: find it).
pub const DOCKER_PATH_KEY: &str = "containers.dockerPath";

/// How "This PC" reads in lists and messages.
pub const THIS_PC_NAME: &str = "This PC";

/// The shell a container shell starts: bash when the image has it, else sh.
pub const CONTAINER_SHELL: &str = "command -v bash >/dev/null && exec bash || exec sh";

/// How container reads connect. The defaults suit real networks; tests shorten them.
#[derive(Debug, Clone)]
pub struct ContainerTuning {
    pub connect_timeout: Duration,
    /// A host's connection closes after this long without a read or a change.
    pub idle: Duration,
    pub agent: AgentSource,
}

impl Default for ContainerTuning {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            idle: Duration::from_secs(180),
            agent: AgentSource::System,
        }
    }
}

/// One engine of a host, as the host list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostEngine {
    pub engine: EngineKind,
    pub sudo: SudoMode,
    /// "as the login user", "with sudo (the login password)"...
    pub runs: String,
}

/// A container host: a marked session, or this PC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerHostInfo {
    pub host: ContainerHost,
    /// The session's name, or "This PC".
    pub name: String,
    /// The session's host name or address (`None` for this PC).
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub port: Option<u16>,
    pub environment: Environment,
    pub protected: bool,
    pub engines: Vec<HostEngine>,
    /// SS-07: the jump hosts on the way, by name.
    pub via: Vec<String>,
    /// CT-02: the docker.exe in use.
    pub cli_path: Option<String>,
}

/// One read of a host's containers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerList {
    pub containers: Vec<ContainerSummary>,
    pub read_at: String,
    /// The CLI ran under sudo.
    pub sudo: bool,
}

/// What [`Containers::detect`] found for one engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedEngine {
    pub engine: EngineKind,
    pub installed: bool,
    pub version: Option<EngineVersion>,
    /// What to mark: how the CLI worked, if it did.
    pub suggested: Option<SudoMode>,
    /// Why it can't be used yet, in words (daemon down, sudo asks for a password...).
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub session_id: Uuid,
    pub engines: Vec<DetectedEngine>,
}

/// A terminal that opens a shell in a container ([`crate::terminal::Terminals::open_container_shell`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerShell {
    /// Typed into the login shell once it is ready; replaces the session's startup command.
    pub command: String,
    /// The tab's title: the container and its host.
    pub title: String,
    /// The audit entry's action and detail.
    pub action: String,
    pub detail: String,
}

/// What the job runner does on container hosts (CT-01, CT-02).
#[async_trait]
pub trait ContainerActions: Send + Sync {
    /// Carries out `op` on one [`TargetRef::Container`].
    async fn change(&self, ctx: &Context, target: &TargetRef, op: &ContainerOp) -> Result<ChangeOutput>;
}

/// A kept SSH connection to one host.
#[derive(Default)]
struct Kept {
    /// What the connection was made with: an edited session connects again.
    spec_key: String,
    connection: Option<Arc<dyn ExecSession>>,
    used: Option<Instant>,
}

/// What the last reads of one engine listed: names for targets, and the impact preview's fallback.
#[derive(Default, Clone)]
struct Seen {
    containers: Option<Vec<ContainerSummary>>,
    images: Option<Vec<ImageSummary>>,
    volumes: Option<Vec<VolumeSummary>>,
}

struct Inner {
    store: Store,
    vault: Arc<dyn Vault>,
    remote: Arc<dyn RemoteAdapter>,
    known_hosts: Arc<KnownHosts>,
    engines: Arc<dyn ContainerEngines>,
    marks: ContainerMarks,
    kept: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<Kept>>>>,
    seen: Mutex<HashMap<(ContainerHost, EngineKind), Seen>>,
    tuning: RwLock<ContainerTuning>,
}

/// The containers service. Cloning gives another handle to the same one.
#[derive(Clone)]
pub struct Containers {
    inner: Arc<Inner>,
}

impl Containers {
    pub fn new(
        store: Store,
        vault: Arc<dyn Vault>,
        remote: Arc<dyn RemoteAdapter>,
        known_hosts: Arc<KnownHosts>,
        engines: Arc<dyn ContainerEngines>,
    ) -> Self {
        let inner = Arc::new(Inner {
            marks: ContainerMarks::new(store.clone()),
            store,
            vault,
            remote,
            known_hosts,
            engines,
            kept: Mutex::default(),
            seen: Mutex::default(),
            tuning: RwLock::new(ContainerTuning::default()),
        });
        // Idle connections close on their own, without anyone reading.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak: Weak<Inner> = Arc::downgrade(&inner);
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    close_idle(&inner).await;
                }
            });
        }
        Self { inner }
    }

    pub fn set_tuning(&self, tuning: ContainerTuning) {
        *locks::write(&self.inner.tuning) = tuning;
    }

    pub fn marks(&self) -> &ContainerMarks {
        &self.inner.marks
    }

    /// CT-02: the docker.exe in use, if any.
    pub fn this_pc_cli(&self) -> Option<std::path::PathBuf> {
        self.inner.engines.this_pc_cli()
    }

    /// CT-02: looks for docker.exe again (after the Settings path changed).
    pub fn find_this_pc_cli(&self, saved: Option<&std::path::Path>) {
        self.inner.engines.find_this_pc_cli(saved);
        locks::lock(&self.inner.seen).retain(|(host, _), _| *host != ContainerHost::ThisPc);
    }

    /// The marked sessions, by name, then this PC when Docker Desktop's CLI is there. No connection.
    pub async fn hosts(&self, ctx: &Context) -> Result<Vec<ContainerHostInfo>> {
        let marks = self.inner.marks.list(ctx, None).await?;
        let mut by_session: HashMap<Uuid, Vec<ContainerMark>> = HashMap::new();
        for mark in marks {
            by_session.entry(mark.session_id).or_default().push(mark);
        }
        let mut out = Vec::new();
        for (session_id, marks) in by_session {
            let Some(session) = self.inner.store.get_session(ctx, session_id).await? else {
                continue;
            };
            let spec = self.inner.store.session_spec(ctx, session_id).await?;
            let mut engines = Vec::new();
            for mark in marks {
                engines.push(HostEngine {
                    engine: mark.engine,
                    sudo: mark.sudo,
                    runs: self.inner.marks.describe_sudo(ctx, mark.sudo).await?,
                });
            }
            out.push(ContainerHostInfo {
                host: ContainerHost::Session { session_id },
                name: session.name.clone(),
                hostname: Some(session.host.clone()),
                username: session.username.clone(),
                port: Some(session.port),
                environment: session.environment,
                protected: session.protected,
                engines,
                via: spec
                    .map(|s| s.jumps().iter().map(|j| j.name.clone()).collect())
                    .unwrap_or_default(),
                cli_path: None,
            });
        }
        out.sort_by_key(|h| h.name.to_lowercase());
        if let Some(path) = self.inner.engines.this_pc_cli() {
            out.push(ContainerHostInfo {
                host: ContainerHost::ThisPc,
                name: THIS_PC_NAME.to_owned(),
                hostname: None,
                username: None,
                port: None,
                environment: Environment::None,
                protected: false,
                engines: vec![HostEngine {
                    engine: EngineKind::Docker,
                    sudo: SudoMode::Off,
                    runs: "Docker Desktop".to_owned(),
                }],
                via: Vec::new(),
                cli_path: Some(path.display().to_string()),
            });
        }
        Ok(out)
    }

    /// CT-01: which CLIs a session's host has, and whether they work for the login user or need sudo.
    /// A read: nothing is marked until the user saves. Sudo is tried only with the session's own login
    /// password (or a chosen one), and NOPASSWD sudo is tried without one.
    pub async fn detect(
        &self,
        ctx: &Context,
        session_id: Uuid,
        sudo_password: Option<crate::vault::SecretId>,
    ) -> Result<Detection> {
        let spec = self.spec(ctx, session_id).await?;
        let connection = self.connection(ctx, &spec).await?;
        let mut engines = Vec::new();
        for kind in EngineKind::ALL {
            let probe = format!("command -v {}", kind.program());
            let found = connection.run(&probe, 4096).await?;
            if found.exit_code != Some(0) {
                engines.push(DetectedEngine {
                    engine: kind,
                    installed: false,
                    version: None,
                    suggested: None,
                    problem: None,
                });
                continue;
            }
            let plain = self
                .inner
                .engines
                .over_ssh(kind, &spec.name, Arc::clone(&connection), SudoRun::No);
            let mut detected = DetectedEngine {
                engine: kind,
                installed: true,
                version: None,
                suggested: None,
                problem: None,
            };
            match plain.version().await {
                Ok(version) => {
                    detected.version = Some(version);
                    detected.suggested = Some(SudoMode::Off);
                }
                Err(CoreError::Container {
                    problem: ContainerProblem::NeedsSudo,
                    message,
                }) => {
                    // Without a password first (NOPASSWD), then with one.
                    let no_password =
                        self.inner
                            .engines
                            .over_ssh(kind, &spec.name, Arc::clone(&connection), SudoRun::NoPassword);
                    if let Ok(version) = no_password.version().await {
                        detected.version = Some(version);
                        detected.suggested = Some(SudoMode::NoPassword);
                    } else {
                        let mode = SudoMode::Password {
                            password_id: sudo_password,
                        };
                        match self.sudo_run(ctx, &spec, mode).await {
                            Ok(run) => {
                                let with = self
                                    .inner
                                    .engines
                                    .over_ssh(kind, &spec.name, Arc::clone(&connection), run);
                                match with.version().await {
                                    Ok(version) => {
                                        detected.version = Some(version);
                                        detected.suggested = Some(mode);
                                    }
                                    Err(err) => detected.problem = Some(format!("{message}; with sudo: {err}")),
                                }
                            }
                            Err(err) => detected.problem = Some(format!("{message}. {err}")),
                        }
                    }
                }
                Err(err) => detected.problem = Some(err.to_string()),
            }
            engines.push(detected);
        }
        Ok(Detection { session_id, engines })
    }

    pub async fn version(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<EngineVersion> {
        self.engine(ctx, host, kind).await?.version().await
    }

    /// Every container on the host, stopped ones too.
    pub async fn containers(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<ContainerList> {
        let (engine, sudo) = self.engine_with_sudo(ctx, host, kind).await?;
        let containers = engine.containers().await?;
        self.remember(host, kind, |seen| seen.containers = Some(containers.clone()));
        Ok(ContainerList {
            containers,
            read_at: now_rfc3339(),
            sudo,
        })
    }

    pub async fn stats(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<Vec<ContainerStats>> {
        self.engine(ctx, host, kind).await?.stats().await
    }

    pub async fn details(
        &self,
        ctx: &Context,
        host: ContainerHost,
        kind: EngineKind,
        id: &ContainerId,
    ) -> Result<ContainerDetails> {
        self.engine(ctx, host, kind).await?.inspect(id).await
    }

    pub async fn logs(
        &self,
        ctx: &Context,
        host: ContainerHost,
        kind: EngineKind,
        id: &ContainerId,
        query: &LogQuery,
    ) -> Result<Logs> {
        self.engine(ctx, host, kind).await?.logs(id, query).await
    }

    pub async fn images(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<Vec<ImageSummary>> {
        let images = self.engine(ctx, host, kind).await?.images().await?;
        self.remember(host, kind, |seen| seen.images = Some(images.clone()));
        Ok(images)
    }

    pub async fn volumes(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<Vec<VolumeSummary>> {
        let volumes = self.engine(ctx, host, kind).await?.volumes().await?;
        self.remember(host, kind, |seen| seen.volumes = Some(volumes.clone()));
        Ok(volumes)
    }

    pub async fn networks(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<Vec<NetworkSummary>> {
        self.engine(ctx, host, kind).await?.networks().await
    }

    /// Closes a host's kept connection now (the page closed it, or the session changed).
    pub async fn release(&self, session_id: Uuid) {
        let slot = locks::lock(&self.inner.kept).remove(&session_id);
        if let Some(slot) = slot {
            let mut kept = slot.lock().await;
            if let Some(connection) = kept.connection.take() {
                connection.close().await;
            }
        }
    }

    /// The command bus's view of a container target: its name (from the engine's own list, read again
    /// if it is not known yet), and the host's label and protection. A container, image or volume the
    /// engine does not list can't be a target.
    pub async fn target(&self, ctx: &Context, target: &TargetRef) -> Result<Target> {
        let TargetRef::Container { host, engine, object } = target else {
            return Err(CoreError::WrongTargetKind {
                action: "a container action".into(),
                target: format!("a {} target", target.kind()),
            });
        };
        let (host_name, environment, protected) = self.host_label(ctx, *host, *engine).await?;
        let on = format!("on {host_name} ({})", engine.label());
        let name = match object {
            ContainerObject::Container { id } => {
                let container = self.find_container(ctx, *host, *engine, id).await?;
                format!("{} {on}", container.name)
            }
            ContainerObject::Image { id } => {
                let image = self
                    .find(
                        ctx,
                        *host,
                        *engine,
                        |seen| seen.images.as_ref(),
                        |images: &[ImageSummary]| images.iter().find(|i| i.id.same_as(id)).cloned(),
                    )
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(format!("image {} {on}", id.short())))?;
                format!("image {} {on}", image.display_name())
            }
            ContainerObject::Volume { name } => {
                self.find(
                    ctx,
                    *host,
                    *engine,
                    |seen| seen.volumes.as_ref(),
                    |volumes: &[VolumeSummary]| volumes.iter().find(|v| v.name == *name).cloned(),
                )
                .await?
                .ok_or_else(|| CoreError::UnknownTarget(format!("volume {name} {on}")))?;
                format!("volume {name} {on}")
            }
            ContainerObject::Engine => format!("{} on {host_name}", engine.label()),
        };
        Ok(Target {
            target: target.clone(),
            name,
            environment,
            protected,
        })
    }

    /// AP-02: each container target as it is now (read again), for the approval dialog. A read that
    /// fails shows the last list, and says so.
    pub async fn impact(&self, ctx: &Context, targets: &[Target], op: Option<&ContainerOp>) -> Vec<TargetImpact> {
        let mut out = Vec::new();
        let mut fresh: HashMap<(ContainerHost, EngineKind), (Seen, Option<String>)> = HashMap::new();
        for target in targets {
            let TargetRef::Container { host, engine, object } = &target.target else {
                continue;
            };
            let key = (*host, *engine);
            if let std::collections::hash_map::Entry::Vacant(slot) = fresh.entry(key) {
                slot.insert(self.read_for_impact(ctx, *host, *engine, op).await);
            }
            let Some((seen, note)) = fresh.get(&key) else {
                continue;
            };
            let mut notes: Vec<String> = note.iter().cloned().collect();
            let container = impact_of(object, seen, op, &mut notes);
            out.push(TargetImpact {
                target: target.target.key(),
                power_state: Default::default(),
                running_since: None,
                uptime_secs: None,
                snapshot_count: None,
                old_snapshot_count: None,
                notes,
                container: Some(container),
            });
        }
        out
    }

    /// "Open a shell": what a terminal to the session types to enter a running container, with sudo
    /// the way the host's engine runs (a password is asked in the terminal; QL-06 can type it).
    pub async fn shell(
        &self,
        ctx: &Context,
        session_id: Uuid,
        kind: EngineKind,
        id: &ContainerId,
    ) -> Result<ContainerShell> {
        let host = ContainerHost::Session { session_id };
        let mark = self.mark(ctx, session_id, kind).await?;
        let spec = self.spec(ctx, session_id).await?;
        // Read again: the container must be there and running now.
        let list = self.containers(ctx, host, kind).await?;
        let container = list
            .containers
            .into_iter()
            .find(|c| c.id.same_as(id))
            .ok_or_else(|| CoreError::UnknownTarget(format!("container {} on {}", id.short(), spec.name)))?;
        if container.state != ContainerState::Running {
            return Err(CoreError::InvalidInput(format!(
                "'{}' is not running ({}), so it has no shell to open. Start it first.",
                container.name, container.status
            )));
        }
        let sudo = match mark.sudo {
            SudoMode::Off => "",
            SudoMode::Password { .. } => "sudo ",
            SudoMode::NoPassword => "sudo -n ",
        };
        // The id is hex (checked when it was read), so it needs no quoting; the shell's script is quoted.
        let command = format!(
            "exec {sudo}{} exec -it {} sh -c {}",
            kind.program(),
            container.id,
            sh_quote(CONTAINER_SHELL)
        );
        let runs = self.inner.marks.describe_sudo(ctx, mark.sudo).await?;
        Ok(ContainerShell {
            command,
            title: format!("{} ({})", container.name, spec.name),
            action: format!(
                "Opened a shell in container '{}' on '{}' ({})",
                container.name,
                spec.name,
                kind.label()
            ),
            detail: format!("container {}, image {}, {runs}", container.id.short(), container.image),
        })
    }

    // ---- Helpers -----------------------------------------------------------------------------------

    async fn spec(&self, ctx: &Context, session_id: Uuid) -> Result<SessionSpec> {
        self.inner
            .store
            .session_spec(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))
    }

    async fn mark(&self, ctx: &Context, session_id: Uuid, kind: EngineKind) -> Result<ContainerMark> {
        let marks = self.inner.marks.list(ctx, Some(session_id)).await?;
        match marks.into_iter().find(|m| m.engine == kind) {
            Some(mark) => Ok(mark),
            None => {
                let name = self
                    .inner
                    .store
                    .get_session(ctx, session_id)
                    .await?
                    .map_or_else(|| "That session".to_owned(), |s| format!("'{}'", s.name));
                Err(CoreError::InvalidInput(format!(
                    "{name} is not marked as a {} host. Mark it on the Containers page first.",
                    kind.label()
                )))
            }
        }
    }

    async fn host_label(
        &self,
        ctx: &Context,
        host: ContainerHost,
        kind: EngineKind,
    ) -> Result<(String, Environment, bool)> {
        match host {
            ContainerHost::ThisPc => Ok((THIS_PC_NAME.to_owned(), Environment::None, false)),
            ContainerHost::Session { session_id } => {
                self.mark(ctx, session_id, kind).await?;
                self.inner
                    .store
                    .find_session_target(ctx, session_id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))
            }
        }
    }

    async fn engine(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<Arc<dyn ContainerEngine>> {
        Ok(self.engine_with_sudo(ctx, host, kind).await?.0)
    }

    /// The engine, and whether it runs under sudo.
    async fn engine_with_sudo(
        &self,
        ctx: &Context,
        host: ContainerHost,
        kind: EngineKind,
    ) -> Result<(Arc<dyn ContainerEngine>, bool)> {
        match host {
            ContainerHost::ThisPc => {
                if kind != EngineKind::Docker {
                    return Err(CoreError::InvalidInput(
                        "Only Docker Desktop runs on this PC; Podman is read on SSH hosts.".into(),
                    ));
                }
                let engine = self.inner.engines.this_pc().ok_or_else(|| CoreError::Container {
                    problem: ContainerProblem::CliMissing,
                    message:
                        "Docker Desktop was not found on this PC. Install it, or set the path to docker.exe in Settings"
                            .into(),
                })?;
                Ok((engine, false))
            }
            ContainerHost::Session { session_id } => {
                let mark = self.mark(ctx, session_id, kind).await?;
                let spec = self.spec(ctx, session_id).await?;
                let connection = self.connection(ctx, &spec).await?;
                let sudo = self.sudo_run(ctx, &spec, mark.sudo).await?;
                let engine = self.inner.engines.over_ssh(kind, &spec.name, connection, sudo);
                Ok((engine, mark.sudo.uses_sudo()))
            }
        }
    }

    /// BX-07's sudo password: the one chosen for the host, or the session's own login password.
    async fn sudo_run(&self, ctx: &Context, spec: &SessionSpec, mode: SudoMode) -> Result<SudoRun> {
        let id = match (mode, &spec.auth) {
            (SudoMode::Off, _) => return Ok(SudoRun::No),
            (SudoMode::NoPassword, _) => return Ok(SudoRun::NoPassword),
            (SudoMode::Password { password_id: Some(id) }, _) => {
                match self.inner.store.vault_item_kind(ctx, id).await? {
                    Some(_) => id,
                    // The chosen item was deleted: the login password, as the mark says.
                    None => match &spec.auth {
                        AuthMethod::Password(Some(login)) => *login,
                        _ => return Err(no_sudo_password(spec)),
                    },
                }
            }
            (SudoMode::Password { password_id: None }, AuthMethod::Password(Some(login))) => *login,
            (SudoMode::Password { password_id: None }, _) => return Err(no_sudo_password(spec)),
        };
        Ok(SudoRun::Password(self.inner.vault.get(ctx, id).await?))
    }

    /// The host's kept connection, or a new one: the saved login only, nothing asked.
    async fn connection(&self, ctx: &Context, spec: &SessionSpec) -> Result<Arc<dyn ExecSession>> {
        let slot = Arc::clone(locks::lock(&self.inner.kept).entry(spec.id).or_default());
        let mut kept = slot.lock().await;
        let key = spec_key(spec);
        let stale = kept.spec_key != key || kept.connection.as_ref().is_some_and(|c| c.is_closed());
        if stale {
            if let Some(old) = kept.connection.take() {
                old.close().await;
            }
        }
        if kept.connection.is_none() {
            kept.connection = Some(self.connect(ctx, spec).await?);
            kept.spec_key = key;
        }
        kept.used = Some(Instant::now());
        kept.connection
            .clone()
            .ok_or_else(|| CoreError::Ssh("no connection".into()))
    }

    async fn connect(&self, ctx: &Context, spec: &SessionSpec) -> Result<Arc<dyn ExecSession>> {
        let mut hops = spec.jumps();
        hops.push(spec);
        for hop in &hops {
            let what = if hop.id == spec.id {
                format!("'{}'", hop.name)
            } else {
                format!("the jump host '{}'", hop.name)
            };
            if hop.auth == AuthMethod::Password(None) {
                return Err(CoreError::AuthFailed(format!(
                    "no password is saved for {what}. Save it in the vault and choose it in that session, so the Containers page can log in"
                )));
            }
            let needs_vault = matches!(hop.auth, AuthMethod::Password(Some(_)) | AuthMethod::PrivateKey { .. });
            if needs_vault && self.inner.vault.status() != VaultStatus::Unlocked {
                return Err(CoreError::VaultLocked);
            }
        }
        let tuning = locks::read(&self.inner.tuning).clone();
        let credentials = crate::sessions::credentials(self.inner.vault.as_ref(), ctx, spec, None).await?;
        let jump_credentials =
            crate::sessions::jump_credentials(self.inner.vault.as_ref(), ctx, spec, &HashMap::new()).await?;
        let options = ConnectOptions {
            connect_timeout: tuning.connect_timeout,
            agent: tuning.agent.clone(),
            ..ConnectOptions::default()
        };
        let verifier = Arc::new(GuestVerifier {
            known_hosts: Arc::clone(&self.inner.known_hosts),
            ctx: *ctx,
            target: Target {
                target: TargetRef::Session { session_id: spec.id },
                name: spec.name.clone(),
                environment: spec.environment,
                protected: false,
            },
            record_blocked: true,
        });
        let limit = tuning.connect_timeout.saturating_mul(2);
        let connected = tokio::time::timeout(
            limit,
            self.inner.remote.connect(ConnectRequest {
                session: spec,
                credentials,
                jump_credentials,
                options: &options,
                verifier,
            }),
        )
        .await
        .map_err(|_| CoreError::Timeout {
            command: format!("logging in to '{}'", spec.name),
            seconds: limit.as_secs(),
        })?;
        match connected {
            Ok(connection) => Ok(Arc::from(connection)),
            // Unlike a bulk run, the user can't tick "trust new keys" here.
            Err(CoreError::HostKeyUnknown { address, jump }) => {
                let place = match &jump {
                    Some(name) => format!("the jump host '{name}' ({address})"),
                    None => address.clone(),
                };
                Err(CoreError::Ssh(format!(
                    "the host key of {place} is not trusted yet. Connect to it once in a terminal to check and trust it"
                )))
            }
            Err(err) => Err(err),
        }
    }

    fn remember(&self, host: ContainerHost, kind: EngineKind, update: impl FnOnce(&mut Seen)) {
        update(locks::lock(&self.inner.seen).entry((host, kind)).or_default());
    }

    fn seen(&self, host: ContainerHost, kind: EngineKind) -> Seen {
        locks::lock(&self.inner.seen)
            .get(&(host, kind))
            .cloned()
            .unwrap_or_default()
    }

    async fn find_container(
        &self,
        ctx: &Context,
        host: ContainerHost,
        kind: EngineKind,
        id: &ContainerId,
    ) -> Result<ContainerSummary> {
        let pick = |list: &[ContainerSummary]| list.iter().find(|c| c.id.same_as(id)).cloned();
        if let Some(found) = self.seen(host, kind).containers.as_deref().and_then(pick) {
            return Ok(found);
        }
        let list = self.containers(ctx, host, kind).await?;
        pick(&list.containers).ok_or_else(|| CoreError::UnknownTarget(format!("container {}", id.short())))
    }

    /// One image or volume from the last list, or from a new read when it is not there.
    async fn find<T: Clone>(
        &self,
        ctx: &Context,
        host: ContainerHost,
        kind: EngineKind,
        list: impl Fn(&Seen) -> Option<&Vec<T>>,
        pick: impl Fn(&[T]) -> Option<T>,
    ) -> Result<Option<T>> {
        let seen = self.seen(host, kind);
        if let Some(found) = list(&seen).and_then(|l| pick(l)) {
            return Ok(Some(found));
        }
        // Not in the last list (or none was read): ask the engine again.
        self.images_or_volumes_again(ctx, host, kind).await?;
        let seen = self.seen(host, kind);
        Ok(list(&seen).and_then(|l| pick(l)))
    }

    async fn images_or_volumes_again(&self, ctx: &Context, host: ContainerHost, kind: EngineKind) -> Result<()> {
        self.images(ctx, host, kind).await?;
        self.volumes(ctx, host, kind).await?;
        Ok(())
    }

    /// What the impact preview needs of one engine, read now; the last lists when that fails.
    async fn read_for_impact(
        &self,
        ctx: &Context,
        host: ContainerHost,
        kind: EngineKind,
        op: Option<&ContainerOp>,
    ) -> (Seen, Option<String>) {
        let needs_images = matches!(
            op,
            Some(ContainerOp::RemoveImage | ContainerOp::Pull { .. })
                | Some(ContainerOp::Prune {
                    what: PruneWhat::Images
                })
        );
        let needs_volumes = matches!(
            op,
            Some(ContainerOp::RemoveVolume)
                | Some(ContainerOp::Prune {
                    what: PruneWhat::Volumes
                })
        );
        let read = async {
            self.containers(ctx, host, kind).await?;
            if needs_images {
                self.images(ctx, host, kind).await?;
            }
            if needs_volumes {
                self.volumes(ctx, host, kind).await?;
            }
            Ok::<(), CoreError>(())
        };
        let note = match read.await {
            Ok(()) => None,
            Err(err) => Some(format!("From the last list; reading it again failed: {err}")),
        };
        (self.seen(host, kind), note)
    }

    /// After a change the lists are out of date: names are read again next time.
    fn forget(&self, host: ContainerHost, kind: EngineKind) {
        locks::lock(&self.inner.seen).remove(&(host, kind));
    }
}

fn no_sudo_password(spec: &SessionSpec) -> CoreError {
    CoreError::NoSudoPassword(format!(
        "'{}' has no saved login password for sudo. Choose the password sudo takes for this host",
        spec.name
    ))
}

async fn close_idle(inner: &Inner) {
    let idle = locks::read(&inner.tuning).idle;
    let slots: Vec<(Uuid, Arc<tokio::sync::Mutex<Kept>>)> = locks::lock(&inner.kept)
        .iter()
        .map(|(id, s)| (*id, Arc::clone(s)))
        .collect();
    for (id, slot) in slots {
        // In use right now: not idle.
        let Ok(mut kept) = slot.try_lock() else {
            continue;
        };
        let expired = kept.used.is_none_or(|used| used.elapsed() >= idle);
        if expired {
            if let Some(connection) = kept.connection.take() {
                connection.close().await;
            }
            drop(kept);
            locks::lock(&inner.kept).remove(&id);
        }
    }
}

/// Most names one impact entry lists.
const MAX_LISTED: usize = 50;

fn listed(names: impl Iterator<Item = String>) -> Vec<String> {
    names.take(MAX_LISTED).collect()
}

/// One target's impact entry from the lists read for it.
fn impact_of(
    object: &ContainerObject,
    seen: &Seen,
    op: Option<&ContainerOp>,
    notes: &mut Vec<String>,
) -> ContainerImpact {
    let containers = seen.containers.as_deref().unwrap_or_default();
    match object {
        ContainerObject::Container { id } => match containers.iter().find(|c| c.id.same_as(id)) {
            Some(c) => ContainerImpact {
                kind: "container".into(),
                name: c.name.clone(),
                state: Some(c.state),
                status: Some(c.status.clone()),
                image: Some(c.image.clone()),
                ports: c.ports.iter().map(|p| p.describe()).collect(),
                ..ContainerImpact::empty("container", id.short())
            },
            None => {
                notes.push("It is no longer in the engine's list".into());
                ContainerImpact::empty("container", id.short())
            }
        },
        ContainerObject::Image { id } => {
            let image = seen
                .images
                .as_deref()
                .unwrap_or_default()
                .iter()
                .find(|i| i.id.same_as(id));
            let used_by = listed(
                containers
                    .iter()
                    .filter(|c| image.is_some_and(|i| i.tags.contains(&c.image)) || c.image.contains(id.short()))
                    .map(|c| format!("{} ({})", c.name, c.state.as_str())),
            );
            match image {
                Some(i) => ContainerImpact {
                    size_bytes: i.size_bytes,
                    used_by,
                    ..ContainerImpact::empty("image", &i.display_name())
                },
                None => {
                    notes.push("It is no longer in the engine's list".into());
                    ContainerImpact::empty("image", id.short())
                }
            }
        }
        ContainerObject::Volume { name } => {
            let used_by = listed(
                containers
                    .iter()
                    .filter(|c| c.mounts.iter().any(|m| m == name.as_str()))
                    .map(|c| format!("{} ({})", c.name, c.state.as_str())),
            );
            let mut impact = ContainerImpact {
                used_by,
                ..ContainerImpact::empty("volume", name.as_str())
            };
            impact.removes.push(format!("every file in the volume {name}"));
            impact
        }
        ContainerObject::Engine => {
            let mut impact = ContainerImpact::empty("engine", "");
            match op {
                Some(ContainerOp::Prune {
                    what: PruneWhat::Containers,
                }) => {
                    impact.removes = listed(
                        containers
                            .iter()
                            .filter(|c| {
                                matches!(
                                    c.state,
                                    ContainerState::Exited | ContainerState::Created | ContainerState::Dead
                                )
                            })
                            .map(|c| format!("container {} ({})", c.name, c.status)),
                    );
                }
                Some(ContainerOp::Prune {
                    what: PruneWhat::Images,
                }) => {
                    impact.removes = listed(
                        seen.images
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .filter(|i| i.dangling)
                            .map(|i| format!("image {} (no tag)", i.id.short())),
                    );
                }
                Some(ContainerOp::Prune {
                    what: PruneWhat::Volumes,
                }) => {
                    let in_use: Vec<&str> = containers
                        .iter()
                        .flat_map(|c| c.mounts.iter().map(String::as_str))
                        .collect();
                    impact.removes = listed(
                        seen.volumes
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .filter(|v| !in_use.contains(&v.name.as_str()))
                            .map(|v| {
                                let what = if v.anonymous { "anonymous volume" } else { "volume" };
                                format!("{what} {} and its data", v.name)
                            }),
                    );
                    notes.push(
                        "Docker 23 and later prune only anonymous volumes; older Docker and Podman prune every volume no container uses"
                            .into(),
                    );
                }
                Some(ContainerOp::Prune {
                    what: PruneWhat::BuildCache,
                }) => impact.removes.push("the build cache".into()),
                Some(ContainerOp::Pull { reference }) => {
                    let wanted = ImageRef::parse(reference)
                        .map(|r| r.as_str().to_owned())
                        .unwrap_or_default();
                    if let Some(old) = seen.images.as_deref().unwrap_or_default().iter().find(|i| {
                        i.tags
                            .iter()
                            .any(|t| *t == wanted || t.ends_with(&format!("/{wanted}")))
                    }) {
                        notes.push(format!(
                            "{wanted} is image {} now; containers made from it keep running it",
                            old.id.short()
                        ));
                    }
                }
                _ => {}
            }
            impact
        }
    }
}

#[async_trait]
impl ContainerActions for Containers {
    async fn change(&self, ctx: &Context, target: &TargetRef, op: &ContainerOp) -> Result<ChangeOutput> {
        let TargetRef::Container { host, engine, object } = target else {
            return Err(CoreError::WrongTargetKind {
                action: "a container action".into(),
                target: format!("a {} target", target.kind()),
            });
        };
        let change = engine_change(object, op)?;
        let result = self.engine(ctx, *host, *engine).await?.change(&change).await;
        self.forget(*host, *engine);
        result
    }
}

/// The engine call for an op on one object; [`Command::validate`](crate::command_bus::Command) has
/// checked they fit.
pub fn engine_change(object: &ContainerObject, op: &ContainerOp) -> Result<EngineChange> {
    let mismatch = || {
        CoreError::InvalidInput(format!(
            "{} can't act on {} {}",
            op.label(),
            match object {
                ContainerObject::Image { .. } => "an",
                _ => "a",
            },
            object.kind()
        ))
    };
    Ok(match (op, object) {
        (ContainerOp::Start, ContainerObject::Container { id }) => EngineChange::Start(id.clone()),
        (ContainerOp::Stop, ContainerObject::Container { id }) => EngineChange::Stop(id.clone()),
        (ContainerOp::Restart, ContainerObject::Container { id }) => EngineChange::Restart(id.clone()),
        (ContainerOp::Pause, ContainerObject::Container { id }) => EngineChange::Pause(id.clone()),
        (ContainerOp::Unpause, ContainerObject::Container { id }) => EngineChange::Unpause(id.clone()),
        (ContainerOp::Remove { force }, ContainerObject::Container { id }) => EngineChange::Remove {
            id: id.clone(),
            force: *force,
        },
        (ContainerOp::RemoveImage, ContainerObject::Image { id }) => EngineChange::RemoveImage(id.clone()),
        (ContainerOp::RemoveVolume, ContainerObject::Volume { name }) => EngineChange::RemoveVolume(name.clone()),
        (ContainerOp::Pull { reference }, ContainerObject::Engine) => EngineChange::Pull(ImageRef::parse(reference)?),
        (ContainerOp::Prune { what }, ContainerObject::Engine) => EngineChange::Prune(*what),
        _ => return Err(mismatch()),
    })
}
