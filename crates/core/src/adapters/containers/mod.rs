//! Container engines (CT-01, CT-02): Docker and Podman on SSH hosts, and Docker Desktop on this PC.
//!
//! Every engine is driven through its own CLI with JSON output (`--format '{{json .}}'` for Docker,
//! `--format json` for Podman), parsed field by field so the formats of different versions all read
//! ([`parse`]). [`ContainerEngine`] is what the core asks of an engine; [`cli::CliEngine`] is the one
//! implementation, over two kinds of [`cli::Cli`]:
//!
//! * [`cli::SshCli`]: `docker` or `podman` on a host, on an exec channel of a logged-in SSH connection
//!   (so jump hosts and host key checks apply as for any connection), with sudo when the host needs
//!   it: the password goes on stdin as for bulk runs (BX-07), or none for NOPASSWD.
//! * [`cli::LocalCli`]: Docker Desktop's `docker.exe` on this PC, found like vmrun
//!   ([`cli::locate_docker`]), run without a shell or a console window.
//!
//! Ids, names and references reach a command line only after [`names`] checked them, and on a host
//! every word is shell-quoted as well. Reads change nothing; changes only run from the job runner,
//! after the command bus and the policy engine ([`EngineChange`]).

pub mod cli;
pub mod names;
pub mod parse;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::adapters::remote::ExecSession;
use crate::error::Result;
use crate::vault::SecretString;

pub use names::{ContainerId, ImageId, ImageRef, VolumeName};

/// Which CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EngineKind {
    Docker,
    Podman,
}

impl EngineKind {
    pub const ALL: [EngineKind; 2] = [EngineKind::Docker, EngineKind::Podman];

    pub fn as_str(self) -> &'static str {
        match self {
            EngineKind::Docker => "docker",
            EngineKind::Podman => "podman",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == text)
    }

    /// "Docker", "Podman".
    pub fn label(self) -> &'static str {
        match self {
            EngineKind::Docker => "Docker",
            EngineKind::Podman => "Podman",
        }
    }

    /// The program on the host.
    pub fn program(self) -> &'static str {
        self.as_str()
    }
}

/// A container's state, as both engines name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContainerState {
    Created,
    Running,
    Paused,
    Restarting,
    Removing,
    /// Docker's "exited", Podman's "exited" and "stopped".
    Exited,
    Dead,
    #[default]
    Unknown,
}

impl ContainerState {
    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "created" | "configured" | "initialized" => ContainerState::Created,
            "running" | "up" => ContainerState::Running,
            "paused" => ContainerState::Paused,
            "restarting" => ContainerState::Restarting,
            "removing" => ContainerState::Removing,
            "exited" | "stopped" | "stopping" => ContainerState::Exited,
            "dead" => ContainerState::Dead,
            _ => ContainerState::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ContainerState::Created => "created",
            ContainerState::Running => "running",
            ContainerState::Paused => "paused",
            ContainerState::Restarting => "restarting",
            ContainerState::Removing => "removing",
            ContainerState::Exited => "exited",
            ContainerState::Dead => "dead",
            ContainerState::Unknown => "unknown",
        }
    }

    /// Running, paused or restarting: it has a process.
    pub fn is_up(self) -> bool {
        matches!(
            self,
            ContainerState::Running | ContainerState::Paused | ContainerState::Restarting
        )
    }
}

/// A published port: `0.0.0.0:8080->80/tcp`, or `443/tcp` when it is only exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    pub host_ip: Option<String>,
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: String,
}

impl PortMapping {
    pub fn describe(&self) -> String {
        match (&self.host_ip, self.host_port) {
            (Some(ip), Some(port)) if !ip.is_empty() => {
                let ip = if ip.contains(':') {
                    format!("[{ip}]")
                } else {
                    ip.clone()
                };
                format!("{ip}:{port}->{}/{}", self.container_port, self.protocol)
            }
            (_, Some(port)) => format!("{port}->{}/{}", self.container_port, self.protocol),
            _ => format!("{}/{}", self.container_port, self.protocol),
        }
    }
}

/// One row of the container list.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSummary {
    pub id: ContainerId,
    pub name: String,
    /// What it was created from, as the engine names it (`nginx:1.27`, or an id).
    pub image: String,
    pub command: Option<String>,
    pub state: ContainerState,
    /// The engine's own words, e.g. "Up 2 hours (healthy)" or "Exited (0) 3 days ago".
    pub status: String,
    /// RFC 3339 when the engine gave a time that reads as one.
    pub created_at: Option<String>,
    /// Podman says when it started; Docker's list does not (its inspect does).
    pub started_at: Option<String>,
    pub ports: Vec<PortMapping>,
    pub networks: Vec<String>,
    /// Docker: volume names and bind sources; Podman: where they are mounted.
    pub mounts: Vec<String>,
    /// From the Compose label, when it has one.
    pub project: Option<String>,
    /// "healthy", "unhealthy" or "starting", from a health check.
    pub health: Option<String>,
}

/// One container's resource use right now (`stats --no-stream`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerStats {
    pub id: ContainerId,
    pub name: Option<String>,
    pub cpu_pct: Option<f64>,
    pub mem_bytes: Option<u64>,
    pub mem_limit_bytes: Option<u64>,
    pub mem_pct: Option<f64>,
    pub net_rx_bytes: Option<u64>,
    pub net_tx_bytes: Option<u64>,
    pub block_read_bytes: Option<u64>,
    pub block_write_bytes: Option<u64>,
    pub pids: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MountInfo {
    /// "volume", "bind", "tmpfs"...
    pub kind: String,
    /// The volume's name, for a volume.
    pub name: Option<String>,
    pub source: Option<String>,
    pub destination: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkAttachment {
    pub name: String,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthInfo {
    /// "healthy", "unhealthy", "starting".
    pub status: String,
    pub failing_streak: Option<i64>,
}

/// What `inspect` says about one container. Environment variables are listed by name only: their
/// values often hold passwords and tokens, so they never leave the parser.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerDetails {
    pub id: ContainerId,
    pub name: String,
    pub image: String,
    pub image_id: Option<String>,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub state: ContainerState,
    pub exit_code: Option<i64>,
    /// Why it failed to start, when it did.
    pub error: Option<String>,
    pub oom_killed: bool,
    pub health: Option<HealthInfo>,
    /// "no", "always", "unless-stopped", "on-failure" (with "on-failure:3" for a retry limit).
    pub restart_policy: Option<String>,
    pub restart_count: Option<i64>,
    pub command: Option<String>,
    pub entrypoint: Option<String>,
    pub working_dir: Option<String>,
    /// The user its processes run as (`Config.User`), when set.
    pub runs_as: Option<String>,
    pub env_names: Vec<String>,
    pub mounts: Vec<MountInfo>,
    pub networks: Vec<NetworkAttachment>,
    pub ports: Vec<PortMapping>,
    pub project: Option<String>,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageSummary {
    pub id: ImageId,
    /// `repository:tag` for each tag; empty for a dangling image.
    pub tags: Vec<String>,
    pub digest: Option<String>,
    pub created_at: Option<String>,
    pub size_bytes: Option<u64>,
    /// Containers made from it, when the engine counts them.
    pub containers: Option<u64>,
    /// No tag: what `image prune` removes.
    pub dangling: bool,
}

impl ImageSummary {
    /// The first tag, or the short id.
    pub fn display_name(&self) -> String {
        self.tags.first().cloned().unwrap_or_else(|| self.id.short().to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeSummary {
    pub name: VolumeName,
    pub driver: Option<String>,
    pub mountpoint: Option<String>,
    pub scope: Option<String>,
    pub created_at: Option<String>,
    pub project: Option<String>,
    /// Named by the engine with 64 hex digits, not by anyone.
    pub anonymous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSummary {
    pub id: String,
    pub name: String,
    pub driver: Option<String>,
    pub scope: Option<String>,
    pub internal: Option<bool>,
    pub ipv6: Option<bool>,
    pub subnets: Vec<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineVersion {
    pub client: Option<String>,
    /// The daemon's (Docker) or the service's (a remote Podman) version; `None` for local Podman.
    pub server: Option<String>,
    pub api: Option<String>,
    /// e.g. `linux/amd64`.
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LogStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogLine {
    /// When the engine logged it (RFC 3339, nanoseconds).
    pub at: Option<String>,
    pub stream: LogStream,
    pub text: String,
}

/// The most log lines one read takes.
pub const MAX_LOG_TAIL: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogQuery {
    /// The last lines (1 to [`MAX_LOG_TAIL`]).
    pub tail: u32,
    /// Only lines after this time: the last line's `at` from the previous read, to follow a log.
    #[serde(default)]
    pub since: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Logs {
    pub lines: Vec<LogLine>,
    /// The output was longer than Remotely keeps, so the oldest lines were dropped.
    pub truncated: bool,
}

/// What a prune removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PruneWhat {
    /// Stopped containers.
    Containers,
    /// Dangling images (no tag, no container).
    Images,
    /// Volumes no container uses (anonymous ones only on Docker 23 and later). Deletes data.
    Volumes,
    /// Docker's build cache. Podman keeps none of its own.
    BuildCache,
}

impl PruneWhat {
    pub fn label(self) -> &'static str {
        match self {
            PruneWhat::Containers => "stopped containers",
            PruneWhat::Images => "unused images",
            PruneWhat::Volumes => "unused volumes",
            PruneWhat::BuildCache => "the build cache",
        }
    }
}

/// A change the job runner asks an engine for, with its ids checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineChange {
    Start(ContainerId),
    Stop(ContainerId),
    Restart(ContainerId),
    Pause(ContainerId),
    Unpause(ContainerId),
    Remove { id: ContainerId, force: bool },
    RemoveImage(ImageId),
    RemoveVolume(VolumeName),
    Pull(ImageRef),
    Prune(PruneWhat),
}

/// How a change went: the CLI's output, kept with the job (never in the audit log).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeOutput {
    pub stdout: String,
    pub stderr: String,
    /// One line for the job's audit entry, e.g. "reclaimed 1.2GB" after a prune. Never output text
    /// that could hold a secret.
    pub note: Option<String>,
}

/// One engine on one host. Reads never change anything; [`ContainerEngine::change`] is only called by
/// the job runner.
#[async_trait]
pub trait ContainerEngine: Send + Sync {
    fn kind(&self) -> EngineKind;
    /// Also how a host is checked: the CLI is there, and the user may use it.
    async fn version(&self) -> Result<EngineVersion>;
    /// Every container, stopped ones too.
    async fn containers(&self) -> Result<Vec<ContainerSummary>>;
    /// Running containers' resource use, one sample.
    async fn stats(&self) -> Result<Vec<ContainerStats>>;
    async fn inspect(&self, id: &ContainerId) -> Result<ContainerDetails>;
    async fn logs(&self, id: &ContainerId, query: &LogQuery) -> Result<Logs>;
    async fn images(&self) -> Result<Vec<ImageSummary>>;
    async fn volumes(&self) -> Result<Vec<VolumeSummary>>;
    async fn networks(&self) -> Result<Vec<NetworkSummary>>;
    async fn change(&self, change: &EngineChange) -> Result<ChangeOutput>;
}

/// How an engine's commands use sudo on a host.
#[derive(Clone)]
pub enum SudoRun {
    /// As the login user (in the `docker` group, or rootless Podman).
    No,
    /// `sudo -S`, with this password on stdin (BX-07).
    Password(SecretString),
    /// `sudo -n`: sudoers lets the user in without a password.
    NoPassword,
}

/// Makes engines (the adapter's entry point, so tests can give fakes instead).
pub trait ContainerEngines: Send + Sync {
    /// CT-01: `docker` or `podman` on the host of `connection`. `host` names it in messages.
    fn over_ssh(
        &self,
        kind: EngineKind,
        host: &str,
        connection: Arc<dyn ExecSession>,
        sudo: SudoRun,
    ) -> Arc<dyn ContainerEngine>;

    /// CT-02: Docker Desktop on this PC, when its CLI was found.
    fn this_pc(&self) -> Option<Arc<dyn ContainerEngine>>;

    /// CT-02: the docker.exe in use, if any.
    fn this_pc_cli(&self) -> Option<PathBuf>;

    /// CT-02: looks for docker.exe again, with the path saved in Settings first (`None`: find it).
    fn find_this_pc_cli(&self, saved: Option<&Path>);
}
