//! CT-01, CT-02: the container CLIs, on a host over SSH or on this PC.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;

use super::names::{shell_line, shown};
use super::{
    parse, ChangeOutput, ContainerDetails, ContainerEngine, ContainerEngines, ContainerId, ContainerStats,
    ContainerSummary, EngineChange, EngineKind, EngineVersion, ImageSummary, LogQuery, Logs, NetworkSummary, PruneWhat,
    SudoRun, VolumeSummary, MAX_LOG_TAIL,
};
use crate::adapters::remote::ExecSession;
use crate::error::{ContainerProblem, CoreError, Result};
use crate::locks;

/// How long a read may take, and how much of its output is kept.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Lists of a few thousand containers or images, with `--no-trunc`.
const MAX_READ_OUTPUT: usize = 8 * 1024 * 1024;
/// Start, stop (which waits up to 10 s for the process), restart, pause, remove.
const CHANGE_TIMEOUT: Duration = Duration::from_secs(120);
/// Pulling a large image, or pruning many.
const LONG_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// What a change keeps of its output for the job.
const MAX_CHANGE_OUTPUT: usize = 64 * 1024;

/// What a CLI printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOutput {
    /// `None` when a signal ended it or no status came back.
    pub status: Option<i64>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

/// Runs the engine's program.
#[async_trait]
pub trait Cli: Send + Sync {
    /// Runs it with these arguments: without a shell on this PC, each word shell-quoted on a host.
    async fn run(&self, args: &[String], timeout: Duration, max_output: usize) -> Result<CliOutput>;
    /// Where it runs, for messages: the session's name, or "this PC".
    fn place(&self) -> &str;
    /// The sudo it uses, if any (messages say so).
    fn sudo(&self) -> bool {
        false
    }
}

/// CT-01: `docker` or `podman` on a host, on exec channels of a logged-in SSH connection.
pub struct SshCli {
    kind: EngineKind,
    host: String,
    connection: Arc<dyn ExecSession>,
    sudo: SudoRun,
}

impl SshCli {
    pub fn new(kind: EngineKind, host: &str, connection: Arc<dyn ExecSession>, sudo: SudoRun) -> Self {
        Self {
            kind,
            host: host.to_owned(),
            connection,
            sudo,
        }
    }
}

#[async_trait]
impl Cli for SshCli {
    async fn run(&self, args: &[String], timeout: Duration, max_output: usize) -> Result<CliOutput> {
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(self.kind.program().to_owned());
        argv.extend(args.iter().cloned());
        let line = shell_line(&argv);
        let ran = match &self.sudo {
            SudoRun::No => tokio::time::timeout(timeout, self.connection.run(&line, max_output)).await,
            // `-n`: never asks; fails at once if sudoers wants a password after all.
            SudoRun::NoPassword => {
                tokio::time::timeout(timeout, self.connection.run(&format!("sudo -n {line}"), max_output)).await
            }
            SudoRun::Password(password) => {
                tokio::time::timeout(timeout, self.connection.run_sudo(&line, password, max_output)).await
            }
        };
        let result = ran.map_err(|_| CoreError::Timeout {
            command: format!("{} {}", self.kind.program(), args.first().map_or("", String::as_str)),
            seconds: timeout.as_secs(),
        })??;
        Ok(CliOutput {
            status: result.exit_code.map(i64::from),
            truncated: result.output.truncated,
            stdout: result.output.stdout,
            stderr: result.output.stderr,
        })
    }

    fn place(&self) -> &str {
        &self.host
    }

    fn sudo(&self) -> bool {
        !matches!(self.sudo, SudoRun::No)
    }
}

/// CT-02: Docker Desktop's docker.exe on this PC, run without a shell or a console window.
pub struct LocalCli {
    path: PathBuf,
}

impl LocalCli {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

/// At most `max` bytes of `bytes`, as text.
fn capped(bytes: &[u8], max: usize) -> (String, bool) {
    let cut = bytes.len() > max;
    let kept = if cut { &bytes[..max] } else { bytes };
    (String::from_utf8_lossy(kept).into_owned(), cut)
}

#[async_trait]
impl Cli for LocalCli {
    async fn run(&self, args: &[String], timeout: Duration, max_output: usize) -> Result<CliOutput> {
        let mut cmd = tokio::process::Command::new(&self.path);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let output = match tokio::time::timeout(timeout, cmd.output()).await {
            Err(_) => {
                return Err(CoreError::Timeout {
                    command: format!("docker {}", args.first().map_or("", String::as_str)),
                    seconds: timeout.as_secs(),
                })
            }
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(CoreError::Container {
                    problem: ContainerProblem::CliMissing,
                    message: format!(
                        "{} is gone. Install Docker Desktop, or set the path to docker.exe in Settings",
                        self.path.display()
                    ),
                })
            }
            Ok(other) => other?,
        };
        let (stdout, cut_out) = capped(&output.stdout, max_output);
        let (stderr, cut_err) = capped(&output.stderr, max_output);
        Ok(CliOutput {
            status: output.status.code().map(i64::from),
            stdout,
            stderr,
            truncated: cut_out || cut_err,
        })
    }

    fn place(&self) -> &str {
        "this PC"
    }
}

/// CT-01, CT-02: finds Docker Desktop's CLI like vmrun: the path saved in Settings, then
/// `REMOTELY_DOCKER`, then Docker Desktop's install folder.
pub fn locate_docker(saved: Option<&Path>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(saved.map(Path::to_path_buf));
    candidates.extend(std::env::var_os("REMOTELY_DOCKER").map(PathBuf::from));
    if let Some(dir) = std::env::var_os("ProgramFiles") {
        candidates.push(PathBuf::from(dir).join(r"Docker\Docker\resources\bin\docker.exe"));
    }
    candidates.push(PathBuf::from(
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
    ));
    candidates.into_iter().find(|p| p.is_file())
}

/// CT-02: a path saved in Settings must be an existing docker.exe.
pub fn validate_docker_path(path: &Path) -> Result<()> {
    let named = path
        .file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("docker.exe"));
    if !named || !path.is_file() {
        return Err(CoreError::InvalidSetting(format!(
            "{} is not docker.exe. Docker Desktop puts it in C:\\Program Files\\Docker\\Docker\\resources\\bin",
            path.display()
        )));
    }
    Ok(())
}

/// The engines the app uses: the real CLIs.
pub struct CliEngines {
    this_pc: RwLock<Option<PathBuf>>,
    /// Tests never look for this PC's Docker.
    find_this_pc: bool,
}

impl CliEngines {
    /// The app: SSH engines, and Docker Desktop's CLI when it is found.
    pub fn new(saved: Option<&Path>) -> Self {
        let engines = Self {
            this_pc: RwLock::new(None),
            find_this_pc: true,
        };
        engines.find_this_pc_cli(saved);
        engines
    }

    /// SSH engines only: never this PC's Docker (tests).
    pub fn without_this_pc() -> Self {
        Self {
            this_pc: RwLock::new(None),
            find_this_pc: false,
        }
    }
}

impl ContainerEngines for CliEngines {
    fn over_ssh(
        &self,
        kind: EngineKind,
        host: &str,
        connection: Arc<dyn ExecSession>,
        sudo: SudoRun,
    ) -> Arc<dyn ContainerEngine> {
        Arc::new(CliEngine::new(
            kind,
            Box::new(SshCli::new(kind, host, connection, sudo)),
        ))
    }

    fn this_pc(&self) -> Option<Arc<dyn ContainerEngine>> {
        let path = locks::read(&self.this_pc).clone()?;
        Some(Arc::new(CliEngine::new(
            EngineKind::Docker,
            Box::new(LocalCli::new(path)),
        )))
    }

    fn this_pc_cli(&self) -> Option<PathBuf> {
        locks::read(&self.this_pc).clone()
    }

    fn find_this_pc_cli(&self, saved: Option<&Path>) {
        if self.find_this_pc {
            *locks::write(&self.this_pc) = locate_docker(saved);
        }
    }
}

/// The first line worth showing of what a CLI printed on failure.
fn first_line(out: &CliOutput) -> String {
    let line = out
        .stderr
        .lines()
        .chain(out.stdout.lines())
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no message");
    let line = line
        .trim_start_matches("Error: ")
        .trim_start_matches("Error response from daemon: ");
    let mut text = parse::clean(line);
    if text.chars().count() > 300 {
        text = text.chars().take(300).collect::<String>() + "…";
    }
    text
}

/// Why a CLI call failed, in words the UI can act on.
pub fn failure(kind: EngineKind, out: &CliOutput, place: &str, sudo: bool, what: &str) -> CoreError {
    let lower = format!("{}\n{}", out.stderr, out.stdout).to_ascii_lowercase();
    let program = kind.program();
    let label = kind.label();
    let problem = |problem, message: String| CoreError::Container { problem, message };
    let missing = out.status == Some(127)
        || lower.contains(&format!("{program}: not found"))
        || lower.contains(&format!("{program}: command not found"))
        || lower.contains(&format!("sudo: {program}: command not found"));
    if missing {
        return problem(
            ContainerProblem::CliMissing,
            format!("{label} is not installed on {place}: there is no {program} command"),
        );
    }
    if lower.contains("sudo: a password is required") || lower.contains("sudo: a terminal is required") {
        return problem(
            ContainerProblem::NeedsSudo,
            format!("sudo on {place} asks for a password. Choose the password sudo takes for this host"),
        );
    }
    let socket = lower.contains("docker.sock") || lower.contains("daemon socket") || lower.contains("docker api");
    if lower.contains("permission denied") && socket {
        let advice = if sudo {
            "even with sudo"
        } else {
            "Use sudo for this host, or add the user to the docker group"
        };
        return problem(
            ContainerProblem::NeedsSudo,
            format!("the Docker daemon on {place} refused the user (permission denied). {advice}"),
        );
    }
    let down = [
        "cannot connect to the docker daemon",
        "failed to connect to the docker api",
        "is the docker daemon running",
        "error during connect",
        "cannot connect to podman",
    ];
    if down.iter().any(|d| lower.contains(d)) {
        let message = if place == "this PC" {
            "Docker Desktop is not running on this PC. Start it, then refresh".to_owned()
        } else {
            format!("the {label} service on {place} is not running")
        };
        return problem(ContainerProblem::DaemonDown, message);
    }
    let gone = [
        "no such container",
        "no such image",
        "no such volume",
        "no container with name or id",
        "image not known",
        "no volume with name",
        "no such object",
    ];
    if gone.iter().any(|g| lower.contains(g)) {
        return problem(
            ContainerProblem::NotFound,
            format!("{label} on {place} could not {what}: {}", first_line(out)),
        );
    }
    problem(
        ContainerProblem::Failed,
        format!("{label} on {place} could not {what}: {}", first_line(out)),
    )
}

/// CT-01, CT-02: an engine driven through its CLI.
pub struct CliEngine {
    kind: EngineKind,
    cli: Box<dyn Cli>,
}

impl CliEngine {
    pub fn new(kind: EngineKind, cli: Box<dyn Cli>) -> Self {
        Self { kind, cli }
    }

    /// `--format '{{json .}}'` (Docker: one object per line) or `--format json` (Podman: an array).
    fn format(&self) -> [String; 2] {
        let format = match self.kind {
            EngineKind::Docker => "{{json .}}",
            EngineKind::Podman => "json",
        };
        ["--format".to_owned(), format.to_owned()]
    }

    fn words(&self, words: &[&str], json: bool) -> Vec<String> {
        let mut args: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
        if json {
            args.extend(self.format());
        }
        args
    }

    async fn call(&self, args: Vec<String>, timeout: Duration, max: usize, what: &str) -> Result<CliOutput> {
        let out = self.cli.run(&args, timeout, max).await?;
        if out.status != Some(0) {
            return Err(failure(self.kind, &out, self.cli.place(), self.cli.sudo(), what));
        }
        Ok(out)
    }

    /// A read whose output must be whole to be read.
    async fn read(&self, args: Vec<String>, what: &str) -> Result<String> {
        let out = self.call(args, READ_TIMEOUT, MAX_READ_OUTPUT, what).await?;
        if out.truncated {
            return Err(CoreError::Container {
                problem: ContainerProblem::Unreadable,
                message: format!(
                    "{} on {} printed more than {} MB to {what}",
                    self.kind.label(),
                    self.cli.place(),
                    MAX_READ_OUTPUT / (1024 * 1024)
                ),
            });
        }
        Ok(out.stdout)
    }
}

#[async_trait]
impl ContainerEngine for CliEngine {
    fn kind(&self) -> EngineKind {
        self.kind
    }

    async fn version(&self) -> Result<EngineVersion> {
        let stdout = self.read(self.words(&["version"], true), "say its version").await?;
        parse::version(&stdout)
    }

    async fn containers(&self) -> Result<Vec<ContainerSummary>> {
        let stdout = self
            .read(self.words(&["ps", "-a", "--no-trunc"], true), "list the containers")
            .await?;
        parse::containers(&stdout)
    }

    async fn stats(&self) -> Result<Vec<ContainerStats>> {
        let words: &[&str] = match self.kind {
            EngineKind::Docker => &["stats", "--no-stream", "--no-trunc"],
            EngineKind::Podman => &["stats", "--no-stream"],
        };
        let stdout = self.read(self.words(words, true), "read the containers' stats").await?;
        parse::stats(&stdout)
    }

    async fn inspect(&self, id: &ContainerId) -> Result<ContainerDetails> {
        let mut args = self.words(&["inspect", "--type", "container"], false);
        args.push(id.as_str().to_owned());
        let stdout = self.read(args, "show the container's details").await?;
        parse::details(&stdout)
    }

    async fn logs(&self, id: &ContainerId, query: &LogQuery) -> Result<Logs> {
        let tail = query.tail.clamp(1, MAX_LOG_TAIL);
        let mut args = self.words(&["logs", "--timestamps", "--tail"], false);
        args.push(tail.to_string());
        let since = match &query.since {
            Some(since) if super::names::is_log_time(since) => {
                args.push("--since".into());
                args.push(since.clone());
                Some(since.as_str())
            }
            Some(other) => return Err(CoreError::InvalidInput(format!("'{}' is not a log time", shown(other)))),
            None => None,
        };
        args.push(id.as_str().to_owned());
        let out = self.call(args, READ_TIMEOUT, MAX_READ_OUTPUT, "read the log").await?;
        let mut lines = parse::logs(&out.stdout, &out.stderr, since);
        let over = lines.len().saturating_sub(tail as usize);
        lines.drain(..over);
        Ok(Logs {
            lines,
            truncated: out.truncated || over > 0,
        })
    }

    async fn images(&self) -> Result<Vec<ImageSummary>> {
        let stdout = self
            .read(self.words(&["images", "--no-trunc"], true), "list the images")
            .await?;
        parse::images(&stdout)
    }

    async fn volumes(&self) -> Result<Vec<VolumeSummary>> {
        let stdout = self
            .read(self.words(&["volume", "ls"], true), "list the volumes")
            .await?;
        parse::volumes(&stdout)
    }

    async fn networks(&self) -> Result<Vec<NetworkSummary>> {
        let stdout = self
            .read(self.words(&["network", "ls", "--no-trunc"], true), "list the networks")
            .await?;
        parse::networks(&stdout)
    }

    async fn change(&self, change: &EngineChange) -> Result<ChangeOutput> {
        let (args, what, timeout): (Vec<String>, String, Duration) = match change {
            EngineChange::Start(id) => (vec!["start".into(), id.to_string()], "start it".into(), CHANGE_TIMEOUT),
            EngineChange::Stop(id) => (vec!["stop".into(), id.to_string()], "stop it".into(), CHANGE_TIMEOUT),
            EngineChange::Restart(id) => (
                vec!["restart".into(), id.to_string()],
                "restart it".into(),
                CHANGE_TIMEOUT,
            ),
            EngineChange::Pause(id) => (vec!["pause".into(), id.to_string()], "pause it".into(), CHANGE_TIMEOUT),
            EngineChange::Unpause(id) => (
                vec!["unpause".into(), id.to_string()],
                "unpause it".into(),
                CHANGE_TIMEOUT,
            ),
            EngineChange::Remove { id, force } => {
                let mut args = vec!["rm".to_owned()];
                if *force {
                    args.push("-f".into());
                }
                args.push(id.to_string());
                (args, "remove it".into(), CHANGE_TIMEOUT)
            }
            EngineChange::RemoveImage(id) => (
                vec!["rmi".into(), id.to_string()],
                "remove the image".into(),
                CHANGE_TIMEOUT,
            ),
            EngineChange::RemoveVolume(name) => (
                vec!["volume".into(), "rm".into(), name.to_string()],
                "remove the volume".into(),
                CHANGE_TIMEOUT,
            ),
            EngineChange::Pull(reference) => (
                vec!["pull".into(), "-q".into(), reference.to_string()],
                format!("pull {reference}"),
                LONG_TIMEOUT,
            ),
            EngineChange::Prune(what) => {
                let words: &[&str] = match (what, self.kind) {
                    (PruneWhat::Containers, _) => &["container", "prune", "-f"],
                    (PruneWhat::Images, _) => &["image", "prune", "-f"],
                    (PruneWhat::Volumes, _) => &["volume", "prune", "-f"],
                    (PruneWhat::BuildCache, EngineKind::Docker) => &["builder", "prune", "-f"],
                    (PruneWhat::BuildCache, EngineKind::Podman) => {
                        return Err(CoreError::InvalidInput(
                            "Podman keeps no build cache of its own: its build layers are images (prune those)".into(),
                        ))
                    }
                };
                (
                    words.iter().map(|w| (*w).to_owned()).collect(),
                    format!("prune {}", what.label()),
                    LONG_TIMEOUT,
                )
            }
        };
        let out = self.call(args, timeout, MAX_CHANGE_OUTPUT, &what).await?;
        let note = match change {
            EngineChange::Prune(_) => parse::prune_note(&out.stdout),
            EngineChange::Pull(reference) => Some(format!("pulled {reference}")),
            _ => None,
        };
        Ok(ChangeOutput {
            stdout: out.stdout,
            stderr: out.stderr,
            note,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers every call with the same output and records the arguments.
    struct Canned {
        out: CliOutput,
        calls: Mutex<Vec<Vec<String>>>,
    }

    #[async_trait]
    impl Cli for Arc<Canned> {
        async fn run(&self, args: &[String], _: Duration, _: usize) -> Result<CliOutput> {
            self.calls.lock().unwrap().push(args.to_vec());
            Ok(self.out.clone())
        }

        fn place(&self) -> &str {
            "web01"
        }
    }

    fn engine(kind: EngineKind, status: i64, stdout: &str, stderr: &str) -> (CliEngine, Arc<Canned>) {
        let canned = Arc::new(Canned {
            out: CliOutput {
                status: Some(status),
                stdout: stdout.into(),
                stderr: stderr.into(),
                truncated: false,
            },
            calls: Mutex::new(Vec::new()),
        });
        (CliEngine::new(kind, Box::new(Arc::clone(&canned))), canned)
    }

    fn id() -> ContainerId {
        ContainerId::parse("1a2b3c4d5e6f1a2b3c4d5e6f").unwrap()
    }

    #[tokio::test]
    async fn each_engine_gets_its_own_json_format() {
        let (docker, calls) = engine(EngineKind::Docker, 0, "", "");
        docker.containers().await.unwrap();
        assert_eq!(
            calls.calls.lock().unwrap()[0],
            ["ps", "-a", "--no-trunc", "--format", "{{json .}}"]
        );
        let (podman, calls) = engine(EngineKind::Podman, 0, "[]", "");
        podman.images().await.unwrap();
        assert_eq!(
            calls.calls.lock().unwrap()[0],
            ["images", "--no-trunc", "--format", "json"]
        );
    }

    #[tokio::test]
    async fn changes_pass_checked_ids_as_their_own_words() {
        let (docker, calls) = engine(EngineKind::Docker, 0, "", "");
        docker
            .change(&EngineChange::Remove { id: id(), force: true })
            .await
            .unwrap();
        docker
            .change(&EngineChange::Pull(
                super::super::ImageRef::parse("nginx:1.27").unwrap(),
            ))
            .await
            .unwrap();
        docker.change(&EngineChange::Prune(PruneWhat::Volumes)).await.unwrap();
        let calls = calls.calls.lock().unwrap();
        assert_eq!(calls[0], ["rm", "-f", "1a2b3c4d5e6f1a2b3c4d5e6f"]);
        assert_eq!(calls[1], ["pull", "-q", "nginx:1.27"]);
        assert_eq!(calls[2], ["volume", "prune", "-f"]);
    }

    #[tokio::test]
    async fn podman_has_no_build_cache_to_prune() {
        let (podman, calls) = engine(EngineKind::Podman, 0, "", "");
        let err = podman
            .change(&EngineChange::Prune(PruneWhat::BuildCache))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert!(calls.calls.lock().unwrap().is_empty(), "nothing ran");
    }

    #[tokio::test]
    async fn logs_follow_after_a_checked_time_only() {
        let (docker, calls) = engine(EngineKind::Docker, 0, "2026-10-21T10:00:00.000000001Z hi\n", "");
        let logs = docker
            .logs(
                &id(),
                &LogQuery {
                    tail: 50,
                    since: Some("2026-10-21T09:00:00.000000000Z".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(logs.lines.len(), 1);
        assert_eq!(
            calls.calls.lock().unwrap()[0],
            [
                "logs",
                "--timestamps",
                "--tail",
                "50",
                "--since",
                "2026-10-21T09:00:00.000000000Z",
                "1a2b3c4d5e6f1a2b3c4d5e6f"
            ]
        );
        let err = docker
            .logs(
                &id(),
                &LogQuery {
                    tail: 50,
                    since: Some("1h; reboot".into()),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }

    #[test]
    fn failures_say_what_helps() {
        let out = |status, stderr: &str| CliOutput {
            status: Some(status),
            stdout: String::new(),
            stderr: stderr.into(),
            truncated: false,
        };
        let code =
            |o: &CliOutput, place: &str| failure(EngineKind::Docker, o, place, false, "list the containers").code();
        assert_eq!(
            code(&out(127, "sh: 1: docker: not found\n"), "web01"),
            "container_cli_missing"
        );
        assert_eq!(
            code(
                &out(
                    1,
                    "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get \"http://%2Fvar%2Frun%2Fdocker.sock/v1.47/containers/json\": dial unix /var/run/docker.sock: connect: permission denied\n"
                ),
                "web01"
            ),
            "container_needs_sudo"
        );
        assert_eq!(
            code(
                &out(1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n"),
                "web01"
            ),
            "container_daemon_down"
        );
        let desktop = failure(
            EngineKind::Docker,
            &out(1, "failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine; check if the path is correct and if the daemon is running"),
            "this PC",
            false,
            "list the containers",
        );
        assert!(
            desktop.to_string().contains("Docker Desktop is not running"),
            "{desktop}"
        );
        assert_eq!(
            code(&out(1, "Error: No such container: abc\n"), "web01"),
            "container_not_found"
        );
        assert_eq!(
            code(&out(1, "sudo: a password is required\n"), "web01"),
            "container_needs_sudo"
        );
        let other = failure(
            EngineKind::Podman,
            &out(125, "Error: something odd\x1b[31m happened\n"),
            "web01",
            false,
            "stop it",
        );
        assert_eq!(other.code(), "container_failed");
        assert_eq!(
            other.to_string(),
            "Podman on web01 could not stop it: something odd happened"
        );
    }

    #[test]
    fn a_saved_docker_path_must_be_docker_exe() {
        let dir = std::env::temp_dir().join(format!("remotely-docker-path-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let other = dir.join("notepad.exe");
        std::fs::write(&other, b"").unwrap();
        assert!(validate_docker_path(&other).is_err());
        let docker = dir.join("docker.exe");
        assert!(validate_docker_path(&docker).is_err(), "not there yet");
        std::fs::write(&docker, b"").unwrap();
        assert!(validate_docker_path(&docker).is_ok());
        assert_eq!(locate_docker(Some(&docker)), Some(docker.clone()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tests_never_find_this_pcs_docker() {
        let engines = CliEngines::without_this_pc();
        engines.find_this_pc_cli(None);
        assert!(engines.this_pc().is_none());
        assert!(engines.this_pc_cli().is_none());
    }
}
