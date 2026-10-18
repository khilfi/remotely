//! Fake adapters for tests: one per outside system, each recording what it was asked to do. None of
//! them touches a real VM, host, vault or update server (CLAUDE.md "Development safety").
//!
//! Compiled for the crate's own unit tests and, through the `fakes` feature, for the integration
//! tests in `tests/`. The app never enables that feature.

pub mod github_server;
pub mod ssh_server;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::adapters::dns::Resolver;
use crate::adapters::exec_output::OutputCollector;
use crate::adapters::host_counters::{DiskSpace, HostCounters, HostTotals, SystemCpuTimes, VmProcess};
use crate::adapters::remote::{
    ConnectRequest, Credentials, ExecRequest, ExecResult, ExecSession, Prompter, RemoteAdapter, ShellEnd, ShellHandle,
    ShellInput, ShellOutput, ShellRequest,
};
use crate::adapters::updater::{ReleaseCheck, TokenReport, UpdateInfo, UpdaterAdapter};
use crate::adapters::vmware::{path_key, LibraryVm, SnapshotInfo, SnapshotTree, ToolsState, VmwareAdapter, VmxInfo};
use crate::command_bus::{PowerOp, SnapshotOp, StopMode};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::snapshots::is_safety_name;
use crate::vault::{
    self, KeyProtector, SecretId, SecretKind, SecretMeta, SecretString, UnlockMethod, Vault, VaultInfo, VaultStatus,
};

/// Workstation in memory. VMs can sit in the library, in scanned folders and in the running list;
/// power calls change the running list and snapshot calls change each VM's snapshot tree the way
/// vmrun would. Like vmrun, a soft stop, restart or suspend waits for as long as VMware Tools is not
/// running in the guest. Records every power and snapshot call as text, e.g.
/// `power Suspend C:\VMs\a\a.vmx`.
/// Safety snapshot names carry a job id and a time, so they are recorded as
/// `snapshot take safety <vmx>`.
#[derive(Default)]
pub struct FakeVmware {
    library: Vec<LibraryVm>,
    folders: HashMap<String, Vec<PathBuf>>,
    vmx: HashMap<String, VmxInfo>,
    gone: HashSet<String>,
    ips: HashMap<String, String>,
    unresponsive: HashSet<String>,
    slow_shutdown: HashSet<String>,
    tools: HashMap<String, ToolsState>,
    questions: HashSet<String>,
    no_vmrun: bool,
    power_delay: Duration,
    started_at: HashMap<String, OffsetDateTime>,
    failing_snapshots: HashSet<String>,
    unreadable_snapshots: HashSet<String>,
    snapshots: Mutex<HashMap<String, SnapshotTree>>,
    running: Mutex<Vec<PathBuf>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    calls: Mutex<Vec<String>>,
}

impl FakeVmware {
    pub fn with_running<P: Into<PathBuf>>(paths: impl IntoIterator<Item = P>) -> Self {
        Self {
            running: Mutex::new(paths.into_iter().map(Into::into).collect()),
            ..Default::default()
        }
    }

    /// Adds a VM to Workstation's library.
    pub fn in_library(mut self, vmx: &str, name: Option<&str>) -> Self {
        self.library.push(LibraryVm {
            vmx_path: PathBuf::from(vmx),
            display_name: name.map(String::from),
        });
        self
    }

    /// A .vmx that a scan of `folder` finds.
    pub fn in_folder(mut self, folder: &str, vmx: &str) -> Self {
        self.folders
            .entry(path_key(Path::new(folder)))
            .or_default()
            .push(PathBuf::from(vmx));
        self
    }

    /// What the .vmx file holds. Without this, a .vmx reads as just a display name (its file name).
    pub fn with_vmx(mut self, vmx: &str, info: VmxInfo) -> Self {
        self.vmx.insert(path_key(Path::new(vmx)), info);
        self
    }

    /// The .vmx file no longer exists (still listed in the library, say).
    pub fn without_file(mut self, vmx: &str) -> Self {
        self.gone.insert(path_key(Path::new(vmx)));
        self
    }

    /// The guest reports this IP address while running.
    pub fn with_ip(mut self, vmx: &str, ip: &str) -> Self {
        self.ips.insert(path_key(Path::new(vmx)), ip.to_owned());
        self
    }

    /// VM-03: VMware Tools runs, but a soft stop fails at once and the VM keeps running.
    pub fn unresponsive(mut self, vmx: &str) -> Self {
        self.unresponsive.insert(path_key(Path::new(vmx)));
        self
    }

    /// VM-02: VMware Tools state while the VM runs. Without this, Tools run in every running VM.
    /// A soft stop, restart or suspend then waits for Tools forever, as vmrun does.
    pub fn with_tools(mut self, vmx: &str, state: ToolsState) -> Self {
        self.tools.insert(path_key(Path::new(vmx)), state);
        self
    }

    /// VM-02: Workstation shows a question for this VM, so every power call on it waits for an
    /// answer, here forever.
    pub fn with_question(mut self, vmx: &str) -> Self {
        self.questions.insert(path_key(Path::new(vmx)));
        self
    }

    /// VM-03: a soft stop never finishes; the VM keeps running.
    pub fn slow_shutdown(mut self, vmx: &str) -> Self {
        self.slow_shutdown.insert(path_key(Path::new(vmx)));
        self
    }

    /// vmrun.exe is missing: Workstation's files still read, every vmrun call fails.
    pub fn without_vmrun(mut self) -> Self {
        self.no_vmrun = true;
        self
    }

    /// VM-06: each power call takes this long, so tests can see how many run at once.
    pub fn with_power_delay(mut self, delay: Duration) -> Self {
        self.power_delay = delay;
        self
    }

    /// VM-04: a snapshot taken at `at`, from the VM's current snapshot; it becomes the current one.
    pub fn with_snapshot(mut self, vmx: &str, name: &str, at: OffsetDateTime) -> Self {
        let trees = self
            .snapshots
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        take_snapshot(trees.entry(path_key(Path::new(vmx))).or_default(), name, at);
        self
    }

    /// AP-02: the VM's process started at `at` (what the first line of its vmware.log says).
    pub fn with_started_at(mut self, vmx: &str, at: OffsetDateTime) -> Self {
        self.started_at.insert(path_key(Path::new(vmx)), at);
        self
    }

    /// Every snapshot call on this VM fails, e.g. its disk is full (VM-05).
    pub fn failing_snapshots(mut self, vmx: &str) -> Self {
        self.failing_snapshots.insert(path_key(Path::new(vmx)));
        self
    }

    /// The VM's .vmsd cannot be read.
    pub fn unreadable_snapshots(mut self, vmx: &str) -> Self {
        self.unreadable_snapshots.insert(path_key(Path::new(vmx)));
        self
    }

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }

    /// The VM's snapshot names, in the order they were taken.
    pub fn snapshot_names(&self, vmx: &str) -> Vec<String> {
        locks::lock(&self.snapshots)
            .get(&path_key(Path::new(vmx)))
            .map(|tree| tree.snapshots.iter().map(|s| s.name.clone()).collect())
            .unwrap_or_default()
    }

    /// The name of the snapshot the VM's current state was taken from.
    pub fn current_snapshot(&self, vmx: &str) -> Option<String> {
        let trees = locks::lock(&self.snapshots);
        let tree = trees.get(&path_key(Path::new(vmx)))?;
        let uid = tree.current_uid?;
        tree.snapshots.iter().find(|s| s.uid == uid).map(|s| s.name.clone())
    }

    pub fn running(&self) -> Vec<PathBuf> {
        locks::lock(&self.running).clone()
    }

    /// The most power calls that were in progress at the same time.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    /// Power calls in progress now. A call the job runner gave up on no longer counts: with the real
    /// adapter, that kills vmrun.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    fn record(&self, call: String) {
        locks::lock(&self.calls).push(call);
    }

    fn is_running(&self, vmx: &Path) -> bool {
        let key = path_key(vmx);
        locks::lock(&self.running).iter().any(|p| path_key(p) == key)
    }

    fn set_running(&self, vmx: &Path, on: bool) {
        let key = path_key(vmx);
        let mut running = locks::lock(&self.running);
        running.retain(|p| path_key(p) != key);
        if on {
            running.push(vmx.to_path_buf());
        }
    }

    fn vmrun(&self) -> Result<()> {
        if self.no_vmrun {
            Err(CoreError::VmrunNotFound)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl VmwareAdapter for FakeVmware {
    fn tool_path(&self) -> Option<PathBuf> {
        None
    }

    async fn library(&self) -> Result<Vec<LibraryVm>> {
        Ok(self.library.clone())
    }

    async fn scan_folder(&self, folder: &Path) -> Result<Vec<PathBuf>> {
        self.folders
            .get(&path_key(folder))
            .cloned()
            .ok_or_else(|| CoreError::InvalidInput(format!("{} is not a folder", folder.display())))
    }

    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        self.vmrun()?;
        Ok(self.running())
    }

    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo> {
        let key = path_key(vmx);
        if self.gone.contains(&key) {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        }
        Ok(self.vmx.get(&key).cloned().unwrap_or_else(|| VmxInfo {
            display_name: vmx.file_stem().map(|s| s.to_string_lossy().into_owned()),
            ..Default::default()
        }))
    }

    async fn tools_state(&self, vmx: &Path) -> Result<ToolsState> {
        self.vmrun()?;
        Ok(if self.is_running(vmx) {
            self.tools.get(&path_key(vmx)).copied().unwrap_or(ToolsState::Running)
        } else {
            ToolsState::Unknown
        })
    }

    async fn guest_ip(&self, vmx: &Path) -> Result<Option<String>> {
        self.vmrun()?;
        Ok(self.ips.get(&path_key(vmx)).cloned().filter(|_| self.is_running(vmx)))
    }

    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()> {
        self.vmrun()?;
        self.record(format!("power {op:?} {}", vmx.display()));
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let _done = InFlight(&self.in_flight);
        if !self.power_delay.is_zero() {
            tokio::time::sleep(self.power_delay).await;
        }

        let key = path_key(vmx);
        if self.questions.contains(&key) {
            std::future::pending::<()>().await;
        }
        let soft = matches!(
            op,
            PowerOp::Stop { mode: StopMode::Soft } | PowerOp::Reset { mode: StopMode::Soft } | PowerOp::Suspend
        );
        let tools = self.tools.get(&key).copied().unwrap_or(ToolsState::Running);
        if soft && self.is_running(vmx) && tools != ToolsState::Running {
            std::future::pending::<()>().await;
        }
        match op {
            PowerOp::Start { .. } | PowerOp::Reset { .. } => self.set_running(vmx, true),
            PowerOp::Stop { mode: StopMode::Soft } if self.unresponsive.contains(&key) => {
                return Err(CoreError::Vmrun {
                    command: "stop".into(),
                    message: "The guest did not accept the shutdown request".into(),
                });
            }
            PowerOp::Stop { mode: StopMode::Soft } if self.slow_shutdown.contains(&key) => {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            PowerOp::Stop { .. } | PowerOp::Suspend => self.set_running(vmx, false),
            PowerOp::Pause | PowerOp::Unpause => {}
        }
        Ok(())
    }

    async fn snapshot(&self, vmx: &Path, op: &SnapshotOp) -> Result<()> {
        self.vmrun()?;
        let what = match op {
            SnapshotOp::Take { name } if is_safety_name(name) => "take safety".to_owned(),
            SnapshotOp::Take { name } => format!("take {name}"),
            SnapshotOp::Revert { name } => format!("revert {name}"),
            SnapshotOp::Delete { name } => format!("delete {name}"),
        };
        self.record(format!("snapshot {what} {}", vmx.display()));
        let key = path_key(vmx);
        let failure = |command: &str, message: &str| CoreError::Vmrun {
            command: command.into(),
            message: message.into(),
        };
        if self.failing_snapshots.contains(&key) {
            return Err(failure("snapshot", "Insufficient disk space"));
        }
        let mut trees = locks::lock(&self.snapshots);
        let tree = trees.entry(key).or_default();
        match op {
            SnapshotOp::Take { name } => {
                if tree.snapshots.iter().any(|s| &s.name == name) {
                    return Err(failure("snapshot", "A snapshot with the name already exists"));
                }
                take_snapshot(tree, name, OffsetDateTime::now_utc());
            }
            SnapshotOp::Revert { name } => {
                let uid = find_snapshot(tree, name)
                    .ok_or_else(|| failure("revertToSnapshot", "The snapshot does not exist"))?;
                tree.current_uid = Some(uid);
            }
            SnapshotOp::Delete { name } => {
                let uid = find_snapshot(tree, name)
                    .ok_or_else(|| failure("deleteSnapshot", "The snapshot does not exist"))?;
                let parent = tree.snapshots.iter().find(|s| s.uid == uid).and_then(|s| s.parent_uid);
                tree.snapshots.retain(|s| s.uid != uid);
                // Workstation keeps the children and hangs them on the deleted snapshot's parent.
                for child in tree.snapshots.iter_mut().filter(|s| s.parent_uid == Some(uid)) {
                    child.parent_uid = parent;
                }
                if tree.current_uid == Some(uid) {
                    tree.current_uid = parent;
                }
            }
        }
        Ok(())
    }

    async fn list_snapshots(&self, vmx: &Path) -> Result<Vec<String>> {
        self.vmrun()?;
        Ok(self.snapshot_names(&vmx.to_string_lossy()))
    }

    async fn snapshots(&self, vmx: &Path) -> Result<SnapshotTree> {
        let key = path_key(vmx);
        if self.unreadable_snapshots.contains(&key) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into());
        }
        Ok(locks::lock(&self.snapshots).get(&key).cloned().unwrap_or_default())
    }

    async fn running_since(&self, vmx: &Path) -> Result<Option<OffsetDateTime>> {
        Ok(self.started_at.get(&path_key(vmx)).copied())
    }
}

/// Counts a power call as finished when it returns or is dropped.
struct InFlight<'a>(&'a AtomicUsize);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Adds a snapshot from the current one and makes it current, as `vmrun snapshot` does.
fn take_snapshot(tree: &mut SnapshotTree, name: &str, at: OffsetDateTime) {
    let uid = tree.snapshots.iter().map(|s| s.uid).max().unwrap_or(0) + 1;
    tree.snapshots.push(SnapshotInfo {
        uid,
        parent_uid: tree.current_uid,
        name: name.to_owned(),
        description: None,
        created_at: Some(at),
    });
    tree.current_uid = Some(uid);
}

/// By name, or by vmrun's path form (`base/child`).
fn find_snapshot(tree: &SnapshotTree, name: &str) -> Option<u32> {
    let by_name: Vec<u32> = tree
        .snapshots
        .iter()
        .filter(|s| s.name == name)
        .map(|s| s.uid)
        .collect();
    if let [uid] = by_name[..] {
        return Some(uid);
    }
    let mut parent = None;
    let mut found = None;
    for part in name.split('/') {
        found = tree
            .snapshots
            .iter()
            .find(|s| s.parent_uid == parent && s.name == part)
            .map(|s| s.uid);
        parent = Some(found?);
    }
    found
}

/// Remote hosts that answer every command with `ok from <host>` and exit code 0, unless a host is
/// given another output, exit code, delay or failure. Records `<host>: <script>` (with ` [sudo]` for
/// sudo runs); never records a password.
#[derive(Default)]
pub struct FakeRemote {
    exit_codes: HashMap<String, u32>,
    outputs: HashMap<String, String>,
    delays: HashMap<String, Duration>,
    unreachable: HashSet<String>,
    /// BX-07: the sudo password every host takes; any other is refused.
    sudo_password: Option<String>,
    calls: std::sync::Arc<Mutex<Vec<String>>>,
    /// MO-02: bumped by `drop_connections`; kept connections from before count as lost.
    generation: std::sync::Arc<AtomicUsize>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl FakeRemote {
    pub fn with_exit_code(mut self, host: &str, code: u32) -> Self {
        self.exit_codes.insert(host.to_owned(), code);
        self
    }

    /// What `host` prints on stdout, instead of `ok from <host>`.
    pub fn with_output(mut self, host: &str, stdout: &str) -> Self {
        self.outputs.insert(host.to_owned(), stdout.to_owned());
        self
    }

    /// Every command on `host` takes this long.
    pub fn with_delay(mut self, host: &str, delay: Duration) -> Self {
        self.delays.insert(host.to_owned(), delay);
        self
    }

    /// Connecting to `host` fails.
    pub fn unreachable(mut self, host: &str) -> Self {
        self.unreachable.insert(host.to_owned());
        self
    }

    pub fn with_sudo_password(mut self, password: &str) -> Self {
        self.sudo_password = Some(password.to_owned());
        self
    }

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }

    /// MO-02: every connection kept open so far counts as lost from now on.
    pub fn drop_connections(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// The most commands that ran at the same time.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RemoteAdapter for FakeRemote {
    async fn exec(&self, request: ExecRequest<'_>) -> Result<ExecResult> {
        let host = request.session.host.clone();
        let sudo = if request.sudo_password.is_some() { " [sudo]" } else { "" };
        locks::lock(&self.calls).push(format!("{host}: {}{sudo}", request.script));
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let _done = InFlight(&self.in_flight);
        if let Some(delay) = self.delays.get(&host) {
            tokio::time::sleep(*delay).await;
        }
        if self.unreachable.contains(&host) {
            return Err(CoreError::Ssh(format!(
                "can't connect to {host}:{}: connection refused",
                request.session.port
            )));
        }
        if let (Some(given), Some(wanted)) = (&request.sudo_password, &self.sudo_password) {
            if given.expose() != wanted {
                return Err(CoreError::SudoPasswordRefused);
            }
        }
        let mut secrets: Vec<&SecretString> = request.sudo_password.iter().collect();
        if let Credentials::Password(Some(password)) = &request.credentials {
            secrets.push(password);
        }
        let stdout = self
            .outputs
            .get(&host)
            .cloned()
            .unwrap_or_else(|| format!("ok from {host}\n"));
        Ok(ExecResult {
            exit_code: Some(self.exit_codes.get(&host).copied().unwrap_or(0)),
            signal: None,
            output: OutputCollector::collect(stdout.as_bytes(), b"", &secrets, request.max_output),
            duration_ms: 1,
        })
    }

    async fn open_shell(&self, request: ShellRequest<'_>, _: &mut dyn Prompter) -> Result<ShellHandle> {
        locks::lock(&self.calls).push(format!("{}: shell", request.session.host));
        Ok(loopback_shell())
    }

    async fn connect(&self, request: ConnectRequest<'_>) -> Result<Box<dyn ExecSession>> {
        let host = request.session.host.clone();
        locks::lock(&self.calls).push(format!("{host}: connect"));
        if let Some(delay) = self.delays.get(&host) {
            tokio::time::sleep(*delay).await;
        }
        if self.unreachable.contains(&host) {
            return Err(CoreError::Ssh(format!(
                "can't connect to {host}:{}: connection refused",
                request.session.port
            )));
        }
        Ok(Box::new(FakeSession {
            stdout: self
                .outputs
                .get(&host)
                .cloned()
                .unwrap_or_else(|| format!("ok from {host}\n")),
            exit_code: self.exit_codes.get(&host).copied().unwrap_or(0),
            host,
            calls: std::sync::Arc::clone(&self.calls),
            generation: std::sync::Arc::clone(&self.generation),
            opened_in: self.generation.load(Ordering::SeqCst),
            closed: std::sync::atomic::AtomicBool::new(false),
        }))
    }
}

/// A connection [`FakeRemote::connect`] kept open: answers every command like `exec` would.
struct FakeSession {
    host: String,
    stdout: String,
    exit_code: u32,
    calls: std::sync::Arc<Mutex<Vec<String>>>,
    generation: std::sync::Arc<AtomicUsize>,
    opened_in: usize,
    closed: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl ExecSession for FakeSession {
    async fn run(&self, script: &str, max_output: usize) -> Result<ExecResult> {
        if self.is_closed() {
            return Err(CoreError::Ssh("the connection was lost: the connection was cut".into()));
        }
        locks::lock(&self.calls).push(format!("{}: {script}", self.host));
        Ok(ExecResult {
            exit_code: Some(self.exit_code),
            signal: None,
            output: OutputCollector::collect(self.stdout.as_bytes(), b"", &[], max_output),
            duration_ms: 1,
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.generation.load(Ordering::SeqCst) != self.opened_in
    }

    async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// A shell that echoes what is typed and answers each line with `not connected: <line>`; `exit`
/// ends it.
pub fn loopback_shell() -> ShellHandle {
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<ShellInput>(64);
    let (output_tx, output_rx) = tokio::sync::mpsc::channel::<ShellOutput>(64);
    tokio::spawn(async move {
        let mut line = Vec::new();
        while let Some(msg) = input_rx.recv().await {
            let bytes = match msg {
                ShellInput::Close => break,
                ShellInput::Resize { .. } => continue,
                ShellInput::Data(bytes) => bytes,
            };
            let mut out = Vec::new();
            for byte in bytes {
                if byte == b'\r' {
                    let text = String::from_utf8_lossy(&line).into_owned();
                    line.clear();
                    if text == "exit" {
                        let _ = output_tx.send(ShellOutput::Data(out)).await;
                        let _ = output_tx
                            .send(ShellOutput::Closed(ShellEnd::Exited { status: Some(0) }))
                            .await;
                        return;
                    }
                    out.extend_from_slice(format!("\r\nnot connected: {text}\r\n").as_bytes());
                } else {
                    line.push(byte);
                    out.push(byte);
                }
            }
            if output_tx.send(ShellOutput::Data(out)).await.is_err() {
                return;
            }
        }
        let _ = output_tx
            .send(ShellOutput::Closed(ShellEnd::Exited { status: None }))
            .await;
    });
    ShellHandle {
        input: input_tx,
        output: output_rx,
    }
}

/// An unlocked vault with a known password, holding secrets in memory. Tests of the vault itself use
/// [`vault::LocalVault`] with [`FakeKeyProtector`] instead.
pub struct FakeVault {
    password: String,
    items: Mutex<HashMap<SecretId, (SecretMeta, SecretString)>>,
    status: watch::Sender<VaultStatus>,
}

impl FakeVault {
    pub fn with_password(password: &str) -> Self {
        Self {
            password: password.to_owned(),
            items: Mutex::default(),
            status: watch::channel(VaultStatus::Unlocked).0,
        }
    }
}

#[async_trait]
impl Vault for FakeVault {
    fn info(&self) -> VaultInfo {
        VaultInfo {
            status: VaultStatus::Unlocked,
            windows_login: false,
            windows_login_available: false,
            idle_lock_minutes: 15,
        }
    }

    fn watch(&self) -> watch::Receiver<VaultStatus> {
        self.status.subscribe()
    }

    async fn setup(&self, _: &Context, _: SecretString, _: bool) -> Result<()> {
        Err(CoreError::InvalidInput("The vault is already set up.".into()))
    }

    async fn unlock(&self, _method: UnlockMethod) -> Result<()> {
        Ok(())
    }

    fn lock(&self) {}

    async fn verify_password(&self, password: &SecretString) -> Result<bool> {
        Ok(password.expose() == self.password)
    }

    async fn change_password(&self, _: &SecretString, _: SecretString) -> Result<()> {
        Err(CoreError::NotImplemented("FakeVault password change"))
    }

    async fn set_windows_login(&self, _: &SecretString, _: bool) -> Result<()> {
        Err(CoreError::NotImplemented("FakeVault Windows login"))
    }

    async fn list(&self, _: &Context) -> Result<Vec<SecretMeta>> {
        let mut items: Vec<SecretMeta> = locks::lock(&self.items).values().map(|(m, _)| m.clone()).collect();
        items.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(items)
    }

    async fn put(&self, _: &Context, kind: SecretKind, label: &str, secret: SecretString) -> Result<SecretId> {
        let id = SecretId(Uuid::new_v4());
        let meta = SecretMeta {
            id,
            kind,
            label: label.to_owned(),
            used_by: 0,
            created_at: String::new(),
            updated_at: String::new(),
        };
        locks::lock(&self.items).insert(id, (meta, secret));
        Ok(id)
    }

    async fn replace(&self, _: &Context, id: SecretId, secret: SecretString) -> Result<()> {
        let mut items = locks::lock(&self.items);
        let item = items
            .get_mut(&id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {id}")))?;
        item.1 = secret;
        Ok(())
    }

    async fn rename(&self, _: &Context, id: SecretId, label: &str) -> Result<()> {
        let mut items = locks::lock(&self.items);
        let item = items
            .get_mut(&id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {id}")))?;
        label.clone_into(&mut item.0.label);
        Ok(())
    }

    async fn delete(&self, _: &Context, id: SecretId) -> Result<()> {
        locks::lock(&self.items)
            .remove(&id)
            .map(drop)
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {id}")))
    }

    async fn get(&self, _: &Context, id: SecretId) -> Result<SecretString> {
        locks::lock(&self.items)
            .get(&id)
            .map(|(_, s)| s.clone())
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {id}")))
    }
}

/// Stands in for DPAPI: wraps with a key of its own, so a vault opened with another instance (another
/// Windows user, or the same user after a password reset) cannot use the Windows login.
pub struct FakeKeyProtector {
    key: vault::Key,
    available: bool,
}

impl FakeKeyProtector {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self {
            key: vault::Key::from_array(key),
            available: true,
        }
    }

    /// A machine without DPAPI.
    pub fn unavailable() -> Self {
        Self {
            available: false,
            ..Self::new()
        }
    }
}

impl Default for FakeKeyProtector {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProtector for FakeKeyProtector {
    fn available(&self) -> bool {
        self.available
    }

    fn protect(&self, data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(CoreError::NotImplemented("DPAPI on this machine"));
        }
        let (nonce, ciphertext) = vault::encrypt(&self.key, data, entropy)?;
        Ok([&nonce[..], &ciphertext].concat())
    }

    fn unprotect(&self, blob: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if blob.len() < 12 {
            return Err(CoreError::Vault("blob too short".into()));
        }
        let (nonce, ciphertext) = blob.split_at(12);
        vault::decrypt(&self.key, nonce, ciphertext, entropy)?
            .ok_or_else(|| CoreError::Vault("the key could not be decrypted (another Windows user?)".into()))
    }
}

/// Fixed host counters: no VM processes, 32 GB RAM (24 GB available), 16 logical CPUs, a 1 TB drive
/// with 50% free by default. The host's CPU is 25% busy between any two readings, and this app has
/// used 10 ms more CPU at each reading. With `unavailable`, every read fails. `processes` is shared, so
/// a test can start and stop "VMs" between metric rounds.
pub struct FakeHostCounters {
    pub processes: std::sync::Arc<Mutex<Vec<VmProcess>>>,
    pub totals: HostTotals,
    pub free_disk_pct: f64,
    pub unavailable: bool,
    readings: AtomicUsize,
}

impl Default for FakeHostCounters {
    fn default() -> Self {
        Self {
            processes: std::sync::Arc::default(),
            totals: HostTotals {
                physical_ram_mb: 32 * 1024,
                available_ram_mb: 24 * 1024,
                logical_cpus: 16,
            },
            free_disk_pct: 50.0,
            unavailable: false,
            readings: AtomicUsize::new(0),
        }
    }
}

impl FakeHostCounters {
    /// What the next round of `vm_processes` returns.
    pub fn set_processes(&self, processes: Vec<VmProcess>) {
        *locks::lock(&self.processes) = processes;
    }

    fn available(&self) -> Result<()> {
        if self.unavailable {
            Err(CoreError::Io(std::io::Error::other("counters unavailable")))
        } else {
            Ok(())
        }
    }

    fn reading(&self) -> u32 {
        u32::try_from(self.readings.fetch_add(1, Ordering::SeqCst) + 1).unwrap_or(u32::MAX)
    }
}

#[async_trait]
impl HostCounters for FakeHostCounters {
    async fn vm_processes(&self) -> Result<Vec<VmProcess>> {
        self.available()?;
        Ok(locks::lock(&self.processes).clone())
    }

    async fn host_totals(&self) -> Result<HostTotals> {
        self.available()?;
        Ok(self.totals)
    }

    async fn system_cpu_times(&self) -> Result<SystemCpuTimes> {
        self.available()?;
        let n = self.reading();
        Ok(SystemCpuTimes {
            idle: Duration::from_secs(3) * n,
            total: Duration::from_secs(4) * n,
        })
    }

    async fn own_cpu_time(&self) -> Result<Duration> {
        self.available()?;
        Ok(Duration::from_millis(10) * self.reading())
    }

    async fn disk_space(&self, _path: &Path) -> Result<DiskSpace> {
        self.available()?;
        let total_bytes = 1u64 << 40;
        Ok(DiskSpace {
            free_bytes: (total_bytes as f64 * self.free_disk_pct / 100.0) as u64,
            total_bytes,
        })
    }

    async fn free_disk_pct(&self, _path: &Path) -> Result<f64> {
        self.available()?;
        Ok(self.free_disk_pct)
    }
}

/// Name resolution from a fixed table: no DNS server is asked. Names not in it do not resolve.
/// Records every name looked up.
#[derive(Default)]
pub struct FakeResolver {
    names: Mutex<HashMap<String, Vec<std::net::IpAddr>>>,
    lookups: Mutex<Vec<String>>,
    delay: Option<Duration>,
}

impl FakeResolver {
    /// `name` resolves to `ips` (any letter case).
    pub fn with(self, name: &str, ips: &[&str]) -> Self {
        self.set(name, ips);
        self
    }

    /// Changes what `name` resolves to, or makes it unresolvable with no `ips`.
    pub fn set(&self, name: &str, ips: &[&str]) {
        let parsed = ips.iter().filter_map(|ip| ip.parse().ok()).collect();
        locks::lock(&self.names).insert(name.to_ascii_lowercase(), parsed);
    }

    /// Every lookup waits this long first, like a DNS server that does not answer.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    pub fn lookups(&self) -> Vec<String> {
        locks::lock(&self.lookups).clone()
    }
}

#[async_trait]
impl Resolver for FakeResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>> {
        locks::lock(&self.lookups).push(host.to_owned());
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        let found = locks::lock(&self.names).get(&host.to_ascii_lowercase()).cloned();
        match found {
            Some(ips) if !ips.is_empty() => Ok(ips),
            _ => Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("could not resolve {host}"),
            ))),
        }
    }
}

/// An update server that offers at most one version. Records the versions installed and the calls
/// it got. With [`FakeUpdater::accepting`] it takes one token only and refuses any other the way
/// GitHub refuses a revoked one; by default it takes any.
#[derive(Default)]
pub struct FakeUpdater {
    offered: Option<UpdateInfo>,
    token: Option<String>,
    expires_on: Option<String>,
    /// Revoked (or expired) on GitHub: every token is refused.
    revoked: AtomicBool,
    installed: Mutex<Vec<String>>,
    calls: AtomicUsize,
}

impl FakeUpdater {
    pub fn offering(current: &str, version: &str) -> Self {
        Self {
            offered: Some(UpdateInfo {
                current_version: current.to_owned(),
                version: version.to_owned(),
                notes: Some(format!("Release notes for {version}")),
                pub_date: None,
            }),
            ..Default::default()
        }
    }

    /// Takes only `token`, which GitHub says expires on `expires_on` (`YYYY-MM-DD`).
    pub fn accepting(mut self, token: &str, expires_on: Option<&str>) -> Self {
        self.token = Some(token.to_owned());
        self.expires_on = expires_on.map(str::to_owned);
        self
    }

    /// From now on GitHub answers 401, as it does for a revoked or expired token.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    pub fn installed(&self) -> Vec<String> {
        locks::lock(&self.installed).clone()
    }

    /// Calls that reached it (checks, installs and tests), i.e. would have gone to GitHub.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn authorize(&self, token: &SecretString) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let refused = self.revoked.load(Ordering::SeqCst)
            || self.token.as_ref().is_some_and(|accepted| accepted != token.expose());
        match refused {
            true => Err(CoreError::UpdateTokenRefused { expired_on: None }),
            false => Ok(()),
        }
    }
}

#[async_trait]
impl UpdaterAdapter for FakeUpdater {
    async fn check(&self, token: &SecretString) -> Result<ReleaseCheck> {
        self.authorize(token)?;
        Ok(ReleaseCheck {
            update: self.offered.clone(),
            token_expires_on: self.expires_on.clone(),
        })
    }

    async fn install(&self, token: &SecretString, version: &str) -> Result<()> {
        self.authorize(token)?;
        locks::lock(&self.installed).push(version.to_owned());
        Ok(())
    }

    async fn test_token(&self, token: &SecretString) -> Result<TokenReport> {
        self.authorize(token)?;
        Ok(TokenReport {
            repository: "alice/remotely".into(),
            latest_release: self.offered.as_ref().map(|u| format!("v{}", u.version)),
            expires_on: self.expires_on.clone(),
        })
    }
}
