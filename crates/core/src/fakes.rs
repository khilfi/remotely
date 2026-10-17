//! Fake adapters for tests: one per outside system, each recording what it was asked to do. None of
//! them touches a real VM, host, vault or update server (CLAUDE.md "Development safety").
//!
//! Compiled for the crate's own unit tests and, through the `fakes` feature, for the integration
//! tests in `tests/`. The app never enables that feature.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::adapters::host_counters::{HostCounters, HostTotals, VmProcess};
use crate::adapters::remote::{loopback_shell, ExecResult, RemoteAdapter, SessionSpec, ShellHandle};
use crate::adapters::updater::{UpdateInfo, UpdaterAdapter};
use crate::adapters::vmware::{path_key, LibraryVm, ToolsState, VmwareAdapter, VmxInfo};
use crate::command_bus::{PowerOp, SnapshotOp, StopMode};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::vault::{SecretId, SecretKind, SecretString, UnlockMethod, Vault, VaultStatus};

/// Workstation in memory. VMs can sit in the library, in scanned folders and in the running list;
/// power calls change the running list the way vmrun would. Records every power and snapshot call
/// as text, e.g. `power Suspend C:\VMs\a\a.vmx`. Safety snapshot names carry a job id and a time, so
/// they are recorded as `snapshot take safety <vmx>`.
#[derive(Default)]
pub struct FakeVmware {
    library: Vec<LibraryVm>,
    folders: HashMap<String, Vec<PathBuf>>,
    vmx: HashMap<String, VmxInfo>,
    gone: HashSet<String>,
    ips: HashMap<String, String>,
    unresponsive: HashSet<String>,
    slow_shutdown: HashSet<String>,
    no_vmrun: bool,
    power_delay: Duration,
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

    /// The guest reports this IP address while running (Tools always runs in a running fake VM).
    pub fn with_ip(mut self, vmx: &str, ip: &str) -> Self {
        self.ips.insert(path_key(Path::new(vmx)), ip.to_owned());
        self
    }

    /// VM-03: a soft stop fails at once (no VMware Tools in the guest) and the VM keeps running.
    pub fn unresponsive(mut self, vmx: &str) -> Self {
        self.unresponsive.insert(path_key(Path::new(vmx)));
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

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }

    pub fn running(&self) -> Vec<PathBuf> {
        locks::lock(&self.running).clone()
    }

    /// The most power calls that were in progress at the same time.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
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
            ToolsState::Running
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
        if !self.power_delay.is_zero() {
            tokio::time::sleep(self.power_delay).await;
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);

        let key = path_key(vmx);
        match op {
            PowerOp::Start { .. } | PowerOp::Reset { .. } => self.set_running(vmx, true),
            PowerOp::Stop { mode: StopMode::Soft } if self.unresponsive.contains(&key) => {
                return Err(CoreError::Vmrun {
                    command: "stop".into(),
                    message: "The VMware Tools are not running in the virtual machine".into(),
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
            SnapshotOp::Take { name } if name.starts_with("safety-") => "take safety".to_owned(),
            SnapshotOp::Take { name } => format!("take {name}"),
            SnapshotOp::Revert { name } => format!("revert {name}"),
            SnapshotOp::Delete { name } => format!("delete {name}"),
        };
        self.record(format!("snapshot {what} {}", vmx.display()));
        Ok(())
    }

    async fn list_snapshots(&self, _: &Path) -> Result<Vec<String>> {
        self.vmrun()?;
        Ok(Vec::new())
    }
}

/// Remote hosts that answer every command with `ok from <host>` and exit code 0, unless a host is
/// given another exit code. Records `<host>: <script>`; never records a sudo password.
#[derive(Default)]
pub struct FakeRemote {
    exit_codes: HashMap<String, u32>,
    calls: Mutex<Vec<String>>,
}

impl FakeRemote {
    pub fn with_exit_code(mut self, host: &str, code: u32) -> Self {
        self.exit_codes.insert(host.to_owned(), code);
        self
    }

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }
}

#[async_trait]
impl RemoteAdapter for FakeRemote {
    async fn exec(
        &self,
        session: &SessionSpec,
        script: &str,
        _sudo_password: Option<&SecretString>,
    ) -> Result<ExecResult> {
        locks::lock(&self.calls).push(format!("{}: {script}", session.host));
        Ok(ExecResult {
            exit_code: Some(self.exit_codes.get(&session.host).copied().unwrap_or(0)),
            stdout: format!("ok from {}\n", session.host),
            stderr: String::new(),
            duration_ms: 1,
        })
    }

    async fn open_shell(&self, _: &SessionSpec, _: u16, _: u16) -> Result<ShellHandle> {
        Ok(loopback_shell())
    }
}

/// An unlocked vault with a known password, holding secrets in memory.
pub struct FakeVault {
    password: String,
    items: Mutex<HashMap<SecretId, SecretString>>,
}

impl FakeVault {
    pub fn with_password(password: &str) -> Self {
        Self {
            password: password.to_owned(),
            items: Mutex::default(),
        }
    }
}

#[async_trait]
impl Vault for FakeVault {
    fn status(&self) -> VaultStatus {
        VaultStatus::Unlocked
    }

    async fn unlock(&self, _method: UnlockMethod) -> Result<()> {
        Ok(())
    }

    fn lock(&self) {}

    async fn verify_password(&self, password: &SecretString) -> Result<bool> {
        Ok(password.expose() == self.password)
    }

    async fn put(&self, _: &Context, _: SecretKind, _: &str, secret: SecretString) -> Result<SecretId> {
        let id = SecretId(Uuid::new_v4());
        locks::lock(&self.items).insert(id, secret);
        Ok(id)
    }

    async fn get(&self, _: &Context, id: SecretId) -> Result<SecretString> {
        locks::lock(&self.items)
            .get(&id)
            .cloned()
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {}", id.0)))
    }
}

/// Fixed host counters: no VM processes, 32 GB RAM, 16 logical CPUs, 50% free disk by default.
pub struct FakeHostCounters {
    pub processes: Vec<VmProcess>,
    pub totals: HostTotals,
    pub free_disk_pct: f64,
}

impl Default for FakeHostCounters {
    fn default() -> Self {
        Self {
            processes: Vec::new(),
            totals: HostTotals {
                physical_ram_mb: 32 * 1024,
                logical_cpus: 16,
            },
            free_disk_pct: 50.0,
        }
    }
}

#[async_trait]
impl HostCounters for FakeHostCounters {
    async fn vm_processes(&self) -> Result<Vec<VmProcess>> {
        Ok(self.processes.clone())
    }

    async fn host_totals(&self) -> Result<HostTotals> {
        Ok(self.totals)
    }

    async fn free_disk_pct(&self, _path: &Path) -> Result<f64> {
        Ok(self.free_disk_pct)
    }
}

/// An update server that offers at most one version. Records the versions installed.
#[derive(Default)]
pub struct FakeUpdater {
    offered: Option<UpdateInfo>,
    installed: Mutex<Vec<String>>,
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
            installed: Mutex::default(),
        }
    }

    pub fn installed(&self) -> Vec<String> {
        locks::lock(&self.installed).clone()
    }
}

#[async_trait]
impl UpdaterAdapter for FakeUpdater {
    async fn check(&self) -> Result<Option<UpdateInfo>> {
        Ok(self.offered.clone())
    }

    async fn install(&self, version: &str) -> Result<()> {
        locks::lock(&self.installed).push(version.to_owned());
        Ok(())
    }
}
