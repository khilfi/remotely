//! Fake adapters for tests: one per outside system, each recording what it was asked to do. None of
//! them touches a real VM, host, vault or update server (CLAUDE.md "Development safety").
//!
//! Compiled for the crate's own unit tests and, through the `fakes` feature, for the integration
//! tests in `tests/`. The app never enables that feature.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use uuid::Uuid;

use crate::adapters::host_counters::{HostCounters, HostTotals, VmProcess};
use crate::adapters::remote::{loopback_shell, ExecResult, RemoteAdapter, SessionSpec, ShellHandle};
use crate::adapters::updater::{UpdateInfo, UpdaterAdapter};
use crate::adapters::vmware::{VmwareAdapter, VmxInfo};
use crate::command_bus::{PowerOp, SnapshotOp};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::vault::{SecretId, SecretKind, SecretString, UnlockMethod, Vault, VaultStatus};

/// Workstation with a fixed set of running VMs. Records every power and snapshot call as text, e.g.
/// `power Suspend C:\VMs\a\a.vmx`. Safety snapshot names carry a job id and a time, so they are
/// recorded as `snapshot take safety <vmx>`.
#[derive(Default)]
pub struct FakeVmware {
    running: Vec<PathBuf>,
    calls: Mutex<Vec<String>>,
}

impl FakeVmware {
    pub fn with_running<P: Into<PathBuf>>(paths: impl IntoIterator<Item = P>) -> Self {
        Self {
            running: paths.into_iter().map(Into::into).collect(),
            calls: Mutex::default(),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }

    fn record(&self, call: String) {
        locks::lock(&self.calls).push(call);
    }
}

#[async_trait]
impl VmwareAdapter for FakeVmware {
    fn tool_path(&self) -> Option<PathBuf> {
        None
    }

    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        Ok(self.running.clone())
    }

    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo> {
        Ok(VmxInfo {
            display_name: vmx.file_stem().map(|s| s.to_string_lossy().into_owned()),
            ..Default::default()
        })
    }

    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()> {
        self.record(format!("power {op:?} {}", vmx.display()));
        Ok(())
    }

    async fn snapshot(&self, vmx: &Path, op: &SnapshotOp) -> Result<()> {
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
