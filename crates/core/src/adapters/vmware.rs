//! VMware Workstation Pro adapter: every call to Workstation goes through here.
//!
//! Today it drives `vmrun.exe` as a child process. The PRD's plan is to also run `vmrest` on
//! localhost with vault-generated credentials (VM-01, VM-11, VM-12) and fall back to vmrun when it is
//! unavailable; that lands behind this same trait.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;

use crate::command_bus::{PowerOp, SnapshotOp, StopMode};
use crate::error::{CoreError, Result};
use crate::locks;

/// Settings read from a .vmx file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmxInfo {
    pub display_name: Option<String>,
    pub guest_os: Option<String>,
    pub num_vcpus: Option<u32>,
    pub memsize_mb: Option<u32>,
}

#[async_trait]
pub trait VmwareAdapter: Send + Sync {
    /// Path of the Workstation tool in use, for diagnostics.
    fn tool_path(&self) -> Option<PathBuf>;
    /// `vmrun list`: .vmx paths of running VMs (VM-01).
    async fn list_running(&self) -> Result<Vec<PathBuf>>;
    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo>;
    /// VM-02, VM-03. Only the job runner calls this.
    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()>;
    /// VM-04, VM-05. Only the job runner calls this.
    async fn snapshot(&self, vmx: &Path, op: &SnapshotOp) -> Result<()>;
    async fn list_snapshots(&self, vmx: &Path) -> Result<Vec<String>>;
}

/// Builds the adapter for this machine. When vmrun cannot be found the app still starts and every
/// VMware call returns [`CoreError::VmrunNotFound`], which the UI shows.
pub fn connect(vmrun_override: Option<PathBuf>) -> Box<dyn VmwareAdapter> {
    match locate_vmrun(vmrun_override) {
        Some(path) => {
            tracing::info!(vmrun = %path.display(), "using vmrun");
            Box::new(VmrunAdapter::new(path))
        }
        None => {
            tracing::warn!("vmrun.exe not found; VMware features are unavailable");
            Box::new(MissingWorkstation)
        }
    }
}

/// Finds vmrun.exe: explicit override, then `REMOTELY_VMRUN`, then the Workstation install path in the
/// registry, then the default install folders.
pub fn locate_vmrun(override_path: Option<PathBuf>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(override_path);
    candidates.extend(std::env::var_os("REMOTELY_VMRUN").map(PathBuf::from));
    candidates.extend(registry_install_dirs().into_iter().map(|d| d.join("vmrun.exe")));
    candidates.push(PathBuf::from(
        r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    ));
    candidates.push(PathBuf::from(r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"));
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(windows)]
fn registry_install_dirs() -> Vec<PathBuf> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    [
        r"SOFTWARE\VMware, Inc.\VMware Workstation",
        r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation",
    ]
    .iter()
    .filter_map(|key| hklm.open_subkey(key).ok())
    .filter_map(|key| key.get_value::<String, _>("InstallPath").ok())
    .map(PathBuf::from)
    .collect()
}

#[cfg(not(windows))]
fn registry_install_dirs() -> Vec<PathBuf> {
    Vec::new()
}

pub struct VmrunAdapter {
    vmrun: PathBuf,
}

const LIST_TIMEOUT: Duration = Duration::from_secs(30);
const POWER_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

impl VmrunAdapter {
    pub fn new(vmrun: PathBuf) -> Self {
        Self { vmrun }
    }

    /// Runs `vmrun -T ws <args>` without a console window and returns stdout.
    async fn run(&self, args: Vec<OsString>, timeout: Duration) -> Result<String> {
        let label = args
            .first()
            .map(|a| a.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut cmd = tokio::process::Command::new(&self.vmrun);
        cmd.arg("-T")
            .arg("ws")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let output = tokio::time::timeout(timeout, cmd.output())
            .await
            .map_err(|_| CoreError::Timeout {
                command: format!("vmrun {label}"),
                seconds: timeout.as_secs(),
            })??;

        // vmrun writes errors to stdout as "Error: ...". Console code page, not always UTF-8.
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success() {
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = [stdout.trim(), stderr.trim()]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            Err(CoreError::Vmrun {
                command: label,
                message: message.trim_start_matches("Error: ").to_owned(),
            })
        }
    }
}

#[async_trait]
impl VmwareAdapter for VmrunAdapter {
    fn tool_path(&self) -> Option<PathBuf> {
        Some(self.vmrun.clone())
    }

    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        let out = self.run(vec!["list".into()], LIST_TIMEOUT).await?;
        parse_list_output(&out)
    }

    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo> {
        let bytes = tokio::fs::read(vmx).await?;
        Ok(parse_vmx(&String::from_utf8_lossy(&bytes)))
    }

    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()> {
        let (verb, mode) = power_args(op);
        let mut args: Vec<OsString> = vec![verb.into(), vmx.into()];
        args.extend(mode.map(OsString::from));
        self.run(args, POWER_TIMEOUT).await.map(drop)
    }

    async fn snapshot(&self, vmx: &Path, op: &SnapshotOp) -> Result<()> {
        let args: Vec<OsString> = match op {
            SnapshotOp::Take { name } => vec!["snapshot".into(), vmx.into(), name.into()],
            SnapshotOp::Revert { name } => vec!["revertToSnapshot".into(), vmx.into(), name.into()],
            SnapshotOp::Delete { name } => vec!["deleteSnapshot".into(), vmx.into(), name.into()],
        };
        self.run(args, SNAPSHOT_TIMEOUT).await.map(drop)
    }

    async fn list_snapshots(&self, vmx: &Path) -> Result<Vec<String>> {
        let out = self.run(vec!["listSnapshots".into(), vmx.into()], LIST_TIMEOUT).await?;
        Ok(out
            .lines()
            .skip_while(|l| !l.starts_with("Total snapshots:"))
            .skip(1)
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }
}

/// vmrun verb and optional mode argument for a power operation.
pub fn power_args(op: PowerOp) -> (&'static str, Option<&'static str>) {
    let mode = |m: StopMode| match m {
        StopMode::Soft => "soft",
        StopMode::Hard => "hard",
    };
    match op {
        PowerOp::Start { gui } => ("start", Some(if gui { "gui" } else { "nogui" })),
        PowerOp::Stop { mode: m } => ("stop", Some(mode(m))),
        PowerOp::Reset { mode: m } => ("reset", Some(mode(m))),
        PowerOp::Suspend => ("suspend", Some("soft")),
        PowerOp::Pause => ("pause", None),
        PowerOp::Unpause => ("unpause", None),
    }
}

/// Parses `vmrun list`:
///
/// ```text
/// Total running VMs: 2
/// C:\VMs\web01\web01.vmx
/// D:\Labs\db01\db01.vmx
/// ```
pub fn parse_list_output(out: &str) -> Result<Vec<PathBuf>> {
    let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
    let header = lines.next().unwrap_or_default();
    let expected: usize = header
        .strip_prefix("Total running VMs:")
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| CoreError::Vmrun {
            command: "list".into(),
            message: format!("unexpected output: {header:?}"),
        })?;
    let paths: Vec<PathBuf> = lines.map(PathBuf::from).collect();
    if paths.len() != expected {
        tracing::warn!(expected, got = paths.len(), "vmrun list count mismatch");
    }
    Ok(paths)
}

/// Reads the keys the inventory needs from a .vmx file (`key = "value"` lines).
pub fn parse_vmx(text: &str) -> VmxInfo {
    let mut info = VmxInfo::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').to_owned();
        match key.as_str() {
            "displayname" => info.display_name = Some(value),
            "guestos" => info.guest_os = Some(value),
            "numvcpus" => info.num_vcpus = value.parse().ok(),
            "memsize" => info.memsize_mb = value.parse().ok(),
            _ => {}
        }
    }
    info
}

/// The adapter the rest of the core holds. Changing the vmrun path in Settings swaps what is inside
/// without restarting; a call already in flight finishes on the adapter it started with.
pub struct SwitchableVmware {
    inner: RwLock<Arc<dyn VmwareAdapter>>,
}

impl SwitchableVmware {
    pub fn new(adapter: Arc<dyn VmwareAdapter>) -> Self {
        Self {
            inner: RwLock::new(adapter),
        }
    }

    pub fn replace(&self, adapter: Arc<dyn VmwareAdapter>) {
        *locks::write(&self.inner) = adapter;
    }

    fn current(&self) -> Arc<dyn VmwareAdapter> {
        Arc::clone(&locks::read(&self.inner))
    }
}

#[async_trait]
impl VmwareAdapter for SwitchableVmware {
    fn tool_path(&self) -> Option<PathBuf> {
        self.current().tool_path()
    }
    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        self.current().list_running().await
    }
    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo> {
        self.current().read_vmx(vmx).await
    }
    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()> {
        self.current().power(vmx, op).await
    }
    async fn snapshot(&self, vmx: &Path, op: &SnapshotOp) -> Result<()> {
        self.current().snapshot(vmx, op).await
    }
    async fn list_snapshots(&self, vmx: &Path) -> Result<Vec<String>> {
        self.current().list_snapshots(vmx).await
    }
}

/// Checks a user-chosen vmrun path before it is saved: it must be an existing file named vmrun.exe.
pub fn validate_vmrun_path(path: &Path) -> Result<()> {
    let named_vmrun = path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("vmrun.exe"));
    if !named_vmrun {
        return Err(CoreError::InvalidSetting(format!(
            "{} is not vmrun.exe",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(CoreError::InvalidSetting(format!("{} does not exist", path.display())));
    }
    Ok(())
}

/// Stand-in when Workstation is not installed.
struct MissingWorkstation;

#[async_trait]
impl VmwareAdapter for MissingWorkstation {
    fn tool_path(&self) -> Option<PathBuf> {
        None
    }
    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        Err(CoreError::VmrunNotFound)
    }
    async fn read_vmx(&self, _: &Path) -> Result<VmxInfo> {
        Err(CoreError::VmrunNotFound)
    }
    async fn power(&self, _: &Path, _: PowerOp) -> Result<()> {
        Err(CoreError::VmrunNotFound)
    }
    async fn snapshot(&self, _: &Path, _: &SnapshotOp) -> Result<()> {
        Err(CoreError::VmrunNotFound)
    }
    async fn list_snapshots(&self, _: &Path) -> Result<Vec<String>> {
        Err(CoreError::VmrunNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vmrun_list() {
        let out = "Total running VMs: 2\r\nC:\\VMs\\web01\\web01.vmx\r\nD:\\Labs\\db 01\\db01.vmx\r\n";
        let vms = parse_list_output(out).unwrap();
        assert_eq!(
            vms,
            vec![
                PathBuf::from(r"C:\VMs\web01\web01.vmx"),
                PathBuf::from(r"D:\Labs\db 01\db01.vmx"),
            ]
        );
    }

    #[test]
    fn parses_empty_vmrun_list() {
        assert!(parse_list_output("Total running VMs: 0\r\n").unwrap().is_empty());
    }

    #[test]
    fn rejects_unexpected_vmrun_output() {
        assert!(parse_list_output("Error: something broke").is_err());
    }

    #[test]
    fn parses_vmx_keys() {
        let vmx = r#".encoding = "UTF-8"
config.version = "8"
displayName = "Ubuntu 24.04 web01"
guestOS = "ubuntu-64"
numvcpus = "4"
memsize = "8192"
ethernet0.present = "TRUE"
"#;
        assert_eq!(
            parse_vmx(vmx),
            VmxInfo {
                display_name: Some("Ubuntu 24.04 web01".into()),
                guest_os: Some("ubuntu-64".into()),
                num_vcpus: Some(4),
                memsize_mb: Some(8192),
            }
        );
    }

    #[test]
    fn vmrun_path_must_name_vmrun_exe() {
        let err = validate_vmrun_path(Path::new(r"C:\Windows\System32\notepad.exe")).unwrap_err();
        assert!(matches!(err, CoreError::InvalidSetting(_)));
        let missing = validate_vmrun_path(Path::new(r"C:\does-not-exist\vmrun.exe")).unwrap_err();
        assert!(matches!(missing, CoreError::InvalidSetting(_)));
    }

    #[test]
    fn power_ops_map_to_vmrun_arguments() {
        assert_eq!(power_args(PowerOp::Start { gui: false }), ("start", Some("nogui")));
        assert_eq!(power_args(PowerOp::Start { gui: true }), ("start", Some("gui")));
        assert_eq!(
            power_args(PowerOp::Stop { mode: StopMode::Hard }),
            ("stop", Some("hard"))
        );
        assert_eq!(
            power_args(PowerOp::Reset { mode: StopMode::Soft }),
            ("reset", Some("soft"))
        );
        assert_eq!(power_args(PowerOp::Pause), ("pause", None));
    }
}
