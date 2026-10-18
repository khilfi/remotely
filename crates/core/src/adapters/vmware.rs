//! VMware Workstation Pro adapter: every call to Workstation goes through here.
//!
//! Today it drives `vmrun.exe` as a child process and reads Workstation's own files (the library in
//! `inventory.vmls` and each `.vmx`). The PRD's plan is to also run `vmrest` on localhost with
//! vault-generated credentials (VM-11, VM-12) and fall back to vmrun when it is unavailable; that
//! lands behind this same trait.

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::AsyncReadExt;

use crate::command_bus::{PowerOp, SnapshotOp, StopMode};
use crate::error::{CoreError, Result};
use crate::locks;

/// Settings read from a .vmx file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmxInfo {
    pub display_name: Option<String>,
    /// Workstation's guest OS id, e.g. `ubuntu-64`.
    pub guest_os: Option<String>,
    /// The name the guest reported through VMware Tools, e.g. "Ubuntu 24.04 LTS", when known.
    pub guest_os_name: Option<String>,
    pub num_vcpus: Option<u32>,
    pub memsize_mb: Option<u32>,
    /// `checkpoint.vmState` names a saved state: the VM is suspended.
    pub suspended: bool,
}

/// A VM in Workstation's library (VM-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryVm {
    pub vmx_path: PathBuf,
    /// The name the library shows; the .vmx `displayName` usually matches.
    pub display_name: Option<String>,
}

/// VMware Tools state from `vmrun checkToolsState` (VM-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ToolsState {
    Running,
    /// Installed but not running.
    Installed,
    NotInstalled,
    Unknown,
}

impl ToolsState {
    pub fn as_str(self) -> &'static str {
        match self {
            ToolsState::Running => "running",
            ToolsState::Installed => "installed",
            ToolsState::NotInstalled => "notInstalled",
            ToolsState::Unknown => "unknown",
        }
    }

    pub fn parse(out: &str) -> Self {
        match out.trim().to_ascii_lowercase().replace([' ', '_'], "").as_str() {
            "running" => ToolsState::Running,
            "installed" => ToolsState::Installed,
            "notinstalled" => ToolsState::NotInstalled,
            _ => ToolsState::Unknown,
        }
    }

    /// The state in words, for saying why a graceful power operation did not run (VM-02, VM-03).
    pub fn describe(self) -> &'static str {
        match self {
            ToolsState::Running => "VMware Tools is running in the guest",
            ToolsState::Installed => "VMware Tools is installed in the guest but not running",
            ToolsState::NotInstalled => "VMware Tools is not installed in the guest",
            ToolsState::Unknown => {
                "Workstation can't tell whether VMware Tools is running in the guest (it may still be starting)"
            }
        }
    }
}

/// One snapshot as Workstation records it in the VM's `.vmsd` file (VM-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// `snapshotN.uid`: stays the same for the life of the snapshot.
    pub uid: u32,
    /// The parent's uid; `None` for a snapshot taken before any other.
    pub parent_uid: Option<u32>,
    pub name: String,
    pub description: Option<String>,
    /// When it was taken. vmrun cannot tell; the .vmsd can.
    pub created_at: Option<OffsetDateTime>,
}

/// A VM's snapshots (VM-04).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotTree {
    /// In the order the .vmsd lists them.
    pub snapshots: Vec<SnapshotInfo>,
    /// `snapshot.current`: the snapshot the VM's current state was taken from ("you are here").
    pub current_uid: Option<u32>,
}

#[async_trait]
pub trait VmwareAdapter: Send + Sync {
    /// Path of the Workstation tool in use, for diagnostics.
    fn tool_path(&self) -> Option<PathBuf>;
    /// VM-01: the VMs in Workstation's library. Empty when Workstation has no library yet.
    async fn library(&self) -> Result<Vec<LibraryVm>>;
    /// VM-01: .vmx files in a user-chosen folder and its subfolders.
    async fn scan_folder(&self, folder: &Path) -> Result<Vec<PathBuf>>;
    /// `vmrun list`: .vmx paths of running VMs (VM-01).
    async fn list_running(&self) -> Result<Vec<PathBuf>>;
    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo>;
    /// VM-01: `vmrun checkToolsState`, for a running VM.
    async fn tools_state(&self, vmx: &Path) -> Result<ToolsState>;
    /// VM-01: `vmrun getGuestIPAddress` without waiting. `None` when the guest has not reported one.
    async fn guest_ip(&self, vmx: &Path) -> Result<Option<String>>;
    /// VM-02, VM-03. Only the job runner calls this.
    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()>;
    /// VM-04, VM-05. Only the job runner calls this.
    async fn snapshot(&self, vmx: &Path, op: &SnapshotOp) -> Result<()>;
    /// `vmrun listSnapshots`: names only. The snapshot manager reads [`VmwareAdapter::snapshots`].
    async fn list_snapshots(&self, vmx: &Path) -> Result<Vec<String>>;
    /// VM-04: the snapshot tree with creation times, read from the VM's .vmsd file. A VM without
    /// snapshots has no .vmsd, or an empty one.
    async fn snapshots(&self, vmx: &Path) -> Result<SnapshotTree>;
    /// AP-02: when the VM's running process started (its power-on or resume), from the first line of
    /// its `vmware.log`. Needs no guest login. Only meaningful while the VM runs; `None` without a log.
    async fn running_since(&self, vmx: &Path) -> Result<Option<OffsetDateTime>>;
}

/// Builds the adapter for this machine. When vmrun cannot be found the app still starts: the library,
/// folders and .vmx files are still read, and every vmrun call returns [`CoreError::VmrunNotFound`],
/// which the UI shows.
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

/// Workstation's library: `%APPDATA%\VMware\inventory.vmls`.
pub fn default_library_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|dir| PathBuf::from(dir).join("VMware").join("inventory.vmls"))
}

pub struct VmrunAdapter {
    vmrun: PathBuf,
}

const LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// checkToolsState and getGuestIPAddress: quick reads, run for every running VM on each refresh.
const QUERY_TIMEOUT: Duration = Duration::from_secs(20);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Folder levels searched below a chosen folder, e.g. `D:\VMs\lab\web01\web01.vmx` is 2 levels down.
const SCAN_DEPTH: usize = 5;
/// Folders visited per scan at most, so choosing a whole drive cannot hang the refresh.
const SCAN_MAX_DIRS: usize = 20_000;

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

    async fn library(&self) -> Result<Vec<LibraryVm>> {
        read_library().await
    }

    async fn scan_folder(&self, folder: &Path) -> Result<Vec<PathBuf>> {
        scan_for_vmx(folder).await
    }

    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        let out = self.run(vec!["list".into()], LIST_TIMEOUT).await?;
        parse_list_output(&out)
    }

    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo> {
        read_vmx_file(vmx).await
    }

    async fn tools_state(&self, vmx: &Path) -> Result<ToolsState> {
        let out = self
            .run(vec!["checkToolsState".into(), vmx.into()], QUERY_TIMEOUT)
            .await?;
        Ok(ToolsState::parse(&out))
    }

    async fn guest_ip(&self, vmx: &Path) -> Result<Option<String>> {
        match self
            .run(vec!["getGuestIPAddress".into(), vmx.into()], QUERY_TIMEOUT)
            .await
        {
            Ok(out) => Ok(parse_guest_ip(&out)),
            // "The VMware Tools are not running", "Unable to get the IP address": no IP to show.
            Err(CoreError::Vmrun { .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn power(&self, vmx: &Path, op: PowerOp) -> Result<()> {
        let (verb, mode) = power_args(op);
        let mut args: Vec<OsString> = vec![verb.into(), vmx.into()];
        args.extend(mode.map(OsString::from));
        self.run(args, power_timeout(op)).await.map(drop).map_err(no_answer)
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

    async fn snapshots(&self, vmx: &Path) -> Result<SnapshotTree> {
        read_vmsd_file(vmx).await
    }

    async fn running_since(&self, vmx: &Path) -> Result<Option<OffsetDateTime>> {
        read_log_start(vmx).await
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

/// How long a vmrun power call may run. Workstation holds a VM's power calls while it waits for an
/// answer to a question or message (e.g. "No operating system was found"), so each call gets about
/// as long as its operation can need and no more.
pub fn power_timeout(op: PowerOp) -> Duration {
    match op {
        // Stops or restarts the virtual CPUs only.
        PowerOp::Pause | PowerOp::Unpause => Duration::from_secs(60),
        // Like the power button: nothing is written to disk.
        PowerOp::Stop { mode: StopMode::Hard } | PowerOp::Reset { mode: StopMode::Hard } => Duration::from_secs(2 * 60),
        // The job runner stops waiting after the shutdown wait setting (VM-03), which can be up to
        // an hour; vmrun must not give up first.
        PowerOp::Stop { mode: StopMode::Soft } => Duration::from_secs(60 * 60),
        // A start may resume a suspended VM, and a suspend writes the VM's memory to disk: both can
        // take minutes for a large VM. A restart waits for the guest to shut down.
        PowerOp::Start { .. } | PowerOp::Suspend | PowerOp::Reset { mode: StopMode::Soft } => {
            Duration::from_secs(10 * 60)
        }
    }
}

/// A power call that timed out says why it may have hung.
fn no_answer(err: CoreError) -> CoreError {
    match err {
        CoreError::Timeout { command, seconds } => CoreError::PowerTimeout {
            command: command.trim_start_matches("vmrun ").to_owned(),
            seconds,
        },
        other => other,
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

/// `vmrun getGuestIPAddress` prints one address. Anything else means there is none to show.
pub fn parse_guest_ip(out: &str) -> Option<String> {
    let text = out.trim();
    text.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Splits a `key = "value"` line of a VMware config file (.vmx, .vmls) into a lowercase key and the
/// unescaped value. Comments and lines without `=` give `None`.
fn config_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    Some((key.trim().to_ascii_lowercase(), unescape_value(value)))
}

/// VMware config files write some characters as `|XX` (hex byte), e.g. `|22` for `"` and `|7C` for `|`.
fn unescape_value(value: &str) -> String {
    if !value.contains('|') {
        return value.to_owned();
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'|' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads the keys the inventory needs from a .vmx file (`key = "value"` lines).
pub fn parse_vmx(text: &str) -> VmxInfo {
    let mut info = VmxInfo::default();
    for (key, value) in text.lines().filter_map(config_line) {
        match key.as_str() {
            "displayname" => info.display_name = Some(value),
            "guestos" => info.guest_os = Some(value),
            "numvcpus" => info.num_vcpus = value.parse().ok(),
            "memsize" => info.memsize_mb = value.parse().ok(),
            "checkpoint.vmstate" => info.suspended = !value.trim().is_empty(),
            // Written by Workstation from VMware Tools: `... prettyName='Ubuntu 24.04 LTS' ...`.
            "guestinfo.detailed.data" => info.guest_os_name = pretty_name(&value),
            _ => {}
        }
    }
    info
}

fn pretty_name(detailed: &str) -> Option<String> {
    let start = detailed.find("prettyName='")? + "prettyName='".len();
    let rest = &detailed[start..];
    let name = rest[..rest.find('\'')?].trim();
    (!name.is_empty()).then(|| name.to_owned())
}

async fn read_vmx_file(vmx: &Path) -> Result<VmxInfo> {
    let bytes = tokio::fs::read(vmx).await?;
    Ok(parse_vmx(&String::from_utf8_lossy(&bytes)))
}

/// Parses Workstation's library (`inventory.vmls`):
///
/// ```text
/// vmlist1.config = "C:\VMs\web01\web01.vmx"
/// vmlist1.DisplayName = "web01"
/// vmlist2.config = "folder2"
/// vmlist2.Type = "2"
/// vmlist3.config = ""
/// ```
///
/// Folders (`Type = "2"`), empty slots and anything that is not a .vmx are left out. The same .vmx
/// listed twice (any letter case) is kept once.
pub fn parse_vmls(text: &str) -> Vec<LibraryVm> {
    #[derive(Default)]
    struct Entry {
        config: Option<String>,
        display_name: Option<String>,
        folder: bool,
    }
    let mut entries: BTreeMap<u32, Entry> = BTreeMap::new();
    for (key, value) in text.lines().filter_map(config_line) {
        let Some(rest) = key.strip_prefix("vmlist") else {
            continue;
        };
        let Some((index, field)) = rest.split_once('.') else {
            continue;
        };
        let Ok(index) = index.parse::<u32>() else {
            continue;
        };
        let entry = entries.entry(index).or_default();
        match field {
            "config" => entry.config = Some(value),
            "displayname" => entry.display_name = Some(value).filter(|v| !v.trim().is_empty()),
            "type" => entry.folder = value.trim() == "2",
            _ => {}
        }
    }
    let mut seen = HashSet::new();
    entries
        .into_values()
        .filter(|e| !e.folder)
        .filter_map(|e| {
            let config = e.config?;
            let path = PathBuf::from(config.trim());
            let is_vmx = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("vmx"));
            (is_vmx && seen.insert(path_key(&path))).then_some(LibraryVm {
                vmx_path: path,
                display_name: e.display_name,
            })
        })
        .collect()
}

async fn read_library() -> Result<Vec<LibraryVm>> {
    let Some(path) = default_library_path() else {
        return Ok(Vec::new());
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => Ok(parse_vmls(&String::from_utf8_lossy(&bytes))),
        // No library yet: Workstation was never opened by this Windows user.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err.into()),
    }
}

/// Parses a VM's snapshot list (`<vm>.vmsd`, next to the .vmx), as Workstation 17 and later write it:
///
/// ```text
/// snapshot.lastUID = "3"
/// snapshot.current = "3"
/// snapshot0.uid = "1"
/// snapshot0.filename = "web01-Snapshot1.vmsn"
/// snapshot0.displayName = "base"
/// snapshot0.description = ""
/// snapshot0.createTimeHigh = "417299"
/// snapshot0.createTimeLow = "-1088677800"
/// snapshot.numSnapshots = "2"
/// snapshot1.uid = "2"
/// snapshot1.parent = "1"
/// ...
/// ```
///
/// `parent` names the parent's uid and is missing on a first snapshot. The creation time is
/// microseconds since 1970 (UTC), split into a high and a signed low 32-bit half. Entries without a
/// uid are left out.
pub fn parse_vmsd(text: &str) -> SnapshotTree {
    #[derive(Default)]
    struct Entry {
        uid: Option<u32>,
        parent: Option<u32>,
        name: Option<String>,
        description: Option<String>,
        time_high: Option<i64>,
        time_low: Option<i64>,
    }
    let mut entries: BTreeMap<u32, Entry> = BTreeMap::new();
    let mut current_uid = None;
    for (key, value) in text.lines().filter_map(config_line) {
        if key == "snapshot.current" {
            current_uid = value.trim().parse().ok();
            continue;
        }
        // snapshot.lastUID, snapshot.numSnapshots, snapshot.mru0.uid: no index, so skipped here.
        let Some((index, field)) = key.strip_prefix("snapshot").and_then(|rest| rest.split_once('.')) else {
            continue;
        };
        let Ok(index) = index.parse::<u32>() else {
            continue;
        };
        let entry = entries.entry(index).or_default();
        match field {
            "uid" => entry.uid = value.trim().parse().ok(),
            "parent" => entry.parent = value.trim().parse().ok(),
            "displayname" => entry.name = Some(value),
            "description" => entry.description = Some(value).filter(|d| !d.trim().is_empty()),
            "createtimehigh" => entry.time_high = value.trim().parse().ok(),
            "createtimelow" => entry.time_low = value.trim().parse().ok(),
            _ => {}
        }
    }
    let snapshots = entries
        .into_values()
        .filter_map(|e| {
            Some(SnapshotInfo {
                uid: e.uid?,
                parent_uid: e.parent,
                name: e.name.unwrap_or_default(),
                description: e.description,
                created_at: e
                    .time_high
                    .zip(e.time_low)
                    .and_then(|(high, low)| snapshot_time(high, low)),
            })
        })
        .collect();
    SnapshotTree { snapshots, current_uid }
}

/// `createTimeHigh` and `createTimeLow` are the two 32-bit halves of microseconds since 1970 (UTC).
fn snapshot_time(high: i64, low: i64) -> Option<OffsetDateTime> {
    // The low half is written as a signed 32-bit number; only its bits count.
    let low = i64::from(u32::try_from(low & 0xFFFF_FFFF).ok()?);
    let micros = high.checked_shl(32)?.checked_add(low)?;
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1000).ok()
}

/// The .vmsd sits next to the .vmx and has the same name.
async fn read_vmsd_file(vmx: &Path) -> Result<SnapshotTree> {
    match tokio::fs::read(vmx.with_extension("vmsd")).await {
        Ok(bytes) => Ok(parse_vmsd(&String::from_utf8_lossy(&bytes))),
        // Never had a snapshot.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SnapshotTree::default()),
        Err(err) => Err(err.into()),
    }
}

/// The time at the start of the first line of `vmware.log`, which the VM's process writes when it
/// starts:
///
/// ```text
/// 2026-08-08T15:19:28.598Z In(05) vmx Log for VMware Workstation pid=1234 version=17.6.0 ...
/// 2026-08-08T15:19:28.598Z -INFO vmware-vmx.exe 1234 [ws@4413 threadName="vmx"] Log for VMware ...
/// ```
pub fn parse_log_start(first_line: &str) -> Option<OffsetDateTime> {
    let token = first_line.split(|c: char| c.is_whitespace() || c == '|').next()?;
    OffsetDateTime::parse(token, &Rfc3339).ok()
}

/// Reads only the start of `vmware.log` in the VM's folder; the running VM keeps writing the rest.
async fn read_log_start(vmx: &Path) -> Result<Option<OffsetDateTime>> {
    let Some(folder) = vmx.parent() else {
        return Ok(None);
    };
    let mut file = match tokio::fs::File::open(folder.join("vmware.log")).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut head = vec![0u8; 256];
    let read = file.read(&mut head).await?;
    let text = String::from_utf8_lossy(&head[..read]);
    Ok(text.lines().next().and_then(parse_log_start))
}

/// .vmx files under `folder`, at most [`SCAN_DEPTH`] levels down. Symbolic links and Workstation's
/// lock folders (`*.lck`) are not followed.
pub async fn scan_for_vmx(folder: &Path) -> Result<Vec<PathBuf>> {
    let folder = folder.to_path_buf();
    tokio::task::spawn_blocking(move || scan_blocking(&folder))
        .await
        .map_err(|err| CoreError::Io(std::io::Error::other(err)))?
}

fn scan_blocking(folder: &Path) -> Result<Vec<PathBuf>> {
    if !folder.is_dir() {
        return Err(CoreError::InvalidInput(format!("{} is not a folder", folder.display())));
    }
    let mut found = Vec::new();
    let mut pending = vec![(folder.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = pending.pop() {
        visited += 1;
        if visited > SCAN_MAX_DIRS {
            tracing::warn!(folder = %folder.display(), "folder scan stopped after {SCAN_MAX_DIRS} folders");
            break;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // The chosen folder itself must be readable; a subfolder we may not enter is skipped.
            Err(err) if depth == 0 => return Err(err.into()),
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_dir() {
                let is_lock = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("lck"));
                if depth < SCAN_DEPTH && !is_lock {
                    pending.push((path, depth + 1));
                }
            } else if kind.is_file() && path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("vmx")) {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Windows paths are case-insensitive: the key to compare .vmx paths by.
pub fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
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
    async fn library(&self) -> Result<Vec<LibraryVm>> {
        self.current().library().await
    }
    async fn scan_folder(&self, folder: &Path) -> Result<Vec<PathBuf>> {
        self.current().scan_folder(folder).await
    }
    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        self.current().list_running().await
    }
    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo> {
        self.current().read_vmx(vmx).await
    }
    async fn tools_state(&self, vmx: &Path) -> Result<ToolsState> {
        self.current().tools_state(vmx).await
    }
    async fn guest_ip(&self, vmx: &Path) -> Result<Option<String>> {
        self.current().guest_ip(vmx).await
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
    async fn snapshots(&self, vmx: &Path) -> Result<SnapshotTree> {
        self.current().snapshots(vmx).await
    }
    async fn running_since(&self, vmx: &Path) -> Result<Option<OffsetDateTime>> {
        self.current().running_since(vmx).await
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

/// Stand-in when Workstation is not installed: Workstation's files are still read, so the VM list
/// shows what is there; anything that needs vmrun fails with [`CoreError::VmrunNotFound`].
struct MissingWorkstation;

#[async_trait]
impl VmwareAdapter for MissingWorkstation {
    fn tool_path(&self) -> Option<PathBuf> {
        None
    }
    async fn library(&self) -> Result<Vec<LibraryVm>> {
        read_library().await
    }
    async fn scan_folder(&self, folder: &Path) -> Result<Vec<PathBuf>> {
        scan_for_vmx(folder).await
    }
    async fn list_running(&self) -> Result<Vec<PathBuf>> {
        Err(CoreError::VmrunNotFound)
    }
    async fn read_vmx(&self, vmx: &Path) -> Result<VmxInfo> {
        read_vmx_file(vmx).await
    }
    async fn tools_state(&self, _: &Path) -> Result<ToolsState> {
        Err(CoreError::VmrunNotFound)
    }
    async fn guest_ip(&self, _: &Path) -> Result<Option<String>> {
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
    async fn snapshots(&self, vmx: &Path) -> Result<SnapshotTree> {
        read_vmsd_file(vmx).await
    }
    async fn running_since(&self, vmx: &Path) -> Result<Option<OffsetDateTime>> {
        read_log_start(vmx).await
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
checkpoint.vmState = ""
guestInfo.detailed.data = "architecture='X86' bitness='64' distroName='Ubuntu' prettyName='Ubuntu 24.04.1 LTS'"
"#;
        assert_eq!(
            parse_vmx(vmx),
            VmxInfo {
                display_name: Some("Ubuntu 24.04 web01".into()),
                guest_os: Some("ubuntu-64".into()),
                guest_os_name: Some("Ubuntu 24.04.1 LTS".into()),
                num_vcpus: Some(4),
                memsize_mb: Some(8192),
                suspended: false,
            }
        );
    }

    #[test]
    fn a_saved_state_means_suspended() {
        let info = parse_vmx("displayName = \"db01\"\ncheckpoint.vmState = \"db01-a1b2c3.vmss\"\n");
        assert!(info.suspended);
        assert_eq!(info.guest_os_name, None);
    }

    #[test]
    fn vmx_values_are_unescaped() {
        let info = parse_vmx("displayName = \"lab |22blue|22 |7C web\"\n");
        assert_eq!(info.display_name.as_deref(), Some("lab \"blue\" | web"));
        assert_eq!(unescape_value("50|"), "50|", "a trailing bar is kept");
        assert_eq!(unescape_value("a|zzb"), "a|zzb", "not hex: kept as is");
    }

    #[test]
    fn parses_the_workstation_library() {
        // The shape of %APPDATA%\VMware\inventory.vmls written by Workstation 17 and later.
        let vmls = r#".encoding = "UTF-8"
vmlist1.config = ""
vmlist2.config = "C:\VMs\web01\web01.vmx"
vmlist2.DisplayName = "web01"
vmlist2.ParentID = "4"
vmlist2.ItemID = "2"
vmlist2.IsFavorite = "FALSE"
vmlist2.State = "normal"
vmlist3.config = "D:\Labs\db01\db01.VMX"
vmlist3.DisplayName = ""
vmlist4.config = "folder4"
vmlist4.Type = "2"
vmlist4.DisplayName = "Lab"
vmlist5.config = "c:\vms\WEB01\web01.vmx"
vmlist5.DisplayName = "web01 again"
vmlist6.config = "C:\ISOs\notes.txt"
index0.field0.name = "guest"
index.count = "1"
"#;
        assert_eq!(
            parse_vmls(vmls),
            vec![
                LibraryVm {
                    vmx_path: PathBuf::from(r"C:\VMs\web01\web01.vmx"),
                    display_name: Some("web01".into()),
                },
                LibraryVm {
                    vmx_path: PathBuf::from(r"D:\Labs\db01\db01.VMX"),
                    display_name: None,
                },
            ]
        );
    }

    #[tokio::test]
    async fn scans_folders_for_vmx_files() {
        let root = std::env::temp_dir().join(format!("remotely-scan-{}", uuid::Uuid::new_v4()));
        let make = |rel: &str| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "displayName = \"x\"\n").unwrap();
            path
        };
        let web = make(r"lab\web01\web01.vmx");
        let db = make(r"db01\db01.VMX");
        make(r"db01\db01.vmxf");
        make(r"db01\db01.vmx.lck\M12345.lck");
        make(r"a\b\c\d\e\f\too-deep.vmx");

        let mut found = scan_for_vmx(&root).await.unwrap();
        found.sort();
        let mut expected = vec![db, web];
        expected.sort();
        assert_eq!(found, expected);

        let missing = scan_for_vmx(&root.join("nope")).await.unwrap_err();
        assert!(matches!(missing, CoreError::InvalidInput(_)));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn parses_tools_state_and_guest_ip() {
        assert_eq!(ToolsState::parse("running\r\n"), ToolsState::Running);
        assert_eq!(ToolsState::parse("installed"), ToolsState::Installed);
        assert_eq!(ToolsState::parse("notInstalled"), ToolsState::NotInstalled);
        assert_eq!(ToolsState::parse("unknown"), ToolsState::Unknown);
        assert_eq!(ToolsState::parse("something new"), ToolsState::Unknown);

        assert_eq!(parse_guest_ip("192.0.2.15\r\n").as_deref(), Some("192.0.2.15"));
        assert_eq!(parse_guest_ip("2001:db8::5").as_deref(), Some("2001:db8::5"));
        assert_eq!(parse_guest_ip("unknown"), None);
        assert_eq!(parse_guest_ip(""), None);
    }

    #[test]
    fn vmrun_path_must_name_vmrun_exe() {
        let err = validate_vmrun_path(Path::new(r"C:\Windows\System32\notepad.exe")).unwrap_err();
        assert!(matches!(err, CoreError::InvalidSetting(_)));
        let missing = validate_vmrun_path(Path::new(r"C:\does-not-exist\vmrun.exe")).unwrap_err();
        assert!(matches!(missing, CoreError::InvalidSetting(_)));
    }

    /// The shape Workstation 26 writes: "base", then "child one" on it, then a revert to "base" and
    /// `branch "two"` taken from there.
    const VMSD: &str = r#".encoding = "UTF-8"
snapshot.lastUID = "3"
snapshot.current = "3"
snapshot0.uid = "1"
snapshot0.filename = "web01-Snapshot1.vmsn"
snapshot0.displayName = "base"
snapshot0.description = ""
snapshot0.createTimeHigh = "417299"
snapshot0.createTimeLow = "-1088677800"
snapshot.numSnapshots = "3"
snapshot1.uid = "2"
snapshot1.filename = "web01-Snapshot2.vmsn"
snapshot1.parent = "1"
snapshot1.displayName = "child one"
snapshot1.description = "before the upgrade"
snapshot1.createTimeHigh = "417299"
snapshot1.createTimeLow = "-1088118800"
snapshot2.uid = "3"
snapshot2.filename = "web01-Snapshot3.vmsn"
snapshot2.parent = "1"
snapshot2.displayName = "branch |22two|22"
snapshot2.description = ""
snapshot2.createTimeHigh = "417299"
snapshot2.createTimeLow = "-1087100800"
snapshot2.numDisks = "1"
snapshot2.disk0.fileName = "web01.vmdk"
snapshot2.disk0.node = "scsi0:0"
"#;

    #[test]
    fn parses_the_snapshot_tree_and_creation_times() {
        let tree = parse_vmsd(VMSD);
        assert_eq!(tree.current_uid, Some(3));
        let summary: Vec<_> = tree
            .snapshots
            .iter()
            .map(|s| (s.uid, s.parent_uid, s.name.as_str(), s.description.as_deref()))
            .collect();
        assert_eq!(
            summary,
            [
                (1, None, "base", None),
                (2, Some(1), "child one", Some("before the upgrade")),
                (3, Some(1), "branch \"two\"", None),
            ]
        );
        // (417299 << 32) + 3206289496 microseconds; Workstation showed 09:59:23 at UTC+8.
        assert_eq!(
            tree.snapshots[0].created_at,
            Some(time::macros::datetime!(2026-10-18 01:59:23.943 UTC))
        );
        assert_eq!(
            tree.snapshots[2].created_at,
            Some(time::macros::datetime!(2026-10-18 01:59:25.520 UTC))
        );
    }

    #[test]
    fn an_empty_vmsd_has_no_snapshots() {
        assert_eq!(parse_vmsd(""), SnapshotTree::default());
        let only_counters = "snapshot.lastUID = \"4\"\nsnapshot.numSnapshots = \"0\"\nsnapshot.current = \"\"\n";
        assert_eq!(parse_vmsd(only_counters), SnapshotTree::default());
    }

    #[test]
    fn a_snapshot_without_a_time_still_lists() {
        let tree =
            parse_vmsd("snapshot0.uid = \"7\"\nsnapshot0.displayName = \"x\"\nsnapshot1.displayName = \"no uid\"\n");
        assert_eq!(tree.snapshots.len(), 1, "an entry without a uid is left out");
        assert_eq!(tree.snapshots[0].created_at, None);
    }

    #[tokio::test]
    async fn reads_the_vmsd_next_to_the_vmx() {
        let dir = std::env::temp_dir().join(format!("remotely-vmsd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let vmx = dir.join("web01.vmx");
        assert_eq!(
            read_vmsd_file(&vmx).await.unwrap(),
            SnapshotTree::default(),
            "no .vmsd yet"
        );
        std::fs::write(dir.join("web01.vmsd"), "").unwrap();
        assert!(read_vmsd_file(&vmx).await.unwrap().snapshots.is_empty());
        std::fs::write(dir.join("web01.vmsd"), VMSD).unwrap();
        assert_eq!(read_vmsd_file(&vmx).await.unwrap().snapshots.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_log_start_is_the_first_time_in_vmware_log() {
        let ws26 = "2026-08-08T15:19:28.598Z -INFO vmware-vmx.exe 4242 [ws@4413 threadName=\"vmx\"] Log for VMware Workstation pid=4242";
        assert_eq!(
            parse_log_start(ws26),
            Some(time::macros::datetime!(2026-08-08 15:19:28.598 UTC))
        );
        let ws17 = "2024-03-22T10:13:00.123+01:00| vmx| I005: Log for VMware Workstation pid=4242";
        assert_eq!(
            parse_log_start(ws17),
            Some(time::macros::datetime!(2024-03-22 09:13:00.123 UTC))
        );
        assert_eq!(parse_log_start("not a time"), None);
        assert_eq!(parse_log_start(""), None);
    }

    #[tokio::test]
    async fn reads_only_the_first_line_of_vmware_log() {
        let dir = std::env::temp_dir().join(format!("remotely-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let vmx = dir.join("web01.vmx");
        assert_eq!(read_log_start(&vmx).await.unwrap(), None, "no log yet");
        let mut log = String::from("2026-08-08T15:19:28.598Z In(05) vmx Log for VMware Workstation\n");
        log.push_str(&"2026-08-08T16:00:00.000Z In(05) vmx later line\n".repeat(1000));
        std::fs::write(dir.join("vmware.log"), log).unwrap();
        assert_eq!(
            read_log_start(&vmx).await.unwrap(),
            Some(time::macros::datetime!(2026-08-08 15:19:28.598 UTC))
        );
        std::fs::remove_dir_all(&dir).unwrap();
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

    #[test]
    fn quick_power_ops_get_short_timeouts() {
        let secs = |op| power_timeout(op).as_secs();
        assert_eq!(secs(PowerOp::Pause), 60);
        assert_eq!(secs(PowerOp::Unpause), 60);
        assert_eq!(secs(PowerOp::Stop { mode: StopMode::Hard }), 120);
        assert_eq!(secs(PowerOp::Reset { mode: StopMode::Hard }), 120);
        assert_eq!(secs(PowerOp::Suspend), 600);
        assert_eq!(secs(PowerOp::Start { gui: false }), 600);
        assert_eq!(secs(PowerOp::Reset { mode: StopMode::Soft }), 600);
        // VM-03: the shutdown wait setting, not vmrun, decides when a soft stop has taken too long.
        assert!(
            secs(PowerOp::Stop { mode: StopMode::Soft }) >= crate::jobs::JobLimits::MAX_SHUTDOWN_WAIT_SECS,
            "vmrun must not give up before the longest shutdown wait"
        );
    }

    #[test]
    fn a_power_timeout_says_the_vm_may_be_waiting_for_an_answer() {
        let err = no_answer(CoreError::Timeout {
            command: "vmrun pause".into(),
            seconds: 60,
        });
        assert_eq!(err.code(), "power_timeout");
        assert_eq!(
            err.to_string(),
            "vmrun pause got no answer within 60 s. The VM may be waiting for a reply to a message in \
             Workstation: open it there to check"
        );
        let failed = no_answer(CoreError::Vmrun {
            command: "pause".into(),
            message: "The virtual machine is not powered on".into(),
        });
        assert_eq!(failed.code(), "vmrun_failed", "other errors pass through");
    }
}
