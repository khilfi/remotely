//! Fake adapters for tests: one per outside system, each recording what it was asked to do. None of
//! them touches a real VM, host, vault or update server (CLAUDE.md "Development safety").
//!
//! Compiled for the crate's own unit tests and, through the `fakes` feature, for the integration
//! tests in `tests/`. The app never enables that feature.

pub mod containers;
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

use crate::adapters::exec_output::OutputCollector;
use crate::adapters::host_counters::{DiskSpace, HostCounters, HostTotals, SystemCpuTimes, VmProcess};
use crate::adapters::network::{ip_literal, NetworkAdapter};
use crate::adapters::remote::forward::{
    self, Duplex, ForwardKind, ForwardSpec, Opener, RemoteForwards, RunningForward,
};
use crate::adapters::remote::{
    ConnectRequest, Credentials, EntryKind, ExecRequest, ExecResult, ExecSession, PromptShell, Prompter, RemoteAdapter,
    RemoteEntry, RemoteFiles, RemoteListing, RemoteRead, RemoteWrite, ShellEnd, ShellHandle, ShellInput, ShellOutput,
    ShellRequest, Written,
};
use crate::adapters::updater::{ReleaseCheck, TokenReport, UpdateInfo, UpdaterAdapter};
use crate::adapters::virtualbox::{
    self as vbox, VboxController, VboxDisk, VboxDvd, VboxListedVm, VboxNic, VboxVmInfo, VirtualBoxAdapter,
    GUEST_NET_COUNT, GUEST_OS_PRODUCT,
};
use crate::adapters::vm_hardware::VmHardware;
use crate::adapters::vmware::{path_key, LibraryVm, SnapshotInfo, SnapshotTree, ToolsState, VmwareAdapter, VmxInfo};
use crate::command_bus::{PowerOp, SnapshotOp, StopMode};
use crate::domain::{Context, PowerState};
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
    /// MO-13: what each VM's files say about its hardware.
    hardware: HashMap<String, VmHardware>,
    /// MO-13: the VMs' files can't be read right now (a drive that went away).
    hardware_fails: AtomicBool,
    running: Mutex<Vec<PathBuf>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    calls: Mutex<Vec<String>>,
    snapshot_reads: Mutex<Vec<String>>,
    /// Calls that would each start a vmrun process.
    vmrun_runs: AtomicUsize,
    /// VM-21: Workstation's default VM folder (`with_default_folder`).
    default_folder: Option<PathBuf>,
    /// VM-23: each VM's .vmx text, once a test gives it or Remotely writes it. Without one, a .vmx reads as
    /// what its [`VmxInfo`] says.
    vmx_texts: Mutex<HashMap<String, (PathBuf, String)>>,
    /// VM-23: backup copies beside the .vmx files, by path.
    backups: Mutex<HashMap<String, (PathBuf, String)>>,
    /// VM-16: virtual disks by path: (path, provisioned MB, bytes on disk).
    disks: Mutex<HashMap<String, (PathBuf, u64, u64)>>,
    /// VM-16, VM-24: other files on "this PC" (ISOs, folders, a VM's logs), by path: (path, size).
    files: Mutex<HashMap<String, (PathBuf, u64)>>,
    /// VM-23: the next .vmx write fails (a full disk), so the backup is put back.
    failing_vmx_write: AtomicBool,
    /// VM-16: vdiskmanager fails.
    failing_vdisk: AtomicBool,
    /// VM-23: Workstation's window (`vmware.exe`) runs.
    workstation_open: AtomicBool,
    /// VM-21: operations that fail (`clone`, `ovftool`, `convert`), after leaving what they made, as a real
    /// tool stopped halfway does.
    failing: Mutex<HashSet<String>>,
    /// VM-21: no ovftool.exe on this PC.
    no_ovftool: bool,
    /// VM-21: a clone takes this long once its files are there (so a test can cancel it halfway).
    clone_delay: Duration,
}

/// What the fake writes for a .vmx it was given no text for.
fn synthesized_vmx(info: &VmxInfo) -> String {
    let mut text = String::from(".encoding = \"UTF-8\"\nconfig.version = \"8\"\nvirtualHW.version = \"21\"\n");
    if let Some(name) = &info.display_name {
        text.push_str(&format!(
            "displayName = \"{}\"\n",
            crate::adapters::vmx_file::escape_value(name)
        ));
    }
    if let Some(os) = &info.guest_os {
        text.push_str(&format!("guestOS = \"{os}\"\n"));
    }
    text.push_str(&format!("numvcpus = \"{}\"\n", info.num_vcpus.unwrap_or(1)));
    text.push_str(&format!("memsize = \"{}\"\n", info.memsize_mb.unwrap_or(1024)));
    if info.suspended {
        text.push_str("checkpoint.vmState = \"saved.vmss\"\n");
    }
    text
}

impl FakeVmware {
    /// VM-21: where Workstation would put new VMs (by default a made-up folder under alice's Documents).
    pub fn with_default_folder(mut self, folder: impl Into<PathBuf>) -> Self {
        self.default_folder = Some(folder.into());
        self
    }

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

    /// MO-13: the VM's hardware as its .vmx and disk files describe it. Without this, a VM's hardware is
    /// what its [`VmxInfo`] says (vCPUs, memory, guest OS), with no disks or adapters.
    pub fn with_hardware(mut self, vmx: &str, hardware: VmHardware) -> Self {
        self.hardware.insert(path_key(Path::new(vmx)), hardware);
        self
    }

    /// MO-13: from now on reading any VM's hardware fails (or works again).
    pub fn set_hardware_failing(&self, failing: bool) {
        self.hardware_fails.store(failing, Ordering::SeqCst);
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

    /// VM-23: the .vmx's text. Its keys then answer `read_vmx` and `hardware`, and Remotely's edits change it.
    pub fn with_vmx_text(self, vmx: &str, text: &str) -> Self {
        locks::lock(&self.vmx_texts).insert(path_key(Path::new(vmx)), (PathBuf::from(vmx), text.to_owned()));
        self
    }

    /// VM-16: a virtual disk of `size_mb` at `path`, taking a tenth of that on disk.
    pub fn with_disk(self, path: &str, size_mb: u64) -> Self {
        locks::lock(&self.disks).insert(
            path_key(Path::new(path)),
            (PathBuf::from(path), size_mb, size_mb * 1024 * 1024 / 10),
        );
        self
    }

    /// VM-16, VM-24: a file (an ISO, a folder to share, a VM's log) of `size` bytes.
    pub fn with_file(self, path: &str, size: u64) -> Self {
        locks::lock(&self.files).insert(path_key(Path::new(path)), (PathBuf::from(path), size));
        self
    }

    /// VM-23: from now on writing a .vmx fails (or works again).
    pub fn set_failing_vmx_write(&self, failing: bool) {
        self.failing_vmx_write.store(failing, Ordering::SeqCst);
    }

    /// VM-23: Workstation's window runs (or not) from now on.
    pub fn set_workstation_open(&self, open: bool) {
        self.workstation_open.store(open, Ordering::SeqCst);
    }

    /// VM-16: from now on vdiskmanager fails (or works again).
    /// VM-21: `op` (`clone`, `ovftool` or `convert`) fails from now on, after leaving the files it made.
    pub fn set_failing(&self, op: &str, failing: bool) {
        let mut set = locks::lock(&self.failing);
        if failing {
            set.insert(op.to_owned());
        } else {
            set.remove(op);
        }
    }

    fn fails(&self, op: &str) -> bool {
        locks::lock(&self.failing).contains(op)
    }

    /// VM-21: each clone takes this long after it has written its files, as a large one does.
    pub fn with_clone_delay(mut self, delay: Duration) -> Self {
        self.clone_delay = delay;
        self
    }

    /// VM-21: Workstation without its OVFTool folder.
    pub fn without_ovftool(mut self) -> Self {
        self.no_ovftool = true;
        self
    }

    /// VM-21: whether the fake holds a VM at this .vmx (made by a clone, an import or a write).
    pub fn has_vm(&self, vmx: &str) -> bool {
        locks::lock(&self.vmx_texts).contains_key(&path_key(Path::new(vmx)))
    }

    /// VM-21: the disks the fake holds in a folder, by path.
    pub fn disks_in(&self, folder: &str) -> Vec<PathBuf> {
        let folder = path_key(Path::new(folder));
        let mut out: Vec<PathBuf> = locks::lock(&self.disks)
            .values()
            .filter(|(p, _, _)| p.parent().is_some_and(|f| path_key(f) == folder))
            .map(|(p, _, _)| p.clone())
            .collect();
        out.sort();
        out
    }

    /// VM-21: what a clone of `source` at `target` holds: its .vmx with the clone's name, and a copy of each disk
    /// in the target's folder.
    fn clone_vm(&self, source: &Path, target: &Path, name: &str) -> Result<()> {
        let text = self.text_of(source)?;
        let mut file = crate::adapters::vmx_file::VmxFile::from_text(&text);
        file.set("displayName", name)?;
        let (_, disks) = crate::adapters::vm_hardware::parse_vmx_hardware(&text);
        let source_folder = source.parent().unwrap_or(Path::new(""));
        let target_folder = target.parent().unwrap_or(Path::new(""));
        {
            let mut known = locks::lock(&self.disks);
            for (i, disk) in disks.iter().enumerate() {
                let from = crate::vm_settings::vmware::resolve(source_folder, &disk.file_name);
                let size = known.get(&path_key(&from)).map_or(10 * 1024, |(_, mb, _)| *mb);
                let file_name = if i == 0 {
                    format!("{name}.vmdk")
                } else {
                    format!("{name}-{i}.vmdk")
                };
                let to = target_folder.join(&file_name);
                known.insert(path_key(&to), (to, size, 65536));
                file.set(&format!("{}.fileName", disk.slot), &file_name)?;
            }
        }
        locks::lock(&self.vmx_texts).insert(path_key(target), (target.to_path_buf(), file.to_text()));
        Ok(())
    }

    pub fn set_failing_vdisk(&self, failing: bool) {
        self.failing_vdisk.store(failing, Ordering::SeqCst);
    }

    /// VM-23: the .vmx's text now (as Remotely last wrote it, or as the test gave it).
    pub fn vmx_text(&self, vmx: &str) -> Option<String> {
        locks::lock(&self.vmx_texts)
            .get(&path_key(Path::new(vmx)))
            .map(|(_, t)| t.clone())
    }

    /// VM-23: the backup copies still beside .vmx files.
    pub fn backups(&self) -> Vec<PathBuf> {
        locks::lock(&self.backups).values().map(|(p, _)| p.clone()).collect()
    }

    /// VM-16: a disk's provisioned size in MB, if it is there.
    pub fn disk_size_mb(&self, path: &str) -> Option<u64> {
        locks::lock(&self.disks)
            .get(&path_key(Path::new(path)))
            .map(|(_, mb, _)| *mb)
    }

    /// Whether a file (a disk, a .vmx or another file) is there.
    pub fn has_file(&self, path: &str) -> bool {
        let key = path_key(Path::new(path));
        locks::lock(&self.files).contains_key(&key)
            || locks::lock(&self.disks).contains_key(&key)
            || locks::lock(&self.vmx_texts).contains_key(&key)
    }

    fn text_of(&self, vmx: &Path) -> Result<String> {
        let key = path_key(vmx);
        if self.gone.contains(&key) {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        }
        if let Some((_, text)) = locks::lock(&self.vmx_texts).get(&key) {
            return Ok(text.clone());
        }
        let info = self.vmx.get(&key).cloned().unwrap_or_else(|| VmxInfo {
            display_name: vmx.file_stem().map(|s| s.to_string_lossy().into_owned()),
            ..Default::default()
        });
        Ok(synthesized_vmx(&info))
    }

    /// The .vmx's text with `key` set (the fake's own edits: an upgrade).
    fn set_vmx_key(&self, vmx: &Path, key: &str, value: &str) -> Result<()> {
        let mut file = crate::adapters::vmx_file::VmxFile::from_text(&self.text_of(vmx)?);
        file.set(key, value)?;
        locks::lock(&self.vmx_texts).insert(path_key(vmx), (vmx.to_path_buf(), file.to_text()));
        Ok(())
    }

    /// VM-16: what vdiskmanager does with these arguments.
    fn vdisk(&self, args: &[String]) -> Result<String> {
        let failed = |command: &str, message: &str| CoreError::VdiskManager {
            command: command.into(),
            message: message.into(),
        };
        let path = args.last().cloned().unwrap_or_default();
        let key = path_key(Path::new(&path));
        let size_of = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .and_then(|s| s.strip_suffix("MB"))
                .and_then(|s| s.parse::<u64>().ok())
        };
        let mut disks = locks::lock(&self.disks);
        match args.first().map(String::as_str) {
            Some("-c") => {
                if disks.contains_key(&key) {
                    return Err(failed("create", "The file already exists"));
                }
                let size = size_of("-s").ok_or_else(|| failed("create", "Invalid size"))?;
                let thick = args.iter().position(|a| a == "-t").and_then(|i| args.get(i + 1)) == Some(&"2".to_owned());
                let on_disk = if thick { size * 1024 * 1024 } else { 65536 };
                disks.insert(key, (PathBuf::from(&path), size, on_disk));
                Ok("Virtual disk creation successful.".into())
            }
            Some("-x") => {
                let size = size_of("-x").ok_or_else(|| failed("expand", "Invalid size"))?;
                let disk = disks
                    .get_mut(&key)
                    .ok_or_else(|| failed("expand", "Failed to open the disk: The file was not found"))?;
                if size <= disk.1 {
                    return Err(failed("expand", "The new capacity must be larger"));
                }
                disk.1 = size;
                Ok("Disk expansion completed successfully.".into())
            }
            Some("-r") => {
                let source = args.get(1).cloned().unwrap_or_default();
                if disks.contains_key(&key) {
                    return Err(failed("convert", "The file already exists"));
                }
                // A disk the fake holds, else a file on this PC (an image, or a descriptor a test's temp folder has).
                let size = disks
                    .get(&path_key(Path::new(&source)))
                    .map(|(_, mb, _)| *mb)
                    .or_else(|| {
                        std::fs::metadata(&source)
                            .ok()
                            .map(|m| m.len().div_ceil(1024 * 1024).max(1))
                    })
                    .ok_or_else(|| failed("convert", "Failed to open the source disk: The file was not found"))?;
                disks.insert(key, (PathBuf::from(&path), size, 65536));
                if self.fails("convert") {
                    return Err(failed("convert", "Failed to convert the disk: insufficient disk space"));
                }
                Ok("Virtual disk conversion successful.".into())
            }
            Some(flag @ ("-k" | "-d")) => {
                let disk = disks.get_mut(&key).ok_or_else(|| {
                    failed(
                        if flag == "-k" { "shrink" } else { "defragment" },
                        "Failed to open the disk",
                    )
                })?;
                if flag == "-k" {
                    disk.2 /= 2;
                }
                Ok("done".into())
            }
            _ => Err(failed("?", "Unknown operation")),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }

    /// VM-01: how many vmrun processes the real adapter would have started so far.
    pub fn vmrun_runs(&self) -> usize {
        self.vmrun_runs.load(Ordering::SeqCst)
    }

    /// QL-14: the VMs whose .vmsd was read, in order (lower-case paths).
    pub fn snapshot_reads(&self) -> Vec<String> {
        locks::lock(&self.snapshot_reads).clone()
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
        self.vmrun_runs.fetch_add(1, Ordering::SeqCst);
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
        let key = path_key(folder);
        // VM-21: VMs made since (a clone, an import, a new .vmx) in a folder under it.
        let made: Vec<PathBuf> = locks::lock(&self.vmx_texts)
            .values()
            .map(|(p, _)| p.clone())
            .filter(|p| path_key(p).starts_with(&format!("{key}\\")))
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("vmx")))
            .collect();
        match self.folders.get(&key) {
            Some(listed) => {
                let mut all = listed.clone();
                all.extend(
                    made.into_iter()
                        .filter(|p| !listed.iter().any(|l| path_key(l) == path_key(p))),
                );
                Ok(all)
            }
            None if !made.is_empty() => Ok(made),
            None => Err(CoreError::InvalidInput(format!("{} is not a folder", folder.display()))),
        }
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
        if let Some((_, text)) = locks::lock(&self.vmx_texts).get(&key) {
            let mut info = crate::adapters::vmware::parse_vmx(text);
            // What VMware Tools reported stays with the VM.
            if info.guest_os_name.is_none() {
                info.guest_os_name = self.vmx.get(&key).and_then(|i| i.guest_os_name.clone());
            }
            return Ok(info);
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
        locks::lock(&self.snapshot_reads).push(key.clone());
        if self.unreadable_snapshots.contains(&key) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into());
        }
        Ok(locks::lock(&self.snapshots).get(&key).cloned().unwrap_or_default())
    }

    async fn running_since(&self, vmx: &Path) -> Result<Option<OffsetDateTime>> {
        Ok(self.started_at.get(&path_key(vmx)).copied())
    }

    async fn default_vm_folder(&self) -> Result<PathBuf> {
        Ok(self
            .default_folder
            .clone()
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\alice\Documents\Virtual Machines")))
    }

    async fn hardware(&self, vmx: &Path) -> Result<VmHardware> {
        if self.hardware_fails.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("the drive holding the VM is not there").into());
        }
        let key = path_key(vmx);
        if let Some(hardware) = self.hardware.get(&key) {
            return Ok(hardware.clone());
        }
        let text = locks::lock(&self.vmx_texts).get(&key).map(|(_, t)| t.clone());
        if let Some(text) = text {
            // VM-23: what the .vmx says, with each disk's sizes from the fake's disks.
            let (mut hardware, disks) = crate::adapters::vm_hardware::parse_vmx_hardware(&text);
            let folder = vmx.parent().unwrap_or(Path::new(""));
            let known = locks::lock(&self.disks);
            for disk in disks {
                let path = crate::vm_settings::vmware::resolve(folder, &disk.file_name);
                let found = known.get(&path_key(&path));
                hardware.disks.push(crate::adapters::vm_hardware::VirtualDisk {
                    slot: disk.slot,
                    path: path.display().to_string(),
                    format: found.map(|_| "monolithicSparse".to_owned()),
                    provisioned_bytes: found.map(|(_, mb, _)| mb * 1024 * 1024),
                    on_disk_bytes: found.map(|(_, _, bytes)| *bytes),
                    files: u32::from(found.is_some()),
                    problem: found.is_none().then(|| "the disk file is not there".to_owned()),
                    controller: disk.controller,
                    thin: found.map(|_| true),
                    ..Default::default()
                });
            }
            return Ok(hardware);
        }
        let info = self.read_vmx(vmx).await?;
        Ok(VmHardware {
            guest_os: info.guest_os,
            guest_os_name: info.guest_os_name,
            vcpus: info.num_vcpus,
            memory_mb: info.memsize_mb,
            ..VmHardware::default()
        })
    }

    async fn vmx_bytes(&self, vmx: &Path) -> Result<Vec<u8>> {
        Ok(self.text_of(vmx)?.into_bytes())
    }

    async fn backup_vmx(&self, vmx: &Path, tag: &str) -> Result<PathBuf> {
        let text = self.text_of(vmx)?;
        let copy = crate::adapters::vmware::files::backup_path(vmx, tag);
        self.record(format!("backup {}", vmx.display()));
        locks::lock(&self.backups).insert(path_key(&copy), (copy.clone(), text));
        Ok(copy)
    }

    async fn write_vmx(&self, vmx: &Path, bytes: &[u8]) -> Result<()> {
        self.record(format!("write {}", vmx.display()));
        if self.failing_vmx_write.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("There is not enough space on the disk.").into());
        }
        let text = String::from_utf8(bytes.to_vec()).map_err(|e| CoreError::InvalidInput(e.to_string()))?;
        locks::lock(&self.vmx_texts).insert(path_key(vmx), (vmx.to_path_buf(), text));
        Ok(())
    }

    async fn restore_vmx(&self, vmx: &Path, backup: &Path) -> Result<()> {
        self.record(format!("restore {}", vmx.display()));
        let text = locks::lock(&self.backups)
            .get(&path_key(backup))
            .map(|(_, t)| t.clone())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        locks::lock(&self.vmx_texts).insert(path_key(vmx), (vmx.to_path_buf(), text));
        Ok(())
    }

    async fn discard_backup(&self, backup: &Path) -> Result<()> {
        locks::lock(&self.backups).remove(&path_key(backup));
        Ok(())
    }

    async fn vdiskmanager(&self, args: Vec<std::ffi::OsString>, _timeout: Duration) -> Result<String> {
        let args: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        self.record(format!("vdiskmanager {}", args.join(" ")));
        if self.failing_vdisk.load(Ordering::SeqCst) {
            return Err(CoreError::VdiskManager {
                command: "?".into(),
                message: "Failed: insufficient disk space".into(),
            });
        }
        self.vdisk(&args)
    }

    async fn vmrun_change(&self, args: Vec<std::ffi::OsString>, _timeout: Duration) -> Result<String> {
        self.vmrun()?;
        let args: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        self.record(format!("vmrun {}", args.join(" ")));
        let vmx = PathBuf::from(args.get(1).cloned().unwrap_or_default());
        let failed = |command: &str, message: &str| CoreError::Vmrun {
            command: command.into(),
            message: message.into(),
        };
        match args.first().map(String::as_str) {
            Some("upgradevm") => {
                if self.is_running(&vmx) {
                    return Err(failed("upgradevm", "The virtual machine is powered on"));
                }
                self.set_vmx_key(&vmx, "virtualHW.version", "22")?;
            }
            Some("installTools") => {
                if !self.is_running(&vmx) {
                    return Err(failed("installTools", "The virtual machine is not powered on"));
                }
            }
            Some("connectNamedDevice" | "disconnectNamedDevice" | "writeVariable") => {
                if !self.is_running(&vmx) {
                    return Err(failed(&args[0], "The virtual machine is not powered on"));
                }
            }
            Some("clone") => {
                let target = PathBuf::from(args.get(2).cloned().unwrap_or_default());
                let linked = args.get(3).map(String::as_str) == Some("linked");
                let snapshot = args.iter().find_map(|a| a.strip_prefix("-snapshot="));
                let name = args
                    .iter()
                    .find_map(|a| a.strip_prefix("-cloneName="))
                    .unwrap_or("Clone")
                    .to_owned();
                if linked && snapshot.is_none() {
                    return Err(failed("clone", "A linked clone needs a snapshot"));
                }
                match snapshot {
                    None if self.is_running(&vmx) => {
                        return Err(failed(
                            "clone",
                            "The virtual machine must be powered off to clone it as it is now",
                        ))
                    }
                    None => {}
                    Some(path) => {
                        let tree = locks::lock(&self.snapshots)
                            .get(&path_key(&vmx))
                            .cloned()
                            .unwrap_or_default();
                        let nodes = crate::snapshots::tree_nodes(&tree, OffsetDateTime::now_utc());
                        if !nodes.iter().any(|n| n.path == path) {
                            return Err(failed("clone", "The snapshot was not found"));
                        }
                    }
                }
                if self.has_vm(&target.to_string_lossy()) {
                    return Err(failed("clone", "The destination file already exists"));
                }
                self.clone_vm(&vmx, &target, &name)?;
                if !self.clone_delay.is_zero() {
                    tokio::time::sleep(self.clone_delay).await;
                }
                if self.fails("clone") {
                    return Err(failed("clone", "Insufficient permission to access the file"));
                }
            }
            Some("deleteVM") => {
                if self.is_running(&vmx) {
                    return Err(failed("deleteVM", "The virtual machine is powered on"));
                }
                let key = path_key(&vmx);
                let folder = path_key(vmx.parent().unwrap_or(Path::new("")));
                locks::lock(&self.vmx_texts).remove(&key);
                // Workstation deletes the VM's own files in its folder; a disk outside it stays.
                let in_folder = |p: &Path| p.parent().is_some_and(|f| path_key(f) == folder);
                locks::lock(&self.disks).retain(|_, (p, _, _)| !in_folder(p));
                locks::lock(&self.files).retain(|_, (p, _)| {
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    !(in_folder(p) && (name.ends_with(".log") || name.ends_with(".vmsd") || name.ends_with(".nvram")))
                });
                locks::lock(&self.snapshots).remove(&key);
            }
            _ => return Err(failed("?", "Unknown command")),
        }
        Ok(String::new())
    }

    async fn delete_files(&self, paths: &[PathBuf]) -> Result<()> {
        for path in paths {
            if crate::untrusted::path_refusal(path).is_some() {
                return Err(CoreError::VmSettingRefused(format!(
                    "{} is not on this PC",
                    path.display()
                )));
            }
        }
        for path in paths {
            self.record(format!("delete {}", path.display()));
            let key = path_key(path);
            locks::lock(&self.disks).remove(&key);
            locks::lock(&self.files).remove(&key);
        }
        Ok(())
    }

    async fn disk_files(&self, path: &Path) -> Result<Vec<(PathBuf, u64)>> {
        locks::lock(&self.disks)
            .get(&path_key(path))
            .map(|(p, _, bytes)| vec![(p.clone(), *bytes)])
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound).into())
    }

    async fn folder_files(&self, folder: &Path) -> Result<Vec<(PathBuf, u64)>> {
        let folder = path_key(folder);
        let here = |p: &Path| p.parent().is_some_and(|f| path_key(f) == folder);
        let mut out: Vec<(PathBuf, u64)> = Vec::new();
        for (path, text) in locks::lock(&self.vmx_texts).values() {
            if here(path) {
                out.push((path.clone(), text.len() as u64));
            }
        }
        out.extend(
            locks::lock(&self.disks)
                .values()
                .filter(|(p, _, _)| here(p))
                .map(|(p, _, bytes)| (p.clone(), *bytes)),
        );
        out.extend(locks::lock(&self.files).values().filter(|(p, _)| here(p)).cloned());
        out.sort();
        Ok(out)
    }

    async fn file_exists(&self, path: &Path) -> bool {
        crate::untrusted::path_refusal(path).is_none() && self.has_file(&path.to_string_lossy())
    }

    async fn open_console(&self, vmx: &Path) -> Result<()> {
        self.vmrun()?;
        self.record(format!("console {}", vmx.display()));
        Ok(())
    }

    async fn ovftool(&self, args: Vec<std::ffi::OsString>, _timeout: Duration) -> Result<String> {
        if self.no_ovftool {
            return Err(CoreError::OvftoolNotFound);
        }
        let args: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        self.record(format!("ovftool {}", args.join(" ")));
        let failed = |message: &str| CoreError::Ovftool {
            message: message.into(),
        };
        let target = PathBuf::from(args.last().cloned().unwrap_or_default());
        let source = args
            .len()
            .checked_sub(2)
            .and_then(|i| args.get(i))
            .cloned()
            .unwrap_or_default();
        if !(self.has_file(&source) || Path::new(&source).is_file()) {
            return Err(failed(&format!("Failed to open file: {source}")));
        }
        if self.has_vm(&target.to_string_lossy()) {
            return Err(failed("The target exists already"));
        }
        let name = args
            .iter()
            .find_map(|a| a.strip_prefix("--name="))
            .unwrap_or("appliance")
            .to_owned();
        let disk_name = format!("{name}-disk1.vmdk");
        let text = format!(
            ".encoding = \"UTF-8\"\nconfig.version = \"8\"\nvirtualHW.version = \"20\"\ndisplayName = \"{}\"\nguestOS = \"ubuntu-64\"\nnumvcpus = \"1\"\nmemsize = \"1024\"\nscsi0.present = \"TRUE\"\nscsi0.virtualDev = \"pvscsi\"\nscsi0:0.present = \"TRUE\"\nscsi0:0.fileName = \"{disk_name}\"\nethernet0.present = \"TRUE\"\nethernet0.connectionType = \"nat\"\n",
            crate::adapters::vmx_file::escape_value(&name)
        );
        let disk = target.parent().unwrap_or(Path::new("")).join(&disk_name);
        locks::lock(&self.disks).insert(path_key(&disk), (disk, 10 * 1024, 65536));
        locks::lock(&self.vmx_texts).insert(path_key(&target), (target.clone(), text));
        if self.fails("ovftool") {
            return Err(failed("Failed to write the disk: insufficient disk space"));
        }
        Ok("Completed successfully".into())
    }

    fn ovftool_path(&self) -> Option<PathBuf> {
        (!self.no_ovftool).then(|| PathBuf::from(r"C:\Program Files\VMware\VMware Workstation\OVFTool\ovftool.exe"))
    }

    async fn workstation_window_open(&self) -> bool {
        self.workstation_open.load(Ordering::SeqCst)
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
        id: None,
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

pub use containers::FakeContainers;

/// VM-18: VirtualBox in memory. VMs are registered with a UUID, a name and a state; power calls
/// change the state and snapshot calls the tree the way VBoxManage would, through the same checks as
/// the real adapter ([`vbox::check_snapshot_op`]): a revert powers a running VM off first, and a
/// snapshot with two children can't be deleted. A soft stop presses the ACPI button and waits until
/// the guest is off (forever for a guest that ignores it); a graceful restart needs the Guest
/// Additions. Records every power and snapshot call as text, e.g. `power Suspend <uuid>` and
/// `snapshot take safety <uuid>`. Default: installed, with no VMs.
#[derive(Default)]
pub struct FakeVirtualBox {
    not_installed: bool,
    failing_list: AtomicBool,
    vms: Mutex<Vec<VboxVmInfo>>,
    properties: HashMap<String, HashMap<String, String>>,
    ignores_acpi: HashSet<String>,
    unreadable: HashSet<String>,
    failing_snapshots: HashSet<String>,
    power_delay: Duration,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    calls: Mutex<Vec<String>>,
    snapshot_reads: Mutex<Vec<String>>,
    /// Calls that would each start a VBoxManage process.
    vboxmanage_runs: AtomicUsize,
    /// VM-01: `list vms` takes this long (a busy VirtualBox), so refreshes overlap.
    list_delay: Duration,
    /// VM-21: VirtualBox's default machine folder and host-only adapters.
    default_folder: Option<PathBuf>,
    host_only: Option<Vec<String>>,
    /// VM-21: ISOs `unattended detect` says it can install, by path in lower case.
    unattended_isos: HashSet<String>,
    /// VM-16, VM-24: files on "this PC" (disk images, ISOs, a VM's logs), by path: (path, size).
    files: Mutex<HashMap<String, (PathBuf, u64)>>,
    /// VM-16: each disk image's provisioned size in MB, by path.
    disk_sizes: Mutex<HashMap<String, u64>>,
    /// VM-23: what each VM's .vbox file adds (TPM, shared folders' flags).
    extras: Mutex<HashMap<String, vbox::VboxSettingsExtras>>,
    /// VM-24: VMs whose .vbox `registervm` can add, by the file's path.
    registerable: Mutex<HashMap<String, VboxVmInfo>>,
    /// VM-15: VirtualBox's folder has no VBoxGuestAdditions.iso.
    no_additions_iso: bool,
    /// VM-21: operations that fail (`clonevm`, `import`, `clonemedium`, `createvm`), after leaving what they made.
    failing: Mutex<HashSet<String>>,
    /// VM-21: guest IPs by VM name, for VMs a deploy makes (their UUID is the deploy's to choose).
    ips_by_name: HashMap<String, String>,
    /// VM-21: what unattended installs were asked: (VM uuid, user). The password is read and dropped.
    unattended: Mutex<Vec<(String, String)>>,
}

/// The value after `--name` in a VBoxManage call.
fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The VBoxManage `VMState` for a power state.
fn vbox_state(state: PowerState) -> &'static str {
    match state {
        PowerState::Running => "running",
        PowerState::Paused => "paused",
        PowerState::Suspended => "saved",
        PowerState::NotRunning => "poweroff",
        PowerState::Unknown => "unknown",
    }
}

impl FakeVirtualBox {
    /// VM-21: where VirtualBox would put new VMs (by default a made-up folder under alice's profile).
    pub fn with_default_folder(mut self, folder: impl Into<PathBuf>) -> Self {
        self.default_folder = Some(folder.into());
        self
    }

    /// VM-21: an ISO VirtualBox can install by itself (`unattended detect`).
    pub fn with_unattended_iso(mut self, iso: &str) -> Self {
        self.unattended_isos.insert(iso.to_lowercase());
        self
    }

    /// VM-21: this PC's host-only adapters (by default VirtualBox's first one).
    pub fn with_host_only_adapters(mut self, names: &[&str]) -> Self {
        self.host_only = Some(names.iter().map(|n| (*n).to_owned()).collect());
        self
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// VBoxManage.exe is not on this PC.
    pub fn not_installed() -> Self {
        Self {
            not_installed: true,
            ..Default::default()
        }
    }

    /// A registered VM: 2 CPUs, 2048 MB, "Ubuntu (64-bit)", one NAT adapter, its .vbox under
    /// `C:\Users\alice\VirtualBox VMs\<name>\`, and Guest Additions running while it is on.
    pub fn with_vm(self, uuid: &str, name: &str, state: PowerState) -> Self {
        let uuid = crate::adapters::hypervisor::virtualbox_key(uuid).unwrap_or_else(|| uuid.to_owned());
        let info = VboxVmInfo {
            uuid,
            name: name.to_owned(),
            accessible: true,
            os_type: Some("Ubuntu (64-bit)".into()),
            cpus: Some(2),
            memory_mb: Some(2048),
            state: vbox_state(state).to_owned(),
            state_changed_at: Some(OffsetDateTime::now_utc()),
            config_file: Some(PathBuf::from(format!(
                r"C:\Users\alice\VirtualBox VMs\{name}\{name}.vbox"
            ))),
            disks: vec![VboxDisk {
                slot: "SATA-0-0".into(),
                path: PathBuf::from(format!(r"C:\Users\alice\VirtualBox VMs\{name}\{name}.vdi")),
            }],
            firmware: Some("BIOS".into()),
            additions_run_level: state.is_on().then_some(2),
            additions_version: state.is_on().then(|| "7.2.22 r175245".to_owned()),
            nics: vec![VboxNic {
                slot: 1,
                attachment: "nat".into(),
                mac: Some("080027000001".into()),
                model: Some("82540EM".into()),
                cable_connected: Some(true),
                network_name: None,
            }],
            snapshots: SnapshotTree::default(),
            controllers: vec![VboxController {
                name: "SATA".into(),
                kind: Some("IntelAhci".into()),
                ports: Some(2),
            }],
            dvds: vec![VboxDvd {
                slot: "SATA-1-0".into(),
                image: None,
                host_drive: None,
            }],
            audio: Some("default".into()),
            video_memory_mb: Some(16),
            graphics_controller: Some("vmsvga".into()),
            ..VboxVmInfo::default()
        };
        locks::lock(&self.vms).push(info);
        self
    }

    /// Changes what `showvminfo` says about a VM.
    pub fn with_info(self, uuid: &str, change: impl FnOnce(&mut VboxVmInfo)) -> Self {
        if let Some(vm) = locks::lock(&self.vms).iter_mut().find(|v| v.uuid == uuid) {
            change(vm);
        }
        self
    }

    /// The VM's Guest Additions don't run (no run level).
    pub fn without_guest_additions(self, uuid: &str) -> Self {
        self.with_info(uuid, |vm| {
            vm.additions_run_level = None;
            vm.additions_version = None;
        })
    }

    /// A guest property the Guest Additions set, while the VM is on.
    pub fn with_guest_property(mut self, uuid: &str, name: &str, value: &str) -> Self {
        self.properties
            .entry(uuid.to_owned())
            .or_default()
            .insert(name.to_owned(), value.to_owned());
        self
    }

    /// The guest reports one adapter with this address, and Linux as its OS.
    pub fn with_ip(self, uuid: &str, ip: &str) -> Self {
        self.with_guest_property(uuid, GUEST_NET_COUNT, "1")
            .with_guest_property(uuid, "/VirtualBox/GuestInfo/Net/0/V4/IP", ip)
            .with_guest_property(uuid, "/VirtualBox/GuestInfo/Net/0/MAC", "080027000001")
            .with_guest_property(uuid, GUEST_OS_PRODUCT, "Linux")
    }

    /// VM-03: the guest ignores the ACPI power button, so a soft stop never ends.
    pub fn ignores_acpi(mut self, uuid: &str) -> Self {
        self.ignores_acpi.insert(uuid.to_owned());
        self
    }

    /// `list vms` fails (VirtualBox busy or broken).
    pub fn failing_list(self) -> Self {
        self.set_failing_list(true);
        self
    }

    /// From now on `list vms` fails, or works again.
    pub fn set_failing_list(&self, on: bool) {
        self.failing_list.store(on, Ordering::SeqCst);
    }

    /// `showvminfo` of this VM fails.
    pub fn unreadable(mut self, uuid: &str) -> Self {
        self.unreadable.insert(uuid.to_owned());
        self
    }

    /// Every snapshot call on this VM fails (VM-05).
    pub fn failing_snapshots(mut self, uuid: &str) -> Self {
        self.failing_snapshots.insert(uuid.to_owned());
        self
    }

    /// VM-06: each power call takes this long.
    pub fn with_power_delay(mut self, delay: Duration) -> Self {
        self.power_delay = delay;
        self
    }

    /// VM-04: a snapshot taken at `at` from the VM's current one; it becomes the current one.
    pub fn with_snapshot(self, uuid: &str, name: &str, at: OffsetDateTime) -> Self {
        if let Some(vm) = locks::lock(&self.vms).iter_mut().find(|v| v.uuid == uuid) {
            take_vbox_snapshot(&mut vm.snapshots, name, at);
        }
        self
    }

    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }

    /// VM-01: how many VBoxManage processes the real adapter would have started so far.
    pub fn vboxmanage_runs(&self) -> usize {
        self.vboxmanage_runs.load(Ordering::SeqCst)
    }

    /// VM-01: `list vms` takes this long, so a second refresh can start while one runs.
    pub fn with_list_delay(mut self, delay: Duration) -> Self {
        self.list_delay = delay;
        self
    }

    /// The VMs whose snapshot tree was read, in order.
    pub fn snapshot_reads(&self) -> Vec<String> {
        locks::lock(&self.snapshot_reads).clone()
    }

    /// VM-16, VM-24: a file of `size` bytes on this PC (an ISO, a VM's log).
    pub fn with_file(self, path: &str, size: u64) -> Self {
        locks::lock(&self.files).insert(path_key(Path::new(path)), (PathBuf::from(path), size));
        self
    }

    /// VM-16: the VM's first disk image is `size_mb` and takes a tenth of that on disk; its file is there.
    pub fn with_disk_size(self, path: &str, size_mb: u64) -> Self {
        locks::lock(&self.disk_sizes).insert(path_key(Path::new(path)), size_mb);
        self.with_file(path, size_mb * 1024 * 1024 / 10)
    }

    /// VM-23: what the VM's .vbox file says that showvminfo doesn't.
    pub fn with_extras(self, uuid: &str, extras: vbox::VboxSettingsExtras) -> Self {
        locks::lock(&self.extras).insert(uuid.to_owned(), extras);
        self
    }

    /// VM-24: a .vbox at `path` that `registervm` can add: a VM like [`Self::with_vm`]'s, off.
    pub fn registerable(self, path: &str, uuid: &str, name: &str) -> Self {
        let probe = FakeVirtualBox::new().with_vm(uuid, name, PowerState::NotRunning);
        if let Some(mut info) = probe.find(uuid) {
            info.config_file = Some(PathBuf::from(path));
            locks::lock(&self.registerable).insert(path_key(Path::new(path)), info);
        }
        self.with_file(path, 4000)
    }

    /// VM-15: VirtualBox's folder has no Guest Additions ISO.
    /// VM-21: `op` (`clonevm`, `import`, `clonemedium`, `createvm`) fails from now on, after leaving what it made.
    pub fn set_failing(&self, op: &str, failing: bool) {
        let mut set = locks::lock(&self.failing);
        if failing {
            set.insert(op.to_owned());
        } else {
            set.remove(op);
        }
    }

    fn fails(&self, op: &str) -> bool {
        locks::lock(&self.failing).contains(op)
    }

    /// VM-21: once a VM named `name` runs, its Guest Additions report this IP.
    pub fn with_ip_for_name(mut self, name: &str, ip: &str) -> Self {
        self.ips_by_name.insert(name.to_owned(), ip.to_owned());
        self
    }

    /// VM-21: the VM named `name`, if one is registered.
    pub fn vm_named(&self, name: &str) -> Option<VboxVmInfo> {
        locks::lock(&self.vms).iter().find(|vm| vm.name == name).cloned()
    }

    /// VM-21: the unattended installs asked so far: (VM uuid, user).
    pub fn unattended_installs(&self) -> Vec<(String, String)> {
        locks::lock(&self.unattended).clone()
    }

    /// A file the fake holds, or (VM-21) one on this PC, such as a seed or image a test made in its temp folder.
    fn medium_exists(&self, path: &str) -> bool {
        self.has_file(path) || Path::new(path).is_file()
    }

    /// The size in MB of a disk the fake holds, else of a file on this PC.
    fn medium_mb(&self, path: &str) -> Option<u64> {
        locks::lock(&self.disk_sizes)
            .get(&path_key(Path::new(path)))
            .copied()
            .or_else(|| {
                std::fs::metadata(path)
                    .ok()
                    .map(|m| m.len().div_ceil(1024 * 1024).max(1))
            })
    }

    /// VM-21: a new disk file the fake holds.
    fn add_disk_file(&self, path: &Path, size_mb: u64) {
        locks::lock(&self.files).insert(path_key(path), (path.to_path_buf(), 2 * 1024 * 1024));
        locks::lock(&self.disk_sizes).insert(path_key(path), size_mb);
    }

    /// VM-21: `createvm`, `clonevm` and `import`: a registered VM in `<base>\<name>`.
    fn register_new(&self, uuid: &str, name: &str, base: &str, like: Option<&VboxVmInfo>) -> VboxVmInfo {
        let folder = Path::new(base).join(name);
        let config = folder.join(format!("{name}.vbox"));
        let mut info = like.cloned().unwrap_or_else(|| VboxVmInfo {
            accessible: true,
            os_type: Some("Other Linux (64-bit)".into()),
            cpus: Some(1),
            memory_mb: Some(512),
            ..VboxVmInfo::default()
        });
        info.uuid = uuid.to_owned();
        info.name = name.to_owned();
        info.state = "poweroff".into();
        info.state_changed_at = Some(OffsetDateTime::now_utc());
        info.config_file = Some(config.clone());
        info.snapshots = SnapshotTree::default();
        locks::lock(&self.files).insert(path_key(&config), (config, 4096));
        info
    }

    /// VM-21: what deploys ask VBoxManage that the settings changes don't: new VMs and copies of disks.
    fn apply_deploy(&self, args: &[String]) -> Option<Result<String>> {
        let failed = |command: &str, message: &str| Self::failed(command, message);
        let sub = args.first().map(String::as_str).unwrap_or_default();
        let done = match sub {
            "createvm" => {
                let name = option(args, "--name").unwrap_or_default().to_owned();
                let uuid = option(args, "--uuid").unwrap_or_default().to_owned();
                let base = option(args, "--basefolder").unwrap_or_default().to_owned();
                if self.find(&uuid).is_some() {
                    return Some(Err(failed("createvm", "A machine with this UUID exists already")));
                }
                let mut info = self.register_new(&uuid, &name, &base, None);
                info.os_type = option(args, "--ostype").map(str::to_owned);
                locks::lock(&self.vms).push(info);
                if self.fails("createvm") {
                    return Some(Err(failed(
                        "createvm",
                        "The machine settings file could not be written",
                    )));
                }
                Ok(format!(
                    "Virtual machine '{name}' is created and registered.\nUUID: {uuid}\n"
                ))
            }
            "clonevm" => {
                let source = args.get(1).cloned().unwrap_or_default();
                let Some(from) = self.find(&source) else {
                    return Some(Err(failed(
                        "clonevm",
                        &format!("Could not find a registered machine named '{source}'"),
                    )));
                };
                let snapshot = option(args, "--snapshot");
                let linked = args.iter().any(|a| a == "--options=Link");
                if linked && snapshot.is_none() {
                    return Some(Err(failed(
                        "clonevm",
                        "Linked clone can only be created from a snapshot",
                    )));
                }
                if let Some(snapshot) = snapshot {
                    if vbox::find_snapshot(&from.snapshots, snapshot).is_none() {
                        return Some(Err(failed(
                            "clonevm",
                            &format!("Could not find a snapshot named '{snapshot}'"),
                        )));
                    }
                } else if from.power_state().is_on() {
                    return Some(Err(failed("clonevm", "The machine is locked for a session")));
                }
                let name = option(args, "--name").unwrap_or("Clone").to_owned();
                let uuid = option(args, "--uuid").unwrap_or_default().to_owned();
                let base = option(args, "--basefolder").unwrap_or_default().to_owned();
                let mut info = self.register_new(&uuid, &name, &base, Some(&from));
                let folder = Path::new(&base).join(&name);
                info.disks = from
                    .disks
                    .iter()
                    .enumerate()
                    .map(|(i, disk)| {
                        let path = if i == 0 {
                            folder.join(format!("{name}.vdi"))
                        } else {
                            folder.join(format!("{name}-disk{}.vdi", i + 1))
                        };
                        let size = self.medium_mb(&disk.path.to_string_lossy()).unwrap_or(10 * 1024);
                        self.add_disk_file(&path, size);
                        VboxDisk {
                            slot: disk.slot.clone(),
                            path,
                        }
                    })
                    .collect();
                info.dvds.clear();
                locks::lock(&self.vms).push(info);
                if self.fails("clonevm") {
                    return Some(Err(failed("clonevm", "Clone VM failed: not enough free space")));
                }
                Ok(format!("Machine has been successfully cloned as \"{name}\"\n"))
            }
            "import" => {
                let file = args.get(1).cloned().unwrap_or_default();
                if !self.medium_exists(&file) {
                    return Some(Err(failed("import", &format!("Cannot open file '{file}'"))));
                }
                let name = option(args, "--vmname").unwrap_or("appliance").to_owned();
                let base = option(args, "--basefolder").unwrap_or_default().to_owned();
                let uuid = Uuid::new_v4().hyphenated().to_string();
                let mut info = self.register_new(&uuid, &name, &base, None);
                info.cpus = option(args, "--cpus").and_then(|c| c.parse().ok()).or(Some(1));
                info.memory_mb = option(args, "--memory").and_then(|m| m.parse().ok()).or(Some(1024));
                let disk = Path::new(&base).join(&name).join(format!("{name}-disk001.vmdk"));
                self.add_disk_file(&disk, 10 * 1024);
                info.controllers.push(VboxController {
                    name: "SATA".into(),
                    kind: Some("IntelAhci".into()),
                    ports: Some(2),
                });
                info.disks.push(VboxDisk {
                    slot: "SATA-0-0".into(),
                    path: disk,
                });
                info.nics.push(VboxNic {
                    slot: 1,
                    attachment: "nat".into(),
                    mac: Some("080027000101".into()),
                    ..VboxNic::default()
                });
                locks::lock(&self.vms).push(info);
                if self.fails("import") {
                    return Some(Err(failed("import", "Appliance import failed: not enough free space")));
                }
                Ok(format!("Successfully imported the appliance.\nVM name: {name}\n"))
            }
            "clonemedium" | "convertfromraw" => {
                let (from, to) = if sub == "clonemedium" {
                    (
                        args.get(2).cloned().unwrap_or_default(),
                        args.get(3).cloned().unwrap_or_default(),
                    )
                } else {
                    (
                        args.get(1).cloned().unwrap_or_default(),
                        args.get(2).cloned().unwrap_or_default(),
                    )
                };
                let Some(size) = self.medium_exists(&from).then(|| self.medium_mb(&from)).flatten() else {
                    return Some(Err(failed(
                        sub,
                        &format!("Could not find file for the medium '{from}'"),
                    )));
                };
                if self.has_file(&to) {
                    return Some(Err(failed(sub, "The file already exists")));
                }
                self.add_disk_file(Path::new(&to), size);
                if self.fails("clonemedium") {
                    return Some(Err(failed(sub, "Failed to clone the medium: not enough free space")));
                }
                Ok(String::new())
            }
            "unattended" => {
                let uuid = args.get(2).cloned().unwrap_or_default();
                if self.find(&uuid).is_none() {
                    return Some(Err(failed("unattended", "Could not find the machine")));
                }
                let iso = option(args, "--iso").unwrap_or_default().to_owned();
                if !self.medium_exists(&iso) {
                    return Some(Err(failed("unattended", &format!("Cannot open the ISO '{iso}'"))));
                }
                // As VBoxManage does: the password is read from the file, never taken on the command line.
                if args.iter().any(|a| a == "--password") {
                    return Some(Err(failed("unattended", "The password must come in a file")));
                }
                let file = option(args, "--password-file").unwrap_or_default().to_owned();
                match std::fs::read_to_string(&file) {
                    Ok(text) if !text.trim().is_empty() => {}
                    _ => return Some(Err(failed("unattended", "Could not read the password file"))),
                }
                let user = option(args, "--user").unwrap_or_default().to_owned();
                locks::lock(&self.unattended).push((uuid, user));
                Ok(String::new())
            }
            _ => return None,
        };
        Some(done)
    }

    pub fn without_additions_iso(mut self) -> Self {
        self.no_additions_iso = true;
        self
    }

    /// The VM as `showvminfo` would describe it now.
    pub fn info(&self, uuid: &str) -> Option<VboxVmInfo> {
        self.find(uuid)
    }

    /// Whether a file is there.
    pub fn has_file(&self, path: &str) -> bool {
        locks::lock(&self.files).contains_key(&path_key(Path::new(path)))
    }

    /// VM-16: a disk image's provisioned size in MB.
    pub fn disk_size_mb(&self, path: &str) -> Option<u64> {
        locks::lock(&self.disk_sizes).get(&path_key(Path::new(path))).copied()
    }

    /// VM-23 and on: what VBoxManage does with these arguments, as VirtualBox 7 would.
    fn apply_change(&self, args: &[String]) -> Result<String> {
        if let Some(done) = self.apply_deploy(args) {
            return done;
        }
        let failed = |command: &str, message: &str| Self::failed(command, message);
        let sub = args.first().map(String::as_str).unwrap_or_default();
        let uuid_at = match sub {
            "sharedfolder" => 2,
            "modifymedium" | "closemedium" | "createmedium" | "registervm" => usize::MAX,
            _ => 1,
        };
        let uuid = args.get(uuid_at).cloned().unwrap_or_default();
        let vm_now = || {
            self.find(&uuid)
                .ok_or_else(|| failed(sub, &format!("Could not find a registered machine named '{uuid}'")))
        };
        let locked = |info: &VboxVmInfo| {
            if info.power_state().is_on() {
                Err(failed(
                    sub,
                    &format!(
                        "The machine '{}' is already locked for a session (or being unlocked)",
                        info.name
                    ),
                ))
            } else {
                Ok(())
            }
        };
        let with_vm = |change: &mut dyn FnMut(&mut VboxVmInfo) -> Result<()>| -> Result<()> {
            let mut vms = locks::lock(&self.vms);
            let vm = vms
                .iter_mut()
                .find(|v| v.uuid == uuid)
                .ok_or_else(|| failed(sub, "The VM is gone"))?;
            change(vm)
        };
        match sub {
            "modifyvm" => {
                locked(&vm_now()?)?;
                let opts = &args[2..];
                with_vm(&mut |vm| {
                    for pair in opts.chunks(2) {
                        let (name, value) = (pair[0].as_str(), pair.get(1).map(String::as_str).unwrap_or_default());
                        let nic = |prefix: &str| name.strip_prefix(prefix).and_then(|n| n.parse::<u32>().ok());
                        match name {
                            "--cpus" => vm.cpus = value.parse().ok(),
                            "--memory" => vm.memory_mb = value.parse().ok(),
                            "--nested-hw-virt" => vm.nested_hw_virt = Some(value == "on"),
                            "--firmware" => vm.firmware = Some(value.to_ascii_uppercase()),
                            "--name" => {
                                vm.name = value.to_owned();
                            }
                            "--ostype" => vm.os_type = Some(value.to_owned()),
                            "--tpm-type" => {}
                            // VM-21: what a new VM gets that the fake doesn't show.
                            "--ioapic"
                            | "--graphicscontroller"
                            | "--vram"
                            | "--boot1"
                            | "--boot2"
                            | "--boot3"
                            | "--boot4" => {}
                            _ => {
                                let slot = |n: u32, nics: &mut Vec<VboxNic>| -> usize {
                                    if let Some(i) = nics.iter().position(|x| x.slot == n) {
                                        return i;
                                    }
                                    nics.push(VboxNic {
                                        slot: n,
                                        attachment: "none".into(),
                                        ..VboxNic::default()
                                    });
                                    nics.sort_by_key(|x| x.slot);
                                    nics.iter().position(|x| x.slot == n).unwrap_or(0)
                                };
                                if let Some(n) = nic("--nictype") {
                                    let i = slot(n, &mut vm.nics);
                                    vm.nics[i].model = Some(value.to_owned());
                                } else if let Some(n) = nic("--nic") {
                                    let i = slot(n, &mut vm.nics);
                                    vm.nics[i].attachment = value.to_owned();
                                    if vm.nics[i].mac.is_none() && value != "none" {
                                        vm.nics[i].mac = Some(format!("0800270000{n:02X}"));
                                    }
                                } else if let Some(n) = nic("--macaddress") {
                                    let i = slot(n, &mut vm.nics);
                                    vm.nics[i].mac = Some(if value == "auto" {
                                        format!("08002712{n:04X}")
                                    } else {
                                        value.to_owned()
                                    });
                                } else if let Some(n) = nic("--cableconnected") {
                                    let i = slot(n, &mut vm.nics);
                                    vm.nics[i].cable_connected = Some(value == "on");
                                } else if let Some(n) = nic("--intnet")
                                    .or_else(|| nic("--nat-network"))
                                    .or_else(|| nic("--bridgeadapter"))
                                    .or_else(|| nic("--hostonlyadapter"))
                                {
                                    let i = slot(n, &mut vm.nics);
                                    vm.nics[i].network_name = Some(value.to_owned());
                                } else {
                                    return Err(failed("modifyvm", &format!("Invalid parameter '{name}'")));
                                }
                            }
                        }
                    }
                    Ok(())
                })?;
            }
            "modifynvram" => {
                locked(&vm_now()?)?;
                let verb = args.get(2).map(String::as_str).unwrap_or_default();
                with_vm(&mut |vm| {
                    match verb {
                        "inituefivarstore" => vm.secure_boot = Some(false),
                        "enrollmssignatures" | "enrollorclpk" => {}
                        "secureboot" => {
                            if vm.secure_boot.is_none() {
                                return Err(failed(
                                    "modifynvram secureboot",
                                    "The UEFI variable store doesn't exist",
                                ));
                            }
                            vm.secure_boot = Some(args.get(3).is_some_and(|a| a == "--enable"));
                        }
                        _ => return Err(failed("modifynvram", "Unknown command")),
                    }
                    Ok(())
                })?;
            }
            "sharedfolder" => {
                let name = option(args, "--name").unwrap_or_default().to_owned();
                match args.get(1).map(String::as_str) {
                    Some("add") => {
                        let path = option(args, "--hostpath").unwrap_or_default().to_owned();
                        with_vm(&mut |vm| {
                            vm.shared_folders.push((name.clone(), PathBuf::from(&path)));
                            Ok(())
                        })?;
                    }
                    _ => with_vm(&mut |vm| {
                        let before = vm.shared_folders.len();
                        vm.shared_folders.retain(|(n, _)| *n != name);
                        if vm.shared_folders.len() == before {
                            return Err(failed("sharedfolder remove", "No such shared folder"));
                        }
                        Ok(())
                    })?,
                }
            }
            "storagectl" => {
                locked(&vm_now()?)?;
                let name = option(args, "--name").unwrap_or_default().to_owned();
                let ports = option(args, "--portcount").and_then(|p| p.parse::<u32>().ok());
                let adding = args.iter().any(|a| a == "--add");
                with_vm(&mut |vm| {
                    if adding {
                        vm.controllers.push(VboxController {
                            name: name.clone(),
                            kind: option(args, "--controller").map(str::to_owned),
                            ports,
                        });
                    } else if let Some(c) = vm.controllers.iter_mut().find(|c| c.name == name) {
                        c.ports = ports;
                    }
                    Ok(())
                })?;
            }
            "storageattach" => {
                let info = vm_now()?;
                let controller = option(args, "--storagectl").unwrap_or_default().to_owned();
                let port = option(args, "--port").unwrap_or("0");
                let device = option(args, "--device").unwrap_or("0");
                let kind = option(args, "--type").unwrap_or_default().to_owned();
                let medium = option(args, "--medium").unwrap_or_default().to_owned();
                let slot = format!("{controller}-{port}-{device}");
                if !info.controllers.iter().any(|c| c.name == controller) {
                    return Err(failed(
                        "storageattach",
                        &format!("Could not find a controller named '{controller}'"),
                    ));
                }
                // A DVD's medium changes on a running VM too; anything else needs it off.
                if kind != "dvddrive" {
                    locked(&info)?;
                } else if info.power_state().is_on() && !info.dvds.iter().any(|d| d.slot == slot) {
                    return Err(failed("storageattach", "A drive can't be added to a running VM"));
                }
                let additions = self.guest_additions_iso().map(|iso| path_key(&iso));
                let files = locks::lock(&self.files);
                let exists = |p: &str| {
                    let key = path_key(Path::new(p));
                    files.contains_key(&key) || additions.as_ref() == Some(&key) || Path::new(p).is_file()
                };
                if !matches!(medium.as_str(), "none" | "emptydrive") && !exists(&medium) {
                    return Err(failed(
                        "storageattach",
                        &format!("Could not find file for the medium '{medium}'"),
                    ));
                }
                drop(files);
                with_vm(&mut |vm| {
                    vm.disks.retain(|d| d.slot != slot);
                    if kind == "dvddrive" {
                        vm.dvds.retain(|d| d.slot != slot);
                        if medium != "none" {
                            vm.dvds.push(VboxDvd {
                                slot: slot.clone(),
                                image: (medium != "emptydrive").then(|| PathBuf::from(&medium)),
                                host_drive: None,
                            });
                        }
                    } else if medium != "none" {
                        vm.disks.push(VboxDisk {
                            slot: slot.clone(),
                            path: PathBuf::from(&medium),
                        });
                    }
                    Ok(())
                })?;
            }
            "createmedium" => {
                let file = option(args, "--filename").unwrap_or_default().to_owned();
                let size: u64 = option(args, "--size").and_then(|s| s.parse().ok()).unwrap_or(0);
                if self.has_file(&file) {
                    return Err(failed("createmedium", "The file already exists"));
                }
                let fixed = option(args, "--variant") == Some("Fixed");
                locks::lock(&self.files).insert(
                    path_key(Path::new(&file)),
                    (
                        PathBuf::from(&file),
                        if fixed { size * 1024 * 1024 } else { 2 * 1024 * 1024 },
                    ),
                );
                locks::lock(&self.disk_sizes).insert(path_key(Path::new(&file)), size);
            }
            "modifymedium" => {
                let file = args.get(2).cloned().unwrap_or_default();
                let key = path_key(Path::new(&file));
                let mut sizes = locks::lock(&self.disk_sizes);
                let size = sizes
                    .get_mut(&key)
                    .ok_or_else(|| failed("modifymedium", &format!("Could not find file for the medium '{file}'")))?;
                if let Some(new) = option(args, "--resize").and_then(|s| s.parse::<u64>().ok()) {
                    if new < *size {
                        return Err(failed("modifymedium", "Shrinking is not yet supported"));
                    }
                    *size = new;
                }
            }
            "closemedium" => {
                let file = args.get(2).cloned().unwrap_or_default();
                let key = path_key(Path::new(&file));
                let in_use = locks::lock(&self.vms)
                    .iter()
                    .any(|vm| vm.disks.iter().any(|d| path_key(&d.path) == key));
                if in_use {
                    return Err(failed("closemedium", "The medium is attached to a virtual machine"));
                }
                if args.iter().any(|a| a == "--delete") {
                    locks::lock(&self.files).remove(&key);
                    locks::lock(&self.disk_sizes).remove(&key);
                }
            }
            "controlvm" => {
                let info = vm_now()?;
                let verb = args.get(2).cloned().unwrap_or_default();
                let Some(n) = verb.strip_prefix("setlinkstate").and_then(|n| n.parse::<u32>().ok()) else {
                    return Err(failed("controlvm", "Unknown command"));
                };
                if !info.power_state().is_on() {
                    return Err(failed(
                        "controlvm",
                        &format!("Machine '{}' is not currently running", info.name),
                    ));
                }
                let on = args.get(3).is_some_and(|a| a == "on");
                with_vm(&mut |vm| {
                    if let Some(nic) = vm.nics.iter_mut().find(|x| x.slot == n) {
                        nic.cable_connected = Some(on);
                    }
                    Ok(())
                })?;
            }
            "unregistervm" => {
                let info = vm_now()?;
                locked(&info)?;
                locks::lock(&self.vms).retain(|v| v.uuid != uuid);
                if args.iter().any(|a| a == "--delete") {
                    let folder = info
                        .config_file
                        .as_ref()
                        .and_then(|f| f.parent())
                        .map(path_key)
                        .unwrap_or_default();
                    // Its disks now and those its snapshots keep, as VirtualBox deletes them.
                    let mut disks: Vec<String> = info.disks.iter().map(|d| path_key(&d.path)).collect();
                    if let Some(extras) = locks::lock(&self.extras).get(uuid.as_str()) {
                        let base = info
                            .config_file
                            .as_ref()
                            .and_then(|f| f.parent())
                            .unwrap_or(Path::new(""));
                        disks.extend(
                            extras
                                .hard_disks
                                .iter()
                                .map(|location| path_key(&crate::vm_settings::vmware::resolve(base, location))),
                        );
                    }
                    let snapshots = format!("{folder}\\snapshots");
                    locks::lock(&self.files).retain(|key, (path, _)| {
                        let own_disk = disks.contains(key);
                        let in_folder = path.parent().is_some_and(|f| {
                            let f = path_key(f);
                            f == folder || f.starts_with(&format!("{folder}\\"))
                        });
                        if path.parent().is_some_and(|f| path_key(f) == snapshots) {
                            return false;
                        }
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_lowercase())
                            .unwrap_or_default();
                        let own = name.ends_with(".vbox")
                            || name.ends_with(".vbox-prev")
                            || name.ends_with(".nvram")
                            || name.ends_with(".log");
                        !(own_disk || (in_folder && own))
                    });
                }
            }
            "registervm" => {
                let file = args.get(1).cloned().unwrap_or_default();
                let info = locks::lock(&self.registerable)
                    .get(&path_key(Path::new(&file)))
                    .cloned()
                    .ok_or_else(|| failed("registervm", &format!("Could not find file '{file}'")))?;
                if self.find(&info.uuid).is_some() {
                    return Err(failed(
                        "registervm",
                        &format!("Trying to open a VM config '{file}' which has the same UUID as an existing virtual machine"),
                    ));
                }
                locks::lock(&self.vms).push(info);
            }
            _ => return Err(failed(sub, "Unknown command")),
        }
        Ok(String::new())
    }

    pub fn power_state(&self, uuid: &str) -> PowerState {
        self.find(uuid).map_or(PowerState::Unknown, |vm| vm.power_state())
    }

    pub fn snapshot_names(&self, uuid: &str) -> Vec<String> {
        self.find(uuid)
            .map(|vm| vm.snapshots.snapshots.iter().map(|s| s.name.clone()).collect())
            .unwrap_or_default()
    }

    pub fn current_snapshot(&self, uuid: &str) -> Option<String> {
        let vm = self.find(uuid)?;
        let uid = vm.snapshots.current_uid?;
        vm.snapshots
            .snapshots
            .iter()
            .find(|s| s.uid == uid)
            .map(|s| s.name.clone())
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    /// Power calls in progress now; one the job runner gave up on no longer counts.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    fn find(&self, uuid: &str) -> Option<VboxVmInfo> {
        locks::lock(&self.vms).iter().find(|v| v.uuid == uuid).cloned()
    }

    fn installed(&self) -> Result<()> {
        self.vboxmanage_runs.fetch_add(1, Ordering::SeqCst);
        if self.not_installed {
            Err(CoreError::VboxManageNotFound)
        } else {
            Ok(())
        }
    }

    fn record(&self, call: String) {
        locks::lock(&self.calls).push(call);
    }

    fn failed(command: &str, message: &str) -> CoreError {
        CoreError::VboxManage {
            command: command.to_owned(),
            message: message.to_owned(),
        }
    }

    fn set_state(&self, uuid: &str, state: PowerState) {
        if let Some(vm) = locks::lock(&self.vms).iter_mut().find(|v| v.uuid == uuid) {
            let was_on = vm.power_state().is_on();
            vm.state = vbox_state(state).to_owned();
            if state.is_on() != was_on {
                vm.state_changed_at = Some(OffsetDateTime::now_utc());
            }
            if !state.is_on() {
                vm.additions_run_level = None;
            } else if vm.additions_version.is_some() {
                vm.additions_run_level = Some(2);
            }
        }
    }
}

#[async_trait]
impl VirtualBoxAdapter for FakeVirtualBox {
    fn tool_path(&self) -> Option<PathBuf> {
        (!self.not_installed).then(|| PathBuf::from(vbox::DEFAULT_VBOXMANAGE))
    }

    async fn list_vms(&self) -> Result<Vec<VboxListedVm>> {
        self.installed()?;
        if !self.list_delay.is_zero() {
            tokio::time::sleep(self.list_delay).await;
        }
        if self.failing_list.load(Ordering::SeqCst) {
            return Err(Self::failed("list vms", "The object is not ready"));
        }
        Ok(locks::lock(&self.vms)
            .iter()
            .map(|vm| VboxListedVm {
                name: vm.name.clone(),
                uuid: vm.uuid.clone(),
            })
            .collect())
    }

    async fn list_running(&self) -> Result<Vec<String>> {
        self.installed()?;
        Ok(locks::lock(&self.vms)
            .iter()
            .filter(|vm| vm.power_state().is_on())
            .map(|vm| vm.uuid.clone())
            .collect())
    }

    async fn vm_info(&self, uuid: &str) -> Result<VboxVmInfo> {
        self.installed()?;
        if self.unreadable.contains(uuid) {
            return Err(Self::failed("showvminfo", "The VM's settings could not be read"));
        }
        let mut info = self.find(uuid).ok_or_else(|| {
            Self::failed(
                "showvminfo",
                &format!("Could not find a registered machine named '{uuid}'"),
            )
        })?;
        // showvminfo prints no snapshot times; they are in the .vbox file.
        for snapshot in &mut info.snapshots.snapshots {
            snapshot.created_at = None;
        }
        Ok(info)
    }

    async fn guest_properties(&self, uuid: &str) -> Result<vbox::GuestProperties> {
        self.installed()?;
        let vm = self.find(uuid);
        let on = vm.as_ref().is_some_and(|vm| vm.power_state().is_on());
        if let Some(props) = self.properties.get(uuid) {
            return Ok(props.clone()).map(|p| if on { p } else { Default::default() });
        }
        // VM-21: a VM a deploy made gets its IP by name.
        let Some(ip) = vm.as_ref().and_then(|vm| self.ips_by_name.get(&vm.name)).filter(|_| on) else {
            return Ok(Default::default());
        };
        let mut props = vbox::GuestProperties::new();
        props.insert(GUEST_NET_COUNT.to_owned(), "1".to_owned());
        props.insert("/VirtualBox/GuestInfo/Net/0/V4/IP".to_owned(), ip.clone());
        props.insert(
            "/VirtualBox/GuestInfo/Net/0/MAC".to_owned(),
            vm.and_then(|vm| vm.nics.first().and_then(|n| n.mac.clone()))
                .unwrap_or_else(|| "080027000001".to_owned()),
        );
        Ok(props)
    }

    async fn power(&self, uuid: &str, op: PowerOp) -> Result<()> {
        self.installed()?;
        self.record(format!("power {op:?} {uuid}"));
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let _done = InFlight(&self.in_flight);
        if !self.power_delay.is_zero() {
            tokio::time::sleep(self.power_delay).await;
        }
        let vm = self.find(uuid).ok_or_else(|| {
            Self::failed(
                "controlvm",
                &format!("Could not find a registered machine named '{uuid}'"),
            )
        })?;
        let state = vm.power_state();
        let not_running = || Self::failed("controlvm", &format!("Machine '{}' is not currently running", vm.name));
        match op {
            // VM-21: a VM that can't start, for deploy cleanup tests.
            PowerOp::Start { .. } if self.fails("startvm") => {
                return Err(Self::failed("startvm", "VT-x is not available (VERR_VMX_NO_VMX)"))
            }
            PowerOp::Start { .. } if state.is_on() => {
                return Err(Self::failed(
                    "startvm",
                    &format!("The machine '{}' is already locked by a session", vm.name),
                ))
            }
            PowerOp::Start { .. } => self.set_state(uuid, PowerState::Running),
            _ if !state.is_on() => return Err(not_running()),
            PowerOp::Stop { mode: StopMode::Soft } => {
                if self.ignores_acpi.contains(uuid) {
                    std::future::pending::<()>().await;
                }
                self.set_state(uuid, PowerState::NotRunning);
            }
            PowerOp::Stop { mode: StopMode::Hard } => self.set_state(uuid, PowerState::NotRunning),
            PowerOp::Reset { mode: StopMode::Soft } => {
                if vm.additions_run_level.unwrap_or(0) < 1 {
                    return Err(Self::failed(
                        "controlvm reboot",
                        "The guest needs the Guest Additions to reboot",
                    ));
                }
            }
            PowerOp::Reset { mode: StopMode::Hard } => {}
            PowerOp::Suspend => self.set_state(uuid, PowerState::Suspended),
            PowerOp::Pause => self.set_state(uuid, PowerState::Paused),
            PowerOp::Unpause => self.set_state(uuid, PowerState::Running),
        }
        Ok(())
    }

    async fn snapshot(&self, uuid: &str, op: &SnapshotOp) -> Result<()> {
        self.installed()?;
        let what = match op {
            SnapshotOp::Take { name } if is_safety_name(name) => "take safety".to_owned(),
            SnapshotOp::Take { name } => format!("take {name}"),
            SnapshotOp::Revert { name } => format!("restore {name}"),
            SnapshotOp::Delete { name } => format!("delete {name}"),
        };
        self.record(format!("snapshot {what} {uuid}"));
        if self.failing_snapshots.contains(uuid) {
            return Err(Self::failed("snapshot", "Not enough free space"));
        }
        let info = self.vm_info(uuid).await?;
        vbox::check_snapshot_op(&info, op)?;
        if matches!(op, SnapshotOp::Revert { .. }) && info.power_state().is_on() {
            self.record(format!("power poweroff before restore {uuid}"));
            self.set_state(uuid, PowerState::NotRunning);
        }
        let mut vms = locks::lock(&self.vms);
        let Some(vm) = vms.iter_mut().find(|v| v.uuid == uuid) else {
            return Err(Self::failed("snapshot", "The VM is gone"));
        };
        let tree = &mut vm.snapshots;
        match op {
            SnapshotOp::Take { name } => take_vbox_snapshot(tree, name, OffsetDateTime::now_utc()),
            SnapshotOp::Revert { name } => {
                let uid = vbox::find_snapshot(tree, name).map(|s| s.uid);
                tree.current_uid = uid;
            }
            SnapshotOp::Delete { name } => {
                let Some((uid, parent)) = vbox::find_snapshot(tree, name).map(|s| (s.uid, s.parent_uid)) else {
                    return Err(Self::failed("snapshot delete", "No such snapshot"));
                };
                if tree.snapshots.iter().filter(|s| s.parent_uid == Some(uid)).count() > 1 {
                    return Err(Self::failed(
                        "snapshot delete",
                        &format!("Snapshot '{name}' has more than one child snapshot"),
                    ));
                }
                tree.snapshots.retain(|s| s.uid != uid);
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

    async fn snapshots(&self, uuid: &str) -> Result<SnapshotTree> {
        self.installed()?;
        locks::lock(&self.snapshot_reads).push(uuid.to_owned());
        if self.unreadable.contains(uuid) {
            return Err(Self::failed("showvminfo", "The VM's settings could not be read"));
        }
        Ok(self.find(uuid).map(|vm| vm.snapshots).unwrap_or_default())
    }

    async fn default_machine_folder(&self) -> Result<PathBuf> {
        self.installed()?;
        Ok(self
            .default_folder
            .clone()
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\alice\VirtualBox VMs")))
    }

    async fn unattended_detect(&self, iso: &Path) -> Result<(bool, Option<String>)> {
        self.installed()?;
        let supported = self.unattended_isos.contains(&iso.display().to_string().to_lowercase());
        Ok((supported, supported.then(|| "Ubuntu24_LTS_64".to_owned())))
    }

    async fn host_adapters(&self, bridged: bool) -> Result<Vec<String>> {
        self.installed()?;
        Ok(if bridged {
            vec!["Ethernet".to_owned()]
        } else {
            self.host_only
                .clone()
                .unwrap_or_else(|| vec!["VirtualBox Host-Only Ethernet Adapter".to_owned()])
        })
    }

    /// MO-13, VM-23: as VirtualBox's own reader, with each disk's size from memory (no disk file is opened).
    async fn hardware(&self, uuid: &str) -> Result<VmHardware> {
        let info = self.vm_info(uuid).await?;
        let props = self.guest_properties(uuid).await.unwrap_or_default();
        let mut stripped = info.clone();
        stripped.disks.clear();
        let (os_name, kernel) = vbox::guest_os_and_kernel(&props);
        let mut hardware = crate::adapters::vm_hardware::read_virtualbox(&stripped, os_name, kernel).await;
        {
            let sizes = locks::lock(&self.disk_sizes);
            let files = locks::lock(&self.files);
            for disk in &info.disks {
                let key = path_key(&disk.path);
                let controller = disk
                    .slot
                    .rsplitn(3, '-')
                    .nth(2)
                    .and_then(|name| info.controllers.iter().find(|c| c.name == name))
                    .and_then(|c| c.kind.clone());
                let there = files.contains_key(&key);
                hardware.disks.push(crate::adapters::vm_hardware::VirtualDisk {
                    slot: disk.slot.clone(),
                    path: disk.path.display().to_string(),
                    format: there.then(|| "VDI (dynamic)".into()),
                    provisioned_bytes: sizes.get(&key).map(|mb| mb * 1024 * 1024),
                    on_disk_bytes: files.get(&key).map(|(_, size)| *size),
                    files: u32::from(there),
                    controller,
                    thin: there.then_some(true),
                    problem: (!there).then(|| "the disk file is not there".to_owned()),
                    ..Default::default()
                });
            }
        }
        let extras = self.settings_extras(&info).await;
        crate::adapters::vm_hardware::add_virtualbox_extras(&mut hardware, extras.as_ref(), vbox::guest_ips(&props));
        Ok(hardware)
    }

    async fn settings_extras(&self, info: &VboxVmInfo) -> Option<vbox::VboxSettingsExtras> {
        locks::lock(&self.extras).get(&info.uuid).cloned()
    }

    async fn change(&self, args: Vec<String>, _timeout: Duration) -> Result<String> {
        self.installed()?;
        self.record(format!("change {}", args.join(" ")));
        self.apply_change(&args)
    }

    async fn os_types(&self) -> Result<Vec<vbox::VboxOsType>> {
        self.installed()?;
        Ok([
            ("Ubuntu_64", "Ubuntu (64-bit)"),
            ("Debian_64", "Debian (64-bit)"),
            ("Windows11_64", "Windows 11 (64-bit)"),
        ]
        .into_iter()
        .map(|(id, description)| vbox::VboxOsType {
            id: id.into(),
            description: description.into(),
            family: None,
        })
        .collect())
    }

    async fn screenshot(&self, uuid: &str) -> Result<Vec<u8>> {
        self.installed()?;
        self.record(format!("screenshot {uuid}"));
        if !self.power_state(uuid).is_on() {
            return Err(Self::failed(
                "controlvm screenshotpng",
                "Machine is not currently running",
            ));
        }
        Ok(b"\x89PNG\r\n\x1a\nfake".to_vec())
    }

    async fn open_console(&self, uuid: &str) -> Result<()> {
        self.installed()?;
        self.record(format!("console {uuid}"));
        Ok(())
    }

    fn guest_additions_iso(&self) -> Option<PathBuf> {
        (!self.no_additions_iso && !self.not_installed)
            .then(|| PathBuf::from(r"C:\Program Files\Oracle\VirtualBox\VBoxGuestAdditions.iso"))
    }

    async fn file_exists(&self, path: &Path) -> bool {
        let key = path_key(path);
        crate::untrusted::path_refusal(path).is_none()
            && (self.has_file(&path.to_string_lossy())
                || self.guest_additions_iso().is_some_and(|iso| path_key(&iso) == key))
    }

    async fn folder_files(&self, folder: &Path) -> Result<Vec<(PathBuf, u64)>> {
        let folder = path_key(folder);
        let mut out: Vec<(PathBuf, u64)> = locks::lock(&self.files)
            .values()
            .filter(|(p, _)| p.parent().is_some_and(|f| path_key(f) == folder))
            .cloned()
            .collect();
        out.sort();
        Ok(out)
    }
}

/// Adds a snapshot from the current one, with a new UUID, and makes it current.
fn take_vbox_snapshot(tree: &mut SnapshotTree, name: &str, at: OffsetDateTime) {
    let uid = tree.snapshots.iter().map(|s| s.uid).max().unwrap_or(0) + 1;
    tree.snapshots.push(SnapshotInfo {
        uid,
        parent_uid: tree.current_uid,
        name: name.to_owned(),
        description: None,
        created_at: Some(at),
        id: Some(Uuid::new_v4().hyphenated().to_string()),
    });
    tree.current_uid = Some(uid);
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
    /// SS-08: the files every terminal on this fake reaches.
    files: FakeFiles,
}

impl FakeRemote {
    /// SS-08: the files its terminals transfer to and from (shared: changes show in `files()`).
    pub fn with_files(mut self, files: FakeFiles) -> Self {
        self.files = files;
        self
    }

    pub fn files(&self) -> FakeFiles {
        self.files.clone()
    }

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
            peer_ip: None,
        })
    }

    async fn open_shell(&self, request: ShellRequest<'_>, _: &mut dyn Prompter) -> Result<ShellHandle> {
        // SS-07: a shell through jump hosts is recorded with them, e.g. `db01.test: shell via bastion`.
        let via: Vec<&str> = request.session.jumps().iter().map(|j| j.name.as_str()).collect();
        let via = match via.as_slice() {
            [] => String::new(),
            names => format!(" via {}", names.join(", ")),
        };
        locks::lock(&self.calls).push(format!("{}: shell{via}", request.session.host));
        Ok(loopback_shell_with(self.files.clone(), None))
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
            peer_ip: None,
        })
    }

    async fn run_sudo(&self, script: &str, password: &SecretString, max_output: usize) -> Result<ExecResult> {
        if self.is_closed() {
            return Err(CoreError::Ssh("the connection was lost: the connection was cut".into()));
        }
        locks::lock(&self.calls).push(format!("{}: {script} [sudo]", self.host));
        Ok(ExecResult {
            exit_code: Some(self.exit_code),
            signal: None,
            output: OutputCollector::collect(self.stdout.as_bytes(), b"", &[password], max_output),
            duration_ms: 1,
            peer_ip: None,
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
    loopback_shell_with(FakeFiles::default(), None)
}

/// [`loopback_shell`] with these files (SS-08) and what the shell probe says it is.
pub fn loopback_shell_with(files: FakeFiles, shell: Option<PromptShell>) -> ShellHandle {
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
    let (hostname_tx, hostname_rx) = tokio::sync::oneshot::channel();
    let _ = hostname_tx.send(None);
    let (shell_tx, shell_rx) = tokio::sync::oneshot::channel();
    let _ = shell_tx.send(shell);
    ShellHandle {
        input: input_tx,
        output: output_rx,
        peer_ip: None,
        hostname: hostname_rx,
        shell: shell_rx,
        files: std::sync::Arc::new(files),
        forwards: std::sync::Arc::new(DirectForwards),
        commands: None,
    }
}

/// SS-07 port forwards for terminals on [`FakeRemote`]: local and SOCKS forwards listen on this PC
/// like the real ones, and each connection goes straight to its destination from this PC, as if the
/// host had opened it. A fake host can't listen, so remote forwards fail.
pub struct DirectForwards;

struct DirectOpener;

#[async_trait]
impl Opener for DirectOpener {
    async fn open(
        &self,
        host: &str,
        port: u16,
        _from: std::net::SocketAddr,
    ) -> std::result::Result<Box<dyn Duplex>, String> {
        let stream = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|err| err.to_string())?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl RemoteForwards for DirectForwards {
    async fn start(&self, spec: &ForwardSpec) -> Result<RunningForward> {
        match spec.kind {
            ForwardKind::Remote => Err(CoreError::Tunnel(
                "the fake host can't listen for remote forwards".into(),
            )),
            ForwardKind::Local | ForwardKind::Dynamic => {
                forward::listen_here(spec, std::sync::Arc::new(DirectOpener)).await
            }
        }
    }
}

/// SS-08: a host's files in memory, for terminals on [`FakeRemote`]: folders and files by absolute
/// path, folders the user can't write to (`/etc`, `/root` and `/usr` unless more are added), and a
/// pause per chunk or a failure part way through, so tests can watch progress, cancel and retry.
/// Clones share the same files.
#[derive(Clone)]
pub struct FakeFiles {
    inner: std::sync::Arc<Mutex<FakeFs>>,
}

struct FakeFs {
    user: String,
    home: String,
    dirs: HashSet<String>,
    files: HashMap<String, Vec<u8>>,
    protected: Vec<String>,
    /// Each read and write waits this long.
    delay: Duration,
    /// The next write fails once this many bytes of it went through.
    fail_after: Option<u64>,
    /// H8: the host renames over a file in one step (OpenSSH's posix-rename); without it a replaced
    /// file is kept as a `.bak`.
    atomic_rename: bool,
    /// For temporary file names.
    next_temp: u64,
}

impl Default for FakeFiles {
    fn default() -> Self {
        let dirs = ["/", "/home", "/home/alice", "/tmp", "/etc", "/root", "/usr", "/srv"]
            .into_iter()
            .map(String::from)
            .collect();
        Self {
            inner: std::sync::Arc::new(Mutex::new(FakeFs {
                user: "alice".into(),
                home: "/home/alice".into(),
                dirs,
                files: HashMap::new(),
                protected: vec!["/etc".into(), "/root".into(), "/usr".into()],
                delay: Duration::ZERO,
                fail_after: None,
                atomic_rename: true,
                next_temp: 1,
            })),
        }
    }
}

/// `/a/b` for `/a/b/c`; `/` for `/a`.
fn fake_parent(path: &str) -> String {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/".to_owned(),
        Some((parent, _)) => parent.to_owned(),
    }
}

impl FakeFiles {
    pub fn with_dir(self, path: &str) -> Self {
        locks::lock(&self.inner).dirs.insert(path.to_owned());
        self
    }

    pub fn with_file(self, path: &str, content: &[u8]) -> Self {
        self.set_file(path, content);
        self
    }

    pub fn set_file(&self, path: &str, content: &[u8]) {
        locks::lock(&self.inner).files.insert(path.to_owned(), content.to_vec());
    }

    /// Writes into this folder (and below) are refused, like a folder the user may not write to.
    pub fn protect(self, folder: &str) -> Self {
        locks::lock(&self.inner).protected.push(folder.to_owned());
        self
    }

    /// Each read and write of a chunk waits this long, so a transfer takes a while.
    pub fn with_delay(self, delay: Duration) -> Self {
        locks::lock(&self.inner).delay = delay;
        self
    }

    /// The next write fails after this many bytes, as if the connection dropped; later ones work.
    pub fn fail_next_write_after(&self, bytes: u64) {
        locks::lock(&self.inner).fail_after = Some(bytes);
    }

    /// H8: like a server without posix-rename: a replaced file is renamed to a `.bak` first.
    pub fn without_atomic_rename(self) -> Self {
        locks::lock(&self.inner).atomic_rename = false;
        self
    }

    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        locks::lock(&self.inner).files.get(path).cloned()
    }

    /// Every file's path, sorted: to see nothing temporary was left.
    pub fn paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = locks::lock(&self.inner).files.keys().cloned().collect();
        paths.sort();
        paths
    }

    fn entry(fs: &FakeFs, path: &str) -> Option<RemoteEntry> {
        let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or(path).to_owned();
        if fs.dirs.contains(path) {
            return Some(RemoteEntry {
                name,
                kind: EntryKind::Folder,
                link: false,
                size: 4096,
                modified: Some(1_700_000_000),
                mode: Some(0o755),
            });
        }
        fs.files.get(path).map(|content| RemoteEntry {
            name,
            kind: EntryKind::File,
            link: false,
            size: content.len() as u64,
            modified: Some(1_700_000_000),
            mode: Some(0o644),
        })
    }
}

#[async_trait]
impl RemoteFiles for FakeFiles {
    fn user(&self) -> String {
        locks::lock(&self.inner).user.clone()
    }

    async fn home(&self) -> Result<String> {
        Ok(locks::lock(&self.inner).home.clone())
    }

    async fn list(&self, folder: &str) -> Result<RemoteListing> {
        let fs = locks::lock(&self.inner);
        if !fs.dirs.contains(folder) {
            return Err(CoreError::RemoteNotFound {
                path: folder.to_owned(),
            });
        }
        let inside = |path: &&String| fake_parent(path) == folder && path.as_str() != folder;
        let mut paths: Vec<&String> = fs
            .dirs
            .iter()
            .filter(inside)
            .chain(fs.files.keys().filter(inside))
            .collect();
        paths.sort();
        let more = paths.len() > crate::adapters::remote::MAX_LISTING;
        paths.truncate(crate::adapters::remote::MAX_LISTING);
        Ok(RemoteListing {
            entries: paths.into_iter().filter_map(|path| Self::entry(&fs, path)).collect(),
            more,
        })
    }

    async fn stat(&self, path: &str) -> Result<Option<RemoteEntry>> {
        Ok(Self::entry(&locks::lock(&self.inner), path))
    }

    async fn read(&self, path: &str) -> Result<Box<dyn RemoteRead>> {
        let (content, delay) = {
            let fs = locks::lock(&self.inner);
            let content = fs
                .files
                .get(path)
                .cloned()
                .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })?;
            (content, fs.delay)
        };
        Ok(Box::new(FakeRead { content, at: 0, delay }))
    }

    async fn write(&self, path: &str, replace: bool) -> Result<Box<dyn RemoteWrite>> {
        let opened = {
            let mut fs = locks::lock(&self.inner);
            let folder = fake_parent(path);
            if fs
                .protected
                .iter()
                .any(|p| folder == *p || folder.starts_with(&format!("{p}/")))
            {
                return Err(CoreError::RemotePermissionDenied {
                    user: fs.user.clone(),
                    what: "write to",
                    path: path.to_owned(),
                    advice: "",
                });
            }
            if !fs.dirs.contains(&folder) {
                return Err(CoreError::RemoteNotFound { path: folder });
            }
            let there = fs.files.contains_key(path);
            if there && !replace {
                return Err(CoreError::RemoteFileExists { path: path.to_owned() });
            }
            // H8: a replacement goes to a temporary file beside the old one.
            let target = (there && replace).then(|| path.to_owned());
            let written_to = if target.is_some() {
                let name = path.rsplit('/').next().unwrap_or(path);
                let temp = format!("{folder}/.{name}.remotely-{}.part", fs.next_temp).replace("//", "/");
                fs.next_temp += 1;
                temp
            } else {
                path.to_owned()
            };
            fs.files.insert(written_to.clone(), Vec::new());
            (written_to, target, fs.fail_after.take())
        };
        let (path, target, fail_after) = opened;
        Ok(Box::new(FakeWrite {
            files: self.clone(),
            path,
            target,
            written: 0,
            fail_after,
            settled: false,
        }))
    }

    async fn remove(&self, path: &str) -> Result<()> {
        locks::lock(&self.inner)
            .files
            .remove(path)
            .map(drop)
            .ok_or_else(|| CoreError::RemoteNotFound { path: path.to_owned() })
    }
}

struct FakeRead {
    content: Vec<u8>,
    at: usize,
    delay: Duration,
}

#[async_trait]
impl RemoteRead for FakeRead {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let n = buf.len().min(self.content.len() - self.at);
        buf[..n].copy_from_slice(&self.content[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

struct FakeWrite {
    files: FakeFiles,
    /// What is written to: the file itself, or a replacement's temporary file.
    path: String,
    /// H8: the file a replacement takes the place of.
    target: Option<String>,
    written: u64,
    fail_after: Option<u64>,
    /// Finished or aborted; until then dropping it deletes what it made.
    settled: bool,
}

impl Drop for FakeWrite {
    fn drop(&mut self) {
        if !self.settled {
            locks::lock(&self.files.inner).files.remove(&self.path);
        }
    }
}

#[async_trait]
impl RemoteWrite for FakeWrite {
    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let delay = locks::lock(&self.files.inner).delay;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if self
            .fail_after
            .is_some_and(|limit| self.written + data.len() as u64 > limit)
        {
            return Err(CoreError::Ssh("the connection was lost: the connection was cut".into()));
        }
        self.written += data.len() as u64;
        locks::lock(&self.files.inner)
            .files
            .entry(self.path.clone())
            .or_default()
            .extend_from_slice(data);
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<Written> {
        self.settled = true;
        let Some(target) = self.target.clone() else {
            return Ok(Written::Created);
        };
        let mut fs = locks::lock(&self.files.inner);
        let content = fs.files.remove(&self.path).unwrap_or_default();
        if fs.atomic_rename {
            fs.files.insert(target, content);
            return Ok(Written::Replaced);
        }
        let backup = format!("{target}.20261025-120000.bak");
        if let Some(old) = fs.files.remove(&target) {
            fs.files.insert(backup.clone(), old);
        }
        fs.files.insert(target, content);
        Ok(Written::ReplacedKeepingBackup { backup })
    }

    async fn abort(mut self: Box<Self>) -> String {
        self.settled = true;
        locks::lock(&self.files.inner).files.remove(&self.path);
        match &self.target {
            Some(target) => format!("{target} on the host is as it was"),
            None => "nothing was left on the host".to_owned(),
        }
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

    async fn turn_off_windows_login(&self) -> Result<bool> {
        Ok(false)
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
    /// MO-15: this PC's paging files; `None` reads as not available.
    pub paging: Option<crate::adapters::paging::PagingInfo>,
    pub free_disk_pct: f64,
    pub unavailable: bool,
    /// SS-07: other users signed in to this PC.
    pub other_users: usize,
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
            paging: Some(crate::adapters::paging::PagingInfo::new(
                vec![crate::adapters::paging::PagingFile {
                    path: r"C:\pagefile.sys".into(),
                    total_bytes: 4 << 30,
                    used_bytes: 1 << 30,
                    peak_bytes: 2 << 30,
                }],
                12 << 30,
                36 << 30,
            )),
            free_disk_pct: 50.0,
            unavailable: false,
            other_users: 0,
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

    async fn other_users_signed_in(&self) -> Result<usize> {
        self.available()?;
        Ok(self.other_users)
    }

    async fn paging(&self) -> Result<crate::adapters::paging::PagingInfo> {
        self.available()?;
        self.paging.clone().ok_or(CoreError::NotImplemented("paging files"))
    }
}

/// An update server that offers at most one version. Records the versions installed and the calls
/// it got. Its releases are public by default: it answers calls without a token, and takes any token.
/// With [`FakeUpdater::accepting`] it takes one token only and refuses any other the way GitHub
/// refuses a revoked one. [`FakeUpdater::set_private`] hides the releases from calls without a token
/// (GitHub's 404 for a private repository), and [`FakeUpdater::rate_limit_anonymous`] refuses those
/// calls the way GitHub does once its limit for them is used up.
#[derive(Default)]
pub struct FakeUpdater {
    offered: Option<UpdateInfo>,
    token: Option<String>,
    expires_on: Option<String>,
    /// Revoked (or expired) on GitHub: every token is refused.
    revoked: AtomicBool,
    /// Calls without a token see no releases.
    private: AtomicBool,
    /// Calls without a token are refused until this time (RFC 3339).
    anonymous_limit: Mutex<Option<String>>,
    installed: Mutex<Vec<String>>,
    calls: AtomicUsize,
    anonymous_calls: AtomicUsize,
    /// QL-15: the download never ends (a connection that stalls).
    stalls: bool,
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

    /// QL-15: installing never gets past the download, like a connection that stalls.
    pub fn stalling(mut self) -> Self {
        self.stalls = true;
        self
    }

    /// From now on GitHub answers 401, as it does for a revoked or expired token.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    /// The repository is private (again), or public.
    pub fn set_private(&self, private: bool) {
        self.private.store(private, Ordering::SeqCst);
    }

    /// Calls without a token are refused until `until` (RFC 3339), or answered again with `None`.
    pub fn rate_limit_anonymous(&self, until: Option<&str>) {
        *locks::lock(&self.anonymous_limit) = until.map(str::to_owned);
    }

    pub fn installed(&self) -> Vec<String> {
        locks::lock(&self.installed).clone()
    }

    /// Calls that reached it (checks, installs and tests), i.e. would have gone to GitHub.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Of [`Self::calls`], those made without a token.
    pub fn anonymous_calls(&self) -> usize {
        self.anonymous_calls.load(Ordering::SeqCst)
    }

    fn authorize(&self, token: Option<&SecretString>) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Some(token) = token else {
            self.anonymous_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(until) = locks::lock(&self.anonymous_limit).clone() {
                return Err(CoreError::UpdateRateLimited {
                    until,
                    with_token: false,
                });
            }
            return match self.private.load(Ordering::SeqCst) {
                true => Err(CoreError::UpdateTokenNeeded {
                    repo: "alice/remotely".into(),
                }),
                false => Ok(()),
            };
        };
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
    async fn check(&self, token: Option<&SecretString>) -> Result<ReleaseCheck> {
        self.authorize(token)?;
        Ok(ReleaseCheck {
            update: self.offered.clone(),
            // GitHub sends the expiry only with answers to a token.
            token_expires_on: token.and(self.expires_on.clone()),
        })
    }

    async fn install(&self, token: Option<&SecretString>, version: &str) -> Result<()> {
        self.authorize(token)?;
        if self.stalls {
            std::future::pending::<()>().await;
        }
        locks::lock(&self.installed).push(version.to_owned());
        Ok(())
    }

    async fn test_token(&self, token: &SecretString) -> Result<TokenReport> {
        self.authorize(Some(token))?;
        Ok(TokenReport {
            repository: "alice/remotely".into(),
            latest_release: self.offered.as_ref().map(|u| format!("v{}", u.version)),
            expires_on: self.expires_on.clone(),
        })
    }
}

/// DNS and reachability without the network (QL-01, QL-03, QL-04): names and addresses the test
/// sets, and ports that answer or not. No DNS server is asked: names not in its table do not resolve.
/// Records every lookup and probe.
#[derive(Default)]
pub struct FakeNetwork {
    forward: Mutex<HashMap<String, Vec<std::net::IpAddr>>>,
    reverse: Mutex<HashMap<std::net::IpAddr, String>>,
    open_ports: Mutex<HashSet<(String, u16)>>,
    lookup_delay: Option<Duration>,
    /// QL-01: names whose lookup takes this long (others answer at once).
    slow_names: HashMap<String, Duration>,
    probe_delay: Mutex<Option<Duration>>,
    lookups: Mutex<Vec<String>>,
    calls: Mutex<Vec<String>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl FakeNetwork {
    /// `host` resolves to `ip` (added to what it resolves to already), and `ip` back to `host`.
    pub fn with_name(self, host: &str, ip: &str) -> Self {
        let ip: std::net::IpAddr = ip
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        locks::lock(&self.forward)
            .entry(host.to_ascii_lowercase())
            .or_default()
            .push(ip);
        locks::lock(&self.reverse).insert(ip, host.to_owned());
        self
    }

    /// `name` resolves to `ips` (any letter case); reverse DNS is left as it is.
    pub fn with_addresses(self, name: &str, ips: &[&str]) -> Self {
        self.set_addresses(name, ips);
        self
    }

    /// Changes what `name` resolves to, or makes it unresolvable with no `ips`.
    pub fn set_addresses(&self, name: &str, ips: &[&str]) {
        let parsed = ips.iter().filter_map(|ip| ip.parse().ok()).collect();
        locks::lock(&self.forward).insert(name.to_ascii_lowercase(), parsed);
    }

    /// Every DNS lookup (forward or reverse) waits this long first, like a DNS server that does not
    /// answer.
    pub fn with_lookup_delay(mut self, delay: Duration) -> Self {
        self.lookup_delay = Some(delay);
        self
    }

    /// A lookup of `name` (any letter case) waits this long first; other names answer as usual.
    pub fn with_slow_name(mut self, name: &str, delay: Duration) -> Self {
        self.slow_names.insert(name.to_ascii_lowercase(), delay);
        self
    }

    /// A probe of `host:port` succeeds (or, with `false`, fails again).
    pub fn set_open(&self, host: &str, port: u16, open: bool) {
        let key = (host.to_lowercase(), port);
        let mut ports = locks::lock(&self.open_ports);
        if open {
            ports.insert(key);
        } else {
            ports.remove(&key);
        }
    }

    pub fn with_open_port(self, host: &str, port: u16) -> Self {
        self.set_open(host, port, true);
        self
    }

    /// Every probe takes this long.
    pub fn with_probe_delay(self, delay: Duration) -> Self {
        *locks::lock(&self.probe_delay) = Some(delay);
        self
    }

    /// The hosts forward lookups were asked for, in order.
    pub fn lookups(&self) -> Vec<String> {
        locks::lock(&self.lookups).clone()
    }

    /// `resolve <host>`, `reverse <ip>` and `probe <host>:<port>`, in order.
    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.calls).clone()
    }

    /// The most probes that ran at the same time.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    async fn wait_for_dns(&self) {
        if let Some(delay) = self.lookup_delay {
            tokio::time::sleep(delay).await;
        }
    }
}

#[async_trait]
impl NetworkAdapter for FakeNetwork {
    async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>> {
        locks::lock(&self.calls).push(format!("resolve {host}"));
        locks::lock(&self.lookups).push(host.to_owned());
        if let Some(ip) = ip_literal(host) {
            return Ok(vec![ip]);
        }
        self.wait_for_dns().await;
        if let Some(delay) = self.slow_names.get(&host.to_ascii_lowercase()) {
            tokio::time::sleep(*delay).await;
        }
        let found = locks::lock(&self.forward).get(&host.to_ascii_lowercase()).cloned();
        match found {
            Some(ips) if !ips.is_empty() => Ok(ips),
            _ => Err(CoreError::Network(format!("{host} could not be found"))),
        }
    }

    async fn reverse(&self, ip: std::net::IpAddr) -> Option<String> {
        locks::lock(&self.calls).push(format!("reverse {ip}"));
        self.wait_for_dns().await;
        locks::lock(&self.reverse).get(&ip).cloned()
    }

    async fn probe(&self, host: &str, port: u16, _timeout: Duration) -> Result<Duration> {
        locks::lock(&self.calls).push(format!("probe {host}:{port}"));
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let _done = InFlight(&self.in_flight);
        let delay = *locks::lock(&self.probe_delay);
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if locks::lock(&self.open_ports).contains(&(host.to_lowercase(), port)) {
            Ok(Duration::from_millis(1))
        } else {
            Err(CoreError::Network("the port is closed (connection refused)".into()))
        }
    }
}
