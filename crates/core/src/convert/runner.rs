//! CV-01 to CV-03, VM-17: the job's work ([`ConvertActions`]): a conversion (CV-03) or an export (VM-17, CV-02),
//! and the disk conversions a deploy runs for an import (CV-01, [`Converter::convert_into`]).
//!
//! * The source is only read. Each output is new: the job refuses a file that is there, writes into a work folder
//!   of its own beside the output (`.remotely-<job>`) and moves the finished files into place; an export makes its
//!   own folder (`<folder>\<vm>-<target>`), which must not be there. A failure or a cancel (the running tool is
//!   killed) removes what the job made, and only that.
//! * Free space is checked before anything is written: the outputs at their worst (a thin image as large as the
//!   data in its source, a thick one at its full size), steps in between included.
//! * VirtualBox's `clonemedium` registers its source and its target in VirtualBox's media list (hand check, 7.2):
//!   the job closes (`closemedium`, the file stays) every medium it registered that way, never one that was
//!   registered before (a VirtualBox VM's own disk).

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::args;
use super::formats::{flat_extent, size_text, DiskFormat, OutputKind, MIB};
use super::inspect::{inspect, ImageInfo};
use super::plan::{self, Source, Step};
use super::spec::{ConvertSpec, ExportSpec, ExportTarget};
use super::targets::{self, ExportedDisk, ExportedVm};
use crate::adapters::disk_tools::{DiskTools, Tool, ToolOutput, ToolPaths, ToolRun};
use crate::adapters::host_counters::HostCounters;
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vmware::path_key;
use crate::adapters::vmx_file::VmxFile;
use crate::domain::{Context, PowerState};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::save_guard::{self, Saved};

/// A disk image's conversion takes long; the job's cancel stops it sooner.
const LONG: Duration = Duration::from_secs(6 * 60 * 60);
/// Listing and closing VirtualBox's media.
const SHORT: Duration = Duration::from_secs(2 * 60);

/// The job's progress: overall percent (0 to 100) and what it is doing, in words.
pub type ProgressFn<'a> = dyn Fn(f64, &str) + Send + Sync + 'a;

/// What the job runner calls for a [`crate::command_bus::Command::ImageConvert`] or
/// [`crate::command_bus::Command::VmExport`].
#[async_trait]
pub trait ConvertActions: Send + Sync {
    /// Converts the spec's source into its new image. Returns the job's note (what was made, with which tools).
    async fn convert(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &ConvertSpec,
        progress: &ProgressFn<'_>,
        token: &CancellationToken,
    ) -> Result<String>;

    /// Exports the spec's VM into its new folder. Returns the job's note.
    async fn export(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &ExportSpec,
        progress: &ProgressFn<'_>,
        token: &CancellationToken,
    ) -> Result<String>;
}

/// How the runner waits; tests shorten it.
#[derive(Debug, Clone, Copy)]
pub struct ConvertTuning {
    /// A file a killed tool still holds is removed this often...
    pub cleanup_tries: u32,
    /// ...this long apart.
    pub cleanup_pause: Duration,
}

impl Default for ConvertTuning {
    fn default() -> Self {
        Self {
            cleanup_tries: 5,
            cleanup_pause: Duration::from_secs(1),
        }
    }
}

fn refused(message: impl Into<String>) -> CoreError {
    CoreError::ConversionRefused(message.into())
}

/// The space a plan's outputs may take at worst: each step's output (steps in between are kept until the next
/// step has read them), a thin one as large as the data in the source, a thick one at its full size.
pub fn estimate(info: &ImageInfo, steps: &[Step]) -> u64 {
    let full = info.virtual_bytes.or(info.on_disk_bytes).unwrap_or(0);
    let data = info.on_disk_bytes.unwrap_or(full).min(full.max(1));
    steps
        .iter()
        .map(|step| {
            let full = step.grow_to.unwrap_or(full).max(full);
            if step.to.thin() {
                data
            } else {
                full
            }
        })
        .sum()
}

/// Azure's whole megabytes: the size to grow to, when the disk isn't one.
pub fn whole_megabytes(info: &ImageInfo) -> Option<u64> {
    let bytes = info.virtual_bytes?;
    (bytes % MIB != 0).then(|| bytes.div_ceil(MIB) * MIB)
}

/// The source as the planner sees it: a Workstation delta's chain or one of VirtualBox's own disks.
pub fn source_of(info: &ImageInfo, vbox_medium: bool) -> Source {
    Source {
        format: info.format,
        chain: info.has_parent(),
        vbox_medium,
    }
}

/// `.remotely-<first 8 of the job id>`.
fn work_name(job_id: Uuid) -> String {
    format!(".remotely-{}", &job_id.simple().to_string()[..8])
}

/// The conversion runner the job runner calls (`JobRunner::set_converter`), and the deploy runner for imports.
pub struct Converter {
    hypervisors: Hypervisors,
    tools: Arc<dyn DiskTools>,
    host: Arc<dyn HostCounters>,
    tuning: RwLock<ConvertTuning>,
}

impl Converter {
    pub fn new(hypervisors: Hypervisors, tools: Arc<dyn DiskTools>, host: Arc<dyn HostCounters>) -> Self {
        Self {
            hypervisors,
            tools,
            host,
            tuning: RwLock::new(ConvertTuning::default()),
        }
    }

    pub fn set_tuning(&self, tuning: ConvertTuning) {
        *locks::write(&self.tuning) = tuning;
    }

    pub fn disk_tools(&self) -> &Arc<dyn DiskTools> {
        &self.tools
    }

    /// Where each conversion tool is now: Workstation's and VirtualBox's from their adapters (Settings' paths),
    /// qemu-img from its own.
    pub fn tool_paths(&self) -> ToolPaths {
        let vmware = self.hypervisors.vmware();
        ToolPaths {
            qemu_img: self.tools.qemu_img(),
            vdiskmanager: vmware.vdiskmanager_path(),
            vboxmanage: self.hypervisors.virtualbox().tool_path(),
            ovftool: vmware.ovftool_path(),
        }
    }

    /// A VM's virtual hardware and disks (MO-13's reader). A read.
    pub async fn hardware(&self, key: &str) -> Result<crate::adapters::vm_hardware::VmHardware> {
        self.hypervisors.hardware(key).await
    }

    /// Free space on the drive `folder` is on, when it can be read.
    pub async fn free_bytes(&self, folder: &Path) -> Option<u64> {
        self.host.disk_space(folder).await.ok().map(|d| d.free_bytes)
    }

    async fn check_space(&self, folder: &Path, needed: u64) -> Result<()> {
        if let Some(free) = self.free_bytes(folder).await {
            if free < needed {
                return Err(refused(format!(
                    "{} may need up to {}, and its drive has {} free. Free some space or choose another drive.",
                    folder.display(),
                    size_text(needed),
                    size_text(free)
                )));
            }
        }
        Ok(())
    }

    async fn run_tool(
        &self,
        tools: &ToolPaths,
        tool: Tool,
        args: Vec<std::ffi::OsString>,
        timeout: Duration,
        progress: &(dyn Fn(f64) + Send + Sync),
    ) -> Result<ToolOutput> {
        let program = tools.get(tool).ok_or(match tool {
            Tool::QemuImg => CoreError::QemuImgNotFound,
            Tool::VdiskManager => CoreError::VdiskManagerNotFound,
            Tool::VBoxManage => CoreError::VboxManageNotFound,
            Tool::Ovftool => CoreError::OvftoolNotFound,
        })?;
        self.tools
            .run(ToolRun::new(tool, program, args, timeout, progress))
            .await
    }

    async fn vbox(
        &self,
        tools: &ToolPaths,
        args: Vec<String>,
        timeout: Duration,
        progress: &(dyn Fn(f64) + Send + Sync),
    ) -> Result<ToolOutput> {
        let args = args.into_iter().map(std::ffi::OsString::from).collect();
        self.run_tool(tools, Tool::VBoxManage, args, timeout, progress).await
    }

    /// VirtualBox's media list now (each medium's location).
    async fn vbox_media(&self, tools: &ToolPaths) -> Result<Vec<String>> {
        let listed = self.vbox(tools, args::vbox_list_hdds(), SHORT, &|_| {}).await?;
        Ok(args::parse_hdd_locations(&listed.text))
    }

    /// Closes the media VirtualBox registered during the job: listed now, not `before`, and the job's own (in one
    /// of `folders`, or one of `files`). Failures are logged: the file is the job's to delete either way.
    async fn release_media(&self, tools: &ToolPaths, before: &[String], folders: &[&Path], files: &[&Path]) {
        let Ok(now) = self.vbox_media(tools).await else {
            return;
        };
        let known: Vec<String> = before.iter().map(|b| path_key(Path::new(b))).collect();
        let folders: Vec<String> = folders
            .iter()
            .map(|f| format!("{}\\", path_key(f).trim_end_matches('\\')))
            .collect();
        let files: Vec<String> = files.iter().map(|f| path_key(f)).collect();
        for location in now {
            let key = path_key(Path::new(&location));
            let ours = files.contains(&key) || folders.iter().any(|f| key.starts_with(f.as_str()));
            if ours && !known.contains(&key) {
                if let Err(err) = self
                    .vbox(tools, args::vbox_close(Path::new(&location)), SHORT, &|_| {})
                    .await
                {
                    tracing::warn!(error = %err, "conversion: VirtualBox kept a medium it registered");
                }
            }
        }
    }

    /// Deletes a folder the job made, trying again while a killed tool still holds a file in it.
    async fn remove_dir(&self, folder: &Path) -> Option<String> {
        let tuning = *locks::read(&self.tuning);
        let mut last = None;
        for attempt in 0..tuning.cleanup_tries.max(1) {
            match tokio::fs::remove_dir_all(folder).await {
                Ok(()) => return None,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
                Err(err) => last = Some(err.to_string()),
            }
            if attempt + 1 < tuning.cleanup_tries {
                tokio::time::sleep(tuning.cleanup_pause).await;
            }
        }
        last.map(|err| format!("{} ({err}): delete it by hand", folder.display()))
    }

    /// Grows the image a step reads (one the job made, in its work folder) to `bytes`.
    async fn grow(&self, tools: &ToolPaths, path: &Path, format: DiskFormat, bytes: u64) -> Result<()> {
        match format {
            DiskFormat::Vdi => self
                .vbox(tools, args::vbox_resize(path, bytes), LONG, &|_| {})
                .await
                .map(drop),
            DiskFormat::Qcow2 => self
                .run_tool(
                    tools,
                    Tool::QemuImg,
                    args::qemu_resize(path, format, bytes),
                    LONG,
                    &|_| {},
                )
                .await
                .map(drop),
            other => Err(refused(format!(
                "Remotely doesn't grow a {} on the way.",
                other.label()
            ))),
        }
    }

    /// One step: `input` (of the step's format) into `output` (of its kind).
    async fn step(
        &self,
        tools: &ToolPaths,
        step: &Step,
        input: &Path,
        output: &Path,
        work: &Path,
        progress: &(dyn Fn(f64) + Send + Sync),
    ) -> Result<()> {
        if let Some(bytes) = step.grow_to {
            self.grow(tools, input, step.from, bytes).await?;
        }
        match step.tool {
            Tool::QemuImg => {
                let args = args::qemu_convert(input, step.from, output, step.to);
                self.run_tool(tools, Tool::QemuImg, args, LONG, progress)
                    .await
                    .map(drop)
            }
            Tool::VBoxManage => {
                let args = args::vbox_convert(input, step.from, output, step.to)
                    .ok_or_else(|| refused(format!("VBoxManage doesn't write {}.", step.to.label())))?;
                self.vbox(tools, args, LONG, progress).await.map(drop)
            }
            Tool::VdiskManager => {
                let descriptor;
                let source = if step.from == DiskFormat::Raw {
                    // vdiskmanager reads a raw disk through a flat-extent descriptor that names it.
                    let bytes = tokio::fs::metadata(input).await?.len();
                    descriptor = work.join(format!("raw-{}.vmdk", Uuid::new_v4().simple()));
                    tokio::fs::write(&descriptor, crate::deploy::workstation::raw_descriptor(input, bytes)).await?;
                    descriptor.as_path()
                } else {
                    input
                };
                if step.to == OutputKind::Raw {
                    // A preallocated VMDK's extent is the raw disk.
                    let flat = work.join(format!("flat-{}.vmdk", Uuid::new_v4().simple()));
                    let args = args::vdisk_convert(source, &flat, OutputKind::VmdkFlat)
                        .ok_or_else(|| refused("vmware-vdiskmanager doesn't write that."))?;
                    self.run_tool(tools, Tool::VdiskManager, args, LONG, progress).await?;
                    tokio::fs::rename(flat_extent(&flat), output).await?;
                    let _ = tokio::fs::remove_file(&flat).await;
                } else {
                    let args = args::vdisk_convert(source, output, step.to)
                        .ok_or_else(|| refused(format!("vmware-vdiskmanager doesn't write {}.", step.to.label())))?;
                    self.run_tool(tools, Tool::VdiskManager, args, LONG, progress).await?;
                }
                if source != input {
                    let _ = tokio::fs::remove_file(source).await;
                }
                Ok(())
            }
            Tool::Ovftool => Err(refused("ovftool exports whole VMs only.")),
        }
    }

    /// Runs a plan: `source` into `target`, steps in between written in `work` and deleted once read. `report`
    /// gets the plan's progress, 0 to 100.
    pub async fn run_steps(
        &self,
        tools: &ToolPaths,
        source: &Path,
        steps: &[Step],
        target: &Path,
        work: &Path,
        report: &(dyn Fn(f64, &str) + Send + Sync),
    ) -> Result<()> {
        let count = steps.len().max(1) as f64;
        let mut input = source.to_path_buf();
        for (i, step) in steps.iter().enumerate() {
            let last = i + 1 == steps.len();
            let output = if last {
                target.to_path_buf()
            } else {
                work.join(format!("step-{}.{}", i + 1, step.to.extension()))
            };
            let what = format!("{} ({} to {})", step.tool.label(), step.from.label(), step.to.label());
            let shown = |p: f64| report((i as f64 + p / 100.0) / count * 100.0, &what);
            shown(0.0);
            self.step(tools, step, &input, &output, work, &shown).await?;
            if i > 0 {
                // A step in between is the job's own; the source never is.
                for file in step_files(steps[i - 1].to, &input) {
                    let _ = tokio::fs::remove_file(file).await;
                }
            }
            input = output;
        }
        Ok(())
    }

    /// CV-01: one disk of an import converted into a new VM's folder (`target`, which must not be there), the
    /// hypervisors' tools first; VirtualBox's media list is left as it was. `work` is a folder the caller made and
    /// deletes. Returns the plan it ran.
    pub async fn convert_into(
        &self,
        source: &Path,
        info: &ImageInfo,
        out: OutputKind,
        target: &Path,
        work: &Path,
        token: &CancellationToken,
    ) -> Result<Vec<Step>> {
        let tools = self.tool_paths();
        let steps = plan::plan(source_of(info, false), out, None, &tools)
            .map_err(|why| refused(why.describe(info.format, out)))?;
        let before = self.media_before(&tools, &steps).await?;
        let ran = tokio::select! {
            biased;
            _ = token.cancelled() => Err(CoreError::Cancelled),
            ran = self.run_steps(&tools, source, &steps, target, work, &|_, _| {}) => ran,
        };
        if let Some(before) = &before {
            // The new VM's disk stays registered once it is attached; the source and the steps in between don't.
            self.release_media(&tools, before, &[work], &[source]).await;
        }
        ran.map(|()| steps)
    }

    /// VirtualBox's media list before a plan that runs VBoxManage, so the job can close what it registers.
    async fn media_before(&self, tools: &ToolPaths, steps: &[Step]) -> Result<Option<Vec<String>>> {
        let uses_vbox = steps
            .iter()
            .any(|s| s.tool == Tool::VBoxManage || (s.grow_to.is_some() && s.from == DiskFormat::Vdi));
        if !uses_vbox {
            return Ok(None);
        }
        Ok(Some(self.vbox_media(tools).await?))
    }

    /// VM-17: refuses a VM that isn't powered off, or that Workstation holds.
    pub async fn require_off(&self, key: &str) -> Result<()> {
        let power = match Hypervisor::of_key(key) {
            Hypervisor::Vmware => {
                let vmware = self.hypervisors.vmware();
                let vmx = Path::new(key);
                let running = vmware.list_running().await?;
                if running.iter().any(|p| path_key(p) == path_key(vmx)) {
                    PowerState::Running
                } else if vmware.read_vmx(vmx).await?.suspended {
                    PowerState::Suspended
                } else {
                    let file = VmxFile::parse(&vmware.vmx_bytes(vmx).await?)?;
                    if let Some(lock) = crate::vm_settings::workstation_lock(vmware.as_ref(), vmx, &file).await {
                        return Err(refused(format!(
                            "Workstation is using the VM: its lock {} is there. Close the VM's tab in Workstation and try again.",
                            lock.display()
                        )));
                    }
                    PowerState::NotRunning
                }
            }
            Hypervisor::VirtualBox => self.hypervisors.virtualbox().vm_info(key).await?.power_state(),
        };
        match power {
            PowerState::NotRunning => Ok(()),
            PowerState::Suspended => Err(refused(
                "The VM is suspended: an export takes a VM that is shut down. Start it and shut it down first.",
            )),
            PowerState::Running | PowerState::Paused => Err(refused(
                "The VM is running: an export takes a VM that is shut down. Shut it down first.",
            )),
            PowerState::Unknown => Err(refused(
                "Remotely could not tell whether the VM is running, so it wasn't exported.",
            )),
        }
    }

    /// VM-17, CV-02: plans each disk of the VM for the export: (disk, its source info, steps, file name).
    pub async fn export_plan(&self, spec: &ExportSpec, tools: &ToolPaths) -> Result<Vec<DiskExport>> {
        let Some(kind) = spec.disk_kind else {
            return Ok(Vec::new());
        };
        let hardware = self.hypervisors.hardware(&spec.vm_key).await?;
        if hardware.disks.is_empty() {
            return Err(refused("The VM has no virtual disk to export."));
        }
        let vbox = spec.hypervisor == Hypervisor::VirtualBox;
        let count = hardware.disks.len();
        let mut out = Vec::new();
        for (i, disk) in hardware.disks.iter().enumerate() {
            let path = PathBuf::from(&disk.path);
            let mut info = inspect(&path)
                .await
                .map_err(|err| refused(format!("Disk {}: {err}", i + 1)))?;
            if vbox && info.has_parent() {
                // VirtualBox's own differencing image: VBoxManage reads its whole chain.
                info.problems.retain(|p| !p.contains("differencing"));
                if info.virtual_bytes.is_none() {
                    info.virtual_bytes = disk.provisioned_bytes;
                }
            }
            if let Some(problem) = info.problems.first() {
                return Err(refused(format!("Disk {} ({}): {problem}.", i + 1, disk.path)));
            }
            let grow = if spec.target == ExportTarget::Azure {
                whole_megabytes(&info)
            } else {
                None
            };
            let steps = plan::plan(source_of(&info, vbox), kind, grow, tools)
                .map_err(|why| refused(format!("Disk {}: {}.", i + 1, why.describe(info.format, kind))))?;
            out.push(DiskExport {
                file: targets::disk_file(&spec.vm_name, i, count, kind),
                virtual_bytes: grow.or(info.virtual_bytes).unwrap_or(0),
                source: path,
                info,
                steps,
            });
        }
        Ok(out)
    }

    /// VM-17: the appliance's tool and arguments, for the VM's hypervisor.
    fn appliance_run(spec: &ExportSpec, file: &Path) -> (Tool, Vec<std::ffi::OsString>) {
        match (spec.hypervisor, spec.target) {
            (Hypervisor::VirtualBox, ExportTarget::Appliance { version, .. }) => (
                Tool::VBoxManage,
                args::vbox_export(&spec.vm_key, file, version)
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            _ => (Tool::Ovftool, args::ovftool_export(Path::new(&spec.vm_key), file)),
        }
    }

    async fn export_into(
        &self,
        spec: &ExportSpec,
        folder: &Path,
        tools: &ToolPaths,
        progress: &ProgressFn<'_>,
    ) -> Result<String> {
        let hardware = self.hypervisors.hardware(&spec.vm_key).await?;
        let vm = ExportedVm::from_hardware(&spec.vm_name, spec.hypervisor, &hardware);
        let today = crate::catalog::today();
        let made_on = format!("{}-{:02}-{:02}", today.year(), u8::from(today.month()), today.day());
        let mut extra = Vec::new();
        let mut written = Vec::new();
        if let ExportTarget::Appliance { ova, .. } = spec.target {
            let data: u64 = hardware.disks.iter().filter_map(|d| d.on_disk_bytes).sum();
            self.check_space(folder, data).await?;
            let file = folder.join(format!(
                "{}.{}",
                targets::slug(&spec.vm_name),
                if ova { "ova" } else { "ovf" }
            ));
            let (tool, args) = Self::appliance_run(spec, &file);
            let what = format!("{} (the whole VM)", tool.label());
            self.run_tool(tools, tool, args, LONG, &|p| progress(p, &what)).await?;
            let mut names: Vec<String> = Vec::new();
            let mut entries = tokio::fs::read_dir(folder).await?;
            while let Some(entry) = entries.next_entry().await? {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
            names.sort();
            extra = names;
        } else {
            let disks = self.export_plan(spec, tools).await?;
            let needed: u64 = disks.iter().map(|d| estimate(&d.info, &d.steps)).sum();
            self.check_space(folder, needed).await?;
            let work = folder.join(".work");
            tokio::fs::create_dir(&work).await?;
            let count = disks.len() as f64;
            for (i, disk) in disks.iter().enumerate() {
                let target = folder.join(&disk.file);
                let label = |p: f64, what: &str| {
                    progress(
                        (i as f64 + p / 100.0) / count * 100.0,
                        &format!("disk {} of {}: {what}", i + 1, disks.len()),
                    )
                };
                self.run_steps(tools, &disk.source, &disk.steps, &target, &work, &label)
                    .await?;
                written.push(ExportedDisk {
                    file: disk.file.clone(),
                    kind: disk.steps.last().map_or(OutputKind::Raw, |s| s.to),
                    virtual_bytes: disk.virtual_bytes,
                });
            }
            let _ = tokio::fs::remove_dir_all(&work).await;
            match spec.target {
                ExportTarget::Kvm => {
                    let name = format!("{}.xml", targets::slug(&spec.vm_name));
                    tokio::fs::write(folder.join(&name), targets::libvirt_xml(&vm, &written)).await?;
                    extra.push(name);
                }
                ExportTarget::Proxmox => {
                    let name = "import-to-proxmox.sh".to_owned();
                    // LF line ends: the script runs on Linux.
                    tokio::fs::write(folder.join(&name), targets::proxmox_script(&vm, &written)).await?;
                    extra.push(name);
                }
                _ => {}
            }
        }
        tokio::fs::write(
            folder.join("README.md"),
            targets::readme(spec.target, &vm, &written, &extra, &made_on),
        )
        .await?;
        // Every file (a flat VMDK is two).
        let mut files = 0usize;
        let mut entries = tokio::fs::read_dir(folder).await?;
        while entries.next_entry().await?.is_some() {
            files += 1;
        }
        Ok(format!(
            "exported to {} ({files} files, README.md says how to import it)",
            folder.display()
        ))
    }
}

/// One disk of an export, as planned.
#[derive(Debug, Clone)]
pub struct DiskExport {
    pub source: PathBuf,
    pub info: ImageInfo,
    pub steps: Vec<Step>,
    /// Its file name in the export's folder.
    pub file: String,
    pub virtual_bytes: u64,
}

/// The files an output of `kind` at `path` is.
fn step_files(kind: OutputKind, path: &Path) -> Vec<PathBuf> {
    kind.files(path)
}

#[async_trait]
impl ConvertActions for Converter {
    async fn convert(
        &self,
        _ctx: &Context,
        job_id: Uuid,
        spec: &ConvertSpec,
        progress: &ProgressFn<'_>,
        token: &CancellationToken,
    ) -> Result<String> {
        spec.validate()?;
        let source = Path::new(&spec.source);
        let output = Path::new(&spec.output);
        let info = inspect(source).await?;
        if info.format != spec.source_format {
            return Err(refused(format!(
                "{} is a {} now, not the {} it was when the conversion was asked.",
                spec.source,
                info.format.label(),
                spec.source_format.label()
            )));
        }
        if let Some(problem) = info.problems.first() {
            return Err(refused(format!("{}: {problem}.", spec.source)));
        }
        let tools = self.tool_paths();
        let grow = if spec.whole_megabytes {
            whole_megabytes(&info)
        } else {
            None
        };
        let steps = plan::plan(source_of(&info, false), spec.kind, grow, &tools)
            .map_err(|why| refused(why.describe(info.format, spec.kind)))?;
        let folder = output
            .parent()
            .filter(|f| f.is_dir())
            .ok_or_else(|| refused(format!("The folder of {} is not there.", spec.output)))?;
        save_guard::refuse_repository(output, Saved::Image)?;
        for file in spec.kind.files(output) {
            if tokio::fs::symlink_metadata(&file).await.is_ok() {
                return Err(refused(format!(
                    "{} is there already: a conversion never replaces a file. Choose another name.",
                    file.display()
                )));
            }
        }
        self.check_space(folder, estimate(&info, &steps)).await?;
        let work = folder.join(work_name(job_id));
        tokio::fs::create_dir(&work).await?;
        let staged = work.join(output.file_name().unwrap_or_default());
        let before = match self.media_before(&tools, &steps).await {
            Ok(before) => before,
            Err(err) => {
                let _ = self.remove_dir(&work).await;
                return Err(err);
            }
        };
        let ran = tokio::select! {
            biased;
            _ = token.cancelled() => Err(CoreError::Cancelled),
            ran = self.run_steps(&tools, source, &steps, &staged, &work, progress) => ran,
        };
        if let Some(before) = &before {
            self.release_media(&tools, before, &[&work], &[source]).await;
        }
        let moved = match ran {
            Ok(()) => {
                let mut moved = Ok(());
                for (from, to) in spec.kind.files(&staged).iter().zip(spec.kind.files(output)) {
                    if let Err(err) = tokio::fs::rename(from, &to).await {
                        moved = Err(CoreError::from(err));
                        break;
                    }
                }
                moved
            }
            Err(err) => Err(err),
        };
        let left = self.remove_dir(&work).await;
        if let Err(err) = moved {
            // A file moved before a later one failed is the job's too.
            if !matches!(err, CoreError::Cancelled) {
                for file in spec.kind.files(output) {
                    let _ = tokio::fs::remove_file(file).await;
                }
            }
            return Err(match left {
                Some(left) if !matches!(err, CoreError::Cancelled) => {
                    refused(format!("{err}; what it made was removed but for {left}"))
                }
                _ => err,
            });
        }
        let made = inspect(output)
            .await
            .map(|i| format!("{}, {} on disk", i.describe(), size_text(i.on_disk_bytes.unwrap_or(0))))
            .unwrap_or_else(|_| spec.kind.label().to_owned());
        Ok(format!(
            "made {} ({made}) from {} with {}",
            spec.output,
            info.describe(),
            plan::describe(&steps)
        ))
    }

    async fn export(
        &self,
        _ctx: &Context,
        _job_id: Uuid,
        spec: &ExportSpec,
        progress: &ProgressFn<'_>,
        token: &CancellationToken,
    ) -> Result<String> {
        spec.validate()?;
        self.require_off(&spec.vm_key).await?;
        let parent = Path::new(&spec.folder);
        if !parent.is_dir() {
            return Err(refused(format!("{} is not there.", spec.folder)));
        }
        save_guard::refuse_repository_folder(parent, Saved::Export)?;
        let tools = self.tool_paths();
        let folder = spec.out_folder();
        match tokio::fs::create_dir(&folder).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(refused(format!(
                    "{} is there already, and an export makes its folder itself. Choose another place or name.",
                    folder.display()
                )))
            }
            Err(err) => return Err(err.into()),
        }
        let before = if tools.has(Tool::VBoxManage) {
            self.vbox_media(&tools).await.ok()
        } else {
            None
        };
        // A Workstation VM's disks that VBoxManage reads get registered too (hand check): they are closed after.
        let sources: Vec<PathBuf> = self
            .hypervisors
            .hardware(&spec.vm_key)
            .await
            .map(|h| h.disks.iter().map(|d| PathBuf::from(&d.path)).collect())
            .unwrap_or_default();
        let ran = tokio::select! {
            biased;
            _ = token.cancelled() => Err(CoreError::Cancelled),
            ran = self.export_into(spec, &folder, &tools, progress) => ran,
        };
        if let Some(before) = &before {
            let files: Vec<&Path> = sources.iter().map(PathBuf::as_path).collect();
            self.release_media(&tools, before, &[&folder], &files).await;
        }
        match ran {
            Ok(note) => Ok(note),
            Err(err) => {
                let left = self.remove_dir(&folder).await;
                Err(match left {
                    Some(left) if !matches!(err, CoreError::Cancelled) => {
                        refused(format!("{err}; what it made was removed but for {left}"))
                    }
                    _ => err,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(virtual_bytes: u64, on_disk: u64) -> ImageInfo {
        ImageInfo {
            path: "a".into(),
            format: DiskFormat::Raw,
            subformat: None,
            thin: Some(false),
            virtual_bytes: Some(virtual_bytes),
            on_disk_bytes: Some(on_disk),
            extents: Vec::new(),
            parent: None,
            chain: Vec::new(),
            encrypted: false,
            partition_table: None,
            problems: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn space_is_estimated_at_the_worst_and_megabytes_rounded_up() {
        let step = |to, grow_to| Step {
            tool: Tool::QemuImg,
            from: DiskFormat::Raw,
            to,
            grow_to,
        };
        let i = info(20 << 30, 2 << 30);
        assert_eq!(estimate(&i, &[step(OutputKind::Qcow2, None)]), 2 << 30);
        assert_eq!(estimate(&i, &[step(OutputKind::VhdFixed, None)]), 20 << 30);
        assert_eq!(
            estimate(
                &i,
                &[
                    step(OutputKind::Qcow2, None),
                    step(OutputKind::VhdFixed, Some(21 << 30))
                ]
            ),
            (2 << 30) + (21 << 30)
        );
        assert_eq!(whole_megabytes(&info(20 << 30, 0)), None);
        assert_eq!(whole_megabytes(&info((20 << 30) + 512, 0)), Some((20 << 30) + MIB));
        assert_eq!(
            work_name(Uuid::from_u128(0xabcdef12_0000_0000_0000_000000000000)),
            ".remotely-abcdef12"
        );
    }
}
