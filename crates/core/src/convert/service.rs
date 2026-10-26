//! The conversion service (`Core.convert`): what the Image tools page, a VM's Export and Settings call.
//!
//! Reads (no bus, no audit): which tools are here, Inspect, what each output would take (its tools, its plan, why
//! it can't be made), an export's plan, and Verify. Changes go to the bus: [`Command::ImageConvert`] and
//! [`Command::VmExport`], built here from the file the user picked and the place the shell's dialog chose (the
//! UI never sends one), each checked here first (refused paths, a file that is there, a Git working tree, free
//! space, the tools) and again by the job.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};
use uuid::Uuid;

use super::args::OvfVersion;
use super::formats::{DiskFormat, OutputKind};
use super::inspect::{inspect, ImageInfo};
use super::plan::{self, NoPlan, Step};
use super::runner::{estimate, source_of, whole_megabytes, Converter};
use super::spec::{ConvertSpec, ExportSpec, ExportTarget};
use super::targets::slug;
use super::verify::{self, VerifyProgress, VerifyReport};
use crate::adapters::disk_tools::{Tool, ToolPaths};
use crate::adapters::hypervisor::Hypervisor;
use crate::command_bus::{Command, CommandBus, SubmitOutcome};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::save_guard::{self, Saved};
use crate::store::Store;

/// QEMU's official download page for Windows, the one link Remotely opens for it (QEMU's Windows builds are linked
/// from there). Remotely never downloads or ships qemu-img itself: it is GPL-licensed.
pub const QEMU_DOWNLOAD: &str = "https://www.qemu.org/download/#windows";
const QEMU_HOST: &str = "www.qemu.org";

/// `url` when it is QEMU's download page: https on www.qemu.org, its `/download/` page, the usual port, no user
/// name or password. Anything else is refused.
pub fn checked_qemu_site(url: &str) -> Result<Url> {
    let refused = || CoreError::InvalidInput("Remotely opens only QEMU's own download page.".into());
    let parsed = Url::parse(url.trim()).map_err(|_| refused())?;
    let host_ok = matches!(parsed.host(), Some(Host::Domain(host)) if host == QEMU_HOST);
    if parsed.scheme() != "https"
        || !host_ok
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/download/"
    {
        return Err(refused());
    }
    Ok(parsed)
}

/// Which conversion tools this PC has, for Image tools and Settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsReport {
    pub paths: ToolPaths,
    /// The qemu-img.exe path saved in Settings, if any.
    pub qemu_img_saved: Option<String>,
    /// The formats only qemu-img reads and writes.
    pub qemu_img_formats: Vec<DiskFormat>,
    pub download_page: &'static str,
}

/// One output a source can be converted into, or why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputOption {
    pub kind: OutputKind,
    pub label: &'static str,
    pub extension: &'static str,
    pub steps: Vec<Step>,
    /// The plan in words ("qemu-img (qcow2 to VMDK...)").
    pub plan: String,
    /// Why it can't be made here; `None` when it can.
    pub reason: Option<String>,
    /// It could be made with qemu-img, which isn't installed.
    pub needs_qemu_img: bool,
    /// The space it may take at worst, steps in between included.
    pub estimate_bytes: u64,
}

/// What Convert shows for a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvertOptions {
    pub info: ImageInfo,
    pub outputs: Vec<OutputOption>,
    /// Free space on the source's drive (where the new image goes by default).
    pub free_bytes: Option<u64>,
    /// Its virtual size isn't a whole number of megabytes (Azure rounds it up).
    pub rounds_to_megabytes: bool,
}

/// One disk of an export as planned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportDiskView {
    pub source: String,
    pub file: String,
    pub source_format: DiskFormat,
    pub virtual_bytes: u64,
    pub plan: String,
}

/// One export target for a VM, or why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOption {
    pub target: ExportTarget,
    pub label: &'static str,
    pub disks: Vec<ExportDiskView>,
    /// The hypervisor's own export of the whole VM (OVA/OVF), by `tool`.
    pub tool: Option<Tool>,
    pub reason: Option<String>,
    pub needs_qemu_img: bool,
    pub estimate_bytes: u64,
    /// The folder the export makes: `<vm>-<target>`.
    pub folder_name: String,
}

/// What a VM's Export shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOptions {
    pub vm_key: String,
    pub vm_name: String,
    pub hypervisor: Hypervisor,
    /// Why the VM can't be exported now (running, suspended, held by Workstation); `None` when it can.
    pub refusal: Option<String>,
    pub targets: Vec<ExportOption>,
}

/// Every export target, in the order the dialog lists them.
pub fn all_targets() -> Vec<ExportTarget> {
    vec![
        ExportTarget::Appliance {
            ova: true,
            version: OvfVersion::V1,
        },
        ExportTarget::Appliance {
            ova: true,
            version: OvfVersion::V2,
        },
        ExportTarget::Appliance {
            ova: false,
            version: OvfVersion::V1,
        },
        ExportTarget::Appliance {
            ova: false,
            version: OvfVersion::V2,
        },
        ExportTarget::Esxi { thick: false },
        ExportTarget::Esxi { thick: true },
        ExportTarget::HyperV,
        ExportTarget::Azure,
        ExportTarget::Kvm,
        ExportTarget::Proxmox,
        ExportTarget::Raw,
    ]
}

fn refused(message: impl Into<String>) -> CoreError {
    CoreError::ConversionRefused(message.into())
}

/// The conversion service.
#[derive(Clone)]
pub struct Conversions {
    store: Store,
    converter: Arc<Converter>,
    bus: Arc<CommandBus>,
    /// Verify runs by request id, so the page can stop one.
    verifying: Arc<Mutex<HashMap<Uuid, CancellationToken>>>,
}

impl Conversions {
    pub fn new(store: Store, converter: Arc<Converter>, bus: Arc<CommandBus>) -> Self {
        Self {
            store,
            converter,
            bus,
            verifying: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn converter(&self) -> &Arc<Converter> {
        &self.converter
    }

    /// The conversion tools here now. A read.
    pub async fn tools(&self, ctx: &Context) -> Result<ToolsReport> {
        Ok(ToolsReport {
            paths: self.converter.tool_paths(),
            qemu_img_saved: self
                .store
                .get_setting::<Option<String>>(ctx, crate::store::QEMU_IMG_PATH_KEY)
                .await?
                .flatten(),
            qemu_img_formats: vec![DiskFormat::Qcow2, DiskFormat::Vhdx],
            download_page: QEMU_DOWNLOAD,
        })
    }

    /// CV-03 Inspect. A read.
    pub async fn inspect(&self, path: &Path) -> Result<ImageInfo> {
        inspect(path).await
    }

    fn option(info: &ImageInfo, kind: OutputKind, tools: &ToolPaths) -> OutputOption {
        let source = source_of(info, false);
        let (steps, reason, needs_qemu_img) = if let Some(problem) = info.problems.first() {
            (
                Vec::new(),
                Some(format!("The source can't be converted: {problem}.")),
                false,
            )
        } else {
            match plan::plan(source, kind, None, tools) {
                Ok(steps) => (steps, None, false),
                Err(why) => (
                    Vec::new(),
                    Some(why.describe(info.format, kind)),
                    why == NoPlan::NeedsQemuImg,
                ),
            }
        };
        OutputOption {
            kind,
            label: kind.label(),
            extension: kind.extension(),
            plan: plan::describe(&steps),
            estimate_bytes: estimate(info, &steps),
            steps,
            reason,
            needs_qemu_img,
        }
    }

    /// CV-03 Convert: every output the source can be made into here, how, and why not. A read.
    pub async fn options(&self, source: &Path) -> Result<ConvertOptions> {
        let info = inspect(source).await?;
        let tools = self.converter.tool_paths();
        let outputs = OutputKind::ALL
            .iter()
            .map(|kind| Self::option(&info, *kind, &tools))
            .collect();
        let free_bytes = match source.parent() {
            Some(folder) => self.converter.free_bytes(folder).await,
            None => None,
        };
        Ok(ConvertOptions {
            rounds_to_megabytes: whole_megabytes(&info).is_some(),
            info,
            outputs,
            free_bytes,
        })
    }

    /// CV-03: submits a conversion of `source` into `output` (the shell's save dialog chose it) to the bus, after
    /// the job's own checks. Low: it runs at once.
    pub async fn submit_convert(
        &self,
        ctx: &Context,
        source: &Path,
        output: &Path,
        kind: OutputKind,
        whole_mb: bool,
    ) -> Result<SubmitOutcome> {
        let info = inspect(source).await?;
        if let Some(problem) = info.problems.first() {
            return Err(refused(format!("{}: {problem}.", source.display())));
        }
        let tools = self.converter.tool_paths();
        let grow = if whole_mb { whole_megabytes(&info) } else { None };
        let steps = plan::plan(source_of(&info, false), kind, grow, &tools)
            .map_err(|why| refused(why.describe(info.format, kind)))?;
        let spec = ConvertSpec {
            source: source.display().to_string(),
            source_format: info.format,
            output: output.display().to_string(),
            kind,
            whole_megabytes: whole_mb,
        };
        spec.validate()?;
        let folder = output
            .parent()
            .filter(|f| f.is_dir())
            .ok_or_else(|| refused(format!("The folder of {} is not there.", output.display())))?;
        save_guard::refuse_repository(output, Saved::Image)?;
        for file in kind.files(output) {
            if file.exists() {
                return Err(refused(format!(
                    "{} is there already: a conversion never replaces a file. Choose another name.",
                    file.display()
                )));
            }
        }
        let needed = estimate(&info, &steps);
        if let Some(free) = self.converter.free_bytes(folder).await {
            if free < needed {
                return Err(refused(format!(
                    "The new image may need up to {}, and its drive has {} free.",
                    super::formats::size_text(needed),
                    super::formats::size_text(free)
                )));
            }
        }
        self.bus
            .submit(
                ctx,
                Command::ImageConvert {
                    targets: spec.targets(),
                    spec: Box::new(spec),
                },
            )
            .await
    }

    /// VM-17, CV-02: every target the VM can be exported to here, each disk's plan, and why not. A read.
    pub async fn export_options(&self, ctx: &Context, vm_key: &str) -> Result<ExportOptions> {
        let vm = self
            .store
            .find_vm(ctx, vm_key)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(vm_key.to_owned()))?;
        let refusal = self
            .converter
            .require_off(&vm.vmx_path)
            .await
            .err()
            .map(|e| e.to_string());
        let tools = self.converter.tool_paths();
        let mut targets = Vec::new();
        for target in all_targets() {
            targets.push(
                self.export_option(&vm.vmx_path, &vm.display_name, vm.hypervisor, target, &tools)
                    .await,
            );
        }
        Ok(ExportOptions {
            vm_key: vm.vmx_path,
            vm_name: vm.display_name,
            hypervisor: vm.hypervisor,
            refusal,
            targets,
        })
    }

    fn spec_for(
        vm_key: &str,
        vm_name: &str,
        hypervisor: Hypervisor,
        target: ExportTarget,
        tools: &ToolPaths,
        folder: &str,
    ) -> ExportSpec {
        ExportSpec {
            vm_key: vm_key.to_owned(),
            vm_name: vm_name.to_owned(),
            hypervisor,
            target,
            folder: folder.to_owned(),
            name: format!("{}-{}", slug(vm_name), target.suffix()),
            disk_kind: target.disk_kind(tools.has(Tool::QemuImg)),
        }
    }

    async fn export_option(
        &self,
        vm_key: &str,
        vm_name: &str,
        hypervisor: Hypervisor,
        target: ExportTarget,
        tools: &ToolPaths,
    ) -> ExportOption {
        let spec = Self::spec_for(vm_key, vm_name, hypervisor, target, tools, r"C:\");
        let mut option = ExportOption {
            target,
            label: target.label(),
            disks: Vec::new(),
            tool: None,
            reason: None,
            needs_qemu_img: false,
            estimate_bytes: 0,
            folder_name: spec.name.clone(),
        };
        if let ExportTarget::Appliance { version, .. } = target {
            let tool = match hypervisor {
                Hypervisor::Vmware => Tool::Ovftool,
                Hypervisor::VirtualBox => Tool::VBoxManage,
            };
            option.tool = Some(tool);
            if hypervisor == Hypervisor::Vmware && version == OvfVersion::V2 {
                option.reason = Some("Workstation's ovftool writes OVF 1.0 only.".into());
            } else if !tools.has(tool) {
                option.reason = Some(format!("{} isn't on this PC.", tool.label()));
            } else if let Ok(hardware) = self.converter_hardware(vm_key).await {
                option.estimate_bytes = hardware.disks.iter().filter_map(|d| d.on_disk_bytes).sum();
            }
            return option;
        }
        match self.converter.export_plan(&spec, tools).await {
            Ok(disks) => {
                option.estimate_bytes = disks.iter().map(|d| estimate(&d.info, &d.steps)).sum();
                option.disks = disks
                    .iter()
                    .map(|d| ExportDiskView {
                        source: d.source.display().to_string(),
                        file: d.file.clone(),
                        source_format: d.info.format,
                        virtual_bytes: d.virtual_bytes,
                        plan: plan::describe(&d.steps),
                    })
                    .collect();
            }
            Err(err) => {
                let text = err.to_string();
                option.needs_qemu_img = text.contains("needs qemu-img");
                option.reason = Some(text);
            }
        }
        option
    }

    async fn converter_hardware(&self, vm_key: &str) -> Result<crate::adapters::vm_hardware::VmHardware> {
        self.converter.hardware(vm_key).await
    }

    /// VM-17, CV-02: submits the VM's export into `folder` (the shell's folder dialog chose it) to the bus, after
    /// the job's own checks. Low (a Prod VM's is Medium).
    pub async fn submit_export(
        &self,
        ctx: &Context,
        vm_key: &str,
        target: ExportTarget,
        folder: &Path,
    ) -> Result<SubmitOutcome> {
        let vm = self
            .store
            .find_vm(ctx, vm_key)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(vm_key.to_owned()))?;
        self.converter.require_off(&vm.vmx_path).await?;
        let tools = self.converter.tool_paths();
        let spec = Self::spec_for(
            &vm.vmx_path,
            &vm.display_name,
            vm.hypervisor,
            target,
            &tools,
            &folder.display().to_string(),
        );
        spec.validate()?;
        if !folder.is_dir() {
            return Err(refused(format!("{} is not there.", folder.display())));
        }
        save_guard::refuse_repository_folder(folder, Saved::Export)?;
        if spec.out_folder().exists() {
            return Err(refused(format!(
                "{} is there already, and an export makes its folder itself. Choose another folder.",
                spec.out_folder().display()
            )));
        }
        let option = self
            .export_option(&vm.vmx_path, &vm.display_name, vm.hypervisor, target, &tools)
            .await;
        if let Some(reason) = option.reason {
            return Err(refused(reason));
        }
        if let Some(free) = self.converter.free_bytes(folder).await {
            if free < option.estimate_bytes {
                return Err(refused(format!(
                    "The export may need up to {}, and the drive has {} free.",
                    super::formats::size_text(option.estimate_bytes),
                    super::formats::size_text(free)
                )));
            }
        }
        self.bus
            .submit(
                ctx,
                Command::VmExport {
                    targets: spec.targets(),
                    spec: Box::new(spec),
                },
            )
            .await
    }

    /// CV-03 Verify, as request `request` (the page can stop it with [`Self::cancel_verify`]). A read.
    pub async fn verify(
        &self,
        request: Uuid,
        first: &Path,
        second: Option<&Path>,
        progress: Arc<dyn Fn(VerifyProgress) + Send + Sync>,
    ) -> Result<VerifyReport> {
        let token = CancellationToken::new();
        locks::lock(&self.verifying).insert(request, token.clone());
        let tools = Arc::clone(self.converter.disk_tools());
        let report = verify::verify(tools.as_ref(), first, second, token, progress).await;
        locks::lock(&self.verifying).remove(&request);
        report
    }

    /// Stops Verify's request. False when it isn't running.
    pub fn cancel_verify(&self, request: Uuid) -> bool {
        locks::lock(&self.verifying)
            .get(&request)
            .map(CancellationToken::cancel)
            .is_some()
    }
}

/// The default name for a conversion's output: the source's name with the output's extension, beside it.
pub fn default_output(source: &Path, kind: OutputKind) -> PathBuf {
    let stem = source
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "disk".into());
    let mut name = format!("{stem}.{}", kind.extension());
    if source
        .file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(&name))
    {
        name = format!("{stem}-converted.{}", kind.extension());
    }
    source.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_qemus_download_page_opens() {
        checked_qemu_site(QEMU_DOWNLOAD).unwrap();
        for url in [
            "http://www.qemu.org/download/",
            "https://qemu.org/download/",
            "https://www.qemu.org/docs/",
            "https://www.qemu.org:8443/download/",
            "https://user@www.qemu.org/download/",
            "https://www.qemu.org.example.com/download/",
            "https://qemu.weilnetz.de/w64/",
            "file:///C:/Windows/System32/calc.exe",
        ] {
            assert!(checked_qemu_site(url).is_err(), "{url}");
        }
    }

    #[test]
    fn the_new_image_is_named_after_its_source() {
        assert_eq!(
            default_output(Path::new(r"C:\Images\rocky.qcow2"), OutputKind::VmdkSparse),
            Path::new(r"C:\Images\rocky.vmdk")
        );
        assert_eq!(
            default_output(Path::new(r"C:\Images\web.vmdk"), OutputKind::VmdkStream),
            Path::new(r"C:\Images\web-converted.vmdk")
        );
        assert_eq!(all_targets().len(), 11);
    }
}
