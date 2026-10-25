//! CV-01 to CV-03, VM-17: a fake of the conversion tools ([`DiskTools`]). It runs no program: it reads the
//! arguments the real tools would get and writes small files with the header of the format they would write
//! (from [`super::disk_images`]), so the job's file handling (its work folder, the move into place, cleanup) and
//! Inspect run on them as on real outputs. VBoxManage's media list is kept as VirtualBox keeps it: `clonemedium`
//! registers its source and its target, `closemedium` forgets one.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use super::disk_images as img;
use crate::adapters::disk_tools::{DiskTools, Tool, ToolOutput, ToolRun};
use crate::adapters::vmware::path_key;
use crate::convert::formats::{flat_extent, DiskFormat, OutputKind};
use crate::error::{CoreError, Result};
use crate::locks;

#[derive(Default)]
struct State {
    qemu_img: Option<PathBuf>,
    calls: Vec<String>,
    failing: BTreeSet<&'static str>,
    delay: Option<Duration>,
    registered: Vec<String>,
    compare_differs: bool,
}

/// The conversion tools, without qemu-img unless a test installs it ([`FakeDiskTools::with_qemu_img`]).
#[derive(Default)]
pub struct FakeDiskTools {
    state: Mutex<State>,
}

/// Where tests say qemu-img is.
pub const FAKE_QEMU_IMG: &str = r"C:\Program Files\qemu\qemu-img.exe";

impl FakeDiskTools {
    pub fn new() -> Self {
        Self::default()
    }

    /// qemu-img is installed.
    pub fn with_qemu_img(self) -> Self {
        locks::lock(&self.state).qemu_img = Some(PathBuf::from(FAKE_QEMU_IMG));
        self
    }

    /// The tool fails (`qemu-img`, `vdiskmanager`, `VBoxManage`, `ovftool`) with its own kind of message.
    pub fn set_failing(&self, tool: Tool, failing: bool) {
        let mut state = locks::lock(&self.state);
        if failing {
            state.failing.insert(tool.label());
        } else {
            state.failing.remove(tool.label());
        }
    }

    /// Each run takes this long (so a test can cancel one midway).
    pub fn set_delay(&self, delay: Duration) {
        locks::lock(&self.state).delay = Some(delay);
    }

    /// `qemu-img compare` finds the images differ.
    pub fn set_compare_differs(&self, differs: bool) {
        locks::lock(&self.state).compare_differs = differs;
    }

    /// Every run, as `<tool> <args>`.
    pub fn calls(&self) -> Vec<String> {
        locks::lock(&self.state).calls.clone()
    }

    /// VirtualBox's media list now.
    pub fn registered(&self) -> Vec<String> {
        locks::lock(&self.state).registered.clone()
    }

    /// A medium VirtualBox knows already (a VM's own disk).
    pub fn register(&self, path: &Path) {
        locks::lock(&self.state).registered.push(path.display().to_string());
    }
}

fn failed(tool: Tool, message: &str) -> CoreError {
    CoreError::ConversionTool {
        tool: tool.label().into(),
        message: message.into(),
    }
}

/// The virtual size the source's header says, as the real tool would read it.
async fn source_bytes(tool: Tool, source: &Path) -> Result<u64> {
    let info = crate::convert::inspect::inspect(source)
        .await
        .map_err(|err| failed(tool, &format!("Could not open '{}': {err}", source.display())))?;
    info.virtual_bytes
        .ok_or_else(|| failed(tool, &format!("Could not read the size of '{}'", source.display())))
}

/// Writes what a tool writes for `out` at `target`. Data is zeros: a few MB at most in tests.
fn write_output(target: &Path, out: OutputKind, bytes: u64) -> Result<()> {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let small = usize::try_from(bytes.min(64 << 20)).unwrap_or(0);
    let data: Vec<u8> = match out {
        OutputKind::VmdkSparse => img::vmdk_sparse(&name, bytes, false),
        OutputKind::VmdkStream => img::vmdk_sparse(&name, bytes, true),
        OutputKind::VmdkFlat | OutputKind::VmdkEsx => {
            let extent = flat_extent(target);
            let extent_name = extent
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            std::fs::write(&extent, vec![0u8; small])?;
            let (create, kind) = if out == OutputKind::VmdkEsx {
                ("vmfs", "VMFS")
            } else {
                ("monolithicFlat", "FLAT")
            };
            img::vmdk_descriptor(create, &[(bytes / 512, kind, &extent_name)], None).into_bytes()
        }
        OutputKind::VdiDynamic => img::vdi(bytes, 1),
        OutputKind::VdiFixed => img::vdi(bytes, 2),
        OutputKind::VhdDynamic => img::vhd_dynamic(bytes, false),
        OutputKind::VhdFixed => {
            let mut data = vec![0u8; small];
            data.extend_from_slice(&img::vhd_footer(bytes, 2));
            data
        }
        OutputKind::VhdxDynamic => img::vhdx(bytes, false, false),
        OutputKind::VhdxFixed => img::vhdx(bytes, true, false),
        OutputKind::Qcow2 | OutputKind::Qcow2Thick => img::qcow2(bytes, None),
        OutputKind::Raw => img::raw_mbr(bytes.min(64 << 20)),
    };
    std::fs::write(target, data)?;
    Ok(())
}

fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn qemu_kind(format: &str, options: Option<&str>) -> Option<OutputKind> {
    let options = options.unwrap_or("");
    Some(match format {
        "vmdk" if options.contains("monolithicFlat") => OutputKind::VmdkFlat,
        "vmdk" if options.contains("streamOptimized") => OutputKind::VmdkStream,
        "vmdk" => OutputKind::VmdkSparse,
        "vdi" if options.contains("static=on") => OutputKind::VdiFixed,
        "vdi" => OutputKind::VdiDynamic,
        "vpc" if options.contains("subformat=fixed") => OutputKind::VhdFixed,
        "vpc" => OutputKind::VhdDynamic,
        "vhdx" if options.contains("subformat=fixed") => OutputKind::VhdxFixed,
        "vhdx" => OutputKind::VhdxDynamic,
        "qcow2" if options.contains("preallocation=full") => OutputKind::Qcow2Thick,
        "qcow2" => OutputKind::Qcow2,
        "raw" => OutputKind::Raw,
        _ => return None,
    })
}

fn qemu_format(name: &str) -> Option<DiskFormat> {
    DiskFormat::ALL.into_iter().find(|f| f.qemu_name() == name)
}

impl FakeDiskTools {
    async fn qemu(&self, args: &[String]) -> Result<ToolOutput> {
        let tool = Tool::QemuImg;
        match args.first().map(String::as_str) {
            Some("convert") => {
                let from = arg_after(args, "-f").ok_or_else(|| failed(tool, "no input format (-f)"))?;
                let to = arg_after(args, "-O").ok_or_else(|| failed(tool, "no output format (-O)"))?;
                let out = qemu_kind(to, arg_after(args, "-o")).ok_or_else(|| failed(tool, "Unknown file format"))?;
                let (source, target) = (args[args.len() - 2].clone(), args[args.len() - 1].clone());
                let info = crate::convert::inspect::inspect(Path::new(&source))
                    .await
                    .map_err(|err| failed(tool, &format!("Could not open '{source}': {err}")))?;
                if qemu_format(from) != Some(info.format) {
                    return Err(failed(
                        tool,
                        &format!("Could not open '{source}': Image is not in {from} format"),
                    ));
                }
                let bytes = info.virtual_bytes.unwrap_or(0);
                write_output(Path::new(&target), out, bytes)?;
                Ok(ToolOutput {
                    code: 0,
                    text: "    (100.00/100%)\r\n".into(),
                })
            }
            Some("compare") => {
                let a = Path::new(&args[args.len() - 2]);
                let b = Path::new(&args[args.len() - 1]);
                let (a, b) = (source_bytes(tool, a).await?, source_bytes(tool, b).await?);
                if a != b {
                    return Ok(ToolOutput {
                        code: 1,
                        text: "Warning: Image size mismatch!\nImages are identical.\n".into(),
                    });
                }
                if locks::lock(&self.state).compare_differs {
                    return Ok(ToolOutput {
                        code: 1,
                        text: "Content mismatch at offset 0!\n".into(),
                    });
                }
                Ok(ToolOutput {
                    code: 0,
                    text: "Images are identical.\n".into(),
                })
            }
            Some("resize") => {
                let format = arg_after(args, "-f")
                    .and_then(qemu_format)
                    .ok_or_else(|| failed(tool, "-f"))?;
                let path = PathBuf::from(&args[args.len() - 2]);
                let bytes: u64 = args[args.len() - 1].parse().map_err(|_| failed(tool, "Invalid size"))?;
                write_output(&path, OutputKind::of(format, true), bytes)?;
                Ok(ToolOutput {
                    code: 0,
                    text: "Image resized.\n".into(),
                })
            }
            _ => Err(failed(tool, "unknown command")),
        }
    }

    async fn vdisk(&self, args: &[String]) -> Result<ToolOutput> {
        let tool = Tool::VdiskManager;
        if args.first().map(String::as_str) != Some("-r") || args.len() != 5 {
            return Err(failed(tool, "Unknown operation"));
        }
        let (source, kind, target) = (Path::new(&args[1]), args[3].as_str(), Path::new(&args[4]));
        if target.exists() {
            return Err(failed(tool, "Failed to convert disk: The file already exists"));
        }
        let bytes = source_bytes(tool, source).await?;
        let out = match kind {
            "0" => OutputKind::VmdkSparse,
            "2" => OutputKind::VmdkFlat,
            "4" => OutputKind::VmdkEsx,
            "5" => OutputKind::VmdkStream,
            _ => return Err(failed(tool, "Invalid disk type")),
        };
        write_output(target, out, bytes)?;
        Ok(ToolOutput {
            code: 0,
            text: "Creating disk\r\n  Convert: 100% done.\r\nVirtual disk conversion successful.\r\n".into(),
        })
    }

    fn register_once(&self, path: &str) {
        let mut state = locks::lock(&self.state);
        let key = path_key(Path::new(path));
        if !state.registered.iter().any(|r| path_key(Path::new(r)) == key) {
            state.registered.push(path.to_owned());
        }
    }

    async fn vbox(&self, args: &[String]) -> Result<ToolOutput> {
        let tool = Tool::VBoxManage;
        let ok = |text: &str| {
            Ok(ToolOutput {
                code: 0,
                text: text.to_owned(),
            })
        };
        match args.first().map(String::as_str) {
            Some("list") => {
                let text: String = locks::lock(&self.state)
                    .registered
                    .iter()
                    .map(|r| format!("UUID:           00000000-0000-0000-0000-000000000000\nLocation:       {r}\n\n"))
                    .collect();
                ok(&text)
            }
            Some("closemedium") => {
                let path = args.get(2).cloned().unwrap_or_default();
                let key = path_key(Path::new(&path));
                let mut state = locks::lock(&self.state);
                let before = state.registered.len();
                state.registered.retain(|r| path_key(Path::new(r)) != key);
                if state.registered.len() == before {
                    return Err(failed(tool, "Could not find file for the medium"));
                }
                ok("")
            }
            Some(sub @ ("clonemedium" | "convertfromraw")) => {
                let (source, target) = if sub == "clonemedium" {
                    (args[2].clone(), args[3].clone())
                } else {
                    (args[1].clone(), args[2].clone())
                };
                if Path::new(&target).exists() {
                    return Err(failed(tool, &format!("Could not create the clone medium '{target}'")));
                }
                let format = arg_after(args, "--format").unwrap_or("VDI");
                let variant = arg_after(args, "--variant").unwrap_or("Standard");
                let thin = variant == "Standard" || variant == "Stream";
                let out = match (format, variant) {
                    ("VMDK", "Stream") => OutputKind::VmdkStream,
                    ("VMDK", _) => OutputKind::of(DiskFormat::Vmdk, thin),
                    ("VHD", _) => OutputKind::of(DiskFormat::Vhd, thin),
                    ("RAW", _) => OutputKind::Raw,
                    _ => OutputKind::of(DiskFormat::Vdi, thin),
                };
                let bytes = if sub == "convertfromraw" {
                    std::fs::metadata(&source)
                        .map_err(|_| failed(tool, "Cannot open the raw disk"))?
                        .len()
                } else {
                    source_bytes(tool, Path::new(&source)).await?
                };
                write_output(Path::new(&target), out, bytes)?;
                if sub == "clonemedium" {
                    self.register_once(&source);
                    self.register_once(&target);
                }
                ok("0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%\r\n")
            }
            Some("modifymedium") => {
                let path = PathBuf::from(args.get(2).cloned().unwrap_or_default());
                let mb: u64 = arg_after(args, "--resize")
                    .and_then(|m| m.parse().ok())
                    .ok_or_else(|| failed(tool, "Invalid size"))?;
                let info = crate::convert::inspect::inspect(&path)
                    .await
                    .map_err(|err| failed(tool, &err.to_string()))?;
                write_output(&path, OutputKind::of(info.format, true), mb << 20)?;
                self.register_once(&path.display().to_string());
                ok("0%...100%\r\n")
            }
            Some("export") => {
                let target = PathBuf::from(arg_after(args, "--output").unwrap_or_default());
                let ovf = img::ovf(
                    "exported",
                    2,
                    2048,
                    false,
                    "ubuntu64Guest",
                    &[("disk001.vmdk", 64 << 20)],
                );
                write_appliance(&target, &ovf)?;
                ok("0%...100%\r\nSuccessfully exported 1 machine(s).\r\n")
            }
            _ => Err(failed(tool, "unknown command")),
        }
    }

    fn ovftool(&self, args: &[String]) -> Result<ToolOutput> {
        let target = PathBuf::from(args.last().cloned().unwrap_or_default());
        let source = PathBuf::from(&args[args.len().saturating_sub(2)]);
        if !source.exists() {
            return Err(failed(
                Tool::Ovftool,
                &format!("Failed to open file: {}", source.display()),
            ));
        }
        let ovf = img::ovf(
            "exported",
            2,
            2048,
            false,
            "ubuntu64Guest",
            &[("exported-disk1.vmdk", 64 << 20)],
        );
        write_appliance(&target, &ovf)?;
        Ok(ToolOutput {
            code: 0,
            text: "Opening VMX source\r\nDisk progress: 100%\r\nCompleted successfully\r\n".into(),
        })
    }
}

/// An OVA (a tar of the descriptor, its manifest and a disk), or an OVF with its files beside it.
fn write_appliance(target: &Path, ovf: &str) -> Result<()> {
    let disk = img::vmdk_sparse("disk1.vmdk", 64 << 20, true);
    let manifest = b"SHA256(exported.ovf)= 00\n";
    if target.extension().is_some_and(|e| e.eq_ignore_ascii_case("ova")) {
        std::fs::write(
            target,
            img::tar(&[
                ("exported.ovf", ovf.as_bytes()),
                ("exported.mf", manifest),
                ("exported-disk1.vmdk", &disk),
            ]),
        )?;
    } else {
        std::fs::write(target, ovf)?;
        std::fs::write(target.with_extension("mf"), manifest)?;
        std::fs::write(target.with_file_name("exported-disk1.vmdk"), disk)?;
    }
    Ok(())
}

#[async_trait]
impl DiskTools for FakeDiskTools {
    fn qemu_img(&self) -> Option<PathBuf> {
        locks::lock(&self.state).qemu_img.clone()
    }

    fn locate_qemu_img(&self, saved: Option<PathBuf>) {
        if let Some(saved) = saved {
            locks::lock(&self.state).qemu_img = Some(saved);
        }
    }

    async fn run(&self, run: ToolRun<'_>) -> Result<ToolOutput> {
        let args: Vec<String> = run.args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let (delay, failing) = {
            let mut state = locks::lock(&self.state);
            state.calls.push(format!("{} {}", run.tool.label(), args.join(" ")));
            (state.delay, state.failing.contains(run.tool.label()))
        };
        (run.progress)(50.0);
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if failing {
            return Err(failed(run.tool, "Failed: insufficient disk space"));
        }
        let output = match run.tool {
            Tool::QemuImg => self.qemu(&args).await?,
            Tool::VdiskManager => self.vdisk(&args).await?,
            Tool::VBoxManage => self.vbox(&args).await?,
            Tool::Ovftool => self.ovftool(&args)?,
        };
        if !run.answers.contains(&output.code) {
            return Err(failed(run.tool, &output.text));
        }
        (run.progress)(100.0);
        Ok(output)
    }
}
