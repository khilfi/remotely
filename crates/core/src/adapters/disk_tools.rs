//! CV-01 to CV-03, VM-17: the disk conversion tools as one outside system, behind [`DiskTools`] so tests use
//! [`crate::fakes::FakeDiskTools`].
//!
//! * The hypervisors' own first: `vmware-vdiskmanager` and `ovftool` (both come with Workstation) and
//!   `VBoxManage` (`clonemedium`, `convertfromraw`, `export`). Their paths come from the hypervisor adapters
//!   ([`ToolPaths`]), so a path changed in Settings applies at once.
//! * `qemu-img` for what they can't do (qcow2, VHDX), **only if the owner installed it**: it is GPL-licensed, so
//!   Remotely never ships it. Found like vmrun ([`locate_qemu_img`]): the path saved in Settings, then
//!   `REMOTELY_QEMU_IMG`, then QEMU's default install folder.
//!
//! Each run has a time limit, gets no console window and no input, and is killed when its job is cancelled (the
//! future is dropped). Its output is read as it comes, so the job shows the tool's own progress: qemu-img's
//! `(12.00/100%)`, VBoxManage's `10%...20%`, vdiskmanager's `Convert: 12% done.`, ovftool's `Disk progress: 12%`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::io::AsyncReadExt;

use crate::error::{CoreError, Result};
use crate::locks;

/// A conversion tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Tool {
    QemuImg,
    VdiskManager,
    VBoxManage,
    Ovftool,
}

impl Tool {
    pub fn label(self) -> &'static str {
        match self {
            Tool::QemuImg => "qemu-img",
            Tool::VdiskManager => "vmware-vdiskmanager",
            Tool::VBoxManage => "VBoxManage",
            Tool::Ovftool => "ovftool",
        }
    }
}

/// Where each tool is on this PC now; `None`: not found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPaths {
    pub qemu_img: Option<PathBuf>,
    pub vdiskmanager: Option<PathBuf>,
    pub vboxmanage: Option<PathBuf>,
    pub ovftool: Option<PathBuf>,
}

impl ToolPaths {
    pub fn get(&self, tool: Tool) -> Option<&Path> {
        match tool {
            Tool::QemuImg => self.qemu_img.as_deref(),
            Tool::VdiskManager => self.vdiskmanager.as_deref(),
            Tool::VBoxManage => self.vboxmanage.as_deref(),
            Tool::Ovftool => self.ovftool.as_deref(),
        }
    }

    pub fn has(&self, tool: Tool) -> bool {
        self.get(tool).is_some()
    }

    /// Every tool, for tests and a PC with all of them.
    pub fn all() -> Self {
        Self {
            qemu_img: Some(PathBuf::from(DEFAULT_QEMU_IMG)),
            vdiskmanager: Some(PathBuf::from(
                r"C:\Program Files\VMware\VMware Workstation\vmware-vdiskmanager.exe",
            )),
            vboxmanage: Some(PathBuf::from(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")),
            ovftool: Some(PathBuf::from(
                r"C:\Program Files\VMware\VMware Workstation\OVFTool\ovftool.exe",
            )),
        }
    }
}

/// One run of a tool.
pub struct ToolRun<'a> {
    pub tool: Tool,
    pub program: &'a Path,
    pub args: Vec<OsString>,
    pub timeout: Duration,
    /// Called with the tool's progress, 0 to 100, as it reports it.
    pub progress: &'a (dyn Fn(f64) + Send + Sync),
    /// Exit codes that are an answer, not a failure: `qemu-img compare` says 1 for images that differ.
    pub answers: &'a [i32],
}

impl<'a> ToolRun<'a> {
    /// A run whose only good exit code is 0.
    pub fn new(
        tool: Tool,
        program: &'a Path,
        args: Vec<OsString>,
        timeout: Duration,
        progress: &'a (dyn Fn(f64) + Send + Sync),
    ) -> Self {
        Self {
            tool,
            program,
            args,
            timeout,
            progress,
            answers: &[0],
        }
    }
}

/// What a tool that ended well printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Its exit code, one of [`ToolRun::answers`].
    pub code: i32,
    /// stdout then stderr, the last 64 KB of each.
    pub text: String,
}

#[async_trait]
pub trait DiskTools: Send + Sync {
    /// The qemu-img.exe in use, or `None` when it isn't installed (or not found).
    fn qemu_img(&self) -> Option<PathBuf>;

    /// Looks for qemu-img again with this path from Settings (`None`: `REMOTELY_QEMU_IMG`, then the default folder).
    fn locate_qemu_img(&self, saved: Option<PathBuf>);

    /// Runs the tool to the end: its output when its exit code is one of the run's answers; a
    /// [`CoreError::ConversionTool`] with its own message otherwise; [`CoreError::Timeout`] after the limit.
    async fn run(&self, run: ToolRun<'_>) -> Result<ToolOutput>;
}

/// QEMU's Windows installer's default folder.
pub const DEFAULT_QEMU_IMG: &str = r"C:\Program Files\qemu\qemu-img.exe";
/// The environment variable that names qemu-img.exe.
pub const QEMU_IMG_ENV: &str = "REMOTELY_QEMU_IMG";

/// qemu-img.exe: the Settings path, then `REMOTELY_QEMU_IMG`, then QEMU's default install folder. Never a path
/// on a share or a device path.
pub fn locate_qemu_img(saved: Option<PathBuf>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(saved);
    candidates.extend(std::env::var_os(QEMU_IMG_ENV).map(PathBuf::from));
    candidates.push(PathBuf::from(DEFAULT_QEMU_IMG));
    candidates
        .into_iter()
        .filter(|p| crate::untrusted::path_refusal(p).is_none())
        .find(|p| p.is_file())
}

/// A qemu-img path typed in Settings: an existing file named qemu-img.exe.
pub fn validate_qemu_img_path(path: &Path) -> Result<()> {
    if let Some(refusal) = crate::untrusted::path_refusal(path) {
        return Err(CoreError::InvalidSetting(format!(
            "{} {}",
            path.display(),
            refusal.describe()
        )));
    }
    let named = path
        .file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("qemu-img.exe"));
    if !named || !path.is_file() {
        return Err(CoreError::InvalidSetting(format!(
            "{} is not qemu-img.exe. It is in the folder QEMU for Windows was installed to.",
            path.display()
        )));
    }
    Ok(())
}

/// The last progress a tool printed in `text`, 0 to 100: the last `NN%` or `(NN.NN/100%)`.
pub fn last_progress(text: &str) -> Option<f64> {
    let bytes = text.as_bytes();
    let mut end = bytes.len();
    while let Some(pos) = text[..end].rfind('%') {
        // `(12.34/100%)`: the number before `/100`.
        let before = &text[..pos];
        let number_end = before.strip_suffix("/100").map_or(before.len(), str::len);
        let digits_start = text[..number_end]
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_digit() || *c == '.')
            .last()
            .map(|(i, _)| i);
        if let Some(start) = digits_start {
            // VBoxManage's `...20%`: the dots before the number aren't part of it.
            if let Ok(value) = text[start..number_end].trim_start_matches('.').parse::<f64>() {
                if (0.0..=100.0).contains(&value) {
                    return Some(value);
                }
            }
        }
        end = pos;
    }
    None
}

/// What a failed tool said, in its own words, without its path, progress or VBoxManage's Details and Context lines.
pub fn failure_message(tool: Tool, stdout: &str, stderr: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for raw in stderr.lines().chain(stdout.lines()) {
        for part in raw.split('\r') {
            let line = part.trim();
            if line.is_empty() || last_progress(line).is_some() && line.len() < 40 {
                continue;
            }
            let line = match tool {
                Tool::VBoxManage => {
                    let Some(rest) = line.split_once("error: ").map(|(_, r)| r) else {
                        continue;
                    };
                    if rest.starts_with("Details:") || rest.starts_with("Context:") {
                        continue;
                    }
                    rest.to_owned()
                }
                // `C:\Program Files\qemu\qemu-img.exe: Could not open 'a.vmdk': ...`
                Tool::QemuImg => line
                    .split_once("qemu-img.exe: ")
                    .or_else(|| line.split_once("qemu-img: "))
                    .map_or(line, |(_, r)| r)
                    .to_owned(),
                Tool::Ovftool => line.strip_prefix("Error: ").unwrap_or(line).to_owned(),
                Tool::VdiskManager => {
                    if line.starts_with("Creating disk") {
                        continue;
                    }
                    line.to_owned()
                }
            };
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    let text = lines.into_iter().take(3).collect::<Vec<_>>().join(" ");
    let text: String = text.chars().take(500).collect();
    if text.is_empty() {
        "it ended with an error and said nothing more".into()
    } else {
        text
    }
}

/// The tools on this PC.
pub struct LocalDiskTools {
    qemu_img: RwLock<Option<PathBuf>>,
}

impl LocalDiskTools {
    pub fn new(saved_qemu_img: Option<PathBuf>) -> Self {
        Self {
            qemu_img: RwLock::new(locate_qemu_img(saved_qemu_img)),
        }
    }
}

/// The last `cap` bytes of a stream read so far.
fn keep_tail(buffer: &mut Vec<u8>, chunk: &[u8], cap: usize) {
    buffer.extend_from_slice(chunk);
    if buffer.len() > cap {
        let cut = buffer.len() - cap;
        buffer.drain(..cut);
    }
}

const KEEP_OUTPUT: usize = 64 * 1024;

/// Reads a tool's stream to its end, keeping its last [`KEEP_OUTPUT`] bytes and passing on the progress it prints.
async fn read_stream(stream: Option<impl tokio::io::AsyncRead + Unpin>, progress: &(dyn Fn(f64) + Send + Sync)) -> Vec<u8> {
    let mut kept = Vec::new();
    let Some(mut stream) = stream else {
        return kept;
    };
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return kept,
            Ok(n) => {
                keep_tail(&mut kept, &buf[..n], KEEP_OUTPUT);
                let seen = String::from_utf8_lossy(&kept[kept.len().saturating_sub(256)..]).into_owned();
                if let Some(p) = last_progress(&seen) {
                    progress(p);
                }
            }
        }
    }
}

#[async_trait]
impl DiskTools for LocalDiskTools {
    fn qemu_img(&self) -> Option<PathBuf> {
        locks::read(&self.qemu_img).clone()
    }

    fn locate_qemu_img(&self, saved: Option<PathBuf>) {
        *locks::write(&self.qemu_img) = locate_qemu_img(saved);
    }

    async fn run(&self, run: ToolRun<'_>) -> Result<ToolOutput> {
        let mut cmd = tokio::process::Command::new(run.program);
        cmd.args(&run.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn().map_err(|err| CoreError::ConversionTool {
            tool: run.tool.label().into(),
            message: format!("it didn't start: {err}"),
        })?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let progress = run.progress;
        let work = async {
            let (out, err, status) = tokio::join!(
                read_stream(stdout, progress),
                read_stream(stderr, progress),
                child.wait()
            );
            Ok::<_, CoreError>((status?, out, err))
        };
        let (status, out, err) = tokio::time::timeout(run.timeout, work)
            .await
            .map_err(|_| CoreError::Timeout {
                command: run.tool.label().into(),
                seconds: run.timeout.as_secs(),
            })??;
        let out = String::from_utf8_lossy(&out).into_owned();
        let err = String::from_utf8_lossy(&err).into_owned();
        let code = status.code().unwrap_or(-1);
        if run.answers.contains(&code) {
            progress(100.0);
            Ok(ToolOutput {
                code,
                text: format!("{out}{err}"),
            })
        } else {
            Err(CoreError::ConversionTool {
                tool: run.tool.label().into(),
                message: failure_message(run.tool, &out, &err),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_tools_progress_is_read() {
        assert_eq!(last_progress("    (0.00/100%)\r    (45.50/100%)\r"), Some(45.5));
        assert_eq!(last_progress("0%...10%...20%..."), Some(20.0));
        assert_eq!(last_progress("  Convert: 12% done.  Convert: 13% done."), Some(13.0));
        assert_eq!(last_progress("Disk progress: 99%"), Some(99.0));
        assert_eq!(last_progress("Opening VMX source"), None);
        assert_eq!(last_progress("250%"), None);
    }

    #[test]
    fn a_tools_own_words_are_kept_without_its_noise() {
        let vbox = "0%...VBOX_E_FILE_ERROR\r\nVBoxManage.exe: error: Failed to clone medium\r\nVBoxManage.exe: error: Could not create the clone medium 'C:\\x.vdi'\r\nVBoxManage.exe: error: Details: code VBOX_E_FILE_ERROR\r\nVBoxManage.exe: error: Context: \"CloneTo\"\r\n";
        assert_eq!(
            failure_message(Tool::VBoxManage, "", vbox),
            "Failed to clone medium Could not create the clone medium 'C:\\x.vdi'"
        );
        let qemu = "C:\\Program Files\\qemu\\qemu-img.exe: Could not open 'a.vmdk': Image is not in qcow2 format\r\n";
        assert_eq!(
            failure_message(Tool::QemuImg, "", qemu),
            "Could not open 'a.vmdk': Image is not in qcow2 format"
        );
        assert_eq!(
            failure_message(Tool::VdiskManager, "Creating disk 'b.vmdk'\r\nFailed to convert disk: Insufficient disk space\r\n", ""),
            "Failed to convert disk: Insufficient disk space"
        );
        assert_eq!(failure_message(Tool::Ovftool, "Error: Invalid target", ""), "Invalid target");
        assert!(failure_message(Tool::Ovftool, "", "").contains("said nothing"));
    }

    #[test]
    fn qemu_img_is_found_where_settings_or_the_environment_say() {
        let dir = std::env::temp_dir().join(format!("remotely-qemu-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("qemu-img.exe");
        std::fs::write(&exe, b"stand-in").unwrap();
        assert_eq!(locate_qemu_img(Some(exe.clone())), Some(exe.clone()));
        validate_qemu_img_path(&exe).unwrap();
        let other = dir.join("qemu-system-x86_64.exe");
        std::fs::write(&other, b"stand-in").unwrap();
        assert!(validate_qemu_img_path(&other).is_err());
        assert!(validate_qemu_img_path(Path::new(r"\\server.example.com\tools\qemu-img.exe")).is_err());
        assert_eq!(
            locate_qemu_img(Some(PathBuf::from(r"\\server.example.com\tools\qemu-img.exe")))
                .filter(|p| p.starts_with(r"\\")),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
