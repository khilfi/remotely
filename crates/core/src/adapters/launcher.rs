//! SS-12 remote desktop and VNC windows: the programs Remotely starts for an RDP or VNC session, behind the
//! [`ConsoleLauncher`] trait, so tests record what would start ([`crate::fakes::FakeLauncher`]) and never start
//! `mstsc.exe` or a viewer.
//!
//! * RDP: `mstsc.exe` from System32 on a `.rdp` file Remotely writes (host, user, screen, what is shared), in a
//!   folder of its own in this Windows user's temp folder (which only they, SYSTEM and administrators can read),
//!   deleted once mstsc has read it ([`RDP_FILE_KEPT`]) or exits. mstsc asks for the password: the file never holds
//!   one, and nothing goes to Windows' credential store.
//! * VNC: the owner's own viewer (TigerVNC, TightVNC, RealVNC or UltraVNC), found like the other tools
//!   ([`locate_vnc_viewer`]), started with the host and port; it asks for the password.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;

use crate::error::{CoreError, Result};

/// How long the `.rdp` file stays for mstsc to read it, at most.
pub const RDP_FILE_KEPT: Duration = Duration::from_secs(20);

/// What to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// `mstsc.exe` on a `.rdp` file with this text, named after `name`.
    Rdp { name: String, file: String },
    /// A VNC viewer with these arguments.
    Viewer { exe: PathBuf, args: Vec<String> },
}

/// A started window's program.
#[async_trait]
pub trait LaunchedWindow: Send {
    /// Waits until it exits (its window closed).
    async fn wait(self: Box<Self>);
}

#[async_trait]
pub trait ConsoleLauncher: Send + Sync {
    /// Starts the program and returns once it runs. [`CoreError::Console`] when it can't start.
    async fn launch(&self, launch: Launch) -> Result<Box<dyn LaunchedWindow>>;
}

/// The real programs.
pub struct WindowsLauncher;

struct Child(tokio::process::Child);

#[async_trait]
impl LaunchedWindow for Child {
    async fn wait(mut self: Box<Self>) {
        let _ = self.0.wait().await;
    }
}

/// `mstsc.exe` in System32: never one found on the PATH or in the working folder.
pub fn mstsc_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    root.join("System32").join("mstsc.exe")
}

/// A file name made of the session's name: letters, digits, `-`, `_` and `.` only, and never a DOS device's name
/// (`NUL`, `CON`, `COM1`...), which Windows would open instead of a file.
pub fn file_stem(name: &str) -> String {
    let stem: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(60)
        .collect();
    let stem = stem.trim_matches('.').to_owned();
    if stem.is_empty() {
        "remote-desktop".to_owned()
    } else if crate::untrusted::is_device_name(&stem) || crate::untrusted::is_device_name(&format!("{stem}.rdp")) {
        format!("remote-desktop-{stem}")
    } else {
        stem
    }
}

/// The `.rdp` file as mstsc reads it: UTF-16 little-endian with its byte-order mark, CR LF line ends (what mstsc
/// itself saves), so a user name in any script arrives whole.
pub fn rdp_file_bytes(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.replace("\r\n", "\n").replace('\n', "\r\n").encode_utf16() {
        out.extend(unit.to_le_bytes());
    }
    out
}

#[async_trait]
impl ConsoleLauncher for WindowsLauncher {
    async fn launch(&self, launch: Launch) -> Result<Box<dyn LaunchedWindow>> {
        match launch {
            Launch::Rdp { name, file } => {
                let dir = std::env::temp_dir().join(format!("remotely-rdp-{}", uuid::Uuid::new_v4()));
                tokio::fs::create_dir(&dir).await?;
                let path = dir.join(format!("{}.rdp", file_stem(&name)));
                if let Err(err) = tokio::fs::write(&path, rdp_file_bytes(&file)).await {
                    let _ = tokio::fs::remove_dir_all(&dir).await;
                    return Err(err.into());
                }
                let started = tokio::process::Command::new(mstsc_path()).arg(&path).spawn();
                let child = match started {
                    Ok(child) => child,
                    Err(err) => {
                        let _ = tokio::fs::remove_dir_all(&dir).await;
                        return Err(CoreError::Console(format!("mstsc.exe could not be started: {err}")));
                    }
                };
                // Read by mstsc as it starts; gone soon after, whatever happens next.
                tokio::spawn(async move {
                    tokio::time::sleep(RDP_FILE_KEPT).await;
                    if let Err(err) = tokio::fs::remove_dir_all(&dir).await {
                        tracing::warn!(error = %err, "could not delete a remote desktop file");
                    }
                });
                Ok(Box::new(Child(child)))
            }
            Launch::Viewer { exe, args } => {
                let child = tokio::process::Command::new(&exe).args(&args).spawn().map_err(|err| {
                    CoreError::Console(format!("The VNC viewer {} could not be started: {err}", exe.display()))
                })?;
                Ok(Box::new(Child(child)))
            }
        }
    }
}

/// SS-12, under the `fakes` feature (tests only): the default refuses, so a test that forgot its
/// [`crate::fakes::FakeLauncher`] fails instead of starting a real program.
pub struct NoLauncher;

#[async_trait]
impl ConsoleLauncher for NoLauncher {
    async fn launch(&self, _launch: Launch) -> Result<Box<dyn LaunchedWindow>> {
        Err(CoreError::Console(
            "tests start no programs: give the terminals a FakeLauncher".into(),
        ))
    }
}

/// The VNC viewers Remotely knows, for their arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Viewer {
    TigerVnc,
    TightVnc,
    RealVnc,
    UltraVnc,
}

impl Viewer {
    /// Which viewer a path is, by its folder and file name; an unknown `vncviewer.exe` is taken as TigerVNC's.
    pub fn of(path: &Path) -> Viewer {
        let text = path.display().to_string().to_ascii_lowercase();
        if text.contains("tvnviewer") || text.contains("tightvnc") {
            Viewer::TightVnc
        } else if text.contains("realvnc") || text.contains("vnc-viewer") {
            Viewer::RealVnc
        } else if text.contains("ultravnc") || text.contains("uvnc") {
            Viewer::UltraVnc
        } else {
            Viewer::TigerVnc
        }
    }

    /// The viewer's arguments: its options, then `host::port` (two colons: a port, not a display number).
    pub fn args(self, host: &str, port: u16, view_only: bool) -> Vec<String> {
        let mut args = Vec::new();
        if view_only {
            args.push(match self {
                Viewer::TigerVnc | Viewer::RealVnc => "-ViewOnly".to_owned(),
                Viewer::TightVnc | Viewer::UltraVnc => "-viewonly".to_owned(),
            });
        }
        // An IPv6 address in brackets, as everywhere else: `[2001:db8::5]::5900`.
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        args.push(format!("{host}::{port}"));
        args
    }
}

/// Where the viewers install by themselves, under `Program Files` (and its x86 twin).
const VIEWER_FOLDERS: [&str; 6] = [
    r"TigerVNC\vncviewer.exe",
    r"TightVNC\tvnviewer.exe",
    r"RealVNC\VNC Viewer\vncviewer.exe",
    r"uvnc bvba\UltraVNC\vncviewer.exe",
    r"UltraVNC\vncviewer.exe",
    r"uvnc\UltraVNC\vncviewer.exe",
];

/// SS-12: finds the VNC viewer like the other tools: the path saved in Settings, then `REMOTELY_VNC_VIEWER`, then
/// each viewer's default folder.
pub fn locate_vnc_viewer(saved: Option<&Path>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(saved.map(Path::to_path_buf));
    candidates.extend(std::env::var_os("REMOTELY_VNC_VIEWER").map(PathBuf::from));
    let mut roots: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(dir) = std::env::var_os(var) {
            roots.push(PathBuf::from(dir));
        }
    }
    roots.push(PathBuf::from(r"C:\Program Files"));
    for root in &roots {
        for folder in VIEWER_FOLDERS {
            candidates.push(root.join(folder));
        }
    }
    candidates
        .into_iter()
        .find(|p| crate::untrusted::path_refusal(p).is_none() && p.is_file())
}

/// SS-12: a path saved in Settings must be an existing `.exe` of a VNC viewer on this PC (not on a share).
pub fn validate_vnc_viewer_path(path: &Path) -> Result<()> {
    if let Some(why) = crate::untrusted::path_refusal(path) {
        return Err(CoreError::InvalidSetting(format!(
            "{} {}: choose a viewer installed on this PC",
            path.display(),
            why.describe()
        )));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if !name.ends_with(".exe") || !name.contains("vnc") || !path.is_file() {
        return Err(CoreError::InvalidSetting(format!(
            "{} is not a VNC viewer. TigerVNC's is vncviewer.exe, TightVNC's tvnviewer.exe",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_viewer_gets_its_own_view_only_switch() {
        assert_eq!(
            Viewer::of(Path::new(r"C:\Program Files\TigerVNC\vncviewer.exe")).args("vnc01.example.com", 5901, true),
            ["-ViewOnly", "vnc01.example.com::5901"]
        );
        assert_eq!(
            Viewer::of(Path::new(r"C:\Program Files\TightVNC\tvnviewer.exe")).args("192.0.2.5", 5900, true),
            ["-viewonly", "192.0.2.5::5900"]
        );
        assert_eq!(
            Viewer::of(Path::new(r"C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe")),
            Viewer::UltraVnc
        );
        assert_eq!(
            Viewer::of(Path::new(r"C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe")),
            Viewer::RealVnc
        );
        assert_eq!(Viewer::TigerVnc.args("127.0.0.1", 50123, false), ["127.0.0.1::50123"]);
        // IPv6 in brackets, never `2001:db8::5::5900`.
        assert_eq!(
            Viewer::TigerVnc.args("2001:db8::5", 5900, false),
            ["[2001:db8::5]::5900"]
        );
        assert_eq!(
            Viewer::TigerVnc.args("[2001:db8::5]", 5900, false),
            ["[2001:db8::5]::5900"]
        );
    }

    #[test]
    fn rdp_files_are_utf16_with_crlf() {
        let bytes = rdp_file_bytes("username:s:Zoë\n");
        assert_eq!(&bytes[..2], [0xFF, 0xFE]);
        let units: Vec<u16> = bytes[2..].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "username:s:Zoë\r\n");
    }

    #[test]
    fn file_names_come_from_the_session_name() {
        assert_eq!(file_stem("win01 (Prod)"), "win01__Prod_");
        assert_eq!(file_stem("..\\..\\x"), "_.._x");
        assert_eq!(file_stem("..."), "remote-desktop");
        // A DOS device's name would open the device, not a file.
        for device in ["NUL", "con", "COM1", "lpt3", "AUX.backup"] {
            let stem = file_stem(device);
            assert!(stem.starts_with("remote-desktop-"), "{device}: {stem}");
            assert!(!crate::untrusted::is_device_name(&format!("{stem}.rdp")), "{stem}");
        }
        assert_eq!(file_stem("console"), "console");
    }

    #[test]
    fn a_viewer_path_must_be_a_vnc_exe_here() {
        let dir = std::env::temp_dir().join(format!("remotely-vnc-path-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let viewer = dir.join("vncviewer.exe");
        let other = dir.join("notepad.exe");
        std::fs::write(&viewer, b"").unwrap();
        std::fs::write(&other, b"").unwrap();
        assert!(validate_vnc_viewer_path(&viewer).is_ok());
        assert!(validate_vnc_viewer_path(&other).is_err());
        assert!(
            validate_vnc_viewer_path(&dir.join("tvnviewer.exe")).is_err(),
            "not there"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
