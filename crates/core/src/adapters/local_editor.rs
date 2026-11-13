//! SS-08 (0.8.0 G4): the editor on this PC that "Edit on this PC" opens a host's file in, behind the [`LocalEditors`]
//! trait, so tests record what would open ([`crate::fakes::FakeLocalEditors`]) and never start a real editor.
//!
//! * **Which editor**: the one chosen in Settings' tools table, else `REMOTELY_LOCAL_EDITOR`, else VS Code (the user's
//!   install, then the machine's), Notepad++, then Notepad ([`locate_local_editor`]).
//! * **How**: the program itself with the file as an argument, never Windows' default "open" action for the file's
//!   type, which would run a `.bat`, `.ps1` or `.vbs` from the host. The program must be an `.exe` on this PC, and
//!   never one that runs what it is given (cmd, PowerShell, the script hosts: [`validate_local_editor_path`]); the
//!   file's path always starts with a drive letter, so no editor reads it as an option.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Serialize;

use crate::error::{CoreError, Result};

/// The editor's path chosen in Settings (`None`: find one). This PC's setting ([`crate::settings::MACHINE_KEYS`]).
pub const LOCAL_EDITOR_PATH_KEY: &str = "files.localEditorPath";

/// The editors Remotely knows by name, for how it opens two files to compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EditorKind {
    VsCode,
    NotepadPlusPlus,
    Notepad,
    Other,
}

impl EditorKind {
    /// By the program's file name.
    pub fn of(program: &Path) -> Self {
        let name = program
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        match name.as_str() {
            "code.exe" | "code - insiders.exe" | "vscodium.exe" => EditorKind::VsCode,
            "notepad++.exe" => EditorKind::NotepadPlusPlus,
            "notepad.exe" => EditorKind::Notepad,
            _ => EditorKind::Other,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            EditorKind::VsCode => "VS Code",
            EditorKind::NotepadPlusPlus => "Notepad++",
            EditorKind::Notepad => "Notepad",
            EditorKind::Other => "the editor chosen in Settings",
        }
    }

    /// Opens two files side by side as a diff ([`LocalEditors::open`] with `diff`).
    pub fn compares(self) -> bool {
        self == EditorKind::VsCode
    }
}

/// Programs that run what they are given: never an editor for a host's file.
const RUNNERS: [&str; 12] = [
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "explorer.exe",
    "conhost.exe",
    "wt.exe",
    "msiexec.exe",
];

/// Where the editors install by themselves: (the environment variable, the path under it).
const KNOWN_PLACES: [(&str, &str); 6] = [
    ("LOCALAPPDATA", r"Programs\Microsoft VS Code\Code.exe"),
    ("ProgramFiles", r"Microsoft VS Code\Code.exe"),
    ("ProgramFiles", r"Notepad++\notepad++.exe"),
    ("ProgramFiles(x86)", r"Notepad++\notepad++.exe"),
    ("SystemRoot", r"System32\notepad.exe"),
    ("SystemRoot", r"notepad.exe"),
];

/// SS-08: finds the editor like the other tools: the path saved in Settings, then `REMOTELY_LOCAL_EDITOR`, then VS
/// Code, Notepad++ and Notepad where they install. Only a usable `.exe` on this PC counts.
pub fn locate_local_editor(saved: Option<&Path>) -> Option<PathBuf> {
    if let Some(saved) = saved {
        // A chosen editor that is gone is not swapped for another one silently.
        return validate_local_editor_path(saved).is_ok().then(|| saved.to_path_buf());
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(std::env::var_os("REMOTELY_LOCAL_EDITOR").map(PathBuf::from));
    for (var, rest) in KNOWN_PLACES {
        if let Some(dir) = std::env::var_os(var) {
            candidates.push(PathBuf::from(dir).join(rest));
        }
    }
    candidates.into_iter().find(|p| validate_local_editor_path(p).is_ok())
}

/// SS-08: an editor's path must be an existing `.exe` on this PC (not on a share), and not a program that runs what it
/// is given.
pub fn validate_local_editor_path(path: &Path) -> Result<()> {
    if let Some(why) = crate::untrusted::path_refusal(path) {
        return Err(CoreError::InvalidSetting(format!(
            "{} {}: choose an editor installed on this PC",
            path.display(),
            why.describe()
        )));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if !path.is_absolute() || !name.ends_with(".exe") {
        return Err(CoreError::InvalidSetting(format!(
            "{} is not a program: give the full path of the editor's .exe, such as Code.exe or notepad++.exe",
            path.display()
        )));
    }
    if RUNNERS.contains(&name.as_str()) {
        return Err(CoreError::InvalidSetting(format!(
            "{} runs what it is given rather than editing it, so it can't open files from hosts",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(CoreError::InvalidSetting(format!("{} isn't there", path.display())));
    }
    Ok(())
}

/// What opens a downloaded copy in the editor.
#[async_trait]
pub trait LocalEditors: Send + Sync {
    /// Starts `program` on `files` (in its own window) and returns once it started; never waits for it to exit, since
    /// many editors hand the file to a window they already have and exit at once. `diff`: VS Code's `--diff` of the two
    /// files.
    async fn open(&self, program: &Path, files: &[PathBuf], diff: bool) -> Result<()>;
}

/// The real editors.
pub struct WindowsEditors;

#[async_trait]
impl LocalEditors for WindowsEditors {
    async fn open(&self, program: &Path, files: &[PathBuf], diff: bool) -> Result<()> {
        validate_local_editor_path(program)?;
        let mut command = std::process::Command::new(program);
        if diff && EditorKind::of(program).compares() && files.len() == 2 {
            command.arg("--diff");
        }
        for file in files {
            // Every copy lives in Remotely's own folder: a full path from a drive letter, so never an option.
            if !file.is_absolute() {
                return Err(CoreError::LocalEditor(format!(
                    "{} is not a full path, so it was not opened",
                    file.display()
                )));
            }
            command.arg(file);
        }
        // Not waited for, and not killed when Remotely drops it: the editor is the user's.
        command
            .spawn()
            .map(drop)
            .map_err(|err| CoreError::LocalEditor(format!("{} could not be started: {err}", program.display())))
    }
}

/// Under the `fakes` feature (tests only): the default refuses, so a test that forgot its
/// [`crate::fakes::FakeLocalEditors`] fails instead of starting a real editor.
pub struct NoEditors;

#[async_trait]
impl LocalEditors for NoEditors {
    async fn open(&self, _program: &Path, _files: &[PathBuf], _diff: bool) -> Result<()> {
        Err(CoreError::LocalEditor(
            "tests start no editors: give the terminals FakeLocalEditors".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editors_are_known_by_their_file_names() {
        assert_eq!(
            EditorKind::of(Path::new(
                r"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe"
            )),
            EditorKind::VsCode
        );
        assert_eq!(
            EditorKind::of(Path::new(r"C:\Program Files\Notepad++\notepad++.exe")),
            EditorKind::NotepadPlusPlus
        );
        assert_eq!(
            EditorKind::of(Path::new(r"C:\Windows\System32\notepad.exe")),
            EditorKind::Notepad
        );
        assert_eq!(
            EditorKind::of(Path::new(r"C:\Tools\sublime_text.exe")),
            EditorKind::Other
        );
        assert!(EditorKind::VsCode.compares() && !EditorKind::Notepad.compares());
    }

    #[test]
    fn only_an_editor_exe_on_this_pc_is_taken() {
        for refused in [
            r"\\server\share\Code.exe",
            r"\\?\C:\Tools\Code.exe",
            r"Code.exe",
            r"C:\Tools\edit.bat",
            r"C:\Tools\edit.ps1",
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\wscript.exe",
            r"C:\Windows\System32\mshta.exe",
        ] {
            assert!(validate_local_editor_path(Path::new(refused)).is_err(), "{refused}");
        }
        // A real program on this PC.
        let notepad = std::env::var_os("SystemRoot").map(|r| PathBuf::from(r).join(r"System32\notepad.exe"));
        if let Some(notepad) = notepad.filter(|p| p.is_file()) {
            assert!(validate_local_editor_path(&notepad).is_ok());
            assert_eq!(locate_local_editor(Some(&notepad)), Some(notepad));
        }
        // A chosen editor that is gone is not swapped for another.
        assert_eq!(locate_local_editor(Some(Path::new(r"C:\No\Such\Code.exe"))), None);
    }
}
