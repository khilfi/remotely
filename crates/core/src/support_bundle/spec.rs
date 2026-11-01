//! FD-04: what a support bundle collects ([`BundleSpec`], carried by `Command::SupportBundle`), its checks, its caps,
//! and the names each host's files get inside the zip. What is approved is what runs: the presets are expanded into
//! the spec's items before the bus rates them.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::presets::{self, HostKind, PresetId};
use crate::adapters::remote::ScriptKind;
use crate::command_bus::Rollout;
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::untrusted::{is_device_name, is_format_char};
use crate::vault::SecretId;

/// The most one file of a bundle keeps: a longer output or file is cut, and the manifest says so.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// The most one host adds to a bundle.
pub const MAX_HOST_BYTES: u64 = 100 * 1024 * 1024;
/// The most a whole bundle holds (before compression).
pub const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
/// The most commands and files one bundle collects from each host.
pub const MAX_ITEMS: usize = 100;
/// How long one command may run before it counts as timed out and the host goes on to its next item (a `df -h` on a
/// stale NFS mount never ends).
pub const COMMAND_LIMIT_SECS: u64 = 60;
/// How long reading one file may take (up to 10 MB over SFTP) before the host goes on to its next item.
pub const FILE_LIMIT_SECS: u64 = 180;
/// The longest command a bundle runs.
pub const MAX_COMMAND_BYTES: usize = 4 * 1024;
/// The longest file path a bundle reads.
pub const MAX_PATH_BYTES: usize = 1024;

/// One thing collected from each host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum BundleItem {
    /// A command the login shell runs (under sudo when the bundle says so); what it prints becomes a text file.
    Command { command: String },
    /// A file read over SFTP as the login user (never with sudo).
    File { path: String },
}

impl BundleItem {
    pub fn command(text: &str) -> Self {
        Self::Command {
            command: text.to_owned(),
        }
    }

    pub fn file(path: &str) -> Self {
        Self::File { path: path.to_owned() }
    }

    /// The command or the path, for messages and the manifest.
    pub fn text(&self) -> &str {
        match self {
            Self::Command { command } => command,
            Self::File { path } => path,
        }
    }
}

/// FD-04: a support bundle as approved: the items every host gives, how it connects, and where the zip goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleSpec {
    /// The presets the items came from (they are in `items` already), for the summary and the manifest.
    #[serde(default)]
    pub presets: Vec<PresetId>,
    /// The presets' items, then the custom commands and files, each once: what each Linux host (an SSH session) gives.
    pub items: Vec<BundleItem>,
    /// BX-13: the same for each Windows host (a WinRM session): the Windows presets' PowerShell reads, then custom
    /// PowerShell commands and files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows_items: Vec<BundleItem>,
    /// BX-07: the commands run under sudo. Files are read over SFTP as the login user all the same.
    #[serde(default)]
    pub sudo: bool,
    /// BX-07: the vault password sudo gets. `None`: each session's own login password.
    #[serde(default)]
    pub sudo_password_id: Option<SecretId>,
    /// SS-05 for bulk runs: trust (and save, audited) the key of a host never seen before.
    #[serde(default)]
    pub trust_new_host_keys: bool,
    /// Seconds each host may take for all its items; one that takes longer ends with what it gave so far.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// H9: one host first, and a stop after failures.
    #[serde(default)]
    pub rollout: Rollout,
    /// The zip's full path on this PC, from the shell's save dialog.
    pub output: String,
    /// The workspace's name when the bundle was asked for, for the manifest.
    #[serde(default)]
    pub workspace: String,
}

impl BundleSpec {
    /// The Linux hosts' commands, one per line: what the policy engine rates, as it rates a Compare hosts run.
    pub fn rated_script(&self) -> String {
        self.commands().collect::<Vec<_>>().join("\n")
    }

    /// BX-13: the commands hosts running `kind` get, one per line, for the policy engine.
    pub fn rated_script_for(&self, kind: ScriptKind) -> String {
        match kind {
            ScriptKind::Posix => self.rated_script(),
            ScriptKind::PowerShell => commands_of(&self.windows_items).collect::<Vec<_>>().join("\n"),
        }
    }

    /// What a host of `kind` gives.
    pub fn items_for(&self, kind: HostKind) -> &[BundleItem] {
        match kind {
            HostKind::Linux => &self.items,
            HostKind::Windows => &self.windows_items,
        }
    }

    pub fn commands(&self) -> impl Iterator<Item = &str> {
        commands_of(&self.items)
    }

    pub fn files(&self) -> impl Iterator<Item = &str> {
        files_of(&self.items)
    }

    /// BX-13: the Windows hosts' commands and files.
    pub fn windows_commands(&self) -> impl Iterator<Item = &str> {
        commands_of(&self.windows_items)
    }

    pub fn windows_files(&self) -> impl Iterator<Item = &str> {
        files_of(&self.windows_items)
    }

    /// What it collects in words: "System, Logs, 2 more commands and 1 file".
    pub fn describe(&self) -> String {
        let preset_items: HashSet<BundleItem> = self
            .presets
            .iter()
            .flat_map(|id| presets::preset(*id).items.iter().map(|item| item.item()))
            .collect();
        let mut parts: Vec<String> = self
            .presets
            .iter()
            .map(|id| presets::preset(*id).label.to_owned())
            .collect();
        let extra = |kind: fn(&BundleItem) -> bool| {
            self.items
                .iter()
                .chain(&self.windows_items)
                .filter(|item| kind(item) && !preset_items.contains(*item))
                .count()
        };
        let more = if parts.is_empty() { "" } else { "more " };
        let commands = extra(|item| matches!(item, BundleItem::Command { .. }));
        let files = extra(|item| matches!(item, BundleItem::File { .. }));
        if commands > 0 {
            parts.push(count(commands, &format!("{more}command"), &format!("{more}commands")));
        }
        if files > 0 {
            parts.push(count(files, "file", "files"));
        }
        match parts.len() {
            0 => "nothing".to_owned(),
            1 => parts.remove(0),
            n => format!("{} and {}", parts[..n - 1].join(", "), parts[n - 1]),
        }
    }

    /// For the audit log, kept for good: no secret typed into a command.
    pub fn summary(&self, hosts: usize) -> String {
        let (what, _) = redact_secrets(&self.describe());
        format!(
            "Collect a support bundle ({what}) from {}",
            count(hosts, "host", "hosts")
        )
    }

    /// The spec as the job journal keeps it: what looks like a secret in a command is `[redacted]`
    /// ([`redact_secrets`]). Returns whether anything was.
    pub fn for_journal(&self) -> (Self, bool) {
        let mut kept = self.clone();
        let mut changed = false;
        for item in kept.items.iter_mut().chain(kept.windows_items.iter_mut()) {
            if let BundleItem::Command { command } = item {
                let (clean, was) = redact_secrets(command);
                if was {
                    *command = clean;
                    changed = true;
                }
            }
        }
        (kept, changed)
    }

    /// Checks what the caller gave, before any target is looked up.
    pub fn validate(&self, targets: &[TargetRef]) -> Result<()> {
        let invalid = |message: String| Err(CoreError::InvalidInput(message));
        if targets.iter().any(|t| !matches!(t, TargetRef::Session { .. })) {
            return invalid("A support bundle collects from saved sessions.".into());
        }
        if self.items.is_empty() && self.windows_items.is_empty() {
            return invalid("Choose a preset, or add a command or a file to collect.".into());
        }
        // BX-13: each kind of host is capped on its own: a host gets one list.
        for (items, windows) in [(&self.items, false), (&self.windows_items, true)] {
            if items.len() > MAX_ITEMS {
                return invalid(format!("A bundle collects at most {MAX_ITEMS} commands and files."));
            }
            let mut seen = HashSet::new();
            for item in items {
                match item {
                    BundleItem::Command { command } => check_command(command)?,
                    BundleItem::File { path } if windows => check_windows_path(path)?,
                    BundleItem::File { path } => check_path(path)?,
                }
                if !seen.insert(item) {
                    return invalid(format!("'{}' is listed twice.", item.text()));
                }
            }
        }
        let output = Path::new(&self.output);
        let zip = output.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip"));
        if !output.is_absolute() || !zip {
            return invalid(format!("'{}' is not a full path to a .zip file.", self.output));
        }
        crate::command_bus::validate_timeout(self.timeout_secs)?;
        self.rollout.validate()
    }
}

fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// A command a host's shell can take.
pub fn check_command(command: &str) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    if command.trim().is_empty() {
        return invalid("A command is empty.".into());
    }
    if command.len() > MAX_COMMAND_BYTES {
        return invalid(format!("A command can be at most {} KB.", MAX_COMMAND_BYTES / 1024));
    }
    if command.contains('\0') {
        return invalid("A command can't hold NUL characters.".into());
    }
    Ok(())
}

/// A file path on a host: absolute, one line, not a folder.
pub fn check_path(path: &str) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    if !path.starts_with('/') {
        return invalid(format!(
            "'{path}' is not a full path on the host (it must start with /)."
        ));
    }
    if path.ends_with('/') {
        return invalid(format!("'{path}' is a folder: name the files in it."));
    }
    if path.len() > MAX_PATH_BYTES || path.contains(['\0', '\n', '\r']) {
        return invalid("A file path can't hold line breaks and is at most 1 KB.".into());
    }
    Ok(())
}

/// BX-13: a file path on a Windows host: a drive's full path (`C:\Windows\Logs\x.log`), one line, not a folder. Never a
/// share (`\\server\share`) or a device path (`\\?\`, `\\.\`): the host would reach another computer, or a device,
/// with the sign-in's rights.
pub fn check_windows_path(path: &str) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    let mut chars = path.chars();
    let drive = matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(d), Some(':'), Some('\\' | '/')) if d.is_ascii_alphabetic()
    );
    if !drive {
        return invalid(format!(
            "'{path}' is not a full path on the Windows host (it must start with a drive, as C:\\)."
        ));
    }
    if path.ends_with(['\\', '/']) {
        return invalid(format!("'{path}' is a folder: name the files in it."));
    }
    if path.len() > MAX_PATH_BYTES || path.chars().any(|c| c.is_control()) {
        return invalid("A file path can't hold line breaks and is at most 1 KB.".into());
    }
    if path.contains(['*', '?', '<', '>', '|', '"']) || path[2..].contains(':') {
        return invalid(format!("'{path}' holds characters a Windows file name can't."));
    }
    Ok(())
}

fn commands_of(items: &[BundleItem]) -> impl Iterator<Item = &str> {
    items.iter().filter_map(|item| match item {
        BundleItem::Command { command } => Some(command.as_str()),
        BundleItem::File { .. } => None,
    })
}

fn files_of(items: &[BundleItem]) -> impl Iterator<Item = &str> {
    items.iter().filter_map(|item| match item {
        BundleItem::File { path } => Some(path.as_str()),
        BundleItem::Command { .. } => None,
    })
}

/// A name Windows (and every zip tool) can make a file or folder of: no `<>:"/\|?*`, control or invisible
/// format characters, no `.` or `..`, no trailing dot or space, no device name, at most 100 characters. Empty:
/// `fallback`.
pub fn safe_name(text: &str, fallback: &str) -> String {
    if matches!(text.trim(), "" | "." | "..") {
        return fallback.to_owned();
    }
    let name: String = text
        .chars()
        .map(|c| {
            if c.is_control() || is_format_char(c) || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            {
                '_'
            } else {
                c
            }
        })
        .take(100)
        .collect();
    let name = name.trim_start();
    // Windows drops a trailing dot or space, so two names could become one.
    let kept = name.trim_end_matches([' ', '.']);
    let name = format!("{kept}{}", "_".repeat(name.len() - kept.len()));
    if is_device_name(&name) {
        format!("_{name}")
    } else {
        name
    }
}

/// A command as a file name: its words in lower case joined by `-` (`uname -a` is `uname-a`), at most 60
/// characters.
fn command_slug(command: &str) -> String {
    let mut slug = String::new();
    for c in command.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
        if slug.len() >= 60 {
            break;
        }
    }
    let slug = slug.trim_end_matches('-').to_owned();
    if slug.is_empty() {
        "command".to_owned()
    } else {
        slug
    }
}

/// Where each item goes in its host's folder, in the items' order: `commands/uname-a.txt`,
/// `files/etc/os-release`. Every name is a safe one ([`safe_name`]), and two items never share one.
pub fn entry_names(items: &[BundleItem]) -> Vec<String> {
    let mut taken = HashSet::new();
    items
        .iter()
        .map(|item| {
            let base = match item {
                BundleItem::Command { command } => format!("commands/{}", command_slug(command)),
                BundleItem::File { path } => {
                    // BX-13: a Windows host's `C:\Windows\x.log` is `files/C_/Windows/x.log`.
                    let parts: Vec<String> = path
                        .split(['/', '\\'])
                        .filter(|p| !p.is_empty())
                        .map(|p| safe_name(p, "_"))
                        .collect();
                    format!("files/{}", parts.join("/"))
                }
            };
            let ext = if matches!(item, BundleItem::Command { .. }) {
                ".txt"
            } else {
                ""
            };
            unique(&mut taken, &base, ext)
        })
        .collect()
}

/// `base` + `ext`, or `base-2` + `ext` and so on when that is taken (letter case aside: Windows' folders ignore it).
pub(crate) fn unique(taken: &mut HashSet<String>, base: &str, ext: &str) -> String {
    let mut n = 1;
    loop {
        let name = if n == 1 {
            format!("{base}{ext}")
        } else {
            format!("{base}-{n}{ext}")
        };
        if taken.insert(name.to_lowercase()) {
            return name;
        }
        n += 1;
    }
}

/// The save dialog's choice as the bundle's path. A `.zip` is taken as chosen: the dialog asked before replacing a file
/// of that name. Another name gets `.zip` in place of its extension (`report.txt` is `report.zip`), which the dialog
/// never asked about, so a file there already is refused rather than replaced.
pub fn zip_path(chosen: &Path) -> Result<std::path::PathBuf> {
    if chosen.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip")) {
        return Ok(chosen.to_owned());
    }
    let mut path = chosen.to_owned();
    path.set_extension("zip");
    if path.exists() {
        return Err(CoreError::InvalidInput(format!(
            "{} is there already. Choose another name, or choose that file itself to replace it.",
            path.display()
        )));
    }
    Ok(path)
}

/// The zip's name the save dialog offers: `remotely-bundle-<workspace>-<UTC time>.zip`, the workspace's name made
/// safe for a file name (`remotely-bundle-Acme-Lab-20261101T143000Z.zip`). FD-03: `None` while presenting
/// (`remotely-bundle-20261101T143000Z.zip`): the save dialog is out of the masker's reach.
pub fn default_file_name(workspace: Option<&str>, now: time::OffsetDateTime) -> String {
    let workspace = workspace.map(|workspace| {
        let words: Vec<String> = workspace
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(str::to_owned)
            .collect();
        if words.is_empty() {
            "workspace-".to_owned()
        } else {
            format!("{}-", words.join("-").chars().take(40).collect::<String>())
        }
    });
    let workspace = workspace.unwrap_or_default();
    let now = now.to_offset(time::UtcOffset::UTC);
    format!(
        "remotely-bundle-{workspace}{:04}{:02}{:02}T{:02}{:02}{:02}Z.zip",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(items: Vec<BundleItem>) -> BundleSpec {
        BundleSpec {
            presets: Vec::new(),
            items,
            windows_items: Vec::new(),
            sudo: false,
            sudo_password_id: None,
            trust_new_host_keys: false,
            timeout_secs: None,
            rollout: Rollout::default(),
            output: if cfg!(windows) {
                r"C:\Users\alice\Documents\bundle.zip".into()
            } else {
                "/home/alice/bundle.zip".into()
            },
            workspace: "Lab".into(),
        }
    }

    fn session() -> Vec<TargetRef> {
        vec![TargetRef::Session {
            session_id: uuid::Uuid::nil(),
        }]
    }

    #[test]
    fn a_bundle_needs_items_sessions_and_a_zip_path() {
        assert!(spec(vec![BundleItem::command("uname -a")]).validate(&session()).is_ok());
        assert!(spec(vec![]).validate(&session()).is_err(), "nothing to collect");
        let vm = vec![TargetRef::Vm {
            vmx_path: r"C:\VMs\a\a.vmx".into(),
        }];
        assert!(spec(vec![BundleItem::command("uptime")]).validate(&vm).is_err());
        let twice = spec(vec![BundleItem::command("uptime"), BundleItem::command("uptime")]);
        assert!(twice.validate(&session()).is_err());
        let mut relative = spec(vec![BundleItem::command("uptime")]);
        relative.output = "bundle.zip".into();
        assert!(relative.validate(&session()).is_err());
        let mut not_zip = spec(vec![BundleItem::command("uptime")]);
        not_zip.output = not_zip.output.replace(".zip", ".txt");
        assert!(not_zip.validate(&session()).is_err());
        let many = spec(
            (0..=MAX_ITEMS)
                .map(|n| BundleItem::command(&format!("echo {n}")))
                .collect(),
        );
        assert!(many.validate(&session()).is_err());
    }

    #[test]
    fn commands_and_paths_are_checked() {
        assert!(check_command("  ").is_err());
        assert!(check_command("echo\0").is_err());
        assert!(check_command(&"x".repeat(MAX_COMMAND_BYTES + 1)).is_err());
        assert!(check_path("/etc/hosts").is_ok());
        assert!(check_path("etc/hosts").is_err(), "relative");
        assert!(check_path("/var/log/").is_err(), "a folder");
        assert!(check_path("/etc/a\nb").is_err());
    }

    #[test]
    fn each_item_gets_a_safe_name_of_its_own() {
        let items = vec![
            BundleItem::command("uname -a"),
            BundleItem::command("Uname  -A"),
            BundleItem::command("tail -n 1000 /var/log/syslog 2>/dev/null || tail -n 1000 /var/log/messages"),
            BundleItem::file("/etc/os-release"),
            BundleItem::file("/srv/app/../con.log"),
            BundleItem::file("/srv/a:b*c?.log"),
            BundleItem::command("!!"),
        ];
        assert_eq!(
            entry_names(&items),
            [
                "commands/uname-a.txt",
                "commands/uname-a-2.txt",
                "commands/tail-n-1000-var-log-syslog-2-dev-null-tail-n-1000-var-log-me.txt",
                "files/etc/os-release",
                "files/srv/app/_/_con.log",
                "files/srv/a_b_c_.log",
                "commands/command.txt",
            ]
        );
    }

    #[test]
    fn host_folder_names_are_safe_on_windows() {
        assert_eq!(safe_name("web01", "host"), "web01");
        assert_eq!(safe_name("db/primary", "host"), "db_primary");
        assert_eq!(safe_name("nul", "host"), "_nul");
        assert_eq!(safe_name("trailing. ", "host"), "trailing__");
        assert_eq!(safe_name("..", "host"), "host");
        assert_eq!(safe_name("", "host"), "host");
        assert_eq!(safe_name("evil\u{202e}txt", "host"), "evil_txt");
        assert_eq!(safe_name(&"a".repeat(300), "host").len(), 100);
    }

    #[test]
    fn a_name_that_isnt_a_zip_never_replaces_a_file_unasked() {
        let dir = std::env::temp_dir().join(format!("remotely-zip-path-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // Chosen as a .zip: the dialog asked about replacing it.
        std::fs::write(dir.join("old.zip"), b"x").unwrap();
        assert_eq!(zip_path(&dir.join("old.zip")).unwrap(), dir.join("old.zip"));
        assert_eq!(zip_path(&dir.join("new.ZIP")).unwrap(), dir.join("new.ZIP"));
        // `report.txt` becomes `report.zip`, which nobody was asked about.
        assert_eq!(zip_path(&dir.join("report")).unwrap(), dir.join("report.zip"));
        std::fs::write(dir.join("report.zip"), b"someone's report").unwrap();
        let err = zip_path(&dir.join("report.txt")).unwrap_err();
        assert!(err.to_string().contains("is there already"), "{err}");
        assert_eq!(std::fs::read(dir.join("report.zip")).unwrap(), b"someone's report");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_file_name_names_the_workspace_and_the_utc_time() {
        let at = time::macros::datetime!(2026-11-01 15:30:00 +01:00);
        assert_eq!(
            default_file_name(Some("Acme / Lab"), at),
            "remotely-bundle-Acme-Lab-20261101T143000Z.zip"
        );
        assert_eq!(
            default_file_name(Some("…"), at),
            "remotely-bundle-workspace-20261101T143000Z.zip"
        );
        assert_eq!(
            default_file_name(None, at),
            "remotely-bundle-20261101T143000Z.zip",
            "while presenting"
        );
    }

    #[test]
    fn the_summary_names_presets_and_extras_without_secrets() {
        let mut s = spec(
            presets::preset(PresetId::System)
                .items
                .iter()
                .map(|i| i.item())
                .chain([
                    BundleItem::command("mysql --password=hunter2 -e 'show status'"),
                    BundleItem::file("/etc/app.conf"),
                ])
                .collect(),
        );
        s.presets = vec![PresetId::System];
        assert_eq!(
            s.summary(3),
            "Collect a support bundle (System, 1 more command and 1 file) from 3 hosts"
        );
        let (kept, redacted) = s.for_journal();
        assert!(redacted);
        assert!(!serde_json::to_string(&kept).unwrap().contains("hunter2"));
        assert_eq!(spec(vec![BundleItem::command("uptime")]).describe(), "1 command");
    }
}
