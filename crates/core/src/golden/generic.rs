//! VM-30: making a freshly installed system generic, so each clone of its snapshot is a machine of its own. Pure: the
//! scripts the build runs on the build VM, and how their reports read. "Golden image builds (G7)" in CLAUDE.md says
//! what each step is for and what was seen by hand.
//!
//! * Linux ([`LINUX_SCRIPT`], run as root through the config user's sudo over SSH): cloud-init on again and as if it
//!   never ran (Ubuntu's installer turns it off with `/etc/cloud/cloud-init.disabled` and pins its datasource to
//!   `None` in `cloud.cfg.d/99-installer.cfg`, which would keep VM-22's seed from ever being read); `/etc/machine-id`
//!   emptied (systemd makes a new one at the next boot; deleting it would break units that bind it) and
//!   `/var/lib/dbus/machine-id` deleted (D-Bus falls back to `/etc/machine-id`); the SSH host keys deleted, with a
//!   oneshot unit that makes them again (`ssh-keygen -A`) before sshd starts, since Debian's and Ubuntu's sshd refuse
//!   to start without keys and only cloud-init would make them; the installer's logs deleted (Ubuntu keeps the
//!   rendered answer file, password hash and all, as `/var/log/installer/autoinstall-user-data`; Debian keeps its
//!   answers in `cdebconf/questions.dat`); the other logs, shell history and DHCP leases cleared. Then
//!   [`LINUX_POWER_OFF`] on its own, so the report comes back before sshd stops.
//! * Windows ([`windows_script`], over WinRM as the Administrator with the vault's password and the certificate the
//!   VM wrote to COM1): a scheduled task, as SYSTEM, a few seconds after the WinRM run ends (a process started from a
//!   WinRM shell is killed with the shell), deletes the build's WinRM over HTTPS listener and its certificate (each
//!   clone makes its own at its first sign-in and writes its fingerprint to COM1, as G6 checks), Setup's copies of the
//!   answer file, PowerShell's history and the event logs, then runs `sysprep /generalize /oobe /shutdown /quiet`.
//!   Its steps go to COM1 as `remotely-generic ...` lines, so a sysprep that fails says so on the serial log.

use base64::Engine;

/// The marker every report line starts with (stdout on Linux, COM1 on Windows).
pub const REPORT_MARKER: &str = "remotely-generic";
/// The scheduled task that generalizes a Windows build VM (it deletes itself before sysprep runs).
pub const WINDOWS_TASK: &str = "Remotely generalize";
/// Where the Windows task's script is written (it deletes itself before sysprep runs).
pub const WINDOWS_TASK_SCRIPT: &str = r"C:\Windows\Temp\remotely-generalize.ps1";
/// The oneshot unit that makes a clone's SSH host keys at its first boot.
pub const HOST_KEYS_UNIT: &str = "remotely-ssh-host-keys.service";

/// Linux: run as root (`sudo sh -c`). Every step says what it did on a line of its own; none stops the others.
pub const LINUX_SCRIPT: &str = r#"say() { printf 'remotely-generic %s\n' "$*"; }
if command -v cloud-init >/dev/null 2>&1; then
  say cloud-init yes
  if [ -e /etc/cloud/cloud-init.disabled ]; then rm -f /etc/cloud/cloud-init.disabled && say enabled cloud-init; fi
  for f in /etc/cloud/cloud.cfg.d/99-installer.cfg /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg /etc/cloud/cloud.cfg.d/90-installer-network.cfg; do
    if [ -e "$f" ]; then rm -f "$f" && say removed "$f"; fi
  done
  if cloud-init clean --logs >/dev/null 2>&1; then say cleaned cloud-init; else say failed cloud-init clean; fi
  rm -rf /var/lib/cloud/seed
else
  say cloud-init no
fi
if [ -e /etc/machine-id ]; then : > /etc/machine-id && say emptied /etc/machine-id; fi
if [ -e /var/lib/dbus/machine-id ] || [ -L /var/lib/dbus/machine-id ]; then rm -f /var/lib/dbus/machine-id && say removed /var/lib/dbus/machine-id; fi
cat > /etc/systemd/system/remotely-ssh-host-keys.service <<'UNIT'
[Unit]
Description=SSH host keys for a clone of a golden image (Remotely)
Before=ssh.service sshd.service
ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target ssh.service
UNIT
if systemctl enable remotely-ssh-host-keys.service >/dev/null 2>&1; then say made remotely-ssh-host-keys.service; else say failed remotely-ssh-host-keys.service; fi
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub && say removed ssh host keys
if [ -d /var/log/installer ]; then rm -rf /var/log/installer && say removed /var/log/installer; fi
rm -f /root/anaconda-ks.cfg /root/original-ks.cfg
journalctl --rotate >/dev/null 2>&1
journalctl --vacuum-time=1s >/dev/null 2>&1 && say vacuumed the journal
find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -delete 2>/dev/null
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null && say cleared /var/log
rm -f /root/.bash_history /home/*/.bash_history && say removed shell history
rm -f /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease /var/lib/dhcpcd/*.lease6 /var/lib/NetworkManager/*.lease 2>/dev/null
say removed DHCP leases
if command -v vmtoolsd >/dev/null 2>&1; then say vm-tools yes; else say vm-tools no; fi
sync
say done
"#;

/// Linux: the shutdown, run on its own after [`LINUX_SCRIPT`] (its answer may never come: sshd stops).
pub const LINUX_POWER_OFF: &str = "systemctl --no-block poweroff";

/// The script the Windows task runs as SYSTEM. No empty line (it is written to a file, but kept so in case it is ever
/// sent to a console that ends a statement there).
const WINDOWS_TASK_BODY: &str = r#"$ErrorActionPreference = 'Continue'
function Say($t) { try { $p = New-Object System.IO.Ports.SerialPort COM1,115200; $p.Open(); $p.WriteLine('remotely-generic ' + $t); $p.Close() } catch { } }
Unregister-ScheduledTask -TaskName 'Remotely generalize' -Confirm:$false -ErrorAction SilentlyContinue
Say 'started'
foreach ($l in @(Get-ChildItem WSMan:\localhost\Listener)) {
  if ($l.Keys -contains 'Transport=HTTPS') {
    $thumb = (Get-ChildItem -LiteralPath $l.PSPath | Where-Object { $_.Name -eq 'CertificateThumbprint' }).Value
    Remove-Item -LiteralPath $l.PSPath -Recurse -Force
    if ($thumb) { Remove-Item -LiteralPath ('Cert:\LocalMachine\My\' + $thumb) -Force -ErrorAction SilentlyContinue }
    Say 'removed winrm-https'
  }
}
foreach ($f in @('C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\unattend-original.xml')) {
  if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force; Say ('removed ' + $f) }
}
Get-ChildItem -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
foreach ($log in @(wevtutil el)) { wevtutil cl "$log" 2>$null }
Say 'cleared event-logs'
Remove-Item -LiteralPath 'C:\Windows\Temp\remotely-generalize.ps1' -Force -ErrorAction SilentlyContinue
Say 'sysprep'
$s = Start-Process -FilePath "$env:SystemRoot\System32\Sysprep\sysprep.exe" -ArgumentList '/generalize', '/oobe', '/shutdown', '/quiet' -Wait -PassThru
Say ('sysprep-failed ' + $s.ExitCode)
"#;

/// Windows: run over WinRM (one `powershell -Command -`, one line per statement). It writes the task's script and
/// registers the task to run a few seconds later, then reports `remotely-generic scheduled`.
pub fn windows_script() -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(WINDOWS_TASK_BODY.as_bytes());
    format!(
        "$b = [Convert]::FromBase64String('{body}'); [IO.File]::WriteAllBytes('{WINDOWS_TASK_SCRIPT}', $b)\n\
         $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File {WINDOWS_TASK_SCRIPT}'\n\
         $t = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(15))\n\
         Register-ScheduledTask -TaskName '{WINDOWS_TASK}' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null\n\
         '{REPORT_MARKER} scheduled'\n"
    )
}

/// What a generalization said, line by line (`remotely-generic <what>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub lines: Vec<String>,
}

impl Report {
    /// The report lines in `text` (a Linux run's stdout, or the Windows serial log's text).
    pub fn parse(text: &str) -> Self {
        let prefix = format!("{REPORT_MARKER} ");
        let lines = text
            .lines()
            .filter_map(|l| l.trim().split_once(&prefix).map(|(_, rest)| rest.trim().to_owned()))
            .filter(|l| !l.is_empty())
            .collect();
        Self { lines }
    }

    pub fn has(&self, line: &str) -> bool {
        self.lines.iter().any(|l| l == line)
    }

    fn starts(&self, prefix: &str) -> Option<&str> {
        self.lines.iter().find_map(|l| l.strip_prefix(prefix).map(str::trim))
    }

    /// Linux: the script ran to its end.
    pub fn finished(&self) -> bool {
        self.has("done")
    }

    /// Linux: whether the system has cloud-init (`None`: not said).
    pub fn cloud_init(&self) -> Option<bool> {
        self.starts("cloud-init ").map(|v| v == "yes")
    }

    /// Linux: whether the system has open-vm-tools (Workstation's first boot reads cloud-init's data through it).
    pub fn vm_tools(&self) -> Option<bool> {
        self.starts("vm-tools ").map(|v| v == "yes")
    }

    /// Steps that went wrong (`failed <what>`), and Windows' sysprep exit code (`sysprep-failed <code>`).
    pub fn failures(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .lines
            .iter()
            .filter_map(|l| l.strip_prefix("failed ").map(|w| format!("{w} didn't work")))
            .collect();
        if let Some(code) = self.starts("sysprep-failed") {
            out.push(format!(
                "sysprep stopped with exit code {code} without shutting Windows down: its log is C:\\Windows\\System32\\Sysprep\\Panther\\setuperr.log"
            ));
        }
        out
    }

    /// What was done, in words, for the build's note.
    pub fn done_text(&self) -> String {
        let mut done: Vec<&str> = self
            .lines
            .iter()
            .map(String::as_str)
            .filter(|l| {
                !l.starts_with("cloud-init ")
                    && !l.starts_with("vm-tools ")
                    && !l.starts_with("failed ")
                    && !matches!(*l, "done" | "scheduled" | "started" | "sysprep")
                    && !l.starts_with("sysprep-failed")
            })
            .collect();
        done.dedup();
        done.join(", ")
    }
}

/// The JSON facts a version keeps of what its generalization found.
pub fn facts(report: &Report) -> serde_json::Value {
    serde_json::json!({
        "cloudInit": report.cloud_init(),
        "vmTools": report.vm_tools(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_linux_script_covers_every_step_and_says_each() {
        for step in [
            "rm -f /etc/cloud/cloud-init.disabled",
            "99-installer.cfg",
            "subiquity-disable-cloudinit-networking.cfg",
            "cloud-init clean --logs",
            "rm -rf /var/lib/cloud/seed",
            ": > /etc/machine-id",
            "rm -f /var/lib/dbus/machine-id",
            "rm -f /etc/ssh/ssh_host_*_key",
            "ExecStart=/usr/bin/ssh-keygen -A",
            "Before=ssh.service sshd.service",
            "ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key",
            "systemctl enable remotely-ssh-host-keys.service",
            "rm -rf /var/log/installer",
            "journalctl --vacuum-time=1s",
            "truncate -s 0",
            "/root/.bash_history /home/*/.bash_history",
            "/var/lib/dhcp/*.leases",
            "say done",
        ] {
            assert!(LINUX_SCRIPT.contains(step), "{step}");
        }
        // Emptied, never deleted: systemd binds a new id over an empty file at the next boot.
        assert!(!LINUX_SCRIPT.contains("rm -f /etc/machine-id"));
        // The shutdown is its own run, after the report.
        assert!(!LINUX_SCRIPT.contains("poweroff"));
        assert_eq!(LINUX_POWER_OFF, "systemctl --no-block poweroff");
    }

    #[test]
    fn the_windows_script_writes_a_task_that_runs_sysprep_after_the_winrm_run() {
        let script = windows_script();
        assert!(script.contains("Register-ScheduledTask -TaskName 'Remotely generalize'"));
        assert!(script.contains("-User 'SYSTEM'"));
        assert!(script.ends_with("'remotely-generic scheduled'\n"));
        // One statement a line, and no empty line (a WinRM console ends a statement there).
        assert!(!script.contains("\n\n"));
        let encoded = script.split('\'').nth(1).unwrap();
        let body = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded).unwrap()).unwrap();
        assert_eq!(body, WINDOWS_TASK_BODY);
        for step in [
            "Transport=HTTPS",
            "Cert:\\LocalMachine\\My\\",
            "C:\\Windows\\Panther\\unattend-original.xml",
            "ConsoleHost_history.txt",
            "wevtutil cl",
            "'/generalize', '/oobe', '/shutdown', '/quiet'",
            "-Wait -PassThru",
            "sysprep-failed",
        ] {
            assert!(body.contains(step), "{step}");
        }
        assert!(!body.contains("\n\n"));
        let unregister = body.find("Unregister-ScheduledTask").unwrap();
        let sysprep = body.find("Sysprep\\sysprep.exe").unwrap();
        assert!(unregister < sysprep, "the task is gone before sysprep runs");
    }

    #[test]
    fn reports_read_their_lines_wherever_they_are() {
        let linux = Report::parse(
            "remotely-generic cloud-init yes\nremotely-generic enabled cloud-init\nremotely-generic removed /etc/cloud/cloud.cfg.d/99-installer.cfg\nnoise\nremotely-generic emptied /etc/machine-id\nremotely-generic vm-tools no\nremotely-generic done\n",
        );
        assert!(linux.finished());
        assert_eq!(linux.cloud_init(), Some(true));
        assert_eq!(linux.vm_tools(), Some(false));
        assert!(linux.failures().is_empty());
        assert_eq!(
            linux.done_text(),
            "enabled cloud-init, removed /etc/cloud/cloud.cfg.d/99-installer.cfg, emptied /etc/machine-id"
        );
        // Windows: the serial log, escapes and all.
        let windows = Report::parse(
            "\u{1b}[0mremotely-generic started\r\nremotely-generic sysprep\r\nremotely-generic sysprep-failed 1\r\n",
        );
        assert!(!windows.finished());
        assert!(
            windows.failures()[0].contains("exit code 1"),
            "{:?}",
            windows.failures()
        );
        let failed = Report::parse("remotely-generic failed cloud-init clean\n");
        assert_eq!(failed.failures(), ["cloud-init clean didn't work"]);
        assert_eq!(facts(&linux), serde_json::json!({"cloudInit": true, "vmTools": false}));
    }
}
