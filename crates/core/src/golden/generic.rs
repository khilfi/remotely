//! VM-30: making a freshly installed system generic, so each clone of its snapshot is a machine of its own. Pure: the
//! scripts the build runs on the build VM, and how their reports read. "Golden image builds (G7)" in CLAUDE.md says
//! what each step is for and what was seen by hand.
//!
//! * Linux ([`LINUX_SCRIPT`], run as root through the config user's sudo over SSH): each step a function that says
//!   `ok <step>` or `failed <step>`, and the script stops at the first that fails ([`LINUX_STEPS`]: every one must say
//!   `ok`, else the build fails and keeps the VM). `boot` waits (time-limited) for the first boot's own work: systemd's
//!   start-up, cloud-init's stages and any package job. `cloud_init` turns cloud-init back on and makes it as if it
//!   never ran (Ubuntu's installer turns it off with `/etc/cloud/cloud-init.disabled` and pins its datasource to `None`
//!   in `cloud.cfg.d/99-installer.cfg`, which would keep VM-22's seed from ever being read), then checks the marker and
//!   the instance state are gone. `machine_id` empties `/etc/machine-id` (systemd makes a new one at the next boot;
//!   deleting it would break units that bind it) and deletes `/var/lib/dbus/machine-id` (D-Bus falls back to
//!   `/etc/machine-id`). `host_keys` makes and enables a oneshot unit that makes the host keys again (`ssh-keygen -A`)
//!   before sshd starts, after cloud-init (whose ssh module makes them per instance when it runs), and only then
//!   deletes the keys, since Debian's and Ubuntu's sshd refuse to start without keys. `answer_files` deletes the
//!   installer's logs (Ubuntu keeps the rendered answer file, password hash and all, as
//!   `/var/log/installer/autoinstall-user-data`; Debian its answers in `cdebconf/questions.dat`) and empties debconf's
//!   `passwords.dat`. Then the other logs, shell history and DHCP leases. Then [`LINUX_POWER_OFF`] on its own, so the
//!   report comes back before sshd stops.
//! * Windows ([`windows_script`], over WinRM as the Administrator with the vault's password and the certificate the
//!   VM wrote to COM1): a scheduled task, as SYSTEM, a few seconds after the WinRM run ends (a process started from a
//!   WinRM shell is killed with the shell), deletes the build's WinRM over HTTPS listener and its certificate with its
//!   private key (each clone makes its own at its first sign-in and writes its fingerprint to COM1, as G6 checks),
//!   Setup's copies of the answer file, PowerShell's history and the event logs, then runs
//!   `sysprep /generalize /oobe /shutdown /quiet`. Its steps go to COM1 as `remotely-generic ...` lines; the build
//!   takes the power-off as sealed only after `sysprep`, and a sysprep that returns an error says so.

use base64::Engine;

/// The marker every report line starts with (stdout on Linux, COM1 on Windows).
pub const REPORT_MARKER: &str = "remotely-generic";
/// The scheduled task that generalizes a Windows build VM (it deletes itself before sysprep runs).
pub const WINDOWS_TASK: &str = "Remotely generalize";
/// Where the Windows task's script is written (it deletes itself before sysprep runs).
pub const WINDOWS_TASK_SCRIPT: &str = r"C:\Windows\Temp\remotely-generalize.ps1";
/// The oneshot unit that makes a clone's SSH host keys at its first boot.
pub const HOST_KEYS_UNIT: &str = "remotely-ssh-host-keys.service";
/// Linux: every step of [`LINUX_SCRIPT`], in order; each must say `ok`.
pub const LINUX_STEPS: [&str; 8] = [
    "boot",
    "cloud_init",
    "machine_id",
    "host_keys",
    "answer_files",
    "logs",
    "history",
    "leases",
];
/// Windows: what the task must say on COM1 before the power-off counts as sysprep's.
pub const WINDOWS_STEPS: [&str; 2] = ["removed winrm-https", "sysprep"];

/// Linux: run as root (`sudo sh -c`). Each step says `ok` or `failed`; the first that fails ends it (exit 0, so its
/// report comes back), and `done` comes only when every step went.
pub const LINUX_SCRIPT: &str = r#"say() { printf 'remotely-generic %s\n' "$*"; }
run() { if "$1"; then say ok "$1"; else say failed "$1"; exit 0; fi; }
boot() {
  if command -v systemctl >/dev/null 2>&1; then timeout 600 systemctl is-system-running --wait >/dev/null 2>&1; [ $? -ne 124 ] || return 1; fi
  if command -v cloud-init >/dev/null 2>&1; then timeout 600 cloud-init status --wait >/dev/null 2>&1; [ $? -ne 124 ] || return 1; fi
  n=0
  while pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null 2>&1; do
    n=$((n+1)); [ $n -lt 120 ] || return 1; sleep 5
  done
  return 0
}
cloud_init() {
  if ! command -v cloud-init >/dev/null 2>&1; then say cloud-init no; return 0; fi
  say cloud-init yes
  rm -f /etc/cloud/cloud-init.disabled
  for f in /etc/cloud/cloud.cfg.d/99-installer.cfg /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg /etc/cloud/cloud.cfg.d/90-installer-network.cfg; do
    if [ -e "$f" ]; then rm -f "$f" && say removed "$f"; fi
  done
  cloud-init clean --logs >/dev/null 2>&1 || return 1
  rm -rf /var/lib/cloud/seed
  [ ! -e /etc/cloud/cloud-init.disabled ] || return 1
  [ ! -e /var/lib/cloud/instance ] || return 1
  [ -z "$(ls -A /var/lib/cloud/instances 2>/dev/null)" ]
}
machine_id() {
  : > /etc/machine-id || return 1
  [ ! -s /etc/machine-id ] || return 1
  rm -f /var/lib/dbus/machine-id
  [ ! -e /var/lib/dbus/machine-id ] && [ ! -L /var/lib/dbus/machine-id ]
}
host_keys() {
  cat > /etc/systemd/system/remotely-ssh-host-keys.service <<'UNIT' || return 1
[Unit]
Description=SSH host keys for a clone of a golden image (Remotely)
After=cloud-init.service cloud-init-network.service
Before=ssh.service sshd.service
ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target ssh.service
UNIT
  systemctl enable remotely-ssh-host-keys.service >/dev/null 2>&1 || return 1
  systemctl is-enabled remotely-ssh-host-keys.service >/dev/null 2>&1 || return 1
  rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
  ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1
}
answer_files() {
  rm -rf /var/log/installer
  rm -f /root/anaconda-ks.cfg /root/original-ks.cfg
  if [ -f /var/cache/debconf/passwords.dat ]; then : > /var/cache/debconf/passwords.dat || return 1; fi
  [ ! -e /var/log/installer ]
}
logs() {
  if command -v journalctl >/dev/null 2>&1; then journalctl --rotate >/dev/null 2>&1; journalctl --vacuum-time=1s >/dev/null 2>&1; fi
  find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -delete 2>/dev/null
  find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null
  return 0
}
history() {
  rm -f /root/.bash_history /home/*/.bash_history
  ! ls /root/.bash_history /home/*/.bash_history >/dev/null 2>&1
}
leases() {
  rm -f /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease /var/lib/dhcpcd/*.lease6 /var/lib/NetworkManager/*.lease 2>/dev/null
  return 0
}
run boot
run cloud_init
run machine_id
run host_keys
run answer_files
run logs
run history
run leases
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
    if ($thumb) { Remove-Item -LiteralPath ('Cert:\LocalMachine\My\' + $thumb) -DeleteKey -Force -ErrorAction SilentlyContinue }
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
if ($s.ExitCode -ne 0) { Say ('sysprep-failed ' + $s.ExitCode) }
"#;

/// Windows: run over WinRM (one `powershell -Command -`, one line per statement). It writes the task's script and
/// registers the task to run a few seconds later (on battery power too), then reports `remotely-generic scheduled`
/// only once the task is there.
pub fn windows_script() -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(WINDOWS_TASK_BODY.as_bytes());
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $b = [Convert]::FromBase64String('{body}'); [IO.File]::WriteAllBytes('{WINDOWS_TASK_SCRIPT}', $b)\n\
         $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File {WINDOWS_TASK_SCRIPT}'\n\
         $t = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(15))\n\
         $o = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries\n\
         Register-ScheduledTask -TaskName '{WINDOWS_TASK}' -Action $a -Trigger $t -Settings $o -User 'SYSTEM' -RunLevel Highest -Force | Out-Null\n\
         if (Get-ScheduledTask -TaskName '{WINDOWS_TASK}') {{ '{REPORT_MARKER} scheduled' }}\n"
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

    /// Linux: what isn't done, in words: a step that failed, else the steps that never said `ok`. Empty only when
    /// every step of [`LINUX_STEPS`] went and the script ended.
    pub fn linux_problems(&self) -> Vec<String> {
        if let Some(step) = self.starts("failed ") {
            return vec![format!("the step that {} failed", step_words(step))];
        }
        let mut out: Vec<String> = LINUX_STEPS
            .iter()
            .filter(|s| !self.has(&format!("ok {s}")))
            .map(|s| format!("the step that {} didn't run", step_words(s)))
            .collect();
        if out.is_empty() && !self.finished() {
            out.push("the steps that make it generic didn't run to their end".into());
        }
        out
    }

    /// Windows: what the task must have said before the power-off is sysprep's, and didn't.
    pub fn windows_missing(&self) -> Vec<&'static str> {
        WINDOWS_STEPS.iter().copied().filter(|s| !self.has(s)).collect()
    }

    /// Linux: whether the system has cloud-init (`None`: not said).
    pub fn cloud_init(&self) -> Option<bool> {
        self.starts("cloud-init ").map(|v| v == "yes")
    }

    /// Linux: whether the system has open-vm-tools (Workstation's first boot reads cloud-init's data through it).
    pub fn vm_tools(&self) -> Option<bool> {
        self.starts("vm-tools ").map(|v| v == "yes")
    }

    /// Windows: sysprep's own error (`sysprep-failed <code>`, a code other than 0).
    pub fn sysprep_failed(&self) -> Option<String> {
        let code = self.starts("sysprep-failed")?;
        (code != "0").then(|| {
            format!(
                "sysprep stopped with exit code {code} without shutting Windows down: its log is C:\\Windows\\System32\\Sysprep\\Panther\\setuperr.log"
            )
        })
    }

    /// What was done, in words, for the build's note.
    pub fn done_text(&self) -> String {
        let mut done: Vec<String> = self
            .lines
            .iter()
            .filter_map(|l| {
                if let Some(step) = l.strip_prefix("ok ") {
                    return Some(step_words(step).to_owned());
                }
                (l.starts_with("removed ") || l.starts_with("cleared ")).then(|| l.clone())
            })
            .collect();
        done.dedup();
        done.join(", ")
    }
}

/// A Linux step in words.
fn step_words(step: &str) -> &str {
    match step {
        "boot" => "waited for the first boot to settle",
        "cloud_init" => "turned cloud-init back on and cleaned it",
        "machine_id" => "emptied the machine id",
        "host_keys" => "made the SSH host keys go and come back at each clone's first boot",
        "answer_files" => "deleted the installer's copies of the answer file",
        "logs" => "cleared the logs",
        "history" => "deleted the shell history",
        "leases" => "deleted the DHCP leases",
        other => other,
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
            "timeout 600 systemctl is-system-running --wait",
            "timeout 600 cloud-init status --wait",
            "pgrep -x 'apt|apt-get|dpkg|unattended-upgr'",
            "rm -f /etc/cloud/cloud-init.disabled",
            "99-installer.cfg",
            "subiquity-disable-cloudinit-networking.cfg",
            "cloud-init clean --logs >/dev/null 2>&1 || return 1",
            "[ ! -e /etc/cloud/cloud-init.disabled ] || return 1",
            "[ -z \"$(ls -A /var/lib/cloud/instances 2>/dev/null)\" ]",
            "rm -rf /var/lib/cloud/seed",
            ": > /etc/machine-id || return 1",
            "rm -f /var/lib/dbus/machine-id",
            "ExecStart=/usr/bin/ssh-keygen -A",
            "After=cloud-init.service cloud-init-network.service",
            "Before=ssh.service sshd.service",
            "ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key",
            "systemctl is-enabled remotely-ssh-host-keys.service >/dev/null 2>&1 || return 1",
            "rm -rf /var/log/installer",
            ": > /var/cache/debconf/passwords.dat",
            "journalctl --vacuum-time=1s",
            "truncate -s 0",
            "/root/.bash_history /home/*/.bash_history",
            "/var/lib/dhcp/*.leases",
            "say done",
        ] {
            assert!(LINUX_SCRIPT.contains(step), "{step}");
        }
        for step in LINUX_STEPS {
            assert!(LINUX_SCRIPT.contains(&format!("\nrun {step}\n")), "{step}");
            assert!(LINUX_SCRIPT.contains(&format!("\n{step}() {{\n")), "{step}");
        }
        // The keys go only once the unit that makes them again is enabled (A3 of PR 100's review).
        let enabled = LINUX_SCRIPT.find("systemctl is-enabled").unwrap();
        let removed = LINUX_SCRIPT.find("rm -f /etc/ssh/ssh_host_*_key").unwrap();
        assert!(enabled < removed);
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
        assert!(script.contains("-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries"));
        assert!(
            script.starts_with("$ErrorActionPreference = 'Stop'\n"),
            "a failed registration stops the run"
        );
        assert!(script
            .ends_with("if (Get-ScheduledTask -TaskName 'Remotely generalize') { 'remotely-generic scheduled' }\n"));
        // One statement a line, and no empty line (a WinRM console ends a statement there).
        assert!(!script.contains("\n\n"));
        let encoded = script.split('\'').nth(3).unwrap();
        let body = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded).unwrap()).unwrap();
        assert_eq!(body, WINDOWS_TASK_BODY);
        for step in [
            "Transport=HTTPS",
            "Cert:\\LocalMachine\\My\\",
            "-DeleteKey",
            "C:\\Windows\\Panther\\unattend-original.xml",
            "ConsoleHost_history.txt",
            "wevtutil cl",
            "'/generalize', '/oobe', '/shutdown', '/quiet'",
            "-Wait -PassThru",
            "if ($s.ExitCode -ne 0) { Say ('sysprep-failed '",
        ] {
            assert!(body.contains(step), "{step}");
        }
        assert!(!body.contains("\n\n"));
        let unregister = body.find("Unregister-ScheduledTask").unwrap();
        let sysprep = body.find("Sysprep\\sysprep.exe").unwrap();
        assert!(unregister < sysprep, "the task is gone before sysprep runs");
    }

    #[test]
    fn a_linux_report_is_whole_only_when_every_step_said_ok() {
        let mut whole = String::from("remotely-generic cloud-init yes\n");
        for step in LINUX_STEPS {
            whole.push_str(&format!("remotely-generic ok {step}\n"));
        }
        whole.push_str("remotely-generic vm-tools no\nremotely-generic done\n");
        let report = Report::parse(&whole);
        assert!(report.linux_problems().is_empty(), "{:?}", report.linux_problems());
        assert_eq!(report.cloud_init(), Some(true));
        assert_eq!(report.vm_tools(), Some(false));
        assert!(
            report.done_text().contains("emptied the machine id"),
            "{}",
            report.done_text()
        );
        // A failed step: the build fails, naming it.
        let failed = Report::parse(
            "remotely-generic ok boot\nremotely-generic ok cloud_init\nremotely-generic failed machine_id\n",
        );
        assert_eq!(failed.linux_problems(), ["the step that emptied the machine id failed"]);
        // A step that never said ok (a script cut short).
        let short = Report::parse("remotely-generic ok boot\n");
        assert!(
            short.linux_problems().iter().any(|p| p.contains("cloud-init")),
            "{:?}",
            short.linux_problems()
        );
        assert_eq!(facts(&report), serde_json::json!({"cloudInit": true, "vmTools": false}));
    }

    #[test]
    fn a_windows_report_needs_the_listener_gone_and_sysprep_started_and_only_an_error_code_fails() {
        let windows = Report::parse(
            "\u{1b}[0mremotely-generic started\r\nremotely-generic removed winrm-https\r\nremotely-generic sysprep\r\n",
        );
        assert!(windows.windows_missing().is_empty());
        assert_eq!(windows.sysprep_failed(), None);
        let early = Report::parse("remotely-generic started\r\n");
        assert_eq!(early.windows_missing(), ["removed winrm-https", "sysprep"]);
        let zero = Report::parse("remotely-generic sysprep\r\nremotely-generic sysprep-failed 0\r\n");
        assert_eq!(zero.sysprep_failed(), None, "0 is sysprep's own success");
        let failed = Report::parse("remotely-generic sysprep\r\nremotely-generic sysprep-failed 1\r\n");
        assert!(failed.sysprep_failed().unwrap().contains("exit code 1"));
    }
}
