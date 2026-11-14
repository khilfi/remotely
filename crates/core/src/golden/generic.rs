//! VM-30: making a freshly installed system generic, so each clone of its snapshot is a machine of its own. Pure: the
//! scripts the build runs on the build VM, and how their reports read. "Golden image builds (G7)" in CLAUDE.md says
//! what each step is for and what was seen by hand.
//!
//! * Linux ([`LINUX_SCRIPT`], run as root through the config user's sudo over SSH): each step a function that says
//!   `ok <step>` or `failed <step>`, and the script stops at the first that fails ([`LINUX_STEPS`]: every one must say
//!   `ok`, else the build fails and keeps the VM, running). `boot` waits (time-limited) for the first boot's own work:
//!   systemd's start-up, cloud-init's stages and any package job (`apt`, `apt-get` and `dpkg` by name, and
//!   `unattended-upgrade` by its command line: unattended-upgrades.service's shutdown helper runs for as long as the
//!   system is up and has the same 15-character name). `cloud_init` turns cloud-init back on and makes it as if it
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
//!   Setup's copies of the answer file, PowerShell's history and the event logs, each checked gone (else it stops
//!   with `failed <what>`), then runs `sysprep /generalize /oobe /quit /quiet` and shuts Windows down itself only once
//!   sysprep returned 0 and left `Sysprep_succeeded.tag` (`sealed`). With `/shutdown` the shutdown could end
//!   sysprep.exe before its exit code was read, and a power-off during sysprep would look like its own. Its steps go
//!   to COM1 as `remotely-generic ...` lines; the build takes the power-off as sealed only after `sealed`
//!   ([`WINDOWS_STEPS`]).

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
/// Windows: what the task must say on COM1 before the power-off counts as sysprep's: the build's listener gone,
/// sysprep started, and sysprep done (exit 0 and its `Sysprep_succeeded.tag`) before the task shut Windows down.
pub const WINDOWS_STEPS: [&str; 3] = ["removed winrm-https", "sysprep", "sealed"];

/// Linux: run as root (`sudo sh -c`). Each step says `ok` or `failed`; the first that fails ends it (exit 0, so its
/// report comes back), and `done` comes only when every step went.
pub const LINUX_SCRIPT: &str = r#"say() { printf 'remotely-generic %s\n' "$*"; }
run() { if "$1"; then say ok "$1"; else say failed "$1"; exit 0; fi; }
packages() {
  pgrep -x 'apt|apt-get|dpkg' >/dev/null 2>&1 && return 0
  pgrep -f '^/usr/bin/python3(\.[0-9]+)? /usr/bin/unattended-upgrade( |$)' >/dev/null 2>&1
}
boot() {
  t0=$(date +%s)
  if command -v systemctl >/dev/null 2>&1; then timeout 600 systemctl is-system-running --wait >/dev/null 2>&1; [ $? -ne 124 ] || return 1; fi
  if command -v cloud-init >/dev/null 2>&1; then
    timeout 600 cloud-init status --wait >/dev/null 2>&1; rc=$?
    [ $rc -ne 124 ] || return 1
    [ $rc -eq 0 ] || say note "cloud-init's first boot ended with status $rc"
  fi
  n=0
  while packages; do
    n=$((n+1)); [ $n -lt 120 ] || return 1; sleep 5
  done
  say waited $(( $(date +%s) - t0 ))
  return 0
}
cloud_init() {
  if ! command -v cloud-init >/dev/null 2>&1; then say cloud-init no; return 0; fi
  say cloud-init yes
  rm -f /etc/cloud/cloud-init.disabled
  for f in /etc/cloud/cloud.cfg.d/99-installer.cfg /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg /etc/cloud/cloud.cfg.d/90-installer-network.cfg; do
    if [ -e "$f" ]; then rm -f "$f"; [ ! -e "$f" ] || return 1; say removed "$f"; fi
  done
  cloud-init clean --logs >/dev/null 2>&1 || return 1
  rm -rf /var/lib/cloud/seed
  [ ! -e /var/lib/cloud/seed ] || return 1
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
  for f in /root/.bash_history /home/*/.bash_history; do
    [ -e "$f" ] || continue
    rm -f "$f" && [ ! -e "$f" ] || return 1
  done
  return 0
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
function Stop-Here($t) { Say ('failed ' + $t); exit 1 }
Unregister-ScheduledTask -TaskName 'Remotely generalize' -Confirm:$false -ErrorAction SilentlyContinue
Say 'started'
foreach ($l in @(Get-ChildItem WSMan:\localhost\Listener)) {
  if ($l.Keys -contains 'Transport=HTTPS') {
    $thumb = (Get-ChildItem -LiteralPath $l.PSPath | Where-Object { $_.Name -eq 'CertificateThumbprint' }).Value
    Remove-Item -LiteralPath $l.PSPath -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $l.PSPath) { Stop-Here 'winrm-https' }
    if ($thumb) {
      $cert = 'Cert:\LocalMachine\My\' + $thumb
      Remove-Item -LiteralPath $cert -DeleteKey -Force -ErrorAction SilentlyContinue
      if (Test-Path -LiteralPath $cert) { Stop-Here 'winrm-certificate' }
    }
    Say 'removed winrm-https'
  }
}
$panther = @('C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\unattend-original.xml')
foreach ($f in $panther) {
  if (Test-Path -LiteralPath $f) {
    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $f) { Stop-Here ('answer-file ' + $f) }
    Say ('removed ' + $f)
  }
}
Get-ChildItem -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
foreach ($log in @(wevtutil el)) { wevtutil cl "$log" 2>$null }
Say 'cleared event-logs'
Remove-Item -LiteralPath 'C:\Windows\Temp\remotely-generalize.ps1' -Force -ErrorAction SilentlyContinue
$tag = "$env:SystemRoot\System32\Sysprep\Sysprep_succeeded.tag"
Remove-Item -LiteralPath $tag -Force -ErrorAction SilentlyContinue
Say 'sysprep'
$s = Start-Process -FilePath "$env:SystemRoot\System32\Sysprep\sysprep.exe" -ArgumentList '/generalize', '/oobe', '/quit', '/quiet' -Wait -PassThru
Say ('sysprep-exit ' + $s.ExitCode)
if (($s.ExitCode -ne 0) -or -not (Test-Path -LiteralPath $tag)) { Say ('sysprep-failed ' + $s.ExitCode); exit 1 }
foreach ($f in $panther) {
  if (Test-Path -LiteralPath $f) {
    Say ('after-sysprep ' + $f)
    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $f) { Stop-Here ('answer-file ' + $f) }
  }
}
Say 'sealed'
Stop-Computer -Force
"#;

/// Windows: run over WinRM (one `powershell -Command -`, one line per statement: `Stop` ends only the line that
/// fails). It writes the task's script and registers the task to run a few seconds later (on battery power too), then
/// reports `remotely-generic scheduled` only once both the script's file and the task are there.
pub fn windows_script() -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(WINDOWS_TASK_BODY.as_bytes());
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $b = [Convert]::FromBase64String('{body}'); [IO.File]::WriteAllBytes('{WINDOWS_TASK_SCRIPT}', $b)\n\
         $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File {WINDOWS_TASK_SCRIPT}'\n\
         $t = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(15))\n\
         $o = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries\n\
         Register-ScheduledTask -TaskName '{WINDOWS_TASK}' -Action $a -Trigger $t -Settings $o -User 'SYSTEM' -RunLevel Highest -Force | Out-Null\n\
         if ((Test-Path -LiteralPath '{WINDOWS_TASK_SCRIPT}') -and (Get-ScheduledTask -TaskName '{WINDOWS_TASK}')) {{ '{REPORT_MARKER} scheduled' }}\n"
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

    /// Windows: why the task stopped before it shut Windows down, if it said so: a step whose item it couldn't remove
    /// (`failed <what>`), or sysprep's own failure (`sysprep-failed <code>`: an exit code other than 0, or 0 without
    /// `Sysprep_succeeded.tag`). With `/quit` sysprep always returns, so any such line is its own.
    pub fn windows_failure(&self) -> Option<String> {
        if let Some(what) = self.starts("failed ") {
            let what = match what {
                "winrm-https" => "the build's WinRM over HTTPS listener".to_owned(),
                "winrm-certificate" => "the listener's certificate and its private key".to_owned(),
                other => match other.strip_prefix("answer-file ") {
                    Some(file) => format!("Setup's copy of the answer file {file}"),
                    None => other.to_owned(),
                },
            };
            return Some(format!(
                "the task that runs sysprep couldn't remove {what}, so it didn't run sysprep: the VM is left running"
            ));
        }
        let code = self.starts("sysprep-failed")?;
        let what = if code == "0" {
            "sysprep returned 0 but left no Sysprep_succeeded.tag".to_owned()
        } else {
            format!("sysprep stopped with exit code {code}")
        };
        Some(format!(
            "{what}, so Windows wasn't shut down as sealed: its log is C:\\Windows\\System32\\Sysprep\\Panther\\setuperr.log"
        ))
    }

    /// The last line the task wrote, for a wait that ran out.
    pub fn last(&self) -> Option<&str> {
        self.lines.last().map(String::as_str)
    }

    /// Linux: what the build's note adds (`note <text>`: cloud-init's first boot ended with an error, say), and how
    /// long `boot` waited, in seconds (`waited <s>`).
    pub fn notes(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .lines
            .iter()
            .filter_map(|l| l.strip_prefix("note ").map(str::to_owned))
            .collect();
        if let Some(s) = self.starts("waited ").and_then(|s| s.parse::<u64>().ok()) {
            if s > 0 {
                out.push(format!("it waited {s} s for the first boot's own work"));
            }
        }
        out
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
        "bootWaitedSeconds": report.starts("waited ").and_then(|s| s.parse::<u64>().ok()),
        "removed": report.lines.iter().filter_map(|l| l.strip_prefix("removed ")).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A function's body in [`LINUX_SCRIPT`], from `name() {` to its closing line.
    fn function(name: &str) -> &'static str {
        let start = LINUX_SCRIPT.find(&format!("\n{name}() {{\n")).expect(name) + 1;
        let end = LINUX_SCRIPT[start..].find("\n}\n").expect(name) + start;
        &LINUX_SCRIPT[start..end]
    }

    /// The quoted pattern after `pgrep <flag> '` in `text`.
    fn pgrep_pattern<'a>(text: &'a str, flag: &str) -> &'a str {
        let at = text.find(&format!("pgrep {flag} '")).expect(flag) + flag.len() + 8;
        let end = text[at..].find('\'').expect(flag) + at;
        &text[at..end]
    }

    #[test]
    fn the_linux_script_covers_every_step_and_says_each() {
        for step in [
            "timeout 600 systemctl is-system-running --wait",
            "timeout 600 cloud-init status --wait",
            "say note \"cloud-init's first boot ended with status $rc\"",
            "rm -f /etc/cloud/cloud-init.disabled",
            "99-installer.cfg",
            "subiquity-disable-cloudinit-networking.cfg",
            "rm -f \"$f\"; [ ! -e \"$f\" ] || return 1; say removed \"$f\"",
            "cloud-init clean --logs >/dev/null 2>&1 || return 1",
            "[ ! -e /var/lib/cloud/seed ] || return 1",
            "[ ! -e /etc/cloud/cloud-init.disabled ] || return 1",
            "[ -z \"$(ls -A /var/lib/cloud/instances 2>/dev/null)\" ]",
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
    fn boot_waits_for_package_work_but_not_for_unattended_upgrades_shutdown_helper() {
        // N1 of PR 100's second review. procps' pgrep -x matches `^(pattern)$` against the process name (at most 15
        // characters), pgrep -f the pattern against the whole command line, both as extended regular expressions.
        let packages = function("packages");
        let by_name = regex::Regex::new(&format!("^({})$", pgrep_pattern(packages, "-x"))).unwrap();
        let by_line = regex::Regex::new(pgrep_pattern(packages, "-f")).unwrap();
        let busy = |name: &str, line: &str| by_name.is_match(name) || by_line.is_match(line);
        // unattended-upgrades.service's helper, a python script whose name is cut to `unattended-upgr`, runs for as
        // long as the system is up: never package work.
        assert!(!busy(
            "unattended-upgr",
            "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal"
        ));
        assert!(!busy("sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"));
        assert!(!busy(
            "apt.systemd.dai",
            "/bin/sh /usr/lib/apt/apt.systemd.daily update"
        ));
        // Real package work.
        for (name, line) in [
            ("apt-get", "apt-get -qq -y update"),
            ("apt", "apt install -y nginx"),
            ("dpkg", "/usr/bin/dpkg --status-fd 23 --configure --pending"),
            ("unattended-upgr", "/usr/bin/python3 /usr/bin/unattended-upgrade"),
            (
                "unattended-upgr",
                "/usr/bin/python3 /usr/bin/unattended-upgrade --download-only",
            ),
        ] {
            assert!(busy(name, line), "{line}");
        }
        let boot = function("boot");
        assert!(boot.contains("while packages; do"), "{boot}");
        assert!(boot.contains("say waited"), "{boot}");
        assert!(!LINUX_SCRIPT.contains("unattended-upgr'"), "never by its cut name");
    }

    #[test]
    fn each_linux_step_checks_what_it_removed() {
        // N7 of PR 100's second review: a leftover is the step's failure, each file looked at on its own.
        let history = function("history");
        assert!(
            history.contains("for f in /root/.bash_history /home/*/.bash_history; do"),
            "{history}"
        );
        assert!(
            history.contains("rm -f \"$f\" && [ ! -e \"$f\" ] || return 1"),
            "{history}"
        );
        assert!(!history.contains("! ls"), "{history}");
        let cloud = function("cloud_init");
        assert!(cloud.contains("[ ! -e \"$f\" ] || return 1"), "{cloud}");
        assert!(cloud.contains("[ ! -e /var/lib/cloud/seed ] || return 1"), "{cloud}");
    }

    #[test]
    fn the_windows_script_writes_a_task_that_runs_sysprep_after_the_winrm_run() {
        let script = windows_script();
        assert!(script.contains("Register-ScheduledTask -TaskName 'Remotely generalize'"));
        assert!(script.contains("-User 'SYSTEM'"));
        assert!(script.contains("-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries"));
        assert!(
            script.starts_with("$ErrorActionPreference = 'Stop'\n"),
            "a failed registration stops its line"
        );
        // N6 of PR 100's second review: `Stop` ends only the line that fails, so the last line looks at both.
        assert!(script.ends_with(
            "if ((Test-Path -LiteralPath 'C:\\Windows\\Temp\\remotely-generalize.ps1') -and (Get-ScheduledTask -TaskName 'Remotely generalize')) { 'remotely-generic scheduled' }\n"
        ));
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
            "-Wait -PassThru",
            // N5: each removal said only once it is gone, else the task stops.
            "if (Test-Path -LiteralPath $l.PSPath) { Stop-Here 'winrm-https' }",
            "if (Test-Path -LiteralPath $cert) { Stop-Here 'winrm-certificate' }",
            "if (Test-Path -LiteralPath $f) { Stop-Here ('answer-file ' + $f) }",
            // N8: sysprep returns (/quit); sealed only on 0 and its tag; then the task shuts Windows down.
            "'/generalize', '/oobe', '/quit', '/quiet'",
            "Remove-Item -LiteralPath $tag",
            "Say ('sysprep-exit ' + $s.ExitCode)",
            "if (($s.ExitCode -ne 0) -or -not (Test-Path -LiteralPath $tag)) { Say ('sysprep-failed ' + $s.ExitCode); exit 1 }",
            "Say ('after-sysprep ' + $f)",
            "Say 'sealed'\nStop-Computer -Force\n",
        ] {
            assert!(body.contains(step), "{step}");
        }
        assert!(!body.contains("/shutdown"));
        assert!(!body.contains("\n\n"));
        let unregister = body.find("Unregister-ScheduledTask").unwrap();
        let sysprep = body.find("Sysprep\\sysprep.exe").unwrap();
        let sealed = body.find("Say 'sealed'").unwrap();
        let removed = body.find("Say 'removed winrm-https'").unwrap();
        assert!(unregister < sysprep, "the task is gone before sysprep runs");
        assert!(removed < sysprep && sysprep < sealed);
    }

    #[test]
    fn a_linux_report_is_whole_only_when_every_step_said_ok() {
        let mut whole = String::from("remotely-generic cloud-init yes\nremotely-generic waited 42\n");
        whole.push_str("remotely-generic note cloud-init's first boot ended with status 2\n");
        whole.push_str("remotely-generic removed /etc/cloud/cloud.cfg.d/99-installer.cfg\n");
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
        assert_eq!(
            report.notes(),
            [
                "cloud-init's first boot ended with status 2",
                "it waited 42 s for the first boot's own work"
            ]
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
        assert_eq!(
            facts(&report),
            serde_json::json!({
                "cloudInit": true,
                "vmTools": false,
                "bootWaitedSeconds": 42,
                "removed": ["/etc/cloud/cloud.cfg.d/99-installer.cfg"],
            })
        );
    }

    #[test]
    fn a_windows_report_is_sealed_only_after_sysprep_returned_0_and_any_failure_says_why() {
        let sealed = Report::parse(
            "\u{1b}[0mremotely-generic started\r\nremotely-generic removed winrm-https\r\nremotely-generic sysprep\r\nremotely-generic sysprep-exit 0\r\nremotely-generic sealed\r\n",
        );
        assert!(sealed.windows_missing().is_empty());
        assert_eq!(sealed.windows_failure(), None);
        let early = Report::parse("remotely-generic started\r\n");
        assert_eq!(early.windows_missing(), ["removed winrm-https", "sysprep", "sealed"]);
        // A power-off while sysprep runs (N8): sysprep started, never sealed.
        let cut = Report::parse("remotely-generic removed winrm-https\r\nremotely-generic sysprep\r\n");
        assert_eq!(cut.windows_missing(), ["sealed"]);
        assert_eq!(cut.last(), Some("sysprep"));
        // With /quit any sysprep-failed is sysprep's own: a code, or 0 without its tag.
        let failed = Report::parse("remotely-generic sysprep\r\nremotely-generic sysprep-failed 1\r\n");
        assert!(failed.windows_failure().unwrap().contains("exit code 1"));
        let untagged = Report::parse("remotely-generic sysprep\r\nremotely-generic sysprep-failed 0\r\n");
        assert!(untagged.windows_failure().unwrap().contains("no Sysprep_succeeded.tag"));
        // A removal that didn't go stops the task before sysprep (N5).
        let kept = Report::parse("remotely-generic started\r\nremotely-generic failed winrm-certificate\r\n");
        let why = kept.windows_failure().unwrap();
        assert!(
            why.contains("certificate") && why.contains("didn't run sysprep"),
            "{why}"
        );
    }
}
