//! BX-13: the policy engine's PowerShell rules, for Compare hosts runs on WinRM hosts, Type in all tabs on PowerShell
//! tabs and Windows support bundles. Like the shell rules (BX-06), they are data in [`super::PolicyRules`], editable
//! in Settings' approval rules under Advanced:
//!
//! * **Read-only commands**: a script whose every command is on the list (and none of them is a form that writes,
//!   [`writes`]) is read-only, Low. Entries name commands as PowerShell resolves them, never an alias; a multi-word
//!   entry matches the command and its first words (`route print`). Interpreters and command runners
//!   (`powershell`, `cmd`, `Invoke-Expression`, `Invoke-Command`, `Start-Process`, `Set-Alias`...: [`runs_anything`])
//!   can never be entries.
//! * **Dangerous commands**: named regular expressions, tested against the script as typed and against each command
//!   as the parser reads it ([`parse::PsCommand::line`]: an alias's command, quotes removed), so `rm -r` matches the
//!   `Remove-Item -Recurse` rule. A match is High.
//! * Anything else is "other", Medium, and so is anything the parser can't read ([`parse::PsScript::unreadable`]): it
//!   fails closed.

mod parse;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

pub(crate) use parse::{ArgKind, PsCommand};

use super::DangerousPattern;

/// BX-13: the PowerShell rules, beside the shell's in [`super::PolicyRules`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PowerShellRules {
    /// Named regular expressions; a PowerShell command that matches one is High.
    pub dangerous_commands: Vec<DangerousPattern>,
    /// Commands (and their first words) that only read, by the names PowerShell resolves: `Get-Service`, `ipconfig`,
    /// `route print`.
    pub read_only_commands: Vec<String>,
}

impl Default for PowerShellRules {
    fn default() -> Self {
        Self {
            dangerous_commands: default_dangerous_patterns(),
            read_only_commands: default_read_only_commands(),
        }
    }
}

/// The start of a command: the line's start, a space, a separator, a bracket or a path's separator.
const S: &str = r"(?:^|[\s;|&({\\/])";
/// The end of a command's name: the line's end, a space, a separator or a bracket.
const E: &str = r"(?:$|[\s;|&)}(])";
/// The rest of the same command (no separator).
const R: &str = r"[^\n;|&]*";

/// BX-13: the default dangerous PowerShell commands. Each is tested (case aside) against the script as typed and
/// against each command as the parser reads it: `rm -r` reads as `Remove-Item -r`, `IEX` as `Invoke-Expression`,
/// `–Recurse` (an en dash) as `-Recurse`. Saved rules keep their own list: these apply to new and default rules.
pub fn default_dangerous_patterns() -> Vec<DangerousPattern> {
    let p = |name: &str, pattern: String| DangerousPattern {
        name: name.into(),
        pattern: format!("(?i){pattern}"),
    };
    // `-EncodedCommand` and every shorter form PowerShell takes (`-e`, `-ec`, `-enc`...).
    let encoded = {
        let mut forms: Vec<String> = vec!["e".into(), "ec".into()];
        let word = "encodedcommand";
        forms.extend((2..=word.len()).map(|n| word[..n].to_owned()));
        forms.join("|")
    };
    vec![
        p(
            "Stop-Computer / Restart-Computer",
            format!(r"{S}(?:stop|restart)-computer{E}"),
        ),
        p(
            "shutdown / logoff",
            format!(r"{S}shutdown(?:\.exe)?\s+(?:{R}\s)?[/-][srpghlei](?:$|\s)|{S}logoff(?:\.exe)?{E}"),
        ),
        p(
            "Remove-Item -Recurse / rd /s",
            format!(r"{S}remove-item\s+(?:{R}\s)?-r[a-z]*(?::\S*)?(?:$|\s)|{S}(?:rd|rmdir|del|erase)\s+(?:{R}\s)?/s(?:$|\s)"),
        ),
        p(
            "Format-Volume / Clear-Disk / diskpart",
            format!(
                r"{S}(?:format-volume|clear-disk|initialize-disk|remove-partition|resize-partition|set-disk|remove-virtualdisk|remove-storagepool|reset-physicaldisk){E}|{S}format(?:\.com)?\s+[a-z]:|{S}diskpart(?:\.exe)?{E}"
            ),
        ),
        p("Invoke-Expression", format!(r"{S}(?:invoke-expression|iex){E}")),
        p(
            "powershell -EncodedCommand",
            format!(r"{S}(?:powershell|pwsh)(?:\.exe)?\s+(?:{R}\s)?[-/–—―](?:{encoded})(?:$|\s)"),
        ),
        p(
            "stop or disable WinRM",
            format!(
                r"{S}(?:stop|suspend|restart)-service\s{R}\bwinrm\b|{S}set-service\s{R}(?:\bwinrm\b{R}\b(?:disabled|stopped|manual)\b|\b(?:disabled|stopped|manual)\b{R}\bwinrm\b)|{S}disable-psremoting{E}|{S}(?:net(?:\.exe)?\s+stop|sc\.exe\s+(?:stop|config|delete))\s+winrm\b"
            ),
        ),
        p(
            "disable a network adapter or address",
            format!(r"{S}(?:disable-netadapter|remove-netipaddress|remove-netroute){E}|{S}netsh(?:\.exe)?\s{R}\bdisabled?\b"),
        ),
        p(
            "remove firewall rules / block outbound",
            format!(
                r"{S}(?:remove-netfirewallrule|disable-netfirewallrule){E}|{S}set-netfirewallprofile\s{R}-defaultoutboundaction(?:\s+|:)block\b|{S}netsh(?:\.exe)?\s+advfirewall\s{R}\b(?:blockoutbound|reset)\b"
            ),
        ),
        p(
            "stop a system process",
            format!(
                r"{S}(?:stop-process|taskkill(?:\.exe)?)\s{R}\b(?:lsass|csrss|wininit|winlogon|smss|services|svchost)(?:\.exe)?\b"
            ),
        ),
        p(
            "delete users or directory objects",
            format!(
                r"{S}remove-(?:localuser|localgroup|localgroupmember|aduser|adcomputer|adgroup|adgroupmember|adobject|adorganizationalunit){E}|{S}net(?:\.exe)?\s+(?:user|localgroup|group)\s{R}/del(?:ete)?\b"
            ),
        ),
        p(
            "clear event logs",
            format!(r"{S}(?:clear-eventlog|remove-eventlog){E}|{S}wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b"),
        ),
        p(
            "delete registry keys",
            format!(r"{S}reg(?:\.exe)?\s+delete\b|{S}remove-item(?:property)?\s{R}\b(?:hklm|hkcu|hkcr|hku|hkcc|registry):"),
        ),
        p(
            "turn off Windows Defender",
            format!(
                r"{S}set-mppreference\s{R}-disable\w*(?:\s+|:)(?:\$true|1)\b|{S}(?:add|set)-mppreference\s{R}-exclusion\w*"
            ),
        ),
        p(
            "BitLocker or boot settings",
            format!(
                r"{S}(?:disable-bitlocker|suspend-bitlocker|clear-bitlockerautounlock|remove-bitlockerkeyprotector){E}|{S}bcdedit(?:\.exe)?\s+(?:{R}\s)?/(?:delete|deletevalue|set|import|createstore)\b|{S}manage-bde(?:\.exe)?\s{R}-(?:off|forcerecovery|delete)\b"
            ),
        ),
        p(
            "delete shadow copies or backups",
            format!(
                r"{S}vssadmin(?:\.exe)?\s+(?:delete|resize)\b|{S}wbadmin(?:\.exe)?\s+delete\b|{S}wmic(?:\.exe)?\s{R}\bshadowcopy\s+delete\b|\bwin32_shadowcopy\b[^\n;]*\|\s*(?:remove-wmiobject|remove-ciminstance|rwmi)\b"
            ),
        ),
        p(
            "uninstall features or software",
            format!(
                r"{S}(?:uninstall-windowsfeature|remove-windowsfeature|disable-windowsoptionalfeature|uninstall-package|remove-appxpackage){E}|{S}msiexec(?:\.exe)?\s+(?:{R}\s)?[/-]x(?:$|\s)"
            ),
        ),
        p(
            "leave the domain",
            format!(r"{S}(?:remove-computer|reset-computermachinepassword){E}|{S}netdom(?:\.exe)?\s+remove\b"),
        ),
        p(
            "Invoke-Command on other computers",
            format!(
                r"{S}invoke-command(?:\s{R})?\s-(?:com(?:p(?:u(?:t(?:e(?:r(?:n(?:a(?:m(?:e)?)?)?)?)?)?)?)?)?|cn|ses(?:s(?:i(?:o(?:n)?)?)?)?|vmn(?:a(?:m(?:e)?)?)?|vmid|hostn(?:a(?:m(?:e)?)?)?|connectionu(?:r(?:i)?)?|containerid)(?:$|[\s:])"
            ),
        ),
        p(
            "DROP DATABASE / TABLE",
            r#"\bdrop\s+(?:database|schema)\b|\bdrop\s+table\s+[\w"`\[]|\btruncate\s+table\s+[\w"`\[]"#.into(),
        ),
        p("kubectl delete", format!(r"{S}(?:kubectl|oc)(?:\.exe)?\s+(?:{R}\s)?delete{E}")),
        p(
            "docker / podman prune",
            format!(
                r"{S}(?:docker|podman)(?:\.exe)?\s+(?:{R}\s)?(?:system|container|image|volume|builder|buildx)\s+prune{E}"
            ),
        ),
        p(
            "docker / podman volume rm",
            format!(r"{S}(?:docker|podman)(?:\.exe)?\s+(?:{R}\s)?volume\s+(?:rm|remove){E}"),
        ),
    ]
}

/// BX-13: commands that only read, by the names PowerShell resolves (no aliases). The forms of these that write
/// (`ipconfig /release`, `ForEach-Object Kill`, `nslookup` with no name, which waits for typed lines) are never
/// read-only, whatever the list says ([`writes`]).
pub fn default_read_only_commands() -> Vec<String> {
    [
        // --- Files and folders (reading) ---
        "Get-ChildItem",
        "Get-Item",
        "Get-ItemProperty",
        "Get-ItemPropertyValue",
        "Get-Content",
        "Get-Location",
        "Get-PSDrive",
        "Get-PSProvider",
        "Test-Path",
        "Resolve-Path",
        "Split-Path",
        "Join-Path",
        "Convert-Path",
        "Get-FileHash",
        "Get-Acl",
        "Select-String",
        "Format-Hex",
        // --- The system ---
        "Get-ComputerInfo",
        "Get-HotFix",
        "Get-Process",
        "Get-Service",
        "Get-CimInstance",
        "Get-CimClass",
        "Get-WmiObject",
        "Get-Counter",
        "Get-WinEvent",
        "Get-EventLog",
        "Get-Date",
        "Get-TimeZone",
        "Get-Uptime",
        "Get-Culture",
        "Get-UICulture",
        "Get-Host",
        "Get-ExecutionPolicy",
        "Get-ScheduledTask",
        "Get-ScheduledTaskInfo",
        "Get-LocalUser",
        "Get-LocalGroup",
        "Get-LocalGroupMember",
        "Get-WindowsFeature",
        "Get-WindowsOptionalFeature",
        "Get-Package",
        "Get-InstalledModule",
        "Get-AppxPackage",
        "Get-PnpDevice",
        "Get-Printer",
        "Get-PrintJob",
        "Get-ComputerRestorePoint",
        "Get-BitLockerVolume",
        "Get-Tpm",
        "Get-MpComputerStatus",
        "Get-MpPreference",
        "Get-MpThreat",
        "Get-MpThreatDetection",
        "Get-AuthenticodeSignature",
        "Get-PfxCertificate",
        "Get-TlsCipherSuite",
        "Get-WSManInstance",
        "Test-WSMan",
        // --- Disks and storage ---
        "Get-Disk",
        "Get-Partition",
        "Get-Volume",
        "Get-PhysicalDisk",
        "Get-StoragePool",
        "Get-VirtualDisk",
        "Get-SmbShare",
        "Get-SmbSession",
        "Get-SmbConnection",
        "Get-SmbMapping",
        "Get-SmbServerConfiguration",
        // --- Network ---
        "Get-NetAdapter",
        "Get-NetAdapterStatistics",
        "Get-NetAdapterBinding",
        "Get-NetIPAddress",
        "Get-NetIPConfiguration",
        "Get-NetIPInterface",
        "Get-NetRoute",
        "Get-NetNeighbor",
        "Get-NetTCPConnection",
        "Get-NetUDPEndpoint",
        "Get-NetConnectionProfile",
        "Get-NetFirewallRule",
        "Get-NetFirewallProfile",
        "Get-NetFirewallPortFilter",
        "Get-NetFirewallAddressFilter",
        "Get-NetLbfoTeam",
        "Get-DnsClient",
        "Get-DnsClientServerAddress",
        "Get-DnsClientCache",
        "Resolve-DnsName",
        "Test-Connection",
        "Test-NetConnection",
        // --- Roles: IIS, Hyper-V, clustering, Active Directory, group policy ---
        "Get-IISSite",
        "Get-Website",
        "Get-VM",
        "Get-VMSwitch",
        "Get-VMNetworkAdapter",
        "Get-ClusterNode",
        "Get-ClusterGroup",
        "Get-ClusterResource",
        "Get-ADUser",
        "Get-ADComputer",
        "Get-ADGroup",
        "Get-ADGroupMember",
        "Get-ADDomain",
        "Get-ADForest",
        "Get-ADDomainController",
        "Get-ADOrganizationalUnit",
        "Get-ADObject",
        "Get-GPO",
        // --- PowerShell itself ---
        "Get-Command",
        "Get-Help",
        "Get-Member",
        "Get-Alias",
        "Get-Module",
        "Get-Variable",
        "Get-Job",
        "Get-History",
        "Get-Random",
        // --- Pipelines and output ---
        "Where-Object",
        "ForEach-Object",
        "Select-Object",
        "Sort-Object",
        "Group-Object",
        "Measure-Object",
        "Compare-Object",
        "Get-Unique",
        "Format-Table",
        "Format-List",
        "Format-Wide",
        "Format-Custom",
        "Out-String",
        "Out-Null",
        "Write-Output",
        "Write-Host",
        "Write-Verbose",
        "Write-Warning",
        "Write-Information",
        "Write-Debug",
        "Write-Error",
        "ConvertTo-Json",
        "ConvertFrom-Json",
        "ConvertTo-Csv",
        "ConvertFrom-Csv",
        "ConvertTo-Xml",
        "ConvertTo-Html",
        "ConvertFrom-StringData",
        "Select-Xml",
        "Measure-Command",
        "Start-Sleep",
        "New-TimeSpan",
        // --- Windows programs that only show (each form that writes is a rule in `writes`) ---
        "whoami",
        "hostname",
        "systeminfo",
        "ipconfig",
        "netstat",
        "tasklist",
        "getmac",
        "ping",
        "tracert",
        "pathping",
        "nslookup",
        "quser",
        "qwinsta",
        "query user",
        "query session",
        "driverquery",
        "findstr",
        "where.exe",
        "tree",
        "gpresult",
        "route print",
        "arp -a",
        "netsh interface show",
        "netsh interface ipv4 show",
        "netsh interface ipv6 show",
        "netsh advfirewall show",
        "netsh advfirewall firewall show",
        "netsh winhttp show",
        "netsh http show",
        "netsh wlan show",
        "sc.exe query",
        "sc.exe queryex",
        "sc.exe qc",
        "sc.exe qdescription",
        "sc.exe qfailure",
        "sc.exe qtriggerinfo",
        "sc.exe getdisplayname",
        "sc.exe getkeyname",
        "sc.exe enumdepend",
        "sc.exe sdshow",
        "schtasks /query",
        "reg query",
        "wevtutil qe",
        "wevtutil el",
        "wevtutil gl",
        "wevtutil gli",
        "w32tm /query",
        "w32tm /tz",
        "bcdedit /enum",
        "manage-bde -status",
        "vssadmin list",
        "tzutil /g",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Programs and cmdlets that run whatever they are given, or change what a command's name runs. As a read-only entry
/// any of them would let every command through as a read (`powershell -c 'Stop-Computer'`, `Invoke-Expression`,
/// `Set-Alias Get-Service Stop-Service`), so none can be one. By key ([`parse::command_key`]).
const RUNS_ANYTHING: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "cmd.exe",
    "conhost.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "bitsadmin.exe",
    "explorer.exe",
    "bash.exe",
    "wsl.exe",
    "sh.exe",
    "py.exe",
    "node.exe",
    "ruby.exe",
    "java.exe",
    "javaw.exe",
    "psexec.exe",
    "psexec64.exe",
    "paexec.exe",
    "runas.exe",
    "winrs.exe",
    "ssh.exe",
    "plink.exe",
    "wmic.exe",
    "forfiles.exe",
    "at.exe",
    "invoke-expression",
    "invoke-command",
    "start-process",
    "start-job",
    "start-threadjob",
    "invoke-item",
    "invoke-history",
    "invoke-wmimethod",
    "invoke-cimmethod",
    "new-pssession",
    "enter-pssession",
    "add-type",
    "import-module",
    "new-module",
    "register-scheduledjob",
    "register-scheduledtask",
    "set-alias",
    "new-alias",
    "import-alias",
];

/// Interpreters named by a prefix (`python3.12`, `perl5`), and scripts by their extension.
const RUNS_ANYTHING_PREFIXES: &[&str] = &["python", "perl", "php", "lua", "pypy", "ruby", "node"];
const SCRIPT_EXTENSIONS: &[&str] = &[".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"];

/// Why a command with this key runs anything it is given, if it does.
fn runs_anything_key(key: &str) -> Option<&'static str> {
    if RUNS_ANYTHING.contains(&key) {
        return Some("runs any command it is given");
    }
    // `python.exe`, and `python3.12` (a name with a dot, which PowerShell runs as a program too).
    let stem = key.strip_suffix(".exe").unwrap_or(key);
    if !stem.contains('-') && RUNS_ANYTHING_PREFIXES.iter().any(|p| stem.starts_with(p)) {
        return Some("runs any command it is given");
    }
    if SCRIPT_EXTENSIONS.iter().any(|ext| key.ends_with(ext)) {
        return Some("runs a script");
    }
    None
}

/// Characters that join, redirect, quote or expand in PowerShell. A read-only entry holding one would let another
/// command ride along.
fn special(c: char) -> bool {
    matches!(
        c,
        ';' | '&' | '|' | '>' | '<' | '`' | '$' | '@' | '(' | ')' | '{' | '}' | ',' | '#' | '\'' | '"' | '\n' | '\r'
    ) || matches!(c, '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' | '\u{201c}' | '\u{201d}' | '\u{201e}')
}

/// BX-13: why a PowerShell read-only entry can't be one, if it can't.
pub(crate) fn entry_problem(entry: &str) -> Option<String> {
    let shown = entry.trim();
    if shown.is_empty() {
        return Some("an entry is empty".into());
    }
    if shown.contains(special) {
        return Some(format!(
            "'{shown}' holds a PowerShell operator (; & | > < ` $ @ , # quotes or brackets)"
        ));
    }
    let first = shown.split_whitespace().next().unwrap_or(shown);
    if first.contains(['\\', '/']) {
        return Some(format!("'{shown}' names a path: name the command itself"));
    }
    if let Some(command) = parse::alias_of(first) {
        return Some(format!(
            "'{first}' is PowerShell's alias of {command}: name the command itself (a program with the alias's name is \
             written with .exe, as sc.exe)"
        ));
    }
    let (_, key) = parse::command_key(first);
    if let Some(why) = key.as_deref().and_then(runs_anything_key) {
        return Some(format!("'{shown}' {why}, so it can't be read-only"));
    }
    None
}

/// A read-only entry as matched: the command's key and its first words in lower case.
fn entry_key(entry: &str) -> Option<(String, Vec<String>)> {
    let mut words = entry.split_whitespace();
    let (_, key) = parse::command_key(words.next()?);
    let rest = words.map(|w| parse::plain_dashes(w).to_lowercase()).collect();
    Some((key?, rest))
}

/// An entry with its spaces collapsed and its case kept, so two spellings of one entry compare equal.
pub(crate) fn squeeze(entry: &str) -> String {
    entry.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// BX-13: the parts of a script the rules read: the whole of it, then each statement PowerShell runs it as. Over
/// WinRM a script goes to `powershell -Command -`, which reads it a line at a time, as the PowerShell console does: a
/// statement goes once it closes, or when an empty line ends it, so `"x` + an empty line + `Stop-Service a` + `"` is
/// three statements (the second runs), not one string. Each part with where it starts.
fn parts(script: &str) -> Vec<(usize, String)> {
    let mut starts = Vec::new();
    let mut lines = Vec::new();
    let mut at = 0;
    for piece in script.split('\n') {
        starts.push(at);
        lines.push(piece.strip_suffix('\r').unwrap_or(piece));
        at += piece.len() + 1;
    }
    let (sent, held_from) = crate::adapters::winrm::console::statement_ranges(0, &lines);
    let mut out = vec![(0, script.to_owned())];
    let ranges = sent
        .into_iter()
        .chain((held_from < lines.len()).then_some(held_from..lines.len()));
    for range in ranges {
        let text = lines[range.clone()].join("\n");
        // A script of one statement is read once.
        if !text.trim().is_empty() && text.trim() != script.trim() {
            out.push((starts[range.start], text));
        }
    }
    out
}

/// BX-13: true when the parser read every part of the script (the whole of it and each statement PowerShell runs it
/// as), every command it runs is on the read-only list, and none of them is a form that writes. A script of
/// expressions only (`$PSVersionTable`) reads too.
pub(crate) fn is_read_only(script: &str, read_only: &[String]) -> bool {
    if script.trim().is_empty() {
        return false;
    }
    let entries: Vec<(String, Vec<String>)> = read_only.iter().filter_map(|e| entry_key(e)).collect();
    parts(script).iter().all(|(_, part)| {
        let parsed = parse::parse(part);
        parsed.unreadable.is_empty() && parsed.commands.iter().all(|command| command_reads(command, &entries))
    })
}

fn command_reads(command: &PsCommand, entries: &[(String, Vec<String>)]) -> bool {
    let Some(key) = command.key.as_deref() else {
        return false;
    };
    if runs_anything_key(key).is_some() {
        return false;
    }
    let listed = entries.iter().any(|(entry, words)| {
        entry == key
            && words.iter().enumerate().all(|(i, word)| {
                command
                    .args
                    .get(i)
                    .is_some_and(|a| a.literal && a.kind != ArgKind::Block && a.text.to_lowercase() == *word)
            })
    });
    listed && !writes(command)
}

/// The command's literal arguments in lower case, or `None` when one is known only when it runs.
fn literal_args(command: &PsCommand) -> Option<Vec<String>> {
    command
        .args
        .iter()
        .map(|a| (a.literal && a.kind != ArgKind::Block).then(|| a.text.to_lowercase()))
        .collect()
}

/// An option as a Windows program reads it: `/release`, `-release` and `/RELEASE` are `release`.
fn option(word: &str) -> Option<&str> {
    word.strip_prefix('/').or_else(|| word.strip_prefix('-'))
}

/// BX-13: forms of read-only commands that write or wait for typed lines (in a PowerShell tab, what is typed into a
/// running program passes straight through, unrated), whatever the list says. An argument known only when it runs
/// (`ipconfig $x`) may be any of them.
pub(crate) fn writes(command: &PsCommand) -> bool {
    let Some(key) = command.key.as_deref() else {
        return true;
    };
    match key {
        "foreach-object" => foreach_writes(command),
        "ipconfig.exe" => args_match(command, |args| {
            args.iter().any(|a| {
                option(a).is_some_and(|o| ["release", "renew", "flushdns", "registerdns", "setclassid"].iter().any(|w| o.starts_with(w)))
            })
        }),
        "arp.exe" => args_match(command, |args| args.iter().any(|a| matches!(option(a), Some("d" | "s")))),
        "route.exe" => args_match(command, |args| {
            args.iter()
                .any(|a| matches!(a.as_str(), "add" | "delete" | "change") || matches!(option(a), Some("f" | "p")))
        }),
        "netsh.exe" => args_match(command, |args| {
            args.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "set" | "add" | "delete" | "del" | "reset" | "install" | "uninstall" | "import" | "export" | "dump"
                        | "trace" | "start" | "stop" | "connect" | "disconnect" | "exec" | "flush"
                )
            })
        }),
        // With no name to look up, nslookup waits for typed lines.
        "nslookup.exe" => args_match(command, |args| !args.iter().any(|a| !a.starts_with('-'))),
        "gpresult.exe" => args_match(command, |args| {
            args.iter().any(|a| option(a).is_some_and(|o| o.starts_with('h') || o.starts_with('x') || o == "f"))
        }),
        "sc.exe" => args_match(command, |args| {
            args.first().is_none_or(|verb| {
                !matches!(
                    verb.as_str(),
                    "query" | "queryex" | "qc" | "qdescription" | "qfailure" | "qtriggerinfo" | "getdisplayname"
                        | "getkeyname" | "enumdepend" | "sdshow"
                )
            })
        }),
        "schtasks.exe" => args_match(command, |args| {
            args.iter()
                .any(|a| option(a).is_some_and(|o| matches!(o, "create" | "delete" | "run" | "end" | "change")))
        }),
        "reg.exe" => args_match(command, |args| args.first().is_none_or(|verb| verb != "query")),
        "wevtutil.exe" => args_match(command, |args| {
            args.first()
                .is_none_or(|verb| !matches!(verb.as_str(), "qe" | "query-events" | "el" | "enum-logs" | "gl" | "get-log" | "gli" | "get-log-info"))
        }),
        "w32tm.exe" => args_match(command, |args| {
            args.iter().any(|a| option(a).is_some_and(|o| matches!(o, "resync" | "config" | "register" | "unregister")))
        }),
        "bcdedit.exe" => args_match(command, |args| {
            args.iter().any(|a| option(a).is_some_and(|o| o != "enum" && o != "v"))
        }),
        "manage-bde.exe" => args_match(command, |args| {
            args.first().is_none_or(|verb| option(verb) != Some("status"))
        }),
        "vssadmin.exe" => args_match(command, |args| args.first().is_none_or(|verb| verb != "list")),
        "tzutil.exe" => args_match(command, |args| args.iter().any(|a| option(a).is_some_and(|o| o != "g" && o != "l"))),
        _ => false,
    }
}

/// `test` on the literal arguments; an argument known only when it runs counts as writing.
fn args_match(command: &PsCommand, test: impl Fn(&[String]) -> bool) -> bool {
    match literal_args(command) {
        Some(args) => test(&args),
        None => true,
    }
}

/// `ForEach-Object` reads when it only runs script blocks written in the script (read like any other): a member's
/// name (`% Kill`, `-MemberName Kill`) calls that method on every object, and a block held in a variable
/// (`-Process $sb`) wasn't read.
fn foreach_writes(command: &PsCommand) -> bool {
    const BLOCKS: &[&str] = &["begin", "process", "end", "remainingscripts", "parallel"];
    const VALUES: &[&str] = &["inputobject", "throttlelimit", "timeoutseconds"];
    const FLAGS: &[&str] = &["whatif", "confirm", "usenewrunspace"];
    let mut args = command.args.iter();
    while let Some(arg) = args.next() {
        match arg.kind {
            ArgKind::Block => {}
            ArgKind::Parameter => {
                let Some(name) = arg.parameter().filter(|n| !n.is_empty()) else {
                    return true;
                };
                let block = BLOCKS.iter().any(|p| p.starts_with(&name));
                let value = VALUES.iter().any(|p| p.starts_with(&name));
                let flag = FLAGS.iter().any(|p| p.starts_with(&name));
                // A prefix of a parameter that may call a method (`-m`, `-a` for -MemberName, -ArgumentList) or of two
                // kinds at once can't be trusted.
                let refused = ["membername", "argumentlist", "asjob"].iter().any(|p| p.starts_with(&name));
                if refused || u8::from(block) + u8::from(value) + u8::from(flag) != 1 {
                    return true;
                }
                if arg.attached() {
                    // `-Process:{ … }`: what follows the colon is in the parameter's text.
                    let attached = arg.text.split_once(':').map(|(_, v)| v.trim()).unwrap_or_default();
                    if block && !(attached.starts_with('{') && attached.ends_with('}')) {
                        return true;
                    }
                    continue;
                }
                if flag {
                    continue;
                }
                match args.next() {
                    Some(next) if block && next.kind != ArgKind::Block => return true,
                    Some(_) => {}
                    None => return true,
                }
            }
            ArgKind::Value | ArgKind::Expression => return true,
        }
    }
    false
}

/// BX-13: every command the script runs, as the dangerous-command rules see them: in the whole of it and in each
/// statement PowerShell runs it as ([`parts`]), each at its place in the script.
pub(crate) fn commands(script: &str) -> Vec<PsCommand> {
    let mut out = Vec::new();
    for (i, (start, part)) in parts(script).into_iter().enumerate() {
        out.extend(parse::parse(&part).commands.into_iter().map(|mut c| {
            // A statement's commands are placed at its first line (its lines lost their CRs, so offsets inside it
            // aren't the script's).
            if i > 0 {
                c.at = start;
            }
            c
        }));
    }
    out
}
