//! BX-13 tier rules (docs/plan-0.7.md, "Approval tiers"): a PowerShell line in Type in all tabs or a Compare hosts run
//! on WinRM hosts is rated by the PowerShell rules (read-only Low, others Medium, dangerous High); a selection with SSH
//! and WinRM hosts rates each by its own rules; the rules are validated, loosening them is named, and rules saved
//! before them get the defaults.

use super::*;
use crate::command_bus::{Command, Rollout};
use crate::domain::{Environment, Target, TargetRef};
use crate::support_bundle::presets::{self, HostKind, PresetId};
use crate::support_bundle::{BundleItem, BundleSpec};

use ScriptKind::{PowerShell, Posix};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn host(n: usize, environment: Environment) -> Target {
    Target {
        target: TargetRef::Session {
            session_id: uuid::Uuid::from_u128(n as u128 + 1),
        },
        name: format!("win{n:02}"),
        environment,
        protected: false,
    }
}

fn run(script: &str, hosts: &[Target]) -> Command {
    Command::RemoteExec {
        targets: hosts.iter().map(|t| t.target.clone()).collect(),
        script: script.into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Rollout::default(),
    }
}

fn line(text: &str, unreliable: bool) -> Command {
    Command::TerminalLine {
        targets: vec![TargetRef::Terminal {
            terminal_id: uuid::Uuid::from_u128(9),
            session_id: None,
        }],
        line: text.into(),
        unreliable,
        keys: "\r".into(),
    }
}

#[test]
fn a_powershell_read_is_low_another_command_medium_and_a_dangerous_one_high() {
    let engine = engine();
    let hosts = [host(0, Environment::Lab)];
    let rate = |script: &str| engine.evaluate_on(&run(script, &hosts), &hosts, &[PowerShell]);
    let read = rate("Get-Service | Where-Object Status -eq Running");
    assert_eq!((read.action, read.tier), (ActionKind::ExecReadOnly, Tier::Low), "{:?}", read.reasons);
    assert!(read.reasons.iter().any(|r| r == "rated by the PowerShell rules"));
    let other = rate("Restart-Service Spooler");
    assert_eq!((other.action, other.tier), (ActionKind::ExecOther, Tier::Medium));
    let dangerous = rate("Stop-Computer -Force");
    assert_eq!((dangerous.action, dangerous.tier), (ActionKind::ExecDangerous, Tier::High));
    assert!(dangerous.reasons.iter().any(|r| r.contains("Stop-Computer / Restart-Computer")));
    // What the parser can't read rates like an unknown command.
    let unknown = rate("(Get-Item C:\\x).Delete()");
    assert_eq!(unknown.action, ActionKind::ExecOther);
    // The same text by the shell's rules is not PowerShell's: `Get-Service` is no Linux command.
    assert_eq!(engine.classify_script("Get-Service"), ActionKind::ExecOther);
    assert_eq!(engine.classify_script_as("Get-Service", PowerShell), ActionKind::ExecReadOnly);
    // A Prod host moves it up one, as for SSH hosts.
    let prod = [host(1, Environment::Prod)];
    let decision = engine.evaluate_on(&run("Get-Date", &prod), &prod, &[PowerShell]);
    assert_eq!(decision.tier, Tier::Medium);
}

#[test]
fn a_mixed_selection_rates_each_host_by_its_own_rules() {
    let engine = engine();
    let hosts = [host(0, Environment::Lab), host(1, Environment::Lab)];
    // `hostname` reads in both languages: Low.
    let both = engine.evaluate_on(&run("hostname", &hosts), &hosts, &[Posix, PowerShell]);
    assert_eq!(both.tier, Tier::Low, "{:?}", both.reasons);
    assert!(
        both.reasons
            .iter()
            .any(|r| r.contains("each target is rated by its own rules") && r.contains("read-only")),
        "{:?}",
        both.reasons
    );
    assert_eq!(both.script_kinds.len(), 2);
    assert_eq!(both.script_kinds.get(&hosts[1].target.key()), Some(&PowerShell));
    // `Get-Service` reads in PowerShell but is unknown to a shell: the shell's rating counts.
    let mixed = engine.evaluate_on(&run("Get-Service", &hosts), &hosts, &[Posix, PowerShell]);
    assert_eq!(mixed.action, ActionKind::ExecOther);
    // `uptime` reads in a shell but is no Windows command.
    let mixed = engine.evaluate_on(&run("uptime", &hosts), &hosts, &[Posix, PowerShell]);
    assert_eq!(mixed.action, ActionKind::ExecOther);
    // A rule of either language makes it dangerous.
    let dangerous = engine.evaluate_on(&run("shutdown /r /t 0", &hosts), &hosts, &[Posix, PowerShell]);
    assert_eq!(dangerous.action, ActionKind::ExecDangerous);
    // No kinds: the shell's rules, as before F8.
    assert_eq!(engine.evaluate(&run("Get-Service", &hosts), &hosts).script_kinds.get(&hosts[0].target.key()), Some(&Posix));
}

#[test]
fn a_protected_host_left_out_takes_its_language_with_it() {
    let engine = engine();
    let mut windows = host(1, Environment::Lab);
    windows.protected = true;
    let hosts = [host(0, Environment::Lab), windows];
    // Only the SSH host runs it, so PowerShell's rules don't count.
    let decision = engine.evaluate_on(&run("uptime", &hosts), &hosts, &[Posix, PowerShell]);
    assert_eq!(decision.action, ActionKind::ExecReadOnly, "{:?}", decision.reasons);
    assert_eq!(decision.script_kinds.len(), 1);
}

#[test]
fn a_powershell_line_typed_in_all_tabs_is_rated_as_powershell() {
    let engine = engine();
    let tab = [Target {
        target: TargetRef::Terminal {
            terminal_id: uuid::Uuid::from_u128(9),
            session_id: None,
        },
        name: "win01".into(),
        environment: Environment::Lab,
        protected: false,
    }];
    let read = engine.evaluate_on(&line("Get-Process", false), &tab, &[PowerShell]);
    assert_eq!(read.tier, Tier::Low);
    // An unreliable line is never read-only, in either language.
    let unreliable = engine.evaluate_on(&line("Get-Process", true), &tab, &[PowerShell]);
    assert_eq!(unreliable.action, ActionKind::ExecOther);
    assert_eq!(unreliable.tier, Tier::Medium);
    // A shell's pager rule is a shell's: `more` in a PowerShell tab is rated by PowerShell's rules (not listed).
    let pager = engine.evaluate_on(&line("less x", false), &tab, &[Posix]);
    assert_eq!(pager.action, ActionKind::ExecOther);
    let dangerous = engine.evaluate_on(&line("rm -r C:\\x", false), &tab, &[PowerShell]);
    assert_eq!(dangerous.action, ActionKind::ExecDangerous);
}

#[test]
fn a_docker_prune_on_a_windows_host_is_rated_like_the_containers_page() {
    let engine = engine();
    let hosts = [host(0, Environment::Lab)];
    let decision = engine.evaluate_on(&run("docker volume prune -f", &hosts), &hosts, &[PowerShell]);
    // The Containers page rates pruning volumes Critical.
    assert_eq!(decision.tier, Tier::Critical, "{:?}", decision.reasons);
    assert!(decision.reasons.iter().any(|r| r.contains("Containers page")));
}

#[test]
fn a_windows_bundle_rates_its_own_commands_by_the_powershell_rules() {
    let engine = engine();
    let windows_items = presets::expand(
        HostKind::Windows,
        &[PresetId::WindowsSystem, PresetId::WindowsLogs, PresetId::WindowsNetwork],
        &[],
        &[],
    );
    let items = presets::expand(HostKind::Linux, &[PresetId::System], &[], &[]);
    let hosts = [host(0, Environment::Lab), host(1, Environment::Lab)];
    let bundle = |items: Vec<BundleItem>, windows_items: Vec<BundleItem>| Command::SupportBundle {
        targets: hosts.iter().map(|t| t.target.clone()).collect(),
        spec: Box::new(BundleSpec {
            presets: Vec::new(),
            items,
            windows_items,
            sudo: false,
            sudo_password_id: None,
            trust_new_host_keys: false,
            timeout_secs: None,
            rollout: Rollout::default(),
            output: r"C:\Users\alice\Documents\bundle.zip".into(),
            workspace: "Lab".into(),
        }),
    };
    let presets_only = bundle(items.clone(), windows_items.clone());
    let decision = engine.evaluate_on(&presets_only, &hosts, &[Posix, PowerShell]);
    assert_eq!(decision.tier, Tier::Low, "{:?}", decision.reasons);
    assert!(decision.reasons.iter().any(|r| r.contains("Windows commands are rated together")));
    // A Windows custom command that changes something rates the bundle Medium.
    let mut changed = windows_items.clone();
    changed.push(BundleItem::command("Restart-Service Spooler"));
    let decision = engine.evaluate_on(&bundle(items.clone(), changed), &hosts, &[Posix, PowerShell]);
    assert_eq!(decision.tier, Tier::Medium);
    // Files read on Windows hosts are reads.
    let files = bundle(Vec::new(), vec![BundleItem::file(r"C:\Windows\Logs\CBS\CBS.log")]);
    let decision = engine.evaluate_on(&files, &hosts[1..], &[PowerShell]);
    assert_eq!(decision.tier, Tier::Low);
    assert!(decision.reasons.iter().any(|r| r.contains("read by PowerShell")));
}

#[test]
fn every_windows_preset_command_is_read_only_under_the_powershell_rules() {
    let engine = engine();
    for preset in presets::PRESETS.iter().filter(|p| p.host_kind == HostKind::Windows) {
        for item in preset.items {
            if let BundleItem::Command { command } = item.item() {
                assert_eq!(
                    engine.classify_script_as(&command, PowerShell),
                    ActionKind::ExecReadOnly,
                    "{}: {command}",
                    preset.label
                );
            }
        }
    }
}

#[test]
fn the_powershell_rules_are_validated() {
    let mut rules = PolicyRules::default();
    rules.powershell.read_only_commands.push("Invoke-Expression".into());
    let err = rules.validate().unwrap_err().to_string();
    assert!(err.contains("Read-only PowerShell commands") && err.contains("can't be read-only"), "{err}");

    let mut rules = PolicyRules::default();
    rules.powershell.read_only_commands.push("gsv".into());
    assert!(rules.validate().unwrap_err().to_string().contains("alias"));

    let mut rules = PolicyRules::default();
    rules.powershell.read_only_commands.push("get-service".into());
    assert!(rules.validate().unwrap_err().to_string().contains("listed twice"));

    let mut rules = PolicyRules::default();
    rules.powershell.dangerous_commands.push(DangerousPattern {
        name: "everything".into(),
        pattern: ".*".into(),
    });
    assert!(rules.validate().unwrap_err().to_string().contains("matches every command"));

    let mut rules = PolicyRules::default();
    rules.powershell.dangerous_commands.push(DangerousPattern {
        name: "Invoke-Expression".into(),
        pattern: "x+".into(),
    });
    assert!(rules
        .validate()
        .unwrap_err()
        .to_string()
        .contains("another dangerous PowerShell rule has this name"));

    let mut rules = PolicyRules::default();
    rules.powershell.dangerous_commands.push(DangerousPattern {
        name: "broken".into(),
        pattern: "(".into(),
    });
    assert!(rules.validate().unwrap_err().to_string().contains("not a valid regular expression"));
}

#[test]
fn loosening_the_powershell_rules_is_named_and_audited() {
    let before = PolicyRules::default();
    let mut after = before.clone();
    after.powershell.dangerous_commands.retain(|p| p.name != "Invoke-Expression");
    after.powershell.read_only_commands.push("Restart-Service".into());
    let loosened = before.loosened(&after);
    assert!(loosened.contains(&"dangerous PowerShell command 'Invoke-Expression' removed".to_owned()));
    assert!(loosened.contains(&"'Restart-Service' counts as read-only in PowerShell".to_owned()));
    let changes = before.changes(&after);
    assert!(changes.contains(&"Dangerous PowerShell command removed: Invoke-Expression".to_owned()));
    assert!(changes.contains(&"Read-only PowerShell command added: Restart-Service".to_owned()));
    // Tightening isn't loosening.
    let mut tighter = before.clone();
    tighter.powershell.read_only_commands.retain(|c| c != "Get-Process");
    assert!(before.loosened(&tighter).is_empty());
    assert!(before.changes(&tighter).contains(&"Read-only PowerShell command removed: Get-Process".to_owned()));
    // A changed pattern loosens too.
    let mut changed = before.clone();
    changed.powershell.dangerous_commands[0].pattern = "(?i)nothing-like-it".into();
    assert_eq!(before.loosened(&changed).len(), 1);
    // Normalizing collapses an entry's spaces.
    let mut spaced = before.clone();
    spaced.powershell.read_only_commands = vec!["  route   print ".into()];
    assert_eq!(spaced.normalized().powershell.read_only_commands, ["route print"]);
}

#[test]
fn rules_saved_before_the_powershell_rules_get_the_defaults() {
    let mut saved = serde_json::to_value(PolicyRules::default()).unwrap();
    saved.as_object_mut().unwrap().remove("powershell");
    let rules: PolicyRules = serde_json::from_value(saved).unwrap();
    assert_eq!(rules.powershell, PowerShellRules::default());
    assert!(rules.validate().is_ok());
}
