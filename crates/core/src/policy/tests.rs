//! Tier rules from the PRD "Approvals and audit" table.

use uuid::Uuid;

use super::*;
use crate::command_bus::{Command, PowerOp, SnapshotOp, StopMode};
use crate::domain::{Environment, Target, TargetRef};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn vm(n: usize) -> Target {
    Target {
        target: TargetRef::Vm {
            vmx_path: format!(r"C:\VMs\vm{n}\vm{n}.vmx"),
        },
        name: format!("vm{n}"),
        environment: Environment::Lab,
        protected: false,
    }
}

fn vms(count: usize) -> Vec<Target> {
    (0..count).map(vm).collect()
}

fn host(env: Environment) -> Target {
    Target {
        target: TargetRef::Session {
            session_id: Uuid::new_v4(),
        },
        name: "host".into(),
        environment: env,
        protected: false,
    }
}

fn refs(targets: &[Target]) -> Vec<TargetRef> {
    targets.iter().map(|t| t.target.clone()).collect()
}

fn power(op: PowerOp, targets: &[Target]) -> Command {
    Command::VmPower {
        targets: refs(targets),
        op,
    }
}

fn snapshot(op: SnapshotOp, targets: &[Target]) -> Command {
    Command::VmSnapshot {
        targets: refs(targets),
        op,
    }
}

fn exec(script: &str, targets: &[Target]) -> Command {
    Command::RemoteExec {
        targets: refs(targets),
        script: script.into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
    }
}

fn tier(command: Command, targets: &[Target]) -> Tier {
    engine().evaluate(&command, targets).tier
}

const SOFT: StopMode = StopMode::Soft;
const HARD: StopMode = StopMode::Hard;

// ---- Low ---------------------------------------------------------------------------------------

#[test]
fn starting_vms_is_low_at_any_count() {
    for n in [1, 2, 20] {
        let t = vms(n);
        assert_eq!(tier(power(PowerOp::Start { gui: false }, &t), &t), Tier::Low, "{n} VMs");
    }
}

#[test]
fn taking_a_snapshot_is_low() {
    let t = vms(5);
    let take = SnapshotOp::Take {
        name: "before-patch".into(),
    };
    assert_eq!(tier(snapshot(take, &t), &t), Tier::Low);
}

#[test]
fn unpause_is_low() {
    let t = vms(3);
    assert_eq!(tier(power(PowerOp::Unpause, &t), &t), Tier::Low);
}

#[test]
fn read_only_commands_are_low() {
    let t = vec![host(Environment::Lab)];
    for script in [
        "uptime",
        "df -h",
        "free -m && uptime",
        "cat /etc/os-release | grep PRETTY",
        "sudo journalctl -u nginx --since today",
        "systemctl status sshd 2>&1",
        "ls /var/log > /dev/null",
    ] {
        assert_eq!(tier(exec(script, &t), &t), Tier::Low, "{script}");
    }
}

#[test]
fn low_tier_needs_no_steps() {
    let t = vms(4);
    let d = engine().evaluate(&power(PowerOp::Start { gui: true }, &t), &t);
    assert!(d.steps.is_empty());
}

// ---- Medium ------------------------------------------------------------------------------------

#[test]
fn suspend_or_reset_or_stop_one_vm_is_medium() {
    let t = vms(1);
    assert_eq!(tier(power(PowerOp::Suspend, &t), &t), Tier::Medium);
    assert_eq!(tier(power(PowerOp::Reset { mode: SOFT }, &t), &t), Tier::Medium);
    assert_eq!(tier(power(PowerOp::Stop { mode: SOFT }, &t), &t), Tier::Medium);
}

#[test]
fn pausing_vms_is_medium_at_any_count() {
    for n in [1, 5] {
        let t = vms(n);
        assert_eq!(tier(power(PowerOp::Pause, &t), &t), Tier::Medium, "{n} VMs");
    }
}

#[test]
fn commands_that_are_not_read_only_are_medium() {
    let t = vec![host(Environment::Lab)];
    for script in [
        "systemctl restart nginx",
        "apt-get install -y htop",
        "echo hi > /tmp/file",
        "echo $(whoami)",
        "sudo -u postgres psql -c 'select 1'",
    ] {
        assert_eq!(tier(exec(script, &t), &t), Tier::Medium, "{script}");
    }
}

#[test]
fn the_command_panels_read_only_commands_are_low_and_their_writing_cousins_are_not() {
    let t = vec![host(Environment::Lab)];
    for script in [
        "systemd-detect-virt",
        "findmnt --real",
        "mpstat -P ALL 1 3",
        "tracepath web01.example.com",
        "ip neigh show",
        "systemctl list-unit-files --type=service",
        "systemctl list-timers --all",
        "systemctl cat nginx",
        "systemd-analyze blame | head -20",
        "apt-cache policy nginx",
        "dpkg -S /usr/bin/ssh",
        "rpm -qa | sort",
        "rpm -qf /usr/bin/ssh",
        "dnf check-update",
        "dnf info nginx",
        "dnf repolist",
        "dnf history list",
        "getent group wheel",
        "sudo chage -l alice",
        "sudo lastb -n 20",
        "sudo ufw status verbose",
        "sudo firewall-cmd --list-all",
        "sudo firewall-cmd --state",
        "sudo iptables -L -n -v --line-numbers",
        "sudo iptables -S",
        "sudo nft list ruleset",
        "docker logs --tail 200 web",
        "docker stats --no-stream",
        "docker inspect web",
        "docker system df",
        "docker network ls",
        "docker compose ps",
        "kubectl logs web-1 -n shop --tail=200",
        "kubectl top pods -A",
        "kubectl config get-contexts",
        "kubectl cluster-info",
        "kubectl version",
    ] {
        assert_eq!(tier(exec(script, &t), &t), Tier::Low, "{script}");
    }
    for script in [
        "ip neigh add 192.0.2.1 lladdr 00:00:5e:00:53:01 dev eth0",
        "systemctl list-timers; systemctl stop nginx",
        "sudo ufw allow 22/tcp",
        "sudo firewall-cmd --add-port=80/tcp",
        "sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
        "sudo nft flush ruleset",
        "docker logs web > /tmp/web.log",
        "docker system prune",
        "docker network rm shop",
        "docker compose down",
        "kubectl config use-context prod",
        "dnf history undo 5",
        "rpm -e nginx",
    ] {
        assert_eq!(tier(exec(script, &t), &t), Tier::Medium, "{script}");
    }
}

#[test]
fn a_script_on_its_own_is_classified_like_a_remote_command() {
    let e = engine();
    let t = vec![host(Environment::Lab)];
    for script in [
        "uptime",
        "systemctl restart nginx",
        "sudo systemctl reboot",
        "rm -rf /tmp/x",
    ] {
        assert_eq!(e.classify_script(script), e.classify(&exec(script, &t)), "{script}");
    }
    assert_eq!(e.classify_script("df -h"), ActionKind::ExecReadOnly);
    assert_eq!(e.classify_script("apt upgrade"), ActionKind::ExecOther);
    assert_eq!(e.classify_script("sudo systemctl reboot"), ActionKind::ExecDangerous);
}

#[test]
fn medium_tier_is_one_confirm() {
    let t = vms(1);
    let d = engine().evaluate(&power(PowerOp::Suspend, &t), &t);
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
}

#[test]
fn installing_an_update_is_medium_with_one_confirm() {
    // CLAUDE.md, FD-14: installing is a Medium-tier command through the bus.
    let command = Command::AppUpdate {
        version: "0.1.1".into(),
    };
    let app = vec![Target {
        target: TargetRef::App,
        name: "Remotely".into(),
        environment: Environment::None,
        protected: false,
    }];
    let d = engine().evaluate(&command, &app);
    assert_eq!(d.action, ActionKind::AppUpdate);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
    assert_eq!(command.targets(), [TargetRef::App]);
}

fn push_key(targets: &[Target]) -> Command {
    Command::PushSshKey {
        targets: refs(targets),
        // Only the classification is tested here; the key's text is checked by `Command::validate`.
        public_key: "ssh-ed25519 AAAA alice@example.com".into(),
        trust_new_host_keys: false,
        timeout_secs: None,
    }
}

#[test]
fn pushing_an_ssh_key_is_medium_for_one_host_or_many() {
    // SS-09: adding a key to authorized_keys grants a login, so it is a change with one confirm.
    for n in [1, 2, 50] {
        let t: Vec<Target> = (0..n).map(|_| host(Environment::Lab)).collect();
        let d = engine().evaluate(&push_key(&t), &t);
        assert_eq!(d.action, ActionKind::SshKeyPush);
        assert_eq!(d.tier, Tier::Medium, "{n} hosts");
        assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
    }
}

#[test]
fn pushing_an_ssh_key_to_a_prod_host_is_high_without_a_safety_snapshot() {
    let t = vec![host(Environment::Lab), host(Environment::Prod)];
    let d = engine().evaluate(&push_key(&t), &t);
    assert_eq!(d.tier, Tier::High);
    assert!(d.reasons.iter().any(|r| r.contains("Prod")), "{:?}", d.reasons);
    assert!(!d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    assert!(d.steps.contains(&ApprovalStep::TypeTargetCount { expected: 2 }));
}

// ---- High --------------------------------------------------------------------------------------

#[test]
fn stop_reset_or_suspend_two_or_more_vms_is_high() {
    for n in [2, 3, 30] {
        let t = vms(n);
        assert_eq!(
            tier(power(PowerOp::Stop { mode: SOFT }, &t), &t),
            Tier::High,
            "stop {n}"
        );
        assert_eq!(
            tier(power(PowerOp::Reset { mode: SOFT }, &t), &t),
            Tier::High,
            "reset {n}"
        );
        assert_eq!(tier(power(PowerOp::Suspend, &t), &t), Tier::High, "suspend {n}");
    }
}

#[test]
fn reverting_or_deleting_snapshots_is_high_even_for_one_vm() {
    let t = vms(1);
    assert_eq!(
        tier(snapshot(SnapshotOp::Revert { name: "base".into() }, &t), &t),
        Tier::High
    );
    assert_eq!(
        tier(snapshot(SnapshotOp::Delete { name: "old".into() }, &t), &t),
        Tier::High
    );
}

#[test]
fn dangerous_commands_are_high() {
    let t = vec![host(Environment::Lab)];
    for script in [
        "rm -rf /var/tmp/build",
        "rm -fr ./cache",
        "rm -f -r ./cache",
        "rm --recursive /opt/old",
        "/bin/rm -Rf /srv/x",
        "sudo mkfs.ext4 /dev/sdb1",
        "mkfs -t xfs /dev/sdc",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "sudo shutdown -h now",
        "reboot",
        "systemctl poweroff",
        "init 0",
        "iptables -F",
        "ip6tables --flush INPUT",
        "iptables -t nat -F",
        "mysql -e 'DROP DATABASE prod'",
        "psql -c \"drop database app\"",
        "uptime; rm -rf /tmp/x",
    ] {
        assert_eq!(tier(exec(script, &t), &t), Tier::High, "{script}");
    }
}

#[test]
fn harmless_lookalikes_are_not_flagged_dangerous() {
    let e = engine();
    for script in [
        "rm -f file.txt",
        "perform -rf",
        "add user",
        "cat shutdown.log",
        "iptables -L",
    ] {
        assert!(e.dangerous_matches(script).is_empty(), "{script}");
    }
}

#[test]
fn high_tier_steps_for_vms() {
    let t = vms(3);
    let d = engine().evaluate(&power(PowerOp::Stop { mode: SOFT }, &t), &t);
    assert_eq!(
        d.steps,
        vec![
            ApprovalStep::ImpactPreview,
            ApprovalStep::SafetySnapshot { default_on: true },
            ApprovalStep::TypeTargetCount { expected: 3 },
            ApprovalStep::Reason,
            ApprovalStep::Countdown { seconds: 10 },
        ]
    );
}

#[test]
fn high_tier_on_hosts_has_no_safety_snapshot() {
    let t = vec![host(Environment::Lab), host(Environment::Lab)];
    let d = engine().evaluate(&exec("rm -rf /tmp/x", &t), &t);
    assert!(!d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    assert!(d.steps.contains(&ApprovalStep::TypeTargetCount { expected: 2 }));
}

// ---- Critical ----------------------------------------------------------------------------------

#[test]
fn hard_power_off_is_critical_even_for_one_vm() {
    let t = vms(1);
    assert_eq!(tier(power(PowerOp::Stop { mode: HARD }, &t), &t), Tier::Critical);
    assert_eq!(tier(power(PowerOp::Reset { mode: HARD }, &t), &t), Tier::Critical);
}

#[test]
fn critical_tier_adds_vault_reauth_after_the_high_steps() {
    let t = vms(2);
    let d = engine().evaluate(&power(PowerOp::Stop { mode: HARD }, &t), &t);
    assert_eq!(d.steps.last(), Some(&ApprovalStep::VaultReauth));
    assert!(d.steps.contains(&ApprovalStep::Countdown { seconds: 10 }));
    assert!(d.steps.contains(&ApprovalStep::Reason));
}

// ---- Prod moves the action up one tier ---------------------------------------------------------

#[test]
fn prod_target_moves_the_action_up_one_tier() {
    let prod = vec![host(Environment::Prod)];
    assert_eq!(tier(exec("uptime", &prod), &prod), Tier::Medium);
    assert_eq!(tier(exec("systemctl restart nginx", &prod), &prod), Tier::High);
    assert_eq!(
        tier(exec("rm -rf /tmp/x", &prod), &prod),
        Tier::Critical,
        "any High action on Prod"
    );
}

#[test]
fn one_prod_target_in_a_bulk_action_bumps_the_whole_action() {
    let mut t = vms(3);
    t[1].environment = Environment::Prod;
    assert_eq!(tier(power(PowerOp::Start { gui: false }, &t), &t), Tier::Medium);
    assert_eq!(tier(power(PowerOp::Suspend, &t), &t), Tier::Critical);
}

#[test]
fn critical_on_prod_stays_critical() {
    let mut t = vms(1);
    t[0].environment = Environment::Prod;
    assert_eq!(tier(power(PowerOp::Stop { mode: HARD }, &t), &t), Tier::Critical);
}

#[test]
fn staging_does_not_bump() {
    let t = vec![host(Environment::Staging)];
    assert_eq!(tier(exec("uptime", &t), &t), Tier::Low);
}

// ---- Protected targets (AP-04) -----------------------------------------------------------------

#[test]
fn protected_targets_are_skipped_and_do_not_count() {
    let mut t = vms(2);
    t[0].protected = true;
    let d = engine().evaluate(&power(PowerOp::Suspend, &t), &t);
    assert_eq!(d.targets.len(), 1);
    assert_eq!(d.skipped.len(), 1);
    assert_eq!(d.tier, Tier::Medium, "suspending the one remaining VM");
}

#[test]
fn a_protected_prod_target_does_not_bump() {
    let mut t = vms(2);
    t[0].environment = Environment::Prod;
    t[0].protected = true;
    assert_eq!(tier(power(PowerOp::Start { gui: false }, &t), &t), Tier::Low);
}

fn protect(protected: bool, targets: &[Target]) -> Command {
    Command::VmProtect {
        targets: refs(targets),
        protected,
    }
}

#[test]
fn protecting_vms_is_low_and_unprotecting_them_is_medium() {
    for n in [1, 3] {
        let t = vms(n);
        assert_eq!(tier(protect(true, &t), &t), Tier::Low, "protect {n}");
        assert_eq!(tier(protect(false, &t), &t), Tier::Medium, "unprotect {n}");
    }
    let t = vms(2);
    let d = engine().evaluate(&protect(false, &t), &t);
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
}

#[test]
fn changing_protection_never_skips_protected_targets() {
    let mut t = vms(2);
    t[0].protected = true;
    t[1].protected = true;
    for protected in [true, false] {
        let d = engine().evaluate(&protect(protected, &t), &t);
        assert_eq!(d.targets.len(), 2);
        assert!(d.skipped.is_empty());
    }
}

#[test]
fn unprotecting_a_prod_vm_is_high_without_a_safety_snapshot() {
    let mut t = vms(1);
    t[0].environment = Environment::Prod;
    let d = engine().evaluate(&protect(false, &t), &t);
    assert_eq!(d.tier, Tier::High);
    assert!(
        !d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })),
        "changing protection does not touch the VM"
    );
}

#[test]
fn rules_saved_before_protection_existed_still_load() {
    let mut saved = PolicyRules::default();
    saved.tiers.remove(&ActionKind::VmProtect);
    saved.tiers.remove(&ActionKind::VmUnprotect);
    saved.tiers.insert(ActionKind::VmStart, TierRule::same(Tier::Medium));
    assert!(PolicyEngine::new(saved.clone()).is_err());

    saved.fill_missing_tiers();
    let e = PolicyEngine::new(saved).unwrap();
    let t = vms(1);
    assert_eq!(
        e.evaluate(&protect(false, &t), &t).tier,
        Tier::Medium,
        "default filled in"
    );
    assert_eq!(
        e.evaluate(&power(PowerOp::Start { gui: false }, &t), &t).tier,
        Tier::Medium,
        "the user's own tier is kept"
    );
}

// ---- Rules are editable (AP-01) ----------------------------------------------------------------

#[test]
fn edited_rules_change_the_tier() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(
        ActionKind::VmStart,
        TierRule {
            single: Tier::Low,
            bulk: Tier::Medium,
        },
    );
    rules.prod_bump = false;
    let e = PolicyEngine::new(rules).unwrap();

    let one = vms(1);
    let many = vms(4);
    assert_eq!(
        e.evaluate(&power(PowerOp::Start { gui: false }, &one), &one).tier,
        Tier::Low
    );
    assert_eq!(
        e.evaluate(&power(PowerOp::Start { gui: false }, &many), &many).tier,
        Tier::Medium
    );

    let prod = vec![host(Environment::Prod)];
    assert_eq!(
        e.evaluate(&exec("uptime", &prod), &prod).tier,
        Tier::Low,
        "prod bump off"
    );
}

#[test]
fn custom_dangerous_pattern_is_applied() {
    let mut rules = PolicyRules::default();
    rules.dangerous_commands.push(DangerousPattern {
        name: "kubectl delete".into(),
        pattern: r"\bkubectl\s+delete\b".into(),
    });
    let e = PolicyEngine::new(rules).unwrap();
    let t = vec![host(Environment::Lab)];
    assert_eq!(e.evaluate(&exec("kubectl delete ns staging", &t), &t).tier, Tier::High);
}

#[test]
fn invalid_rules_are_rejected() {
    let mut bad_regex = PolicyRules::default();
    bad_regex.dangerous_commands.push(DangerousPattern {
        name: "broken".into(),
        pattern: "(".into(),
    });
    assert!(matches!(
        PolicyEngine::new(bad_regex),
        Err(CoreError::InvalidRule { .. })
    ));

    let mut missing = PolicyRules::default();
    missing.tiers.remove(&ActionKind::VmStopHard);
    assert!(matches!(PolicyEngine::new(missing), Err(CoreError::InvalidRule { .. })));

    let threshold = PolicyRules {
        bulk_threshold: 1,
        ..Default::default()
    };
    assert!(PolicyEngine::new(threshold).is_err());
}

#[test]
fn rules_round_trip_through_json() {
    let rules = PolicyRules::default();
    let json = serde_json::to_string(&rules).unwrap();
    let back: PolicyRules = serde_json::from_str(&json).unwrap();
    assert_eq!(rules, back);
}

#[test]
fn tier_bump_caps_at_critical() {
    assert_eq!(Tier::Low.bump(), Tier::Medium);
    assert_eq!(Tier::Medium.bump(), Tier::High);
    assert_eq!(Tier::High.bump(), Tier::Critical);
    assert_eq!(Tier::Critical.bump(), Tier::Critical);
    assert!(Tier::Low < Tier::Medium && Tier::High < Tier::Critical);
}

// ---- Warnings before an action (VM-07) ---------------------------------------------------------

#[test]
fn a_warning_adds_one_confirm_to_an_action_without_a_dialog() {
    let t = vms(2);
    let mut d = engine().evaluate(&power(PowerOp::Start { gui: false }, &t), &t);
    d.add_warnings(vec!["not enough RAM".into()]);
    assert_eq!(d.tier, Tier::Low, "the tier stays");
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
    assert_eq!(d.warnings, ["not enough RAM"]);
}

#[test]
fn a_warning_leaves_the_steps_of_a_tier_with_a_dialog_alone() {
    let mut t = vms(2);
    t[0].environment = Environment::Prod;
    let start = power(PowerOp::Start { gui: false }, &t);
    let stop = power(PowerOp::Stop { mode: SOFT }, &t);
    for command in [start, stop] {
        let mut d = engine().evaluate(&command, &t);
        let before = d.steps.clone();
        d.add_warnings(vec!["low disk".into()]);
        assert_eq!(d.steps, before);
        assert_eq!(d.warnings.len(), 1);
    }
}

#[test]
fn no_warnings_change_nothing() {
    let t = vms(1);
    let mut d = engine().evaluate(&power(PowerOp::Start { gui: false }, &t), &t);
    d.add_warnings(vec![]);
    assert!(d.steps.is_empty());
    assert!(d.warnings.is_empty());
}

// ---- Safety snapshot (VM-05) -------------------------------------------------------------------

fn offers_safety_snapshot(e: &PolicyEngine, command: &Command, targets: &[Target]) -> Option<bool> {
    e.evaluate(command, targets).steps.iter().find_map(|s| match s {
        ApprovalStep::SafetySnapshot { default_on } => Some(*default_on),
        _ => None,
    })
}

#[test]
fn stop_reset_suspend_and_revert_offer_a_safety_snapshot_on_by_default() {
    let e = engine();
    let t = vms(2);
    for command in [
        power(PowerOp::Stop { mode: SOFT }, &t),
        power(PowerOp::Stop { mode: HARD }, &t),
        power(PowerOp::Reset { mode: SOFT }, &t),
        power(PowerOp::Reset { mode: HARD }, &t),
        power(PowerOp::Suspend, &t),
        snapshot(SnapshotOp::Revert { name: "base".into() }, &t),
    ] {
        assert_eq!(offers_safety_snapshot(&e, &command, &t), Some(true), "{command:?}");
    }
}

#[test]
fn a_prod_vm_gets_a_safety_snapshot_once_the_bump_makes_it_high() {
    let mut t = vms(1);
    t[0].environment = Environment::Prod;
    let suspend = power(PowerOp::Suspend, &t);
    assert_eq!(engine().evaluate(&suspend, &t).tier, Tier::High);
    assert_eq!(offers_safety_snapshot(&engine(), &suspend, &t), Some(true));
}

#[test]
fn actions_with_nothing_to_undo_get_no_safety_snapshot_even_when_high() {
    // Every action High, so only the kind of action decides.
    let mut rules = PolicyRules::default();
    for rule in rules.tiers.values_mut() {
        *rule = TierRule::same(Tier::High);
    }
    let e = PolicyEngine::new(rules).unwrap();
    let t = vms(2);
    for command in [
        power(PowerOp::Start { gui: false }, &t),
        power(PowerOp::Pause, &t),
        power(PowerOp::Unpause, &t),
        snapshot(SnapshotOp::Take { name: "x".into() }, &t),
        // Deleting snapshots to free space would add one per VM, and the deleted one is not in it.
        snapshot(SnapshotOp::Delete { name: "old".into() }, &t),
        protect(true, &t),
        protect(false, &t),
    ] {
        assert_eq!(e.evaluate(&command, &t).tier, Tier::High, "{command:?}");
        assert_eq!(offers_safety_snapshot(&e, &command, &t), None, "{command:?}");
    }
}

#[test]
fn the_safety_snapshot_default_is_a_rule() {
    let rules = PolicyRules {
        safety_snapshot_default: false,
        ..Default::default()
    };
    let e = PolicyEngine::new(rules).unwrap();
    let t = vms(3);
    assert_eq!(
        offers_safety_snapshot(&e, &power(PowerOp::Stop { mode: SOFT }, &t), &t),
        Some(false)
    );
}

#[test]
fn the_job_runner_and_the_dialog_share_one_safety_snapshot_rule() {
    let t = vms(2);
    assert!(safety_snapshot_applies(&power(PowerOp::Suspend, &t)));
    assert!(!safety_snapshot_applies(&power(PowerOp::Start { gui: true }, &t)));
    let hosts = vec![host(Environment::Lab)];
    assert!(!safety_snapshot_applies(&exec("reboot", &hosts)), "not a VM");
}

// ---- Editable rules are checked (AP-01) ---------------------------------------------------------

fn rule_error(rules: PolicyRules) -> String {
    match rules.validate() {
        Err(CoreError::InvalidRule { name, message }) => format!("{name}: {message}"),
        other => panic!("expected an invalid rule, got {other:?}"),
    }
}

#[test]
fn the_default_rules_are_valid() {
    PolicyRules::default().validate().unwrap();
}

#[test]
fn the_bulk_tier_cannot_be_lower_than_the_single_target_tier() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(
        ActionKind::VmStopSoft,
        TierRule {
            single: Tier::High,
            bulk: Tier::Medium,
        },
    );
    let message = rule_error(rules);
    assert!(message.starts_with("Shut down VMs: "), "{message}");
    assert!(message.contains("can't be lower"), "{message}");
}

#[test]
fn the_bulk_threshold_and_countdown_have_bounds() {
    for threshold in [0, 1, MAX_BULK_THRESHOLD + 1] {
        let rules = PolicyRules {
            bulk_threshold: threshold,
            ..Default::default()
        };
        assert!(rule_error(rules).starts_with("Bulk threshold"), "{threshold}");
    }
    let rules = PolicyRules {
        countdown_seconds: MAX_COUNTDOWN_SECONDS + 1,
        ..Default::default()
    };
    assert!(rule_error(rules).starts_with("Countdown"));
    // 0 turns the countdown off; that is the user's call.
    PolicyRules {
        countdown_seconds: 0,
        ..Default::default()
    }
    .validate()
    .unwrap();
}

#[test]
fn dangerous_patterns_need_a_unique_name_and_a_pattern_that_does_not_match_everything() {
    let with = |name: &str, pattern: &str| {
        let mut rules = PolicyRules::default();
        rules.dangerous_commands.push(DangerousPattern {
            name: name.into(),
            pattern: pattern.into(),
        });
        rules
    };
    assert!(rule_error(with(" ", r"\bkubectl\b")).contains("give the pattern a name"));
    assert!(rule_error(with("kubectl", "  ")).contains("the pattern is empty"));
    assert!(rule_error(with("kubectl", "(")).contains("not a valid regular expression"));
    assert!(rule_error(with("everything", ".*")).contains("matches every command"));
    assert!(rule_error(with("MKFS", r"\bmkfs2\b")).contains("another dangerous-command rule has this name"));
    with("kubectl delete", r"\bkubectl\s+delete\b").validate().unwrap();
}

#[test]
fn read_only_entries_cannot_hold_shell_operators_or_repeat() {
    let with = |entry: &str| {
        let mut rules = PolicyRules::default();
        rules.read_only_commands.push(entry.into());
        rules
    };
    for entry in [
        "cat x; rm -rf /",
        "ls > out",
        "echo $(id)",
        "a && b",
        "tee | x",
        "sub (shell)",
    ] {
        assert!(rule_error(with(entry)).contains("shell operator"), "{entry}");
    }
    assert!(rule_error(with("  ")).contains("empty"));
    assert!(rule_error(with("systemctl  status")).contains("listed twice"));
    with("zfs list").validate().unwrap();
}

#[test]
fn normalizing_trims_names_and_collapses_spaces() {
    let rules = PolicyRules {
        dangerous_commands: vec![DangerousPattern {
            name: "  kubectl delete ".into(),
            pattern: r" \bkubectl\s+delete\b ".into(),
        }],
        read_only_commands: vec!["  systemctl   status ".into()],
        ..Default::default()
    };
    let n = rules.normalized();
    assert_eq!(n.dangerous_commands[0].name, "kubectl delete");
    assert_eq!(n.dangerous_commands[0].pattern, r"\bkubectl\s+delete\b");
    assert_eq!(n.read_only_commands, ["systemctl status"]);
}

#[test]
fn changes_say_what_differs_for_the_audit_log() {
    let old = PolicyRules::default();
    assert!(old.changes(&old.clone()).is_empty());

    let mut new = old.clone();
    new.tiers.insert(
        ActionKind::VmPause,
        TierRule {
            single: Tier::Medium,
            bulk: Tier::High,
        },
    );
    new.countdown_seconds = 5;
    new.prod_bump = false;
    new.safety_snapshot_default = false;
    new.bulk_threshold = 3;
    new.dangerous_commands.retain(|p| p.name != "dd");
    new.dangerous_commands.push(DangerousPattern {
        name: "kubectl delete".into(),
        pattern: r"\bkubectl\s+delete\b".into(),
    });
    new.read_only_commands.retain(|c| c != "w");
    new.read_only_commands.push("zfs list".into());
    assert_eq!(
        old.changes(&new),
        [
            "Pause VMs: medium for one, medium in bulk -> medium for one, high in bulk",
            "Bulk threshold: 2 -> 3 targets",
            "Prod raises the tier: on -> off",
            "Countdown: 10 -> 5 s",
            "Safety snapshot by default: on -> off",
            r"Dangerous command added: kubectl delete = \bkubectl\s+delete\b",
            "Dangerous command removed: dd",
            "Read-only command added: zfs list",
            "Read-only command removed: w",
        ]
    );
}

#[test]
fn every_action_is_listed_once_with_a_label_and_a_default_tier() {
    let mut seen = std::collections::HashSet::new();
    let defaults = PolicyRules::default();
    for kind in ActionKind::ALL {
        assert!(seen.insert(kind), "{kind:?} listed twice");
        assert!(!kind.label().is_empty());
        assert!(defaults.tiers.contains_key(&kind), "{kind:?} has no default");
    }
    assert_eq!(seen.len(), defaults.tiers.len());
}

#[test]
fn reasons_name_the_action_in_words() {
    let t = vms(2);
    let d = engine().evaluate(&power(PowerOp::Suspend, &t), &t);
    assert_eq!(d.reasons[0], "Suspend VMs on 2 targets: high");
}

// ---- BX-06: which rule matched, for the editor and the approval dialog ----------------------------

#[test]
fn dangerous_details_name_each_rule_with_the_line_it_matched() {
    let e = engine();
    let found = e.dangerous_details("cd /srv\nsudo rm -rf /var/cache/app\nmkfs.ext4 /dev/sdb1\nrm -rf /tmp/x");
    assert_eq!(
        found,
        vec![
            DangerousMatch {
                rule: "rm -r / rm -rf".into(),
                text: "sudo rm -rf /var/cache/app".into(),
                line: 2,
            },
            DangerousMatch {
                rule: "mkfs".into(),
                text: "mkfs.ext4 /dev/sdb1".into(),
                line: 3,
            },
        ],
        "one entry per rule, at its first match"
    );
    let first_line = e.dangerous_details("shutdown -r now");
    assert_eq!(
        (first_line[0].line, first_line[0].text.as_str()),
        (1, "shutdown -r now")
    );
    let joined = e.dangerous_details("echo bye; reboot");
    assert_eq!(
        (joined[0].rule.as_str(), joined[0].text.as_str()),
        ("shutdown / reboot", "echo bye; reboot")
    );
    assert!(e.dangerous_details("uptime\ndf -h").is_empty());
}

// ---- BX-06: forms of read-only commands that write ----------------------------------------------

/// With `read_only` as the read-only list (the defaults when `None`), each of `reads` is read-only
/// and each of `writes` is "other": a bulk run or MultiExec asks before it sends one.
fn reads_and_writes(read_only: Option<&[&str]>, reads: &[&str], writes: &[&str]) {
    let mut rules = PolicyRules::default();
    if let Some(list) = read_only {
        rules.read_only_commands = list.iter().map(|s| s.to_string()).collect();
    }
    let e = PolicyEngine::new(rules).expect("valid rules");
    for script in reads {
        assert_eq!(e.classify_script(script), ActionKind::ExecReadOnly, "reads: {script}");
    }
    for script in writes {
        assert_eq!(e.classify_script(script), ActionKind::ExecOther, "writes: {script}");
    }
}

#[test]
fn ip_reads_only_when_it_shows_lists_or_gets() {
    reads_and_writes(
        None,
        &[
            "ip a",
            "ip addr",
            "ip addr show dev eth0",
            "ip a s",
            "ip a list",
            "ip -br a",
            "ip -br a show eth0",
            "ip route",
            "ip r",
            "ip route show table all",
            "ip route get 192.0.2.1",
            "ip r g 192.0.2.1",
            "ip link",
            "sudo ip link show eth0",
            "ip link ls",
            "ip neigh show",
        ],
        &[
            "ip link set eth0 down",
            "sudo ip link set dev eth0 mtu 9000",
            "ip link s eth0 down",
            "ip link add br0 type bridge",
            "ip link delete br0",
            "ip route add 198.51.100.0/24 via 192.0.2.1",
            "ip r del default",
            "ip r a 198.51.100.0/24 via 192.0.2.1",
            "ip route replace default via 192.0.2.1",
            "ip route flush cache",
            "ip route restore",
            "ip a add 192.0.2.5/24 dev eth0",
            "ip a a 192.0.2.5/24 dev eth0",
            "ip addr del 192.0.2.5/24 dev eth0",
            "ip a flush dev eth0",
            "ip -br a add 192.0.2.5/24 dev eth0",
            "ip link $ACTION eth0",
        ],
    );
    // A saved list with `ip` alone: options before the object are read, and only show/list/get read.
    reads_and_writes(
        Some(&["ip"]),
        &[
            "ip",
            "ip -4 -o addr show",
            "ip -s -s link",
            "ip -n blue route",
            "ip -j -p a",
            "ip netns",
            "ip rule show",
        ],
        &[
            "ip -batch /tmp/commands",
            "ip -b /tmp/commands",
            "ip -force -batch /tmp/commands",
            "ip -n blue link set eth0 up",
            "ip netns exec blue ip link set lo up",
            "ip netns add blue",
            "ip netns s blue 1",
            "ip rule add from 192.0.2.0/24 table 100",
            "ip $OBJECT show",
            "ip -n $NS link",
        ],
    );
}

#[test]
fn systemctl_reads_only_with_a_verb_that_shows_something() {
    reads_and_writes(
        None,
        &[
            "systemctl status nginx",
            "systemctl --failed",
            "systemctl --failed --no-legend",
            "systemctl list-units --type=service --state=running",
            "systemctl list-units --type service",
            "systemctl is-active nginx",
            "systemctl cat nginx",
        ],
        &[
            "systemctl --failed restart nginx",
            "systemctl --failed stop nginx",
            "sudo systemctl --failed --type service stop nginx",
            "systemctl --failed $VERB nginx",
        ],
    );
    reads_and_writes(
        Some(&["systemctl"]),
        &[
            "systemctl",
            "systemctl -t service --state failed",
            "systemctl -H web01.example.com status nginx",
            "systemctl --no-pager show nginx -p MainPID",
            "systemctl list-dependencies sshd",
            "systemctl get-default",
        ],
        &[
            "systemctl enable --now nginx",
            "systemctl -q stop nginx",
            "systemctl --type service start nginx",
            "systemctl daemon-reload",
            "systemctl set-default multi-user.target",
            "systemctl -H $HOST status",
        ],
    );
}

#[test]
fn timedatectl_and_hostnamectl_read_only_when_they_show() {
    reads_and_writes(
        None,
        &[
            "timedatectl",
            "timedatectl status",
            "timedatectl show --property=NTP --value",
            "timedatectl list-timezones",
            "timedatectl timesync-status",
            "timedatectl -H web01.example.com status",
            "hostnamectl status",
            "hostnamectl status --static",
        ],
        &[
            "timedatectl set-time '2026-10-19 12:00:00'",
            "sudo timedatectl set-timezone UTC",
            "timedatectl set-ntp true",
            "timedatectl --adjust-system-clock set-local-rtc 1",
            "timedatectl ntp-servers eth0 192.0.2.123",
            "timedatectl revert eth0",
        ],
    );
    reads_and_writes(
        Some(&["hostnamectl"]),
        &[
            "hostnamectl",
            "hostnamectl hostname",
            "hostnamectl hostname --static",
            "hostnamectl chassis",
        ],
        &[
            "hostnamectl hostname web02",
            "hostnamectl set-hostname web02",
            "sudo hostnamectl chassis vm",
            "hostnamectl set-location rack-1",
        ],
    );
}

#[test]
fn env_reads_alone_or_when_it_runs_a_read_only_command_with_harmless_settings() {
    reads_and_writes(
        None,
        &[
            "env",
            "env | sort",
            "env -0",
            "env -u HOME",
            "env -i",
            "env --null",
            "env LC_ALL=C",
            // The command env runs is classified like any other.
            "env cat /etc/hosts",
            "env LC_ALL=C sort /tmp/table",
            "env TZ=UTC date",
            "env -i TZ=UTC date +%F",
            "env -u PAGER -u LESS systemctl status sshd",
            "env -iu PAGER uptime",
            "env --unset=PAGER uptime",
            "env - LANG=C ls /var/log",
            "env -- LC_ALL=C sort /tmp/table",
            "sudo env LANG=C journalctl -u nginx",
            "LC_ALL=C env TZ=UTC date",
        ],
        &[
            "env systemctl stop nginx",
            "env LANG=C apt-get -y upgrade",
            "sudo env -i PATH=/usr/bin systemctl restart nginx",
            "env -S 'systemctl stop nginx'",
            "env -u HOME journalctl --vacuum-time=1d",
            "env $COMMAND",
            "env TZ=UTC date -s 12:00",
            "env LC_ALL=C sort -o /tmp/out /tmp/table",
            // Settings that are not harmless, with a command or without one.
            "env LD_PRELOAD=/tmp/x.so cat /etc/hosts",
            "env PAGER=/tmp/x systemctl status sshd",
            "env LESSOPEN='|/tmp/x %s' less /etc/hosts",
            "env -i PATH=/tmp/bin uptime",
            "env TZ=UTC LD_PRELOAD=/tmp/x.so date",
            "env LANG=C env LD_PRELOAD=/tmp/x.so cat /etc/hosts",
            "env LD_PRELOAD=/tmp/x.so",
            // Options other than -i, - and -u.
            "env -C /tmp cat x",
            "env --chdir=/tmp cat x",
            "env -v uptime",
            "env --ignore-signal=INT uptime",
        ],
    );
}

#[test]
fn a_setting_that_can_load_code_or_run_a_program_is_not_read_only() {
    // The locale, time zone, terminal and colours only change what the output looks like; most other
    // variables can make a read-only command load a library, start a program or write a file.
    reads_and_writes(
        None,
        &[
            "LC_ALL=C sort /tmp/table",
            "TZ=UTC date",
            "TZ='America/New_York' date",
            "LANG=en_US.UTF-8 ls -l /var/log",
            "LC_ALL=C LANG=C df -h",
            "LC_TIME=C.UTF-8 last -n 5",
            "TERM=dumb top -b -n 1",
            "COLUMNS=200 ps aux",
            "NO_COLOR=1 SYSTEMD_COLORS=0 systemctl status sshd",
            "TIME_STYLE=long-iso ls -l",
            "S_TIME_FORMAT=ISO iostat -x 1 2",
            "SYSTEMD_PAGER= systemctl status sshd",
            "PAGER=cat journalctl -u nginx",
            "sudo LC_ALL=C journalctl -u nginx",
            "TZ=UTC; date",
            "uptime && LC_ALL=C sort /tmp/table | head",
        ],
        &[
            "LD_PRELOAD=/tmp/x.so cat /etc/hosts",
            "LD_LIBRARY_PATH=/tmp cat /etc/hosts",
            "GCONV_PATH=/tmp cat /etc/hosts",
            "LESSOPEN='|/tmp/x %s' less /etc/hosts",
            "LESS=-o/tmp/log less /etc/hosts",
            "LESSKEY=/tmp/keys less /etc/hosts",
            "SYSTEMD_LESS=-o/tmp/log systemctl status sshd",
            "PAGER=/tmp/x systemctl status sshd",
            "SYSTEMD_PAGER='sh -c /tmp/x' journalctl",
            "PAGER=$P journalctl",
            "PATH=/tmp/bin:$PATH uptime",
            "BASH_ENV=/tmp/x uptime",
            "ENV=/tmp/x uptime",
            "EDITOR=/tmp/x systemctl status sshd",
            "KUBECONFIG=/tmp/kubeconfig kubectl get pods",
            "DOCKER_HOST=ssh://bob@web01.example.com docker ps",
            "GIT_SSH_COMMAND=/tmp/x ls",
            // A locale with `/` is a folder to load.
            "LC_ALL=/tmp/locale sort /tmp/table",
            "LANG=$L ls",
            // On their own they last for the rest of the script, and in MultiExec's shell for the lines
            // after it; PROMPT_COMMAND runs before every prompt.
            "PATH=/tmp/bin; uptime",
            "PROMPT_COMMAND=/tmp/x; uptime",
            "LC_ALL=C LD_PRELOAD=/tmp/x.so sort /tmp/table",
            "LD_PRELOAD=/tmp/x.so sudo cat /etc/shadow",
            "sudo LD_PRELOAD=/tmp/x.so cat /etc/shadow",
            "uptime; LD_PRELOAD=/tmp/x.so cat /etc/hosts",
        ],
    );
}

#[test]
fn journalctl_reads_unless_it_vacuums_rotates_flushes_or_writes_a_file() {
    reads_and_writes(
        None,
        &[
            "journalctl -u nginx --since today",
            "journalctl -b -p err --no-pager",
            "journalctl -k -n 100",
            "journalctl --since '1 hour ago' --no-pager",
            "journalctl -f",
            "journalctl --list-boots",
            "journalctl --disk-usage",
            "journalctl --verify",
            "journalctl --cursor=s=0123 -n 5",
            "journalctl --after-cursor s=0123",
        ],
        &[
            "sudo journalctl --vacuum-size=100M",
            "journalctl --vacuum-time 2weeks",
            "journalctl --vacuum-files=5",
            "journalctl --vacuum-s=1G",
            "journalctl --rotate",
            "journalctl --rot",
            "journalctl --flush",
            "journalctl --sync",
            "journalctl --relinquish-var",
            "journalctl --smart-relinquish-var",
            "journalctl --setup-keys",
            "journalctl --update-catalog",
            "journalctl -u nginx --cursor-file=/tmp/cursor",
            "journalctl -u $UNIT",
            "journalctl $OPTIONS",
        ],
    );
}

#[test]
fn dmesg_reads_unless_it_clears_the_buffer_or_sets_the_console() {
    reads_and_writes(
        None,
        &[
            "dmesg",
            "dmesg -T",
            "dmesg -T | tail -50",
            "dmesg --level=err,warn",
            "dmesg -l err",
            "dmesg -lcrit",
            "dmesg -Lnever",
            "dmesg -w",
        ],
        &[
            "dmesg -C",
            "sudo dmesg -c",
            "dmesg -Tc",
            "dmesg --clear",
            "dmesg --read-clear",
            "dmesg -n 1",
            "dmesg --console-level 1",
            "dmesg -D",
            "dmesg -E",
            "dmesg --console-off",
        ],
    );
}

#[test]
fn date_and_hostname_read_unless_they_set_the_clock_or_the_name() {
    reads_and_writes(
        None,
        &[
            "date",
            "date +%F",
            "date -u '+%F %T'",
            "date -R",
            "date -Iseconds",
            "date --iso-8601=seconds",
            "date -d '2 days ago' +%F",
            "date -d @1700000000",
            "date --date 'next friday'",
            "date -r /etc/hosts",
            "date --rfc-3339 seconds",
            "hostname",
            "hostname -f",
            "hostname -I",
            "hostname --fqdn",
            "hostname -s",
            "hostname -A",
        ],
        &[
            "date -s '2026-10-19 12:00'",
            "sudo date --set='2026-10-19 12:00'",
            "date --set 12:00",
            "date -us 12:00",
            "date 101912002026",
            "date -u 101912002026",
            "date -- 1019120026",
            "date $NOW",
            "hostname web02",
            "sudo hostname web02.example.com",
            "hostname -F /etc/hostname",
            "hostname --file /etc/hostname",
            "hostname -b web02",
            "hostname --boot",
            "hostname $NAME",
        ],
    );
}

#[test]
fn ss_reads_unless_it_kills_sockets_or_dumps_them_to_a_file() {
    reads_and_writes(
        None,
        &[
            "ss -tulpn",
            "sudo ss -tulpn",
            "ss -tan state established",
            "ss -s",
            "ss -f inet -n",
            "ss -tnp dst 192.0.2.1",
        ],
        &[
            "ss -K dst 192.0.2.1",
            "sudo ss -tK dport = 22",
            "ss --kill dst 192.0.2.1",
            "ss -D /tmp/sockets",
            "ss --diag=/tmp/sockets",
        ],
    );
}

#[test]
fn sort_and_uniq_read_unless_they_write_an_output_file() {
    reads_and_writes(
        None,
        &[
            "sort -h",
            "sudo du -xh --max-depth=1 /var 2>/dev/null | sort -h | tail -20",
            "sort -rn /tmp/counts",
            "sort -t: -k3 -n /etc/passwd",
            "sort -nk2 /tmp/counts",
            "cut -d: -f1 /etc/passwd | sort | uniq -c",
            "uniq -c",
            "uniq -f 1 /var/log/app.log",
            "uniq --skip-fields 1 /var/log/app.log",
        ],
        &[
            "sort -o /etc/hosts /etc/hosts",
            "sort --output=/tmp/sorted /tmp/counts",
            "sort -uo /tmp/sorted /tmp/counts",
            "sort --compress-program=gzip /tmp/counts",
            "sort -k2 $FILE",
            "uniq /tmp/in /tmp/out",
            "sort /tmp/in | uniq - /tmp/out",
        ],
    );
}

#[test]
fn less_and_file_read_unless_they_write_a_log_or_a_magic_file() {
    reads_and_writes(
        Some(&["less", "file"]),
        &[
            "less /var/log/syslog",
            "less -R /var/log/syslog",
            "less -N +G /var/log/syslog",
            "less -pfoo /var/log/syslog",
            "file /bin/ls",
            "file -L /etc/localtime",
            "file -m /usr/share/misc/magic /bin/ls",
        ],
        &[
            "less -o /tmp/log /var/log/syslog",
            "less -O/tmp/log /var/log/syslog",
            "less -No /tmp/log /var/log/syslog",
            "less --log-file=/tmp/log /var/log/syslog",
            "file -C -m /tmp/magic",
            "file --compile -m /tmp/magic",
        ],
    );
}

#[test]
fn rpm_reads_unless_it_pipes_to_a_command_or_expands_macros() {
    reads_and_writes(
        None,
        &[
            "rpm -q bash",
            "rpm -qa | sort",
            "rpm -qf /usr/bin/ssh",
            "rpm -qa --last",
            "rpm -q -i bash",
        ],
        &[
            "rpm -qa --pipe 'tee /tmp/packages'",
            "rpm -q --eval '%(id)'",
            "rpm -q -D '_dbpath /tmp' bash",
            "rpm -q --define '_dbpath /tmp' bash",
            "rpm -q --specfile /tmp/app.spec",
            "rpm -q $PACKAGE",
        ],
    );
}

#[test]
fn firewall_and_cluster_listings_read_unless_they_change_or_save_something() {
    reads_and_writes(
        None,
        &[
            "sudo iptables -L -n -v --line-numbers",
            "iptables -L INPUT -n",
            "sudo iptables -S",
            "sudo nft list ruleset",
            "nft list ruleset -a",
            "sudo firewall-cmd --list-all",
            "firewall-cmd --state",
            "firewall-cmd --list-all --zone=public",
            "firewall-cmd --list-all --permanent --zone public",
            "kubectl cluster-info",
            "kubectl cluster-info dump",
        ],
        &[
            "iptables -L -Z",
            "sudo iptables -L INPUT -n -Z",
            "iptables -L --zero",
            "iptables -S -Z",
            "sudo nft list ruleset -f /tmp/rules.nft",
            "firewall-cmd --list-all --add-port=80/tcp",
            "firewall-cmd --state --reload",
            "sudo firewall-cmd --list-all --zone=public --add-service=http",
            "firewall-cmd --list-all --remove-port=22/tcp",
            "firewall-cmd --list-all $MORE",
            "kubectl cluster-info dump --output-directory=/tmp/dump",
            "kubectl cluster-info dump --output-directory /tmp/dump",
        ],
    );
}

#[test]
fn redirects_into_files_and_process_substitution_are_not_read_only() {
    reads_and_writes(
        None,
        &[
            "systemctl status sshd 2>&1",
            "ls /var/log > /dev/null",
            "uptime >&2",
            "uptime 1>&2",
            "cat /etc/hosts 2>/dev/null",
            "df -h &>/dev/null",
            "uptime >/dev/null 2>&1",
            "uptime >&-",
        ],
        &[
            "echo hi >| w",
            "echo hi >|/tmp/x",
            "echo hi >&/tmp/x",
            "echo hi >& file",
            "uptime &>/tmp/x",
            "uptime &>> /tmp/x",
            "cat <(systemctl restart nginx)",
            "wc -l >(tee /tmp/x)",
        ],
    );
}

#[test]
fn quotes_and_comments_are_read_as_the_shell_reads_them() {
    reads_and_writes(
        None,
        &[
            "grep 'a b' /etc/hosts",
            "cat \"/etc/my file\"",
            "\"cat\" /etc/hosts",
            "uptime # how busy is it",
            "date # -s would set it",
            "sort -t$'\\t' -k2 /tmp/table",
            "LC_ALL=C sort /tmp/table",
            "TZ='America/New_York' date",
        ],
        &[
            "journalctl \"--vacuum-size=100M\"",
            "journalctl '--rotate'",
            "journalctl --vacuum\\-size=1M",
            "date -s\"12:00\"",
            "ip link 'set' eth0 down",
            "hostname 'web 02'",
        ],
    );
}

#[test]
fn a_saved_list_from_before_these_checks_gets_them_too() {
    // Rules saved by an older version keep their own list, entries the user added included; the
    // writing forms are caught in code, so there is nothing to migrate.
    let saved = [
        "ip link",
        "ip route",
        "journalctl",
        "date",
        "hostname",
        "timedatectl",
        "dmesg",
        "env",
        "systemctl --failed",
        "ip link set",
    ];
    reads_and_writes(
        Some(&saved),
        &[
            "ip link show",
            "ip route",
            "journalctl -u nginx",
            "date +%F",
            "hostname -f",
            "timedatectl",
            "dmesg -T",
            "env",
            "systemctl --failed",
        ],
        &[
            "ip link set eth0 down",
            "ip route add default via 192.0.2.1",
            "journalctl --vacuum-size=100M",
            "date -s 12:00",
            "hostname web02",
            "timedatectl set-time 12:00",
            "dmesg -C",
            "env systemctl stop nginx",
            "systemctl --failed stop nginx",
        ],
    );
}

#[test]
fn the_extended_library_commands_read_or_write() {
    // BX-08 (extended library): the reading forms of the commands added for the bigger library are
    // read-only, and their writing cousins are "other" (a bulk run or MultiExec asks first).
    reads_and_writes(
        None,
        &[
            // Storage: LVM and RAID, filesystems, SAN.
            "sudo pvs",
            "sudo vgs",
            "sudo lvs -a -o +devices",
            "sudo pvdisplay",
            "sudo vgdisplay",
            "sudo lvdisplay",
            "sudo xfs_info /",
            "sudo dumpe2fs -h /dev/sda1",
            "showmount -e nfs01.test",
            "nfsstat -c",
            "sudo multipath -ll",
            "sudo multipath -l",
            // Memory and processes.
            "sudo slabtop -o -s c",
            "smem -rs pss",
            "pidstat -dru 1 3",
            "sudo iotop -b -n 2 -o -k",
            "swapon --show",
            // Network.
            "traceroute -n host.test",
            "mtr -rwznc 10 host.test",
            "resolvectl status",
            "resolvectl query host.test",
            // System, services, logs.
            "localectl status",
            "systemd-analyze time",
            "systemd-analyze critical-chain --no-pager",
            // Packages.
            "apt-cache search nginx",
            "sudo apt-get check",
            "dpkg -C",
            "dpkg -V bash",
            "dpkg --get-selections",
            "apt-mark showhold",
            "apt-mark showmanual",
            "dnf repoquery nginx",
            "dnf search nginx",
            "dnf provides /usr/bin/ssh",
            "dnf grouplist",
            "dnf group list",
            "dnf updateinfo list security",
            "needs-restarting -r",
            "rpm -V bash",
            "rpm -K /tmp/pkg.rpm",
            // Users and security.
            "lslogins",
            "loginctl list-sessions",
            "loginctl session-status 1",
            "sestatus",
            "getsebool -a",
            "sudo aa-status",
            "sudo ausearch -m avc -ts recent",
            "sudo aureport",
            "sudo auditctl -l",
            "sudo auditctl -s",
            "sudo sshd -T",
            "sudo sshd -t",
            "sudo visudo -c",
            "sudo fail2ban-client status",
            "sudo fail2ban-client status sshd",
            "klist",
            // Firewall.
            "sudo nft list tables",
            // Web servers.
            "sudo nginx -t",
            "sudo nginx -T",
            "nginx -V",
            "sudo apachectl configtest",
            "sudo apache2ctl -S",
            "sudo httpd -t",
            // Databases.
            "sudo mysqladmin status",
            "sudo mysqladmin ping",
            "mysql --version",
            "psql --version",
            "pg_isready",
            "pg_lsclusters",
            // Scheduling and time.
            "crontab -l",
            "sudo crontab -l -u bob",
            "atq",
            "chronyc tracking",
            "chronyc sources -v",
            "ntpq -p -n",
            "sudo hwclock --show",
            // Identity.
            "realm list",
            "sudo sssctl domain-list",
            "adcli info example.test",
            // VMware Tools in the guest.
            "vmware-toolbox-cmd -v",
            "vmware-toolbox-cmd stat hosttime",
            "vmware-toolbox-cmd timesync status",
            "vmware-toolbox-cmd device list",
            // Containers and Kubernetes.
            "podman ps -a",
            "podman images",
            "podman pod ps",
            "podman system df",
            "docker version",
            "docker info",
            "docker volume ls",
            "docker compose logs",
            "kubectl api-resources",
            "kubectl rollout status deploy/web -n shop",
            "kubectl auth can-i --list",
            "kubectl config view",
            "helm list -A",
            "helm status web -n shop",
            "helm get values web",
            "helm repo list",
            "helm search repo nginx",
        ],
        &[
            // The writing cousins of the same commands.
            "sudo multipath -f mpatha",
            "swapon /dev/sdb2",
            "resolvectl flush-caches",
            "apt-mark hold nginx",
            "sudo dnf group install 'Development Tools'",
            "loginctl terminate-session 3",
            "sudo auditctl -w /etc/passwd -p wa",
            "sudo setsebool httpd_can_network_connect on",
            "sudo fail2ban-client set sshd unbanip 192.0.2.5",
            "sudo nginx -s reload",
            "sudo apachectl graceful",
            "sudo mysqladmin flush-logs",
            "crontab -r",
            "sudo chronyc makestep",
            "sudo hwclock --systohc",
            "sudo realm join example.test -U bob",
            "sudo sssctl cache-expire",
            "vmware-toolbox-cmd timesync enable",
            "vmware-toolbox-cmd device disconnect net0",
            "podman rm web",
            "docker volume rm data",
            "kubectl rollout restart deploy/web -n shop",
            "kubectl delete pod web-1 -n shop",
            "helm uninstall web -n shop",
            "helm repo add charts https://charts.test",
            "sudo nft add rule inet filter input tcp dport 22 accept",
            "sudo pvcreate /dev/sdb",
            "sudo lvextend -L +1G /dev/vg0/root",
        ],
    );
}

#[test]
fn smartctl_reads_health_and_writes_when_it_tests_or_sets() {
    // BX-08: `smartctl` reads SMART data; it writes to the device when it starts or aborts a
    // self-test (-t, -X) or turns a feature on or off (-s, -o, -S).
    reads_and_writes(
        None,
        &[
            "sudo smartctl -H /dev/sda",
            "sudo smartctl -a /dev/sda",
            "sudo smartctl -A /dev/sda",
            "sudo smartctl -x /dev/sda",
            "sudo smartctl -i /dev/sda",
            "sudo smartctl -l error /dev/sda",
            "sudo smartctl --scan",
            "sudo smartctl --all /dev/nvme0",
        ],
        &[
            "sudo smartctl -t short /dev/sda",
            "sudo smartctl -t long /dev/sda",
            "sudo smartctl -X /dev/sda",
            "sudo smartctl -s on /dev/sda",
            "sudo smartctl -o on /dev/sda",
            "sudo smartctl -S on /dev/sda",
            "sudo smartctl --test=short /dev/sda",
            "sudo smartctl --abort /dev/sda",
            "sudo smartctl --smart=on /dev/sda",
            "sudo smartctl -a -s on /dev/sda",
            "sudo smartctl -t $KIND /dev/sda",
        ],
    );
}

#[test]
fn sysctl_reads_a_parameter_and_writes_when_it_sets_one() {
    // BX-08: `sysctl` reads values (`-a`, a bare key); it writes with `-w`, a `name=value` operand or
    // by loading a file (`-p`, --load, --system).
    reads_and_writes(
        None,
        &[
            "sudo sysctl -a",
            "sysctl --all",
            "sysctl net.ipv4.ip_forward",
            "sysctl -n kernel.hostname",
            "sysctl vm.swappiness",
        ],
        &[
            "sudo sysctl -w net.ipv4.ip_forward=1",
            "sudo sysctl net.ipv4.ip_forward=1",
            "sudo sysctl kernel.hostname=web02",
            "sudo sysctl -p",
            "sudo sysctl -p /etc/sysctl.conf",
            "sudo sysctl --system",
            "sudo sysctl --load=/etc/sysctl.conf",
            "sudo sysctl -f /etc/sysctl.conf",
            "sysctl -w $PARAM",
        ],
    );
}

#[test]
fn openssl_inspects_certs_and_writes_when_it_creates_files_or_keys() {
    // BX-08: `openssl` reads certificates and keys and connects to TLS servers; it writes a file with
    // -out/-keyout, and the ca and rehash subcommands and the key generators write by design.
    reads_and_writes(
        None,
        &[
            "openssl x509 -in /tmp/c.pem -noout -dates",
            "openssl x509 -noout -text -in /tmp/c.pem",
            "openssl x509 -in /tmp/c.pem -noout -fingerprint -sha256",
            "openssl verify -CAfile /tmp/ca.pem /tmp/c.pem",
            "openssl req -in /tmp/r.csr -noout -text -verify",
            "openssl rsa -in /tmp/k.pem -noout -check",
            "openssl pkey -in /tmp/k.pem -noout -text",
            "openssl s_client -connect host.test:443 -servername host.test",
            "echo | openssl s_client -connect host.test:443",
            "openssl crl -in /tmp/c.crl -noout -text",
            "openssl ciphers -v",
            "openssl list -digest-algorithms",
            "openssl version",
        ],
        &[
            "openssl req -new -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/r.csr",
            "openssl x509 -in /tmp/c.pem -out /tmp/c.der -outform DER",
            "openssl x509 -in /tmp/c.pem -signkey /tmp/k.pem -out /tmp/s.pem",
            "openssl genrsa -out /tmp/k.pem 2048",
            "openssl genrsa 2048",
            "openssl genpkey -algorithm RSA",
            "sudo openssl ca -config /etc/pki/tls/openssl.cnf",
            "openssl rehash /etc/ssl/certs",
            "openssl x509 -in /tmp/c.pem -out $DEST",
            // Review #3: more write forms an allow-list has to cover.
            "openssl s_client -connect host.test:443 -sess_out /tmp/sess",
            "openssl s_client -connect host.test:443 -keylogfile /tmp/keys",
            "openssl req -new -x509 -keyout /tmp/k.pem -days 365",
            "openssl req -newkey rsa:2048 -nodes",
            "openssl dhparam -out /tmp/dh.pem 2048",
            "openssl ecparam -name prime256v1 -genkey",
            "openssl s_server -accept 4433 -cert /tmp/c.pem",
            "openssl rand -writerand /tmp/rnd",
        ],
    );
}

#[test]
fn library_prefixes_catch_multiple_commands_and_last_option_wins() {
    // Review of PR #25: several new read-only prefixes could be turned into host changes by packing a
    // second command into one call, or by a later option overriding an earlier read one. Each writing
    // form must stay "other" so MultiExec and Compare ask first.
    reads_and_writes(
        None,
        &[
            // Still plain reads.
            "sudo mysqladmin status",
            "sudo mysqladmin ping",
            "sudo mysqladmin -u alice -h db.example.com -P 3306 status",
            "sudo mysqladmin status extended-status processlist",
            "sudo nft list ruleset",
            "sudo nft list tables",
            "sudo nft list ruleset -a",
            "sudo auditctl -l",
            "sudo auditctl -s",
            "sudo multipath -ll",
            "sudo multipath -l -v 2",
            "swapon --show",
            "chronyc tracking",
            "chronyc sources -v",
            "ntpq -p -n",
            "crontab -l",
            "sudo crontab -l -u bob",
            "sudo hwclock --show",
            "sudo nginx -t",
            "sudo nginx -T",
            "sudo apachectl configtest",
            "sudo httpd -t",
            "mysql --version",
            "psql --version",
            "kubectl config view",
        ],
        &[
            // mysqladmin: a second command word runs too (`status shutdown` is caught even harder, as
            // Dangerous by the shutdown rule; these stay "other").
            "sudo mysqladmin status reload",
            "sudo mysqladmin ping flush-hosts",
            "sudo mysqladmin flush-logs",
            "sudo mysqladmin -u alice status create appdb",
            // nft: extra statements in one argument, or -f/-I, clustered or attached.
            "sudo nft -f /tmp/rules.nft",
            "sudo nft list ruleset -f /tmp/x",
            "sudo nft -I /tmp/inc list ruleset",
            "nft $'list ruleset\\nflush ruleset'",
            // auditctl / multipath: the last option wins, clustered too.
            "sudo auditctl -l -D",
            "sudo auditctl -lD",
            "sudo auditctl -D",
            "sudo auditctl -l -w /etc/passwd -p wa",
            "sudo multipath -ll -F",
            "sudo multipath -llF",
            "sudo multipath -l -r",
            "swapon --show -a",
            // chronyc -m (clustered -nm), ntpq -c (attached/clustered), crontab -r (clustered -lr).
            "chronyc tracking -m makestep",
            "chronyc -nm tracking makestep",
            "ntpq -p -c writevar",
            "ntpq -p -cwritevar",
            "ntpq -pc writevar",
            "ntpq -p -c ':config server x'",
            "crontab -l -r",
            "crontab -lr",
            // hwclock / nginx / apache control actions reached via a read flag, attached/clustered.
            "sudo hwclock --show --systohc",
            "sudo hwclock --show --sys",
            "sudo nginx -t -s reload",
            "sudo nginx -ts stop",
            "sudo apachectl -t -k graceful",
            "sudo apachectl -tk stop",
            "sudo httpd -t -kstop",
            // SQL clients: --version plus a query, attached or with =.
            "mysql --version -e 'SELECT 1'",
            "mysql --version -e'SELECT 1'",
            "mysql --version --execute='SELECT 1'",
            "psql --version -c 'SELECT 1'",
            "psql --version --command='SELECT 1'",
            "psql --version -o /tmp/out",
            // kubectl config view --raw leaks credentials (plain and =true).
            "kubectl config view --raw",
            "kubectl config view --raw=true",
        ],
    );
}

#[test]
fn library_prefixes_catch_commands_that_write_files() {
    // Review of PR #25, like `sort -o`: a read command that can be pointed at an output file.
    reads_and_writes(
        None,
        &[
            "sudo ausearch -m avc -ts recent",
            "sudo lshw -short",
            "sudo sshd -T",
            "sudo sshd -t",
            "nfsstat -c",
            "apt-cache search nginx",
            "apt-cache policy nginx",
        ],
        &[
            "sudo ausearch -m avc --checkpoint /tmp/cp",
            "sudo ausearch --checkpoint=/tmp/cp",
            "sudo ausearch --check /tmp/cp",
            "sudo lshw -dump /tmp/hw.db",
            "sudo lshw --dump=/tmp/hw.db",
            "sudo sshd -t -E /tmp/sshd.log",
            "sudo sshd -T -E /tmp/sshd.log",
            "sudo sshd -E/tmp/sshd.log -T",
            "sudo sshd -tE /tmp/sshd.log",
            "nfsstat -z",
            "nfsstat -sz",
            "nfsstat --zero",
            "apt-cache gencaches",
        ],
    );
}

#[test]
fn openssl_option_spellings_are_normalised() {
    // Review of PR #25: openssl takes -opt, --opt and -opt=value, so equivalent spellings must not
    // slip past the allow-list as read-only.
    reads_and_writes(
        None,
        &[
            "openssl x509 -in /tmp/c.pem -noout -text",
            "openssl s_client -connect host.test:443",
            "openssl req -in /tmp/r.csr -noout -text",
        ],
        &[
            "openssl s_client -connect host.test:443 --keylogfile=/tmp/k",
            "openssl s_client -connect host.test:443 -sess_out=/tmp/s",
            "openssl x509 -in /tmp/c.pem --out=/tmp/c.der",
            "openssl req --newkey rsa:2048 -nodes",
            "openssl req --new --x509 --keyout=/tmp/k.pem",
            "openssl x509 -in /tmp/c.pem -CAcreateserial -CA /tmp/ca.pem",
            "openssl x509 -in /tmp/c.pem -CAserial=/tmp/ca.srl",
            "openssl ca -config /etc/pki/tls/openssl.cnf",
            "openssl dhparam -out /tmp/dh.pem 2048",
        ],
    );
}

// ---- BX-08 (0.4.0): finding files, iSCSI, time, copies -------------------------------------------

#[test]
fn find_lists_files_unless_an_action_deletes_runs_a_command_or_writes_a_file() {
    reads_and_writes(
        None,
        &[
            "find /etc -xdev -type d -iname '*ssh*'",
            "sudo find / -xdev -type f -iname '*.conf' 2>/dev/null | head -50",
            "sudo find /var -xdev -type f -size +100M -print0 2>/dev/null | sudo du -h --files0-from=- | sort -rh",
            "find /etc -xdev -type f -mmin -60 -printf '%TY-%Tm-%Td %TH:%TM  %p\\n'",
            "find /var/log -type f -mtime +30 -ls",
            "find /srv -type f -print0",
            "find . -name '*.log' -newer /tmp/mark",
            "find -L /srv -maxdepth 2 -user alice",
            "sudo find / -xdev -perm -4000 -type f",
            "find /srv -type f | wc -l",
        ],
        &[
            "find /tmp -name '*.tmp' -delete",
            "find /var/log -mtime +30 -exec rm {} \\;",
            "find /srv -type f -exec sha256sum {} +",
            "find /srv -type d -execdir chmod 755 {} +",
            "find /tmp -ok rm {} \\;",
            "find /tmp -okdir rm {} \\;",
            "find / -xdev -fprint /tmp/list",
            "find / -xdev -fprint0 /tmp/list",
            "find / -xdev -fprintf /tmp/list '%p\\n'",
            "find / -xdev -fls /tmp/list",
            // Quoted or escaped, the shell still hands find the same word.
            "find /tmp -name x '-delete'",
            "find /tmp -name x -del\\ete",
            "find /tmp -name x \"-exec\" rm {} +",
            // An expansion can become any action.
            "find /tmp $ACTION",
            "find /tmp -name x -o -delete",
        ],
    );
    // The check is code, so a list the user saved with their own `find` entry gets it too.
    reads_and_writes(
        Some(&["find", "locate", "iscsiadm"]),
        &["find /etc -name '*.conf'", "locate fstab", "iscsiadm -m session"],
        &["find /tmp -delete", "locate -u", "iscsiadm -m node --login"],
    );
}

#[test]
fn locate_searches_the_database_and_rebuilding_it_writes() {
    reads_and_writes(
        None,
        &[
            "locate -i -l 50 sshd_config",
            "locate -b '\\nginx.conf'",
            "plocate -i nginx",
            "locate -c '*.rpmnew'",
            "locate -d /var/lib/plocate/plocate.db -i fstab",
        ],
        &[
            "sudo updatedb",
            // slocate's update options.
            "locate -u",
            "locate -U /srv",
            "locate -iu nginx",
            "locate --update",
            "locate $PATTERN",
        ],
    );
}

#[test]
fn iscsiadm_shows_sessions_and_records_and_writes_when_it_logs_in_discovers_or_changes() {
    reads_and_writes(
        None,
        &[
            "sudo iscsiadm -m session",
            "sudo iscsiadm -m session -P 3",
            "sudo iscsiadm -m session -P3",
            "sudo iscsiadm -m session -r 1 -s",
            "sudo iscsiadm -msession -P 1",
            "sudo iscsiadm --mode session --print 3",
            "sudo iscsiadm --mode=session --print=1",
            "sudo iscsiadm -m node",
            "sudo iscsiadm -m node -T iqn.2026-01.test.example:storage -p 192.0.2.10",
            "sudo iscsiadm -m node -T iqn.2026-01.test.example:storage -p 192.0.2.10:3260 -o show",
            "sudo iscsiadm -m node -o show",
            "sudo iscsiadm -m node --op=show",
            "sudo iscsiadm -m discovery",
            "sudo iscsiadm -m discovery -P 1",
            "sudo iscsiadm -m discovery -p 192.0.2.10",
            "sudo iscsiadm -m discoverydb",
            "sudo iscsiadm -m host",
            "sudo iscsiadm -m host -P 1",
            "iscsiadm -V",
            "sudo iscsiadm -m session -P 3 | grep -i -e target -e 'attached scsi disk'",
        ],
        &[
            // Logging in and out, one target or all.
            "sudo iscsiadm -m node -T iqn.2026-01.test.example:storage -p 192.0.2.10 --login",
            "sudo iscsiadm -m node -T iqn.2026-01.test.example:storage -p 192.0.2.10 -l",
            "sudo iscsiadm -m node -T iqn.2026-01.test.example:storage -p 192.0.2.10 --logout",
            "sudo iscsiadm -m node -u",
            "sudo iscsiadm -m node --loginall=automatic",
            "sudo iscsiadm -m node -L all",
            "sudo iscsiadm -m session -U all",
            "sudo iscsiadm -m session -r 1 -u",
            // Discovery saves node records.
            "sudo iscsiadm -m discovery -t sendtargets -p 192.0.2.10",
            "sudo iscsiadm -m discovery -t st -p 192.0.2.10:3260",
            "sudo iscsiadm -m discoverydb -t st -p 192.0.2.10 --discover",
            "sudo iscsiadm -m discoverydb -t st -p 192.0.2.10 -D",
            "sudo iscsiadm -m discovery -p 192.0.2.10 -D",
            // Rescan, change or delete records, kill the daemon, show CHAP passwords.
            "sudo iscsiadm -m session --rescan",
            "sudo iscsiadm -m session -R",
            "sudo iscsiadm -m node -T iqn.2026-01.test.example:storage -o update -n node.startup -v automatic",
            "sudo iscsiadm -m node -o delete",
            "sudo iscsiadm -m node -o new -T iqn.2026-01.test.example:storage -p 192.0.2.10",
            "sudo iscsiadm -m node -o show -o delete",
            "sudo iscsiadm -m node --op delete",
            "sudo iscsiadm -m node --op=update",
            "sudo iscsiadm -m node -odelete",
            "sudo iscsiadm -m node -o nonpersistent",
            "sudo iscsiadm -k 0",
            "sudo iscsiadm -m node -S",
            "sudo iscsiadm -m node --show",
            "sudo iscsiadm -m node -o show -S",
            // Clustered, attached or abbreviated.
            "sudo iscsiadm -m node -sl",
            "sudo iscsiadm -m node --log",
            "sudo iscsiadm -m node --login",
            "sudo iscsiadm -m session --r 1",
            "sudo iscsiadm -m node --s",
            // Modes that write or log in.
            "sudo iscsiadm -m iface",
            "sudo iscsiadm -m iface -I iface0 -o new",
            "sudo iscsiadm -m fw",
            "sudo iscsiadm -m fw -l",
            "sudo iscsiadm -m session -m fw",
            "sudo iscsiadm --mode=fw",
            "sudo iscsiadm -m host -H 1 -C chap -o delete",
            // Operands and expansions.
            "sudo iscsiadm -m session extra",
            "sudo iscsiadm -m $MODE",
            "sudo iscsiadm -m node -o $OP",
        ],
    );
}

#[test]
fn chronyd_only_reads_when_it_prints_its_configuration() {
    reads_and_writes(
        None,
        &[
            "sudo chronyd -p",
            "sudo chronyd -p -f /etc/chrony.conf",
            "sudo chronyd -p -f/etc/chrony/chrony.conf",
            "chronyd -p 2>&1 | head -80",
        ],
        &[
            "sudo chronyd",
            "sudo chronyd -q",
            "sudo chronyd -q 'server 192.0.2.123 iburst'",
            "sudo chronyd -Q",
            "sudo chronyd -d",
            "sudo chronyd -p -q",
            "sudo chronyd -pq",
            "sudo chronyd -p -l /tmp/chrony.log",
            "sudo chronyd -p -l/tmp/chrony.log",
            "sudo chronyd -p -s",
            "sudo chronyd -p 'server 192.0.2.123'",
            "sudo chronyd -p --version",
            "sudo chronyd -p -f $CONF",
        ],
    );
}

#[test]
fn the_0_4_library_time_disk_and_copy_commands_read_or_write() {
    reads_and_writes(
        None,
        &[
            // Time and its daemons.
            "timedatectl show-timesync --all",
            "timedatectl timesync-status",
            "timedatectl list-timezones | grep -i europe",
            "systemctl status systemd-timesyncd --no-pager",
            "systemctl list-units --all --no-pager --type=service 'chrony*' 'systemd-timesyncd*' 'ntp*'",
            "systemd-analyze cat-config systemd/timesyncd.conf --no-pager",
            "grep -sHv -e '^[[:space:]]*#' -e '^[[:space:]]*$' /etc/chrony.conf /etc/chrony/chrony.conf",
            // fstab, disks and volumes.
            "sudo findmnt --verify --verbose",
            "findmnt --fstab --evaluate",
            "sudo blkid /dev/sdb1",
            "lsblk -o NAME,SIZE,TYPE,FSTYPE,UUID,MOUNTPOINT",
            "lsblk -S -o NAME,HCTL,TRAN,VENDOR,MODEL,SIZE",
            "sudo dmesg -T | grep -i -e 'attached scsi' -e 'capacity change' | tail -20",
            "sudo lsof +f -- /data",
            // Copies: sizes before, checksums after.
            "du -sh /srv/data",
            "sha256sum /srv/data/backup.tar",
            "sudo cat /etc/iscsi/initiatorname.iscsi",
        ],
        &[
            "sudo timedatectl set-timezone UTC",
            "sudo timedatectl set-ntp false",
            "sudo systemctl restart systemd-timesyncd",
            "sudo chronyc reload sources",
            "systemd-analyze log-level debug",
            "systemd-analyze service-watchdogs off",
            // Copies stay changes, dry runs included: -e, --rsync-path, --log-file and
            // --write-batch can run programs or write files.
            "scp -p /tmp/a.tar alice@host.test:/tmp/",
            "scp -rp alice@host.test:/srv/data /tmp/",
            "rsync -avh /srv/data/ alice@host.test:/srv/data/",
            "rsync -avhn --delete /srv/data/ alice@host.test:/srv/data/",
            "rsync --dry-run -avh /srv/data/ alice@host.test:/srv/data/",
            "rsync -avhcn /srv/data/ alice@host.test:/srv/data/",
            "rsync -n -e 'ssh -p 2222' /srv/data/ alice@host.test:/srv/data/",
            // Disks: rescans, partitions, resizes and mounts.
            "echo '- - -' | sudo tee /sys/class/scsi_host/host*/scan >/dev/null",
            "echo 1 | sudo tee /sys/class/block/sdb/device/rescan",
            "sudo rescan-scsi-bus.sh",
            "sudo growpart -N /dev/sda 3",
            "sudo growpart /dev/sda 3",
            "sudo pvresize /dev/sda3",
            "sudo parted -s /dev/sdb mklabel gpt mkpart primary 0% 100%",
            "sudo mount -fav",
            "sudo mount -a",
            "sudo umount /data",
            "sudo updatedb",
        ],
    );
}

// ---- SS-10: MultiExec lines ----------------------------------------------------------------------

fn terminal(env: Environment) -> Target {
    Target {
        target: TargetRef::Terminal {
            terminal_id: Uuid::new_v4(),
            session_id: Some(Uuid::new_v4()),
        },
        name: "web01".into(),
        environment: env,
        protected: false,
    }
}

fn terminals(n: usize) -> Vec<Target> {
    (0..n).map(|_| terminal(Environment::Lab)).collect()
}

fn line(text: &str, unreliable: bool, targets: &[Target]) -> Command {
    Command::TerminalLine {
        targets: refs(targets),
        line: text.into(),
        unreliable,
        keys: "\r".into(),
    }
}

#[test]
fn a_read_only_multiexec_line_is_low_and_sent_without_asking() {
    let t = terminals(3);
    let d = engine().evaluate(&line("uptime", false, &t), &t);
    assert_eq!(d.action, ActionKind::ExecReadOnly);
    assert_eq!(d.tier, Tier::Low);
    assert!(d.steps.is_empty());
}

#[test]
fn a_multiexec_line_that_may_change_the_hosts_needs_a_confirm() {
    let t = terminals(2);
    let d = engine().evaluate(&line("systemctl restart nginx", false, &t), &t);
    assert_eq!(d.action, ActionKind::ExecOther);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
}

#[test]
fn a_dangerous_multiexec_line_needs_the_full_approval() {
    let t = terminals(2);
    let d = engine().evaluate(&line("rm -rf /var/lib/app", false, &t), &t);
    assert_eq!(d.action, ActionKind::ExecDangerous);
    assert_eq!(d.tier, Tier::High);
    assert!(
        d.reasons.iter().any(|r| r.starts_with("flagged dangerous")),
        "{:?}",
        d.reasons
    );
    assert!(d.steps.contains(&ApprovalStep::TypeTargetCount { expected: 2 }));
    assert!(d.steps.contains(&ApprovalStep::Reason));
    assert!(!d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
}

#[test]
fn a_prod_terminal_raises_a_multiexec_line() {
    let t = vec![terminal(Environment::Lab), terminal(Environment::Prod)];
    let d = engine().evaluate(&line("uptime", false, &t), &t);
    assert_eq!(d.tier, Tier::Medium, "read-only on Prod: one confirm");
    assert!(d.reasons.iter().any(|r| r.contains("Prod")), "{:?}", d.reasons);
}

#[test]
fn a_multiexec_line_remotely_could_not_follow_is_never_read_only() {
    let t = terminals(2);
    let d = engine().evaluate(&line("uptime", true, &t), &t);
    assert_eq!(d.action, ActionKind::ExecOther);
    assert_eq!(d.tier, Tier::Medium);
    assert!(d.reasons.iter().any(|r| r.contains("can't follow")), "{:?}", d.reasons);
    // Nothing known at all (a line recalled from the history) is the same.
    let d = engine().evaluate(&line("", true, &t), &t);
    assert_eq!(d.tier, Tier::Medium);
    // A dangerous line stays dangerous.
    let d = engine().evaluate(&line("reboot", true, &t), &t);
    assert_eq!(d.action, ActionKind::ExecDangerous);
}

#[test]
fn a_multiexec_line_remotely_could_not_follow_gets_a_confirm_even_when_other_commands_are_low() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::ExecOther, TierRule::same(Tier::Low));
    let e = PolicyEngine::new(rules).unwrap();
    let t = terminals(2);
    assert_eq!(e.evaluate(&line("touch /tmp/x", false, &t), &t).tier, Tier::Low);
    let d = e.evaluate(&line("touch /tmp/x", true, &t), &t);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
    // ...and Prod still raises it from there.
    let p = vec![terminal(Environment::Prod)];
    assert_eq!(e.evaluate(&line("touch /tmp/x", true, &p), &p).tier, Tier::High);
}

#[test]
fn multiexec_lines_go_to_terminals_only_and_are_never_retried() {
    let t = terminals(1);
    let ok = line("uptime", false, &t);
    assert!(ok.validate().is_ok());
    assert!(ok.with_targets(refs(&t)).is_none(), "a line is not sent again later");
    let hosts = vec![host(Environment::Lab)];
    assert!(line("uptime", false, &hosts).validate().is_err());
    assert!(
        line("   ", false, &t).validate().is_err(),
        "an empty line has nothing to rate"
    );
    assert!(line("", true, &t).validate().is_ok(), "but a recalled one does");
    let no_enter = Command::TerminalLine {
        targets: refs(&t),
        line: "uptime".into(),
        unreliable: false,
        keys: "x".into(),
    };
    assert!(no_enter.validate().is_err());
}

#[test]
fn multiexec_summaries_name_the_line_without_secrets() {
    let t = terminals(3);
    assert_eq!(
        line("df -h /", false, &t).summary(3),
        "MultiExec: run `df -h /` in 3 terminals"
    );
    assert_eq!(
        line("cd /srv\nmake\n", false, &t).summary(1),
        "MultiExec: run `cd /srv` (and 1 more line) in 1 terminal"
    );
    assert_eq!(line("", true, &t).summary(2), "MultiExec: press Enter in 2 terminals");
    let summary = line("mysql --password=hunter2-secret", false, &t).summary(3);
    assert!(!summary.contains("hunter2-secret"), "{summary}");
}

// ---- SS-08: uploads ------------------------------------------------------------------------------

fn upload(files: &[(&str, bool)], targets: &[Target]) -> Command {
    Command::FileUpload {
        targets: refs(targets),
        folder: "/srv/www".into(),
        files: files
            .iter()
            .map(|(name, replace)| crate::command_bus::UploadFile {
                local_path: format!(r"C:\Users\alice\Documents\{name}"),
                name: (*name).into(),
                size: 1500,
                replace: *replace,
            })
            .collect(),
    }
}

#[test]
fn uploading_new_files_is_low_and_runs_without_asking() {
    let t = vec![terminal(Environment::Lab)];
    let d = engine().evaluate(&upload(&[("index.html", false), ("app.js", false)], &t), &t);
    assert_eq!(d.action, ActionKind::FileUpload);
    assert_eq!(d.tier, Tier::Low);
    assert!(d.steps.is_empty());
}

#[test]
fn replacing_a_file_by_uploading_asks_for_a_confirm() {
    let t = vec![terminal(Environment::Lab)];
    let d = engine().evaluate(&upload(&[("index.html", true), ("app.js", false)], &t), &t);
    assert_eq!(d.action, ActionKind::FileReplace);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
}

#[test]
fn a_prod_terminal_raises_uploads_one_tier() {
    let t = vec![terminal(Environment::Prod)];
    let d = engine().evaluate(&upload(&[("index.html", false)], &t), &t);
    assert_eq!(d.tier, Tier::Medium, "a new file on Prod: one confirm");
    assert!(d.reasons.iter().any(|r| r.contains("Prod")), "{:?}", d.reasons);
    let d = engine().evaluate(&upload(&[("index.html", true)], &t), &t);
    assert_eq!(d.tier, Tier::High, "replacing a file on Prod: the full approval");
    assert!(d.steps.contains(&ApprovalStep::Reason));
    assert!(!d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
}

#[test]
fn replacing_files_can_never_be_set_below_a_confirm() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::FileReplace, TierRule::same(Tier::Low));
    let err = PolicyEngine::new(rules).err().expect("rejected");
    assert!(err.to_string().contains("always asks"), "{err}");
    // Raising it is fine, and so is making plain uploads ask.
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::FileReplace, TierRule::same(Tier::High));
    rules.tiers.insert(ActionKind::FileUpload, TierRule::same(Tier::Medium));
    let e = PolicyEngine::new(rules).unwrap();
    let t = vec![terminal(Environment::Lab)];
    assert_eq!(e.evaluate(&upload(&[("a", false)], &t), &t).tier, Tier::Medium);
    assert_eq!(e.evaluate(&upload(&[("a", true)], &t), &t).tier, Tier::High);
}

#[test]
fn uploads_go_to_one_open_terminal_with_plain_names() {
    let t = vec![terminal(Environment::Lab)];
    assert!(upload(&[("a.txt", false)], &t).validate().is_ok());
    let two = terminals(2);
    assert!(
        upload(&[("a.txt", false)], &two).validate().is_err(),
        "one terminal at a time"
    );
    let hosts = vec![host(Environment::Lab)];
    assert!(
        upload(&[("a.txt", false)], &hosts).validate().is_err(),
        "through a terminal"
    );
    for bad in ["", "..", "a/b", "line\nbreak"] {
        assert!(upload(&[(bad, false)], &t).validate().is_err(), "{bad:?}");
    }
    assert!(upload(&[("a", false), ("a", true)], &t).validate().is_err(), "twice");
    assert!(upload(&[], &t).validate().is_err(), "nothing to upload");
    let Command::FileUpload { targets, files, .. } = upload(&[("a", false)], &t) else {
        unreachable!()
    };
    let relative = Command::FileUpload {
        targets: targets.clone(),
        folder: "srv/www".into(),
        files: files.clone(),
    };
    assert!(relative.validate().is_err(), "the host folder must be absolute");
    let mut local = files;
    local[0].local_path = r"Documents\a".into();
    let local = Command::FileUpload {
        targets,
        folder: "/srv".into(),
        files: local,
    };
    assert!(local.validate().is_err(), "the PC's path must be absolute");
}

#[test]
fn upload_summaries_name_the_files_the_size_and_what_they_replace() {
    let t = vec![terminal(Environment::Lab)];
    assert_eq!(
        upload(&[("index.html", false)], &t).summary(1),
        "Upload 'index.html' (1.5 KB) to /srv/www"
    );
    assert_eq!(
        upload(&[("index.html", true)], &t).summary(1),
        "Upload 'index.html' (1.5 KB) to /srv/www, replacing the file there"
    );
    assert_eq!(
        upload(&[("a", true), ("b", false), ("c", true)], &t).summary(1),
        "Upload 3 files (4.5 KB) to /srv/www, replacing 2 files there"
    );
    assert!(
        upload(&[("a", false)], &t).with_targets(refs(&t)).is_some(),
        "a failed upload can be retried"
    );
    assert!(!safety_snapshot_applies(&upload(&[("a", true)], &t)));
}

#[test]
fn sizes_read_naturally() {
    use crate::command_bus::human_size;
    assert_eq!(human_size(0), "0 B");
    assert_eq!(human_size(999), "999 B");
    assert_eq!(human_size(1500), "1.5 KB");
    assert_eq!(human_size(25_000_000), "25 MB");
    assert_eq!(human_size(3_200_000_000), "3.2 GB");
}

// ---- SS-07: tunnels -----------------------------------------------------------------------------

fn tunnel(kind: crate::adapters::remote::forward::ForwardKind, bind: &str, targets: &[Target]) -> Command {
    use crate::adapters::remote::forward::{ForwardKind, ForwardSpec};
    Command::OpenTunnel {
        targets: refs(targets),
        forward: crate::forwards::PortForward {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            label: None,
            spec: ForwardSpec {
                kind,
                bind_address: bind.into(),
                bind_port: 8080,
                dest_host: if kind == ForwardKind::Dynamic {
                    String::new()
                } else {
                    "db01.example.com".into()
                },
                dest_port: if kind == ForwardKind::Dynamic { 0 } else { 5432 },
            },
            auto_start: true,
        },
    }
}

#[test]
fn a_tunnel_only_this_pc_can_use_is_low_and_medium_on_prod() {
    use crate::adapters::remote::forward::ForwardKind;
    let lab = vec![terminal(Environment::Lab)];
    for kind in [ForwardKind::Local, ForwardKind::Dynamic] {
        let d = engine().evaluate(&tunnel(kind, "127.0.0.1", &lab), &lab);
        assert_eq!((d.action, d.tier), (ActionKind::TunnelLocal, Tier::Low), "{kind:?}");
        assert!(d.steps.is_empty());
    }
    // The PRD tier table: "open a tunnel to a Prod host" is Medium.
    let prod = vec![terminal(Environment::Prod)];
    let d = engine().evaluate(&tunnel(ForwardKind::Local, "localhost", &prod), &prod);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
}

#[test]
fn a_remote_tunnel_asks_for_a_confirm() {
    use crate::adapters::remote::forward::ForwardKind;
    let lab = vec![terminal(Environment::Lab)];
    let d = engine().evaluate(&tunnel(ForwardKind::Remote, "localhost", &lab), &lab);
    assert_eq!((d.action, d.tier), (ActionKind::TunnelRemote, Tier::Medium));
    let prod = vec![terminal(Environment::Prod)];
    assert_eq!(
        engine()
            .evaluate(&tunnel(ForwardKind::Remote, "localhost", &prod), &prod)
            .tier,
        Tier::High
    );
}

#[test]
fn a_tunnel_other_computers_can_use_asks_and_says_why() {
    use crate::adapters::remote::forward::ForwardKind;
    let lab = vec![terminal(Environment::Lab)];
    for (kind, bind) in [
        (ForwardKind::Local, "0.0.0.0"),
        (ForwardKind::Dynamic, "192.0.2.10"),
        (ForwardKind::Remote, "0.0.0.0"),
        (ForwardKind::Dynamic, "::"),
    ] {
        let d = engine().evaluate(&tunnel(kind, bind, &lab), &lab);
        assert_eq!(
            (d.action, d.tier),
            (ActionKind::TunnelShared, Tier::Medium),
            "{kind:?} {bind}"
        );
        assert!(
            d.reasons.iter().any(|r| r.contains("which other computers can reach")),
            "{:?}",
            d.reasons
        );
    }
    let prod = vec![terminal(Environment::Prod)];
    assert_eq!(
        engine()
            .evaluate(&tunnel(ForwardKind::Local, "0.0.0.0", &prod), &prod)
            .tier,
        Tier::High
    );
}

#[test]
fn shared_tunnels_can_never_be_set_below_a_confirm() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::TunnelShared, TierRule::same(Tier::Low));
    let err = PolicyEngine::new(rules).err().expect("rejected");
    assert!(err.to_string().contains("always asks first"), "{err}");
    // The others can go either way.
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::TunnelRemote, TierRule::same(Tier::Low));
    rules
        .tiers
        .insert(ActionKind::TunnelLocal, TierRule::same(Tier::Medium));
    assert!(PolicyEngine::new(rules).is_ok());
}

#[test]
fn tunnels_open_on_one_terminal_and_are_never_retried_elsewhere() {
    use crate::adapters::remote::forward::ForwardKind;
    let t = vec![terminal(Environment::Lab)];
    let open = tunnel(ForwardKind::Local, "127.0.0.1", &t);
    assert!(open.validate().is_ok());
    assert_eq!(
        open.summary(1),
        "Open a tunnel: local 127.0.0.1:8080 -> db01.example.com:5432"
    );
    assert!(
        open.with_targets(refs(&t)).is_none(),
        "a tunnel belongs to its terminal"
    );
    assert!(!safety_snapshot_applies(&open));
    assert!(tunnel(ForwardKind::Local, "127.0.0.1", &terminals(2))
        .validate()
        .is_err());
    let hosts = vec![host(Environment::Lab)];
    assert!(tunnel(ForwardKind::Local, "127.0.0.1", &hosts).validate().is_err());
}

// ---- FD-03: the read-only lock while presenting ---------------------------------------------------

/// One command of every kind the bus takes.
fn every_command() -> Vec<(Command, Vec<Target>)> {
    use crate::adapters::remote::forward::ForwardKind;
    let lab = vms(1);
    let two = vms(2);
    let hosts = vec![host(Environment::Lab)];
    let t = vec![terminal(Environment::Lab)];
    let app = vec![Target {
        target: TargetRef::App,
        name: "Remotely".into(),
        environment: Environment::None,
        protected: false,
    }];
    vec![
        (power(PowerOp::Start { gui: false }, &lab), lab.clone()),
        (power(PowerOp::Unpause, &lab), lab.clone()),
        (power(PowerOp::Pause, &lab), lab.clone()),
        (power(PowerOp::Suspend, &two), two.clone()),
        (power(PowerOp::Reset { mode: SOFT }, &lab), lab.clone()),
        (power(PowerOp::Reset { mode: HARD }, &lab), lab.clone()),
        (power(PowerOp::Stop { mode: SOFT }, &lab), lab.clone()),
        (power(PowerOp::Stop { mode: HARD }, &lab), lab.clone()),
        (snapshot(SnapshotOp::Take { name: "before".into() }, &lab), lab.clone()),
        (
            snapshot(SnapshotOp::Revert { name: "before".into() }, &lab),
            lab.clone(),
        ),
        (
            snapshot(SnapshotOp::Delete { name: "before".into() }, &lab),
            lab.clone(),
        ),
        (protect(true, &lab), lab.clone()),
        (protect(false, &lab), lab.clone()),
        (exec("uptime", &hosts), hosts.clone()),
        (exec("systemctl restart nginx", &hosts), hosts.clone()),
        (exec("rm -rf /var/lib/app", &hosts), hosts.clone()),
        (push_key(&hosts), hosts.clone()),
        (line("uptime", false, &t), t.clone()),
        (upload(&[("a.txt", false)], &t), t.clone()),
        (upload(&[("a.txt", true)], &t), t.clone()),
        (tunnel(ForwardKind::Local, "127.0.0.1", &t), t.clone()),
        (tunnel(ForwardKind::Remote, "localhost", &t), t.clone()),
        (tunnel(ForwardKind::Dynamic, "0.0.0.0", &t), t.clone()),
        (
            Command::AppUpdate {
                version: "0.3.0".into(),
            },
            app,
        ),
    ]
    .into_iter()
    .chain(every_container_command())
    .collect()
}

#[test]
fn the_read_only_lock_refuses_every_kind_of_command_and_names_it() {
    let engine = engine();
    let commands = every_command();
    let kinds: std::collections::BTreeSet<ActionKind> = commands.iter().map(|(c, _)| engine.classify(c)).collect();
    // Every action the policy engine knows is covered.
    assert_eq!(kinds.len(), ActionKind::ALL.len());
    for (command, targets) in &commands {
        let action = engine.classify(command);
        let err = engine.check_read_only(true, command).expect_err("locked: refused");
        assert_eq!(err.code(), "read_only_lock");
        assert!(err.to_string().contains(action.label()), "names the action: {err}");
        assert!(err.to_string().contains("read-only lock"), "{err}");
        // Whatever the tier would have been: a Low one (start, read-only exec) is refused too.
        let _ = engine.evaluate(command, targets);
        assert!(
            engine.check_read_only(false, command).is_ok(),
            "unlocked: {action:?} goes on"
        );
    }
}

#[test]
fn the_read_only_lock_ignores_tiers_labels_and_protection() {
    let engine = engine();
    let mut prod = host(Environment::Prod);
    prod.protected = true;
    let low = exec("uptime", std::slice::from_ref(&prod));
    assert!(engine.check_read_only(true, &low).is_err());
    // Rules that make everything Low change nothing about the lock.
    let mut rules = PolicyRules::default();
    for kind in ActionKind::ALL {
        if kind != ActionKind::FileReplace && kind != ActionKind::TunnelShared {
            rules.tiers.insert(kind, TierRule::same(Tier::Low));
        }
    }
    let lenient = PolicyEngine::new(rules).expect("valid");
    assert!(lenient
        .check_read_only(true, &power(PowerOp::Start { gui: false }, &vms(1)))
        .is_err());
}

#[test]
fn the_read_only_lock_refuses_every_edit_of_the_apps_data() {
    use crate::presentation::Change;
    let mut labels = std::collections::HashSet::new();
    for change in Change::ALL {
        assert!(labels.insert(change.label()), "labels differ: {}", change.label());
        let err = read_only_edit_refusal(true, change).expect_err("locked: refused");
        assert_eq!(err.code(), "read_only_lock");
        assert!(err.to_string().contains(change.label()), "{err}");
        assert!(read_only_edit_refusal(false, change).is_ok());
    }
}

// ---- CT-01, CT-02: containers -------------------------------------------------------------------

use crate::adapters::containers::{ContainerId, EngineKind, ImageId, PruneWhat, VolumeName};
use crate::command_bus::ContainerOp;
use crate::domain::{ContainerHost, ContainerObject};

fn container_host(env: Environment) -> (ContainerHost, Environment) {
    (
        ContainerHost::Session {
            session_id: Uuid::new_v4(),
        },
        env,
    )
}

fn object_target(host: (ContainerHost, Environment), engine: EngineKind, object: ContainerObject) -> Target {
    Target {
        name: format!("{} on host", object.kind()),
        target: TargetRef::Container {
            host: host.0,
            engine,
            object,
        },
        environment: host.1,
        protected: false,
    }
}

/// `n` containers on one host labelled `env`.
fn containers(n: usize, env: Environment) -> Vec<Target> {
    let host = container_host(env);
    (0..n)
        .map(|i| {
            let id = ContainerId::parse(&format!("{i:012x}{}", "0".repeat(52))).expect("hex");
            object_target(host, EngineKind::Docker, ContainerObject::Container { id })
        })
        .collect()
}

fn image_target(env: Environment) -> Target {
    let id = ImageId::parse(&format!("sha256:{}", "ab".repeat(32))).expect("hex");
    object_target(container_host(env), EngineKind::Docker, ContainerObject::Image { id })
}

fn volume_target(env: Environment) -> Target {
    let name = VolumeName::parse("pgdata").expect("name");
    object_target(
        container_host(env),
        EngineKind::Docker,
        ContainerObject::Volume { name },
    )
}

fn engine_target(env: Environment, engine: EngineKind) -> Target {
    object_target(container_host(env), engine, ContainerObject::Engine)
}

fn container(op: ContainerOp, targets: &[Target]) -> Command {
    Command::Container {
        targets: refs(targets),
        op,
    }
}

fn prune(what: PruneWhat) -> ContainerOp {
    ContainerOp::Prune { what }
}

/// One container command of every kind, for the read-only lock test.
fn every_container_command() -> Vec<(Command, Vec<Target>)> {
    let one = containers(1, Environment::Lab);
    let image = vec![image_target(Environment::Lab)];
    let volume = vec![volume_target(Environment::Lab)];
    let docker = vec![engine_target(Environment::Lab, EngineKind::Docker)];
    let mut out: Vec<(Command, Vec<Target>)> = [
        ContainerOp::Start,
        ContainerOp::Unpause,
        ContainerOp::Pause,
        ContainerOp::Restart,
        ContainerOp::Stop,
        ContainerOp::Remove { force: false },
    ]
    .into_iter()
    .map(|op| (container(op, &one), one.clone()))
    .collect();
    out.push((container(ContainerOp::RemoveImage, &image), image.clone()));
    out.push((container(ContainerOp::RemoveVolume, &volume), volume.clone()));
    out.push((
        container(
            ContainerOp::Pull {
                reference: "nginx:1.27".into(),
            },
            &docker,
        ),
        docker.clone(),
    ));
    for what in [
        PruneWhat::Containers,
        PruneWhat::Images,
        PruneWhat::BuildCache,
        PruneWhat::Volumes,
    ] {
        out.push((container(prune(what), &docker), docker.clone()));
    }
    out
}

#[test]
fn starting_or_unpausing_containers_is_low_at_any_count() {
    for n in [1, 2, 20] {
        let t = containers(n, Environment::Lab);
        assert_eq!(tier(container(ContainerOp::Start, &t), &t), Tier::Low, "start {n}");
        assert_eq!(tier(container(ContainerOp::Unpause, &t), &t), Tier::Low, "unpause {n}");
    }
}

#[test]
fn stopping_restarting_or_pausing_one_container_is_medium_and_two_or_more_high() {
    for op in [ContainerOp::Stop, ContainerOp::Restart, ContainerOp::Pause] {
        let one = containers(1, Environment::Lab);
        assert_eq!(tier(container(op.clone(), &one), &one), Tier::Medium, "{op:?} on 1");
        let d = engine().evaluate(&container(op.clone(), &one), &one);
        assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
        for n in [2, 5] {
            let many = containers(n, Environment::Lab);
            assert_eq!(tier(container(op.clone(), &many), &many), Tier::High, "{op:?} on {n}");
        }
    }
}

#[test]
fn removing_containers_or_images_is_high() {
    for t in [containers(1, Environment::Lab), containers(3, Environment::Lab)] {
        for force in [false, true] {
            assert_eq!(tier(container(ContainerOp::Remove { force }, &t), &t), Tier::High);
        }
    }
    let image = vec![image_target(Environment::None)];
    let d = engine().evaluate(&container(ContainerOp::RemoveImage, &image), &image);
    assert_eq!(d.tier, Tier::High);
    assert_eq!(d.action, ActionKind::ImageRemove);
    assert!(d.steps.contains(&ApprovalStep::TypeTargetCount { expected: 1 }));
    assert!(d.steps.contains(&ApprovalStep::Reason));
    assert!(!d.steps.contains(&ApprovalStep::VaultReauth));
    assert!(
        !d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })),
        "no safety snapshot for containers"
    );
}

#[test]
fn a_forced_remove_says_running_containers_are_killed() {
    let t = containers(1, Environment::Lab);
    let d = engine().evaluate(&container(ContainerOp::Remove { force: true }, &t), &t);
    assert!(d.reasons.iter().any(|r| r.contains("killed first")), "{:?}", d.reasons);
}

#[test]
fn pruning_containers_images_or_the_build_cache_is_high() {
    for what in [PruneWhat::Containers, PruneWhat::Images, PruneWhat::BuildCache] {
        let t = vec![engine_target(Environment::Lab, EngineKind::Docker)];
        assert_eq!(tier(container(prune(what), &t), &t), Tier::High, "{what:?}");
    }
}

#[test]
fn removing_volumes_or_pruning_them_deletes_data_so_it_is_critical() {
    let volume = vec![volume_target(Environment::Lab)];
    let d = engine().evaluate(&container(ContainerOp::RemoveVolume, &volume), &volume);
    assert_eq!(d.tier, Tier::Critical);
    assert_eq!(d.action, ActionKind::VolumeRemove);
    assert!(d.steps.contains(&ApprovalStep::VaultReauth));
    assert!(
        d.reasons.iter().any(|r| r.contains("data is deleted")),
        "{:?}",
        d.reasons
    );
    let docker = vec![engine_target(Environment::Lab, EngineKind::Docker)];
    let d = engine().evaluate(&container(prune(PruneWhat::Volumes), &docker), &docker);
    assert_eq!(d.tier, Tier::Critical);
    assert_eq!(d.action, ActionKind::PruneVolumes);
    assert!(d.steps.contains(&ApprovalStep::VaultReauth));
}

#[test]
fn pulling_an_image_is_low() {
    let t = vec![engine_target(Environment::Lab, EngineKind::Podman)];
    let pull = ContainerOp::Pull {
        reference: "registry.example.com/team/app:2.1".into(),
    };
    assert_eq!(tier(container(pull, &t), &t), Tier::Low);
}

#[test]
fn a_prod_container_host_raises_container_actions_one_tier() {
    let one = containers(1, Environment::Prod);
    assert_eq!(tier(container(ContainerOp::Start, &one), &one), Tier::Medium);
    assert_eq!(tier(container(ContainerOp::Stop, &one), &one), Tier::High);
    let two = containers(2, Environment::Prod);
    assert_eq!(tier(container(ContainerOp::Restart, &two), &two), Tier::Critical);
    assert_eq!(
        tier(container(ContainerOp::Remove { force: false }, &one), &one),
        Tier::Critical
    );
    let image = vec![image_target(Environment::Prod)];
    assert_eq!(
        tier(container(ContainerOp::RemoveImage, &image), &image),
        Tier::Critical
    );
    let volume = vec![volume_target(Environment::Prod)];
    assert_eq!(
        tier(container(ContainerOp::RemoveVolume, &volume), &volume),
        Tier::Critical,
        "Critical stays Critical"
    );
    let docker = vec![engine_target(Environment::Prod, EngineKind::Docker)];
    let pull = ContainerOp::Pull {
        reference: "nginx".into(),
    };
    assert_eq!(tier(container(pull, &docker), &docker), Tier::Medium);
    let d = engine().evaluate(&container(ContainerOp::Stop, &one), &one);
    assert!(d.reasons.iter().any(|r| r.contains("Prod")), "{:?}", d.reasons);
}

#[test]
fn containers_on_a_protected_host_are_skipped() {
    let mut t = containers(3, Environment::Lab);
    t[0].protected = true;
    let d = engine().evaluate(&container(ContainerOp::Stop, &t), &t);
    assert_eq!(d.targets.len(), 2);
    assert_eq!(d.skipped.len(), 1);
    assert_eq!(d.tier, Tier::High, "2 left: still bulk");
    t[1].protected = true;
    let d = engine().evaluate(&container(ContainerOp::Stop, &t), &t);
    assert_eq!(d.targets.len(), 1);
    assert_eq!(d.tier, Tier::Medium, "1 left");
}

#[test]
fn container_commands_check_their_targets_and_references() {
    let one = containers(1, Environment::Lab);
    assert!(container(ContainerOp::Stop, &one).validate().is_ok());
    // An op on the wrong kind of object.
    let image = vec![image_target(Environment::Lab)];
    assert!(container(ContainerOp::Stop, &image).validate().is_err());
    assert!(container(ContainerOp::RemoveVolume, &one).validate().is_err());
    let docker = vec![engine_target(Environment::Lab, EngineKind::Docker)];
    assert!(container(ContainerOp::Start, &docker).validate().is_err());
    // Not a container target at all.
    let vms = vms(1);
    assert!(container(ContainerOp::Start, &vms).validate().is_err());
    // The same target twice.
    let twice = vec![one[0].clone(), one[0].clone()];
    assert!(container(ContainerOp::Start, &twice).validate().is_err());
    // Image references follow the grammar.
    for bad in ["", "Nginx", "nginx;reboot", "-q", "nginx latest", "$(id)"] {
        let pull = ContainerOp::Pull { reference: bad.into() };
        assert!(container(pull, &docker).validate().is_err(), "{bad:?}");
    }
    // Podman has no build cache; this PC runs Docker only.
    let podman = vec![engine_target(Environment::Lab, EngineKind::Podman)];
    assert!(container(prune(PruneWhat::BuildCache), &podman).validate().is_err());
    assert!(container(prune(PruneWhat::Images), &podman).validate().is_ok());
    let this_pc_podman = vec![object_target(
        (ContainerHost::ThisPc, Environment::None),
        EngineKind::Podman,
        ContainerObject::Engine,
    )];
    assert!(container(prune(PruneWhat::Images), &this_pc_podman).validate().is_err());
}

#[test]
fn container_ids_never_parse_from_hostile_text() {
    let json = r#"{"kind":"container","host":{"kind":"thisPc"},"engine":"docker","object":{"kind":"container","id":"abc; reboot"}}"#;
    assert!(serde_json::from_str::<TargetRef>(json).is_err());
    let json = r#"{"kind":"container","host":{"kind":"thisPc"},"engine":"docker","object":{"kind":"volume","name":"$(reboot)"}}"#;
    assert!(serde_json::from_str::<TargetRef>(json).is_err());
    let good = format!(
        r#"{{"kind":"container","host":{{"kind":"thisPc"}},"engine":"docker","object":{{"kind":"container","id":"{}"}}}}"#,
        "a".repeat(64)
    );
    let target: TargetRef = serde_json::from_str(&good).expect("hex id");
    assert_eq!(TargetRef::container_from_key(&target.key()), Some(target.clone()));
}

#[test]
fn container_summaries_name_what_they_do() {
    let one = containers(1, Environment::Lab);
    assert_eq!(container(ContainerOp::Stop, &one).summary(1), "Stop 1 container");
    assert_eq!(
        container(ContainerOp::Remove { force: true }, &one).summary(3),
        "Force-remove 3 containers"
    );
    assert_eq!(
        container(ContainerOp::RemoveVolume, &one).summary(1),
        "Remove 1 volume and its data"
    );
    let docker = vec![engine_target(Environment::Lab, EngineKind::Docker)];
    assert_eq!(
        container(prune(PruneWhat::Volumes), &docker).summary(2),
        "Prune unused volumes on 2 hosts"
    );
    let pull = ContainerOp::Pull {
        reference: " nginx:1.27 ".into(),
    };
    assert_eq!(container(pull, &docker).summary(1), "Pull nginx:1.27 on 1 host");
}

#[test]
fn container_actions_never_offer_a_safety_snapshot() {
    for (command, _) in every_container_command() {
        assert!(!safety_snapshot_applies(&command), "{command:?}");
    }
}

#[test]
fn container_tiers_are_editable_like_any_other() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::ContainerStop, TierRule::same(Tier::Low));
    let lenient = PolicyEngine::new(rules).expect("valid");
    let two = containers(2, Environment::Lab);
    assert_eq!(
        lenient.evaluate(&container(ContainerOp::Stop, &two), &two).tier,
        Tier::Low
    );
    // Saved rules from before 0.4.0 get the container defaults.
    let mut old = PolicyRules::default();
    for kind in [
        ActionKind::ContainerStart,
        ActionKind::VolumeRemove,
        ActionKind::PruneVolumes,
    ] {
        old.tiers.remove(&kind);
    }
    old.fill_missing_tiers();
    assert_eq!(old.tiers[&ActionKind::VolumeRemove], TierRule::same(Tier::Critical));
    assert!(PolicyEngine::new(old).is_ok());
}
