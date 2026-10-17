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
