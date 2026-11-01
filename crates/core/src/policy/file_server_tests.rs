//! FD-09 tier rules (docs/plan-0.7.md, "Approval tiers"): the quick file server is Medium while it only serves (one
//! confirm) and High with "Accept uploads" on (the full approval). Its one target is this PC, which has no label, so the
//! Prod rule never moves it. It is never built by the UI, never retried and refused by the read-only lock.

use super::*;
use crate::command_bus::Command;
use crate::domain::{Environment, Target, TargetRef};
use crate::toolbox::file_server::{FileServerSpec, UploadSpec};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn spec(address: &str, uploads: bool) -> FileServerSpec {
    FileServerSpec {
        root: r"C:\Images\fw.bin".into(),
        address: address.parse().expect("an address"),
        tftp_port: Some(69),
        http_port: Some(8080),
        minutes: 30,
        uploads: uploads.then(|| UploadSpec {
            folder: r"C:\Uploads".into(),
            max_file_mb: 100,
            max_total_mb: 500,
        }),
    }
}

fn serve(address: &str, uploads: bool) -> (Command, Vec<Target>) {
    (
        Command::FileServer {
            targets: vec![TargetRef::App],
            spec: Box::new(spec(address, uploads)),
        },
        vec![Target {
            target: TargetRef::App,
            name: format!("this PC ({address})"),
            environment: Environment::None,
            protected: false,
        }],
    )
}

/// Serving only and with uploads, for the read-only lock's list of every command.
pub(super) fn every_file_server_command() -> Vec<(Command, Vec<Target>)> {
    vec![serve("192.0.2.10", false), serve("192.0.2.10", true)]
}

#[test]
fn serving_only_is_medium_and_asks_once() {
    let (command, targets) = serve("192.0.2.10", false);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::FileServer);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, [ApprovalStep::Confirm]);
    assert!(
        d.reasons
            .iter()
            .any(|r| r.contains("192.0.2.10, which other computers on that network can reach")),
        "{:?}",
        d.reasons
    );
    assert!(!safety_snapshot_applies(&command));
}

#[test]
fn accepting_uploads_is_high_with_the_full_approval() {
    let (command, targets) = serve("192.0.2.10", true);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::FileServerUploads);
    assert_eq!(d.tier, Tier::High);
    assert!(d.steps.contains(&ApprovalStep::ImpactPreview));
    assert!(d.steps.contains(&ApprovalStep::TypeTargetCount { expected: 1 }));
    assert!(d.steps.contains(&ApprovalStep::Reason));
    assert!(d.steps.iter().any(|s| matches!(s, ApprovalStep::Countdown { .. })));
    assert!(!d.steps.contains(&ApprovalStep::VaultReauth), "High, not Critical");
    assert!(
        d.reasons
            .iter()
            .any(|r| r == r"files they send are saved in C:\Uploads (at most 100 MB each, 500 MB in all)"),
        "{:?}",
        d.reasons
    );
}

#[test]
fn loopback_is_still_medium_and_says_only_this_pc_reaches_it() {
    let (command, targets) = serve("127.0.0.1", false);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::Medium);
    assert!(
        d.reasons.iter().any(|r| r.contains("which only this PC reaches")),
        "{:?}",
        d.reasons
    );
}

#[test]
fn the_rules_can_be_raised_and_are_listed() {
    assert!(ActionKind::ALL.contains(&ActionKind::FileServer));
    assert!(ActionKind::ALL.contains(&ActionKind::FileServerUploads));
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::FileServer, TierRule::same(Tier::High));
    rules
        .tiers
        .insert(ActionKind::FileServerUploads, TierRule::same(Tier::Critical));
    let engine = PolicyEngine::new(rules).expect("valid");
    let (command, targets) = serve("192.0.2.10", false);
    assert_eq!(engine.evaluate(&command, &targets).tier, Tier::High);
    let (command, targets) = serve("192.0.2.10", true);
    let d = engine.evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::Critical);
    assert!(d.steps.contains(&ApprovalStep::VaultReauth));
}

#[test]
fn it_is_refused_while_presenting_never_from_the_ui_and_never_retried() {
    for (command, _) in every_file_server_command() {
        command.validate().expect("valid");
        assert!(
            command.check_from_ui().is_err(),
            "the core builds it after checking the folders"
        );
        assert!(engine().check_read_only(true, &command).is_err());
        assert!(engine().check_read_only(false, &command).is_ok());
        assert!(command.with_targets(vec![TargetRef::App]).is_none());
        assert_eq!(command.type_name(), "fileServer");
    }
    let (command, _) = serve("192.0.2.10", true);
    assert_eq!(
        command.summary(1),
        r"Serve C:\Images\fw.bin over TFTP (port 69) and HTTP (port 8080) on 192.0.2.10 for 30 minutes, accepting uploads into C:\Uploads"
    );
}

#[test]
fn its_one_target_is_this_pc() {
    let other = Command::FileServer {
        targets: vec![TargetRef::Session {
            session_id: uuid::Uuid::new_v4(),
        }],
        spec: Box::new(spec("192.0.2.10", false)),
    };
    assert!(other.validate().is_err());
    let none = Command::FileServer {
        targets: vec![],
        spec: Box::new(spec("192.0.2.10", false)),
    };
    assert!(none.validate().is_err());
    let all = Command::FileServer {
        targets: vec![TargetRef::App],
        spec: Box::new(spec("0.0.0.0", false)),
    };
    assert!(all.validate().is_err(), "never every address of this PC");
}
