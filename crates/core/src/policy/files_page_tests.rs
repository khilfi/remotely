//! SS-14, BX-10 tier rules of 0.8.0 G3 (docs/plan-0.8.md, "Approval tiers"): a folder sync to a host is rated by its
//! biggest change (uploads Low, replacements Medium, deletes High, never below Medium), one tier higher as root, and the
//! Prod rule applies; a push to many hosts is Medium, High from the bulk threshold for commands on hosts (5 hosts),
//! never below a confirm when it replaces; a fetch from many hosts is Low, and Medium for a Prod host.

use super::*;
use crate::bulk_files::{BulkFilesOp, BulkFilesSpec};
use crate::command_bus::{Command, UploadFile};
use crate::domain::{Environment, Target, TargetRef};
use uuid::Uuid;

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

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

fn hosts(n: usize, env: Environment) -> Vec<Target> {
    (0..n)
        .map(|i| Target {
            target: TargetRef::Session {
                session_id: Uuid::new_v4(),
            },
            name: format!("web{i:02}"),
            environment: env,
            protected: false,
        })
        .collect()
}

fn file(name: &str, replace: bool) -> UploadFile {
    UploadFile {
        local_path: format!(r"C:\Users\alice\site\{name}"),
        name: name.into(),
        size: 10,
        replace,
        modified: None,
    }
}

/// A sync to the host: new files, replacements and deletes as given.
fn sync(replace: bool, delete: &[&str], as_root: bool, env: Environment) -> (Command, Vec<Target>) {
    let t = terminal(env);
    (
        Command::FileUpload {
            targets: vec![t.target.clone()],
            folder: "/srv/www".into(),
            files: vec![file("index.html", false), file("old.html", replace)],
            folders: vec![],
            keep_times: true,
            as_root,
            delete: delete.iter().map(|d| (*d).to_owned()).collect(),
        },
        vec![t],
    )
}

fn push(n: usize, replace: bool, env: Environment) -> (Command, Vec<Target>) {
    let targets = hosts(n, env);
    (
        Command::BulkFiles {
            targets: targets.iter().map(|t| t.target.clone()).collect(),
            spec: Box::new(BulkFilesSpec {
                op: BulkFilesOp::Push {
                    folder: "/etc/app".into(),
                    files: vec![file("app.conf", replace)],
                    replace,
                },
                trust_new_host_keys: false,
                timeout_secs: None,
            }),
        },
        targets,
    )
}

fn fetch(n: usize, env: Environment) -> (Command, Vec<Target>) {
    let targets = hosts(n, env);
    (
        Command::BulkFiles {
            targets: targets.iter().map(|t| t.target.clone()).collect(),
            spec: Box::new(BulkFilesSpec {
                op: BulkFilesOp::Fetch {
                    path: "/etc/ssh/sshd_config".into(),
                    dest: r"C:\Users\alice\Downloads".into(),
                },
                trust_new_host_keys: false,
                timeout_secs: None,
            }),
        },
        targets,
    )
}

fn rated((command, targets): (Command, Vec<Target>)) -> Decision {
    engine().evaluate(&command, &targets)
}

/// One command for each of G3's actions, for the read-only lock's list of every command.
pub(super) fn every_files_page_command() -> Vec<(Command, Vec<Target>)> {
    vec![
        sync(false, &["extra.html"], false, Environment::Lab),
        push(2, false, Environment::Lab),
        fetch(2, Environment::Lab),
    ]
}

#[test]
fn a_sync_is_rated_by_its_biggest_change() {
    let d = rated(sync(false, &[], false, Environment::Lab));
    assert_eq!((d.action, d.tier), (ActionKind::FileUpload, Tier::Low));
    let d = rated(sync(true, &[], false, Environment::Lab));
    assert_eq!((d.action, d.tier), (ActionKind::FileReplace, Tier::Medium));
    let d = rated(sync(true, &["extra.html", "gone"], false, Environment::Lab));
    assert_eq!((d.action, d.tier), (ActionKind::FileSyncDelete, Tier::High));
    assert!(
        d.reasons.iter().any(|r| r.contains("deletes 2 items")),
        "{:?}",
        d.reasons
    );
    assert!(d.steps.contains(&ApprovalStep::ImpactPreview));
}

#[test]
fn a_sync_as_root_or_on_prod_is_one_tier_higher_each() {
    let d = rated(sync(false, &["x"], true, Environment::Lab));
    assert_eq!(d.tier, Tier::Critical);
    let d = rated(sync(true, &[], true, Environment::Lab));
    assert_eq!(d.tier, Tier::High);
    let d = rated(sync(true, &[], false, Environment::Prod));
    assert_eq!(d.tier, Tier::High);
    let d = rated(sync(false, &[], true, Environment::Prod));
    assert_eq!(d.tier, Tier::High, "Low, +1 as root, +1 for Prod");
}

#[test]
fn a_syncs_deletes_can_never_be_set_below_a_confirm() {
    let mut rules = PolicyRules::default();
    rules
        .tiers
        .insert(ActionKind::FileSyncDelete, TierRule::same(Tier::Low));
    let err = rules.validate().unwrap_err();
    assert!(err.to_string().contains("can't be lower than medium"), "{err}");
    rules
        .tiers
        .insert(ActionKind::FileSyncDelete, TierRule::same(Tier::Medium));
    assert!(rules.validate().is_ok());
}

#[test]
fn a_push_is_medium_and_high_from_five_hosts() {
    for n in 1..5 {
        let d = rated(push(n, false, Environment::Lab));
        assert_eq!((d.action, d.tier), (ActionKind::FilePush, Tier::Medium), "{n} hosts");
    }
    let d = rated(push(5, false, Environment::Lab));
    assert_eq!(d.tier, Tier::High);
    assert!(
        d.reasons.iter().any(|r| r.contains("5 or more hosts")),
        "{:?}",
        d.reasons
    );
    let d = rated(push(1, false, Environment::Prod));
    assert_eq!(d.tier, Tier::High, "Prod");
}

#[test]
fn a_push_that_replaces_asks_at_least_once_whatever_the_rules() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::FilePush, TierRule::same(Tier::Low));
    let lenient = PolicyEngine::new(rules).expect("valid");
    let (command, targets) = push(2, false, Environment::Lab);
    assert_eq!(lenient.evaluate(&command, &targets).tier, Tier::Low);
    let (command, targets) = push(2, true, Environment::Lab);
    let d = lenient.evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::Medium);
    assert!(d.reasons.iter().any(|r| r.contains("are replaced")), "{:?}", d.reasons);
}

#[test]
fn a_fetch_is_low_and_medium_for_a_prod_host() {
    let d = rated(fetch(3, Environment::Lab));
    assert_eq!((d.action, d.tier), (ActionKind::FileFetch, Tier::Low));
    assert!(d.steps.is_empty());
    let d = rated(fetch(1, Environment::Prod));
    assert_eq!(d.tier, Tier::Medium);
    let d = rated(fetch(8, Environment::Lab));
    assert_eq!(d.tier, Tier::Low, "the bulk tier is Low too");
}

#[test]
fn neither_is_built_from_the_window() {
    for (command, _) in every_files_page_command() {
        assert!(command.check_from_ui().is_err(), "{}", command.type_name());
    }
}
