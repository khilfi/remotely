//! SS-14 tier rules (docs/plan-0.8.md, "Approval tiers"): a new folder or file, and a rename or move that replaces
//! nothing, are Low; one that replaces, permissions or owner, a copy within the host, and deleting a file or an empty
//! folder are Medium; deleting a folder with what is in it is High. Any of them as root is one tier higher, and a Prod
//! target one more. Replacing and deleting can never be set below a confirm. A copy's `cp -a` is rated by the shell
//! rules too. Uploads as root are one tier higher as well.

use super::*;
use crate::command_bus::{Command, UploadFile};
use crate::domain::{Environment, Target, TargetRef};
use crate::terminal::file_ops::{FileOp, FileOpSpec};
use uuid::Uuid;

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn paths(list: &[&str]) -> Vec<String> {
    list.iter().map(|p| (*p).to_owned()).collect()
}

/// The command and its targets as the bus resolves them: each path on the terminal, with the terminal's label.
fn change(op: FileOp, as_root: bool, env: Environment) -> (Command, Vec<Target>) {
    let spec = FileOpSpec {
        terminal_id: Uuid::nil(),
        op,
        as_root,
    };
    let refs = spec.targets();
    let targets = refs
        .iter()
        .map(|target| Target {
            target: target.clone(),
            name: "web01: /srv/x".into(),
            environment: env,
            protected: false,
        })
        .collect();
    (
        Command::FileOp {
            targets: refs,
            spec: Box::new(spec),
        },
        targets,
    )
}

fn rated(op: FileOp, as_root: bool, env: Environment) -> Decision {
    let (command, targets) = change(op, as_root, env);
    engine().evaluate(&command, &targets)
}

fn new_folder() -> FileOp {
    FileOp::NewFolder {
        path: "/srv/www/new".into(),
    }
}

fn rename(replace: bool) -> FileOp {
    FileOp::Rename {
        path: "/srv/www/a.html".into(),
        name: "b.html".into(),
        replace,
    }
}

fn delete(recursive: bool) -> FileOp {
    FileOp::Delete {
        paths: paths(&["/srv/www/old", "/srv/www/older"]),
        recursive,
    }
}

/// One command for each file action, for the read-only lock's list of every command.
pub(super) fn every_file_op_command() -> Vec<(Command, Vec<Target>)> {
    [
        new_folder(),
        rename(false),
        rename(true),
        FileOp::Copy {
            paths: paths(&["/srv/www/a"]),
            into: "/backup".into(),
        },
        FileOp::Mode {
            paths: paths(&["/srv/run.sh"]),
            mode: 0o755,
        },
        delete(false),
        delete(true),
    ]
    .into_iter()
    .map(|op| change(op, false, Environment::Lab))
    // SS-14, SS-08 (G4): an editor tab and an editing session on this PC.
    .chain([
        editing(false, Environment::Lab, false),
        editing(false, Environment::Lab, true),
    ])
    .collect()
}

#[test]
fn making_a_folder_or_an_empty_file_is_low_and_runs_without_asking() {
    for op in [
        new_folder(),
        FileOp::NewFile {
            path: "/srv/www/empty.txt".into(),
        },
    ] {
        let d = rated(op, false, Environment::Lab);
        assert_eq!((d.action, d.tier), (ActionKind::FileNew, Tier::Low));
        assert!(d.steps.is_empty());
    }
}

#[test]
fn renaming_or_moving_without_replacing_is_low() {
    let d = rated(rename(false), false, Environment::Lab);
    assert_eq!((d.action, d.tier), (ActionKind::FileMove, Tier::Low));
    let moved = FileOp::Move {
        paths: paths(&["/srv/a", "/srv/b", "/srv/c"]),
        into: "/tmp".into(),
        replace: false,
    };
    let d = rated(moved, false, Environment::Lab);
    assert_eq!(
        (d.action, d.tier),
        (ActionKind::FileMove, Tier::Low),
        "three paths are still Low"
    );
    assert_eq!(d.targets.len(), 3, "a step per path");
}

#[test]
fn renaming_or_moving_over_a_file_asks_for_a_confirm() {
    let d = rated(rename(true), false, Environment::Lab);
    assert_eq!((d.action, d.tier), (ActionKind::FileMoveReplace, Tier::Medium));
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
    let moved = FileOp::Move {
        paths: paths(&["/srv/a"]),
        into: "/tmp".into(),
        replace: true,
    };
    assert_eq!(
        rated(moved, false, Environment::Lab).action,
        ActionKind::FileMoveReplace
    );
}

#[test]
fn permissions_and_owners_ask_for_a_confirm() {
    let mode = FileOp::Mode {
        paths: paths(&["/srv/run.sh"]),
        mode: 0o755,
    };
    let owner = FileOp::Owner {
        paths: paths(&["/srv/run.sh"]),
        uid: Some(33),
        gid: Some(33),
    };
    for op in [mode, owner] {
        let d = rated(op, false, Environment::Lab);
        assert_eq!((d.action, d.tier), (ActionKind::FilePermissions, Tier::Medium));
        assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
    }
}

#[test]
fn deleting_a_file_or_an_empty_folder_asks_for_a_confirm() {
    let d = rated(delete(false), false, Environment::Lab);
    assert_eq!((d.action, d.tier), (ActionKind::FileDelete, Tier::Medium));
    assert_eq!(d.steps, vec![ApprovalStep::Confirm]);
}

#[test]
fn deleting_a_folder_with_what_is_in_it_is_the_full_approval() {
    let d = rated(delete(true), false, Environment::Lab);
    assert_eq!((d.action, d.tier), (ActionKind::FileDeleteFolder, Tier::High));
    assert!(d.steps.contains(&ApprovalStep::ImpactPreview));
    assert!(
        d.steps.contains(&ApprovalStep::TypeTargetCount { expected: 2 }),
        "the count typed is the paths' count: {:?}",
        d.steps
    );
    assert!(d.steps.contains(&ApprovalStep::Reason));
    assert!(!d.steps.contains(&ApprovalStep::VaultReauth), "High, not Critical");
    assert!(
        !d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })),
        "no VM to snapshot"
    );
}

#[test]
fn a_copy_is_medium_and_its_cp_is_rated_by_the_shell_rules_too() {
    let copy = || FileOp::Copy {
        paths: paths(&["/srv/www/site"]),
        into: "/backup".into(),
    };
    let d = rated(copy(), false, Environment::Lab);
    assert_eq!((d.action, d.tier), (ActionKind::FileCopy, Tier::Medium));
    assert!(
        d.reasons
            .iter()
            .any(|r| r.contains("`cp -a` is rated by the shell rules as other")),
        "{:?}",
        d.reasons
    );
    // A dangerous-command rule that matches the copy raises it to that rule's tier.
    let mut rules = PolicyRules::default();
    rules.dangerous_commands.push(DangerousPattern {
        name: "Backups".into(),
        pattern: r"cp .*/backup".into(),
    });
    let strict = PolicyEngine::new(rules).unwrap();
    let (command, targets) = change(copy(), false, Environment::Lab);
    let d = strict.evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::High, "{:?}", d.reasons);
    assert!(
        d.reasons.iter().any(|r| r.contains("flagged dangerous: Backups")),
        "{:?}",
        d.reasons
    );
    // And "other" commands asking for more makes a copy ask for more.
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::ExecOther, TierRule::same(Tier::High));
    let (command, targets) = change(copy(), false, Environment::Lab);
    assert_eq!(
        PolicyEngine::new(rules).unwrap().evaluate(&command, &targets).tier,
        Tier::High
    );
    // Many paths on one host aren't the bulk tier for commands on many hosts.
    let many = FileOp::Copy {
        paths: (0..8).map(|n| format!("/srv/f{n}")).collect(),
        into: "/backup".into(),
    };
    assert_eq!(rated(many, false, Environment::Lab).tier, Tier::Medium);
}

#[test]
fn any_change_as_root_is_one_tier_higher() {
    for (op, before, after) in [
        (new_folder(), Tier::Low, Tier::Medium),
        (rename(false), Tier::Low, Tier::Medium),
        (rename(true), Tier::Medium, Tier::High),
        (delete(false), Tier::Medium, Tier::High),
        (delete(true), Tier::High, Tier::Critical),
    ] {
        assert_eq!(rated(op.clone(), false, Environment::Lab).tier, before, "{op:?}");
        let d = rated(op.clone(), true, Environment::Lab);
        assert_eq!(d.tier, after, "{op:?}");
        assert!(
            d.reasons.iter().any(|r| r.starts_with("as root (sudo)")),
            "{:?}",
            d.reasons
        );
    }
    let d = rated(delete(true), true, Environment::Lab);
    assert!(
        d.steps.contains(&ApprovalStep::VaultReauth),
        "Critical asks for the vault password"
    );
}

#[test]
fn prod_raises_a_change_one_more_tier_as_root_or_not() {
    let d = rated(rename(false), false, Environment::Prod);
    assert_eq!(d.tier, Tier::Medium);
    let d = rated(rename(false), true, Environment::Prod);
    assert_eq!(d.tier, Tier::High, "Low, as root Medium, on Prod High: {:?}", d.reasons);
    assert!(d.reasons.iter().any(|r| r.contains("Prod")));
}

#[test]
fn a_protected_terminal_is_skipped() {
    let (command, mut targets) = change(delete(false), false, Environment::Lab);
    for t in &mut targets {
        t.protected = true;
    }
    let d = engine().evaluate(&command, &targets);
    assert!(d.targets.is_empty());
    assert_eq!(d.skipped.len(), 2);
}

#[test]
fn replacing_and_deleting_can_never_be_set_below_a_confirm() {
    for kind in [
        ActionKind::FileMoveReplace,
        ActionKind::FileDelete,
        ActionKind::FileDeleteFolder,
    ] {
        let mut rules = PolicyRules::default();
        rules.tiers.insert(kind, TierRule::same(Tier::Low));
        let err = PolicyEngine::new(rules).err().expect("rejected");
        assert!(err.to_string().contains("always asks first"), "{kind:?}: {err}");
    }
    // Lowering a deleted folder to one confirm is the user's to choose.
    let mut rules = PolicyRules::default();
    rules
        .tiers
        .insert(ActionKind::FileDeleteFolder, TierRule::same(Tier::Medium));
    rules.tiers.insert(ActionKind::FileMove, TierRule::same(Tier::Medium));
    let e = PolicyEngine::new(rules).unwrap();
    let (command, targets) = change(delete(true), false, Environment::Lab);
    assert_eq!(e.evaluate(&command, &targets).tier, Tier::Medium);
    let (command, targets) = change(rename(false), false, Environment::Lab);
    assert_eq!(e.evaluate(&command, &targets).tier, Tier::Medium);
}

#[test]
fn rules_saved_before_get_the_file_tiers_by_default() {
    let mut saved = PolicyRules::default();
    for kind in [
        ActionKind::FileNew,
        ActionKind::FileMove,
        ActionKind::FileMoveReplace,
        ActionKind::FileCopy,
        ActionKind::FilePermissions,
        ActionKind::FileDelete,
        ActionKind::FileDeleteFolder,
    ] {
        saved.tiers.remove(&kind);
    }
    assert!(saved.validate().is_err(), "missing tiers are refused as they are");
    saved.fill_missing_tiers();
    assert_eq!(saved, PolicyRules::default());
}

#[test]
fn uploading_as_root_is_one_tier_higher() {
    let target = Target {
        target: TargetRef::Terminal {
            terminal_id: Uuid::nil(),
            session_id: None,
        },
        name: "web01".into(),
        environment: Environment::Lab,
        protected: false,
    };
    let upload = |replace: bool| Command::FileUpload {
        targets: vec![target.target.clone()],
        folder: "/etc/nginx".into(),
        files: vec![UploadFile {
            local_path: r"C:\Users\alice\nginx.conf".into(),
            name: "nginx.conf".into(),
            size: 10,
            replace,
            modified: None,
        }],
        folders: vec![],
        keep_times: true,
        as_root: true,
    };
    let targets = std::slice::from_ref(&target);
    let d = engine().evaluate(&upload(false), targets);
    assert_eq!((d.action, d.tier), (ActionKind::FileUpload, Tier::Medium));
    let d = engine().evaluate(&upload(true), targets);
    assert_eq!((d.action, d.tier), (ActionKind::FileReplace, Tier::High));
    assert_eq!(
        upload(false).summary(1),
        "Upload 'nginx.conf' (10 B) to /etc/nginx, as root"
    );
}

#[test]
fn file_changes_come_only_from_the_core_and_retry_their_failed_paths() {
    let (command, _) = change(delete(false), false, Environment::Lab);
    assert!(command.check_from_ui().is_err(), "the drawer goes through Core.files");
    assert!(command.validate().is_ok());
    // Targets must be the spec's own steps.
    let Command::FileOp { spec, .. } = &command else {
        unreachable!()
    };
    let wrong = Command::FileOp {
        targets: vec![TargetRef::App],
        spec: spec.clone(),
    };
    assert!(wrong.validate().is_err());
    let retry = command
        .with_targets(vec![command.targets()[1].clone()])
        .expect("a retry of the failed path");
    let Command::FileOp { spec, targets } = &retry else {
        unreachable!()
    };
    assert_eq!(spec.op.paths(), vec!["/srv/www/older"]);
    assert_eq!(targets.len(), 1);
    assert!(command.with_targets(vec![TargetRef::App]).is_none());
    assert!(!safety_snapshot_applies(&command));
}

/// SS-14, SS-08 (G4): an editor tab and an editing session on this PC, on a terminal of `env`.
fn editing(as_root: bool, env: Environment, local: bool) -> (Command, Vec<Target>) {
    let path = "/etc/nginx/nginx.conf".to_owned();
    let command = if local {
        let spec = crate::terminal::edit_local::EditSpec {
            terminal_id: Uuid::nil(),
            path,
            as_root,
        };
        Command::EditLocal {
            targets: spec.targets(),
            spec: Box::new(spec),
        }
    } else {
        let spec = crate::terminal::editor::EditorSpec {
            terminal_id: Uuid::nil(),
            path,
            editor: "nano".into(),
            as_root,
        };
        Command::EditorOpen {
            targets: spec.targets(),
            spec: Box::new(spec),
        }
    };
    let targets = command
        .targets()
        .iter()
        .map(|target| Target {
            target: target.clone(),
            name: "web01: /etc/nginx/nginx.conf".into(),
            environment: env,
            protected: false,
        })
        .collect();
    (command, targets)
}

#[test]
fn an_editor_tab_is_low_and_one_tier_more_for_root_and_for_prod_never_rated_by_the_shell_rules() {
    for (as_root, env, tier) in [
        (false, Environment::Lab, Tier::Low),
        (false, Environment::Prod, Tier::Medium),
        (true, Environment::Lab, Tier::Medium),
        (true, Environment::Prod, Tier::High),
    ] {
        let (command, targets) = editing(as_root, env, false);
        let d = engine().evaluate(&command, &targets);
        assert_eq!(
            (d.action, d.tier),
            (ActionKind::FileEditorOpen, tier),
            "{as_root} {env:?}"
        );
        assert!(!d.reasons.iter().any(|r| r.contains("shell rules")), "{:?}", d.reasons);
    }
}

#[test]
fn editing_on_this_pc_is_a_replacement_approved_once_and_never_below_a_confirm() {
    for (as_root, env, tier) in [
        (false, Environment::Lab, Tier::Medium),
        (false, Environment::Prod, Tier::High),
        (true, Environment::Lab, Tier::High),
        (true, Environment::Prod, Tier::Critical),
    ] {
        let (command, targets) = editing(as_root, env, true);
        let d = engine().evaluate(&command, &targets);
        assert_eq!(
            (d.action, d.tier),
            (ActionKind::FileEditLocal, tier),
            "{as_root} {env:?}"
        );
    }
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::FileEditLocal, TierRule::same(Tier::Low));
    let err = PolicyEngine::new(rules).err().expect("rejected");
    assert!(err.to_string().contains("always asks first"), "{err}");
    // An editor tab may be raised, and rules saved before get both by default.
    let mut saved = PolicyRules::default();
    saved.tiers.remove(&ActionKind::FileEditorOpen);
    saved.tiers.remove(&ActionKind::FileEditLocal);
    saved.fill_missing_tiers();
    assert_eq!(saved, PolicyRules::default());
}
