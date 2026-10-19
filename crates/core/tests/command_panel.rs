//! Post-MVP P5, BX-08 the command panel, end to end: favourite commands (add, change, reorder,
//! delete, folders, `{{variables}}`), the built-in library classified by the policy engine (and
//! following the user's rules), and favourites in the encrypted export and import (FD-07).
//!
//! No host is contacted: nothing here runs a command.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{HashMap, HashSet};

use common::Setup;
use remotely_core::fakes::FakeVmware;
use remotely_core::policy::{ActionKind, DangerousPattern};
use remotely_core::snippets::library::LibraryGroup;
use remotely_core::snippets::{Favourite, FavouriteInput};
use remotely_core::store::AuditEntry;
use remotely_core::transfer::{ExportRequest, ItemAction, ItemChoice, ItemStatus, TransferCommit};
use remotely_core::vault::SecretString;
use remotely_core::Core;
use uuid::Uuid;

async fn core() -> Core {
    Setup::new(FakeVmware::default()).with_real_vault().build().await
}

fn input(folder: Option<&str>, name: &str, command: &str) -> FavouriteInput {
    FavouriteInput {
        folder: folder.map(String::from),
        name: name.into(),
        command: command.into(),
        description: None,
    }
}

async fn add(core: &Core, folder: Option<&str>, name: &str, command: &str) -> Favourite {
    core.snippets
        .add(&core.ctx, input(folder, name, command))
        .await
        .unwrap()
}

async fn names(core: &Core) -> Vec<String> {
    core.snippets
        .favourites(&core.ctx)
        .await
        .unwrap()
        .iter()
        .map(|f| match &f.folder {
            Some(folder) => format!("{folder}/{}", f.name),
            None => f.name.clone(),
        })
        .collect()
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 300).await.unwrap()
}

async fn favourite_audit(core: &Core) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = audit(core)
        .await
        .into_iter()
        .filter(|e| e.event == "favourite_changed")
        .map(|e| (e.action, e.detail.unwrap_or_default()))
        .collect();
    entries.reverse();
    entries
}

// ---- Favourites ---------------------------------------------------------------------------------------

#[tokio::test]
async fn favourites_are_added_in_folders_and_listed_in_order() {
    let core = core().await;
    let restart = core
        .snippets
        .add(
            &core.ctx,
            FavouriteInput {
                folder: Some("  Web  ".into()),
                name: " Restart nginx ".into(),
                command: "sudo systemctl restart nginx\r\n".into(),
                description: Some("After a config change.".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(restart.folder.as_deref(), Some("Web"));
    assert_eq!(restart.name, "Restart nginx");
    assert_eq!(restart.command, "sudo systemctl restart nginx");
    assert_eq!(restart.description.as_deref(), Some("After a config change."));
    assert_eq!(restart.risk.action, ActionKind::ExecOther);
    assert!(restart.variables.is_empty());

    add(&core, None, "Disk", "df -h").await;
    // The folder keeps its first spelling.
    let logs = add(
        &core,
        Some("web"),
        "Logs",
        "journalctl -u {{service:nginx}} -n {{lines}}",
    )
    .await;
    assert_eq!(logs.folder.as_deref(), Some("Web"));
    assert_eq!(logs.risk.action, ActionKind::ExecReadOnly);
    let vars: Vec<(&str, Option<&str>)> = logs
        .variables
        .iter()
        .map(|v| (v.name.as_str(), v.default.as_deref()))
        .collect();
    assert_eq!(vars, [("service", Some("nginx")), ("lines", None)]);
    add(&core, Some("DB"), "Backup", "pg_dump shop > /tmp/shop.sql").await;

    // The top level first, then folders by name, each in the order added.
    assert_eq!(
        names(&core).await,
        ["Disk", "DB/Backup", "Web/Restart nginx", "Web/Logs"]
    );

    // Stored with the workspace and the user, like every record.
    let (workspace, user): (String, String) =
        sqlx::query_as("SELECT workspace_id, user_id FROM command_favourites WHERE id = ?")
            .bind(logs.id.to_string())
            .fetch_one(core.store.pool())
            .await
            .unwrap();
    assert_eq!(workspace, core.ctx.workspace_id.to_string());
    assert_eq!(user, core.ctx.user_id.to_string());
}

#[tokio::test]
async fn names_are_unique_within_a_folder_and_inputs_are_checked() {
    let core = core().await;
    add(&core, Some("Web"), "Logs", "journalctl -u nginx").await;
    let err = core
        .snippets
        .add(&core.ctx, input(Some("WEB"), "logs", "tail /var/log/syslog"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
    assert_eq!(err.to_string(), "The folder 'Web' already has a command named 'logs'.");
    // The same name elsewhere is fine.
    add(&core, None, "Logs", "journalctl -n 50").await;
    add(&core, Some("DB"), "Logs", "journalctl -u postgresql").await;

    for bad in [
        input(None, "", "uptime"),
        input(None, "Empty", "   \n "),
        input(None, "Escape", "printf '\x1b[2J'"),
        input(Some("a\tb"), "Tab in folder", "uptime"),
        input(None, &"n".repeat(81), "uptime"),
        input(None, "Too long", &"x".repeat(9 * 1024)),
    ] {
        let err = core.snippets.add(&core.ctx, bad.clone()).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{bad:?}");
    }
    assert_eq!(names(&core).await.len(), 3, "nothing bad was saved");
}

#[tokio::test]
async fn changing_a_favourite_moves_renames_and_audits_without_the_command() {
    let core = core().await;
    let secretish = format!("token-{}", Uuid::new_v4().simple());
    let a = add(&core, Some("Web"), "One", "uptime").await;
    add(&core, Some("Web"), "Two", "free -h").await;
    add(&core, Some("DB"), "Three", "df -h").await;

    let moved = core
        .snippets
        .update(
            &core.ctx,
            a.id,
            FavouriteInput {
                folder: Some("db".into()),
                name: "First".into(),
                command: format!("curl -H 'X-Token: {secretish}' https://app.example.com/health"),
                description: Some("Health check".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(moved.id, a.id);
    assert_eq!(moved.folder.as_deref(), Some("DB"));
    // Moved to the end of its new folder.
    assert_eq!(names(&core).await, ["DB/Three", "DB/First", "Web/Two"]);

    // The same values again change nothing and log nothing.
    let before = favourite_audit(&core).await.len();
    let same = core
        .snippets
        .update(
            &core.ctx,
            a.id,
            FavouriteInput {
                folder: Some("DB".into()),
                name: "First".into(),
                command: moved.command.clone(),
                description: Some("Health check".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(same, moved);
    assert_eq!(favourite_audit(&core).await.len(), before);

    // Renaming onto another favourite in the folder is refused.
    let err = core
        .snippets
        .update(&core.ctx, a.id, input(Some("DB"), "three", "uptime"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");

    let log = favourite_audit(&core).await;
    assert_eq!(
        log[0],
        ("Added the favourite command 'One'".into(), "in the folder 'Web'".into())
    );
    assert_eq!(
        log[3],
        (
            "Changed the favourite command 'One'".into(),
            "renamed to 'First', moved to the folder 'DB', command changed, description changed".into()
        )
    );
    // The command text never reaches the audit log.
    for entry in audit(&core).await {
        assert!(!format!("{entry:?}").contains(&secretish), "{entry:?}");
    }
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn favourites_are_reordered_within_their_folder_and_deleted() {
    let core = core().await;
    let a = add(&core, Some("Web"), "A", "uptime").await;
    let b = add(&core, Some("Web"), "B", "free -h").await;
    let c = add(&core, Some("Web"), "C", "df -h").await;
    let top = add(&core, None, "Top", "w").await;

    let listed = core
        .snippets
        .reorder(&core.ctx, Some("web"), &[c.id, a.id, b.id])
        .await
        .unwrap();
    let order: Vec<&str> = listed.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(order, ["Top", "C", "A", "B"]);

    // Not exactly the folder's favourites: refused, nothing changes.
    for wrong in [vec![c.id, a.id], vec![c.id, a.id, b.id, top.id], vec![c.id, c.id, a.id]] {
        let err = core.snippets.reorder(&core.ctx, Some("Web"), &wrong).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }
    assert_eq!(names(&core).await, ["Top", "Web/C", "Web/A", "Web/B"]);

    core.snippets.delete(&core.ctx, a.id).await.unwrap();
    assert_eq!(names(&core).await, ["Top", "Web/C", "Web/B"]);
    let err = core.snippets.delete(&core.ctx, a.id).await.unwrap_err();
    assert_eq!(err.code(), "unknown_target");
    // A new one goes to the end, after the reordered ones.
    add(&core, Some("Web"), "D", "id").await;
    assert_eq!(names(&core).await, ["Top", "Web/C", "Web/B", "Web/D"]);

    let log = favourite_audit(&core).await;
    assert!(log.contains(&(
        "Reordered the favourite commands".into(),
        "3 in the folder 'Web'".into()
    )));
    assert!(log.contains(&(
        "Deleted the favourite command 'A'".into(),
        "from the folder 'Web'".into()
    )));
}

#[tokio::test]
async fn variables_are_filled_in_before_pasting() {
    let core = core().await;
    let fav = add(
        &core,
        None,
        "Pod logs",
        "kubectl logs {{pod}} -n {{namespace:default}} --tail={{lines:200}}",
    )
    .await;
    let values = HashMap::from([
        ("pod".to_owned(), "web-1".to_owned()),
        ("lines".to_owned(), "50".to_owned()),
    ]);
    assert_eq!(
        core.snippets.fill(&fav.command, &values).unwrap(),
        "kubectl logs web-1 -n default --tail=50"
    );
    let err = core.snippets.fill(&fav.command, &HashMap::new()).unwrap_err();
    assert_eq!(err.to_string(), "Give a value for {{pod}}.");
    let err = core
        .snippets
        .fill(
            &fav.command,
            &HashMap::from([("pod".to_owned(), "web-1\nreboot".to_owned())]),
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
}

// ---- Library ------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_library_covers_every_group_with_described_entries() {
    let core = core().await;
    let library = core.snippets.library();
    let mut ids = HashSet::new();
    for group in LibraryGroup::ALL {
        let entries: Vec<_> = library.iter().filter(|e| e.group == group).collect();
        assert!(entries.len() >= 4, "{} has {} entries", group.label(), entries.len());
        let mut names = HashSet::new();
        for e in entries {
            assert!(ids.insert(e.id), "{} twice", e.id);
            assert!(names.insert(e.name), "{} twice in {}", e.name, group.label());
            assert_eq!(e.group_label, group.label());
            assert!(e.description.ends_with('.') && e.description.len() > 10, "{}", e.id);
            assert_eq!(e.command.trim(), e.command, "{}", e.id);
            assert!(!e.command.contains(['\n', '\t', '\r']), "{}", e.id);
            assert!(
                !e.command.contains("example.com"),
                "no made-up hosts in commands: {}",
                e.id
            );
        }
    }
    assert_eq!(ids.len(), library.len(), "every entry is in a group");
    // Go templates are not variables; real ones are.
    let names = library.iter().find(|e| e.id == "docker.names").unwrap();
    assert!(names.variables.is_empty());
    let logs = library.iter().find(|e| e.id == "k8s.logs").unwrap();
    let vars: Vec<&str> = logs.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(vars, ["pod", "namespace", "lines"]);
}

#[tokio::test]
async fn library_entries_are_classified_by_the_policy_engine() {
    let core = core().await;
    let library = core.snippets.library();
    let by_id = |id: &str| library.iter().find(|e| e.id == id).unwrap().clone();

    // Mostly read-only.
    let read_only = library
        .iter()
        .filter(|e| e.risk.action == ActionKind::ExecReadOnly)
        .count();
    assert!(
        read_only * 100 >= library.len() * 75,
        "{read_only} of {} are read-only",
        library.len()
    );
    // Exactly the entries a default dangerous-command rule matches are marked dangerous.
    let dangerous: Vec<(&str, Vec<String>)> = library
        .iter()
        .filter(|e| e.risk.action == ActionKind::ExecDangerous)
        .map(|e| (e.id, e.risk.dangerous.clone()))
        .collect();
    assert_eq!(dangerous, [("system.reboot", vec!["shutdown / reboot".to_owned()])]);
    // What changes things is marked as such.
    for id in [
        "services.restart",
        "apt.upgrade",
        "dnf.install",
        "users.add",
        "firewall.ufw-allow",
        "docker.prune",
        "k8s.delete-pod",
        "cpu.kill",
    ] {
        assert_eq!(by_id(id).risk.action, ActionKind::ExecOther, "{id}");
    }
    for id in [
        "disk.free",
        "logs.service",
        "firewall.iptables",
        "docker.logs",
        "k8s.logs",
        "dnf.installed",
    ] {
        assert_eq!(by_id(id).risk.action, ActionKind::ExecReadOnly, "{id}");
    }

    // The marks follow the user's rules: a new rule flags prune, and without the reboot rule the
    // reboot entry is merely "other".
    let mut rules = core.bus.rules();
    rules.dangerous_commands.retain(|p| p.name != "shutdown / reboot");
    rules.dangerous_commands.push(DangerousPattern {
        name: "docker prune".into(),
        pattern: r"docker\s+(?:system|image|volume)\s+prune".into(),
    });
    core.bus.set_rules(&core.ctx, rules).await.unwrap();
    let library = core.snippets.library();
    let by_id = |id: &str| library.iter().find(|e| e.id == id).unwrap().clone();
    assert_eq!(by_id("docker.prune").risk.action, ActionKind::ExecDangerous);
    assert_eq!(by_id("docker.prune").risk.dangerous, ["docker prune"]);
    assert_eq!(by_id("system.reboot").risk.action, ActionKind::ExecOther);
    assert!(by_id("system.reboot").risk.dangerous.is_empty());

    // Favourites too.
    let fav = add(&core, None, "Prune", "docker image prune -a").await;
    assert_eq!(fav.risk.action, ActionKind::ExecDangerous);
}

#[tokio::test]
async fn a_library_entry_can_be_copied_into_the_favourites() {
    let core = core().await;
    let entry = core
        .snippets
        .library()
        .into_iter()
        .find(|e| e.id == "logs.service")
        .unwrap();
    let fav = core
        .snippets
        .add(
            &core.ctx,
            FavouriteInput {
                folder: Some(entry.group_label.into()),
                name: entry.name.into(),
                command: entry.command.into(),
                description: Some(entry.description.into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(fav.command, entry.command);
    assert_eq!(fav.variables, entry.variables);
    assert_eq!(fav.risk, entry.risk);
    assert_eq!(names(&core).await, ["Logs (journalctl)/A service's log"]);
}

// ---- Export and import (FD-07) -------------------------------------------------------------------------

#[tokio::test]
async fn favourites_travel_in_the_encrypted_export() {
    let a = core().await;
    let b = core().await;
    a.transfer.use_insecure_fast_kdf();
    b.transfer.use_insecure_fast_kdf();
    add(&a, None, "Disk", "df -h").await;
    add(&a, Some("Web"), "Logs", "journalctl -u nginx -n 100").await;
    add(&a, Some("Web"), "Restart", "sudo systemctl restart nginx").await;
    // B has Disk already, the same; and its own Web/Logs, with another command.
    add(&b, None, "Disk", "df -h").await;
    let local_logs = add(&b, Some("web"), "Logs", "tail -n 100 /var/log/nginx/error.log").await;

    let dir = common::temp_folder("favourites-export");
    let path = dir.join("favourites.remotely");
    let report = a
        .transfer
        .export(
            &a.ctx,
            &path,
            ExportRequest {
                passphrase: SecretString::new("five unrelated words here"),
                include_known_hosts: true,
                include_secrets: false,
                vault_password: None,
            },
            &a.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    assert_eq!(report.favourites, 3);
    let exported = audit(&a)
        .await
        .into_iter()
        .find(|e| e.event == "data_exported")
        .unwrap();
    assert!(exported.detail.unwrap().contains("3 favourite commands"));

    let preview = b
        .transfer
        .open(&b.ctx, &path, SecretString::new("five unrelated words here"), &b.vault)
        .await
        .unwrap();
    let rows: Vec<(&str, ItemStatus)> = preview.favourites.iter().map(|i| (i.name.as_str(), i.status)).collect();
    assert_eq!(
        rows,
        [
            ("Disk", ItemStatus::Same),
            ("Logs", ItemStatus::Conflict),
            ("Restart", ItemStatus::New)
        ]
    );
    let logs_row = &preview.favourites[1];
    assert_eq!(
        logs_row.conflict.as_deref(),
        Some("A favourite with this name in 'web' has another command.")
    );
    assert_eq!(logs_row.detail, "in 'Web': journalctl -u nginx -n 100");

    let report = b
        .transfer
        .commit(
            &b.ctx,
            TransferCommit {
                preview_id: preview.id,
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
                favourites: vec![ItemChoice {
                    index: logs_row.index,
                    action: ItemAction::KeepBoth,
                }],
            },
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert_eq!(report.favourites.added, 1);
    assert_eq!(report.favourites.kept_both, 1);
    assert_eq!(report.favourites.skipped, 1);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(names(&b).await, ["Disk", "web/Logs", "web/Logs (2)", "web/Restart"]);
    // B's own Logs is untouched; each import was audited by the panel's module.
    let kept = b.snippets.get(&b.ctx, local_logs.id).await.unwrap();
    assert_eq!(kept.command, local_logs.command);
    let log = favourite_audit(&b).await;
    assert!(log
        .iter()
        .any(|(action, _)| action == "Added the favourite command 'Logs (2)'"));
    let imported = audit(&b)
        .await
        .into_iter()
        .find(|e| e.event == "data_imported")
        .unwrap();
    assert!(imported
        .detail
        .unwrap()
        .contains("favourite commands 1 added, 0 replaced, 1 kept both, 1 skipped"),);

    // Importing again with Replace overwrites the local one in place.
    let preview = b
        .transfer
        .open(&b.ctx, &path, SecretString::new("five unrelated words here"), &b.vault)
        .await
        .unwrap();
    let logs_row = preview.favourites.iter().find(|i| i.name == "Logs").unwrap();
    b.transfer
        .commit(
            &b.ctx,
            TransferCommit {
                preview_id: preview.id,
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
                favourites: vec![ItemChoice {
                    index: logs_row.index,
                    action: ItemAction::Replace,
                }],
            },
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    let replaced = b.snippets.get(&b.ctx, local_logs.id).await.unwrap();
    assert_eq!(replaced.command, "journalctl -u nginx -n 100");
    let _ = std::fs::remove_dir_all(dir);
}
