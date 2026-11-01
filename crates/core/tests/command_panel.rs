//! Post-MVP P5, BX-08 the command panel, end to end: favourite commands (add, change, reorder,
//! delete, folders, `{{variables}}`), the built-in library classified by the policy engine (and
//! following the user's rules), each with a link to its manual page (QL-13), and favourites in the
//! encrypted export and import (FD-07).
//!
//! No host is contacted: nothing here runs a command or opens a page.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{HashMap, HashSet};

use common::Setup;
use remotely_core::fakes::FakeVmware;
use remotely_core::policy::{ActionKind, DangerousPattern};
use remotely_core::snippets::library::{LibraryGroup, LibrarySection, LIBRARY, TROUBLESHOOT};
use remotely_core::snippets::manual::{self, MANUAL_HOSTS};
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
        .add(&core.ctx(), input(folder, name, command))
        .await
        .unwrap()
}

async fn names(core: &Core) -> Vec<String> {
    core.snippets
        .favourites(&core.ctx())
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
    core.store.recent_audit(&core.ctx(), 300).await.unwrap()
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
            &core.ctx(),
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
    assert_eq!(workspace, core.ctx().workspace_id.to_string());
    assert_eq!(user, core.ctx().user_id.to_string());
}

#[tokio::test]
async fn names_are_unique_within_a_folder_and_inputs_are_checked() {
    let core = core().await;
    add(&core, Some("Web"), "Logs", "journalctl -u nginx").await;
    let err = core
        .snippets
        .add(&core.ctx(), input(Some("WEB"), "logs", "tail /var/log/syslog"))
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
        let err = core.snippets.add(&core.ctx(), bad.clone()).await.unwrap_err();
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
            &core.ctx(),
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
            &core.ctx(),
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
        .update(&core.ctx(), a.id, input(Some("DB"), "three", "uptime"))
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
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
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
        .reorder(&core.ctx(), Some("web"), &[c.id, a.id, b.id])
        .await
        .unwrap();
    let order: Vec<&str> = listed.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(order, ["Top", "C", "A", "B"]);

    // Not exactly the folder's favourites: refused, nothing changes.
    for wrong in [vec![c.id, a.id], vec![c.id, a.id, b.id, top.id], vec![c.id, c.id, a.id]] {
        let err = core
            .snippets
            .reorder(&core.ctx(), Some("Web"), &wrong)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }
    assert_eq!(names(&core).await, ["Top", "Web/C", "Web/A", "Web/B"]);

    core.snippets.delete(&core.ctx(), a.id).await.unwrap();
    assert_eq!(names(&core).await, ["Top", "Web/C", "Web/B"]);
    let err = core.snippets.delete(&core.ctx(), a.id).await.unwrap_err();
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
        "from the folder 'Web'; moved to the trash for 30 days".into()
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

    // Every area entry is defined once in LIBRARY, with a unique id and a clean, described command.
    let mut area_ids = HashSet::new();
    for b in LIBRARY {
        assert_eq!(b.group.section(), LibrarySection::Area, "{} is in an area group", b.id);
        assert!(area_ids.insert(b.id), "{} defined twice", b.id);
        assert!(b.description.ends_with('.') && b.description.len() > 10, "{}", b.id);
        assert_eq!(b.command.trim(), b.command, "{}", b.id);
        assert!(!b.command.contains(['\n', '\t', '\r']), "{}", b.id);
        // Test data uses only reserved example hosts (.test / 192.0.2.0/24), never example.com.
        assert!(!b.command.contains("example.com"), "no made-up hosts: {}", b.id);
    }

    // Each area group is shown, with a handful of entries, names unique within it.
    for group in LibraryGroup::ALL {
        if group.section() != LibrarySection::Area {
            continue;
        }
        let entries: Vec<_> = library.iter().filter(|e| e.group == group).collect();
        assert!(entries.len() >= 4, "{} has {} entries", group.label(), entries.len());
        let mut names = HashSet::new();
        for e in &entries {
            assert_eq!(e.section, LibrarySection::Area);
            assert_eq!(e.section_label, "By area");
            assert_eq!(e.group_label, group.label());
            assert!(names.insert(e.name), "{} twice in {}", e.name, group.label());
        }
    }

    // Every Troubleshoot runbook has an order of real area-entry ids, and each symptom entry reuses
    // the area entry's text and classification.
    let mut symptom_groups = HashSet::new();
    for symptom in TROUBLESHOOT {
        assert_eq!(symptom.group.section(), LibrarySection::Troubleshoot);
        assert!(symptom_groups.insert(symptom.group), "{} twice", symptom.group.label());
        assert!(symptom.steps.len() >= 3, "{} is too short", symptom.group.label());
        for id in symptom.steps {
            let b = LIBRARY
                .iter()
                .find(|b| b.id == *id)
                .unwrap_or_else(|| panic!("unknown id {id}"));
            let shown = library
                .iter()
                .find(|e| e.id == *id && e.group == symptom.group)
                .unwrap_or_else(|| panic!("{id} not shown under {}", symptom.group.label()));
            assert_eq!(shown.section, LibrarySection::Troubleshoot);
            assert_eq!(shown.command, b.command);
            assert_eq!(shown.risk, core.snippets.classify(b.command));
        }
    }
    assert_eq!(symptom_groups.len(), TROUBLESHOOT.len());

    // The Troubleshoot section is listed before the area section, so the panel shows it first.
    let first_area = library.iter().position(|e| e.section == LibrarySection::Area).unwrap();
    let last_troubleshoot = library
        .iter()
        .rposition(|e| e.section == LibrarySection::Troubleshoot)
        .unwrap();
    assert!(last_troubleshoot < first_area, "Troubleshoot comes before By area");

    // Go templates are not variables; real ones are. (Picked from the area copies.)
    let names = library.iter().find(|e| e.id == "docker.names").unwrap();
    assert!(names.variables.is_empty());
    let logs = library
        .iter()
        .find(|e| e.id == "k8s.logs" && e.section == LibrarySection::Area)
        .unwrap();
    let vars: Vec<&str> = logs.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(vars, ["pod", "namespace", "lines"]);
}

/// Every area entry that the default rules do NOT classify read-only, pinned so a later rule change,
/// or a careless new command, shows up as a diff in this test. Read-only is the default; this is the
/// exception list of checks that change something (or that Remotely cannot prove only read, like curl
/// or an interactive tool) and so ask before a bulk run or MultiExec sends them.
const EXPECTED_NON_READ_ONLY: &[&str] = &[
    // Dangerous (a default dangerous-command rule matches). From 0.4.1 also attach.partition (parted
    // mklabel), docker.prune and podman.prune (prunes) and k8s.delete-pod (kubectl delete), listed below
    // with the other entries of their groups; the `dangerous` list in the test pins them all.
    "system.reboot",
    // Changes, or not provably read-only (ExecOther).
    "disk.ncdu",
    "lvm.scan",
    "lvm.lvextend",
    "lvm.resize",
    "lvm.fsgrow-xfs",
    "lvm.fsgrow-ext",
    "lvm.mddetail",
    "lvm.mdexamine",
    "san.smart-test",
    "san.smb-shares",
    "san.fsck-check",
    "memory.dropcaches",
    "cpu.strace",
    "cpu.renice",
    "cpu.kill",
    "cpu.killname",
    "network.tcpprobe",
    "network.curl-time",
    "network.curl-head",
    "network.curl-resolve",
    "network.iface-detail",
    "network.nmcli",
    "network.tcpdump",
    "network.conntrack",
    "services.start",
    "services.stop",
    "services.restart",
    "services.reload",
    "services.enable",
    "services.disable",
    "services.mask",
    "services.reset-failed",
    "services.daemon-reload",
    "logs.vacuum",
    "logs.vacuum-time",
    "apt.update",
    "apt.upgrade",
    "apt.full-upgrade",
    "apt.install",
    "apt.remove",
    "apt.autoremove",
    "apt.fix-broken",
    "apt.clean",
    "dnf.upgrade",
    "dnf.install",
    "dnf.remove",
    "dnf.autoremove",
    "dnf.downgrade",
    "dnf.distrosync",
    "dnf.makecache",
    "dnf.clean",
    "users.add",
    "users.add-to-group",
    "users.lock",
    "users.deluser",
    "sec.setenforce",
    "sec.restorecon",
    "sec.sudo-rights",
    "sec.fail2ban-unban",
    "cert.update-trust",
    "firewall.ufw-allow",
    "firewall.ufw-reload",
    "firewall.firewalld-allow",
    "firewall.firewalld-reload",
    "web.nginx-reload",
    "web.apache-reload",
    "web.local-check",
    "db.pg-activity",
    "db.pg-conns",
    "time.set-ntp",
    "time.makestep",
    "id.sss-cache",
    "id.realm-join",
    "docker.restart",
    "docker.shell",
    "docker.prune",
    "podman.restart",
    "podman.prune",
    "k8s.restart",
    "k8s.scale",
    "k8s.delete-pod",
    "helm.rollback",
    // 0.4.0 additions. Disks: rescans, growing, partitioning, formatting (also Dangerous) and mounting.
    "attach.rescan-hosts",
    "attach.rescan-tool",
    "attach.rescan-disk",
    "attach.growpart-dry",
    "attach.growpart",
    "attach.pvresize",
    "attach.lvextend-all",
    "attach.vgextend",
    "attach.partition",
    "attach.format",
    "attach.mount",
    // fstab edits and mounts; mount --fake is not provably read-only.
    "fstab.backup",
    "fstab.add",
    "fstab.mount-all",
    "fstab.mount-preview",
    "fstab.mount-one",
    "fstab.unmount",
    // iSCSI: discovery saves node records; logins, rescans and record changes; netcat.
    "iscsi.portal-reach",
    "iscsi.discover",
    "iscsi.login",
    "iscsi.startup",
    "iscsi.logout",
    "iscsi.rescan",
    "iscsi.multipath-reload",
    // locate's database rebuild.
    "find.updatedb",
    // Every scp and rsync, dry runs included, and find -exec.
    "copy.scp-to",
    "copy.scp-from",
    "copy.scp-dir",
    "copy.scp-limit",
    "copy.rsync-to",
    "copy.rsync-from",
    "copy.rsync-preview",
    "copy.rsync-mirror-preview",
    "copy.rsync-mirror",
    "copy.rsync-resume",
    "copy.rsync-limit",
    "copy.rsync-port",
    "copy.rsync-verify",
    "copy.checksum-folder",
    // Time: time zone, NTP on/off, timesyncd and chrony changes.
    "time.set-timezone",
    "time.ntp-off",
    "time.timesyncd-set",
    "time.timesyncd-restart",
    "time.chrony-reload",
    "time.chrony-restart",
];

#[tokio::test]
async fn library_entries_are_classified_by_the_policy_engine() {
    let core = core().await;
    let library = core.snippets.library();
    let by_id = |id: &str| {
        library
            .iter()
            .find(|e| e.id == id && e.section == LibrarySection::Area)
            .unwrap()
            .clone()
    };

    // Each area entry's classification is pinned: everything is read-only except EXPECTED_NON_READ_ONLY.
    let mut actual: Vec<&str> = library
        .iter()
        .filter(|e| e.section == LibrarySection::Area && e.risk.action != ActionKind::ExecReadOnly)
        .map(|e| e.id)
        .collect();
    actual.sort_unstable();
    let mut expected: Vec<&str> = EXPECTED_NON_READ_ONLY.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected, "the set of non-read-only library entries changed");

    // The vast majority are read-only.
    let read_only = library
        .iter()
        .filter(|e| e.risk.action == ActionKind::ExecReadOnly)
        .count();
    assert!(
        read_only * 100 >= library.len() * 75,
        "{read_only} of {} are read-only",
        library.len()
    );
    // Exactly the entries a default dangerous-command rule matches are marked dangerous. BX-06 (0.4.1)
    // added the partition step, the Docker and Podman prunes and deleting a pod.
    let mut dangerous: Vec<(&str, Vec<String>)> = library
        .iter()
        .filter(|e| e.section == LibrarySection::Area && e.risk.action == ActionKind::ExecDangerous)
        .map(|e| (e.id, e.risk.dangerous.clone()))
        .collect();
    dangerous.dedup();
    assert_eq!(
        dangerous,
        [
            ("system.reboot", vec!["shutdown / reboot".to_owned()]),
            ("attach.partition", vec!["parted mklabel / mkpart / rm".to_owned()]),
            ("attach.format", vec!["mkfs".to_owned()]),
            ("docker.prune", vec!["docker / podman prune".to_owned()]),
            ("podman.prune", vec!["docker / podman prune".to_owned()]),
            ("k8s.delete-pod", vec!["kubectl delete".to_owned()]),
        ]
    );
    // Spot checks on both sides of the line.
    for id in [
        "services.restart",
        "apt.upgrade",
        "dnf.install",
        "users.add",
        "cpu.kill",
        "copy.rsync-preview",
        "iscsi.discover",
        "iscsi.login",
        "find.updatedb",
        "fstab.mount-preview",
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
        "san.smart-health",
        "sec.sshd-config",
        "cert.expiry",
        "lvm.pvs",
        "find.files",
        "find.big",
        "find.grep-include",
        "san.iscsi-sessions",
        "iscsi.node-detail",
        "fstab.verify",
        "time.chrony-check",
        "time.timesyncd-config",
        "copy.checksum",
    ] {
        assert_eq!(by_id(id).risk.action, ActionKind::ExecReadOnly, "{id}");
    }

    // The marks follow the user's rules: a new rule flags restarts, and without the reboot and prune
    // rules those entries are merely "other".
    let mut rules = core.bus.rules();
    rules
        .dangerous_commands
        .retain(|p| p.name != "shutdown / reboot" && p.name != "docker / podman prune");
    rules.dangerous_commands.push(DangerousPattern {
        name: "service restart".into(),
        pattern: r"systemctl\s+restart".into(),
    });
    // AP-06: dropping two dangerous-command rules loosens the rules.
    core.bus
        .set_rules_with(&core.ctx(), rules, Some(&SecretString::new(common::VAULT_PASSWORD)))
        .await
        .unwrap();
    let library = core.snippets.library();
    let by_id = |id: &str| library.iter().find(|e| e.id == id).unwrap().clone();
    assert_eq!(by_id("services.restart").risk.action, ActionKind::ExecDangerous);
    assert_eq!(by_id("services.restart").risk.dangerous, ["service restart"]);
    assert_eq!(by_id("system.reboot").risk.action, ActionKind::ExecOther);
    assert!(by_id("system.reboot").risk.dangerous.is_empty());
    assert_eq!(by_id("docker.prune").risk.action, ActionKind::ExecOther);

    // Favourites too.
    let fav = add(&core, None, "Restart", "sudo systemctl restart nginx").await;
    assert_eq!(fav.risk.action, ActionKind::ExecDangerous);
    let fav = add(&core, None, "Prune", "docker image prune -a").await;
    assert_eq!(fav.risk.action, ActionKind::ExecOther);
}

#[tokio::test]
async fn every_library_entry_links_to_its_manual_on_an_allowed_site() {
    // QL-13: each entry, in its area group and in any runbook, links to its official manual page:
    // an https address on one of the documentation sites the app may open.
    let core = core().await;
    let library = core.snippets.library();
    let mut used = HashSet::new();
    for e in &library {
        let url = manual::checked(&e.manual).unwrap_or_else(|_| panic!("{}: {} is refused", e.id, e.manual));
        assert_eq!(url.scheme(), "https", "{}", e.id);
        assert_eq!(url.as_str(), e.manual, "{} is written as the browser gets it", e.id);
        used.insert(url.host_str().unwrap_or_default().to_owned());
    }
    // The allow-list holds only sites a link uses.
    for host in MANUAL_HOSTS {
        assert!(used.contains(*host), "no manual link uses {host}");
    }
    // The page is the command's own, or that of the file it reads.
    let manual_of = |id: &str| library.iter().find(|e| e.id == id).unwrap().manual.clone();
    assert_eq!(
        manual_of("disk.free"),
        "https://man7.org/linux/man-pages/man1/df.1.html"
    );
    assert_eq!(
        manual_of("disk.fstab"),
        "https://man7.org/linux/man-pages/man5/fstab.5.html"
    );
    assert_eq!(
        manual_of("services.status"),
        "https://www.freedesktop.org/software/systemd/man/latest/systemctl.html"
    );
    assert_eq!(
        manual_of("san.iscsi-sessions"),
        "https://manpages.debian.org/bookworm/open-iscsi/iscsiadm.8.en.html"
    );
    assert_eq!(
        manual_of("docker.ps"),
        "https://docs.docker.com/reference/cli/docker/container/ls/"
    );
    assert_eq!(
        manual_of("copy.rsync-to"),
        "https://download.samba.org/pub/rsync/rsync.1"
    );
    assert_eq!(
        manual_of("time.chrony-check"),
        "https://chrony-project.org/doc/4.6/chronyd.html"
    );
}

#[tokio::test]
async fn a_library_entry_can_be_copied_into_the_favourites() {
    let core = core().await;
    let entry = core
        .snippets
        .library()
        .into_iter()
        .find(|e| e.id == "logs.service" && e.section == LibrarySection::Area)
        .unwrap();
    let fav = core
        .snippets
        .add(
            &core.ctx(),
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
            &a.ctx(),
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
        .open(
            &b.ctx(),
            &path,
            SecretString::new("five unrelated words here"),
            &b.vault,
        )
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
            &b.ctx(),
            TransferCommit {
                preview_id: preview.id,
                catalog: Default::default(),
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
                folder_defaults: vec![],
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
                groups: vec![],
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
    let kept = b.snippets.get(&b.ctx(), local_logs.id).await.unwrap();
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
        .open(
            &b.ctx(),
            &path,
            SecretString::new("five unrelated words here"),
            &b.vault,
        )
        .await
        .unwrap();
    let logs_row = preview.favourites.iter().find(|i| i.name == "Logs").unwrap();
    b.transfer
        .commit(
            &b.ctx(),
            TransferCommit {
                preview_id: preview.id,
                catalog: Default::default(),
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
                folder_defaults: vec![],
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
                groups: vec![],
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
    let replaced = b.snippets.get(&b.ctx(), local_logs.id).await.unwrap();
    assert_eq!(replaced.command, "journalctl -u nginx -n 100");
    let _ = std::fs::remove_dir_all(dir);
}
