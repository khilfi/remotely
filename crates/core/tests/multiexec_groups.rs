//! QL-19 saved MultiExec groups: saved, listed, changed and deleted, each change audited with the member
//! sessions as targets; names and members checked and capped; a deleted session leaving its groups; every
//! edit refused by the read-only lock (FD-03); and groups carried between two "laptops" by FD-07, members
//! mapped to the sessions they became there. Opening a group's terminals and typing into them with MultiExec
//! is in tests/multiexec.rs, against local SSH test servers.
//!
//! No host is touched: the sessions are only saved (reserved example names and addresses).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{temp_folder, Setup};
use remotely_core::domain::Environment;
use remotely_core::fakes::FakeVmware;
use remotely_core::multiexec_groups::{GroupInput, MultiExecGroup, MAX_GROUPS, MAX_MEMBERS, MAX_NAME};
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::transfer::{
    ExportRequest, ItemAction, ItemChoice, ItemStatus, TransferCommit, TransferPreview, TransferReport,
};
use remotely_core::vault::SecretString;
use remotely_core::{Core, CoreError};
use uuid::Uuid;

const PASSPHRASE: &str = "tulip anvil orbit";

async fn core() -> Core {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    core.transfer.use_insecure_fast_kdf();
    core
}

fn session(name: &str, host: &str) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: Some("alice".into()),
        auth: SessionAuth::Agent,
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::None,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

async fn add_session(core: &Core, name: &str, host: &str) -> Uuid {
    core.sessions.create(&core.ctx(), session(name, host)).await.unwrap().id
}

fn group(name: &str, sessions: &[Uuid]) -> GroupInput {
    GroupInput {
        name: name.into(),
        session_ids: sessions.to_vec(),
    }
}

fn member_names(group: &MultiExecGroup) -> Vec<&str> {
    group.members.iter().map(|m| m.name.as_str()).collect()
}

async fn group_audit(core: &Core) -> Vec<AuditEntry> {
    let mut entries: Vec<AuditEntry> = core
        .store
        .recent_audit(&core.ctx(), 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "multiexec_group_changed")
        .collect();
    entries.reverse();
    entries
}

fn invalid(result: remotely_core::Result<MultiExecGroup>, says: &str) {
    match result {
        Err(CoreError::InvalidInput(message)) => assert!(message.contains(says), "{message:?} says {says:?}"),
        other => panic!("expected {says:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn a_group_is_saved_changed_and_deleted_and_each_change_is_audited() {
    let core = core().await;
    let ctx = &core.ctx();
    let web01 = add_session(&core, "web01", "web01.example.com").await;
    let web02 = add_session(&core, "web02", "web02.example.com").await;
    let web03 = add_session(&core, "web03", "192.0.2.13").await;
    let db01 = add_session(&core, "db01", "db01.example.org").await;

    // Repeats are dropped; the order is the user's.
    let web = core
        .groups
        .create(ctx, group("  Web servers ", &[web02, web01, web02]))
        .await
        .unwrap();
    assert_eq!(web.name, "Web servers");
    assert_eq!(member_names(&web), ["web02", "web01"]);
    assert_eq!(web.session_ids(), [web02, web01]);
    let all = core.groups.create(ctx, group("all", &[db01, web01])).await.unwrap();
    let listed = core.groups.list(ctx).await.unwrap();
    assert_eq!(
        listed.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(),
        ["all", "Web servers"],
        "by name, any letter case"
    );

    let audit = group_audit(&core).await;
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].action, "Created the MultiExec group 'Web servers'");
    assert_eq!(audit[0].detail.as_deref(), Some("2 sessions: 'web02', 'web01'"));
    assert!(audit[0].targets_json.contains(&web01.to_string()));
    assert!(audit[0].targets_json.contains(&web02.to_string()));
    assert!(!audit[0].targets_json.contains(&db01.to_string()));
    assert_eq!(audit[0].tier, None, "no approval tier: an edit of the app's own data");

    // Renamed, one session added and one removed: all said, the removed one among the targets.
    let changed = core
        .groups
        .update(ctx, web.id, group("Web tier", &[web03, web02]))
        .await
        .unwrap();
    assert_eq!(changed.id, web.id);
    assert_eq!(changed.name, "Web tier");
    assert_eq!(member_names(&changed), ["web03", "web02"]);
    let audit = group_audit(&core).await;
    let entry = audit.last().unwrap();
    assert_eq!(entry.action, "Changed the MultiExec group 'Web servers'");
    let detail = entry.detail.as_deref().unwrap();
    assert!(detail.contains("renamed to 'Web tier'"), "{detail}");
    assert!(detail.contains("added 'web03'"), "{detail}");
    assert!(detail.contains("removed 'web01'"), "{detail}");
    assert!(detail.ends_with("now 2 sessions"), "{detail}");
    for id in [web01, web02, web03] {
        assert!(entry.targets_json.contains(&id.to_string()), "{id} among the targets");
    }

    // Only the order changed: said so. Nothing changed: nothing audited.
    core.groups
        .update(ctx, web.id, group("Web tier", &[web02, web03]))
        .await
        .unwrap();
    assert_eq!(
        group_audit(&core).await.last().unwrap().detail.as_deref(),
        Some("reordered; now 2 sessions")
    );
    let count = group_audit(&core).await.len();
    core.groups
        .update(ctx, web.id, group("Web tier", &[web02, web03, web02]))
        .await
        .unwrap();
    assert_eq!(group_audit(&core).await.len(), count, "no change, no entry");

    // Deleting a group keeps its sessions.
    core.groups.delete(ctx, all.id).await.unwrap();
    let audit = group_audit(&core).await;
    let entry = audit.last().unwrap();
    assert_eq!(entry.action, "Deleted the MultiExec group 'all'");
    assert_eq!(entry.detail.as_deref(), Some("it held 2 sessions: 'db01', 'web01'"));
    assert_eq!(core.groups.list(ctx).await.unwrap().len(), 1);
    assert!(core.sessions.get(ctx, db01).await.is_ok());
    assert!(matches!(
        core.groups.delete(ctx, all.id).await,
        Err(CoreError::UnknownTarget(_))
    ));
}

#[tokio::test]
async fn names_and_members_are_checked_and_capped() {
    let core = core().await;
    let ctx = &core.ctx();
    let web01 = add_session(&core, "web01", "web01.example.com").await;
    let web02 = add_session(&core, "web02", "web02.example.com").await;
    let first = core.groups.create(ctx, group("Web servers", &[web01])).await.unwrap();

    invalid(
        core.groups.create(ctx, group("  ", &[web01])).await,
        "Give the group a name",
    );
    invalid(
        core.groups
            .create(ctx, group(&"x".repeat(MAX_NAME + 1), &[web01]))
            .await,
        "at most 60 characters",
    );
    invalid(
        core.groups.create(ctx, group("two\nlines", &[web01])).await,
        "line breaks",
    );
    invalid(
        core.groups.create(ctx, group("WEB SERVERS", &[web02])).await,
        "There is a group named 'WEB SERVERS' already",
    );
    invalid(
        core.groups.create(ctx, group("empty", &[])).await,
        "at least one saved session",
    );
    invalid(
        core.groups.create(ctx, group("ghost", &[web01, Uuid::new_v4()])).await,
        "1 session picked for the group is not saved here",
    );
    let too_many: Vec<Uuid> = (0..=MAX_MEMBERS).map(|_| Uuid::new_v4()).collect();
    invalid(
        core.groups.create(ctx, group("big", &too_many)).await,
        "at most 100 sessions",
    );
    // Its own name, in another letter case, is fine for the group itself.
    let renamed = core
        .groups
        .update(ctx, first.id, group("web SERVERS", &[web01, web02]))
        .await
        .unwrap();
    assert_eq!(renamed.name, "web SERVERS");
    assert!(matches!(
        core.groups.update(ctx, Uuid::new_v4(), group("x", &[web01])).await,
        Err(CoreError::UnknownTarget(_))
    ));

    // At most MAX_GROUPS groups in a workspace.
    for n in 1..MAX_GROUPS {
        core.groups
            .create(ctx, group(&format!("g{n:03}"), &[web02]))
            .await
            .unwrap();
    }
    assert_eq!(core.groups.list(ctx).await.unwrap().len(), MAX_GROUPS);
    invalid(
        core.groups.create(ctx, group("one more", &[web01])).await,
        "There are 200 MultiExec groups already",
    );
}

#[tokio::test]
async fn a_deleted_session_leaves_its_groups() {
    let core = core().await;
    let ctx = &core.ctx();
    let web01 = add_session(&core, "web01", "web01.example.com").await;
    let web02 = add_session(&core, "web02", "web02.example.com").await;
    let web = core.groups.create(ctx, group("Web", &[web01, web02])).await.unwrap();

    core.sessions.delete(ctx, web01).await.unwrap();
    let after = core.groups.get(ctx, web.id).await.unwrap();
    assert_eq!(member_names(&after), ["web02"]);

    // With its last session gone, the group stays, empty, until the user deletes or refills it.
    core.sessions.delete(ctx, web02).await.unwrap();
    let empty = core.groups.get(ctx, web.id).await.unwrap();
    assert!(empty.members.is_empty());
    assert_eq!(core.groups.list(ctx).await.unwrap().len(), 1);
    let web03 = add_session(&core, "web03", "web03.example.com").await;
    let refilled = core.groups.update(ctx, web.id, group("Web", &[web03])).await.unwrap();
    assert_eq!(member_names(&refilled), ["web03"]);
    let detail = group_audit(&core).await.last().unwrap().detail.clone().unwrap();
    assert!(detail.contains("added 'web03'"), "{detail}");
}

#[tokio::test]
async fn the_read_only_lock_refuses_every_group_edit() {
    let core = core().await;
    let ctx = &core.ctx();
    let web01 = add_session(&core, "web01", "web01.example.com").await;
    let web = core.groups.create(ctx, group("Web", &[web01])).await.unwrap();
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let before = group_audit(&core).await.len();

    let refused = |result: remotely_core::Result<()>| match result {
        Err(err @ CoreError::ReadOnlyLock { .. }) => {
            assert!(err.to_string().contains("Edit saved MultiExec groups"), "{err}");
        }
        other => panic!("expected the read-only lock, got {other:?}"),
    };
    refused(core.groups.create(ctx, group("Other", &[web01])).await.map(drop));
    refused(
        core.groups
            .update(ctx, web.id, group("Renamed", &[web01]))
            .await
            .map(drop),
    );
    refused(core.groups.delete(ctx, web.id).await);
    // Reading is not an edit.
    assert_eq!(core.groups.list(ctx).await.unwrap(), std::slice::from_ref(&web));
    assert_eq!(group_audit(&core).await.len(), before);

    core.presentation
        .set(Presentation {
            enabled: false,
            read_only: false,
        })
        .await
        .unwrap();
    core.groups.delete(ctx, web.id).await.unwrap();
}

// ---- FD-07 ----------------------------------------------------------------------------------------------

fn request() -> ExportRequest {
    ExportRequest {
        passphrase: SecretString::new(PASSPHRASE),
        include_known_hosts: true,
        include_secrets: false,
        vault_password: None,
    }
}

async fn export(core: &Core, dir: &Path) -> PathBuf {
    let path = dir.join(format!("export-{}.remotely", Uuid::new_v4().simple()));
    let report = core
        .transfer
        .export(&core.ctx(), &path, request(), &core.vault, "Remotely test")
        .await
        .unwrap();
    assert_eq!(report.groups, core.groups.list(&core.ctx()).await.unwrap().len());
    path
}

async fn open(core: &Core, path: &Path) -> TransferPreview {
    core.transfer
        .open(&core.ctx(), path, SecretString::new(PASSPHRASE), &core.vault)
        .await
        .unwrap()
}

async fn commit(
    core: &Core,
    preview: &TransferPreview,
    sessions: &[(usize, ItemAction)],
    groups: &[(usize, ItemAction)],
) -> TransferReport {
    let choices = |list: &[(usize, ItemAction)]| {
        list.iter()
            .map(|&(index, action)| ItemChoice { index, action })
            .collect()
    };
    core.transfer
        .commit(
            &core.ctx(),
            TransferCommit {
                preview_id: preview.id,
                sessions: choices(sessions),
                known_hosts: vec![],
                secrets: vec![],
                favourites: vec![],
                groups: choices(groups),
                checks: vec![],
                catalog: Default::default(),
                folder_defaults: vec![],
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
            },
            &core.sessions,
            &core.vault,
            &core.known_hosts,
            &core.snippets,
        )
        .await
        .unwrap()
}

fn row<'a>(items: &'a [remotely_core::transfer::PreviewItem], name: &str) -> &'a remotely_core::transfer::PreviewItem {
    items
        .iter()
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("no {name} in {items:?}"))
}

async fn by_name(core: &Core, name: &str) -> MultiExecGroup {
    core.groups
        .list(&core.ctx())
        .await
        .unwrap()
        .into_iter()
        .find(|g| g.name == name)
        .unwrap_or_else(|| panic!("no group {name}"))
}

#[tokio::test]
async fn groups_travel_in_the_encrypted_export_with_their_sessions() {
    let dir = temp_folder("groups-transfer");
    let a = core().await;
    let web01 = add_session(&a, "web01", "web01.example.com").await;
    let web02 = add_session(&a, "web02", "web02.example.com").await;
    let db01 = add_session(&a, "db01", "192.0.2.20").await;
    a.groups
        .create(&a.ctx(), group("Web servers", &[web02, web01]))
        .await
        .unwrap();
    a.groups
        .create(&a.ctx(), group("Everything", &[db01, web01, web02]))
        .await
        .unwrap();
    let path = export(&a, &dir).await;
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("Web servers"), "the file is encrypted");
    let exported = a
        .store
        .recent_audit(&a.ctx(), 50)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "data_exported")
        .unwrap();
    assert!(exported.detail.unwrap().contains("2 MultiExec groups"));

    // A laptop with nothing: both groups are new, and come with the sessions (which keep their ids).
    let b = core().await;
    let preview = open(&b, &path).await;
    assert_eq!(preview.groups.len(), 2);
    let web_row = row(&preview.groups, "Web servers");
    assert_eq!(web_row.status, ItemStatus::New);
    assert_eq!(web_row.default_action, ItemAction::Import);
    assert_eq!(web_row.detail, "2 sessions: 'web02', 'web01'");
    let report = commit(&b, &preview, &[], &[]).await;
    assert_eq!(report.groups.added, 2);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let web = by_name(&b, "Web servers").await;
    assert_eq!(web.session_ids(), [web02, web01]);
    assert_eq!(
        member_names(&by_name(&b, "Everything").await),
        ["db01", "web01", "web02"]
    );
    let imported = b
        .store
        .recent_audit(&b.ctx(), 100)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "data_imported")
        .unwrap();
    let detail = imported.detail.unwrap();
    assert!(detail.contains("MultiExec groups 2 added"), "{detail}");
    assert_eq!(
        group_audit(&b).await.len(),
        2,
        "each group saved and audited by the groups module"
    );

    // The same file again: the same groups, skipped by default.
    let again = open(&b, &path).await;
    assert!(again.groups.iter().all(|g| g.status == ItemStatus::Same));
    assert!(again.groups.iter().all(|g| g.default_action == ItemAction::Skip));
    b.transfer.close(again.id);

    // B changes its copy: a conflict, replaced on request.
    b.groups
        .update(&b.ctx(), web.id, group("Web servers", &[web01]))
        .await
        .unwrap();
    let conflict = open(&b, &path).await;
    let web_row = row(&conflict.groups, "Web servers");
    assert_eq!(web_row.status, ItemStatus::Conflict);
    assert_eq!(web_row.default_action, ItemAction::Skip);
    assert_eq!(
        web_row.choices,
        [ItemAction::Skip, ItemAction::Replace, ItemAction::KeepBoth]
    );
    let index = web_row.index;
    let report = commit(&b, &conflict, &[], &[(index, ItemAction::Replace)]).await;
    assert_eq!(report.groups.replaced, 1);
    let replaced = by_name(&b, "Web servers").await;
    assert_eq!(replaced.id, web.id, "replacing keeps the group here");
    assert_eq!(replaced.session_ids(), [web02, web01]);

    // Keep both: a second group under a free name.
    b.groups
        .update(&b.ctx(), web.id, group("Web servers", &[web02]))
        .await
        .unwrap();
    let both = open(&b, &path).await;
    let index = row(&both.groups, "Web servers").index;
    let report = commit(&b, &both, &[], &[(index, ItemAction::KeepBoth)]).await;
    assert_eq!(report.groups.kept_both, 1);
    assert_eq!(by_name(&b, "Web servers").await.session_ids(), [web02]);
    assert_eq!(by_name(&b, "Web servers (2)").await.session_ids(), [web02, web01]);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn members_become_the_sessions_here_or_are_left_out_with_a_note() {
    let dir = temp_folder("groups-transfer");
    let a = core().await;
    let web01 = add_session(&a, "web01", "web01.example.com").await;
    let web02 = add_session(&a, "web02", "web02.example.com").await;
    let db01 = add_session(&a, "db01", "192.0.2.20").await;
    a.groups
        .create(&a.ctx(), group("Web servers", &[web01, web02]))
        .await
        .unwrap();
    a.groups.create(&a.ctx(), group("Databases", &[db01])).await.unwrap();
    let path = export(&a, &dir).await;

    // B has web01 already, under another id (the same user, host and port), and skips web02 and db01.
    let b = core().await;
    let here = add_session(&b, "web01", "web01.example.com").await;
    let preview = open(&b, &path).await;
    let session_index = |name: &str| preview.sessions.iter().find(|s| s.name == name).unwrap().index;
    assert_eq!(
        preview.sessions[session_index("web01")].status,
        ItemStatus::Same,
        "{:?}",
        preview.sessions
    );
    let report = commit(
        &b,
        &preview,
        &[
            (session_index("web02"), ItemAction::Skip),
            (session_index("db01"), ItemAction::Skip),
        ],
        &[],
    )
    .await;
    assert_eq!(report.groups.added, 1);
    let web = by_name(&b, "Web servers").await;
    assert_eq!(web.session_ids(), [here], "web01 is the session already here");
    let note = report
        .problems
        .iter()
        .find(|p| p.name == "Web servers (MultiExec group)")
        .unwrap();
    assert!(
        note.reason
            .contains("Saved without 1 session that was not imported: 'web02'"),
        "{}",
        note.reason
    );
    let none = report
        .problems
        .iter()
        .find(|p| p.name == "Databases (MultiExec group)")
        .unwrap();
    assert!(none.reason.contains("None of its sessions is here"), "{}", none.reason);
    assert!(b
        .groups
        .list(&b.ctx())
        .await
        .unwrap()
        .iter()
        .all(|g| g.name != "Databases"));
    let _ = std::fs::remove_dir_all(dir);
}
