//! 0.7.0 F5 end to end on the fakes: FD-06 notes (saved, rendered, audited without their text, refused by the
//! read-only lock), QL-26 stars and recents, QL-27 the trash (a deleted session with what hangs off it, a favourite
//! command, a size, an image, a launch template and a stack; restore, a taken name, gone folders and jump hosts, AP-06,
//! the purge, Delete now and Empty trash) and QL-28 bulk edit. No real host or VM.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::sync::Arc;

use common::{listed, temp_folder, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::containers::EngineKind;
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::adapters::remote::forward::ForwardKind;
use remotely_core::catalog::sizes::{DiskSpec, Provisioning, SizeInput};
use remotely_core::catalog::{AfterDeploy, CloneMode, HashProgress, ImageInput, Network, SourceInput, TemplateInput};
use remotely_core::containers::{MarkInput, SudoMode};
use remotely_core::domain::Environment;
use remotely_core::fakes::FakeVmware;
use remotely_core::forwards::ForwardInput;
use remotely_core::multiexec_groups::GroupInput;
use remotely_core::notes::{NoteInput, NoteKind, NoteLink, NoteTarget};
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{BulkEdit, FolderChoice, JumpChoice, SessionAuth, SessionInput, UserChoice};
use remotely_core::snippets::FavouriteInput;
use remotely_core::stacks::{Readiness, StackInput, StackStep};
use remotely_core::stars::{RecentKind, StarKind, MAX_RECENTS};
use remotely_core::store::AuditEntry;
use remotely_core::trash::TrashKind;
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::{Core, CoreError};
use uuid::Uuid;

const LOCKED: Presentation = Presentation {
    enabled: true,
    read_only: true,
};

const UNLOCKED: Presentation = Presentation {
    enabled: false,
    read_only: false,
};

async fn core() -> Core {
    Setup::new(listed(FakeVmware::default(), &["it-web"]))
        .with_real_vault()
        .build()
        .await
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

async fn secret(core: &Core, label: &str, value: &str) -> SecretId {
    core.vault
        .add(&core.ctx(), SecretKind::Password, label, SecretString::new(value))
        .await
        .unwrap()
        .id
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx(), 200).await.unwrap()
}

fn note(body: &str) -> NoteInput {
    NoteInput {
        body: body.into(),
        handover: false,
    }
}

// ---- FD-06 notes ------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_note_is_saved_rendered_and_audited_without_its_text() {
    let core = core().await;
    let ctx = core.ctx();
    let web = core
        .sessions
        .create(&ctx, session("web01", "web01.example.com"))
        .await
        .unwrap();
    secret(&core, "DB admin", "pw-value-1").await;
    let target = NoteTarget::session(web.id);
    let body = "# web01\n\nRestart with `systemctl restart nginx`.\n\n```bash\nsudo systemctl restart nginx\n```\n\n\
                See [the runbook](https://example.com/runbooks/nginx), the [db password](<vault:DB admin>) and \
                <vm:it-web>.";
    let saved = core.notes.save(&ctx, &target, note(body)).await.unwrap().unwrap();
    assert_eq!(saved.title, "web01");
    assert!(!saved.looks_secret);
    assert_eq!(core.notes.get(&ctx, &target).await.unwrap().unwrap().body, body);

    let entry = audit(&core).await.remove(0);
    assert_eq!(entry.event, "note_changed");
    assert_eq!(entry.action, "Added a note to session 'web01'");
    assert!(entry.targets_json.contains(&web.id.to_string()));
    let logged = format!("{} {}", entry.action, entry.detail.clone().unwrap_or_default());
    assert!(
        !logged.contains("nginx"),
        "the note's text stays out of the audit log: {logged}"
    );

    let rendered = core.notes.render(&ctx, body).await.unwrap();
    assert_eq!(rendered.code_blocks, vec!["sudo systemctl restart nginx\n".to_owned()]);
    assert_eq!(
        rendered.links,
        vec![
            NoteLink::Web {
                url: "https://example.com/runbooks/nginx".into()
            },
            NoteLink::Vault {
                name: "DB admin".into(),
                found: true
            },
            NoteLink::Vm {
                name: "it-web".into(),
                key: Some(vmx("it-web"))
            },
        ]
    );
    assert!(
        !rendered.html.contains("pw-value-1"),
        "a vault link never carries its secret"
    );

    // An edit that changes nothing writes nothing; the handover mark is audited.
    let before = audit(&core).await.len();
    core.notes.save(&ctx, &target, note(body)).await.unwrap();
    assert_eq!(audit(&core).await.len(), before);
    let marked = core.notes.set_handover(&ctx, &target, true).await.unwrap();
    assert!(marked.handover);
    assert!(audit(&core).await[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("handover pack"));
    let handover = core.notes.for_handover(&ctx).await.unwrap();
    assert_eq!(handover.len(), 1);
    assert!(handover[0].1.contains("<a href=\"https://example.com/runbooks/nginx\""));
    assert!(!handover[0].1.contains("data-note-link"));

    // QL-20: notes are listed for search with what they are about.
    let listed = core.notes.list(&ctx).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kind, NoteKind::Session);

    // An empty text deletes it.
    assert!(core.notes.save(&ctx, &target, note("  \n")).await.unwrap().is_none());
    assert!(core.notes.get(&ctx, &target).await.unwrap().is_none());
    assert_eq!(audit(&core).await[0].action, "Deleted the note of session 'web01'");
}

#[tokio::test]
async fn notes_say_when_they_look_like_a_secret_and_are_refused_while_presenting() {
    let core = core().await;
    let ctx = core.ctx();
    let vm = NoteTarget::vm(&vmx("it-web"));
    let saved = core
        .notes
        .save(&ctx, &vm, note("admin password=Hunter2Hunter2!"))
        .await
        .unwrap()
        .unwrap();
    assert!(saved.looks_secret);
    assert_eq!(saved.title, "it-web");
    assert!(audit(&core).await[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("looks like it holds a secret"));
    assert!(!audit(&core).await[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("Hunter2"));

    // A VM this workspace doesn't have takes no note.
    assert!(core
        .notes
        .save(&ctx, &NoteTarget::vm(&vmx("not-here")), note("x"))
        .await
        .is_err());

    core.presentation.set(LOCKED).await.unwrap();
    assert!(matches!(
        core.notes.save(&ctx, &vm, note("changed")).await.unwrap_err(),
        CoreError::ReadOnlyLock { .. }
    ));
    // QL-26: stars and recents are not locked.
    core.stars.set(&ctx, StarKind::Vm, &vmx("it-web"), true).await.unwrap();
    core.stars.opened(&ctx, RecentKind::Page, "dashboard").await.unwrap();
}

#[tokio::test]
async fn a_folders_note_goes_with_the_folder() {
    let core = core().await;
    let ctx = core.ctx();
    let folder = core.sessions.create_folder(&ctx, "Customer A", None).await.unwrap();
    core.notes
        .save(&ctx, &NoteTarget::folder(folder.id), note("Change window: Sundays."))
        .await
        .unwrap();
    core.sessions.delete_folder(&ctx, folder.id).await.unwrap();
    assert!(core.notes.list(&ctx).await.unwrap().is_empty());
    assert!(audit(&core).await[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("its note was deleted"));
}

// ---- QL-26 stars and recents ----------------------------------------------------------------------------------------

#[tokio::test]
async fn stars_and_recents_are_kept_per_workspace_and_not_audited() {
    let core = core().await;
    let ctx = core.ctx();
    let before = audit(&core).await.len();
    let web = core
        .sessions
        .create(&ctx, session("web01", "web01.example.com"))
        .await
        .unwrap();
    core.stars
        .set(&ctx, StarKind::Session, &web.id.to_string(), true)
        .await
        .unwrap();
    core.stars
        .set(&ctx, StarKind::Command, "library:disk.usage", true)
        .await
        .unwrap();
    let stars = core.stars.set(&ctx, StarKind::Vm, &vmx("it-web"), true).await.unwrap();
    assert_eq!(stars.len(), 3);
    let stars = core
        .stars
        .set(&ctx, StarKind::Command, "library:disk.usage", false)
        .await
        .unwrap();
    assert_eq!(stars.len(), 2);
    for n in 0..(MAX_RECENTS + 5) {
        core.stars
            .opened(&ctx, RecentKind::Page, &format!("page-{n}"))
            .await
            .unwrap();
    }
    let recents = core.stars.opened(&ctx, RecentKind::Vm, &vmx("it-web")).await.unwrap();
    assert_eq!(recents.len(), MAX_RECENTS);
    assert_eq!(recents[0].kind, RecentKind::Vm);
    assert_eq!(recents[1].key, format!("page-{}", MAX_RECENTS + 4));
    // Opening one again moves it to the top, once.
    let recents = core.stars.opened(&ctx, RecentKind::Page, "page-24").await.unwrap();
    assert_eq!(recents[0].key, "page-24");
    assert_eq!(recents.iter().filter(|r| r.key == "page-24").count(), 1);
    // Only the session's creation was audited.
    assert_eq!(audit(&core).await.len(), before + 1);
    assert!(core.stars.set(&ctx, StarKind::Session, " \n", true).await.is_err());
}

// ---- QL-27 the trash ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_deleted_session_comes_back_with_everything_that_hung_off_it() {
    let core = core().await;
    let ctx = core.ctx();
    let folder = core.sessions.create_folder(&ctx, "Customer A", None).await.unwrap();
    let mut input = session("web01", "web01.example.com");
    input.folder_id = Some(folder.id);
    input.tags = vec!["web".into(), "nginx".into()];
    let web = core.sessions.create(&ctx, input).await.unwrap();
    let other = core
        .sessions
        .create(&ctx, session("db01", "db01.example.com"))
        .await
        .unwrap();
    core.forwards
        .save(
            &ctx,
            web.id,
            &[ForwardInput {
                id: None,
                label: Some("admin".into()),
                kind: ForwardKind::Local,
                bind_address: "127.0.0.1".into(),
                bind_port: 8443,
                dest_host: "localhost".into(),
                dest_port: 443,
                auto_start: false,
            }],
        )
        .await
        .unwrap();
    core.containers
        .marks()
        .set(
            &ctx,
            web.id,
            &[MarkInput {
                engine: EngineKind::Docker,
                sudo: SudoMode::Off,
            }],
        )
        .await
        .unwrap();
    let group = core
        .groups
        .create(
            &ctx,
            GroupInput {
                name: "web servers".into(),
                session_ids: vec![other.id, web.id],
            },
        )
        .await
        .unwrap();
    core.notes
        .save(&ctx, &NoteTarget::session(web.id), note("Deploys on Fridays."))
        .await
        .unwrap();
    core.stars
        .set(&ctx, StarKind::Session, &web.id.to_string(), true)
        .await
        .unwrap();

    core.sessions.delete(&ctx, web.id).await.unwrap();
    assert!(core.sessions.get(&ctx, web.id).await.is_err());
    assert!(core.forwards.list(&ctx, web.id).await.unwrap().is_empty());
    assert_eq!(
        core.groups.get(&ctx, group.id).await.unwrap().session_ids(),
        vec![other.id]
    );
    assert!(core.notes.list(&ctx).await.unwrap().is_empty());
    let deleted = audit(&core).await.remove(0);
    assert!(deleted
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("moved to the trash for 30 days"));

    let trash = core.trash.list(&ctx).await.unwrap();
    assert_eq!(trash.len(), 1);
    assert_eq!(trash[0].kind, TrashKind::Session);
    assert_eq!(trash[0].name, "web01");
    assert_eq!(trash[0].place, "Sessions › Customer A");
    assert_eq!(
        trash[0].detail,
        "1 port forward, its container host mark, its place in 1 MultiExec group, its note"
    );

    let report = core.trash.restore(&ctx, trash[0].id, None).await.unwrap();
    assert_eq!(report.item_id, web.id.to_string());
    assert!(report.notes.is_empty(), "{:?}", report.notes);
    let back = core.sessions.get(&ctx, web.id).await.unwrap();
    assert_eq!(back.name, "web01");
    assert_eq!(back.folder_id, Some(folder.id));
    assert_eq!(back.tags, vec!["nginx".to_owned(), "web".to_owned()]);
    assert_eq!(core.forwards.list(&ctx, web.id).await.unwrap().len(), 1);
    assert_eq!(core.containers.marks().list(&ctx, Some(web.id)).await.unwrap().len(), 1);
    assert_eq!(
        core.groups.get(&ctx, group.id).await.unwrap().session_ids(),
        vec![other.id, web.id]
    );
    assert_eq!(
        core.notes
            .get(&ctx, &NoteTarget::session(web.id))
            .await
            .unwrap()
            .unwrap()
            .body,
        "Deploys on Fridays."
    );
    assert!(core
        .stars
        .list(&ctx)
        .await
        .unwrap()
        .iter()
        .any(|s| s.key == web.id.to_string()));
    assert!(core.trash.list(&ctx).await.unwrap().is_empty());
    let restored = audit(&core).await.remove(0);
    assert_eq!(restored.event, "trash_restored");
    assert_eq!(restored.action, "Restored the session 'web01'");
}

#[tokio::test]
async fn a_restore_takes_a_free_name_and_leaves_out_what_is_gone() {
    let core = core().await;
    let ctx = core.ctx();
    let folder = core.sessions.create_folder(&ctx, "Old", None).await.unwrap();
    let bastion = core
        .sessions
        .create(&ctx, session("bastion", "bastion.example.com"))
        .await
        .unwrap();
    let mut input = session("web01", "web01.example.com");
    input.folder_id = Some(folder.id);
    input.jump_session_id = Some(bastion.id);
    let web = core.sessions.create(&ctx, input).await.unwrap();
    core.sessions.delete(&ctx, web.id).await.unwrap();
    core.sessions.delete_folder(&ctx, folder.id).await.unwrap();
    core.sessions.delete(&ctx, bastion.id).await.unwrap();
    core.sessions
        .create(&ctx, session("web01", "web02.example.com"))
        .await
        .unwrap();

    // Undo, as a delete's toast does: the newest entry of that item.
    let report = core
        .trash
        .undo(&ctx, TrashKind::Session, &web.id.to_string(), None)
        .await
        .unwrap();
    assert_eq!(report.name, "web01 (restored)");
    let notes = report.notes.join(" | ");
    assert!(notes.contains("folder is gone"), "{notes}");
    assert!(notes.contains("jump host is gone"), "{notes}");
    let back = core.sessions.get(&ctx, web.id).await.unwrap();
    assert_eq!(back.folder_id, None);
    assert_eq!(back.jump_session_id, None);
    assert_eq!(
        core.trash.list(&ctx).await.unwrap().len(),
        1,
        "the bastion is still in the trash"
    );
}

#[tokio::test]
async fn a_restore_that_sends_a_vault_password_somewhere_new_asks_for_the_vault_password() {
    let core = core().await;
    let ctx = core.ctx();
    // Same place as before: it may send its password there again without asking.
    let password = secret(&core, "web root", "pw-value-2").await;
    let mut input = session("web01", "web01.example.com");
    input.auth = SessionAuth::Password {
        password_id: Some(password),
    };
    let web = core.sessions.create(&ctx, input).await.unwrap();
    core.sessions.delete(&ctx, web.id).await.unwrap();
    core.trash
        .undo(&ctx, TrashKind::Session, &web.id.to_string(), None)
        .await
        .unwrap();

    // Its jump host gone: the password would go straight to the host, where it never went.
    let bastion = core
        .sessions
        .create(&ctx, session("bastion", "bastion.example.com"))
        .await
        .unwrap();
    let other = secret(&core, "db root", "pw-value-3").await;
    let mut input = session("db01", "db01.example.com");
    input.auth = SessionAuth::Password {
        password_id: Some(other),
    };
    input.jump_session_id = Some(bastion.id);
    let db = core.sessions.create(&ctx, input).await.unwrap();
    core.sessions.delete(&ctx, db.id).await.unwrap();
    core.sessions.delete(&ctx, bastion.id).await.unwrap();
    let err = core
        .trash
        .undo(&ctx, TrashKind::Session, &db.id.to_string(), None)
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::ReauthRequired { .. }), "{err:?}");
    assert!(core.sessions.get(&ctx, db.id).await.is_err(), "nothing was restored");
    let report = core
        .trash
        .undo(
            &ctx,
            TrashKind::Session,
            &db.id.to_string(),
            Some(&SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    assert_eq!(report.name, "db01");
    assert!(audit(&core).await[0].detail.as_deref().unwrap_or("").contains("AP-06"));
}

#[tokio::test]
async fn the_trash_purges_after_thirty_days_and_can_be_emptied_but_not_while_presenting() {
    let core = core().await;
    let ctx = core.ctx();
    for name in ["a", "b", "c"] {
        let s = core
            .sessions
            .create(&ctx, session(name, &format!("{name}.example.com")))
            .await
            .unwrap();
        core.sessions.delete(&ctx, s.id).await.unwrap();
    }
    let trash = core.trash.list(&ctx).await.unwrap();
    assert_eq!(trash.len(), 3);
    sqlx::query("UPDATE trash SET deleted_at = '2026-01-01T00:00:00Z' WHERE id = ?")
        .bind(trash[2].id.to_string())
        .execute(core.store.pool())
        .await
        .unwrap();
    let purged = core.trash.purge().await.unwrap();
    assert_eq!(purged.removed, 1);
    assert_eq!(audit(&core).await[0].event, "trash_purged");
    assert_eq!(core.trash.list(&ctx).await.unwrap().len(), 2);

    core.presentation.set(LOCKED).await.unwrap();
    assert!(matches!(
        core.trash.restore(&ctx, trash[0].id, None).await.unwrap_err(),
        CoreError::ReadOnlyLock { .. }
    ));
    assert!(matches!(
        core.trash.empty(&ctx).await.unwrap_err(),
        CoreError::ReadOnlyLock { .. }
    ));
    core.presentation.set(UNLOCKED).await.unwrap();

    core.trash.delete_now(&ctx, trash[0].id).await.unwrap();
    assert_eq!(audit(&core).await[0].event, "trash_deleted");
    assert_eq!(core.trash.empty(&ctx).await.unwrap(), 1);
    assert_eq!(audit(&core).await[0].event, "trash_emptied");
    assert!(core.trash.list(&ctx).await.unwrap().is_empty());
}

fn write_image(label: &str) -> std::path::PathBuf {
    let dir = temp_folder(label);
    let path = dir.join("noble.vmdk");
    let mut bytes = vec![0u8; 0x8800];
    bytes[..4].copy_from_slice(b"KDMV");
    std::fs::File::create(&path).unwrap().write_all(&bytes).unwrap();
    path
}

#[tokio::test]
async fn sizes_images_templates_stacks_and_favourite_commands_come_back_under_their_own_ids() {
    let core = core().await;
    let ctx = core.ctx();
    let size = core
        .catalog
        .add_size(
            &ctx,
            SizeInput {
                name: "lab.web".into(),
                sockets: 1,
                cores_per_socket: 2,
                memory_mb: 4096,
                disks: vec![DiskSpec {
                    size_gb: 40,
                    provisioning: Provisioning::Thin,
                    controller: None,
                }],
                description: None,
            },
        )
        .await
        .unwrap();
    let progress: Arc<dyn Fn(HashProgress) + Send + Sync> = Arc::new(|_| {});
    let image = core
        .catalog
        .add_image(
            &ctx,
            Uuid::new_v4(),
            ImageInput {
                name: "Noble".into(),
                source: SourceInput::CloudImage {
                    path: write_image("trash-image").display().to_string(),
                },
                hypervisors: vec![],
                os_profile: "ubuntu".into(),
                notes: None,
            },
            progress,
        )
        .await
        .unwrap();
    let template = core
        .catalog
        .add_template(
            &ctx,
            TemplateInput {
                name: "web".into(),
                image_id: image.id,
                size_id: size.id.clone(),
                hypervisor: Hypervisor::Vmware,
                vm_folder: Some(temp_folder("trash-vms").display().to_string()),
                network: Network::Nat,
                ssh_key_id: None,
                naming_pattern: "web-{n}".into(),
                default_count: 1,
                environment: Environment::Lab,
                tags: vec![],
                after_deploy: AfterDeploy {
                    create_session: false,
                    link_session: false,
                    clean_snapshot: false,
                    open_console: false,
                },
                guest_user: None,
                packages: vec![],
                clone_mode: CloneMode::Full,
            },
        )
        .await
        .unwrap();
    let stack = core
        .stacks
        .add(
            &ctx,
            StackInput {
                name: "shop".into(),
                description: None,
                steps: vec![StackStep {
                    template_id: template.id,
                    count: 1,
                    readiness: Readiness::None,
                    ready_timeout_secs: 300,
                    delay_secs: 0,
                }],
            },
        )
        .await
        .unwrap();
    let command = core
        .snippets
        .add(
            &ctx,
            FavouriteInput {
                folder: Some("web".into()),
                name: "Reload nginx".into(),
                command: "sudo systemctl reload nginx".into(),
                description: None,
            },
        )
        .await
        .unwrap();

    core.stacks.delete(&ctx, stack.id).await.unwrap();
    core.catalog.delete_template(&ctx, template.id).await.unwrap();
    core.catalog.delete_size(&ctx, &size.id).await.unwrap();
    core.catalog.delete_image(&ctx, image.id).await.unwrap();
    core.snippets.delete(&ctx, command.id).await.unwrap();
    let trash = core.trash.list(&ctx).await.unwrap();
    let kinds: Vec<TrashKind> = trash.iter().map(|t| t.kind).collect();
    assert_eq!(
        kinds,
        vec![
            TrashKind::Command,
            TrashKind::Image,
            TrashKind::Size,
            TrashKind::Template,
            TrashKind::Stack
        ]
    );
    assert_eq!(trash[0].place, "Favourite commands › web");

    // The template first: its image and size are still in the trash, so it says so.
    let report = core
        .trash
        .undo(&ctx, TrashKind::Template, &template.id.to_string(), None)
        .await
        .unwrap();
    assert_eq!(report.notes.len(), 2, "{:?}", report.notes);
    core.trash
        .undo(&ctx, TrashKind::Image, &image.id.to_string(), None)
        .await
        .unwrap();
    core.trash.undo(&ctx, TrashKind::Size, &size.id, None).await.unwrap();
    let back = core.catalog.template(&ctx, template.id).await.unwrap();
    assert_eq!(back.spec.image_id, image.id);
    assert_eq!(back.spec.size_id, size.id);
    let report = core
        .trash
        .undo(&ctx, TrashKind::Stack, &stack.id.to_string(), None)
        .await
        .unwrap();
    assert!(report.notes.is_empty(), "its template is back: {:?}", report.notes);
    assert_eq!(core.stacks.get(&ctx, stack.id).await.unwrap().name, "shop");

    // A favourite command whose name was taken in its folder since.
    core.snippets
        .add(
            &ctx,
            FavouriteInput {
                folder: Some("web".into()),
                name: "Reload nginx".into(),
                command: "sudo nginx -s reload".into(),
                description: None,
            },
        )
        .await
        .unwrap();
    let report = core
        .trash
        .undo(&ctx, TrashKind::Command, &command.id.to_string(), None)
        .await
        .unwrap();
    assert_eq!(report.name, "Reload nginx (restored)");
    assert_eq!(core.snippets.favourites(&ctx).await.unwrap().len(), 2);
    assert!(core.trash.list(&ctx).await.unwrap().is_empty());
}

// ---- QL-28 bulk edit ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_bulk_edit_previews_then_changes_every_session_with_one_audit_entry() {
    let core = core().await;
    let ctx = core.ctx();
    let folder = core.sessions.create_folder(&ctx, "Customer A", None).await.unwrap();
    let bastion = core
        .sessions
        .create(&ctx, session("bastion", "bastion.example.com"))
        .await
        .unwrap();
    let mut first = session("web01", "web01.example.com");
    first.tags = vec!["old".into(), "web".into()];
    let a = core.sessions.create(&ctx, first).await.unwrap();
    let b = core
        .sessions
        .create(&ctx, session("web02", "web02.example.com"))
        .await
        .unwrap();
    let edit = BulkEdit {
        folder: Some(FolderChoice {
            folder_id: Some(folder.id),
        }),
        port: Some(2222),
        username: Some(UserChoice {
            username: Some("bob".into()),
        }),
        jump: Some(JumpChoice::Session { id: bastion.id }),
        environment: Some(Environment::Staging),
        tags_add: vec!["edge".into()],
        tags_remove: vec!["OLD".into()],
        ..BulkEdit::default()
    };
    let ids = [a.id, b.id];
    let preview = core.sessions.bulk_preview(&ctx, &ids, &edit).await.unwrap();
    assert_eq!(preview.changed, 2);
    let fields: Vec<&str> = preview.rows[0].changes.iter().map(|c| c.field.as_str()).collect();
    assert_eq!(
        fields,
        vec!["Folder", "Port", "User", "Jump host", "Environment", "Tags"]
    );
    let tags = preview.rows[0].changes.iter().find(|c| c.field == "Tags").unwrap();
    assert_eq!((tags.before.as_str(), tags.after.as_str()), ("old, web", "edge, web"));
    assert_eq!(
        core.sessions.get(&ctx, a.id).await.unwrap().port,
        22,
        "a preview saves nothing"
    );

    let before = audit(&core).await.len();
    core.sessions.bulk_edit(&ctx, &ids, &edit, None).await.unwrap();
    for id in ids {
        let s = core.sessions.get(&ctx, id).await.unwrap();
        assert_eq!(s.port, 2222);
        assert_eq!(s.folder_id, Some(folder.id));
        assert_eq!(s.username.as_deref(), Some("bob"));
        assert_eq!(s.jump_session_id, Some(bastion.id));
        assert_eq!(s.environment, Environment::Staging);
        assert!(s.tags.contains(&"edge".to_owned()));
        assert!(!s.tags.contains(&"old".to_owned()));
    }
    let entries = audit(&core).await;
    assert_eq!(entries.len(), before + 1, "one audit entry for the whole edit");
    assert_eq!(entries[0].action, "Changed 2 sessions at once");
    assert!(entries[0].targets_json.contains(&a.id.to_string()));
    assert!(entries[0].targets_json.contains(&b.id.to_string()));
    assert!(entries[0].detail.as_deref().unwrap_or("").contains("port -> 2222"));

    // An edit that leaves them as they are writes nothing.
    let again = core.sessions.bulk_edit(&ctx, &ids, &edit, None).await.unwrap();
    assert_eq!(again.changed, 0);
    assert_eq!(audit(&core).await.len(), before + 1);

    // A session can't be its own jump host, and the error names it.
    let loop_edit = BulkEdit {
        jump: Some(JumpChoice::Session { id: bastion.id }),
        ..BulkEdit::default()
    };
    let err = core
        .sessions
        .bulk_edit(&ctx, &[bastion.id], &loop_edit, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bastion"), "{err}");

    core.presentation.set(LOCKED).await.unwrap();
    assert!(matches!(
        core.sessions
            .bulk_edit(&ctx, &ids, &BulkEdit::default(), None)
            .await
            .unwrap_err(),
        CoreError::ReadOnlyLock { .. }
    ));
}

#[tokio::test]
async fn a_bulk_edit_that_sends_a_vault_password_somewhere_new_asks_once() {
    let core = core().await;
    let ctx = core.ctx();
    let password = secret(&core, "web root", "pw-value-4").await;
    let mut input = session("web01", "web01.example.com");
    input.auth = SessionAuth::Password {
        password_id: Some(password),
    };
    let a = core.sessions.create(&ctx, input).await.unwrap();
    let b = core
        .sessions
        .create(&ctx, session("web02", "web02.example.com"))
        .await
        .unwrap();
    // web02 would log in with web01's password, and web01 would send it to another port.
    let edit = BulkEdit {
        port: Some(2200),
        auth: Some(SessionAuth::Password {
            password_id: Some(password),
        }),
        ..BulkEdit::default()
    };
    let err = core
        .sessions
        .bulk_edit(&ctx, &[a.id, b.id], &edit, None)
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::ReauthRequired { .. }), "{err:?}");
    assert_eq!(
        core.sessions.get(&ctx, a.id).await.unwrap().port,
        22,
        "nothing was saved"
    );
    core.sessions
        .bulk_edit(&ctx, &[a.id, b.id], &edit, Some(&SecretString::new(VAULT_PASSWORD)))
        .await
        .unwrap();
    assert_eq!(core.sessions.get(&ctx, b.id).await.unwrap().port, 2200);
    assert!(audit(&core).await[0].detail.as_deref().unwrap_or("").contains("AP-06"));
}
