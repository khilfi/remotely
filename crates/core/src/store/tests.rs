use super::*;
use crate::adapters::vmware::VmxInfo;
use crate::domain::{Environment, PowerState, Target, TargetRef};
use crate::error::CoreError;
use crate::inventory::VmFilter;
use crate::policy::Tier;

async fn store_with_identity() -> (Store, Context) {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\akiza", "Akiza").await.unwrap();
    (store, ctx)
}

fn entry<'a>(event: &'a str, targets: &'a [Target]) -> NewAuditEntry<'a> {
    NewAuditEntry {
        event,
        action: "Suspend 2 VMs",
        tier: Some(Tier::High),
        job_id: None,
        targets,
        approval: None,
        result: None,
        detail: None,
    }
}

fn target() -> Target {
    Target {
        target: TargetRef::Vm {
            vmx_path: r"C:\VMs\a\a.vmx".into(),
        },
        name: "a".into(),
        environment: Environment::Lab,
        protected: false,
    }
}

#[tokio::test]
async fn file_database_uses_wal() {
    let path = std::env::temp_dir().join(format!("remotely-test-{}.db", Uuid::new_v4()));
    let store = Store::open(&path).await.unwrap();
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(mode, "wal");
    store.pool().close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn identity_is_created_once() {
    let (store, first) = store_with_identity().await;
    let again = store.ensure_identity(r"lab\AKIZA", "Akiza").await.unwrap();
    assert_eq!(first, again, "account match is case-insensitive");
}

#[tokio::test]
async fn audit_chain_links_and_verifies() {
    let (store, ctx) = store_with_identity().await;
    let targets = [target()];
    let a = store
        .append_audit(&ctx, entry("approval_requested", &targets))
        .await
        .unwrap();
    let b = store
        .append_audit(&ctx, entry("approval_granted", &targets))
        .await
        .unwrap();
    let c = store.append_audit(&ctx, entry("job_started", &targets)).await.unwrap();

    assert_eq!(a.prev_hash, audit::GENESIS_HASH);
    assert_eq!(b.prev_hash, a.hash);
    assert_eq!(c.prev_hash, b.hash);
    assert_eq!(a.workspace_id, ctx.workspace_id.to_string());
    assert_eq!(a.user_id, ctx.user_id.to_string());

    let check = store.verify_audit_chain().await.unwrap();
    assert_eq!(
        check,
        ChainCheck {
            entries: 3,
            ok: true,
            first_bad_seq: None,
            problem: None
        }
    );
}

#[tokio::test]
async fn audit_log_refuses_update_and_delete() {
    let (store, ctx) = store_with_identity().await;
    let targets = [target()];
    store.append_audit(&ctx, entry("job_started", &targets)).await.unwrap();

    let update = sqlx::query("UPDATE audit_log SET result = 'ok'")
        .execute(store.pool())
        .await;
    assert!(update.unwrap_err().to_string().contains("append-only"));
    let delete = sqlx::query("DELETE FROM audit_log").execute(store.pool()).await;
    assert!(delete.unwrap_err().to_string().contains("append-only"));
}

#[tokio::test]
async fn verify_catches_edits_that_bypass_the_triggers() {
    let (store, ctx) = store_with_identity().await;
    let targets = [target()];
    for event in ["approval_requested", "approval_granted", "job_started", "job_finished"] {
        store.append_audit(&ctx, entry(event, &targets)).await.unwrap();
    }

    // Someone with the file drops the trigger and rewrites history.
    sqlx::query("DROP TRIGGER audit_log_no_update")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE audit_log SET result = 'nothing happened' WHERE seq = 3")
        .execute(store.pool())
        .await
        .unwrap();

    let check = store.verify_audit_chain().await.unwrap();
    assert!(!check.ok);
    assert_eq!(check.first_bad_seq, Some(3));
    assert_eq!(check.entries, 2, "entries before the bad one");
}

#[tokio::test]
async fn verify_catches_a_removed_entry() {
    let (store, ctx) = store_with_identity().await;
    let targets = [target()];
    for event in ["a", "b", "c"] {
        store.append_audit(&ctx, entry(event, &targets)).await.unwrap();
    }
    sqlx::query("DROP TRIGGER audit_log_no_delete")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_log WHERE seq = 2")
        .execute(store.pool())
        .await
        .unwrap();

    let check = store.verify_audit_chain().await.unwrap();
    assert!(!check.ok);
    assert_eq!(check.first_bad_seq, Some(3));
}

fn found(path: &str, name: &str, state: PowerState) -> DiscoveredVm {
    DiscoveredVm {
        vmx_path: path.into(),
        display_name: name.into(),
        info: VmxInfo {
            display_name: Some(name.into()),
            guest_os: Some("ubuntu-64".into()),
            guest_os_name: Some("Ubuntu 24.04 LTS".into()),
            num_vcpus: Some(2),
            memsize_mb: Some(4096),
            suspended: state == PowerState::Suspended,
        },
        power_state: state,
        tools_state: state.is_on().then(|| "running".to_owned()),
        ip_address: state.is_on().then(|| "192.0.2.20".to_owned()),
    }
}

#[tokio::test]
async fn refreshes_record_every_vm_and_hide_ones_no_longer_found() {
    let (store, ctx) = store_with_identity().await;
    store
        .record_inventory(
            &ctx,
            &[
                found(r"C:\VMs\web\web.vmx", "web", PowerState::Running),
                found(r"C:\VMs\db\db.vmx", "db", PowerState::NotRunning),
            ],
        )
        .await
        .unwrap();
    let all = store.list_vms(&ctx).await.unwrap();
    assert_eq!(all.len(), 2);
    let web = all.iter().find(|v| v.display_name == "web").unwrap();
    assert_eq!(web.power_state, PowerState::Running);
    assert_eq!(web.ip_address.as_deref(), Some("192.0.2.20"));
    assert_eq!(web.guest_os_name.as_deref(), Some("Ubuntu 24.04 LTS"));

    // Same VM, different path case: still one row (Windows paths are case-insensitive). db is gone.
    store
        .record_inventory(&ctx, &[found(r"c:\vms\WEB\web.vmx", "web", PowerState::Suspended)])
        .await
        .unwrap();
    let now = store.list_vms(&ctx).await.unwrap();
    assert_eq!(now.len(), 1);
    assert_eq!(now[0].power_state, PowerState::Suspended);
    assert_eq!(now[0].ip_address, None);

    // The missing VM keeps its row, so protection and tags come back with it.
    let db = store.find_vm(&ctx, r"C:\VMs\db\db.vmx").await.unwrap().unwrap();
    assert_eq!(db.display_name, "db");
    store
        .record_inventory(&ctx, &[found(r"C:\VMs\db\db.vmx", "db", PowerState::NotRunning)])
        .await
        .unwrap();
    assert_eq!(store.list_vms(&ctx).await.unwrap()[0].id, db.id);
}

#[tokio::test]
async fn a_paused_vm_stays_paused_while_vmrun_lists_it_as_running() {
    let (store, ctx) = store_with_identity().await;
    let path = r"C:\VMs\web\web.vmx";
    store
        .record_inventory(&ctx, &[found(path, "web", PowerState::Running)])
        .await
        .unwrap();
    store.set_vm_power_state(&ctx, path, PowerState::Paused).await.unwrap();

    let mut again = found(path, "web", PowerState::Running);
    again.ip_address = None;
    again.tools_state = None;
    store.record_inventory(&ctx, &[again]).await.unwrap();
    let vm = store.find_vm(&ctx, path).await.unwrap().unwrap();
    assert_eq!(vm.power_state, PowerState::Paused);
    assert_eq!(vm.ip_address.as_deref(), Some("192.0.2.20"), "keeps the last IP");

    store
        .set_vm_power_state(&ctx, path, PowerState::NotRunning)
        .await
        .unwrap();
    let vm = store.find_vm(&ctx, path).await.unwrap().unwrap();
    assert_eq!(vm.power_state, PowerState::NotRunning);
    assert_eq!(vm.ip_address, None, "an off VM has no IP");
    assert_eq!(vm.tools_state, None);
}

#[tokio::test]
async fn settings_round_trip() {
    let (store, ctx) = store_with_identity().await;
    assert_eq!(store.get_setting::<u32>(&ctx, "x").await.unwrap(), None);
    store.put_setting(&ctx, "x", &7u32).await.unwrap();
    store.put_setting(&ctx, "x", &8u32).await.unwrap();
    assert_eq!(store.get_setting::<u32>(&ctx, "x").await.unwrap(), Some(8));
}

// ---- VM-02: tags and saved filters -------------------------------------------------------------

#[tokio::test]
async fn tags_attach_to_vms_without_regard_to_letter_case() {
    let (store, ctx) = store_with_identity().await;
    let web = r"C:\VMs\web\web.vmx".to_owned();
    let db = r"C:\VMs\db\db.vmx".to_owned();
    store
        .record_inventory(
            &ctx,
            &[
                found(&web, "web", PowerState::Running),
                found(&db, "db", PowerState::NotRunning),
            ],
        )
        .await
        .unwrap();

    store
        .tag_vms(&ctx, &[web.clone(), db.clone()], " lab-a ")
        .await
        .unwrap();
    store.tag_vms(&ctx, std::slice::from_ref(&web), "LAB-A").await.unwrap();
    store
        .tag_vms(&ctx, std::slice::from_ref(&web), "frontend")
        .await
        .unwrap();

    let tags = store.list_tags(&ctx).await.unwrap();
    let summary: Vec<_> = tags.iter().map(|t| (t.name.as_str(), t.vm_count)).collect();
    assert_eq!(summary, [("frontend", 1), ("lab-a", 2)], "one lab-a tag, trimmed");
    let web_tags = store.find_vm(&ctx, &web).await.unwrap().unwrap().tags;
    assert_eq!(web_tags, ["frontend", "lab-a"]);

    // Removing a tag from its last VM deletes the tag.
    store
        .untag_vms(&ctx, std::slice::from_ref(&web), "Frontend")
        .await
        .unwrap();
    let names: Vec<_> = store
        .list_tags(&ctx)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(names, ["lab-a"]);

    store.delete_tag(&ctx, "lab-a").await.unwrap();
    assert!(store.list_tags(&ctx).await.unwrap().is_empty());
    assert!(store.find_vm(&ctx, &db).await.unwrap().unwrap().tags.is_empty());
}

#[tokio::test]
async fn tag_names_are_checked_and_vms_must_be_known() {
    let (store, ctx) = store_with_identity().await;
    let web = r"C:\VMs\web\web.vmx".to_owned();
    store
        .record_inventory(&ctx, &[found(&web, "web", PowerState::Running)])
        .await
        .unwrap();
    for bad in ["", "   ", "tab\there", &"x".repeat(41)] {
        let err = store.tag_vms(&ctx, std::slice::from_ref(&web), bad).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)), "{bad:?}");
    }
    let unknown = store
        .tag_vms(&ctx, &[r"C:\VMs\nope\nope.vmx".to_owned()], "lab")
        .await
        .unwrap_err();
    assert!(matches!(unknown, CoreError::UnknownTarget(_)));
    assert!(
        store.list_tags(&ctx).await.unwrap().is_empty(),
        "nothing saved on failure"
    );
}

#[tokio::test]
async fn saved_filters_round_trip_and_replace_by_name() {
    let (store, ctx) = store_with_identity().await;
    let lab = VmFilter {
        tags: vec!["lab-a".into()],
        power_states: vec![PowerState::NotRunning],
        ..Default::default()
    };
    let saved = store.save_filter(&ctx, "Lab A, off", &lab).await.unwrap();
    assert_eq!(saved.filter, lab);

    let prod = VmFilter {
        environments: vec![Environment::Prod],
        ..Default::default()
    };
    let replaced = store.save_filter(&ctx, "Lab A, off", &prod).await.unwrap();
    assert_eq!(replaced.id, saved.id, "same name replaces");
    store
        .save_filter(&ctx, "Everything", &VmFilter::default())
        .await
        .unwrap();

    let all = store.list_saved_filters(&ctx).await.unwrap();
    let names: Vec<_> = all.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["Everything", "Lab A, off"]);
    assert_eq!(all[1].filter, prod);

    store.delete_saved_filter(&ctx, &saved.id).await.unwrap();
    assert_eq!(store.list_saved_filters(&ctx).await.unwrap().len(), 1);
    assert!(store.save_filter(&ctx, " ", &prod).await.is_err());
}
