use super::*;
use crate::adapters::vmware::VmxInfo;
use crate::domain::{Environment, Target, TargetRef};
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

#[tokio::test]
async fn running_vms_are_recorded_and_others_marked_not_running() {
    let (store, ctx) = store_with_identity().await;
    let vm = |path: &str, name: Option<&str>| DiscoveredVm {
        vmx_path: path.into(),
        info: VmxInfo {
            display_name: name.map(String::from),
            guest_os: Some("ubuntu-64".into()),
            num_vcpus: Some(2),
            memsize_mb: Some(4096),
        },
    };

    let first = store
        .record_running_vms(
            &ctx,
            &[vm(r"C:\VMs\web\web.vmx", Some("web")), vm(r"C:\VMs\db\db.vmx", None)],
        )
        .await
        .unwrap();
    assert_eq!(first.len(), 2);
    assert!(
        first.iter().any(|v| v.display_name == "db"),
        "falls back to the file name"
    );

    // Same VM, different path case: still one row (Windows paths are case-insensitive).
    let second = store
        .record_running_vms(&ctx, &[vm(r"c:\vms\WEB\web.vmx", Some("web"))])
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].power_state, "running");

    let all = store.list_vms(&ctx, None).await.unwrap();
    assert_eq!(all.len(), 2);
    let db = all.iter().find(|v| v.display_name == "db").unwrap();
    assert_eq!(db.power_state, "not_running");
}

#[tokio::test]
async fn settings_round_trip() {
    let (store, ctx) = store_with_identity().await;
    assert_eq!(store.get_setting::<u32>(&ctx, "x").await.unwrap(), None);
    store.put_setting(&ctx, "x", &7u32).await.unwrap();
    store.put_setting(&ctx, "x", &8u32).await.unwrap();
    assert_eq!(store.get_setting::<u32>(&ctx, "x").await.unwrap(), Some(8));
}
