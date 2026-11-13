//! VM-32 (0.8.0 G6) address pools end to end, on the fakes: edits audited and refused by the read-only lock; picking
//! skips leased, reserved, excluded and answering addresses (FakeNetworkTools: no packet leaves this PC); two claims of
//! one address and only one wins; assign and release; a VM Remotely deletes frees its address; a pool with held
//! addresses can't be deleted. Addresses are from 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;

use common::{vm, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::address_pools::{AddressPoolInput, LeaseState};
use remotely_core::catalog::templates::Network;
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::fakes::{FakeNetworkTools, FakeVmware};
use remotely_core::jobs::{JobEvent, JobStatus};
use remotely_core::policy::ApprovalStep;
use remotely_core::presentation::Presentation;
use remotely_core::store::AuditEntry;
use remotely_core::vault::SecretString;
use remotely_core::vm_settings::VmLifecycleOp;
use remotely_core::Core;
use uuid::Uuid;

const WEB_VMX: &str = ".encoding = \"UTF-8\"\r\n\
config.version = \"8\"\r\n\
virtualHW.version = \"21\"\r\n\
displayName = \"web\"\r\n\
guestOS = \"ubuntu-64\"\r\n\
numvcpus = \"2\"\r\n\
memsize = \"4096\"\r\n\
scsi0.present = \"TRUE\"\r\n\
scsi0.virtualDev = \"pvscsi\"\r\n\
scsi0:0.present = \"TRUE\"\r\n\
scsi0:0.fileName = \"web.vmdk\"\r\n\
ethernet0.present = \"TRUE\"\r\n\
ethernet0.connectionType = \"nat\"\r\n\
ethernet0.virtualDev = \"vmxnet3\"\r\n\
ethernet0.addressType = \"generated\"\r\n";

fn ip(text: &str) -> Ipv4Addr {
    text.parse().unwrap()
}

fn pool(name: &str, first: &str, last: &str) -> AddressPoolInput {
    AddressPoolInput {
        name: name.into(),
        hypervisor: Hypervisor::Vmware,
        network: Network::Nat,
        first_ip: first.into(),
        last_ip: last.into(),
        prefix: 24,
        gateway: Some("192.0.2.1".into()),
        dns: vec!["192.0.2.53".into()],
        notes: None,
    }
}

/// A core whose pings are answered by `tools`. The fake answers every address it has no rule for, so a test makes the
/// addresses it wants free silent.
async fn core_with(tools: &Arc<FakeNetworkTools>, vmware: FakeVmware) -> Core {
    let core = Setup::new(vmware).with_network_tools(tools.clone()).build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    core
}

fn silent(tools: &FakeNetworkTools, from: u8, to: u8) {
    for n in from..=to {
        tools.set_silent(&format!("192.0.2.{n}"), true);
    }
}

async fn pool_audit(core: &Core) -> Vec<AuditEntry> {
    core.store
        .recent_audit(&core.ctx(), 200)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "address_pool_changed")
        .collect()
}

fn pinged(tools: &FakeNetworkTools) -> Vec<Ipv4Addr> {
    tools
        .echoes()
        .iter()
        .map(|e| match e.to {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => panic!("IPv4 only"),
        })
        .collect()
}

#[tokio::test]
async fn pools_are_added_changed_and_deleted_each_audited() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool(" lab ", "192.0.2.10", "192.0.2.50"))
        .await
        .unwrap();
    assert_eq!(lab.name, "lab");
    assert_eq!((lab.size, lab.usable, lab.used, lab.free), (41, 41, 0, 41));
    assert_eq!(lab.dns, [ip("192.0.2.53")]);

    // Names are unique without letter case, and two pools never share an address on one network.
    let err = core
        .address_pools
        .add(&ctx, pool("LAB", "192.0.2.60", "192.0.2.70"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("named 'lab' already"), "{err}");
    let err = core
        .address_pools
        .add(&ctx, pool("more", "192.0.2.50", "192.0.2.70"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("overlaps 'lab'"), "{err}");
    // The same range on another network is another network's.
    let mut host_only = pool("host-only", "192.0.2.10", "192.0.2.50");
    host_only.network = Network::HostOnly;
    let other = core.address_pools.add(&ctx, host_only).await.unwrap();

    let mut changed = pool("lab", "192.0.2.10", "192.0.2.60");
    changed.gateway = Some("192.0.2.10".into());
    let lab2 = core.address_pools.update(&ctx, lab.id, changed.clone()).await.unwrap();
    assert_eq!(
        (lab2.size, lab2.usable),
        (51, 49),
        "the gateway and DNS server in the range are never handed out"
    );
    // Unchanged: nothing written.
    let entries = pool_audit(&core).await.len();
    core.address_pools.update(&ctx, lab.id, changed).await.unwrap();
    assert_eq!(pool_audit(&core).await.len(), entries);

    assert_eq!(
        core.address_pools
            .pools_for(&ctx, Hypervisor::Vmware, &Network::Nat)
            .await
            .unwrap()
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>(),
        [lab.id]
    );
    assert!(core
        .address_pools
        .pools_for(&ctx, Hypervisor::VirtualBox, &Network::Nat)
        .await
        .unwrap()
        .is_empty());

    core.address_pools.delete(&ctx, other.id).await.unwrap();
    let names: Vec<String> = core
        .address_pools
        .list(&ctx)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, ["lab"]);

    let audit = pool_audit(&core).await;
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    for wanted in [
        "Added address pool 'lab'",
        "Added address pool 'host-only'",
        "Changed address pool 'lab'",
        "Deleted address pool 'host-only'",
    ] {
        assert!(actions.contains(&wanted), "{wanted} in {actions:?}");
    }
    let added = audit.iter().find(|e| e.action == "Added address pool 'lab'").unwrap();
    assert_eq!(
        added.detail.as_deref(),
        Some("Workstation, NAT, 192.0.2.10 to 192.0.2.50 /24, gateway 192.0.2.1, DNS 192.0.2.53")
    );
    assert!(audit.iter().all(|e| e.tier.is_none()), "no approval tier");
}

#[tokio::test]
async fn the_read_only_lock_refuses_every_pool_edit() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "gone", Uuid::new_v4())
        .await
        .unwrap_err(); // Every address answers by default.
    let before = pool_audit(&core).await.len();
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let refused = [
        core.address_pools
            .add(&ctx, pool("other", "192.0.2.30", "192.0.2.40"))
            .await
            .err(),
        core.address_pools
            .update(&ctx, lab.id, pool("renamed", "192.0.2.10", "192.0.2.20"))
            .await
            .err(),
        core.address_pools.delete(&ctx, lab.id).await.err(),
        core.address_pools.free(&ctx, lab.id, ip("192.0.2.10")).await.err(),
    ];
    for err in refused {
        assert_eq!(err.expect("refused").code(), "read_only_lock");
    }
    assert_eq!(pool_audit(&core).await.len(), before);
    // Reads go on.
    assert_eq!(core.address_pools.list(&ctx).await.unwrap().len(), 1);
}

#[tokio::test]
async fn pick_skips_leased_reserved_excluded_and_answering_addresses() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let mut input = pool("lab", "192.0.2.10", "192.0.2.20");
    input.gateway = Some("192.0.2.12".into());
    input.dns = vec!["192.0.2.13".into()];
    let lab = core.address_pools.add(&ctx, input).await.unwrap();
    assert_eq!(lab.usable, 9);
    silent(&tools, 10, 20);
    tools.set_silent("192.0.2.15", false); // Something answers there.
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "web-1", Uuid::new_v4())
        .await
        .unwrap();
    let before = tools.echoes().len();

    let picked = core
        .address_pools
        .pick(&ctx, lab.id, 3, &[ip("192.0.2.11")])
        .await
        .unwrap();
    let ips: Vec<Ipv4Addr> = picked.iter().map(|a| a.ip).collect();
    assert_eq!(ips, [ip("192.0.2.14"), ip("192.0.2.16"), ip("192.0.2.17")]);
    assert_eq!(picked[0].prefix, 24);
    assert_eq!(picked[0].gateway, Some(ip("192.0.2.12")));
    assert_eq!(picked[0].dns, [ip("192.0.2.13")]);
    assert_eq!(picked[0].pool_name, "lab");
    let asked = &pinged(&tools)[before..];
    for never in ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"] {
        assert!(!asked.contains(&ip(never)), "{never} was pinged: {asked:?}");
    }
    assert!(tools.echoes()[before..].iter().all(|e| e.timeout.as_secs() == 1));
    // A preview reserves nothing.
    assert_eq!(core.address_pools.leases(&ctx, lab.id).await.unwrap().len(), 1);
    assert_eq!(core.address_pools.pick(&ctx, lab.id, 0, &[]).await.unwrap(), []);

    // 11, 14 and 16 to 20 are free: 7 of the 8 not taken (15 answers); 9 is more than are not taken.
    let err = core
        .address_pools
        .pick(&ctx, lab.id, 8, &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Only 7 of the 8 addresses"), "{err}");
    assert!(err.contains("something answers on 1 more"), "{err}");
    let err = core
        .address_pools
        .pick(&ctx, lab.id, 9, &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("has 8 of its 9 addresses not taken"), "{err}");
}

#[tokio::test]
async fn of_two_claims_of_one_address_one_wins_and_an_answering_one_is_refused() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);

    let (a, b) = tokio::join!(
        core.address_pools
            .claim(&ctx, lab.id, ip("192.0.2.11"), "web-1", Uuid::new_v4()),
        core.address_pools
            .claim(&ctx, lab.id, ip("192.0.2.11"), "web-2", Uuid::new_v4()),
    );
    assert!(a.is_ok() != b.is_ok(), "one claim wins: {a:?} {b:?}");
    let lost = a.err().or(b.err()).unwrap().to_string();
    assert!(lost.contains("went to 'web-"), "{lost}");
    let won = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert_eq!(won.len(), 1);
    assert_eq!(won[0].state, LeaseState::Claimed);
    assert_eq!(won[0].vm_key, None);

    // Something answers now: refused, and the claim is undone.
    tools.set_silent("192.0.2.12", false);
    let err = core
        .address_pools
        .claim(&ctx, lab.id, ip("192.0.2.12"), "web-3", Uuid::new_v4())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("answers on 192.0.2.12"), "{err}");
    assert_eq!(core.address_pools.leases(&ctx, lab.id).await.unwrap().len(), 1);

    // Not the pool's to give.
    for (address, says) in [("192.0.2.21", "isn't in 'lab'"), ("198.51.100.10", "isn't in 'lab'")] {
        let err = core
            .address_pools
            .claim(&ctx, lab.id, ip(address), "web-4", Uuid::new_v4())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(says), "{err}");
    }
    let mut reserved = pool("lab", "192.0.2.10", "192.0.2.20");
    reserved.gateway = Some("192.0.2.13".into());
    core.address_pools.update(&ctx, lab.id, reserved).await.unwrap();
    let err = core
        .address_pools
        .claim(&ctx, lab.id, ip("192.0.2.13"), "web-4", Uuid::new_v4())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("gateway or DNS server"), "{err}");
}

#[tokio::test]
async fn a_claim_is_assigned_to_its_vm_or_released() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);
    let job = Uuid::new_v4();
    let got = core
        .address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "web-1", job)
        .await
        .unwrap();
    assert_eq!(got.ip, ip("192.0.2.10"));
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.11"), "web-2", job)
        .await
        .unwrap();

    core.address_pools
        .assign(&ctx, lab.id, ip("192.0.2.10"), r"C:\VMs\web-1\web-1.vmx")
        .await
        .unwrap();
    core.address_pools
        .release(&ctx, lab.id, ip("192.0.2.11"))
        .await
        .unwrap();
    let leases = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].state, LeaseState::Assigned);
    assert_eq!(leases[0].vm_key.as_deref(), Some(r"C:\VMs\web-1\web-1.vmx"));
    assert_eq!(leases[0].job_id, Some(job));
    let listed = core.address_pools.list(&ctx).await.unwrap();
    assert_eq!((listed[0].used, listed[0].free), (1, 10));
    // An address nobody claimed can't be a VM's.
    assert!(core
        .address_pools
        .assign(&ctx, lab.id, ip("192.0.2.12"), r"C:\VMs\x\x.vmx")
        .await
        .is_err());
    // The next pick goes on from the first address not taken.
    let next = core.address_pools.pick(&ctx, lab.id, 1, &[]).await.unwrap();
    assert_eq!(next[0].ip, ip("192.0.2.11"));
}

fn asked(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

#[tokio::test]
async fn a_deleted_vm_frees_its_address_and_a_pool_with_held_addresses_stays() {
    let tools = Arc::new(FakeNetworkTools::new());
    let fake = FakeVmware::default()
        .in_library(&vmx("web"), Some("web"))
        .with_vmx_text(&vmx("web"), WEB_VMX)
        .with_disk(r"C:\VMs\web\web.vmdk", 1024);
    let core = core_with(&tools, fake).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.15"), "web", Uuid::new_v4())
        .await
        .unwrap();
    // The key in another letter case is the same VM.
    core.address_pools
        .assign(&ctx, lab.id, ip("192.0.2.15"), &vmx("web").to_uppercase())
        .await
        .unwrap();

    let held = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert!(!held[0].can_free, "its VM is on the VMs page");
    let err = core.address_pools.delete(&ctx, lab.id).await.unwrap_err().to_string();
    assert!(err.contains("VMs hold addresses from 'lab': web"), "{err}");
    let err = core
        .address_pools
        .free(&ctx, lab.id, ip("192.0.2.15"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("deleting the VM frees it"), "{err}");
    let err = core
        .address_pools
        .update(&ctx, lab.id, pool("lab", "192.0.2.16", "192.0.2.20"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("192.0.2.15 is web's"), "{err}");
    let mut moved = pool("lab", "192.0.2.10", "192.0.2.20");
    moved.network = Network::HostOnly;
    let err = core
        .address_pools
        .update(&ctx, lab.id, moved)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("hypervisor and network stay"), "{err}");

    // Remotely deletes the VM: its address goes back, and the job says so.
    let mut rx = core.jobs.subscribe();
    let request = asked(
        core.bus
            .submit(
                &ctx,
                Command::VmLifecycle {
                    targets: vec![vm("web")],
                    op: VmLifecycleOp::Delete,
                },
            )
            .await
            .unwrap(),
    );
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("VM-32 test".into()),
        safety_snapshot: None,
        vault_password: request
            .steps
            .contains(&ApprovalStep::VaultReauth)
            .then(|| SecretString::new(VAULT_PASSWORD)),
        change_id: None,
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    let mut note = None;
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match rx.recv().await.unwrap() {
                JobEvent::TargetFinished { job_id, note: n, .. } if job_id == job => note = n,
                JobEvent::Finished { job_id, status, .. } if job_id == job => return status,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(status, JobStatus::Succeeded);
    assert!(
        note.as_deref()
            .unwrap_or_default()
            .contains("192.0.2.15 went back to the address pool 'lab'"),
        "{note:?}"
    );
    assert!(core.address_pools.leases(&ctx, lab.id).await.unwrap().is_empty());
    core.address_pools.delete(&ctx, lab.id).await.unwrap();
}

#[tokio::test]
async fn an_address_whose_vm_is_gone_is_freed_by_hand_and_old_claims_go_at_start() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);
    // A VM deleted in Workstation's own window: Remotely never lists it.
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "old", Uuid::new_v4())
        .await
        .unwrap();
    core.address_pools
        .assign(&ctx, lab.id, ip("192.0.2.10"), r"C:\VMs\old\old.vmx")
        .await
        .unwrap();
    // A claim whose deploy never ended.
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.11"), "web-1", Uuid::new_v4())
        .await
        .unwrap();
    let err = core.address_pools.delete(&ctx, lab.id).await.unwrap_err().to_string();
    assert!(err.contains("VMs hold addresses from 'lab': old."), "{err}");

    let leases = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert!(leases.iter().all(|l| l.can_free), "{leases:?}");
    core.address_pools.free(&ctx, lab.id, ip("192.0.2.10")).await.unwrap();
    let freed = pool_audit(&core)
        .await
        .into_iter()
        .find(|e| e.action == "Freed an address of address pool 'lab'")
        .expect("audited");
    assert_eq!(freed.detail.as_deref(), Some("192.0.2.10, which was old's (assigned)"));

    // A fresh claim stays; one a day old goes.
    assert_eq!(core.address_pools.release_stale_claims(&ctx).await.unwrap(), 0);
    sqlx::query("UPDATE address_leases SET created_at = '2026-01-01T00:00:00Z'")
        .execute(core.store.pool())
        .await
        .unwrap();
    assert_eq!(
        core.address_pools
            .release_stale_claims_everywhere(ctx.user_id)
            .await
            .unwrap(),
        1
    );
    assert!(core.address_pools.leases(&ctx, lab.id).await.unwrap().is_empty());
    let err = core.address_pools.delete(&ctx, Uuid::new_v4()).await.unwrap_err();
    assert_eq!(err.code(), "unknown_target");
    core.address_pools.delete(&ctx, lab.id).await.unwrap();
}
