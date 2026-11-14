//! VM-32 (0.8.0 G6) address pools end to end, on the fakes: edits audited and refused by the read-only lock; one network
//! of this PC under two names is one network (Workstation's NAT and its vmnet, VirtualBox's host-only adapters by name);
//! picking skips held, reserved, excluded and answering addresses (a ping reply, "unreachable" from the address itself,
//! an ARP answer), skips and counts one it couldn't check, and is kept a few seconds; nothing is picked or claimed on a
//! subnet this PC has no adapter on; two claims of one address and only one wins; a claim dropped mid-check, or whose
//! job ended, holds nothing; assign and release take only the job's own claim; a VM Remotely deletes frees its address;
//! a pool with held addresses can't be deleted. FakeNetworkTools: no packet leaves this PC. Addresses are from
//! 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 198.18.0.0/15 only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use common::{vm, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::host_networks::VmnetKind;
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::address_pools::{AddressPoolInput, LeaseState, PICK_FRESH};
use remotely_core::catalog::templates::Network;
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::domain::Context;
use remotely_core::fakes::{FakeNetworkTools, FakeVirtualBox, FakeVmware};
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
        host_adapter: None,
        first_ip: first.into(),
        last_ip: last.into(),
        prefix: 24,
        gateway: Some("192.0.2.1".into()),
        dns: vec!["192.0.2.53".into()],
        notes: None,
    }
}

/// This PC with Workstation's NAT host adapter on 192.0.2.0/24. The fake answers every ping it has no rule for, so a
/// test makes the addresses it wants free silent.
fn tools() -> Arc<FakeNetworkTools> {
    Arc::new(FakeNetworkTools::new().with_adapter("VMware Network Adapter VMnet8", "192.0.2.1", 24, &[]))
}

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

/// A deploy job's row, running: its claims hold their addresses.
async fn open_job(core: &Core, ctx: &Context) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO jobs (id, workspace_id, user_id, summary, action, tier, command_json, status, created_at)
         VALUES (?, ?, ?, 'Deploy', 'vm_deploy', 'medium', '{}', 'running', '2026-11-14T00:00:00Z')",
    )
    .bind(id.to_string())
    .bind(ctx.workspace_id.0.to_string())
    .bind(ctx.user_id.0.to_string())
    .execute(core.store.pool())
    .await
    .unwrap();
    id
}

async fn end_job(core: &Core, id: Uuid) {
    sqlx::query("UPDATE jobs SET status = 'cancelled' WHERE id = ?")
        .bind(id.to_string())
        .execute(core.store.pool())
        .await
        .unwrap();
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

fn ips(addresses: &[remotely_core::address_pools::PoolAddress]) -> Vec<Ipv4Addr> {
    addresses.iter().map(|a| a.ip).collect()
}

#[tokio::test]
async fn pools_are_added_changed_and_deleted_each_audited() {
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool(" lab ", "192.0.2.10", "192.0.2.50"))
        .await
        .unwrap();
    assert_eq!(lab.name, "lab");
    assert_eq!(
        (lab.size, lab.usable, lab.used, lab.held_elsewhere, lab.free),
        (41, 41, 0, 0, 41)
    );
    assert_eq!(lab.dns, [ip("192.0.2.53")]);

    // Names are unique without letter case (beyond ASCII too), and two pools never share an address on one network.
    let err = core
        .address_pools
        .add(&ctx, pool("LAB", "192.0.2.60", "192.0.2.70"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("named 'lab' already"), "{err}");
    core.address_pools
        .add(&ctx, pool("Läb", "192.0.2.60", "192.0.2.70"))
        .await
        .unwrap();
    let err = core
        .address_pools
        .add(&ctx, pool("LÄB", "192.0.2.80", "192.0.2.90"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("named 'Läb' already"), "{err}");
    let err = core
        .address_pools
        .add(&ctx, pool("more", "192.0.2.50", "192.0.2.55"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("overlaps 'lab'"), "{err}");
    // The same range on another network of this PC is that network's.
    let mut host_only = pool("host-only", "192.0.2.10", "192.0.2.50");
    host_only.network = Network::HostOnly;
    let other = core.address_pools.add(&ctx, host_only).await.unwrap();

    let mut changed = pool("lab", "192.0.2.10", "192.0.2.59");
    changed.gateway = Some("192.0.2.10".into());
    let lab2 = core.address_pools.update(&ctx, lab.id, changed.clone()).await.unwrap();
    assert_eq!(
        (lab2.size, lab2.usable),
        (50, 48),
        "the gateway and DNS server in the range are never handed out"
    );
    // Unchanged: nothing written.
    let entries = pool_audit(&core).await.len();
    core.address_pools.update(&ctx, lab.id, changed).await.unwrap();
    assert_eq!(pool_audit(&core).await.len(), entries);

    let nat: Vec<String> = core
        .address_pools
        .pools_for(&ctx, Hypervisor::Vmware, &Network::Nat)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(nat, ["lab", "Läb"]);
    assert!(core
        .address_pools
        .pools_for(&ctx, Hypervisor::VirtualBox, &Network::Bridged)
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
    assert_eq!(names, ["lab", "Läb"]);

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
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
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
async fn one_network_of_this_pc_under_two_names_is_one_network() {
    // Workstation's NAT is vmnet8 here, its host-only network vmnet1; this PC has adapters on both.
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_adapter("VMware Network Adapter VMnet8", "192.0.2.1", 24, &[])
            .with_adapter("VMware Network Adapter VMnet1", "198.51.100.1", 24, &[]),
    );
    let vmware = FakeVmware::default()
        .with_vmnet(1, VmnetKind::HostOnly, "198.51.100.0")
        .with_vmnet(8, VmnetKind::Nat, "192.0.2.0");
    let core = core_with(&tools, vmware).await;
    let ctx = core.ctx();
    let with = |name: &str, network: Network, first: &str, last: &str| {
        let mut input = pool(name, first, last);
        input.network = network;
        input.gateway = None;
        input.dns = vec![];
        input
    };
    let nat = core
        .address_pools
        .add(&ctx, with("nat", Network::Nat, "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    for (name, network, first, last, other) in [
        (
            "vmnet8",
            Network::Vmnet { number: 8 },
            "192.0.2.15",
            "192.0.2.25",
            "nat",
        ),
        (
            "vmnet1",
            Network::Vmnet { number: 1 },
            "198.51.100.15",
            "198.51.100.25",
            "host-only",
        ),
        (
            "vmnet0",
            Network::Vmnet { number: 0 },
            "203.0.113.15",
            "203.0.113.25",
            "bridged",
        ),
    ] {
        if other != "nat" {
            let network = if other == "host-only" {
                Network::HostOnly
            } else {
                Network::Bridged
            };
            let first_of_other = first.replace(".15", ".10");
            let last_of_other = last.replace(".25", ".20");
            core.address_pools
                .add(&ctx, with(other, network, &first_of_other, &last_of_other))
                .await
                .unwrap();
        }
        let err = core
            .address_pools
            .add(&ctx, with(name, network, first, last))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(&format!("overlaps '{other}'")), "{name}: {err}");
    }
    // The NAT network is vmnet8's subnet, so a range elsewhere is refused.
    let err = core
        .address_pools
        .add(
            &ctx,
            with("far", Network::Vmnet { number: 8 }, "203.0.113.30", "203.0.113.40"),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("NAT (vmnet8) is on 192.0.2.0/24"), "{err}");
    let vmnet8 = core
        .address_pools
        .add(
            &ctx,
            with("vmnet8", Network::Vmnet { number: 8 }, "192.0.2.30", "192.0.2.40"),
        )
        .await
        .unwrap();
    // A deploy on either name is offered both.
    let offered: Vec<Uuid> = core
        .address_pools
        .pools_for(&ctx, Hypervisor::Vmware, &Network::Vmnet { number: 8 })
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert_eq!(offered, [nat.id, vmnet8.id]);
}

#[tokio::test]
async fn virtualbox_host_only_pools_name_their_adapter() {
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_adapter("VirtualBox Host-Only Network", "203.0.113.1", 24, &[])
            .with_adapter("VirtualBox Host-Only Network #2", "198.51.100.1", 24, &[]),
    );
    let core = Setup::new(FakeVmware::default())
        .with_virtualbox(
            FakeVirtualBox::new()
                .with_host_only("vboxnet0", "203.0.113.1")
                .with_host_only("vboxnet1", "198.51.100.1"),
        )
        .with_network_tools(tools.clone())
        .build()
        .await;
    let ctx = core.ctx();
    let vbox = |name: &str, network: Network, adapter: Option<&str>, first: &str, last: &str| AddressPoolInput {
        name: name.into(),
        hypervisor: Hypervisor::VirtualBox,
        network,
        host_adapter: adapter.map(str::to_owned),
        first_ip: first.into(),
        last_ip: last.into(),
        prefix: 24,
        gateway: None,
        dns: vec![],
        notes: None,
    };
    let zero = core
        .address_pools
        .add(
            &ctx,
            vbox(
                "zero",
                Network::HostOnly,
                Some("vboxnet0"),
                "203.0.113.10",
                "203.0.113.20",
            ),
        )
        .await
        .unwrap();
    assert_eq!(zero.host_adapter.as_deref(), Some("vboxnet0"));
    let one = core
        .address_pools
        .add(
            &ctx,
            vbox(
                "one",
                Network::HostOnly,
                Some("vboxnet1"),
                "198.51.100.10",
                "198.51.100.20",
            ),
        )
        .await
        .unwrap();
    for (input, says) in [
        (
            vbox("none", Network::HostOnly, None, "203.0.113.30", "203.0.113.40"),
            "Pick VirtualBox's host-only adapter",
        ),
        (
            vbox(
                "gone",
                Network::HostOnly,
                Some("vboxnet7"),
                "203.0.113.30",
                "203.0.113.40",
            ),
            "no host-only adapter named 'vboxnet7'",
        ),
        (
            vbox(
                "off",
                Network::HostOnly,
                Some("vboxnet0"),
                "198.51.100.30",
                "198.51.100.40",
            ),
            "is on 203.0.113.0/24",
        ),
        (
            vbox("nat", Network::Nat, None, "203.0.113.30", "203.0.113.40"),
            "This PC has no adapter on VirtualBox's NAT",
        ),
        (
            vbox(
                "natnet",
                Network::NatNetwork { name: "lab".into() },
                None,
                "203.0.113.30",
                "203.0.113.40",
            ),
            "This PC has no adapter on VirtualBox's NAT network 'lab'",
        ),
        (
            vbox(
                "int",
                Network::Internal { name: "lab".into() },
                None,
                "203.0.113.30",
                "203.0.113.40",
            ),
            "This PC has no adapter on VirtualBox's internal network 'lab'",
        ),
    ] {
        let err = core.address_pools.add(&ctx, input).await.unwrap_err().to_string();
        assert!(err.contains(says), "{says}: {err}");
    }
    // A deploy names its adapter; without one, no host-only pool is offered.
    let ids =
        |pools: Vec<remotely_core::address_pools::AddressPool>| pools.into_iter().map(|p| p.id).collect::<Vec<_>>();
    assert!(core
        .address_pools
        .pools_for(&ctx, Hypervisor::VirtualBox, &Network::HostOnly)
        .await
        .unwrap()
        .is_empty());
    for (adapter, wanted) in [("vboxnet0", zero.id), ("VBOXNET1", one.id)] {
        let offered = core
            .address_pools
            .pools_for_adapter(&ctx, Hypervisor::VirtualBox, &Network::HostOnly, Some(adapter))
            .await
            .unwrap();
        assert_eq!(ids(offered), [wanted], "{adapter}");
    }
}

#[tokio::test]
async fn pick_skips_held_reserved_excluded_and_answering_addresses_and_counts_unchecked_ones() {
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let mut input = pool("lab", "192.0.2.10", "192.0.2.20");
    input.gateway = Some("192.0.2.12".into());
    input.dns = vec!["192.0.2.13".into()];
    let lab = core.address_pools.add(&ctx, input).await.unwrap();
    assert_eq!(lab.usable, 9);
    silent(&tools, 10, 20);
    tools.set_silent("192.0.2.15", false); // Something answers pings there.
    tools.set_arp_host("192.0.2.16", true); // A Windows guest: no pings, but it answers ARP.
    tools.set_refusing("192.0.2.17", true); // A host that says "protocol unreachable" itself.
    tools.set_echo_error("192.0.2.18", true); // Windows couldn't send that ping.
    let job = open_job(&core, &ctx).await;
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "web-1", job)
        .await
        .unwrap();
    let before = tools.echoes().len();

    let picked = core
        .address_pools
        .pick(&ctx, lab.id, 3, &[ip("192.0.2.11")])
        .await
        .unwrap();
    assert_eq!(ips(&picked), [ip("192.0.2.14"), ip("192.0.2.19"), ip("192.0.2.20")]);
    assert_eq!(picked[0].prefix, 24);
    assert_eq!(picked[0].gateway, Some(ip("192.0.2.12")));
    assert_eq!(picked[0].dns, [ip("192.0.2.13")]);
    assert_eq!(picked[0].pool_name, "lab");
    let asked: Vec<Ipv4Addr> = tools.echoes()[before..]
        .iter()
        .map(|e| match e.to {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => panic!("IPv4 only"),
        })
        .collect();
    for never in ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"] {
        assert!(!asked.contains(&ip(never)), "{never} was pinged: {asked:?}");
    }
    assert!(tools.echoes()[before..]
        .iter()
        .all(|e| e.timeout == Duration::from_secs(1)));
    assert!(tools.arps().contains(&ip("192.0.2.16")), "ARP was asked as well");

    // The same question within a few seconds is answered again without a ping (the Deploy dialog's checks).
    let pinged = tools.echoes().len();
    let again = core
        .address_pools
        .pick(&ctx, lab.id, 3, &[ip("192.0.2.11")])
        .await
        .unwrap();
    assert_eq!(again, picked);
    assert_eq!(tools.echoes().len(), pinged, "kept for {PICK_FRESH:?}");
    // A preview reserves nothing.
    assert_eq!(core.address_pools.leases(&ctx, lab.id).await.unwrap().len(), 1);
    assert_eq!(core.address_pools.pick(&ctx, lab.id, 0, &[]).await.unwrap(), []);

    // 11, 14, 19 and 20 are free: 4 of the 8 not taken (15, 16 and 17 in use, 18 unchecked).
    assert_eq!(core.address_pools.pick(&ctx, lab.id, 4, &[]).await.unwrap().len(), 4);
    let err = core
        .address_pools
        .pick(&ctx, lab.id, 5, &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Only 4 of the 5 addresses"), "{err}");
    assert!(err.contains("1 of its 9 addresses are taken"), "{err}");
    assert!(
        err.contains("something answers on 3 more, and 1 couldn't be checked"),
        "{err}"
    );
    let err = core
        .address_pools
        .pick(&ctx, lab.id, 9, &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("has 8 of its 9 addresses not taken"), "{err}");
    // A claim forgets what was picked.
    let echoes = tools.echoes().len();
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.11"), "web-2", job)
        .await
        .unwrap();
    core.address_pools
        .pick(&ctx, lab.id, 3, &[ip("192.0.2.11")])
        .await
        .unwrap();
    assert!(tools.echoes().len() > echoes + 1);
    // Held addresses, for the approval of a deploy that picked them.
    let held = core
        .address_pools
        .held_now(&ctx, lab.id, &[ip("192.0.2.10"), ip("192.0.2.14")], None)
        .await
        .unwrap();
    assert_eq!(held, [ip("192.0.2.10")]);
    assert!(core
        .address_pools
        .held_now(&ctx, lab.id, &[ip("192.0.2.10")], Some(job))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_pick_checks_as_many_addresses_at_once_as_it_may_need() {
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.49"))
        .await
        .unwrap();
    silent(&tools, 10, 49);
    // A ping times out after a while, and SendARP waits for its retries when nothing answers.
    tools.set_echo_delay(Duration::from_millis(300));
    tools.set_arp_delay(Duration::from_millis(600));
    let started = std::time::Instant::now();
    let picked = core.address_pools.pick(&ctx, lab.id, 20, &[]).await.unwrap();
    let took = started.elapsed();
    assert_eq!(picked.len(), 20);
    assert_eq!((picked[0].ip, picked[19].ip), (ip("192.0.2.10"), ip("192.0.2.29")));
    assert!(
        took < Duration::from_millis(1500),
        "about one check's time (600 ms), not one per batch of addresses: {took:?}"
    );
    assert_eq!(tools.arps().len(), 20, "no more checks than it needed");
    assert_eq!(tools.echoes().len(), 20);

    // Addresses in use make it check the next ones as their answers come back; the lowest free ones are still taken.
    tools.set_silent("192.0.2.12", false);
    tools.set_arp_host("192.0.2.15", true);
    let picked = core.address_pools.pick(&ctx, lab.id, 5, &[]).await.unwrap();
    assert_eq!(
        ips(&picked),
        ["192.0.2.10", "192.0.2.11", "192.0.2.13", "192.0.2.14", "192.0.2.16"].map(ip)
    );
}

#[tokio::test]
async fn nothing_is_picked_or_claimed_on_a_subnet_this_pc_has_no_adapter_on() {
    // This PC has an adapter on 198.51.100.0/24 only: a ping to 192.0.2.x would leave through another network.
    let tools = Arc::new(FakeNetworkTools::new().with_adapter("Ethernet", "198.51.100.7", 24, &[]));
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);
    let job = open_job(&core, &ctx).await;
    for err in [
        core.address_pools.pick(&ctx, lab.id, 1, &[]).await.unwrap_err(),
        core.address_pools
            .claim(&ctx, lab.id, ip("192.0.2.10"), "web-1", job)
            .await
            .unwrap_err(),
    ] {
        assert!(
            err.to_string()
                .contains("This PC has no network adapter on 192.0.2.0/24, the subnet of 'lab'"),
            "{err}"
        );
    }
    assert!(tools.echoes().is_empty(), "no ping went anywhere");
    assert!(tools.arps().is_empty());
    assert!(core.address_pools.leases(&ctx, lab.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn of_two_claims_of_one_address_one_wins_and_an_answering_or_unchecked_one_is_refused() {
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);
    let (a, b) = (open_job(&core, &ctx).await, open_job(&core, &ctx).await);

    let (first, second) = tokio::join!(
        core.address_pools.claim(&ctx, lab.id, ip("192.0.2.11"), "web-1", a),
        core.address_pools.claim(&ctx, lab.id, ip("192.0.2.11"), "web-2", b),
    );
    assert!(first.is_ok() != second.is_ok(), "one claim wins: {first:?} {second:?}");
    let lost = first.err().or(second.err()).unwrap().to_string();
    assert!(lost.contains("went to 'web-"), "{lost}");
    let won = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert_eq!(won.len(), 1);
    assert_eq!(won[0].state, LeaseState::Claimed);
    assert_eq!(won[0].vm_key, None);
    assert!(!won[0].can_free, "its deploy runs");

    // Something there now: refused, and the claim is undone.
    for (address, rule) in [
        ("192.0.2.12", "ping"),
        ("192.0.2.13", "arp"),
        ("192.0.2.14", "refusing"),
    ] {
        match rule {
            "ping" => tools.set_silent(address, false),
            "arp" => tools.set_arp_host(address, true),
            _ => tools.set_refusing(address, true),
        }
        let err = core
            .address_pools
            .claim(&ctx, lab.id, ip(address), "web-3", b)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(&format!("answers on {address}")), "{rule}: {err}");
    }
    // Not checked: refused too.
    tools.set_echo_error("192.0.2.15", true);
    let err = core
        .address_pools
        .claim(&ctx, lab.id, ip("192.0.2.15"), "web-3", b)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "network");
    assert!(
        err.to_string().contains("couldn't check that 192.0.2.15 is free"),
        "{err}"
    );
    assert_eq!(core.address_pools.leases(&ctx, lab.id).await.unwrap().len(), 1);

    // Not the pool's to give.
    for (address, says) in [("192.0.2.21", "isn't in 'lab'"), ("198.51.100.10", "isn't in 'lab'")] {
        let err = core
            .address_pools
            .claim(&ctx, lab.id, ip(address), "web-4", b)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(says), "{err}");
    }
    let mut reserved = pool("lab", "192.0.2.10", "192.0.2.20");
    reserved.gateway = Some("192.0.2.16".into());
    core.address_pools.update(&ctx, lab.id, reserved).await.unwrap();
    let err = core
        .address_pools
        .claim(&ctx, lab.id, ip("192.0.2.16"), "web-4", b)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("gateway or DNS server"), "{err}");
}

#[tokio::test]
async fn a_claim_whose_deploy_ended_or_was_dropped_mid_check_holds_nothing() {
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);

    // The job's cancel drops the claim while it pings: its row goes with it.
    tools.set_echo_delay(Duration::from_millis(500));
    let job = open_job(&core, &ctx).await;
    let dropped = tokio::time::timeout(
        Duration::from_millis(100),
        core.address_pools.claim(&ctx, lab.id, ip("192.0.2.10"), "web-1", job),
    )
    .await;
    assert!(dropped.is_err(), "dropped mid-check");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !core.address_pools.leases(&ctx, lab.id).await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the dropped claim's row went");
    tools.set_echo_delay(Duration::ZERO);

    // A claim of a job that ended counts as free at once, and the next claim of its address takes it.
    let a = open_job(&core, &ctx).await;
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "web-1", a)
        .await
        .unwrap();
    assert_eq!(
        ips(&core.address_pools.pick(&ctx, lab.id, 1, &[]).await.unwrap()),
        [ip("192.0.2.11")]
    );
    end_job(&core, a).await;
    assert_eq!(
        ips(&core.address_pools.pick(&ctx, lab.id, 2, &[]).await.unwrap()),
        [ip("192.0.2.10"), ip("192.0.2.11")]
    );
    let listed = core.address_pools.list(&ctx).await.unwrap();
    assert_eq!(listed[0].used, 0, "it holds nothing");
    let leases = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert!(leases[0].can_free);
    let b = open_job(&core, &ctx).await;
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "web-1", b)
        .await
        .unwrap();
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.11"), "web-2", b)
        .await
        .unwrap();
    let leases = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert_eq!(leases.len(), 2);
    assert!(leases.iter().all(|l| l.job_id == Some(b)));

    // The job lets go of what it claimed and didn't assign (a step's error or cancel, its end).
    core.address_pools
        .assign(&ctx, lab.id, ip("192.0.2.11"), b, r"C:\VMs\web-2\web-2.vmx")
        .await
        .unwrap();
    assert_eq!(core.address_pools.release_job_claims(&ctx, b).await.unwrap(), 1);
    let left = core.address_pools.leases(&ctx, lab.id).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!((left[0].ip, left[0].state), (ip("192.0.2.11"), LeaseState::Assigned));
}

#[tokio::test]
async fn assign_and_release_take_only_the_jobs_own_claim() {
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);
    let job = open_job(&core, &ctx).await;
    let other = open_job(&core, &ctx).await;
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

    // Another job's assign or release does nothing to it.
    assert!(core
        .address_pools
        .assign(&ctx, lab.id, ip("192.0.2.10"), other, r"C:\VMs\x\x.vmx")
        .await
        .is_err());
    core.address_pools
        .release(&ctx, lab.id, ip("192.0.2.10"), other)
        .await
        .unwrap();
    assert_eq!(core.address_pools.leases(&ctx, lab.id).await.unwrap().len(), 2);

    core.address_pools
        .assign(&ctx, lab.id, ip("192.0.2.10"), job, r"C:\VMs\web-1\web-1.vmx")
        .await
        .unwrap();
    // Assigned once: a second assign doesn't re-point it, and a release doesn't take it.
    assert!(core
        .address_pools
        .assign(&ctx, lab.id, ip("192.0.2.10"), job, r"C:\VMs\other\other.vmx")
        .await
        .is_err());
    core.address_pools
        .release(&ctx, lab.id, ip("192.0.2.10"), job)
        .await
        .unwrap();
    core.address_pools
        .release(&ctx, lab.id, ip("192.0.2.11"), job)
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
        .assign(&ctx, lab.id, ip("192.0.2.12"), job, r"C:\VMs\x\x.vmx")
        .await
        .is_err());
    // And the database never holds an assigned address without its VM.
    let orphan = sqlx::query(
        "INSERT INTO address_leases (pool_id, workspace_id, user_id, network_key, ip, vm_key, vm_name, job_id, state,
                                     created_at)
         VALUES (?, ?, ?, 'vmware:vmnet8', '192.0.2.19', NULL, 'x', NULL, 'assigned', '2026-11-14T00:00:00Z')",
    )
    .bind(lab.id.to_string())
    .bind(ctx.workspace_id.0.to_string())
    .bind(ctx.user_id.0.to_string())
    .execute(core.store.pool())
    .await;
    assert!(orphan.is_err(), "the CHECK refuses it");
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
    let tools = tools();
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
    let job = open_job(&core, &ctx).await;
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.15"), "web", job)
        .await
        .unwrap();
    // The key in another letter case is the same VM.
    core.address_pools
        .assign(&ctx, lab.id, ip("192.0.2.15"), job, &vmx("web").to_uppercase())
        .await
        .unwrap();
    end_job(&core, job).await;

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
    moved.network = Network::Bridged;
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
    let deleting = core.bus.approve(request.id, answers).await.unwrap();
    let mut note = None;
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match rx.recv().await.unwrap() {
                JobEvent::TargetFinished { job_id, note: n, .. } if job_id == deleting => note = n,
                JobEvent::Finished { job_id, status, .. } if job_id == deleting => return status,
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
    let tools = tools();
    let core = core_with(&tools, FakeVmware::default()).await;
    let ctx = core.ctx();
    let lab = core
        .address_pools
        .add(&ctx, pool("lab", "192.0.2.10", "192.0.2.20"))
        .await
        .unwrap();
    silent(&tools, 10, 20);
    // A VM deleted in Workstation's own window: no workspace lists it.
    let job = open_job(&core, &ctx).await;
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.10"), "old", job)
        .await
        .unwrap();
    core.address_pools
        .assign(&ctx, lab.id, ip("192.0.2.10"), job, r"C:\VMs\old\old.vmx")
        .await
        .unwrap();
    // A claim whose deploy never ended (the app stopped): it holds nothing.
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

    // A fresh claim stays at start; one a day old goes.
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
    // A stale claim doesn't keep the pool from going either.
    core.address_pools
        .claim(&ctx, lab.id, ip("192.0.2.12"), "web-2", Uuid::new_v4())
        .await
        .unwrap();
    core.address_pools.delete(&ctx, lab.id).await.unwrap();
}
