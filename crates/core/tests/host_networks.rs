//! VM-11 host networks end to end with the fakes: the report (vmnets, NAT forwards, VirtualBox's host-only
//! interfaces, NAT networks and VMs' NAT rules, the VMs on each), and port forward changes through the bus (High,
//! Critical with a Prod VM on the network, refused before asking when Workstation needs administrator rights) to the
//! fakes' vmrun and VBoxManage. No real network or VM is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::{vbox_vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::host_networks::{ForwardProtocol, VboxRule, VmnetForward, VmnetKind};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::adapters::virtualbox::VboxNic;
use remotely_core::adapters::vm_hardware::{VirtualNic, VmHardware};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::domain::{Environment, PowerState, TargetRef};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::host_networks::{HostNetworkOp, NatForward};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::presentation::Presentation;
use remotely_core::vault::SecretString;
use remotely_core::Core;
use uuid::Uuid;

const LAB: &str = "9d1e2f3a-0000-4000-8000-0000000000aa";
const EDGE: &str = "9d1e2f3a-0000-4000-8000-0000000000bb";

fn nic(slot: &str, connection: &str, network: Option<&str>) -> VirtualNic {
    VirtualNic {
        slot: slot.into(),
        connection: Some(connection.into()),
        network_name: network.map(String::from),
        ..Default::default()
    }
}

/// `web` on vmnet8 (203.0.113.10) and bridged; `db` on vmnet2; a forward to web's SSH.
fn workstation() -> FakeVmware {
    FakeVmware::default()
        .with_default_networks()
        .with_vmnet(2, VmnetKind::HostOnly, "198.51.100.0")
        .in_library(&vmx("web"), Some("web"))
        .with_hardware(
            &vmx("web"),
            VmHardware {
                nics: vec![nic("ethernet0", "nat", None), nic("ethernet1", "bridged", None)],
                guest_ips: vec!["203.0.113.10".into(), "192.0.2.77".into()],
                ..Default::default()
            },
        )
        .in_library(&vmx("db"), Some("db"))
        .with_hardware(
            &vmx("db"),
            VmHardware {
                nics: vec![nic("ethernet0", "custom (VMnet2)", Some("VMnet2"))],
                ..Default::default()
            },
        )
        .with_forward(
            "vmnet8",
            VmnetForward {
                protocol: ForwardProtocol::Tcp,
                host_port: 2222,
                guest_ip: "203.0.113.10".into(),
                guest_port: 22,
                description: Some("web ssh".into()),
            },
        )
}

/// `lab01` (off) on the NAT network lab-net and NAT with a rule; `edge01` (running) on NAT.
fn virtualbox() -> FakeVirtualBox {
    FakeVirtualBox::new()
        .with_host_only("VirtualBox Host-Only Ethernet Adapter", "192.0.2.1")
        .with_nat_network("lab-net", "198.51.100.0/24")
        .with_vm(LAB, "lab01", PowerState::NotRunning)
        .with_info(LAB, |vm| {
            vm.nics = vec![
                VboxNic {
                    slot: 1,
                    attachment: "natnetwork".into(),
                    network_name: Some("lab-net".into()),
                    ..Default::default()
                },
                VboxNic {
                    slot: 2,
                    attachment: "nat".into(),
                    ..Default::default()
                },
            ];
        })
        .with_vm_rule(LAB, 2, rule("ssh", 2222, 22))
        .with_vm(EDGE, "edge01", PowerState::Running)
}

fn rule(name: &str, host_port: u16, guest_port: u16) -> VboxRule {
    VboxRule {
        name: name.into(),
        protocol: ForwardProtocol::Tcp,
        host_ip: None,
        host_port,
        guest_ip: None,
        guest_port,
    }
}

async fn built(setup: Setup) -> Core {
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    core
}

fn vmnet8() -> TargetRef {
    TargetRef::Network {
        hypervisor: Hypervisor::Vmware,
        name: "vmnet8".into(),
    }
}

fn lab_net() -> TargetRef {
    TargetRef::Network {
        hypervisor: Hypervisor::VirtualBox,
        name: "lab-net".into(),
    }
}

fn web_forward(host_port: u16) -> NatForward {
    NatForward {
        name: Some("web".into()),
        protocol: ForwardProtocol::Tcp,
        host_ip: None,
        host_port,
        guest_ip: Some("203.0.113.10".into()),
        guest_port: 80,
        slot: None,
    }
}

fn add(target: TargetRef, forward: NatForward) -> Command {
    Command::HostNetwork {
        targets: vec![target],
        op: HostNetworkOp::AddForward { forward },
    }
}

fn remove(target: TargetRef, forward: NatForward) -> Command {
    Command::HostNetwork {
        targets: vec![target],
        op: HostNetworkOp::RemoveForward { forward },
    }
}

fn asked(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

async fn approve(core: &Core, request: &ApprovalRequest) -> Uuid {
    let vault = request.steps.contains(&ApprovalStep::VaultReauth);
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("R4 test".into()),
        safety_snapshot: None,
        vault_password: vault.then(|| SecretString::new(VAULT_PASSWORD)),
    };
    core.bus.approve(request.id, answers).await.unwrap()
}

async fn run(core: &Core, command: Command) -> (Uuid, JobStatus) {
    let mut rx = core.jobs.subscribe();
    let job = match core.bus.submit(&core.ctx, command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => approve(core, &request).await,
    };
    (job, wait_finished(&mut rx, job).await)
}

async fn finished_detail(core: &Core) -> String {
    core.store
        .recent_audit(&core.ctx, 20)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "job_finished")
        .and_then(|e| e.detail)
        .unwrap_or_default()
}

#[tokio::test]
async fn the_report_lists_each_network_its_vms_and_forwards() {
    let core = built(Setup::new(workstation()).with_virtualbox(virtualbox())).await;
    let report = core.networks.report(&core.ctx).await.unwrap();

    let vmware = &report.vmware;
    assert!(vmware.available);
    assert!(vmware.forwards_refused.is_some(), "not an administrator");
    let names: Vec<&str> = vmware.networks.iter().map(|n| n.network.name.as_str()).collect();
    assert_eq!(names, ["vmnet0", "vmnet1", "vmnet2", "vmnet8"]);
    let nat = vmware.networks.iter().find(|n| n.network.name == "vmnet8").unwrap();
    assert_eq!(nat.target, vmnet8());
    assert_eq!(nat.vms.len(), 1);
    assert_eq!(
        (nat.vms[0].name.as_str(), nat.vms[0].adapter.as_str()),
        ("web", "ethernet0")
    );
    assert_eq!(nat.vms[0].ips, ["203.0.113.10"]);
    assert_eq!(nat.forwards.len(), 1);
    assert_eq!(nat.forwards[0].description.as_deref(), Some("web ssh"));
    let vmnet2 = vmware.networks.iter().find(|n| n.network.name == "vmnet2").unwrap();
    assert_eq!(vmnet2.vms[0].name, "db");
    assert_eq!(vmware.networks[0].vms[0].name, "web", "bridged");

    let vbox = &report.virtualbox;
    assert!(vbox.available);
    assert_eq!(vbox.host_only.len(), 1);
    assert_eq!(vbox.nat_networks[0].network.name, "lab-net");
    assert_eq!(vbox.nat_networks[0].vms[0].name, "lab01");
    let lab_nat = vbox.vm_nat.iter().find(|v| v.vm.name == "lab01").unwrap();
    assert_eq!((lab_nat.slot, lab_nat.rules.len()), (2, 1));
    assert_eq!(lab_nat.rules[0].name, "ssh");
    let edge = vbox.vm_nat.iter().find(|v| v.vm.name == "edge01").unwrap();
    assert!(edge.rules.is_empty());
    assert!(report.stale_vms.is_empty());
}

/// QL-21: the topology map's network nodes come from the networks alone: vmrun's list and VBoxManage's two, no VM
/// read and no forward.
#[tokio::test]
async fn the_networks_alone_read_no_vm_and_no_forward() {
    let setup = Setup::new(workstation()).with_virtualbox(virtualbox());
    let (vmware, vbox) = (Arc::clone(&setup.vmware), Arc::clone(&setup.virtualbox));
    let core = built(setup).await;
    let (vmrun_before, vbox_before) = (vmware.vmrun_runs(), vbox.vboxmanage_runs());

    let list = core.networks.networks_only().await;
    let names: Vec<&str> = list.vmware.networks.iter().map(|n| n.network.name.as_str()).collect();
    assert_eq!(names, ["vmnet1", "vmnet2", "vmnet8"], "as vmrun lists them");
    assert!(list
        .vmware
        .networks
        .iter()
        .all(|n| n.vms.is_empty() && n.forwards.is_empty()));
    assert_eq!(list.virtualbox.host_only.len(), 1);
    assert_eq!(list.virtualbox.nat_networks[0].network.name, "lab-net");
    assert!(list.virtualbox.nat_networks[0].vms.is_empty());
    assert!(list.virtualbox.vm_nat.is_empty() && list.virtualbox.other.is_empty());
    assert_eq!(vmware.vmrun_runs() - vmrun_before, 1, "listHostNetworks only");
    assert_eq!(
        vbox.vboxmanage_runs() - vbox_before,
        2,
        "list hostonlyifs and natnets: no showvminfo or guest properties"
    );
}

/// VM-11: the report's VMs come from QL-21's adapter read, which stores them; a VM whose files can't be read now
/// shows on its networks with what was stored, and is named as such.
#[tokio::test]
async fn the_report_shares_the_maps_adapter_read_and_falls_back_to_what_it_stored() {
    let setup = Setup::new(workstation());
    let vmware = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    core.networks.report(&core.ctx).await.unwrap();
    let stored = core.host_details.vm_networks(&core.ctx, false).await.unwrap();
    let web = stored.iter().find(|n| n.vmx_path == vmx("web")).unwrap();
    assert!(web.stored, "the report's read was kept for the map");
    assert_eq!(web.nics.len(), 2);
    assert_eq!(web.guest_ips, ["203.0.113.10", "192.0.2.77"]);

    vmware.set_hardware_failing(true);
    let report = core.networks.report(&core.ctx).await.unwrap();
    let mut stale = report.stale_vms.clone();
    stale.sort();
    assert_eq!(stale, ["db", "web"]);
    let nat = report
        .vmware
        .networks
        .iter()
        .find(|n| n.network.name == "vmnet8")
        .unwrap();
    assert_eq!(nat.vms[0].name, "web");
    assert_eq!(nat.vms[0].ips, ["203.0.113.10"]);
}

#[tokio::test]
async fn forwards_read_from_vmnetnat_conf_when_vmrun_prints_them_in_another_form() {
    let core = built(Setup::new(workstation().with_forwards_in_conf_only())).await;
    let report = core.networks.report(&core.ctx).await.unwrap();
    let nat = report
        .vmware
        .networks
        .iter()
        .find(|n| n.network.name == "vmnet8")
        .unwrap();
    assert_eq!(nat.forwards_problem, None);
    assert_eq!(nat.forwards.len(), 1);
    assert_eq!((nat.forwards[0].host_port, nat.forwards[0].guest_port), (2222, 22));
}

#[tokio::test]
async fn without_the_hypervisors_the_report_says_they_are_not_there() {
    let core = built(Setup::new(FakeVmware::default()).with_virtualbox(FakeVirtualBox::not_installed())).await;
    let report = core.networks.report(&core.ctx).await.unwrap();
    assert!(report.vmware.networks.is_empty());
    assert!(!report.virtualbox.available);
}

#[tokio::test]
async fn a_workstation_forward_is_refused_before_asking_when_remotely_isnt_an_administrator() {
    let setup = Setup::new(workstation());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let err = core
        .bus
        .submit(&core.ctx, add(vmnet8(), web_forward(8080)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "host_network_refused");
    assert!(err.to_string().contains("administrator"), "{err}");
    let audit = core.store.recent_audit(&core.ctx, 20).await.unwrap();
    assert!(
        audit.iter().all(|e| e.event != "approval_requested"),
        "nothing was asked"
    );
    assert_eq!(fake.networks().forwards("vmnet8").len(), 1);
}

#[tokio::test]
async fn adding_and_removing_a_workstation_forward_goes_through_a_high_approval() {
    let setup = Setup::new(workstation().as_admin());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    // The adapters are read (and stored) for the network's VMs.
    core.networks.report(&core.ctx).await.unwrap();

    let request = asked(
        core.bus
            .submit(&core.ctx, add(vmnet8(), web_forward(8080)))
            .await
            .unwrap(),
    );
    assert_eq!((request.action, request.tier), (ActionKind::NatForwardAdd, Tier::High));
    assert_eq!(request.targets[0].name, "vmnet8 (Workstation)");
    assert!(
        request.warnings.iter().any(|w| w.contains("every address of this PC")),
        "{:?}",
        request.warnings
    );
    assert!(request
        .warnings
        .iter()
        .any(|w| w.contains("203.0.113.10 is web's address on vmnet8")));
    assert!(request.warnings.iter().any(|w| w.starts_with("VMs on vmnet8: web")));
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    let forwards = fake.networks().forwards("vmnet8");
    assert!(forwards.iter().any(|f| f.host_port == 8080 && f.guest_port == 80));
    assert!(fake
        .calls()
        .iter()
        .any(|c| c == "host setPortForwarding vmnet8 tcp 8080 203.0.113.10 80 web"));
    assert!(finished_detail(&core).await.contains("1 succeeded"));
    let audit = core.store.recent_audit(&core.ctx, 20).await.unwrap();
    let started = audit.iter().find(|e| e.event == "job_started").unwrap();
    assert!(
        started.targets_json.contains("\"kind\":\"network\""),
        "{}",
        started.targets_json
    );

    let (_, status) = run(&core, remove(vmnet8(), web_forward(8080))).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(!fake.networks().forwards("vmnet8").iter().any(|f| f.host_port == 8080));
}

#[tokio::test]
async fn a_workstation_forward_on_a_port_in_use_is_refused_rather_than_replaced() {
    let setup = Setup::new(workstation().as_admin());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let (_, status) = run(&core, add(vmnet8(), web_forward(2222))).await;
    assert_eq!(status, JobStatus::Failed);
    assert!(finished_detail(&core).await.contains("1 failed"));
    let forwards = fake.networks().forwards("vmnet8");
    assert_eq!(forwards.len(), 1);
    assert_eq!(forwards[0].guest_port, 22, "the forward there is kept");
    // A forward that isn't there can't be removed.
    let (_, status) = run(&core, remove(vmnet8(), web_forward(9999))).await;
    assert_eq!(status, JobStatus::Failed);
    // Port forwards are for NAT networks.
    let vmnet1 = TargetRef::Network {
        hypervisor: Hypervisor::Vmware,
        name: "vmnet1".into(),
    };
    let (_, status) = run(&core, add(vmnet1, web_forward(8081))).await;
    assert_eq!(status, JobStatus::Failed);
}

#[tokio::test]
async fn a_network_with_a_prod_vm_on_it_is_critical() {
    let core = built(Setup::new(workstation().as_admin())).await;
    core.networks.report(&core.ctx).await.unwrap();
    core.inventory
        .set_environment(&core.ctx, &[vmx("web")], Environment::Prod)
        .await
        .unwrap();
    let request = asked(
        core.bus
            .submit(&core.ctx, add(vmnet8(), web_forward(8080)))
            .await
            .unwrap(),
    );
    assert_eq!(request.tier, Tier::Critical);
    assert_eq!(request.targets[0].environment, Environment::Prod);
    assert!(request.steps.contains(&ApprovalStep::VaultReauth));
}

#[tokio::test]
async fn virtualbox_nat_network_rules_add_and_remove() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox());
    let fake = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let forward = NatForward {
        name: Some("web".into()),
        guest_ip: Some("198.51.100.5".into()),
        host_ip: Some("127.0.0.1".into()),
        ..web_forward(8080)
    };
    let request = asked(
        core.bus
            .submit(&core.ctx, add(lab_net(), forward.clone()))
            .await
            .unwrap(),
    );
    assert_eq!(request.tier, Tier::High);
    assert!(
        !request.warnings.iter().any(|w| w.contains("every address")),
        "loopback only: {:?}",
        request.warnings
    );
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    let rules = fake.networks().nat_rules("lab-net");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].host_ip.as_deref(), Some("127.0.0.1"));
    // The same name again is refused before VBoxManage runs.
    let (_, status) = run(&core, add(lab_net(), forward.clone())).await;
    assert_eq!(status, JobStatus::Failed);
    let (_, status) = run(&core, remove(lab_net(), forward)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(fake.networks().nat_rules("lab-net").is_empty());
}

#[tokio::test]
async fn a_virtualbox_vms_rule_uses_modifyvm_while_off_and_controlvm_while_running() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox());
    let fake = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let lab_rule = NatForward {
        name: Some("web".into()),
        guest_ip: None,
        slot: Some(2),
        ..web_forward(8080)
    };
    let (_, status) = run(&core, add(vbox_vm(LAB), lab_rule.clone())).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(fake
        .calls()
        .iter()
        .any(|c| c == "host modifyvm 9d1e2f3a-0000-4000-8000-0000000000aa --natpf2 web,tcp,,8080,,80"));
    assert_eq!(fake.networks().vm_rules(LAB).len(), 2);

    let edge_rule = NatForward {
        slot: Some(1),
        ..lab_rule.clone()
    };
    let (_, status) = run(&core, add(vbox_vm(EDGE), edge_rule.clone())).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(fake
        .calls()
        .iter()
        .any(|c| c.starts_with("host controlvm 9d1e2f3a-0000-4000-8000-0000000000bb natpf1 web,")));
    assert!(finished_detail(&core).await.contains("1 succeeded"));
    let (_, status) = run(&core, remove(vbox_vm(EDGE), edge_rule)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(fake.networks().vm_rules(EDGE).is_empty());

    // Adapter 1 of lab01 is on a NAT network, not NAT.
    let wrong = NatForward {
        slot: Some(1),
        name: Some("other".into()),
        ..lab_rule
    };
    let (_, status) = run(&core, add(vbox_vm(LAB), wrong)).await;
    assert_eq!(status, JobStatus::Failed);
}

#[tokio::test]
async fn a_suspended_vms_rules_are_refused() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(FakeVirtualBox::new().with_vm(
        LAB,
        "lab01",
        PowerState::Suspended,
    ));
    let core = built(setup).await;
    let rule = NatForward {
        guest_ip: None,
        slot: Some(1),
        ..web_forward(8080)
    };
    let (_, status) = run(&core, add(vbox_vm(LAB), rule)).await;
    assert_eq!(status, JobStatus::Failed);
    let audit = core.store.recent_audit(&core.ctx, 20).await.unwrap();
    let finished = audit.iter().find(|e| e.event == "job_finished").unwrap();
    assert!(finished.detail.as_deref().unwrap_or_default().contains("1 failed"));
}

#[tokio::test]
async fn the_read_only_lock_refuses_port_forwards_and_not_the_report() {
    let core = built(Setup::new(workstation().as_admin())).await;
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let err = core
        .bus
        .submit(&core.ctx, add(vmnet8(), web_forward(8080)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    assert!(core.networks.report(&core.ctx).await.is_ok());
}

#[tokio::test]
async fn the_ui_cant_send_a_forward_to_the_wrong_kind_of_target() {
    let core = built(Setup::new(workstation().as_admin())).await;
    for command in [
        add(TargetRef::App, web_forward(8080)),
        add(common::vm("web"), web_forward(8080)),
        Command::HostNetwork {
            targets: vec![vmnet8(), lab_net()],
            op: HostNetworkOp::AddForward {
                forward: web_forward(8080),
            },
        },
    ] {
        let err = core.bus.submit(&core.ctx, command).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{err}");
    }
}
