//! VM-18 Oracle VirtualBox end to end, with fake adapters: VirtualBox VMs listed next to Workstation
//! ones, filtered by hypervisor; power and snapshot commands through the bus with the same tiers, Prod
//! label and protection as VMware VMs, the approval steps, VM-05 safety snapshots, AP-02 impact
//! preview, VM-07 capacity check, cancel, and the audit log; QL-01 auto-linking by the Guest
//! Additions' IP; MO-01 host usage from VirtualBox's processes; the VBoxManage path setting. No real
//! VM or VirtualBox install is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{vbox_vm, vm, vmx, wait_finished, Setup};
use remotely_core::adapters::host_counters::VmProcess;
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SnapshotOp, StopMode, SubmitOutcome};
use remotely_core::domain::{Environment, PowerState, Target, TargetRef};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::inventory::VmFilter;
use remotely_core::jobs::{JobEvent, JobStatus};
use remotely_core::metrics::RowKind;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::vault::SecretString;
use remotely_core::{Core, CoreError};
use time::OffsetDateTime;
use uuid::Uuid;

/// Running, Guest Additions running, reports 192.0.2.30.
const WEB: &str = "3f0c1a2b-1111-4222-8333-444455556666";
/// Saved state.
const DB: &str = "9d1e2f3a-0000-4000-8000-0000000000aa";
/// Powered off.
const APP: &str = "5a5a5a5a-2222-4333-8444-555566667777";
/// Paused.
const IDLE: &str = "6b6b6b6b-3333-4444-8555-666677778888";

fn virtualbox() -> FakeVirtualBox {
    FakeVirtualBox::new()
        .with_vm(WEB, "vbox-web", PowerState::Running)
        .with_ip(WEB, "192.0.2.30")
        .with_vm(DB, "vbox-db", PowerState::Suspended)
        .with_vm(APP, "vbox-app", PowerState::NotRunning)
        .with_vm(IDLE, "vbox-idle", PowerState::Paused)
}

fn workstation() -> FakeVmware {
    FakeVmware::with_running([vmx("web")])
        .in_library(&vmx("web"), Some("web"))
        .in_library(&vmx("db"), Some("db"))
        .with_ip(&vmx("web"), "192.0.2.10")
}

async fn mixed() -> (Core, Arc<FakeVmware>, Arc<FakeVirtualBox>) {
    let setup = Setup::new(workstation()).with_virtualbox(virtualbox());
    let (vmware, vbox) = (Arc::clone(&setup.vmware), Arc::clone(&setup.virtualbox));
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    (core, vmware, vbox)
}

fn names(targets: &[Target]) -> Vec<&str> {
    targets.iter().map(|t| t.name.as_str()).collect()
}

fn confirm() -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    }
}

fn high_answers(count: usize, safety_snapshot: bool) -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(count),
        reason: Some("CHG-18".into()),
        safety_snapshot: Some(safety_snapshot),
        ..Default::default()
    }
}

fn power(targets: Vec<TargetRef>, op: PowerOp) -> Command {
    Command::VmPower { targets, op }
}

/// Submits, approves when asked, and waits for the job.
async fn run(core: &Core, command: Command, answers: ApprovalAnswers) -> (Uuid, JobStatus) {
    let mut events = core.jobs.subscribe();
    let job = match core.bus.submit(&core.ctx, command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core.bus.approve(request.id, answers).await.unwrap(),
    };
    (job, wait_finished(&mut events, job).await)
}

async fn target_errors(core: &Core, job: Uuid) -> Vec<(String, Option<String>)> {
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    targets.into_iter().map(|t| (t.target_name, t.error)).collect()
}

// ---- VM-01, VM-02: one list for both hypervisors ------------------------------------------------

#[tokio::test]
async fn a_refresh_lists_workstation_and_virtualbox_vms_together() {
    let (core, _, _) = mixed().await;
    let vms = core.inventory.list(&core.ctx, &VmFilter::default()).await.unwrap();
    let listed: Vec<(&str, Hypervisor, PowerState)> = vms
        .iter()
        .map(|v| (v.display_name.as_str(), v.hypervisor, v.power_state))
        .collect();
    assert_eq!(
        listed,
        [
            ("db", Hypervisor::Vmware, PowerState::NotRunning),
            ("vbox-app", Hypervisor::VirtualBox, PowerState::NotRunning),
            ("vbox-db", Hypervisor::VirtualBox, PowerState::Suspended),
            ("vbox-idle", Hypervisor::VirtualBox, PowerState::Paused),
            ("vbox-web", Hypervisor::VirtualBox, PowerState::Running),
            ("web", Hypervisor::Vmware, PowerState::Running),
        ]
    );
    let web = vms.iter().find(|v| v.display_name == "vbox-web").unwrap();
    assert_eq!(web.vmx_path, WEB, "a VirtualBox VM's key is its UUID");
    assert_eq!(web.ip_address.as_deref(), Some("192.0.2.30"));
    assert_eq!(web.tools_state.as_deref(), Some("running"), "Guest Additions run");
    assert_eq!(web.guest_os.as_deref(), Some("Ubuntu (64-bit)"));
    assert_eq!(web.guest_os_name.as_deref(), Some("Linux"));
    assert_eq!((web.num_vcpus, web.memsize_mb), (Some(2), Some(2048)));
    assert_eq!(
        web.config_path.as_deref(),
        Some(r"C:\Users\alice\VirtualBox VMs\vbox-web\vbox-web.vbox")
    );
    let off = vms.iter().find(|v| v.display_name == "vbox-app").unwrap();
    assert_eq!((off.tools_state.as_deref(), off.ip_address.as_deref()), (None, None));

    let only_vbox = VmFilter {
        hypervisors: vec![Hypervisor::VirtualBox],
        power_states: vec![PowerState::Running],
        ..Default::default()
    };
    let found = core.inventory.list(&core.ctx, &only_vbox).await.unwrap();
    assert_eq!(
        found.iter().map(|v| v.display_name.as_str()).collect::<Vec<_>>(),
        ["vbox-web"]
    );
}

#[tokio::test]
async fn without_virtualbox_there_are_only_workstation_vms_and_no_warning() {
    let core = Setup::new(workstation())
        .with_virtualbox(FakeVirtualBox::not_installed())
        .build()
        .await;
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(report.vms.iter().all(|v| v.hypervisor == Hypervisor::Vmware));
    assert_eq!(report.vms.len(), 2);
    assert_eq!(core.vboxmanage_path(), None);
}

#[tokio::test]
async fn with_only_virtualbox_a_missing_workstation_is_no_warning() {
    let core = Setup::new(FakeVmware::default().without_vmrun())
        .with_virtualbox(virtualbox())
        .build()
        .await;
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(report.vms.len(), 4);

    // A Workstation VM in the library still says vmrun is missing.
    let core = Setup::new(
        FakeVmware::default()
            .in_library(&vmx("web"), Some("web"))
            .without_vmrun(),
    )
    .with_virtualbox(virtualbox())
    .build()
    .await;
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(report.warnings.len(), 1);
    assert_eq!(report.warnings[0].code, "vmrun_not_found");
}

#[tokio::test]
async fn when_virtualbox_cannot_be_asked_its_vms_stay_listed_with_a_warning() {
    let (core, _, vbox) = mixed().await;
    vbox.set_failing_list(true);
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(report.warnings.len(), 1);
    assert_eq!(report.warnings[0].code, "vboxmanage_failed");
    assert!(report.warnings[0]
        .message
        .starts_with("Could not ask VirtualBox for its VMs"));
    assert_eq!(
        report
            .vms
            .iter()
            .filter(|v| v.hypervisor == Hypervisor::VirtualBox)
            .count(),
        4,
        "kept as the last refresh found them"
    );
    vbox.set_failing_list(false);
    assert!(core.inventory.refresh(&core.ctx).await.unwrap().warnings.is_empty());
}

#[tokio::test]
async fn a_virtualbox_vm_that_cannot_be_read_is_a_warning_and_the_rest_still_list() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox().unreadable(DB));
    let core = setup.build().await;
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(report.warnings.len(), 1);
    assert!(report.warnings[0]
        .message
        .starts_with("Could not read VirtualBox VM 'vbox-db'"));
    let names: Vec<&str> = report.vms.iter().map(|v| v.display_name.as_str()).collect();
    assert_eq!(names, ["vbox-app", "vbox-idle", "vbox-web"]);
}

#[tokio::test]
async fn a_virtualbox_vm_whose_settings_are_gone_is_left_out() {
    let fake = virtualbox().with_info(APP, |vm| vm.accessible = false);
    let core = Setup::new(FakeVmware::default()).with_virtualbox(fake).build().await;
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert!(report.warnings.is_empty());
    assert!(!report.vms.iter().any(|v| v.vmx_path == APP));
}

#[tokio::test]
async fn the_guest_ip_is_the_one_the_host_can_reach_not_the_nat_one() {
    // NAT on adapter 1 (10.0.2.15 in every VM) and host-only on adapter 2: the guest reports both.
    let fake = FakeVirtualBox::new()
        .with_vm(WEB, "vbox-web", PowerState::Running)
        .with_info(WEB, |vm| {
            vm.nics.push(remotely_core::adapters::virtualbox::VboxNic {
                slot: 2,
                attachment: "hostonly".into(),
                mac: Some("080027000002".into()),
                ..Default::default()
            });
        })
        .with_guest_property(WEB, "/VirtualBox/GuestInfo/Net/Count", "2")
        .with_guest_property(WEB, "/VirtualBox/GuestInfo/Net/0/V4/IP", "10.0.2.15")
        .with_guest_property(WEB, "/VirtualBox/GuestInfo/Net/0/MAC", "080027000001")
        .with_guest_property(WEB, "/VirtualBox/GuestInfo/Net/1/V4/IP", "192.0.2.31")
        .with_guest_property(WEB, "/VirtualBox/GuestInfo/Net/1/MAC", "080027000002")
        .with_guest_property(WEB, "/VirtualBox/GuestInfo/OS/Product", "Windows 11")
        .with_guest_property(WEB, "/VirtualBox/GuestInfo/OS/Release", "10.0.22631");
    let core = Setup::new(FakeVmware::default()).with_virtualbox(fake).build().await;
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(report.vms[0].ip_address.as_deref(), Some("192.0.2.31"));
    assert_eq!(report.vms[0].guest_os_name.as_deref(), Some("Windows 11 10.0.22631"));
}

/// `count` running VMs, each with a NAT and a host-only adapter and Guest Additions that report both
/// (the host-only one 192.0.2.N) and the OS.
fn busy_lab(count: u8) -> FakeVirtualBox {
    let mut fake = FakeVirtualBox::new();
    for n in 1..=count {
        let uuid = format!("3f0c1a2b-1111-4222-8333-4444555566{n:02x}");
        fake = fake
            .with_vm(&uuid, &format!("lab{n:02}"), PowerState::Running)
            .with_info(&uuid, |vm| {
                vm.nics.push(remotely_core::adapters::virtualbox::VboxNic {
                    slot: 2,
                    attachment: "hostonly".into(),
                    mac: Some("080027000002".into()),
                    ..Default::default()
                });
            })
            .with_guest_property(&uuid, "/VirtualBox/GuestInfo/Net/Count", "2")
            .with_guest_property(&uuid, "/VirtualBox/GuestInfo/Net/0/V4/IP", "10.0.2.15")
            .with_guest_property(&uuid, "/VirtualBox/GuestInfo/Net/0/MAC", "080027000001")
            .with_guest_property(&uuid, "/VirtualBox/GuestInfo/Net/1/V4/IP", &format!("192.0.2.{n}"))
            .with_guest_property(&uuid, "/VirtualBox/GuestInfo/Net/1/MAC", "080027000002")
            .with_guest_property(&uuid, "/VirtualBox/GuestInfo/OS/Product", "Linux")
            .with_guest_property(&uuid, "/VirtualBox/GuestInfo/OS/Release", "6.8.0-45-generic");
    }
    fake
}

#[tokio::test]
async fn a_refresh_asks_virtualbox_twice_per_running_vm() {
    // VM-01: `showvminfo`, then one `guestproperty enumerate` for the address and the OS (it was one
    // `guestproperty get` per property: 7 per VM with two adapters).
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(busy_lab(40));
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    let before = vbox.vboxmanage_runs();
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    let runs = vbox.vboxmanage_runs() - before;
    eprintln!("VBoxManage runs for one refresh of 40 running VMs: {runs}");
    assert_eq!(
        runs,
        1 + 40 * 2,
        "list vms, then showvminfo and guestproperty enumerate per VM"
    );
    let lab07 = report.vms.iter().find(|vm| vm.display_name == "lab07").unwrap();
    assert_eq!(lab07.ip_address.as_deref(), Some("192.0.2.7"), "the host-only address");
    assert_eq!(lab07.guest_os_name.as_deref(), Some("Linux 6.8.0-45-generic"));
}

#[tokio::test]
async fn refreshes_asked_for_while_one_runs_share_one_more_run() {
    // VM-01: ten refreshes at once (ten uploads finishing, say) run the inventory twice: the one that
    // was running, and one more for everything asked for while it ran.
    let setup =
        Setup::new(FakeVmware::default()).with_virtualbox(busy_lab(3).with_list_delay(Duration::from_millis(200)));
    let (vbox, vmware) = (Arc::clone(&setup.virtualbox), Arc::clone(&setup.vmware));
    let core = setup.build().await;
    let (vbox_before, vmrun_before) = (vbox.vboxmanage_runs(), vmware.vmrun_runs());
    let reports = futures::future::join_all((0..10).map(|_| core.inventory.refresh(&core.ctx))).await;
    assert!(reports.iter().all(|r| r.as_ref().is_ok_and(|r| r.vms.len() == 3)));
    let (vbox_runs, vmrun_runs) = (vbox.vboxmanage_runs() - vbox_before, vmware.vmrun_runs() - vmrun_before);
    eprintln!("ten overlapping refreshes: {vbox_runs} VBoxManage runs, {vmrun_runs} vmrun runs");
    assert_eq!(vbox_runs, 2 * (1 + 3 * 2), "two refreshes");
    assert_eq!(vmrun_runs, 2, "vmrun list, twice");

    // One asked for after they are done runs again: nothing it could share was still running.
    core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(vbox.vboxmanage_runs() - vbox_before, 3 * (1 + 3 * 2));
}

// ---- Tiers: the same for both hypervisors, Prod and protected included --------------------------

#[tokio::test]
async fn every_power_and_snapshot_command_gets_the_same_tier_on_either_hypervisor() {
    let (core, _, _) = mixed().await;
    let ops = [
        PowerOp::Start { gui: false },
        PowerOp::Start { gui: true },
        PowerOp::Stop { mode: StopMode::Soft },
        PowerOp::Stop { mode: StopMode::Hard },
        PowerOp::Reset { mode: StopMode::Soft },
        PowerOp::Reset { mode: StopMode::Hard },
        PowerOp::Suspend,
        PowerOp::Pause,
        PowerOp::Unpause,
    ];
    let snapshots = [
        SnapshotOp::Take { name: "x".into() },
        SnapshotOp::Revert { name: "x".into() },
        SnapshotOp::Delete { name: "x".into() },
    ];
    let mut commands: Vec<Box<dyn Fn(Vec<TargetRef>) -> Command>> = Vec::new();
    for op in ops {
        commands.push(Box::new(move |targets| power(targets, op)));
    }
    for op in snapshots {
        commands.push(Box::new(move |targets| Command::VmSnapshot {
            targets,
            op: op.clone(),
        }));
    }
    let preview = |command: Command| {
        let core = &core;
        async move { core.bus.preview(&core.ctx, &command).await.unwrap() }
    };
    for make in &commands {
        for (vmware, vbox) in [
            (vec![vm("web")], vec![vbox_vm(WEB)]),
            (vec![vm("web"), vm("db")], vec![vbox_vm(WEB), vbox_vm(DB)]),
        ] {
            let a = preview(make(vmware)).await;
            let b = preview(make(vbox)).await;
            assert_eq!(
                (a.action, a.tier, &a.steps),
                (b.action, b.tier, &b.steps),
                "{:?}",
                a.action
            );
        }
    }

    // Prod raises a VirtualBox VM's tier like a VMware VM's.
    core.inventory
        .set_environment(&core.ctx, &[vmx("web"), WEB.to_owned()], Environment::Prod)
        .await
        .unwrap();
    let stop = |target| power(vec![target], PowerOp::Stop { mode: StopMode::Soft });
    let a = preview(stop(vm("web"))).await;
    let b = preview(stop(vbox_vm(WEB))).await;
    assert_eq!((a.tier, b.tier), (Tier::High, Tier::High), "Medium + Prod");
    assert_eq!(a.reasons, b.reasons);
    let start = |target| power(vec![target], PowerOp::Start { gui: false });
    assert_eq!(preview(start(vbox_vm(WEB))).await.tier, Tier::Medium, "Low + Prod");
}

#[tokio::test]
async fn a_protected_virtualbox_vm_is_skipped_until_it_is_unprotected() {
    let (core, _, vbox) = mixed().await;
    let protect = Command::VmProtect {
        targets: vec![vbox_vm(WEB)],
        protected: true,
    };
    let (_, status) = run(&core, protect, confirm()).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(core.store.find_vm(&core.ctx, WEB).await.unwrap().unwrap().protected);

    let suspend = power(vec![vbox_vm(WEB), vbox_vm(APP)], PowerOp::Suspend);
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend).await.unwrap() else {
        panic!("suspending one VM is Medium");
    };
    assert_eq!(request.tier, Tier::Medium, "one VM left");
    assert_eq!(names(&request.skipped), ["vbox-web"]);
    core.bus.cancel_approval(request.id).await.unwrap();
    assert!(matches!(
        core.bus
            .submit(&core.ctx, power(vec![vbox_vm(WEB)], PowerOp::Pause))
            .await,
        Err(CoreError::AllTargetsProtected)
    ));
    assert!(vbox.calls().is_empty(), "no VBoxManage call for a protected VM");
}

// ---- VM-02, VM-03: power through the bus --------------------------------------------------------

#[tokio::test]
async fn power_commands_reach_virtualbox_through_the_bus_and_are_audited() {
    let (core, vmware, vbox) = mixed().await;

    // Start (Low): headless by default, with a window when asked.
    let (job, status) = run(
        &core,
        power(vec![vbox_vm(APP)], PowerOp::Start { gui: true }),
        confirm(),
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(vbox.power_state(APP), PowerState::Running);
    let vm = core.store.find_vm(&core.ctx, APP).await.unwrap().unwrap();
    assert_eq!(
        vm.power_state,
        PowerState::Running,
        "the list shows it before the next refresh"
    );

    // Pause, then resume; suspend (save state).
    run(&core, power(vec![vbox_vm(APP)], PowerOp::Pause), confirm()).await;
    assert_eq!(vbox.power_state(APP), PowerState::Paused);
    run(&core, power(vec![vbox_vm(APP)], PowerOp::Unpause), confirm()).await;
    assert_eq!(vbox.power_state(APP), PowerState::Running);
    run(&core, power(vec![vbox_vm(APP)], PowerOp::Suspend), confirm()).await;
    assert_eq!(vbox.power_state(APP), PowerState::Suspended);

    // A soft stop presses the ACPI button and waits for the guest.
    let (_, status) = run(
        &core,
        power(vec![vbox_vm(WEB)], PowerOp::Stop { mode: StopMode::Soft }),
        confirm(),
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(vbox.power_state(WEB), PowerState::NotRunning);

    assert_eq!(
        vbox.calls(),
        [
            format!("power Start {{ gui: true }} {APP}"),
            format!("power Pause {APP}"),
            format!("power Unpause {APP}"),
            format!("power Suspend {APP}"),
            format!("power Stop {{ mode: Soft }} {WEB}"),
        ]
    );
    assert!(vmware.calls().is_empty(), "nothing went to Workstation");

    // The audit log names the VM and its key, the start and end of each job, and the chain holds.
    let audit = core.store.recent_audit(&core.ctx, 100).await.unwrap();
    let start = audit
        .iter()
        .find(|e| e.event == "job_started" && e.job_id.as_deref() == Some(job.to_string().as_str()))
        .unwrap();
    assert_eq!(start.action, "Start 1 VM");
    assert_eq!(start.tier.as_deref(), Some("low"));
    assert!(start.targets_json.contains(APP) && start.targets_json.contains("vbox-app"));
    assert!(audit.iter().any(|e| e.event == "job_finished"
        && e.action == "Shut down 1 VM"
        && e.result.as_deref() == Some("succeeded")));
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn a_guest_that_ignores_the_acpi_button_is_left_running_until_a_critical_force_off() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox().ignores_acpi(WEB));
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    core.set_shutdown_wait_secs(1).await.unwrap();
    let mut events = core.jobs.subscribe();

    let SubmitOutcome::NeedsApproval { request } = core
        .bus
        .submit(
            &core.ctx,
            power(vec![vbox_vm(WEB)], PowerOp::Stop { mode: StopMode::Soft }),
        )
        .await
        .unwrap()
    else {
        panic!("stopping one VM is Medium");
    };
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    let mut still_running = Vec::new();
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await.unwrap() {
                JobEvent::StillRunning { job_id, targets } if job_id == job => still_running = targets,
                JobEvent::Finished { job_id, status, .. } if job_id == job => return status,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(status, JobStatus::Failed);
    assert_eq!(names(&still_running), ["vbox-web"]);
    assert_eq!(
        vbox.power_state(WEB),
        PowerState::Running,
        "never forced off by the soft stop"
    );
    let error = target_errors(&core, job).await[0].1.clone().unwrap();
    assert!(error.contains("did not shut down within 1 s"), "{error}");
    assert_eq!(vbox.in_flight(), 0, "the waiting VBoxManage call was dropped");

    // Forcing it off is its own Critical command, with the vault password.
    let SubmitOutcome::NeedsApproval { request } = core
        .bus
        .submit(
            &core.ctx,
            power(vec![vbox_vm(WEB)], PowerOp::Stop { mode: StopMode::Hard }),
        )
        .await
        .unwrap()
    else {
        panic!("a hard power-off is Critical");
    };
    assert_eq!(request.tier, Tier::Critical);
    assert!(request.steps.contains(&ApprovalStep::VaultReauth));
    let answers = ApprovalAnswers {
        vault_password: Some(SecretString::new(common::VAULT_PASSWORD)),
        ..high_answers(1, false)
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(vbox.power_state(WEB), PowerState::NotRunning);
}

#[tokio::test]
async fn a_graceful_restart_needs_the_guest_additions_and_says_so_at_once() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox().without_guest_additions(WEB));
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let restart = power(vec![vbox_vm(WEB)], PowerOp::Reset { mode: StopMode::Soft });
    let (job, status) = run(&core, restart, confirm()).await;
    assert_eq!(status, JobStatus::Failed);
    assert!(vbox.calls().is_empty(), "VBoxManage was never asked to reboot it");
    assert_eq!(
        target_errors(&core, job).await[0].1.as_deref(),
        Some(
            "Guest Additions are not running in the guest, so it can't restart gracefully. Reset (hard) forces it; \
             that needs its own approval."
        )
    );
    let vm = core.store.find_vm(&core.ctx, WEB).await.unwrap().unwrap();
    assert_eq!(vm.tools_state.as_deref(), Some("notRunning"));

    // With Guest Additions running, the restart goes ahead.
    let core = Setup::new(FakeVmware::default())
        .with_virtualbox(virtualbox())
        .build()
        .await;
    let restart = power(vec![vbox_vm(WEB)], PowerOp::Reset { mode: StopMode::Soft });
    assert_eq!(run(&core, restart, confirm()).await.1, JobStatus::Succeeded);
}

#[tokio::test]
async fn a_bulk_start_reaches_both_hypervisors_and_counts_both_in_the_capacity_check() {
    let mut setup = Setup::new(FakeVmware::default().in_library(&vmx("big"), Some("big")).with_vmx(
        &vmx("big"),
        VmxInfo {
            display_name: Some("big".into()),
            memsize_mb: Some(6 * 1024),
            num_vcpus: Some(2),
            ..Default::default()
        },
    ))
    .with_virtualbox(virtualbox().with_info(WEB, |vm| vm.memory_mb = Some(4 * 1024)));
    setup.host.totals.physical_ram_mb = 8 * 1024;
    let (vmware, vbox) = (Arc::clone(&setup.vmware), Arc::clone(&setup.virtualbox));
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();

    // vbox-web (4 GB) and vbox-idle (2 GB, paused) run; big (6 GB) and vbox-app (2 GB) would start.
    let start = power(vec![vm("big"), vbox_vm(APP)], PowerOp::Start { gui: false });
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, start).await.unwrap() else {
        panic!("a start that would overcommit RAM asks for a confirm");
    };
    assert_eq!(
        request.warnings,
        [
            "Running VMs would be assigned 14.0 GB of RAM, more than this host's 8.0 GB.",
            // VM-26: what suspending would free; the paused VM is never suggested.
            "Even suspending every running VM that can be ('vbox-web') frees only 4.0 GB of the 6.0 GB needed."
        ]
    );
    let mut events = core.jobs.subscribe();
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(vmware.running().len(), 1);
    assert_eq!(vbox.power_state(APP), PowerState::Running);
}

#[tokio::test]
async fn cancel_stops_waiting_for_a_virtualbox_power_call() {
    let setup =
        Setup::new(FakeVmware::default()).with_virtualbox(virtualbox().with_power_delay(Duration::from_secs(60)));
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id: job, .. } = core
        .bus
        .submit(&core.ctx, power(vec![vbox_vm(APP)], PowerOp::Start { gui: false }))
        .await
        .unwrap()
    else {
        panic!("starting is Low");
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while vbox.in_flight() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(core.jobs.cancel(job));
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Cancelled);
    assert_eq!(vbox.in_flight(), 0, "the call was dropped, which kills VBoxManage");
    assert_eq!(
        target_errors(&core, job).await[0].1.as_deref(),
        Some("cancelled while VBoxManage was running; VirtualBox may still finish the action, so check the VM's state")
    );
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert!(audit[0]
        .detail
        .as_deref()
        .unwrap()
        .contains("cancelled while VBoxManage was running, so VirtualBox may still finish it"));
}

// ---- VM-04, VM-05, AP-02: snapshots -------------------------------------------------------------

fn with_snapshots() -> FakeVirtualBox {
    let now = OffsetDateTime::now_utc();
    virtualbox()
        .with_snapshot(WEB, "base", now - time::Duration::days(45))
        .with_snapshot(WEB, "patched", now - time::Duration::days(2))
}

#[tokio::test]
async fn a_virtualbox_vms_snapshot_tree_lists_like_a_workstation_one() {
    let setup = Setup::new(workstation()).with_virtualbox(with_snapshots());
    let (vmware, vbox) = (Arc::clone(&setup.vmware), Arc::clone(&setup.virtualbox));
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();

    let list = core
        .snapshots
        .list(&core.ctx, Some(&[WEB.to_uppercase()]))
        .await
        .unwrap();
    assert_eq!(list.len(), 1, "keys match in any letter case");
    let web = &list[0];
    assert_eq!(web.hypervisor, Hypervisor::VirtualBox);
    let tree: Vec<_> = web
        .snapshots
        .iter()
        .map(|s| (s.depth, s.name.as_str(), s.old, s.current))
        .collect();
    assert_eq!(tree, [(0, "base", true, false), (1, "patched", false, true)]);
    assert_eq!(web.old_count, 1);
    assert!(
        Uuid::parse_str(&web.snapshots[1].path).is_ok(),
        "VirtualBox names a snapshot by its UUID, not a path"
    );
    assert_eq!(vbox.snapshot_reads(), [WEB]);
    assert!(vmware.snapshot_reads().is_empty(), "only the asked VM is read");
}

#[tokio::test]
async fn snapshots_of_virtualbox_vms_are_taken_reverted_and_deleted_through_the_bus() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(with_snapshots());
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();

    // Take (Low): queued at once. VirtualBox takes names with '/'.
    let take = Command::VmSnapshot {
        targets: vec![vbox_vm(WEB)],
        op: SnapshotOp::Take {
            name: "before/upgrade".into(),
        },
    };
    let (_, status) = run(&core, take, confirm()).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(vbox.snapshot_names(WEB), ["base", "patched", "before/upgrade"]);
    assert_eq!(vbox.current_snapshot(WEB).as_deref(), Some("before/upgrade"));

    // A name the VM has already is refused: VirtualBox would make a second one.
    let again = Command::VmSnapshot {
        targets: vec![vbox_vm(WEB)],
        op: SnapshotOp::Take { name: "base".into() },
    };
    let (job, status) = run(&core, again, confirm()).await;
    assert_eq!(status, JobStatus::Failed);
    assert!(target_errors(&core, job).await[0]
        .1
        .as_deref()
        .unwrap()
        .contains("already has a snapshot named 'base'"));

    // Revert (High) on a running VM: the preview says it is powered off first; a safety snapshot
    // comes before.
    let revert = Command::VmSnapshot {
        targets: vec![vbox_vm(WEB)],
        op: SnapshotOp::Revert { name: "base".into() },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, revert).await.unwrap() else {
        panic!("revert is High");
    };
    assert_eq!(request.tier, Tier::High);
    assert_eq!(
        request.warnings,
        [
            "VirtualBox restores a snapshot only on a VM that is not running, so Remotely powers off vbox-web first, \
          without shutting the guest down."
        ]
    );
    assert!(request
        .steps
        .contains(&ApprovalStep::SafetySnapshot { default_on: true }));
    let impact = &request.impact[0];
    assert_eq!(impact.target, WEB);
    assert_eq!(impact.power_state, PowerState::Running);
    assert!(impact.uptime_secs.is_some(), "VirtualBox says when the VM started");
    assert_eq!(impact.snapshot_count, Some(3));
    assert_eq!(impact.old_snapshot_count, Some(1));
    let mut events = core.jobs.subscribe();
    let job = core.bus.approve(request.id, high_answers(1, true)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    let calls = vbox.calls();
    assert_eq!(
        &calls[calls.len() - 3..],
        [
            format!("snapshot take safety {WEB}"),
            format!("snapshot restore base {WEB}"),
            format!("power poweroff before restore {WEB}"),
        ]
    );
    assert_eq!(vbox.current_snapshot(WEB).as_deref(), Some("base"));
    assert_eq!(vbox.power_state(WEB), PowerState::NotRunning);
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    assert!(targets[0]
        .safety_snapshot
        .as_deref()
        .unwrap()
        .starts_with("Remotely safety before revert"));

    // Delete (High).
    let delete = Command::VmSnapshot {
        targets: vec![vbox_vm(WEB)],
        op: SnapshotOp::Delete {
            name: "before/upgrade".into(),
        },
    };
    let (_, status) = run(&core, delete, high_answers(1, false)).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(!vbox.snapshot_names(WEB).contains(&"before/upgrade".to_owned()));
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn a_twin_named_snapshot_is_reverted_by_its_uuid() {
    let now = OffsetDateTime::now_utc();
    let fake = virtualbox()
        .with_snapshot(APP, "same", now - time::Duration::days(3))
        .with_snapshot(APP, "same", now - time::Duration::days(1));
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(fake);
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let tree = core.snapshots.list(&core.ctx, Some(&[APP.to_owned()])).await.unwrap();
    let first = &tree[0].snapshots[0];
    assert_eq!(first.name, tree[0].snapshots[1].name);
    assert!(tree[0].snapshots[1].current, "the second twin, taken last");
    let revert = Command::VmSnapshot {
        targets: vec![vbox_vm(APP)],
        op: SnapshotOp::Revert {
            name: first.path.clone(),
        },
    };
    let (_, status) = run(&core, revert, high_answers(1, false)).await;
    assert_eq!(status, JobStatus::Succeeded);
    let after = core.snapshots.list(&core.ctx, Some(&[APP.to_owned()])).await.unwrap();
    assert!(after[0].snapshots[0].current, "the first of the twins, by UUID");
    assert!(!after[0].snapshots[1].current);
    assert!(
        !vbox.calls().iter().any(|c| c.contains("poweroff")),
        "it was off already"
    );
}

#[tokio::test]
async fn a_slash_in_a_new_snapshot_name_is_refused_only_for_workstation_vms() {
    let (core, _, _) = mixed().await;
    let take = |targets| Command::VmSnapshot {
        targets,
        op: SnapshotOp::Take { name: "a/b".into() },
    };
    assert!(core.bus.submit(&core.ctx, take(vec![vbox_vm(APP)])).await.is_ok());
    for targets in [vec![vm("web")], vec![vbox_vm(APP), vm("db")]] {
        let err = core.bus.submit(&core.ctx, take(targets)).await.unwrap_err();
        assert!(err.to_string().contains("vmrun reads it as the path"), "{err}");
    }
}

#[tokio::test]
async fn a_safety_snapshot_that_fails_leaves_the_virtualbox_vm_untouched() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox().failing_snapshots(WEB));
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let stop = power(
        vec![vbox_vm(WEB), vbox_vm(IDLE)],
        PowerOp::Stop { mode: StopMode::Hard },
    );
    let answers = ApprovalAnswers {
        vault_password: Some(SecretString::new(common::VAULT_PASSWORD)),
        ..high_answers(2, true)
    };
    let (job, status) = run(&core, stop, answers).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    assert_eq!(vbox.power_state(WEB), PowerState::Running, "no safety net, no change");
    assert_eq!(vbox.power_state(IDLE), PowerState::NotRunning);
    let errors = target_errors(&core, job).await;
    let web = errors.iter().find(|(name, _)| name == "vbox-web").unwrap();
    assert!(web.1.as_deref().unwrap().starts_with("the safety snapshot failed"));
}

// ---- QL-01, MO-01: links and host usage ---------------------------------------------------------

#[tokio::test]
async fn a_session_reaching_a_virtualbox_guest_is_linked_by_a_refresh() {
    let (core, _, _) = mixed().await;
    let input = SessionInput {
        name: "vbox-web ssh".into(),
        folder_id: None,
        host: "192.0.2.30".into(),
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
    };
    let session = core.sessions.create(&core.ctx, input).await.unwrap();
    core.inventory.refresh(&core.ctx).await.unwrap();
    let vm = core.store.find_vm(&core.ctx, WEB).await.unwrap().unwrap();
    let session = core.sessions.get(&core.ctx, session.id).await.unwrap();
    assert_eq!(session.vm_id, Some(vm.id));
}

#[tokio::test]
async fn virtualbox_processes_give_their_vms_host_usage_on_the_dashboard() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox());
    let processes = Arc::clone(&setup.host.processes);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let process = |pid: u32, key: Option<&str>, name: Option<&str>| VmProcess {
        pid,
        vmx_path: key.map(String::from),
        name: name.map(String::from),
        cpu_pct: Some(12.5),
        working_set_bytes: Some(1 << 30),
        read_bps: None,
        write_bps: None,
    };
    *processes.lock().unwrap() = vec![
        process(10, Some(&WEB.to_uppercase()), Some("vbox-web")),
        // Started with the VM's name rather than its UUID.
        process(11, None, Some("vbox-idle")),
    ];
    let cost = core.metrics.collect_once().await;
    assert_eq!(cost.vms, 2);
    let overview = core.metrics.overview(&core.ctx).await.unwrap();
    let rows: Vec<(&str, Option<Hypervisor>, Option<PowerState>)> = overview
        .rows
        .iter()
        .filter(|r| r.kind == RowKind::Vm)
        .map(|r| (r.name.as_str(), r.hypervisor, r.power_state))
        .collect();
    assert_eq!(
        rows,
        [
            ("vbox-idle", Some(Hypervisor::VirtualBox), Some(PowerState::Paused)),
            ("vbox-web", Some(Hypervisor::VirtualBox), Some(PowerState::Running)),
        ]
    );
    let web = overview.rows.iter().find(|r| r.key == WEB).unwrap();
    let sample = web.host.as_ref().unwrap();
    assert_eq!(sample.host_cpu_pct, Some(12.5));
    assert_eq!(sample.mem_total_bytes, Some(2048 * 1024 * 1024));
}

// ---- Settings ------------------------------------------------------------------------------------

#[tokio::test]
async fn the_vboxmanage_path_is_checked_saved_and_audited() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let bad = core
        .set_vboxmanage_path(Some(r"C:\Windows\System32\notepad.exe".into()))
        .await
        .unwrap_err();
    assert!(matches!(bad, CoreError::InvalidSetting(_)));
    let missing = core
        .set_vboxmanage_path(Some(r"C:\does-not-exist\VBoxManage.exe".into()))
        .await
        .unwrap_err();
    assert!(matches!(missing, CoreError::InvalidSetting(_)));

    core.set_vboxmanage_path(None).await.unwrap();
    assert_eq!(core.saved_vboxmanage_path().await.unwrap(), None);
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "setting_changed");
    assert_eq!(audit[0].action, "Set the VBoxManage.exe path");
    assert!(audit[0]
        .detail
        .as_deref()
        .unwrap()
        .starts_with("saved: find automatically; in use: "));
}
