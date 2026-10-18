//! Milestone 1 (VMs and power) end to end, with fake adapters: discovery (VM-01), tags, saved filters
//! and start (VM-02), graceful-then-forced shutdown (VM-03), power calls that fail fast or can be
//! cancelled instead of hanging (VM-02, VM-03), the power-on limit (VM-06), the capacity check (VM-07),
//! protected VMs (AP-04) and environment labels on VMs (SS-06).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, vm, vmx, wait_finished, Setup};
use remotely_core::adapters::vmware::{ToolsState, VmxInfo};
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, StopMode, SubmitOutcome};
use remotely_core::domain::{Environment, PowerState, Target};
use remotely_core::fakes::{FakeHostCounters, FakeRemote, FakeUpdater, FakeVault, FakeVmware};
use remotely_core::inventory::VmFilter;
use remotely_core::jobs::{JobEvent, JobLimits, JobStatus};
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::vault::SecretString;
use remotely_core::{Adapters, Core, CoreError};

fn names(targets: &[Target]) -> Vec<&str> {
    targets.iter().map(|t| t.name.as_str()).collect()
}

// ---- VM-01: discover every VM ------------------------------------------------------------------

#[tokio::test]
async fn refresh_lists_the_library_chosen_folders_and_running_vms() {
    let folder = temp_folder("lab");
    let app = folder.join(r"app\app.vmx").display().to_string();
    let fake = FakeVmware::with_running([vmx("web").to_uppercase(), r"E:\Other\tmp\tmp.vmx".into()])
        .in_library(&vmx("web"), Some("web"))
        .in_library(&vmx("db"), Some("db"))
        .in_library(&vmx("gone"), Some("gone"))
        .without_file(&vmx("gone"))
        .in_folder(&folder.display().to_string(), &app)
        .with_vmx(
            &vmx("web"),
            VmxInfo {
                display_name: Some("web".into()),
                guest_os: Some("ubuntu-64".into()),
                guest_os_name: Some("Ubuntu 24.04 LTS".into()),
                num_vcpus: Some(2),
                memsize_mb: Some(4096),
                suspended: false,
            },
        )
        .with_vmx(
            &vmx("db"),
            VmxInfo {
                display_name: Some("db".into()),
                suspended: true,
                ..Default::default()
            },
        )
        .with_ip(&vmx("web"), "192.0.2.10");
    let core = Setup::new(fake).build().await;
    core.set_scan_folders(vec![folder.clone()]).await.unwrap();

    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    let names: Vec<_> = report.vms.iter().map(|v| v.display_name.as_str()).collect();
    assert_eq!(
        names,
        ["app", "db", "tmp", "web"],
        "a library entry whose file is gone is left out"
    );

    let by_name = |n: &str| report.vms.iter().find(|v| v.display_name == n).unwrap();
    let web = by_name("web");
    assert_eq!(web.power_state, PowerState::Running, "path case does not matter");
    assert_eq!(web.ip_address.as_deref(), Some("192.0.2.10"));
    assert_eq!(web.tools_state.as_deref(), Some("running"));
    assert_eq!(web.guest_os_name.as_deref(), Some("Ubuntu 24.04 LTS"));
    assert_eq!(web.memsize_mb, Some(4096));
    assert_eq!(by_name("db").power_state, PowerState::Suspended);
    assert_eq!(by_name("app").power_state, PowerState::NotRunning);
    assert_eq!(by_name("app").tools_state, None, "no Tools query for a VM that is off");
    assert_eq!(
        by_name("tmp").power_state,
        PowerState::Running,
        "running but in no library"
    );

    std::fs::remove_dir_all(&folder).unwrap();
}

#[tokio::test]
async fn without_vmrun_the_library_still_lists_with_a_warning() {
    let fake = FakeVmware::default()
        .in_library(&vmx("web"), Some("web"))
        .without_vmrun();
    let core = Setup::new(fake).build().await;

    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(report.vms.len(), 1);
    assert_eq!(report.vms[0].power_state, PowerState::Unknown);
    assert_eq!(report.warnings.len(), 1);
    assert_eq!(report.warnings[0].code, "vmrun_not_found");
}

#[tokio::test]
async fn a_folder_that_cannot_be_scanned_is_a_warning_not_a_failure() {
    let folder = temp_folder("unplugged");
    let fake = FakeVmware::default().in_library(&vmx("web"), None);
    let core = Setup::new(fake).build().await;
    core.set_scan_folders(vec![folder.clone()]).await.unwrap();
    std::fs::remove_dir_all(&folder).unwrap();

    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(report.vms.len(), 1);
    assert_eq!(report.warnings.len(), 1);
    assert!(report.warnings[0].message.contains("Could not scan"));
}

#[tokio::test]
async fn vms_no_longer_found_drop_out_of_the_list() {
    let folder = temp_folder("lab");
    let app = folder.join(r"app\app.vmx").display().to_string();
    let fake = FakeVmware::default().in_folder(&folder.display().to_string(), &app);
    let core = Setup::new(fake).build().await;

    core.set_scan_folders(vec![folder.clone()]).await.unwrap();
    assert_eq!(core.inventory.refresh(&core.ctx).await.unwrap().vms.len(), 1);
    core.set_scan_folders(vec![]).await.unwrap();
    assert!(core.inventory.refresh(&core.ctx).await.unwrap().vms.is_empty());
    std::fs::remove_dir_all(&folder).unwrap();
}

#[tokio::test]
async fn a_folder_saved_with_forward_slashes_lists_a_running_vm_once() {
    // The scan of C:/VMs found C:/VMs/web/web.vmx, then vmrun list named the running VM
    // C:\VMs\web\web.vmx and the list showed it twice.
    let fake = FakeVmware::with_running([vmx("web")]).in_folder("C:/VMs", "C:/VMs/web/web.vmx");
    let core = Setup::new(fake).build().await;
    // Saved as typed, as set_scan_folders did before it saved folders with `\`.
    core.store
        .put_setting(&core.ctx, remotely_core::store::SCAN_FOLDERS_KEY, &["C:/VMs"])
        .await
        .unwrap();

    for _ in 0..2 {
        let report = core.inventory.refresh(&core.ctx).await.unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.vms.len(), 1, "{:?}", report.vms);
        assert_eq!(report.vms[0].power_state, PowerState::Running);
        if cfg!(windows) {
            assert_eq!(report.vms[0].vmx_path, vmx("web"), "saved as vmrun names it");
        }
    }
}

#[tokio::test]
async fn scan_folders_must_exist_are_deduplicated_and_audited() {
    let folder = temp_folder("lab");
    let core = Setup::new(FakeVmware::default()).build().await;

    let missing = core
        .set_scan_folders(vec![folder.join("does-not-exist")])
        .await
        .unwrap_err();
    assert!(matches!(missing, CoreError::InvalidSetting(_)));
    assert!(core.scan_folders().await.unwrap().is_empty());

    let upper = PathBuf::from(folder.display().to_string().to_uppercase());
    let slashed = PathBuf::from(folder.display().to_string().replace('\\', "/"));
    let kept = core
        .set_scan_folders(vec![slashed, folder.clone(), upper])
        .await
        .unwrap();
    // As text: on Windows, Path equality already treats `/` and `\` alike.
    let text = |paths: &[PathBuf]| paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>();
    assert_eq!(
        text(&kept),
        [folder.display().to_string()],
        "saved with backslashes, duplicates dropped"
    );
    assert_eq!(text(&core.scan_folders().await.unwrap()), text(&kept));

    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "setting_changed");
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
    std::fs::remove_dir_all(&folder).unwrap();
}

// ---- AP-04: protected VMs ----------------------------------------------------------------------

fn protect(names: &[&str], protected: bool) -> Command {
    Command::VmProtect {
        targets: names.iter().map(|n| vm(n)).collect(),
        protected,
    }
}

fn confirm() -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn protected_vms_are_skipped_until_they_are_unprotected() {
    let setup = Setup::new(FakeVmware::with_running([vmx("a"), vmx("b")]));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let mut events = core.jobs.subscribe();

    // Protecting is Low: logged, no approval, and no VM is touched.
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bus.submit(&core.ctx, protect(&["a"], true)).await.unwrap()
    else {
        panic!("protecting is Low");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    assert!(
        core.store
            .find_vm(&core.ctx, &vmx("a"))
            .await
            .unwrap()
            .unwrap()
            .protected
    );

    // A bulk suspend leaves the protected VM alone: one VM left, so Medium.
    let suspend = Command::VmPower {
        targets: vec![vm("a"), vm("b")],
        op: PowerOp::Suspend,
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend).await.unwrap() else {
        panic!("suspending one VM is Medium");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(names(&request.skipped), ["a"]);
    assert_eq!(names(&request.targets), ["b"]);
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(fake.calls(), [r"power Suspend C:\VMs\b\b.vmx"]);

    // A Low action reports what it skipped, and an action on only protected VMs is refused.
    let start = |names: &[&str]| Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op: PowerOp::Start { gui: false },
    };
    let SubmitOutcome::Queued { skipped, job_id, .. } = core.bus.submit(&core.ctx, start(&["a", "b"])).await.unwrap()
    else {
        panic!("starting is Low");
    };
    assert_eq!(names(&skipped), ["a"]);
    wait_finished(&mut events, job_id).await;
    assert!(matches!(
        core.bus.submit(&core.ctx, start(&["a"])).await,
        Err(CoreError::AllTargetsProtected)
    ));

    // Unlocking needs one confirm, and reaches the protected VM.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, protect(&["a"], false)).await.unwrap()
    else {
        panic!("unprotecting is Medium");
    };
    assert_eq!(names(&request.targets), ["a"]);
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert!(
        !core
            .store
            .find_vm(&core.ctx, &vmx("a"))
            .await
            .unwrap()
            .unwrap()
            .protected
    );

    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    for action in ["Protect 1 VM", "Unprotect 1 VM"] {
        assert!(
            audit.iter().any(|e| e.event == "job_finished" && e.action == action),
            "{action}"
        );
    }
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn protecting_a_vm_not_in_the_inventory_fails() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, protect(&["nope"], true)).await.unwrap()
    else {
        panic!("protecting is Low");
    };
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Failed);
}

// ---- SS-06: environment labels on VMs -----------------------------------------------------------

fn soft_stop(names: &[&str]) -> Command {
    Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op: PowerOp::Stop { mode: StopMode::Soft },
    }
}

#[tokio::test]
async fn a_prod_label_moves_a_shutdown_of_one_vm_from_medium_to_high_and_outlasts_a_refresh() {
    let core = Setup::new(FakeVmware::with_running([vmx("a"), vmx("b")])).build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();

    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, soft_stop(&["a"])).await.unwrap() else {
        panic!("stopping one VM is Medium");
    };
    assert_eq!(request.tier, Tier::Medium);
    core.bus.cancel_approval(request.id).await.unwrap();

    // Labelling is the app's own data: no approval, and audited with what changed.
    let changed = core
        .inventory
        .set_environment(&core.ctx, &[vmx("a")], Environment::Prod)
        .await
        .unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].environment, Environment::Prod);
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "vm_label_changed");
    assert_eq!(audit[0].action, "Changed the label of VM 'a'");
    assert_eq!(audit[0].detail.as_deref(), Some("label: none -> prod"));
    assert_eq!(audit[0].tier, None);
    let targets: Vec<Target> = serde_json::from_str(&audit[0].targets_json).unwrap();
    assert_eq!(names(&targets), ["a"]);
    assert_eq!(targets[0].environment, Environment::Prod);

    // A refresh keeps the label.
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    let by_name = |n: &str| report.vms.iter().find(|v| v.display_name == n).unwrap();
    assert_eq!(by_name("a").environment, Environment::Prod);
    assert_eq!(by_name("b").environment, Environment::None);
    let prod = VmFilter {
        environments: vec![Environment::Prod],
        ..Default::default()
    };
    let picked = core.inventory.list(&core.ctx, &prod).await.unwrap();
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].display_name, "a");

    // The same shutdown is now High, and says why.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, soft_stop(&["a"])).await.unwrap() else {
        panic!("stopping a Prod VM is High");
    };
    assert_eq!(request.tier, Tier::High);
    assert!(
        request
            .reasons
            .iter()
            .any(|r| r == "a target is labelled Prod: medium -> high"),
        "{:?}",
        request.reasons
    );
    assert!(request.steps.contains(&ApprovalStep::Reason));
    core.bus.cancel_approval(request.id).await.unwrap();

    // The unlabelled VM is still Medium.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, soft_stop(&["b"])).await.unwrap() else {
        panic!("stopping one VM is Medium");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn labelling_checks_every_vm_first_and_logs_only_real_changes() {
    let core = Setup::new(FakeVmware::with_running([vmx("a"), vmx("b")])).build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let label = |vm: &str| {
        let core = &core;
        let vmx = vmx(vm);
        async move { core.store.find_vm(&core.ctx, &vmx).await.unwrap().unwrap().environment }
    };
    let audit_count = || async { core.store.recent_audit(&core.ctx, 100).await.unwrap().len() };
    let before = audit_count().await;

    assert!(matches!(
        core.inventory.set_environment(&core.ctx, &[], Environment::Lab).await,
        Err(CoreError::NoTargets)
    ));
    // A VM not in the inventory fails the whole change.
    let unknown = core
        .inventory
        .set_environment(&core.ctx, &[vmx("a"), vmx("nope")], Environment::Lab)
        .await
        .unwrap_err();
    assert!(matches!(unknown, CoreError::UnknownTarget(p) if p == vmx("nope")));
    assert_eq!(label("a").await, Environment::None);
    assert_eq!(audit_count().await, before);

    // Path case does not matter, and a VM listed twice changes once.
    let changed = core
        .inventory
        .set_environment(
            &core.ctx,
            &[vmx("a"), vmx("a").to_uppercase(), vmx("b")],
            Environment::Lab,
        )
        .await
        .unwrap();
    assert_eq!(changed.len(), 2);
    assert_eq!(audit_count().await, before + 1);
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].action, "Changed the label of 2 VMs");
    assert_eq!(audit[0].detail.as_deref(), Some("label: none -> lab"));

    // Nothing to change: nothing written.
    let unchanged = core
        .inventory
        .set_environment(&core.ctx, &[vmx("a"), vmx("b")], Environment::Lab)
        .await
        .unwrap();
    assert!(unchanged.is_empty());
    assert_eq!(audit_count().await, before + 1);

    // Mixed labels before: each VM's change is named. VMs that already have the label are left out.
    core.inventory
        .set_environment(&core.ctx, &[vmx("a")], Environment::Prod)
        .await
        .unwrap();
    let changed = core
        .inventory
        .set_environment(&core.ctx, &[vmx("a"), vmx("b")], Environment::Prod)
        .await
        .unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].display_name, "b");
    core.inventory
        .set_environment(&core.ctx, &[vmx("a")], Environment::Staging)
        .await
        .unwrap();
    core.inventory
        .set_environment(&core.ctx, &[vmx("a"), vmx("b")], Environment::None)
        .await
        .unwrap();
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(
        audit[0].detail.as_deref(),
        Some("label: staging -> none (a); prod -> none (b)")
    );
    assert_eq!(label("a").await, Environment::None);
    assert_eq!(label("b").await, Environment::None);
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

// ---- VM-02: tags, saved filters and start -------------------------------------------------------

#[tokio::test]
async fn a_saved_filter_picks_the_stopped_lab_vms_which_start_with_a_console_window() {
    let setup = Setup::new(
        FakeVmware::with_running([vmx("c")])
            .in_library(&vmx("a"), None)
            .in_library(&vmx("b"), None)
            .in_library(&vmx("c"), None)
            .in_library(&vmx("other"), None),
    );
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let lab: Vec<String> = ["a", "b", "c"].iter().map(|n| vmx(n)).collect();
    core.store.tag_vms(&core.ctx, &lab, "lab").await.unwrap();

    let filter = VmFilter {
        tags: vec!["lab".into()],
        power_states: vec![PowerState::NotRunning],
        ..Default::default()
    };
    let saved = core.store.save_filter(&core.ctx, "Lab, off", &filter).await.unwrap();
    let picked = core.inventory.list(&core.ctx, &saved.filter).await.unwrap();
    let names: Vec<_> = picked.iter().map(|v| v.display_name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);

    let mut events = core.jobs.subscribe();
    let start = Command::VmPower {
        targets: picked.iter().map(|v| vm(&v.display_name)).collect(),
        op: PowerOp::Start { gui: true },
    };
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bus.submit(&core.ctx, start).await.unwrap() else {
        panic!("starting VMs is Low");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    let mut calls = fake.calls();
    calls.sort();
    assert_eq!(
        calls,
        [
            r"power Start { gui: true } C:\VMs\a\a.vmx",
            r"power Start { gui: true } C:\VMs\b\b.vmx"
        ]
    );
    // The list shows them running before the next refresh.
    assert!(core.inventory.list(&core.ctx, &saved.filter).await.unwrap().is_empty());
}

// ---- VM-06: parallel power-on limit ------------------------------------------------------------

async fn start_all(core: &Core, names: &[&str]) -> JobStatus {
    let mut events = core.jobs.subscribe();
    let start = Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op: PowerOp::Start { gui: false },
    };
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, start).await.unwrap() else {
        panic!("starting VMs is Low");
    };
    wait_finished(&mut events, job_id).await
}

const SIX: [&str; 6] = ["a", "b", "c", "d", "e", "f"];

#[tokio::test]
async fn at_most_three_vms_power_on_at_once_by_default() {
    let setup = Setup::new(FakeVmware::default().with_power_delay(Duration::from_millis(60)));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    assert_eq!(core.power_on_limit(), 3);

    assert_eq!(start_all(&core, &SIX).await, JobStatus::Succeeded);
    assert_eq!(fake.max_in_flight(), 3);
    assert_eq!(fake.running().len(), 6);
}

#[tokio::test]
async fn the_power_on_limit_is_a_saved_setting() {
    let setup = Setup::new(FakeVmware::default().with_power_delay(Duration::from_millis(40)));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;

    core.set_power_on_limit(1).await.unwrap();
    assert_eq!(start_all(&core, &SIX).await, JobStatus::Succeeded);
    assert_eq!(fake.max_in_flight(), 1);

    // Kept across a restart.
    let again = Core::assemble(
        core.store.clone(),
        core.ctx,
        Adapters {
            vmware: Arc::new(FakeVmware::default()),
            remote: Arc::new(FakeRemote::default()),
            vault: Arc::new(FakeVault::with_password("x")),
            host_counters: Arc::new(FakeHostCounters::default()),
            updater: Arc::new(FakeUpdater::default()),
        },
        JobLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(again.power_on_limit(), 1);

    for bad in [0, JobLimits::MAX_POWER_ON + 1] {
        assert!(matches!(
            core.set_power_on_limit(bad).await,
            Err(CoreError::InvalidSetting(_))
        ));
    }
    assert_eq!(core.power_on_limit(), 1);
    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    assert!(audit
        .iter()
        .any(|e| e.event == "setting_changed" && e.detail.as_deref() == Some("1")));
}

// ---- VM-07: capacity check before power-on -----------------------------------------------------

fn with_ram(fake: FakeVmware, name: &str, gb: u32) -> FakeVmware {
    fake.with_vmx(
        &vmx(name),
        VmxInfo {
            display_name: Some(name.into()),
            memsize_mb: Some(gb * 1024),
            ..Default::default()
        },
    )
}

fn start(names: &[&str]) -> Command {
    Command::VmPower {
        targets: names.iter().map(|n| vm(n)).collect(),
        op: PowerOp::Start { gui: false },
    }
}

#[tokio::test]
async fn starting_vms_that_would_overcommit_host_ram_asks_for_a_confirm() {
    let mut fake = FakeVmware::with_running([vmx("a")]);
    for (name, gb) in [("a", 16), ("b", 20), ("c", 8)] {
        fake = with_ram(fake, name, gb);
    }
    let setup = Setup::new(fake); // the fake host has 32 GB
    let vmware = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();

    // 16 GB running + 8 GB fits.
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, start(&["c"])).await.unwrap() else {
        panic!("enough RAM: no dialog");
    };
    wait_finished(&mut events, job_id).await;

    // 24 GB running + 20 GB does not. Starting is still Low, but the warning needs a confirm.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, start(&["a", "b"])).await.unwrap() else {
        panic!("over the host's RAM: a confirm");
    };
    assert_eq!(request.tier, Tier::Low);
    assert_eq!(request.steps, [ApprovalStep::Confirm]);
    assert_eq!(
        request.warnings,
        ["Running VMs would be assigned 44.0 GB of RAM, more than this host's 32.0 GB."],
        "a is already running, so only b counts as starting"
    );
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "approval_requested");
    assert!(audit[0].detail.as_deref().unwrap().contains("44.0 GB"));

    assert!(core.bus.approve(request.id, ApprovalAnswers::default()).await.is_err());
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(common::running(&vmware), ["a", "b", "c"]);
}

#[tokio::test]
async fn a_nearly_full_vm_drive_asks_for_a_confirm() {
    let mut setup = Setup::new(FakeVmware::default());
    setup.host.free_disk_pct = 5.0;
    let core = setup.build().await;

    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, start(&["a", "b"])).await.unwrap() else {
        panic!("low disk: a confirm");
    };
    assert_eq!(
        request.warnings,
        ["Drive C: has 5.0% free space, under 10%."],
        "one per drive"
    );
}

#[tokio::test]
async fn a_capacity_check_that_cannot_run_is_a_warning_too() {
    let mut setup = Setup::new(FakeVmware::default());
    setup.host.unavailable = true;
    let core = setup.build().await;

    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, start(&["a"])).await.unwrap() else {
        panic!("unchecked capacity: a confirm");
    };
    assert!(request.warnings.iter().all(|w| w.starts_with("Capacity not checked")));
    assert_eq!(request.warnings.len(), 2, "RAM and disk");
}

#[tokio::test]
async fn other_actions_skip_the_capacity_check() {
    let mut setup = Setup::new(FakeVmware::with_running([vmx("a")]));
    setup.host.free_disk_pct = 1.0;
    let core = setup.build().await;
    let unpause = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Unpause,
    };
    assert!(matches!(
        core.bus.submit(&core.ctx, unpause).await.unwrap(),
        SubmitOutcome::Queued { .. }
    ));
}

// ---- VM-03: graceful-then-forced shutdown ------------------------------------------------------

/// Reads job events until `job` finishes: its status and the VMs it reported still running.
async fn finish_with_still_running(
    rx: &mut tokio::sync::broadcast::Receiver<JobEvent>,
    job: uuid::Uuid,
) -> (JobStatus, Vec<String>) {
    let mut still_running = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match rx.recv().await.unwrap() {
                JobEvent::StillRunning { job_id, targets } if job_id == job => {
                    still_running = targets.into_iter().map(|t| t.name).collect();
                }
                JobEvent::Finished { job_id, status } if job_id == job => return (status, still_running.clone()),
                _ => {}
            }
        }
    })
    .await
    .expect("job finished in time")
}

fn high_answers(count: usize) -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(count),
        reason: Some("CHG-1001".into()),
        safety_snapshot: Some(false),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_vm_that_will_not_shut_down_is_left_running_until_a_separate_critical_force_off() {
    let setup = Setup::new(FakeVmware::with_running([vmx("a"), vmx("b")]).unresponsive(&vmx("b")));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();

    // Step 1: soft stop both (High: 2 VMs).
    let soft = Command::VmPower {
        targets: vec![vm("a"), vm("b")],
        op: PowerOp::Stop { mode: StopMode::Soft },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, soft).await.unwrap() else {
        panic!("stopping 2 VMs is High");
    };
    let job = core.bus.approve(request.id, high_answers(2)).await.unwrap();
    let (status, still_running) = finish_with_still_running(&mut events, job).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    assert_eq!(still_running, ["b"]);
    assert_eq!(common::running(&fake), ["b"], "never forced off by the soft stop");
    assert!(!fake.calls().iter().any(|c| c.contains("Hard")));

    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert!(audit[0]
        .detail
        .as_deref()
        .unwrap()
        .contains("still running after the soft stop: b"));

    // Step 2: forcing it off is its own command, at Critical, with the vault password again.
    let hard = Command::VmPower {
        targets: vec![vm("b")],
        op: PowerOp::Stop { mode: StopMode::Hard },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, hard).await.unwrap() else {
        panic!("a hard power-off is Critical");
    };
    assert_eq!(request.tier, Tier::Critical);
    assert!(request.steps.contains(&ApprovalStep::VaultReauth));
    let answers = ApprovalAnswers {
        vault_password: Some(SecretString::new(common::VAULT_PASSWORD)),
        ..high_answers(1)
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert!(common::running(&fake).is_empty());
    assert_eq!(
        fake.calls().last().unwrap(),
        r"power Stop { mode: Hard } C:\VMs\b\b.vmx"
    );
}

#[tokio::test]
async fn a_soft_stop_that_outlasts_the_wait_counts_as_still_running() {
    let setup = Setup::new(FakeVmware::with_running([vmx("a")]).slow_shutdown(&vmx("a")));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.set_shutdown_wait_secs(1).await.unwrap();
    let mut events = core.jobs.subscribe();

    let soft = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Stop { mode: StopMode::Soft },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, soft).await.unwrap() else {
        panic!("stopping one VM is Medium");
    };
    let started = std::time::Instant::now();
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    let (status, still_running) = finish_with_still_running(&mut events, job).await;
    assert!(started.elapsed() >= Duration::from_secs(1), "waited the set time");
    assert_eq!(status, JobStatus::Failed);
    assert_eq!(still_running, ["a"]);
    assert_eq!(common::running(&fake), ["a"]);

    let jobs = core.store.recent_jobs(&core.ctx, 1).await.unwrap();
    assert_eq!(jobs[0].targets_failed, 1);
}

#[tokio::test]
async fn a_clean_shutdown_reports_nothing_still_running() {
    let setup = Setup::new(FakeVmware::with_running([vmx("a")]));
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();
    let soft = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Stop { mode: StopMode::Soft },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, soft).await.unwrap() else {
        panic!("stopping one VM is Medium");
    };
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(
        finish_with_still_running(&mut events, job).await,
        (JobStatus::Succeeded, vec![])
    );
    let vm = core.store.find_vm(&core.ctx, &vmx("a")).await.unwrap();
    assert!(vm.is_none() || vm.unwrap().power_state == PowerState::NotRunning);
}

#[tokio::test]
async fn the_shutdown_wait_is_a_checked_saved_setting() {
    let core = Setup::new(FakeVmware::default()).build().await;
    assert_eq!(core.shutdown_wait_secs(), 120, "default");
    for bad in [0, JobLimits::MAX_SHUTDOWN_WAIT_SECS + 1] {
        assert!(matches!(
            core.set_shutdown_wait_secs(bad).await,
            Err(CoreError::InvalidSetting(_))
        ));
    }
    core.set_shutdown_wait_secs(300).await.unwrap();
    assert_eq!(core.shutdown_wait_secs(), 300);
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].detail.as_deref(), Some("300 s"));
}

// ---- VM-02, VM-03: no power call waits on VMware Tools or an unanswered question ----------------

/// Each target's name and error, in the order the job lists them.
async fn target_errors(core: &Core, job: uuid::Uuid) -> Vec<(String, Option<String>)> {
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    targets.into_iter().map(|t| (t.target_name, t.error)).collect()
}

#[tokio::test]
async fn a_shutdown_without_vmware_tools_is_reported_at_once_instead_of_after_the_wait() {
    let setup = Setup::new(FakeVmware::with_running([vmx("a")]).with_tools(&vmx("a"), ToolsState::Installed));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    assert_eq!(core.shutdown_wait_secs(), 120);
    let mut events = core.jobs.subscribe();

    let soft = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Stop { mode: StopMode::Soft },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, soft).await.unwrap() else {
        panic!("stopping one VM is Medium");
    };
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    // The fake, like vmrun, would wait for Tools for good; the job finishes within the 10 s
    // wait_finished allows, long before the 120 s shutdown wait.
    let (status, still_running) = finish_with_still_running(&mut events, job).await;
    assert_eq!(status, JobStatus::Failed);
    assert_eq!(
        still_running,
        ["a"],
        "so the UI offers the separate, Critical force-off"
    );
    assert!(fake.calls().is_empty(), "vmrun was never asked to stop it");
    assert_eq!(common::running(&fake), ["a"]);
    assert_eq!(
        target_errors(&core, job).await,
        [(
            "a".to_owned(),
            Some(
                "still running: VMware Tools is installed in the guest but not running, so it can't be asked to \
                 shut down. Power it off (hard) to force it; that needs its own approval"
                    .to_owned()
            )
        )]
    );
}

#[tokio::test]
async fn suspend_and_restart_without_vmware_tools_fail_at_once_and_say_why() {
    let setup = Setup::new(
        FakeVmware::with_running([vmx("a"), vmx("b"), vmx("c")])
            .with_tools(&vmx("b"), ToolsState::NotInstalled)
            .with_tools(&vmx("c"), ToolsState::Unknown),
    );
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();

    let suspend = Command::VmPower {
        targets: vec![vm("a"), vm("b"), vm("c")],
        op: PowerOp::Suspend,
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend).await.unwrap() else {
        panic!("suspending 3 VMs is High");
    };
    let job = core.bus.approve(request.id, high_answers(3)).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::PartiallyFailed);
    assert_eq!(
        common::running(&fake),
        ["b", "c"],
        "only a, whose Tools run, was suspended"
    );
    assert_eq!(fake.calls(), [r"power Suspend C:\VMs\a\a.vmx"], "no hard fallback");
    let advice = "Try again once VMware Tools runs in the guest.";
    assert_eq!(
        target_errors(&core, job).await,
        [
            ("a".to_owned(), None),
            (
                "b".to_owned(),
                Some(format!(
                    "VMware Tools is not installed in the guest, so it can't suspend gracefully. {advice}"
                ))
            ),
            (
                "c".to_owned(),
                Some(format!(
                    "Workstation can't tell whether VMware Tools is running in the guest (it may still be \
                     starting), so it can't suspend gracefully. {advice}"
                ))
            ),
        ]
    );

    let restart = Command::VmPower {
        targets: vec![vm("b")],
        op: PowerOp::Reset { mode: StopMode::Soft },
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, restart).await.unwrap() else {
        panic!("restarting one VM is Medium");
    };
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Failed);
    assert_eq!(fake.calls().len(), 1, "vmrun was never asked to restart it");
    assert_eq!(
        target_errors(&core, job).await[0].1.as_deref(),
        Some(
            "VMware Tools is not installed in the guest, so it can't restart gracefully. Reset (hard) forces it; \
             that needs its own approval."
        )
    );
}

#[tokio::test]
async fn a_vm_that_is_not_running_goes_straight_to_vmrun() {
    // No Tools to wait for: vmrun answers at once (the real one with "not powered on").
    let setup = Setup::new(FakeVmware::default());
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();
    let suspend = Command::VmPower {
        targets: vec![vm("a")],
        op: PowerOp::Suspend,
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, suspend).await.unwrap() else {
        panic!("suspending one VM is Medium");
    };
    let job = core.bus.approve(request.id, confirm()).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(fake.calls(), [r"power Suspend C:\VMs\a\a.vmx"]);
}

/// Polls until `done` holds, for at most 5 s.
async fn wait_until(mut done: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("condition met in time");
}

#[tokio::test]
async fn cancel_stops_waiting_for_a_vm_that_waits_for_an_answer_in_workstation() {
    let setup = Setup::new(FakeVmware::default().with_question(&vmx("b")));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let mut events = core.jobs.subscribe();

    let start = Command::VmPower {
        targets: vec![vm("a"), vm("b")],
        op: PowerOp::Start { gui: false },
    };
    let SubmitOutcome::Queued { job_id: job, .. } = core.bus.submit(&core.ctx, start).await.unwrap() else {
        panic!("starting VMs is Low");
    };
    // a starts; b's start waits for an answer that never comes.
    wait_until(|| fake.running().len() == 1 && fake.in_flight() == 1).await;
    assert!(core.jobs.cancel(job));
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Cancelled);
    assert_eq!(fake.in_flight(), 0, "b's call was dropped, which kills vmrun");
    assert_eq!(common::running(&fake), ["a"]);

    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    let outcomes: Vec<_> = targets
        .iter()
        .map(|t| (t.target_name.as_str(), t.status.as_str(), t.error.as_deref()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("a", "succeeded", None),
            (
                "b",
                "cancelled",
                Some("cancelled while vmrun was running; Workstation may still finish the action, so check the VM's state")
            ),
        ]
    );
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "job_finished");
    assert_eq!(audit[0].result.as_deref(), Some("cancelled"));
    assert!(audit[0]
        .detail
        .as_deref()
        .unwrap()
        .ends_with("; cancelled while vmrun was running, so Workstation may still finish it: b"));
}
