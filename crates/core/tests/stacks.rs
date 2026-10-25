//! VM-08, VM-26: stacks end to end on a core with fake hypervisors and a fake clock: a stack deployed as one job in
//! boot order with its readiness checks and delays (nothing sleeps: the waits run on [`FakeStackClock`]), a step not
//! ready in time, a failure mid-stack that cleans up only its own VM, the instance started and stopped in boot
//! order, its teardown deleting exactly its own VMs (never a protected one, or one added by hand unless picked), the
//! capacity planner before a deploy and its suspend suggestion, and the edits' audit and read-only lock. Image files
//! and the VMs' folders are made at run time in the system temp folder; no real VM is made.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::catalog::{AfterDeploy, CloneMode, HashProgress, Image, ImageInput, Network, SourceInput, TemplateInput};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, PowerOp, StopMode, SubmitOutcome};
use remotely_core::deploy::runner::DeployTuning;
use remotely_core::deploy::service::{DeployFrom, DeployRequest};
use remotely_core::domain::{Environment, PowerState, TargetRef};
use remotely_core::fakes::stack_clock::FakeStackClock;
use remotely_core::fakes::{FakeNetwork, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::presentation::Presentation;
use remotely_core::stacks::{Readiness, StackAction, StackDeployRequest, StackInput, StackStep, StackTuning};
use remotely_core::store::MemberOrigin;
use remotely_core::vault::SecretString;
use remotely_core::Core;
use uuid::Uuid;

/// A file that looks like a VMDK (a sparse header).
fn vmdk_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x8800];
    bytes[..4].copy_from_slice(b"KDMV");
    bytes
}

fn write(folder: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = folder.join(name);
    std::fs::File::create(&path).unwrap().write_all(bytes).unwrap();
    path
}

struct Lab {
    core: Core,
    fake: Arc<FakeVmware>,
    network: Arc<FakeNetwork>,
    clock: Arc<FakeStackClock>,
    dir: PathBuf,
    lab: PathBuf,
    image: Image,
}

impl Lab {
    fn vmx(&self, name: &str) -> String {
        self.lab.join(name).join(format!("{name}.vmx")).display().to_string()
    }
}

async fn lab_with(label: &str, vmware: impl FnOnce(&Path) -> FakeVmware) -> Lab {
    let dir = temp_folder(label);
    let lab = dir.join("lab");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let network = Arc::new(FakeNetwork::default());
    let setup = Setup::new(vmware(&lab)).with_network(network.clone());
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.set_deploy_tuning(DeployTuning {
        ip_poll: Duration::from_millis(10),
        ip_wait_cap: Some(Duration::from_millis(100)),
        cleanup_tries: 3,
        cleanup_pause: Duration::from_millis(10),
    });
    let clock = Arc::new(FakeStackClock::default());
    core.set_stack_clock(
        clock.clone(),
        StackTuning {
            poll: Duration::from_secs(5),
            probe_timeout: Duration::from_millis(50),
        },
    );
    let progress: Arc<dyn Fn(HashProgress) + Send + Sync> = Arc::new(|_| {});
    let image = core
        .catalog
        .add_image(
            &core.ctx,
            Uuid::new_v4(),
            ImageInput {
                name: "Noble".into(),
                source: SourceInput::CloudImage {
                    path: image_file.display().to_string(),
                },
                hypervisors: vec![],
                os_profile: "ubuntu".into(),
                notes: None,
            },
            progress,
        )
        .await
        .unwrap();
    Lab {
        core,
        fake,
        network,
        clock,
        dir,
        lab,
        image,
    }
}

async fn lab(label: &str) -> Lab {
    lab_with(label, |_| FakeVmware::default()).await
}

/// A launch template `name` making `<name>-{n}` VMs into the lab folder, with no after-deploy steps.
async fn template(lab: &Lab, name: &str) -> Uuid {
    lab.core
        .catalog
        .add_template(
            &lab.core.ctx,
            TemplateInput {
                name: name.into(),
                image_id: lab.image.id,
                size_id: "gp.small".into(),
                hypervisor: Hypervisor::Vmware,
                vm_folder: Some(lab.lab.display().to_string()),
                network: Network::Nat,
                ssh_key_id: None,
                naming_pattern: format!("{name}-{{n}}"),
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
        .unwrap()
        .id
}

fn step(template: Uuid, count: u32, readiness: Readiness, timeout: u32, delay: u32) -> StackStep {
    StackStep {
        template_id: template,
        count,
        readiness,
        ready_timeout_secs: timeout,
        delay_secs: delay,
    }
}

async fn stack(lab: &Lab, name: &str, steps: Vec<StackStep>) -> Uuid {
    lab.core
        .stacks
        .add(
            &lab.core.ctx,
            StackInput {
                name: name.into(),
                description: None,
                steps,
            },
        )
        .await
        .unwrap()
        .id
}

fn needs_approval(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

/// Approves with every answer the steps ask for, and waits for the job.
async fn approve_and_wait(core: &Core, request: &ApprovalRequest) -> (Uuid, JobStatus) {
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("lab build".into()),
        safety_snapshot: Some(false),
        vault_password: request
            .steps
            .contains(&ApprovalStep::VaultReauth)
            .then(|| SecretString::new(VAULT_PASSWORD)),
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), core.jobs.wait(job))
        .await
        .expect("the job finished in time")
        .unwrap();
    (job, status)
}

async fn run(core: &Core, outcome: SubmitOutcome) -> (Uuid, JobStatus) {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => approve_and_wait(core, &request).await,
        SubmitOutcome::Queued { job_id, .. } => {
            let status = tokio::time::timeout(Duration::from_secs(30), core.jobs.wait(job_id))
                .await
                .unwrap()
                .unwrap();
            (job_id, status)
        }
    }
}

async fn targets_of(core: &Core, job: Uuid) -> Vec<(String, String, Option<String>)> {
    core.store
        .job_targets(&core.ctx, job)
        .await
        .unwrap()
        .into_iter()
        .map(|t| (t.target_name, t.status, t.error))
        .collect()
}

async fn job_end_detail(core: &Core, job: Uuid) -> String {
    core.store
        .recent_audit(&core.ctx, 500)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "job_finished" && e.job_id.as_deref() == Some(job.to_string().as_str()))
        .and_then(|e| e.detail)
        .unwrap_or_default()
}

/// The index of the first call that matches.
fn first(calls: &[String], what: impl Fn(&str) -> bool) -> usize {
    calls
        .iter()
        .position(|c| what(c))
        .unwrap_or_else(|| panic!("no such call in {calls:?}"))
}

#[tokio::test]
async fn a_stack_deploys_as_one_job_in_boot_order_with_its_delays() {
    let lab = lab("stack-order").await;
    let core = &lab.core;
    let ctx = &core.ctx;
    let db = template(&lab, "db").await;
    let web = template(&lab, "web").await;
    let id = stack(
        &lab,
        "web lab",
        vec![
            step(db, 1, Readiness::Tools, 300, 30),
            step(web, 2, Readiness::None, 600, 0),
        ],
    )
    .await;

    // The dialog's check: every VM of every step, and this PC after it.
    let request = StackDeployRequest {
        stack_id: id,
        instance_name: None,
    };
    let check = core.stacks.check_deploy(ctx, &request).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    assert_eq!(check.instance_name, "web lab 1");
    let details = check.details.unwrap();
    assert_eq!(details.action, StackAction::Deploy);
    assert_eq!(
        details.steps.iter().map(|s| s.vms.clone()).collect::<Vec<_>>(),
        [vec!["db-1".to_owned()], vec!["web-1".to_owned(), "web-2".to_owned()]]
    );
    assert_eq!(details.disk_bytes, 3 * 20 * (1 << 30), "gp.small's 20 GB thin disk at its full size, 3 times");
    let capacity = check.capacity.unwrap();
    assert_eq!(capacity.new_vms, 3);
    assert_eq!(capacity.ram.adds_mb, 3 * 2048);
    assert!(capacity.fits, "{:?}", capacity.problems);

    // One approval for all three VMs, in boot order; Medium as a deploy of 3.
    let approval = needs_approval(core.stacks.deploy(ctx, &request).await.unwrap());
    assert_eq!(approval.action, ActionKind::VmDeploy);
    assert_eq!(approval.tier, Tier::Medium);
    assert_eq!(approval.summary, "Deploy stack 'web lab' as 'web lab 1' (3 VMs)");
    let names: Vec<&str> = approval.targets.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["db-1", "web-1", "web-2"]);
    assert_eq!(approval.stack.as_ref().unwrap().steps.len(), 2);
    assert!(approval.capacity.is_some());
    let (job, status) = approve_and_wait(core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded, "{:?}", targets_of(core, job).await);

    // db-1 was made and started before web's VMs were begun; the job waited the 30 s delay on the fake clock, and
    // db-1's Tools ran at the first ask (no wait for them).
    let calls = lab.fake.calls();
    let db_started = first(&calls, |c| c.starts_with("power Start") && c.contains("db-1.vmx"));
    let web_begun = first(&calls, |c| c.contains("web-1") || c.contains("web-2"));
    assert!(db_started < web_begun, "{calls:?}");
    assert_eq!(lab.clock.sleeps(), [Duration::from_secs(30)]);
    let detail = job_end_detail(core, job).await;
    assert!(detail.contains("step 1 ('db') was ready (the guest tools running) after 0 s"), "{detail}");
    assert!(detail.contains("waited 30 s after step 1 ('db')"), "{detail}");

    // The instance holds exactly its three VMs, at their steps.
    let instances = core.stacks.instances(ctx).await.unwrap();
    assert_eq!(instances.len(), 1);
    let instance = &instances[0];
    assert_eq!(instance.name, "web lab 1");
    assert_eq!(instance.stack_name, "web lab");
    assert_eq!(instance.job_id, Some(job));
    let members: Vec<(&str, u32, MemberOrigin)> =
        instance.vms.iter().map(|v| (v.name.as_str(), v.step, v.origin)).collect();
    assert_eq!(
        members,
        [
            ("db-1", 0, MemberOrigin::Deploy),
            ("web-1", 1, MemberOrigin::Deploy),
            ("web-2", 1, MemberOrigin::Deploy)
        ]
    );
    assert!(instance.vms.iter().all(|v| v.power_state == Some(PowerState::Running)));
    // The AP-02 preview of any later action shows them as the instance's.
    let impact = core.bus.submit(
        ctx,
        Command::VmPower {
            targets: vec![TargetRef::Vm { vmx_path: lab.vmx("web-1") }],
            op: PowerOp::Stop { mode: StopMode::Soft },
        },
    );
    let request = needs_approval(impact.await.unwrap());
    let membership = request.impact[0].stack.as_ref().expect("web-1 is the instance's");
    assert_eq!((membership.instance_name.as_str(), membership.step, membership.steps), ("web lab 1", 2, 2));
    core.bus.cancel_approvals(&[request.id], "test").await;
    // A second deploy numbers past the first.
    let check = core.stacks.check_deploy(ctx, &StackDeployRequest { stack_id: id, instance_name: None }).await.unwrap();
    assert_eq!(check.instance_name, "web lab 2");
    let details = check.details.unwrap();
    assert_eq!(details.steps[1].vms, ["web-3", "web-4"]);
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn readiness_waits_on_the_clock_until_the_guest_port_opens() {
    let lab = lab_with("stack-ready", |lab| {
        FakeVmware::default().with_ip(&lab.join("db-1").join("db-1.vmx").display().to_string(), "192.0.2.31")
    })
    .await;
    let core = &lab.core;
    let ctx = &core.ctx;
    let db = template(&lab, "db").await;
    let web = template(&lab, "web").await;
    let id = stack(
        &lab,
        "db first",
        vec![
            step(db, 1, Readiness::SshPort { port: 22 }, 300, 0),
            step(web, 1, Readiness::None, 600, 0),
        ],
    )
    .await;
    // The port opens 20 s in (fake time).
    let network = Arc::clone(&lab.network);
    lab.clock
        .at(Duration::from_secs(20), move || network.set_open("192.0.2.31", 22, true));
    let request = StackDeployRequest {
        stack_id: id,
        instance_name: Some("lab A".into()),
    };
    let (job, status) = run(core, core.stacks.deploy(ctx, &request).await.unwrap()).await;
    assert_eq!(status, JobStatus::Succeeded, "{:?}", targets_of(core, job).await);
    // Asked every 5 s until it answered: four waits, none real.
    assert_eq!(lab.clock.sleeps(), vec![Duration::from_secs(5); 4]);
    let probes = lab.network.calls().iter().filter(|c| c.starts_with("probe 192.0.2.31:22")).count();
    assert_eq!(probes, 5);
    let detail = job_end_detail(core, job).await;
    assert!(detail.contains("was ready (SSH (port 22) open) after 20 s"), "{detail}");
    let calls = lab.fake.calls();
    assert!(lab.fake.has_vm(&lab.vmx("web-1")));
    let db_started = first(&calls, |c| c.starts_with("power Start") && c.contains("db-1.vmx"));
    let web_begun = first(&calls, |c| c.contains("web-1"));
    assert!(db_started < web_begun, "{calls:?}");
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn a_step_not_ready_in_time_stops_the_steps_after_it_and_a_retry_finishes_them() {
    let lab = lab_with("stack-not-ready", |lab| {
        FakeVmware::default().with_ip(&lab.join("db-1").join("db-1.vmx").display().to_string(), "192.0.2.41")
    })
    .await;
    let core = &lab.core;
    let ctx = &core.ctx;
    let db = template(&lab, "db").await;
    let web = template(&lab, "web").await;
    let id = stack(
        &lab,
        "slow db",
        vec![
            step(db, 1, Readiness::SshPort { port: 5432 }, 60, 0),
            step(web, 2, Readiness::None, 600, 0),
        ],
    )
    .await;
    let request = StackDeployRequest {
        stack_id: id,
        instance_name: None,
    };
    let (job, status) = run(core, core.stacks.deploy(ctx, &request).await.unwrap()).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    let targets = targets_of(core, job).await;
    assert_eq!(targets.iter().find(|t| t.0 == "db-1").unwrap().1, "succeeded");
    for name in ["web-1", "web-2"] {
        let t = targets.iter().find(|t| t.0 == name).unwrap();
        assert_eq!(t.1, "skipped", "{t:?}");
        let why = t.2.as_deref().unwrap();
        assert!(why.contains("step 1 ('db') was not ready within 60 s (port 5432 open expected)"), "{why}");
        assert!(why.contains("port 5432 on 192.0.2.41 doesn't answer yet"), "{why}");
        assert!(!lab.lab.join(name).exists(), "{name} was never begun");
    }
    // Exactly the wait's 60 s, in 5 s asks.
    assert_eq!(lab.clock.elapsed(), Duration::from_secs(60));
    let instance = &core.stacks.instances(ctx).await.unwrap()[0];
    assert_eq!(instance.vms.len(), 1, "db-1 stays in the instance");

    // Once the database answers, retrying the job makes the steps that never started, into the same instance.
    lab.network.set_open("192.0.2.41", 5432, true);
    let retry = core.bus.retry_failed(ctx, job, false).await.unwrap();
    let request = needs_approval(retry);
    assert_eq!(
        request.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["web-1", "web-2"]
    );
    let (job, status) = approve_and_wait(core, &request).await;
    assert_eq!(status, JobStatus::Succeeded, "{:?}", targets_of(core, job).await);
    let instance = &core.stacks.instances(ctx).await.unwrap()[0];
    assert_eq!(
        instance.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["db-1", "web-1", "web-2"]
    );
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn a_failure_mid_stack_cleans_up_only_its_own_vm() {
    let lab = lab_with("stack-failure", |_| {
        FakeVmware::with_running([vmx("other")])
            .in_library(&vmx("other"), Some("other"))
    })
    .await;
    let core = &lab.core;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let db = template(&lab, "db").await;
    let app = template(&lab, "app").await;
    let web = template(&lab, "web").await;
    let id = stack(
        &lab,
        "three tier",
        vec![
            step(db, 1, Readiness::None, 600, 10),
            step(app, 1, Readiness::None, 600, 0),
            step(web, 1, Readiness::None, 600, 0),
        ],
    )
    .await;
    // Copying an image fails from 10 s on: after db-1 is made, before app-1's disk is copied.
    let fake = Arc::clone(&lab.fake);
    lab.clock.at(Duration::from_secs(10), move || fake.set_failing("convert", true));
    let request = StackDeployRequest {
        stack_id: id,
        instance_name: None,
    };
    let (job, status) = run(core, core.stacks.deploy(ctx, &request).await.unwrap()).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    let targets = targets_of(core, job).await;
    let status_of = |name: &str| targets.iter().find(|t| t.0 == name).unwrap().1.clone();
    assert_eq!(
        (status_of("db-1"), status_of("app-1"), status_of("web-1")),
        ("succeeded".into(), "failed".into(), "skipped".into())
    );
    let app_error = targets.iter().find(|t| t.0 == "app-1").unwrap().2.clone().unwrap();
    assert!(app_error.contains("what it made was removed"), "{app_error}");
    // app-1's step removed what it made, and only that; db-1 stays, made and in the instance; web-1 never began.
    assert!(lab.lab.join("db-1").exists());
    assert!(lab.fake.has_vm(&lab.vmx("db-1")));
    assert!(!lab.lab.join("app-1").exists());
    assert!(!lab.fake.has_vm(&lab.vmx("app-1")));
    assert!(!lab.lab.join("web-1").exists());
    let web_skip = targets.iter().find(|t| t.0 == "web-1").unwrap().2.clone().unwrap();
    assert!(web_skip.contains("step 2 ('app') didn't finish"), "{web_skip}");
    let instance = &core.stacks.instances(ctx).await.unwrap()[0];
    assert_eq!(instance.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), ["db-1"]);
    // The VM that was here before is untouched.
    assert!(lab.fake.running().iter().any(|p| p.ends_with(r"other\other.vmx")));
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn an_instance_starts_and_stops_in_boot_order_and_tears_down_only_its_own_vms() {
    let lab = lab_with("stack-teardown", |_| {
        FakeVmware::default()
            .in_library(&vmx("tools01"), Some("tools01"))
            .in_library(&vmx("bystander"), Some("bystander"))
    })
    .await;
    let core = &lab.core;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let db = template(&lab, "db").await;
    let web = template(&lab, "web").await;
    let id = stack(
        &lab,
        "web lab",
        vec![step(db, 1, Readiness::Tools, 300, 15), step(web, 2, Readiness::None, 600, 0)],
    )
    .await;
    let (_, status) = run(
        core,
        core.stacks
            .deploy(ctx, &StackDeployRequest { stack_id: id, instance_name: None })
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    let instance_id = core.stacks.instances(ctx).await.unwrap()[0].id;

    // tools01 joins by hand at step 2; web-2 is protected.
    let instance = core.stacks.add_vm(ctx, instance_id, &vmx("tools01"), 1).await.unwrap();
    assert_eq!(instance.vms.iter().find(|v| v.name == "tools01").unwrap().origin, MemberOrigin::Hand);
    let protect = core
        .bus
        .submit(
            ctx,
            Command::VmProtect {
                targets: vec![TargetRef::Vm { vmx_path: lab.vmx("web-2") }],
                protected: true,
            },
        )
        .await
        .unwrap();
    run(core, protect).await;

    // A running instance can't be torn down.
    let err = core.stacks.teardown(ctx, instance_id, &[]).await.unwrap_err().to_string();
    assert!(err.contains("shut the instance down first"), "{err}");

    // Shut down: the last step first, the protected VM left out (AP-04).
    let calls_before = lab.fake.calls().len();
    let approval = needs_approval(core.stacks.power(ctx, instance_id, PowerOp::Stop { mode: StopMode::Soft }).await.unwrap());
    assert_eq!(approval.action, ActionKind::VmStopSoft);
    assert_eq!(
        approval.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["web-1", "db-1"]
    );
    assert_eq!(approval.skipped.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["web-2"]);
    let (_, status) = approve_and_wait(core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded);
    let calls: Vec<String> = lab.fake.calls()[calls_before..].to_vec();
    let web_stop = first(&calls, |c| c.starts_with("power Stop") && c.contains("web-1.vmx"));
    let db_stop = first(&calls, |c| c.starts_with("power Stop") && c.contains("db-1.vmx"));
    assert!(web_stop < db_stop, "{calls:?}");
    // Unprotect web-2 and stop it too, for the teardown.
    let unprotect = Command::VmProtect {
        targets: vec![TargetRef::Vm { vmx_path: lab.vmx("web-2") }],
        protected: false,
    };
    run(core, core.bus.submit(ctx, unprotect).await.unwrap()).await;
    let stop = Command::VmPower {
        targets: vec![TargetRef::Vm { vmx_path: lab.vmx("web-2") }],
        op: PowerOp::Stop { mode: StopMode::Soft },
    };
    run(core, core.bus.submit(ctx, stop).await.unwrap()).await;

    // Start: boot order, waiting for db-1's Tools and the 15 s delay before web.
    let calls_before = lab.fake.calls().len();
    let slept = lab.clock.sleeps().len();
    let (_, status) = run(
        core,
        core.stacks.power(ctx, instance_id, PowerOp::Start { gui: false }).await.unwrap(),
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    let calls: Vec<String> = lab.fake.calls()[calls_before..].to_vec();
    let db_start = first(&calls, |c| c.starts_with("power Start") && c.contains("db-1.vmx"));
    let web_start = first(&calls, |c| c.starts_with("power Start") && c.contains("web-1.vmx"));
    let tools_start = first(&calls, |c| c.starts_with("power Start") && c.contains("tools01.vmx"));
    assert!(db_start < web_start && db_start < tools_start, "{calls:?}");
    assert_eq!(lab.clock.sleeps()[slept..], [Duration::from_secs(15)]);
    let stop = core.stacks.power(ctx, instance_id, PowerOp::Stop { mode: StopMode::Soft }).await.unwrap();
    run(core, stop).await;

    // web-2 protected again: the teardown leaves it, and tools01 (added by hand), and deletes the rest.
    run(
        core,
        core.bus
            .submit(
                ctx,
                Command::VmProtect {
                    targets: vec![TargetRef::Vm { vmx_path: lab.vmx("web-2") }],
                    protected: true,
                },
            )
            .await
            .unwrap(),
    )
    .await;
    let approval = needs_approval(core.stacks.teardown(ctx, instance_id, &[]).await.unwrap());
    assert_eq!(approval.action, ActionKind::StackTeardown);
    assert_eq!(approval.tier, Tier::Critical);
    assert!(approval.steps.contains(&ApprovalStep::VaultReauth));
    assert_eq!(approval.summary, "Tear down stack instance 'web lab 1' (2 VMs)");
    assert_eq!(
        approval.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["db-1", "web-1"]
    );
    assert_eq!(approval.skipped.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["web-2"]);
    let details = approval.stack.as_ref().unwrap();
    assert_eq!(details.action, StackAction::Teardown);
    assert_eq!(details.kept.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), ["tools01"]);
    let change = approval.vm_change.as_ref().expect("R3's delete preview");
    assert_eq!(change.targets.len(), 2);
    assert!(change.targets.iter().all(|t| !t.deletes.is_empty() && t.problem.is_none()), "{change:?}");
    assert!(change.targets[0].deletes.iter().any(|f| f.path.ends_with("db-1.vmx")), "{change:?}");
    let (job, status) = approve_and_wait(core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded, "{:?}", targets_of(core, job).await);
    assert!(!lab.fake.has_vm(&lab.vmx("db-1")));
    assert!(!lab.fake.has_vm(&lab.vmx("web-1")));
    assert!(lab.fake.has_vm(&lab.vmx("web-2")), "protected: never deleted");
    let instance = core.stacks.instance(ctx, instance_id).await.unwrap();
    assert_eq!(
        instance.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["web-2", "tools01"]
    );
    let detail = job_end_detail(core, job).await;
    assert!(detail.contains("stack instance 'web lab 1' keeps these VMs: 'web-2', 'tools01'"), "{detail}");
    // The bystander, in no instance, was never touched.
    assert!(!lab.fake.calls().iter().any(|c| c.contains("bystander")));

    // Forgetting the instance leaves its VMs as they are.
    core.stacks.forget_instance(ctx, instance_id).await.unwrap();
    assert!(core.stacks.instances(ctx).await.unwrap().is_empty());
    assert!(lab.fake.has_vm(&lab.vmx("web-2")));
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn a_hand_added_vm_is_deleted_only_when_picked() {
    let lab = lab_with("stack-hand", |_| FakeVmware::default().in_library(&vmx("tools01"), Some("tools01"))).await;
    let core = &lab.core;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let db = template(&lab, "db").await;
    let id = stack(&lab, "solo", vec![step(db, 1, Readiness::None, 600, 0)]).await;
    run(
        core,
        core.stacks
            .deploy(ctx, &StackDeployRequest { stack_id: id, instance_name: None })
            .await
            .unwrap(),
    )
    .await;
    let instance_id = core.stacks.instances(ctx).await.unwrap()[0].id;
    core.stacks.add_vm(ctx, instance_id, &vmx("tools01"), 0).await.unwrap();
    run(core, core.stacks.power(ctx, instance_id, PowerOp::Stop { mode: StopMode::Soft }).await.unwrap()).await;
    let approval = needs_approval(core.stacks.teardown(ctx, instance_id, &[vmx("tools01")]).await.unwrap());
    assert_eq!(
        approval.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["db-1", "tools01"]
    );
    assert!(approval.stack.as_ref().unwrap().kept.is_empty());
    let (_, status) = approve_and_wait(core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(
        lab.fake.calls().iter().any(|c| c.starts_with("vmrun deleteVM") && c.contains("tools01.vmx")),
        "picked on purpose: deleted"
    );
    // Every VM of it went, so the instance went too, audited.
    assert!(core.stacks.instances(ctx).await.unwrap().is_empty());
    let audit = core.store.recent_audit(ctx, 200).await.unwrap();
    assert!(audit.iter().any(|e| e.event == "stack_changed" && e.action == "Removed a stack instance"));
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn stack_edits_are_audited_checked_and_refused_by_the_read_only_lock() {
    let lab = lab("stack-edits").await;
    let core = &lab.core;
    let ctx = &core.ctx;
    let db = template(&lab, "db").await;
    let input = StackInput {
        name: "web lab".into(),
        description: Some("db, then web".into()),
        steps: vec![step(db, 2, Readiness::Tools, 300, 0)],
    };
    let saved = core.stacks.add(ctx, input.clone()).await.unwrap();
    assert_eq!(saved.vm_count, 2);
    assert!(saved.problems.is_empty(), "{:?}", saved.problems);
    assert_eq!(saved.steps[0].template_name.as_deref(), Some("db"));
    let err = core.stacks.add(ctx, input.clone()).await.unwrap_err().to_string();
    assert!(err.contains("exists already"), "{err}");

    // The editor's live check.
    let mut bad = input.clone();
    bad.steps[0].count = 0;
    let check = core.stacks.check(ctx, &bad).await.unwrap();
    assert!(check.invalid.unwrap().contains("makes no VM"));

    // A deleted template: the stack stays and says why it can't deploy.
    core.catalog.delete_template(ctx, db).await.unwrap();
    let listed = core.stacks.list(ctx).await.unwrap();
    assert!(listed[0].problems[0].contains("its launch template was deleted"), "{:?}", listed[0].problems);
    let check = core
        .stacks
        .check_deploy(ctx, &StackDeployRequest { stack_id: saved.id, instance_name: None })
        .await
        .unwrap();
    assert!(check.details.is_none() && !check.problems.is_empty());

    // Presenting with the read-only lock: no edit.
    let lock = |on: bool| Presentation {
        enabled: on,
        read_only: on,
    };
    core.presentation.set(lock(true)).await.unwrap();
    let err = core
        .stacks
        .add(
            ctx,
            StackInput {
                name: "other".into(),
                ..input.clone()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    assert!(err.to_string().contains("Edit stacks and their instances"), "{err}");
    assert_eq!(core.stacks.delete(ctx, saved.id).await.unwrap_err().code(), "read_only_lock");
    core.presentation.set(lock(false)).await.unwrap();
    core.stacks.delete(ctx, saved.id).await.unwrap();

    let audit = core.store.recent_audit(ctx, 200).await.unwrap();
    let actions: Vec<&str> = audit
        .iter()
        .filter(|e| e.event == "stack_changed")
        .map(|e| e.action.as_str())
        .collect();
    assert!(actions.contains(&"Added the stack 'web lab'"), "{actions:?}");
    assert!(actions.contains(&"Deleted the stack 'web lab'"), "{actions:?}");
    let added = audit.iter().find(|e| e.action == "Added the stack 'web lab'").unwrap();
    assert_eq!(added.tier, None, "no approval tier");
    assert!(added.detail.as_deref().unwrap().contains("step 1: 'db' x2"));
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn the_capacity_planner_shows_this_pc_after_a_deploy_and_what_to_suspend() {
    // 30 GB of a 32 GB PC is assigned to a running VM; a 2 GB VM makes 32 (fits), two make 34 (doesn't).
    let lab = lab_with("stack-capacity", |_| {
        FakeVmware::with_running([vmx("build01")])
            .in_library(&vmx("build01"), Some("build01"))
            .with_vmx(
                &vmx("build01"),
                VmxInfo {
                    display_name: Some("build01".into()),
                    memsize_mb: Some(30 * 1024),
                    num_vcpus: Some(4),
                    ..Default::default()
                },
            )
    })
    .await;
    let core = &lab.core;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let web = template(&lab, "web").await;
    let request = |count| DeployRequest {
        from: DeployFrom::Template { id: web },
        count,
        naming_pattern: None,
        host_adapter: None,
        guest_password_id: None,
    };
    let check = core.deploy.check(ctx, &request(1)).await.unwrap();
    let capacity = check.capacity.unwrap();
    assert_eq!(capacity.ram.running_mb, 30 * 1024);
    assert_eq!(capacity.ram.after_mb, 32 * 1024);
    assert_eq!(capacity.ram.physical_mb, Some(32 * 1024));
    assert_eq!((capacity.cpu.running_vcpus, capacity.cpu.after_vcpus), (4, 5));
    assert!(capacity.fits && capacity.suspend.is_none());

    let check = core.deploy.check(ctx, &request(2)).await.unwrap();
    let capacity = check.capacity.unwrap();
    assert!(!capacity.fits);
    let suspend = capacity.suspend.as_ref().unwrap();
    assert!(suspend.enough);
    assert_eq!(suspend.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), ["build01"]);
    // The approval says it too.
    let approval = needs_approval(core.deploy.submit(ctx, &request(2)).await.unwrap());
    assert!(approval.capacity.as_ref().is_some_and(|c| !c.fits));
    assert!(
        approval.warnings.iter().any(|w| w.contains("Suspending 'build01' would free 30.0 GB")),
        "{:?}",
        approval.warnings
    );
    core.bus.cancel_approvals(&[approval.id], "test").await;

    // A protected VM is never suggested.
    run(
        core,
        core.bus
            .submit(
                ctx,
                Command::VmProtect {
                    targets: vec![common::vm("build01")],
                    protected: true,
                },
            )
            .await
            .unwrap(),
    )
    .await;
    let capacity = core.deploy.check(ctx, &request(2)).await.unwrap().capacity.unwrap();
    assert!(!capacity.fits);
    assert!(capacity.suspend.is_none());
    std::fs::remove_dir_all(&lab.dir).unwrap();
}

#[tokio::test]
async fn vm_07_at_power_on_names_vms_to_suspend() {
    let lab = lab_with("stack-vm07", |_| {
        FakeVmware::with_running([vmx("big")])
            .in_library(&vmx("big"), Some("big"))
            .in_library(&vmx("new"), Some("new"))
            .with_vmx(
                &vmx("big"),
                VmxInfo {
                    display_name: Some("big".into()),
                    memsize_mb: Some(24 * 1024),
                    num_vcpus: Some(2),
                    ..Default::default()
                },
            )
            .with_vmx(
                &vmx("new"),
                VmxInfo {
                    display_name: Some("new".into()),
                    memsize_mb: Some(16 * 1024),
                    num_vcpus: Some(2),
                    ..Default::default()
                },
            )
    })
    .await;
    let core = &lab.core;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let outcome = core
        .bus
        .submit(
            ctx,
            Command::VmPower {
                targets: vec![common::vm("new")],
                op: PowerOp::Start { gui: false },
            },
        )
        .await
        .unwrap();
    let request = needs_approval(outcome);
    assert!(request.warnings.iter().any(|w| w.contains("more than this host's 32.0 GB")), "{:?}", request.warnings);
    assert!(
        request.warnings.iter().any(|w| w.contains("Suspending 'big' would free 24.0 GB")),
        "{:?}",
        request.warnings
    );
    std::fs::remove_dir_all(&lab.dir).unwrap();
}
