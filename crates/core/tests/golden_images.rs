//! VM-30 (0.8.0 G7): golden image builds end to end on a core with fake hypervisors. The ISOs are small images made at
//! run time (`fakes::install_isos`), the installers are played by the test writing the lines S1 to S3 saw into each
//! VM's serial log, the installed system's SSH is a banner on 127.0.0.1, the Linux generalization a fake guest shell
//! that powers the fake VM off, and Windows' WinRM a fake client whose sysprep task powers it off. Everything lives in
//! the system temp folder; no real VM, ISO or host is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use common::{temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::adapters::exec_output::OutputCollector;
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::adapters::remote::{ExecResult, ExecSession, ScriptKind, SecretPromptShown};
use remotely_core::adapters::virtualbox::VirtualBoxAdapter;
use remotely_core::adapters::vmware::VmwareAdapter;
use remotely_core::adapters::winrm::console::ConsoleShell;
use remotely_core::adapters::winrm::http::CERT_KEY_TYPE;
use remotely_core::adapters::winrm::{WinrmAdapter, WinrmConnect, WinrmSession};
use remotely_core::catalog::install::{starters, InstallConfigInput, SecretRefKind};
use remotely_core::catalog::{
    AfterDeploy, CloneMode, HashProgress, Image, ImageInput, ImageSource, Network, SourceInput, TemplateInput,
};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, PowerOp, StopMode, SubmitOutcome};
use remotely_core::deploy::runner::{DeployTuning, GuestShell, LinuxGuest};
use remotely_core::deploy::service::{DeployFrom, DeployRequest};
use remotely_core::domain::{Environment, PowerState};
use remotely_core::fakes::{install_isos, FakeVirtualBox, FakeVmware};
use remotely_core::golden::{generic, BuildRecipe, BuildRequest, BuildTarget, VersionState};
use remotely_core::jobs::{JobEvent, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::vault::{SecretId, SecretKind, SecretString, UnlockMethod};
use remotely_core::{Core, CoreError};
use uuid::Uuid;

/// What a generalization prints when every step went (as `golden::generic::LINUX_SCRIPT`'s `say` lines).
fn linux_report() -> String {
    let mut out = String::from(
        "remotely-generic cloud-init yes\nremotely-generic removed /etc/cloud/cloud.cfg.d/99-installer.cfg\n",
    );
    for step in generic::LINUX_STEPS {
        out.push_str(&format!("remotely-generic ok {step}\n"));
    }
    out.push_str("remotely-generic vm-tools yes\nremotely-generic done\n");
    out
}

const FINGERPRINT: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

/// The installed system's SSH: a banner on 127.0.0.1 (the deploy's probe goes here instead of the guest).
async fn ssh_banner() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.6 test\r\n").await;
        }
    });
    port
}

fn fast(core: &Core, ssh_port: u16) {
    tuned(core, ssh_port, Duration::from_secs(20));
}

/// The deploy's waits made short; `cap` bounds the install's, the generalization's and the shutdown's.
fn tuned(core: &Core, ssh_port: u16, cap: Duration) {
    core.set_deploy_tuning(DeployTuning {
        ip_poll: Duration::from_millis(10),
        ip_wait_cap: Some(Duration::from_millis(500)),
        cleanup_tries: 3,
        cleanup_pause: Duration::from_millis(10),
        install_poll: Duration::from_millis(20),
        install_cap: Some(cap),
        hang_silence: Duration::from_secs(60),
        connect_wait: Duration::from_millis(500),
        leases_file: None,
        probe: Some(("127.0.0.1".into(), ssh_port, 1)),
        ..DeployTuning::default()
    });
}

/// A password made at run time, never a literal in the repo.
fn password() -> String {
    format!("Pw-{}-x", Uuid::new_v4().simple())
}

async fn vault_password(core: &Core, value: &str) -> SecretId {
    core.vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            &format!("build admin {}", &Uuid::new_v4().simple().to_string()[..6]),
            SecretString::new(value),
        )
        .await
        .unwrap()
        .id
}

async fn build_key(core: &Core) -> SecretId {
    core.keys
        .generate(
            &core.ctx(),
            GenerateKey {
                label: "build key".into(),
                key_type: KeyType::Ed25519,
                comment: "alice@example.com".into(),
            },
        )
        .await
        .unwrap()
        .id
}

/// A starter copied as an own config with its vault items picked; `edit` changes its file first.
async fn config_from(
    core: &Core,
    starter: &str,
    password: SecretId,
    key: Option<SecretId>,
    edit: impl Fn(&mut InstallConfigInput),
) -> Uuid {
    let mut spec = starters::all().into_iter().find(|c| c.id == starter).unwrap().spec;
    spec.name = format!("{} ({})", spec.name, &Uuid::new_v4().simple().to_string()[..6]);
    edit(&mut spec);
    for s in &mut spec.secrets {
        s.secret_id = match s.kind {
            SecretRefKind::Password => Some(password),
            SecretRefKind::SshKey => key,
        };
    }
    let saved = core.catalog.add_install_config(&core.ctx(), spec).await.unwrap();
    assert!(saved.can_deploy(), "{:?}", saved.problems);
    Uuid::parse_str(&saved.id).unwrap()
}

async fn iso_image(core: &Core, dir: &Path, name: &str, bytes: &[u8], profile: &str) -> Image {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    let progress: Arc<dyn Fn(HashProgress) + Send + Sync> = Arc::new(|_| {});
    core.catalog
        .add_image(
            &core.ctx(),
            Uuid::new_v4(),
            ImageInput {
                name: name.into(),
                source: SourceInput::Iso {
                    path: path.display().to_string(),
                },
                hypervisors: vec![],
                os_profile: profile.into(),
                notes: None,
            },
            progress,
        )
        .await
        .unwrap()
}

fn recipe(iso: &Image, config: Uuid, hypervisor: Hypervisor, folder: &Path, size: &str) -> BuildRecipe {
    BuildRecipe {
        iso_image_id: iso.id,
        install_config_id: config,
        size_id: size.into(),
        hypervisor,
        network: Network::Nat,
        host_adapter: None,
        vm_folder: Some(folder.display().to_string()),
        values: Default::default(),
        address_pool_id: None,
        install_minutes: 60,
        keep: None,
    }
}

fn needs_approval(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

async fn approve(core: &Core, request: &ApprovalRequest) -> Uuid {
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("golden build".into()),
        safety_snapshot: request
            .steps
            .iter()
            .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. }))
            .then_some(false),
        vault_password: request
            .steps
            .contains(&ApprovalStep::VaultReauth)
            .then(|| SecretString::new(VAULT_PASSWORD)),
        change_id: None,
    };
    core.bus.approve(request.id, answers).await.unwrap()
}

async fn wait(core: &Core, job: Uuid) -> JobStatus {
    tokio::time::timeout(Duration::from_secs(60), core.jobs.wait(job))
        .await
        .expect("the build finished in time")
        .unwrap()
}

async fn notes_of(core: &Core, job: Uuid) -> String {
    core.store
        .job_targets(&core.ctx(), job)
        .await
        .unwrap()
        .into_iter()
        .map(|t| {
            format!(
                "{} {} {} {}",
                t.target_name,
                t.status,
                t.output.unwrap_or_default(),
                t.error.unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Plays an installer: once the VM's folder has its seed, writes `lines` into its serial log one by one.
fn installer(serial: PathBuf, lines: Vec<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..3000 {
            if serial.with_file_name("install-seed").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !serial.with_file_name("install-seed").exists() {
            // The build never made its VM: the test's own assertions say why.
            return;
        }
        for line in lines {
            tokio::time::sleep(Duration::from_millis(40)).await;
            append(&serial, line.as_bytes());
        }
    })
}

fn append(path: &Path, text: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    file.write_all(text).unwrap();
}

fn ubuntu_lines(host: &str) -> Vec<String> {
    vec![
        "[    0.000000] Command line: BOOT_IMAGE=/casper/vmlinuz autoinstall console=tty0 console=ttyS0,115200n8 ---\r\n".into(),
        "start: subiquity/Install/install/curthooks: configuring\r\n".into(),
        "start: subiquity/Shutdown/shutdown: mode=REBOOT\r\n[  400.1] reboot: Restarting system\r\n".into(),
        "[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-6.8.0-45-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro\r\n".into(),
        format!("\r\n{host} login: "),
    ]
}

fn debian_lines(host: &str) -> Vec<String> {
    vec![
        "\x1b[1;1H Detecting hardware to find installation media\x1b[2;1H".into(),
        "\x1b[5;3H\x1b[31mInstalling the base system\x1b[0m\x1b[6;1H".into(),
        "\r\nreboot: Restarting system\r\n GNU GRUB  version 2.06\r\n".into(),
        format!("Debian GNU/Linux 12 {host} ttyS0\r\n\r\n{host} login: "),
    ]
}

/// One generalization run: (vm, user, sudo password given, script, power off).
type GuestRun = (String, String, Option<String>, String, String);

/// How the fake Linux build VM ends its generalization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum GuestEnd {
    /// It shuts itself down, as the script's power-off does.
    #[default]
    PowersOff,
    /// VirtualBox: its process crashes (`aborted`) instead of shutting down (A4).
    Aborts,
    /// The run never answers (Q3).
    Hangs,
    /// It shuts down, and then Workstation can't write its settings (A6).
    PowersOffSettingsLocked,
    /// VirtualBox: it shuts down, and VBoxHeadless holds its session lock for this many more changes (N2).
    PowersOffSessionHeld(u32),
}

/// The Linux build VM as the test plays it: the generalization's report, then the guest powers itself off.
struct FakeGuest {
    report: Mutex<String>,
    vmware: Arc<FakeVmware>,
    virtualbox: Arc<FakeVirtualBox>,
    /// The deploy's folder (each VM's is `<folder>\<name>`).
    folder: PathBuf,
    /// (vm, user, sudo password given, script, power off).
    runs: Mutex<Vec<GuestRun>>,
    end: Mutex<GuestEnd>,
    /// Q2: for each run, whether the VM's seed was out of its drive, its answer file gone, as the run started.
    seed_out: Mutex<Vec<bool>>,
    /// C1: holds each run until notified (a build in progress).
    gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
}

fn holds(bytes: &[u8], text: &[u8]) -> bool {
    bytes.windows(text.len()).any(|w| w == text)
}

#[async_trait]
impl GuestShell for FakeGuest {
    async fn linux(
        &self,
        guest: &LinuxGuest<'_>,
        script: &str,
        power_off: &str,
    ) -> remotely_core::error::Result<String> {
        assert!(
            guest.key.expose().contains("PRIVATE KEY"),
            "the config's private key from the vault"
        );
        let vmx = self.folder.join(guest.vm).join(format!("{}.vmx", guest.vm));
        let workstation = self.vmware.has_vm(&vmx.display().to_string());
        let seed = self
            .folder
            .join(guest.vm)
            .join("install-seed")
            .join(format!("{}-seed.iso", guest.vm));
        let answers_gone = std::fs::read(&seed).map_or(true, |b| !holds(&b, b"autoinstall") && !holds(&b, b"d-i "));
        let ejected = if workstation {
            self.vmware
                .calls()
                .iter()
                .any(|c| c.starts_with("vmrun disconnectNamedDevice") && c.contains(guest.vm))
        } else {
            !seed.exists()
        };
        self.seed_out.lock().unwrap().push(answers_gone && ejected);
        self.runs.lock().unwrap().push((
            guest.vm.to_owned(),
            guest.user.to_owned(),
            guest.sudo_password.as_ref().map(|p| p.expose().to_owned()),
            script.to_owned(),
            power_off.to_owned(),
        ));
        let gate = self.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.notified().await;
        }
        let end = *self.end.lock().unwrap();
        let report = self.report.lock().unwrap().clone();
        // N4 of PR 100's second review: as SshGuestShell, the power-off only after every step went.
        let whole = generic::Report::parse(&report).linux_problems().is_empty();
        match end {
            GuestEnd::Hangs => tokio::time::sleep(Duration::from_secs(3600)).await,
            GuestEnd::Aborts => {
                let vm = self.virtualbox.vm_named(guest.vm).expect("a VirtualBox build VM");
                self.virtualbox.abort(&vm.uuid);
            }
            _ if !whole => {}
            GuestEnd::PowersOff | GuestEnd::PowersOffSettingsLocked | GuestEnd::PowersOffSessionHeld(_) => {
                if workstation {
                    self.vmware
                        .power(&vmx, PowerOp::Stop { mode: StopMode::Hard })
                        .await
                        .unwrap();
                    if end == GuestEnd::PowersOffSettingsLocked {
                        self.vmware.set_failing_vmx_write(true);
                    }
                } else if let Some(vm) = self.virtualbox.vm_named(guest.vm) {
                    self.virtualbox
                        .power(&vm.uuid, PowerOp::Stop { mode: StopMode::Hard })
                        .await
                        .unwrap();
                    if let GuestEnd::PowersOffSessionHeld(changes) = end {
                        self.virtualbox.hold_session(&vm.uuid, changes);
                    }
                }
            }
        }
        Ok(report)
    }
}

struct Lab {
    core: Core,
    dir: PathBuf,
    vms: PathBuf,
    vmware: Arc<FakeVmware>,
    virtualbox: Arc<FakeVirtualBox>,
    guest: Arc<FakeGuest>,
    secret: String,
    ssh: u16,
}

async fn lab(label: &str, vm_ips: &[&str]) -> Lab {
    let dir = temp_folder(label);
    let vms = dir.join("vms");
    let mut vmware = FakeVmware::default();
    for (i, name) in vm_ips.iter().enumerate() {
        let vmx = vms.join(name).join(format!("{name}.vmx"));
        vmware = vmware.with_ip(&vmx.display().to_string(), &format!("192.0.2.{}", 40 + i));
    }
    let setup = Setup::new(vmware)
        .with_virtualbox(FakeVirtualBox::new())
        .with_real_vault();
    let (vmware, virtualbox) = (Arc::clone(&setup.vmware), Arc::clone(&setup.virtualbox));
    let core = setup.build().await;
    let ssh = ssh_banner().await;
    fast(&core, ssh);
    let guest = Arc::new(FakeGuest {
        report: Mutex::new(linux_report()),
        vmware: Arc::clone(&vmware),
        virtualbox: Arc::clone(&virtualbox),
        folder: vms.clone(),
        runs: Mutex::new(Vec::new()),
        end: Mutex::default(),
        seed_out: Mutex::default(),
        gate: Mutex::default(),
    });
    core.set_guest_shell(guest.clone());
    Lab {
        core,
        dir,
        vms,
        vmware,
        virtualbox,
        guest,
        secret: password(),
        ssh,
    }
}

/// Builds and approves; returns the job and its status.
async fn build(lab: &Lab, request: &BuildRequest, lines: Vec<String>) -> (Uuid, JobStatus, String) {
    let ctx = &lab.core.ctx();
    let approval = needs_approval(lab.core.golden.submit(ctx, request).await.unwrap());
    let vm = approval.image_build.as_ref().unwrap().vm_name.clone();
    let play = installer(lab.vms.join(&vm).join(format!("{vm}-serial.log")), lines);
    let job = approve(&lab.core, &approval).await;
    let status = wait(&lab.core, job).await;
    play.await.unwrap();
    (job, status, notes_of(&lab.core, job).await)
}

async fn template_of(core: &Core, image: &Image, hypervisor: Hypervisor, folder: &Path, clone_mode: CloneMode) -> Uuid {
    core.catalog
        .add_template(
            &core.ctx(),
            TemplateInput {
                name: "web".into(),
                image_id: image.id,
                size_id: "gp.medium".into(),
                hypervisor,
                vm_folder: Some(folder.display().to_string()),
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
                clone_mode,
                install_config_id: None,
            },
        )
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn an_ubuntu_build_on_workstation_makes_a_generic_versioned_image_and_a_rebuild_its_next_version() {
    let lab = lab("golden-ubuntu", &["ubuntu-golden-v1", "ubuntu-golden-v2"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Ubuntu golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };

    // The dialog's check: what it builds, where, and what makes it generic.
    let check = core.golden.check(ctx, &request).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let preview = check.preview.unwrap();
    assert_eq!(preview.details.vm_name, "ubuntu-golden-v1");
    assert_eq!(preview.details.version, 1);
    assert!(preview.details.new_image);
    assert!(
        preview.details.sign_in.contains("sysadmin"),
        "{}",
        preview.details.sign_in
    );
    assert!(preview.details.steps.iter().any(|s| s.contains("cloud-init")));
    assert!(
        preview.warnings.iter().any(|w| w.contains("open-vm-tools")),
        "ubuntu-server-minimal on Workstation: {:?}",
        preview.warnings
    );

    // Medium, with the vault password asked again (the answer file and sudo get the vault's password).
    let approval = needs_approval(core.golden.submit(ctx, &request).await.unwrap());
    assert_eq!(approval.action, ActionKind::ImageBuild);
    assert_eq!(approval.tier, Tier::Medium);
    assert!(
        approval.steps.contains(&ApprovalStep::VaultReauth),
        "{:?}",
        approval.steps
    );
    assert!(approval.deploy.is_some(), "the build VM's deploy preview");
    let play = installer(
        lab.vms.join("ubuntu-golden-v1").join("ubuntu-golden-v1-serial.log"),
        ubuntu_lines("ubuntu-golden-v1"),
    );
    let job = approve(core, &approval).await;
    let status = wait(core, job).await;
    play.await.unwrap();
    let notes = notes_of(core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    assert!(notes.contains("turned cloud-init back on and cleaned it"), "{notes}");
    assert!(notes.contains("emptied the machine id"), "{notes}");
    assert!(
        notes.contains("snapshot 'Remotely image v1' taken, powered off"),
        "{notes}"
    );
    // Q2 of PR 100's review: the seed (the answer file) left the VM before it was made generic.
    assert!(
        notes.contains("its seed (the answer file) is taken out and emptied"),
        "{notes}"
    );
    assert_eq!(*lab.guest.seed_out.lock().unwrap(), [true]);

    // Made generic as the config's user, through sudo with its vault password; then powered off on the same connection.
    let runs = lab.guest.runs.lock().unwrap().clone();
    assert_eq!(runs.len(), 1);
    let (vm, user, sudo, script, power_off) = &runs[0];
    assert_eq!((vm.as_str(), user.as_str()), ("ubuntu-golden-v1", "sysadmin"));
    assert_eq!(sudo.as_deref(), Some(lab.secret.as_str()));
    assert!(script.contains("cloud-init clean --logs"));
    assert_eq!(power_off, "systemctl --no-block poweroff");

    // The image: a golden VM at its version's snapshot, with its recipe; version 1.
    let images = core.catalog.images(ctx).await.unwrap();
    let image = images
        .iter()
        .find(|i| i.name == "Ubuntu golden")
        .expect("the image is made");
    let vmx = lab.vms.join("ubuntu-golden-v1").join("ubuntu-golden-v1.vmx");
    match &image.source {
        ImageSource::GoldenVm {
            vm_key, snapshot_name, ..
        } => {
            assert_eq!(vm_key.to_lowercase(), vmx.display().to_string().to_lowercase());
            assert_eq!(snapshot_name, "Remotely image v1");
        }
        other => panic!("a golden VM image, not {other:?}"),
    }
    assert_eq!(image.version, Some(1));
    assert_eq!(image.build.as_ref().unwrap().install_config_id, config);
    assert_eq!(image.os_profile, "ubuntu");
    assert_eq!(image.problem, None, "{:?}", image.problem);
    assert_eq!(
        lab.vmware.snapshot_names(&vmx.display().to_string()),
        ["Remotely image v1"],
        "only the image's snapshot: no clean install snapshot, no session"
    );

    // Its clones copy nothing of the install: no install drives, no serial port; the seed, the ISO copy and the
    // serial log are gone.
    let text = lab.vmware.vmx_text(&vmx.display().to_string()).unwrap();
    for gone in ["-install.iso", "-seed.iso", "serial0."] {
        assert!(!text.contains(gone), "{gone} in {text}");
    }
    let folder = lab.vms.join("ubuntu-golden-v1");
    for file in ["ubuntu-golden-v1-install.iso", "ubuntu-golden-v1-serial.log"] {
        assert!(!folder.join(file).exists(), "{file}");
    }
    assert!(!folder.join("install-seed").exists());
    assert!(core.sessions.list(ctx, &Default::default()).await.unwrap().is_empty());
    // Rule 7: no password or hash in the job or the audit log.
    let audit = format!("{:?}", core.store.recent_audit(ctx, 300).await.unwrap());
    assert!(audit.contains("Built image 'Ubuntu golden' (version 1)"), "{audit}");
    for leak in [lab.secret.as_str(), "$6$"] {
        assert!(!audit.contains(leak), "the audit log holds {leak}");
        assert!(!notes.contains(leak), "the job holds {leak}");
    }

    // A template that uses the image deploys its newest version.
    let template = template_of(
        core,
        image,
        Hypervisor::Vmware,
        &lab.dir.join("clones"),
        CloneMode::Linked,
    )
    .await;
    let first = core.catalog.plan(ctx, template, 1).await.unwrap().unwrap();
    assert!(
        matches!(&first.image.source, ImageSource::GoldenVm { snapshot_name, .. } if snapshot_name == "Remotely image v1")
    );

    // Rebuild: version 2, a VM of its own; the image and its template move to it, version 1 stays.
    let rebuild = core.golden.rebuild_request(ctx, image.id).await.unwrap();
    let (job, status, notes) = build(&lab, &rebuild, ubuntu_lines("ubuntu-golden-v2")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    assert!(notes.contains("registered as version 2"), "{notes}");
    let image = core.catalog.image(ctx, image.id).await.unwrap();
    assert_eq!(image.version, Some(2));
    let second = core.catalog.plan(ctx, template, 1).await.unwrap().unwrap();
    match &second.image.source {
        ImageSource::GoldenVm {
            vm_key, snapshot_name, ..
        } => {
            assert!(vm_key.to_lowercase().ends_with("ubuntu-golden-v2.vmx"), "{vm_key}");
            assert_eq!(snapshot_name, "Remotely image v2");
        }
        other => panic!("{other:?}"),
    }
    let versions = core.golden.versions(ctx, image.id).await.unwrap();
    assert_eq!(
        versions.iter().map(|v| (v.number, v.state)).collect::<Vec<_>>(),
        [(2, VersionState::Newest), (1, VersionState::Kept)]
    );
    assert_eq!(versions[0].facts["cloudInit"], serde_json::json!(true));
    assert!(lab.vmware.has_vm(&vmx.display().to_string()), "version 1's VM stays");
    let _ = job;

    // B4 of PR 100's review: a build of the image's next version builds from its saved settings, never others.
    let mut other = rebuild.clone();
    other.recipe.install_minutes = 90;
    let refused = core.golden.submit(ctx, &other).await.unwrap_err().to_string();
    assert!(refused.contains("build settings first"), "{refused}");

    // C3 of PR 100's review: version 2's VM deleted by hand marks the version deleted, and the image (and its
    // template) deploy version 1 again.
    let v2 = lab.vms.join("ubuntu-golden-v2").join("ubuntu-golden-v2.vmx");
    let delete = remotely_core::command_bus::Command::VmLifecycle {
        targets: vec![remotely_core::domain::TargetRef::Vm {
            vmx_path: v2.display().to_string(),
        }],
        op: remotely_core::vm_settings::VmLifecycleOp::Delete,
    };
    let asked = needs_approval(core.bus.submit(ctx, delete).await.unwrap());
    let job = approve(core, &asked).await;
    let status = wait(core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{}", notes_of(core, job).await);
    let versions = core.golden.versions(ctx, image.id).await.unwrap();
    assert_eq!(
        versions.iter().map(|v| (v.number, v.state)).collect::<Vec<_>>(),
        [(2, VersionState::Deleted), (1, VersionState::Newest)]
    );
    let image = core.catalog.image(ctx, image.id).await.unwrap();
    assert_eq!(image.version, Some(1));
    assert!(
        matches!(&image.source, ImageSource::GoldenVm { snapshot_name, .. } if snapshot_name == "Remotely image v1")
    );
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn retention_keeps_the_newest_and_any_version_a_linked_clone_uses() {
    let lab = lab("golden-keep", &["deb-golden-v1", "deb-golden-v2", "deb-golden-v3"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.debian-12-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "bookworm.iso", &install_isos::debian(), "debian").await;
    let mut first = BuildRequest {
        target: BuildTarget::New {
            name: "Deb golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    first.recipe.keep = Some(1);
    // Keeping only the newest deletes VMs: rated as deleting VMs.
    let approval = needs_approval(core.golden.submit(ctx, &first).await.unwrap());
    assert_eq!(approval.action, ActionKind::ImageBuildPrune);
    assert_eq!(approval.tier, Tier::Critical);
    let check = core.golden.check(ctx, &first).await.unwrap();
    assert!(
        check
            .preview
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("installs no cloud-init")),
        "Debian's starter installs no cloud-init"
    );
    let (_, status, notes) = build(&lab, &first, debian_lines("deb-golden-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Deb golden")
        .unwrap();
    let v1 = lab.vms.join("deb-golden-v1").join("deb-golden-v1.vmx");
    // A linked clone of version 1: it must stay while the clone needs it.
    let clone = lab.dir.join("clones").join("web-1").join("web-1.vmx");
    lab.vmware.add_linked_clone(&v1, "Remotely image v1", &clone);
    lab.vmware.set_file(&clone.display().to_string(), true);

    let rebuild = core.golden.rebuild_request(ctx, image.id).await.unwrap();
    let (_, status, notes) = build(&lab, &rebuild, debian_lines("deb-golden-v2")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    assert!(notes.contains("version 1 stays"), "{notes}");
    assert!(
        lab.vmware.has_vm(&v1.display().to_string()),
        "a linked clone uses version 1"
    );

    // Version 3: version 2 (no clone) goes with its VM, version 1 still stays for its clone.
    let (_, status, notes) = build(&lab, &rebuild, debian_lines("deb-golden-v3")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    assert!(
        notes.contains("version 2 deleted with its VM 'deb-golden-v2'"),
        "{notes}"
    );
    assert!(notes.contains("version 1 stays"), "{notes}");
    let v2 = lab.vms.join("deb-golden-v2").join("deb-golden-v2.vmx");
    assert!(
        !lab.vmware.has_vm(&v2.display().to_string()),
        "version 2's VM is deleted"
    );
    assert!(lab.vmware.has_vm(&v1.display().to_string()));
    let versions = core.golden.versions(ctx, image.id).await.unwrap();
    assert_eq!(
        versions.iter().map(|v| (v.number, v.state)).collect::<Vec<_>>(),
        [
            (3, VersionState::Newest),
            (2, VersionState::Deleted),
            (1, VersionState::Kept)
        ]
    );
    assert_eq!(versions[2].linked_clones, ["web-1"], "{versions:?}");
    let audit = format!("{:?}", core.store.recent_audit(ctx, 300).await.unwrap());
    assert!(audit.contains("Deleted version 2 of image 'Deb golden'"), "{audit}");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_debian_build_on_virtualbox_takes_out_its_drives_serial_port_and_nat_rule() {
    let lab = lab("golden-vbox", &[]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.debian-12-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "bookworm.iso", &install_isos::debian(), "debian").await;
    let request = BuildRequest {
        target: BuildTarget::New { name: "Deb box".into() },
        recipe: recipe(&iso, config, Hypervisor::VirtualBox, &lab.vms, "gp.medium"),
    };
    // N2 of PR 100's second review: VBoxHeadless still holds the session lock for a moment after the power-off.
    *lab.guest.end.lock().unwrap() = GuestEnd::PowersOffSessionHeld(2);
    let (_, status, notes) = build(&lab, &request, debian_lines("deb-box-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    // The seal's two drives out (`--medium none`), the first asked twice more while the lock was held.
    let detaches = lab
        .virtualbox
        .calls()
        .iter()
        .filter(|c| c.starts_with("change storageattach") && c.contains("--medium none"))
        .count();
    assert_eq!(detaches, 4, "the seal asked again");
    let vm = lab.virtualbox.vm_named("deb-box-v1").expect("the version's VM");
    assert_eq!(lab.virtualbox.power_state(&vm.uuid), PowerState::NotRunning);
    assert_eq!(lab.virtualbox.snapshot_names(&vm.uuid), ["Remotely image v1"]);
    assert!(vm.dvds.iter().all(|d| d.image.is_none()), "{:?}", vm.dvds);
    let calls = lab.virtualbox.calls().join("\n");
    for want in ["--medium none", "--uart1 off", "--natpf1 delete remotely-install"] {
        assert!(calls.contains(want), "{want} in {calls}");
    }
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Deb box")
        .unwrap();
    assert_eq!(image.hypervisors, [Hypervisor::VirtualBox]);
    assert!(matches!(&image.source, ImageSource::GoldenVm { vm_key, .. } if *vm_key == vm.uuid));
    let _ = lab.ssh;
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_locked_vault_holds_the_build_until_it_is_unlocked() {
    let lab = lab("golden-vault", &["vault-golden-v1"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Vault golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let approval = needs_approval(core.golden.submit(ctx, &request).await.unwrap());
    let mut events = core.jobs.subscribe();
    core.vault.lock(ctx).await.unwrap();
    let job = approve(core, &approval).await;
    let waited = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(JobEvent::TargetProgress { step, .. }) = events.recv().await {
                if step.starts_with("waiting for the vault to be unlocked") {
                    return;
                }
            }
        }
    })
    .await;
    assert!(waited.is_ok(), "the step said it waits for the vault");
    assert!(
        !lab.vms.join("vault-golden-v1").exists(),
        "nothing is made while the vault is locked"
    );
    let play = installer(
        lab.vms.join("vault-golden-v1").join("vault-golden-v1-serial.log"),
        ubuntu_lines("vault-golden-v1"),
    );
    core.vault
        .unlock(ctx, UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)))
        .await
        .unwrap();
    let status = wait(core, job).await;
    play.await.unwrap();
    let notes = notes_of(core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn builds_refuse_what_they_cant_make_generic() {
    let lab = lab("golden-refuse", &[]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    // Kickstart has no spike, so Remotely doesn't deliver it.
    let rocky = iso_image(core, &lab.dir, "rocky.iso", &install_isos::ubuntu_24_04(), "rhel").await;
    let kickstart = config_from(core, "starter.rocky-9-minimal", pw, Some(key), |_| {}).await;
    let check = core
        .golden
        .check(
            ctx,
            &BuildRequest {
                target: BuildTarget::New { name: "Rocky".into() },
                recipe: recipe(&rocky, kickstart, Hypervisor::Vmware, &lab.vms, "gp.medium"),
            },
        )
        .await
        .unwrap();
    assert!(
        check.problems.iter().any(|p| p.contains("Kickstart")),
        "{:?}",
        check.problems
    );
    // A config whose user has no key from the vault: Remotely couldn't sign in to make it generic.
    let keyless = config_from(core, "starter.ubuntu-24.04-minimal", pw, None, |_| {}).await;
    let check = core
        .golden
        .check(
            ctx,
            &BuildRequest {
                target: BuildTarget::New { name: "Keyless".into() },
                recipe: recipe(&iso, keyless, Hypervisor::Vmware, &lab.vms, "gp.medium"),
            },
        )
        .await
        .unwrap();
    assert!(!check.problems.is_empty(), "no key: {check:?}");
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    // B5 of PR 100's review: a folder on a share is refused by its text, never looked at.
    let mut shared = recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium");
    shared.vm_folder = Some(r"\\files.example.com\vms".into());
    let check = core
        .golden
        .check(
            ctx,
            &BuildRequest {
                target: BuildTarget::New { name: "Shared".into() },
                recipe: shared,
            },
        )
        .await
        .unwrap();
    assert!(check.preview.is_none() && !check.problems.is_empty(), "{check:?}");
    // A2 of PR 100's review: a fixed address ({{ip}}) or an address pool would go into every clone.
    let fixed = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |c| {
        c.body = c
            .body
            .replacen("\n  network:", "\n  # the address: {{ip}}\n  network:", 1);
    })
    .await;
    let mut pooled = recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium");
    pooled.address_pool_id = Some(Uuid::new_v4());
    for (name, recipe, want) in [
        (
            "Fixed",
            recipe(&iso, fixed, Hypervisor::Vmware, &lab.vms, "gp.medium"),
            "fixed address",
        ),
        ("Pooled", pooled, "address pool"),
    ] {
        let check = core
            .golden
            .check(
                ctx,
                &BuildRequest {
                    target: BuildTarget::New { name: name.into() },
                    recipe,
                },
            )
            .await
            .unwrap();
        assert!(check.problems.iter().any(|p| p.contains(want)), "{want}: {check:?}");
    }
    // The UI never builds the command.
    let request = BuildRequest {
        target: BuildTarget::New { name: "Ok".into() },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let SubmitOutcome::NeedsApproval { request: approval } = core.golden.submit(ctx, &request).await.unwrap() else {
        panic!("an approval")
    };
    let _ = approval;
    let command = core.golden.command_for(ctx, Uuid::new_v4()).await;
    assert!(matches!(command, Err(CoreError::UnknownTarget(_))), "{command:?}");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

/// A fake WinRM client playing a Windows build VM and its clones: it shows `fingerprint`'s certificate, takes any
/// password until `Set-LocalUser` sets one and only that one after; the generalization's task "runs sysprep": it writes
/// `task_says` to the VM's COM1 (its serial log), then powers the VM off (`sysprep` names the VM to power off) and
/// forgets the password, as OOBE sets a clone's again.
struct FakeWinrm {
    fingerprint: String,
    password: Arc<Mutex<Option<String>>>,
    signins: Mutex<Vec<(String, String)>>,
    scripts: Arc<Mutex<Vec<String>>>,
    vmware: Arc<FakeVmware>,
    sysprep: Arc<Mutex<Option<PathBuf>>>,
    task_says: Arc<Mutex<Vec<&'static str>>>,
    /// Whether the task's Windows goes off after its lines: by itself once `sealed`, or as a hard power-off.
    task_powers_off: Arc<Mutex<Option<bool>>>,
    /// Q2, N3: whether the build VM's seed was out of its drive, its answer file gone, when the task was registered.
    seed_out_at_task: Arc<Mutex<Vec<bool>>>,
}

/// What the real task writes to COM1 when every step goes.
const TASK_SAYS: [&str; 6] = [
    "started",
    "removed winrm-https",
    "cleared event-logs",
    "sysprep",
    "sysprep-exit 0",
    "sealed",
];

struct FakeWinrmSession {
    scripts: Arc<Mutex<Vec<String>>>,
    password: Arc<Mutex<Option<String>>>,
    vmware: Arc<FakeVmware>,
    sysprep: Arc<Mutex<Option<PathBuf>>>,
    task_says: Arc<Mutex<Vec<&'static str>>>,
    task_powers_off: Arc<Mutex<Option<bool>>>,
    seed_out_at_task: Arc<Mutex<Vec<bool>>>,
}

#[async_trait]
impl WinrmAdapter for FakeWinrm {
    async fn connect(&self, request: WinrmConnect<'_>) -> remotely_core::error::Result<Arc<dyn WinrmSession>> {
        request
            .verifier
            .verify(
                &HostKey {
                    host: request.spec.host.clone(),
                    port: request.spec.port,
                    key_type: CERT_KEY_TYPE.into(),
                    fingerprint: self.fingerprint.clone(),
                },
                None,
            )
            .await?;
        let password = request
            .password
            .as_ref()
            .map(|p| p.expose().to_owned())
            .unwrap_or_default();
        if let Some(set) = self.password.lock().unwrap().as_deref() {
            if set != password {
                return Err(CoreError::AuthFailed("the user name or password is incorrect".into()));
            }
        }
        self.signins
            .lock()
            .unwrap()
            .push((request.spec.username.clone().unwrap_or_default(), password));
        Ok(Arc::new(FakeWinrmSession {
            scripts: Arc::clone(&self.scripts),
            password: Arc::clone(&self.password),
            vmware: Arc::clone(&self.vmware),
            sysprep: Arc::clone(&self.sysprep),
            task_says: Arc::clone(&self.task_says),
            task_powers_off: Arc::clone(&self.task_powers_off),
            seed_out_at_task: Arc::clone(&self.seed_out_at_task),
        }))
    }
}

#[async_trait]
impl ExecSession for FakeWinrmSession {
    async fn run(&self, script: &str, max_output: usize) -> remotely_core::error::Result<ExecResult> {
        self.scripts.lock().unwrap().push(script.to_owned());
        if let Some(rest) = script.strip_prefix("$p = ConvertTo-SecureString '") {
            let quoted = rest.split("' -AsPlainText").next().unwrap_or_default();
            *self.password.lock().unwrap() = Some(quoted.replace("''", "'"));
        }
        let stdout = if script.contains("unattend-original.xml") && !script.contains("Register-ScheduledTask") {
            "answer-file 00\r\nsigned-out 1\r\n".to_owned()
        } else if script.contains("Register-ScheduledTask -TaskName 'Remotely generalize'") {
            // The task runs a few seconds later: sysprep shuts Windows down, and the clone's OOBE sets its password.
            let vmx = self.sysprep.lock().unwrap().clone();
            if let Some(vmx) = vmx {
                let (vmware, password) = (Arc::clone(&self.vmware), Arc::clone(&self.password));
                let says = self.task_says.lock().unwrap().clone();
                let stem = vmx.file_stem().unwrap().to_string_lossy().into_owned();
                let seed = vmx.with_file_name("install-seed").join(format!("{stem}-seed.iso"));
                let answers_gone = std::fs::read(&seed).map_or(true, |b| !holds(&b, b"unattend"));
                let ejected = vmware
                    .calls()
                    .iter()
                    .any(|c| c.starts_with("vmrun disconnectNamedDevice") && c.contains(&stem));
                self.seed_out_at_task.lock().unwrap().push(answers_gone && ejected);
                let powers_off = self
                    .task_powers_off
                    .lock()
                    .unwrap()
                    .unwrap_or_else(|| says.contains(&"sealed"));
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let stem = vmx.file_stem().unwrap().to_string_lossy().into_owned();
                    let serial = vmx.with_file_name(format!("{stem}-serial.log"));
                    for line in says {
                        append(&serial, format!("remotely-generic {line}\r\n").as_bytes());
                    }
                    if powers_off {
                        *password.lock().unwrap() = None;
                        vmware
                            .power(&vmx, PowerOp::Stop { mode: StopMode::Hard })
                            .await
                            .unwrap();
                    }
                });
            }
            "remotely-generic scheduled\r\n".to_owned()
        } else {
            String::new()
        };
        Ok(ExecResult {
            exit_code: Some(0),
            signal: None,
            output: OutputCollector::collect(stdout.as_bytes(), b"", &[], max_output),
            duration_ms: 1,
            peer_ip: None,
        })
    }
    async fn run_sudo(&self, _: &str, _: &SecretString, _: usize) -> remotely_core::error::Result<ExecResult> {
        Err(CoreError::NotImplemented("sudo"))
    }
    fn is_closed(&self) -> bool {
        false
    }
    async fn close(&self) {}
    fn script_kind(&self) -> ScriptKind {
        ScriptKind::PowerShell
    }
}

#[async_trait]
impl WinrmSession for FakeWinrmSession {
    async fn console(&self, _: SecretPromptShown) -> remotely_core::error::Result<ConsoleShell> {
        Err(CoreError::NotImplemented("console"))
    }
    async fn read(&self, _: &str, _: usize, _: Duration) -> remotely_core::error::Result<String> {
        Ok(String::new())
    }
    fn exec(self: Arc<Self>) -> Arc<dyn ExecSession> {
        self
    }
    fn host_key(&self) -> Option<String> {
        None
    }
}

/// Setup's two restarts in Workstation's log once the VM's seed is there, then `lines` on its serial port.
fn windows_setup(folder: &Path, vm: &str, resets: usize, lines: Vec<String>) -> tokio::task::JoinHandle<()> {
    let log = folder.join("vmware.log");
    let serial = folder.join(format!("{vm}-serial.log"));
    let seed = folder.join("install-seed");
    tokio::spawn(async move {
        for _ in 0..3000 {
            if seed.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for _ in 0..resets {
            tokio::time::sleep(Duration::from_millis(40)).await;
            append(
                &log,
                b"In(05) vcpu-0 Chipset: The guest has requested that the virtual machine be hard reset.\n",
            );
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        for line in lines {
            tokio::time::sleep(Duration::from_millis(60)).await;
            append(&serial, line.as_bytes());
        }
    })
}

#[tokio::test]
async fn a_windows_image_is_sysprepped_and_its_clones_get_g6s_one_time_password_and_certificate() {
    let lab = lab("golden-windows", &["winsrv-v1", "web-1"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    // 0.8.0 refuses Windows images (windows_golden_images_are_refused_in_0_8_0_with_why); the kept seal and clone code
    // runs here as the later release would run it. The hand checks proved the build half on real VMs; their clones
    // didn't read the seed's answer file, which these fakes can't show.
    core.catalog.windows_images().set_allowed_for_tests(true);
    let winrm = Arc::new(FakeWinrm {
        fingerprint: FINGERPRINT.into(),
        password: Arc::default(),
        signins: Mutex::default(),
        scripts: Arc::default(),
        vmware: Arc::clone(&lab.vmware),
        sysprep: Arc::new(Mutex::new(Some(lab.vms.join("winsrv-v1").join("winsrv-v1.vmx")))),
        task_says: Arc::new(Mutex::new(TASK_SAYS.to_vec())),
        task_powers_off: Arc::default(),
        seed_out_at_task: Arc::default(),
    });
    core.set_deploy_winrm(winrm.clone());
    let pw = vault_password(core, &lab.secret).await;
    let config = config_from(core, "starter.windows-server-2025", pw, None, |_| {}).await;
    let iso = iso_image(
        core,
        &lab.dir,
        "server.iso",
        &install_isos::windows_server(),
        "windows-server",
    )
    .await;
    let request = BuildRequest {
        target: BuildTarget::New { name: "WinSrv".into() },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.large"),
    };
    let approval = needs_approval(core.golden.submit(ctx, &request).await.unwrap());
    let details = approval.image_build.as_ref().unwrap();
    assert_eq!(details.vm_name, "winsrv-v1");
    assert!(details.steps.iter().any(|s| s.contains("sysprep")));
    assert!(details.sign_in.contains("WinRM"), "{}", details.sign_in);
    let folder = lab.vms.join("winsrv-v1");
    let play = windows_setup(
        &folder,
        "winsrv-v1",
        2,
        vec![format!("remotely-winrm {FINGERPRINT}\r\n")],
    );
    let job = approve(core, &approval).await;
    let status = wait(core, job).await;
    play.await.unwrap();
    let notes = notes_of(core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    // The one-time password, the vault's for the after-install script, then the vault's for the generalization.
    let signins = winrm.signins.lock().unwrap().clone();
    assert!(signins.len() >= 3, "{signins:?}");
    assert_eq!(signins.last().unwrap().1, lab.secret);
    // Q2, N3 of PR 100's reviews: the seed was out of its drive, its answer file gone, before the task was made.
    assert_eq!(*winrm.seed_out_at_task.lock().unwrap(), [true]);
    assert!(
        notes.contains("sealed") || notes.contains("snapshot 'Remotely image v1' taken"),
        "{notes}"
    );
    let scripts = winrm.scripts.lock().unwrap().clone();
    assert!(scripts
        .last()
        .unwrap()
        .contains("Register-ScheduledTask -TaskName 'Remotely generalize'"));
    let vmx = folder.join("winsrv-v1.vmx");
    assert_eq!(
        lab.vmware.snapshot_names(&vmx.display().to_string()),
        ["Remotely image v1"]
    );
    let text = lab.vmware.vmx_text(&vmx.display().to_string()).unwrap();
    assert!(!text.contains("serial0."), "{text}");

    // A template of the image deploys a clone that reads the build config's passes from its own seed.
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "WinSrv")
        .unwrap();
    let clones = lab.vms.clone();
    let template = template_of(core, &image, Hypervisor::Vmware, &clones, CloneMode::Full).await;
    let deploy = DeployRequest {
        from: DeployFrom::Template { id: template },
        count: 1,
        naming_pattern: None,
        host_adapter: None,
        guest_password_id: None,
        vm_values: vec![],
        address_pool_id: None,
        install_minutes: None,
    };
    let check = core.deploy.check(ctx, &deploy).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let approval = needs_approval(core.deploy.submit(ctx, &deploy).await.unwrap());
    assert!(approval.steps.contains(&ApprovalStep::VaultReauth));
    let web = lab.vms.join("web-1");
    // No Setup from an ISO: the clone's first sign-in writes its new certificate's line, with no restart counted.
    let play = windows_setup(&web, "web-1", 0, vec![format!("remotely-winrm {FINGERPRINT}\r\n")]);
    *winrm.sysprep.lock().unwrap() = None;
    let job = approve(core, &approval).await;
    let status = wait(core, job).await;
    play.await.unwrap();
    let notes = notes_of(core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let clone = lab
        .vmware
        .vmx_text(&web.join("web-1.vmx").display().to_string())
        .unwrap();
    assert!(clone.contains("serial0.fileType = \"file\""), "{clone}");
    assert!(clone.contains("web-1-seed.iso"), "{clone}");
    assert!(notes.contains("password set to the vault's"), "{notes}");
    assert!(!web.join("web-1-install.iso").exists(), "a clone has no ISO copy");
    let audit = format!("{:?}", core.store.recent_audit(ctx, 300).await.unwrap());
    assert!(!audit.contains(lab.secret.as_str()));

    // C5 of PR 100's review: the clones read the passes of the config version 1 was built from, as it was then; once
    // that config is edited, the template says to build the image again instead of deploying other passes.
    let mut edited = core
        .catalog
        .install_config(ctx, &config.to_string())
        .await
        .unwrap()
        .spec;
    assert!(
        edited.body.contains("<TimeZone>UTC</TimeZone>"),
        "the starter's time zone"
    );
    edited.body = edited.body.replace(
        "<TimeZone>UTC</TimeZone>",
        "<TimeZone>W. Europe Standard Time</TimeZone>",
    );
    core.catalog.update_install_config(ctx, config, edited).await.unwrap();
    let problems = core.catalog.plan(ctx, template, 1).await.unwrap().unwrap_err();
    assert!(
        problems.iter().any(|p| p.message.contains("changed since version 1")),
        "{problems:?}"
    );
    let _ = std::fs::remove_dir_all(&lab.dir);
}

/// A Windows build up to its sysprep task, whose COM1 lines are `task_says` (and whose Windows goes off as
/// `powers_off` says: `None`, by itself once `sealed`). Returns the job's status, its notes and the fake WinRM.
async fn windows_build(
    lab: &Lab,
    vm: &str,
    name: &str,
    task_says: Vec<&'static str>,
    powers_off: Option<bool>,
) -> (JobStatus, String, Arc<FakeWinrm>) {
    let core = &lab.core;
    let ctx = &core.ctx();
    // The kept Windows seal, which 0.8.0 refuses to run (see the test above).
    core.catalog.windows_images().set_allowed_for_tests(true);
    let vmx = lab.vms.join(vm).join(format!("{vm}.vmx"));
    let winrm = Arc::new(FakeWinrm {
        fingerprint: FINGERPRINT.into(),
        password: Arc::default(),
        signins: Mutex::default(),
        scripts: Arc::default(),
        vmware: Arc::clone(&lab.vmware),
        sysprep: Arc::new(Mutex::new(Some(vmx))),
        task_says: Arc::new(Mutex::new(task_says)),
        task_powers_off: Arc::new(Mutex::new(powers_off)),
        seed_out_at_task: Arc::default(),
    });
    core.set_deploy_winrm(winrm.clone());
    let pw = vault_password(core, &lab.secret).await;
    let config = config_from(core, "starter.windows-server-2025", pw, None, |_| {}).await;
    let iso = iso_image(
        core,
        &lab.dir,
        &format!("{vm}.iso"),
        &install_isos::windows_server(),
        "windows-server",
    )
    .await;
    let request = BuildRequest {
        target: BuildTarget::New { name: name.into() },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.large"),
    };
    let approval = needs_approval(core.golden.submit(ctx, &request).await.unwrap());
    let play = windows_setup(
        &lab.vms.join(vm),
        vm,
        2,
        vec![format!("remotely-winrm {FINGERPRINT}\r\n")],
    );
    let job = approve(core, &approval).await;
    let status = wait(core, job).await;
    play.await.unwrap();
    (status, notes_of(core, job).await, winrm)
}

/// Whether the fake Workstation runs the VM now.
async fn running(lab: &Lab, vmx: &Path) -> bool {
    let wanted = vmx.display().to_string().to_lowercase();
    lab.vmware
        .list_running()
        .await
        .unwrap()
        .iter()
        .any(|p| p.display().to_string().to_lowercase() == wanted)
}

/// No snapshot on the VM and no image of that name: nothing was registered.
async fn nothing_registered(lab: &Lab, vm: &str, image: &str) {
    let vmx = lab.vms.join(vm).join(format!("{vm}.vmx"));
    assert!(lab.vmware.snapshot_names(&vmx.display().to_string()).is_empty());
    let ctx = &lab.core.ctx();
    assert!(lab
        .core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .iter()
        .all(|i| i.name != image));
}

#[tokio::test]
async fn a_windows_build_vm_that_goes_off_before_sysprep_sealed_it_isnt_sealed() {
    // A4 of PR 100's review: a power-off before the task removed the build's listener and started sysprep.
    let lab = lab("golden-win-early", &["early-v1", "cut-v1"]).await;
    let (status, notes, _) = windows_build(&lab, "early-v1", "Early", vec!["started"], Some(true)).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(
        notes.contains(
            "went off before the task that runs sysprep said 'removed winrm-https' and 'sysprep' and 'sealed'"
        ),
        "{notes}"
    );
    nothing_registered(&lab, "early-v1", "Early").await;
    // N8 of PR 100's second review: a hard power-off while sysprep runs (after its line, before `sealed`) isn't
    // sysprep's either.
    let cut = vec!["started", "removed winrm-https", "cleared event-logs", "sysprep"];
    let (status, notes, _) = windows_build(&lab, "cut-v1", "Cut", cut, Some(true)).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(notes.contains("said 'sealed': it isn't sealed"), "{notes}");
    nothing_registered(&lab, "cut-v1", "Cut").await;
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_windows_build_whose_sysprep_fails_or_whose_seed_stays_in_fails_and_leaves_windows_running() {
    let lab = lab("golden-win-fail", &["failed-v1", "stuck-v1"]).await;
    // N8: sysprep /quit returned 1: the task says so and doesn't shut Windows down; the build fails at once.
    let says = vec![
        "started",
        "removed winrm-https",
        "sysprep",
        "sysprep-exit 1",
        "sysprep-failed 1",
    ];
    let (status, notes, winrm) = windows_build(&lab, "failed-v1", "Failed", says, None).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(notes.contains("sysprep stopped with exit code 1"), "{notes}");
    assert!(
        running(&lab, &lab.vms.join("failed-v1").join("failed-v1.vmx")).await,
        "left running for a look"
    );
    // Q2: the seed was out of its drive, its answer file gone, before the task was registered.
    assert_eq!(*winrm.seed_out_at_task.lock().unwrap(), [true]);
    nothing_registered(&lab, "failed-v1", "Failed").await;

    // N3: a seed that won't leave its drive: no task, no sysprep with the answer file attached.
    lab.vmware.set_failing("disconnectNamedDevice", true);
    let (status, notes, winrm) = windows_build(&lab, "stuck-v1", "Stuck", TASK_SAYS.to_vec(), None).await;
    lab.vmware.set_failing("disconnectNamedDevice", false);
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(
        notes.contains("wasn't generalized with its answer file attached"),
        "{notes}"
    );
    let scripts = winrm.scripts.lock().unwrap().clone();
    assert!(
        scripts.iter().all(|s| !s.contains("Register-ScheduledTask")),
        "no sysprep task"
    );
    nothing_registered(&lab, "stuck-v1", "Stuck").await;
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn windows_golden_images_are_refused_in_0_8_0_with_why() {
    // The owner deferred Windows images on 14 Nov 2026: every way to build one, or to deploy a clone of one Remotely
    // built, says why, instead of a clone that waits at OOBE to its time limit.
    use remotely_core::fakes::clock::{FakeClock, FakeZone};
    use remotely_core::golden::WINDOWS_DEFERRED;
    use remotely_core::schedules::{
        RunOutcome, ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleState, ScheduleTarget, Timing, WallTime,
    };
    let lab = lab("golden-win-deferred", &["deferred-v1", "web-1"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let says = |err: &CoreError| err.to_string().contains(WINDOWS_DEFERRED);

    // A new Windows image: the dialog's check says why, and a submit is refused before anything is asked.
    let pw = vault_password(core, &lab.secret).await;
    let config = config_from(core, "starter.windows-server-2025", pw, None, |_| {}).await;
    let iso = iso_image(
        core,
        &lab.dir,
        "server.iso",
        &install_isos::windows_server(),
        "windows-server",
    )
    .await;
    let request = BuildRequest {
        target: BuildTarget::New { name: "Never".into() },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.large"),
    };
    let check = core.golden.check(ctx, &request).await.unwrap();
    assert!(check.preview.is_none());
    assert!(
        check.problems.iter().any(|p| p.contains(WINDOWS_DEFERRED)),
        "{:?}",
        check.problems
    );
    let Err(err) = core.golden.submit(ctx, &request).await else {
        panic!("a Windows build was submitted");
    };
    assert!(says(&err), "{err}");

    // An image built while they were allowed (only a build of this PR's earlier commits made one), with a template and
    // a scheduled rebuild approved then.
    let (status, notes, _) = windows_build(&lab, "deferred-v1", "Deferred", TASK_SAYS.to_vec(), None).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Deferred")
        .unwrap();
    let template = template_of(core, &image, Hypervisor::Vmware, &lab.vms, CloneMode::Full).await;
    let clock = Arc::new(FakeClock::new(
        time::macros::datetime!(2026-06-10 10:00 UTC),
        FakeZone::central_europe(),
    ));
    core.schedules().set_clock(clock.clone());
    let input = |name: &str| ScheduleInput {
        id: None,
        name: name.into(),
        spec: ScheduleSpec {
            action: ScheduleAction::RebuildImage,
            targets: vec![ScheduleTarget::Image { image_id: image.id }],
            timing: Timing::Daily {
                at: WallTime::new(3, 0).unwrap(),
            },
        },
    };
    let saved = core.schedules().save(input("nightly rebuild")).await.unwrap();
    let request = saved.approval.expect("a build asks");
    let answers = ApprovalAnswers {
        confirmed: true,
        vault_password: Some(SecretString::new(VAULT_PASSWORD)),
        ..Default::default()
    };
    let view = core.schedules().approve(request.id, answers).await.unwrap();
    assert_eq!(view.state, ScheduleState::Active);

    // 0.8.0: no rebuild, no build settings, no new schedule (nothing saved), no clone.
    core.catalog.windows_images().set_allowed_for_tests(false);
    let Err(err) = core.golden.rebuild(ctx, image.id).await else {
        panic!("a Windows image was rebuilt");
    };
    assert!(says(&err), "{err}");
    let Err(err) = core
        .golden
        .set_recipe(ctx, image.id, image.build.clone().unwrap())
        .await
    else {
        panic!("a Windows image's build settings were saved");
    };
    assert!(says(&err), "{err}");
    let Err(err) = core.schedules().save(input("weekly rebuild")).await else {
        panic!("a Windows rebuild was scheduled");
    };
    assert!(says(&err), "{err}");
    assert_eq!(core.schedules().list().await.unwrap().len(), 1, "nothing was saved");
    let problems = core.catalog.plan(ctx, template, 1).await.unwrap().unwrap_err();
    assert!(
        problems.iter().any(|p| p.message.contains(WINDOWS_DEFERRED)),
        "{problems:?}"
    );
    let deploy = DeployRequest {
        from: DeployFrom::Template { id: template },
        count: 1,
        naming_pattern: None,
        host_adapter: None,
        guest_password_id: None,
        vm_values: vec![],
        address_pool_id: None,
        install_minutes: None,
    };
    let check = core.deploy.check(ctx, &deploy).await.unwrap();
    assert!(
        check.problems.iter().any(|p| p.message.contains(WINDOWS_DEFERRED)),
        "{:?}",
        check.problems
    );
    assert!(core.deploy.submit(ctx, &deploy).await.is_err());
    assert!(!lab.vms.join("web-1").exists(), "no clone was made");

    // The schedule approved before: its run fails with why and builds nothing.
    let at = &view.next_run.as_ref().unwrap().at;
    let due = time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).unwrap();
    clock.set(due);
    let report = core.schedules().tick().await.unwrap();
    assert_eq!(report.started, 1);
    core.schedules().wait_runs().await;
    let view = core.schedules().get(view.id).await.unwrap();
    let last = view.last_run.as_ref().unwrap();
    assert_eq!(last.outcome, RunOutcome::Failed, "{:?}", last.detail);
    assert!(
        last.detail.as_deref().unwrap_or_default().contains(WINDOWS_DEFERRED),
        "{:?}",
        last.detail
    );
    assert_eq!(core.catalog.image(ctx, image.id).await.unwrap().version, Some(1));
    assert!(!lab.vms.join("deferred-v2").exists(), "no version 2");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_build_whose_steps_dont_all_go_or_dont_end_fails_and_keeps_its_vm() {
    let lab = lab(
        "golden-steps",
        &["steps-golden-v1", "short-golden-v1", "hung-golden-v1"],
    )
    .await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;

    // A1, A3 of PR 100's review: the first step that fails ends the script, and the build fails naming it.
    *lab.guest.report.lock().unwrap() = "remotely-generic cloud-init yes\nremotely-generic ok boot\nremotely-generic ok cloud_init\nremotely-generic failed machine_id\n".into();
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Steps golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("steps-golden-v1")).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(notes.contains("the step that emptied the machine id failed"), "{notes}");
    assert!(notes.contains("the VM is kept for a look"), "{notes}");
    let vmx = lab.vms.join("steps-golden-v1").join("steps-golden-v1.vmx");
    assert!(lab.vmware.has_vm(&vmx.display().to_string()), "kept for a look");
    // N4 of PR 100's second review: left running, so the work the step waited for isn't cut short.
    assert!(running(&lab, &vmx).await, "left running");
    assert!(notes.contains("it is left running"), "{notes}");
    nothing_registered(&lab, "steps-golden-v1", "Steps golden").await;

    // A report that ends (exit 0) without a word about some steps is no better.
    *lab.guest.report.lock().unwrap() =
        "remotely-generic cloud-init yes\nremotely-generic ok boot\nremotely-generic ok cloud_init\n".into();
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Short golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("short-golden-v1")).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(
        notes.contains("the step that emptied the machine id didn't run"),
        "{notes}"
    );
    assert!(running(&lab, &lab.vms.join("short-golden-v1").join("short-golden-v1.vmx")).await);
    nothing_registered(&lab, "short-golden-v1", "Short golden").await;

    // Q3 of PR 100's review: a run that never answers fails at its time limit.
    *lab.guest.report.lock().unwrap() = linux_report();
    *lab.guest.end.lock().unwrap() = GuestEnd::Hangs;
    tuned(core, lab.ssh, Duration::from_secs(3));
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Hung golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("hung-golden-v1")).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(
        notes.contains("the steps that make it generic didn't end within"),
        "{notes}"
    );
    assert!(core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .iter()
        .all(|i| i.name != "Hung golden"));
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_virtualbox_build_vm_that_aborts_isnt_sealed() {
    // A4 of PR 100's review: VirtualBox's `aborted` is a crash, not the guest's own shutdown.
    let lab = lab("golden-abort", &[]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.debian-12-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "bookworm.iso", &install_isos::debian(), "debian").await;
    *lab.guest.end.lock().unwrap() = GuestEnd::Aborts;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Deb crash".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::VirtualBox, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, debian_lines("deb-crash-v1")).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(notes.contains("aborted instead of shutting down"), "{notes}");
    let vm = lab.virtualbox.vm_named("deb-crash-v1").expect("kept for a look");
    assert!(lab.virtualbox.snapshot_names(&vm.uuid).is_empty());
    // Q2: the seed was out of its drive (ejected, its file deleted) before the steps ran.
    assert_eq!(*lab.guest.seed_out.lock().unwrap(), [true]);
    assert!(core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .iter()
        .all(|i| i.name != "Deb crash"));
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_build_whose_settings_change_fails_takes_no_snapshot() {
    // A6 of PR 100's review: the install's drives and serial port must leave the VM's settings before the snapshot.
    let lab = lab("golden-seal", &["seal-golden-v1"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    *lab.guest.end.lock().unwrap() = GuestEnd::PowersOffSettingsLocked;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Seal golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("seal-golden-v1")).await;
    lab.vmware.set_failing_vmx_write(false);
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(notes.contains("are still in its settings"), "{notes}");
    assert!(notes.contains("without a snapshot"), "{notes}");
    let vmx = lab.vms.join("seal-golden-v1").join("seal-golden-v1.vmx");
    assert!(lab.vmware.snapshot_names(&vmx.display().to_string()).is_empty());
    assert!(core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .iter()
        .all(|i| i.name != "Seal golden"));
    // The rest of A6: the files its settings still name stay, the serial log above all.
    assert!(
        notes.contains("stay with it, as its settings still name them"),
        "{notes}"
    );
    let folder = lab.vms.join("seal-golden-v1");
    assert!(folder.join("seal-golden-v1-serial.log").exists());
    assert!(folder.join("install-seed").join("seal-golden-v1-seed.iso").exists());
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_virtualbox_build_whose_seal_cant_change_its_settings_fails() {
    // A6 of PR 100's review on VirtualBox: a lock that outlasts every try.
    let lab = lab("golden-vbox-seal", &[]).await;
    let core = &lab.core;
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.debian-12-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "bookworm.iso", &install_isos::debian(), "debian").await;
    *lab.guest.end.lock().unwrap() = GuestEnd::PowersOffSessionHeld(6);
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Deb held".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::VirtualBox, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, debian_lines("deb-held-v1")).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(notes.contains("already locked for a session"), "{notes}");
    assert!(notes.contains("without a snapshot"), "{notes}");
    let vm = lab.virtualbox.vm_named("deb-held-v1").expect("kept");
    assert!(lab.virtualbox.snapshot_names(&vm.uuid).is_empty());
    assert!(lab.vms.join("deb-held-v1").join("deb-held-v1-serial.log").exists());
    let ctx = &core.ctx();
    assert!(core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .iter()
        .all(|i| i.name != "Deb held"));
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn one_build_of_an_image_runs_at_a_time_and_never_registers_an_older_version() {
    // C1 of PR 100's review.
    let lab = lab("golden-once", &["once-golden-v1", "once-golden-v2"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Once golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("once-golden-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Once golden")
        .unwrap();
    // Three builds of version 2, each approved before any ran.
    let rebuild = core.golden.rebuild_request(ctx, image.id).await.unwrap();
    let asked: Vec<ApprovalRequest> = three_approvals(core, &rebuild).await;
    for a in &asked {
        assert_eq!(a.image_build.as_ref().unwrap().version, 2);
    }
    let gate = Arc::new(tokio::sync::Notify::new());
    *lab.guest.gate.lock().unwrap() = Some(Arc::clone(&gate));
    let play = installer(
        lab.vms.join("once-golden-v2").join("once-golden-v2-serial.log"),
        ubuntu_lines("once-golden-v2"),
    );
    let first = approve(core, &asked[0]).await;
    let reached = tokio::time::timeout(Duration::from_secs(20), async {
        while lab.guest.runs.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(reached.is_ok(), "the first rebuild reached its generalization");
    // While it runs, another build of the image is refused before it makes anything.
    let second = approve(core, &asked[1]).await;
    assert_eq!(wait(core, second).await, JobStatus::Failed);
    let notes = notes_of(core, second).await;
    assert!(notes.contains("is being built by job"), "{notes}");
    gate.notify_one();
    let status = wait(core, first).await;
    play.await.unwrap();
    assert_eq!(status, JobStatus::Succeeded, "{}", notes_of(core, first).await);
    // Once it registered version 2, a build approved for version 2 is refused rather than registered over it.
    let third = approve(core, &asked[2]).await;
    assert_eq!(wait(core, third).await, JobStatus::Failed);
    let notes = notes_of(core, third).await;
    assert!(notes.contains("was built since this build was approved"), "{notes}");
    let versions = core.golden.versions(ctx, image.id).await.unwrap();
    assert_eq!(
        versions.iter().map(|v| (v.number, v.state)).collect::<Vec<_>>(),
        [(2, VersionState::Newest), (1, VersionState::Kept)]
    );
    assert_eq!(core.catalog.image(ctx, image.id).await.unwrap().version, Some(2));
    let _ = std::fs::remove_dir_all(&lab.dir);
}

/// Three approvals of the same build.
async fn three_approvals(core: &Core, request: &BuildRequest) -> Vec<ApprovalRequest> {
    let mut out = Vec::new();
    for _ in 0..3 {
        out.push(needs_approval(core.golden.submit(&core.ctx(), request).await.unwrap()));
    }
    out
}

#[tokio::test]
async fn retention_leaves_a_version_whose_vm_went_to_another_workspace() {
    // B2 of PR 100's review: an old version's VM is deleted only while it is this workspace's.
    let lab = lab(
        "golden-moved",
        &["moved-golden-v1", "moved-golden-v2", "moved-golden-v3"],
    )
    .await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let mut request = BuildRequest {
        target: BuildTarget::New {
            name: "Moved golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    request.recipe.keep = Some(1);
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("moved-golden-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Moved golden")
        .unwrap();
    let other = core
        .workspaces
        .create(remotely_core::workspaces::WorkspaceInput {
            name: "Other".into(),
            color: None,
        })
        .await
        .unwrap();
    let elsewhere = remotely_core::domain::Context {
        workspace_id: other.id,
        user_id: ctx.user_id,
    };
    let v1 = lab
        .vms
        .join("moved-golden-v1")
        .join("moved-golden-v1.vmx")
        .display()
        .to_string();
    let move_v1 = |from: remotely_core::domain::Context, to: remotely_core::domain::Context| {
        let v1 = v1.clone();
        async move {
            core.inventory.release(&from, std::slice::from_ref(&v1)).await.unwrap();
            core.inventory.claim(&to, &[v1]).await.unwrap();
        }
    };
    // Planned while version 1's VM is another workspace's: not a target, and the approval says why.
    move_v1(*ctx, elsewhere).await;
    let rebuild = core.golden.rebuild_request(ctx, image.id).await.unwrap();
    let asked = needs_approval(core.golden.submit(ctx, &rebuild).await.unwrap());
    assert_eq!(asked.targets.len(), 1, "only the new VM: {:?}", asked.targets);
    let details = asked.image_build.as_ref().unwrap();
    assert!(details.deletes.is_empty(), "{details:?}");
    assert!(
        details.retained.iter().any(|r| r.starts_with("version 1 stays")),
        "{details:?}"
    );
    let play = installer(
        lab.vms.join("moved-golden-v2").join("moved-golden-v2-serial.log"),
        ubuntu_lines("moved-golden-v2"),
    );
    let job = approve(core, &asked).await;
    assert_eq!(wait(core, job).await, JobStatus::Succeeded);
    play.await.unwrap();
    assert!(lab.vmware.has_vm(&v1), "another workspace's VM stays");

    // Planned while it is here again, then moved before the old versions go: left alone, version 2 deleted.
    move_v1(elsewhere, *ctx).await;
    let asked = needs_approval(core.golden.submit(ctx, &rebuild).await.unwrap());
    assert_eq!(
        asked.targets.len(),
        3,
        "the new VM and both old versions: {:?}",
        asked.targets
    );
    assert_eq!(asked.action, ActionKind::ImageBuildPrune);
    let deletes = &asked.image_build.as_ref().unwrap().deletes;
    assert!(
        deletes.iter().any(|d| d.starts_with("version 2")) && deletes.iter().any(|d| d.starts_with("version 1")),
        "{deletes:?}"
    );
    let play = installer(
        lab.vms.join("moved-golden-v3").join("moved-golden-v3-serial.log"),
        ubuntu_lines("moved-golden-v3"),
    );
    let job = approve(core, &asked).await;
    move_v1(*ctx, elsewhere).await;
    assert_eq!(wait(core, job).await, JobStatus::Succeeded);
    play.await.unwrap();
    let notes = notes_of(core, job).await;
    assert!(notes.contains("version 1 stays"), "{notes}");
    assert!(notes.contains("version 2 deleted with its VM"), "{notes}");
    assert!(lab.vmware.has_vm(&v1));
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn an_export_doesnt_replace_an_image_remotely_builds() {
    // C6 of PR 100's review: FD-07's Replace would drop the image's build settings and orphan its versions.
    use remotely_core::catalog::ImageEdit;
    use remotely_core::transfer::{CatalogChoices, ExportRequest, ItemAction, ItemChoice, TransferCommit};
    let lab = lab("golden-export", &["export-golden-v1"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Export golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("export-golden-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Export golden")
        .unwrap();
    let file = lab.dir.join("catalog.remotely");
    let passphrase = password();
    core.transfer
        .export(
            ctx,
            &file,
            ExportRequest {
                passphrase: SecretString::new(passphrase.clone()),
                include_known_hosts: false,
                include_secrets: false,
                vault_password: None,
            },
            &core.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    // The image here changes, so the export's is a conflict, and Replace is asked for.
    core.catalog
        .update_image(
            ctx,
            image.id,
            ImageEdit {
                name: image.name.clone(),
                hypervisors: image.hypervisors.clone(),
                os_profile: image.os_profile.clone(),
                notes: Some("changed here".into()),
            },
        )
        .await
        .unwrap();
    let preview = core
        .transfer
        .open(ctx, &file, SecretString::new(passphrase), &core.vault)
        .await
        .unwrap();
    let row = preview
        .catalog
        .images
        .iter()
        .find(|r| r.name == "Export golden")
        .expect("the built image is in the export");
    let mut choices = CatalogChoices::default();
    choices.images.push(ItemChoice {
        index: row.index,
        action: ItemAction::Replace,
    });
    let report = core
        .transfer
        .commit(
            ctx,
            TransferCommit {
                preview_id: preview.id,
                catalog: choices,
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
                favourites: vec![],
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
                folder_defaults: vec![],
                groups: vec![],
                checks: vec![],
            },
            &core.sessions,
            &core.vault,
            &core.known_hosts,
            &core.snippets,
        )
        .await
        .unwrap();
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.reason.contains("is one Remotely builds here")),
        "{:?}",
        report.problems
    );
    let kept = core.catalog.image(ctx, image.id).await.unwrap();
    assert!(kept.build.is_some(), "its build settings stay");
    assert_eq!(kept.version, Some(1));
    assert_eq!(core.golden.versions(ctx, image.id).await.unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_scheduled_rebuild_runs_under_its_standing_approval_and_asks_again_once_its_config_changes() {
    use remotely_core::fakes::clock::{FakeClock, FakeZone};
    use remotely_core::schedules::{
        RunOutcome, ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleState, ScheduleTarget, Timing, WallTime,
    };
    let lab = lab("golden-schedule", &["sched-golden-v1", "sched-golden-v2"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Sched golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("sched-golden-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Sched golden")
        .unwrap();

    let clock = Arc::new(FakeClock::new(
        time::macros::datetime!(2026-06-10 10:00 UTC),
        FakeZone::central_europe(),
    ));
    core.schedules().set_clock(clock.clone());
    let saved = core
        .schedules()
        .save(ScheduleInput {
            id: None,
            name: "nightly rebuild".into(),
            spec: ScheduleSpec {
                action: ScheduleAction::RebuildImage,
                targets: vec![ScheduleTarget::Image { image_id: image.id }],
                timing: Timing::Daily {
                    at: WallTime::new(3, 0).unwrap(),
                },
            },
        })
        .await
        .unwrap();
    // The approval is for the image's next build as it would be built now, at its tier.
    let request = saved.approval.expect("a Medium build asks");
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(request.action, ActionKind::ImageBuild);
    assert!(request.standing.is_some());
    assert_eq!(request.image_build.as_ref().unwrap().version, 2);
    assert!(
        request.summary.contains("rebuild image 'Sched golden'"),
        "{}",
        request.summary
    );
    // B1 of PR 100's review: the rebuilds give the vault's sudo password to each new VM, so the standing approval asks
    // for the vault password, as the dialog's build does.
    assert!(
        request.steps.contains(&ApprovalStep::VaultReauth),
        "{:?}",
        request.steps
    );
    let answers = ApprovalAnswers {
        confirmed: true,
        vault_password: Some(SecretString::new(VAULT_PASSWORD)),
        ..Default::default()
    };
    let view = core.schedules().approve(request.id, answers).await.unwrap();
    assert_eq!(view.state, ScheduleState::Active);
    let at = &view.next_run.as_ref().unwrap().at;
    let due = time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).unwrap();

    // Its run builds version 2 under that approval.
    clock.set(due);
    let play = installer(
        lab.vms.join("sched-golden-v2").join("sched-golden-v2-serial.log"),
        ubuntu_lines("sched-golden-v2"),
    );
    let report = core.schedules().tick().await.unwrap();
    assert_eq!(report.started, 1);
    core.schedules().wait_runs().await;
    play.await.unwrap();
    let view = core.schedules().get(view.id).await.unwrap();
    let last = view.last_run.as_ref().unwrap();
    assert_eq!(last.outcome, RunOutcome::Succeeded, "{:?}", last.detail);
    assert_eq!(core.catalog.image(ctx, image.id).await.unwrap().version, Some(2));
    let audit = format!("{:?}", core.store.recent_audit(ctx, 300).await.unwrap());
    assert!(audit.contains("approval_used"), "the run used the schedule's approval");

    // The install config changes: the next tick pauses the schedule and asks again; nothing is built.
    let mut changed = core
        .catalog
        .install_config(ctx, &config.to_string())
        .await
        .unwrap()
        .spec;
    changed.body = changed.body.replace("timezone: Etc/UTC", "timezone: Europe/Berlin");
    assert!(changed.body.contains("Europe/Berlin"), "the starter's time zone line");
    core.catalog.update_install_config(ctx, config, changed).await.unwrap();
    let report = core.schedules().tick().await.unwrap();
    assert_eq!(report.paused, 1);
    let view = core.schedules().get(view.id).await.unwrap();
    assert_eq!(view.state, ScheduleState::NeedsApproval);
    assert!(
        view.state_reason
            .as_deref()
            .unwrap_or_default()
            .contains("install config"),
        "{:?}",
        view.state_reason
    );
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_scheduled_rebuild_waiting_for_the_vault_builds_nothing_once_its_schedule_is_deleted() {
    // Q1 of PR 100's review: each round of the vault wait asks whether the schedule's approval still stands.
    use remotely_core::fakes::clock::{FakeClock, FakeZone};
    use remotely_core::schedules::{ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleTarget, Timing, WallTime};
    let lab = lab("golden-withdrawn", &["gone-golden-v1", "gone-golden-v2"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let request = BuildRequest {
        target: BuildTarget::New {
            name: "Gone golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("gone-golden-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Gone golden")
        .unwrap();
    let clock = Arc::new(FakeClock::new(
        time::macros::datetime!(2026-06-10 10:00 UTC),
        FakeZone::central_europe(),
    ));
    core.schedules().set_clock(clock.clone());
    let saved = core
        .schedules()
        .save(ScheduleInput {
            id: None,
            name: "nightly rebuild".into(),
            spec: ScheduleSpec {
                action: ScheduleAction::RebuildImage,
                targets: vec![ScheduleTarget::Image { image_id: image.id }],
                timing: Timing::Daily {
                    at: WallTime::new(3, 0).unwrap(),
                },
            },
        })
        .await
        .unwrap();
    let request = saved.approval.expect("a Medium build asks");
    let answers = ApprovalAnswers {
        confirmed: true,
        vault_password: Some(SecretString::new(VAULT_PASSWORD)),
        ..Default::default()
    };
    let view = core.schedules().approve(request.id, answers).await.unwrap();
    let at = &view.next_run.as_ref().unwrap().at;
    let due = time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).unwrap();

    let mut events = core.jobs.subscribe();
    core.vault.lock(ctx).await.unwrap();
    clock.set(due);
    let report = core.schedules().tick().await.unwrap();
    assert_eq!(report.started, 1);
    let job = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(JobEvent::TargetProgress { job_id, step, .. }) = events.recv().await {
                if step.starts_with("waiting for the vault to be unlocked") {
                    return job_id;
                }
            }
        }
    })
    .await;
    let Ok(job) = job else {
        core.schedules().wait_runs().await;
        let run = core.schedules().get(view.id).await.unwrap().last_run;
        panic!("the run didn't wait for the vault: {run:?}");
    };
    core.schedules().delete(view.id).await.unwrap();
    assert_eq!(wait(core, job).await, JobStatus::Failed);
    let notes = notes_of(core, job).await;
    assert!(
        notes.contains("approval was withdrawn while the build waited"),
        "{notes}"
    );
    assert!(!lab.vms.join("gone-golden-v2").exists(), "nothing was made");
    core.vault
        .unlock(ctx, UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)))
        .await
        .unwrap();
    core.schedules().wait_runs().await;
    assert_eq!(core.golden.versions(ctx, image.id).await.unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[tokio::test]
async fn a_scheduled_rebuild_asks_again_before_it_deletes_an_old_version_labelled_prod_since() {
    // B3 of PR 100's review: a run's old versions are its own targets, with their labels at the run.
    use remotely_core::fakes::clock::{FakeClock, FakeZone};
    use remotely_core::schedules::{
        ScheduleAction, ScheduleInput, ScheduleSpec, ScheduleState, ScheduleTarget, Timing, WallTime,
    };
    let lab = lab("golden-prod", &["prod-golden-v1", "prod-golden-v2"]).await;
    let core = &lab.core;
    let ctx = &core.ctx();
    let pw = vault_password(core, &lab.secret).await;
    let key = build_key(core).await;
    let config = config_from(core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let iso = iso_image(core, &lab.dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let mut request = BuildRequest {
        target: BuildTarget::New {
            name: "Prod golden".into(),
        },
        recipe: recipe(&iso, config, Hypervisor::Vmware, &lab.vms, "gp.medium"),
    };
    request.recipe.keep = Some(1);
    let (_, status, notes) = build(&lab, &request, ubuntu_lines("prod-golden-v1")).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let image = core
        .catalog
        .images(ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == "Prod golden")
        .unwrap();
    let clock = Arc::new(FakeClock::new(
        time::macros::datetime!(2026-06-10 10:00 UTC),
        FakeZone::central_europe(),
    ));
    core.schedules().set_clock(clock.clone());
    let saved = core
        .schedules()
        .save(ScheduleInput {
            id: None,
            name: "nightly rebuild".into(),
            spec: ScheduleSpec {
                action: ScheduleAction::RebuildImage,
                targets: vec![ScheduleTarget::Image { image_id: image.id }],
                timing: Timing::Daily {
                    at: WallTime::new(3, 0).unwrap(),
                },
            },
        })
        .await
        .unwrap();
    let request = saved.approval.expect("a rebuild that deletes VMs asks");
    assert_eq!(request.tier, Tier::Critical);
    assert!(
        request
            .image_build
            .as_ref()
            .unwrap()
            .deletes
            .iter()
            .any(|d| d.starts_with("version 1")),
        "{:?}",
        request.image_build
    );
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("nightly".into()),
        vault_password: Some(SecretString::new(VAULT_PASSWORD)),
        ..Default::default()
    };
    let view = core.schedules().approve(request.id, answers).await.unwrap();
    assert_eq!(view.state, ScheduleState::Active);
    let due = time::OffsetDateTime::parse(
        &view.next_run.as_ref().unwrap().at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();

    // Version 1's VM is labelled Prod after the approval: the run asks again, and nothing is built or deleted.
    let v1 = lab
        .vms
        .join("prod-golden-v1")
        .join("prod-golden-v1.vmx")
        .display()
        .to_string();
    core.inventory
        .set_environment(ctx, std::slice::from_ref(&v1), Environment::Prod)
        .await
        .unwrap();
    clock.set(due);
    core.schedules().tick().await.unwrap();
    core.schedules().wait_runs().await;
    let view = core.schedules().get(view.id).await.unwrap();
    assert_eq!(view.state, ScheduleState::NeedsApproval, "{:?}", view.last_run);
    let reason = format!("{:?} {:?}", view.state_reason, view.last_run);
    assert!(reason.contains("is labelled Prod"), "{reason}");
    assert!(!lab.vms.join("prod-golden-v2").exists(), "nothing was built");
    assert!(lab.vmware.has_vm(&v1));
    let _ = std::fs::remove_dir_all(&lab.dir);
}
