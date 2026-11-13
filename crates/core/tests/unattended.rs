//! VM-29, VM-32 (0.8.0 G6): unattended deploys from install configs end to end on a core with fake hypervisors. The
//! ISOs are small images made at run time (`fakes::install_isos`), the installers are played by the test writing the
//! lines S1 to S3 saw into each VM's serial log, the installed system's SSH is a banner on 127.0.0.1, and a new
//! Windows VM's WinRM a fake client. Everything lives in the system temp folder; no real VM, ISO or host is touched.

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
use remotely_core::adapters::winrm::console::ConsoleShell;
use remotely_core::adapters::winrm::http::CERT_KEY_TYPE;
use remotely_core::adapters::winrm::{WinrmAdapter, WinrmConnect, WinrmSession};
use remotely_core::address_pools::AddressPoolInput;
use remotely_core::catalog::install::{starters, InstallConfigInput, SecretRefKind};
use remotely_core::catalog::{
    AfterDeploy, CloneMode, HashProgress, Image, ImageInput, Network, SourceInput, TemplateInput,
};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, SubmitOutcome};
use remotely_core::deploy::iso::{self, Tree};
use remotely_core::deploy::runner::DeployTuning;
use remotely_core::deploy::seed::read_joliet;
use remotely_core::deploy::service::{DeployFrom, DeployRequest};
use remotely_core::deploy::spec::VmInstall;
use remotely_core::domain::Environment;
use remotely_core::fakes::{install_isos, FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::ApprovalStep;
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::{Core, CoreError};
use uuid::Uuid;

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
    core.set_deploy_tuning(DeployTuning {
        ip_poll: Duration::from_millis(10),
        ip_wait_cap: Some(Duration::from_millis(500)),
        cleanup_tries: 3,
        cleanup_pause: Duration::from_millis(10),
        install_poll: Duration::from_millis(20),
        install_cap: Some(Duration::from_secs(20)),
        hang_silence: Duration::from_millis(300),
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
            "install admin",
            SecretString::new(value),
        )
        .await
        .unwrap()
        .id
}

async fn deploy_key(core: &Core) -> SecretId {
    core.keys
        .generate(
            &core.ctx(),
            GenerateKey {
                label: "install key".into(),
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
    spec.name = format!("{} (lab)", spec.name);
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

async fn iso_image(core: &Core, dir: &Path, name: &str, bytes: &[u8], profile: &str) -> (Image, PathBuf) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    let progress: Arc<dyn Fn(HashProgress) + Send + Sync> = Arc::new(|_| {});
    let image = core
        .catalog
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
        .unwrap();
    (image, path)
}

#[allow(clippy::too_many_arguments)]
async fn template(
    core: &Core,
    name: &str,
    image: &Image,
    hypervisor: Hypervisor,
    folder: &Path,
    network: Network,
    config: Uuid,
    size: &str,
) -> Uuid {
    core.catalog
        .add_template(
            &core.ctx(),
            TemplateInput {
                name: name.into(),
                image_id: image.id,
                size_id: size.into(),
                hypervisor,
                vm_folder: Some(folder.display().to_string()),
                network,
                ssh_key_id: None,
                naming_pattern: format!("{name}-{{n}}"),
                default_count: 1,
                environment: Environment::Lab,
                tags: vec!["lab".into()],
                after_deploy: AfterDeploy {
                    create_session: true,
                    link_session: true,
                    clean_snapshot: true,
                    open_console: false,
                },
                guest_user: None,
                packages: vec![],
                clone_mode: CloneMode::Full,
                install_config_id: Some(config),
            },
        )
        .await
        .unwrap()
        .id
}

fn request(template: Uuid, count: u32, rows: Vec<VmInstall>) -> DeployRequest {
    DeployRequest {
        from: DeployFrom::Template { id: template },
        count,
        naming_pattern: None,
        host_adapter: None,
        guest_password_id: None,
        vm_values: rows,
        address_pool_id: None,
        install_minutes: None,
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
        reason: Some("lab build".into()),
        safety_snapshot: None,
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
        .expect("the deploy finished in time")
        .unwrap()
}

/// Plays an installer: once the VM's folder is there, writes `lines` into its serial log one by one.
fn installer(serial: PathBuf, lines: Vec<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..2000 {
            if serial.parent().is_some_and(Path::exists) && serial.with_file_name("install-seed").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for line in lines {
            tokio::time::sleep(Duration::from_millis(40)).await;
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&serial)
                .unwrap();
            file.write_all(line.as_bytes()).unwrap();
        }
    })
}

async fn notes_of(core: &Core, job: Uuid) -> String {
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    targets
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
        .join(
            "
",
        )
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

#[tokio::test]
async fn ubuntu_installs_unattended_on_workstation_from_its_own_iso_copy_and_seed() {
    let dir = temp_folder("unattended-ubuntu");
    let setup = Setup::new(FakeVmware::default()).with_real_vault();
    let ws = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let ssh = ssh_banner().await;
    fast(&core, ssh);
    let ctx = &core.ctx();
    let secret = password();
    let pw = vault_password(&core, &secret).await;
    let key = deploy_key(&core).await;
    let config = config_from(&core, "starter.ubuntu-24.04-minimal", pw, Some(key), |_| {}).await;
    let (image, original) = iso_image(&core, &dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
    let original_bytes = std::fs::read(&original).unwrap();
    let vms = dir.join("vms");
    let id = template(
        &core,
        "web",
        &image,
        Hypervisor::Vmware,
        &vms,
        Network::Nat,
        config,
        "gp.medium",
    )
    .await;
    let rows = vec![VmInstall {
        ip: Some("192.0.2.21".into()),
        values: Default::default(),
    }];

    // The dialog's check: the install's preview, with the ISO's copy in the free space it needs.
    let check = core.deploy.check(ctx, &request(id, 1, rows.clone())).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let preview = check.preview.unwrap();
    let install = preview.install.as_ref().unwrap();
    assert_eq!(install.kind, "Ubuntu autoinstall");
    assert_eq!(install.vms[0].ip.as_deref(), Some("192.0.2.21"));
    assert_eq!(install.iso_copy_bytes, Some(original_bytes.len() as u64));

    let approval = needs_approval(core.deploy.submit(ctx, &request(id, 1, rows)).await.unwrap());
    assert!(
        approval.steps.contains(&ApprovalStep::VaultReauth),
        "{:?}",
        approval.steps
    );
    assert!(
        approval.warnings.iter().any(|w| w.contains("SHA-512 hash")),
        "{:?}",
        approval.warnings
    );
    let folder = vms.join("web-1");
    let play = installer(folder.join("web-1-serial.log"), ubuntu_lines("web-1"));
    let job = approve(&core, &approval).await;
    let status = wait(&core, job).await;
    play.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");

    // The VM booted its copy of the ISO with its seed in a second drive and COM1 to a file.
    let vmx = ws.vmx_text(&folder.join("web-1.vmx").display().to_string()).unwrap();
    let iso_copy = folder.join("web-1-install.iso");
    let seed = folder.join("install-seed").join("web-1-seed.iso");
    for want in [
        format!("sata0:0.fileName = \"{}\"", iso_copy.display()),
        format!("sata0:1.fileName = \"{}\"", seed.display()),
        "serial0.fileType = \"file\"".into(),
        format!("serial0.fileName = \"{}\"", folder.join("web-1-serial.log").display()),
    ] {
        assert!(vmx.contains(&want), "{want} in {vmx}");
    }
    // The original ISO is untouched; both drives hold empty discs once the install is done.
    assert_eq!(std::fs::read(&original).unwrap(), original_bytes);
    for emptied in [&iso_copy, &seed] {
        let disc = read_joliet(&std::fs::read(emptied).unwrap()).unwrap();
        assert!(
            disc.files.is_empty(),
            "{} still holds {:?}",
            emptied.display(),
            disc.files
        );
    }
    assert!(
        ws.calls().iter().any(|c| c.contains("disconnectNamedDevice")),
        "{:?}",
        ws.calls()
    );
    assert!(
        ws.snapshot_names(&folder.join("web-1.vmx").display().to_string())
            .contains(&"clean install".to_owned()),
        "the clean install snapshot"
    );
    // The job's note names the config and the file's SHA-256, never the file, the password or its hash.
    assert!(notes.contains("SHA-256"), "{notes}");
    assert!(notes.contains("installed, reached at 192.0.2.21"), "{notes}");
    let audit = format!("{:?}", core.store.recent_audit(ctx, 200).await.unwrap());
    for leak in [secret.as_str(), "$6$"] {
        assert!(!audit.contains(leak), "the audit log holds {leak}");
        assert!(!notes.contains(leak), "the job holds {leak}");
    }
    // The SSH session, as the config's user, linked to the VM.
    let sessions = core.sessions.list(ctx, &Default::default()).await.unwrap();
    let session = sessions.iter().find(|s| s.name == "web-1").expect("a session");
    assert_eq!(session.host, "192.0.2.21");
    assert_eq!(session.username.as_deref(), Some("sysadmin"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_iso_copy_and_seed_carry_the_boot_menu_and_the_rendered_file() {
    // The copy and the seed as the job makes them, read back before the install takes them out.
    let dir = temp_folder("unattended-media");
    let setup = Setup::new(FakeVmware::default()).with_real_vault();
    let core = setup.build().await;
    fast(&core, 1);
    core.set_deploy_tuning(DeployTuning {
        install_poll: Duration::from_millis(20),
        install_cap: Some(Duration::from_millis(1500)),
        leases_file: None,
        probe: Some(("127.0.0.1".into(), 1, 1)),
        ..DeployTuning::default()
    });
    let ctx = &core.ctx();
    let secret = password();
    let pw = vault_password(&core, &secret).await;
    let config = config_from(
        &core,
        "starter.debian-12-minimal",
        pw,
        Some(deploy_key(&core).await),
        |_| {},
    )
    .await;
    let (image, _) = iso_image(&core, &dir, "bookworm.iso", &install_isos::debian(), "debian").await;
    let vms = dir.join("vms");
    let id = template(
        &core,
        "db",
        &image,
        Hypervisor::Vmware,
        &vms,
        Network::Nat,
        config,
        "gp.medium",
    )
    .await;
    let approval = needs_approval(core.deploy.submit(ctx, &request(id, 1, vec![])).await.unwrap());
    let job = approve(&core, &approval).await;
    // No installer writes anything: the install runs out of its time, and its VM and media are kept for a look.
    let status = wait(&core, job).await;
    assert_eq!(status, JobStatus::Failed);
    let notes = notes_of(&core, job).await;
    assert!(notes.contains("kept as it is"), "{notes}");
    let folder = vms.join("db-1");
    let copy = std::fs::read(folder.join("db-1-install.iso")).unwrap();
    let grub = iso::read_file(&mut std::io::Cursor::new(&copy), "/boot/grub/grub.cfg", Tree::RockRidge)
        .unwrap()
        .unwrap();
    let grub = String::from_utf8(grub).unwrap();
    assert!(grub.contains("preseed/early_command="), "{grub}");
    assert!(grub.contains("/sys/block/"), "the seed's drive is dropped: {grub}");
    let seed = read_joliet(&std::fs::read(folder.join("install-seed").join("db-1-seed.iso")).unwrap()).unwrap();
    let (name, preseed) = &seed.files[0];
    assert_eq!(name, "preseed.cfg");
    let preseed = String::from_utf8(preseed.clone()).unwrap();
    assert!(preseed.contains("d-i netcfg/get_hostname string db-1"), "{preseed}");
    assert!(preseed.contains("user-password-crypted password $6$rounds=5000$"));
    assert!(!preseed.contains(&secret), "only the hash");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn debian_on_virtualbox_nat_reaches_its_guest_through_a_rule_and_a_question_fails_the_install() {
    let dir = temp_folder("unattended-debian");
    let setup = Setup::new(FakeVmware::default())
        .with_virtualbox(FakeVirtualBox::new())
        .with_real_vault();
    let vb = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    fast(&core, 1);
    core.set_deploy_tuning(DeployTuning {
        install_poll: Duration::from_millis(20),
        install_cap: Some(Duration::from_secs(20)),
        connect_wait: Duration::from_millis(500),
        leases_file: None,
        probe: None,
        ..DeployTuning::default()
    });
    let ctx = &core.ctx();
    let pw = vault_password(&core, &password()).await;
    let config = config_from(
        &core,
        "starter.debian-12-minimal",
        pw,
        Some(deploy_key(&core).await),
        |_| {},
    )
    .await;
    let (image, _) = iso_image(&core, &dir, "trixie.iso", &install_isos::debian(), "debian").await;
    let vms = dir.join("vms");
    let id = template(
        &core,
        "db",
        &image,
        Hypervisor::VirtualBox,
        &vms,
        Network::Nat,
        config,
        "gp.medium",
    )
    .await;
    let approval = needs_approval(core.deploy.submit(ctx, &request(id, 2, vec![])).await.unwrap());
    // The guests' SSH through the NAT rule the deploy adds: a banner on the port it picked.
    let calls_for = |vb: &FakeVirtualBox| vb.calls().join("\n");
    let vb2 = Arc::clone(&vb);
    let banner = tokio::spawn(async move {
        // Each VM gets a rule of its own: every port it names answers.
        let mut listening = std::collections::HashSet::new();
        for _ in 0..3000 {
            let calls = calls_for(&vb2);
            for rule in calls.split("remotely-install,tcp,127.0.0.1,").skip(1) {
                let port: u16 = rule.split(',').next().unwrap().parse().unwrap();
                if listening.insert(port) {
                    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
                    tokio::spawn(async move {
                        while let Ok((mut stream, _)) = listener.accept().await {
                            use tokio::io::AsyncWriteExt;
                            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.2 test\r\n").await;
                        }
                    });
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let good = installer(
        vms.join("db-1").join("db-1-serial.log"),
        vec![
            "\x1b[1;1H Detecting hardware to find installation media\x1b[2;1H".into(),
            "\x1b[5;3H\x1b[31mInstalling the base system\x1b[0m\x1b[6;1H".into(),
            "\r\nreboot: Restarting system\r\n GNU GRUB  version 2.06\r\n".into(),
            "Debian GNU/Linux 12 db-1 ttyS0\r\n\r\ndb-1 login: ".into(),
        ],
    );
    let stuck = installer(
        vms.join("db-2").join("db-2-serial.log"),
        vec![
            "\x1b[1;1H Detecting hardware to find installation media\x1b[2;1H".into(),
            "\x1b[3;10H\x1b(0u\x1b(B\x1b[31m [!!] Partition disks \x1b[0m\x1b(0t\x1b(B\x1b[4;1H".into(),
        ],
    );
    let job = approve(&core, &approval).await;
    let status = wait(&core, job).await;
    good.await.unwrap();
    stuck.await.unwrap();
    banner.abort();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::PartiallyFailed, "{notes}");
    assert!(notes.contains("Partition disks"), "{notes}");
    assert!(notes.contains("installed, reached at 127.0.0.1"), "{notes}");
    let calls = vb.calls().join("\n");
    for want in [
        "--uart1 0x3F8 4 --uartmode1 file",
        "--boot1 disk --boot2 dvd",
        "natpf1 delete remotely-install",
        "--medium emptydrive",
    ] {
        assert!(calls.contains(want), "{want} in {calls}");
    }
    // The failed VM is kept, with a screenshot; the one that installed lost its seed and ISO copy.
    let stuck_vm = vb.vm_named("db-2").expect("the failed VM is kept");
    assert!(!stuck_vm.dvds.is_empty());
    assert!(vms.join("db-2").join("db-2-install-failed.png").exists());
    assert!(!vms.join("db-1").join("install-seed").join("db-1-seed.iso").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fake WinRM client: checks the certificate the deploy pins, records each sign-in and script.
#[derive(Default)]
struct FakeWinrm {
    signins: Mutex<Vec<(String, String)>>,
    scripts: Arc<Mutex<Vec<String>>>,
    fingerprint: String,
}

struct FakeWinrmSession {
    scripts: Arc<Mutex<Vec<String>>>,
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
        self.signins
            .lock()
            .unwrap()
            .push((request.spec.username.clone().unwrap_or_default(), password));
        Ok(Arc::new(FakeWinrmSession {
            scripts: Arc::clone(&self.scripts),
        }))
    }
}

#[async_trait]
impl ExecSession for FakeWinrmSession {
    async fn run(&self, script: &str, max_output: usize) -> remotely_core::error::Result<ExecResult> {
        self.scripts.lock().unwrap().push(script.to_owned());
        let stdout = if script.contains("unattend-original.xml") {
            "answer-file 00\r\nsigned-out 1\r\n"
        } else {
            ""
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

#[tokio::test]
async fn windows_gets_the_vault_password_over_winrm_with_the_certificate_from_its_serial_port() {
    let dir = temp_folder("unattended-windows");
    let setup = Setup::new(FakeVmware::default()).with_real_vault();
    let core = setup.build().await;
    fast(&core, 1);
    let fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU".to_owned();
    let winrm = Arc::new(FakeWinrm {
        fingerprint: fingerprint.clone(),
        ..FakeWinrm::default()
    });
    core.set_deploy_winrm(winrm.clone());
    let ctx = &core.ctx();
    let secret = password();
    let pw = vault_password(&core, &secret).await;
    let config = config_from(&core, "starter.windows-server-2025", pw, None, |_| {}).await;
    let (image, _) = iso_image(
        &core,
        &dir,
        "server.iso",
        &install_isos::windows_server(),
        "windows-server",
    )
    .await;
    let vms = dir.join("vms");
    let id = template(
        &core,
        "win",
        &image,
        Hypervisor::Vmware,
        &vms,
        Network::Nat,
        config,
        "gp.large",
    )
    .await;
    let rows = vec![VmInstall {
        ip: Some("192.0.2.31".into()),
        values: Default::default(),
    }];
    let approval = needs_approval(core.deploy.submit(ctx, &request(id, 1, rows)).await.unwrap());
    assert!(approval.steps.contains(&ApprovalStep::VaultReauth));
    let folder = vms.join("win-1");
    // Setup restarts twice (Workstation's log), then the first sign-in writes the certificate's fingerprint.
    let log = folder.join("vmware.log");
    let resets = tokio::spawn({
        let log = log.clone();
        async move {
            for _ in 0..2000 {
                if log.parent().is_some_and(Path::exists) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            for _ in 0..2 {
                tokio::time::sleep(Duration::from_millis(60)).await;
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                    .unwrap();
                file.write_all(b"2026-11-13T10:00:00.000Z In(05) vcpu-0 Chipset: The guest has requested that the virtual machine be hard reset.\n").unwrap();
            }
        }
    });
    let play = installer(
        folder.join("win-1-serial.log"),
        vec![
            "remotely-stage specialize 10:01:02.03 \r\n".into(),
            "pause\r\n".into(),
            "pause\r\n".into(),
            format!("\x1b[0mremotely-winrm {fingerprint}\r\n"),
        ],
    );
    let job = approve(&core, &approval).await;
    let status = wait(&core, job).await;
    play.await.unwrap();
    resets.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    // First the one-time password, then the vault's: the Administrator's was set to it in between, on stdin.
    let signins = winrm.signins.lock().unwrap().clone();
    assert_eq!(signins.len(), 2, "{signins:?}");
    assert_eq!(signins[0].0, "Administrator");
    assert_ne!(signins[0].1, secret);
    assert_eq!(signins[0].1.len(), 24, "the one-time password");
    assert_eq!(signins[1].1, secret);
    let scripts = winrm.scripts.lock().unwrap().clone();
    assert!(scripts[0].contains("Set-LocalUser -Name 'Administrator'"));
    assert!(scripts[0].contains(&format!("'{secret}'")));
    assert!(scripts[1].contains("unattend-original.xml"));
    assert!(notes.contains("autologon session is signed out"), "{notes}");
    // Rule 7: neither password reaches the job, the audit log or the session list.
    let audit = format!("{:?}", core.store.recent_audit(ctx, 200).await.unwrap());
    for leak in [secret.as_str(), signins[0].1.as_str()] {
        assert!(!notes.contains(leak));
        assert!(!audit.contains(leak));
    }
    // The WinRM session, its certificate trusted as the VM wrote it.
    let sessions = core.sessions.list(ctx, &Default::default()).await.unwrap();
    assert!(
        sessions.iter().any(|s| s.name == "win-1" && s.host == "192.0.2.31"),
        "{sessions:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn deploys_refuse_what_they_cant_deliver_and_take_addresses_from_a_pool() {
    let dir = temp_folder("unattended-checks");
    let tools = Arc::new(remotely_core::fakes::FakeNetworkTools::new());
    for n in 100..=110 {
        tools.set_silent(&format!("192.0.2.{n}"), true);
    }
    let setup = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_network_tools(tools.clone());
    let core = setup.build().await;
    fast(&core, 1);
    let ctx = &core.ctx();
    let pw = vault_password(&core, &password()).await;
    let key = deploy_key(&core).await;
    let (image, _) = iso_image(&core, &dir, "bookworm.iso", &install_isos::debian(), "debian").await;
    let vms = dir.join("vms");

    // A preseed with a static address: {{ip}} and the pool's gateway and netmask as its own variables.
    let config = config_from(&core, "starter.debian-12-minimal", pw, Some(key), |spec| {
        spec.body.push_str("d-i netcfg/disable_autoconfig boolean true\nd-i netcfg/get_ipaddress string {{ip}}\nd-i netcfg/get_netmask string {{netmask}}\nd-i netcfg/get_gateway string {{gateway}}\n");
        for name in ["netmask", "gateway"] {
            spec.variables.push(remotely_core::catalog::install::VariableDef {
                name: name.into(),
                default: None,
            });
        }
    })
    .await;
    let pool = core
        .address_pools
        .add(
            ctx,
            AddressPoolInput {
                name: "lab".into(),
                hypervisor: Hypervisor::Vmware,
                network: Network::Nat,
                first_ip: "192.0.2.100".into(),
                last_ip: "192.0.2.110".into(),
                prefix: 24,
                gateway: Some("192.0.2.1".into()),
                dns: vec!["192.0.2.53".into()],
                notes: None,
            },
        )
        .await
        .unwrap();
    let id = template(
        &core,
        "db",
        &image,
        Hypervisor::Vmware,
        &vms,
        Network::Nat,
        config,
        "gp.medium",
    )
    .await;
    // Without an address, a config that uses {{ip}} can't render.
    let check = core.deploy.check(ctx, &request(id, 2, vec![])).await.unwrap();
    assert!(
        check.problems.iter().any(|p| p.message.contains("needs an IP address")),
        "{:?}",
        check.problems
    );
    // With the pool: each VM gets the next free address, and the gateway and netmask fill its variables.
    let pooled = DeployRequest {
        address_pool_id: Some(pool.id),
        ..request(id, 2, vec![])
    };
    let check = core.deploy.check(ctx, &pooled).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let install = check.preview.unwrap().install.unwrap();
    assert_eq!(install.pool.as_deref(), Some("lab"));
    let ips: Vec<_> = install.vms.iter().map(|v| v.ip.clone().unwrap()).collect();
    assert_eq!(ips, ["192.0.2.100", "192.0.2.101"]);
    assert_eq!(
        install.vms[0].values.get("gateway").map(String::as_str),
        Some("192.0.2.1")
    );
    assert_eq!(
        install.vms[0].values.get("netmask").map(String::as_str),
        Some("255.255.255.0")
    );

    // A config edited after the approval refuses to run.
    let approval = needs_approval(core.deploy.submit(ctx, &pooled).await.unwrap());
    let mut edited = core
        .catalog
        .install_config(ctx, &config.to_string())
        .await
        .unwrap()
        .spec;
    edited.notes = Some("changed".into());
    edited.body.push_str("d-i clock-setup/ntp boolean false\n");
    core.catalog.update_install_config(ctx, config, edited).await.unwrap();
    let job = approve(&core, &approval).await;
    assert_eq!(wait(&core, job).await, JobStatus::Failed);
    let notes = notes_of(&core, job).await;
    assert!(notes.contains("changed since the deploy was approved"), "{notes}");
    // The addresses went back to the pool.
    let pools = core.address_pools.list(ctx).await.unwrap();
    assert_eq!(pools[0].used, 0, "{pools:?}");

    // Kickstart isn't delivered yet.
    let ks = config_from(&core, "starter.rocky-9-minimal", pw, Some(key), |_| {}).await;
    let (rocky, _) = iso_image(&core, &dir, "rocky.iso", &install_isos::debian(), "rhel").await;
    let id = template(
        &core,
        "rk",
        &rocky,
        Hypervisor::Vmware,
        &vms,
        Network::Nat,
        ks,
        "gp.medium",
    )
    .await;
    let check = core.deploy.check(ctx, &request(id, 1, vec![])).await.unwrap();
    assert!(
        check.problems.iter().any(|p| p.message.contains("Kickstart")),
        "{:?}",
        check.problems
    );
    let _ = std::fs::remove_dir_all(&dir);
}
