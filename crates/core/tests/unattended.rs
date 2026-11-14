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
use remotely_core::jobs::{JobEvent, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::ApprovalStep;
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::stacks::{Readiness, StackDeployRequest, StackInput, StackStep};
use remotely_core::vault::{SecretId, SecretKind, SecretString, UnlockMethod};
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
    let vmx_path = dir.join("vms").join("web-1").join("web-1.vmx");
    let setup =
        Setup::new(FakeVmware::default().with_ip(&vmx_path.display().to_string(), "192.0.2.21")).with_real_vault();
    let ws = Arc::clone(&setup.vmware);
    // The installed system locks its CD doors, as PR 98's hand check saw: a disconnect that isn't answered ahead
    // leaves the drive connected and its file open.
    ws.set_failing("cdrom-locked", true);
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
        ip: None,
        values: Default::default(),
    }];

    // The dialog's check: the install's preview, with the ISO's copy in the free space it needs.
    let check = core.deploy.check(ctx, &request(id, 1, rows.clone())).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let preview = check.preview.unwrap();
    let install = preview.install.as_ref().unwrap();
    assert_eq!(install.kind, "Ubuntu autoinstall");
    assert_eq!(install.vms[0].ip, None, "DHCP: the config has no {{ip}}");
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
    let calls = ws.calls();
    let answer = calls
        .iter()
        .position(|c| c.contains("writeVariable") && c.contains("answer.msg.cdromdisconnect.locked Yes"));
    let disconnect = calls.iter().position(|c| c.contains("disconnectNamedDevice"));
    assert!(
        answer.is_some() && disconnect.is_some() && answer < disconnect,
        "the lock question is answered before the drive is disconnected: {calls:?}"
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
    let folder = vms.join("db-1");
    let seed_path = folder.join("install-seed").join("db-1-seed.iso");
    // The seed while the install runs (it goes when the install ends, however it ends).
    let reader = tokio::spawn({
        let seed_path = seed_path.clone();
        async move {
            for _ in 0..1000 {
                if let Ok(bytes) = std::fs::read(&seed_path) {
                    if let Some(seed) = read_joliet(&bytes).filter(|s| !s.files.is_empty()) {
                        return Some(seed);
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            None
        }
    });
    let job = approve(&core, &approval).await;
    // No installer writes anything: the install runs out of its time. Its VM, ISO copy and log are kept for a look;
    // its seed (the answer file) is taken out.
    let status = wait(&core, job).await;
    assert_eq!(status, JobStatus::Failed);
    let notes = notes_of(&core, job).await;
    assert!(notes.contains("the VM is kept for a look"), "{notes}");
    assert!(notes.contains("not done within"), "{notes}");
    assert!(
        notes.contains("answer file from"),
        "the step's notes stay with its error: {notes}"
    );
    assert!(notes.contains("its seed (the answer file) is taken out"), "{notes}");
    let left = read_joliet(&std::fs::read(&seed_path).unwrap()).unwrap();
    assert!(left.files.is_empty(), "Workstation's drive keeps an empty disc");
    let copy = std::fs::read(folder.join("db-1-install.iso")).unwrap();
    assert!(!folder.join("db-1-install.iso.partial").exists());
    let grub = iso::read_file(&mut std::io::Cursor::new(&copy), "/boot/grub/grub.cfg", Tree::RockRidge)
        .unwrap()
        .unwrap();
    let grub = String::from_utf8(grub).unwrap();
    assert!(grub.contains("preseed/early_command="), "{grub}");
    assert!(grub.contains("/sys/block/"), "the seed's drive is dropped: {grub}");
    let seed = reader.await.unwrap().expect("the seed was read while the install ran");
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
    // The installed guest locks its drives, as PR 98's hand check saw: a plain eject fails while it runs.
    vb.set_failing("dvd-locked", true);
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
        "--medium emptydrive --forceunmount",
    ] {
        assert!(calls.contains(want), "{want} in {calls}");
    }
    assert!(notes.contains("the seed is taken out and deleted"), "{notes}");
    assert!(!notes.contains("still in its drive"), "{notes}");
    // The failed VM is kept, with a screenshot; the one that installed lost its seed and ISO copy.
    let stuck_vm = vb.vm_named("db-2").expect("the failed VM is kept");
    assert!(!stuck_vm.dvds.is_empty());
    assert!(vms.join("db-2").join("db-2-install-failed.png").exists());
    assert!(!vms.join("db-1").join("install-seed").join("db-1-seed.iso").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fake WinRM client playing a new Windows VM: it shows `fingerprint`'s certificate, takes any password until
/// `Set-LocalUser` sets one and only that one after, and breaks the connections `blips` names (by their order, from 0).
#[derive(Default)]
struct FakeWinrm {
    signins: Mutex<Vec<(String, String)>>,
    scripts: Arc<Mutex<Vec<String>>>,
    fingerprint: String,
    /// The Administrator's password once a script set it.
    password: Arc<Mutex<Option<String>>>,
    /// Connections (counted from 0) that fail as a broken connection would.
    blips: Vec<usize>,
    connects: Mutex<usize>,
    /// The first Set-LocalUser applies, then its connection breaks before the answer.
    break_after_swap: Arc<std::sync::atomic::AtomicBool>,
}

struct FakeWinrmSession {
    scripts: Arc<Mutex<Vec<String>>>,
    password: Arc<Mutex<Option<String>>>,
    break_after_swap: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl WinrmAdapter for FakeWinrm {
    async fn connect(&self, request: WinrmConnect<'_>) -> remotely_core::error::Result<Arc<dyn WinrmSession>> {
        let n = {
            let mut connects = self.connects.lock().unwrap();
            *connects += 1;
            *connects - 1
        };
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
        if self.blips.contains(&n) {
            return Err(CoreError::Winrm("the connection was reset".into()));
        }
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
            break_after_swap: Arc::clone(&self.break_after_swap),
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
            // N4: the swap applied, its answer lost once.
            if self.break_after_swap.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(CoreError::Winrm("the connection was reset".into()));
            }
        }
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
    let win_vmx = dir.join("vms").join("win-1").join("win-1.vmx");
    let setup =
        Setup::new(FakeVmware::default().with_ip(&win_vmx.display().to_string(), "192.0.2.31")).with_real_vault();
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
        ip: None,
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
    assert!(
        notes.contains("its copy in Panther (with the one-time password) couldn't be deleted"),
        "the fake printed no removed-original line, so the note says so: {notes}"
    );
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
    let tools = Arc::new(remotely_core::fakes::FakeNetworkTools::new().with_adapter(
        "VMware Network Adapter VMnet8",
        "192.0.2.254",
        24,
        &[],
    ));
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
                host_adapter: None,
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

const FINGERPRINT: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

/// A Windows Server deploy of one VM on Workstation's NAT, approved up to the point its job would start, with `winrm`
/// as the client it signs in with.
async fn windows_lab(label: &str, winrm: Arc<FakeWinrm>) -> (Core, PathBuf, PathBuf, String, ApprovalRequest) {
    let dir = temp_folder(label);
    let win_vmx = dir.join("vms").join("win-1").join("win-1.vmx");
    let core = Setup::new(FakeVmware::default().with_ip(&win_vmx.display().to_string(), "192.0.2.31"))
        .with_real_vault()
        .build()
        .await;
    fast(&core, 1);
    core.set_deploy_winrm(winrm);
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
        ip: None,
        values: Default::default(),
    }];
    let approval = needs_approval(core.deploy.submit(ctx, &request(id, 1, rows)).await.unwrap());
    (core, dir, vms.join("win-1"), secret, approval)
}

/// Setup: two restarts in Workstation's log, then `lines` on the serial port.
fn windows_setup(folder: &Path, lines: Vec<String>) -> tokio::task::JoinHandle<()> {
    windows_setup_with(folder, Vec::new(), lines)
}

/// Setup as [`windows_setup`], with `before` written to the serial port before the restarts (windowsPE, a boot
/// loader). The installed system's `lines` come a good while after the second restart, as they do on a real VM
/// (minutes there), so the watcher has counted it first.
fn windows_setup_with(folder: &Path, before: Vec<String>, lines: Vec<String>) -> tokio::task::JoinHandle<()> {
    let log = folder.join("vmware.log");
    let serial = folder.join("win-1-serial.log");
    tokio::spawn(async move {
        for _ in 0..2000 {
            if serial.with_file_name("install-seed").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        use std::io::Write;
        let append = |path: &Path, text: &[u8]| {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap();
            file.write_all(text).unwrap();
        };
        for line in before {
            append(&serial, line.as_bytes());
        }
        for _ in 0..2 {
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
async fn a_connection_broken_after_the_swap_signs_in_with_the_vaults_password_and_finishes() {
    // D3 of PR 98's review: the second sign-in (after Set-LocalUser) breaks once.
    let winrm = Arc::new(FakeWinrm {
        fingerprint: FINGERPRINT.into(),
        blips: vec![1],
        ..FakeWinrm::default()
    });
    let (core, dir, folder, secret, approval) = windows_lab("unattended-win-blip", winrm.clone()).await;
    let play = windows_setup(&folder, vec![format!("remotely-winrm {FINGERPRINT}\r\n")]);
    let job = approve(&core, &approval).await;
    let status = wait(&core, job).await;
    play.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let signins = winrm.signins.lock().unwrap().clone();
    assert_eq!(
        signins.len(),
        2,
        "the one-time password once, then the vault's: {signins:?}"
    );
    assert_ne!(signins[0].1, secret);
    assert_eq!(
        signins[1].1, secret,
        "after the swap only the vault's password is tried"
    );
    let scripts = winrm.scripts.lock().unwrap().clone();
    assert_eq!(
        scripts.iter().filter(|s| s.contains("Set-LocalUser")).count(),
        1,
        "the swap isn't done again"
    );
    assert!(notes.contains("autologon session is signed out"), "{notes}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_locked_vault_holds_the_sign_in_until_it_is_unlocked() {
    // D2: nothing goes to Windows while the vault is locked; the step says it waits for it.
    let winrm = Arc::new(FakeWinrm {
        fingerprint: FINGERPRINT.into(),
        ..FakeWinrm::default()
    });
    let (core, dir, folder, secret, approval) = windows_lab("unattended-win-vault", winrm.clone()).await;
    let mut events = core.jobs.subscribe();
    let job = approve(&core, &approval).await;
    // Locked once the seed is written, before Windows answers.
    for _ in 0..2000 {
        if folder.join("install-seed").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    core.vault.lock(&core.ctx()).await.unwrap();
    let play = windows_setup(&folder, vec![format!("remotely-winrm {FINGERPRINT}\r\n")]);
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
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        winrm.signins.lock().unwrap().is_empty(),
        "no sign-in while the vault is locked"
    );
    core.vault
        .unlock(
            &core.ctx(),
            UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    let status = wait(&core, job).await;
    play.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    assert_eq!(winrm.signins.lock().unwrap()[1].1, secret);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn another_certificate_fails_the_install_loudly() {
    // D6: WinRM shows a certificate the VM didn't write; and a line before Setup's restarts isn't taken.
    let winrm = Arc::new(FakeWinrm {
        fingerprint: "SHA256:AAAAQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU".into(),
        ..FakeWinrm::default()
    });
    let (core, dir, folder, _secret, approval) = windows_lab("unattended-win-cert", winrm.clone()).await;
    // windowsPE writes a fingerprint before any restart: never taken.
    let play = windows_setup_with(
        &folder,
        vec!["remotely-winrm SHA256:BBBBQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\r\n".into()],
        vec![format!("remotely-winrm {FINGERPRINT}\r\n")],
    );
    let job = approve(&core, &approval).await;
    let status = wait(&core, job).await;
    play.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Failed, "{notes}");
    assert!(notes.contains("WinRM showed the certificate SHA256:AAAA"), "{notes}");
    assert!(
        notes.contains(FINGERPRINT),
        "the pinned one is the installed system's: {notes}"
    );
    assert!(winrm.signins.lock().unwrap().is_empty(), "nothing was sent");
    assert!(notes.contains("its seed (the answer file) is taken out"), "{notes}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_cancelled_install_takes_its_seed_out_and_says_what_it_keeps() {
    // D4: cancelled while it installs.
    let dir = temp_folder("unattended-cancel");
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    fast(&core, 1);
    let ctx = &core.ctx();
    let pw = vault_password(&core, &password()).await;
    let config = config_from(
        &core,
        "starter.ubuntu-24.04-minimal",
        pw,
        Some(deploy_key(&core).await),
        |_| {},
    )
    .await;
    let (image, _) = iso_image(&core, &dir, "noble.iso", &install_isos::ubuntu_24_04(), "ubuntu").await;
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
    let approval = needs_approval(core.deploy.submit(ctx, &request(id, 1, vec![])).await.unwrap());
    let folder = vms.join("web-1");
    let play = installer(
        folder.join("web-1-serial.log"),
        vec!["Command line: BOOT_IMAGE=/casper/vmlinuz autoinstall ---\r\n".into()],
    );
    let job = approve(&core, &approval).await;
    play.await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(core.jobs.cancel(job));
    let status = wait(&core, job).await;
    assert_eq!(status, JobStatus::Cancelled);
    let notes = notes_of(&core, job).await;
    assert!(notes.contains("cancelled while it was watched"), "{notes}");
    assert!(notes.contains("answer file from"), "{notes}");
    assert!(notes.contains("the VM is kept for a look"), "{notes}");
    let seed = read_joliet(&std::fs::read(folder.join("install-seed").join("web-1-seed.iso")).unwrap()).unwrap();
    assert!(seed.files.is_empty(), "the seed is taken out");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_stack_of_an_install_config_asks_for_the_vault_password_too() {
    // D1: the same template deployed alone and as a stack's step asks the same steps.
    let dir = temp_folder("unattended-stack");
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    fast(&core, 1);
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
    let (image, _) = iso_image(&core, &dir, "bookworm.iso", &install_isos::debian(), "debian").await;
    let id = template(
        &core,
        "db",
        &image,
        Hypervisor::Vmware,
        &dir.join("vms"),
        Network::Nat,
        config,
        "gp.medium",
    )
    .await;
    let alone = needs_approval(core.deploy.submit(ctx, &request(id, 1, vec![])).await.unwrap());
    let stack = core
        .stacks
        .add(
            ctx,
            StackInput {
                name: "db lab".into(),
                description: None,
                steps: vec![StackStep {
                    template_id: id,
                    count: 1,
                    readiness: Readiness::None,
                    ready_timeout_secs: 300,
                    delay_secs: 0,
                }],
            },
        )
        .await
        .unwrap();
    let staged = needs_approval(
        core.stacks
            .deploy(
                ctx,
                &StackDeployRequest {
                    stack_id: stack.id,
                    instance_name: None,
                },
            )
            .await
            .unwrap(),
    );
    assert!(alone.steps.contains(&ApprovalStep::VaultReauth));
    assert_eq!(staged.steps, alone.steps, "the stack asks what the deploy asks");
    assert!(
        staged.warnings.iter().any(|w| w.contains("SHA-512 hash")),
        "{:?}",
        staged.warnings
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn virtualboxs_own_unattended_files_go_once_its_iso_is_out_or_the_vm_is_off() {
    // D5 of PR 98's review: VM-21's cleanup waits in the background, not in the job.
    use remotely_core::adapters::hypervisor::Hypervisors;
    use remotely_core::adapters::virtualbox::VirtualBoxAdapter;
    use remotely_core::command_bus::{PowerOp, StopMode};
    use remotely_core::deploy::runner::clean_vbox_unattended;
    use remotely_core::domain::PowerState;

    let dir = temp_folder("unattended-vm21");
    let uuid = "3f0c1a2b-1111-4222-8333-444455556666";
    let vb = Arc::new(FakeVirtualBox::new().with_vm(uuid, "vb-1", PowerState::NotRunning));
    let hypervisors = Hypervisors::new(Arc::new(FakeVmware::default()), vb.clone());
    let args = |list: &[&str]| list.iter().map(|a| (*a).to_owned()).collect::<Vec<String>>();
    vb.change(
        args(&[
            "storagectl",
            uuid,
            "--name",
            "IDE",
            "--add",
            "ide",
            "--controller",
            "PIIX4",
        ]),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let viso = dir.join(format!("Unattended-{uuid}-aux-iso.viso"));
    let data = dir.join(format!("Unattended-{uuid}-user-data"));
    let settings = dir.join("vb-1.vbox");
    for file in [&viso, &data, &settings] {
        std::fs::write(file, b"x").unwrap();
    }
    let attach = |medium: &str| {
        args(&[
            "storageattach",
            uuid,
            "--storagectl",
            "IDE",
            "--port",
            "0",
            "--device",
            "0",
            "--type",
            "dvddrive",
            "--medium",
            medium,
        ])
    };
    vb.change(attach(&viso.display().to_string()), Duration::from_secs(5))
        .await
        .unwrap();
    vb.power(uuid, PowerOp::Start { gui: false }).await.unwrap();
    // Still installing, the virtual ISO in its drive: everything stays.
    let left = clean_vbox_unattended(
        &hypervisors,
        uuid,
        &dir,
        Duration::from_millis(10),
        Duration::from_millis(80),
    )
    .await;
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(viso.exists() && data.exists());
    // N2: saved mid-install (suspended) isn't off: the install goes on when it is resumed, so nothing goes.
    vb.power(uuid, PowerOp::Suspend).await.unwrap();
    let left = clean_vbox_unattended(
        &hypervisors,
        uuid,
        &dir,
        Duration::from_millis(10),
        Duration::from_millis(80),
    )
    .await;
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(viso.exists() && data.exists(), "a saved VM keeps its install files");
    vb.power(uuid, PowerOp::Start { gui: false }).await.unwrap();
    // Shut down with it still in (Windows never ejects it): ejected, closed and deleted; other files stay.
    vb.power(uuid, PowerOp::Stop { mode: StopMode::Hard }).await.unwrap();
    let left = clean_vbox_unattended(
        &hypervisors,
        uuid,
        &dir,
        Duration::from_millis(10),
        Duration::from_secs(5),
    )
    .await;
    assert!(left.is_empty(), "{left:?}");
    assert!(!viso.exists() && !data.exists());
    assert!(settings.exists(), "only VirtualBox's install files go");
    let calls = vb.calls().join("\n");
    assert!(calls.contains("--medium emptydrive"), "{calls}");
    assert!(calls.contains("closemedium dvd"), "{calls}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_swap_whose_answer_was_lost_signs_in_with_the_vaults_password_next() {
    // N4 of PR 98's re-check: Set-LocalUser applied, then the connection broke before its answer.
    let winrm = Arc::new(FakeWinrm {
        fingerprint: FINGERPRINT.into(),
        break_after_swap: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        ..FakeWinrm::default()
    });
    let (core, dir, folder, secret, approval) = windows_lab("unattended-win-lost", winrm.clone()).await;
    let play = windows_setup(&folder, vec![format!("remotely-winrm {FINGERPRINT}\r\n")]);
    let job = approve(&core, &approval).await;
    let status = wait(&core, job).await;
    play.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    let signins = winrm.signins.lock().unwrap().clone();
    assert!(signins.len() >= 2, "{signins:?}");
    assert!(
        signins[1..].iter().all(|(_, p)| *p == secret),
        "after the lost answer, the vault's password: {signins:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_fingerprint_line_written_before_the_restarts_is_never_taken_however_late_it_is_read() {
    // N5: a long log before the restarts, ending in a forged line; then the restarts and the real one.
    let winrm = Arc::new(FakeWinrm {
        fingerprint: FINGERPRINT.into(),
        ..FakeWinrm::default()
    });
    let (core, dir, folder, _secret, approval) = windows_lab("unattended-win-late", winrm.clone()).await;
    // More log than one read takes, written before the restarts, the forged line last.
    let mut before = "x".repeat(900 * 1024);
    before.push_str("\r\nremotely-winrm SHA256:BBBBQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\r\n");
    let play = windows_setup_with(&folder, vec![before], vec![format!("remotely-winrm {FINGERPRINT}\r\n")]);
    let job = approve(&core, &approval).await;
    let status = wait(&core, job).await;
    play.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "the real certificate was pinned: {notes}");
    assert!(notes.contains(FINGERPRINT), "{notes}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_wait_for_the_vault_doesnt_count_against_the_time_limit() {
    // N9: locked past the install's own time limit, then unlocked: the install still finishes.
    let winrm = Arc::new(FakeWinrm {
        fingerprint: FINGERPRINT.into(),
        ..FakeWinrm::default()
    });
    let (core, dir, folder, secret, approval) = windows_lab("unattended-win-limit", winrm.clone()).await;
    core.set_deploy_tuning(DeployTuning {
        install_poll: Duration::from_millis(20),
        install_cap: Some(Duration::from_millis(1500)),
        connect_wait: Duration::from_millis(500),
        leases_file: None,
        probe: Some(("127.0.0.1".into(), 1, 1)),
        ..DeployTuning::default()
    });
    let job = approve(&core, &approval).await;
    for _ in 0..2000 {
        if folder.join("install-seed").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    core.vault.lock(&core.ctx()).await.unwrap();
    let play = windows_setup(&folder, vec![format!("remotely-winrm {FINGERPRINT}\r\n")]);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    core.vault
        .unlock(
            &core.ctx(),
            UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    let status = wait(&core, job).await;
    play.await.unwrap();
    let notes = notes_of(&core, job).await;
    assert_eq!(status, JobStatus::Succeeded, "{notes}");
    assert_eq!(winrm.signins.lock().unwrap()[1].1, secret);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_seed_that_wont_leave_its_drive_is_said_so_and_kept() {
    // N10: the eject failed, so the seed isn't emptied, and the note says it is still in its drive.
    let dir = temp_folder("unattended-stuck-seed");
    let setup = Setup::new(FakeVmware::default()).with_real_vault();
    let vmware = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.set_deploy_tuning(DeployTuning {
        install_poll: Duration::from_millis(20),
        install_cap: Some(Duration::from_millis(600)),
        leases_file: None,
        probe: Some(("127.0.0.1".into(), 1, 1)),
        ..DeployTuning::default()
    });
    vmware.set_failing("disconnectNamedDevice", true);
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
    assert_eq!(wait(&core, job).await, JobStatus::Failed);
    let notes = notes_of(&core, job).await;
    assert!(notes.contains("is still in its drive"), "{notes}");
    assert!(!notes.contains("its seed (the answer file) is taken out"), "{notes}");
    let seed =
        read_joliet(&std::fs::read(vms.join("db-1").join("install-seed").join("db-1-seed.iso")).unwrap()).unwrap();
    assert_eq!(seed.files.len(), 1, "a seed still in its drive isn't emptied under it");
    let _ = std::fs::remove_dir_all(&dir);
}
