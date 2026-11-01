//! FD-05, BX-12, FD-08 end to end: the inventory to Excel, the Ansible inventory and the handover pack, read from the
//! fake hypervisors and from SSH servers on 127.0.0.1 that describe an Ubuntu or RHEL host (`fakes::ssh_server::host`),
//! written to the system temp folder and read back: the xlsx's cells, both Ansible formats, the zip's members, the
//! page's policy and that no secret reaches any of the files. No real host or VM is read.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{vault_password_given, vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::host_networks::{ForwardProtocol, VmnetForward, VmnetKind};
use remotely_core::adapters::remote::AgentSource;
use remotely_core::adapters::vm_hardware::{VirtualDisk, VirtualNic, VmHardware};
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::bulk::TargetPicks;
use remotely_core::checks::spec::{CheckInput, CheckSpec};
use remotely_core::checks::{CheckResult, RunResult};
use remotely_core::command_bus::{ApprovalAnswers, Command, PowerOp, SubmitOutcome};
use remotely_core::domain::{Context, Environment, TargetRef};
use remotely_core::fakes::ssh_server::host::HostFixture;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::FakeVmware;
use remotely_core::host_details::SpecsTuning;
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::notes::{NoteInput, NoteTarget};
use remotely_core::policy::ApprovalStep;
use remotely_core::presentation::Presentation;
use remotely_core::reports::{
    AnsibleFormat, AnsibleRequest, GroupBy, HandoverRequest, InventoryOptions, InventoryRequest, ReadControl,
};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::toolbox::ProbeTarget;
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::workspaces::WorkspaceInput;
use remotely_core::Core;
use uuid::Uuid;

/// What must never reach a file: put in a note, a job's output, a session's name and a tag.
const SECRET: &str = "Hunter2Secret";

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn no_agent() -> AgentSource {
    AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4()))
}

/// A folder of its own in the system temp folder, removed when dropped.
struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("remotely-reports-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every member of a zip (an xlsx is one) as text, by name.
fn members(path: &Path) -> Vec<(String, Vec<u8>)> {
    let bytes = std::fs::read(path).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..zip.len())
        .map(|i| {
            let mut file = zip.by_index(i).unwrap();
            let mut data = Vec::new();
            file.read_to_end(&mut data).unwrap();
            (file.name().unwrap().into_owned(), data)
        })
        .collect()
}

fn text_of(members: &[(String, Vec<u8>)], name: &str) -> String {
    let (_, data) = members
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("{name} is in the zip"));
    String::from_utf8_lossy(data).into_owned()
}

/// Every text an xlsx holds: its members' XML, with the shared strings unescaped enough to find a word.
fn xlsx_text(bytes: &[u8]) -> String {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
    let mut all = String::new();
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).unwrap();
        let mut text = String::new();
        let _ = file.read_to_string(&mut text);
        all.push_str(&text);
    }
    all
}

fn web_hardware() -> VmHardware {
    VmHardware {
        guest_os_name: Some("Ubuntu 24.04.1 LTS".into()),
        vcpus: Some(4),
        memory_mb: Some(8192),
        firmware: Some("UEFI".into()),
        disks: vec![VirtualDisk {
            slot: "scsi0:0".into(),
            path: r"C:\VMs\web\web.vmdk".into(),
            provisioned_bytes: Some(40 * 1024 * 1024 * 1024),
            thin: Some(true),
            ..VirtualDisk::default()
        }],
        nics: vec![VirtualNic {
            slot: "ethernet0".into(),
            connection: Some("nat".into()),
            mac: Some("00:0c:29:ab:cd:ef".into()),
            ..VirtualNic::default()
        }],
        guest_ips: vec!["192.0.2.10".into()],
        ..VmHardware::default()
    }
}

fn forward(host_port: u16, guest_ip: &str) -> VmnetForward {
    VmnetForward {
        protocol: ForwardProtocol::Tcp,
        host_port,
        guest_ip: guest_ip.into(),
        guest_port: 22,
        description: None,
    }
}

/// Workstation with `web` (running, its hardware known, on NAT vmnet8) and a VM whose name is a formula. Rule 8: the
/// networks are this PC's: vmnet8 also forwards to 203.0.113.99, which no VM of the lab has, and vmnet3 has no VM.
fn vmware() -> FakeVmware {
    FakeVmware::with_running([vmx("web")])
        .in_library(&vmx("web"), Some("web"))
        .in_library(&vmx("evil"), None)
        .with_vmx(
            &vmx("evil"),
            VmxInfo {
                display_name: Some("=HYPERLINK(\"http://example.com\",\"x\")".into()),
                ..Default::default()
            },
        )
        .with_hardware(&vmx("web"), web_hardware())
        .with_ip(&vmx("web"), "192.0.2.10")
        .with_vmnet(8, VmnetKind::Nat, "192.0.2.0")
        .with_vmnet(3, VmnetKind::HostOnly, "198.51.100.0")
        .with_forward("vmnet8", forward(2210, "192.0.2.10"))
        .with_forward("vmnet8", forward(2299, "203.0.113.99"))
}

async fn core() -> Core {
    let core = Setup::new(vmware()).with_real_vault().with_ssh().build().await;
    core.host_details.collector().set_tuning(SpecsTuning {
        agent: no_agent(),
        connect_timeout: Duration::from_secs(5),
        ..SpecsTuning::default()
    });
    core
}

async fn server(password: &str, fixture: HostFixture, hostname: &str) -> TestSshServer {
    TestSshServer::start()
        .await
        .with_password("alice", password)
        .with_hostname(hostname)
        .with_host_facts(fixture)
}

async fn trust(core: &Core, server: &TestSshServer) {
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
}

fn input(name: &str, host: &str, port: u16, password_id: Option<remotely_core::vault::SecretId>) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port,
        username: Some("alice".into()),
        auth: SessionAuth::Password { password_id },
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: Default::default(),
    }
}

/// Two SSH hosts (Ubuntu and RHEL) on test servers, a session behind a jump host, an RDP session and a folder.
struct Lab {
    core: Core,
    _servers: Vec<TestSshServer>,
    web: Uuid,
    db: Uuid,
    behind: Uuid,
}

async fn lab() -> Lab {
    let core = core().await;
    let password = new_password();
    let ubuntu = server(&password, HostFixture::ubuntu(), "web01").await;
    let rhel = server(&password, HostFixture::rhel(), "db01").await;
    trust(&core, &ubuntu).await;
    trust(&core, &rhel).await;
    let secret = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "lab login",
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    vault_password_given(&core).await;
    let customer = core
        .sessions
        .create_folder(&core.ctx(), "Customer", None)
        .await
        .unwrap();
    let mut web = input(
        &format!("web01 token={SECRET}"),
        "127.0.0.1",
        ubuntu.port(),
        Some(secret),
    );
    web.folder_id = Some(customer.id);
    web.tags = vec![
        "web".into(),
        format!("password={SECRET}"),
        format!("token\u{200B}={SECRET}"),
    ];
    web.environment = Environment::Prod;
    let web = core.sessions.create(&core.ctx(), web).await.unwrap().id;
    let mut db = input("db01", "127.0.0.1", rhel.port(), Some(secret));
    db.tags = vec!["db".into()];
    let db = core.sessions.create(&core.ctx(), db).await.unwrap().id;
    // Behind the db host as a jump host; never reached in these tests.
    let mut behind = input("app01", "app01.test", 22, None);
    behind.jump_session_id = Some(db);
    behind.username = Some("bob".into());
    let behind = core.sessions.create(&core.ctx(), behind).await.unwrap().id;
    let mut rdp = input("desk01", "desk01.example.com", 3389, None);
    rdp.kind = remotely_core::sessions::SessionKind::Rdp(Default::default());
    core.sessions.create(&core.ctx(), rdp).await.unwrap();
    Lab {
        core,
        _servers: vec![ubuntu, rhel],
        web,
        db,
        behind,
    }
}

#[tokio::test]
async fn the_inventory_goes_to_excel_with_every_text_as_text() {
    let lab = lab().await;
    let core = &lab.core;
    let ctx = core.ctx();
    // A check with runs in the last day.
    let check = core
        .checks
        .create(CheckInput {
            name: "web ping".into(),
            target: ProbeTarget::Session { session_id: lab.web },
            spec: CheckSpec::Tcp { port: 22 },
            interval_secs: 60,
            timeout_secs: 5,
            failures_before_down: 2,
            paused: true,
        })
        .await
        .unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
    for (n, result) in [RunResult::Up, RunResult::Up, RunResult::Up, RunResult::Down]
        .into_iter()
        .enumerate()
    {
        let at = now - 3_600_000 + i64::try_from(n).unwrap() * 60_000;
        let run = CheckResult {
            at,
            result,
            took_ms: Some(3),
            detail: "port 22 open".into(),
            cert_days: None,
        };
        core.store.insert_check_result(&ctx, check.id, &run).await.unwrap();
    }

    let temp = Temp::new();
    let path = temp.join("inventory.xlsx");
    let request = InventoryRequest {
        options: InventoryOptions {
            read_again: true,
            updates: true,
            packages: true,
        },
        utc_offset_minutes: 480,
    };
    let report = core
        .reports
        .export_inventory(&ctx, &path, request, "Remotely test", &ReadControl::default())
        .await
        .unwrap();
    assert_eq!(report.vms, 2);
    assert_eq!(report.hosts, 4, "every session, of every kind");
    assert_eq!(report.checks, 1);
    let read = report.read.as_ref().unwrap();
    assert_eq!(read.asked, 3, "the SSH sessions");
    assert_eq!(
        read.read, 2,
        "the two test servers; app01.test is behind a jump host nobody can reach"
    );
    assert_eq!(read.problems.len(), 1, "{:?}", read.problems);
    assert!(report.packages.unwrap() >= 9, "Ubuntu's 4 and RHEL's 5 packages");
    assert!(!temp.join("inventory.xlsx.part").exists());

    let files = members(&path);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    for sheet in 1..=5 {
        assert!(
            names.contains(&format!("xl/worksheets/sheet{sheet}.xml").as_str()),
            "{names:?}"
        );
    }
    let book = text_of(&files, "xl/workbook.xml");
    for title in ["VMs", "Hosts", "Networks", "Checks", "Packages"] {
        assert!(book.contains(&format!("name=\"{title}\"")), "{book}");
    }
    // No formula anywhere: a VM named like one is a string.
    for (name, data) in &files {
        let text = String::from_utf8_lossy(data);
        assert!(!text.contains("<f>") && !text.contains("<f "), "a formula in {name}");
        assert!(!text.contains(SECRET), "the secret in {name}");
    }
    let strings = text_of(&files, "xl/sharedStrings.xml");
    assert!(strings.contains("=HYPERLINK("), "{strings}");
    for expected in [
        "Ubuntu 24.04.1 LTS",
        "6.8.0-45-generic",
        "Red Hat Enterprise Linux",
        "openssh-server",
        "kernel-core",
        "00:0c:29:ab:cd:ef",
        "web ping",
        "tcp 22",
        "Read now",
        "token=[redacted]",
        "Customer",
    ] {
        assert!(strings.contains(expected), "{expected} in {strings}");
    }
    // Times as the window reads them, never RFC 3339's raw text.
    assert!(
        !regex::Regex::new(r"\d{4}-\d\d-\d\dT\d\d:").unwrap().is_match(&strings),
        "{strings}"
    );

    // Audited once, as an export, without a tier.
    let audit = core.store.recent_audit(&ctx, 10).await.unwrap();
    let entry = audit.iter().find(|e| e.event == "data_exported").unwrap();
    assert_eq!(entry.action, "Exported the inventory to Excel");
    assert_eq!(entry.tier, None);
    assert!(
        entry.detail.as_deref().unwrap().contains("2 of 3 hosts read again"),
        "{:?}",
        entry.detail
    );
}

#[tokio::test]
async fn without_reading_again_the_stored_facts_are_used_and_nobody_logs_in() {
    let lab = lab().await;
    let core = &lab.core;
    let ctx = core.ctx();
    // A refresh stores db01's facts; web01 has none.
    core.host_details.refresh_session(&ctx, lab.db).await.unwrap();
    core.host_details.release(lab.db).await;
    let temp = Temp::new();
    let path = temp.join("stored.xlsx");
    let report = core
        .reports
        .export_inventory(
            &ctx,
            &path,
            InventoryRequest::default(),
            "Remotely test",
            &ReadControl::default(),
        )
        .await
        .unwrap();
    assert!(report.read.is_none());
    assert_eq!(report.packages, None);
    let files = members(&path);
    let strings = text_of(&files, "xl/sharedStrings.xml");
    assert!(strings.contains("Red Hat Enterprise Linux"), "db01's stored facts");
    assert!(strings.contains("Stored facts"));
    assert!(!text_of(&files, "xl/workbook.xml").contains("Packages"));
}

#[tokio::test]
async fn reading_again_says_how_far_it_got_and_a_cancel_writes_nothing() {
    let lab = lab().await;
    let core = &lab.core;
    let ctx = core.ctx();
    let temp = Temp::new();
    let request = InventoryRequest {
        options: InventoryOptions {
            read_again: true,
            ..InventoryOptions::default()
        },
        utc_offset_minutes: 0,
    };

    // Each SSH host done is heard of, up to all of them.
    let heard = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let into = std::sync::Arc::clone(&heard);
    let control = ReadControl::default().with_progress(move |p| into.lock().unwrap().push((p.done, p.total)));
    let path = temp.join("followed.xlsx");
    core.reports
        .export_inventory(&ctx, &path, request, "x", &control)
        .await
        .unwrap();
    let heard = heard.lock().unwrap().clone();
    assert_eq!(heard.first(), Some(&(0, 3)), "web01, db01 and app01: {heard:?}");
    assert_eq!(heard.last(), Some(&(3, 3)), "{heard:?}");

    // Cancelled while the hosts are read: no file, nothing audited.
    let cancel = tokio_util::sync::CancellationToken::new();
    let stopper = cancel.clone();
    let control = ReadControl::new(cancel).with_progress(move |p| {
        if p.done == 0 {
            stopper.cancel();
        }
    });
    let path = temp.join("cancelled.xlsx");
    let before = core.store.recent_audit(&ctx, 50).await.unwrap().len();
    let err = core
        .reports
        .export_inventory(&ctx, &path, request, "x", &control)
        .await
        .unwrap_err();
    assert!(matches!(err, remotely_core::CoreError::Cancelled), "{err}");
    assert!(!path.exists());
    assert!(!temp.join("cancelled.xlsx.part").exists(), "no part file left either");
    let after = core.store.recent_audit(&ctx, 50).await.unwrap().len();
    assert_eq!(before, after, "nothing exported, nothing audited");

    // The pack too.
    let (from_ms, to_ms) = day_range();
    let pack = HandoverRequest {
        from_ms,
        to_ms,
        inventory: request.options,
        ..HandoverRequest::default()
    };
    let control = ReadControl::new(tokio_util::sync::CancellationToken::new());
    control.cancel.cancel();
    let path = temp.join("cancelled.zip");
    assert!(core
        .reports
        .export_handover(&ctx, &path, &pack, "x", &control)
        .await
        .is_err());
    assert!(!path.exists());
}

#[tokio::test]
async fn ansible_inventories_in_yaml_and_ini_carry_no_secret() {
    let lab = lab().await;
    let core = &lab.core;
    let ctx = core.ctx();
    let all = AnsibleRequest {
        picks: TargetPicks::default(),
        format: AnsibleFormat::Yaml,
        group_by: GroupBy {
            folder: true,
            tag: true,
            environment: true,
            workspace: true,
        },
    };
    let preview = core.reports.ansible_preview(&ctx, &all).await.unwrap();
    assert_eq!(preview.hosts, 3, "the SSH sessions: {}", preview.text);
    assert!(
        preview.notes.iter().any(|n| n.contains("1 session of other kinds")),
        "{:?}",
        preview.notes
    );
    let yaml = &preview.text;
    assert!(
        yaml.starts_with("# Ansible inventory from Remotely: workspace \""),
        "{yaml}"
    );
    assert!(
        yaml.contains("    \"db01\":\n      ansible_host: \"127.0.0.1\"\n"),
        "{yaml}"
    );
    assert!(yaml.contains("      ansible_user: \"alice\"\n"));
    assert!(
        yaml.contains("    \"app01\":\n      ansible_host: \"app01.test\"\n      ansible_port: 22\n      ansible_user: \"bob\"\n      ansible_ssh_common_args: \"-o ProxyJump=alice@127.0.0.1:"),
        "{yaml}"
    );
    for group in [
        "\"folder_customer\":",
        "\"tag_web\":",
        "\"tag_db\":",
        "\"env_prod\":",
        "\"env_lab\":",
        "\"workspace_default\":",
    ] {
        assert!(yaml.contains(group), "{group} in {yaml}");
    }
    for word in [SECRET, "pw-", VAULT_PASSWORD] {
        assert!(!yaml.contains(word), "{word} in {yaml}");
    }

    let temp = Temp::new();
    let yml = temp.join("hosts.yml");
    let done = core.reports.export_ansible(&ctx, &yml, &all).await.unwrap();
    assert_eq!(done.hosts, 3);
    assert_eq!(std::fs::read_to_string(&yml).unwrap(), *yaml);

    // INI, for two picked sessions only.
    let picked = AnsibleRequest {
        picks: TargetPicks {
            session_ids: vec![lab.web, lab.behind],
            ..TargetPicks::default()
        },
        format: AnsibleFormat::Ini,
        group_by: GroupBy::default(),
    };
    let ini_path = temp.join("hosts.ini");
    let done = core.reports.export_ansible(&ctx, &ini_path, &picked).await.unwrap();
    assert_eq!(done.hosts, 2);
    let ini = std::fs::read_to_string(&ini_path).unwrap();
    assert!(
        ini.contains("web01_token_redacted ansible_host=\"127.0.0.1\" ansible_port="),
        "{ini}"
    );
    assert!(ini.contains("app01 ansible_host=\"app01.test\" ansible_port=22 ansible_user=\"bob\" ansible_ssh_common_args=\"-o ProxyJump=alice@127.0.0.1:"), "{ini}");
    assert!(ini.contains("\n[folder_customer]\nweb01_token_redacted\n"), "{ini}");
    assert!(ini.contains("\n[env_prod]\nweb01_token_redacted\n"), "{ini}");
    assert!(!ini.contains("[db01"), "db01 wasn't picked, only reached through");
    for word in [SECRET, "pw-", VAULT_PASSWORD] {
        assert!(!ini.contains(word), "{word} in {ini}");
    }
    let audit = core.store.recent_audit(&ctx, 10).await.unwrap();
    assert_eq!(audit.iter().filter(|e| e.event == "data_exported").count(), 2);

    // Nothing to write: no file.
    let none = AnsibleRequest {
        picks: TargetPicks {
            vm_paths: vec![vmx("evil")],
            ..TargetPicks::default()
        },
        ..AnsibleRequest::default()
    };
    let empty = temp.join("empty.yml");
    assert!(core.reports.export_ansible(&ctx, &empty, &none).await.is_err());
    assert!(!empty.exists());
}

/// A High job with a change ID (two VMs suspended), and a Low one whose output holds the secret.
async fn jobs(lab: &Lab) {
    let core = &lab.core;
    let ctx = core.ctx();
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::NeedsApproval { request } = core
        .bus
        .submit(
            &ctx,
            Command::VmPower {
                targets: vec![vm("web"), vm("evil")],
                op: PowerOp::Suspend,
            },
        )
        .await
        .unwrap()
    else {
        panic!("two VMs suspended ask first");
    };
    let mut answers = ApprovalAnswers {
        confirmed: true,
        change_id: Some("CHG0012345".into()),
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => answers.typed_target_count = Some(*expected),
            ApprovalStep::Reason => answers.reason = Some("planned maintenance".into()),
            ApprovalStep::VaultReauth => answers.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            ApprovalStep::SafetySnapshot { .. } => answers.safety_snapshot = Some(false),
            _ => {}
        }
    }
    let job = core.bus.approve(request.id, answers).await.unwrap();
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);

    let outcome = core
        .bus
        .submit(
            &ctx,
            Command::RemoteExec {
                targets: vec![TargetRef::Session { session_id: lab.db }],
                script: format!("echo password={SECRET}; uname -srm"),
                sudo: false,
                sudo_password_id: None,
                trust_new_host_keys: false,
                timeout_secs: Some(30),
                rollout: Default::default(),
            },
        )
        .await
        .unwrap();
    let job = match outcome {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core
            .bus
            .approve(
                request.id,
                ApprovalAnswers {
                    confirmed: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
    };
    let status = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let remotely_core::jobs::JobEvent::Finished { job_id, status, .. } = events.recv().await.unwrap() {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(status, JobStatus::Succeeded);
}

fn day_range() -> (i64, i64) {
    let now = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
    (now - 86_400_000, now + 86_400_000)
}

#[tokio::test]
async fn the_handover_pack_is_one_safe_page_beside_the_inventory() {
    let lab = lab().await;
    let core = &lab.core;
    let ctx = core.ctx();
    jobs(&lab).await;
    core.notes
        .save(
            &ctx,
            &NoteTarget::session(lab.web),
            NoteInput {
                body: format!(
                    "# Web tier\n\nRestart nginx after a deploy. db password: {SECRET}\n\n\
                     **Password:** {SECRET}\n\n**Token**: {SECRET}\n\n`api_key`: {SECRET}\n\nSecret:\n- {SECRET}\n\n\
                     See [the runbook](https://example.com/runbooks/web).\n\n<script>alert(1)</script>"
                ),
                handover: true,
            },
        )
        .await
        .unwrap();
    let (from_ms, to_ms) = day_range();
    let request = HandoverRequest {
        from_ms,
        to_ms,
        utc_offset_minutes: 0,
        prepared_by: "Alice <alice@example.com>".into(),
        include_outputs: true,
        inventory: InventoryOptions {
            read_again: true,
            updates: false,
            packages: true,
        },
    };
    let preview = core.reports.handover_preview(&ctx, &request).await.unwrap();
    assert_eq!(preview.jobs, 2);
    assert_eq!(preview.notes, 1);

    let temp = Temp::new();
    let path = temp.join("handover.zip");
    let report = core
        .reports
        .export_handover(&ctx, &path, &request, "Remotely test", &ReadControl::default())
        .await
        .unwrap();
    assert_eq!(report.jobs, 2);
    assert!(!temp.join("handover.zip.part").exists());
    let files = members(&path);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "index.html",
            "inventory.xlsx",
            "vms.csv",
            "hosts.csv",
            "networks.csv",
            "checks.csv",
            "packages.csv",
            "activity.csv",
            "uptime.csv"
        ]
    );
    assert_eq!(report.files, names);

    // No secret in any file of the pack, the workbook's own members included.
    for (name, data) in &files {
        let text = if name.ends_with(".xlsx") {
            xlsx_text(data)
        } else {
            String::from_utf8_lossy(data).into_owned()
        };
        for word in [SECRET, VAULT_PASSWORD] {
            assert!(!text.contains(word), "{word} in {name}");
        }
    }

    let html = text_of(&files, "index.html");
    // One page, nothing that runs or reaches out.
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(
        html.contains(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src &#39;none&#39;; img-src data:;"
        ),
        "{html}"
    );
    assert!(!html.to_lowercase().contains("<script"), "no script element");
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "a note's HTML is text"
    );
    let attributes =
        regex::Regex::new(r#"(?i)\b(?:href|src|action|formaction|xlink:href|srcset|poster|data)\s*=\s*"([^"]*)""#)
            .unwrap();
    for cap in attributes.captures_iter(&html) {
        let value = &cap[1];
        assert!(
            value.starts_with('#') || value.starts_with("data:image/svg+xml;base64,"),
            "an attribute leads somewhere: {value}"
        );
    }
    assert!(
        !regex::Regex::new(r#"=\s*"https?:"#).unwrap().is_match(&html),
        "no address in an attribute"
    );
    assert!(!html.contains("url("), "no style that fetches");
    assert!(
        html.contains("(https://example.com/runbooks/web)"),
        "a note's link is its address as text"
    );
    // The cover.
    assert!(html.contains("<h1>Handover: Default</h1>"), "{html}");
    assert!(
        html.contains("<dt>Prepared by</dt><dd>Alice &lt;alice@example.com&gt;</dd>"),
        "{html}"
    );
    // What was done: the approval, its change ID and the outputs, grouped per job.
    assert!(html.contains("change ID CHG0012345"), "{html}");
    assert!(html.contains("planned maintenance"));
    assert!(html.contains("Approval asked") && html.contains("Approved") && html.contains("Finished"));
    assert!(
        html.contains("Linux 5.14.0-427.13.1.el9_4.x86_64 x86_64"),
        "db01's output"
    );
    assert!(html.contains("password=[redacted]"));
    // The diagram, as an image of plain SVG.
    let start = html.find("data:image/svg+xml;base64,").expect("the diagram") + "data:image/svg+xml;base64,".len();
    let end = start + html[start..].find('"').unwrap();
    use base64::Engine;
    let svg = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&html[start..end])
            .unwrap(),
    )
    .unwrap();
    assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
    assert!(svg.contains(">web<") && svg.contains("NAT (VMnet8)"), "{svg}");
    assert!(!svg.contains("<script") && !svg.contains("href") && !svg.contains(SECRET));
    // The note, without its secret.
    assert!(html.contains("Restart nginx after a deploy."));

    // A10 in the CSVs.
    let vms = text_of(&files, "vms.csv");
    assert!(vms.starts_with('\u{FEFF}'));
    assert!(
        vms.contains("\"'=HYPERLINK(\"\"http://example.com\"\",\"\"x\"\")\""),
        "{vms}"
    );
    let activity = text_of(&files, "activity.csv");
    assert!(activity.contains("CHG0012345"), "{activity}");

    let audit = core.store.recent_audit(&ctx, 10).await.unwrap();
    let entry = audit.iter().find(|e| e.event == "data_exported").unwrap();
    assert_eq!(entry.action, "Saved a handover pack");
    assert!(
        entry.detail.as_deref().unwrap().contains("2 jobs"),
        "{:?}",
        entry.detail
    );
    assert!(entry.detail.as_deref().unwrap().contains("with outputs"));
}

#[tokio::test]
async fn outputs_stay_out_unless_chosen() {
    let lab = lab().await;
    let core = &lab.core;
    jobs(&lab).await;
    let (from_ms, to_ms) = day_range();
    let request = HandoverRequest {
        from_ms,
        to_ms,
        prepared_by: "Alice".into(),
        ..HandoverRequest::default()
    };
    let temp = Temp::new();
    let path = temp.join("no-outputs.zip");
    core.reports
        .export_handover(&core.ctx(), &path, &request, "Remotely test", &ReadControl::default())
        .await
        .unwrap();
    let html = text_of(&members(&path), "index.html");
    assert!(html.contains("Outputs are left out"));
    assert!(!html.contains("Linux 5.14.0-427.13.1.el9_4.x86_64 x86_64"), "no output");
    assert!(!html.contains("<pre>"));

    // A range that runs backwards, or over a year, is refused before anything is written.
    let backwards = HandoverRequest {
        from_ms: to_ms,
        to_ms: from_ms,
        ..request.clone()
    };
    let refused = temp.join("refused.zip");
    assert!(core
        .reports
        .export_handover(&core.ctx(), &refused, &backwards, "x", &ReadControl::default())
        .await
        .is_err());
    assert!(!refused.exists());
}

#[tokio::test]
async fn no_export_goes_into_a_git_working_tree() {
    let core = core().await;
    let ctx = core.ctx();
    let temp = Temp::new();
    std::fs::create_dir_all(temp.join(".git")).unwrap();
    let inventory = temp.join("inventory.xlsx");
    let err = core
        .reports
        .export_inventory(
            &ctx,
            &inventory,
            InventoryRequest::default(),
            "x",
            &ReadControl::default(),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("inside a Git repository"), "{err}");
    let ansible = temp.join("hosts.yml");
    assert!(core
        .reports
        .export_ansible(&ctx, &ansible, &AnsibleRequest::default())
        .await
        .unwrap_err()
        .to_string()
        .contains("inside a Git repository"));
    let (from_ms, to_ms) = day_range();
    let pack = temp.join("pack.zip");
    let request = HandoverRequest {
        from_ms,
        to_ms,
        ..HandoverRequest::default()
    };
    assert!(core
        .reports
        .export_handover(&ctx, &pack, &request, "x", &ReadControl::default())
        .await
        .unwrap_err()
        .to_string()
        .contains("inside a Git repository"));
    for path in [inventory, ansible, pack] {
        assert!(!path.exists());
    }
    assert!(core
        .store
        .recent_audit(&ctx, 10)
        .await
        .unwrap()
        .iter()
        .all(|e| e.event != "data_exported"));
}

#[tokio::test]
async fn the_read_only_lock_allows_exports_and_each_holds_one_workspace() {
    let lab = lab().await;
    let core = &lab.core;
    let home = core.ctx();
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let temp = Temp::new();
    let path = temp.join("locked.xlsx");
    let report = core
        .reports
        .export_inventory(&home, &path, InventoryRequest::default(), "x", &ReadControl::default())
        .await
        .unwrap();
    assert!(path.exists());
    // Rule 8: of this PC's networks, only the one a VM of this workspace is on, with only its forward to that VM.
    let book = xlsx_text(&std::fs::read(&path).unwrap());
    assert!(book.contains("vmnet8"), "web is on it");
    assert!(book.contains("2210"), "the forward to web");
    assert!(
        !book.contains("203.0.113.99") && !book.contains("2299"),
        "the other forward is left out"
    );
    assert!(!book.contains("vmnet3"), "no VM of this workspace is on vmnet3");
    assert_eq!(report.networks, 1);
    assert!(
        report.notes.iter().any(|n| n
            == "Networks: 1 network no VM of this workspace is on, and 1 port forward to VMs outside it, left out."),
        "{:?}",
        report.notes
    );
    core.presentation
        .set(Presentation {
            enabled: false,
            read_only: false,
        })
        .await
        .unwrap();

    // Another workspace's export holds none of this one's sessions, VMs or notes.
    let other = core
        .workspaces
        .create(WorkspaceInput {
            name: "Globex".into(),
            color: None,
        })
        .await
        .unwrap();
    let ctx = Context {
        workspace_id: other.id,
        user_id: home.user_id,
    };
    let overview = core.reports.overview(&ctx).await.unwrap();
    assert_eq!((overview.vms, overview.sessions), (0, 0));
    assert_eq!(overview.workspace, "Globex");
    let preview = core
        .reports
        .ansible_preview(&ctx, &AnsibleRequest::default())
        .await
        .unwrap();
    assert_eq!(preview.hosts, 0);
    assert!(!preview.text.contains("db01"));
    let pack = temp.join("globex.zip");
    let (from_ms, to_ms) = day_range();
    let request = HandoverRequest {
        from_ms,
        to_ms,
        ..HandoverRequest::default()
    };
    core.reports
        .export_handover(&ctx, &pack, &request, "x", &ReadControl::default())
        .await
        .unwrap();
    let files = members(&pack);
    let html = text_of(&files, "index.html");
    assert!(html.contains("Handover: Globex"));
    assert!(
        !html.contains("db01") && !html.contains(">web<"),
        "nothing of the home workspace"
    );
    // No VM of Globex is on any network: none of this PC's networks or forwards go in.
    let networks = text_of(&files, "networks.csv");
    assert_eq!(networks.lines().count(), 1, "the header alone: {networks}");
    assert!(!html.contains("vmnet8") && !html.contains("2210"), "{html}");
    let book = xlsx_text(
        files
            .iter()
            .find(|(n, _)| n == "inventory.xlsx")
            .map(|(_, b)| b)
            .unwrap(),
    );
    assert!(
        !book.contains("vmnet") && !book.contains("192.0.2.10"),
        "nothing of the home workspace's networks"
    );
    // Audited in the workspace it holds.
    assert!(core
        .store
        .recent_audit(&ctx, 10)
        .await
        .unwrap()
        .iter()
        .any(|e| e.event == "data_exported"));
    let _ = lab.web;
}
