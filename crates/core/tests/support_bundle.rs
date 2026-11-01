//! FD-04 support bundles end to end: the real russh adapter against SSH servers on 127.0.0.1 (their exec shell runs
//! the commands, their SFTP serves the files), the bus, the job runner and the zip in the system temp folder. The caps
//! run against in-memory hosts, so no test writes more than a few MB (the zip compresses what they give). No real
//! host is reached and nothing is written into the repository.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::{temp_folder, Setup};
use remotely_core::adapters::exec_output::OutputCollector;
use remotely_core::adapters::remote::{AgentSource, ExecResult};
use remotely_core::command_bus::{ApprovalAnswers, Command, Rollout, SubmitOutcome};
use remotely_core::domain::{Environment, Target, TargetRef};
use remotely_core::error::Result as CoreResult;
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::fakes::{FakeFiles, FakeRemote, FakeVmware};
use remotely_core::jobs::{ExecTuning, JobEvent, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput, SessionKind};
use remotely_core::support_bundle::collect::collect_host;
use remotely_core::support_bundle::spec::entry_names;
use remotely_core::support_bundle::writer::OpenBundle;
use remotely_core::support_bundle::{
    BundleHost, BundleItem, BundleRequest, BundleSpec, FileRead, HostKind, ItemLimits, PresetId, MAX_BUNDLE_BYTES,
    MAX_FILE_BYTES, MAX_HOST_BYTES,
};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(30);

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

async fn ssh_core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.jobs.set_exec_tuning(ExecTuning {
        connect_timeout: Duration::from_secs(5),
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        ..ExecTuning::default()
    });
    core
}

/// A saved session on `server` logging in as alice with `password` from the vault (a vault item of its own).
async fn session(core: &Core, name: &str, port: u16, password: &str, environment: Environment) -> Uuid {
    let id = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            &format!("{name} login"),
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    core.sessions
        .create(
            &core.ctx(),
            SessionInput {
                name: name.into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port,
                username: Some("alice".into()),
                auth: SessionAuth::Password { password_id: Some(id) },
                jump_session_id: None,
                jump_direct: false,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment,
                color: None,
                tags: vec![],
                vm_id: None,
                kind: SessionKind::Ssh,
            },
        )
        .await
        .unwrap()
        .id
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

/// A host with a few of the System preset's programs, an os-release served over SFTP that holds a secret, and a
/// program that prints the login password (a broken script would).
async fn server(password: &str) -> TestSshServer {
    let kind = "OPENSSH PRIVATE KEY";
    TestSshServer::start()
        .await
        .with_password("alice", password)
        .with_program("uname", "Linux web01 6.8.0-45-generic x86_64 GNU/Linux\n")
        .with_program(
            "df",
            "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 40G 12G 26G 32% /\n",
        )
        .with_program("free", "Mem: 7953 2210 4120\n")
        .with_program("leaky", &format!("connecting with {password}\n"))
        .with_sftp_file("/etc/os-release", b"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n")
        .with_sftp_file(
            "/srv/app/app.conf",
            format!("db_password = hunter2\n-----BEGIN {kind}-----\nAAAAB3NzaC1\n-----END {kind}-----\nport=8080\n")
                .as_bytes(),
        )
}

fn request(sessions: &[Uuid]) -> BundleRequest {
    BundleRequest {
        session_ids: sessions.to_vec(),
        presets: vec![PresetId::System],
        commands: vec!["leaky".into()],
        files: vec!["/srv/app/app.conf".into(), "/srv/app/missing.log".into()],
        timeout_secs: Some(60),
        ..BundleRequest::default()
    }
}

async fn wait_for(core: &Core, job: Uuid) -> JobStatus {
    tokio::time::timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap()
}

/// Every file in the zip, and its manifest.
fn read_zip(path: &Path) -> (BTreeMap<String, Vec<u8>>, Value) {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut files = BTreeMap::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).unwrap();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        let name = entry.name().unwrap().to_string();
        files.insert(name, bytes);
    }
    let manifest = serde_json::from_slice(&files["manifest.json"]).unwrap();
    (files, manifest)
}

fn host<'a>(manifest: &'a Value, name: &str) -> &'a Value {
    manifest["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == name)
        .unwrap()
}

fn item<'a>(host: &'a Value, source: &str) -> &'a Value {
    host["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["source"] == source)
        .unwrap_or_else(|| panic!("no item {source} in {host}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_from_two_hosts_is_one_zip_with_a_folder_each_and_a_manifest() {
    let core = ssh_core().await;
    let (pw1, pw2) = (new_password(), new_password());
    let (one, two) = (server(&pw1).await, server(&pw2).await);
    trust(&core, &one).await;
    trust(&core, &two).await;
    let web01 = session(&core, "web01", one.port(), &pw1, Environment::Lab).await;
    let web02 = session(&core, "web02", two.port(), &pw2, Environment::Lab).await;
    let folder = temp_folder("bundle");
    let output = folder.join(core.bundles.default_file_name(&core.ctx()).await.unwrap());
    assert!(output
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("remotely-bundle-"));

    // Read-only presets and commands: Low, so it runs at once.
    let request = request(&[web01, web02]);
    core.bundles.check(&core.ctx(), &request).await.unwrap();
    let preview = core.bundles.preview(&core.ctx(), &request).await.unwrap();
    assert_eq!(
        preview.tier,
        Tier::Medium,
        "`leaky` isn't on the read-only list: {:?}",
        preview.reasons
    );
    let mut read_only = request.clone();
    read_only.commands.clear();
    let preview = core.bundles.preview(&core.ctx(), &read_only).await.unwrap();
    assert_eq!(preview.tier, Tier::Low, "{:?}", preview.reasons);

    let SubmitOutcome::NeedsApproval { request: asked } =
        core.bundles.submit(&core.ctx(), &request, &output).await.unwrap()
    else {
        panic!("a command that isn't read-only asks for a confirm");
    };
    let exec = asked.exec.as_ref().unwrap();
    assert!(exec.script.contains("uname -a") && exec.script.contains("leaky"));
    let details = asked.bundle.as_ref().unwrap();
    assert_eq!(details.output, output.display().to_string());
    assert!(details.files.contains(&"/etc/os-release".to_owned()));
    let job = core
        .bus
        .approve(
            asked.id,
            ApprovalAnswers {
                confirmed: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(wait_for(&core, job).await, JobStatus::Succeeded);

    assert!(output.is_file());
    assert!(!folder
        .join(format!("{}.part", output.file_name().unwrap().to_string_lossy()))
        .exists());
    assert_eq!(core.bundles.saved_at(&core.ctx(), job).await.unwrap(), output);
    let (files, manifest) = read_zip(&output);
    assert_eq!(manifest["format"], 1);
    assert_eq!(manifest["presets"], serde_json::json!(["System"]));
    assert_eq!(manifest["hosts"].as_array().unwrap().len(), 2);

    for (name, password) in [("web01", &pw1), ("web02", &pw2)] {
        let h = host(&manifest, name);
        assert_eq!(h["folder"], name);
        assert_eq!(h["status"], "succeeded");
        assert!(h["address"].as_str().unwrap().starts_with("alice@127.0.0.1:"));

        let uname = item(h, "uname -a");
        assert_eq!(uname["exitCode"], 0);
        let text = &files[&format!("{name}/commands/uname-a.txt")];
        assert_eq!(text, b"Linux web01 6.8.0-45-generic x86_64 GNU/Linux\n");
        assert_eq!(uname["sha256"], hex::encode(Sha256::digest(text)));
        assert_eq!(uname["bytes"], text.len());

        // A program the host doesn't have: its exit code and what the shell said are kept.
        let ss = item(h, "ss -tulpn");
        assert_eq!(ss["exitCode"], 127);
        let said = String::from_utf8_lossy(&files[ss["file"].as_str().unwrap()]).into_owned();
        assert!(said.contains("--- stderr ---"), "{said}");

        // Over SFTP.
        assert_eq!(
            files[&format!("{name}/files/etc/os-release")],
            b"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n"
        );
        let missing = item(h, "/srv/app/missing.log");
        assert!(missing["file"].is_null());
        assert!(missing["error"].as_str().unwrap().contains("missing.log"), "{missing}");

        // Scrubbed: the login password the host printed, and a password and a private key in a file.
        let leaky = String::from_utf8_lossy(&files[&format!("{name}/commands/leaky.txt")]).into_owned();
        assert_eq!(leaky, "connecting with [redacted]\n");
        assert!(item(h, "leaky")["redacted"].as_u64().unwrap() >= 1);
        let conf = String::from_utf8_lossy(&files[&format!("{name}/files/srv/app/app.conf")]).into_owned();
        assert!(!conf.contains("hunter2") && !conf.contains("AAAAB3NzaC1"), "{conf}");
        assert!(conf.contains("port=8080"));
        assert_eq!(item(h, "/srv/app/app.conf")["redacted"], 2);
        assert!(!String::from_utf8_lossy(&files["manifest.json"]).contains(password.as_str()));
    }
    for (name, bytes) in &files {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(&pw1) && !text.contains(&pw2), "{name}");
    }

    // Audited as a job, and as data exported, naming the file.
    let audit = core.store.recent_audit(&core.ctx(), 200).await.unwrap();
    let of_job = Some(job.to_string());
    let exported = audit
        .iter()
        .find(|e| e.event == "data_exported" && e.job_id == of_job)
        .unwrap();
    assert!(exported
        .detail
        .as_deref()
        .unwrap()
        .contains(&output.display().to_string()));
    let finished = audit
        .iter()
        .find(|e| e.event == "job_finished" && e.job_id == of_job)
        .unwrap();
    assert!(finished.action.starts_with("Collect a support bundle (System"));
    assert!(finished.detail.as_deref().unwrap().contains("saved the support bundle"));
    let _ = std::fs::remove_dir_all(folder);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_fails_is_in_the_manifest_and_the_others_are_saved() {
    let core = ssh_core().await;
    let password = new_password();
    let good = server(&password).await;
    trust(&core, &good).await;
    let web01 = session(&core, "web01", good.port(), &password, Environment::Lab).await;
    // Nothing listens there.
    let dead_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let gone = session(&core, "gone", dead_port, &new_password(), Environment::Lab).await;
    let folder = temp_folder("bundle-partial");
    let output = folder.join("bundle.zip");
    let mut request = request(&[web01, gone]);
    request.commands.clear();
    let SubmitOutcome::Queued { job_id, tier, .. } = core.bundles.submit(&core.ctx(), &request, &output).await.unwrap()
    else {
        panic!("read-only presets run at once");
    };
    assert_eq!(tier, Tier::Low);
    assert_eq!(wait_for(&core, job_id).await, JobStatus::PartiallyFailed);
    let (_, manifest) = read_zip(&output);
    assert_eq!(host(&manifest, "web01")["status"], "succeeded");
    let failed = host(&manifest, "gone");
    assert_eq!(failed["status"], "failed");
    assert!(failed["error"].as_str().is_some_and(|e| !e.is_empty()));
    assert!(failed["items"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(folder);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sudo_runs_the_commands_with_a_vault_password_asked_for_once() {
    let core = ssh_core().await;
    let (login, sudo) = (new_password(), new_password());
    let srv = server(&login).await.with_sudo(SudoMode::Password(sudo.clone()));
    trust(&core, &srv).await;
    let web01 = session(&core, "web01", srv.port(), &login, Environment::Prod).await;
    let sudo_id = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "sudo",
            SecretString::new(sudo.as_str()),
        )
        .await
        .unwrap()
        .id;
    let folder = temp_folder("bundle-sudo");
    let output = folder.join("bundle.zip");
    let request = BundleRequest {
        session_ids: vec![web01],
        commands: vec!["whoami".into()],
        sudo: true,
        sudo_password_id: Some(sudo_id),
        ..BundleRequest::default()
    };
    // Prod: Medium; and the sudo password is new to this host, so the vault password is asked for (AP-06).
    let SubmitOutcome::NeedsApproval { request: asked } =
        core.bundles.submit(&core.ctx(), &request, &output).await.unwrap()
    else {
        panic!("Prod asks");
    };
    assert_eq!(asked.tier, Tier::Medium);
    assert!(asked.steps.contains(&ApprovalStep::VaultReauth), "{:?}", asked.steps);
    assert!(!format!("{asked:?}").contains(&sudo));
    let job = core
        .bus
        .approve(
            asked.id,
            ApprovalAnswers {
                confirmed: true,
                vault_password: Some(SecretString::new(common::VAULT_PASSWORD)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(wait_for(&core, job).await, JobStatus::Succeeded);
    let (files, manifest) = read_zip(&output);
    assert_eq!(files["web01/commands/whoami.txt"], b"root\n");
    assert_eq!(manifest["sudo"], true);
    for bytes in files.values() {
        assert!(!String::from_utf8_lossy(bytes).contains(&sudo));
    }
    let _ = std::fs::remove_dir_all(folder);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_bundle_leaves_no_file() {
    let core = ssh_core().await;
    let password = new_password();
    let slow = server(&password).await.with_exec_delay(Duration::from_secs(5));
    trust(&core, &slow).await;
    let web01 = session(&core, "web01", slow.port(), &password, Environment::Lab).await;
    let folder = temp_folder("bundle-cancel");
    let output = folder.join("bundle.zip");
    let mut events = core.jobs.subscribe();
    let mut request = request(&[web01]);
    request.commands.clear();
    let SubmitOutcome::Queued { job_id, .. } = core.bundles.submit(&core.ctx(), &request, &output).await.unwrap()
    else {
        panic!("Low");
    };
    tokio::time::timeout(WAIT, async {
        loop {
            if let JobEvent::TargetStarted { job_id: id, .. } = events.recv().await.unwrap() {
                if id == job_id {
                    return;
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(core.jobs.cancel(job_id));
    assert_eq!(wait_for(&core, job_id).await, JobStatus::Cancelled);
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(&folder).unwrap().count(), 0, "no .part left");
    assert!(core.bundles.saved_at(&core.ctx(), job_id).await.is_err());
    let _ = std::fs::remove_dir_all(folder);
}

#[tokio::test]
async fn a_bundle_is_never_saved_into_a_git_working_tree_nor_built_by_the_ui() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let repo = temp_folder("bundle-repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let session = core
        .sessions
        .create(&core.ctx(), fake_session("web01.example.com"))
        .await
        .unwrap()
        .id;
    let mut request = BundleRequest {
        session_ids: vec![session],
        presets: vec![PresetId::System],
        ..BundleRequest::default()
    };
    let err = core
        .bundles
        .submit(&core.ctx(), &request, &repo.join("bundle.zip"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("inside a Git repository"), "{err}");

    // Nothing to collect, or no host: refused before the save dialog opens.
    request.presets.clear();
    assert!(core.bundles.check(&core.ctx(), &request).await.is_err());
    assert!(core
        .bundles
        .check(&core.ctx(), &BundleRequest::default())
        .await
        .is_err());

    // The UI can't send the command itself: the zip's place comes from the shell's save dialog.
    let command = Command::SupportBundle {
        targets: vec![TargetRef::Session { session_id: session }],
        spec: Box::new(spec(
            vec![BundleItem::command("uptime")],
            &std::env::temp_dir().join("x.zip"),
        )),
    };
    assert!(command.check_from_ui().is_err());
    let _ = std::fs::remove_dir_all(repo);
}

fn fake_session(host: &str) -> SessionInput {
    SessionInput {
        name: host.split('.').next().unwrap().into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: Some("alice".into()),
        auth: SessionAuth::Password { password_id: None },
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: SessionKind::Ssh,
    }
}

fn spec(items: Vec<BundleItem>, output: &Path) -> BundleSpec {
    BundleSpec {
        presets: Vec::new(),
        items,
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
        rollout: Rollout::default(),
        output: output.display().to_string(),
        workspace: "Lab".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_file_is_cut_and_one_that_isnt_text_is_left_out() {
    let big: Vec<u8> = b"0123456789abcdef\n".repeat((MAX_FILE_BYTES as usize) / 17 + 4096);
    let files = FakeFiles::default()
        .with_dir("/var")
        .with_dir("/var/log")
        .with_file("/var/log/big.log", &big)
        .with_file("/var/log/core.gz", &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x01])
        .with_file("/etc/hosts", b"127.0.0.1 localhost\n");
    let core = Setup::new(FakeVmware::default())
        .with_remote(Arc::new(FakeRemote::default().with_files(files)))
        .build()
        .await;
    let session = core
        .sessions
        .create(&core.ctx(), fake_session("web01.example.com"))
        .await
        .unwrap()
        .id;
    let folder = temp_folder("bundle-caps");
    let output = folder.join("bundle.zip");
    let request = BundleRequest {
        session_ids: vec![session],
        commands: vec!["uptime".into()],
        files: vec![
            "/var/log/big.log".into(),
            "/var/log/core.gz".into(),
            "/etc/hosts".into(),
        ],
        ..BundleRequest::default()
    };
    let SubmitOutcome::Queued { job_id, .. } = core.bundles.submit(&core.ctx(), &request, &output).await.unwrap()
    else {
        panic!("Low");
    };
    assert_eq!(wait_for(&core, job_id).await, JobStatus::Succeeded);
    let (files, manifest) = read_zip(&output);
    let h = host(&manifest, "web01");
    let cut = item(h, "/var/log/big.log");
    assert_eq!(cut["bytes"], MAX_FILE_BYTES);
    assert_eq!(cut["originalBytes"], big.len());
    assert!(cut["cut"].as_str().unwrap().contains("first"), "{cut}");
    assert_eq!(files["web01/files/var/log/big.log"].len() as u64, MAX_FILE_BYTES);
    assert!(big.starts_with(&files["web01/files/var/log/big.log"]));
    let binary = item(h, "/var/log/core.gz");
    assert!(binary["file"].is_null());
    assert!(binary["error"].as_str().unwrap().contains("isn't text"));
    assert!(!files.contains_key("web01/files/var/log/core.gz"));
    assert_eq!(files["web01/files/etc/hosts"], b"127.0.0.1 localhost\n");
    assert_eq!(files["web01/commands/uptime.txt"], b"ok from web01.example.com\n");
    let listed: Vec<&str> = manifest["cut"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(listed.len(), 2, "{listed:?}");
    let _ = std::fs::remove_dir_all(folder);
}

/// A host whose every file is as large as the bundle lets it be, made as it is read.
struct EndlessHost;

#[async_trait]
impl BundleHost for EndlessHost {
    fn kind(&self) -> HostKind {
        HostKind::Linux
    }

    fn address(&self) -> String {
        "alice@web01.example.com:22".into()
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        None
    }

    async fn run(&self, _: &str, max_bytes: usize) -> CoreResult<ExecResult> {
        Ok(ExecResult {
            exit_code: Some(0),
            signal: None,
            output: OutputCollector::collect(b"ok\n", b"", &[], max_bytes),
            duration_ms: 1,
            peer_ip: None,
        })
    }

    async fn read(&self, _: &str, max_bytes: u64) -> CoreResult<FileRead> {
        Ok(FileRead {
            bytes: vec![b'a'; max_bytes as usize],
            size: max_bytes * 2,
            more: true,
        })
    }

    fn secrets(&self) -> &[SecretString] {
        &[]
    }

    fn lost(&self) -> bool {
        false
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_stops_at_its_cap_and_the_rest_is_listed_as_left_out() {
    let folder = temp_folder("bundle-host-cap");
    let output = folder.join("bundle.zip");
    let per_host = (MAX_HOST_BYTES / MAX_FILE_BYTES) as usize;
    let items: Vec<BundleItem> = (0..=per_host)
        .map(|n| BundleItem::file(&format!("/var/log/{n}.log")))
        .chain([BundleItem::command("uptime")])
        .collect();
    let names = entry_names(&items);
    let target = Target {
        target: TargetRef::Session {
            session_id: Uuid::new_v4(),
        },
        name: "web01".into(),
        environment: Environment::Lab,
        protected: false,
    };
    let bundle = Arc::new(
        OpenBundle::create(
            Uuid::new_v4(),
            &spec(items.clone(), &output),
            std::slice::from_ref(&target),
        )
        .unwrap(),
    );
    let report = collect_host(
        &bundle,
        &target.target.key(),
        &EndlessHost,
        &items,
        &names,
        ItemLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.saved, per_host);
    assert_eq!(report.bytes, MAX_HOST_BYTES);
    assert_eq!(report.failed, 2, "the last file and the command");
    assert!(
        report
            .lines
            .last()
            .unwrap()
            .contains("the host's 100.0 MB were reached"),
        "{:?}",
        report.lines
    );
    let saved = tokio::task::spawn_blocking(move || bundle.finish())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(saved.files, per_host);
    assert_eq!(saved.bytes, MAX_HOST_BYTES);
    let _ = std::fs::remove_dir_all(folder);
}

/// A host where the command `hang` and the file `/hang` never answer (a `df -h` on a stale NFS mount), and the rest
/// answer at once.
struct HangingHost;

#[async_trait]
impl BundleHost for HangingHost {
    fn kind(&self) -> HostKind {
        HostKind::Linux
    }

    fn address(&self) -> String {
        "alice@web01.example.com:22".into()
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        None
    }

    async fn run(&self, command: &str, max_bytes: usize) -> CoreResult<ExecResult> {
        if command == "hang" {
            std::future::pending::<()>().await;
        }
        Ok(ExecResult {
            exit_code: Some(0),
            signal: None,
            output: OutputCollector::collect(b"ok\n", b"", &[], max_bytes),
            duration_ms: 1,
            peer_ip: None,
        })
    }

    async fn read(&self, path: &str, _: u64) -> CoreResult<FileRead> {
        if path == "/hang" {
            std::future::pending::<()>().await;
        }
        Ok(FileRead {
            bytes: b"127.0.0.1 localhost\n".to_vec(),
            size: 20,
            more: false,
        })
    }

    fn secrets(&self) -> &[SecretString] {
        &[]
    }

    fn lost(&self) -> bool {
        false
    }
}

fn web01() -> Target {
    Target {
        target: TargetRef::Session {
            session_id: Uuid::new_v4(),
        },
        name: "web01".into(),
        environment: Environment::Lab,
        protected: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_item_that_hangs_times_out_and_the_host_goes_on() {
    let folder = temp_folder("bundle-hang");
    let output = folder.join("bundle.zip");
    let items = vec![
        BundleItem::command("hang"),
        BundleItem::command("uptime"),
        BundleItem::file("/hang"),
        BundleItem::file("/etc/hosts"),
    ];
    let names = entry_names(&items);
    let target = web01();
    let bundle = Arc::new(
        OpenBundle::create(
            Uuid::new_v4(),
            &spec(items.clone(), &output),
            std::slice::from_ref(&target),
        )
        .unwrap(),
    );
    let limits = ItemLimits {
        command: Duration::from_millis(150),
        file: Duration::from_millis(150),
    };
    let report = collect_host(&bundle, &target.target.key(), &HangingHost, &items, &names, limits)
        .await
        .unwrap();
    assert_eq!((report.saved, report.failed), (2, 2), "{:?}", report.lines);
    assert!(
        report.lines[0].starts_with("hang: timed out after 150 ms"),
        "{:?}",
        report.lines
    );
    assert!(report.lines[2].starts_with("/hang: timed out"), "{:?}", report.lines);
    // The timed-out items held nothing back: only the two small files count against the cap.
    assert_eq!(bundle.reserve(MAX_BUNDLE_BYTES), MAX_BUNDLE_BYTES - report.bytes);
    let saved = tokio::task::spawn_blocking(move || bundle.finish())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(saved.files, 2);
    let (files, manifest) = read_zip(&output);
    let h = host(&manifest, "web01");
    assert!(item(h, "hang")["error"].as_str().unwrap().contains("timed out"));
    assert!(item(h, "hang")["file"].is_null());
    assert_eq!(files["web01/commands/uptime.txt"], b"ok\n");
    assert_eq!(manifest["caps"]["commandSecs"], 60);
    let _ = std::fs::remove_dir_all(folder);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_dropped_part_way_gives_its_bytes_back_and_leaves_no_file_without_its_record() {
    let folder = temp_folder("bundle-dropped");
    let output = folder.join("bundle.zip");
    let items = vec![BundleItem::command("uptime"), BundleItem::file("/hang")];
    let names = entry_names(&items);
    let target = web01();
    let bundle = Arc::new(
        OpenBundle::create(
            Uuid::new_v4(),
            &spec(items.clone(), &output),
            std::slice::from_ref(&target),
        )
        .unwrap(),
    );
    // The host's own time limit (or a cancel) drops its work while it waits on `/hang`.
    let dropped = tokio::time::timeout(
        Duration::from_millis(300),
        collect_host(
            &bundle,
            &target.target.key(),
            &HangingHost,
            &items,
            &names,
            ItemLimits::default(),
        ),
    )
    .await;
    assert!(dropped.is_err(), "it was still waiting");
    // Only the finished item's 3 bytes stay held; the 10 MB the dropped one held went back.
    assert_eq!(bundle.reserve(MAX_BUNDLE_BYTES), MAX_BUNDLE_BYTES - 3);
    let saved = tokio::task::spawn_blocking(move || bundle.finish())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(saved.files, 1);
    let (files, manifest) = read_zip(&output);
    let records = host(&manifest, "web01")["items"].as_array().unwrap().len();
    // Every file in the zip but the manifest has its record.
    assert_eq!(files.len() - 1, records);
    let _ = std::fs::remove_dir_all(folder);
}

#[test]
fn the_bundle_gives_out_no_more_than_its_cap() {
    let folder = temp_folder("bundle-cap");
    let output: PathBuf = folder.join("bundle.zip");
    let bundle = OpenBundle::create(Uuid::new_v4(), &spec(vec![BundleItem::command("uptime")], &output), &[]).unwrap();
    let cap = MAX_BUNDLE_BYTES;
    assert_eq!(bundle.reserve(cap - 10), cap - 10);
    assert_eq!(bundle.reserve(100), 10, "only what is left");
    assert_eq!(bundle.reserve(100), 0);
    bundle.release(50);
    assert_eq!(bundle.reserve(100), 50);
    // Nothing collected: nothing is saved, and no half file is left.
    assert!(bundle.finish().unwrap().is_none());
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(&folder).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(folder);
}
