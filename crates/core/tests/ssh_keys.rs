//! SS-09 SSH key manager, end to end: keys generated into the app's own vault (fake DPAPI, fast key
//! derivation), their public halves, attaching them to sessions, and pushing a public key through the
//! command bus to SSH servers on 127.0.0.1 (`fakes::ssh_server`), whose toy shell keeps a small file
//! system. Keys and passwords are made at run time; no real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::AgentSource;
use remotely_core::bulk::GroupOptions;
use remotely_core::command_bus::{ApprovalAnswers, Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::{self, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::{ExecTuning, JobEvent, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::ssh_keys::{GenerateKey, KeyType, SshKey};
use remotely_core::store::AuditEntry;
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::Core;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(30);
const AUTHORIZED_KEYS: &str = "/home/alice/.ssh/authorized_keys";

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

async fn core() -> Core {
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

async fn generate(core: &Core, label: &str, key_type: KeyType) -> SshKey {
    core.keys
        .generate(
            &core.ctx,
            GenerateKey {
                label: label.into(),
                key_type,
                comment: String::new(),
            },
        )
        .await
        .unwrap()
}

fn input(name: &str, port: u16, auth: SessionAuth, environment: Environment) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: "127.0.0.1".into(),
        port,
        username: Some("alice".into()),
        auth,
        jump_session_id: None,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

/// A session on `server` that logs in as alice with a password saved in the vault, its host key trusted.
async fn host(core: &Core, server: &TestSshServer, name: &str, password: &str, environment: Environment) -> Uuid {
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
    let pw = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Password,
            &format!("{name} login"),
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    let auth = SessionAuth::Password { password_id: Some(pw) };
    core.sessions
        .create(&core.ctx, input(name, server.port(), auth, environment))
        .await
        .unwrap()
        .id
}

fn push(public_key: &str, sessions: &[Uuid]) -> Command {
    Command::PushSshKey {
        targets: sessions
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect(),
        public_key: public_key.into(),
        trust_new_host_keys: false,
        timeout_secs: Some(20),
    }
}

/// Submits and approves. Returns the job id and the tier it was given.
async fn run(core: &Core, command: Command) -> (Uuid, Tier) {
    match core.bus.submit(&core.ctx, command).await.unwrap() {
        SubmitOutcome::Queued { job_id, tier, .. } => (job_id, tier),
        SubmitOutcome::NeedsApproval { request } => {
            let mut answers = ApprovalAnswers {
                confirmed: true,
                ..Default::default()
            };
            for step in &request.steps {
                match step {
                    ApprovalStep::TypeTargetCount { expected } => answers.typed_target_count = Some(*expected),
                    ApprovalStep::Reason => answers.reason = Some("CHG-1234".into()),
                    ApprovalStep::VaultReauth => answers.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
                    _ => {}
                }
            }
            let tier = request.tier;
            (core.bus.approve(request.id, answers).await.unwrap(), tier)
        }
    }
}

async fn finished(rx: &mut Receiver<JobEvent>, job: Uuid) -> JobStatus {
    tokio::time::timeout(WAIT, async {
        loop {
            if let JobEvent::Finished { job_id, status, .. } = rx.recv().await.unwrap() {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .expect("job finished in time")
}

async fn stdout(core: &Core, job: Uuid, session: Uuid) -> String {
    core.bulk
        .host_output(&core.ctx, job, &session.to_string())
        .await
        .unwrap()
        .stdout
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 500).await.unwrap()
}

// ---- Generating keys -------------------------------------------------------------------------------

#[tokio::test]
async fn an_ed25519_key_is_generated_into_the_vault_with_its_public_half() {
    let core = core().await;
    let key = generate(&core, "laptop key", KeyType::default()).await;
    assert!(key.generated);
    let public = key.public.clone().unwrap();
    assert_eq!(public.algorithm, "ssh-ed25519");
    assert_eq!(public.comment, "laptop key", "the label is the default comment");
    assert!(public.line.starts_with("ssh-ed25519 AAAA"));

    // The private half is an ordinary private key in the vault, and it matches the public half.
    let meta = core.vault.list(&core.ctx).await.unwrap();
    let item = meta.iter().find(|m| m.id == key.id).unwrap();
    assert_eq!(item.kind, SecretKind::PrivateKey);
    let private = core.vault.vault().get(&core.ctx, key.id).await.unwrap();
    let decoded = russh::keys::decode_secret_key(private.expose(), None).unwrap();
    assert_eq!(
        decoded
            .public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string(),
        public.fingerprint
    );

    // Locked, the public half is still shown.
    core.vault.lock(&core.ctx).await.unwrap();
    let listed = core.keys.list(&core.ctx).await.unwrap();
    assert_eq!(listed, vec![key.clone()]);

    // Audited with the type and fingerprint, never the private key.
    let entries = audit(&core).await;
    let generated = entries
        .iter()
        .find(|e| e.action == "Generated the SSH key 'laptop key'")
        .unwrap();
    assert_eq!(generated.event, "vault_changed");
    assert_eq!(
        generated.detail.as_deref(),
        Some(format!("Ed25519, {}", public.fingerprint).as_str())
    );
    assert!(!entries
        .iter()
        .any(|e| format!("{e:?}").contains("PRIVATE KEY") || format!("{e:?}").contains(private.expose())));
}

#[tokio::test]
async fn an_rsa_4096_key_can_be_chosen() {
    let core = core().await;
    let key = core
        .keys
        .generate(
            &core.ctx,
            GenerateKey {
                label: "old hosts".into(),
                key_type: KeyType::Rsa,
                comment: "alice@laptop".into(),
            },
        )
        .await
        .unwrap();
    let public = key.public.unwrap();
    assert_eq!(public.algorithm, "ssh-rsa");
    assert_eq!(public.bits, Some(4096));
    assert_eq!(public.comment, "alice@laptop");
}

#[tokio::test]
async fn generating_needs_an_unlocked_vault_and_a_free_label() {
    let core = core().await;
    generate(&core, "laptop key", KeyType::Ed25519).await;
    let taken = core
        .keys
        .generate(
            &core.ctx,
            GenerateKey {
                label: "LAPTOP KEY".into(),
                key_type: KeyType::Ed25519,
                comment: String::new(),
            },
        )
        .await
        .unwrap_err();
    assert!(taken.to_string().contains("already a secret labelled"), "{taken}");
    let bad_comment = core
        .keys
        .generate(
            &core.ctx,
            GenerateKey {
                label: "other".into(),
                key_type: KeyType::Ed25519,
                comment: "two\nlines".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(bad_comment.code(), "invalid_input");
    core.vault.lock(&core.ctx).await.unwrap();
    let locked = core
        .keys
        .generate(
            &core.ctx,
            GenerateKey {
                label: "other".into(),
                key_type: KeyType::Ed25519,
                comment: String::new(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(locked.code(), "vault_locked");
    assert_eq!(core.keys.list(&core.ctx).await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_public_half_of_a_pasted_key_is_read_once_and_dropped_when_the_key_is_replaced() {
    let core = core().await;
    let first = ssh_server::generate_key();
    let id = core
        .vault
        .add(
            &core.ctx,
            SecretKind::PrivateKey,
            "pasted",
            ssh_server::private_key_text(&first, None),
        )
        .await
        .unwrap()
        .id;
    let listed = core.keys.get(&core.ctx, id).await.unwrap();
    assert!(!listed.generated);
    assert_eq!(listed.public, None, "not read yet");

    let read = core.keys.read_public_key(&core.ctx, id).await.unwrap();
    assert_eq!(read.public.unwrap().fingerprint, ssh_server::fingerprint(&first));

    let second = ssh_server::generate_key();
    core.vault
        .replace(&core.ctx, id, ssh_server::private_key_text(&second, None))
        .await
        .unwrap();
    assert_eq!(core.keys.get(&core.ctx, id).await.unwrap().public, None);
    let again = core.keys.read_public_key(&core.ctx, id).await.unwrap();
    assert_eq!(again.public.unwrap().fingerprint, ssh_server::fingerprint(&second));

    // Deleting the vault item deletes its public half with it.
    core.vault.delete(&core.ctx, id).await.unwrap();
    assert!(core.keys.list(&core.ctx).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_key_with_a_passphrase_is_read_with_the_passphrase_a_session_saves() {
    let core = core().await;
    let key = ssh_server::generate_key();
    let id = core
        .vault
        .add(
            &core.ctx,
            SecretKind::PrivateKey,
            "locked key",
            ssh_server::private_key_text(&key, Some("open sesame")),
        )
        .await
        .unwrap()
        .id;
    let err = core.keys.read_public_key(&core.ctx, id).await.unwrap_err();
    assert!(err.to_string().contains("has a passphrase"), "{err}");
    assert!(!err.to_string().contains("open sesame"));

    let passphrase = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Passphrase,
            "locked key passphrase",
            SecretString::new("open sesame"),
        )
        .await
        .unwrap()
        .id;
    let auth = SessionAuth::Key {
        key_id: Some(id),
        passphrase_id: Some(passphrase),
    };
    core.sessions
        .create(&core.ctx, input("web01", 22, auth, Environment::Lab))
        .await
        .unwrap();
    let read = core.keys.read_public_key(&core.ctx, id).await.unwrap();
    assert_eq!(read.public.unwrap().fingerprint, ssh_server::fingerprint(&key));
}

// ---- Attaching a key to sessions ---------------------------------------------------------------------

#[tokio::test]
async fn attaching_a_key_makes_sessions_log_in_with_it_and_is_audited_per_session() {
    let core = core().await;
    let key = generate(&core, "laptop key", KeyType::Ed25519).await;
    let mut ids = Vec::new();
    for name in ["web01", "web02"] {
        let auth = SessionAuth::Password { password_id: None };
        let s = core
            .sessions
            .create(&core.ctx, input(name, 22, auth, Environment::Lab))
            .await
            .unwrap();
        ids.push(s.id);
    }
    let changed = core.keys.attach(&core.ctx, key.id, &ids, &core.sessions).await.unwrap();
    assert_eq!(changed.len(), 2);
    for id in &ids {
        let s = core.sessions.get(&core.ctx, *id).await.unwrap();
        assert_eq!(
            s.auth,
            SessionAuth::Key {
                key_id: Some(key.id),
                passphrase_id: None
            }
        );
    }
    assert_eq!(core.keys.get(&core.ctx, key.id).await.unwrap().used_by, 2);
    let entries = audit(&core).await;
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.action.starts_with("Changed session") && e.detail.as_deref().unwrap_or("").contains("login:"))
            .count(),
        2
    );
    // Attaching again changes nothing.
    assert!(core
        .keys
        .attach(&core.ctx, key.id, &ids, &core.sessions)
        .await
        .unwrap()
        .is_empty());
    let not_a_key = SecretId(Uuid::new_v4());
    assert!(core
        .keys
        .attach(&core.ctx, not_a_key, &ids, &core.sessions)
        .await
        .is_err());
}

// ---- Pushing a public key -----------------------------------------------------------------------------

#[tokio::test]
async fn a_pushed_key_lands_once_with_the_right_permissions_and_then_logs_in() {
    let core = core().await;
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let session = host(&core, &server, "web01", &password, Environment::Lab).await;
    let key = generate(&core, "laptop key", KeyType::Ed25519).await;
    let line = key.public.clone().unwrap().line;
    let mut events = core.jobs.subscribe();

    // Through the bus: classified as a key push, Medium, with one confirm.
    let preview = core.bus.preview(&core.ctx, &push(&line, &[session])).await.unwrap();
    assert_eq!(preview.action, ActionKind::SshKeyPush);
    assert_eq!(preview.tier, Tier::Medium);
    let (job, tier) = run(&core, push(&line, &[session])).await;
    assert_eq!(tier, Tier::Medium);
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(
        server.file(AUTHORIZED_KEYS).as_deref(),
        Some(format!("{line}\n").as_str())
    );
    assert_eq!(server.mode("/home/alice/.ssh"), Some(0o700));
    assert_eq!(server.mode(AUTHORIZED_KEYS), Some(0o600));
    assert!(stdout(&core, job, session).await.contains("Added the key"));

    // Again: nothing is added.
    let (again, _) = run(&core, push(&line, &[session])).await;
    assert_eq!(finished(&mut events, again).await, JobStatus::Succeeded);
    assert_eq!(
        server
            .file(AUTHORIZED_KEYS)
            .unwrap()
            .matches(key.public.as_ref().unwrap().blob())
            .count(),
        1
    );
    assert!(stdout(&core, again, session).await.contains("already in"));

    // The job shows like a bulk run's, with the script each host ran.
    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert!(results.run.unwrap().script.contains("authorized_keys"));

    // Audited with the key's comment and fingerprint.
    let summary = format!(
        "Add the SSH key 'laptop key' ({}) to 1 host",
        key.public.as_ref().unwrap().fingerprint
    );
    let entries = audit(&core).await;
    for event in ["approval_requested", "approval_granted", "job_started", "job_finished"] {
        assert!(
            entries.iter().any(|e| e.event == event && e.action == summary),
            "{event}: {entries:#?}"
        );
    }

    // The server now takes the key: the session logs in with it, without its password.
    core.keys
        .attach(&core.ctx, key.id, &[session], &core.sessions)
        .await
        .unwrap();
    let (check, _) = run(
        &core,
        Command::RemoteExec {
            targets: vec![TargetRef::Session { session_id: session }],
            script: "whoami".into(),
            sudo: false,
            sudo_password_id: None,
            trust_new_host_keys: false,
            timeout_secs: Some(20),
        },
    )
    .await;
    assert_eq!(finished(&mut events, check).await, JobStatus::Succeeded);
    assert_eq!(stdout(&core, check, session).await, "alice\n");
    assert!(
        server.log().iter().any(|l| l == "publickey alice ok"),
        "{:?}",
        server.log()
    );
}

#[tokio::test]
async fn a_push_keeps_other_keys_and_fixes_a_missing_line_break_and_loose_permissions() {
    let core = core().await;
    let password = new_password();
    let other = ssh_server::generate_key().public_key().to_openssh().unwrap();
    // An existing file whose last line has no line break, writable by the group.
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_file(AUTHORIZED_KEYS, &other)
        .with_mode("/home/alice/.ssh", 0o775)
        .with_mode(AUTHORIZED_KEYS, 0o664);
    let session = host(&core, &server, "web01", &password, Environment::Lab).await;
    let key = generate(&core, "laptop key", KeyType::Ed25519).await;
    let line = key.public.unwrap().line;
    let mut events = core.jobs.subscribe();

    let (job, _) = run(&core, push(&line, &[session])).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(server.file(AUTHORIZED_KEYS).unwrap(), format!("{other}\n{line}\n"));
    assert_eq!(server.mode("/home/alice/.ssh"), Some(0o700));
    assert_eq!(server.mode(AUTHORIZED_KEYS), Some(0o600));
}

#[tokio::test]
async fn a_key_already_there_with_another_comment_is_not_added_again() {
    let core = core().await;
    let password = new_password();
    let key = generate(&core, "laptop key", KeyType::Ed25519).await;
    let public = key.public.unwrap();
    let existing = format!("from=\"192.0.2.0/24\" ssh-ed25519 {} old comment\n", public.blob());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_file(AUTHORIZED_KEYS, &existing);
    let session = host(&core, &server, "web01", &password, Environment::Lab).await;
    let mut events = core.jobs.subscribe();

    let (job, _) = run(&core, push(&public.line, &[session])).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(server.file(AUTHORIZED_KEYS).unwrap(), existing);
}

#[tokio::test]
async fn pushing_to_many_hosts_reports_each_and_a_prod_host_raises_the_tier() {
    let core = core().await;
    let password = new_password();
    let a = TestSshServer::start().await.with_password("alice", &password);
    let b = TestSshServer::start().await.with_password("alice", &password);
    let lab = host(&core, &a, "web01", &password, Environment::Lab).await;
    let prod = host(&core, &b, "db01", &password, Environment::Prod).await;
    let key = generate(&core, "laptop key", KeyType::Ed25519).await;
    let line = key.public.unwrap().line;

    let outcome = core.bus.submit(&core.ctx, push(&line, &[lab, prod])).await.unwrap();
    let SubmitOutcome::NeedsApproval { request } = outcome else {
        panic!("a Prod host needs approval");
    };
    assert_eq!(request.tier, Tier::High);
    assert!(request.steps.contains(&ApprovalStep::TypeTargetCount { expected: 2 }));
    assert!(!request
        .steps
        .iter()
        .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    let exec = request.exec.as_ref().expect("the dialog shows the script");
    assert!(exec
        .script
        .contains(&line.split_whitespace().nth(1).unwrap().to_owned()));
    assert!(!exec.sudo);
    core.bus.cancel_approval(request.id).await.unwrap();

    let mut events = core.jobs.subscribe();
    let (job, _) = run(&core, push(&line, &[lab, prod])).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);
    for server in [&a, &b] {
        assert!(server.file(AUTHORIZED_KEYS).unwrap().contains(&line));
    }
}

#[tokio::test]
async fn a_host_that_refuses_the_write_fails_with_its_message() {
    let core = core().await;
    let password = new_password();
    // ~/.ssh is a file, so the folder can't be made.
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_file("/home/alice/.ssh", "not a folder");
    let session = host(&core, &server, "web01", &password, Environment::Lab).await;
    let key = generate(&core, "laptop key", KeyType::Ed25519).await;
    let mut events = core.jobs.subscribe();

    let (job, _) = run(&core, push(&key.public.unwrap().line, &[session])).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Failed);
    let out = core
        .bulk
        .host_output(&core.ctx, job, &session.to_string())
        .await
        .unwrap();
    assert_eq!(out.exit_code, Some(1));
    assert!(out.stderr.contains("File exists"), "{out:?}");
}

#[tokio::test]
async fn a_push_with_something_that_is_not_a_public_key_is_refused_before_anything_runs() {
    let core = core().await;
    let session = core
        .sessions
        .create(&core.ctx, input("web01", 22, SessionAuth::Agent, Environment::Lab))
        .await
        .unwrap()
        .id;
    let private_kind = "OPENSSH PRIVATE KEY";
    for bad in [
        "ssh-ed25519 AAAA'; rm -rf ~; echo '".to_owned(),
        format!("-----BEGIN {private_kind}-----"),
        String::new(),
    ] {
        let err = core.bus.submit(&core.ctx, push(&bad, &[session])).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{bad}");
    }
    assert!(core.jobs.open_jobs() == 0);
}
