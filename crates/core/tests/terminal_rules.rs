//! QL-17 highlight and alert rules, end to end: the rules' list, edits (audited by name and scope, never the
//! pattern; refused by presentation mode's read-only lock), and alerts from a terminal on the test SSH server
//! (`fakes::ssh_server` on 127.0.0.1, passwords made at run time): one alert per burst of matching lines, then a
//! cooldown, never one per line. No real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::Setup;
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::FakeVmware;
use remotely_core::known_hosts::HostKey;
use remotely_core::presentation::Presentation;
use remotely_core::sessions::SessionColor;
use remotely_core::sessions::SessionInput;
use remotely_core::store::AuditEntry;
use remotely_core::terminal::alerts::{AlertTiming, TerminalAlert};
use remotely_core::terminal::rules::{RuleScope, RuleStyle, TerminalRule, TerminalRuleInput, MAX_RULES};
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::{Core, CoreError};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);

async fn core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        ..TerminalTuning::default()
    });
    core
}

fn rule(name: &str, pattern: &str, scope: RuleScope) -> TerminalRuleInput {
    TerminalRuleInput {
        name: name.into(),
        pattern: pattern.into(),
        case_sensitive: false,
        color: Some(SessionColor::Violet),
        style: RuleStyle::Text,
        alert: false,
        scope,
        enabled: true,
    }
}

/// A saved session, from the editor's JSON (the fields it leaves out take their defaults).
async fn session(core: &Core, name: &str, port: u16, environment: &str, password: Option<&str>) -> Uuid {
    let password_id = match password {
        Some(password) => Some(
            core.vault
                .add(&core.ctx(), SecretKind::Password, name, SecretString::new(password))
                .await
                .unwrap()
                .id,
        ),
        None => None,
    };
    let input: SessionInput = serde_json::from_value(serde_json::json!({
        "name": name,
        "host": "127.0.0.1",
        "port": port,
        "username": "alice",
        "auth": { "method": "password", "passwordId": password_id },
        "environment": environment,
    }))
    .unwrap();
    core.sessions.create(&core.ctx(), input).await.unwrap().id
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx(), 300).await.unwrap()
}

async fn rule_entries(core: &Core) -> Vec<AuditEntry> {
    audit(core)
        .await
        .into_iter()
        .filter(|e| e.event == "terminal_rule_changed")
        .collect()
}

async fn names(core: &Core) -> Vec<String> {
    core.terminal_rules
        .list(&core.ctx())
        .await
        .unwrap()
        .iter()
        .map(|r| r.name.clone())
        .collect()
}

fn invalid(result: remotely_core::Result<TerminalRule>, needle: &str) {
    match result {
        Err(CoreError::InvalidInput(message)) => assert!(message.contains(needle), "{message}"),
        other => panic!("expected an invalid input about {needle:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn rules_are_listed_built_ins_first_and_edits_are_audited_without_the_pattern() {
    let core = core().await;
    let web = session(&core, "web01", 22, "prod", None).await;

    // Five built-ins, highlights on, alerts off.
    let fresh = core.terminal_rules.list(&core.ctx()).await.unwrap();
    assert_eq!(
        fresh.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        [
            "builtin:error",
            "builtin:fatal",
            "builtin:panic",
            "builtin:traceback",
            "builtin:warning"
        ]
    );
    assert!(fresh.iter().all(|r| r.builtin && r.enabled && !r.alert));

    let oom = core
        .terminal_rules
        .create(
            &core.ctx(),
            rule("OOM killer", r"Out of memory: Killed process \d+", RuleScope::Global),
        )
        .await
        .unwrap();
    assert!(!oom.builtin && oom.problem.is_none());
    let mut prod = rule(
        "Prod 5xx",
        r"\bHTTP/1\.1\x22? 5\d\d",
        RuleScope::Environment {
            environment: Environment::Prod,
        },
    );
    prod.style = RuleStyle::Fill;
    let prod = core.terminal_rules.create(&core.ctx(), prod).await.unwrap();
    let only_web = core
        .terminal_rules
        .create(
            &core.ctx(),
            rule(
                "web01 deploys",
                "deploy finished",
                RuleScope::Session { session_id: web },
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        names(&core).await[5..],
        ["OOM killer", "Prod 5xx", "web01 deploys"].map(String::from)
    );

    // Changed: renamed, alert on, now alert-only; it keeps its place.
    let mut change = rule("OOM", r"Out of memory: Killed process \d+", RuleScope::Global);
    change.alert = true;
    change.color = None;
    let oom_id: Uuid = oom.id.parse().unwrap();
    let changed = core.terminal_rules.update(&core.ctx(), oom_id, change).await.unwrap();
    assert!(changed.alert && changed.color.is_none());
    // Reordered, then one deleted.
    let ids: Vec<Uuid> = [&only_web, &prod, &changed]
        .iter()
        .map(|r| r.id.parse().unwrap())
        .collect();
    core.terminal_rules.reorder(&core.ctx(), &ids).await.unwrap();
    assert_eq!(
        names(&core).await[5..],
        ["web01 deploys", "Prod 5xx", "OOM"].map(String::from)
    );
    core.terminal_rules
        .delete(&core.ctx(), prod.id.parse().unwrap())
        .await
        .unwrap();
    // A built-in turned off, another's alert on.
    let error = core
        .terminal_rules
        .set_builtin(&core.ctx(), "error", false, false)
        .await
        .unwrap();
    assert!(!error.enabled);
    let fatal = core
        .terminal_rules
        .set_builtin(&core.ctx(), "fatal", true, true)
        .await
        .unwrap();
    assert!(fatal.enabled && fatal.alert);
    let listed = core.terminal_rules.list(&core.ctx()).await.unwrap();
    assert!(!listed[0].enabled && listed[1].alert);
    assert_eq!(listed.len(), 7);

    let entries = rule_entries(&core).await;
    let actions: Vec<&str> = entries.iter().rev().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "Added the terminal rule 'OOM killer'",
            "Added the terminal rule 'Prod 5xx'",
            "Added the terminal rule 'web01 deploys'",
            "Changed the terminal rule 'OOM killer'",
            "Reordered the terminal rules",
            "Deleted the terminal rule 'Prod 5xx'",
            "Changed the built-in terminal rule 'Error'",
            "Changed the built-in terminal rule 'Fatal'",
        ]
    );
    let detail = |action: &str| {
        entries
            .iter()
            .find(|e| e.action == action)
            .and_then(|e| e.detail.clone())
            .unwrap_or_default()
    };
    assert_eq!(
        detail("Added the terminal rule 'OOM killer'"),
        "for every terminal; violet text; alerts off"
    );
    assert_eq!(
        detail("Added the terminal rule 'Prod 5xx'"),
        "for Prod sessions; violet fill; alerts off"
    );
    assert_eq!(
        detail("Added the terminal rule 'web01 deploys'"),
        "for the session 'web01'; violet text; alerts off"
    );
    assert_eq!(
        detail("Changed the terminal rule 'OOM killer'"),
        "renamed to 'OOM', now no highlight, alerts on"
    );
    assert_eq!(detail("Changed the built-in terminal rule 'Fatal'"), "alerts on");
    // The session-scoped rule names its session as the target.
    let scoped = entries
        .iter()
        .find(|e| e.action == "Added the terminal rule 'web01 deploys'")
        .unwrap();
    assert!(
        scoped.targets_json.contains(&web.to_string()),
        "{}",
        scoped.targets_json
    );
    // Never the pattern.
    for entry in &entries {
        let text = format!("{entry:?}");
        assert!(!text.contains("Killed process"), "{text}");
        assert!(!text.contains("HTTP/1"), "{text}");
        assert!(!text.contains("deploy finished"), "{text}");
    }
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);

    // Nothing changed: nothing audited.
    let before = rule_entries(&core).await.len();
    core.terminal_rules
        .set_builtin(&core.ctx(), "fatal", true, true)
        .await
        .unwrap();
    let mut same = rule("OOM", r"Out of memory: Killed process \d+", RuleScope::Global);
    same.alert = true;
    same.color = None;
    core.terminal_rules.update(&core.ctx(), oom_id, same).await.unwrap();
    assert_eq!(rule_entries(&core).await.len(), before);
}

#[tokio::test]
async fn bad_rules_are_refused_with_a_reason() {
    let core = core().await;
    let rules = &core.terminal_rules;
    invalid(
        rules.create(&core.ctx(), rule("  ", "x", RuleScope::Global)).await,
        "name",
    );
    invalid(
        rules.create(&core.ctx(), rule("error", "x", RuleScope::Global)).await,
        "built-in",
    );
    invalid(
        rules.create(&core.ctx(), rule("A", "(?i)x", RuleScope::Global)).await,
        "Match case",
    );
    invalid(
        rules.create(&core.ctx(), rule("A", "(a+)+", RuleScope::Global)).await,
        "very slow",
    );
    invalid(
        rules.create(&core.ctx(), rule("A", "x*", RuleScope::Global)).await,
        "empty text",
    );
    let mut nothing = rule("A", "x", RuleScope::Global);
    nothing.color = None;
    invalid(rules.create(&core.ctx(), nothing).await, "does nothing");
    invalid(
        rules
            .create(
                &core.ctx(),
                rule(
                    "A",
                    "x",
                    RuleScope::Environment {
                        environment: Environment::None,
                    },
                ),
            )
            .await,
        "label",
    );
    invalid(
        rules
            .create(
                &core.ctx(),
                rule(
                    "A",
                    "x",
                    RuleScope::Session {
                        session_id: Uuid::new_v4(),
                    },
                ),
            )
            .await,
        "no longer exists",
    );
    rules
        .create(&core.ctx(), rule("A", "x", RuleScope::Global))
        .await
        .unwrap();
    invalid(
        rules.create(&core.ctx(), rule("a", "y", RuleScope::Global)).await,
        "already",
    );
    // The live check says the same, and changes nothing.
    let check = rules.validate("(a|ab)*c", false);
    assert!(!check.valid && check.message.unwrap().contains("very slow"));
    assert!(rules.validate(r"\berror\b", false).valid);
    // At most MAX_RULES.
    for i in 1..MAX_RULES {
        rules
            .create(&core.ctx(), rule(&format!("rule {i}"), "x", RuleScope::Global))
            .await
            .unwrap();
    }
    invalid(
        rules
            .create(&core.ctx(), rule("one more", "x", RuleScope::Global))
            .await,
        "Delete some",
    );
    // A reorder that doesn't name every rule is refused.
    let some: Vec<Uuid> = rules.list(&core.ctx()).await.unwrap()[5..7]
        .iter()
        .map(|r| r.id.parse().unwrap())
        .collect();
    assert!(matches!(
        rules.reorder(&core.ctx(), &some).await,
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        rules.set_builtin(&core.ctx(), "nope", true, true).await,
        Err(CoreError::UnknownTarget(_))
    ));
}

#[tokio::test]
async fn the_read_only_lock_refuses_every_rule_edit() {
    let core = core().await;
    let kept = core
        .terminal_rules
        .create(&core.ctx(), rule("Kept", "x", RuleScope::Global))
        .await
        .unwrap();
    let id: Uuid = kept.id.parse().unwrap();
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let before = audit(&core).await.len();
    let refused = |result: remotely_core::Result<()>| match result {
        Err(err @ CoreError::ReadOnlyLock { .. }) => {
            assert!(err.to_string().contains("Edit highlight and alert rules"), "{err}");
        }
        other => panic!("expected the read-only lock, got {other:?}"),
    };
    let rules = &core.terminal_rules;
    refused(
        rules
            .create(&core.ctx(), rule("New", "y", RuleScope::Global))
            .await
            .map(drop),
    );
    refused(
        rules
            .update(&core.ctx(), id, rule("Renamed", "x", RuleScope::Global))
            .await
            .map(drop),
    );
    refused(rules.delete(&core.ctx(), id).await);
    refused(rules.reorder(&core.ctx(), &[id]).await.map(drop));
    refused(rules.set_builtin(&core.ctx(), "error", false, true).await.map(drop));
    // Reads and the live check still work; nothing was written or audited.
    assert!(rules.validate("x", false).valid);
    assert_eq!(names(&core).await.len(), 6);
    assert_eq!(audit(&core).await.len(), before);
}

/// A pane under test: its output and events.
struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    unread: Vec<u8>,
    /// Alerts seen while waiting for something else.
    alerts: Vec<TerminalAlert>,
}

impl Pane {
    fn new(handle: TerminalHandle) -> Self {
        Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            unread: Vec::new(),
            alerts: Vec::new(),
        }
    }

    async fn expect_output(&mut self, needle: &str) {
        let found = timeout(WAIT, async {
            loop {
                let text = String::from_utf8_lossy(&self.unread).into_owned();
                if let Some(at) = text.find(needle) {
                    self.unread = text.as_bytes()[at + needle.len()..].to_vec();
                    return;
                }
                let chunk = self.output.recv().await.expect("output ended");
                self.unread.extend_from_slice(&chunk);
            }
        })
        .await;
        found.unwrap_or_else(|_| panic!("no {needle:?} in {:?}", String::from_utf8_lossy(&self.unread)));
    }

    async fn connected(&mut self) {
        timeout(WAIT, async {
            loop {
                match self.events.recv().await.expect("events ended") {
                    TerminalEvent::Status {
                        status: TerminalStatus::Connected,
                    } => return,
                    TerminalEvent::Alert { alert } => self.alerts.push(alert),
                    _ => {}
                }
            }
        })
        .await
        .expect("connected in time");
    }

    /// The alerts that arrive within `within` (output is drained meanwhile, so the pane never waits on it).
    async fn alerts_within(&mut self, within: Duration) -> Vec<TerminalAlert> {
        let mut alerts = std::mem::take(&mut self.alerts);
        let deadline = tokio::time::Instant::now() + within;
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return alerts,
                event = self.events.recv() => match event {
                    Some(TerminalEvent::Alert { alert }) => alerts.push(alert),
                    Some(_) => {}
                    None => return alerts,
                },
                chunk = self.output.recv() => {
                    if let Some(chunk) = chunk {
                        self.unread.extend_from_slice(&chunk);
                    }
                }
            }
        }
    }

    async fn type_text(&self, core: &Core, text: &str) {
        core.terminals.write(self.id, text.as_bytes().to_vec()).await;
    }
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

#[tokio::test]
async fn matching_lines_alert_once_per_burst_then_cool_down() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust(&core, &server).await;
    core.terminals.set_alert_timing(AlertTiming {
        burst: Duration::from_millis(400),
        cooldown: Duration::from_millis(2500),
    });
    let lab = session(&core, "lab box", server.port(), "lab", Some(&password)).await;
    let mut pane = Pane::new(
        core.terminals
            .open(&core.ctx(), lab, PtySize { cols: 80, rows: 24 })
            .await
            .unwrap(),
    );
    pane.connected().await;
    pane.expect_output("$ ").await;

    // Rules made while the pane is open reach it: one that alerts (lines that start with ERROR, so the typed
    // command line doesn't count either way), one for Prod only, and the built-in Fatal with its alert on.
    let mut alerting = rule("Errors", r"^ERROR\b", RuleScope::Global);
    alerting.alert = true;
    core.terminal_rules.create(&core.ctx(), alerting).await.unwrap();
    let mut prod_only = rule(
        "Prod errors",
        "ERROR",
        RuleScope::Environment {
            environment: Environment::Prod,
        },
    );
    prod_only.alert = true;
    core.terminal_rules.create(&core.ctx(), prod_only).await.unwrap();
    core.terminal_rules
        .set_builtin(&core.ctx(), "fatal", true, true)
        .await
        .unwrap();

    // Three matching lines at once, split by colour codes as a program would print them: one alert.
    pane.type_text(&core, "echo ERROR one\recho ERROR two\recho ERROR three\r")
        .await;
    pane.expect_output("ERROR three\r\n$ ").await;
    let alerts = pane.alerts_within(Duration::from_millis(1200)).await;
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    let alert = &alerts[0];
    assert_eq!(
        (alert.rule_name.as_str(), alert.count, alert.suppressed),
        ("Errors", 3, 0)
    );
    assert_eq!(alert.sample, "ERROR one");
    assert_eq!(alert.terminal_id, pane.id);
    assert_eq!(alert.session_id, Some(lab));
    assert!(alert.first_at <= alert.last_at);

    // During the cooldown: counted, no alert.
    pane.type_text(&core, "echo ERROR four\r").await;
    pane.expect_output("ERROR four\r\n$ ").await;
    assert!(pane.alerts_within(Duration::from_millis(700)).await.is_empty());

    // A full-screen program's lines never alert, and neither does the cooldown's end by itself.
    pane.type_text(&core, "top\r").await;
    pane.expect_output("Tasks: 99 total").await;
    pane.type_text(&core, "q").await;
    pane.expect_output("$ ").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // After the cooldown, the next match alerts again, with what the cooldown counted.
    pane.type_text(&core, "echo fatal: disk gone\recho ERROR five\r").await;
    pane.expect_output("ERROR five\r\n$ ").await;
    let mut alerts = pane.alerts_within(Duration::from_millis(1200)).await;
    alerts.sort_by(|a, b| a.rule_name.cmp(&b.rule_name));
    let seen: Vec<(&str, u32, u32)> = alerts
        .iter()
        .map(|a| (a.rule_name.as_str(), a.count, a.suppressed))
        .collect();
    assert_eq!(seen, [("Errors", 1, 1), ("Fatal", 1, 0)]);

    // Turned off: nothing more.
    core.terminal_rules
        .set_builtin(&core.ctx(), "fatal", true, false)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2600)).await;
    pane.type_text(&core, "echo fatal: again\r").await;
    pane.expect_output("again\r\n$ ").await;
    let late = pane.alerts_within(Duration::from_millis(800)).await;
    assert!(late.iter().all(|a| a.rule_name != "Fatal"), "{late:?}");

    // Alerts are notices, not edits: none of them is in the audit log.
    let entries = audit(&core).await;
    assert!(entries.iter().all(|e| !format!("{e:?}").contains("ERROR one")));
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn a_sample_never_shows_the_login_password() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust(&core, &server).await;
    core.terminals.set_alert_timing(AlertTiming {
        burst: Duration::from_millis(200),
        cooldown: Duration::from_secs(60),
    });
    let mut alerting = rule("Errors", "error", RuleScope::Global);
    alerting.alert = true;
    core.terminal_rules.create(&core.ctx(), alerting).await.unwrap();
    let lab = session(&core, "lab box", server.port(), "lab", Some(&password)).await;
    let mut pane = Pane::new(
        core.terminals
            .open(&core.ctx(), lab, PtySize { cols: 80, rows: 24 })
            .await
            .unwrap(),
    );
    pane.connected().await;
    pane.expect_output("$ ").await;
    pane.type_text(&core, &format!("echo error: {password} refused\r"))
        .await;
    pane.expect_output("refused\r\n$ ").await;
    let alerts = pane.alerts_within(Duration::from_millis(800)).await;
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].sample, "error: [redacted] refused");
    core.terminals.close(pane.id).await;
}
