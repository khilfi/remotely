//! Command bus: the one way in for changes.
//!
//! The UI (and later the CLI, plugins and AI helper, FD-12/FD-13) submit a [`Command`] here. The bus
//! resolves the targets, asks the [`PolicyEngine`] for a tier, collects approval answers when the tier
//! needs them (AP-02, AP-03, AP-06), writes the audit log (AP-05) and hands the work to the
//! [`JobRunner`]. Nothing else can enqueue a job, so approvals and audit cannot be skipped.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{now_rfc3339, Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::jobs::{JobRunner, JobSpec};
use crate::locks;
use crate::policy::{ActionKind, ApprovalStep, Decision, PolicyEngine, PolicyRules, Tier};
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretString, Vault};

/// A state-changing request. Reads (inventory, metrics) do not go through the bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Command {
    /// VM-02 bulk power actions; VM-03 soft-then-hard stop is two commands.
    VmPower { targets: Vec<TargetRef>, op: PowerOp },
    /// VM-04 bulk snapshot take, revert and delete.
    VmSnapshot { targets: Vec<TargetRef>, op: SnapshotOp },
    /// AP-04 mark VMs "do not touch" (`protected: true`) or unlock them. Other actions skip
    /// protected targets; this one is the way to change that, so it never skips them.
    VmProtect { targets: Vec<TargetRef>, protected: bool },
    /// BX-02 run a command or script on many hosts; BX-07 with sudo from the vault.
    RemoteExec {
        targets: Vec<TargetRef>,
        script: String,
        #[serde(default)]
        sudo: bool,
    },
    /// FD-14 install a checked, signed update. Runs once no other job is open.
    AppUpdate { version: String },
}

/// The one target of commands that act on the app itself.
const APP_TARGET: &[TargetRef] = &[TargetRef::App];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PowerOp {
    Start {
        /// Open a console window (vmrun `gui`) instead of running headless (`nogui`).
        #[serde(default)]
        gui: bool,
    },
    Stop {
        mode: StopMode,
    },
    Reset {
        mode: StopMode,
    },
    Suspend,
    Pause,
    Unpause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StopMode {
    /// Ask the guest OS to shut down (needs VMware Tools).
    Soft,
    /// Power off immediately. Critical tier (VM-03).
    Hard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SnapshotOp {
    Take { name: String },
    Revert { name: String },
    Delete { name: String },
}

impl Command {
    pub fn targets(&self) -> &[TargetRef] {
        match self {
            Command::VmPower { targets, .. }
            | Command::VmSnapshot { targets, .. }
            | Command::VmProtect { targets, .. }
            | Command::RemoteExec { targets, .. } => targets,
            Command::AppUpdate { .. } => APP_TARGET,
        }
    }

    /// Short human summary for dialogs, job lists and the audit log.
    pub fn summary(&self, target_count: usize) -> String {
        let noun = |kind: &str| {
            if target_count == 1 {
                format!("1 {kind}")
            } else {
                format!("{target_count} {kind}s")
            }
        };
        match self {
            Command::VmPower { op, .. } => {
                let verb = match op {
                    PowerOp::Start { .. } => "Start",
                    PowerOp::Stop { mode: StopMode::Soft } => "Shut down",
                    PowerOp::Stop { mode: StopMode::Hard } => "Power off (hard)",
                    PowerOp::Reset { mode: StopMode::Soft } => "Restart",
                    PowerOp::Reset { mode: StopMode::Hard } => "Reset (hard)",
                    PowerOp::Suspend => "Suspend",
                    PowerOp::Pause => "Pause",
                    PowerOp::Unpause => "Unpause",
                };
                format!("{verb} {}", noun("VM"))
            }
            Command::VmSnapshot { op, .. } => match op {
                SnapshotOp::Take { name } => format!("Take snapshot '{name}' on {}", noun("VM")),
                SnapshotOp::Revert { name } => format!("Revert {} to '{name}'", noun("VM")),
                SnapshotOp::Delete { name } => format!("Delete snapshot '{name}' on {}", noun("VM")),
            },
            Command::VmProtect { protected: true, .. } => format!("Protect {}", noun("VM")),
            Command::VmProtect { protected: false, .. } => format!("Unprotect {}", noun("VM")),
            Command::RemoteExec { script, sudo, .. } => {
                let first_line = script.lines().next().unwrap_or_default();
                let sudo = if *sudo { "sudo " } else { "" };
                format!("Run `{sudo}{first_line}` on {}", noun("host"))
            }
            Command::AppUpdate { version } => format!("Install update {version}"),
        }
    }
}

/// Looks targets up in the inventory so the policy engine knows their labels.
#[async_trait]
pub trait TargetDirectory: Send + Sync {
    async fn resolve(&self, ctx: &Context, target: &TargetRef) -> Result<Target>;
}

/// What happened to a submitted command.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SubmitOutcome {
    /// Low tier: logged and queued straight away. `skipped` are protected targets left alone (AP-04).
    Queued {
        job_id: Uuid,
        tier: Tier,
        summary: String,
        skipped: Vec<Target>,
    },
    /// Medium and above: collect the answers for `steps`, then call [`CommandBus::approve`].
    NeedsApproval { request: ApprovalRequest },
}

/// Everything the UI needs to draw the approval dialog and impact preview (AP-02).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub action: ActionKind,
    pub tier: Tier,
    pub summary: String,
    pub steps: Vec<ApprovalStep>,
    pub targets: Vec<Target>,
    pub skipped: Vec<Target>,
    pub reasons: Vec<String>,
}

/// The user's answers to the approval steps (AP-03, AP-06).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalAnswers {
    #[serde(default)]
    pub confirmed: bool,
    pub typed_target_count: Option<usize>,
    pub reason: Option<String>,
    /// Overrides the safety snapshot default (VM-05). `None` keeps the default.
    pub safety_snapshot: Option<bool>,
    /// Only for Critical. Checked against the vault, never stored or logged.
    pub vault_password: Option<SecretString>,
}

/// What gets journaled with the job and written to the audit log. No secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    pub request_id: Uuid,
    pub tier: Tier,
    pub typed_target_count: Option<usize>,
    pub reason: Option<String>,
    pub safety_snapshot: bool,
    pub vault_reauth: bool,
    pub approved_at: String,
}

struct Pending {
    ctx: Context,
    command: Command,
    decision: Decision,
    request: ApprovalRequest,
}

pub struct CommandBus {
    policy: RwLock<PolicyEngine>,
    directory: Arc<dyn TargetDirectory>,
    jobs: Arc<JobRunner>,
    store: Store,
    vault: Arc<dyn Vault>,
    pending: Mutex<HashMap<Uuid, Pending>>,
}

impl CommandBus {
    pub fn new(
        policy: PolicyEngine,
        directory: Arc<dyn TargetDirectory>,
        jobs: Arc<JobRunner>,
        store: Store,
        vault: Arc<dyn Vault>,
    ) -> Self {
        Self {
            policy: RwLock::new(policy),
            directory,
            jobs,
            store,
            vault,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn rules(&self) -> PolicyRules {
        locks::read(&self.policy).rules().clone()
    }

    /// AP-01: tier rules are editable. Invalid rules are rejected and the old ones stay.
    pub async fn set_rules(&self, ctx: &Context, rules: PolicyRules) -> Result<()> {
        let engine = PolicyEngine::new(rules.clone())?;
        self.store
            .put_setting(ctx, crate::store::POLICY_RULES_KEY, &rules)
            .await?;
        *locks::write(&self.policy) = engine;
        Ok(())
    }

    pub async fn submit(&self, ctx: &Context, command: Command) -> Result<SubmitOutcome> {
        if command.targets().is_empty() {
            return Err(CoreError::NoTargets);
        }
        let mut targets = Vec::with_capacity(command.targets().len());
        for target in command.targets() {
            targets.push(self.directory.resolve(ctx, target).await?);
        }

        let decision = locks::read(&self.policy).evaluate(&command, &targets);
        if decision.targets.is_empty() {
            return Err(CoreError::AllTargetsProtected);
        }
        let summary = command.summary(decision.targets.len());

        if decision.steps.is_empty() {
            // Low tier: no approval, logged only.
            let tier = decision.tier;
            let skipped = decision.skipped.clone();
            let job_id = self
                .jobs
                .enqueue(JobSpec {
                    ctx: *ctx,
                    command,
                    decision,
                    approval: None,
                    safety_snapshot: false,
                })
                .await?;
            return Ok(SubmitOutcome::Queued {
                job_id,
                tier,
                summary,
                skipped,
            });
        }

        let request = ApprovalRequest {
            id: Uuid::new_v4(),
            action: decision.action,
            tier: decision.tier,
            summary: summary.clone(),
            steps: decision.steps.clone(),
            targets: decision.targets.clone(),
            skipped: decision.skipped.clone(),
            reasons: decision.reasons.clone(),
        };
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "approval_requested",
                    action: &summary,
                    tier: Some(decision.tier),
                    job_id: None,
                    targets: &decision.targets,
                    approval: None,
                    result: None,
                    detail: Some(&decision.reasons.join("; ")),
                },
            )
            .await?;
        locks::lock(&self.pending).insert(
            request.id,
            Pending {
                ctx: *ctx,
                command,
                decision,
                request: request.clone(),
            },
        );
        Ok(SubmitOutcome::NeedsApproval { request })
    }

    /// Checks the answers against every required step. On a wrong answer the request stays pending
    /// so the user can correct it; on success the job is queued.
    pub async fn approve(&self, request_id: Uuid, answers: ApprovalAnswers) -> Result<Uuid> {
        let pending = locks::lock(&self.pending)
            .remove(&request_id)
            .ok_or(CoreError::UnknownApproval(request_id))?;

        match self.check_answers(&pending, &answers).await {
            Ok(record) => {
                let summary = pending.request.summary.clone();
                self.store
                    .append_audit(
                        &pending.ctx,
                        NewAuditEntry {
                            event: "approval_granted",
                            action: &summary,
                            tier: Some(pending.decision.tier),
                            job_id: None,
                            targets: &pending.decision.targets,
                            approval: Some(&record),
                            result: None,
                            detail: None,
                        },
                    )
                    .await?;
                let safety_snapshot = record.safety_snapshot;
                self.jobs
                    .enqueue(JobSpec {
                        ctx: pending.ctx,
                        command: pending.command,
                        decision: pending.decision,
                        approval: Some(record),
                        safety_snapshot,
                    })
                    .await
            }
            Err(err) => {
                locks::lock(&self.pending).insert(request_id, pending);
                Err(err)
            }
        }
    }

    /// The user closed the dialog. Logged so the audit trail shows abandoned high-impact actions.
    pub async fn cancel_approval(&self, request_id: Uuid) -> Result<()> {
        let pending = locks::lock(&self.pending).remove(&request_id);
        if let Some(p) = pending {
            self.store
                .append_audit(
                    &p.ctx,
                    NewAuditEntry {
                        event: "approval_cancelled",
                        action: &p.request.summary,
                        tier: Some(p.decision.tier),
                        job_id: None,
                        targets: &p.decision.targets,
                        approval: None,
                        result: None,
                        detail: None,
                    },
                )
                .await?;
        }
        Ok(())
    }

    async fn check_answers(&self, pending: &Pending, answers: &ApprovalAnswers) -> Result<ApprovalRecord> {
        let mut safety_snapshot = false;
        let mut vault_reauth = false;
        for step in &pending.decision.steps {
            match step {
                ApprovalStep::Confirm | ApprovalStep::ImpactPreview => {
                    if !answers.confirmed {
                        return Err(CoreError::ApprovalRejected("the action was not confirmed".into()));
                    }
                }
                ApprovalStep::TypeTargetCount { expected } => {
                    if answers.typed_target_count != Some(*expected) {
                        return Err(CoreError::ApprovalRejected(format!(
                            "type the number of targets ({expected}) to confirm"
                        )));
                    }
                }
                ApprovalStep::Reason => {
                    if answers.reason.as_deref().map(str::trim).unwrap_or_default().is_empty() {
                        return Err(CoreError::ApprovalRejected(
                            "a reason or ticket number is required".into(),
                        ));
                    }
                }
                ApprovalStep::SafetySnapshot { default_on } => {
                    safety_snapshot = answers.safety_snapshot.unwrap_or(*default_on);
                }
                // Enforced by the job runner: the job waits this long and can be cancelled meanwhile.
                ApprovalStep::Countdown { .. } => {}
                ApprovalStep::VaultReauth => {
                    let password = answers
                        .vault_password
                        .as_ref()
                        .ok_or_else(|| CoreError::ApprovalRejected("the vault password is required".into()))?;
                    if !self.vault.verify_password(password).await? {
                        return Err(CoreError::ApprovalRejected("wrong vault password".into()));
                    }
                    vault_reauth = true;
                }
            }
        }
        Ok(ApprovalRecord {
            request_id: pending.request.id,
            tier: pending.decision.tier,
            typed_target_count: answers.typed_target_count,
            reason: answers.reason.as_ref().map(|r| r.trim().to_owned()),
            safety_snapshot,
            vault_reauth,
            approved_at: now_rfc3339(),
        })
    }
}
