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

use crate::capacity::CapacityChecker;
use crate::domain::{now_rfc3339, Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::impact::{ImpactPreviewer, TargetImpact};
use crate::jobs::{JobRunner, JobSpec, TargetStatus};
use crate::locks;
use crate::policy::{ActionKind, ApprovalStep, DangerousMatch, Decision, PolicyEngine, PolicyRules, Tier};
use crate::snapshots::{is_safety_name, SAFETY_PREFIX};
use crate::ssh_keys;
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretId, SecretKind, SecretString, Vault};

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
        /// BX-07: the vault password sudo gets. `None`: each session's own login password.
        #[serde(default)]
        sudo_password_id: Option<SecretId>,
        /// SS-05 for bulk runs: trust (and save, audited) the key of a host never seen before. A bulk
        /// run can't ask; without this such a host fails. A changed key always blocks.
        #[serde(default)]
        trust_new_host_keys: bool,
        /// Seconds each host may take before it counts as failed. `None`: no limit.
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// FD-14 install a checked, signed update. Runs once no other job is open.
    AppUpdate { version: String },
    /// SS-09 add a public key to `~/.ssh/authorized_keys` on many hosts, unless it is there already
    /// (see [`ssh_keys::authorized_keys_script`]).
    PushSshKey {
        targets: Vec<TargetRef>,
        /// The public key in OpenSSH's one-line form. Checked, and written to the hosts in Remotely's
        /// own form, never as typed.
        public_key: String,
        /// As for [`Command::RemoteExec`]: a run can't ask about a host key it has not seen.
        #[serde(default)]
        trust_new_host_keys: bool,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
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
    Take {
        name: String,
    },
    /// `name` may be vmrun's path form (`base/child`) when the VM has two snapshots with that name.
    Revert {
        name: String,
    },
    /// Deletes that one snapshot; its children stay and move up to its parent.
    Delete {
        name: String,
    },
}

/// Longest snapshot name the app takes (VM-04).
pub const MAX_SNAPSHOT_NAME: usize = 120;
/// BX-02: the longest script a bulk run takes.
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
/// BX-02: the longest per-host time limit, a day.
pub const MAX_EXEC_TIMEOUT_SECS: u64 = 24 * 60 * 60;

impl SnapshotOp {
    pub fn name(&self) -> &str {
        match self {
            SnapshotOp::Take { name } | SnapshotOp::Revert { name } | SnapshotOp::Delete { name } => name,
        }
    }

    /// VM-04: a name vmrun will take and the snapshot manager can find again.
    fn validate(&self) -> Result<()> {
        let name = self.name();
        let invalid = |message: String| Err(CoreError::InvalidInput(message));
        if name.trim().is_empty() {
            return invalid("Give the snapshot a name.".into());
        }
        if name.chars().any(char::is_control) {
            return invalid("A snapshot name can't hold line breaks or tabs.".into());
        }
        if name.chars().count() > MAX_SNAPSHOT_NAME {
            return invalid(format!(
                "A snapshot name can be at most {MAX_SNAPSHOT_NAME} characters."
            ));
        }
        if let SnapshotOp::Take { name } = self {
            if name.trim() != name {
                return invalid("A snapshot name can't start or end with a space.".into());
            }
            if name.contains('/') {
                return invalid(
                    "A snapshot name can't contain '/': vmrun reads it as the path to a child snapshot.".into(),
                );
            }
            // VM-05: the prefix marks Remotely's own safety snapshots.
            if is_safety_name(name) {
                return invalid(format!(
                    "Names starting with '{SAFETY_PREFIX}' are kept for safety snapshots."
                ));
            }
        }
        Ok(())
    }
}

/// BX-02: a script the hosts' shells can take.
fn validate_script(script: &str, timeout_secs: Option<u64>) -> Result<()> {
    let invalid = |message: String| Err(CoreError::InvalidInput(message));
    if script.trim().is_empty() {
        return invalid("Type a command or script to run.".into());
    }
    if script.len() > MAX_SCRIPT_BYTES {
        return invalid(format!("A script can be at most {} KB.", MAX_SCRIPT_BYTES / 1024));
    }
    if script.contains('\0') {
        return invalid("A script can't hold NUL characters.".into());
    }
    validate_timeout(timeout_secs)
}

/// BX-02: a per-host time limit within bounds.
fn validate_timeout(timeout_secs: Option<u64>) -> Result<()> {
    if let Some(secs) = timeout_secs {
        if !(1..=MAX_EXEC_TIMEOUT_SECS).contains(&secs) {
            return Err(CoreError::InvalidInput(format!(
                "The time limit must be 1 to {MAX_EXEC_TIMEOUT_SECS} seconds (a day)."
            )));
        }
    }
    Ok(())
}

impl Command {
    /// Checks what the caller typed, before any target is looked up.
    pub fn validate(&self) -> Result<()> {
        match self {
            Command::VmSnapshot { op, .. } => op.validate(),
            Command::RemoteExec {
                script, timeout_secs, ..
            } => validate_script(script, *timeout_secs),
            Command::PushSshKey {
                public_key,
                timeout_secs,
                ..
            } => {
                ssh_keys::parse_public_key(public_key)?;
                validate_timeout(*timeout_secs)
            }
            _ => Ok(()),
        }
    }

    /// The same command on other targets (BX-04 retry). `None` for commands with a fixed target.
    pub fn with_targets(&self, new: Vec<TargetRef>) -> Option<Command> {
        let mut command = self.clone();
        match &mut command {
            Command::VmPower { targets, .. }
            | Command::VmSnapshot { targets, .. }
            | Command::VmProtect { targets, .. }
            | Command::RemoteExec { targets, .. }
            | Command::PushSshKey { targets, .. } => *targets = new,
            Command::AppUpdate { .. } => return None,
        }
        Some(command)
    }

    pub fn targets(&self) -> &[TargetRef] {
        match self {
            Command::VmPower { targets, .. }
            | Command::VmSnapshot { targets, .. }
            | Command::VmProtect { targets, .. }
            | Command::RemoteExec { targets, .. }
            | Command::PushSshKey { targets, .. } => targets,
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
                // The summary is stored in the audit log for good: no secret typed into a command.
                let (first_line, _) = redact_secrets(script.lines().next().unwrap_or_default());
                let sudo = if *sudo { "sudo " } else { "" };
                format!("Run `{sudo}{first_line}` on {}", noun("host"))
            }
            Command::AppUpdate { version } => format!("Install update {version}"),
            Command::PushSshKey { public_key, .. } => match ssh_keys::parse_public_key(public_key) {
                Ok(key) => format!("Add the SSH key {} to {}", key.describe(), noun("host")),
                Err(_) => format!("Add an SSH key to {}", noun("host")),
            },
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
    /// Problems to read before approving, e.g. the capacity check before a power-on (VM-07).
    pub warnings: Vec<String>,
    /// AP-02: each VM target's state, uptime and snapshot count right now.
    pub impact: Vec<TargetImpact>,
    /// BX-02, BX-06, BX-07: for a remote command, what will run and how.
    pub exec: Option<Box<ExecDetails>>,
}

/// A remote command as the approval dialog and the bulk run editor show it (BX-02, BX-06, BX-07).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecDetails {
    /// The whole script, as typed.
    pub script: String,
    pub sudo: bool,
    /// The vault item sudo gets, by label. `None` with sudo: each session's login password.
    pub sudo_password_label: Option<String>,
    pub trust_new_host_keys: bool,
    pub timeout_secs: Option<u64>,
    /// BX-06: the dangerous-command rules the script matched, and what matched.
    pub dangerous: Vec<DangerousMatch>,
    /// BX-04: the job whose failed hosts this one retries.
    pub retry_of: Option<Uuid>,
}

/// What a command would need, without submitting it (BX-06: the bulk run editor shows the tier and
/// the matched rules before anything runs). A read: nothing is audited or queued.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandPreview {
    pub action: ActionKind,
    pub tier: Tier,
    pub steps: Vec<ApprovalStep>,
    /// Targets it would run on (protected ones left out).
    pub targets: usize,
    pub skipped: Vec<Target>,
    pub reasons: Vec<String>,
    pub dangerous: Vec<DangerousMatch>,
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
    retry_of: Option<Uuid>,
}

pub struct CommandBus {
    policy: RwLock<PolicyEngine>,
    directory: Arc<dyn TargetDirectory>,
    jobs: Arc<JobRunner>,
    store: Store,
    vault: Arc<dyn Vault>,
    capacity: CapacityChecker,
    impact: ImpactPreviewer,
    pending: Mutex<HashMap<Uuid, Pending>>,
}

impl CommandBus {
    pub fn new(
        policy: PolicyEngine,
        directory: Arc<dyn TargetDirectory>,
        jobs: Arc<JobRunner>,
        store: Store,
        vault: Arc<dyn Vault>,
        capacity: CapacityChecker,
        impact: ImpactPreviewer,
    ) -> Self {
        Self {
            policy: RwLock::new(policy),
            directory,
            jobs,
            store,
            vault,
            capacity,
            impact,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn rules(&self) -> PolicyRules {
        locks::read(&self.policy).rules().clone()
    }

    /// AP-01: tier rules are editable. Invalid rules are rejected with the reason and the old ones
    /// stay. A change is saved, applies to the next command, and is audited with what changed;
    /// returns those changes (none: nothing saved or logged). Approvals already open keep the steps
    /// they were asked with.
    pub async fn set_rules(&self, ctx: &Context, rules: PolicyRules) -> Result<Vec<String>> {
        let rules = rules.normalized();
        let engine = PolicyEngine::new(rules.clone())?;
        let changes = self.rules().changes(&rules);
        if changes.is_empty() {
            return Ok(changes);
        }
        self.store
            .put_setting(ctx, crate::store::POLICY_RULES_KEY, &rules)
            .await?;
        *locks::write(&self.policy) = engine;
        let detail = changes.join("; ");
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action: "Changed the approval rules",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        Ok(changes)
    }

    pub async fn submit(&self, ctx: &Context, command: Command) -> Result<SubmitOutcome> {
        self.submit_job(ctx, command, None).await
    }

    /// BX-04: runs the same command again on the targets that failed in `job_id`, as a new job that
    /// points back at it. It goes through the policy engine like any command, so its tier and approval
    /// steps are decided again for the targets it has now.
    pub async fn retry_failed(&self, ctx: &Context, job_id: Uuid) -> Result<SubmitOutcome> {
        let (job, command) = self
            .store
            .job_detail(ctx, job_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("job {job_id}")))?;
        if job.is_open() {
            return Err(CoreError::InvalidInput(
                "That job is still running. Retry its failed targets once it has ended.".into(),
            ));
        }
        let failed: Vec<TargetRef> = self
            .store
            .job_targets(ctx, job_id)
            .await?
            .iter()
            .filter(|t| t.status == TargetStatus::Failed.as_str())
            .filter_map(|t| t.target_ref())
            .collect();
        if failed.is_empty() {
            return Err(CoreError::InvalidInput("No target failed in that job.".into()));
        }
        let retry = command
            .with_targets(failed)
            .ok_or_else(|| CoreError::InvalidInput("That job can't be retried.".into()))?;
        self.submit_job(ctx, retry, Some(job_id)).await
    }

    /// BX-06: the tier, steps and matched dangerous-command rules the command would get now. Targets
    /// may be empty while the user is still choosing them.
    pub async fn preview(&self, ctx: &Context, command: &Command) -> Result<CommandPreview> {
        let mut targets = Vec::with_capacity(command.targets().len());
        for target in command.targets() {
            targets.push(self.directory.resolve(ctx, target).await?);
        }
        let policy = locks::read(&self.policy);
        let decision = policy.evaluate(command, &targets);
        let dangerous = match command {
            Command::RemoteExec { script, .. } => policy.dangerous_details(script),
            _ => Vec::new(),
        };
        Ok(CommandPreview {
            action: decision.action,
            tier: decision.tier,
            steps: decision.steps,
            targets: decision.targets.len(),
            skipped: decision.skipped,
            reasons: decision.reasons,
            dangerous,
        })
    }

    /// For a remote command: what the approval dialog shows about it.
    async fn exec_details(
        &self,
        ctx: &Context,
        command: &Command,
        retry_of: Option<Uuid>,
    ) -> Result<Option<Box<ExecDetails>>> {
        if let Command::PushSshKey {
            public_key,
            trust_new_host_keys,
            timeout_secs,
            ..
        } = command
        {
            // SS-09: the dialog shows the script each host runs.
            let key = ssh_keys::parse_public_key(public_key)?;
            return Ok(Some(Box::new(ExecDetails {
                script: ssh_keys::authorized_keys_script(&key),
                sudo: false,
                sudo_password_label: None,
                trust_new_host_keys: *trust_new_host_keys,
                timeout_secs: *timeout_secs,
                dangerous: Vec::new(),
                retry_of,
            })));
        }
        let Command::RemoteExec {
            script,
            sudo,
            sudo_password_id,
            trust_new_host_keys,
            timeout_secs,
            ..
        } = command
        else {
            return Ok(None);
        };
        let sudo_password_label = match (sudo, sudo_password_id) {
            (true, Some(id)) => self
                .vault
                .list(ctx)
                .await?
                .into_iter()
                .find(|s| s.id == *id)
                .map(|s| s.label),
            _ => None,
        };
        Ok(Some(Box::new(ExecDetails {
            script: script.clone(),
            sudo: *sudo,
            sudo_password_label,
            trust_new_host_keys: *trust_new_host_keys,
            timeout_secs: *timeout_secs,
            dangerous: locks::read(&self.policy).dangerous_details(script),
            retry_of,
        })))
    }

    /// BX-07: a sudo password chosen from the vault must be a password that is there.
    async fn check_sudo_password(&self, ctx: &Context, command: &Command) -> Result<()> {
        if let Command::RemoteExec {
            sudo: true,
            sudo_password_id: Some(id),
            ..
        } = command
        {
            match self.store.vault_item_kind(ctx, *id).await? {
                Some(SecretKind::Password) => {}
                Some(other) => {
                    return Err(CoreError::InvalidInput(format!(
                        "sudo needs a password, and that vault item is a {}.",
                        other.label()
                    )))
                }
                None => return Err(CoreError::InvalidInput("The sudo password is not in the vault.".into())),
            }
        }
        Ok(())
    }

    async fn submit_job(&self, ctx: &Context, command: Command, retry_of: Option<Uuid>) -> Result<SubmitOutcome> {
        if command.targets().is_empty() {
            return Err(CoreError::NoTargets);
        }
        command.validate()?;
        self.check_sudo_password(ctx, &command).await?;
        let mut targets = Vec::with_capacity(command.targets().len());
        for target in command.targets() {
            targets.push(self.directory.resolve(ctx, target).await?);
        }

        let mut decision = locks::read(&self.policy).evaluate(&command, &targets);
        if decision.targets.is_empty() {
            return Err(CoreError::AllTargetsProtected);
        }
        if let Command::VmPower {
            op: PowerOp::Start { .. },
            ..
        } = &command
        {
            // VM-07: capacity check before power-on.
            let warnings = self.capacity.check_power_on(ctx, &decision.targets).await;
            decision.add_warnings(warnings.iter().map(|w| w.message()).collect());
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
                    retry_of,
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
            warnings: decision.warnings.clone(),
            impact: self.impact.preview(ctx, &decision.targets).await,
            exec: self.exec_details(ctx, &command, retry_of).await?,
        };
        let detail = decision
            .reasons
            .iter()
            .chain(&decision.warnings)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
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
                    detail: Some(&detail),
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
                retry_of,
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
                        retry_of: pending.retry_of,
                    })
                    .await
            }
            Err(err) => {
                let ctx = pending.ctx;
                let summary = pending.request.summary.clone();
                let tier = pending.decision.tier;
                let targets = pending.decision.targets.clone();
                locks::lock(&self.pending).insert(request_id, pending);
                if matches!(err, CoreError::WrongVaultPassword) {
                    // AP-06: failed re-authentication shows in the audit log, so guessing does too.
                    self.store
                        .append_audit(
                            &ctx,
                            NewAuditEntry {
                                event: "approval_rejected",
                                action: &summary,
                                tier: Some(tier),
                                job_id: None,
                                targets: &targets,
                                approval: None,
                                result: None,
                                detail: Some("wrong vault password"),
                            },
                        )
                        .await?;
                }
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
                // AP-06: the vault's master password, whichever way the vault is unlocked day to day. A
                // vault that is not set up has no password, so the action cannot be approved yet.
                ApprovalStep::VaultReauth => {
                    let password = answers
                        .vault_password
                        .as_ref()
                        .filter(|p| !p.is_empty())
                        .ok_or_else(|| CoreError::ApprovalRejected("the vault password is required".into()))?;
                    if !self.vault.verify_password(password).await? {
                        return Err(CoreError::WrongVaultPassword);
                    }
                    vault_reauth = true;
                }
            }
        }
        Ok(ApprovalRecord {
            request_id: pending.request.id,
            tier: pending.decision.tier,
            typed_target_count: answers.typed_target_count,
            // Kept in the audit log for good, so a secret typed into it by mistake is not.
            reason: answers.reason.as_ref().map(|r| redact_secrets(r.trim()).0),
            safety_snapshot,
            vault_reauth,
            approved_at: now_rfc3339(),
        })
    }
}
