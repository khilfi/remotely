//! VM-14, VM-27 standing approvals: a schedule is approved when it is saved, and each run is a run of that approval
//! (docs/plan-0.5.md, "Approval tiers").
//!
//! * [`CommandBus::ask_standing`]: the save asks with the same steps as running the schedule then (AP-06 included):
//!   the policy engine rates each of its commands on its targets and the save gets the highest tier's steps, with
//!   no countdown (each run's job has its own, [`crate::policy::PolicyEngine::evaluate_standing`]). Low asks
//!   nothing: the approval is granted and recorded at once.
//! * [`CommandBus::approve_standing`]: the answers are checked like any approval's ([`CommandBus::check_answers`]),
//!   and the bus records a [`StandingGrant`]: the schedule's content hash, a fingerprint of the rules that rated it,
//!   the tier, the commands a run may submit, the targets it was shown with their labels then, and the answers.
//! * [`CommandBus::submit_standing`]: each scheduled command names its grant. The bus refuses it while the read-only
//!   lock is on, and asks again ([`CoreError::StandingChanged`], nothing runs) when the schedule was edited, the
//!   rules that rated it changed, a target is new, protected or labelled Prod since, or the command rates higher
//!   than approved. Otherwise the job runs with the grant's answers (its safety snapshot choice too), and the audit
//!   log has `approval_used`, then the job's entries, each carrying the approval with the run it belongs to.
//!   A command that names no grant, a revoked one or another schedule's is refused.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApprovalAnswers, ApprovalRecord, ApprovalRequest, CommandBus, Pending, Previews};
use crate::adapters::vmware::path_key;
use crate::command_bus::{Command, SnapshotOp};
use crate::domain::{now_rfc3339, Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::jobs::JobSpec;
use crate::locks;
use crate::policy::{safety_snapshot_applies, ActionKind, Decision, Tier};
use crate::presentation::Change;
use crate::schedules::SNAPSHOT_PREFIX;
use crate::store::NewAuditEntry;

/// What a schedule asks the bus to approve when it is saved.
#[derive(Debug, Clone)]
pub struct StandingDraft {
    /// The schedule.
    pub owner_id: Uuid,
    /// "Schedule 'nightly': take a snapshot of 3 VMs daily at 02:00, keeping the last 7".
    pub summary: String,
    /// SHA-256 of the schedule's content (action, targets, times).
    pub content_hash: String,
    /// The commands each run submits, on the schedule's targets as they are now.
    pub commands: Vec<Command>,
    /// For the approval dialog.
    pub details: StandingDetails,
    /// Problems to read before approving (snapshot chains, safety snapshots adding up).
    pub warnings: Vec<String>,
    /// Why it is asked again (the schedule was edited, a target became Prod...), for the dialog and the audit log.
    pub again: Option<String>,
}

/// A schedule as the approval dialog shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingDetails {
    pub schedule_id: Uuid,
    pub name: String,
    /// "Daily at 02:00".
    pub when: String,
    /// The next runs, local time in words ("Sun 25 Oct 02:00"), with what daylight saving does to one.
    pub next_runs: Vec<String>,
    /// How the targets were found: "tag 'lab': web01, web02".
    pub resolves: Vec<String>,
    /// VM-27: what its snapshots are called, and how many it keeps.
    pub snapshot_name: Option<String>,
    pub keep: Option<u32>,
    /// The countdown each run's job waits, when its tier has one (cancellable in Activity).
    pub countdown_seconds: Option<u32>,
}

/// What [`CommandBus::ask_standing`] did.
#[derive(Debug, Clone)]
pub enum StandingAsk {
    /// Nothing to ask (Low): the approval is granted and recorded.
    Granted(Box<StandingGrant>),
    /// Collect the answers, then call [`CommandBus::approve_standing`].
    NeedsApproval(Box<ApprovalRequest>),
}

/// An approval given when a schedule was saved, as the bus records it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingGrant {
    /// The approval request's id.
    pub id: Uuid,
    /// The schedule.
    pub owner_id: Uuid,
    pub content_hash: String,
    /// [`crate::policy::PolicyRules::fingerprint`] of the rules that rated it.
    pub rules_hash: String,
    pub tier: Tier,
    pub kinds: Vec<ActionKind>,
    /// The commands a run may submit, without targets.
    pub commands: Vec<Command>,
    /// The targets it was approved for, with their labels then.
    pub targets: Vec<Target>,
    /// Targets that were protected then, and so left out.
    pub skipped: Vec<Target>,
    /// The answers (no secret).
    pub record: ApprovalRecord,
    pub granted_at: String,
}

/// A command a schedule's run submits under its standing approval.
#[derive(Debug, Clone)]
pub struct StandingRun {
    pub approval_id: Uuid,
    /// The schedule's content hash now.
    pub content_hash: String,
    pub command: Command,
    pub run_id: Uuid,
    /// "Schedule 'nightly'", for the audit log.
    pub label: String,
    /// When the run was due, for the audit log.
    pub due: String,
}

/// In each job and audit entry of a scheduled run: which standing approval it ran under, and which run it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandingUse {
    pub approval_id: Uuid,
    pub schedule_id: Uuid,
    pub run_id: Uuid,
    /// "Schedule 'nightly'".
    pub label: String,
    /// When the approval was given.
    pub granted_at: String,
}

/// A grant's commands as the record keeps them: no targets.
fn template(command: &Command) -> Command {
    command.with_targets(Vec::new()).unwrap_or_else(|| command.clone())
}

/// Whether a run's command is one the grant approved: the same power operation, or a snapshot taken under the
/// schedules' own name (VM-27), or a snapshot deleted (which ones: the schedule's retention, by recorded id).
fn covers(approved: &Command, command: &Command) -> bool {
    match (approved, command) {
        (Command::VmPower { op: a, .. }, Command::VmPower { op: b, .. }) => a == b,
        (
            Command::VmSnapshot {
                op: SnapshotOp::Take { .. },
                ..
            },
            Command::VmSnapshot {
                op: SnapshotOp::Take { name },
                ..
            },
        ) => name.starts_with(SNAPSHOT_PREFIX),
        (
            Command::VmSnapshot {
                op: SnapshotOp::Delete { .. },
                ..
            },
            Command::VmSnapshot {
                op: SnapshotOp::Delete { .. },
                ..
            },
        ) => true,
        _ => false,
    }
}

fn key(target: &Target) -> String {
    match &target.target {
        TargetRef::Vm { vmx_path } => path_key(std::path::Path::new(vmx_path)),
        other => other.key(),
    }
}

impl CommandBus {
    /// VM-14, VM-27: what a schedule's save asks for (see the module). Refused while the read-only lock is on.
    pub async fn ask_standing(&self, ctx: &Context, draft: StandingDraft) -> Result<StandingAsk> {
        self.store.read_only().check(Change::Schedules)?;
        self.expire_stale().await;
        self.ask_standing_as(ctx, Uuid::new_v4(), draft).await
    }

    async fn ask_standing_as(&self, ctx: &Context, id: Uuid, draft: StandingDraft) -> Result<StandingAsk> {
        let Some(first) = draft.commands.first().cloned() else {
            return Err(CoreError::NoTargets);
        };
        if first.targets().is_empty() {
            return Err(CoreError::NoTargets);
        }
        for command in &draft.commands {
            command.validate()?;
        }
        let targets = self.resolve_targets(ctx, &first).await?;
        let mut decision = locks::read(&self.policy)
            .evaluate_standing(&draft.commands, &targets)
            .ok_or(CoreError::NoTargets)?;
        if decision.targets.is_empty() {
            return Err(CoreError::AllTargetsProtected);
        }
        // AP-08: a schedule's High or Critical approval takes a change ID like any, and each run carries it.
        self.apply_change_id_rule(ctx, &mut decision).await?;
        decision.add_warnings(draft.warnings.clone());
        if decision.steps.is_empty() {
            // Low: nothing to ask, as when it runs now; the approval is still recorded and audited.
            let record = ApprovalRecord {
                request_id: id,
                tier: decision.tier,
                typed_target_count: None,
                reason: None,
                safety_snapshot: false,
                vault_reauth: false,
                approved_at: now_rfc3339(),
                standing: None,
                change_id: None,
            };
            let grant = self.grant(ctx, &draft, &decision, record).await?;
            return Ok(StandingAsk::Granted(Box::new(grant)));
        }
        let mut request = self
            .request_for(ctx, id, &first, &decision, Previews::default(), None)
            .await?;
        request.summary = draft.summary.clone();
        let countdown = locks::read(&self.policy).rules().countdown_seconds;
        let mut details = draft.details.clone();
        // High and Critical runs wait out the countdown before they start.
        details.countdown_seconds = (decision.tier >= Tier::High && countdown > 0).then_some(countdown);
        request.standing = Some(Box::new(details));
        self.audit_requested(ctx, &decision, &draft.summary, draft.again.as_deref())
            .await?;
        locks::lock(&self.pending).insert(
            id,
            Pending {
                ctx: *ctx,
                command: first,
                decision,
                request: request.clone(),
                retry_of: None,
                asked: Instant::now(),
                standing: Some(Box::new(draft)),
            },
        );
        Ok(StandingAsk::NeedsApproval(Box::new(request)))
    }

    /// VM-14, VM-27: checks the answers to a schedule's approval and records the grant. Like
    /// [`CommandBus::approve`]: an expired request is gone, a wrong answer leaves it waiting, and a target that became
    /// Prod or protected since it was asked asks again under the same id ([`CoreError::ApprovalChanged`]).
    pub async fn approve_standing(&self, request_id: Uuid, answers: ApprovalAnswers) -> Result<StandingGrant> {
        let pending = locks::lock(&self.pending)
            .remove(&request_id)
            .ok_or(CoreError::UnknownApproval(request_id))?;
        let Some(draft) = pending.standing.clone() else {
            locks::lock(&self.pending).insert(request_id, pending);
            return Err(CoreError::InvalidInput(
                "That approval is for an action, not a schedule.".into(),
            ));
        };
        let ttl = self.approval_ttl();
        if pending.expired(ttl) {
            self.audit_expired(&pending, ttl).await;
            self.expire_stale().await;
            return Err(CoreError::ApprovalExpired {
                minutes: ttl.as_secs().div_ceil(60),
            });
        }
        if let Err(err) = self.store.read_only().check(Change::Schedules) {
            locks::lock(&self.pending).insert(request_id, pending);
            return Err(err);
        }
        let (_, changes) = match self.label_changes(&pending).await {
            Ok(found) => found,
            Err(err) => {
                locks::lock(&self.pending).insert(request_id, pending);
                return Err(err);
            }
        };
        if !changes.is_empty() {
            let changes = changes.join("; ");
            let mut again = *draft;
            again.again = Some(changes.clone());
            return Err(match self.ask_standing_as(&pending.ctx, request_id, again).await {
                Ok(StandingAsk::NeedsApproval(request)) => CoreError::ApprovalChanged { changes, request },
                // Nothing to ask any more: it is granted, but the schedule must look again for it.
                Ok(StandingAsk::Granted(_)) => {
                    CoreError::ApprovalRejected(format!("{changes}; ask for the schedule's approval again"))
                }
                Err(err) => err,
            });
        }
        match self.check_answers(&pending, &answers).await {
            Ok(record) => self.grant(&pending.ctx, &draft, &pending.decision, record).await,
            Err(err) => {
                let ctx = pending.ctx;
                let summary = pending.request.summary.clone();
                let tier = pending.decision.tier;
                let targets = pending.decision.targets.clone();
                locks::lock(&self.pending).insert(request_id, pending);
                if matches!(err, CoreError::WrongVaultPassword) {
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

    /// Records and audits a granted standing approval.
    async fn grant(
        &self,
        ctx: &Context,
        draft: &StandingDraft,
        decision: &Decision,
        record: ApprovalRecord,
    ) -> Result<StandingGrant> {
        let (kinds, rules_hash) = {
            let policy = locks::read(&self.policy);
            (
                policy.standing_kinds(&draft.commands),
                policy.standing_fingerprint(&draft.commands),
            )
        };
        let grant = StandingGrant {
            id: record.request_id,
            owner_id: draft.owner_id,
            content_hash: draft.content_hash.clone(),
            rules_hash,
            tier: decision.tier,
            kinds,
            commands: draft.commands.iter().map(template).collect(),
            targets: decision.targets.clone(),
            skipped: decision.skipped.clone(),
            granted_at: record.approved_at.clone(),
            record,
        };
        self.store.insert_standing_approval(ctx, &grant).await?;
        let detail = format!(
            "standing approval: each run of the schedule is a run of it, until the schedule is edited or deleted, \
             or a target or the rules that rated it change; {}",
            draft.details.when
        );
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "approval_granted",
                    action: &draft.summary,
                    tier: Some(decision.tier),
                    job_id: None,
                    targets: &decision.targets,
                    approval: Some(&grant.record),
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        Ok(grant)
    }

    /// VM-14, VM-27: no command runs under a schedule's approvals any more (it was edited, re-approved or deleted).
    /// Audited by the schedule.
    pub async fn revoke_standing(&self, ctx: &Context, owner_id: Uuid, why: &str) -> Result<u64> {
        self.store.revoke_standing_approvals(ctx, owner_id, why).await
    }

    /// The grant a run names, if it is one the bus gave and did not revoke.
    pub async fn standing_grant(&self, ctx: &Context, approval_id: Uuid) -> Result<Option<StandingGrant>> {
        self.store.standing_approval(ctx, approval_id).await
    }

    /// VM-14, VM-27: what makes a scheduled command need approving again, in words (none: it may run). `Err` for a
    /// command no grant covers. A read: nothing is audited. The scheduler asks it before each run and to pause a
    /// schedule as soon as something changed.
    pub async fn standing_changes(
        &self,
        ctx: &Context,
        approval_id: Uuid,
        content_hash: &str,
        command: &Command,
    ) -> Result<Vec<String>> {
        let grant = self.covering_grant(ctx, approval_id, command).await?;
        let targets = self.resolve_targets(ctx, command).await?;
        let mut changes = self.changes_since(&grant, content_hash, command, &targets).1;
        changes.extend(self.change_id_now_needed(ctx, &grant, &targets).await?);
        Ok(changes)
    }

    /// AP-08: the workspace requires a change ID for Prod targets since the schedule was approved without one.
    async fn change_id_now_needed(
        &self,
        ctx: &Context,
        grant: &StandingGrant,
        targets: &[Target],
    ) -> Result<Option<String>> {
        if grant.tier < Tier::High || grant.record.change_id.is_some() {
            return Ok(None);
        }
        let rules = super::ChangeIdRules::load(&self.store, ctx).await?;
        Ok(rules
            .requires(targets)
            .then(|| "this workspace needs a change ID for Prod targets now".to_owned()))
    }

    async fn covering_grant(&self, ctx: &Context, approval_id: Uuid, command: &Command) -> Result<StandingGrant> {
        let grant =
            self.store.standing_approval(ctx, approval_id).await?.ok_or_else(|| {
                CoreError::InvalidInput("That schedule's approval was withdrawn or never given.".into())
            })?;
        if !grant.commands.iter().any(|approved| covers(approved, command)) {
            return Err(CoreError::InvalidInput(format!(
                "\"{}\" is not what the schedule was approved for.",
                command.summary(command.targets().len())
            )));
        }
        Ok(grant)
    }

    /// The decision for `command` now, and what changed since `grant`.
    fn changes_since(
        &self,
        grant: &StandingGrant,
        content_hash: &str,
        command: &Command,
        targets: &[Target],
    ) -> (Decision, Vec<String>) {
        let policy = locks::read(&self.policy);
        let decision = policy.evaluate(command, targets);
        let mut changes = Vec::new();
        if grant.content_hash != content_hash {
            changes.push("the schedule was edited".to_owned());
        }
        let approved: HashMap<String, &Target> = grant.targets.iter().map(|t| (key(t), t)).collect();
        let skipped: HashMap<String, &Target> = grant.skipped.iter().map(|t| (key(t), t)).collect();
        for target in targets {
            let k = key(target);
            match (approved.get(&k), skipped.get(&k)) {
                (Some(was), _) => {
                    if target.protected && !was.protected {
                        changes.push(format!("{} is protected now", target.name));
                    } else if target.environment == Environment::Prod && was.environment != Environment::Prod {
                        changes.push(format!("{} is labelled Prod now", target.name));
                    }
                }
                // Protected when approved, and still protected: skipped, as approved.
                (None, Some(_)) if target.protected => {}
                (None, Some(_)) => changes.push(format!("{} is not protected any more", target.name)),
                (None, None) => changes.push(format!("{} was not among the approved targets", target.name)),
            }
        }
        if policy.rules().fingerprint(&grant.kinds) != grant.rules_hash {
            changes.push("the approval rules changed".to_owned());
        }
        if decision.tier > grant.tier && changes.is_empty() {
            changes.push(format!(
                "it rates {} now, above the {} approved",
                decision.tier.as_str(),
                grant.tier.as_str()
            ));
        }
        (decision, changes)
    }

    /// VM-14, VM-27: runs a scheduled command under its standing approval (see the module). Returns the job.
    pub async fn submit_standing(&self, ctx: &Context, run: StandingRun) -> Result<Uuid> {
        let StandingRun {
            approval_id,
            content_hash,
            command,
            run_id,
            label,
            due,
        } = run;
        // FD-03: nothing scheduled runs while the read-only lock is on.
        locks::read(&self.policy).check_read_only(self.store.read_only().is_locked(), &command)?;
        if command.targets().is_empty() {
            return Err(CoreError::NoTargets);
        }
        command.validate()?;
        let grant = match self.covering_grant(ctx, approval_id, &command).await {
            Ok(grant) => grant,
            Err(err) => {
                // Never expected from the scheduler: logged so it shows if it ever happens.
                let detail = format!("refused: {err}");
                let written = self
                    .store
                    .append_audit(
                        ctx,
                        NewAuditEntry {
                            event: "approval_refused",
                            action: &command.summary(command.targets().len()),
                            tier: None,
                            job_id: None,
                            targets: &[],
                            approval: None,
                            result: None,
                            detail: Some(&detail),
                        },
                    )
                    .await;
                if let Err(audit) = written {
                    tracing::error!(error = %audit, "could not audit a refused scheduled command");
                }
                return Err(err);
            }
        };
        let targets = self.resolve_targets(ctx, &command).await?;
        let (decision, mut changes) = self.changes_since(&grant, &content_hash, &command, &targets);
        changes.extend(self.change_id_now_needed(ctx, &grant, &targets).await?);
        if !changes.is_empty() {
            return Err(CoreError::StandingChanged {
                changes: changes.join("; "),
            });
        }
        if decision.targets.is_empty() {
            return Err(CoreError::AllTargetsProtected);
        }
        let mut record = grant.record.clone();
        record.standing = Some(StandingUse {
            approval_id: grant.id,
            schedule_id: grant.owner_id,
            run_id,
            label: label.clone(),
            granted_at: grant.granted_at.clone(),
        });
        let summary = command.summary(decision.targets.len());
        let detail = format!("{label}, run due {due}, under the approval given {}", grant.granted_at);
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "approval_used",
                    action: &summary,
                    tier: Some(decision.tier),
                    job_id: None,
                    targets: &decision.targets,
                    approval: Some(&record),
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        let safety_snapshot = record.safety_snapshot && safety_snapshot_applies(&command);
        self.jobs
            .enqueue(JobSpec {
                ctx: *ctx,
                command,
                decision,
                approval: Some(record),
                safety_snapshot,
                retry_of: None,
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_bus::{PowerOp, StopMode};

    #[test]
    fn a_grant_covers_its_own_kinds_of_command_only() {
        let suspend = Command::VmPower {
            targets: vec![],
            op: PowerOp::Suspend,
        };
        let stop = Command::VmPower {
            targets: vec![],
            op: PowerOp::Stop { mode: StopMode::Soft },
        };
        let hard = Command::VmPower {
            targets: vec![],
            op: PowerOp::Stop { mode: StopMode::Hard },
        };
        assert!(covers(&suspend, &suspend));
        assert!(!covers(&suspend, &stop));
        assert!(!covers(&stop, &hard), "a soft stop's approval never covers a hard one");
        let take = |name: &str| Command::VmSnapshot {
            targets: vec![],
            op: SnapshotOp::Take { name: name.into() },
        };
        assert!(covers(
            &take("x"),
            &take("Remotely schedule 'nightly' 2026-10-25 02:00 (run 1a2b3c4d)")
        ));
        assert!(!covers(&take("x"), &take("base")), "only the schedules' own names");
        let revert = Command::VmSnapshot {
            targets: vec![],
            op: SnapshotOp::Revert { name: "x".into() },
        };
        assert!(!covers(&take("x"), &revert));
        assert!(!covers(&suspend, &take("Remotely schedule x")));
    }
}
