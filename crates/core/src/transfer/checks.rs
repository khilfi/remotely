//! FD-07, MO-08: health check definitions in an export, and back (never their results).
//!
//! A check goes into the file with its kind, timing and target: a typed address as it is, a session by its id in the
//! file, a VM by its key. On import a check is new, the same as one here (same name, any letter case, and the same
//! definition once its session is mapped), or in conflict with the one here of that name; the user skips it, replaces
//! the one here or keeps both. A session target becomes the session imported from the file (or the one here with
//! that id when the file doesn't hold it); a VM target needs that VM in this workspace on this laptop. A check whose
//! target ends up nowhere is not imported, with a note. Saving goes through [`Checks`], so it is checked and audited
//! as if the user had made it here.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::CONFLICT_CHOICES;
use super::{free_name, item, plural, ItemAction, ItemProblem, Payload, PreviewItem, RowPlan, TransferReport};
use crate::checks::spec::{CheckInput, CheckSpec, HealthCheck, MAX_NAME};
use crate::checks::Checks;
use crate::domain::Context;
use crate::error::Result;
use crate::sessions::SessionRecord;
use crate::store::Store;
use crate::toolbox::ProbeTarget;

/// One check in the file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CheckEntry {
    pub(super) name: String,
    /// A session by its id in the file.
    pub(super) target: ProbeTarget,
    pub(super) spec: CheckSpec,
    pub(super) interval_secs: u64,
    pub(super) timeout_secs: u64,
    pub(super) failures_before_down: u32,
    #[serde(default)]
    pub(super) paused: bool,
}

impl CheckEntry {
    fn input(&self, target: ProbeTarget) -> CheckInput {
        CheckInput {
            name: self.name.clone(),
            target,
            spec: self.spec.clone(),
            interval_secs: self.interval_secs,
            timeout_secs: self.timeout_secs,
            failures_before_down: self.failures_before_down,
            paused: self.paused,
        }
    }
}

/// Every check of this workspace, for an export.
pub(super) async fn entries(store: &Store, ctx: &Context) -> Result<Vec<CheckEntry>> {
    Ok(store
        .list_checks(ctx)
        .await?
        .into_iter()
        .map(|c| CheckEntry {
            name: c.name,
            target: c.target,
            spec: c.spec,
            interval_secs: c.interval_secs,
            timeout_secs: c.timeout_secs,
            failures_before_down: c.failures_before_down,
            paused: c.paused,
        })
        .collect())
}

/// Where a check's target lands here: a session mapped from the file, the session here with that id, a VM of this
/// workspace, a typed address; `None` when it ends up nowhere.
async fn target_here(
    store: &Store,
    ctx: &Context,
    entry: &CheckEntry,
    payload: &Payload,
    mapped: &HashMap<Uuid, Uuid>,
    sessions_here: &HashSet<Uuid>,
) -> Result<Option<ProbeTarget>> {
    Ok(match &entry.target {
        ProbeTarget::Address { host } => Some(ProbeTarget::Address { host: host.clone() }),
        ProbeTarget::Session { session_id } => {
            let here = mapped.get(session_id).copied().or_else(|| {
                let in_file = payload.sessions.iter().any(|s| s.id == *session_id);
                (!in_file && sessions_here.contains(session_id)).then_some(*session_id)
            });
            here.map(|session_id| ProbeTarget::Session { session_id })
        }
        ProbeTarget::Vm { vm_key } => {
            let here = store.require_vm_here(ctx, vm_key).await.is_ok() && store.find_vm(ctx, vm_key).await?.is_some();
            here.then(|| ProbeTarget::Vm { vm_key: vm_key.clone() })
        }
    })
}

/// Each check of the file compared with the checks here, by name.
pub(super) async fn plan(
    store: &Store,
    ctx: &Context,
    payload: &Payload,
    mapped: &HashMap<Uuid, Uuid>,
    sessions_here: &HashSet<Uuid>,
) -> Result<Vec<RowPlan<Uuid>>> {
    let here = store.list_checks(ctx).await?;
    let mut rows = Vec::with_capacity(payload.checks.len());
    for (index, entry) in payload.checks.iter().enumerate() {
        let name = entry.name.trim().to_lowercase();
        let Some(local) = here.iter().find(|c| c.name.to_lowercase() == name) else {
            rows.push(RowPlan::new(index));
            continue;
        };
        let target = target_here(store, ctx, entry, payload, mapped, sessions_here).await?;
        if target.is_some_and(|t| same(local, entry, &t)) {
            rows.push(RowPlan::same(
                index,
                local.id,
                "Already a health check here.".to_owned(),
            ));
        } else {
            rows.push(RowPlan::conflict(
                index,
                local.id,
                format!(
                    "A health check named '{}' is here: {}.",
                    local.name,
                    local.spec.describe()
                ),
                CONFLICT_CHOICES.to_vec(),
            ));
        }
    }
    Ok(rows)
}

fn same(local: &HealthCheck, entry: &CheckEntry, target: &ProbeTarget) -> bool {
    local.target == *target
        && local.spec == entry.spec
        && local.interval_secs == entry.interval_secs
        && local.timeout_secs == entry.timeout_secs
        && local.failures_before_down == entry.failures_before_down
}

/// The preview's rows: what each check does and on what, and a note when its target won't be here.
pub(super) fn preview(
    payload: &Payload,
    rows: Vec<RowPlan<Uuid>>,
    sessions_here: &[SessionRecord],
) -> Vec<PreviewItem> {
    rows.into_iter()
        .map(|row| {
            let entry = &payload.checks[row.index];
            let (on, mut notes) = match &entry.target {
                ProbeTarget::Address { host } => (host.clone(), Vec::new()),
                ProbeTarget::Session { session_id } => {
                    let name = payload
                        .sessions
                        .iter()
                        .find(|s| s.id == *session_id)
                        .map(|s| s.name.clone())
                        .or_else(|| {
                            sessions_here
                                .iter()
                                .find(|s| s.id == *session_id)
                                .map(|s| s.name.clone())
                        });
                    match name {
                        Some(name) => (
                            name,
                            vec!["It is left out if you skip its session and it isn't here already.".to_owned()],
                        ),
                        None => (
                            "a session not in the file".to_owned(),
                            vec!["Its session isn't in the file or here, so it is left out.".to_owned()],
                        ),
                    }
                }
                ProbeTarget::Vm { .. } => (
                    "a VM".to_owned(),
                    vec!["It is imported only when its VM is in this workspace on this laptop.".to_owned()],
                ),
            };
            if entry.paused {
                notes.push("It comes paused.".to_owned());
            }
            let detail = format!(
                "{} on {on}, {}",
                entry.spec.describe(),
                crate::checks::spec::every_text(entry.interval_secs)
            );
            item(row, entry.name.trim().to_owned(), detail, notes)
        })
        .collect()
}

/// Where the file's sessions ended up once they are in.
pub(super) struct Landed<'a> {
    /// Each file session to the session it became here.
    pub(super) imported: &'a HashMap<Uuid, Uuid>,
    /// The sessions that were here before the import.
    pub(super) here_before: &'a HashSet<Uuid>,
}

/// Saves the chosen checks once the sessions are in, each through [`Checks`] (checked and audited).
#[allow(clippy::too_many_arguments)]
pub(super) async fn commit(
    ctx: &Context,
    store: &Store,
    checks: Option<&Checks>,
    payload: &Payload,
    (rows, actions): (&[RowPlan<Uuid>], &[ItemAction]),
    landed: Landed<'_>,
    report: &mut TransferReport,
) -> Result<()> {
    for (row, action) in rows.iter().zip(actions) {
        let entry = &payload.checks[row.index];
        let shown = format!("{} (health check)", entry.name.trim());
        if *action == ItemAction::Skip {
            report.checks.count(*action);
            continue;
        }
        let Some(checks) = checks else {
            report.problems.push(ItemProblem {
                name: shown,
                reason: "Health checks can't be imported here.".to_owned(),
            });
            continue;
        };
        let Some(target) = target_here(store, ctx, entry, payload, landed.imported, landed.here_before).await? else {
            let reason = match entry.target {
                ProbeTarget::Vm { .. } => "Its VM isn't in this workspace on this laptop, so it was not imported.",
                _ => "Its session isn't here (it was skipped, or isn't in the file), so it was not imported.",
            };
            report.problems.push(ItemProblem {
                name: shown,
                reason: reason.to_owned(),
            });
            continue;
        };
        let mut input = entry.input(target);
        let result = match (action, row.local) {
            (ItemAction::Replace, Some(id)) => checks.update_in(*ctx, id, input).await,
            (ItemAction::KeepBoth, _) => {
                let taken: HashSet<String> = store
                    .list_checks(ctx)
                    .await?
                    .iter()
                    .map(|c| c.name.to_lowercase())
                    .collect();
                input.name = free_name(entry.name.trim(), &taken, MAX_NAME);
                checks.create_in(*ctx, input).await
            }
            _ => checks.create_in(*ctx, input).await,
        };
        match result {
            Ok(_) => report.checks.count(*action),
            Err(err) => report.problems.push(ItemProblem {
                name: shown,
                reason: err.to_string(),
            }),
        }
    }
    Ok(())
}

/// "3 health checks".
pub(super) fn count_text(n: usize) -> String {
    plural(n, "health check")
}
