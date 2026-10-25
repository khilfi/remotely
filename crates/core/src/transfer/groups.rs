//! FD-07, QL-19: saved MultiExec groups in an export, and back.
//!
//! A group goes into the file by name, with its member sessions by their ids in the file. On import a
//! group is new, the same as one here (same name, any letter case, and the same sessions in the same
//! order), or in conflict with the one here of that name; the user skips it, replaces the one here or
//! keeps both. Each member becomes the session imported from the file (which may be one already here:
//! a skipped session that matches one here, or a replaced one), or the session here with that id when
//! the file does not hold it. Members that end up nowhere are left out of the group, with a note; a
//! group left with none is not imported. Saving goes through [`MultiExecGroups`], so it is checked and
//! audited as if the user had made it on this laptop.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::CONFLICT_CHOICES;
use super::{free_name, item, plural, ItemAction, ItemProblem, Payload, PreviewItem, RowPlan, TransferReport};
use crate::domain::Context;
use crate::error::Result;
use crate::multiexec_groups::{GroupInput, MultiExecGroup, MultiExecGroups, MAX_NAME};
use crate::sessions::SessionRecord;
use crate::store::Store;

/// Member names a preview lists before "and N more".
const NAMES_SHOWN: usize = 5;

/// One group in the file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GroupEntry {
    pub(super) name: String,
    /// Its sessions by their id in the file, in order.
    #[serde(default)]
    pub(super) sessions: Vec<Uuid>,
}

/// Every group of this workspace, for an export.
pub(super) async fn entries(store: &Store, ctx: &Context) -> Result<Vec<GroupEntry>> {
    let groups = MultiExecGroups::new(store.clone()).list(ctx).await?;
    Ok(groups
        .into_iter()
        .map(|g| GroupEntry {
            sessions: g.session_ids(),
            name: g.name,
        })
        .collect())
}

/// This workspace's groups, for a preview or a commit.
pub(super) async fn here(store: &Store, ctx: &Context) -> Result<Vec<MultiExecGroup>> {
    MultiExecGroups::new(store.clone()).list(ctx).await
}

/// Which session here each file session would be with the default choices, as far as the preview can
/// tell: the session it matches here (by id, address or name). A new one has none yet.
pub(super) fn matched_here(payload: &Payload, session_rows: &[RowPlan<Uuid>]) -> HashMap<Uuid, Uuid> {
    session_rows
        .iter()
        .filter_map(|row| Some((payload.sessions[row.index].id, row.local?)))
        .collect()
}

/// A member's session here: the one its file session became, or the session here with its id when the
/// file does not hold it.
fn member_here(
    id: Uuid,
    payload: &Payload,
    mapped: &HashMap<Uuid, Uuid>,
    sessions_here: &HashSet<Uuid>,
) -> Option<Uuid> {
    if let Some(here) = mapped.get(&id) {
        return Some(*here);
    }
    let in_file = payload.sessions.iter().any(|s| s.id == id);
    (!in_file && sessions_here.contains(&id)).then_some(id)
}

/// Each member's session here, in order and once each, and how many end up nowhere.
fn members_here(
    entry: &GroupEntry,
    payload: &Payload,
    mapped: &HashMap<Uuid, Uuid>,
    sessions_here: &HashSet<Uuid>,
) -> (Vec<Uuid>, Vec<Uuid>) {
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    let mut lost = Vec::new();
    for id in &entry.sessions {
        match member_here(*id, payload, mapped, sessions_here) {
            Some(here) => {
                if seen.insert(here) {
                    found.push(here);
                }
            }
            None => lost.push(*id),
        }
    }
    (found, lost)
}

/// Each group of the file compared with the groups here, by name.
pub(super) fn plan(
    payload: &Payload,
    groups_here: &[MultiExecGroup],
    mapped: &HashMap<Uuid, Uuid>,
    sessions_here: &HashSet<Uuid>,
) -> Vec<RowPlan<Uuid>> {
    payload
        .groups
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let name = entry.name.trim().to_lowercase();
            let Some(here) = groups_here.iter().find(|g| g.name.to_lowercase() == name) else {
                return RowPlan::new(index);
            };
            let (found, lost) = members_here(entry, payload, mapped, sessions_here);
            if lost.is_empty() && found == here.session_ids() {
                RowPlan::same(index, here.id, "Already a MultiExec group here.".to_owned())
            } else {
                RowPlan::conflict(
                    index,
                    here.id,
                    format!(
                        "A MultiExec group named '{}' is here, with {}.",
                        here.name,
                        if here.members.is_empty() {
                            "no sessions".to_owned()
                        } else {
                            format!("other sessions ({})", plural(here.members.len(), "session"))
                        }
                    ),
                    CONFLICT_CHOICES.to_vec(),
                )
            }
        })
        .collect()
}

/// `'web01', 'web02' and 3 more`.
fn listed(names: &[String]) -> String {
    let shown: Vec<String> = names.iter().take(NAMES_SHOWN).map(|n| format!("'{n}'")).collect();
    let more = names.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// The preview's rows: each group's sessions by name, and a note for members that would be left out.
pub(super) fn preview(
    payload: &Payload,
    rows: Vec<RowPlan<Uuid>>,
    sessions_here: &[SessionRecord],
    mapped: &HashMap<Uuid, Uuid>,
) -> Vec<PreviewItem> {
    let ids_here: HashSet<Uuid> = sessions_here.iter().map(|s| s.id).collect();
    let name_of = |id: &Uuid| -> Option<String> {
        payload
            .sessions
            .iter()
            .find(|s| s.id == *id)
            .map(|s| s.name.clone())
            .or_else(|| sessions_here.iter().find(|s| s.id == *id).map(|s| s.name.clone()))
    };
    rows.into_iter()
        .map(|row| {
            let entry = &payload.groups[row.index];
            let names: Vec<String> = entry.sessions.iter().filter_map(name_of).collect();
            let detail = if names.is_empty() {
                "no sessions".to_owned()
            } else {
                format!("{}: {}", plural(names.len(), "session"), listed(&names))
            };
            let (_, lost) = members_here(entry, payload, mapped, &ids_here);
            let missing = lost.iter().filter(|id| name_of(id).is_none()).count();
            let mut notes = Vec::new();
            if missing > 0 {
                notes.push(format!(
                    "{} not in the file or here, so left out of it.",
                    if missing == 1 {
                        "1 of its sessions is".to_owned()
                    } else {
                        format!("{missing} of its sessions are")
                    }
                ));
            }
            notes.push("Sessions you skip and that aren't here already are left out of it.".to_owned());
            item(row, entry.name.trim().to_owned(), detail, notes)
        })
        .collect()
}

/// Where the file's sessions ended up once they are in.
pub(super) struct Landed<'a> {
    /// Each file session to the session it became here: imported, replaced, or skipped for one here.
    pub(super) imported: &'a HashMap<Uuid, Uuid>,
    /// The sessions that were here before the import.
    pub(super) here_before: &'a HashSet<Uuid>,
}

/// Saves the chosen groups (`rows` and their `actions`) once the sessions are in. Each group is saved
/// and audited by [`MultiExecGroups`]; a group that fails, or loses members, is reported.
pub(super) async fn commit(
    ctx: &Context,
    store: &Store,
    payload: &Payload,
    (rows, actions): (&[RowPlan<Uuid>], &[ItemAction]),
    landed: Landed<'_>,
    report: &mut TransferReport,
) -> Result<()> {
    let Landed {
        imported,
        here_before: sessions_here,
    } = landed;
    let groups = MultiExecGroups::new(store.clone());
    for (row, action) in rows.iter().zip(actions) {
        let entry = &payload.groups[row.index];
        let shown = format!("{} (MultiExec group)", entry.name.trim());
        if *action == ItemAction::Skip {
            report.groups.count(*action);
            continue;
        }
        let (members, lost) = members_here(entry, payload, imported, sessions_here);
        if members.is_empty() {
            report.problems.push(ItemProblem {
                name: shown,
                reason:
                    "None of its sessions is here (they were skipped, or are not in the file), so it was not imported."
                        .to_owned(),
            });
            continue;
        }
        let mut input = GroupInput {
            name: entry.name.clone(),
            session_ids: members,
        };
        let result = match (action, row.local) {
            (ItemAction::Replace, Some(id)) => groups.update(ctx, id, input).await,
            (ItemAction::KeepBoth, _) => {
                let taken: HashSet<String> = groups.list(ctx).await?.iter().map(|g| g.name.to_lowercase()).collect();
                input.name = free_name(entry.name.trim(), &taken, MAX_NAME);
                groups.create(ctx, input).await
            }
            _ => groups.create(ctx, input).await,
        };
        match result {
            Ok(_) => {
                report.groups.count(*action);
                if !lost.is_empty() {
                    let names: Vec<String> = lost
                        .iter()
                        .map(|id| {
                            payload
                                .sessions
                                .iter()
                                .find(|s| s.id == *id)
                                .map_or_else(|| "a session not in the file".to_owned(), |s| s.name.clone())
                        })
                        .collect();
                    report.problems.push(ItemProblem {
                        name: shown,
                        reason: format!(
                            "Saved without {} that {} not imported: {}.",
                            plural(lost.len(), "session"),
                            if lost.len() == 1 { "was" } else { "were" },
                            listed(&names)
                        ),
                    });
                }
            }
            Err(err) => report.problems.push(ItemProblem {
                name: shown,
                reason: err.to_string(),
            }),
        }
    }
    Ok(())
}
