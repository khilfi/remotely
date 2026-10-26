//! FD-07 for stacks (VM-08), as part of the catalogue's section: each stack by name, its steps naming their launch
//! templates by their id in the file and by name. Instances stay out: they are this PC's own VMs.
//!
//! * A stack matches one here by name: the same (description and steps, templates by name) or a conflict the user
//!   decides (skip, replace, keep both).
//! * On import each step's template is the one the file's template became here (imported, replaced, or the one here it
//!   matched), else a template here of the same name; one that is neither stays named, and the stack says it can't
//!   deploy until it gets one.
//!
//! Saving goes through [`crate::stacks::import_stack`], which checks and audits it as imported.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{free_name, item, Counts, ItemAction, ItemProblem, PreviewItem, RowPlan, CONFLICT_CHOICES};
use crate::domain::Context;
use crate::error::Result;
use crate::stacks::{StackInput, StackStep};
use crate::store::{StackRow, Store, TemplateRow};

/// One step in the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StepEntry {
    #[serde(flatten)]
    step: StackStep,
    /// The template's name on the exporting laptop, so one not in the file is found here by name.
    #[serde(default)]
    template_name: Option<String>,
}

/// One stack in the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StackEntry {
    name: String,
    #[serde(default)]
    description: Option<String>,
    steps: Vec<StepEntry>,
}

impl StackEntry {
    pub(super) fn name(&self) -> &str {
        &self.name
    }
}

/// Every stack of this workspace, for an export.
pub(super) async fn export(store: &Store, ctx: &Context) -> Result<Vec<StackEntry>> {
    let templates = store.list_catalog_templates(ctx).await?;
    let name_of = |id: Uuid| templates.iter().find(|t| t.id == id).map(|t| t.spec.name.clone());
    Ok(store
        .list_stacks(ctx)
        .await?
        .into_iter()
        .map(|row| StackEntry {
            name: row.input.name,
            description: row.input.description,
            steps: row
                .input
                .steps
                .into_iter()
                .map(|step| StepEntry {
                    template_name: name_of(step.template_id),
                    step,
                })
                .collect(),
        })
        .collect())
}

/// A step's template, by name: the file's template's name, else the name the step carries.
fn template_name(step: &StepEntry, file_templates: &HashMap<Uuid, String>) -> Option<String> {
    file_templates
        .get(&step.step.template_id)
        .cloned()
        .or_else(|| step.template_name.clone())
}

/// What a stack's steps are, in words: `'db' x1 -> 'web' x2`.
fn steps_text(steps: &[(Option<String>, u32)]) -> String {
    steps
        .iter()
        .map(|(name, count)| format!("'{}' x{count}", name.as_deref().unwrap_or("a template not in the file")))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Each stack of the file compared with the stacks here, by name.
pub(super) fn plan(
    file: &[StackEntry],
    here: &[StackRow],
    file_templates: &HashMap<Uuid, String>,
    templates_here: &[TemplateRow],
) -> Vec<RowPlan<Uuid>> {
    let here_name = |id: Uuid| {
        templates_here
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.spec.name.to_lowercase())
    };
    file.iter()
        .enumerate()
        .map(|(index, e)| {
            let Some(l) = here.iter().find(|l| l.input.name.eq_ignore_ascii_case(e.name.trim())) else {
                return RowPlan::new(index);
            };
            let same_steps = e.steps.len() == l.input.steps.len()
                && e.steps.iter().zip(&l.input.steps).all(|(f, h)| {
                    template_name(f, file_templates).map(|n| n.to_lowercase()) == here_name(h.template_id)
                        && StackStep {
                            template_id: h.template_id,
                            ..f.step.clone()
                        } == *h
                });
            let same_text = e.description.as_deref().map(str::trim) == l.input.description.as_deref();
            if same_steps && same_text {
                RowPlan::same(index, l.id, "Already here.".into())
            } else {
                RowPlan::conflict(
                    index,
                    l.id,
                    format!("A stack named '{}' is here, with other steps.", l.input.name),
                    CONFLICT_CHOICES.to_vec(),
                )
            }
        })
        .collect()
}

/// The preview's rows: each stack's steps, and a note for a template neither in the file nor here.
pub(super) fn preview(
    file: &[StackEntry],
    rows: Vec<RowPlan<Uuid>>,
    file_templates: &HashMap<Uuid, String>,
    templates_here: &[TemplateRow],
) -> Vec<PreviewItem> {
    rows.into_iter()
        .map(|row| {
            let e = &file[row.index];
            let steps: Vec<(Option<String>, u32)> = e
                .steps
                .iter()
                .map(|s| (template_name(s, file_templates), s.step.count))
                .collect();
            let mut notes = Vec::new();
            for (i, step) in e.steps.iter().enumerate() {
                let in_file = file_templates.contains_key(&step.step.template_id);
                let here = template_name(step, file_templates).is_some_and(|name| {
                    templates_here.iter().any(|t| t.spec.name.eq_ignore_ascii_case(&name))
                });
                if !in_file && !here {
                    notes.push(format!(
                        "Step {}'s launch template isn't in the file or here, so the stack can't deploy until it gets one.",
                        i + 1
                    ));
                }
            }
            notes.push("Its instances (the VMs it deployed) stay on the other laptop.".into());
            item(row, e.name.trim().to_owned(), steps_text(&steps), notes)
        })
        .collect()
}

/// Imports the user's choices, each step pointing at the template its file template became here (`template_map`), or
/// one here of the same name.
pub(super) async fn commit(
    store: &Store,
    ctx: &Context,
    file: &[StackEntry],
    decided: Vec<(RowPlan<Uuid>, ItemAction)>,
    file_templates: &HashMap<Uuid, String>,
    template_map: &HashMap<Uuid, Uuid>,
    problems: &mut Vec<ItemProblem>,
) -> Result<Counts> {
    let mut counts = Counts::default();
    let templates_here = store.list_catalog_templates(ctx).await?;
    for (row, action) in decided {
        let e = &file[row.index];
        if action == ItemAction::Skip {
            counts.count(action);
            continue;
        }
        let steps = e
            .steps
            .iter()
            .map(|s| {
                let here = template_map.get(&s.step.template_id).copied().or_else(|| {
                    let name = template_name(s, file_templates)?;
                    templates_here
                        .iter()
                        .find(|t| t.spec.name.eq_ignore_ascii_case(&name))
                        .map(|t| t.id)
                });
                StackStep {
                    template_id: here.unwrap_or(s.step.template_id),
                    ..s.step.clone()
                }
            })
            .collect();
        let mut input = StackInput {
            name: e.name.clone(),
            description: e.description.clone(),
            steps,
        };
        let replace = match action {
            ItemAction::Replace => row.local,
            ItemAction::KeepBoth => {
                let taken: HashSet<String> = store
                    .list_stacks(ctx)
                    .await?
                    .iter()
                    .map(|s| s.input.name.to_lowercase())
                    .collect();
                input.name = free_name(e.name.trim(), &taken, crate::stacks::spec::MAX_NAME);
                None
            }
            _ => None,
        };
        match crate::stacks::import_stack(store, ctx, replace, input).await {
            Ok(_) => counts.count(action),
            Err(err) => problems.push(ItemProblem {
                name: format!("stack '{}'", e.name),
                reason: err.to_string(),
            }),
        }
    }
    Ok(counts)
}
