//! VM-08, AP-02: what the approval dialog (and the stack deploy dialog before it) shows for a stack command: the
//! instance, its steps in the order they run with each step's VMs, the readiness check and delay between steps,
//! each step's deploy preview (R2: names, folders, size, disk space, network), and for a teardown the VMs it keeps.
//! Reads only.

use std::collections::HashMap;

use serde::Serialize;

use super::spec::{KeptVm, Readiness, StackOp};
use crate::adapters::host_counters::HostCounters;
use crate::adapters::hypervisor::Hypervisors;
use crate::command_bus::PowerOp;
use crate::deploy::preview::{preview, DeployPreview};
use crate::domain::Target;

/// What a stack command does to its instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StackAction {
    Deploy,
    Start,
    ShutDown,
    Suspend,
    Teardown,
}

/// One step, in the order the job runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepDetails {
    pub label: String,
    /// Its VMs' names.
    pub vms: Vec<String>,
    /// What the next step waits for (starting only).
    pub readiness: Readiness,
    pub ready_timeout_secs: u32,
    pub delay_secs: u32,
    /// A deploy's preview of this step (R2).
    pub deploy: Option<DeployPreview>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackDetails {
    pub action: StackAction,
    pub instance_name: String,
    pub stack_name: Option<String>,
    pub steps: Vec<StepDetails>,
    /// A teardown: the instance's VMs it leaves, and why.
    pub kept: Vec<KeptVm>,
    /// A deploy: what all its VMs may take, thin disks at their full size, and the thick part.
    pub disk_bytes: u64,
    pub thick_bytes: u64,
    /// A deploy: each step's warnings and refusals, named by step.
    pub warnings: Vec<String>,
    pub refusals: Vec<String>,
}

/// The details of `op` on `targets` (the targets after the policy engine's look-up: names, and protected ones left
/// out).
pub async fn stack_details(
    op: &StackOp,
    targets: &[Target],
    hypervisors: &Hypervisors,
    host: &dyn HostCounters,
) -> StackDetails {
    let names: HashMap<String, &str> = targets
        .iter()
        .map(|t| (t.target.key(), t.name.as_str()))
        .collect();
    match op {
        StackOp::Deploy { spec } => {
            let mut steps = Vec::with_capacity(spec.steps.len());
            let (mut disk, mut thick) = (0u64, 0u64);
            let mut warnings = Vec::new();
            let mut refusals = Vec::new();
            let many = spec.steps.len() > 1;
            for (i, step) in spec.steps.iter().enumerate() {
                let shown = preview(&step.spec, hypervisors, host).await;
                disk = disk.saturating_add(shown.disk_bytes);
                thick = thick.saturating_add(shown.thick_bytes);
                let named = |text: &String| {
                    if many {
                        format!("Step {} ('{}'): {text}", i + 1, step.label)
                    } else {
                        text.clone()
                    }
                };
                warnings.extend(shown.warnings.iter().map(named));
                refusals.extend(shown.refusals.iter().map(named));
                steps.push(StepDetails {
                    label: step.label.clone(),
                    vms: step.spec.vms.iter().map(|v| v.name.clone()).collect(),
                    readiness: step.readiness,
                    ready_timeout_secs: step.ready_timeout_secs,
                    delay_secs: step.delay_secs,
                    deploy: Some(shown),
                });
            }
            StackDetails {
                action: StackAction::Deploy,
                instance_name: spec.instance_name.clone(),
                stack_name: Some(spec.stack_name.clone()),
                steps,
                kept: Vec::new(),
                disk_bytes: disk,
                thick_bytes: thick,
                warnings,
                refusals,
            }
        }
        StackOp::Power { spec } => {
            let action = match spec.op {
                PowerOp::Start { .. } => StackAction::Start,
                PowerOp::Suspend => StackAction::Suspend,
                _ => StackAction::ShutDown,
            };
            let starts = action == StackAction::Start;
            StackDetails {
                action,
                instance_name: spec.instance_name.clone(),
                stack_name: None,
                steps: spec
                    .steps
                    .iter()
                    .map(|s| StepDetails {
                        label: s.label.clone(),
                        // Protected VMs are left out by the policy engine, so only those that run are named.
                        vms: s.vms.iter().filter_map(|k| names.get(k).map(|n| (*n).to_owned())).collect(),
                        readiness: if starts { s.readiness } else { Readiness::None },
                        ready_timeout_secs: s.ready_timeout_secs,
                        delay_secs: if starts { s.delay_secs } else { 0 },
                        deploy: None,
                    })
                    .collect(),
                kept: Vec::new(),
                disk_bytes: 0,
                thick_bytes: 0,
                warnings: Vec::new(),
                refusals: Vec::new(),
            }
        }
        StackOp::Teardown { spec } => StackDetails {
            action: StackAction::Teardown,
            instance_name: spec.instance_name.clone(),
            stack_name: Some(spec.stack_name.clone()),
            steps: vec![StepDetails {
                label: "Delete".into(),
                vms: targets.iter().map(|t| t.name.clone()).collect(),
                readiness: Readiness::None,
                ready_timeout_secs: 0,
                delay_secs: 0,
                deploy: None,
            }],
            kept: spec.kept.clone(),
            disk_bytes: 0,
            thick_bytes: 0,
            warnings: Vec::new(),
            refusals: Vec::new(),
        },
    }
}
