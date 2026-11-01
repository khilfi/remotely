//! VM-08 (R6): stacks. A stack is a named set of launch templates, each with a count, in boot order, with a
//! readiness check (the guest tools running, or a port open) and a delay between steps. Deploying one makes a stack
//! instance: one job through R2's deploy, one AP-02 preview listing every VM, one approval and its tier (a deploy of
//! all its VMs), and the steps made in boot order. The instance records which VMs it holds, so they show as a group,
//! start and stop together in boot order (through the power commands' own work and tiers), and its teardown deletes
//! exactly those (R3's delete, Critical; protected VMs and VMs added by hand are never deleted silently).
//!
//! * [`spec`]: what a stack is and what [`crate::command_bus::Command::Stack`] carries.
//! * [`preview`]: the approval dialog's details of a stack command.
//! * [`runner`]: what the job runner calls between steps (readiness, delays) and the instance's records.
//!
//! Stacks are the app's own data, like the catalogue: edits skip the bus, are audited (`stack_changed`, no tier),
//! refused by the read-only lock ([`Change::Stacks`]) and carried by FD-07 (`transfer::stacks`). Every change to a
//! VM is a command on the bus.

pub mod preview;
pub mod runner;
pub mod spec;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use self::preview::{StackAction, StackDetails, StepDetails};
pub use self::runner::{ReadyOutcome, StackActions, StackClock, StackRunner, StackTuning, SystemStackClock};
pub use self::spec::{
    check_stack, InstanceStep, KeptVm, NamedVm, PowerStep, Readiness, StackDeploySpec, StackInput, StackOp,
    StackPowerSpec, StackStep, StackStepRun, StackTag, StackTeardownSpec,
};
use crate::adapters::host_counters::HostCounters;
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vmware::path_key;
use crate::capacity_plan::DeployCapacity;
use crate::catalog::images::ImageKind;
use crate::catalog::templates::Network;
use crate::catalog::{Catalog, LaunchTemplate, ProblemCode};
use crate::command_bus::{Command, CommandBus, PowerOp, SubmitOutcome};
use crate::deploy::service::{DeployFrom, DeployRequest, Deploys};
use crate::domain::{Context, Environment, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{InstanceRow, MemberOrigin, NewAuditEntry, Store, VmRecord};

/// How the audit log names a stack change.
pub(crate) const EVENT: &str = "stack_changed";

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// A step as the Stacks tab shows it: what it names, and why it can't deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackStepView {
    #[serde(flatten)]
    pub step: StackStep,
    /// `None` when the template is gone.
    pub template_name: Option<String>,
    pub hypervisor: Option<Hypervisor>,
    pub problems: Vec<String>,
}

/// A saved stack, with why it can't deploy (empty when it can).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stack {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<StackStepView>,
    pub vm_count: u32,
    /// Its instances on this PC.
    pub instances: usize,
    pub problems: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// The editor's live check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackCheck {
    /// Why it can't be saved (it isn't valid).
    pub invalid: Option<String>,
    /// Why it couldn't deploy now (it can be saved anyway).
    pub problems: Vec<String>,
    pub vm_count: u32,
}

/// One VM of an instance, as it is now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceVm {
    pub key: String,
    pub name: String,
    /// From 0: the first to boot.
    pub step: u32,
    pub origin: MemberOrigin,
    /// `None` when the VM isn't on this PC any more.
    pub power_state: Option<PowerState>,
    pub protected: bool,
    pub environment: Environment,
}

/// A stack instance, as the VMs page and the Stacks tab show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackInstance {
    pub id: Uuid,
    pub stack_id: Uuid,
    pub stack_name: String,
    pub name: String,
    pub steps: Vec<InstanceStep>,
    pub job_id: Option<Uuid>,
    pub created_at: String,
    /// In step order.
    pub vms: Vec<InstanceVm>,
}

/// What the stack deploy dialog sends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackDeployRequest {
    pub stack_id: Uuid,
    /// `None`: `<stack name> <n>`, numbered past the instances here.
    #[serde(default)]
    pub instance_name: Option<String>,
}

/// The stack deploy dialog's answer: why it can't deploy, or its preview and this PC after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackDeployCheck {
    pub problems: Vec<String>,
    pub instance_name: String,
    pub details: Option<StackDetails>,
    /// VM-26.
    pub capacity: Option<DeployCapacity>,
}

/// The stacks service (`Core.stacks`).
#[derive(Clone)]
pub struct Stacks {
    store: Store,
    catalog: Catalog,
    deploys: Deploys,
    hypervisors: Hypervisors,
    host: Arc<dyn HostCounters>,
    bus: Arc<CommandBus>,
    /// Read again before an instance starts, stops or goes, so VMs already in that state are left alone.
    inventory: Arc<crate::inventory::Inventory>,
}

/// `'a', 'b' and 3 more`.
fn listed(names: &[String]) -> String {
    let shown: Vec<String> = names.iter().take(5).map(|n| format!("'{n}'")).collect();
    let more = names.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// Why each step of `input` couldn't deploy now: its template gone or unable to deploy, a count its naming pattern
/// can't name, or a readiness check that can't pass.
fn step_problems(
    input: &StackInput,
    templates: &[LaunchTemplate],
    image_kind: &dyn Fn(Uuid) -> Option<ImageKind>,
) -> Vec<StackStepView> {
    input
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let n = i + 1;
            let template = templates.iter().find(|t| t.id == step.template_id);
            let mut problems = Vec::new();
            match template {
                None => problems.push(format!("Step {n}: its launch template was deleted.")),
                Some(t) => {
                    let name = &t.spec.name;
                    for p in &t.problems {
                        // The step's own count is checked below, not the template's default.
                        if p.code != ProblemCode::PatternNeedsNumber {
                            problems.push(format!("Step {n} ('{name}'): {}", p.message));
                        }
                    }
                    if step.count > 1 && !crate::catalog::templates::pattern_numbers(&t.spec.naming_pattern) {
                        problems.push(format!(
                            "Step {n} ('{name}'): its naming pattern has no {{n}}, so it names one VM only; add {{n}} to make {}.",
                            step.count
                        ));
                    }
                    if i + 1 < input.steps.len() && !step.readiness.is_none() {
                        if image_kind(t.spec.image_id) == Some(ImageKind::Iso) {
                            problems.push(format!(
                                "Step {n} ('{name}') boots an ISO with no OS yet, so its readiness check can't pass: set it to nothing."
                            ));
                        } else if matches!(step.readiness, Readiness::SshPort { .. })
                            && t.spec.hypervisor == Hypervisor::VirtualBox
                            && t.spec.network == Network::Nat
                        {
                            problems.push(format!(
                                "Step {n} ('{name}'): on VirtualBox's NAT the guest's port can't be reached from this PC; use a host-only network, or wait for the Guest Additions instead."
                            ));
                        }
                    }
                }
            }
            StackStepView {
                step: step.clone(),
                template_name: template.map(|t| t.spec.name.clone()),
                hypervisor: template.map(|t| t.spec.hypervisor),
                problems,
            }
        })
        .collect()
}

/// The VMs on this PC, by [`path_key`].
fn by_key(vms: &[VmRecord]) -> HashMap<String, &VmRecord> {
    vms.iter().map(|vm| (path_key(Path::new(&vm.vmx_path)), vm)).collect()
}

impl Stacks {
    pub fn new(
        store: Store,
        catalog: Catalog,
        deploys: Deploys,
        hypervisors: Hypervisors,
        host: Arc<dyn HostCounters>,
        bus: Arc<CommandBus>,
        inventory: Arc<crate::inventory::Inventory>,
    ) -> Self {
        Self {
            store,
            catalog,
            deploys,
            hypervisors,
            host,
            bus,
            inventory,
        }
    }

    /// The VM list as the hypervisors have it now; when they can't be asked, as the last refresh saw it.
    async fn refresh(&self, ctx: &Context) {
        if let Err(err) = self.inventory.refresh(ctx).await {
            tracing::debug!(error = %err, "the VM list couldn't be read again before a stack instance's action");
        }
    }

    async fn image_kinds(&self, ctx: &Context) -> Result<HashMap<Uuid, ImageKind>> {
        Ok(self
            .catalog
            .images(ctx)
            .await?
            .into_iter()
            .map(|i| (i.id, i.kind()))
            .collect())
    }

    async fn view(
        &self,
        row: crate::store::StackRow,
        templates: &[LaunchTemplate],
        kinds: &HashMap<Uuid, ImageKind>,
        instances: &[InstanceRow],
    ) -> Stack {
        let steps = step_problems(&row.input, templates, &|id| kinds.get(&id).copied());
        Stack {
            id: row.id,
            vm_count: row.input.vm_count(),
            name: row.input.name,
            description: row.input.description,
            problems: steps.iter().flat_map(|s| s.problems.clone()).collect(),
            steps,
            instances: instances.iter().filter(|i| i.stack_id == row.id).count(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    /// Every stack, by name, each with why it can't deploy now.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<Stack>> {
        let rows = self.store.list_stacks(ctx).await?;
        let templates = self.catalog.templates(ctx).await?;
        let kinds = self.image_kinds(ctx).await?;
        let instances = self.store.list_stack_instances(ctx).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(self.view(row, &templates, &kinds, &instances).await);
        }
        Ok(out)
    }

    pub async fn get(&self, ctx: &Context, id: Uuid) -> Result<Stack> {
        let row = self.row(ctx, id).await?;
        let templates = self.catalog.templates(ctx).await?;
        let kinds = self.image_kinds(ctx).await?;
        let instances = self.store.list_stack_instances(ctx).await?;
        Ok(self.view(row, &templates, &kinds, &instances).await)
    }

    async fn row(&self, ctx: &Context, id: Uuid) -> Result<crate::store::StackRow> {
        self.store
            .stack(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("stack {id}")))
    }

    /// The editor's check while a stack is filled in. A read.
    pub async fn check(&self, ctx: &Context, input: &StackInput) -> Result<StackCheck> {
        let checked = match check_stack(input) {
            Ok(checked) => checked,
            Err(err) => {
                return Ok(StackCheck {
                    invalid: Some(err.to_string()),
                    problems: Vec::new(),
                    vm_count: input.vm_count(),
                })
            }
        };
        let templates = self.catalog.templates(ctx).await?;
        let kinds = self.image_kinds(ctx).await?;
        let steps = step_problems(&checked, &templates, &|id| kinds.get(&id).copied());
        Ok(StackCheck {
            invalid: None,
            problems: steps.into_iter().flat_map(|s| s.problems).collect(),
            vm_count: checked.vm_count(),
        })
    }

    /// What a stack's steps say in the audit log.
    fn describe(input: &StackInput, templates: &[LaunchTemplate]) -> String {
        let steps: Vec<String> = input
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let name = templates
                    .iter()
                    .find(|t| t.id == s.template_id)
                    .map_or_else(|| "(deleted)".to_owned(), |t| format!("'{}'", t.spec.name));
                let mut text = format!("step {}: {name} x{}", i + 1, s.count);
                if i + 1 < input.steps.len() {
                    if !s.readiness.is_none() {
                        text.push_str(&format!(", then waits for {}", s.readiness.describe()));
                    }
                    if s.delay_secs > 0 {
                        text.push_str(&format!(", then {} s", s.delay_secs));
                    }
                }
                text
            })
            .collect();
        steps.join("; ")
    }

    pub async fn add(&self, ctx: &Context, input: StackInput) -> Result<Stack> {
        self.store.read_only().check(Change::Stacks)?;
        self.save(ctx, None, input, "Added").await
    }

    pub async fn update(&self, ctx: &Context, id: Uuid, input: StackInput) -> Result<Stack> {
        self.store.read_only().check(Change::Stacks)?;
        self.save(ctx, Some(id), input, "Changed").await
    }

    /// Saves a new stack, or one over `id`; checked, named once, audited.
    async fn save(&self, ctx: &Context, id: Option<Uuid>, input: StackInput, verb: &str) -> Result<Stack> {
        let checked = check_stack(&input)?;
        let rows = self.store.list_stacks(ctx).await?;
        if rows
            .iter()
            .any(|r| r.input.name.eq_ignore_ascii_case(&checked.name) && Some(r.id) != id)
        {
            return invalid(format!("A stack named '{}' exists already.", checked.name));
        }
        let templates = self.catalog.templates(ctx).await?;
        let id = match id {
            Some(id) => {
                let before = rows
                    .iter()
                    .find(|r| r.id == id)
                    .ok_or_else(|| CoreError::UnknownTarget(format!("stack {id}")))?;
                if before.input == checked {
                    return self.get(ctx, id).await;
                }
                self.store.update_stack(ctx, id, &checked).await?;
                id
            }
            None => {
                if rows.len() >= spec::MAX_STACKS {
                    return invalid(format!("A workspace keeps at most {} stacks.", spec::MAX_STACKS));
                }
                let id = Uuid::new_v4();
                self.store.insert_stack(ctx, id, &checked).await?;
                id
            }
        };
        self.audit(
            ctx,
            &format!("{verb} the stack '{}'", checked.name),
            &Self::describe(&checked, &templates),
            &[],
        )
        .await?;
        self.get(ctx, id).await
    }

    /// Its instances stay: they are VMs on this PC, and keep the stack's name.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Stacks)?;
        let row = self.row(ctx, id).await?;
        // QL-27: into the trash, in one transaction with the delete.
        let item = crate::trash::TrashItem {
            kind: crate::trash::TrashKind::Stack,
            item_id: &id.to_string(),
            name: &row.input.name,
            place: "Templates › Stacks".to_owned(),
            sent: None,
        };
        if crate::trash::move_to_trash(&self.store, ctx, item).await?.is_none() {
            return Err(CoreError::UnknownTarget(format!("stack {id}")));
        }
        self.audit(
            ctx,
            &format!("Deleted the stack '{}'", row.input.name),
            &format!("moved to the trash for {} days", crate::trash::KEEP_DAYS),
            &[],
        )
        .await
    }

    // ---- Deploy ---------------------------------------------------------------------------------------------------

    /// `<stack> <n>`, numbered past the instances here.
    fn default_instance_name(stack: &str, instances: &[InstanceRow]) -> String {
        let taken: HashSet<String> = instances.iter().map(|i| i.name.to_lowercase()).collect();
        let base: String = stack.chars().take(spec::MAX_NAME - 4).collect();
        (1..)
            .map(|n| format!("{base} {n}"))
            .find(|name| !taken.contains(&name.to_lowercase()))
            .unwrap_or(base)
    }

    /// The deploy a request makes, with the instance's name; or why it can't.
    async fn deploy_spec(
        &self,
        ctx: &Context,
        request: &StackDeployRequest,
    ) -> Result<(String, std::result::Result<StackDeploySpec, Vec<String>>)> {
        let row = self.row(ctx, request.stack_id).await?;
        let stack = self.get(ctx, request.stack_id).await?;
        let instances = self.store.list_stack_instances(ctx).await?;
        let instance_name = match request
            .instance_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            Some(name) => spec::check_name(name, "instance")?,
            None => Self::default_instance_name(&row.input.name, &instances),
        };
        let mut problems = stack.problems.clone();
        if instances.iter().any(|i| i.name.eq_ignore_ascii_case(&instance_name)) {
            problems.push(format!("A stack instance named '{instance_name}' is here already."));
        }
        if !problems.is_empty() {
            return Ok((instance_name, Err(problems)));
        }
        let instance_id = Uuid::new_v4();
        let mut steps = Vec::with_capacity(row.input.steps.len());
        let mut taken: Vec<String> = Vec::new();
        for (i, (step, view)) in row.input.steps.iter().zip(&stack.steps).enumerate() {
            let label = view.template_name.clone().unwrap_or_default();
            let deploy = DeployRequest {
                from: DeployFrom::Template { id: step.template_id },
                count: step.count,
                naming_pattern: None,
                host_adapter: None,
                guest_password_id: None,
            };
            match self.deploys.spec_for_taken(ctx, &deploy, &taken).await? {
                Ok(mut spec) => {
                    spec.stack = Some(StackTag {
                        instance_id,
                        step: i as u32,
                    });
                    taken.extend(spec.vms.iter().map(|v| v.name.clone()));
                    steps.push(StackStepRun {
                        label,
                        template_id: step.template_id,
                        spec,
                        readiness: step.readiness,
                        ready_timeout_secs: step.ready_timeout_secs,
                        delay_secs: step.delay_secs,
                    });
                }
                Err(found) => problems.extend(
                    found
                        .into_iter()
                        .map(|p| format!("Step {} ('{label}'): {}", i + 1, p.message)),
                ),
            }
        }
        if !problems.is_empty() {
            return Ok((instance_name, Err(problems)));
        }
        let spec = StackDeploySpec {
            stack_id: row.id,
            stack_name: row.input.name.clone(),
            instance_id,
            instance_name: instance_name.clone(),
            steps,
        };
        spec.validate()?;
        Ok((instance_name, Ok(spec)))
    }

    /// The stack's preview and this PC after it.
    async fn preview(&self, ctx: &Context, spec: &StackDeploySpec) -> (StackDetails, DeployCapacity) {
        let op = StackOp::Deploy {
            spec: Box::new(spec.clone()),
        };
        let details = preview::stack_details(&op, &[], &self.hypervisors, self.host.as_ref()).await;
        let demands: Vec<crate::capacity_plan::VmDemand> = spec
            .steps
            .iter()
            .zip(&details.steps)
            .filter_map(|(step, shown)| {
                shown
                    .deploy
                    .as_ref()
                    .map(|p| crate::capacity_plan::deploy_demands(&step.spec, p))
            })
            .flatten()
            .collect();
        let capacity = self.deploys.plan_capacity(ctx, &demands).await;
        (details, capacity)
    }

    /// The stack deploy dialog's check: why it can't deploy, or its AP-02 preview and VM-26's plan. A read.
    pub async fn check_deploy(&self, ctx: &Context, request: &StackDeployRequest) -> Result<StackDeployCheck> {
        let (instance_name, spec) = self.deploy_spec(ctx, request).await?;
        match spec {
            Err(problems) => Ok(StackDeployCheck {
                problems,
                instance_name,
                details: None,
                capacity: None,
            }),
            Ok(spec) => {
                for step in &spec.steps {
                    step.spec.require_sources_here(&self.store, ctx).await?;
                }
                let (details, capacity) = self.preview(ctx, &spec).await;
                Ok(StackDeployCheck {
                    problems: Vec::new(),
                    instance_name,
                    details: Some(details),
                    capacity: Some(capacity),
                })
            }
        }
    }

    /// Submits the stack's deploy to the bus: one approval (a deploy of all its VMs), then one job.
    pub async fn deploy(&self, ctx: &Context, request: &StackDeployRequest) -> Result<SubmitOutcome> {
        let (_, spec) = self.deploy_spec(ctx, request).await?;
        let spec = match spec {
            Ok(spec) => spec,
            Err(problems) => return invalid(problems.join(" ")),
        };
        for step in &spec.steps {
            step.spec.require_sources_here(&self.store, ctx).await?;
        }
        let (details, _) = self.preview(ctx, &spec).await;
        if !details.refusals.is_empty() {
            return invalid(details.refusals.join(" "));
        }
        self.bus
            .submit(
                ctx,
                Command::Stack {
                    targets: spec.targets(),
                    op: StackOp::Deploy { spec: Box::new(spec) },
                },
            )
            .await
    }

    // ---- Instances ------------------------------------------------------------------------------------------------

    fn instance_view(row: InstanceRow, vms: &HashMap<String, &VmRecord>) -> StackInstance {
        StackInstance {
            vms: row
                .members
                .iter()
                .map(|m| {
                    let vm = vms.get(&path_key(Path::new(&m.vm_key)));
                    InstanceVm {
                        key: vm.map_or_else(|| m.vm_key.clone(), |v| v.vmx_path.clone()),
                        name: vm.map_or_else(|| m.vm_name.clone(), |v| v.display_name.clone()),
                        step: m.step,
                        origin: m.origin,
                        power_state: vm.map(|v| v.power_state),
                        protected: vm.is_some_and(|v| v.protected),
                        environment: vm.map(|v| v.environment).unwrap_or_default(),
                    }
                })
                .collect(),
            id: row.id,
            stack_id: row.stack_id,
            stack_name: row.stack_name,
            name: row.name,
            steps: row.steps,
            job_id: row.job_id,
            created_at: row.created_at,
        }
    }

    /// Every instance on this PC, newest first, each VM as the VM list has it now.
    pub async fn instances(&self, ctx: &Context) -> Result<Vec<StackInstance>> {
        let rows = self.store.list_stack_instances(ctx).await?;
        let vms = self.store.list_vms(ctx).await?;
        let known = by_key(&vms);
        Ok(rows.into_iter().map(|r| Self::instance_view(r, &known)).collect())
    }

    pub async fn instance(&self, ctx: &Context, id: Uuid) -> Result<StackInstance> {
        let row = self
            .store
            .stack_instance(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("stack instance {id}")))?;
        let vms = self.store.list_vms(ctx).await?;
        Ok(Self::instance_view(row, &by_key(&vms)))
    }

    /// R7 (VM-14, VM-27): the VMs of every instance of a stack, each once, as (key, name); gone ones left out.
    pub async fn stack_vms(&self, ctx: &Context, stack_id: Uuid) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        for instance in self.instances(ctx).await? {
            if instance.stack_id != stack_id {
                continue;
            }
            out.extend(
                instance
                    .vms
                    .into_iter()
                    .filter(|v| v.power_state.is_some())
                    .map(|v| (v.key, v.name)),
            );
        }
        Ok(out)
    }

    fn target_of(vm: &InstanceVm) -> Target {
        Target {
            target: TargetRef::Vm {
                vmx_path: vm.key.clone(),
            },
            name: vm.name.clone(),
            environment: vm.environment,
            protected: vm.protected,
        }
    }

    /// Starts, shuts down or suspends the instance's VMs: starting in boot order with its readiness checks and
    /// delays, stopping the last step first. VMs already in that state are left alone, gone ones skipped.
    pub async fn power(&self, ctx: &Context, id: Uuid, op: PowerOp) -> Result<SubmitOutcome> {
        if !spec::instance_op_allowed(&op) {
            return invalid("A stack instance starts, shuts down or suspends as a whole.");
        }
        self.refresh(ctx).await;
        let instance = self.instance(ctx, id).await?;
        let starts = matches!(op, PowerOp::Start { .. });
        let applies = |state: PowerState| match op {
            PowerOp::Start { .. } => !state.is_on(),
            _ => state == PowerState::Running,
        };
        let count = instance
            .steps
            .len()
            .max(instance.vms.iter().map(|v| v.step as usize + 1).max().unwrap_or(0));
        let mut steps: Vec<PowerStep> = (0..count)
            .map(|i| {
                let here: Vec<&InstanceVm> = instance
                    .vms
                    .iter()
                    .filter(|v| v.step as usize == i && v.power_state.is_some())
                    .collect();
                let kept = instance.steps.get(i);
                PowerStep {
                    label: kept.map_or_else(|| format!("step {}", i + 1), |s| s.label.clone()),
                    vms: here
                        .iter()
                        .filter(|v| v.power_state.is_some_and(applies))
                        .map(|v| v.key.clone())
                        .collect(),
                    ready: here
                        .iter()
                        .map(|v| NamedVm {
                            key: v.key.clone(),
                            name: v.name.clone(),
                        })
                        .collect(),
                    readiness: if starts {
                        kept.map(|s| s.readiness).unwrap_or_default()
                    } else {
                        Readiness::None
                    },
                    ready_timeout_secs: kept.map_or(spec::DEFAULT_READY_TIMEOUT_SECS, |s| s.ready_timeout_secs),
                    delay_secs: if starts { kept.map_or(0, |s| s.delay_secs) } else { 0 },
                }
            })
            .collect();
        if !starts {
            steps.reverse();
        }
        let power = StackPowerSpec {
            instance_id: instance.id,
            instance_name: instance.name.clone(),
            op,
            steps,
        };
        let targets = power.targets();
        if targets.is_empty() {
            return invalid(if starts {
                format!("Every VM of '{}' is running already.", instance.name)
            } else {
                format!("No VM of '{}' is running.", instance.name)
            });
        }
        self.bus
            .submit(
                ctx,
                Command::Stack {
                    targets,
                    op: StackOp::Power { spec: Box::new(power) },
                },
            )
            .await
    }

    /// Tears the instance down: R3's delete on each VM its deploy made, and on the VMs added by hand that `also`
    /// names (by key) on purpose; the other hand-added VMs are kept and said so. Refused while a VM of it runs (shut
    /// it down first), as R3's delete is; protected VMs are left out by the policy engine (AP-04).
    pub async fn teardown(&self, ctx: &Context, id: Uuid, also: &[String]) -> Result<SubmitOutcome> {
        self.refresh(ctx).await;
        let instance = self.instance(ctx, id).await?;
        let also: HashSet<String> = also.iter().map(|k| path_key(Path::new(k))).collect();
        let mut targets = Vec::new();
        let mut kept = Vec::new();
        let mut running = Vec::new();
        for vm in &instance.vms {
            let picked = vm.origin == MemberOrigin::Deploy || also.contains(&path_key(Path::new(&vm.key)));
            match (vm.power_state, picked) {
                (None, _) => {}
                (Some(_), false) => kept.push(KeptVm {
                    key: vm.key.clone(),
                    name: vm.name.clone(),
                    why: "added to the instance by hand".into(),
                }),
                (Some(state), true) => {
                    if state.is_on() {
                        running.push(vm.name.clone());
                    }
                    targets.push(TargetRef::Vm {
                        vmx_path: vm.key.clone(),
                    });
                }
            }
        }
        if !running.is_empty() {
            return invalid(format!(
                "{} {} running: shut the instance down first, then tear it down.",
                listed(&running),
                if running.len() == 1 { "is" } else { "are" }
            ));
        }
        if targets.is_empty() {
            return invalid(format!(
                "'{}' has no VM its deploy made left to delete. Forget the instance to remove it from the list (its VMs stay).",
                instance.name
            ));
        }
        let teardown = StackTeardownSpec {
            instance_id: instance.id,
            instance_name: instance.name.clone(),
            stack_name: instance.stack_name.clone(),
            kept,
        };
        self.bus
            .submit(
                ctx,
                Command::Stack {
                    targets,
                    op: StackOp::Teardown {
                        spec: Box::new(teardown),
                    },
                },
            )
            .await
    }

    /// Adds a VM of this PC to the instance by hand, at `step` (from 0). It starts and stops with the instance, and a
    /// teardown keeps it unless it is picked on purpose. Audited; no tier (nothing in the VM changes).
    pub async fn add_vm(&self, ctx: &Context, id: Uuid, vm_key: &str, step: u32) -> Result<StackInstance> {
        self.store.read_only().check(Change::Stacks)?;
        self.store.require_vm_here(ctx, vm_key).await?;
        let instance = self.instance(ctx, id).await?;
        let vm = self
            .store
            .find_vm(ctx, vm_key)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(vm_key.to_owned()))?;
        let steps = instance.steps.len().max(1) as u32;
        if step >= steps {
            return invalid(format!("'{}' has {steps} step(s).", instance.name));
        }
        let key = path_key(Path::new(&vm.vmx_path));
        if instance.vms.iter().any(|v| path_key(Path::new(&v.key)) == key) {
            return invalid(format!("'{}' is in '{}' already.", vm.display_name, instance.name));
        }
        if let Some(other) = self
            .instances(ctx)
            .await?
            .into_iter()
            .find(|i| i.vms.iter().any(|v| path_key(Path::new(&v.key)) == key))
        {
            return invalid(format!(
                "'{}' is in the stack instance '{}': take it out there first.",
                vm.display_name, other.name
            ));
        }
        self.store
            .add_stack_vm(ctx, id, &vm.vmx_path, &vm.display_name, step, MemberOrigin::Hand)
            .await?;
        let target = Target {
            target: TargetRef::Vm {
                vmx_path: vm.vmx_path.clone(),
            },
            name: vm.display_name.clone(),
            environment: vm.environment,
            protected: vm.protected,
        };
        let label = instance
            .steps
            .get(step as usize)
            .map_or_else(String::new, |s| format!(" ('{}')", s.label));
        self.audit(
            ctx,
            &format!("Added '{}' to the stack instance '{}'", vm.display_name, instance.name),
            &format!(
                "by hand, at step {}{label}; a teardown keeps it unless it is picked",
                step + 1
            ),
            &[target],
        )
        .await?;
        self.instance(ctx, id).await
    }

    /// Takes a VM out of the instance; the VM itself stays as it is. Audited.
    pub async fn remove_vm(&self, ctx: &Context, id: Uuid, vm_key: &str) -> Result<StackInstance> {
        self.store.read_only().check(Change::Stacks)?;
        let instance = self.instance(ctx, id).await?;
        let key = path_key(Path::new(vm_key));
        let vm = instance
            .vms
            .iter()
            .find(|v| path_key(Path::new(&v.key)) == key)
            .ok_or_else(|| CoreError::InvalidInput("That VM isn't in this stack instance.".into()))?;
        self.store.remove_stack_vm(ctx, &vm.key).await?;
        let made = match vm.origin {
            MemberOrigin::Deploy => "its deploy made it",
            MemberOrigin::Hand => "it was added by hand",
        };
        self.audit(
            ctx,
            &format!("Took '{}' out of the stack instance '{}'", vm.name, instance.name),
            &format!("{made}; the VM stays, and a teardown of the instance won't delete it"),
            &[Self::target_of(vm)],
        )
        .await?;
        self.instance(ctx, id).await
    }

    /// Forgets the instance: its VMs stay as they are, in no instance. Audited.
    pub async fn forget_instance(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Stacks)?;
        let instance = self.instance(ctx, id).await?;
        self.store.delete_stack_instance(ctx, id).await?;
        let names: Vec<String> = instance.vms.iter().map(|v| v.name.clone()).collect();
        let targets: Vec<Target> = instance
            .vms
            .iter()
            .filter(|v| v.power_state.is_some())
            .map(Self::target_of)
            .collect();
        self.audit(
            ctx,
            &format!("Forgot the stack instance '{}'", instance.name),
            &if names.is_empty() {
                "it had no VMs".to_owned()
            } else {
                format!("its VMs stay: {}", listed(&names))
            },
            &targets,
        )
        .await
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: &str, targets: &[Target]) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: EVENT,
                    action,
                    tier: None,
                    job_id: None,
                    targets,
                    approval: None,
                    result: None,
                    detail: Some(detail).filter(|d| !d.is_empty()),
                },
            )
            .await
            .map(drop)
    }
}

/// FD-07: a stack from an export, new or over `replace`, its templates already mapped to this laptop's (one that
/// isn't here stays named, and the stack says it can't deploy). Checked, named once, and audited as imported.
pub(crate) async fn import_stack(
    store: &Store,
    ctx: &Context,
    replace: Option<Uuid>,
    input: StackInput,
) -> Result<Uuid> {
    let checked = check_stack(&input)?;
    let rows = store.list_stacks(ctx).await?;
    if rows
        .iter()
        .any(|r| r.input.name.eq_ignore_ascii_case(&checked.name) && Some(r.id) != replace)
    {
        return invalid(format!("A stack named '{}' exists already.", checked.name));
    }
    if replace.is_none() && rows.len() >= spec::MAX_STACKS {
        return invalid(format!("A workspace keeps at most {} stacks.", spec::MAX_STACKS));
    }
    let id = match replace {
        Some(id) => {
            store.update_stack(ctx, id, &checked).await?;
            id
        }
        None => {
            let id = Uuid::new_v4();
            store.insert_stack(ctx, id, &checked).await?;
            id
        }
    };
    let templates = Catalog::new(store.clone()).templates(ctx).await?;
    let verb = if replace.is_some() { "Replaced" } else { "Imported" };
    let action = format!("{verb} the stack '{}' from a Remotely export", checked.name);
    let detail = Stacks::describe(&checked, &templates);
    store
        .append_audit(
            ctx,
            NewAuditEntry {
                event: EVENT,
                action: &action,
                tier: None,
                job_id: None,
                targets: &[],
                approval: None,
                result: None,
                detail: Some(&detail),
            },
        )
        .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_number_past_those_here() {
        let row = |name: &str| InstanceRow {
            id: Uuid::new_v4(),
            stack_id: Uuid::nil(),
            stack_name: "web lab".into(),
            name: name.into(),
            steps: Vec::new(),
            job_id: None,
            created_at: String::new(),
            members: Vec::new(),
        };
        assert_eq!(Stacks::default_instance_name("web lab", &[]), "web lab 1");
        assert_eq!(
            Stacks::default_instance_name("web lab", &[row("Web Lab 1"), row("web lab 3")]),
            "web lab 2"
        );
        assert_eq!(listed(&["a".into(), "b".into()]), "'a', 'b'");
        assert_eq!(
            listed(&(0..7).map(|i| i.to_string()).collect::<Vec<_>>()),
            "'0', '1', '2', '3', '4' and 2 more"
        );
    }
}
