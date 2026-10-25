//! VM-08: what a stack is, and what its commands carry.
//!
//! * [`StackInput`]: a stack as the editor saves it: a name, launch templates with a count each in boot order, and
//!   between steps a readiness check ([`Readiness`]) and a delay. Checked by [`check_stack`].
//! * [`StackOp`]: what [`crate::command_bus::Command::Stack`] does: deploy an instance ([`StackDeploySpec`], each
//!   step a whole [`DeploySpec`] made by R2's deploy runner), start, shut down or suspend an instance's VMs in boot
//!   order ([`StackPowerSpec`]), or tear an instance down ([`StackTeardownSpec`], R3's delete on each of its VMs).
//!   The core builds every one of them; the UI never sends one (`Command::check_from_ui`).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::command_bus::{PowerOp, StopMode};
use crate::deploy::DeploySpec;
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};
use crate::untrusted::is_format_char;

/// Longest stack or instance name, in characters.
pub const MAX_NAME: usize = 60;
pub const MAX_DESCRIPTION: usize = 500;
/// Steps one stack has.
pub const MAX_STEPS: usize = 20;
/// VMs one stack makes in all: as many as one deploy makes (R2).
pub const MAX_STACK_VMS: u32 = crate::catalog::templates::MAX_DEPLOY_COUNT;
/// Stacks one workspace keeps.
pub const MAX_STACKS: usize = 200;
/// How long a step waits for its VMs to be ready by default.
pub const DEFAULT_READY_TIMEOUT_SECS: u32 = 10 * 60;
pub const MIN_READY_TIMEOUT_SECS: u32 = 30;
pub const MAX_READY_TIMEOUT_SECS: u32 = 60 * 60;
/// The longest delay between two steps.
pub const MAX_DELAY_SECS: u32 = 60 * 60;
pub const DEFAULT_SSH_PORT: u16 = 22;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// What a step's VMs must show before the next step starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Readiness {
    /// Nothing: the next step starts once these VMs are made (or started), after the delay.
    #[default]
    None,
    /// VMware Tools or the Guest Additions run in each guest.
    Tools,
    /// Each guest's IP (as its tools report it) takes a TCP connection on this port, e.g. SSH on 22.
    SshPort { port: u16 },
}

impl Readiness {
    pub fn describe(&self) -> String {
        match self {
            Readiness::None => "nothing".into(),
            Readiness::Tools => "the guest tools running".into(),
            Readiness::SshPort { port } if *port == DEFAULT_SSH_PORT => "SSH (port 22) open".into(),
            Readiness::SshPort { port } => format!("port {port} open"),
        }
    }

    pub fn is_none(&self) -> bool {
        *self == Readiness::None
    }
}

fn default_ready_timeout() -> u32 {
    DEFAULT_READY_TIMEOUT_SECS
}

/// One step of a stack: a launch template and how many VMs of it, then what the next step waits for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackStep {
    pub template_id: Uuid,
    pub count: u32,
    /// Checked on this step's VMs before the next step starts.
    #[serde(default)]
    pub readiness: Readiness,
    /// How long the check may take before the stack stops there.
    #[serde(default = "default_ready_timeout")]
    pub ready_timeout_secs: u32,
    /// How long to wait after this step (and its check) before the next starts.
    #[serde(default)]
    pub delay_secs: u32,
}

/// A stack as the editor saves it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackInput {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// In boot order: the first starts first.
    pub steps: Vec<StackStep>,
}

impl StackInput {
    /// VMs the stack makes in all.
    pub fn vm_count(&self) -> u32 {
        self.steps.iter().map(|s| s.count).fold(0, u32::saturating_add)
    }
}

/// A name for a stack or an instance: trimmed, 1 to [`MAX_NAME`] characters, no control or format characters.
pub fn check_name(name: &str, what: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return invalid(format!("Give the {what} a name."));
    }
    if name.chars().count() > MAX_NAME {
        return invalid(format!("A {what} name is at most {MAX_NAME} characters."));
    }
    if name.chars().any(|c| c.is_control() || is_format_char(c)) {
        return invalid(format!("The {what} name has a character it can't keep."));
    }
    Ok(name.to_owned())
}

/// A readiness check that can be made.
fn check_readiness(readiness: &Readiness) -> Result<()> {
    if let Readiness::SshPort { port } = readiness {
        if *port == 0 {
            return invalid("A readiness check needs a port from 1 to 65535.");
        }
    }
    Ok(())
}

/// The stack as it is saved: its name and description trimmed, every step within bounds.
pub fn check_stack(input: &StackInput) -> Result<StackInput> {
    let name = check_name(&input.name, "stack")?;
    let description = match input.description.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        Some(d) if d.chars().count() > MAX_DESCRIPTION => {
            return invalid(format!("A description is at most {MAX_DESCRIPTION} characters."))
        }
        Some(d) if d.chars().any(|c| (c.is_control() && c != '\n') || is_format_char(c)) => {
            return invalid("The description has a character it can't keep.")
        }
        Some(d) => Some(d.to_owned()),
        None => None,
    };
    if input.steps.is_empty() {
        return invalid("A stack needs at least one launch template.");
    }
    if input.steps.len() > MAX_STEPS {
        return invalid(format!("A stack has at most {MAX_STEPS} steps."));
    }
    for (i, step) in input.steps.iter().enumerate() {
        let n = i + 1;
        if step.count == 0 {
            return invalid(format!("Step {n} makes no VM: give it a count of 1 or more."));
        }
        check_readiness(&step.readiness)?;
        if !(MIN_READY_TIMEOUT_SECS..=MAX_READY_TIMEOUT_SECS).contains(&step.ready_timeout_secs) {
            return invalid(format!(
                "Step {n}'s readiness wait is {} seconds to an hour.",
                MIN_READY_TIMEOUT_SECS
            ));
        }
        if step.delay_secs > MAX_DELAY_SECS {
            return invalid(format!("Step {n}'s delay is at most an hour."));
        }
    }
    let total = input.vm_count();
    if total > MAX_STACK_VMS {
        return invalid(format!(
            "A stack makes at most {MAX_STACK_VMS} VMs; this one makes {total}."
        ));
    }
    Ok(StackInput {
        name,
        description,
        steps: input.steps.clone(),
    })
}

/// What an instance keeps of each step: what starting it waits for between steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceStep {
    /// The launch template's name when it was deployed.
    pub label: String,
    #[serde(default)]
    pub readiness: Readiness,
    #[serde(default = "default_ready_timeout")]
    pub ready_timeout_secs: u32,
    #[serde(default)]
    pub delay_secs: u32,
}

/// One step of a stack deploy: the step's whole deploy (R2), then what the next step waits for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackStepRun {
    pub label: String,
    pub template_id: Uuid,
    pub spec: DeploySpec,
    pub readiness: Readiness,
    pub ready_timeout_secs: u32,
    pub delay_secs: u32,
}

impl StackStepRun {
    pub fn instance_step(&self) -> InstanceStep {
        InstanceStep {
            label: self.label.clone(),
            readiness: self.readiness,
            ready_timeout_secs: self.ready_timeout_secs,
            delay_secs: self.delay_secs,
        }
    }
}

/// VM-08: a stack deploy: one instance, its steps in boot order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackDeploySpec {
    pub stack_id: Uuid,
    pub stack_name: String,
    pub instance_id: Uuid,
    pub instance_name: String,
    pub steps: Vec<StackStepRun>,
}

impl StackDeploySpec {
    /// Every new VM, step by step.
    pub fn targets(&self) -> Vec<TargetRef> {
        self.steps.iter().flat_map(|s| s.spec.targets()).collect()
    }

    pub fn vm_count(&self) -> usize {
        self.steps.iter().map(|s| s.spec.vms.len()).sum()
    }

    /// The step that makes the VM `name`, and its index.
    pub fn step_of(&self, name: &str) -> Option<(usize, &StackStepRun)> {
        self.steps.iter().enumerate().find(|(_, s)| s.spec.vm(name).is_some())
    }

    pub fn instance_steps(&self) -> Vec<InstanceStep> {
        self.steps.iter().map(StackStepRun::instance_step).collect()
    }

    pub fn summary(&self) -> String {
        let n = self.vm_count();
        format!(
            "Deploy stack '{}' as '{}' ({n} {})",
            self.stack_name,
            self.instance_name,
            if n == 1 { "VM" } else { "VMs" }
        )
    }

    /// What the audit log says the deploy is.
    pub fn describe(&self) -> String {
        let steps: Vec<String> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let names: Vec<&str> = s.spec.vms.iter().map(|v| v.name.as_str()).collect();
                let mut text = format!(
                    "step {}: '{}' x{} ({})",
                    i + 1,
                    s.label,
                    s.spec.vms.len(),
                    names.join(", ")
                );
                if i + 1 < self.steps.len() {
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
        format!(
            "instance '{}' of stack '{}': {}",
            self.instance_name,
            self.stack_name,
            steps.join("; ")
        )
    }

    /// Checked on the bus, whoever built it: each step's deploy is valid and tagged with this instance and its
    /// place, names are unique across steps, and the instance stays within bounds.
    pub fn validate(&self) -> Result<()> {
        check_name(&self.stack_name, "stack")?;
        check_name(&self.instance_name, "instance")?;
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return invalid(format!("A stack has 1 to {MAX_STEPS} steps."));
        }
        let total = self.vm_count();
        if total == 0 || total > MAX_STACK_VMS as usize {
            return invalid(format!("A stack makes 1 to {MAX_STACK_VMS} VMs."));
        }
        let mut names = HashSet::new();
        let mut last: Option<u32> = None;
        for step in &self.steps {
            step.spec.validate()?;
            // A retry keeps only the steps with VMs left, each at its place in the instance.
            match &step.spec.stack {
                Some(tag) if tag.instance_id == self.instance_id && last.is_none_or(|l| tag.step > l) => {
                    last = Some(tag.step);
                }
                _ => return invalid("Each step of a stack deploy belongs to its instance, in order."),
            }
            check_readiness(&step.readiness)?;
            if !(MIN_READY_TIMEOUT_SECS..=MAX_READY_TIMEOUT_SECS).contains(&step.ready_timeout_secs)
                || step.delay_secs > MAX_DELAY_SECS
            {
                return invalid("A step's readiness wait or delay is out of bounds.");
            }
            for vm in &step.spec.vms {
                if !names.insert(vm.name.to_lowercase()) {
                    return invalid(format!("Two VMs of the stack are named '{}'.", vm.name));
                }
            }
        }
        Ok(())
    }

    /// The same deploy for only these targets (BX-04: retry the VMs that failed): steps with none left go, the
    /// others keep their place in the instance.
    pub fn only(&self, targets: &[TargetRef]) -> Self {
        let mut spec = self.clone();
        spec.steps = self
            .steps
            .iter()
            .map(|s| {
                let mut step = s.clone();
                step.spec = s.spec.only(targets);
                step
            })
            .filter(|s| !s.spec.vms.is_empty())
            .collect();
        spec
    }
}

/// A VM by its key and name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamedVm {
    pub key: String,
    pub name: String,
}

/// One step of an instance's start, shut down or suspend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PowerStep {
    pub label: String,
    /// The VMs this step acts on (their keys), in the order of the command's targets.
    pub vms: Vec<String>,
    /// The VMs whose readiness is checked after this step (start only): those started and those running already.
    #[serde(default)]
    pub ready: Vec<NamedVm>,
    #[serde(default)]
    pub readiness: Readiness,
    #[serde(default = "default_ready_timeout")]
    pub ready_timeout_secs: u32,
    #[serde(default)]
    pub delay_secs: u32,
}

/// VM-08: start, shut down or suspend an instance's VMs, in boot order (starting) or the other way (stopping).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackPowerSpec {
    pub instance_id: Uuid,
    pub instance_name: String,
    pub op: PowerOp,
    /// In the order they run: boot order to start, the last step first to stop.
    pub steps: Vec<PowerStep>,
}

/// The power operations an instance takes as a whole.
pub fn instance_op_allowed(op: &PowerOp) -> bool {
    matches!(
        op,
        PowerOp::Start { gui: false } | PowerOp::Stop { mode: StopMode::Soft } | PowerOp::Suspend
    )
}

impl StackPowerSpec {
    pub fn targets(&self) -> Vec<TargetRef> {
        self.steps
            .iter()
            .flat_map(|s| s.vms.iter().map(|k| TargetRef::Vm { vmx_path: k.clone() }))
            .collect()
    }

    pub fn starts(&self) -> bool {
        matches!(self.op, PowerOp::Start { .. })
    }

    pub fn verb(&self) -> &'static str {
        match self.op {
            PowerOp::Start { .. } => "Start",
            PowerOp::Suspend => "Suspend",
            _ => "Shut down",
        }
    }

    pub fn summary(&self, count: usize) -> String {
        format!(
            "{} stack instance '{}' ({count} {})",
            self.verb(),
            self.instance_name,
            if count == 1 { "VM" } else { "VMs" }
        )
    }

    pub fn validate(&self) -> Result<()> {
        check_name(&self.instance_name, "instance")?;
        if !instance_op_allowed(&self.op) {
            return invalid("A stack instance starts, shuts down or suspends as a whole.");
        }
        if self.steps.len() > MAX_STEPS {
            return invalid(format!("A stack has at most {MAX_STEPS} steps."));
        }
        let mut keys = HashSet::new();
        for step in &self.steps {
            check_readiness(&step.readiness)?;
            for key in &step.vms {
                if !keys.insert(crate::adapters::vmware::path_key(std::path::Path::new(key))) {
                    return invalid("A VM is listed twice.");
                }
            }
        }
        Ok(())
    }

    /// The same, for only these targets (BX-04).
    pub fn only(&self, targets: &[TargetRef]) -> Self {
        let keep: HashSet<String> = targets.iter().map(TargetRef::key).collect();
        let mut spec = self.clone();
        for step in &mut spec.steps {
            step.vms.retain(|k| keep.contains(k));
        }
        spec.steps.retain(|s| !s.vms.is_empty());
        spec
    }
}

/// A VM of an instance that a teardown keeps, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeptVm {
    pub key: String,
    pub name: String,
    pub why: String,
}

/// VM-08: tear an instance down: R3's delete on each VM its deploy made (and those the user picked on purpose).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackTeardownSpec {
    pub instance_id: Uuid,
    pub instance_name: String,
    pub stack_name: String,
    /// VMs of the instance the teardown leaves: added by hand and not picked, or gone already.
    #[serde(default)]
    pub kept: Vec<KeptVm>,
}

impl StackTeardownSpec {
    pub fn summary(&self, count: usize) -> String {
        format!(
            "Tear down stack instance '{}' ({count} {})",
            self.instance_name,
            if count == 1 { "VM" } else { "VMs" }
        )
    }

    pub fn validate(&self) -> Result<()> {
        check_name(&self.instance_name, "instance")?;
        check_name(&self.stack_name, "stack")?;
        Ok(())
    }
}

/// What a [`crate::command_bus::Command::Stack`] does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum StackOp {
    Deploy { spec: Box<StackDeploySpec> },
    Power { spec: Box<StackPowerSpec> },
    Teardown { spec: Box<StackTeardownSpec> },
}

impl StackOp {
    pub fn instance_id(&self) -> Uuid {
        match self {
            StackOp::Deploy { spec } => spec.instance_id,
            StackOp::Power { spec } => spec.instance_id,
            StackOp::Teardown { spec } => spec.instance_id,
        }
    }

    pub fn instance_name(&self) -> &str {
        match self {
            StackOp::Deploy { spec } => &spec.instance_name,
            StackOp::Power { spec } => &spec.instance_name,
            StackOp::Teardown { spec } => &spec.instance_name,
        }
    }

    pub fn summary(&self, count: usize) -> String {
        match self {
            StackOp::Deploy { spec } => spec.summary(),
            StackOp::Power { spec } => spec.summary(count),
            StackOp::Teardown { spec } => spec.summary(count),
        }
    }

    /// Checked on the bus: the op's own checks, and targets that are what it acts on.
    pub fn validate(&self, targets: &[TargetRef]) -> Result<()> {
        match self {
            StackOp::Deploy { spec } => {
                spec.validate()?;
                if targets != spec.targets() {
                    return invalid("A stack deploy's targets are the VMs it makes, step by step.");
                }
            }
            StackOp::Power { spec } => {
                spec.validate()?;
                if targets != spec.targets() {
                    return invalid("A stack instance's targets are its VMs, step by step.");
                }
            }
            StackOp::Teardown { spec } => {
                spec.validate()?;
                let mut keys = HashSet::new();
                for target in targets {
                    let TargetRef::Vm { vmx_path } = target else {
                        return invalid("A teardown deletes VMs only.");
                    };
                    if !keys.insert(crate::adapters::vmware::path_key(std::path::Path::new(vmx_path))) {
                        return invalid("A VM is listed twice.");
                    }
                }
            }
        }
        Ok(())
    }

    /// The same op for these targets (BX-04 retry).
    pub fn only(&self, targets: &[TargetRef]) -> Self {
        match self {
            StackOp::Deploy { spec } => StackOp::Deploy {
                spec: Box::new(spec.only(targets)),
            },
            StackOp::Power { spec } => StackOp::Power {
                spec: Box::new(spec.only(targets)),
            },
            StackOp::Teardown { spec } => StackOp::Teardown { spec: spec.clone() },
        }
    }

    /// The targets the op itself names (a teardown's are the command's own).
    pub fn targets(&self) -> Option<Vec<TargetRef>> {
        match self {
            StackOp::Deploy { spec } => Some(spec.targets()),
            StackOp::Power { spec } => Some(spec.targets()),
            StackOp::Teardown { .. } => None,
        }
    }
}

/// What tags a deploy's VMs as an instance's, so the deploy runner records each one there once it is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackTag {
    pub instance_id: Uuid,
    /// The step's index, from 0.
    pub step: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(count: u32) -> StackStep {
        StackStep {
            template_id: Uuid::from_u128(1),
            count,
            readiness: Readiness::Tools,
            ready_timeout_secs: DEFAULT_READY_TIMEOUT_SECS,
            delay_secs: 0,
        }
    }

    fn input(steps: Vec<StackStep>) -> StackInput {
        StackInput {
            name: "  web lab ".into(),
            description: Some("  db, then web  ".into()),
            steps,
        }
    }

    #[test]
    fn a_stack_is_trimmed_and_checked() {
        let checked = check_stack(&input(vec![step(1), step(3)])).unwrap();
        assert_eq!(checked.name, "web lab");
        assert_eq!(checked.description.as_deref(), Some("db, then web"));
        assert_eq!(checked.vm_count(), 4);

        let bad = |steps: Vec<StackStep>, why: &str| {
            let err = check_stack(&input(steps)).unwrap_err().to_string();
            assert!(err.contains(why), "{why}: {err}");
        };
        bad(vec![], "at least one");
        bad(vec![step(0)], "makes no VM");
        bad(vec![step(30), step(21)], "at most 50 VMs");
        bad((0..21).map(|_| step(1)).collect(), "at most 20 steps");
        let mut s = step(1);
        s.readiness = Readiness::SshPort { port: 0 };
        bad(vec![s], "port from 1");
        let mut s = step(1);
        s.ready_timeout_secs = 5;
        bad(vec![s], "readiness wait");
        let mut s = step(1);
        s.delay_secs = 7200;
        bad(vec![s], "at most an hour");
        assert!(check_name("x\u{202e}", "stack").is_err());
        assert!(check_name(&"x".repeat(61), "stack").is_err());
    }

    #[test]
    fn readiness_reads_in_words_and_round_trips() {
        assert_eq!(Readiness::None.describe(), "nothing");
        assert_eq!(Readiness::SshPort { port: 22 }.describe(), "SSH (port 22) open");
        assert_eq!(Readiness::SshPort { port: 5432 }.describe(), "port 5432 open");
        let json = serde_json::to_value(Readiness::SshPort { port: 22 }).unwrap();
        assert_eq!(json, serde_json::json!({"kind": "sshPort", "port": 22}));
        // Older or hand-written steps take the defaults.
        let step: StackStep =
            serde_json::from_value(serde_json::json!({"templateId": Uuid::from_u128(1), "count": 2})).unwrap();
        assert_eq!(step.readiness, Readiness::None);
        assert_eq!(step.ready_timeout_secs, DEFAULT_READY_TIMEOUT_SECS);
    }

    #[test]
    fn only_start_shut_down_and_suspend_act_on_an_instance() {
        assert!(instance_op_allowed(&PowerOp::Start { gui: false }));
        assert!(instance_op_allowed(&PowerOp::Suspend));
        assert!(instance_op_allowed(&PowerOp::Stop { mode: StopMode::Soft }));
        assert!(!instance_op_allowed(&PowerOp::Stop { mode: StopMode::Hard }));
        assert!(!instance_op_allowed(&PowerOp::Reset { mode: StopMode::Soft }));
        assert!(!instance_op_allowed(&PowerOp::Pause));
    }
}
