//! VM-08: what the job runner calls between a stack's steps ([`StackActions`]), and the instance bookkeeping around
//! a stack job.
//!
//! * Before a stack deploy's first VM, its instance is recorded (a retry finds it there); each VM the deploy runner
//!   makes joins it at its step (`deploy::runner`). An instance left with no VM after its deploy is forgotten.
//! * Between steps, the step's VMs must pass its readiness check ([`Readiness`]): the guest tools running, or a port
//!   open on the guest's IP (as its tools report it). Each VM is asked every [`StackTuning::poll`] until all pass or the
//!   step's wait runs out; then the job stops starting steps, and says which VM wasn't ready and why. The delay after
//!   a step follows. Both wait on a [`StackClock`], so tests run them on a fake clock without sleeping.
//! * A teardown takes each VM it deleted out of the instance; the instance goes once it has none left.
//!
//! Reads only, apart from the instance rows: the hypervisors' tools state and guest IP, and a TCP connection to the
//! guest's port (QL-04's probe).

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::spec::{Readiness, StackOp};
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::network::NetworkAdapter;
use crate::adapters::vmware::{path_key, ToolsState};
use crate::domain::Context;
use crate::error::Result;
use crate::locks;
use crate::store::{InstanceRow, NewAuditEntry, NewInstance, Store};

/// The time a stack job waits on: monotonic, and fake in tests.
#[async_trait]
pub trait StackClock: Send + Sync {
    /// How long since some fixed moment.
    fn now(&self) -> Duration;
    async fn sleep(&self, how_long: Duration);
}

/// The real clock.
pub struct SystemStackClock {
    origin: std::time::Instant,
}

impl Default for SystemStackClock {
    fn default() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

#[async_trait]
impl StackClock for SystemStackClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    async fn sleep(&self, how_long: Duration) {
        tokio::time::sleep(how_long).await;
    }
}

/// How the readiness checks ask.
#[derive(Debug, Clone, Copy)]
pub struct StackTuning {
    /// How often a VM that isn't ready yet is asked again.
    pub poll: Duration,
    /// How long one TCP connection to a guest's port may take.
    pub probe_timeout: Duration,
}

impl Default for StackTuning {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(3),
        }
    }
}

/// How a readiness wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadyOutcome {
    Ready {
        after: Duration,
    },
    /// A VM wasn't ready in time; why, in words.
    NotReady {
        why: String,
    },
    Cancelled,
}

/// What the job runner calls for a [`crate::command_bus::Command::Stack`].
#[async_trait]
pub trait StackActions: Send + Sync {
    /// Before the job's first VM: a deploy's instance is recorded, unless it is there (a retry's).
    async fn begin(&self, ctx: &Context, job_id: Uuid, op: &StackOp) -> Result<()>;
    /// The VMs (key, name) an instance has at `step`.
    async fn step_vms(&self, ctx: &Context, instance_id: Uuid, step: usize) -> Result<Vec<(String, String)>>;
    /// Waits until every VM passes `readiness`, at most `timeout`.
    async fn wait_ready(
        &self,
        vms: &[(String, String)],
        readiness: Readiness,
        timeout: Duration,
        token: &CancellationToken,
    ) -> ReadyOutcome;
    /// Waits `delay`; false when the job was cancelled meanwhile.
    async fn pause(&self, delay: Duration, token: &CancellationToken) -> bool;
    /// A teardown deleted this VM: it leaves its instance.
    async fn torn_down(&self, ctx: &Context, vm_key: &str) -> Result<()>;
    /// After the job: an instance left with no VMs goes. Returns what the job's audit entry says about it.
    async fn end(&self, ctx: &Context, op: &StackOp) -> Option<String>;
}

/// The job runner's [`StackActions`] (`JobRunner::set_stacks`).
pub struct StackRunner {
    store: Store,
    hypervisors: Hypervisors,
    network: Arc<dyn NetworkAdapter>,
    clock: RwLock<Arc<dyn StackClock>>,
    tuning: RwLock<StackTuning>,
}

impl StackRunner {
    pub fn new(store: Store, hypervisors: Hypervisors, network: Arc<dyn NetworkAdapter>) -> Self {
        Self {
            store,
            hypervisors,
            network,
            clock: RwLock::new(Arc::new(SystemStackClock::default())),
            tuning: RwLock::new(StackTuning::default()),
        }
    }

    /// Tests run the waits on their own clock.
    pub fn set_clock(&self, clock: Arc<dyn StackClock>) {
        *locks::write(&self.clock) = clock;
    }

    pub fn set_tuning(&self, tuning: StackTuning) {
        *locks::write(&self.tuning) = tuning;
    }

    fn clock(&self) -> Arc<dyn StackClock> {
        Arc::clone(&locks::read(&self.clock))
    }

    fn tuning(&self) -> StackTuning {
        *locks::read(&self.tuning)
    }

    /// The guest's IP as its tools report it.
    async fn guest_ip(&self, key: &str) -> Option<String> {
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => self.hypervisors.vmware().guest_ip(Path::new(key)).await.ok().flatten(),
            Hypervisor::VirtualBox => {
                let vbox = self.hypervisors.virtualbox();
                let props = vbox.guest_properties(key).await.ok()?;
                let info = vbox.vm_info(key).await.ok()?;
                crate::adapters::virtualbox::guest_ip(&props, &info.nics)
            }
        }
    }

    /// Whether the VM passes `readiness` now; why not when it doesn't.
    async fn ready_now(&self, key: &str, readiness: Readiness) -> std::result::Result<(), String> {
        let hypervisor = Hypervisor::of_key(key);
        match readiness {
            Readiness::None => Ok(()),
            Readiness::Tools => {
                let state = match hypervisor {
                    Hypervisor::Vmware => self.hypervisors.vmware().tools_state(Path::new(key)).await,
                    Hypervisor::VirtualBox => self
                        .hypervisors
                        .virtualbox()
                        .vm_info(key)
                        .await
                        .map(|info| info.tools_state().unwrap_or(ToolsState::NotRunning)),
                };
                match state {
                    Ok(ToolsState::Running) => Ok(()),
                    Ok(_) => Err(format!("{} not running in the guest yet", hypervisor.tools_name())),
                    Err(err) => Err(format!("{} couldn't be asked ({err})", hypervisor.label())),
                }
            }
            Readiness::SshPort { port } => {
                let Some(ip) = self.guest_ip(key).await else {
                    return Err(format!("no guest IP yet ({} report it)", hypervisor.tools_name()));
                };
                match self.network.probe(&ip, port, self.tuning().probe_timeout).await {
                    Ok(_) => Ok(()),
                    Err(_) => Err(format!("port {port} on {ip} doesn't answer yet")),
                }
            }
        }
    }
}

impl StackRunner {
    /// An instance with no VMs left goes, audited.
    async fn forget(&self, ctx: &Context, instance: &InstanceRow, what: &str) -> Option<String> {
        if let Err(err) = self.store.delete_stack_instance(ctx, instance.id).await {
            tracing::warn!(error = %err, "could not forget a stack instance with no VMs");
            return None;
        }
        let detail = format!(
            "instance '{}' of stack '{}': {what}",
            instance.name, instance.stack_name
        );
        let written = self
            .store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: super::EVENT,
                    action: "Removed a stack instance",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await;
        if let Err(err) = written {
            tracing::error!(error = %err, "could not audit a stack instance going");
        }
        Some(format!("stack instance '{}' removed ({what})", instance.name))
    }
}

fn seconds(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 120 {
        format!("{secs} s")
    } else {
        crate::error::in_minutes(secs.div_ceil(60))
    }
}

#[async_trait]
impl StackActions for StackRunner {
    async fn begin(&self, ctx: &Context, job_id: Uuid, op: &StackOp) -> Result<()> {
        let StackOp::Deploy { spec } = op else {
            return Ok(());
        };
        let steps = spec.instance_steps();
        let name = self
            .store
            .insert_stack_instance(
                ctx,
                &NewInstance {
                    id: spec.instance_id,
                    stack_id: spec.stack_id,
                    stack_name: &spec.stack_name,
                    name: &spec.instance_name,
                    steps: &steps,
                    job_id: Some(job_id),
                },
            )
            .await?;
        if name != spec.instance_name {
            tracing::info!(%name, "a stack instance's name was taken meanwhile, so it got another");
        }
        Ok(())
    }

    async fn step_vms(&self, ctx: &Context, instance_id: Uuid, step: usize) -> Result<Vec<(String, String)>> {
        Ok(self
            .store
            .stack_instance(ctx, instance_id)
            .await?
            .map(|instance| {
                instance
                    .members
                    .into_iter()
                    .filter(|m| m.step as usize == step)
                    .map(|m| (m.vm_key, m.vm_name))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn wait_ready(
        &self,
        vms: &[(String, String)],
        readiness: Readiness,
        timeout: Duration,
        token: &CancellationToken,
    ) -> ReadyOutcome {
        if readiness.is_none() {
            return ReadyOutcome::Ready { after: Duration::ZERO };
        }
        let clock = self.clock();
        let poll = self.tuning().poll;
        let start = clock.now();
        let mut pending: Vec<&(String, String)> = vms.iter().collect();
        loop {
            if token.is_cancelled() {
                return ReadyOutcome::Cancelled;
            }
            let mut still = Vec::new();
            let mut why = Vec::new();
            for vm in pending {
                if let Err(reason) = self.ready_now(&vm.0, readiness).await {
                    why.push(format!("'{}': {reason}", vm.1));
                    still.push(vm);
                }
            }
            pending = still;
            let waited = clock.now().saturating_sub(start);
            if pending.is_empty() {
                return ReadyOutcome::Ready { after: waited };
            }
            if waited >= timeout {
                return ReadyOutcome::NotReady {
                    why: format!(
                        "not ready within {} ({} expected): {}",
                        seconds(timeout),
                        readiness.describe(),
                        why.join("; ")
                    ),
                };
            }
            tokio::select! {
                biased;
                _ = token.cancelled() => return ReadyOutcome::Cancelled,
                _ = clock.sleep(poll.min(timeout.saturating_sub(waited)).max(Duration::from_millis(1))) => {}
            }
        }
    }

    async fn pause(&self, delay: Duration, token: &CancellationToken) -> bool {
        if delay.is_zero() {
            return !token.is_cancelled();
        }
        let clock = self.clock();
        tokio::select! {
            biased;
            _ = token.cancelled() => false,
            _ = clock.sleep(delay) => true,
        }
    }

    async fn torn_down(&self, ctx: &Context, vm_key: &str) -> Result<()> {
        self.store.remove_stack_vm(ctx, vm_key).await.map(drop)
    }

    async fn end(&self, ctx: &Context, op: &StackOp) -> Option<String> {
        let id = op.instance_id();
        let mut instance = match self.store.stack_instance(ctx, id).await {
            Ok(Some(instance)) => instance,
            Ok(None) => return None,
            Err(err) => {
                tracing::warn!(error = %err, "could not read a stack instance after its job");
                return None;
            }
        };
        if let StackOp::Teardown { .. } = op {
            // VMs deleted outside Remotely before the teardown leave the instance with it, so it can empty.
            if let Ok(vms) = self.store.list_vms(ctx).await {
                let here: std::collections::HashSet<String> =
                    vms.iter().map(|vm| path_key(Path::new(&vm.vmx_path))).collect();
                let (gone, kept): (Vec<_>, Vec<_>) = instance
                    .members
                    .into_iter()
                    .partition(|m| !here.contains(&path_key(Path::new(&m.vm_key))));
                for member in &gone {
                    if let Err(err) = self.store.remove_stack_vm(ctx, &member.vm_key).await {
                        tracing::warn!(error = %err, "a gone VM could not leave its stack instance");
                    }
                }
                instance.members = kept;
            }
        }
        match op {
            StackOp::Deploy { .. } if instance.members.is_empty() => {
                self.forget(ctx, &instance, "its deploy made no VM").await
            }
            StackOp::Deploy { .. } => Some(format!(
                "stack instance '{}' has {} VM(s)",
                instance.name,
                instance.members.len()
            )),
            StackOp::Teardown { .. } if instance.members.is_empty() => {
                self.forget(ctx, &instance, "every VM of it was deleted").await
            }
            StackOp::Teardown { .. } => {
                let names: Vec<String> = instance.members.iter().map(|m| format!("'{}'", m.vm_name)).collect();
                Some(format!(
                    "stack instance '{}' keeps {}: {}",
                    instance.name,
                    if names.len() == 1 { "1 VM" } else { "these VMs" },
                    names.join(", ")
                ))
            }
            StackOp::Power { .. } => None,
        }
    }
}
