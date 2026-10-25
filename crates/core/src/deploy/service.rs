//! The deploy service (`Core.deploy`): what the Deploy dialog and the VMs page's Clone call. It resolves a launch
//! template (or the dialog's own values, Custom) through the catalogue, or the picked VMs for a bulk clone, into a
//! [`DeploySpec`], previews it, and submits it to the bus as [`Command::Deploy`]. It never changes a VM itself.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::preview::{preview, DeployPreview};
use super::spec::{DeployOrigin, DeploySource, DeploySpec, DeployVm, DEFAULT_IP_WAIT_SECS};
use crate::adapters::host_counters::HostCounters;
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vmware::with_backslashes;
use crate::catalog::templates::{self, AfterDeploy, Network, Problem, ProblemCode, TemplateInput, MAX_DEPLOY_COUNT};
use crate::catalog::Catalog;
use crate::command_bus::{Command, CommandBus, SubmitOutcome};
use crate::domain::{Context, Environment, PowerState};
use crate::error::{CoreError, Result};
use crate::store::{Store, VmRecord};

/// What a deploy starts from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DeployFrom {
    /// A saved launch template.
    Template { id: Uuid },
    /// Every value chosen in the dialog, checked like a template's.
    Custom { input: Box<TemplateInput> },
}

/// What the Deploy dialog sends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployRequest {
    pub from: DeployFrom,
    pub count: u32,
    /// The dialog's naming pattern, when it isn't the template's.
    #[serde(default)]
    pub naming_pattern: Option<String>,
    /// VirtualBox's host-only or bridged adapter, when the network needs one (`None`: the first).
    #[serde(default)]
    pub host_adapter: Option<String>,
}

/// VM-10: what the VMs page's Clone sends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloneRequest {
    /// The VMs to clone, by key; one clone each.
    pub vm_keys: Vec<String>,
    /// `{template}` is each source VM's name: `{template}-clone`, `{template}-{n}`.
    pub naming_pattern: String,
    /// `None`: the hypervisor's default folder.
    #[serde(default)]
    pub folder: Option<String>,
    /// `None`: the strictest of the sources' labels.
    #[serde(default)]
    pub environment: Option<Environment>,
}

/// The dialog's answer while it is filled in: why it can't deploy, or what it would make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployCheck {
    pub problems: Vec<Problem>,
    pub preview: Option<DeployPreview>,
}

/// The VMs page's default naming pattern for a bulk clone.
pub const DEFAULT_CLONE_PATTERN: &str = "{template}-clone";

fn problem(message: impl Into<String>) -> Problem {
    Problem {
        code: ProblemCode::ImageUnavailable,
        message: message.into(),
    }
}

/// The deploy service.
#[derive(Clone)]
pub struct Deploys {
    store: Store,
    catalog: Catalog,
    hypervisors: Hypervisors,
    host: Arc<dyn HostCounters>,
    bus: Arc<CommandBus>,
}

impl Deploys {
    pub fn new(
        store: Store,
        catalog: Catalog,
        hypervisors: Hypervisors,
        host: Arc<dyn HostCounters>,
        bus: Arc<CommandBus>,
    ) -> Self {
        Self {
            store,
            catalog,
            hypervisors,
            host,
            bus,
        }
    }

    /// The folder a hypervisor puts new VMs in, as a full path with `\`.
    pub async fn default_folder(&self, hypervisor: Hypervisor) -> Result<String> {
        let folder = match hypervisor {
            Hypervisor::Vmware => self.hypervisors.vmware().default_vm_folder().await?,
            Hypervisor::VirtualBox => self.hypervisors.virtualbox().default_machine_folder().await?,
        };
        Ok(with_backslashes(&folder).display().to_string())
    }

    /// VirtualBox's host-only adapters, or with `bridged` the network adapters it bridges to.
    pub async fn host_adapters(&self, bridged: bool) -> Result<Vec<String>> {
        self.hypervisors.virtualbox().host_adapters(bridged).await
    }

    /// The spec a request makes, or why it can't make one.
    async fn spec_for(
        &self,
        ctx: &Context,
        request: &DeployRequest,
    ) -> Result<std::result::Result<DeploySpec, Vec<Problem>>> {
        if !(1..=MAX_DEPLOY_COUNT).contains(&request.count) {
            return Ok(Err(vec![Problem {
                code: ProblemCode::CountOutOfRange,
                message: format!("A deploy makes 1 to {MAX_DEPLOY_COUNT} VMs."),
            }]));
        }
        let (id, origin, mut input) = match &request.from {
            DeployFrom::Template { id } => {
                let template = self.catalog.template(ctx, *id).await?;
                let origin = DeployOrigin::Template {
                    id: *id,
                    name: template.spec.name.clone(),
                };
                (*id, origin, template.spec)
            }
            DeployFrom::Custom { input } => (
                Uuid::nil(),
                DeployOrigin::Custom {
                    name: input.name.trim().to_owned(),
                },
                (**input).clone(),
            ),
        };
        if let Some(pattern) = request
            .naming_pattern
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            input.naming_pattern = pattern.to_owned();
        }
        // The template's own default count is checked only as the template's.
        input.default_count = request.count;
        let plan = match self.catalog.plan_input(ctx, id, &input, request.count).await? {
            Ok(plan) => plan,
            Err(problems) => return Ok(Err(problems)),
        };
        let folder = match &plan.vm_folder {
            Some(folder) => with_backslashes(Path::new(folder)).display().to_string(),
            None => self.default_folder(plan.hypervisor).await?,
        };
        let host_adapter = match (&plan.hypervisor, &plan.network) {
            (Hypervisor::VirtualBox, Network::HostOnly | Network::Bridged) => {
                let bridged = plan.network == Network::Bridged;
                let known = self.host_adapters(bridged).await.unwrap_or_default();
                match request.host_adapter.as_deref() {
                    Some(asked) if known.iter().any(|k| k == asked) => Some(asked.to_owned()),
                    Some(asked) => {
                        return Ok(Err(vec![problem(format!(
                            "VirtualBox has no {} adapter named '{asked}'.",
                            if bridged { "network" } else { "host-only" }
                        ))]))
                    }
                    None => match known.into_iter().next() {
                        Some(first) => Some(first),
                        None => {
                            return Ok(Err(vec![problem(if bridged {
                                "VirtualBox lists no network adapter to bridge to."
                            } else {
                                "VirtualBox has no host-only network yet: add one in VirtualBox (File, Tools, Network Manager)."
                            })]))
                        }
                    },
                }
            }
            _ => None,
        };
        let spec = DeploySpec::from_plan(&plan, origin, folder, host_adapter);
        spec.validate()?;
        Ok(Ok(spec))
    }

    /// The Deploy dialog's check: why it can't deploy, or its AP-02 preview. A read.
    pub async fn check(&self, ctx: &Context, request: &DeployRequest) -> Result<DeployCheck> {
        match self.spec_for(ctx, request).await? {
            Err(problems) => Ok(DeployCheck {
                problems,
                preview: None,
            }),
            Ok(spec) => Ok(DeployCheck {
                problems: Vec::new(),
                preview: Some(preview(&spec, &self.hypervisors, self.host.as_ref()).await),
            }),
        }
    }

    /// Submits the deploy to the bus: approval for every tier but Low (it is Medium at least by default), then one
    /// job. Refused when it can't deploy or its preview refuses it.
    pub async fn submit(&self, ctx: &Context, request: &DeployRequest) -> Result<SubmitOutcome> {
        let spec = match self.spec_for(ctx, request).await? {
            Ok(spec) => spec,
            Err(problems) => return Err(refused(problems.into_iter().map(|p| p.message).collect())),
        };
        self.submit_spec(ctx, spec).await
    }

    async fn submit_spec(&self, ctx: &Context, spec: DeploySpec) -> Result<SubmitOutcome> {
        let checked = preview(&spec, &self.hypervisors, self.host.as_ref()).await;
        if !checked.refusals.is_empty() {
            return Err(refused(checked.refusals));
        }
        self.bus
            .submit(
                ctx,
                Command::Deploy {
                    targets: spec.targets(),
                    spec: Box::new(spec),
                },
            )
            .await
    }

    /// VM-10: the bulk clone's spec: one full clone of each picked VM (powered off, one hypervisor), named by the
    /// pattern with `{template}` as the source's name.
    async fn clone_spec(
        &self,
        ctx: &Context,
        request: &CloneRequest,
    ) -> Result<std::result::Result<DeploySpec, Vec<Problem>>> {
        let mut problems = Vec::new();
        if request.vm_keys.is_empty() || request.vm_keys.len() > MAX_DEPLOY_COUNT as usize {
            return Err(CoreError::InvalidInput(format!(
                "Clone 1 to {MAX_DEPLOY_COUNT} VMs at a time."
            )));
        }
        let mut sources: Vec<VmRecord> = Vec::new();
        for key in &request.vm_keys {
            let vm = self
                .store
                .find_vm(ctx, key)
                .await?
                .ok_or_else(|| CoreError::UnknownTarget(key.clone()))?;
            if sources.iter().any(|s| s.id == vm.id) {
                continue;
            }
            if matches!(
                vm.power_state,
                PowerState::Running | PowerState::Paused | PowerState::Suspended
            ) {
                problems.push(problem(format!(
                    "{} is {}: a clone copies a VM that is shut down. Shut it down first.",
                    vm.display_name,
                    match vm.power_state {
                        PowerState::Suspended => "suspended",
                        PowerState::Paused => "paused",
                        _ => "running",
                    }
                )));
            }
            sources.push(vm);
        }
        let hypervisor = sources.first().map(|s| s.hypervisor).unwrap_or_default();
        if sources.iter().any(|s| s.hypervisor != hypervisor) {
            problems.push(problem("Clone the VMs of one hypervisor at a time."));
        }
        let pattern = request.naming_pattern.trim();
        let numbered = templates::pattern_numbers(pattern);
        let today = crate::catalog::today();
        let mut taken: HashSet<String> = self
            .store
            .list_vms(ctx)
            .await?
            .into_iter()
            .map(|vm| vm.display_name.to_lowercase())
            .collect();
        let mut vms = Vec::new();
        for source in &sources {
            let mut name = None;
            let last = if numbered { taken.len() as u32 + 2 } else { 1 };
            for n in 1..=last {
                let candidate = templates::expand(pattern, &source.display_name, n, today)?;
                if taken.insert(candidate.to_lowercase()) {
                    name = Some((n, candidate));
                    break;
                }
            }
            match name {
                Some((n, name)) => vms.push(DeployVm {
                    number: n,
                    hostname: templates::hostname(&name, n),
                    name,
                    clone_of: Some((source.vmx_path.clone(), source.display_name.clone())),
                }),
                None => problems.push(Problem {
                    code: ProblemCode::NameTaken,
                    message: format!(
                        "The pattern names the clone of {} as a VM that is here already; add {{n}} to number it.",
                        source.display_name
                    ),
                }),
            }
        }
        if !problems.is_empty() {
            return Ok(Err(problems));
        }
        let folder = match request.folder.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
            Some(folder) => {
                if let Some(why) = crate::catalog::images::folder_problem(folder) {
                    return Err(CoreError::InvalidInput(why));
                }
                with_backslashes(Path::new(folder)).display().to_string()
            }
            None => self.default_folder(hypervisor).await?,
        };
        let environment = request.environment.unwrap_or_else(|| {
            sources
                .iter()
                .map(|s| s.environment)
                .max_by_key(|e| match e {
                    Environment::Prod => 3,
                    Environment::Staging => 2,
                    Environment::Lab => 1,
                    Environment::None => 0,
                })
                .unwrap_or_default()
        });
        let spec = DeploySpec {
            origin: DeployOrigin::BulkClone,
            hypervisor,
            source: DeploySource::BulkClone,
            folder,
            profile: None,
            size: None,
            network: None,
            host_adapter: None,
            first_boot: None,
            ssh_key_id: None,
            environment,
            tags: Vec::new(),
            after_deploy: AfterDeploy {
                create_session: false,
                link_session: false,
                clean_snapshot: false,
                open_console: false,
            },
            ip_wait_secs: DEFAULT_IP_WAIT_SECS,
            vms,
        };
        spec.validate()?;
        Ok(Ok(spec))
    }

    /// VM-10: the Clone dialog's check. A read.
    pub async fn check_clone(&self, ctx: &Context, request: &CloneRequest) -> Result<DeployCheck> {
        match self.clone_spec(ctx, request).await? {
            Err(problems) => Ok(DeployCheck {
                problems,
                preview: None,
            }),
            Ok(spec) => Ok(DeployCheck {
                problems: Vec::new(),
                preview: Some(preview(&spec, &self.hypervisors, self.host.as_ref()).await),
            }),
        }
    }

    /// VM-10: submits the bulk clone to the bus, as one job.
    pub async fn submit_clone(&self, ctx: &Context, request: &CloneRequest) -> Result<SubmitOutcome> {
        match self.clone_spec(ctx, request).await? {
            Ok(spec) => self.submit_spec(ctx, spec).await,
            Err(problems) => Err(refused(problems.into_iter().map(|p| p.message).collect())),
        }
    }
}

fn refused(reasons: Vec<String>) -> CoreError {
    CoreError::InvalidInput(reasons.join(" "))
}
