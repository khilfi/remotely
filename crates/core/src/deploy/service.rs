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

mod import;
pub use import::{ImportCloudInit, ImportRequest};

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
    /// VirtualBox, an ISO it can install by itself: the vault password its guest user gets. `None`: the VM boots the
    /// ISO and the OS is installed from the console.
    #[serde(default)]
    pub guest_password_id: Option<crate::vault::SecretId>,
    /// VM-29: with an install config, each VM's row (in the order the VMs are named): `{{ip}}` and own variables.
    #[serde(default)]
    pub vm_values: Vec<super::spec::VmInstall>,
    /// VM-32: the address pool each VM's `{{ip}}` comes from.
    #[serde(default)]
    pub address_pool_id: Option<Uuid>,
    /// VM-29: how long the install watcher waits for each VM (`None`: an hour).
    #[serde(default)]
    pub install_minutes: Option<u32>,
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
    /// VM-26: RAM, CPU and disk on this PC after the deploy, next to now; with the preview.
    pub capacity: Option<crate::capacity_plan::DeployCapacity>,
    /// VM-29: the VMs the deploy names, also while it has problems (the Deploy dialog's rows of values per VM).
    #[serde(default)]
    pub vm_names: Vec<String>,
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
    /// VM-26: the capacity planner's reads.
    capacity: Arc<crate::capacity::CapacityChecker>,
    /// CV-01: the conversion tools, for imports.
    converter: Option<Arc<crate::convert::Converter>>,
    /// VM-32: where a deploy's addresses come from.
    pools: Option<Arc<crate::address_pools::AddressPools>>,
}

impl Deploys {
    pub fn new(
        store: Store,
        catalog: Catalog,
        hypervisors: Hypervisors,
        host: Arc<dyn HostCounters>,
        bus: Arc<CommandBus>,
    ) -> Self {
        let capacity = Arc::new(crate::capacity::CapacityChecker::new(
            store.clone(),
            hypervisors.clone(),
            Arc::clone(&host),
        ));
        Self {
            store,
            catalog,
            hypervisors,
            host,
            bus,
            capacity,
            converter: None,
            pools: None,
        }
    }

    /// VM-32: deploys with an install config take their addresses from these pools.
    pub fn with_address_pools(mut self, pools: Arc<crate::address_pools::AddressPools>) -> Self {
        self.pools = Some(pools);
        self
    }

    /// CV-01: imports read their disks' formats and plans with these tools.
    pub fn with_converter(mut self, converter: Arc<crate::convert::Converter>) -> Self {
        self.converter = Some(converter);
        self
    }

    /// VM-26: this PC after the deploy of `spec` (whose preview is `preview`), next to now. A read.
    pub async fn capacity(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
        preview: &DeployPreview,
    ) -> crate::capacity_plan::DeployCapacity {
        let demands = crate::capacity_plan::deploy_demands(spec, preview);
        self.capacity.deploy_capacity(ctx, &demands).await
    }

    /// VM-26: this PC after a deploy of `demands` (VM-08: a stack's every step). A read.
    pub(crate) async fn plan_capacity(
        &self,
        ctx: &Context,
        demands: &[crate::capacity_plan::VmDemand],
    ) -> crate::capacity_plan::DeployCapacity {
        self.capacity.deploy_capacity(ctx, demands).await
    }

    /// The deploy's AP-02 preview, and VM-26's capacity after it.
    pub(crate) async fn preview_spec(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
    ) -> (DeployPreview, crate::capacity_plan::DeployCapacity) {
        let preview = preview(spec, &self.hypervisors, self.host.as_ref()).await;
        let capacity = self.capacity(ctx, spec, &preview).await;
        (preview, capacity)
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

    /// VirtualBox's host-only or bridged adapter for the network: the one asked for when VirtualBox has it, else the
    /// first; `None` for a network that needs none.
    async fn host_adapter_for(
        &self,
        hypervisor: Hypervisor,
        network: &Network,
        asked: Option<&str>,
    ) -> std::result::Result<Option<String>, Problem> {
        match (hypervisor, network) {
            (Hypervisor::VirtualBox, Network::HostOnly | Network::Bridged) => {
                let bridged = *network == Network::Bridged;
                let known = self.host_adapters(bridged).await.unwrap_or_default();
                match asked {
                    Some(asked) if known.iter().any(|k| k == asked) => Ok(Some(asked.to_owned())),
                    Some(asked) => Err(problem(format!(
                        "VirtualBox has no {} adapter named '{asked}'.",
                        if bridged { "network" } else { "host-only" }
                    ))),
                    None => match known.into_iter().next() {
                        Some(first) => Ok(Some(first)),
                        None => Err(problem(if bridged {
                            "VirtualBox lists no network adapter to bridge to."
                        } else {
                            "VirtualBox has no host-only network yet: add one in VirtualBox (File, Tools, Network Manager)."
                        })),
                    },
                }
            }
            _ => Ok(None),
        }
    }

    /// The spec a request makes, or why it can't make one.
    async fn spec_for(
        &self,
        ctx: &Context,
        request: &DeployRequest,
    ) -> Result<std::result::Result<DeploySpec, Vec<Problem>>> {
        self.spec_for_taken(ctx, request, &[]).await
    }

    /// [`Self::spec_for`], numbering past `also_taken` too (VM-08: the names a stack's earlier steps give).
    pub(crate) async fn spec_for_taken(
        &self,
        ctx: &Context,
        request: &DeployRequest,
        also_taken: &[String],
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
        let plan = match self
            .catalog
            .plan_input_taken(ctx, id, &input, request.count, also_taken)
            .await?
        {
            Ok(plan) => plan,
            Err(problems) => return Ok(Err(problems)),
        };
        let folder = match &plan.vm_folder {
            Some(folder) => with_backslashes(Path::new(folder)).display().to_string(),
            None => self.default_folder(plan.hypervisor).await?,
        };
        let host_adapter = match self
            .host_adapter_for(plan.hypervisor, &plan.network, request.host_adapter.as_deref())
            .await
        {
            Ok(adapter) => adapter,
            Err(problem) => return Ok(Err(vec![problem])),
        };
        let mut spec = DeploySpec::from_plan(&plan, origin, folder, host_adapter);
        // VM-29: an install config's install: what it delivers, each VM's values and address.
        if let Some(config) = &plan.install_config {
            if let Err(problems) = self.install_spec(ctx, &plan, config, request, &mut spec).await? {
                return Ok(Err(problems));
            }
        } else if request.address_pool_id.is_some() {
            return Ok(Err(vec![install_problem(
                "An address pool gives addresses to an install config's VMs: the template has no install config.",
            )]));
        }
        if let Some(password_id) = request.guest_password_id {
            match self
                .unattended(ctx, &spec, password_id, plan.guest_user.as_deref())
                .await?
            {
                Ok(unattended) => spec.unattended = Some(unattended),
                Err(problem) => return Ok(Err(vec![problem])),
            }
        }
        spec.validate()?;
        Ok(Ok(spec))
    }

    /// VirtualBox's unattended install of the spec's ISO, with the guest user and this vault password; or why not.
    async fn unattended(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
        password_id: crate::vault::SecretId,
        user: Option<&str>,
    ) -> Result<std::result::Result<super::spec::UnattendedSpec, Problem>> {
        let DeploySource::Iso { path } = &spec.source else {
            return Ok(Err(problem("Only an ISO install takes a guest password.")));
        };
        if spec.hypervisor != Hypervisor::VirtualBox {
            return Ok(Err(problem(
                "Workstation installs from an ISO through its console; only VirtualBox installs one by itself.",
            )));
        }
        let Some(user) = user else {
            return Ok(Err(problem(
                "An unattended install needs a guest user: set one in the template (or Custom).",
            )));
        };
        match self.store.vault_item_kind(ctx, password_id).await? {
            Some(crate::vault::SecretKind::Password) => {}
            Some(_) => return Ok(Err(problem("The guest password must be a vault password."))),
            None => return Ok(Err(problem("That guest password is not in the vault."))),
        }
        let (supported, detected) = self
            .hypervisors
            .virtualbox()
            .unattended_detect(Path::new(path))
            .await
            .unwrap_or((false, None));
        if !supported {
            return Ok(Err(problem(format!(
                "VirtualBox can't install {path} by itself: deploy it without a guest password and install it from the console."
            ))));
        }
        // VM-21: the OS VirtualBox reads on the ISO must be the image's OS profile's (Ubuntu24_64 is Ubuntu_64's).
        if let (Some(detected), Some(profile)) = (detected.as_deref(), &spec.profile) {
            if os_family(detected) != os_family(&profile.guest_os) {
                return Ok(Err(problem(format!(
                    "VirtualBox reads {path} as {detected}, and the image's OS profile is {} ({}): fix the image's profile, or pick the right ISO.",
                    profile.name, profile.guest_os
                ))));
            }
        }
        Ok(Ok(super::spec::UnattendedSpec {
            user: user.to_owned(),
            password_id,
        }))
    }

    /// The Deploy dialog's check: why it can't deploy, or its AP-02 preview. A read.
    pub async fn check(&self, ctx: &Context, request: &DeployRequest) -> Result<DeployCheck> {
        match self.spec_for(ctx, request).await? {
            Err(problems) => Ok(DeployCheck {
                problems,
                preview: None,
                capacity: None,
                vm_names: self.planned_names(ctx, request).await,
            }),
            Ok(spec) => {
                spec.require_sources_here(&self.store, ctx).await?;
                let (preview, capacity) = self.preview_spec(ctx, &spec).await;
                Ok(DeployCheck {
                    problems: Vec::new(),
                    vm_names: spec.vms.iter().map(|vm| vm.name.clone()).collect(),
                    preview: Some(preview),
                    capacity: Some(capacity),
                })
            }
        }
    }

    /// VM-29: the names a request's plan gives its VMs, when it resolves (its install's values aside).
    async fn planned_names(&self, ctx: &Context, request: &DeployRequest) -> Vec<String> {
        let (id, mut input) = match &request.from {
            DeployFrom::Template { id } => match self.catalog.template(ctx, *id).await {
                Ok(t) => (*id, t.spec),
                Err(_) => return Vec::new(),
            },
            DeployFrom::Custom { input } => (Uuid::nil(), (**input).clone()),
        };
        if let Some(pattern) = request
            .naming_pattern
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            input.naming_pattern = pattern.to_owned();
        }
        input.default_count = request.count;
        match self.catalog.plan_input(ctx, id, &input, request.count).await {
            Ok(Ok(plan)) => plan.vms.into_iter().map(|vm| vm.name).collect(),
            _ => Vec::new(),
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
        spec.require_sources_here(&self.store, ctx).await?;
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
            // FD-02: only this workspace's VMs are cloned (one taken out still has its row here).
            self.store.require_vm_here(ctx, key).await?;
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
                    install: None,
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
            unattended: None,
            install: None,
            vms,
            stack: None,
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
                capacity: None,
                vm_names: Vec::new(),
            }),
            Ok(spec) => {
                let (preview, capacity) = self.preview_spec(ctx, &spec).await;
                Ok(DeployCheck {
                    problems: Vec::new(),
                    preview: Some(preview),
                    capacity: Some(capacity),
                    vm_names: Vec::new(),
                })
            }
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

fn install_problem(message: impl Into<String>) -> Problem {
    Problem {
        code: ProblemCode::InstallConfigProblems,
        message: message.into(),
    }
}

/// VirtualBox's OS type id without its version and bits: `Ubuntu24_64` and `Ubuntu_64` are both `ubuntu`.
fn os_family(os_type: &str) -> String {
    os_type
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// VM-32: an address pool's gateway, DNS servers and prefix fill the config's own variables of those names, where a
/// VM's row leaves them empty.
fn pool_values(
    config: &crate::catalog::install::InstallConfigInput,
    address: &crate::address_pools::PoolAddress,
    values: &mut std::collections::BTreeMap<String, String>,
) {
    let netmask = u32::MAX
        .checked_shl(32 - u32::from(address.prefix.min(32)))
        .map_or(std::net::Ipv4Addr::UNSPECIFIED, std::net::Ipv4Addr::from);
    let dns: Vec<String> = address.dns.iter().map(ToString::to_string).collect();
    for (name, value) in [
        ("gateway", address.gateway.map(|g| g.to_string())),
        ("dns", (!dns.is_empty()).then(|| dns.join(","))),
        ("prefix", Some(address.prefix.to_string())),
        ("netmask", Some(netmask.to_string())),
    ] {
        if let Some(value) = value {
            if config.variables.iter().any(|v| v.name == name) && !values.contains_key(name) {
                values.insert(name.to_owned(), value);
            }
        }
    }
}

impl Deploys {
    /// VM-29: the install a template's install config makes, into `spec`: what Remotely delivers, the firmware and
    /// disk layout agreeing, the ISO's layout what the spikes saw, and each VM's values and address (VM-32: from the
    /// pool, checked free now). Problems in words when it can't.
    async fn install_spec(
        &self,
        ctx: &Context,
        plan: &crate::catalog::templates::DeployPlan,
        config: &crate::catalog::install::InstallConfig,
        request: &DeployRequest,
        spec: &mut DeploySpec,
    ) -> Result<std::result::Result<(), Vec<Problem>>> {
        use super::install::Flavor;
        use crate::catalog::install::{render, unattend, SecretRefKind};
        use crate::catalog::profiles::Firmware;
        let kind = config.spec.kind;
        let Some(flavor) = Flavor::of(kind) else {
            return Ok(Err(vec![install_problem(format!(
                "Remotely doesn't install from {} configs yet: only Ubuntu autoinstall, Debian preseed and Windows unattend were tried by hand.",
                kind.label()
            ))]));
        };
        let DeploySource::Iso { path } = &spec.source else {
            return Ok(Err(vec![install_problem(
                "An install config installs from an ISO image.",
            )]));
        };
        let path = path.clone();
        let mut problems = Vec::new();
        if request.guest_password_id.is_some() {
            problems.push(install_problem(
                "The install config installs the VMs: leave VirtualBox's own unattended install (the guest password) out.",
            ));
        }
        // S3: Setup on UEFI wants a GPT layout, and on BIOS stops at the disk page with one.
        if flavor.windows() {
            match (unattend::disk_style(&config.spec.body), plan.profile.firmware) {
                (Some(unattend::DiskStyle::Gpt), Firmware::Bios) => problems.push(install_problem(format!(
                    "The install config lays the disk out for UEFI (GPT), and the OS profile {} starts with BIOS: Setup would stop at the disk page.",
                    plan.profile.name
                ))),
                (Some(unattend::DiskStyle::Mbr), Firmware::Efi | Firmware::EfiSecureBoot) => problems.push(install_problem(format!(
                    "The install config lays the disk out for BIOS (no EFI partition), and the OS profile {} starts with UEFI: Setup would stop at the disk page.",
                    plan.profile.name
                ))),
                _ => {}
            }
            if !config.spec.body.contains(unattend::WINRM_FINGERPRINT_MARKER) {
                problems.push(install_problem(
                    "The install config doesn't write its WinRM certificate's fingerprint to COM1, so Remotely can't check the certificate before it sets the Administrator's password: copy the starter's first sign-in commands.",
                ));
            }
        }
        // Remotely must reach the installed system to say it is done (Windows: to set its password).
        let uses_ip = render::uses_ip(&config.spec);
        // Workstation leases its NAT and host-only addresses itself (vmnetdhcp.leases); VirtualBox's NAT gets a rule.
        let reachable_without_pool = matches!(
            (plan.hypervisor, &plan.network),
            (
                Hypervisor::Vmware,
                Network::Nat | Network::HostOnly | Network::Vmnet { .. }
            ) | (Hypervisor::VirtualBox, Network::Nat)
        );
        let mut addresses = Vec::new();
        let mut pool_ref = None;
        match request.address_pool_id {
            Some(pool_id) => {
                let Some(pools) = &self.pools else {
                    return Err(CoreError::NotImplemented("address pools"));
                };
                let fitting = pools.pools_for(ctx, plan.hypervisor, &plan.network).await?;
                match fitting.iter().find(|p| p.id == pool_id) {
                    None => problems.push(install_problem(format!(
                        "That address pool isn't for {} on {}.",
                        templates::hypervisor_label(plan.hypervisor),
                        plan.network.describe()
                    ))),
                    Some(pool) => {
                        if !uses_ip {
                            problems.push(install_problem(format!(
                                "The install config doesn't use {{{{ip}}}}, so the VMs wouldn't take the address pool '{}''s addresses.",
                                pool.name
                            )));
                        }
                        pool_ref = Some(super::spec::PoolRef {
                            id: pool.id,
                            name: pool.name.clone(),
                        });
                        match pools.pick(ctx, pool_id, spec.vms.len(), &[]).await {
                            Ok(picked) => addresses = picked,
                            Err(err) => problems.push(install_problem(err.to_string())),
                        }
                    }
                }
            }
            None if flavor.windows() && !reachable_without_pool => problems.push(install_problem(format!(
                "On {} Remotely can't learn a new Windows VM's address before it is reached, so it couldn't set its password: give the VMs addresses from an address pool.",
                plan.network.describe()
            ))),
            None => {}
        }
        let template = match &spec.origin {
            super::spec::DeployOrigin::Template { name, .. } | super::spec::DeployOrigin::Custom { name } => {
                name.clone()
            }
            _ => String::new(),
        };
        for (i, vm) in spec.vms.iter_mut().enumerate() {
            let row = request.vm_values.get(i).cloned().unwrap_or_default();
            let mut values: std::collections::BTreeMap<String, String> = row
                .values
                .into_iter()
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
                .filter(|(k, v)| !k.is_empty() && !v.is_empty())
                .collect();
            let ip = match addresses.get(i) {
                Some(address) => {
                    pool_values(&config.spec, address, &mut values);
                    Some(address.ip.to_string())
                }
                None => row.ip.map(|ip| ip.trim().to_owned()).filter(|ip| !ip.is_empty()),
            };
            let check = render::VmValues {
                hostname: vm.hostname.clone(),
                ip: ip.clone(),
                n: vm.number,
                template: template.clone(),
                date: crate::catalog::today(),
                values: values.clone(),
            };
            if let Err(err) = render::check_values(&config.spec, &check) {
                problems.push(install_problem(format!("{}: {err}", vm.name)));
            }
            vm.install = Some(super::spec::VmInstall { ip, values });
        }
        let password_ids: Vec<crate::vault::SecretId> = config
            .spec
            .secrets
            .iter()
            .filter(|s| s.kind == SecretRefKind::Password)
            .filter_map(|s| s.secret_id)
            .collect();
        let key_id = config
            .spec
            .secrets
            .iter()
            .find(|s| s.kind == SecretRefKind::SshKey)
            .and_then(|s| s.secret_id);
        // The ISO's layout must be what the spikes saw, read now (the copy is made by the job).
        let iso_flavor = flavor.iso();
        let iso_path = path.clone();
        let planned = tokio::task::spawn_blocking(move || super::iso::plan_file(Path::new(&iso_path), iso_flavor))
            .await
            .map_err(|err| CoreError::InvalidInput(format!("the ISO couldn't be read: {err}")))?;
        if let Err(err) = planned {
            problems.push(install_problem(format!("The ISO {path} can't be prepared: {err}")));
        }
        if !problems.is_empty() {
            return Ok(Err(problems));
        }
        let minutes = request
            .install_minutes
            .unwrap_or(super::spec::DEFAULT_INSTALL_MINUTES)
            .clamp(1, super::spec::MAX_INSTALL_MINUTES);
        spec.install = Some(super::spec::InstallSpec {
            config_id: Uuid::parse_str(&config.id)
                .map_err(|_| CoreError::InvalidInput("A starter is copied before it deploys.".into()))?,
            config_name: config.spec.name.clone(),
            kind,
            fingerprint: super::spec::config_fingerprint(&config.spec),
            password_ids,
            key_id,
            time_limit_minutes: minutes,
            pool: pool_ref,
        });
        if key_id.is_some() {
            spec.ssh_key_id = key_id;
        }
        Ok(Ok(()))
    }
}
