//! VM-30: [`GoldenImages`] (`Core.golden`), what the Templates page's Images tab and the scheduler call: the build
//! dialog's check, a build or a rebuild submitted to the bus as [`Command::ImageBuild`], an image's build settings and
//! its versions. It never changes a VM itself. [`ImageBuildActions`] is the job runner's side: a built version
//! registered as the image's newest, and the old versions its retention may delete.
//!
//! A build's VM is planned exactly as the Deploy dialog's Custom plans a VM ([`crate::deploy::service::Deploys`]): a
//! launch template's fields made from the recipe (the ISO image, the size, the hypervisor, the network, the folder,
//! the install config; no session, console or snapshot of its own), one VM named `<image>-v<N>`, with the config's own
//! values. So the build's install is G6's, refusals and all, and what is approved is what runs.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::spec::{self, BuildOs, BuildRecipe, BuildSpec, PruneVm, SignIn, DEFAULT_SEAL_MINUTES, MAX_KEEP_VERSIONS};
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::catalog::install::{self, SecretRefKind};
use crate::catalog::templates::{AfterDeploy, CloneMode, TemplateInput};
use crate::catalog::{Catalog, ImageKind, ImageSource};
use crate::command_bus::{Command, CommandBus, SubmitOutcome};
use crate::deploy::service::{DeployFrom, DeployRequest, Deploys};
use crate::deploy::spec::{DeploySource, VmInstall};
use crate::domain::{Context, Environment};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{NewAuditEntry, NewVersion, Store, VersionRow};
use crate::vault::SecretId;

/// How the audit log names a change to the catalogue (VM-19's own event).
const EVENT: &str = "catalog_changed";

/// What a build makes a version of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum BuildTarget {
    /// A new image of this name: its first build makes it.
    New { name: String },
    /// An image Remotely builds: its next version.
    Image { id: Uuid },
}

/// What the build dialog sends (and a rebuild, with the image's own recipe).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildRequest {
    pub target: BuildTarget,
    pub recipe: BuildRecipe,
}

/// The build dialog's preview: what the build makes and does, the build VM's deploy preview and this PC after it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildPreview {
    pub details: super::spec::BuildDetails,
    pub deploy: crate::deploy::preview::DeployPreview,
    pub capacity: crate::capacity_plan::DeployCapacity,
    /// What to read before building (a clone's first boot that won't set the guest up, retention...).
    pub warnings: Vec<String>,
}

/// The build dialog's answer while it is filled in: why it can't build, or what it would build.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildCheck {
    pub problems: Vec<String>,
    pub preview: Option<BuildPreview>,
}

/// What the deploy runner made of a build: the version's VM and its snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub vm_key: String,
    pub vm_name: String,
    /// Workstation's `snapshotN.uid`, or VirtualBox's snapshot UUID.
    pub snapshot_id: String,
    pub snapshot_name: String,
    /// What making it generic found (JSON).
    pub facts: serde_json::Value,
    /// What each step did, for the job's note.
    pub notes: Vec<String>,
}

/// Where a version stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VersionState {
    /// What the image's templates deploy.
    Newest,
    /// An older one, still there.
    Kept,
    /// Its VM was deleted (retention, or by hand).
    Deleted,
}

/// One version, as the Images tab's versions list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageVersion {
    pub id: Uuid,
    pub number: u32,
    pub state: VersionState,
    pub hypervisor: Hypervisor,
    pub vm_key: String,
    pub vm_name: String,
    pub snapshot_name: String,
    pub config_name: String,
    pub built_at: String,
    pub deleted_at: Option<String>,
    /// The linked clones made from it (a version with any is never deleted).
    pub linked_clones: Vec<String>,
    /// Why its clones couldn't be looked up, if they couldn't.
    pub clones_unread: Option<String>,
    /// What making it generic found: `cloudInit`, `vmTools` (true, false or null: not said).
    pub facts: serde_json::Value,
}

/// VM-30: the job runner's side of a build.
#[async_trait]
pub trait ImageBuildActions: Send + Sync {
    /// C1 of PR 100's review: the build of `spec` starts: refused while another build of its image (or of a new image
    /// of its name) runs, or when a version at least as new as its own, or an image of its new name, was made since it
    /// was planned. The image counts as being built until the guard is dropped.
    async fn begin(&self, ctx: &Context, job_id: Uuid, spec: &BuildSpec) -> Result<BuildGuard>;
    /// The built VM recorded as one of the image's versions (a first build makes the image), audited; the image
    /// moves to it only when it is the newest. Returns what the job says about it.
    async fn register(&self, ctx: &Context, job_id: Uuid, spec: &BuildSpec, built: &Built) -> Result<String>;
    /// A version's VM was deleted (or found gone): recorded and audited.
    async fn version_deleted(&self, ctx: &Context, version: &VersionRow, job_id: Uuid, why: &str) -> Result<()>;
}

/// The builds running now: the job, by `image:<id>` and a new image's `name:<lower-case name>`.
type Building = Arc<std::sync::Mutex<std::collections::HashMap<String, Uuid>>>;

/// An image being built: its keys leave [`Building`] when this is dropped (the build's step ended).
pub struct BuildGuard {
    building: Building,
    keys: Vec<String>,
}

impl Drop for BuildGuard {
    fn drop(&mut self) {
        let mut building = crate::locks::lock(&self.building);
        for key in &self.keys {
            building.remove(key);
        }
    }
}

fn building_keys(image_id: Uuid, name: &str) -> [String; 2] {
    [format!("image:{image_id}"), format!("name:{}", name.to_lowercase())]
}

/// Q1 of PR 100's review: whether the approval a build runs under still stands. A scheduled build asks it while it
/// waits for the vault, so a schedule edited, paused or deleted meanwhile (its standing approval withdrawn) builds
/// nothing.
#[async_trait]
pub trait StillApproved: Send + Sync {
    async fn check(&self) -> Result<()>;
}

/// The job runner's [`StillApproved`]: a build approved in the dialog always stands; a scheduled one while its grant
/// isn't withdrawn and its schedule is active.
pub struct StandingCheck {
    store: Store,
    ctx: Context,
    standing: Option<crate::command_bus::StandingUse>,
}

impl StandingCheck {
    pub fn new(store: Store, ctx: Context, standing: Option<crate::command_bus::StandingUse>) -> Self {
        Self { store, ctx, standing }
    }
}

#[async_trait]
impl StillApproved for StandingCheck {
    async fn check(&self) -> Result<()> {
        let Some(standing) = &self.standing else {
            return Ok(());
        };
        let withdrawn = || {
            CoreError::ApprovalRejected(format!(
                "{}'s approval was withdrawn while the build waited (the schedule was edited, paused or deleted): nothing was built",
                standing.label
            ))
        };
        if self
            .store
            .standing_approval(&self.ctx, standing.approval_id)
            .await?
            .is_none()
        {
            return Err(withdrawn());
        }
        match self.store.schedule(&self.ctx, standing.schedule_id).await? {
            Some(row) if row.state == crate::schedules::ScheduleState::Active => Ok(()),
            _ => Err(withdrawn()),
        }
    }
}

/// The golden image service (`Core.golden`).
#[derive(Clone)]
pub struct GoldenImages {
    store: Store,
    catalog: Catalog,
    deploys: Deploys,
    bus: Arc<CommandBus>,
    hypervisors: Hypervisors,
    building: Building,
}

/// The config's own vault id for a `{{password.<name>}}` or `{{ssh_key.<name>}}` placeholder.
fn picked(config: &install::InstallConfigInput, kind: SecretRefKind, placeholder: &str) -> Option<SecretId> {
    let prefix = match kind {
        SecretRefKind::Password => "{{password.",
        SecretRefKind::SshKey => "{{ssh_key.",
    };
    let name = placeholder.trim().strip_prefix(prefix)?.strip_suffix("}}")?;
    config
        .secrets
        .iter()
        .find(|s| s.kind == kind && s.name == name)
        .and_then(|s| s.secret_id)
}

/// How the build signs in to its VM, from the config: Linux, its first user's key and password; Windows, the first
/// account whose one-time password the deploy replaces with the vault's.
fn sign_in(
    config: &install::InstallConfigInput,
    os: BuildOs,
    key_id: Option<SecretId>,
) -> std::result::Result<SignIn, String> {
    if os.windows() {
        let accounts = install::unattend::password_accounts(&config.body);
        let Some((name, account)) = accounts.first() else {
            return Err(format!(
                "The install config '{}' gives no account a password, so Remotely couldn't sign in to make the VM generic.",
                config.name
            ));
        };
        let password_id =
            picked(config, SecretRefKind::Password, &format!("{{{{password.{name}}}}}")).ok_or_else(|| {
                format!(
                    "{{{{password.{name}}}}} isn't picked from the vault in the install config '{}'.",
                    config.name
                )
            })?;
        return Ok(SignIn::Winrm {
            account: account.clone(),
            password_id,
        });
    }
    let form = install::read_form(config.kind, &config.body).form;
    let Some(user) = form.users.first() else {
        return Err(format!(
            "The install config '{}' makes no user, so Remotely couldn't sign in to make the VM generic.",
            config.name
        ));
    };
    if user.name.contains("{{") {
        return Err(format!(
            "The install config '{}''s first user is named by a variable: name it, so the build knows whom to sign in as.",
            config.name
        ));
    }
    // A preseed gives the user its key in a late command, which the form doesn't read: the config's own key then.
    let key = user
        .ssh_keys
        .iter()
        .find_map(|k| picked(config, SecretRefKind::SshKey, k))
        .or(key_id.filter(|_| user.ssh_keys.is_empty()));
    let Some(key) = key else {
        return Err(format!(
            "The build signs in as {} with an SSH key from the vault: give that user one in the install config '{}' ({{{{ssh_key.<name>}}}}).",
            user.name, config.name
        ));
    };
    if key_id != Some(key) {
        return Err(format!(
            "The build signs in as {} with the first SSH key the install config '{}' picks: give that user that key.",
            user.name, config.name
        ));
    }
    let sudo_password_id = user
        .password
        .as_deref()
        .and_then(|p| picked(config, SecretRefKind::Password, p));
    Ok(SignIn::Ssh {
        user: user.name.clone(),
        key_id: key,
        sudo_password_id,
    })
}

impl GoldenImages {
    pub fn new(
        store: Store,
        catalog: Catalog,
        deploys: Deploys,
        bus: Arc<CommandBus>,
        hypervisors: Hypervisors,
    ) -> Self {
        Self {
            store,
            catalog,
            deploys,
            bus,
            hypervisors,
            building: Arc::default(),
        }
    }

    /// The job building the image (or a new image of this name) now, if one is.
    fn building(&self, image_id: Uuid, name: &str) -> Option<Uuid> {
        let building = crate::locks::lock(&self.building);
        building_keys(image_id, name)
            .iter()
            .find_map(|key| building.get(key).copied())
    }

    /// The build a request makes, or why it can't make one (in words).
    async fn spec_for(
        &self,
        ctx: &Context,
        request: &BuildRequest,
    ) -> Result<std::result::Result<BuildSpec, Vec<String>>> {
        let recipe = &request.recipe;
        let mut problems = Vec::new();
        if recipe.keep.is_some_and(|k| !(1..=MAX_KEEP_VERSIONS).contains(&k)) {
            problems.push(format!("Keep 1 to {MAX_KEEP_VERSIONS} versions, or every version."));
        }
        let images = self.catalog.images(ctx).await?;
        let (image_id, image_new, image_name, image_profile) = match &request.target {
            BuildTarget::New { name } => {
                let name = crate::catalog::images::clean_image_name(name)?;
                if images.iter().any(|i| i.name.eq_ignore_ascii_case(&name)) {
                    problems.push(format!("An image named '{name}' is there already: pick another name."));
                }
                (Uuid::new_v4(), true, name, None)
            }
            BuildTarget::Image { id } => {
                let Some(image) = images.iter().find(|i| i.id == *id) else {
                    return Err(CoreError::UnknownTarget(format!("image {id}")));
                };
                if image.build.is_none() || image.kind() != ImageKind::GoldenVm {
                    return Ok(Err(vec![format!(
                        "Image '{}' isn't one Remotely builds: build a new image instead.",
                        image.name
                    )]));
                }
                (image.id, false, image.name.clone(), Some(image.os_profile.clone()))
            }
        };
        // The ISO it installs from, and so the OS profile its clones deploy with.
        let Some(iso) = images.iter().find(|i| i.id == recipe.iso_image_id) else {
            return Ok(Err(vec!["The build's ISO image was deleted: pick another.".into()]));
        };
        let ImageSource::Iso { .. } = &iso.source else {
            return Ok(Err(vec![format!("Image '{}' isn't an ISO.", iso.name)]));
        };
        if let Some(problem) = &iso.problem {
            problems.push(format!("The ISO image '{}': {problem}", iso.name));
        }
        if let Some(profile) = &image_profile {
            if *profile != iso.os_profile {
                problems.push(format!(
                    "Image '{image_name}' deploys as {profile}, and the ISO image '{}' is {}: pick an ISO of the same system, or build a new image.",
                    iso.name, iso.os_profile
                ));
            }
        }
        // The install config: an own one of a kind Remotely delivers.
        let config = match self
            .catalog
            .install_config(ctx, &recipe.install_config_id.to_string())
            .await
        {
            Ok(config) => config,
            Err(CoreError::UnknownTarget(_)) => {
                return Ok(Err(
                    vec!["The build's install config was deleted: pick another.".into()],
                ))
            }
            Err(err) => return Err(err),
        };
        let Some(os) = BuildOs::of(config.spec.kind) else {
            return Ok(Err(vec![format!(
                "The install config '{}' is {}: Remotely builds images from Ubuntu autoinstall, Debian preseed and Windows unattend configs.",
                config.spec.name,
                config.spec.kind.label()
            )]));
        };
        // A2 of PR 100's review: an address of the build VM's own would go into every clone (and stay leased to the
        // version's VM), so a build takes its address by DHCP.
        if recipe.address_pool_id.is_some() {
            problems.push(
                "A golden image's VM takes its address by DHCP: an address from a pool would go into every clone. Leave the address pool out."
                    .into(),
            );
        }
        if install::render::uses_ip(&config.spec) {
            problems.push(format!(
                "The install config '{}' gives the VM a fixed address ({{{{ip}}}}), which every clone would take: build from a config whose network is DHCP.",
                config.spec.name
            ));
        }
        // The next version, and a VM name and folder nothing has yet.
        let mut version = if image_new {
            1
        } else {
            self.store.next_image_version(ctx, image_id).await?
        };
        let folder = match &recipe.vm_folder {
            Some(folder) => crate::adapters::vmware::with_backslashes(Path::new(folder))
                .display()
                .to_string(),
            None => self.deploys.default_folder(recipe.hypervisor).await?,
        };
        // B5 of PR 100's review: a share or device path never reaches the file system (A3).
        if let Some(problem) = crate::catalog::images::folder_problem(&folder) {
            problems.push(problem);
            return Ok(Err(problems));
        }
        let names: Vec<String> = self
            .store
            .list_vms(ctx)
            .await?
            .into_iter()
            .map(|vm| vm.display_name.to_lowercase())
            .collect();
        let mut vm_name = spec::version_vm_name(&image_name, os, version);
        for _ in 0..100 {
            let taken = names.contains(&vm_name.to_lowercase()) || Path::new(&folder).join(&vm_name).exists();
            if !taken {
                break;
            }
            version += 1;
            vm_name = spec::version_vm_name(&image_name, os, version);
        }
        if version > spec::MAX_VERSION {
            problems.push(format!("Image '{image_name}' has had {} versions.", spec::MAX_VERSION));
        }
        // C1 of PR 100's review: one build of an image at a time.
        if let Some(job) = self.building(image_id, &image_name) {
            problems.push(format!(
                "Image '{image_name}' is being built now (job {}): build it again once that build ends.",
                &job.to_string()[..8]
            ));
        }
        // B3 of PR 100's review: the versions its retention would delete are planned now, each a target of the build.
        let (prune, retained) = match recipe.keep {
            Some(keep) if !image_new => self.plan_prune(ctx, image_id, keep).await?,
            _ => (Vec::new(), Vec::new()),
        };
        let input = TemplateInput {
            name: image_name.clone(),
            image_id: iso.id,
            size_id: recipe.size_id.clone(),
            hypervisor: recipe.hypervisor,
            vm_folder: Some(folder),
            network: recipe.network.clone(),
            ssh_key_id: None,
            naming_pattern: vm_name.clone(),
            default_count: 1,
            environment: Environment::None,
            tags: Vec::new(),
            after_deploy: AfterDeploy {
                create_session: false,
                link_session: false,
                clean_snapshot: false,
                open_console: false,
            },
            guest_user: None,
            packages: Vec::new(),
            clone_mode: CloneMode::Full,
            install_config_id: Some(recipe.install_config_id),
        };
        let deploy_request = DeployRequest {
            from: DeployFrom::Custom { input: Box::new(input) },
            count: 1,
            naming_pattern: None,
            host_adapter: recipe.host_adapter.clone(),
            guest_password_id: None,
            vm_values: vec![VmInstall {
                ip: None,
                values: recipe.values.clone(),
            }],
            address_pool_id: recipe.address_pool_id,
            install_minutes: Some(recipe.install_minutes),
        };
        let deploy = match self.deploys.spec_for_taken(ctx, &deploy_request, &[]).await? {
            Ok(deploy) => deploy,
            Err(found) => {
                problems.extend(found.into_iter().map(|p| p.message));
                return Ok(Err(problems));
            }
        };
        let Some(install) = deploy.install.clone() else {
            problems.push("The build installs from the install config.".into());
            return Ok(Err(problems));
        };
        let sign_in = match sign_in(&config.spec, os, install.key_id) {
            Ok(sign_in) => sign_in,
            Err(problem) => {
                problems.push(problem);
                return Ok(Err(problems));
            }
        };
        if deploy.vms.first().map(|vm| vm.name.as_str()) != Some(vm_name.as_str()) {
            problems.push(format!("The build's VM couldn't be named {vm_name}."));
        }
        if !problems.is_empty() {
            return Ok(Err(problems));
        }
        let DeploySource::Iso { path } = &deploy.source else {
            return Ok(Err(vec!["A build installs from an ISO image.".into()]));
        };
        // The deploy's ISO is the ISO image's file (the plan took it from there).
        let iso_path = path.clone();
        let mut recipe = recipe.clone();
        recipe.install_minutes = install.time_limit_minutes;
        let spec = BuildSpec {
            image_id,
            image_new,
            image_name,
            os_profile: iso.os_profile.clone(),
            version,
            os,
            recipe,
            config_name: install.config_name.clone(),
            config_fingerprint: install.fingerprint.clone(),
            iso_path,
            iso_seen: install.iso_seen,
            seal_minutes: DEFAULT_SEAL_MINUTES,
            sign_in,
            deploy,
            prune,
            retained,
        };
        spec.validate()?;
        Ok(Ok(spec))
    }

    /// The older versions a build that keeps the newest `keep` would delete once it registered its own (its own is
    /// then the newest, so `keep - 1` of the others stay), and why it leaves others past `keep`: a VM that isn't
    /// this workspace's any more or is gone, or one a linked clone uses (VM-04: R3's delete would refuse it anyway).
    async fn plan_prune(&self, ctx: &Context, image_id: Uuid, keep: u32) -> Result<(Vec<PruneVm>, Vec<String>)> {
        let stay = usize::try_from(keep.saturating_sub(1)).unwrap_or(0);
        let versions = self.store.image_versions(ctx, image_id).await?;
        let linked = crate::linked_clones::LinkedClones::new(self.hypervisors.clone());
        let mut media = crate::linked_clones::VboxMedia::default();
        let (mut prune, mut retained) = (Vec::new(), Vec::new());
        for version in versions.into_iter().filter(|v| v.deleted_at.is_none()).skip(stay) {
            let n = version.number;
            if let Err(err) = self.store.require_vm_here(ctx, &version.vm_key).await {
                retained.push(format!("version {n} stays: {err}"));
                continue;
            }
            let Some(vm) = self.store.find_vm(ctx, &version.vm_key).await? else {
                retained.push(format!(
                    "version {n}'s VM {} is no longer in the VM list",
                    version.vm_name
                ));
                continue;
            };
            match linked.of_vm(&vm.vmx_path, &mut media).await {
                Ok(found) if found.iter().any(|s| !s.clones.is_empty()) => {
                    let names: Vec<String> = found
                        .iter()
                        .flat_map(|s| s.clones.iter().map(|c| c.name.clone()))
                        .collect();
                    retained.push(format!(
                        "version {n} stays: the linked clones {} use it",
                        names.join(", ")
                    ));
                }
                Ok(_) => prune.push(PruneVm {
                    number: n,
                    vm_key: vm.vmx_path.clone(),
                    vm_name: vm.display_name.clone(),
                }),
                Err(err) => retained.push(format!("version {n} stays: its linked clones couldn't be read ({err})")),
            }
        }
        Ok((prune, retained))
    }

    /// What a build's preview warns about: a clone's first boot that won't set the guest up, and retention.
    fn warnings(&self, spec: &BuildSpec, config_packages: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let has = |name: &str| config_packages.iter().any(|p| p.trim() == name);
        if spec.os == BuildOs::Debian && !has("cloud-init") {
            out.push(
                "This Debian config installs no cloud-init, so the image's clones keep this build's hostname, users and keys, and a launch template's guest user, SSH key and packages aren't set on them: add cloud-init to the config's packages (pkgsel/include) for that."
                    .into(),
            );
        }
        if spec.os == BuildOs::Ubuntu && spec.recipe.hypervisor == Hypervisor::Vmware && !has("open-vm-tools") {
            out.push(
                "On Workstation a clone's first boot reads cloud-init's settings through open-vm-tools, which ubuntu-server-minimal leaves out: add open-vm-tools to the config's packages, or the build's note says whether the system has it."
                    .into(),
            );
        }
        if spec.os.windows() {
            out.push(
                "Each clone of a Windows image reads this install config's specialize and oobeSystem passes from a seed of its own (its name, a one-time password the deploy replaces with the vault's, and a WinRM certificate of its own), so the config stays the image's while the image is used."
                    .into(),
            );
        }
        if let Some(keep) = spec.recipe.keep {
            out.push(format!(
                "The image keeps its newest {keep} version{}: older versions' VMs and their files are deleted after the build, unless a linked clone uses them.",
                if keep == 1 { "" } else { "s" }
            ));
        }
        out
    }

    /// The build dialog's check: why it can't build, or its preview. A read.
    pub async fn check(&self, ctx: &Context, request: &BuildRequest) -> Result<BuildCheck> {
        let spec = match self.spec_for(ctx, request).await? {
            Ok(spec) => spec,
            Err(problems) => {
                return Ok(BuildCheck {
                    problems,
                    preview: None,
                })
            }
        };
        let (deploy, capacity) = self.deploys.preview_spec(ctx, &spec.deploy).await;
        let packages = self.config_packages(ctx, &spec).await;
        let mut warnings = self.warnings(&spec, &packages);
        warnings.extend(deploy.warnings.iter().cloned());
        Ok(BuildCheck {
            problems: deploy.refusals.clone(),
            preview: Some(BuildPreview {
                details: super::spec::BuildDetails::of(&spec),
                deploy,
                capacity,
                warnings,
            }),
        })
    }

    async fn config_packages(&self, ctx: &Context, spec: &BuildSpec) -> Vec<String> {
        match self
            .catalog
            .install_config(ctx, &spec.recipe.install_config_id.to_string())
            .await
        {
            Ok(config) => install::read_form(config.spec.kind, &config.spec.body).form.packages,
            Err(_) => Vec::new(),
        }
    }

    /// The build as a command, or why it can't build (an error that says so).
    async fn command(&self, ctx: &Context, request: &BuildRequest) -> Result<Command> {
        let spec = match self.spec_for(ctx, request).await? {
            Ok(spec) => spec,
            Err(problems) => return Err(CoreError::InvalidInput(problems.join(" "))),
        };
        let (checked, _) = self.deploys.preview_spec(ctx, &spec.deploy).await;
        if !checked.refusals.is_empty() {
            return Err(CoreError::InvalidInput(checked.refusals.join(" ")));
        }
        Ok(Command::ImageBuild {
            targets: spec.targets(),
            spec: Box::new(spec),
        })
    }

    /// Submits a build to the bus: Medium (Critical while it keeps only the newest versions), then one job. An image's
    /// next version builds from its build settings as saved (B4 of PR 100's review: a build never changes them).
    pub async fn submit(&self, ctx: &Context, request: &BuildRequest) -> Result<SubmitOutcome> {
        if let BuildTarget::Image { id } = &request.target {
            let image = self.catalog.image(ctx, *id).await?;
            if image.build.as_ref() != Some(&request.recipe) {
                return Err(CoreError::InvalidInput(format!(
                    "Save image '{}''s build settings first: a build of its next version builds from them.",
                    image.name
                )));
            }
        }
        let command = self.command(ctx, request).await?;
        self.bus.submit(ctx, command).await
    }

    /// The request that builds an image's next version from its recipe as it is saved.
    pub async fn rebuild_request(&self, ctx: &Context, image_id: Uuid) -> Result<BuildRequest> {
        let image = self.catalog.image(ctx, image_id).await?;
        let recipe = image
            .build
            .ok_or_else(|| CoreError::InvalidInput(format!("Image '{}' isn't one Remotely builds.", image.name)))?;
        Ok(BuildRequest {
            target: BuildTarget::Image { id: image_id },
            recipe,
        })
    }

    /// "Rebuild": the image's next version from its recipe as it is saved.
    pub async fn rebuild(&self, ctx: &Context, image_id: Uuid) -> Result<SubmitOutcome> {
        let request = self.rebuild_request(ctx, image_id).await?;
        self.submit(ctx, &request).await
    }

    /// VM-27: what a scheduled rebuild of the image submits now (its standing approval is checked by the bus).
    pub async fn command_for(&self, ctx: &Context, image_id: Uuid) -> Result<Command> {
        let request = self.rebuild_request(ctx, image_id).await?;
        self.command(ctx, &request).await
    }

    /// VM-27: what changed since `approved` (a schedule's granted build) in what a rebuild of the image would build
    /// now, in words, read cheaply (the image's recipe, its config's fingerprint and the ISO's size and time, without
    /// planning the VM). The scheduler pauses the schedule on any.
    pub async fn changes_since(&self, ctx: &Context, approved: &BuildSpec) -> Result<Vec<String>> {
        // The store's rows, not the catalogue's checked ones: this runs at each scheduler tick, and a golden VM's check
        // reads its snapshots through the hypervisor, a config's runs its syntax checks.
        let Some(image) = self.store.catalog_image(ctx, approved.image_id).await? else {
            return Ok(vec![format!("image '{}' was deleted", approved.image_name)]);
        };
        let Some(recipe) = image.build.clone() else {
            return Ok(vec![format!(
                "image '{}' isn't one Remotely builds any more",
                image.name
            )]);
        };
        let Some(config) = self.store.install_config_row(ctx, recipe.install_config_id).await? else {
            return Ok(vec![format!("image '{}''s install config was deleted", image.name)]);
        };
        let Some(iso) = self.store.catalog_image(ctx, recipe.iso_image_id).await? else {
            return Ok(vec![format!("image '{}''s ISO image was deleted", image.name)]);
        };
        let iso_path = iso.source.path().map(str::to_owned).unwrap_or_default();
        let iso_seen = crate::deploy::spec::IsoSeen::of(Path::new(&iso_path)).await;
        // As a build plans it.
        let install_minutes = recipe
            .install_minutes
            .clamp(1, crate::deploy::spec::MAX_INSTALL_MINUTES);
        let now = BuildSpec {
            image_id: image.id,
            image_new: false,
            image_name: image.name.clone(),
            os_profile: iso.os_profile.clone(),
            version: approved.version,
            os: approved.os,
            recipe: BuildRecipe {
                install_minutes,
                ..recipe
            },
            config_name: config.spec.name.clone(),
            config_fingerprint: crate::deploy::spec::config_fingerprint(&config.spec),
            iso_path,
            iso_seen,
            seal_minutes: approved.seal_minutes,
            sign_in: approved.sign_in.clone(),
            deploy: approved.deploy.clone(),
            // Planned again at each run (the versions there then); the bus checks each one's labels (B3).
            prune: approved.prune.clone(),
            retained: approved.retained.clone(),
        };
        // The first build approved for a schedule is a rebuild of an image that exists by then.
        let mut approved = approved.clone();
        approved.image_new = false;
        Ok(now.differences(&approved))
    }

    /// An image's build settings: what its next builds build from. Audited, refused by the read-only lock; a
    /// schedule that rebuilds the image asks again before its next run.
    pub async fn set_recipe(
        &self,
        ctx: &Context,
        image_id: Uuid,
        recipe: BuildRecipe,
    ) -> Result<crate::catalog::Image> {
        self.store.read_only().check(Change::Catalog)?;
        let image = self.catalog.image(ctx, image_id).await?;
        if image.build.is_none() {
            return Err(CoreError::InvalidInput(format!(
                "Image '{}' isn't one Remotely builds.",
                image.name
            )));
        }
        let request = BuildRequest {
            target: BuildTarget::Image { id: image_id },
            recipe: recipe.clone(),
        };
        if let Err(problems) = self.spec_for(ctx, &request).await? {
            return Err(CoreError::InvalidInput(problems.join(" ")));
        }
        if !self.store.set_image_build(ctx, image_id, &recipe).await? {
            return Err(CoreError::UnknownTarget(format!("image {image_id}")));
        }
        let detail = format!(
            "its builds install from the install config {} and the ISO image {} on {}, {}",
            recipe.install_config_id,
            recipe.iso_image_id,
            crate::catalog::templates::hypervisor_label(recipe.hypervisor),
            match recipe.keep {
                Some(n) => format!("keeping the newest {n} versions"),
                None => "keeping every version".into(),
            }
        );
        self.audit(
            ctx,
            &format!("Changed image '{}''s build settings", image.name),
            &detail,
        )
        .await?;
        self.catalog.image(ctx, image_id).await
    }

    /// An image's versions, newest first, with the linked clones each has (read now).
    pub async fn versions(&self, ctx: &Context, image_id: Uuid) -> Result<Vec<ImageVersion>> {
        let image = self.catalog.image(ctx, image_id).await?;
        let rows = self.store.image_versions(ctx, image.id).await?;
        let linked = crate::linked_clones::LinkedClones::new(self.hypervisors.clone());
        let mut media = crate::linked_clones::VboxMedia::default();
        let newest = rows.iter().find(|r| r.deleted_at.is_none()).map(|r| r.id);
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let state = match (&row.deleted_at, Some(row.id) == newest) {
                (Some(_), _) => VersionState::Deleted,
                (None, true) => VersionState::Newest,
                (None, false) => VersionState::Kept,
            };
            let (linked_clones, clones_unread) = if state == VersionState::Deleted {
                (Vec::new(), None)
            } else {
                match linked.of_vm(&row.vm_key, &mut media).await {
                    Ok(found) => (
                        found
                            .into_iter()
                            .flat_map(|s| s.clones.into_iter().map(|c| c.name))
                            .collect(),
                        None,
                    ),
                    Err(err) => (Vec::new(), Some(err.to_string())),
                }
            };
            out.push(ImageVersion {
                id: row.id,
                number: row.number,
                state,
                hypervisor: row.hypervisor,
                vm_key: row.vm_key,
                vm_name: row.vm_name,
                snapshot_name: row.snapshot_name,
                config_name: row.config_name,
                built_at: row.built_at,
                deleted_at: row.deleted_at,
                linked_clones,
                clones_unread,
                facts: row.facts,
            });
        }
        Ok(out)
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: EVENT,
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

#[async_trait]
impl ImageBuildActions for GoldenImages {
    async fn begin(&self, ctx: &Context, job_id: Uuid, spec: &BuildSpec) -> Result<BuildGuard> {
        let keys: Vec<String> = building_keys(spec.image_id, &spec.image_name)
            .into_iter()
            .filter(|k| spec.image_new || k.starts_with("image:"))
            .collect();
        {
            let mut building = crate::locks::lock(&self.building);
            if let Some(job) = keys.iter().find_map(|k| building.get(k).copied()) {
                return Err(CoreError::InvalidInput(format!(
                    "image '{}' is being built by job {} now: build it again once that build ends",
                    spec.image_name,
                    &job.to_string()[..8]
                )));
            }
            for key in &keys {
                building.insert(key.clone(), job_id);
            }
        }
        let guard = BuildGuard {
            building: Arc::clone(&self.building),
            keys,
        };
        if spec.image_new {
            let taken = self
                .store
                .list_catalog_images(ctx)
                .await?
                .into_iter()
                .any(|i| i.id == spec.image_id || i.name.eq_ignore_ascii_case(&spec.image_name));
            if taken {
                return Err(CoreError::InvalidInput(format!(
                    "an image named '{}' was made since this build was approved: build it again under another name",
                    spec.image_name
                )));
            }
        } else if self.store.next_image_version(ctx, spec.image_id).await? > spec.version {
            return Err(CoreError::InvalidInput(format!(
                "a version of image '{}' at least as new as {} was built since this build was approved: rebuild it",
                spec.image_name, spec.version
            )));
        }
        Ok(guard)
    }

    async fn register(&self, ctx: &Context, job_id: Uuid, spec: &BuildSpec, built: &Built) -> Result<String> {
        let newest = self
            .store
            .record_image_version(
                ctx,
                &NewVersion {
                    image_id: spec.image_id,
                    number: spec.version,
                    hypervisor: spec.recipe.hypervisor,
                    vm_key: &built.vm_key,
                    vm_name: &built.vm_name,
                    snapshot_id: &built.snapshot_id,
                    snapshot_name: &built.snapshot_name,
                    config_id: spec.recipe.install_config_id,
                    config_name: &spec.config_name,
                    config_fingerprint: &spec.config_fingerprint,
                    facts: &built.facts,
                    job_id,
                },
                spec.image_new
                    .then_some((spec.image_name.as_str(), spec.os_profile.as_str(), &spec.recipe)),
            )
            .await?;
        let action = if spec.image_new {
            format!("Built image '{}' (version {})", spec.image_name, spec.version)
        } else {
            format!("Built version {} of image '{}'", spec.version, spec.image_name)
        };
        let detail = format!(
            "golden VM {} at snapshot '{}', from the install config '{}' (SHA-256 {}) and the ISO {}",
            built.vm_name, built.snapshot_name, spec.config_name, spec.config_fingerprint, spec.iso_path
        );
        if let Err(err) = self.audit(ctx, &action, &detail).await {
            tracing::error!(error = %err, "a built golden image version couldn't be audited");
        }
        Ok(if spec.image_new {
            format!(
                "registered as image '{}' version {} (snapshot '{}')",
                spec.image_name, spec.version, built.snapshot_name
            )
        } else if !newest {
            format!(
                "registered as version {} of image '{}' (snapshot '{}'); the image stays on its newer version",
                spec.version, spec.image_name, built.snapshot_name
            )
        } else {
            format!(
                "registered as version {} of image '{}' (snapshot '{}'): its launch templates deploy this version from now on",
                spec.version, spec.image_name, built.snapshot_name
            )
        })
    }

    async fn version_deleted(&self, ctx: &Context, version: &VersionRow, job_id: Uuid, why: &str) -> Result<()> {
        self.store.mark_image_version_deleted(ctx, version.id).await?;
        let name = self
            .catalog
            .image(ctx, version.image_id)
            .await
            .map_or_else(|_| version.image_id.to_string(), |i| i.name);
        let detail = format!("its VM {} is deleted ({why}); job {job_id}", version.vm_name);
        self.audit(
            ctx,
            &format!("Deleted version {} of image '{name}'", version.number),
            &detail,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::install::{InstallConfigInput, InstallKind, SecretRef};

    fn config(kind: InstallKind, body: &str, secrets: Vec<SecretRef>) -> InstallConfigInput {
        InstallConfigInput {
            name: "lab".into(),
            kind,
            body: body.into(),
            variables: Vec::new(),
            secrets,
            notes: None,
        }
    }

    #[test]
    fn a_linux_build_signs_in_as_the_first_user_with_its_key_and_password() {
        let key = SecretId(Uuid::from_u128(1));
        let pw = SecretId(Uuid::from_u128(2));
        let body = "#cloud-config\nautoinstall:\n  version: 1\n  identity:\n    hostname: '{{hostname}}'\n    username: alice\n    password: '{{password.admin}}'\n  ssh:\n    install-server: true\n    authorized-keys:\n      - '{{ssh_key.deploy}}'\n";
        let spec = config(
            InstallKind::Autoinstall,
            body,
            vec![
                SecretRef {
                    name: "admin".into(),
                    kind: SecretRefKind::Password,
                    secret_id: Some(pw),
                },
                SecretRef {
                    name: "deploy".into(),
                    kind: SecretRefKind::SshKey,
                    secret_id: Some(key),
                },
            ],
        );
        assert_eq!(
            sign_in(&spec, BuildOs::Ubuntu, Some(key)).unwrap(),
            SignIn::Ssh {
                user: "alice".into(),
                key_id: key,
                sudo_password_id: Some(pw)
            }
        );
        let other = SecretId(Uuid::from_u128(3));
        assert!(sign_in(&spec, BuildOs::Ubuntu, Some(other)).is_err());
        let keyless = config(
            InstallKind::Autoinstall,
            &body.replace("'{{ssh_key.deploy}}'", "'ssh-ed25519 AAAA bob'"),
            spec.secrets.clone(),
        );
        assert!(sign_in(&keyless, BuildOs::Ubuntu, Some(key))
            .unwrap_err()
            .contains("SSH key"));
    }
}
