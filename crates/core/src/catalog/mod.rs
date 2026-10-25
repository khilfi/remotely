//! VM-19 to VM-21: the spec catalogue, which describes VMs like a cloud provider does.
//!
//! * [`sizes`]: what a VM gets (CPU, RAM, disks). Twelve built-ins, read only; the owner's own beside them.
//! * [`profiles`]: what the guest needs (firmware, disk controller, network card, guest OS type, hardware version),
//!   per hypervisor.
//! * [`images`]: where the OS comes from: a golden VM's snapshot, a cloud image, an ISO or an OVA/OVF, each file
//!   checked and hashed when it is added.
//! * [`templates`]: an image and a size with everything else a deploy needs, checked, with why it can't deploy,
//!   and [`templates::resolve`] into one plan per VM for deploy (R2: `Catalog::plan`).
//!
//! The catalogue is the app's own data: nothing here touches a VM or a host, so edits skip the command bus like
//! the session library, are audited (`catalog_changed`, no approval tier, `docs/plan-0.5.md` "Approval tiers"),
//! and are refused while the read-only lock is on ([`Change::Catalog`]). Reads only read: a golden VM's snapshots
//! through the hypervisors, an image file's size through its metadata. FD-07 carries it all to another laptop
//! (`transfer::catalog`).

pub mod images;
pub mod profiles;
pub mod sizes;
pub mod templates;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub use self::images::{
    checked_site, HashProgress, Image, ImageEdit, ImageFormat, ImageInput, ImageKind, ImageSite, ImageSource,
    SourceInput, IMAGE_SITES,
};
pub use self::profiles::{profiles, Firmware, OsProfile};
pub use self::sizes::{built_in_sizes, DiskController, DiskSpec, Provisioning, Size, SizeInput};
pub use self::templates::{
    AfterDeploy, CloneMode, DeployPlan, KeyState, LaunchTemplate, Network, PlannedVm, Problem, ProblemCode, TemplateInput,
};
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::presentation::Change;
use crate::store::{NewAuditEntry, NewImage, Store, TemplateRow, VmRecord};
use crate::vault::{SecretId, SecretKind};

/// How the audit log names a catalogue change.
const EVENT: &str = "catalog_changed";

/// What the template editor shows while it is filled in: why it can't deploy, and the names a deploy would give.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplatePreview {
    pub problems: Vec<Problem>,
    /// For the template's default count; empty when it has problems.
    pub vms: Vec<PlannedVm>,
}

/// Saving refuses these problems: the editor can fix them. The others (a file not on this PC yet, a qcow2 waiting
/// for conversion, a key not read yet) are shown and saved.
const BLOCKS_SAVING: [ProblemCode; 8] = [
    ProblemCode::ImageGone,
    ProblemCode::SizeGone,
    ProblemCode::KeyGone,
    ProblemCode::HypervisorMismatch,
    ProblemCode::NotOnHypervisor,
    ProblemCode::NetworkMismatch,
    ProblemCode::UnknownProfile,
    ProblemCode::PatternNeedsNumber,
];

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// The catalogue (`Core.catalog`).
#[derive(Clone)]
pub struct Catalog {
    store: Store,
    /// Reads golden VMs' snapshot trees. `None` (FD-07's own copy): golden VMs are checked against the VM list only.
    hypervisors: Option<Hypervisors>,
    /// Images being hashed, by the request id the UI gave, so Cancel can stop one.
    hashing: Arc<Mutex<HashMap<Uuid, CancellationToken>>>,
}

/// What a check of templates needs, read once.
struct Facts {
    sizes: Vec<Size>,
    images: Vec<Image>,
    keys: HashMap<SecretId, crate::ssh_keys::PublicKeyInfo>,
    vault_keys: HashSet<SecretId>,
}

impl Facts {
    fn size(&self, id: &str) -> Option<&Size> {
        self.sizes.iter().find(|s| s.id.eq_ignore_ascii_case(id))
    }

    fn image(&self, id: Uuid) -> Option<&Image> {
        self.images.iter().find(|i| i.id == id)
    }

    fn key(&self, id: Option<SecretId>) -> KeyState {
        match id {
            None => KeyState::None,
            Some(id) => match self.keys.get(&id) {
                Some(public) => KeyState::Ready(public.clone()),
                None if self.vault_keys.contains(&id) => KeyState::NotRead,
                None => KeyState::Gone,
            },
        }
    }

    fn problems(&self, spec: &TemplateInput) -> Vec<Problem> {
        templates::problems(
            spec,
            &templates::Refs {
                image: self.image(spec.image_id),
                size: self.size(&spec.size_id),
                key: self.key(spec.ssh_key_id),
            },
        )
    }
}

impl Catalog {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            hypervisors: None,
            hashing: Arc::default(),
        }
    }

    /// Golden VM images check that their snapshot is still there.
    pub fn with_hypervisors(mut self, hypervisors: Hypervisors) -> Self {
        self.hypervisors = Some(hypervisors);
        self
    }

    // ---- Reads ----------------------------------------------------------------------------------------------

    /// The built-ins (in the plan's order), then the owner's own by name.
    pub async fn sizes(&self, ctx: &Context) -> Result<Vec<Size>> {
        let mut sizes = built_in_sizes();
        sizes.extend(self.store.list_catalog_sizes(ctx).await?);
        Ok(sizes)
    }

    /// A built-in by its name, or an own size by its id.
    pub async fn size(&self, ctx: &Context, id: &str) -> Result<Size> {
        if let Some(size) = sizes::built_in(id) {
            return Ok(size);
        }
        self.store
            .catalog_size(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("size {id}")))
    }

    /// Every image, by name, each with why it can't deploy now.
    pub async fn images(&self, ctx: &Context) -> Result<Vec<Image>> {
        let images = self.store.list_catalog_images(ctx).await?;
        self.with_problems(ctx, images).await
    }

    pub async fn image(&self, ctx: &Context, id: Uuid) -> Result<Image> {
        let image = self
            .store
            .catalog_image(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("image {id}")))?;
        let mut checked = self.with_problems(ctx, vec![image]).await?;
        checked
            .pop()
            .ok_or_else(|| CoreError::UnknownTarget(format!("image {id}")))
    }

    /// Fills in each image's `problem` and a golden VM's name: a file that is gone or changed size, a VM the VM list
    /// doesn't have, a snapshot that is gone. Refused paths are never looked at.
    async fn with_problems(&self, ctx: &Context, mut images: Vec<Image>) -> Result<Vec<Image>> {
        let vms = self.store.list_vms(ctx).await?;
        let files: Vec<(usize, String, Option<u64>)> = images
            .iter()
            .enumerate()
            .filter_map(|(i, image)| image.source.path().map(|p| (i, p.to_owned(), image.size_bytes)))
            .collect();
        let file_problems = tokio::task::spawn_blocking(move || {
            files
                .into_iter()
                .map(|(i, path, size)| (i, images::file_problem(&path, size)))
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|err| CoreError::InvalidInput(format!("the image files couldn't be checked: {err}")))?;
        for (i, problem) in file_problems {
            if let Some(image) = images.get_mut(i) {
                image.problem = problem;
            }
        }
        for image in &mut images {
            let ImageSource::GoldenVm {
                vm_key,
                snapshot_id,
                snapshot_name,
            } = &image.source
            else {
                continue;
            };
            let Some(vm) = find_vm(&vms, vm_key) else {
                image.problem = Some(
                    "Its VM isn't in the VM list on this PC: refresh the list, or add the VM's folder in Settings."
                        .into(),
                );
                continue;
            };
            image.vm_name = Some(vm.display_name.clone());
            let Some(hypervisors) = &self.hypervisors else {
                continue;
            };
            match hypervisors.snapshots(&vm.vmx_path).await {
                Ok(tree) => {
                    if !tree.snapshots.iter().any(|s| snapshot_key(s) == *snapshot_id) {
                        image.problem = Some(format!("Its snapshot '{snapshot_name}' is no longer on the VM."));
                    }
                }
                Err(err) => image.problem = Some(format!("Its VM's snapshots can't be read: {err}")),
            }
        }
        Ok(images)
    }

    /// Every launch template, by name, each with why it can't deploy now.
    pub async fn templates(&self, ctx: &Context) -> Result<Vec<LaunchTemplate>> {
        let rows = self.store.list_catalog_templates(ctx).await?;
        let facts = self.facts(ctx).await?;
        Ok(rows.into_iter().map(|row| launch_template(row, &facts)).collect())
    }

    pub async fn template(&self, ctx: &Context, id: Uuid) -> Result<LaunchTemplate> {
        let row = self.template_row(ctx, id).await?;
        let facts = self.facts(ctx).await?;
        Ok(launch_template(row, &facts))
    }

    async fn template_row(&self, ctx: &Context, id: Uuid) -> Result<TemplateRow> {
        self.store
            .catalog_template(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("launch template {id}")))
    }

    async fn facts(&self, ctx: &Context) -> Result<Facts> {
        let keys = self
            .store
            .ssh_key_rows(ctx)
            .await?
            .into_iter()
            .map(|(id, row)| (id, row.public))
            .collect();
        let vault_keys = self
            .store
            .vault_items(ctx)
            .await?
            .into_iter()
            .filter(|m| m.kind == SecretKind::PrivateKey)
            .map(|m| m.id)
            .collect();
        Ok(Facts {
            sizes: self.sizes(ctx).await?,
            images: self.images(ctx).await?,
            keys,
            vault_keys,
        })
    }

    /// The editor's check while a template is filled in: its own fields ([`templates::check_template`]), then why
    /// it couldn't deploy and the names its default count would get.
    pub async fn preview(&self, ctx: &Context, input: &TemplateInput) -> Result<TemplatePreview> {
        let spec = templates::check_template(input)?;
        let facts = self.facts(ctx).await?;
        let taken = self.vm_names(ctx).await?;
        let refs = templates::Refs {
            image: facts.image(spec.image_id),
            size: facts.size(&spec.size_id),
            key: facts.key(spec.ssh_key_id),
        };
        Ok(
            match templates::resolve(Uuid::nil(), &spec, &refs, spec.default_count, &taken, today()) {
                Ok(plan) => TemplatePreview {
                    problems: Vec::new(),
                    vms: plan.vms,
                },
                Err(problems) => TemplatePreview {
                    problems,
                    vms: Vec::new(),
                },
            },
        )
    }

    /// R2: a saved template and `count` VMs as one plan, each VM's name numbered past the VMs already here; or why
    /// it can't deploy.
    pub async fn plan(
        &self,
        ctx: &Context,
        id: Uuid,
        count: u32,
    ) -> Result<std::result::Result<DeployPlan, Vec<Problem>>> {
        let row = self.template_row(ctx, id).await?;
        let facts = self.facts(ctx).await?;
        let taken = self.vm_names(ctx).await?;
        let refs = templates::Refs {
            image: facts.image(row.spec.image_id),
            size: facts.size(&row.spec.size_id),
            key: facts.key(row.spec.ssh_key_id),
        };
        Ok(templates::resolve(id, &row.spec, &refs, count, &taken, today()))
    }

    /// R2: a template's fields as the Deploy dialog sends them (a saved template's, perhaps with another naming
    /// pattern, or Custom's own) and `count` VMs as one plan; or why it can't deploy. `id` is the saved template's,
    /// nil for Custom.
    pub async fn plan_input(
        &self,
        ctx: &Context,
        id: Uuid,
        input: &TemplateInput,
        count: u32,
    ) -> Result<std::result::Result<DeployPlan, Vec<Problem>>> {
        let spec = templates::check_template(input)?;
        let facts = self.facts(ctx).await?;
        let taken = self.vm_names(ctx).await?;
        let refs = templates::Refs {
            image: facts.image(spec.image_id),
            size: facts.size(&spec.size_id),
            key: facts.key(spec.ssh_key_id),
        };
        Ok(templates::resolve(id, &spec, &refs, count, &taken, today()))
    }

    async fn vm_names(&self, ctx: &Context) -> Result<Vec<String>> {
        Ok(self
            .store
            .list_vms(ctx)
            .await?
            .into_iter()
            .map(|vm| vm.display_name)
            .collect())
    }

    // ---- Sizes ----------------------------------------------------------------------------------------------

    pub async fn add_size(&self, ctx: &Context, input: SizeInput) -> Result<Size> {
        self.store.read_only().check(Change::Catalog)?;
        self.save_size(ctx, None, input, "Added").await
    }

    /// Built-ins are read only.
    pub async fn update_size(&self, ctx: &Context, id: &str, input: SizeInput) -> Result<Size> {
        self.store.read_only().check(Change::Catalog)?;
        refuse_built_in(id)?;
        self.save_size(ctx, Some(id), input, "Changed").await
    }

    async fn save_size(&self, ctx: &Context, id: Option<&str>, input: SizeInput, verb: &str) -> Result<Size> {
        let clean = sizes::check_size(&input)?;
        let own = self.store.list_catalog_sizes(ctx).await?;
        if own
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(&clean.name) && Some(s.id.as_str()) != id)
        {
            return invalid(format!("A size named {} exists already.", clean.name));
        }
        let (id, detail) = match id {
            Some(id) => {
                let before = own
                    .iter()
                    .find(|s| s.id == id)
                    .ok_or_else(|| CoreError::UnknownTarget(format!("size {id}")))?;
                let changes = sizes::size_changes(before, &clean);
                if changes.is_empty() {
                    return Ok(before.clone());
                }
                self.store.update_catalog_size(ctx, id, &clean).await?;
                (id.to_owned(), changes.join("; "))
            }
            None => {
                if own.len() >= sizes::MAX_SIZES {
                    return invalid(format!("A workspace keeps at most {} sizes.", sizes::MAX_SIZES));
                }
                let id = Uuid::new_v4();
                self.store.insert_catalog_size(ctx, id, &clean).await?;
                let saved = self.size(ctx, &id.to_string()).await?;
                (id.to_string(), saved.describe())
            }
        };
        let saved = self.size(ctx, &id).await?;
        self.audit(ctx, &format!("{verb} the size '{}'", saved.name), &detail)
            .await?;
        Ok(saved)
    }

    /// Templates that use it say so until they get another size.
    pub async fn delete_size(&self, ctx: &Context, id: &str) -> Result<()> {
        self.store.read_only().check(Change::Catalog)?;
        refuse_built_in(id)?;
        let size = self.size(ctx, id).await?;
        let used = self
            .templates_using(ctx, |t| t.size_id.eq_ignore_ascii_case(id))
            .await?;
        if !self.store.delete_catalog_size(ctx, id).await? {
            return Err(CoreError::UnknownTarget(format!("size {id}")));
        }
        self.audit(ctx, &format!("Deleted the size '{}'", size.name), &used_by(&used))
            .await
    }

    // ---- Images ---------------------------------------------------------------------------------------------

    /// Adds an image. A file is checked and hashed on a blocking thread first, with `progress` along the way;
    /// [`Catalog::cancel_hash`] with the same `request` stops it. A golden VM's snapshot is looked up on the VM.
    pub async fn add_image(
        &self,
        ctx: &Context,
        request: Uuid,
        input: ImageInput,
        progress: Arc<dyn Fn(HashProgress) + Send + Sync>,
    ) -> Result<Image> {
        self.store.read_only().check(Change::Catalog)?;
        let name = images::clean_image_name(&input.name)?;
        let notes = images::clean_notes(input.notes.as_deref())?;
        let os = profiles::profile(&input.os_profile)
            .ok_or_else(|| CoreError::InvalidInput("Pick the image's OS profile.".into()))?;
        let existing = self.store.list_catalog_images(ctx).await?;
        name_free(&existing, &name, None)?;
        if existing.len() >= images::MAX_IMAGES {
            return invalid(format!("A workspace keeps at most {} images.", images::MAX_IMAGES));
        }
        let (source, allowed, sha256, size_bytes) = match input.source {
            SourceInput::GoldenVm { vm_key, snapshot } => {
                let (source, hypervisor) = self.golden_source(ctx, &vm_key, &snapshot).await?;
                (source, vec![hypervisor], None, None)
            }
            file => {
                let kind = file.kind();
                let (SourceInput::CloudImage { path } | SourceInput::Iso { path } | SourceInput::Appliance { path }) =
                    file
                else {
                    return invalid("A golden VM has no file.");
                };
                let hashed = self.hash(request, &path, kind, progress).await?;
                let path = hashed.path.display().to_string();
                let source = match kind {
                    ImageKind::Iso => ImageSource::Iso { path },
                    ImageKind::Appliance => ImageSource::Appliance {
                        path,
                        format: hashed.format,
                    },
                    _ => ImageSource::CloudImage {
                        path,
                        format: hashed.format,
                    },
                };
                (
                    source,
                    Hypervisor::ALL.to_vec(),
                    Some(hashed.sha256),
                    Some(hashed.size_bytes),
                )
            }
        };
        let hypervisors = deploys_on(&input.hypervisors, &allowed, &os)?;
        // The lock may have come on while a large file was read.
        self.store.read_only().check(Change::Catalog)?;
        let id = Uuid::new_v4();
        self.store
            .insert_catalog_image(
                ctx,
                id,
                &NewImage {
                    name: &name,
                    source: &source,
                    hypervisors: &hypervisors,
                    os_profile: os.id,
                    sha256: sha256.as_deref(),
                    size_bytes,
                    notes: notes.as_deref(),
                },
            )
            .await?;
        let image = self.image(ctx, id).await?;
        self.audit(ctx, &format!("Added the image '{name}'"), &describe_image(&image))
            .await?;
        Ok(image)
    }

    /// Stops hashing the image `request` adds. False when none is being hashed under that id.
    pub fn cancel_hash(&self, request: Uuid) -> bool {
        locks::lock(&self.hashing)
            .get(&request)
            .map(CancellationToken::cancel)
            .is_some()
    }

    async fn hash(
        &self,
        request: Uuid,
        path: &str,
        kind: ImageKind,
        progress: Arc<dyn Fn(HashProgress) + Send + Sync>,
    ) -> Result<images::HashedFile> {
        if let Some(problem) = images::path_problem(path) {
            return invalid(problem);
        }
        let token = CancellationToken::new();
        locks::lock(&self.hashing).insert(request, token.clone());
        let path = PathBuf::from(path.trim());
        let result =
            tokio::task::spawn_blocking(move || images::hash_file(&path, kind, &token, progress.as_ref())).await;
        locks::lock(&self.hashing).remove(&request);
        result.map_err(|err| CoreError::InvalidInput(format!("hashing the image stopped: {err}")))?
    }

    /// A golden VM image's source: the VM by its key, the snapshot by its path, name or id.
    async fn golden_source(&self, ctx: &Context, vm_key: &str, snapshot: &str) -> Result<(ImageSource, Hypervisor)> {
        let vms = self.store.list_vms(ctx).await?;
        let vm = find_vm(&vms, vm_key.trim())
            .ok_or_else(|| CoreError::InvalidInput("Pick a VM from the VM list.".into()))?;
        let Some(hypervisors) = &self.hypervisors else {
            return invalid("The VM's snapshots can't be read here.");
        };
        let tree = hypervisors.snapshots(&vm.vmx_path).await?;
        let nodes = crate::snapshots::tree_nodes(&tree, time::OffsetDateTime::now_utc());
        let wanted = snapshot.trim();
        let by_name: Vec<_> = tree.snapshots.iter().filter(|s| s.name == wanted).collect();
        let found = tree
            .snapshots
            .iter()
            .find(|s| snapshot_key(s) == wanted || nodes.iter().any(|n| n.uid == s.uid && n.path == wanted))
            // Its name, when no other snapshot of the VM has it (VirtualBox allows twins).
            .or_else(|| (by_name.len() == 1).then(|| by_name[0]));
        let Some(found) = found else {
            return invalid(format!(
                "{} has no snapshot '{wanted}'. A golden VM image starts from one of its snapshots: take one first.",
                vm.display_name
            ));
        };
        Ok((
            ImageSource::GoldenVm {
                vm_key: vm.vmx_path.clone(),
                snapshot_id: snapshot_key(found),
                snapshot_name: found.name.clone(),
            },
            vm.hypervisor,
        ))
    }

    /// Its name, hypervisors, OS profile and notes; its file or VM stay.
    pub async fn update_image(&self, ctx: &Context, id: Uuid, edit: ImageEdit) -> Result<Image> {
        self.store.read_only().check(Change::Catalog)?;
        let before = self.image(ctx, id).await?;
        let name = images::clean_image_name(&edit.name)?;
        let notes = images::clean_notes(edit.notes.as_deref())?;
        let os = profiles::profile(&edit.os_profile)
            .ok_or_else(|| CoreError::InvalidInput("Pick the image's OS profile.".into()))?;
        let existing = self.store.list_catalog_images(ctx).await?;
        name_free(&existing, &name, Some(id))?;
        let allowed = match &before.source {
            ImageSource::GoldenVm { vm_key, .. } => vec![Hypervisor::of_key(vm_key)],
            _ => Hypervisor::ALL.to_vec(),
        };
        let hypervisors = deploys_on(&edit.hypervisors, &allowed, &os)?;
        let clean = ImageEdit {
            name,
            hypervisors,
            os_profile: os.id.to_owned(),
            notes,
        };
        let mut changes = Vec::new();
        if before.name != clean.name {
            changes.push(format!("renamed to '{}'", clean.name));
        }
        if before.hypervisors != clean.hypervisors {
            changes.push(format!("deploys on {}", hypervisors_text(&clean.hypervisors)));
        }
        if before.os_profile != clean.os_profile {
            changes.push(format!("OS profile {} -> {}", before.os_profile, clean.os_profile));
        }
        if before.notes != clean.notes {
            changes.push("notes changed".into());
        }
        if changes.is_empty() {
            return Ok(before);
        }
        self.store.update_catalog_image(ctx, id, &clean).await?;
        self.audit(
            ctx,
            &format!("Changed the image '{}'", before.name),
            &changes.join("; "),
        )
        .await?;
        self.image(ctx, id).await
    }

    /// Only the catalogue's entry: the file or VM stays where it is. Templates that use it say so.
    pub async fn delete_image(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Catalog)?;
        let image = self
            .store
            .catalog_image(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("image {id}")))?;
        let used = self.templates_using(ctx, |t| t.image_id == id).await?;
        self.store.delete_catalog_image(ctx, id).await?;
        self.audit(
            ctx,
            &format!("Deleted the image '{}'", image.name),
            &format!(
                "{}; the file or VM stays; {}",
                image.source.describe(None),
                used_by(&used)
            ),
        )
        .await
    }

    // ---- Launch templates -----------------------------------------------------------------------------------

    pub async fn add_template(&self, ctx: &Context, input: TemplateInput) -> Result<LaunchTemplate> {
        self.store.read_only().check(Change::Catalog)?;
        self.save_template(ctx, None, input).await
    }

    pub async fn update_template(&self, ctx: &Context, id: Uuid, input: TemplateInput) -> Result<LaunchTemplate> {
        self.store.read_only().check(Change::Catalog)?;
        self.save_template(ctx, Some(id), input).await
    }

    async fn save_template(&self, ctx: &Context, id: Option<Uuid>, input: TemplateInput) -> Result<LaunchTemplate> {
        let spec = templates::check_template(&input)?;
        let rows = self.store.list_catalog_templates(ctx).await?;
        if rows
            .iter()
            .any(|r| r.spec.name.eq_ignore_ascii_case(&spec.name) && Some(r.id) != id)
        {
            return invalid(format!("A template named '{}' exists already.", spec.name));
        }
        let facts = self.facts(ctx).await?;
        let blocking: Vec<String> = facts
            .problems(&spec)
            .into_iter()
            .filter(|p| BLOCKS_SAVING.contains(&p.code))
            .map(|p| p.message)
            .collect();
        if !blocking.is_empty() {
            return invalid(blocking.join(" "));
        }
        let (id, action, detail) = match id {
            Some(id) => {
                let before = rows
                    .iter()
                    .find(|r| r.id == id)
                    .ok_or_else(|| CoreError::UnknownTarget(format!("launch template {id}")))?;
                let changes = templates::template_changes(
                    &before.spec,
                    &spec,
                    &|image| {
                        facts
                            .image(image)
                            .map_or_else(|| "(deleted)".to_owned(), |i| format!("'{}'", i.name))
                    },
                    &|size| {
                        facts
                            .size(size)
                            .map_or_else(|| "(deleted)".to_owned(), |s| s.name.clone())
                    },
                );
                if changes.is_empty() {
                    return Ok(launch_template(before.clone(), &facts));
                }
                self.store.update_catalog_template(ctx, id, &spec).await?;
                (
                    id,
                    format!("Changed the launch template '{}'", before.spec.name),
                    changes.join("; "),
                )
            }
            None => {
                if rows.len() >= templates::MAX_TEMPLATES {
                    return invalid(format!(
                        "A workspace keeps at most {} launch templates.",
                        templates::MAX_TEMPLATES
                    ));
                }
                let id = Uuid::new_v4();
                self.store.insert_catalog_template(ctx, id, &spec).await?;
                (
                    id,
                    format!("Added the launch template '{}'", spec.name),
                    describe_template(&spec, &facts),
                )
            }
        };
        self.audit(ctx, &action, &detail).await?;
        let row = self.template_row(ctx, id).await?;
        Ok(launch_template(row, &facts))
    }

    pub async fn delete_template(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Catalog)?;
        let row = self.template_row(ctx, id).await?;
        self.store.delete_catalog_template(ctx, id).await?;
        self.audit(ctx, &format!("Deleted the launch template '{}'", row.spec.name), "")
            .await
    }

    async fn templates_using(&self, ctx: &Context, uses: impl Fn(&TemplateInput) -> bool) -> Result<Vec<String>> {
        Ok(self
            .store
            .list_catalog_templates(ctx)
            .await?
            .into_iter()
            .filter(|r| uses(&r.spec))
            .map(|r| r.spec.name)
            .collect())
    }

    // ---- FD-07: what an import saves, audited as imported --------------------------------------------------

    /// A size from an export, new or over `replace` (an own size's id).
    pub(crate) async fn import_size(&self, ctx: &Context, replace: Option<&str>, input: SizeInput) -> Result<Size> {
        if let Some(id) = replace {
            refuse_built_in(id)?;
        }
        self.save_size(ctx, replace, input, "Imported").await
    }

    /// An image from an export, new or over `replace`: its file by path and the checksum taken on the other laptop
    /// (the file isn't read again; its problem says when it isn't on this PC). A refused path is refused here too.
    pub(crate) async fn import_image(
        &self,
        ctx: &Context,
        replace: Option<Uuid>,
        image: ImportedImage,
    ) -> Result<Image> {
        let name = images::clean_image_name(&image.name)?;
        let notes = images::clean_notes(image.notes.as_deref())?;
        let os_profile = image.os_profile.trim().to_owned();
        if os_profile.is_empty() || os_profile.len() > 40 {
            return invalid("The image's OS profile is damaged.");
        }
        let source = match &image.source {
            ImageSource::GoldenVm {
                vm_key,
                snapshot_id,
                snapshot_name,
            } => {
                let clean = |text: &str, what: &str| -> Result<String> {
                    let text = text.trim();
                    if text.is_empty()
                        || text.chars().count() > images::MAX_PATH_CHARS
                        || text.chars().any(char::is_control)
                    {
                        return invalid(format!("The image's {what} is damaged."));
                    }
                    Ok(text.to_owned())
                };
                ImageSource::GoldenVm {
                    vm_key: clean(vm_key, "VM")?,
                    snapshot_id: clean(snapshot_id, "snapshot")?,
                    snapshot_name: clean(snapshot_name, "snapshot name")?,
                }
            }
            other => {
                let path = other.path().unwrap_or_default();
                if let Some(problem) = images::path_problem(path) {
                    return invalid(problem);
                }
                let format = other.format();
                if !format.is_some_and(|f| ImageFormat::allowed(other.kind()).contains(&f)) {
                    return invalid("The image's format doesn't fit its kind.");
                }
                other.clone()
            }
        };
        let allowed = match &source {
            ImageSource::GoldenVm { vm_key, .. } => vec![Hypervisor::of_key(vm_key)],
            _ => Hypervisor::ALL.to_vec(),
        };
        let mut hypervisors: Vec<Hypervisor> = Hypervisor::ALL
            .into_iter()
            .filter(|h| image.hypervisors.contains(h) && allowed.contains(h))
            .collect();
        if let Some(os) = profiles::profile(&os_profile) {
            hypervisors.retain(|h| os.runs_on(*h));
        }
        if hypervisors.is_empty() {
            return invalid("The image deploys on no hypervisor this version has.");
        }
        let sha256 = image
            .sha256
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()));
        let existing = self.store.list_catalog_images(ctx).await?;
        name_free(&existing, &name, replace)?;
        if let Some(id) = replace {
            self.store.delete_catalog_image(ctx, id).await?;
        }
        let id = replace.unwrap_or_else(Uuid::new_v4);
        self.store
            .insert_catalog_image(
                ctx,
                id,
                &NewImage {
                    name: &name,
                    source: &source,
                    hypervisors: &hypervisors,
                    os_profile: &os_profile,
                    sha256: sha256.as_deref(),
                    size_bytes: image.size_bytes,
                    notes: notes.as_deref(),
                },
            )
            .await?;
        let saved = self.image(ctx, id).await?;
        let verb = if replace.is_some() { "Replaced" } else { "Imported" };
        self.audit(
            ctx,
            &format!("{verb} the image '{name}' from a Remotely export"),
            &describe_image(&saved),
        )
        .await?;
        Ok(saved)
    }

    /// A template from an export, new or over `replace`, with what it names already mapped to this laptop's. What
    /// is gone shows as its problems rather than stopping the import.
    pub(crate) async fn import_template(
        &self,
        ctx: &Context,
        replace: Option<Uuid>,
        input: TemplateInput,
    ) -> Result<LaunchTemplate> {
        let spec = templates::check_template(&input)?;
        let rows = self.store.list_catalog_templates(ctx).await?;
        if rows
            .iter()
            .any(|r| r.spec.name.eq_ignore_ascii_case(&spec.name) && Some(r.id) != replace)
        {
            return invalid(format!("A template named '{}' exists already.", spec.name));
        }
        let facts = self.facts(ctx).await?;
        let id = match replace {
            Some(id) => {
                self.store.update_catalog_template(ctx, id, &spec).await?;
                id
            }
            None => {
                let id = Uuid::new_v4();
                self.store.insert_catalog_template(ctx, id, &spec).await?;
                id
            }
        };
        let verb = if replace.is_some() { "Replaced" } else { "Imported" };
        self.audit(
            ctx,
            &format!("{verb} the launch template '{}' from a Remotely export", spec.name),
            &describe_template(&spec, &facts),
        )
        .await?;
        let row = self.template_row(ctx, id).await?;
        Ok(launch_template(row, &facts))
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
                    detail: Some(detail).filter(|d| !d.is_empty()),
                },
            )
            .await
            .map(drop)
    }
}

/// An image as an export carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportedImage {
    pub name: String,
    pub source: ImageSource,
    pub hypervisors: Vec<Hypervisor>,
    pub os_profile: String,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub notes: Option<String>,
}

fn launch_template(row: TemplateRow, facts: &Facts) -> LaunchTemplate {
    let problems = facts.problems(&row.spec);
    LaunchTemplate {
        id: row.id,
        spec: row.spec,
        created_at: row.created_at,
        updated_at: row.updated_at,
        problems,
    }
}

fn refuse_built_in(id: &str) -> Result<()> {
    if let Some(size) = sizes::built_in(id) {
        return invalid(format!(
            "{} is a built-in size, so it is read only. Duplicate it to make an editable copy.",
            size.name
        ));
    }
    Ok(())
}

fn name_free(images: &[Image], name: &str, except: Option<Uuid>) -> Result<()> {
    if images
        .iter()
        .any(|i| i.name.eq_ignore_ascii_case(name) && Some(i.id) != except)
    {
        return invalid(format!("An image named '{name}' exists already."));
    }
    Ok(())
}

/// The hypervisors an image deploys on: those asked (all `allowed` when none), within `allowed` and where its OS
/// profile runs. Windows 11 asked on Workstation says why it can't.
fn deploys_on(asked: &[Hypervisor], allowed: &[Hypervisor], os: &OsProfile) -> Result<Vec<Hypervisor>> {
    if let Some(no) = asked.iter().find(|h| !os.runs_on(**h)) {
        if let Some(why) = os.refusal(*no) {
            return invalid(why);
        }
    }
    let runs: Vec<Hypervisor> = allowed.iter().copied().filter(|h| os.runs_on(*h)).collect();
    if runs.is_empty() {
        return invalid(
            os.refusal(Hypervisor::Vmware)
                .unwrap_or("This image deploys on no hypervisor."),
        );
    }
    images::clean_hypervisors(asked, &runs)
}

fn find_vm<'a>(vms: &'a [VmRecord], key: &str) -> Option<&'a VmRecord> {
    vms.iter().find(|vm| vm.vmx_path.eq_ignore_ascii_case(key))
}

/// A snapshot's id that stays when it is renamed: VirtualBox's UUID, or Workstation's uid.
fn snapshot_key(snapshot: &crate::adapters::vmware::SnapshotInfo) -> String {
    snapshot.id.clone().unwrap_or_else(|| snapshot.uid.to_string())
}

fn hypervisors_text(list: &[Hypervisor]) -> String {
    list.iter()
        .map(|h| templates::hypervisor_label(*h))
        .collect::<Vec<_>>()
        .join(" and ")
}

fn describe_image(image: &Image) -> String {
    let mut text = format!(
        "{}; deploys on {}; OS profile {}",
        image.source.describe(image.vm_name.as_deref()),
        hypervisors_text(&image.hypervisors),
        image.os_profile
    );
    if let Some(sha) = &image.sha256 {
        text.push_str(&format!("; SHA-256 {sha}"));
    }
    text
}

fn describe_template(spec: &TemplateInput, facts: &Facts) -> String {
    let image = facts
        .image(spec.image_id)
        .map_or_else(|| "a deleted image".to_owned(), |i| format!("image '{}'", i.name));
    let size = facts
        .size(&spec.size_id)
        .map_or_else(|| "a deleted size".to_owned(), |s| format!("size {}", s.name));
    format!(
        "{image}, {size}, on {}, network {}, named {}, {} by default, environment {}, tags {}; after deploy: {}; \
         guest user {}, packages {}, golden VMs: {}",
        templates::hypervisor_label(spec.hypervisor),
        spec.network.describe(),
        spec.naming_pattern,
        spec.default_count,
        spec.environment.as_str(),
        templates::tags_text(&spec.tags),
        spec.after_deploy.describe(),
        spec.guest_user.as_deref().unwrap_or("the image's default"),
        templates::tags_text(&spec.packages),
        spec.clone_mode.label()
    )
}

fn used_by(templates: &[String]) -> String {
    match templates.len() {
        0 => "no template used it".to_owned(),
        _ => format!(
            "used by {}, which now can't deploy until they get another",
            templates
                .iter()
                .map(|t| format!("'{t}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Today on this PC, for `{date}`.
pub(crate) fn today() -> time::Date {
    time::OffsetDateTime::now_local()
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
        .date()
}
