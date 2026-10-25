//! FD-07 for the spec catalogue (VM-19 to VM-21): the owner's own sizes, the images and the launch templates go in
//! the export; the built-in sizes are part of every copy of the app and stay out.
//!
//! * Sizes match one here by name, images by id (one exported from this laptop before) and then by name, templates by
//!   name. Each is new, the same, or a conflict the user decides: skip, replace or keep both, as for favourites.
//! * Images travel by path: the file itself never goes in the export. The preview notes when the file isn't on this
//!   laptop (or a golden VM isn't in its VM list); the image is imported anyway and shows the same as its problem
//!   until the file is copied there. A path on a network share or a device path is refused before the file system
//!   sees it ([`crate::untrusted::path_refusal`]), so that image can only be skipped. Checksums come along as taken on
//!   the other laptop.
//! * Templates point at this laptop's images, sizes and keys after the import: an image or size from the file maps to
//!   what it became here, a key by its vault label like sessions' secrets. One that didn't come along stays named,
//!   and the template says it can't deploy until it gets another.
//!
//! Every save goes through [`crate::catalog::Catalog`], which checks and audits it as imported.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{free_name, item, Counts, ItemAction, ItemChoice, ItemProblem, PreviewItem, RowPlan, CONFLICT_CHOICES};
use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::images::file_problem;
use crate::catalog::sizes::{built_in, MAX_SIZE_NAME};
use crate::catalog::templates::hypervisor_label;
use crate::catalog::{Catalog, Image, ImageSource, ImportedImage, Size, SizeInput, TemplateInput};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::store::{Store, TemplateRow};
use crate::vault::SecretId;

// ---- In the file ------------------------------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CatalogEntries {
    #[serde(default)]
    sizes: Vec<SizeEntry>,
    #[serde(default)]
    images: Vec<ImageEntry>,
    #[serde(default)]
    templates: Vec<TemplateEntry>,
    /// VM-08 stacks. Files from before 0.5.0 R6 have none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stacks: Vec<super::stacks::StackEntry>,
}

impl CatalogEntries {
    pub(super) fn counts(&self) -> CatalogCounts {
        CatalogCounts {
            sizes: self.sizes.len(),
            images: self.images.len(),
            templates: self.templates.len(),
            stacks: self.stacks.len(),
        }
    }

    /// VM-08: each template of the file by its id, with its name.
    fn template_names(&self) -> HashMap<Uuid, String> {
        self.templates.iter().map(|t| (t.id, t.spec.name.clone())).collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SizeEntry {
    id: String,
    #[serde(flatten)]
    size: SizeInput,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImageEntry {
    id: Uuid,
    name: String,
    source: ImageSource,
    hypervisors: Vec<Hypervisor>,
    os_profile: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateEntry {
    id: Uuid,
    #[serde(flatten)]
    spec: TemplateInput,
}

/// What an export holds of the catalogue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogCounts {
    pub sizes: usize,
    pub images: usize,
    pub templates: usize,
    /// VM-08.
    pub stacks: usize,
}

impl CatalogCounts {
    pub(super) fn describe(&self) -> String {
        format!(
            "{} sizes, {} images, {} launch templates, {} stacks",
            self.sizes, self.images, self.templates, self.stacks
        )
    }
}

/// The catalogue's part of the import preview.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPreview {
    pub sizes: Vec<PreviewItem>,
    pub images: Vec<PreviewItem>,
    pub templates: Vec<PreviewItem>,
    /// VM-08.
    pub stacks: Vec<PreviewItem>,
}

/// What the user chose for the catalogue's items. Items not listed get their default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogChoices {
    #[serde(default)]
    pub sizes: Vec<ItemChoice>,
    #[serde(default)]
    pub images: Vec<ItemChoice>,
    #[serde(default)]
    pub templates: Vec<ItemChoice>,
    /// VM-08.
    #[serde(default)]
    pub stacks: Vec<ItemChoice>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogReport {
    pub sizes: Counts,
    pub images: Counts,
    pub templates: Counts,
    /// VM-08.
    pub stacks: Counts,
    /// Images imported whose file isn't on this laptop (or whose golden VM isn't in its VM list).
    pub images_missing_here: usize,
}

impl CatalogReport {
    pub(super) fn describe(&self) -> String {
        let mut text = format!(
            "sizes {}; images {}; launch templates {}",
            self.sizes.describe(),
            self.images.describe(),
            self.templates.describe()
        );
        if self.stacks != Counts::default() {
            text.push_str(&format!("; stacks {}", self.stacks.describe()));
        }
        if self.images_missing_here > 0 {
            text.push_str(&format!(
                "; {} imported without their file or VM here",
                self.images_missing_here
            ));
        }
        text
    }

    pub(super) fn is_empty(&self) -> bool {
        *self == CatalogReport::default()
    }
}

// ---- Export ----------------------------------------------------------------------------------------------------

pub(super) async fn export(store: &Store, ctx: &Context) -> Result<CatalogEntries> {
    let sizes = store
        .list_catalog_sizes(ctx)
        .await?
        .iter()
        .map(|s| SizeEntry {
            id: s.id.clone(),
            size: SizeInput::from(s),
        })
        .collect();
    let images = store
        .list_catalog_images(ctx)
        .await?
        .into_iter()
        .map(|i| ImageEntry {
            id: i.id,
            name: i.name,
            source: i.source,
            hypervisors: i.hypervisors,
            os_profile: i.os_profile,
            sha256: i.sha256,
            size_bytes: i.size_bytes,
            notes: i.notes,
        })
        .collect();
    let templates = store
        .list_catalog_templates(ctx)
        .await?
        .into_iter()
        .map(|t| TemplateEntry { id: t.id, spec: t.spec })
        .collect();
    Ok(CatalogEntries {
        sizes,
        images,
        templates,
        stacks: super::stacks::export(store, ctx).await?,
    })
}

// ---- Comparing with this laptop -----------------------------------------------------------------------------------

/// This laptop's catalogue, read once per preview or commit.
pub(super) struct LocalCatalog {
    sizes: Vec<Size>,
    images: Vec<Image>,
    templates: Vec<TemplateRow>,
    vm_keys: HashSet<String>,
    /// VM-08.
    stacks: Vec<crate::store::StackRow>,
}

impl LocalCatalog {
    pub(super) async fn read(store: &Store, ctx: &Context) -> Result<Self> {
        Ok(Self {
            sizes: store.list_catalog_sizes(ctx).await?,
            images: store.list_catalog_images(ctx).await?,
            templates: store.list_catalog_templates(ctx).await?,
            stacks: store.list_stacks(ctx).await?,
            vm_keys: store
                .list_vms(ctx)
                .await?
                .into_iter()
                .map(|vm| vm.vmx_path.to_lowercase())
                .collect(),
        })
    }
}

fn plan_sizes(file: &CatalogEntries, local: &LocalCatalog) -> Vec<RowPlan<String>> {
    file.sizes
        .iter()
        .enumerate()
        .map(|(index, e)| {
            if built_in(&e.size.name).is_some() {
                return RowPlan::conflict(
                    index,
                    String::new(),
                    format!(
                        "{} is a built-in size here; keep both imports it under another name.",
                        e.size.name
                    ),
                    vec![ItemAction::Skip, ItemAction::KeepBoth],
                );
            }
            match local
                .sizes
                .iter()
                .find(|l| l.name.eq_ignore_ascii_case(e.size.name.trim()))
            {
                None => RowPlan::new(index),
                Some(l) if SizeInput::from(l) == e.size => RowPlan::same(index, l.id.clone(), "Already here.".into()),
                Some(l) => RowPlan::conflict(
                    index,
                    l.id.clone(),
                    format!("The size {} here is {}.", l.name, l.describe()),
                    CONFLICT_CHOICES.to_vec(),
                ),
            }
        })
        .collect()
}

fn same_image(e: &ImageEntry, l: &Image) -> bool {
    e.name == l.name
        && e.source == l.source
        && e.hypervisors == l.hypervisors
        && e.os_profile == l.os_profile
        && e.sha256 == l.sha256
        && e.notes == l.notes
}

fn plan_images(file: &CatalogEntries, local: &LocalCatalog) -> Vec<RowPlan<Uuid>> {
    file.images
        .iter()
        .enumerate()
        .map(|(index, e)| {
            // The preview's note says why (refused_note).
            if e.source
                .path()
                .is_some_and(|p| crate::untrusted::path_refusal(p).is_some())
            {
                let mut row = RowPlan::new(index);
                row.choices = vec![ItemAction::Skip];
                row.default_action = ItemAction::Skip;
                return row;
            }
            let here = local
                .images
                .iter()
                .find(|l| l.id == e.id)
                .or_else(|| local.images.iter().find(|l| l.name.eq_ignore_ascii_case(e.name.trim())));
            match here {
                None => RowPlan::new(index),
                Some(l) if same_image(e, l) => RowPlan::same(index, l.id, "Already here.".into()),
                Some(l) => RowPlan::conflict(
                    index,
                    l.id,
                    format!("The image '{}' here is {}.", l.name, l.source.describe(None)),
                    CONFLICT_CHOICES.to_vec(),
                ),
            }
        })
        .collect()
}

/// The image or size a template entry names, by name: in the file, else here by id.
fn image_name(id: Uuid, file: &CatalogEntries, local: &LocalCatalog) -> Option<String> {
    file.images
        .iter()
        .find(|i| i.id == id)
        .map(|i| i.name.clone())
        .or_else(|| local.images.iter().find(|i| i.id == id).map(|i| i.name.clone()))
}

fn size_name(id: &str, file: &CatalogEntries, local: &LocalCatalog) -> Option<String> {
    built_in(id)
        .map(|s| s.name)
        .or_else(|| file.sizes.iter().find(|s| s.id == id).map(|s| s.size.name.clone()))
        .or_else(|| local.sizes.iter().find(|s| s.id == id).map(|s| s.name.clone()))
}

fn plan_templates(file: &CatalogEntries, local: &LocalCatalog) -> Vec<RowPlan<Uuid>> {
    file.templates
        .iter()
        .enumerate()
        .map(|(index, e)| {
            let Some(l) = local
                .templates
                .iter()
                .find(|l| l.spec.name.eq_ignore_ascii_case(e.spec.name.trim()))
            else {
                return RowPlan::new(index);
            };
            let names = |name: Option<String>| name.map(|n| n.to_lowercase());
            let same_refs = names(image_name(e.spec.image_id, file, local))
                == names(image_name(l.spec.image_id, file, local))
                && names(size_name(&e.spec.size_id, file, local)) == names(size_name(&l.spec.size_id, file, local));
            let same_rest = TemplateInput {
                image_id: l.spec.image_id,
                size_id: l.spec.size_id.clone(),
                ssh_key_id: l.spec.ssh_key_id,
                ..e.spec.clone()
            } == l.spec;
            if same_refs && same_rest {
                RowPlan::same(index, l.id, "Already here.".into())
            } else {
                RowPlan::conflict(
                    index,
                    l.id,
                    format!(
                        "A launch template named '{}' is here, with other settings.",
                        l.spec.name
                    ),
                    CONFLICT_CHOICES.to_vec(),
                )
            }
        })
        .collect()
}

/// The preview's rows: what each item is, and what importing it means.
pub(super) async fn preview(file: &CatalogEntries, local: &LocalCatalog) -> Result<CatalogPreview> {
    let sizes = plan_sizes(file, local)
        .into_iter()
        .map(|row| {
            let e = &file.sizes[row.index];
            let shown = Size {
                id: e.id.clone(),
                name: e.size.name.clone(),
                built_in: false,
                sockets: e.size.sockets,
                cores_per_socket: e.size.cores_per_socket,
                memory_mb: e.size.memory_mb,
                disks: e.size.disks.clone(),
                description: e.size.description.clone(),
                created_at: None,
                updated_at: None,
            };
            item(row, e.size.name.clone(), shown.describe(), Vec::new())
        })
        .collect();
    // Whether each image's file is on this laptop: metadata only, off the async threads; refused paths never.
    let files: Vec<(String, Option<u64>)> = file
        .images
        .iter()
        .map(|e| (e.source.path().unwrap_or_default().to_owned(), e.size_bytes))
        .collect();
    let file_notes = tokio::task::spawn_blocking(move || {
        files
            .into_iter()
            .map(|(path, size)| {
                if path.is_empty() || crate::untrusted::path_refusal(&path).is_some() {
                    None
                } else {
                    file_problem(&path, size)
                }
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|err| CoreError::InvalidInput(format!("the image files couldn't be checked: {err}")))?;
    let images = plan_images(file, local)
        .into_iter()
        .map(|row| {
            let e = &file.images[row.index];
            let on: Vec<&str> = e.hypervisors.iter().map(|h| hypervisor_label(*h)).collect();
            let detail = format!("{}, for {}", e.source.describe(None), on.join(" and "));
            let mut notes = Vec::new();
            if let Some(refused) = e.source.path().and_then(crate::untrusted::path_refusal) {
                notes.push(format!(
                    "Its file {}, which Remotely doesn't use: it can only be skipped.",
                    refused.describe()
                ));
            }
            if let Some(problem) = &file_notes[row.index] {
                notes.push(format!(
                    "{problem} Imported anyway, it can't deploy until the file is there."
                ));
            }
            if let ImageSource::GoldenVm { vm_key, .. } = &e.source {
                if !local.vm_keys.contains(&vm_key.to_lowercase()) {
                    notes.push(
                        "Its VM isn't in this laptop's VM list; imported anyway, it can't deploy until the VM is."
                            .into(),
                    );
                }
            }
            item(row, e.name.clone(), detail, notes)
        })
        .collect();
    let templates = plan_templates(file, local)
        .into_iter()
        .map(|row| {
            let e = &file.templates[row.index];
            let image = image_name(e.spec.image_id, file, local).unwrap_or_else(|| "an image not in the file".into());
            let size = size_name(&e.spec.size_id, file, local).unwrap_or_else(|| "a size not in the file".into());
            let detail = format!(
                "'{image}' at {size} on {}, named {}",
                hypervisor_label(e.spec.hypervisor),
                e.spec.naming_pattern
            );
            let mut notes = Vec::new();
            if image_name(e.spec.image_id, file, local).is_none() || size_name(&e.spec.size_id, file, local).is_none() {
                notes.push(
                    "Its image or size isn't in the file or here, so it can't deploy until it gets another.".into(),
                );
            }
            item(row, e.spec.name.clone(), detail, notes)
        })
        .collect();
    let file_templates = file.template_names();
    let stacks = super::stacks::preview(
        &file.stacks,
        super::stacks::plan(&file.stacks, &local.stacks, &file_templates, &local.templates),
        &file_templates,
        &local.templates,
    );
    Ok(CatalogPreview {
        sizes,
        images,
        templates,
        stacks,
    })
}

/// The rows as a commit found them, and what the user chose for each.
pub(super) struct CatalogDecided {
    sizes: Vec<(RowPlan<String>, ItemAction)>,
    images: Vec<(RowPlan<Uuid>, ItemAction)>,
    templates: Vec<(RowPlan<Uuid>, ItemAction)>,
    stacks: Vec<(RowPlan<Uuid>, ItemAction)>,
}

/// Checks the user's choice for every catalogue item before anything changes.
pub(super) fn decide(file: &CatalogEntries, local: &LocalCatalog, choices: &CatalogChoices) -> Result<CatalogDecided> {
    Ok(CatalogDecided {
        sizes: with_actions(plan_sizes(file, local), &choices.sizes, |i| {
            file.sizes[i].size.name.clone()
        })?,
        images: with_actions(plan_images(file, local), &choices.images, |i| {
            file.images[i].name.clone()
        })?,
        templates: with_actions(plan_templates(file, local), &choices.templates, |i| {
            file.templates[i].spec.name.clone()
        })?,
        stacks: with_actions(
            super::stacks::plan(&file.stacks, &local.stacks, &file.template_names(), &local.templates),
            &choices.stacks,
            |i| file.stacks[i].name().to_owned(),
        )?,
    })
}

fn with_actions<T>(
    rows: Vec<RowPlan<T>>,
    list: &[ItemChoice],
    name: impl Fn(usize) -> String,
) -> Result<Vec<(RowPlan<T>, ItemAction)>> {
    let chosen: HashMap<usize, ItemAction> = list.iter().map(|c| (c.index, c.action)).collect();
    rows.into_iter()
        .map(|row| {
            let action = row.action(&chosen, &name(row.index))?;
            Ok((row, action))
        })
        .collect()
}

/// `name-2`, `name-3`, ...: a size name not taken here (sizes can't hold spaces or brackets).
fn free_size_name(name: &str, taken: &HashSet<String>) -> String {
    for n in 2..10_000 {
        let suffix = format!("-{n}");
        let keep = MAX_SIZE_NAME.saturating_sub(suffix.len());
        let candidate = format!("{}{suffix}", name.chars().take(keep).collect::<String>());
        if !taken.contains(&candidate.to_lowercase()) && built_in(&candidate).is_none() {
            return candidate;
        }
    }
    format!("size-{}", Uuid::new_v4().simple())
}

/// Imports the user's choices: sizes and images first, then templates pointing at what they became here. A key
/// maps through `secrets` (the file's vault ids to this vault's). Each item that fails is reported in `problems`.
pub(super) async fn commit(
    store: &Store,
    ctx: &Context,
    file: &CatalogEntries,
    decided: CatalogDecided,
    secrets: &HashMap<SecretId, SecretId>,
    problems: &mut Vec<ItemProblem>,
) -> Result<CatalogReport> {
    let catalog = Catalog::new(store.clone());
    let mut report = CatalogReport::default();

    // Sizes: the file's id -> the size here.
    let mut size_map: HashMap<String, String> = HashMap::new();
    for (row, action) in decided.sizes {
        let e = &file.sizes[row.index];
        let result = match action {
            ItemAction::Skip => {
                if let Some(here) = row.local.filter(|id| !id.is_empty()) {
                    size_map.insert(e.id.clone(), here);
                }
                report.sizes.count(action);
                continue;
            }
            ItemAction::Replace => match row.local.as_deref().filter(|id| !id.is_empty()) {
                Some(id) => catalog.import_size(ctx, Some(id), e.size.clone()).await,
                None => catalog.import_size(ctx, None, e.size.clone()).await,
            },
            ItemAction::KeepBoth => {
                let taken: HashSet<String> = catalog
                    .sizes(ctx)
                    .await?
                    .iter()
                    .map(|s| s.name.to_lowercase())
                    .collect();
                let mut size = e.size.clone();
                size.name = free_size_name(e.size.name.trim(), &taken);
                catalog.import_size(ctx, None, size).await
            }
            ItemAction::Import => catalog.import_size(ctx, None, e.size.clone()).await,
        };
        match result {
            Ok(saved) => {
                size_map.insert(e.id.clone(), saved.id);
                report.sizes.count(action);
            }
            Err(err) => problems.push(ItemProblem {
                name: format!("size {}", e.size.name),
                reason: err.to_string(),
            }),
        }
    }

    // Images: the file's id -> the image here.
    let mut image_map: HashMap<Uuid, Uuid> = HashMap::new();
    for (row, action) in decided.images {
        let e = &file.images[row.index];
        let imported = ImportedImage {
            name: e.name.clone(),
            source: e.source.clone(),
            hypervisors: e.hypervisors.clone(),
            os_profile: e.os_profile.clone(),
            sha256: e.sha256.clone(),
            size_bytes: e.size_bytes,
            notes: e.notes.clone(),
        };
        let result = match action {
            ItemAction::Skip => {
                if let Some(here) = row.local {
                    image_map.insert(e.id, here);
                }
                report.images.count(action);
                continue;
            }
            ItemAction::Replace => catalog.import_image(ctx, row.local, imported).await,
            ItemAction::KeepBoth => {
                let taken: HashSet<String> = catalog
                    .images(ctx)
                    .await?
                    .iter()
                    .map(|i| i.name.to_lowercase())
                    .collect();
                let name = free_name(e.name.trim(), &taken, crate::catalog::images::MAX_IMAGE_NAME);
                catalog
                    .import_image(ctx, None, ImportedImage { name, ..imported })
                    .await
            }
            ItemAction::Import => catalog.import_image(ctx, None, imported).await,
        };
        match result {
            Ok(saved) => {
                if saved.problem.is_some() {
                    report.images_missing_here += 1;
                }
                image_map.insert(e.id, saved.id);
                report.images.count(action);
            }
            Err(err) => problems.push(ItemProblem {
                name: format!("image '{}'", e.name),
                reason: err.to_string(),
            }),
        }
    }

    // Templates, pointing at what their image, size and key became here. VM-08: the file's id -> the template here,
    // for the stacks.
    let mut template_map: HashMap<Uuid, Uuid> = HashMap::new();
    for (row, action) in decided.templates {
        let e = &file.templates[row.index];
        let mut spec = e.spec.clone();
        spec.image_id = image_map.get(&spec.image_id).copied().unwrap_or(spec.image_id);
        if let Some(here) = size_map.get(&spec.size_id) {
            spec.size_id.clone_from(here);
        }
        spec.ssh_key_id = spec.ssh_key_id.map(|k| secrets.get(&k).copied().unwrap_or(k));
        let result = match action {
            ItemAction::Skip => {
                if let Some(here) = row.local {
                    template_map.insert(e.id, here);
                }
                report.templates.count(action);
                continue;
            }
            ItemAction::Replace => catalog.import_template(ctx, row.local, spec).await,
            ItemAction::KeepBoth => {
                let taken: HashSet<String> = store
                    .list_catalog_templates(ctx)
                    .await?
                    .iter()
                    .map(|t| t.spec.name.to_lowercase())
                    .collect();
                spec.name = free_name(e.spec.name.trim(), &taken, crate::catalog::templates::MAX_TEMPLATE_NAME);
                catalog.import_template(ctx, None, spec).await
            }
            ItemAction::Import => catalog.import_template(ctx, None, spec).await,
        };
        match result {
            Ok(saved) => {
                template_map.insert(e.id, saved.id);
                report.templates.count(action);
            }
            Err(err) => problems.push(ItemProblem {
                name: format!("launch template '{}'", e.spec.name),
                reason: err.to_string(),
            }),
        }
    }

    // VM-08: stacks, each step pointing at what its template became here.
    report.stacks = super::stacks::commit(
        store,
        ctx,
        &file.stacks,
        decided.stacks,
        &file.template_names(),
        &template_map,
        problems,
    )
    .await?;
    Ok(report)
}
