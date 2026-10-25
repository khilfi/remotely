//! VM-19 to VM-21 catalogue rows (migration 0019). Checks live in `crate::catalog`; these only read and write.

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::{
    AfterDeploy, CloneMode, DiskSpec, Image, ImageEdit, ImageFormat, ImageKind, ImageSource, Network, Size, SizeInput,
    TemplateInput,
};
use crate::domain::{now_rfc3339, Context, Environment};
use crate::error::{CoreError, Result};
use crate::vault::SecretId;

/// A launch template as stored, before the catalogue checks what it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TemplateRow {
    pub id: Uuid,
    pub spec: TemplateInput,
    pub created_at: String,
    pub updated_at: String,
}

/// An image's file facts, as hashing found them.
pub(crate) struct NewImage<'a> {
    pub name: &'a str,
    pub source: &'a ImageSource,
    pub hypervisors: &'a [Hypervisor],
    pub os_profile: &'a str,
    pub sha256: Option<&'a str>,
    pub size_bytes: Option<u64>,
    pub notes: Option<&'a str>,
}

fn decode(err: impl std::error::Error + Send + Sync + 'static) -> CoreError {
    sqlx::Error::Decode(Box::new(err)).into()
}

fn hypervisors_text(list: &[Hypervisor]) -> String {
    list.iter().map(|h| h.as_str()).collect::<Vec<_>>().join(",")
}

fn hypervisors_of(text: &str) -> Vec<Hypervisor> {
    let mut out: Vec<Hypervisor> = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let h = Hypervisor::parse(part);
        if !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

fn row_to_size(row: &sqlx::sqlite::SqliteRow) -> Result<Size> {
    let disks: String = row.try_get("disks")?;
    let sockets: i64 = row.try_get("sockets")?;
    let cores: i64 = row.try_get("cores_per_socket")?;
    let memory: i64 = row.try_get("memory_mb")?;
    Ok(Size {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        built_in: false,
        sockets: u32::try_from(sockets).map_err(decode)?,
        cores_per_socket: u32::try_from(cores).map_err(decode)?,
        memory_mb: u32::try_from(memory).map_err(decode)?,
        disks: serde_json::from_str::<Vec<DiskSpec>>(&disks)?,
        description: row.try_get("description")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_image(row: &sqlx::sqlite::SqliteRow) -> Result<Image> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let kind = ImageKind::parse(&kind).ok_or_else(|| decode(std::io::Error::other(format!("image kind {kind}"))))?;
    let path: Option<String> = row.try_get("path")?;
    let format: Option<String> = row.try_get("format")?;
    let format = format.as_deref().and_then(ImageFormat::parse);
    let file = || -> Result<(String, ImageFormat)> {
        match (&path, format) {
            (Some(path), Some(format)) => Ok((path.clone(), format)),
            _ => Err(decode(std::io::Error::other(
                "an image file without its path or format",
            ))),
        }
    };
    let source = match kind {
        ImageKind::GoldenVm => ImageSource::GoldenVm {
            vm_key: row.try_get::<Option<String>, _>("vm_key")?.unwrap_or_default(),
            snapshot_id: row.try_get::<Option<String>, _>("snapshot_id")?.unwrap_or_default(),
            snapshot_name: row.try_get::<Option<String>, _>("snapshot_name")?.unwrap_or_default(),
        },
        ImageKind::CloudImage => {
            let (path, format) = file()?;
            ImageSource::CloudImage { path, format }
        }
        ImageKind::Iso => ImageSource::Iso { path: file()?.0 },
        ImageKind::Appliance => {
            let (path, format) = file()?;
            ImageSource::Appliance { path, format }
        }
    };
    let hypervisors: String = row.try_get("hypervisors")?;
    let size_bytes: Option<i64> = row.try_get("size_bytes")?;
    Ok(Image {
        id: parse_uuid(&id)?,
        name: row.try_get("name")?,
        source,
        hypervisors: hypervisors_of(&hypervisors),
        os_profile: row.try_get("os_profile")?,
        sha256: row.try_get("sha256")?,
        size_bytes: size_bytes.and_then(|s| u64::try_from(s).ok()),
        notes: row.try_get("notes")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        problem: None,
        vm_name: None,
    })
}

fn row_to_template(row: &sqlx::sqlite::SqliteRow) -> Result<TemplateRow> {
    let id: String = row.try_get("id")?;
    let image_id: String = row.try_get("image_id")?;
    let hypervisor: String = row.try_get("hypervisor")?;
    let network: String = row.try_get("network")?;
    let ssh_key_id: Option<String> = row.try_get("ssh_key_id")?;
    let default_count: i64 = row.try_get("default_count")?;
    let environment: String = row.try_get("environment")?;
    let tags: String = row.try_get("tags")?;
    let after_deploy: String = row.try_get("after_deploy")?;
    let packages: String = row.try_get("packages")?;
    let clone_mode: String = row.try_get("clone_mode")?;
    Ok(TemplateRow {
        id: parse_uuid(&id)?,
        spec: TemplateInput {
            name: row.try_get("name")?,
            image_id: parse_uuid(&image_id)?,
            size_id: row.try_get("size_id")?,
            hypervisor: Hypervisor::parse(&hypervisor),
            vm_folder: row.try_get("vm_folder")?,
            network: serde_json::from_str::<Network>(&network)?,
            ssh_key_id: ssh_key_id.as_deref().map(parse_uuid).transpose()?.map(SecretId),
            naming_pattern: row.try_get("naming_pattern")?,
            default_count: u32::try_from(default_count).map_err(decode)?,
            environment: Environment::parse(&environment),
            tags: serde_json::from_str(&tags)?,
            after_deploy: serde_json::from_str::<AfterDeploy>(&after_deploy)?,
            guest_user: row.try_get("guest_user")?,
            packages: serde_json::from_str(&packages)?,
            clone_mode: CloneMode::parse(&clone_mode),
        },
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

macro_rules! size_columns {
    () => {
        "id, name, sockets, cores_per_socket, memory_mb, disks, description, created_at, updated_at"
    };
}

macro_rules! image_columns {
    () => {
        "id, name, kind, path, format, vm_key, snapshot_id, snapshot_name, hypervisors, os_profile, sha256, size_bytes,
         notes, created_at, updated_at"
    };
}

macro_rules! template_columns {
    () => {
        "id, name, image_id, size_id, hypervisor, vm_folder, network, ssh_key_id, naming_pattern, default_count,
         environment, tags, after_deploy, guest_user, packages, clone_mode, created_at, updated_at"
    };
}

impl Store {
    // ---- Sizes ----

    /// The owner's own sizes, by name.
    pub(crate) async fn list_catalog_sizes(&self, ctx: &Context) -> Result<Vec<Size>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            size_columns!(),
            " FROM catalog_sizes WHERE workspace_id = ? ORDER BY name COLLATE NOCASE"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_size).collect()
    }

    pub(crate) async fn catalog_size(&self, ctx: &Context, id: &str) -> Result<Option<Size>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            size_columns!(),
            " FROM catalog_sizes WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_size).transpose()
    }

    pub(crate) async fn insert_catalog_size(&self, ctx: &Context, id: Uuid, size: &SizeInput) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO catalog_sizes (id, workspace_id, user_id, name, sockets, cores_per_socket, memory_mb, disks,
                                        description, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&size.name)
        .bind(i64::from(size.sockets))
        .bind(i64::from(size.cores_per_socket))
        .bind(i64::from(size.memory_mb))
        .bind(serde_json::to_string(&size.disks)?)
        .bind(size.description.as_deref())
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn update_catalog_size(&self, ctx: &Context, id: &str, size: &SizeInput) -> Result<()> {
        sqlx::query(
            "UPDATE catalog_sizes SET name = ?, sockets = ?, cores_per_socket = ?, memory_mb = ?, disks = ?,
                 description = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(&size.name)
        .bind(i64::from(size.sockets))
        .bind(i64::from(size.cores_per_socket))
        .bind(i64::from(size.memory_mb))
        .bind(serde_json::to_string(&size.disks)?)
        .bind(size.description.as_deref())
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn delete_catalog_size(&self, ctx: &Context, id: &str) -> Result<bool> {
        let done = sqlx::query("DELETE FROM catalog_sizes WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    // ---- Images ----

    /// Every image, by name.
    pub(crate) async fn list_catalog_images(&self, ctx: &Context) -> Result<Vec<Image>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            image_columns!(),
            " FROM catalog_images WHERE workspace_id = ? ORDER BY name COLLATE NOCASE"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_image).collect()
    }

    pub(crate) async fn catalog_image(&self, ctx: &Context, id: Uuid) -> Result<Option<Image>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            image_columns!(),
            " FROM catalog_images WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_image).transpose()
    }

    pub(crate) async fn insert_catalog_image(&self, ctx: &Context, id: Uuid, image: &NewImage<'_>) -> Result<()> {
        let now = now_rfc3339();
        let (path, format, vm_key, snapshot_id, snapshot_name) = match image.source {
            ImageSource::GoldenVm {
                vm_key,
                snapshot_id,
                snapshot_name,
            } => (
                None,
                None,
                Some(vm_key.as_str()),
                Some(snapshot_id.as_str()),
                Some(snapshot_name.as_str()),
            ),
            other => (other.path(), other.format().map(ImageFormat::as_str), None, None, None),
        };
        sqlx::query(
            "INSERT INTO catalog_images (id, workspace_id, user_id, name, kind, path, format, vm_key, snapshot_id,
                                         snapshot_name, hypervisors, os_profile, sha256, size_bytes, notes,
                                         created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(image.name)
        .bind(image.source.kind().as_str())
        .bind(path)
        .bind(format)
        .bind(vm_key)
        .bind(snapshot_id)
        .bind(snapshot_name)
        .bind(hypervisors_text(image.hypervisors))
        .bind(image.os_profile)
        .bind(image.sha256)
        .bind(image.size_bytes.and_then(|s| i64::try_from(s).ok()))
        .bind(image.notes)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn update_catalog_image(&self, ctx: &Context, id: Uuid, edit: &ImageEdit) -> Result<()> {
        sqlx::query(
            "UPDATE catalog_images SET name = ?, hypervisors = ?, os_profile = ?, notes = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(&edit.name)
        .bind(hypervisors_text(&edit.hypervisors))
        .bind(&edit.os_profile)
        .bind(edit.notes.as_deref())
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn delete_catalog_image(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM catalog_images WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    // ---- Launch templates ----

    pub(crate) async fn list_catalog_templates(&self, ctx: &Context) -> Result<Vec<TemplateRow>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            template_columns!(),
            " FROM catalog_templates WHERE workspace_id = ? ORDER BY name COLLATE NOCASE"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_template).collect()
    }

    pub(crate) async fn catalog_template(&self, ctx: &Context, id: Uuid) -> Result<Option<TemplateRow>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            template_columns!(),
            " FROM catalog_templates WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_template).transpose()
    }

    pub(crate) async fn insert_catalog_template(&self, ctx: &Context, id: Uuid, t: &TemplateInput) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO catalog_templates (id, workspace_id, user_id, name, image_id, size_id, hypervisor, vm_folder,
                                            network, ssh_key_id, naming_pattern, default_count, environment, tags,
                                            after_deploy, guest_user, packages, clone_mode, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&t.name)
        .bind(t.image_id.to_string())
        .bind(&t.size_id)
        .bind(t.hypervisor.as_str())
        .bind(t.vm_folder.as_deref())
        .bind(serde_json::to_string(&t.network)?)
        .bind(t.ssh_key_id.map(|k| k.0.to_string()))
        .bind(&t.naming_pattern)
        .bind(i64::from(t.default_count))
        .bind(t.environment.as_str())
        .bind(serde_json::to_string(&t.tags)?)
        .bind(serde_json::to_string(&t.after_deploy)?)
        .bind(t.guest_user.as_deref())
        .bind(serde_json::to_string(&t.packages)?)
        .bind(t.clone_mode.as_str())
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn update_catalog_template(&self, ctx: &Context, id: Uuid, t: &TemplateInput) -> Result<()> {
        sqlx::query(
            "UPDATE catalog_templates SET name = ?, image_id = ?, size_id = ?, hypervisor = ?, vm_folder = ?,
                 network = ?, ssh_key_id = ?, naming_pattern = ?, default_count = ?, environment = ?, tags = ?,
                 after_deploy = ?, guest_user = ?, packages = ?, clone_mode = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(&t.name)
        .bind(t.image_id.to_string())
        .bind(&t.size_id)
        .bind(t.hypervisor.as_str())
        .bind(t.vm_folder.as_deref())
        .bind(serde_json::to_string(&t.network)?)
        .bind(t.ssh_key_id.map(|k| k.0.to_string()))
        .bind(&t.naming_pattern)
        .bind(i64::from(t.default_count))
        .bind(t.environment.as_str())
        .bind(serde_json::to_string(&t.tags)?)
        .bind(serde_json::to_string(&t.after_deploy)?)
        .bind(t.guest_user.as_deref())
        .bind(serde_json::to_string(&t.packages)?)
        .bind(t.clone_mode.as_str())
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn delete_catalog_template(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM catalog_templates WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}
