//! VM-30 (0.8.0 G7): golden image versions and an image's build recipe (migration 0037). The rules are
//! `crate::golden`'s; this module only reads and writes, always within the workspace of `ctx`.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::adapters::hypervisor::Hypervisor;
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::golden::BuildRecipe;

/// One version of an image, as the store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRow {
    pub id: Uuid,
    pub image_id: Uuid,
    pub number: u32,
    pub hypervisor: Hypervisor,
    pub vm_key: String,
    pub vm_name: String,
    pub snapshot_id: String,
    pub snapshot_name: String,
    pub config_name: String,
    pub config_fingerprint: String,
    pub facts: serde_json::Value,
    pub job_id: Option<Uuid>,
    pub built_at: String,
    pub deleted_at: Option<String>,
}

/// A new version, as a build made it.
pub(crate) struct NewVersion<'a> {
    pub image_id: Uuid,
    pub number: u32,
    pub hypervisor: Hypervisor,
    pub vm_key: &'a str,
    pub vm_name: &'a str,
    pub snapshot_id: &'a str,
    pub snapshot_name: &'a str,
    pub config_name: &'a str,
    pub config_fingerprint: &'a str,
    pub facts: &'a serde_json::Value,
    pub job_id: Uuid,
}

fn version(row: &sqlx::sqlite::SqliteRow) -> Result<VersionRow> {
    let id: String = row.try_get("id")?;
    let image_id: String = row.try_get("image_id")?;
    let number: i64 = row.try_get("number")?;
    let hypervisor: String = row.try_get("hypervisor")?;
    let facts: String = row.try_get("facts")?;
    let job_id: Option<String> = row.try_get("job_id")?;
    Ok(VersionRow {
        id: parse_uuid(&id)?,
        image_id: parse_uuid(&image_id)?,
        number: u32::try_from(number).unwrap_or(0),
        hypervisor: Hypervisor::parse(&hypervisor),
        vm_key: row.try_get("vm_key")?,
        vm_name: row.try_get("vm_name")?,
        snapshot_id: row.try_get("snapshot_id")?,
        snapshot_name: row.try_get("snapshot_name")?,
        config_name: row.try_get("config_name")?,
        config_fingerprint: row.try_get("config_fingerprint")?,
        facts: serde_json::from_str(&facts).unwrap_or(serde_json::Value::Null),
        job_id: job_id.as_deref().and_then(|j| Uuid::parse_str(j).ok()),
        built_at: row.try_get("built_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

macro_rules! version_columns {
    () => {
        "id, image_id, number, hypervisor, vm_key, vm_name, snapshot_id, snapshot_name, config_name,
         config_fingerprint, facts, job_id, built_at, deleted_at"
    };
}

impl Store {
    /// An image's versions, newest first (deleted ones too: their numbers are never used again).
    pub async fn image_versions(&self, ctx: &Context, image_id: Uuid) -> Result<Vec<VersionRow>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            version_columns!(),
            " FROM image_versions WHERE workspace_id = ? AND image_id = ? ORDER BY number DESC"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(image_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(version).collect()
    }

    /// Each built image's newest version's number (deleted ones aside), by image.
    pub(crate) async fn newest_image_versions(&self, ctx: &Context) -> Result<HashMap<Uuid, u32>> {
        let rows = sqlx::query(
            "SELECT image_id, MAX(number) AS newest FROM image_versions
             WHERE workspace_id = ? AND deleted_at IS NULL GROUP BY image_id",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut out = HashMap::new();
        for row in rows {
            let id: String = row.try_get("image_id")?;
            let newest: i64 = row.try_get("newest")?;
            if let (Ok(id), Ok(newest)) = (Uuid::parse_str(&id), u32::try_from(newest)) {
                out.insert(id, newest);
            }
        }
        Ok(out)
    }

    /// The number the image's next version gets: one past every number it ever had.
    pub(crate) async fn next_image_version(&self, ctx: &Context, image_id: Uuid) -> Result<u32> {
        let max: Option<i64> =
            sqlx::query_scalar("SELECT MAX(number) FROM image_versions WHERE workspace_id = ? AND image_id = ?")
                .bind(ctx.workspace_id.to_string())
                .bind(image_id.to_string())
                .fetch_one(&self.pool)
                .await?;
        Ok(max.and_then(|m| u32::try_from(m).ok()).unwrap_or(0) + 1)
    }

    /// The version a VM is, by its key, in this workspace (letter case aside on Workstation's paths).
    pub async fn image_version_of_vm(&self, ctx: &Context, vm_key: &str) -> Result<Option<VersionRow>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            version_columns!(),
            " FROM image_versions WHERE workspace_id = ? AND vm_key = ? COLLATE NOCASE AND deleted_at IS NULL"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(vm_key)
        .fetch_all(&self.pool)
        .await?;
        rows.first().map(version).transpose()
    }

    /// A build's version, and the image pointing at it, in one transaction: a first build makes the image (a golden VM
    /// image with its recipe), a rebuild moves the image's source to the new version.
    pub(crate) async fn record_image_version(
        &self,
        ctx: &Context,
        v: &NewVersion<'_>,
        first: Option<(&str, &str)>,
        recipe: &BuildRecipe,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let now = now_rfc3339();
        let ws = ctx.workspace_id.to_string();
        let recipe = serde_json::to_string(recipe)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO image_versions (id, workspace_id, user_id, image_id, number, hypervisor, vm_key, vm_name,
                                         snapshot_id, snapshot_name, config_name, config_fingerprint, facts, job_id,
                                         built_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(&ws)
        .bind(ctx.user_id.to_string())
        .bind(v.image_id.to_string())
        .bind(i64::from(v.number))
        .bind(v.hypervisor.as_str())
        .bind(v.vm_key)
        .bind(v.vm_name)
        .bind(v.snapshot_id)
        .bind(v.snapshot_name)
        .bind(v.config_name)
        .bind(v.config_fingerprint)
        .bind(serde_json::to_string(v.facts)?)
        .bind(v.job_id.to_string())
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        match first {
            Some((name, os_profile)) => {
                sqlx::query(
                    "INSERT INTO catalog_images (id, workspace_id, user_id, name, kind, vm_key, snapshot_id,
                                                 snapshot_name, hypervisors, os_profile, notes, created_at, updated_at,
                                                 build)
                     VALUES (?, ?, ?, ?, 'golden_vm', ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                )
                .bind(v.image_id.to_string())
                .bind(&ws)
                .bind(ctx.user_id.to_string())
                .bind(name)
                .bind(v.vm_key)
                .bind(v.snapshot_id)
                .bind(v.snapshot_name)
                .bind(v.hypervisor.as_str())
                .bind(os_profile)
                .bind(&now)
                .bind(&now)
                .bind(&recipe)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                let done = sqlx::query(
                    "UPDATE catalog_images SET vm_key = ?, snapshot_id = ?, snapshot_name = ?, hypervisors = ?,
                         build = ?, user_id = ?, updated_at = ?
                     WHERE workspace_id = ? AND id = ? AND kind = 'golden_vm'",
                )
                .bind(v.vm_key)
                .bind(v.snapshot_id)
                .bind(v.snapshot_name)
                .bind(v.hypervisor.as_str())
                .bind(&recipe)
                .bind(ctx.user_id.to_string())
                .bind(&now)
                .bind(&ws)
                .bind(v.image_id.to_string())
                .execute(&mut *tx)
                .await?;
                if done.rows_affected() == 0 {
                    return Err(crate::error::CoreError::UnknownTarget(format!(
                        "image {} (deleted while it was built)",
                        v.image_id
                    )));
                }
            }
        }
        tx.commit().await?;
        Ok(id)
    }

    /// A version's VM is gone (deleted by retention or by hand): the row stays, so its number is never used again.
    pub(crate) async fn mark_image_version_deleted(&self, ctx: &Context, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE image_versions SET deleted_at = ? WHERE workspace_id = ? AND id = ? AND deleted_at IS NULL",
        )
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// An image's recipe, as its build settings say now.
    pub(crate) async fn set_image_build(&self, ctx: &Context, image_id: Uuid, recipe: &BuildRecipe) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE catalog_images SET build = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ? AND kind = 'golden_vm' AND build IS NOT NULL",
        )
        .bind(serde_json::to_string(recipe)?)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(image_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }
}
