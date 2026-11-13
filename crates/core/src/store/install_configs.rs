//! VM-28 install config rows (migration 0035). Checks live in `crate::catalog::install`; these only read and write.

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::catalog::install::{InstallConfigInput, InstallKind, SecretRef, VariableDef};
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};

/// An install config as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstallConfigRow {
    pub id: Uuid,
    pub spec: InstallConfigInput,
    pub created_at: String,
    pub updated_at: String,
}

fn row_to_config(row: &sqlx::sqlite::SqliteRow) -> Result<InstallConfigRow> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let kind = InstallKind::parse(&kind).ok_or_else(|| {
        CoreError::from(sqlx::Error::Decode(Box::new(std::io::Error::other(format!(
            "install config kind {kind}"
        )))))
    })?;
    let variables: String = row.try_get("variables")?;
    let secrets: String = row.try_get("secrets")?;
    Ok(InstallConfigRow {
        id: parse_uuid(&id)?,
        spec: InstallConfigInput {
            name: row.try_get("name")?,
            kind,
            body: row.try_get("body")?,
            variables: serde_json::from_str::<Vec<VariableDef>>(&variables)?,
            secrets: serde_json::from_str::<Vec<SecretRef>>(&secrets)?,
            notes: row.try_get("notes")?,
        },
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

macro_rules! columns {
    () => {
        "id, name, kind, body, variables, secrets, notes, created_at, updated_at"
    };
}

impl Store {
    /// Every install config, by name.
    pub(crate) async fn list_install_configs(&self, ctx: &Context) -> Result<Vec<InstallConfigRow>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM install_configs WHERE workspace_id = ? ORDER BY name COLLATE NOCASE"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_config).collect()
    }

    pub(crate) async fn install_config_row(&self, ctx: &Context, id: Uuid) -> Result<Option<InstallConfigRow>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM install_configs WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_config).transpose()
    }

    pub(crate) async fn insert_install_config(&self, ctx: &Context, id: Uuid, c: &InstallConfigInput) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO install_configs (id, workspace_id, user_id, name, kind, body, variables, secrets, notes,
                                          created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&c.name)
        .bind(c.kind.as_str())
        .bind(&c.body)
        .bind(serde_json::to_string(&c.variables)?)
        .bind(serde_json::to_string(&c.secrets)?)
        .bind(c.notes.as_deref())
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn update_install_config(&self, ctx: &Context, id: Uuid, c: &InstallConfigInput) -> Result<()> {
        sqlx::query(
            "UPDATE install_configs SET name = ?, kind = ?, body = ?, variables = ?, secrets = ?, notes = ?,
                 user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(&c.name)
        .bind(c.kind.as_str())
        .bind(&c.body)
        .bind(serde_json::to_string(&c.variables)?)
        .bind(serde_json::to_string(&c.secrets)?)
        .bind(c.notes.as_deref())
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
