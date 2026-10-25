//! MO-13: the latest OS and hardware facts per session and per VM (migration 0014). The JSON is
//! written and read by `crate::host_details`.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::domain::Context;
use crate::error::Result;

/// One stored reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSpecs {
    pub specs: String,
    pub collected_at: String,
    /// Sessions only: `terminal`, `dashboard` or `refresh`.
    pub collected_by: Option<String>,
}

impl Store {
    pub(crate) async fn put_session_specs(
        &self,
        ctx: &Context,
        session_id: Uuid,
        specs: &str,
        collected_at: &str,
        collected_by: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO session_specs (session_id, workspace_id, user_id, specs, collected_at, collected_by)
             SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM sessions WHERE id = ? AND workspace_id = ?)
             ON CONFLICT(session_id) DO UPDATE SET
                 specs = excluded.specs, collected_at = excluded.collected_at, collected_by = excluded.collected_by",
        )
        .bind(session_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(specs)
        .bind(collected_at)
        .bind(collected_by)
        .bind(session_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn session_specs(&self, ctx: &Context, session_id: Uuid) -> Result<Option<StoredSpecs>> {
        let row = sqlx::query(
            "SELECT specs, collected_at, collected_by FROM session_specs WHERE workspace_id = ? AND session_id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(StoredSpecs {
                specs: row.try_get("specs")?,
                collected_at: row.try_get("collected_at")?,
                collected_by: row.try_get("collected_by")?,
            })
        })
        .transpose()
    }

    /// When each session's stored facts were read, without the facts (P8: the dashboard's summaries
    /// are parsed again only for facts read since).
    pub(crate) async fn session_specs_times(&self, ctx: &Context) -> Result<HashMap<Uuid, String>> {
        let rows = sqlx::query("SELECT session_id, collected_at FROM session_specs WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let id: String = row.try_get("session_id")?;
                Ok((parse_uuid(&id)?, row.try_get("collected_at")?))
            })
            .collect()
    }

    /// Every session's stored facts (the dashboard's one-line summaries).
    pub(crate) async fn all_session_specs(&self, ctx: &Context) -> Result<HashMap<Uuid, StoredSpecs>> {
        let rows = sqlx::query(
            "SELECT session_id, specs, collected_at, collected_by FROM session_specs WHERE workspace_id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let id: String = row.try_get("session_id")?;
                Ok((
                    parse_uuid(&id)?,
                    StoredSpecs {
                        specs: row.try_get("specs")?,
                        collected_at: row.try_get("collected_at")?,
                        collected_by: row.try_get("collected_by")?,
                    },
                ))
            })
            .collect()
    }

    pub(crate) async fn put_vm_specs(&self, ctx: &Context, vm_id: &str, specs: &str, collected_at: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO vm_specs (vm_id, workspace_id, user_id, specs, collected_at)
             SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM vms WHERE id = ? AND workspace_id = ?)
             ON CONFLICT(vm_id) DO UPDATE SET specs = excluded.specs, collected_at = excluded.collected_at",
        )
        .bind(vm_id)
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(specs)
        .bind(collected_at)
        .bind(vm_id)
        .bind(ctx.workspace_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// QL-21: every VM's stored reading, by VM id, in one query (the topology map).
    pub(crate) async fn all_vm_specs(&self, ctx: &Context) -> Result<HashMap<String, StoredSpecs>> {
        let rows = sqlx::query("SELECT vm_id, specs, collected_at FROM vm_specs WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get("vm_id")?,
                    StoredSpecs {
                        specs: row.try_get("specs")?,
                        collected_at: row.try_get("collected_at")?,
                        collected_by: None,
                    },
                ))
            })
            .collect()
    }

    pub(crate) async fn vm_specs(&self, ctx: &Context, vm_id: &str) -> Result<Option<StoredSpecs>> {
        let row = sqlx::query("SELECT specs, collected_at FROM vm_specs WHERE workspace_id = ? AND vm_id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(vm_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(StoredSpecs {
                specs: row.try_get("specs")?,
                collected_at: row.try_get("collected_at")?,
                collected_by: None,
            })
        })
        .transpose()
    }
}
