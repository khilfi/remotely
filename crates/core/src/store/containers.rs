//! CT-01 container host marks. Checks and audits live in `crate::containers`.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::adapters::containers::EngineKind;
use crate::containers::{ContainerMark, SudoMode};
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};
use crate::vault::SecretId;

fn row_to_mark(row: &sqlx::sqlite::SqliteRow) -> Result<ContainerMark> {
    let session: String = row.try_get("session_id")?;
    let engine: String = row.try_get("engine")?;
    let sudo: String = row.try_get("sudo")?;
    let password: Option<String> = row.try_get("sudo_password_id")?;
    let password_id = password.as_deref().map(parse_uuid).transpose()?.map(SecretId);
    Ok(ContainerMark {
        session_id: parse_uuid(&session)?,
        engine: EngineKind::parse(&engine)
            .ok_or_else(|| CoreError::InvalidInput(format!("unknown container engine '{engine}'")))?,
        sudo: match sudo.as_str() {
            "password" => SudoMode::Password { password_id },
            "no_password" => SudoMode::NoPassword,
            _ => SudoMode::Off,
        },
    })
}

impl Store {
    /// A session's marks (Docker first), or every session's with `None`.
    pub(crate) async fn container_marks(&self, ctx: &Context, session_id: Option<Uuid>) -> Result<Vec<ContainerMark>> {
        let rows = sqlx::query(
            "SELECT session_id, engine, sudo, sudo_password_id FROM container_hosts
             WHERE workspace_id = ? AND (? IS NULL OR session_id = ?) ORDER BY session_id, engine",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(session_id.map(|s| s.to_string()))
        .bind(session_id.map(|s| s.to_string()))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_mark).collect()
    }

    /// Every session's marks, by session (FD-07 export).
    pub(crate) async fn container_marks_by_session(&self, ctx: &Context) -> Result<HashMap<Uuid, Vec<ContainerMark>>> {
        let mut out: HashMap<Uuid, Vec<ContainerMark>> = HashMap::new();
        for mark in self.container_marks(ctx, None).await? {
            out.entry(mark.session_id).or_default().push(mark);
        }
        Ok(out)
    }

    /// Replaces a session's marks with `marks` (none: it is no container host any more).
    pub(crate) async fn replace_container_marks(
        &self,
        ctx: &Context,
        session_id: Uuid,
        marks: &[ContainerMark],
    ) -> Result<()> {
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM container_hosts WHERE workspace_id = ? AND session_id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(session_id.to_string())
            .execute(&mut *tx)
            .await?;
        for mark in marks {
            let (sudo, password) = match mark.sudo {
                SudoMode::Off => ("off", None),
                SudoMode::Password { password_id } => ("password", password_id.map(|p| p.0.to_string())),
                SudoMode::NoPassword => ("no_password", None),
            };
            sqlx::query(
                "INSERT INTO container_hosts (workspace_id, user_id, session_id, engine, sudo, sudo_password_id,
                                              created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(ctx.workspace_id.to_string())
            .bind(ctx.user_id.to_string())
            .bind(session_id.to_string())
            .bind(mark.engine.as_str())
            .bind(sudo)
            .bind(password)
            .bind(&now)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
