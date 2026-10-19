//! SS-07 port forward rows. Checks live in `crate::forwards`.

use std::collections::HashMap;

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::adapters::remote::forward::{ForwardKind, ForwardSpec};
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};
use crate::forwards::PortForward;

macro_rules! forward_columns {
    () => {
        "id, session_id, label, kind, bind_address, bind_port, dest_host, dest_port, auto_start, created_at, updated_at"
    };
}

fn row_to_forward(row: &sqlx::sqlite::SqliteRow) -> Result<PortForward> {
    let id: String = row.try_get("id")?;
    let session: String = row.try_get("session_id")?;
    let kind: String = row.try_get("kind")?;
    let bind_port: i64 = row.try_get("bind_port")?;
    let dest_port: i64 = row.try_get("dest_port")?;
    let auto_start: i64 = row.try_get("auto_start")?;
    Ok(PortForward {
        id: parse_uuid(&id)?,
        session_id: parse_uuid(&session)?,
        label: row.try_get("label")?,
        spec: ForwardSpec {
            kind: ForwardKind::parse(&kind)
                .ok_or_else(|| CoreError::InvalidInput(format!("unknown kind of port forward '{kind}'")))?,
            bind_address: row.try_get("bind_address")?,
            bind_port: u16::try_from(bind_port).unwrap_or(0),
            dest_host: row.try_get("dest_host")?,
            dest_port: u16::try_from(dest_port).unwrap_or(0),
        },
        auto_start: auto_start != 0,
    })
}

impl Store {
    /// A session's forwards, in its order.
    pub(crate) async fn list_forwards(&self, ctx: &Context, session_id: Uuid) -> Result<Vec<PortForward>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            forward_columns!(),
            " FROM port_forwards WHERE workspace_id = ? AND session_id = ? ORDER BY position, rowid"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(session_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_forward).collect()
    }

    /// Every session's forwards, by session, each in its order.
    pub(crate) async fn all_forwards(&self, ctx: &Context) -> Result<HashMap<Uuid, Vec<PortForward>>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            forward_columns!(),
            " FROM port_forwards WHERE workspace_id = ? ORDER BY session_id, position, rowid"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut by_session: HashMap<Uuid, Vec<PortForward>> = HashMap::new();
        for row in &rows {
            let forward = row_to_forward(row)?;
            by_session.entry(forward.session_id).or_default().push(forward);
        }
        Ok(by_session)
    }

    pub(crate) async fn forward(&self, ctx: &Context, id: Uuid) -> Result<Option<PortForward>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            forward_columns!(),
            " FROM port_forwards WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_forward).transpose()
    }

    /// Replaces a session's forwards with these, in this order (already checked). A forward that
    /// keeps its id keeps when it was created.
    pub(crate) async fn replace_forwards(
        &self,
        ctx: &Context,
        session_id: Uuid,
        forwards: &[PortForward],
    ) -> Result<()> {
        let ws = ctx.workspace_id.to_string();
        let session = session_id.to_string();
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        let created: HashMap<String, String> =
            sqlx::query("SELECT id, created_at FROM port_forwards WHERE workspace_id = ? AND session_id = ?")
                .bind(&ws)
                .bind(&session)
                .fetch_all(&mut *tx)
                .await?
                .iter()
                .map(|r| Ok((r.try_get("id")?, r.try_get("created_at")?)))
                .collect::<Result<_>>()?;
        sqlx::query("DELETE FROM port_forwards WHERE workspace_id = ? AND session_id = ?")
            .bind(&ws)
            .bind(&session)
            .execute(&mut *tx)
            .await?;
        for (position, forward) in forwards.iter().enumerate() {
            let id = forward.id.to_string();
            sqlx::query(
                "INSERT INTO port_forwards (id, workspace_id, user_id, session_id, position, label, kind, bind_address,
                                            bind_port, dest_host, dest_port, auto_start, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&ws)
            .bind(ctx.user_id.to_string())
            .bind(&session)
            .bind(i64::try_from(position).unwrap_or(i64::MAX))
            .bind(forward.label.as_deref())
            .bind(forward.spec.kind.as_str())
            .bind(&forward.spec.bind_address)
            .bind(i64::from(forward.spec.bind_port))
            .bind(&forward.spec.dest_host)
            .bind(i64::from(forward.spec.dest_port))
            .bind(i64::from(forward.auto_start))
            .bind(created.get(&id).unwrap_or(&now))
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
