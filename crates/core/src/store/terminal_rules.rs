//! QL-17 highlight and alert rules (`terminal_rules`) and the user's changes to the built-in ones
//! (`terminal_builtin_rules`). Checks live in `crate::terminal::rules`.

use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;

/// A rule as stored, before its fields are read into the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalRuleRow {
    pub id: Uuid,
    pub name: String,
    pub pattern: String,
    pub case_sensitive: bool,
    pub color: Option<String>,
    pub style: String,
    pub alert: bool,
    pub scope: String,
    pub environment: Option<String>,
    pub session_id: Option<Uuid>,
    pub enabled: bool,
    pub updated_at: String,
}

/// What [`Store::insert_terminal_rule`] and [`Store::update_terminal_rule`] write. Already checked.
pub(crate) struct TerminalRuleFields<'a> {
    pub name: &'a str,
    pub pattern: &'a str,
    pub case_sensitive: bool,
    pub color: Option<&'a str>,
    pub style: &'a str,
    pub alert: bool,
    pub scope: &'a str,
    pub environment: Option<&'a str>,
    pub session_id: Option<Uuid>,
    pub enabled: bool,
}

/// How the user changed a built-in rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuiltinRuleRow {
    pub rule_key: String,
    pub enabled: bool,
    pub alert: bool,
}

fn row_to_rule(row: &sqlx::sqlite::SqliteRow) -> Result<TerminalRuleRow> {
    let id: String = row.try_get("id")?;
    let session_id: Option<String> = row.try_get("session_id")?;
    Ok(TerminalRuleRow {
        id: parse_uuid(&id)?,
        name: row.try_get("name")?,
        pattern: row.try_get("pattern")?,
        case_sensitive: row.try_get::<i64, _>("case_sensitive")? != 0,
        color: row.try_get("color")?,
        style: row.try_get("style")?,
        alert: row.try_get::<i64, _>("alert")? != 0,
        scope: row.try_get("scope")?,
        environment: row.try_get("environment")?,
        session_id: session_id.as_deref().map(parse_uuid).transpose()?,
        enabled: row.try_get::<i64, _>("enabled")? != 0,
        updated_at: row.try_get("updated_at")?,
    })
}

impl Store {
    /// The user's rules, in their order.
    pub(crate) async fn list_terminal_rules(&self, ctx: &Context) -> Result<Vec<TerminalRuleRow>> {
        let rows = sqlx::query(
            "SELECT id, name, pattern, case_sensitive, color, style, alert, scope, environment, session_id, enabled,
                    updated_at
             FROM terminal_rules WHERE workspace_id = ? ORDER BY position, rowid",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_rule).collect()
    }

    pub(crate) async fn terminal_rule(&self, ctx: &Context, id: Uuid) -> Result<Option<TerminalRuleRow>> {
        let row = sqlx::query(
            "SELECT id, name, pattern, case_sensitive, color, style, alert, scope, environment, session_id, enabled,
                    updated_at
             FROM terminal_rules WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_rule).transpose()
    }

    /// Adds it after the others.
    pub(crate) async fn insert_terminal_rule(
        &self,
        ctx: &Context,
        id: Uuid,
        fields: &TerminalRuleFields<'_>,
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO terminal_rules (id, workspace_id, user_id, name, pattern, case_sensitive, color, style, alert,
                                         scope, environment, session_id, enabled, position, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                     (SELECT COALESCE(MAX(position), -1) + 1 FROM terminal_rules WHERE workspace_id = ?),
                     ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(fields.name)
        .bind(fields.pattern)
        .bind(i64::from(fields.case_sensitive))
        .bind(fields.color)
        .bind(fields.style)
        .bind(i64::from(fields.alert))
        .bind(fields.scope)
        .bind(fields.environment)
        .bind(fields.session_id.map(|s| s.to_string()))
        .bind(i64::from(fields.enabled))
        .bind(ctx.workspace_id.to_string())
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Keeps its place in the order.
    pub(crate) async fn update_terminal_rule(
        &self,
        ctx: &Context,
        id: Uuid,
        fields: &TerminalRuleFields<'_>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE terminal_rules SET
                 name = ?, pattern = ?, case_sensitive = ?, color = ?, style = ?, alert = ?, scope = ?,
                 environment = ?, session_id = ?, enabled = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(fields.name)
        .bind(fields.pattern)
        .bind(i64::from(fields.case_sensitive))
        .bind(fields.color)
        .bind(fields.style)
        .bind(i64::from(fields.alert))
        .bind(fields.scope)
        .bind(fields.environment)
        .bind(fields.session_id.map(|s| s.to_string()))
        .bind(i64::from(fields.enabled))
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn delete_terminal_rule(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM terminal_rules WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Numbers the rules 0, 1, 2… in the order given (all of them, checked by the caller).
    pub(crate) async fn order_terminal_rules(&self, ctx: &Context, ids: &[Uuid]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for (position, id) in ids.iter().enumerate() {
            sqlx::query("UPDATE terminal_rules SET position = ? WHERE workspace_id = ? AND id = ?")
                .bind(i64::try_from(position).unwrap_or(i64::MAX))
                .bind(ctx.workspace_id.to_string())
                .bind(id.to_string())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The built-in rules the user turned on or off, or whose alert they changed.
    pub(crate) async fn terminal_builtin_rules(&self, ctx: &Context) -> Result<Vec<BuiltinRuleRow>> {
        let rows = sqlx::query("SELECT rule_key, enabled, alert FROM terminal_builtin_rules WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(BuiltinRuleRow {
                    rule_key: row.try_get("rule_key")?,
                    enabled: row.try_get::<i64, _>("enabled")? != 0,
                    alert: row.try_get::<i64, _>("alert")? != 0,
                })
            })
            .collect()
    }

    pub(crate) async fn set_terminal_builtin_rule(
        &self,
        ctx: &Context,
        rule_key: &str,
        enabled: bool,
        alert: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO terminal_builtin_rules (workspace_id, user_id, rule_key, enabled, alert, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, rule_key) DO UPDATE SET
                 user_id = excluded.user_id, enabled = excluded.enabled, alert = excluded.alert,
                 updated_at = excluded.updated_at",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(rule_key)
        .bind(i64::from(enabled))
        .bind(i64::from(alert))
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
