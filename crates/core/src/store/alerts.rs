//! MO-07: alert rules and the alert list ([`crate::alerts`]). Resolved alerts are pruned with the dashboard's
//! history ([`Store::prune_history`]).

use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::alerts::rules::{AlertMetric, AlertRule, AlertRuleInput, AlertScope, Builtin, Severity};
use crate::alerts::{Alert, AlertTarget, AlertTargetKind, Resolution};
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};

fn corrupt(what: &str, value: &str) -> CoreError {
    sqlx::Error::Decode(format!("unknown {what} '{value}' in the alert tables").into()).into()
}

fn rule_from(row: &SqliteRow) -> Result<AlertRule> {
    let metric: String = row.try_get("metric")?;
    let scope_kind: String = row.try_get("scope_kind")?;
    let severity: String = row.try_get("severity")?;
    let id: String = row.try_get("id")?;
    Ok(AlertRule {
        id: parse_uuid(&id)?,
        builtin: row.try_get("builtin")?,
        name: row.try_get("name")?,
        metric: AlertMetric::parse(&metric).ok_or_else(|| corrupt("metric", &metric))?,
        scope: AlertScope::from_parts(&scope_kind, row.try_get("scope_key")?)
            .ok_or_else(|| corrupt("scope", &scope_kind))?,
        threshold: row.try_get("threshold")?,
        for_secs: u64::try_from(row.try_get::<i64, _>("for_secs")?).unwrap_or(0),
        severity: Severity::parse(&severity).ok_or_else(|| corrupt("severity", &severity))?,
        notify: row.try_get("notify")?,
        enabled: row.try_get("enabled")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn alert_from(row: &SqliteRow) -> Result<Alert> {
    let id: String = row.try_get("id")?;
    let rule_id: String = row.try_get("rule_id")?;
    let metric: String = row.try_get("metric")?;
    let severity: String = row.try_get("severity")?;
    let kind: String = row.try_get("target_kind")?;
    let resolution: Option<String> = row.try_get("resolution")?;
    Ok(Alert {
        id: parse_uuid(&id)?,
        rule_id: parse_uuid(&rule_id)?,
        rule_name: row.try_get("rule_name")?,
        metric: AlertMetric::parse(&metric).ok_or_else(|| corrupt("metric", &metric))?,
        severity: Severity::parse(&severity).ok_or_else(|| corrupt("severity", &severity))?,
        target: AlertTarget {
            kind: AlertTargetKind::parse(&kind).ok_or_else(|| corrupt("target", &kind))?,
            key: row.try_get("target_key")?,
            name: row.try_get("target_name")?,
        },
        threshold: row.try_get("threshold")?,
        for_secs: u64::try_from(row.try_get::<i64, _>("for_secs")?).unwrap_or(0),
        value: row.try_get("value")?,
        peak: row.try_get("peak")?,
        message: row.try_get("message")?,
        fired_at: row.try_get("fired_at")?,
        resolved_at: row.try_get("resolved_at")?,
        resolution: resolution.as_deref().and_then(Resolution::parse),
        acknowledged_at: row.try_get("acknowledged_at")?,
    })
}

impl Store {
    /// MO-07: adds the built-in rules this workspace doesn't have yet, as Remotely ships them. Rules already
    /// there keep the owner's changes.
    pub async fn ensure_builtin_rules(&self, ctx: &Context, builtins: &[Builtin]) -> Result<()> {
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        for builtin in builtins {
            let input = builtin.input();
            sqlx::query(
                "INSERT INTO alert_rules (id, workspace_id, user_id, builtin, name, metric, scope_kind, scope_key,
                                          threshold, for_secs, severity, notify, enabled, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (workspace_id, builtin) DO NOTHING",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(ctx.workspace_id.to_string())
            .bind(ctx.user_id.to_string())
            .bind(builtin.key)
            .bind(&input.name)
            .bind(input.metric.as_str())
            .bind(input.scope.kind_str())
            .bind(input.scope.key())
            .bind(input.threshold)
            .bind(i64::try_from(input.for_secs).unwrap_or(0))
            .bind(input.severity.as_str())
            .bind(input.notify)
            .bind(input.enabled)
            .bind(&now)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// MO-07: the workspace's rules, built-in ones first (in Remotely's order), then the owner's by name.
    pub async fn alert_rules(&self, ctx: &Context) -> Result<Vec<AlertRule>> {
        let rows = sqlx::query(
            "SELECT id, builtin, name, metric, scope_kind, scope_key, threshold, for_secs, severity, notify, enabled,
                    updated_at
             FROM alert_rules WHERE workspace_id = ?
             ORDER BY builtin IS NULL, created_at, name COLLATE NOCASE",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut rules = rows.iter().map(rule_from).collect::<Result<Vec<_>>>()?;
        // Built-in rules in the order Remotely lists them, whenever each was created.
        let order = |rule: &AlertRule| {
            rule.builtin
                .as_deref()
                .and_then(|key| crate::alerts::rules::BUILTINS.iter().position(|b| b.key == key))
                .unwrap_or(usize::MAX)
        };
        rules.sort_by_key(|r| (r.builtin.is_none(), order(r)));
        Ok(rules)
    }

    pub async fn alert_rule(&self, ctx: &Context, id: Uuid) -> Result<Option<AlertRule>> {
        let row = sqlx::query(
            "SELECT id, builtin, name, metric, scope_kind, scope_key, threshold, for_secs, severity, notify, enabled,
                    updated_at
             FROM alert_rules WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(rule_from).transpose()
    }

    pub async fn insert_alert_rule(
        &self,
        ctx: &Context,
        builtin: Option<&str>,
        input: &AlertRuleInput,
    ) -> Result<AlertRule> {
        let id = Uuid::new_v4();
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO alert_rules (id, workspace_id, user_id, builtin, name, metric, scope_kind, scope_key,
                                      threshold, for_secs, severity, notify, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(builtin)
        .bind(&input.name)
        .bind(input.metric.as_str())
        .bind(input.scope.kind_str())
        .bind(input.scope.key())
        .bind(input.threshold)
        .bind(i64::try_from(input.for_secs).unwrap_or(0))
        .bind(input.severity.as_str())
        .bind(input.notify)
        .bind(input.enabled)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        self.alert_rule(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(id.to_string()))
    }

    pub async fn update_alert_rule(
        &self,
        ctx: &Context,
        id: Uuid,
        input: &AlertRuleInput,
    ) -> Result<Option<AlertRule>> {
        let done = sqlx::query(
            "UPDATE alert_rules SET user_id = ?, name = ?, metric = ?, scope_kind = ?, scope_key = ?, threshold = ?,
                    for_secs = ?, severity = ?, notify = ?, enabled = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.user_id.to_string())
        .bind(&input.name)
        .bind(input.metric.as_str())
        .bind(input.scope.kind_str())
        .bind(input.scope.key())
        .bind(input.threshold)
        .bind(i64::try_from(input.for_secs).unwrap_or(0))
        .bind(input.severity.as_str())
        .bind(input.notify)
        .bind(input.enabled)
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        if done.rows_affected() == 0 {
            return Ok(None);
        }
        self.alert_rule(ctx, id).await
    }

    pub async fn delete_alert_rule(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM alert_rules WHERE workspace_id = ? AND id = ? AND builtin IS NULL")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// MO-07: a new alert in the list.
    pub async fn insert_alert(&self, ctx: &Context, alert: &Alert) -> Result<()> {
        sqlx::query(
            "INSERT INTO alerts (id, workspace_id, user_id, rule_id, rule_name, metric, severity, target_kind,
                                 target_key, target_name, threshold, for_secs, value, peak, message, fired_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(alert.id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(alert.rule_id.to_string())
        .bind(&alert.rule_name)
        .bind(alert.metric.as_str())
        .bind(alert.severity.as_str())
        .bind(alert.target.kind.as_str())
        .bind(&alert.target.key)
        .bind(&alert.target.name)
        .bind(alert.threshold)
        .bind(i64::try_from(alert.for_secs).unwrap_or(0))
        .bind(alert.value)
        .bind(alert.peak)
        .bind(&alert.message)
        .bind(&alert.fired_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// MO-07: an alert stopped firing. Returns it as it is now; `None` when it was not open.
    pub async fn resolve_alert(
        &self,
        ctx: &Context,
        id: Uuid,
        resolution: Resolution,
        peak: Option<f64>,
        at: &str,
    ) -> Result<Option<Alert>> {
        let done = sqlx::query(
            "UPDATE alerts SET resolved_at = ?, resolution = ?, peak = COALESCE(?, peak)
             WHERE workspace_id = ? AND id = ? AND resolved_at IS NULL",
        )
        .bind(at)
        .bind(resolution.as_str())
        .bind(peak)
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        if done.rows_affected() == 0 {
            return Ok(None);
        }
        self.alert(ctx, id).await
    }

    pub async fn alert(&self, ctx: &Context, id: Uuid) -> Result<Option<Alert>> {
        let row = sqlx::query(
            "SELECT id, rule_id, rule_name, metric, severity, target_kind, target_key, target_name, threshold, for_secs,
                    value, peak, message, fired_at, resolved_at, resolution, acknowledged_at
             FROM alerts WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(alert_from).transpose()
    }

    /// MO-07: closes every alert still open (at start: the app closed while they fired). Returns how many.
    pub async fn close_open_alerts(&self, ctx: &Context, resolution: Resolution, at: &str) -> Result<u64> {
        let done = sqlx::query(
            "UPDATE alerts SET resolved_at = ?, resolution = ? WHERE workspace_id = ? AND resolved_at IS NULL",
        )
        .bind(at)
        .bind(resolution.as_str())
        .bind(ctx.workspace_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// MO-07: the newest alerts first; only open ones when `open_only`.
    pub async fn list_alerts(&self, ctx: &Context, open_only: bool, limit: u32) -> Result<Vec<Alert>> {
        let rows = if open_only {
            sqlx::query(
                "SELECT id, rule_id, rule_name, metric, severity, target_kind, target_key, target_name, threshold,
                        for_secs, value, peak, message, fired_at, resolved_at, resolution, acknowledged_at
                 FROM alerts WHERE workspace_id = ? AND resolved_at IS NULL ORDER BY fired_at DESC LIMIT ?",
            )
        } else {
            sqlx::query(
                "SELECT id, rule_id, rule_name, metric, severity, target_kind, target_key, target_name, threshold,
                        for_secs, value, peak, message, fired_at, resolved_at, resolution, acknowledged_at
                 FROM alerts WHERE workspace_id = ? ORDER BY fired_at DESC LIMIT ?",
            )
        }
        .bind(ctx.workspace_id.to_string())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(alert_from).collect()
    }

    /// MO-07: alerts open, and open and not acknowledged.
    pub async fn alert_counts(&self, ctx: &Context) -> Result<(u64, u64)> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS open, COALESCE(SUM(acknowledged_at IS NULL), 0) AS unacknowledged
             FROM alerts WHERE workspace_id = ? AND resolved_at IS NULL",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_one(&self.pool)
        .await?;
        let open: i64 = row.try_get("open")?;
        let unacknowledged: i64 = row.try_get("unacknowledged")?;
        Ok((open.unsigned_abs(), unacknowledged.unsigned_abs()))
    }

    /// MO-07: acknowledges `ids` (every open alert when empty) that were not yet. Returns those it changed.
    pub async fn acknowledge_alerts(&self, ctx: &Context, ids: &[Uuid], at: &str) -> Result<Vec<Alert>> {
        let ws = ctx.workspace_id.to_string();
        let chosen: Vec<String> = if ids.is_empty() {
            sqlx::query_scalar(
                "SELECT id FROM alerts WHERE workspace_id = ? AND resolved_at IS NULL AND acknowledged_at IS NULL",
            )
            .bind(&ws)
            .fetch_all(&self.pool)
            .await?
        } else {
            ids.iter().map(Uuid::to_string).collect()
        };
        let mut changed = Vec::new();
        let mut tx = self.pool.begin().await?;
        for id in &chosen {
            let done = sqlx::query(
                "UPDATE alerts SET acknowledged_at = ? WHERE workspace_id = ? AND id = ? AND acknowledged_at IS NULL",
            )
            .bind(at)
            .bind(&ws)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            if done.rows_affected() > 0 {
                changed.push(id.clone());
            }
        }
        tx.commit().await?;
        let mut alerts = Vec::new();
        for id in changed {
            if let Some(alert) = self.alert(ctx, parse_uuid(&id)?).await? {
                alerts.push(alert);
            }
        }
        Ok(alerts)
    }

    /// MO-07: whether a job acted on the VM `key` lately: one still open, or one that finished at `since` or
    /// later (RFC 3339 times, compared as the journal stores them). Only jobs from the last day are looked at.
    pub async fn vm_job_since(&self, ctx: &Context, key: &str, since: time::OffsetDateTime) -> Result<bool> {
        let format = |t: time::OffsetDateTime| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| t.unix_timestamp().to_string())
        };
        let day = format(since - time::Duration::days(1));
        let since = format(since);
        let found: i64 = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM jobs j JOIN job_targets t ON t.job_id = j.id
                 WHERE j.workspace_id = ? AND j.created_at >= ? AND t.target_kind = 'vm'
                   AND t.target_key = ? COLLATE NOCASE
                   AND (j.status IN ('queued', 'countdown', 'running') OR j.finished_at >= ?))",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(day)
        .bind(key)
        .bind(since)
        .fetch_one(&self.pool)
        .await?;
        Ok(found != 0)
    }
}
