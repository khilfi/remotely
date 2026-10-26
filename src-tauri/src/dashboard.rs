//! The dashboard's 0.5.0 commands: MO-06 history on disk (charts' ranges, the retention setting), MO-07 alerts
//! (rules, the list, acknowledging, and the Windows notification the UI asks for once it has masked the text),
//! and MO-16 the layout and its services widget. Reads go straight to the core; rule, acknowledgement and
//! layout changes are the app's own data, audited there and refused by the read-only lock.

use remotely_core::alerts::{AlertList, AlertQuery, AlertRule, AlertRuleInput};
use remotely_core::dashboard::{DashboardLayout, LayoutInfo};
use remotely_core::host_details::ServicesRead;
use remotely_core::metrics::history::{
    now_ms, HistoryInfo, HistoryRange, HistoryRetention, HistorySeries, HistorySource,
};
use remotely_core::CoreError;
use tauri::{AppHandle, State};
use tauri_plugin_notification::NotificationExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Longest notification title and text the UI may ask for.
const MAX_TITLE: usize = 120;
const MAX_BODY: usize = 400;

/// The most alerts one acknowledgement names.
const MAX_ACKNOWLEDGE: usize = 500;

/// MO-06: one series' stored minutes over a range, in buckets (1 minute to 30 minutes), up to now. The chart
/// then carries on with the live rounds (`metrics_series`). A read: no approval, not audited.
#[tauri::command]
pub async fn metrics_history(
    state: State<'_, AppState>,
    source: HistorySource,
    key: String,
    range: HistoryRange,
) -> IpcResult<HistorySeries> {
    if key.is_empty() || key.len() > 1024 {
        return Err(CoreError::InvalidInput("Choose a VM or host.".into()).into());
    }
    let core = &state.core;
    Ok(core.history.series(&core.ctx(), source, &key, range, now_ms()).await?)
}

/// MO-06: how long the history is kept, what it holds and the last prune, for Settings.
#[tauri::command]
pub async fn history_info(state: State<'_, AppState>) -> IpcResult<HistoryInfo> {
    Ok(state.core.history.info().await?)
}

/// MO-06: how long the history is kept (1, 3, 7, 14 or 30 days). Audited; a shorter time prunes at once.
#[tauri::command]
pub async fn history_retention_set(state: State<'_, AppState>, retention: HistoryRetention) -> IpcResult<HistoryInfo> {
    Ok(state.core.history.set_retention(retention).await?)
}

/// MO-07: the alert list (firing ones, or the history too) and its counts.
#[tauri::command]
pub async fn alerts_list(state: State<'_, AppState>, query: Option<AlertQuery>) -> IpcResult<AlertList> {
    Ok(state.core.alerts.list(query.unwrap_or_default()).await?)
}

/// MO-07: acknowledges alerts (all open ones when `ids` is empty). Audited.
#[tauri::command]
pub async fn alerts_acknowledge(state: State<'_, AppState>, ids: Vec<Uuid>) -> IpcResult<Vec<Uuid>> {
    if ids.len() > MAX_ACKNOWLEDGE {
        return Err(CoreError::InvalidInput(format!("At most {MAX_ACKNOWLEDGE} alerts at once.")).into());
    }
    Ok(state.core.alerts.acknowledge(&ids).await?)
}

/// MO-07: the rules, built-in ones first.
#[tauri::command]
pub fn alert_rules(state: State<'_, AppState>) -> Vec<AlertRule> {
    state.core.alerts.rules()
}

/// MO-07. Audited.
#[tauri::command]
pub async fn alert_rule_create(state: State<'_, AppState>, input: AlertRuleInput) -> IpcResult<AlertRule> {
    Ok(state.core.alerts.create_rule(input).await?)
}

/// MO-07. Audited.
#[tauri::command]
pub async fn alert_rule_update(state: State<'_, AppState>, id: Uuid, input: AlertRuleInput) -> IpcResult<AlertRule> {
    Ok(state.core.alerts.update_rule(id, input).await?)
}

/// MO-07: a rule of the owner's own. Audited.
#[tauri::command]
pub async fn alert_rule_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    Ok(state.core.alerts.delete_rule(id).await?)
}

/// MO-07: a built-in rule back to its defaults. Audited.
#[tauri::command]
pub async fn alert_rule_reset(state: State<'_, AppState>, id: Uuid) -> IpcResult<AlertRule> {
    Ok(state.core.alerts.reset_rule(id).await?)
}

/// MO-07: a Windows notification for alerts that fired. The core decides when (its cooldown); the UI masks the
/// text while presenting (`maskedOutside`) and groups a round's alerts into one.
#[tauri::command]
pub fn alert_notify(app: AppHandle, title: String, body: String) -> IpcResult<()> {
    let title: String = title.chars().filter(|c| !c.is_control()).take(MAX_TITLE).collect();
    let body: String = body.chars().filter(|c| !c.is_control()).take(MAX_BODY).collect();
    if title.trim().is_empty() {
        return Err(CoreError::InvalidInput("A notification needs a title.".into()).into());
    }
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|err| IpcError::new("notification", format!("the notification could not be shown: {err}")))?;
    tracing::info!("alert notification shown");
    Ok(())
}

/// MO-16: this workspace's layout, or the default.
#[tauri::command]
pub async fn dashboard_layout(state: State<'_, AppState>) -> IpcResult<LayoutInfo> {
    Ok(state.core.layouts.get().await?)
}

/// MO-16: saves the layout the editor arranged. Audited.
#[tauri::command]
pub async fn dashboard_layout_set(state: State<'_, AppState>, layout: DashboardLayout) -> IpcResult<LayoutInfo> {
    Ok(state.core.layouts.set(layout).await?)
}

/// MO-16: back to the default layout. Audited.
#[tauri::command]
pub async fn dashboard_layout_reset(state: State<'_, AppState>) -> IpcResult<LayoutInfo> {
    Ok(state.core.layouts.reset().await?)
}

/// MO-16: the services widget's read of a watched host, on the dashboard's kept connection only (no login).
#[tauri::command]
pub async fn host_services(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<ServicesRead> {
    Ok(state.core.host_details.services(session_id).await?)
}
