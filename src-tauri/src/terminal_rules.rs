//! QL-17 highlight and alert rules: the Settings card's list and editor, and the rules the Terminal page gives each
//! pane. Changes are audited by the core (name and scope, never the pattern) and refused by presentation mode's
//! read-only lock. An alert reaches the page as the pane's own event; the notification it may show goes through
//! `notify_terminal_alert` in command_panel.rs.

use remotely_core::terminal::rules::{PatternCheck, TerminalRule, TerminalRuleInput};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Built-in rules first, then the user's, in their order.
#[tauri::command]
pub async fn terminal_rules_list(state: State<'_, AppState>) -> IpcResult<Vec<TerminalRule>> {
    let core = &state.core;
    Ok(core.terminal_rules.list(&core.ctx).await?)
}

/// The editor's live check of a pattern. Changes nothing.
#[tauri::command]
pub fn terminal_rule_validate(state: State<'_, AppState>, pattern: String, case_sensitive: bool) -> PatternCheck {
    state.core.terminal_rules.validate(&pattern, case_sensitive)
}

/// Saves a new rule after the others. Audited.
#[tauri::command]
pub async fn terminal_rule_add(state: State<'_, AppState>, input: TerminalRuleInput) -> IpcResult<TerminalRule> {
    let core = &state.core;
    Ok(core.terminal_rules.create(&core.ctx, input).await?)
}

/// Audited with what changed.
#[tauri::command]
pub async fn terminal_rule_update(
    state: State<'_, AppState>,
    id: Uuid,
    input: TerminalRuleInput,
) -> IpcResult<TerminalRule> {
    let core = &state.core;
    Ok(core.terminal_rules.update(&core.ctx, id, input).await?)
}

/// Audited.
#[tauri::command]
pub async fn terminal_rule_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.terminal_rules.delete(&core.ctx, id).await?)
}

/// The user's rules in a new order (all of them). Audited.
#[tauri::command]
pub async fn terminal_rules_reorder(state: State<'_, AppState>, ids: Vec<Uuid>) -> IpcResult<Vec<TerminalRule>> {
    let core = &state.core;
    Ok(core.terminal_rules.reorder(&core.ctx, &ids).await?)
}

/// Turns a built-in rule, or its alert, on or off. Audited.
#[tauri::command]
pub async fn terminal_rule_set_builtin(
    state: State<'_, AppState>,
    key: String,
    enabled: bool,
    alert: bool,
) -> IpcResult<TerminalRule> {
    let core = &state.core;
    Ok(core.terminal_rules.set_builtin(&core.ctx, &key, enabled, alert).await?)
}
