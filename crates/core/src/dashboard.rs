//! MO-16: the dashboard's layout: which widgets it shows, in what order and at what size, saved per workspace.
//!
//! Widgets sit on a grid of [`GRID_COLUMNS`] columns, in order, each [`Widget::w`] columns wide and
//! [`Widget::h`] rows tall: the overview grid, host capacity, this PC's memory and the alert list (one of each
//! at most), the services of a chosen SSH host (MO-14, read on the dashboard's kept connection) and charts of
//! a chosen VM, host or this PC. The layout is a setting (`dashboard.layout`, per workspace, set aside by
//! QL-15's repair when this version can't read it); null or missing means the default. Saving and resetting it
//! are audited and refused by the FD-03 read-only lock; the editor saves once, when the owner is done.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{Context, THIS_PC_KEY};
use crate::error::{CoreError, Result};
use crate::metrics::history::HistorySource;
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};

/// The setting: `Option<DashboardLayout>` (null: the default).
pub const LAYOUT_KEY: &str = "dashboard.layout";

pub const LAYOUT_VERSION: u32 = 1;

/// Columns of the grid; a widget is 1 to 4 of them wide.
pub const GRID_COLUMNS: u8 = 4;

/// The tallest a widget can be, in rows.
pub const MAX_ROWS: u8 = 6;

pub const MAX_WIDGETS: usize = 24;

const MAX_ID: usize = 40;
const MAX_KEY: usize = 1024;
const MAX_NAME: usize = 200;

/// What a chart widget draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChartMetric {
    Cpu,
    Memory,
    Swap,
    DiskIo,
    Network,
    Load,
    DiskUsed,
}

/// A chart widget's range: the live rounds in memory, or MO-06's history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChartRange {
    #[default]
    #[serde(rename = "live")]
    Live,
    #[serde(rename = "1h")]
    Hour,
    #[serde(rename = "6h")]
    SixHours,
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
}

/// A widget and what it shows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum WidgetKind {
    /// MO-03: the running VMs and watched hosts, with filters and the drill-down.
    Overview,
    /// MO-04: RAM, CPU and VM folders' drives.
    Capacity,
    /// MO-15: this PC's RAM and paging files.
    ThisPcMemory,
    /// MO-07: firing alerts and the history.
    Alerts,
    /// MO-14: a watched SSH host's running and failed services. `None` until one is chosen.
    Services {
        #[serde(default)]
        session_id: Option<Uuid>,
    },
    /// A metric of a VM (host side), a watched host (guest) or this PC, live or from the history.
    Chart {
        #[serde(default)]
        source: Option<HistorySource>,
        #[serde(default)]
        key: Option<String>,
        /// The name it had when chosen, shown when it isn't on the dashboard now.
        #[serde(default)]
        name: Option<String>,
        metric: ChartMetric,
        #[serde(default)]
        range: ChartRange,
    },
}

impl WidgetKind {
    fn label(&self) -> String {
        match self {
            WidgetKind::Overview => "overview".into(),
            WidgetKind::Capacity => "capacity".into(),
            WidgetKind::ThisPcMemory => "this PC's memory".into(),
            WidgetKind::Alerts => "alerts".into(),
            WidgetKind::Services { session_id } => match session_id {
                Some(_) => "services of a host".into(),
                None => "services (no host chosen)".into(),
            },
            WidgetKind::Chart { name, metric, .. } => {
                let metric = serde_json::to_value(metric)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                match name {
                    Some(name) => format!("{metric} chart of {name}"),
                    None => format!("{metric} chart"),
                }
            }
        }
    }

    /// At most one of these on a dashboard.
    fn single(&self) -> Option<&'static str> {
        match self {
            WidgetKind::Overview => Some("overview"),
            WidgetKind::Capacity => Some("capacity"),
            WidgetKind::ThisPcMemory => Some("this PC's memory"),
            WidgetKind::Alerts => Some("alert list"),
            WidgetKind::Services { .. } | WidgetKind::Chart { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Widget {
    /// Stable within the layout (the UI's key and drag handle).
    pub id: String,
    /// Columns wide, 1 to [`GRID_COLUMNS`].
    pub w: u8,
    /// Rows tall, 1 to [`MAX_ROWS`].
    pub h: u8,
    #[serde(flatten)]
    pub kind: WidgetKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardLayout {
    pub version: u32,
    pub widgets: Vec<Widget>,
}

impl Default for DashboardLayout {
    /// What the dashboard showed before MO-16, with the alert list beside this PC's memory.
    fn default() -> Self {
        let widget = |id: &str, w, h, kind| Widget {
            id: id.into(),
            w,
            h,
            kind,
        };
        Self {
            version: LAYOUT_VERSION,
            widgets: vec![
                widget("capacity", 4, 2, WidgetKind::Capacity),
                widget("this-pc-memory", 2, 2, WidgetKind::ThisPcMemory),
                widget("alerts", 2, 2, WidgetKind::Alerts),
                widget("overview", 4, 5, WidgetKind::Overview),
            ],
        }
    }
}

impl DashboardLayout {
    /// Refused, with a reason, when the layout can't be saved as it is.
    pub fn validate(&self) -> Result<()> {
        let invalid = |why: String| Err(CoreError::InvalidInput(why));
        if self.version != LAYOUT_VERSION {
            return invalid(format!(
                "This layout is version {}; Remotely reads version {LAYOUT_VERSION}.",
                self.version
            ));
        }
        if self.widgets.len() > MAX_WIDGETS {
            return invalid(format!("A dashboard can hold at most {MAX_WIDGETS} widgets."));
        }
        let mut ids = HashSet::new();
        let mut singles = HashSet::new();
        for widget in &self.widgets {
            let id_ok = !widget.id.is_empty()
                && widget.id.len() <= MAX_ID
                && widget
                    .id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if !id_ok {
                return invalid("A widget's id is 1 to 40 letters, digits, '-' or '_'.".into());
            }
            if !ids.insert(widget.id.as_str()) {
                return invalid(format!("Two widgets share the id '{}'.", widget.id));
            }
            if !(1..=GRID_COLUMNS).contains(&widget.w) || !(1..=MAX_ROWS).contains(&widget.h) {
                return invalid(format!(
                    "A widget is 1 to {GRID_COLUMNS} columns wide and 1 to {MAX_ROWS} rows tall."
                ));
            }
            if let Some(kind) = widget.kind.single() {
                if !singles.insert(kind) {
                    return invalid(format!("A dashboard shows the {kind} once."));
                }
            }
            if let WidgetKind::Chart { source, key, name, .. } = &widget.kind {
                let text_ok = |t: &Option<String>, max: usize| {
                    t.as_ref()
                        .is_none_or(|t| t.len() <= max && !t.chars().any(char::is_control))
                };
                if !text_ok(key, MAX_KEY) || !text_ok(name, MAX_NAME) {
                    return invalid("A chart's VM or host is too long or holds control characters.".into());
                }
                match (source, key.as_deref()) {
                    (None, None) => {}
                    (Some(HistorySource::ThisPc), Some(THIS_PC_KEY)) => {}
                    (Some(HistorySource::Host | HistorySource::Guest), Some(k)) if !k.trim().is_empty() => {}
                    _ => return invalid("Choose the VM or host the chart draws.".into()),
                }
            }
        }
        Ok(())
    }

    /// The widgets in a line, for the audit log: "capacity 4x2, alerts 2x2, overview 4x5".
    pub fn describe(&self) -> String {
        if self.widgets.is_empty() {
            return "no widgets".into();
        }
        self.widgets
            .iter()
            .map(|w| format!("{} {}x{}", w.kind.label(), w.w, w.h))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The layout in use and the grid's limits, for the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayoutInfo {
    pub layout: DashboardLayout,
    /// The owner arranged it; false: the default.
    pub custom: bool,
    pub columns: u8,
    pub max_rows: u8,
    pub max_widgets: usize,
}

/// MO-16: the saved layout of this workspace (`Core.layouts`).
pub struct Layouts {
    store: Store,
    ctx: Context,
}

impl Layouts {
    pub fn new(store: Store, ctx: Context) -> Self {
        Self { store, ctx }
    }

    fn info(&self, saved: Option<DashboardLayout>) -> LayoutInfo {
        let custom = saved.is_some();
        LayoutInfo {
            layout: saved.unwrap_or_default(),
            custom,
            columns: GRID_COLUMNS,
            max_rows: MAX_ROWS,
            max_widgets: MAX_WIDGETS,
        }
    }

    /// The saved layout, or the default. A saved one that no longer passes the checks gives the default (it is
    /// kept until the next save).
    pub async fn get(&self) -> Result<LayoutInfo> {
        let saved = self
            .store
            .get_setting::<Option<DashboardLayout>>(&self.ctx, LAYOUT_KEY)
            .await?
            .flatten();
        let saved = saved.filter(|layout| match layout.validate() {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(error = %err, "the saved dashboard layout can't be used; showing the default");
                false
            }
        });
        Ok(self.info(saved))
    }

    /// Saves the layout. Audited; refused while presenting with the read-only lock.
    pub async fn set(&self, layout: DashboardLayout) -> Result<LayoutInfo> {
        self.store.read_only().check(Change::DashboardLayout)?;
        layout.validate()?;
        self.store.put_setting(&self.ctx, LAYOUT_KEY, &Some(&layout)).await?;
        self.audit("Changed the dashboard layout", &layout.describe()).await?;
        Ok(self.info(Some(layout)))
    }

    /// Back to the default layout. Audited; refused while presenting.
    pub async fn reset(&self) -> Result<LayoutInfo> {
        self.store.read_only().check(Change::DashboardLayout)?;
        self.store
            .put_setting(&self.ctx, LAYOUT_KEY, &Option::<DashboardLayout>::None)
            .await?;
        self.audit(
            "Reset the dashboard layout",
            &format!("the default: {}", DashboardLayout::default().describe()),
        )
        .await?;
        Ok(self.info(None))
    }

    async fn audit(&self, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event: "dashboard_layout_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chart(id: &str, source: Option<HistorySource>, key: Option<&str>) -> Widget {
        Widget {
            id: id.into(),
            w: 2,
            h: 2,
            kind: WidgetKind::Chart {
                source,
                key: key.map(str::to_owned),
                name: Some("web-01".into()),
                metric: ChartMetric::Cpu,
                range: ChartRange::Day,
            },
        }
    }

    #[test]
    fn the_default_layout_passes_the_checks() {
        let layout = DashboardLayout::default();
        layout.validate().unwrap();
        assert_eq!(
            layout.describe(),
            "capacity 4x2, this PC's memory 2x2, alerts 2x2, overview 4x5"
        );
    }

    #[test]
    fn widgets_read_and_write_as_flat_objects() {
        let widget = chart("cpu-1", Some(HistorySource::Host), Some(r"C:\VMs\web\web.vmx"));
        let json = serde_json::to_value(&widget).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "id": "cpu-1", "w": 2, "h": 2, "kind": "chart", "source": "host",
                "key": r"C:\VMs\web\web.vmx", "name": "web-01", "metric": "cpu", "range": "24h"
            })
        );
        assert_eq!(serde_json::from_value::<Widget>(json).unwrap(), widget);
        let services: Widget = serde_json::from_str(r#"{"id":"s","w":1,"h":3,"kind":"services"}"#).unwrap();
        assert_eq!(services.kind, WidgetKind::Services { session_id: None });
        assert!(
            serde_json::from_str::<Widget>(r#"{"id":"x","w":1,"h":1,"kind":"weather"}"#).is_err(),
            "a widget this version doesn't know"
        );
    }

    #[test]
    fn a_layout_that_cant_be_drawn_is_refused_with_a_reason() {
        let refused = |widgets: Vec<Widget>| {
            DashboardLayout {
                version: LAYOUT_VERSION,
                widgets,
            }
            .validate()
            .unwrap_err()
            .to_string()
        };
        let mut wide = chart("a", None, None);
        wide.w = 5;
        assert!(refused(vec![wide]).contains("columns wide"));
        let mut flat = chart("a", None, None);
        flat.h = 0;
        assert!(refused(vec![flat]).contains("rows tall"));
        assert!(refused(vec![chart("a", None, None), chart("a", None, None)]).contains("share the id"));
        assert!(refused(vec![chart("a b", None, None)]).contains("id"));
        let alerts = |id: &str| Widget {
            id: id.into(),
            w: 2,
            h: 2,
            kind: WidgetKind::Alerts,
        };
        assert!(refused(vec![alerts("a"), alerts("b")]).contains("once"));
        assert!(refused(vec![chart("a", Some(HistorySource::Host), None)]).contains("Choose"));
        assert!(refused(vec![chart("a", Some(HistorySource::ThisPc), Some("web"))]).contains("Choose"));
        assert!(refused(vec![chart("a", Some(HistorySource::Guest), Some("a\nb"))]).contains("control"));
        let many: Vec<Widget> = (0..=MAX_WIDGETS).map(|i| chart(&format!("c{i}"), None, None)).collect();
        assert!(refused(many).contains("at most"));
        let newer = DashboardLayout {
            version: 2,
            widgets: vec![],
        };
        assert!(newer.validate().unwrap_err().to_string().contains("version"));
        // Fine: this PC, a host's guest, a chart not set up yet, and an empty dashboard.
        DashboardLayout {
            version: LAYOUT_VERSION,
            widgets: vec![
                chart("a", Some(HistorySource::ThisPc), Some(THIS_PC_KEY)),
                chart(
                    "b",
                    Some(HistorySource::Guest),
                    Some("5e0c3b5e-0000-4000-8000-000000000001"),
                ),
                chart("c", None, None),
            ],
        }
        .validate()
        .unwrap();
        DashboardLayout {
            version: LAYOUT_VERSION,
            widgets: vec![],
        }
        .validate()
        .unwrap();
    }
}
