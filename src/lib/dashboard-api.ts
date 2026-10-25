// Typed wrappers over the dashboard's 0.5.0 IPC commands in src-tauri/src/dashboard.rs: MO-06 history on disk,
// MO-07 alerts and MO-16 the layout and its services widget. Types mirror the serde shapes in crates/core
// (metrics/history.rs, alerts/, dashboard.rs, host_details/mod.rs). Like api.ts, every answer and event goes past the
// presentation masker (FD-03).

import { invoke, listen, type HostService, type MetricPoint, type ServiceManager } from "@/lib/api";

// ---- MO-06: history on disk ----

export type HistorySource = "host" | "guest" | "thisPc";
export type HistoryRange = "1h" | "6h" | "24h" | "7d";
/** A chart's range: the live rounds in memory (30 minutes), or the history on disk. */
export type ChartRange = "live" | HistoryRange;
export type HistoryRetention = "day1" | "days3" | "days7" | "days14" | "days30";

/** A bucket of stored minutes: the fields of a live point (averages), plus the lowest and highest. */
export interface HistoryPoint extends MetricPoint {
  /** The rounds behind it. */
  samples: number;
  cpuMin: number | null;
  cpuMax: number | null;
  memMaxBytes: number | null;
  loadMax: number | null;
}

export interface HistorySeries {
  range: HistoryRange;
  bucketSecs: number;
  /** Unix ms. */
  from: number;
  to: number;
  /** The end of the last stored minute (Unix ms): live rounds take over from there. */
  storedUntil: number | null;
  points: HistoryPoint[];
}

export interface HistorySize {
  series: number;
  minutes: number;
  oldest: string | null;
  bytes: number | null;
}

export interface HistoryPruneReport {
  at: string;
  retention: HistoryRetention;
  before: string;
  removed: { minutes: number; series: number; alerts: number };
  compacted: boolean;
}

export interface HistoryInfo {
  retention: HistoryRetention;
  size: HistorySize;
  lastPrune: HistoryPruneReport | null;
}

// ---- MO-07: alerts ----

export type AlertMetric = "cpu" | "memory" | "disk" | "swap" | "unreachable" | "stopped";
export type Severity = "warning" | "critical";

export type AlertScope =
  | { kind: "allVms" }
  | { kind: "vm"; key: string }
  | { kind: "tag"; tag: string }
  | { kind: "host"; sessionId: string }
  | { kind: "allHosts" }
  | { kind: "thisPc" };

export type AlertScopeKind = AlertScope["kind"];

export interface AlertRuleInput {
  name: string;
  metric: AlertMetric;
  scope: AlertScope;
  /** Percent; null for unreachable and stopped. */
  threshold: number | null;
  forSecs: number;
  severity: Severity;
  notify: boolean;
  enabled: boolean;
}

export interface AlertRule extends AlertRuleInput {
  id: string;
  /** A rule Remotely ships ("vm-stopped"...); null for the owner's own. */
  builtin: string | null;
  updatedAt: string;
}

export type AlertTargetKind = "vm" | "session" | "thisPc";

export interface AlertTarget {
  kind: AlertTargetKind;
  key: string;
  name: string;
}

export type Resolution = "cleared" | "gone" | "ruleChanged" | "restarted";

export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  metric: AlertMetric;
  severity: Severity;
  target: AlertTarget;
  threshold: number | null;
  forSecs: number;
  value: number | null;
  peak: number | null;
  message: string;
  firedAt: string;
  resolvedAt: string | null;
  resolution: Resolution | null;
  acknowledgedAt: string | null;
}

/** MO-07: what the core sends as alerts change (QL-25's notification centre can list these too). */
export type AlertEvent =
  | { kind: "fired"; alert: Alert; notify: boolean }
  | { kind: "resolved"; alert: Alert }
  | { kind: "acknowledged"; ids: string[] };

export interface AlertList {
  alerts: Alert[];
  open: number;
  unacknowledged: number;
}

// ---- MO-16: the layout ----

export type ChartMetric = "cpu" | "memory" | "swap" | "diskIo" | "network" | "load" | "diskUsed";

export type WidgetKind =
  | { kind: "overview" }
  | { kind: "capacity" }
  | { kind: "thisPcMemory" }
  | { kind: "alerts" }
  | { kind: "services"; sessionId?: string | null }
  | {
      kind: "chart";
      source?: HistorySource | null;
      key?: string | null;
      name?: string | null;
      metric: ChartMetric;
      range: ChartRange;
    };

export type Widget = { id: string; w: number; h: number } & WidgetKind;

export interface DashboardLayout {
  version: number;
  widgets: Widget[];
}

export interface LayoutInfo {
  layout: DashboardLayout;
  /** The owner arranged it; false: the default. */
  custom: boolean;
  columns: number;
  maxRows: number;
  maxWidgets: number;
}

export interface ServicesReport {
  sessionId: string;
  serviceManager: ServiceManager;
  running: HostService[];
  failed: HostService[];
  other: HostService[];
  collectedAt: string;
}

export type ServicesRead =
  | { state: "read"; report: ServicesReport }
  /** Nothing read and nobody logged in: not watched, or the dashboard's connection isn't up. */
  | { state: "notConnected"; watched: boolean };

export const dashboardApi = {
  /** MO-06: a range of one series from the history on disk, in buckets. */
  history: (source: HistorySource, key: string, range: HistoryRange) =>
    invoke<HistorySeries>("metrics_history", { source, key, range }),
  historyInfo: () => invoke<HistoryInfo>("history_info"),
  /** Audited; a shorter time prunes at once. */
  setHistoryRetention: (retention: HistoryRetention) => invoke<HistoryInfo>("history_retention_set", { retention }),

  alerts: (openOnly = false, limit?: number) =>
    invoke<AlertList>("alerts_list", { query: { openOnly, limit: limit ?? null } }),
  /** All open ones when `ids` is empty. Audited. */
  acknowledge: (ids: string[]) => invoke<string[]>("alerts_acknowledge", { ids }),
  alertRules: () => invoke<AlertRule[]>("alert_rules"),
  createAlertRule: (input: AlertRuleInput) => invoke<AlertRule>("alert_rule_create", { input }),
  updateAlertRule: (id: string, input: AlertRuleInput) => invoke<AlertRule>("alert_rule_update", { id, input }),
  deleteAlertRule: (id: string) => invoke<void>("alert_rule_delete", { id }),
  resetAlertRule: (id: string) => invoke<AlertRule>("alert_rule_reset", { id }),
  /** A Windows notification; the caller masks the text while presenting (maskedOutside). */
  notifyAlert: (title: string, body: string) => invoke<void>("alert_notify", { title, body }),
  onAlertEvent: (handler: (event: AlertEvent) => void) =>
    listen<AlertEvent>("alerts://event", (e) => handler(e.payload)),

  layout: () => invoke<LayoutInfo>("dashboard_layout"),
  /** Audited. */
  setLayout: (layout: DashboardLayout) => invoke<LayoutInfo>("dashboard_layout_set", { layout }),
  resetLayout: () => invoke<LayoutInfo>("dashboard_layout_reset"),
  /** MO-16: a watched host's services, on the dashboard's kept connection only. */
  services: (sessionId: string) => invoke<ServicesRead>("host_services", { sessionId }),
};
