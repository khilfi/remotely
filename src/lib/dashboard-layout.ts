// MO-16: the dashboard's layout as pure functions (tested in dashboard-layout.test.ts): which widgets there are, adding,
// removing, moving (by drag or from the keyboard, up and down) and resizing them on the grid, and turning a resize drag
// into whole columns and rows. The core checks a layout again when it is saved (dashboard.rs) and keeps it per
// workspace.

import type { ChartMetric, ChartRange, DashboardLayout, HistorySource, Widget, WidgetKind } from "./dashboard-api.ts";

export const GRID_COLUMNS = 4;
export const MAX_ROWS = 6;
export const MAX_WIDGETS = 24;
/** One grid row, and the gap between cells, in pixels (the page's `auto-rows` and `gap`). */
export const ROW_PX = 120;
export const GAP_PX = 16;

export type WidgetKindName = WidgetKind["kind"];

export interface WidgetChoice {
  kind: WidgetKindName;
  label: string;
  description: string;
  /** At most one on a dashboard. */
  single: boolean;
  w: number;
  h: number;
}

export const WIDGET_CHOICES: WidgetChoice[] = [
  {
    kind: "overview",
    label: "Overview grid",
    description: "Running VMs and watched hosts, with filters and details",
    single: true,
    w: 4,
    h: 5,
  },
  {
    kind: "capacity",
    label: "Host capacity",
    description: "RAM and CPUs assigned to running VMs, and the VM folders' drives",
    single: true,
    w: 4,
    h: 2,
  },
  {
    kind: "thisPcMemory",
    label: "This PC's memory",
    description: "RAM and paging files, live or over a range",
    single: true,
    w: 2,
    h: 2,
  },
  {
    kind: "alerts",
    label: "Alerts",
    description: "Firing alerts, the history and the rules",
    single: true,
    w: 2,
    h: 2,
  },
  {
    kind: "checks",
    label: "Health checks",
    description: "How many checks are up, failing and down, and the ones that need a look",
    single: true,
    w: 2,
    h: 2,
  },
  {
    kind: "services",
    label: "Services of a host",
    description: "A watched host's running and failed services, read every minute",
    single: false,
    w: 1,
    h: 3,
  },
  {
    kind: "chart",
    label: "Metric chart",
    description: "One metric of a VM, a watched host or this PC",
    single: false,
    w: 2,
    h: 2,
  },
];

export function widgetChoice(kind: WidgetKindName): WidgetChoice {
  return WIDGET_CHOICES.find((c) => c.kind === kind) ?? WIDGET_CHOICES[0];
}

/** Why a widget can't be added now, or null. */
export function cannotAdd(layout: DashboardLayout, kind: WidgetKindName): string | null {
  if (layout.widgets.length >= MAX_WIDGETS) return `A dashboard holds at most ${MAX_WIDGETS} widgets.`;
  if (widgetChoice(kind).single && layout.widgets.some((w) => w.kind === kind)) {
    return "It is on the dashboard already.";
  }
  return null;
}

/** An id no widget of the layout has: `chart-3`. */
export function newWidgetId(layout: DashboardLayout, kind: WidgetKindName): string {
  const base = kind
    .replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)
    .replace(/[^a-z0-9-]/g, "")
    .slice(0, 30);
  const taken = new Set(layout.widgets.map((w) => w.id));
  if (!taken.has(base)) return base;
  for (let n = 2; ; n++) {
    const id = `${base}-${n}`;
    if (!taken.has(id)) return id;
  }
}

/** A new widget of `kind` at its usual size: a chart starts on CPU, live, with nothing chosen. */
export function newWidget(layout: DashboardLayout, kind: WidgetKindName): Widget {
  const { w, h } = widgetChoice(kind);
  const id = newWidgetId(layout, kind);
  switch (kind) {
    case "services":
      return { id, w, h, kind, sessionId: null };
    case "chart":
      return { id, w, h, kind, source: null, key: null, name: null, metric: "cpu", range: "live" };
    default:
      return { id, w, h, kind } as Widget;
  }
}

/** The layout with a new widget of `kind` at the end; unchanged when it can't be added. */
export function addWidget(layout: DashboardLayout, kind: WidgetKindName): DashboardLayout {
  if (cannotAdd(layout, kind)) return layout;
  return { ...layout, widgets: [...layout.widgets, newWidget(layout, kind)] };
}

export function removeWidget(layout: DashboardLayout, id: string): DashboardLayout {
  return { ...layout, widgets: layout.widgets.filter((w) => w.id !== id) };
}

/** The widget moved to `index` (clamped), the others keeping their order. */
export function moveWidgetTo(layout: DashboardLayout, id: string, index: number): DashboardLayout {
  const from = layout.widgets.findIndex((w) => w.id === id);
  if (from < 0) return layout;
  const widgets = [...layout.widgets];
  const [widget] = widgets.splice(from, 1);
  const to = Math.max(0, Math.min(widgets.length, index));
  widgets.splice(to, 0, widget);
  return { ...layout, widgets };
}

/** One place earlier (-1) or later (+1): "Move up" and "Move down", and the arrow keys on the handle. */
export function moveWidget(layout: DashboardLayout, id: string, delta: -1 | 1): DashboardLayout {
  const from = layout.widgets.findIndex((w) => w.id === id);
  if (from < 0) return layout;
  return moveWidgetTo(layout, id, from + delta);
}

/**
 * Where a dragged widget lands when dropped on `target`: before it when the pointer is on its first half, else after.
 * `before` comes from the pointer's place on the target.
 */
export function dropIndex(layout: DashboardLayout, dragged: string, target: string, before: boolean): number {
  const without = layout.widgets.filter((w) => w.id !== dragged);
  const at = without.findIndex((w) => w.id === target);
  if (at < 0) return layout.widgets.findIndex((w) => w.id === dragged);
  return before ? at : at + 1;
}

export function clampSize(w: number, h: number): { w: number; h: number } {
  const whole = (n: number, max: number) => Math.max(1, Math.min(max, Math.round(Number.isFinite(n) ? n : 1)));
  return { w: whole(w, GRID_COLUMNS), h: whole(h, MAX_ROWS) };
}

export function resizeWidget(layout: DashboardLayout, id: string, w: number, h: number): DashboardLayout {
  const size = clampSize(w, h);
  return {
    ...layout,
    widgets: layout.widgets.map((widget) => (widget.id === id ? { ...widget, ...size } : widget)),
  };
}

/**
 * UX-07: widgets that take the height of what they show, up to their size, so the dashboard has no empty band under a
 * short one (the capacity cards, an alert list with nothing firing). Charts keep their size: their plot fills it.
 * While customizing, every widget shows at its full size, so the sizes picked are the ones seen.
 */
export function fitsContent(kind: WidgetKindName): boolean {
  return kind === "overview" || kind === "capacity" || kind === "alerts" || kind === "services";
}

/**
 * Widgets whose content opens with its own title (a chart, the alert list), so Customize's bar doesn't show the title a
 * second time; the capacity cards and the overview grid have none, so the bar names them.
 */
export function showsOwnTitle(kind: WidgetKindName): boolean {
  return kind === "thisPcMemory" || kind === "alerts" || kind === "services" || kind === "chart";
}

/** A widget's height in pixels for `h` rows. */
export function heightPx(h: number): number {
  return h * ROW_PX + (h - 1) * GAP_PX;
}

/**
 * A resize drag in whole columns and rows: from the size it started at, the pointer moved `dx`, `dy` pixels, on a grid
 * whose columns are `columnPx` wide.
 */
export function sizeFromDrag(
  start: { w: number; h: number },
  dx: number,
  dy: number,
  columnPx: number,
): { w: number; h: number } {
  const colStep = Math.max(1, columnPx + GAP_PX);
  const rowStep = ROW_PX + GAP_PX;
  return clampSize(start.w + dx / colStep, start.h + dy / rowStep);
}

/** Replaces a widget's settings (a chart's VM, metric and range, a services widget's host). */
export function updateWidget(layout: DashboardLayout, id: string, change: Partial<Widget>): DashboardLayout {
  return {
    ...layout,
    widgets: layout.widgets.map((w) => (w.id === id ? ({ ...w, ...change, id: w.id, kind: w.kind } as Widget) : w)),
  };
}

export function sameLayout(a: DashboardLayout | null, b: DashboardLayout | null): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** What a chart can draw for each source: a VM's process has no swap, network, load or disk space. */
export const CHART_METRICS: Record<HistorySource, ChartMetric[]> = {
  host: ["cpu", "memory", "diskIo"],
  guest: ["cpu", "memory", "swap", "diskIo", "network", "load", "diskUsed"],
  thisPc: ["cpu", "memory", "swap"],
};

export const CHART_METRIC_LABEL: Record<ChartMetric, string> = {
  cpu: "CPU",
  memory: "Memory",
  swap: "Swap",
  diskIo: "Disk I/O",
  network: "Network",
  load: "Load",
  diskUsed: "Disk used",
};

/** A chart's metric for a new source: the same when it can draw it, else CPU. */
export function metricFor(source: HistorySource, metric: ChartMetric): ChartMetric {
  return CHART_METRICS[source].includes(metric) ? metric : "cpu";
}

/** A widget's title: "CPU of web-01", "Services of db01". */
export function widgetTitle(widget: Widget, name?: string | null): string {
  switch (widget.kind) {
    case "chart":
      return `${CHART_METRIC_LABEL[widget.metric]} of ${name ?? widget.name ?? "…"}`;
    case "services":
      return name ? `Services of ${name}` : "Services";
    default:
      return widgetChoice(widget.kind).label;
  }
}

export type { ChartRange };
