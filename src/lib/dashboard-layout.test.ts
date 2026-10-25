/// <reference types="node" />
// MO-16: adding, removing, moving and resizing the dashboard's widgets. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { DashboardLayout } from "./dashboard-api.ts";
import {
  addWidget,
  cannotAdd,
  clampSize,
  dropIndex,
  heightPx,
  MAX_WIDGETS,
  metricFor,
  moveWidget,
  moveWidgetTo,
  newWidgetId,
  removeWidget,
  resizeWidget,
  sameLayout,
  sizeFromDrag,
  updateWidget,
  widgetTitle,
} from "./dashboard-layout.ts";

const layout: DashboardLayout = {
  version: 1,
  widgets: [
    { id: "capacity", w: 4, h: 2, kind: "capacity" },
    { id: "this-pc-memory", w: 2, h: 2, kind: "thisPcMemory" },
    { id: "alerts", w: 2, h: 2, kind: "alerts" },
    { id: "overview", w: 4, h: 5, kind: "overview" },
  ],
};

const ids = (l: DashboardLayout) => l.widgets.map((w) => w.id);

test("widgets are added at the end, once for the ones a dashboard shows once", () => {
  assert.equal(cannotAdd(layout, "alerts"), "It is on the dashboard already.");
  assert.equal(addWidget(layout, "alerts"), layout, "unchanged");
  const charts = addWidget(addWidget(layout, "chart"), "chart");
  assert.deepEqual(ids(charts).slice(-2), ["chart", "chart-2"]);
  const chart = charts.widgets[4];
  assert.deepEqual(chart, {
    id: "chart",
    w: 2,
    h: 2,
    kind: "chart",
    source: null,
    key: null,
    name: null,
    metric: "cpu",
    range: "live",
  });
  assert.equal(newWidgetId(charts, "thisPcMemory"), "this-pc-memory-2");
  const services = addWidget(layout, "services").widgets[4];
  assert.deepEqual(services, { id: "services", w: 1, h: 3, kind: "services", sessionId: null });
  const full: DashboardLayout = {
    version: 1,
    widgets: Array.from({ length: MAX_WIDGETS }, (_, i) => ({
      id: `c${i}`,
      w: 1,
      h: 1,
      kind: "chart" as const,
      metric: "cpu" as const,
      range: "live" as const,
    })),
  };
  assert.match(cannotAdd(full, "chart") ?? "", /at most/);
  assert.deepEqual(ids(removeWidget(layout, "alerts")), ["capacity", "this-pc-memory", "overview"]);
});

test("moving up and down, as the keyboard does, stops at the ends", () => {
  assert.deepEqual(ids(moveWidget(layout, "alerts", -1)), ["capacity", "alerts", "this-pc-memory", "overview"]);
  assert.deepEqual(ids(moveWidget(layout, "overview", 1)), ids(layout), "already last");
  assert.deepEqual(ids(moveWidget(layout, "capacity", -1)), ids(layout), "already first");
  assert.deepEqual(ids(moveWidget(layout, "nope", 1)), ids(layout));
  assert.deepEqual(ids(moveWidgetTo(layout, "capacity", 99)), ["this-pc-memory", "alerts", "overview", "capacity"]);
});

test("a drop lands before or after the widget under the pointer", () => {
  const before = moveWidgetTo(layout, "overview", dropIndex(layout, "overview", "this-pc-memory", true));
  assert.deepEqual(ids(before), ["capacity", "overview", "this-pc-memory", "alerts"]);
  const after = moveWidgetTo(layout, "capacity", dropIndex(layout, "capacity", "alerts", false));
  assert.deepEqual(ids(after), ["this-pc-memory", "alerts", "capacity", "overview"]);
  assert.equal(dropIndex(layout, "alerts", "alerts", true), 2, "onto itself: where it is");
});

test("sizes stay on the grid, and a resize drag snaps to whole columns and rows", () => {
  assert.deepEqual(clampSize(9, 0), { w: 4, h: 1 });
  assert.deepEqual(clampSize(2.4, 7.6), { w: 2, h: 6 });
  assert.deepEqual(clampSize(Number.NaN, 2), { w: 1, h: 2 });
  const resized = resizeWidget(layout, "alerts", 1, 4);
  assert.deepEqual(resized.widgets[2], { id: "alerts", w: 1, h: 4, kind: "alerts" });
  // Columns 200 px wide with 16 px gaps: a little over half a column more rounds up.
  assert.deepEqual(sizeFromDrag({ w: 1, h: 2 }, 120, 0, 200), { w: 2, h: 2 });
  assert.deepEqual(sizeFromDrag({ w: 1, h: 2 }, 100, 0, 200), { w: 1, h: 2 });
  assert.deepEqual(sizeFromDrag({ w: 2, h: 2 }, -1000, 140, 200), { w: 1, h: 3 });
  assert.equal(heightPx(1), 120);
  assert.equal(heightPx(3), 3 * 120 + 2 * 16);
});

test("a widget's settings change, never its id or kind", () => {
  const withChart = addWidget(layout, "chart");
  const changed = updateWidget(withChart, "chart", {
    source: "guest",
    key: "s1",
    name: "db01",
    metric: "load",
    range: "24h",
  });
  const chart = changed.widgets[4];
  assert.equal(chart.kind, "chart");
  assert.equal(widgetTitle(chart), "Load of db01");
  assert.equal(widgetTitle(chart, "db01 (renamed)"), "Load of db01 (renamed)");
  assert.equal(widgetTitle(layout.widgets[0]), "Host capacity");
  assert.equal(metricFor("host", "load"), "cpu", "a VM's process has no load average");
  assert.equal(metricFor("guest", "load"), "load");
  assert.equal(sameLayout(layout, structuredClone(layout)), true);
  assert.equal(sameLayout(layout, changed), false);
});
