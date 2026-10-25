// MO-16: one metric of a VM (its host side), a watched host (its guest) or this PC, as a dashboard widget. Its range
// starts as the layout says and can be changed for the moment from the chart (Customize saves another default). Live
// reads the collector's last 30 minutes each round; a longer range reads the history on disk (MO-06) and carries on
// with the live rounds. Reads only while the dashboard shows and the window is visible.

import { useState } from "react";
import { LineChartIcon } from "lucide-react";
import { MetricChart, type ChartSeries } from "@/components/MetricChart";
import { RangePicker } from "@/components/RangePicker";
import { useChartPoints } from "@/hooks/use-chart-points";
import type { ChartMetric, ChartRange, HistorySource, Widget } from "@/lib/dashboard-api";
import { CHART_METRIC_LABEL } from "@/lib/dashboard-layout";
import { isHistoryRange, type ChartPoint } from "@/lib/history";
import { formatBytes, formatRate } from "@/lib/metrics";
import type { ResolvedTheme } from "@/lib/theme";

type ChartWidget = Extract<Widget, { kind: "chart" }>;

function seriesFor(
  metric: ChartMetric,
  source: HistorySource,
  points: ChartPoint[],
  long: boolean,
): { series: ChartSeries[]; format: (v: number) => string; max?: number; subtitle: string } {
  const pick = (f: (p: ChartPoint) => number | null) => points.map(f);
  const pct = (v: number) => `${Math.round(v)}%`;
  switch (metric) {
    case "cpu":
      return {
        series: [
          { label: "CPU", slot: 1, values: pick((p) => p.cpuPct) },
          // MO-06: over a range, the highest reading of each bucket shows the spikes the averages smooth out.
          ...(long ? [{ label: "Highest", slot: "muted" as const, dashed: true, values: pick((p) => p.cpuMax) }] : []),
        ],
        format: pct,
        max: 100,
        subtitle:
          source === "host"
            ? "The VM's process, as a share of its own vCPUs"
            : source === "guest"
              ? "Busy share of the guest's CPUs"
              : "This PC's CPU, busy share of every logical processor",
      };
    case "memory":
      return {
        series: [
          { label: source === "host" ? "Working set" : "In use", slot: 1, values: pick((p) => p.memBytes) },
          {
            label: source === "host" ? "Configured RAM" : "Total",
            slot: 1,
            dashed: true,
            values: pick((p) => p.memTotalBytes),
          },
        ],
        format: (v) => formatBytes(v),
        subtitle:
          source === "host"
            ? "The VM process's working set under its configured RAM"
            : "Memory in use under all there is",
      };
    case "swap":
      return {
        series: [
          { label: "In use", slot: 2, values: pick((p) => p.swapUsedBytes) },
          { label: "Size", slot: 2, dashed: true, values: pick((p) => p.swapTotalBytes) },
        ],
        format: (v) => formatBytes(v),
        subtitle: source === "thisPc" ? "The paging files in use under their size" : "Swap in use under its size",
      };
    case "diskIo":
      return {
        series: [
          { label: "Read", slot: 1, values: pick((p) => p.diskReadBps) },
          { label: "Write", slot: 2, values: pick((p) => p.diskWriteBps) },
        ],
        format: (v) => formatRate(v),
        subtitle: source === "host" ? "Read and written by the VM's process" : "Read and written by the guest's disks",
      };
    case "network":
      return {
        series: [
          { label: "Received", slot: 1, values: pick((p) => p.netRxBps) },
          { label: "Sent", slot: 2, values: pick((p) => p.netTxBps) },
        ],
        format: (v) => formatRate(v),
        subtitle: "All interfaces but loopback and container links",
      };
    case "load":
      return {
        series: [{ label: "Load", slot: 1, values: pick((p) => p.load1) }],
        format: (v) => v.toFixed(2),
        subtitle: "1-minute load average",
      };
    case "diskUsed":
      return {
        series: [{ label: "Fullest disk", slot: 1, values: pick((p) => p.diskUsedPct) }],
        format: pct,
        max: 100,
        subtitle: "Space used on the fullest mounted disk",
      };
  }
}

export function MetricChartWidget({
  widget,
  name,
  round,
  live,
  theme,
  height,
}: {
  widget: ChartWidget;
  /** The VM's or host's name now, when the dashboard knows it. */
  name: string | null;
  round: number;
  live: boolean;
  theme: ResolvedTheme;
  /** The plot's height in pixels. */
  height: number;
}) {
  const [range, setRange] = useState<ChartRange>(widget.range);
  // The saved default changed (Customize): follow it.
  const [savedRange, setSavedRange] = useState(widget.range);
  if (widget.range !== savedRange) {
    setSavedRange(widget.range);
    setRange(widget.range);
  }
  const source = widget.source ?? null;
  const key = widget.key ?? null;
  const target = source && key ? { source, key } : null;
  const { points, loaded } = useChartPoints(target, range, round, live);
  const title = `${CHART_METRIC_LABEL[widget.metric]} of ${name ?? widget.name ?? "…"}`;

  if (!target || !source) {
    return (
      <section className="flex h-full flex-col items-center justify-center gap-2 rounded-lg border bg-card p-3 text-center text-xs text-muted-foreground">
        <LineChartIcon className="size-5" />
        Choose a VM, a watched host or this PC in Customize.
      </section>
    );
  }
  const long = isHistoryRange(range);
  const { series, format, max, subtitle } = seriesFor(widget.metric, source, points, long);
  return (
    <MetricChart
      title={title}
      subtitle={subtitle}
      times={points.map((p) => p.t)}
      series={series}
      format={format}
      max={max}
      theme={theme}
      height={height}
      actions={<RangePicker value={range} onChange={setRange} label={`${title}: range`} />}
      empty={
        long
          ? loaded
            ? "No history for this range yet."
            : "Reading the history…"
          : source === "host"
            ? "No readings: the VM isn't running, or the next round is on its way."
            : "No readings yet. They arrive with the dashboard's rounds."
      }
    />
  );
}
