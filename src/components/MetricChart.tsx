// MO-03 drill-down chart: a uPlot line chart (CLAUDE.md stack) with one y-axis and up to four series of the same
// unit. 2 px lines, a 10% wash under a single series, hairline grid. MO-15: a series can be dashed, for what there
// is (a VM's configured RAM, a host's total, the paging files' size) next to what is in use, in the same colour as
// the solid line it bounds, or muted when it bounds several. The legend under the plot is the app's own: it shows
// the latest reading of each series, and the hovered one while the pointer is over the plot (uPlot's own legend
// showed dashes until hovered). Canvas colours come from the CSS tokens, so the chart is rebuilt when the theme
// changes. MO-06, MO-16: a chart can take its height from its widget and show controls (a range picker) beside its
// title; over a range longer than a day its legend names the day too.

import { useEffect, useRef, useState, type ReactNode } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { latestValue } from "@/lib/host-details";
import type { ResolvedTheme } from "@/lib/theme";

export interface ChartSeries {
  label: string;
  /** One value per time; null leaves a gap, undefined (no reading at that time) is joined over. */
  values: (number | null | undefined)[];
  /** Categorical slot: the series' colour follows its identity, never its rank. "muted" for a shared limit. */
  slot: 1 | 2 | "muted";
  /** MO-15: a limit (what there is), drawn dashed. */
  dashed?: boolean;
}

interface Props {
  title: string;
  /** What the series measure, e.g. "Host side and guest". */
  subtitle?: string;
  /** Unix time in milliseconds. */
  times: number[];
  series: ChartSeries[];
  /** Axis ticks and readout values. */
  format: (value: number) => string;
  /** A fixed top, e.g. 100 for percentages. */
  max?: number;
  theme: ResolvedTheme;
  /** What shows instead of the plot while no series has a value. */
  empty?: string;
  /** The plot's height in pixels; 140 by default. */
  height?: number;
  /** Controls beside the title, e.g. a range picker. */
  actions?: ReactNode;
}

const HEIGHT = 140;
const DAY_MS = 24 * 60 * 60 * 1000;
const DASH = [6, 4];

function token(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function colourToken(slot: ChartSeries["slot"]) {
  return slot === "muted" ? "--chart-axis" : `--series-${slot}`;
}

/** The legend's line sample: solid or dashed, in the series' colour. */
function Swatch({ slot, dashed }: { slot: ChartSeries["slot"]; dashed?: boolean }) {
  return (
    <svg width="18" height="8" aria-hidden className="shrink-0">
      <line
        x1="1"
        y1="4"
        x2="17"
        y2="4"
        stroke={`var(${colourToken(slot)})`}
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray={dashed ? "4 3" : undefined}
      />
    </svg>
  );
}

export function MetricChart({ title, subtitle, times, series, format, max, theme, empty, height, actions }: Props) {
  const plotHeight = Math.max(60, Math.round(height ?? HEIGHT));
  const host = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const [width, setWidth] = useState(0);
  /** The hovered point's index, or null when the pointer is elsewhere. */
  const [hovered, setHovered] = useState<number | null>(null);
  const labels = series.map((s) => `${s.slot}:${s.label}:${s.dashed ? 1 : 0}`).join("|");
  const hasData = series.some((s) => s.values.some((v) => v != null));

  // Keep the plot as wide as its card.
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const data: uPlot.AlignedData = [times.map((t) => t / 1000), ...series.map((s) => s.values)];

  // Build once per series set, theme and width.
  useEffect(() => {
    const el = host.current;
    if (!el || width === 0 || !hasData) return;
    const grid = token("--chart-grid");
    const axis = token("--chart-axis");
    const font = "11px system-ui, 'Segoe UI', sans-serif";
    const solid = series.filter((s) => !s.dashed);
    const options: uPlot.Options = {
      width,
      height: plotHeight,
      cursor: { drag: { x: false, y: false }, points: { size: 8 } },
      legend: { show: false },
      scales: {
        x: { time: true },
        y: { range: (_u, _min, top) => [0, max ?? (top > 0 ? top * 1.15 : 1)] },
      },
      axes: [
        { stroke: axis, font, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid, width: 1 } },
        {
          stroke: axis,
          font,
          size: 64,
          grid: { stroke: grid, width: 1 },
          ticks: { show: false },
          values: (_u, ticks) => ticks.map(format),
        },
      ],
      series: [
        {},
        ...series.map((s) => {
          const color = token(colourToken(s.slot));
          return {
            label: s.label,
            stroke: color,
            width: s.dashed ? 1.5 : 2,
            dash: s.dashed ? DASH : undefined,
            // A wash only under a lone solid line.
            fill: !s.dashed && solid.length === 1 ? `${color}1a` : undefined,
            points: { show: false },
            spanGaps: false,
          };
        }),
      ],
      hooks: {
        setCursor: [(u) => setHovered(u.cursor.idx ?? null)],
      },
    };
    const created = new uPlot(options, data, el);
    plot.current = created;
    const leave = () => setHovered(null);
    el.addEventListener("mouseleave", leave);
    return () => {
      el.removeEventListener("mouseleave", leave);
      created.destroy();
      plot.current = null;
    };
    // Rebuilt only when what is drawn changes shape; new points go through setData below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [labels, theme, width, max, hasData, plotHeight]);

  // New points only: hovering re-renders the chart (the legend follows the pointer) without new data.
  const latest = times.length > 0 ? times[times.length - 1] : 0;
  const filled = series.map((s) => s.values.filter((v) => v != null).length).join(",");
  useEffect(() => {
    plot.current?.setData(data);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [times.length, latest, filled]);

  const at = hovered !== null && hovered < times.length ? hovered : null;
  const longSpan = times.length > 1 && times[times.length - 1] - times[0] > DAY_MS * 0.8;
  const when =
    at === null
      ? "Latest"
      : longSpan
        ? new Date(times[at] ?? 0).toLocaleString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })
        : new Date(times[at] ?? 0).toLocaleTimeString();

  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="mb-2 flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-medium">{title}</div>
          {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
        </div>
        {actions}
      </div>
      <div className="relative" style={{ minHeight: plotHeight }}>
        {/* uPlot owns this element's children; React renders nothing inside it. */}
        <div ref={host} className="metric-chart" />
        {!hasData && (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
            {empty ?? "No readings yet. They arrive every 5 seconds."}
          </div>
        )}
      </div>
      {hasData && (
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs" aria-live="off">
          <span className={`${longSpan ? "w-28" : "w-16"} shrink-0 text-muted-foreground tabular-nums`}>{when}</span>
          {series.map((s) => {
            const value = at !== null ? (s.values[at] ?? null) : latestValue(s.values);
            return (
              <span key={s.label} className="flex items-center gap-1.5">
                <Swatch slot={s.slot} dashed={s.dashed} />
                <span className="text-muted-foreground">{s.label}</span>
                <span className="font-medium tabular-nums">{value === null ? "—" : format(value)}</span>
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
}
