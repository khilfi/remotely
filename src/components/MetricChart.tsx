// MO-03 drill-down chart: a uPlot line chart (CLAUDE.md stack) with one y-axis and one or two series
// of the same unit. 2 px lines, a 10% wash under a single series, hairline grid. uPlot's live legend
// under the plot names each series and doubles as the hover readout (crosshair plus values). Canvas
// colours come from the CSS tokens, so the chart is rebuilt when the theme changes.

import { useEffect, useRef, useState } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { ResolvedTheme } from "@/lib/theme";

export interface ChartSeries {
  label: string;
  /** One value per time; null leaves a gap. */
  values: (number | null)[];
  /** Categorical slot: the series' colour follows its identity, never its rank. */
  slot: 1 | 2;
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
}

const HEIGHT = 140;

function token(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function MetricChart({ title, subtitle, times, series, format, max, theme }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const [width, setWidth] = useState(0);
  const labels = series.map((s) => `${s.slot}:${s.label}`).join("|");
  const hasData = series.some((s) => s.values.some((v) => v !== null));

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
    const single = series.length === 1;
    const options: uPlot.Options = {
      width,
      height: HEIGHT,
      cursor: { drag: { x: false, y: false }, points: { size: 8 } },
      legend: { live: true },
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
        { value: (_u, v) => (v == null ? "—" : new Date(v * 1000).toLocaleTimeString()) },
        ...series.map((s) => {
          const color = token(`--series-${s.slot}`);
          return {
            label: s.label,
            stroke: color,
            width: 2,
            fill: single ? `${color}1a` : undefined,
            points: { show: false },
            spanGaps: false,
            value: (_u: uPlot, v: number | null) => (v == null ? "—" : format(v)),
          };
        }),
      ],
    };
    const created = new uPlot(options, data, el);
    plot.current = created;
    return () => {
      created.destroy();
      plot.current = null;
    };
    // Rebuilt only when what is drawn changes shape; new points go through setData below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [labels, theme, width, max, hasData]);

  useEffect(() => {
    plot.current?.setData(data);
  });

  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="mb-2">
        <div className="text-sm font-medium">{title}</div>
        {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
      </div>
      <div className="relative min-h-[140px]">
        {/* uPlot owns this element's children; React renders nothing inside it. */}
        <div ref={host} className="metric-chart" />
        {!hasData && (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
            No readings yet. They arrive every 5 seconds.
          </div>
        )}
      </div>
    </div>
  );
}
