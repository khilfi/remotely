// MO-15: this PC's memory, on the dashboard under the capacity panel: RAM in use against all the RAM there is, and the
// paging files in use against their size, each limit dashed in its line's colour. Read from the metrics rounds (nothing
// extra is polled for it), every round while the dashboard shows and the window is visible (`live`, P8): hidden, it
// reads nothing. MO-06: the dashboard's one range (UX-07: the page's, not the chart's own) shows the last hour to the
// last week from the history on disk, carried on with the live rounds.

import { useEffect, useMemo, useState } from "react";
import { MetricChart } from "@/components/MetricChart";
import { chartPoints, useHistory } from "@/hooks/use-chart-points";
import { api, type ThisPcSeries } from "@/lib/api";
import type { ChartRange } from "@/lib/dashboard-api";
import { isHistoryRange } from "@/lib/history";
import { formatBytes } from "@/lib/metrics";
import type { ResolvedTheme } from "@/lib/theme";

const SERIES = { source: "thisPc", key: "this-pc" } as const;

export function ThisPcMemoryChart({
  round,
  range,
  live,
  theme,
  height,
}: {
  round: number;
  /** The dashboard's range. */
  range: ChartRange;
  live: boolean;
  theme: ResolvedTheme;
  /** The plot's height in pixels (the widget's size). */
  height?: number;
}) {
  const [series, setSeries] = useState<ThisPcSeries | null>(null);
  const history = useHistory(SERIES, range, live);

  useEffect(() => {
    if (!live) return;
    let stale = false;
    api.metricsThisPc().then(
      (s) => !stale && setSeries(s),
      () => undefined,
    );
    return () => {
      stale = true;
    };
  }, [round, live]);

  const points = useMemo(
    () => chartPoints(range, series?.points ?? [], history),
    // `round` moves a history range on with the clock.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [range, series, history, round],
  );
  const pick = (f: (p: (typeof points)[number]) => number | null) => points.map(f);
  const paging = series?.latest?.paging ?? null;
  // One line: what Windows has promised to programs, out of RAM plus the paging files (named on hover).
  const subtitle = paging
    ? `Committed ${formatBytes(paging.commitUsedBytes)} of ${formatBytes(paging.commitLimitBytes)}`
    : "RAM in use and all there is";
  const pagingFiles = paging?.files.map((f) => f.path).join(", ") || null;

  return (
    <MetricChart
      title="This PC's memory"
      subtitle={subtitle}
      subtitleTitle={
        pagingFiles
          ? `Committed: memory Windows has promised to programs, out of RAM plus the paging files (${pagingFiles})`
          : undefined
      }
      times={points.map((p) => p.t)}
      theme={theme}
      height={height}
      format={(v) => formatBytes(v)}
      empty={
        isHistoryRange(range)
          ? history
            ? "No history for this range yet: it is kept from the first minute Remotely runs."
            : "Reading the history…"
          : "This PC's memory shows from the next round (every 5 seconds)."
      }
      series={[
        { label: "RAM in use", slot: 1, values: pick((p) => p.memBytes) },
        { label: "RAM", slot: 1, dashed: true, values: pick((p) => p.memTotalBytes) },
        ...(paging && paging.totalBytes > 0
          ? [
              { label: "Paging file in use", slot: 2 as const, values: pick((p) => p.swapUsedBytes) },
              { label: "Paging file size", slot: 2 as const, dashed: true, values: pick((p) => p.swapTotalBytes) },
            ]
          : []),
      ]}
    />
  );
}
