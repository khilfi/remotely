// MO-15: this PC's memory over the last 30 minutes, on the dashboard under the capacity panel: RAM in use against
// all the RAM there is, and the paging files in use against their size, each limit dashed in its line's colour. Read
// from the metrics rounds (nothing extra is polled for it), every round while the dashboard shows.

import { useEffect, useState } from "react";
import { MetricChart } from "@/components/MetricChart";
import { api, type ThisPcSeries } from "@/lib/api";
import { formatBytes } from "@/lib/metrics";
import type { ResolvedTheme } from "@/lib/theme";

export function ThisPcMemoryChart({ round, theme }: { round: number; theme: ResolvedTheme }) {
  const [series, setSeries] = useState<ThisPcSeries | null>(null);

  useEffect(() => {
    let stale = false;
    api.metricsThisPc().then(
      (s) => !stale && setSeries(s),
      () => undefined,
    );
    return () => {
      stale = true;
    };
  }, [round]);

  const points = series?.points ?? [];
  const pick = (f: (p: (typeof points)[number]) => number | null) => points.map(f);
  const paging = series?.latest?.paging ?? null;
  const subtitle = paging
    ? `RAM, and the paging files (${paging.files.map((f) => f.path).join(", ") || "none"}). Committed now: ${formatBytes(
        paging.commitUsedBytes,
      )} of ${formatBytes(paging.commitLimitBytes)} (RAM plus paging files).`
    : "RAM in use and all there is. The paging files show once Windows reports them.";

  return (
    <MetricChart
      title="This PC's memory"
      subtitle={subtitle}
      times={points.map((p) => p.t)}
      theme={theme}
      format={(v) => formatBytes(v)}
      empty="This PC's memory shows from the next round (every 5 seconds)."
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
