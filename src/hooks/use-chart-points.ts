// MO-06: chart points for a range. Live: the collector's last 30 minutes, read again each round. A history range: the
// stored minutes, read when the range or series changes and again every few minutes (historyRefreshMs), carried on each
// round with the live rounds (mergeHistory). Reads only while `live` (the dashboard shows and the window is visible,
// P8); hidden, nothing is read.

import { useEffect, useMemo, useState } from "react";
import { usePoll } from "@/hooks/use-poll";
import { api, type MetricPoint } from "@/lib/api";
import { dashboardApi, type ChartRange, type HistorySeries, type HistorySource } from "@/lib/dashboard-api";
import { fromLive, historyRefreshMs, isHistoryRange, mergeHistory, type ChartPoint } from "@/lib/history";

export interface SeriesRef {
  source: HistorySource;
  key: string;
}

/**
 * The stored history of `series` for `range` (null for live, or until it is read). Read while `live`, again when the
 * series or range changes and every few minutes.
 */
export function useHistory(series: SeriesRef | null, range: ChartRange, live: boolean): HistorySeries | null {
  const key = series && isHistoryRange(range) ? `${series.source}|${series.key}|${range}` : "";
  const [history, setHistory] = useState<{ key: string; series: HistorySeries } | null>(null);
  usePoll(
    async (stillLive) => {
      if (!series || !isHistoryRange(range)) return;
      const read = await dashboardApi.history(series.source, series.key, range);
      if (stillLive()) setHistory({ key, series: read });
    },
    {
      enabled: live && key !== "",
      resetKey: key,
      intervalMs: isHistoryRange(range) ? historyRefreshMs(range) : 60_000,
    },
  );
  return history && history.key === key ? history.series : null;
}

/** A series' points for `range` at `now`: the live rounds alone, or the stored minutes carried on with them. */
export function chartPoints(
  range: ChartRange,
  live: MetricPoint[],
  history: HistorySeries | null,
  now = Date.now(),
): ChartPoint[] {
  return isHistoryRange(range) ? mergeHistory(history, live, range, now) : live.map(fromLive);
}

/** The live points of a series: a VM's host side, a watched guest, or this PC. */
function readLive(series: SeriesRef): Promise<MetricPoint[]> {
  return series.source === "thisPc"
    ? api.metricsThisPc().then((s) => s.points)
    : api.metricsSeries(series.source, series.key);
}

/** One series' points for `range`, read as the dashboard's rounds come (`round`) while `live`. */
export function useChartPoints(
  series: SeriesRef | null,
  range: ChartRange,
  round: number,
  live: boolean,
): { points: ChartPoint[]; loaded: boolean } {
  const id = series ? `${series.source}|${series.key}` : null;
  const [liveState, setLive] = useState<{ id: string; points: MetricPoint[] } | null>(null);
  const history = useHistory(series, range, live);

  useEffect(() => {
    if (!series || !id || !live) return;
    let stale = false;
    readLive(series).then(
      (points) => !stale && setLive({ id, points }),
      () => !stale && setLive({ id, points: [] }),
    );
    return () => {
      stale = true;
    };
    // `series` is the same as long as `id` is.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, round, live]);

  const livePoints = liveState && liveState.id === id ? liveState.points : null;
  const points = useMemo(
    () => chartPoints(range, livePoints ?? [], history),
    // `round` moves the merge on with the clock even when nothing new was read.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [range, livePoints, history, round],
  );
  const loaded = isHistoryRange(range) ? history !== null : livePoints !== null;
  return { points, loaded };
}
