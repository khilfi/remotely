// MO-06: a chart's range and its points, as pure functions (tested in history.test.ts). "Live" is the collector's
// last 30 minutes, every round. A longer range reads the history on disk in buckets (1 minute up to 6 hours, 5 minutes
// for a day, 30 minutes for a week), then carries on with the live rounds from where the stored minutes end, put in the
// same buckets, so a chart moves on every round without reading the store again. A bucket with no reading leaves a
// gap (a null point), so a line doesn't cross hours the VM was off.

import type { MetricPoint } from "./api.ts";
import type {
  ChartRange,
  HistoryPoint,
  HistoryPruneReport,
  HistoryRange,
  HistoryRetention,
  HistorySeries,
  HistorySize,
} from "./dashboard-api.ts";
import { formatBytes } from "./retention.ts";

const MINUTE = 60_000;

export const CHART_RANGES: { value: ChartRange; label: string; hint: string }[] = [
  { value: "live", label: "Live", hint: "The last 30 minutes, every round, from memory" },
  { value: "1h", label: "1 h", hint: "The last hour, a point a minute" },
  { value: "6h", label: "6 h", hint: "The last 6 hours, a point a minute" },
  { value: "24h", label: "24 h", hint: "The last day, a point every 5 minutes" },
  { value: "7d", label: "7 d", hint: "The last week, a point every 30 minutes" },
];

export const RANGE_SPAN_MS: Record<HistoryRange, number> = {
  "1h": 60 * MINUTE,
  "6h": 6 * 60 * MINUTE,
  "24h": 24 * 60 * MINUTE,
  "7d": 7 * 24 * 60 * MINUTE,
};

/** The core's bucket for each range (metrics/history.rs, HistoryRange::bucket_minutes). */
export const RANGE_BUCKET_MS: Record<HistoryRange, number> = {
  "1h": MINUTE,
  "6h": MINUTE,
  "24h": 5 * MINUTE,
  "7d": 30 * MINUTE,
};

export function isHistoryRange(range: ChartRange): range is HistoryRange {
  return range !== "live";
}

export function isChartRange(value: unknown): value is ChartRange {
  return typeof value === "string" && CHART_RANGES.some((r) => r.value === value);
}

/**
 * How often a chart reads its range from the store again. Between reads it carries on with the live rounds, which
 * the collector keeps for 30 minutes, so these stay well inside that.
 */
export function historyRefreshMs(range: HistoryRange): number {
  return range === "1h" || range === "6h" ? MINUTE : range === "24h" ? 5 * MINUTE : 10 * MINUTE;
}

/** A point of a chart: a live round (weight 1) or a bucket of stored minutes (weighted by its rounds). */
export interface ChartPoint extends MetricPoint {
  samples: number;
  cpuMin: number | null;
  cpuMax: number | null;
}

export function fromLive(p: MetricPoint): ChartPoint {
  return { ...p, samples: 1, cpuMin: p.cpuPct, cpuMax: p.cpuPct };
}

export function fromHistory(p: HistoryPoint): ChartPoint {
  return { ...p };
}

/** Every field that a bucket averages, weighted by its rounds. */
const AVERAGED = [
  "cpuPct",
  "memBytes",
  "swapUsedBytes",
  "diskReadBps",
  "diskWriteBps",
  "netRxBps",
  "netTxBps",
  "load1",
] as const;

/** The fields where a bucket keeps the latest reading: what there is. */
const LATEST = ["memTotalBytes", "swapTotalBytes"] as const;

function emptyPoint(t: number): ChartPoint {
  return {
    t,
    samples: 0,
    cpuPct: null,
    cpuMin: null,
    cpuMax: null,
    memBytes: null,
    memTotalBytes: null,
    swapUsedBytes: null,
    swapTotalBytes: null,
    diskReadBps: null,
    diskWriteBps: null,
    netRxBps: null,
    netTxBps: null,
    load1: null,
    diskUsedPct: null,
  };
}

function finite(v: number | null | undefined): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

/**
 * Points (oldest first) in buckets of `bucketMs` starting on whole multiples: averages weighted by each point's rounds,
 * the lowest and highest CPU over the bucket, the fullest disk's highest reading, and the latest of what there is.
 */
export function bucketPoints(points: ChartPoint[], bucketMs: number): ChartPoint[] {
  const size = Math.max(1, bucketMs);
  const buckets = new Map<
    number,
    { point: ChartPoint; weights: Record<string, number>; sums: Record<string, number> }
  >();
  for (const p of [...points].sort((a, b) => a.t - b.t)) {
    const start = Math.floor(p.t / size) * size;
    let b = buckets.get(start);
    if (!b) {
      b = { point: emptyPoint(start), weights: {}, sums: {} };
      buckets.set(start, b);
    }
    const w = Math.max(1, p.samples);
    b.point.samples += w;
    for (const field of AVERAGED) {
      const v = p[field];
      if (finite(v)) {
        b.weights[field] = (b.weights[field] ?? 0) + w;
        b.sums[field] = (b.sums[field] ?? 0) + v * w;
      }
    }
    for (const field of LATEST) {
      const v = p[field];
      if (finite(v)) b.point[field] = v;
    }
    const low = finite(p.cpuMin) ? p.cpuMin : p.cpuPct;
    const high = finite(p.cpuMax) ? p.cpuMax : p.cpuPct;
    if (finite(low)) b.point.cpuMin = finite(b.point.cpuMin) ? Math.min(b.point.cpuMin, low) : low;
    if (finite(high)) b.point.cpuMax = finite(b.point.cpuMax) ? Math.max(b.point.cpuMax, high) : high;
    if (finite(p.diskUsedPct)) {
      b.point.diskUsedPct = finite(b.point.diskUsedPct) ? Math.max(b.point.diskUsedPct, p.diskUsedPct) : p.diskUsedPct;
    }
  }
  return [...buckets.values()]
    .sort((a, b) => a.point.t - b.point.t)
    .map(({ point, weights, sums }) => {
      for (const field of AVERAGED) {
        const w = weights[field];
        point[field] = w ? (sums[field] ?? 0) / w : null;
      }
      return point;
    });
}

/** A point with no reading wherever two points are more than one and a half buckets apart, so the line breaks there. */
export function withGaps(points: ChartPoint[], bucketMs: number): ChartPoint[] {
  const out: ChartPoint[] = [];
  for (const p of points) {
    const last = out[out.length - 1];
    if (last && p.t - last.t > bucketMs * 1.5) out.push(emptyPoint(last.t + bucketMs));
    out.push(p);
  }
  return out;
}

/** Where a range starts at `now`: on a whole bucket, as the core reads it. */
export function rangeStart(range: HistoryRange, now: number): number {
  const size = RANGE_BUCKET_MS[range];
  const toMinute = Math.floor(now / MINUTE) + 1;
  return Math.floor((toMinute * MINUTE - RANGE_SPAN_MS[range]) / size) * size;
}

/**
 * A history chart's points at `now`: the stored buckets, then the live rounds from where the stored minutes end (all of
 * them when nothing is stored yet), in the range's buckets, with gaps. Live rounds older than the range are left out.
 */
export function mergeHistory(
  history: HistorySeries | null,
  live: MetricPoint[],
  range: HistoryRange,
  now: number,
): ChartPoint[] {
  const size = RANGE_BUCKET_MS[range];
  const start = rangeStart(range, now);
  const stored = (history?.points ?? []).map(fromHistory);
  const cutoff = history?.storedUntil ?? Number.NEGATIVE_INFINITY;
  const tail = live.filter((p) => p.t >= cutoff).map(fromLive);
  const inRange = [...stored, ...tail].filter((p) => p.t >= start && p.t <= now);
  return withGaps(bucketPoints(inRange, size), size);
}

/** The x-axis span a chart shows: the range, or nothing fixed for live. */
export function rangeLabel(range: ChartRange): string {
  return CHART_RANGES.find((r) => r.value === range)?.hint ?? "";
}

// ---- Settings: how long the history is kept ----

export const HISTORY_RETENTION_CHOICES: { value: HistoryRetention; label: string }[] = [
  { value: "day1", label: "1 day" },
  { value: "days3", label: "3 days" },
  { value: "days7", label: "7 days (default)" },
  { value: "days14", label: "14 days" },
  { value: "days30", label: "30 days" },
];

/** UX-10: how many days a choice keeps, to tell a shorter one (which prunes at once, so no Undo) from a longer. */
export function retentionDays(retention: HistoryRetention): number {
  const days: Record<HistoryRetention, number> = { day1: 1, days3: 3, days7: 7, days14: 14, days30: 30 };
  return days[retention];
}

/** What the history holds, in a line: "4.2 MB for 3 series, since 18 Oct". */
export function historySizeText(size: HistorySize): string {
  if (size.minutes === 0) return "Nothing kept yet: the first minute is written a minute after Remotely starts.";
  const what = size.bytes !== null ? formatBytes(size.bytes) : `${size.minutes} one-minute readings`;
  const series = `${size.series} series`;
  const since = size.oldest
    ? `, since ${new Date(size.oldest).toLocaleDateString([], { day: "numeric", month: "short" })}`
    : "";
  return `${what} for ${series}${since}.`;
}

/** One sentence for the last prune. */
export function pruneSummary(report: HistoryPruneReport): string {
  const { minutes, series, alerts } = report.removed;
  if (minutes === 0 && series === 0 && alerts === 0) return "Nothing was old enough to remove.";
  const parts = [`${minutes} one-minute ${minutes === 1 ? "reading" : "readings"}`];
  if (alerts > 0) parts.push(`${alerts} resolved ${alerts === 1 ? "alert" : "alerts"}`);
  const gone = series > 0 ? ` ${series} series no longer reporting went with them.` : "";
  return `Removed ${parts.join(" and ")}.${gone}${report.compacted ? " The database file was compacted." : ""}`;
}
