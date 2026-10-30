/// <reference types="node" />
// MO-06: a chart's range, buckets and the merge of stored minutes with live rounds. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { MetricPoint } from "./api.ts";
import type { HistoryPoint, HistorySeries } from "./dashboard-api.ts";
import {
  bucketPoints,
  CHART_RANGES,
  fromLive,
  HISTORY_RETENTION_CHOICES,
  historyRefreshMs,
  historySizeText,
  isChartRange,
  isHistoryRange,
  mergeHistory,
  pruneSummary,
  RANGE_BUCKET_MS,
  RANGE_SPAN_MS,
  retentionDays,
  rangeStart,
  withGaps,
} from "./history.ts";

const MINUTE = 60_000;
/** A whole hour. */
const T0 = 1_792_000_800_000;

function live(t: number, cpu: number | null, extra: Partial<MetricPoint> = {}): MetricPoint {
  return {
    t,
    cpuPct: cpu,
    memBytes: 100,
    memTotalBytes: 400,
    swapUsedBytes: null,
    swapTotalBytes: null,
    diskReadBps: null,
    diskWriteBps: null,
    netRxBps: null,
    netTxBps: null,
    load1: null,
    diskUsedPct: null,
    ...extra,
  };
}

function stored(t: number, samples: number, cpu: number): HistoryPoint {
  return { ...live(t, cpu), samples, cpuMin: cpu - 1, cpuMax: cpu + 1, memMaxBytes: 100, loadMax: null };
}

test("the range picker offers live and four ranges, each a few hundred points at most", () => {
  assert.deepEqual(
    CHART_RANGES.map((r) => r.value),
    ["live", "1h", "6h", "24h", "7d"],
  );
  for (const range of ["1h", "6h", "24h", "7d"] as const) {
    assert.ok(RANGE_SPAN_MS[range] / RANGE_BUCKET_MS[range] <= 360, range);
    assert.ok(historyRefreshMs(range) < 30 * MINUTE, "re-read well within the 30 live minutes");
    assert.ok(isHistoryRange(range));
  }
  assert.equal(isHistoryRange("live"), false);
  assert.equal(isChartRange("24h"), true);
  assert.equal(isChartRange("2d"), false);
  assert.equal(isChartRange(null), false);
});

test("buckets average by rounds and keep the lowest, highest and fullest", () => {
  const points = [
    fromLive(live(T0, 10, { diskUsedPct: 40, memTotalBytes: 400 })),
    fromLive(live(T0 + 5_000, 30, { diskUsedPct: 60, memTotalBytes: 500 })),
    fromLive(live(T0 + 10_000, null)),
    { ...stored(T0 + MINUTE, 10, 50), cpuMin: 45, cpuMax: 90 },
  ];
  const [first] = bucketPoints(points, 5 * MINUTE);
  assert.equal(first.t, T0);
  assert.equal(first.samples, 13);
  assert.equal(first.cpuPct, (10 + 30 + 50 * 10) / 12, "a missing reading adds no weight");
  assert.equal(first.cpuMin, 10);
  assert.equal(first.cpuMax, 90);
  assert.equal(first.diskUsedPct, 60);
  assert.equal(first.memTotalBytes, 400, "the latest of what there is, by time");
  assert.equal(first.memBytes, 100);
  assert.equal(first.netRxBps, null);

  const minutes = bucketPoints([fromLive(live(T0 + 61_000, 1)), fromLive(live(T0 + 1_000, 2))], MINUTE);
  assert.deepEqual(
    minutes.map((p) => [p.t, p.cpuPct]),
    [
      [T0, 2],
      [T0 + MINUTE, 1],
    ],
    "in time order, on whole minutes",
  );
});

test("a gap longer than a bucket and a half breaks the line", () => {
  const points = [T0, T0 + MINUTE, T0 + 5 * MINUTE].map((t) => fromLive(live(t, 1)));
  const out = withGaps(points, MINUTE);
  assert.deepEqual(
    out.map((p) => [p.t, p.cpuPct]),
    [
      [T0, 1],
      [T0 + MINUTE, 1],
      [T0 + 2 * MINUTE, null],
      [T0 + 5 * MINUTE, 1],
    ],
  );
  assert.equal(withGaps([], MINUTE).length, 0);
});

test("a range starts on a whole bucket, as the core reads it", () => {
  const now = T0 + 7 * MINUTE + 20_000;
  assert.equal(rangeStart("1h", now), T0 + 8 * MINUTE - 60 * MINUTE);
  assert.equal(rangeStart("24h", now) % (5 * MINUTE), 0);
  assert.equal(rangeStart("7d", now) % (30 * MINUTE), 0);
});

test("stored minutes carry on with the live rounds from where they end", () => {
  const now = T0 + 3 * MINUTE + 12_000;
  const history: HistorySeries = {
    range: "1h",
    bucketSecs: 60,
    from: T0 - 57 * MINUTE,
    to: now,
    storedUntil: T0 + 2 * MINUTE,
    points: [stored(T0, 12, 10), stored(T0 + MINUTE, 12, 20)],
  };
  // The live rounds overlap the stored minutes: only those from the end of the stored ones, up to now, count.
  const rounds = Array.from({ length: 30 }, (_, i) => live(T0 + MINUTE + i * 5_000, 40));
  const points = mergeHistory(history, rounds, "1h", now);
  assert.deepEqual(
    points.map((p) => [p.t, p.cpuPct, p.samples]),
    [
      [T0, 10, 12],
      [T0 + MINUTE, 20, 12],
      [T0 + 2 * MINUTE, 40, 12],
      [T0 + 3 * MINUTE, 40, 3],
    ],
  );
  // Nothing stored yet: the live rounds alone, bucketed.
  const fresh = mergeHistory({ ...history, points: [], storedUntil: null }, rounds, "1h", now);
  assert.equal(fresh[0].t, T0 + MINUTE);
  assert.equal(fresh[0].samples, 12);
  assert.deepEqual(mergeHistory(null, [], "7d", now), []);
});

test("a long range puts the live rounds in its own buckets and leaves out what is older than it", () => {
  const now = T0 + 10 * MINUTE;
  const history: HistorySeries = {
    range: "24h",
    bucketSecs: 300,
    from: rangeStart("24h", now),
    to: now,
    storedUntil: T0 + 7 * MINUTE,
    points: [stored(T0 + 5 * MINUTE, 24, 10)],
  };
  const rounds = [live(T0 + 7 * MINUTE, 70), live(T0 + 8 * MINUTE, 70), live(rangeStart("24h", now) - 1, 99)];
  const points = mergeHistory(history, rounds, "24h", now);
  assert.equal(points.length, 1, "the boundary bucket merges stored and live");
  assert.equal(points[0].t, T0 + 5 * MINUTE);
  assert.equal(points[0].samples, 26);
  assert.equal(points[0].cpuPct, (10 * 24 + 70 * 2) / 26);
});

test("Settings says how long the history is kept, what it holds and what a prune removed", () => {
  assert.deepEqual(
    HISTORY_RETENTION_CHOICES.map((c) => c.value),
    ["day1", "days3", "days7", "days14", "days30"],
  );
  assert.match(historySizeText({ series: 0, minutes: 0, oldest: null, bytes: null }), /^Nothing kept yet/);
  assert.match(
    historySizeText({ series: 3, minutes: 4320, oldest: "2026-10-18T08:00:00Z", bytes: 4_200_000 }),
    /^4\.2 MB for 3 series, since /,
  );
  assert.equal(
    historySizeText({ series: 1, minutes: 60, oldest: null, bytes: null }),
    "60 one-minute readings for 1 series.",
  );
  const report = {
    at: "2026-10-25T08:00:00Z",
    retention: "days7" as const,
    before: "2026-10-18T08:00:00Z",
    removed: { minutes: 1440, series: 1, alerts: 2 },
    compacted: false,
  };
  assert.equal(
    pruneSummary(report),
    "Removed 1440 one-minute readings and 2 resolved alerts. 1 series no longer reporting went with them.",
  );
  assert.equal(
    pruneSummary({ ...report, removed: { minutes: 0, series: 0, alerts: 0 } }),
    "Nothing was old enough to remove.",
  );
});

test("UX-10: each retention choice's days, so a shorter one is told apart (it prunes at once: no Undo)", () => {
  const days = HISTORY_RETENTION_CHOICES.map((c) => retentionDays(c.value));
  assert.deepEqual(days, [1, 3, 7, 14, 30]);
  assert.ok(retentionDays("days3") < retentionDays("days7"));
});
