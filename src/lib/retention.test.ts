/// <reference types="node" />
// BX-02: the retention choices and the purge's summary in Settings. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PurgeReport } from "./api.ts";
import { formatBytes, purgeSummary, RETENTION_CHOICES } from "./retention.ts";

const report = (over: Partial<PurgeReport> = {}): PurgeReport => ({
  at: "2026-10-25T08:00:00Z",
  retention: "days90",
  before: "2026-07-27T08:00:00Z",
  removed: { jobs: 12, outputs: 340, commands: 25, bytes: 2_100_000 },
  redacted: 0,
  compacted: false,
  byHand: true,
  ...over,
});

test("four choices, 90 days the default", () => {
  assert.deepEqual(
    RETENTION_CHOICES.map((c) => c.value),
    ["days30", "days90", "year", "forever"],
  );
  assert.match(RETENTION_CHOICES[1].label, /default/);
});

test("sizes read as the core writes them", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2_100_000), "2.1 MB");
  assert.equal(formatBytes(65_000_000), "65 MB");
});

test("the summary says what went", () => {
  assert.equal(purgeSummary(report()), "Removed 340 outputs and 25 scripts or lines (2.1 MB) from 12 older jobs.");
  assert.equal(
    purgeSummary(report({ removed: { jobs: 1, outputs: 1, commands: 1, bytes: 40 }, compacted: true })),
    "Removed 1 output and 1 script or line (40 B) from 1 older job. The database file was compacted.",
  );
  assert.equal(
    purgeSummary(report({ removed: { jobs: 3, outputs: 0, commands: 0, bytes: 0 } })),
    "Nothing was old enough to remove.",
  );
  assert.equal(
    purgeSummary(report({ retention: "forever", before: null })),
    "Job outputs are kept forever, so nothing was removed.",
  );
});
