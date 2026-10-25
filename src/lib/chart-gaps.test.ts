/// <reference types="node" />
// MO-02, MO-03: a guest polled less often than the host side keeps its line on a VM row's charts. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { guestGapMs, joinShortGaps } from "./chart-gaps.ts";

/** Host-side rounds every 5 s. */
const times = Array.from({ length: 10 }, (_, i) => 1_000_000 + i * 5000);

test("a guest read every 15 s is joined over the host-only rounds between its readings", () => {
  const guest = [10, null, null, 12, null, null, 11, null, null, 13];
  assert.deepEqual(joinShortGaps(times, guest, guestGapMs(15)), [
    10,
    undefined,
    undefined,
    12,
    undefined,
    undefined,
    11,
    undefined,
    undefined,
    13,
  ]);
});

test("a longer gap still shows, and so do nulls before the first and after the last reading", () => {
  // Read every 15 s, then a reading missed (30 s without one).
  const guest = [null, 10, null, null, null, null, null, 12, null, null];
  assert.deepEqual(joinShortGaps(times, guest, guestGapMs(15)), [
    null,
    10,
    null,
    null,
    null,
    null,
    null,
    12,
    null,
    null,
  ]);
  // Every 5 s: one missed reading is a gap of 10 s, more than 7.5 s.
  assert.deepEqual(joinShortGaps(times.slice(0, 3), [1, null, 2], guestGapMs(5)), [1, null, 2]);
});

test("readings side by side and values of 0 are left as they are", () => {
  assert.deepEqual(joinShortGaps(times.slice(0, 3), [0, 0, 0], guestGapMs(60)), [0, 0, 0]);
  assert.deepEqual(joinShortGaps([], [], guestGapMs(5)), []);
  assert.equal(guestGapMs(60), 90_000);
  assert.equal(guestGapMs(0), 7500, "never shorter than the 5 s round");
});
