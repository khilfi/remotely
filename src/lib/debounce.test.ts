/// <reference types="node" />
// AP-03, BX-03: Activity and Compare reload once per burst of job events. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { debounceAt, RELOAD_MAX_WAIT_MS, RELOAD_WAIT_MS } from "./debounce.ts";

test("one event reloads after the pause", () => {
  assert.equal(debounceAt(1_000, 1_000, RELOAD_WAIT_MS, RELOAD_MAX_WAIT_MS), 1_300);
});

test("each event in a burst moves the reload on, up to the longest wait after the first", () => {
  assert.equal(debounceAt(1_000, 1_200, 300, 1_000), 1_500);
  assert.equal(debounceAt(1_000, 1_650, 300, 1_000), 1_950);
  assert.equal(debounceAt(1_000, 1_800, 300, 1_000), 2_000, "capped: a steady stream still reloads");
  assert.equal(debounceAt(1_000, 5_000, 300, 1_000), 2_000);
});

test("100 events 5 ms apart reload once, 300 ms after the last", () => {
  const first = 0;
  let due = 0;
  for (let i = 0; i < 100; i++) due = debounceAt(first, i * 5, RELOAD_WAIT_MS, RELOAD_MAX_WAIT_MS);
  assert.equal(due, 495 + RELOAD_WAIT_MS);
});

test("a longest wait shorter than the pause is the pause", () => {
  assert.equal(debounceAt(0, 0, 300, 100), 300);
});
