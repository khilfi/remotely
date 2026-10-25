/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import { strengthView } from "./passwords.ts";

test("SS-04: the meter fills a quarter per point and shows a sliver at 0", () => {
  assert.deepEqual(
    [0, 1, 2, 3, 4].map((s) => strengthView(s, s >= 3).percent),
    [5, 25, 50, 75, 100],
  );
  assert.equal(strengthView(-1, false).percent, 5);
  assert.equal(strengthView(9, true).percent, 100);
  assert.equal(strengthView(Number.NaN, false).label, "Very weak");
});

test("SS-04: the colour follows what the core would take, not the score alone", () => {
  assert.equal(strengthView(0, false).level, "critical");
  assert.equal(strengthView(1, false).level, "critical");
  assert.equal(strengthView(2, false).level, "warning");
  assert.equal(strengthView(3, true).level, "ok");
  assert.equal(strengthView(4, true).label, "Strong");
  // Too short or too long: refused whatever the score says.
  assert.equal(strengthView(4, false).level, "warning");
});
