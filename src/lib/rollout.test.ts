import assert from "node:assert/strict";
import test from "node:test";

import { canaryPrompt, parseStopAfter, retryChoices, rolloutText, timeLeft } from "./rollout.ts";

test("stop after takes a whole number of failures, or nothing", () => {
  assert.deepEqual(parseStopAfter(""), { ok: true, value: null });
  assert.deepEqual(parseStopAfter("  "), { ok: true, value: null });
  assert.deepEqual(parseStopAfter("3"), { ok: true, value: 3 });
  assert.deepEqual(parseStopAfter("1000"), { ok: true, value: 1000 });
  for (const bad of ["0", "1001", "2.5", "-1", "two", "1e2"]) {
    assert.equal(parseStopAfter(bad).ok, false, bad);
  }
});

test("the approval dialog says how the run spreads", () => {
  assert.equal(rolloutText(null, 5), null);
  assert.equal(rolloutText({ canary: false, stopAfterFailures: null }, 5), null);
  assert.match(rolloutText({ canary: true, stopAfterFailures: null }, 5) ?? "", /one host first.*other 4/);
  assert.equal(rolloutText({ canary: true, stopAfterFailures: null }, 1), null, "one host has no canary");
  assert.match(rolloutText({ canary: false, stopAfterFailures: 1 }, 5) ?? "", /after the first failure/);
  assert.match(rolloutText({ canary: true, stopAfterFailures: 3 }, 5) ?? "", /other 4.*once 3 have failed/);
});

test("the canary's prompt and time left read naturally", () => {
  assert.equal(canaryPrompt("web01", 1), "web01 finished without errors. Run on the other host?");
  assert.equal(canaryPrompt("web01", 9), "web01 finished without errors. Run on the other 9 hosts?");
  const now = Date.parse("2026-10-25T12:00:00Z");
  assert.equal(timeLeft("2026-10-25T12:14:05Z", now), "14:05");
  assert.equal(timeLeft("2026-10-25T11:59:00Z", now), "0:00");
});

test("a retry leaves hosts whose outcome is unknown out unless picked on purpose", () => {
  assert.deepEqual(retryChoices({ failed: 2, unknown: 0 }), { failed: 2, withUnknown: null });
  assert.deepEqual(retryChoices({ failed: 2, unknown: 3 }), { failed: 2, withUnknown: 5 });
  assert.deepEqual(retryChoices({ failed: 0, unknown: 1 }), { failed: 0, withUnknown: 1 });
});
