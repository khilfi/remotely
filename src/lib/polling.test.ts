/// <reference types="node" />
// CT-01: when the Containers page's background reads run. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { afterRead, MAX_POLL_WAIT_MS, pollDelay, pollWait, shouldPoll, type LastRead } from "./polling.ts";

test("reads run only while the page is shown and the window is visible", () => {
  assert.equal(shouldPoll(true, "visible"), true);
  assert.equal(shouldPoll(false, "visible"), false, "another page is shown");
  assert.equal(shouldPoll(true, "hidden"), false, "the window is minimised");
  assert.equal(shouldPoll(false, "hidden"), false);
});

test("a failed read waits twice as long each time, up to a minute", () => {
  assert.equal(pollWait(10_000, 0), 10_000);
  assert.equal(pollWait(10_000, 1), 20_000);
  assert.equal(pollWait(10_000, 2), 40_000);
  assert.equal(pollWait(10_000, 3), MAX_POLL_WAIT_MS);
  assert.equal(pollWait(10_000, 1000), MAX_POLL_WAIT_MS);
  assert.equal(pollWait(2_000, 3, 30_000), 16_000);
  assert.equal(pollWait(2_000, 5, 30_000), 30_000);
  assert.equal(pollWait(120_000, 2), 120_000, "never below the interval");
});

test("failures are counted per key, and a good read starts again", () => {
  const first = afterRead(null, "web/docker", false, 1_000);
  assert.deepEqual(first, { key: "web/docker", finishedAt: 1_000, failures: 1 });
  const second = afterRead(first, "web/docker", false, 2_000);
  assert.equal(second.failures, 2);
  assert.equal(afterRead(second, "db/docker", false, 3_000).failures, 1, "another host starts from 0");
  assert.equal(afterRead(second, "web/docker", true, 3_000).failures, 0);
});

test("the next read is timed from when the last one finished", () => {
  const last: LastRead = { key: "web/docker", finishedAt: 100_000, failures: 0 };
  const timing = { intervalMs: 10_000 };
  assert.equal(pollDelay(last, "web/docker", 103_000, timing), 7_000);
  assert.equal(pollDelay(last, "web/docker", 110_000, timing), 0);
  assert.equal(pollDelay(last, "web/docker", 500_000, timing), 0, "back after a long time: at once");
  assert.equal(
    pollDelay({ ...last, failures: 2 }, "web/docker", 103_000, timing),
    37_000,
    "after two failures, 40 s from the last",
  );
});

test("a key not read yet is read at once, or after one interval when asked", () => {
  const last: LastRead = { key: "web/docker", finishedAt: 100_000, failures: 3 };
  assert.equal(pollDelay(null, "web/docker", 0, { intervalMs: 10_000 }), 0);
  assert.equal(pollDelay(last, "db/docker", 101_000, { intervalMs: 10_000 }), 0, "another host: at once");
  assert.equal(pollDelay(null, "logs", 0, { intervalMs: 2_000, immediate: false }), 2_000);
  assert.equal(
    pollDelay({ key: "logs", finishedAt: 100_000, failures: 0 }, "logs", 101_500, {
      intervalMs: 2_000,
      immediate: false,
    }),
    500,
  );
});
