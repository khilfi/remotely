/// <reference types="node" />
// QL-17: recent alerts kept in memory and the words of an alert's notification. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { TerminalAlert } from "./api.ts";
import {
  alertNotification,
  clearAlerts,
  MAX_RECENT_ALERTS,
  recentAlerts,
  recordAlert,
  subscribeAlerts,
} from "./terminal-alerts.ts";

const alert = (over: Partial<TerminalAlert> = {}): TerminalAlert => ({
  ruleId: "builtin:error",
  ruleName: "Error",
  terminalId: "t1",
  sessionId: "s1",
  count: 1,
  suppressed: 0,
  firstAt: "2026-10-25T10:00:00Z",
  lastAt: "2026-10-25T10:00:00Z",
  sample: "ERROR: disk full",
  ...over,
});

test("alerts are kept newest first, up to a cap, and subscribers hear of each", () => {
  clearAlerts();
  let heard = 0;
  const stop = subscribeAlerts(() => (heard += 1));
  recordAlert(alert({ sample: "first" }), "web01", 1);
  recordAlert(alert({ sample: "second" }), "web01", 2);
  assert.deepEqual(
    recentAlerts().map((r) => r.alert.sample),
    ["second", "first"],
  );
  assert.equal(recentAlerts()[0].terminal, "web01");
  assert.equal(heard, 2);
  const before = recentAlerts();
  assert.equal(recentAlerts(), before, "the same array until something changes");
  for (let i = 0; i < MAX_RECENT_ALERTS + 5; i++) recordAlert(alert(), "db01", 10 + i);
  assert.equal(recentAlerts().length, MAX_RECENT_ALERTS);
  stop();
  recordAlert(alert(), "db01");
  assert.equal(heard, MAX_RECENT_ALERTS + 7, "not after unsubscribing");
  clearAlerts();
  assert.equal(recentAlerts().length, 0);
});

test("a notification names the rule and terminal, counts the burst and shows the first line", () => {
  assert.deepEqual(alertNotification(alert(), "web01"), {
    title: "Error in web01",
    body: "A line matched: ERROR: disk full",
  });
  assert.deepEqual(
    alertNotification(alert({ count: 5, suppressed: 12, sample: "" }), "web01").body,
    "5 lines matched (and 12 lines since the last alert)",
  );
  assert.equal(
    alertNotification(alert({ count: 1, suppressed: 1 }), "db01").body,
    "A line matched (and 1 line since the last alert): ERROR: disk full",
  );
});
