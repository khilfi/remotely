/// <reference types="node" />
// 0.7.0 F6: the export dialogs' helpers. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ansibleReason,
  ansibleSavedText,
  busyText,
  dayRange,
  daysFromActivity,
  dayStart,
  fileName,
  handoverCountText,
  handoverReason,
  inventorySavedText,
  isoDay,
  MAX_RANGE_DAYS,
  readText,
  utcOffsetMinutes,
} from "./reports.ts";

test("days are local midnights and a range ends after its last day", () => {
  const start = dayStart("2026-11-01");
  assert.equal(start, new Date(2026, 10, 1).getTime());
  assert.equal(dayStart("2026-02-30"), null, "not a real day");
  assert.equal(dayStart("1 Nov"), null);
  const range = dayRange("2026-11-01", "2026-11-07");
  assert.ok("fromMs" in range);
  if ("fromMs" in range) {
    assert.equal(range.fromMs, new Date(2026, 10, 1).getTime());
    assert.equal(range.toMs, new Date(2026, 10, 8).getTime());
  }
  assert.deepEqual(dayRange("2026-11-07", "2026-11-01"), { problem: "The last day can't be before the first." });
  assert.deepEqual(dayRange("", "2026-11-01"), { problem: "Enter the first day as a date." });
  assert.ok("problem" in dayRange("2025-01-01", "2026-11-01"), `over ${MAX_RANGE_DAYS} days`);
  assert.ok("fromMs" in dayRange("2026-01-01", "2026-12-31"), "a whole year");
});

test("the Activity filter becomes days, any time the last 30", () => {
  const now = new Date(2026, 10, 15, 13, 0);
  assert.deepEqual(daysFromActivity("today", now), { from: "2026-11-15", to: "2026-11-15" });
  assert.deepEqual(daysFromActivity("7d", now), { from: "2026-11-08", to: "2026-11-15" });
  assert.deepEqual(daysFromActivity("all", now), { from: "2026-10-16", to: "2026-11-15" });
  assert.equal(isoDay(new Date(2026, 0, 5)), "2026-01-05");
  assert.equal(typeof utcOffsetMinutes(now), "number");
  assert.ok(!Object.is(utcOffsetMinutes(now), -0));
});

test("buttons say why they are off", () => {
  const range = { fromMs: 0, toMs: 1 };
  assert.equal(handoverReason({ range, preparedBy: "Alice", busy: false }), null);
  assert.equal(
    handoverReason({ range, preparedBy: "x".repeat(121), busy: false }),
    '"Prepared by" can be at most 120 characters.',
  );
  assert.equal(handoverReason({ range: { problem: "No." }, preparedBy: "", busy: false }), "No.");
  assert.equal(handoverReason({ range, preparedBy: "", busy: true }), "Making the pack…");
  assert.equal(ansibleReason({ hosts: 3, busy: false }), null);
  assert.match(ansibleReason({ hosts: 0, busy: false }) ?? "", /No SSH session/);
  assert.equal(ansibleReason({ hosts: null, busy: false }), "Reading the sessions…");
  // A preview that failed says why, never "Reading…" for ever.
  assert.equal(ansibleReason({ hosts: null, busy: false, problem: "The store is busy." }), "The store is busy.");
  assert.equal(ansibleReason({ hosts: 3, busy: false, problem: null }), null);
  assert.equal(handoverReason({ range, preparedBy: "", busy: false, problem: "No counts." }), "No counts.");
});

test("a busy export says how many hosts are read", () => {
  const saving = "Saving…";
  assert.equal(busyText({ reading: false, progress: null, saving }), saving);
  assert.equal(busyText({ reading: true, progress: null, saving }), "Reading hosts…");
  assert.equal(busyText({ reading: true, progress: { done: 3, total: 12 }, saving }), "Reading hosts: 3 of 12…");
  assert.equal(busyText({ reading: true, progress: { done: 12, total: 12 }, saving }), saving, "then it writes");
  assert.equal(busyText({ reading: true, progress: { done: 0, total: 0 }, saving }), "Reading hosts…");
});

test("what the toasts say", () => {
  assert.equal(
    fileName("C:\\Users\\x\\Documents\\remotely-inventory-Acme-2026-11-01.xlsx"),
    "remotely-inventory-Acme-2026-11-01.xlsx",
  );
  assert.equal(fileName("/tmp/a.zip"), "a.zip");
  assert.equal(
    inventorySavedText({
      savedId: "s",
      path: "C:\\docs\\inv.xlsx",
      vms: 1,
      hosts: 3,
      networks: 2,
      checks: 0,
      packages: 12,
      read: null,
      notes: [],
    }),
    "Saved inv.xlsx: 1 VM, 3 hosts, 0 health checks, 12 packages.",
  );
  assert.equal(
    ansibleSavedText({ savedId: "s", path: "/x/hosts.yml", hosts: 2, groups: 1, notes: [] }),
    "Saved hosts.yml: 2 hosts in 1 group.",
  );
  assert.equal(
    readText({ asked: 3, read: 2, problems: ["x"] }),
    "2 of 3 SSH hosts read again; 1 kept what was read before.",
  );
  assert.equal(readText({ asked: 1, read: 1, problems: [] }), "1 of 1 SSH host read again.");
  assert.equal(readText(null), null);
  assert.equal(handoverCountText(1, 0, 2), "1 job, 0 other changes and 2 marked notes");
});
