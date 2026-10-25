/// <reference types="node" />
// QL-25 notification centre: what each source keeps, the job tracker, grouping by day and key, and the times.
// Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { TerminalAlert } from "./api.ts";
import type { Alert } from "./dashboard-api.ts";
import {
  dayLabel,
  entryLink,
  fromAlertEvent,
  fromCommandFinished,
  fromSkipped,
  fromTerminalAlert,
  fromUpdate,
  groupNotifications,
  JobNotes,
  timeAgo,
  unreadBadge,
  type AppNotification,
} from "./notifications.ts";

const alert: Alert = {
  id: "a1",
  ruleId: "host-disk",
  ruleName: "Disk above 85%",
  metric: "disk",
  severity: "warning",
  target: { kind: "session", key: "s-1", name: "web01" },
  threshold: 85,
  forSecs: 300,
  value: 91,
  peak: 93,
  message: "Disk at 91% for 5 minutes",
  firedAt: "2026-10-25T10:00:00Z",
  resolvedAt: null,
  resolution: null,
  acknowledgedAt: null,
};

function entry(id: number, at: string, extra: Partial<AppNotification> = {}): AppNotification {
  return {
    id,
    source: "job",
    level: "info",
    title: `Entry ${id}`,
    body: null,
    link: null,
    group: null,
    at,
    read: false,
    ...extra,
  };
}

test("a metric alert keeps its rule and target, critical as an error, and links to the alert list", () => {
  const fired = fromAlertEvent({ kind: "fired", alert, notify: false });
  assert.equal(fired?.level, "warning");
  assert.equal(fired?.title, "Warning: Disk above 85% on web01");
  assert.equal(fired?.body, alert.message);
  assert.deepEqual(fired?.link, { kind: "alerts" });
  assert.equal(fired?.group, "alert:host-disk:session:s-1");
  const critical = fromAlertEvent({ kind: "fired", alert: { ...alert, severity: "critical" }, notify: true });
  assert.equal(critical?.level, "error");
  const resolved = fromAlertEvent({ kind: "resolved", alert });
  assert.equal(resolved?.level, "success");
  assert.equal(resolved?.group, fired?.group, "a rule's alerts on one target show together");
  assert.equal(fromAlertEvent({ kind: "acknowledged", ids: ["a1"] }), null);
});

test("a terminal alert keeps the rule, terminal and sample, and links to its terminal", () => {
  const raw: TerminalAlert = {
    ruleId: "error",
    ruleName: "Error",
    terminalId: "t-1",
    sessionId: "s-1",
    count: 3,
    suppressed: 0,
    firstAt: "2026-10-25T10:00:00Z",
    lastAt: "2026-10-25T10:00:01Z",
    sample: "ERROR: disk full",
  };
  const kept = fromTerminalAlert(raw, "web01");
  assert.equal(kept.title, "Error in web01");
  assert.match(kept.body ?? "", /3 lines matched: ERROR: disk full/);
  assert.deepEqual(kept.link, { kind: "terminal", terminalId: "t-1" });
  assert.equal(kept.group, "terminal-alert:t-1:error");
});

test("finished commands, updates and skipped targets", () => {
  const done = fromCommandFinished("Command finished in web01", "It ran 2 minutes", "t-1");
  assert.deepEqual(done.link, { kind: "terminal", terminalId: "t-1" });
  assert.equal(fromCommandFinished("x", "y", null).link, null);
  const update = fromUpdate({ currentVersion: "0.5.0", version: "0.5.1", notes: null, pubDate: null });
  assert.equal(update.once, "update:0.5.1", "one entry per version");
  assert.deepEqual(update.link, { kind: "update" });
  assert.equal(fromSkipped(["db01"]).title, "Skipped 1 protected target");
  assert.equal(fromSkipped(["db01", "db02"]).body, "db01, db02");
});

test("jobs: the end of each job with its summary, nothing for MultiExec lines", () => {
  const notes = new JobNotes();
  assert.equal(
    notes.note({ event: "queued", jobId: "j1", summary: "Start web01", tier: "low", targets: 1, quiet: false }),
    null,
  );
  assert.equal(notes.note({ event: "started", jobId: "j1" }), null);
  const done = notes.note({ event: "finished", jobId: "j1", status: "succeeded", scope: "vms" });
  assert.equal(done?.title, "Job succeeded: Start web01");
  assert.equal(done?.level, "success");
  assert.deepEqual(done?.link, { kind: "job", jobId: "j1" });

  notes.note({ event: "queued", jobId: "j2", summary: "Run uptime", tier: "medium", targets: 3, quiet: false });
  const failed = notes.note({ event: "finished", jobId: "j2", status: "partially_failed", scope: "other" });
  assert.equal(failed?.level, "error");
  assert.equal(failed?.title, "Job partly failed: Run uptime");

  notes.note({ event: "queued", jobId: "j3", summary: "ls", tier: "low", targets: 2, quiet: true });
  assert.equal(notes.note({ event: "finished", jobId: "j3", status: "succeeded", scope: "other" }), null);

  const still = notes.note({
    event: "stillRunning",
    jobId: "j4",
    targets: [{ target: { kind: "vm", vmxPath: "x" }, name: "db01", environment: "none", protected: false }],
  });
  assert.equal(still?.level, "warning");
  assert.match(still?.title ?? "", /db01/);
  const canary = notes.note({
    event: "canaryWaiting",
    jobId: "j2",
    target: "s-1",
    name: "web01",
    rest: 4,
    until: "2026-10-25T10:15:00Z",
  });
  assert.match(canary?.body ?? "", /other 4 hosts wait/);
  // A job whose queued event was missed (a reload) still gets an entry.
  assert.equal(
    notes.note({ event: "finished", jobId: "j9", status: "failed", scope: "other" })?.title,
    "Job failed: a job",
  );
});

test("the list goes by day, newest first, with entries in a row that share a key as one line", () => {
  const now = Date.parse("2026-10-25T15:00:00");
  const today = (h: number) => new Date(`2026-10-25T${String(h).padStart(2, "0")}:00:00`).toISOString();
  const entries = [
    entry(1, new Date("2026-10-24T09:00:00").toISOString()),
    entry(2, today(10), { group: "alert:x" }),
    entry(3, today(11), { group: "alert:x", read: true }),
    entry(4, today(12), { group: "alert:x" }),
    entry(5, today(13)),
    entry(6, today(14), { group: "alert:x" }),
  ];
  const days = groupNotifications(entries, now);
  assert.deepEqual(
    days.map((d) => d.label),
    ["Today", "Yesterday"],
  );
  const groups = days[0].groups;
  assert.deepEqual(
    groups.map((g) => g.entries.map((e) => e.id)),
    [[6], [5], [4, 3, 2]],
    "only entries next to each other share a line",
  );
  assert.equal(groups[2].unread, 2);
  assert.equal(groups[2].latest.id, 4);
  const unread = groupNotifications(entries, now, true);
  assert.deepEqual(
    unread[0].groups.map((g) => g.entries.map((e) => e.id)),
    [[6], [5], [4, 2]],
  );
});

test("times in words, and the bell's count", () => {
  const now = Date.parse("2026-10-25T15:00:00Z");
  assert.equal(timeAgo(now - 10_000, now), "just now");
  assert.equal(timeAgo(now - 5 * 60_000, now), "5 min ago");
  assert.equal(timeAgo(now - 2 * 3_600_000, now), "2 h ago");
  assert.equal(timeAgo(now + 5_000, now), "just now", "a clock a little ahead is not in the future");
  assert.equal(dayLabel(now, now), "Today");
  assert.equal(unreadBadge(0), null);
  assert.equal(unreadBadge(7), "7");
  assert.equal(unreadBadge(150), "99+");
});

test("a link the core gave back opens only when this version knows it", () => {
  assert.deepEqual(entryLink(entry(1, "2026-10-25T10:00:00Z", { link: { kind: "job", jobId: "j1" } })), {
    kind: "job",
    jobId: "j1",
  });
  assert.equal(entryLink(entry(1, "2026-10-25T10:00:00Z", { link: { kind: "schedule", id: "x" } })), null);
  assert.equal(entryLink(entry(1, "2026-10-25T10:00:00Z", { link: null })), null);
});
