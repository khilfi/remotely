/// <reference types="node" />
// UX-17, UX-18 (0.9.0 H3): Compare hosts' one results list and how Activity opens a job. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { JobSummary, RecordedLine } from "./api.ts";
import {
  activityView,
  itemBadge,
  itemKey,
  itemRunning,
  itemStatus,
  itemTitle,
  resultItems,
  retryBlockedReason,
  shownKey,
  shownResult,
  TYPED_NO_RETRY,
} from "./results-list.ts";

function job(id: string, createdAt: string, more: Partial<JobSummary> = {}): JobSummary {
  return {
    id,
    summary: "Run `uptime` on 12 hosts",
    action: "execReadOnly",
    tier: "low",
    status: "succeeded",
    createdAt,
    startedAt: createdAt,
    finishedAt: createdAt,
    targetsTotal: 12,
    targetsSucceeded: 12,
    targetsFailed: 0,
    targetsUnknown: 0,
    countdownUntil: null,
    retryOf: null,
    bodiesRemoved: false,
    commandRedacted: false,
    changeId: null,
    commandType: "remoteExec",
    ...more,
  };
}

function line(id: string, recordedAt: string, more: Partial<RecordedLine> = {}): RecordedLine {
  return {
    id,
    line: "df -h /",
    tier: "low",
    jobId: null,
    recordedAt,
    waitingApproval: false,
    terminals: 6,
    finished: 6,
    headline: "All 6 the same",
    groups: 1,
    truncated: false,
    fullScreen: false,
    durationMs: 900,
    ...more,
  };
}

test("runs and typed lines are one list, newest first, whatever started them", () => {
  const runs = [
    job("r2", "2026-11-20T10:05:00Z"),
    job("push", "2026-11-20T10:03:00Z", { commandType: "bulkFiles", action: "filePush" }),
    job("r1", "2026-11-20T10:00:00Z"),
  ];
  const lines = [line("l2", "2026-11-20T10:04:00.250Z"), line("l1", "2026-11-20T10:01:00Z")];
  const items = resultItems(runs, lines);
  assert.deepEqual(
    items.map((i) => i.key),
    ["run:r2", "typed:l2", "run:push", "typed:l1", "run:r1"],
  );
  assert.equal(itemKey("typed", "l1"), "typed:l1");
  assert.deepEqual(resultItems([], []), []);
});

test("each is badged with what it was and how many it reached", () => {
  const [run, push, fetch, typed] = resultItems(
    [
      job("r", "2026-11-20T10:03:00Z"),
      job("p", "2026-11-20T10:02:00Z", { commandType: "bulkFiles", action: "filePush", targetsTotal: 5 }),
      job("f", "2026-11-20T10:01:00Z", { commandType: "bulkFiles", action: "fileFetch", targetsTotal: 1 }),
    ],
    [line("l", "2026-11-20T10:00:00Z")],
  );
  assert.equal(itemBadge(run), "Run on 12 hosts");
  assert.equal(itemBadge(push), "Pushed to 5 hosts");
  assert.equal(itemBadge(fetch), "Fetched from 1 host");
  assert.equal(itemBadge(typed), "Typed in 6 tabs");
  assert.equal(itemTitle(typed), "df -h /");
  assert.equal(
    itemTitle(resultItems([job("x", "2026-11-20T10:00:00Z", { retryOf: "r" })], [])[0]),
    "Retry: Run `uptime` on 12 hosts",
  );
});

test("items of the same instant keep one order: runs as the core listed them, then typed lines", () => {
  const at = "2026-11-20T10:00:00Z";
  const items = resultItems([job("r2", at), job("r1", at)], [line("l2", at), line("l1", at)]);
  assert.deepEqual(
    items.map((i) => i.key),
    ["run:r2", "run:r1", "typed:l2", "typed:l1"],
  );
  // The same answer however often it is asked (a re-read doesn't reshuffle the list).
  assert.deepEqual(
    resultItems([job("r2", at), job("r1", at)], [line("l2", at), line("l1", at)]).map((i) => i.key),
    items.map((i) => i.key),
  );
});

test("a failed host's retry is off only where the core refuses it", () => {
  const lock = "Read-only while presenting";
  const fresh = { commandType: "remoteExec", bodiesRemoved: false, commandRedacted: false };
  assert.equal(retryBlockedReason(fresh, null), null);
  assert.equal(retryBlockedReason(fresh, lock), lock, "the read-only lock first");
  // The purge empties a remote exec run's script, so that run can't go again as it ran...
  assert.match(retryBlockedReason({ ...fresh, bodiesRemoved: true }, null) ?? "", /removed after the retention period/);
  // ...but a push, fetch or key push keeps what it needs: the core retries it.
  for (const commandType of ["bulkFiles", "pushSshKey"])
    assert.equal(retryBlockedReason({ ...fresh, commandType, bodiesRemoved: true }, null), null, commandType);
  assert.match(retryBlockedReason({ ...fresh, commandRedacted: true }, null) ?? "", /looked like a secret/);
  // A typed line has no retry at all, and says why.
  assert.match(TYPED_NO_RETRY, /can't be retried/);
});

test("the panel opens the picked run even before the list is read again, and a gone line gives way", () => {
  const items = resultItems([job("r", "2026-11-20T10:01:00Z")], [line("l", "2026-11-20T10:02:00Z")]);
  const newest = shownResult(items, null);
  assert.equal(newest?.kind === "typed" && newest.line.id, "l");
  assert.equal(shownKey(newest), "typed:l");
  // Just queued: not listed yet, still opened by its id.
  assert.deepEqual(shownResult(items, "run:queued-now"), { kind: "run", jobId: "queued-now" });
  assert.equal(shownKey(shownResult(items, "run:r")), "run:r");
  assert.equal(shownKey(shownResult(items, "typed:gone")), "typed:l");
  assert.equal(shownResult([], null), null);
  assert.equal(shownKey(null), null);
});

test("where each stands, in words", () => {
  const partly = resultItems(
    [job("r", "2026-11-20T10:00:00Z", { status: "partially_failed", targetsSucceeded: 10, targetsFailed: 2 })],
    [],
  )[0];
  assert.equal(itemStatus(partly), "10 of 12 hosts succeeded, 2 failed");
  assert.ok(!itemRunning(partly));
  const running = resultItems([job("r", "2026-11-20T10:00:00Z", { status: "running", targetsSucceeded: 3 })], [])[0];
  assert.equal(itemStatus(running), "3 of 12 hosts succeeded, running");
  assert.ok(itemRunning(running));
  const typing = resultItems([], [line("l", "2026-11-20T10:00:00Z", { finished: 2 })])[0];
  assert.equal(itemStatus(typing), "2 of 6 terminals done");
  assert.ok(itemRunning(typing));
});

test("Activity opens bulk jobs in the grouped results view, a bundle in its mode, the rest in their sheet", () => {
  assert.equal(activityView("remoteExec"), "results");
  assert.equal(activityView("bulkFiles"), "results");
  assert.equal(activityView("pushSshKey"), "results");
  assert.equal(activityView("supportBundle"), "bundle");
  for (const other of ["vmPower", "terminalLine", "fileUpload", "deploy", ""])
    assert.equal(activityView(other), null, other);
});
