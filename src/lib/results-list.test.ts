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
  noRetryReason,
  resultItems,
  shownItem,
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

test("only runs retry; a typed line says why it has none", () => {
  const [run, typed] = resultItems([job("r", "2026-11-20T10:01:00Z")], [line("l", "2026-11-20T10:00:00Z")]);
  assert.equal(noRetryReason(run), null);
  assert.equal(noRetryReason(typed), TYPED_NO_RETRY);
  assert.match(TYPED_NO_RETRY, /can't be retried/);
});

test("the picked item while it is listed, else the newest", () => {
  const items = resultItems([job("r", "2026-11-20T10:01:00Z")], [line("l", "2026-11-20T10:02:00Z")]);
  assert.equal(shownItem(items, null)?.key, "typed:l");
  assert.equal(shownItem(items, "run:r")?.key, "run:r");
  // A typed line goes when typing stops: the newest shows instead.
  assert.equal(shownItem(items, "typed:gone")?.key, "typed:l");
  assert.equal(shownItem([], "run:r"), null);
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
