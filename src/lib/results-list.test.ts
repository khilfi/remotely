/// <reference types="node" />
// UX-17, UX-18 (0.9.0 H3): Compare hosts' one results list and how Activity opens a job. Run with `npm test`.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { JobSummary, RecordedLine } from "./api.ts";
import {
  activityView,
  itemBadge,
  itemKey,
  itemRunning,
  itemStatus,
  itemTitle,
  keepReason,
  KEPT_LINE,
  KEPT_NO_RETRY,
  resultItems,
  retryBlockedReason,
  shownKey,
  shownResult,
  TERMINAL_STATUS,
  TERMINAL_UNKNOWN,
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
    kept: false,
    reached: 6,
    ...more,
  };
}

/** QL-31: a typed line kept as a run: its job's id is the line's. */
function kept(id: string, createdAt: string, more: Partial<JobSummary> = {}): JobSummary {
  return job(id, createdAt, {
    summary: "Typed `df -h /` in 6 tabs",
    targetsTotal: 6,
    targetsSucceeded: 6,
    commandType: KEPT_LINE,
    ...more,
  });
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

test("a kept line lists among runs, badged as kept, and its typed original goes once its run is listed", () => {
  const runs = [
    job("r2", "2026-11-20T10:05:00Z"),
    kept("l2", "2026-11-20T10:04:00Z"),
    job("r1", "2026-11-20T10:00:00Z"),
  ];
  // l2 is kept and listed; l1 was kept too, but its run is past the list's page: it stays, saying it was kept.
  const lines = [
    line("l2", "2026-11-20T10:04:00Z", { kept: true }),
    line("l1", "2026-11-20T10:01:00Z", { kept: true }),
  ];
  const items = resultItems(runs, lines);
  assert.deepEqual(
    items.map((i) => i.key),
    ["run:r2", "kept:l2", "typed:l1", "run:r1"],
  );
  const keptItem = items[1];
  assert.equal(keptItem.kind, "kept");
  assert.equal(itemBadge(keptItem), "Kept from 6 tabs");
  assert.equal(itemTitle(keptItem), "Typed `df -h /` in 6 tabs");
  assert.equal(itemStatus(keptItem), "6 of 6 tabs with the prompt back");
  assert.ok(!itemRunning(keptItem));
  assert.equal(itemStatus(items[2]), "Kept as a run · All 6 the same");
  // Each tab's exit state where known: the prompt back, unknown (it never came back), or Enter never sent.
  const partly = resultItems(
    [kept("k", "2026-11-20T10:00:00Z", { targetsSucceeded: 3, targetsUnknown: 2, targetsFailed: 1 })],
    [],
  )[0];
  assert.equal(itemStatus(partly), "3 of 6 tabs with the prompt back, 2 outcome unknown, 1 not sent");
});

test("a typed or kept line's terminals read by their exit state where known", () => {
  assert.equal(TERMINAL_STATUS.succeeded, "Prompt back");
  assert.equal(TERMINAL_STATUS.unknown, "Outcome unknown");
  assert.equal(TERMINAL_STATUS.failed, "Not sent");
  assert.match(TERMINAL_UNKNOWN, /prompt never came back/);
});

test("a line picked and then kept shows as its kept run, even before the list is read again", () => {
  const before = resultItems([], [line("l", "2026-11-20T10:00:00Z")]);
  // Just kept: the panel asks for its run by id.
  assert.deepEqual(shownResult(before, "kept:l"), { kind: "kept", jobId: "l" });
  assert.equal(shownKey(shownResult(before, "kept:l")), "kept:l");
  // Read again: the typed original is gone and its pick finds the kept run.
  const after = resultItems([kept("l", "2026-11-20T10:00:00Z")], [line("l", "2026-11-20T10:00:00Z", { kept: true })]);
  assert.deepEqual(shownResult(after, "typed:l"), { kind: "kept", jobId: "l" });
  assert.deepEqual(shownResult(after, null), { kind: "kept", jobId: "l" });
});

test("a kept line is never retried, and a typed line is kept only once every tab has finished it", () => {
  const keptJob = { commandType: KEPT_LINE, bodiesRemoved: false, commandRedacted: false };
  assert.equal(retryBlockedReason(keptJob, null), KEPT_NO_RETRY);
  assert.equal(retryBlockedReason(keptJob, "Read-only while presenting"), KEPT_NO_RETRY);
  // Word for word as the core refuses it (crates/core/src/kept_lines.rs NO_RETRY).
  const core = readFileSync(new URL("../../crates/core/src/kept_lines.rs", import.meta.url), "utf8");
  const said = /pub const NO_RETRY: &str =\s*"([^"]*)";/.exec(core)?.[1];
  assert.equal(said, KEPT_NO_RETRY);

  const lock = "Read-only while presenting";
  const done = { waitingApproval: false, finished: 3, terminals: 3, reached: 3 };
  assert.equal(keepReason(done, null), null);
  assert.equal(keepReason(done, lock), lock);
  assert.match(
    keepReason({ ...done, waitingApproval: true, finished: 0, reached: 0 }, null) ?? "",
    /waits for its approval/,
  );
  // Approved, its Enter not gone yet: AP-03's countdown.
  assert.match(keepReason({ ...done, finished: 0, reached: 0 }, null) ?? "", /countdown/);
  assert.match(keepReason({ ...done, finished: 2 }, null) ?? "", /still running it/);
  // Enter reached none of its tabs: nothing to keep.
  assert.match(keepReason({ ...done, reached: 0 }, null) ?? "", /nothing to keep/);
});

test("Activity opens bulk jobs in the grouped results view, a bundle in its mode, the rest in their sheet", () => {
  assert.equal(activityView("remoteExec"), "results");
  assert.equal(activityView("bulkFiles"), "results");
  assert.equal(activityView("pushSshKey"), "results");
  assert.equal(activityView(KEPT_LINE), "results", "a kept line, shown there without retry");
  assert.equal(activityView("supportBundle"), "bundle");
  for (const other of ["vmPower", "terminalLine", "fileUpload", "deploy", ""])
    assert.equal(activityView(other), null, other);
});
