/// <reference types="node" />
// QL-12 recordings and QL-07 notifications, the UI side. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { RecordedLine } from "./api.ts";
import {
  capsNote,
  captureText,
  lineNotification,
  lineStatus,
  shortDuration,
  shouldNotify,
  shownLine,
  type NotifyChoice,
} from "./recordings.ts";

function line(id: string, patch: Partial<RecordedLine> = {}): RecordedLine {
  return {
    id,
    line: "uptime",
    tier: "low",
    jobId: null,
    recordedAt: "2026-10-21T10:00:00Z",
    waitingApproval: false,
    terminals: 3,
    finished: 3,
    headline: "All 3 hosts the same",
    groups: 1,
    truncated: false,
    fullScreen: false,
    durationMs: 1200,
    ...patch,
  };
}

test("a terminal's recording reads as where it stands", () => {
  assert.deepEqual(captureText({ state: "done", how: "prompt" }, 1234), {
    text: "Prompt back after 1.2 s",
    tone: "ok",
  });
  assert.equal(captureText({ state: "running" }, 4000).text, "Running 4.0 s");
  assert.equal(captureText({ state: "running" }, null).text, "Running");
  assert.equal(captureText({ state: "waiting" }, null).tone, "muted");
  assert.equal(captureText({ state: "done", how: "quiet" }, 30_000).tone, "warn");
  assert.match(captureText({ state: "done", how: "nextLine" }, 500).text, /next line after 500 ms/);
  assert.match(captureText({ state: "timedOut" }, null).text, /time limit/);
  assert.deepEqual(captureText({ state: "lost", reason: "the terminal closed" }, null), {
    text: "Lost: the terminal closed",
    tone: "bad",
  });
  assert.equal(captureText({ state: "notSent", reason: "not connected" }, null).text, "Not sent: not connected");
  assert.equal(shortDuration(65_000), "1 min");
  assert.equal(shortDuration(12_400), "12 s");
});

test("the list says what waits, what runs, and how the rest group", () => {
  assert.equal(lineStatus(line("a", { waitingApproval: true, finished: 0 })), "Waiting for approval");
  assert.equal(lineStatus(line("a", { finished: 2 })), "2 of 3 terminals done");
  assert.equal(lineStatus(line("a")), "All 3 hosts the same");
});

test("the panel shows the picked line while it is kept, else the newest", () => {
  const lines = [line("new"), line("old")];
  assert.equal(shownLine(lines, null)?.id, "new");
  assert.equal(shownLine(lines, "old")?.id, "old");
  assert.equal(shownLine(lines, "dropped")?.id, "new");
  assert.equal(shownLine([], "old"), null);
});

test("the caps say so only when one was hit", () => {
  const limits = { maxLines: 200, maxOutputBytes: 65_536, maxSessionBytes: 32 * 1024 * 1024, lineSecs: 600 };
  assert.equal(capsNote(0, limits), null);
  assert.equal(
    capsNote(1, limits),
    "This MultiExec session keeps its last 200 lines (32 MB of output at most): 1 older line was dropped.",
  );
  assert.match(capsNote(5, limits) ?? "", /5 older lines were dropped/);
});

test("QL-07: long commands, or any command, only while away", () => {
  const long: NotifyChoice = { on: true, when: "long", afterSecs: 30 };
  const any: NotifyChoice = { on: true, when: "any", afterSecs: 30 };
  assert.equal(shouldNotify(long, 45, true), true);
  assert.equal(shouldNotify(long, 2, true), false, "short");
  assert.equal(shouldNotify(any, 0, true), true, "any length");
  assert.equal(shouldNotify(any, 300, false), false, "not while looking at it");
  assert.equal(shouldNotify({ ...any, on: false }, 300, true), false, "off");
});

test("QL-07: one notification for a MultiExec line, naming the line and its terminals", () => {
  assert.deepEqual(lineNotification("uptime", 3, 42, "prompt", 0), {
    title: "MultiExec `uptime` finished in 3 terminals",
    body: "It ran 42 s; the prompt is back in all 3.",
  });
  assert.equal(lineNotification("df -h", 2, 5, "prompt", 0).body, "It ran 5 s; the prompt is back in both.");
  const quiet = lineNotification("apt upgrade", 1, 125, "quiet", 1);
  assert.equal(quiet.title, "MultiExec `apt upgrade` finished in 1 terminal");
  assert.match(quiet.body, /2 min; in some terminals the output stopped/);
  assert.match(quiet.body, /1 terminal stopped recording/);
  assert.equal(
    lineNotification("cd /srv\nmake", 2, 1, "prompt", 0).title,
    "MultiExec `cd /srv …` finished in 2 terminals",
  );
  assert.match(lineNotification("x".repeat(100), 2, 1, "prompt", 0).title, /x{59}…`/);
});
