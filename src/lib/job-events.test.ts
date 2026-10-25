/// <reference types="node" />
// P6, VM-01: which job events and setting changes make the app render or read again. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { JobEvent, JobScope } from "./api.ts";
import {
  changesAppInfo,
  changesContainerHosts,
  changesJobList,
  changesUpdates,
  changesVmList,
  progressesJob,
  refreshDue,
  refreshesContainers,
  refreshesVms,
  type SettingsChange,
} from "./job-events.ts";

const jobId = "7d1c6a52-0000-4000-8000-000000000001";

/** One of each event a job sends, in the order a job with one target sends them. */
function lifecycle(scope: JobScope): JobEvent[] {
  return [
    { event: "queued", jobId, summary: "Suspend web01", tier: "medium", targets: 1, quiet: false },
    { event: "countdown", jobId, seconds: 10, until: "2026-10-25T10:00:10Z" },
    { event: "started", jobId },
    { event: "targetStarted", jobId, target: "vm:web01", name: "web01" },
    {
      event: "targetFinished",
      jobId,
      target: "vm:web01",
      name: "web01",
      status: "succeeded",
      message: null,
      exitCode: null,
      durationMs: 1200,
      safetySnapshot: null,
    },
    { event: "finished", jobId, status: "succeeded", scope },
  ];
}

test("only a job queued or ended changes App's state; the rest is progress", () => {
  const events = lifecycle("vms");
  assert.deepEqual(
    events.filter(changesJobList).map((e) => e.event),
    ["queued", "finished"],
  );
  assert.deepEqual(
    events.filter(progressesJob).map((e) => e.event),
    ["countdown", "started", "targetFinished"],
  );
  // A target starting changes no count Activity shows.
  assert.equal(progressesJob(events[3]), false);
  assert.equal(progressesJob({ event: "stillRunning", jobId, targets: [] }), true);
});

test("a 50-target job changes App's state twice, not 104 times", () => {
  const [queued, countdown, started, targetStarted, targetFinished, finished] = lifecycle("other");
  const events = [
    queued,
    countdown,
    started,
    ...Array.from({ length: 50 }, () => [targetStarted, targetFinished]).flat(),
    finished,
  ];
  assert.equal(events.length, 104);
  assert.equal(events.filter(changesJobList).length, 2);
});

test("a finished job refreshes only the page whose things it may have changed", () => {
  const finished = (scope: JobScope) => lifecycle(scope)[5];
  assert.equal(refreshesVms(finished("vms")), true);
  assert.equal(refreshesVms(finished("containers")), false);
  assert.equal(refreshesVms(finished("other")), false, "an upload or a remote command changes no VM");
  assert.equal(refreshesContainers(finished("containers")), true);
  assert.equal(refreshesContainers(finished("vms")), false);
  // Progress never refreshes, whatever the job.
  for (const e of lifecycle("vms").slice(0, 5)) {
    assert.equal(refreshesVms(e), false, e.event);
    assert.equal(refreshesContainers(e), false, e.event);
  }
});

test("a setting refreshes only what depends on it", () => {
  const all: SettingsChange[] = ["vmrun", "vboxmanage", "scanFolders", "docker", "updates", "other"];
  assert.deepEqual(all.filter(changesVmList), ["vmrun", "vboxmanage", "scanFolders"]);
  assert.deepEqual(all.filter(changesContainerHosts), ["docker"]);
  assert.deepEqual(all.filter(changesAppInfo), ["vmrun", "vboxmanage"]);
  assert.deepEqual(all.filter(changesUpdates), ["updates"], "no GitHub check after an unrelated save");
});

test("a hidden page lets its refreshes wait and does one when it shows", () => {
  assert.equal(refreshDue(true, "0:0", null), true, "the first time it shows");
  assert.equal(refreshDue(true, "0:0", "0:0"), false, "nothing changed");
  // Three VM jobs finished while another page showed: nothing is refreshed yet...
  for (const wanted of ["0:1", "0:2", "0:3"]) assert.equal(refreshDue(false, wanted, "0:0"), false);
  // ...and one refresh when the page shows again.
  assert.equal(refreshDue(true, "0:3", "0:0"), true);
  assert.equal(refreshDue(true, "0:3", "0:3"), false, "showing it again later reads nothing");
});
