/// <reference types="node" />
// QL-22 status bar: the vault countdown, open jobs and tunnels, alerts and updates in words; the tunnels store the
// panes feed. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { JobSummary, TunnelInfo, VaultInfo } from "./api.ts";
import { forgetTerminal, isOpen, openTunnels, reportTunnels, resetTunnels, subscribeTunnels } from "./open-tunnels.ts";
import {
  alertsText,
  formatCountdown,
  jobsText,
  LOCK_WARNING_SECS,
  OpenJobs,
  reportVault,
  secondsLeft,
  tunnelsText,
  updateText,
  vaultLockAt,
  vaultText,
} from "./status-bar.ts";

const unlocked: VaultInfo = {
  status: "unlocked",
  windowsLogin: false,
  windowsLoginAvailable: true,
  idleLockMinutes: 15,
  locksInSecs: 600,
};

function tunnel(id: string, state: TunnelInfo["state"], label: string | null = null): TunnelInfo {
  return {
    forward: {
      id,
      sessionId: "s-1",
      label,
      kind: "local",
      bindAddress: "127.0.0.1",
      bindPort: 8080,
      destHost: "db01.example.com",
      destPort: 5432,
      autoStart: false,
    },
    state,
    connections: 0,
    open: 0,
    lastError: null,
    saved: true,
    changed: false,
  };
}

function job(id: string, status: JobSummary["status"]): JobSummary {
  return { id, summary: `Job ${id}`, status } as unknown as JobSummary;
}

test("the countdown reads as minutes and seconds", () => {
  assert.equal(formatCountdown(14 * 60 + 5), "14:05");
  assert.equal(formatCountdown(42), "0:42");
  assert.equal(formatCountdown(3723), "1:02:03");
  assert.equal(formatCountdown(-3), "0:00");
});

test("the vault's answers set when it locks; locked or not set up, there is no countdown", () => {
  reportVault(unlocked, 1_000_000);
  assert.equal(vaultLockAt(), 1_000_000 + 600_000);
  assert.equal(secondsLeft(vaultLockAt(), 1_000_000 + 1_500), 599);
  assert.equal(secondsLeft(vaultLockAt(), 1_000_000 + 700_000), 0);
  reportVault({ ...unlocked, status: "locked", locksInSecs: null });
  assert.equal(vaultLockAt(), null);
  assert.equal(secondsLeft(null, 0), null);
});

test("the vault in words: amber in the last minute", () => {
  assert.equal(vaultText(unlocked, 600).label, "Vault locks in 10:00");
  assert.equal(vaultText(unlocked, 600).tone, "good");
  assert.equal(vaultText(unlocked, LOCK_WARNING_SECS).tone, "warning");
  assert.equal(vaultText({ ...unlocked, status: "locked", locksInSecs: null }, null).label, "Vault locked");
  assert.equal(vaultText({ ...unlocked, status: "notSetUp", locksInSecs: null }, null).label, "No vault yet");
  assert.equal(vaultText(null, null).label, "Vault");
});

test("open jobs: seeded from the recent ones, then followed by their events", () => {
  const jobs = new OpenJobs();
  jobs.seed([job("a", "running"), job("b", "succeeded"), job("c", "countdown")]);
  assert.equal(jobs.count, 2);
  assert.ok(jobs.note({ event: "queued", jobId: "d", summary: "Start web01", tier: "low", targets: 1, quiet: false }));
  assert.equal(jobs.count, 3);
  assert.ok(!jobs.note({ event: "started", jobId: "d" }), "progress changes nothing here");
  assert.ok(jobs.note({ event: "finished", jobId: "a", status: "succeeded", scope: "vms" }));
  assert.equal(jobs.count, 2);
  assert.ok(!jobs.note({ event: "finished", jobId: "zz", status: "failed", scope: "other" }), "not one it knew");
  assert.equal(jobsText(0, []), null);
  assert.equal(jobsText(1, ["Start web01"])?.label, "1 job running");
  assert.match(
    jobsText(
      7,
      Array.from({ length: 7 }, (_, i) => `job ${i}`),
    )?.title ?? "",
    /and 2 more/,
  );
});

test("tunnels: the panes report theirs; open means listening, opening or waiting; a closed pane forgets them", () => {
  resetTunnels();
  let changes = 0;
  const stop = subscribeTunnels(() => (changes += 1));
  const listening = tunnel("f1", { state: "listening", at: "127.0.0.1:8080" });
  const stopped = tunnel("f2", { state: "stopped" });
  reportTunnels("t-1", [listening, stopped]);
  assert.equal(openTunnels().length, 1);
  assert.equal(openTunnels()[0].terminalId, "t-1");
  assert.equal(openTunnels()[0].sessionId, "s-1");
  const same = openTunnels();
  assert.equal(openTunnels(), same, "the same array until something changes");
  reportTunnels("t-2", [tunnel("f3", { state: "waiting", reason: "reconnecting" })]);
  assert.equal(openTunnels().length, 2);
  assert.ok(isOpen(tunnel("x", { state: "opening" })));
  assert.ok(!isOpen(tunnel("x", { state: "failed", message: "refused" })));
  assert.ok(!isOpen(tunnel("x", { state: "asking" })));
  forgetTerminal("t-1");
  assert.equal(openTunnels().length, 1);
  assert.equal(changes, 3);
  stop();
  const text = tunnelsText(openTunnels(), () => "web");
  assert.equal(text?.label, "1 tunnel");
  assert.equal(text?.tone, "warning", "a tunnel waiting for its terminal");
  assert.equal(
    tunnelsText([], () => ""),
    null,
  );
  resetTunnels();
});

test("alerts and updates in words", () => {
  assert.equal(alertsText(0, 0), null);
  assert.equal(alertsText(2, 1)?.tone, "danger");
  assert.equal(alertsText(2, 0)?.tone, "warning");
  assert.equal(updateText(null, null), null);
  assert.equal(updateText({ status: "upToDate" }, null)?.label, "Up to date");
  assert.equal(
    updateText(
      { status: "available", update: { currentVersion: "0.5.0", version: "0.5.1", notes: null, pubDate: null } },
      null,
    )?.label,
    "Update 0.5.1",
  );
  assert.equal(updateText({ status: "off" }, null)?.tone, "muted");
  assert.equal(updateText({ status: "upToDate" }, "The token was refused.")?.tone, "danger");
});
