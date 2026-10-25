/// <reference types="node" />
// VM-21, VM-22, VM-10: the Deploy and Clone dialogs' texts and a deploy job's steps. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { DeployCheck, DeployPreview, JobEvent } from "./api.ts";
import {
  applyJobEvent,
  bytesText,
  cloneReason,
  deployReason,
  newVmKey,
  packagesText,
  parseCount,
  parsePackages,
  progressSummary,
  startProgress,
  stepText,
} from "./deploy.ts";

test("counts are whole numbers from 1 to 50", () => {
  assert.equal(parseCount(" 3 "), 3);
  assert.equal(parseCount("50"), 50);
  for (const bad of ["0", "51", "2.5", "", "x", "-1"]) assert.equal(parseCount(bad), null, bad);
});

test("packages split on commas and spaces, each once", () => {
  assert.deepEqual(parsePackages("nginx, curl  htop,nginx\n"), ["nginx", "curl", "htop"]);
  assert.deepEqual(parsePackages("  "), []);
  assert.equal(packagesText(["nginx", "curl"]), "nginx, curl");
});

function preview(change: Partial<DeployPreview> = {}): DeployPreview {
  return {
    summary: "Deploy 2 VMs from 'web'",
    origin: { kind: "template", id: "t", name: "web" },
    hypervisor: "vmware",
    source: "the VMDK cloud image C:\\Images\\noble.vmdk on Workstation",
    folder: "C:\\VMs\\lab",
    size: null,
    network: "NAT",
    hostAdapter: null,
    environment: "lab",
    tags: [],
    firstBoot: null,
    afterDeploy: { createSession: true, linkSession: true, cleanSnapshot: false, openConsole: false },
    vms: [],
    diskBytes: 0,
    thickBytes: 0,
    freeBytes: null,
    notes: [],
    warnings: [],
    refusals: [],
    ...change,
  };
}

test("Deploy says why it can't be pressed", () => {
  const ok: DeployCheck = { problems: [], preview: preview() };
  const base = { busy: false, count: 2, checking: false, check: ok, error: null };
  assert.equal(deployReason(base), null);
  assert.equal(deployReason({ ...base, busy: true }), "Submitting…");
  assert.equal(deployReason({ ...base, count: null }), "The count is a whole number, 1 to 50");
  assert.equal(deployReason({ ...base, checking: true }), "Checking…");
  assert.equal(deployReason({ ...base, error: "the vault is locked" }), "the vault is locked");
  assert.equal(
    deployReason({
      ...base,
      check: { problems: [{ code: "imageGone", message: "Its image was deleted." }], preview: null },
    }),
    "Its image was deleted.",
  );
  assert.equal(
    deployReason({ ...base, check: { problems: [], preview: preview({ refusals: ["web-2: the folder is there"] }) } }),
    "web-2: the folder is there",
  );
});

test("a deploy job's events become one step per VM", () => {
  const vms = [
    { name: "web-1", target: newVmKey("vmware", "web-1") },
    { name: "web-2", target: newVmKey("vmware", "web-2") },
  ];
  assert.equal(vms[0].target, "new-vm/vmware/web-1");
  let p = startProgress("job", vms);
  assert.equal(progressSummary(p), "Waiting to start");
  const events: JobEvent[] = [
    { event: "countdown", jobId: "job", seconds: 10, until: "2026-10-25T10:00:10Z" },
    { event: "started", jobId: "job" },
    { event: "targetStarted", jobId: "job", target: vms[0].target, name: "web-1" },
    { event: "targetStarted", jobId: "other", target: vms[1].target, name: "web-2" },
  ];
  p = applyJobEvent(p, events[0]);
  assert.equal(progressSummary(p), "Starts after the countdown; nothing is made yet");
  for (const e of events.slice(1)) p = applyJobEvent(p, e);
  assert.equal(p.steps[0].status, "running");
  assert.equal(p.steps[1].status, "waiting", "another job's event changes nothing");
  assert.equal(progressSummary(p), "0 of 2 made");
  p = applyJobEvent(p, {
    event: "targetFinished",
    jobId: "job",
    target: vms[0].target,
    name: "web-1",
    status: "succeeded",
    message: null,
    exitCode: null,
    durationMs: 5000,
    safetySnapshot: null,
    note: "web-1: in C:\\VMs\\lab\\web-1, IP 192.0.2.10",
  });
  assert.equal(stepText(p.steps[0]), "in C:\\VMs\\lab\\web-1, IP 192.0.2.10", "the step shows the name already");
  p = applyJobEvent(p, { event: "finished", jobId: "job", status: "cancelled", scope: "vms" });
  assert.equal(p.steps[1].status, "cancelled", "never reached");
  assert.equal(progressSummary(p), "Done: 1 made, 1 cancelled");
  assert.equal(stepText(p.steps[1]), "Cancelled; what it made was removed");
  assert.match(
    stepText({ ...p.steps[1], status: "failed", message: "vmrun clone failed" }),
    /Failed: vmrun clone failed\. What it made was removed\./,
  );
});

test("sizes read in GB and TB", () => {
  assert.equal(bytesText(540 * 2 ** 30), "540 GB");
  assert.equal(bytesText(1.5 * 2 ** 30), "1.5 GB");
  assert.equal(bytesText(1620 * 2 ** 30), "1.6 TB");
  assert.equal(bytesText(300 * 2 ** 20), "300 MB");
  assert.equal(bytesText(null), "unknown");
});

test("Clone says why the picked VMs can't be cloned", () => {
  const off = { name: "web01", powerState: "not_running", hypervisor: "vmware" };
  assert.equal(cloneReason([off]), null);
  assert.equal(cloneReason([]), "Pick the VMs to clone");
  assert.equal(cloneReason([off, { ...off, hypervisor: "virtualbox" }]), "Clone the VMs of one hypervisor at a time");
  assert.equal(
    cloneReason([off, { ...off, name: "db01", powerState: "running" }]),
    "Shut db01 down first: a clone copies a VM that is off",
  );
});
