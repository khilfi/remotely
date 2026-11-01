/// <reference types="node" />
// UX-10: the tools table and the approval rules' summary. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PolicyRules, Settings } from "./api.ts";
import { rulesChanged, rulesLine, tierSteps, toolRows, toolStatus } from "./settings-summary.ts";

const settings = {
  vmrunPathSaved: null,
  vmrunPathInUse: "C:\\Program Files\\VMware\\VMware Workstation\\vmrun.exe",
  ovftoolPathSaved: null,
  ovftoolPathInUse: null,
  vboxmanagePathSaved: "D:\\VirtualBox\\VBoxManage.exe",
  vboxmanagePathInUse: "D:\\VirtualBox\\VBoxManage.exe",
  qemuImgPathSaved: "D:\\nothing\\qemu-img.exe",
  qemuImgPathInUse: null,
  dockerPathSaved: null,
  dockerPathInUse: null,
  vncViewerPathSaved: null,
  vncViewerPathInUse: "C:\\Program Files\\TigerVNC\\vncviewer.exe",
} as unknown as Settings;

test("the tools table has one row per tool, the editable ones and vdiskmanager beside vmrun", () => {
  const rows = toolRows(settings, "C:\\Program Files\\VMware\\VMware Workstation\\vmware-vdiskmanager.exe");
  assert.deepEqual(
    rows.map((r) => r.id),
    ["vmrun", "vdiskmanager", "ovftool", "vboxmanage", "qemuImg", "docker", "vncViewer"],
  );
  assert.equal(rows.find((r) => r.id === "vdiskmanager")?.editable, false);
  assert.ok(rows.filter((r) => r.id !== "vdiskmanager").every((r) => r.editable));
  // Links to the old cards open their rows.
  assert.deepEqual(
    rows.filter((r) => r.section).map((r) => r.section),
    ["vmware", "virtualbox", "qemu-img", "docker", "vnc-viewer"],
  );
});

test("each tool's status is a few words", () => {
  const rows = toolRows(settings, null);
  const status = (id: string) => toolStatus(rows.find((r) => r.id === id)!);
  assert.equal(status("vmrun"), "Found");
  assert.equal(status("vboxmanage"), "Found · path set here");
  assert.equal(status("qemuImg"), "Not at the path set here");
  assert.equal(status("docker"), "Not installed");
  assert.equal(status("ovftool"), "Not found");
  assert.equal(status("vdiskmanager"), "Not found");
  assert.equal(status("vncViewer"), "Found");
});

const DEFAULTS: PolicyRules = {
  tiers: {
    vmStart: { single: "low", bulk: "low" },
    vmStopHard: { single: "critical", bulk: "critical" },
  } as PolicyRules["tiers"],
  bulkThreshold: 3,
  execBulkThreshold: 5,
  deployBulkThreshold: 5,
  prodBump: true,
  dangerousCommands: [{ name: "Recursive delete", pattern: "rm\\s+-rf" }],
  readOnlyCommands: ["uptime", "df -h"],
  countdownSeconds: 10,
  safetySnapshotDefault: true,
};

test("the summary counts each rule that differs from the defaults", () => {
  assert.equal(rulesChanged(DEFAULTS, DEFAULTS), 0);
  assert.equal(rulesLine(0), "Default rules · 0 changed");
  const mine: PolicyRules = {
    ...DEFAULTS,
    tiers: { ...DEFAULTS.tiers, vmStart: { single: "low", bulk: "medium" } },
    countdownSeconds: 0,
    dangerousCommands: [...DEFAULTS.dangerousCommands, { name: "Format", pattern: "mkfs" }],
    readOnlyCommands: ["uptime"],
  };
  assert.equal(rulesChanged(mine, DEFAULTS), 4);
  assert.equal(rulesLine(4), "Your rules · 4 changed");
  // The order of the read-only commands doesn't count.
  assert.equal(rulesChanged({ ...DEFAULTS, readOnlyCommands: ["df -h", "uptime"] }, DEFAULTS), 0);
});

test("each tier's steps read in plain words, with the countdown and snapshot as set", () => {
  const steps = tierSteps(DEFAULTS);
  assert.deepEqual(
    steps.map((s) => s.tier),
    ["low", "medium", "high", "critical"],
  );
  assert.equal(steps[2].steps, "The impact, a safety snapshot, type to confirm and a reason, then a 10 s countdown");
  const off = tierSteps({ countdownSeconds: 0, safetySnapshotDefault: false });
  assert.equal(off[2].steps, "The impact, a safety snapshot (off by default), type to confirm and a reason");
  assert.match(steps[3].steps, /vault password/);
});
