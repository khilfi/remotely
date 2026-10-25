/// <reference types="node" />
// R4 (VM-25, VM-11, VM-16, VM-14): following and searching a log, the timeline's groups, the port forward form and
// its command, the waste finder's reasons and sums. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { PROTECTED_REASON } from "./vm-snapshots.ts";
import {
  EMPTY_FORWARD,
  describeForward,
  deleteVmReason,
  eventLabel,
  followLog,
  followReason,
  forwardCommand,
  forwardFromForm,
  forwardProblems,
  forwardReason,
  groupTimeline,
  isHostIpv4,
  logMatches,
  mergeTimeline,
  outcomeText,
  prefixLength,
  splitMatches,
  startLog,
  suspendReason,
  topologyHostNetworks,
  vboxForward,
  vmnetForward,
  vmnetKindLabel,
  wasteTotals,
  type ForwardPlace,
} from "./vm-insight.ts";
import type { VirtualNic } from "./api.ts";
import { networkKey } from "./topology.ts";
import type { HostNetworksReport, LogChunk, TimelineEntry, WasteReport, WasteVm } from "./vm-insight-api.ts";

function chunk(over: Partial<LogChunk>): LogChunk {
  return {
    file: "vmware.log",
    start: 0,
    end: 0,
    size: 0,
    text: "",
    truncatedBefore: false,
    reset: false,
    skipped: 0,
    ...over,
  };
}

test("a followed log grows at the end and keeps its last lines", () => {
  let view = startLog(chunk({ text: "one\ntwo\n", end: 8, truncatedBefore: true }));
  assert.equal(view.startsMidway, true);
  view = followLog(view, chunk({ text: "", end: 8 }));
  assert.equal(view.text, "one\ntwo\n");
  view = followLog(view, chunk({ text: "three\n", start: 8, end: 14 }));
  assert.equal(view.text, "one\ntwo\nthree\n");
  assert.equal(view.end, 14);
  const capped = followLog(view, chunk({ text: "four\nfive\n", start: 14, end: 24 }), 12);
  assert.equal(capped.text, "four\nfive\n", "dropped from a line's start");
  assert.equal(capped.startsMidway, true);
});

test("a replaced log or a skip starts the view afresh and says so", () => {
  const view = startLog(chunk({ text: "old\n", end: 4 }));
  const restarted = followLog(view, chunk({ text: "new\n", end: 4, reset: true }));
  assert.equal(restarted.text, "new\n");
  assert.equal(restarted.restarted, true);
  const skipped = followLog(view, chunk({ text: "tail\n", end: 900, skipped: 500, truncatedBefore: true }));
  assert.equal(skipped.skipped, 500);
  assert.equal(skipped.text, "tail\n");
});

test("search finds lines in any letter case and splits them for highlighting", () => {
  const text = "alpha OK\nBeta error here\ngamma\nanother ERROR\n";
  assert.deepEqual(
    logMatches(text, "error").map((m) => m.line),
    [2, 4],
  );
  assert.deepEqual(logMatches(text, "  "), []);
  assert.deepEqual(logMatches("one\r\nTwo error\r\n", "error"), [{ line: 2, text: "Two error" }], "CRLF lines");
  assert.equal(logMatches(text, "a", 2).length, 2, "capped");
  assert.deepEqual(splitMatches("Beta error here", "ERROR"), [
    { text: "Beta ", match: false },
    { text: "error", match: true },
    { text: " here", match: false },
  ]);
  assert.deepEqual(splitMatches("plain", ""), [{ text: "plain", match: false }]);
});

test("only the current log of a running VM can be followed", () => {
  const current = { name: "vmware.log", size: 1, modified: null, current: true };
  const old = { ...current, name: "vmware-0.log", current: false };
  assert.equal(followReason("running", current), null);
  assert.equal(followReason("paused", current), null);
  assert.match(followReason("running", old) ?? "", /older log/);
  assert.match(followReason("not_running", current) ?? "", /isn't running/);
  assert.match(followReason("running", undefined) ?? "", /Choose/);
});

function entry(seq: number, event: string, jobId: string | null, over: Partial<TimelineEntry> = {}): TimelineEntry {
  return {
    seq,
    at: "2026-10-25T10:00:00Z",
    event,
    action: "Suspend 1 VM",
    tier: "medium",
    jobId,
    result: null,
    detail: null,
    reason: null,
    otherTargets: 0,
    outcome: null,
    ...over,
  };
}

test("a job's entries group together and the rest stand alone", () => {
  const ok = { status: "succeeded", error: null, durationMs: 10, safetySnapshot: null, finishedAt: null };
  const groups = groupTimeline([
    entry(9, "vm_label_changed", null),
    entry(8, "job_finished", "j1", { outcome: ok }),
    entry(7, "job_started", "j1"),
    entry(6, "approval_granted", null, { reason: "CHG-1" }),
    entry(5, "job_finished", "j0"),
  ]);
  assert.deepEqual(
    groups.map((g) => [g.jobId, g.entries.length]),
    [
      [null, 1],
      ["j1", 2],
      [null, 1],
      ["j0", 1],
    ],
  );
  assert.equal(groups[1].outcome?.status, "succeeded");
  assert.equal(groups[2].reason, "CHG-1");
  const merged = mergeTimeline(
    [entry(8, "job_finished", "j1")],
    [entry(8, "job_finished", "j1"), entry(7, "job_started", "j1")],
  );
  assert.equal(merged.length, 2, "an entry seen twice counts once");
  assert.equal(groupTimeline(merged).length, 1, "a job split across pages is one group");
});

test("events and outcomes read as words", () => {
  assert.equal(eventLabel("approval_granted"), "Approved");
  assert.equal(eventLabel("something_new"), "Something new");
  assert.deepEqual(
    outcomeText({ status: "failed", error: "x", durationMs: null, safetySnapshot: null, finishedAt: null }),
    {
      text: "Failed",
      tone: "bad",
    },
  );
  assert.equal(outcomeText(null), null);
});

const vmnet: ForwardPlace = { kind: "vmnet", name: "vmnet8" };
const natNet: ForwardPlace = { kind: "natNetwork", name: "lab-net" };
const vboxVm: ForwardPlace = { kind: "vboxVm", vmxPath: "u-1", slot: 2, vmName: "lab01" };

test("the forward form is checked like the core checks it", () => {
  const ok = { ...EMPTY_FORWARD, hostPort: "8080", guestPort: "80", guestIp: "203.0.113.10" };
  assert.deepEqual(forwardProblems(ok, vmnet), []);
  assert.match(forwardProblems({ ...ok, hostIp: "127.0.0.1" }, vmnet).join(), /every address/);
  assert.match(forwardProblems(ok, natNet).join(), /name/);
  assert.deepEqual(forwardProblems({ ...ok, name: "web" }, natNet), []);
  assert.match(forwardProblems({ ...ok, name: "a:b" }, natNet).join(), /letters/);
  assert.match(forwardProblems({ ...ok, name: 'say "hi"' }, vmnet).join(), /quotes/);
  assert.deepEqual(
    forwardProblems({ ...ok, name: "web", guestIp: "" }, vboxVm),
    [],
    "a VM's rule may leave the guest out",
  );
  assert.match(forwardProblems({ ...ok, guestIp: "" }, vmnet).join(), /guest's address/);
  assert.match(forwardProblems({ ...ok, hostPort: "70000" }, vmnet).join(), /1 to 65535/);
  assert.match(forwardProblems({ ...ok, guestPort: "0" }, vmnet).join(), /1 to 65535/);
  assert.equal(isHostIpv4("192.0.2.1"), true);
  for (const bad of ["0.0.0.0", "255.255.255.255", "224.0.0.1", "1.2.3", "300.1.1.1", "web01.example.com"]) {
    assert.equal(isHostIpv4(bad), false, bad);
  }
});

test("the form becomes the forward and the command the bus takes", () => {
  const form = { ...EMPTY_FORWARD, name: "web", hostIp: "127.0.0.1", hostPort: "8080", guestPort: "80" };
  const forward = forwardFromForm(form, vboxVm);
  assert.deepEqual(forward, {
    name: "web",
    protocol: "tcp",
    hostIp: "127.0.0.1",
    hostPort: 8080,
    guestIp: null,
    guestPort: 80,
    slot: 2,
  });
  assert.deepEqual(forwardCommand(vboxVm, true, forward), {
    type: "hostNetwork",
    targets: [{ kind: "vm", vmxPath: "u-1" }],
    op: { kind: "addForward", forward },
  });
  const remove = forwardCommand(
    vmnet,
    false,
    vmnetForward({
      protocol: "udp",
      hostPort: 5353,
      guestIp: "203.0.113.11",
      guestPort: 53,
      description: null,
    }),
  );
  assert.deepEqual(remove.type === "hostNetwork" && remove.targets, [
    { kind: "network", hypervisor: "vmware", name: "vmnet8" },
  ]);
  assert.equal(
    forwardFromForm({ ...form, guestIp: "203.0.113.10" }, vmnet).hostIp,
    null,
    "Workstation: no host address",
  );
  const rule = vboxForward(
    { name: "ssh", protocol: "tcp", hostIp: null, hostPort: 2222, guestIp: null, guestPort: 22 },
    1,
  );
  assert.equal(describeForward(rule), "'ssh': tcp 2222 → the guest:22");
  assert.equal(describeForward({ ...rule, name: null, guestIp: "198.51.100.5" }), "tcp 2222 → 198.51.100.5:22");
});

test("forward actions say why they are off", () => {
  assert.equal(forwardReason({ readOnly: null }), null);
  assert.equal(forwardReason({ readOnly: "locked" }), "locked");
  assert.equal(forwardReason({ readOnly: null, refused: "needs admin" }), "needs admin");
  assert.equal(forwardReason({ readOnly: null, vm: { protected: true, powerState: "running" } }), PROTECTED_REASON);
  assert.match(forwardReason({ readOnly: null, vm: { protected: false, powerState: "suspended" } }) ?? "", /Suspended/);
  assert.equal(vmnetKindLabel("nat"), "NAT");
  assert.equal(vmnetKindLabel({ other: "custom" }), "custom");
});

function wvm(over: Partial<WasteVm> = {}): WasteVm {
  return {
    vmxPath: "C:\\VMs\\a\\a.vmx",
    name: "a",
    hypervisor: "vmware",
    powerState: "running",
    environment: "none",
    protected: false,
    memoryMb: 2048,
    folder: "C:\\VMs\\a",
    ...over,
  };
}

test("waste rows say why their actions are off", () => {
  assert.equal(suspendReason(wvm(), null), null);
  assert.equal(suspendReason(wvm({ protected: true }), null), PROTECTED_REASON);
  assert.match(suspendReason(wvm({ powerState: "suspended" }), null) ?? "", /running VM/);
  assert.equal(suspendReason(wvm(), "locked"), "locked");
  assert.equal(deleteVmReason(wvm({ powerState: "suspended" }), null), null);
  assert.match(deleteVmReason(wvm(), null) ?? "", /shut it down/);
});

test("the report's sums add disk and memory", () => {
  const report: WasteReport = {
    options: { idleDays: 3, chainDepth: 5, chainGb: 20 },
    idleDays: 3,
    idle: [
      {
        vm: wvm({ memoryMb: 4096 }),
        verdict: {
          idle: true,
          coveredHours: 72,
          cpuAvg: 0.2,
          cpuPeakHour: 0.4,
          guestCpuPeakHour: null,
          guestNetPeakHour: null,
          whyNot: null,
        },
        guestSession: null,
      },
    ],
    suspended: [{ vm: wvm(), since: null, stateBytes: 1000, folderBytes: 5000 }],
    chains: [{ vm: wvm(), snapshots: 5, depth: 5, snapshotBytes: 300, oldest: null, why: [] }],
    orphans: [{ path: "D:\\VMs\\old", kind: "disks", bytes: 70, files: 1, newest: null, examples: [] }],
    searched: [],
    skipped: [],
    problems: [],
    notes: [],
    readAt: "",
  };
  assert.deepEqual(wasteTotals(report), { diskBytes: 1370, memoryMb: 4096, rows: 4 });
});

function nic(connection: string, networkName: string | null = null): VirtualNic {
  return {
    slot: "nic1",
    connection,
    model: null,
    mac: null,
    connected: true,
    networkName,
    connectedNow: null,
    staticMac: false,
  };
}

const NETWORKS: HostNetworksReport = {
  vmware: {
    available: true,
    problem: null,
    forwardsRefused: null,
    networks: [
      {
        network: { index: 1, name: "vmnet1", kind: "hostOnly", dhcp: true, subnet: "192.0.2.0", mask: "255.255.255.0" },
        target: { kind: "network", hypervisor: "vmware", name: "vmnet1" },
        vms: [],
        forwards: [],
        forwardsProblem: null,
      },
      {
        network: { index: 8, name: "vmnet8", kind: "nat", dhcp: false, subnet: "198.51.100.0", mask: "255.255.255.0" },
        target: { kind: "network", hypervisor: "vmware", name: "vmnet8" },
        vms: [],
        forwards: [{ protocol: "tcp", hostPort: 8022, guestIp: "198.51.100.10", guestPort: 22, description: null }],
        forwardsProblem: null,
      },
      {
        network: { index: 5, name: "vmnet5", kind: { other: "" }, dhcp: null, subnet: null, mask: null },
        target: { kind: "network", hypervisor: "vmware", name: "vmnet5" },
        vms: [],
        forwards: [],
        forwardsProblem: null,
      },
    ],
  },
  virtualbox: {
    available: true,
    problem: null,
    hostOnly: [
      {
        iface: {
          name: "VirtualBox Host-Only Ethernet Adapter",
          ip: "203.0.113.1",
          mask: "255.255.255.0",
          dhcp: false,
          status: "Down",
        },
        vms: [],
      },
    ],
    natNetworks: [
      {
        network: {
          name: "lab-net",
          enabled: false,
          network: "10.0.5.0/24",
          gateway: null,
          dhcp: true,
          ipv6: false,
          forwards: [],
        },
        target: { kind: "network", hypervisor: "virtualbox", name: "lab-net" },
        vms: [],
      },
    ],
    other: [],
    vmNat: [],
  },
  staleVms: [],
  readAt: "2026-10-26T10:00:00Z",
};

test("host networks are keyed like the map's adapters, named and described, and open the networks view", () => {
  const list = topologyHostNetworks(NETWORKS);
  const byKey = new Map(list.map((n) => [n.key, n]));
  // The keys the map gives the adapters on these networks.
  const keys = [
    networkKey("vmware", nic("hostonly"))?.key,
    networkKey("vmware", nic("nat"))?.key,
    networkKey("vmware", nic("custom (VMnet5)", "vmnet5"))?.key,
    networkKey("virtualbox", nic("hostonly", "VirtualBox Host-Only Ethernet Adapter"))?.key,
    networkKey("virtualbox", nic("natnetwork", "lab-net"))?.key,
  ];
  assert.deepEqual(
    keys.map((k) => byKey.has(k ?? "")),
    [true, true, true, true, true],
  );
  assert.equal(list.length, 5);
  assert.deepEqual(byKey.get("vmware:vmnet1"), {
    key: "vmware:vmnet1",
    label: "Host-only (VMnet1)",
    detail: "Workstation · 192.0.2.0/24 · DHCP",
    link: { kind: "hostNetworks" },
  });
  assert.equal(byKey.get("vmware:vmnet8")?.detail, "Workstation · 198.51.100.0/24 · 1 port forward");
  assert.equal(byKey.get("vmware:vmnet5")?.label, "VMnet5");
  assert.equal(byKey.get("vmware:vmnet5")?.detail, "Workstation");
  const hostOnly = byKey.get("virtualbox:hostonly:VirtualBox Host-Only Ethernet Adapter");
  assert.equal(hostOnly?.label, "Host-only: VirtualBox Host-Only Ethernet Adapter");
  assert.equal(hostOnly?.detail, "VirtualBox · 203.0.113.1/24 · down");
  assert.equal(byKey.get("virtualbox:natnetwork:lab-net")?.detail, "VirtualBox · 10.0.5.0/24 · DHCP · off");
});

test("a mask's prefix length, and none for what isn't a mask", () => {
  assert.equal(prefixLength("255.255.255.0"), 24);
  assert.equal(prefixLength("255.255.240.0"), 20);
  assert.equal(prefixLength("255.255.255.255"), 32);
  assert.equal(prefixLength("0.0.0.0"), 0);
  assert.equal(prefixLength("255.0.255.0"), null);
  assert.equal(prefixLength("255.255.255"), null);
  assert.equal(prefixLength("255.255.256.0"), null);
  assert.equal(prefixLength(null), null);
});
