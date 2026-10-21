/// <reference types="node" />
// QL-14 (VM-04, AP-04, QL-08): the snapshot decisions on the Virtual machines page. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { SnapshotNode, VmSnapshots } from "./api.ts";
import { READ_ONLY_REASON } from "./disabled-reasons.ts";
import {
  approvalHint,
  bulkSnapshotReasons,
  noMatchText,
  PROTECTED_REASON,
  snapshotActionReason,
  snapshotArg,
  summarize,
  takeReason,
  vmsMatching,
} from "./vm-snapshots.ts";

function node(uid: number, name: string, extra: Partial<SnapshotNode> = {}): SnapshotNode {
  return {
    uid,
    parentUid: null,
    name,
    path: name,
    description: null,
    createdAt: "2026-10-01T09:00:00Z",
    ageDays: 20,
    depth: 0,
    old: false,
    safety: false,
    current: false,
    ...extra,
  };
}

function vm(name: string, snapshots: SnapshotNode[], extra: Partial<VmSnapshots> = {}): VmSnapshots {
  return {
    vmxPath: `D:\\VMs\\${name}\\${name}.vmx`,
    displayName: name,
    powerState: "not_running",
    environment: "none",
    protected: false,
    snapshots,
    oldCount: snapshots.filter((s) => s.old).length,
    safetyCount: snapshots.filter((s) => s.safety).length,
    error: null,
    ...extra,
  };
}

test("a snapshot is named by its path only when the VM has two with that name", () => {
  const base = node(1, "base");
  const child = node(2, "clean", { parentUid: 1, path: "base/clean", depth: 1 });
  const other = node(3, "clean", { path: "clean" });
  assert.equal(snapshotArg(vm("web01", [base, child]), child), "clean");
  assert.equal(snapshotArg(vm("web01", [base, child, other]), child), "base/clean");
  assert.equal(snapshotArg(vm("web01", [base, child, other]), other), "clean");
});

test("revert and delete on one snapshot say why they are off", () => {
  const ok = { node: node(1, "base"), readOnly: null, protected: false, busy: false };
  assert.equal(snapshotActionReason(ok), null);
  assert.equal(snapshotActionReason({ ...ok, readOnly: READ_ONLY_REASON }), READ_ONLY_REASON);
  assert.equal(snapshotActionReason({ ...ok, protected: true }), PROTECTED_REASON);
  assert.match(snapshotActionReason({ ...ok, node: node(2, "a/b") }) ?? "", /manage this snapshot in Workstation/);
  assert.match(snapshotActionReason({ ...ok, busy: true }) ?? "", /Sending/);
  // The lock comes first: it is the one thing the user has to change before anything else works.
  assert.equal(snapshotActionReason({ ...ok, readOnly: READ_ONLY_REASON, protected: true }), READ_ONLY_REASON);
});

test("taking a snapshot of one VM waits for its tree", () => {
  const ok = { readOnly: null, protected: false, loading: false, busy: false };
  assert.equal(takeReason(ok), null);
  assert.match(takeReason({ ...ok, loading: true }) ?? "", /Reading/);
  assert.equal(takeReason({ ...ok, protected: true }), PROTECTED_REASON);
  assert.equal(takeReason({ ...ok, readOnly: READ_ONLY_REASON }), READ_ONLY_REASON);
});

test("the selection's snapshot actions follow what the selected VMs have", () => {
  const plain = { readOnly: null, busy: false };
  const one = [{ protected: false }];
  const two = [{ protected: false }, { protected: false }];

  const none = bulkSnapshotReasons({ ...plain, selected: [], trees: [] });
  assert.deepEqual(none, { take: "Select VMs first", revert: "Select VMs first", delete: "Select VMs first" });

  const reading = bulkSnapshotReasons({ ...plain, selected: two, trees: null });
  assert.match(reading.take ?? "", /Reading/, "the take dialog checks names against the trees");
  assert.match(reading.revert ?? "", /Reading/);

  const empty = bulkSnapshotReasons({ ...plain, selected: two, trees: [vm("a", []), vm("b", [])] });
  assert.equal(empty.take, null);
  assert.equal(empty.revert, "None of the 2 selected VMs has a snapshot");
  assert.equal(empty.delete, empty.revert);
  assert.equal(
    bulkSnapshotReasons({ ...plain, selected: one, trees: [vm("a", [])] }).revert,
    "The selected VM has no snapshots",
  );

  const slashes = bulkSnapshotReasons({ ...plain, selected: one, trees: [vm("a", [node(1, "x/y")])] });
  assert.match(slashes.revert ?? "", /'\/'/);

  const ready = bulkSnapshotReasons({ ...plain, selected: two, trees: [vm("a", [node(1, "base")]), vm("b", [])] });
  assert.deepEqual(ready, { take: null, revert: null, delete: null });
});

test("protected VMs and the read-only lock turn the selection's snapshot actions off", () => {
  const trees = [vm("a", [node(1, "base")], { protected: true })];
  const locked = bulkSnapshotReasons({
    readOnly: READ_ONLY_REASON,
    selected: [{ protected: false }],
    trees,
    busy: false,
  });
  assert.deepEqual(locked, { take: READ_ONLY_REASON, revert: READ_ONLY_REASON, delete: READ_ONLY_REASON });

  const guarded = bulkSnapshotReasons({ readOnly: null, selected: [{ protected: true }], trees, busy: false });
  assert.equal(guarded.take, "All selected VMs are protected");

  // A protected VM's snapshots don't count: the bus would skip it.
  const mixed = bulkSnapshotReasons({
    readOnly: null,
    selected: [{ protected: true }, { protected: false }],
    trees: [...trees, vm("b", [])],
    busy: false,
  });
  assert.equal(mixed.take, null);
  assert.equal(mixed.revert, "None of the 2 selected VMs has a snapshot");
});

test("the tier hint follows the policy engine's preview", () => {
  assert.equal(approvalHint({ tier: "low", steps: [] }), "Low: runs without asking");
  assert.equal(
    approvalHint({ tier: "high", steps: [{ step: "confirm" }, { step: "impactPreview" }] }),
    "High: asks for approval first",
  );
  assert.equal(
    approvalHint({ tier: "critical", steps: [{ step: "confirm" }, { step: "safetySnapshot", defaultOn: true }] }),
    "Critical: asks for approval and offers a safety snapshot first (ticked)",
  );
  assert.match(approvalHint({ tier: "high", steps: [{ step: "safetySnapshot", defaultOn: false }] }), /not ticked/);
});

test("summaries and the Select menu's snapshot picks", () => {
  const trees = [
    vm("web01", [node(1, "base", { old: true }), node(2, "Remotely safety before revert", { safety: true })]),
    vm("db01", [node(3, "Before upgrade")]),
    vm("app01", []),
  ];
  assert.deepEqual(summarize(trees), { vms: 3, withSnapshots: 2, snapshots: 3, old: 1, safety: 1 });
  assert.deepEqual(vmsMatching(trees, { kind: "old" }), [trees[0].vmxPath]);
  assert.deepEqual(vmsMatching(trees, { kind: "safety" }), [trees[0].vmxPath]);
  assert.deepEqual(vmsMatching(trees, { kind: "named", text: " UPGRADE " }), [trees[1].vmxPath]);
  assert.deepEqual(vmsMatching(trees, { kind: "named", text: "  " }), [], "an empty name matches nothing");

  assert.equal(noMatchText({ kind: "old" }, 4, 30), "None of the 4 VMs shown has snapshots older than 30 days");
  assert.equal(noMatchText({ kind: "safety" }, 1, 30), "The VM shown has no safety snapshots");
  assert.equal(noMatchText({ kind: "named", text: "base" }, 1, 30), 'The VM shown has no snapshot named like "base"');
});
