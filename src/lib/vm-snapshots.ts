// QL-14: what the Virtual machines page decides about snapshots, as pure functions (tested in vm-snapshots.test.ts).
// A VM's snapshot tree (VM-04, read from its .vmsd) loads when its details open, and the selected VMs' trees when the
// selection's Snapshots menu opens; these helpers work on whatever has been read. QL-08: every reason says why an
// action is off; `null` means it is available.

import type { ApprovalStep, SnapshotNode, Tier, VmSnapshots } from "./api.ts";

/** Where a VM's details panel opens: its details, or its snapshot tree and actions. */
export type VmView = "details" | "snapshots";

/** AP-04: what a protected VM's actions say. */
export const PROTECTED_REASON = "Protected: actions skip this VM until it is unprotected";

const BUSY_REASON = "Sending the last action…";

/** vmrun reads '/' in a snapshot name as a path to a child snapshot, so it cannot name those. */
export function unreachableByName(node: SnapshotNode) {
  return node.name.includes("/");
}

/** The name to give vmrun: the plain name, or the path form when this VM has two snapshots with that name. */
export function snapshotArg(vm: VmSnapshots, node: SnapshotNode) {
  const twins = vm.snapshots.filter((s) => s.name === node.name).length;
  return twins > 1 ? node.path : node.name;
}

/** VM-04: why one VM's Take snapshot is off. */
export function takeReason(input: {
  /** FD-03: the read-only lock's reason, or null. */
  readOnly: string | null;
  protected: boolean;
  /** The tree is still being read (the dialog checks the name against it). */
  loading: boolean;
  busy: boolean;
}): string | null {
  if (input.readOnly) return input.readOnly;
  if (input.protected) return PROTECTED_REASON;
  if (input.loading) return "Reading the VM's snapshots…";
  if (input.busy) return BUSY_REASON;
  return null;
}

/** VM-04: why reverting to or deleting one snapshot is off. */
export function snapshotActionReason(input: {
  node: SnapshotNode;
  readOnly: string | null;
  protected: boolean;
  busy: boolean;
}): string | null {
  if (input.readOnly) return input.readOnly;
  if (input.protected) return PROTECTED_REASON;
  if (unreachableByName(input.node))
    return "vmrun reads '/' in a name as a path, so manage this snapshot in Workstation";
  if (input.busy) return BUSY_REASON;
  return null;
}

/**
 * What the policy engine's preview of an action on this VM means, in a few words: its tier, whether it asks first and
 * (VM-05) whether it offers a safety snapshot, ticked or not. The approval dialog asks the actual questions.
 */
export function approvalHint(preview: { tier: Tier; steps: ApprovalStep[] }) {
  const tier = preview.tier.charAt(0).toUpperCase() + preview.tier.slice(1);
  if (preview.steps.length === 0) return `${tier}: runs without asking`;
  const safety = preview.steps.find((s) => s.step === "safetySnapshot");
  if (!safety) return `${tier}: asks for approval first`;
  const ticked = safety.step === "safetySnapshot" && safety.defaultOn ? "ticked" : "not ticked";
  return `${tier}: asks for approval and offers a safety snapshot first (${ticked})`;
}

/** Counts over the trees read so far, for the selection's Snapshots menu. */
export interface SnapshotSummary {
  vms: number;
  withSnapshots: number;
  snapshots: number;
  old: number;
  safety: number;
}

export function summarize(trees: VmSnapshots[]): SnapshotSummary {
  return {
    vms: trees.length,
    withSnapshots: trees.filter((t) => t.snapshots.length > 0).length,
    snapshots: trees.reduce((n, t) => n + t.snapshots.length, 0),
    old: trees.reduce((n, t) => n + t.oldCount, 0),
    safety: trees.reduce((n, t) => n + t.safetyCount, 0),
  };
}

/** The selection's bulk snapshot actions (VM-04): why each is off. */
export interface BulkSnapshotReasons {
  take: string | null;
  revert: string | null;
  delete: string | null;
}

export function bulkSnapshotReasons(input: {
  readOnly: string | null;
  /** The selected VMs, with their protection (AP-04). */
  selected: { protected: boolean }[];
  /** Their trees; null while they are read. */
  trees: VmSnapshots[] | null;
  busy: boolean;
}): BulkSnapshotReasons {
  const every = (reason: string | null) => ({ take: reason, revert: reason, delete: reason });
  // Take works on any VM; revert and delete pick from its snapshots.
  const pickers = (reason: string) => ({ take: null, revert: reason, delete: reason });
  if (input.readOnly) return every(input.readOnly);
  if (input.selected.length === 0) return every("Select VMs first");
  if (input.selected.every((v) => v.protected)) return every("All selected VMs are protected");
  if (input.busy) return every(BUSY_REASON);
  // Take waits too: its dialog leaves out the VMs that already have the name.
  if (input.trees === null) return every("Reading the selected VMs' snapshots…");
  const open = input.trees.filter((t) => !t.protected);
  if (open.every((t) => t.snapshots.length === 0)) {
    return pickers(
      input.selected.length === 1
        ? "The selected VM has no snapshots"
        : `None of the ${input.selected.length} selected VMs has a snapshot`,
    );
  }
  if (open.every((t) => t.snapshots.every(unreachableByName))) {
    return pickers("Their snapshots have '/' in the name, which vmrun can't name: manage them in Workstation");
  }
  return every(null);
}

/** Select menu (VM-02 with VM-04): which VMs to select by their snapshots. */
export type SnapshotMatch = { kind: "old" } | { kind: "safety" } | { kind: "named"; text: string };

export function vmsMatching(trees: VmSnapshots[], match: SnapshotMatch): string[] {
  const needle = match.kind === "named" ? match.text.trim().toLowerCase() : "";
  return trees
    .filter((t) => {
      switch (match.kind) {
        case "old":
          return t.oldCount > 0;
        case "safety":
          return t.safetyCount > 0;
        case "named":
          return needle !== "" && t.snapshots.some((s) => s.name.toLowerCase().includes(needle));
      }
    })
    .map((t) => t.vmxPath);
}

/** What the Select menu says when no VM shown matched. */
export function noMatchText(match: SnapshotMatch, shown: number, oldAfterDays: number) {
  const what =
    match.kind === "old"
      ? `snapshots older than ${oldAfterDays} days`
      : match.kind === "safety"
        ? "safety snapshots"
        : `a snapshot named like "${match.text.trim()}"`;
  return shown === 1 ? `The VM shown has no ${what.replace(/^a /, "")}` : `None of the ${shown} VMs shown has ${what}`;
}
