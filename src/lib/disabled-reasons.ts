// QL-08: every disabled action button says why it is disabled. The reasons the Terminal page and its panels show,
// as pure functions (tested in disabled-reasons.test.ts); `null` means the action is available. Shown in a tooltip
// on the button (WhyDisabled.tsx) or under a disabled menu item.

import type { ApprovalStep } from "./api.ts";

/** FD-03: an action that changes something, while presenting with the read-only lock on (the core refuses it too). */
export const READ_ONLY_REASON = "Read-only while presenting: turn the read-only lock off first (Presenting menu)";

/** BX-03 Compare: the Run button. */
export function compareRunReason(input: {
  /** Saved sessions on this computer. */
  savedSessions: number;
  /** Tabs and tree sessions picked. */
  picked: number;
  /** The hosts the picks reach (saved sessions), with their protection. */
  hosts: { protected: boolean }[];
  /** Picked tabs that are quick connections (not saved), which Compare can't reach. */
  unsavedTabs: number;
  script: string;
  timeoutOk: boolean;
  submitting: boolean;
  /** FD-03: the read-only lock applies. */
  readOnly?: boolean;
}): string | null {
  if (input.readOnly) return READ_ONLY_REASON;
  if (input.savedSessions === 0) return "No saved sessions on this computer: add or import sessions first";
  if (input.picked === 0) return "Pick tabs, or sessions in the tree, to run on";
  if (input.hosts.length === 0) {
    return input.unsavedTabs > 0
      ? "The picked tabs are quick connections: save them as sessions first"
      : "None of the picks is a saved session it can run on";
  }
  if (input.hosts.every((h) => h.protected)) return "All selected targets are protected";
  if (!input.script.trim()) return "Type a command first";
  if (!input.timeoutOk) return "The time limit must be a whole number of seconds, 1 to 86400 (or empty)";
  if (input.submitting) return "Starting the run…";
  return null;
}

/** SS-10: the MultiExec switch. */
export function multiExecReason(input: { tabs: number; on: boolean; readOnly?: boolean }): string | null {
  if (input.on) return null;
  if (input.readOnly) return READ_ONLY_REASON;
  if (input.tabs === 0) return "Open a terminal first: MultiExec types into open tabs";
  return null;
}

/** SS-10: when MultiExec is on, what the bar says when no picked terminal gets the keys. */
export function multiExecIdleReason(targets: { receives: boolean; reason: string | null }[]): string | null {
  if (targets.length === 0) return "No tab is picked: Ctrl+click tabs, or pick them by folder or label";
  if (targets.every((t) => !t.receives)) {
    const reasons = [...new Set(targets.map((t) => t.reason).filter(Boolean))];
    return reasons.length === 1 && reasons[0]?.startsWith("protected")
      ? "All selected targets are protected"
      : `No picked tab receives keys now: ${reasons.join("; ")}`;
  }
  return null;
}

/** The split buttons. */
export function splitReason(input: { panes: number; maxPanes: number; connectedOnce: boolean }): string | null {
  if (input.panes >= input.maxPanes)
    return `A tab holds at most ${input.maxPanes} panes: open the session in another tab`;
  if (!input.connectedOnce) return "This terminal never connected, so there is nothing to split";
  return null;
}

/** AP-03, AP-06: the approval dialog's Approve button, from the steps the policy engine asked for. */
export function approveReason(input: {
  steps: ApprovalStep[];
  typedCount: string;
  reason: string;
  password: string;
  busy: boolean;
}): string | null {
  for (const step of input.steps) {
    if (step.step === "typeTargetCount" && Number(input.typedCount) !== step.expected)
      return `Type the number of targets (${step.expected}) first`;
    if (step.step === "reason" && input.reason.trim() === "") return "Give a reason or ticket number first";
    if (step.step === "vaultReauth" && input.password === "") return "Type the vault password first";
  }
  if (input.busy) return "Checking the answers…";
  return null;
}

/** BX-03: comparing two groups' outputs. */
export function diffReason(groups: number): string | null {
  return groups < 2 ? "Only one group so far: every host that finished gave the same answer" : null;
}

/** The menu items and buttons that act on a terminal's connection. */
export function connectedReason(input: { open: boolean; connected: boolean }): string | null {
  if (!input.open) return "No terminal is open";
  if (!input.connected) return "This terminal has not connected yet";
  return null;
}

/** SS-08: uploading into a terminal (the toolbar's button, the drawer's, a drop). */
export function uploadReason(input: { open: boolean; connected: boolean; readOnly?: boolean }): string | null {
  if (input.readOnly) return READ_ONLY_REASON;
  if (!input.open) return "Open a terminal first: files are uploaded through it";
  if (!input.connected) return "This terminal is not connected, so nothing can be uploaded through it";
  return null;
}

/** SS-08: the drawer's Download buttons, for the picked entries. */
export function downloadReason(input: { connected: boolean; picked: { kind: "file" | "folder" | "other" }[] }) {
  if (!input.connected) return "This terminal is not connected, so its files can't be reached";
  if (input.picked.length === 0) return "Tick the files to download first";
  if (input.picked.some((e) => e.kind === "folder")) return "Folders aren't downloaded: open the folder and pick files";
  if (input.picked.some((e) => e.kind === "other")) return "Only regular files can be downloaded";
  return null;
}
