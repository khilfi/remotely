// FD-02 customer workspaces: the switcher's texts, the editor's checks (the core checks again), what a switch closes,
// and the VMs page's reasons (QL-08) for adding and taking out VMs. Pure functions, tested in workspaces.test.ts.

import type { Environment } from "@/lib/api";

/** The colours a workspace can have: the core's `workspaces::COLORS`. */
export const WORKSPACE_COLORS = ["slate", "blue", "green", "amber", "red", "violet", "pink", "teal"] as const;
export type WorkspaceColor = (typeof WORKSPACE_COLORS)[number];

/** A workspace's name is 1 to this many characters (the core's `MAX_NAME_CHARS`). */
export const MAX_WORKSPACE_NAME = 60;

/** The dot in the switcher and its menu: Tailwind's palette, readable in both themes. */
export const COLOR_CLASS: Record<WorkspaceColor, string> = {
  slate: "bg-slate-500",
  blue: "bg-blue-500",
  green: "bg-green-500",
  amber: "bg-amber-500",
  red: "bg-red-500",
  violet: "bg-violet-500",
  pink: "bg-pink-500",
  teal: "bg-teal-500",
};

export const COLOR_LABEL: Record<WorkspaceColor, string> = {
  slate: "Slate",
  blue: "Blue",
  green: "Green",
  amber: "Amber",
  red: "Red",
  violet: "Violet",
  pink: "Pink",
  teal: "Teal",
};

/** The class for a colour the core sent, or slate's for one this UI doesn't know. */
export function colorClass(color: string): string {
  return (COLOR_CLASS as Record<string, string>)[color] ?? COLOR_CLASS.slate;
}

interface Named {
  id: string;
  name: string;
}

/** Why `name` can't be a workspace's name, or null when it can. `others` are the user's workspaces, archived too. */
export function nameProblem(name: string, others: readonly Named[], exceptId?: string): string | null {
  const trimmed = name.trim();
  if (trimmed === "") return "Give the workspace a name.";
  if ([...trimmed].length > MAX_WORKSPACE_NAME) return `At most ${MAX_WORKSPACE_NAME} characters.`;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f​-‏‪-‮⁠-⁤﻿]/.test(trimmed)) {
    return "One line of plain text.";
  }
  const lower = trimmed.toLowerCase();
  if (others.some((w) => w.id !== exceptId && w.name.toLowerCase() === lower)) {
    return "Another workspace has that name (archived ones count).";
  }
  return null;
}

interface Listed extends Named {
  archived: boolean;
  current: boolean;
}

/** The switcher's list: the shown one first, then the other active ones by name; archived ones only in Manage. */
export function switchable<T extends Listed>(workspaces: readonly T[]): T[] {
  return workspaces
    .filter((w) => !w.archived)
    .sort((a, b) => Number(b.current) - Number(a.current) || a.name.localeCompare(b.name));
}

/** What a switch closes, for its confirm. */
export interface SwitchCounts {
  openJobs: number;
  terminals: number;
  multiexec: boolean;
  approvals: number;
}

function plural(n: number, one: string, many: string) {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/** Why the switch can't happen now, or null. */
export function switchRefusal(p: SwitchCounts): string | null {
  if (p.openJobs === 0) return null;
  const jobs = p.openJobs === 1 ? "A job started here is" : `${p.openJobs} jobs started here are`;
  return `${jobs} still running. Wait for ${p.openJobs === 1 ? "it" : "them"} to finish, or cancel ${
    p.openJobs === 1 ? "it" : "them"
  } in Activity, then switch. Scheduled runs don't count: they go on in their own workspace.`;
}

/** What closes, one line each; empty when nothing is open. */
export function switchCloses(p: SwitchCounts): string[] {
  const out: string[] = [];
  if (p.terminals > 0) {
    out.push(`${plural(p.terminals, "terminal closes", "terminals close")}, with their tunnels, logs and transfers.`);
  }
  if (p.multiexec) out.push("MultiExec stops.");
  if (p.approvals > 0) out.push(`${plural(p.approvals, "approval", "approvals")} waiting for an answer: cancelled.`);
  return out;
}

/** Said in every switch's confirm: what a workspace keeps to itself and what goes on. */
export const SWITCH_NOTE =
  "The dashboard's connections close and the window loads the other workspace. Schedules of every workspace keep running, each in its own.";

/** QL-08: why VMs can't be taken out of this workspace, or null. */
export function releaseReason(
  vms: readonly { displayName: string; protected: boolean; environment: Environment }[],
  activeWorkspaces: number,
): string | null {
  if (vms.length === 0) return "Select the VMs to take out first.";
  if (activeWorkspaces < 2) return "With one workspace, every VM is in it. Make another workspace first.";
  const locked = vms.find((v) => v.protected);
  if (locked) return `'${locked.displayName}' is protected: unprotect it first.`;
  const prod = vms.find((v) => v.environment === "prod");
  if (prod) return `'${prod.displayName}' is labelled Prod: change its label first.`;
  return null;
}

/** QL-08: why the Unassigned view's selection can't be added, or null. */
export function claimReason(selected: number, readOnly: string | null): string | null {
  if (readOnly) return readOnly;
  if (selected === 0) return "Select the VMs to add first.";
  return null;
}
