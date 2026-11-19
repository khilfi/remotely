// UX-16, BX-01 (0.9.0 H2): one host picker for every bulk job, Compare hosts included. What the picker's summary line
// says ("12 hosts: 6 picked tabs, folder 'Web', tag 'db'"), which tabs Compare hosts runs on, and the picks a page's
// selection becomes ("Run a command on these…" on the Sessions and VMs pages). Pure, tested in bulk-picks.test.ts; the
// core resolves the picks into hosts (crates/core/src/bulk.rs, `bulk_targets`).

import type { MultiExecGroup, SavedFilter, SessionFolder, SessionRecord, TargetPicks, VmRecord } from "./api.ts";
import { flattenFolders, subtree } from "./folders.ts";
import { plural } from "./format.ts";

/** The picks `BulkTargetPicker` edits; tabs are picked on the Terminal page's tab row. */
export type PickKind = "sessionIds" | "vmPaths" | "tags" | "filterIds" | "groupIds";
export const PICK_KINDS: readonly PickKind[] = ["sessionIds", "vmPaths", "tags", "filterIds", "groupIds"];

/** Parts named in the summary before "and N more". */
export const SUMMARY_PARTS = 4;

/** Anything picked in the picker (sessions, VMs, tags, filters or groups; tabs not counted). */
export function anyPicks(picks: TargetPicks): boolean {
  return PICK_KINDS.some((k) => (picks[k] ?? []).length > 0);
}

/** How many things are picked, tabs included. */
export function pickCount(picks: TargetPicks): number {
  return (picks.terminalIds ?? []).length + PICK_KINDS.reduce((n, k) => n + (picks[k] ?? []).length, 0);
}

/** The picker's picks with `kind`'s `value` added or taken out (each once). */
export function togglePick(picks: TargetPicks, kind: PickKind, value: string, on: boolean): TargetPicks {
  const rest = (picks[kind] ?? []).filter((v) => v !== value);
  return { ...picks, [kind]: on ? [...rest, value] : rest };
}

/** The tabs a summary counts: picked ones, or the current tab when nothing else is picked. */
export interface TabsPart {
  count: number;
  /** The one tab is the current tab, used because nothing was picked. */
  current: boolean;
}

/** What the summary names things by. */
export interface SummaryNames {
  /** Saved sessions (those the job takes), for names and whole folders. */
  sessions: readonly Pick<SessionRecord, "id" | "name" | "folderId">[];
  folders: readonly SessionFolder[];
  vms: readonly Pick<VmRecord, "vmxPath" | "displayName">[];
  filters: readonly Pick<SavedFilter, "id" | "name">[];
  groups: readonly Pick<MultiExecGroup, "id" | "name">[];
}

/**
 * Picked sessions as whole folders where every session under a folder is picked (the tree's Ctrl+click on a folder
 * picks them so), outermost first, then the rest by name or count.
 */
function sessionParts(ids: readonly string[], names: SummaryNames): string[] {
  if (ids.length === 0) return [];
  const picked = new Set(ids);
  const left = new Set(ids);
  const parts: string[] = [];
  for (const { folder } of flattenFolders([...names.folders])) {
    const under = subtree([...names.folders], folder.id);
    const inside = names.sessions.filter((s) => s.folderId !== null && under.has(s.folderId));
    if (inside.length === 0 || !inside.every((s) => picked.has(s.id))) continue;
    if (!inside.some((s) => left.has(s.id))) continue; // a folder above it is named already
    parts.push(`folder '${folder.name}'`);
    for (const s of inside) left.delete(s.id);
  }
  if (left.size === 1) {
    const [id] = left;
    const session = names.sessions.find((s) => s.id === id);
    parts.push(session ? `session '${session.name}'` : "1 session");
  } else if (left.size > 1) {
    parts.push(plural(left.size, "session"));
  }
  return parts;
}

function named<T>(ids: readonly string[], list: readonly T[], key: (t: T) => string, name: (t: T) => string) {
  return ids.map((id) => {
    const found = list.find((t) => key(t) === id);
    return found ? name(found) : null;
  });
}

/** Each pick in words, in the order the summary names them: tabs, sessions, VMs, tags, filters, groups. */
export function picksParts(picks: TargetPicks, tabs: TabsPart, names: SummaryNames): string[] {
  const parts: string[] = [];
  if (tabs.count > 0) parts.push(tabs.current ? "this tab" : plural(tabs.count, "picked tab"));
  parts.push(...sessionParts(picks.sessionIds ?? [], names));
  const vms = picks.vmPaths ?? [];
  if (vms.length > 2) parts.push(plural(vms.length, "VM"));
  else
    parts.push(
      ...named(
        vms.map((p) => p.toLowerCase()),
        names.vms,
        (v) => v.vmxPath.toLowerCase(),
        (v) => `VM '${v.displayName}'`,
      ).map((n) => n ?? "1 VM"),
    );
  parts.push(...(picks.tags ?? []).map((t) => `tag '${t}'`));
  parts.push(
    ...named(
      picks.filterIds ?? [],
      names.filters,
      (f) => f.id,
      (f) => `filter '${f.name}'`,
    ).map((n) => n ?? "a saved filter (deleted)"),
  );
  parts.push(
    ...named(
      picks.groupIds ?? [],
      names.groups,
      (g) => g.id,
      (g) => `group '${g.name}'`,
    ).map((n) => n ?? "a group (deleted)"),
  );
  return parts;
}

/** "12 hosts: 6 picked tabs, folder 'Web', tag 'db'"; past SUMMARY_PARTS, "and N more". */
export function picksSummary(hosts: number, parts: readonly string[]): string {
  if (parts.length === 0) return "Nothing picked";
  const shown =
    parts.length > SUMMARY_PARTS
      ? `${parts.slice(0, SUMMARY_PARTS).join(", ")} and ${parts.length - SUMMARY_PARTS} more`
      : parts.join(", ");
  return `${plural(hosts, "host")}: ${shown}`;
}

/**
 * The tabs Compare hosts runs on: Type in all tabs' picked tabs while it is on, else the Ctrl+clicked ones, else the
 * current tab, but only while nothing else is picked (so "Run a command on these…" runs on exactly those picks).
 */
export function compareTabKeys(input: {
  typing: boolean;
  /** The picked tabs, left to right. */
  picked: readonly string[];
  current: string | null;
  /** Something is picked in the tree or the picker. */
  otherPicks: boolean;
}): { keys: string[]; current: boolean } {
  if (input.typing || input.picked.length > 0) return { keys: [...input.picked], current: false };
  if (input.current && !input.otherPicks) return { keys: [input.current], current: true };
  return { keys: [], current: false };
}

/** BX-01: what "Run a command on these…" opens Compare hosts with: the Sessions page's or the VMs page's selection. */
export function selectionPicks(from: { sessionIds?: readonly string[]; vmPaths?: readonly string[] }): TargetPicks {
  return { sessionIds: [...(from.sessionIds ?? [])], vmPaths: [...(from.vmPaths ?? [])] };
}
