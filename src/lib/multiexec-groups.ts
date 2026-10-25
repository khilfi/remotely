// QL-19 saved MultiExec groups, the Terminal page's side: which open tabs a group selects, which of its sessions need
// a new tab ("Open group" reuses a tab already open for a session rather than opening a duplicate), what "Save picked
// tabs as a group" saves, and the group editor's checks and edits. Pure functions over what the page knows of each tab,
// tested in multiexec-groups.test.ts. The core checks every edit again (crates/core/src/multiexec_groups.rs).

import type { GroupMember, MultiExecGroup } from "./api.ts";

/** As the core: a name of 1 to 60 characters, 1 to 100 sessions a group. */
export const GROUP_NAME_MAX = 60;
export const GROUP_MEMBERS_MAX = 100;

/** What a group needs to know of an open tab. */
export interface GroupTab {
  key: string;
  /** The saved session its panes reach; null for a quick connection that was not saved. */
  sessionId: string | null;
}

/** The tabs a group picks, and its sessions with no tab open. */
export interface GroupTabs {
  /** One tab per session of the group that is open (the leftmost, when a session is open in several), in tab order. */
  keys: string[];
  /** Members with no open tab, in the group's order. */
  missing: GroupMember[];
}

/** Select group (and the first half of Open group): the open tabs of the group's sessions. */
export function groupTabs(group: Pick<MultiExecGroup, "members">, tabs: GroupTab[]): GroupTabs {
  const members = new Set(group.members.map((m) => m.sessionId));
  const taken = new Set<string>();
  const keys: string[] = [];
  for (const tab of tabs) {
    if (tab.sessionId === null || !members.has(tab.sessionId) || taken.has(tab.sessionId)) continue;
    taken.add(tab.sessionId);
    keys.push(tab.key);
  }
  return { keys, missing: group.members.filter((m) => !taken.has(m.sessionId)) };
}

/** What "Save picked tabs as a group" saves: each saved session once, in tab order; quick connections left out. */
export function sessionsOfTabs(tabs: GroupTab[]): { sessionIds: string[]; quick: number } {
  const sessionIds: string[] = [];
  let quick = 0;
  for (const tab of tabs) {
    if (tab.sessionId === null) quick += 1;
    else if (!sessionIds.includes(tab.sessionId)) sessionIds.push(tab.sessionId);
  }
  return { sessionIds: sessionIds.slice(0, GROUP_MEMBERS_MAX), quick };
}

/** QL-08: why "Save picked tabs as a group" is disabled, or null. */
export function saveGroupReason(input: { tabs: GroupTab[]; readOnly: string | null }): string | null {
  if (input.readOnly) return input.readOnly;
  if (input.tabs.length === 0) return "Open a terminal first";
  if (input.tabs.every((t) => t.sessionId === null))
    return "The picked tabs are quick connections: save them as sessions first";
  return null;
}

/** "3 sessions, 2 open" for the Groups menu. */
export function groupSummary(group: Pick<MultiExecGroup, "members">, tabs: GroupTab[]): string {
  const total = group.members.length;
  if (total === 0) return "no sessions (deleted)";
  const open = total - groupTabs(group, tabs).missing.length;
  const sessions = total === 1 ? "1 session" : `${total} sessions`;
  if (open === 0) return `${sessions}, none open`;
  if (open === total) return `${sessions}, all open`;
  return `${sessions}, ${open} open`;
}

/** `web03, db01 and 2 more`, for "not open" notes. */
export function memberNames(members: GroupMember[], shown = 3): string {
  const names = members.slice(0, shown).map((m) => m.name);
  const more = members.length - names.length;
  return more > 0 ? `${names.join(", ")} and ${more} more` : names.join(", ");
}

/** The editor's check of a name before the core's: what is wrong with it, or null. */
export function groupNameProblem(name: string, groups: Pick<MultiExecGroup, "id" | "name">[], self: string | null) {
  const clean = name.trim();
  if (!clean) return "Give the group a name";
  if ([...clean].length > GROUP_NAME_MAX) return `At most ${GROUP_NAME_MAX} characters`;
  const lower = clean.toLowerCase();
  if (groups.some((g) => g.id !== self && g.name.toLowerCase() === lower))
    return `There is a group named '${clean}' already`;
  return null;
}

/** QL-08: why the editor's Save is disabled, or null. */
export function saveDraftReason(input: {
  name: string;
  sessionIds: string[];
  groups: Pick<MultiExecGroup, "id" | "name">[];
  self: string | null;
  readOnly: string | null;
  changed: boolean;
}): string | null {
  if (input.readOnly) return input.readOnly;
  const problem = groupNameProblem(input.name, input.groups, input.self);
  if (problem) return problem;
  if (input.sessionIds.length === 0) return "Pick at least one saved session";
  if (input.sessionIds.length > GROUP_MEMBERS_MAX) return `A group holds at most ${GROUP_MEMBERS_MAX} sessions`;
  if (!input.changed) return "Nothing changed";
  return null;
}

/** Adds a session at the end, or takes it out. */
export function toggleMember(ids: string[], id: string): string[] {
  return ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id];
}

/** Moves the member at `index` one place up (-1) or down (+1); at an end it stays. */
export function moveMember(ids: string[], index: number, by: -1 | 1): string[] {
  const to = index + by;
  if (index < 0 || index >= ids.length || to < 0 || to >= ids.length) return ids;
  const next = [...ids];
  [next[index], next[to]] = [next[to], next[index]];
  return next;
}

/** Whether a draft differs from the group as saved. */
export function draftChanged(
  draft: { name: string; sessionIds: string[] },
  saved: Pick<MultiExecGroup, "name" | "members"> | null,
): boolean {
  if (!saved) return true;
  const ids = saved.members.map((m) => m.sessionId);
  return (
    draft.name.trim() !== saved.name ||
    draft.sessionIds.length !== ids.length ||
    draft.sessionIds.some((id, i) => id !== ids[i])
  );
}
