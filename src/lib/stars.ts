// QL-26 stars and recents in the window, as pure functions (tested in stars.test.ts). A star marks a session, a VM or a
// command so it comes first in the session tree, the VMs list and Ctrl+K; the window calls them "starred" (BX-08's
// saved commands are its "favourites"). Recents are the 20 sessions, VMs and pages opened last, newest first.

import type { Recent, RecentKind, Star, StarKind } from "./comfort-api.ts";
import type { SearchItem } from "./search.ts";

/** The stars, by kind, as sets of keys (VM keys without letter case, as the core matches them). */
export interface StarSets {
  session: Set<string>;
  vm: Set<string>;
  command: Set<string>;
}

export function starSets(stars: readonly Star[]): StarSets {
  const sets: StarSets = { session: new Set(), vm: new Set(), command: new Set() };
  for (const s of stars) sets[s.kind].add(starKey(s.kind, s.key));
  return sets;
}

/** The key as the sets hold it: a VM's path in lower case. */
export function starKey(kind: StarKind, key: string): string {
  return kind === "vm" ? key.toLowerCase() : key;
}

export function isStarred(sets: StarSets, kind: StarKind, key: string): boolean {
  return sets[kind].has(starKey(kind, key));
}

/** A saved command's key (`favourite:<id>`), and a built-in one's (`library:<id>`), as search ids use them. */
export function commandStarKey(source: "favourite" | "library", id: string): string {
  return `${source}:${id}`;
}

/** Starred items first, each part in the order given. */
export function starredFirst<T>(items: readonly T[], starred: (item: T) => boolean): T[] {
  const first: T[] = [];
  const rest: T[] = [];
  for (const item of items) (starred(item) ? first : rest).push(item);
  return [...first, ...rest];
}

/** The recent items of the kinds asked for, newest first, at most `limit`. */
export function recentOf(recents: readonly Recent[], kinds: readonly RecentKind[], limit = 20): Recent[] {
  return recents.filter((r) => kinds.includes(r.kind)).slice(0, limit);
}

/** What the star button says. */
export function starLabel(starred: boolean, name: string): string {
  return starred ? `Unstar ${name}` : `Star ${name}`;
}

/** The most a star adds to a search result's score: a starred item comes first among equal matches, never ahead of a
 * better one (search.ts caps an item's boost). */
export const STAR_BOOST = 4;

/** Search items with a boost for the starred ones (`vm:<key>`, `session:<id>`, `favourite:<id>`, `library:<id>`). */
export function boostStarred(items: readonly SearchItem[], sets: StarSets): SearchItem[] {
  return items.map((item) => {
    const colon = item.id.indexOf(":");
    const prefix = item.id.slice(0, colon);
    const rest = item.id.slice(colon + 1);
    const starred =
      (prefix === "vm" && isStarred(sets, "vm", rest)) ||
      (prefix === "session" && isStarred(sets, "session", rest)) ||
      ((prefix === "favourite" || prefix === "library") && isStarred(sets, "command", item.id));
    return starred ? { ...item, boost: (item.boost ?? 0) + STAR_BOOST } : item;
  });
}
