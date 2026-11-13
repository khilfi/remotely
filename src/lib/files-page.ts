// SS-14, BX-10 (0.8.0 G3): the Files page's pure helpers: each pane's view of its entries (hidden files, filter, sort),
// multiple selection with Shift and Ctrl, Back and Forward, this PC's breadcrumbs, the drag between the panes, a
// comparison's rows in words and which ones a sync takes by default. Tested in files-page.test.ts.

import type { DiffRow, LocalEntry, RowState, SyncDirection } from "./files-page-api.ts";

/** What both panes show of an entry. */
export interface PaneEntry {
  name: string;
  kind: "file" | "folder" | "other";
  link: boolean;
  size: number;
  modified: number | null;
}

export type PaneSort = "name" | "size" | "modified";

export interface PaneView {
  sort: PaneSort;
  dir: 1 | -1;
  hidden: boolean;
  filter: string;
}

export const DEFAULT_VIEW: PaneView = { sort: "name", dir: 1, hidden: false, filter: "" };

/** A host entry is hidden by its leading dot; one of this PC by its attribute too (`hidden`). */
export function isHidden(entry: PaneEntry & { hidden?: boolean }): boolean {
  return entry.hidden === true || entry.name.startsWith(".");
}

/** A filter as a test: words must all be in the name (no letter case), or a glob with `*` and `?`. */
export function filterTest(filter: string): (name: string) => boolean {
  const text = filter.trim().toLowerCase();
  if (!text) return () => true;
  if (/[*?]/.test(text)) {
    const pattern = text
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");
    const glob = new RegExp(`^${pattern}$`, "u");
    return (name) => glob.test(name.toLowerCase());
  }
  const words = text.split(/\s+/);
  return (name) => {
    const lower = name.toLowerCase();
    return words.every((w) => lower.includes(w));
  };
}

/** The entries a pane shows: hidden ones only when asked, the filter, folders first, then the sort. */
export function viewEntries<T extends PaneEntry & { hidden?: boolean }>(entries: readonly T[], view: PaneView): T[] {
  const test = filterTest(view.filter);
  const byName = (a: T, b: T) => a.name.localeCompare(b.name, undefined, { numeric: true });
  return entries
    .filter((e) => (view.hidden || !isHidden(e)) && test(e.name))
    .sort((a, b) => {
      const folders = Number(b.kind === "folder") - Number(a.kind === "folder");
      if (folders !== 0) return folders;
      let order = 0;
      if (view.sort === "size") order = a.size - b.size;
      else if (view.sort === "modified") order = (a.modified ?? 0) - (b.modified ?? 0);
      return (order || byName(a, b)) * view.dir;
    });
}

/** A click on a row: alone it picks only that row, Ctrl adds or takes it away, Shift picks the range from the anchor. */
export function clickPick(
  shown: readonly string[],
  picked: readonly string[],
  anchor: string | null,
  name: string,
  mods: { ctrl: boolean; shift: boolean },
): { picked: string[]; anchor: string } {
  if (mods.shift && anchor !== null && shown.includes(anchor)) {
    const [a, b] = [shown.indexOf(anchor), shown.indexOf(name)].sort((x, y) => x - y);
    const range = shown.slice(a, b + 1);
    const base = mods.ctrl ? picked.filter((p) => !range.includes(p)) : [];
    return { picked: [...base, ...range], anchor };
  }
  if (mods.ctrl) {
    return {
      picked: picked.includes(name) ? picked.filter((p) => p !== name) : [...picked, name],
      anchor: name,
    };
  }
  return { picked: [name], anchor: name };
}

/** A pane's Back and Forward: the places it showed, and where it is among them. */
export interface History<T> {
  items: T[];
  at: number;
}

export function emptyHistory<T>(): History<T> {
  return { items: [], at: -1 };
}

/** A new place: what was ahead of the current one is dropped; the same place twice is one entry. */
export function visit<T>(history: History<T>, item: T, same: (a: T, b: T) => boolean, max = 50): History<T> {
  const current = history.items[history.at];
  if (current !== undefined && same(current, item)) return history;
  const items = [...history.items.slice(0, history.at + 1), item].slice(-max);
  return { items, at: items.length - 1 };
}

export function canGo<T>(history: History<T>, step: -1 | 1): boolean {
  const next = history.at + step;
  return next >= 0 && next < history.items.length;
}

export function go<T>(history: History<T>, step: -1 | 1): { history: History<T>; item: T } | null {
  if (!canGo(history, step)) return null;
  const at = history.at + step;
  return { history: { ...history, at }, item: history.items[at] };
}

/** This PC's breadcrumbs: `This PC`, `C:\`, `C:\Users`, `C:\Users\alice`, each a path to type again. */
export function localCrumbs(path: string | null): { label: string; path: string | null }[] {
  const out: { label: string; path: string | null }[] = [{ label: "This PC", path: null }];
  if (!path) return out;
  const parts = path.split(/[\\/]+/).filter(Boolean);
  if (parts.length === 0) return out;
  let at = `${parts[0]}\\`;
  out.push({ label: parts[0], path: at });
  for (const part of parts.slice(1)) {
    at = at.endsWith("\\") ? `${at}${part}` : `${at}\\${part}`;
    out.push({ label: part, path: at });
  }
  return out;
}

/** What is dragged between the panes: files of a local listing, or of a host folder on a terminal. */
export type DragItems =
  | { from: "local"; listing: string; names: string[] }
  | { from: "host"; terminalId: string; folder: string; paths: string[]; asRoot: boolean };

/** Where a drop does something, and what (`null`: nothing happens there). */
export type DropAction =
  { kind: "upload"; folder: string } | { kind: "download" } | { kind: "move"; into: string } | null;

/** What dropping `items` on `target` does: local files on the host pane upload, host files on the local pane download,
 * host files on a folder of the same host move into it. A local folder is never a drop target: nothing on this PC is
 * changed but by a download into the pane's folder. */
export function dropAction(
  items: DragItems,
  target:
    | { pane: "local"; listing: string | null }
    | { pane: "host"; terminalId: string; folder: string; intoFolder?: string },
): DropAction {
  if (items.from === "local") {
    if (target.pane !== "host") return null;
    return { kind: "upload", folder: target.intoFolder ?? target.folder };
  }
  if (target.pane === "local") return target.listing ? { kind: "download" } : null;
  if (target.terminalId !== items.terminalId || !target.intoFolder) return null;
  const into = target.intoFolder;
  // Never into itself or a folder inside it, and not where they are already.
  if (items.paths.some((p) => into === p || into.startsWith(`${p}/`))) return null;
  if (into === items.folder) return null;
  return { kind: "move", into };
}

/** A comparison's row in a few words. */
export function rowWords(row: DiffRow): string {
  const side = (s: "here" | "there") => (s === "here" ? "this PC's" : "the host's");
  switch (row.state) {
    case "same":
      return "Same";
    case "onlyHere":
      return "Only on this PC";
    case "onlyThere":
      return "Only on the host";
    case "conflict":
      return "A file on one side, a folder on the other";
    case "differs": {
      const parts: string[] = [];
      if (row.sameContent === false) parts.push("other contents");
      if (row.newer) parts.push(`${side(row.newer)} is newer`);
      if (row.larger) parts.push(`${side(row.larger)} is larger`);
      const text = parts.join(", ") || "different";
      return text.charAt(0).toUpperCase() + text.slice(1);
    }
  }
}

/** Whether a sync that way can take the row, and whether it does by default (newer or missing on the other side). */
export function syncTakes(
  row: DiffRow,
  direction: SyncDirection,
  deleting: boolean,
): { can: boolean; byDefault: boolean } {
  const state: RowState = row.state;
  if (state === "same" || state === "conflict") return { can: false, byDefault: false };
  if (direction === "toHost") {
    if (state === "onlyHere") return { can: true, byDefault: true };
    if (state === "onlyThere") return { can: deleting, byDefault: deleting };
    return { can: true, byDefault: row.newer !== "there" };
  }
  if (state === "onlyThere") return { can: true, byDefault: true };
  if (state === "onlyHere") return { can: false, byDefault: false };
  return { can: true, byDefault: row.newer !== "here" };
}

/** The rows a sync takes by default. */
export function defaultPicks(rows: readonly DiffRow[], direction: SyncDirection, deleting: boolean): string[] {
  return rows.filter((r) => syncTakes(r, direction, deleting).byDefault).map((r) => r.path);
}

/** What a sync of the picked rows does, for its button and the line above it. */
export function syncSummary(
  rows: readonly DiffRow[],
  picked: readonly string[],
  direction: SyncDirection,
  deleting: boolean,
): { send: number; replace: number; remove: number } {
  let send = 0;
  let replace = 0;
  let remove = 0;
  for (const row of rows) {
    if (!picked.includes(row.path) || !syncTakes(row, direction, deleting).can) continue;
    const info = direction === "toHost" ? row.here : row.there;
    if (direction === "toHost" && row.state === "onlyThere") {
      remove += 1;
      continue;
    }
    if (info?.folder) continue;
    if (row.state === "differs") replace += 1;
    else send += 1;
  }
  return { send, replace, remove };
}

/** A local entry as both panes show it. */
export function localPaneEntry(e: LocalEntry): PaneEntry & { hidden: boolean } {
  return { name: e.name, kind: e.kind, link: e.link, size: e.size, modified: e.modified, hidden: e.hidden };
}
