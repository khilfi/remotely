// SS-10: which open tabs MultiExec types into: all of them, the tabs of one folder or one label, or tabs picked by
// hand (Ctrl+click, Shift+click; see tab-selection.ts). Pure functions over what the page knows of each tab, so they
// are tested on their own (multiexec-picks.test.ts).

import type { Environment } from "./api.ts";

/** What picking needs to know of an open tab. */
export interface PickableTab {
  key: string;
  /** The saved session's folder; null at the top level or for a quick connection. */
  folderId: string | null;
  /** The session's environment label; null for a quick connection. */
  environment: Environment | null;
  /** A quick connection that was not saved as a session. */
  unsaved: boolean;
}

export type PickBy =
  | { kind: "all" }
  /** The folder, and the folders under it (`under`, from folders.ts `subtree`). */
  | { kind: "folder"; under: Set<string> }
  | { kind: "label"; environment: Environment }
  | { kind: "unsaved" };

/** The tab keys a pick takes, in tab order. */
export function pickTabs(tabs: PickableTab[], by: PickBy): string[] {
  return tabs
    .filter((t) => {
      switch (by.kind) {
        case "all":
          return true;
        case "folder":
          return t.folderId !== null && by.under.has(t.folderId);
        case "label":
          return t.environment === by.environment;
        case "unsaved":
          return t.unsaved;
      }
    })
    .map((t) => t.key);
}

/** The labels open tabs carry, most tabs first, each with how many. */
export function labelChoices(tabs: PickableTab[]): { environment: Environment; count: number }[] {
  const counts = new Map<Environment, number>();
  for (const t of tabs) {
    if (t.environment !== null && t.environment !== "none")
      counts.set(t.environment, (counts.get(t.environment) ?? 0) + 1);
  }
  const order: Environment[] = ["prod", "staging", "lab"];
  return order
    .filter((e) => counts.has(e))
    .map((environment) => ({ environment, count: counts.get(environment) ?? 0 }));
}

/** How many open tabs each folder (with the folders under it) holds; only folders that hold one. */
export function folderCounts(tabs: PickableTab[], subtrees: Map<string, Set<string>>): Map<string, number> {
  const counts = new Map<string, number>();
  for (const [folder, under] of subtrees) {
    const n = tabs.filter((t) => t.folderId !== null && under.has(t.folderId)).length;
    if (n > 0) counts.set(folder, n);
  }
  return counts;
}

/** "3 of 5 tabs", for the MultiExec bar. */
export function pickedText(picked: number, total: number): string {
  if (picked === total) return total === 1 ? "the only tab" : `all ${total} tabs`;
  return `${picked} of ${total} tabs`;
}
