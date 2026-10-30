// UX-03, UX-07 (0.6.0): what the Ctrl+K palette lists before anything is typed, and when its bulk actions show, as pure
// functions (tested in palette.test.ts). Opened, it lists the pages first, then what makes something new, then the
// other actions, VMs and sessions. The actions on every running VM at once ("Shut down all running VMs") never show
// until the search asks for them, so they can't be picked by accident from the top of the list.

/** The app's actions that make something new (a VM, a template, a schedule, a terminal...), by id. */
export const CREATE_ACTION_IDS: readonly string[] = [
  "deploy",
  "add-vm",
  "import-vm",
  "new-template",
  "add-image",
  "new-stack",
  "new-schedule",
  "new-terminal",
];

export function isCreateAction(id: string): boolean {
  return CREATE_ACTION_IDS.includes(id);
}

/** The palette's actions in two groups, each in the order given: what makes something new, then the rest. */
export function splitActions<T extends { id: string }>(actions: readonly T[]): { create: T[]; other: T[] } {
  const create: T[] = [];
  const other: T[] = [];
  for (const action of actions) (isCreateAction(action.id) ? create : other).push(action);
  // "New…" in the order of CREATE_ACTION_IDS, which follows the sidebar's pages.
  create.sort((a, b) => CREATE_ACTION_IDS.indexOf(a.id) - CREATE_ACTION_IDS.indexOf(b.id));
  return { create, other };
}

/** The shortest search that may show a bulk action. */
export const BULK_MIN_CHARS = 3;

/**
 * Whether a search asks for a bulk action (one on every running VM): at least three characters, and every word of it
 * the start of a word of the action ("shut", "susp", "all run"). Anything shorter or looser leaves them out, so they
 * never come up for a search about something else.
 */
export function typedForBulk(query: string, label: string): boolean {
  const q = query.trim().toLowerCase();
  if (q.length < BULK_MIN_CHARS) return false;
  const words = label
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return q
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => words.some((word) => word.startsWith(w)));
}
