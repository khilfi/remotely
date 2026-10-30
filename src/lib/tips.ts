// UX-09: one-time tips. A tip shows until the user dismisses it; the dismissed ids are kept in the window's local
// storage (per Windows user, like the theme), and Settings › General's "Show tips again" clears them. Storage can be
// missing or full, so every read and write is wrapped: a tip that can't be remembered just shows again next time.
// Tip ids are "<page>.<what>", for example "vms.selection". Tested in tips.test.ts.

const STORAGE_KEY = "remotely.tips.dismissed";

/** The dismissed ids in a stored value; anything unreadable is none. */
export function parseDismissed(raw: string | null | undefined): Set<string> {
  if (!raw) return new Set();
  try {
    const value: unknown = JSON.parse(raw);
    return new Set(Array.isArray(value) ? value.filter((id): id is string => typeof id === "string") : []);
  } catch {
    return new Set();
  }
}

/** The stored value for a set of dismissed ids, sorted so it reads the same each time. */
export function serialiseDismissed(ids: ReadonlySet<string>): string {
  return JSON.stringify([...ids].sort());
}

interface TipStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

function storage(): TipStorage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

let dismissed: Set<string> | null = null;
const listeners = new Set<() => void>();

function current(): Set<string> {
  if (dismissed) return dismissed;
  try {
    dismissed = parseDismissed(storage()?.getItem(STORAGE_KEY));
  } catch {
    dismissed = new Set();
  }
  return dismissed;
}

function changed(next: Set<string>) {
  dismissed = next;
  try {
    const store = storage();
    if (next.size === 0) store?.removeItem(STORAGE_KEY);
    else store?.setItem(STORAGE_KEY, serialiseDismissed(next));
  } catch {
    // Not remembered: the tip shows again next time.
  }
  for (const listener of listeners) listener();
}

/** Whether a tip was dismissed. */
export function isTipDismissed(id: string): boolean {
  return current().has(id);
}

/** Hides a tip for good (until "Show tips again"). */
export function dismissTip(id: string) {
  if (current().has(id)) return;
  changed(new Set([...current(), id]));
}

/** Shows every tip again. */
export function resetTips() {
  changed(new Set());
}

/** How many tips were dismissed (Settings says whether there is anything to show again). */
export function dismissedTipCount(): number {
  return current().size;
}

/** For useSyncExternalStore: called whenever a tip is dismissed or the tips are reset. */
export function subscribeTips(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** A version that changes with every dismissal or reset (useSyncExternalStore's snapshot). */
export function tipsSnapshot(): Set<string> {
  return current();
}
