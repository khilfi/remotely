// QL-26: the workspace's stars and recents, read once and kept outside React state, so every page that shows a star or
// a Recent list shares one copy (useSyncExternalStore). A workspace switch reloads the window, which starts it again.
// Starring and noting what was opened are not audited and the read-only lock allows them (the core says why).

import { useEffect, useSyncExternalStore } from "react";
import { toast } from "sonner";
import { errorMessage } from "@/lib/api";
import { comfortApi, type Recent, type RecentKind, type Star, type StarKind } from "@/lib/comfort-api";
import { isStarred, starSets, type StarSets } from "@/lib/stars";

interface Snapshot {
  stars: Star[];
  sets: StarSets;
  recents: Recent[];
}

let snapshot: Snapshot = { stars: [], sets: starSets([]), recents: [] };
let requested = false;
const listeners = new Set<() => void>();

function set(next: Partial<Snapshot>) {
  snapshot = { ...snapshot, ...next };
  if (next.stars) snapshot.sets = starSets(next.stars);
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Reads the stars and recents (once; `again` reads them again). */
export function loadStars(again = false) {
  if (requested && !again) return;
  requested = true;
  comfortApi.stars().then(
    (stars) => set({ stars }),
    () => undefined,
  );
  comfortApi.recents().then(
    (recents) => set({ recents }),
    () => undefined,
  );
}

function useSnapshot(): Snapshot {
  useEffect(() => loadStars(), []);
  return useSyncExternalStore(subscribe, () => snapshot);
}

export function useStars(): StarSets {
  return useSnapshot().sets;
}

export function useRecents(): Recent[] {
  return useSnapshot().recents;
}

/** Stars an item, or takes its star off. */
export async function toggleStar(kind: StarKind, key: string) {
  const starred = !isStarred(snapshot.sets, kind, key);
  try {
    set({ stars: await comfortApi.setStar(kind, key, starred) });
  } catch (err) {
    toast.error(errorMessage(err));
  }
}

/** Notes that a VM's details or a page was opened. A failure is ignored: it only orders a list. */
export function noteOpened(kind: RecentKind, key: string) {
  comfortApi.opened(kind, key).then(
    (recents) => set({ recents }),
    () => undefined,
  );
}

/** A terminal notes its session in the core by itself; this reads the list again. */
export function refreshRecents() {
  comfortApi.recents().then(
    (recents) => set({ recents }),
    () => undefined,
  );
}
