// SS-08, P6: every file transfer, kept outside React state. A running transfer changes up to five times a second, and
// in the Terminal page's state each change re-rendered the whole page; here only what shows transfers (the transfers
// panel, the drawer's "an upload finished here" count) reads it, through useSyncExternalStore
// (src/hooks/use-transfers.ts). No React in this file, so its logic is tested in transfers-store.test.ts.

import type { TransferInfo } from "./api.ts";
import { isActive, mergeTransfer } from "./transfers.ts";

export interface TransferSnapshot {
  /** Every transfer, oldest first. */
  all: TransferInfo[];
  /** What the transfers panel lists: `all` less the finished ones cleared from it. */
  shown: TransferInfo[];
}

export interface TransferStore {
  /** The same object until something changes (what useSyncExternalStore needs). */
  getSnapshot(): TransferSnapshot;
  subscribe(listener: () => void): () => void;
  /** The core's list when the page opened. A transfer that changed before it arrived keeps its newer state. */
  load(list: TransferInfo[]): void;
  /** One change from the core. True when it ended the transfer just now (done, failed or cancelled). */
  apply(changed: TransferInfo): boolean;
  /** The panel's Clear: finished transfers leave the panel (and stay in `all`); running ones stay. */
  clearFinished(): void;
}

export function createTransferStore(): TransferStore {
  let all: TransferInfo[] = [];
  let cleared = new Set<string>();
  let snapshot: TransferSnapshot = { all, shown: all };
  const listeners = new Set<() => void>();

  const publish = () => {
    snapshot = { all, shown: cleared.size === 0 ? all : all.filter((t) => !cleared.has(t.id)) };
    listeners.forEach((listener) => listener());
  };

  return {
    getSnapshot: () => snapshot,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    load(list) {
      const known = new Map(all.map((t) => [t.id, t]));
      const loaded = new Set(list.map((t) => t.id));
      all = [...list.map((t) => known.get(t.id) ?? t), ...all.filter((t) => !loaded.has(t.id))];
      publish();
    },
    apply(changed) {
      const before = all.find((t) => t.id === changed.id);
      all = mergeTransfer(all, changed);
      publish();
      return before !== undefined && before.state !== changed.state && !isActive(changed);
    },
    clearFinished() {
      const finished = all.filter((t) => !isActive(t) && !cleared.has(t.id));
      if (finished.length === 0) return;
      cleared = new Set([...cleared, ...finished.map((t) => t.id)]);
      publish();
    },
  };
}

/** SS-08: uploads finished through this terminal. The drawer lists its folder again each time the count grows. */
export function uploadsDone(all: TransferInfo[], terminalId: string | null): number {
  if (!terminalId) return 0;
  return all.filter((t) => t.terminalId === terminalId && t.direction === "upload" && t.state === "done").length;
}

/** The app's one store: the Terminal page feeds it from the core's transfer events. */
export const transferStore = createTransferStore();
