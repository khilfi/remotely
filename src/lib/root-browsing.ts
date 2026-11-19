// UX-14 (0.9.0 H1): which terminals browse as root, as the core says (`files_root_status`), shared by every host pane of
// the window: root browsing started in the Terminal's drawer shows on the Files page's tab of the same terminal, and the
// other way round. A pane reads the core's answer when it shows a terminal, when the terminal connects and on Refresh;
// starting and stopping set it at once. A read that was asked before a start or stop is dropped when it answers, so it
// can't undo it. No React here: tested in root-browsing.test.ts.

/** The core's answer for one terminal: whether it browses as root now. */
export type RootReader = (terminalId: string) => Promise<boolean>;

export interface RootStore {
  /** Whether the terminal browses as root, as far as the window knows. */
  isRoot(terminalId: string): boolean;
  /** A number that changes with any terminal's state (what useSyncExternalStore needs). */
  version(): number;
  subscribe(listener: () => void): () => void;
  /** Started or stopped here, or ended in the core: known at once. True when it changed (so it is said once). */
  set(terminalId: string, on: boolean): boolean;
  /** Asks the core again; its answer counts unless the state was set since the read started. */
  load(terminalId: string, read: RootReader): Promise<void>;
}

export function createRootStore(): RootStore {
  const on = new Map<string, boolean>();
  /** Per terminal, bumped by every `set`, so a read that started before one is dropped. */
  const sets = new Map<string, number>();
  const listeners = new Set<() => void>();
  let version = 0;

  const change = (terminalId: string, value: boolean) => {
    if ((on.get(terminalId) ?? false) === value && on.has(terminalId)) return false;
    on.set(terminalId, value);
    version += 1;
    listeners.forEach((listener) => listener());
    return true;
  };

  return {
    isRoot: (terminalId) => on.get(terminalId) ?? false,
    version: () => version,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    set(terminalId, value) {
      sets.set(terminalId, (sets.get(terminalId) ?? 0) + 1);
      return change(terminalId, value);
    },
    async load(terminalId, read) {
      const asked = sets.get(terminalId) ?? 0;
      let answer: boolean;
      try {
        answer = await read(terminalId);
      } catch {
        return;
      }
      if ((sets.get(terminalId) ?? 0) === asked) change(terminalId, answer);
    },
  };
}

/** The window's one store. */
export const rootStore = createRootStore();
