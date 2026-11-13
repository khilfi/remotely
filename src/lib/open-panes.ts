// SS-14 (0.8.0 G3): the Terminal page's open panes, for the Files page. A Files host tab rides on an open SSH
// terminal's connection (its SFTP, root browsing and transfer queue), as the Terminal's "Files here" drawer does, so the
// Files page lists the panes the Terminal page publishes here and follows each one's snapshot (its status, folder and
// user). The Terminal page owns the panes: closing one there ends its Files tab. Tested in open-panes.test.ts.

/** What the Files page needs of a pane: its core id, its session, its name and a way to follow it. */
export interface OpenPane {
  /** The pane's key on the Terminal page. */
  key: string;
  /** The core's terminal id, once the pane opened. */
  terminalId: string | null;
  sessionId: string | null;
  /** How the Terminal page names its tab. */
  title: string;
  /** SSH panes carry files; Telnet, serial, tunnel and PowerShell panes don't. */
  ssh: boolean;
  /** The pane's own snapshot store. */
  subscribe: (listener: () => void) => () => void;
  getSnapshot: () => { status: { state: string } };
}

let panes: readonly OpenPane[] = [];
const listeners = new Set<() => void>();

function same(a: readonly OpenPane[], b: readonly OpenPane[]) {
  return (
    a.length === b.length &&
    a.every(
      (p, i) =>
        p.key === b[i].key &&
        p.terminalId === b[i].terminalId &&
        p.sessionId === b[i].sessionId &&
        p.title === b[i].title &&
        p.ssh === b[i].ssh,
    )
  );
}

/** The Terminal page's panes now, in its tabs' order. */
export function publishPanes(next: readonly OpenPane[]) {
  if (same(panes, next)) return;
  panes = next;
  for (const listener of listeners) listener();
}

/** The same array until something changes (for useSyncExternalStore). */
export function openPanes(): readonly OpenPane[] {
  return panes;
}

export function subscribePanes(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The pane of a terminal id, if it is still open. */
export function paneOf(terminalId: string | null | undefined): OpenPane | undefined {
  return terminalId ? panes.find((p) => p.terminalId === terminalId) : undefined;
}

/** SSH panes that have opened (they have a terminal id), for the Files page's host tabs. */
export function filePanes(list: readonly OpenPane[]): OpenPane[] {
  return list.filter((p) => p.ssh && p.terminalId !== null);
}

/** Tests only. */
export function resetPanes() {
  panes = [];
}
