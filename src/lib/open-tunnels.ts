// SS-07 for QL-21 and QL-22: every terminal's tunnels in one place, for the status bar's count and the map. The panes
// report what their core events say (terminal-session.ts: each change to a terminal's tunnels is one event), so this
// reads nothing itself and polls nothing. A closed pane forgets its tunnels, which close with it. Tested in
// open-tunnels.test.ts.

import type { TunnelInfo } from "./api.ts";

/** A tunnel and the terminal it belongs to. */
export interface OpenTunnel {
  terminalId: string;
  /** The saved session the terminal is a pane of. */
  sessionId: string;
  tunnel: TunnelInfo;
}

let byTerminal = new Map<string, TunnelInfo[]>();
let shown: readonly OpenTunnel[] = [];
const listeners = new Set<() => void>();

/** Listening, opening, or approved and waiting for its terminal to reconnect: it uses or will use a port. */
export function isOpen(tunnel: TunnelInfo): boolean {
  const state = tunnel.state.state;
  return state === "listening" || state === "opening" || state === "waiting";
}

function rebuild() {
  shown = [...byTerminal].flatMap(([terminalId, tunnels]) =>
    tunnels.filter(isOpen).map((tunnel) => ({ terminalId, sessionId: tunnel.forward.sessionId, tunnel })),
  );
  for (const listener of listeners) listener();
}

/** A terminal's tunnels as its latest event says. */
export function reportTunnels(terminalId: string, tunnels: TunnelInfo[]) {
  const before = byTerminal.get(terminalId);
  if (before === tunnels) return;
  byTerminal = new Map(byTerminal).set(terminalId, tunnels);
  rebuild();
}

/** The terminal closed: its tunnels closed with it. */
export function forgetTerminal(terminalId: string) {
  if (!byTerminal.has(terminalId)) return;
  byTerminal = new Map(byTerminal);
  byTerminal.delete(terminalId);
  rebuild();
}

/** The open ones, terminal by terminal. The same array until something changes (for useSyncExternalStore). */
export function openTunnels(): readonly OpenTunnel[] {
  return shown;
}

export function subscribeTunnels(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Tests only: forget every terminal. */
export function resetTunnels() {
  byTerminal = new Map();
  rebuild();
}
