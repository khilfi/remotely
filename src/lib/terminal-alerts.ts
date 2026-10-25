// QL-17 alerts, the UI side: the recent ones in memory (for R10's notification centre, QL-25, to list later), and
// the words of the Windows notification one shows. The core sends one alert per burst of matching lines in a
// terminal, then counts quietly for a while (its cooldown), so nothing here ever notifies per line. Tested in
// terminal-alerts.test.ts.

import type { TerminalAlert } from "./api.ts";

/** How many alerts are kept in memory, newest first. */
export const MAX_RECENT_ALERTS = 200;

/** An alert as the app keeps it: with the terminal's name when it came, and when it came. */
export interface RecordedAlert {
  alert: TerminalAlert;
  /** The terminal's name as its tab showed it. */
  terminal: string;
  /** When the UI got it (ms since 1970). */
  receivedAt: number;
}

let recent: RecordedAlert[] = [];
const listeners = new Set<() => void>();

/** Keeps an alert (the oldest goes past MAX_RECENT_ALERTS) and tells the subscribers. */
export function recordAlert(alert: TerminalAlert, terminal: string, receivedAt = Date.now()): RecordedAlert {
  const recorded = { alert, terminal, receivedAt };
  recent = [recorded, ...recent].slice(0, MAX_RECENT_ALERTS);
  listeners.forEach((listener) => listener());
  return recorded;
}

/** The alerts kept, newest first. The same array until one is added or they are cleared (for useSyncExternalStore). */
export function recentAlerts(): readonly RecordedAlert[] {
  return recent;
}

export function clearAlerts() {
  if (recent.length === 0) return;
  recent = [];
  listeners.forEach((listener) => listener());
}

/** Calls `listener` after each change; returns the way to stop. */
export function subscribeAlerts(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function lines(n: number) {
  return n === 1 ? "1 line" : `${n} lines`;
}

/** The Windows notification for an alert: the rule and the terminal, how many lines, and the first line's sample. */
export function alertNotification(alert: TerminalAlert, terminal: string): { title: string; body: string } {
  const counted = alert.count > 1 ? `${lines(alert.count)} matched` : "A line matched";
  const earlier = alert.suppressed > 0 ? ` (and ${lines(alert.suppressed)} since the last alert)` : "";
  const sample = alert.sample ? `: ${alert.sample}` : "";
  return {
    title: `${alert.ruleName} in ${terminal}`,
    body: `${counted}${earlier}${sample}`,
  };
}
