// CT-01: background reads that stay gentle on the hosts they read, as pure functions (tested in polling.test.ts). A
// read runs only while its page is shown and the window is visible; the next one is timed from when the last one
// finished, so a slow host never has two of the same read in flight; a read that failed waits longer each time it
// fails again. The hook that runs them is src/hooks/use-poll.ts.

/** The longest wait after reads that failed in a row (unless the interval itself is longer). */
export const MAX_POLL_WAIT_MS = 60_000;

/**
 * Whether a background read may run now: its page is the one shown, and the window is visible (not minimised, not
 * behind the lock screen). `visibility` is `document.visibilityState`.
 */
export function shouldPoll(pageActive: boolean, visibility: string): boolean {
  return pageActive && visibility === "visible";
}

/** The wait after a read: the interval, doubled for each failure in a row, up to `maxMs` (never below the interval). */
export function pollWait(intervalMs: number, failures: number, maxMs = MAX_POLL_WAIT_MS): number {
  const doublings = Math.min(Math.max(failures, 0), 16);
  return Math.min(intervalMs * 2 ** doublings, Math.max(maxMs, intervalMs));
}

/** The last read of one kind: what it read (`key`), when it finished, and how many failed in a row. */
export interface LastRead {
  key: string;
  finishedAt: number;
  failures: number;
}

/** The record after a read of `key` finished at `now`. */
export function afterRead(last: LastRead | null, key: string, ok: boolean, now: number): LastRead {
  const before = last && last.key === key ? last.failures : 0;
  return { key, finishedAt: now, failures: ok ? 0 : before + 1 };
}

export interface PollTiming {
  intervalMs: number;
  maxMs?: number;
  /** False: the first read of a key waits one interval (the same thing was just read another way). */
  immediate?: boolean;
}

/**
 * How long to wait before the next read of `key`: what is left of the wait after the last read of it (so hiding and
 * showing the page, or a re-render, never reads early), or, for a key not read yet, nothing (or one interval).
 */
export function pollDelay(last: LastRead | null, key: string, now: number, timing: PollTiming): number {
  if (!last || last.key !== key) return timing.immediate === false ? timing.intervalMs : 0;
  return Math.max(0, last.finishedAt + pollWait(timing.intervalMs, last.failures, timing.maxMs) - now);
}
