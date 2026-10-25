// AP-03, BX-03: reloads that follow job events wait for a pause in them, so a burst costs one reload instead of one
// per event (a MultiExec line on 50 terminals sends about 100: each terminal starting and finishing). While events
// keep coming, a reload still runs every `maxWait`, so a long run's progress shows.

/** The default pause, and the longest wait while events keep coming (ms). */
export const RELOAD_WAIT_MS = 300;
export const RELOAD_MAX_WAIT_MS = 1000;

/** When a debounced reload runs: `wait` after the burst's last event, but no later than `maxWait` after its first. */
export function debounceAt(firstAt: number, lastAt: number, wait: number, maxWait: number): number {
  return Math.min(lastAt + wait, firstAt + Math.max(wait, maxWait));
}
