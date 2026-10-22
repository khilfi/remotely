// CT-01: a background read, run again and again while `enabled` (the timing is src/lib/polling.ts). The next read is
// timed from when the last one finished, and never starts while one is still out, even when the poll stops and starts
// again (the page hidden and shown) during a slow read. A read that throws counts as failed, and the next one waits
// longer.

import { useEffect, useRef, useSyncExternalStore } from "react";
import { afterRead, pollDelay, type LastRead, type PollTiming } from "@/lib/polling";

function subscribe(onChange: () => void) {
  document.addEventListener("visibilitychange", onChange);
  return () => document.removeEventListener("visibilitychange", onChange);
}

/** `document.visibilityState`, kept up to date: "hidden" while the window is minimised or behind the lock screen. */
export function useVisibility(): DocumentVisibilityState {
  return useSyncExternalStore(subscribe, () => document.visibilityState);
}

export interface PollOptions extends PollTiming {
  enabled: boolean;
  /** What is read: another key starts afresh; the same key keeps its wait across stops and starts. */
  resetKey: string;
}

/**
 * Runs `read` now (or when due) and again after each one finishes, while `enabled`. `read` gets `live`, which turns
 * false once this poll stopped or moved on to another key: what such a read brings back is dropped.
 */
export function usePoll(read: (live: () => boolean) => Promise<unknown>, options: PollOptions): void {
  const { enabled, resetKey, intervalMs, maxMs, immediate } = options;
  const latest = useRef(read);
  useEffect(() => {
    latest.current = read;
  });
  const last = useRef<LastRead | null>(null);
  const inFlight = useRef<Promise<void> | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let timer: number | undefined;
    const live = () => !stopped;
    const run = () => {
      inFlight.current = Promise.resolve()
        .then(() => latest.current(live))
        .then(
          () => true,
          () => false,
        )
        .then((ok) => {
          last.current = afterRead(last.current, resetKey, ok, Date.now());
          inFlight.current = null;
          if (!stopped) schedule();
        });
    };
    const schedule = () => {
      const delay = pollDelay(last.current, resetKey, Date.now(), { intervalMs, maxMs, immediate });
      timer = window.setTimeout(run, delay);
    };
    // A read from before (another key, or before the page was hidden) finishes first.
    const pending = inFlight.current;
    if (pending) {
      void pending.then(() => {
        if (!stopped) schedule();
      });
    } else {
      schedule();
    }
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [enabled, resetKey, intervalMs, maxMs, immediate]);
}
