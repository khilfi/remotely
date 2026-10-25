// AP-03, BX-03: a value that follows another once it stops changing (src/lib/debounce.ts), for reloads driven by job
// events.

import { useEffect, useRef, useState } from "react";
import { debounceAt, RELOAD_MAX_WAIT_MS, RELOAD_WAIT_MS } from "@/lib/debounce";

/** `value` once it has not changed for `wait` ms, or every `maxWait` ms while it keeps changing. */
export function useDebounced<T>(value: T, wait = RELOAD_WAIT_MS, maxWait = RELOAD_MAX_WAIT_MS): T {
  const [settled, setSettled] = useState(value);
  // When the burst of changes began; null while `settled` is current.
  const firstAt = useRef<number | null>(null);
  useEffect(() => {
    if (Object.is(value, settled)) {
      firstAt.current = null;
      return;
    }
    const now = Date.now();
    firstAt.current ??= now;
    const delay = Math.max(0, debounceAt(firstAt.current, now, wait, maxWait) - now);
    const timer = window.setTimeout(() => {
      firstAt.current = null;
      setSettled(value);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [value, settled, wait, maxWait]);
  return settled;
}
