// H9 blast radius of bulk runs (BX-01, BX-02): the Compare panel's "one host first" and "stop after N failures", how
// the approval dialog and the results say them, and which hosts a retry takes. Pure helpers, tested in
// rollout.test.ts. The core enforces all of it (`Rollout` in command_bus.rs, the job runner).

import type { BulkCounts, Rollout } from "./api.ts";

/** The most failures a run may be told to stop after (the core's MAX_STOP_AFTER_FAILURES). */
export const MAX_STOP_AFTER = 1000;

/** The "Stop after" field: empty is off; otherwise a whole number of failures, 1 to 1000. */
export function parseStopAfter(text: string): { ok: boolean; value: number | null } {
  const t = text.trim();
  if (t === "") return { ok: true, value: null };
  if (!/^\d+$/.test(t)) return { ok: false, value: null };
  const n = Number(t);
  return n >= 1 && n <= MAX_STOP_AFTER ? { ok: true, value: n } : { ok: false, value: null };
}

/** What the run will do about its blast radius, for the approval dialog; null when both are off. */
export function rolloutText(rollout: Rollout | null | undefined, hosts: number): string | null {
  if (!rollout) return null;
  const parts: string[] = [];
  if (rollout.canary && hosts > 1) {
    parts.push(
      `Runs on one host first, then waits for you before the other ${hosts - 1}; if it fails, they don't run.`,
    );
  }
  if (rollout.stopAfterFailures !== null) {
    const n = rollout.stopAfterFailures;
    parts.push(
      n === 1
        ? "Starts no more hosts after the first failure."
        : `Starts no more hosts once ${n} have failed (a host that times out counts).`,
    );
  }
  return parts.length ? parts.join(" ") : null;
}

/** The results' prompt while the rest wait after the canary. */
export function canaryPrompt(name: string, rest: number): string {
  return `${name} finished without errors. Run on the other ${rest === 1 ? "host" : `${rest} hosts`}?`;
}

/** Minutes and seconds left until `until` (RFC 3339), for the canary's wait; "0:00" once past. */
export function timeLeft(until: string, now: number): string {
  const secs = Math.max(0, Math.round((new Date(until).getTime() - now) / 1000));
  return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
}

/**
 * BX-04, H9: what the retry buttons offer. Hosts whose outcome is unknown (timed out, or cancelled while running) may
 * have run the command, so they are offered apart, never in the plain retry.
 */
export function retryChoices(counts: Pick<BulkCounts, "failed" | "unknown">): {
  failed: number;
  withUnknown: number | null;
} {
  return {
    failed: counts.failed,
    withUnknown: counts.unknown > 0 ? counts.failed + counts.unknown : null,
  };
}
