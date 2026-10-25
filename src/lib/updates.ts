// FD-14: pure helpers for update checks (tested in updates.test.ts): what a check found, in words for
// Settings' status line and the command palette's toast, and when to check again after GitHub's API
// limit was used up. The releases are public, so checks need no GitHub update token; it is optional.

import type { UpdateCheck } from "@/lib/api";

/** One more check this long after GitHub's limit resets, so it has surely reset. */
export const RECHECK_MARGIN_MS = 30_000;
/** The regular check runs every 24 hours anyway. */
export const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

/** `until` (RFC 3339) as a local time of day, e.g. 14:05; the date too when it is not today. */
export function localTime(until: string, now: Date = new Date()): string {
  const at = new Date(until);
  if (Number.isNaN(at.getTime())) return "later";
  const time = at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return at.toDateString() === now.toDateString() ? time : `${at.toLocaleDateString()} ${time}`;
}

/** Why a check found nothing because GitHub's limit is used up, and what helps. */
export function rateLimitedText(until: string, withToken: boolean, now: Date = new Date()): string {
  const at = localTime(until, now);
  return withToken
    ? `GitHub's API limit for the update token is used up until ${at}. Remotely checks again then.`
    : `GitHub's limit for update checks without a token (60 an hour from one internet address) is used up until ${at}. ` +
        "Remotely checks again then. A GitHub update token (Settings, Updates) has a limit of its own.";
}

/** What a check found, as a sentence for Settings' status line and the palette's toast. */
export function checkMessage(result: UpdateCheck, now: Date = new Date()): string {
  switch (result.status) {
    case "available":
      return `Version ${result.update.version} is available.`;
    case "upToDate":
      return "You have the latest version.";
    case "tokenNeeded":
      return `GitHub doesn't show the releases of ${result.repository} without a token, so the repository may be private again. Add a GitHub update token in Settings, under Updates.`;
    case "vaultLocked":
      return "GitHub doesn't show the releases without a token. Unlock the vault so Remotely can use the GitHub update token kept there.";
    case "rateLimited":
      return rateLimitedText(result.until, result.withToken, now);
    case "off":
      return "Update checks are off.";
  }
}

/** Whether a result is worth telling about quietly (a toast or status line) rather than as a success. */
export function isNotice(result: UpdateCheck): boolean {
  return result.status === "tokenNeeded" || result.status === "vaultLocked" || result.status === "rateLimited";
}

/**
 * After GitHub's limit was used up: how long until one more check, just after the time GitHub named. `null`
 * for any other result, or when the regular 24-hour check comes first.
 */
export function recheckDelayMs(result: UpdateCheck, now: number): number | null {
  if (result.status !== "rateLimited") return null;
  const until = Date.parse(result.until);
  if (Number.isNaN(until)) return null;
  const delay = Math.max(until - now, 0) + RECHECK_MARGIN_MS;
  return delay < UPDATE_CHECK_INTERVAL_MS ? delay : null;
}
