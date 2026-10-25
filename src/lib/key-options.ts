// SS-09: the restrictions a pushed key can carry (OpenSSH's `expiry-time` and `from`, written before the key in
// authorized_keys), as the push dialog reads them. Pure helpers, tested in key-options.test.ts; the core checks
// them again (`KeyOptions::validate` in ssh_keys.rs) and only writes what passes.

import type { KeyOptions } from "./api.ts";

/** The most `from` patterns one push takes (the core's MAX_FROM_PATTERNS). */
export const MAX_FROM = 32;

/** A host name or address with `*` and `?`, a CIDR network, `!` in front to exclude. */
const PATTERN = /^!?[A-Za-z0-9.\-_:*?%]+(\/[0-9]{1,3})?$/;

/** The "Only from" field: patterns separated by commas, spaces or new lines. */
export function parseFrom(text: string): { patterns: string[]; problem: string | null } {
  const patterns = text
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (patterns.length > MAX_FROM) return { patterns, problem: `At most ${MAX_FROM} hosts or networks.` };
  const bad = patterns.find((p) => !PATTERN.test(p) || p.length > 255);
  if (bad) {
    return {
      patterns,
      problem: `'${bad}' is not a host, address or network: use names like *.example.com, addresses like 192.0.2.10 or networks like 192.0.2.0/24.`,
    };
  }
  return { patterns, problem: null };
}

/** `YYYY-MM-DD` of a date in UTC. */
export function utcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** The earliest expiry the core takes: tomorrow (UTC). */
export function earliestExpiry(now: Date): string {
  return utcDay(new Date(now.getTime() + 24 * 60 * 60 * 1000));
}

/** What is wrong with an expiry date (`YYYY-MM-DD`, from a date input), or null. Empty is no expiry. */
export function expiryProblem(day: string, now: Date): string | null {
  if (!day) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || Number.isNaN(Date.parse(`${day}T00:00:00Z`))) {
    return "Give the expiry date as a day.";
  }
  if (day < earliestExpiry(now)) return "The key's expiry date must be after today.";
  return null;
}

/** The options a push sends; both parts optional. */
export function keyOptions(expiresOn: string, fromText: string): KeyOptions {
  return { expiresOn: expiresOn || null, from: parseFrom(fromText).patterns };
}

/** The line written before the key, as the core writes it, for the dialog to show. Empty for none. */
export function optionsPrefix(options: KeyOptions): string {
  const parts: string[] = [];
  if (options.expiresOn) parts.push(`expiry-time="${options.expiresOn.split("-").join("")}Z"`);
  if (options.from.length) parts.push(`from="${options.from.join(",")}"`);
  return parts.join(",");
}
