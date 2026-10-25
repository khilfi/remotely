// FD-03: when the masker learns a value (a host or user name from an answer that arrived later), text already on
// screen that holds it must be masked again. Instead of masking the whole window again for each value, the DOM masker
// (presentation-dom.ts) gathers the values learnt in one go and masks again only the text that mentions one of them.
// Pure functions, tested in presentation-rescan.test.ts.

import type { Learned } from "./presentation.ts";

function escapeRegExp(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * A quick test for text that may hold one of `values`, or null for none. It ignores letter case and word edges, so it
 * finds more than the masker would mask (masking such text again changes nothing); it never misses one.
 */
export function mentionsAny(values: readonly string[]): ((text: string) => boolean) | null {
  const words = [...new Set(values.filter((v) => v !== "").map((v) => v.toLowerCase()))];
  if (words.length === 0) return null;
  // Longest first, so a value that starts another is no trouble to the alternation.
  words.sort((a, b) => b.length - a.length);
  const re = new RegExp(words.map(escapeRegExp).join("|"), "i");
  return (text: string) => text !== "" && re.test(text);
}

/** Values learnt since the last rescan; `add` says whether a rescan has to be queued for it. */
export class LearnedBatch {
  private values = new Set<string>();

  /** True for the first value of a batch: the caller queues one rescan for all of them. */
  add(learned: Learned): boolean {
    const first = this.values.size === 0;
    this.values.add(learned.value);
    return first;
  }

  get size(): number {
    return this.values.size;
  }

  /** The values gathered so far, and a fresh batch for what comes next. */
  take(): string[] {
    const out = [...this.values];
    this.values = new Set();
    return out;
  }
}
