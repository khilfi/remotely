// QL-20 global search in the palette, the ranking (tested in search.test.ts). Each provider (search-providers.ts) turns
// what the app already read into items with the fields they can be found by: a name, an address (host name or IP), a
// tag, or a detail (an image's path, a command's text). Every word of the query has to match one of an item's fields;
// how well each matches and which kind of field it is make the score, so "web" finds web01 before a VM tagged web,
// and "192.0.2" finds the hosts at those addresses. Nothing here reads anything.

import type { AppLink } from "./links.ts";

export type FieldKind = "name" | "address" | "tag" | "detail";

export interface SearchField {
  text: string;
  kind: FieldKind;
}

/**
 * What choosing an item does: open a link, show a VM's or session's own actions in the palette, run an action, or
 * (UX-05) show a glossary term's definition in the palette.
 */
export type SearchTarget =
  { open: AppLink } | { drill: "vm" | "session"; id: string } | { action: string } | { define: string };

/** FD-03: what the item's detail holds, so it is masked as one value while presenting (`data-mask`). */
export type DetailMask = "host" | "ip" | "user" | "address";

export interface SearchItem {
  /** Unique across providers. */
  id: string;
  /** The provider's id: the group it shows in. */
  provider: string;
  title: string;
  /** Shown after the title, muted. */
  detail?: string;
  detailMask?: DetailMask;
  /** A short state ("running", "built-in"), shown on the right. */
  badge?: string;
  fields: SearchField[];
  target: SearchTarget;
  /** A little extra for items more likely wanted (running VMs, say); never more than a better match. */
  boost?: number;
}

export interface RankedItem {
  item: SearchItem;
  score: number;
}

export interface RankedGroup {
  provider: string;
  items: RankedItem[];
  /** Items past the group's limit. */
  more: number;
}

const WEIGHT: Record<FieldKind, number> = { name: 1, address: 0.9, tag: 0.75, detail: 0.5 };

/** Lower case, accents dropped, so "Café" is found by "cafe". */
export function normalise(text: string): string {
  return text.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase();
}

/** The query's words, normalised. */
export function queryWords(query: string): string[] {
  return normalise(query).split(/\s+/).filter(Boolean);
}

const WORD_START = /[\s\-_.:/\\@()[\],|]/;

/** How well one word matches one text (both normalised): 0 when it doesn't. */
export function matchQuality(word: string, text: string): number {
  if (!word || !text) return 0;
  if (text === word) return 100;
  if (text.startsWith(word)) return 80;
  let at = text.indexOf(word);
  while (at > 0) {
    if (WORD_START.test(text[at - 1])) return 60;
    at = text.indexOf(word, at + 1);
  }
  if (text.includes(word)) return 40;
  return word.length >= 2 ? subsequence(word, text) : 0;
}

/** Letters skipped at most in a letters-in-order match: more, and "shop" would find "dashboard polling". */
const MAX_SKIPPED = 3;

/** Letters in order with a few skipped ("wb1" in "web01"): a weak match, weaker for each gap. */
function subsequence(word: string, text: string): number {
  let best = 0;
  for (let start = text.indexOf(word[0]); start >= 0; start = text.indexOf(word[0], start + 1)) {
    let last = start;
    let gaps = 0;
    let ok = true;
    for (const ch of word.slice(1)) {
      const found = text.indexOf(ch, last + 1);
      if (found < 0) {
        ok = false;
        break;
      }
      if (found > last + 1) gaps += 1;
      last = found;
    }
    if (!ok) break;
    if (last - start + 1 - word.length <= MAX_SKIPPED) best = Math.max(best, Math.max(5, 25 - gaps * 5));
  }
  return best;
}

/** An item's score for the query: every word must match some field (0 otherwise). */
export function scoreItem(words: readonly string[], item: SearchItem): number {
  if (words.length === 0) return 0;
  const fields = item.fields.map((f) => ({ text: normalise(f.text), weight: WEIGHT[f.kind] }));
  let total = 0;
  for (const word of words) {
    let best = 0;
    for (const field of fields) {
      // A weak, letters-in-order match only counts in names: in a path or a command it finds anything.
      const quality = matchQuality(word, field.text);
      const counted = quality < 40 && field.weight < 1 ? 0 : quality * field.weight;
      if (counted > best) best = counted;
    }
    if (best === 0) return 0;
    total += best;
  }
  return total / words.length + Math.min(item.boost ?? 0, 4);
}

/** The items that match, best first; equal scores keep their providers' order, then go by title. */
export function rankItems(query: string, items: readonly SearchItem[], providerOrder: readonly string[] = []) {
  const words = queryWords(query);
  const order = new Map(providerOrder.map((id, i) => [id, i]));
  return items
    .map((item) => ({ item, score: scoreItem(words, item) }))
    .filter((r) => r.score > 0)
    .sort(
      (a, b) =>
        b.score - a.score ||
        (order.get(a.item.provider) ?? 99) - (order.get(b.item.provider) ?? 99) ||
        a.item.title.localeCompare(b.item.title),
    );
}

/**
 * The palette's list: items grouped by provider, the group with the best item first, each group best first and at
 * most `perGroup` long. The first item shown is the best match overall, so Enter picks it.
 */
export function groupRanked(ranked: readonly RankedItem[], perGroup = 6): RankedGroup[] {
  const groups = new Map<string, RankedItem[]>();
  for (const r of ranked) {
    const list = groups.get(r.item.provider) ?? [];
    list.push(r);
    groups.set(r.item.provider, list);
  }
  return [...groups.entries()].map(([provider, items]) => ({
    provider,
    items: items.slice(0, perGroup),
    more: Math.max(0, items.length - perGroup),
  }));
}
