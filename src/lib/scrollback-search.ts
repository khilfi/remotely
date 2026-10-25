// QL-18: search across every open terminal's scrollback. Pure helpers over the text of a terminal's rows, so they are
// tested on their own (scrollback-search.test.ts); scrollback-xterm.ts reads the rows out of xterm.js and shows a match.
//
// A terminal holds rows of cells; a long line the host printed wraps over several rows. Lines are searched whole: the
// rows of a wrapped line are joined first ("logical lines"), so a match that crosses a row edge is found, and wide
// characters (CJK, emoji) count as the one character they are. Each line is searched up to MAX_LINE_CHARS characters,
// and results are capped per terminal (MAX_PER_PANE) and in all (MAX_TOTAL), so a huge scrollback or a pattern that
// matches everything can't hold the page up; the panel says when it cut. The search is plain text or a JavaScript
// regular expression, with or without case; an invalid one is refused with its error.

/** Case and regular expression, as the terminal's own search bar has them. */
export interface SearchOptions {
  caseSensitive: boolean;
  regex: boolean;
}

/** Matches kept per terminal. */
export const MAX_PER_PANE = 200;
/** Matches kept over every terminal. */
export const MAX_TOTAL = 2000;
/** Characters of a line that are searched; the rest of a longer line is not. */
export const MAX_LINE_CHARS = 4000;
/** The start of a match's line kept to find that line again when the user jumps to it. */
export const PROBE_CHARS = 200;
/** The excerpt shown for a match: this much before it, the match itself up to MATCH_CHARS, then this much after. */
export const BEFORE_CHARS = 40;
export const MATCH_CHARS = 160;
export const AFTER_CHARS = 120;

export type CompiledSearch = { ok: true; pattern: RegExp } | { ok: false; error: string };

/** The query as a global RegExp, or why it can't be one. null for an empty query. */
export function compileSearch(query: string, options: SearchOptions): CompiledSearch | null {
  if (query === "") return null;
  const flags = options.caseSensitive ? "g" : "gi";
  if (!options.regex) return { ok: true, pattern: new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), flags) };
  try {
    return { ok: true, pattern: new RegExp(query, flags) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: `Not a valid regular expression: ${message.replace(/^Invalid regular expression: /, "")}`,
    };
  }
}

/** One row of a terminal's buffer as text (wide characters once), and whether it continues the row before. */
export interface RowText {
  text: string;
  wrapped: boolean;
}

/** A line as the host printed it: its first row in the buffer, its text (trailing blanks dropped), and its rows. */
export interface LogicalLine {
  row: number;
  text: string;
  /** Where each of its rows starts in `text`. */
  starts: number[];
}

/** Joins wrapped rows into lines. `first` is the buffer row of `rows[0]`. */
export function joinRows(rows: RowText[], first = 0): LogicalLine[] {
  const lines: LogicalLine[] = [];
  let current: LogicalLine | null = null;
  rows.forEach((r, i) => {
    if (r.wrapped && current) {
      current.starts.push(current.text.length);
      current.text += r.text;
      return;
    }
    if (current) lines.push(current);
    current = { row: first + i, text: r.text, starts: [0] };
  });
  if (current) lines.push(current);
  for (const line of lines) line.text = line.text.trimEnd();
  return lines;
}

/** Where a match is: its line's first row and its offsets in the line's text, and what to show for it. */
export interface LineHit {
  row: number;
  start: number;
  end: number;
  /** What matched. */
  matched: string;
  /** The start of its line, to find the line again once more output came. */
  probe: string;
  before: string;
  /** The match as shown, cut at MATCH_CHARS. */
  shown: string;
  after: string;
  /** Text was left out before or after the excerpt. */
  cutBefore: boolean;
  cutAfter: boolean;
}

/** One terminal's matches. */
export interface PaneHits {
  hits: LineHit[];
  /** More matched than MAX_PER_PANE (or the cap given). */
  capped: boolean;
  /** Lines longer than MAX_LINE_CHARS, searched only that far. */
  longLines: number;
}

/** The excerpt for a match at [start, end) of `text`. */
export function excerpt(text: string, start: number, end: number) {
  const from = Math.max(0, start - BEFORE_CHARS);
  const matched = text.slice(start, end);
  const to = Math.min(text.length, end + AFTER_CHARS);
  return {
    before: text.slice(from, start),
    shown: matched.length > MATCH_CHARS ? `${matched.slice(0, MATCH_CHARS)}…` : matched,
    after: text.slice(end, to),
    cutBefore: from > 0,
    cutAfter: to < text.length,
  };
}

/** Every match in the lines, in order, up to `cap`. Empty matches (`a*` between letters) are skipped. */
export function findInLines(lines: LogicalLine[], pattern: RegExp, cap = MAX_PER_PANE): PaneHits {
  const global = pattern.global ? pattern : new RegExp(pattern.source, `${pattern.flags}g`);
  const hits: LineHit[] = [];
  let longLines = 0;
  for (const line of lines) {
    let text = line.text;
    if (text.length > MAX_LINE_CHARS) {
      longLines += 1;
      text = text.slice(0, MAX_LINE_CHARS);
    }
    global.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = global.exec(text)) !== null) {
      if (m[0].length === 0) {
        global.lastIndex += 1;
        continue;
      }
      if (hits.length >= cap) return { hits, capped: true, longLines };
      hits.push({
        row: line.row,
        start: m.index,
        end: m.index + m[0].length,
        matched: m[0],
        probe: line.text.slice(0, PROBE_CHARS),
        ...excerpt(text, m.index, m.index + m[0].length),
      });
    }
  }
  return { hits, capped: false, longLines };
}

/** The line a match was found in, as the buffer holds it now: at `expectedRow`, or the nearest with the same start
 * and the same text at the match. null when it is gone (scrolled out of the scrollback, or cleared). */
export function relocate(lines: LogicalLine[], hit: LineHit, expectedRow: number): LogicalLine | null {
  const fits = (l: LogicalLine) => l.text.startsWith(hit.probe) && l.text.slice(hit.start, hit.end) === hit.matched;
  let best: LogicalLine | null = null;
  for (const line of lines) {
    if (!fits(line)) continue;
    if (!best || Math.abs(line.row - expectedRow) < Math.abs(best.row - expectedRow)) best = line;
  }
  return best;
}

/** Which row of a line holds string offset `offset`, and the offset within that row. An offset at a row edge is the
 * start of the next row, or with `atEnd` (a match's end) the end of the row before. */
export function rowOfOffset(line: Pick<LogicalLine, "starts">, offset: number, atEnd = false) {
  let i = 0;
  while (i + 1 < line.starts.length && (atEnd ? offset > line.starts[i + 1] : offset >= line.starts[i + 1])) i += 1;
  return { rowIndex: i, offset: offset - line.starts[i] };
}

/** One terminal's matches, with where it is. */
export interface PaneResult {
  tabKey: string;
  /** The tab's title. */
  title: string;
  paneKey: string;
  /** The pane's own name, shown when its tab is split into several. */
  paneName: string;
  hits: LineHit[];
  capped: boolean;
  longLines: number;
}

export interface TabGroup {
  tabKey: string;
  title: string;
  count: number;
  /** Its panes that matched, in the tab's order. */
  panes: PaneResult[];
  /** Some of its matches were left out. */
  capped: boolean;
}

export interface SearchSummary {
  groups: TabGroup[];
  total: number;
  /** A terminal had more than MAX_PER_PANE matches, or all of them more than MAX_TOTAL. */
  capped: boolean;
  longLines: number;
  /** Terminals searched. */
  searched: number;
}

/** The matches grouped by tab, in tab order, cut at `totalCap` over all of them. */
export function groupByTab(results: PaneResult[], totalCap = MAX_TOTAL): SearchSummary {
  const groups: TabGroup[] = [];
  let total = 0;
  let capped = false;
  let longLines = 0;
  for (const result of results) {
    longLines += result.longLines;
    if (result.capped) capped = true;
    if (result.hits.length === 0) continue;
    const room = totalCap - total;
    if (room <= 0) {
      capped = true;
      continue;
    }
    const hits = result.hits.slice(0, room);
    const cut = result.capped || hits.length < result.hits.length;
    if (hits.length < result.hits.length) capped = true;
    total += hits.length;
    let group = groups.find((g) => g.tabKey === result.tabKey);
    if (!group) {
      group = { tabKey: result.tabKey, title: result.title, count: 0, panes: [], capped: false };
      groups.push(group);
    }
    group.panes.push({ ...result, hits, capped: cut });
    group.count += hits.length;
    group.capped ||= cut;
  }
  return { groups, total, capped, longLines, searched: results.length };
}

function count(n: number, word: string) {
  return `${n.toLocaleString("en-GB")} ${word}${n === 1 ? "" : "es"}`;
}

/** "37 matches in 4 tabs", and what was cut. */
export function summaryText(summary: SearchSummary): string {
  if (summary.searched === 0) return "No terminal is open";
  if (summary.total === 0) {
    return summary.searched === 1 ? "No matches in the terminal" : `No matches in ${summary.searched} terminals`;
  }
  const tabs = summary.groups.length === 1 ? "1 tab" : `${summary.groups.length} tabs`;
  const text = `${count(summary.total, "match")} in ${tabs}`;
  if (!summary.capped) return text;
  return summary.total >= MAX_TOTAL
    ? `${text}: the first ${MAX_TOTAL.toLocaleString("en-GB")} shown, there are more`
    : `${text}: at most ${MAX_PER_PANE} shown for each terminal, some have more`;
}

/** A note on lines too long to search whole, or null. */
export function longLinesText(summary: SearchSummary): string | null {
  if (summary.longLines === 0) return null;
  const lines = summary.longLines === 1 ? "1 line was" : `${summary.longLines} lines were`;
  return `${lines} longer than ${MAX_LINE_CHARS.toLocaleString("en-GB")} characters: only their start was searched`;
}
