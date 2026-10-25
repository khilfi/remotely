// QL-17 highlight rules, the pure part (terminal-highlights.ts draws them in xterm.js; tested in
// highlight-rules.test.ts): which rules apply to a pane, compiling them, matching one logical line to coloured
// ranges, mapping those ranges to the cells they cover, the colours per theme, and the editor's local pattern check.
//
// The core checks every pattern (crates/core/src/terminal/rules.rs): a subset that Rust's regex crate and JavaScript
// with the `u` flag read alike, without nested repeats, which JavaScript's backtracking can take exponential time on.
// Here a pattern is compiled with the `u` flag (and `i` unless it matches case); one that doesn't compile is left out.

import type { Environment, RuleStyle, SessionColor, TerminalRule } from "./api.ts";
import type { ResolvedTheme } from "./theme.ts";

/** A line is matched on this many characters, its start (as the core matches alerts). */
export const MAX_MATCHED_CHARS = 2000;
/** The most decorations one terminal keeps; past that the oldest go (xterm.js keeps an element for each one shown). */
export const MAX_DECORATIONS = 1000;
/** The most matches one line gets decorated. */
export const MAX_MATCHES_PER_LINE = 50;
/** One check of new lines stops after this long and goes on in a moment, so a flood of output never holds the page. */
export const SLICE_MS = 8;
/** Matching may take this long in any second; more pauses highlighting in that terminal for PAUSE_MS. */
export const BUDGET_MS_PER_SECOND = 150;
export const PAUSE_MS = 5000;
/** After the rules change, this many lines up from the cursor are matched again (never the whole scrollback). */
export const RECHECK_LINES = 1000;
/** The longest pattern the core takes, in characters. */
export const MAX_PATTERN_CHARS = 200;

/** A rule ready to match: its regular expression and how it looks. */
export interface CompiledRule {
  id: string;
  regex: RegExp;
  color: SessionColor;
  style: RuleStyle;
}

/** A match on one logical line: string offsets [start, end) and the rule's index. */
export interface MatchRange {
  start: number;
  end: number;
  rule: number;
}

/** Where one character of a logical line sits: the row (from the line's first), the column, and its width. */
export interface CellAt {
  row: number;
  col: number;
  width: number;
}

/** A decoration's place: a row of the logical line, its first column and its width in cells. */
export interface CellSpan {
  row: number;
  col: number;
  width: number;
}

/** The colours a decoration uses, as xterm.js wants them (#RRGGBB). */
export interface Look {
  foreground: string;
  background: string | null;
}

/** Text colour per theme, and a fill with the text colour drawn on it. */
const PALETTE: Record<
  SessionColor,
  { text: Record<ResolvedTheme, string>; fill: Record<ResolvedTheme, string>; on: string }
> = {
  red: { text: { light: "#dc2626", dark: "#f87171" }, fill: { light: "#dc2626", dark: "#b91c1c" }, on: "#ffffff" },
  orange: { text: { light: "#c2410c", dark: "#fb923c" }, fill: { light: "#ea580c", dark: "#c2410c" }, on: "#ffffff" },
  amber: { text: { light: "#b45309", dark: "#fbbf24" }, fill: { light: "#f59e0b", dark: "#d97706" }, on: "#1f1f1f" },
  green: { text: { light: "#15803d", dark: "#4ade80" }, fill: { light: "#16a34a", dark: "#15803d" }, on: "#ffffff" },
  teal: { text: { light: "#0f766e", dark: "#2dd4bf" }, fill: { light: "#0d9488", dark: "#0f766e" }, on: "#ffffff" },
  blue: { text: { light: "#1d4ed8", dark: "#60a5fa" }, fill: { light: "#2563eb", dark: "#1d4ed8" }, on: "#ffffff" },
  violet: { text: { light: "#6d28d9", dark: "#a78bfa" }, fill: { light: "#7c3aed", dark: "#6d28d9" }, on: "#ffffff" },
  pink: { text: { light: "#be185d", dark: "#f472b6" }, fill: { light: "#db2777", dark: "#be185d" }, on: "#ffffff" },
  slate: { text: { light: "#475569", dark: "#94a3b8" }, fill: { light: "#64748b", dark: "#475569" }, on: "#ffffff" },
};

/** The colours a rule draws with in a theme. */
export function lookOf(color: SessionColor, style: RuleStyle, theme: ResolvedTheme): Look {
  const p = PALETTE[color];
  return style === "fill"
    ? { foreground: p.on, background: p.fill[theme] }
    : { foreground: p.text[theme], background: null };
}

/** Whether a rule's scope covers a terminal of this saved session (null: not saved) with this label. */
export function appliesTo(rule: TerminalRule, sessionId: string | null, environment: Environment): boolean {
  switch (rule.scope.kind) {
    case "global":
      return true;
    case "environment":
      return environment !== "none" && rule.scope.environment === environment;
    case "session":
      return sessionId !== null && rule.scope.sessionId === sessionId;
  }
}

/** The rules that highlight in a terminal: on, with a colour, usable, and scoped to it; in list order. */
export function rulesForPane(
  rules: TerminalRule[],
  sessionId: string | null,
  environment: Environment,
): TerminalRule[] {
  return rules.filter(
    (r) => r.enabled && r.color !== null && r.problem === null && appliesTo(r, sessionId, environment),
  );
}

/** A key that changes when anything a pane draws with changes (so setting the same rules again does nothing). */
export function rulesKey(rules: TerminalRule[]): string {
  return rules.map((r) => [r.id, r.pattern, r.caseSensitive ? 1 : 0, r.color, r.style].join("\u0000")).join("\u0001");
}

/** The rules compiled for JavaScript; a pattern that doesn't compile here is left out. */
export function compileRules(rules: TerminalRule[]): CompiledRule[] {
  const out: CompiledRule[] = [];
  for (const rule of rules) {
    if (rule.color === null) continue;
    try {
      out.push({
        id: rule.id,
        regex: new RegExp(rule.pattern, rule.caseSensitive ? "gu" : "giu"),
        color: rule.color,
        style: rule.style,
      });
    } catch {
      // The core took it, this engine didn't: no highlight rather than a wrong one.
    }
  }
  return out;
}

/**
 * The coloured ranges of one logical line, matched on its first MAX_MATCHED_CHARS characters. A rule earlier in the
 * list wins a character two rules match: a later match that overlaps one already taken is left out. Ordered by start.
 */
export function matchLine(text: string, rules: CompiledRule[]): MatchRange[] {
  const line = text.length > MAX_MATCHED_CHARS ? text.slice(0, MAX_MATCHED_CHARS) : text;
  const taken: MatchRange[] = [];
  rules.forEach((rule, index) => {
    const regex = rule.regex;
    regex.lastIndex = 0;
    let found = 0;
    for (let m = regex.exec(line); m !== null && found < MAX_MATCHES_PER_LINE; m = regex.exec(line)) {
      const start = m.index;
      const end = start + m[0].length;
      if (end === start) {
        // An empty match (the core refuses patterns that can only match empty text): step past it.
        regex.lastIndex = start + 1;
        continue;
      }
      found += 1;
      if (!taken.some((t) => start < t.end && t.start < end)) taken.push({ start, end, rule: index });
    }
    regex.lastIndex = 0;
  });
  return taken.sort((a, b) => a.start - b.start);
}

/**
 * A row's characters as xterm.js holds them: one entry per cell, the cell's text ("" for the second half of a wide
 * character, which takes two cells) and its width (0, 1 or 2). An empty cell reads as a space.
 */
export interface RowCells {
  chars: string[];
  widths: number[];
}

/** Each UTF-16 unit of a logical line made of these rows, and where it sits (wide characters take two cells). */
export function cellMap(rows: RowCells[]): { text: string; at: CellAt[] } {
  let text = "";
  const at: CellAt[] = [];
  rows.forEach((row, r) => {
    for (let col = 0; col < row.widths.length; col++) {
      const width = row.widths[col];
      if (width === 0) continue;
      const chars = row.chars[col] || " ";
      text += chars;
      for (let i = 0; i < chars.length; i++) at.push({ row: r, col, width });
    }
  });
  return { text, at };
}

/** The cells a range of a logical line covers: one span per row it touches. */
export function spansOf(at: CellAt[], start: number, end: number): CellSpan[] {
  const spans: CellSpan[] = [];
  for (let i = start; i < end && i < at.length; i++) {
    const cell = at[i];
    const last = spans[spans.length - 1];
    if (last && last.row === cell.row) {
      const right = Math.max(last.col + last.width, cell.col + cell.width);
      last.width = right - last.col;
    } else {
      spans.push({ row: cell.row, col: cell.col, width: cell.width });
    }
  }
  return spans;
}

/**
 * The editor's own quick check, beside the core's (which says more, and decides): the pattern compiles here (with the
 * u flag), and no group that holds a `+`, `*` or `|` is itself repeated without end, as in (a+)+ or (a|b)*. Null
 * when it looks fine.
 */
export function localPatternProblem(pattern: string): string | null {
  if (!pattern.trim()) return "Type a pattern.";
  if ([...pattern].length > MAX_PATTERN_CHARS) return `A pattern can be at most ${MAX_PATTERN_CHARS} characters.`;
  try {
    new RegExp(pattern, "u");
  } catch (err) {
    return `JavaScript can't read it: ${err instanceof Error ? err.message : String(err)}`;
  }
  if (/\((?:[^()\\]|\\.)*[+*|](?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\})/.test(pattern)) {
    return "Repeats of something that repeats or alternates again, such as (a+)+ or (a|b)*, can make highlighting very slow.";
  }
  return null;
}

/** Time spent matching, per second, to pause a terminal that floods (see BUDGET_MS_PER_SECOND). */
export class Budget {
  private windowStart = 0;
  private spent = 0;

  /** Adds `ms` spent at `now`; true when this second's budget is used up. */
  spend(ms: number, now: number): boolean {
    if (now - this.windowStart >= 1000) {
      this.windowStart = now;
      this.spent = 0;
    }
    this.spent += ms;
    return this.spent > BUDGET_MS_PER_SECOND;
  }

  reset() {
    this.windowStart = 0;
    this.spent = 0;
  }
}
