// QL-17 highlights in one xterm.js terminal: what the pane's rules match, coloured with xterm decorations (drawn by
// the WebGL renderer as well as the DOM one). The pure part (matching, cells, colours) is highlight-rules.ts.
//
// Never the whole scrollback on each write: after each write is parsed, only the lines the cursor has moved past since
// last time are matched, from a marker at the first unchecked line (so trimming the scrollback can't confuse it),
// wrapped rows joined into one logical line. A line the host erases (CSI J, CSI K: `clear`, a progress line drawn
// again) loses its decorations and is matched again once the cursor has passed it again; so is a line the cursor
// went back up to. Only the normal screen: a full-screen program's (the alternate screen) is never matched, and the
// decorations hide while it is open. At most MAX_DECORATIONS per terminal (the oldest go), and matching may take at
// most BUDGET_MS_PER_SECOND each second: past that, highlighting pauses in that terminal for PAUSE_MS (the pane says
// so) and skips what was printed meanwhile.
//
// FD-03: a presenting pane's masked terminal has a highlighter of its own, which matches the masked text, so a rule
// naming a real host never lights up its stand-in.

import type { IBufferLine, IDecoration, IDisposable, IMarker, Terminal } from "@xterm/xterm";
import {
  Budget,
  cellMap,
  lookOf,
  matchLine,
  MAX_DECORATIONS,
  PAUSE_MS,
  RECHECK_LINES,
  SLICE_MS,
  spansOf,
  type CompiledRule,
  type RowCells,
} from "@/lib/highlight-rules";
import type { ResolvedTheme } from "@/lib/theme";

/** One coloured span: its own marker (so it follows its line), its cells, and the rule that coloured it. */
interface Painted {
  marker: IMarker;
  col: number;
  width: number;
  rule: CompiledRule;
  decoration: IDecoration | undefined;
}

/** How long after the last resize the lines on screen are matched again (a drag sends many). */
const RESIZE_SETTLE_MS = 200;

export class Highlighter {
  private readonly term: Terminal;
  private readonly onPaused: (paused: boolean) => void;
  private rules: CompiledRule[] = [];
  private theme: ResolvedTheme;
  /** The first line not matched yet. */
  private next: IMarker | null = null;
  private painted: Painted[] = [];
  /** The highest line painted on (it can only be too high, after the scrollback was trimmed). */
  private highest = -1;
  private readonly listeners: IDisposable[] = [];
  private readonly budget = new Budget();
  private paused = false;
  private pauseTimer: number | null = null;
  private continueTimer: number | null = null;
  private resizeTimer: number | null = null;
  private disposed = false;

  constructor(term: Terminal, theme: ResolvedTheme, onPaused: (paused: boolean) => void) {
    this.term = term;
    this.theme = theme;
    this.onPaused = onPaused;
    this.listeners.push(
      term.onWriteParsed(() => this.check()),
      // Returning false lets xterm.js erase as usual, after the decorations there went.
      term.parser.registerCsiHandler({ final: "J" }, (params) => this.erased("J", params)),
      term.parser.registerCsiHandler({ prefix: "?", final: "J" }, (params) => this.erased("J", params)),
      term.parser.registerCsiHandler({ final: "K" }, (params) => this.erased("K", params)),
      term.parser.registerCsiHandler({ prefix: "?", final: "K" }, (params) => this.erased("K", params)),
      term.buffer.onBufferChange((buffer) => (buffer.type === "alternate" ? this.hide() : this.show())),
      term.onResize(() => this.recheckSoon()),
    );
  }

  /** New rules: what was painted goes, and the lines up to RECHECK_LINES above the cursor are matched again. */
  setRules(rules: CompiledRule[]) {
    if (this.disposed) return;
    this.clear();
    this.rules = rules;
    if (rules.length > 0) this.recheck();
  }

  setTheme(theme: ResolvedTheme) {
    if (this.disposed || theme === this.theme) return;
    this.theme = theme;
    if (!this.normal) return;
    for (const p of this.painted) {
      p.decoration?.dispose();
      p.decoration = undefined;
      this.paint(p);
    }
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    for (const timer of [this.pauseTimer, this.continueTimer, this.resizeTimer]) {
      if (timer !== null) window.clearTimeout(timer);
    }
    this.listeners.forEach((l) => l.dispose());
    this.clear();
    if (this.paused) this.onPaused(false);
  }

  // ---- lines ----

  private get normal() {
    return this.term.buffer.active.type === "normal";
  }

  private cursorLine() {
    const buffer = this.term.buffer.active;
    return buffer.baseY + buffer.cursorY;
  }

  /** The first row of the logical line row `y` belongs to. */
  private lineStart(y: number) {
    const buffer = this.term.buffer.active;
    let row = Math.max(0, y);
    while (row > 0 && buffer.getLine(row)?.isWrapped) row--;
    return row;
  }

  private nextLine() {
    return this.next && !this.next.isDisposed ? this.next.line : 0;
  }

  private setNext(line: number) {
    const at = Math.max(0, line);
    if (this.next && !this.next.isDisposed && this.next.line === at) return;
    this.next?.dispose();
    this.next = null;
    if (!this.normal) return;
    this.next = this.term.registerMarker(at - this.cursorLine()) ?? null;
  }

  /** Matches again from RECHECK_LINES above the cursor. */
  private recheck() {
    if (!this.normal || this.rules.length === 0) return;
    this.dropPainted(0, Number.MAX_SAFE_INTEGER);
    this.setNext(this.lineStart(this.cursorLine() - RECHECK_LINES));
    this.check();
  }

  private recheckSoon() {
    if (this.rules.length === 0) return;
    if (this.resizeTimer !== null) window.clearTimeout(this.resizeTimer);
    this.resizeTimer = window.setTimeout(() => {
      this.resizeTimer = null;
      this.recheck();
    }, RESIZE_SETTLE_MS);
  }

  /** Matches the lines the cursor has moved past since last time, for at most SLICE_MS. */
  private check() {
    if (this.disposed || this.paused || this.rules.length === 0 || !this.normal) return;
    const buffer = this.term.buffer.active;
    const end = this.lineStart(this.cursorLine());
    let row = this.lineStart(this.nextLine());
    if (row > end) {
      // The cursor went back up (cleared, or a line drawn again): from its line on, once it has passed it again.
      this.setNext(end);
      return;
    }
    if (row === end) return;
    const started = performance.now();
    // Lines matched again (the cursor went back over them) lose what they had first.
    if (row <= this.highest) this.dropPainted(row, end - 1);
    while (row < end) {
      const rows: number[] = [row];
      while (row + rows.length < end && buffer.getLine(row + rows.length)?.isWrapped) rows.push(row + rows.length);
      this.matchRows(rows);
      row += rows.length;
      if (performance.now() - started > SLICE_MS && row < end) break;
    }
    this.setNext(row);
    const spent = performance.now() - started;
    if (this.budget.spend(spent, Date.now())) {
      this.pause();
      return;
    }
    if (row < end && this.continueTimer === null) {
      this.continueTimer = window.setTimeout(() => {
        this.continueTimer = null;
        this.check();
      }, 0);
    }
  }

  /** One logical line: its rows' text, matched; when something matches, its cells, matched again on them. */
  private matchRows(rows: number[]) {
    const buffer = this.term.buffer.active;
    const lines: IBufferLine[] = [];
    for (const y of rows) {
      const line = buffer.getLine(y);
      if (!line) return;
      lines.push(line);
    }
    const text = lines.map((line, i) => line.translateToString(i === lines.length - 1)).join("");
    if (!text.trim() || matchLine(text, this.rules).length === 0) return;
    const cell = buffer.getNullCell();
    const cells: RowCells[] = lines.map((line) => {
      const row: RowCells = { chars: [], widths: [] };
      for (let x = 0; x < line.length; x++) {
        line.getCell(x, cell);
        row.chars.push(cell.getChars());
        row.widths.push(cell.getWidth());
      }
      return row;
    });
    const mapped = cellMap(cells);
    for (const range of matchLine(mapped.text.trimEnd(), this.rules)) {
      const rule = this.rules[range.rule];
      for (const span of spansOf(mapped.at, range.start, range.end)) {
        const y = rows[span.row];
        if (y !== undefined) this.decorate(y, span.col, span.width, rule);
      }
    }
  }

  // ---- decorations ----

  private decorate(y: number, col: number, width: number, rule: CompiledRule) {
    const marker = this.term.registerMarker(y - this.cursorLine());
    if (!marker) return;
    const p: Painted = { marker, col, width, rule, decoration: undefined };
    this.painted.push(p);
    this.highest = Math.max(this.highest, y);
    this.paint(p);
    while (this.painted.length > MAX_DECORATIONS) this.painted.shift()?.marker.dispose();
  }

  private paint(p: Painted) {
    if (p.marker.isDisposed || !this.normal) return;
    const look = lookOf(p.rule.color, p.rule.style, this.theme);
    p.decoration = this.term.registerDecoration({
      marker: p.marker,
      x: p.col,
      width: p.width,
      foregroundColor: look.foreground,
      ...(look.background ? { backgroundColor: look.background } : {}),
      // Under the selection, so a selection over a highlight still shows.
      layer: "bottom",
    });
  }

  /** Removes what was painted on lines `from` to `to` (and anything whose line was trimmed away). */
  private dropPainted(from: number, to: number) {
    if (this.painted.length === 0 || from > this.highest) return;
    this.painted = this.painted.filter((p) => {
      const line = p.marker.isDisposed ? -1 : p.marker.line;
      if (line >= 0 && (line < from || line > to)) return true;
      p.marker.dispose();
      return false;
    });
    if (from === 0 && to === Number.MAX_SAFE_INTEGER) this.highest = -1;
  }

  private clear() {
    for (const p of this.painted) p.marker.dispose();
    this.painted = [];
    this.highest = -1;
    this.next?.dispose();
    this.next = null;
  }

  /** CSI J or K is about to erase: what was painted there goes, and it is matched again once the cursor passes. */
  private erased(final: "J" | "K", params: (number | number[])[]): boolean {
    if (this.disposed || this.rules.length === 0 || !this.normal) return false;
    const first = params[0];
    const mode = typeof first === "number" ? first : 0;
    const buffer = this.term.buffer.active;
    const cursor = this.cursorLine();
    let from = cursor;
    let to = cursor;
    if (final === "J") {
      const top = buffer.baseY;
      const bottom = top + this.term.rows - 1;
      if (mode === 0) to = bottom;
      else if (mode === 1) from = top;
      else if (mode === 2) [from, to] = [top, bottom];
      // 3 clears the scrollback: its markers go with its lines.
      else return false;
    }
    if (from <= this.highest) this.dropPainted(from, to);
    if (from < this.nextLine()) this.setNext(this.lineStart(from));
    return false;
  }

  /** A full-screen program took the screen: the decorations hide (their lines stay marked). */
  private hide() {
    for (const p of this.painted) {
      p.decoration?.dispose();
      p.decoration = undefined;
    }
  }

  /** Back on the normal screen: the decorations show again, and what was printed meanwhile is matched. */
  private show() {
    this.painted = this.painted.filter((p) => !p.marker.isDisposed);
    for (const p of this.painted) this.paint(p);
    this.check();
  }

  // ---- the time budget ----

  private pause() {
    this.paused = true;
    this.onPaused(true);
    if (this.pauseTimer !== null) window.clearTimeout(this.pauseTimer);
    this.pauseTimer = window.setTimeout(() => {
      this.pauseTimer = null;
      this.paused = false;
      this.budget.reset();
      this.onPaused(false);
      // What was printed during the pause is not matched.
      if (this.normal) this.setNext(this.lineStart(this.cursorLine()));
      this.check();
    }, PAUSE_MS);
  }
}
