// QL-18 search all terminals, the xterm.js side: a terminal's buffer read once into rows of text for
// scrollback-search.ts, and a match shown: scrolled into view and highlighted with a decoration that stays on its line
// as more output comes (the search addon would search again on every write, and select, which copies with
// copy-on-select on).
//
// Rows are read the way xterm.js's own search reads them (a wide character is one character; the empty cell left at a
// row's end when a wide character didn't fit is not text), so the offsets found map back to the same cells. A marker
// set at the cursor when the buffer is read tells how many lines scrolled out of the scrollback since, so a match is
// found again where its line is now; when that line changed or went (the screen was cleared, the pane was resized and
// the lines reflowed), the nearest line with the same start and the same matched text is used, or the panel says it
// is gone. Tested against a stand-in terminal in scrollback-xterm.test.ts (xterm.js itself needs a DOM).

import type { IBufferLine, IDisposable, IMarker, Terminal } from "@xterm/xterm";
import {
  findInLines,
  joinRows,
  relocate,
  rowOfOffset,
  type LineHit,
  type LogicalLine,
  type PaneHits,
  type RowText,
} from "./scrollback-search.ts";

/** The highlight of a match jumped to: the search addon's active match colour. */
const REVEAL_BACKGROUND = "#ff9632";
const REVEAL_FOREGROUND = "#000000";
/** Rows of one match highlighted at most (a match is at most MAX_LINE_CHARS characters). */
const MAX_REVEAL_ROWS = 50;

/** One buffer read for a search: the terminal it read, and where its cursor line was then. */
export interface ScrollbackScan {
  term: Terminal;
  anchor: IMarker | null;
  anchorLine: number;
  hits: PaneHits;
}

/** A row's text as xterm.js's search reads it. */
function rowText(line: IBufferLine, next: IBufferLine | undefined): string {
  let text = line.translateToString(false);
  if (next?.isWrapped && text.length > 0) {
    const last = line.getCell(line.length - 1);
    if (last && last.getCode() === 0 && last.getWidth() === 1 && next.getCell(0)?.getWidth() === 2) {
      text = text.slice(0, -1);
    }
  }
  return text;
}

/** Every row of the terminal's buffer on screen (scrollback and screen). */
export function readRows(term: Terminal): RowText[] {
  const buffer = term.buffer.active;
  const rows: RowText[] = [];
  for (let y = 0; y < buffer.length; y++) {
    const line = buffer.getLine(y);
    rows.push(
      line ? { text: rowText(line, buffer.getLine(y + 1)), wrapped: line.isWrapped } : { text: "", wrapped: false },
    );
  }
  return rows;
}

/** Reads the buffer once and finds the matches. Dispose the old scan's anchor first (`endScan`). */
export function scanTerminal(term: Terminal, pattern: RegExp): ScrollbackScan {
  const buffer = term.buffer.active;
  let anchor: IMarker | null = null;
  try {
    anchor = term.registerMarker(0) ?? null;
  } catch {
    // No marker on this buffer: matches are found again by their text alone.
  }
  return {
    term,
    anchor,
    anchorLine: anchor?.line ?? buffer.baseY + buffer.cursorY,
    hits: findInLines(joinRows(readRows(term)), pattern),
  };
}

export function endScan(scan: ScrollbackScan | null) {
  scan?.anchor?.dispose();
}

/** The cell column of string offset `offset` in a row (after its last cell when the offset is at its end). */
function columnOf(line: IBufferLine, offset: number): number {
  let units = 0;
  let col = 0;
  while (col < line.length) {
    const cell = line.getCell(col);
    if (!cell) break;
    const width = cell.getWidth();
    if (width === 0) {
      col += 1;
      continue;
    }
    if (units >= offset) return col;
    units += (cell.getChars() || " ").length;
    col += width;
  }
  return col;
}

/** The line at `row` of the buffer, joined like a scan joins it, if a line starts there. */
function lineAt(term: Terminal, row: number): LogicalLine | null {
  const buffer = term.buffer.active;
  const first = buffer.getLine(row);
  if (!first || first.isWrapped) return null;
  const rows: RowText[] = [];
  for (let y = row; y < buffer.length; y++) {
    const line = buffer.getLine(y);
    if (!line || (y > row && !line.isWrapped)) break;
    rows.push({ text: rowText(line, buffer.getLine(y + 1)), wrapped: y > row });
  }
  return joinRows(rows, row)[0] ?? null;
}

/**
 * Scrolls the terminal to a match of the scan and highlights it. Returns what to dispose to take the highlight off, or
 * why it can't be shown.
 */
export function revealHit(term: Terminal, scan: ScrollbackScan, hit: LineHit): IDisposable[] | string {
  if (scan.term !== term) return "This terminal changed since the search (presenting started or stopped): search again";
  const buffer = term.buffer.active;
  const moved = scan.anchor && !scan.anchor.isDisposed ? scan.anchorLine - scan.anchor.line : null;
  const expected = hit.row - (moved ?? 0);
  let line = lineAt(term, expected);
  const same = (l: LogicalLine | null) =>
    l !== null && l.text.startsWith(hit.probe) && l.text.slice(hit.start, hit.end) === hit.matched;
  if (!same(line)) line = relocate(joinRows(readRows(term)), hit, expected);
  if (!line) return "That line is no longer in the terminal's scrollback: search again";

  const start = rowOfOffset(line, hit.start);
  const end = rowOfOffset(line, hit.end, true);
  const startRow = line.row + start.rowIndex;
  const endRow = line.row + end.rowIndex;
  const startLine = buffer.getLine(startRow);
  const endLine = buffer.getLine(endRow);
  if (!startLine || !endLine) return "That line is no longer in the terminal's scrollback: search again";
  const startCol = columnOf(startLine, start.offset);
  const endCol = columnOf(endLine, end.offset);

  if (startRow < buffer.viewportY || endRow >= buffer.viewportY + term.rows) {
    term.scrollToLine(Math.max(0, startRow - Math.floor(term.rows / 3)));
  }
  const cursor = buffer.baseY + buffer.cursorY;
  const shown: IDisposable[] = [];
  for (let r = startRow; r <= endRow && r < startRow + MAX_REVEAL_ROWS; r++) {
    let marker: IMarker | undefined;
    try {
      marker = term.registerMarker(r - cursor);
    } catch {
      marker = undefined;
    }
    if (!marker) continue;
    shown.push(marker);
    const x = r === startRow ? startCol : 0;
    const to = r === endRow ? endCol : term.cols;
    const decoration = term.registerDecoration({
      marker,
      x,
      width: Math.max(1, to - x),
      backgroundColor: REVEAL_BACKGROUND,
      foregroundColor: REVEAL_FOREGROUND,
      layer: "top",
    });
    if (decoration) shown.push(decoration);
  }
  return shown;
}
