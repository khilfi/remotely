/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import type { Terminal } from "@xterm/xterm";
import { compileSearch } from "./scrollback-search.ts";
import { endScan, readRows, revealHit, scanTerminal } from "./scrollback-xterm.ts";

// A stand-in for xterm.js's buffer API: rows of cells, a wide character taking two (the second of width 0), and an
// empty cell at a row's end when a wide character did not fit, as xterm.js lays them out.

interface Cell {
  chars: string;
  width: number;
  code: number;
}

const NULL_CELL: Cell = { chars: "", width: 1, code: 0 };
const wide = (c: string) => (c.codePointAt(0) ?? 0) >= 0x3000 && (c.codePointAt(0) ?? 0) <= 0x9fff;

class Line {
  readonly cells: Cell[];
  readonly isWrapped: boolean;
  constructor(cells: Cell[], isWrapped: boolean) {
    this.cells = cells;
    this.isWrapped = isWrapped;
  }
  get length() {
    return this.cells.length;
  }
  getCell(x: number) {
    const c = this.cells[x];
    return c && { getChars: () => c.chars, getWidth: () => c.width, getCode: () => c.code };
  }
  translateToString(trimRight = false) {
    let s = "";
    for (let x = 0; x < this.cells.length; x += this.cells[x].width || 1) s += this.cells[x].chars || " ";
    return trimRight ? s.trimEnd() : s;
  }
}

interface Marker {
  line: number;
  isDisposed: boolean;
  dispose(): void;
}

interface Decoration {
  marker: Marker;
  x: number;
  width: number;
  disposed: boolean;
  dispose(): void;
}

class FakeTerminal {
  lines: Line[] = [];
  markers: Marker[] = [];
  decorations: Decoration[] = [];
  viewportY = 0;
  readonly cols: number;
  readonly rows: number;
  constructor(cols: number, rows: number) {
    this.cols = cols;
    this.rows = rows;
  }

  /** Each text is a line the host printed, wrapped over rows; the cursor ends on the last. */
  print(...texts: string[]) {
    for (const text of texts) {
      let row: Cell[] = [];
      let wrapped = false;
      const flush = () => {
        while (row.length < this.cols) row.push(NULL_CELL);
        this.lines.push(new Line(row, wrapped));
        row = [];
        wrapped = true;
      };
      for (const c of text) {
        const w = wide(c) ? 2 : 1;
        if (row.length + w > this.cols) flush();
        row.push({ chars: c, width: w, code: c.codePointAt(0) ?? 0 });
        if (w === 2) row.push({ chars: "", width: 0, code: 0 });
      }
      flush();
    }
    this.viewportY = this.baseY;
  }

  /** Lines scrolled out of the scrollback: markers move up with their lines, and go with them. */
  trim(n: number) {
    this.lines.splice(0, n);
    for (const m of this.markers) {
      m.line -= n;
      if (m.line < 0) m.isDisposed = true;
    }
  }

  get baseY() {
    return Math.max(0, this.lines.length - this.rows);
  }

  get buffer() {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const term = this;
    return {
      active: {
        get length() {
          return term.lines.length;
        },
        getLine: (y: number) => term.lines[y],
        get baseY() {
          return term.baseY;
        },
        get cursorY() {
          return term.lines.length - 1 - term.baseY;
        },
        get viewportY() {
          return term.viewportY;
        },
      },
    };
  }

  registerMarker(offset = 0): Marker {
    const marker: Marker = {
      line: this.baseY + this.buffer.active.cursorY + offset,
      isDisposed: false,
      dispose() {
        this.isDisposed = true;
      },
    };
    this.markers.push(marker);
    return marker;
  }

  registerDecoration(options: { marker: Marker; x?: number; width?: number }): Decoration {
    const decoration: Decoration = {
      marker: options.marker,
      x: options.x ?? 0,
      width: options.width ?? 1,
      disposed: false,
      dispose() {
        this.disposed = true;
      },
    };
    this.decorations.push(decoration);
    return decoration;
  }

  scrollToLine(y: number) {
    this.viewportY = y;
  }
}

const asTerminal = (t: FakeTerminal) => t as unknown as Terminal;

function search(query: string, regex = false): RegExp {
  const compiled = compileSearch(query, { caseSensitive: false, regex });
  assert.ok(compiled && compiled.ok);
  return compiled.pattern;
}

/** Where the decorations of a reveal are: [row, x, width] each. */
function shown(term: FakeTerminal) {
  return term.decorations.filter((d) => !d.disposed).map((d) => [d.marker.line, d.x, d.width]);
}

test("rows are read with each wide character once, and without the cell a wrapped wide character left", () => {
  const term = new FakeTerminal(7, 4);
  term.print("ab日本語");
  assert.deepEqual(
    term.lines.map((l) => l.cells.length),
    [7, 7],
  );
  // "ab日本" fills 6 cells; 語 does not fit in the 7th, which stays empty.
  assert.deepEqual(readRows(asTerminal(term)), [
    { text: "ab日本", wrapped: false },
    { text: "語     ", wrapped: true },
  ]);
});

test("a match after wide characters is highlighted on its own cells", () => {
  const term = new FakeTerminal(20, 5);
  term.print("$ cat log", "日本語 error here", "ok");
  const scan = scanTerminal(asTerminal(term), search("error"));
  const [hit] = scan.hits.hits;
  assert.deepEqual([hit.row, hit.start, hit.end], [1, 4, 9]);
  const result = revealHit(asTerminal(term), scan, hit);
  assert.ok(Array.isArray(result));
  // 日 本 語 take cells 0 to 5, the space 6: "error" starts at cell 7.
  assert.deepEqual(shown(term), [[1, 7, 5]]);
  for (const d of result) d.dispose();
  assert.deepEqual(shown(term), []);
  endScan(scan);
  assert.ok(scan.anchor?.isDisposed);
});

test("a match across a row edge is highlighted on both rows", () => {
  const term = new FakeTerminal(10, 5);
  term.print("$ dmesg", "connection refused by peer");
  const scan = scanTerminal(asTerminal(term), search("tion refu"));
  const [hit] = scan.hits.hits;
  assert.equal(hit.row, 1);
  assert.ok(Array.isArray(revealHit(asTerminal(term), scan, hit)));
  assert.deepEqual(shown(term), [
    [1, 6, 4],
    [2, 0, 5],
  ]);
});

test("after lines scrolled out of the scrollback, a match is shown where its line is now", () => {
  const term = new FakeTerminal(30, 3);
  term.print("boot", "one", "ERROR disk full", "two", "three");
  const scan = scanTerminal(asTerminal(term), search("disk"));
  const [hit] = scan.hits.hits;
  assert.equal(hit.row, 2);
  term.print("four", "five");
  term.trim(2);
  assert.equal(term.lines[0].translateToString(true), "ERROR disk full");
  term.viewportY = term.baseY;
  assert.ok(Array.isArray(revealHit(asTerminal(term), scan, hit)));
  assert.deepEqual(shown(term), [[0, 6, 4]]);
  assert.equal(term.viewportY, 0, "scrolled up to it");
});

test("a match whose line went, or a terminal that changed, says so", () => {
  const term = new FakeTerminal(30, 3);
  term.print("ERROR disk full", "ok");
  const scan = scanTerminal(asTerminal(term), search("disk"));
  const [hit] = scan.hits.hits;
  term.print(...Array.from({ length: 10 }, (_, i) => `line ${i}`));
  term.trim(5);
  assert.match(String(revealHit(asTerminal(term), scan, hit)), /no longer in the terminal's scrollback/);
  // FD-03: presenting started or stopped, so another terminal is on screen.
  const masked = new FakeTerminal(30, 3);
  masked.print("ERROR disk full");
  assert.match(String(revealHit(asTerminal(masked), scan, hit)), /changed since the search/);
  assert.deepEqual(shown(masked), []);
});
