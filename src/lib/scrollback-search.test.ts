/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compileSearch,
  excerpt,
  findInLines,
  groupByTab,
  joinRows,
  longLinesText,
  MAX_LINE_CHARS,
  MAX_PER_PANE,
  MAX_TOTAL,
  relocate,
  rowOfOffset,
  summaryText,
  type LineHit,
  type PaneResult,
  type RowText,
} from "./scrollback-search.ts";

const row = (text: string, wrapped = false): RowText => ({ text, wrapped });

function pattern(query: string, caseSensitive = false, regex = false): RegExp {
  const compiled = compileSearch(query, { caseSensitive, regex });
  assert.ok(compiled && compiled.ok, `${query} compiles`);
  return compiled.pattern;
}

test("plain text is matched literally, with or without case", () => {
  const lines = joinRows([row("ERROR: disk /dev/sda1 (95%)"), row("error again"), row("a.b+c")]);
  assert.equal(findInLines(lines, pattern("error")).hits.length, 2);
  assert.equal(findInLines(lines, pattern("error", true)).hits.length, 1);
  assert.equal(findInLines(lines, pattern("(95%)")).hits[0].matched, "(95%)");
  assert.equal(findInLines(lines, pattern("a.b+")).hits.length, 1, "dots and pluses are plain characters");
  assert.equal(compileSearch("", { caseSensitive: false, regex: true }), null);
});

test("a regular expression is used as JavaScript reads it, and an invalid one says why", () => {
  const lines = joinRows([row("web01 up 3 days"), row("web02 down"), row("db01 up")]);
  const hits = findInLines(lines, pattern("^web\\d+ (up|down)", false, true)).hits;
  assert.deepEqual(
    hits.map((h) => h.matched),
    ["web01 up", "web02 down"],
  );
  const bad = compileSearch("(unclosed", { caseSensitive: false, regex: true });
  assert.ok(bad && !bad.ok);
  assert.match(bad.error, /^Not a valid regular expression: /);
  // Empty matches are skipped rather than looping forever.
  assert.deepEqual(
    findInLines(lines, pattern("x*", false, true)).hits.map((h) => h.matched),
    [],
  );
});

test("wrapped rows are one line, so a match across a row edge is found where it starts", () => {
  const rows = [row("$ tail log"), row("connection refu"), row("sed by peer   ", true), row("next")];
  const lines = joinRows(rows, 100);
  assert.deepEqual(
    lines.map((l) => [l.row, l.text, l.starts]),
    [
      [100, "$ tail log", [0]],
      [101, "connection refused by peer", [0, 15]],
      [103, "next", [0]],
    ],
  );
  const [hit] = findInLines(lines, pattern("refused")).hits;
  assert.equal(hit.row, 101);
  assert.deepEqual([hit.start, hit.end], [11, 18]);
  assert.deepEqual(rowOfOffset(lines[1], hit.start), { rowIndex: 0, offset: 11 });
  assert.deepEqual(rowOfOffset(lines[1], hit.end, true), { rowIndex: 1, offset: 3 });
  // At a row edge: the next row's start for a match's start, the row before's end for its end.
  assert.deepEqual(rowOfOffset(lines[1], 15), { rowIndex: 1, offset: 0 });
  assert.deepEqual(rowOfOffset(lines[1], 15, true), { rowIndex: 0, offset: 15 });
});

test("wide characters are one character each", () => {
  const lines = joinRows([row("日本語のログ error")]);
  const [hit] = findInLines(lines, pattern("error")).hits;
  assert.equal(hit.start, 7);
  assert.equal(hit.before, "日本語のログ ");
});

test("matches are capped per terminal and long lines are searched only so far", () => {
  const rows = Array.from({ length: MAX_PER_PANE + 50 }, (_, i) => row(`line ${i} ok`));
  const many = findInLines(joinRows(rows), pattern("ok"));
  assert.equal(many.hits.length, MAX_PER_PANE);
  assert.equal(many.capped, true);
  const exactly = findInLines(joinRows(rows.slice(0, MAX_PER_PANE)), pattern("ok"));
  assert.equal(exactly.capped, false, "exactly the cap is not cut");

  const long = `${"x".repeat(MAX_LINE_CHARS)}needle`;
  const found = findInLines(joinRows([row(long), row("needle")]), pattern("needle"));
  assert.equal(found.hits.length, 1, "the needle past the limit is not searched");
  assert.equal(found.longLines, 1);
});

test("an excerpt shows the match with some of its line around it", () => {
  const text = `${"a".repeat(100)}MATCH${"b".repeat(200)}`;
  const e = excerpt(text, 100, 105);
  assert.equal(e.shown, "MATCH");
  assert.equal(e.before.length, 40);
  assert.equal(e.after.length, 120);
  assert.ok(e.cutBefore && e.cutAfter);
  assert.deepEqual(excerpt("short ok", 6, 8), {
    before: "short ",
    shown: "ok",
    after: "",
    cutBefore: false,
    cutAfter: false,
  });
  assert.ok(excerpt("y".repeat(500), 0, 500).shown.endsWith("…"));
});

test("a match is found again after more output moved its line, or not at all once it is gone", () => {
  const before = joinRows([row("boot"), row("ERROR disk full"), row("ok")]);
  const [hit] = findInLines(before, pattern("disk")).hits;
  // Two lines scrolled out of the scrollback: the line is now at row 0, not 1.
  const after = joinRows([row("ERROR disk full"), row("ok"), row("more"), row("ERROR disk full")]);
  assert.equal(relocate(after, hit, 1)?.row, 0, "the nearest copy of the line");
  assert.equal(relocate(after, hit, 3)?.row, 3);
  assert.equal(relocate(joinRows([row("cleared")]), hit, 1), null);
});

function result(tabKey: string, paneKey: string, n: number, capped = false): PaneResult {
  const hits: LineHit[] = Array.from({ length: n }, (_, i) => ({
    row: i,
    start: 0,
    end: 1,
    matched: "x",
    probe: "x",
    before: "",
    shown: "x",
    after: "",
    cutBefore: false,
    cutAfter: false,
  }));
  return { tabKey, title: `tab ${tabKey}`, paneKey, paneName: paneKey, hits, capped, longLines: 0 };
}

test("results are grouped by tab in tab order, with a count each", () => {
  const summary = groupByTab([
    result("t1", "p1", 3),
    result("t2", "p2", 0),
    result("t3", "p3", 2),
    result("t3", "p4", 1),
  ]);
  assert.deepEqual(
    summary.groups.map((g) => [g.tabKey, g.count, g.panes.length]),
    [
      ["t1", 3, 1],
      ["t3", 3, 2],
    ],
  );
  assert.equal(summary.total, 6);
  assert.equal(summary.searched, 4);
  assert.equal(summaryText(summary), "6 matches in 2 tabs");
  assert.equal(summaryText(groupByTab([result("t1", "p1", 1)])), "1 match in 1 tab");
  assert.equal(summaryText(groupByTab([result("t1", "p1", 0), result("t2", "p2", 0)])), "No matches in 2 terminals");
  assert.equal(summaryText(groupByTab([])), "No terminal is open");
});

test("results are capped in all, and the summary says what was cut", () => {
  const panes = Array.from({ length: 12 }, (_, i) => result(`t${i}`, `p${i}`, MAX_PER_PANE));
  const summary = groupByTab(panes);
  assert.equal(summary.total, MAX_TOTAL);
  assert.equal(summary.groups.length, MAX_TOTAL / MAX_PER_PANE);
  assert.ok(summary.capped);
  assert.match(summaryText(summary), /the first 2,000 shown, there are more/);

  const one = groupByTab([result("t1", "p1", MAX_PER_PANE, true), result("t2", "p2", 4)]);
  assert.ok(one.capped && one.groups[0].capped && !one.groups[1].capped);
  assert.match(summaryText(one), /at most 200 shown for each terminal/);
  assert.equal(longLinesText(one), null);
  assert.match(longLinesText({ ...one, longLines: 2 }) ?? "", /2 lines were longer than 4,000 characters/);
});
