/// <reference types="node" />
// QL-17: which rules a pane highlights with, matching a line, mapping matches to cells, colours and the editor's own
// pattern check. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { TerminalRule } from "./api.ts";
import {
  BUDGET_MS_PER_SECOND,
  Budget,
  cellMap,
  compileRules,
  localPatternProblem,
  lookOf,
  MAX_MATCHED_CHARS,
  matchLine,
  rulesForPane,
  rulesKey,
  spansOf,
  type RowCells,
} from "./highlight-rules.ts";

const rule = (over: Partial<TerminalRule> = {}): TerminalRule => ({
  id: "r1",
  builtin: false,
  name: "Errors",
  pattern: String.raw`\berror\b`,
  caseSensitive: false,
  color: "red",
  style: "text",
  alert: false,
  scope: { kind: "global" },
  enabled: true,
  problem: null,
  updatedAt: null,
  ...over,
});

test("a pane gets the enabled rules with a colour for its session and label, in list order", () => {
  const rules = [
    rule({ id: "all" }),
    rule({ id: "prod", scope: { kind: "environment", environment: "prod" } }),
    rule({ id: "web", scope: { kind: "session", sessionId: "s-web" } }),
    rule({ id: "off", enabled: false }),
    rule({ id: "alert-only", color: null, alert: true }),
    rule({ id: "broken", problem: "saved by another version" }),
  ];
  const ids = (picked: TerminalRule[]) => picked.map((r) => r.id);
  assert.deepEqual(ids(rulesForPane(rules, "s-web", "prod")), ["all", "prod", "web"]);
  assert.deepEqual(ids(rulesForPane(rules, "s-db", "lab")), ["all"]);
  assert.deepEqual(ids(rulesForPane(rules, null, "none")), ["all"], "a quick connection that was not saved");
});

test("the rules' key changes only with what a pane draws", () => {
  const base = [rule()];
  assert.equal(rulesKey(base), rulesKey([rule()]));
  assert.notEqual(rulesKey(base), rulesKey([rule({ color: "blue" })]));
  assert.notEqual(rulesKey(base), rulesKey([rule({ caseSensitive: true })]));
  assert.notEqual(rulesKey(base), rulesKey([rule({ pattern: "x" })]));
  assert.equal(rulesKey(base), rulesKey([rule({ alert: true, name: "Renamed" })]), "alerts are the core's");
});

test("a line matches as JavaScript reads it, case as the rule says", () => {
  const [errors] = compileRules([rule()]);
  assert.deepEqual(matchLine("ERROR: disk full, error again", [errors]), [
    { start: 0, end: 5, rule: 0 },
    { start: 18, end: 23, rule: 0 },
  ]);
  assert.deepEqual(matchLine("errors and stderr", [errors]), [], "whole words only");
  const [exact] = compileRules([rule({ pattern: "Error", caseSensitive: true })]);
  assert.deepEqual(matchLine("ERROR Error", [exact]), [{ start: 6, end: 11, rule: 0 }]);
  // \w is ASCII in JavaScript, as the core makes it for alerts.
  const [word] = compileRules([rule({ pattern: String.raw`\w+` })]);
  assert.deepEqual(matchLine("café", [word]), [{ start: 0, end: 3, rule: 0 }]);
});

test("the earlier rule wins text two rules match, and only a line's start is matched", () => {
  const compiled = compileRules([
    rule({ id: "a", pattern: "disk full" }),
    rule({ id: "b", pattern: String.raw`full\b.*` }),
    rule({ id: "c", pattern: "again" }),
  ]);
  assert.deepEqual(matchLine("disk full, again", compiled), [
    { start: 0, end: 9, rule: 0 },
    { start: 11, end: 16, rule: 2 },
  ]);
  const late = `${"x".repeat(MAX_MATCHED_CHARS)} error`;
  assert.deepEqual(matchLine(late, compileRules([rule()])), []);
});

test("a pattern JavaScript can't read is left out instead of breaking the others", () => {
  const compiled = compileRules([rule({ id: "bad", pattern: "(unclosed" }), rule({ id: "good" })]);
  assert.deepEqual(
    compiled.map((r) => r.id),
    ["good"],
  );
});

/** A row as xterm.js holds it, from cells written as [text, width]. */
const row = (...cells: [string, number][]): RowCells => ({
  chars: cells.map(([c]) => c),
  widths: cells.map(([, w]) => w),
});
const plain = (text: string, cols = text.length): RowCells =>
  row(...[...text.padEnd(cols, " ")].map((c): [string, number] => [c === " " ? "" : c, 1]));

test("a match maps to the cells it covers, wide characters taking two", () => {
  // "错误 error": two wide characters, each followed by the empty half cell.
  const line = row(["错", 2], ["", 0], ["误", 2], ["", 0], ["", 1], ["e", 1], ["r", 1], ["r", 1], ["o", 1], ["r", 1]);
  const { text, at } = cellMap([line]);
  assert.equal(text, "错误 error");
  const [errors] = compileRules([rule({ pattern: "error" })]);
  const [m] = matchLine(text, [errors]);
  assert.deepEqual(spansOf(at, m.start, m.end), [{ row: 0, col: 5, width: 5 }]);
  const [wide] = matchLine(text, compileRules([rule({ pattern: "误" })]));
  assert.deepEqual(spansOf(at, wide.start, wide.end), [{ row: 0, col: 2, width: 2 }]);
});

test("a match across a wrapped row is one span per row", () => {
  const { text, at } = cellMap([plain("abc ER"), plain("ROR x", 6)]);
  assert.equal(text, "abc ERROR x ");
  const [m] = matchLine(text.trimEnd(), compileRules([rule({ pattern: "ERROR" })]));
  assert.deepEqual(spansOf(at, m.start, m.end), [
    { row: 0, col: 4, width: 2 },
    { row: 1, col: 0, width: 3 },
  ]);
});

test("a character outside the BMP is two UTF-16 units in one cell", () => {
  const { text, at } = cellMap([row(["🔥", 2], ["", 0], ["!", 1])]);
  assert.equal(text.length, 3);
  assert.deepEqual(spansOf(at, 0, 2), [{ row: 0, col: 0, width: 2 }]);
  assert.deepEqual(spansOf(at, 2, 3), [{ row: 0, col: 2, width: 1 }]);
});

test("colours are #RRGGBB for xterm.js, a fill with readable text on it", () => {
  const text = lookOf("red", "text", "dark");
  assert.equal(text.background, null);
  assert.match(text.foreground, /^#[0-9a-f]{6}$/);
  assert.notEqual(lookOf("red", "text", "light").foreground, text.foreground, "each theme its own");
  const fill = lookOf("amber", "fill", "light");
  assert.match(fill.background ?? "", /^#[0-9a-f]{6}$/);
  assert.equal(fill.foreground, "#1f1f1f", "dark text on amber");
  assert.equal(lookOf("blue", "fill", "dark").foreground, "#ffffff");
});

test("the editor's own check catches what JavaScript can't read and nested repeats", () => {
  assert.equal(localPatternProblem(String.raw`\berror\b`), null);
  assert.equal(localPatternProblem(String.raw`(\d{1,3}\.){3}\d{1,3}`), null);
  assert.equal(localPatternProblem(String.raw`(?:ab?)+`), null);
  assert.match(localPatternProblem("(unclosed") ?? "", /JavaScript can't read it/);
  assert.match(localPatternProblem(String.raw`\-`) ?? "", /JavaScript can't read it/, "u flag: no needless escapes");
  for (const nested of ["(a+)+", String.raw`(\d+\.)*`, "(a|ab)*", "(?:error|warn)+", "(x+){2,}"]) {
    assert.match(localPatternProblem(nested) ?? "", /very slow/, nested);
  }
  assert.match(localPatternProblem("  ") ?? "", /Type a pattern/);
  assert.match(localPatternProblem("x".repeat(201)) ?? "", /at most 200/);
});

test("matching time is budgeted per second", () => {
  const budget = new Budget();
  assert.equal(budget.spend(BUDGET_MS_PER_SECOND - 1, 1000), false);
  assert.equal(budget.spend(2, 1500), true, "over the budget in the same second");
  assert.equal(budget.spend(10, 2600), false, "a new second starts over");
  budget.reset();
  assert.equal(budget.spend(1, 2700), false);
});
