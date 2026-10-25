/// <reference types="node" />
// SS-03, FD-03: when a pane draws with WebGL, and how a presenting pane's masked copy is filled. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { Masker, TerminalMasker } from "./presentation.ts";
import {
  MASK_CHUNK_CHARS,
  MASKED_SCROLLBACK,
  MAX_WEBGL_FAILURES,
  MAX_WEBGL_PANES,
  maskedScrollback,
  splitAtLineBreaks,
  wantsWebgl,
} from "./terminal-render.ts";

const ESC = "\x1b";
const shown = { visible: true, failures: 0, unavailable: false, others: 0 };

test("a pane on screen draws with WebGL; a hidden one gives its context back", () => {
  assert.equal(wantsWebgl(shown), true);
  assert.equal(wantsWebgl({ ...shown, visible: false }), false, "another tab or page");
});

test("WebGL stops for a pane that failed too often, and for every pane where it can't start", () => {
  assert.equal(wantsWebgl({ ...shown, failures: MAX_WEBGL_FAILURES - 1 }), true);
  assert.equal(wantsWebgl({ ...shown, failures: MAX_WEBGL_FAILURES }), false);
  assert.equal(wantsWebgl({ ...shown, unavailable: true }), false);
});

test("no more panes hold a WebGL context than the browser allows", () => {
  assert.ok(MAX_WEBGL_PANES < 16, "Chromium drops the oldest context past 16");
  assert.equal(wantsWebgl({ ...shown, others: MAX_WEBGL_PANES - 1 }), true);
  assert.equal(wantsWebgl({ ...shown, others: MAX_WEBGL_PANES }), false, "the DOM renderer draws this one");
});

test("the masked copy keeps less scrollback than the real terminal", () => {
  assert.equal(maskedScrollback(10_000), MASKED_SCROLLBACK, "the default setting");
  assert.equal(maskedScrollback(500), 500, "never more than the real one");
  assert.equal(maskedScrollback(0), 0);
  assert.equal(maskedScrollback(-1), 0);
});

test("pieces are cut just after a line break, and joined give the text back", () => {
  const text = "one\r\ntwo\r\nthree\r\nfour\r\n";
  const pieces = splitAtLineBreaks(text, 11);
  assert.deepEqual(pieces, ["one\r\ntwo\r\n", "three\r\n", "four\r\n"]);
  assert.equal(pieces.join(""), text);
  for (const p of pieces.slice(0, -1)) assert.ok(p.endsWith("\n"), JSON.stringify(p));
});

test("a line longer than a piece stays whole, and the end needs no line break", () => {
  const long = "x".repeat(50);
  assert.deepEqual(splitAtLineBreaks(`ab\r\n${long}\r\ncd`, 10), ["ab\r\n", `${long}\r\n`, "cd"]);
  assert.deepEqual(splitAtLineBreaks(long, 10), [long], "no line break at all");
  assert.deepEqual(splitAtLineBreaks("", 10), []);
  assert.deepEqual(splitAtLineBreaks("short", 10), ["short"]);
});

test("masking a restored screen piece by piece masks it as a whole would", () => {
  // A serialized screen: styles, wrapped rows (no line break between them) and values across a style change.
  const rows: string[] = [];
  for (let i = 0; i < 400; i++) {
    rows.push(
      `${ESC}[32malice@web${i % 7}.example.com${ESC}[0m:~$ ssh 192.0.2.${i % 250} ` +
        `${"y".repeat(i % 90)} ${ESC}[1mdb01.example.org${ESC}[22m`,
    );
  }
  const screen = `${rows.join("\r\n")}${ESC}[12;5H`;
  const whole = new TerminalMasker(new Masker()).mask(screen);
  const masker = new Masker();
  const pieces = splitAtLineBreaks(screen, 1024);
  assert.ok(pieces.length > 10);
  const byPiece = pieces.map((p) => new TerminalMasker(masker).mask(p)).join("");
  assert.equal(byPiece, whole);
  assert.ok(!byPiece.includes("alice") && !byPiece.includes("192.0.2.") && !byPiece.includes("example.org"));
});

test("a default scrollback's pieces are a few dozen, not one", () => {
  const line = `${"z".repeat(150)}\r\n`;
  const screen = line.repeat(MASKED_SCROLLBACK + 50);
  const pieces = splitAtLineBreaks(screen, MASK_CHUNK_CHARS);
  assert.ok(pieces.length >= 5 && pieces.length <= 50, String(pieces.length));
  assert.ok(pieces.every((p) => p.length <= MASK_CHUNK_CHARS));
});
