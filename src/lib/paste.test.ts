/// <reference types="node" />
// QL-05, SS-03 paste cleaning and the multi-line confirm's preview. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { pasteHasLineBreak, pasteLines, pastePreview, sanitizePaste } from "./paste.ts";

const ESC = "\x1b";

test("plain text, tabs, line endings, emoji and other scripts are kept as they are", () => {
  for (const text of ["ls -la", "a\tb", "one\ntwo\n", "one\r\ntwo", "a\rb", "héllo wörld", "日本語", "👍🏽 ok", ""]) {
    assert.equal(sanitizePaste(text), text, JSON.stringify(text));
  }
});

test("both bracketed-paste markers go, so a paste can't end bracketed paste early", () => {
  assert.equal(sanitizePaste(`echo safe${ESC}[201~rm -rf ~\n`), "echo saferm -rf ~\n");
  assert.equal(sanitizePaste(`${ESC}[200~ls${ESC}[201~`), "ls");
  // Their 8-bit CSI forms too.
  assert.equal(sanitizePaste("a\x9b201~b\x9b200~c"), "abc");
});

test("a marker split around another comes out whole, and none is ever left", () => {
  assert.equal(sanitizePaste(`a${ESC}[20${ESC}[201~1~b`), "ab");
  // Three deep: each marker that goes makes the next one.
  assert.equal(sanitizePaste(`a${ESC}[20${ESC}[20${ESC}[201~1~0~b`), "ab");
  // Split by a control character: once that goes, ESC has gone too, so what is left is plain text.
  const split = sanitizePaste(`a${ESC}[20\x001~b`);
  assert.equal(split, "a[201~b");
  assert.ok(!split.includes(ESC));
});

test("C0 controls go, except tab, CR and LF", () => {
  for (let code = 0; code < 0x20; code++) {
    const ch = String.fromCharCode(code);
    const kept = code === 0x09 || code === 0x0a || code === 0x0d;
    assert.equal(sanitizePaste(`a${ch}b`), kept ? `a${ch}b` : "ab", `0x${code.toString(16)}`);
  }
  // Ctrl+C, Ctrl+D, Ctrl+Z, ESC sequences: only their printable rest is left.
  assert.equal(sanitizePaste(`x\x03\x04\x1a${ESC}[31mred${ESC}[0m`), "x[31mred[0m");
});

test("DEL and C1 controls go; U+00A0 and above stay", () => {
  assert.equal(sanitizePaste("a\x7fb"), "ab");
  for (let code = 0x80; code <= 0x9f; code++) {
    assert.equal(sanitizePaste(`a${String.fromCharCode(code)}b`), "ab", `0x${code.toString(16)}`);
  }
  assert.equal(sanitizePaste("a bÿc"), "a bÿc");
  // U+009B is an 8-bit CSI: what would follow it is plain text.
  assert.equal(sanitizePaste("\x9b2J"), "2J");
});

test("a paste with a line break asks; one line that ends with one asks too, as its break presses Enter", () => {
  assert.equal(pasteHasLineBreak("uptime"), false);
  assert.equal(pasteHasLineBreak("uptime\n"), true);
  assert.equal(pasteHasLineBreak("uptime\r"), true);
  assert.equal(pasteHasLineBreak("a\r\nb"), true);
  assert.equal(pasteHasLineBreak(""), false);
});

test("lines end at CRLF, CR or LF, and a break at the very end starts no line", () => {
  assert.deepEqual(pasteLines(""), []);
  assert.deepEqual(pasteLines("a"), ["a"]);
  assert.deepEqual(pasteLines("a\n"), ["a"]);
  assert.deepEqual(pasteLines("a\r\nb\rc\nd"), ["a", "b", "c", "d"]);
  assert.deepEqual(pasteLines("a\r\n"), ["a"]);
  assert.deepEqual(pasteLines("\n"), [""]);
  assert.deepEqual(pasteLines("a\n\n"), ["a", ""]);
});

test("the preview counts lines, shows the first few cut to length, and says what is left", () => {
  const one = pastePreview("sudo systemctl restart nginx\n");
  assert.deepEqual(one, { lines: 1, shown: ["sudo systemctl restart nginx"], more: 0, endsWithBreak: true });

  const text = Array.from({ length: 8 }, (_, i) => `echo ${i + 1}`).join("\r\n");
  const many = pastePreview(text, 3);
  assert.equal(many.lines, 8);
  assert.deepEqual(many.shown, ["echo 1", "echo 2", "echo 3"]);
  assert.equal(many.more, 5);
  assert.equal(many.endsWithBreak, false);

  const long = pastePreview(`${"x".repeat(50)}\nb`, 5, 10);
  assert.equal(long.shown[0], `${"x".repeat(9)}…`);
  // An emoji at the cut is never split in half.
  assert.equal(pastePreview(`${"👍".repeat(12)}\n`, 5, 10).shown[0], `${"👍".repeat(9)}…`);
});
