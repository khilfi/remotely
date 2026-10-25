/// <reference types="node" />
// QL-15: a crashed page's text, and the browser keys a release build ignores. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { describeError, isBrowserKey, MAX_ERROR_CHARS, type KeyPress } from "./ui-errors.ts";

const press = (key: string, mods: Partial<KeyPress> = {}): KeyPress => ({
  key,
  ctrlKey: false,
  shiftKey: false,
  altKey: false,
  metaKey: false,
  ...mods,
});

test("an error reads as one short line", () => {
  assert.equal(
    describeError(new TypeError("Cannot read properties of undefined (reading 'x')")),
    "Cannot read properties of undefined (reading 'x')",
  );
  assert.equal(describeError("boom\n  at line 2"), "boom at line 2");
  assert.equal(describeError({ code: "io" }), '{"code":"io"}');
  assert.equal(describeError(undefined), "undefined");
  assert.equal(describeError(""), "Unknown error");
  const long = describeError(new Error("x".repeat(2_000)));
  assert.equal(long.length, MAX_ERROR_CHARS + 1);
  assert.ok(long.endsWith("…"));
});

test("reload and developer-tool keys are browser keys", () => {
  for (const key of [
    press("F5"),
    press("F5", { ctrlKey: true }),
    press("F12"),
    press("r", { ctrlKey: true }),
    press("R", { ctrlKey: true, shiftKey: true }),
    press("I", { ctrlKey: true, shiftKey: true }),
    press("J", { ctrlKey: true, shiftKey: true }),
  ]) {
    assert.ok(isBrowserKey(key), JSON.stringify(key));
  }
});

test("editing keys and the app's own shortcuts are not", () => {
  for (const key of [
    press("c", { ctrlKey: true }),
    press("C", { ctrlKey: true, shiftKey: true }),
    press("v", { ctrlKey: true }),
    press("a", { ctrlKey: true }),
    press("i", { ctrlKey: true }),
    press("r"),
    press("r", { ctrlKey: true, altKey: true }),
    press("3", { ctrlKey: true }),
    press("Enter"),
  ]) {
    assert.ok(!isBrowserKey(key), JSON.stringify(key));
  }
});
