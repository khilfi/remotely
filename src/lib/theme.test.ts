/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import { afterDarkSwitch, afterFollowWindows, resolveTheme } from "./theme.ts";

test("QL-11: while Windows decides, the switch shows the theme in effect", () => {
  assert.equal(resolveTheme("system", true), "dark");
  assert.equal(resolveTheme("system", false), "light");
  assert.equal(resolveTheme("dark", false), "dark");
  assert.equal(resolveTheme("light", true), "light");
});

test("QL-11: using the switch turns Follow Windows off", () => {
  assert.equal(afterDarkSwitch(true), "dark");
  assert.equal(afterDarkSwitch(false), "light");
});

test("QL-11: turning Follow Windows off keeps the theme on screen; on lets Windows decide", () => {
  assert.equal(afterFollowWindows(false, "system", true), "dark");
  assert.equal(afterFollowWindows(false, "system", false), "light");
  assert.equal(afterFollowWindows(false, "light", true), "light");
  assert.equal(afterFollowWindows(true, "dark", false), "system");
});
