/// <reference types="node" />
// QL-24: the shortcut sheet lists every page's shortcut and the rest, Ctrl+/ opens it (Ctrl+Shift+/ in a terminal),
// and density is stored as one of its two values. Run with `npm test`.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { DENSITIES, parseDensity } from "./density.ts";
import { navTarget, shortcutTarget } from "./navigation.ts";
import {
  filterShortcuts,
  opensShortcutSheet,
  pageShortcuts,
  SHEET_KEYS,
  SHEET_KEYS_IN_TERMINAL,
  shortcutGroups,
} from "./shortcuts.ts";

const PAGES = pageShortcuts();

function press(
  key: string,
  extra: Partial<{ code: string; ctrlKey: boolean; shiftKey: boolean; altKey: boolean; metaKey: boolean }> = {},
) {
  return { key, code: "", ctrlKey: true, shiftKey: false, altKey: false, metaKey: false, ...extra };
}

test("the pages are listed in sidebar order, then the tabs that kept their shortcut (UX-08)", () => {
  const pages = shortcutGroups(PAGES).find((g) => g.title === "Pages");
  assert.deepEqual(
    pages?.shortcuts.map((s) => `${s.keys} ${s.what}`),
    [
      "Ctrl+1 Virtual machines",
      "Ctrl+2 Templates",
      "Ctrl+3 Schedules",
      "Ctrl+4 Sessions",
      "Ctrl+5 Terminal",
      "Ctrl+6 Containers",
      "Ctrl+7 Dashboard",
      "Ctrl+8 Activity",
      "Ctrl+9 Vault",
      "Ctrl+, Settings",
      "Ctrl+; Templates › Disk images",
      "Ctrl+0 Dashboard › Map",
    ],
  );
});

test("every page shortcut on the sheet opens what it says, and none is listed twice", () => {
  const keys = PAGES.map((p) => p.shortcut);
  assert.equal(new Set(keys).size, keys.length);
  for (const p of PAGES) assert.ok(shortcutTarget(p.shortcut.slice(5)), p.shortcut);
  assert.deepEqual(shortcutTarget("0"), navTarget("map"));
});

test("App takes its pages from the registry, not a list of its own", () => {
  const app = readFileSync(new URL("../App.tsx", import.meta.url), "utf8");
  assert.ok(!/const PAGES\b/.test(app), "App.tsx has no PAGES table of its own");
  assert.ok(app.includes("pageShortcuts()"), "the sheet's pages come from pageShortcuts");
});

test("the sheet lists the keys each part of the app handles", () => {
  const keys = shortcutGroups(PAGES).flatMap((g) => g.shortcuts.map((s) => s.keys));
  for (const key of [
    "Ctrl+K",
    SHEET_KEYS,
    "Ctrl+Shift+K",
    SHEET_KEYS_IN_TERMINAL,
    "Ctrl+Shift+F",
    "Ctrl+Shift+G",
    "Ctrl+Enter",
  ])
    assert.ok(keys.includes(key), key);
  const pairs = shortcutGroups(PAGES).flatMap((g) => g.shortcuts.map((s) => `${g.title}|${s.keys}|${s.what}`));
  assert.equal(new Set(pairs).size, pairs.length, "nothing listed twice");
});

test("Ctrl+/ opens the sheet outside a terminal; inside one only Ctrl+Shift+/ does", () => {
  assert.ok(opensShortcutSheet(press("/"), false));
  assert.ok(!opensShortcutSheet(press("/"), true), "Ctrl+/ is the shell's undo there");
  assert.ok(opensShortcutSheet(press("?", { shiftKey: true }), true));
  assert.ok(opensShortcutSheet(press("7", { code: "Slash", shiftKey: true }), true), "a layout where / is elsewhere");
  assert.ok(!opensShortcutSheet(press("/", { ctrlKey: false }), false));
  assert.ok(!opensShortcutSheet(press("/", { altKey: true }), false));
  assert.ok(!opensShortcutSheet(press("k"), false));
});

test("the filter finds shortcuts by their keys or words, and drops empty groups", () => {
  const groups = shortcutGroups(PAGES);
  const scroll = filterShortcuts(groups, "scrollback");
  assert.ok(scroll.length >= 1 && scroll.every((g) => g.shortcuts.length > 0));
  assert.ok(scroll.flatMap((g) => g.shortcuts).every((s) => /scrollback/i.test(s.what)));
  assert.equal(filterShortcuts(groups, "ctrl+0")[0].shortcuts[0].what, "Dashboard › Map");
  assert.equal(filterShortcuts(groups, "").length, groups.length);
  assert.equal(filterShortcuts(groups, "no such key").length, 0);
});

test("density is comfortable unless compact was chosen", () => {
  assert.equal(parseDensity("compact"), "compact");
  for (const other of [null, undefined, "", "cosy", "COMPACT"]) assert.equal(parseDensity(other), "comfortable");
  assert.deepEqual(
    DENSITIES.map((d) => d.value),
    ["comfortable", "compact"],
  );
});

test("compact density is set through the spacing and radius tokens, not one-off rules", () => {
  const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");
  const rule = /html\[data-density="compact"\]\s*\{([^}]*)\}/.exec(css);
  assert.ok(rule, "the compact rule is there");
  const declarations = rule[1]
    .split(";")
    .map((d) => d.trim())
    .filter(Boolean)
    .map((d) => d.split(":")[0].trim());
  assert.deepEqual(declarations.sort(), ["--radius", "--spacing"]);
});
