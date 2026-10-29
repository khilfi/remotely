/// <reference types="node" />
// UX-04: the help registry. Every page has its "?" entry, every entry is short and plain, and every link opens
// something this version knows. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { HELP, helpEntry, isHelpKey, type HelpKey } from "./help.ts";
import { isAppLink } from "./links.ts";
import { MOVED_PAGES, navTarget, PAGES } from "./navigation.ts";
import { settingsSection } from "./settings-index.ts";

const KEYS = Object.keys(HELP) as HelpKey[];

test("every page, and every page that became a tab, has its own entry", () => {
  for (const page of PAGES) assert.ok(isHelpKey(`page.${page.id}`), page.id);
  assert.ok(isHelpKey("page.diskImages") && isHelpKey("page.map") && isHelpKey("page.knownHosts"));
  assert.equal(Object.keys(MOVED_PAGES).length, 4, "a new moved page gets an entry here too");
  assert.equal(helpEntry("page.vms").title, "Virtual machines", "titles match the sidebar");
});

test("the explanations the 0.5.0 audit found repeated are each one entry", () => {
  for (const key of [
    "windowsUnlock",
    "presentationMode",
    "readOnlyLock",
    "promptHook",
    "toolPaths",
    "retention",
    "prodTier",
    "safetySnapshot",
    "updateToken",
    "dashboardPolling",
    "vaultIdleLock",
    "qemuImg",
    "auditLog",
  ])
    assert.ok(isHelpKey(key), key);
  assert.ok(!isHelpKey("toString"), "only the registry's own keys");
});

test("entries are short: a title and one or two paragraphs in plain words", () => {
  for (const key of KEYS) {
    const entry = helpEntry(key);
    assert.ok(entry.title.length > 0 && entry.title.length <= 40, `${key}: title`);
    assert.match(entry.title, /^[A-Z0-9]/, `${key}: the title starts with a capital`);
    assert.ok(entry.body.length >= 1 && entry.body.length <= 2, `${key}: one or two paragraphs`);
    for (const paragraph of entry.body) {
      assert.ok(paragraph.length <= 320, `${key}: a paragraph of at most 320 characters`);
      assert.match(paragraph, /[.!?)]$/, `${key}: paragraphs end with a full stop`);
      assert.doesNotMatch(paragraph, /\b(?:VM|SS|BX|AP|MO|FD|QL|CT|CV|UX)-\d{2}\b/, `${key}: no requirement ID`);
      assert.doesNotMatch(paragraph, /\b(?:please|successfully)\b/i, `${key}: no "please" or "successfully"`);
    }
  }
});

test("every link opens a page, a setting or a place this version knows", () => {
  for (const key of KEYS) {
    const link = helpEntry(key).link;
    if (!link) continue;
    assert.ok(link.label.length > 0, key);
    assert.ok(isAppLink(link.to), `${key}: a link`);
    if (link.to.kind === "setting") assert.ok(settingsSection(link.to.section), `${key}: ${link.to.section}`);
    if (link.to.kind === "page") assert.ok(navTarget(link.to.page), `${key}: ${link.to.page}`);
  }
});
