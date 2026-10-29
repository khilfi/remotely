/// <reference types="node" />
// UX-08 (FD-01, QL-14): the page registry, the sidebar's groups, page shortcuts in sidebar order, and the pages that
// became tabs still reached by their ids and free shortcuts. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MOVED_PAGES,
  movedPageEntries,
  NAV_GROUPS,
  navTarget,
  OLD_SHORTCUTS,
  pageLabel,
  PAGES,
  SHORTCUT_KEYS,
  shortcutTarget,
  sidebarGroups,
} from "./navigation.ts";

test("the sidebar has Machines, Remote and Overview, then Vault and Settings at the bottom", () => {
  assert.deepEqual(
    NAV_GROUPS.map((g) => g.label),
    ["Machines", "Remote", "Overview"],
  );
  const groups = sidebarGroups().map((g) => [g.group?.label ?? "bottom", g.pages.map((p) => p.label)]);
  assert.deepEqual(groups, [
    ["Machines", ["Virtual machines", "Templates", "Schedules"]],
    ["Remote", ["Sessions", "Terminal", "Containers"]],
    ["Overview", ["Dashboard", "Activity"]],
    ["bottom", ["Vault", "Settings"]],
  ]);
});

test("page shortcuts follow the sidebar's order, Settings keeps Ctrl+,", () => {
  const order = sidebarGroups().flatMap((g) => g.pages);
  assert.deepEqual(
    order.map((p) => p.shortcut),
    ["Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5", "Ctrl+6", "Ctrl+7", "Ctrl+8", "Ctrl+9", "Ctrl+,"],
  );
  for (const page of PAGES) assert.deepEqual(shortcutTarget(page.shortcut.slice(5)), { page: page.id }, page.id);
  const all = [
    ...PAGES.map((p) => p.shortcut),
    ...movedPageEntries().flatMap((m) => (m.shortcut ? [m.shortcut] : [])),
    ...Object.keys(OLD_SHORTCUTS),
  ];
  assert.equal(new Set(all).size, all.length, "no two places share a shortcut");
  for (const shortcut of all) assert.ok(SHORTCUT_KEYS.test(shortcut.slice(5)), `App listens for ${shortcut}`);
});

test("the 0.5.0 shortcuts no page took still open what they opened", () => {
  assert.deepEqual(shortcutTarget("0"), { page: "dashboard", tab: "map" });
  assert.deepEqual(shortcutTarget(";"), { page: "templates", tab: "disks" });
  assert.deepEqual(shortcutTarget("."), { page: "schedules" });
  assert.equal(shortcutTarget("-"), null);
  assert.equal(shortcutTarget("toString"), null, "only the tables' own keys");
});

test("the pages that became tabs are reached by their old ids", () => {
  assert.deepEqual(navTarget("images"), { page: "templates", tab: "disks" });
  assert.deepEqual(navTarget("map"), { page: "dashboard", tab: "map" });
  assert.deepEqual(navTarget("knownHosts"), { page: "vault", tab: "knownHosts" });
  assert.deepEqual(navTarget("snapshots"), { page: "vms", tab: "snapshots" });
  assert.deepEqual(navTarget("templates"), { page: "templates" });
  assert.deepEqual(navTarget("settings"), { page: "settings" });
  assert.equal(navTarget("bulk"), null);
  assert.equal(navTarget("toString"), null, "only the tables' own keys");
  assert.equal(navTarget("constructor"), null);
});

test("each moved page names its home, and only Disk images and the Map keep a shortcut", () => {
  assert.deepEqual(movedPageEntries(), [
    { id: "images", label: "Templates › Disk images", shortcut: "Ctrl+;" },
    { id: "map", label: "Dashboard › Map", shortcut: "Ctrl+0" },
    { id: "knownHosts", label: "Vault › Known hosts", shortcut: undefined },
  ]);
  for (const moved of Object.values(MOVED_PAGES)) assert.ok(PAGES.some((p) => p.id === moved.home));
});

test("titles come from the registry", () => {
  assert.equal(pageLabel("vms"), "Virtual machines");
  assert.equal(pageLabel("activity"), "Activity");
  assert.equal(new Set(PAGES.map((p) => p.label)).size, PAGES.length);
});
