/// <reference types="node" />
// FD-01 and QL-14: page shortcuts by each page's own shortcut, and the Snapshots page's old id and shortcut. Run with
// `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { navTarget, shortcutTarget } from "./navigation.ts";

// The sidebar after QL-14: slot 3 is free until Containers (Q6) takes it.
const PAGES = [
  { id: "vms", shortcut: "Ctrl+1" },
  { id: "dashboard", shortcut: "Ctrl+2" },
  { id: "sessions", shortcut: "Ctrl+4" },
  { id: "terminal", shortcut: "Ctrl+5" },
  { id: "settings", shortcut: "Ctrl+," },
];

test("each page keeps its own shortcut when another page leaves the sidebar", () => {
  assert.deepEqual(shortcutTarget("1", PAGES), { page: "vms" });
  assert.deepEqual(shortcutTarget("4", PAGES), { page: "sessions" });
  assert.deepEqual(shortcutTarget("5", PAGES), { page: "terminal" });
  assert.deepEqual(shortcutTarget(",", PAGES), { page: "settings" });
  assert.equal(shortcutTarget("9", PAGES), null);
});

test("Ctrl+3 opens the snapshot view until a page takes the slot", () => {
  assert.deepEqual(shortcutTarget("3", PAGES), { moved: "snapshots" });
  const withContainers = [...PAGES, { id: "containers", shortcut: "Ctrl+3" }];
  assert.deepEqual(shortcutTarget("3", withContainers), { page: "containers" });
});

test("the old Snapshots page id still opens something", () => {
  assert.deepEqual(navTarget("snapshots", PAGES), { moved: "snapshots" });
  assert.deepEqual(navTarget("dashboard", PAGES), { page: "dashboard" });
  assert.equal(navTarget("bulk", PAGES), null);
  assert.equal(navTarget("toString", PAGES), null, "only the table's own keys");
});
