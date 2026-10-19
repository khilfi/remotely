/// <reference types="node" />
// SS-10: picking the tabs MultiExec types into. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { folderCounts, labelChoices, pickedText, pickTabs, type PickableTab } from "./multiexec-picks.ts";

const tabs: PickableTab[] = [
  { key: "a", folderId: "web", environment: "prod", unsaved: false },
  { key: "b", folderId: "web-eu", environment: "lab", unsaved: false },
  { key: "c", folderId: null, environment: "prod", unsaved: false },
  { key: "d", folderId: null, environment: null, unsaved: true },
];

test("all, by folder (with the folders under it), by label, or the quick connections", () => {
  assert.deepEqual(pickTabs(tabs, { kind: "all" }), ["a", "b", "c", "d"]);
  assert.deepEqual(pickTabs(tabs, { kind: "folder", under: new Set(["web", "web-eu"]) }), ["a", "b"]);
  assert.deepEqual(pickTabs(tabs, { kind: "folder", under: new Set(["web-eu"]) }), ["b"]);
  assert.deepEqual(pickTabs(tabs, { kind: "label", environment: "prod" }), ["a", "c"]);
  assert.deepEqual(pickTabs(tabs, { kind: "unsaved" }), ["d"]);
});

test("the choices offered are the ones open tabs have", () => {
  assert.deepEqual(labelChoices(tabs), [
    { environment: "prod", count: 2 },
    { environment: "lab", count: 1 },
  ]);
  const subtrees = new Map([
    ["web", new Set(["web", "web-eu"])],
    ["web-eu", new Set(["web-eu"])],
    ["db", new Set(["db"])],
  ]);
  assert.deepEqual(
    [...folderCounts(tabs, subtrees)],
    [
      ["web", 2],
      ["web-eu", 1],
    ],
  );
});

test("the bar says how many tabs get the keys", () => {
  assert.equal(pickedText(4, 4), "all 4 tabs");
  assert.equal(pickedText(1, 1), "the only tab");
  assert.equal(pickedText(2, 4), "2 of 4 tabs");
});
