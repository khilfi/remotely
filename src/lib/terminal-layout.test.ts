/// <reference types="node" />
// UX-03, UX-04: the Terminal page's one side panel, the folding tree and the output labels. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  initialSidePanel,
  LEGACY_COMMANDS_KEY,
  LEGACY_FILES_KEY,
  OUTPUT_LABELS,
  pickedTabsText,
  SIDE_PANEL_KEY,
  SIDE_PANEL_SIZE,
  SIDE_PANELS,
  storedSidePanel,
  toggleSidePanel,
  treeShown,
} from "./terminal-layout.ts";

const reader = (values: Record<string, string>) => (key: string) => values[key] ?? null;

test("the side panel opens on the view kept, or none", () => {
  assert.equal(initialSidePanel(reader({ [SIDE_PANEL_KEY]: "compare" }), 1000), "compare");
  assert.equal(initialSidePanel(reader({ [SIDE_PANEL_KEY]: "none" }), 2000), null);
  // Something unreadable is ignored.
  assert.equal(initialSidePanel(reader({ [SIDE_PANEL_KEY]: "map" }), 2000), "commands");
});

test("a window that used 0.5.0's drawers keeps what it showed", () => {
  assert.equal(initialSidePanel(reader({ [LEGACY_FILES_KEY]: "true", [LEGACY_COMMANDS_KEY]: "true" }), 2000), "files");
  assert.equal(initialSidePanel(reader({ [LEGACY_COMMANDS_KEY]: "true" }), 800), "commands");
  assert.equal(initialSidePanel(reader({ [LEGACY_COMMANDS_KEY]: "false" }), 2000), null);
});

test("with nothing kept, a wide window starts on Commands and a narrow one closed", () => {
  assert.equal(initialSidePanel(reader({}), 1440), "commands");
  assert.equal(initialSidePanel(reader({}), 1280), null);
});

test("a switch opens its view, and closes the panel when it was the one open", () => {
  assert.equal(toggleSidePanel(null, "files"), "files");
  assert.equal(toggleSidePanel("commands", "files"), "files");
  assert.equal(toggleSidePanel("files", "files"), null);
  assert.equal(storedSidePanel(null), "none");
  assert.equal(storedSidePanel("compare"), "compare");
});

test("every view has a label and a width, and Compare hosts opens widest", () => {
  assert.deepEqual(
    SIDE_PANELS.map((p) => p.id),
    ["files", "compare", "commands"],
  );
  for (const { id } of SIDE_PANELS) assert.ok(SIDE_PANEL_SIZE[id] >= 20 && SIDE_PANEL_SIZE[id] <= 50, id);
  assert.ok(SIDE_PANEL_SIZE.compare > SIDE_PANEL_SIZE.files && SIDE_PANEL_SIZE.files > SIDE_PANEL_SIZE.commands);
});

test("the tree shows with no terminal open and folds once one is, unless shown again", () => {
  assert.equal(treeShown({ tabs: 0, shownEmpty: true, shownWithTabs: false }), true);
  assert.equal(treeShown({ tabs: 2, shownEmpty: true, shownWithTabs: false }), false);
  assert.equal(treeShown({ tabs: 2, shownEmpty: true, shownWithTabs: true }), true);
  assert.equal(treeShown({ tabs: 0, shownEmpty: false, shownWithTabs: true }), false);
});

test("output labels are one set, and the picked tabs say how many", () => {
  assert.equal(OUTPUT_LABELS.copy, "Copy output");
  assert.ok(
    Object.values(OUTPUT_LABELS).every((label) => /^[A-Z]/.test(label)),
    "sentence case",
  );
  assert.equal(pickedTabsText(2, 2), "2 tabs picked");
  assert.equal(pickedTabsText(2, 3), "2 tabs picked (3 terminals)");
});
