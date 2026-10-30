/// <reference types="node" />
// UX-07: the Templates page's tab order, the tab it opens on, and why New is off. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { newStackReason, newTemplateReason, openingTab, TEMPLATE_TABS } from "./templates-page.ts";

test("the tabs follow a first deploy's steps, Disk images last", () => {
  assert.deepEqual(
    TEMPLATE_TABS.map((t) => t.label),
    ["Images", "Sizes", "Launch templates", "Stacks", "Disk images"],
  );
});

test("the page opens on the first step that isn't done", () => {
  assert.equal(openingTab({ images: 0, templates: 0 }), "images");
  assert.equal(openingTab({ images: 2, templates: 0 }), "templates");
  assert.equal(openingTab({ images: 2, templates: 3 }), "templates", "where Deploy is");
  assert.equal(openingTab({ images: 0, templates: 1 }), "images", "a template whose image went needs one again");
});

test("New launch template and New stack say why they are off", () => {
  assert.equal(newTemplateReason(null, 1), null);
  assert.match(newTemplateReason(null, 0) ?? "", /^Add an image first/);
  assert.equal(newTemplateReason("Read-only", 0), "Read-only", "the read-only lock comes first");
  assert.equal(newStackReason(null, 2), null);
  assert.match(newStackReason(null, 0) ?? "", /^Make a launch template first/);
});
