/// <reference types="node" />
// UX-04: the session editor's folded Advanced section says what it holds. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { advancedSummary, environmentNote, type AdvancedValues } from "./session-editor.ts";

test("UX-12: the Environment line says what applies and where it comes from", () => {
  assert.equal(
    environmentNote({ environment: "prod", from: { kind: "vm", name: "db-01" } }, null),
    "Prod · from VM db-01: actions on it move up one approval tier.",
  );
  assert.equal(
    environmentNote({ environment: "lab", from: { kind: "folder", name: "Dev" } }, null),
    "Lab · from folder Dev.",
  );
  assert.equal(
    environmentNote({ environment: "staging", from: null }, { environment: "prod", folder: "Production" }),
    "Overrides Prod from folder Production.",
  );
  assert.equal(
    environmentNote({ environment: "prod", from: null }, null),
    "Prod: actions on it move up one approval tier.",
  );
  assert.equal(
    environmentNote({ environment: "none", from: null }, null),
    "Shown on its tab and rows. Prod raises the approval tier.",
  );
});

const nothing: AdvancedValues = {
  jumpHost: null,
  vm: null,
  startupCommand: false,
  promptHook: null,
  portForwards: 0,
  colour: false,
  tags: 0,
};

test("with nothing set, it names what is inside", () => {
  assert.equal(advancedSummary(nothing), "Jump host, VM, startup command, port forwards, colour and tags");
});

test("what is set, in the order the section shows it", () => {
  assert.equal(
    advancedSummary({
      jumpHost: "bastion",
      vm: "db-01",
      startupCommand: true,
      promptHook: false,
      portForwards: 2,
      colour: true,
      tags: 3,
    }),
    "Jump host bastion · VM db-01 · startup command · prompt hook off · 2 port forwards · colour · 3 tags",
  );
  assert.equal(advancedSummary({ ...nothing, tags: 1, portForwards: 1 }), "1 port forward · 1 tag");
  assert.equal(advancedSummary({ ...nothing, startupCommand: true }), "Startup command");
});
