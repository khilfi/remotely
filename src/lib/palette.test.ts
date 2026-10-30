/// <reference types="node" />
// UX-03, UX-07: the palette's order before anything is typed, and when its bulk actions show. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { CREATE_ACTION_IDS, isCreateAction, splitActions, typedForBulk } from "./palette.ts";

test("what makes something new comes before the other actions, in the sidebar's order", () => {
  const actions = [
    { id: "refresh" },
    { id: "new-terminal" },
    { id: "snapshots" },
    { id: "new-schedule" },
    { id: "deploy" },
    { id: "lock" },
  ];
  const { create, other } = splitActions(actions);
  assert.deepEqual(
    create.map((a) => a.id),
    ["deploy", "new-schedule", "new-terminal"],
  );
  assert.deepEqual(
    other.map((a) => a.id),
    ["refresh", "snapshots", "lock"],
    "the rest keep their order",
  );
  assert.equal(isCreateAction("add-vm"), true);
  assert.equal(isCreateAction("refresh"), false);
  assert.equal(new Set(CREATE_ACTION_IDS).size, CREATE_ACTION_IDS.length);
});

test("bulk actions show only when the search asks for them", () => {
  const shut = "Shut down all running VMs (3)";
  const suspend = "Suspend all running VMs (3)";
  assert.equal(typedForBulk("", shut), false, "nothing typed");
  assert.equal(typedForBulk("s", shut), false);
  assert.equal(typedForBulk("sh", shut), false, "too short");
  assert.equal(typedForBulk("shu", shut), true);
  assert.equal(typedForBulk("shut down", shut), true);
  assert.equal(typedForBulk("SUSP", suspend), true, "any case");
  assert.equal(typedForBulk("susp", shut), false);
  assert.equal(typedForBulk("all running", suspend), true);
  assert.equal(typedForBulk("web-01", shut), false, "a search for something else");
  assert.equal(typedForBulk("own", shut), false, "the middle of a word isn't enough");
  assert.equal(typedForBulk("run", shut), true);
});
