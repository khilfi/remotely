import assert from "node:assert/strict";
import { test } from "node:test";
import { deletedMessage, restoredMessage, trashKindLabel } from "./trash.ts";

test("each kind has a name in sentence case", () => {
  assert.equal(trashKindLabel("command"), "Favourite command");
  assert.equal(trashKindLabel("template"), "Launch template");
});

test("a restore says what it left out", () => {
  assert.deepEqual(restoredMessage({ kind: "session", itemId: "s1", name: "web01", notes: [] }), {
    title: "Restored 'web01'",
  });
  assert.deepEqual(
    restoredMessage({
      kind: "session",
      itemId: "s1",
      name: "web01 (restored)",
      notes: ["'web01' was taken, so it is 'web01 (restored)' now", "its jump host is gone, so it was left out"],
    }),
    {
      title: "Restored 'web01 (restored)'",
      description: "'web01' was taken, so it is 'web01 (restored)' now. Its jump host is gone, so it was left out.",
    },
  );
});

test("a delete says it went to the trash", () => {
  assert.equal(deletedMessage("web01").description, "It is in the trash for 30 days.");
});
