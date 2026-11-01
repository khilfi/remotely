import assert from "node:assert/strict";
import { test } from "node:test";
import { bulkEditFrom, emptyBulkForm, loginAuth, parseTags } from "./bulk-edit.ts";

test("nothing ticked is no edit", () => {
  assert.deepEqual(bulkEditFrom(emptyBulkForm()), { error: "Tick what to change." });
});

test("only ticked fields go into the edit", () => {
  const form = emptyBulkForm();
  form.port = { on: true, value: " 2222 " };
  form.folder = { on: true, value: null };
  form.user = { on: true, value: "  " };
  form.jump = { on: true, value: "s-bastion" };
  form.environment = { on: false, value: "prod" };
  form.tagsAdd = "edge, web web";
  assert.deepEqual(bulkEditFrom(form), {
    edit: {
      folder: { folderId: null },
      port: 2222,
      username: { username: null },
      jump: { kind: "session", id: "s-bastion" },
      tagsAdd: ["edge", "web"],
    },
  });
});

test("a bad port or a tag both added and removed is refused", () => {
  const form = emptyBulkForm();
  form.port = { on: true, value: "70000" };
  assert.ok("error" in bulkEditFrom(form));
  const tags = emptyBulkForm();
  tags.tagsAdd = "web";
  tags.tagsRemove = "WEB";
  assert.ok("error" in bulkEditFrom(tags));
});

test("login choices become the core's logins", () => {
  assert.deepEqual(loginAuth("agent"), { method: "agent" });
  assert.deepEqual(loginAuth("asked"), { method: "password", passwordId: null });
  assert.deepEqual(loginAuth("password:p1"), { method: "password", passwordId: "p1" });
  assert.deepEqual(loginAuth("key:k1"), { method: "key", keyId: "k1", passphraseId: null });
  assert.deepEqual(loginAuth("folder"), { method: "folder" });
});

test("tags split on commas and spaces, each once", () => {
  assert.deepEqual(parseTags(" a, b  c,A "), ["a", "b", "c"]);
});
