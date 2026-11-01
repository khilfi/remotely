import assert from "node:assert/strict";
import { test } from "node:test";
import { boostStarred, commandStarKey, isStarred, recentOf, starLabel, starSets, starredFirst } from "./stars.ts";
import type { SearchItem } from "./search.ts";

const at = "2026-11-01T10:00:00Z";

test("stars are found by kind and key, a VM's path without letter case", () => {
  const sets = starSets([
    { kind: "session", key: "s1", createdAt: at },
    { kind: "vm", key: "C:\\VMs\\Web\\web.vmx", createdAt: at },
    { kind: "command", key: commandStarKey("library", "disk.usage"), createdAt: at },
  ]);
  assert.ok(isStarred(sets, "session", "s1"));
  assert.ok(!isStarred(sets, "session", "S1"));
  assert.ok(isStarred(sets, "vm", "c:\\vms\\web\\WEB.vmx"));
  assert.ok(isStarred(sets, "command", "library:disk.usage"));
  assert.ok(!isStarred(sets, "command", "favourite:disk.usage"));
});

test("starred items come first and keep their order", () => {
  const items = ["a", "b", "c", "d"];
  assert.deepEqual(
    starredFirst(items, (x) => x === "c" || x === "a"),
    ["a", "c", "b", "d"],
  );
});

test("recents are filtered by kind, newest first, capped", () => {
  const recents = [
    { kind: "page" as const, key: "vms", openedAt: at },
    { kind: "session" as const, key: "s1", openedAt: at },
    { kind: "vm" as const, key: "v1", openedAt: at },
    { kind: "session" as const, key: "s2", openedAt: at },
  ];
  assert.deepEqual(
    recentOf(recents, ["session"]).map((r) => r.key),
    ["s1", "s2"],
  );
  assert.equal(recentOf(recents, ["session", "vm", "page"], 2).length, 2);
});

test("the star button says what it does", () => {
  assert.equal(starLabel(false, "web01"), "Star web01");
  assert.equal(starLabel(true, "web01"), "Unstar web01");
});

test("starred search results get a boost, the others stay as they are", () => {
  const sets = starSets([
    { kind: "session", key: "s1", createdAt: at },
    { kind: "command", key: "library:disk.usage", createdAt: at },
  ]);
  const item = (id: string): SearchItem => ({
    id,
    provider: "x",
    title: id,
    fields: [],
    target: { action: id },
  });
  const boosted = boostStarred([item("session:s1"), item("session:s2"), item("library:disk.usage")], sets);
  assert.deepEqual(
    boosted.map((i) => i.boost ?? 0),
    [4, 0, 4],
  );
});
