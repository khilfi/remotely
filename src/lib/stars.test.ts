import assert from "node:assert/strict";
import { test } from "node:test";
import { boostStarred, isStarred, recentOf, recentSessions, starLabel, starSets, starredFirst } from "./stars.ts";
import type { Star } from "./comfort-api.ts";
import type { SearchItem } from "./search.ts";

const at = "2026-11-01T10:00:00Z";

test("stars are found by kind and key, a VM's path without letter case", () => {
  const sets = starSets([
    { kind: "session", key: "s1", createdAt: at },
    { kind: "vm", key: "C:\\VMs\\Web\\web.vmx", createdAt: at },
  ]);
  assert.ok(isStarred(sets, "session", "s1"));
  assert.ok(!isStarred(sets, "session", "S1"));
  assert.ok(isStarred(sets, "vm", "c:\\vms\\web\\WEB.vmx"));
});

test("UX-20: a command star from an older core is left out", () => {
  const old = { kind: "command", key: "library:disk.usage", createdAt: at } as unknown as Star;
  const sets = starSets([old, { kind: "session", key: "s1", createdAt: at }]);
  assert.deepEqual(Object.keys(sets).sort(), ["session", "vm"]);
  assert.ok(isStarred(sets, "session", "s1"));
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

test("UX-22: recent sessions are the recents' sessions that still exist, newest first", () => {
  const recents = [
    { kind: "session" as const, key: "gone", openedAt: at },
    { kind: "vm" as const, key: "s1", openedAt: at },
    { kind: "session" as const, key: "s2", openedAt: at },
    { kind: "session" as const, key: "s1", openedAt: at },
  ];
  const byId = new Map([
    ["s1", { id: "s1", name: "web01" }],
    ["s2", { id: "s2", name: "db01" }],
  ]);
  assert.deepEqual(
    recentSessions(recents, byId).map((s) => s.name),
    ["db01", "web01"],
  );
  assert.equal(recentSessions(recents, byId, 1).length, 1);
});

test("the star button says what it does", () => {
  assert.equal(starLabel(false, "web01"), "Star web01");
  assert.equal(starLabel(true, "web01"), "Unstar web01");
});

test("starred search results get a boost, commands no longer do", () => {
  const sets = starSets([{ kind: "session", key: "s1", createdAt: at }]);
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
    [4, 0, 0],
  );
});
