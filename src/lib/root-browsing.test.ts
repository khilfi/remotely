/// <reference types="node" />
// UX-14 (0.9.0 H1): root browsing as the core says, shared by the drawer and the Files page. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createRootStore } from "./root-browsing.ts";

test("a start in one place shows in every place at once", () => {
  const store = createRootStore();
  let heard = 0;
  store.subscribe(() => (heard += 1));
  assert.equal(store.isRoot("t1"), false);
  store.set("t1", true);
  assert.equal(store.isRoot("t1"), true);
  assert.equal(store.isRoot("t2"), false);
  assert.equal(heard, 1);
  // The same state again tells no one.
  store.set("t1", true);
  assert.equal(heard, 1);
  store.set("t1", false);
  assert.equal(heard, 2);
});

test("an end heard in two places is said once", () => {
  const store = createRootStore();
  store.set("t1", true);
  // The drawer and a Files tab on the same terminal both hear that root browsing ended.
  assert.equal(store.set("t1", false), true);
  assert.equal(store.set("t1", false), false);
});

test("the core's answer is what counts", async () => {
  const store = createRootStore();
  await store.load("t1", async () => true);
  assert.equal(store.isRoot("t1"), true);
  // Root browsing ended in the core (a reconnect, the vault locked).
  await store.load("t1", async () => false);
  assert.equal(store.isRoot("t1"), false);
});

test("a read asked before a start or stop can't undo it", async () => {
  const store = createRootStore();
  let answer: (value: boolean) => void = () => undefined;
  const reading = store.load("t1", () => new Promise<boolean>((resolve) => (answer = resolve)));
  store.set("t1", true);
  answer(false);
  await reading;
  assert.equal(store.isRoot("t1"), true);
});

test("a failed read changes nothing", async () => {
  const store = createRootStore();
  store.set("t1", true);
  const before = store.version();
  await store.load("t1", async () => {
    throw new Error("the terminal closed");
  });
  assert.equal(store.isRoot("t1"), true);
  assert.equal(store.version(), before);
});
