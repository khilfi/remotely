/// <reference types="node" />
// UX-09: one-time tips. Dismissed ids are kept in local storage, "Show tips again" clears them, and storage that is
// missing, full or holding something else never breaks a page. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";

/** A local storage stand-in; `failing` makes every call throw, as a full or blocked store does. */
class FakeStorage {
  values = new Map<string, string>();
  failing = false;
  getItem(key: string) {
    if (this.failing) throw new Error("blocked");
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    if (this.failing) throw new Error("full");
    this.values.set(key, value);
  }
  removeItem(key: string) {
    if (this.failing) throw new Error("blocked");
    this.values.delete(key);
  }
}

const storage = new FakeStorage();
storage.values.set("remotely.tips.dismissed", JSON.stringify(["vms.selection", 5, "terminal.pickTabs"]));
Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });

// Imported after the stand-in is in place: the module reads storage on first use.
const tips = await import("./tips.ts");

test("stored values are read loosely: anything that isn't a list of ids is none", () => {
  assert.deepEqual([...tips.parseDismissed(null)], []);
  assert.deepEqual([...tips.parseDismissed("")], []);
  assert.deepEqual([...tips.parseDismissed("{not json")], []);
  assert.deepEqual([...tips.parseDismissed('{"a":1}')], []);
  assert.deepEqual([...tips.parseDismissed('["b", 2, "a", null]')], ["b", "a"]);
  assert.equal(tips.serialiseDismissed(new Set(["b", "a"])), '["a","b"]');
});

test("a dismissed tip stays dismissed, and Show tips again brings every tip back", () => {
  assert.ok(tips.isTipDismissed("vms.selection"), "read from storage");
  assert.ok(!tips.isTipDismissed("dashboard.customize"));
  let calls = 0;
  const stop = tips.subscribeTips(() => calls++);
  tips.dismissTip("dashboard.customize");
  tips.dismissTip("dashboard.customize");
  assert.equal(calls, 1, "dismissing twice notifies once");
  assert.ok(tips.isTipDismissed("dashboard.customize"));
  assert.deepEqual(JSON.parse(storage.values.get("remotely.tips.dismissed") ?? "[]"), [
    "dashboard.customize",
    "terminal.pickTabs",
    "vms.selection",
  ]);
  assert.equal(tips.dismissedTipCount(), 3);
  const before = tips.tipsSnapshot();
  tips.resetTips();
  assert.notEqual(tips.tipsSnapshot(), before, "a new snapshot for useSyncExternalStore");
  assert.equal(tips.dismissedTipCount(), 0);
  assert.ok(!storage.values.has("remotely.tips.dismissed"), "the key is removed");
  assert.equal(calls, 2);
  stop();
  tips.dismissTip("vms.selection");
  assert.equal(calls, 2, "no call after unsubscribing");
});

test("storage that throws doesn't break anything: the tip is just not remembered", () => {
  storage.failing = true;
  assert.doesNotThrow(() => tips.dismissTip("schedules.first"));
  assert.ok(tips.isTipDismissed("schedules.first"), "kept for this run");
  assert.doesNotThrow(() => tips.resetTips());
  storage.failing = false;
});
