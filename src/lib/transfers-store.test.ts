/// <reference types="node" />
// SS-08, P6: the transfers store the panel and the drawer read instead of the Terminal page's state. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { TransferInfo } from "./api.ts";
import { createTransferStore, uploadsDone } from "./transfers-store.ts";

function transfer(id: string, state: TransferInfo["state"], more: Partial<TransferInfo> = {}): TransferInfo {
  return {
    id,
    jobId: null,
    terminalId: "t1",
    terminal: "'web01'",
    direction: "upload",
    name: `${id}.txt`,
    remotePath: `/srv/${id}.txt`,
    localPath: null,
    size: 10,
    done: 0,
    bytesPerSec: 0,
    state,
    message: null,
    sha256: null,
    replace: false,
    ...more,
  };
}

test("the snapshot stays the same object until something changes, and listeners hear each change", () => {
  const store = createTransferStore();
  let heard = 0;
  const stop = store.subscribe(() => (heard += 1));
  const first = store.getSnapshot();
  assert.equal(store.getSnapshot(), first, "useSyncExternalStore needs the same snapshot between changes");
  store.apply(transfer("a", "running"));
  const second = store.getSnapshot();
  assert.notEqual(second, first);
  assert.equal(store.getSnapshot(), second);
  assert.equal(heard, 1);
  stop();
  store.apply({ ...transfer("a", "running"), done: 5 });
  assert.equal(heard, 1, "unsubscribed");
});

test("progress replaces a transfer in place and says nothing ended", () => {
  const store = createTransferStore();
  store.load([transfer("a", "running"), transfer("b", "queued")]);
  for (const done of [2, 4, 6, 8]) assert.equal(store.apply({ ...transfer("a", "running"), done }), false);
  const { all } = store.getSnapshot();
  assert.deepEqual(
    all.map((t) => [t.id, t.done]),
    [
      ["a", 8],
      ["b", 0],
    ],
  );
});

test("a transfer that ends says so once; one first seen finished does not", () => {
  const store = createTransferStore();
  store.apply(transfer("a", "queued"));
  assert.equal(store.apply(transfer("a", "running")), false);
  assert.equal(store.apply({ ...transfer("a", "done"), done: 10 }), true, "running -> done");
  assert.equal(store.apply({ ...transfer("a", "done"), done: 10 }), false, "the same state again");
  assert.equal(store.apply(transfer("b", "failed")), false, "never seen running: no news");
  store.apply(transfer("c", "running"));
  assert.equal(store.apply(transfer("c", "cancelled")), true);
});

test("a change that came before the page's first list keeps its newer state", () => {
  const store = createTransferStore();
  store.apply({ ...transfer("a", "running"), done: 7 });
  store.load([transfer("a", "queued"), transfer("b", "done")]);
  assert.deepEqual(
    store.getSnapshot().all.map((t) => [t.id, t.state, t.done]),
    [
      ["a", "running", 7],
      ["b", "done", 0],
    ],
  );
  // A loaded transfer counts as seen: its end later is news.
  assert.equal(store.apply(transfer("a", "done")), true);
});

test("Clear hides finished transfers from the panel only; running ones and later ones show", () => {
  const store = createTransferStore();
  store.load([transfer("a", "done"), transfer("b", "running"), transfer("c", "failed")]);
  const before = store.getSnapshot();
  store.clearFinished();
  const { all, shown } = store.getSnapshot();
  assert.equal(all.length, 3, "still known (the drawer counts finished uploads)");
  assert.deepEqual(
    shown.map((t) => t.id),
    ["b"],
  );
  store.apply(transfer("d", "queued"));
  assert.deepEqual(
    store.getSnapshot().shown.map((t) => t.id),
    ["b", "d"],
  );
  // Nothing finished to clear: no new snapshot, no re-render.
  const now = store.getSnapshot();
  store.clearFinished();
  assert.equal(store.getSnapshot(), now);
  assert.notEqual(now, before);
});

test("the drawer counts the uploads finished through its own terminal", () => {
  const all = [
    transfer("a", "done"),
    transfer("b", "done", { terminalId: "t2" }),
    transfer("c", "done", { direction: "download" }),
    transfer("d", "running"),
    transfer("e", "done"),
  ];
  assert.equal(uploadsDone(all, "t1"), 2);
  assert.equal(uploadsDone(all, "t2"), 1);
  assert.equal(uploadsDone(all, null), 0);
});
