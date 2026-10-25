/// <reference types="node" />
// QL-05: terminal copies go to the clipboard one at a time, the last selection last. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { latestOnly } from "./clipboard-copy.ts";

/** A send that finishes only when the test says so. */
function controlledSend() {
  const sent: string[] = [];
  const finish: Array<(err?: Error) => void> = [];
  const send = (value: string) =>
    new Promise<void>((resolve, reject) => {
      sent.push(value);
      finish.push((err) => (err ? reject(err) : resolve()));
    });
  return { sent, finish, send };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

test("a copy goes at once", () => {
  const { sent, send } = controlledSend();
  const copy = latestOnly(send, () => assert.fail("no error"));
  copy("$ uptime");
  assert.deepEqual(sent, ["$ uptime"]);
});

test("copies made while one is on its way: only the newest follows it", async () => {
  const { sent, finish, send } = controlledSend();
  const copy = latestOnly(send, () => assert.fail("no error"));
  copy("first");
  copy("second");
  copy("third");
  assert.deepEqual(sent, ["first"], "one at a time");
  finish[0]();
  await settle();
  assert.deepEqual(sent, ["first", "third"], "the clipboard ends with the last selection");
  finish[1]();
  await settle();
  assert.deepEqual(sent, ["first", "third"], "nothing else was waiting");
  copy("fourth");
  assert.deepEqual(sent, ["first", "third", "fourth"]);
});

test("a failed copy is reported and the next one still goes", async () => {
  const { sent, finish, send } = controlledSend();
  const errors: unknown[] = [];
  const copy = latestOnly(send, (err) => errors.push(err));
  copy("first");
  copy("second");
  finish[0](new Error("the clipboard couldn't be written"));
  await settle();
  assert.equal(errors.length, 1);
  assert.deepEqual(sent, ["first", "second"]);
});

test("a send that throws at once is reported too", async () => {
  const errors: unknown[] = [];
  let calls = 0;
  const copy = latestOnly(
    () => {
      calls += 1;
      throw new Error("no shell");
    },
    (err) => errors.push(err),
  );
  copy("first");
  await settle();
  copy("second");
  await settle();
  assert.equal(calls, 2);
  assert.equal(errors.length, 2);
});
