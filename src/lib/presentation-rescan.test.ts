/// <reference types="node" />
// FD-03: which text on screen is masked again after the masker learns a value. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { Masker, type Learned } from "./presentation.ts";
import { LearnedBatch, mentionsAny } from "./presentation-rescan.ts";

test("the masker says which value it learnt, once", () => {
  const m = new Masker();
  const heard: Learned[] = [];
  const stop = m.onChange((learned) => heard.push(learned));
  m.learn("host", "web01.example.com");
  m.learn("user", "alice");
  m.learn("host", "WEB01.example.com");
  m.learn("ip", "192.0.2.10");
  assert.deepEqual(heard, [
    { kind: "host", value: "web01.example.com" },
    { kind: "user", value: "alice" },
  ]);
  stop();
  m.learn("user", "bob");
  assert.equal(heard.length, 2, "no longer listening");
});

test("only text that mentions a learnt value is masked again", () => {
  const mentions = mentionsAny(["web01.example.com", "alice"]);
  assert.ok(mentions);
  assert.equal(mentions("Connected to web01.example.com"), true);
  assert.equal(mentions("ALICE logged in"), true, "letter case is the masker's to decide");
  assert.equal(mentions("Saved 3 sessions"), false);
  assert.equal(mentions(""), false);
  // Dots are dots, not "any character".
  assert.equal(mentions("web01xexamplexcom"), false);
});

test("values with characters regular expressions use are found as written", () => {
  const mentions = mentionsAny(["db+1.example.com", "a(b)", "x|y"]);
  assert.ok(mentions);
  assert.equal(mentions("open db+1.example.com"), true);
  assert.equal(mentions("dbb1.example.com"), false);
  assert.equal(mentions("call a(b) now"), true);
  assert.equal(mentions("x"), false);
  assert.equal(mentions("x|y"), true);
});

test("nothing learnt means nothing to look for", () => {
  assert.equal(mentionsAny([]), null);
  assert.equal(mentionsAny([""]), null);
});

test("values learnt in one go are one rescan", () => {
  const batch = new LearnedBatch();
  assert.equal(batch.add({ kind: "host", value: "web01.example.com" }), true, "the first queues the rescan");
  assert.equal(batch.add({ kind: "user", value: "alice" }), false);
  assert.equal(batch.add({ kind: "user", value: "alice" }), false);
  assert.equal(batch.size, 2);
  assert.deepEqual(batch.take().sort(), ["alice", "web01.example.com"]);
  assert.equal(batch.size, 0);
  assert.equal(batch.add({ kind: "user", value: "bob" }), true, "a new batch after the rescan");
});
