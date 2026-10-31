/// <reference types="node" />
// UX-06: counts read as words ("2 entries", not "2 entrys"). Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { plural } from "./format.ts";

test("plural adds s, or ies after a consonant and y", () => {
  assert.equal(plural(1, "entry"), "1 entry");
  assert.equal(plural(0, "entry"), "0 entries");
  assert.equal(plural(3, "entry"), "3 entries");
  assert.equal(plural(2, "security update"), "2 security updates");
  // A vowel before the y keeps it.
  assert.equal(plural(2, "key"), "2 keys");
  assert.equal(plural(7, "day"), "7 days");
  assert.equal(plural(4, "VM"), "4 VMs");
  assert.equal(plural(1, "session"), "1 session");
});
