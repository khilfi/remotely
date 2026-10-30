/// <reference types="node" />
// FD-14, UX-04: which one update notice shows. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { updateNotice } from "./update-notice.ts";

const update = { currentVersion: "0.5.0", version: "0.6.0", notes: "Tidier.", pubDate: null };

test("one notice at most: a newer release, then a failed check, then a token needed", () => {
  const problem = { code: "update_failed", message: "GitHub didn't answer" };
  assert.equal(updateNotice({ status: "available", update }, problem, null)?.kind, "available");
  assert.equal(updateNotice({ status: "upToDate" }, problem, null)?.kind, "problem");
  assert.deepEqual(updateNotice({ status: "tokenNeeded", repository: "example/remotely" }, null, null), {
    kind: "tokenNeeded",
    key: "tokenNeeded",
    repository: "example/remotely",
  });
  assert.equal(updateNotice({ status: "upToDate" }, null, null), null);
  assert.equal(updateNotice({ status: "rateLimited", until: "", withToken: false }, null, null), null);
  assert.equal(updateNotice(null, null, null), null);
});

test("Later hides a notice until there is something else to say", () => {
  assert.equal(updateNotice({ status: "available", update }, null, "0.6.0"), null);
  assert.equal(
    updateNotice({ status: "available", update: { ...update, version: "0.6.1" } }, null, "0.6.0")?.kind,
    "available",
  );
  assert.equal(updateNotice({ status: "tokenNeeded", repository: "x" }, null, "tokenNeeded"), null);
});
