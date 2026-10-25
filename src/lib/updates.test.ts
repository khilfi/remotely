/// <reference types="node" />
// FD-14: update check wording and the check after a used-up GitHub limit. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { checkMessage, isNotice, localTime, RECHECK_MARGIN_MS, recheckDelayMs } from "./updates.ts";

const NOW = Date.parse("2026-10-25T12:00:00Z");

test("a check after a used-up limit runs just after GitHub's reset", () => {
  const limited = { status: "rateLimited", until: "2026-10-25T12:40:00Z", withToken: false } as const;
  assert.equal(recheckDelayMs(limited, NOW), 40 * 60_000 + RECHECK_MARGIN_MS);
  // A reset already past: check again shortly.
  const past = { ...limited, until: "2026-10-25T11:00:00Z" };
  assert.equal(recheckDelayMs(past, NOW), RECHECK_MARGIN_MS);
  // The 24-hour check comes first, or the time is unreadable.
  assert.equal(recheckDelayMs({ ...limited, until: "2026-10-27T12:00:00Z" }, NOW), null);
  assert.equal(recheckDelayMs({ ...limited, until: "soon" }, NOW), null);
});

test("only a used-up limit schedules another check", () => {
  for (const result of [
    { status: "upToDate" },
    { status: "off" },
    { status: "vaultLocked" },
    { status: "tokenNeeded", repository: "alice/remotely" },
  ] as const) {
    assert.equal(recheckDelayMs(result, NOW), null, result.status);
  }
});

test("messages say what the check found and what helps", () => {
  const now = new Date(NOW);
  assert.equal(
    checkMessage(
      { status: "available", update: { version: "0.5.0", currentVersion: "0.4.2", notes: null, pubDate: null } },
      now,
    ),
    "Version 0.5.0 is available.",
  );
  assert.equal(checkMessage({ status: "upToDate" }, now), "You have the latest version.");
  assert.match(
    checkMessage({ status: "tokenNeeded", repository: "alice/remotely" }, now),
    /alice\/remotely.*private again/,
  );
  assert.match(checkMessage({ status: "vaultLocked" }, now), /Unlock the vault/);
  const anonymous = checkMessage({ status: "rateLimited", until: "2026-10-25T12:40:00Z", withToken: false }, now);
  assert.match(anonymous, /without a token/);
  assert.match(anonymous, /A GitHub update token/);
  assert.doesNotMatch(
    checkMessage({ status: "rateLimited", until: "2026-10-25T12:40:00Z", withToken: true }, now),
    /without a token/,
  );
});

test("token and limit results are notices, not successes", () => {
  assert.equal(isNotice({ status: "rateLimited", until: "2026-10-25T12:40:00Z", withToken: false }), true);
  assert.equal(isNotice({ status: "tokenNeeded", repository: "alice/remotely" }), true);
  assert.equal(isNotice({ status: "vaultLocked" }), true);
  assert.equal(isNotice({ status: "upToDate" }), false);
  assert.equal(isNotice({ status: "off" }), false);
});

test("times are local, with the date when it is not today", () => {
  const now = new Date(NOW);
  const today = localTime("2026-10-25T12:40:00Z", now);
  assert.match(today, /\d/);
  assert.equal(today.includes(new Date(NOW).toLocaleDateString()), false);
  assert.ok(localTime("2026-10-29T12:40:00Z", now).includes(new Date("2026-10-29T12:40:00Z").toLocaleDateString()));
  assert.equal(localTime("not a time", now), "later");
});
