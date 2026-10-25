import assert from "node:assert/strict";
import test from "node:test";

import { earliestExpiry, expiryProblem, keyOptions, optionsPrefix, parseFrom } from "./key-options.ts";

test("only-from takes hosts, addresses and networks, and nothing that could end the option", () => {
  assert.deepEqual(parseFrom("192.0.2.0/24, *.example.com\n!198.51.100.7"), {
    patterns: ["192.0.2.0/24", "*.example.com", "!198.51.100.7"],
    problem: null,
  });
  assert.deepEqual(parseFrom("  "), { patterns: [], problem: null });
  // Spaces and commas separate patterns, so only what sshd's option could not hold is refused.
  for (const bad of ['192.0.2.1" command="sh', "a;b", "x/24/8", "back\\slash"]) {
    assert.ok(parseFrom(bad).problem, bad);
  }
  assert.match(parseFrom(Array.from({ length: 33 }, (_, i) => `h${i}`).join(" ")).problem ?? "", /At most 32/);
});

test("an expiry is a day after today, in UTC", () => {
  const now = new Date("2026-10-25T12:00:00Z");
  assert.equal(earliestExpiry(now), "2026-10-26");
  assert.equal(expiryProblem("", now), null);
  assert.equal(expiryProblem("2026-12-01", now), null);
  assert.match(expiryProblem("2026-10-25", now) ?? "", /after today/);
  assert.match(expiryProblem("next week", now) ?? "", /as a day/);
});

test("the options read as the core writes them", () => {
  const options = keyOptions("2026-12-01", "192.0.2.0/24 *.example.com");
  assert.deepEqual(options, { expiresOn: "2026-12-01", from: ["192.0.2.0/24", "*.example.com"] });
  assert.equal(optionsPrefix(options), 'expiry-time="20261201Z",from="192.0.2.0/24,*.example.com"');
  assert.equal(optionsPrefix(keyOptions("", "")), "");
});
