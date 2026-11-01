/// <reference types="node" />
// MO-08: health checks in words, the editor's checks and defaults, the status bar's text and the sparkline. Run with
// `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  agoText,
  checkProblem,
  cleanCheckInput,
  defaultSpec,
  everyText,
  kindTakes,
  needingLook,
  newCheckInput,
  sparkPath,
  specText,
  statusTone,
  suggestedName,
  summaryText,
  tookText,
  uptimeText,
} from "./checks.ts";
import type { CheckInput, CheckRow, CheckStatus } from "./checks-api.ts";

const web = { kind: "address", host: "web01.example.com" } as const;

function input(change: Partial<CheckInput> = {}): CheckInput {
  return { ...newCheckInput(web, "web01"), ...change };
}

test("a new check is named after its target and takes a kind it can run", () => {
  const made = newCheckInput(web, "web01");
  assert.equal(made.name, "web01 HTTP(S)");
  assert.equal(made.spec.kind, "http");
  assert.equal(made.intervalSecs, 60);
  assert.equal(made.failuresBeforeDown, 2);
  assert.equal(newCheckInput({ kind: "vm", vmKey: "x" }, "db", "dns").spec.kind, "tcp", "a VM has no name to look up");
  assert.equal(newCheckInput(web, "web01", "service").spec.kind, "tcp", "a service needs a session");
  assert.equal(newCheckInput({ kind: "session", sessionId: "s" }, "app", "service").spec.kind, "service");
  assert.equal(suggestedName("x".repeat(90), "ping").length, 80);
  assert.equal(newCheckInput({ kind: "address", host: "" }, "").name, "", "named once there is a target");
  assert.equal(kindTakes("ping", "vm"), true);
});

test("the editor refuses what the core refuses, with a reason", () => {
  assert.equal(checkProblem(input()), null);
  assert.match(checkProblem(input({ name: "  " }))!, /name/);
  assert.match(checkProblem(input({ intervalSecs: 20 }))!, /30 seconds/);
  assert.match(checkProblem(input({ timeoutSecs: 60, intervalSecs: 60 }))!, /shorter/);
  assert.match(checkProblem(input({ failuresBeforeDown: 0 }))!, /1 to 10/);
  assert.match(checkProblem(input({ target: { kind: "address", host: " " } }))!, /host name/);
  assert.match(checkProblem(input({ spec: { kind: "tcp", port: 70000 } }))!, /port/);
  const http = defaultSpec("http");
  if (http.kind !== "http") throw new Error("not http");
  assert.match(checkProblem(input({ spec: { ...http, path: "/a b" } }))!, /path/);
  assert.match(checkProblem(input({ spec: { ...http, statusMin: 500, statusMax: 200 } }))!, /range/);
  assert.match(checkProblem(input({ spec: { kind: "service", unit: "nginx; reboot" } }))!, /session/);
  assert.match(
    checkProblem(
      input({ target: { kind: "session", sessionId: "s" }, spec: { kind: "service", unit: "nginx; reboot" } }),
    )!,
    /unit/,
  );
  assert.equal(
    checkProblem(input({ target: { kind: "session", sessionId: "s" }, spec: { kind: "service", unit: "nginx" } })),
    null,
  );
  const dns = { kind: "dns", recordType: "A", server: null, expect: null } as const;
  assert.match(checkProblem(input({ target: { kind: "address", host: "192.0.2.10" }, spec: dns }))!, /not an address/);
  assert.match(checkProblem(input({ spec: { ...dns, expect: "web01" } }))!, /expected address/);
  assert.equal(checkProblem(input({ spec: { ...dns, expect: "192.0.2.10", server: "2001:db8::53" } })), null);
});

test("the input is cleaned before it goes to the core", () => {
  const http = defaultSpec("http");
  if (http.kind !== "http") throw new Error("not http");
  const clean = cleanCheckInput(
    input({
      name: " web ",
      target: { kind: "address", host: " web01.example.com " },
      spec: { ...http, path: " ", bodyContains: "  " },
    }),
  );
  assert.equal(clean.name, "web");
  assert.deepEqual(clean.target, { kind: "address", host: "web01.example.com" });
  assert.equal(clean.spec.kind === "http" && clean.spec.path, "/");
  assert.equal(clean.spec.kind === "http" && clean.spec.bodyContains, null);
});

test("checks, times and uptime read in words", () => {
  assert.equal(specText(defaultSpec("http")), "HTTPS GET / (200-399)");
  assert.equal(specText({ kind: "tcp", port: 22 }), "TCP port 22");
  assert.equal(
    specText({ kind: "dns", recordType: "A", server: null, expect: "192.0.2.10" }),
    "DNS A record, expecting 192.0.2.10",
  );
  assert.equal(everyText(60), "every 1 minute");
  assert.equal(everyText(30), "every 30 seconds");
  assert.equal(everyText(3600), "every 1 hour");
  assert.equal(uptimeText(null), "—");
  assert.equal(uptimeText(100), "100%");
  assert.equal(uptimeText(99.54), "99.5%");
  assert.equal(uptimeText(0), "0%");
  assert.equal(tookText(85.4), "85 ms");
  assert.equal(tookText(1234), "1.2 s");
  assert.equal(agoText(1_000, 10_000), "just now");
  assert.equal(agoText(0, 3 * 60_000), "3 min ago");
  assert.equal(agoText(0, 5 * 3_600_000), "5 h ago");
  assert.equal(agoText(0, 3 * 86_400_000), "3 d ago");
  assert.equal(statusTone("down"), "bad");
  assert.equal(statusTone("paused"), "muted");
});

test("the status bar counts down and failing checks only", () => {
  const summary = { total: 5, up: 2, failing: 1, down: 1, unknown: 1, paused: 0, pending: 0 };
  assert.equal(summaryText(summary), "2 checks failing");
  assert.equal(summaryText({ ...summary, failing: 0, down: 1 }), "1 check failing");
  assert.equal(summaryText({ ...summary, failing: 0, down: 0 }), null);
});

test("the widget lists down first, then failing, then what can't be checked", () => {
  const row = (status: CheckStatus, name: string) => ({ status, check: { name } }) as unknown as CheckRow;
  const look = needingLook([
    row("up", "a"),
    row("unknown", "b"),
    row("down", "c"),
    row("failing", "d"),
    row("paused", "e"),
  ]);
  assert.deepEqual(
    look.map((r) => r.check.name),
    ["c", "d", "b"],
  );
});

test("a sparkline puts the slowest run at the top and skips buckets without a time", () => {
  assert.equal(sparkPath([], 100, 20), "");
  assert.equal(sparkPath([{ at: 0, ms: 5 }], 100, 20), "");
  const path = sparkPath(
    [
      { at: 0, ms: 10 },
      { at: 50, ms: null },
      { at: 100, ms: 20 },
    ],
    100,
    20,
  );
  assert.equal(path, "M0.0,10.0 L100.0,1.0");
});
