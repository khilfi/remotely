/// <reference types="node" />
// R10 links: which values are links this version opens, and what a button that opens one says. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { isAppLink, linkLabel, type AppLink } from "./links.ts";

const EVERY: AppLink[] = [
  { kind: "page", page: "activity" },
  { kind: "vm", vmxPath: "C:\\VMs\\web\\web.vmx", view: "snapshots" },
  { kind: "session", sessionId: "s-1" },
  { kind: "terminal", terminalId: "t-1", tunnels: true },
  { kind: "job", jobId: "j-1" },
  { kind: "container", host: { kind: "thisPc" }, engine: "docker", containerId: "abc" },
  { kind: "catalog", tab: "sizes", id: "gp.medium" },
  { kind: "setting", section: "updates" },
  { kind: "snippet", command: "disk usage" },
  { kind: "alerts" },
  { kind: "update" },
  { kind: "vault" },
  { kind: "map" },
  { kind: "schedule", scheduleId: "s-1" },
];

test("every kind of link is one, and has words for its button", () => {
  for (const link of EVERY) {
    assert.ok(isAppLink(link), link.kind);
    assert.ok(linkLabel(link).length > 0, link.kind);
  }
});

test("values that aren't links this version can open are refused", () => {
  const refused: unknown[] = [
    null,
    "job",
    { kind: "schedule", id: "x" },
    { kind: "job" },
    { kind: "job", jobId: "" },
    { kind: "job", jobId: 5 },
    { kind: "container", engine: "docker", containerId: "abc" },
    { kind: "container", host: { kind: "session" }, engine: "docker", containerId: "abc" },
    { kind: "catalog", tab: "deploy" },
    { kind: "toString" },
  ];
  for (const value of refused) assert.equal(isAppLink(value), false, JSON.stringify(value));
});
