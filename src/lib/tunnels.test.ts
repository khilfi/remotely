/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ForwardInput, TunnelInfo } from "./api.ts";
import {
  clashes,
  exposureText,
  forwardsProblem,
  forwardProblem,
  forwardText,
  isLoopback,
  jumpChain,
  liveTunnels,
  routeText,
  tunnelStateText,
  viaText,
  type JumpLink,
} from "./tunnels.ts";

const links = (list: [string, string, string | null][]) =>
  new Map<string, JumpLink>(list.map(([id, name, jumpSessionId]) => [id, { id, name, jumpSessionId }]));

test("a chain lists the jump hosts in the order they are connected", () => {
  const byId = links([
    ["b", "bastion", null],
    ["i", "inner", "b"],
    ["d", "db01", "i"],
  ]);
  assert.deepEqual(jumpChain("d", byId), { names: ["bastion", "inner"], loop: false });
  assert.deepEqual(jumpChain("b", byId), { names: [], loop: false });
  assert.equal(routeText(["bastion", "inner"]), "bastion → inner");
  assert.equal(viaText(["bastion", "inner"]), "via inner");
  assert.equal(viaText([]), null);
});

test("a chain that goes round in a loop says so", () => {
  const byId = links([
    ["a", "a", "b"],
    ["b", "b", "a"],
  ]);
  assert.equal(jumpChain("a", byId).loop, true);
  // A jump host that is gone ends the chain.
  assert.deepEqual(jumpChain("x", links([["x", "x", "gone"]])), { names: [], loop: false });
});

test("loopback listeners are told apart from network ones", () => {
  for (const a of ["127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "127.1.2.3"])
    assert.equal(isLoopback(a), true, a);
  for (const a of ["0.0.0.0", "::", "192.0.2.10", "web01.example.com"]) assert.equal(isLoopback(a), false, a);
});

const input = (change: Partial<ForwardInput>): ForwardInput => ({
  id: null,
  label: null,
  kind: "local",
  bindAddress: "",
  bindPort: 8080,
  destHost: "db01.example.com",
  destPort: 5432,
  autoStart: true,
  ...change,
});

test("forwards read like the audit log", () => {
  assert.equal(
    forwardText({
      kind: "local",
      bindAddress: "127.0.0.1",
      bindPort: 8080,
      destHost: "db01.example.com",
      destPort: 5432,
    }),
    "local 127.0.0.1:8080 → db01.example.com:5432",
  );
  assert.equal(
    forwardText({ kind: "remote", bindAddress: "localhost", bindPort: 0, destHost: "127.0.0.1", destPort: 3000 }),
    "remote localhost (any free port) on the host → 127.0.0.1:3000",
  );
  assert.equal(
    forwardText({ kind: "dynamic", bindAddress: "::1", bindPort: 1080, destHost: "", destPort: 0 }),
    "SOCKS on [::1]:1080",
  );
});

test("the dialog says what is wrong with a forward before saving", () => {
  assert.equal(forwardProblem(input({})), null);
  assert.equal(forwardProblem(input({ kind: "dynamic", destHost: "", destPort: 0 })), null);
  assert.match(forwardProblem(input({ destHost: " " })) ?? "", /where it leads/);
  assert.match(forwardProblem(input({ destPort: 0 })) ?? "", /port it leads to/);
  assert.match(forwardProblem(input({ bindPort: 70000 })) ?? "", /0 to 65535/);
  assert.match(forwardProblem(input({ bindAddress: "web01.example.com" })) ?? "", /IP address/);
});

test("who can use a tunnel is said plainly", () => {
  assert.equal(exposureText({ kind: "local", bindAddress: "" }), "Only this PC can use it.");
  assert.equal(exposureText({ kind: "remote", bindAddress: "localhost" }), "Only programs on the host can use it.");
  assert.match(exposureText({ kind: "dynamic", bindAddress: "0.0.0.0" }), /other computers that reach this PC/);
});

test("tunnel states read naturally", () => {
  const forward = {
    id: "f",
    sessionId: "s",
    label: null,
    kind: "local" as const,
    bindAddress: "127.0.0.1",
    bindPort: 0,
    destHost: "db01.example.com",
    destPort: 5432,
    autoStart: true,
  };
  const t = (state: TunnelInfo["state"], connections = 0): TunnelInfo => ({
    forward,
    state,
    connections,
    open: 0,
    lastError: null,
    saved: true,
    changed: false,
  });
  assert.equal(
    tunnelStateText(t({ state: "listening", at: "127.0.0.1:53211" }, 2)),
    "Listening on 127.0.0.1:53211, 2 connections",
  );
  assert.equal(tunnelStateText(t({ state: "failed", message: "port taken" })), "Failed: port taken");
  assert.equal(liveTunnels([t({ state: "listening", at: "x" }), t({ state: "stopped" })]), 1);
  assert.equal(liveTunnels(null), 0);
});

test("two forwards listening on one port on the same side clash", () => {
  const list = [
    input({ bindPort: 8080 }),
    input({ kind: "dynamic", bindAddress: "127.0.0.1", bindPort: 8080, destHost: "", destPort: 0 }),
    input({ kind: "remote", bindPort: 8080 }),
    input({ bindPort: 0 }),
    input({ bindPort: 0 }),
  ];
  assert.deepEqual([...clashes(list)].sort(), [0, 1], "a remote one listens on the host; port 0 never clashes");
  assert.match(forwardsProblem(list) ?? "", /listen on one port/);
  assert.match(forwardsProblem([input({ destPort: 0 })]) ?? "", /^Port forward 1: /);
  assert.equal(forwardsProblem([input({})]), null);
});
