/// <reference types="node" />
// FD-09: the Toolbox's helpers: tools, targets, the recent inputs kept per tool, and how results read. Run with
// `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  certificateVerdict,
  daysLeftText,
  dnsServerText,
  echoText,
  hasTarget,
  HISTORY_LIMIT,
  isToolboxTool,
  normalizeMac,
  pingSummaryText,
  probeTarget,
  recentInputs,
  recentScope,
  rememberInput,
  rttText,
  setRecentScope,
  subscribeRecentScope,
  TOOLBOX_TOOLS,
  wakeAddress,
  type HistoryStorage,
} from "./toolbox.ts";
import type { CertificateReport, PingSummary } from "./toolbox-api.ts";

function memory(): HistoryStorage & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
  };
}

test("the tools are tabs in a fixed order, each id once", () => {
  const ids = TOOLBOX_TOOLS.map((t) => t.id);
  assert.deepEqual(ids, ["ping", "trace", "dns", "ports", "certificate", "subnet", "wake"]);
  assert.ok(isToolboxTool("ports"));
  assert.ok(!isToolboxTool("scan"));
  assert.ok(!isToolboxTool(undefined));
});

test("a target loses its label on the way to the core", () => {
  assert.deepEqual(probeTarget({ kind: "session", sessionId: "s-1", label: "web01" }), {
    kind: "session",
    sessionId: "s-1",
  });
  assert.deepEqual(probeTarget({ kind: "address", host: " 192.0.2.10 " }), { kind: "address", host: "192.0.2.10" });
  assert.equal(hasTarget({ kind: "address", host: "  " }), false);
  assert.equal(hasTarget({ kind: "vm", vmKey: "k", label: "web" }), true);
});

const WS = "ws-a";

test("recent inputs keep the last twenty, newest first, each once", () => {
  const storage = memory();
  for (let i = 0; i < 25; i++) rememberInput("ping", WS, `192.0.2.${i}`, storage);
  const list = recentInputs("ping", WS, storage);
  assert.equal(list.length, HISTORY_LIMIT);
  assert.equal(list[0], "192.0.2.24");
  rememberInput("ping", WS, "192.0.2.10", storage);
  const again = recentInputs("ping", WS, storage);
  assert.equal(again[0], "192.0.2.10");
  assert.equal(again.filter((v) => v === "192.0.2.10").length, 1);
  assert.deepEqual(recentInputs("dns", WS, storage), [], "per tool");
  rememberInput("dns", WS, "Web01.Example.com", storage);
  rememberInput("dns", WS, "web01.example.com", storage);
  assert.deepEqual(recentInputs("dns", WS, storage), ["web01.example.com"], "any letter case once");
  assert.deepEqual(rememberInput("dns", WS, "   ", storage), ["web01.example.com"], "blank is not kept");
});

test("each workspace keeps its own recent inputs, and none are kept before the workspace is known", () => {
  const storage = memory();
  rememberInput("ports", "ws-a", "db01.customer-a.example", storage);
  rememberInput("ports", "ws-b", "web01.customer-b.example", storage);
  assert.deepEqual(recentInputs("ports", "ws-a", storage), ["db01.customer-a.example"]);
  assert.deepEqual(recentInputs("ports", "ws-b", storage), ["web01.customer-b.example"]);
  assert.deepEqual(recentInputs("ports", null, storage), []);
  assert.deepEqual(rememberInput("ports", null, "192.0.2.9", storage), ["192.0.2.9"], "shown, not saved");
  assert.equal(storage.data.size, 2);
});

test("the workspace scope is set once and tells who listens", () => {
  const seen: (string | null)[] = [];
  const stop = subscribeRecentScope(() => seen.push(recentScope()));
  setRecentScope("ws-test");
  setRecentScope("ws-test");
  stop();
  setRecentScope("ws-other");
  assert.deepEqual(seen, ["ws-test"]);
  assert.equal(recentScope(), "ws-other");
});

test("storage that throws or holds junk gives no history and no error", () => {
  const broken: HistoryStorage = {
    getItem: () => {
      throw new Error("blocked");
    },
    setItem: () => {
      throw new Error("full");
    },
  };
  assert.deepEqual(recentInputs("ping", WS, broken), []);
  assert.deepEqual(rememberInput("ping", WS, "192.0.2.1", broken), ["192.0.2.1"]);
  const junk = memory();
  junk.setItem(`remotely.toolbox.recent.${WS}.ping`, "{not json");
  assert.deepEqual(recentInputs("ping", WS, junk), []);
  junk.setItem(`remotely.toolbox.recent.${WS}.ping`, JSON.stringify(["192.0.2.1", 5, null]));
  assert.deepEqual(recentInputs("ping", WS, junk), ["192.0.2.1"]);
  assert.deepEqual(recentInputs("ping", WS, null), []);
});

test("ping results read in plain words", () => {
  assert.equal(rttText(0), "<1 ms");
  assert.equal(rttText(12), "12 ms");
  assert.equal(rttText(null), "*");
  assert.equal(
    echoText({ kind: "reply", from: "192.0.2.10", rttMs: 3, ttl: 64 }),
    "Reply from 192.0.2.10: 3 ms, TTL 64",
  );
  assert.equal(echoText({ kind: "timedOut" }), "No answer");
  assert.equal(
    echoText({ kind: "unreachable", from: "198.51.100.1", reason: "the host can't be reached" }),
    "198.51.100.1: the host can't be reached",
  );
  const summary: PingSummary = {
    label: "web01",
    host: "web01.example.com",
    address: "192.0.2.10",
    replies: [],
    sent: 4,
    received: 3,
    lossPercent: 25,
    minMs: 1,
    avgMs: 2.5,
    maxMs: 4,
    cancelled: false,
  };
  assert.equal(pingSummaryText(summary), "4 sent, 3 received, 25% lost · min 1 ms, average 2.5 ms, max 4 ms");
  assert.equal(
    pingSummaryText({ ...summary, received: 0, lossPercent: 100, avgMs: null }),
    "4 sent, 0 received, 100% lost",
  );
});

test("DNS servers and certificate days read in plain words", () => {
  assert.equal(dnsServerText({ kind: "chosen", address: "192.0.2.53" }), "Asked 192.0.2.53");
  assert.equal(
    dnsServerText({ kind: "windows", servers: ["192.0.2.53"] }),
    "Windows' resolver (this PC's DNS servers: 192.0.2.53)",
  );
  assert.equal(daysLeftText(42), "Expires in 42 days");
  assert.equal(daysLeftText(0), "Expires today");
  assert.equal(daysLeftText(-3), "Expired 3 days ago");
  assert.equal(daysLeftText(null), null);
});

test("a certificate's verdict names what is wrong", () => {
  const report: CertificateReport = {
    source: "web01 (web01.example.com:443)",
    address: "192.0.2.10",
    via: null,
    serverName: "web01.example.com",
    protocol: "TLS 1.3",
    cipher: null,
    chain: [],
    built: [],
    trusted: true,
    trustProblems: [],
    nameMatches: true,
    daysLeft: 90,
    handshakeError: null,
    unreadable: [],
    host: "web01.example.com",
    hosts: ["web01.example.com"],
  };
  assert.deepEqual(certificateVerdict(report), { ok: true, text: "Trusted and valid · expires in 90 days" });
  assert.deepEqual(certificateVerdict({ ...report, trusted: false, nameMatches: false }), {
    ok: false,
    text: "Not trusted by this PC, doesn't name web01.example.com",
  });
});

test("MACs and wake-up addresses are checked like the core does", () => {
  assert.equal(normalizeMac("00-0C-29-AB-CD-EF"), "00:0c:29:ab:cd:ef");
  assert.equal(normalizeMac("000c.29ab.cdef"), "00:0c:29:ab:cd:ef");
  for (const bad of ["", "00:0c:29", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:00:5e:00:00:01", "zz0c29abcdef"]) {
    assert.equal(normalizeMac(bad), null, bad);
  }
  assert.equal(wakeAddress("192.0.2.255"), "192.0.2.255");
  for (const bad of ["0.0.0.0", "224.0.0.1", "192.0.2", "192.0.2.256", "nas01"]) {
    assert.equal(wakeAddress(bad), null, bad);
  }
});
