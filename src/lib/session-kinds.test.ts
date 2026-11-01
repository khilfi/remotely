/// <reference types="node" />
// SS-12: session kinds as the editor, tabs and rows use them. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  comPortName,
  defaultKind,
  kindAddress,
  kindOf,
  kindSummary,
  joinReason,
  opensInTab,
  opensWindow,
  paneKindOf,
  portAfterKindChange,
  rdpProblem,
  RDP_DEFAULTS,
  serialFrame,
  serialProblem,
  SERIAL_DEFAULTS,
  takesJumpHost,
} from "./session-kinds.ts";

test("each kind's defaults, and what it opens", () => {
  assert.deepEqual(defaultKind("telnet"), { protocol: "telnet", lineEnding: "crLf" });
  assert.equal(defaultKind("rdp").protocol, "rdp");
  assert.ok(opensInTab(defaultKind("ssh")) && opensInTab(defaultKind("serial")));
  assert.ok(opensWindow(defaultKind("rdp")) && opensWindow(defaultKind("vnc")));
  assert.ok(takesJumpHost(defaultKind("vnc")) && !takesJumpHost(defaultKind("telnet")));
  // A record from before 0.7.0 is SSH.
  assert.deepEqual(kindOf({ protocol: "ssh" }), { protocol: "ssh" });
});

test("the port follows the kind unless one was typed", () => {
  assert.equal(portAfterKindChange("22", "ssh", "rdp"), "3389");
  assert.equal(portAfterKindChange("", "ssh", "telnet"), "23");
  assert.equal(portAfterKindChange("2222", "ssh", "telnet"), "2222");
  assert.equal(portAfterKindChange("1", "serial", "vnc"), "5900");
  assert.equal(portAfterKindChange("22", "ssh", "serial"), "22");
});

test("serial lines are checked and named as 8N1", () => {
  assert.equal(serialFrame(SERIAL_DEFAULTS), "9600 8N1");
  assert.equal(serialFrame({ ...SERIAL_DEFAULTS, speed: 115200, parity: "even", stopBits: "two" }), "115200 8E2");
  assert.equal(serialProblem(SERIAL_DEFAULTS), null);
  assert.ok(serialProblem({ ...SERIAL_DEFAULTS, speed: 10 }));
  assert.ok(serialProblem({ ...SERIAL_DEFAULTS, stopBits: "onePointFive" }));
  assert.equal(serialProblem({ ...SERIAL_DEFAULTS, dataBits: 5, stopBits: "onePointFive" }), null);
  assert.equal(comPortName(" com7 "), "COM7");
  for (const bad of ["COM0", "COM03", "COM257", "LPT1", "\\\\.\\COM3", "COM"])
    assert.equal(comPortName(bad), null, bad);
});

test("an RDP window has a sensible size", () => {
  assert.equal(rdpProblem(RDP_DEFAULTS), null);
  assert.ok(rdpProblem({ ...RDP_DEFAULTS, screen: { mode: "window", width: 100, height: 800 } }));
  assert.equal(rdpProblem({ ...RDP_DEFAULTS, screen: { mode: "window", width: 1600, height: 900 } }), null);
});

test("rows say where a session connects and what its kind sets", () => {
  assert.equal(
    kindAddress({ host: "COM3", port: 1, username: null, kind: { protocol: "serial", ...SERIAL_DEFAULTS } }),
    "COM3 · 9600 8N1",
  );
  assert.equal(
    kindAddress({
      host: "vnc01.example.com",
      port: 5901,
      username: "alice",
      kind: { protocol: "vnc", viewOnly: true },
    }),
    "vnc01.example.com:5901",
  );
  assert.equal(kindAddress({ host: "web01.example.com", port: 22, username: "alice" }), "alice@web01.example.com:22");
  assert.equal(kindSummary({ protocol: "rdp", ...RDP_DEFAULTS }), "full screen · clipboard");
  assert.equal(kindSummary({ protocol: "telnet", lineEnding: "cr" }), "Enter sends CR");
  assert.equal(
    kindSummary({ protocol: "serial", ...SERIAL_DEFAULTS, flowControl: "rtsCts", localEcho: true }),
    "9600 8N1 · RTS/CTS · local echo",
  );
  assert.equal(kindSummary({ protocol: "ssh" }), null);
});

test("only SSH tabs join typing in all tabs and Compare hosts", () => {
  assert.equal(joinReason("ssh"), null);
  assert.equal(joinReason(undefined), null);
  for (const kind of ["telnet", "serial", "tunnel"] as const) assert.ok(joinReason(kind), kind);
  assert.equal(paneKindOf(defaultKind("rdp"), true), "tunnel");
  assert.equal(paneKindOf(defaultKind("telnet"), false), "telnet");
});
