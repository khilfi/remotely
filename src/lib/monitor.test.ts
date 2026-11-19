/// <reference types="node" />
// UX-19 (0.9.0 H4): monitoring setup: Monitor ▸'s watch state and cost lines, where an alerts link leads, and the
// checks "Add a check" and "Keep checking this…" fill in. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { checkProblem } from "./checks.ts";
import type { DnsRecord } from "./toolbox-api.ts";
import type { ToolTarget } from "./toolbox.ts";
import {
  alertsOpens,
  certificateCheck,
  checkCostText,
  dnsCheck,
  dnsCheckProblem,
  pingCheck,
  portCheck,
  requestedCheck,
  sessionSource,
  vmSource,
  watchable,
  watchCostText,
  watchState,
} from "./monitor.ts";

// A session's kind from its protocol, as kindOf reads a record without one.
const ssh = { id: "s-web", name: "web01", protocol: "ssh" };
const winrm = { id: "s-win", name: "win01", protocol: "winrm" };
const rdp = { id: "s-rdp", name: "desk01", protocol: "rdp" };

test("a session reads its guest over SSH or WinRM only", () => {
  assert.equal(watchable(ssh).readsGuest, true);
  assert.equal(watchable({ ...ssh, kind: { protocol: "ssh" } }).readsGuest, true, "its kind when it has one");
  assert.equal(watchable(winrm).readsGuest, true);
  assert.equal(watchable(rdp).readsGuest, false);
  assert.equal(watchable({ ...ssh, protocol: "telnet" }).readsGuest, false);
});

test("a session's own row is watched through itself", () => {
  assert.deepEqual(watchState(sessionSource(ssh), new Set()), {
    can: true,
    sessionId: "s-web",
    watching: false,
    via: null,
  });
  assert.deepEqual(watchState(sessionSource(ssh), new Set(["s-web"])), {
    can: true,
    sessionId: "s-web",
    watching: true,
    via: null,
  });
  const refused = watchState(sessionSource(rdp), new Set());
  assert.equal(refused.can, false);
  assert.match(refused.can ? "" : refused.reason, /SSH and WinRM/);
});

test("a VM is watched through a linked session that reads its guest, the watched one first", () => {
  const sessions = [
    { ...rdp, vmId: "vm-1" },
    { ...ssh, vmId: "vm-1" },
    { ...winrm, vmId: "vm-1" },
    { id: "s-other", name: "db01", protocol: "ssh", vmId: "vm-2" },
  ];
  assert.deepEqual(watchState(vmSource("vm-1", sessions), new Set()), {
    can: true,
    sessionId: "s-web",
    watching: false,
    via: "web01",
  });
  assert.deepEqual(watchState(vmSource("vm-1", sessions), new Set(["s-win"])), {
    can: true,
    sessionId: "s-win",
    watching: true,
    via: "win01",
  });
  // Another VM's watched session doesn't count.
  assert.equal(watchState(vmSource("vm-1", sessions), new Set(["s-other"])).can, true);
  const none = watchState(vmSource("vm-1", [{ ...rdp, vmId: "vm-1" }]), new Set());
  assert.equal(none.can, false);
  assert.match(none.can ? "" : none.reason, /Link an SSH or WinRM session/);
  assert.equal(watchState(vmSource("vm-3", sessions), new Set()).can, false);
});

test("each item says what it costs in one line", () => {
  const off = { can: true as const, sessionId: "s", watching: false, via: null };
  assert.equal(watchCostText(off, 5), "Keeps a login open and reads it every 5 s");
  assert.equal(watchCostText({ ...off, via: "web01" }, 60), "Keeps a login to web01 open and reads it every 1 min");
  assert.equal(watchCostText(off, 0), "Keeps a login open and reads it every 5 s", "before the first round");
  assert.equal(watchCostText({ ...off, watching: true }, 5), "Closes the login it keeps");
  assert.equal(watchCostText({ ...off, watching: true, via: "web01" }, 5), "Closes the login to web01");
  assert.equal(checkCostText(), "A probe from this PC every minute");
  assert.equal(checkCostText(300), "A probe from this PC every 5 minutes");
  assert.equal(checkCostText(30), "A probe from this PC every 30 seconds");
  for (const line of [watchCostText(off, 15), checkCostText()]) assert.ok(!line.includes("\n"));
});

test("an alerts link opens the widget, or the rules without one on the layout", () => {
  assert.equal(alertsOpens({}, ["capacity", "alerts", "overview"]), "widget");
  assert.equal(alertsOpens({}, new Set(["capacity", "overview"])), "rules", "the widget was removed");
  assert.equal(alertsOpens({}, []), "rules", "an empty layout");
  assert.equal(alertsOpens({ rules: true }, ["alerts"]), "rules", "the palette's Alert rules");
  assert.equal(alertsOpens({ rules: false }, ["alerts"]), "widget");
});

const host: ToolTarget = { kind: "address", host: "web01.example.com" };
const session: ToolTarget = { kind: "session", sessionId: "s-web", label: "web01" };
const vm: ToolTarget = { kind: "vm", vmKey: "C:\\VMs\\web\\web.vmx", label: "web-vm" };

test("Add a check opens the editor's default check on the row, named after it", () => {
  const onSession = requestedCheck(session);
  assert.deepEqual(onSession.target, { kind: "session", sessionId: "s-web" });
  assert.equal(onSession.name, "web01 HTTP(S)");
  assert.equal(onSession.spec.kind, "http");
  assert.equal(onSession.intervalSecs, 60, "what checkCostText says");
  assert.equal(requestedCheck(vm).target.kind, "vm");
  assert.equal(requestedCheck({ kind: "address", host: " web01.example.com " }).target.kind, "address");
});

/** The check a `checks` link's editor opens with, as the Checks tab makes it. */
function opened(link: ReturnType<typeof pingCheck> | null) {
  assert.ok(link?.add, "a link with a target");
  return requestedCheck(link.add, link.spec);
}

test("Keep checking this fills in what each tool ran", () => {
  const ping = opened(pingCheck(session));
  assert.deepEqual(ping.spec, { kind: "ping" });
  assert.equal(ping.name, "web01 Ping");
  assert.equal(checkProblem(ping), null);

  const port = portCheck(host, 8443);
  assert.deepEqual(port, { kind: "checks", add: host, spec: { kind: "tcp", port: 8443 } });
  assert.equal(opened(port).name, "web01.example.com TCP port");
  assert.equal(checkProblem(opened(port)), null);

  const cert = certificateCheck(vm, 443, "  www.example.com ");
  assert.deepEqual(cert.spec, { kind: "certificate", port: 443, serverName: "www.example.com", allowUntrusted: false });
  assert.deepEqual(certificateCheck(vm, 8443, "").spec, {
    kind: "certificate",
    port: 8443,
    serverName: null,
    allowUntrusted: false,
  });
  assert.equal(checkProblem(opened(cert)), null);
});

test("a DNS lookup becomes a check of A or AAAA records, expecting its one address", () => {
  const one: DnsRecord[] = [{ name: "web01.example.com", recordType: "A", ttl: 300, data: "192.0.2.10" }];
  const link = dnsCheck(" web01.example.com ", "A", " 198.51.100.53 ", one);
  assert.deepEqual(link, {
    kind: "checks",
    add: { kind: "address", host: "web01.example.com" },
    spec: { kind: "dns", recordType: "A", server: "198.51.100.53", expect: "192.0.2.10" },
  });
  assert.equal(checkProblem(opened(link)), null);

  const two: DnsRecord[] = [...one, { name: "web01.example.com", recordType: "A", ttl: 300, data: "192.0.2.11" }];
  const any = dnsCheck("web01.example.com", "A", "", two);
  assert.deepEqual(any?.spec, { kind: "dns", recordType: "A", server: null, expect: null }, "round robin: any");
  // A CNAME on the way isn't the address expected.
  const viaAlias: DnsRecord[] = [
    { name: "www.example.com", recordType: "CNAME", ttl: 300, data: "web01.example.com" },
    { name: "web01.example.com", recordType: "AAAA", ttl: 300, data: "2001:db8::10" },
  ];
  assert.deepEqual(dnsCheck("www.example.com", "AAAA", "", viaAlias)?.spec, {
    kind: "dns",
    recordType: "AAAA",
    server: null,
    expect: "2001:db8::10",
  });
  assert.deepEqual(dnsCheck("web01.example.com", "A", "", [])?.spec, {
    kind: "dns",
    recordType: "A",
    server: null,
    expect: null,
  });

  for (const type of ["MX", "TXT", "PTR", "CNAME"] as const) {
    assert.equal(dnsCheck("example.com", type, "", []), null, type);
    assert.match(dnsCheckProblem(type) ?? "", /A or AAAA/);
  }
  assert.equal(dnsCheckProblem("AAAA"), null);
});

test("a spec the target can't take falls back to the editor's default", () => {
  // A DNS check looks up a name, never a VM's address.
  const input = requestedCheck(vm, { kind: "dns", recordType: "A", server: null, expect: null });
  assert.notEqual(input.spec.kind, "dns");
});
