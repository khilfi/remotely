/// <reference types="node" />
// UX-19 (0.9.0 H4): monitoring setup: Monitor ▸'s watch state (every watched session, any kind stoppable) and cost
// lines (through a jump host), where an alerts link leads, and the checks "Add a check" and "Keep checking this…" fill
// in, offered only when the editor and the core take them. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { checkProblem } from "./checks.ts";
import type { DnsRecord } from "./toolbox-api.ts";
import type { ToolTarget } from "./toolbox.ts";
import {
  alertsOpens,
  certificateCheck,
  certificateFinding,
  checkCostText,
  checkVia,
  dnsCheck,
  dnsCheckProblem,
  keepCheckingProblem,
  pingCheck,
  portCheck,
  requestedCheck,
  sessionSource,
  vmSource,
  watchable,
  watchCostText,
  watchedFrom,
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

test("a watched session can be stopped whatever its kind now", () => {
  // Watched over SSH, then edited into an RDP session: it is still watched and must be stoppable.
  assert.deepEqual(watchState(sessionSource(rdp), new Set(["s-rdp"])), {
    can: true,
    sessionId: "s-rdp",
    watching: true,
    via: null,
  });
  assert.deepEqual(watchState(vmSource("vm-1", [{ ...rdp, vmId: "vm-1" }]), new Set(["s-rdp"])), {
    can: true,
    sessionId: "s-rdp",
    watching: true,
    via: "desk01",
  });
});

test("every watched session counts, not one per VM (the metrics_watched read)", () => {
  // web-vm has two linked sessions, both watched. The overview's VM row names only one of them; the watched list
  // names both, so each session's Monitor says Stop watching and the second can be stopped first.
  const webAdmin = { id: "s-admin", name: "web-admin", protocol: "ssh", vmId: "vm-web" };
  const webDeploy = { id: "s-deploy", name: "web-deploy", protocol: "ssh", vmId: "vm-web" };
  const { watched, intervalSecs } = watchedFrom({ sessions: ["s-admin", "s-deploy"], intervalSecs: 15 });
  assert.equal(intervalSecs, 15);
  for (const s of [webAdmin, webDeploy]) {
    const state = watchState(sessionSource(s), watched);
    assert.ok(state.can && state.watching, s.name);
    assert.equal(state.can ? watchCostText(state, intervalSecs) : "", "Closes the login it keeps");
  }
  const vm = watchState(vmSource("vm-web", [webAdmin, webDeploy]), watched);
  assert.ok(vm.can && vm.watching);
  // The overview's one session per VM (the old read) left web-deploy looking unwatched.
  assert.deepEqual(watchState(sessionSource(webDeploy), new Set(["s-admin"])), {
    can: true,
    sessionId: "s-deploy",
    watching: false,
    via: null,
  });
  assert.equal(watchedFrom({ sessions: [], intervalSecs: 0 }).intervalSecs, 5, "no interval from the core");
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
  assert.equal(checkCostText(null, 300), "A probe from this PC every 5 minutes");
  assert.equal(checkCostText(null, 30), "A probe from this PC every 30 seconds");
  // Behind a jump host the check goes through it, and holds its login between runs up to every 10 minutes.
  assert.equal(
    checkCostText("bastion"),
    "A probe through bastion every minute; the login to it stays open between runs",
  );
  assert.equal(
    checkCostText("bastion", 600),
    "A probe through bastion every 10 minutes; the login to it stays open between runs",
  );
  assert.equal(checkCostText("bastion", 1800), "A probe through bastion every 30 minutes, logging in to it each time");
  for (const line of [watchCostText(off, 15), checkCostText(), checkCostText("bastion")]) {
    assert.ok(!line.includes("\n"));
  }
});

test("a session's check goes through its own jump host, by name", () => {
  const sessions = [
    { id: "j-1", name: "bastion" },
    { id: "s-1", name: "web01" },
  ];
  assert.equal(checkVia({ jumpSessionId: "j-1" }, sessions), "bastion");
  assert.equal(checkVia({ jumpSessionId: null }, sessions), null);
  assert.equal(checkVia({ jumpSessionId: "gone" }, sessions), "its jump host");
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

test("Keep checking this is offered only for a DNS check the editor and the core take (checks/spec.rs)", () => {
  const lookup = (name: string, server = "") => keepCheckingProblem(dnsCheck(name, "A", server, []));
  assert.equal(lookup("web01.example.com"), null);
  // A lookup of an address: the core looks up names only.
  assert.match(lookup("192.0.2.10") ?? "", /not an address/);
  assert.match(lookup("[2001:db8::10]") ?? "", /not an address/);
  // A name the core's check_host refuses (ASCII letters, digits and . - _ : % only).
  assert.match(lookup("bücher.example.com") ?? "", /isn't a host name/);
  assert.match(lookup("web01 example") ?? "", /isn't a host name/);
  // Servers as the core reads them: brackets and zones are fine, a name isn't.
  assert.equal(lookup("web01.example.com", "[2001:db8::53]"), null);
  assert.equal(lookup("web01.example.com", "fe80::1%12"), null);
  assert.equal(lookup("web01.example.com", "198.51.100.53"), null);
  assert.match(lookup("web01.example.com", "dns.example.com") ?? "", /DNS server as an IP address/);
  // What the button says for a type no check looks up.
  assert.equal(keepCheckingProblem(dnsCheck("example.com", "MX", "", [])), "This result can't become a check.");
  // The other tools' checks are taken.
  assert.equal(keepCheckingProblem(pingCheck(session)), null);
  assert.equal(keepCheckingProblem(portCheck(host, 22)), null);
  assert.equal(keepCheckingProblem(certificateCheck(vm, 443, "www.example.com")), null);
});

test("an untrusted certificate's check says it will be down until allowed", () => {
  const read = { trusted: false, nameMatches: true, serverName: "www.example.com", host: "192.0.2.10" };
  assert.equal(certificateFinding(read, ""), "isn't trusted by this PC");
  assert.equal(
    certificateFinding({ ...read, nameMatches: false }, "web.example.com"),
    "isn't trusted by this PC and doesn't name web.example.com",
  );
  assert.equal(certificateFinding({ ...read, trusted: true, nameMatches: false }, ""), "doesn't name www.example.com");
  assert.equal(certificateFinding({ ...read, trusted: true }, ""), null);
  assert.equal(certificateFinding({ ...read, trusted: true, nameMatches: null }, ""), null, "no name to check");
  // The default stays: untrusted ones aren't allowed; the editor is told why the check will be down.
  const link = certificateCheck(host, 443, "", certificateFinding(read, ""));
  assert.equal(link.untrusted, "isn't trusted by this PC");
  assert.equal(link.spec?.kind === "certificate" && link.spec.allowUntrusted, false);
  assert.equal(certificateCheck(host, 443, "", null).untrusted, undefined);
});

test("a spec the target can't take becomes a TCP check, newCheckInput's fallback", () => {
  // A DNS check looks up a name, never a VM's address.
  const input = requestedCheck(vm, { kind: "dns", recordType: "A", server: null, expect: null });
  assert.equal(input.spec.kind, "tcp");
  assert.equal(input.name, "web-vm TCP port");
});
