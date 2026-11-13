/// <reference types="node" />
// VM-32: the address pool editor's checks (the core's, said before saving) and the tab's wording. Run with `npm test`.
// Addresses from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 198.18.0.0/15 only.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  deletePoolReason,
  EMPTY_POOL_FORM,
  formatIpv4,
  freeReason,
  parseIpv4,
  parsePoolForm,
  poolForm,
  poolNetworkKinds,
  poolNetworkText,
  sizeText,
  usedText,
  type PoolForm,
} from "./address-pools.ts";
import type { AddressLease } from "./address-pools-api.ts";

const LAB: PoolForm = {
  ...EMPTY_POOL_FORM,
  name: " lab ",
  firstIp: "192.0.2.10",
  lastIp: "192.0.2.50",
  gateway: "192.0.2.1",
  dns: ["192.0.2.53", "", "192.0.2.53"],
};

function error(change: Partial<PoolForm>, taken: string[] = []): string {
  const parsed = parsePoolForm({ ...LAB, ...change }, taken);
  assert.ok("error" in parsed, `refused: ${JSON.stringify(change)}`);
  return parsed.error;
}

test("dotted IPv4 addresses read as the core reads them", () => {
  assert.equal(parseIpv4("192.0.2.10"), 0xc000020a);
  assert.equal(formatIpv4(0xc000020a), "192.0.2.10");
  assert.equal(formatIpv4(0xffffffff), "255.255.255.255");
  for (const bad of ["192.0.2", "192.0.2.256", "192.0.2.010", "192.0.2.1.1", "a.b.c.d", "", "2001:db8::1"])
    assert.equal(parseIpv4(bad), null, bad);
});

test("a pool is tidied into what the core gets", () => {
  const parsed = parsePoolForm({ ...LAB, hostAdapter: "ignored" });
  assert.ok("input" in parsed);
  assert.deepEqual(parsed.input, {
    name: "lab",
    hypervisor: "vmware",
    network: { kind: "nat" },
    hostAdapter: null,
    firstIp: "192.0.2.10",
    lastIp: "192.0.2.50",
    prefix: 24,
    gateway: "192.0.2.1",
    dnsServers: ["192.0.2.53"],
    notes: null,
  });
  assert.equal(parsed.size, 41);
  assert.equal(parsed.usable, 41);
  const inside = parsePoolForm({ ...LAB, gateway: "192.0.2.10", dns: ["192.0.2.11", "198.51.100.53", ""] });
  assert.ok("input" in inside);
  assert.equal(inside.usable, 39, "the gateway and a DNS server in the range are never handed out");
  // Back to a form and through again.
  const again = parsePoolForm(poolForm(parsed.input));
  assert.ok("input" in again);
  assert.deepEqual(again.input, parsed.input);
});

test("ranges are one IPv4 subnet without its own or its broadcast address", () => {
  assert.match(error({ firstIp: "2001:db8::1" }), /IPv4 only/);
  assert.match(error({ lastIp: "" }), /^Give the last address/);
  assert.match(error({ firstIp: "192.0.2.60" }), /comes after/);
  assert.match(
    error({ prefix: "25", firstIp: "192.0.2.100", lastIp: "192.0.2.200", gateway: "" }),
    /different \/25 subnets/,
  );
  assert.match(error({ firstIp: "192.0.2.0" }), /subnet's own address .* start at 192\.0\.2\.1 /);
  assert.match(error({ lastIp: "192.0.2.255" }), /broadcast address: end at 192\.0\.2\.254 /);
  assert.match(
    error({ prefix: "25", firstIp: "198.51.100.128", lastIp: "198.51.100.140", gateway: "" }),
    /subnet's own address \(198\.51\.100\.128\/25\)/,
  );
  assert.match(
    error({ prefix: "25", firstIp: "198.51.100.120", lastIp: "198.51.100.140", gateway: "" }),
    /different \/25 subnets/,
  );
  assert.match(error({ prefix: "31" }), /\/8 to \/30/);
  assert.match(error({ prefix: "7" }), /\/8 to \/30/);
  assert.match(error({ firstIp: "127.0.0.1" }), /can't be used/);
  assert.match(error({ firstIp: "169.254.0.10" }), /can't be used/);
  assert.match(error({ prefix: "8", firstIp: "0.0.0.5", lastIp: "0.0.0.9", gateway: "" }), /can't be used/);
  assert.match(
    error({ prefix: "16", firstIp: "198.18.0.1", lastIp: "198.18.16.1", gateway: "" }),
    /at most 4096 addresses; 198\.18\.0\.1 to 198\.18\.16\.1 is 4097/,
  );
  const exactly = parsePoolForm({ ...LAB, prefix: "/16", firstIp: "198.18.0.1", lastIp: "198.18.16.0", gateway: "" });
  assert.ok("input" in exactly);
  assert.equal(exactly.size, 4096);
  const tiny = parsePoolForm({ ...LAB, prefix: "30", firstIp: "203.0.113.5", lastIp: "203.0.113.6", gateway: "" });
  assert.ok("input" in tiny);
  assert.equal(tiny.size, 2);
});

test("the gateway, DNS servers, names and networks are checked", () => {
  assert.match(error({ gateway: "198.51.100.1" }), /isn't an address of 192\.0\.2\.0\/24/);
  assert.match(error({ dns: ["224.0.0.1", "", ""] }), /can't be used/);
  assert.match(error({ dns: ["192.0.2.255", "", ""] }), /own or broadcast address/);
  assert.match(error({ dns: ["192.0.2.0", "", ""] }), /own or broadcast address/);
  assert.match(error({ name: "  " }), /^Give the address pool a name/);
  assert.match(error({ name: "a\tb" }), /invisible/);
  assert.match(error({ name: "lab\u202e" }), /invisible/);
  assert.match(error({ name: "x".repeat(61) }), /at most 60/);
  assert.match(error({}, ["LAB"]), /named 'lab' already/);
  // Letter case beyond ASCII folds as the core folds it.
  assert.match(error({ name: "LÄB" }, ["Läb"]), /named 'LÄB' already/);
  assert.match(error({ network: { kind: "vmnet", number: 20 } }), /vmnet0 to vmnet19/);
  assert.match(error({ network: { kind: "natNetwork", name: "lab" } }), /VirtualBox's/);
  assert.match(error({ hypervisor: "virtualbox", network: { kind: "vmnet", number: 2 } }), /Workstation's/);
  assert.match(error({ hypervisor: "virtualbox", network: { kind: "internal", name: "lab;x" } }), /letters, digits/);
});

test("VirtualBox pools name their host-only adapter, and never sit where this PC has no adapter", () => {
  assert.deepEqual(poolNetworkKinds("virtualbox"), ["hostOnly", "bridged"]);
  assert.deepEqual(poolNetworkKinds("vmware"), ["nat", "hostOnly", "bridged", "vmnet"]);
  const vbox: Partial<PoolForm> = { hypervisor: "virtualbox", network: { kind: "hostOnly" } };
  assert.match(error(vbox), /^Pick VirtualBox's host-only adapter/);
  const named = parsePoolForm({ ...LAB, ...vbox, hostAdapter: "  vboxnet0 " });
  assert.ok("input" in named);
  assert.equal(named.input.hostAdapter, "vboxnet0");
  for (const [network, says] of [
    [{ kind: "nat" }, /VirtualBox's NAT \(each VM's network of its own\)/],
    [{ kind: "natNetwork", name: " lab net " }, /VirtualBox's NAT network 'lab net'/],
    [{ kind: "internal", name: "lab" }, /VirtualBox's internal network 'lab'/],
  ] as const) {
    assert.match(error({ hypervisor: "virtualbox", network }), says);
  }
  assert.equal(poolNetworkText({ network: { kind: "hostOnly" }, hostAdapter: "vboxnet0" }), "Host-only 'vboxnet0'");
  assert.equal(poolNetworkText({ network: { kind: "nat" }, hostAdapter: null }), "NAT");
  assert.equal(poolNetworkText({ network: { kind: "vmnet", number: 2 }, hostAdapter: null }), "Custom vmnet (vmnet2)");
});

test("the tab's words", () => {
  assert.equal(usedText({ used: 3, usable: 41, heldElsewhere: 0 }), "3 of 41 used");
  assert.equal(usedText({ used: 3, usable: 41, heldElsewhere: 2 }), "3 of 41 used, 2 more held in another workspace");
  assert.equal(sizeText(41, 41), "41 addresses");
  assert.equal(sizeText(41, 40), "41 addresses, 40 to hand out");
  assert.equal(deletePoolReason(null, { used: 0 }), null);
  assert.equal(deletePoolReason("Read-only", { used: 0 }), "Read-only");
  assert.match(deletePoolReason(null, { used: 2 }) ?? "", /^VMs hold 2 of its addresses/);
  const lease: AddressLease = {
    poolId: "p",
    ip: "192.0.2.10",
    vmKey: "C:\\VMs\\web\\web.vmx",
    vmName: "web",
    jobId: null,
    state: "assigned",
    createdAt: "2026-11-14T00:00:00Z",
    canFree: false,
  };
  assert.match(freeReason(null, lease) ?? "", /^web is still on the VMs page/);
  assert.equal(freeReason(null, { ...lease, canFree: true }), null);
  assert.match(freeReason(null, { ...lease, state: "claimed" }) ?? "", /^A deploy is making web/);
});
