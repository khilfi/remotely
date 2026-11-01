/// <reference types="node" />
// FD-09: the subnet calculator. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { calculate, countText, formatV6, parseV4, parseV6, prefixOfMask, split, type SubnetInfo } from "./subnet.ts";

function info(text: string): SubnetInfo {
  const result = calculate(text);
  assert.ok(result.ok, text);
  return result.info;
}

test("an IPv4 CIDR gives its network, mask, wildcard, broadcast, hosts and counts", () => {
  const net = info("192.0.2.130/26");
  assert.equal(net.cidr, "192.0.2.128/26");
  assert.equal(net.network, "192.0.2.128");
  assert.equal(net.mask, "255.255.255.192");
  assert.equal(net.wildcard, "0.0.0.63");
  assert.equal(net.broadcast, "192.0.2.191");
  assert.equal(net.first, "192.0.2.129");
  assert.equal(net.last, "192.0.2.190");
  assert.equal(net.addresses, 64n);
  assert.equal(net.hosts, 62n);
});

test("a mask is read in place of a prefix, either way it is written", () => {
  assert.equal(info("198.51.100.7 255.255.255.0").cidr, "198.51.100.0/24");
  assert.equal(info("198.51.100.7/255.255.240.0").cidr, "198.51.96.0/20");
  assert.equal(info("203.0.113.9").cidr, "203.0.113.9/32");
  assert.equal(prefixOfMask("255.255.255.0"), 24);
  assert.equal(prefixOfMask("255.0.255.0"), null, "not contiguous");
  assert.equal(calculate("192.0.2.1/255.0.255.0").ok, false);
});

test("/31 and /32 have no broadcast: every address is a host", () => {
  const p2p = info("192.0.2.4/31");
  assert.equal(p2p.broadcast, null);
  assert.equal(p2p.first, "192.0.2.4");
  assert.equal(p2p.last, "192.0.2.5");
  assert.equal(p2p.hosts, 2n);
  const one = info("192.0.2.4/32");
  assert.equal(one.hosts, 1n);
  assert.equal(one.first, one.last);
  const everything = info("0.0.0.0/0");
  assert.equal(everything.addresses, 4294967296n);
  assert.equal(everything.mask, "0.0.0.0");
});

test("IPv6 gives the network, first and last address and the count", () => {
  const net = info("2001:db8:abcd:12::1/64");
  assert.equal(net.cidr, "2001:db8:abcd:12::/64");
  assert.equal(net.first, "2001:db8:abcd:12::");
  assert.equal(net.last, "2001:db8:abcd:12:ffff:ffff:ffff:ffff");
  assert.equal(net.mask, null);
  assert.equal(net.broadcast, null);
  assert.equal(net.addresses, 1n << 64n);
  assert.equal(countText(net.addresses), "2^64");
  assert.equal(info("[2001:DB8::1]").cidr, "2001:db8::1/128");
  assert.equal(info("fe80::1%eth0/10").network, "fe80::");
});

test("IPv6 is read in every spelling and written as RFC 5952 says", () => {
  assert.equal(parseV6("::"), 0n);
  assert.equal(parseV6("::1"), 1n);
  assert.equal(formatV6(parseV6("2001:0db8:0000:0000:0001:0000:0000:0001") as bigint), "2001:db8::1:0:0:1");
  assert.equal(formatV6(parseV6("2001:db8:0:1:1:1:1:1") as bigint), "2001:db8:0:1:1:1:1:1", "one zero stays");
  assert.equal(formatV6(parseV6("::ffff:192.0.2.10") as bigint), "::ffff:c000:20a");
  for (const bad of ["1::2::3", "2001:db8:::1", "12345::", "1:2:3:4:5:6:7:8:9", "g::1", "1:2:3:4:5:6:7::8:9"]) {
    assert.equal(parseV6(bad), null, bad);
  }
});

test("IPv4 refuses what isn't a dotted address", () => {
  for (const bad of ["192.0.2", "192.0.2.256", "192.0.2.010", "a.b.c.d", "192.0.2.1.5"]) {
    assert.equal(parseV4(bad), null, bad);
  }
  for (const bad of ["", "web01.example.com/24", "192.0.2.1/33", "2001:db8::/129", "192.0.2.1/24 extra"]) {
    assert.equal(calculate(bad).ok, false, bad);
  }
});

test("a split lists the smaller subnets in order, up to a cap, with the full count", () => {
  const net = info("192.0.2.0/24");
  const quarters = split(net, 26);
  assert.ok(quarters.ok);
  assert.deepEqual(quarters.subnets, ["192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"]);
  assert.equal(quarters.listedAll, true);
  const many = split(info("10.0.0.0/8"), 24);
  assert.ok(many.ok);
  assert.equal(many.total, 65536n);
  assert.equal(many.subnets.length, 256);
  assert.equal(many.subnets[255], "10.0.255.0/24");
  assert.equal(many.listedAll, false);
  const v6 = split(info("2001:db8::/32"), 34);
  assert.ok(v6.ok);
  assert.deepEqual(v6.subnets, ["2001:db8::/34", "2001:db8:4000::/34", "2001:db8:8000::/34", "2001:db8:c000::/34"]);
  assert.equal(split(net, 24).ok, false, "not smaller");
  assert.equal(split(net, 33).ok, false);
});

test("counts read with separators until they are too long", () => {
  assert.equal(countText(62n), "62");
  assert.equal(countText(16777214n), "16,777,214");
  assert.equal(countText(1n << 80n), "2^80");
});
