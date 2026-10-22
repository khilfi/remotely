/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalIpv6,
  fitWidth,
  hostPart,
  isLocalAddress,
  learnFields,
  Masker,
  namesAHost,
  PAD,
  parseIpv6,
  TerminalMasker,
} from "./presentation.ts";

const ESC = "\x1b";

test("IPv4 addresses get stable stand-ins, numbered as first seen", () => {
  const m = new Masker();
  assert.equal(m.text("Connected to 192.0.2.10:22"), "Connected to ip-1:22");
  assert.equal(m.text("then 198.51.100.7/24 and 192.0.2.10 again"), "then ip-2/24 and ip-1 again");
  assert.equal(m.text("203.0.113.255"), "ip-3");
  // Not addresses: versions with more parts, numbers inside words.
  assert.equal(m.text("version 1.2.3.4.5"), "version 1.2.3.4.5");
  assert.equal(m.text("v192.0.2.1"), "v192.0.2.1");
  assert.equal(m.text("999.0.2.1"), "999.0.2.1");
});

test("loopback and 'any' addresses stay, so tunnel listeners still read right", () => {
  const m = new Masker();
  assert.equal(m.text("Listening on 127.0.0.1:8080"), "Listening on 127.0.0.1:8080");
  assert.equal(m.text("on 0.0.0.0, every network"), "on 0.0.0.0, every network");
  assert.equal(m.text("[::1]:22 and ::"), "[::1]:22 and ::");
  assert.equal(m.text("localhost:9000"), "localhost:9000");
  assert.ok(isLocalAddress("127.12.0.1"));
  assert.ok(!isLocalAddress("192.0.2.1"));
});

test("IPv6 addresses, compressed or not, are one address", () => {
  const m = new Masker();
  assert.equal(m.text("2001:db8::1"), "ip-1");
  assert.equal(m.text("2001:0db8:0000:0000:0000:0000:0000:0001"), "ip-1");
  assert.equal(m.text("ssh -p 22 [2001:db8::1]:22"), "ssh -p 22 [ip-1]:22");
  assert.equal(m.text("fe80::1ff:fe23:4567:890a%eth0 up"), "ip-2 up");
  assert.equal(m.text("::ffff:192.0.2.1"), "ip-3");
  assert.equal(m.text("2001:db8:85a3::8a2e:370:7334"), "ip-4");
  // Not IP addresses: times, MAC addresses (MO-13 masks those as MACs), C++ names, words of hex letters.
  assert.equal(m.text("at 12:34:56"), "at 12:34:56");
  assert.equal(m.text("00:1a:2b:3c:4d:5e"), "mac-1");
  assert.equal(m.text("std::vector and dead::beef"), "std::vector and dead::beef");
  assert.equal(canonicalIpv6(parseIpv6("2001:db8:0:0:1:0:0:1") ?? []), "2001:db8::1:0:0:1");
  assert.equal(parseIpv6("1:2:3"), null);
  assert.equal(parseIpv6("1::2::3"), null);
});

test("a listener's 'any' address stays, whatever ss calls it", () => {
  const m = new Masker();
  assert.equal(m.field("ip", "*"), "*");
  assert.equal(m.field("ip", "[::]"), "[::]");
  assert.equal(m.field("ip", "0.0.0.0"), "0.0.0.0");
  assert.equal(m.field("ip", "192.0.2.10"), "ip-1");
});

test("MAC addresses with colons or hyphens get stand-ins, as text or as a field", () => {
  const m = new Masker();
  assert.equal(m.text("ethernet0 00:0C:29:AB:CD:EF nat"), "ethernet0 mac-1 nat");
  assert.equal(m.text("the same one: 00-0c-29-ab-cd-ef"), "the same one: mac-1");
  assert.equal(m.field("mac", "08:00:27:00:00:01"), "mac-2");
  // Not a MAC: mixed separators, a time, an IPv6 address.
  assert.equal(m.text("00:0c-29:ab:cd:ef at 10:30:00 from 2001:db8::1"), "00:0c-29:ab:cd:ef at 10:30:00 from ip-1");
  assert.equal(m.learn("mac", "00:0c:29:00:00:02"), false);
});

test("FQDN-like names are hosts; file names and plain words are not", () => {
  const m = new Masker();
  assert.equal(m.text("Reached web01.example.com."), "Reached host-1.");
  assert.equal(m.text("db01.corp.intern timed out"), "host-2 timed out");
  assert.equal(m.text("dev-host-02.test"), "host-3");
  assert.equal(m.text("tail -f web01.example.com.log"), "tail -f host-1.log");
  assert.equal(m.text("https://web01.example.com/status"), "https://host-1/status");
  for (const plain of ["README.md", "index.html", "nginx.conf", "app.min.js", "v1.2.3", "e.g. this", "server", "a.b"]) {
    assert.equal(m.text(plain), plain);
  }
  assert.equal(hostPart("backup.tar.gz"), null);
  assert.equal(hostPart("www.example.org"), "www.example.org");
  assert.equal(hostPart("mail.example.de"), "mail.example.de");
});

test("user@host masks both parts, with an IP or a bracketed IPv6 address too", () => {
  const m = new Masker();
  assert.equal(m.text("alice@web01:~$ "), "user-1@host-1:~$ ");
  assert.equal(m.text("bob@192.0.2.10's password:"), "user-2@ip-1's password:");
  assert.equal(m.text("alice@[2001:db8::5]"), "user-1@[ip-2]");
  assert.equal(m.text("root@localhost"), "user-3@localhost");
  assert.equal(m.text("ssh-ed25519 AAAA alice@laptop"), "ssh-ed25519 AAAA user-1@host-2");
  // A package version is not a host.
  assert.equal(m.text("react@19.1.0"), "react@19.1.0");
  // Nor is a systemd template unit (MO-14 lists services).
  assert.equal(m.text("postgresql@16-main.service failed"), "postgresql@16-main.service failed");
  assert.equal(m.text("getty@tty1.service user@1000.service"), "getty@tty1.service user@1000.service");
});

test("the Windows user name in local paths is masked, and /home/<name> on hosts", () => {
  const m = new Masker();
  assert.equal(m.text("C:\\Users\\alice\\Downloads\\notes.txt"), "C:\\Users\\user-1\\Downloads\\notes.txt");
  assert.equal(m.text("Saved to C:/Users/Alice B/Documents/out.txt"), "Saved to C:/Users/user-2/Documents/out.txt");
  assert.equal(m.text("\\\\?\\C:\\Users\\bob\\x"), "\\\\?\\C:\\Users\\user-3\\x");
  assert.equal(m.text("in C:\\Users\\alice"), "in C:\\Users\\user-1");
  assert.equal(m.text("C:\\Users\\Public\\Desktop"), "C:\\Users\\Public\\Desktop");
  assert.equal(m.text("/home/carol/.ssh/authorized_keys"), "/home/user-4/.ssh/authorized_keys");
  // A name seen in a path is a known user from then on.
  assert.equal(m.text("Signed in as alice"), "Signed in as user-1");
});

test("values learned by field are masked as whole words in free text", () => {
  const m = new Masker();
  learnFields(m, {
    sessions: [
      { name: "Customer A bastion", host: "db01", username: "carol", lastIp: "192.0.2.20" },
      { name: "edge", host: "gateway", username: "root" },
    ],
    facts: { hostname: "web07", ip: null },
    target: { address: "dave@app02.example.org:2222" },
  });
  assert.equal(m.text("Can't reach db01 (DB01)"), "Can't reach host-1 (host-1)");
  assert.equal(m.text("carol can't write to /etc"), "user-1 can't write to /etc");
  assert.equal(m.text("web07 says hi"), "host-2 says hi");
  assert.equal(m.text("dave"), "user-2");
  // Not part of another name; letter-only values only as written; generic accounts not as bare words.
  assert.equal(m.text("db01-backup and xdb01"), "db01-backup and xdb01");
  assert.equal(m.text("the gateway, Gateway"), "the host-3, Gateway");
  assert.equal(m.text("Carol"), "Carol");
  assert.equal(m.text("run as root"), "run as root");
  // Plain labels stay.
  assert.equal(m.text("Customer A bastion"), "Customer A bastion");
});

test("a field is masked whole, whatever it looks like", () => {
  const m = new Masker();
  assert.equal(m.field("host", "web"), "host-1");
  assert.equal(m.field("user", "root"), "user-1");
  assert.equal(m.field("address", "alice@web01:2222"), "user-2@host-2:2222");
  assert.equal(m.field("host", "[2001:db8::1]:22"), "[ip-1]:22");
  assert.equal(m.field("host", "2001:db8::1"), "ip-1");
  assert.equal(m.field("ip", " 192.0.2.9 "), " ip-2 ");
  assert.equal(m.field("host", "127.0.0.1"), "127.0.0.1");
  assert.equal(m.field("host", ""), "");
  assert.equal(m.field("host", "web01 and web02.example.com"), "web01 and host-3");
});

test("masking is idempotent: stand-ins are never masked again", () => {
  const m = new Masker();
  const once = m.text("alice@web01.example.com via 192.0.2.10 from C:\\Users\\bob\\x");
  assert.equal(once, "user-1@host-1 via ip-1 from C:\\Users\\user-2\\x");
  assert.equal(m.text(once), once);
  assert.ok(m.isStandIn("host-1"));
  assert.ok(!m.isStandIn("host-9"));
  // The mapping can't be read back from a stand-in: a counter, not a hash.
  assert.equal(new Masker().text("web99.example.com"), "host-1");
});

test("learning a new value tells the listeners", () => {
  const m = new Masker();
  let calls = 0;
  m.onChange(() => (calls += 1));
  assert.ok(m.learn("host", "db02"));
  assert.ok(!m.learn("host", "DB02"));
  assert.ok(!m.learn("host", "192.0.2.1"));
  assert.ok(!m.learn("user", "ab"));
  assert.equal(calls, 1);
});

test("terminal stand-ins keep the width of what they replace", () => {
  assert.equal(fitWidth("ip-1", "ip", 10), `ip-1${PAD.repeat(6)}`);
  assert.equal(fitWidth("user-12", "user", 5), "u-12" + PAD);
  assert.equal(fitWidth("host-123", "host", 4), "h123");
  assert.equal(fitWidth("host-1234", "host", 3), PAD.repeat(3));
  const t = new TerminalMasker(new Masker());
  const line = "inet 192.0.2.10/24 brd 192.0.2.255\r\n";
  const shown = t.push(line);
  assert.equal(shown.length, line.length);
  assert.equal(shown, `inet ip-1${PAD.repeat(6)}/24 brd ip-2${PAD.repeat(7)}\r\n`);
});

test("terminal: escape sequences around and inside a value stay where they were", () => {
  const t = new TerminalMasker(new Masker());
  const prompt = `${ESC}[01;32malice@web01${ESC}[00m:${ESC}[01;34m~${ESC}[00m$ `;
  // alice@web01 is 11 cells, so each part gets a stand-in of its own width.
  assert.equal(t.push(prompt), `${ESC}[01;32mu-1${PAD}${PAD}@h-1${PAD}${PAD}${ESC}[00m:${ESC}[01;34m~${ESC}[00m$ `);
  // A style change in the middle of a name: the name is still found, the style kept.
  const split = `web${ESC}[1m02.example.com\r\n`;
  assert.equal(t.push(split), `hos${ESC}[1mt-2${PAD.repeat(11)}\r\n`);
  // A window title (OSC) is not shown, so it passes as it is; it also ends a value.
  assert.equal(t.push(`${ESC}]0;alice@web01: ~\x07ok\r\n`), `${ESC}]0;alice@web01: ~\x07ok\r\n`);
});

test("terminal: values and escape sequences split across reads", () => {
  const t = new TerminalMasker(new Masker());
  const a = t.push("Connecting to 192.0.");
  assert.equal(a, "Connecting to ");
  assert.ok(t.holding);
  const b = t.push("2.10 ...\r\n");
  assert.equal(a + b, `Connecting to ip-1${PAD.repeat(6)} ...\r\n`);
  assert.ok(!t.holding);
  // An escape sequence cut in two is held whole, with the word before it.
  const c = t.push(`ok web03.exam${ESC}[3`);
  const d = t.push(`2mple.com${ESC}[0m\r\n`);
  // web03.exam (10 cells) before the style change, ple.com (7) after it.
  assert.equal(c + d, `ok host-1${PAD.repeat(4)}${ESC}[32m${PAD.repeat(7)}${ESC}[0m\r\n`);
  // A value is never joined across a line break.
  const e = t.push("192.0.2.\r\n10\r\n");
  assert.equal(e, "192.0.2.\r\n10\r\n");
});

test("terminal: what is held back comes out on flush, masked", () => {
  const t = new TerminalMasker(new Masker());
  assert.equal(t.push("$ ping 198.51.100.7"), "$ ping ");
  assert.equal(t.flush(), `ip-1${PAD.repeat(8)}`);
  assert.equal(t.flush(), "");
  // Typed characters echo after the flush; a prompt ending in a space holds nothing.
  assert.equal(t.push("l"), "");
  assert.equal(t.flush(), "l");
  assert.equal(t.push("alice@web01:~$ "), `u-1${PAD}${PAD}@h-1${PAD}${PAD}:~$ `);
  assert.ok(!t.holding);
});

test("terminal: the session's own values are masked as bare words, the same width", () => {
  const m = new Masker();
  learnFields(m, { host: "db01", username: "carol", hostname: "dbserver01" });
  const t = new TerminalMasker(m);
  const out = t.push("drwxr-x--- 2 carol carol 4096 dbserver01\r\n");
  assert.equal(out, `drwxr-x--- 2 u-1${PAD}${PAD} u-1${PAD}${PAD} 4096 host-1${PAD.repeat(4)}\r\n`);
  assert.equal(out.length, "drwxr-x--- 2 carol carol 4096 dbserver01\r\n".length);
});

test("command variables named like a host or user hold one", () => {
  for (const name of ["host", "target_ip", "dbServer", "user", "jump-host", "IP", "node2"]) {
    assert.ok(namesAHost(name), name);
  }
  for (const name of ["zip", "service", "script", "count", "pipeline", "path"]) assert.ok(!namesAHost(name), name);
});
