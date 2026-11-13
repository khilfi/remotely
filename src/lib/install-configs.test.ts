/// <reference types="node" />
// VM-28: the install configs' pure helpers. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  blankConfig,
  configReason,
  copyName,
  copyOf,
  diskText,
  fitsImage,
  KIND_LABEL,
  KIND_ORDER,
  lineRange,
  missingVariables,
  parseLines,
  parseWords,
  placeholder,
  problemSummary,
  refOf,
  refSlug,
  syncSecrets,
} from "./install-configs.ts";
import type { InstallConfig } from "./install-configs-api.ts";

const starter: InstallConfig = {
  id: "starter.ubuntu-24.04-minimal",
  builtIn: true,
  name: "Ubuntu 24.04 server, minimal",
  kind: "autoinstall",
  body: "#cloud-config\n",
  variables: [{ name: "domain", default: "example.com" }],
  secrets: [{ name: "admin", kind: "password", secretId: "x" }],
  notes: null,
  createdAt: null,
  updatedAt: null,
  problems: [],
  diskNeedMb: null,
};

test("every kind has a label and a blank file that uses {{hostname}}", () => {
  assert.equal(KIND_ORDER.length, 5);
  for (const kind of KIND_ORDER) {
    assert.ok(KIND_LABEL[kind]);
    const blank = blankConfig(kind);
    assert.ok(blank.body.includes("{{hostname}}"), kind);
    assert.equal(blank.name, "");
  }
});

test("a copy gets a free name and a starter's picks are made again", () => {
  assert.equal(copyName("web", []), "web (copy)");
  assert.equal(copyName("web", ["WEB (copy)"]), "web (copy 2)");
  assert.equal(copyName("x".repeat(60), []).length, 60);
  const copy = copyOf(starter, [starter.name]);
  assert.equal(copy.name, "Ubuntu 24.04 server, minimal (copy)");
  assert.equal(copy.secrets[0].secretId, null);
  assert.deepEqual(copy.variables, starter.variables);
  const own = copyOf({ ...starter, builtIn: false }, []);
  assert.equal(own.secrets[0].secretId, "x", "an own config's copy keeps its picks");
});

test("references are named from text and read back", () => {
  assert.equal(refSlug("Alice"), "alice");
  assert.equal(refSlug("Bob Smith"), "bob_smith");
  assert.equal(refSlug("9lives"), "lives");
  assert.equal(refSlug("!!"), "admin");
  assert.equal(placeholder("password", "alice"), "{{password.alice}}");
  assert.equal(placeholder("sshKey", "alice"), "{{ssh_key.alice}}");
  assert.equal(refOf("{{password.alice}}", "password"), "alice");
  assert.equal(refOf(" {{ ssh_key.bob }} ", "sshKey"), "bob");
  assert.equal(refOf("{{password.alice}}", "sshKey"), null);
  assert.equal(refOf("ssh-ed25519 AAAA", "sshKey"), null);
});

test("vault picks follow the file's placeholders and keep picks it no longer uses", () => {
  const rows = syncSecrets({ builtIns: [], variables: [], passwords: ["admin"], sshKeys: ["admin"] }, [
    { name: "admin", kind: "password", secretId: "p1" },
    { name: "old", kind: "password", secretId: "p2" },
  ]);
  assert.deepEqual(
    rows.map((r) => [r.kind, r.name, r.secretId, r.used]),
    [
      ["password", "admin", "p1", true],
      ["sshKey", "admin", null, true],
      ["password", "old", "p2", false],
    ],
  );
  assert.deepEqual(
    missingVariables({ builtIns: [], variables: ["domain", "zone"], passwords: [], sshKeys: [] }, starter.variables),
    ["zone"],
  );
});

test("problems are summed up, and the first error says why it can't deploy", () => {
  assert.equal(problemSummary([]), "No problems");
  const problems = [
    { severity: "warning" as const, line: null, message: "w" },
    { severity: "error" as const, line: 4, message: "bad" },
    { severity: "error" as const, line: null, message: "worse" },
  ];
  assert.equal(problemSummary(problems), "2 errors · 1 warning");
  assert.equal(configReason({ problems }), "Line 4: bad");
  assert.equal(configReason({ problems: [problems[0]] }), null);
  assert.equal(diskText(41_024), "41 GB");
  assert.equal(diskText(null), null);
});

test("lists and lines parse as the form writes them", () => {
  assert.deepEqual(parseWords("curl, git\nnginx  "), ["curl", "git", "nginx"]);
  assert.deepEqual(parseLines("echo a\n\necho b\n\n"), ["echo a", "", "echo b"]);
  assert.deepEqual(lineRange("a\nbc\nd", 2), [2, 4]);
  assert.deepEqual(lineRange("a", 5), [1, 1]);
});

test("a config fits an image when it installs from that kind, for that OS", () => {
  const own = (kind: InstallConfig["kind"]) => ({ kind, builtIn: false });
  assert.ok(fitsImage(own("kickstart"), { kind: "iso", family: "linux" }));
  assert.ok(!fitsImage(own("kickstart"), { kind: "cloudImage", family: "linux" }));
  assert.ok(fitsImage(own("cloudInit"), { kind: "goldenVm", family: "linux" }));
  assert.ok(!fitsImage(own("cloudInit"), { kind: "iso", family: "linux" }));
  assert.ok(fitsImage(own("unattend"), { kind: "iso", family: "windows" }));
  assert.ok(!fitsImage(own("unattend"), { kind: "iso", family: "linux" }));
  assert.ok(!fitsImage({ kind: "kickstart", builtIn: true }, { kind: "iso", family: "linux" }), "starters copy first");
});
