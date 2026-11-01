import assert from "node:assert/strict";
import test from "node:test";

import type { BundlePreset } from "./api.ts";
import { READ_ONLY_REASON } from "./disabled-reasons.ts";
import { collectReason, itemCount, limitsText, lines, pathProblem, sizeText, stepsText } from "./support-bundle.ts";

const PRESETS: BundlePreset[] = [
  {
    id: "system",
    hostKind: "linux",
    label: "System",
    description: "",
    items: [
      { kind: "file", path: "/etc/os-release" },
      { kind: "command", command: "uname -a" },
    ],
  },
  {
    id: "containers",
    hostKind: "linux",
    label: "Containers",
    description: "",
    items: [{ kind: "command", command: "docker ps -a" }],
  },
];

test("typed commands and files are their non-blank lines, each once", () => {
  assert.deepEqual(lines("  uptime \n\r\n\nuptime\r\ndf -h\n"), ["uptime", "df -h"]);
  assert.deepEqual(lines(""), []);
});

test("a file path is a full path to a file", () => {
  assert.equal(pathProblem(["/etc/hosts", "/var/log/syslog"]), null);
  assert.match(pathProblem(["etc/hosts"]) ?? "", /full path/);
  assert.match(pathProblem(["/var/log/"]) ?? "", /folder/);
});

test("items are counted once across presets and typed lines", () => {
  assert.equal(itemCount(PRESETS, [], [], []), 0);
  assert.equal(itemCount(PRESETS, ["system"], [], []), 2);
  assert.equal(itemCount(PRESETS, ["system", "containers"], ["uname -a", "uptime"], ["/etc/os-release"]), 4);
});

test("Collect says why it is off", () => {
  const ok = {
    readOnly: false,
    hosts: [{ protected: false }],
    items: 3,
    maxItems: 100,
    pathProblem: null,
    timeoutOk: true,
    stopAfterOk: true,
    submitting: false,
  };
  assert.equal(collectReason(ok), null);
  assert.equal(collectReason({ ...ok, readOnly: true }), READ_ONLY_REASON);
  assert.match(collectReason({ ...ok, hosts: [] }) ?? "", /Pick the hosts/);
  assert.match(collectReason({ ...ok, hosts: [{ protected: true }] }) ?? "", /Protected/);
  assert.match(collectReason({ ...ok, items: 0 }) ?? "", /Choose a preset/);
  assert.match(collectReason({ ...ok, items: 101 }) ?? "", /at most 100/);
  assert.equal(collectReason({ ...ok, pathProblem: "bad path" }), "bad path");
  assert.match(collectReason({ ...ok, timeoutOk: false }) ?? "", /time limit/);
  assert.match(collectReason({ ...ok, stopAfterOk: false }) ?? "", /Stop after/);
});

test("the caps and the steps read naturally", () => {
  assert.equal(sizeText(10 * 1024 * 1024), "10 MB");
  assert.equal(sizeText(1024 ** 3), "1 GB");
  assert.equal(sizeText(1536), "1.5 KB");
  assert.equal(
    limitsText({ fileBytes: 10 * 1024 ** 2, hostBytes: 100 * 1024 ** 2, bundleBytes: 1024 ** 3, maxItems: 100 }),
    "Each file keeps up to 10 MB, each host 100 MB and the bundle 1 GB.",
  );
  assert.equal(stepsText([]), "Runs at once; logged.");
  assert.equal(stepsText([{ step: "confirm" }]), "Needs one confirm.");
});
