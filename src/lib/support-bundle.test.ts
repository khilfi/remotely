import assert from "node:assert/strict";
import test from "node:test";

import type { BundlePreset } from "./api.ts";
import { READ_ONLY_REASON } from "./disabled-reasons.ts";
import {
  collectReason,
  itemCount,
  limitsText,
  lines,
  pathProblem,
  shownPresets,
  sizeText,
  stepsText,
  windowsPathProblem,
} from "./support-bundle.ts";

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

test("Windows hosts give the Windows presets and their own files and commands", () => {
  const windows: BundlePreset = {
    id: "windowsNetwork",
    hostKind: "windows",
    label: "Windows network",
    description: "",
    items: [{ kind: "command", command: "ipconfig /all" }],
  };
  const all = [...PRESETS, windows];
  assert.equal(itemCount(all, ["system", "windowsNetwork"], [], []), 2, "Linux hosts don't get the Windows preset");
  assert.equal(itemCount(all, ["system", "windowsNetwork"], ["hostname"], [], "windows"), 2);
  assert.equal(windowsPathProblem(["C:\\Windows\\Logs\\CBS\\CBS.log", "d:/app/app.log"]), null);
  assert.match(windowsPathProblem(["\\\\server\\share\\x.log"]) ?? "", /full path on the Windows host/);
  assert.match(windowsPathProblem(["C:\\Logs\\"]) ?? "", /folder/);
  assert.match(windowsPathProblem(["C:\\Logs\\*.log"]) ?? "", /characters/);
  const ok = {
    readOnly: false,
    hosts: [{ protected: false }, { protected: false, scriptKind: "powerShell" as const }],
    items: 3,
    windowsItems: 2,
    maxItems: 100,
    pathProblem: null,
    timeoutOk: true,
    stopAfterOk: true,
    submitting: false,
  };
  assert.equal(collectReason(ok), null);
  assert.match(collectReason({ ...ok, windowsItems: 0 }) ?? "", /Windows preset/);
  assert.match(collectReason({ ...ok, items: 0 }) ?? "", /Linux preset/);
  assert.equal(collectReason({ ...ok, hosts: [ok.hosts[1]], items: 0 }), null, "no Linux host: no Linux items needed");
  assert.deepEqual(
    shownPresets(all, 0, 0).map((p) => p.id),
    ["system", "containers"],
  );
  assert.deepEqual(
    shownPresets(all, 0, 1).map((p) => p.id),
    ["windowsNetwork"],
  );
  assert.equal(shownPresets(all, 1, 1).length, 3);
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
