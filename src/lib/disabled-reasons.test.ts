/// <reference types="node" />
// QL-08: the reasons disabled buttons give. Run with `npm test` (Node's own test runner, which reads TypeScript).

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  approveReason,
  compareRunReason,
  connectedReason,
  diffReason,
  multiExecIdleReason,
  multiExecReason,
  splitReason,
} from "./disabled-reasons.ts";

const ready = {
  savedSessions: 3,
  picked: 2,
  hosts: [{ protected: false }, { protected: true }],
  unsavedTabs: 0,
  script: "uptime",
  timeoutOk: true,
  submitting: false,
};

test("Compare runs only once there is something to run on and something to run", () => {
  assert.equal(compareRunReason(ready), null);
  assert.equal(
    compareRunReason({ ...ready, savedSessions: 0, picked: 0, hosts: [] }),
    "No saved sessions on this computer: add or import sessions first",
  );
  assert.equal(compareRunReason({ ...ready, picked: 0, hosts: [] }), "Pick tabs, or sessions in the tree, to run on");
  assert.equal(
    compareRunReason({ ...ready, hosts: [], unsavedTabs: 2 }),
    "The picked tabs are quick connections: save them as sessions first",
  );
  assert.equal(
    compareRunReason({ ...ready, hosts: [{ protected: true }, { protected: true }] }),
    "All selected targets are protected",
  );
  assert.equal(compareRunReason({ ...ready, script: "   " }), "Type a command first");
  assert.match(compareRunReason({ ...ready, timeoutOk: false }) ?? "", /^The time limit must be/);
  assert.equal(compareRunReason({ ...ready, submitting: true }), "Starting the run…");
});

test("MultiExec needs an open terminal, and says when no picked one gets the keys", () => {
  assert.equal(multiExecReason({ tabs: 0, on: false }), "Open a terminal first: MultiExec types into open tabs");
  assert.equal(multiExecReason({ tabs: 1, on: false }), null);
  assert.equal(multiExecReason({ tabs: 0, on: true }), null, "it can always be turned off");
  assert.equal(multiExecIdleReason([]), "No tab is picked: Ctrl+click tabs, or pick them by folder or label");
  assert.equal(
    multiExecIdleReason([
      { receives: false, reason: "protected: MultiExec leaves it out (AP-04)" },
      { receives: false, reason: "protected: MultiExec leaves it out (AP-04)" },
    ]),
    "All selected targets are protected",
  );
  assert.equal(
    multiExecIdleReason([
      { receives: false, reason: "not connected" },
      { receives: false, reason: "at a password prompt" },
    ]),
    "No picked tab receives keys now: not connected; at a password prompt",
  );
  assert.equal(
    multiExecIdleReason([
      { receives: true, reason: null },
      { receives: false, reason: "x" },
    ]),
    null,
  );
});

test("splitting says why it can't", () => {
  assert.equal(splitReason({ panes: 2, maxPanes: 6, connectedOnce: true }), null);
  assert.equal(
    splitReason({ panes: 6, maxPanes: 6, connectedOnce: true }),
    "A tab holds at most 6 panes: open the session in another tab",
  );
  assert.equal(
    splitReason({ panes: 1, maxPanes: 6, connectedOnce: false }),
    "This terminal never connected, so there is nothing to split",
  );
});

test("Approve names the first answer still missing", () => {
  const steps = [
    { step: "impactPreview" as const },
    { step: "typeTargetCount" as const, expected: 3 },
    { step: "reason" as const },
    { step: "vaultReauth" as const },
  ];
  const answers = { steps, typedCount: "3", reason: "CHG-1", password: "x", busy: false };
  assert.equal(approveReason(answers), null);
  assert.equal(approveReason({ ...answers, typedCount: "2" }), "Type the number of targets (3) first");
  assert.equal(approveReason({ ...answers, reason: " " }), "Give a reason or ticket number first");
  assert.equal(approveReason({ ...answers, password: "" }), "Type the vault password first");
  assert.equal(approveReason({ ...answers, busy: true }), "Checking the answers…");
  assert.equal(
    approveReason({ steps: [{ step: "confirm" }], typedCount: "", reason: "", password: "", busy: false }),
    null,
  );
});

test("comparing groups and connection actions say why they wait", () => {
  assert.equal(diffReason(1), "Only one group so far: every host that finished gave the same answer");
  assert.equal(diffReason(2), null);
  assert.equal(connectedReason({ open: false, connected: false }), "No terminal is open");
  assert.equal(connectedReason({ open: true, connected: false }), "This terminal has not connected yet");
  assert.equal(connectedReason({ open: true, connected: true }), null);
});
