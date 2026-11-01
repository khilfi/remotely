/// <reference types="node" />
// QL-08: the reasons disabled buttons give. Run with `npm test` (Node's own test runner, which reads TypeScript).

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  compareRunReason,
  connectedReason,
  diffReason,
  downloadReason,
  multiExecIdleReason,
  multiExecReason,
  READ_ONLY_REASON,
  splitReason,
  uploadReason,
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
    "Every picked tab is Protected",
  );
  assert.equal(compareRunReason({ ...ready, script: "   " }), "Type a command first");
  assert.match(compareRunReason({ ...ready, timeoutOk: false }) ?? "", /^The time limit must be/);
  assert.match(compareRunReason({ ...ready, stopAfterOk: false }) ?? "", /^Stop after must be/);
  assert.equal(compareRunReason({ ...ready, stopAfterOk: true }), null);
  assert.equal(compareRunReason({ ...ready, submitting: true }), "Starting the run…");
});

test("MultiExec needs an open terminal, and says when no picked one gets the keys", () => {
  assert.equal(multiExecReason({ tabs: 0, on: false }), "Open a terminal first: Type in all tabs needs open tabs");
  assert.equal(multiExecReason({ tabs: 1, on: false }), null);
  // SS-12: Telnet, serial and tunnel tabs never join.
  assert.match(multiExecReason({ tabs: 2, on: false, sshTabs: 0 }) ?? "", /Only SSH tabs join/);
  assert.equal(multiExecReason({ tabs: 2, on: false, sshTabs: 1 }), null);
  assert.equal(multiExecReason({ tabs: 0, on: true }), null, "it can always be turned off");
  assert.equal(multiExecIdleReason([]), "No tab is picked: Ctrl+click tabs, or pick them by folder or environment");
  assert.equal(
    multiExecIdleReason([
      { receives: false, reason: "protected: Type in all tabs leaves it out" },
      { receives: false, reason: "protected: Type in all tabs leaves it out" },
    ]),
    "Every picked tab is Protected",
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

test("comparing groups and connection actions say why they wait", () => {
  assert.equal(diffReason(1), "Only one group so far: every host that finished gave the same answer");
  assert.equal(diffReason(2), null);
  assert.equal(connectedReason({ open: false, connected: false }), "No terminal is open");
  assert.equal(connectedReason({ open: true, connected: false }), "This terminal has not connected yet");
  assert.equal(connectedReason({ open: true, connected: true }), null);
});

test("SS-08: uploads need a connected terminal", () => {
  assert.match(uploadReason({ open: false, connected: false }) ?? "", /Open a terminal/);
  assert.match(uploadReason({ open: true, connected: false }) ?? "", /not connected/);
  assert.equal(uploadReason({ open: true, connected: true }), null);
});

test("SS-08: downloads take files, not folders", () => {
  const file = { kind: "file" as const };
  assert.match(downloadReason({ connected: false, picked: [file] }) ?? "", /not connected/);
  assert.match(downloadReason({ connected: true, picked: [] }) ?? "", /Tick the files/);
  assert.match(downloadReason({ connected: true, picked: [file, { kind: "folder" }] }) ?? "", /Folders aren't/);
  assert.match(downloadReason({ connected: true, picked: [{ kind: "other" }] }) ?? "", /regular files/);
  assert.equal(downloadReason({ connected: true, picked: [file, file] }), null);
});

test("FD-03: with the read-only lock on, changing actions say so first", () => {
  assert.equal(compareRunReason({ ...ready, readOnly: true }), READ_ONLY_REASON);
  assert.equal(compareRunReason({ ...ready, readOnly: false }), null);
  assert.equal(multiExecReason({ tabs: 2, on: false, readOnly: true }), READ_ONLY_REASON);
  // Already on: the switch turns it off, which the lock never blocks.
  assert.equal(multiExecReason({ tabs: 2, on: true, readOnly: true }), null);
  assert.equal(uploadReason({ open: true, connected: true, readOnly: true }), READ_ONLY_REASON);
  assert.equal(uploadReason({ open: true, connected: true }), null);
  assert.match(READ_ONLY_REASON, /read-only lock/);
});
