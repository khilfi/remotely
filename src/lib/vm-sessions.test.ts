/// <reference types="node" />
// QL-29: SSH sessions made from VMs, the parts the window works out. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { SessionDraft, VmSessionDraft, VmSessionMade } from "./api.ts";
import {
  draftMissing,
  linkedSshSessions,
  loginText,
  saveReason,
  savedOneText,
  savedSummary,
  sentence,
  sessionTargets,
  splitDrafts,
  vmsWithoutSsh,
} from "./vm-sessions.ts";

const sessions = [
  { name: "web", vmId: "vm-web", protocol: "ssh" },
  { name: "web desktop", vmId: "vm-desk", protocol: "rdp" },
  { name: "db", vmId: null, protocol: "ssh" },
];

test("QL-29: only an SSH session linked to the VM counts as its session", () => {
  assert.deepEqual(
    linkedSshSessions("vm-web", sessions).map((s) => s.name),
    ["web"],
  );
  assert.deepEqual(linkedSshSessions("vm-desk", sessions), [], "an RDP session isn't an SSH session");
  const vms = [{ id: "vm-web" }, { id: "vm-desk" }, { id: "vm-db" }];
  assert.deepEqual(
    vmsWithoutSsh(vms, sessions).map((v) => v.id),
    ["vm-desk", "vm-db"],
  );
});

const draft = (over: Partial<SessionDraft> = {}): SessionDraft => ({
  name: "web-1",
  host: "192.0.2.21",
  port: 22,
  username: "alice",
  auth: { method: "key", keyId: "k-1", passphraseId: null },
  environment: "lab",
  tags: ["web"],
  vmId: "vm-1",
  deploy: "launch template 'web'",
  ...over,
});

test("QL-29: the selection's Create SSH sessions goes to its running VMs without an SSH session", () => {
  const vms = [
    { id: "vm-web", powerState: "running" as const },
    { id: "vm-desk", powerState: "running" as const },
    { id: "vm-db", powerState: "not_running" as const },
    { id: "vm-cache", powerState: "suspended" as const },
    { id: "vm-app", powerState: "running" as const },
  ];
  assert.deepEqual(
    sessionTargets(vms, sessions).map((v) => v.id),
    ["vm-desk", "vm-app"],
    "web has its SSH session; an RDP session doesn't count; db and cache report no address",
  );
  assert.deepEqual(sessionTargets([], sessions), []);
});

test("QL-29: the editor's toast says linked only while the session still is", () => {
  const asked = { vmId: "vm-1", vmName: "web-1" };
  assert.equal(savedOneText({ name: "web-1", vmId: "vm-1" }, asked), "Created 'web-1', linked to web-1");
  assert.equal(savedOneText({ name: "web-1", vmId: "vm-2" }, asked), "Created 'web-1'", "another VM picked");
  assert.equal(savedOneText({ name: "web-1", vmId: null }, asked), "Created 'web-1'", "an RDP session, unlinked");
});

test("QL-29: a draft says how it logs in and what it leaves to fill in", () => {
  const labels = (id: string) => (id === "k-1" ? "deploy key" : undefined);
  assert.equal(loginText(draft().auth, labels), "Key 'deploy key'");
  assert.equal(loginText({ method: "key", keyId: "gone", passphraseId: null }, labels), "A key");
  assert.equal(loginText({ method: "password", passwordId: null }, labels), "Password, asked when connecting");
  assert.deepEqual(draftMissing(draft()), []);
  assert.deepEqual(draftMissing(draft({ username: null, auth: { method: "password", passwordId: null } })), [
    "user",
    "key or password",
  ]);
});

test("QL-29: the preview saves the VMs that get a draft and says why the others don't", () => {
  const drafts: VmSessionDraft[] = [
    { vmId: "vm-1", vmName: "web-1", session: draft(), refused: null, notes: [] },
    { vmId: "vm-2", vmName: "web-2", session: null, refused: "it isn't running", notes: [] },
  ];
  const { saving, refused } = splitDrafts(drafts);
  assert.deepEqual(
    saving.map((d) => d.vmName),
    ["web-1"],
  );
  assert.deepEqual(
    refused.map((d) => d.vmName),
    ["web-2"],
  );
  assert.equal(sentence("it isn't running"), "It isn't running.");

  // Save says why it is off: the lock, still reading, a failed read, or nothing to save.
  assert.equal(saveReason({ readOnly: null, drafts, failed: false }), null);
  assert.equal(saveReason({ readOnly: "Presenting", drafts, failed: false }), "Presenting");
  assert.equal(saveReason({ readOnly: null, drafts: null, failed: false }), "The sessions are still being worked out.");
  assert.match(saveReason({ readOnly: null, drafts: null, failed: true }) ?? "", /couldn't be worked out/);
  assert.match(saveReason({ readOnly: null, drafts: refused, failed: false }) ?? "", /None of these VMs/);
  assert.equal(sentence("Already a sentence."), "Already a sentence.");
});

test("QL-29: the toast after saving counts what was saved and what wasn't", () => {
  const made = (vmName: string, ok: boolean): VmSessionMade => ({
    vmId: vmName,
    vmName,
    sessionId: ok ? `s-${vmName}` : null,
    sessionName: ok ? vmName : null,
    error: ok ? null : "it isn't running",
  });
  assert.equal(savedSummary([made("a", true), made("b", true)]).title, "Saved 2 SSH sessions");
  assert.equal(savedSummary([made("a", true)]).title, "Saved 1 SSH session");
  const mixed = savedSummary([made("a", true), made("b", false)]);
  assert.equal(mixed.title, "Saved 1 SSH session; 1 VM got none");
  assert.deepEqual(
    mixed.failed.map((m) => m.vmName),
    ["b"],
  );
  assert.equal(savedSummary([made("b", false)]).title, "No SSH session was saved");
});
