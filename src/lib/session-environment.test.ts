/// <reference types="node" />
// UX-12: the environment that applies to a session and where it comes from. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  appliedEnvironment,
  environmentText,
  sourceText,
  vmsById,
  type EnvironmentOfSession,
} from "./session-environment.ts";

const vms = vmsById([
  { id: "vm-db", displayName: "db-01", environment: "prod" as const },
  { id: "vm-lab", displayName: "lab-01", environment: "lab" as const },
]);

function session(over: Partial<EnvironmentOfSession> = {}): EnvironmentOfSession {
  return { environment: "lab", inherited: { environment: null }, vmId: null, ...over };
}

test("a session's own environment says nothing more", () => {
  const applied = appliedEnvironment(session(), vms);
  assert.deepEqual(applied, { environment: "lab", from: null });
  assert.equal(environmentText(applied), "Lab");
  assert.equal(environmentText(appliedEnvironment(session({ environment: "none" }), vms)), "None");
});

test("a Prod VM the session reaches makes it Prod, and says so", () => {
  const applied = appliedEnvironment(session({ vmId: "vm-db" }), vms);
  assert.deepEqual(applied, { environment: "prod", from: { kind: "vm", name: "db-01" } });
  assert.equal(environmentText(applied), "Prod · from VM db-01");
  // A session that is Prod itself stays its own.
  assert.equal(environmentText(appliedEnvironment(session({ environment: "prod", vmId: "vm-db" }), vms)), "Prod");
});

test("a VM that isn't Prod changes nothing, nor does one that isn't listed", () => {
  assert.equal(environmentText(appliedEnvironment(session({ vmId: "vm-lab" }), vms)), "Lab");
  assert.equal(environmentText(appliedEnvironment(session({ vmId: "gone" }), vms)), "Lab");
});

test("an environment from a folder names the folder", () => {
  const fromFolder = session({ environment: "prod", inherited: { environment: { name: "Production" } } });
  assert.equal(environmentText(appliedEnvironment(fromFolder, vms)), "Prod · from folder Production");
  // A Prod VM raises a Lab folder's session to Prod, and the VM is named.
  const labFolder = session({ inherited: { environment: { name: "Dev" } }, vmId: "vm-db" });
  assert.equal(environmentText(appliedEnvironment(labFolder, vms)), "Prod · from VM db-01");
});

test("the source alone, for a second line", () => {
  assert.equal(sourceText(null), "");
  assert.equal(sourceText({ kind: "folder", name: "Staging" }), "from folder Staging");
  assert.equal(sourceText({ kind: "vm", name: "web-01" }), "from VM web-01");
});
