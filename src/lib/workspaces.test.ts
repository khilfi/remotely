/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  claimReason,
  colorClass,
  MAX_WORKSPACE_NAME,
  nameProblem,
  releaseReason,
  switchable,
  switchCloses,
  switchRefusal,
  WORKSPACE_COLORS,
} from "./workspaces.ts";

const ws = (id: string, name: string, archived = false, current = false) => ({ id, name, archived, current });

test("FD-02: a workspace name is one trimmed line, unique among the user's (letter case aside)", () => {
  const others = [ws("1", "Acme"), ws("2", "Old client", true)];
  assert.equal(nameProblem("  ", others), "Give the workspace a name.");
  assert.equal(nameProblem("x".repeat(MAX_WORKSPACE_NAME), others), null);
  assert.match(nameProblem("x".repeat(MAX_WORKSPACE_NAME + 1), others) ?? "", /At most 60/);
  assert.match(nameProblem("acme", others) ?? "", /Another workspace/);
  assert.match(nameProblem("OLD CLIENT", others) ?? "", /archived ones count/);
  assert.equal(nameProblem("Acme", others, "1"), null, "renaming to its own name");
  assert.equal(nameProblem("Acme‮Corp", others), "One line of plain text.");
  assert.equal(nameProblem("Globex", others), null);
});

test("FD-02: the switcher lists the shown workspace first, then active ones by name, never archived ones", () => {
  const list = switchable([ws("1", "Zeta"), ws("2", "Alpha"), ws("3", "Beta", false, true), ws("4", "Aardvark", true)]);
  assert.deepEqual(
    list.map((w) => w.name),
    ["Beta", "Alpha", "Zeta"],
  );
});

test("FD-02: a switch is refused while jobs started here run, and says what it closes", () => {
  const nothing = { openJobs: 0, terminals: 0, multiexec: false, approvals: 0 };
  assert.equal(switchRefusal(nothing), null);
  assert.deepEqual(switchCloses(nothing), []);
  assert.match(switchRefusal({ ...nothing, openJobs: 1 }) ?? "", /^A job started here is still running/);
  assert.match(switchRefusal({ ...nothing, openJobs: 3 }) ?? "", /^3 jobs .* cancel them in Activity/);
  assert.deepEqual(switchCloses({ openJobs: 0, terminals: 2, multiexec: true, approvals: 1 }), [
    "2 terminals close, with their tunnels, logs and transfers.",
    "MultiExec stops.",
    "1 approval waiting for an answer: cancelled.",
  ]);
});

test("FD-02: only unprotected, non-Prod VMs leave a workspace, and only when another workspace exists", () => {
  const vm = (displayName: string, protectedVm = false, environment: "none" | "prod" = "none") => ({
    displayName,
    protected: protectedVm,
    environment,
  });
  assert.equal(releaseReason([vm("web")], 2), null);
  assert.match(releaseReason([vm("web")], 1) ?? "", /one workspace/);
  assert.match(releaseReason([vm("web"), vm("db", true)], 2) ?? "", /'db' is protected/);
  assert.match(releaseReason([vm("db", false, "prod")], 3) ?? "", /labelled Prod/);
  assert.match(releaseReason([], 2) ?? "", /Select/);
  assert.equal(claimReason(2, null), null);
  assert.equal(claimReason(2, "Presenting: read-only"), "Presenting: read-only");
});

test("FD-02: every colour the core knows has a class; an unknown one falls back", () => {
  for (const c of WORKSPACE_COLORS) assert.match(colorClass(c), /^bg-/);
  assert.equal(colorClass("ultraviolet"), colorClass("slate"));
});
