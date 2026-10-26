/// <reference types="node" />
// VM-08, VM-26: the Stacks tab's and the capacity planner's texts, reasons and grouping. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  betweenText,
  cpuLine,
  deployStackReason,
  driveLine,
  groupByInstance,
  handAdded,
  instancePowerReason,
  instanceStateText,
  moveStep,
  newStep,
  ramLine,
  readinessText,
  secondsText,
  stackInputReason,
  stepLine,
  stepsText,
  suspendTargets,
  teardownReason,
} from "./stacks.ts";
import type { DeployCapacity, InstanceVm, Stack, StackInstance } from "./stacks-api.ts";

test("readiness and waits read in words", () => {
  assert.equal(readinessText({ kind: "none" }), "nothing");
  assert.equal(readinessText({ kind: "tools" }), "the guest tools running");
  assert.equal(readinessText({ kind: "sshPort", port: 22 }), "SSH (port 22) open");
  assert.equal(readinessText({ kind: "sshPort", port: 5432 }), "port 5432 open");
  assert.equal(secondsText(30), "30 s");
  assert.equal(secondsText(600), "10 min");
  assert.equal(secondsText(3600), "1 h");
  assert.equal(
    betweenText({ readiness: { kind: "tools" }, readyTimeoutSecs: 300, delaySecs: 30 }),
    "waits up to 5 min for the guest tools running, then waits 30 s",
  );
  assert.equal(betweenText({ readiness: { kind: "none" }, readyTimeoutSecs: 300, delaySecs: 0 }), "");
  assert.equal(
    stepsText([
      { templateName: "db", count: 1 },
      { templateName: null, count: 2 },
    ]),
    "db ×1 → (deleted) ×2",
  );
});

test("steps move up and down, and the editor checks what the core would refuse", () => {
  assert.deepEqual(moveStep(["a", "b", "c"], 2, -1), ["a", "c", "b"]);
  assert.deepEqual(moveStep(["a", "b"], 0, -1), ["a", "b"]);
  const step = newStep("t1");
  assert.equal(stackInputReason({ name: "lab", steps: [step] }), null);
  assert.equal(stackInputReason({ name: " ", steps: [step] }), "Give the stack a name");
  assert.equal(stackInputReason({ name: "lab", steps: [] }), "Add a launch template");
  assert.match(stackInputReason({ name: "lab", steps: [{ ...step, count: 0 }] })!, /count of 1/);
  assert.match(
    stackInputReason({ name: "lab", steps: [{ ...step, readiness: { kind: "sshPort", port: 0 } }] })!,
    /port/,
  );
  assert.match(stackInputReason({ name: "lab", steps: [{ ...step, readyTimeoutSecs: 5 }] })!, /30 seconds/);
  assert.match(stackInputReason({ name: "lab", steps: [{ ...step, delaySecs: 7200 }] })!, /at most an hour/);
  assert.match(
    stackInputReason({
      name: "lab",
      steps: [
        { ...step, count: 30 },
        { ...step, count: 21 },
      ],
    })!,
    /at most 50/,
  );
});

function vm(name: string, change: Partial<InstanceVm> = {}): InstanceVm {
  return {
    key: `C:\\VMs\\${name}\\${name}.vmx`,
    name,
    step: 0,
    origin: "deploy",
    powerState: "running",
    protected: false,
    environment: "lab",
    ...change,
  };
}

function instance(vms: InstanceVm[], id = "i1"): StackInstance {
  return {
    id,
    stackId: "s1",
    stackName: "web lab",
    name: `web lab ${id}`,
    steps: [],
    jobId: null,
    createdAt: "",
    vms,
  };
}

test("an instance says what state its VMs are in and why an action is off", () => {
  const i = instance([vm("db-1"), vm("web-1", { powerState: "not_running" }), vm("old", { powerState: null })]);
  assert.equal(instanceStateText(i), "3 VMs: 1 running, 1 off, 1 gone");
  assert.equal(instancePowerReason(i, "start", null), null);
  assert.equal(instancePowerReason(i, "stop", null), null);
  assert.equal(instancePowerReason(i, "stop", "Presenting"), "Presenting");
  const allOn = instance([vm("db-1"), vm("web-1")]);
  assert.equal(instancePowerReason(allOn, "start", null), "Every VM of it is running");
  const allOff = instance([vm("db-1", { powerState: "not_running" })]);
  assert.equal(instancePowerReason(allOff, "suspend", null), "No VM of it is running");
  assert.equal(teardownReason(allOn, null), "db-1 is running: shut the instance down first");
  assert.equal(teardownReason(allOff, null), null);
  const handOnly = instance([vm("tools01", { origin: "hand", powerState: "not_running" })]);
  assert.match(teardownReason(handOnly, null)!, /forget the instance/);
  assert.deepEqual(
    handAdded(handOnly).map((v) => v.name),
    ["tools01"],
  );
});

test("the VMs page groups rows by instance, keeping its own order within each", () => {
  const a = instance([vm("db-1"), vm("web-1")], "a");
  const b = instance([vm("solo-1")], "b");
  const rows = [
    { vmxPath: "C:\\VMs\\other\\other.vmx" },
    { vmxPath: "c:\\vms\\WEB-1\\web-1.vmx" },
    { vmxPath: "C:\\VMs\\solo-1\\solo-1.vmx" },
    { vmxPath: "C:\\VMs\\db-1\\db-1.vmx" },
  ];
  const groups = groupByInstance(rows, [a, b]);
  assert.deepEqual(
    groups.map((g) => [g.instance?.id ?? null, g.vms.map((v) => v.vmxPath.split("\\").pop()!.toLowerCase())]),
    [
      ["a", ["web-1.vmx", "db-1.vmx"]],
      ["b", ["solo-1.vmx"]],
      [null, ["other.vmx"]],
    ],
  );
  assert.deepEqual(groupByInstance(rows.slice(0, 1), []), [{ instance: null, vms: rows.slice(0, 1) }]);
});

function capacity(change: Partial<DeployCapacity> = {}): DeployCapacity {
  return {
    ram: { physicalMb: 32768, inUseMb: 20480, runningMb: 12288, addsMb: 8192, afterMb: 20480, fits: true },
    cpu: { logicalCpus: 16, runningVcpus: 4, addsVcpus: 4, afterVcpus: 8, largestVmVcpus: 2, fits: true },
    drives: [
      {
        drive: "D:",
        freeBytes: 500 * 2 ** 30,
        totalBytes: 1000 * 2 ** 30,
        addsBytes: 80 * 2 ** 30,
        thickBytes: 0,
        freeAfterBytes: 420 * 2 ** 30,
        fits: true,
        worstCaseFits: true,
        lowAfter: false,
      },
    ],
    runningVms: 2,
    unsizedVms: 0,
    newVms: 2,
    startingVms: 2,
    fits: true,
    problems: [],
    warnings: [],
    suspend: null,
    unchecked: [],
    ...change,
  };
}

test("the capacity plan reads in lines and its suspend suggestion is a power target list", () => {
  const c = capacity();
  assert.equal(ramLine(c), "20.0 GB of 32.0 GB after (12.0 GB now)");
  assert.equal(cpuLine(c), "8 vCPUs on 16 logical CPUs after (4 now)");
  assert.equal(driveLine(c.drives[0]), "up to 80 GB of 500 GB free (420 GB left)");
  assert.deepEqual(suspendTargets(c), []);
  const tight = capacity({
    fits: false,
    suspend: {
      vms: [{ key: "C:\\VMs\\build01\\build01.vmx", name: "build01", ramMb: 8192, environment: "lab" }],
      freesMb: 8192,
      needsMb: 4096,
      enough: true,
    },
  });
  assert.deepEqual(suspendTargets(tight), [{ kind: "vm", vmxPath: "C:\\VMs\\build01\\build01.vmx" }]);
});

test("a stack's deploy reason and a step's line", () => {
  const stack = { problems: ["Step 1: its launch template was deleted."] } as Stack;
  assert.equal(deployStackReason(stack, null), "Step 1: its launch template was deleted.");
  assert.equal(deployStackReason({ problems: [] } as unknown as Stack, null), null);
  assert.equal(deployStackReason({ problems: [] } as unknown as Stack, "Presenting"), "Presenting");
  const step = {
    label: "db",
    vms: ["db-1"],
    readiness: { kind: "tools" as const },
    readyTimeoutSecs: 300,
    delaySecs: 0,
    deploy: null,
  };
  assert.equal(stepLine(step, 0, false), "1. db: db-1; waits up to 5 min for the guest tools running");
  assert.equal(stepLine(step, 0, true), "1. db: db-1");
});
