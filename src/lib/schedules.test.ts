/// <reference types="node" />
// VM-14, VM-27: the schedule editor's form and checks, and the Schedules page's wording. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ScheduleView } from "./schedules-api.ts";
import {
  emptyForm,
  formatPlanned,
  formFromView,
  formProblem,
  formToInput,
  normalTime,
  outcomeTone,
  rowReasons,
  targetsText,
  withAction,
  withTiming,
} from "./schedules.ts";

const view = (over: Partial<ScheduleView> = {}): ScheduleView => ({
  id: "s1",
  name: "nightly",
  spec: {
    action: { kind: "snapshot", keep: 3 },
    targets: [
      { kind: "vm", vmKey: "C:\\VMs\\web01\\web01.vmx" },
      { kind: "tag", tag: "lab" },
    ],
    timing: { kind: "weekly", days: ["mon", "fri"], at: "02:30" },
  },
  action: "Take a snapshot, keep the last 3",
  when: "Mon, Fri at 02:30",
  targets: [
    { target: { kind: "vm", vmKey: "C:\\VMs\\web01\\web01.vmx" }, name: "web01", vms: 1 },
    { target: { kind: "tag", tag: "lab" }, name: "lab", vms: 3 },
  ],
  state: "active",
  stateReason: null,
  nextRun: null,
  lastRun: null,
  approval: null,
  asksAgain: [],
  chainWarnings: [],
  running: false,
  createdAt: "2026-10-25T08:00:00Z",
  updatedAt: "2026-10-25T08:00:00Z",
  ...over,
});

test("a new form needs a name and a target before it saves", () => {
  const form = emptyForm();
  assert.equal(formProblem(form), "Give the schedule a name");
  assert.equal(formProblem({ ...form, name: "nightly" }), "Choose at least one VM, tag or stack");
  assert.equal(formProblem({ ...form, name: "nightly", vms: ["k"] }), null);
});

test("numbers and times are checked as the core checks them", () => {
  const ok = { ...emptyForm(["k"]), name: "n" };
  assert.match(formProblem({ ...ok, keep: "0" }) ?? "", /Keep 1 to 100/);
  assert.equal(formProblem({ ...ok, keepOn: false, keep: "0" }), null, "no retention: no count");
  assert.match(formProblem({ ...ok, at: "25:00" }) ?? "", /time like 08:00/);
  assert.match(formProblem({ ...ok, timing: "hourly", minute: "60" }) ?? "", /0 to 59/);
  assert.match(formProblem({ ...ok, timing: "weekly", days: [] }) ?? "", /one day/);
  const idle = withTiming(ok, "idle");
  assert.equal(formProblem(idle), null);
  assert.match(formProblem({ ...idle, idleMinutes: "5" }) ?? "", /10 minutes/);
  assert.match(formProblem({ ...idle, cpuBelow: "80" }) ?? "", /under 1% to 50%/);
  assert.equal(normalTime("8:05"), "08:05");
  assert.equal(normalTime("8:5"), null);
});

test("idle timing goes with Suspend only", () => {
  const form = withTiming({ ...emptyForm(["k"]), name: "n" }, "idle");
  assert.equal(form.action, "suspend");
  const started = withAction(form, "start");
  assert.equal(started.timing, "daily");
  assert.equal(withAction(form, "suspend").timing, "idle");
});

test("the form round-trips a saved schedule", () => {
  const form = formFromView(view());
  assert.deepEqual(form.days, ["mon", "fri"]);
  assert.equal(form.keep, "3");
  const input = formToInput(form);
  assert.deepEqual(input.spec, view().spec);
  assert.equal(input.id, "s1");
});

test("weekly days go in week order and times are written HH:MM", () => {
  const form = {
    ...emptyForm(["k"]),
    name: " lab ",
    timing: "weekly" as const,
    days: ["sun" as const, "mon" as const],
    at: "7:30",
  };
  const input = formToInput(form);
  assert.deepEqual(input.spec.timing, { kind: "weekly", days: ["mon", "sun"], at: "07:30" });
  assert.equal(input.name, "lab");
  assert.deepEqual(formToInput({ ...form, keepOn: false }).spec.action, { kind: "snapshot", keep: null });
});

test("rows say why a button is off", () => {
  assert.equal(rowReasons(view(), null).pause, null);
  assert.match(rowReasons(view(), null).resume ?? "", /already/);
  assert.match(rowReasons(view({ state: "paused" }), null).pause ?? "", /active/);
  assert.equal(rowReasons(view({ state: "paused" }), "Read-only").resume, "Read-only");
  assert.equal(rowReasons(view({ state: "needsApproval" }), null).approve, null);
});

test("targets and outcomes read in words", () => {
  assert.equal(targetsText(view()), "web01, tag 'lab' (3 VMs)");
  assert.equal(
    targetsText(view({ targets: [{ target: { kind: "vm", vmKey: "x" }, name: "gone", vms: 0 }] })),
    "gone (not in the VM list)",
  );
  assert.equal(outcomeTone("missed"), "warning");
  assert.equal(outcomeTone("failed"), "destructive");
  assert.equal(formatPlanned("2026-10-25T00:30:00Z", "Europe/Paris"), "Sun 25 Oct, 02:30");
});
