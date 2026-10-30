/// <reference types="node" />
// UX-02, UX-03: the Virtual machines page's header, columns, selection bar and details tabs. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  activeFilterCount,
  defaultColumns,
  moreGroups,
  parseColumns,
  powerTargets,
  selectionPowerReason,
  serialiseColumns,
  stateDetail,
  viewOfTab,
  visibleColumns,
  VM_COLUMNS,
  VM_TABS,
  vmTabOf,
  type SelectedVm,
} from "./vm-page.ts";

function vm(extra: Partial<SelectedVm> = {}): SelectedVm {
  return { powerState: "not_running", protected: false, environment: "none", tags: [], ...extra };
}

test("the details panel has five tabs, and the 0.5.0 views open the tab that holds them", () => {
  assert.deepEqual(
    VM_TABS.map((t) => t.label),
    ["Overview", "Snapshots", "Settings", "Log", "Activity"],
  );
  assert.equal(vmTabOf("details"), "overview");
  assert.equal(vmTabOf("system"), "overview");
  assert.equal(vmTabOf("timeline"), "activity");
  assert.equal(vmTabOf("schedules"), "activity");
  assert.equal(vmTabOf("snapshots"), "snapshots");
  assert.equal(vmTabOf("settings"), "settings");
  assert.equal(vmTabOf("log"), "log");
  for (const tab of VM_TABS) assert.equal(vmTabOf(viewOfTab(tab.id)), tab.id, `${tab.id} round-trips`);
});

test("columns: defaults, stored choices and what a narrow list leaves out", () => {
  const shown = defaultColumns();
  assert.ok(shown.has("state") && shown.has("environment") && shown.has("ip"));
  assert.ok(!shown.has("sessions"), "sessions show in the details by default");
  assert.equal(parseColumns(null).size, shown.size);
  assert.equal(parseColumns("not json").size, shown.size, "unreadable storage is the default");
  assert.equal(parseColumns('{"a":1}').size, shown.size);
  const stored = parseColumns('["state","nonsense","ip"]');
  assert.deepEqual([...stored].sort(), ["ip", "state"], "unknown ids are dropped");
  assert.equal(serialiseColumns(new Set(["ip", "hypervisor"])), '["hypervisor","ip"]', "in the list's order");
  assert.deepEqual(visibleColumns(new Set(["guestOs", "state", "ram"]), false), ["guestOs", "ram", "state"]);
  assert.deepEqual(visibleColumns(new Set(["guestOs", "state", "ram"]), true), ["state"], "wide ones give way");
  assert.ok(VM_COLUMNS.every((c) => c.label.length > 0));
});

test("the Filter button counts the kinds of filter on, not the search text", () => {
  assert.equal(activeFilterCount({}), 0);
  assert.equal(activeFilterCount({ text: "web" }), 0);
  assert.equal(activeFilterCount({ tags: ["web", "db"], powerStates: ["running"] }), 2);
  assert.equal(activeFilterCount({ hypervisors: ["vmware"], environments: ["prod"], protected: false }), 3);
  assert.equal(activeFilterCount({ tags: [], protected: null }), 0);
});

test("the State badge folds the guest tools in and flags a running VM whose tools don't run", () => {
  assert.deepEqual(stateDetail({ powerState: "not_running", toolsState: null, hypervisor: "vmware" }), {
    text: "Off",
    toolsWarning: false,
  });
  assert.deepEqual(stateDetail({ powerState: "running", toolsState: "running", hypervisor: "vmware" }), {
    text: "Running · VMware Tools running",
    toolsWarning: false,
  });
  assert.deepEqual(stateDetail({ powerState: "running", toolsState: "notInstalled", hypervisor: "virtualbox" }), {
    text: "Running · Guest Additions not installed",
    toolsWarning: true,
  });
  assert.equal(stateDetail({ powerState: "running", toolsState: "unknown", hypervisor: "vmware" }).toolsWarning, false);
  assert.equal(stateDetail({ powerState: "suspended", toolsState: "running", hypervisor: "vmware" }).text, "Suspended");
});

test("More shows only what applies to the selection, in groups", () => {
  const ids = (groups: ReturnType<typeof moreGroups>) => groups.map((g) => [g.label, g.items.map((i) => i.id)]);
  const off = moreGroups([vm()], { snapshots: 0, canRelease: false, canExport: true });
  assert.deepEqual(ids(off), [
    ["Power", ["startGui"]],
    ["Change", ["resize", "clone", "export", "delete"]],
    ["Organise", ["addTag", "environment", "protect"]],
  ]);

  const running = moreGroups([vm({ powerState: "running", tags: ["web"] })], {
    snapshots: 1,
    canRelease: true,
    canExport: false,
  });
  assert.deepEqual(ids(running), [
    ["Power", ["suspend", "restart", "pause", "powerOff"]],
    ["Snapshots", ["revert", "deleteSnapshot"]],
    ["Change", ["tools"]],
    ["Organise", ["addTag", "removeTag", "environment", "protect", "release"]],
  ]);

  const protectedRunning = moreGroups([vm({ powerState: "running", protected: true })], {
    snapshots: null,
    canRelease: false,
    canExport: false,
  });
  const change = protectedRunning.find((g) => g.label === "Change");
  assert.equal(change, undefined, "a protected VM gets no tools, resize or delete");
  assert.equal(
    protectedRunning.find((g) => g.label === "Snapshots"),
    undefined,
    "left out while the trees are read",
  );
  assert.deepEqual(
    protectedRunning.find((g) => g.label === "Organise")?.items.map((i) => i.id),
    ["addTag", "environment", "unprotect"],
  );

  const mixed = moreGroups([vm({ powerState: "running" }), vm(), vm({ powerState: "paused" })], {
    snapshots: 2,
    canRelease: false,
    canExport: false,
  });
  const power = mixed.find((g) => g.label === "Power")?.items ?? [];
  assert.deepEqual(
    power.map((i) => [i.id, i.count]),
    [
      ["startGui", 1],
      ["suspend", 1],
      ["restart", 2],
      ["pause", 1],
      ["unpause", 1],
      ["powerOff", 2],
    ],
  );
});

test("power goes to the VMs in a state it applies to, and to VMs in an unknown state", () => {
  const vms = [vm({ powerState: "running" }), vm({ powerState: "unknown" }), vm()];
  assert.equal(powerTargets(vms, ["running"]).length, 2);
  assert.equal(selectionPowerReason([vm({ powerState: "running" })], "start"), "It is running already");
  assert.equal(selectionPowerReason([vm(), vm()], "shutDown"), "None of them is running");
  assert.equal(selectionPowerReason([vm(), vm({ powerState: "running" })], "shutDown"), null);
  assert.equal(selectionPowerReason([vm({ powerState: "suspended" })], "start"), null, "a suspended VM resumes");
});
