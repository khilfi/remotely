/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import type { SessionFolder } from "./api.ts";
import {
  anyPicks,
  compareTabKeys,
  leftOutText,
  pickCount,
  picksParts,
  picksSummary,
  selectionPicks,
  togglePick,
  type SummaryNames,
} from "./bulk-picks.ts";

const folder = (id: string, name: string, parentId: string | null = null): SessionFolder => ({
  id,
  parentId,
  name,
  sortOrder: 0,
  defaults: {} as SessionFolder["defaults"],
});

const names: SummaryNames = {
  folders: [folder("web", "Web"), folder("web-eu", "EU", "web"), folder("db", "Databases")],
  sessions: [
    { id: "w1", name: "web01", folderId: "web" },
    { id: "w2", name: "web02", folderId: "web-eu" },
    { id: "d1", name: "db01", folderId: "db" },
    { id: "d2", name: "db02", folderId: "db" },
    { id: "b", name: "bastion", folderId: null },
  ],
  vms: [
    { vmxPath: "C:\\VMs\\web\\web.vmx", displayName: "web" },
    { vmxPath: "C:\\VMs\\db\\db.vmx", displayName: "db" },
  ],
  filters: [{ id: "f1", name: "Lab" }],
  groups: [{ id: "g1", name: "web servers" }],
};

test("the summary names whole folders, then sessions, VMs, tags, filters and groups", () => {
  const parts = picksParts(
    {
      sessionIds: ["w1", "w2", "d1", "b"],
      vmPaths: ["c:\\vms\\web\\web.vmx"],
      tags: ["db"],
      filterIds: ["f1"],
      groupIds: ["g1"],
    },
    { count: 6, current: false },
    names,
  );
  assert.deepEqual(parts, [
    "6 picked tabs",
    "folder 'Web'",
    "2 sessions",
    "VM 'web'",
    "tag 'db'",
    "filter 'Lab'",
    "group 'web servers'",
  ]);
  assert.equal(
    picksSummary(12, parts),
    "12 hosts: 6 picked tabs, folder 'Web', 2 sessions, VM 'web' and 3 more",
    "past four parts, the rest are counted",
  );
  assert.equal(
    picksSummary(12, ["6 picked tabs", "folder 'Web'", "tag 'db'"]),
    "12 hosts: 6 picked tabs, folder 'Web', tag 'db'",
  );
  assert.equal(picksSummary(0, []), "Nothing picked");
});

test("a folder is named only when every session under it is picked, and a subfolder not again", () => {
  assert.deepEqual(picksParts({ sessionIds: ["w2"] }, { count: 0, current: false }, names), ["folder 'EU'"]);
  assert.deepEqual(picksParts({ sessionIds: ["w1"] }, { count: 0, current: false }, names), ["session 'web01'"]);
  assert.deepEqual(picksParts({ sessionIds: ["d1", "d2", "w1", "w2"] }, { count: 0, current: false }, names), [
    "folder 'Databases'",
    "folder 'Web'",
  ]);
});

test("the current tab is 'this tab'; many VMs are counted; deleted picks still show", () => {
  assert.deepEqual(picksParts({}, { count: 1, current: true }, names), ["this tab"]);
  assert.deepEqual(picksParts({ vmPaths: ["a", "b", "c"] }, { count: 0, current: false }, names), ["3 VMs"]);
  assert.deepEqual(picksParts({ groupIds: ["gone"], filterIds: ["gone"] }, { count: 0, current: false }, names), [
    "a saved filter (deleted)",
    "a group (deleted)",
  ]);
});

test("Compare runs on the tabs the tab row marks picked, or the current tab only when nothing else is picked", () => {
  assert.deepEqual(compareTabKeys({ typing: true, picked: ["a", "b"], current: "c", otherPicks: true }), {
    keys: ["a", "b"],
    current: false,
    leftOut: 0,
  });
  assert.deepEqual(compareTabKeys({ typing: false, picked: ["a", "b"], current: "c", otherPicks: true }), {
    keys: ["a", "b"],
    current: false,
    leftOut: 0,
  });
  // One Ctrl+clicked tab (A picked, then C unpicked; or one of two picked tabs closed) isn't marked picked, so it
  // isn't one here either: the current tab is, as before 0.9.0.
  assert.deepEqual(compareTabKeys({ typing: false, picked: ["a"], current: "c", otherPicks: false }), {
    keys: ["c"],
    current: true,
    leftOut: 0,
  });
  assert.deepEqual(compareTabKeys({ typing: false, picked: ["a"], current: "c", otherPicks: true }), {
    keys: [],
    current: false,
    leftOut: 0,
  });
  assert.deepEqual(compareTabKeys({ typing: false, picked: [], current: "c", otherPicks: false }), {
    keys: ["c"],
    current: true,
    leftOut: 0,
  });
  assert.deepEqual(
    compareTabKeys({ typing: false, picked: [], current: "c", otherPicks: true }),
    { keys: [], current: false, leftOut: 0 },
    "a run on a tag reaches exactly its picks",
  );
  assert.deepEqual(compareTabKeys({ typing: false, picked: [], current: null, otherPicks: false }), {
    keys: [],
    current: false,
    leftOut: 0,
  });
});

test("BX-01: Run a command on these… leaves the typing tabs out until the picked tabs change", () => {
  const typing = ["a", "b", "c", "d", "e", "f"];
  assert.deepEqual(
    compareTabKeys({ typing: true, picked: typing, current: "a", otherPicks: true, leftOut: [...typing].reverse() }),
    { keys: [], current: false, leftOut: 6 },
    "the same tabs, in any order: left out",
  );
  assert.deepEqual(
    compareTabKeys({ typing: true, picked: [...typing, "g"], current: "a", otherPicks: true, leftOut: typing }),
    { keys: [...typing, "g"], current: false, leftOut: 0 },
    "a tab Ctrl+clicked since: the typing tabs count again",
  );
  assert.equal(leftOutText(6), "The 6 tabs you're typing in are left out.");
  assert.equal(leftOutText(1), "The tab you're typing in is left out.");
});

test("the summary counts only sessions the job takes (a folder's RDP session isn't one)", () => {
  // The tree's Ctrl+click on Web picks its RDP session too; it runs nowhere, so Web is still the whole folder.
  assert.deepEqual(picksParts({ sessionIds: ["w1", "w2", "rdp"] }, { count: 0, current: false }, names), [
    "folder 'Web'",
  ]);
  assert.deepEqual(picksParts({ sessionIds: ["rdp"] }, { count: 0, current: false }, names), []);
});

test("picks are toggled once each and counted with the tabs", () => {
  let picks = togglePick({}, "groupIds", "g1", true);
  picks = togglePick(picks, "groupIds", "g1", true);
  assert.deepEqual(picks.groupIds, ["g1"]);
  assert.ok(anyPicks(picks));
  assert.equal(pickCount({ ...picks, terminalIds: ["t1", "t2"] }), 3);
  picks = togglePick(picks, "groupIds", "g1", false);
  assert.ok(!anyPicks({ ...picks, terminalIds: ["t1"] }), "tabs are not the picker's picks");
  assert.deepEqual(selectionPicks({ vmPaths: ["C:\\VMs\\web\\web.vmx"] }), {
    sessionIds: [],
    vmPaths: ["C:\\VMs\\web\\web.vmx"],
  });
});
