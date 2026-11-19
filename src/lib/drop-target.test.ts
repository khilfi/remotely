/// <reference types="node" />
// UX-14, UX-15 (0.9.0 H1): which target gets files dropped from Explorer. Run with `npm test`.
//
// The first tests pin the owner's constraint (docs/plan-0.9.md, Decisions): a drop on a connected SSH terminal uploads
// into that terminal's shell folder, or its home folder, never as root, whatever the Files drawer is doing.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  dropTarget,
  hostDropLabel,
  readDropSpot,
  type DropHost,
  type DropPlaces,
  type SpotElement,
} from "./drop-target.ts";

const panes = [
  { key: "pane-a", folder: "/home/alice/app" },
  { key: "pane-b", folder: null },
];

/** Every state the drawer can be in beside the panes: none, another folder, browsing as root, on another terminal. */
const drawers: (DropHost | null)[] = [
  null,
  { key: "drawer", terminalId: "t-a", folder: null, asRoot: false },
  { key: "drawer", terminalId: "t-a", folder: "/srv/www", asRoot: false },
  { key: "drawer", terminalId: "t-a", folder: "/etc", asRoot: true },
  { key: "drawer", terminalId: "t-b", folder: "/root", asRoot: true },
];

const terminalPage = (drawer: DropHost | null): DropPlaces => ({ panes, hosts: drawer ? [drawer] : [] });

test("a drop on a terminal pane uploads into its shell folder, not as root, whatever the drawer does", () => {
  for (const drawer of drawers) {
    assert.deepEqual(
      dropTarget({ paneKey: "pane-a" }, terminalPage(drawer)),
      { kind: "terminal", paneKey: "pane-a", folder: "/home/alice/app", asRoot: false },
      `drawer: ${JSON.stringify(drawer)}`,
    );
  }
});

test("a drop on a terminal whose shell doesn't report its folder goes to its home folder, not as root", () => {
  for (const drawer of drawers) {
    assert.deepEqual(dropTarget({ paneKey: "pane-b" }, terminalPage(drawer)), {
      kind: "terminal",
      paneKey: "pane-b",
      folder: null,
      asRoot: false,
    });
  }
});

test("a pane under the point wins over any other marker there", () => {
  const spot = { paneKey: "pane-a", files: "host" as const, filesTab: "drawer", filesFolder: "/etc/nginx" };
  assert.deepEqual(dropTarget(spot, terminalPage(drawers[3])), {
    kind: "terminal",
    paneKey: "pane-a",
    folder: "/home/alice/app",
    asRoot: false,
  });
});

test("a pane the page doesn't know takes nothing", () => {
  assert.deepEqual(dropTarget({ paneKey: "gone" }, terminalPage(drawers[2])), { kind: "none" });
});

test("a drop on the drawer uploads into the folder it shows, as root when it browses as root", () => {
  assert.deepEqual(dropTarget({ files: "host", filesTab: "drawer" }, terminalPage(drawers[2])), {
    kind: "host",
    key: "drawer",
    terminalId: "t-a",
    folder: "/srv/www",
    asRoot: false,
  });
  assert.deepEqual(dropTarget({ files: "host", filesTab: "drawer" }, terminalPage(drawers[3])), {
    kind: "host",
    key: "drawer",
    terminalId: "t-a",
    folder: "/etc",
    asRoot: true,
  });
});

test("a drop on a host pane's folder row uploads into that folder", () => {
  const spot = { files: "host" as const, filesTab: "drawer", filesFolder: "/srv/www/static" };
  assert.deepEqual(dropTarget(spot, terminalPage(drawers[2])), {
    kind: "host",
    key: "drawer",
    terminalId: "t-a",
    folder: "/srv/www/static",
    asRoot: false,
  });
});

test("a host pane with no folder open, or one the page doesn't have, takes nothing", () => {
  assert.deepEqual(dropTarget({ files: "host", filesTab: "drawer" }, terminalPage(drawers[1])), { kind: "none" });
  assert.deepEqual(dropTarget({ files: "host", filesTab: "drawer" }, terminalPage(null)), { kind: "none" });
  assert.deepEqual(dropTarget({ files: "host", filesTab: "tab-x" }, terminalPage(drawers[2])), { kind: "none" });
});

test("the Files page: host tabs, This PC and Many hosts", () => {
  const files: DropPlaces = {
    hosts: [
      { key: "tab-1", terminalId: "t-1", folder: "/var/log", asRoot: false },
      { key: "tab-2", terminalId: "t-2", folder: "/opt", asRoot: true },
    ],
    many: true,
  };
  assert.deepEqual(dropTarget({ files: "host", filesTab: "tab-2" }, files), {
    kind: "host",
    key: "tab-2",
    terminalId: "t-2",
    folder: "/opt",
    asRoot: true,
  });
  // Nothing on this PC is changed by a drop.
  assert.deepEqual(dropTarget({ files: "local" }, files), { kind: "none" });
  assert.deepEqual(dropTarget({ files: "many" }, files), { kind: "many" });
  assert.deepEqual(dropTarget({ files: "many" }, { hosts: files.hosts }), { kind: "none" });
  assert.deepEqual(dropTarget({}, files), { kind: "none" });
});

test("a VM's row takes an ISO only on the Virtual machines page", () => {
  assert.deepEqual(dropTarget({ vm: "C:\\VMs\\web\\web.vmx" }, { vms: true }), {
    kind: "vm",
    vm: "C:\\VMs\\web\\web.vmx",
  });
  assert.deepEqual(dropTarget({ vm: "C:\\VMs\\web\\web.vmx" }, terminalPage(null)), { kind: "none" });
  assert.deepEqual(dropTarget({}, { vms: true }), { kind: "none" });
});

test("pages without panes ignore a pane marker", () => {
  assert.deepEqual(dropTarget({ paneKey: "pane-a" }, { vms: true }), { kind: "none" });
});

test("the drawer's label says where a drop goes", () => {
  assert.equal(
    hostDropLabel({ kind: "host", key: "drawer", terminalId: "t", folder: "/etc", asRoot: true }),
    "Drop to upload into /etc as root",
  );
  assert.equal(
    hostDropLabel({ kind: "host", key: "drawer", terminalId: "t", folder: "/srv", asRoot: false }),
    "Drop to upload into /srv",
  );
});

/** A stand-in element: the markers on it and on its parents, nearest first. */
function element(...chain: Record<string, string>[]): SpotElement {
  const attr = (selector: string) => selector.slice(1, -1);
  const key = (name: string) => name.replace(/^data-/, "").replace(/-(\w)/g, (_, c: string) => c.toUpperCase());
  return {
    closest(selector) {
      const found = chain.find((marks) => attr(selector) in marks);
      if (!found) return null;
      return { dataset: Object.fromEntries(Object.entries(found).map(([k, v]) => [key(k), v])) };
    },
  };
}

test("the spot is read from the nearest markers", () => {
  const row = element({ "data-files-folder": "/etc/nginx" }, { "data-files-drop": "host", "data-files-tab": "drawer" });
  assert.deepEqual(
    readDropSpot(5, 6, () => row),
    {
      paneKey: undefined,
      files: "host",
      filesTab: "drawer",
      filesFolder: "/etc/nginx",
      vm: undefined,
    },
  );
  const pane = element({ "data-pane-key": "pane-a" });
  assert.equal(readDropSpot(0, 0, () => pane).paneKey, "pane-a");
  assert.deepEqual(
    readDropSpot(0, 0, () => null),
    {},
  );
  // An unknown kind of files pane counts as none.
  assert.equal(readDropSpot(0, 0, () => element({ "data-files-drop": "elsewhere" })).files, undefined);
});
