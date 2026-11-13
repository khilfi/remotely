/// <reference types="node" />
// SS-14, BX-10 (0.8.0 G3): the Files page's helpers. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { DiffRow } from "./files-page-api.ts";
import {
  canGo,
  clickPick,
  DEFAULT_VIEW,
  defaultPicks,
  dropAction,
  emptyHistory,
  filterTest,
  go,
  localCrumbs,
  rowWords,
  syncSummary,
  syncTakes,
  viewEntries,
  visit,
  type DragItems,
  type PaneEntry,
} from "./files-page.ts";

const entry = (name: string, kind: PaneEntry["kind"] = "file", size = 1, modified = 1): PaneEntry => ({
  name,
  kind,
  link: false,
  size,
  modified,
});

test("a pane shows folders first, hides dot files unless asked, and filters by words or a glob", () => {
  const entries = [entry("b.conf", "file", 5), entry("a.txt", "file", 9), entry("logs", "folder"), entry(".env")];
  assert.deepEqual(
    viewEntries(entries, DEFAULT_VIEW).map((e) => e.name),
    ["logs", "a.txt", "b.conf"],
  );
  assert.deepEqual(
    viewEntries(entries, { ...DEFAULT_VIEW, hidden: true }).map((e) => e.name),
    ["logs", ".env", "a.txt", "b.conf"],
  );
  assert.deepEqual(
    viewEntries(entries, { ...DEFAULT_VIEW, sort: "size", dir: -1 }).map((e) => e.name),
    ["logs", "a.txt", "b.conf"],
  );
  assert.deepEqual(
    viewEntries(entries, { ...DEFAULT_VIEW, filter: "*.CONF" }).map((e) => e.name),
    ["b.conf"],
  );
  assert.ok(filterTest("a t")("a.txt"));
  assert.ok(!filterTest("a z")("a.txt"));
  assert.ok(filterTest("")("anything"));
  assert.ok(filterTest("[x]*")("[x]y"), "brackets are plain characters");
  const hiddenHere = [{ ...entry("desktop.ini"), hidden: true }];
  assert.equal(viewEntries(hiddenHere, DEFAULT_VIEW).length, 0, "Windows' hidden attribute counts too");
});

test("clicks pick one row, Ctrl adds or removes, Shift picks a range", () => {
  const shown = ["a", "b", "c", "d"];
  let s = clickPick(shown, [], null, "b", { ctrl: false, shift: false });
  assert.deepEqual(s, { picked: ["b"], anchor: "b" });
  s = clickPick(shown, s.picked, s.anchor, "d", { ctrl: false, shift: true });
  assert.deepEqual(s.picked, ["b", "c", "d"]);
  s = clickPick(shown, s.picked, s.anchor, "c", { ctrl: true, shift: false });
  assert.deepEqual(s.picked, ["b", "d"]);
  s = clickPick(shown, s.picked, s.anchor, "a", { ctrl: true, shift: true });
  assert.deepEqual(s.picked.sort(), ["a", "b", "c", "d"]);
});

test("Back and Forward go through the places shown, a new one dropping what was ahead", () => {
  const same = (a: string, b: string) => a === b;
  let h = visit(emptyHistory<string>(), "/srv", same);
  h = visit(h, "/srv/www", same);
  h = visit(h, "/srv/www", same);
  assert.equal(h.items.length, 2);
  assert.ok(canGo(h, -1) && !canGo(h, 1));
  const back = go(h, -1);
  assert.equal(back?.item, "/srv");
  h = visit(back!.history, "/etc", same);
  assert.deepEqual(h.items, ["/srv", "/etc"]);
  assert.equal(go(h, 1), null);
});

test("this PC's breadcrumbs start at its drives", () => {
  assert.deepEqual(localCrumbs("C:\\Users\\alice"), [
    { label: "This PC", path: null },
    { label: "C:", path: "C:\\" },
    { label: "Users", path: "C:\\Users" },
    { label: "alice", path: "C:\\Users\\alice" },
  ]);
  assert.deepEqual(localCrumbs(null), [{ label: "This PC", path: null }]);
});

test("a drop uploads, downloads or moves, and never changes a folder of this PC", () => {
  const local: DragItems = { from: "local", listing: "l1", names: ["a.txt"] };
  const host: DragItems = { from: "host", terminalId: "t1", folder: "/srv", paths: ["/srv/a"], asRoot: false };
  assert.deepEqual(dropAction(local, { pane: "host", terminalId: "t1", folder: "/srv" }), {
    kind: "upload",
    folder: "/srv",
  });
  assert.deepEqual(dropAction(local, { pane: "host", terminalId: "t1", folder: "/srv", intoFolder: "/srv/www" }), {
    kind: "upload",
    folder: "/srv/www",
  });
  assert.equal(dropAction(local, { pane: "local", listing: "l2" }), null);
  assert.deepEqual(dropAction(host, { pane: "local", listing: "l1" }), { kind: "download" });
  assert.equal(dropAction(host, { pane: "local", listing: null }), null, "not on the drives view");
  assert.deepEqual(dropAction(host, { pane: "host", terminalId: "t1", folder: "/srv", intoFolder: "/srv/www" }), {
    kind: "move",
    into: "/srv/www",
  });
  assert.equal(dropAction(host, { pane: "host", terminalId: "t1", folder: "/srv", intoFolder: "/srv/a/b" }), null);
  assert.equal(dropAction(host, { pane: "host", terminalId: "t2", folder: "/srv", intoFolder: "/x" }), null);
  assert.equal(dropAction(host, { pane: "host", terminalId: "t1", folder: "/srv" }), null);
});

const row = (path: string, state: DiffRow["state"], extra: Partial<DiffRow> = {}): DiffRow => ({
  path,
  here: state === "onlyThere" ? null : { folder: false, size: 1, modified: 1 },
  there: state === "onlyHere" ? null : { folder: false, size: 1, modified: 1 },
  state,
  newer: null,
  larger: null,
  sameContent: null,
  ...extra,
});

test("a sync takes what is missing or newer on the other side, and deletes only when asked", () => {
  const rows = [
    row("new.html", "onlyHere"),
    row("extra.html", "onlyThere"),
    row("old.html", "differs", { newer: "here" }),
    row("theirs.html", "differs", { newer: "there" }),
    row("clash", "conflict"),
  ];
  assert.deepEqual(defaultPicks(rows, "toHost", false), ["new.html", "old.html"]);
  assert.deepEqual(defaultPicks(rows, "toHost", true), ["new.html", "extra.html", "old.html"]);
  assert.deepEqual(defaultPicks(rows, "toPc", false), ["extra.html", "theirs.html"]);
  assert.ok(syncTakes(rows[3], "toHost", false).can, "an older file can still be picked by hand");
  assert.ok(!syncTakes(rows[4], "toHost", true).can);
  assert.ok(!syncTakes(rows[0], "toPc", true).can, "nothing on this PC is deleted");
  assert.deepEqual(syncSummary(rows, ["new.html", "extra.html", "old.html"], "toHost", true), {
    send: 1,
    replace: 1,
    remove: 1,
  });
  assert.deepEqual(syncSummary(rows, ["extra.html"], "toHost", false), { send: 0, replace: 0, remove: 0 });
});

test("rows say how they differ", () => {
  assert.equal(rowWords(row("a", "onlyHere")), "Only on this PC");
  assert.equal(
    rowWords(row("a", "differs", { newer: "there", larger: "here" })),
    "The host's is newer, this PC's is larger",
  );
  assert.equal(rowWords(row("a", "differs", { sameContent: false })), "Other contents");
});
