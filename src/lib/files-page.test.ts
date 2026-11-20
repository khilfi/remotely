/// <reference types="node" />
// SS-14, BX-10 (0.8.0 G3): the Files page's helpers. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { DiffRow } from "./files-page-api.ts";
import {
  back,
  canGo,
  clickPick,
  DEFAULT_VIEW,
  defaultPicks,
  dropAction,
  emptyHistory,
  filterTest,
  go,
  localCrumbs,
  manyHostsDrop,
  pushableFiles,
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

test("QL-09: Back from a folder that wouldn't open goes to the last one that did", () => {
  const same = (a: string, b: string) => a === b;
  // Only folders that opened join the history: /home/alice, then its logs.
  let h = visit(emptyHistory<string>(), "/home/alice", same);
  // /root is refused: Back goes to /home/alice, though nothing was before it.
  assert.deepEqual(back(h, { item: "/root", failed: true }, same), { history: h, item: "/home/alice" });
  h = visit(h, "/home/alice/logs", same);
  // From logs that opened, Back is the place before.
  assert.equal(back(h, { item: "/home/alice/logs", failed: false }, same)?.item, "/home/alice");
  // From a refused /root after logs: logs, not skipped.
  assert.equal(back(h, { item: "/root", failed: true }, same)?.item, "/home/alice/logs");
  // A folder that opened before and fails now (gone) goes to the place before it, not to itself.
  assert.equal(back(h, { item: "/home/alice/logs", failed: true }, same)?.item, "/home/alice");
  // Nothing shown yet, or nothing before.
  assert.equal(back(emptyHistory<string>(), null, same), null);
  assert.equal(back(visit(emptyHistory<string>(), "/", same), { item: "/", failed: false }, same), null);
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

test("rows of this PC let go on Many hosts fill its push, in place of files chosen before", () => {
  // UX-15, the owner's hand check of #115: the drop was silent; then #116's review: a hint alone could be false.
  const local: DragItems = { from: "local", listing: "l1", names: ["app.conf"] };
  assert.deepEqual(dropAction(local, { pane: "many" }), { kind: "push" });
  const host: DragItems = { from: "host", terminalId: "t1", folder: "/srv", paths: ["/srv/a"], asRoot: false };
  assert.equal(dropAction(host, { pane: "many" }), null, "a host's rows don't push");

  const entries = [entry("a.txt"), entry("b.txt"), entry("logs", "folder"), { ...entry("current.log"), link: true }];
  assert.deepEqual(pushableFiles(["a.txt", "logs", "current.log", "gone.txt"], entries), ["a.txt"]);
  // Nothing chosen before: the push sends the dragged files.
  assert.deepEqual(manyHostsDrop(["a.txt", "logs"], entries, null), {
    files: ["a.txt"],
    unstage: false,
    text: "Push now sends 1 file from this PC.",
  });
  // a.txt chosen with Choose files, then b.txt dragged: the push sends b.txt, never the chosen one.
  assert.deepEqual(manyHostsDrop(["b.txt"], entries, 1), {
    files: ["b.txt"],
    unstage: true,
    text: "Push now sends 1 file from this PC in place of the 1 file chosen before.",
  });
  assert.equal(
    manyHostsDrop(["a.txt", "b.txt"], entries, 3).text,
    "Push now sends 2 files from this PC in place of the 3 files chosen before.",
  );
  // No file among them: nothing changes, what was chosen stays, and it says why.
  assert.deepEqual(manyHostsDrop(["logs", "current.log"], entries, 1), {
    files: [],
    unstage: false,
    text: "Nothing changed: a push sends files, not folders or links.",
  });
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
