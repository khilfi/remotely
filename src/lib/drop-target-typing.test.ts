/// <reference types="node" />
// QL-30 (0.9.0 H6): a drop on a terminal while Type in all tabs is on. Run with `npm test`.
//
// The owner's constraint holds here too (drop-target.test.ts pins it without typing, unchanged): the upload into the
// pane's shell folder or home, never as root, stays the drop's default. Typing in more than one tab only adds the
// push beside it; one tab picked, the drawer, or typing off change nothing.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MAX_PUSH_FILES,
  dropPush,
  dropTarget,
  dropTyping,
  pushLabel,
  pushLeftOut,
  pushNotice,
  pushReason,
  terminalPageDrop,
  type DropHost,
  type DropPlaces,
  type DropTyping,
} from "./drop-target.ts";

/** Stand-ins for the Terminal page's panes: a key, a core id, the shell's folder, and its saved session if any. */
function pane(key: string, terminalId: string | null, folder: string | null, sessionId: string | null = null) {
  return { key, terminalId, sessionId, getSnapshot: () => ({ folder: folder === null ? null : { path: folder } }) };
}

const a = pane("pane-a", "t-a", "/srv/www");
const b = pane("pane-b", "t-b", null);
const everyPane = [a, b];

/** Whatever the drawer shows: none, another folder of the same terminal as root, another terminal as root. */
const drawerStates: (DropHost | null)[] = [
  null,
  { key: "drawer", terminalId: "t-a", folder: "/home/alice", asRoot: true },
  { key: "drawer", terminalId: "t-b", folder: "/root", asRoot: true },
  { key: "drawer", terminalId: "t-a", folder: null, asRoot: true, why: "This terminal is not connected" },
];

/**
 * Three tabs picked: web01 (two panes of one saved session, split), web02, and a quick connection; a PowerShell tab
 * of a saved session, and a tab still connecting.
 */
const typing: DropTyping = {
  tabs: 5,
  panes: [
    { terminalId: "t-a", sessionId: "s-web01", ssh: true },
    { terminalId: "t-a2", sessionId: "s-web01", ssh: true },
    { terminalId: "t-b", sessionId: "s-web02", ssh: true },
    { terminalId: "t-q", sessionId: null, ssh: true },
    { terminalId: "t-ps", sessionId: "s-win01", ssh: false },
    { terminalId: null, sessionId: "s-web03", ssh: true },
  ],
};

test("typing in all tabs, a drop on a terminal asks, and its default is exactly the upload without typing", () => {
  for (const drawer of drawerStates) {
    for (const spot of [{ paneKey: "pane-a" }, { paneKey: "pane-b" }]) {
      const plain = terminalPageDrop(spot, everyPane, drawer);
      const asked = terminalPageDrop(spot, everyPane, drawer, typing);
      assert.equal(asked.kind, "choose", `drawer: ${JSON.stringify(drawer)}`);
      if (asked.kind !== "choose") continue;
      assert.deepEqual(asked.upload, plain, "the default is today's upload");
      assert.equal(asked.upload.pane, spot.paneKey === "pane-a" ? a : b, "through the pane under the drop");
      assert.equal(asked.upload.asRoot, false, "never as root");
    }
  }
  const onA = terminalPageDrop({ paneKey: "pane-a" }, everyPane, null, typing);
  assert.deepEqual(onA.kind === "choose" && [onA.upload.folder, onA.upload.asRoot], ["/srv/www", false]);
  // A shell that doesn't report its folder: null, so the page asks the core for the home folder, as before.
  const onB = terminalPageDrop({ paneKey: "pane-b" }, everyPane, null, typing);
  assert.deepEqual(onB.kind === "choose" && [onB.upload.folder, onB.upload.asRoot], [null, false]);
});

test("typing off, or in one tab, a drop on a terminal uploads as it always has", () => {
  const one: DropTyping = { tabs: 1, panes: typing.panes.slice(0, 1) };
  const none: DropTyping = { tabs: 0, panes: [] };
  for (const drawer of drawerStates) {
    for (const spot of [{ paneKey: "pane-a" }, { paneKey: "pane-b" }]) {
      const plain = terminalPageDrop(spot, everyPane, drawer);
      assert.equal(plain.kind, "upload");
      assert.deepEqual(terminalPageDrop(spot, everyPane, drawer, undefined), plain);
      assert.deepEqual(terminalPageDrop(spot, everyPane, drawer, one), plain);
      assert.deepEqual(terminalPageDrop(spot, everyPane, drawer, none), plain);
    }
  }
  // dropTarget's terminal target carries nothing more than before without typing, or with one tab.
  const places: DropPlaces = { panes: [{ key: "pane-a", folder: "/srv/www" }], hosts: [] };
  const target = { kind: "terminal", paneKey: "pane-a", folder: "/srv/www", asRoot: false };
  assert.deepEqual(dropTarget({ paneKey: "pane-a" }, places), target);
  assert.deepEqual(dropTarget({ paneKey: "pane-a" }, { ...places, typing: one }), target);
});

test("typing in all tabs changes nothing for the drawer, or for a drop that falls nowhere", () => {
  const drawer: DropHost = { key: "drawer", terminalId: "t-b", folder: "/etc/nginx", asRoot: true };
  const spot = { files: "host" as const, filesTab: "drawer" };
  assert.deepEqual(
    terminalPageDrop(spot, everyPane, drawer, typing),
    terminalPageDrop(spot, everyPane, drawer),
    "the drawer's upload, as root while it browses so",
  );
  const refused = { ...drawer, why: "Read-only while presenting" };
  assert.deepEqual(terminalPageDrop(spot, everyPane, refused, typing), {
    kind: "refused",
    why: "Read-only while presenting",
  });
  assert.deepEqual(terminalPageDrop({}, everyPane, drawer, typing), { kind: "none" });
  assert.deepEqual(terminalPageDrop({ paneKey: "gone" }, everyPane, drawer, typing), { kind: "none" });
});

test("the push goes to the picked SSH terminals of saved sessions, one host per session, and counts the rest", () => {
  const push = dropPush(typing);
  assert.deepEqual(push, {
    terminalIds: ["t-a", "t-a2", "t-b"],
    hosts: 2,
    others: 2,
    quick: 1,
    other: 2,
    why: null,
  });
  const asked = terminalPageDrop({ paneKey: "pane-a" }, everyPane, null, typing);
  assert.deepEqual(asked.kind === "choose" && asked.push, push);
  assert.equal(pushLabel(push), "Push to the 2 picked hosts…");
  // What each part counts: quick connections, and other terminals (panes), never "tabs".
  assert.equal(
    pushLeftOut(push),
    "1 quick connection left out: it isn't a saved session; 2 other terminals left out: they aren't SSH, or haven't connected",
  );
  // A terminal picked twice (the core's list holds each once).
  assert.deepEqual(dropPush({ tabs: 2, panes: [typing.panes[0], typing.panes[0]] }).terminalIds, ["t-a"]);
  // Dropped on web01: web02 is the one other host.
  assert.equal(dropPush(typing, "s-web01").others, 1);
});

test("a drop asks only when the push would reach a host besides the dropped tab's own", () => {
  const web01 = pane("pane-w1", "t-a", "/srv/www", "s-web01");
  const web01b = pane("pane-w1b", "t-a2", "/srv/www", "s-web01");
  const quickPane = pane("pane-q", "t-q", "/tmp");
  const panes = [web01, web01b, quickPane];
  const plain = (key: string) => terminalPageDrop({ paneKey: key }, panes, null);

  // Only quick connections picked: nothing to push to, so no question; the upload as today.
  const quickOnly: DropTyping = {
    tabs: 2,
    panes: [
      { terminalId: "t-q", sessionId: null, ssh: true },
      { terminalId: "t-q2", sessionId: null, ssh: true },
    ],
  };
  assert.deepEqual(terminalPageDrop({ paneKey: "pane-q" }, panes, null, quickOnly), plain("pane-q"));
  assert.equal(dropPush(quickOnly).why, "Quick connections can't take a push: save them as sessions first");
  assert.equal(pushLeftOut(dropPush(quickOnly)), "2 quick connections left out: they aren't saved sessions");
  assert.equal(pushLabel(dropPush(quickOnly)), "Push to the picked hosts…");

  // web01 split in two and a Telnet tab: two tabs picked, but the one host is the dropped tab's.
  const telnet: DropTyping = {
    tabs: 2,
    panes: [
      { terminalId: "t-a", sessionId: "s-web01", ssh: true },
      { terminalId: "t-a2", sessionId: "s-web01", ssh: true },
      { terminalId: "t-tel", sessionId: "s-router", ssh: false },
    ],
  };
  assert.deepEqual(terminalPageDrop({ paneKey: "pane-w1" }, panes, null, telnet), plain("pane-w1"));
  assert.deepEqual(terminalPageDrop({ paneKey: "pane-w1b" }, panes, null, telnet), plain("pane-w1b"));
  // A PowerShell tab alone takes no push either.
  assert.equal(
    dropPush({ tabs: 2, panes: [typing.panes[4]] }).why,
    "None of the picked tabs is a connected SSH session",
  );
  assert.equal(
    pushLeftOut(dropPush({ tabs: 2, panes: [typing.panes[4]] })),
    "1 other terminal left out: it isn't SSH, or hasn't connected",
  );

  // web01 and a quick connection: dropped on the quick one, web01 is another host, so it asks.
  const mixed: DropTyping = {
    tabs: 2,
    panes: [
      { terminalId: "t-a", sessionId: "s-web01", ssh: true },
      { terminalId: "t-q", sessionId: null, ssh: true },
    ],
  };
  const onQuick = terminalPageDrop({ paneKey: "pane-q" }, panes, null, mixed);
  assert.equal(onQuick.kind, "choose");
  assert.deepEqual(onQuick.kind === "choose" && [onQuick.upload, onQuick.push.others], [plain("pane-q"), 1]);
  // Dropped on web01 instead: the push would only reach web01, so no question.
  assert.deepEqual(terminalPageDrop({ paneKey: "pane-w1" }, panes, null, mixed), plain("pane-w1"));
});

test("one host and nothing left out", () => {
  const push = dropPush({ tabs: 2, panes: typing.panes.slice(0, 2) });
  assert.equal(pushLabel(push), "Push to the picked host…");
  assert.equal(pushLeftOut(push), null);
});

test("a push sends files: dropped folders keep it from being chosen, never the upload", () => {
  const push = dropPush(typing);
  assert.equal(pushReason(push, { files: [{}, { folder: false }] }), null);
  assert.equal(pushReason(push, { files: [{}, { folder: true }] }), "A push sends files: drop files, not folders");
  const none = dropPush({ tabs: 2, panes: [] });
  assert.equal(pushReason(none, { files: [{ folder: true }] }), none.why, "the first reason wins");
});

test("the read-only lock keeps the push from being chosen, before its dialog takes the drop", () => {
  const push = dropPush(typing);
  const locked = "Read-only while presenting: turn the read-only lock off first (Presenting menu)";
  assert.equal(pushReason(push, { files: [{}] }, locked), locked);
  assert.equal(pushReason(push, { files: [{ folder: true }] }, locked), locked, "the lock is said first");
  assert.equal(pushReason(push, { files: [{}] }, null), null);
});

test("a push takes at most the core's 100 files", () => {
  const push = dropPush(typing);
  const files = (n: number) => ({ files: Array.from({ length: n }, () => ({})) });
  assert.equal(MAX_PUSH_FILES, 100);
  assert.equal(pushReason(push, files(100)), null);
  assert.equal(pushReason(push, files(101)), "A push sends at most 100 files; 101 were dropped");
});

test("the push's notice says how many hosts got the files, and names the folder", () => {
  assert.deepEqual(pushNotice("'app.conf'", "/srv/www", ["succeeded", "succeeded"]), {
    title: "Pushed 'app.conf' to 2 hosts",
    description: "Into /srv/www",
    ok: true,
  });
  assert.deepEqual(pushNotice("2 items", "/srv/www", ["succeeded", "failed", "skipped", "unknown"]), {
    title: "Pushed 2 items to 1 of 3 hosts",
    description: "Into /srv/www; 1 host skipped (protected)",
    ok: false,
  });
  assert.deepEqual(pushNotice("'a'", "/srv", ["failed"]), {
    title: "The push of 'a' failed on 1 host",
    description: "Into /srv",
    ok: false,
  });
  assert.equal(pushNotice("'a'", "/srv", ["succeeded"]).title, "Pushed 'a' to 1 host");
  assert.equal(pushNotice("'a'", "/srv", []).title, "The push of 'a' finished", "its hosts couldn't be read");
});

test("a cancelled or interrupted push says so, not that it failed", () => {
  assert.deepEqual(pushNotice("'a'", "/srv", ["cancelled", "cancelled"], "cancelled"), {
    title: "The push of 'a' was cancelled",
    description: "Into /srv",
    ok: false,
  });
  assert.deepEqual(pushNotice("'a'", "/srv", ["succeeded", "cancelled", "skipped"], "cancelled"), {
    title: "The push of 'a' was cancelled",
    description: "Into /srv; 1 host skipped (protected); 1 of 2 hosts got it before",
    ok: false,
  });
  assert.equal(pushNotice("'a'", "/srv", ["unknown"], "interrupted").title, "The push of 'a' was interrupted");
  assert.equal(pushNotice("'a'", "/srv", ["failed"], "failed").title, "The push of 'a' failed on 1 host");
});

test("the page's panes become the typing the drop reads", () => {
  assert.deepEqual(
    dropTyping(3, [
      { terminalId: "t-a", sessionId: "s-1", kind: "ssh" },
      { terminalId: "t-w", sessionId: "s-2", kind: "powershell" },
      { terminalId: null, sessionId: null, kind: "ssh" },
    ]),
    {
      tabs: 3,
      panes: [
        { terminalId: "t-a", sessionId: "s-1", ssh: true },
        { terminalId: "t-w", sessionId: "s-2", ssh: false },
        { terminalId: null, sessionId: null, ssh: true },
      ],
    },
  );
});
