import { test } from "node:test";
import assert from "node:assert/strict";
import {
  applyEdit,
  doubleClickTitle,
  editInTerminalLabel,
  editInTerminalReason,
  editStateText,
  endsInText,
  fileName,
  savesText,
  stopChoices,
} from "./editing.ts";
import type { EditInfo, HostEditors } from "./editing-api.ts";

const editors = (found: string[], uses: string | null): HostEditors => ({
  found,
  chosen: null,
  uses,
  sessionId: null,
});

const edit = (id: string, state: EditInfo["state"], saves = 0): EditInfo => ({
  id,
  terminalId: "t1",
  name: "web01",
  path: "/etc/nginx/nginx.conf",
  asRoot: false,
  editor: "VS Code",
  state,
  saves,
  note: null,
  startedAt: "2026-11-13T10:00:00Z",
  endsAt: "2026-11-13T14:00:00Z",
  endedAt: null,
});

test("a file's name is its path's last part", () => {
  assert.equal(fileName("/etc/nginx/nginx.conf"), "nginx.conf");
  assert.equal(fileName("/srv/it's here.txt"), "it's here.txt");
  assert.equal(fileName("/"), "/");
});

test("a double-click says what it does, as the setting and the host's editors say", () => {
  assert.equal(doubleClickTitle(undefined, null), "Double-click to edit in the terminal");
  assert.equal(
    doubleClickTitle("terminalEditor", editors(["nano", "vi"], "nano")),
    "Double-click to edit in nano on the host",
  );
  assert.equal(doubleClickTitle("thisPc", editors(["nano"], "nano")), "Double-click to edit on this PC");
  assert.match(doubleClickTitle("terminalEditor", editors([], null)), /no terminal editor/);
  assert.equal(editInTerminalLabel(editors(["vim"], "vim")), "Edit in vim");
  assert.equal(editInTerminalLabel(null), "Edit in the terminal");
  assert.equal(editInTerminalReason(editors(["vi"], "vi")), null);
  assert.match(editInTerminalReason(editors([], null)) ?? "", /on this PC instead/);
  assert.equal(editInTerminalReason(null), null, "not known yet: the core says when it opens");
});

test("a session's saves, time left and state are in words", () => {
  assert.equal(savesText(0), "No saves yet");
  assert.equal(savesText(1), "1 save uploaded");
  assert.equal(savesText(3), "3 saves uploaded");
  const start = Date.parse("2026-11-13T10:00:30Z");
  assert.equal(endsInText("2026-11-13T14:00:00Z", start), "Ends in 3 h 59 min");
  assert.equal(endsInText("2026-11-13T10:12:31Z", start), "Ends in 12 min");
  assert.equal(endsInText("2026-11-13T10:01:00Z", start), "Ends in under a minute");
  assert.equal(editStateText({ state: "watching" }).tone, "muted");
  assert.equal(editStateText({ state: "conflict", message: "x" }).tone, "warn");
  assert.deepEqual(editStateText({ state: "failed", message: "The save was not uploaded: gone" }), {
    text: "The save was not uploaded: gone",
    tone: "error",
  });
});

test("the list follows the events: added, updated in place, gone when ended", () => {
  let list: EditInfo[] = [];
  list = applyEdit(list, edit("a", { state: "watching" }));
  list = applyEdit(list, edit("b", { state: "watching" }));
  list = applyEdit(list, edit("a", { state: "watching" }, 2));
  assert.deepEqual(
    list.map((e) => [e.id, e.saves]),
    [
      ["a", 2],
      ["b", 0],
    ],
  );
  list = applyEdit(list, edit("a", { state: "ended", reason: "stopped", message: "stopped by the user" }));
  assert.deepEqual(
    list.map((e) => e.id),
    ["b"],
  );
  // A copy kept with a save that didn't go up stays listed until it is discarded.
  const kept = { state: "kept", reason: "terminalClosed", message: "its last save was not uploaded" } as const;
  list = applyEdit(list, edit("b", kept));
  assert.deepEqual(
    list.map((e) => e.state.state),
    ["kept"],
  );
  assert.equal(editStateText(kept).tone, "warn");
  list = applyEdit(list, edit("b", { state: "ended", reason: "terminalClosed", message: "discarded" }));
  assert.equal(list.length, 0);
});

test("Stop's question offers keeping the copy first, and Upload again only when it could help", () => {
  assert.deepEqual(
    stopChoices(false).map((c) => c.choice),
    ["keep", "upload", "discard"],
  );
  assert.deepEqual(
    stopChoices(true).map((c) => c.choice),
    ["keep", "discard"],
  );
  assert.equal(editStateText({ state: "held", message: "The read-only lock is on" }).tone, "warn");
});
