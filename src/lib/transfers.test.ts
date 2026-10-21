/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import type { RemoteEntry, ShellUsers, TransferInfo } from "./api.ts";
import {
  crumbs,
  fileWordAt,
  formatSize,
  formatSpeed,
  joinPath,
  mergeTransfer,
  percent,
  secondsLeft,
  sortEntries,
  userNote,
} from "./transfers.ts";

test("sizes read naturally, like the audit log's", () => {
  assert.equal(formatSize(0), "0 B");
  assert.equal(formatSize(999), "999 B");
  assert.equal(formatSize(1500), "1.5 KB");
  assert.equal(formatSize(25_000_000), "25 MB");
  assert.equal(formatSpeed(2_400_000), "2.4 MB/s");
  assert.equal(formatSpeed(0), null);
});

test("progress and time left come from the speed", () => {
  const t = { size: 10_000, done: 4_000, bytesPerSec: 2_000, state: "running" as const };
  assert.equal(percent(t), 40);
  assert.equal(secondsLeft(t), 3);
  assert.equal(secondsLeft({ ...t, bytesPerSec: 0 }), null);
  assert.equal(percent({ size: 0, done: 0, state: "done" }), 100);
  assert.equal(percent({ size: 0, done: 0, state: "running" }), 0);
});

function transfer(id: string, state: TransferInfo["state"]): TransferInfo {
  return {
    id,
    jobId: null,
    terminalId: "t1",
    terminal: "'web01'",
    direction: "upload",
    name: `${id}.txt`,
    remotePath: `/srv/${id}.txt`,
    localPath: null,
    size: 10,
    done: 0,
    bytesPerSec: 0,
    state,
    message: null,
    sha256: null,
    replace: false,
  };
}

test("a transfer's change replaces it in place; a new one goes last", () => {
  const list = [transfer("a", "running"), transfer("b", "queued")];
  const changed = mergeTransfer(list, { ...transfer("a", "done"), done: 10 });
  assert.deepEqual(
    changed.map((t) => [t.id, t.state]),
    [
      ["a", "done"],
      ["b", "queued"],
    ],
  );
  assert.equal(mergeTransfer(list, transfer("c", "queued")).length, 3);
});

function entry(name: string, kind: RemoteEntry["kind"], size: number, modified: number): RemoteEntry {
  return { name, kind, link: false, size, modified, mode: 0o644 };
}

test("folders come first, then the chosen column", () => {
  const entries = [
    entry("b.log", "file", 300, 3),
    entry("logs", "folder", 4096, 1),
    entry("a10.txt", "file", 100, 2),
    entry("a9.txt", "file", 200, 4),
  ];
  assert.deepEqual(
    sortEntries(entries, "name", 1).map((e) => e.name),
    ["logs", "a9.txt", "a10.txt", "b.log"],
  );
  assert.deepEqual(
    sortEntries(entries, "name", -1).map((e) => e.name),
    ["logs", "b.log", "a10.txt", "a9.txt"],
  );
  assert.deepEqual(
    sortEntries(entries, "size", -1).map((e) => e.name),
    ["logs", "b.log", "a9.txt", "a10.txt"],
  );
  assert.deepEqual(
    sortEntries(entries, "modified", 1).map((e) => e.name),
    ["logs", "a10.txt", "b.log", "a9.txt"],
  );
});

test("host paths join and break into a breadcrumb", () => {
  assert.equal(joinPath("/srv/www", "index.html"), "/srv/www/index.html");
  assert.equal(joinPath("/", "etc"), "/etc");
  assert.deepEqual(crumbs("/srv/www"), [
    { label: "/", path: "/" },
    { label: "srv", path: "/srv" },
    { label: "www", path: "/srv/www" },
  ]);
  assert.deepEqual(crumbs("/"), [{ label: "/", path: "/" }]);
});

test("a right-click finds the file name under the pointer", () => {
  const ls = "-rw-r--r-- 1 alice alice 1234 Oct 19 10:00 report.pdf";
  assert.equal(fileWordAt(ls, ls.indexOf("report") + 2), "report.pdf");
  assert.equal(fileWordAt(ls, 2), null, "the permissions column");
  assert.equal(fileWordAt(ls, ls.indexOf("1234") + 1), null, "a size");
  assert.equal(fileWordAt(ls, ls.indexOf("10:00") + 1), null, "a time");
  assert.equal(fileWordAt("backup.sh*  logs/  notes.txt", 3), "backup.sh", "ls -F's executable mark");
  assert.equal(fileWordAt("backup.sh*  logs/  notes.txt", 13), null, "a folder");
  assert.equal(fileWordAt("cat: /var/log/app.log: Permission denied", 8), "/var/log/app.log");
  assert.equal(fileWordAt("'my file.txt'", 1), "my", "quoted names with spaces are cut at the space");
  assert.equal(fileWordAt("saved to ./out/build.zip.", 12), "./out/build.zip");
  assert.equal(fileWordAt("alice@web01:~$ ", 14), null, "a blank");
  assert.equal(fileWordAt("short", 10), null, "past the end");
});

test("QL-09: the drawer says who the shell runs as only when it may differ from the login", () => {
  const login: ShellUsers = { username: "alice", shell: null, stopped: false };
  assert.deepEqual(userNote(undefined), { kind: "same" });
  assert.deepEqual(userNote(login), { kind: "same" });
  assert.deepEqual(userNote({ ...login, shell: { username: "alice.admin", seenIn: "hook" } }), {
    kind: "reported",
    shell: "alice.admin",
  });
  assert.deepEqual(userNote({ ...login, shell: { username: "bob", seenIn: "prompt" }, stopped: true }), {
    kind: "switched",
    shell: "bob",
  });
  assert.deepEqual(userNote({ ...login, stopped: true }), { kind: "stopped" });
  assert.deepEqual(userNote({ ...login, shell: { username: "root", seenIn: "prompt" } }), {
    kind: "prompt",
    shell: "root",
  });
});
