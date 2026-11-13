import { test } from "node:test";
import assert from "node:assert/strict";
import {
  baseName,
  changeLabel,
  folderProblem,
  modeOctal,
  modeText,
  nameProblem,
  parseId,
  parseMode,
  replaces,
} from "./file-ops.ts";

test("names are one plain part, as the core takes them", () => {
  assert.equal(nameProblem("notes 2026.txt"), null);
  assert.equal(nameProblem("отчёт.pdf"), null);
  for (const bad of ["", ".", "..", "a/b", "tab\there", "x‮txt.exe", "zero​width", "a".repeat(256)]) {
    assert.notEqual(nameProblem(bad), null, JSON.stringify(bad));
  }
  assert.notEqual(nameProblem("é".repeat(128)), null, "256 bytes");
});

test("folders to go into are full paths without dot parts", () => {
  assert.equal(folderProblem("/srv/www"), null);
  assert.equal(folderProblem("/"), null);
  assert.notEqual(folderProblem("srv"), null);
  assert.notEqual(folderProblem("/srv/../etc"), null);
  assert.notEqual(folderProblem("/srv//www"), null);
  assert.notEqual(folderProblem("/srv/"), null);
});

test("modes read and print as ls and chmod do", () => {
  assert.equal(modeText(0o644), "rw-r--r--");
  assert.equal(modeText(0o755), "rwxr-xr-x");
  assert.equal(modeText(0o4755), "rwsr-xr-x");
  assert.equal(modeText(0o2644), "rw-r-Sr--");
  assert.equal(modeText(0o1777), "rwxrwxrwt");
  assert.equal(parseMode("644"), 0o644);
  assert.equal(parseMode("0755"), 0o755);
  assert.equal(parseMode("4755"), 0o4755);
  for (const bad of ["", "8", "64", "rwx", "77777", "-644"]) assert.equal(parseMode(bad), null, bad);
  assert.equal(modeOctal(0o644), "0644");
});

test("owner and group numbers", () => {
  assert.equal(parseId(""), null);
  assert.equal(parseId("33"), 33);
  assert.equal(parseId("www-data"), "bad");
  assert.equal(parseId("99999999999"), "bad");
});

test("each change says what it did in a few words", () => {
  assert.equal(baseName("/srv/www/a.html"), "a.html");
  assert.equal(changeLabel({ kind: "rename", path: "/srv/a", name: "b" }), "Renamed 'a' to 'b'");
  assert.equal(changeLabel({ kind: "delete", paths: ["/a", "/b"] }), "Deleted 2 items");
  assert.equal(changeLabel({ kind: "move", paths: ["/a"], into: "/tmp" }), "Moved 'a' to /tmp");
  assert.ok(replaces("replace") && replaces("replaceIfNewer"));
  assert.ok(!replaces("keepBoth") && !replaces("skip"));
});
