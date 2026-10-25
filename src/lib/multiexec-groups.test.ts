/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import type { GroupMember } from "./api.ts";
import {
  draftChanged,
  GROUP_MEMBERS_MAX,
  GROUP_NAME_MAX,
  groupNameProblem,
  groupSummary,
  groupTabs,
  memberNames,
  moveMember,
  saveDraftReason,
  saveGroupReason,
  sessionsOfTabs,
  toggleMember,
  type GroupTab,
} from "./multiexec-groups.ts";

const member = (sessionId: string): GroupMember => ({ sessionId, name: `host-${sessionId}` });
const web = { members: [member("w1"), member("w2"), member("w3")] };

test("a group selects one open tab per session, in tab order, and says which are not open", () => {
  const tabs: GroupTab[] = [
    { key: "t1", sessionId: "db" },
    { key: "t2", sessionId: "w2" },
    { key: "t3", sessionId: null },
    { key: "t4", sessionId: "w1" },
    { key: "t5", sessionId: "w2" },
  ];
  const picked = groupTabs(web, tabs);
  assert.deepEqual(picked.keys, ["t2", "t4"], "w2 open twice: the leftmost tab only");
  assert.deepEqual(
    picked.missing.map((m) => m.sessionId),
    ["w3"],
  );
  assert.deepEqual(groupTabs(web, []), { keys: [], missing: web.members });
  assert.deepEqual(groupTabs({ members: [] }, tabs), { keys: [], missing: [] });
});

test("saving picked tabs keeps each saved session once and counts the quick connections left out", () => {
  const tabs: GroupTab[] = [
    { key: "a", sessionId: "s2" },
    { key: "b", sessionId: null },
    { key: "c", sessionId: "s1" },
    { key: "d", sessionId: "s2" },
  ];
  assert.deepEqual(sessionsOfTabs(tabs), { sessionIds: ["s2", "s1"], quick: 1 });
  const many = Array.from({ length: GROUP_MEMBERS_MAX + 5 }, (_, i) => ({ key: `k${i}`, sessionId: `s${i}` }));
  assert.equal(sessionsOfTabs(many).sessionIds.length, GROUP_MEMBERS_MAX);
});

test("saving picked tabs says why it can't", () => {
  assert.equal(saveGroupReason({ tabs: [], readOnly: null }), "Open a terminal first");
  assert.match(
    saveGroupReason({ tabs: [{ key: "a", sessionId: null }], readOnly: null }) ?? "",
    /quick connections: save them as sessions first/,
  );
  assert.equal(saveGroupReason({ tabs: [{ key: "a", sessionId: "s" }], readOnly: null }), null);
  assert.equal(saveGroupReason({ tabs: [{ key: "a", sessionId: "s" }], readOnly: "Read-only" }), "Read-only");
});

test("the menu says how many of a group's sessions are open", () => {
  assert.equal(groupSummary(web, []), "3 sessions, none open");
  assert.equal(groupSummary(web, [{ key: "a", sessionId: "w1" }]), "3 sessions, 1 open");
  assert.equal(
    groupSummary(
      web,
      ["w1", "w2", "w3"].map((s) => ({ key: s, sessionId: s })),
    ),
    "3 sessions, all open",
  );
  assert.equal(groupSummary({ members: [member("x")] }, []), "1 session, none open");
  assert.equal(groupSummary({ members: [] }, []), "no sessions (deleted)");
  assert.equal(memberNames(web.members), "host-w1, host-w2, host-w3");
  assert.equal(memberNames(web.members, 2), "host-w1, host-w2 and 1 more");
});

test("a group name is checked like the core does", () => {
  const groups = [
    { id: "g1", name: "Web servers" },
    { id: "g2", name: "Databases" },
  ];
  assert.equal(groupNameProblem("  ", groups, null), "Give the group a name");
  assert.equal(groupNameProblem("x".repeat(GROUP_NAME_MAX + 1), groups, null), "At most 60 characters");
  assert.equal(groupNameProblem("é".repeat(GROUP_NAME_MAX), groups, null), null, "characters, not bytes");
  assert.equal(groupNameProblem(" web SERVERS ", groups, null), "There is a group named 'web SERVERS' already");
  assert.equal(groupNameProblem("web SERVERS", groups, "g1"), null, "its own name, in another case");
});

test("the editor's Save says why it is disabled", () => {
  const base = { name: "Web", sessionIds: ["a"], groups: [], self: null, readOnly: null, changed: true };
  assert.equal(saveDraftReason(base), null);
  assert.equal(saveDraftReason({ ...base, readOnly: "Read-only" }), "Read-only");
  assert.equal(saveDraftReason({ ...base, name: "" }), "Give the group a name");
  assert.equal(saveDraftReason({ ...base, sessionIds: [] }), "Pick at least one saved session");
  assert.equal(saveDraftReason({ ...base, changed: false }), "Nothing changed");
});

test("members are added, removed and moved", () => {
  assert.deepEqual(toggleMember(["a", "b"], "c"), ["a", "b", "c"]);
  assert.deepEqual(toggleMember(["a", "b", "c"], "b"), ["a", "c"]);
  assert.deepEqual(moveMember(["a", "b", "c"], 2, -1), ["a", "c", "b"]);
  assert.deepEqual(moveMember(["a", "b", "c"], 0, 1), ["b", "a", "c"]);
  assert.deepEqual(moveMember(["a", "b", "c"], 0, -1), ["a", "b", "c"], "the first stays first");
  assert.deepEqual(moveMember(["a", "b", "c"], 2, 1), ["a", "b", "c"], "the last stays last");
});

test("a draft is compared with the saved group", () => {
  const saved = { name: "Web", members: [member("a"), member("b")] };
  assert.equal(draftChanged({ name: " Web ", sessionIds: ["a", "b"] }, saved), false);
  assert.equal(draftChanged({ name: "Web", sessionIds: ["b", "a"] }, saved), true, "reordered");
  assert.equal(draftChanged({ name: "Webs", sessionIds: ["a", "b"] }, saved), true);
  assert.equal(draftChanged({ name: "Web", sessionIds: ["a"] }, saved), true);
  assert.equal(draftChanged({ name: "Web", sessionIds: ["a"] }, null), true, "a new group");
});
