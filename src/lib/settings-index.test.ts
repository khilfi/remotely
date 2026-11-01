/// <reference types="node" />
// UX-10: the Settings page's side list and search. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  groupSections,
  groupTitle,
  searchCards,
  searchSettings,
  sectionCard,
  SETTINGS_GROUPS,
  SETTINGS_SECTIONS,
  settingsSection,
} from "./settings-index.ts";

test("every group has sections, and every section a group of the side list", () => {
  const groups = SETTINGS_GROUPS.map((g) => g.id);
  for (const g of groups) assert.ok(groupSections(g).length > 0, g);
  for (const s of SETTINGS_SECTIONS) assert.ok(groups.includes(s.group), s.id);
  assert.equal(groupTitle("tools"), "Tools and VMs");
});

test("a row of another card names a card that is a section of the same group", () => {
  for (const s of SETTINGS_SECTIONS) {
    if (!s.card) continue;
    const card = settingsSection(s.card);
    assert.ok(card === undefined || card.group === s.group, s.id);
  }
  assert.equal(sectionCard(settingsSection("vmware")!), "tools");
  assert.equal(sectionCard(settingsSection("change-ids")!), "rules");
  assert.equal(sectionCard(settingsSection("power")!), "power");
});

test("the search finds a setting by its name, a word it covers or its group", () => {
  const ids = (q: string) => searchSettings(q).map((s) => s.id);
  assert.deepEqual(ids(""), []);
  assert.deepEqual(ids("   "), []);
  assert.deepEqual(ids("vmrun"), ["vmware"]);
  assert.deepEqual(ids("idle lock"), ["vault"]);
  assert.deepEqual(ids("DENS"), ["appearance"]);
  assert.ok(ids("prompt hook").includes("terminal"));
  assert.ok(ids("change").includes("change-ids"));
  // Every word must match.
  assert.deepEqual(ids("vmrun density"), []);
  // A group's name finds its sections.
  assert.deepEqual(ids("dashboard"), ["dashboard", "history"]);
  assert.deepEqual(ids("nothing-like-this"), []);
});

test("search results show each card once, with the rows that matched", () => {
  const cards = searchCards("path");
  assert.deepEqual(cards, [
    { card: "tools", group: "tools", sections: ["vmware", "virtualbox", "qemu-img", "docker", "vnc-viewer"] },
  ]);
  assert.deepEqual(searchCards("prod"), [{ card: "rules", group: "approvals", sections: ["rules", "change-ids"] }]);
});
