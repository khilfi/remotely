/// <reference types="node" />
// UX-05: the glossary. The terms the 0.5.0 audit found hard to decode each have one plain sentence, and the palette
// finds them by their other names too. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import { GLOSSARY, glossaryEntry, glossaryTerms, isTermKey, type TermKey } from "./glossary.ts";
import { rankItems } from "./search.ts";
import { glossaryItems } from "./search-sources.ts";

const KEYS = Object.keys(GLOSSARY) as TermKey[];

test("the audit's hard terms are all defined", () => {
  for (const key of [
    "tier",
    "low",
    "medium",
    "high",
    "critical",
    "prod",
    "inherited",
    "protected",
    "standingApproval",
    "safetySnapshot",
    "changeId",
    "vaultReauth",
    "typeInAllTabs",
    "compareHosts",
    "pickedTabs",
    "savedGroup",
    "promptHook",
    "filesHere",
    "goldenVm",
    "size",
    "image",
    "launchTemplate",
    "stack",
    "instance",
    "workspace",
    "unassignedVm",
    "snapshotChain",
    "reachability",
    "presentationMode",
    "readOnlyLock",
    "guestOk",
    "hostKey",
    "purge",
    "hashChain",
  ])
    assert.ok(isTermKey(key), key);
  assert.ok(!isTermKey("constructor"), "only the glossary's own keys");
});

test("each definition is one plain sentence", () => {
  for (const key of KEYS) {
    const { term, definition } = glossaryEntry(key);
    assert.match(term, /^[A-Z]/, `${key}: the term starts with a capital`);
    assert.match(definition, /^[A-Z].*\.$/, `${key}: a sentence with a full stop`);
    assert.equal(definition.split(/[.!?] /).length, 1, `${key}: one sentence`);
    assert.ok(definition.length <= 160, `${key}: at most 160 characters`);
    assert.doesNotMatch(definition, /\b(?:VM|SS|BX|AP|MO|FD|QL|CT|CV|UX)-\d{2}\b/, `${key}: no requirement ID`);
  }
  const terms = KEYS.map((k) => glossaryEntry(k).term.toLowerCase());
  assert.equal(new Set(terms).size, terms.length, "no term twice");
});

test("terms are listed A to Z", () => {
  const listed = glossaryTerms().map((t) => t.entry.term);
  assert.deepEqual(
    listed,
    [...listed].sort((a, b) => a.localeCompare(b)),
  );
  assert.equal(listed.length, KEYS.length);
});

test("the palette finds a term by its old name, and choosing it shows the definition", () => {
  const items = glossaryItems(glossaryTerms());
  const multiexec = rankItems("multiexec", items)[0]?.item;
  assert.equal(multiexec?.title, "Type in all tabs");
  assert.deepEqual(multiexec?.target, { define: "typeInAllTabs" });
  assert.equal(rankItems("do not touch", items)[0]?.item.title, "Protected");
  assert.equal(rankItems("golden", items)[0]?.item.title, "Golden VM");
  assert.ok(
    items.every((i) => i.provider === "glossary" && i.detail === glossaryEntry(i.id.slice(5) as TermKey).definition),
  );
});
