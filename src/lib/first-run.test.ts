/// <reference types="node" />
// QL-23 first-run wizard: when it offers itself, what each step shows as done, and moving between steps.
// Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  FIRST_RUN_STEPS,
  SETUP_STEPS,
  stepButtons,
  stepsIntro,
  nextStep,
  onFirstRunRequest,
  previousStep,
  requestFirstRun,
  shouldOfferFirstRun,
  stepMark,
  type FirstRunFacts,
} from "./first-run.ts";

const fresh: FirstRunFacts = {
  vaultStatus: "notSetUp",
  sessionCount: 0,
  vmrunFound: false,
  vboxmanageFound: false,
  scanFolders: 0,
};

test("it offers itself with no vault and no session, until it was finished or skipped", () => {
  assert.ok(shouldOfferFirstRun(fresh, false));
  assert.ok(!shouldOfferFirstRun(fresh, true), "skipped or finished on this machine");
  assert.ok(!shouldOfferFirstRun({ ...fresh, vaultStatus: "locked" }, false));
  assert.ok(!shouldOfferFirstRun({ ...fresh, sessionCount: 3 }, false));
  assert.ok(!shouldOfferFirstRun({ ...fresh, sessionCount: null }, false), "not before the sessions are known");
  assert.ok(!shouldOfferFirstRun({ ...fresh, vaultStatus: null }, false));
});

test("each step shows what is done already", () => {
  assert.equal(stepMark("hypervisors", fresh), "todo");
  assert.equal(stepMark("hypervisors", { ...fresh, vboxmanageFound: true }), "done", "either one is enough");
  assert.equal(stepMark("vault", fresh), "todo");
  assert.equal(stepMark("vault", { ...fresh, vaultStatus: "locked" }), "done");
  assert.equal(stepMark("folders", fresh), "optional");
  assert.equal(stepMark("folders", { ...fresh, scanFolders: 1 }), "done");
  assert.equal(stepMark("sessions", { ...fresh, sessionCount: 2 }), "done");
});

test("the steps go in order: hypervisors, vault, folders, sessions, done", () => {
  assert.deepEqual(
    FIRST_RUN_STEPS.map((s) => s.id),
    ["hypervisors", "vault", "folders", "sessions", "done"],
  );
  assert.equal(nextStep("hypervisors"), "vault");
  assert.equal(nextStep("done"), "done");
  assert.equal(previousStep("vault"), "hypervisors");
  assert.equal(previousStep("hypervisors"), "hypervisors");
});

test("Settings and the palette open it again", () => {
  let opened = 0;
  const stop = onFirstRunRequest(() => (opened += 1));
  requestFirstRun();
  stop();
  requestFirstRun();
  assert.equal(opened, 1);
});

test("UX-07: the intro counts the steps it lists, and the last one shows only Finish", () => {
  assert.equal(SETUP_STEPS.length, FIRST_RUN_STEPS.length - 1);
  assert.ok(!SETUP_STEPS.some((s) => s.id === "done"));
  assert.match(stepsIntro(), /^Four steps/);
  assert.deepEqual(stepButtons("done"), { skip: false, back: false, next: false, finish: true });
  assert.deepEqual(stepButtons("hypervisors"), { skip: true, back: false, next: true, finish: false });
  assert.deepEqual(stepButtons("vault"), { skip: true, back: true, next: true, finish: false });
});
