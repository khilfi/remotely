/// <reference types="node" />
// MO-07: alerts in words, the rule editor's checks and the grouped notification. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  cleanRuleInput,
  conditionText,
  durationText,
  newRuleInput,
  notificationText,
  ruleProblem,
  scopeAllows,
  scopeOfKind,
  scopeText,
  sortAlerts,
  unacknowledged,
} from "./alerts.ts";
import type { Alert } from "./dashboard-api.ts";

function alert(over: Partial<Alert> = {}): Alert {
  return {
    id: "a",
    ruleId: "r",
    ruleName: "CPU",
    metric: "cpu",
    severity: "warning",
    target: { kind: "vm", key: "C:\\VMs\\web\\web.vmx", name: "web" },
    threshold: 90,
    forSecs: 300,
    value: 97,
    peak: 97,
    message: "CPU at 97%, above 90% for 5 minutes",
    firedAt: "2026-10-25T08:00:00Z",
    resolvedAt: null,
    resolution: null,
    acknowledgedAt: null,
    ...over,
  };
}

test("a rule's condition and duration read as words", () => {
  assert.equal(conditionText({ metric: "cpu", threshold: 90, forSecs: 300 }), "CPU above 90% for 5 minutes");
  assert.equal(conditionText({ metric: "disk", threshold: 85, forSecs: 0 }), "Disk above 85%");
  assert.equal(conditionText({ metric: "swap", threshold: 2.5, forSecs: 90 }), "Swap above 2.5% for 90 seconds");
  assert.equal(conditionText({ metric: "unreachable", threshold: null, forSecs: 3600 }), "Unreachable for 1 hour");
  assert.equal(conditionText({ metric: "stopped", threshold: null, forSecs: 0 }), "Stopped without a Remotely action");
  assert.equal(durationText(0), "at once");
  assert.equal(durationText(60), "1 minute");
  assert.equal(
    scopeText({ kind: "vm", key: "k" }, { vm: () => "web" }),
    "the VM web",
    "named when the caller knows it",
  );
  assert.equal(scopeText({ kind: "tag", tag: "builds" }), "everything tagged builds");
});

test("the editor refuses what the core would, with the same reasons", () => {
  const ok = { ...newRuleInput(), name: "Busy VMs" };
  assert.equal(ruleProblem(ok), null);
  assert.match(ruleProblem({ ...ok, name: "  " }) ?? "", /name/);
  assert.match(ruleProblem({ ...ok, threshold: 100 }) ?? "", /threshold/);
  assert.match(ruleProblem({ ...ok, threshold: null }) ?? "", /threshold/);
  assert.match(ruleProblem({ ...ok, metric: "disk", scope: { kind: "thisPc" } }) ?? "", /this PC/);
  assert.match(ruleProblem({ ...ok, metric: "stopped", scope: { kind: "allHosts" } }) ?? "", /watched host/);
  assert.match(ruleProblem({ ...ok, scope: { kind: "vm", key: "" } }) ?? "", /VM/);
  assert.match(ruleProblem({ ...ok, scope: { kind: "host", sessionId: "" } }) ?? "", /host/);
  assert.equal(ruleProblem({ ...ok, metric: "unreachable", threshold: null, scope: { kind: "allHosts" } }), null);
  assert.equal(cleanRuleInput({ ...ok, metric: "stopped", name: " x " }).threshold, null);
  assert.equal(cleanRuleInput({ ...ok, name: " x " }).name, "x");
  assert.equal(scopeAllows("thisPc", "swap"), true);
  assert.equal(scopeAllows("tag", "stopped"), true);
  // Changing the scope's kind starts its key afresh; the same kind keeps it.
  assert.deepEqual(scopeOfKind("tag", { kind: "vm", key: "k" }), { kind: "tag", tag: "" });
  assert.deepEqual(scopeOfKind("vm", { kind: "vm", key: "k" }), { kind: "vm", key: "k" });
});

test("the list shows open alerts first, critical ones on top", () => {
  const sorted = sortAlerts([
    alert({ id: "old", resolvedAt: "2026-10-25T09:00:00Z", firedAt: "2026-10-25T08:30:00Z" }),
    alert({ id: "warn", firedAt: "2026-10-25T08:00:00Z" }),
    alert({ id: "crit", severity: "critical", firedAt: "2026-10-25T07:00:00Z" }),
    alert({ id: "new", firedAt: "2026-10-25T08:10:00Z" }),
  ]);
  assert.deepEqual(
    sorted.map((a) => a.id),
    ["crit", "new", "warn", "old"],
  );
  assert.deepEqual(
    unacknowledged([
      alert({ id: "x", acknowledgedAt: "t" }),
      alert({ id: "y" }),
      alert({ id: "z", resolvedAt: "t" }),
    ]).map((a) => a.id),
    ["y"],
  );
});

test("a round's alerts make one notification", () => {
  assert.equal(notificationText([]), null);
  assert.deepEqual(notificationText([alert()]), {
    title: "Warning: web",
    body: "CPU at 97%, above 90% for 5 minutes",
  });
  const many = ["a", "b", "c", "d", "e"].map((name, i) =>
    alert({ id: name, target: { kind: "vm", key: name, name }, severity: i === 4 ? "critical" : "warning" }),
  );
  const text = notificationText(many);
  assert.equal(text?.title, "5 alerts, some critical");
  assert.equal(text?.body.split("\n").length, 4);
  assert.match(text?.body ?? "", /^a: CPU at 97%/);
  assert.match(text?.body ?? "", /and 2 more$/);
});

test("MO-08: rules on checks have their own scopes, units and words", () => {
  assert.equal(scopeAllows("allChecks", "checkDown"), true);
  assert.equal(scopeAllows("allChecks", "cpu"), false);
  assert.equal(scopeAllows("allVms", "certExpiring"), false);
  assert.equal(scopeAllows("check", "checkSlow"), true);
  const slow = { ...newRuleInput(), name: "slow", metric: "checkSlow" as const, scope: { kind: "allChecks" as const } };
  assert.equal(ruleProblem({ ...slow, threshold: 500 }), null);
  assert.match(ruleProblem({ ...slow, threshold: 0 })!, /600,000 ms/);
  const expiring = { ...slow, metric: "certExpiring" as const, threshold: 400 };
  assert.match(ruleProblem(expiring)!, /1 to 365/);
  assert.equal(ruleProblem({ ...expiring, threshold: 14 }), null);
  assert.match(ruleProblem({ ...slow, scope: { kind: "check" as const, checkId: "" }, threshold: 500 })!, /check/);
  assert.equal(conditionText({ metric: "checkDown", threshold: null, forSecs: 0 }), "Down");
  assert.equal(
    conditionText({ metric: "checkSlow", threshold: 500, forSecs: 60 }),
    "Check slow above 500 ms for 1 minute",
  );
  assert.equal(
    conditionText({ metric: "certExpiring", threshold: 14, forSecs: 0 }),
    "Certificate expiring in under 14 days",
  );
  assert.equal(scopeText({ kind: "check", checkId: "c1" }, { check: () => "web" }), "the check web");
  assert.equal(scopeOfKind("check", { kind: "allVms" }).kind, "check");
  assert.equal(cleanRuleInput({ ...slow, metric: "checkDown", threshold: 5 }).threshold, null);
});
