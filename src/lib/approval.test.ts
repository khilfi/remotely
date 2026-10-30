/// <reference types="node" />
// UX-11 (AP-03, AP-08): the approval dialog's summary line, type to confirm, and the one reason or change ID field.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ApprovalRequest, ApprovalStep, Target } from "./api.ts";
import {
  approvalProblem,
  confirmLabel,
  confirmMatches,
  confirmPhrase,
  findChangeId,
  plainReason,
  reasonAnswers,
  reasonField,
  targetsLine,
  tierLine,
  typedCount,
} from "./approval.ts";

const vm = (name: string, environment: Target["environment"] = "lab"): Target => ({
  target: { kind: "vm", vmxPath: `C:\\VMs\\${name}\\${name}.vmx` },
  name,
  environment,
  protected: false,
});

const HIGH: ApprovalStep[] = [
  { step: "impactPreview" },
  { step: "safetySnapshot", defaultOn: true },
  { step: "typeTargetCount", expected: 1 },
  { step: "reason" },
  { step: "changeId", required: false },
  { step: "countdown", seconds: 10 },
];
const required = (steps: ApprovalStep[]): ApprovalStep[] =>
  steps.map((s) => (s.step === "changeId" ? { step: "changeId", required: true } : s));

function request(change: Partial<ApprovalRequest>): ApprovalRequest {
  return {
    id: "r1",
    action: "vmStopSoft",
    tier: "high",
    summary: "Shut down 1 VM",
    steps: HIGH,
    targets: [vm("db-01", "prod")],
    skipped: [],
    reasons: ["Shut down VMs on 1 target: medium", "a target is labelled Prod: medium -> high"],
    warnings: [],
    impact: [],
    exec: null,
    upload: null,
    tunnel: null,
    deploy: null,
    vmChange: null,
    ...change,
  };
}

test("the targets read as a short list", () => {
  assert.equal(targetsLine([]), "");
  assert.equal(targetsLine([vm("db-01")]), "db-01");
  assert.equal(targetsLine([vm("db-01"), vm("web-01")]), "db-01 and web-01");
  assert.equal(targetsLine([vm("a"), vm("b"), vm("c")]), "a, b and c");
  assert.equal(targetsLine([vm("a"), vm("b"), vm("c"), vm("d"), vm("e")]), "a, b and 3 more");
});

test("the tier line names the one plain reason: Prod first", () => {
  assert.equal(tierLine(request({})), "High: db-01 is Prod");
  assert.equal(
    tierLine(request({ targets: [vm("db-01", "prod"), vm("db-02", "prod"), vm("web-01")] })),
    "High: 2 targets are Prod",
  );
  // A Prod target the rules didn't raise for (the Prod rule off): not the reason.
  assert.equal(
    tierLine(request({ tier: "critical", reasons: ["Power off VMs (hard) on 1 target: critical"] })),
    "Critical: set in the approval rules",
  );
});

test("the tier line says when a command matched a dangerous-command rule, or the bulk tier applied", () => {
  const exec = {
    dangerous: [{ rule: "Recursive delete", line: 1, text: "rm -rf /tmp/x" }],
  } as unknown as ApprovalRequest["exec"];
  assert.equal(
    tierLine(request({ targets: [vm("web-01")], reasons: ["Run a command on 1 target: high"], exec })),
    "High: the command matches the dangerous-command rule “Recursive delete”",
  );
  assert.equal(
    tierLine(
      request({
        targets: [vm("a"), vm("b"), vm("c"), vm("d"), vm("e")],
        reasons: ["Run a command on 5 targets: high", "5 or more hosts: the bulk tier for commands on hosts applies"],
      }),
    ),
    "High: 5 targets at once get the bulk tier",
  );
});

test("the core's reasons read in plain words for Why?", () => {
  assert.equal(plainReason("a target is labelled Prod: medium -> high"), "A target is labelled Prod: Medium → High");
  assert.equal(plainReason("Shut down VMs on 1 target: medium"), "Shut down VMs on 1 target: Medium");
  assert.equal(plainReason("1 protected target(s) skipped"), "1 protected target(s) skipped");
  // Tier words elsewhere in a sentence are left alone.
  assert.equal(plainReason("a high number of hosts"), "A high number of hosts");
});

test("one target asks for its name; several, or presenting, ask for the count", () => {
  const one = confirmPhrase(request({}), false);
  assert.deepEqual(one, { kind: "name", expected: "db-01", count: 1 });
  assert.equal(confirmLabel(one!), "Type the name to confirm");
  assert.ok(confirmMatches(one!, "db-01"));
  assert.ok(confirmMatches(one!, "  DB-01 "));
  assert.ok(!confirmMatches(one!, "1"));
  assert.ok(!confirmMatches(one!, "db-0"));
  assert.equal(typedCount(one!, "db-01"), 1);
  assert.equal(typedCount(one!, "db-0"), undefined);

  // Presenting: the name may be masked on screen, so the count is asked.
  assert.deepEqual(confirmPhrase(request({}), true), { kind: "count", expected: 1, count: 1 });

  const three = confirmPhrase(
    request({
      steps: HIGH.map((s) => (s.step === "typeTargetCount" ? { step: "typeTargetCount", expected: 3 } : s)),
      targets: [vm("a"), vm("b"), vm("c")],
    }),
    false,
  );
  assert.deepEqual(three, { kind: "count", expected: 3, count: 3 });
  assert.equal(confirmLabel(three!), "Type the number of targets (3) to confirm");
  assert.ok(confirmMatches(three!, "3"));
  assert.ok(!confirmMatches(three!, ""));
  assert.ok(!confirmMatches(three!, "2"));
  assert.equal(typedCount(three!, "3"), 3);
  assert.equal(typedCount(three!, "2"), 2);
});

test("a name too long or with control characters asks for the count", () => {
  assert.equal(confirmPhrase(request({ targets: [vm("x".repeat(61))] }), false)?.kind, "count");
  assert.equal(confirmPhrase(request({ targets: [vm("a\u0007b")] }), false)?.kind, "count");
  assert.equal(confirmPhrase(request({ targets: [vm("   ")] }), false)?.kind, "count");
  // Medium asks for nothing to type.
  assert.equal(confirmPhrase(request({ steps: [{ step: "confirm" }] }), false), null);
});

test("the change ID is the ticket or change number the text starts with", () => {
  assert.equal(findChangeId("CHG0012345"), "CHG0012345");
  assert.equal(findChangeId("  CHG0012345 restart DB01"), "CHG0012345");
  assert.equal(findChangeId("INC-42: reboot"), "INC-42");
  assert.equal(findChangeId("#1234, see the ticket"), "#1234");
  assert.equal(findChangeId("4711823 patch"), "4711823");
  assert.equal(findChangeId("(RITM_0042) rollback"), "RITM_0042");
  // Anywhere else in the text it is part of the reason only.
  assert.equal(findChangeId("patch window, CHG0012345."), null);
  assert.equal(findChangeId("rollback of INC-42"), null);
  // Product and host names are not change IDs.
  assert.equal(findChangeId("Patch RHEL9 kernel"), null);
  assert.equal(findChangeId("Upgrade SQL2019"), null);
  assert.equal(findChangeId("Enable TLS13"), null);
  assert.equal(findChangeId("restart db01 and web-01"), null);
  assert.equal(findChangeId("Q4 2026 rollout"), null);
  assert.equal(findChangeId("patching"), null);
  assert.equal(findChangeId(""), null);
  assert.equal(findChangeId(`CHG${"1".repeat(70)}`), null);
});

test("a target's name is never the change ID, whatever its case", () => {
  assert.equal(findChangeId("Restart DB01", ["DB01"]), null);
  assert.equal(findChangeId("DB01 restart", ["db01"]), null);
  assert.equal(findChangeId("SRV42 reboot", ["web-01", " srv42 "]), null);
  assert.equal(findChangeId("CHG0012345 restart DB01", ["DB01"]), "CHG0012345");
  assert.equal(findChangeId("CHG0012345 restart", ["web-01"]), "CHG0012345");
});

test("the field's label follows the steps and the workspace's rule", () => {
  assert.equal(reasonField(HIGH).label, "Reason or change ID");
  assert.equal(reasonField(HIGH).changeIdRequired, false);
  assert.equal(reasonField(required(HIGH)).label, "Change ID and reason");
  assert.equal(reasonField(required(HIGH)).changeIdRequired, true);
  assert.equal(reasonField([{ step: "reason" }]).label, "Reason");
  assert.equal(reasonField([{ step: "changeId", required: false }]).label, "Change ID (optional)");
  assert.equal(reasonField([{ step: "confirm" }]).shown, false);
});

test("the whole text is the reason; the ticket number it starts with is the change ID", () => {
  assert.deepEqual(reasonAnswers(HIGH, "  CHG0012345 patch window "), {
    reason: "CHG0012345 patch window",
    changeId: "CHG0012345",
  });
  assert.deepEqual(reasonAnswers(HIGH, "disk full on db01"), { reason: "disk full on db01" });
  assert.deepEqual(reasonAnswers(HIGH, "Patch RHEL9 kernel"), { reason: "Patch RHEL9 kernel" });
  assert.deepEqual(reasonAnswers(HIGH, "DB01 restart", ["DB01"]), { reason: "DB01 restart" });
  assert.deepEqual(reasonAnswers(HIGH, ""), { reason: "" });
  // Without a reason step the field is the change ID alone.
  assert.deepEqual(reasonAnswers([{ step: "changeId", required: false }], " my-ticket "), { changeId: "my-ticket" });
  assert.deepEqual(reasonAnswers([{ step: "confirm" }], "anything"), {});
});

test("Approve says what is missing, in the order the dialog asks", () => {
  const phrase = confirmPhrase(request({}), false);
  const base = { steps: HIGH, phrase, typed: "db-01", text: "patch", password: "", busy: false };
  assert.equal(approvalProblem(base), null);
  assert.equal(approvalProblem({ ...base, typed: "1" }), "Type db-01 to confirm first");
  assert.equal(approvalProblem({ ...base, text: " " }), "Give a reason or change ID first");
  assert.equal(
    approvalProblem({ ...base, steps: [{ step: "reason" }], phrase: null, text: "" }),
    "Give a reason first",
  );
  assert.equal(approvalProblem({ ...base, busy: true }), "Checking the answers…");

  // AP-08: the workspace requires a change ID for Prod: a reason alone isn't enough.
  const strict = { ...base, steps: required(HIGH) };
  assert.match(approvalProblem(strict) ?? "", /needs one for Prod/);
  assert.equal(approvalProblem({ ...strict, text: "CHG0012345 patch" }), null);
  // A product or host name at the start doesn't satisfy the rule, nor does a ticket number further on.
  assert.match(approvalProblem({ ...strict, text: "Patch RHEL9 kernel" }) ?? "", /needs one for Prod/);
  assert.match(approvalProblem({ ...strict, text: "DB01 restart", targetNames: ["DB01"] }) ?? "", /needs one/);
  assert.match(approvalProblem({ ...strict, text: "restart, CHG0012345" }) ?? "", /needs one for Prod/);
  assert.equal(approvalProblem({ ...strict, text: "CHG0012345 restart DB01", targetNames: ["DB01"] }), null);

  // AP-06: Critical asks for the vault password.
  const critical = { ...base, steps: [...HIGH, { step: "vaultReauth" } as ApprovalStep] };
  assert.equal(approvalProblem(critical), "Type the vault password first");
  assert.equal(approvalProblem({ ...critical, password: "x" }), null);

  // The count, for several targets.
  const count = { ...base, phrase: { kind: "count" as const, expected: 3, count: 3 }, typed: "2" };
  assert.equal(approvalProblem(count), "Type the number of targets (3) first");
  assert.equal(approvalProblem({ ...count, typed: "3" }), null);
});

test("a change ID typed alone is checked for length", () => {
  const steps: ApprovalStep[] = [{ step: "changeId", required: false }];
  const base = { steps, phrase: null, typed: "", password: "", busy: false };
  assert.equal(approvalProblem({ ...base, text: "x".repeat(64) }), null);
  assert.match(approvalProblem({ ...base, text: "x".repeat(65) }) ?? "", /at most 64/);
});
