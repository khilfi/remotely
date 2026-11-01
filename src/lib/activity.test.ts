/// <reference types="node" />
// UX-02, UX-06: the Activity page's event names, grouping and filters. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { AuditEntry, JobSummary } from "./api.ts";
import {
  ACTIVITY_KINDS,
  EVENT_LABELS,
  eventLabel,
  filterEntries,
  filterGroups,
  groupActivity,
  isFiltered,
  kindOfAction,
  kindOfEvent,
  NO_FILTER,
  plainText,
  rangeStart,
  resultLabel,
  resultTone,
  stepsText,
  targetNames,
} from "./activity.ts";

let seq = 0;
function entry(event: string, action: string, ts: string, more: Partial<AuditEntry> = {}): AuditEntry {
  seq += 1;
  return {
    seq,
    id: `e${seq}`,
    ts,
    event,
    action,
    tier: null,
    jobId: null,
    targetsJson: "[]",
    approvalJson: null,
    result: null,
    detail: null,
    prevHash: "",
    hash: "",
    ...more,
  };
}

function job(id: string, summary: string, createdAt: string, more: Partial<JobSummary> = {}): JobSummary {
  return {
    id,
    summary,
    action: "execReadOnly",
    tier: "medium",
    status: "succeeded",
    createdAt,
    startedAt: createdAt,
    finishedAt: createdAt,
    targetsTotal: 2,
    targetsSucceeded: 2,
    targetsFailed: 0,
    targetsUnknown: 0,
    countdownUntil: null,
    retryOf: null,
    bodiesRemoved: false,
    commandRedacted: false,
    changeId: null,
    ...more,
  };
}

const targets = (...names: string[]) =>
  JSON.stringify(
    names.map((name) => ({ target: { kind: "session", sessionId: name }, name, environment: "lab", protected: false })),
  );

test("every event the core writes has plain words, and none is a code", () => {
  const events = [
    "approval_requested",
    "approval_granted",
    "approval_rejected",
    "approval_cancelled",
    "approval_expired",
    "approval_refused",
    "approval_used",
    "job_started",
    "job_finished",
    "job_cancelled",
    "canary_go_on",
    "job_exported",
    "multiexec_exported",
    "host_key_trusted",
    "host_key_retrusted",
    "host_key_changed",
    "host_key_removed",
    "terminal_opened",
    "rdp_opened",
    "terminal_break_sent",
    "vnc_opened",
    "terminal_closed",
    "terminal_output_saved",
    "terminal_output_printed",
    "terminal_log_started",
    "terminal_log_stopped",
    "vault_secret_typed",
    "folder_hook_installed",
    "tunnel_opened",
    "tunnel_closed",
    "file_downloaded",
    "file_uploaded",
    "terminal_rule_changed",
    "vault_changed",
    "vault_unlocked",
    "vault_locked",
    "vault_auth_failed",
    "vault_secret_allowed",
    "workspace_created",
    "workspace_changed",
    "workspace_archived",
    "workspace_restored",
    "workspace_left",
    "workspace_opened",
    "schedule_saved",
    "schedule_paused",
    "schedule_resumed",
    "schedule_deleted",
    "schedule_missed",
    "schedule_skipped",
    "schedule_run",
    "vm_assigned",
    "vm_released",
    "vm_label_changed",
    "vm_console_opened",
    "history_pruned",
    "journal_purged",
    "setting_changed",
    "session_changed",
    "sessions_imported",
    "data_exported",
    "data_imported",
    "audit_exported",
    "alert_acknowledged",
    "alert_rule_changed",
    "check_changed",
    "dashboard_layout_changed",
    "multiexec_group_changed",
    "favourite_changed",
    "catalog_changed",
    "stack_changed",
    "database_set_aside",
  ];
  for (const event of events) {
    assert.ok(EVENT_LABELS[event], `${event} has words`);
    assert.doesNotMatch(eventLabel(event), /_/, event);
    assert.match(eventLabel(event), /^[A-Z]/, `${event} starts with a capital`);
  }
  assert.equal(eventLabel("approval_granted"), "Approved");
  assert.equal(eventLabel("job_started"), "Started");
  assert.equal(eventLabel("job_finished"), "Finished");
  assert.equal(eventLabel("folder_hook_installed"), "Folder tracking set up");
  // The core writes it only for a wrong vault password (command_bus.rs, standing.rs).
  assert.equal(eventLabel("approval_rejected"), "Approval refused: wrong vault password");
  // Something the core adds later still reads as words.
  assert.equal(eventLabel("something_new"), "Something new");
  assert.equal(eventLabel(""), "Event");
});

test("results read as words, in both the jobs' and the schedules' spelling", () => {
  assert.equal(resultLabel("succeeded"), "Succeeded");
  assert.equal(resultLabel("partially_failed"), "Partly failed");
  assert.equal(resultLabel("partiallyFailed"), "Partly failed");
  assert.equal(resultLabel("missed"), "Missed");
  assert.equal(resultLabel("somethingElse"), "Something else");
  assert.equal(resultLabel(null), null);
  assert.equal(resultTone("succeeded"), "ok");
  assert.equal(resultTone("partiallyFailed"), "bad");
  assert.equal(resultTone("cancelled"), "neutral");
});

test("requirement IDs in old audit text stay off the screen", () => {
  assert.equal(plainText("the vault password was asked again (AP" + "-06)"), "the vault password was asked again");
  assert.equal(plainText("FD" + "-14: read-only token for update checks"), "read-only token for update checks");
  assert.equal(plainText("Change CHG-1234 applied"), "Change CHG-1234 applied");
});

test("kinds come from a job's action, or an entry's event", () => {
  assert.equal(kindOfAction("vmStart"), "vms");
  assert.equal(kindOfAction("snapshotRevert"), "snapshots");
  assert.equal(kindOfAction("execDangerous"), "commands");
  assert.equal(kindOfAction("sshKeyPush"), "commands");
  assert.equal(kindOfAction("fileUpload"), "files");
  assert.equal(kindOfAction("tunnelLocal"), "files");
  assert.equal(kindOfAction("containerStop"), "containers");
  assert.equal(kindOfAction("imagePull"), "containers");
  assert.equal(kindOfAction("pruneVolumes"), "containers");
  assert.equal(kindOfAction("imageConvert"), "vms");
  assert.equal(kindOfAction("appUpdate"), "app");
  assert.equal(kindOfAction("wakeOnLan"), "sessions");
  assert.equal(kindOfEvent("host_key_trusted"), "sessions");
  assert.equal(kindOfEvent("folder_hook_installed"), "sessions");
  assert.equal(kindOfEvent("session_changed"), "sessions");
  assert.equal(kindOfEvent("tunnel_opened"), "files");
  assert.equal(kindOfEvent("vault_unlocked"), "vault");
  assert.equal(kindOfEvent("schedule_run"), "schedules");
  assert.equal(kindOfEvent("vm_label_changed"), "vms");
  assert.equal(kindOfEvent("setting_changed"), "app");
  assert.equal(kindOfEvent("workspace_opened"), "app");
  assert.ok(ACTIVITY_KINDS.every((k) => k.label.length > 0));
});

test("target names come from the entry's targets, and bad JSON gives none", () => {
  assert.deepEqual(targetNames(targets("dev-host-01", "dev-host-02")), ["dev-host-01", "dev-host-02"]);
  assert.deepEqual(targetNames("not json"), []);
  assert.deepEqual(targetNames('{"name":"x"}'), []);
  assert.deepEqual(targetNames('[{"name":""},{"other":1}]'), []);
});

test("a job's entries and its approval fold into one row, newest job first", () => {
  const line = "Type in all tabs: run `uptime` in 2 terminals";
  const jobs = [job("j1", line, "2026-10-30T01:58:08Z")];
  const audit = [
    entry("session_changed", "Marked 'dev-host-01' as a container host", "2026-10-30T01:50:00Z"),
    entry("approval_requested", line, "2026-10-30T01:57:52Z", { tier: "medium", targetsJson: targets("dev-host-01") }),
    entry("approval_granted", line, "2026-10-30T01:58:08Z", { tier: "medium" }),
    entry("job_started", line, "2026-10-30T01:58:08Z", {
      jobId: "j1",
      tier: "medium",
      targetsJson: targets("dev-host-02"),
    }),
    entry("job_finished", line, "2026-10-30T01:58:09Z", { jobId: "j1", tier: "medium", result: "succeeded" }),
    entry(
      "folder_hook_installed",
      "Typed the folder prompt hook into the shell of 'dev-host-02'",
      "2026-10-30T02:00:00Z",
    ),
  ];
  const groups = groupActivity(jobs, audit);
  assert.equal(groups.length, 3, "one row for the job, one for each entry of no job");
  assert.equal(groups[0].entries[0].event, "folder_hook_installed", "newest first");
  const row = groups[1];
  assert.equal(row.jobId, "j1");
  assert.equal(row.job?.id, "j1");
  assert.deepEqual(
    row.entries.map((e) => e.event),
    ["approval_requested", "approval_granted", "job_started", "job_finished"],
    "oldest first, the approval before the job",
  );
  assert.equal(row.at, "2026-10-30T01:57:52Z", "it began when the approval was asked");
  assert.equal(row.result, "succeeded");
  assert.deepEqual(row.targets, ["dev-host-01", "dev-host-02"]);
  assert.equal(row.kind, "commands");
  assert.equal(groups[2].title, "Marked 'dev-host-01' as a container host");
  assert.equal(groups[2].kind, "sessions");
});

test("a cancelled approval stays a row of its own, and the next job doesn't take it", () => {
  const line = "Shut down db-01";
  const audit = [
    entry("approval_requested", line, "2026-10-30T01:00:00Z"),
    entry("approval_cancelled", line, "2026-10-30T01:00:10Z"),
    entry("approval_requested", line, "2026-10-30T01:01:00Z"),
    entry("approval_granted", line, "2026-10-30T01:01:05Z"),
    entry("job_started", line, "2026-10-30T01:01:15Z", { jobId: "j2" }),
    entry("job_finished", line, "2026-10-30T01:01:30Z", { jobId: "j2", result: "failed" }),
  ];
  const groups = groupActivity([], audit);
  assert.equal(groups.length, 2);
  assert.deepEqual(
    groups[0].entries.map((e) => e.event),
    ["approval_requested", "approval_granted", "job_started", "job_finished"],
  );
  assert.equal(groups[0].job, null, "a job older than the jobs list still groups its entries");
  assert.equal(groups[0].result, "failed");
  assert.deepEqual(
    groups[1].entries.map((e) => e.event),
    ["approval_requested", "approval_cancelled"],
  );
});

test("an approval granted long before a job of the same words isn't folded under it", () => {
  const line = "Restart web-01";
  const audit = [
    entry("approval_requested", line, "2026-10-30T01:00:00Z"),
    entry("approval_granted", line, "2026-10-30T01:00:05Z"),
    entry("job_started", line, "2026-10-30T03:00:00Z", { jobId: "j3" }),
  ];
  const groups = groupActivity([], audit);
  assert.equal(groups.length, 2);
  assert.equal(groups[0].jobId, "j3");
  assert.equal(groups[0].entries.length, 1);
});

test("two jobs of the same words each take their own approval", () => {
  const line = "Type in all tabs: run `ls` in 2 terminals";
  const audit = [
    entry("approval_requested", line, "2026-10-30T01:00:00Z"),
    entry("approval_granted", line, "2026-10-30T01:00:01Z"),
    entry("job_started", line, "2026-10-30T01:00:01Z", { jobId: "a" }),
    entry("job_finished", line, "2026-10-30T01:00:02Z", { jobId: "a", result: "succeeded" }),
    entry("approval_requested", line, "2026-10-30T01:00:10Z"),
    entry("approval_granted", line, "2026-10-30T01:00:11Z"),
    entry("job_started", line, "2026-10-30T01:00:11Z", { jobId: "b" }),
  ];
  const groups = groupActivity([], audit);
  assert.equal(groups.length, 2);
  assert.deepEqual(
    groups.map((g) => [g.jobId, g.entries.length]),
    [
      ["b", 3],
      ["a", 4],
    ],
  );
});

test("a job in the jobs list with no entries read yet is still a row", () => {
  const groups = groupActivity([job("j9", "Start db-01", "2026-10-30T05:00:00Z", { action: "vmStart" })], []);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].kind, "vms");
  assert.equal(groups[0].entries.length, 0);
});

test("filters keep rows by target or action words, kind and date", () => {
  const now = Date.parse("2026-10-30T12:00:00Z");
  const jobs = [
    job("j1", "Shut down db-01", "2026-10-30T10:00:00Z", { action: "vmStopSoft" }),
    job("j2", "Run `uptime` on 2 hosts", "2026-10-20T10:00:00Z"),
  ];
  const audit = [
    entry("job_started", "Shut down db-01", "2026-10-30T10:00:01Z", { jobId: "j1", targetsJson: targets("db-01") }),
    entry("job_started", "Run `uptime` on 2 hosts", "2026-10-20T10:00:01Z", {
      jobId: "j2",
      targetsJson: targets("web-01", "web-02"),
    }),
    entry("vault_unlocked", "Unlocked the vault", "2026-09-01T10:00:00Z"),
  ];
  const groups = groupActivity(jobs, audit);
  assert.equal(filterGroups(groups, NO_FILTER, now).length, 3);
  assert.deepEqual(
    filterGroups(groups, { ...NO_FILTER, text: "web-02" }, now).map((g) => g.jobId),
    ["j2"],
    "a target's name",
  );
  assert.deepEqual(
    filterGroups(groups, { ...NO_FILTER, text: "shut DB" }, now).map((g) => g.jobId),
    ["j1"],
    "every word, any case",
  );
  assert.deepEqual(
    filterGroups(groups, { ...NO_FILTER, kind: "vault" }, now).map((g) => g.title),
    ["Unlocked the vault"],
  );
  assert.deepEqual(
    filterGroups(groups, { ...NO_FILTER, range: "7d" }, now).map((g) => g.jobId),
    ["j1"],
  );
  assert.equal(filterGroups(groups, { ...NO_FILTER, range: "30d" }, now).length, 2);
  assert.equal(isFiltered(NO_FILTER), false);
  assert.equal(isFiltered({ ...NO_FILTER, text: " " }), false);
  assert.equal(isFiltered({ ...NO_FILTER, kind: "vms" }), true);

  assert.deepEqual(
    filterEntries(audit, jobs, { ...NO_FILTER, kind: "commands" }, now).map((e) => e.jobId),
    ["j2"],
  );
  assert.deepEqual(
    filterEntries(audit, jobs, { ...NO_FILTER, text: "unlocked" }, now).map((e) => e.event),
    ["vault_unlocked"],
    "the plain event name matches too",
  );
});

test("today starts at local midnight; any time has no start", () => {
  const now = new Date(2026, 9, 30, 15, 30).getTime();
  assert.equal(rangeStart("today", now), new Date(2026, 9, 30, 0, 0).getTime());
  assert.equal(rangeStart("all", now), null);
  assert.equal(rangeStart("7d", now), now - 7 * 24 * 60 * 60 * 1000);
});

test("steps read in words", () => {
  assert.equal(stepsText(1), "1 step");
  assert.equal(stepsText(4), "4 steps");
});
