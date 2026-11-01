// UX-02, UX-06: the Activity page as pure functions (tested in activity.test.ts). Jobs and the audit log become one
// list: each job is one row with its audit entries folded under it (approval asked, approved, started, finished), and
// an entry of no job (a session edited, a host key trusted) is a row of its own. Event codes show as plain words, and
// the list filters by target or action text, by kind and by date. The audit log view shows the same entries one by one.
//
// The core writes an approval's entries without a job id (the job doesn't exist until it is approved), so an approval
// is folded under the job that follows it with the same action text within the approval's life (15 minutes, the
// core's APPROVAL_TTL). One that was cancelled, expired or refused stays a row of its own.

import type { AuditEntry, JobStatus, JobSummary, Tier } from "./api.ts";

// ---- Event names in plain words ----

/**
 * Every audit event the core writes, in plain words. The raw code stays in the CSV export and on hover; anything new
 * the core adds later shows as its code in words ("Something new").
 */
export const EVENT_LABELS: Record<string, string> = {
  // A job's life, and its approval.
  approval_requested: "Approval asked",
  approval_granted: "Approved",
  approval_rejected: "Approval refused: wrong vault password",
  approval_cancelled: "Approval cancelled",
  approval_expired: "Approval expired",
  approval_refused: "Refused: no standing approval",
  approval_used: "Ran on its standing approval",
  job_started: "Started",
  job_finished: "Finished",
  job_cancelled: "Cancelled",
  canary_go_on: "Went on after the first host",
  job_exported: "Results exported",
  multiexec_exported: "Typed lines exported",
  // Hosts, terminals, files and tunnels.
  host_key_trusted: "Host key trusted",
  host_key_retrusted: "Host key replaced",
  host_key_changed: "Host key changed: blocked",
  host_key_removed: "Host key forgotten",
  terminal_opened: "Terminal opened",
  terminal_break_sent: "Break sent",
  rdp_opened: "Remote desktop opened",
  vnc_opened: "VNC viewer opened",
  terminal_closed: "Terminal closed",
  terminal_output_saved: "Output saved",
  terminal_output_printed: "Output printed",
  terminal_log_started: "Session log started",
  terminal_log_stopped: "Session log stopped",
  terminal_rule_changed: "Terminal rule changed",
  folder_hook_installed: "Folder tracking set up",
  tunnel_opened: "Tunnel opened",
  tunnel_closed: "Tunnel closed",
  file_downloaded: "File downloaded",
  file_uploaded: "File uploaded",
  session_changed: "Sessions changed",
  sessions_imported: "Sessions imported",
  multiexec_group_changed: "Saved group changed",
  favourite_changed: "Favourite command changed",
  // The vault.
  vault_changed: "Vault changed",
  vault_unlocked: "Vault unlocked",
  vault_locked: "Vault locked",
  vault_auth_failed: "Wrong vault password",
  vault_secret_allowed: "Vault password allowed for a host",
  vault_secret_typed: "Vault password typed",
  // VMs, templates and stacks.
  vm_assigned: "VM added to the workspace",
  vm_released: "VM taken out of the workspace",
  vm_label_changed: "VM environment or protection changed",
  vm_console_opened: "Console opened",
  catalog_changed: "Templates changed",
  stack_changed: "Stack changed",
  // Schedules.
  schedule_saved: "Schedule saved",
  schedule_paused: "Schedule paused",
  schedule_resumed: "Schedule resumed",
  schedule_deleted: "Schedule deleted",
  schedule_run: "Schedule ran",
  schedule_missed: "Run missed",
  schedule_skipped: "Run skipped",
  // Workspaces.
  workspace_created: "Workspace created",
  workspace_changed: "Workspace changed",
  workspace_archived: "Workspace archived",
  workspace_restored: "Workspace restored",
  workspace_left: "Left the workspace",
  workspace_opened: "Opened the workspace",
  // Settings and the app's own data.
  setting_changed: "Setting changed",
  alert_acknowledged: "Alert acknowledged",
  alert_rule_changed: "Alert rule changed",
  dashboard_layout_changed: "Dashboard layout changed",
  history_pruned: "Dashboard history pruned",
  journal_purged: "Old job outputs removed",
  note_changed: "Note changed",
  trash_restored: "Restored from the trash",
  trash_deleted: "Deleted from the trash",
  trash_emptied: "Trash emptied",
  trash_purged: "Old items removed from the trash",
  audit_exported: "Audit log exported",
  data_exported: "Exported to a file",
  data_imported: "Imported from a file",
  database_set_aside: "Database set aside",
};

/** "Approved", "Folder tracking set up", or an unknown code in words ("Something new"). */
export function eventLabel(event: string): string {
  const known = EVENT_LABELS[event];
  if (known) return known;
  const words = event.replace(/_/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Event";
}

/** An audit entry's result in words: jobs write snake_case ("partially_failed"), schedule runs camelCase. */
export function resultLabel(result: string | null): string | null {
  if (!result) return null;
  switch (result) {
    case "succeeded":
      return "Succeeded";
    case "failed":
      return "Failed";
    case "partially_failed":
    case "partiallyFailed":
      return "Partly failed";
    case "cancelled":
      return "Cancelled";
    case "missed":
      return "Missed";
    case "skipped":
      return "Skipped";
    case "paused":
      return "Paused";
    default: {
      const words = result.replace(/_/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2");
      return words.charAt(0).toUpperCase() + words.slice(1).toLowerCase();
    }
  }
}

/** Whether a result reads as good, bad or neither (for its colour). */
export function resultTone(result: string | null): "ok" | "bad" | "neutral" {
  if (result === "succeeded") return "ok";
  if (result === "failed" || result === "partially_failed" || result === "partiallyFailed" || result === "missed") {
    return "bad";
  }
  return "neutral";
}

const REQUIREMENT_ID =
  /\s*\(\s*(?:VM|SS|BX|AP|MO|FD|QL|CT|CV|UX)-\d{2}\s*\)|\b(?:VM|SS|BX|AP|MO|FD|QL|CT|CV|UX)-\d{2}:\s*/g;

/**
 * Text the core wrote into the audit log, for the screen: older entries name requirement IDs ("the vault password was
 * asked again (…)", "…: read-only token for update checks"), which the screen leaves out. The log itself keeps them.
 */
export function plainText(text: string): string {
  return text.replace(REQUIREMENT_ID, "").trim();
}

// ---- Kinds ----

export type ActivityKind =
  "vms" | "snapshots" | "commands" | "containers" | "files" | "sessions" | "vault" | "schedules" | "app";

export const ACTIVITY_KINDS: { value: ActivityKind; label: string }[] = [
  { value: "vms", label: "VMs" },
  { value: "snapshots", label: "Snapshots" },
  { value: "commands", label: "Commands" },
  { value: "containers", label: "Containers" },
  { value: "files", label: "Files and tunnels" },
  { value: "sessions", label: "Sessions and hosts" },
  { value: "vault", label: "Vault" },
  { value: "schedules", label: "Schedules" },
  { value: "app", label: "Settings and app" },
];

/** What a job's action is about, from its action kind ("vmStart", "execReadOnly", "containerStop"...). */
export function kindOfAction(action: string): ActivityKind {
  if (action.startsWith("snapshot")) return "snapshots";
  if (action.startsWith("exec") || action.startsWith("sshKey")) return "commands";
  if (action.startsWith("file") || action.startsWith("tunnel")) return "files";
  if (
    action.startsWith("container") ||
    action.startsWith("prune") ||
    action === "imagePull" ||
    action === "imageRemove" ||
    action === "volumeRemove"
  ) {
    return "containers";
  }
  if (action === "appUpdate") return "app";
  // FD-09: a wake-up is for a machine on the network, as often a host as a VM.
  if (action === "wakeOnLan") return "sessions";
  return "vms";
}

const EVENT_KINDS: [prefix: string, kind: ActivityKind][] = [
  ["job_exported", "commands"],
  ["multiexec_", "commands"],
  ["favourite_", "commands"],
  ["file_", "files"],
  ["tunnel_", "files"],
  ["session", "sessions"],
  ["host_key_", "sessions"],
  ["terminal_", "sessions"],
  ["folder_hook_", "sessions"],
  ["vault_", "vault"],
  ["schedule_", "schedules"],
  ["vm_", "vms"],
  ["catalog_", "vms"],
  ["stack_", "vms"],
];

/** What an audit entry of no job is about, from its event. */
export function kindOfEvent(event: string): ActivityKind {
  for (const [prefix, kind] of EVENT_KINDS) {
    if (event.startsWith(prefix)) return kind;
  }
  return "app";
}

// ---- Targets ----

interface ParsedTarget {
  name: string | null;
  kind: string | null;
}

function parseTargets(targetsJson: string): ParsedTarget[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(targetsJson);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.flatMap((t: unknown) => {
    if (!t || typeof t !== "object") return [];
    const o = t as { name?: unknown; target?: { kind?: unknown } };
    return [
      {
        name: typeof o.name === "string" && o.name.trim() ? o.name.trim() : null,
        kind: o.target && typeof o.target.kind === "string" ? o.target.kind : null,
      },
    ];
  });
}

/** The names an entry's targets carry (the audit log keeps each target's name with its key). */
export function targetNames(targetsJson: string): string[] {
  return parseTargets(targetsJson).flatMap((t) => (t.name ? [t.name] : []));
}

/** A job's kind from what its entries act on, for a job older than the jobs list (whose action isn't known). */
export function kindOfTargets(targetsJson: string): ActivityKind {
  const kinds = new Set(parseTargets(targetsJson).map((t) => t.kind));
  if (kinds.has("container")) return "containers";
  if (kinds.has("session") || kinds.has("terminal")) return "commands";
  if (kinds.has("app")) return "app";
  return "vms";
}

// ---- Grouping ----

export interface ActivityGroup {
  /** The job's id, or `seq-<n>` for an entry (or an approval) of its own. */
  key: string;
  jobId: string | null;
  /** The job as the jobs list has it (status, counts, countdown); null for an older job or an entry of its own. */
  job: JobSummary | null;
  title: string;
  /** When it began: an approval asked for it, the job's creation, or its first entry, whichever came first. */
  at: string;
  tier: Tier | null;
  kind: ActivityKind;
  /** Oldest first, so they read in order: approval asked, approved, started, finished. */
  entries: AuditEntry[];
  /** The targets' names, each once. */
  targets: string[];
  /** The last result written (a job's finish, a schedule run's outcome); null when none was. */
  result: string | null;
}

const OPEN: ReadonlySet<JobStatus> = new Set(["queued", "countdown", "running"]);

export function isOpenJob(job: JobSummary | null): boolean {
  return job !== null && OPEN.has(job.status);
}

/** How long an approval lives in the core (APPROVAL_TTL), and a little for the job's countdown after it. */
export const APPROVAL_LIFE_MS = 15 * 60 * 1000;
const COUNTDOWN_SLACK_MS = 10 * 60 * 1000;

/** Approval events that end an approval without a job. */
const APPROVAL_ENDS = new Set(["approval_cancelled", "approval_expired", "approval_refused"]);

function ms(ts: string): number {
  const t = Date.parse(ts);
  return Number.isNaN(t) ? 0 : t;
}

function addTargets(group: ActivityGroup, names: string[]) {
  for (const name of names) if (!group.targets.includes(name)) group.targets.push(name);
}

/**
 * Jobs and audit entries as one list, newest first: a job with its entries folded under it (those that name it, and
 * the approval that let it run), and each other entry on its own. A job older than the jobs read still groups its
 * entries, titled by them.
 */
export function groupActivity(jobs: readonly JobSummary[], audit: readonly AuditEntry[]): ActivityGroup[] {
  const byJob = new Map<string, ActivityGroup>();
  const groups: ActivityGroup[] = [];
  const merged = new Set<ActivityGroup>();
  /** Approvals asked for and not ended yet, by action text: the next job of that text takes one once approved. */
  const approvals = new Map<string, { group: ActivityGroup; grantedAt: number | null }>();

  for (const job of jobs) {
    const group: ActivityGroup = {
      key: job.id,
      jobId: job.id,
      job,
      title: job.summary,
      at: job.createdAt,
      tier: job.tier,
      kind: kindOfAction(job.action),
      entries: [],
      targets: [],
      result: null,
    };
    byJob.set(job.id, group);
    groups.push(group);
  }

  /** Folds the approval of `action`, granted shortly before `at`, under the job's group. */
  function claimApproval(group: ActivityGroup, action: string, at: number) {
    const open = approvals.get(action);
    if (!open || open.grantedAt === null) return;
    if (at < open.grantedAt - 1000 || at - open.grantedAt > COUNTDOWN_SLACK_MS) return;
    approvals.delete(action);
    merged.add(open.group);
    group.entries.unshift(...open.group.entries);
    group.tier ??= open.group.tier;
    addTargets(group, open.group.targets);
  }

  const entries = [...audit].sort((a, b) => a.seq - b.seq);
  for (const entry of entries) {
    const names = targetNames(entry.targetsJson);
    const at = ms(entry.ts);

    if (entry.jobId) {
      let group = byJob.get(entry.jobId);
      if (!group) {
        group = {
          key: entry.jobId,
          jobId: entry.jobId,
          job: null,
          title: plainText(entry.action),
          at: entry.ts,
          tier: entry.tier,
          kind: kindOfTargets(entry.targetsJson),
          entries: [],
          targets: [],
          result: null,
        };
        byJob.set(entry.jobId, group);
        groups.push(group);
      }
      if (group.entries.length === 0) claimApproval(group, entry.action, at);
      group.entries.push(entry);
      if (entry.result) group.result = entry.result;
      group.tier ??= entry.tier;
      addTargets(group, names);
      continue;
    }

    if (entry.event.startsWith("approval_") && entry.event !== "approval_used") {
      let open = approvals.get(entry.action);
      // A new ask, or an old one past its life, starts a group of its own.
      if (!open || entry.event === "approval_requested" || at - ms(open.group.at) > APPROVAL_LIFE_MS) {
        const group: ActivityGroup = {
          key: `seq-${entry.seq}`,
          jobId: null,
          job: null,
          title: plainText(entry.action),
          at: entry.ts,
          tier: entry.tier,
          kind: kindOfTargets(entry.targetsJson),
          entries: [],
          targets: [],
          result: null,
        };
        groups.push(group);
        open = { group, grantedAt: null };
        approvals.set(entry.action, open);
      }
      open.group.entries.push(entry);
      open.group.tier ??= entry.tier;
      addTargets(open.group, names);
      if (entry.event === "approval_granted") open.grantedAt = at;
      if (APPROVAL_ENDS.has(entry.event)) approvals.delete(entry.action);
      continue;
    }

    groups.push({
      key: `seq-${entry.seq}`,
      jobId: null,
      job: null,
      title: plainText(entry.action),
      at: entry.ts,
      tier: entry.tier,
      kind: kindOfEvent(entry.event),
      entries: [entry],
      targets: [...new Set(names)],
      result: entry.result,
    });
  }

  // A job that took its approval began when the approval was asked.
  const kept = groups.filter((g) => !merged.has(g));
  for (const g of kept) {
    if (g.entries.length > 0 && ms(g.entries[0].ts) < ms(g.at)) g.at = g.entries[0].ts;
  }
  return kept.sort((a, b) => ms(b.at) - ms(a.at) || b.key.localeCompare(a.key));
}

// ---- Filters ----

export type DateRange = "today" | "7d" | "30d" | "all";

export const DATE_RANGES: { value: DateRange; label: string }[] = [
  { value: "all", label: "Any time" },
  { value: "today", label: "Today" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];

const DAY_MS = 24 * 60 * 60 * 1000;

/** The earliest time a range shows, in ms; null for any time. Today starts at local midnight. */
export function rangeStart(range: DateRange, now: number): number | null {
  switch (range) {
    case "all":
      return null;
    case "today": {
      const midnight = new Date(now);
      midnight.setHours(0, 0, 0, 0);
      return midnight.getTime();
    }
    case "7d":
      return now - 7 * DAY_MS;
    case "30d":
      return now - 30 * DAY_MS;
  }
}

export interface ActivityFilter {
  /** Matches a target's name or the action's words. */
  text: string;
  kind: ActivityKind | "all";
  range: DateRange;
}

export const NO_FILTER: ActivityFilter = { text: "", kind: "all", range: "all" };

export function isFiltered(filter: ActivityFilter): boolean {
  return filter.text.trim() !== "" || filter.kind !== "all" || filter.range !== "all";
}

function words(text: string): string[] {
  return text.trim().toLowerCase().split(/\s+/).filter(Boolean);
}

/** Every word of the text is in one of the fields (case aside). */
function matchesText(needle: string[], fields: string[]): boolean {
  if (needle.length === 0) return true;
  const hay = fields.map((f) => f.toLowerCase());
  return needle.every((w) => hay.some((f) => f.includes(w)));
}

/** When a group last moved: its newest entry, else when it began. */
function lastMoved(group: ActivityGroup): number {
  const last = group.entries.length > 0 ? ms(group.entries[group.entries.length - 1].ts) : 0;
  return Math.max(last, ms(group.at));
}

/** The groups the filter keeps: by target or action text, by kind, and by when they last moved. */
export function filterGroups(groups: readonly ActivityGroup[], filter: ActivityFilter, now: number): ActivityGroup[] {
  const since = rangeStart(filter.range, now);
  const needle = words(filter.text);
  return groups.filter(
    (g) =>
      (filter.kind === "all" || g.kind === filter.kind) &&
      (since === null || lastMoved(g) >= since) &&
      matchesText(needle, [g.title, ...g.targets]),
  );
}

/** The audit entries the filter keeps, for the audit log view: the same text, kind and date rules. */
export function filterEntries(
  entries: readonly AuditEntry[],
  jobs: readonly JobSummary[],
  filter: ActivityFilter,
  now: number,
): AuditEntry[] {
  const since = rangeStart(filter.range, now);
  const needle = words(filter.text);
  const jobKind = new Map(jobs.map((j) => [j.id, kindOfAction(j.action)]));
  return entries.filter((e) => {
    if (filter.kind !== "all") {
      const kind = e.jobId
        ? (jobKind.get(e.jobId) ?? kindOfTargets(e.targetsJson))
        : e.event.startsWith("approval_")
          ? kindOfTargets(e.targetsJson)
          : kindOfEvent(e.event);
      if (kind !== filter.kind) return false;
    }
    if (since !== null && ms(e.ts) < since) return false;
    return matchesText(needle, [e.action, eventLabel(e.event), ...targetNames(e.targetsJson)]);
  });
}

/** "3 steps": what a folded group holds, for its toggle. */
export function stepsText(count: number): string {
  return count === 1 ? "1 step" : `${count} steps`;
}
