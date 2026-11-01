// QL-25 notification centre, the pure part (tested in notifications.test.ts): the entries each source adds, how the
// list groups them, and their times in words. The history itself lives in the core's memory (crates/core/src/
// notifications.rs says why not on disk), which redacts every title and body before keeping it; the store that talks to
// it is notifications-store.ts. Nothing here notifies outside the window: the Windows notifications stay where they
// were (AlertNotifier, the Terminal page), each masked with `maskedOutside` while presenting.

import type { JobEvent, JobStatus, TerminalAlert, UpdateInfo } from "./api.ts";
import type { Alert, AlertEvent } from "./dashboard-api.ts";
import { isAppLink, type AppLink } from "./links.ts";
import type { ScheduleEvent } from "./schedules-api.ts";
import { alertNotification } from "./terminal-alerts.ts";

/** Entries the core keeps (crates/core/src/notifications.rs MAX_NOTIFICATIONS); the oldest go first. */
export const MAX_KEPT = 500;

export type NotificationSource = "alert" | "terminalAlert" | "command" | "job" | "update" | "schedule" | "app";
export type NotificationLevel = "info" | "success" | "warning" | "error";

/** What the UI hands the core (crates/core/src/notifications.rs `NotificationInput`). */
export interface NotificationInput {
  source: NotificationSource;
  level: NotificationLevel;
  title: string;
  body?: string | null;
  link?: AppLink | null;
  /** Entries with the same key show together. */
  group?: string | null;
  /** At most one entry with this key is kept (an update's version). */
  once?: string | null;
}

/** An entry as the core keeps it: redacted, with an id and a time. */
export interface AppNotification {
  id: number;
  source: NotificationSource;
  level: NotificationLevel;
  title: string;
  body: string | null;
  /** Checked with `isAppLink` before it is opened (`entryLink`). */
  link: unknown;
  group: string | null;
  /** RFC 3339, UTC. */
  at: string;
  read: boolean;
}

export interface NotificationList {
  entries: AppNotification[];
  unread: number;
}

/** The link of an entry, when this version can open it. */
export function entryLink(entry: AppNotification): AppLink | null {
  return isAppLink(entry.link) ? entry.link : null;
}

// ---- What each source adds ----

/** MO-07: an alert that fired or resolved (every one, whether or not Windows was told: the list is the history). */
export function fromAlertEvent(event: AlertEvent): NotificationInput | null {
  if (event.kind === "acknowledged") return null;
  const alert: Alert = event.alert;
  // MO-08: one rule's alerts on every check are one line, so a lost network (every check down at once, then up) is
  // one line that opens to show them, not one per check.
  const group =
    alert.target.kind === "check"
      ? `alert:${alert.ruleId}:check:${event.kind}`
      : `alert:${alert.ruleId}:${alert.target.kind}:${alert.target.key}`;
  if (event.kind === "resolved") {
    return {
      source: "alert",
      level: "success",
      title: `Resolved: ${alert.ruleName} on ${alert.target.name}`,
      body: alert.message,
      link: { kind: "alerts" },
      group,
    };
  }
  return {
    source: "alert",
    level: alert.severity === "critical" ? "error" : "warning",
    title: `${alert.severity === "critical" ? "Critical" : "Warning"}: ${alert.ruleName} on ${alert.target.name}`,
    body: alert.message,
    link: { kind: "alerts" },
    group,
  };
}

/** QL-17: a terminal's alert rule matched (the core sends one per burst of lines; its sample is already scrubbed). */
export function fromTerminalAlert(alert: TerminalAlert, terminal: string): NotificationInput {
  const { title, body } = alertNotification(alert, terminal);
  return {
    source: "terminalAlert",
    level: "warning",
    title,
    body,
    link: { kind: "terminal", terminalId: alert.terminalId },
    group: `terminal-alert:${alert.terminalId}:${alert.ruleId}`,
  };
}

/** QL-07: a long command (or a MultiExec line) finished; the words are its Windows notification's. */
export function fromCommandFinished(title: string, body: string, terminalId: string | null): NotificationInput {
  return {
    source: "command",
    level: "info",
    title,
    body,
    link: terminalId ? { kind: "terminal", terminalId } : null,
  };
}

/** FD-14: an update is available; one entry per version. */
export function fromUpdate(update: UpdateInfo): NotificationInput {
  return {
    source: "update",
    level: "info",
    title: `Remotely ${update.version} is available`,
    body: `You have ${update.currentVersion}. Installing asks first and waits until no job is running.`,
    link: { kind: "update" },
    once: `update:${update.version}`,
  };
}

/**
 * VM-14, VM-27: a schedule's run that did not happen: missed (the PC slept, Remotely was closed), skipped (the read-only
 * lock, the last run still going), or the schedule waits to be approved again. Runs that ran are their jobs' entries.
 */
export function fromScheduleEvent(event: ScheduleEvent): NotificationInput | null {
  const link: AppLink = { kind: "schedule", scheduleId: event.scheduleId };
  const group = `schedule:${event.scheduleId}`;
  switch (event.event) {
    case "missed":
      return { source: "schedule", level: "warning", title: `Missed: ${event.name}`, body: event.detail, link, group };
    case "skipped":
      return { source: "schedule", level: "warning", title: `Skipped: ${event.name}`, body: event.detail, link, group };
    case "needsApproval":
      return {
        source: "schedule",
        level: "warning",
        title: `${event.name} waits for approval`,
        body: `${event.reason} since it was approved, so it doesn't run until you review it.`,
        link,
        group,
      };
    default:
      return null;
  }
}

/** AP-04: a Low action left protected targets alone (the toast that says so is worth keeping). */
export function fromSkipped(names: string[]): NotificationInput {
  return {
    source: "app",
    level: "info",
    title: `Skipped ${names.length} protected ${names.length === 1 ? "target" : "targets"}`,
    body: names.join(", "),
  };
}

const FINISHED: Record<Exclude<JobStatus, "queued" | "countdown" | "running">, [NotificationLevel, string]> = {
  succeeded: ["success", "Job succeeded"],
  failed: ["error", "Job failed"],
  partially_failed: ["error", "Job partly failed"],
  cancelled: ["warning", "Job cancelled"],
  interrupted: ["warning", "Job interrupted"],
};

/**
 * Jobs: remembers each job's summary from its "queued" event, and words its end (and what it waits for) the way its
 * toast does. MultiExec lines (`quiet`) are left out: their terminals and QL-07 say how they went.
 */
export class JobNotes {
  private summaries = new Map<string, string>();
  private quiet = new Set<string>();

  /** The entry for this event, or null when it adds none. */
  note(event: JobEvent): NotificationInput | null {
    const id = event.jobId;
    const link: AppLink = { kind: "job", jobId: id };
    const group = `job:${id}`;
    switch (event.event) {
      case "queued":
        if (event.quiet) this.quiet.add(id);
        else this.summaries.set(id, event.summary);
        return null;
      case "canaryWaiting":
        if (this.quiet.has(id)) return null;
        return {
          source: "job",
          level: "warning",
          title: `${event.name} finished without errors`,
          body: `${event.rest === 1 ? "The other host waits" : `The other ${event.rest} hosts wait`} for you to look at its result and say go on: ${this.summary(id)}`,
          link,
          group,
        };
      case "stillRunning":
        if (this.quiet.has(id)) return null;
        return {
          source: "job",
          level: "warning",
          title: `Still running after the shutdown: ${event.targets.map((t) => t.name).join(", ")}`,
          body: "The guest did not shut down in time. Forcing it off needs its own approval.",
          link,
          group,
        };
      case "finished": {
        const summary = this.summary(id);
        const wasQuiet = this.quiet.delete(id);
        this.summaries.delete(id);
        if (wasQuiet) return null;
        const outcome = FINISHED[event.status as keyof typeof FINISHED];
        if (!outcome) return null;
        const [level, words] = outcome;
        return { source: "job", level, title: `${words}: ${summary}`, link, group };
      }
      default:
        return null;
    }
  }

  private summary(id: string) {
    return this.summaries.get(id) ?? "a job";
  }
}

// ---- The list ----

/** Entries in a row that share a group key: one line in the list, the newest first. */
export interface NotificationGroup {
  key: string;
  latest: AppNotification;
  entries: AppNotification[];
  unread: number;
}

export interface NotificationDay {
  /** "Today", "Yesterday", or the date. */
  label: string;
  groups: NotificationGroup[];
}

function dayStart(ms: number) {
  const d = new Date(ms);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/** The day heading for a time, in local time. */
export function dayLabel(atMs: number, nowMs: number): string {
  const days = Math.round((dayStart(nowMs) - dayStart(atMs)) / 86_400_000);
  if (days <= 0) return "Today";
  if (days === 1) return "Yesterday";
  return new Date(atMs).toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" });
}

/**
 * The list as the centre shows it: by day, newest first, and within a day the entries next to each other that share a
 * group key (one rule's alerts on one target, one job's events) as one line that opens to show them all. Filtered to
 * the unread ones when asked.
 */
export function groupNotifications(
  entries: readonly AppNotification[],
  nowMs: number,
  unreadOnly = false,
): NotificationDay[] {
  const days: NotificationDay[] = [];
  const sorted = [...entries]
    .filter((e) => !unreadOnly || !e.read)
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at) || b.id - a.id);
  for (const entry of sorted) {
    const label = dayLabel(Date.parse(entry.at), nowMs);
    let day = days[days.length - 1];
    if (!day || day.label !== label) {
      day = { label, groups: [] };
      days.push(day);
    }
    const last = day.groups[day.groups.length - 1];
    if (entry.group && last && last.key === entry.group) {
      last.entries.push(entry);
      if (!entry.read) last.unread += 1;
      continue;
    }
    day.groups.push({
      key: entry.group ?? `entry:${entry.id}`,
      latest: entry,
      entries: [entry],
      unread: entry.read ? 0 : 1,
    });
  }
  return days;
}

/** "just now", "5 min ago", "2 h ago", then the clock time. */
export function timeAgo(atMs: number, nowMs: number): string {
  const secs = Math.max(0, Math.round((nowMs - atMs) / 1000));
  if (secs < 45) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 6) return `${hours} h ago`;
  return new Date(atMs).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** The count the bell shows: nothing at 0, "99+" past 99. */
export function unreadBadge(unread: number): string | null {
  if (unread <= 0) return null;
  return unread > 99 ? "99+" : String(unread);
}
