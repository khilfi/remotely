// 0.7.0 F6: the export dialogs as pure functions (tested in reports.test.ts): the handover pack's local days as the
// core's range, the Activity page's date filter as days, why a dialog's button is off, and what a toast says once a
// file is saved.

import type { DateRange } from "./activity.ts";
import type { AnsibleExport, HandoverExport, InventoryExport, ReadProgress, ReadSummary } from "./reports-api.ts";

/** The core's longest range, in days (`MAX_RANGE_DAYS`). */
export const MAX_RANGE_DAYS = 366;
/** "Prepared by" at most (`MAX_PREPARED_BY`). */
export const MAX_PREPARED_BY = 120;

const DAY_MS = 24 * 60 * 60 * 1000;

function plural(n: number, word: string): string {
  return n === 1 ? `1 ${word}` : `${n} ${word}s`;
}

/** The window's offset east of UTC, in minutes, as the core takes it (UTC+08:00 is 480). */
export function utcOffsetMinutes(at: Date = new Date()): number {
  // getTimezoneOffset is west of UTC; `|| 0` keeps -0 out.
  return -at.getTimezoneOffset() || 0;
}

/** `2026-11-01`, in local time. */
export function isoDay(at: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
}

/** Local midnight of a `YYYY-MM-DD` day; null for text that isn't a real day. */
export function dayStart(day: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day.trim());
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const at = new Date(y, mo - 1, d);
  if (at.getFullYear() !== y || at.getMonth() !== mo - 1 || at.getDate() !== d) return null;
  return at.getTime();
}

/** The first day's local midnight and the day after the last one's, or why there is no range. */
export function dayRange(from: string, to: string): { fromMs: number; toMs: number } | { problem: string } {
  const start = dayStart(from);
  const last = dayStart(to);
  if (start === null) return { problem: "Enter the first day as a date." };
  if (last === null) return { problem: "Enter the last day as a date." };
  if (last < start) return { problem: "The last day can't be before the first." };
  const end = new Date(last);
  end.setDate(end.getDate() + 1);
  const toMs = end.getTime();
  if (toMs - start > (MAX_RANGE_DAYS + 1) * DAY_MS) return { problem: `A pack covers at most ${MAX_RANGE_DAYS} days.` };
  return { fromMs: start, toMs };
}

/** The Activity page's date filter as the pack's first and last day; any time is the last 30 days. */
export function daysFromActivity(range: DateRange, now: Date = new Date()): { from: string; to: string } {
  const to = isoDay(now);
  const back = (days: number) => {
    const at = new Date(now);
    at.setDate(at.getDate() - days);
    return isoDay(at);
  };
  switch (range) {
    case "today":
      return { from: to, to };
    case "7d":
      return { from: back(7), to };
    case "30d":
    case "all":
      return { from: back(30), to };
  }
}

/** Why the handover pack's Save is off, or null. `problem`: why the dates' counts could not be read. */
export function handoverReason(input: {
  range: { fromMs: number; toMs: number } | { problem: string };
  preparedBy: string;
  busy: boolean;
  problem?: string | null;
}): string | null {
  if (input.busy) return "Making the pack…";
  if ("problem" in input.range) return input.range.problem;
  if (input.problem) return input.problem;
  if (input.preparedBy.trim().length > MAX_PREPARED_BY)
    return `"Prepared by" can be at most ${MAX_PREPARED_BY} characters.`;
  return null;
}

/** Why the Ansible export's Save is off, or null. `problem`: why the preview could not be made. */
export function ansibleReason(input: { hosts: number | null; busy: boolean; problem?: string | null }): string | null {
  if (input.busy) return "Saving…";
  if (input.problem) return input.problem;
  if (input.hosts === null) return "Reading the sessions…";
  if (input.hosts === 0) return "No SSH session is picked: pick sessions, or VMs linked to one.";
  return null;
}

/** What a busy export's button says: "Reading hosts: 3 of 12…" while the hosts are read, then `saving`. */
export function busyText(input: { reading: boolean; progress: ReadProgress | null; saving: string }): string {
  const p = input.progress;
  if (!input.reading || (p !== null && p.total > 0 && p.done >= p.total)) return input.saving;
  if (p === null || p.total === 0) return "Reading hosts…";
  return `Reading hosts: ${p.done} of ${p.total}…`;
}

/** "2 of 3 hosts read again; 1 kept what was read before." (SSH and WinRM hosts) */
export function readText(read: ReadSummary | null): string | null {
  if (!read) return null;
  const failed = read.asked - read.read;
  const first = `${read.read} of ${plural(read.asked, "host")} read again`;
  return failed > 0 ? `${first}; ${failed} kept what was read before.` : `${first}.`;
}

/** The file's own name, from its full path. */
export function fileName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

/** What the toast says once the workbook is saved. */
export function inventorySavedText(report: InventoryExport): string {
  const parts = [plural(report.vms, "VM"), plural(report.hosts, "host"), plural(report.checks, "health check")];
  if (report.packages !== null) parts.push(plural(report.packages, "package"));
  return `Saved ${fileName(report.path)}: ${parts.join(", ")}.`;
}

export function ansibleSavedText(report: AnsibleExport): string {
  return `Saved ${fileName(report.path)}: ${plural(report.hosts, "host")} in ${plural(report.groups, "group")}.`;
}

export function handoverSavedText(report: HandoverExport): string {
  return `Saved ${fileName(report.path)}: ${plural(report.jobs, "job")} and ${plural(report.notes, "note")}.`;
}

/** The handover dialog's count line: "3 jobs, 1 other change and 2 notes in these dates". */
export function handoverCountText(jobs: number, others: number, notes: number): string {
  return `${plural(jobs, "job")}, ${plural(others, "other change")} and ${plural(notes, "marked note")}`;
}
