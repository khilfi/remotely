// BX-02: the job journal's retention setting and what a purge did, in words for Settings.

import type { PurgeReport, Retention } from "./api.ts";

export const RETENTION_CHOICES: { value: Retention; label: string }[] = [
  { value: "days30", label: "30 days" },
  { value: "days90", label: "90 days (default)" },
  { value: "year", label: "1 year" },
  { value: "forever", label: "Forever" },
];

/** "2.1 MB", "512 B": as the core writes sizes (powers of 1000). */
export function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit + 1 < units.length) {
    value /= 1000;
    unit += 1;
  }
  if (unit === 0) return `${bytes} B`;
  return `${value < 10 ? value.toFixed(1) : value.toFixed(0)} ${units[unit]}`;
}

function count(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`;
}

/** One sentence for the last purge. */
export function purgeSummary(report: PurgeReport): string {
  if (report.before === null) return "Job outputs are kept forever, so nothing was removed.";
  const { outputs, commands, bytes, jobs } = report.removed;
  const removed =
    outputs > 0 || commands > 0
      ? `Removed ${count(outputs, "output", "outputs")} and ${count(commands, "script or line", "scripts or lines")} (${formatBytes(bytes)}) from ${count(jobs, "older job", "older jobs")}.`
      : "Nothing was old enough to remove.";
  const compacted = report.compacted ? " The database file was compacted." : "";
  return removed + compacted;
}
