// UX-17, UX-18 (0.9.0 H3): one results list for bulk work. Compare hosts lists its one-shot jobs on hosts (BX-03 runs,
// and BX-10's pushes and fetches, whoever started them) and the lines typed in all tabs (QL-12 recordings) together,
// newest first, each badged with what it was ("Run on 12 hosts", "Typed in 6 tabs"); each opens the same grouped
// card. Activity opens a bulk job (a run, a push or fetch, a support bundle, an SSH key push) in that grouped view
// too, and every other job in its per-target sheet. Pure functions, tested on their own (results-list.test.ts).
//
// The item kinds are one union, so a kind added later (QL-31, H7: a kept line, a run without retry) is a compile error
// in every switch below until it says what it shows.

import type { JobSummary, RecordedLine } from "./api.ts";
import { plural } from "./format.ts";
import { lineStatus } from "./recordings.ts";

/** A one-shot job on hosts from the journal: a Compare hosts run, a push or a fetch. */
export interface RunItem {
  kind: "run";
  /** Unique across kinds: `run:<job id>`. */
  key: string;
  /** RFC 3339: when it was queued. */
  at: string;
  job: JobSummary;
}

/** A line typed in all tabs and recorded in each terminal. It lives in memory until typing stops. */
export interface TypedItem {
  kind: "typed";
  /** Unique across kinds: `typed:<line id>`. */
  key: string;
  /** RFC 3339: when Enter was pressed. */
  at: string;
  line: RecordedLine;
}

export type ResultItem = RunItem | TypedItem;
export type ResultKind = ResultItem["kind"];

export function itemKey(kind: ResultKind, id: string): string {
  return `${kind}:${id}`;
}

function time(at: string): number {
  const t = Date.parse(at);
  return Number.isNaN(t) ? 0 : t;
}

/** Runs (newest first, as the core lists them) and recorded lines (newest first) as one list, newest first. */
export function resultItems(runs: readonly JobSummary[], lines: readonly RecordedLine[]): ResultItem[] {
  const items: ResultItem[] = [
    ...runs.map((job): RunItem => ({ kind: "run", key: itemKey("run", job.id), at: job.createdAt, job })),
    ...lines.map((line): TypedItem => ({ kind: "typed", key: itemKey("typed", line.id), at: line.recordedAt, line })),
  ];
  // A stable sort keeps each source's own order between items of the same instant.
  return items.sort((a, b) => time(b.at) - time(a.at));
}

/** What the panel opens: a run's job (by id), or a typed line. */
export type ShownResult = { kind: "run"; jobId: string } | { kind: "typed"; line: RecordedLine };

/**
 * The picked item, else the newest. A run picked as it was queued shows before the list is read again (it isn't
 * listed yet); a typed line that went (typing stopped) gives way to the newest.
 */
export function shownResult(items: readonly ResultItem[], picked: string | null): ShownResult | null {
  const listed = items.find((i) => i.key === picked);
  if (!listed && picked?.startsWith("run:")) return { kind: "run", jobId: picked.slice("run:".length) };
  const item = listed ?? items[0];
  if (!item) return null;
  switch (item.kind) {
    case "run":
      return { kind: "run", jobId: item.job.id };
    case "typed":
      return { kind: "typed", line: item.line };
  }
}

/** The list's key of what is shown, to mark it. */
export function shownKey(shown: ShownResult | null): string | null {
  if (!shown) return null;
  switch (shown.kind) {
    case "run":
      return itemKey("run", shown.jobId);
    case "typed":
      return itemKey("typed", shown.line.id);
  }
}

/** What it was, in a few words: "Run on 12 hosts", "Pushed to 5 hosts", "Fetched from 3 hosts", "Typed in 6 tabs". */
export function itemBadge(item: ResultItem): string {
  switch (item.kind) {
    case "run": {
      const hosts = plural(item.job.targetsTotal, "host");
      if (item.job.action === "filePush") return `Pushed to ${hosts}`;
      if (item.job.action === "fileFetch") return `Fetched from ${hosts}`;
      return `Run on ${hosts}`;
    }
    case "typed":
      return `Typed in ${plural(item.line.terminals, "tab")}`;
  }
}

/** The item's text in the list: the run's summary, or the line as typed. */
export function itemTitle(item: ResultItem): string {
  switch (item.kind) {
    case "run":
      return item.job.retryOf ? `Retry: ${item.job.summary}` : item.job.summary;
    case "typed":
      return item.line.line;
  }
}

const OPEN = new Set(["queued", "countdown", "running"]);

/** Still going: hosts or terminals have yet to finish. */
export function itemRunning(item: ResultItem): boolean {
  switch (item.kind) {
    case "run":
      return OPEN.has(item.job.status);
    case "typed":
      return item.line.finished < item.line.terminals;
  }
}

/** Where it stands, in words: "2 of 3 hosts succeeded, 1 failed", or a typed line's grouping. */
export function itemStatus(item: ResultItem): string {
  switch (item.kind) {
    case "run": {
      const { status, targetsTotal, targetsSucceeded, targetsFailed, targetsUnknown } = item.job;
      if (status === "queued") return "Queued";
      if (status === "countdown") return "Waiting for its countdown";
      const parts = [`${targetsSucceeded} of ${plural(targetsTotal, "host")} succeeded`];
      if (targetsFailed > 0) parts.push(`${targetsFailed} failed`);
      if (targetsUnknown > 0) parts.push(`${targetsUnknown} outcome unknown`);
      if (status === "running") parts.push("running");
      if (status === "cancelled" || status === "interrupted") parts.push(status);
      return parts.join(", ");
    }
    case "typed":
      return lineStatus(item.line);
  }
}

/** Why a typed line has no retry or canary, for its disabled Retry (QL-08). */
export const TYPED_NO_RETRY =
  "A typed line can't be retried: pressing Enter again later could run it after something else. Type it again, or run it here as a command.";

/** How long a typed line is kept. */
export const TYPED_KEPT = "It goes when Type in all tabs is turned off: typed lines are kept in memory only.";

/**
 * BX-02, BX-04 (QL-08): why a finished job's failed hosts can't be retried, or null; the core's `retry_failed` refuses
 * the same. The read-only lock first; then a remote exec run whose script the retention purge emptied (it empties only
 * scripts, typed lines and a bundle's items, so a push, fetch or key push older than the retention period can still be
 * retried); then a command the journal keeps as [redacted].
 */
export function retryBlockedReason(
  job: Pick<JobSummary, "commandType" | "bodiesRemoved" | "commandRedacted">,
  readOnly: string | null,
): string | null {
  if (readOnly) return readOnly;
  if (job.bodiesRemoved && job.commandType === "remoteExec")
    return "Its script was removed after the retention period. Run it again from Compare hosts.";
  if (job.commandRedacted)
    return "Its script had something that looked like a secret, which the journal doesn't keep. Run it again from Compare hosts.";
  return null;
}

/**
 * UX-18: how Activity opens a job: `results`, the grouped results view with retry, diff and export (a Compare hosts
 * run, a push or fetch to many hosts, an SSH key push); `bundle`, that view's support bundle mode (its zip is its
 * result: no retry or export, Show folder); or null, the per-target sheet every other job keeps.
 */
export function activityView(commandType: string): "results" | "bundle" | null {
  switch (commandType) {
    case "remoteExec":
    case "bulkFiles":
    case "pushSshKey":
      return "results";
    case "supportBundle":
      return "bundle";
    default:
      return null;
  }
}
