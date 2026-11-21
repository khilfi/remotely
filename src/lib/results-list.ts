// UX-17, UX-18 (0.9.0 H3): one results list for bulk work. Compare hosts lists its one-shot jobs on hosts (BX-03 runs,
// and BX-10's pushes and fetches, whoever started them) and the lines typed in all tabs (QL-12 recordings) together,
// newest first, each badged with what it was ("Run on 12 hosts", "Typed in 6 tabs"); each opens the same grouped
// card. Activity opens a bulk job (a run, a push or fetch, a support bundle, an SSH key push) in that grouped view
// too, and every other job in its per-target sheet. Pure functions, tested on their own (results-list.test.ts).
//
// The item kinds are one union, so a kind added later is a compile error in every switch below until it says what it
// shows. QL-31 (0.9.0 H7) added the third: a typed line kept as a run in the job journal ("Keep this line"), listed
// among runs, badged "Kept from 6 tabs", grouped, diffed and exported like a run, never retried. Its typed original
// leaves the list once the kept run is listed (the kept run's job id is the typed line's id).

import type { JobSummary, RecordedLine } from "./api.ts";
import { plural } from "./format.ts";
import { lineStatus } from "./recordings.ts";

/** QL-31: the journal's command type of a typed line kept as a run (the core's `store::KEPT_LINE`). */
export const KEPT_LINE = "keptLine";

/** A one-shot job on hosts from the journal: a Compare hosts run, a push or a fetch. */
export interface RunItem {
  kind: "run";
  /** Unique across kinds: `run:<job id>`. */
  key: string;
  /** RFC 3339: when it was queued. */
  at: string;
  job: JobSummary;
}

/** QL-31: a line typed in all tabs and kept as a run in the journal: its line, terminals and recorded outputs. */
export interface KeptItem {
  kind: "kept";
  /** Unique across kinds: `kept:<job id>`, the job id being the typed line's id. */
  key: string;
  /** RFC 3339: when Enter was pressed. */
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

export type ResultItem = RunItem | KeptItem | TypedItem;
export type ResultKind = ResultItem["kind"];

export function itemKey(kind: ResultKind, id: string): string {
  return `${kind}:${id}`;
}

function time(at: string): number {
  const t = Date.parse(at);
  return Number.isNaN(t) ? 0 : t;
}

/** QL-31: the job is a typed line kept as a run. */
export function isKeptLine(job: Pick<JobSummary, "commandType">): boolean {
  return job.commandType === KEPT_LINE;
}

/**
 * Runs (newest first, as the core lists them: its kept lines among them) and recorded lines (newest first) as one list,
 * newest first. QL-31: a typed line whose kept run is listed is that run now, so it is listed once.
 */
export function resultItems(runs: readonly JobSummary[], lines: readonly RecordedLine[]): ResultItem[] {
  const kept = new Set(runs.filter(isKeptLine).map((job) => job.id));
  const items: ResultItem[] = [
    ...runs.map((job): RunItem | KeptItem =>
      isKeptLine(job)
        ? { kind: "kept", key: itemKey("kept", job.id), at: job.createdAt, job }
        : { kind: "run", key: itemKey("run", job.id), at: job.createdAt, job },
    ),
    ...lines
      .filter((line) => !kept.has(line.id))
      .map((line): TypedItem => ({ kind: "typed", key: itemKey("typed", line.id), at: line.recordedAt, line })),
  ];
  // A stable sort keeps each source's own order between items of the same instant.
  return items.sort((a, b) => time(b.at) - time(a.at));
}

/** What the panel opens: a run's or a kept line's job (by id), or a typed line. */
export type ShownResult =
  { kind: "run"; jobId: string } | { kind: "kept"; jobId: string } | { kind: "typed"; line: RecordedLine };

/**
 * The picked item, else the newest. A run picked as it was queued, or a line just kept, shows before the list is read
 * again (it isn't listed yet); a typed line kept since shows as its kept run; a typed line that went (typing stopped)
 * gives way to the newest.
 */
export function shownResult(items: readonly ResultItem[], picked: string | null): ShownResult | null {
  const listed =
    items.find((i) => i.key === picked) ??
    (picked?.startsWith("typed:")
      ? items.find((i) => i.key === itemKey("kept", picked.slice("typed:".length)))
      : undefined);
  if (!listed && picked?.startsWith("run:")) return { kind: "run", jobId: picked.slice("run:".length) };
  if (!listed && picked?.startsWith("kept:")) return { kind: "kept", jobId: picked.slice("kept:".length) };
  const item = listed ?? items[0];
  if (!item) return null;
  switch (item.kind) {
    case "run":
      return { kind: "run", jobId: item.job.id };
    case "kept":
      return { kind: "kept", jobId: item.job.id };
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
    case "kept":
      return itemKey("kept", shown.jobId);
    case "typed":
      return itemKey("typed", shown.line.id);
  }
}

/**
 * What it was, in a few words: "Run on 12 hosts", "Pushed to 5 hosts", "Fetched from 3 hosts", "Kept from 6 tabs",
 * "Typed in 6 tabs".
 */
export function itemBadge(item: ResultItem): string {
  switch (item.kind) {
    case "run": {
      const hosts = plural(item.job.targetsTotal, "host");
      if (item.job.action === "filePush") return `Pushed to ${hosts}`;
      if (item.job.action === "fileFetch") return `Fetched from ${hosts}`;
      return `Run on ${hosts}`;
    }
    case "kept":
      return `Kept from ${plural(item.job.targetsTotal, "tab")}`;
    case "typed":
      return `Typed in ${plural(item.line.terminals, "tab")}`;
  }
}

/** The item's text in the list: the run's or kept line's summary, or the line as typed. */
export function itemTitle(item: ResultItem): string {
  switch (item.kind) {
    case "run":
      return item.job.retryOf ? `Retry: ${item.job.summary}` : item.job.summary;
    case "kept":
      return item.job.summary;
    case "typed":
      return item.line.line;
  }
}

const OPEN = new Set(["queued", "countdown", "running"]);

/** Still going: hosts or terminals have yet to finish. A kept line was kept once every tab had finished it. */
export function itemRunning(item: ResultItem): boolean {
  switch (item.kind) {
    case "run":
      return OPEN.has(item.job.status);
    case "kept":
      return false;
    case "typed":
      return item.line.finished < item.line.terminals;
  }
}

/** Where it stands, in words: "2 of 3 hosts succeeded, 1 failed", "3 of 3 tabs finished", or a typed line's grouping. */
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
    case "kept": {
      const { targetsTotal, targetsSucceeded, targetsFailed, targetsUnknown } = item.job;
      const parts = [`${targetsSucceeded} of ${plural(targetsTotal, "tab")} with the prompt back`];
      if (targetsUnknown > 0) parts.push(`${targetsUnknown} outcome unknown`);
      if (targetsFailed > 0) parts.push(`${targetsFailed} not sent`);
      return parts.join(", ");
    }
    case "typed":
      // QL-31: kept, its run not on the list's page (the list shows the newest runs).
      return item.line.kept ? `Kept as a run · ${lineStatus(item.line)}` : lineStatus(item.line);
  }
}

/** Why a typed line has no retry or canary, for its disabled Retry (QL-08). */
export const TYPED_NO_RETRY =
  "A typed line can't be retried: pressing Enter again later could run it after something else. Type it again, or run it here as a command.";

/**
 * QL-31: why a kept line has no retry or canary, word for word as the core's `retry_failed` refuses it (the core's
 * `kept_lines::NO_RETRY`; the test reads it there), shown in Compare hosts and in Activity alike.
 */
export const KEPT_NO_RETRY =
  "A kept line can't be retried: pressing Enter again later could run it after something else. Type it again, or run it from Compare hosts as a command.";

/** How long a typed line is kept, and how to keep it longer (QL-31). */
export const TYPED_KEPT =
  "It goes when Type in all tabs is turned off, unless you keep it as a run: then it stays for as long as job outputs are kept.";

/**
 * QL-31: a terminal of a typed or kept line, by its exit state where known (the core's `record.rs` target_record): the
 * prompt came back; Enter never reached it; or the prompt never came back, so the command may still run.
 */
export const TERMINAL_STATUS: Record<string, string> = {
  pending: "Waiting for Enter",
  running: "Running",
  succeeded: "Prompt back",
  failed: "Not sent",
  unknown: "Outcome unknown",
  cancelled: "Cancelled",
  skipped: "Not started",
};

/** QL-31: what a terminal's unknown outcome means, for its tooltip. */
export const TERMINAL_UNKNOWN =
  "The prompt never came back (the output went quiet, the next line came first, the time limit passed or the connection was lost), so the command may still run.";

/**
 * QL-31 (QL-08): why "Keep this line" is off for a typed line, or null. The core refuses the same: the read-only lock,
 * a line that waits for its approval, one whose Enter hasn't gone yet (AP-03's countdown), one some tab is still
 * running, and one whose Enter reached no tab. A line kept already offers its run instead. (Whether the line's own job
 * was purged only the core knows: it says so if asked.)
 */
export function keepReason(
  line: Pick<RecordedLine, "waitingApproval" | "finished" | "terminals" | "reached">,
  readOnly: string | null,
): string | null {
  if (readOnly) return readOnly;
  if (line.waitingApproval) return "It waits for its approval: keep it once it has run.";
  if (line.finished < line.terminals && line.reached === 0)
    return "Its Enter hasn't gone yet (its countdown may still run): keep it once it has run.";
  if (line.finished < line.terminals) return "Some tabs are still running it: keep it once every tab has finished it.";
  if (line.reached === 0) return "Enter reached none of its tabs, so there is nothing to keep.";
  return null;
}

/**
 * BX-02, BX-04 (QL-08): why a finished job's failed hosts can't be retried, or null; the core's `retry_failed` refuses
 * the same. A kept line never (QL-31); the read-only lock first otherwise; then a remote exec run whose script the
 * retention purge emptied (it empties only scripts, typed lines and a bundle's items, so a push, fetch or key push
 * older than the retention period can still be retried); then a command the journal keeps as [redacted].
 */
export function retryBlockedReason(
  job: Pick<JobSummary, "commandType" | "bodiesRemoved" | "commandRedacted">,
  readOnly: string | null,
): string | null {
  if (isKeptLine(job)) return KEPT_NO_RETRY;
  if (readOnly) return readOnly;
  if (job.bodiesRemoved && job.commandType === "remoteExec")
    return "Its script was removed after the retention period. Run it again from Compare hosts.";
  if (job.commandRedacted)
    return "Its script had something that looked like a secret, which the journal doesn't keep. Run it again from Compare hosts.";
  return null;
}

/**
 * UX-18: how Activity opens a job: `results`, the grouped results view with retry, diff and export (a Compare hosts
 * run, a push or fetch to many hosts, an SSH key push; QL-31 a typed line kept as a run, which that view shows without
 * retry); `bundle`, that view's support bundle mode (its zip is its result: no retry or export, Show folder); or null,
 * the per-target sheet every other job keeps.
 */
export function activityView(commandType: string): "results" | "bundle" | null {
  switch (commandType) {
    case "remoteExec":
    case "bulkFiles":
    case "pushSshKey":
    case KEPT_LINE:
      return "results";
    case "supportBundle":
      return "bundle";
    default:
      return null;
  }
}
