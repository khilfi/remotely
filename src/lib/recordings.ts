// QL-12 MultiExec recordings and QL-07 notifications, the UI side: what a terminal's recording reads as, which
// recorded line the Compare panel shows, what the caps say, and whether a finished command or MultiExec line
// notifies (once per line, never per terminal). Pure functions, tested on their own (recordings.test.ts).

import type { CaptureState, FinishedHow, NotifyWhen, RecordedLine, RecordLimits } from "./api.ts";
import { formatDuration, plural } from "./format.ts";

/** "350 ms", "4.2 s", "18 s", "3 min". */
export function shortDuration(ms: number | null) {
  if (ms === null) return "";
  if (ms < 1000) return `${ms} ms`;
  if (ms < 10_000) return `${(ms / 1000).toFixed(1)} s`;
  return formatDuration(Math.round(ms / 1000));
}

export type CaptureTone = "ok" | "running" | "warn" | "bad" | "muted";

/** How a terminal's recording of a line reads, e.g. "Prompt back after 1.2 s" or "Running 4.0 s". */
export function captureText(state: CaptureState, durationMs: number | null): { text: string; tone: CaptureTone } {
  const took = durationMs === null ? "" : ` after ${shortDuration(durationMs)}`;
  switch (state.state) {
    case "waiting":
      return { text: "Waiting for Enter", tone: "muted" };
    case "running":
      return { text: durationMs === null ? "Running" : `Running ${shortDuration(durationMs)}`, tone: "running" };
    case "done":
      if (state.how === "prompt") return { text: `Prompt back${took}`, tone: "ok" };
      if (state.how === "quiet")
        return { text: `Output stopped${took} (no prompt recognised, or it waits for an answer)`, tone: "warn" };
      return { text: `Answered by the next line${took}`, tone: "ok" };
    case "timedOut":
      return { text: "Still running at the time limit: recording stopped, the command goes on", tone: "warn" };
    case "lost":
      return { text: `Lost: ${state.reason}`, tone: "bad" };
    case "notSent":
      return { text: `Not sent: ${state.reason}`, tone: "bad" };
  }
}

/** One line of the list: its state while it runs, else how its outputs group. */
export function lineStatus(line: RecordedLine) {
  if (line.waitingApproval) return "Waiting for approval";
  if (line.finished < line.terminals) return `${line.finished} of ${plural(line.terminals, "terminal")} done`;
  return line.headline;
}

/** The line the panel shows: the one picked while it is still kept, else the newest. */
export function shownLine(lines: RecordedLine[], picked: string | null): RecordedLine | null {
  return lines.find((l) => l.id === picked) ?? lines[0] ?? null;
}

/** What the session caps did, or null when none was hit. */
export function capsNote(dropped: number, limits: RecordLimits) {
  if (dropped === 0) return null;
  return `Typing in all tabs keeps its last ${limits.maxLines} lines (${Math.round(
    limits.maxSessionBytes / 1024 / 1024,
  )} MB of output at most): ${plural(dropped, "older line")} ${dropped === 1 ? "was" : "were"} dropped.`;
}

/** QL-07 as the settings say it. */
export interface NotifyChoice {
  on: boolean;
  when: NotifyWhen;
  /** "Commands longer than": seconds. */
  afterSecs: number;
}

/**
 * QL-07: whether a finished command, or a MultiExec line (all its terminals done), notifies. Only while the user is
 * away (`away`: the tab is not on screen, the page is another one, or Remotely is not in front).
 */
export function shouldNotify(choice: NotifyChoice, ranSecs: number, away: boolean) {
  if (!choice.on || !away) return false;
  return choice.when === "any" || ranSecs >= choice.afterSecs;
}

/** "uptime", or the first 60 characters of a long line (the first line of a paste). */
function shortLine(line: string) {
  const first = line.split("\n")[0];
  const more = first !== line ? " …" : "";
  return first.length > 60 ? `${first.slice(0, 59)}…` : `${first}${more}`;
}

/** QL-07: the one notification for a MultiExec line. */
export function lineNotification(
  line: string,
  terminals: number,
  afterSecs: number,
  how: FinishedHow,
  unfinished: number,
) {
  const ran = formatDuration(afterSecs);
  const where = plural(terminals, "terminal");
  let body =
    how === "prompt"
      ? `It ran ${ran}; the prompt is back in ${terminals === 1 ? "it" : terminals === 2 ? "both" : `all ${terminals}`}.`
      : `It ran ${ran}; in some terminals the output stopped: finished, or waiting for an answer.`;
  if (unfinished > 0) body += ` ${plural(unfinished, "terminal")} stopped recording before its prompt came back.`;
  return { title: `Typed in all tabs: \`${shortLine(line)}\` finished in ${where}`, body };
}
