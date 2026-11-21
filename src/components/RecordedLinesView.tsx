// QL-12: the lines typed in all tabs, for Compare hosts. Every line MultiExec sends is recorded in each of its
// terminals, from Enter until that terminal's prompt comes back (crates/core/src/terminal/record.rs), so it can be
// compared at any time without typing it again. UX-17 (0.9.0 H3): the lines are items of Compare hosts' one results
// list beside its runs (ComparePanel, lib/results-list.ts); useRecordings reads them, and RecordedLineResults shows
// the line picked with the same grouped card as a run: identical outputs grouped A, B..., the diff between groups,
// the ignore-trailing-whitespace switch, each terminal's state as it fills in, and CSV, JSON or HTML export of this
// line or all of them. A typed line has no retry or canary (it says why) and goes when Type in all tabs is turned
// off. QL-31 (0.9.0 H7): "Keep this line" stores it, once every tab has finished it, as a run in the job journal
// (kept for as long as job outputs are; off with the reason under the read-only lock); the panel then shows the kept
// run, and a line kept already offers it. FD-03: everything here is plain DOM text, so presentation mode masks it
// like the rest of the page.

import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ArchiveIcon,
  ChevronRightIcon,
  DownloadIcon,
  GitCompareArrowsIcon,
  LoaderCircleIcon,
  RotateCcwIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TierBadge } from "@/components/Badges";
import { GroupCard, HostOutputDialog } from "@/components/BulkResultsView";
import { HelpTip } from "@/components/HelpTip";
import { OutputDiffDialog } from "@/components/OutputDiffDialog";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type ExportFormat,
  type HostResult,
  type RecordedLine,
  type RecordedResults,
  type RecordedTerminal,
  type Recordings,
} from "@/lib/api";
import { diffReason } from "@/lib/disabled-reasons";
import { plural } from "@/lib/format";
import { captureText, shortDuration, type CaptureTone } from "@/lib/recordings";
import { keepReason, TYPED_KEPT, TYPED_NO_RETRY } from "@/lib/results-list";
import { cn } from "@/lib/utils";

/** Reloads at most this often while terminals finish. */
const RELOAD_MS = 150;
/** A line still running is read again this often (running times, output so far). */
const POLL_MS = 1000;

const EXPORTS: { format: ExportFormat; label: string }[] = [
  { format: "html", label: "HTML report" },
  { format: "csv", label: "CSV (one row per terminal)" },
  { format: "json", label: "JSON" },
];

const TONES: Record<CaptureTone, string> = {
  ok: "text-success",
  running: "text-foreground",
  warn: "text-tier-medium",
  bad: "text-destructive",
  muted: "text-muted-foreground",
};

function time(ts: string) {
  return new Date(ts).toLocaleTimeString();
}

/**
 * The session's recorded lines (newest first), read while the panel shows and again, at most every RELOAD_MS, as
 * lines are recorded or finish; `version` moves with each read so a line's results follow it.
 */
export function useRecordings(active: boolean, multiExecOn: boolean) {
  const [recordings, setRecordings] = useState<Recordings | null>(null);
  const [version, setVersion] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // Recorded, a terminal started or finished, lines dropped: read again, at most every RELOAD_MS.
  useEffect(() => {
    let timer: number | undefined;
    const unlisten = api.onMultiExecEvent((event) => {
      if (event.event !== "recorded" && event.event !== "lineFinished") return;
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        setVersion((v) => v + 1);
      }, RELOAD_MS);
    });
    return () => {
      window.clearTimeout(timer);
      void unlisten.then((stop) => stop());
    };
  }, []);

  useEffect(() => {
    if (!active) return;
    let stale = false;
    api.multiExecRecordings().then(
      (r) => {
        if (stale) return;
        setRecordings(r);
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [active, version, multiExecOn]);

  return { recordings, version, error };
}

async function exportLines(lineId: string | null, format: ExportFormat, ignoreTrailingWhitespace: boolean) {
  try {
    const done = await api.multiExecExport(lineId, format, { ignoreTrailingWhitespace });
    if (!done) return;
    const redacted =
      done.redacted > 0 ? `; ${plural(done.redacted, "text")} had something like a secret, now [redacted]` : "";
    toast.success(
      `Exported ${plural(done.lines, "line")} (${plural(done.outputs, "terminal output")}) to ${done.path}${redacted}`,
    );
  } catch (err) {
    toast.error(errorMessage(err));
  }
}

/** One typed line's results, grouped like a run's. */
export function RecordedLineResults({
  line,
  version,
  active,
  onKept,
}: {
  line: RecordedLine;
  /** Moves with each read of the recordings. */
  version: number;
  active: boolean;
  /** QL-31: the line is kept as a run (just now, or before): show that run, by its job id. */
  onKept: (jobId: string) => void;
}) {
  const [results, setResults] = useState<RecordedResults | null>(null);
  const [ignoreWs, setIgnoreWs] = useState(false);
  const [tick, setTick] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [comparing, setComparing] = useState<{ left: string; right: string } | null>(null);
  const [viewing, setViewing] = useState<{ host: HostResult; terminal: RecordedTerminal | undefined } | null>(null);
  const [keeping, setKeeping] = useState(false);
  // FD-03: keeping writes to the journal, which the read-only lock refuses (the core too).
  const readOnly = useReadOnlyReason();
  const running = results ? results.line.finished < results.line.terminals : true;

  async function keep() {
    setKeeping(true);
    try {
      const kept = await api.multiExecKeep(line.id);
      toast.success(
        kept.alreadyKept
          ? "That line was kept already."
          : "Kept as a run: it stays in the results list and in Activity after typing stops.",
      );
      onKept(kept.jobId);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setKeeping(false);
    }
  }

  useEffect(() => {
    let stale = false;
    api.multiExecRecorded(line.id, { ignoreTrailingWhitespace: ignoreWs }).then(
      (r) => {
        if (stale) return;
        setResults(r);
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [line.id, ignoreWs, version, tick]);

  // While a terminal still runs: its time and what it printed so far.
  useEffect(() => {
    if (!running || !active) return;
    const timer = window.setInterval(() => setTick((n) => n + 1), POLL_MS);
    return () => window.clearInterval(timer);
  }, [running, active]);

  if (error && !results) {
    return (
      <p className="text-sm text-destructive" role="alert">
        {error}
      </p>
    );
  }
  if (!results) return <Skeleton className="h-64" />;

  const { counts, groups, hosts, terminals } = results;
  const names = new Map(hosts.map((h) => [h.targetKey, h.name]));
  const byId = new Map(terminals.map((t) => [t.terminalId, t]));
  const done = counts.succeeded + counts.failed + counts.cancelled;
  const notKept = keeping ? "Keeping it…" : keepReason(results.line, readOnly);

  return (
    <div className="grid min-w-0 gap-4">
      <div className="grid min-w-0 gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Badge variant="outline">Typed in {plural(results.line.terminals, "tab")}</Badge>
          {results.line.tier && <TierBadge tier={results.line.tier} />}
          {results.line.waitingApproval && <Badge variant="outline">waiting for approval</Badge>}
          <span className="text-xs text-muted-foreground">
            Recorded {time(results.line.recordedAt)}
            {results.line.durationMs !== null && ` · took ${shortDuration(results.line.durationMs)}`}
          </span>
          <HelpTip topic="recordedLines" />
        </div>
        <pre className="max-h-24 overflow-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs break-words whitespace-pre-wrap">
          {results.line.line}
        </pre>
        <p className="text-lg leading-tight font-semibold break-words" aria-live="polite">
          {results.line.waitingApproval ? "Waiting for approval: Enter is held in every terminal" : results.headline}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {/* QL-31: kept as a run, once every tab has finished it; one kept already offers that run. */}
          {results.line.kept ? (
            <Button variant="outline" size="sm" onClick={() => onKept(line.id)}>
              <ArchiveIcon data-icon="inline-start" />
              Show the kept run
            </Button>
          ) : (
            <WhyDisabled reason={notKept}>
              <Button variant="outline" size="sm" disabled={notKept !== null} onClick={() => void keep()}>
                <ArchiveIcon data-icon="inline-start" />
                Keep this line
              </Button>
            </WhyDisabled>
          )}
          {/* UX-17: only runs retry; a typed line says why it has none. */}
          <WhyDisabled reason={TYPED_NO_RETRY}>
            <Button variant="outline" size="sm" disabled>
              <RotateCcwIcon data-icon="inline-start" />
              Retry
            </Button>
          </WhyDisabled>
          <WhyDisabled reason={diffReason(groups.length)}>
            <Button
              variant="outline"
              size="sm"
              disabled={groups.length < 2}
              onClick={() => setComparing({ left: groups[0].label, right: groups[1].label })}
            >
              <GitCompareArrowsIcon data-icon="inline-start" />
              Compare groups
            </Button>
          </WhyDisabled>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <DownloadIcon data-icon="inline-start" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Save this line as</DropdownMenuLabel>
              {EXPORTS.map((e) => (
                <DropdownMenuItem key={e.format} onSelect={() => void exportLines(line.id, e.format, ignoreWs)}>
                  {e.label}
                </DropdownMenuItem>
              ))}
              <DropdownMenuSeparator />
              <DropdownMenuLabel>Save every typed line as</DropdownMenuLabel>
              {EXPORTS.map((e) => (
                <DropdownMenuItem key={`all-${e.format}`} onSelect={() => void exportLines(null, e.format, ignoreWs)}>
                  {e.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <p className="text-xs text-muted-foreground">{TYPED_KEPT}</p>
      </div>

      <div className="grid gap-2">
        <Progress
          value={counts.total ? (done / counts.total) * 100 : 0}
          aria-label={`${done} of ${counts.total} terminals done`}
        />
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>
            {done} of {plural(counts.total, "terminal")} done
          </span>
          {counts.running > 0 && <span>{counts.running} running</span>}
          {counts.pending > 0 && <span>{counts.pending} waiting for Enter</span>}
          {counts.failed > 0 && <span className="text-destructive">{counts.failed} not finished</span>}
          <span className="ml-auto flex items-center gap-2">
            <Switch id={`ignore-ws-${line.id}`} checked={ignoreWs} onCheckedChange={setIgnoreWs} size="sm" />
            <Label htmlFor={`ignore-ws-${line.id}`} className="text-xs font-normal">
              Ignore trailing whitespace
            </Label>
          </span>
        </div>
        {results.line.fullScreen && (
          <p className="text-xs text-muted-foreground">
            A full-screen program ran: its screens, and the keys sent to it, are not recorded.
          </p>
        )}
      </div>

      {groups.length > 0 && (
        <div className="grid gap-2">
          {groups.map((g, i) => (
            <GroupCard
              key={`${g.label}-${g.sample}`}
              group={g}
              names={g.hosts.map((k) => names.get(k) ?? k)}
              defaultOpen={i < 2 || groups.length <= 4}
              terminals
              badge={<Badge variant="outline">{g.ok ? "prompt back" : "not finished"}</Badge>}
              load={() => api.multiExecRecordedOutput(line.id, g.sample)}
            />
          ))}
        </div>
      )}

      <Collapsible defaultOpen={groups.length === 0 || running} className="grid gap-2">
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm" className="group justify-self-start">
            <ChevronRightIcon
              className="transition-transform group-data-[state=open]:rotate-90"
              data-icon="inline-start"
            />
            Every terminal ({terminals.length})
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="max-h-96 overflow-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Terminal</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Group</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hosts.map((h) => {
                  const t = byId.get(h.targetKey);
                  const state = t ? captureText(t, t.durationMs) : null;
                  return (
                    <TableRow
                      key={h.targetKey}
                      className="cursor-pointer"
                      onClick={() => setViewing({ host: h, terminal: t })}
                    >
                      <TableCell className="whitespace-normal">
                        <div className="font-medium break-words">{h.name}</div>
                        {t?.truncated && <div className="text-xs text-muted-foreground">output cut in the middle</div>}
                      </TableCell>
                      <TableCell className={cn("whitespace-normal", state && TONES[state.tone])}>
                        <span className="inline-flex items-center gap-1.5">
                          {t?.state === "running" && <LoaderCircleIcon className="size-3.5 animate-spin" aria-hidden />}
                          {state?.text ?? h.status}
                        </span>
                      </TableCell>
                      <TableCell>{h.group !== null ? groups[h.group]?.label : "—"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CollapsibleContent>
      </Collapsible>

      {comparing && (
        <OutputDiffDialog
          load={(left, right, options) => api.multiExecRecordedDiff(line.id, left, right, options)}
          groups={groups}
          terminals
          ignoreTrailingWhitespace={ignoreWs}
          left={comparing.left}
          right={comparing.right}
          onClose={() => setComparing(null)}
        />
      )}
      {viewing && (
        <HostOutputDialog
          host={viewing.host}
          load={() => api.multiExecRecordedOutput(line.id, viewing.host.targetKey)}
          description={
            viewing.terminal
              ? `${captureText(viewing.terminal, viewing.terminal.durationMs).text}${
                  viewing.terminal.state === "running" ? " (the output so far)" : ""
                }`
              : undefined
          }
          onClose={() => setViewing(null)}
        />
      )}
    </div>
  );
}
