// QL-12: the Compare panel's MultiExec view. Every line MultiExec sends is recorded in each of its terminals, from
// Enter until that terminal's prompt comes back (crates/core/src/terminal/record.rs), so it can be compared at any
// time without typing it again: the list of lines (newest first, with time, terminals and tier) and, for the line
// picked (or the newest), the same grouped view as a one-shot run: identical outputs grouped A, B..., the diff
// between groups, the ignore-trailing-whitespace switch, each terminal's state as it fills in, and CSV, JSON or HTML
// export of this line or all of them. Recordings live in memory until MultiExec is turned off. FD-03: everything here
// is plain DOM text, so presentation mode masks it like the rest of the page.

import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ChevronRightIcon,
  DownloadIcon,
  GitCompareArrowsIcon,
  LoaderCircleIcon,
  RadioTowerIcon,
  ScissorsIcon,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TierBadge } from "@/components/Badges";
import { GroupCard, HostOutputDialog } from "@/components/BulkResultsView";
import { OutputDiffDialog } from "@/components/OutputDiffDialog";
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
import { capsNote, captureText, lineStatus, shortDuration, shownLine, type CaptureTone } from "@/lib/recordings";
import { cn } from "@/lib/utils";

interface Props {
  active: boolean;
  /** MultiExec is on: lines typed now are recorded. */
  multiExecOn: boolean;
}

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

export function RecordedLinesView({ active, multiExecOn }: Props) {
  const [recordings, setRecordings] = useState<Recordings | null>(null);
  const [picked, setPicked] = useState<string | null>(null);
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

  const lines = recordings?.lines ?? [];
  const shown = shownLine(lines, picked);
  const caps = recordings ? capsNote(recordings.dropped, recordings.limits) : null;

  async function exportAll(format: ExportFormat) {
    await exportLines(null, format, false);
  }

  if (error && !recordings) {
    return (
      <p className="text-sm text-destructive" role="alert">
        {error}
      </p>
    );
  }
  if (!recordings) return <Skeleton className="h-48" />;

  if (lines.length === 0) {
    return (
      <Empty className="border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <RadioTowerIcon />
          </EmptyMedia>
          <EmptyTitle>{multiExecOn ? "No line recorded yet" : "MultiExec is off"}</EmptyTitle>
          <EmptyDescription>
            {multiExecOn
              ? "Type a command in one of the picked terminals. Each terminal's output is recorded until its prompt comes back, and shows here grouped by output."
              : "Turn MultiExec on and type in a terminal: every line goes to the picked terminals and is recorded here, so you can compare the outputs without typing the command again."}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 @5xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
      <div className="grid min-w-0 grid-cols-1 content-start gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h3 className="text-sm font-medium">{plural(lines.length, "recorded line")}</h3>
          {picked && (
            <Button size="xs" variant="ghost" onClick={() => setPicked(null)}>
              Show the newest
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="xs" variant="outline" className="ml-auto">
                <DownloadIcon data-icon="inline-start" />
                Export all
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Save every recorded line as</DropdownMenuLabel>
              {EXPORTS.map((e) => (
                <DropdownMenuItem key={e.format} onSelect={() => void exportAll(e.format)}>
                  {e.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <ul className="grid max-h-[28rem] min-w-0 grid-cols-1 gap-1 overflow-y-auto rounded-md border p-1" role="list">
          {lines.map((l) => (
            <li key={l.id} className="min-w-0">
              <LineItem line={l} selected={l.id === shown?.id} onPick={() => setPicked(l.id)} />
            </li>
          ))}
        </ul>
        {caps && (
          <Alert>
            <ScissorsIcon />
            <AlertDescription className="text-xs">{caps}</AlertDescription>
          </Alert>
        )}
        <p className="text-xs break-words text-muted-foreground">
          Lines typed with MultiExec on are recorded in each terminal, from Enter until its prompt comes back (or its
          output stops for the quiet spell in Settings, or {shortDuration(recordings.limits.lineSecs * 1000)} pass).
          Password prompts and keys sent to full-screen programs are not recorded, and secrets are scrubbed. Recordings
          are kept in memory until MultiExec is turned off.
        </p>
      </div>
      <div className="min-w-0">
        {shown && <RecordedLineResults key={shown.id} line={shown} version={version} active={active} />}
      </div>
    </div>
  );
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

function LineItem({ line, selected, onPick }: { line: RecordedLine; selected: boolean; onPick: () => void }) {
  const running = line.finished < line.terminals;
  return (
    <button
      type="button"
      onClick={onPick}
      aria-current={selected || undefined}
      className={cn(
        "grid w-full min-w-0 gap-1 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent",
        selected && "bg-accent",
      )}
    >
      <span className="flex min-w-0 items-center gap-2">
        {running && <LoaderCircleIcon className="size-3.5 shrink-0 animate-spin" aria-label="Running" />}
        <code className="min-w-0 flex-1 truncate font-mono text-xs" title={line.line}>
          {line.line}
        </code>
        {line.tier && <TierBadge tier={line.tier} />}
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
        <span>{time(line.recordedAt)}</span>
        <span>{plural(line.terminals, "terminal")}</span>
        <span className="min-w-0 truncate">{lineStatus(line)}</span>
      </span>
    </button>
  );
}

function RecordedLineResults({ line, version, active }: { line: RecordedLine; version: number; active: boolean }) {
  const [results, setResults] = useState<RecordedResults | null>(null);
  const [ignoreWs, setIgnoreWs] = useState(false);
  const [tick, setTick] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [comparing, setComparing] = useState<{ left: string; right: string } | null>(null);
  const [viewing, setViewing] = useState<{ host: HostResult; terminal: RecordedTerminal | undefined } | null>(null);
  const running = results ? results.line.finished < results.line.terminals : true;

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

  return (
    <div className="grid min-w-0 gap-4">
      <div className="grid min-w-0 gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {results.line.tier && <TierBadge tier={results.line.tier} />}
          {results.line.waitingApproval && <Badge variant="outline">waiting for approval</Badge>}
          <span className="text-xs text-muted-foreground">
            Recorded {time(results.line.recordedAt)}
            {results.line.durationMs !== null && ` · took ${shortDuration(results.line.durationMs)}`}
          </span>
        </div>
        <pre className="max-h-24 overflow-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs break-words whitespace-pre-wrap">
          {results.line.line}
        </pre>
        <p className="text-lg leading-tight font-semibold break-words" aria-live="polite">
          {results.line.waitingApproval ? "Waiting for approval: Enter is held in every terminal" : results.headline}
        </p>
        <div className="flex flex-wrap items-center gap-2">
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
              <DropdownMenuLabel>Save every recorded line as</DropdownMenuLabel>
              {EXPORTS.map((e) => (
                <DropdownMenuItem key={`all-${e.format}`} onSelect={() => void exportLines(null, e.format, ignoreWs)}>
                  {e.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
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
