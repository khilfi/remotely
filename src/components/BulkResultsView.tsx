// A bulk run's results, live (BX-02 to BX-05): progress and counts, the one-line summary ("48 hosts same,
// 2 differ"), output groups (largest first, each with one host's output standing for all), every host
// with its status, exit code and duration, and the actions: cancel, retry the failed hosts, compare two
// groups and export. Grouping happens in the core; this view reloads it as hosts finish. QL-12: the group cards and
// the output dialog serve the Compare panel's MultiExec view too (terminals instead of hosts).

import { useEffect, useState, type ReactNode } from "react";
import { toast } from "sonner";
import {
  ChevronRightIcon,
  DownloadIcon,
  GitCompareArrowsIcon,
  HourglassIcon,
  LoaderCircleIcon,
  PlayIcon,
  RotateCcwIcon,
  ScissorsIcon,
  SquareIcon,
} from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  api,
  errorMessage,
  type BulkResults,
  type ExportFormat,
  type HostOutput,
  type HostResult,
  type OutputGroup,
  type SubmitOutcome,
} from "@/lib/api";
import { formatWhen, plural } from "@/lib/format";
import { cn } from "@/lib/utils";
import { diffReason } from "@/lib/disabled-reasons";
import { canaryPrompt, retryChoices, timeLeft } from "@/lib/rollout";
import { ConfirmDialog } from "./ConfirmDialog";
import { StatusBadge, TierBadge } from "./Badges";
import { OutputDiffDialog } from "./OutputDiffDialog";
import { WhyDisabled } from "./WhyDisabled";

interface Props {
  jobId: string;
  /** A retry was submitted: the new job (or its approval) is the parent's to follow. */
  onRetry: (outcome: SubmitOutcome) => void;
}

const OPEN = new Set(["queued", "countdown", "running"]);
/** Reloads at most this often while hosts finish. */
const RELOAD_MS = 200;
/** Hosts named on a group's line before "and N more". */
const NAMES_SHOWN = 8;

const EXPORTS: { format: ExportFormat; label: string }[] = [
  { format: "html", label: "HTML report" },
  { format: "csv", label: "CSV (one row per host)" },
  { format: "json", label: "JSON" },
];

function seconds(ms: number | null) {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return ms < 10_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms / 1000)} s`;
}

function bytes(n: number | null) {
  if (n === null) return "";
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function BulkResultsView({ jobId, onRetry }: Props) {
  const [results, setResults] = useState<BulkResults | null>(null);
  const [ignoreWs, setIgnoreWs] = useState(false);
  const [version, setVersion] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [comparing, setComparing] = useState<{ left: string; right: string } | null>(null);
  const [viewing, setViewing] = useState<HostResult | null>(null);
  const [busy, setBusy] = useState(false);
  // H9: the canary host finished; the rest wait for the go-ahead until `until`.
  const [canary, setCanary] = useState<{ name: string; rest: number; until: string } | null>(null);
  const [confirmUnknown, setConfirmUnknown] = useState(false);
  const shown = results?.job.id === jobId ? results : null;
  const open = shown ? OPEN.has(shown.job.status) : true;

  // Hosts finishing -> reload, at most every RELOAD_MS.
  useEffect(() => {
    let timer: number | undefined;
    const unlisten = api.onJobEvent((event) => {
      if (event.jobId !== jobId) return;
      if (event.event === "canaryWaiting") setCanary({ name: event.name, rest: event.rest, until: event.until });
      else if (event.event === "targetStarted" || event.event === "finished") setCanary(null);
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
  }, [jobId]);

  useEffect(() => {
    let stale = false;
    api.bulkResults(jobId, { ignoreTrailingWhitespace: ignoreWs }).then(
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
  }, [jobId, ignoreWs, version]);

  // Running hosts show how long they have been at it (and the canary's wait, how long is left).
  useEffect(() => {
    if (!open) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [open]);

  async function cancel() {
    if (!(await api.cancelJob(jobId))) toast.info("The run has already finished.");
  }

  async function retry(includeUnknown = false) {
    setBusy(true);
    try {
      onRetry(await api.bulkRetryFailed(jobId, includeUnknown));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function goOn() {
    setBusy(true);
    try {
      if (!(await api.bulkGoOn(jobId))) toast.info("The run is no longer waiting.");
      setCanary(null);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function exportAs(format: ExportFormat) {
    try {
      const done = await api.bulkExport(jobId, format, { ignoreTrailingWhitespace: ignoreWs });
      if (!done) return;
      const redacted =
        done.redacted > 0 ? `; ${plural(done.redacted, "text")} had something like a secret, now [redacted]` : "";
      toast.success(`Exported ${plural(done.hosts, "host")} to ${done.path}${redacted}`);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  if (error && !shown) {
    return (
      <p className="text-sm text-destructive" role="alert">
        {error}
      </p>
    );
  }
  if (!shown) return <Skeleton className="h-64" />;

  const { job, counts, groups, hosts, run } = shown;
  const names = new Map(hosts.map((h) => [h.targetKey, h.name]));
  const done = counts.succeeded + counts.failed + counts.cancelled + counts.unknown + counts.skipped;
  const retries = retryChoices(counts);
  const canRetry = !open && retries.failed > 0;
  // H9: the event may have come before this view opened; the results say whether the rest still wait.
  const waiting =
    canary ?? (shown.canaryWaiting ? { name: hosts[0]?.name ?? "The first host", rest: 0, until: "" } : null);

  return (
    <div className="grid gap-4">
      <div className="grid gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={job.status} />
          <TierBadge tier={job.tier} />
          {run?.sudo && <Badge variant="outline">sudo</Badge>}
          {job.retryOf && <Badge variant="outline">retry</Badge>}
          <span className="text-xs text-muted-foreground">{formatWhen(job.startedAt ?? job.createdAt)}</span>
        </div>
        <p className="text-lg leading-tight font-semibold" aria-live="polite">
          {shown.headline}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {open && (
            <Button variant="outline" size="sm" onClick={() => void cancel()}>
              <SquareIcon data-icon="inline-start" />
              Cancel
            </Button>
          )}
          {canRetry && (
            <WhyDisabled reason={busy ? "Submitting the retry…" : null}>
              <Button variant="outline" size="sm" onClick={() => void retry()} disabled={busy}>
                <RotateCcwIcon data-icon="inline-start" />
                Retry {plural(counts.failed, "failed host")}
              </Button>
            </WhyDisabled>
          )}
          {!open && retries.withUnknown !== null && (
            <WhyDisabled reason={busy ? "Submitting the retry…" : null}>
              <Button variant="outline" size="sm" onClick={() => setConfirmUnknown(true)} disabled={busy}>
                <RotateCcwIcon data-icon="inline-start" />
                Retry {retries.failed > 0 ? "them and " : ""}
                {plural(counts.unknown, "host")} with the outcome unknown
              </Button>
            </WhyDisabled>
          )}
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
              <DropdownMenuLabel>Save the results as</DropdownMenuLabel>
              {EXPORTS.map((e) => (
                <DropdownMenuItem key={e.format} onSelect={() => void exportAs(e.format)}>
                  {e.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {open && waiting && (
        <Alert>
          <HourglassIcon />
          <AlertTitle>
            {waiting.rest > 0
              ? canaryPrompt(waiting.name, waiting.rest)
              : `${waiting.name} finished without errors. Run on the other hosts?`}
          </AlertTitle>
          <AlertDescription>
            Check its result below first. Nothing else has run yet.
            {waiting.until && ` The others wait ${timeLeft(waiting.until, now)} more, then the run stops.`}
          </AlertDescription>
          <AlertAction className="flex gap-2">
            <Button size="sm" onClick={() => void goOn()} disabled={busy}>
              <PlayIcon data-icon="inline-start" />
              Run on the rest
            </Button>
            <Button size="sm" variant="outline" onClick={() => void cancel()} disabled={busy}>
              Stop here
            </Button>
          </AlertAction>
        </Alert>
      )}

      <div className="grid gap-2">
        <Progress
          value={counts.total ? (done / counts.total) * 100 : 0}
          aria-label={`${done} of ${counts.total} hosts done`}
        />
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>
            {done} of {plural(counts.total, "host")} done
          </span>
          {counts.succeeded > 0 && <span className="text-success">{counts.succeeded} succeeded</span>}
          {counts.failed > 0 && <span className="text-destructive">{counts.failed} failed</span>}
          {counts.running > 0 && <span>{counts.running} running</span>}
          {counts.pending > 0 && <span>{counts.pending} waiting</span>}
          {counts.unknown > 0 && (
            <span className="text-tier-medium" title="Timed out, or cancelled while the command ran: it may have run">
              {counts.unknown} outcome unknown
            </span>
          )}
          {counts.cancelled > 0 && <span>{counts.cancelled} cancelled</span>}
          {counts.skipped > 0 && <span>{counts.skipped} not started</span>}
          <span className="ml-auto flex items-center gap-2">
            <Switch id={`ignore-ws-${jobId}`} checked={ignoreWs} onCheckedChange={setIgnoreWs} size="sm" />
            <Label htmlFor={`ignore-ws-${jobId}`} className="text-xs font-normal">
              Ignore trailing whitespace
            </Label>
          </span>
        </div>
      </div>

      {run && (
        <pre className="max-h-24 overflow-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs whitespace-pre-wrap">
          {run.script}
        </pre>
      )}

      {groups.length > 0 && (
        <div className="grid gap-2">
          {groups.map((g, i) => (
            <GroupCard
              key={`${g.label}-${g.sample}`}
              group={g}
              names={g.hosts.map((k) => names.get(k) ?? k)}
              defaultOpen={i < 2 || groups.length <= 4}
              load={() => api.bulkHostOutput(jobId, g.sample)}
            />
          ))}
        </div>
      )}

      <Collapsible defaultOpen={groups.length === 0} className="grid gap-2">
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm" className="group justify-self-start">
            <ChevronRightIcon
              className="transition-transform group-data-[state=open]:rotate-90"
              data-icon="inline-start"
            />
            Every host ({hosts.length})
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="max-h-96 overflow-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Exit</TableHead>
                  <TableHead className="text-right">Time</TableHead>
                  <TableHead>Group</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hosts.map((h) => (
                  <TableRow
                    key={h.targetKey}
                    className={h.status === "pending" || h.status === "running" ? undefined : "cursor-pointer"}
                    onClick={() => h.status !== "pending" && h.status !== "running" && setViewing(h)}
                  >
                    <TableCell className="whitespace-normal">
                      <div className="font-medium">{h.name}</div>
                      {h.error && <div className="text-xs text-destructive">{h.error}</div>}
                    </TableCell>
                    <TableCell>
                      <HostStatus host={h} now={now} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{h.exitCode ?? "—"}</TableCell>
                    <TableCell className="text-right tabular-nums">{seconds(h.durationMs)}</TableCell>
                    <TableCell>{h.group !== null ? groups[h.group]?.label : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CollapsibleContent>
      </Collapsible>

      {comparing && (
        <OutputDiffDialog
          load={(left, right, options) => api.bulkDiff(jobId, left, right, options)}
          groups={groups}
          ignoreTrailingWhitespace={ignoreWs}
          left={comparing.left}
          right={comparing.right}
          onClose={() => setComparing(null)}
        />
      )}
      {viewing && (
        <HostOutputDialog
          host={viewing}
          load={() => api.bulkHostOutput(jobId, viewing.targetKey)}
          onClose={() => setViewing(null)}
        />
      )}
      {confirmUnknown && (
        <ConfirmDialog
          title="Run it again where the outcome is unknown?"
          description="Those hosts timed out, or were cancelled while the command ran, so it may have run there already: running it again may run it twice. The retry still asks for its approval."
          confirmLabel="Retry them"
          onConfirm={() => retry(true)}
          onClose={() => setConfirmUnknown(false)}
        />
      )}
    </div>
  );
}

/** Each host's state in a word or two. */
const STATUS_LABEL: Record<HostResult["status"], string> = {
  pending: "Waiting",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
  skipped: "Not started",
  unknown: "Outcome unknown",
};

function HostStatus({ host, now }: { host: HostResult; now: number }) {
  if (host.status === "running") {
    const since = host.startedAt ? Math.max(0, Math.floor((now - new Date(host.startedAt).getTime()) / 1000)) : null;
    return (
      <span className="inline-flex items-center gap-1.5 text-sm">
        <LoaderCircleIcon className="size-3.5 animate-spin" aria-hidden />
        Running{since !== null && ` ${since} s`}
      </span>
    );
  }
  const className = {
    pending: "text-muted-foreground",
    succeeded: "text-success",
    failed: "text-destructive",
    cancelled: "text-muted-foreground",
    skipped: "text-muted-foreground",
    unknown: "text-tier-medium",
  }[host.status];
  const label = STATUS_LABEL[host.status];
  return <span className={cn("text-sm", className)}>{label}</span>;
}

/**
 * BX-03: one output group, with its sample's output. QL-12 `terminals`: a MultiExec line's group, whose members are
 * terminals with no exit code, and whose error groups (time limit, lost) show what was recorded until then.
 */
export function GroupCard({
  group,
  names,
  defaultOpen,
  load: loadOutput,
  terminals = false,
  badge,
}: {
  group: OutputGroup;
  names: string[];
  defaultOpen: boolean;
  /** The sample's whole output, when it did not come with the results. */
  load: () => Promise<HostOutput>;
  terminals?: boolean;
  /** Replaces the exit-code badge of an output group. */
  badge?: ReactNode;
}) {
  const [loaded, setLoaded] = useState<HostOutput | null>(null);
  const stdout = group.stdout ?? loaded?.stdout ?? null;
  const stderr = group.stderr ?? loaded?.stderr ?? null;
  const more = names.length - NAMES_SHOWN;
  const unit = terminals ? "terminal" : "host";
  const showsOutput = group.kind === "output" || (terminals && Boolean(stdout));

  async function load() {
    try {
      setLoaded(await loadOutput());
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  return (
    <Collapsible defaultOpen={defaultOpen} className="rounded-lg border">
      <CollapsibleTrigger asChild>
        <button type="button" className="group flex w-full items-start gap-3 p-3 text-left">
          <ChevronRightIcon className="mt-1 size-4 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
          <span
            className={cn(
              "grid size-7 shrink-0 place-items-center rounded-md border text-sm font-semibold",
              group.ok ? "border-success/40 text-success" : "border-destructive/40 text-destructive",
            )}
          >
            {group.label}
          </span>
          <span className="grid min-w-0 flex-1 gap-1">
            <span className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{plural(group.hosts.length, unit)}</span>
              {group.kind === "output" ? (
                (badge ?? <Badge variant={group.ok ? "outline" : "destructive"}>exit {group.exitCode ?? "?"}</Badge>)
              ) : (
                <Badge variant="destructive">{group.errorCode?.replace(/_/g, " ") ?? "failed"}</Badge>
              )}
              {group.truncated && (
                <Badge variant="outline" className="font-normal">
                  <ScissorsIcon />
                  output cut
                </Badge>
              )}
            </span>
            <span className="truncate text-xs text-muted-foreground">
              {names.slice(0, NAMES_SHOWN).join(", ")}
              {more > 0 && ` and ${more} more`}
            </span>
            {group.error && (
              <span className="text-sm text-destructive">
                {group.error}
                {group.messagesDiffer && ` (the message differs a little per ${unit}; see Every ${unit})`}
              </span>
            )}
          </span>
        </button>
      </CollapsibleTrigger>
      {showsOutput && (
        <CollapsibleContent className="grid gap-2 px-3 pb-3">
          {stdout === null ? (
            <Button variant="outline" size="sm" className="justify-self-start" onClick={() => void load()}>
              Show the output
            </Button>
          ) : (
            <OutputText stdout={stdout} stderr={stderr ?? ""} />
          )}
          {group.truncated && (
            <p className="text-xs text-muted-foreground">
              The output was long, so its middle was cut: the first and last 32 KB are kept.{" "}
              {terminals ? "Terminals" : "Hosts"} still group by their whole output.
            </p>
          )}
        </CollapsibleContent>
      )}
    </Collapsible>
  );
}

export function OutputText({ stdout, stderr }: { stdout: string; stderr: string }) {
  return (
    <div className="grid gap-2">
      {stdout === "" && stderr === "" && <p className="text-xs text-muted-foreground">No output.</p>}
      {stdout !== "" && (
        <pre className="max-h-80 overflow-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs whitespace-pre-wrap">
          {stdout}
        </pre>
      )}
      {stderr !== "" && (
        <div className="grid gap-1">
          <span className="text-xs font-medium text-muted-foreground">stderr</span>
          <pre className="max-h-60 overflow-auto rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 font-mono text-xs whitespace-pre-wrap">
            {stderr}
          </pre>
        </div>
      )}
    </div>
  );
}

/** One host's (or, QL-12, one terminal's) whole output. `load` is called once, when the dialog opens. */
export function HostOutputDialog({
  host,
  load,
  onClose,
  description,
}: {
  host: HostResult;
  load: () => Promise<HostOutput>;
  onClose: () => void;
  /** Replaces the status line under the title. */
  description?: string;
}) {
  const [output, setOutput] = useState<HostOutput | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadOnce] = useState(() => load);

  useEffect(() => {
    let stale = false;
    loadOnce().then(
      (o) => {
        if (!stale) setOutput(o);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [loadOnce]);

  const sizes = [host.stdoutBytes, host.stderrBytes].some((b) => b)
    ? ` · ${bytes(host.stdoutBytes ?? 0)} out, ${bytes(host.stderrBytes ?? 0)} err`
    : "";
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{host.name}</DialogTitle>
          <DialogDescription>
            {description ?? (
              <>
                {STATUS_LABEL[host.status]}
                {host.exitCode !== null && ` · exit code ${host.exitCode}`} · {seconds(host.durationMs)}
                {sizes}
              </>
            )}
          </DialogDescription>
        </DialogHeader>
        {host.error && (
          <p className={cn("text-sm", host.status === "unknown" ? "text-tier-medium" : "text-destructive")}>
            {host.error}
          </p>
        )}
        {(host.peerIp || host.hostKey) && (
          <p className="text-xs text-muted-foreground">
            {host.peerIp && (
              <>
                Reached <span data-mask="ip">{host.peerIp}</span>
              </>
            )}
            {host.peerIp && host.hostKey && ", "}
            {host.hostKey && <span className="font-mono">host key {host.hostKey}</span>}
          </p>
        )}
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        {output ? (
          <OutputText stdout={output.stdout} stderr={output.stderr} />
        ) : (
          !error && <Skeleton className="h-32" />
        )}
        {output?.truncated && (
          <p className="text-xs text-muted-foreground">
            The middle of a long output was cut; the first and last 32 KB are kept.
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}
