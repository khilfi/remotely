// BX-03 Compare output, in the Terminal page (post-MVP P6; it replaces the Bulk run page). One command runs once on
// each host of the picked tabs and of the sessions picked in the tree, as a one-shot job through the bulk engine
// (exec channels, not the terminals; BX-02 to BX-07): the parallel limit, sudo with a password from the vault, the
// approval tier shown while typing and the dangerous-command rules (BX-06), then the results grouped by output ("48
// same, 2 differ"), the diff between two groups, retry of the failed hosts and CSV, JSON or HTML export. Hosts are
// saved sessions: a tab of a quick connection that was not saved can't be reached. QL-08: Run says why it is
// disabled.

import { useEffect, useMemo, useState } from "react";
import { KeyRoundIcon, OctagonAlertIcon, PlayIcon, SquareTerminalIcon, XIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/Badges";
import { BulkResultsView } from "@/components/BulkResultsView";
import { WhyDisabled } from "@/components/WhyDisabled";
import { usePresentation } from "@/components/Presentation";
import {
  api,
  errorMessage,
  type ApprovalStep,
  type Command,
  type CommandPreview,
  type JobSummary,
  type ResolvedTargets,
  type SecretMeta,
  type SubmitOutcome,
  type VaultInfo,
} from "@/lib/api";
import { compareRunReason } from "@/lib/disabled-reasons";
import { formatWhen, plural } from "@/lib/format";
import { readOnlyLocked } from "@/lib/presentation-state";

interface Props {
  active: boolean;
  vault: VaultInfo | null;
  /** The picked tabs' terminals (each reaches its saved session). */
  terminalIds: string[];
  /** Sessions picked in the tree, with no tab needed. */
  sessionIds: string[];
  /** How many of the picked tabs are quick connections that were not saved. */
  unsavedTabs: number;
  /** Saved sessions on this computer. */
  savedSessions: number;
  onClearTree: () => void;
  /** Goes through the app, which opens the approval dialog; `onJob` gets the job id once queued. */
  onSubmit: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenVault: () => void;
  onClose: () => void;
}

/** sudo gets each session's own login password. */
const LOGIN = "login";
const DEFAULT_TIMEOUT = "600";
/** Hosts named in the summary before "and N more". */
const NAMES_SHOWN = 6;

function stepsText(steps: ApprovalStep[]) {
  if (steps.length === 0) return "Runs at once; logged.";
  if (steps.some((s) => s.step === "vaultReauth")) return "Needs every approval step and the vault password.";
  if (steps.some((s) => s.step === "reason")) return "Needs the target count typed, a reason and a countdown.";
  return "Needs one confirm.";
}

export function ComparePanel({
  active,
  vault,
  terminalIds,
  sessionIds,
  unsavedTabs,
  savedSessions,
  onClearTree,
  onSubmit,
  onOpenVault,
  onClose,
}: Props) {
  // FD-03: Run says why it is off while the read-only lock applies.
  const presentation = usePresentation();
  const [resolved, setResolved] = useState<ResolvedTargets | null>(null);
  const [script, setScript] = useState("");
  const [sudo, setSudo] = useState(false);
  const [sudoPassword, setSudoPassword] = useState(LOGIN);
  const [trustNew, setTrustNew] = useState(false);
  const [timeout, setTimeoutText] = useState(DEFAULT_TIMEOUT);
  const [preview, setPreview] = useState<{ key: string; preview: CommandPreview } | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [parallel, setParallel] = useState<number | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [runs, setRuns] = useState<JobSummary[]>([]);
  const [runsVersion, setRunsVersion] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const picksKey = JSON.stringify([terminalIds, sessionIds]);
  const hosts = useMemo(() => resolved?.hosts ?? [], [resolved]);
  const timeoutSecs = timeout.trim() === "" ? null : Number(timeout);
  const timeoutOk =
    timeoutSecs === null || (Number.isInteger(timeoutSecs) && timeoutSecs >= 1 && timeoutSecs <= 86_400);
  const command: Command = {
    type: "remoteExec",
    targets: hosts.map((h) => ({ kind: "session", sessionId: h.sessionId })),
    script,
    sudo,
    sudoPasswordId: sudo && sudoPassword !== LOGIN ? sudoPassword : null,
    trustNewHostKeys: trustNew,
    timeoutSecs: timeoutOk ? timeoutSecs : null,
  };
  const commandKey = JSON.stringify(command);
  const shownPreview = script.trim() && preview?.key === commandKey ? preview.preview : null;
  const notReady = compareRunReason({
    savedSessions,
    picked: terminalIds.length + sessionIds.length,
    hosts,
    unsavedTabs,
    script,
    timeoutOk,
    submitting,
    readOnly: readOnlyLocked(presentation),
  });

  useEffect(() => {
    if (!active) return;
    let stale = false;
    Promise.all([api.secrets(), api.settings()]).then(
      ([s, settings]) => {
        if (stale) return;
        setSecrets(s.filter((x) => x.kind === "password"));
        setParallel(settings.bulkParallelLimit);
      },
      () => {},
    );
    return () => {
      stale = true;
    };
  }, [active]);

  // BX-01: the hosts the picked tabs and tree sessions reach.
  useEffect(() => {
    let stale = false;
    const [terminals, sessions] = JSON.parse(picksKey) as [string[], string[]];
    api.bulkTargets({ terminalIds: terminals, sessionIds: sessions }).then(
      (r) => {
        if (!stale) setResolved(r);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [picksKey, active]);

  // BX-06: the tier and any dangerous-command rule, shown while typing.
  useEffect(() => {
    if (!script.trim()) return;
    let stale = false;
    const parsed = JSON.parse(commandKey) as Command;
    const timer = window.setTimeout(() => {
      api.bulkPreview(parsed).then(
        (p) => {
          if (!stale) setPreview({ key: commandKey, preview: p });
        },
        () => {},
      );
    }, 250);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [commandKey, script]);

  // Earlier runs; again whenever a run ends.
  useEffect(() => {
    if (!active) return;
    let stale = false;
    api.bulkRuns(20).then(
      (r) => {
        if (!stale) setRuns(r);
      },
      () => {},
    );
    return () => {
      stale = true;
    };
  }, [active, runsVersion, jobId]);

  useEffect(() => {
    const unlisten = api.onJobEvent((event) => {
      if (event.event === "queued" || event.event === "finished") setRunsVersion((v) => v + 1);
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  async function run() {
    if (notReady) return;
    setSubmitting(true);
    setError(null);
    try {
      onSubmit(await api.submit(command), setJobId);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  const vaultLocked = vault?.status !== "unlocked";
  const runCount = hosts.filter((h) => !h.protected).length;
  const protectedCount = hosts.length - runCount;
  const names = hosts.map((h) => h.name);
  const shownNames =
    names.length > NAMES_SHOWN
      ? `${names.slice(0, NAMES_SHOWN).join(", ")} and ${names.length - NAMES_SHOWN} more`
      : names.join(", ");

  return (
    <div className="flex h-full min-h-0 flex-col rounded-lg border bg-background">
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b px-3 py-2">
        <h2 className="text-sm font-semibold">Compare output</h2>
        <span className="min-w-0 flex-1 truncate text-sm text-muted-foreground" title={names.join(", ")}>
          {hosts.length === 0
            ? "Pick tabs (Ctrl+click), or sessions in the tree (Ctrl+click), to run on."
            : `Runs once on ${plural(runCount, "host")}: ${shownNames}`}
          {protectedCount > 0 && ` (${protectedCount} protected, skipped)`}
        </span>
        <Badge variant="outline" className="font-normal">
          {plural(terminalIds.length, "tab")}
        </Badge>
        <Badge variant="outline" className="font-normal">
          {plural(sessionIds.length, "tree session")}
        </Badge>
        {sessionIds.length > 0 && (
          <Button size="xs" variant="ghost" onClick={onClearTree}>
            Clear the tree picks
          </Button>
        )}
        <Button variant="ghost" size="icon-sm" aria-label="Close Compare output" onClick={onClose}>
          <XIcon />
        </Button>
      </div>
      <ScrollArea className="@container min-h-0 flex-1">
        <div className="grid gap-4 p-3 @5xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
          <div className="grid content-start gap-3">
            {resolved && resolved.notes.length > 0 && (
              <Alert>
                <SquareTerminalIcon />
                <AlertTitle>Not every pick can run the command</AlertTitle>
                <AlertDescription>
                  <ul className="list-disc pl-4">
                    {resolved.notes.map((n) => (
                      <li key={n}>{n}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
            <div className="grid gap-1.5">
              <Label htmlFor="compare-script">
                Command or script{parallel ? `, on up to ${parallel} hosts at once` : ""} (Ctrl+Enter runs it)
              </Label>
              <Textarea
                id="compare-script"
                rows={4}
                spellCheck={false}
                className="font-mono text-xs"
                placeholder={"uptime\ndf -h /"}
                value={script}
                onChange={(e) => setScript(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    void run();
                  }
                }}
              />
              <p className="text-xs text-muted-foreground">
                Each host runs it once in its own login shell (not in the terminals), and the results are grouped by
                output.
              </p>
            </div>

            {shownPreview && (
              <div className="grid gap-2">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <TierBadge tier={shownPreview.tier} />
                  <span className="text-muted-foreground">{stepsText(shownPreview.steps)}</span>
                </div>
                {shownPreview.dangerous.length > 0 && (
                  <Alert className="border-tier-high/40">
                    <OctagonAlertIcon className="text-tier-high" />
                    <AlertTitle>Flagged dangerous, so it needs approval</AlertTitle>
                    <AlertDescription>
                      <ul className="grid gap-1">
                        {shownPreview.dangerous.map((d) => (
                          <li key={d.rule}>
                            Line {d.line}: <code className="font-mono text-xs">{d.text}</code> matches &ldquo;{d.rule}
                            &rdquo;
                          </li>
                        ))}
                      </ul>
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            )}

            <div className="grid gap-3 rounded-md border p-3">
              <div className="flex items-center gap-3">
                <Switch id="compare-sudo" checked={sudo} onCheckedChange={setSudo} />
                <Label htmlFor="compare-sudo" className="font-normal">
                  Run with sudo
                </Label>
              </div>
              {sudo && (
                <div className="grid gap-1.5 pl-12">
                  <Label htmlFor="compare-sudo-password" className="font-normal text-muted-foreground">
                    Password for sudo, from the vault
                  </Label>
                  <Select value={sudoPassword} onValueChange={setSudoPassword}>
                    <SelectTrigger id="compare-sudo-password" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={LOGIN}>Each session&apos;s login password</SelectItem>
                      {secrets.length > 0 && <SelectSeparator />}
                      {secrets.map((s) => (
                        <SelectItem key={s.id} value={s.id}>
                          {s.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Given to sudo on its input, never typed or shown. A host that refuses it is reported on its own.
                  </p>
                </div>
              )}
              <div className="flex items-start gap-3">
                <Checkbox
                  id="compare-trust"
                  className="mt-0.5"
                  checked={trustNew}
                  onCheckedChange={(v) => setTrustNew(v === true)}
                />
                <div className="grid gap-0.5">
                  <Label htmlFor="compare-trust" className="font-normal">
                    Trust new host keys
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    A run can&apos;t ask, so a host whose key is not trusted yet fails unless this is on. Each key it
                    trusts is logged. A changed key always blocks the host.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Label htmlFor="compare-timeout" className="font-normal">
                  Time limit per host
                </Label>
                <Input
                  id="compare-timeout"
                  className="w-24"
                  inputMode="numeric"
                  value={timeout}
                  onChange={(e) => setTimeoutText(e.currentTarget.value)}
                  aria-invalid={!timeoutOk || undefined}
                />
                <span className="text-sm text-muted-foreground">seconds (empty: none)</span>
              </div>
            </div>

            {vaultLocked && (
              <Alert>
                <KeyRoundIcon />
                <AlertTitle>
                  {vault?.status === "notSetUp" ? "The vault is not set up" : "The vault is locked"}
                </AlertTitle>
                <AlertDescription>
                  Hosts that log in with a saved password or key, and sudo, need the vault unlocked.
                </AlertDescription>
                <AlertAction>
                  <Button size="sm" variant="outline" onClick={onOpenVault}>
                    Vault
                  </Button>
                </AlertAction>
              </Alert>
            )}
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <div className="flex items-center gap-2">
              <WhyDisabled reason={notReady}>
                <Button onClick={() => void run()} disabled={notReady !== null}>
                  <PlayIcon data-icon="inline-start" />
                  {runCount > 0 ? `Run on ${plural(runCount, "host")}` : "Run"}
                </Button>
              </WhyDisabled>
              {runs.length > 0 && (
                <Select value={jobId ?? ""} onValueChange={(id) => setJobId(id || null)}>
                  <SelectTrigger className="min-w-0 flex-1" aria-label="Open an earlier run">
                    <SelectValue placeholder="Earlier runs…" />
                  </SelectTrigger>
                  <SelectContent>
                    {runs.map((r) => (
                      <SelectItem key={r.id} value={r.id}>
                        <span className="truncate font-mono text-xs">
                          {r.retryOf && "Retry: "}
                          {r.summary}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {r.targetsSucceeded}/{r.targetsTotal} · {formatWhen(r.createdAt)}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          </div>

          <div className="min-w-0">
            {jobId ? (
              <BulkResultsView key={jobId} jobId={jobId} onRetry={(outcome) => onSubmit(outcome, setJobId)} />
            ) : (
              <Empty className="border">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <SquareTerminalIcon />
                  </EmptyMedia>
                  <EmptyTitle>No run open</EmptyTitle>
                  <EmptyDescription>
                    Type a command and run it: hosts with the same exit code and output are grouped, so 50 hosts read
                    like a few answers. Or open an earlier run.
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
