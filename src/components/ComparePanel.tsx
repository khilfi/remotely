// BX-03 Compare output, in the Terminal page (post-MVP P6; it replaces the Bulk run page). One command runs once on
// each host of the picked tabs and of the sessions picked in the tree, as a one-shot job through the bulk engine
// (exec channels, not the terminals; BX-02 to BX-07): the parallel limit, sudo with a password from the vault, the
// approval tier shown while typing and the dangerous-command rules (BX-06), then the results grouped by output ("48
// same, 2 differ"), the diff between two groups, retry of the failed hosts and CSV, JSON or HTML export. Hosts are
// saved sessions: a tab of a quick connection that was not saved can't be reached. QL-08: Run says why it is
// disabled.
//
// QL-12: a second view, MultiExec, shows the lines MultiExec recorded in the terminals, grouped the same way
// (RecordedLinesView), so a line typed in the terminals can be compared without typing it again here.
// BX-03 layout: one column up to a 64rem wide panel, two above it; every column and track can shrink (minmax(0, ...),
// min-w-0), so long text wraps or truncates inside its column instead of running into the results, and the panel
// scrolls natively (Radix ScrollArea sizes its content like a table, which let it grow past the panel).

import { useEffect, useMemo, useState } from "react";
import {
  ChevronRightIcon,
  KeyRoundIcon,
  OctagonAlertIcon,
  PlayIcon,
  RadioTowerIcon,
  SquareTerminalIcon,
} from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/Badges";
import { BulkResultsView } from "@/components/BulkResultsView";
import { HelpTip } from "@/components/HelpTip";
import { RecordedLinesView } from "@/components/RecordedLinesView";
import { WhyDisabled } from "@/components/WhyDisabled";
import { usePresentation } from "@/components/Presentation";
import { useDebounced } from "@/hooks/use-debounced";
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
import { EmptyState } from "@/components/EmptyState";
import { compareRunReason, sudoWindowsReason } from "@/lib/disabled-reasons";
import { formatWhen, plural } from "@/lib/format";
import { readOnlyLocked } from "@/lib/presentation-state";
import { compareOptionsSummary, parseStopAfter } from "@/lib/rollout";
import { cn } from "@/lib/utils";

/** QL-12: a one-shot run here, or the lines MultiExec recorded in the terminals. */
export type CompareView = "run" | "multiExec";

interface Props {
  active: boolean;
  vault: VaultInfo | null;
  view: CompareView;
  onViewChange: (view: CompareView) => void;
  /** MultiExec is on: lines typed in the picked terminals are recorded. */
  multiExecOn: boolean;
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
  view,
  onViewChange,
  multiExecOn,
  terminalIds,
  sessionIds,
  unsavedTabs,
  savedSessions,
  onClearTree,
  onSubmit,
  onOpenVault,
}: Props) {
  // FD-03: Run says why it is off while the read-only lock applies.
  const presentation = usePresentation();
  const [resolved, setResolved] = useState<ResolvedTargets | null>(null);
  const [script, setScript] = useState("");
  const [sudo, setSudo] = useState(false);
  const [sudoPassword, setSudoPassword] = useState(LOGIN);
  const [trustNew, setTrustNew] = useState(false);
  const [timeout, setTimeoutText] = useState(DEFAULT_TIMEOUT);
  // H9: blast radius. Both off by default: a non-zero exit is normal for read-only checks (grep, test).
  const [canary, setCanary] = useState(false);
  const [stopAfter, setStopAfter] = useState("");
  /** UX-04: the options fold into one line until opened. */
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [preview, setPreview] = useState<{ key: string; preview: CommandPreview } | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [parallel, setParallel] = useState<number | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [runs, setRuns] = useState<JobSummary[]>([]);
  const [runsVersion, setRunsVersion] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const recorded = useRecordedCount(active);

  const picksKey = JSON.stringify([terminalIds, sessionIds]);
  const hosts = useMemo(() => resolved?.hosts ?? [], [resolved]);
  const timeoutSecs = timeout.trim() === "" ? null : Number(timeout);
  const timeoutOk =
    timeoutSecs === null || (Number.isInteger(timeoutSecs) && timeoutSecs >= 1 && timeoutSecs <= 86_400);
  const stopAfterParsed = parseStopAfter(stopAfter);
  // BX-13: sudo is a Linux host's; over WinRM, PowerShell runs as the session's sign-in user.
  const windowsHosts = hosts.filter((h) => h.scriptKind === "powerShell").length;
  const sudoReason = windowsHosts > 0 ? sudoWindowsReason(windowsHosts) : null;
  const sudoOn = sudo && sudoReason === null;
  const command: Command = {
    type: "remoteExec",
    targets: hosts.map((h) => ({ kind: "session", sessionId: h.sessionId })),
    script,
    sudo: sudoOn,
    sudoPasswordId: sudoOn && sudoPassword !== LOGIN ? sudoPassword : null,
    trustNewHostKeys: trustNew,
    timeoutSecs: timeoutOk ? timeoutSecs : null,
    rollout: { canary, stopAfterFailures: stopAfterParsed.value },
  };
  const optionsSummary = compareOptionsSummary({
    sudo: sudoOn,
    trustNewKeys: trustNew,
    timeoutSecs: timeoutOk ? timeoutSecs : Number(DEFAULT_TIMEOUT),
    defaultTimeoutSecs: Number(DEFAULT_TIMEOUT),
    canary,
    stopAfter: stopAfterParsed.value,
  });
  const commandKey = JSON.stringify(command);
  const shownPreview = script.trim() && preview?.key === commandKey ? preview.preview : null;
  const notReady = compareRunReason({
    savedSessions,
    picked: terminalIds.length + sessionIds.length,
    hosts,
    unsavedTabs,
    script,
    timeoutOk,
    stopAfterOk: stopAfterParsed.ok,
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
    // BX-13: WinRM hosts too: their commands run in PowerShell, rated by the PowerShell rules.
    api.bulkTargets({ terminalIds: terminals, sessionIds: sessions, winrm: true }).then(
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

  // Earlier runs; again whenever a run ends, once per burst of job events (BX-03).
  const settledRuns = useDebounced(runsVersion);
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
  }, [active, settledRuns, jobId]);

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

  /** Where the hosts come from: "2 tabs and 3 sessions from the tree". */
  const sources = [
    terminalIds.length > 0 && plural(terminalIds.length, "tab"),
    sessionIds.length > 0 && `${plural(sessionIds.length, "session")} from the tree`,
  ]
    .filter(Boolean)
    .join(" and ");

  return (
    <div className="flex h-full min-h-0 flex-col rounded-lg border bg-background">
      <div className="grid shrink-0 gap-2 border-b px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="flex items-center gap-1 text-sm font-semibold">
            Compare hosts
            <HelpTip topic="compareHosts" />
          </h2>
          <Tabs value={view} onValueChange={(v) => onViewChange(v as CompareView)} className="ml-auto">
            <TabsList>
              <TabsTrigger value="run">One-shot run</TabsTrigger>
              <TabsTrigger value="multiExec">
                <RadioTowerIcon />
                Type in all tabs
                {recorded > 0 && (
                  <Badge variant="secondary" className="ml-0.5 h-4 min-w-4 px-1 text-[10px] tabular-nums">
                    {recorded}
                  </Badge>
                )}
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
        {view === "run" ? (
          <div className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground">
            <span className="min-w-0 flex-1 truncate" title={names.join(", ")}>
              {hosts.length === 0
                ? "Ctrl+click tabs, or sessions in the tree, to run on them."
                : `Runs once on ${plural(runCount, "host")}: ${shownNames}`}
              {protectedCount > 0 && ` (${protectedCount} protected, skipped)`}
              {sources && hosts.length > 0 && <span className="text-xs"> · {sources}</span>}
            </span>
            {sessionIds.length > 0 && (
              <Button size="sm" variant="ghost" onClick={onClearTree}>
                Clear the tree picks
              </Button>
            )}
          </div>
        ) : (
          <p className="truncate text-sm text-muted-foreground">
            {multiExecOn
              ? "Each line typed in all tabs, with what each terminal answered."
              : "Type in all tabs is off: turning it on starts a new recording."}
          </p>
        )}
      </div>
      <div className="@container min-h-0 flex-1 overflow-y-auto">
        <div className="p-3">
          {view === "multiExec" ? (
            <RecordedLinesView active={active} multiExecOn={multiExecOn} />
          ) : (
            <div className="grid grid-cols-1 gap-4 @5xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
              <div className="grid min-w-0 grid-cols-1 content-start gap-3">
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
                  <Label htmlFor="compare-script" title="Ctrl+Enter runs it">
                    Command or script{parallel ? `, on up to ${parallel} hosts at once` : ""}
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
                                Line {d.line}: <code className="font-mono text-xs">{d.text}</code> matches &ldquo;
                                {d.rule}
                                &rdquo;
                              </li>
                            ))}
                          </ul>
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                )}

                <Collapsible open={optionsOpen} onOpenChange={setOptionsOpen} className="rounded-md border">
                  <CollapsibleTrigger asChild>
                    <button
                      type="button"
                      className="flex w-full min-w-0 items-center gap-2 rounded-md px-3 py-2 text-left text-sm hover:bg-muted/60"
                    >
                      <ChevronRightIcon
                        className={cn("size-4 shrink-0 transition-transform", optionsOpen && "rotate-90")}
                        aria-hidden
                      />
                      <span className="font-medium">Options</span>
                      <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">{optionsSummary}</span>
                    </button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="grid gap-3 border-t p-3">
                    <div className="flex items-center gap-3">
                      <WhyDisabled reason={sudoReason}>
                        <Switch
                          id="compare-sudo"
                          checked={sudoOn}
                          onCheckedChange={setSudo}
                          disabled={sudoReason !== null}
                        />
                      </WhyDisabled>
                      <Label htmlFor="compare-sudo" className="font-normal">
                        Run with sudo
                      </Label>
                    </div>
                    {sudoOn && (
                      <div className="grid min-w-0 gap-1.5 pl-12">
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
                        <p className="text-xs break-words text-muted-foreground">
                          Given to sudo, never typed or shown.
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
                      <div className="grid min-w-0 gap-0.5">
                        <Label htmlFor="compare-trust" className="font-normal">
                          Trust new host keys
                        </Label>
                        <p className="text-xs break-words text-muted-foreground">
                          Else a host with a key not trusted yet fails. A changed key always blocks.
                        </p>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
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
                    <div className="flex items-start gap-3">
                      <Checkbox
                        id="compare-canary"
                        className="mt-0.5"
                        checked={canary}
                        onCheckedChange={(v) => setCanary(v === true)}
                      />
                      <div className="grid min-w-0 gap-0.5">
                        <Label htmlFor="compare-canary" className="font-normal">
                          Run on one host first
                        </Label>
                        <p className="text-xs break-words text-muted-foreground">
                          You see its result before the others run.
                        </p>
                      </div>
                    </div>
                    <div className="grid gap-0.5">
                      <div className="flex flex-wrap items-center gap-3">
                        <Label htmlFor="compare-stop-after" className="font-normal">
                          Stop after
                        </Label>
                        <Input
                          id="compare-stop-after"
                          className="w-20"
                          inputMode="numeric"
                          placeholder="never"
                          value={stopAfter}
                          onChange={(e) => setStopAfter(e.currentTarget.value)}
                          aria-invalid={!stopAfterParsed.ok || undefined}
                        />
                        <span className="text-sm text-muted-foreground">failures (empty: never)</span>
                      </div>
                      <p className="text-xs break-words text-muted-foreground">Hosts already running finish.</p>
                    </div>
                  </CollapsibleContent>
                </Collapsible>

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
                <div className="grid min-w-0 grid-cols-1 gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <WhyDisabled reason={notReady}>
                      <Button onClick={() => void run()} disabled={notReady !== null}>
                        <PlayIcon data-icon="inline-start" />
                        {runCount > 0 ? `Run on ${plural(runCount, "host")}` : "Run"}
                      </Button>
                    </WhyDisabled>
                  </div>
                  {runs.length > 0 && (
                    <Select value={jobId ?? ""} onValueChange={(id) => setJobId(id || null)}>
                      <SelectTrigger className="w-full min-w-0" aria-label="Open an earlier run">
                        <SelectValue placeholder="Earlier runs…" />
                      </SelectTrigger>
                      <SelectContent className="max-w-[min(36rem,90vw)]">
                        {runs.map((r) => (
                          <SelectItem key={r.id} value={r.id}>
                            <span className="min-w-0 truncate font-mono text-xs">
                              {r.retryOf && "Retry: "}
                              {r.summary}
                            </span>
                            <span className="shrink-0 text-xs text-muted-foreground">
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
                  <EmptyState
                    icon={SquareTerminalIcon}
                    title="No run open"
                    description="Run a command: hosts with the same output are grouped together. Or open an earlier run."
                  />
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** QL-12: how many lines MultiExec has recorded, for the view switch. */
function useRecordedCount(active: boolean) {
  const [count, setCount] = useState(0);
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const unlisten = api.onMultiExecEvent((event) => {
      if (event.event === "recorded") setVersion((v) => v + 1);
    });
    return () => void unlisten.then((stop) => stop());
  }, []);
  useEffect(() => {
    if (!active) return;
    let stale = false;
    api.multiExecRecordings().then(
      (r) => {
        if (!stale) setCount(r.lines.length);
      },
      () => undefined,
    );
    return () => {
      stale = true;
    };
  }, [active, version]);
  return count;
}
