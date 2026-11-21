// BX-03 Compare output, in the Terminal page (post-MVP P6; it replaces the Bulk run page). One command runs once on
// each host picked, as a one-shot job through the bulk engine
// (exec channels, not the terminals; BX-02 to BX-07): the parallel limit, sudo with a password from the vault, the
// approval tier shown while typing and the dangerous-command rules (BX-06), then the results grouped by output ("48
// same, 2 differ"), the diff between two groups, retry of the failed hosts and CSV, JSON or HTML export. Hosts are
// saved sessions: a tab of a quick connection that was not saved can't be reached. QL-08: Run says why it is
// disabled.
// UX-16 (0.9.0 H2): the hosts are picked with BulkTargetPicker in its compact mode, the one picker of every bulk job:
// it opens filled with the picked tabs and the tree's Ctrl+clicks (the tree's picks are its sessions), and Change…
// adds sessions, VMs, tags, saved filters and saved groups. BX-01: the Sessions and VMs pages' "Run a command on
// these…" open it with their selection.
//
// UX-17 (0.9.0 H3): one results list under Run, newest first, of the one-shot jobs on hosts (its runs, and BX-10's
// pushes and fetches, whoever started them: the list follows the bulk jobs' events) and the lines typed in all tabs
// (QL-12, recorded in the terminals), each badged "Run on 12 hosts" or "Typed in 6 tabs" (lib/results-list.ts). The
// one picked, or the newest, opens beside it in the same grouped card: BulkResultsView for a run, with retry of the
// failed hosts and the canary's go-ahead; RecordedLineResults for a typed line, whose Retry says why it has none and
// which goes when typing stops. Turning Type in all tabs on shows the newest again.
// QL-31 (0.9.0 H7): a typed line kept as a run ("Keep this line") lists among the runs, badged "Kept from 6 tabs",
// and opens in BulkResultsView without retry; its typed original leaves the list once the kept run is listed, and the
// panel shows the kept run as soon as the line is kept.
// BX-03 layout: one column up to a 64rem wide panel, two above it; every column and track can shrink (minmax(0, ...),
// min-w-0), so long text wraps or truncates inside its column instead of running into the results, and the panel
// scrolls natively (Radix ScrollArea sizes its content like a table, which let it grow past the panel).

import { useEffect, useMemo, useState } from "react";
import {
  ChevronRightIcon,
  KeyRoundIcon,
  LoaderCircleIcon,
  OctagonAlertIcon,
  PlayIcon,
  ScissorsIcon,
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
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/Badges";
import { BulkResultsView } from "@/components/BulkResultsView";
import { BulkTargetPicker } from "@/components/BulkTargetPicker";
import { HelpTip } from "@/components/HelpTip";
import { RecordedLineResults, useRecordings } from "@/components/RecordedLinesView";
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
  type TargetPicks,
  type VaultInfo,
} from "@/lib/api";
import { pickCount, type TabsPart } from "@/lib/bulk-picks";
import { requestLink } from "@/lib/links";
import { EmptyState } from "@/components/EmptyState";
import { compareRunReason, sudoWindowsReason } from "@/lib/disabled-reasons";
import { formatWhen, plural } from "@/lib/format";
import { changesJobList, progressesJob, PROGRESS_READ_MS } from "@/lib/job-events";
import { readOnlyLocked } from "@/lib/presentation-state";
import { capsNote } from "@/lib/recordings";
import {
  itemBadge,
  itemKey,
  itemRunning,
  itemStatus,
  itemTitle,
  resultItems,
  shownKey,
  shownResult,
  type ResultItem,
} from "@/lib/results-list";
import { compareOptionsSummary, parseStopAfter } from "@/lib/rollout";
import { cn } from "@/lib/utils";

interface Props {
  active: boolean;
  vault: VaultInfo | null;
  /** MultiExec is on: lines typed in the picked terminals are recorded. */
  multiExecOn: boolean;
  /**
   * UX-16: what the run reaches: the picked tabs' terminals (each reaches its saved session), and the picker's picks
   * (its sessions are the tree's Ctrl+clicks too).
   */
  picks: TargetPicks;
  /** The picker changed its picks (tabs are picked on the tab row, so `terminalIds` is ignored). */
  onPicksChange: (picks: TargetPicks) => void;
  /** The tabs in `picks.terminalIds`, for the summary: picked ones, or the current tab. */
  tabs: TabsPart;
  /** UX-16: changes when a saved group changes (Manage groups), so its picks are resolved again before a run. */
  groupsKey?: string;
  /** How many of the picked tabs are quick connections that were not saved. */
  unsavedTabs: number;
  /** Saved sessions on this computer. */
  savedSessions: number;
  /** Goes through the app, which opens the approval dialog; `onJob` gets the job id once queued. */
  onSubmit: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenVault: () => void;
}

/** sudo gets each session's own login password. */
const LOGIN = "login";
const DEFAULT_TIMEOUT = "600";

function stepsText(steps: ApprovalStep[]) {
  if (steps.length === 0) return "Runs at once; logged.";
  if (steps.some((s) => s.step === "vaultReauth")) return "Needs every approval step and the vault password.";
  if (steps.some((s) => s.step === "reason")) return "Needs the target count typed, a reason and a countdown.";
  return "Needs one confirm.";
}

export function ComparePanel({
  active,
  vault,
  multiExecOn,
  picks,
  onPicksChange,
  tabs,
  groupsKey = "",
  unsavedTabs,
  savedSessions,
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
  const [runs, setRuns] = useState<JobSummary[]>([]);
  const [runsVersion, setRunsVersion] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** The picker asked for the hosts again with the same picks (a link it just confirmed). */
  const [resolveAgain, setResolveAgain] = useState(0);
  // UX-17: the one results list (runs and typed lines) and the item picked in it (`run:<id>`, `typed:<id>`); none
  // picked shows the newest.
  const typed = useRecordings(active, multiExecOn);
  const items = useMemo(() => resultItems(runs, typed.recordings?.lines ?? []), [runs, typed.recordings]);
  const [picked, setPicked] = useState<string | null>(null);
  const shown = shownResult(items, picked);
  const openRun = (jobId: string) => setPicked(itemKey("run", jobId));
  // QL-31: a line just kept shows as its run, and the list reads its runs again (a keep is no job event).
  const openKept = (jobId: string) => {
    setPicked(itemKey("kept", jobId));
    setRunsVersion((v) => v + 1);
  };
  // Turning Type in all tabs on shows the newest again, so its first line shows as it is recorded.
  const [typingSeen, setTypingSeen] = useState(multiExecOn);
  if (multiExecOn !== typingSeen) {
    setTypingSeen(multiExecOn);
    if (multiExecOn) setPicked(null);
  }
  const caps = typed.recordings ? capsNote(typed.recordings.dropped, typed.recordings.limits) : null;

  // BX-13: WinRM hosts too: their commands run in PowerShell, rated by the PowerShell rules.
  const picksKey = JSON.stringify({ ...picks, winrm: true });
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
    picked: pickCount(picks),
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

  // BX-01, UX-16: the hosts the picks reach.
  useEffect(() => {
    let stale = false;
    api.bulkTargets(JSON.parse(picksKey) as TargetPicks).then(
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
    // groupsKey: a picked group edited in Manage groups runs on its members as they are now.
  }, [picksKey, active, resolveAgain, groupsKey]);

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

  // Earlier runs, pushes and fetches (BX-03); UX-17: by the jobs' events, whoever started them (a push from the Files
  // page or a drop shows here too). Read again as a job is queued, counts down, starts, finishes a host or ends, so the
  // list's status words keep up with the card beside it; asks join for a second (as Activity's), so a 50-host run reads
  // it at most once a second.
  const settledRuns = useDebounced(runsVersion, PROGRESS_READ_MS, PROGRESS_READ_MS);
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
  }, [active, settledRuns]);

  useEffect(() => {
    const unlisten = api.onJobEvent((event) => {
      if (changesJobList(event) || progressesJob(event)) setRunsVersion((v) => v + 1);
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  async function run() {
    if (notReady) return;
    setSubmitting(true);
    setError(null);
    try {
      onSubmit(await api.submit(command), openRun);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  const vaultLocked = vault?.status !== "unlocked";
  const runCount = hosts.filter((h) => !h.protected).length;

  return (
    <div className="flex h-full min-h-0 flex-col rounded-lg border bg-background">
      <div className="grid shrink-0 gap-2 border-b px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="flex items-center gap-1 text-sm font-semibold">
            Compare hosts
            <HelpTip topic="compareHosts" />
          </h2>
        </div>
      </div>
      <div className="@container min-h-0 flex-1 overflow-y-auto">
        <div className="p-3">
          <div className="grid grid-cols-1 gap-4 @5xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
            <div className="grid min-w-0 grid-cols-1 content-start gap-3">
              {/* UX-16: the one host picker, as one line until Change… */}
              <BulkTargetPicker
                active={active}
                picks={picks}
                onPicksChange={(next) => {
                  setResolveAgain((n) => n + 1);
                  onPicksChange(next);
                }}
                resolved={resolved}
                onOpenSessions={() => requestLink({ kind: "page", page: "sessions" })}
                winrm
                compact={{ tabs }}
                refresh={groupsKey}
                hideNotes
              />
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
                      <p className="text-xs break-words text-muted-foreground">Given to sudo, never typed or shown.</p>
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
                        Else a host with a key not trusted yet fails (a Windows host&apos;s HTTPS certificate counts as
                        its key). A changed key always blocks.
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
              </div>

              {/* UX-17: one list, newest first, of runs and typed lines. */}
              {items.length > 0 && (
                <section className="grid min-w-0 grid-cols-1 gap-2" aria-label="Results">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <h3 className="text-sm font-medium">Results</h3>
                    <span className="text-xs text-muted-foreground">{plural(items.length, "item")}, newest first</span>
                    {picked && shownKey(shown) !== items[0]?.key && (
                      <Button size="xs" variant="ghost" className="ml-auto" onClick={() => setPicked(null)}>
                        Show the newest
                      </Button>
                    )}
                  </div>
                  <ul
                    className="grid max-h-[28rem] min-w-0 grid-cols-1 gap-1 overflow-y-auto rounded-md border p-1"
                    role="list"
                  >
                    {items.map((item) => (
                      <li key={item.key} className="min-w-0">
                        <ResultRow
                          item={item}
                          selected={item.key === shownKey(shown)}
                          onPick={() => setPicked(item.key)}
                        />
                      </li>
                    ))}
                  </ul>
                  {caps && (
                    <Alert>
                      <ScissorsIcon />
                      <AlertDescription className="text-xs">{caps}</AlertDescription>
                    </Alert>
                  )}
                </section>
              )}
              {/* QL-12: the typed lines couldn't be read (the runs still list). */}
              {typed.error && (
                <p className="text-sm text-destructive" role="alert">
                  Could not read the typed lines: {typed.error}
                </p>
              )}
            </div>

            <div className="min-w-0">
              {/* QL-31: a kept line is a run without retry, shown by the same view. */}
              {shown?.kind === "run" || shown?.kind === "kept" ? (
                <BulkResultsView
                  key={shown.jobId}
                  jobId={shown.jobId}
                  onRetry={(outcome) => onSubmit(outcome, openRun)}
                />
              ) : shown?.kind === "typed" ? (
                <RecordedLineResults
                  key={shown.line.id}
                  line={shown.line}
                  version={typed.version}
                  active={active}
                  onKept={openKept}
                />
              ) : (
                <EmptyState
                  icon={SquareTerminalIcon}
                  title="No results yet"
                  description={
                    multiExecOn
                      ? "Run a command, or type a line in one of the picked terminals: hosts and terminals with the same output are grouped together."
                      : "Run a command: hosts with the same output are grouped together. Lines typed in all tabs show here too."
                  }
                />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/** "10:42" today, "18 Nov, 10:42" before; the full date and time on hover. */
function shortWhen(ts: string) {
  const at = new Date(ts);
  const time = at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (at.toDateString() === new Date().toDateString()) return time;
  return `${at.toLocaleDateString([], { day: "numeric", month: "short" })}, ${time}`;
}

/** UX-17: one item of the results list: what it was, its badge, when, and where it stands. */
function ResultRow({ item, selected, onPick }: { item: ResultItem; selected: boolean; onPick: () => void }) {
  const title = itemTitle(item);
  const tier = item.kind === "typed" ? item.line.tier : item.job.tier;
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
        {itemRunning(item) && <LoaderCircleIcon className="size-3.5 shrink-0 animate-spin" aria-label="Running" />}
        <code className="min-w-0 flex-1 truncate font-mono text-xs" title={title}>
          {title}
        </code>
        {tier && <TierBadge tier={tier} />}
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        <Badge variant="outline" className="font-normal">
          {itemBadge(item)}
        </Badge>
        <time dateTime={item.at} title={formatWhen(item.at)}>
          {shortWhen(item.at)}
        </time>
        <span className="min-w-0 truncate">{itemStatus(item)}</span>
      </span>
    </button>
  );
}
