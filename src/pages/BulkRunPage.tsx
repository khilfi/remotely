// Bulk run (BX-01 to BX-07): pick hosts, type a command or script, see its approval tier and any
// dangerous-command rule it matches before it runs, run it (through the command bus, so the policy
// engine and the approval dialog decide), then follow the results live, grouped by output. Earlier runs
// can be opened again from the list.

import { useEffect, useState } from "react";
import { KeyRoundIcon, OctagonAlertIcon, PlayIcon, SquareTerminalIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge, TierBadge } from "@/components/Badges";
import { BulkResultsView } from "@/components/BulkResultsView";
import { BulkTargetPicker } from "@/components/BulkTargetPicker";
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
import { formatWhen, plural } from "@/lib/format";

interface Props {
  active: boolean;
  vault: VaultInfo | null;
  /** Goes through the app, which opens the approval dialog; `onJob` gets the job id once queued. */
  onSubmit: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenVault: () => void;
  onOpenSessions: () => void;
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

export function BulkRunPage({ active, vault, onSubmit, onOpenVault, onOpenSessions }: Props) {
  const [picks, setPicks] = useState<TargetPicks>({});
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

  const hosts = resolved?.hosts ?? [];
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
  const runnable = hosts.some((h) => !h.protected) && script.trim() !== "" && timeoutOk && !submitting;

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

  // BX-01: the hosts the picks reach.
  useEffect(() => {
    let stale = false;
    api.bulkTargets(picks).then(
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
  }, [picks, active]);

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
    if (!runnable) return;
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

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,30rem)_minmax(0,1fr)]">
      <div className="grid content-start gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Hosts</CardTitle>
            <CardDescription>
              Pick saved sessions, VMs (through the session linked to each), tags or saved filters. Each host runs the
              command once.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <BulkTargetPicker
              active={active}
              picks={picks}
              onPicksChange={setPicks}
              resolved={resolved}
              onOpenSessions={onOpenSessions}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Command</CardTitle>
            <CardDescription>
              One command or a script of several lines, run by each host&apos;s login shell
              {parallel ? `, on up to ${parallel} hosts at once` : ""}. Ctrl+Enter runs it.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            <Textarea
              aria-label="Command or script"
              rows={6}
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
                <Switch id="bulk-sudo" checked={sudo} onCheckedChange={setSudo} />
                <Label htmlFor="bulk-sudo" className="font-normal">
                  Run with sudo
                </Label>
              </div>
              {sudo && (
                <div className="grid gap-1.5 pl-12">
                  <Label htmlFor="bulk-sudo-password" className="font-normal text-muted-foreground">
                    Password for sudo, from the vault
                  </Label>
                  <Select value={sudoPassword} onValueChange={setSudoPassword}>
                    <SelectTrigger id="bulk-sudo-password" className="w-full">
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
                  id="bulk-trust"
                  className="mt-0.5"
                  checked={trustNew}
                  onCheckedChange={(v) => setTrustNew(v === true)}
                />
                <div className="grid gap-0.5">
                  <Label htmlFor="bulk-trust" className="font-normal">
                    Trust new host keys
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    A run can&apos;t ask, so a host whose key is not trusted yet fails unless this is on. Each key it
                    trusts is logged. A changed key always blocks the host.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Label htmlFor="bulk-timeout" className="font-normal">
                  Time limit per host
                </Label>
                <Input
                  id="bulk-timeout"
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
          </CardContent>
          <CardFooter>
            <Button onClick={() => void run()} disabled={!runnable}>
              <PlayIcon data-icon="inline-start" />
              {runCount > 0 ? `Run on ${plural(runCount, "host")}` : "Run"}
            </Button>
          </CardFooter>
        </Card>
      </div>

      <div className="grid content-start gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Results</CardTitle>
            <CardDescription>
              Hosts with the same exit code and output are grouped, so 50 hosts read like a few answers.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {jobId ? (
              <BulkResultsView key={jobId} jobId={jobId} onRetry={(outcome) => onSubmit(outcome, setJobId)} />
            ) : (
              <Empty>
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <SquareTerminalIcon />
                  </EmptyMedia>
                  <EmptyTitle>No run open</EmptyTitle>
                  <EmptyDescription>
                    Pick hosts, type a command and run it, or open an earlier run below.
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
          </CardContent>
        </Card>

        {runs.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Earlier runs</CardTitle>
            </CardHeader>
            <CardContent>
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead>Command</TableHead>
                    <TableHead className="w-28">Hosts</TableHead>
                    <TableHead className="w-32">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runs.map((r) => (
                    <TableRow
                      key={r.id}
                      className="cursor-pointer"
                      data-state={r.id === jobId ? "selected" : undefined}
                      onClick={() => setJobId(r.id)}
                    >
                      <TableCell title={r.summary}>
                        <div className="truncate font-mono text-xs">
                          {r.retryOf && <span className="mr-1 font-sans text-muted-foreground">Retry:</span>}
                          {r.summary}
                        </div>
                        <div className="text-xs text-muted-foreground">{formatWhen(r.createdAt)}</div>
                      </TableCell>
                      <TableCell className="tabular-nums">
                        {r.targetsSucceeded}/{r.targetsTotal}
                        {r.targetsFailed > 0 && (
                          <div className="text-xs text-destructive">{r.targetsFailed} failed</div>
                        )}
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={r.status} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
