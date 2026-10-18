// Approval dialog (AP-02, AP-03, AP-06, VM-05, VM-07): draws the steps the policy engine asked for, the
// impact preview of each VM target and any warnings found before the action. After approval it shows
// the countdown, which can be cancelled until it ends. The core checks every answer again; these
// fields only help the user get them right first time.

import { useEffect, useRef, useState } from "react";
import { InfoIcon, ShieldAlertIcon, TimerIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, errorMessage, type ApprovalRequest, type ApprovalStep, type TargetImpact } from "@/lib/api";
import { formatDuration, plural } from "@/lib/format";
import { EnvBadge, StateBadge, TierBadge } from "./Badges";

interface Props {
  request: ApprovalRequest;
  /** Called with the job id once approved, or null when the user cancels before approving. */
  onClose: (jobId: string | null) => void;
}

function find<S extends ApprovalStep["step"]>(steps: ApprovalStep[], step: S) {
  return steps.find((s) => s.step === step) as Extract<ApprovalStep, { step: S }> | undefined;
}

function targetKey(target: ApprovalRequest["targets"][number]["target"]) {
  if (target.kind === "vm") return target.vmxPath;
  if (target.kind === "session") return target.sessionId;
  return "app";
}

/** After approval: the job waits until `until` and can be cancelled meanwhile (AP-03). */
type Countdown = { jobId: string; until: number; seconds: number };

export function ApprovalDialog({ request, onClose }: Props) {
  const { steps, tier } = request;
  const snapshot = find(steps, "safetySnapshot");
  const typeCount = find(steps, "typeTargetCount");
  const needsReason = Boolean(find(steps, "reason"));
  const countdownStep = find(steps, "countdown");
  const reauth = Boolean(find(steps, "vaultReauth"));
  const risky = tier === "high" || tier === "critical";
  const impact = new Map<string, TargetImpact>(request.impact.map((i) => [i.target, i]));
  const hasVms = request.targets.some((t) => t.target.kind === "vm");

  const [safetySnapshot, setSafetySnapshot] = useState(snapshot?.defaultOn ?? false);
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [countdown, setCountdown] = useState<Countdown | null>(null);

  const ready =
    (!typeCount || Number(typed) === typeCount.expected) &&
    (!needsReason || reason.trim() !== "") &&
    (!reauth || password !== "");

  async function approve() {
    setBusy(true);
    setError(null);
    try {
      const jobId = await api.approve(request.id, {
        // Pressing the approve button is the confirmation (AP-03).
        confirmed: true,
        typedTargetCount: typeCount ? Number(typed) : undefined,
        reason: needsReason ? reason : undefined,
        safetySnapshot: snapshot ? safetySnapshot : undefined,
        vaultPassword: reauth ? password : undefined,
      });
      setPassword("");
      if (countdownStep && countdownStep.seconds > 0) {
        const seconds = countdownStep.seconds;
        setCountdown({ jobId, seconds, until: Date.now() + seconds * 1000 });
      } else {
        onClose(jobId);
      }
    } catch (err) {
      // The request stays pending on a wrong answer, so the user can correct it.
      setError(errorMessage(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    try {
      await api.cancelApproval(request.id);
    } finally {
      onClose(null);
    }
  }

  if (countdown) {
    return <CountdownView countdown={countdown} summary={request.summary} onClose={() => onClose(countdown.jobId)} />;
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && void cancel()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <TierBadge tier={tier} />
            <DialogTitle>{request.summary}</DialogTitle>
          </div>
          <DialogDescription asChild>
            <ul className="list-disc space-y-0.5 pl-5">
              {request.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-1.5">
          <div className="max-h-64 overflow-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  {hasVms && (
                    <>
                      <TableHead>State</TableHead>
                      <TableHead>Up for</TableHead>
                      <TableHead className="text-right">Snapshots</TableHead>
                    </>
                  )}
                  <TableHead className="w-20">Label</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {request.targets.map((t) => {
                  const key = targetKey(t.target);
                  const now = impact.get(key);
                  return (
                    <TableRow key={key}>
                      <TableCell className="whitespace-normal">
                        <div className="font-medium">{t.name}</div>
                        {t.target.kind === "vm" && (
                          <div className="font-mono text-xs break-all text-muted-foreground">{t.target.vmxPath}</div>
                        )}
                        {now?.notes.map((note) => (
                          <div key={note} className="text-xs text-tier-medium">
                            {note}
                          </div>
                        ))}
                      </TableCell>
                      {hasVms && (
                        <>
                          <TableCell>
                            {now ? (
                              <StateBadge state={now.powerState} />
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell
                            className="tabular-nums"
                            title={
                              now?.runningSince ? `Since ${new Date(now.runningSince).toLocaleString()}` : undefined
                            }
                          >
                            {now?.uptimeSecs != null ? (
                              formatDuration(now.uptimeSecs)
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell className="text-right tabular-nums">
                            {now?.snapshotCount != null ? now.snapshotCount : "—"}
                            {(now?.oldSnapshotCount ?? 0) > 0 && (
                              <Badge variant="outline" className="ml-1.5 border-tier-medium/40 text-tier-medium">
                                {now?.oldSnapshotCount} old
                              </Badge>
                            )}
                          </TableCell>
                        </>
                      )}
                      <TableCell>
                        <EnvBadge env={t.environment} />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          {hasVms && (
            <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
              <InfoIcon className="mt-px size-3.5 shrink-0" aria-hidden />
              <span>
                Up for is how long each VM has run since it was last powered on or resumed. Not shown yet: users logged
                in to each guest (that needs a guest login) and VMs that depend on these (that needs lab blueprints).
              </span>
            </p>
          )}
        </div>

        {request.warnings.length > 0 && (
          <Alert className="border-tier-medium/40">
            <TriangleAlertIcon className="text-tier-medium" />
            <AlertTitle>Read this before you go on</AlertTitle>
            <AlertDescription>
              <ul className="list-disc pl-5">
                {request.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}

        {request.skipped.length > 0 && (
          <Alert>
            <ShieldAlertIcon />
            <AlertTitle>{plural(request.skipped.length, "protected target")} will be skipped</AlertTitle>
            <AlertDescription>{request.skipped.map((t) => t.name).join(", ")}</AlertDescription>
          </Alert>
        )}

        <div className="grid gap-4">
          {snapshot && (
            <div className="flex items-start gap-2">
              <Checkbox
                id="approval-snapshot"
                checked={safetySnapshot}
                onCheckedChange={(checked) => setSafetySnapshot(checked === true)}
              />
              <div className="grid gap-1">
                <Label htmlFor="approval-snapshot">Take a safety snapshot of each VM first</Label>
                <p className="text-xs text-muted-foreground">
                  Every VM gets one with the same name, starting &ldquo;Remotely safety&rdquo;, so a single revert
                  undoes this job. A VM whose safety snapshot fails is left untouched.
                </p>
              </div>
            </div>
          )}

          {typeCount && (
            <div className="grid gap-2">
              <Label htmlFor="approval-count">Type the number of targets ({typeCount.expected}) to confirm</Label>
              <Input
                id="approval-count"
                className="w-32"
                inputMode="numeric"
                autoComplete="off"
                value={typed}
                onChange={(e) => setTyped(e.currentTarget.value)}
              />
            </div>
          )}

          {needsReason && (
            <div className="grid gap-2">
              <Label htmlFor="approval-reason">Reason or ticket number</Label>
              <Input id="approval-reason" value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
            </div>
          )}

          {reauth && (
            <div className="grid gap-2">
              <Label htmlFor="approval-password">Vault password (Critical actions ask for it again)</Label>
              <Input
                id="approval-password"
                type="password"
                autoComplete="off"
                value={password}
                onChange={(e) => setPassword(e.currentTarget.value)}
              />
            </div>
          )}

          {countdownStep && countdownStep.seconds > 0 && (
            <p className="text-sm text-muted-foreground">
              After you approve, the action waits {countdownStep.seconds} seconds and can be cancelled until then, here
              or in Activity.
            </p>
          )}

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => void cancel()} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={risky ? "destructive" : "default"}
            onClick={() => void approve()}
            disabled={!ready || busy}
            autoFocus={tier === "medium"}
          >
            {risky ? "Approve" : "Confirm"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** AP-03: the approved job's countdown, cancellable until it ends. Closes when the job starts or ends. */
function CountdownView({
  countdown,
  summary,
  onClose,
}: {
  countdown: Countdown;
  summary: string;
  onClose: () => void;
}) {
  const [now, setNow] = useState(() => Date.now());
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const left = Math.max(0, Math.ceil((countdown.until - now) / 1000));
  // The parent passes a new function on every render; the listener below must not resubscribe for it.
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  });

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now());
      // The start event should close this first; this covers one that was missed.
      if (Date.now() > countdown.until + 3000) close.current();
    }, 250);
    return () => window.clearInterval(timer);
  }, [countdown.until]);

  // The job has started (or was cancelled from Activity): nothing left to cancel here.
  useEffect(() => {
    const unlisten = api.onJobEvent((event) => {
      if (event.jobId === countdown.jobId && (event.event === "started" || event.event === "finished")) {
        close.current();
      }
    });
    return () => void unlisten.then((stop) => stop());
  }, [countdown.jobId]);

  async function cancelJob() {
    setCancelling(true);
    setError(null);
    try {
      if (!(await api.cancelJob(countdown.jobId))) setError("The job has already finished.");
    } catch (err) {
      setError(errorMessage(err));
      setCancelling(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <TimerIcon className="size-4 text-tier-high" aria-hidden />
            <DialogTitle>Starts in {left} s</DialogTitle>
          </div>
          <DialogDescription>
            {summary}. Nothing has been done yet; cancel now and no target is touched. You can also cancel it from
            Activity until the countdown ends.
          </DialogDescription>
        </DialogHeader>
        <Progress
          value={((countdown.seconds - left) / countdown.seconds) * 100}
          aria-label={`${left} seconds before the action starts`}
        />
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button variant="destructive" onClick={() => void cancelJob()} disabled={cancelling} autoFocus>
            {cancelling ? "Cancelling…" : "Cancel the action"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
