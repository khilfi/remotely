// Approval dialog (AP-02, AP-03, AP-06, VM-05, VM-07): draws the steps the policy engine asked for, the
// impact preview of each VM target and any warnings found before the action. For a remote command it
// shows the whole script, how it runs (sudo, host keys, time limit) and the dangerous-command rules it
// matched (BX-02, BX-06, BX-07). A Critical action asks for
// the vault password again; without a vault it points to the Vault page. After approval it shows
// the countdown, which can be cancelled until it ends. The core checks every answer again; these
// fields only help the user get them right first time.
//
// SS-10: a MultiExec line comes here too, held at Enter (or another key that runs it, `exec.runKey`): it shows the
// line and the terminals it is typed into, and the caller answers it through MultiExec (`approve`, `cancel`), which
// sends that key, or Ctrl+C to clear the line.
// SS-08: an upload shows the host folder and its files, marking the ones that replace a file there.
// SS-07: a tunnel shows where it listens, where it leads and who can use it (a network address is called out).
// QL-08: a disabled button says why.

import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { InfoIcon, KeyRoundIcon, OctagonAlertIcon, ShieldAlertIcon, TimerIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { DeployPreviewView } from "@/components/DeployPreviewView";
import {
  api,
  changedRequest,
  errorCode,
  errorMessage,
  type ApprovalAnswers,
  type ApprovalRequest,
  type ApprovalStep,
  type ContainerImpact,
  type TargetImpact,
  type VaultInfo,
} from "@/lib/api";
import { containerTargetKey, formatBytes } from "@/lib/containers";
import { rolloutText } from "@/lib/rollout";
import { isLoopback } from "@/lib/tunnels";
import { approveReason } from "@/lib/disabled-reasons";
import { formatDuration, plural } from "@/lib/format";
import { targetLocation } from "@/lib/hypervisors";
import { formatSize } from "@/lib/transfers";
import { ContainerStateBadge, EnvBadge, StateBadge, TierBadge } from "./Badges";
import { WhyDisabled } from "./WhyDisabled";

interface Props {
  request: ApprovalRequest;
  /** AP-06: Critical actions need the vault password, so the vault must be set up. */
  vault: VaultInfo | null;
  /** Cancels this approval and opens the Vault page. */
  onOpenVault: () => void;
  /** Called with the job id once approved, or null when the user cancels before approving. */
  onClose: (jobId: string | null) => void;
  /** Called as soon as the job is queued, before any countdown ends. */
  onApproved?: (jobId: string) => void;
  /** SS-10: answers a held MultiExec line instead of the bus directly; returns the job. */
  approve?: (answers: ApprovalAnswers) => Promise<string>;
  /** SS-10: cancels it (the terminals get Ctrl+C). */
  cancel?: () => Promise<void>;
}

function find<S extends ApprovalStep["step"]>(steps: ApprovalStep[], step: S) {
  return steps.find((s) => s.step === step) as Extract<ApprovalStep, { step: S }> | undefined;
}

function targetKey(target: ApprovalRequest["targets"][number]["target"]) {
  if (target.kind === "vm") return target.vmxPath;
  if (target.kind === "session") return target.sessionId;
  if (target.kind === "terminal") return target.terminalId;
  if (target.kind === "container") return containerTargetKey(target);
  if (target.kind === "newVm") return `new-vm/${target.hypervisor}/${target.name}`;
  return "app";
}

/** CT-01, CT-02: what a container target is and what it touches. */
function ContainerImpactLines({ impact }: { impact: ContainerImpact }) {
  return (
    <div className="grid gap-0.5 text-xs text-muted-foreground">
      {impact.image && <div>Image {impact.image}</div>}
      {impact.ports.length > 0 && <div>Ports {impact.ports.join(", ")}</div>}
      {impact.usedBy.length > 0 && <div>Used by {impact.usedBy.join(", ")}</div>}
      {impact.removes.length > 0 && (
        <div className="text-tier-high">
          Removes:
          <ul className="list-disc pl-4">
            {impact.removes.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </div>
      )}
      {impact.kind === "engine" && impact.removes.length === 0 && impact.usedBy.length === 0 && (
        <div>Nothing listed to remove</div>
      )}
    </div>
  );
}

/** After approval: the job waits until `until` and can be cancelled meanwhile (AP-03). */
type Countdown = { jobId: string; until: number; seconds: number };

export function ApprovalDialog({
  request: asked,
  vault,
  onOpenVault,
  onClose,
  onApproved,
  approve: approveWith,
  cancel: cancelWith,
}: Props) {
  // AP-01: the core may ask again (a target became Prod or protected meanwhile) under the same id: the new request
  // replaces this one. Another request from the caller (another id) is shown as it comes.
  const [askedAgain, setRequest] = useState<ApprovalRequest | null>(null);
  const request = askedAgain?.id === asked.id ? askedAgain : asked;
  const { steps, tier } = request;
  const snapshot = find(steps, "safetySnapshot");
  const typeCount = find(steps, "typeTargetCount");
  const needsReason = Boolean(find(steps, "reason"));
  const countdownStep = find(steps, "countdown");
  const reauth = Boolean(find(steps, "vaultReauth"));
  const risky = tier === "high" || tier === "critical";
  const impact = new Map<string, TargetImpact>(request.impact.map((i) => [i.target, i]));
  const hasVms = request.targets.some((t) => t.target.kind === "vm");
  // CT-01, CT-02: containers show their state, image and uptime; images and volumes what uses them.
  const hasContainers = request.impact.some((i) => i.container);

  const [safetySnapshot, setSafetySnapshot] = useState(snapshot?.defaultOn ?? false);
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [noVault, setNoVault] = useState(false);
  const [busy, setBusy] = useState(false);
  const [countdown, setCountdown] = useState<Countdown | null>(null);
  // AP-01: the approval waited too long and is gone in the core; only Cancel is left.
  const [expired, setExpired] = useState(false);
  const vaultMissing = reauth && (noVault || vault?.status === "notSetUp");

  const ready =
    (!typeCount || Number(typed) === typeCount.expected) &&
    (!needsReason || reason.trim() !== "") &&
    (!reauth || password !== "");
  const notReady = expired
    ? "This approval expired: start the action again"
    : approveReason({ steps, typedCount: typed, reason, password, busy });
  // FD-01: the first answer to type gets the focus, and Enter in any of them approves once all are
  // right (the same as pressing Approve).
  const firstField = typeCount ? "count" : needsReason ? "reason" : reauth ? "password" : null;
  const enterApproves = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && ready && !busy && !expired) {
      e.preventDefault();
      void approve();
    }
  };

  async function approve() {
    setBusy(true);
    setError(null);
    try {
      const answers: ApprovalAnswers = {
        // Pressing the approve button is the confirmation (AP-03).
        confirmed: true,
        typedTargetCount: typeCount ? Number(typed) : undefined,
        reason: needsReason ? reason : undefined,
        safetySnapshot: snapshot ? safetySnapshot : undefined,
        vaultPassword: reauth ? password : undefined,
      };
      const jobId = approveWith ? await approveWith(answers) : await api.approve(request.id, answers);
      setPassword("");
      onApproved?.(jobId);
      if (countdownStep && countdownStep.seconds > 0) {
        const seconds = countdownStep.seconds;
        setCountdown({ jobId, seconds, until: Date.now() + seconds * 1000 });
      } else {
        onClose(jobId);
      }
    } catch (err) {
      // The request stays pending on a wrong answer, so the user can correct it.
      setError(errorMessage(err));
      const again = changedRequest(err);
      if (again) {
        // Asked again under the same id: the answers start over, for what the action would do now.
        setRequest(again);
        setTyped("");
        setReason("");
        setSafetySnapshot(find(again.steps, "safetySnapshot")?.defaultOn ?? false);
      }
      setExpired(errorCode(err) === "approval_expired");
      setNoVault(errorCode(err) === "vault_not_set_up");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    try {
      await (cancelWith ? cancelWith() : api.cancelApproval(request.id));
    } finally {
      onClose(null);
    }
  }

  async function openVault() {
    try {
      await (cancelWith ? cancelWith() : api.cancelApproval(request.id));
    } finally {
      onOpenVault();
    }
  }

  if (countdown) {
    return <CountdownView countdown={countdown} summary={request.summary} onClose={() => onClose(countdown.jobId)} />;
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && void cancel()}>
      {/* VM-24: a long list of files to delete must not push Approve and Cancel off a small window. */}
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-3xl">
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

        {request.exec && <ExecSummary exec={request.exec} targets={request.targets.length} />}
        {request.upload && <UploadSummary upload={request.upload} />}
        {request.tunnel && <TunnelSummary tunnel={request.tunnel} />}
        {/* VM-21: the VMs a deploy makes, where, and the disk they may take; its warnings are listed below. */}
        {request.deploy && <DeployPreviewView preview={request.deploy} showWarnings={false} />}
        {request.vmChange && <VmChangeSummary change={request.vmChange} />}

        <div className="grid gap-1.5" hidden={request.deploy !== null}>
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
                  {hasContainers && (
                    <>
                      <TableHead>State</TableHead>
                      <TableHead>Now</TableHead>
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
                          <div className="font-mono text-xs break-all text-muted-foreground">
                            {targetLocation(t.target.vmxPath)}
                          </div>
                        )}
                        {now?.container && <ContainerImpactLines impact={now.container} />}
                        {now?.notes.map((note) => (
                          <div key={note} className="text-xs text-tier-medium">
                            {note}
                          </div>
                        ))}
                      </TableCell>
                      {hasContainers && (
                        <>
                          <TableCell>
                            {now?.container?.state ? (
                              <ContainerStateBadge state={now.container.state} />
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell className="text-sm whitespace-normal text-muted-foreground">
                            {now?.container?.status ??
                              (now?.container?.sizeBytes != null ? formatBytes(now.container.sizeBytes) : "—")}
                          </TableCell>
                        </>
                      )}
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
                onKeyDown={enterApproves}
                autoFocus={firstField === "count"}
              />
            </div>
          )}

          {needsReason && (
            <div className="grid gap-2">
              <Label htmlFor="approval-reason">Reason or ticket number</Label>
              <Input
                id="approval-reason"
                value={reason}
                onChange={(e) => setReason(e.currentTarget.value)}
                onKeyDown={enterApproves}
                autoFocus={firstField === "reason"}
              />
            </div>
          )}

          {reauth && vaultMissing && (
            <Alert>
              <KeyRoundIcon />
              <AlertTitle>Set up the vault first</AlertTitle>
              <AlertDescription>
                Critical actions ask for the vault password again, and there is no vault yet. Setting it up takes a
                minute; then start this action again.
              </AlertDescription>
              <AlertAction>
                <Button size="sm" variant="outline" onClick={() => void openVault()}>
                  Open the vault
                </Button>
              </AlertAction>
            </Alert>
          )}

          {reauth && !vaultMissing && (
            <div className="grid gap-2">
              <Label htmlFor="approval-password">Vault password</Label>
              <Input
                id="approval-password"
                type="password"
                autoComplete="off"
                value={password}
                onChange={(e) => setPassword(e.currentTarget.value)}
                onKeyDown={enterApproves}
                autoFocus={firstField === "password"}
              />
              <p className="text-xs text-muted-foreground">
                {request.tier === "critical"
                  ? "Critical actions ask for it again (AP-06), even when your Windows login unlocked the vault."
                  : "Asked because a vault password would go to hosts that don't get it yet (see above). Once approved, they may use it."}
              </p>
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
          <WhyDisabled reason={busy ? "Checking the answers…" : null}>
            <Button variant="outline" onClick={() => void cancel()} disabled={busy}>
              {request.exec?.multiExec ? "Cancel (Ctrl+C)" : "Cancel"}
            </Button>
          </WhyDisabled>
          <WhyDisabled reason={notReady}>
            <Button
              variant={risky ? "destructive" : "default"}
              onClick={() => void approve()}
              disabled={!ready || busy || expired}
              autoFocus={tier === "medium"}
            >
              {request.exec?.multiExec
                ? risky
                  ? `Approve and press ${request.exec.runKey ?? "Enter"}`
                  : `Press ${request.exec.runKey ?? "Enter"}`
                : risky
                  ? "Approve"
                  : "Confirm"}
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** BX-02, BX-06, BX-07: what a remote command will run, and how. SS-10: a MultiExec line, held at Enter. */
function ExecSummary({ exec, targets }: { exec: NonNullable<ApprovalRequest["exec"]>; targets: number }) {
  const how = [
    exec.sudo &&
      (exec.sudoPasswordLabel
        ? `With sudo, password '${exec.sudoPasswordLabel}' from the vault`
        : "With sudo, each session's login password from the vault"),
    exec.trustNewHostKeys && "Trusts host keys it has not seen before",
    exec.timeoutSecs != null && `Time limit ${exec.timeoutSecs} s per host`,
    exec.retryOf && "Retries the hosts that failed in an earlier run",
    rolloutText(exec.rollout, targets),
  ].filter((x): x is string => Boolean(x));
  return (
    <div className="grid gap-2">
      {exec.multiExec && (
        <p className="text-sm text-muted-foreground">
          MultiExec: this line is typed into {plural(targets, "terminal")} and waits there. Approving presses{" "}
          {exec.runKey ?? "Enter"} in each; cancelling sends Ctrl+C, which clears it.
        </p>
      )}
      <pre className="max-h-40 overflow-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs whitespace-pre-wrap">
        {exec.script || <span className="text-muted-foreground italic">(nothing Remotely could follow)</span>}
      </pre>
      {exec.unreliable && (
        <Alert className="border-tier-medium/40">
          <TriangleAlertIcon className="text-tier-medium" />
          <AlertTitle>The terminals may run something else</AlertTitle>
          <AlertDescription>
            The line was edited with keys Remotely can&apos;t follow (Tab completion, arrow keys, history search), or a
            terminal already had text on its line. Look at the terminals before you press Enter.
          </AlertDescription>
        </Alert>
      )}
      {how.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {how.map((h) => (
            <Badge key={h} variant="outline" className="font-normal">
              {h}
            </Badge>
          ))}
        </div>
      )}
      {exec.dangerous.length > 0 && (
        <Alert className="border-tier-high/40">
          <OctagonAlertIcon className="text-tier-high" />
          <AlertTitle>Flagged dangerous</AlertTitle>
          <AlertDescription>
            <ul className="grid gap-1">
              {exec.dangerous.map((d) => (
                <li key={d.rule}>
                  Line {d.line}: <code className="font-mono text-xs">{d.text}</code> matches the rule &ldquo;{d.rule}
                  &rdquo;
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

/**
 * VM-23, VM-24 (AP-02): what a settings or lifecycle change does to each VM, before and after, every file it deletes
 * (with its size), what it keeps, and a VM it would be refused on.
 */
function VmChangeSummary({ change }: { change: NonNullable<ApprovalRequest["vmChange"]> }) {
  const deletes = change.targets.reduce((n, t) => n + t.deletes.length, 0);
  const bytes = change.targets.reduce((n, t) => n + t.deletes.reduce((m, f) => m + (f.bytes ?? 0), 0), 0);
  return (
    <div className="grid gap-2">
      {deletes > 0 && (
        <p className="text-sm font-medium text-destructive">
          Deletes {plural(deletes, "file")} ({formatSize(bytes)}) for good: they don&apos;t go to the Recycle Bin.
        </p>
      )}
      <ul className="max-h-56 divide-y overflow-auto rounded-md border text-sm">
        {change.targets.map((t) => (
          <li key={t.target} className="grid gap-1 px-3 py-2">
            <span className="font-medium">{t.name}</span>
            {t.problem ? (
              <span className="text-xs text-tier-high">Refused as things are: {t.problem}</span>
            ) : (
              <ul className="list-disc pl-5 text-xs">
                {t.changes.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            )}
            {t.deletes.length > 0 && (
              <ul className="grid gap-0.5 text-xs">
                {t.deletes.map((f) => (
                  <li key={f.path} className="flex items-center gap-2">
                    <span className="truncate font-mono" title={f.path}>
                      {f.path}
                    </span>
                    <span className="ml-auto shrink-0 text-muted-foreground tabular-nums">
                      {f.bytes === null ? "" : formatSize(f.bytes)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {t.keeps.map((k) => (
              <span key={k} className="text-xs text-muted-foreground">
                Keeps {k}
              </span>
            ))}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** SS-08: what an upload writes, and where. */
function UploadSummary({ upload }: { upload: NonNullable<ApprovalRequest["upload"]> }) {
  const replacing = upload.files.filter((f) => f.replace).length;
  return (
    <div className="grid gap-2">
      <p className="text-sm text-muted-foreground">
        Into <code className="font-mono text-xs">{upload.folder}</code> on the host, as the logged-in user.
        {replacing > 0 && ` ${plural(replacing, "file")} there ${replacing === 1 ? "is" : "are"} replaced.`}
      </p>
      <ul className="max-h-40 divide-y overflow-auto rounded-md border text-sm">
        {upload.files.map((f) => (
          <li key={f.name} className="flex items-center gap-2 px-3 py-1">
            <span className="truncate font-mono text-xs">{f.name}</span>
            {f.replace && (
              <Badge variant="outline" className="border-tier-medium/50 font-normal text-tier-medium">
                replaces the file there
              </Badge>
            )}
            <span className="ml-auto shrink-0 text-xs text-muted-foreground tabular-nums">{formatSize(f.size)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** SS-07: what a tunnel opens, and who can use it. */
function TunnelSummary({ tunnel }: { tunnel: NonNullable<ApprovalRequest["tunnel"]> }) {
  const shared = !isLoopback(tunnel.forward.bindAddress);
  return (
    <div className="grid gap-1.5 rounded-md border p-3 text-sm">
      {tunnel.forward.label && <p className="font-medium">{tunnel.forward.label}</p>}
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-muted-foreground">Listens on</dt>
        <dd className="font-mono text-xs">{tunnel.listens}</dd>
        <dt className="text-muted-foreground">Leads to</dt>
        <dd className="font-mono text-xs">{tunnel.leads}</dd>
      </dl>
      <p className={shared ? "text-tier-medium" : "text-muted-foreground"}>{tunnel.exposes}</p>
      <p className="text-xs text-muted-foreground">
        It stays open until you stop it or close the terminal, and opens again by itself after a reconnect. Opening and
        closing are audited, never what goes through.
      </p>
    </div>
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
          <WhyDisabled reason={cancelling ? "Cancelling…" : null}>
            <Button variant="destructive" onClick={() => void cancelJob()} disabled={cancelling} autoFocus>
              {cancelling ? "Cancelling…" : "Cancel the action"}
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
