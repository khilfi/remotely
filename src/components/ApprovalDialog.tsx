// Approval dialog (AP-02, AP-03, AP-06, VM-05, VM-07): draws the steps the policy engine asked for, the
// impact preview of each VM target and any warnings found before the action. For a remote command it
// shows the whole script, how it runs (sudo, host keys, time limit) and the dangerous-command rules it
// matched (BX-02, BX-06, BX-07). A Critical action asks for
// the vault password again; without a vault it points to the Vault page. After approval it shows
// the countdown, which can be cancelled until it ends. The core checks every answer again; these
// fields only help the user get them right first time.
//
// UX-11: summary first (the action, its targets, the tier with one plain reason and a "Why?" popover with the core's
// reasons), then the warnings and the impact table, folded when long, then the steps. One target asks for its name to
// confirm, several for their count (AP-03); one field takes the reason and the change ID (AP-03, AP-08): see
// lib/approval.ts.
//
// SS-10: a MultiExec line comes here too, held at Enter (or another key that runs it, `exec.runKey`): it shows the
// line and the terminals it is typed into, and the caller answers it through MultiExec (`approve`, `cancel`), which
// sends that key, or Ctrl+C to clear the line.
// SS-08: an upload shows the host folder and its files, marking the ones that replace a file there.
// SS-07: a tunnel shows where it listens, where it leads and who can use it (a network address is called out).
// QL-08: a disabled button says why.

import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { KeyRoundIcon, OctagonAlertIcon, ShieldAlertIcon, TimerIcon, TriangleAlertIcon } from "lucide-react";
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
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { CapacityPlanView } from "@/components/CapacityPlanView";
import { DeployPreviewView } from "@/components/DeployPreviewView";
import { StackDetailsView } from "@/components/StackDetailsView";
import { usePresentation } from "@/components/Presentation";
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
import { HelpTip } from "@/components/HelpTip";
import { Term } from "@/components/Term";
import {
  approvalProblem,
  confirmLabel,
  confirmPhrase,
  findChangeId,
  plainReason,
  reasonAnswers,
  reasonField,
  targetsLine,
  tierLine,
  typedCount,
} from "@/lib/approval";
import { containerTargetKey, formatBytes } from "@/lib/containers";
import { glossaryEntry } from "@/lib/glossary";
import { rolloutText } from "@/lib/rollout";
import { isLoopback } from "@/lib/tunnels";
import { formatDuration, plural } from "@/lib/format";
import { targetLocation } from "@/lib/hypervisors";
import { formatSize } from "@/lib/transfers";
import { cloneNames } from "@/lib/vm-snapshots";
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

/** Rows of the impact table and warnings shown before "Show all". */
const FOLD_ROWS = 6;
const FOLD_WARNINGS = 3;

function find<S extends ApprovalStep["step"]>(steps: ApprovalStep[], step: S) {
  return steps.find((s) => s.step === step) as Extract<ApprovalStep, { step: S }> | undefined;
}

function targetKey(target: ApprovalRequest["targets"][number]["target"]) {
  if (target.kind === "vm") return target.vmxPath;
  if (target.kind === "session") return target.sessionId;
  if (target.kind === "terminal") return target.terminalId;
  if (target.kind === "container") return containerTargetKey(target);
  if (target.kind === "network") return `${target.hypervisor}:${target.name}`;
  if (target.kind === "newVm") return `new-vm/${target.hypervisor}/${target.name}`;
  if (target.kind === "diskImage") return `disk-image/${target.path}`;
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

/** After approval: the job waits this many seconds and can be cancelled meanwhile (AP-03). */
type Countdown = { jobId: string; seconds: number };

/** VM-08: a stack instance's VMs together (in the request's order within each), other targets after them. A stack
 * command's own targets keep their order: it is the order they run in. */
function groupedTargets(request: ApprovalRequest): ApprovalRequest["targets"] {
  if (request.stack) return request.targets;
  const instanceOf = new Map(request.impact.filter((i) => i.stack).map((i) => [i.target, i.stack!.instanceName]));
  const order: string[] = [];
  for (const t of request.targets) {
    const name = instanceOf.get(targetKey(t.target));
    if (name !== undefined && !order.includes(name)) order.push(name);
  }
  const rank = (t: ApprovalRequest["targets"][number]) => {
    const name = instanceOf.get(targetKey(t.target));
    return name === undefined ? order.length : order.indexOf(name);
  };
  return request.targets
    .map((t, i) => ({ t, i }))
    .sort((a, b) => rank(a.t) - rank(b.t) || a.i - b.i)
    .map(({ t }) => t);
}

/** A column heading with its explanation on hover or focus. */
function HeadTip({ label, tip }: { label: string; tip: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="cursor-help underline decoration-muted-foreground/60 decoration-dotted underline-offset-4 outline-none focus-visible:rounded-sm focus-visible:ring-3 focus-visible:ring-ring/50"
        >
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{tip}</TooltipContent>
    </Tooltip>
  );
}

/** "Why?": the core's reasons for the tier, in plain words, and what the tier asks. */
function WhyTier({ request }: { request: ApprovalRequest }) {
  const tier = glossaryEntry(request.tier);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button type="button" variant="link" size="sm" className="h-auto p-0 text-sm">
          Why?
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-96 gap-2 p-3" aria-label={`Why ${tier.term}`}>
        <p className="font-medium">Why {tier.term}</p>
        <ul className="list-disc space-y-0.5 pl-4 text-muted-foreground">
          {request.reasons.map((r) => (
            <li key={r}>{plainReason(r)}</li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">
          {tier.term}: {tier.definition}
        </p>
      </PopoverContent>
    </Popover>
  );
}

/** A list that shows its first `limit` items and a button for the rest. */
function Folded<T>({
  items,
  limit,
  noun,
  children,
}: {
  items: readonly T[];
  limit: number;
  noun: string;
  children: (shown: readonly T[]) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  // Fold only when it saves more than one line.
  const folds = items.length > limit + 1;
  const shown = folds && !open ? items.slice(0, limit) : items;
  return (
    <>
      {children(shown)}
      {folds && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="justify-self-start"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? `Show fewer ${noun}s` : `Show all ${plural(items.length, noun)}`}
        </Button>
      )}
    </>
  );
}

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
  const { presenting } = usePresentation();
  const snapshot = find(steps, "safetySnapshot");
  // AP-03: a lone target's name, or the count; FD-03: the count while presenting (names may be masked on screen).
  const phrase = confirmPhrase(request, presenting);
  // AP-03, AP-08: one field for the reason and the change ID.
  const field = reasonField(steps);
  const countdownStep = find(steps, "countdown");
  const reauth = Boolean(find(steps, "vaultReauth"));
  const risky = tier === "high" || tier === "critical";
  const impact = new Map<string, TargetImpact>(request.impact.map((i) => [i.target, i]));
  const hasVms = request.targets.some((t) => t.target.kind === "vm");
  // CT-01, CT-02: containers show their state, image and uptime; images and volumes what uses them.
  const hasContainers = request.impact.some((i) => i.container);

  const [safetySnapshot, setSafetySnapshot] = useState(snapshot?.defaultOn ?? false);
  const [typed, setTyped] = useState("");
  const [text, setText] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [noVault, setNoVault] = useState(false);
  const [busy, setBusy] = useState(false);
  const [countdown, setCountdown] = useState<Countdown | null>(null);
  // AP-01: the approval waited too long and is gone in the core; only Cancel is left.
  const [expired, setExpired] = useState(false);
  const vaultMissing = reauth && (noVault || vault?.status === "notSetUp");
  // AP-08: a target's name ("DB01") is never taken as the change ID.
  const targetNames = request.targets.map((t) => t.name);

  const notReady = expired
    ? "This approval expired: start the action again"
    : approvalProblem({ steps, phrase, typed, text, password, busy, targetNames });
  const ready = notReady === null;
  const changeId =
    field.shown && find(steps, "reason") && find(steps, "changeId") ? findChangeId(text, targetNames) : null;
  // FD-01: the first answer to type gets the focus, and Enter in any of them approves once all are
  // right (the same as pressing Approve).
  const firstField = phrase ? "confirm" : field.shown ? "reason" : reauth ? "password" : null;
  const enterApproves = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && ready) {
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
        typedTargetCount: phrase ? typedCount(phrase, typed) : undefined,
        ...reasonAnswers(steps, text, targetNames),
        safetySnapshot: snapshot ? safetySnapshot : undefined,
        vaultPassword: reauth ? password : undefined,
      };
      const jobId = approveWith ? await approveWith(answers) : await api.approve(request.id, answers);
      setPassword("");
      onApproved?.(jobId);
      if (countdownStep && countdownStep.seconds > 0) {
        const seconds = countdownStep.seconds;
        setCountdown({ jobId, seconds });
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
        setText("");
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

  const targetsText = targetsLine(request.targets);
  const rows = groupedTargets(request);

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && void cancel()}>
      {/* VM-24: a long list of files to delete must not push Approve and Cancel off a small window. */}
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <TierBadge tier={tier} />
            <DialogTitle>{request.summary}</DialogTitle>
          </div>
          <DialogDescription className="flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5">
            {targetsText && (
              <>
                <span className="font-medium text-foreground">{targetsText}</span>
                <span aria-hidden>·</span>
              </>
            )}
            <span>{tierLine(request)}</span>
            <WhyTier request={request} />
          </DialogDescription>
        </DialogHeader>

        {request.exec && (!request.bundle || request.exec.script) && (
          <ExecSummary exec={request.exec} targets={request.targets.length} />
        )}
        {request.bundle && <BundleSummary bundle={request.bundle} />}
        {request.upload && <UploadSummary upload={request.upload} />}
        {request.tunnel && <TunnelSummary tunnel={request.tunnel} />}
        {/* VM-21: the VMs a deploy makes, where, and the disk they may take; its warnings are listed below. */}
        {request.deploy && <DeployPreviewView preview={request.deploy} showWarnings={false} />}
        {request.vmChange && <VmChangeSummary change={request.vmChange} />}
        {/* VM-08: a stack command's instance and steps in the order they run; VM-26: this PC after a deploy. */}
        {request.stack && <StackDetailsView details={request.stack} showWarnings={false} />}
        {request.capacity && <CapacityPlanView capacity={request.capacity} />}
        {request.standing && <StandingSummary standing={request.standing} />}

        {request.warnings.length > 0 && (
          <Alert className="border-tier-medium/40">
            <TriangleAlertIcon className="text-tier-medium" />
            <AlertTitle>Read this before you go on</AlertTitle>
            <AlertDescription className="grid">
              <Folded items={request.warnings} limit={FOLD_WARNINGS} noun="warning">
                {(shown) => (
                  <ul className="list-disc pl-5">
                    {shown.map((w) => (
                      <li key={w}>{w}</li>
                    ))}
                  </ul>
                )}
              </Folded>
            </AlertDescription>
          </Alert>
        )}

        {request.skipped.length > 0 && (
          <Alert>
            <ShieldAlertIcon />
            <AlertTitle>
              {request.skipped.length} <Term id="protected" /> {request.skipped.length === 1 ? "target" : "targets"}{" "}
              will be skipped
            </AlertTitle>
            <AlertDescription>{request.skipped.map((t) => t.name).join(", ")}</AlertDescription>
          </Alert>
        )}

        <div className="grid gap-1.5" hidden={request.deploy !== null || request.stack?.action === "deploy"}>
          <Folded items={rows} limit={FOLD_ROWS - 1} noun="target">
            {(shown) => (
              <div className="max-h-64 overflow-auto rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Target</TableHead>
                      {hasVms && (
                        <>
                          <TableHead className="w-28">State</TableHead>
                          <TableHead className="w-24">
                            <HeadTip
                              label="Up for"
                              tip="How long each VM has run since it was last started or resumed."
                            />
                          </TableHead>
                          <TableHead className="w-28 text-right">
                            <HeadTip
                              label="Snapshots"
                              tip="The snapshots each VM has now. A delete that would break a linked clone says so under the VM."
                            />
                          </TableHead>
                        </>
                      )}
                      {hasContainers && (
                        <>
                          <TableHead>State</TableHead>
                          <TableHead>Now</TableHead>
                        </>
                      )}
                      <TableHead className="w-24">
                        <Term id="environment" />
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {shown.map((t) => {
                      const key = targetKey(t.target);
                      const now = impact.get(key);
                      return (
                        <TableRow key={key}>
                          <TableCell className="max-w-0 whitespace-normal">
                            <div className="font-medium">{t.name}</div>
                            {t.target.kind === "vm" && (
                              <div
                                className="truncate font-mono text-xs text-muted-foreground"
                                title={targetLocation(t.target.vmxPath)}
                              >
                                {targetLocation(t.target.vmxPath)}
                              </div>
                            )}
                            {now?.stack && (
                              <div className="text-xs text-muted-foreground">
                                Stack instance {now.stack.instanceName}, step {now.stack.step} of {now.stack.steps}
                                {now.stack.byHand && " (added by hand)"}
                              </div>
                            )}
                            {now?.container && <ContainerImpactLines impact={now.container} />}
                            {now?.notes.map((note) => (
                              <div key={note} className="text-xs text-tier-medium">
                                {note}
                              </div>
                            ))}
                            {now?.linkedClones.map((s) => (
                              <div key={s.uid} className="text-xs text-destructive">
                                Not deleted: {plural(s.clones.length, "linked clone")} made from its snapshot &apos;
                                {s.snapshot}&apos; ({cloneNames(s.clones)})
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
            )}
          </Folded>
        </div>

        <div className="grid gap-4">
          {snapshot && (
            <div className="flex items-center gap-2">
              <Checkbox
                id="approval-snapshot"
                checked={safetySnapshot}
                onCheckedChange={(checked) => setSafetySnapshot(checked === true)}
              />
              <Label htmlFor="approval-snapshot">Take a safety snapshot of each VM first</Label>
              <HelpTip topic="safetySnapshot" />
            </div>
          )}

          {phrase && (
            <div className="grid gap-2">
              <Label htmlFor="approval-confirm">
                {phrase.kind === "name" ? (
                  <span>
                    Type <span className="font-mono font-semibold">{phrase.expected}</span> to confirm
                  </span>
                ) : (
                  confirmLabel(phrase)
                )}
              </Label>
              <Input
                id="approval-confirm"
                className={phrase.kind === "name" ? "max-w-sm" : "w-32"}
                inputMode={phrase.kind === "count" ? "numeric" : undefined}
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                value={typed}
                onChange={(e) => setTyped(e.currentTarget.value)}
                onKeyDown={enterApproves}
                autoFocus={firstField === "confirm"}
              />
            </div>
          )}

          {field.shown && (
            <div className="grid gap-2">
              <span className="flex items-center gap-1">
                <Label htmlFor="approval-reason">{field.label}</Label>
                <HelpTip topic="reasonOrChangeId" />
              </span>
              <Input
                id="approval-reason"
                autoComplete="off"
                placeholder={field.placeholder}
                value={text}
                onChange={(e) => setText(e.currentTarget.value)}
                onKeyDown={enterApproves}
                autoFocus={firstField === "reason"}
              />
              {changeId ? (
                <p className="text-xs text-muted-foreground">
                  <Term id="changeId" />: <span className="font-mono">{changeId}</span>
                </p>
              ) : (
                field.changeIdRequired && (
                  <p className="text-xs text-muted-foreground">
                    This workspace needs a change ID for Prod: start with it.
                  </p>
                )
              )}
            </div>
          )}

          {reauth && vaultMissing && (
            <Alert>
              <KeyRoundIcon />
              <AlertTitle>Set up the vault first</AlertTitle>
              <AlertDescription className="flex items-center gap-1">
                There is no vault yet, so there is no vault password to ask for. Set it up, then start again.
                <HelpTip topic="vaultReauth" />
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
              <span className="flex items-center gap-1">
                <Label htmlFor="approval-password">Vault password</Label>
                <HelpTip topic="vaultReauth" />
              </span>
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
                  ? "Critical actions ask for it again, however the vault was unlocked."
                  : "A vault password would go to hosts that don't get it yet."}
              </p>
            </div>
          )}

          {countdownStep && countdownStep.seconds > 0 && (
            <p className="text-sm text-muted-foreground">
              Waits {countdownStep.seconds} seconds after you approve; you can cancel it until then.
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
              disabled={!ready}
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

/** VM-14, VM-27: a schedule's approval holds for each of its runs: when they come and what each does. */
function StandingSummary({ standing }: { standing: NonNullable<ApprovalRequest["standing"]> }) {
  return (
    <Alert>
      <TimerIcon />
      <AlertTitle className="flex items-center gap-1">
        <span>
          <Term id="standingApproval" /> for &lsquo;{standing.name}&rsquo;: {standing.when}
        </span>
        <HelpTip topic="standingApproval" />
      </AlertTitle>
      <AlertDescription>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
          {standing.nextRuns.length > 0 && (
            <>
              <dt className="text-muted-foreground">Next runs</dt>
              <dd>{standing.nextRuns.join("; ")}</dd>
            </>
          )}
          {standing.resolves.length > 0 && (
            <>
              <dt className="text-muted-foreground">Targets</dt>
              <dd>{standing.resolves.join("; ")}</dd>
            </>
          )}
          {standing.snapshotName && (
            <>
              <dt className="text-muted-foreground">Snapshots</dt>
              <dd>
                &lsquo;{standing.snapshotName}&rsquo;
                {standing.keep !== null && `, keeping this schedule's last ${standing.keep}`}
              </dd>
            </>
          )}
          {standing.countdownSeconds !== null && (
            <>
              <dt className="text-muted-foreground">Countdown</dt>
              <dd>{standing.countdownSeconds} seconds before each run, cancellable in Activity</dd>
            </>
          )}
        </dl>
      </AlertDescription>
    </Alert>
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
          Type in all tabs: this line is typed into {plural(targets, "terminal")} and waits there. Approving presses{" "}
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

/** FD-04: a support bundle's files (its commands are in ExecSummary) and where the zip goes. */
function BundleSummary({ bundle }: { bundle: NonNullable<ApprovalRequest["bundle"]> }) {
  return (
    <div className="grid gap-2 text-sm">
      {bundle.files.length > 0 && (
        <>
          <p className="text-muted-foreground">
            Reads {plural(bundle.files.length, "file")} over SFTP as each session&apos;s user, never with sudo:
          </p>
          <ul className="max-h-32 divide-y overflow-auto rounded-md border">
            {bundle.files.map((f) => (
              <li key={f} className="truncate px-3 py-1 font-mono text-xs" title={f}>
                {f}
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="text-muted-foreground">
        Saves the zip as <code className="font-mono text-xs break-all">{bundle.output}</code>, with what looks like a
        secret redacted.
      </p>
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
        Stays open until you stop it or close the terminal, and opens again after a reconnect.
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
  // From when this view shows, which is when the approval was answered.
  const [until] = useState(() => Date.now() + countdown.seconds * 1000);
  const left = Math.max(0, Math.ceil((until - now) / 1000));
  // The parent passes a new function on every render; the listener below must not resubscribe for it.
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  });

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now());
      // The start event should close this first; this covers one that was missed.
      if (Date.now() > until + 3000) close.current();
    }, 250);
    return () => window.clearInterval(timer);
  }, [until]);

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
            {summary}. Nothing has run yet: cancel now, here or in Activity, and no target is touched.
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
