// Approval dialog (AP-02, AP-03, AP-06, VM-05): draws the steps the policy engine asked for. The
// core checks every answer again; these fields only help the user get them right first time.

import { useState } from "react";
import { ShieldAlertIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, errorMessage, type ApprovalRequest, type ApprovalStep } from "@/lib/api";
import { EnvBadge, TierBadge } from "./Badges";

interface Props {
  request: ApprovalRequest;
  /** Called with the job id once approved, or null when the user cancels. */
  onClose: (jobId: string | null) => void;
}

function find<S extends ApprovalStep["step"]>(steps: ApprovalStep[], step: S) {
  return steps.find((s) => s.step === step) as Extract<ApprovalStep, { step: S }> | undefined;
}

export function ApprovalDialog({ request, onClose }: Props) {
  const { steps, tier } = request;
  const snapshot = find(steps, "safetySnapshot");
  const typeCount = find(steps, "typeTargetCount");
  const needsReason = Boolean(find(steps, "reason"));
  const countdown = find(steps, "countdown");
  const reauth = Boolean(find(steps, "vaultReauth"));
  const risky = tier === "high" || tier === "critical";

  const [safetySnapshot, setSafetySnapshot] = useState(snapshot?.defaultOn ?? false);
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
      onClose(jobId);
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

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && void cancel()}>
      <DialogContent className="sm:max-w-xl">
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

        <div className="max-h-56 overflow-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target</TableHead>
                <TableHead className="w-24">Label</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {request.targets.map((t) => (
                <TableRow key={JSON.stringify(t.target)}>
                  <TableCell>
                    <div className="font-medium">{t.name}</div>
                    {t.target.kind === "vm" && (
                      <div className="font-mono text-xs break-all text-muted-foreground">{t.target.vmxPath}</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <EnvBadge env={t.environment} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {request.skipped.length > 0 && (
          <Alert>
            <ShieldAlertIcon />
            <AlertTitle>{request.skipped.length} protected target(s) will be skipped</AlertTitle>
            <AlertDescription>{request.skipped.map((t) => t.name).join(", ")}</AlertDescription>
          </Alert>
        )}

        <div className="grid gap-4">
          {snapshot && (
            <div className="flex items-center gap-2">
              <Checkbox
                id="approval-snapshot"
                checked={safetySnapshot}
                onCheckedChange={(checked) => setSafetySnapshot(checked === true)}
              />
              <Label htmlFor="approval-snapshot">Take a safety snapshot of each VM first (VM-05)</Label>
            </div>
          )}

          {typeCount && (
            <div className="grid gap-2">
              <Label htmlFor="approval-count">Type the number of targets ({typeCount.expected}) to confirm</Label>
              <Input
                id="approval-count"
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

          {countdown && countdown.seconds > 0 && (
            <p className="text-sm text-muted-foreground">
              After you approve, the action waits {countdown.seconds} seconds and can be cancelled until then.
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
            {tier === "medium" ? "Confirm" : "Approve"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
