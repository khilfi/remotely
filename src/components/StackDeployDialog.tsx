// VM-08: deploys a stack as one instance. The core checks it as it is named: every VM of every step with R2's
// preview per step (names, folders, size, disk space, network), the waits between steps, and VM-26's plan of this PC
// after it (with what to suspend when it won't fit). Deploy asks for one approval (a deploy of all its VMs), then one
// job makes the steps in boot order.

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
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
import { CapacityPlanView } from "@/components/CapacityPlanView";
import { useReadOnlyReason } from "@/components/Presentation";
import { StackDetailsView } from "@/components/StackDetailsView";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import { errorMessage, type SubmitOutcome } from "@/lib/api";
import { stacksApi, type Stack, type StackDeployCheck } from "@/lib/stacks-api";

interface Props {
  stack: Stack;
  /** The approval dialog for the deploy (or a suspend the planner suggests). */
  onSubmitted: (outcome: SubmitOutcome) => void;
  onClose: () => void;
}

export function StackDeployDialog({ stack, onSubmitted, onClose }: Props) {
  const readOnly = useReadOnlyReason();
  const [name, setName] = useState("");
  const [check, setCheck] = useState<StackDeployCheck | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const checkedName = useDebounced(name, 300);

  useEffect(() => {
    let stopped = false;
    stacksApi.deployCheck({ stackId: stack.id, instanceName: checkedName.trim() || null }).then(
      (c) => {
        if (stopped) return;
        setCheck(c);
        setCheckError(null);
      },
      (err) => {
        if (stopped) return;
        setCheck(null);
        setCheckError(errorMessage(err));
      },
    );
    return () => {
      stopped = true;
    };
  }, [stack.id, checkedName]);

  async function deploy() {
    setBusy(true);
    setError(null);
    try {
      onSubmitted(await stacksApi.deploy({ stackId: stack.id, instanceName: name.trim() || null }));
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const refusals = check?.details?.refusals ?? [];
  const reason =
    readOnly ??
    (busy
      ? "Submitting…"
      : checkedName !== name || (!check && !checkError)
        ? "Checking…"
        : checkError
          ? checkError
          : check?.problems.length
            ? check.problems[0]
            : refusals.length
              ? refusals[0]
              : null);

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Deploy {stack.name}</DialogTitle>
          <DialogDescription>
            {stack.vmCount} VMs in {stack.steps.length} step{stack.steps.length === 1 ? "" : "s"}, made in boot order as
            one job. The instance remembers its VMs, so it starts, stops and tears down as one.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!reason) void deploy();
          }}
        >
          <div className="-mx-1 grid max-h-[65vh] gap-4 overflow-x-hidden overflow-y-auto px-1">
            <div className="grid gap-2">
              <Label htmlFor="stack-instance-name">Instance name</Label>
              <Input
                id="stack-instance-name"
                value={name}
                placeholder={check?.instanceName ?? `${stack.name} 1`}
                maxLength={60}
                onChange={(e) => setName(e.currentTarget.value)}
              />
            </div>
            {check?.problems.length ? (
              <ul className="grid gap-1 text-sm text-destructive" role="alert">
                {check.problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            ) : null}
            {checkError && (
              <p className="text-sm text-destructive" role="alert">
                {checkError}
              </p>
            )}
            {check?.details && <StackDetailsView details={check.details} />}
            {check?.capacity && (
              <CapacityPlanView capacity={check.capacity} readOnly={readOnly} onSubmitted={onSubmitted} />
            )}
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <WhyDisabled reason={reason}>
              <Button type="submit" disabled={reason !== null}>
                {busy ? "Submitting…" : `Deploy ${stack.vmCount} VMs`}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
