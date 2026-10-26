// VM-26: the deploy capacity planner. RAM, CPU and disk on this PC after a deploy, next to what runs now (thin disks
// at their full size, the worst case); why it won't fit; and, when the RAM won't, which running VMs to suspend, with
// a button that submits that suspend (the usual power command and its approval). Shown in the Deploy, Clone and
// stack deploy dialogs, and in the approval dialog.

import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { CpuIcon, HardDriveIcon, InfoIcon, MemoryStickIcon, PauseIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { LevelIcon, Meter } from "@/components/MetricBits";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type SubmitOutcome } from "@/lib/api";
import type { Level } from "@/lib/metrics";
import { afterPct, cpuLine, driveLine, gbText, ramLine, suspendTargets } from "@/lib/stacks";
import type { DeployCapacity } from "@/lib/stacks-api";
import { plural } from "@/lib/format";

interface Props {
  capacity: DeployCapacity;
  /** Offers to suspend the suggested VMs; the outcome goes here (the approval dialog). Without it, only named. */
  onSubmitted?: (outcome: SubmitOutcome) => void;
  /** Why the suspend button is off (presentation's read-only lock). */
  readOnly?: string | null;
}

function levelOf(pct: number | null, fits: boolean): Level {
  if (!fits) return "critical";
  if (pct !== null && pct > 90) return "warning";
  return "ok";
}

function Row({
  icon,
  label,
  line,
  pct,
  fits,
}: {
  icon: ReactNode;
  label: string;
  line: string;
  pct: number | null;
  fits: boolean;
}) {
  const level = levelOf(pct, fits);
  return (
    <div className="grid gap-1">
      <div className="flex items-center justify-between gap-2 text-sm">
        <span className="flex items-center gap-1.5 font-medium">
          {icon}
          {label}
        </span>
        <span className="flex items-center gap-1 text-xs text-muted-foreground tabular-nums">
          <LevelIcon level={level} />
          {line}
        </span>
      </div>
      <Meter pct={pct} level={level} label={`${label} after the deploy`} />
    </div>
  );
}

export function CapacityPlanView({ capacity, onSubmitted, readOnly = null }: Props) {
  const [busy, setBusy] = useState(false);
  const suspend = capacity.suspend;

  async function suspendThem() {
    if (!onSubmitted) return;
    setBusy(true);
    try {
      onSubmitted(await api.submit({ type: "vmPower", targets: suspendTargets(capacity), op: { kind: "suspend" } }));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="This PC after the deploy" className="grid gap-3 rounded-md border p-3">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="text-sm font-medium">This PC after the deploy</h3>
        <span className="text-xs text-muted-foreground">
          {plural(capacity.runningVms, "VM")} running now
          {capacity.startingVms !== capacity.newVms &&
            `; ${capacity.newVms - capacity.startingVms} of the new VMs stay off`}
        </span>
      </div>
      <Row
        icon={<MemoryStickIcon className="size-4 text-muted-foreground" aria-hidden />}
        label="RAM"
        line={ramLine(capacity)}
        pct={afterPct(capacity.ram.afterMb, capacity.ram.physicalMb)}
        fits={capacity.ram.fits}
      />
      <Row
        icon={<CpuIcon className="size-4 text-muted-foreground" aria-hidden />}
        label="CPU"
        line={cpuLine(capacity)}
        pct={afterPct(capacity.cpu.afterVcpus, capacity.cpu.logicalCpus)}
        fits={capacity.cpu.fits}
      />
      {capacity.drives.map((drive) => (
        <Row
          key={drive.drive}
          icon={<HardDriveIcon className="size-4 text-muted-foreground" aria-hidden />}
          label={`Disk ${drive.drive}`}
          line={driveLine(drive)}
          pct={
            drive.totalBytes && drive.freeBytes !== null
              ? afterPct(drive.totalBytes - (drive.freeAfterBytes ?? 0), drive.totalBytes)
              : null
          }
          fits={drive.fits && drive.worstCaseFits}
        />
      ))}

      {capacity.problems.length > 0 && (
        <Alert variant="destructive">
          <AlertTitle>It won't fit as it is</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-5">
              {capacity.problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {suspend && (
        <div className="grid gap-2 rounded-md bg-muted/50 p-2 text-sm">
          <p>
            {suspend.enough ? (
              <>
                Suspending {suspend.vms.map((v) => v.name).join(", ")} frees {gbText(suspend.freesMb)}, enough for the{" "}
                {gbText(suspend.needsMb)} the deploy needs. Suspending writes each VM's memory to its folder's drive.
              </>
            ) : (
              <>
                Even suspending every running VM that can be ({suspend.vms.map((v) => v.name).join(", ")}) frees only{" "}
                {gbText(suspend.freesMb)} of the {gbText(suspend.needsMb)} needed.
              </>
            )}
          </p>
          {onSubmitted && suspend.enough && (
            <WhyDisabled reason={readOnly}>
              <Button
                size="sm"
                variant="outline"
                className="justify-self-start"
                disabled={busy || readOnly !== null}
                onClick={() => void suspendThem()}
              >
                <PauseIcon data-icon="inline-start" />
                {busy ? "Submitting…" : `Suspend ${plural(suspend.vms.length, "VM")}`}
              </Button>
            </WhyDisabled>
          )}
        </div>
      )}
      {capacity.warnings.length > 0 && (
        <ul className="grid gap-1 text-xs text-tier-medium">
          {capacity.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
      {capacity.unchecked.length > 0 && (
        <div className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <InfoIcon className="mt-px size-3.5 shrink-0" aria-hidden />
          <ul className="grid gap-1">
            {capacity.unchecked.map((u) => (
              <li key={u}>{u}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
