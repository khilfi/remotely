// VM-14, VM-27: a VM's Schedules tab: the schedules that act on it (by name or through a tag), each with its next and
// last run and state, and its snapshot chain against the warning limits (MO-13's disk sizes). New schedule and the run
// history open on the Schedules page, where schedules are edited and approved.

import { useEffect, useState } from "react";
import { CalendarClockIcon, HistoryIcon, PlusIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { OutcomeBadge } from "@/components/ScheduleRunsSheet";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type VmRecord } from "@/lib/api";
import { formatPlanned, stateLabel } from "@/lib/schedules";
import { schedulesApi, type ScheduleView, type VmSchedules } from "@/lib/schedules-api";
import { formatBytes } from "@/lib/retention";

export interface ScheduleAsk {
  /** A new schedule for these VMs. */
  create?: boolean;
  vms?: string[];
  /** One schedule's runs. */
  scheduleId?: string;
}

interface Props {
  vm: VmRecord;
  /** Changes when a job finished: read again. */
  refreshKey: string;
  readOnly: string | null;
  onSchedules: (ask: ScheduleAsk) => void;
}

export function VmSchedulesTab({ vm, refreshKey, readOnly, onSchedules }: Props) {
  const [data, setData] = useState<VmSchedules | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    schedulesApi.forVm(vm.vmxPath).then(
      (d) => {
        if (!live) return;
        setData(d);
        setError(null);
      },
      (err: unknown) => live && setError(errorMessage(err)),
    );
    const unlisten = schedulesApi.onEvent(() => {
      schedulesApi.forVm(vm.vmxPath).then(
        (d) => live && setData(d),
        () => {},
      );
    });
    return () => {
      live = false;
      void unlisten.then((stop) => stop());
    };
  }, [vm.vmxPath, refreshKey]);

  if (error) return <p className="text-sm text-destructive">{error}</p>;
  if (!data) return <Skeleton className="h-24 w-full" />;
  const chain = data.chain;

  return (
    <div className="grid gap-3">
      <div className="flex items-center gap-2">
        <p className="text-sm text-muted-foreground">Schedules that act on {vm.displayName}, by name or tag.</p>
        <WhyDisabled reason={readOnly} className="ml-auto">
          <Button
            size="sm"
            variant="outline"
            disabled={readOnly !== null}
            onClick={() => onSchedules({ create: true, vms: [vm.vmxPath] })}
          >
            <PlusIcon data-icon="inline-start" />
            New schedule…
          </Button>
        </WhyDisabled>
      </div>

      {chain && chain.warnings.length > 0 && (
        <Alert>
          <TriangleAlertIcon />
          <AlertTitle>Snapshot chain</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-4">
              {chain.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {chain && (
        <p className="text-xs text-muted-foreground">
          {chain.error ??
            [
              chain.snapshots !== null && `${chain.snapshots === 1 ? "1 snapshot" : `${chain.snapshots} snapshots`}`,
              chain.depth !== null && `chain ${chain.depth} deep`,
              chain.sizeBytes !== null && `${formatBytes(chain.sizeBytes)} on this PC`,
            ]
              .filter(Boolean)
              .join(", ")}
          {` (warns past ${data.limits.maxDepth} deep or ${data.limits.maxSizeGb} GB)`}
        </p>
      )}

      {data.schedules.length === 0 && (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <CalendarClockIcon className="size-4" /> No schedule acts on this VM.
        </p>
      )}
      {data.schedules.map((s) => (
        <ScheduleCard key={s.id} schedule={s} onRuns={() => onSchedules({ scheduleId: s.id })} />
      ))}
    </div>
  );
}

function ScheduleCard({ schedule: s, onRuns }: { schedule: ScheduleView; onRuns: () => void }) {
  return (
    <div className="grid gap-1 rounded-md border p-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{s.name}</span>
        <Badge variant="outline">{stateLabel(s.state)}</Badge>
        <Button variant="ghost" size="sm" className="ml-auto" onClick={onRuns}>
          <HistoryIcon data-icon="inline-start" />
          Runs
        </Button>
      </div>
      <div className="text-muted-foreground">
        {s.action} · {s.when}
      </div>
      {s.nextRun && (
        <div className="text-xs">
          Next: {formatPlanned(s.nextRun.at)}
          {s.nextRun.note && <span className="text-tier-medium"> ({s.nextRun.note})</span>}
        </div>
      )}
      {s.lastRun && (
        <div className="flex items-center gap-2 text-xs">
          Last: <OutcomeBadge outcome={s.lastRun.outcome} /> {formatPlanned(s.lastRun.dueAt)}
        </div>
      )}
      {s.state !== "active" && s.stateReason && s.stateReason !== "new" && (
        <div className="text-xs text-tier-high">{s.stateReason}</div>
      )}
    </div>
  );
}
