// VM-14, VM-27: the schedules part of a VM's Activity tab (UX-03: Timeline and Schedules are one tab since 0.6.0): the
// schedules that act on it (by name or through a tag), each with its next and last run and state, and its snapshot
// chain as one status line, with the limits in its tooltip (MO-13's disk sizes). New schedule and the run history open
// on the Schedules page, where schedules are edited and approved.

import { useEffect, useState } from "react";
import { CalendarClockIcon, HistoryIcon, PlusIcon, TriangleAlertIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { OutcomeBadge } from "@/components/ScheduleRunsSheet";
import { Term } from "@/components/Term";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type VmRecord } from "@/lib/api";
import { formatPlanned, stateLabel } from "@/lib/schedules";
import { schedulesApi, type ScheduleView, type VmSchedules } from "@/lib/schedules-api";
import { cn } from "@/lib/utils";
import { chainStatus } from "@/lib/vm-page";

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
  if (!data) return <Skeleton className="h-16 w-full" />;
  const chain = data.chain ? chainStatus(data.chain, data.limits) : null;

  return (
    <section className="grid gap-2" aria-label="Schedules">
      <div className="flex items-center gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-medium">
          <CalendarClockIcon className="size-4 text-muted-foreground" aria-hidden /> Schedules
        </h3>
        <WhyDisabled reason={readOnly} className="ml-auto">
          <Button
            size="sm"
            variant="ghost"
            disabled={readOnly !== null}
            onClick={() => onSchedules({ create: true, vms: [vm.vmxPath] })}
          >
            <PlusIcon data-icon="inline-start" />
            New schedule…
          </Button>
        </WhyDisabled>
      </div>

      {chain && (
        <p className={cn("flex items-center gap-1.5 text-xs", chain.ok ? "text-muted-foreground" : "text-tier-medium")}>
          {!chain.ok && <TriangleAlertIcon className="size-3.5" aria-hidden />}
          <Term id="snapshotChain">Snapshot chain</Term>:
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="cursor-help outline-none focus-visible:underline">
                {chain.text}
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-xs">{chain.detail}</TooltipContent>
          </Tooltip>
        </p>
      )}

      {data.schedules.length === 0 ? (
        <p className="text-sm text-muted-foreground">No schedule acts on this VM.</p>
      ) : (
        <ul className="grid gap-1.5">
          {data.schedules.map((s) => (
            <ScheduleRow key={s.id} schedule={s} onRuns={() => onSchedules({ scheduleId: s.id })} />
          ))}
        </ul>
      )}
    </section>
  );
}

function ScheduleRow({ schedule: s, onRuns }: { schedule: ScheduleView; onRuns: () => void }) {
  const waiting = s.state !== "active" && s.stateReason && s.stateReason !== "new" ? s.stateReason : null;
  return (
    <li className="flex items-start gap-2 rounded-md border px-2.5 py-1.5 text-sm">
      <div className="grid min-w-0 flex-1 gap-0.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{s.name}</span>
          <Badge variant="outline">{stateLabel(s.state)}</Badge>
          {s.lastRun && <OutcomeBadge outcome={s.lastRun.outcome} />}
        </div>
        <div className="text-xs text-muted-foreground">
          {s.action} · {s.when}
          {s.nextRun && <> · next {formatPlanned(s.nextRun.at)}</>}
        </div>
        {waiting && <div className="text-xs text-tier-high">{waiting}</div>}
      </div>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`Runs of ${s.name}`} onClick={onRuns}>
            <HistoryIcon />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Runs</TooltipContent>
      </Tooltip>
    </li>
  );
}
