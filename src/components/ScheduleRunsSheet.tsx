// VM-14, VM-27: one schedule's run history, newest first: when each run was due, how it went (missed and skipped
// runs included, with why) and its jobs, which Activity shows in full. The newest 200 runs are kept.

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { errorMessage } from "@/lib/api";
import { formatPlanned, outcomeLabel, outcomeTone, type Tone } from "@/lib/schedules";
import { schedulesApi, type ScheduleRun, type ScheduleView } from "@/lib/schedules-api";
import { cn } from "@/lib/utils";

const TONE: Record<Tone, string> = {
  success: "border-success/40 text-success",
  warning: "border-tier-medium/50 text-tier-medium",
  destructive: "border-destructive/50 text-destructive",
  muted: "text-muted-foreground",
};

export function OutcomeBadge({ outcome }: { outcome: ScheduleRun["outcome"] }) {
  return (
    <Badge variant="outline" className={cn("shrink-0", TONE[outcomeTone(outcome)])}>
      {outcomeLabel(outcome)}
    </Badge>
  );
}

interface Props {
  schedule: ScheduleView;
  /** Changes when a run started or ended: the list is read again. */
  refreshKey: number;
  onClose: () => void;
}

export function ScheduleRunsSheet({ schedule, refreshKey, onClose }: Props) {
  const [runs, setRuns] = useState<ScheduleRun[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    schedulesApi.runs(schedule.id, 200).then(
      (r) => live && setRuns(r),
      (err: unknown) => live && setError(errorMessage(err)),
    );
    return () => {
      live = false;
    };
  }, [schedule.id, refreshKey]);

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Runs of &lsquo;{schedule.name}&rsquo;</SheetTitle>
          <SheetDescription>
            {schedule.action}, {schedule.when.charAt(0).toLowerCase() + schedule.when.slice(1)}. Each run is a run of
            its approval; its jobs are in Activity.
          </SheetDescription>
        </SheetHeader>
        <div className="grid gap-2 px-4 pb-4">
          {error && <p className="text-sm text-destructive">{error}</p>}
          {!runs && !error && <Skeleton className="h-24 w-full" />}
          {runs?.length === 0 && <p className="text-sm text-muted-foreground">No run yet.</p>}
          {runs?.map((run) => (
            <div key={run.id} className="grid gap-1 rounded-md border p-2 text-sm">
              <div className="flex items-center gap-2">
                <OutcomeBadge outcome={run.outcome} />
                <span>Due {formatPlanned(run.dueAt)}</span>
                {run.finishedAt && run.startedAt && (
                  <span className="ml-auto text-xs text-muted-foreground">ended {formatPlanned(run.finishedAt)}</span>
                )}
              </div>
              {run.detail && <p className="text-xs break-words text-muted-foreground">{run.detail}</p>}
              {run.jobIds.length > 0 && (
                <p className="font-mono text-xs text-muted-foreground">
                  {run.jobIds.length === 1 ? "Job" : "Jobs"} {run.jobIds.map((j) => j.slice(0, 8)).join(", ")}
                </p>
              )}
            </div>
          ))}
        </div>
      </SheetContent>
    </Sheet>
  );
}
