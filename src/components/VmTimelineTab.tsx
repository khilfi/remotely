// VM-25: a VM's Timeline tab: everything Remotely did to it, from the audit log (approvals, jobs, label changes, Open
// console...) with each job's outcome for this VM from the job journal, newest first, 50 at a time. A job's entries
// show as one card. Read again when a job finishes or a setting changes (refreshKey). A read: not audited.

import { useEffect, useState } from "react";
import { HistoryIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { TierBadge } from "@/components/Badges";
import { RefreshButton } from "@/components/RefreshButton";
import { errorMessage, type Tier, type VmRecord } from "@/lib/api";
import { formatDuration, formatWhen } from "@/lib/format";
import { cn } from "@/lib/utils";
import { insightApi, type TimelineEntry } from "@/lib/vm-insight-api";
import { eventLabel, groupTimeline, mergeTimeline, outcomeText } from "@/lib/vm-insight";

const TONE: Record<"ok" | "bad" | "neutral", string> = {
  ok: "border-tier-low/40 text-tier-low",
  bad: "border-tier-critical/50 text-tier-critical",
  neutral: "",
};

const TIERS: Tier[] = ["low", "medium", "high", "critical"];

export function VmTimelineTab({ vm, refreshKey }: { vm: VmRecord; refreshKey: string }) {
  const [reloads, setReloads] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);
  const vmxPath = vm.vmxPath;
  // The pages read so far, for what was asked (`key`): another VM, a finished job or Refresh starts again.
  const key = `${vmxPath}|${refreshKey}|${reloads}`;
  const [read, setRead] = useState<{
    key: string;
    entries?: TimelineEntry[];
    next: number | null;
    error?: string;
  } | null>(null);
  const current = read?.key === key ? read : null;
  const entries = current?.entries ?? null;
  const next = current?.next ?? null;
  const error = current?.error ?? null;

  useEffect(() => {
    let stale = false;
    insightApi.vmTimeline(vmxPath, null).then(
      (page) => !stale && setRead({ key, entries: page.entries, next: page.nextBefore }),
      (err: unknown) => !stale && setRead({ key, next: null, error: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [vmxPath, key]);

  async function loadOlder() {
    if (next === null) return;
    setLoadingMore(true);
    try {
      const page = await insightApi.vmTimeline(vmxPath, next);
      setRead((was) =>
        was && was.key === key
          ? { key, entries: mergeTimeline(was.entries ?? [], page.entries), next: page.nextBefore }
          : was,
      );
    } catch (err) {
      setRead({ key, next: null, error: errorMessage(err) });
    } finally {
      setLoadingMore(false);
    }
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <TriangleAlertIcon />
        <AlertTitle>Could not read the timeline</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }
  if (!entries) {
    return (
      <div className="flex flex-col gap-2" aria-label="Reading the timeline">
        <Skeleton className="h-14 w-full" />
        <Skeleton className="h-14 w-full" />
      </div>
    );
  }
  if (entries.length === 0) {
    return (
      <Empty className="border py-8">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <HistoryIcon />
          </EmptyMedia>
          <EmptyTitle>Nothing yet</EmptyTitle>
          <EmptyDescription>
            What Remotely does to this VM (power, snapshots, settings, labels, approvals) shows here, from the audit
            log.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }

  const groups = groupTimeline(entries);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        From the audit log and the job journal, newest first.
        <RefreshButton className="ml-auto" onClick={() => setReloads((n) => n + 1)} />
      </div>
      <ol className="flex flex-col gap-2">
        {groups.map((group) => {
          const outcome = outcomeText(group.outcome);
          const tier = TIERS.find((t) => t === group.tier);
          return (
            <li key={group.key} className="rounded-md border p-2.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-medium break-words">{group.action}</span>
                {tier && <TierBadge tier={tier} />}
                {outcome && (
                  <Badge variant="outline" className={cn(TONE[outcome.tone])}>
                    {outcome.text}
                  </Badge>
                )}
                <span className="ml-auto text-xs text-muted-foreground">{formatWhen(group.at)}</span>
              </div>
              {group.reason && <div className="mt-1 text-xs">Reason: {group.reason}</div>}
              {group.outcome?.error && <div className="mt-1 text-xs text-tier-critical">{group.outcome.error}</div>}
              {group.outcome?.safetySnapshot && (
                <div className="mt-1 text-xs text-muted-foreground">
                  Safety snapshot first: {group.outcome.safetySnapshot}
                </div>
              )}
              <ul className="mt-1.5 flex flex-col gap-0.5 text-xs text-muted-foreground">
                {group.entries.map((e) => (
                  <li key={e.seq} className="flex flex-wrap gap-x-2">
                    <span className="font-medium text-foreground/80">{eventLabel(e.event)}</span>
                    <span>{formatWhen(e.at)}</span>
                    {e.event === "job_finished" && group.outcome?.durationMs != null && (
                      <span>took {formatDuration(group.outcome.durationMs / 1000)}</span>
                    )}
                    {e.otherTargets > 0 && <span>with {e.otherTargets} other target(s)</span>}
                    {e.detail && <span className="w-full break-words">{e.detail}</span>}
                  </li>
                ))}
              </ul>
            </li>
          );
        })}
      </ol>
      {next !== null && (
        <Button
          variant="outline"
          size="sm"
          className="self-center"
          disabled={loadingMore}
          onClick={() => void loadOlder()}
        >
          Show older
        </Button>
      )}
    </div>
  );
}
