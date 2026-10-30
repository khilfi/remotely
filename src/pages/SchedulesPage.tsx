// VM-14, VM-27: the Schedules page. Every schedule with what it does, on which VMs and tags, when (the next run in local
// time, with what daylight saving does to it), its last run and its state: active, paused, or waiting for approval
// (new, edited, or something changed since: a VM became Prod or protected, a new VM got the tag, the approval rules
// changed), with the reason. UX-02: each row's main action (Review approval, Resume, or Runs) and one row menu with
// Runs, Pause, Edit and Delete; New schedule in the header, the snapshot chain warnings' limits in its ⋯ menu. Saving
// opens the approval dialog with the schedule's details (a standing approval: each run is a run of it). Reads the list
// when it shows and on each scheduler event.

import { useCallback, useEffect, useState, type ReactElement } from "react";
import { toast } from "sonner";
import {
  CalendarClockIcon,
  HistoryIcon,
  PauseIcon,
  PencilIcon,
  PlayIcon,
  PlusIcon,
  ShieldCheckIcon,
  Trash2Icon,
  TriangleAlertIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ApprovalDialog } from "@/components/ApprovalDialog";
import { TierBadge } from "@/components/Badges";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { PageHeader } from "@/components/PageHeader";
import { RowMenu } from "@/components/RowMenu";
import { useReadOnlyReason } from "@/components/Presentation";
import { ScheduleDialog } from "@/components/ScheduleDialog";
import { OutcomeBadge, ScheduleRunsSheet } from "@/components/ScheduleRunsSheet";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type ApprovalRequest, type Tag, type VaultInfo, type VmRecord } from "@/lib/api";
import { formatPlanned, rowReasons, stateLabel, targetsText } from "@/lib/schedules";
import {
  schedulesApi,
  type ChainLimits,
  type SaveOutcome,
  type ScheduleEvent,
  type ScheduleView,
} from "@/lib/schedules-api";
import { cn } from "@/lib/utils";

/** What another page asks of this one: a new schedule (for some VMs), or one schedule's runs. */
export interface SchedulesRequest {
  create?: boolean;
  vms?: string[];
  scheduleId?: string;
  n: number;
}

interface Props {
  active: boolean;
  vault: VaultInfo | null;
  onOpenVault: () => void;
  request: SchedulesRequest | null;
}

type Editor = { existing?: ScheduleView; initialVms?: string[] };

function StateBadge({ view }: { view: ScheduleView }) {
  const tone =
    view.state === "active"
      ? "border-success/40 text-success"
      : view.state === "needsApproval"
        ? "border-tier-high/50 text-tier-high"
        : "text-muted-foreground";
  return (
    <Badge variant="outline" className={cn("shrink-0", tone)}>
      {stateLabel(view.state)}
    </Badge>
  );
}

export function SchedulesPage({ active, vault, onOpenVault, request }: Props) {
  const [schedules, setSchedules] = useState<ScheduleView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const [editor, setEditor] = useState<Editor | null>(null);
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [approval, setApproval] = useState<ApprovalRequest | null>(null);
  const [runsOf, setRunsOf] = useState<ScheduleView | null>(null);
  const [deleting, setDeleting] = useState<ScheduleView | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [limitsOpen, setLimitsOpen] = useState(false);
  const readOnly = useReadOnlyReason();
  const reload = useCallback(() => setVersion((v) => v + 1), []);

  // The list, when the page shows and after each change.
  useEffect(() => {
    if (!active) return;
    let live = true;
    schedulesApi.list().then(
      (list) => {
        if (!live) return;
        setSchedules(list);
        setError(null);
      },
      (err: unknown) => live && setError(errorMessage(err)),
    );
    return () => {
      live = false;
    };
  }, [active, version]);

  // The scheduler's events: runs, missed runs, pauses. A schedule that waits for approval says so once.
  useEffect(() => {
    const unlisten = schedulesApi.onEvent((event: ScheduleEvent) => {
      reload();
      if (event.event === "needsApproval")
        toast.warning(`Schedule '${event.name}' waits for approval again`, { description: event.reason });
      if (event.event === "missed")
        toast.warning(`Schedule '${event.name}' missed a run`, { description: event.detail });
    });
    return () => void unlisten.then((stop) => stop());
  }, [reload]);

  const openEditor = useCallback(async (next: Editor) => {
    try {
      const [vmList, tagList] = await Promise.all([api.vmList(), api.tags()]);
      setVms(vmList);
      setTags(tagList);
      setEditor(next);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }, []);

  // Asked from another page (a VM's Schedules tab, the palette).
  useEffect(() => {
    if (!request) return;
    let live = true;
    if (request.create) {
      Promise.all([api.vmList(), api.tags()]).then(
        ([vmList, tagList]) => {
          if (!live) return;
          setVms(vmList);
          setTags(tagList);
          setEditor({ initialVms: request.vms });
        },
        (err: unknown) => toast.error(errorMessage(err)),
      );
    }
    if (request.scheduleId) {
      schedulesApi.get(request.scheduleId).then(
        (s) => live && setRunsOf(s),
        (err: unknown) => toast.error(errorMessage(err)),
      );
    }
    return () => {
      live = false;
    };
  }, [request]);

  function outcome(saved: SaveOutcome, done: string) {
    setEditor(null);
    reload();
    if (saved.approval) setApproval(saved.approval);
    else if (saved.schedule.state === "active") toast.success(done);
  }

  async function act(id: string, run: () => Promise<void>) {
    setBusy(id);
    try {
      await run();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
      reload();
    }
  }

  return (
    <div className="grid gap-4">
      <PageHeader
        page="schedules"
        tools={
          <DropdownMenuItem onSelect={() => setLimitsOpen(true)}>
            <TriangleAlertIcon />
            Snapshot chain warnings…
          </DropdownMenuItem>
        }
        primary={
          // The empty list has its own button.
          schedules && schedules.length > 0 ? (
            <WhyDisabled reason={readOnly}>
              <Button disabled={readOnly !== null} onClick={() => void openEditor({})}>
                <PlusIcon data-icon="inline-start" />
                New schedule
              </Button>
            </WhyDisabled>
          ) : undefined
        }
      />

      {error && <p className="text-sm text-destructive">{error}</p>}
      {!schedules && !error && <Skeleton className="h-32 w-full" />}
      {schedules?.length === 0 && (
        <EmptyState
          icon={CalendarClockIcon}
          title="No schedules yet"
          description="Take nightly snapshots, start a lab at 08:00 and suspend it at 19:00, or suspend idle VMs."
          action={
            <WhyDisabled reason={readOnly}>
              <Button disabled={readOnly !== null} onClick={() => void openEditor({})}>
                <PlusIcon data-icon="inline-start" />
                New schedule
              </Button>
            </WhyDisabled>
          }
        />
      )}
      {schedules && schedules.length > 0 && (
        <div className="overflow-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Schedule</TableHead>
                <TableHead>On</TableHead>
                <TableHead>When</TableHead>
                <TableHead>Last run</TableHead>
                <TableHead>State</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {schedules.map((s) => {
                const reasons = rowReasons(s, readOnly ?? (busy === s.id ? "Working…" : null));
                return (
                  <TableRow key={s.id}>
                    <TableCell className="align-top">
                      <div className="font-medium">{s.name}</div>
                      <div className="text-xs text-muted-foreground">{s.action}</div>
                    </TableCell>
                    <TableCell className="max-w-56 align-top text-sm break-words">{targetsText(s)}</TableCell>
                    <TableCell className="align-top text-sm">
                      <div>{s.when}</div>
                      {s.nextRun && (
                        <div className="text-xs text-muted-foreground">Next: {formatPlanned(s.nextRun.at)}</div>
                      )}
                      {s.nextRun?.note && <div className="text-xs text-tier-medium">{s.nextRun.note}</div>}
                      {s.running && <div className="text-xs text-muted-foreground">Running now…</div>}
                    </TableCell>
                    <TableCell className="align-top text-sm">
                      {s.lastRun ? (
                        <div className="grid justify-items-start gap-1">
                          <OutcomeBadge outcome={s.lastRun.outcome} />
                          <span className="text-xs text-muted-foreground">{formatPlanned(s.lastRun.dueAt)}</span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="max-w-64 align-top">
                      <div className="flex flex-wrap items-center gap-1">
                        <StateBadge view={s} />
                        {s.approval && s.state === "active" && <TierBadge tier={s.approval.tier} />}
                      </div>
                      {s.state !== "active" && s.stateReason && s.stateReason !== "new" && (
                        <p className="text-xs text-muted-foreground">{s.stateReason}</p>
                      )}
                      {s.asksAgain.length > 0 && (
                        <p className="text-xs text-tier-high">Asks again: {s.asksAgain.join("; ")}</p>
                      )}
                      {s.chainWarnings.length > 0 && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <p className="flex items-center gap-1 text-xs text-tier-medium">
                              <TriangleAlertIcon className="size-3" />
                              {s.chainWarnings.length === 1
                                ? "1 chain warning"
                                : `${s.chainWarnings.length} chain warnings`}
                            </p>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-sm">
                            <ul className="list-disc pl-4">
                              {s.chainWarnings.map((w) => (
                                <li key={w}>{w}</li>
                              ))}
                            </ul>
                          </TooltipContent>
                        </Tooltip>
                      )}
                    </TableCell>
                    <TableCell className="align-top">
                      {/* UX-02: the row's main action, then one row menu with the rest. */}
                      <div className="flex justify-end gap-1">
                        {s.state === "needsApproval" ? (
                          <WhyDisabled reason={reasons.approve}>
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={reasons.approve !== null}
                              onClick={() =>
                                void act(s.id, async () => {
                                  const saved = await schedulesApi.askApproval(s.id);
                                  outcome(saved, `Schedule '${s.name}' is active`);
                                })
                              }
                            >
                              <ShieldCheckIcon data-icon="inline-start" />
                              Review approval…
                            </Button>
                          </WhyDisabled>
                        ) : s.state === "paused" ? (
                          <WhyDisabled reason={reasons.resume}>
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={reasons.resume !== null}
                              onClick={() =>
                                void act(s.id, async () => {
                                  const saved = await schedulesApi.resume(s.id);
                                  outcome(saved, `Schedule '${s.name}' runs again`);
                                })
                              }
                            >
                              <PlayIcon data-icon="inline-start" />
                              Resume
                            </Button>
                          </WhyDisabled>
                        ) : (
                          <Button variant="ghost" size="sm" onClick={() => setRunsOf(s)}>
                            <HistoryIcon data-icon="inline-start" />
                            Runs
                          </Button>
                        )}
                        <RowMenu label={s.name}>
                          {s.state !== "active" && (
                            <DropdownMenuItem onSelect={() => setRunsOf(s)}>
                              <HistoryIcon />
                              Runs
                            </DropdownMenuItem>
                          )}
                          {s.state === "active" && (
                            <MenuItemWhy reason={reasons.pause}>
                              <DropdownMenuItem
                                disabled={reasons.pause !== null}
                                onSelect={() =>
                                  void act(s.id, async () => {
                                    await schedulesApi.pause(s.id);
                                  })
                                }
                              >
                                <PauseIcon />
                                Pause
                              </DropdownMenuItem>
                            </MenuItemWhy>
                          )}
                          <MenuItemWhy reason={reasons.edit}>
                            <DropdownMenuItem
                              disabled={reasons.edit !== null}
                              onSelect={() => void openEditor({ existing: s })}
                            >
                              <PencilIcon />
                              Edit…
                            </DropdownMenuItem>
                          </MenuItemWhy>
                          <DropdownMenuSeparator />
                          <MenuItemWhy reason={reasons.remove}>
                            <DropdownMenuItem
                              variant="destructive"
                              disabled={reasons.remove !== null}
                              onSelect={() => setDeleting(s)}
                            >
                              <Trash2Icon />
                              Delete…
                            </DropdownMenuItem>
                          </MenuItemWhy>
                        </RowMenu>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}

      {limitsOpen && <ChainLimitsDialog readOnly={readOnly} onSaved={reload} onClose={() => setLimitsOpen(false)} />}

      {editor && (
        <ScheduleDialog
          existing={editor.existing}
          initialVms={editor.initialVms}
          vms={vms}
          tags={tags}
          onClose={() => setEditor(null)}
          onSaved={(saved) =>
            outcome(
              saved,
              editor.existing
                ? `Saved schedule '${saved.schedule.name}'`
                : `Schedule '${saved.schedule.name}' is active`,
            )
          }
        />
      )}
      {approval && (
        <ApprovalDialog
          request={approval}
          vault={vault}
          onOpenVault={() => {
            setApproval(null);
            onOpenVault();
          }}
          approve={async (answers) => (await schedulesApi.approve(approval.id, answers)).id}
          cancel={() => api.cancelApproval(approval.id)}
          onClose={(approved) => {
            setApproval(null);
            reload();
            if (approved) toast.success("Schedule approved: it runs from its next time");
          }}
        />
      )}
      {runsOf && <ScheduleRunsSheet schedule={runsOf} refreshKey={version} onClose={() => setRunsOf(null)} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete schedule '${deleting.name}'?`}
          description={
            deleting.spec.action.kind === "snapshot"
              ? "Its approval is withdrawn and it never runs again. The snapshots it took stay on the VMs, named starting with 'Remotely schedule'."
              : "Its approval is withdrawn and it never runs again."
          }
          confirmLabel="Delete"
          onConfirm={async () => {
            await schedulesApi.remove(deleting.id);
            reload();
          }}
          onClose={() => setDeleting(null)}
        />
      )}
    </div>
  );
}

/** UX-02: a disabled menu item says why in a tooltip (a disabled item gets no pointer events itself). */
function MenuItemWhy({ reason, children }: { reason: string | null; children: ReactElement }) {
  return (
    <WhyDisabled reason={reason} className="flex w-full *:w-full">
      {children}
    </WhyDisabled>
  );
}

/** VM-27: when snapshot chains warn, on VMs and in this list (the header's ⋯ menu opens it). Audited. */
function ChainLimitsDialog({
  readOnly,
  onSaved,
  onClose,
}: {
  readOnly: string | null;
  onSaved: () => void;
  onClose: () => void;
}) {
  const [limits, setLimits] = useState<ChainLimits | null>(null);
  const [depth, setDepth] = useState("");
  const [size, setSize] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    schedulesApi.chainLimits().then(
      (l) => {
        setLimits(l);
        setDepth(String(l.maxDepth));
        setSize(String(l.maxSizeGb));
      },
      () => {},
    );
  }, []);

  const next = { maxDepth: Number(depth), maxSizeGb: Number(size) };
  const valid =
    Number.isInteger(next.maxDepth) &&
    next.maxDepth >= 1 &&
    next.maxDepth <= 32 &&
    Number.isInteger(next.maxSizeGb) &&
    next.maxSizeGb >= 1 &&
    next.maxSizeGb <= 10000;
  const changed = limits !== null && (next.maxDepth !== limits.maxDepth || next.maxSizeGb !== limits.maxSizeGb);
  const reason = readOnly ?? (!valid ? "Depth 1 to 32, size 1 to 10000 GB" : !changed ? "Nothing changed" : null);

  async function save() {
    setBusy(true);
    try {
      setLimits(await schedulesApi.setChainLimits(next));
      toast.success("Saved the snapshot chain warnings");
      onSaved();
      onClose();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-1">
            Snapshot chain warnings
            <HelpTip topic="chainLimits" />
          </DialogTitle>
          <DialogDescription>Flag a VM whose snapshot chain gets longer or bigger than this.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="chain-depth">Deeper than (snapshots)</Label>
            <Input
              id="chain-depth"
              className="w-28"
              inputMode="numeric"
              value={depth}
              onChange={(e) => setDepth(e.currentTarget.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="chain-size">Larger than (GB)</Label>
            <Input
              id="chain-size"
              className="w-28"
              inputMode="numeric"
              value={size}
              onChange={(e) => setSize(e.currentTarget.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <WhyDisabled reason={busy ? "Saving…" : reason}>
            <Button disabled={busy || reason !== null} onClick={() => void save()}>
              Save
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
