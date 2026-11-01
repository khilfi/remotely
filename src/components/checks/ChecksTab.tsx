// MO-08: the Dashboard's Checks tab: every health check of the workspace shown with its status, last result, a
// sparkline of the time its runs took and its uptime over the range. A row opens its history; its menu runs it now,
// edits, pauses or deletes it. Read when the tab shows and again after each run (checks://event), never while hidden.
// Edits are audited by the core and refused while presenting with the read-only lock; "Run now" only reads.

import { useEffect, useState } from "react";
import { HeartPulseIcon, HistoryIcon, PauseIcon, PencilIcon, PlayIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { useReadOnlyReason } from "@/components/Presentation";
import { RowMenu } from "@/components/RowMenu";
import { ReasonLine } from "@/components/WhyDisabled";
import { CheckDialog } from "@/components/checks/CheckDialog";
import { CheckHistorySheet } from "@/components/checks/CheckHistorySheet";
import { CheckStatusBadge, Sparkline } from "@/components/checks/CheckBits";
import { errorMessage } from "@/lib/api";
import { checksApi, type CheckInput, type CheckRow, type ChecksOverview, type HealthCheck } from "@/lib/checks-api";
import { agoText, everyText, newCheckInput, specText, tookText, uptimeText, waitText, withResult } from "@/lib/checks";
import type { HistoryRange } from "@/lib/dashboard-api";
import { probeTarget, type ToolTarget } from "@/lib/toolbox";

/** What another page asked the tab to show: a check's history, or a new check on a row. */
export interface ChecksRequest {
  checkId?: string;
  add?: ToolTarget;
  /** Counts up so the same request can come twice. */
  n: number;
}

interface Props {
  active: boolean;
  range: HistoryRange;
  onRangeChange: (range: HistoryRange) => void;
  request: ChecksRequest | null;
  /** The page header's "Add a check": counts up each time it is pressed. */
  addRequest: number;
}

type Editing = { kind: "new"; input: CheckInput } | { kind: "edit"; check: HealthCheck } | null;

/** The longest the sparklines and uptime wait to be read again while runs come in. */
const FULL_READ_MS = 30_000;

function summaryLine(o: ChecksOverview): string {
  const s = o.summary;
  const parts = [
    `${s.total} check${s.total === 1 ? "" : "s"}`,
    s.up > 0 ? `${s.up} up` : null,
    s.failing > 0 ? `${s.failing} failing` : null,
    s.down > 0 ? `${s.down} down` : null,
    s.unknown > 0 ? `${s.unknown} can't check` : null,
    s.paused > 0 ? `${s.paused} paused` : null,
  ];
  return parts.filter((p): p is string => p !== null).join(" · ");
}

export function ChecksTab({ active, range, onRangeChange, request, addRequest }: Props) {
  const [overview, setOverview] = useState<ChecksOverview | null>(null);
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<CheckRow | null>(null);
  const [historyOf, setHistoryOf] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const readOnly = useReadOnlyReason();

  // Read while the tab shows. A run's result updates its row at once (no history read); the whole overview, with the
  // sparklines and uptime, is read again at most every FULL_READ_MS, or a second after a check is added, changed or
  // deleted.
  useEffect(() => {
    if (!active) return;
    let stopped = false;
    let timer: number | undefined;
    const read = () =>
      checksApi.overview(range).then(
        (o) => {
          if (stopped) return;
          setOverview(o);
          setNow(Date.now());
        },
        (err) => {
          if (!stopped) toast.error(errorMessage(err));
        },
      );
    void read();
    const readSoon = (wait: number) => {
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        void read();
      }, wait);
    };
    const unlisten = checksApi.onEvent((event) => {
      if (event.kind === "changed") {
        readSoon(1000);
        return;
      }
      setOverview((o) => (o ? withResult(o, event) : o));
      readSoon(FULL_READ_MS);
    });
    // "3 min ago" moves on between runs.
    const tick = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      window.clearInterval(tick);
      void unlisten.then((stop) => stop());
    };
  }, [active, range]);

  // A check's history, or a new check on a row, asked for from elsewhere (a link); and the header's "Add a check".
  // Each is taken once, while rendering (as ToolboxPage takes its requests).
  const [handled, setHandled] = useState(0);
  if (request && request.n !== handled) {
    setHandled(request.n);
    if (request.add) {
      const target = request.add;
      const name = target.kind === "address" ? target.host : target.label;
      setEditing({ kind: "new", input: newCheckInput(probeTarget(target), name) });
    } else if (request.checkId) {
      setHistoryOf(request.checkId);
    }
  }
  const [added, setAdded] = useState(addRequest);
  if (addRequest !== added) {
    setAdded(addRequest);
    setEditing({ kind: "new", input: newCheckInput({ kind: "address", host: "" }, "") });
  }

  const rows = overview?.rows ?? [];

  async function pause(row: CheckRow, paused: boolean) {
    try {
      await checksApi.setPaused(row.check.id, paused);
      toast.success(paused ? "Check paused" : "Check resumed");
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function runNow(row: CheckRow) {
    try {
      await checksApi.runNow(row.check.id);
      toast.success("Running it now");
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  return (
    <div className="flex min-h-0 flex-col gap-3">
      {overview && rows.length === 0 && (
        <EmptyState
          icon={HeartPulseIcon}
          title="No checks yet"
          description="A check pings, connects to or asks a host on a schedule, and alerts you when it goes down."
          help="checks"
          action={
            <Button
              disabled={readOnly !== null}
              onClick={() => setEditing({ kind: "new", input: newCheckInput({ kind: "address", host: "" }, "") })}
            >
              <HeartPulseIcon data-icon="inline-start" />
              Add a check
            </Button>
          }
        />
      )}
      {overview && rows.length > 0 && (
        <>
          <p className="text-sm text-muted-foreground">{summaryLine(overview)}</p>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-28">Status</TableHead>
                  <TableHead>Check</TableHead>
                  <TableHead>On</TableHead>
                  <TableHead>Last run</TableHead>
                  <TableHead className="w-40">Time taken</TableHead>
                  <TableHead className="w-20 text-right">Uptime</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.check.id} className="cursor-pointer" onClick={() => setHistoryOf(row.check.id)}>
                    <TableCell>
                      <CheckStatusBadge status={row.status} />
                      {waitText(row.waitingUntil, now) && (
                        <div className="mt-1 text-xs text-muted-foreground">{waitText(row.waitingUntil, now)}</div>
                      )}
                    </TableCell>
                    <TableCell className="max-w-56">
                      <div className="truncate font-medium">{row.check.name}</div>
                      <div className="truncate text-xs text-muted-foreground">
                        {specText(row.check.spec)}, {everyText(row.check.intervalSecs)}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-48">
                      <div className="truncate" data-mask={row.target.kind === "address" ? "host" : undefined}>
                        {row.target.name}
                      </div>
                      {row.target.host && row.target.kind !== "address" && (
                        <div className="truncate text-xs text-muted-foreground" data-mask="host">
                          {row.target.host}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="max-w-72">
                      {row.last ? (
                        <>
                          <div className="truncate" title={row.last.detail}>
                            {row.last.detail}
                          </div>
                          <div className="text-xs text-muted-foreground">{agoText(row.last.at, now)}</div>
                        </>
                      ) : (
                        <span className="text-muted-foreground">Not run yet</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Sparkline points={row.spark} width={72} height={20} />
                        <span className="text-xs text-muted-foreground tabular-nums">
                          {tookText(row.last?.result === "up" ? row.last.tookMs : null)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{uptimeText(row.uptime)}</TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <RowMenu label={row.check.name}>
                        <DropdownMenuItem onSelect={() => setHistoryOf(row.check.id)}>
                          <HistoryIcon />
                          Show history
                        </DropdownMenuItem>
                        <DropdownMenuItem disabled={row.check.paused} onSelect={() => void runNow(row)}>
                          <RefreshCwIcon />
                          Run now
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          disabled={readOnly !== null}
                          onSelect={() => setEditing({ kind: "edit", check: row.check })}
                        >
                          <PencilIcon />
                          <div>
                            Edit
                            <ReasonLine reason={readOnly} />
                          </div>
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={readOnly !== null}
                          onSelect={() => void pause(row, !row.check.paused)}
                        >
                          {row.check.paused ? <PlayIcon /> : <PauseIcon />}
                          {row.check.paused ? "Resume" : "Pause"}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          variant="destructive"
                          disabled={readOnly !== null}
                          onSelect={() => setDeleting(row)}
                        >
                          <Trash2Icon />
                          Delete
                        </DropdownMenuItem>
                      </RowMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      )}
      {editing && (
        <CheckDialog
          start={editing}
          onClose={() => setEditing(null)}
          // A new or changed check runs at the next tick; the list reads again on its events.
          onSaved={() => undefined}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete the check '${deleting.check.name}'?`}
          description="Its history goes with it. Alerts it raised stay in the alert list."
          confirmLabel="Delete"
          onConfirm={async () => {
            await checksApi.remove(deleting.check.id);
            toast.success("Check deleted");
          }}
          onClose={() => setDeleting(null)}
        />
      )}
      <CheckHistorySheet
        checkId={historyOf}
        range={range}
        onRangeChange={onRangeChange}
        onClose={() => setHistoryOf(null)}
      />
    </div>
  );
}
