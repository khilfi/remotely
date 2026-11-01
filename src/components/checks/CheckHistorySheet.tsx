// MO-08: a check's history in a sheet: where it stands, its uptime and time taken over the range, and each run (newest
// first, at most 500). Read when it opens and again after each of its runs; reads only.

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { RangePicker } from "@/components/RangePicker";
import { CheckStatusBadge, Sparkline } from "@/components/checks/CheckBits";
import { errorMessage } from "@/lib/api";
import { checksApi, type CheckHistory } from "@/lib/checks-api";
import { everyText, resultLabel, specText, tookText, uptimeText } from "@/lib/checks";
import type { ChartRange, HistoryRange } from "@/lib/dashboard-api";
import { cn } from "@/lib/utils";

function time(at: number) {
  const date = new Date(at);
  const today = new Date().toDateString() === date.toDateString();
  return today
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function CheckHistorySheet({
  checkId,
  range,
  onRangeChange,
  onClose,
}: {
  checkId: string | null;
  range: HistoryRange;
  onRangeChange: (range: HistoryRange) => void;
  onClose: () => void;
}) {
  const [read, setRead] = useState<CheckHistory | null>(null);
  // A history read for another check (or another range) isn't shown while this one is read.
  const history = read && checkId && read.row.check.id === checkId ? read : null;

  useEffect(() => {
    if (!checkId) return;
    let stopped = false;
    const read = () =>
      checksApi.history(checkId, range).then(
        (h) => {
          if (!stopped) setRead(h);
        },
        (err) => {
          if (!stopped) toast.error(errorMessage(err));
        },
      );
    void read();
    const unlisten = checksApi.onEvent((event) => {
      if (event.kind === "changed" || event.checkId === checkId) void read();
    });
    return () => {
      stopped = true;
      void unlisten.then((stop) => stop());
    };
  }, [checkId, range]);

  const row = history?.row;
  return (
    <Sheet open={checkId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="flex w-full flex-col gap-0 sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <span className="truncate">{row?.check.name ?? "Check"}</span>
            {row && <CheckStatusBadge status={row.status} />}
          </SheetTitle>
          <SheetDescription>
            {row ? (
              <>
                {specText(row.check.spec)} on <span data-mask="host">{row.target.name}</span>,{" "}
                {everyText(row.check.intervalSecs)}
              </>
            ) : (
              "Reading its history…"
            )}
          </SheetDescription>
        </SheetHeader>
        {row && history && (
          <div className="flex min-h-0 flex-1 flex-col gap-4 px-4 pb-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <RangePicker
                value={range}
                onChange={(r: ChartRange) => r !== "live" && onRangeChange(r)}
                label="History range"
                live={false}
              />
              <span className="text-sm text-muted-foreground">
                Uptime <span className="font-medium text-foreground tabular-nums">{uptimeText(row.uptime)}</span>
              </span>
            </div>
            <Sparkline points={row.spark} width={480} height={56} className="w-full" />
            {history.results.length === 0 ? (
              <p className="text-sm text-muted-foreground">No runs in this range yet.</p>
            ) : (
              <div className="min-h-0 flex-1 overflow-y-auto rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-28">When</TableHead>
                      <TableHead className="w-24">Result</TableHead>
                      <TableHead className="w-20 text-right">Time</TableHead>
                      <TableHead>Detail</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {history.results.map((r) => (
                      <TableRow key={r.at}>
                        <TableCell className="tabular-nums">{time(r.at)}</TableCell>
                        <TableCell
                          className={cn(
                            r.result === "down" && "text-status-critical",
                            r.result === "unknown" && "text-status-warning",
                          )}
                        >
                          {resultLabel(r)}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{tookText(r.tookMs)}</TableCell>
                        <TableCell className="whitespace-normal break-words">{r.detail}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
