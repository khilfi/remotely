// MO-03 drill-down: one VM or host with live charts of the last 30 minutes (kept in memory by the core),
// its current readings and each mounted disk. Host-side series come from the VM's process (MO-01),
// guest series from a watched session (MO-02). Each chart has one axis and one unit. MO-15: the memory chart
// draws what there is (a VM's configured RAM, a host's total) dashed next to what is in use, and Linux swap has a
// chart of its own. MO-13: "Host details…" opens the session's host details. MO-02: a guest polled less often than
// the host side (Settings, Dashboard) keeps its line on a VM's charts (chart-gaps.ts). MO-06: the dashboard's one range
// (UX-07), which the sheet's picker changes for the whole page, shows the last hour to the last week from the history on
// disk, carried on with the live rounds. UX-03: watching a host has one home, the page's Watch hosts; the sheet says
// how a VM's guest gets watched, and a host whose key isn't trusted opens a terminal that asks about it.

import { useEffect, useState } from "react";
import { HardDriveIcon, RotateCwIcon, SquareTerminalIcon, ZapIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EnvBadge, StateBadge } from "@/components/Badges";
import { GuestStatusBadge } from "@/components/GuestStatusBadge";
import { LevelIcon, Meter } from "@/components/MetricBits";
import { MetricChart, type ChartSeries } from "@/components/MetricChart";
import { RangePicker } from "@/components/RangePicker";
import { chartPoints, useHistory } from "@/hooks/use-chart-points";
import { api, type DashboardRow, type MetricPoint } from "@/lib/api";
import { guestGapMs, joinShortGaps } from "@/lib/chart-gaps";
import type { ChartRange } from "@/lib/dashboard-api";
import { isHistoryRange, rangeLabel } from "@/lib/history";
import { formatDuration } from "@/lib/format";
import { formatBytes, formatPct, formatRate, level, rowCpu, rowMemory, type Thresholds } from "@/lib/metrics";
import type { ResolvedTheme } from "@/lib/theme";

interface Props {
  row: DashboardRow | null;
  /** Bumped on every metrics round while the dashboard shows, so the charts move on. */
  round: number;
  /** MO-06: the dashboard shows and the window is visible, so the history may be read. */
  live: boolean;
  /** MO-02: seconds between two polls of a watched host. */
  guestIntervalSecs: number;
  /** The dashboard's one range, and changing it (for the whole page). */
  range: ChartRange;
  onRangeChange: (range: ChartRange) => void;
  thresholds: Thresholds;
  theme: ResolvedTheme;
  onClose: () => void;
  /** MO-02: logs in to a parked or waiting host again. */
  onRetry: (sessionId: string) => void;
  onConnect: (sessionId: string) => void;
  /** Opens the command palette on this VM's actions. */
  onActions: (vmxPath: string) => void;
  /** MO-13, MO-14: a session's host details. */
  onHostDetails: (session: { id: string; name: string }) => void;
}

/** Both series on one time line: the core records host and guest samples of a round at the same t. */
function align(host: MetricPoint[], guest: MetricPoint[]) {
  const times = [...new Set([...host.map((p) => p.t), ...guest.map((p) => p.t)])].sort((a, b) => a - b);
  const at = (points: MetricPoint[]) => {
    const byT = new Map(points.map((p) => [p.t, p]));
    return times.map((t) => byT.get(t) ?? null);
  };
  return { times, host: at(host), guest: at(guest) };
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-lg border bg-card px-3 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
      {hint && <div className="truncate text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}

export function MetricsDetail({
  row,
  round,
  live,
  guestIntervalSecs,
  range,
  onRangeChange,
  thresholds,
  theme,
  onClose,
  onRetry,
  onConnect,
  onActions,
  onHostDetails,
}: Props) {
  const [series, setSeries] = useState<{ key: string; host: MetricPoint[]; guest: MetricPoint[] } | null>(null);
  const rowKey = row ? `${row.key}|${row.watchedSession ?? ""}` : null;
  const hostKey = row?.kind === "vm" ? row.key : null;
  const guestKey = row?.watchedSession ?? null;

  useEffect(() => {
    if (!rowKey) return;
    let stale = false;
    Promise.all([
      hostKey ? api.metricsSeries("host", hostKey) : Promise.resolve([]),
      guestKey ? api.metricsSeries("guest", guestKey) : Promise.resolve([]),
    ]).then(
      ([host, guest]) => {
        if (!stale) setSeries({ key: rowKey, host, guest });
      },
      () => {
        if (!stale) setSeries({ key: rowKey, host: [], guest: [] });
      },
    );
    return () => {
      stale = true;
    };
  }, [rowKey, hostKey, guestKey, round]);

  const open = row !== null && live;
  const hostHistory = useHistory(hostKey ? { source: "host", key: hostKey } : null, range, open);
  const guestHistory = useHistory(guestKey ? { source: "guest", key: guestKey } : null, range, open);
  const current = series && series.key === rowKey ? series : { host: [], guest: [] };
  const { times, host, guest } = align(
    chartPoints(range, current.host, hostHistory),
    chartPoints(range, current.guest, guestHistory),
  );
  const hasHost = row?.kind === "vm";
  const values = (points: (MetricPoint | null)[], pick: (p: MetricPoint) => number | null) => {
    const raw = points.map((p) => (p ? pick(p) : null));
    // A VM's guest has no reading at the host-only rounds between its polls (a history range is in buckets).
    return hasHost && points === guest && !isHistoryRange(range)
      ? joinShortGaps(times, raw, guestGapMs(guestIntervalSecs))
      : raw;
  };
  const empty = isHistoryRange(range)
    ? hostHistory || guestHistory
      ? "No history for this range yet: it is kept from the first minute a VM runs or a host is watched."
      : "Reading the history…"
    : undefined;
  const hasGuest = guestKey !== null;
  const two = (a: ChartSeries | null, b: ChartSeries | null) => [a, b].filter((s): s is ChartSeries => s !== null);

  const cpu = row ? rowCpu(row) : null;
  const memory = row ? rowMemory(row) : null;
  const linked = row?.kind === "vm" ? row.sessions : [];
  // MO-13: the session whose host details open: the watched one, else the first linked.
  const detailsSession = row?.watchedSession
    ? (row.sessions.find((s) => s.id === row.watchedSession) ?? null)
    : (linked[0] ?? null);
  // Host-side series show once the VM's process was seen, or when there is nothing else to show.
  const showHost = hasHost && (host.some((p) => p !== null) || !hasGuest);
  // MO-15: memory in use, and dashed what there is: one line in its colour, or muted when it bounds two.
  const memorySeries = two(
    showHost ? { label: "Working set", slot: 1, values: values(host, (p) => p.memBytes) } : null,
    hasGuest ? { label: hasHost ? "Guest in use" : "In use", slot: 2, values: values(guest, (p) => p.memBytes) } : null,
  );
  if (hasHost) {
    // The VM's settings say how much it has, whether or not its process was seen at that time.
    const configured = row?.memsizeMb ? row.memsizeMb * 1024 * 1024 : null;
    memorySeries.push({
      label: "Configured RAM",
      slot: memorySeries.length > 1 ? "muted" : (memorySeries[0]?.slot ?? 1),
      dashed: true,
      values: times.map((_, i) => host[i]?.memTotalBytes ?? configured),
    });
  } else if (hasGuest) {
    memorySeries.push({ label: "Total", slot: 2, dashed: true, values: values(guest, (p) => p.memTotalBytes) });
  }
  const swapTotal = row?.guest?.swapTotalBytes ?? null;
  const swapUsed = row?.guest?.swapUsedBytes ?? null;

  return (
    <Sheet open={row !== null} onOpenChange={(open) => !open && onClose()}>
      {row && (
        <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-3xl">
          <SheetHeader>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary">{row.kind === "vm" ? "VM" : "Host"}</Badge>
              {row.powerState && <StateBadge state={row.powerState} />}
              <EnvBadge env={row.environment} />
              {row.guestStatus && <GuestStatusBadge status={row.guestStatus} onCheckKey={onConnect} />}
            </div>
            <SheetTitle>{row.name}</SheetTitle>
            <SheetDescription>
              {[
                row.address,
                row.guestOs,
                row.vcpus && `${row.vcpus} vCPUs`,
                row.memsizeMb && `${formatBytes(row.memsizeMb * 1024 * 1024)} RAM`,
              ]
                .filter(Boolean)
                .join(" · ") || "No details yet"}
            </SheetDescription>
            <div className="flex flex-wrap gap-2 pt-1">
              {row.kind === "vm" && (
                <Button size="sm" variant="outline" onClick={() => onActions(row.key)}>
                  <ZapIcon /> Actions…
                </Button>
              )}
              {guestKey && (
                <Button size="sm" variant="outline" onClick={() => onConnect(guestKey)}>
                  <SquareTerminalIcon /> Open terminal
                </Button>
              )}
              {detailsSession && (
                <Button size="sm" variant="outline" onClick={() => onHostDetails(detailsSession)}>
                  <HardDriveIcon /> Host details…
                </Button>
              )}
            </div>
            {row.guestStatus?.message && row.guestStatus.state !== "hostKey" && (
              <p className="text-xs text-muted-foreground">
                {row.guestStatus.message}
                {row.guestStatus.retryInSecs != null && ` Next try in ${row.guestStatus.retryInSecs} s.`}
              </p>
            )}
            {row.guestStatus && (row.guestStatus.parked || row.guestStatus.state === "paused") && (
              <div>
                <Button size="sm" variant="outline" onClick={() => onRetry(row.guestStatus!.sessionId)}>
                  <RotateCwIcon /> Retry
                </Button>
              </div>
            )}
          </SheetHeader>

          <div className="flex flex-col gap-4 overflow-auto px-4 pb-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs text-muted-foreground">{rangeLabel(range)}</span>
              <RangePicker value={range} onChange={onRangeChange} label="The dashboard's range" />
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat
                label="CPU"
                value={formatPct(cpu?.value ?? null)}
                hint={row.host?.hostCpuPct != null ? `${formatPct(row.host.hostCpuPct)} of this host` : undefined}
              />
              <Stat
                label="Memory"
                value={formatBytes(memory?.used ?? null)}
                hint={
                  [
                    memory?.total ? `of ${formatBytes(memory.total)}` : null,
                    row.host?.hostMemPct != null ? `${formatPct(row.host.hostMemPct)} of this host's RAM` : null,
                    swapTotal === 0
                      ? "no swap"
                      : swapTotal
                        ? `swap ${formatBytes(swapUsed)} of ${formatBytes(swapTotal)}`
                        : null,
                  ]
                    .filter(Boolean)
                    .join(" · ") || undefined
                }
              />
              <Stat
                label="Load (1, 5, 15 min)"
                value={row.guest?.load1 != null ? row.guest.load1.toFixed(2) : "—"}
                hint={
                  row.guest?.load5 != null && row.guest.load15 != null
                    ? `${row.guest.load5.toFixed(2)}, ${row.guest.load15.toFixed(2)}`
                    : undefined
                }
              />
              <Stat label="Up for" value={row.guest?.uptimeSecs != null ? formatDuration(row.guest.uptimeSecs) : "—"} />
            </div>

            <MetricChart
              title="CPU"
              subtitle="Busy share of its own CPUs"
              times={times}
              theme={theme}
              empty={empty}
              max={100}
              format={(v) => `${Math.round(v)}%`}
              series={two(
                showHost ? { label: "Host side", slot: 1, values: values(host, (p) => p.cpuPct) } : null,
                hasGuest ? { label: "Guest", slot: 2, values: values(guest, (p) => p.cpuPct) } : null,
              )}
            />
            <MetricChart
              title="Memory"
              subtitle={
                hasHost
                  ? "The VM process's working set on this host and, when watched, the guest's own use, under its configured RAM (dashed)"
                  : "In use (total minus available), under all the memory the host has (dashed)"
              }
              times={times}
              theme={theme}
              empty={empty}
              format={(v) => formatBytes(v)}
              series={memorySeries}
            />
            {hasGuest && swapTotal !== null && swapTotal > 0 && (
              <MetricChart
                title="Swap"
                subtitle="Swap in use under the swap there is (dashed)"
                times={times}
                theme={theme}
                empty={empty}
                format={(v) => formatBytes(v)}
                series={[
                  { label: "Swap in use", slot: 2, values: values(guest, (p) => p.swapUsedBytes) },
                  { label: "Swap size", slot: 2, dashed: true, values: values(guest, (p) => p.swapTotalBytes) },
                ]}
              />
            )}
            <MetricChart
              title="Disk I/O"
              subtitle={hasHost ? "Read and written by the VM's process" : "Read and written by the guest's disks"}
              times={times}
              theme={theme}
              empty={empty}
              format={(v) => formatRate(v)}
              series={[
                { label: "Read", slot: 1, values: values(hasHost ? host : guest, (p) => p.diskReadBps) },
                { label: "Write", slot: 2, values: values(hasHost ? host : guest, (p) => p.diskWriteBps) },
              ]}
            />
            {hasGuest && (
              <>
                <MetricChart
                  title="Network"
                  subtitle="All interfaces but loopback and container links"
                  times={times}
                  theme={theme}
                  empty={empty}
                  format={(v) => formatRate(v)}
                  series={[
                    { label: "Received", slot: 1, values: values(guest, (p) => p.netRxBps) },
                    { label: "Sent", slot: 2, values: values(guest, (p) => p.netTxBps) },
                  ]}
                />
                <MetricChart
                  title="Load"
                  subtitle="1-minute load average"
                  times={times}
                  theme={theme}
                  empty={empty}
                  format={(v) => v.toFixed(2)}
                  series={[{ label: "Load", slot: 1, values: values(guest, (p) => p.load1) }]}
                />
              </>
            )}

            {row.guest && row.guest.mounts.length > 0 && (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Mounted on</TableHead>
                      <TableHead>Device</TableHead>
                      <TableHead className="w-48">Used</TableHead>
                      <TableHead className="text-right">Size</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {row.guest.mounts.map((m) => {
                      const mountLevel = level(m.usedPct, thresholds.disk);
                      return (
                        <TableRow key={m.mount}>
                          <TableCell className="font-mono text-xs">{m.mount}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">{m.filesystem}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Meter pct={m.usedPct} level={mountLevel} label={`Used on ${m.mount}`} />
                              <span className="flex w-14 shrink-0 items-center justify-end gap-1 text-xs tabular-nums">
                                <LevelIcon level={mountLevel} />
                                {formatPct(m.usedPct)}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="text-right text-xs tabular-nums">{formatBytes(m.totalBytes)}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
            {!hasGuest && row.kind === "vm" && (
              <p className="text-xs text-muted-foreground">
                {linked.length > 0
                  ? `Watch ${linked[0].name} with Watch hosts to add the guest's own CPU, memory, disks and load.`
                  : "Link a session to this VM to add the guest's own CPU, memory, disks and load."}
              </p>
            )}
          </div>
        </SheetContent>
      )}
    </Sheet>
  );
}
