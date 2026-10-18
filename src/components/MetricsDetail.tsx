// MO-03 drill-down: one VM or host with live charts of the last 30 minutes (kept in memory by the core),
// its current readings and each mounted disk. Host-side series come from the VM's process (MO-01),
// guest series from a watched session (MO-02). Each chart has one axis and one unit.

import { useEffect, useState } from "react";
import { EyeIcon, SquareTerminalIcon, ZapIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EnvBadge, StateBadge } from "@/components/Badges";
import { GuestStatusBadge } from "@/components/GuestStatusBadge";
import { LevelIcon, Meter } from "@/components/MetricBits";
import { MetricChart, type ChartSeries } from "@/components/MetricChart";
import { api, type DashboardRow, type MetricPoint } from "@/lib/api";
import { formatDuration } from "@/lib/format";
import { formatBytes, formatPct, formatRate, level, rowCpu, rowMemory, type Thresholds } from "@/lib/metrics";
import type { ResolvedTheme } from "@/lib/theme";

interface Props {
  row: DashboardRow | null;
  /** Bumped on every metrics round, so the charts move on. */
  round: number;
  thresholds: Thresholds;
  theme: ResolvedTheme;
  onClose: () => void;
  onWatch: (sessionId: string, watch: boolean) => void;
  onConnect: (sessionId: string) => void;
  /** Opens the command palette on this VM's actions. */
  onActions: (vmxPath: string) => void;
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

export function MetricsDetail({ row, round, thresholds, theme, onClose, onWatch, onConnect, onActions }: Props) {
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

  const current = series && series.key === rowKey ? series : { host: [], guest: [] };
  const { times, host, guest } = align(current.host, current.guest);
  const values = (points: (MetricPoint | null)[], pick: (p: MetricPoint) => number | null) =>
    points.map((p) => (p ? pick(p) : null));
  const hasHost = row?.kind === "vm";
  const hasGuest = guestKey !== null;
  const two = (a: ChartSeries | null, b: ChartSeries | null) => [a, b].filter((s): s is ChartSeries => s !== null);

  const cpu = row ? rowCpu(row) : null;
  const memory = row ? rowMemory(row) : null;
  const linked = row?.kind === "vm" ? row.sessions : [];

  return (
    <Sheet open={row !== null} onOpenChange={(open) => !open && onClose()}>
      {row && (
        <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-3xl">
          <SheetHeader>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary">{row.kind === "vm" ? "VM" : "Host"}</Badge>
              {row.powerState && <StateBadge state={row.powerState} />}
              <EnvBadge env={row.environment} />
              {row.guestStatus && <GuestStatusBadge status={row.guestStatus} />}
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
              {guestKey ? (
                <Button size="sm" variant="ghost" onClick={() => onWatch(guestKey, false)}>
                  Stop guest metrics
                </Button>
              ) : (
                linked.map((s) => (
                  <Button key={s.id} size="sm" variant="outline" onClick={() => onWatch(s.id, true)}>
                    <EyeIcon /> Watch guest via {s.name}
                  </Button>
                ))
              )}
            </div>
            {row.guestStatus?.message && (
              <p className="text-xs text-muted-foreground">
                {row.guestStatus.message}
                {row.guestStatus.retryInSecs != null && ` Next try in ${row.guestStatus.retryInSecs} s.`}
              </p>
            )}
          </SheetHeader>

          <div className="flex flex-col gap-4 overflow-auto px-4 pb-4">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat
                label="CPU"
                value={formatPct(cpu?.value ?? null)}
                hint={row.host?.hostCpuPct != null ? `${formatPct(row.host.hostCpuPct)} of this host` : undefined}
              />
              <Stat
                label="Memory"
                value={formatBytes(memory?.used ?? null)}
                hint={memory?.total ? `of ${formatBytes(memory.total)}` : undefined}
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
              max={100}
              format={(v) => `${Math.round(v)}%`}
              series={two(
                hasHost ? { label: "Host side", slot: 1, values: values(host, (p) => p.cpuPct) } : null,
                hasGuest ? { label: "Guest", slot: 2, values: values(guest, (p) => p.cpuPct) } : null,
              )}
            />
            <MetricChart
              title="Memory"
              subtitle={hasHost ? "Host side: the VM process's working set. Guest: memory in use." : "Memory in use"}
              times={times}
              theme={theme}
              format={(v) => formatBytes(v)}
              series={two(
                hasHost ? { label: "Host side", slot: 1, values: values(host, (p) => p.memBytes) } : null,
                hasGuest ? { label: "Guest", slot: 2, values: values(guest, (p) => p.memBytes) } : null,
              )}
            />
            <MetricChart
              title="Disk I/O"
              subtitle={hasHost ? "Read and written by the VM's process" : "Read and written by the guest's disks"}
              times={times}
              theme={theme}
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
                  ? "Watch the guest through a linked session to add its own CPU, memory, disks, network and load."
                  : "Link a session to this VM on the Sessions page to read the guest's own CPU, memory, disks, network and load over SSH."}
              </p>
            )}
          </div>
        </SheetContent>
      )}
    </Sheet>
  );
}
