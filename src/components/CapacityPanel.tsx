// MO-04: the host capacity panel. RAM and vCPUs assigned to the running VMs against what this machine
// has, its CPU right now, and free space on each drive that holds a VM folder (the VM-07 check's
// reads, shown before anything is started).

import { CpuIcon, HardDriveIcon, MemoryStickIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LevelIcon, Meter } from "@/components/MetricBits";
import type { HostCapacity } from "@/lib/api";
import { plural } from "@/lib/format";
import { formatBytes, formatPct, level, type Level } from "@/lib/metrics";

const MB = 1024 * 1024;

function gb(mb: number) {
  return formatBytes(mb * MB);
}

export function CapacityPanel({ capacity }: { capacity: HostCapacity | null }) {
  if (!capacity) {
    return <div className="grid gap-4 md:grid-cols-3" aria-busy />;
  }
  const ramPct = capacity.physicalRamMb ? (capacity.assignedRamMb * 100) / capacity.physicalRamMb : null;
  const ramLevel: Level = ramPct === null ? "ok" : ramPct > 100 ? "critical" : ramPct > 90 ? "warning" : "ok";
  const inUse = capacity.availableRamMb === null ? null : Math.max(0, capacity.physicalRamMb - capacity.availableRamMb);
  const cpuRatio = capacity.logicalCpus ? capacity.assignedVcpus / capacity.logicalCpus : null;
  const hostCpu = capacity.hostCpuPct;
  const unchecked = capacity.warnings.filter((w) => w.kind === "unchecked");

  return (
    <section aria-label="Host capacity" className="grid gap-4 md:grid-cols-3">
      <Card size="sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <MemoryStickIcon className="size-4 text-muted-foreground" /> RAM
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex items-baseline justify-between gap-2">
            <span>
              <span className="font-semibold">{gb(capacity.assignedRamMb)}</span>{" "}
              <span className="text-muted-foreground">assigned of {gb(capacity.physicalRamMb)}</span>
            </span>
            <span className="flex items-center gap-1 tabular-nums">
              <LevelIcon level={ramLevel} />
              {formatPct(ramPct)}
            </span>
          </div>
          <Meter pct={ramPct} level={ramLevel} label="RAM assigned to running VMs" />
          <p className="text-xs text-muted-foreground">
            {plural(capacity.runningVms, "running VM")}
            {inUse !== null && <> · Windows has {gb(inUse)} in use</>}
            {capacity.unsizedVms > 0 && <> · {capacity.unsizedVms} of unknown size left out</>}
          </p>
        </CardContent>
      </Card>

      <Card size="sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <CpuIcon className="size-4 text-muted-foreground" /> CPU
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex items-baseline justify-between gap-2">
            <span>
              <span className="font-semibold">{capacity.assignedVcpus} vCPUs</span>{" "}
              <span className="text-muted-foreground">on {plural(capacity.logicalCpus, "logical CPU")}</span>
            </span>
            {cpuRatio !== null && (
              <span className="text-muted-foreground tabular-nums">{cpuRatio.toFixed(2)} per CPU</span>
            )}
          </div>
          <Meter pct={hostCpu} level={level(hostCpu, [75, 90])} label="Host CPU busy" />
          <p className="flex items-center gap-1 text-xs text-muted-foreground">
            <LevelIcon level={level(hostCpu, [75, 90])} />
            Host CPU busy now: {formatPct(hostCpu)}
          </p>
        </CardContent>
      </Card>

      <Card size="sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <HardDriveIcon className="size-4 text-muted-foreground" /> VM folders
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {capacity.drives.length === 0 && <p className="text-xs text-muted-foreground">No VM folders known yet.</p>}
          {capacity.drives.map((d) => {
            const usedPct = 100 - d.freePct;
            const driveLevel: Level = d.low ? "critical" : d.freePct < 20 ? "warning" : "ok";
            return (
              <div key={d.drive} className="space-y-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate font-medium" title={d.drive}>
                    {d.drive} <span className="text-xs font-normal text-muted-foreground">{plural(d.vms, "VM")}</span>
                  </span>
                  <span className="flex items-center gap-1 text-xs tabular-nums">
                    <LevelIcon level={driveLevel} />
                    {formatBytes(d.freeBytes)} free ({formatPct(d.freePct)})
                  </span>
                </div>
                <Meter pct={usedPct} level={driveLevel} label={`Used space on ${d.drive}`} />
              </div>
            );
          })}
        </CardContent>
      </Card>
      {unchecked.length > 0 && (
        <p className="text-xs text-muted-foreground md:col-span-3">
          {unchecked.map((w) => (w.kind === "unchecked" ? w.message : "")).join(" ")}
        </p>
      )}
    </section>
  );
}
