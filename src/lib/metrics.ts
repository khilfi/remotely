// MO-03: what the dashboard shows for a row, the colour thresholds, and number formats. A VM row has
// host-side samples (MO-01, no login) and, when a linked session is watched, guest samples (MO-02);
// where both measure the same thing, the guest's own view wins because it is what the OS sees.

import { useEffect, useState } from "react";
import type { DashboardRow, MetricSource } from "@/lib/api";

export type Level = "ok" | "warning" | "critical";

/** Warning and critical limits, in percent. */
export interface Thresholds {
  cpu: [number, number];
  memory: [number, number];
  disk: [number, number];
}

export const DEFAULT_THRESHOLDS: Thresholds = { cpu: [75, 90], memory: [80, 95], disk: [80, 90] };

const THRESHOLDS_KEY = "remotely.dashboard.thresholds";

function validPair(value: unknown): value is [number, number] {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    value.every((v) => typeof v === "number" && v >= 1 && v <= 100) &&
    value[0] <= value[1]
  );
}

function readThresholds(): Thresholds {
  try {
    const saved = JSON.parse(localStorage.getItem(THRESHOLDS_KEY) ?? "null") as Partial<Thresholds> | null;
    if (saved && validPair(saved.cpu) && validPair(saved.memory) && validPair(saved.disk)) {
      return { cpu: saved.cpu, memory: saved.memory, disk: saved.disk };
    }
  } catch {
    // Unreadable or unavailable storage: the defaults apply.
  }
  return DEFAULT_THRESHOLDS;
}

/** The dashboard's colour thresholds: a view preference, remembered per machine like the theme. */
export function useThresholds() {
  const [thresholds, setThresholds] = useState<Thresholds>(readThresholds);
  useEffect(() => {
    try {
      localStorage.setItem(THRESHOLDS_KEY, JSON.stringify(thresholds));
    } catch {
      // Not persisted; still applied for this session.
    }
  }, [thresholds]);
  return [thresholds, setThresholds] as const;
}

export function level(value: number | null, [warning, critical]: [number, number]): Level {
  if (value === null) return "ok";
  if (value >= critical) return "critical";
  if (value >= warning) return "warning";
  return "ok";
}

export const LEVEL_LABEL: Record<Level, string> = { ok: "OK", warning: "Warning", critical: "Critical" };

export interface Reading {
  value: number | null;
  source: MetricSource | null;
}

/** CPU busy share of the machine's own CPUs: the guest's view, else the VM process on the host. */
export function rowCpu(row: DashboardRow): Reading {
  if (row.guest?.cpuPct != null) return { value: row.guest.cpuPct, source: "guest" };
  if (row.host?.cpuPct != null) return { value: row.host.cpuPct, source: "host" };
  return { value: null, source: null };
}

export interface MemoryReading {
  used: number | null;
  total: number | null;
  pct: number | null;
  source: MetricSource | null;
}

/** Memory in use (guest), else the VM process's working set against its assigned RAM (host). */
export function rowMemory(row: DashboardRow): MemoryReading {
  for (const sample of [row.guest, row.host]) {
    if (sample?.memBytes != null) {
      const total = sample.memTotalBytes;
      return {
        used: sample.memBytes,
        total,
        pct: total ? Math.min(100, (sample.memBytes * 100) / total) : null,
        source: sample.source,
      };
    }
  }
  return { used: null, total: null, pct: null, source: null };
}

export interface RatePair {
  a: number | null;
  b: number | null;
  source: MetricSource | null;
}

/** Disk read and write per second: the VM process on the host, else the guest's disks. */
export function rowDiskIo(row: DashboardRow): RatePair {
  for (const sample of [row.host, row.guest]) {
    if (sample && (sample.diskReadBps != null || sample.diskWriteBps != null)) {
      return { a: sample.diskReadBps, b: sample.diskWriteBps, source: sample.source };
    }
  }
  return { a: null, b: null, source: null };
}

/** Network received and sent per second (guest only: the host side can't tell VMs apart). */
export function rowNetwork(row: DashboardRow): RatePair {
  const g = row.guest;
  return g ? { a: g.netRxBps, b: g.netTxBps, source: "guest" } : { a: null, b: null, source: null };
}

/** The fullest mounted disk, in percent used (guest only). */
export function rowDiskUsed(row: DashboardRow): { pct: number | null; mount: string | null } {
  let best: { pct: number | null; mount: string | null } = { pct: null, mount: null };
  for (const m of row.guest?.mounts ?? []) {
    if (best.pct === null || m.usedPct > best.pct) best = { pct: m.usedPct, mount: m.mount };
  }
  return best;
}

/** The worst level a row reaches on any threshold. */
export function rowLevel(row: DashboardRow, t: Thresholds): Level {
  const levels = [
    level(rowCpu(row).value, t.cpu),
    level(rowMemory(row).pct, t.memory),
    level(rowDiskUsed(row).pct, t.disk),
  ];
  if (levels.includes("critical")) return "critical";
  if (levels.includes("warning")) return "warning";
  return "ok";
}

export const SOURCE_LABEL: Record<MetricSource, string> = {
  host: "Host side (the VM's process; no login)",
  guest: "Guest (read over SSH)",
};

const UNITS = ["B", "KB", "MB", "GB", "TB"];

/** Binary units, like Windows shows them: 1.5 GB. */
export function formatBytes(bytes: number | null) {
  if (bytes === null) return "—";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${UNITS[unit]}`;
}

export function formatRate(bps: number | null) {
  return bps === null ? "—" : `${formatBytes(bps)}/s`;
}

export function formatPct(pct: number | null) {
  if (pct === null) return "—";
  if (pct > 0 && pct < 0.1) return "<0.1%";
  return `${pct >= 10 || pct === 0 ? Math.round(pct) : pct.toFixed(1)}%`;
}
