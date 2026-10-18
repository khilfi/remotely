// MO-03, MO-04: a meter whose fill carries the threshold level, and the icon that goes with a level so
// colour never carries it alone. shadcn's Progress has one fixed colour, hence this small component.

import { OctagonAlertIcon, TriangleAlertIcon } from "lucide-react";
import type { Level } from "@/lib/metrics";
import { LEVEL_LABEL } from "@/lib/metrics";
import { cn } from "@/lib/utils";

const FILL: Record<Level, string> = {
  ok: "bg-series-1",
  warning: "bg-status-warning",
  critical: "bg-status-critical",
};

export function Meter({
  pct,
  level,
  label,
  className,
}: {
  /** 0 to 100; more is drawn full. */
  pct: number | null;
  level: Level;
  /** What the meter measures, for screen readers. */
  label: string;
  className?: string;
}) {
  const shown = pct === null ? 0 : Math.max(0, Math.min(100, pct));
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct === null ? undefined : Math.round(pct)}
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-muted", className)}
    >
      <div className={cn("h-full rounded-full transition-[width]", FILL[level])} style={{ width: `${shown}%` }} />
    </div>
  );
}

/** Nothing for OK; an icon with its level named for screen readers otherwise. */
export function LevelIcon({ level, className }: { level: Level; className?: string }) {
  if (level === "ok") return null;
  const Icon = level === "critical" ? OctagonAlertIcon : TriangleAlertIcon;
  return (
    <Icon
      role="img"
      aria-label={LEVEL_LABEL[level]}
      className={cn("size-3.5 shrink-0", level === "critical" ? "text-tier-critical" : "text-tier-medium", className)}
    />
  );
}
