// MO-08: small pieces the Checks tab, the widget and the history sheet share: a check's status badge and a sparkline
// of the time its runs took.

import { Badge } from "@/components/ui/badge";
import type { CheckStatus, SparkPoint } from "@/lib/checks-api";
import { sparkPath, STATUS_LABEL, statusTone } from "@/lib/checks";
import { cn } from "@/lib/utils";

const TONE_CLASS = {
  ok: "border-success/40 text-success",
  warn: "border-status-warning/40 text-status-warning",
  bad: "border-status-critical/40 bg-status-critical/5 text-status-critical",
  muted: "text-muted-foreground",
} as const;

export function CheckStatusBadge({ status, className }: { status: CheckStatus; className?: string }) {
  return (
    <Badge variant="outline" className={cn("shrink-0", TONE_CLASS[statusTone(status)], className)}>
      {STATUS_LABEL[status]}
    </Badge>
  );
}

/**
 * The time each bucket's runs took, slowest at the top; a bucket with a failed run gets a red tick along the bottom.
 * Decorative: the numbers are beside it.
 */
export function Sparkline({
  points,
  width = 120,
  height = 24,
  className,
}: {
  points: SparkPoint[];
  width?: number;
  height?: number;
  className?: string;
}) {
  const path = sparkPath(points, width, height);
  const first = points[0]?.at ?? 0;
  const span = Math.max(1, (points[points.length - 1]?.at ?? 0) - first);
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      className={cn("shrink-0 overflow-visible", className)}
      aria-hidden="true"
      preserveAspectRatio="none"
    >
      {path && (
        <path
          d={path}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
          className="text-primary"
        />
      )}
      {points
        .filter((p) => p.down > 0)
        .map((p) => {
          const x = points.length < 2 ? width / 2 : ((p.at - first) / span) * width;
          return (
            <line
              key={p.at}
              x1={x}
              x2={x}
              y1={height - 4}
              y2={height}
              stroke="currentColor"
              strokeWidth={2}
              className="text-status-critical"
            />
          );
        })}
    </svg>
  );
}
