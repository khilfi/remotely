// MO-06: a chart's range: live (the last 30 minutes, every round) or 1 hour to 7 days from the history on disk. MO-08's
// checks have no live view, so they pick from the history only (`live` off).

import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import type { ChartRange } from "@/lib/dashboard-api";
import { CHART_RANGES, isChartRange } from "@/lib/history";

export function RangePicker({
  value,
  onChange,
  label = "Range",
  live = true,
}: {
  value: ChartRange;
  onChange: (range: ChartRange) => void;
  label?: string;
  /** Offer the live view (charts); health checks have only the history. */
  live?: boolean;
}) {
  return (
    <ToggleGroup
      type="single"
      variant="outline"
      size="sm"
      value={value}
      onValueChange={(v) => isChartRange(v) && onChange(v)}
      aria-label={label}
    >
      {CHART_RANGES.filter((r) => live || r.value !== "live").map((r) => (
        <ToggleGroupItem key={r.value} value={r.value} title={r.hint} className="px-2 text-xs">
          {r.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}
