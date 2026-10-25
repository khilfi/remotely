// MO-16: a widget's settings while customizing: a chart's VM, watched host or this PC, its metric and the range it
// opens with; a services widget's host. The choices come from the dashboard's rows (read once when the settings open)
// and the saved sessions. Saved with the layout.

import { useEffect, useMemo, useState } from "react";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, type DashboardRow, type SessionRecord } from "@/lib/api";
import type { ChartMetric, ChartRange, HistorySource, Widget } from "@/lib/dashboard-api";
import { CHART_METRIC_LABEL, CHART_METRICS, metricFor } from "@/lib/dashboard-layout";
import { CHART_RANGES } from "@/lib/history";

interface TargetChoice {
  value: string;
  source: HistorySource;
  key: string;
  name: string;
  label: string;
}

const THIS_PC: TargetChoice = {
  value: "thisPc|this-pc",
  source: "thisPc",
  key: "this-pc",
  name: "This PC",
  label: "This PC",
};

/** What a chart can draw now: each running VM's host side, each watched guest, and this PC. */
function targetChoices(rows: DashboardRow[]): TargetChoice[] {
  const out: TargetChoice[] = [THIS_PC];
  for (const row of rows) {
    if (row.kind === "vm") {
      out.push({
        value: `host|${row.key}`,
        source: "host",
        key: row.key,
        name: row.name,
        label: `${row.name} (VM, host side)`,
      });
      if (row.watchedSession) {
        out.push({
          value: `guest|${row.watchedSession}`,
          source: "guest",
          key: row.watchedSession,
          name: row.name,
          label: `${row.name} (guest)`,
        });
      }
    } else {
      out.push({
        value: `guest|${row.key}`,
        source: "guest",
        key: row.key,
        name: row.name,
        label: `${row.name} (host)`,
      });
    }
  }
  return out;
}

export function WidgetSettings({ widget, onChange }: { widget: Widget; onChange: (change: Partial<Widget>) => void }) {
  const [rows, setRows] = useState<DashboardRow[]>([]);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);

  useEffect(() => {
    if (widget.kind === "chart") {
      api.metricsOverview().then(
        (o) => setRows(o.rows),
        () => undefined,
      );
    } else if (widget.kind === "services") {
      api.sessions().then(setSessions, () => undefined);
      api.metricsOverview().then(
        (o) => setRows(o.rows),
        () => undefined,
      );
    }
  }, [widget.kind]);

  const watched = useMemo(() => new Set(rows.flatMap((r) => (r.watchedSession ? [r.watchedSession] : []))), [rows]);

  if (widget.kind === "services") {
    return (
      <div className="grid gap-1.5">
        <Label htmlFor={`${widget.id}-host`}>Host</Label>
        <Select value={widget.sessionId ?? undefined} onValueChange={(sessionId) => onChange({ sessionId })}>
          <SelectTrigger id={`${widget.id}-host`} className="w-full">
            <SelectValue placeholder="Choose a session" />
          </SelectTrigger>
          <SelectContent>
            {sessions.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.name}
                {watched.has(s.id) ? "" : " (not watched)"}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          Read every minute on the dashboard&apos;s connection to the host, so only a watched host shows its services.
        </p>
      </div>
    );
  }
  if (widget.kind !== "chart") return null;

  const choices = targetChoices(rows);
  const current = widget.source && widget.key ? `${widget.source}|${widget.key}` : undefined;
  if (current && !choices.some((c) => c.value === current) && widget.source && widget.key) {
    choices.push({
      value: current,
      source: widget.source,
      key: widget.key,
      name: widget.name ?? widget.key,
      label: `${widget.name ?? "Chosen before"} (not on the dashboard now)`,
    });
  }
  const source = widget.source ?? "thisPc";
  return (
    <div className="grid gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor={`${widget.id}-target`}>VM or host</Label>
        <Select
          value={current}
          onValueChange={(value) => {
            const choice = choices.find((c) => c.value === value);
            if (!choice) return;
            onChange({
              source: choice.source,
              key: choice.key,
              name: choice.name,
              metric: metricFor(choice.source, widget.metric),
            });
          }}
        >
          <SelectTrigger id={`${widget.id}-target`} className="w-full">
            <SelectValue placeholder="Choose what to chart" />
          </SelectTrigger>
          <SelectContent>
            {choices.map((c) => (
              <SelectItem key={c.value} value={c.value}>
                {c.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor={`${widget.id}-metric`}>Metric</Label>
          <Select value={widget.metric} onValueChange={(v) => onChange({ metric: v as ChartMetric })}>
            <SelectTrigger id={`${widget.id}-metric`} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CHART_METRICS[source].map((m) => (
                <SelectItem key={m} value={m}>
                  {CHART_METRIC_LABEL[m]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor={`${widget.id}-range`}>Opens with</Label>
          <Select value={widget.range} onValueChange={(v) => onChange({ range: v as ChartRange })}>
            <SelectTrigger id={`${widget.id}-range`} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CHART_RANGES.map((r) => (
                <SelectItem key={r.value} value={r.value}>
                  {r.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
}
