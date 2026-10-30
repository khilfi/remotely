// MO-07: the alert list on the dashboard: firing alerts first (critical on top), with acknowledge, and the history of
// resolved ones on request; the rules open beside it. Read when the dashboard shows and again as alerts fire, resolve
// or are acknowledged (alerts://event), never while it is hidden. Acknowledging is audited and refused while presenting
// with the read-only lock.

import { useCallback, useEffect, useRef, useState } from "react";
import { BellRingIcon, CheckCheckIcon, CheckIcon, HistoryIcon, ListChecksIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Toggle } from "@/components/ui/toggle";
import { AlertRulesSheet } from "@/components/AlertRulesSheet";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage } from "@/lib/api";
import { RESOLUTION_LABEL, sortAlerts, unacknowledged } from "@/lib/alerts";
import { dashboardApi, type Alert, type AlertList, type AlertTarget } from "@/lib/dashboard-api";
import { cn } from "@/lib/utils";

function time(ts: string) {
  const at = new Date(ts);
  const today = new Date().toDateString() === at.toDateString();
  return today
    ? at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : at.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function AlertRow({
  alert,
  readOnly,
  onAcknowledge,
  onOpen,
}: {
  alert: Alert;
  readOnly: string | null;
  onAcknowledge: (id: string) => void;
  onOpen?: (target: AlertTarget) => void;
}) {
  const open = !alert.resolvedAt;
  const critical = alert.severity === "critical";
  return (
    <li
      className={cn(
        "flex items-start gap-2 rounded-md px-2 py-1.5 text-sm",
        open && !alert.acknowledgedAt && (critical ? "bg-status-critical/5" : "bg-status-warning/5"),
        !open && "text-muted-foreground",
      )}
    >
      <TriangleAlertIcon
        className={cn(
          "mt-0.5 size-4 shrink-0",
          !open ? "text-muted-foreground" : critical ? "text-status-critical" : "text-status-warning",
        )}
        aria-label={critical ? "Critical" : "Warning"}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2">
          {onOpen && alert.target.kind !== "thisPc" ? (
            <button
              type="button"
              className="truncate font-medium underline-offset-2 hover:underline"
              onClick={() => onOpen(alert.target)}
            >
              {alert.target.name}
            </button>
          ) : (
            <span className="truncate font-medium">{alert.target.name}</span>
          )}
          <span className="text-xs text-muted-foreground tabular-nums">{time(alert.firedAt)}</span>
        </div>
        <div className="break-words">{alert.message}</div>
        <div className="text-xs text-muted-foreground">
          {alert.ruleName}
          {alert.resolvedAt && (
            <>
              {" "}
              · {alert.resolution ? RESOLUTION_LABEL[alert.resolution] : "Resolved"} at {time(alert.resolvedAt)}
              {alert.peak !== null &&
                alert.value !== null &&
                alert.peak > alert.value &&
                ` · worst ${Math.round(alert.peak)}%`}
            </>
          )}
          {alert.acknowledgedAt && ` · acknowledged ${time(alert.acknowledgedAt)}`}
        </div>
      </div>
      {open && !alert.acknowledgedAt && (
        <WhyDisabled reason={readOnly}>
          <Button
            size="icon-sm"
            variant="ghost"
            disabled={readOnly !== null}
            aria-label={`Acknowledge the alert on ${alert.target.name}`}
            title="Acknowledge: seen, and stays listed until it resolves"
            onClick={() => onAcknowledge(alert.id)}
          >
            <CheckIcon />
          </Button>
        </WhyDisabled>
      )}
    </li>
  );
}

export function AlertsWidget({
  live,
  onOpenTarget,
}: {
  /** The dashboard shows and the window is visible. */
  live: boolean;
  /** Opens the drill-down of an alert's VM or host. */
  onOpenTarget?: (target: AlertTarget) => void;
}) {
  const [list, setList] = useState<AlertList | null>(null);
  const [history, setHistory] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const readOnly = useReadOnlyReason();
  const liveRef = useRef(live);
  useEffect(() => {
    liveRef.current = live;
  }, [live]);

  const load = useCallback(() => {
    dashboardApi.alerts(!history, 200).then(setList, (err) => toast.error(errorMessage(err), { id: "alerts-load" }));
  }, [history]);

  useEffect(() => {
    if (live) load();
  }, [live, load]);

  // Alerts fire and resolve as rounds come: read again then (a burst of events is one read).
  useEffect(() => {
    let timer: number | undefined;
    const unlisten = dashboardApi.onAlertEvent(() => {
      if (!liveRef.current || timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        load();
      }, 300);
    });
    return () => {
      window.clearTimeout(timer);
      void unlisten.then((stop) => stop());
    };
  }, [load]);

  async function acknowledge(ids: string[]) {
    try {
      const done = await dashboardApi.acknowledge(ids);
      if (ids.length === 0)
        toast.success(done.length === 1 ? "Acknowledged 1 alert" : `Acknowledged ${done.length} alerts`);
      load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const alerts = sortAlerts(list?.alerts ?? []);
  const fresh = unacknowledged(alerts);
  return (
    <section aria-label="Alerts" className="flex h-full min-h-0 flex-col rounded-lg border bg-card p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <BellRingIcon className="size-4 text-muted-foreground" />
        <span className="text-sm font-medium">Alerts</span>
        {list && list.open > 0 && (
          <Badge variant="outline" className="tabular-nums">
            {list.open} open
            {list.unacknowledged > 0 && list.unacknowledged < list.open && `, ${list.unacknowledged} new`}
          </Badge>
        )}
        <div className="ml-auto flex items-center gap-1">
          <Toggle
            size="sm"
            pressed={history}
            onPressedChange={setHistory}
            aria-label="Show resolved alerts too"
            title="Show resolved alerts too"
          >
            <HistoryIcon />
          </Toggle>
          <WhyDisabled reason={fresh.length === 0 ? null : readOnly}>
            <Button
              size="sm"
              variant="ghost"
              disabled={fresh.length === 0 || readOnly !== null}
              onClick={() => void acknowledge([])}
              title="Acknowledge every open alert"
            >
              <CheckCheckIcon /> All
            </Button>
          </WhyDisabled>
          <Button size="sm" variant="ghost" onClick={() => setRulesOpen(true)}>
            <ListChecksIcon /> Rules
          </Button>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {list === null ? (
          <p className="px-2 text-xs text-muted-foreground">Reading the alerts…</p>
        ) : alerts.length === 0 ? (
          <p className="px-2 py-3 text-center text-xs text-muted-foreground">
            {history ? "No alerts yet." : "Nothing is firing."}
          </p>
        ) : (
          <ul className="flex flex-col gap-1">
            {alerts.map((a) => (
              <AlertRow
                key={a.id}
                alert={a}
                readOnly={readOnly}
                onAcknowledge={(id) => void acknowledge([id])}
                onOpen={onOpenTarget}
              />
            ))}
          </ul>
        )}
      </div>
      <AlertRulesSheet open={rulesOpen} onClose={() => setRulesOpen(false)} />
    </section>
  );
}
