// MO-06 dashboard history: how long the 1-minute averages of the VMs, watched hosts and this PC are kept (1 to 30 days,
// 7 by default), what they take, and the last prune. Pruned at start and daily, with the resolved alerts; a shorter time
// prunes at once. Kept on this PC only: no export carries it. Saved in the core and audited; presentation mode's
// read-only lock refuses changing it (the daily prune still runs). UX-10: the choice saves at once; a longer time has
// Undo, a shorter one doesn't, since the core prunes the older minutes at once and Undo couldn't bring them back.

import { useEffect, useState } from "react";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage } from "@/lib/api";
import { dashboardApi, type HistoryInfo, type HistoryRetention } from "@/lib/dashboard-api";
import { formatWhen } from "@/lib/format";
import { HISTORY_RETENTION_CHOICES, historySizeText, pruneSummary, retentionDays } from "@/lib/history";

export function DashboardHistoryCard() {
  const [info, setInfo] = useState<HistoryInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const status = useSaveStatus();
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    dashboardApi.historyInfo().then(setInfo, (err) => setError(errorMessage(err)));
  }, []);

  function save(retention: HistoryRetention) {
    const before = info?.retention;
    const shorter = before !== undefined && retentionDays(retention) < retentionDays(before);
    void status.run(
      async () => setInfo(await dashboardApi.setHistoryRetention(retention)),
      before && !shorter ? async () => setInfo(await dashboardApi.setHistoryRetention(before)) : undefined,
      shorter ? "Saved: older history was removed" : undefined,
    );
  }

  const last = info?.lastPrune ?? null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Dashboard history
          <HelpTip topic="dashboardHistory" />
        </CardTitle>
        <CardDescription>For the charts&apos; longer ranges and the alert list. It stays on this PC.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2">
          <Label htmlFor="history-retention">Keep the history and resolved alerts for</Label>
          <WhyDisabled reason={readOnly} className="w-48">
            <Select
              // Controlled from the start: "" shows the placeholder until the setting is read.
              value={info?.retention ?? ""}
              disabled={!info || readOnly !== null}
              onValueChange={(value) => value && save(value as HistoryRetention)}
            >
              <SelectTrigger id="history-retention" className="w-48">
                <SelectValue placeholder="…" />
              </SelectTrigger>
              <SelectContent>
                {HISTORY_RETENTION_CHOICES.map((choice) => (
                  <SelectItem key={choice.value} value={choice.value}>
                    {choice.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </WhyDisabled>
        </div>
        {/* One line; the last prune is in its tooltip. */}
        <p
          className={error ? "text-sm text-destructive" : "text-sm text-muted-foreground"}
          title={last ? `Last pruned ${formatWhen(last.at)}: ${pruneSummary(last)}` : undefined}
        >
          {error ?? (info ? historySizeText(info.size) : "")}
        </p>
      </CardContent>
    </Card>
  );
}
