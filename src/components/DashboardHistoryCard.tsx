// MO-06 dashboard history: how long the 1-minute averages of the VMs, watched hosts and this PC are kept (1 to 30 days,
// 7 by default), what they take, and the last prune. Pruned at start and daily, with the resolved alerts; a shorter time
// prunes at once. Kept on this PC only: no export carries it. Saved in the core and audited; presentation mode's
// read-only lock refuses changing it (the daily prune still runs).

import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage } from "@/lib/api";
import { dashboardApi, type HistoryInfo, type HistoryRetention } from "@/lib/dashboard-api";
import { formatWhen } from "@/lib/format";
import { HISTORY_RETENTION_CHOICES, historySizeText, pruneSummary } from "@/lib/history";

type Message = { ok: boolean; text: string } | null;

export function DashboardHistoryCard() {
  const [info, setInfo] = useState<HistoryInfo | null>(null);
  const [message, setMessage] = useState<Message>(null);
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    dashboardApi.historyInfo().then(setInfo, (err) => setMessage({ ok: false, text: errorMessage(err) }));
  }, []);

  async function save(retention: HistoryRetention) {
    try {
      const next = await dashboardApi.setHistoryRetention(retention);
      setInfo(next);
      setMessage({ ok: true, text: "Saved. Older history and resolved alerts are removed now and daily." });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  const last = info?.lastPrune ?? null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Dashboard history</CardTitle>
        <CardDescription>
          The dashboard keeps a 1-minute average of each running VM, watched host and this PC, for the charts&apos; 1
          hour to 7 day ranges, and the alert list&apos;s history. It stays on this PC: exports never carry it.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2">
          <Label htmlFor="history-retention">Keep the history and resolved alerts for</Label>
          <WhyDisabled reason={readOnly} className="w-48">
            <Select
              // Controlled from the start: "" shows the placeholder until the setting is read.
              value={info?.retention ?? ""}
              disabled={!info || readOnly !== null}
              onValueChange={(value) => value && void save(value as HistoryRetention)}
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
        {info && <p className="text-xs text-muted-foreground">{historySizeText(info.size)}</p>}
        {last && (
          <p className="text-xs text-muted-foreground">
            Last pruned {formatWhen(last.at)}: {pruneSummary(last)}
          </p>
        )}
        {message && (
          <p className={message.ok ? "text-xs text-muted-foreground" : "text-xs text-destructive"} role="status">
            {message.text}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
