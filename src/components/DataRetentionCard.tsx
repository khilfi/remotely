// BX-02 job outputs and command text: how long the job journal keeps them (30 days, 90 days by default, 1 year or
// forever), the last purge, and "Purge now". A purge runs at start and daily: older jobs lose their hosts' outputs and
// their script or MultiExec line, and keep their rows, results and audit entries. Saved in the core and audited;
// presentation mode's read-only lock refuses changing it and Purge now (the daily purge still runs).

import { useEffect, useState } from "react";
import { EraserIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type PurgeReport, type Retention, type RetentionInfo } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { purgeSummary, RETENTION_CHOICES } from "@/lib/retention";

type Message = { ok: boolean; text: string } | null;

export function DataRetentionCard() {
  const [info, setInfo] = useState<RetentionInfo | null>(null);
  const [message, setMessage] = useState<Message>(null);
  const [purging, setPurging] = useState(false);
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    api.retention().then(setInfo, (err) => setMessage({ ok: false, text: errorMessage(err) }));
  }, []);

  async function save(retention: Retention) {
    try {
      setInfo(await api.setRetention(retention));
      setMessage({ ok: true, text: "Saved. Applies at the next purge: today's, or Purge now." });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function purgeNow() {
    setPurging(true);
    try {
      const report: PurgeReport = await api.purgeNow();
      setInfo((old) => (old ? { ...old, lastPurge: report } : old));
      setMessage({ ok: true, text: purgeSummary(report) });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    } finally {
      setPurging(false);
    }
  }

  const last = info?.lastPurge ?? null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Job outputs</CardTitle>
        <CardDescription>
          Every job keeps what its hosts printed and the script or line it ran, so Activity and Compare hosts can show
          them. That is your customers&apos; data, on this PC. After the time below, Remotely removes them; the jobs,
          their results and the audit log stay. Passwords and tokens typed into a command are never kept.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2">
          <Label htmlFor="retention">Keep job outputs and command text for</Label>
          <WhyDisabled reason={readOnly} className="w-48">
            <Select
              value={info?.retention}
              disabled={!info || readOnly !== null}
              onValueChange={(value) => void save(value as Retention)}
            >
              <SelectTrigger id="retention" className="w-48">
                <SelectValue placeholder="…" />
              </SelectTrigger>
              <SelectContent>
                {RETENTION_CHOICES.map((choice) => (
                  <SelectItem key={choice.value} value={choice.value}>
                    {choice.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </WhyDisabled>
        </div>
        <p className="text-sm text-muted-foreground">
          {last
            ? `Last purge ${formatWhen(last.at)}: ${purgeSummary(last)}`
            : "Remotely purges at start and once a day."}
        </p>
        {message && (
          <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
            {message.text}
          </p>
        )}
      </CardContent>
      <CardFooter>
        <WhyDisabled reason={readOnly}>
          <Button variant="outline" onClick={() => void purgeNow()} disabled={!info || purging || readOnly !== null}>
            <EraserIcon data-icon="inline-start" />
            {purging ? "Purging…" : "Purge now"}
          </Button>
        </WhyDisabled>
      </CardFooter>
    </Card>
  );
}
