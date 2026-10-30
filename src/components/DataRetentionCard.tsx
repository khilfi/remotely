// BX-02 job outputs and command text: how long the job journal keeps them (30 days, 90 days by default, 1 year or
// forever), the last purge, and "Purge now". A purge runs at start and daily: older jobs lose their hosts' outputs and
// their script or MultiExec line, and keep their rows, results and audit entries. Saved in the core and audited;
// presentation mode's read-only lock refuses changing it and Purge now (the daily purge still runs). UX-10: the choice
// saves at once, with Undo.

import { useEffect, useState } from "react";
import { EraserIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useReadOnlyReason } from "@/components/Presentation";
import { SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { WhyDisabled } from "@/components/WhyDisabled";
import { HelpTip } from "@/components/HelpTip";
import { api, errorMessage, type Retention, type RetentionInfo } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { purgeSummary, RETENTION_CHOICES } from "@/lib/retention";

export function DataRetentionCard() {
  const [info, setInfo] = useState<RetentionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [purging, setPurging] = useState(false);
  const status = useSaveStatus();
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    api.retention().then(setInfo, (err) => setError(errorMessage(err)));
  }, []);

  function save(retention: Retention) {
    const before = info?.retention;
    void status.run(
      async () => setInfo(await api.setRetention(retention)),
      before ? async () => setInfo(await api.setRetention(before)) : undefined,
    );
  }

  async function purgeNow() {
    setPurging(true);
    setError(null);
    try {
      const report = await api.purgeNow();
      setInfo((old) => (old ? { ...old, lastPurge: report } : old));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPurging(false);
    }
  }

  const last = info?.lastPurge ?? null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Job outputs
          <HelpTip topic="retention" />
        </CardTitle>
        <CardDescription>
          What your hosts printed is your customers&apos; data: it is removed after this time.
        </CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2">
          <Label htmlFor="retention">Keep job outputs and command text for</Label>
          <div className="flex flex-wrap items-center gap-2">
            <WhyDisabled reason={readOnly} className="w-48">
              <Select
                value={info?.retention}
                disabled={!info || readOnly !== null}
                onValueChange={(value) => save(value as Retention)}
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
            <WhyDisabled reason={readOnly}>
              <Button variant="ghost" onClick={() => void purgeNow()} disabled={!info || purging || readOnly !== null}>
                <EraserIcon data-icon="inline-start" />
                {purging ? "Purging…" : "Purge now"}
              </Button>
            </WhyDisabled>
          </div>
        </div>
        <p className={error ? "text-sm text-destructive" : "text-sm text-muted-foreground"} role="status">
          {error ?? (last ? `Last purge ${formatWhen(last.at)}: ${purgeSummary(last)}` : "Purged at start and daily.")}
        </p>
      </CardContent>
    </Card>
  );
}
