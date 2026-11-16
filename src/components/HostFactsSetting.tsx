// MO-13: Settings › Dashboard: whether this workspace reads its hosts' OS and hardware in the background, when a
// terminal connects and from the dashboard (at most once a day), or only when asked (Refresh, the inventory). A
// setting of the workspace (FD-02), so a customer whose SOC alerts on routine reads can have them off; the change is
// audited and refused by the read-only lock. A row of the dashboard polling card, saved at once.

import { useEffect, useState } from "react";
import { useReadOnlyReason } from "@/components/Presentation";
import { SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { WhyDisabled } from "@/components/WhyDisabled";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api, errorMessage } from "@/lib/api";

export function HostFactsSetting() {
  const [on, setOn] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const status = useSaveStatus();
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    api
      .hostBackgroundReads()
      .then(setOn)
      .catch((err) => setError(`Could not read this setting: ${errorMessage(err)}`));
  }, []);

  function set(next: boolean) {
    void status.run(async () => setOn(await api.setHostBackgroundReads(next)));
  }

  return (
    <div className="grid gap-1">
      <div className="flex items-center gap-3">
        <WhyDisabled reason={readOnly}>
          <Switch
            id="host-background-reads"
            checked={on ?? true}
            disabled={on === null || status.state.kind === "saving" || !!readOnly}
            onCheckedChange={set}
          />
        </WhyDisabled>
        <Label htmlFor="host-background-reads">Read host details in the background</Label>
        <SaveStatus status={status} className="ml-auto" />
      </div>
      <p className="pl-12 text-sm text-muted-foreground">
        {error ??
          "OS and hardware, at most once a day when a terminal connects or the dashboard watches a host. Off: only when you press Refresh. A setting of this workspace."}
      </p>
    </div>
  );
}
