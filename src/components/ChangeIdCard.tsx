// AP-08: Settings → Approval rules: whether this workspace needs a change ID (a ticket or change number) for High and
// Critical actions on Prod targets. A setting of the workspace (FD-02), so each engagement decides; the change is
// audited in it and refused by the read-only lock.

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { errorMessage } from "@/lib/api";
import { workspacesApi, type ChangeIdRules } from "@/lib/workspaces-api";

export function ChangeIdCard() {
  const [rules, setRules] = useState<ChangeIdRules | null>(null);
  const [busy, setBusy] = useState(false);
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    workspacesApi
      .changeIdRules()
      .then(setRules)
      .catch((err) => toast.error(`Could not read the change ID rule: ${errorMessage(err)}`));
  }, []);

  async function set(requiredForProd: boolean) {
    setBusy(true);
    try {
      setRules(await workspacesApi.setChangeIdRules({ requiredForProd }));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change IDs</CardTitle>
        <CardDescription>
          High and Critical approvals, a schedule&apos;s too, take a ticket or change number. It is kept in the job, the
          audit log and the exports. This is a setting of this workspace: each engagement has its own.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-start justify-between gap-4">
          <Label htmlFor="change-id-required" className="grid gap-1">
            <span>Require a change ID for Prod targets</span>
            <span className="font-normal text-muted-foreground">
              A High or Critical action on a VM or host labelled Prod can&apos;t be approved without one. A schedule
              approved without one asks again.
            </span>
          </Label>
          <WhyDisabled reason={readOnly}>
            <Switch
              id="change-id-required"
              checked={rules?.requiredForProd ?? false}
              disabled={!rules || busy || !!readOnly}
              onCheckedChange={(on) => void set(on)}
            />
          </WhyDisabled>
        </div>
      </CardContent>
    </Card>
  );
}
