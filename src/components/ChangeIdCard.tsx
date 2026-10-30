// AP-08: Settings › Approvals: whether this workspace needs a change ID (a ticket or change number) for High and
// Critical actions on Prod targets. A setting of the workspace (FD-02), so each engagement decides; the change is
// audited in it and refused by the read-only lock. UX-10: a row of the approval rules' card, saved at once.

import { useEffect, useState } from "react";
import { useReadOnlyReason } from "@/components/Presentation";
import { HelpTip } from "@/components/HelpTip";
import { SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { Term } from "@/components/Term";
import { WhyDisabled } from "@/components/WhyDisabled";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { errorMessage } from "@/lib/api";
import { workspacesApi, type ChangeIdRules } from "@/lib/workspaces-api";

export function ChangeIdSetting() {
  const [rules, setRules] = useState<ChangeIdRules | null>(null);
  const [error, setError] = useState<string | null>(null);
  const status = useSaveStatus();
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    workspacesApi
      .changeIdRules()
      .then(setRules)
      .catch((err) => setError(`Could not read the change ID rule: ${errorMessage(err)}`));
  }, []);

  function set(requiredForProd: boolean) {
    void status.run(async () => setRules(await workspacesApi.setChangeIdRules({ requiredForProd })));
  }

  return (
    <div className="grid gap-1">
      <div className="flex items-center gap-3">
        <WhyDisabled reason={readOnly}>
          <Switch
            id="change-id-required"
            checked={rules?.requiredForProd ?? false}
            disabled={!rules || status.state.kind === "saving" || !!readOnly}
            onCheckedChange={set}
          />
        </WhyDisabled>
        <Label htmlFor="change-id-required">
          <span>
            Require a <Term id="changeId">change ID</Term> for Prod targets
          </span>
        </Label>
        <HelpTip topic="reasonOrChangeId" />
        <SaveStatus status={status} className="ml-auto" />
      </div>
      <p className="pl-12 text-sm text-muted-foreground">
        {error ?? "A setting of this workspace, for High and Critical actions."}
      </p>
    </div>
  );
}
