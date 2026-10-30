// UX-10 (AP-01, AP-08): Settings › Approvals. It opens on a summary: whether the rules are the defaults ("Default rules
// · 0 changed"), what each tier asks in plain words, the Prod rule and the safety snapshot default, and this
// workspace's change ID rule (saved at once). The tier table, the bulk thresholds, the countdown and the
// dangerous-command and read-only patterns are under Advanced (PolicyRulesEditor), which keeps an explicit Save.

import { useEffect, useState } from "react";
import { ChevronDownIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Separator } from "@/components/ui/separator";
import { TierBadge } from "@/components/Badges";
import { ChangeIdSetting } from "@/components/ChangeIdCard";
import { HelpTip } from "@/components/HelpTip";
import { PolicyRulesEditor } from "@/components/PolicyRulesEditor";
import { SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { Term } from "@/components/Term";
import { api, errorMessage, type PolicyCatalog, type PolicyRules } from "@/lib/api";
import { settingsCardId } from "@/lib/settings-index";
import { rulesChanged, rulesLine, tierSteps } from "@/lib/settings-summary";
import { cn } from "@/lib/utils";

interface Props {
  /** Open Advanced (a search that matched the rules themselves). */
  openAdvanced?: boolean;
  /** The row a link lights. */
  lit: string | null;
}

export function ApprovalRulesCard({ openAdvanced = false, lit }: Props) {
  const [catalog, setCatalog] = useState<PolicyCatalog | null>(null);
  const [rules, setRules] = useState<PolicyRules | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(openAdvanced);
  const status = useSaveStatus();
  const [asked, setAsked] = useState(openAdvanced);
  if (openAdvanced !== asked) {
    setAsked(openAdvanced);
    if (openAdvanced) setAdvanced(true);
  }

  useEffect(() => {
    Promise.all([api.policyCatalog(), api.policyRules()]).then(
      ([c, r]) => {
        setCatalog(c);
        setRules(r);
      },
      (err) => setError(errorMessage(err)),
    );
  }, []);

  const changed = catalog && rules ? rulesChanged(rules, catalog.defaults) : null;

  return (
    // Not clipped, so Advanced's Save bar can stick to the bottom of the page while it scrolls.
    <Card className="overflow-visible">
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Approval rules
          <HelpTip topic="approvalTiers" />
        </CardTitle>
        <CardDescription>The steps before an action runs depend on its tier.</CardDescription>
        <CardAction className="flex items-center gap-2">
          <SaveStatus status={status} />
          {changed !== null && (
            <Badge variant={changed === 0 ? "secondary" : "outline"} className="font-normal">
              {rulesLine(changed)}
            </Badge>
          )}
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-4">
        {error && <p className="text-sm text-destructive">{error}</p>}
        {rules && (
          <>
            <dl className="grid grid-cols-[6rem_1fr] items-center gap-x-4 gap-y-2 text-sm">
              {tierSteps(rules).map(({ tier, steps }) => (
                <div key={tier} className="contents">
                  <dt>
                    <TierBadge tier={tier} />
                  </dt>
                  <dd className="text-muted-foreground">{steps}</dd>
                </div>
              ))}
            </dl>
            <p className="text-sm text-muted-foreground">
              A <Term id="prod" /> target {rules.prodBump ? "raises the tier by one" : "doesn't raise the tier"}; the
              safety snapshot is {rules.safetySnapshotDefault ? "on" : "off"} by default.
            </p>
          </>
        )}
        <Separator />
        <div
          id={settingsCardId("change-ids")}
          className={cn("scroll-mt-4 rounded-md", lit === "change-ids" && "ring-2 ring-ring ring-offset-4")}
        >
          <ChangeIdSetting />
        </div>
        <Separator />
        <Collapsible open={advanced} onOpenChange={setAdvanced}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" size="sm" className="-ml-2" aria-expanded={advanced}>
              <ChevronDownIcon className={cn("transition-transform", !advanced && "-rotate-90")} aria-hidden />
              Advanced: every action&apos;s tier, the patterns and the countdown
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="pt-4">
            {catalog && rules && (
              <PolicyRulesEditor
                catalog={catalog}
                saved={rules}
                onSaved={(result) => {
                  setRules(result.rules);
                  // Already saved by the editor: the card only says so.
                  void status.run(() => Promise.resolve());
                }}
              />
            )}
          </CollapsibleContent>
        </Collapsible>
      </CardContent>
    </Card>
  );
}
