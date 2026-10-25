// VM-08, AP-02: a stack command as the approval dialog (and the stack deploy dialog before it) shows it: the
// instance, its steps in the order they run with each step's VMs, what the next step waits for, each step's deploy
// preview (R2) when it deploys, and the VMs a teardown keeps.

import { BanIcon, ChevronRightIcon, LayersIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { DeployPreviewView } from "@/components/DeployPreviewView";
import { bytesText } from "@/lib/deploy";
import { betweenText } from "@/lib/stacks";
import type { StackDetails } from "@/lib/stacks-api";

const ACTION_TEXT: Record<StackDetails["action"], string> = {
  deploy: "Deploys",
  start: "Starts, in boot order,",
  shutDown: "Shuts down, the last step first,",
  suspend: "Suspends, the last step first,",
  teardown: "Deletes, with their files,",
};

interface Props {
  details: StackDetails;
  /** The approval dialog lists the warnings itself. */
  showWarnings?: boolean;
}

export function StackDetailsView({ details, showWarnings = true }: Props) {
  const last = details.steps.length - 1;
  const deploy = details.action === "deploy";
  return (
    <section aria-label="Stack" className="grid gap-3 text-sm">
      <p className="flex items-center gap-1.5">
        <LayersIcon className="size-4 text-muted-foreground" aria-hidden />
        <span>
          {ACTION_TEXT[details.action]} the VMs of stack instance{" "}
          <span className="font-medium">{details.instanceName}</span>
          {details.stackName && <> (stack {details.stackName})</>}
          {deploy && details.diskBytes > 0 && (
            <span className="text-muted-foreground">
              {" "}
              · disks up to {bytesText(details.diskBytes)}
              {details.thickBytes > 0 && `, ${bytesText(details.thickBytes)} thick`}
            </span>
          )}
        </span>
      </p>
      <ol className="grid gap-2">
        {details.steps.map((step, i) => {
          const between = deploy || details.action === "start" ? betweenText(step) : "";
          return (
            <li key={`${i}-${step.label}`} className="rounded-md border p-2">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                <span className="font-medium">
                  {details.action === "teardown" ? step.label : `${i + 1}. ${step.label}`}
                </span>
                <span className="text-xs break-all text-muted-foreground">
                  {step.vms.length ? step.vms.join(", ") : "no VM to act on"}
                </span>
              </div>
              {i < last && between && <p className="mt-1 text-xs text-muted-foreground">Then {between}.</p>}
              {step.deploy && (
                <Collapsible className="mt-1">
                  <CollapsibleTrigger className="group flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
                    <ChevronRightIcon className="size-3.5 transition-transform group-data-[state=open]:rotate-90" />
                    What it makes
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <DeployPreviewView preview={step.deploy} showWarnings={false} />
                  </CollapsibleContent>
                </Collapsible>
              )}
            </li>
          );
        })}
      </ol>
      {details.kept.length > 0 && (
        <div className="rounded-md bg-muted/50 p-2">
          <p className="font-medium">Kept</p>
          <ul className="grid gap-0.5 text-xs text-muted-foreground">
            {details.kept.map((k) => (
              <li key={k.key}>
                {k.name}: {k.why}
              </li>
            ))}
          </ul>
        </div>
      )}
      {details.refusals.length > 0 && (
        <Alert variant="destructive">
          <BanIcon />
          <AlertTitle>It can't run as it is</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-5">
              {details.refusals.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {showWarnings && details.warnings.length > 0 && (
        <ul className="grid gap-1 text-xs text-tier-medium">
          {details.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
    </section>
  );
}
