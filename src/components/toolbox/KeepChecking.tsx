// UX-19 (0.9.0 H4): "Keep checking this…" under a Toolbox result (Ping, Check ports, Certificate, DNS lookup). It opens
// MO-08's check editor on the Dashboard's Checks tab, filled in from what the tool just ran (a `checks` link, as every
// "Add a check" outside that tab does); nothing is saved until the dialog's Add check, which the core audits as
// check_changed. Disabled, with the reason, under the read-only lock (as the Checks tab's own Add a check) and for a
// result the editor and the core wouldn't take as a check (lib/monitor.ts keepCheckingProblem). A secondary button:
// the tool's run stays the tab's one primary.

import { ChevronDownIcon, HeartPulseIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { requestLink, type AppLink } from "@/lib/links";
import { keepCheckingProblem, portCheck } from "@/lib/monitor";
import { portStateText, type ToolTarget } from "@/lib/toolbox";
import type { PortResult } from "@/lib/toolbox-api";

const LABEL = "Keep checking this…";

type ChecksLink = Extract<AppLink, { kind: "checks" }>;

/** The button, for one check; disabled with its reason when it can't open one (`reason` first, when given). */
export function KeepCheckingButton({ link, reason = null }: { link: ChecksLink | null; reason?: string | null }) {
  const readOnly = useReadOnlyReason();
  const why = readOnly ?? reason ?? keepCheckingProblem(link);
  return (
    <WhyDisabled reason={why}>
      <Button variant="outline" size="sm" disabled={why !== null} onClick={() => link && requestLink(link)}>
        <HeartPulseIcon data-icon="inline-start" />
        {LABEL}
      </Button>
    </WhyDisabled>
  );
}

/** Check ports: one check per port, so several ports checked offer each. */
export function KeepCheckingPorts({ target, results }: { target: ToolTarget; results: readonly PortResult[] }) {
  const readOnly = useReadOnlyReason();
  if (results.length === 1) return <KeepCheckingButton link={portCheck(target, results[0].port)} />;
  return (
    <DropdownMenu>
      <WhyDisabled reason={readOnly}>
        <DropdownMenuTrigger asChild disabled={readOnly !== null}>
          <Button variant="outline" size="sm" disabled={readOnly !== null}>
            <HeartPulseIcon data-icon="inline-start" />
            {LABEL}
            <ChevronDownIcon data-icon="inline-end" />
          </Button>
        </DropdownMenuTrigger>
      </WhyDisabled>
      <DropdownMenuContent align="end" className="max-h-72 min-w-44 overflow-y-auto">
        {results.map((r) => (
          <DropdownMenuItem key={r.port} onSelect={() => requestLink(portCheck(target, r.port))}>
            Port {r.port}
            <span className="ml-auto text-xs text-muted-foreground">{portStateText(r.state)}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
