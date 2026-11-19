// UX-19 (0.9.0 H4): "Keep checking this…" under a Toolbox result (Ping, Check ports, Certificate, DNS lookup). It opens
// MO-08's check editor on the Dashboard's Checks tab, filled in from what the tool just ran (a `checks` link, as every
// "Add a check" does); nothing is saved until the dialog's Add check, which the core audits as check_changed. A secondary
// button: the tool's run stays the tab's one primary.

import { ChevronDownIcon, HeartPulseIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { WhyDisabled } from "@/components/WhyDisabled";
import { requestLink, type AppLink } from "@/lib/links";
import { portCheck } from "@/lib/monitor";
import { portStateText, type ToolTarget } from "@/lib/toolbox";
import type { PortResult } from "@/lib/toolbox-api";

const LABEL = "Keep checking this…";

/** The button, for one check; disabled with its reason when the result can't become one. */
export function KeepCheckingButton({ link, reason = null }: { link: AppLink | null; reason?: string | null }) {
  const why = reason ?? (link ? null : "This result can't become a check.");
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
  if (results.length === 1) return <KeepCheckingButton link={portCheck(target, results[0].port)} />;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <HeartPulseIcon data-icon="inline-start" />
          {LABEL}
          <ChevronDownIcon data-icon="inline-end" />
        </Button>
      </DropdownMenuTrigger>
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
