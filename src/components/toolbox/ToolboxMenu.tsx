// FD-09: the Toolbox's items in a session's or VM's row menu: Ping, Trace route, Check ports, View certificate and
// Wake up, each opening its tab with the row filled in (a `toolbox` link, so no page needs a callback for it). MO-08's
// "Add a check" sits with them: a `checks` link opens the Dashboard's Checks tab with a new check on the row.

import {
  ActivityIcon,
  HeartPulseIcon,
  NetworkIcon,
  PowerIcon,
  RouteIcon,
  ShieldCheckIcon,
  WrenchIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { requestLink } from "@/lib/links";
import type { ToolboxTool, ToolTarget } from "@/lib/toolbox";

/** The tools a row offers, also listed by the palette's VM and session views. */
export const TOOLBOX_ROW_ITEMS: { tool: ToolboxTool; label: string; icon: typeof ActivityIcon }[] = [
  { tool: "ping", label: "Ping", icon: ActivityIcon },
  { tool: "trace", label: "Trace route", icon: RouteIcon },
  { tool: "ports", label: "Check ports", icon: NetworkIcon },
  { tool: "certificate", label: "View certificate", icon: ShieldCheckIcon },
  { tool: "wake", label: "Wake up", icon: PowerIcon },
];

/** The same tools behind a toolbar icon: the VM details panel's header, beside its other actions. */
export function ToolboxIconMenu({ target }: { target: ToolTarget }) {
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label="Toolbox: ping, ports, wake up, add a check"
            >
              <WrenchIcon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Toolbox</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="min-w-44">
        {TOOLBOX_ROW_ITEMS.map(({ tool, label, icon: Icon }) => (
          <DropdownMenuItem key={tool} onSelect={() => requestLink({ kind: "toolbox", tool, target })}>
            <Icon />
            {label}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => requestLink({ kind: "checks", add: target })}>
          <HeartPulseIcon />
          Add a check
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function ToolboxMenu({ target }: { target: ToolTarget }) {
  return (
    <DropdownMenuSub>
      <DropdownMenuSubTrigger>
        <WrenchIcon />
        Toolbox
      </DropdownMenuSubTrigger>
      <DropdownMenuSubContent>
        {TOOLBOX_ROW_ITEMS.map(({ tool, label, icon: Icon }) => (
          <DropdownMenuItem key={tool} onSelect={() => requestLink({ kind: "toolbox", tool, target })}>
            <Icon />
            {label}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => requestLink({ kind: "checks", add: target })}>
          <HeartPulseIcon />
          Add a check
        </DropdownMenuItem>
      </DropdownMenuSubContent>
    </DropdownMenuSub>
  );
}
