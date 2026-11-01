// FD-09: the Toolbox's items in a session's or VM's row menu: Ping, Trace route, Check ports, View certificate and
// Wake up, each opening its tab with the row filled in (a `toolbox` link, so no page needs a callback for it).

import { ActivityIcon, NetworkIcon, PowerIcon, RouteIcon, ShieldCheckIcon, WrenchIcon } from "lucide-react";
import {
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from "@/components/ui/dropdown-menu";
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
      </DropdownMenuSubContent>
    </DropdownMenuSub>
  );
}
