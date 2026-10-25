// QL-19: the Terminal page's Groups menu, next to the MultiExec switch. Each saved group can be opened (a tab for each
// of its sessions, reusing tabs already open, then MultiExec on with exactly those tabs picked) or selected (its open
// tabs picked, MultiExec on). The picked tabs can be saved as a group, and the groups managed. QL-08: disabled items say
// why under their label.

import { LayersIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ReasonLine } from "@/components/WhyDisabled";
import type { MultiExecGroup } from "@/lib/api";
import { plural } from "@/lib/format";
import { groupSummary, groupTabs, type GroupTab } from "@/lib/multiexec-groups";
import { cn } from "@/lib/utils";

interface Props {
  groups: MultiExecGroup[];
  /** Every open tab, left to right. */
  tabs: GroupTab[];
  /** Why MultiExec can't be turned on (FD-03 read-only lock), or null. */
  multiExecBlocked: string | null;
  /** Why the picked tabs can't be saved as a group, or null. */
  saveReason: string | null;
  /** The saved sessions "Save picked tabs as a group" would save. */
  saveCount: number;
  onOpenGroup: (group: MultiExecGroup) => void;
  onSelectGroup: (group: MultiExecGroup) => void;
  onSave: () => void;
  onManage: () => void;
  /** The menu opened: the groups are read again. */
  onShow: () => void;
  className?: string;
}

export function MultiExecGroupsMenu({
  groups,
  tabs,
  multiExecBlocked,
  saveReason,
  saveCount,
  onOpenGroup,
  onSelectGroup,
  onSave,
  onManage,
  onShow,
  className,
}: Props) {
  return (
    <DropdownMenu onOpenChange={(open) => open && onShow()}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Saved MultiExec groups" className={className}>
              <LayersIcon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Saved MultiExec groups: open or select a set of sessions</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuLabel>Saved MultiExec groups</DropdownMenuLabel>
        {groups.length === 0 && (
          <DropdownMenuItem disabled>
            <span>
              No groups saved yet
              <ReasonLine reason="Pick tabs and save them as a group, or make one in Manage groups" />
            </span>
          </DropdownMenuItem>
        )}
        <div className="max-h-80 overflow-y-auto">
          {groups.map((group) => {
            const picked = groupTabs(group, tabs);
            const toOpen = picked.missing.length;
            const empty = group.members.length === 0 ? "Its sessions were deleted: edit it in Manage groups" : null;
            const openReason = multiExecBlocked ?? empty;
            const selectReason =
              multiExecBlocked ??
              empty ??
              (picked.keys.length === 0 ? "None of its sessions is open: use Open group" : null);
            return (
              <DropdownMenuSub key={group.id}>
                <DropdownMenuSubTrigger>
                  <span className="grid min-w-0">
                    <span className="truncate">{group.name}</span>
                    <span className="text-xs text-muted-foreground">{groupSummary(group, tabs)}</span>
                  </span>
                </DropdownMenuSubTrigger>
                <DropdownMenuSubContent className="w-72">
                  <DropdownMenuItem disabled={openReason !== null} onSelect={() => onOpenGroup(group)}>
                    <span>
                      Open group
                      <span className={cn("block text-xs text-muted-foreground", openReason && "hidden")}>
                        {toOpen === 0
                          ? `Every session is open: MultiExec on for its ${plural(picked.keys.length, "tab")}`
                          : `Opens ${plural(toOpen, "tab")}${picked.keys.length > 0 ? `, uses ${picked.keys.length} open already` : ""}, then MultiExec on for them`}
                      </span>
                      <ReasonLine reason={openReason} />
                    </span>
                  </DropdownMenuItem>
                  <DropdownMenuItem disabled={selectReason !== null} onSelect={() => onSelectGroup(group)}>
                    <span>
                      Select group
                      <span className={cn("block text-xs text-muted-foreground", selectReason && "hidden")}>
                        MultiExec on for its {plural(picked.keys.length, "open tab")}
                        {toOpen > 0 ? ` (${toOpen} not open)` : ""}
                      </span>
                      <ReasonLine reason={selectReason} />
                    </span>
                  </DropdownMenuItem>
                </DropdownMenuSubContent>
              </DropdownMenuSub>
            );
          })}
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled={saveReason !== null} onSelect={onSave}>
          <span>
            {saveCount > 1 ? `Save the ${saveCount} picked sessions as a group…` : "Save picked tabs as a group…"}
            <ReasonLine reason={saveReason} />
          </span>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={onManage}>Manage groups…</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
