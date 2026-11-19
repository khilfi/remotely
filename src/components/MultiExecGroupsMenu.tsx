// QL-19 saved groups on the Terminal page; UX-16 (0.9.0 H2) moved them from Terminal ⋯ › Saved groups into the typing
// bar's "Pick tabs ▸" menu (UX-03: one home, plus the palette's "Open group: <name>"). Each saved group can be opened
// (a tab for each of its sessions, reusing tabs already open, then Type in all tabs on with exactly those tabs picked)
// or selected (its open tabs picked, Type in all tabs on). The picked tabs can be saved as a group, and the groups
// managed. QL-08: disabled items say why under their label. A group is also a pick in every bulk job's picker
// (BulkTargetPicker's Groups tab).

import {
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from "@/components/ui/dropdown-menu";
import { ReasonLine } from "@/components/WhyDisabled";
import type { MultiExecGroup } from "@/lib/api";
import { plural } from "@/lib/format";
import { groupSummary, groupTabs, type GroupTab } from "@/lib/multiexec-groups";
import { cn } from "@/lib/utils";

interface Props {
  groups: MultiExecGroup[];
  /** Every open tab, left to right. */
  tabs: GroupTab[];
  /** Why Type in all tabs can't be turned on (the read-only lock while presenting), or null. */
  multiExecBlocked: string | null;
  /** Why the picked tabs can't be saved as a group, or null. */
  saveReason: string | null;
  /** The saved sessions "Save picked tabs as a group" would save. */
  saveCount: number;
  onOpenGroup: (group: MultiExecGroup) => void;
  onSelectGroup: (group: MultiExecGroup) => void;
  onSave: () => void;
  onManage: () => void;
}

/** The saved groups' items, for the inside of the typing bar's "Pick tabs" menu. */
export function MultiExecGroupsItems({
  groups,
  tabs,
  multiExecBlocked,
  saveReason,
  saveCount,
  onOpenGroup,
  onSelectGroup,
  onSave,
  onManage,
}: Props) {
  return (
    <>
      <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">Saved groups</DropdownMenuLabel>
      {groups.length === 0 && (
        <DropdownMenuItem disabled>
          <span>
            No groups saved yet
            <ReasonLine reason="Save the picked tabs as a group, or make one in Manage groups" />
          </span>
        </DropdownMenuItem>
      )}
      <div className="max-h-64 overflow-y-auto">
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
                        ? `Every session is open: types in all its ${plural(picked.keys.length, "tab")}`
                        : `Opens ${plural(toOpen, "tab")}${picked.keys.length > 0 ? `, uses ${picked.keys.length} open already` : ""}, then types in all of them`}
                    </span>
                    <ReasonLine reason={openReason} />
                  </span>
                </DropdownMenuItem>
                <DropdownMenuItem disabled={selectReason !== null} onSelect={() => onSelectGroup(group)}>
                  <span>
                    Select group
                    <span className={cn("block text-xs text-muted-foreground", selectReason && "hidden")}>
                      Types in all its {plural(picked.keys.length, "open tab")}
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
      <DropdownMenuItem disabled={saveReason !== null} onSelect={onSave}>
        <span>
          {saveCount > 1 ? `Save the ${saveCount} picked sessions as a group…` : "Save picked tabs as a group…"}
          <ReasonLine reason={saveReason} />
        </span>
      </DropdownMenuItem>
      <DropdownMenuItem onSelect={onManage}>Manage groups…</DropdownMenuItem>
    </>
  );
}
