// SS-10: the MultiExec bar under the Terminal page's tabs, while MultiExec is on. It says how many tabs get what is
// typed, picks them (all, by folder, by label, the quick connections, or by hand with Ctrl+click and Shift+click on
// the tabs), tiles the picked tabs so each shows its own output, opens Compare output for them, and says what the
// last keys did: a line sent or waiting for approval, keys passed straight through at a password prompt or to a
// full-screen program, and the tabs left out of a line, with why.

import { useMemo } from "react";
import {
  CircleAlertIcon,
  GitCompareArrowsIcon,
  LayoutGridIcon,
  ListChecksIcon,
  LoaderCircleIcon,
  RadioTowerIcon,
} from "lucide-react";
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
import { Toggle } from "@/components/ui/toggle";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import type { Environment, MultiExecStatus, SessionFolder } from "@/lib/api";
import { multiExecIdleReason } from "@/lib/disabled-reasons";
import { flattenFolders, subtree } from "@/lib/folders";
import { folderCounts, labelChoices, pickedText, pickTabs, type PickableTab } from "@/lib/multiexec-picks";
import { cn } from "@/lib/utils";

/** What the bar says about the last keys. */
export interface MultiExecNote {
  tone: "info" | "warn" | "pass" | "wait";
  text: string;
}

const LABELS: Record<Environment, string> = { none: "None", lab: "Lab", staging: "Staging", prod: "Prod" };

interface Props {
  tabs: PickableTab[];
  picked: number;
  status: MultiExecStatus | null;
  note: MultiExecNote | null;
  folders: SessionFolder[];
  tile: boolean;
  onTile: (tile: boolean) => void;
  onPick: (keys: string[]) => void;
  onCompare: () => void;
  onOff: () => void;
}

export function MultiExecBar({ tabs, picked, status, note, folders, tile, onTile, onPick, onCompare, onOff }: Props) {
  const subtrees = useMemo(() => new Map(folders.map((f) => [f.id, subtree(folders, f.id)])), [folders]);
  const counts = useMemo(() => folderCounts(tabs, subtrees), [tabs, subtrees]);
  const folderRows = flattenFolders(folders).filter((row) => counts.has(row.folder.id));
  const labels = labelChoices(tabs);
  const unsaved = tabs.filter((t) => t.unsaved).length;
  const receiving = status?.targets.filter((t) => t.receives).length ?? 0;
  const idle = status ? multiExecIdleReason(status.targets) : null;
  const tileReason = picked < 2 ? "Pick two or more tabs to see them side by side" : null;

  return (
    <div
      className="grid gap-1 rounded-md border border-primary/40 bg-primary/5 px-3 py-1.5 text-sm"
      role="status"
      aria-label="Type in all tabs"
    >
      <div className="flex flex-wrap items-center gap-2">
        <RadioTowerIcon className="size-4 text-primary" aria-hidden />
        <span className="font-medium">Typing in all tabs:</span>
        <span>
          typing goes to {pickedText(picked, tabs.length)}
          {status && receiving !== status.targets.length && ` (${receiving} of ${status.targets.length} terminals now)`}
        </span>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button size="xs" variant="outline">
              <ListChecksIcon data-icon="inline-start" />
              Pick tabs
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-64">
            <DropdownMenuItem onSelect={() => onPick(pickTabs(tabs, { kind: "all" }))}>
              All {tabs.length} tabs
            </DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger disabled={folderRows.length === 0}>
                <span>
                  By folder
                  <ReasonLine reason={folderRows.length === 0 ? "No open tab is in a folder" : null} />
                </span>
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent className="max-h-80 overflow-auto">
                {folderRows.map(({ folder, depth }) => (
                  <DropdownMenuItem
                    key={folder.id}
                    style={{ paddingLeft: `${0.5 + depth * 0.75}rem` }}
                    onSelect={() =>
                      onPick(pickTabs(tabs, { kind: "folder", under: subtrees.get(folder.id) ?? new Set() }))
                    }
                  >
                    <span className="truncate">{folder.name}</span>
                    <span className="ml-auto text-xs text-muted-foreground">{counts.get(folder.id)}</span>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger disabled={labels.length === 0}>
                <span>
                  By environment
                  <ReasonLine reason={labels.length === 0 ? "No open tab is Lab, Staging or Prod" : null} />
                </span>
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                {labels.map(({ environment, count }) => (
                  <DropdownMenuItem
                    key={environment}
                    onSelect={() => onPick(pickTabs(tabs, { kind: "label", environment }))}
                  >
                    {LABELS[environment]}
                    <span className="ml-auto text-xs text-muted-foreground">{count}</span>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuItem disabled={unsaved === 0} onSelect={() => onPick(pickTabs(tabs, { kind: "unsaved" }))}>
              <span>
                Quick connections ({unsaved})
                <ReasonLine reason={unsaved === 0 ? "Every open tab is a saved session" : null} />
              </span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuLabel className="font-normal text-muted-foreground">
              By hand: Ctrl+click a tab to add or remove it, Shift+click for a range.
            </DropdownMenuLabel>
          </DropdownMenuContent>
        </DropdownMenu>
        <WhyDisabled reason={tileReason}>
          <Toggle
            size="sm"
            variant="outline"
            className="h-6"
            pressed={tile && picked > 1}
            onPressedChange={onTile}
            disabled={tileReason !== null}
            aria-label="Show the picked tabs side by side"
          >
            <LayoutGridIcon />
            Side by side
          </Toggle>
        </WhyDisabled>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button size="xs" variant="outline" onClick={onCompare}>
              <GitCompareArrowsIcon data-icon="inline-start" />
              Compare hosts…
            </Button>
          </TooltipTrigger>
          <TooltipContent className="max-w-80">
            Runs one command on the picked tabs&apos; hosts and groups the answers (48 same, 2 differ)
          </TooltipContent>
        </Tooltip>
        <Button size="xs" variant="ghost" className="ml-auto" onClick={onOff}>
          Turn off
        </Button>
      </div>
      {(idle || note) && (
        <p
          className={cn(
            "flex items-start gap-1.5 text-xs",
            (idle || note?.tone === "warn") && "text-tier-medium",
            !idle && note?.tone === "pass" && "text-primary",
            !idle && (note?.tone === "info" || note?.tone === "wait") && "text-muted-foreground",
          )}
        >
          {!idle && note?.tone === "wait" ? (
            <LoaderCircleIcon className="mt-px size-3.5 shrink-0 animate-spin" aria-hidden />
          ) : (
            <CircleAlertIcon className="mt-px size-3.5 shrink-0" aria-hidden />
          )}
          <span>{idle ?? note?.text}</span>
        </p>
      )}
    </div>
  );
}
