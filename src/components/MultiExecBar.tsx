// SS-10, SS-11, UX-02: the one slim bar under the Terminal page's tabs, for the picked tabs. While Type in all tabs
// (MultiExec) is on it says how many tabs get what is typed, picks them (all, by folder, by environment, the quick
// connections, or by hand with Ctrl+click and Shift+click on the tabs), tiles them so each shows its own output, and
// says what the last keys did: a line sent or waiting for approval, keys passed straight through at a password prompt
// or to a full-screen program, and the tabs left out of a line, with why. While it is off and several tabs are picked
// (Ctrl+click), it says so; the toolbar's Type in all tabs and Compare hosts then use them. Either way it holds the
// picked tabs' Output menu, and ✕ (or Esc) turns typing off or clears the picks.

import { useMemo, type ReactNode } from "react";
import { CircleAlertIcon, LayoutGridIcon, ListChecksIcon, LoaderCircleIcon, RadioTowerIcon, XIcon } from "lucide-react";
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
import type { MultiExecStatus, SessionFolder } from "@/lib/api";
import { multiExecIdleReason } from "@/lib/disabled-reasons";
import { flattenFolders, subtree } from "@/lib/folders";
import { folderCounts, labelChoices, pickedText, pickTabs, type PickableTab } from "@/lib/multiexec-picks";
import { ENVIRONMENT_NAMES } from "@/lib/session-environment";
import { pickedTabsText } from "@/lib/terminal-layout";
import { cn } from "@/lib/utils";

/** What the bar says about the last keys. */
export interface MultiExecNote {
  tone: "info" | "warn" | "pass" | "wait";
  text: string;
}

interface Props {
  /** Type in all tabs is on. Off: several tabs are picked. */
  on: boolean;
  /** Every open tab. */
  tabs: PickableTab[];
  picked: number;
  /** The terminals in the picked tabs (a split tab holds several). */
  terminals: number;
  status: MultiExecStatus | null;
  note: MultiExecNote | null;
  folders: SessionFolder[];
  tile: boolean;
  onTile: (tile: boolean) => void;
  onPick: (keys: string[]) => void;
  /** ✕: turns typing off, or clears the picked tabs. */
  onClose: () => void;
  /** The picked tabs' Output menu (a DropdownMenu). */
  output: ReactNode;
}

export function MultiExecBar({
  on,
  tabs,
  picked,
  terminals,
  status,
  note,
  folders,
  tile,
  onTile,
  onPick,
  onClose,
  output,
}: Props) {
  const closeLabel = on ? "Turn off Type in all tabs" : "Clear the picked tabs";
  return (
    <div
      role="toolbar"
      aria-label={on ? "Type in all tabs" : "Picked tabs"}
      className={cn(
        "flex min-h-8 flex-wrap items-center gap-x-2 gap-y-0.5 rounded-lg border py-0.5 pr-0.5 pl-3 text-sm",
        on ? "border-primary/40 bg-primary/5" : "bg-muted/60",
      )}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !e.defaultPrevented) {
          e.preventDefault();
          onClose();
        }
      }}
    >
      {on ? (
        <Typing
          tabs={tabs}
          picked={picked}
          status={status}
          note={note}
          folders={folders}
          tile={tile}
          onTile={onTile}
          onPick={onPick}
          output={output}
        />
      ) : (
        <>
          <span className="font-medium whitespace-nowrap tabular-nums" aria-live="polite">
            {pickedTabsText(picked, terminals)}
          </span>
          {output}
          <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
            Type in all tabs and Compare hosts use them
          </span>
        </>
      )}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="ml-auto"
            aria-label={closeLabel}
            onClick={onClose}
          >
            <XIcon />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{closeLabel} (Esc)</TooltipContent>
      </Tooltip>
    </div>
  );
}

function Typing({
  tabs,
  picked,
  status,
  note,
  folders,
  tile,
  onTile,
  onPick,
  output,
}: Pick<Props, "tabs" | "picked" | "status" | "note" | "folders" | "tile" | "onTile" | "onPick" | "output">) {
  const subtrees = useMemo(() => new Map(folders.map((f) => [f.id, subtree(folders, f.id)])), [folders]);
  const counts = useMemo(() => folderCounts(tabs, subtrees), [tabs, subtrees]);
  const folderRows = flattenFolders(folders).filter((row) => counts.has(row.folder.id));
  const labels = labelChoices(tabs);
  const unsaved = tabs.filter((t) => t.unsaved).length;
  const receiving = status?.targets.filter((t) => t.receives).length ?? 0;
  const idle = status ? multiExecIdleReason(status.targets) : null;
  const tileReason = picked < 2 ? "Pick two or more tabs to see them side by side" : null;
  const message = idle ?? note?.text ?? null;

  return (
    <>
      <span className="flex items-center gap-1.5 whitespace-nowrap">
        <RadioTowerIcon className="size-4 text-primary" aria-hidden />
        <span className="font-medium">Typing in {pickedText(picked, tabs.length)}</span>
        {status && receiving !== status.targets.length && (
          <span className="text-muted-foreground">
            ({receiving} of {status.targets.length} terminals now)
          </span>
        )}
      </span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="sm" variant="ghost">
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
                  {ENVIRONMENT_NAMES[environment]}
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
            Or Ctrl+click a tab to add or remove it.
          </DropdownMenuLabel>
        </DropdownMenuContent>
      </DropdownMenu>
      <WhyDisabled reason={tileReason}>
        <Toggle
          size="sm"
          pressed={tile && picked > 1}
          onPressedChange={onTile}
          disabled={tileReason !== null}
          aria-label="Show the picked tabs side by side"
        >
          <LayoutGridIcon />
          Side by side
        </Toggle>
      </WhyDisabled>
      {output}
      {message && (
        <span
          className={cn(
            "flex min-w-0 flex-1 items-start gap-1.5 text-xs",
            (idle || note?.tone === "warn") && "text-tier-medium",
            !idle && note?.tone === "pass" && "text-primary",
            !idle && (note?.tone === "info" || note?.tone === "wait") && "text-muted-foreground",
          )}
          role="status"
        >
          {!idle && note?.tone === "wait" ? (
            <LoaderCircleIcon className="mt-px size-3.5 shrink-0 animate-spin" aria-hidden />
          ) : (
            <CircleAlertIcon className="mt-px size-3.5 shrink-0" aria-hidden />
          )}
          <span>{message}</span>
        </span>
      )}
    </>
  );
}
