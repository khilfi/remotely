// UX-02: bulk actions show only while rows are selected, in this bar, which takes the place of the page's search row
// (PageHeader's children) until the selection is cleared:
//
//   2 selected | Start  Shut down  Snapshot  ⋯ |                                  ✕
//
//   <PageHeader page="vms" primary={...}>
//     {selected.length > 0 ? (
//       <SelectionBar count={selected.length} onClear={() => setSelected([])}>
//         <Button variant="ghost" size="sm" onClick={start}><PlayIcon /> Start</Button>
//         ...
//       </SelectionBar>
//     ) : (
//       <Input placeholder="Search" ... />
//     )}
//   </PageHeader>
//
// Actions are ghost, size "sm" buttons (a DropdownMenu for the rest); disabled ones say why with WhyDisabled. Esc
// inside the bar, or ✕, clears the selection.

import type { ReactNode } from "react";
import { XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export interface SelectionBarProps {
  /** How many rows are selected (the bar shows only while there is at least one). */
  count: number;
  onClear: () => void;
  /** The actions for the selected rows. */
  children?: ReactNode;
  className?: string;
}

export function SelectionBar({ count, onClear, children, className }: SelectionBarProps) {
  if (count <= 0) return null;
  return (
    <div
      role="toolbar"
      aria-label={`${count} selected`}
      className={cn(
        "flex min-h-8 min-w-0 flex-1 items-center gap-2 rounded-lg border bg-muted/60 py-0.5 pr-0.5 pl-3",
        className,
      )}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !e.defaultPrevented) {
          e.preventDefault();
          onClear();
        }
      }}
    >
      <span className="text-sm font-medium whitespace-nowrap tabular-nums" aria-live="polite">
        {count} selected
      </span>
      {children && (
        <>
          <Separator orientation="vertical" className="data-vertical:self-center data-[orientation=vertical]:h-4" />
          <div className="flex min-w-0 flex-wrap items-center gap-1">{children}</div>
        </>
      )}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="ml-auto"
            aria-label="Clear the selection"
            onClick={onClear}
          >
            <XIcon />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Clear the selection (Esc)</TooltipContent>
      </Tooltip>
    </div>
  );
}
