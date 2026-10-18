// A table header that sorts its column when clicked, with the direction shown and announced: the
// dashboard grid (MO-03) and the VM list's columns, host shares included (MO-01).

import type { ReactNode } from "react";
import { ArrowDownIcon, ArrowUpIcon } from "lucide-react";
import { TableHead } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export function SortableHead({
  label,
  active,
  dir,
  onSort,
  hint,
  className,
}: {
  label: ReactNode;
  /** This column sorts the table now. */
  active: boolean;
  /** 1: ascending. */
  dir: 1 | -1;
  onSort: () => void;
  /** What the column means, shown on hover and focus. */
  hint?: string;
  className?: string;
}) {
  const button = (
    <button
      type="button"
      onClick={onSort}
      className="-mx-1 inline-flex items-center gap-1 rounded px-1 font-medium hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
    >
      {label}
      {active && (dir === 1 ? <ArrowUpIcon className="size-3" /> : <ArrowDownIcon className="size-3" />)}
    </button>
  );
  return (
    <TableHead
      className={cn("whitespace-nowrap", className)}
      aria-sort={active ? (dir === 1 ? "ascending" : "descending") : undefined}
    >
      {hint ? (
        <Tooltip>
          <TooltipTrigger asChild>{button}</TooltipTrigger>
          <TooltipContent className="max-w-xs">{hint}</TooltipContent>
        </Tooltip>
      ) : (
        button
      )}
    </TableHead>
  );
}
