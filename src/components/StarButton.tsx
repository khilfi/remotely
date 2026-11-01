// QL-26: the star on a session, VM or command row. Filled while starred; otherwise shown on the row's hover (the row's
// `group` class) or focus, so it doesn't crowd the list. Starred items come first in the session tree, the VMs list and
// Ctrl+K. Not audited, and allowed while presenting.

import { StarIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { StarKind } from "@/lib/comfort-api";
import { isStarred, starLabel } from "@/lib/stars";
import { toggleStar, useStars } from "@/lib/stars-store";
import { cn } from "@/lib/utils";

export function StarButton({
  kind,
  itemKey,
  name,
  hoverGroup,
  className,
}: {
  kind: StarKind;
  itemKey: string;
  name: string;
  /** The row's named Tailwind group (`group/row`), when it has one. */
  hoverGroup?: "row";
  className?: string;
}) {
  const sets = useStars();
  const starred = isStarred(sets, kind, itemKey);
  const label = starLabel(starred, name);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label={label}
          aria-pressed={starred}
          className={cn(
            "size-6 shrink-0",
            !starred && "opacity-0 focus-visible:opacity-100",
            !starred && (hoverGroup === "row" ? "group-hover/row:opacity-100" : "group-hover:opacity-100"),
            className,
          )}
          onClick={(e) => {
            e.stopPropagation();
            void toggleStar(kind, itemKey);
          }}
          onDoubleClick={(e) => e.stopPropagation()}
        >
          <StarIcon className={cn(starred && "fill-amber-400 text-amber-500")} />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{starred ? "Starred: shown first. Click to unstar" : "Star: show it first"}</TooltipContent>
    </Tooltip>
  );
}
