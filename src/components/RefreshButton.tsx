// UX-06: the one refresh control: a refresh icon, the tooltip "Refresh", spinning while it reads. Every "read it
// again" button in the app is this one, whatever it reads.
//
//   <RefreshButton busy={loading} onClick={() => setReads((n) => n + 1)} />
//   <RefreshButton variant="outline" size="icon" busy={loading} onClick={reload} />   (in a page's toolbar)

import { RefreshCwIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export interface RefreshButtonProps {
  onClick: () => void;
  /** Reading now: the icon spins and the button waits. */
  busy?: boolean;
  disabled?: boolean;
  /** Ghost in panels and sheets, outline beside other outline buttons. */
  variant?: "ghost" | "outline";
  size?: "icon-sm" | "icon";
  className?: string;
}

export function RefreshButton({
  onClick,
  busy = false,
  disabled,
  variant = "ghost",
  size = "icon-sm",
  className,
}: RefreshButtonProps) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant={variant}
          size={size}
          aria-label="Refresh"
          aria-busy={busy || undefined}
          disabled={disabled ?? busy}
          className={className}
          onClick={onClick}
        >
          <RefreshCwIcon className={cn(busy && "animate-spin")} />
        </Button>
      </TooltipTrigger>
      <TooltipContent>Refresh</TooltipContent>
    </Tooltip>
  );
}
