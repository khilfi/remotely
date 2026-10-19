// QL-08: a disabled button says why. A disabled button gets no pointer events, so the tooltip hangs on a wrapper
// that can be hovered and focused; the reason is also its accessible description. Without a reason, the button is
// returned as it is.

import type { ReactElement } from "react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export function WhyDisabled({
  reason,
  children,
  className,
}: {
  /** Why the button is disabled; null or undefined when it is not. */
  reason: string | null | undefined;
  children: ReactElement;
  className?: string;
}) {
  if (!reason) return children;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} aria-label={reason} className={cn("inline-flex cursor-not-allowed", className)}>
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-80">{reason}</TooltipContent>
    </Tooltip>
  );
}

/** QL-08 for a disabled menu item: the reason, small, under its label. */
export function ReasonLine({ reason }: { reason: string | null | undefined }) {
  if (!reason) return null;
  return <span className="block text-xs text-muted-foreground">{reason}</span>;
}
