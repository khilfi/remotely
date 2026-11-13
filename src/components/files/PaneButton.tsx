// SS-14 (0.8.0 G3): a pane toolbar's icon button: its label as a tooltip, or (QL-08) why it is off.

import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { WhyDisabled } from "@/components/WhyDisabled";

export function PaneButton({
  label,
  onClick,
  disabledReason,
  children,
}: {
  label: string;
  onClick: () => void;
  disabledReason?: string | null;
  children: ReactNode;
}) {
  if (disabledReason) {
    return (
      <WhyDisabled reason={`${label}: ${disabledReason}`}>
        <Button variant="ghost" size="icon-sm" aria-label={label} disabled>
          {children}
        </Button>
      </WhyDisabled>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={label} onClick={onClick}>
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}
