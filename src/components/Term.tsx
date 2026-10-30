// UX-05: a term of the app's own, lightly underlined, whose one-sentence definition (lib/glossary.ts) shows on hover
// or keyboard focus. Use it where a term first appears in a view, not on every mention.
//
//   <Term id="goldenVm" />                 shows the glossary's own wording, "Golden VM"
//   a <Term id="goldenVm">golden VM</Term>  shows your wording, with the same definition
//
// The tooltip renders in a portal under <body>, which FD-03's DOM masking covers.

import type { ReactNode } from "react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { glossaryEntry, type TermKey } from "@/lib/glossary";
import { cn } from "@/lib/utils";

export interface TermProps {
  id: TermKey;
  /** The words shown; the glossary's term by default. */
  children?: ReactNode;
  className?: string;
}

export function Term({ id, children, className }: TermProps) {
  const entry = glossaryEntry(id);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          data-term={id}
          className={cn(
            "cursor-help underline decoration-muted-foreground/60 decoration-dotted underline-offset-4 outline-none focus-visible:rounded-sm focus-visible:ring-3 focus-visible:ring-ring/50",
            className,
          )}
        >
          {children ?? entry.term}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <span>
          <span className="font-medium">{entry.term}:</span> {entry.definition}
        </span>
      </TooltipContent>
    </Tooltip>
  );
}
