// UX-04: the "?" next to a page title or a control that needs more than its label. It opens a popover with one entry
// of the help registry (lib/help.ts): a title, one or two short paragraphs and, when the entry has one, a link to a
// Settings card or a page (opened through lib/links.ts requestLink, so no prop is needed). It is a real button, so Tab
// reaches it and Enter or Space opens it; Esc closes it. The popover renders in a portal under <body>, which FD-03's
// DOM masking covers like the rest of the window.
//
//   <HelpTip topic="windowsUnlock" />
//   <Label>Unlock with my Windows login <HelpTip topic="windowsUnlock" /></Label>

import { useState } from "react";
import { ArrowRightIcon, CircleHelpIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { helpEntry, type HelpKey } from "@/lib/help";
import { requestLink } from "@/lib/links";
import { cn } from "@/lib/utils";

export interface HelpTipProps {
  topic: HelpKey;
  /** The button's accessible name; "Help: <entry title>" by default. */
  label?: string;
  side?: "top" | "right" | "bottom" | "left";
  align?: "start" | "center" | "end";
  className?: string;
}

export function HelpTip({ topic, label, side = "bottom", align = "start", className }: HelpTipProps) {
  const [open, setOpen] = useState(false);
  const entry = helpEntry(topic);
  const link = entry.link;
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-xs"
          aria-label={label ?? `Help: ${entry.title}`}
          data-help={topic}
          className={cn("shrink-0 align-middle text-muted-foreground hover:text-foreground", className)}
        >
          <CircleHelpIcon />
        </Button>
      </PopoverTrigger>
      <PopoverContent side={side} align={align} className="w-80 gap-2 p-3" aria-label={entry.title}>
        <p className="font-medium">{entry.title}</p>
        {entry.body.map((paragraph) => (
          <p key={paragraph} className="text-muted-foreground">
            {paragraph}
          </p>
        ))}
        {link && (
          <Button
            type="button"
            variant="link"
            size="sm"
            className="h-auto justify-start p-0"
            onClick={() => {
              setOpen(false);
              requestLink(link.to);
            }}
          >
            {link.label}
            <ArrowRightIcon data-icon="inline-end" />
          </Button>
        )}
      </PopoverContent>
    </Popover>
  );
}
