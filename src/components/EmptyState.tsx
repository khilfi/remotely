// UX-07's pattern, built on shadcn's Empty: a title that names the space ("No images yet"), at most one line saying
// what it is for, and the one action that fills it. Anything longer goes in a HelpTip (`help`).
//
//   <EmptyState
//     icon={DiscIcon}
//     title="No images yet"
//     description="An image is where a new VM's OS comes from."
//     help="page.templates"
//     action={<Button onClick={addImage}><PlusIcon data-icon="inline-start" /> Add an image</Button>}
//   />

import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { HelpTip } from "@/components/HelpTip";
import type { HelpKey } from "@/lib/help";
import { cn } from "@/lib/utils";

export interface EmptyStateProps {
  icon?: LucideIcon;
  /** Names the space: "No sessions yet", "No snapshots". */
  title: ReactNode;
  /** One line: what the space is for, or why it is empty. */
  description?: ReactNode;
  /** More, behind a "?" next to the title. */
  help?: HelpKey;
  /** The one action that fills the space (a primary button), or a WhyDisabled-wrapped one. */
  action?: ReactNode;
  /** A dashed border, for a space that stands alone; off inside a card. Default true. */
  bordered?: boolean;
  className?: string;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  help,
  action,
  bordered = true,
  className,
}: EmptyStateProps) {
  return (
    <Empty className={cn(bordered && "border", className)}>
      <EmptyHeader>
        {Icon && (
          <EmptyMedia variant="icon">
            <Icon />
          </EmptyMedia>
        )}
        <EmptyTitle className="flex items-center gap-1">
          {title}
          {help && <HelpTip topic={help} />}
        </EmptyTitle>
        {description && <EmptyDescription>{description}</EmptyDescription>}
      </EmptyHeader>
      {action && <EmptyContent className="flex-row flex-wrap justify-center">{action}</EmptyContent>}
    </Empty>
  );
}
