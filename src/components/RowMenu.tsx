// UX-02: the one row menu. Every list's rows use this "⋯" trigger (one size, ghost) with the accessible name
// "Actions for <name>"; the items are ordinary DropdownMenuItems. A row's main action may also be its click or a
// hover icon, never a third copy.
//
//   <RowMenu label={vm.displayName}>
//     <DropdownMenuItem onSelect={...}><PencilIcon /> Rename…</DropdownMenuItem>
//     <DropdownMenuSeparator />
//     <DropdownMenuItem variant="destructive" onSelect={...}><Trash2Icon /> Delete…</DropdownMenuItem>
//   </RowMenu>

import type { ReactNode } from "react";
import { MoreHorizontalIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

export interface RowMenuProps {
  /** The row's name, for "Actions for <name>". */
  label: string;
  children: ReactNode;
  align?: "start" | "center" | "end";
  disabled?: boolean;
  onOpenChange?: (open: boolean) => void;
  /** For the trigger, e.g. "opacity-0 group-hover:opacity-100" (keep it visible on focus). */
  className?: string;
}

export function RowMenu({ label, children, align = "end", disabled, onOpenChange, className }: RowMenuProps) {
  return (
    <DropdownMenu onOpenChange={onOpenChange}>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label={`Actions for ${label}`}
          disabled={disabled}
          className={cn("text-muted-foreground hover:text-foreground", className)}
          // A click on the menu doesn't also select or open the row.
          onClick={(e) => e.stopPropagation()}
          onDoubleClick={(e) => e.stopPropagation()}
        >
          <MoreHorizontalIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align={align} className="min-w-44" onClick={(e) => e.stopPropagation()}>
        {children}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
