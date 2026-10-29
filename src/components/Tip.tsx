// UX-09: a one-time tip. It shows until the user dismisses it with ✕ and never again after, until Settings › General's
// "Show tips again" (lib/tips.ts keeps the dismissed ids in local storage). Use it for a first use that needs one
// sentence of guidance (picking several tabs, the selection bar, Customize), not for help that belongs in a HelpTip.
// Ids are "<page>.<what>".
//
//   <Tip id="terminal.pickTabs">Ctrl+click tabs to pick several, then type in all of them at once.</Tip>

import { useSyncExternalStore, type ReactNode } from "react";
import { LightbulbIcon, XIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { dismissTip, resetTips, subscribeTips, tipsSnapshot } from "@/lib/tips";
import { cn } from "@/lib/utils";

export interface TipProps {
  id: string;
  /** One sentence. */
  children: ReactNode;
  className?: string;
}

/** Settings › General: shows every dismissed tip again. Off while none was dismissed. */
export function ShowTipsAgainButton() {
  const dismissed = useSyncExternalStore(subscribeTips, tipsSnapshot);
  const none = dismissed.size === 0;
  return (
    <Button
      type="button"
      variant="outline"
      disabled={none}
      title={none ? "No tip was dismissed" : undefined}
      onClick={() => {
        resetTips();
        toast.success("Tips will show again");
      }}
    >
      <LightbulbIcon data-icon="inline-start" />
      Show tips again
    </Button>
  );
}

export function Tip({ id, children, className }: TipProps) {
  const dismissed = useSyncExternalStore(subscribeTips, tipsSnapshot);
  if (dismissed.has(id)) return null;
  return (
    <div
      role="note"
      data-tip={id}
      className={cn(
        "flex items-center gap-2 rounded-lg border bg-muted/50 py-1 pr-1 pl-3 text-sm text-muted-foreground",
        className,
      )}
    >
      <LightbulbIcon className="size-4 shrink-0 text-tier-medium" aria-hidden />
      <span className="min-w-0 flex-1">{children}</span>
      <Button
        type="button"
        variant="ghost"
        size="icon-xs"
        aria-label="Dismiss the tip"
        title="Dismiss the tip"
        onClick={() => dismissTip(id)}
      >
        <XIcon />
      </Button>
    </div>
  );
}
