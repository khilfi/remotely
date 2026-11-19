// UX-19 (0.9.0 H4): Monitor ▸ in a session's row menu (the Sessions page and the Terminal page's tree) and, as an icon
// menu, in the VM details panel's header: "Watch its metrics" (or "Stop watching") and "Add a check", each with one
// line on what it costs. Watching is MO-02's (a VM through a linked SSH or WinRM session), audited by the core with no
// tier; "Add a check" opens MO-08's check editor on the Dashboard's Checks tab through a `checks` link, the same
// dialog every "Add a check" opens. The palette's VM and session views list the same two (CommandPalette's Monitor
// group). Which sessions are watched is read when the menu opens, never in the background.

import { EyeIcon, EyeOffIcon, HeartPulseIcon, RadarIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useWatched } from "@/hooks/use-watched";
import { requestLink } from "@/lib/links";
import { checkCostText, watchCostText, watchState, type WatchSource } from "@/lib/monitor";
import type { ToolTarget } from "@/lib/toolbox";

export interface MonitorTarget {
  /** What a check goes on. */
  check: ToolTarget;
  /** What its metrics are watched through. */
  watch: WatchSource;
}

/** The two items, read when they show (a submenu's or a menu's content mounts as it opens). */
function MonitorItems({ target }: { target: MonitorTarget }) {
  const { watched, intervalSecs, watch } = useWatched(true);
  const state = watched ? watchState(target.watch, watched) : null;
  const watching = state?.can === true && state.watching;
  return (
    <>
      <DropdownMenuItem
        disabled={state === null || !state.can}
        onSelect={() => {
          if (state?.can) void watch(state.sessionId, !state.watching);
        }}
      >
        {watching ? <EyeOffIcon /> : <EyeIcon />}
        <div className="flex flex-col">
          <span>{watching ? "Stop watching" : "Watch its metrics"}</span>
          <span className="text-xs text-muted-foreground">
            {state === null ? "Reading…" : state.can ? watchCostText(state, intervalSecs) : state.reason}
          </span>
        </div>
      </DropdownMenuItem>
      <DropdownMenuItem onSelect={() => requestLink({ kind: "checks", add: target.check })}>
        <HeartPulseIcon />
        <div className="flex flex-col">
          <span>Add a check</span>
          <span className="text-xs text-muted-foreground">{checkCostText()}</span>
        </div>
      </DropdownMenuItem>
    </>
  );
}

/** Monitor ▸ in a row menu. */
export function MonitorMenu({ target }: { target: MonitorTarget }) {
  return (
    <DropdownMenuSub>
      <DropdownMenuSubTrigger>
        <RadarIcon />
        Monitor
      </DropdownMenuSubTrigger>
      <DropdownMenuSubContent className="max-w-80">
        <MonitorItems target={target} />
      </DropdownMenuSubContent>
    </DropdownMenuSub>
  );
}

/** The same items behind a toolbar icon: the VM details panel's header, beside the Toolbox's. */
export function MonitorIconMenu({ target }: { target: MonitorTarget }) {
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button type="button" variant="ghost" size="icon-sm" aria-label="Monitor: watch its metrics, add a check">
              <RadarIcon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Monitor</TooltipContent>
      </Tooltip>
      {/* Its own width, not the icon's: each item's cost line stays on one line. */}
      <DropdownMenuContent align="end" className="w-auto max-w-80 min-w-44">
        <MonitorItems target={target} />
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
