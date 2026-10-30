// FD-14: the update notice above the pages. A newer signed release shows its version, its notes on request ("What's
// new"), and Install, which submits the `appUpdate` command, so it goes through the approval dialog (Medium tier) and
// waits until no other job is running. A check that failed, or that needs the GitHub update token (the repository went
// private again and there is none, or it expired, was revoked or has no access), says so, so checks never fail quietly.
// A used-up GitHub limit shows nothing, since the app checks again by itself once it resets.
//
// UX-04 (0.6.0): the three banners are one quiet line (lib/update-notice.ts picks which), and the long explanations
// are the help registry's updateChecks and updateToken entries.

import { DownloadIcon, KeyRoundIcon, TriangleAlertIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { sentence } from "@/lib/containers";
import type { UpdateNoticeState } from "@/lib/update-notice";
import { cn } from "@/lib/utils";

interface Props {
  notice: UpdateNoticeState;
  /** QL-08: why Install can't be used now (FD-03: the read-only lock while presenting). */
  installReason?: string | null;
  onInstall: (version: string) => void;
  onOpenSettings: () => void;
  onLater: () => void;
}

export function UpdateNotice({ notice, installReason, onInstall, onOpenSettings, onLater }: Props) {
  const Icon =
    notice.kind === "available" ? DownloadIcon : notice.kind === "problem" ? TriangleAlertIcon : KeyRoundIcon;
  return (
    <div
      role="status"
      className={cn(
        "mb-4 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border bg-muted/40 py-1.5 pr-1.5 pl-3 text-sm",
        notice.kind === "problem" && "border-destructive/30",
      )}
    >
      <Icon
        className={cn("size-4 shrink-0", notice.kind === "problem" ? "text-destructive" : "text-muted-foreground")}
        aria-hidden
      />
      <span className="flex min-w-0 flex-1 items-center gap-1">
        {notice.kind === "available" && (
          <span>
            Remotely {notice.update.version} is available{" "}
            <span className="text-muted-foreground">(you have {notice.update.currentVersion})</span>
          </span>
        )}
        {notice.kind === "problem" && (
          <>
            <span className="min-w-0 truncate" title={sentence(notice.message)}>
              Remotely can&apos;t check for updates: {sentence(notice.message)}
            </span>
            <HelpTip topic="updateChecks" />
          </>
        )}
        {notice.kind === "tokenNeeded" && (
          <>
            <span>Updates need a GitHub update token</span>
            <HelpTip topic="updateToken" />
          </>
        )}
      </span>
      <div className="flex shrink-0 items-center gap-1">
        {notice.kind === "available" && (
          <Popover>
            <PopoverTrigger asChild>
              <Button size="sm" variant="ghost">
                What&apos;s new
              </Button>
            </PopoverTrigger>
            <PopoverContent align="end" className="w-96">
              <p className="mb-1 font-medium">Remotely {notice.update.version}</p>
              <div className="max-h-64 overflow-auto text-sm whitespace-pre-wrap text-muted-foreground">
                {notice.update.notes || "No release notes."}
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                It installs once no other job is running, then Remotely restarts.
              </p>
            </PopoverContent>
          </Popover>
        )}
        <Button size="sm" variant="ghost" onClick={onLater}>
          Later
        </Button>
        {notice.kind === "available" ? (
          <WhyDisabled reason={installReason}>
            <Button size="sm" disabled={!!installReason} onClick={() => onInstall(notice.update.version)}>
              Install
            </Button>
          </WhyDisabled>
        ) : (
          <Button size="sm" variant="outline" onClick={onOpenSettings}>
            Open Settings
          </Button>
        )}
      </div>
    </div>
  );
}
