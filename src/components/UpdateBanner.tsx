// FD-14: shows a newer signed release with its notes. Installing submits the `appUpdate` command, so
// it goes through the approval dialog (Medium tier) and waits until no other job is running.
// `UpdateNotice` says when updates can't be checked because of the GitHub update token (none yet,
// expired, revoked, or without access), so checks never fail quietly.

import { DownloadIcon, KeyRoundIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { WhyDisabled } from "@/components/WhyDisabled";
import type { UpdateInfo } from "@/lib/api";

interface Props {
  update: UpdateInfo;
  /** QL-08: why Install can't be used now (FD-03: the read-only lock while presenting). */
  disabledReason?: string | null;
  onInstall: () => void;
  onLater: () => void;
}

export function UpdateBanner({ update, disabledReason, onInstall, onLater }: Props) {
  return (
    <Alert className="mb-6">
      <DownloadIcon />
      <AlertTitle>
        Remotely {update.version} is available (you have {update.currentVersion})
      </AlertTitle>
      <AlertDescription>
        {update.notes ? (
          <div className="max-h-32 overflow-auto whitespace-pre-wrap">{update.notes}</div>
        ) : (
          "No release notes."
        )}
        <p className="mt-1">It installs once no other job is running, then Remotely restarts.</p>
      </AlertDescription>
      <AlertAction className="flex gap-2">
        <Button size="sm" variant="outline" onClick={onLater}>
          Later
        </Button>
        <WhyDisabled reason={disabledReason}>
          <Button size="sm" disabled={!!disabledReason} onClick={onInstall}>
            Install
          </Button>
        </WhyDisabled>
      </AlertAction>
    </Alert>
  );
}

interface NoticeProps {
  title: string;
  description: string;
  destructive?: boolean;
  onOpenSettings: () => void;
  onLater: () => void;
}

export function UpdateNotice({ title, description, destructive, onOpenSettings, onLater }: NoticeProps) {
  return (
    <Alert className="mb-6" variant={destructive ? "destructive" : "default"}>
      <KeyRoundIcon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{description}</AlertDescription>
      <AlertAction className="flex gap-2">
        <Button size="sm" variant="outline" onClick={onLater}>
          Later
        </Button>
        <Button size="sm" onClick={onOpenSettings}>
          Open Settings
        </Button>
      </AlertAction>
    </Alert>
  );
}
