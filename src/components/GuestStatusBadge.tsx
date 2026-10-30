// MO-02: where guest polling stands for a watched host. The message (why it failed, when it tries
// again) shows on hover and to screen readers. UX-07: a host whose key isn't trusted (new, or changed) is no dead end:
// with `onCheckKey` the badge opens a terminal to the host, where SS-05's host key prompt shows the key to trust; trusting
// it there lets the dashboard log in again at once (the core's credentials_changed).

import { ShieldQuestionIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { GuestState, GuestStatus } from "@/lib/api";
import { cn } from "@/lib/utils";

const STATE: Record<GuestState, { label: string; className: string }> = {
  ok: { label: "Guest OK", className: "border-success/40 text-success" },
  connecting: { label: "Connecting", className: "text-muted-foreground" },
  vaultLocked: { label: "Vault locked", className: "border-tier-medium/40 text-tier-medium" },
  unreachable: { label: "Unreachable", className: "border-tier-critical/40 text-tier-critical" },
  loginFailed: { label: "Login failed", className: "border-tier-critical/40 text-tier-critical" },
  hostKey: { label: "Host key", className: "border-tier-critical/40 text-tier-critical" },
  paused: { label: "Paused", className: "border-tier-medium/40 text-tier-medium" },
  noData: { label: "Not Linux", className: "border-tier-medium/40 text-tier-medium" },
  error: { label: "Error", className: "border-tier-critical/40 text-tier-critical" },
};

export function guestStateLabel(state: GuestState) {
  return STATE[state].label;
}

export function GuestStatusBadge({
  status,
  onCheckKey,
}: {
  status: GuestStatus;
  /** Opens a terminal to the host, which asks about its key. */
  onCheckKey?: (sessionId: string) => void;
}) {
  const { label, className } = STATE[status.state];
  if (status.state === "hostKey" && onCheckKey) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            className={cn("whitespace-nowrap", className)}
            onClick={(e) => {
              e.stopPropagation();
              onCheckKey(status.sessionId);
            }}
          >
            <ShieldQuestionIcon data-icon="inline-start" />
            Check host key
          </Button>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          {status.message ? `${status.message} ` : ""}Opens a terminal, which shows the key to trust.
        </TooltipContent>
      </Tooltip>
    );
  }
  const detail = [
    status.message,
    status.retryInSecs != null && status.retryInSecs > 0 ? `Next try in ${status.retryInSecs} s.` : null,
  ]
    .filter(Boolean)
    .join(" ");
  const badge = (
    <Badge variant="outline" className={cn("whitespace-nowrap", className)}>
      {label}
      {detail && <span className="sr-only">: {detail}</span>}
    </Badge>
  );
  if (!detail) return badge;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          {badge}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{detail}</TooltipContent>
    </Tooltip>
  );
}
