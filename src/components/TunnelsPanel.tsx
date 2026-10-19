// SS-07: the current terminal's tunnels, from the toolbar. The session's saved port forwards, each with its state
// (stopped, asking, opening, listening where and how busy, waiting for a reconnect, failed and why), started and
// stopped by hand here. Starting goes through the approval flow: the page shows the dialog when one is needed.
// Forwards are added and edited with the session (Sessions page).

import { useEffect, useState } from "react";
import { CableIcon, CopyIcon } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type ApprovalRequest, type TunnelInfo } from "@/lib/api";
import type { PaneSession, PaneSnapshot } from "@/lib/terminal-session";
import { forwardText, isLoopback, liveTunnels, tunnelStateText } from "@/lib/tunnels";
import { cn } from "@/lib/utils";

const STATE_TONE: Record<TunnelInfo["state"]["state"], string> = {
  stopped: "text-muted-foreground",
  asking: "text-tier-medium",
  opening: "text-muted-foreground",
  listening: "text-success",
  waiting: "text-tier-medium",
  failed: "text-destructive",
};

/** QL-08: why a tunnel can't be started now, or null. */
function startReason(snapshot: PaneSnapshot): string | null {
  if (!snapshot.sessionId) return "Only saved sessions have port forwards.";
  if (snapshot.status.state !== "connected") return "Connect the terminal first: a tunnel rides its connection.";
  return null;
}

export function TunnelsButton({
  pane,
  snapshot,
  name,
  onApproval,
}: {
  pane: PaneSession | undefined;
  snapshot: PaneSnapshot;
  /** How the terminal is named, for the panel's title. */
  name: string;
  /** A tunnel needs the approval dialog. */
  onApproval: (pane: PaneSession, forwardId: string, request: ApprovalRequest) => void;
}) {
  const [open, setOpen] = useState(false);
  const live = liveTunnels(snapshot.tunnels);
  const label = live > 0 ? `Tunnels: ${live} open on this terminal` : "Tunnels: this session's port forwards";
  const disabledReason = !pane
    ? "Open a terminal first."
    : !snapshot.sessionId
      ? "Only saved sessions have port forwards. Save the connection as a session first."
      : null;

  if (disabledReason) {
    return (
      <WhyDisabled reason={`Tunnels: ${disabledReason}`} className="mb-1">
        <Button variant="ghost" size="icon-sm" aria-label="Tunnels" disabled>
          <CableIcon />
        </Button>
      </WhyDisabled>
    );
  }
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={label}
              className={cn("relative mb-1", (open || live > 0) && "bg-accent")}
            >
              <CableIcon />
              {live > 0 && (
                <span className="absolute -top-0.5 -right-0.5 rounded-full bg-primary px-1 text-[9px] leading-tight text-primary-foreground">
                  {live}
                </span>
              )}
            </Button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent>{label}</TooltipContent>
      </Tooltip>
      <PopoverContent align="end" className="w-[30rem] max-w-[90vw] p-0">
        {open && pane && <TunnelsList pane={pane} snapshot={snapshot} name={name} onApproval={onApproval} />}
      </PopoverContent>
    </Popover>
  );
}

function TunnelsList({
  pane,
  snapshot,
  name,
  onApproval,
}: {
  pane: PaneSession;
  snapshot: PaneSnapshot;
  name: string;
  onApproval: (pane: PaneSession, forwardId: string, request: ApprovalRequest) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ready = pane.terminalId !== null;
  useEffect(() => {
    if (ready) pane.loadTunnels().catch((err) => setError(errorMessage(err)));
  }, [pane, ready]);
  // FD-03: the read-only lock blocks opening tunnels (stopping one stays possible).
  const readOnly = useReadOnlyReason();
  const reason = readOnly ?? startReason(snapshot);
  const tunnels = snapshot.tunnels;

  async function act(forwardId: string, what: () => Promise<void>) {
    setBusy(forwardId);
    setError(null);
    try {
      await what();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  const start = (forwardId: string) =>
    act(forwardId, async () => {
      const started = await pane.startTunnel(forwardId);
      if (started.status === "needsApproval") onApproval(pane, forwardId, started.request);
    });

  const answer = (forwardId: string) =>
    act(forwardId, async () => {
      const request = await pane.tunnelRequest(forwardId);
      if (request) onApproval(pane, forwardId, request);
    });

  return (
    <div className="grid gap-2 p-3">
      <div>
        <p className="text-sm font-medium">Tunnels on {name}</p>
        <p className="text-xs text-muted-foreground">
          The session&apos;s saved port forwards, on this terminal&apos;s connection. Opening one goes through the
          approval flow and is audited; it opens again after a reconnect and closes with the terminal. Add or edit them
          in the session (Sessions page).
        </p>
      </div>
      {tunnels === null ? (
        <p className="text-sm text-muted-foreground">{error ?? "Loading…"}</p>
      ) : tunnels.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          This session has no saved port forwards. Edit it on the Sessions page to add one.
        </p>
      ) : (
        <ul className="grid gap-1.5">
          {tunnels.map((t) => {
            const f = t.forward;
            const state = t.state.state;
            const on = state === "listening" || state === "opening" || state === "waiting";
            const shared = !isLoopback(f.bindAddress);
            return (
              <li key={f.id} className="grid gap-1 rounded-md border p-2">
                <div className="flex items-start gap-2">
                  <div className="grid min-w-0 flex-1 gap-0.5">
                    <span className="truncate text-sm font-medium" title={forwardText(f)}>
                      {f.label ?? forwardText(f)}
                    </span>
                    {f.label && <span className="truncate font-mono text-xs">{forwardText(f)}</span>}
                    <span className={cn("text-xs", STATE_TONE[state])}>{tunnelStateText(t)}</span>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    {shared && (
                      <Badge variant="outline" className="text-tier-medium" title="It listens on a network address">
                        Shared
                      </Badge>
                    )}
                    {f.autoStart && (
                      <Badge variant="secondary" title="Opens when the terminal connects">
                        Auto
                      </Badge>
                    )}
                    {t.state.state === "listening" && (
                      <Button
                        variant="ghost"
                        size="icon-xs"
                        aria-label="Copy where it listens"
                        title="Copy where it listens"
                        onClick={() => {
                          const at = t.state.state === "listening" ? t.state.at.replace(/ on the host$/, "") : "";
                          void navigator.clipboard?.writeText(at).then(
                            () => toast.success(`Copied ${at}`),
                            () => undefined,
                          );
                        }}
                      >
                        <CopyIcon />
                      </Button>
                    )}
                    {state === "asking" ? (
                      <Button size="xs" variant="outline" disabled={busy !== null} onClick={() => void answer(f.id)}>
                        Answer…
                      </Button>
                    ) : on ? (
                      <Button
                        size="xs"
                        variant="outline"
                        disabled={busy !== null}
                        onClick={() => void act(f.id, () => pane.stopTunnel(f.id))}
                      >
                        Stop
                      </Button>
                    ) : (
                      <WhyDisabled reason={reason ?? (busy !== null ? "Wait for the last change to finish." : null)}>
                        <Button
                          size="xs"
                          variant="outline"
                          disabled={reason !== null || busy !== null || !t.saved}
                          onClick={() => void start(f.id)}
                        >
                          Start
                        </Button>
                      </WhyDisabled>
                    )}
                  </div>
                </div>
                {t.lastError && (
                  <p className="text-xs text-muted-foreground">Last connection through it: {t.lastError}</p>
                )}
                {t.changed && (
                  <p className="text-xs text-tier-medium">Edited since it opened: stop and start it to use the edit.</p>
                )}
                {!t.saved && <p className="text-xs text-muted-foreground">No longer saved with the session.</p>}
              </li>
            );
          })}
        </ul>
      )}
      {error && tunnels !== null && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
