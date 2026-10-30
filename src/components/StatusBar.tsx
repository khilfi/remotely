// QL-22 status bar along the bottom of the window: the vault's lock countdown (SS-04's idle lock), the jobs running, the
// open tunnels (SS-07), the open alerts (MO-07) and the update state (FD-14), then the notification centre's bell
// (QL-25). Each opens what it is about. It reads only what the app already has: the vault's answers (App's activity
// pings carry the countdown), job events after one read of the recent jobs, the panes' tunnel events, and the alert
// list's counts after each alert event. Nothing polls; the countdown ticks on its own between the vault's answers.
// UX-04, UX-13 (0.6.0): each item's one or two sentences show in a tooltip, like every icon button's.

import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import {
  BellIcon,
  BellDotIcon,
  CableIcon,
  DownloadIcon,
  KeyRoundIcon,
  ListChecksIcon,
  LockIcon,
  SirenIcon,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api, type SessionRecord, type UpdateCheck, type VaultInfo } from "@/lib/api";
import { dashboardApi } from "@/lib/dashboard-api";
import type { AppLink } from "@/lib/links";
import { unreadBadge } from "@/lib/notifications";
import { useNotifications } from "@/lib/notifications-store";
import { openTunnels, subscribeTunnels } from "@/lib/open-tunnels";
import {
  alertsText,
  jobsText,
  OpenJobs,
  reportVault,
  secondsLeft,
  subscribeVault,
  tunnelsText,
  updateText,
  vaultLockAt,
  vaultText,
  type StatusText,
  type Tone,
} from "@/lib/status-bar";
import { forwardText, tunnelStateText } from "@/lib/tunnels";
import { cn } from "@/lib/utils";

const TONE: Record<Tone, string> = {
  normal: "text-foreground",
  good: "text-success",
  warning: "text-status-warning",
  danger: "text-status-critical",
  muted: "text-muted-foreground",
};

interface Props {
  vault: VaultInfo | null;
  updateCheck: UpdateCheck | null;
  updateProblem: string | null;
  onOpenLink: (link: AppLink) => void;
  onOpenNotifications: () => void;
}

export function StatusBar({ vault, updateCheck, updateProblem, onOpenLink, onOpenNotifications }: Props) {
  const lockAt = useSyncExternalStore(subscribeVault, vaultLockAt);
  const tunnels = useSyncExternalStore(subscribeTunnels, openTunnels);
  const { unread } = useNotifications();
  const [now, setNow] = useState(() => Date.now());
  const jobs = useOpenJobs();
  const alerts = useOpenAlerts();
  const [names, setNames] = useState<Map<string, SessionRecord>>(new Map());

  // The vault's status as App knows it starts the countdown too.
  useEffect(() => reportVault(vault), [vault]);

  // One tick a second while the countdown runs; at zero the core says whether it locked (it may have seen activity
  // this window didn't ping about yet).
  const left = secondsLeft(lockAt, now);
  useEffect(() => {
    if (lockAt === null) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [lockAt]);
  const askedAtZero = useRef(false);
  useEffect(() => {
    if (left !== 0) {
      askedAtZero.current = false;
      return;
    }
    if (askedAtZero.current) return;
    askedAtZero.current = true;
    api.vaultInfo().then(
      (info) => reportVault(info),
      () => undefined,
    );
  }, [left]);

  // Session names for the tunnels' list, read when there are tunnels to name.
  const hasTunnels = tunnels.length > 0;
  useEffect(() => {
    if (!hasTunnels) return;
    api.sessions().then(
      (list) => setNames(new Map(list.map((s) => [s.id, s]))),
      () => undefined,
    );
  }, [hasTunnels]);
  const sessionName = (id: string) => names.get(id)?.name ?? "a session";

  const vaultStatus = vaultText(vault, left);
  const jobsStatus = jobsText(jobs.count, jobs.summaries);
  const tunnelsStatus = tunnelsText(tunnels, sessionName);
  const alertsStatus = alertsText(alerts.open, alerts.unacknowledged);
  const update = updateText(updateCheck, updateProblem);
  const badge = unreadBadge(unread);

  return (
    <footer
      className="flex h-7 shrink-0 items-center gap-1 border-t bg-sidebar px-2 text-xs text-sidebar-foreground"
      aria-label="Status bar"
    >
      <Item
        icon={vault?.status === "unlocked" ? KeyRoundIcon : LockIcon}
        status={vaultStatus}
        onClick={() => onOpenLink({ kind: "vault" })}
        mono={vault?.status === "unlocked" && left !== null}
      />
      {jobsStatus && (
        <Item
          icon={ListChecksIcon}
          status={jobsStatus}
          onClick={() => onOpenLink({ kind: "page", page: "activity" })}
        />
      )}
      {tunnelsStatus && (
        <Popover>
          <PopoverTrigger asChild>
            <StatusButton icon={CableIcon} status={tunnelsStatus} />
          </PopoverTrigger>
          <PopoverContent align="start" className="w-80 p-2">
            <p className="px-2 pb-1.5 text-xs font-medium text-muted-foreground">Open tunnels</p>
            <ul className="flex flex-col gap-0.5">
              {tunnels.map((t) => (
                <li key={`${t.terminalId}:${t.tunnel.forward.id}`}>
                  <button
                    type="button"
                    className="w-full rounded-sm px-2 py-1.5 text-left hover:bg-accent"
                    onClick={() => onOpenLink({ kind: "terminal", terminalId: t.terminalId, tunnels: true })}
                  >
                    <span className="block truncate text-sm">
                      {sessionName(t.sessionId)}
                      {t.tunnel.forward.label ? `: ${t.tunnel.forward.label}` : ""}
                    </span>
                    <span className="block truncate text-xs text-muted-foreground">
                      {forwardText(t.tunnel.forward)} · {tunnelStateText(t.tunnel)}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </PopoverContent>
        </Popover>
      )}
      {alertsStatus && <Item icon={SirenIcon} status={alertsStatus} onClick={() => onOpenLink({ kind: "alerts" })} />}
      <div className="ml-auto flex items-center gap-1">
        {update && (
          <Item
            icon={DownloadIcon}
            status={update}
            onClick={() =>
              onOpenLink(
                updateCheck?.status === "available" ? { kind: "update" } : { kind: "setting", section: "updates" },
              )
            }
          />
        )}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="xs"
              className="relative"
              aria-label={badge ? `Notifications, ${unread} unread` : "Notifications"}
              onClick={onOpenNotifications}
            >
              {badge ? <BellDotIcon /> : <BellIcon />}
              {badge && (
                <span className="rounded-full bg-primary px-1.5 text-[0.65rem] leading-4 font-medium text-primary-foreground">
                  {badge}
                </span>
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent>Notifications</TooltipContent>
        </Tooltip>
      </div>
    </footer>
  );
}

function StatusButton({
  icon: Icon,
  status,
  mono = false,
  ...props
}: { icon: LucideIcon; status: StatusText; mono?: boolean } & React.ComponentProps<"button">) {
  return (
    <Button variant="ghost" size="xs" className={cn("font-normal", TONE[status.tone])} {...props}>
      <Icon />
      <span className={cn(mono && "tabular-nums")}>{status.label}</span>
    </Button>
  );
}

function Item({
  icon,
  status,
  onClick,
  mono,
}: {
  icon: LucideIcon;
  status: StatusText;
  onClick: () => void;
  mono?: boolean;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <StatusButton icon={icon} status={status} mono={mono} onClick={onClick} />
      </TooltipTrigger>
      <TooltipContent className="max-w-xs whitespace-pre-line">{status.title}</TooltipContent>
    </Tooltip>
  );
}

/** The open jobs: one read of the recent ones, then their events. */
function useOpenJobs() {
  const tracker = useMemo(() => new OpenJobs(), []);
  const [, setVersion] = useState(0);
  useEffect(() => {
    let stopped = false;
    api.recentJobs(50).then(
      (list) => {
        if (stopped) return;
        tracker.seed(list);
        setVersion((v) => v + 1);
      },
      () => undefined,
    );
    const unlisten = api.onJobEvent((event) => {
      if (tracker.note(event)) setVersion((v) => v + 1);
    });
    return () => {
      stopped = true;
      void unlisten.then((stop) => stop());
    };
  }, [tracker]);
  return { count: tracker.count, summaries: tracker.summaries };
}

/** MO-07's open alert counts: read once, then after each alert event (at most one read per round of them). */
function useOpenAlerts() {
  const [counts, setCounts] = useState({ open: 0, unacknowledged: 0 });
  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const read = () =>
      dashboardApi.alerts(true, 1).then(
        (list) => {
          if (!stopped) setCounts({ open: list.open, unacknowledged: list.unacknowledged });
        },
        () => undefined,
      );
    void read();
    const unlisten = dashboardApi.onAlertEvent(() => {
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        void read();
      }, 1000);
    });
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      void unlisten.then((stop) => stop());
    };
  }, []);
  return counts;
}
