// QL-25 notification centre: the history of what notified while the app runs (MO-07 alerts, QL-17 terminal alerts,
// QL-07 long commands, jobs, an update, toasts worth keeping), newest first, grouped by day and by what each is about.
// Each entry opens what it is about; opening the centre marks nothing read until an entry is opened or "Mark all read"
// is pressed. The text was redacted by the core, and the window's own masking covers it while presenting (FD-03).
// UX-04 (0.6.0): one line under the title, the rest in its "?"; the toolbar's buttons are ghost.

import { useEffect, useMemo, useState } from "react";
import {
  BellIcon,
  CheckCheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CircleAlertIcon,
  CircleCheckIcon,
  InfoIcon,
  Trash2Icon,
  TriangleAlertIcon,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import type { AppLink } from "@/lib/links";
import { linkLabel } from "@/lib/links";
import {
  entryLink,
  groupNotifications,
  timeAgo,
  type AppNotification,
  type NotificationGroup,
  type NotificationLevel,
} from "@/lib/notifications";
import { clearNotifications, markNotificationsRead, useNotifications } from "@/lib/notifications-store";
import { cn } from "@/lib/utils";

const LEVEL: Record<NotificationLevel, { icon: LucideIcon; className: string; label: string }> = {
  info: { icon: InfoIcon, className: "text-muted-foreground", label: "Information" },
  success: { icon: CircleCheckIcon, className: "text-success", label: "Done" },
  warning: { icon: TriangleAlertIcon, className: "text-status-warning", label: "Warning" },
  error: { icon: CircleAlertIcon, className: "text-status-critical", label: "Problem" },
};

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onOpenLink: (link: AppLink) => void;
}

export function NotificationCentre({ open, onOpenChange, onOpenLink }: Props) {
  const { entries, unread } = useNotifications();
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // "5 min ago" moves on while the centre shows.
  useEffect(() => {
    if (!open) return;
    const first = window.setTimeout(() => setNow(Date.now()), 0);
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [open]);

  const days = useMemo(() => groupNotifications(entries, now, unreadOnly), [entries, now, unreadOnly]);

  function openEntry(entry: AppNotification, group?: NotificationGroup) {
    const ids = (group?.entries ?? [entry]).filter((e) => !e.read).map((e) => e.id);
    markNotificationsRead(ids);
    const link = entryLink(entry);
    if (link) {
      onOpenChange(false);
      onOpenLink(link);
    }
  }

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Notifications</SheetTitle>
          <SheetDescription className="flex items-center gap-1">
            Since Remotely started.
            <HelpTip topic="notifications" />
          </SheetDescription>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="ghost" disabled={unread === 0} onClick={() => markNotificationsRead(null)}>
              <CheckCheckIcon /> Mark all read
            </Button>
            <Button size="sm" variant="ghost" disabled={entries.length === 0} onClick={() => clearNotifications(null)}>
              <Trash2Icon /> Clear
            </Button>
            <div className="ml-auto flex items-center gap-2">
              <Switch id="notifications-unread" checked={unreadOnly} onCheckedChange={setUnreadOnly} />
              <Label htmlFor="notifications-unread" className="font-normal">
                Unread only
              </Label>
            </div>
          </div>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-auto px-4 pb-4">
          {days.length === 0 && (
            <EmptyState
              bordered={false}
              icon={BellIcon}
              title={entries.length === 0 ? "No notifications yet" : "Nothing unread"}
              description={
                entries.length === 0
                  ? "Alerts, finished jobs and long commands show here as they happen."
                  : "Turn off Unread only to see the rest."
              }
            />
          )}
          {days.map((day) => (
            <section key={day.label} className="mb-4" aria-label={day.label}>
              <h3 className="mb-1.5 text-xs font-medium text-muted-foreground">{day.label}</h3>
              <ul className="flex flex-col gap-1">
                {day.groups.map((group) => (
                  <GroupRow
                    key={`${group.key}:${group.latest.id}`}
                    group={group}
                    now={now}
                    expanded={expanded.has(group.key)}
                    onToggle={() => toggle(group.key)}
                    onOpen={openEntry}
                  />
                ))}
              </ul>
            </section>
          ))}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function GroupRow({
  group,
  now,
  expanded,
  onToggle,
  onOpen,
}: {
  group: NotificationGroup;
  now: number;
  expanded: boolean;
  onToggle: () => void;
  onOpen: (entry: AppNotification, group?: NotificationGroup) => void;
}) {
  const more = group.entries.length - 1;
  return (
    <li className="rounded-md border">
      <EntryRow entry={group.latest} now={now} onOpen={() => onOpen(group.latest, group)} unread={group.unread > 0} />
      {more > 0 && (
        <button
          type="button"
          className="flex w-full items-center gap-1 border-t px-3 py-1 text-left text-xs text-muted-foreground hover:bg-accent"
          aria-expanded={expanded}
          onClick={onToggle}
        >
          {expanded ? <ChevronDownIcon className="size-3.5" /> : <ChevronRightIcon className="size-3.5" />}
          {more === 1 ? "1 earlier" : `${more} earlier`}
          {group.unread > 1 && ` (${group.unread} unread)`}
        </button>
      )}
      {expanded && more > 0 && (
        <ul className="border-t">
          {group.entries.slice(1).map((entry) => (
            <li key={entry.id} className="border-b last:border-b-0">
              <EntryRow entry={entry} now={now} onOpen={() => onOpen(entry)} unread={!entry.read} nested />
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

function EntryRow({
  entry,
  now,
  onOpen,
  unread,
  nested = false,
}: {
  entry: AppNotification;
  now: number;
  onOpen: () => void;
  unread: boolean;
  nested?: boolean;
}) {
  const level = LEVEL[entry.level];
  const link = entryLink(entry);
  return (
    <button
      type="button"
      className={cn(
        "flex w-full items-start gap-2.5 px-3 py-2 text-left hover:bg-accent focus-visible:bg-accent",
        nested && "pl-8",
      )}
      title={link ? linkLabel(link) : undefined}
      onClick={onOpen}
    >
      <level.icon className={cn("mt-0.5 size-4 shrink-0", level.className)} aria-label={level.label} />
      <span className="min-w-0 flex-1">
        <span className={cn("block text-sm break-words", unread && "font-medium")}>{entry.title}</span>
        {entry.body && (
          <span className="line-clamp-3 block text-xs break-words whitespace-pre-line text-muted-foreground">
            {entry.body}
          </span>
        )}
      </span>
      <span className="flex shrink-0 flex-col items-end gap-1">
        <time className="text-xs text-muted-foreground" dateTime={entry.at}>
          {timeAgo(Date.parse(entry.at), now)}
        </time>
        {unread && <span className="size-2 rounded-full bg-primary" aria-label="Unread" />}
      </span>
    </button>
  );
}
