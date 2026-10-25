// QL-25: the notification centre's list in the window, kept in step with the core's history (which redacts and keeps
// it). Sources call `notify`; the bell and the centre read the list through `useNotifications`. Every change goes to
// the core and the list comes back from it, so a reloaded window (QL-15) shows the same history.

import { useSyncExternalStore } from "react";
import { navigationApi } from "@/lib/navigation-api";
import type { NotificationInput, NotificationList } from "@/lib/notifications";
import { MAX_KEPT } from "@/lib/notifications";

let list: NotificationList = { entries: [], unread: 0 };
const listeners = new Set<() => void>();

function set(next: NotificationList) {
  list = next;
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The list as the core last gave it. */
export function useNotifications(): NotificationList {
  return useSyncExternalStore(subscribe, () => list);
}

/** Reads the history from the core (at start, and after a reload of the window). */
export function loadNotifications() {
  navigationApi.notifications().then(set, (err) => console.warn("notifications not read", err));
}

/** Keeps an entry. Never throws: a notification that can't be kept must not break what notified. */
export function notify(input: NotificationInput | null) {
  if (!input) return;
  navigationApi.addNotification(input).then(
    (entry) => {
      // An entry kept earlier under the same `once` key comes back unchanged.
      if (list.entries.some((e) => e.id === entry.id)) return;
      const entries = [entry, ...list.entries].slice(0, MAX_KEPT);
      set({ entries, unread: entries.filter((e) => !e.read).length });
    },
    (err) => console.warn("notification not kept", err),
  );
}

export function markNotificationsRead(ids: number[] | null) {
  if (ids !== null && ids.length === 0) return;
  navigationApi.markNotificationsRead(ids).then(set, (err) => console.warn("notifications not marked", err));
}

export function clearNotifications(ids: number[] | null) {
  navigationApi.clearNotifications(ids).then(set, (err) => console.warn("notifications not cleared", err));
}
