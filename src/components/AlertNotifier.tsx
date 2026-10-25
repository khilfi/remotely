// MO-07: the Windows notification for alerts, whatever page shows. The core says which fired alerts should notify (the
// rule notifies, and not again for that target within its half-hour cooldown); the alerts of one round make one
// notification (notificationText), and its text is masked while presenting (FD-03, maskedOutside), like QL-07's. It
// renders nothing.

import { useEffect } from "react";
import { notificationText } from "@/lib/alerts";
import { dashboardApi, type Alert } from "@/lib/dashboard-api";
import { maskedOutside } from "@/lib/presentation-state";

/** Alerts that fire this close together are one notification. */
const GATHER_MS = 1_000;

export function AlertNotifier() {
  useEffect(() => {
    let pending: Alert[] = [];
    let timer: number | undefined;
    const unlisten = dashboardApi.onAlertEvent((event) => {
      if (event.kind !== "fired" || !event.notify) return;
      pending.push(event.alert);
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        const text = notificationText(pending);
        pending = [];
        if (!text) return;
        dashboardApi.notifyAlert(maskedOutside(text.title), maskedOutside(text.body)).catch(() => undefined);
      }, GATHER_MS);
    });
    return () => {
      window.clearTimeout(timer);
      void unlisten.then((stop) => stop());
    };
  }, []);
  return null;
}
