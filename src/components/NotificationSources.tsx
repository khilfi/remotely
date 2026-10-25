// QL-25: what the notification centre keeps from the core's own events, whatever page shows: jobs that finished,
// failed or wait for something (the toasts App shows for them), and MO-07 alerts that fired or resolved. The Terminal
// page adds QL-07's finished commands and QL-17's terminal alerts itself, since it knows their tabs; App adds an update
// and the toasts worth keeping. It renders nothing.

import { useEffect } from "react";
import { api } from "@/lib/api";
import { dashboardApi } from "@/lib/dashboard-api";
import { fromAlertEvent, fromScheduleEvent, JobNotes } from "@/lib/notifications";
import { loadNotifications, notify } from "@/lib/notifications-store";
import { schedulesApi } from "@/lib/schedules-api";

export function NotificationSources() {
  useEffect(() => {
    // The history may hold entries from before a reload of the window (QL-15).
    loadNotifications();
    const jobs = new JobNotes();
    const stopJobs = api.onJobEvent((event) => notify(jobs.note(event)));
    const stopAlerts = dashboardApi.onAlertEvent((event) => notify(fromAlertEvent(event)));
    // VM-14, VM-27: runs that did not happen, and schedules that wait for approval again.
    const stopSchedules = schedulesApi.onEvent((event) => notify(fromScheduleEvent(event)));
    return () => {
      void stopJobs.then((stop) => stop());
      void stopAlerts.then((stop) => stop());
      void stopSchedules.then((stop) => stop());
    };
  }, []);
  return null;
}
