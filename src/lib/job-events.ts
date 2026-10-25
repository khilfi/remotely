// P6, VM-01: which job events and setting changes make the app render or read something again, as pure functions
// (tested in job-events.test.ts). A job sends many events (queued, countdown, started, one or two per target,
// finished); only a job queued or ended changes App's state. Progress is Activity's own business while it shows, and a
// finished job refreshes only the page whose things it may have changed (its `scope`).

import type { JobEvent } from "./api.ts";

/** Activity's job list gains or ends a job: App bumps the version Activity reads again on. */
export function changesJobList(event: JobEvent): boolean {
  return event.event === "queued" || event.event === "finished";
}

/**
 * While Activity shows: a job's progress that changes what it lists (a countdown, a start, a target's result), read
 * again after a moment rather than once per event.
 */
export function progressesJob(event: JobEvent): boolean {
  return (
    event.event === "countdown" ||
    event.event === "started" ||
    event.event === "targetFinished" ||
    event.event === "stillRunning"
  );
}

/** How long Activity waits after a job's progress before it reads the list again (more progress meanwhile joins in). */
export const PROGRESS_READ_MS = 1000;

/** VM-01: a finished job that may have changed VMs (power, snapshots, protection): the VM list is refreshed. */
export function refreshesVms(event: JobEvent): boolean {
  return event.event === "finished" && event.scope === "vms";
}

/** CT-01: a finished container action: the Containers page reads its host again. */
export function refreshesContainers(event: JobEvent): boolean {
  return event.event === "finished" && event.scope === "containers";
}

/** What a save on the Settings page changed, so only what depends on it is read again. */
export type SettingsChange = "vmrun" | "vboxmanage" | "scanFolders" | "docker" | "updates" | "other";

/** VM-01: settings that change what an inventory refresh finds. */
export function changesVmList(change: SettingsChange): boolean {
  return change === "vmrun" || change === "vboxmanage" || change === "scanFolders";
}

/** CT-02: settings that change the Containers page's hosts (this PC's docker.exe). */
export function changesContainerHosts(change: SettingsChange): boolean {
  return change === "docker";
}

/** The sidebar's version and Workstation/VirtualBox status (app_info). */
export function changesAppInfo(change: SettingsChange): boolean {
  return change === "vmrun" || change === "vboxmanage";
}

/** FD-14: an update check runs again (the checks turned on or off, the token added, replaced or removed). */
export function changesUpdates(change: SettingsChange): boolean {
  return change === "updates";
}

/**
 * VM-01: whether a page's refresh is due: it shows, and the key it last refreshed for (`done`) is not the one wanted
 * now. A hidden page lets its key move on and refreshes once, when it shows again; showing it again without a change
 * refreshes nothing.
 */
export function refreshDue(active: boolean, wanted: string, done: string | null): boolean {
  return active && wanted !== done;
}
