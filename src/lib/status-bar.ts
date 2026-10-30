// QL-22 status bar, the pure part (tested in status-bar.test.ts): the vault's lock countdown, the open jobs, the open
// tunnels and alerts, and the update state, each as a few words and a tone. The bar itself is StatusBar.tsx. Nothing
// here reads anything: the vault's answers (including App's activity pings), job events, the panes' tunnel events and
// alert events feed it.

import type { JobEvent, JobStatus, JobSummary, UpdateCheck, VaultInfo } from "./api.ts";
import type { OpenTunnel } from "./open-tunnels.ts";
import { tunnelStateText } from "./tunnels.ts";

export type Tone = "normal" | "good" | "warning" | "danger" | "muted";

export interface StatusText {
  label: string;
  /** The tooltip: what it means and what a click opens. */
  title: string;
  tone: Tone;
}

/** Under this many seconds the countdown turns amber. */
export const LOCK_WARNING_SECS = 60;

/** `14:05`, `0:42`; an hour or more as `1:02:03`. */
export function formatCountdown(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rest = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${rest}` : `${m}:${rest}`;
}

// ---- The vault's countdown ----

/** When the vault locks (ms since 1970) as the core last said, or null while it is not unlocked. */
let lockAt: number | null = null;
const vaultListeners = new Set<() => void>();

/** A vault answer arrived (its status, an unlock, an activity ping): the countdown starts from what it says. */
export function reportVault(info: VaultInfo | null, nowMs = Date.now()) {
  const next =
    info?.status === "unlocked" && info.locksInSecs !== null && info.locksInSecs !== undefined
      ? nowMs + info.locksInSecs * 1000
      : null;
  if (next === lockAt) return;
  lockAt = next;
  for (const listener of vaultListeners) listener();
}

export function vaultLockAt(): number | null {
  return lockAt;
}

export function subscribeVault(listener: () => void): () => void {
  vaultListeners.add(listener);
  return () => {
    vaultListeners.delete(listener);
  };
}

/** Seconds left until the lock, or null. */
export function secondsLeft(at: number | null, nowMs: number): number | null {
  return at === null ? null : Math.max(0, Math.ceil((at - nowMs) / 1000));
}

export function vaultText(info: VaultInfo | null, secsLeft: number | null): StatusText {
  switch (info?.status) {
    case "unlocked": {
      const minutes = info.idleLockMinutes;
      if (secsLeft === null)
        return { label: "Vault unlocked", title: "The vault is unlocked. Open the Vault page.", tone: "good" };
      return {
        label: `Vault locks in ${formatCountdown(secsLeft)}`,
        title: `Locks after ${minutes} minutes without typing or clicking in Remotely. Open the Vault page.`,
        tone: secsLeft <= LOCK_WARNING_SECS ? "warning" : "good",
      };
    }
    case "locked":
      return {
        label: "Vault locked",
        title: "Sessions that log in with it ask to unlock it first. Open the Vault page.",
        tone: "muted",
      };
    case "notSetUp":
      return { label: "No vault yet", title: "Set up the vault on the Vault page.", tone: "muted" };
    default:
      return { label: "Vault", title: "Open the Vault page.", tone: "muted" };
  }
}

// ---- Jobs ----

const OPEN_STATUSES: readonly JobStatus[] = ["queued", "countdown", "running"];

/**
 * The jobs open now (queued, counting down or running), from a first read of the recent jobs and then their events.
 * MultiExec lines count too while they run: they are jobs on the bus.
 */
export class OpenJobs {
  private open = new Map<string, string>();

  /** The recent jobs as Activity lists them. */
  seed(jobs: readonly JobSummary[]) {
    for (const job of jobs) {
      if (OPEN_STATUSES.includes(job.status)) this.open.set(job.id, job.summary);
      else this.open.delete(job.id);
    }
  }

  /** True when the count or the summaries changed. */
  note(event: JobEvent): boolean {
    if (event.event === "queued") {
      this.open.set(event.jobId, event.summary);
      return true;
    }
    if (event.event === "finished") return this.open.delete(event.jobId);
    return false;
  }

  get count() {
    return this.open.size;
  }

  get summaries(): string[] {
    return [...this.open.values()];
  }
}

export function jobsText(count: number, summaries: readonly string[]): StatusText | null {
  if (count === 0) return null;
  const shown = summaries.slice(0, 5).join("\n");
  const more = summaries.length > 5 ? `\nand ${summaries.length - 5} more` : "";
  return {
    label: count === 1 ? "1 job running" : `${count} jobs running`,
    title: `${shown}${more}\nOpen Activity to follow or cancel them.`,
    tone: "normal",
  };
}

// ---- Tunnels ----

export function tunnelsText(tunnels: readonly OpenTunnel[], sessionName: (id: string) => string): StatusText | null {
  if (tunnels.length === 0) return null;
  const lines = tunnels
    .slice(0, 6)
    .map((t) => `${sessionName(t.sessionId)}: ${t.tunnel.forward.label ?? tunnelStateText(t.tunnel)}`);
  const more = tunnels.length > 6 ? `\nand ${tunnels.length - 6} more` : "";
  const waiting = tunnels.some((t) => t.tunnel.state.state === "waiting");
  return {
    label: tunnels.length === 1 ? "1 tunnel" : `${tunnels.length} tunnels`,
    title: `${lines.join("\n")}${more}`,
    tone: waiting ? "warning" : "normal",
  };
}

// ---- Alerts ----

export function alertsText(open: number, unacknowledged: number): StatusText | null {
  if (open === 0) return null;
  return {
    label: open === 1 ? "1 alert" : `${open} alerts`,
    title:
      unacknowledged > 0
        ? `${unacknowledged} not acknowledged yet. Open the dashboard's alert list.`
        : "All acknowledged. Open the dashboard's alert list.",
    tone: unacknowledged > 0 ? "danger" : "warning",
  };
}

// ---- Updates ----

/** FD-14: the last check in words; null before the first one. */
export function updateText(check: UpdateCheck | null, problem: string | null): StatusText | null {
  if (problem) return { label: "Updates: problem", title: `${problem} Open Settings, Updates.`, tone: "danger" };
  if (!check) return null;
  switch (check.status) {
    case "available":
      return {
        label: `Update ${check.update.version}`,
        title: `Remotely ${check.update.version} is available (you have ${check.update.currentVersion}). Show it.`,
        tone: "good",
      };
    case "upToDate":
      return { label: "Up to date", title: "Remotely is up to date. Open Settings, Updates.", tone: "muted" };
    case "off":
      return { label: "Update checks off", title: "Update checks are off in Settings, Updates.", tone: "muted" };
    case "rateLimited":
      return {
        label: "Update check later",
        title: "GitHub's limit for update checks is used up; Remotely checks again once it resets.",
        tone: "muted",
      };
    case "vaultLocked":
      return {
        label: "Update check waits",
        title: "The update token is in the vault, which is locked. Remotely checks once it is unlocked.",
        tone: "muted",
      };
    case "tokenNeeded":
      return {
        label: "Updates need a token",
        title: "GitHub doesn't show the releases without a token. Open Settings, Updates.",
        tone: "warning",
      };
  }
}
