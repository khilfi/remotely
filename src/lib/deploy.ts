// VM-21, VM-22, VM-10: the Deploy and Clone dialogs' texts, their QL-08 reasons, and the per-VM steps of a deploy's
// job as its events arrive, as pure functions (tested in deploy.test.ts). The core checks everything again.

import type { DeployCheck, JobEvent, JobStatus, JobTarget, TargetStatus } from "./api.ts";
import { MAX_DEPLOY_COUNT } from "./catalog.ts";

/** VM-10: the Clone dialog's naming pattern: `{template}` is each VM's own name. */
export const DEFAULT_CLONE_PATTERN = "{template}-clone";

/** A whole number from 1 to the deploy limit, or null. */
export function parseCount(text: string): number | null {
  const t = text.trim();
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t);
  return n >= 1 && n <= MAX_DEPLOY_COUNT ? n : null;
}

/** VM-22: package names from what was typed, split on commas and spaces, each once. */
export function parsePackages(text: string): string[] {
  const out: string[] = [];
  for (const word of text.split(/[\s,]+/)) {
    const name = word.trim();
    if (name && !out.includes(name)) out.push(name);
  }
  return out;
}

export function packagesText(packages: string[]): string {
  return packages.join(", ");
}

/** QL-08: why Deploy (or Clone) can't be pressed yet, or null when it can. */
export function deployReason(state: {
  busy: boolean;
  count: number | null;
  checking: boolean;
  check: DeployCheck | null;
  error: string | null;
}): string | null {
  if (state.busy) return "Submitting…";
  if (state.count === null) return `The count is a whole number, 1 to ${MAX_DEPLOY_COUNT}`;
  if (state.error) return state.error;
  if (state.checking || !state.check) return "Checking…";
  const problem = state.check.problems[0];
  if (problem) return problem.message;
  const refusal = state.check.preview?.refusals[0];
  if (refusal) return refusal;
  return null;
}

/** One VM of a deploy's job, as its events tell it. */
export interface DeployStep {
  /** The target's key (`new-vm/vmware/web-1`). */
  target: string;
  name: string;
  status: TargetStatus | "waiting";
  /** Why it failed or was skipped. */
  message: string | null;
  /** What it came to: its folder, IP, session... */
  note: string | null;
  durationMs: number | null;
}

export interface DeployProgress {
  jobId: string;
  /** null until the job ends. */
  finished: JobStatus | null;
  /** In a countdown (High): it can still be cancelled before anything is made. */
  countdownUntil: string | null;
  steps: DeployStep[];
}

/** A job's progress before any event: every VM waiting. */
export function startProgress(jobId: string, vms: { name: string; target: string }[]): DeployProgress {
  return {
    jobId,
    finished: null,
    countdownUntil: null,
    steps: vms.map((vm) => ({
      target: vm.target,
      name: vm.name,
      status: "waiting",
      message: null,
      note: null,
      durationMs: null,
    })),
  };
}

/** The new VM target key the core uses: `new-vm/<hypervisor>/<name>`. */
export function newVmKey(hypervisor: string, name: string): string {
  return `new-vm/${hypervisor}/${name}`;
}

/** Progress after `event`; events of other jobs change nothing. */
export function applyJobEvent(progress: DeployProgress, event: JobEvent): DeployProgress {
  if (event.jobId !== progress.jobId) return progress;
  const step = (target: string, change: Partial<DeployStep>) => ({
    ...progress,
    steps: progress.steps.map((s) => (s.target === target ? { ...s, ...change } : s)),
  });
  switch (event.event) {
    case "countdown":
      return { ...progress, countdownUntil: event.until };
    case "started":
      return { ...progress, countdownUntil: null };
    case "targetStarted":
      return step(event.target, { status: "running" });
    case "targetFinished":
      return step(event.target, {
        status: event.status,
        message: event.message,
        note: withoutName(event.note ?? null, event.name),
        durationMs: event.durationMs,
      });
    case "finished":
      return {
        ...progress,
        finished: event.status,
        countdownUntil: null,
        // Targets the job never reached (a cancel before their turn) read as cancelled.
        steps: progress.steps.map((s) =>
          s.status === "waiting" || s.status === "running"
            ? { ...s, status: event.status === "cancelled" ? "cancelled" : s.status }
            : s,
        ),
      };
    default:
      return progress;
  }
}

/** The job's note names its VM first (`web-1: ...`), which the step shows already. */
function withoutName(note: string | null, name: string): string | null {
  return note?.startsWith(`${name}: `) ? note.slice(name.length + 2) : note;
}

/**
 * Progress after reading the job's targets from the journal: what the events said, and what was sent before the
 * dialog followed the job (a quick step's start and end).
 */
export function applyJobTargets(progress: DeployProgress, targets: JobTarget[]): DeployProgress {
  return {
    ...progress,
    steps: progress.steps.map((s) => {
      const t = targets.find((x) => x.targetKey === s.target);
      if (!t || t.status === "pending") return s;
      return {
        ...s,
        status: t.status,
        message: t.error ?? s.message,
        note: t.output ?? s.note,
        durationMs: t.durationMs ?? s.durationMs,
      };
    }),
  };
}

/** `2 of 3 made`, `Waiting to start`, `Done: 2 made, 1 failed`. */
export function progressSummary(progress: DeployProgress): string {
  const made = progress.steps.filter((s) => s.status === "succeeded").length;
  const failed = progress.steps.filter((s) => s.status === "failed" || s.status === "unknown").length;
  const cancelled = progress.steps.filter((s) => s.status === "cancelled" || s.status === "skipped").length;
  const total = progress.steps.length;
  if (progress.finished) {
    const parts = [`${made} made`];
    if (failed) parts.push(`${failed} failed`);
    if (cancelled) parts.push(`${cancelled} cancelled`);
    return `Done: ${parts.join(", ")}`;
  }
  if (progress.countdownUntil) return "Starts after the countdown; nothing is made yet";
  if (progress.steps.every((s) => s.status === "waiting")) return "Waiting to start";
  return `${made} of ${total} made`;
}

/** What a step says beside its name. */
export function stepText(step: DeployStep): string {
  switch (step.status) {
    case "waiting":
      return "Waiting";
    case "pending":
      return "Waiting";
    case "running":
      return "Making it…";
    case "succeeded":
      return step.note ?? "Made";
    case "failed":
      return step.message ? `Failed: ${step.message}. What it made was removed.` : "Failed";
    case "cancelled":
      return "Cancelled; what it made was removed";
    case "skipped":
      return step.message ?? "Not started";
    case "unknown":
      return step.message ?? "Its outcome is unknown";
  }
}

/** `120 GB`: what the preview says a VM or a deploy may take. */
export function bytesText(bytes: number | null): string {
  if (bytes === null) return "unknown";
  const gib = bytes / 2 ** 30;
  if (gib >= 1024) return `${(gib / 1024).toFixed(gib >= 10 * 1024 ? 0 : 1)} TB`;
  if (gib >= 1) return `${gib.toFixed(gib >= 10 ? 0 : 1)} GB`;
  return `${Math.max(1, Math.round(bytes / 2 ** 20))} MB`;
}

/** VM-10: why the picked VMs can't be cloned, before the core is asked. */
export function cloneReason(vms: { name: string; powerState: string; hypervisor: string }[]): string | null {
  if (vms.length === 0) return "Pick the VMs to clone";
  if (vms.length > MAX_DEPLOY_COUNT) return `Clone at most ${MAX_DEPLOY_COUNT} VMs at a time`;
  if (new Set(vms.map((v) => v.hypervisor)).size > 1) return "Clone the VMs of one hypervisor at a time";
  const on = vms.find((v) => v.powerState === "running" || v.powerState === "paused" || v.powerState === "suspended");
  if (on) return `Shut ${on.name} down first: a clone copies a VM that is off`;
  return null;
}
