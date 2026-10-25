// Typed wrappers over the schedules' IPC commands in src-tauri/src/schedules.rs (VM-14, VM-27). Types mirror the serde
// shapes in crates/core/src/schedules (mod.rs, spec.rs, timing.rs, chains.rs). Like api.ts, every answer and event goes
// past the presentation masker (FD-03).

import { invoke, listen, type ApprovalAnswers, type ApprovalRequest, type Tier } from "@/lib/api";

export type Day = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";

export type Timing =
  | { kind: "hourly"; minute: number }
  | { kind: "daily"; at: string }
  | { kind: "weekly"; days: Day[]; at: string }
  | { kind: "idle"; minutes: number; cpuBelowPct: number };

export type ScheduleAction =
  | { kind: "snapshot"; keep: number | null }
  | { kind: "start" }
  | { kind: "stop" }
  | { kind: "suspend" }
  | { kind: "resume" };

/** A VM by its key (.vmx path or VirtualBox UUID), or every VM with a tag. */
export type ScheduleTarget = { kind: "vm"; vmKey: string } | { kind: "tag"; tag: string };

export interface ScheduleSpec {
  action: ScheduleAction;
  targets: ScheduleTarget[];
  timing: Timing;
}

export interface ScheduleInput {
  id: string | null;
  name: string;
  spec: ScheduleSpec;
}

export type ScheduleState = "active" | "paused" | "needsApproval";
export type RunOutcome = "running" | "succeeded" | "partiallyFailed" | "failed" | "missed" | "skipped" | "paused";

export interface PlannedRun {
  /** RFC 3339, UTC. */
  at: string;
  /** What daylight saving does to this run, in words. */
  note: string | null;
}

export interface ScheduleRun {
  id: string;
  dueAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  outcome: RunOutcome;
  detail: string | null;
  jobIds: string[];
  approvalId: string | null;
}

export interface TargetView {
  target: ScheduleTarget;
  /** The VM's name, or the tag. */
  name: string;
  /** The VMs it stands for now. */
  vms: number;
}

export interface ApprovalInfo {
  id: string;
  tier: Tier;
  grantedAt: string;
  reason: string | null;
  safetySnapshot: boolean;
}

export interface ScheduleView {
  id: string;
  name: string;
  spec: ScheduleSpec;
  action: string;
  when: string;
  targets: TargetView[];
  state: ScheduleState;
  stateReason: string | null;
  nextRun: PlannedRun | null;
  lastRun: ScheduleRun | null;
  approval: ApprovalInfo | null;
  /** What would make its next run ask again. */
  asksAgain: string[];
  /** VM-27: chains of its VMs past the limits. */
  chainWarnings: string[];
  running: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SaveOutcome {
  schedule: ScheduleView;
  /** The approval to answer; null when nothing is asked (Low) or none is needed. */
  approval: ApprovalRequest | null;
}

export interface SchedulePreview {
  summary: string;
  when: string;
  nextRuns: PlannedRun[];
  vms: string[];
  warnings: string[];
}

export interface ChainLimits {
  maxDepth: number;
  maxSizeGb: number;
}

export interface ChainInfo {
  vmKey: string;
  name: string;
  depth: number | null;
  sizeBytes: number | null;
  snapshots: number | null;
  warnings: string[];
  error: string | null;
}

export interface VmSchedules {
  schedules: ScheduleView[];
  chain: ChainInfo | null;
  limits: ChainLimits;
}

/** What the scheduler did; R10's notification centre may list them too. */
export type ScheduleEvent =
  | { event: "changed"; scheduleId: string }
  | { event: "runStarted"; scheduleId: string; runId: string; name: string }
  | {
      event: "runFinished";
      scheduleId: string;
      runId: string;
      name: string;
      outcome: RunOutcome;
      detail: string | null;
    }
  | { event: "missed"; scheduleId: string; runId: string; name: string; detail: string }
  | { event: "skipped"; scheduleId: string; runId: string; name: string; detail: string }
  | { event: "needsApproval"; scheduleId: string; name: string; reason: string };

export const schedulesApi = {
  list: () => invoke<ScheduleView[]>("schedules_list"),
  get: (id: string) => invoke<ScheduleView>("schedule_get", { id }),
  runs: (id: string, limit?: number) => invoke<ScheduleRun[]>("schedule_runs", { id, limit: limit ?? null }),
  preview: (input: ScheduleInput) => invoke<SchedulePreview>("schedule_preview", { input }),
  /** New content returns its approval to answer. Audited. */
  save: (input: ScheduleInput) => invoke<SaveOutcome>("schedule_save", { input }),
  /** The answers to a schedule's approval; returns the schedule. */
  approve: (requestId: string, answers: ApprovalAnswers) =>
    invoke<ScheduleView>("schedule_approve", { requestId, answers }),
  askApproval: (id: string) => invoke<SaveOutcome>("schedule_ask_approval", { id }),
  pause: (id: string) => invoke<ScheduleView>("schedule_pause", { id }),
  resume: (id: string) => invoke<SaveOutcome>("schedule_resume", { id }),
  remove: (id: string) => invoke<void>("schedule_delete", { id }),
  forVm: (vmKey: string) => invoke<VmSchedules>("schedules_for_vm", { vmKey }),
  chainLimits: () => invoke<ChainLimits>("schedule_chain_limits"),
  setChainLimits: (limits: ChainLimits) => invoke<ChainLimits>("schedule_chain_limits_set", { limits }),
  onEvent: (handler: (event: ScheduleEvent) => void) =>
    listen<ScheduleEvent>("schedules://event", (e) => handler(e.payload)),
};
