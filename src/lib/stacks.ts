// VM-08 stacks and VM-26 the capacity planner: the texts, the QL-08 reasons and the grouping the Stacks tab, the
// VMs page and the dialogs share. Pure functions (tested in stacks.test.ts).

import type { PowerState, TargetRef, VmRecord } from "./api.ts";
import { bytesText } from "./deploy.ts";
import { plural } from "./format.ts";
import type {
  DeployCapacity,
  InstanceVm,
  Readiness,
  Stack,
  StackInput,
  StackInstance,
  StackStep,
  StepDetails,
} from "./stacks-api.ts";

export const DEFAULT_READY_TIMEOUT_SECS = 10 * 60;
export const MIN_READY_TIMEOUT_SECS = 30;
export const MAX_READY_TIMEOUT_SECS = 60 * 60;
export const MAX_DELAY_SECS = 60 * 60;
export const MAX_STEPS = 20;
export const MAX_STACK_VMS = 50;

/** What the next step waits for, in words. */
export function readinessText(readiness: Readiness): string {
  switch (readiness.kind) {
    case "none":
      return "nothing";
    case "tools":
      return "the guest tools running";
    case "sshPort":
      return readiness.port === 22 ? "SSH (port 22) open" : `port ${readiness.port} open`;
  }
}

/** "30 s", "2 min", "1 h". */
export function secondsText(secs: number): string {
  if (secs < 120) return `${secs} s`;
  if (secs < 3600 || secs % 3600 !== 0) return `${Math.round(secs / 60)} min`;
  return `${secs / 3600} h`;
}

/** Between this step and the next, in words; empty for the last step or when nothing is waited for. */
export function betweenText(step: Pick<StackStep, "readiness" | "readyTimeoutSecs" | "delaySecs">): string {
  const parts: string[] = [];
  if (step.readiness.kind !== "none") {
    parts.push(`waits up to ${secondsText(step.readyTimeoutSecs)} for ${readinessText(step.readiness)}`);
  }
  if (step.delaySecs > 0) parts.push(`${parts.length ? "then " : ""}waits ${secondsText(step.delaySecs)}`);
  return parts.join(", ");
}

/** `'db' ×1 → 'web' ×2`. */
export function stepsText(steps: { templateName: string | null; count: number }[]): string {
  return steps.map((s) => `${s.templateName ?? "(deleted)"} ×${s.count}`).join(" → ");
}

export function vmCount(input: Pick<StackInput, "steps">): number {
  return input.steps.reduce((n, s) => n + (Number.isFinite(s.count) ? s.count : 0), 0);
}

/** A new step on `templateId`: one VM, nothing waited for. */
export function newStep(templateId: string): StackStep {
  return {
    templateId,
    count: 1,
    readiness: { kind: "none" },
    readyTimeoutSecs: DEFAULT_READY_TIMEOUT_SECS,
    delaySecs: 0,
  };
}

/** Moves step `index` up (-1) or down (+1). */
export function moveStep<T>(steps: T[], index: number, by: -1 | 1): T[] {
  const to = index + by;
  if (to < 0 || to >= steps.length) return steps;
  const out = steps.slice();
  [out[index], out[to]] = [out[to], out[index]];
  return out;
}

/** The editor's own checks before the core is asked (QL-08); null when it can be saved. */
export function stackInputReason(input: StackInput): string | null {
  if (!input.name.trim()) return "Give the stack a name";
  if (input.steps.length === 0) return "Add a launch template";
  if (input.steps.length > MAX_STEPS) return `A stack has at most ${MAX_STEPS} steps`;
  for (const [i, s] of input.steps.entries()) {
    if (!Number.isInteger(s.count) || s.count < 1) return `Step ${i + 1} needs a count of 1 or more`;
    if (
      s.readiness.kind === "sshPort" &&
      !(Number.isInteger(s.readiness.port) && s.readiness.port >= 1 && s.readiness.port <= 65535)
    )
      return `Step ${i + 1}'s port is 1 to 65535`;
    if (!(s.readyTimeoutSecs >= MIN_READY_TIMEOUT_SECS && s.readyTimeoutSecs <= MAX_READY_TIMEOUT_SECS))
      return `Step ${i + 1}'s readiness wait is 30 seconds to an hour`;
    if (!(s.delaySecs >= 0 && s.delaySecs <= MAX_DELAY_SECS)) return `Step ${i + 1}'s delay is at most an hour`;
  }
  const total = vmCount(input);
  if (total > MAX_STACK_VMS) return `A stack makes at most ${MAX_STACK_VMS} VMs; this one makes ${total}`;
  return null;
}

/** QL-08: why a stack can't deploy now. */
export function deployStackReason(stack: Stack, readOnly: string | null): string | null {
  if (readOnly) return readOnly;
  return stack.problems[0] ?? null;
}

const ON: PowerState[] = ["running", "paused"];

/** "3 VMs: 2 running, 1 off". */
export function instanceStateText(instance: Pick<StackInstance, "vms">): string {
  const vms = instance.vms;
  if (vms.length === 0) return "no VMs";
  const running = vms.filter((v) => v.powerState === "running").length;
  const suspended = vms.filter((v) => v.powerState === "suspended").length;
  const gone = vms.filter((v) => v.powerState === null).length;
  const off = vms.length - running - suspended - gone - vms.filter((v) => v.powerState === "paused").length;
  const parts = [
    running && `${running} running`,
    suspended && `${suspended} suspended`,
    off && `${off} off`,
    gone && `${gone} gone`,
  ].filter(Boolean);
  return `${plural(vms.length, "VM")}: ${parts.join(", ")}`;
}

/** QL-08: why the instance can't start (every VM runs), shut down or suspend (none runs). */
export function instancePowerReason(
  instance: Pick<StackInstance, "vms" | "name">,
  op: "start" | "stop" | "suspend",
  readOnly: string | null,
): string | null {
  if (readOnly) return readOnly;
  const live = instance.vms.filter((v) => v.powerState !== null);
  if (live.length === 0) return `${instance.name} has no VM on this PC`;
  if (op === "start") {
    return live.some((v) => !ON.includes(v.powerState as PowerState)) ? null : "Every VM of it is running";
  }
  return live.some((v) => v.powerState === "running") ? null : "No VM of it is running";
}

/** QL-08: why the instance can't be torn down now. */
export function teardownReason(instance: Pick<StackInstance, "vms">, readOnly: string | null): string | null {
  if (readOnly) return readOnly;
  const mine = instance.vms.filter((v) => v.origin === "deploy" && v.powerState !== null);
  if (mine.length === 0) return "No VM its deploy made is left: forget the instance instead";
  const on = mine.find((v) => ON.includes(v.powerState as PowerState));
  if (on) return `${on.name} is running: shut the instance down first`;
  return null;
}

/** The instance's VMs a teardown keeps unless picked: those added by hand. */
export function handAdded(instance: Pick<StackInstance, "vms">): InstanceVm[] {
  return instance.vms.filter((v) => v.origin === "hand" && v.powerState !== null);
}

/** A group of VM rows on the VMs page: an instance and its VMs in the page's order, or the VMs in none. */
export interface VmGroup<T> {
  instance: StackInstance | null;
  vms: T[];
}

/** VM-08: the VMs page's rows grouped by instance (instances in the order given, the rest last); a VM keeps the
 * page's order within its group. Keys match without letter case, as Windows paths do. */
export function groupByInstance<T extends Pick<VmRecord, "vmxPath">>(
  vms: T[],
  instances: StackInstance[],
): VmGroup<T>[] {
  const of = new Map<string, StackInstance>();
  for (const instance of instances) for (const vm of instance.vms) of.set(vm.key.toLowerCase(), instance);
  const groups = new Map<string, VmGroup<T>>();
  const rest: T[] = [];
  for (const vm of vms) {
    const instance = of.get(vm.vmxPath.toLowerCase());
    if (!instance) {
      rest.push(vm);
      continue;
    }
    const group = groups.get(instance.id) ?? { instance, vms: [] };
    group.vms.push(vm);
    groups.set(instance.id, group);
  }
  const ordered = instances.flatMap((i) => {
    const g = groups.get(i.id);
    return g ? [g] : [];
  });
  return rest.length ? [...ordered, { instance: null, vms: rest }] : ordered;
}

/** VM-26: a resource's share used after the deploy, for a meter; null when the total isn't known. */
export function afterPct(after: number, total: number | null): number | null {
  if (!total) return null;
  return (after * 100) / total;
}

/** "28.0 GB" from MB. */
export function gbText(mb: number): string {
  return `${(mb / 1024).toFixed(1)} GB`;
}

/** VM-26: one line for the plan's RAM: "20.0 GB of 32.0 GB after (12.0 GB now)". */
export function ramLine(capacity: DeployCapacity): string {
  const total = capacity.ram.physicalMb === null ? "this PC's RAM (unknown)" : gbText(capacity.ram.physicalMb);
  return `${gbText(capacity.ram.afterMb)} of ${total} after (${gbText(capacity.ram.runningMb)} now)`;
}

/** VM-26: one line for the plan's CPU: "8 vCPUs on 16 logical CPUs after (4 now)". */
export function cpuLine(capacity: DeployCapacity): string {
  const cpus = capacity.cpu.logicalCpus === null ? "?" : String(capacity.cpu.logicalCpus);
  return `${plural(capacity.cpu.afterVcpus, "vCPU")} on ${cpus} logical CPUs after (${capacity.cpu.runningVcpus} now)`;
}

/** VM-26: a drive's line beside its name: "up to 80 GB of 500 GB free (420 GB left)". */
export function driveLine(drive: DeployCapacity["drives"][number]): string {
  if (drive.freeBytes === null) return `up to ${bytesText(drive.addsBytes)} (free space unknown)`;
  const left = drive.freeAfterBytes ?? 0;
  return `up to ${bytesText(drive.addsBytes)} of ${bytesText(drive.freeBytes)} free (${bytesText(left)} left)`;
}

/** VM-26: the suspend suggestion's VMs as power targets. */
export function suspendTargets(capacity: DeployCapacity): TargetRef[] {
  return (capacity.suspend?.vms ?? []).map((vm) => ({ kind: "vm", vmxPath: vm.key }));
}

/** VM-08: a stack command's steps in words, for the approval dialog: "1. db: db-1 — waits up to 5 min for…". */
export function stepLine(step: StepDetails, index: number, last: boolean): string {
  const vms = step.vms.length ? step.vms.join(", ") : "no VM to act on";
  const between = last ? "" : betweenText(step);
  return `${index + 1}. ${step.label}: ${vms}${between ? `; ${between}` : ""}`;
}
