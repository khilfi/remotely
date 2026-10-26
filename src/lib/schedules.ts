// VM-14, VM-27: the schedule editor's form and checks, and the Schedules page's wording (states, run outcomes, QL-08
// reasons for disabled buttons). Pure: no IPC, so `npm test` covers it.

import type {
  Day,
  RunOutcome,
  ScheduleAction,
  ScheduleInput,
  ScheduleState,
  ScheduleTarget,
  ScheduleView,
  Timing,
} from "./schedules-api.ts";

export type ActionKind = ScheduleAction["kind"];
export type TimingKind = Timing["kind"];

export const ACTION_CHOICES: { value: ActionKind; label: string; hint: string }[] = [
  { value: "snapshot", label: "Take a snapshot", hint: "Of each VM; optionally keep only the last few it took." },
  { value: "start", label: "Start", hint: "Powers on the VMs that are off or suspended." },
  { value: "stop", label: "Shut down", hint: "Through the guest (VMware Tools; ACPI on VirtualBox)." },
  { value: "suspend", label: "Suspend", hint: "Saves each running VM's state to disk." },
  { value: "resume", label: "Resume", hint: "Powers on only the suspended VMs; the ones that are off stay off." },
];

export const TIMING_CHOICES: { value: TimingKind; label: string }[] = [
  { value: "hourly", label: "Every hour" },
  { value: "daily", label: "Every day" },
  { value: "weekly", label: "On chosen days" },
  { value: "idle", label: "When idle (auto-suspend)" },
];

export const DAYS: { value: Day; label: string }[] = [
  { value: "mon", label: "Mon" },
  { value: "tue", label: "Tue" },
  { value: "wed", label: "Wed" },
  { value: "thu", label: "Thu" },
  { value: "fri", label: "Fri" },
  { value: "sat", label: "Sat" },
  { value: "sun", label: "Sun" },
];

/** The core's limits (schedules/spec.rs, timing.rs). */
export const MAX_KEEP = 100;
export const MAX_NAME = 80;
export const MIN_IDLE_MINUTES = 10;
export const MAX_IDLE_MINUTES = 24 * 60;
export const MAX_IDLE_CPU = 50;

/** What the editor holds while it is typed into. Numbers stay text until they are checked. */
export interface ScheduleForm {
  id: string | null;
  name: string;
  action: ActionKind;
  /** Keep only the last N snapshots (retention). */
  keepOn: boolean;
  keep: string;
  timing: TimingKind;
  /** Hourly: the minute. */
  minute: string;
  /** Daily and weekly: HH:MM. */
  at: string;
  days: Day[];
  idleMinutes: string;
  cpuBelow: string;
  /** VM keys. */
  vms: string[];
  tags: string[];
  /** VM-08: stack ids. */
  stacks: string[];
}

export function emptyForm(vms: string[] = []): ScheduleForm {
  return {
    id: null,
    name: "",
    action: "snapshot",
    keepOn: true,
    keep: "7",
    timing: "daily",
    minute: "0",
    at: "02:00",
    days: ["mon", "tue", "wed", "thu", "fri"],
    idleMinutes: "60",
    cpuBelow: "5",
    vms,
    tags: [],
    stacks: [],
  };
}

/** The form for editing a saved schedule. */
export function formFromView(view: ScheduleView): ScheduleForm {
  const form = emptyForm();
  form.id = view.id;
  form.name = view.name;
  const { action, timing, targets } = view.spec;
  form.action = action.kind;
  if (action.kind === "snapshot") {
    form.keepOn = action.keep !== null;
    if (action.keep !== null) form.keep = String(action.keep);
  }
  form.timing = timing.kind;
  if (timing.kind === "hourly") form.minute = String(timing.minute);
  if (timing.kind === "daily") form.at = timing.at;
  if (timing.kind === "weekly") {
    form.at = timing.at;
    form.days = [...timing.days];
  }
  if (timing.kind === "idle") {
    form.idleMinutes = String(timing.minutes);
    form.cpuBelow = String(timing.cpuBelowPct);
  }
  form.vms = targets.filter((t) => t.kind === "vm").map((t) => (t as { vmKey: string }).vmKey);
  form.tags = targets.filter((t) => t.kind === "tag").map((t) => (t as { tag: string }).tag);
  form.stacks = targets.filter((t) => t.kind === "stack").map((t) => (t as { stackId: string }).stackId);
  return form;
}

function whole(text: string): number | null {
  return /^\s*\d+\s*$/.test(text) ? Number(text.trim()) : null;
}

/** "08:00" from "8:00", or null. */
export function normalTime(text: string): string | null {
  const m = /^\s*(\d{1,2}):(\d{2})\s*$/.exec(text);
  if (!m) return null;
  const [hour, minute] = [Number(m[1]), Number(m[2])];
  if (hour > 23 || minute > 59) return null;
  return `${String(hour).padStart(2, "0")}:${m[2]}`;
}

/** QL-08: why the form can't be saved yet, or null. */
export function formProblem(form: ScheduleForm): string | null {
  const name = form.name.trim();
  if (!name) return "Give the schedule a name";
  if (name.length > MAX_NAME) return `A name can be at most ${MAX_NAME} characters`;
  if (form.vms.length + form.tags.length + form.stacks.length === 0) return "Choose at least one VM, tag or stack";
  if (form.action === "snapshot" && form.keepOn) {
    const keep = whole(form.keep);
    if (keep === null || keep < 1 || keep > MAX_KEEP) return `Keep 1 to ${MAX_KEEP} snapshots`;
  }
  switch (form.timing) {
    case "hourly": {
      const minute = whole(form.minute);
      if (minute === null || minute > 59) return "Choose a minute from 0 to 59";
      break;
    }
    case "weekly":
      if (form.days.length === 0) return "Choose at least one day";
      if (!normalTime(form.at)) return "Type a time like 08:00";
      break;
    case "daily":
      if (!normalTime(form.at)) return "Type a time like 08:00";
      break;
    case "idle": {
      if (form.action !== "suspend") return "Only Suspend can run when VMs are idle";
      const minutes = whole(form.idleMinutes);
      if (minutes === null || minutes < MIN_IDLE_MINUTES || minutes > MAX_IDLE_MINUTES)
        return `Idle for ${MIN_IDLE_MINUTES} minutes to ${MAX_IDLE_MINUTES / 60} hours`;
      const cpu = whole(form.cpuBelow);
      if (cpu === null || cpu < 1 || cpu > MAX_IDLE_CPU) return `CPU under 1% to ${MAX_IDLE_CPU}%`;
      break;
    }
  }
  return null;
}

/** What the core takes, once [`formProblem`] has nothing to say. */
export function formToInput(form: ScheduleForm): ScheduleInput {
  let action: ScheduleAction;
  if (form.action === "snapshot") action = { kind: "snapshot", keep: form.keepOn ? whole(form.keep) : null };
  else action = { kind: form.action };
  let timing: Timing;
  const at = normalTime(form.at) ?? form.at;
  switch (form.timing) {
    case "hourly":
      timing = { kind: "hourly", minute: whole(form.minute) ?? 0 };
      break;
    case "daily":
      timing = { kind: "daily", at };
      break;
    case "weekly":
      timing = { kind: "weekly", days: DAYS.map((d) => d.value).filter((d) => form.days.includes(d)), at };
      break;
    case "idle":
      timing = {
        kind: "idle",
        minutes: whole(form.idleMinutes) ?? 60,
        cpuBelowPct: whole(form.cpuBelow) ?? 5,
      };
      break;
  }
  const targets: ScheduleTarget[] = [
    ...form.vms.map((vmKey): ScheduleTarget => ({ kind: "vm", vmKey })),
    ...form.tags.map((tag): ScheduleTarget => ({ kind: "tag", tag })),
    ...form.stacks.map((stackId): ScheduleTarget => ({ kind: "stack", stackId })),
  ];
  return { id: form.id, name: form.name.trim(), spec: { action, targets, timing } };
}

/** Idle timing goes with Suspend only: picking it switches the action, and another action leaves it. */
export function withTiming(form: ScheduleForm, timing: TimingKind): ScheduleForm {
  if (timing === "idle") return { ...form, timing, action: "suspend" };
  return { ...form, timing };
}

export function withAction(form: ScheduleForm, action: ActionKind): ScheduleForm {
  if (action !== "suspend" && form.timing === "idle") return { ...form, action, timing: "daily" };
  return { ...form, action };
}

export function stateLabel(state: ScheduleState): string {
  switch (state) {
    case "active":
      return "Active";
    case "paused":
      return "Paused";
    case "needsApproval":
      return "Needs approval";
  }
}

export function outcomeLabel(outcome: RunOutcome): string {
  switch (outcome) {
    case "running":
      return "Running";
    case "succeeded":
      return "Succeeded";
    case "partiallyFailed":
      return "Partly failed";
    case "failed":
      return "Failed";
    case "missed":
      return "Missed";
    case "skipped":
      return "Skipped";
    case "paused":
      return "Paused";
  }
}

export type Tone = "success" | "warning" | "destructive" | "muted";

export function outcomeTone(outcome: RunOutcome): Tone {
  switch (outcome) {
    case "succeeded":
      return "success";
    case "partiallyFailed":
    case "missed":
    case "skipped":
    case "paused":
      return "warning";
    case "failed":
      return "destructive";
    case "running":
      return "muted";
  }
}

/** "web01, tag 'lab' (3 VMs)". */
export function targetsText(view: Pick<ScheduleView, "targets">): string {
  return view.targets
    .map((t) =>
      t.target.kind === "tag" || t.target.kind === "stack"
        ? `${t.target.kind} '${t.name}' (${t.vms === 1 ? "1 VM" : `${t.vms} VMs`})`
        : t.vms === 0
          ? `${t.name} (not in the VM list)`
          : t.name,
    )
    .join(", ");
}

/** QL-08 reasons for a row's buttons; null when it may be pressed. */
export function rowReasons(view: Pick<ScheduleView, "state" | "running">, readOnly: string | null) {
  return {
    edit: readOnly,
    pause: readOnly ?? (view.state !== "active" ? "Only an active schedule can be paused" : null),
    resume: readOnly ?? (view.state === "active" ? "It is running on its times already" : null),
    approve: readOnly ?? (view.state === "active" ? "It has its approval" : null),
    remove: readOnly,
  };
}

/** "Sun 25 Oct 02:00" in local time (or in `timeZone`, for tests). */
export function formatPlanned(at: string, timeZone?: string): string {
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return at;
  return date.toLocaleString("en-GB", {
    weekday: "short",
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone,
  });
}
