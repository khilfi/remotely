// CT-01, CT-02: the Containers page's decisions, as pure functions (tested in containers.test.ts): container targets
// keyed as the core keys them, which actions fit the selection and why the others are off (QL-08), filters, ports,
// sizes and following a log. Nothing here talks to the core.

import type {
  ContainerHost,
  ContainerHostInfo,
  ContainerObject,
  ContainerOp,
  ContainerState,
  ContainerStats,
  ContainerSummary,
  EngineKind,
  LogLine,
  PortMapping,
  PruneWhat,
  SudoMode,
  TargetRef,
} from "./api.ts";
import { READ_ONLY_REASON } from "./disabled-reasons.ts";

export const ENGINE_LABEL: Record<EngineKind, string> = { docker: "Docker", podman: "Podman" };

/** The host's part of a target key: the session's id, or `this-pc` (TargetRef::key in the core). */
export function hostKey(host: ContainerHost): string {
  return host.kind === "session" ? host.sessionId : "this-pc";
}

export function objectKey(object: ContainerObject): string {
  switch (object.kind) {
    case "container":
      return `container:${object.id}`;
    case "image":
      return `image:${object.id}`;
    case "volume":
      return `volume:${object.name}`;
    case "engine":
      return "engine";
  }
}

/** One engine on one host, as the page keys what it read. */
export function engineKey(host: ContainerHost, engine: EngineKind): string {
  return `${hostKey(host)}/${engine}`;
}

export function containerTarget(host: ContainerHost, engine: EngineKind, object: ContainerObject): TargetRef {
  return { kind: "container", host, engine, object };
}

/** The key the core gives a container target, to match it with the impact preview. */
export function containerTargetKey(target: Extract<TargetRef, { kind: "container" }>): string {
  return `${engineKey(target.host, target.engine)}/${objectKey(target.object)}`;
}

export function sameHost(a: ContainerHost | null, b: ContainerHost | null): boolean {
  if (!a || !b) return false;
  return hostKey(a) === hostKey(b);
}

// ---- Actions on the selection --------------------------------------------------------------------

export type ContainerAction = "start" | "stop" | "restart" | "pause" | "unpause" | "remove" | "forceRemove";

interface ActionDef {
  label: string;
  op: ContainerOp;
  /** States it makes sense in; containers in others are left out of the command. */
  appliesTo: ContainerState[];
  /** How the states read in "None of the selected containers is …". */
  states: string;
}

const STOPPED: ContainerState[] = ["created", "exited", "dead"];
const UP: ContainerState[] = ["running", "paused", "restarting"];

export const ACTIONS: Record<ContainerAction, ActionDef> = {
  start: { label: "Start", op: { kind: "start" }, appliesTo: STOPPED, states: "stopped" },
  stop: { label: "Stop", op: { kind: "stop" }, appliesTo: UP, states: "running or paused" },
  restart: {
    label: "Restart",
    op: { kind: "restart" },
    appliesTo: [...UP, ...STOPPED],
    states: "running, paused or stopped",
  },
  pause: { label: "Pause", op: { kind: "pause" }, appliesTo: ["running"], states: "running" },
  unpause: { label: "Unpause", op: { kind: "unpause" }, appliesTo: ["paused"], states: "paused" },
  remove: { label: "Remove", op: { kind: "remove", force: false }, appliesTo: STOPPED, states: "stopped" },
  forceRemove: {
    label: "Force remove",
    op: { kind: "remove", force: true },
    appliesTo: [...UP, ...STOPPED],
    states: "running, paused or stopped",
  },
};

/** The picked containers the action fits. */
export function applicable(action: ContainerAction, picked: ContainerSummary[]): ContainerSummary[] {
  const states = ACTIONS[action].appliesTo;
  return picked.filter((c) => states.includes(c.state));
}

/** AP-04 for a container host: a session that reaches a protected VM. */
export const PROTECTED_HOST_REASON = "Protected: actions skip this host until its VM is unprotected";

/** QL-08: why an action on the selection is off, or null when it can go. */
export function actionReason(
  action: ContainerAction,
  picked: ContainerSummary[],
  context: { readOnly: boolean; protectedHost: boolean; submitting: boolean },
): string | null {
  if (context.readOnly) return READ_ONLY_REASON;
  if (context.protectedHost) return PROTECTED_HOST_REASON;
  if (picked.length === 0) return "Select containers first";
  if (applicable(action, picked).length === 0) {
    const one = picked.length === 1;
    return one
      ? `${picked[0].name} is ${stateWord(picked[0].state)}`
      : `None of the selected containers is ${ACTIONS[action].states}`;
  }
  if (context.submitting) return "Sending the last action…";
  return null;
}

/** "running", "stopped"... for messages. */
export function stateWord(state: ContainerState): string {
  switch (state) {
    case "exited":
    case "dead":
      return "stopped";
    case "created":
      return "created, not started";
    default:
      return state;
  }
}

/** "Open a shell": only in a running container on an SSH host. */
export function shellReason(container: ContainerSummary | undefined, host: ContainerHost | null): string | null {
  if (!container) return "Select one container first";
  if (host?.kind === "thisPc") {
    return "A shell in Docker Desktop's containers needs a terminal on this PC, which Remotely doesn't have yet: run docker exec -it in a console";
  }
  if (container.state !== "running") return `${container.name} is ${stateWord(container.state)}: start it first`;
  return null;
}

/** QL-08 for the host's own actions (pull, prune). */
export function hostActionReason(
  host: ContainerHostInfo | undefined,
  context: { readOnly: boolean; submitting: boolean },
): string | null {
  if (context.readOnly) return READ_ONLY_REASON;
  if (!host) return "Choose a container host first";
  if (host.protected) return PROTECTED_HOST_REASON;
  if (context.submitting) return "Sending the last action…";
  return null;
}

/** Podman has no build cache of its own to prune. */
export function pruneReason(what: PruneWhat, engine: EngineKind | null): string | null {
  if (what === "buildCache" && engine === "podman") {
    return "Podman keeps no build cache of its own: its build layers are images (prune those)";
  }
  return null;
}

export const PRUNE_LABEL: Record<PruneWhat, string> = {
  containers: "Stopped containers",
  images: "Unused images (no tag)",
  buildCache: "The build cache",
  volumes: "Unused volumes (deletes their data)",
};

// ---- Filtering and showing -----------------------------------------------------------------------

export type StateFilter = "all" | "running" | "paused" | "stopped";

export function stateGroup(state: ContainerState): Exclude<StateFilter, "all"> | "other" {
  if (state === "running" || state === "restarting") return "running";
  if (state === "paused") return "paused";
  if (STOPPED.includes(state)) return "stopped";
  return "other";
}

/** Name, image, project, id or a port, without regard to case; and the state group. */
export function filterContainers(list: ContainerSummary[], text: string, state: StateFilter): ContainerSummary[] {
  const words = text.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return list.filter((c) => {
    if (state !== "all" && stateGroup(c.state) !== state) return false;
    if (words.length === 0) return true;
    const haystack = [c.name, c.image, c.project ?? "", c.id, ...portTexts(c.ports), c.status].join(" ").toLowerCase();
    return words.every((w) => haystack.includes(w));
  });
}

/** `8080→80/tcp`, with the host address only when it is not every address; IPv4 and IPv6 twins once. */
export function portTexts(ports: PortMapping[]): string[] {
  const out: string[] = [];
  for (const p of ports) {
    const any = !p.hostIp || p.hostIp === "0.0.0.0" || p.hostIp === "::";
    const text =
      p.hostPort == null
        ? `${p.containerPort}/${p.protocol}`
        : `${any ? "" : `${p.hostIp?.includes(":") ? `[${p.hostIp}]` : p.hostIp}:`}${p.hostPort}→${p.containerPort}/${p.protocol}`;
    if (!out.includes(text)) out.push(text);
  }
  return out;
}

/** "12.6 MB", decimal units as the CLIs print them. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit + 1 < units.length) {
    value /= 1000;
    unit += 1;
  }
  if (unit === 0) return `${bytes} B`;
  return `${value < 10 ? value.toFixed(1) : value.toFixed(0)} ${units[unit]}`;
}

/** A container's stats: Podman gives 12-digit ids, so either id may be the start of the other. */
export function statsFor(stats: ContainerStats[], id: string): ContainerStats | undefined {
  return stats.find((s) => id.startsWith(s.id) || s.id.startsWith(id));
}

/** How a host's engine runs, in words, for the host list. */
export function sudoLabel(sudo: SudoMode): string {
  switch (sudo.kind) {
    case "off":
      return "As the login user";
    case "noPassword":
      return "With sudo, no password";
    case "password":
      return sudo.passwordId ? "With sudo, a vault password" : "With sudo, the login password";
  }
}

// ---- Logs ------------------------------------------------------------------------------------------

/** The most lines the Logs tab keeps while following. */
export const MAX_LOG_LINES = 5000;

/** Lines read since the last ones, added on; the oldest go when there are more than `cap`. */
export function appendLogs(previous: LogLine[], next: LogLine[], cap = MAX_LOG_LINES): LogLine[] {
  const last = previous.length > 0 ? previous[previous.length - 1].at : null;
  const fresh = last ? next.filter((l) => !l.at || l.at > last) : next;
  const all = previous.concat(fresh);
  return all.length > cap ? all.slice(all.length - cap) : all;
}

/** Where to follow on from: the newest line's time. */
export function lastLogTime(lines: LogLine[]): string | null {
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const at = lines[i].at;
    if (at) return at;
  }
  return null;
}

/** The lines holding `query` (any case), with their place in the log. */
export function searchLogs(lines: LogLine[], query: string): { line: LogLine; index: number }[] {
  const q = query.trim().toLowerCase();
  const all = lines.map((line, index) => ({ line, index }));
  if (!q) return all;
  return all.filter(({ line }) => line.text.toLowerCase().includes(q));
}

/** `2026-10-21 10:00:00.123` in local time, for the timestamps column. */
export function logTime(at: string | null): string {
  if (!at) return "";
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return at;
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(
    date.getMinutes(),
  )}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

/** Core messages start in lower case and end without a full stop; shown on their own they read better as a sentence. */
export function sentence(text: string): string {
  const capital = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

// ---- Pulling ---------------------------------------------------------------------------------------

const DOMAIN =
  "(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*(?::[0-9]+)?";
const PATH = "[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
const IMAGE_REFERENCE = new RegExp(
  `^(?:${DOMAIN}/)?${PATH}(?:/${PATH})*(?::[\\w][\\w.-]{0,127})?(?:@[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,})?$`,
);

/** Why an image reference won't be taken (the core checks it again), or null. */
export function imageReferenceProblem(text: string): string | null {
  const reference = text.trim();
  if (!reference) return "Type the image to pull, e.g. nginx:1.27";
  if (reference.length > 255 || !IMAGE_REFERENCE.test(reference)) {
    return "Not an image reference: use a name like nginx:1.27 or registry.example.com/team/app:2.1 (lower case)";
  }
  return null;
}
