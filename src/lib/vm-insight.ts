// R4 as pure functions (tested in vm-insight.test.ts): VM-25 following a log and searching it, grouping the timeline;
// VM-11 the port forward form, its checks (the core's, in crates/core/src/host_networks/ops.rs, checked again there)
// and the command it becomes, and the host networks as the topology map and search show them; VM-16, VM-14 the waste
// finder's reasons and sums. QL-08: every reason says why an action is off; `null` means it is available.

import type { Command, PowerState, TargetRef } from "./api.ts";
import type { HostNetwork } from "./topology.ts";
import { PROTECTED_REASON } from "./vm-snapshots.ts";
import type {
  ForwardProtocol,
  HostNetworksReport,
  LogChunk,
  LogFile,
  NatForward,
  TimelineEntry,
  TimelineOutcome,
  VboxRule,
  VmnetForward,
  VmnetKind,
  WasteOptions,
  WasteReport,
  WasteVm,
} from "./vm-insight-api.ts";

// ---- VM-25: the Log tab ----

/** How often a followed log is read for what was added. */
export const LOG_FOLLOW_MS = 2000;
/** What the tab keeps of a followed log; older lines drop off the top. */
export const MAX_KEPT_LOG_CHARS = 1_500_000;
/** Matching lines shown at most. */
export const MAX_MATCHES = 2000;

export interface LogView {
  file: string;
  text: string;
  /** Where the next read starts. */
  end: number;
  /** The log goes on above what is shown. */
  startsMidway: boolean;
  /** Bytes left out while following (the log grew faster than a read). */
  skipped: number;
  /** The VM started again and its log was replaced while it was followed. */
  restarted: boolean;
}

export function startLog(chunk: LogChunk): LogView {
  return {
    file: chunk.file,
    text: chunk.text,
    end: chunk.end,
    startsMidway: chunk.truncatedBefore,
    skipped: 0,
    restarted: false,
  };
}

/** Keeps the last `max` characters of `text`, from a line's start. */
function keepTail(text: string, max: number): { text: string; cut: boolean } {
  if (text.length <= max) return { text, cut: false };
  const from = text.length - max;
  const lineStart = text.indexOf("\n", from);
  return { text: lineStart === -1 ? text.slice(from) : text.slice(lineStart + 1), cut: true };
}

/** A followed log after one more read: what was added goes at the end; a replaced log or a skip starts afresh. */
export function followLog(view: LogView, chunk: LogChunk, max = MAX_KEPT_LOG_CHARS): LogView {
  if (chunk.reset || chunk.skipped > 0) {
    return {
      ...startLog(chunk),
      skipped: view.skipped + chunk.skipped,
      restarted: view.restarted || chunk.reset,
    };
  }
  if (chunk.text === "") return { ...view, end: chunk.end };
  const kept = keepTail(view.text + chunk.text, max);
  return { ...view, text: kept.text, end: chunk.end, startsMidway: view.startsMidway || kept.cut };
}

export interface LogMatch {
  /** 1-based within what is shown. */
  line: number;
  text: string;
}

/** The lines holding `query` (any letter case), at most `max`. */
export function logMatches(text: string, query: string, max = MAX_MATCHES): LogMatch[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  const out: LogMatch[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length && out.length < max; i++) {
    // Workstation's logs end their lines with CRLF.
    const line = lines[i].replace(/\r$/, "");
    if (line.toLowerCase().includes(needle)) out.push({ line: i + 1, text: line });
  }
  return out;
}

/** `text` split around each case-insensitive `query`, for highlighting. */
export function splitMatches(text: string, query: string): { text: string; match: boolean }[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [{ text, match: false }];
  const lower = text.toLowerCase();
  const parts: { text: string; match: boolean }[] = [];
  let at = 0;
  for (;;) {
    const found = lower.indexOf(needle, at);
    if (found === -1) break;
    if (found > at) parts.push({ text: text.slice(at, found), match: false });
    parts.push({ text: text.slice(found, found + needle.length), match: true });
    at = found + needle.length;
  }
  if (at < text.length) parts.push({ text: text.slice(at), match: false });
  return parts;
}

/** QL-08: why a log can't be followed: an older log, or the VM isn't running. */
export function followReason(state: PowerState, file: LogFile | undefined): string | null {
  if (!file) return "Choose a log first";
  if (!file.current) return "An older log doesn't change: choose the current one to follow it";
  if (state !== "running" && state !== "paused") return "The VM isn't running, so its log isn't growing";
  return null;
}

// ---- VM-25: the Timeline tab ----

export interface TimelineGroup {
  /** The job's id, or the entry's seq for an entry of its own. */
  key: string;
  jobId: string | null;
  /** Newest first, as the audit log gave them. */
  entries: TimelineEntry[];
  action: string;
  at: string;
  tier: string | null;
  outcome: TimelineOutcome | null;
  reason: string | null;
}

/** Entries of one job next to each other become one group; any other entry is a group of its own. */
export function groupTimeline(entries: TimelineEntry[]): TimelineGroup[] {
  const groups: TimelineGroup[] = [];
  for (const entry of entries) {
    const last = groups[groups.length - 1];
    if (entry.jobId && last && last.jobId === entry.jobId) {
      last.entries.push(entry);
      last.outcome ??= entry.outcome;
      last.reason ??= entry.reason;
      continue;
    }
    groups.push({
      key: entry.jobId ?? `seq-${entry.seq}`,
      jobId: entry.jobId,
      entries: [entry],
      action: entry.action,
      at: entry.at,
      tier: entry.tier,
      outcome: entry.outcome,
      reason: entry.reason,
    });
  }
  return groups;
}

/** Pages put together: a job split across two pages stays one group. */
export function mergeTimeline(earlier: TimelineEntry[], next: TimelineEntry[]): TimelineEntry[] {
  const seen = new Set(earlier.map((e) => e.seq));
  return [...earlier, ...next.filter((e) => !seen.has(e.seq))];
}

const EVENT_LABELS: Record<string, string> = {
  approval_requested: "Approval asked",
  approval_granted: "Approved",
  approval_rejected: "Approval refused (wrong vault password)",
  approval_cancelled: "Approval cancelled",
  approval_expired: "Approval expired",
  job_started: "Started",
  job_finished: "Finished",
  job_cancelled: "Cancelled",
  canary_go_on: "Went on after the first host",
  vm_label_changed: "Label changed",
  vm_console_opened: "Console opened",
};

/** "Approved", "Finished", or the event's name in words. */
export function eventLabel(event: string): string {
  const known = EVENT_LABELS[event];
  if (known) return known;
  const words = event.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** How a job went for the VM, in a word, and whether that's good. */
export function outcomeText(outcome: TimelineOutcome | null): { text: string; tone: "ok" | "bad" | "neutral" } | null {
  if (!outcome) return null;
  switch (outcome.status) {
    case "succeeded":
      return { text: "Succeeded", tone: "ok" };
    case "failed":
      return { text: "Failed", tone: "bad" };
    case "unknown":
      return { text: "Outcome unknown", tone: "bad" };
    case "cancelled":
      return { text: "Cancelled", tone: "neutral" };
    case "skipped":
      return { text: "Not started", tone: "neutral" };
    case "running":
      return { text: "Running", tone: "neutral" };
    default:
      return { text: "Waiting", tone: "neutral" };
  }
}

// ---- VM-11: host networks ----

/** Where a port forward goes: a Workstation NAT vmnet, a VirtualBox NAT network, or a VirtualBox VM's NAT adapter. */
export type ForwardPlace =
  | { kind: "vmnet"; name: string }
  | { kind: "natNetwork"; name: string }
  | { kind: "vboxVm"; vmxPath: string; slot: number; vmName: string };

export interface ForwardForm {
  name: string;
  protocol: ForwardProtocol;
  hostIp: string;
  hostPort: string;
  guestIp: string;
  guestPort: string;
}

export const EMPTY_FORWARD: ForwardForm = {
  name: "",
  protocol: "tcp",
  hostIp: "",
  hostPort: "",
  guestIp: "",
  guestPort: "",
};

/** The longest rule name or description (the core's MAX_RULE_NAME). */
export const MAX_RULE_NAME = 64;

function port(text: string): number | null {
  if (!/^\d{1,5}$/.test(text.trim())) return null;
  const n = Number(text.trim());
  return n >= 1 && n <= 65535 ? n : null;
}

/** A host's IPv4 address: not 0.0.0.0, the broadcast address or multicast. */
export function isHostIpv4(text: string): boolean {
  const parts = text.trim().split(".");
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return false;
  const [a] = parts.map(Number);
  const all = parts.join(".");
  return all !== "0.0.0.0" && all !== "255.255.255.255" && !(a >= 224 && a <= 239);
}

/** What's wrong with the form, for the dialog (the core checks the same again). */
export function forwardProblems(form: ForwardForm, place: ForwardPlace): string[] {
  const problems: string[] = [];
  const vbox = place.kind !== "vmnet";
  const name = form.name;
  if (vbox) {
    if (!name.trim()) problems.push("Give the rule a name.");
    else if (name.trim() !== name) problems.push("A rule name can't start or end with a space.");
    else if (name.startsWith("-")) problems.push("A rule name can't start with '-'.");
    else if (!/^[\p{L}\p{N} ._-]+$/u.test(name))
      problems.push("A rule name can hold letters, digits, spaces, '-', '_' and '.'.");
  } else if (/["\n\r\t]/.test(name)) {
    problems.push("A description can't hold quotes, line breaks or tabs.");
  }
  if ([...name].length > MAX_RULE_NAME) problems.push(`At most ${MAX_RULE_NAME} characters.`);
  if (port(form.hostPort) === null) problems.push("The port on this PC is 1 to 65535.");
  if (port(form.guestPort) === null) problems.push("The guest's port is 1 to 65535.");
  const guest = form.guestIp.trim();
  if (guest && !isHostIpv4(guest)) problems.push("The guest's address is an IPv4 address of one host.");
  if (!guest && place.kind !== "vboxVm") problems.push("Give the guest's address on the network.");
  const host = form.hostIp.trim();
  if (host && place.kind === "vmnet") problems.push("Workstation listens on every address of this PC.");
  else if (host && !isHostIpv4(host)) problems.push("This PC's address is an IPv4 address (or leave it empty).");
  return problems;
}

/** The forward the form describes. */
export function forwardFromForm(form: ForwardForm, place: ForwardPlace): NatForward {
  return {
    name: form.name.trim() || null,
    protocol: form.protocol,
    hostIp: place.kind === "vmnet" ? null : form.hostIp.trim() || null,
    hostPort: port(form.hostPort) ?? 0,
    guestIp: form.guestIp.trim() || null,
    guestPort: port(form.guestPort) ?? 0,
    slot: place.kind === "vboxVm" ? place.slot : null,
  };
}

export function vmnetForward(f: VmnetForward): NatForward {
  return {
    name: f.description,
    protocol: f.protocol,
    hostIp: null,
    hostPort: f.hostPort,
    guestIp: f.guestIp,
    guestPort: f.guestPort,
    slot: null,
  };
}

export function vboxForward(rule: VboxRule, slot: number | null): NatForward {
  return {
    name: rule.name,
    protocol: rule.protocol,
    hostIp: rule.hostIp,
    hostPort: rule.hostPort,
    guestIp: rule.guestIp,
    guestPort: rule.guestPort,
    slot,
  };
}

function placeTarget(place: ForwardPlace): TargetRef {
  switch (place.kind) {
    case "vmnet":
      return { kind: "network", hypervisor: "vmware", name: place.name };
    case "natNetwork":
      return { kind: "network", hypervisor: "virtualbox", name: place.name };
    case "vboxVm":
      return { kind: "vm", vmxPath: place.vmxPath };
  }
}

/** The bus command that adds or removes `forward`. */
export function forwardCommand(place: ForwardPlace, add: boolean, forward: NatForward): Command {
  return {
    type: "hostNetwork",
    targets: [placeTarget(place)],
    op: add ? { kind: "addForward", forward } : { kind: "removeForward", forward },
  };
}

/** `tcp 8080 → 203.0.113.10:80`, as the core describes it. */
export function describeForward(f: NatForward): string {
  const host = f.hostIp ? `${f.hostIp}:${f.hostPort}` : String(f.hostPort);
  const line = `${f.protocol} ${host} → ${f.guestIp ?? "the guest"}:${f.guestPort}`;
  return f.name ? `'${f.name}': ${line}` : line;
}

/** QL-08: why forwards can't be added or removed here. */
export function forwardReason(input: {
  readOnly: string | null;
  /** Workstation: why its NAT forwards can't change from this app (not an administrator). */
  refused?: string | null;
  /** A VM's rules: the VM. */
  vm?: { protected: boolean; powerState: PowerState } | null;
  busy?: boolean;
}): string | null {
  if (input.readOnly) return input.readOnly;
  if (input.refused) return input.refused;
  if (input.vm?.protected) return PROTECTED_REASON;
  if (input.vm?.powerState === "suspended")
    return "Suspended: VirtualBox doesn't change a suspended VM's settings. Start it first";
  if (input.busy) return "Sending the last action…";
  return null;
}

export function vmnetKindLabel(kind: VmnetKind): string {
  if (kind === "hostOnly") return "Host-only";
  if (kind === "nat") return "NAT";
  if (kind === "bridged") return "Bridged";
  return kind.other || "Other";
}

// ---- VM-11, QL-21: host networks on the topology map and in search ----

/** A dotted mask's prefix length (255.255.255.0 is 24), or null for one that isn't a mask. */
export function prefixLength(mask: string | null): number | null {
  const parts = (mask ?? "").split(".");
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  const bits = parts.map((p) => Number(p).toString(2).padStart(8, "0")).join("");
  return /^1*0*$/.test(bits) ? bits.replace(/0+$/, "").length : null;
}

function withPrefix(address: string | null, mask: string | null): string | null {
  if (!address) return null;
  const bits = prefixLength(mask);
  return bits === null ? address : `${address}/${bits}`;
}

function detailLine(...parts: (string | null | false)[]): string {
  return parts.filter((p): p is string => typeof p === "string" && p !== "").join(" · ");
}

function forwardCount(n: number): string | false {
  return n > 0 && (n === 1 ? "1 port forward" : `${n} port forwards`);
}

const HOST_NETWORKS_LINK = { kind: "hostNetworks" } as const;

/**
 * The networks Workstation and VirtualBox list, keyed like topology.ts `networkKey` (`vmware:vmnet8`,
 * `virtualbox:hostonly:<adapter>`, `virtualbox:natnetwork:<name>`): the map names the networks its VMs' adapters are
 * on by them and shows the ones no VM is on yet, and search finds them. Each opens the host networks view.
 */
export function topologyHostNetworks(report: HostNetworksReport): HostNetwork[] {
  const vmnets = report.vmware.networks.map(({ network, forwards }) => ({
    key: `vmware:${network.name.toLowerCase()}`,
    label:
      typeof network.kind === "string"
        ? `${vmnetKindLabel(network.kind)} (VMnet${network.index})`
        : `VMnet${network.index}`,
    detail: detailLine(
      "Workstation",
      withPrefix(network.subnet, network.mask),
      network.dhcp === true && "DHCP",
      forwardCount(forwards.length),
    ),
    link: HOST_NETWORKS_LINK,
  }));
  const hostOnly = report.virtualbox.hostOnly.map(({ iface }) => ({
    key: `virtualbox:hostonly:${iface.name}`,
    label: `Host-only: ${iface.name}`,
    detail: detailLine(
      "VirtualBox",
      withPrefix(iface.ip, iface.mask),
      iface.dhcp === true && "DHCP",
      iface.status !== null && iface.status !== "Up" && iface.status.toLowerCase(),
    ),
    link: HOST_NETWORKS_LINK,
  }));
  const natNetworks = report.virtualbox.natNetworks.map(({ network }) => ({
    key: `virtualbox:natnetwork:${network.name}`,
    label: `NAT network: ${network.name}`,
    detail: detailLine(
      "VirtualBox",
      network.network,
      network.dhcp === true && "DHCP",
      network.enabled === false && "off",
      forwardCount(network.forwards.length),
    ),
    link: HOST_NETWORKS_LINK,
  }));
  return [...vmnets, ...hostOnly, ...natNetworks];
}

// ---- VM-16, VM-14: the waste finder ----

export const WASTE_DEFAULTS: WasteOptions = { idleDays: 3, chainDepth: 5, chainGb: 20 };
export const IDLE_DAY_CHOICES = [1, 3, 7, 14];
export const CHAIN_DEPTH_CHOICES = [3, 5, 10];
export const CHAIN_GB_CHOICES = [10, 20, 50, 100];

/** QL-08: why a waste row's VM can't be suspended. */
export function suspendReason(vm: WasteVm, readOnly: string | null): string | null {
  if (readOnly) return readOnly;
  if (vm.protected) return PROTECTED_REASON;
  if (vm.powerState !== "running") return "Only a running VM can be suspended";
  return null;
}

/** QL-08: why a waste row's VM can't be deleted (R3's Delete VM, Critical). */
export function deleteVmReason(vm: WasteVm, readOnly: string | null): string | null {
  if (readOnly) return readOnly;
  if (vm.protected) return PROTECTED_REASON;
  if (vm.powerState === "running" || vm.powerState === "paused") return "Running: shut it down first";
  return null;
}

/** What the report's rows take on disk and in memory together. */
export function wasteTotals(report: WasteReport): { diskBytes: number; memoryMb: number; rows: number } {
  const diskBytes =
    report.suspended.reduce((n, s) => n + (s.stateBytes ?? 0), 0) +
    report.chains.reduce((n, c) => n + (c.snapshotBytes ?? 0), 0) +
    report.orphans.reduce((n, o) => n + o.bytes, 0);
  const memoryMb = report.idle.reduce((n, i) => n + (i.vm.memoryMb ?? 0), 0);
  const rows = report.idle.length + report.suspended.length + report.chains.length + report.orphans.length;
  return { diskBytes, memoryMb, rows };
}

export function orphanKindLabel(kind: WasteReport["orphans"][number]["kind"]): string {
  switch (kind) {
    case "workstationVm":
      return "Workstation VM not in its library or a scanned folder";
    case "virtualBoxVm":
      return "VirtualBox VM not registered";
    default:
      return "Disks and VM files no VM in the list uses";
  }
}
