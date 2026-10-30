// UX-02, UX-03 for the Virtual machines page: what its header, columns, selection bar and details panel show, as pure
// functions (tested in vm-page.test.ts). The page decides nothing about tiers or approvals: every action is still a
// command for the bus, and the reasons here only say why a control is off or left out.

import type { Environment, Hypervisor, PowerState, ToolsState, VmFilter } from "./api.ts";
import type { ChainInfo, ChainLimits } from "./schedules-api.ts";
import type { VmView } from "./vm-snapshots.ts";

// ---- The environment that applies (UX-12) ----

/**
 * A host network's environment: Prod when a VM on it is (the approval rules rate its forwards so), with where that
 * comes from ("Prod · from VM db-01"). A VM's own environment is its own: nothing passes one on to a VM.
 */
export function networkEnvironment(vms: readonly { name: string; environment: Environment }[]): string | null {
  const prod = [...new Set(vms.filter((v) => v.environment === "prod").map((v) => v.name))];
  if (prod.length === 0) return null;
  return prod.length === 1 ? `Prod · from VM ${prod[0]}` : `Prod · from ${prod.length} VMs (${prod[0]}, …)`;
}

// ---- Plain status lines (UX-06) ----

/** "1.5 GB", for a chain's size on this PC. */
function gb(bytes: number) {
  const value = bytes / 1024 ** 3;
  return `${value >= 10 ? Math.round(value) : Math.round(value * 10) / 10} GB`;
}

/**
 * VM-27: a VM's snapshot chain as a status line ("2 snapshots · OK", "7 snapshots · 7 deep, past 5"), with the rules
 * and the details for a tooltip.
 */
export function chainStatus(chain: ChainInfo, limits: ChainLimits): { text: string; ok: boolean; detail: string } {
  const rules = `Warns past ${limits.maxDepth} deep or ${limits.maxSizeGb} GB.`;
  if (chain.error) return { text: "Chain not read", ok: true, detail: `${chain.error} ${rules}` };
  const count =
    chain.snapshots === null ? "Snapshots" : chain.snapshots === 1 ? "1 snapshot" : `${chain.snapshots} snapshots`;
  const facts = [
    chain.depth !== null ? `${chain.depth} deep` : null,
    chain.sizeBytes !== null ? `${gb(chain.sizeBytes)} on this PC` : null,
  ].filter((f): f is string => f !== null);
  const detail = `${facts.length > 0 ? `${facts.join(", ")}. ` : ""}${rules}`;
  if (chain.warnings.length === 0) return { text: `${count} · OK`, ok: true, detail };
  const past = [
    chain.depth !== null && chain.depth > limits.maxDepth ? `${chain.depth} deep` : null,
    chain.sizeBytes !== null && chain.sizeBytes > limits.maxSizeGb * 1024 ** 3 ? gb(chain.sizeBytes) : null,
  ].filter((f): f is string => f !== null);
  return {
    text: `${count} · ${past.length > 0 ? `${past.join(", ")}: past the limit` : "check the chain"}`,
    ok: false,
    detail: `${chain.warnings.join(" ")} ${rules}`,
  };
}

// ---- The details panel's tabs ----

/** The details panel's five tabs. Overview holds what Details and System showed; Activity the timeline and schedules. */
export type VmTab = "overview" | "snapshots" | "settings" | "log" | "activity";

export const VM_TABS: readonly { id: VmTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "snapshots", label: "Snapshots" },
  { id: "settings", label: "Settings" },
  { id: "log", label: "Log" },
  { id: "activity", label: "Activity" },
];

/** The tab a requested view opens (links, the palette and the waste finder still ask for the 0.5.0 views). */
export function vmTabOf(view: VmView): VmTab {
  switch (view) {
    case "details":
    case "system":
      return "overview";
    case "timeline":
    case "schedules":
      return "activity";
    default:
      return view;
  }
}

/** The view kept for a tab the user clicked. */
export function viewOfTab(tab: VmTab): VmView {
  switch (tab) {
    case "overview":
      return "details";
    case "activity":
      return "timeline";
    default:
      return tab;
  }
}

// ---- The list's columns ----

/** The columns the picker can show or hide; Name is always shown. */
export type VmColumnId =
  "hypervisor" | "guestOs" | "vcpus" | "ram" | "ip" | "state" | "hostCpu" | "hostMem" | "sessions" | "environment";

export interface VmColumnInfo {
  id: VmColumnId;
  /** The picker's name for it. */
  label: string;
  /** Shown until the user hides it. */
  shownByDefault: boolean;
  /** Left out while a VM's details are open beside the list: the details show it. */
  wide: boolean;
}

/** In the list's order. The defaults fit a 1440 px window without scrolling sideways. */
export const VM_COLUMNS: readonly VmColumnInfo[] = [
  { id: "hypervisor", label: "Hypervisor", shownByDefault: true, wide: false },
  { id: "guestOs", label: "Guest OS", shownByDefault: true, wide: true },
  { id: "vcpus", label: "vCPU", shownByDefault: true, wide: true },
  { id: "ram", label: "RAM", shownByDefault: true, wide: true },
  { id: "ip", label: "IP address", shownByDefault: true, wide: false },
  { id: "state", label: "State", shownByDefault: true, wide: false },
  { id: "hostCpu", label: "Host CPU", shownByDefault: true, wide: true },
  { id: "hostMem", label: "Host RAM", shownByDefault: true, wide: true },
  { id: "sessions", label: "Sessions", shownByDefault: false, wide: true },
  { id: "environment", label: "Environment", shownByDefault: true, wide: false },
];

const COLUMN_IDS = new Set<string>(VM_COLUMNS.map((c) => c.id));

/** The columns shown when nothing was stored. */
export function defaultColumns(): Set<VmColumnId> {
  return new Set(VM_COLUMNS.filter((c) => c.shownByDefault).map((c) => c.id));
}

/** The shown columns in a stored value (a JSON list of ids); anything unreadable is the default. */
export function parseColumns(raw: string | null | undefined): Set<VmColumnId> {
  if (!raw) return defaultColumns();
  try {
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value)) return defaultColumns();
    return new Set(value.filter((id): id is VmColumnId => typeof id === "string" && COLUMN_IDS.has(id)));
  } catch {
    return defaultColumns();
  }
}

/** The stored value for the shown columns, in the list's order. */
export function serialiseColumns(shown: ReadonlySet<VmColumnId>): string {
  return JSON.stringify(VM_COLUMNS.filter((c) => shown.has(c.id)).map((c) => c.id));
}

/** The columns to draw, in order: the shown ones, without the wide ones while a VM's details are open. */
export function visibleColumns(shown: ReadonlySet<VmColumnId>, detailOpen: boolean): VmColumnId[] {
  return VM_COLUMNS.filter((c) => shown.has(c.id) && !(detailOpen && c.wide)).map((c) => c.id);
}

// ---- The header's filter ----

/** How many kinds of filter are on besides the search text, for the Filter button's count. */
export function activeFilterCount(filter: VmFilter): number {
  return [
    (filter.tags?.length ?? 0) > 0,
    (filter.powerStates?.length ?? 0) > 0,
    (filter.hypervisors?.length ?? 0) > 0,
    (filter.environments?.length ?? 0) > 0,
    filter.protected !== undefined && filter.protected !== null,
  ].filter(Boolean).length;
}

// ---- The State column (with the guest tools folded in) ----

const STATE_WORDS: Record<PowerState, string> = {
  running: "Running",
  paused: "Paused",
  suspended: "Suspended",
  not_running: "Off",
  unknown: "Unknown",
};

const TOOLS_WORDS: Record<ToolsState, string> = {
  running: "running",
  installed: "not running",
  notRunning: "not running",
  notInstalled: "not installed",
  unknown: "unknown",
};

function toolsWord(hypervisor: Hypervisor) {
  return hypervisor === "virtualbox" ? "Guest Additions" : "VMware Tools";
}

/**
 * The State badge's tooltip, with the guest tools, and whether they need a look: a running VM whose tools don't run
 * can't shut down or restart softly and reports no IP address.
 */
export function stateDetail(vm: { powerState: PowerState; toolsState: ToolsState | null; hypervisor: Hypervisor }): {
  text: string;
  toolsWarning: boolean;
} {
  const state = STATE_WORDS[vm.powerState];
  if (vm.powerState !== "running" || !vm.toolsState) return { text: state, toolsWarning: false };
  const tools = TOOLS_WORDS[vm.toolsState];
  return {
    text: `${state} · ${toolsWord(vm.hypervisor)} ${tools}`,
    toolsWarning: vm.toolsState !== "running" && vm.toolsState !== "unknown",
  };
}

// ---- The selection bar's More menu ----

/** One VM, as the selection's actions see it. */
export interface SelectedVm {
  powerState: PowerState;
  protected: boolean;
  environment: Environment;
  tags: readonly string[];
}

export type MoreItemId =
  // Power
  | "startGui"
  | "suspend"
  | "restart"
  | "pause"
  | "unpause"
  | "powerOff"
  // Snapshots
  | "revert"
  | "deleteSnapshot"
  // Change
  | "resize"
  | "tools"
  | "clone"
  | "export"
  | "delete"
  // Organise
  | "addTag"
  | "removeTag"
  | "environment"
  | "protect"
  | "unprotect"
  | "release";

export interface MoreItem {
  id: MoreItemId;
  /** How many of the selected VMs it goes to; 0 for one that isn't a count (tags, environment). */
  count: number;
}

export interface MoreGroup {
  label: "Power" | "Snapshots" | "Change" | "Organise";
  items: MoreItem[];
}

const ON: PowerState[] = ["running", "paused"];
const OFF: PowerState[] = ["not_running", "suspended"];

/** The selected VMs a power action goes to; a VM in an unknown state (the hypervisor missing) goes to all. */
export function powerTargets<T extends { powerState: PowerState }>(vms: readonly T[], appliesTo: PowerState[]): T[] {
  return vms.filter((v) => v.powerState === "unknown" || appliesTo.includes(v.powerState));
}

/**
 * The More menu for the selection: only the items that apply to at least one selected VM, in groups, and only the
 * groups that have one. `snapshots` is how many selected VMs have a snapshot (null while their trees are read, when
 * the Snapshots group is left out); `canRelease` whether they may leave this workspace; `canExport` whether export is
 * offered (one VM).
 */
export function moreGroups(
  vms: readonly SelectedVm[],
  options: { snapshots: number | null; canRelease: boolean; canExport: boolean },
): MoreGroup[] {
  const count = (pick: (v: SelectedVm) => boolean) => vms.filter(pick).length;
  const open = (v: SelectedVm) => !v.protected;
  const power: MoreItem[] = [
    { id: "startGui", count: powerTargets(vms, OFF).length },
    { id: "suspend", count: powerTargets(vms, ["running"]).length },
    { id: "restart", count: powerTargets(vms, ON).length },
    { id: "pause", count: powerTargets(vms, ["running"]).length },
    { id: "unpause", count: powerTargets(vms, ["paused"]).length },
    { id: "powerOff", count: powerTargets(vms, ON).length },
  ];
  const snapshots: MoreItem[] =
    options.snapshots === null
      ? []
      : [
          { id: "revert", count: options.snapshots },
          { id: "deleteSnapshot", count: options.snapshots },
        ];
  const change: MoreItem[] = [
    { id: "resize", count: count((v) => open(v) && v.powerState === "not_running") },
    { id: "tools", count: count((v) => open(v) && v.powerState === "running") },
    { id: "clone", count: count((v) => v.powerState === "not_running") },
    { id: "export", count: options.canExport ? 1 : 0 },
    { id: "delete", count: count((v) => open(v) && !ON.includes(v.powerState)) },
  ];
  const tagged = vms.some((v) => v.tags.length > 0);
  const organise: MoreItem[] = [
    { id: "addTag", count: vms.length },
    { id: "removeTag", count: tagged ? 1 : 0 },
    { id: "environment", count: vms.length },
    { id: "protect", count: count((v) => !v.protected) },
    { id: "unprotect", count: count((v) => v.protected) },
    { id: "release", count: options.canRelease ? vms.length : 0 },
  ];
  const groups: MoreGroup[] = [
    { label: "Power", items: power },
    { label: "Snapshots", items: snapshots },
    { label: "Change", items: change },
    { label: "Organise", items: organise },
  ];
  return groups
    .map((g) => ({ label: g.label, items: g.items.filter((i) => i.count > 0) }))
    .filter((g) => g.items.length > 0);
}

/** Why Start or Shut down in the selection bar is off: the reason, in a tooltip, or null. */
export function selectionPowerReason(
  vms: readonly { powerState: PowerState }[],
  action: "start" | "shutDown",
): string | null {
  if (action === "start") {
    if (powerTargets(vms, OFF).length > 0) return null;
    return vms.length === 1 ? "It is running already" : "All of them are running already";
  }
  if (powerTargets(vms, ["running"]).length > 0) return null;
  return vms.length === 1 ? "It isn't running" : "None of them is running";
}
