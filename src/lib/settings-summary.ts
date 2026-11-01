// UX-10: what the Settings page shows in a line before any detail, as pure functions (settings-summary.test.ts):
// the tool paths as one table ("vmrun · Found · Change"), and the approval rules as a summary ("Default rules ·
// 0 changed" and each tier's steps in plain words) above the Advanced editor.

import type { PolicyRules, Settings, Tier } from "./api.ts";

// ---- Tool paths ----

export type ToolId = "vmrun" | "vdiskmanager" | "ovftool" | "vboxmanage" | "qemuImg" | "docker" | "vncViewer";

export interface ToolRow {
  id: ToolId;
  /** The settings section a link opens it by, for the row that answers to it. */
  section: string | null;
  exe: string;
  /** What it is for, in a few words. */
  purpose: string;
  /** The path in use, or null when it was not found. */
  inUse: string | null;
  /** The path set in Settings, or null when it is found by itself. */
  saved: string | null;
  /** Whether a path can be set for it (vdiskmanager is always the one beside vmrun). */
  editable: boolean;
}

export function toolRows(settings: Settings, vdiskmanager: string | null): ToolRow[] {
  return [
    {
      id: "vmrun",
      section: "vmware",
      exe: "vmrun.exe",
      purpose: "VMware Workstation",
      inUse: settings.vmrunPathInUse,
      saved: settings.vmrunPathSaved,
      editable: true,
    },
    {
      id: "vdiskmanager",
      section: null,
      exe: "vmware-vdiskmanager.exe",
      purpose: "Workstation's disk tool, beside vmrun",
      inUse: vdiskmanager,
      saved: null,
      editable: false,
    },
    {
      id: "ovftool",
      section: null,
      exe: "ovftool.exe",
      purpose: "OVA and OVF imports into Workstation",
      inUse: settings.ovftoolPathInUse,
      saved: settings.ovftoolPathSaved,
      editable: true,
    },
    {
      id: "vboxmanage",
      section: "virtualbox",
      exe: "VBoxManage.exe",
      purpose: "Oracle VirtualBox 7.0 or later",
      inUse: settings.vboxmanagePathInUse,
      saved: settings.vboxmanagePathSaved,
      editable: true,
    },
    {
      id: "qemuImg",
      section: "qemu-img",
      exe: "qemu-img.exe",
      purpose: "qcow2 and VHDX conversions",
      inUse: settings.qemuImgPathInUse,
      saved: settings.qemuImgPathSaved,
      editable: true,
    },
    {
      id: "docker",
      section: "docker",
      exe: "docker.exe",
      purpose: "Docker Desktop on this PC",
      inUse: settings.dockerPathInUse,
      saved: settings.dockerPathSaved,
      editable: true,
    },
    {
      // SS-12: the owner's own viewer, for VNC sessions.
      id: "vncViewer",
      section: "vnc-viewer",
      exe: "VNC viewer",
      purpose: "VNC sessions: TigerVNC, TightVNC, RealVNC or UltraVNC",
      inUse: settings.vncViewerPathInUse,
      saved: settings.vncViewerPathSaved,
      editable: true,
    },
  ];
}

/** A row's status in words: "Found", "Found (path set here)", or what not finding it means. */
export function toolStatus(row: Pick<ToolRow, "id" | "inUse" | "saved">): string {
  if (row.inUse) return row.saved ? "Found · path set here" : "Found";
  if (row.saved) return "Not at the path set here";
  switch (row.id) {
    case "vmrun":
      return "Not found";
    case "vboxmanage":
      return "Not installed";
    case "qemuImg":
      return "Not installed";
    case "docker":
      return "Not installed";
    case "vncViewer":
      return "None found: VNC sessions can't open";
    default:
      return "Not found";
  }
}

// ---- Approval rules ----

/** How many rules differ from the defaults: each tier (one target or in bulk), number, switch, pattern and command. */
export function rulesChanged(rules: PolicyRules, defaults: PolicyRules): number {
  let n = 0;
  for (const [kind, rule] of Object.entries(defaults.tiers) as [
    keyof PolicyRules["tiers"],
    PolicyRules["tiers"][keyof PolicyRules["tiers"]],
  ][]) {
    const now = rules.tiers[kind];
    if (!now) continue;
    if (now.single !== rule.single) n += 1;
    if (now.bulk !== rule.bulk) n += 1;
  }
  for (const key of [
    "bulkThreshold",
    "execBulkThreshold",
    "deployBulkThreshold",
    "countdownSeconds",
    "prodBump",
    "safetySnapshotDefault",
  ] as const) {
    if (rules[key] !== defaults[key]) n += 1;
  }
  const pattern = (p: { name: string; pattern: string }) => `${p.name}\u0000${p.pattern}`;
  n += symmetricDifference(rules.dangerousCommands.map(pattern), defaults.dangerousCommands.map(pattern));
  n += symmetricDifference(rules.readOnlyCommands, defaults.readOnlyCommands);
  // BX-13: the PowerShell rules count the same way.
  n += symmetricDifference(
    rules.powershell.dangerousCommands.map(pattern),
    defaults.powershell.dangerousCommands.map(pattern),
  );
  n += symmetricDifference(rules.powershell.readOnlyCommands, defaults.powershell.readOnlyCommands);
  return n;
}

function symmetricDifference(a: readonly string[], b: readonly string[]): number {
  const left = new Set(a);
  const right = new Set(b);
  let n = 0;
  for (const x of left) if (!right.has(x)) n += 1;
  for (const x of right) if (!left.has(x)) n += 1;
  return n;
}

/** "Default rules · 0 changed", or "Your rules · 3 changed". */
export function rulesLine(changed: number): string {
  return changed === 0 ? "Default rules · 0 changed" : `Your rules · ${changed} changed`;
}

/** What each tier asks before an action runs, with these rules. */
export function tierSteps(rules: Pick<PolicyRules, "countdownSeconds" | "safetySnapshotDefault">): {
  tier: Tier;
  steps: string;
}[] {
  const snapshot = rules.safetySnapshotDefault ? "a safety snapshot" : "a safety snapshot (off by default)";
  const countdown = rules.countdownSeconds > 0 ? `, then a ${rules.countdownSeconds} s countdown` : "";
  return [
    { tier: "low", steps: "Runs at once" },
    { tier: "medium", steps: "One confirm" },
    { tier: "high", steps: `The impact, ${snapshot}, type to confirm and a reason${countdown}` },
    { tier: "critical", steps: "Everything High asks, and the vault password again" },
  ];
}
