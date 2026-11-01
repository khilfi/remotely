// FD-04: the support bundle dialog's pure parts (tested in support-bundle.test.ts): the custom commands and files as
// typed, how many items a bundle collects, why Collect is off (QL-08), and the caps in words.

import type {
  ApprovalStep,
  BundleHostKind,
  BundleItem,
  BundleLimits,
  BundlePreset,
  BundlePresetId,
  ScriptKind,
} from "./api.ts";
import { READ_ONLY_REASON } from "./disabled-reasons.ts";

/** The non-blank lines of a text box, trimmed, each once. */
export function lines(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      out.push(trimmed);
    }
  }
  return out;
}

/** Why a typed file path can't be read, or null: a full path on the host, not a folder. */
export function pathProblem(paths: string[]): string | null {
  for (const path of paths) {
    if (!path.startsWith("/")) return `'${path}' isn't a full path on the host: it starts with /`;
    if (path.endsWith("/")) return `'${path}' is a folder: name the files in it`;
  }
  return null;
}

/**
 * BX-13: the same for a Windows host's files: a drive's full path (C:\...), not a folder, never a share or a device
 * path (the host would reach another computer with the sign-in's rights).
 */
export function windowsPathProblem(paths: string[]): string | null {
  for (const path of paths) {
    if (!/^[A-Za-z]:[\\/]/.test(path))
      return `'${path}' isn't a full path on the Windows host: it starts with a drive, as C:\\`;
    if (/[\\/]$/.test(path)) return `'${path}' is a folder: name the files in it`;
    if (/[*?<>|"]/.test(path) || path.slice(2).includes(":")) {
      return `'${path}' holds characters a Windows file name can't`;
    }
  }
  return null;
}

function key(item: BundleItem): string {
  return item.kind === "command" ? `c:${item.command}` : `f:${item.path}`;
}

/**
 * How many commands and files each host of `kind` gives: the chosen presets' items for that kind and the typed ones,
 * each once.
 */
export function itemCount(
  presets: BundlePreset[],
  chosen: BundlePresetId[],
  commands: string[],
  files: string[],
  kind: BundleHostKind = "linux",
): number {
  const items = new Set<string>();
  for (const preset of presets) {
    if (preset.hostKind === kind && chosen.includes(preset.id)) for (const item of preset.items) items.add(key(item));
  }
  for (const command of commands) items.add(key({ kind: "command", command }));
  for (const path of files) items.add(key({ kind: "file", path }));
  return items.size;
}

/** QL-08: why Collect is off, or null. */
export function collectReason(input: {
  readOnly: boolean;
  /** The hosts the picks reach, with their protection and (BX-13) whether they are Windows hosts. */
  hosts: { protected: boolean; scriptKind?: ScriptKind }[];
  /** What each Linux host gives. */
  items: number;
  /** BX-13: what each Windows host gives. */
  windowsItems?: number;
  maxItems: number;
  pathProblem: string | null;
  timeoutOk: boolean;
  stopAfterOk: boolean;
  submitting: boolean;
}): string | null {
  if (input.readOnly) return READ_ONLY_REASON;
  if (input.hosts.length === 0) return "Pick the hosts to collect from";
  if (input.hosts.every((h) => h.protected)) return "Every picked host is Protected";
  const windows = input.hosts.filter((h) => h.scriptKind === "powerShell").length;
  const linux = input.hosts.length - windows;
  const windowsItems = input.windowsItems ?? 0;
  if (windows === 0 && input.items === 0) return "Choose a preset, or add a command or a file";
  if (linux > 0 && input.items === 0) return "Choose a Linux preset, or add a command or a file for the Linux hosts";
  if (windows > 0 && windowsItems === 0) {
    return "Choose a Windows preset, or add a PowerShell command or a file for the Windows hosts";
  }
  if (Math.max(input.items, windowsItems) > input.maxItems) {
    return `A bundle collects at most ${input.maxItems} commands and files`;
  }
  if (input.pathProblem) return input.pathProblem;
  if (!input.timeoutOk) return "The time limit must be a whole number of seconds, 1 to 86400 (or empty)";
  if (!input.stopAfterOk) return "Stop after must be a whole number of failures, 1 to 1000 (or empty)";
  if (input.submitting) return "Starting…";
  return null;
}

/** "10 MB", "1 GB" (binary units, as the core counts them). */
export function sizeText(bytes: number): string {
  const units = ["bytes", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const shown = Number.isInteger(value) ? String(value) : value.toFixed(1);
  return `${shown} ${units[unit]}`;
}

/** The caps in one line. */
export function limitsText(limits: BundleLimits): string {
  return `Each file keeps up to ${sizeText(limits.fileBytes)}, each host ${sizeText(limits.hostBytes)} and the bundle ${sizeText(limits.bundleBytes)}.`;
}

/** What approving takes, from the preview's steps. */
export function stepsText(steps: ApprovalStep[]): string {
  if (steps.length === 0) return "Runs at once; logged.";
  if (steps.some((s) => s.step === "vaultReauth")) return "Needs every approval step and the vault password.";
  if (steps.some((s) => s.step === "reason")) return "Needs the host count typed, a reason and a countdown.";
  return "Needs one confirm.";
}

/**
 * BX-13: the presets the dialog offers: the Linux ones while Linux hosts are picked (or none yet), the Windows ones
 * while Windows hosts are.
 */
export function shownPresets(presets: BundlePreset[], linuxHosts: number, windowsHosts: number): BundlePreset[] {
  return presets.filter((p) => (p.hostKind === "windows" ? windowsHosts > 0 : linuxHosts > 0 || windowsHosts === 0));
}

/** A preset's items in words, for its tooltip: "/etc/os-release, uname -a, uptime…". */
export function presetItemsText(preset: BundlePreset): string {
  return preset.items.map((i) => (i.kind === "command" ? i.command : i.path)).join(", ");
}
