// 0.7.0 F6: the inventory to Excel (FD-05), the Ansible inventory (BX-12) and the handover pack (FD-08): the types the
// core sends and the IPC wrappers. Each export opens its save dialog in the shell (never a path from here), reads the
// shown workspace only, and is audited by the core; the read-only lock allows them, as it allows other exports.

import { invoke, listen, type ResolvedTargets, type TargetPicks } from "@/lib/api";

export interface ReportsOverview {
  workspace: string;
  /** The handover pack's "prepared by" until one is typed. */
  preparedBy: string | null;
  vms: number;
  sessions: number;
  sshSessions: number;
  /** Windows hosts: read again too, but not for updates or packages. */
  winrmSessions: number;
  checks: number;
  /** Notes marked for the handover pack. */
  handoverNotes: number;
}

/** What the inventory reads now, besides what is stored. */
export interface InventoryOptions {
  /** Read the SSH hosts again first: facts and listening ports. */
  readAgain: boolean;
  /** Also pending updates (slow on dnf hosts). */
  updates: boolean;
  /** Also each host's installed packages. */
  packages: boolean;
}

export interface ReadSummary {
  asked: number;
  read: number;
  /** "web01: the vault is locked" per host not read, or read in part. */
  problems: string[];
}

/** An export's result, with the id "Show in folder" takes. */
interface Saved {
  savedId: string;
  path: string;
}

export interface InventoryExport extends Saved {
  vms: number;
  hosts: number;
  networks: number;
  checks: number;
  packages: number | null;
  read: ReadSummary | null;
  notes: string[];
}

export type AnsibleFormat = "yaml" | "ini";

export interface GroupBy {
  folder: boolean;
  tag: boolean;
  environment: boolean;
  workspace: boolean;
}

export interface AnsibleRequest {
  /** None picked: every SSH session of the workspace. */
  picks: TargetPicks;
  format: AnsibleFormat;
  groupBy: GroupBy;
}

export interface AnsiblePreview {
  text: string;
  hosts: number;
  groups: number;
  notes: string[];
}

export interface AnsibleExport extends Saved {
  hosts: number;
  groups: number;
  notes: string[];
}

export interface HandoverRequest {
  /** The first day's local midnight, and the day after the last one's, in Unix ms. */
  fromMs: number;
  toMs: number;
  utcOffsetMinutes: number;
  preparedBy: string;
  includeOutputs: boolean;
  inventory: InventoryOptions;
}

export interface HandoverPreview {
  jobs: number;
  otherChanges: number;
  notes: number;
  checks: number;
}

export interface HandoverExport extends Saved {
  jobs: number;
  notes: number;
  files: string[];
  read: ReadSummary | null;
}

/** How far "Read reachable hosts again first" got: hosts done (read or not) of those asked. */
export interface ReadProgress {
  done: number;
  total: number;
}

export const reportsApi = {
  overview: () => invoke<ReportsOverview>("reports_overview"),
  /**
   * Opens the save dialog, then writes the workbook, as run `run` (for `cancel` and `onProgress`); null when the
   * dialog was closed.
   */
  exportInventory: (run: string, options: InventoryOptions, utcOffsetMinutes: number) =>
    invoke<InventoryExport | null>("inventory_export", { run, request: { ...options, utcOffsetMinutes } }),
  /** The hosts the picks reach, SSH and WinRM sessions both (the picker's list). */
  ansibleTargets: (picks: TargetPicks) => invoke<ResolvedTargets>("ansible_targets", { picks }),
  ansiblePreview: (request: AnsibleRequest) => invoke<AnsiblePreview>("ansible_preview", { request }),
  exportAnsible: (request: AnsibleRequest, utcOffsetMinutes: number) =>
    invoke<AnsibleExport | null>("ansible_export", { request, utcOffsetMinutes }),
  handoverPreview: (request: HandoverRequest) => invoke<HandoverPreview>("handover_preview", { request }),
  exportHandover: (run: string, request: HandoverRequest) =>
    invoke<HandoverExport | null>("handover_export", { run, request }),
  /** Stops an export's host reads; nothing is written. */
  cancel: (run: string) => invoke<boolean>("reports_cancel", { run }),
  onProgress: (handler: (event: ReadProgress & { run: string }) => void) =>
    listen<ReadProgress & { run: string }>("reports://progress", (e) => handler(e.payload)),
  showFile: (savedId: string) => invoke<void>("reports_show_file", { savedId }),
};
