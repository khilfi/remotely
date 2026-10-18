// Typed wrappers over the Tauri IPC commands in src-tauri/src/ipc.rs and terminal.rs.
// The UI talks to the Rust core only through these; it never runs vmrun or SSH itself.
// Types mirror the serde shapes in crates/core.

import { Channel, invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Environment = "none" | "lab" | "staging" | "prod";
export type Tier = "low" | "medium" | "high" | "critical";

export type TargetRef = { kind: "vm"; vmxPath: string } | { kind: "session"; sessionId: string } | { kind: "app" };

export interface Target {
  target: TargetRef;
  name: string;
  environment: Environment;
  protected: boolean;
}

export type PowerState = "unknown" | "running" | "not_running" | "suspended" | "paused";

/** VMware Tools state from `vmrun checkToolsState`; null when the VM is not running. */
export type ToolsState = "running" | "installed" | "notInstalled" | "unknown";

export interface VmRecord {
  id: string;
  vmxPath: string;
  displayName: string;
  /** Workstation's guest OS id, e.g. "ubuntu-64". */
  guestOs: string | null;
  /** What the guest calls itself through VMware Tools, e.g. "Ubuntu 24.04 LTS". */
  guestOsName: string | null;
  numVcpus: number | null;
  memsizeMb: number | null;
  powerState: PowerState;
  ipAddress: string | null;
  toolsState: ToolsState | null;
  environment: Environment;
  protected: boolean;
  /** VM-02 tag names, sorted. */
  tags: string[];
  lastSeenAt: string | null;
}

/** Something a refresh could not read (vmrun missing, a folder gone). The rest still lists. */
export interface InventoryWarning {
  code: string;
  message: string;
}

export interface RefreshReport {
  vms: VmRecord[];
  warnings: InventoryWarning[];
}

/**
 * VM-02: which VMs to show or select. Empty fields match everything; a VM must match every field that
 * is set, and any one of the values listed in a field.
 */
export interface VmFilter {
  /** Case-insensitive text in the name, .vmx path, guest OS, IP address or a tag. */
  text?: string;
  tags?: string[];
  powerStates?: PowerState[];
  environments?: Environment[];
  /** true: only protected VMs; false: only unprotected ones. */
  protected?: boolean | null;
}

export interface Tag {
  id: string;
  name: string;
  color: string | null;
  vmCount: number;
}

export interface SavedFilter {
  id: string;
  name: string;
  filter: VmFilter;
  updatedAt: string;
}

export type StopMode = "soft" | "hard";

export type PowerOp =
  | { kind: "start"; gui?: boolean }
  | { kind: "stop"; mode: StopMode }
  | { kind: "reset"; mode: StopMode }
  | { kind: "suspend" }
  | { kind: "pause" }
  | { kind: "unpause" };

export type SnapshotOp =
  { kind: "take"; name: string } | { kind: "revert"; name: string } | { kind: "delete"; name: string };

export type Command =
  | { type: "vmPower"; targets: TargetRef[]; op: PowerOp }
  | { type: "vmSnapshot"; targets: TargetRef[]; op: SnapshotOp }
  /** AP-04: protected VMs ("do not touch") are skipped by every other action. */
  | { type: "vmProtect"; targets: TargetRef[]; protected: boolean }
  | { type: "remoteExec"; targets: TargetRef[]; script: string; sudo?: boolean }
  | { type: "appUpdate"; version: string };

export type ApprovalStep =
  | { step: "confirm" }
  | { step: "impactPreview" }
  | { step: "safetySnapshot"; defaultOn: boolean }
  | { step: "typeTargetCount"; expected: number }
  | { step: "reason" }
  | { step: "countdown"; seconds: number }
  | { step: "vaultReauth" };

export interface ApprovalRequest {
  id: string;
  action: string;
  tier: Tier;
  summary: string;
  steps: ApprovalStep[];
  targets: Target[];
  skipped: Target[];
  reasons: string[];
  /** Problems to read before approving, e.g. the capacity check before a power-on (VM-07). */
  warnings: string[];
}

export type SubmitOutcome =
  /** `skipped`: protected targets left alone (AP-04). */
  | { status: "queued"; jobId: string; tier: Tier; summary: string; skipped: Target[] }
  | { status: "needsApproval"; request: ApprovalRequest };

export interface ApprovalAnswers {
  confirmed: boolean;
  typedTargetCount?: number;
  reason?: string;
  safetySnapshot?: boolean;
  vaultPassword?: string;
}

export type JobStatus =
  "queued" | "countdown" | "running" | "succeeded" | "failed" | "partially_failed" | "cancelled" | "interrupted";

export type TargetStatus = "pending" | "running" | "succeeded" | "failed" | "skipped" | "cancelled";

export type JobEvent =
  | { event: "queued"; jobId: string; summary: string; tier: Tier; targets: number }
  | { event: "countdown"; jobId: string; seconds: number }
  | { event: "started"; jobId: string }
  | {
      event: "targetFinished";
      jobId: string;
      target: string;
      name: string;
      status: TargetStatus;
      message: string | null;
      durationMs: number;
    }
  /** VM-03: these VMs did not shut down. Forcing them off is a separate, Critical command. */
  | { event: "stillRunning"; jobId: string; targets: Target[] }
  | { event: "finished"; jobId: string; status: JobStatus };

export interface JobSummary {
  id: string;
  summary: string;
  action: string;
  tier: Tier;
  status: JobStatus;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  targetsTotal: number;
  targetsSucceeded: number;
  targetsFailed: number;
}

export interface ChainCheck {
  entries: number;
  ok: boolean;
  firstBadSeq: number | null;
  problem: string | null;
}

export interface AuditEntry {
  seq: number;
  id: string;
  ts: string;
  event: string;
  action: string;
  tier: Tier | null;
  jobId: string | null;
  targetsJson: string;
  approvalJson: string | null;
  result: string | null;
  detail: string | null;
  prevHash: string;
  hash: string;
}

export interface Settings {
  /** What the user chose; null means "find vmrun.exe automatically". */
  vmrunPathSaved: string | null;
  /** What the app is using now; null means Workstation was not found. */
  vmrunPathInUse: string | null;
  /** FD-14: check GitHub Releases for updates (off at air-gapped sites). */
  updateChecks: boolean;
  /** VM-01: folders scanned for .vmx files, besides Workstation's library. */
  scanFolders: string[];
  /** VM-06: how many VMs may power on at once (1 to 32, default 3). */
  powerOnLimit: number;
  /** VM-03: seconds a soft stop may take before the VM counts as still running (default 120). */
  shutdownWaitSecs: number;
}

/** FD-14: a newer signed release on GitHub. */
export interface UpdateInfo {
  currentVersion: string;
  version: string;
  notes: string | null;
  pubDate: string | null;
}

export interface AppInfo {
  version: string;
  workspaceId: string;
  userId: string;
  vmrunPath: string | null;
}

/** Error shape from src-tauri/src/ipc.rs. */
export interface IpcError {
  code: string;
  message: string;
}

export function errorMessage(err: unknown): string {
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && "message" in err) return String((err as IpcError).message);
  return "Unexpected error";
}

export function errorCode(err: unknown): string | undefined {
  return err && typeof err === "object" && "code" in err ? String((err as IpcError).code) : undefined;
}

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),

  /** VM-01: finds every VM (Workstation's library, chosen folders, vmrun list) via the core. */
  vmRefresh: () => invoke<RefreshReport>("vm_refresh"),
  /** VM-01, VM-02: the VMs the last refresh found that match the filter, without asking Workstation. */
  vmList: (filter?: VmFilter) => invoke<VmRecord[]>("vm_list", { filter: filter ?? null }),

  /** VM-02: tags are the app's own labels for picking VMs; they change no VM. */
  tags: () => invoke<Tag[]>("tags_list"),
  tagVms: (vmxPaths: string[], tag: string) => invoke<void>("vm_tag", { vmxPaths, tag }),
  untagVms: (vmxPaths: string[], tag: string) => invoke<void>("vm_untag", { vmxPaths, tag }),
  deleteTag: (tag: string) => invoke<void>("tag_delete", { tag }),
  savedFilters: () => invoke<SavedFilter[]>("filters_list"),
  /** Saving under an existing name replaces that filter. */
  saveFilter: (name: string, filter: VmFilter) => invoke<SavedFilter>("filter_save", { name, filter }),
  deleteFilter: (id: string) => invoke<void>("filter_delete", { id }),

  /** The one way in for changes: command bus -> policy engine -> job runner. */
  submit: (command: Command) => invoke<SubmitOutcome>("command_submit", { command }),
  approve: (requestId: string, answers: ApprovalAnswers) => invoke<string>("command_approve", { requestId, answers }),
  cancelApproval: (requestId: string) => invoke<void>("command_cancel_approval", { requestId }),

  cancelJob: (jobId: string) => invoke<boolean>("job_cancel", { jobId }),
  recentJobs: (limit = 50) => invoke<JobSummary[]>("jobs_recent", { limit }),
  recentAudit: (limit = 100) => invoke<AuditEntry[]>("audit_recent", { limit }),
  verifyAudit: () => invoke<ChainCheck>("audit_verify"),
  onJobEvent: (handler: (event: JobEvent) => void): Promise<UnlistenFn> =>
    listen<JobEvent>("job://event", (e) => handler(e.payload)),

  settings: () => invoke<Settings>("settings_get"),
  /** null or "" goes back to finding vmrun.exe automatically. */
  setVmrunPath: (path: string | null) => invoke<Settings>("settings_set_vmrun_path", { path }),
  setUpdateChecks: (enabled: boolean) => invoke<Settings>("settings_set_update_checks", { enabled }),
  /** VM-01: each folder must exist. */
  setScanFolders: (folders: string[]) => invoke<Settings>("settings_set_scan_folders", { folders }),
  setPowerOnLimit: (limit: number) => invoke<Settings>("settings_set_power_on_limit", { limit }),
  setShutdownWait: (secs: number) => invoke<Settings>("settings_set_shutdown_wait", { secs }),
  /** FD-14: null when up to date or when checks are off. Installing is the `appUpdate` command. */
  checkForUpdate: () => invoke<UpdateInfo | null>("update_check"),

  terminalOpen: (onOutput: (data: string) => void) => {
    const channel = new Channel<string>();
    channel.onmessage = onOutput;
    return invoke<string>("terminal_open", { onOutput: channel });
  },
  terminalWrite: (id: string, data: string) => invoke<void>("terminal_write", { id, data }),
  terminalResize: (id: string, cols: number, rows: number) => invoke<void>("terminal_resize", { id, cols, rows }),
  terminalClose: (id: string) => invoke<void>("terminal_close", { id }),
};
