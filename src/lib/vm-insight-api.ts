// Typed wrappers over R4's IPC commands in src-tauri/src/vm_insight.rs: VM-25 a VM's Log and Timeline tabs, VM-11
// the host networks view and VM-16, VM-14 the waste finder. Types mirror the serde shapes in crates/core
// (vm_insight/, host_networks/, adapters/host_networks.rs, waste/). Every answer goes past the presentation masker
// (FD-03) through `invoke`. Adding or removing a port forward is a `hostNetwork` command for the bus (api.submit).

import { invoke, type Environment, type Hypervisor, type PowerState, type TargetRef } from "@/lib/api";

// ---- VM-25: logs ----

export interface LogFile {
  /** `vmware.log`, `vmware-0.log`, `VBox.log`, `VBox.log.1`. */
  name: string;
  size: number;
  modified: string | null;
  /** The log the VM writes to now; the others are older. */
  current: boolean;
}

export interface LogListing {
  folder: string | null;
  files: LogFile[];
  problem: string | null;
}

export interface LogChunk {
  file: string;
  start: number;
  /** Where the next read starts: after the last complete line. */
  end: number;
  size: number;
  text: string;
  /** The log goes on before `start` (this is its tail). */
  truncatedBefore: boolean;
  /** The log got shorter than the last read's end (replaced at the VM's start): this is its tail again. */
  reset: boolean;
  /** Bytes left out because the log grew faster than one read takes. */
  skipped: number;
}

// ---- VM-25: timeline ----

export interface TimelineOutcome {
  status: string;
  error: string | null;
  durationMs: number | null;
  safetySnapshot: string | null;
  finishedAt: string | null;
}

export interface TimelineEntry {
  seq: number;
  at: string;
  event: string;
  action: string;
  tier: string | null;
  jobId: string | null;
  result: string | null;
  detail: string | null;
  reason: string | null;
  otherTargets: number;
  outcome: TimelineOutcome | null;
}

export interface TimelinePage {
  entries: TimelineEntry[];
  nextBefore: number | null;
}

// ---- VM-11: host networks ----

export type ForwardProtocol = "tcp" | "udp";
export type VmnetKind = "hostOnly" | "nat" | "bridged" | { other: string };

export interface Vmnet {
  index: number;
  name: string;
  kind: VmnetKind;
  dhcp: boolean | null;
  subnet: string | null;
  mask: string | null;
}

export interface VmnetForward {
  protocol: ForwardProtocol;
  hostPort: number;
  guestIp: string;
  guestPort: number;
  description: string | null;
}

export interface VboxRule {
  name: string;
  protocol: ForwardProtocol;
  hostIp: string | null;
  hostPort: number;
  guestIp: string | null;
  guestPort: number;
}

export interface NetworkVm {
  vmxPath: string;
  name: string;
  powerState: PowerState;
  environment: Environment;
  protected: boolean;
  adapter: string;
  ips: string[];
}

export interface VmnetView {
  network: Vmnet;
  target: TargetRef;
  vms: NetworkVm[];
  forwards: VmnetForward[];
  forwardsProblem: string | null;
}

export interface VboxHostOnlyIf {
  name: string;
  ip: string | null;
  mask: string | null;
  dhcp: boolean | null;
  status: string | null;
}

export interface VboxNatNetwork {
  name: string;
  enabled: boolean | null;
  network: string | null;
  gateway: string | null;
  dhcp: boolean | null;
  ipv6: boolean | null;
  forwards: VboxRule[];
}

export interface HostNetworksReport {
  vmware: {
    available: boolean;
    problem: string | null;
    forwardsRefused: string | null;
    networks: VmnetView[];
  };
  virtualbox: {
    available: boolean;
    problem: string | null;
    hostOnly: { iface: VboxHostOnlyIf; vms: NetworkVm[] }[];
    natNetworks: { network: VboxNatNetwork; target: TargetRef; vms: NetworkVm[] }[];
    other: { kind: string; name: string; vms: NetworkVm[] }[];
    vmNat: { vm: NetworkVm; slot: number; rules: VboxRule[]; problem: string | null }[];
  };
  staleVms: string[];
  readAt: string;
}

/** What a `hostNetwork` command adds or removes (crates/core/src/host_networks/ops.rs). */
export interface NatForward {
  /** VirtualBox's rule name; Workstation's description. */
  name?: string | null;
  protocol: ForwardProtocol;
  /** VirtualBox only; null: every address of this PC. */
  hostIp?: string | null;
  hostPort: number;
  guestIp?: string | null;
  guestPort: number;
  /** A VirtualBox VM's NAT adapter, 1 to 8. */
  slot?: number | null;
}

export type HostNetworkOp =
  { kind: "addForward"; forward: NatForward } | { kind: "removeForward"; forward: NatForward };

// ---- VM-16, VM-14: waste finder ----

export interface WasteOptions {
  idleDays: number;
  chainDepth: number;
  chainGb: number;
}

export interface WasteVm {
  vmxPath: string;
  name: string;
  hypervisor: Hypervisor;
  powerState: PowerState;
  environment: Environment;
  protected: boolean;
  memoryMb: number | null;
  folder: string | null;
}

export interface IdleVerdict {
  idle: boolean;
  coveredHours: number;
  cpuAvg: number;
  cpuPeakHour: number;
  guestCpuPeakHour: number | null;
  guestNetPeakHour: number | null;
  whyNot: string | null;
}

export type OrphanKind = "workstationVm" | "virtualBoxVm" | "disks";

export interface WasteReport {
  options: WasteOptions;
  idleDays: number;
  idle: { vm: WasteVm; verdict: IdleVerdict; guestSession: string | null }[];
  suspended: { vm: WasteVm; since: string | null; stateBytes: number | null; folderBytes: number | null }[];
  chains: {
    vm: WasteVm;
    snapshots: number;
    depth: number;
    snapshotBytes: number | null;
    oldest: string | null;
    why: string[];
  }[];
  orphans: {
    path: string;
    kind: OrphanKind;
    bytes: number;
    files: number;
    newest: string | null;
    examples: string[];
  }[];
  searched: string[];
  skipped: { path: string; reason: string }[];
  problems: string[];
  notes: string[];
  readAt: string;
}

export const insightApi = {
  vmLogs: (vmxPath: string) => invoke<LogListing>("vm_logs", { vmxPath }),
  vmLogRead: (vmxPath: string, file: string, from: number | null, tail?: number) =>
    invoke<LogChunk>("vm_log_read", { vmxPath, file, from, tail: tail ?? null }),
  vmTimeline: (vmxPath: string, before: number | null, limit?: number) =>
    invoke<TimelinePage>("vm_timeline", { vmxPath, before, limit: limit ?? null }),
  hostNetworks: () => invoke<HostNetworksReport>("host_networks"),
  wasteReport: (options: WasteOptions) => invoke<WasteReport>("waste_report", { options }),
  /** Explorer at a known VM's folder, or a folder the last report listed. */
  wasteOpenFolder: (target: { folder: string } | { vmxPath: string }) =>
    invoke<void>("waste_open_folder", {
      folder: "folder" in target ? target.folder : null,
      vmxPath: "vmxPath" in target ? target.vmxPath : null,
    }),
};
