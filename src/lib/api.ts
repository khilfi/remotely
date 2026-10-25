// Typed wrappers over the Tauri IPC commands in src-tauri/src/ipc.rs, terminal.rs, multiexec.rs, command_panel.rs,
// files.rs and containers.rs.
// The UI talks to the Rust core only through these; it never runs vmrun or SSH itself.
// Types mirror the serde shapes in crates/core.

import { Channel, invoke as tauriInvoke, type InvokeArgs, type InvokeOptions } from "@tauri-apps/api/core";
import { listen as tauriListen, type EventCallback, type UnlistenFn } from "@tauri-apps/api/event";
import { learnFields, masker } from "@/lib/presentation";

// FD-03: every answer and event passes the host, IP and user fields it holds to the presentation masker, so those
// values are masked wherever they show while presenting (presentation.ts). Nothing is changed or stored. Exported for
// the other wrappers (dashboard-api.ts), which go through them too.
export async function invoke<T>(cmd: string, args?: InvokeArgs, options?: InvokeOptions): Promise<T> {
  const answer = await tauriInvoke<T>(cmd, args, options);
  learnFields(masker, answer);
  return answer;
}

export function listen<T>(event: string, handler: EventCallback<T>): Promise<UnlistenFn> {
  return tauriListen<T>(event, (e) => {
    learnFields(masker, e.payload);
    handler(e);
  });
}

/** A terminal's events, learnt like the answers above (QL-03's host name and IP arrive this way). */
function eventChannel(onEvent: (event: TerminalEvent) => void): Channel<TerminalEvent> {
  const events = new Channel<TerminalEvent>();
  events.onmessage = (event) => {
    learnFields(masker, event);
    onEvent(event);
  };
  return events;
}

export type Environment = "none" | "lab" | "staging" | "prod";
export type Tier = "low" | "medium" | "high" | "critical";

export type TargetRef =
  | { kind: "vm"; vmxPath: string }
  | { kind: "session"; sessionId: string }
  | { kind: "app" }
  /** SS-10: an open terminal (MultiExec); the core fills in the session behind it. */
  | { kind: "terminal"; terminalId: string; sessionId?: string | null }
  /** CT-01, CT-02: a container, image or volume on a container host, or the engine itself (pull, prune). */
  | { kind: "container"; host: ContainerHost; engine: EngineKind; object: ContainerObject }
  /** VM-21, VM-10: a VM a deploy makes, by the name and label it will have. */
  | { kind: "newVm"; hypervisor: Hypervisor; name: string; environment: Environment };

export interface Target {
  target: TargetRef;
  name: string;
  environment: Environment;
  protected: boolean;
}

export type PowerState = "unknown" | "running" | "not_running" | "suspended" | "paused";

/**
 * The guest tools' state, null when the VM is not running: VMware Tools from `vmrun checkToolsState`, or VM-18
 * VirtualBox's Guest Additions ("notRunning": no run level, so not started or not installed).
 */
export type ToolsState = "running" | "installed" | "notInstalled" | "notRunning" | "unknown";

/** VM-18: the hypervisor that runs a VM. */
export type Hypervisor = "vmware" | "virtualbox";

export interface VmRecord {
  id: string;
  /** The VM's key: its .vmx path (VMware), or its UUID (VirtualBox). */
  vmxPath: string;
  /** VM-18. */
  hypervisor: Hypervisor;
  /** VM-18: a VirtualBox VM's settings file (.vbox); null for VMware. */
  configPath: string | null;
  displayName: string;
  /** The guest OS chosen for the VM: Workstation's id ("ubuntu-64") or VirtualBox's OS type ("Ubuntu (64-bit)"). */
  guestOs: string | null;
  /** What the guest calls itself through VMware Tools ("Ubuntu 24.04 LTS") or the Guest Additions. */
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
  /** QL-01: sessions linked to VMs (or unlinked) by IP address after this refresh. */
  links: AutoLinkReport;
}

/** QL-01: how a session's VM link was made. auto: by IP address, not confirmed; manual: the user's choice. */
export type VmLink = "auto" | "manual";

/** QL-01: a link auto-linking made, moved or removed. */
export interface LinkChange {
  sessionId: string;
  sessionName: string;
  vmId: string;
  vmName: string;
}

/** QL-01: a session whose address several VMs have; the user picks one. */
export interface AmbiguousLink {
  sessionId: string;
  /** The matching VMs' ids, by name. */
  vmIds: string[];
}

export interface AutoLinkReport {
  linked: LinkChange[];
  unlinked: LinkChange[];
  ambiguous: AmbiguousLink[];
}

/**
 * VM-02: which VMs to show or select. Empty fields match everything; a VM must match every field that
 * is set, and any one of the values listed in a field.
 */
export interface VmFilter {
  /** Case-insensitive text in the name, .vmx path (VirtualBox: UUID or .vbox path), guest OS, IP address or a tag. */
  text?: string;
  tags?: string[];
  powerStates?: PowerState[];
  environments?: Environment[];
  /** VM-18: VMware, VirtualBox or both. */
  hypervisors?: Hypervisor[];
  /** true: only protected VMs; false: only unprotected ones. */
  protected?: boolean | null;
}

export interface Tag {
  id: string;
  name: string;
  color: string | null;
  vmCount: number;
  /** SS-01: sessions carrying the tag. */
  sessionCount: number;
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

/**
 * VM-04. Revert and delete take a name, or when a VM has two snapshots with one name, vmrun's path form ("base/child")
 * or VirtualBox's snapshot UUID (the node's `path`).
 */
export type SnapshotOp =
  { kind: "take"; name: string } | { kind: "revert"; name: string } | { kind: "delete"; name: string };

/** VM-04: one snapshot, read from the VM's .vmsd file. */
export interface SnapshotNode {
  uid: number;
  parentUid: number | null;
  name: string;
  /** Names this one snapshot even when another has its name: vmrun's path form ("base/child one") or VirtualBox's UUID. */
  path: string;
  description: string | null;
  /** RFC 3339 UTC; null when the .vmsd has no time for it. */
  createdAt: string | null;
  ageDays: number | null;
  /** Levels below a first snapshot. */
  depth: number;
  /** Older than 30 days. */
  old: boolean;
  /** VM-05: taken by Remotely before a high-risk action. */
  safety: boolean;
  /** The VM's current state was taken from this snapshot. */
  current: boolean;
}

export interface VmSnapshots {
  vmxPath: string;
  /** VM-18: vmrun reads '/' in a snapshot name as a path; VBoxManage doesn't. */
  hypervisor: Hypervisor;
  displayName: string;
  powerState: PowerState;
  environment: Environment;
  protected: boolean;
  /** Tree order: each snapshot comes right after its parent. */
  snapshots: SnapshotNode[];
  oldCount: number;
  safetyCount: number;
  error: string | null;
}

export interface SnapshotLimits {
  oldAfterDays: number;
  /** Safety snapshot names start with this; names a user types may not. */
  safetyPrefix: string;
  maxNameLength: number;
}

export type Command =
  | { type: "vmPower"; targets: TargetRef[]; op: PowerOp }
  | { type: "vmSnapshot"; targets: TargetRef[]; op: SnapshotOp }
  /** AP-04: protected VMs ("do not touch") are skipped by every other action. */
  | { type: "vmProtect"; targets: TargetRef[]; protected: boolean }
  | {
      type: "remoteExec";
      targets: TargetRef[];
      script: string;
      /** BX-07: run under sudo with a password from the vault. */
      sudo?: boolean;
      /** BX-07: the vault password sudo gets; null: each session's login password. */
      sudoPasswordId?: string | null;
      /** SS-05: trust (and save, audited) host keys never seen before. A changed key always blocks. */
      trustNewHostKeys?: boolean;
      /** Seconds each host may take; null: no limit. One that takes longer ends with its outcome unknown. */
      timeoutSecs?: number | null;
      /** H9: one host first, and a stop after failures. */
      rollout?: Rollout;
    }
  | { type: "appUpdate"; version: string }
  /** SS-09: adds a public key to ~/.ssh/authorized_keys on each host, unless it is there already. */
  | {
      type: "pushSshKey";
      targets: TargetRef[];
      /** The OpenSSH public key line; the core writes its own form of it. */
      publicKey: string;
      trustNewHostKeys?: boolean;
      timeoutSecs?: number | null;
      /** SS-09: restrictions written before the key (expiry-time, from). */
      options?: KeyOptions;
    }
  | {
      /** SS-09: remove a public key from the hosts' ~/.ssh/authorized_keys (every line with its data). */
      type: "removeSshKey";
      targets: TargetRef[];
      publicKey: string;
      trustNewHostKeys?: boolean;
      timeoutSecs?: number | null;
    }
  /**
   * SS-10: the held Enter (or other key that runs the line) of a MultiExec line. The UI can't submit it: only
   * MultiExec builds it, and `commandSubmit` refuses it.
   */
  | { type: "terminalLine"; targets: TargetRef[]; line: string; unreliable: boolean; keys: string }
  /** SS-08: an upload. Never submitted by the UI: `filesUpload` builds it in Rust from picked or dropped files. */
  | { type: "fileUpload"; targets: TargetRef[]; folder: string; files: UploadFile[] }
  /** SS-07: a saved port forward opened on a terminal. Never submitted by the UI: `terminalTunnelStart` builds it. */
  | { type: "openTunnel"; targets: TargetRef[]; forward: PortForward }
  /** CT-01, CT-02: every target a container target whose object fits the op. */
  | { type: "container"; targets: TargetRef[]; op: ContainerOp }
  /** VM-23, VM-12, VM-11: settings of powered-off VMs (a shared folder only through `vmPickSharedFolder`). */
  | { type: "vmConfig"; targets: TargetRef[]; edit: VmConfigEdit }
  /** VM-23, VM-11, VM-15: CD/DVD, cables and guest tools (an ISO only through `vmPickIso` or a drop). */
  | { type: "vmDevice"; targets: TargetRef[]; op: VmDeviceOp }
  /** VM-16: virtual disks of powered-off VMs. */
  | { type: "vmDisk"; targets: TargetRef[]; op: VmDiskOp }
  /** VM-24: deleting VMs (an existing VM is added only through `vmPickExisting`). */
  | { type: "vmLifecycle"; targets: TargetRef[]; op: VmLifecycleOp }
  /** VM-21, VM-10: new VMs. Never submitted by the UI: `deploySubmit` and `deployCloneSubmit` build it in the core. */
  | { type: "deploy"; targets: TargetRef[]; spec: Record<string, unknown> };

/** VM-11: what a network adapter is attached to. */
export type NicNetwork =
  | { kind: "nat" }
  | { kind: "bridged"; adapter?: string | null }
  | { kind: "hostOnly"; adapter?: string | null }
  /** Workstation: VMnet0 to VMnet19. */
  | { kind: "custom"; vnet: string }
  /** VirtualBox. */
  | { kind: "natNetwork"; name: string }
  /** VirtualBox. */
  | { kind: "internal"; name: string };

export type MacAddress = { kind: "generated" } | { kind: "static"; mac: string };

/** VM-23: a VM's firmware in a settings edit (the catalogue's `Firmware` also has Secure Boot in it). */
export type VmFirmware = "bios" | "efi";

/** VM-23, VM-12, VM-11 (crates/core/src/vm_settings/ops.rs). A field left out keeps its value. */
export type VmConfigEdit =
  | {
      kind: "resources";
      vcpus?: number | null;
      coresPerSocket?: number | null;
      memoryMb?: number | null;
      nestedVirtualization?: boolean | null;
    }
  | { kind: "firmware"; firmware: VmFirmware; secureBoot: boolean; tpm?: boolean | null }
  | { kind: "rename"; name: string }
  | { kind: "guestOs"; osType: string }
  | { kind: "addNic"; network: NicNetwork; model?: string | null }
  | {
      kind: "editNic";
      slot: string;
      network?: NicNetwork | null;
      model?: string | null;
      mac?: MacAddress | null;
      connectAtPowerOn?: boolean | null;
    }
  | { kind: "removeNic"; slot: string }
  | { kind: "addSharedFolder"; name: string; hostPath: string; writable: boolean }
  | { kind: "removeSharedFolder"; name: string }
  | { kind: "upgradeHardware" };

export type VmDeviceOp =
  | { kind: "attachIso"; slot?: string | null; path: string }
  | { kind: "ejectIso"; slot?: string | null }
  | { kind: "connectNic"; slot: string }
  | { kind: "disconnectNic"; slot: string }
  | { kind: "installTools" };

export type VmDiskOp =
  | { kind: "add"; sizeMb: number; thin: boolean; bus?: string | null }
  | { kind: "expand"; slot: string; sizeMb: number }
  | { kind: "compact"; slot: string }
  | { kind: "defragment"; slot: string }
  | { kind: "remove"; slot: string };

export type VmLifecycleOp = { kind: "delete" } | { kind: "register"; path: string };

/** AP-02: what a VM settings or lifecycle command does to each VM. */
export interface VmChangePreview {
  targets: VmChangeTarget[];
  /** Said once for the command (Workstation's window is open); the approval's warnings list them too. */
  warnings: string[];
}

export interface VmChangeTarget {
  target: string;
  name: string;
  /** "vCPUs: 2 → 4". */
  changes: string[];
  /** Every file that is deleted. */
  deletes: { path: string; bytes: number | null }[];
  /** What stays that one might expect to go. */
  keeps: string[];
  /** Why this VM would be refused now. */
  problem: string | null;
}

/** VM-24: what Open console did. */
export type ConsoleOutcome = { kind: "opened" } | { kind: "starting"; outcome: SubmitOutcome };

export interface GuestOsType {
  id: string;
  description: string;
}

/** SS-08: one file of an upload. */
export interface UploadFile {
  localPath: string;
  name: string;
  size: number;
  replace: boolean;
}

/** SS-08: an upload as the approval dialog shows it. */
export interface UploadDetails {
  folder: string;
  files: { name: string; size: number; replace: boolean }[];
}

/** AP-02: a VM target as it is now, read without a guest login. */
export interface TargetImpact {
  /** The target's key (its .vmx path). */
  target: string;
  powerState: PowerState;
  /** When the running VM's process started (power-on or resume). */
  runningSince: string | null;
  uptimeSecs: number | null;
  snapshotCount: number | null;
  oldSnapshotCount: number | null;
  /** What could not be read. */
  notes: string[];
  /** CT-01, CT-02: a container target as it is now (the VM fields are empty then). */
  container?: ContainerImpact;
}

/** CT-01, CT-02: one container, image or volume target now, or what a pull or prune does on a host. */
export interface ContainerImpact {
  kind: ContainerObject["kind"];
  name: string;
  state: ContainerState | null;
  /** The engine's words, e.g. "Up 2 hours (healthy)". */
  status: string | null;
  image: string | null;
  ports: string[];
  sizeBytes: number | null;
  /** Containers using the image or volume, with their state. */
  usedBy: string[];
  /** What a prune or a volume removal deletes (at most 50). */
  removes: string[];
}

export type ApprovalStep =
  | { step: "confirm" }
  | { step: "impactPreview" }
  | { step: "safetySnapshot"; defaultOn: boolean }
  | { step: "typeTargetCount"; expected: number }
  | { step: "reason" }
  | { step: "countdown"; seconds: number }
  | { step: "vaultReauth" };

/** BX-06: a dangerous-command rule a script matched, and the line it matched. */
export interface DangerousMatch {
  rule: string;
  text: string;
  line: number;
}

/** SS-09: what a pushed key may do (OpenSSH's authorized_keys options). */
export interface KeyOptions {
  /** `YYYY-MM-DD`: the key stops working at 00:00 UTC that day (expiry-time, OpenSSH 8.2+). */
  expiresOn: string | null;
  /** Hosts or networks it may log in from (from="..."). */
  from: string[];
}

/** H9: a bulk run's blast-radius controls. */
export interface Rollout {
  /** The first host runs alone; the rest wait until the user, who sees its result, says go on. */
  canary: boolean;
  /** Start no more hosts once this many failed or ended with the outcome unknown; null: off. */
  stopAfterFailures: number | null;
}

/** BX-02, BX-06, BX-07: a remote command as the approval dialog shows it. */
export interface ExecDetails {
  script: string;
  sudo: boolean;
  /** The vault item sudo gets; null with sudo: each session's login password. */
  sudoPasswordLabel: string | null;
  trustNewHostKeys: boolean;
  timeoutSecs: number | null;
  dangerous: DangerousMatch[];
  /** BX-04: the job whose failed hosts this retries. */
  retryOf: string | null;
  /** SS-10: a line typed into open terminals (MultiExec); Enter is sent once approved. */
  multiExec: boolean;
  /** SS-10: edited with keys Remotely can't follow, so the terminals may run something else. */
  unreliable: boolean;
  /** SS-10: the key that runs the line when it is not Enter ("Ctrl+O", "Esc then A"...). */
  runKey: string | null;
  /** H9: one host first, and a stop after failures. */
  rollout: Rollout;
}

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
  /** AP-02: each VM target's state, uptime and snapshot count right now. */
  impact: TargetImpact[];
  /** BX-02: for a remote command, what will run and how. */
  exec: ExecDetails | null;
  /** SS-08: for an upload, the folder and the files (which ones replace a file there). */
  upload: UploadDetails | null;
  /** SS-07: for a tunnel, where it listens, where it leads and who can use it. */
  tunnel: TunnelDetails | null;
  /** VM-21: for a deploy, each VM it makes, where, and the disk space it may take. */
  deploy: DeployPreview | null;
  /** VM-23, VM-24: what changes on each VM, the files that go, and why a VM would be refused. */
  vmChange: VmChangePreview | null;
}

/** SS-07: a tunnel as the approval dialog shows it. */
export interface TunnelDetails {
  forward: PortForward;
  /** e.g. 127.0.0.1:8080, or localhost:9000 on the host. */
  listens: string;
  leads: string;
  /** Who can use it, in words. */
  exposes: string;
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

/** H9 `unknown`: timed out, or cancelled while its command ran: it may have run. */
export type TargetStatus = "pending" | "running" | "succeeded" | "failed" | "skipped" | "cancelled" | "unknown";

export type JobEvent =
  /** `quiet`: a MultiExec line, whose terminals show what happened (no toasts). */
  | { event: "queued"; jobId: string; summary: string; tier: Tier; targets: number; quiet: boolean }
  /** AP-03: the job waits until `until` and can be cancelled until then. */
  | { event: "countdown"; jobId: string; seconds: number; until: string }
  | { event: "started"; jobId: string }
  /** BX-02: work on a target began. */
  | { event: "targetStarted"; jobId: string; target: string; name: string }
  | {
      event: "targetFinished";
      jobId: string;
      target: string;
      name: string;
      status: TargetStatus;
      message: string | null;
      /** BX-02: a remote command's exit code. */
      exitCode: number | null;
      durationMs: number;
      /** VM-05: the safety snapshot taken on this target first. */
      safetySnapshot: string | null;
      /** VM-21: what the job says about a target that ended well (a new VM's folder, IP, session...). */
      note?: string | null;
    }
  /** H9: the canary host finished well; `rest` hosts wait until `until` for the go-ahead (`bulkGoOn`). */
  | { event: "canaryWaiting"; jobId: string; target: string; name: string; rest: number; until: string }
  /** VM-03: these VMs did not shut down. Forcing them off is a separate, Critical command. */
  | { event: "stillRunning"; jobId: string; targets: Target[] }
  /** VM-01: `scope` says what the job may have changed, so only that page reads it again. */
  | { event: "finished"; jobId: string; status: JobStatus; scope: JobScope };

/** VM-01: what a finished job may have changed: VMs (power, snapshots, protection), containers, or neither. */
export type JobScope = "vms" | "containers" | "other";

/** SS-10: how MultiExec handled a line's keys. */
export type LineMode = "command" | "password" | "fullScreen";

/** SS-10: a picked terminal that did not get a line's keys, and why. */
export interface LeftOut {
  terminalId: string;
  reason: string;
}

/** SS-10: what happened to keys typed with MultiExec on. */
export type MultiExecOutcome =
  | { status: "typed"; mode: LineMode; reached: string[]; leftOut: LeftOut[] }
  /** Not a MultiExec target: the keys went to that terminal alone. */
  | { status: "alone"; reason: string }
  /** Enter is held: Low has `jobId`; anything higher has `request` for the approval dialog. */
  | {
      status: "held";
      lineId: string;
      tier: Tier;
      reached: string[];
      leftOut: LeftOut[];
      jobId: string | null;
      request: ApprovalRequest | null;
      /** The key that runs the line: "Enter", "Ctrl+O", "Esc then Enter"... */
      runKey: string;
    }
  /** A line waits for its Enter; these keys follow it. */
  | { status: "queued"; lineId: string; dropped: boolean }
  /**
   * Keys that would run what MultiExec can't rate (Ctrl+X Ctrl+E, v after Esc...) were not sent, nor anything
   * typed after them; `reason` says why. The keys before them went to `reached`.
   */
  | { status: "refused"; reason: string; reached: string[]; leftOut: LeftOut[] };

export type MultiExecEvent =
  | {
      event: "lineDone";
      lineId: string;
      sent: boolean;
      terminals: number;
      status: JobStatus | null;
      /** The key that ran it: "Enter", "Ctrl+O"... */
      runKey: string;
    }
  | { event: "outcome"; outcome: MultiExecOutcome }
  /** QL-12: the recorded lines changed (that line, or several when null). */
  | { event: "recorded"; lineId: string | null }
  /**
   * QL-12, QL-07: every terminal of a recorded line is done, once per line. `terminals`: the ones Enter reached;
   * `unfinished`: those whose recording did not end at a prompt (time limit, connection lost, never sent).
   */
  | {
      event: "lineFinished";
      lineId: string;
      line: string;
      /** The terminals Enter reached. */
      terminalIds: string[];
      terminals: number;
      afterSecs: number;
      how: FinishedHow;
      unfinished: number;
    };

/** QL-12: how a terminal's recording of a line ended well. */
export type CaptureEnd = "prompt" | "quiet" | "nextLine";

/** QL-12: where a terminal's recording of a line stands. */
export type CaptureState =
  /** Enter has not reached the shell yet (the approval, or the job). */
  | { state: "waiting" }
  | { state: "running" }
  | { state: "done"; how: CaptureEnd }
  /** Still running at the time limit: recording stopped, the command goes on. */
  | { state: "timedOut" }
  | { state: "lost"; reason: string }
  | { state: "notSent"; reason: string };

/** QL-12: a line MultiExec recorded, in the list. */
export interface RecordedLine {
  id: string;
  line: string;
  tier: Tier | null;
  jobId: string | null;
  recordedAt: string;
  waitingApproval: boolean;
  terminals: number;
  /** Terminals done with it. */
  finished: number;
  /** Grouped by exact output. */
  headline: string;
  groups: number;
  /** Some terminal's output was cut in the middle (the per-line cap). */
  truncated: boolean;
  /** A full-screen program ran: its screens are not recorded. */
  fullScreen: boolean;
  /** From the first Enter to the last prompt, once every terminal is done. */
  durationMs: number | null;
}

export interface RecordLimits {
  maxLines: number;
  maxOutputBytes: number;
  maxSessionBytes: number;
  lineSecs: number;
}

/** QL-12: the MultiExec session's recorded lines. */
export interface Recordings {
  /** Newest first. */
  lines: RecordedLine[];
  /** Older lines the session caps dropped. */
  dropped: number;
  sessionBytes: number;
  limits: RecordLimits;
}

/** QL-12: one terminal of a recorded line. */
export type RecordedTerminal = CaptureState & {
  terminalId: string;
  name: string;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  outputBytes: number;
  truncated: boolean;
  fullScreen: boolean;
};

/** QL-12: a recorded line grouped like a Compare run (BX-03); host target keys are terminal ids. */
export interface RecordedResults {
  line: RecordedLine;
  counts: BulkCounts;
  hosts: HostResult[];
  terminals: RecordedTerminal[];
  groups: OutputGroup[];
  headline: string;
  ignoreTrailingWhitespace: boolean;
}

/** QL-12: what a recordings export wrote. */
export interface RecordedExport {
  path: string;
  format: ExportFormat;
  lines: number;
  /** Terminal outputs written (one per terminal per line). */
  outputs: number;
  redacted: number;
}

export interface MultiExecTarget {
  terminalId: string;
  name: string;
  /** Gets what is typed now. */
  receives: boolean;
  /** Why not, when it does not. */
  reason: string | null;
  /** Keys pass straight through: at a password prompt, or to a full-screen program. */
  note: string | null;
}

export interface MultiExecStatus {
  on: boolean;
  targets: MultiExecTarget[];
  held: string | null;
}

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
  /** H9: targets that timed out or were cancelled while their command ran. */
  targetsUnknown: number;
  /** AP-03: when the countdown ends, while the job is in it. */
  countdownUntil: string | null;
  /** BX-04: the job whose failed targets this one retries. */
  retryOf: string | null;
  /** BX-02: the retention purge removed its outputs and its script or line text (Settings, General). */
  bodiesRemoved: boolean;
  /** BX-04: its script or line had something that looked like a secret, now [redacted], so it can't be retried. */
  commandRedacted: boolean;
}

/** One target of a job and how it went. */
export interface JobTarget {
  targetKind: "vm" | "session" | "app" | "terminal" | "container" | "new_vm";
  targetKey: string;
  targetName: string;
  status: TargetStatus;
  exitCode: number | null;
  output: string | null;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  /** VM-05: the safety snapshot taken before the action. */
  safetySnapshot: string | null;
  /** BX-02: stderr, capped like `output` (stdout). */
  stderr: string | null;
  stdoutBytes: number | null;
  stderrBytes: number | null;
  /** The middle of a long output was cut; the start and the end are kept. */
  outputTruncated: boolean;
  /** Why it failed, as a stable code. */
  errorCode: string | null;
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

export type ActionKind =
  | "vmStart"
  | "vmUnpause"
  | "vmPause"
  | "vmSuspend"
  | "vmResetSoft"
  | "vmResetHard"
  | "vmStopSoft"
  | "vmStopHard"
  | "snapshotTake"
  | "snapshotRevert"
  | "snapshotDelete"
  | "vmProtect"
  | "vmUnprotect"
  | "execReadOnly"
  | "execOther"
  | "execDangerous"
  | "sshKeyPush"
  | "sshKeyRemove"
  | "fileUpload"
  | "fileReplace"
  | "tunnelLocal"
  | "tunnelRemote"
  | "tunnelShared"
  | "containerStart"
  | "containerUnpause"
  | "containerPause"
  | "containerRestart"
  | "containerStop"
  | "containerRemove"
  | "imagePull"
  | "imageRemove"
  | "volumeRemove"
  | "pruneContainers"
  | "pruneImages"
  | "pruneBuildCache"
  | "pruneVolumes"
  | "vmConfigure"
  | "vmUpgradeHardware"
  | "vmIso"
  | "vmNicConnect"
  | "vmNicDisconnect"
  | "vmToolsInstall"
  | "vmDiskAdd"
  | "vmDiskCompact"
  | "vmDiskExpand"
  | "vmDiskRemove"
  | "vmDelete"
  | "vmRegister"
  /** VM-21, VM-10: make new VMs. */
  | "vmDeploy"
  | "appUpdate";

export interface TierRule {
  single: Tier;
  bulk: Tier;
}

export interface DangerousPattern {
  name: string;
  pattern: string;
}

/** AP-01: the editable approval rules (crates/core/src/policy). */
export interface PolicyRules {
  tiers: Record<ActionKind, TierRule>;
  /** Targets from which the bulk tier applies, for every action but commands on hosts. */
  bulkThreshold: number;
  /** BX-06: hosts from which the bulk tier of commands on hosts (Compare, MultiExec) applies. */
  execBulkThreshold: number;
  /** VM-21: new VMs from which a deploy's bulk tier applies (5 by default). */
  deployBulkThreshold: number;
  /** A Prod-labelled target raises the tier by one. */
  prodBump: boolean;
  dangerousCommands: DangerousPattern[];
  readOnlyCommands: string[];
  countdownSeconds: number;
  safetySnapshotDefault: boolean;
}

export interface PolicyCatalog {
  actions: { kind: ActionKind; label: string }[];
  defaults: PolicyRules;
  maxBulkThreshold: number;
  maxCountdownSeconds: number;
}

export interface PolicySaved {
  rules: PolicyRules;
  /** What changed, as written to the audit log. Empty: nothing was saved. */
  changes: string[];
}

/** BX-02: how long the job journal keeps job outputs and command text. */
export type Retention = "days30" | "days90" | "year" | "forever";

/** BX-02: what a retention purge removed. */
export interface PurgeReport {
  at: string;
  retention: Retention;
  /** Jobs created before this lost their outputs and command text; null when kept forever. */
  before: string | null;
  removed: { jobs: number; outputs: number; commands: number; bytes: number };
  /** Older commands that had something that looked like a secret, now [redacted]. */
  redacted: number;
  /** The database file was compacted afterwards. */
  compacted: boolean;
  byHand: boolean;
}

export interface RetentionInfo {
  retention: Retention;
  /** The last purge since Remotely started (one runs at start and daily). */
  lastPurge: PurgeReport | null;
}

/** AP-05: what an audit export wrote. */
export interface AuditExport {
  path: string;
  entries: number;
  /** Rows where something that looked like a secret was replaced by [redacted]. */
  redacted: number;
}

/** FD-03: presentation mode and its read-only lock, as saved. The lock applies while presenting. */
export interface Presentation {
  enabled: boolean;
  readOnly: boolean;
}

export interface Settings {
  /** What the user chose; null means "find vmrun.exe automatically". */
  vmrunPathSaved: string | null;
  /** What the app is using now; null means Workstation was not found. */
  vmrunPathInUse: string | null;
  /** VM-21: the ovftool.exe path chosen; null: found beside vmrun.exe. */
  ovftoolPathSaved: string | null;
  /** VM-21: the ovftool.exe in use; null: not found, so OVA and OVF imports into Workstation can't run. */
  ovftoolPathInUse: string | null;
  /** VM-18: what the user chose; null means "find VBoxManage.exe automatically". */
  vboxmanagePathSaved: string | null;
  /** VM-18: what the app is using now; null means VirtualBox was not found. */
  vboxmanagePathInUse: string | null;
  /** FD-14: check GitHub Releases for updates (off at air-gapped sites). */
  updateChecks: boolean;
  /** FD-14: the GitHub update token in the vault. Never the token itself. */
  updateToken: UpdateTokenInfo;
  /** VM-01: folders scanned for .vmx files, besides Workstation's library. */
  scanFolders: string[];
  /** VM-06: how many VMs may power on at once (1 to 32, default 3). */
  powerOnLimit: number;
  /** VM-03: seconds a soft stop may take before the VM counts as still running (default 120). */
  shutdownWaitSecs: number;
  /** BX-02: how many hosts a bulk run reaches at once (1 to 50, default 10). */
  bulkParallelLimit: number;
  /** CT-02: the docker.exe the user chose; null: find it. */
  dockerPathSaved: string | null;
  /** CT-02: the docker.exe in use; null: Docker Desktop was not found. */
  dockerPathInUse: string | null;
  /** MO-02: seconds between two dashboard polls of each watched host over SSH: 5 (default), 15, 30 or 60. */
  guestPollSecs: number;
}

/** SS-04. */
export type VaultStatus = "notSetUp" | "locked" | "unlocked";

/** SS-04: what the UI may know about the vault. Never a secret. */
export interface VaultInfo {
  status: VaultStatus;
  /** The Windows login unlocks the vault. The vault password always does. */
  windowsLogin: boolean;
  /** This PC can protect the vault key with the Windows login (DPAPI). */
  windowsLoginAvailable: boolean;
  /** The vault locks itself after this many minutes without use. */
  idleLockMinutes: number;
}

/** SS-04, FD-07: how hard a new vault password or export passphrase is to guess. The core checks again on submit. */
export interface PasswordStrength {
  /** 0 (guessed at once) to 4 (very hard to guess); at most 2 while the length is wrong. */
  score: number;
  /** The core would take it as a new vault password or export passphrase. */
  acceptable: boolean;
  /** Why it is weak, or how strong it is. Never quotes the password; empty for an empty one. */
  hint: string;
}

export type SecretKind = "password" | "privateKey" | "passphrase";

/** A vault item as the UI sees it: its label and kind, never its value. */
export interface SecretMeta {
  id: string;
  kind: SecretKind;
  label: string;
  /** Sessions that use it. */
  usedBy: number;
  createdAt: string;
  updatedAt: string;
}

/** SS-01: a session's colour, named so each theme can draw it. */
export type SessionColor = "red" | "orange" | "amber" | "green" | "teal" | "blue" | "violet" | "pink" | "slate";

/** How a session logs in. Credentials are vault IDs. */
export type SessionAuth =
  /** No password chosen: the terminal asks when it connects (SS-03). */
  | { method: "password"; passwordId: string | null }
  | { method: "key"; keyId: string | null; passphraseId: string | null }
  | { method: "agent" }
  /** QL-16: as the session's folders say (a session's own choice; what applies to it is never this). */
  | { method: "folder" };

/** What the session editor sends; the core checks and tidies it. */
export interface SessionInput {
  /** Empty: the host is used. */
  name: string;
  folderId: string | null;
  host: string;
  port: number;
  username: string | null;
  auth: SessionAuth;
  /** null: as its folders say (QL-16), unless jumpDirect. */
  jumpSessionId: string | null;
  /** QL-16: no jump host, whatever its folders set. */
  jumpDirect: boolean;
  startupCommand: string | null;
  /** SS-01: type the startup command again after an automatic reconnect (off: only on connections the user opens). */
  startupOnReconnect: boolean;
  /** SS-08: the folder prompt hook. null follows Settings (off for a Prod session). */
  promptHook: boolean | null;
  /** SS-06: Prod raises the approval tier by one. */
  environment: Environment;
  color: SessionColor | null;
  tags: string[];
  /** BX-01: the VM this session reaches (its id), so a bulk run can pick the VM. */
  vmId: string | null;
}

/** QL-16: the folder a value comes from. */
export interface FromFolder {
  id: string;
  name: string;
}

/** QL-16: which folder gives each value a session doesn't set itself (null: its own, or the app's default). */
export interface Inherited {
  username: FromFolder | null;
  auth: FromFolder | null;
  jump: FromFolder | null;
  environment: FromFolder | null;
  /** Tags from folders the session doesn't have itself. */
  tags: { tag: string; folder: FromFolder }[];
}

/** QL-16: what a session sets itself, of what a folder can set too (what the editor edits). */
export interface OwnValues {
  /** null: from its folders. */
  username: string | null;
  /** "folder": from its folders. */
  auth: SessionAuth;
  jumpSessionId: string | null;
  jumpDirect: boolean;
  /** "none": from its folders. */
  environment: Environment;
  tags: string[];
}

/** QL-16: what applies to a session in a folder that sets nothing itself (the editor's "from folder X"). */
export interface Effective {
  username: string | null;
  auth: SessionAuth;
  jumpSessionId: string | null;
  environment: Environment;
  tags: string[];
  inherited: Inherited;
}

/**
 * A saved session. QL-16: username, auth, jumpSessionId, environment and tags are what applies to it (its own values,
 * then its folders', then the app's); `own` is what it sets itself, and `inherited` names the folders that give the
 * rest.
 */
export interface SessionRecord extends SessionInput {
  id: string;
  protocol: string;
  own: OwnValues;
  inherited: Inherited;
  /** AP-04: bulk actions skip it. */
  protected: boolean;
  /** QL-01: how vmId was set. null: no decision yet, so auto-linking may link it. */
  vmLink: VmLink | null;
  importedFrom: string | null;
  createdAt: string;
  updatedAt: string;
  /** QL-03: the IP address the last connection reached. */
  lastIp: string | null;
  /** QL-03: the server's own name at the last connection (or its DNS name when it didn't say). */
  lastHostname: string | null;
  lastSeenAt: string | null;
  /** QL-02: when a terminal to it was last opened (Recent sessions). */
  lastOpenedAt: string | null;
}

/** QL-16: what a folder sets for the sessions in it and its subfolders. null (or empty): the folder above decides. */
export interface FolderDefaults {
  username: string | null;
  /** Never "folder". */
  auth: SessionAuth | null;
  jumpSessionId: string | null;
  /** No jump host for its sessions, whatever a folder above sets. */
  jumpDirect: boolean;
  /** Never "none": a folder adds a label, it can't take one off. */
  environment: Environment | null;
  tags: string[];
}

export const NO_FOLDER_DEFAULTS: FolderDefaults = {
  username: null,
  auth: null,
  jumpSessionId: null,
  jumpDirect: false,
  environment: null,
  tags: [],
};

export interface SessionFolder {
  id: string;
  /** null: at the top level. */
  parentId: string | null;
  name: string;
  sortOrder: number;
  /** QL-16. */
  defaults: FolderDefaults;
}

/** SS-01 search. Empty fields match everything. */
export interface SessionFilter {
  /** Case-insensitive text in the name, host, user, startup command or a tag. */
  text?: string;
  tags?: string[];
  environments?: Environment[];
  /** Only sessions in this folder or the folders under it. */
  folderId?: string | null;
}

/** SS-05: a key a server presented. */
export interface HostKey {
  host: string;
  port: number;
  /** e.g. "ssh-ed25519". */
  keyType: string;
  /** "SHA256:" and the base64 digest, as OpenSSH prints it. */
  fingerprint: string;
}

/** SS-05: a trusted host key. */
export interface KnownHost {
  id: string;
  host: string;
  port: number;
  keyType: string;
  fingerprint: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

/** SS-03: what a terminal pane is doing. */
export type TerminalStatus =
  /** attempt 0: a first or manual connection; 1 and up: automatic reconnects. */
  | { state: "connecting"; attempt: number }
  | { state: "connected" }
  | { state: "reconnecting"; attempt: number; maxAttempts: number; seconds: number; reason: string }
  /** The remote shell ended; Enter or Reconnect starts a new one. */
  | { state: "ended"; exitStatus: number | null }
  /** Not connected and not trying. `code` says why (host_key_changed, auth_failed, vault_locked, ...). */
  | { state: "disconnected"; code: string; message: string }
  | { state: "closed" };

/** QL-03: "dns" is what the session says, filled in by DNS; "host" is the host itself. */
export type FactSource = "dns" | "host";

/** QL-03: a terminal's host name and address, e.g. web01 · 192.0.2.10. */
export interface HostFacts {
  hostname: string | null;
  hostnameFrom: FactSource | null;
  ip: string | null;
  ipFrom: FactSource | null;
  /** SS-07: the jump hosts the connection goes through, by session name, first one first; empty when direct. */
  via: string[];
}

export type TerminalEvent =
  | { event: "status"; status: TerminalStatus }
  /**
   * SS-05: first connection to a host; answer with `terminalHostKeyAnswer`. `jump`: SS-07, the jump host on the way
   * that presented it, or null for the session's own host.
   */
  | { event: "hostKeyUnknown"; key: HostKey; otherKeyTypes: string[]; jump: string | null }
  /** SS-05: the key changed and the connection was blocked. `jump` as above. */
  | { event: "hostKeyChanged"; key: HostKey; previous: KnownHost; jump: string | null }
  /** SS-07: the terminal's tunnels, after any of them changed. */
  | { event: "tunnels"; tunnels: TunnelInfo[] }
  /** QL-03: what is known about the host so far. */
  | { event: "host"; facts: HostFacts }
  /** QL-07: a command that ran at least the threshold ended (its prompt came back, or its output stopped). */
  | { event: "commandFinished"; afterSecs: number; how: FinishedHow }
  /** SS-08: the shell's folder, or how far it is known (each connection starts over). */
  | { event: "folder"; folder: FolderInfo }
  /** SS-11: the session log could not be written (a full disk, say), so it stopped. */
  | { event: "logStopped"; path: string; reason: string }
  /** QL-17: an alert rule matched (one event per burst of matching lines). */
  | { event: "alert"; alert: TerminalAlert };

// ---- SS-07 port forwards and tunnels ----

/** local: a port on this PC to a host the session's host reaches; remote: a port on the host back here; dynamic: SOCKS. */
export type ForwardKind = "local" | "remote" | "dynamic";

/** SS-07: a saved port forward of a session. */
export interface PortForward {
  id: string;
  sessionId: string;
  label: string | null;
  kind: ForwardKind;
  /** Where it listens: on this PC (local, SOCKS) or on the host (remote). */
  bindAddress: string;
  /** 0: any free port, shown once it listens. */
  bindPort: number;
  /** Where it leads; empty for SOCKS. */
  destHost: string;
  destPort: number;
  /** Opens when the session's terminal connects (through the approval flow). */
  autoStart: boolean;
}

/** What the session dialog sends for one forward. `id` keeps an existing one; null adds one. */
export interface ForwardInput {
  id: string | null;
  label: string | null;
  kind: ForwardKind;
  /** Empty: 127.0.0.1 on this PC, localhost on the host. */
  bindAddress: string;
  bindPort: number;
  destHost: string;
  destPort: number;
  autoStart: boolean;
}

export type TunnelState =
  | { state: "stopped" }
  /** The approval waits for an answer (`terminalTunnelRequest` gives it). */
  | { state: "asking" }
  | { state: "opening" }
  | { state: "listening"; at: string }
  /** Approved; the terminal is reconnecting and it opens again then. */
  | { state: "waiting"; reason: string }
  | { state: "failed"; message: string };

/** SS-07: one tunnel of a terminal. */
export interface TunnelInfo {
  forward: PortForward;
  state: TunnelState;
  /** Connections it carried since it opened, and open now. */
  connections: number;
  open: number;
  /** Why the last connection through it failed. */
  lastError: string | null;
  /** Still one of the session's saved forwards. */
  saved: boolean;
  /** The saved forward was edited since it opened: stop and start it to use the edit. */
  changed: boolean;
}

export type TunnelStart = { status: "opening"; jobId: string } | { status: "needsApproval"; request: ApprovalRequest };

// ---- SS-08 file transfer ----

/**
 * SS-08: how the terminal knows its shell's folder. "following": the shell reports it (bash and zsh, through Remotely's
 * hook); "unsupported": another shell; "missed": bash or zsh, but something was typed before the hook could be set up
 * (a reconnect tries again); "off": the hook is turned off (Settings, the session, or a Prod session).
 */
export type FolderTracking = "waiting" | "following" | "unsupported" | "missed" | "off";

export interface FolderInfo {
  path: string | null;
  tracking: FolderTracking;
  /** QL-09: who transfers run as, and who the shell runs as when that differs. */
  user: ShellUsers;
}

/**
 * QL-09: `username` is the SSH login, which every transfer runs as. `shell` is the shell's user when it is known to be
 * someone else: reported by Remotely's prompt hook, or (`seenIn: "prompt"`) only named by the shell's prompt.
 * `stopped`: the hook's shell stopped reporting after a command (su, sudo -i, bash, ssh), so the drawer can't follow.
 * The fields are named `username` so presentation mode learns them.
 */
export interface ShellUsers {
  username: string | null;
  shell: { username: string; seenIn: "hook" | "prompt" } | null;
  stopped: boolean;
}

/** SS-08: a link counts as what it points to, with `link` set; "other": a device, socket or broken link. */
export type EntryKind = "file" | "folder" | "other";

export interface RemoteEntry {
  name: string;
  kind: EntryKind;
  link: boolean;
  size: number;
  /** Seconds since 1970. */
  modified: number | null;
  /** Permission bits, e.g. 0o644. */
  mode: number | null;
}

export interface FolderListing {
  /** Also when the folder could not be opened (QL-09). */
  path: string;
  parent: string | null;
  entries: RemoteEntry[];
  /** QL-09: why the folder could not be opened; `code` is the core's (`permission_denied`, `not_found`, ...). */
  error: { code: string; message: string } | null;
  /** QL-09: where Back goes. */
  back: string | null;
}

export interface StagedFiles {
  id: string;
  files: { name: string; size: number }[];
  total: number;
}

/** SS-08: what to do with files already in the folder. */
export type Existing = "ask" | "replace" | "skip";

export type UploadStart =
  | { status: "conflicts"; existing: string[]; folder: string }
  | { status: "submitted"; outcome: SubmitOutcome }
  /** Every file was there already and skipped. */
  | { status: "nothing" };

export type TransferState = "queued" | "running" | "done" | "failed" | "cancelled";

export interface TransferInfo {
  id: string;
  jobId: string | null;
  terminalId: string;
  terminal: string;
  direction: "upload" | "download";
  name: string;
  remotePath: string;
  localPath: string | null;
  size: number;
  done: number;
  bytesPerSec: number;
  state: TransferState;
  message: string | null;
  sha256: string | null;
  replace: boolean;
}

export type Retried = { kind: "upload"; start: UploadStart } | { kind: "download"; transfers: TransferInfo[] };

/** SS-08: files dropped on the window, staged by the shell; x and y in CSS pixels. */
export interface DroppedFiles {
  staged: StagedFiles | null;
  error: string | null;
  x: number;
  y: number;
}

/** QL-07: how a long command was seen to end. */
export type FinishedHow = "prompt" | "quiet";

/** QL-04: "auto" checks libraries of up to 200 sessions. */
export type ReachabilityMode = "auto" | "on" | "off";

/** QL-07: which finished commands notify while the tab is not on screen or Remotely is not in front. */
export type NotifyWhen = "long" | "any";

/** SS-03, QL-04, QL-05 settings. */
export interface TerminalSettings {
  /** Seconds without traffic before a keep-alive; 0: off. */
  keepaliveSecs: number;
  autoReconnect: boolean;
  copyOnSelect: boolean;
  /** QL-05: points, 8 to 32. */
  fontSize: number;
  /** QL-05: lines, 1000 to 100000. */
  scrollback: number;
  reachability: ReachabilityMode;
  /** QL-04: seconds between two checks of a host that is up, 15 to 3600 (300 unless chosen); a host down waits longer. */
  reachabilitySecs: number;
  /** QL-07: a Windows notification when a command in a background tab finishes. */
  notifyFinished: boolean;
  /** QL-07: long commands only, or any command that finishes while away. */
  notifyWhen: NotifyWhen;
  /** QL-07: seconds a command must run to count as long, 5 to 3600. */
  notifyAfterSecs: number;
  /** QL-07: seconds without output that end a command whose prompt is not recognised; 0: wait for the prompt. */
  notifyQuietSecs: number;
  /** SS-08: type the folder prompt hook into bash and zsh (a session can say otherwise; Prod: off unless it does). */
  promptHook: boolean;
  /** QL-05: ask before pasting text that holds a line break (see paste.ts). */
  confirmMultilinePaste: boolean;
}

// ---- BX-08 command panel ----

/** BX-08: a `{{variable}}` asked when a command is pasted. */
export interface CommandVariable {
  name: string;
  default: string | null;
}

/** BX-08: what the policy engine makes of a command with the current rules (BX-06). */
export interface CommandRisk {
  action: Extract<ActionKind, "execReadOnly" | "execOther" | "execDangerous">;
  /** The dangerous-command rules it matches, by name. */
  dangerous: string[];
}

/** SS-01: a startup command rated like a run on its session (a Prod session raises the tier). */
export interface StartupRating extends CommandRisk {
  tier: Tier;
}

/** BX-08: a saved command. */
export interface Favourite {
  id: string;
  /** null: at the top level. */
  folder: string | null;
  name: string;
  command: string;
  description: string | null;
  variables: CommandVariable[];
  risk: CommandRisk;
  createdAt: string;
  updatedAt: string;
}

export interface FavouriteInput {
  folder: string | null;
  name: string;
  command: string;
  description: string | null;
}

/** QL-19: one session of a saved MultiExec group. */
export interface GroupMember {
  sessionId: string;
  name: string;
}

/** QL-19: a saved MultiExec group: a named set of saved sessions, in order. */
export interface MultiExecGroup {
  id: string;
  name: string;
  members: GroupMember[];
  createdAt: string;
  updatedAt: string;
}

/** QL-19: what the group editor sends. 1 to 60 characters; 1 to 100 saved sessions. */
export interface GroupInput {
  name: string;
  sessionIds: string[];
}

/** QL-17: how a rule colours what it matches: the text in the colour, or the colour behind it. */
export type RuleStyle = "text" | "fill";

/** QL-17: which terminals a rule applies to. */
export type RuleScope =
  | { kind: "global" }
  | { kind: "environment"; environment: Exclude<Environment, "none"> }
  | { kind: "session"; sessionId: string };

/** QL-17: a highlight and alert rule. */
export interface TerminalRule {
  /** `builtin:<key>` for a built-in rule, else the rule's id. */
  id: string;
  builtin: boolean;
  name: string;
  /** A regular expression both Rust and JavaScript (with the u flag) read alike; the core checks it. */
  pattern: string;
  caseSensitive: boolean;
  /** null: no highlight, the rule only alerts. */
  color: SessionColor | null;
  style: RuleStyle;
  alert: boolean;
  scope: RuleScope;
  enabled: boolean;
  /** Why a saved pattern can't be used any more (saved by another version): it neither highlights nor alerts. */
  problem: string | null;
  updatedAt: string | null;
}

export interface TerminalRuleInput {
  name: string;
  pattern: string;
  caseSensitive: boolean;
  color: SessionColor | null;
  style: RuleStyle;
  alert: boolean;
  scope: RuleScope;
  enabled: boolean;
}

/** QL-17: the editor's live check of a pattern. */
export interface PatternCheck {
  valid: boolean;
  message: string | null;
}

/** QL-17: a burst of lines that matched an alert rule in one terminal (one event per burst, then a cooldown). */
export interface TerminalAlert {
  ruleId: string;
  ruleName: string;
  terminalId: string;
  /** null: a quick connection that was not saved. */
  sessionId: string | null;
  /** Lines that matched in this burst. */
  count: number;
  /** Lines that matched during the cooldown since the last alert. */
  suppressed: number;
  /** RFC 3339, UTC. */
  firstAt: string;
  lastAt: string;
  /** The first matching line, scrubbed of the terminal's secrets, at most 200 characters. */
  sample: string;
}

/** BX-08: the two sections of the library: symptom runbooks first, then groups by area. */
export type LibrarySection = "troubleshoot" | "area";

export type LibraryGroup =
  // Troubleshoot section (symptoms).
  | "slowHost"
  | "outOfMemory"
  | "diskFull"
  | "cantReachService"
  | "dnsFails"
  | "serviceWontStart"
  | "cantLoginSsh"
  | "clockWrong"
  | "certExpired"
  | "packageBroken"
  | "diskNotSeen"
  | "diskNotGrown"
  | "mountFails"
  | "iscsiMissing"
  // Area section.
  | "systemInfo"
  | "disk"
  | "diskSetup"
  | "mounts"
  | "storageLvm"
  | "storageSan"
  | "iscsi"
  | "findFiles"
  | "fileTransfer"
  | "memory"
  | "processes"
  | "network"
  | "services"
  | "logs"
  | "packagesApt"
  | "packagesDnf"
  | "users"
  | "security"
  | "certificates"
  | "firewall"
  | "webServers"
  | "databases"
  | "scheduling"
  | "timeSync"
  | "identity"
  | "vmwareGuest"
  | "docker"
  | "podman"
  | "kubernetes"
  | "helm";

/** BX-08: a built-in command, as one group shows it (a command can appear in a symptom group too). */
export interface LibraryEntry {
  id: string;
  section: LibrarySection;
  sectionLabel: string;
  group: LibraryGroup;
  groupLabel: string;
  name: string;
  command: string;
  description: string;
  variables: CommandVariable[];
  risk: CommandRisk;
  /** QL-13: the address of the command's official manual page. */
  manual: string;
}

/** BX-08: a command's variables and risk, while it is typed. */
export interface CommandInfo {
  variables: CommandVariable[];
  risk: CommandRisk;
}

/** QL-02: what the New terminal form sends. A typed password goes to the core only. */
export interface QuickConnectRequest {
  /** A host name or address; user@host:port is taken apart. */
  host: string;
  port: number | null;
  username: string | null;
  auth: SessionAuth;
  password: string | null;
  save: { name: string; folderId: string | null; environment: Environment; color: SessionColor | null } | null;
  /** SS-04, AP-06: the vault password, when the core asked for it (`reauth_required`). */
  vaultPassword?: string;
}

/** QL-02: a quick connection that was not saved. Never holds a password. */
export interface QuickConnectEntry {
  id: string;
  host: string;
  port: number;
  username: string | null;
  auth: SessionAuth;
  usedAt: string;
}

/** QL-04 session tree. */
export type TreeGrouping = "folder" | "tag" | "label";

export interface TreeNode {
  /** Stable across reloads: folder:<id>, tag:<name>, label:prod, ... */
  key: string;
  kind: "folder" | "tag" | "label" | "other";
  name: string;
  environment: Environment | null;
  children: TreeNode[];
  /** Sessions directly in this group. */
  sessions: string[];
  /** Sessions in this group and below. */
  count: number;
}

export interface SessionTree {
  grouping: TreeGrouping;
  nodes: TreeNode[];
  /** Sessions outside any group (folder grouping). */
  sessions: string[];
  records: SessionRecord[];
}

/** QL-04 reachability (MO-08 lite). */
export interface Reachability {
  sessionId: string;
  state: "up" | "down";
  latencyMs: number | null;
  reason: string | null;
  checkedAt: string;
  /**
   * SS-07: the session is behind jump hosts; this is the first one's state (by name), the one this PC reaches. The
   * session itself is not checked from here.
   */
  via: string | null;
  /**
   * Not probed: this PC holds an SSH connection to the host (or to the first jump host) now, from a terminal, the
   * dashboard or the Containers page. `checkedAt` is when it was last seen open.
   */
  connected: boolean;
}

export interface ReachabilityUpdate {
  enabled: boolean;
  states: Reachability[];
}

/** SS-11: one terminal's text, as read from its buffer. */
export interface TerminalText {
  terminalId: string | null;
  title: string;
  text: string;
}

export type SaveLayout = "oneFile" | "filePerTerminal";

export interface SavedOutput {
  files: string[];
  terminals: number;
}

/** SS-02 import sources. */
export type ImportSource = "putty" | "puttyFile" | "mobaxterm" | "openssh" | "csv";

/** QL-10: how the import reads one format, made from its parser's own tables. */
export interface FormatGuide {
  source: ImportSource;
  title: string;
  intro: string[];
  sections: { heading: string; text: string[]; table: { headings: string[]; rows: string[][] } | null }[];
  /** The sample file's name, as the save dialog suggests it. */
  sampleName: string;
}

export type CandidateAuth = { method: "password" } | { method: "keyFile"; path: string } | { method: "agent" };

/** One session an import source has. */
export interface ImportCandidate {
  name: string;
  host: string;
  port: number;
  username: string | null;
  /** Folder path in the source, outermost first. */
  folder: string[];
  auth: CandidateAuth;
  startupCommand: string | null;
  /** Jump host as the source names it (SS-07 is v2). */
  jump: string | null;
  environment: Environment;
  color: SessionColor | null;
  tags: string[];
  /** What the import left out or changed. */
  notes: string[];
}

export type ImportRowStatus =
  | { kind: "new" }
  | { kind: "duplicate"; sessionId: string; sessionName: string }
  | { kind: "duplicateInImport"; row: number }
  | { kind: "nameConflict"; sessionId: string; renameTo: string };

export interface ImportRow {
  index: number;
  candidate: ImportCandidate;
  status: ImportRowStatus;
  /** Ticked by default. */
  selected: boolean;
  keyFile: { path: string; label: string; exists: boolean } | null;
  /** SS-01: the startup command's rating; it is imported only when its row is ticked for it. */
  startupRating: StartupRating | null;
}

export interface ImportSkipped {
  name: string;
  reason: string;
}

export interface ImportPreview {
  id: string;
  source: ImportSource;
  file: string | null;
  rows: ImportRow[];
  skipped: ImportSkipped[];
  warnings: string[];
}

export interface ImportReport {
  created: number;
  keysAdded: number;
  foldersCreated: number;
  /** SS-01: startup commands left out (their rows were not ticked for them). */
  startupLeftOut: number;
  problems: ImportSkipped[];
}

/** SS-09: a public key in OpenSSH's one-line form. Not secret. */
export interface PublicKeyInfo {
  /** e.g. "ssh-ed25519", "ssh-rsa". */
  algorithm: string;
  /** "<algorithm> <base64> <comment>", as it goes into authorized_keys. */
  line: string;
  /** "SHA256:...", as ssh-keygen -l prints it. */
  fingerprint: string;
  comment: string;
  /** RSA only. */
  bits: number | null;
}

/** SS-09: a private key in the vault, as the key manager shows it. */
export interface SshKey {
  id: string;
  label: string;
  /** Sessions that log in with it. */
  usedBy: number;
  createdAt: string;
  /** Remotely generated it. */
  generated: boolean;
  /** null until read from the private key (needs the vault unlocked). */
  public: PublicKeyInfo | null;
}

export type KeyType = "ed25519" | "rsa";

/** FD-07: what an export wrote. */
export interface ExportReport {
  path: string;
  folders: number;
  sessions: number;
  knownHosts: number;
  /** Vault items named in the file. */
  secrets: number;
  /** Their values are in the file too. */
  secretValues: boolean;
  /** BX-08 favourite commands. */
  favourites: number;
  /** SS-07 saved port forwards, over all sessions. */
  forwards: number;
  /** QL-16 folders with defaults. */
  folderDefaults: number;
  /** QL-19 saved MultiExec groups. */
  groups: number;
  /** VM-19 to VM-21: own sizes, images and launch templates. */
  catalog: { sizes: number; images: number; templates: number };
}

export type TransferStatus = "new" | "same" | "conflict";
export type TransferAction = "import" | "skip" | "replace" | "keepBoth";

/** FD-07: one session, known host or secret of an export, compared with this laptop. */
export interface TransferItem {
  index: number;
  name: string;
  detail: string;
  status: TransferStatus;
  /** What it matches here, and how. */
  conflict: string | null;
  choices: TransferAction[];
  defaultAction: TransferAction;
  notes: string[];
  /** SS-01: a session's startup command and its rating; imported only when ticked. */
  startupCommand?: string;
  startupRating?: StartupRating;
  /** SS-07: a session's saved port forwards, described; imported only when ticked. */
  forwards?: string[];
}

export interface TransferPreview {
  id: string;
  file: string;
  exportedAt: string;
  exportedBy: string;
  folders: number;
  newFolders: number;
  sessions: TransferItem[];
  knownHosts: TransferItem[];
  secrets: TransferItem[];
  secretValues: boolean;
  /** BX-08 favourite commands. */
  favourites: TransferItem[];
  /** QL-16: the file's folders that set defaults, compared with the folder at the same place here. */
  folderDefaults: TransferItem[];
  /** QL-19 saved MultiExec groups. */
  groups: TransferItem[];
  /** VM-19 to VM-21: own sizes, images (by path) and launch templates. */
  catalog: { sizes: TransferItem[]; images: TransferItem[]; templates: TransferItem[] };
  warnings: string[];
}

export interface TransferChoice {
  index: number;
  action: TransferAction;
}

export interface TransferCounts {
  added: number;
  replaced: number;
  keptBoth: number;
  skipped: number;
}

export interface TransferReport {
  sessions: TransferCounts;
  knownHosts: TransferCounts;
  secrets: TransferCounts;
  favourites: TransferCounts;
  /** QL-19 saved MultiExec groups. */
  groups: TransferCounts;
  /** VM-19 to VM-21; imagesMissingHere: imported without their file (or golden VM) on this laptop. */
  catalog: { sizes: TransferCounts; images: TransferCounts; templates: TransferCounts; imagesMissingHere: number };
  /** SS-07: port forwards saved with the imported sessions. */
  forwards: number;
  /** SS-01, SS-07: startup commands and port forwards in the file that were not ticked. */
  startupLeftOut: number;
  forwardsLeftOut: number;
  foldersAdded: number;
  /** QL-16: folder defaults taken from the file. */
  folderDefaults: TransferCounts;
  /** Sessions imported without the password or key they used. */
  withoutCredentials: number;
  problems: { name: string; reason: string }[];
}

// ---- VM-19 to VM-21: the spec catalogue (sizes, OS profiles, images, launch templates) ----

export type Provisioning = "thin" | "thick";
export type DiskController = "scsi" | "sata" | "nvme" | "ide";

export interface DiskSpec {
  sizeGb: number;
  provisioning: Provisioning;
  /** null: the OS profile's controller. */
  controller: DiskController | null;
}

/** VM-19: a size. Built-ins go by their name and are read only; own sizes go by a UUID. */
export interface Size {
  id: string;
  name: string;
  builtIn: boolean;
  sockets: number;
  coresPerSocket: number;
  memoryMb: number;
  /** The first is the boot disk. */
  disks: DiskSpec[];
  description: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface SizeInput {
  name: string;
  sockets: number;
  coresPerSocket: number;
  memoryMb: number;
  disks: DiskSpec[];
  description: string | null;
}

export type Firmware = "bios" | "efi" | "efiSecureBoot";

/** VM-19: what the guest needs, per hypervisor. */
export interface OsProfile {
  id: string;
  name: string;
  family: "linux" | "windows";
  firmware: Firmware;
  /** null: not on Workstation (workstationNote says why). */
  workstation: {
    guestOs: string;
    hardwareVersion: number;
    controller: DiskController;
    scsiAdapter: string | null;
    nic: string;
  } | null;
  virtualbox: { osType: string; controller: DiskController; controllerModel: string; nic: string; tpm: string | null };
  workstationNote: string | null;
}

export type ImageKind = "goldenVm" | "cloudImage" | "iso" | "appliance";
export type ImageFormat = "vmdk" | "ova" | "ovf" | "raw" | "qcow2" | "iso";

export type ImageSource =
  | { kind: "goldenVm"; vmKey: string; snapshotId: string; snapshotName: string }
  | { kind: "cloudImage"; path: string; format: ImageFormat }
  | { kind: "iso"; path: string }
  | { kind: "appliance"; path: string; format: ImageFormat };

/** VM-20: an image. */
export interface Image {
  id: string;
  name: string;
  source: ImageSource;
  hypervisors: Hypervisor[];
  osProfile: string;
  /** Of the file when it was added; null for a golden VM. */
  sha256: string | null;
  sizeBytes: number | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
  /** Why it can't deploy now; null when it can. */
  problem: string | null;
  /** A golden VM's name in the VM list. */
  vmName: string | null;
}

export type ImageSourceInput =
  | { kind: "goldenVm"; vmKey: string; snapshot: string }
  | { kind: "cloudImage"; path: string }
  | { kind: "iso"; path: string }
  | { kind: "appliance"; path: string };

export interface ImageInput {
  name: string;
  source: ImageSourceInput;
  /** Empty: every hypervisor it can deploy on. */
  hypervisors: Hypervisor[];
  osProfile: string;
  notes: string | null;
}

export interface ImageEdit {
  name: string;
  hypervisors: Hypervisor[];
  osProfile: string;
  notes: string | null;
}

/** An official cloud image download page (an allow-list in the core). */
export interface ImageSite {
  id: string;
  name: string;
  url: string;
  hint: string;
}

export interface HashProgress {
  request: string;
  done: number;
  total: number;
}

export type TemplateNetwork =
  | { kind: "nat" }
  | { kind: "hostOnly" }
  | { kind: "bridged" }
  | { kind: "vmnet"; number: number }
  | { kind: "natNetwork"; name: string }
  | { kind: "internal"; name: string };

export interface AfterDeploy {
  createSession: boolean;
  linkSession: boolean;
  cleanSnapshot: boolean;
  openConsole: boolean;
}

/** VM-21: what the template editor sends. */
export interface TemplateInput {
  name: string;
  imageId: string;
  sizeId: string;
  hypervisor: Hypervisor;
  vmFolder: string | null;
  network: TemplateNetwork;
  sshKeyId: string | null;
  namingPattern: string;
  defaultCount: number;
  environment: Environment;
  tags: string[];
  afterDeploy: AfterDeploy;
  /** VM-22: the user cloud-init makes, with sudo and the SSH key; null: the image's default user. */
  guestUser: string | null;
  /** VM-22: packages cloud-init installs on first boot. */
  packages: string[];
  /** VM-21: how a golden VM image is cloned. */
  cloneMode: CloneMode;
}

export type CloneMode = "full" | "linked";

export type ProblemCode =
  | "imageGone"
  | "imageUnavailable"
  | "needsConversion"
  | "unknownProfile"
  | "sizeGone"
  | "hypervisorMismatch"
  | "notOnHypervisor"
  | "networkMismatch"
  | "keyGone"
  | "keyNotRead"
  | "patternNeedsNumber"
  | "countOutOfRange"
  | "nameTaken";

export interface TemplateProblem {
  code: ProblemCode;
  message: string;
}

export interface LaunchTemplate extends TemplateInput {
  id: string;
  createdAt: string;
  updatedAt: string;
  /** Why it can't deploy now; empty when it can. */
  problems: TemplateProblem[];
}

export interface PlannedVm {
  number: number;
  name: string;
  hostname: string;
}

export interface TemplatePreview {
  problems: TemplateProblem[];
  vms: PlannedVm[];
}

// ---- VM-21, VM-22, VM-10: deploy ----

export type DeployFrom = { kind: "template"; id: string } | { kind: "custom"; input: TemplateInput };

export interface DeployRequest {
  from: DeployFrom;
  count: number;
  /** The dialog's naming pattern, when it isn't the template's. */
  namingPattern?: string | null;
  /** VirtualBox's host-only or bridged adapter; null: the first. */
  hostAdapter?: string | null;
  /** VirtualBox, an ISO it installs by itself: the vault password its guest user gets; null: install from the console. */
  guestPasswordId?: string | null;
}

/** VM-10: one full clone of each picked VM. */
export interface CloneRequest {
  vmKeys: string[];
  /** `{template}` is each VM's name. */
  namingPattern: string;
  /** null: the hypervisor's default folder. */
  folder?: string | null;
  /** null: the strictest of the VMs' labels. */
  environment?: Environment | null;
}

export type DeployOrigin =
  { kind: "template"; id: string; name: string } | { kind: "custom"; name: string } | { kind: "bulkClone" };

export interface DeployDisk {
  sizeGb: number;
  provisioning: Provisioning;
  controller: DiskController;
  controllerModel: string;
}

export interface DeploySize {
  id: string;
  name: string;
  sockets: number;
  coresPerSocket: number;
  memoryMb: number;
  disks: DeployDisk[];
}

export interface DeployPreviewVm {
  name: string;
  hostname: string;
  folder: string;
  cloneOf: string | null;
  /** Thin disks at their full size; null when it isn't known. */
  diskBytes: number | null;
  thickBytes: number;
  problem: string | null;
}

/** AP-02 for a deploy. */
export interface DeployPreview {
  summary: string;
  origin: DeployOrigin;
  hypervisor: Hypervisor;
  source: string;
  folder: string;
  size: DeploySize | null;
  network: string | null;
  hostAdapter: string | null;
  environment: Environment;
  tags: string[];
  firstBoot: { user: string | null; keyFingerprint: string | null; packages: string[] } | null;
  afterDeploy: AfterDeploy;
  vms: DeployPreviewVm[];
  diskBytes: number;
  thickBytes: number;
  freeBytes: number | null;
  notes: string[];
  warnings: string[];
  /** Why it can't run as it is. */
  refusals: string[];
}

export interface DeployCheck {
  problems: TemplateProblem[];
  preview: DeployPreview | null;
}

/** BX-01: what is picked: tabs and tree sessions for Compare, sessions, VMs, tags and filters for a key push. */
export interface TargetPicks {
  sessionIds?: string[];
  /** Open terminals (picked tabs), each reached through its saved session. */
  terminalIds?: string[];
  vmPaths?: string[];
  tags?: string[];
  /** Saved VM filters, by id. */
  filterIds?: string[];
}

/** BX-01: a host a run reaches (a saved session). */
export interface BulkHost {
  sessionId: string;
  name: string;
  /** user@host:port */
  address: string;
  /** As the policy engine sees it: Prod when the session or its VM is. */
  environment: Environment;
  /** AP-04: skipped by the run. */
  protected: boolean;
  vmName: string | null;
  /** How it was picked: "session", "VM 'web01'", "tag 'web'", "filter 'Lab'". */
  via: string[];
}

export interface VmWithoutSession {
  vmxPath: string;
  name: string;
  via: string[];
}

/** A4, H11: a picked VM reached only through a session linked automatically (by the guest's own IP). */
export interface UnconfirmedLink {
  vmxPath: string;
  name: string;
  sessionId: string;
  sessionName: string;
  /** `user@host:port` of the session. */
  address: string;
  via: string[];
}

export interface ResolvedTargets {
  hosts: BulkHost[];
  /** Picked VMs no session reaches; guest commands without SSH (VM-09) come in v2. */
  vmsWithoutSession: VmWithoutSession[];
  /** A4, H11: picked VMs whose only link is automatic: not reached until the user confirms it. */
  vmsUnconfirmed: UnconfirmedLink[];
  notes: string[];
}

/** BX-06: what a command would need, without submitting it. */
export interface CommandPreview {
  action: ActionKind;
  tier: Tier;
  steps: ApprovalStep[];
  targets: number;
  skipped: Target[];
  reasons: string[];
  dangerous: DangerousMatch[];
}

export interface GroupOptions {
  /** Spaces and tabs at line ends, and blank lines at the end, don't make outputs differ. */
  ignoreTrailingWhitespace?: boolean;
}

export interface RunInfo {
  script: string;
  sudo: boolean;
  trustNewHostKeys: boolean;
  timeoutSecs: number | null;
}

export interface HostResult {
  targetKey: string;
  name: string;
  status: TargetStatus;
  exitCode: number | null;
  durationMs: number | null;
  error: string | null;
  errorCode: string | null;
  stdoutBytes: number | null;
  stderrBytes: number | null;
  truncated: boolean;
  /** Index into the groups; null while it waits or runs, or when cancelled. */
  group: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  /** The address this PC reached (a host reached directly). */
  peerIp: string | null;
  /** The host key the host presented and the run accepted: `ssh-ed25519 SHA256:...`. */
  hostKey: string | null;
}

/** BX-03: hosts with the same result. */
export interface OutputGroup {
  /** "A", "B", ... largest first. */
  label: string;
  /** output: the command ran; error: it failed before or around it (connection, login, sudo, time limit). */
  kind: "output" | "error";
  ok: boolean;
  exitCode: number | null;
  error: string | null;
  errorCode: string | null;
  messagesDiffer: boolean;
  /** Target keys. */
  hosts: string[];
  /** The host whose output stands for the group. */
  sample: string;
  /** null: too large to send with the results; load it with bulkHostOutput. */
  stdout: string | null;
  stderr: string | null;
  truncated: boolean;
}

export interface BulkCounts {
  total: number;
  pending: number;
  running: number;
  succeeded: number;
  failed: number;
  cancelled: number;
  /** H9: timed out, or cancelled while the command ran. */
  unknown: number;
  /** H9: never started (the run stopped after its failures or its canary). */
  skipped: number;
}

export interface BulkResults {
  job: JobSummary;
  run: RunInfo | null;
  counts: BulkCounts;
  hosts: HostResult[];
  groups: OutputGroup[];
  /** "48 hosts same, 2 differ". */
  headline: string;
  ignoreTrailingWhitespace: boolean;
  /** H9: the canary host finished and the rest wait for the go-ahead, until `until`. */
  canary: { name: string; rest: number; until: string } | null;
}

export interface HostOutput {
  targetKey: string;
  name: string;
  stdout: string;
  stderr: string;
  truncated: boolean;
  exitCode: number | null;
  error: string | null;
}

export interface DiffLine {
  kind: "same" | "removed" | "added";
  text: string;
}

export interface OutputDiff {
  left: string;
  right: string;
  leftExitCode: number | null;
  rightExitCode: number | null;
  stdout: DiffLine[];
  stderr: DiffLine[];
}

export type ExportFormat = "csv" | "json" | "html";

export interface BulkExport {
  path: string;
  format: ExportFormat;
  hosts: number;
  /** Texts where something that looked like a secret was replaced by [redacted]. */
  redacted: number;
}

export interface BulkLimits {
  maxScriptBytes: number;
  maxTimeoutSecs: number;
  maxParallel: number;
}

/** MO-01 host side (vmware-vmx.exe process, no login) or MO-02 guest side (/proc over SSH). */
export type MetricSource = "host" | "guest";

/** MO-02: space used on one mounted disk, from `df`. */
export interface MountUsage {
  mount: string;
  filesystem: string;
  totalBytes: number;
  usedBytes: number;
  usedPct: number;
}

export interface MetricSample {
  source: MetricSource;
  target: TargetRef;
  ts: string;
  /** Busy share of the machine's own CPUs: a VM's vCPUs (host side) or the guest's CPUs. */
  cpuPct: number | null;
  /** Host side: the VM process's share of this whole host's CPU, as Task Manager shows it. */
  hostCpuPct: number | null;
  /** Host side: the VM process's working set as a share of this host's physical RAM. */
  hostMemPct: number | null;
  /** Host side: the VM process's working set. Guest side: memory in use. */
  memBytes: number | null;
  /** Host side: RAM assigned to the VM. Guest side: the guest's total memory. */
  memTotalBytes: number | null;
  /** MO-15, guest side: swap in use and its size. */
  swapUsedBytes: number | null;
  swapTotalBytes: number | null;
  diskReadBps: number | null;
  diskWriteBps: number | null;
  netRxBps: number | null;
  netTxBps: number | null;
  load1: number | null;
  load5: number | null;
  load15: number | null;
  uptimeSecs: number | null;
  mounts: MountUsage[];
}

/** MO-01: one running VM's share of this host, for the VM list. */
export interface VmHostUsage {
  vmxPath: string;
  hostCpuPct: number | null;
  hostMemPct: number | null;
  /** The VM process's working set. */
  memBytes: number | null;
  ts: string;
}

/** MO-03 drill-down: one point of a chart, kept in memory for 30 minutes (MO-06's history on disk: dashboard-api.ts). */
export interface MetricPoint {
  /** Unix time in milliseconds. */
  t: number;
  cpuPct: number | null;
  memBytes: number | null;
  /** MO-15: the memory there is: a VM's configured RAM, a guest's or this PC's total. */
  memTotalBytes: number | null;
  /** MO-15: swap (Linux) or the paging files (this PC) in use, and their size. */
  swapUsedBytes: number | null;
  swapTotalBytes: number | null;
  diskReadBps: number | null;
  diskWriteBps: number | null;
  netRxBps: number | null;
  netTxBps: number | null;
  load1: number | null;
  diskUsedPct: number | null;
}

export type GuestState =
  "connecting" | "ok" | "vaultLocked" | "unreachable" | "loginFailed" | "hostKey" | "paused" | "noData" | "error";

/** MO-02: where guest polling stands for one watched session. */
export interface GuestStatus {
  sessionId: string;
  state: GuestState;
  /** What went wrong, for the user. Never holds a secret. */
  message: string | null;
  /** Seconds until the next try, while backing off. */
  retryInSecs: number | null;
  lastOk: string | null;
  /** No new login until the session or its credentials change, or the user presses Retry. */
  parked: boolean;
}

/** MO-01 NFR: what collecting costs. */
export interface CollectorCost {
  rounds: number;
  intervalSecs: number;
  /** MO-02: seconds between two polls of each watched host (the Settings value in force). */
  guestIntervalSecs: number;
  roundMs: number;
  hostMs: number;
  guestMs: number;
  /** This app's process over the last round, as a share of the whole host's CPU. */
  appCpuPct: number | null;
  vms: number;
  guests: number;
  collectedAt: string | null;
}

export interface LinkedSession {
  id: string;
  name: string;
  /** QL-01: linked automatically by IP address and not confirmed yet. */
  auto: boolean;
}

/** MO-03: a VM (host-side metrics, plus a watched linked session's guest metrics) or a watched host. */
export interface DashboardRow {
  kind: "vm" | "session";
  /** The VM's key (.vmx path or VirtualBox UUID) or the session id. */
  key: string;
  name: string;
  /** VM-18: a VM row's hypervisor; null for a session. */
  hypervisor: Hypervisor | null;
  environment: Environment;
  protected: boolean;
  tags: string[];
  powerState: PowerState | null;
  /** A VM's vCPUs; MO-13: a host's CPUs from its stored facts. */
  vcpus: number | null;
  /** A VM's configured RAM; MO-13: a host's RAM from its stored facts. */
  memsizeMb: number | null;
  /** A VM's IP, or a session's user@host:port. */
  address: string | null;
  guestOs: string | null;
  /** MO-13: when the host's (or the VM's linked session's) facts were read. */
  specsAt: string | null;
  host: MetricSample | null;
  guest: MetricSample | null;
  sessions: LinkedSession[];
  /** The session whose guest metrics the row shows. */
  watchedSession: string | null;
  guestStatus: GuestStatus | null;
}

export interface DashboardOverview {
  rows: DashboardRow[];
  cost: CollectorCost;
}

export type CapacityWarning =
  | { kind: "ram"; assignedMb: number; physicalMb: number }
  | { kind: "disk"; drive: string; freePct: number }
  | { kind: "unchecked"; message: string };

export interface DriveCapacity {
  drive: string;
  freeBytes: number;
  totalBytes: number;
  freePct: number;
  /** Under 10% free. */
  low: boolean;
  vms: number;
}

/** MO-04: assigned vs physical resources on this machine. */
export interface HostCapacity {
  physicalRamMb: number;
  availableRamMb: number | null;
  assignedRamMb: number;
  logicalCpus: number;
  assignedVcpus: number;
  hostCpuPct: number | null;
  runningVms: number;
  unsizedVms: number;
  drives: DriveCapacity[];
  /** MO-15: this PC's paging files and commit charge, from the last metrics round. */
  paging: PagingInfo | null;
  warnings: CapacityWarning[];
}

/** MO-15: one paging file of this PC. */
export interface PagingFile {
  path: string;
  totalBytes: number;
  usedBytes: number;
  peakBytes: number;
}

/** MO-15: this PC's paging files and commit charge (RAM plus paging files). */
export interface PagingInfo {
  files: PagingFile[];
  totalBytes: number;
  usedBytes: number;
  peakBytes: number;
  commitUsedBytes: number;
  commitLimitBytes: number;
}

/** MO-15: this PC's memory now. */
export interface ThisPcMemory {
  ramTotalBytes: number;
  ramUsedBytes: number;
  paging: PagingInfo | null;
}

/** MO-15: this PC's memory now and round by round (`memBytes`/`memTotalBytes`: RAM; `swap…`: paging files). */
export interface ThisPcSeries {
  latest: ThisPcMemory | null;
  points: MetricPoint[];
}

// ---- MO-13, MO-14: host details ----

export interface OsInfo {
  name: string | null;
  version: string | null;
  versionId: string | null;
  id: string | null;
  idLike: string | null;
  prettyName: string | null;
}

export interface CpuInfo {
  model: string | null;
  vendor: string | null;
  logicalCpus: number | null;
  sockets: number | null;
  coresPerSocket: number | null;
  threadsPerCore: number | null;
  maxMhz: number | null;
}

export interface MemoryInfo {
  totalBytes: number | null;
  availableBytes: number | null;
  swapTotalBytes: number | null;
  swapFreeBytes: number | null;
}

export interface SwapArea {
  path: string;
  kind: string;
  sizeBytes: number;
  usedBytes: number;
}

/** A disk, partition, LVM volume... from lsblk. */
export interface BlockDevice {
  name: string;
  kind: string;
  sizeBytes: number | null;
  fstype: string | null;
  mountpoint: string | null;
  model: string | null;
  rotational: boolean | null;
  transport: string | null;
  /** 0 a disk, 1 its partitions, 2 what sits on those. */
  depth: number;
}

export interface Filesystem {
  source: string;
  fstype: string | null;
  sizeBytes: number;
  usedBytes: number;
  availableBytes: number;
  usedPct: number;
  mount: string;
}

/** MO-13: a Linux host's OS and hardware. */
export interface HostSpecs {
  os: OsInfo;
  system: string | null;
  kernel: string | null;
  architecture: string | null;
  hostname: string | null;
  cpu: CpuInfo;
  memory: MemoryInfo;
  swaps: SwapArea[];
  disks: BlockDevice[];
  filesystems: Filesystem[];
  virtualization: string | null;
  uptimeSecs: number | null;
}

export type CollectedBy = "terminal" | "dashboard" | "refresh";

/** MO-13: a session's facts with when and how they were read. */
export interface SessionSpecs {
  sessionId: string;
  specs: HostSpecs;
  collectedAt: string;
  collectedBy: CollectedBy;
  bootedAt: string | null;
}

/** Which connection a read ran on. */
export type ReadVia = "terminal" | "dashboard" | "ownConnection";

export type ServiceManager = "systemd" | "openRc" | "sysV" | "unknown";
export type ServiceState = "running" | "failed" | "stopped" | "unknown";

export interface HostService {
  name: string;
  description: string | null;
  state: ServiceState;
  sub: string | null;
}

export interface ListeningPort {
  protocol: string;
  ip: string;
  port: number;
  interface: string | null;
  processes: string[];
  pids: number[];
}

export interface LoggedInUser {
  user: string;
  terminal: string;
  since: string;
  ip: string | null;
  host: string | null;
}

export interface BootEvent {
  kind: string;
  kernel: string | null;
  when: string;
}

export interface ProcessInfo {
  pid: number;
  user: string;
  cpuPct: number;
  memPct: number;
  rssBytes: number;
  elapsedSecs: number | null;
  command: string;
}

/** MO-14: an admin's view of a host, read on demand. */
export interface AdminDetails {
  serviceManager: ServiceManager;
  running: HostService[];
  failed: HostService[];
  otherServices: HostService[];
  ports: ListeningPort[];
  portsNeedRoot: boolean;
  users: LoggedInUser[];
  bootText: string | null;
  uptimeSecs: number | null;
  boots: BootEvent[];
  processCount: number;
  topCpu: ProcessInfo[];
  topMemory: ProcessInfo[];
  notLinux: boolean;
}

export interface AdminReport {
  sessionId: string;
  details: AdminDetails;
  collectedAt: string;
  via: ReadVia;
}

export interface PendingUpdate {
  name: string;
  version: string;
  current: string | null;
  source: string;
  security: boolean;
}

export interface UpdatesReport {
  manager: "apt" | "dnf" | null;
  packages: PendingUpdate[];
  securityCount: number;
  listsRefreshedUnix: number | null;
  error: string | null;
}

export interface UpdatesCheck {
  sessionId: string;
  report: UpdatesReport;
  checkedAt: string;
  tookMs: number;
  via: ReadVia;
}

export interface VirtualDisk {
  slot: string;
  path: string;
  format: string | null;
  provisionedBytes: number | null;
  onDiskBytes: number | null;
  files: number;
  delta: boolean;
  problem: string | null;
  /** VM-23: the controller's kind (pvscsi, SATA (AHCI), IntelAhci...). */
  controller: string | null;
  /** VM-23: thin or thick; null when unknown (a snapshot's delta). */
  thin: boolean | null;
  /** VM-23: a delta's parents down to the base disk, nearest first. */
  chain: string[];
}

export interface VirtualNic {
  slot: string;
  connection: string | null;
  model: string | null;
  /** FD-03: masked while presenting (`mac` is a field `learnFields` knows). */
  mac: string | null;
  /** Connected when the VM starts (VirtualBox: its cable). */
  connected: boolean | null;
  /** VM-11: the vnet, host adapter, NAT network or internal network. */
  networkName: string | null;
  /** VM-11: plugged in right now (VirtualBox; Workstation can't be asked). */
  connectedNow: boolean | null;
  staticMac: boolean;
}

export interface StorageController {
  name: string;
  kind: string | null;
  ports: number | null;
}

export interface VirtualCdrom {
  slot: string;
  image: string | null;
  hostDrive: string | null;
  connected: boolean | null;
}

export interface VirtualDisplay {
  videoMemoryMb: number | null;
  accelerate3d: boolean | null;
  monitors: number | null;
  controller: string | null;
}

export interface SerialPort {
  slot: string;
  kind: string;
  target: string | null;
}

export interface SharedFolder {
  name: string;
  hostPath: string;
  writable: boolean | null;
  enabled: boolean | null;
}

/** MO-13: a VM's virtual hardware from its hypervisor's files. */
export interface VmHardware {
  guestOs: string | null;
  guestOsName: string | null;
  guestKernel: string | null;
  vcpus: number | null;
  coresPerSocket: number | null;
  memoryMb: number | null;
  firmware: string | null;
  hardwareVersion: string | null;
  disks: VirtualDisk[];
  nics: VirtualNic[];
  // VM-23: the Settings tab.
  nestedVirtualization: boolean | null;
  /** null for BIOS. */
  secureBoot: boolean | null;
  tpm: string | null;
  controllers: StorageController[];
  cdroms: VirtualCdrom[];
  usb: string[];
  sound: string | null;
  display: VirtualDisplay | null;
  serialPorts: SerialPort[];
  sharedFolders: SharedFolder[];
  toolsVersion: string | null;
  guestIps: string[];
}

export interface VmSpecs {
  vmxPath: string;
  hypervisor: Hypervisor;
  hardware: VmHardware;
  collectedAt: string;
  /** The files could not be read now: this is what was read before. */
  stored: boolean;
  problem: string | null;
  /** The guest's own facts, from a linked session. */
  guest: SessionSpecs | null;
  guestSessionName: string | null;
}

/** FD-14: a newer signed release on GitHub. */
export interface UpdateInfo {
  currentVersion: string;
  version: string;
  notes: string | null;
  pubDate: string | null;
}

/**
 * FD-14: what an update check found, or why it found nothing. The releases are public, so checks run
 * without a token; the GitHub update token goes along when the vault can give it.
 */
export type UpdateCheck =
  | { status: "off" }
  /** GitHub doesn't show the releases without a token (the repository is private again), and there is none. */
  | { status: "tokenNeeded"; repository: string }
  /** Same, with the token in the vault, which is locked. Check again once it is unlocked. */
  | { status: "vaultLocked" }
  /** GitHub's API limit is used up; no call goes to GitHub before `until` (RFC 3339). */
  | { status: "rateLimited"; until: string; withToken: boolean }
  | { status: "upToDate" }
  | { status: "available"; update: UpdateInfo };

/** FD-14: what Settings may know about the GitHub update token. */
export interface UpdateTokenInfo {
  stored: boolean;
  /** YYYY-MM-DD, as GitHub last reported it; null before first use and for a token with no expiry. */
  expiresOn: string | null;
}

/** FD-14: what testing the token found. */
export interface TokenReport {
  /** owner/name of the repository whose releases the token can read. */
  repository: string;
  /** Tag of the latest published release, if any. */
  latestRelease: string | null;
  expiresOn: string | null;
}

/** FD-14: error codes that mean the token needs attention in Settings. */
export const UPDATE_TOKEN_ERRORS = [
  "update_token_refused",
  "update_token_no_access",
  "update_token_missing",
  "update_token_needed",
];

export interface AppInfo {
  version: string;
  workspaceId: string;
  userId: string;
  vmrunPath: string | null;
  /** VM-18: the VBoxManage.exe in use; null when VirtualBox was not found. */
  vboxmanagePath: string | null;
}

// ---- CT-01, CT-02 containers ----

export type EngineKind = "docker" | "podman";

/** Where containers run: a session marked as a container host, or Docker Desktop on this PC. */
export type ContainerHost = { kind: "session"; sessionId: string } | { kind: "thisPc" };

export type ContainerObject =
  | { kind: "container"; id: string }
  | { kind: "image"; id: string }
  | { kind: "volume"; name: string }
  /** The engine itself: pulls and prunes. */
  | { kind: "engine" };

export type PruneWhat = "containers" | "images" | "volumes" | "buildCache";

export type ContainerOp =
  | { kind: "start" }
  | { kind: "stop" }
  | { kind: "restart" }
  | { kind: "pause" }
  | { kind: "unpause" }
  /** `force`: a running container is killed first. */
  | { kind: "remove"; force: boolean }
  | { kind: "removeImage" }
  | { kind: "removeVolume" }
  | { kind: "pull"; reference: string }
  | { kind: "prune"; what: PruneWhat };

export type ContainerState =
  "created" | "running" | "paused" | "restarting" | "removing" | "exited" | "dead" | "unknown";

/** How sudo runs a host's engine. */
export type SudoMode =
  | { kind: "off" }
  /** sudo -S with this vault password, or the session's login password (null). */
  | { kind: "password"; passwordId: string | null }
  /** sudo -n: NOPASSWD in sudoers. */
  | { kind: "noPassword" };

export interface ContainerMark {
  sessionId: string;
  engine: EngineKind;
  sudo: SudoMode;
}

export interface MarkInput {
  engine: EngineKind;
  sudo: SudoMode;
}

export interface HostEngine {
  engine: EngineKind;
  sudo: SudoMode;
  /** "as the login user", "with sudo (the login password)"... */
  runs: string;
}

export interface ContainerHostInfo {
  host: ContainerHost;
  /** The session's name, or "This PC". */
  name: string;
  hostname: string | null;
  username: string | null;
  port: number | null;
  environment: Environment;
  protected: boolean;
  engines: HostEngine[];
  /** SS-07: the jump hosts on the way. */
  via: string[];
  /** CT-02: the docker.exe in use. */
  cliPath: string | null;
}

export interface PortMapping {
  hostIp: string | null;
  hostPort: number | null;
  containerPort: number;
  protocol: string;
}

export interface ContainerSummary {
  id: string;
  name: string;
  image: string;
  command: string | null;
  state: ContainerState;
  /** The engine's words: "Up 2 hours (healthy)", "Exited (0) 3 days ago". */
  status: string;
  createdAt: string | null;
  startedAt: string | null;
  ports: PortMapping[];
  networks: string[];
  mounts: string[];
  /** The Compose project. */
  project: string | null;
  health: string | null;
}

export interface ContainerList {
  containers: ContainerSummary[];
  readAt: string;
  /** The CLI ran under sudo. */
  sudo: boolean;
}

export interface ContainerStats {
  id: string;
  name: string | null;
  cpuPct: number | null;
  memBytes: number | null;
  memLimitBytes: number | null;
  memPct: number | null;
  netRxBytes: number | null;
  netTxBytes: number | null;
  blockReadBytes: number | null;
  blockWriteBytes: number | null;
  pids: number | null;
}

export interface MountInfo {
  kind: string;
  name: string | null;
  source: string | null;
  destination: string;
  readOnly: boolean;
}

export interface NetworkAttachment {
  name: string;
  ipAddress: string | null;
  gateway: string | null;
}

/** `inspect`: environment variables by name only, never their values. */
export interface ContainerDetails {
  id: string;
  name: string;
  image: string;
  imageId: string | null;
  createdAt: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  state: ContainerState;
  exitCode: number | null;
  error: string | null;
  oomKilled: boolean;
  health: { status: string; failingStreak: number | null } | null;
  restartPolicy: string | null;
  restartCount: number | null;
  command: string | null;
  entrypoint: string | null;
  workingDir: string | null;
  runsAs: string | null;
  envNames: string[];
  mounts: MountInfo[];
  networks: NetworkAttachment[];
  ports: PortMapping[];
  project: string | null;
  platform: string | null;
}

export interface LogLine {
  at: string | null;
  stream: "stdout" | "stderr";
  text: string;
}

export interface LogQuery {
  tail: number;
  since?: string | null;
}

export interface Logs {
  lines: LogLine[];
  truncated: boolean;
}

export interface ImageSummary {
  id: string;
  tags: string[];
  digest: string | null;
  createdAt: string | null;
  sizeBytes: number | null;
  containers: number | null;
  dangling: boolean;
}

export interface VolumeSummary {
  name: string;
  driver: string | null;
  mountpoint: string | null;
  scope: string | null;
  createdAt: string | null;
  project: string | null;
  anonymous: boolean;
}

export interface NetworkSummary {
  id: string;
  name: string;
  driver: string | null;
  scope: string | null;
  internal: boolean | null;
  ipv6: boolean | null;
  subnets: string[];
  createdAt: string | null;
}

export interface EngineVersion {
  client: string | null;
  server: string | null;
  api: string | null;
  platform: string | null;
}

export interface DetectedEngine {
  engine: EngineKind;
  installed: boolean;
  version: EngineVersion | null;
  /** How it worked, if it did: what to mark. */
  suggested: SudoMode | null;
  problem: string | null;
}

export interface Detection {
  sessionId: string;
  engines: DetectedEngine[];
}

/** Error shape from src-tauri/src/ipc.rs. */
/** QL-15: the app's log folder; null when the data folder is not known. */
export interface LogsInfo {
  folder: string | null;
  keepDays: number;
}

export interface IpcError {
  code: string;
  message: string;
  /** AP-01: with code "approval_changed", the approval asked again (same id), to show instead. */
  request?: ApprovalRequest;
}

export function errorMessage(err: unknown): string {
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && "message" in err) return String((err as IpcError).message);
  return "Unexpected error";
}

export function errorCode(err: unknown): string | undefined {
  return err && typeof err === "object" && "code" in err ? String((err as IpcError).code) : undefined;
}

/** AP-01: the approval asked again, when a target became Prod or protected after it was asked. */
export function changedRequest(err: unknown): ApprovalRequest | null {
  if (errorCode(err) !== "approval_changed" || !err || typeof err !== "object" || !("request" in err)) return null;
  return (err as IpcError).request ?? null;
}

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  /** QL-15: where the app's logs and crash reports are (Settings, About). */
  logsInfo: () => invoke<LogsInfo>("logs_info"),
  /** QL-15: opens the logs folder in Explorer. */
  openLogs: () => invoke<void>("logs_open"),
  /** QL-15: a page crashed; the app's log keeps what broke (shortened, secrets redacted). */
  uiError: (page: string, message: string, stack: string | null) => invoke<void>("ui_error", { page, message, stack }),

  /** VM-01: finds every VM (Workstation's library, chosen folders, vmrun list; VM-18 VirtualBox's VMs) via the core. */
  vmRefresh: () => invoke<RefreshReport>("vm_refresh"),
  /** VM-01, VM-02: the VMs the last refresh found that match the filter, without asking Workstation. */
  vmList: (filter?: VmFilter) => invoke<VmRecord[]>("vm_list", { filter: filter ?? null }),

  /** VM-02: tags are the app's own labels for picking VMs; they change no VM. */
  tags: () => invoke<Tag[]>("tags_list"),
  tagVms: (vmxPaths: string[], tag: string) => invoke<void>("vm_tag", { vmxPaths, tag }),
  untagVms: (vmxPaths: string[], tag: string) => invoke<void>("vm_untag", { vmxPaths, tag }),
  deleteTag: (tag: string) => invoke<void>("tag_delete", { tag }),
  /**
   * SS-06 for VMs: a Prod VM moves actions on it up one tier. The app's own data: audited, no approval.
   * Returns the VMs whose label changed.
   */
  setVmEnvironment: (vmxPaths: string[], environment: Environment) =>
    invoke<VmRecord[]>("vm_set_environment", { vmxPaths, environment }),
  savedFilters: () => invoke<SavedFilter[]>("filters_list"),
  /** Saving under an existing name replaces that filter. */
  saveFilter: (name: string, filter: VmFilter) => invoke<SavedFilter>("filter_save", { name, filter }),
  deleteFilter: (id: string) => invoke<void>("filter_delete", { id }),

  /** The one way in for changes: command bus -> policy engine -> job runner. */
  submit: (command: Command) => invoke<SubmitOutcome>("command_submit", { command }),
  /** FD-01: the tier and approval steps a command would get, without submitting it. */
  commandPreview: (command: Command) => invoke<CommandPreview>("command_preview", { command }),
  approve: (requestId: string, answers: ApprovalAnswers) => invoke<string>("command_approve", { requestId, answers }),
  cancelApproval: (requestId: string) => invoke<void>("command_cancel_approval", { requestId }),

  /**
   * AP-03: cancels a job in its countdown, or the targets of a running job that have not started. VM power
   * actions in progress are no longer waited for (BX-04); Workstation may still finish them.
   */
  cancelJob: (jobId: string) => invoke<boolean>("job_cancel", { jobId }),
  recentJobs: (limit = 50) => invoke<JobSummary[]>("jobs_recent", { limit }),
  jobTargets: (jobId: string) => invoke<JobTarget[]>("job_targets", { jobId }),
  recentAudit: (limit = 100) => invoke<AuditEntry[]>("audit_recent", { limit }),
  verifyAudit: () => invoke<ChainCheck>("audit_verify"),
  /** AP-05: asks where to save, then writes the audit log there as CSV. null when the user cancels. */
  exportAudit: () => invoke<AuditExport | null>("audit_export_csv"),

  /** BX-02: how long job outputs and command text are kept, and the last purge. */
  retention: () => invoke<RetentionInfo>("journal_retention"),
  /** BX-02: applies at the next purge (daily, or Purge now). Audited; refused while presenting. */
  setRetention: (retention: Retention) => invoke<RetentionInfo>("journal_retention_set", { retention }),
  /** BX-02: purges now with the setting. Audited; refused while presenting. */
  purgeNow: () => invoke<PurgeReport>("journal_purge_now"),

  /** VM-04: snapshot trees read from each VM's .vmsd (no vmrun call; VirtualBox: showvminfo). Changes go through `submit`. */
  snapshots: (vmxPaths?: string[]) => invoke<VmSnapshots[]>("snapshots_list", { vmxPaths: vmxPaths ?? null }),
  snapshotLimits: () => invoke<SnapshotLimits>("snapshot_limits"),

  /** AP-01: the approval rules in force, and what the editor needs to change them. */
  policyRules: () => invoke<PolicyRules>("policy_rules"),
  policyCatalog: () => invoke<PolicyCatalog>("policy_catalog"),
  /**
   * Checked by the core (an invalid rule fails with code "invalid_rule") and audited. AP-06: a change that loosens
   * the rules fails with `reauth_required` until it comes with the vault password.
   */
  setPolicyRules: (rules: PolicyRules, vaultPassword?: string) =>
    invoke<PolicySaved>("policy_set_rules", { rules, vaultPassword: vaultPassword ?? null }),
  onJobEvent: (handler: (event: JobEvent) => void): Promise<UnlistenFn> =>
    listen<JobEvent>("job://event", (e) => handler(e.payload)),

  settings: () => invoke<Settings>("settings_get"),
  /** FD-03: read before anything shows, so the app starts presenting if it was. */
  presentation: () => invoke<Presentation>("presentation_get"),
  /** FD-03: audited per change; never refused by the lock. */
  setPresentation: (p: Presentation) =>
    invoke<Presentation>("presentation_set", { enabled: p.enabled, readOnly: p.readOnly }),
  /** null or "" goes back to finding vmrun.exe automatically. */
  setVmrunPath: (path: string | null) => invoke<Settings>("settings_set_vmrun_path", { path }),
  /** VM-21: null or "" goes back to finding ovftool.exe automatically. */
  setOvftoolPath: (path: string | null) => invoke<Settings>("settings_set_ovftool_path", { path }),
  /** VM-18: null or "" goes back to finding VBoxManage.exe automatically. */
  setVboxmanagePath: (path: string | null) => invoke<Settings>("settings_set_vboxmanage_path", { path }),
  setUpdateChecks: (enabled: boolean) => invoke<Settings>("settings_set_update_checks", { enabled }),
  /** VM-01: each folder must exist. */
  setScanFolders: (folders: string[]) => invoke<Settings>("settings_set_scan_folders", { folders }),
  setPowerOnLimit: (limit: number) => invoke<Settings>("settings_set_power_on_limit", { limit }),
  setShutdownWait: (secs: number) => invoke<Settings>("settings_set_shutdown_wait", { secs }),
  /** BX-02: how many hosts a bulk run reaches at once. */
  setBulkParallel: (limit: number) => invoke<Settings>("settings_set_bulk_parallel", { limit }),
  /** MO-02: 5, 15, 30 or 60 seconds between two dashboard polls of each watched host. */
  setGuestPoll: (secs: number) => invoke<Settings>("settings_set_guest_poll", { secs }),
  /** FD-14: installing is the `appUpdate` command. */
  checkForUpdate: () => invoke<UpdateCheck>("update_check"),
  /** FD-14: write-only; stored in the vault, replacing the one there. Needs the vault unlocked. */
  setUpdateToken: (token: string) => invoke<Settings>("update_token_set", { token }),
  testUpdateToken: () => invoke<TokenReport>("update_token_test"),
  removeUpdateToken: () => invoke<Settings>("update_token_remove"),

  /**
   * MO-01 to MO-04. Reads only: no approval. The core collects every 5 s and emits each round's cost;
   * the dashboard reads what it shows when it hears one.
   */
  metricsOverview: () => invoke<DashboardOverview>("metrics_overview"),
  metricsSeries: (source: MetricSource, key: string) => invoke<MetricPoint[]>("metrics_series", { source, key }),
  metricsCapacity: () => invoke<HostCapacity>("metrics_capacity"),
  /** MO-01: each running VM's share of this host's CPU and RAM, from the latest round (no extra polling). */
  metricsHostUsage: () => invoke<VmHostUsage[]>("metrics_host_usage"),
  /** MO-02: watching a session logs in to it over SSH every round. Audited; returns the watched ids. */
  metricsWatch: (sessionId: string, watch: boolean) => invoke<string[]>("metrics_watch", { sessionId, watch }),
  /**
   * MO-02, CT-01: Retry on a host whose background logins are parked (refused login or sudo, changed
   * host key, no saved password) or capped for the hour. The dashboard and Containers page log in again.
   */
  backgroundLoginRetry: (sessionId: string) => invoke<void>("background_login_retry", { sessionId }),
  /** SS-01: a startup command rated as on a session with this label (null before the rules are loaded). */
  sessionStartupRating: (command: string, environment: Environment) =>
    invoke<StartupRating | null>("session_startup_rating", { command, environment }),
  /** MO-15: this PC's RAM and paging files, from the metrics rounds. */
  metricsThisPc: () => invoke<ThisPcSeries>("metrics_this_pc"),
  /** MO-13: what was last read about the session (null before the first read). Makes no connection. */
  hostSpecs: (sessionId: string) => invoke<SessionSpecs | null>("host_specs", { sessionId }),
  /** MO-13: reads the session's OS and specs now (may log in once, since the user asked). */
  hostSpecsRefresh: (sessionId: string) => invoke<SessionSpecs>("host_specs_refresh", { sessionId }),
  /** MO-14: services, ports, users, boots and top processes, read now. */
  hostAdmin: (sessionId: string) => invoke<AdminReport>("host_admin", { sessionId }),
  /** MO-14: pending updates; dnf may take a minute to refresh its metadata. */
  hostUpdates: (sessionId: string) => invoke<UpdatesCheck>("host_updates", { sessionId }),
  /** The host details panel closed: its own connection, if it made one, closes. */
  hostDetailsRelease: (sessionId: string) => invoke<void>("host_details_release", { sessionId }),
  /** MO-13: a VM's hardware from its files, and its guest's facts from a linked session. */
  vmSpecs: (vmxPath: string) => invoke<VmSpecs>("vm_specs", { vmxPath }),
  // VM-23, VM-24: the commands that carry a path of this PC are built in the shell, from a dialog it opens or a
  // drop; null when the dialog was closed.
  vmPickIso: (vmxPath: string, slot?: string | null) =>
    invoke<SubmitOutcome | null>("vm_pick_iso", { vmxPath, slot: slot ?? null }),
  vmAttachDroppedIso: (stagedId: string, vmxPath: string) =>
    invoke<SubmitOutcome>("vm_attach_dropped_iso", { stagedId, vmxPath }),
  vmPickSharedFolder: (vmxPath: string, name: string, writable: boolean) =>
    invoke<SubmitOutcome | null>("vm_pick_shared_folder", { vmxPath, name, writable }),
  vmPickExisting: () => invoke<SubmitOutcome | null>("vm_pick_existing"),
  /** VM-24: the hypervisor's own window; audited, no tier. */
  vmOpenConsole: (vmxPath: string) => invoke<ConsoleOutcome>("vm_open_console", { vmxPath }),
  /** VM-23: a running VirtualBox VM's screen as a PNG data URL. */
  vmScreenshot: (vmxPath: string) => invoke<string>("vm_screenshot", { vmxPath }),
  vmGuestOsTypes: (vmxPath: string) => invoke<GuestOsType[]>("vm_guest_os_types", { vmxPath }),
  /** VM-23: whether Workstation's window runs (it may write its own copy of a VM's settings over a change). */
  vmWorkstationOpen: () => invoke<boolean>("vm_workstation_open"),
  onMetricsRound: (handler: (cost: CollectorCost) => void): Promise<UnlistenFn> =>
    listen<CollectorCost>("metrics://round", (e) => handler(e.payload)),

  /** SS-04 vault. Secret values go in and never come back; the UI holds IDs and labels only. */
  vaultInfo: () => invoke<VaultInfo>("vault_info"),
  /** The vault password is always set (Critical actions ask for it again, AP-06). */
  vaultSetup: (password: string, windowsLogin: boolean) => invoke<VaultInfo>("vault_setup", { password, windowsLogin }),
  /** No password: unlock with the Windows login. */
  vaultUnlock: (password?: string) => invoke<VaultInfo>("vault_unlock", { password: password ?? null }),
  vaultLock: () => invoke<VaultInfo>("vault_lock"),
  vaultChangePassword: (current: string, next: string) =>
    invoke<VaultInfo>("vault_change_password", { current, new: next }),
  vaultSetWindowsLogin: (password: string, enabled: boolean) =>
    invoke<VaultInfo>("vault_set_windows_login", { password, enabled }),
  /** SS-04: one click, no password: the Windows login stops unlocking the vault. */
  vaultTurnOffWindowsLogin: () => invoke<VaultInfo>("vault_turn_off_windows_login"),
  /** SS-04: the user typed or clicked; the idle lock counts from now (background reads never count). */
  vaultActivity: () => invoke<void>("vault_activity"),
  /** SS-04, FD-07: scores a candidate vault password or export passphrase for the meter. Never logged. */
  passwordStrength: (text: string) => invoke<PasswordStrength>("password_strength", { text }),
  /** SS-04, FD-07: six random words joined by "-", for the Generate button. */
  passphraseGenerate: () => invoke<string>("passphrase_generate"),
  /** Status changes, including the lock after the idle time. */
  onVaultStatus: (handler: (status: VaultStatus) => void): Promise<UnlistenFn> =>
    listen<VaultStatus>("vault://status", (e) => handler(e.payload)),
  secrets: () => invoke<SecretMeta[]>("secrets_list"),
  addSecret: (kind: SecretKind, label: string, value: string) =>
    invoke<SecretMeta>("secret_add", { kind, label, value }),
  /** Opens a file dialog in the core and stores the chosen key file; null when cancelled. */
  importKeyFile: (label: string) => invoke<SecretMeta | null>("secret_import_key", { label }),
  replaceSecret: (id: string, value: string) => invoke<SecretMeta>("secret_replace", { id, value }),
  renameSecret: (id: string, label: string) => invoke<SecretMeta>("secret_rename", { id, label }),
  deleteSecret: (id: string) => invoke<void>("secret_delete", { id }),

  /** SS-01, SS-06 session library. Changes are the app's own data: audited, no approval. */
  sessions: (filter?: SessionFilter) => invoke<SessionRecord[]>("sessions_list", { filter: filter ?? null }),
  sessionFolders: () => invoke<SessionFolder[]>("session_folders"),
  /**
   * SS-04, AP-06: a session that would send a vault password to a host where no saved session sends it yet fails with
   * `reauth_required` until it comes with the vault password.
   */
  createSession: (input: SessionInput, vaultPassword?: string) =>
    invoke<SessionRecord>("session_create", { input, vaultPassword: vaultPassword ?? null }),
  updateSession: (id: string, input: SessionInput, vaultPassword?: string) =>
    invoke<SessionRecord>("session_update", { id, input, vaultPassword: vaultPassword ?? null }),
  duplicateSession: (id: string) => invoke<SessionRecord>("session_duplicate", { id }),
  deleteSession: (id: string) => invoke<void>("session_delete", { id }),
  /** QL-01: links a session to a VM by hand (vmId null removes the link); auto-linking leaves it alone. Audited. */
  linkSessionVm: (sessionId: string, vmId: string | null) =>
    invoke<SessionRecord>("session_link_vm", { sessionId, vmId }),
  /** QL-01: keeps an automatic link, so auto-linking never changes it. Audited. */
  confirmSessionVmLink: (sessionId: string) => invoke<SessionRecord>("session_confirm_vm_link", { sessionId }),
  /** QL-01: sessions several VMs match, left for the user to pick. */
  ambiguousVmLinks: () => invoke<AmbiguousLink[]>("vm_links_ambiguous"),
  /**
   * folderId null: the top level. QL-16, SS-04: `reauth_required` when the new folder's login would send a vault
   * password where no saved session sends it yet.
   */
  moveSessions: (ids: string[], folderId: string | null, vaultPassword?: string) =>
    invoke<void>("sessions_move", { ids, folderId, vaultPassword: vaultPassword ?? null }),
  // SS-07: saved port forwards and a terminal's tunnels.
  forwards: (sessionId: string) => invoke<PortForward[]>("forwards_list", { sessionId }),
  allForwards: () => invoke<Record<string, PortForward[]>>("forwards_all"),
  saveForwards: (sessionId: string, forwards: ForwardInput[]) =>
    invoke<PortForward[]>("forwards_save", { sessionId, forwards }),
  terminalTunnels: (terminalId: string) => invoke<TunnelInfo[]>("terminal_tunnels", { terminalId }),
  terminalTunnelStart: (terminalId: string, forwardId: string) =>
    invoke<TunnelStart>("terminal_tunnel_start", { terminalId, forwardId }),
  terminalTunnelRequest: (terminalId: string, forwardId: string) =>
    invoke<ApprovalRequest | null>("terminal_tunnel_request", { terminalId, forwardId }),
  terminalTunnelApprove: (terminalId: string, forwardId: string, answers: ApprovalAnswers) =>
    invoke<string>("terminal_tunnel_approve", { terminalId, forwardId, answers }),
  terminalTunnelDecline: (terminalId: string, forwardId: string) =>
    invoke<void>("terminal_tunnel_decline", { terminalId, forwardId }),
  terminalTunnelStop: (terminalId: string, forwardId: string) =>
    invoke<void>("terminal_tunnel_stop", { terminalId, forwardId }),
  createFolder: (name: string, parentId: string | null) => invoke<SessionFolder>("folder_create", { name, parentId }),
  renameFolder: (id: string, name: string) => invoke<SessionFolder>("folder_rename", { id, name }),
  moveFolder: (id: string, parentId: string | null, vaultPassword?: string) =>
    invoke<SessionFolder>("folder_move", { id, parentId, vaultPassword: vaultPassword ?? null }),
  /** Its sessions and subfolders move up to its parent. */
  deleteFolder: (id: string, vaultPassword?: string) =>
    invoke<void>("folder_delete", { id, vaultPassword: vaultPassword ?? null }),
  /**
   * QL-16: what a folder gives its sessions. Audited like a session edit; `reauth_required` when it would send a vault
   * password where no saved session sends it yet.
   */
  setFolderDefaults: (id: string, defaults: FolderDefaults, vaultPassword?: string) =>
    invoke<SessionFolder>("folder_set_defaults", { id, defaults, vaultPassword: vaultPassword ?? null }),
  /** QL-16: what a session in `folderId` gets when it sets nothing itself (`sessionId`: the one being edited). */
  sessionInherited: (folderId: string | null, sessionId: string | null) =>
    invoke<Effective>("session_inherited", { folderId, sessionId }),

  /**
   * SS-02: reads a session list (PuTTY's registry, or a file chosen in a dialog the core opens; the
   * OpenSSH config is ~/.ssh/config unless chooseFile) and compares it with the library. null when the
   * dialog was closed.
   */
  importPreview: (source: ImportSource, chooseFile = false) =>
    invoke<ImportPreview | null>("import_preview", { source, chooseFile }),
  /** Saves the picked rows of a preview; key files go into the vault when addKeys. */
  importCommit: (request: {
    previewId: string;
    rows: number[];
    folderId: string | null;
    addKeys: boolean;
    /** SS-01: rows whose startup command is imported too. */
    keepStartup: number[];
  }) => invoke<ImportReport>("import_commit", { request }),
  /** QL-10: the format guide for a source. */
  importGuide: (source: ImportSource) => invoke<FormatGuide>("import_guide", { source }),
  /** QL-10: saves the source's sample file where the user picks (a Rust save dialog). null when cancelled. */
  importSaveSample: (source: ImportSource) => invoke<string | null>("import_save_sample", { source }),

  /**
   * FD-07: asks where to save (Documents by default), then writes the encrypted export. Secret values go
   * along only with includeSecrets, which needs the vault password. null when the user cancels.
   */
  transferExport: (request: {
    passphrase: string;
    includeKnownHosts: boolean;
    includeSecrets: boolean;
    vaultPassword: string | null;
  }) => invoke<ExportReport | null>("transfer_export", { request }),
  /** Asks for an export file in a dialog the core opens; its name, or null when cancelled. */
  transferChoose: () => invoke<string | null>("transfer_choose"),
  /** Opens the chosen file with its passphrase (wrong: code "wrong_passphrase") and compares it. */
  transferOpen: (passphrase: string) => invoke<TransferPreview>("transfer_open", { passphrase }),
  /** The opened file compared with the library again, e.g. after unlocking the vault. */
  transferRefresh: (previewId: string) => invoke<TransferPreview>("transfer_refresh", { previewId }),
  /** Drops the opened file. */
  transferClose: (previewId: string) => invoke<boolean>("transfer_close", { previewId }),
  /** Items not listed get their default action. */
  transferCommit: (request: {
    previewId: string;
    sessions: TransferChoice[];
    knownHosts: TransferChoice[];
    secrets: TransferChoice[];
    favourites: TransferChoice[];
    /** QL-16: what to do with each folder's defaults. */
    folderDefaults: TransferChoice[];
    /** QL-19 saved MultiExec groups. */
    groups?: TransferChoice[];
    /** VM-19 to VM-21. */
    catalog?: { sizes: TransferChoice[]; images: TransferChoice[]; templates: TransferChoice[] };
    /** SS-01, SS-07: sessions (by index) whose startup command, and whose port forwards, come along. */
    keepStartup: number[];
    keepForwards: number[];
    /** SS-04, AP-06: the vault password, when the core asked for it (`reauth_required`). */
    vaultPassword?: string;
  }) => invoke<TransferReport>("transfer_commit", { request }),

  /** SS-09 SSH keys in the vault. Pushing one is `submit` with a pushSshKey command. */
  sshKeys: () => invoke<SshKey[]>("ssh_keys_list"),
  generateSshKey: (request: { label: string; keyType: KeyType; comment: string }) =>
    invoke<SshKey>("ssh_key_generate", { request }),
  /** Reads the public half from the private key when it is not known yet (vault unlocked). */
  sshKeyPublic: (id: string) => invoke<SshKey>("ssh_key_public", { id }),
  attachSshKey: (id: string, sessionIds: string[]) => invoke<SessionRecord[]>("ssh_key_attach", { id, sessionIds }),
  parsePublicKey: (publicKey: string) => invoke<PublicKeyInfo>("ssh_public_key_parse", { publicKey }),

  /** BX-01 to BX-07. Running is `submit` with a remoteExec command, through the approval flow. */
  bulkLimits: () => invoke<BulkLimits>("bulk_limits"),
  bulkTargets: (picks: TargetPicks) => invoke<ResolvedTargets>("bulk_targets", { picks }),
  /** BX-06: tier and matched dangerous-command rules, without submitting. */
  bulkPreview: (command: Command) => invoke<CommandPreview>("bulk_preview", { command }),
  bulkRuns: (limit = 20) => invoke<JobSummary[]>("bulk_runs", { limit }),
  bulkResults: (jobId: string, options: GroupOptions) => invoke<BulkResults>("bulk_results", { jobId, options }),
  bulkHostOutput: (jobId: string, targetKey: string) => invoke<HostOutput>("bulk_host_output", { jobId, targetKey }),
  bulkDiff: (jobId: string, left: string, right: string, options: GroupOptions) =>
    invoke<OutputDiff>("bulk_diff", { jobId, left, right, options }),
  /**
   * BX-04: the failed hosts again, as a new job through the bus (it may need approval). H9: hosts whose outcome is
   * unknown only with `includeUnknown` (the command may run there twice).
   */
  bulkRetryFailed: (jobId: string, includeUnknown = false) =>
    invoke<SubmitOutcome>("bulk_retry_failed", { jobId, includeUnknown }),
  /** H9: run on the hosts waiting after the canary. False when the job no longer waits. */
  bulkGoOn: (jobId: string) => invoke<boolean>("bulk_go_on", { jobId }),
  /** BX-05: asks where to save, then writes the results; null when the user cancels. */
  bulkExport: (jobId: string, format: ExportFormat, options: GroupOptions) =>
    invoke<BulkExport | null>("bulk_export", { jobId, format, options }),

  /**
   * SS-03: opens a pane to a saved session. Output arrives as raw bytes (xterm.js decodes them, so a
   * character split across reads stays whole); status and host key questions arrive as events.
   */
  terminalOpen: (
    sessionId: string,
    cols: number,
    rows: number,
    onOutput: (data: Uint8Array) => void,
    onEvent: (event: TerminalEvent) => void,
  ) => {
    const output = new Channel<ArrayBuffer>();
    output.onmessage = (data) => onOutput(new Uint8Array(data));
    const events = eventChannel(onEvent);
    return invoke<string>("terminal_open", { sessionId, cols, rows, onOutput: output, onEvent: events });
  },
  /** Keystrokes and pastes as raw bytes. */
  /** QL-02: a pane to a host typed in the New terminal form, saved as a session or not. */
  terminalQuickConnect: (
    request: QuickConnectRequest,
    cols: number,
    rows: number,
    onOutput: (data: Uint8Array) => void,
    onEvent: (event: TerminalEvent) => void,
  ) => {
    const output = new Channel<ArrayBuffer>();
    output.onmessage = (data) => onOutput(new Uint8Array(data));
    const events = eventChannel(onEvent);
    return invoke<{ id: string; session: SessionRecord | null }>("terminal_quick_connect", {
      request,
      cols,
      rows,
      onOutput: output,
      onEvent: events,
    });
  },
  /** A second pane like an open one (split): same target, and a password typed for it. */
  terminalOpenLike: (
    id: string,
    cols: number,
    rows: number,
    onOutput: (data: Uint8Array) => void,
    onEvent: (event: TerminalEvent) => void,
  ) => {
    const output = new Channel<ArrayBuffer>();
    output.onmessage = (data) => onOutput(new Uint8Array(data));
    const events = eventChannel(onEvent);
    return invoke<string>("terminal_open_like", { id, cols, rows, onOutput: output, onEvent: events });
  },
  terminalWrite: (id: string, data: Uint8Array) =>
    invoke<void>("terminal_write", data, { headers: { "x-terminal-id": id } }),
  /** SS-10: turns MultiExec on for these terminals, or changes them. */
  multiExecSetTargets: (terminalIds: string[]) => invoke<MultiExecStatus>("multiexec_set_targets", { terminalIds }),
  /** SS-10: off; a line waiting for approval gets Ctrl+C. */
  multiExecStop: () => invoke<MultiExecStatus>("multiexec_stop"),
  multiExecStatus: () => invoke<MultiExecStatus>("multiexec_status"),
  /** SS-10: keys typed into terminal `id` while MultiExec is on (raw bytes, like terminalWrite). */
  multiExecInput: (id: string, data: Uint8Array) =>
    invoke<MultiExecOutcome>("multiexec_input", data, { headers: { "x-terminal-id": id } }),
  /** SS-10: the approval dialog's answers for a held line; returns the job that sends its Enter. */
  multiExecApprove: (lineId: string, answers: ApprovalAnswers) =>
    invoke<string>("multiexec_approve", { lineId, answers }),
  /** SS-10: cancels a held line: Ctrl+C instead of Enter on every terminal. */
  multiExecCancel: (lineId: string) => invoke<void>("multiexec_cancel", { lineId }),
  /** QL-12: the lines this MultiExec session recorded, newest first. */
  multiExecRecordings: () => invoke<Recordings>("multiexec_recordings"),
  multiExecRecorded: (lineId: string, options: GroupOptions) =>
    invoke<RecordedResults>("multiexec_recorded", { lineId, options }),
  multiExecRecordedOutput: (lineId: string, terminalId: string) =>
    invoke<HostOutput>("multiexec_recorded_output", { lineId, terminalId }),
  multiExecRecordedDiff: (lineId: string, left: string, right: string, options: GroupOptions) =>
    invoke<OutputDiff>("multiexec_recorded_diff", { lineId, left, right, options }),
  /** QL-12: one line (`lineId`) or all of them (null); a save dialog in Rust; null when cancelled. */
  multiExecExport: (lineId: string | null, format: ExportFormat, options: GroupOptions) =>
    invoke<RecordedExport | null>("multiexec_export", { lineId, format, options }),
  onMultiExecEvent: (handler: (event: MultiExecEvent) => void): Promise<UnlistenFn> =>
    listen<MultiExecEvent>("multiexec://event", (e) => handler(e.payload)),
  terminalResize: (id: string, cols: number, rows: number) => invoke<void>("terminal_resize", { id, cols, rows }),
  /** Connects again now (drops a live connection first). */
  terminalReconnect: (id: string) => invoke<void>("terminal_reconnect", { id }),
  terminalClose: (id: string) => invoke<void>("terminal_close", { id }),
  /** SS-05: the answer to a first-connection host key question. Trusting saves the key (audited). */
  terminalHostKeyAnswer: (id: string, trust: boolean) => invoke<void>("terminal_host_key_answer", { id, trust }),
  /** SS-05: trusts the changed key that blocked this pane (audited) and reconnects. */
  terminalHostKeyReplace: (id: string) => invoke<void>("terminal_host_key_replace", { id }),
  terminalSettings: () => invoke<TerminalSettings>("terminal_settings"),
  setTerminalSettings: (settings: TerminalSettings) => invoke<TerminalSettings>("terminal_set_settings", { settings }),
  /** SS-05: trusted host keys; removing one is audited and the next connection asks again. */
  knownHosts: () => invoke<KnownHost[]>("known_hosts_list"),
  /** QL-02 history of quick connections that were not saved, and Recent sessions. */
  quickConnectHistory: () => invoke<QuickConnectEntry[]>("quick_connect_history"),
  /** Without an id, clears the whole history. Audited. */
  quickConnectForget: (id: string | null) => invoke<void>("quick_connect_forget", { id }),
  recentSessions: (limit?: number) => invoke<SessionRecord[]>("sessions_recent", { limit: limit ?? null }),
  /** QL-04: the Terminal page's session tree. */
  sessionTree: (grouping: TreeGrouping, filter?: SessionFilter) =>
    invoke<SessionTree>("session_tree", { grouping, filter: filter ?? null }),
  /** QL-04: only these sessions are checked; returns what is known so far. */
  reachabilityWatch: (sessionIds: string[]) => invoke<ReachabilityUpdate>("reachability_watch", { sessionIds }),
  onReachability: (handler: (update: ReachabilityUpdate) => void): Promise<UnlistenFn> =>
    listen<ReachabilityUpdate>("reachability://update", (e) => handler(e.payload)),
  /**
   * SS-11 "Copy output": the shell puts the terminals' text on the clipboard, their login secrets scrubbed by the
   * core, kept out of Windows' clipboard history and cloud clipboard.
   */
  terminalOutputCopy: (items: TerminalText[]) => invoke<void>("terminal_output_copy", { items }),
  /**
   * QL-05: a terminal's selection onto the clipboard the same way, scrubbed of that terminal's secrets. id: the
   * core's terminal (null for a pane that never opened). Fails for a terminal that has closed.
   */
  terminalCopySelection: (id: string | null, text: string) => invoke<void>("terminal_copy_selection", { id, text }),
  /** SS-11: the terminals' text with their login secrets scrubbed, for printing; audited as printed. */
  terminalOutputPrint: (items: TerminalText[]) => invoke<TerminalText[]>("terminal_output_print", { items }),
  /** SS-11: asks where (a file, or a folder for one file each), then saves. Audited. null: cancelled. */
  terminalOutputSave: (items: TerminalText[], layout: SaveLayout) =>
    invoke<SavedOutput | null>("terminal_output_save", { items, layout }),
  /** SS-11: asks for a log file, then logs the pane's output to it. null: cancelled. Audited. */
  terminalLogStart: (id: string, title: string) => invoke<string | null>("terminal_log_start", { id, title }),
  terminalLogStop: (id: string) => invoke<boolean>("terminal_log_stop", { id }),
  removeKnownHost: (id: string) => invoke<void>("known_host_remove", { id }),
  /**
   * QL-05 right-click paste: the clipboard's text, read by the shell so WebView2 never asks for permission.
   * null: no text on the clipboard.
   */
  clipboardReadText: () => invoke<string | null>("clipboard_read_text"),

  /** BX-08 favourite commands; changes are audited (name and folder, not the command). */
  favourites: () => invoke<Favourite[]>("favourites_list"),
  addFavourite: (input: FavouriteInput) => invoke<Favourite>("favourite_add", { input }),
  updateFavourite: (id: string, input: FavouriteInput) => invoke<Favourite>("favourite_update", { id, input }),
  deleteFavourite: (id: string) => invoke<void>("favourite_delete", { id }),
  /** One folder's favourites in a new order; `folder` null for the top level. */
  reorderFavourites: (folder: string | null, ids: string[]) =>
    invoke<Favourite[]>("favourites_reorder", { folder, ids }),
  /** QL-19 saved MultiExec groups, by name; changes are audited and refused by the read-only lock. */
  multiExecGroups: () => invoke<MultiExecGroup[]>("multiexec_groups_list"),
  createMultiExecGroup: (input: GroupInput) => invoke<MultiExecGroup>("multiexec_group_create", { input }),
  updateMultiExecGroup: (id: string, input: GroupInput) =>
    invoke<MultiExecGroup>("multiexec_group_update", { id, input }),
  deleteMultiExecGroup: (id: string) => invoke<void>("multiexec_group_delete", { id }),
  /** BX-08 built-in commands, classified with the current rules. */
  commandLibrary: () => invoke<LibraryEntry[]>("command_library"),
  /** BX-08: a command's variables and what the policy engine makes of it. */
  commandInspect: (command: string) => invoke<CommandInfo>("command_inspect", { command }),
  /** BX-08: the command with its variables filled in, ready to paste. */
  commandFill: (command: string, values: Record<string, string>) => invoke<string>("command_fill", { command, values }),
  /**
   * QL-13: opens a library entry's manual page in the default browser. Rust refuses an address that isn't https on
   * one of its documentation sites.
   */
  openManual: (url: string) => invoke<void>("open_manual", { url }),
  /**
   * QL-06: types a vault password or passphrase, then Enter, into the terminal when it shows a password prompt (or
   * with `force`). The value never reaches the UI. Fails with `no_password_prompt` at a shell prompt.
   */
  terminalTypeSecret: (id: string, secretId: string, force: boolean, vaultPassword?: string) =>
    invoke<void>("terminal_type_secret", { id, secretId, force, vaultPassword: vaultPassword ?? null }),
  /** QL-07: a Windows notification that a long command finished in a background tab. */
  notifyCommandFinished: (title: string, body: string) => invoke<void>("notify_command_finished", { title, body }),
  /** QL-17: a Windows notification that an alert rule matched in a background tab (one per burst). */
  notifyTerminalAlert: (title: string, body: string) => invoke<void>("notify_terminal_alert", { title, body }),

  /** QL-17 highlight and alert rules: built-in ones first, then the user's in their order. */
  terminalRules: () => invoke<TerminalRule[]>("terminal_rules_list"),
  /** QL-17: the editor's live check of a pattern (what Rust and JavaScript both read alike). */
  terminalRuleValidate: (pattern: string, caseSensitive: boolean) =>
    invoke<PatternCheck>("terminal_rule_validate", { pattern, caseSensitive }),
  /** QL-17: changes are audited (name and scope, never the pattern) and refused by the read-only lock. */
  addTerminalRule: (input: TerminalRuleInput) => invoke<TerminalRule>("terminal_rule_add", { input }),
  updateTerminalRule: (id: string, input: TerminalRuleInput) =>
    invoke<TerminalRule>("terminal_rule_update", { id, input }),
  deleteTerminalRule: (id: string) => invoke<void>("terminal_rule_delete", { id }),
  /** The user's rules (all of them, by id) in a new order. */
  reorderTerminalRules: (ids: string[]) => invoke<TerminalRule[]>("terminal_rules_reorder", { ids }),
  /** A built-in rule (by its key, e.g. "error") or its alert on or off. */
  setBuiltinTerminalRule: (key: string, enabled: boolean, alert: boolean) =>
    invoke<TerminalRule>("terminal_rule_set_builtin", { key, enabled, alert }),

  /** SS-08: the shell's folder as far as it is known. */
  filesFolder: (id: string) => invoke<FolderInfo | null>("files_folder", { id }),
  /**
   * SS-08: a folder on the terminal's host; without a path, the shell's folder (or home). QL-09: a relative path goes on
   * from `from` (the folder the drawer shows); a folder that can't be opened comes back with its `error`.
   */
  filesList: (id: string, path: string | null, from: string | null = null) =>
    invoke<FolderListing>("files_list", { id, path, from }),
  /** QL-09: the drawer's Back from the folder it shows. */
  filesBack: (id: string, from: string) => invoke<FolderListing>("files_back", { id, from }),
  /** SS-08: what a name right-clicked in the output is, from the shell's folder. null: nothing there. */
  filesLookUp: (id: string, path: string) =>
    invoke<{ path: string; entry: RemoteEntry } | null>("files_look_up", { id, path }),
  /** SS-08: a file dialog opened by the shell; the files wait (staged) for `filesUpload`. null: cancelled. */
  filesPickUpload: () => invoke<StagedFiles | null>("files_pick_upload"),
  /** SS-08: uploads staged files through the command bus (Low; Prod and replacing ask). */
  filesUpload: (id: string, stagedId: string, folder: string, existing: Existing) =>
    invoke<UploadStart>("files_upload", { id, stagedId, folder, existing }),
  filesUnstage: (stagedId: string) => invoke<void>("files_unstage", { stagedId }),
  /** SS-08: to Downloads, or a folder the shell asks for. Audited per file. null: the dialog was closed. */
  filesDownload: (id: string, paths: string[], to: "downloads" | "choose") =>
    invoke<TransferInfo[] | null>("files_download", { id, paths, to }),
  filesTransfers: () => invoke<TransferInfo[]>("files_transfers"),
  filesCancel: (transferId: string) => invoke<boolean>("files_cancel", { transferId }),
  filesRetry: (transferId: string) => invoke<Retried>("files_retry", { transferId }),
  /** SS-08: Explorer at a finished download. */
  filesOpenFolder: (transferId: string) => invoke<void>("files_open_folder", { transferId }),
  onTransfer: (handler: (transfer: TransferInfo) => void): Promise<UnlistenFn> =>
    listen<TransferInfo>("files://transfer", (e) => handler(e.payload)),
  onFilesDropped: (handler: (dropped: DroppedFiles) => void): Promise<UnlistenFn> =>
    listen<DroppedFiles>("files://dropped", (e) => handler(e.payload)),

  // CT-01, CT-02: container hosts and what runs on them. Reads only; changes are `submit` with a container command.
  /** The marked sessions, then this PC when Docker Desktop is there. No connection. */
  containerHosts: () => invoke<ContainerHostInfo[]>("containers_hosts"),
  containerMarks: (sessionId: string) => invoke<ContainerMark[]>("containers_marks", { sessionId }),
  /** Replaces a session's engines (empty: no container host any more). Audited like a session edit. */
  setContainerMarks: (sessionId: string, marks: MarkInput[], vaultPassword?: string) =>
    invoke<ContainerMark[]>("containers_set_marks", { sessionId, marks, vaultPassword: vaultPassword ?? null }),
  /** Which CLIs the host has and whether they need sudo. A read: nothing is marked. */
  detectContainers: (sessionId: string, sudoPasswordId: string | null = null, vaultPassword?: string) =>
    invoke<Detection>("containers_detect", { sessionId, sudoPasswordId, vaultPassword: vaultPassword ?? null }),
  containerVersion: (host: ContainerHost, engine: EngineKind) =>
    invoke<EngineVersion>("containers_version", { host, engine }),
  containers: (host: ContainerHost, engine: EngineKind) => invoke<ContainerList>("containers_list", { host, engine }),
  containerStats: (host: ContainerHost, engine: EngineKind) =>
    invoke<ContainerStats[]>("containers_stats", { host, engine }),
  containerDetails: (host: ContainerHost, engine: EngineKind, id: string) =>
    invoke<ContainerDetails>("containers_details", { host, engine, id }),
  containerLogs: (host: ContainerHost, engine: EngineKind, id: string, query: LogQuery) =>
    invoke<Logs>("containers_logs", { host, engine, id, query }),
  containerImages: (host: ContainerHost, engine: EngineKind) =>
    invoke<ImageSummary[]>("containers_images", { host, engine }),
  containerVolumes: (host: ContainerHost, engine: EngineKind) =>
    invoke<VolumeSummary[]>("containers_volumes", { host, engine }),
  containerNetworks: (host: ContainerHost, engine: EngineKind) =>
    invoke<NetworkSummary[]>("containers_networks", { host, engine }),
  /** Closes a host's kept connection now. */
  releaseContainerHost: (sessionId: string) => invoke<void>("containers_release", { sessionId }),
  /** "Open a shell": a terminal pane that enters the running container. Audited like opening a terminal. */
  containerShellOpen: (
    sessionId: string,
    engine: EngineKind,
    containerId: string,
    cols: number,
    rows: number,
    onOutput: (data: Uint8Array) => void,
    onEvent: (event: TerminalEvent) => void,
  ) => {
    const output = new Channel<ArrayBuffer>();
    output.onmessage = (data) => onOutput(new Uint8Array(data));
    const events = eventChannel(onEvent);
    return invoke<{ id: string; title: string }>("container_shell_open", {
      sessionId,
      engine,
      containerId,
      cols,
      rows,
      onOutput: output,
      onEvent: events,
    });
  },
  /** CT-02: Docker Desktop's docker.exe; null or "" goes back to finding it. */
  setDockerPath: (path: string | null) => invoke<Settings>("settings_set_docker_path", { path }),

  // VM-19 to VM-21: the spec catalogue. Edits are audited and refused by the read-only lock.
  catalogProfiles: () => invoke<OsProfile[]>("catalog_profiles"),
  catalogSites: () => invoke<ImageSite[]>("catalog_sites"),
  /** The twelve built-ins, then the owner's own. */
  catalogSizes: () => invoke<Size[]>("catalog_sizes"),
  catalogSizeAdd: (input: SizeInput) => invoke<Size>("catalog_size_add", { input }),
  catalogSizeUpdate: (id: string, input: SizeInput) => invoke<Size>("catalog_size_update", { id, input }),
  catalogSizeDelete: (id: string) => invoke<void>("catalog_size_delete", { id }),
  catalogImages: () => invoke<Image[]>("catalog_images"),
  /** A file picked in a dialog the core opens (Downloads by default); null when cancelled. */
  catalogImagePick: (kind: ImageKind) => invoke<string | null>("catalog_image_pick", { kind }),
  /** A folder for a template's VMs, picked in a dialog the core opens; null when cancelled. */
  catalogFolderPick: () => invoke<string | null>("catalog_folder_pick"),
  /** A file is checked and hashed first; progress comes as catalogHashProgress events under `request`. */
  catalogImageAdd: (request: string, input: ImageInput) => invoke<Image>("catalog_image_add", { request, input }),
  catalogImageCancel: (request: string) => invoke<boolean>("catalog_image_cancel", { request }),
  onCatalogHash: (handler: (progress: HashProgress) => void): Promise<UnlistenFn> =>
    listen<HashProgress>("catalog://hash", (e) => handler(e.payload)),
  catalogImageUpdate: (id: string, edit: ImageEdit) => invoke<Image>("catalog_image_update", { id, edit }),
  /** The catalogue's entry only; the file or VM stays. */
  catalogImageDelete: (id: string) => invoke<void>("catalog_image_delete", { id }),
  catalogTemplates: () => invoke<LaunchTemplate[]>("catalog_templates"),
  catalogTemplatePreview: (input: TemplateInput) => invoke<TemplatePreview>("catalog_template_preview", { input }),
  catalogTemplateAdd: (input: TemplateInput) => invoke<LaunchTemplate>("catalog_template_add", { input }),
  catalogTemplateUpdate: (id: string, input: TemplateInput) =>
    invoke<LaunchTemplate>("catalog_template_update", { id, input }),
  catalogTemplateDelete: (id: string) => invoke<void>("catalog_template_delete", { id }),
  /** Opens an official cloud image page; the core refuses any other address. */
  catalogOpenSite: (url: string) => invoke<void>("catalog_open_site", { url }),
  // VM-21, VM-22, VM-10: deploy. A check is a read; a submit goes through the bus (approval, then one job).
  deployCheck: (request: DeployRequest) => invoke<DeployCheck>("deploy_check", { request }),
  deploySubmit: (request: DeployRequest) => invoke<SubmitOutcome>("deploy_submit", { request }),
  deployCloneCheck: (request: CloneRequest) => invoke<DeployCheck>("deploy_clone_check", { request }),
  deployCloneSubmit: (request: CloneRequest) => invoke<SubmitOutcome>("deploy_clone_submit", { request }),
  deployHostAdapters: (bridged: boolean) => invoke<string[]>("deploy_host_adapters", { bridged }),
  deployDefaultFolder: (hypervisor: Hypervisor) => invoke<string>("deploy_default_folder", { hypervisor }),
};
