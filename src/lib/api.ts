// Typed wrappers over the Tauri IPC commands in src-tauri/src/ipc.rs, terminal.rs, multiexec.rs, command_panel.rs and
// files.rs.
// The UI talks to the Rust core only through these; it never runs vmrun or SSH itself.
// Types mirror the serde shapes in crates/core.

import { Channel, invoke as tauriInvoke, type InvokeArgs, type InvokeOptions } from "@tauri-apps/api/core";
import { listen as tauriListen, type EventCallback, type UnlistenFn } from "@tauri-apps/api/event";
import { learnFields, masker } from "@/lib/presentation";

// FD-03: every answer and event passes the host, IP and user fields it holds to the presentation masker, so those
// values are masked wherever they show while presenting (presentation.ts). Nothing is changed or stored.
async function invoke<T>(cmd: string, args?: InvokeArgs, options?: InvokeOptions): Promise<T> {
  const answer = await tauriInvoke<T>(cmd, args, options);
  learnFields(masker, answer);
  return answer;
}

function listen<T>(event: string, handler: EventCallback<T>): Promise<UnlistenFn> {
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
  | { kind: "terminal"; terminalId: string; sessionId?: string | null };

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

/** VM-04. Revert and delete take a name, or vmrun's path form ("base/child") when a VM has two snapshots with one name. */
export type SnapshotOp =
  { kind: "take"; name: string } | { kind: "revert"; name: string } | { kind: "delete"; name: string };

/** VM-04: one snapshot, read from the VM's .vmsd file. */
export interface SnapshotNode {
  uid: number;
  parentUid: number | null;
  name: string;
  /** vmrun's path form, e.g. "base/child one". */
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
      /** Seconds each host may take; null: no limit. */
      timeoutSecs?: number | null;
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
    }
  /** SS-10: the held Enter of a MultiExec line. The UI never submits it itself: MultiExec does. */
  | { type: "terminalLine"; targets: TargetRef[]; line: string; unreliable: boolean; keys: string }
  /** SS-08: an upload. Never submitted by the UI: `filesUpload` builds it in Rust from picked or dropped files. */
  | { type: "fileUpload"; targets: TargetRef[]; folder: string; files: UploadFile[] }
  /** SS-07: a saved port forward opened on a terminal. Never submitted by the UI: `terminalTunnelStart` builds it. */
  | { type: "openTunnel"; targets: TargetRef[]; forward: PortForward };

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

export type TargetStatus = "pending" | "running" | "succeeded" | "failed" | "skipped" | "cancelled";

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
    }
  /** VM-03: these VMs did not shut down. Forcing them off is a separate, Critical command. */
  | { event: "stillRunning"; jobId: string; targets: Target[] }
  | { event: "finished"; jobId: string; status: JobStatus };

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
    }
  /** A line waits for its Enter; these keys follow it. */
  | { status: "queued"; lineId: string; dropped: boolean };

export type MultiExecEvent =
  | { event: "lineDone"; lineId: string; sent: boolean; terminals: number; status: JobStatus | null }
  | { event: "outcome"; outcome: MultiExecOutcome };

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
  /** AP-03: when the countdown ends, while the job is in it. */
  countdownUntil: string | null;
  /** BX-04: the job whose failed targets this one retries. */
  retryOf: string | null;
}

/** One target of a job and how it went. */
export interface JobTarget {
  targetKind: "vm" | "session" | "app";
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
  | "fileUpload"
  | "fileReplace"
  | "tunnelLocal"
  | "tunnelRemote"
  | "tunnelShared"
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
  /** Targets from which the bulk tier applies. */
  bulkThreshold: number;
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
  | { method: "agent" };

/** What the session editor sends; the core checks and tidies it. */
export interface SessionInput {
  /** Empty: the host is used. */
  name: string;
  folderId: string | null;
  host: string;
  port: number;
  username: string | null;
  auth: SessionAuth;
  jumpSessionId: string | null;
  startupCommand: string | null;
  /** SS-06: Prod raises the approval tier by one. */
  environment: Environment;
  color: SessionColor | null;
  tags: string[];
  /** BX-01: the VM this session reaches (its id), so a bulk run can pick the VM. */
  vmId: string | null;
}

export interface SessionRecord extends SessionInput {
  id: string;
  protocol: string;
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

export interface SessionFolder {
  id: string;
  /** null: at the top level. */
  parentId: string | null;
  name: string;
  sortOrder: number;
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
  | { event: "folder"; folder: FolderInfo };

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
 * (a reconnect tries again).
 */
export type FolderTracking = "waiting" | "following" | "unsupported" | "missed";

export interface FolderInfo {
  path: string | null;
  tracking: FolderTracking;
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
  path: string;
  parent: string | null;
  entries: RemoteEntry[];
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
  /** QL-04: seconds between two checks of a session, 15 to 3600. */
  reachabilitySecs: number;
  /** QL-07: a Windows notification when a long command in a background tab finishes. */
  notifyFinished: boolean;
  /** QL-07: seconds a command must run to count as long, 5 to 3600. */
  notifyAfterSecs: number;
  /** QL-07: seconds without output that end a command whose prompt is not recognised; 0: wait for the prompt. */
  notifyQuietSecs: number;
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
  // Area section.
  | "systemInfo"
  | "disk"
  | "storageLvm"
  | "storageSan"
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
  /** SS-07: port forwards saved with the imported sessions. */
  forwards: number;
  foldersAdded: number;
  /** Sessions imported without the password or key they used. */
  withoutCredentials: number;
  problems: { name: string; reason: string }[];
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

export interface ResolvedTargets {
  hosts: BulkHost[];
  /** Picked VMs no session reaches; guest commands without SSH (VM-09) come in v2. */
  vmsWithoutSession: VmWithoutSession[];
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

/** MO-03 drill-down: one point of a chart. In memory only (history in SQLite is MO-06, v2). */
export interface MetricPoint {
  /** Unix time in milliseconds. */
  t: number;
  cpuPct: number | null;
  memBytes: number | null;
  diskReadBps: number | null;
  diskWriteBps: number | null;
  netRxBps: number | null;
  netTxBps: number | null;
  load1: number | null;
  diskUsedPct: number | null;
}

export type GuestState =
  "connecting" | "ok" | "vaultLocked" | "unreachable" | "loginFailed" | "hostKey" | "noData" | "error";

/** MO-02: where guest polling stands for one watched session. */
export interface GuestStatus {
  sessionId: string;
  state: GuestState;
  /** What went wrong, for the user. Never holds a secret. */
  message: string | null;
  /** Seconds until the next try, while backing off. */
  retryInSecs: number | null;
  lastOk: string | null;
}

/** MO-01 NFR: what collecting costs. */
export interface CollectorCost {
  rounds: number;
  intervalSecs: number;
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
  /** The .vmx path or the session id. */
  key: string;
  name: string;
  environment: Environment;
  protected: boolean;
  tags: string[];
  powerState: PowerState | null;
  vcpus: number | null;
  memsizeMb: number | null;
  /** A VM's IP, or a session's user@host:port. */
  address: string | null;
  guestOs: string | null;
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
  warnings: CapacityWarning[];
}

/** FD-14: a newer signed release on GitHub. */
export interface UpdateInfo {
  currentVersion: string;
  version: string;
  notes: string | null;
  pubDate: string | null;
}

/** FD-14: what an update check found, or why it did not ask GitHub. */
export type UpdateCheck =
  | { status: "off" }
  /** No GitHub update token in the vault: the private repository's releases can't be read. */
  | { status: "noToken" }
  /** The token is in the vault, which is locked. Check again once it is unlocked. */
  | { status: "vaultLocked" }
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
export const UPDATE_TOKEN_ERRORS = ["update_token_refused", "update_token_no_access", "update_token_missing"];

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

  /** VM-04: snapshot trees read from each VM's .vmsd (no vmrun call). Changes go through `submit`. */
  snapshots: (vmxPaths?: string[]) => invoke<VmSnapshots[]>("snapshots_list", { vmxPaths: vmxPaths ?? null }),
  snapshotLimits: () => invoke<SnapshotLimits>("snapshot_limits"),

  /** AP-01: the approval rules in force, and what the editor needs to change them. */
  policyRules: () => invoke<PolicyRules>("policy_rules"),
  policyCatalog: () => invoke<PolicyCatalog>("policy_catalog"),
  /** Checked by the core (an invalid rule fails with code "invalid_rule") and audited. */
  setPolicyRules: (rules: PolicyRules) => invoke<PolicySaved>("policy_set_rules", { rules }),
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
  setUpdateChecks: (enabled: boolean) => invoke<Settings>("settings_set_update_checks", { enabled }),
  /** VM-01: each folder must exist. */
  setScanFolders: (folders: string[]) => invoke<Settings>("settings_set_scan_folders", { folders }),
  setPowerOnLimit: (limit: number) => invoke<Settings>("settings_set_power_on_limit", { limit }),
  setShutdownWait: (secs: number) => invoke<Settings>("settings_set_shutdown_wait", { secs }),
  /** BX-02: how many hosts a bulk run reaches at once. */
  setBulkParallel: (limit: number) => invoke<Settings>("settings_set_bulk_parallel", { limit }),
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
  createSession: (input: SessionInput) => invoke<SessionRecord>("session_create", { input }),
  updateSession: (id: string, input: SessionInput) => invoke<SessionRecord>("session_update", { id, input }),
  duplicateSession: (id: string) => invoke<SessionRecord>("session_duplicate", { id }),
  deleteSession: (id: string) => invoke<void>("session_delete", { id }),
  /** QL-01: links a session to a VM by hand (vmId null removes the link); auto-linking leaves it alone. Audited. */
  linkSessionVm: (sessionId: string, vmId: string | null) =>
    invoke<SessionRecord>("session_link_vm", { sessionId, vmId }),
  /** QL-01: keeps an automatic link, so auto-linking never changes it. Audited. */
  confirmSessionVmLink: (sessionId: string) => invoke<SessionRecord>("session_confirm_vm_link", { sessionId }),
  /** QL-01: sessions several VMs match, left for the user to pick. */
  ambiguousVmLinks: () => invoke<AmbiguousLink[]>("vm_links_ambiguous"),
  /** folderId null: the top level. */
  moveSessions: (ids: string[], folderId: string | null) => invoke<void>("sessions_move", { ids, folderId }),
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
  moveFolder: (id: string, parentId: string | null) => invoke<SessionFolder>("folder_move", { id, parentId }),
  /** Its sessions and subfolders move up to its parent. */
  deleteFolder: (id: string) => invoke<void>("folder_delete", { id }),

  /**
   * SS-02: reads a session list (PuTTY's registry, or a file chosen in a dialog the core opens; the
   * OpenSSH config is ~/.ssh/config unless chooseFile) and compares it with the library. null when the
   * dialog was closed.
   */
  importPreview: (source: ImportSource, chooseFile = false) =>
    invoke<ImportPreview | null>("import_preview", { source, chooseFile }),
  /** Saves the picked rows of a preview; key files go into the vault when addKeys. */
  importCommit: (request: { previewId: string; rows: number[]; folderId: string | null; addKeys: boolean }) =>
    invoke<ImportReport>("import_commit", { request }),

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
  /** BX-04: the failed hosts again, as a new job through the bus (it may need approval). */
  bulkRetryFailed: (jobId: string) => invoke<SubmitOutcome>("bulk_retry_failed", { jobId }),
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
  /** SS-11: the terminals' text with their login secrets scrubbed, for the clipboard. */
  terminalOutputText: (items: TerminalText[]) => invoke<TerminalText[]>("terminal_output_text", { items }),
  /** SS-11: the same for printing; audited as printed. */
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
  /** BX-08 built-in commands, classified with the current rules. */
  commandLibrary: () => invoke<LibraryEntry[]>("command_library"),
  /** BX-08: a command's variables and what the policy engine makes of it. */
  commandInspect: (command: string) => invoke<CommandInfo>("command_inspect", { command }),
  /** BX-08: the command with its variables filled in, ready to paste. */
  commandFill: (command: string, values: Record<string, string>) => invoke<string>("command_fill", { command, values }),
  /**
   * QL-06: types a vault password or passphrase, then Enter, into the terminal when it shows a password prompt (or
   * with `force`). The value never reaches the UI. Fails with `no_password_prompt` at a shell prompt.
   */
  terminalTypeSecret: (id: string, secretId: string, force: boolean) =>
    invoke<void>("terminal_type_secret", { id, secretId, force }),
  /** QL-07: a Windows notification that a long command finished in a background tab. */
  notifyCommandFinished: (title: string, body: string) => invoke<void>("notify_command_finished", { title, body }),

  /** SS-08: the shell's folder as far as it is known. */
  filesFolder: (id: string) => invoke<FolderInfo | null>("files_folder", { id }),
  /** SS-08: a folder on the terminal's host; without a path, the shell's folder (or home). */
  filesList: (id: string, path: string | null) => invoke<FolderListing>("files_list", { id, path }),
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
};
