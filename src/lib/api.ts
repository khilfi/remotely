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
  | { type: "appUpdate"; version: string };

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

export type TerminalEvent =
  | { event: "status"; status: TerminalStatus }
  /** SS-05: first connection to a host; answer with `terminalHostKeyAnswer`. */
  | { event: "hostKeyUnknown"; key: HostKey; otherKeyTypes: string[] }
  /** SS-05: the key changed and the connection was blocked. */
  | { event: "hostKeyChanged"; key: HostKey; previous: KnownHost };

/** SS-03 settings. */
export interface TerminalSettings {
  /** Seconds without traffic before a keep-alive; 0: off. */
  keepaliveSecs: number;
  autoReconnect: boolean;
  copyOnSelect: boolean;
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

/** BX-01: what is picked on the Bulk run page. */
export interface TargetPicks {
  sessionIds?: string[];
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
    const events = new Channel<TerminalEvent>();
    events.onmessage = onEvent;
    return invoke<string>("terminal_open", { sessionId, cols, rows, onOutput: output, onEvent: events });
  },
  /** Keystrokes and pastes as raw bytes. */
  terminalWrite: (id: string, data: Uint8Array) =>
    invoke<void>("terminal_write", data, { headers: { "x-terminal-id": id } }),
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
  removeKnownHost: (id: string) => invoke<void>("known_host_remove", { id }),
};
