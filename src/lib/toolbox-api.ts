// FD-09: typed wrappers over the Toolbox's IPC commands in src-tauri/src/toolbox.rs. Types mirror the serde shapes
// in crates/core/src/toolbox. Like api.ts, every answer and event goes past the presentation masker (FD-03), since
// they go through api.ts's `invoke` and `listen`. Wake-on-LAN is `api.submit` with a `wakeOnLan` command.

import { invoke, listen, type TargetRef } from "@/lib/api";

/** What a tool is pointed at. */
export type ProbeTarget =
  { kind: "address"; host: string } | { kind: "session"; sessionId: string } | { kind: "vm"; vmKey: string };

export type Echo =
  | { kind: "reply"; from: string; rttMs: number; ttl: number | null }
  | { kind: "ttlExpired"; from: string; rttMs: number }
  | { kind: "unreachable"; from: string | null; reason: string }
  | { kind: "timedOut" };

export interface PingRequest {
  target: ProbeTarget;
  count: number;
  intervalMs: number;
  size: number;
  timeoutMs: number;
}

export interface PingReply {
  seq: number;
  echo: Echo;
}

export interface PingSummary {
  label: string;
  host: string;
  address: string;
  replies: PingReply[];
  sent: number;
  received: number;
  lossPercent: number;
  minMs: number | null;
  avgMs: number | null;
  maxMs: number | null;
  cancelled: boolean;
}

export interface TraceRequest {
  target: ProbeTarget;
  maxHops: number;
  timeoutMs: number;
  resolveNames: boolean;
}

export interface TraceHop {
  hop: number;
  address: string | null;
  name: string | null;
  rttsMs: (number | null)[];
  reached: boolean;
  note: string | null;
}

export interface TraceSummary {
  label: string;
  host: string;
  address: string;
  hops: TraceHop[];
  reached: boolean;
  cancelled: boolean;
}

export type RecordType = "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "NS" | "SOA" | "PTR" | "SRV" | "CAA";

export const RECORD_TYPES: readonly RecordType[] = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "SOA",
  "PTR",
  "SRV",
  "CAA",
];

export interface DnsRequest {
  name: string;
  recordType: RecordType;
  /** An IP address; null for Windows' resolver. */
  server: string | null;
}

export interface DnsRecord {
  name: string;
  recordType: string;
  ttl: number;
  data: string;
}

export type DnsFailure = { kind: "noSuchName" } | { kind: "noRecords" } | { kind: "failed"; message: string };

export type DnsServerUsed = { kind: "windows"; servers: string[] } | { kind: "chosen"; address: string };

export interface DnsResult {
  name: string;
  recordType: RecordType;
  records: DnsRecord[];
  failure: DnsFailure | null;
  server: DnsServerUsed;
  tookMs: number;
}

export interface PortRequest {
  target: ProbeTarget;
  /** "22, 80, 443, 8000-8010"; empty for a session: its own port. */
  ports: string;
  timeoutMs: number;
  banner: boolean;
}

export type PortState = "open" | "closed" | "noAnswer" | "failed";

export interface PortResult {
  port: number;
  state: PortState;
  ms: number | null;
  banner: string | null;
  detail: string | null;
}

export interface PortSummary {
  label: string;
  host: string;
  address: string | null;
  via: string | null;
  results: PortResult[];
  open: number;
  cancelled: boolean;
}

export interface CertRequest {
  target: ProbeTarget;
  port: number;
  serverName: string | null;
  timeoutMs: number;
}

export interface CertificateInfo {
  subject: string;
  subjectCommonName: string | null;
  issuer: string;
  alternativeNames: string[];
  notBefore: string;
  notAfter: string;
  serial: string;
  key: string;
  signatureAlgorithm: string;
  sha256: string;
  sha1: string;
  isCa: boolean;
  selfIssued: boolean;
}

export interface CertificateReport {
  source: string;
  address: string | null;
  via: string | null;
  serverName: string | null;
  protocol: string | null;
  cipher: string | null;
  chain: CertificateInfo[];
  built: string[];
  trusted: boolean;
  trustProblems: string[];
  nameMatches: boolean | null;
  daysLeft: number | null;
  handshakeError: string | null;
}

export interface WakeAdapter {
  name: string;
  address: string;
  prefix: number;
  broadcast: string;
}

export interface KnownMac {
  mac: string;
  source: string;
}

export interface WakeOptions {
  adapters: WakeAdapter[];
  macs: KnownMac[];
}

export type ProbeProgress =
  { kind: "ping"; reply: PingReply } | { kind: "hop"; hop: TraceHop } | { kind: "port"; result: PortResult };

export const toolboxApi = {
  ping: (run: string, request: PingRequest) => invoke<PingSummary>("toolbox_ping", { run, request }),
  trace: (run: string, request: TraceRequest) => invoke<TraceSummary>("toolbox_trace", { run, request }),
  dns: (request: DnsRequest) => invoke<DnsResult>("toolbox_dns", { request }),
  ports: (run: string, request: PortRequest) => invoke<PortSummary>("toolbox_ports", { run, request }),
  certificate: (run: string, request: CertRequest) =>
    invoke<CertificateReport>("toolbox_certificate", { run, request }),
  /** Opens a file dialog, then reads the certificate. null: the dialog was closed. */
  certificateFile: () => invoke<CertificateReport | null>("toolbox_certificate_file"),
  cancel: (run: string) => invoke<boolean>("toolbox_cancel", { run }),
  wakeOptions: (target: TargetRef | null) => invoke<WakeOptions>("toolbox_wake_options", { target }),
  onProgress: (handler: (event: { run: string; progress: ProbeProgress }) => void) =>
    listen<{ run: string; progress: ProbeProgress }>("toolbox://progress", (e) => handler(e.payload)),
};
