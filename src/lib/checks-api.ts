// MO-08: typed wrappers over the health checks' IPC commands in src-tauri/src/checks.rs. Types mirror the serde shapes
// in crates/core/src/checks. Like api.ts, every answer and event goes past the presentation masker (FD-03): a target's
// `host` is a field it learns.

import { invoke, listen } from "@/lib/api";
import type { HistoryRange } from "@/lib/dashboard-api";
import type { ProbeTarget } from "@/lib/toolbox-api";

export type DnsRecordKind = "A" | "AAAA";

/** What a check does, with the kind's own fields. */
export type CheckSpec =
  | { kind: "ping" }
  | { kind: "tcp"; port: number }
  | {
      kind: "http";
      https: boolean;
      /** null: 80, or 443 for HTTPS. */
      port: number | null;
      path: string;
      statusMin: number;
      statusMax: number;
      bodyContains: string | null;
      followRedirects: boolean;
      allowInvalidCert: boolean;
    }
  | { kind: "certificate"; port: number; serverName: string | null; allowUntrusted: boolean }
  | { kind: "dns"; recordType: DnsRecordKind; server: string | null; expect: string | null }
  | { kind: "service"; unit: string };

export type CheckKind = CheckSpec["kind"];

export interface CheckInput {
  name: string;
  target: ProbeTarget;
  spec: CheckSpec;
  intervalSecs: number;
  timeoutSecs: number;
  failuresBeforeDown: number;
  paused: boolean;
}

export interface HealthCheck extends CheckInput {
  id: string;
  createdAt: string;
  updatedAt: string;
}

export type RunResult = "up" | "down" | "unknown";

export interface CheckResult {
  /** Unix ms. */
  at: number;
  result: RunResult;
  tookMs: number | null;
  detail: string;
  certDays: number | null;
}

export type CheckStatus = "pending" | "up" | "failing" | "down" | "unknown" | "paused";

export interface CheckSummary {
  total: number;
  up: number;
  failing: number;
  down: number;
  unknown: number;
  paused: number;
  pending: number;
}

export interface CheckTargetInfo {
  kind: "address" | "session" | "vm";
  name: string;
  /** FD-03: a field the masker learns. */
  host: string | null;
  missing: boolean;
}

export interface SparkPoint {
  at: number;
  ms: number | null;
  up: number;
  down: number;
}

export interface CheckRow {
  check: HealthCheck;
  target: CheckTargetInfo;
  status: CheckStatus;
  failures: number;
  last: CheckResult | null;
  uptime: number | null;
  spark: SparkPoint[];
  /** Its host (or jump host) couldn't be reached: no login is tried before then (Unix ms); the status stays. */
  waitingUntil: number | null;
}

/** The widget's read: the counts and the checks that need a look, without their history. */
export interface ChecksAttention {
  summary: CheckSummary;
  rows: CheckRow[];
}

export interface ChecksOverview {
  rows: CheckRow[];
  summary: CheckSummary;
}

export interface CheckHistory {
  row: CheckRow;
  results: CheckResult[];
}

export type CheckEvent =
  | {
      kind: "result";
      checkId: string;
      result: CheckResult;
      status: CheckStatus;
      failures: number;
      summary: CheckSummary;
    }
  | { kind: "changed"; summary: CheckSummary };

export const checksApi = {
  overview: (range: HistoryRange) => invoke<ChecksOverview>("checks_overview", { range }),
  summary: () => invoke<CheckSummary>("checks_summary"),
  /** Cheap: no history is read. */
  attention: () => invoke<ChecksAttention>("checks_attention"),
  history: (id: string, range: HistoryRange) => invoke<CheckHistory>("check_history", { id, range }),
  /** Audited; refused while presenting with the read-only lock. */
  create: (input: CheckInput) => invoke<HealthCheck>("check_create", { input }),
  update: (id: string, input: CheckInput) => invoke<HealthCheck>("check_update", { id, input }),
  setPaused: (id: string, paused: boolean) => invoke<HealthCheck>("check_pause", { id, paused }),
  remove: (id: string) => invoke<void>("check_delete", { id }),
  /** A read: not audited. */
  runNow: (id: string) => invoke<void>("check_run_now", { id }),
  onEvent: (handler: (event: CheckEvent) => void) => listen<CheckEvent>("checks://event", (e) => handler(e.payload)),
};
