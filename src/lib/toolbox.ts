// FD-09: the Toolbox page's pure helpers: its tools in tab order, the targets a row menu hands it, the last inputs per
// tool kept in the window's local storage (every access in try/catch: a private profile or a full disk throws), and
// the words results are shown in. Tested in toolbox.test.ts.

import type {
  CertificateReport,
  DnsFailure,
  DnsServerUsed,
  Echo,
  PingSummary,
  PortState,
  ProbeTarget,
  TraceHop,
} from "./toolbox-api.ts";

export type ToolboxTool = "ping" | "trace" | "dns" | "ports" | "certificate" | "subnet" | "wake";

/** The tabs, in order. F9 adds the file server after these. */
export const TOOLBOX_TOOLS: readonly { id: ToolboxTool; label: string }[] = [
  { id: "ping", label: "Ping" },
  { id: "trace", label: "Trace route" },
  { id: "dns", label: "DNS lookup" },
  { id: "ports", label: "Check ports" },
  { id: "certificate", label: "Certificate" },
  { id: "subnet", label: "Subnet calculator" },
  { id: "wake", label: "Wake up" },
];

export function isToolboxTool(value: unknown): value is ToolboxTool {
  return typeof value === "string" && TOOLBOX_TOOLS.some((t) => t.id === value);
}

/** What a tool is pointed at, with the name to show for a session or VM. */
export type ToolTarget =
  | { kind: "address"; host: string }
  | { kind: "session"; sessionId: string; label: string }
  | { kind: "vm"; vmKey: string; label: string };

/** The target as the core takes it. */
export function probeTarget(target: ToolTarget): ProbeTarget {
  switch (target.kind) {
    case "address":
      return { kind: "address", host: target.host.trim() };
    case "session":
      return { kind: "session", sessionId: target.sessionId };
    case "vm":
      return { kind: "vm", vmKey: target.vmKey };
  }
}

/** A tool's target is set: a session or VM, or a host typed in. */
export function hasTarget(target: ToolTarget): boolean {
  return target.kind !== "address" || target.host.trim().length > 0;
}

// ---- Recent inputs ----

/** Inputs kept per tool. */
export const HISTORY_LIMIT = 20;

/** The part of Storage the history uses (localStorage in the window, a map in tests). */
export interface HistoryStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** FD-02: each workspace keeps its own list, so one customer's hosts are never offered in another's workspace. */
function key(tool: ToolboxTool, workspace: string): string {
  return `remotely.toolbox.recent.${workspace}.${tool}`;
}

function windowStorage(): HistoryStorage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

/** The tool's last inputs in `workspace`, newest first. Nothing when storage can't be read or the workspace isn't known yet. */
export function recentInputs(
  tool: ToolboxTool,
  workspace: string | null,
  storage: HistoryStorage | null = windowStorage(),
): string[] {
  if (!storage || !workspace) return [];
  try {
    const raw = storage.getItem(key(tool, workspace));
    if (!raw) return [];
    const list: unknown = JSON.parse(raw);
    if (!Array.isArray(list)) return [];
    return list.filter((v): v is string => typeof v === "string").slice(0, HISTORY_LIMIT);
  } catch {
    return [];
  }
}

/**
 * Keeps `input` first in the tool's list in `workspace` (once, any letter case), at most HISTORY_LIMIT. Returns the
 * new list. With no workspace known yet nothing is saved.
 */
export function rememberInput(
  tool: ToolboxTool,
  workspace: string | null,
  input: string,
  storage: HistoryStorage | null = windowStorage(),
): string[] {
  const value = input.trim();
  const before = recentInputs(tool, workspace, storage);
  if (!value || value.length > 300) return before;
  const list = [value, ...before.filter((v) => v.toLowerCase() !== value.toLowerCase())].slice(0, HISTORY_LIMIT);
  if (!storage || !workspace) return list;
  try {
    storage.setItem(key(tool, workspace), JSON.stringify(list));
  } catch {
    // Storage full or blocked: the list lasts as long as the page.
  }
  return list;
}

// The workspace whose lists the tools show: the Toolbox page sets it once it knows (the window loads again after a
// switch, so it changes only from null to the shown workspace).
let scope: string | null = null;
const scopeListeners = new Set<() => void>();

export function recentScope(): string | null {
  return scope;
}

export function setRecentScope(workspace: string): void {
  if (scope === workspace) return;
  scope = workspace;
  for (const listener of scopeListeners) listener();
}

export function subscribeRecentScope(listener: () => void): () => void {
  scopeListeners.add(listener);
  return () => {
    scopeListeners.delete(listener);
  };
}

// ---- Words ----

/** "<1 ms", "12 ms". */
export function rttText(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "*";
  return ms < 1 ? "<1 ms" : `${Math.round(ms * 10) / 10} ms`;
}

/** One ping reply as a line. */
export function echoText(echo: Echo): string {
  switch (echo.kind) {
    case "reply":
      return `Reply from ${echo.from}: ${rttText(echo.rttMs)}${echo.ttl !== null ? `, TTL ${echo.ttl}` : ""}`;
    case "ttlExpired":
      return `TTL expired at ${echo.from}`;
    case "unreachable":
      return echo.from ? `${echo.from}: ${echo.reason}` : echo.reason;
    case "timedOut":
      return "No answer";
  }
}

/** "4 sent, 3 received, 25% lost · 1 / 2.5 / 4 ms". */
export function pingSummaryText(summary: PingSummary): string {
  const loss = `${Math.round(summary.lossPercent)}% lost`;
  const counts = `${summary.sent} sent, ${summary.received} received, ${loss}`;
  if (summary.avgMs === null) return counts;
  return `${counts} · min ${rttText(summary.minMs)}, average ${rttText(summary.avgMs)}, max ${rttText(summary.maxMs)}`;
}

/** A hop's times: "1 ms  2 ms  *". */
export function hopTimes(hop: TraceHop): string {
  return hop.rttsMs.map((ms) => rttText(ms)).join("  ");
}

export function portStateText(state: PortState): string {
  switch (state) {
    case "open":
      return "Open";
    case "closed":
      return "Closed";
    case "noAnswer":
      return "No answer";
    case "failed":
      return "Failed";
  }
}

export function dnsFailureText(failure: DnsFailure): string {
  switch (failure.kind) {
    case "noSuchName":
      return "The name doesn't exist.";
    case "noRecords":
      return "The name has no record of this type.";
    case "failed":
      return `The lookup failed: ${failure.message}`;
  }
}

/** Which server answered, in words. */
export function dnsServerText(server: DnsServerUsed): string {
  if (server.kind === "chosen") return `Asked ${server.address}`;
  return server.servers.length > 0
    ? `Windows' resolver (this PC's DNS servers: ${server.servers.join(", ")})`
    : "Windows' resolver";
}

/** "Expires in 42 days", "Expired 3 days ago", "Expires today". */
export function daysLeftText(days: number | null): string | null {
  if (days === null) return null;
  if (days > 1) return `Expires in ${days} days`;
  if (days === 1) return "Expires tomorrow";
  if (days === 0) return "Expires today";
  if (days === -1) return "Expired yesterday";
  return `Expired ${-days} days ago`;
}

/** The certificate's verdict in a line, and whether it is good. */
export function certificateVerdict(report: CertificateReport): { ok: boolean; text: string } {
  const problems: string[] = [];
  if (!report.trusted) problems.push("not trusted by this PC");
  if (report.nameMatches === false) problems.push(`doesn't name ${report.serverName ?? "the host"}`);
  if (report.daysLeft !== null && report.daysLeft < 0) problems.push("expired");
  if (problems.length === 0) {
    const days = daysLeftText(report.daysLeft);
    return { ok: true, text: days ? `Trusted and valid · ${days.toLowerCase()}` : "Trusted and valid" };
  }
  const text = problems.join(", ");
  return { ok: false, text: text.charAt(0).toUpperCase() + text.slice(1) };
}

/** A MAC as `aa:bb:cc:dd:ee:ff`, or null for one no network card has (the core checks again). */
export function normalizeMac(text: string): string | null {
  const hex = text.trim().replace(/[:\-.\s]/g, "");
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) return null;
  const bytes = hex.toLowerCase().match(/../g) ?? [];
  const first = parseInt(bytes[0] ?? "0", 16);
  if (hex === "000000000000" || /^f{12}$/i.test(hex) || (first & 1) === 1) return null;
  return bytes.join(":");
}

/** An IPv4 address a magic packet can go to, or null. */
export function wakeAddress(text: string): string | null {
  const value = text.trim();
  const parts = value.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
  const first = Number(parts[0]);
  if (value === "0.0.0.0" || (first >= 224 && first <= 239)) return null;
  return parts.map(Number).join(".");
}
