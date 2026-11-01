// MO-08: health checks in words and the editor's form, as pure functions (tested in checks.test.ts): each kind and
// its defaults, a check in a line, the editor's checks (the core checks again: checks/spec.rs), statuses, uptime, the
// status bar's text and a sparkline's path.

import type {
  CheckInput,
  CheckKind,
  CheckResult,
  CheckRow,
  CheckSpec,
  CheckStatus,
  CheckSummary,
} from "./checks-api.ts";
import type { ProbeTarget } from "./toolbox-api.ts";

export const KINDS: { value: CheckKind; label: string; hint: string }[] = [
  { value: "http", label: "HTTP(S)", hint: "A GET request: up when the status is in the range" },
  { value: "tcp", label: "TCP port", hint: "A connection to a port" },
  { value: "ping", label: "Ping", hint: "One echo request from this PC" },
  { value: "certificate", label: "Certificate", hint: "A TLS certificate: valid, trusted, and its days left" },
  { value: "dns", label: "DNS", hint: "A name resolves, optionally to a given address" },
  { value: "service", label: "Service", hint: "A systemd unit on a session's host, over SSH" },
];

/** How often a check may run, as the editor offers it (30 s to 1 h). */
export const INTERVALS: number[] = [30, 60, 120, 300, 600, 900, 1800, 3600];

export const STATUS_LABEL: Record<CheckStatus, string> = {
  pending: "Waiting",
  up: "Up",
  failing: "Failing",
  down: "Down",
  unknown: "Can't check",
  paused: "Paused",
};

/** The badge's look for a status. */
export function statusTone(status: CheckStatus): "ok" | "warn" | "bad" | "muted" {
  switch (status) {
    case "up":
      return "ok";
    case "failing":
    case "unknown":
      return "warn";
    case "down":
      return "bad";
    default:
      return "muted";
  }
}

export function kindLabel(kind: CheckKind): string {
  return KINDS.find((k) => k.value === kind)?.label ?? kind;
}

/** A kind's fields as a new check starts with them. */
export function defaultSpec(kind: CheckKind): CheckSpec {
  switch (kind) {
    case "ping":
      return { kind };
    case "tcp":
      return { kind, port: 22 };
    case "http":
      return {
        kind,
        https: true,
        port: null,
        path: "/",
        statusMin: 200,
        statusMax: 399,
        bodyContains: null,
        followRedirects: true,
        allowInvalidCert: false,
      };
    case "certificate":
      return { kind, port: 443, serverName: null, allowUntrusted: false };
    case "dns":
      return { kind, recordType: "A", server: null, expect: null };
    case "service":
      return { kind, unit: "" };
  }
}

/** Which targets a kind takes: a service reads a session's host; DNS looks up a name, not a VM's address. */
export function kindTakes(kind: CheckKind, target: ProbeTarget["kind"]): boolean {
  if (kind === "service") return target === "session";
  if (kind === "dns") return target !== "vm";
  return true;
}

/** A new check on `target`, named after it ("web01 HTTP(S)"). */
export function newCheckInput(target: ProbeTarget, targetName: string, kind: CheckKind = "http"): CheckInput {
  const usable = kindTakes(kind, target.kind) ? kind : "tcp";
  return {
    name: suggestedName(targetName, usable),
    target,
    spec: defaultSpec(usable),
    intervalSecs: 60,
    timeoutSecs: 10,
    failuresBeforeDown: 2,
    paused: false,
  };
}

/** "web01 HTTP(S)", at most 80 characters; empty without a target name yet. */
export function suggestedName(targetName: string, kind: CheckKind): string {
  if (!targetName.trim()) return "";
  const name = `${targetName.trim()} ${kindLabel(kind)}`.trim();
  return name.length > 80 ? name.slice(0, 80).trim() : name;
}

/** "every 1 minute", "every 30 seconds". */
export function everyText(secs: number): string {
  const unit = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;
  if (secs >= 3600 && secs % 3600 === 0) return `every ${unit(secs / 3600, "hour")}`;
  if (secs >= 60 && secs % 60 === 0) return `every ${unit(secs / 60, "minute")}`;
  return `every ${unit(secs, "second")}`;
}

/** A check's kind in a line: "HTTPS GET /health (200-399)", "TCP port 22". */
export function specText(spec: CheckSpec): string {
  switch (spec.kind) {
    case "ping":
      return "Ping";
    case "tcp":
      return `TCP port ${spec.port}`;
    case "http": {
      const port = spec.port === null ? "" : ` port ${spec.port}`;
      return `${spec.https ? "HTTPS" : "HTTP"}${port} GET ${spec.path} (${spec.statusMin}-${spec.statusMax})`;
    }
    case "certificate":
      return `Certificate on port ${spec.port}`;
    case "dns":
      return spec.expect ? `DNS ${spec.recordType} record, expecting ${spec.expect}` : `DNS ${spec.recordType} record`;
    case "service":
      return `Service ${spec.unit}`;
  }
}

const UNIT = /^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,254}$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/** An IPv4 address, or something IPv6-shaped (the core checks it properly). */
export function looksLikeIp(text: string): boolean {
  const t = text.trim();
  return IPV4.test(t) || (t.includes(":") && /^[0-9a-fA-F:.]+$/.test(t));
}

/** Why the check can't be saved yet, or null. The core checks the same things. */
export function checkProblem(input: CheckInput): string | null {
  const name = input.name.trim();
  if (!name) return "Give the check a name.";
  if (name.length > 80) return "A check's name can be at most 80 characters.";
  if (input.target.kind === "address" && !input.target.host.trim()) return "Type a host name or an IP address.";
  if (input.target.kind === "session" && !input.target.sessionId) return "Choose a session.";
  if (input.target.kind === "vm" && !input.target.vmKey) return "Choose a VM.";
  if (!kindTakes(input.spec.kind, input.target.kind)) {
    return input.spec.kind === "service"
      ? "A service check reads a session's host: choose a session."
      : "A DNS check looks up a name: choose a session or type a host name.";
  }
  if (input.intervalSecs < 30 || input.intervalSecs > 3600) return "A check runs every 30 seconds to 1 hour.";
  if (!Number.isInteger(input.timeoutSecs) || input.timeoutSecs < 1 || input.timeoutSecs > 60) {
    return "A run's timeout is 1 to 60 seconds.";
  }
  if (input.timeoutSecs >= input.intervalSecs) return "A run's timeout must be shorter than the time between runs.";
  if (!Number.isInteger(input.failuresBeforeDown) || input.failuresBeforeDown < 1 || input.failuresBeforeDown > 10) {
    return "A check counts as down after 1 to 10 failed runs in a row.";
  }
  const port = (p: number | null) => p === null || (Number.isInteger(p) && p >= 1 && p <= 65535);
  const spec = input.spec;
  switch (spec.kind) {
    case "tcp":
    case "certificate":
      if (!port(spec.port)) return "Choose a port from 1 to 65535.";
      break;
    case "http":
      if (!port(spec.port)) return "Choose a port from 1 to 65535.";
      if (/\s/.test(spec.path) || spec.path.trim().startsWith("//") || spec.path.length > 2048) {
        return "The path is like /health or /status?full=1: no spaces, at most 2,048 characters.";
      }
      if (
        !Number.isInteger(spec.statusMin) ||
        !Number.isInteger(spec.statusMax) ||
        spec.statusMin < 100 ||
        spec.statusMax > 599 ||
        spec.statusMin > spec.statusMax
      ) {
        return "The expected status is a range from 100 to 599, like 200-399.";
      }
      if ((spec.bodyContains ?? "").length > 200) return "The text to find can be at most 200 characters.";
      break;
    case "dns":
      if (input.target.kind === "address" && looksLikeIp(input.target.host)) {
        return "A DNS check looks up a name: type a host name, not an address.";
      }
      if (spec.server && !looksLikeIp(spec.server)) return "Type the DNS server as an IP address.";
      if (spec.expect && !looksLikeIp(spec.expect)) return "Type the expected address as an IP address.";
      break;
    case "service":
      if (!UNIT.test(spec.unit.trim())) {
        return "A unit's name is letters, digits and : _ . @ - (like nginx.service), starting with a letter or digit.";
      }
      break;
    case "ping":
      break;
  }
  return null;
}

/** The input as the core takes it: text fields trimmed, empty optional ones null. */
export function cleanCheckInput(input: CheckInput): CheckInput {
  const spec = input.spec;
  const blank = (t: string | null) => (t && t.trim() ? t.trim() : null);
  let clean: CheckSpec = spec;
  switch (spec.kind) {
    case "http":
      clean = { ...spec, path: spec.path.trim() || "/", bodyContains: blank(spec.bodyContains) };
      break;
    case "certificate":
      clean = { ...spec, serverName: blank(spec.serverName) };
      break;
    case "dns":
      clean = { ...spec, server: blank(spec.server), expect: blank(spec.expect) };
      break;
    case "service":
      clean = { ...spec, unit: spec.unit.trim() };
      break;
    default:
      break;
  }
  const target: ProbeTarget =
    input.target.kind === "address" ? { kind: "address", host: input.target.host.trim() } : input.target;
  return { ...input, name: input.name.trim(), target, spec: clean };
}

/** "99.5%", "100%", or "—" without runs. */
export function uptimeText(uptime: number | null): string {
  if (uptime === null) return "—";
  if (uptime >= 99.95 || uptime === 0) return `${Math.round(uptime)}%`;
  return `${uptime.toFixed(1)}%`;
}

/** "85 ms", "1.2 s". */
export function tookText(ms: number | null): string {
  if (ms === null) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`;
}

/** When a result came, from now: "just now", "3 min ago", "2 h ago", "4 d ago". */
export function agoText(at: number, now: number): string {
  const secs = Math.max(0, Math.round((now - at) / 1000));
  if (secs < 45) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}

/** Down and failing checks need a look; then the ones Remotely can't check. */
export function needingLook(rows: CheckRow[]): CheckRow[] {
  const rank = (s: CheckStatus) => (s === "down" ? 0 : s === "failing" ? 1 : s === "unknown" ? 2 : 3);
  return rows.filter((r) => rank(r.status) < 3).sort((a, b) => rank(a.status) - rank(b.status));
}

/** The status bar's text, or null when every check is fine (or there are none). */
export function summaryText(summary: CheckSummary): string | null {
  const failing = summary.down + summary.failing;
  if (failing === 0) return null;
  return `${failing} check${failing === 1 ? "" : "s"} failing`;
}

/** A result's look for the history list. */
export function resultLabel(result: CheckResult): string {
  switch (result.result) {
    case "up":
      return "Up";
    case "down":
      return "Down";
    case "unknown":
      return "Can't check";
  }
}

/**
 * A sparkline of the time taken, as an SVG path in a `width` x `height` box: one point per bucket with a time, the
 * slowest at the top. Empty without two points.
 */
export function sparkPath(points: { at: number; ms: number | null }[], width: number, height: number): string {
  const timed = points.filter((p): p is { at: number; ms: number } => p.ms !== null && Number.isFinite(p.ms));
  if (timed.length < 2) return "";
  const first = timed[0].at;
  const span = Math.max(1, timed[timed.length - 1].at - first);
  const max = Math.max(1, ...timed.map((p) => p.ms));
  const x = (at: number) => ((at - first) / span) * width;
  const y = (ms: number) => height - (ms / max) * (height - 2) - 1;
  return timed.map((p, i) => `${i === 0 ? "M" : "L"}${x(p.at).toFixed(1)},${y(p.ms).toFixed(1)}`).join(" ");
}
