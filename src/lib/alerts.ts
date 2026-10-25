// MO-07: alerts in words, as pure functions (tested in alerts.test.ts): what each metric and scope means, a rule in a
// line, the editor's checks (the core checks again: alerts/rules.rs), the alert list's order, and the one Windows
// notification for the alerts of a round (never one per alert when many fire at once).

import type {
  Alert,
  AlertMetric,
  AlertRuleInput,
  AlertScope,
  AlertScopeKind,
  Resolution,
  Severity,
} from "./dashboard-api.ts";

export const METRICS: { value: AlertMetric; label: string; hint: string }[] = [
  { value: "cpu", label: "CPU", hint: "Busy share of its own CPUs: the guest's view, else the VM's process" },
  {
    value: "memory",
    label: "Memory",
    hint: "In use against what there is: the guest's view, else the VM's working set",
  },
  { value: "disk", label: "Disk", hint: "The fullest mounted disk of a watched host" },
  { value: "swap", label: "Swap", hint: "Swap in use against its size (this PC: its paging files)" },
  { value: "unreachable", label: "Unreachable", hint: "A watched host that can't be reached" },
  { value: "stopped", label: "Stopped", hint: "A VM that stopped running with no Remotely job on it" },
];

export const SCOPES: { value: AlertScopeKind; label: string }[] = [
  { value: "allVms", label: "Every VM" },
  { value: "vm", label: "One VM" },
  { value: "tag", label: "A tag" },
  { value: "allHosts", label: "Every watched host" },
  { value: "host", label: "One watched host" },
  { value: "thisPc", label: "This PC" },
];

export const SEVERITIES: { value: Severity; label: string }[] = [
  { value: "warning", label: "Warning" },
  { value: "critical", label: "Critical" },
];

/** How long a condition must hold, as the editor offers it. */
export const DURATIONS: number[] = [0, 30, 60, 120, 300, 600, 900, 1800, 3600];

export function metricLabel(metric: AlertMetric): string {
  return METRICS.find((m) => m.value === metric)?.label ?? metric;
}

export function hasThreshold(metric: AlertMetric): boolean {
  return metric === "cpu" || metric === "memory" || metric === "disk" || metric === "swap";
}

/** Whether a metric means anything on a scope (as the core checks it). */
export function scopeAllows(scope: AlertScopeKind, metric: AlertMetric): boolean {
  if (scope === "thisPc") return metric === "cpu" || metric === "memory" || metric === "swap";
  if (scope === "host" || scope === "allHosts") return metric !== "stopped";
  return true;
}

/** "5 minutes", "30 seconds", "1 hour"; "at once" for none. */
export function durationText(secs: number): string {
  if (secs <= 0) return "at once";
  const unit = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;
  if (secs >= 3600 && secs % 3600 === 0) return unit(secs / 3600, "hour");
  if (secs >= 60 && secs % 60 === 0) return unit(secs / 60, "minute");
  return unit(secs, "second");
}

function pct(value: number): string {
  return value >= 10 ? `${Math.round(value)}%` : `${value.toFixed(1)}%`;
}

/** What names the rules' targets: VM keys, session ids. */
export interface ScopeNames {
  vm?: (key: string) => string | undefined;
  session?: (id: string) => string | undefined;
}

export function scopeText(scope: AlertScope, names: ScopeNames = {}): string {
  switch (scope.kind) {
    case "allVms":
      return "every VM";
    case "vm":
      return `the VM ${names.vm?.(scope.key) ?? scope.key}`;
    case "tag":
      return `everything tagged ${scope.tag}`;
    case "allHosts":
      return "every watched host";
    case "host":
      return `the host ${names.session?.(scope.sessionId) ?? "(a saved session)"}`;
    case "thisPc":
      return "this PC";
  }
}

/** A rule's condition in a line: "CPU above 90% for 5 minutes". */
export function conditionText(rule: Pick<AlertRuleInput, "metric" | "threshold" | "forSecs">): string {
  const held = rule.forSecs > 0 ? ` for ${durationText(rule.forSecs)}` : "";
  switch (rule.metric) {
    case "unreachable":
      return `Unreachable${held}`;
    case "stopped":
      return rule.forSecs > 0
        ? `Stopped without a Remotely action, still off after ${durationText(rule.forSecs)}`
        : "Stopped without a Remotely action";
    default:
      return `${metricLabel(rule.metric)} above ${rule.threshold === null ? "—" : pct(rule.threshold)}${held}`;
  }
}

/** A rule as the editor starts a new one. */
export function newRuleInput(): AlertRuleInput {
  return {
    name: "",
    metric: "cpu",
    scope: { kind: "allVms" },
    threshold: 90,
    forSecs: 300,
    severity: "warning",
    notify: true,
    enabled: true,
  };
}

/** A scope of `kind`, keeping what the old one named where it can. */
export function scopeOfKind(kind: AlertScopeKind, old: AlertScope): AlertScope {
  if (kind === old.kind) return old;
  switch (kind) {
    case "vm":
      return { kind, key: "" };
    case "tag":
      return { kind, tag: "" };
    case "host":
      return { kind, sessionId: "" };
    default:
      return { kind };
  }
}

/** Why a rule can't be saved yet, or null. The core checks the same things. */
export function ruleProblem(input: AlertRuleInput): string | null {
  const name = input.name.trim();
  if (!name) return "Give the rule a name.";
  if (name.length > 80) return "A rule's name can be at most 80 characters.";
  if (!scopeAllows(input.scope.kind, input.metric)) {
    return `${metricLabel(input.metric)} can't be watched on ${scopeText(input.scope)}.`;
  }
  if (input.scope.kind === "vm" && !input.scope.key.trim()) return "Choose the VM.";
  if (input.scope.kind === "tag" && !input.scope.tag.trim()) return "Choose the tag.";
  if (input.scope.kind === "host" && !input.scope.sessionId) return "Choose the host.";
  if (hasThreshold(input.metric)) {
    const t = input.threshold;
    if (t === null || !Number.isFinite(t) || t <= 0 || t >= 100) {
      return "The threshold must be more than 0% and less than 100%.";
    }
  }
  if (input.forSecs < 0 || input.forSecs > 86_400) return "A rule can wait at most a day.";
  return null;
}

/** The input as the core takes it: a threshold only where it means something. */
export function cleanRuleInput(input: AlertRuleInput): AlertRuleInput {
  return { ...input, name: input.name.trim(), threshold: hasThreshold(input.metric) ? input.threshold : null };
}

export const RESOLUTION_LABEL: Record<Resolution, string> = {
  cleared: "Cleared",
  gone: "No longer reported",
  ruleChanged: "Rule changed",
  restarted: "Remotely restarted",
};

/** Open first (critical, then the newest), then the resolved ones, newest first. */
export function sortAlerts(alerts: Alert[]): Alert[] {
  const rank = (a: Alert) => (a.resolvedAt ? 2 : a.severity === "critical" ? 0 : 1);
  return [...alerts].sort((a, b) => rank(a) - rank(b) || b.firedAt.localeCompare(a.firedAt));
}

/** The open alerts nobody has acknowledged. */
export function unacknowledged(alerts: Alert[]): Alert[] {
  return alerts.filter((a) => !a.resolvedAt && !a.acknowledgedAt);
}

/**
 * One Windows notification for the alerts that fired in a round and should notify: one alert says what fired where;
 * several are counted, with the first few named. Null when there is nothing to show.
 */
export function notificationText(fired: Alert[]): { title: string; body: string } | null {
  if (fired.length === 0) return null;
  const critical = fired.some((a) => a.severity === "critical");
  if (fired.length === 1) {
    const [a] = fired;
    return { title: `${critical ? "Critical" : "Warning"}: ${a.target.name}`, body: a.message };
  }
  const shown = fired.slice(0, 3).map((a) => `${a.target.name}: ${a.message}`);
  const more = fired.length - shown.length;
  return {
    title: `${fired.length} alerts${critical ? ", some critical" : ""}`,
    body: shown.join("\n") + (more > 0 ? `\nand ${more} more` : ""),
  };
}

/** The reading an alert shows: "97%", or nothing for states. */
export function alertValue(alert: Alert): string | null {
  return alert.value === null ? null : pct(alert.value);
}
