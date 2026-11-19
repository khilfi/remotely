// UX-19 (0.9.0 H4): monitoring setup, as pure functions (tested in monitor.test.ts). Monitor ▸ on session rows, the VM
// details panel and the palette's VM and session views: whether its metrics can be watched or stopped (MO-02: a
// session that reads its guest, over SSH or WinRM; a VM through a session linked to it; any watched session can be
// stopped), and one line on what watching or a check costs (a check behind a jump host goes through it). Where the
// status bar's alerts link leads (MO-07: the Alerts widget, or the rules sheet when the layout has none). And "Keep
// checking this…" on the Toolbox's Ping, Check ports, Certificate and DNS results (FD-09): the `checks` link that
// opens the check editor (MO-08) filled in, the same dialog every "Add a check" opens, offered only for a check the
// editor and the core would take.

import type { SessionKind } from "./api.ts";
import type { CheckInput, CheckSpec, DnsRecordKind } from "./checks-api.ts";
import { checkProblem, kindTakes, newCheckInput } from "./checks.ts";
import type { AppLink } from "./links.ts";
import type { DnsRecord, RecordType } from "./toolbox-api.ts";
import { kindOf, readsGuest } from "./session-kinds.ts";
import { probeTarget, type ToolTarget } from "./toolbox.ts";

// ---- Watch its metrics ----

/** A session, in the words Monitor ▸ needs: whether the dashboard can read its guest (SSH or WinRM). */
export interface WatchableSession {
  id: string;
  name: string;
  readsGuest: boolean;
}

/** What a row's metrics are watched through: the session itself, or the sessions linked to a VM. */
export type WatchSource = { kind: "session"; session: WatchableSession } | { kind: "vm"; sessions: WatchableSession[] };

/** A saved session in those words. */
export function watchable(session: {
  id: string;
  name: string;
  kind?: SessionKind | null;
  protocol?: string;
}): WatchableSession {
  return { id: session.id, name: session.name, readsGuest: readsGuest(kindOf(session)) };
}

/** A session's own row. */
export function sessionSource(session: Parameters<typeof watchable>[0]): WatchSource {
  return { kind: "session", session: watchable(session) };
}

/** A VM's row: the sessions linked to it. */
export function vmSource(
  vmId: string,
  sessions: readonly (Parameters<typeof watchable>[0] & { vmId: string | null })[],
): WatchSource {
  return { kind: "vm", sessions: sessions.filter((s) => s.vmId === vmId).map(watchable) };
}

export type WatchState =
  /** `via`: the linked session a VM's guest is read through (null for a session's own row). */
  { can: true; sessionId: string; watching: boolean; via: string | null } | { can: false; reason: string };

/**
 * The watched sessions as `metrics_watched` gives them: every one, where the overview's rows name one per VM however
 * many of its linked sessions are watched. A poll interval the core didn't give is the default 5 s.
 */
export function watchedFrom(hosts: { sessions: readonly string[]; intervalSecs: number }): {
  watched: Set<string>;
  intervalSecs: number;
} {
  return {
    watched: new Set(hosts.sessions),
    intervalSecs: Number.isFinite(hosts.intervalSecs) && hosts.intervalSecs > 0 ? hosts.intervalSecs : 5,
  };
}

/**
 * Whether a row can be watched or stopped, and through which session. A watched session can always be stopped, whatever
 * its kind now (an edit may have made it RDP). A VM is watched through a linked session: one already watched, else
 * the first that reads its guest.
 */
export function watchState(source: WatchSource, watched: ReadonlySet<string>): WatchState {
  if (source.kind === "session") {
    const s = source.session;
    if (watched.has(s.id)) return { can: true, sessionId: s.id, watching: true, via: null };
    if (!s.readsGuest) return { can: false, reason: "Only SSH and WinRM sessions report their metrics." };
    return { can: true, sessionId: s.id, watching: false, via: null };
  }
  const on = source.sessions.find((s) => watched.has(s.id));
  if (on) return { can: true, sessionId: on.id, watching: true, via: on.name };
  const reader = source.sessions.find((s) => s.readsGuest);
  if (!reader) return { can: false, reason: "Link an SSH or WinRM session to it first." };
  return { can: true, sessionId: reader.id, watching: false, via: reader.name };
}

/** "every 5 s", "every 1 min". */
function pollText(secs: number): string {
  const s = Number.isFinite(secs) && secs > 0 ? Math.round(secs) : 5;
  return s >= 60 && s % 60 === 0 ? `every ${s / 60} min` : `every ${s} s`;
}

/** What watching costs, in one line: a kept login and a read each poll ("through web01" for a VM's guest). */
export function watchCostText(state: Extract<WatchState, { can: true }>, intervalSecs: number): string {
  if (state.watching) return state.via ? `Closes the login to ${state.via}` : "Closes the login it keeps";
  const through = state.via ? ` to ${state.via}` : "";
  return `Keeps a login${through} open and reads it ${pollText(intervalSecs)}`;
}

/** A check that runs at most this often keeps its jump host's login open between runs (checks/probe.rs). */
export const HOLD_UP_TO_SECS = 600;

/**
 * What a check costs, in one line (a new check runs every minute): a probe from this PC each interval, or, for a
 * session behind a jump host (`via`, its name), a probe through it, with the login to it kept open between runs
 * up to every 10 minutes (checks/probe.rs hold_for), else made for each run.
 */
export function checkCostText(via: string | null = null, intervalSecs = 60): string {
  const every =
    intervalSecs >= 60 && intervalSecs % 60 === 0
      ? intervalSecs === 60
        ? "every minute"
        : `every ${intervalSecs / 60} minutes`
      : `every ${intervalSecs} seconds`;
  if (!via) return `A probe from this PC ${every}`;
  return intervalSecs <= HOLD_UP_TO_SECS
    ? `A probe through ${via} ${every}; the login to it stays open between runs`
    : `A probe through ${via} ${every}, logging in to it each time`;
}

/** The jump host a session's checks go through (its own, or its folder's), by name; null when it has none. */
export function checkVia(
  session: { jumpSessionId: string | null },
  sessions: readonly { id: string; name: string }[],
): string | null {
  if (!session.jumpSessionId) return null;
  return sessions.find((s) => s.id === session.jumpSessionId)?.name ?? "its jump host";
}

// ---- Alert rules ----

/** Where an `alerts` link leads: the Alerts widget when the layout has one, else (or when asked) the rules sheet. */
export function alertsOpens(link: { rules?: boolean }, widgetKinds: Iterable<string>): "widget" | "rules" {
  if (link.rules) return "rules";
  for (const kind of widgetKinds) if (kind === "alerts") return "widget";
  return "rules";
}

// ---- Add a check, and Keep checking this… ----

type ChecksLink = Extract<AppLink, { kind: "checks" }>;

/**
 * The new check a `checks` link asks for: on its target, named after it. Without a spec, the editor's default
 * (HTTP(S)); with one the target takes, that spec as a Toolbox result filled it in; with one it can't take (DNS on a
 * VM), a TCP check, newCheckInput's fallback.
 */
export function requestedCheck(target: ToolTarget, spec?: CheckSpec): CheckInput {
  const name = target.kind === "address" ? target.host : target.label;
  const on = probeTarget(target);
  const input = newCheckInput(on, name, spec?.kind);
  return spec && kindTakes(spec.kind, on.kind) ? { ...input, spec } : input;
}

/**
 * Why "Keep checking this…" can't open its check, or null: what the editor, and the core after it, would refuse in the
 * check it opens with (a DNS lookup of an address, a name the core can't take, a server that isn't an IP address).
 */
export function keepCheckingProblem(link: ChecksLink | null): string | null {
  if (!link?.add) return "This result can't become a check.";
  return checkProblem(requestedCheck(link.add, link.spec));
}

function keep(target: ToolTarget, spec: CheckSpec): ChecksLink {
  return { kind: "checks", add: target, spec };
}

/** A ping check on what was pinged. */
export function pingCheck(target: ToolTarget): ChecksLink {
  return keep(target, { kind: "ping" });
}

/** A TCP check of one port that was checked. */
export function portCheck(target: ToolTarget, port: number): ChecksLink {
  return keep(target, { kind: "tcp", port });
}

/**
 * What the read found that a certificate check refuses unless it allows untrusted certificates (checks/probe.rs: not
 * trusted, or naming another host), in words for the editor: "isn't trusted by this PC", "doesn't name web01"; null
 * when neither.
 */
export function certificateFinding(
  report: { trusted: boolean; nameMatches: boolean | null; serverName: string | null; host: string | null },
  serverName: string,
): string | null {
  const name = serverName.trim() || report.serverName || report.host || "the host";
  const parts = [
    report.trusted ? null : "isn't trusted by this PC",
    report.nameMatches === false ? `doesn't name ${name}` : null,
  ].filter((p): p is string => p !== null);
  return parts.length === 0 ? null : parts.join(" and ");
}

/**
 * A certificate check of what was read: its port and the server name typed, if any. Untrusted ones aren't allowed;
 * `finding` (certificateFinding) tells the editor that this one will be down until they are.
 */
export function certificateCheck(
  target: ToolTarget,
  port: number,
  serverName: string,
  finding: string | null = null,
): ChecksLink {
  const link = keep(target, {
    kind: "certificate",
    port,
    serverName: serverName.trim() ? serverName.trim() : null,
    allowUntrusted: false,
  });
  return finding ? { ...link, untrusted: finding } : link;
}

/** Why a DNS lookup can't become a check, or null: a check looks up A or AAAA records. */
export function dnsCheckProblem(recordType: RecordType): string | null {
  return recordType === "A" || recordType === "AAAA" ? null : "A check looks up A or AAAA records.";
}

/**
 * A DNS check of the name looked up, at the same server. When it found exactly one address of that type, the check
 * expects it (the core is up while the answer holds it); otherwise any answer will do. Null for a type a check can't
 * look up.
 */
export function dnsCheck(
  name: string,
  recordType: RecordType,
  server: string,
  records: readonly DnsRecord[],
): ChecksLink | null {
  if (dnsCheckProblem(recordType) !== null) return null;
  const kind = recordType as DnsRecordKind;
  const found = records.filter((r) => r.recordType === kind);
  return keep(
    { kind: "address", host: name.trim() },
    {
      kind: "dns",
      recordType: kind,
      server: server.trim() ? server.trim() : null,
      expect: found.length === 1 ? found[0].data : null,
    },
  );
}
