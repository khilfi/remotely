// UX-19 (0.9.0 H4): monitoring setup, as pure functions (tested in monitor.test.ts). Monitor ▸ on session rows, the VM
// details panel and the palette's VM and session views: whether its metrics can be watched (MO-02: a session that
// reads its guest, over SSH or WinRM; a VM through a session linked to it), and one line on what watching or a check
// costs. Where the status bar's alerts link leads (MO-07: the Alerts widget, or the rules sheet when the layout has
// none). And "Keep checking this…" on the Toolbox's Ping, Check ports, Certificate and DNS results (FD-09): the
// `checks` link that opens the check editor (MO-08) filled in, the same dialog every "Add a check" opens.

import type { SessionKind } from "./api.ts";
import type { CheckInput, CheckSpec, DnsRecordKind } from "./checks-api.ts";
import { kindTakes, newCheckInput } from "./checks.ts";
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
 * Whether a row can be watched, and through which session. A VM is watched through a linked session that reads its
 * guest: the one already watched, else the first.
 */
export function watchState(source: WatchSource, watched: ReadonlySet<string>): WatchState {
  if (source.kind === "session") {
    const s = source.session;
    if (!s.readsGuest) return { can: false, reason: "Only SSH and WinRM sessions report their metrics." };
    return { can: true, sessionId: s.id, watching: watched.has(s.id), via: null };
  }
  const readers = source.sessions.filter((s) => s.readsGuest);
  if (readers.length === 0) return { can: false, reason: "Link an SSH or WinRM session to it first." };
  const on = readers.find((s) => watched.has(s.id));
  const s = on ?? readers[0];
  return { can: true, sessionId: s.id, watching: on !== undefined, via: s.name };
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

/** What a check costs, in one line: a probe from this PC each interval (a new check runs every minute). */
export function checkCostText(intervalSecs = 60): string {
  const every =
    intervalSecs >= 60 && intervalSecs % 60 === 0
      ? intervalSecs === 60
        ? "every minute"
        : `every ${intervalSecs / 60} minutes`
      : `every ${intervalSecs} seconds`;
  return `A probe from this PC ${every}`;
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
 * The new check a `checks` link asks for: on its target, named after it, with the spec a Toolbox result filled in
 * when it gave one the target takes, else the editor's default kind.
 */
export function requestedCheck(target: ToolTarget, spec?: CheckSpec): CheckInput {
  const name = target.kind === "address" ? target.host : target.label;
  const on = probeTarget(target);
  const input = newCheckInput(on, name, spec?.kind);
  return spec && kindTakes(spec.kind, on.kind) ? { ...input, spec } : input;
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

/** A certificate check of what was read: its port and the server name typed, if any. Untrusted ones aren't allowed. */
export function certificateCheck(target: ToolTarget, port: number, serverName: string): ChecksLink {
  return keep(target, {
    kind: "certificate",
    port,
    serverName: serverName.trim() ? serverName.trim() : null,
    allowUntrusted: false,
  });
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
