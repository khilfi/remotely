// SS-07 jump host chains and port forwards: pure helpers for the session dialog, the session tree, the terminal's tab
// and its Tunnels panel. No DOM, so `npm test` covers them.

import type { ForwardInput, ForwardKind, PortForward, TunnelInfo } from "./api.ts";

/** The most jump hosts a chain may have (the core refuses more). */
export const MAX_JUMP_DEPTH = 8;

/** Enough of a session to follow its jump hosts. */
export interface JumpLink {
  id: string;
  name: string;
  jumpSessionId: string | null;
}

/**
 * The jump hosts on the way to a session, by name, in the order they are connected (the one this PC dials first).
 * `loop` when they go round in a circle (the core refuses to connect then).
 */
export function jumpChain(sessionId: string, byId: Map<string, JumpLink>): { names: string[]; loop: boolean } {
  const names: string[] = [];
  const seen = new Set([sessionId]);
  let next = byId.get(sessionId)?.jumpSessionId ?? null;
  while (next) {
    if (seen.has(next) || names.length > MAX_JUMP_DEPTH) return { names: names.reverse(), loop: true };
    seen.add(next);
    const hop = byId.get(next);
    if (!hop) break;
    names.push(hop.name);
    next = hop.jumpSessionId;
  }
  return { names: names.reverse(), loop: false };
}

/** `bastion → inner`: a chain for a tooltip or the tab. */
export function routeText(names: string[]): string {
  return names.join(" → ");
}

/** What a tree row or tab says about the way in: the session's own jump host ("via inner"). */
export function viaText(names: string[]): string | null {
  return names.length === 0 ? null : `via ${names[names.length - 1]}`;
}

/** The kinds as the UI names them. */
export const FORWARD_KINDS: { kind: ForwardKind; label: string; hint: string }[] = [
  { kind: "local", label: "Local", hint: "A port on this PC leads to a host the session's host reaches (ssh -L)" },
  {
    kind: "remote",
    label: "Remote",
    hint: "A port on the session's host leads back to a host this PC reaches (ssh -R)",
  },
  {
    kind: "dynamic",
    label: "SOCKS",
    hint: "A SOCKS proxy on this PC; programs that use it reach what the host reaches (ssh -D)",
  },
];

/** True for `localhost`, 127.x.x.x and ::1: only the machine that listens can connect. */
export function isLoopback(address: string): boolean {
  const bare = address
    .trim()
    .replace(/^\[(.*)\]$/, "$1")
    .toLowerCase();
  return bare === "localhost" || bare === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare);
}

/** Where a forward listens when the field is left empty. */
export function defaultBind(kind: ForwardKind): string {
  return kind === "remote" ? "localhost" : "127.0.0.1";
}

/** `127.0.0.1:8080`, `[::1]:8080`, or `127.0.0.1 (any free port)`. */
export function listenAddress(f: Pick<PortForward, "bindAddress" | "bindPort">): string {
  const host = f.bindAddress.includes(":") && !f.bindAddress.startsWith("[") ? `[${f.bindAddress}]` : f.bindAddress;
  return f.bindPort === 0 ? `${f.bindAddress} (any free port)` : `${host}:${f.bindPort}`;
}

/** What a forward does, in one line, as the audit log says it. */
export function forwardText(
  f: Pick<PortForward, "kind" | "bindAddress" | "bindPort" | "destHost" | "destPort">,
): string {
  const dest = f.destHost.includes(":") && !f.destHost.startsWith("[") ? `[${f.destHost}]` : f.destHost;
  switch (f.kind) {
    case "local":
      return `local ${listenAddress(f)} → ${dest}:${f.destPort}`;
    case "remote":
      return `remote ${listenAddress(f)} on the host → ${dest}:${f.destPort}`;
    case "dynamic":
      return `SOCKS on ${listenAddress(f)}`;
  }
}

/**
 * QL-08 for the session dialog: what is wrong with a forward before it is saved, or null. The core checks again.
 */
export function forwardProblem(f: ForwardInput): string | null {
  if (!Number.isInteger(f.bindPort) || f.bindPort < 0 || f.bindPort > 65535) return "The port must be 0 to 65535.";
  const bind = f.bindAddress.trim();
  if (bind && bind.toLowerCase() !== "localhost" && !/^[0-9a-fA-F:.[\]]+$/.test(bind))
    return "Listen on localhost or an IP address, such as 127.0.0.1.";
  if (f.kind === "dynamic") return null;
  if (!f.destHost.trim()) return "Enter where it leads: a host name or IP address.";
  if (!Number.isInteger(f.destPort) || f.destPort < 1 || f.destPort > 65535)
    return "Enter the port it leads to (1 to 65535).";
  return null;
}

/** P9 will mask addresses; until then the user sees who can use a listener. */
export function exposureText(f: Pick<PortForward, "kind" | "bindAddress">): string {
  const bind = f.bindAddress.trim() || defaultBind(f.kind);
  if (isLoopback(bind))
    return f.kind === "remote" ? "Only programs on the host can use it." : "Only this PC can use it.";
  return f.kind === "remote"
    ? `The host listens on ${bind}: other computers that reach the host can use it. It asks before it opens.`
    : `It listens on ${bind}: other computers that reach this PC can use it, without logging in. It asks before it opens.`;
}

/** A tunnel's state in a few words, for the panel and the tab. */
export function tunnelStateText(t: TunnelInfo): string {
  switch (t.state.state) {
    case "stopped":
      return "Stopped";
    case "asking":
      return "Waiting for your approval";
    case "opening":
      return "Opening…";
    case "listening": {
      const used =
        t.connections === 0 ? "" : `, ${t.connections === 1 ? "1 connection" : `${t.connections} connections`}`;
      return `Listening on ${t.state.at}${used}`;
    }
    case "waiting":
      return "Opens again when the terminal reconnects";
    case "failed":
      return `Failed: ${t.state.message}`;
  }
}

/** Tunnels open (or about to be) in a terminal, for the toolbar's count. */
export function liveTunnels(tunnels: TunnelInfo[] | null): number {
  return (tunnels ?? []).filter((t) => t.state.state === "listening" || t.state.state === "opening").length;
}

/** A saved forward as the dialog edits it. */
export function toInput(f: PortForward): ForwardInput {
  return {
    id: f.id,
    label: f.label,
    kind: f.kind,
    bindAddress: f.bindAddress,
    bindPort: f.bindPort,
    destHost: f.destHost,
    destPort: f.destPort,
    autoStart: f.autoStart,
  };
}

/** The core keeps at most this many per session. */
export const MAX_FORWARDS = 20;

export function newForward(kind: ForwardKind = "local"): ForwardInput {
  return {
    id: null,
    label: null,
    kind,
    bindAddress: "",
    bindPort: kind === "dynamic" ? 1080 : 8080,
    destHost: "",
    destPort: 0,
    autoStart: true,
  };
}

/** Two forwards that would listen on one port on the same side, by index; the core refuses them too. */
export function clashes(forwards: ForwardInput[]): Set<number> {
  const seen = new Map<string, number>();
  const out = new Set<number>();
  forwards.forEach((f, i) => {
    if (f.bindPort === 0) return;
    const side = f.kind === "remote" ? "host" : "here";
    const key = `${side}|${(f.bindAddress.trim() || defaultBind(f.kind)).toLowerCase()}|${f.bindPort}`;
    const other = seen.get(key);
    if (other !== undefined) {
      out.add(other);
      out.add(i);
    } else seen.set(key, i);
  });
  return out;
}

/** What is wrong with the list, for the dialog's Save button; null when it can be saved. */
export function forwardsProblem(forwards: ForwardInput[]): string | null {
  for (const [i, f] of forwards.entries()) {
    const problem = forwardProblem(f);
    if (problem) return `Port forward ${i + 1}: ${problem}`;
  }
  if (clashes(forwards).size > 0) return "Two port forwards listen on one port; give one another port.";
  return null;
}
