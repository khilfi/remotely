// SS-12: what a session opens (SSH, remote desktop, VNC, Telnet, serial), as the session editor, the tree, the tabs
// and the open actions use it. Pure, so it is tested on its own (session-kinds.test.ts). The core checks every field
// again when a session is saved (crates/core/src/sessions/kinds.rs).

import type {
  FlowControl,
  LineEnding,
  PaneKind,
  Parity,
  RdpOptions,
  SerialOptions,
  SessionKind,
  SessionProtocol,
  StopBits,
  WinrmOptions,
} from "./api.ts";

export const RDP_DEFAULTS: RdpOptions = {
  screen: { mode: "full" },
  clipboard: true,
  drives: false,
  printers: false,
  audio: false,
  admin: false,
};

export const SERIAL_DEFAULTS: SerialOptions = {
  speed: 9600,
  dataBits: 8,
  parity: "none",
  stopBits: "one",
  flowControl: "none",
  lineEnding: "cr",
  localEcho: false,
};

/** F4: HTTPS, the user's vault password through NTLM, and Windows' trust for the certificate. */
export const WINRM_DEFAULTS: WinrmOptions = { transport: "https", signIn: "ntlm", certificate: "windows" };

/** The kinds in the editor's order, with the names it shows. */
export const KINDS: { protocol: SessionProtocol; label: string }[] = [
  { protocol: "ssh", label: "SSH" },
  { protocol: "rdp", label: "Remote desktop" },
  { protocol: "vnc", label: "VNC" },
  { protocol: "telnet", label: "Telnet" },
  { protocol: "serial", label: "Serial" },
  { protocol: "winrm", label: "WinRM" },
];

/** A new kind's fields with their defaults. */
export function defaultKind(protocol: SessionProtocol): SessionKind {
  switch (protocol) {
    case "ssh":
      return { protocol };
    case "rdp":
      return { protocol, ...RDP_DEFAULTS };
    case "vnc":
      return { protocol, viewOnly: false };
    case "telnet":
      return { protocol, lineEnding: "crLf" };
    case "serial":
      return { protocol, ...SERIAL_DEFAULTS };
    case "winrm":
      return { protocol, ...WINRM_DEFAULTS };
  }
}

/** The port a new session of the kind gets; null for serial, which has none. */
export function defaultPort(protocol: SessionProtocol): number | null {
  switch (protocol) {
    case "ssh":
      return 22;
    case "rdp":
      return 3389;
    case "vnc":
      return 5900;
    case "telnet":
      return 23;
    case "serial":
      return null;
    case "winrm":
      return 5986;
  }
}

/**
 * The port after the kind changes: the new kind's default when the port was the old kind's default (or empty),
 * otherwise what was typed.
 */
export function portAfterKindChange(port: string, from: SessionProtocol, to: SessionProtocol): string {
  const before = defaultPort(from);
  const after = defaultPort(to);
  if (after === null) return port;
  if (port.trim() === "" || (before !== null && Number(port) === before) || before === null) return String(after);
  return port;
}

/** "SSH", "Remote desktop"... */
export function kindLabel(protocol: string): string {
  return KINDS.find((k) => k.protocol === protocol)?.label ?? protocol.toUpperCase();
}

/** The session's kind, SSH when a record from before 0.7.0 has none. */
export function kindOf(session: { kind?: SessionKind | null; protocol?: string }): SessionKind {
  return session.kind ?? defaultKind((session.protocol as SessionProtocol | undefined) ?? "ssh");
}

/** Opens in a terminal tab (SSH, Telnet, serial, WinRM's PowerShell console); RDP and VNC open a window. */
export function opensInTab(kind: SessionKind): boolean {
  return (
    kind.protocol === "ssh" || kind.protocol === "telnet" || kind.protocol === "serial" || kind.protocol === "winrm"
  );
}

/** Signs in with the session's user and a password from the vault (SSH, and WinRM unless it uses the Windows sign-in). */
export function logsInWithVault(kind: SessionKind): boolean {
  return kind.protocol === "ssh" || (kind.protocol === "winrm" && kind.signIn !== "windows");
}

/** Gives guest metrics and host facts, and may be linked to its VM: SSH and WinRM. */
export function readsGuest(kind: SessionKind): boolean {
  return kind.protocol === "ssh" || kind.protocol === "winrm";
}

/** Opens a window of another program (mstsc, the VNC viewer). */
export function opensWindow(kind: SessionKind): boolean {
  return kind.protocol === "rdp" || kind.protocol === "vnc";
}

/** May go through a jump host (an SSH session): SSH, and RDP and VNC through a tunnel. */
export function takesJumpHost(kind: SessionKind): boolean {
  return kind.protocol === "ssh" || kind.protocol === "rdp" || kind.protocol === "vnc";
}

const LINE_ENDINGS: Record<LineEnding, string> = { cr: "CR", lf: "LF", crLf: "CR LF" };
export const LINE_ENDING_CHOICES: { value: LineEnding; label: string }[] = [
  { value: "crLf", label: "CR LF" },
  { value: "cr", label: "CR" },
  { value: "lf", label: "LF" },
];
const PARITY_LETTERS: Record<Parity, string> = { none: "N", odd: "O", even: "E", mark: "M", space: "S" };
export const PARITY_CHOICES: { value: Parity; label: string }[] = [
  { value: "none", label: "None" },
  { value: "odd", label: "Odd" },
  { value: "even", label: "Even" },
  { value: "mark", label: "Mark" },
  { value: "space", label: "Space" },
];
const STOP_BITS: Record<StopBits, string> = { one: "1", onePointFive: "1.5", two: "2" };
export const STOP_BIT_CHOICES: { value: StopBits; label: string }[] = [
  { value: "one", label: "1" },
  { value: "onePointFive", label: "1.5" },
  { value: "two", label: "2" },
];
export const FLOW_CHOICES: { value: FlowControl; label: string }[] = [
  { value: "none", label: "None" },
  { value: "xonXoff", label: "XON/XOFF" },
  { value: "rtsCts", label: "RTS/CTS" },
  { value: "dsrDtr", label: "DSR/DTR" },
];
/** The speeds the editor offers; any other from 50 to 4,000,000 can be typed. */
export const SERIAL_SPEEDS = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600];

/** "9600 8N1". */
export function serialFrame(o: SerialOptions): string {
  return `${o.speed} ${o.dataBits}${PARITY_LETTERS[o.parity]}${STOP_BITS[o.stopBits]}`;
}

/** What a serial line's settings refuse, or null (the core checks again). */
export function serialProblem(o: SerialOptions): string | null {
  if (!Number.isInteger(o.speed) || o.speed < 50 || o.speed > 4_000_000) return "The speed is 50 to 4,000,000.";
  if (o.stopBits === "onePointFive" && o.dataBits !== 5) return "1.5 stop bits only go with 5 data bits.";
  if (o.stopBits === "two" && o.dataBits === 5) return "5 data bits go with 1 or 1.5 stop bits.";
  return null;
}

/** `COM3`, or null when it is no COM port name. */
export function comPortName(text: string): string | null {
  const m = /^\s*com([1-9]\d{0,2})\s*$/i.exec(text);
  if (!m) return null;
  const n = Number(m[1]);
  return n >= 1 && n <= 256 ? `COM${n}` : null;
}

/** What a remote desktop window's size refuses, or null. */
export function rdpProblem(o: RdpOptions): string | null {
  if (o.screen.mode !== "window") return null;
  const ok = (n: number) => Number.isInteger(n) && n >= 200 && n <= 8192;
  return ok(o.screen.width) && ok(o.screen.height) ? null : "A window is 200 to 8192 pixels wide and high.";
}

/** The kind's fields in one line, for the editor's folded Advanced and the session's row: "Full screen · clipboard". */
export function kindSummary(kind: SessionKind): string | null {
  switch (kind.protocol) {
    case "ssh":
      return null;
    case "rdp": {
      const screen =
        kind.screen.mode === "full"
          ? "full screen"
          : kind.screen.mode === "allMonitors"
            ? "all monitors"
            : `${kind.screen.width}×${kind.screen.height}`;
      const shared = [
        kind.clipboard && "clipboard",
        kind.drives && "drives",
        kind.printers && "printers",
        kind.audio && "audio",
      ].filter(Boolean);
      const parts = [screen, ...shared, kind.admin ? "admin session" : null].filter(Boolean);
      return parts.join(" · ");
    }
    case "vnc":
      return kind.viewOnly ? "view only" : null;
    case "telnet":
      return `Enter sends ${LINE_ENDINGS[kind.lineEnding]}`;
    case "serial":
      return [
        serialFrame(kind),
        kind.flowControl === "none" ? null : FLOW_CHOICES.find((f) => f.value === kind.flowControl)?.label,
        kind.localEcho ? "local echo" : null,
      ]
        .filter(Boolean)
        .join(" · ");
    case "winrm":
      return [
        kind.transport === "https" ? "HTTPS" : "HTTP, encrypted",
        WINRM_SIGN_INS.find((s) => s.value === kind.signIn)?.short,
        kind.transport === "https" && kind.certificate === "fingerprint" ? "certificate by fingerprint" : null,
      ]
        .filter(Boolean)
        .join(" · ");
  }
}

export const WINRM_TRANSPORTS: { value: WinrmOptions["transport"]; label: string }[] = [
  { value: "https", label: "HTTPS (5986)" },
  { value: "http", label: "HTTP, encrypted by the sign-in (5985)" },
];

export const WINRM_SIGN_INS: { value: WinrmOptions["signIn"]; label: string; short: string }[] = [
  { value: "ntlm", label: "User and password (NTLM)", short: "NTLM" },
  { value: "basic", label: "User and password (Basic, HTTPS only)", short: "Basic" },
  { value: "windows", label: "My Windows sign-in (Kerberos only)", short: "my Windows sign-in" },
];

export const WINRM_CERTIFICATES: { value: WinrmOptions["certificate"]; label: string }[] = [
  { value: "windows", label: "Trusted by Windows" },
  { value: "fingerprint", label: "Trusted by Windows, or by its fingerprint" },
];

/** What a WinRM session's fields refuse, or null (the core checks again). */
export function winrmProblem(o: WinrmOptions, host = ""): string | null {
  if (o.signIn === "basic" && o.transport === "http") {
    return "Basic sends the password as it is, so it needs HTTPS.";
  }
  if (o.signIn === "windows" && looksLikeIpAddress(host)) {
    return "My Windows sign-in is Kerberos, which needs the host's name, not its IP address.";
  }
  return null;
}

/** An IPv4 address, or something IPv6-shaped (the core checks it properly). */
function looksLikeIpAddress(text: string): boolean {
  const t = text.trim().replace(/^\[(.*)\]$/, "$1");
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(t) || (t.includes(":") && /^[0-9a-fA-F:.]+$/.test(t));
}

/** The port after WinRM's transport changes: the other default when the port was one of them, else what was typed. */
export function winrmPortAfterTransport(port: string, transport: WinrmOptions["transport"]): string {
  const p = port.trim();
  if (p === "" || p === "5985" || p === "5986") return transport === "https" ? "5986" : "5985";
  return port;
}

/** Where it connects, as rows show it: `alice@web01:22`, `COM3 · 9600 8N1`, `win01:3389`. */
export function kindAddress(session: { host: string; port: number; username: string | null; kind?: SessionKind }) {
  const kind = kindOf(session);
  if (kind.protocol === "serial") return `${session.host} · ${serialFrame(kind)}`;
  const userShown = kind.protocol !== "vnc" && !(kind.protocol === "winrm" && kind.signIn === "windows");
  const user = session.username && userShown ? `${session.username}@` : "";
  return `${user}${session.host}:${session.port}`;
}

/**
 * Why a pane can't join Type in all tabs or Compare hosts (WhyDisabled), or null for an SSH pane. Telnet and serial
 * panes are network gear, whose commands the rules for shells don't rate.
 */
export function joinReason(kind: PaneKind | null | undefined): string | null {
  switch (kind ?? "ssh") {
    case "ssh":
      return null;
    case "telnet":
      return "Telnet tabs don't join: typing in all tabs and Compare hosts are for SSH shells.";
    case "serial":
      return "Serial tabs don't join: typing in all tabs and Compare hosts are for SSH shells.";
    case "tunnel":
      return "Tunnel tabs carry a remote desktop or VNC window, so they don't join.";
    case "powershell":
      return "PowerShell tabs don't join yet: typing in all tabs and Compare hosts are for SSH shells.";
  }
}

/** The pane kind a session's tab gets. */
export function paneKindOf(kind: SessionKind, viaJumpHost: boolean): PaneKind {
  if (kind.protocol === "telnet") return "telnet";
  if (kind.protocol === "serial") return "serial";
  if (kind.protocol === "winrm") return "powershell";
  if (opensWindow(kind) && viaJumpHost) return "tunnel";
  return "ssh";
}
