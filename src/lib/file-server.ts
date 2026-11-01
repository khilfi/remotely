// FD-09: the File server tab's pure helpers: the form and its defaults (the last choices in this workspace), why Start
// is off, the spec the core gets, and the words the status and the request list are shown in. Tested in
// file-server.test.ts.

import type { FileServerSpec, RequestEntry, RequestOutcome, ServeAddress, ServerStatus } from "./file-server-api.ts";

/** The time limits offered, in minutes (30 by default, 8 hours at most, as the core allows). */
export const TIME_LIMITS: readonly number[] = [5, 15, 30, 60, 120, 240, 480];
export const DEFAULT_MINUTES = 30;
export const DEFAULT_TFTP_PORT = 69;
export const DEFAULT_HTTP_PORT = 8080;
export const DEFAULT_MAX_FILE_MB = 2048;
export const DEFAULT_MAX_TOTAL_MB = 4096;
/** The largest upload cap, in MB (the core's 64 GB). */
export const MAX_UPLOAD_MB = 65536;

/** What the form holds, as typed. */
export interface FileServerForm {
  root: string;
  /** The root is a folder (else one file). */
  folder: boolean;
  address: string;
  tftp: boolean;
  tftpPort: string;
  http: boolean;
  httpPort: string;
  minutes: number;
  uploads: boolean;
  uploadFolder: string;
  maxFileMb: string;
  maxTotalMb: string;
}

/** The form at first: the last choices here when there are some, else the defaults on the first adapter. */
export function initialForm(last: FileServerSpec | null, addresses: ServeAddress[]): FileServerForm {
  const known = (address: string | undefined) => addresses.some((a) => a.address === address);
  const firstAdapter = addresses.find((a) => !a.loopback) ?? addresses[0];
  const address = last && known(last.address) ? last.address : (firstAdapter?.address ?? "");
  return {
    root: last?.root ?? "",
    folder: last ? !looksLikeFile(last.root) : true,
    address,
    tftp: last ? last.tftpPort !== null : true,
    tftpPort: String(last?.tftpPort ?? DEFAULT_TFTP_PORT),
    http: last ? last.httpPort !== null : true,
    httpPort: String(last?.httpPort ?? DEFAULT_HTTP_PORT),
    minutes: last && TIME_LIMITS.includes(last.minutes) ? last.minutes : DEFAULT_MINUTES,
    uploads: false,
    uploadFolder: last?.uploads?.folder ?? "",
    maxFileMb: String(last?.uploads?.maxFileMb ?? DEFAULT_MAX_FILE_MB),
    maxTotalMb: String(last?.uploads?.maxTotalMb ?? DEFAULT_MAX_TOTAL_MB),
  };
}

/** A saved root with an extension after its last separator reads as a file. */
function looksLikeFile(path: string): boolean {
  const last = path.split(/[\\/]/).pop() ?? "";
  return /\.[^.]+$/.test(last);
}

/** A port typed in: 1 to 65535. */
export function parsePort(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d{1,5}$/.test(trimmed)) return null;
  const port = Number(trimmed);
  return port >= 1 && port <= 65535 ? port : null;
}

/** MB typed in: 1 to the largest cap. */
export function parseMb(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d{1,6}$/.test(trimmed)) return null;
  const mb = Number(trimmed);
  return mb >= 1 && mb <= MAX_UPLOAD_MB ? mb : null;
}

/** Why Start is off, or null when the form is ready. */
export function startReason(form: FileServerForm): string | null {
  if (!form.root.trim()) return "Choose a file or folder to serve";
  if (!form.address) return "Choose the address to serve on";
  if (!form.tftp && !form.http) return "Turn on TFTP, HTTP or both";
  if (form.tftp && parsePort(form.tftpPort) === null) return "Type a TFTP port from 1 to 65535";
  if (form.http && parsePort(form.httpPort) === null) return "Type an HTTP port from 1 to 65535";
  if (form.tftp && form.http && form.tftpPort.trim() === form.httpPort.trim()) {
    // Different protocols could share a number, but two servers on one number confuse people more than they help.
    return "Give TFTP and HTTP different ports";
  }
  if (form.uploads) {
    if (!form.uploadFolder.trim()) return "Choose an empty folder for uploads";
    const file = parseMb(form.maxFileMb);
    const total = parseMb(form.maxTotalMb);
    if (file === null) return `Type the largest file in MB, from 1 to ${MAX_UPLOAD_MB}`;
    if (total === null) return `Type the limit for all uploads in MB, from 1 to ${MAX_UPLOAD_MB}`;
    if (file > total) return "One file can't be allowed more than all uploads together";
  }
  return null;
}

/** The spec the core gets, once [`startReason`] is null. */
export function specOf(form: FileServerForm): FileServerSpec {
  return {
    root: form.root.trim(),
    address: form.address,
    tftpPort: form.tftp ? parsePort(form.tftpPort) : null,
    httpPort: form.http ? parsePort(form.httpPort) : null,
    minutes: form.minutes,
    uploads: form.uploads
      ? {
          folder: form.uploadFolder.trim(),
          maxFileMb: parseMb(form.maxFileMb) ?? DEFAULT_MAX_FILE_MB,
          maxTotalMb: parseMb(form.maxTotalMb) ?? DEFAULT_MAX_TOTAL_MB,
        }
      : null,
  };
}

/** "30 minutes", "1 hour", "8 hours". */
export function minutesText(minutes: number): string {
  if (minutes < 60) return minutes === 1 ? "1 minute" : `${minutes} minutes`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  const h = hours === 1 ? "1 hour" : `${hours} hours`;
  return rest === 0 ? h : `${h} ${rest} minutes`;
}

/** `12 MB`, `512 KB`, `100 bytes`, `1.5 GB`, as the core writes them. */
export function sizeText(bytes: number): string {
  const kb = 1024;
  if (bytes < kb) return `${bytes} bytes`;
  if (bytes < kb * kb) return `${Math.round(bytes / kb)} KB`;
  const one = (value: number, unit: string) => `${value.toFixed(1).replace(/\.0$/, "")} ${unit}`;
  if (bytes < kb * kb * kb) return one(bytes / (kb * kb), "MB");
  return one(bytes / (kb * kb * kb), "GB");
}

/** "TFTP on port 69 · HTTP on port 8080". */
export function listeningText(status: ServerStatus): string {
  const parts: string[] = [];
  if (status.tftpPort !== null) parts.push(`TFTP on port ${status.tftpPort}`);
  if (status.httpPort !== null) parts.push(`HTTP on port ${status.httpPort}`);
  return parts.join(" · ");
}

/** "Stops at 14:30" while it runs (in local time), or why it stopped. */
export function endText(status: ServerStatus, now: Date = new Date()): string {
  if (status.stopped) return capitalize(status.stopped);
  const ends = new Date(status.endsAt);
  if (Number.isNaN(ends.getTime())) return "Running";
  const left = Math.max(0, Math.round((ends.getTime() - now.getTime()) / 60000));
  const at = ends.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return left <= 1 ? `Stops at ${at} (in a minute or less)` : `Stops at ${at} (in ${minutesText(left)})`;
}

function capitalize(text: string): string {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}

/** "12 requests: 10 sent, 2 refused". */
export function countsText(status: ServerStatus): string {
  const c = status.counts;
  if (c.requests === 0) return "No requests yet";
  const parts = (
    [
      [c.sent, "sent"],
      [c.received, "received"],
      [c.refused, "refused"],
      [c.failed, "failed"],
    ] as const
  )
    .filter(([n]) => n > 0)
    .map(([n, word]) => `${n} ${word}`);
  const head = c.requests === 1 ? "1 request" : `${c.requests} requests`;
  return `${head}: ${parts.join(", ")}`;
}

const OUTCOME_WORDS: Record<RequestOutcome, string> = {
  sent: "Sent",
  received: "Received",
  refused: "Refused",
  failed: "Failed",
};

/** A request's outcome, in a word. */
export function outcomeText(outcome: RequestOutcome): string {
  return OUTCOME_WORDS[outcome];
}

/** What a request asked for, as the list shows it: `/` for the root, TFTP's `read`/`write` as words. */
export function requestText(entry: RequestEntry): { what: string; path: string } {
  const what = entry.protocol === "tftp" ? (entry.method === "write" ? "TFTP upload" : "TFTP") : `HTTP ${entry.method}`;
  const path = entry.path === "" ? "/" : entry.path;
  return { what, path };
}

/** The local time of a request, `14:03:12`. */
export function requestTime(entry: RequestEntry): string {
  const at = new Date(entry.at);
  return Number.isNaN(at.getTime()) ? entry.at : at.toLocaleTimeString([], { hour12: false });
}
