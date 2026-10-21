// SS-08 file transfer in the terminal: pure helpers for the "Files here" drawer and the transfers panel (tested in
// transfers.test.ts). Paths on the host are POSIX paths; nothing here touches this PC's paths.

import type { RemoteEntry, ShellUsers, TransferInfo } from "./api.ts";

/** "1.5 KB", "25 MB": decimal units, like the core's audit entries. */
export function formatSize(bytes: number) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit + 1 < units.length) {
    value /= 1000;
    unit += 1;
  }
  if (unit === 0) return `${bytes} B`;
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/** "2.4 MB/s"; null while nothing is known yet. */
export function formatSpeed(bytesPerSec: number) {
  return bytesPerSec > 0 ? `${formatSize(bytesPerSec)}/s` : null;
}

/** Seconds left at the current speed; null when it can't be told. */
export function secondsLeft(t: Pick<TransferInfo, "size" | "done" | "bytesPerSec">) {
  if (t.bytesPerSec <= 0 || t.done >= t.size) return null;
  return Math.ceil((t.size - t.done) / t.bytesPerSec);
}

/** 0 to 100. An empty file is whole once done. */
export function percent(t: Pick<TransferInfo, "size" | "done" | "state">) {
  if (t.state === "done") return 100;
  if (t.size <= 0) return 0;
  return Math.min(100, Math.floor((t.done / t.size) * 100));
}

/** The transfers panel's list after one change: replaced in place, or added at the end. */
export function mergeTransfer(list: TransferInfo[], changed: TransferInfo): TransferInfo[] {
  const at = list.findIndex((t) => t.id === changed.id);
  if (at < 0) return [...list, changed];
  const next = [...list];
  next[at] = changed;
  return next;
}

export function isActive(t: Pick<TransferInfo, "state">) {
  return t.state === "queued" || t.state === "running";
}

export type SortKey = "name" | "size" | "modified";

/** Folders first, then by the column, names breaking ties. */
export function sortEntries(entries: RemoteEntry[], key: SortKey, dir: 1 | -1): RemoteEntry[] {
  const byName = (a: RemoteEntry, b: RemoteEntry) => a.name.localeCompare(b.name, undefined, { numeric: true });
  return [...entries].sort((a, b) => {
    const folders = Number(b.kind === "folder") - Number(a.kind === "folder");
    if (folders !== 0) return folders;
    let order = 0;
    if (key === "size") order = a.size - b.size;
    else if (key === "modified") order = (a.modified ?? 0) - (b.modified ?? 0);
    return (order || byName(a, b)) * (key === "name" ? dir : order ? dir : 1);
  });
}

/** `/a/b` and `x` -> `/a/b/x`. */
export function joinPath(folder: string, name: string) {
  return folder.endsWith("/") ? `${folder}${name}` : `${folder}/${name}`;
}

/** The breadcrumb of a host path: `/`, `/srv`, `/srv/www`, each with its last part as the label. */
export function crumbs(path: string): { label: string; path: string }[] {
  const parts = path.split("/").filter(Boolean);
  const out = [{ label: "/", path: "/" }];
  parts.forEach((part, i) => out.push({ label: part, path: `/${parts.slice(0, i + 1).join("/")}` }));
  return out;
}

/**
 * QL-09: what the drawer says about the shell's user, beside "Transfers as <login>".
 * - same: nothing more to say.
 * - reported: Remotely's prompt hook reports another user than the login.
 * - switched: the hook's shell stopped reporting after a command, and the prompt names someone else.
 * - stopped: it stopped reporting, and the prompt names nobody else.
 * - prompt: no hook, and the prompt names someone else.
 */
export type UserNote =
  { kind: "same" } | { kind: "reported" | "switched" | "prompt"; shell: string } | { kind: "stopped" };

export function userNote(user: ShellUsers | undefined): UserNote {
  if (!user) return { kind: "same" };
  const shell = user.shell?.username;
  if (user.stopped) return shell ? { kind: "switched", shell } : { kind: "stopped" };
  if (!shell) return { kind: "same" };
  return { kind: user.shell?.seenIn === "hook" ? "reported" : "prompt", shell };
}

/** Characters that end a file name in terminal output. */
const STOP = /[\s"'`()<>[\]{},;|]/;

/**
 * SS-08 right-click in the terminal: the file name under column `col` of a line of output, or null. Quotes, brackets
 * and the marks `ls -F` adds (`*`, `@`, `|`, `=`) are not part of it, nor is a trailing `:` or `.`; a name ending in
 * `/` is a folder and gives nothing.
 */
export function fileWordAt(line: string, col: number): string | null {
  const chars = Array.from(line);
  if (col < 0 || col >= chars.length || STOP.test(chars[col])) return null;
  let start = col;
  while (start > 0 && !STOP.test(chars[start - 1])) start -= 1;
  let end = col + 1;
  while (end < chars.length && !STOP.test(chars[end])) end += 1;
  let word = chars.slice(start, end).join("");
  word = word.replace(/[*@|=]$/, "").replace(/[:.]+$/, "");
  if (!word || word.endsWith("/") || word === "~" || /^-+$/.test(word)) return null;
  // `ls -l` columns are no file names: permissions, counts, dates and times.
  if (/^[-dlcbps][-rwxsStT]{9}[.+@]?$/.test(word) || /^\d+([.,:]\d+)*$/.test(word)) return null;
  return word;
}
