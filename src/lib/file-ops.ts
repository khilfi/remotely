// SS-14: pure helpers for the Files here drawer's file changes (rename, new folder, move, copy, permissions, owner,
// delete) and the transfer queue's choices. The core checks everything again; these only say why a dialog's button
// is off (QL-08) before anything is sent. Tested in file-ops.test.ts.

import type { Existing, FileChange } from "./api.ts";

/** Unicode format characters (bidi controls, zero-width marks) and line separators: the core refuses names holding
 * them (A8), as it does control characters. By code point, so no invisible character sits in this file. */
const FORMAT_RANGES: [number, number][] = [
  [0xad, 0xad],
  [0x61c, 0x61c],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2028, 0x2029],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
];

function invisible(text: string): boolean {
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return true;
    if (FORMAT_RANGES.some(([from, to]) => c >= from && c <= to)) return true;
  }
  return false;
}

/** Why a new name can't be one on the host, or null. As the core's `check_name`. */
export function nameProblem(name: string): string | null {
  if (name.length === 0) return "Type a name";
  if (name === "." || name === "..") return "That name means a folder itself";
  if (name.includes("/")) return "A name can't hold a /";
  if (new TextEncoder().encode(name).length > 255) return "That name is longer than 255 bytes";
  if (invisible(name)) {
    return "That name holds a control or invisible character";
  }
  return null;
}

/** Why a typed folder can't be one to move or copy into, or null: absolute, no `.` or `..` part, no empty part. */
export function folderProblem(path: string): string | null {
  if (!path.startsWith("/")) return "Type a full path, starting with /";
  if (path === "/") return null;
  if (path.endsWith("/")) return "Leave out the / at the end";
  for (const part of path.slice(1).split("/")) {
    if (part === "") return "The path has an empty part (//)";
    if (part === "." || part === "..") return "Type the folder itself, without . or ..";
  }
  return null;
}

/** "rw-r--r--" for 0o644; setuid, setgid and sticky as ls shows them. */
export function modeText(mode: number): string {
  const bits = ["r", "w", "x"];
  let out = "";
  for (let who = 2; who >= 0; who -= 1) {
    for (let bit = 2; bit >= 0; bit -= 1) {
      out += mode & (1 << (who * 3 + bit)) ? bits[2 - bit] : "-";
    }
  }
  const special = (at: number, flag: number, on: string, off: string) => {
    if (!(mode & flag)) return;
    const x = out[at] === "x";
    out = out.slice(0, at) + (x ? on : off) + out.slice(at + 1);
  };
  special(2, 0o4000, "s", "S");
  special(5, 0o2000, "s", "S");
  special(8, 0o1000, "t", "T");
  return out;
}

/** The mode typed as octal ("644", "0755", "4755"), or null when it isn't one. */
export function parseMode(text: string): number | null {
  const typed = text.trim();
  if (!/^[0-7]{3,4}$/.test(typed)) return null;
  return parseInt(typed, 8);
}

/** "0644". */
export function modeOctal(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

/** A uid or gid typed as a number, or null; empty is "leave it". */
export function parseId(text: string): number | null | "bad" {
  const typed = text.trim();
  if (typed === "") return null;
  if (!/^\d{1,10}$/.test(typed)) return "bad";
  const n = Number(typed);
  return n <= 0xffffffff ? n : "bad";
}

/** The last part of a host path. */
export function baseName(path: string): string {
  const parts = path.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? "/";
}

/** What a change is, in a few words for its toast ("Renamed 'a' to 'b'"). */
export function changeLabel(change: FileChange): string {
  const what = (paths: string[]) => (paths.length === 1 ? `'${baseName(paths[0])}'` : `${paths.length} items`);
  switch (change.kind) {
    case "newFolder":
      return `Made the folder '${change.name}'`;
    case "newFile":
      return `Made the file '${change.name}'`;
    case "rename":
      return `Renamed '${baseName(change.path)}' to '${change.name}'`;
    case "move":
      return `Moved ${what(change.paths)} to ${change.into}`;
    case "copy":
      return `Copied ${what(change.paths)} to ${change.into}`;
    case "delete":
      return `Deleted ${what(change.paths)}`;
    case "mode":
      return `Set the permissions of ${what(change.paths)}`;
    case "owner":
      return `Set the owner of ${what(change.paths)}`;
  }
}

/** The choices for files that are there already, as the conflict dialog offers them. */
export const EXISTING_CHOICES: { value: Exclude<Existing, "ask">; label: string; hint: string }[] = [
  { value: "replace", label: "Replace them", hint: "What is there now is lost" },
  { value: "replaceIfNewer", label: "Replace them if newer", hint: "By modification time; the rest stay" },
  { value: "keepBoth", label: "Keep both", hint: "The new ones get a number: name (1).ext" },
  { value: "skip", label: "Skip them", hint: "Only the others go" },
];

/** Whether a choice replaces anything (an upload then asks for approval). */
export function replaces(choice: Existing): boolean {
  return choice === "replace" || choice === "replaceIfNewer";
}
