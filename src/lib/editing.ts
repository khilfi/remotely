// SS-14, SS-08 (0.8.0 G4): pure helpers for editing a host's files from Files here: what a double-click does, the
// editing sessions list's words, and keeping that list up to date from `files://edit` events. Tested in
// editing.test.ts.

import type { FileDoubleClick } from "./api.ts";
import type { EditInfo, EditState, HostEditors } from "./editing-api.ts";

/** The last part of a host path: `nginx.conf` for `/etc/nginx/nginx.conf`. */
export function fileName(path: string): string {
  const parts = path.split("/").filter((p) => p.length > 0);
  return parts[parts.length - 1] ?? path;
}

/** The row's tooltip for a file: what a double-click does. */
export function doubleClickTitle(setting: FileDoubleClick | undefined, editors: HostEditors | null): string {
  if (setting === "thisPc") return "Double-click to edit on this PC";
  if (editors && !editors.uses) return "Double-click: the host has no terminal editor Remotely knows";
  return editors?.uses ? `Double-click to edit in ${editors.uses} on the host` : "Double-click to edit in the terminal";
}

/** "Edit in nano", or the plain words before the host's editors are known. */
export function editInTerminalLabel(editors: HostEditors | null): string {
  return editors?.uses ? `Edit in ${editors.uses}` : "Edit in the terminal";
}

/** Why "Edit in the terminal" is off, or null. */
export function editInTerminalReason(editors: HostEditors | null): string | null {
  if (editors && editors.found.length === 0) {
    return "The host has none of the editors Remotely knows (nano, micro, vim, vi...); edit it on this PC instead";
  }
  return null;
}

/** "No saves yet", "1 save uploaded", "3 saves uploaded". */
export function savesText(saves: number): string {
  if (saves === 0) return "No saves yet";
  return saves === 1 ? "1 save uploaded" : `${saves} saves uploaded`;
}

/** "Ends in 3 h 59 min", "Ends in 12 min", "Ends in under a minute". */
export function endsInText(endsAt: string, now: number): string {
  const left = Date.parse(endsAt) - now;
  if (!Number.isFinite(left)) return "";
  const minutes = Math.floor(left / 60_000);
  if (minutes < 1) return "Ends in under a minute";
  const hours = Math.floor(minutes / 60);
  return hours > 0 ? `Ends in ${hours} h ${minutes % 60} min` : `Ends in ${minutes} min`;
}

export type EditTone = "muted" | "busy" | "warn" | "error";

/** A session's state in words, and how it shows. */
export function editStateText(state: EditState): { text: string; tone: EditTone } {
  switch (state.state) {
    case "watching":
      return { text: "Watching for saves", tone: "muted" };
    case "uploading":
      return { text: "Uploading a save…", tone: "busy" };
    case "conflict":
      return { text: "The host's copy changed", tone: "warn" };
    case "failed":
      return { text: state.message, tone: "error" };
    case "held":
      return { text: state.message, tone: "warn" };
    case "ended":
      return { text: `Ended: ${state.message}`, tone: "muted" };
    case "kept":
      return { text: `Ended: ${state.message}`, tone: "warn" };
  }
}

/** Stop editing's question when the copy holds a save that didn't go up: the choices it offers, the first the primary.
 * Upload again only when it could help (not while the host's copy changed: that asks for an answer first). */
export function stopChoices(conflict: boolean): { choice: "upload" | "keep" | "discard"; label: string }[] {
  const keep = { choice: "keep" as const, label: "Keep it on this PC" };
  const discard = { choice: "discard" as const, label: "Discard it" };
  return conflict ? [keep, discard] : [keep, { choice: "upload" as const, label: "Upload again" }, discard];
}

/** The list after an event: a session is added or updated in place, and one that ended goes (a kept copy stays until
 * it is discarded). Oldest first. */
export function applyEdit(list: EditInfo[], edit: EditInfo): EditInfo[] {
  if (edit.state.state === "ended") return list.filter((e) => e.id !== edit.id);
  const at = list.findIndex((e) => e.id === edit.id);
  if (at < 0) return [...list, edit];
  return list.map((e, i) => (i === at ? edit : e));
}
