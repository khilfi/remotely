// FD-06 notes in the window, as pure functions (tested in notes.test.ts): what a note's link opens, what its tooltip
// says, and the note's own link (`{ kind: "note" }`, opened by App's note sheet). The HTML itself comes from the core,
// which shows raw HTML and images as text and puts no address in a link.

import type { AppLink } from "./links.ts";
import type { NoteKind, NoteLink, NoteTarget } from "./comfort-api.ts";

/** What clicking a link in a note does: open an app link, ask before a web address, or nothing. */
export type NoteLinkAction = { open: AppLink } | { web: string } | { none: string };

export function noteLinkAction(link: NoteLink): NoteLinkAction {
  switch (link.kind) {
    case "web":
      return { web: link.url };
    case "session":
      return link.id ? { open: { kind: "session", sessionId: link.id } } : { none: `No session named ${link.name}` };
    case "vm":
      return link.key ? { open: { kind: "vm", vmxPath: link.key } } : { none: `No VM named ${link.name}` };
    case "vault":
      return link.found ? { open: { kind: "vault" } } : { none: `The vault has no item named ${link.name}` };
    case "command":
    case "runbook":
      return { open: { kind: "snippet", command: link.name } };
    case "refused":
      return { none: "Only web addresses and the app's own links open from a note" };
  }
}

/** The link's tooltip: where it goes, never a secret (a vault link names its item only). */
export function noteLinkTitle(link: NoteLink): string {
  switch (link.kind) {
    case "web":
      return link.url;
    case "session":
      return link.id ? `Session ${link.name}` : `No session named ${link.name}`;
    case "vm":
      return link.key ? `VM ${link.name}` : `No VM named ${link.name}`;
    case "vault":
      return link.found ? `Vault item ${link.name}` : `The vault has no item named ${link.name}`;
    case "command":
      return `Command ${link.name}`;
    case "runbook":
      return `Runbook ${link.name}`;
    case "refused":
      return "Not opened: only web addresses and the app's own links open from a note";
  }
}

/** "the session web01", for titles and confirms. */
export function noteAbout(kind: NoteKind, title: string): string {
  switch (kind) {
    case "session":
      return `the session ${title}`;
    case "vm":
      return `the VM ${title}`;
    case "folder":
      return `the folder ${title}`;
  }
}

export function noteTarget(kind: NoteKind, key: string): NoteTarget {
  return { kind, key };
}

/** The note's own link: App opens its sheet. `title`: what it is about, for a note not written yet. */
export function noteLink(kind: NoteKind, key: string, title?: string): Extract<AppLink, { kind: "note" }> {
  return title === undefined ? { kind: "note", noteKind: kind, key } : { kind: "note", noteKind: kind, key, title };
}

/** The first line of a note's text without markdown marks, for lists and search results. */
export function noteExcerpt(body: string, max = 120): string {
  const line =
    body
      .split("\n")
      .filter((l) => !/^\s*(```|~~~|---|\*\*\*|\|?[-:| ]+\|[-:| ]*$)/.test(l))
      .map((l) =>
        l
          .replace(/^\s*(#{1,6}\s+|[-*+]\s+(\[[ xX]\]\s+)?|>\s*|\d+\.\s+)/, "")
          .replace(/[*_`~]/g, "")
          .trim(),
      )
      .find((l) => l !== "") ?? "";
  return line.length > max ? `${line.slice(0, max - 1)}…` : line;
}

/**
 * What a code block's "Send to terminal" pastes: its text without the line break(s) at its end, which would press
 * Enter (the core keeps a block's text as written, and CommonMark ends it with one). A block with a line break inside
 * still holds them; the terminal asks about it first, whatever the paste setting.
 */
export function noteCodeToSend(code: string): string {
  return code.replace(/[\r\n]+$/, "");
}
