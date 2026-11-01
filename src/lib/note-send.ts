// FD-06: a note's code block sent to the open terminal. The Terminal page registers how (its current pane's paste,
// which asks before a paste with a line break whatever the paste setting, QL-05); a note calls `sendNoteCode`, which
// takes the block's last line break off first, so nothing is entered by itself.

import { noteCodeToSend } from "./notes.ts";

type Handler = (text: string) => boolean;

let handler: Handler | null = null;

/** The Terminal page's side; `null` when it unmounts. */
export function setNoteSendHandler(next: Handler | null) {
  handler = next;
}

/** Pastes a code block into the current terminal, without the line break at its end. False when no terminal is open
 * and connected, or the block is empty. */
export function sendNoteCode(code: string): boolean {
  const text = noteCodeToSend(code);
  if (!text.trim()) return false;
  return handler ? handler(text) : false;
}
