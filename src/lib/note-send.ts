// FD-06: a note's code block sent to the open terminal. The Terminal page registers how (its current pane's paste,
// which asks before a paste with a line break, QL-05, and never presses Enter); a note calls `sendNoteCode`.

type Handler = (text: string) => boolean;

let handler: Handler | null = null;

/** The Terminal page's side; `null` when it unmounts. */
export function setNoteSendHandler(next: Handler | null) {
  handler = next;
}

/** Pastes `text` into the current terminal. False when no terminal is open and connected. */
export function sendNoteCode(text: string): boolean {
  return handler ? handler(text) : false;
}
