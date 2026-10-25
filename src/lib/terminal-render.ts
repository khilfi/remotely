// SS-03, FD-03: how terminal panes render, and how a presenting pane fills its masked copy, as pure functions
// (terminal-session.ts uses them; tested in terminal-render.test.ts).
//
// SS-03: a pane on screen draws with WebGL (@xterm/addon-webgl), which keeps the DOM small and the main thread free
// while a host prints a lot. A browser allows only about 16 WebGL contexts per page and drops the oldest past that, so
// a hidden pane gives its context back and draws with xterm.js's own DOM renderer, as does a pane whose WebGL failed
// too often, or every pane when WebGL can't start in this window at all.
//
// FD-03: the masked copy keeps less scrollback than the real terminal, and the real one's screen is copied into it in
// pieces cut at line breaks, so a big scrollback never holds the page up and a value is never cut in two.

/** SS-03: panes that may hold a WebGL context at once; the rest draw with the DOM renderer. */
export const MAX_WEBGL_PANES = 12;

/** SS-03: WebGL failures (it could not start, or its context was lost) after which a pane stays on the DOM renderer. */
export const MAX_WEBGL_FAILURES = 3;

/** SS-03: how long a pane stays hidden before it gives its WebGL context back (a quick tab switch keeps it). */
export const WEBGL_RELEASE_MS = 2000;

/** SS-03: what decides whether a pane draws with WebGL. */
export interface WebglCheck {
  /** The pane is on screen (laid out, in the window's view). */
  visible: boolean;
  /** This pane's WebGL failures so far. */
  failures: number;
  /** WebGL could not start in this window at all. */
  unavailable: boolean;
  /** Other panes holding a WebGL context now. */
  others: number;
}

/** SS-03: whether a pane should hold a WebGL context now. */
export function wantsWebgl(check: WebglCheck): boolean {
  return check.visible && !check.unavailable && check.failures < MAX_WEBGL_FAILURES && check.others < MAX_WEBGL_PANES;
}

/** FD-03: scrollback lines the masked copy of a presenting pane keeps (the real terminal keeps the setting's). */
export const MASKED_SCROLLBACK = 1000;

/** FD-03: the masked copy's scrollback for a real terminal with `real` lines of it. */
export function maskedScrollback(real: number): number {
  return Math.max(0, Math.min(Math.floor(real), MASKED_SCROLLBACK));
}

/** FD-03: about how many characters of the real screen are masked and written at a time. */
export const MASK_CHUNK_CHARS = 16 * 1024;

/**
 * FD-03: `text` in pieces of about `maxChars`, each cut just after a line break (`\n`), so a line, and a value on it,
 * is never cut in two. A line longer than `maxChars` is a piece of its own. The pieces joined are `text`.
 */
export function splitAtLineBreaks(text: string, maxChars: number): string[] {
  if (text === "") return [];
  const size = Math.max(1, Math.floor(maxChars));
  const pieces: string[] = [];
  let start = 0;
  while (start < text.length) {
    if (text.length - start <= size) {
      pieces.push(text.slice(start));
      break;
    }
    // The last line break within the size, else the first one after it.
    let cut = text.lastIndexOf("\n", start + size - 1);
    if (cut < start) cut = text.indexOf("\n", start + size);
    if (cut < 0) {
      pieces.push(text.slice(start));
      break;
    }
    pieces.push(text.slice(start, cut + 1));
    start = cut + 1;
  }
  return pieces;
}
