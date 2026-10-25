// QL-05, SS-03: what a paste into a terminal may send, and when it asks first. Every paste goes through here: Ctrl+V,
// Ctrl+Shift+V and the browser's own paste (caught before xterm.js sees them), right-click and the Paste menu item
// (the clipboard read by the shell), and BX-08's command panel (cleaned, never asked: the panel shows its command).
//
// Cleaning: the bracketed-paste markers ESC[200~ and ESC[201~ (and their 8-bit CSI forms) go first, so pasted text
// can't end bracketed paste early and have the rest run as typed; then every C0 control except tab, CR and LF, DEL,
// and the C1 controls U+0080 to U+009F (U+009B is an 8-bit CSI). Removing a marker can join the pieces of another, so
// that repeats until none is left; and with ESC itself gone, no escape sequence can be left over. Line endings stay
// as they are: xterm.js's paste turns each CRLF or LF into CR (and brackets the text when the shell asked for it).
//
// Asking: a paste that holds a line break asks first (TerminalSettings.confirmMultilinePaste, on by default), one
// line that ends with a line break too, because that break presses Enter: a shell without bracketed paste runs the
// line as it arrives.

const BRACKET_MARKERS = ["\x1b[200~", "\x1b[201~", "\x9b200~", "\x9b201~"];

/** C0 controls but tab, LF and CR; DEL; C1 controls. */
function stripped(code: number) {
  return (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || (code >= 0x7f && code <= 0x9f);
}

/** The text a paste may send: no bracketed-paste markers and no control characters but tab, CR and LF. */
export function sanitizePaste(text: string): string {
  let out = text;
  for (;;) {
    const before = out;
    for (const marker of BRACKET_MARKERS) out = out.split(marker).join("");
    if (out === before) break;
  }
  let clean = "";
  let from = 0;
  for (let i = 0; i < out.length; i++) {
    if (!stripped(out.charCodeAt(i))) continue;
    clean += out.slice(from, i);
    from = i + 1;
  }
  return from === 0 ? out : clean + out.slice(from);
}

/** The paste holds a line break, which presses Enter: it asks first. */
export function pasteHasLineBreak(text: string): boolean {
  return /[\r\n]/.test(text);
}

/** What the confirm shows. */
export interface PastePreview {
  /** Lines in the paste; a line break at the very end ends the last line, it does not start another. */
  lines: number;
  /** The first lines, each cut to a readable length. */
  shown: string[];
  /** Lines not shown. */
  more: number;
  /** The paste ends with a line break, so even its last line is entered. */
  endsWithBreak: boolean;
}

export const PREVIEW_LINES = 5;
export const PREVIEW_CHARS = 120;

/** Lines as a terminal sees them: CRLF, CR or LF each end one. */
export function pasteLines(text: string): string[] {
  if (!text) return [];
  const lines = text.split(/\r\n|\r|\n/);
  if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** At most `max` characters (code points, so an emoji is never cut in half), the last one an ellipsis when cut. */
function cut(line: string, max: number) {
  const chars = Array.from(line);
  return chars.length > max ? `${chars.slice(0, Math.max(0, max - 1)).join("")}…` : line;
}

export function pastePreview(text: string, maxLines = PREVIEW_LINES, maxChars = PREVIEW_CHARS): PastePreview {
  const lines = pasteLines(text);
  const shown = lines.slice(0, maxLines).map((line) => cut(line, maxChars));
  return {
    lines: lines.length,
    shown,
    more: Math.max(0, lines.length - shown.length),
    endsWithBreak: /[\r\n]$/.test(text),
  };
}
