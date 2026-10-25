// QL-15: what a crashed page says, and which browser keys a release build swallows. Pure helpers (tested in
// ui-errors.test.ts); the error boundary itself is components/ErrorBoundary.tsx.

/** The longest error text a crashed page shows (and sends to the app's log), in characters. */
export const MAX_ERROR_CHARS = 500;

/** A thrown value as one short line of text. */
export function describeError(error: unknown): string {
  let text: string;
  if (error instanceof Error) text = error.message || error.name;
  else if (typeof error === "string") text = error;
  else {
    try {
      text = JSON.stringify(error) ?? String(error);
    } catch {
      text = String(error);
    }
  }
  text = text.replace(/\s+/g, " ").trim() || "Unknown error";
  return text.length > MAX_ERROR_CHARS ? `${text.slice(0, MAX_ERROR_CHARS)}…` : text;
}

/** The parts of a key press that decide whether it is a browser key. */
export interface KeyPress {
  key: string;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  metaKey: boolean;
}

/**
 * Browser keys a release build ignores: reloading (F5, Ctrl+R, Ctrl+F5, Ctrl+Shift+R) would leave the core's work
 * unseen, and the developer tools (F12, Ctrl+Shift+I or J) are not for users. WebView2's own browser keys are off too
 * (Rust side); this catches them should that setting not apply. Editing keys (Ctrl+C, Ctrl+V...) and the terminal's
 * Ctrl+Shift+C (copy) are not here.
 */
export function isBrowserKey(press: KeyPress): boolean {
  const key = press.key.length === 1 ? press.key.toLowerCase() : press.key;
  if (key === "F5" || key === "F12" || key === "BrowserRefresh") return true;
  if (press.ctrlKey && !press.altKey && !press.metaKey) {
    if (key === "r" && !press.shiftKey) return true;
    if (press.shiftKey && (key === "r" || key === "i" || key === "j")) return true;
  }
  return false;
}
