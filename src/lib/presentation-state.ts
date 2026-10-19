// FD-03: presentation mode in the UI. One small store, read by React (usePresentation in Presentation.tsx) and by code
// outside React (the terminal panes, QL-07's notifications). Changing it applies at once, before React renders again:
// the DOM masker starts or stops and the `data-presenting` attribute styles inputs and the frame, so nothing real
// shows in between. Whether the app presents and whether the lock is on are the core's settings (saved and audited);
// "hide terminal output" is this window's own choice, kept in local storage.

import { masker } from "@/lib/presentation";
import { startDomMasking, stopDomMasking } from "@/lib/presentation-dom";

export interface PresentationView {
  /** The screen is masked. */
  presenting: boolean;
  /** The core's read-only lock is set (it applies while presenting). */
  readOnly: boolean;
  /** Terminals are blurred while presenting, for what masking can't catch (full-screen programs). */
  hideTerminals: boolean;
}

const HIDE_KEY = "remotely.presentation.hideTerminals";

function storedHide(): boolean {
  try {
    return localStorage.getItem(HIDE_KEY) === "1";
  } catch {
    return false;
  }
}

let view: PresentationView = { presenting: false, readOnly: false, hideTerminals: storedHide() };
const listeners = new Set<() => void>();

export function presentationView(): PresentationView {
  return view;
}

export function subscribePresentation(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Whether the read-only lock applies now (presenting with the lock on). */
export function readOnlyLocked(v: PresentationView = view): boolean {
  return v.presenting && v.readOnly;
}

/**
 * Text shown outside the window, which the DOM masker can't reach (QL-07's Windows notifications): masked like the
 * page while presenting.
 */
export function maskedOutside(text: string): string {
  return view.presenting ? masker.text(text) : text;
}

export function setPresentationView(change: Partial<PresentationView>) {
  const next = { ...view, ...change };
  if (
    next.presenting === view.presenting &&
    next.readOnly === view.readOnly &&
    next.hideTerminals === view.hideTerminals
  )
    return;
  const root = document.documentElement;
  // Masking starts before anyone hears of it, and stops only after the attribute is gone.
  if (next.presenting) {
    root.setAttribute("data-presenting", "");
    startDomMasking();
  }
  root.toggleAttribute("data-hide-terminals", next.presenting && next.hideTerminals);
  root.toggleAttribute("data-read-only", readOnlyLocked(next));
  if (next.hideTerminals !== view.hideTerminals) {
    try {
      localStorage.setItem(HIDE_KEY, next.hideTerminals ? "1" : "0");
    } catch {
      // Private storage: the choice lasts until the window closes.
    }
  }
  view = next;
  listeners.forEach((l) => l());
  if (!next.presenting) {
    stopDomMasking();
    root.removeAttribute("data-presenting");
  }
}
