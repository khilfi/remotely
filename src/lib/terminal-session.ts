// One terminal pane (SS-03): an xterm.js instance and its SSH connection in the core. It lives outside
// React's tree so splitting a pane (which reshapes the layout) never remounts, and so never drops, a
// connection: the pane's view attaches `element` wherever the layout puts it.
//
// Bytes stay bytes: keystrokes go to the core as raw UTF-8, output comes back as raw bytes that xterm.js
// decodes itself. Writes are sent one at a time, in order, with whatever was typed meanwhile batched.

import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { api, errorCode, errorMessage, type HostKey, type KnownHost, type TerminalStatus } from "@/lib/api";
import type { ResolvedTheme } from "@/lib/theme";

const MONO = "'Cascadia Mono', 'Cascadia Code', Consolas, monospace";

// In code rather than CSS variables: React runs this page's effects before the app flips the `dark`
// class, so reading CSS variables on a theme change would pick up the old colours.
export const TERMINAL_PALETTE = {
  light: { background: "#fafafa", foreground: "#1f1f1f", cursor: "#1f1f1f", selectionBackground: "#0000002e" },
  dark: { background: "#0c0c0d", foreground: "#e4e4e7", cursor: "#e4e4e7", selectionBackground: "#ffffff38" },
} as const;

/** SS-05: a host key decision the pane is waiting for. */
export type HostKeyQuestion =
  { kind: "unknown"; key: HostKey; otherKeyTypes: string[] } | { kind: "changed"; key: HostKey; previous: KnownHost };

/** Before the core has a status for the pane. */
export type PaneStatus = TerminalStatus | { state: "opening" };

export interface PaneSnapshot {
  status: PaneStatus;
  /** When a reconnect countdown started (ms), to show the seconds left. */
  statusAt: number;
  question: HostKeyQuestion | null;
  /** The last changed-key notice, kept so the user can review it after closing the dialog. */
  changedKey: Extract<HostKeyQuestion, { kind: "changed" }> | null;
}

const encoder = new TextEncoder();

/**
 * A first-connection question ends with its connection attempt; a changed-key notice stays up after
 * the pane reports the blocked connection, until the user closes it.
 */
function keepQuestion(question: HostKeyQuestion | null, status: TerminalStatus): HostKeyQuestion | null {
  if (!question) return null;
  if (status.state === "connecting") return question;
  if (status.state === "disconnected" && question.kind === "changed") return question;
  return null;
}

export class PaneSession {
  readonly key: string;
  readonly sessionId: string;
  readonly element: HTMLDivElement;
  readonly term: Terminal;
  private readonly fitAddon: FitAddon;
  private coreId: string | null = null;
  private started = false;
  private closed = false;
  private snapshot: PaneSnapshot = {
    status: { state: "opening" },
    statusAt: Date.now(),
    question: null,
    changedKey: null,
  };
  private readonly listeners = new Set<() => void>();
  private pending: Uint8Array[] = [];
  private writing = false;
  copyOnSelect = true;

  constructor(key: string, sessionId: string, theme: ResolvedTheme) {
    this.key = key;
    this.sessionId = sessionId;
    this.element = document.createElement("div");
    this.element.className = "h-full w-full";
    this.term = new Terminal({
      fontFamily: MONO,
      fontSize: 13,
      cursorBlink: true,
      scrollback: 10000,
      theme: TERMINAL_PALETTE[theme],
    });
    this.fitAddon = new FitAddon();
    this.term.loadAddon(this.fitAddon);
    this.term.open(this.element);

    this.term.onData((data) => this.send(encoder.encode(data)));
    // Binary data (some mouse reports) is one byte per character.
    this.term.onBinary((data) => this.send(Uint8Array.from(data, (c) => c.charCodeAt(0) & 0xff)));
    this.term.onResize(({ cols, rows }) => {
      if (this.coreId) void api.terminalResize(this.coreId, cols, rows);
    });
    // SS-03 copy-on-select, like PuTTY.
    this.term.onSelectionChange(() => {
      if (this.copyOnSelect && this.term.hasSelection()) void navigator.clipboard?.writeText(this.term.getSelection());
    });
    this.term.attachCustomKeyEventHandler((ev) => this.handleKey(ev));
    // Right-click pastes, like PuTTY.
    this.element.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      void this.pasteFromClipboard();
    });
  }

  // ---- state for React (useSyncExternalStore) ----

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getSnapshot = () => this.snapshot;

  private update(change: Partial<PaneSnapshot>) {
    this.snapshot = { ...this.snapshot, ...change };
    this.listeners.forEach((l) => l());
  }

  // ---- connection ----

  /** Opens the connection, sized to the pane. Called once the element is on screen. */
  start() {
    if (this.started || this.closed) return;
    this.started = true;
    this.fit();
    this.update({ status: { state: "opening" }, statusAt: Date.now() });
    api
      .terminalOpen(
        this.sessionId,
        this.term.cols,
        this.term.rows,
        (data) => this.term.write(data),
        (event) => {
          switch (event.event) {
            case "status":
              this.update({
                status: event.status,
                statusAt: Date.now(),
                question: keepQuestion(this.snapshot.question, event.status),
              });
              break;
            case "hostKeyUnknown":
              this.update({ question: { kind: "unknown", key: event.key, otherKeyTypes: event.otherKeyTypes } });
              break;
            case "hostKeyChanged": {
              const changed = { kind: "changed" as const, key: event.key, previous: event.previous };
              this.update({ question: changed, changedKey: changed });
              break;
            }
          }
        },
      )
      .then((id) => {
        if (this.closed) {
          void api.terminalClose(id);
          return;
        }
        this.coreId = id;
        this.flush();
      })
      .catch((err) => {
        // Nothing was opened (a jump host, a key login with no key chosen, a deleted session).
        this.started = false;
        const message = errorMessage(err);
        this.update({
          status: { state: "disconnected", code: errorCode(err) ?? "error", message },
          statusAt: Date.now(),
        });
        this.term.write(`\r\n\x1b[31m[Not connected: ${message}]\x1b[0m\r\n`);
      });
  }

  /** Connects again now: a fresh open when nothing was opened, otherwise the core reconnects. */
  reconnect() {
    if (this.coreId) void api.terminalReconnect(this.coreId);
    else this.start();
  }

  answerHostKey(trust: boolean) {
    this.update({ question: null });
    if (this.coreId) return api.terminalHostKeyAnswer(this.coreId, trust);
    return Promise.resolve();
  }

  replaceHostKey() {
    this.update({ question: null });
    if (this.coreId) return api.terminalHostKeyReplace(this.coreId);
    return Promise.resolve();
  }

  dismissQuestion() {
    this.update({ question: null });
  }

  reviewChangedKey() {
    if (this.snapshot.changedKey) this.update({ question: this.snapshot.changedKey });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    if (this.coreId) void api.terminalClose(this.coreId);
    this.term.dispose();
    this.listeners.clear();
  }

  // ---- input ----

  private send(bytes: Uint8Array) {
    this.pending.push(bytes);
    this.flush();
  }

  /** One write in flight at a time, so keystrokes arrive in order; the rest is batched. */
  private flush() {
    if (this.writing || !this.coreId || this.pending.length === 0) return;
    const parts = this.pending;
    this.pending = [];
    const size = parts.reduce((n, p) => n + p.length, 0);
    const data = new Uint8Array(size);
    let at = 0;
    for (const p of parts) {
      data.set(p, at);
      at += p.length;
    }
    this.writing = true;
    api
      .terminalWrite(this.coreId, data)
      .catch((err) => console.warn("terminal write failed", err))
      .finally(() => {
        this.writing = false;
        this.flush();
      });
  }

  private handleKey(ev: KeyboardEvent): boolean {
    if (ev.type !== "keydown") return true;
    const key = ev.key.toLowerCase();
    // Ctrl+C with a selection copies (as in Windows Terminal); without one it is ^C for the shell.
    if (ev.ctrlKey && !ev.altKey && key === "c" && (ev.shiftKey || this.term.hasSelection())) {
      if (this.term.hasSelection()) void navigator.clipboard?.writeText(this.term.getSelection());
      this.term.clearSelection();
      ev.preventDefault();
      return false;
    }
    // Ctrl+V and Ctrl+Shift+V: let the browser paste; xterm.js picks up the paste event.
    if (ev.ctrlKey && !ev.altKey && key === "v") return false;
    return true;
  }

  async pasteFromClipboard() {
    try {
      const text = await navigator.clipboard.readText();
      if (text) this.term.paste(text);
    } catch {
      this.term.write("\r\n\x1b[2m[Paste with Ctrl+V]\x1b[0m\r\n");
    }
  }

  // ---- view ----

  setTheme(theme: ResolvedTheme) {
    this.term.options.theme = TERMINAL_PALETTE[theme];
  }

  fit() {
    if (this.element.offsetWidth > 0 && this.element.offsetHeight > 0) {
      try {
        this.fitAddon.fit();
      } catch {
        // Not laid out yet.
      }
    }
  }

  focus() {
    this.term.focus();
  }
}
