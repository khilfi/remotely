// One terminal pane (SS-03): an xterm.js instance and its SSH connection in the core. It lives outside
// React's tree so splitting a pane (which reshapes the layout) never remounts, and so never drops, a
// connection: the pane's view attaches `element` wherever the layout puts it.
//
// Bytes stay bytes: keystrokes go to the core as raw UTF-8, output comes back as raw bytes that xterm.js
// decodes itself. Writes are sent one at a time, in order, with whatever was typed meanwhile batched.
//
// A pane opens a saved session, a quick connection from the New terminal form (QL-02) or another
// connection like an open pane (a split). QL-05: search (Ctrl+Shift+F), Ctrl+Shift+C / Ctrl+Shift+V,
// right-click paste, and the font size, scrollback and copy-on-select settings, applied live. SS-11:
// the whole buffer as text, and logging to a file. BX-08: a command from the command panel is pasted as if typed;
// QL-06: a vault password is typed by the core, which never hands it to the UI; QL-07: the core reports a long
// command that finished, and the page decides whether to notify. SS-10: with MultiExec on, a picked pane's keys go
// to `inputRouter` instead (see multiexec.ts). SS-08: the core says which folder the shell is in (`folder`), and a
// right-click on a file name in the output goes to `onFileWord` (the page offers to download it) instead of pasting.
// SS-07: the core reports the session's tunnels (`tunnels`); one that waits for approval (e.g. one that starts with
// a Prod session's terminal) goes to `onTunnelAsking`, so the page can show the dialog. Host key questions name the
// jump host that asks.

import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import {
  api,
  errorCode,
  errorMessage,
  type ApprovalAnswers,
  type FinishedHow,
  type FolderInfo,
  type HostFacts,
  type HostKey,
  type KnownHost,
  type QuickConnectRequest,
  type SessionRecord,
  type TerminalEvent,
  type TerminalStatus,
  type TunnelInfo,
  type TunnelStart,
} from "@/lib/api";
import type { ResolvedTheme } from "@/lib/theme";
import { fileWordAt } from "@/lib/transfers";

const MONO = "'Cascadia Mono', 'Cascadia Code', Consolas, monospace";

// In code rather than CSS variables: React runs this page's effects before the app flips the `dark`
// class, so reading CSS variables on a theme change would pick up the old colours.
export const TERMINAL_PALETTE = {
  light: { background: "#fafafa", foreground: "#1f1f1f", cursor: "#1f1f1f", selectionBackground: "#0000002e" },
  dark: { background: "#0c0c0d", foreground: "#e4e4e7", cursor: "#e4e4e7", selectionBackground: "#ffffff38" },
} as const;

/** Search matches; the search addon wants #RRGGBB. */
const SEARCH_DECORATIONS = {
  matchBackground: "#ffd33d",
  matchOverviewRuler: "#ffd33d",
  activeMatchBackground: "#ff9632",
  activeMatchColorOverviewRuler: "#ff9632",
};

/** SS-05: a host key decision the pane is waiting for. `jump`: SS-07, the jump host on the way that asks, if any. */
export type HostKeyQuestion =
  | { kind: "unknown"; key: HostKey; otherKeyTypes: string[]; jump: string | null }
  | { kind: "changed"; key: HostKey; previous: KnownHost; jump: string | null };

/** Before the core has a status for the pane. */
export type PaneStatus = TerminalStatus | { state: "opening" };

/** What a pane connects to. */
export type PaneOpener =
  | { kind: "session"; sessionId: string }
  /** QL-02. The typed password, if any, is dropped as soon as the core has it. */
  | { kind: "quick"; request: QuickConnectRequest }
  /** Another connection like an open pane, with a password typed for it (a split). */
  | { kind: "like"; terminalId: string };

export interface PaneSnapshot {
  status: PaneStatus;
  /** When a reconnect countdown started (ms), to show the seconds left. */
  statusAt: number;
  question: HostKeyQuestion | null;
  /** The last changed-key notice, kept so the user can review it after closing the dialog. */
  changedKey: Extract<HostKeyQuestion, { kind: "changed" }> | null;
  /** QL-03: the host's name and address as far as they are known. */
  facts: HostFacts | null;
  /** The saved session, once known (a quick connection saved as one learns it when it opens). */
  sessionId: string | null;
  /** SS-11: the file this pane logs to. */
  logPath: string | null;
  /** QL-05: the search bar is open. */
  searching: boolean;
  /** QL-05: the last search's matches; index -1 when there are too many to number. */
  searchResults: { index: number; count: number } | null;
  /** SS-08: the shell's folder, as far as the core knows it. */
  folder: FolderInfo | null;
  /** SS-07: the session's tunnels and their state, once the core has said. */
  tunnels: TunnelInfo[] | null;
}

/** QL-05 settings a pane applies live. */
export interface PaneOptions {
  fontSize: number;
  scrollback: number;
  copyOnSelect: boolean;
}

export const DEFAULT_PANE_OPTIONS: PaneOptions = { fontSize: 13, scrollback: 10000, copyOnSelect: true };

/** QL-07: a command that ran long has ended in this pane. */
export interface CommandFinished {
  afterSecs: number;
  how: FinishedHow;
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

/** QL-03: `web01 · 192.0.2.10`, or whichever of the two is known. */
export function factsTitle(facts: HostFacts | null): string | null {
  if (!facts) return null;
  const { hostname, ip } = facts;
  if (hostname && ip && hostname !== ip) return `${hostname} · ${ip}`;
  return hostname ?? ip;
}

/** `alice@web01.example.com:2222`; the port only when it is not 22. */
export function sessionAddress(s: Pick<SessionRecord, "username" | "host" | "port">) {
  return `${s.username ? `${s.username}@` : ""}${s.host}${s.port === 22 ? "" : `:${s.port}`}`;
}

export class PaneSession {
  readonly key: string;
  readonly element: HTMLDivElement;
  readonly term: Terminal;
  /** How the pane is named before the core says more: the session's or the typed address. */
  readonly label: string;
  private readonly fitAddon: FitAddon;
  private readonly searchAddon: SearchAddon;
  private opener: PaneOpener | null;
  private coreId: string | null = null;
  private started = false;
  private closed = false;
  private snapshot: PaneSnapshot;
  private readonly listeners = new Set<() => void>();
  private pending: Uint8Array[] = [];
  private writing = false;
  copyOnSelect = true;
  /** QL-07: called when the core reports a long command that finished here. */
  onCommandFinished: ((finished: CommandFinished) => void) | null = null;
  /**
   * SS-10: set while MultiExec is on and this pane is picked. Its keys (typed, pasted, or from the command panel) go
   * there instead of to this terminal alone; MultiExec sends them to every picked terminal and holds Enter.
   */
  inputRouter: ((pane: PaneSession, bytes: Uint8Array) => void) | null = null;
  /**
   * SS-08: a right-click on what looks like a file name in the output: the page looks it up and offers to download
   * it, or pastes. Without it, right-click pastes (QL-05).
   */
  onFileWord: ((word: string, x: number, y: number) => void) | null = null;
  /** SS-07: a tunnel started waiting for the user's approval (the page fetches the request and shows it). */
  onTunnelAsking: ((pane: PaneSession, forwardId: string) => void) | null = null;

  constructor(key: string, opener: PaneOpener, label: string, theme: ResolvedTheme, options: PaneOptions) {
    this.key = key;
    this.opener = opener;
    this.label = label;
    this.snapshot = {
      status: { state: "opening" },
      statusAt: Date.now(),
      question: null,
      changedKey: null,
      facts: null,
      sessionId: opener.kind === "session" ? opener.sessionId : null,
      logPath: null,
      searching: false,
      searchResults: null,
      folder: null,
      tunnels: null,
    };
    this.element = document.createElement("div");
    this.element.className = "h-full w-full";
    this.copyOnSelect = options.copyOnSelect;
    this.term = new Terminal({
      fontFamily: MONO,
      fontSize: options.fontSize,
      cursorBlink: true,
      scrollback: options.scrollback,
      theme: TERMINAL_PALETTE[theme],
      // The search addon's match highlights use the decorations API.
      allowProposedApi: true,
    });
    this.fitAddon = new FitAddon();
    this.term.loadAddon(this.fitAddon);
    this.searchAddon = new SearchAddon({ highlightLimit: 2000 });
    this.term.loadAddon(this.searchAddon);
    this.searchAddon.onDidChangeResults(({ resultIndex, resultCount }) => {
      this.update({ searchResults: { index: resultIndex, count: resultCount } });
    });
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
    // QL-05: right-click pastes, like PuTTY; SS-08: on a file name, the page may offer to download it first.
    this.element.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      const word = this.onFileWord && this.connected ? this.wordAt(ev.clientX, ev.clientY) : null;
      if (word && this.onFileWord) this.onFileWord(word, ev.clientX, ev.clientY);
      else void this.pasteFromClipboard();
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

  /** SS-10: MultiExec takes this pane's keys (a function), or gives them back (null). */
  setInputRouter(router: ((pane: PaneSession, bytes: Uint8Array) => void) | null) {
    this.inputRouter = router;
  }

  /** The core's id for this pane, once it has opened. */
  get terminalId() {
    return this.coreId;
  }

  get sessionId() {
    return this.snapshot.sessionId;
  }

  /** The shell is up, so typed or pasted text reaches it. */
  get connected() {
    return this.coreId !== null && this.snapshot.status.state === "connected";
  }

  // ---- connection ----

  private onEvent = (event: TerminalEvent) => {
    switch (event.event) {
      case "status":
        this.update({
          status: event.status,
          statusAt: Date.now(),
          question: keepQuestion(this.snapshot.question, event.status),
          ...(event.status.state === "closed" ? { logPath: null } : {}),
        });
        break;
      case "hostKeyUnknown":
        this.update({
          question: { kind: "unknown", key: event.key, otherKeyTypes: event.otherKeyTypes, jump: event.jump },
        });
        break;
      case "hostKeyChanged": {
        const changed = { kind: "changed" as const, key: event.key, previous: event.previous, jump: event.jump };
        this.update({ question: changed, changedKey: changed });
        break;
      }
      case "tunnels": {
        const before = new Set(
          (this.snapshot.tunnels ?? []).filter((t) => t.state.state === "asking").map((t) => t.forward.id),
        );
        this.update({ tunnels: event.tunnels });
        for (const t of event.tunnels) {
          if (t.state.state === "asking" && !before.has(t.forward.id)) this.onTunnelAsking?.(this, t.forward.id);
        }
        break;
      }
      case "host":
        this.update({ facts: event.facts });
        break;
      case "commandFinished":
        this.onCommandFinished?.({ afterSecs: event.afterSecs, how: event.how });
        break;
      case "folder":
        this.update({ folder: event.folder });
        break;
    }
  };

  private onOutput = (data: Uint8Array) => this.term.write(data);

  /**
   * Opens the connection, sized to the pane (80×24 until it is on screen; the core gets the real size
   * as soon as the pane is laid out). Resolves once the core has opened the pane, and rejects when it
   * opened nothing (a bad quick connection, jump hosts that go round in a loop, a deleted session).
   */
  async start(): Promise<void> {
    if (this.started || this.closed || !this.opener) return;
    this.started = true;
    this.fit();
    this.update({ status: { state: "opening" }, statusAt: Date.now() });
    const opener = this.opener;
    const { cols, rows } = this.term;
    try {
      let id: string;
      if (opener.kind === "session") {
        id = await api.terminalOpen(opener.sessionId, cols, rows, this.onOutput, this.onEvent);
      } else if (opener.kind === "quick") {
        const opened = await api.terminalQuickConnect(opener.request, cols, rows, this.onOutput, this.onEvent);
        id = opened.id;
        // A saved quick connection is a session from now on: reconnects and splits follow it.
        this.opener = opened.session ? { kind: "session", sessionId: opened.session.id } : null;
        if (opened.session) this.update({ sessionId: opened.session.id });
      } else {
        id = await api.terminalOpenLike(opener.terminalId, cols, rows, this.onOutput, this.onEvent);
        this.opener = null;
      }
      if (this.closed) {
        void api.terminalClose(id);
        return;
      }
      this.coreId = id;
      this.flush();
    } catch (err) {
      this.started = false;
      // A typed password goes to the core once; trying again asks in the terminal.
      if (opener.kind === "quick") this.opener = { kind: "quick", request: { ...opener.request, password: null } };
      const message = errorMessage(err);
      this.update({
        status: { state: "disconnected", code: errorCode(err) ?? "error", message },
        statusAt: Date.now(),
      });
      this.term.write(`\r\n\x1b[31m[Not connected: ${message}]\x1b[0m\r\n`);
      throw err;
    }
  }

  /** Connects again now: a fresh open when nothing was opened, otherwise the core reconnects. */
  reconnect() {
    if (this.coreId) void api.terminalReconnect(this.coreId);
    else this.start().catch(() => undefined);
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
    this.opener = null;
    if (this.coreId) void api.terminalClose(this.coreId);
    this.term.dispose();
    this.listeners.clear();
    this.onCommandFinished = null;
    this.onFileWord = null;
    this.onTunnelAsking = null;
  }

  // ---- SS-07 tunnels ----

  private requireId() {
    if (!this.coreId) throw new Error("This terminal has not opened yet.");
    return this.coreId;
  }

  /** The tunnels as the core has them now (also kept up to date by its events). */
  async loadTunnels() {
    const tunnels = await api.terminalTunnels(this.requireId());
    this.update({ tunnels });
    return tunnels;
  }

  /** Opens a saved forward through the approval flow: opening at once, or the approval to show. */
  startTunnel(forwardId: string): Promise<TunnelStart> {
    return api.terminalTunnelStart(this.requireId(), forwardId);
  }

  stopTunnel(forwardId: string) {
    return api.terminalTunnelStop(this.requireId(), forwardId);
  }

  tunnelRequest(forwardId: string) {
    return api.terminalTunnelRequest(this.requireId(), forwardId);
  }

  approveTunnel(forwardId: string, answers: ApprovalAnswers) {
    return api.terminalTunnelApprove(this.requireId(), forwardId, answers);
  }

  declineTunnel(forwardId: string) {
    return api.terminalTunnelDecline(this.requireId(), forwardId);
  }

  /** SS-08: the file name under a point of the screen (client pixels), if the output shows one there. */
  wordAt(clientX: number, clientY: number): string | null {
    const screen = this.element.querySelector(".xterm-screen");
    if (!screen) return null;
    const rect = screen.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return null;
    const col = Math.floor(((clientX - rect.left) / rect.width) * this.term.cols);
    const row = Math.floor(((clientY - rect.top) / rect.height) * this.term.rows);
    if (col < 0 || row < 0 || col >= this.term.cols || row >= this.term.rows) return null;
    const buffer = this.term.buffer.active;
    const line = buffer.getLine(buffer.viewportY + row);
    return line ? fileWordAt(line.translateToString(false), col) : null;
  }

  // ---- input ----

  private send(bytes: Uint8Array) {
    // Always, so no key typed with MultiExec on skips its checks (one typed just before may still be writing; the
    // core then knows that terminal's line holds text it did not see).
    if (this.inputRouter && this.coreId) {
      this.inputRouter(this, bytes);
      return;
    }
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
    // Ctrl+Shift+C always copies.
    if (ev.ctrlKey && !ev.altKey && key === "c" && (ev.shiftKey || this.term.hasSelection())) {
      if (this.term.hasSelection()) void navigator.clipboard?.writeText(this.term.getSelection());
      this.term.clearSelection();
      ev.preventDefault();
      return false;
    }
    // Ctrl+V and Ctrl+Shift+V: let the browser paste; xterm.js picks up the paste event.
    if (ev.ctrlKey && !ev.altKey && key === "v") return false;
    // QL-05: Ctrl+Shift+F searches the scrollback.
    if (ev.ctrlKey && ev.shiftKey && !ev.altKey && key === "f") {
      ev.preventDefault();
      this.openSearch();
      return false;
    }
    return true;
  }

  /**
   * BX-08: a command pasted as if typed, through xterm.js (bracketed when the shell asked for it, so the shell waits
   * for Enter even when the command has several lines). See `sendCommand` in command-send.ts.
   */
  pasteCommand(command: string) {
    this.term.paste(command);
  }

  /** BX-08 Shift+click: runs what was pasted. */
  pressEnter() {
    this.send(encoder.encode("\r"));
  }

  /**
   * QL-06: the core types a vault password or passphrase into this terminal, then Enter, if it shows a password
   * prompt (or `force`). The value never comes here.
   */
  async typeSecret(secretId: string, force: boolean) {
    if (!this.coreId) throw new Error("This terminal has not connected yet.");
    await api.terminalTypeSecret(this.coreId, secretId, force);
    this.focus();
  }

  /**
   * QL-05 right-click paste. The shell reads the clipboard: the browser's clipboard API would make WebView2 ask
   * for permission, and fail while the window is not focused.
   */
  async pasteFromClipboard() {
    try {
      const text = await api.clipboardReadText();
      if (text) this.term.paste(text);
    } catch {
      this.term.write("\r\n\x1b[2m[Paste with Ctrl+V]\x1b[0m\r\n");
    }
  }

  // ---- QL-05 search ----

  openSearch() {
    this.update({ searching: true });
  }

  closeSearch() {
    this.searchAddon.clearDecorations();
    this.update({ searching: false, searchResults: null });
    this.focus();
  }

  /** Finds the next (or previous) match; false when there is none. */
  find(text: string, backwards: boolean, options: { caseSensitive: boolean; regex: boolean }) {
    if (!text) {
      this.searchAddon.clearDecorations();
      this.update({ searchResults: null });
      return false;
    }
    const search = { ...options, decorations: SEARCH_DECORATIONS };
    return backwards ? this.searchAddon.findPrevious(text, search) : this.searchAddon.findNext(text, search);
  }

  // ---- SS-11 output ----

  /** The whole buffer (scrollback and screen) as text: wrapped lines joined, trailing blank lines dropped. */
  bufferText(): string {
    const buffer = this.term.buffer.active;
    const lines: string[] = [];
    let current: string | null = null;
    for (let i = 0; i < buffer.length; i++) {
      const line = buffer.getLine(i);
      if (!line) continue;
      const text = line.translateToString(false);
      if (line.isWrapped && current !== null) current += text;
      else {
        if (current !== null) lines.push(current.trimEnd());
        current = text;
      }
    }
    if (current !== null) lines.push(current.trimEnd());
    while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    return lines.join("\n");
  }

  /** SS-11: asks the core for a log file and starts logging; null when the user cancelled. */
  async startLog(title: string) {
    if (!this.coreId) throw new Error("This terminal has not connected yet.");
    const path = await api.terminalLogStart(this.coreId, title);
    if (path) this.update({ logPath: path });
    return path;
  }

  async stopLog() {
    if (!this.coreId) return;
    await api.terminalLogStop(this.coreId);
    this.update({ logPath: null });
  }

  // ---- view ----

  setTheme(theme: ResolvedTheme) {
    this.term.options.theme = TERMINAL_PALETTE[theme];
  }

  /** QL-05: font size, scrollback and copy-on-select, applied to an open pane. */
  setOptions(options: PaneOptions) {
    this.copyOnSelect = options.copyOnSelect;
    if (this.term.options.fontSize !== options.fontSize) this.term.options.fontSize = options.fontSize;
    if (this.term.options.scrollback !== options.scrollback) this.term.options.scrollback = options.scrollback;
    this.fit();
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
