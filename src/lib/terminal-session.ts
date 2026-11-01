// One terminal pane (SS-03): an xterm.js instance and its SSH connection in the core. It lives outside
// React's tree so splitting a pane (which reshapes the layout) never remounts, and so never drops, a
// connection: the pane's view attaches `element` wherever the layout puts it.
//
// Bytes stay bytes: keystrokes go to the core as raw UTF-8, output comes back as raw bytes that xterm.js
// decodes itself. Writes are sent one at a time, in order, with whatever was typed meanwhile batched.
//
// A pane opens a saved session, a quick connection from the New terminal form (QL-02) or another
// connection like an open pane (a split). QL-05: search (Ctrl+Shift+F), Ctrl+Shift+C / Ctrl+Shift+V,
// right-click paste, and the font size, scrollback, copy-on-select and multi-line paste settings, applied live. Every
// paste (Ctrl+V and Ctrl+Shift+V, caught before xterm.js sees them, right-click, the menu, the command panel) is
// cleaned by paste.ts first, and one with a line break asks the page (`onPasteConfirm`) unless the setting is off.
// QL-05: every copy of a selection goes through the core, which scrubs this terminal's secrets from it, and the shell
// writes the clipboard (kept out of Windows' clipboard history and cloud clipboard); never the browser's clipboard API.
// SS-11: the whole buffer as text, and logging to a file. BX-08: a command from the command panel is pasted as if
// typed; QL-06: a vault password is typed by the core, which never hands it to the UI; QL-07: the core reports a long
// command that finished, and the page decides whether to notify. SS-10: with MultiExec on, a picked pane's input
// (keys, pastes, mouse reports) goes to `inputRouter` instead (see multiexec.ts); xterm.js's replies to the host's
// queries go to this pane's own connection only (terminal-input.ts tells them apart). OSC 8 links from the host are
// never opened: a click hands the address to `onLink` (the page shows it, to copy). SS-08: the core says which
// folder the shell is in (`folder`), and a right-click on a file name in the output goes to `onFileWord` (the page
// offers to download it) instead of pasting.
// SS-07: the core reports the session's tunnels (`tunnels`); one that waits for approval (e.g. one that starts with
// a Prod session's terminal) goes to `onTunnelAsking`, so the page can show the dialog. Host key questions name the
// jump host that asks.
//
// SS-03 rendering: a pane on screen draws with WebGL (@xterm/addon-webgl), which keeps the DOM small and the main
// thread free while a host prints a lot. A pane that is hidden (another tab, another page) gives its WebGL context back
// after WEBGL_RELEASE_MS and draws with xterm.js's DOM renderer, so dozens of panes never run into the browser's limit
// of about 16 contexts; so does a pane whose WebGL failed too often, or every pane when WebGL can't start in this
// window (terminal-render.ts has the limits).
//
// FD-03: while presenting, the pane shows a second, masked terminal in front of the real one. Output goes to both:
// as it is to the real one, through presentation.ts's TerminalMasker to the masked one, whose stand-ins keep the
// width of what they replace, so both hold the same cells in the same places. Keys, pastes and the host's queries
// are answered by the one on screen; copies (selection, Ctrl+Shift+C, copy-on-select), the whole-buffer text that
// SS-11 saves and prints, and the file name under a right-click are read from the real one at the same place. The
// masked one keeps less scrollback (MASKED_SCROLLBACK lines, so search while presenting looks only that far back). It
// starts from the real one's screen and the end of its scrollback, serialized, then masked and written in pieces cut at
// line breaks, one at a time, so a long scrollback never holds the page up; output that arrives meanwhile waits and
// follows in order. It is dropped when presenting stops. Nothing changes in what is sent to the host.
//
// QL-17: each terminal (the real one, and the masked one while presenting) has its own highlighter
// (terminal-highlights.ts), which colours what the pane's rules match in its own text: the masked one never lights up
// a stand-in for a host a rule names. The page gives the pane the rules for its scope (`setHighlightRules`); the
// core's alerts arrive as events (`onAlert`), one per burst of matching lines.

import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { SerializeAddon } from "@xterm/addon-serialize";
import { toast } from "sonner";
import { latestOnly } from "@/lib/clipboard-copy";
import { forgetTerminal, reportTunnels } from "@/lib/open-tunnels";
import { WebglAddon } from "@xterm/addon-webgl";
import { masker, TerminalMasker } from "@/lib/presentation";
import { presentationView, subscribePresentation } from "@/lib/presentation-state";
import { withVaultPassword } from "@/lib/reauth-prompt";
import {
  api,
  errorCode,
  errorMessage,
  type ApprovalAnswers,
  type EngineKind,
  type FinishedHow,
  type FolderInfo,
  type HostFacts,
  type HostKey,
  type KnownHost,
  type QuickConnectRequest,
  type SessionRecord,
  type TerminalAlert,
  type TerminalEvent,
  type TerminalRule,
  type TerminalStatus,
  type TunnelInfo,
  type TunnelStart,
} from "@/lib/api";
import { compileRules, rulesKey, type CompiledRule } from "@/lib/highlight-rules";
import { pasteHasLineBreak, pastePreview, sanitizePaste, type PastePreview } from "@/lib/paste";
import { Highlighter } from "@/lib/terminal-highlights";
import { InputOrigin } from "@/lib/terminal-input";
import type { ResolvedTheme } from "@/lib/theme";
import {
  MASK_CHUNK_CHARS,
  maskedScrollback,
  splitAtLineBreaks,
  WEBGL_RELEASE_MS,
  wantsWebgl,
} from "@/lib/terminal-render";
import { fileWordAt } from "@/lib/transfers";
import type { IDisposable } from "@xterm/xterm";
import type { LineHit, PaneHits } from "@/lib/scrollback-search";
import { endScan, revealHit, scanTerminal, type ScrollbackScan } from "@/lib/scrollback-xterm";

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
  | { kind: "like"; terminalId: string }
  /** CT-01: a shell in a running container on a session's host (`docker exec -it`), audited like a terminal. */
  | { kind: "container"; sessionId: string; engine: EngineKind; containerId: string };

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
  /** SS-11: why the session log stopped by itself (it could not be written), until dismissed. */
  logError: string | null;
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
  /** Ask (`onPasteConfirm`) before a paste that holds a line break. */
  confirmMultilinePaste: boolean;
}

export const DEFAULT_PANE_OPTIONS: PaneOptions = {
  fontSize: 13,
  scrollback: 10000,
  copyOnSelect: true,
  confirmMultilinePaste: true,
};

/** QL-05: a paste with a line break, for the page to confirm. */
export interface PasteAsk {
  preview: PastePreview;
  /** The shell asked for bracketed paste (it holds pasted text until Enter). */
  bracketed: boolean;
}

/** QL-07: a command that ran long has ended in this pane. */
export interface CommandFinished {
  afterSecs: number;
  how: FinishedHow;
}

const encoder = new TextEncoder();

/**
 * QL-05: one clipboard, so one queue for every pane's copies (the last selection ends up on it). A failure shows
 * the reason, never the text.
 */
const copySelectionText = latestOnly<{ id: string | null; text: string }>(
  ({ id, text }) => api.terminalCopySelection(id, text),
  (err) => toast.error(`Copy failed: ${errorMessage(err)}`, { id: "terminal-copy" }),
);

/** FD-03: how long the masked terminal waits for the rest of a value split across reads. */
const MASK_HOLD_MS = 25;

/** SS-03: the panes holding a WebGL context now. */
const webglPanes = new Set<PaneSession>();
/** SS-03: WebGL could not start in this window at all (no WebGL 2): every pane draws with the DOM renderer. */
let webglUnavailable = false;
/** SS-03: how long after a lost WebGL context a pane on screen tries again. */
const WEBGL_RETRY_MS = 1000;

/** FD-03: the masked terminal on screen while presenting. */
interface MaskedView {
  term: Terminal;
  host: HTMLDivElement;
  fit: FitAddon;
  search: SearchAddon;
  mask: TerminalMasker;
  decoder: TextDecoder;
  timer: number | null;
  /** The real terminal's screen has been copied in; output before that waits in `queue`. */
  ready: boolean;
  queue: string[];
  /** QL-17: matches the masked text. */
  highlighter: Highlighter;
}

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
  /** The real terminal: everything the host sent, as it sent it. While presenting, a masked one is on screen. */
  private readonly term: Terminal;
  private readonly realHost: HTMLDivElement;
  /** How the pane is named before the core says more: the session's or the typed address. */
  readonly label: string;
  /** CT-01: the label stays the title (a container's shell is named after the container, not the session). */
  readonly fixedTitle: boolean;
  private readonly fitAddon: FitAddon;
  private readonly searchAddon: SearchAddon;
  private readonly serializer: SerializeAddon;
  private masked: MaskedView | null = null;
  /** SS-03: the WebGL renderer on the terminal on screen, while the pane shows. */
  private webgl: { term: Terminal; addon: WebglAddon } | null = null;
  private webglFailures = 0;
  private webglTimer: number | null = null;
  /** SS-03: the pane is on screen (laid out and in view), as its IntersectionObserver last said. */
  private visible = false;
  private readonly visibility: IntersectionObserver | null;
  private readonly stopFollowing: () => void;
  private theme: ResolvedTheme;
  private opener: PaneOpener | null;
  private coreId: string | null = null;
  private started = false;
  private closed = false;
  private snapshot: PaneSnapshot;
  private readonly listeners = new Set<() => void>();
  private pending: Uint8Array[] = [];
  private writing = false;
  /** SS-10: each terminal's input told from its replies (the real one, and the masked one while presenting). */
  private readonly origins = new WeakMap<Terminal, InputOrigin>();
  copyOnSelect = true;
  /** QL-05: a paste with a line break asks first. */
  confirmMultilinePaste = true;
  /**
   * QL-05: asks the user about a paste with a line break; resolves true to paste. Without it, such a paste goes
   * without asking.
   */
  onPasteConfirm: ((pane: PaneSession, ask: PasteAsk) => Promise<boolean>) | null = null;
  /** An OSC 8 link from the host was clicked: the page shows its address (to copy). Nothing opens it. */
  onLink: ((uri: string) => void) | null = null;
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
  /** QL-17: an alert rule matched here (the core sends one per burst of matching lines). */
  onAlert: ((alert: TerminalAlert) => void) | null = null;
  /** QL-17: the real terminal's highlighter. */
  private readonly highlighter: Highlighter;
  /** QL-17: the pane's highlight rules, compiled, and what they were compiled from. */
  private highlightRules: CompiledRule[] = [];
  private highlightKey = "";
  /** QL-17: the terminals whose highlighting paused (too much output), and the note that says so. */
  private readonly highlightPaused = new Set<Terminal>();
  private pauseNote: HTMLDivElement | null = null;

  constructor(
    key: string,
    opener: PaneOpener,
    label: string,
    theme: ResolvedTheme,
    options: PaneOptions,
    fixedTitle = false,
  ) {
    this.key = key;
    this.opener = opener;
    this.theme = theme;
    this.label = label;
    this.fixedTitle = fixedTitle;
    this.snapshot = {
      status: { state: "opening" },
      statusAt: Date.now(),
      question: null,
      changedKey: null,
      facts: null,
      sessionId: opener.kind === "session" || opener.kind === "container" ? opener.sessionId : null,
      logPath: null,
      logError: null,
      searching: false,
      searchResults: null,
      folder: null,
      tunnels: null,
    };
    this.element = document.createElement("div");
    this.element.className = "relative h-full w-full";
    // FD-03: the page's masker leaves terminals alone; this pane masks its own output.
    this.element.setAttribute("data-presentation-skip", "");
    this.realHost = document.createElement("div");
    this.realHost.className = "absolute inset-0";
    this.element.appendChild(this.realHost);
    this.copyOnSelect = options.copyOnSelect;
    this.confirmMultilinePaste = options.confirmMultilinePaste;
    this.term = this.newTerminal(theme, options);
    this.fitAddon = new FitAddon();
    this.term.loadAddon(this.fitAddon);
    this.searchAddon = this.newSearch(this.term);
    this.serializer = new SerializeAddon();
    this.term.loadAddon(this.serializer);
    this.term.open(this.realHost);
    this.wire(this.term);
    this.highlighter = this.newHighlighter(this.term, theme);
    // SS-03: WebGL while the pane is on screen; hidden (another tab or page, detached), the DOM renderer.
    this.visibility =
      typeof IntersectionObserver === "undefined"
        ? null
        : new IntersectionObserver((entries) => {
            const last = entries[entries.length - 1];
            if (last) this.setVisible(last.isIntersecting && this.element.isConnected);
          });
    this.visibility?.observe(this.element);
    // QL-05: right-click pastes, like PuTTY; SS-08: on a file name, the page may offer to download it first.
    this.element.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      const word = this.onFileWord && this.connected ? this.wordAt(ev.clientX, ev.clientY) : null;
      if (word && this.onFileWord) this.onFileWord(word, ev.clientX, ev.clientY);
      else void this.pasteFromClipboard();
    });
    // QL-05: a copy the browser starts itself (Ctrl+Insert) would put xterm.js's selection on the clipboard as it is;
    // caught before it reaches xterm.js, it goes through the core like every other copy.
    this.element.addEventListener(
      "copy",
      (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        this.copySelection();
      },
      true,
    );
    // QL-05: Ctrl+V, Ctrl+Shift+V and any other paste the browser makes, caught on the way down (capture), before
    // xterm.js's own handler would send the text as it is.
    this.element.addEventListener(
      "paste",
      (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        void this.paste(ev.clipboardData?.getData("text/plain") ?? "");
      },
      true,
    );
    // FD-03: masked from its first output when the app is presenting, and from the moment it starts.
    this.stopFollowing = subscribePresentation(() => this.present(presentationView().presenting));
    this.present(presentationView().presenting);
  }

  private newTerminal(theme: ResolvedTheme, options: PaneOptions) {
    return new Terminal({
      fontFamily: MONO,
      fontSize: options.fontSize,
      cursorBlink: true,
      scrollback: options.scrollback,
      theme: TERMINAL_PALETTE[theme],
      // The search addon's match highlights use the decorations API.
      allowProposedApi: true,
      // OSC 8 hyperlinks come from the host, which can put any address behind any text: never opened. Only http(s)
      // ones are links at all (xterm.js drops the rest); a click hands the address to the page to show and copy.
      linkHandler: {
        activate: (_event, uri) => this.onLink?.(uri),
        allowNonHttpProtocols: false,
      },
    });
  }

  private newSearch(term: Terminal) {
    const search = new SearchAddon({ highlightLimit: 2000 });
    term.loadAddon(search);
    search.onDidChangeResults(({ resultIndex, resultCount }) => {
      if (term === this.screen) this.update({ searchResults: { index: resultIndex, count: resultCount } });
    });
    return search;
  }

  /**
   * Keys, pastes, the host's queries and size changes come from the terminal on screen only. SS-10: input goes
   * through `send` (MultiExec, when it has this pane); xterm.js's replies to the host go to this pane alone.
   */
  private wire(term: Terminal) {
    const origin = new InputOrigin(term);
    this.origins.set(term, origin);
    term.onData((data) => {
      // Asked for every event, in order, so a mark never outlives its own data.
      const input = origin.isInput(data);
      if (term !== this.screen) return;
      if (input) this.send(encoder.encode(data));
      else this.reply(encoder.encode(data));
    });
    // Binary data (mouse reports in the default encoding) is one byte per character: input, like other mouse reports.
    term.onBinary((data) => {
      if (term === this.screen) this.send(Uint8Array.from(data, (c) => c.charCodeAt(0) & 0xff));
    });
    term.onResize(({ cols, rows }) => {
      if (term !== this.screen) return;
      // The real terminal keeps the same size, so both hold the same cells.
      if (term !== this.term) this.term.resize(cols, rows);
      if (this.coreId) void api.terminalResize(this.coreId, cols, rows);
    });
    // SS-03 copy-on-select, like PuTTY (FD-03: the real text, even while presenting).
    term.onSelectionChange(() => {
      if (term === this.screen && this.copyOnSelect && term.hasSelection()) this.copySelection();
    });
    term.attachCustomKeyEventHandler((ev) => this.handleKey(ev));
  }

  /** The terminal on screen: the masked one while presenting, otherwise the real one. */
  private get screen(): Terminal {
    return this.masked?.term ?? this.term;
  }

  // ---- SS-03 rendering ----

  private setVisible(visible: boolean) {
    this.visible = visible;
    this.syncRenderer();
  }

  /**
   * WebGL on the terminal on screen while the pane shows; a hidden pane gives its context back after a moment (a quick
   * tab switch keeps it). A terminal that is no longer on screen (presenting started or stopped) gives it back at once.
   */
  private syncRenderer() {
    const screen = this.closed ? null : this.screen;
    if (this.webgl && this.webgl.term !== screen) this.dropWebgl();
    if (!screen) return;
    if (!this.visible) {
      if (this.webgl && this.webglTimer === null)
        this.webglTimer = window.setTimeout(() => {
          this.webglTimer = null;
          if (!this.visible) this.dropWebgl();
        }, WEBGL_RELEASE_MS);
      return;
    }
    this.clearWebglTimer();
    if (this.webgl) return;
    const check = {
      visible: true,
      failures: this.webglFailures,
      unavailable: webglUnavailable,
      others: webglPanes.size,
    };
    if (!wantsWebgl(check)) return;
    let addon: WebglAddon | null = null;
    try {
      addon = new WebglAddon();
      screen.loadAddon(addon);
    } catch (err) {
      // No WebGL 2 here, or no context to be had: the DOM renderer draws. With no other pane on WebGL, none will be.
      this.webglFailures += 1;
      if (webglPanes.size === 0) webglUnavailable = true;
      try {
        addon?.dispose();
      } catch {
        // It never started.
      }
      console.warn("WebGL renderer unavailable; drawing the terminal with the DOM renderer", err);
      return;
    }
    const held = { term: screen, addon };
    this.webgl = held;
    webglPanes.add(this);
    addon.onContextLoss(() => {
      if (this.webgl !== held) return;
      // The GPU process restarted or the browser took the context back: the DOM renderer draws, and a pane still on
      // screen tries again in a moment, until it failed too often.
      this.webglFailures += 1;
      this.dropWebgl();
      this.webglTimer = window.setTimeout(() => {
        this.webglTimer = null;
        this.syncRenderer();
      }, WEBGL_RETRY_MS);
    });
  }

  /** Back to xterm.js's DOM renderer (disposing the addon puts it back). */
  private dropWebgl() {
    this.clearWebglTimer();
    const held = this.webgl;
    if (!held) return;
    this.webgl = null;
    webglPanes.delete(this);
    try {
      held.addon.dispose();
    } catch {
      // Its terminal was disposed first.
    }
  }

  private clearWebglTimer() {
    if (this.webglTimer === null) return;
    window.clearTimeout(this.webglTimer);
    this.webglTimer = null;
  }

  // ---- FD-03 presentation mode ----

  private present(on: boolean) {
    if (on && !this.masked && !this.closed) this.showMasked();
    else if (!on && this.masked) this.showReal();
  }

  private showMasked() {
    const hadFocus = this.realHost.contains(document.activeElement);
    // Hidden at once, before the next paint; the masked copy shows once it holds the real one's screen.
    this.realHost.style.visibility = "hidden";
    const host = document.createElement("div");
    host.className = "absolute inset-0";
    // Shown once it holds the real screen, so it never scrolls through the copied scrollback on screen.
    host.style.visibility = "hidden";
    this.element.appendChild(host);
    const scrollback = maskedScrollback(this.term.options.scrollback ?? DEFAULT_PANE_OPTIONS.scrollback);
    const term = this.newTerminal(this.theme, {
      fontSize: this.term.options.fontSize ?? DEFAULT_PANE_OPTIONS.fontSize,
      scrollback,
      copyOnSelect: this.copyOnSelect,
      confirmMultilinePaste: this.confirmMultilinePaste,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    term.resize(this.term.cols, this.term.rows);
    this.wire(term);
    // QL-17: its own matches, on the masked text, from its first line.
    const highlighter = this.newHighlighter(term, this.theme);
    highlighter.setRules(this.highlightRules);
    const view: MaskedView = {
      term,
      host,
      fit,
      search: this.newSearch(term),
      mask: new TerminalMasker(masker),
      decoder: new TextDecoder(),
      timer: null,
      ready: false,
      queue: [],
      highlighter,
    };
    this.masked = view;
    this.searchAddon.clearDecorations();
    this.syncRenderer();
    // Once the real terminal has parsed what it was given so far, its screen and the end of its scrollback start the
    // copy: masked and written a piece at a time, each once the one before was parsed and in a task of its own, so
    // the page stays responsive. Output that arrived meanwhile follows in order.
    this.term.write("", () => {
      if (this.masked !== view) return;
      const pieces = splitAtLineBreaks(this.serializer.serialize({ scrollback }), MASK_CHUNK_CHARS);
      const next = () => {
        if (this.masked !== view) return;
        const piece = pieces.shift();
        if (piece !== undefined) {
          term.write(view.mask.mask(piece), () => window.setTimeout(next, 0));
          return;
        }
        view.ready = true;
        for (const chunk of view.queue) term.write(chunk);
        view.queue = [];
        host.style.visibility = "";
        if (hadFocus) term.focus();
      };
      next();
    });
  }

  private showReal() {
    const view = this.masked;
    if (!view) return;
    this.masked = null;
    if (view.timer !== null) window.clearTimeout(view.timer);
    const hadFocus = view.host.contains(document.activeElement);
    // SS-03: its WebGL context goes with it; the real terminal gets one if the pane shows.
    if (this.webgl?.term === view.term) this.dropWebgl();
    view.highlighter.dispose();
    view.term.dispose();
    view.host.remove();
    this.realHost.style.visibility = "";
    this.syncRenderer();
    this.fit();
    this.term.refresh(0, this.term.rows - 1);
    if (this.snapshot.searching) this.update({ searchResults: null });
    if (hadFocus) this.term.focus();
  }

  /** Output for the masked terminal: decoded, masked, and the last word held a moment for the rest of a value. */
  private showMaskedOutput(data: Uint8Array | string) {
    const view = this.masked;
    if (!view) return;
    const text = typeof data === "string" ? data : view.decoder.decode(data, { stream: true });
    this.writeMasked(view, view.mask.push(text));
    if (view.timer !== null) window.clearTimeout(view.timer);
    view.timer = view.mask.holding
      ? window.setTimeout(() => {
          view.timer = null;
          if (this.masked === view) this.writeMasked(view, view.mask.flush());
        }, MASK_HOLD_MS)
      : null;
  }

  private writeMasked(view: MaskedView, text: string) {
    if (!text) return;
    if (view.ready) view.term.write(text);
    else view.queue.push(text);
  }

  /** A line of the app's own (a connection error, a paste hint), shown in both terminals. */
  private say(text: string) {
    this.term.write(text);
    this.showMaskedOutput(text);
  }

  /**
   * The real text of what is selected on screen. Both terminals hold the same cells, counted from the bottom (the
   * masked one keeps less scrollback: MASKED_SCROLLBACK lines at most).
   */
  private selectionText(): string {
    const view = this.masked;
    if (!view) return this.term.getSelection();
    const at = view.term.getSelectionPosition();
    if (!at) return "";
    const offset = this.term.buffer.active.length - view.term.buffer.active.length;
    const length = (at.end.y - at.start.y) * this.term.cols + (at.end.x - at.start.x);
    if (length <= 0) return "";
    this.term.select(at.start.x, at.start.y + offset, length);
    const text = this.term.getSelection();
    this.term.clearSelection();
    return text;
  }

  /**
   * QL-05: what is selected on screen to the clipboard: through the core, which scrubs this terminal's secrets from
   * it (FD-03: the real text, even while presenting), and the shell, which writes the clipboard.
   */
  private copySelection() {
    if (!this.screen.hasSelection()) return;
    const text = this.selectionText();
    if (text) copySelectionText({ id: this.coreId, text });
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
        // QL-21, QL-22: the status bar and the map follow every terminal's tunnels.
        if (this.coreId) reportTunnels(this.coreId, event.tunnels);
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
      case "logStopped":
        this.update({
          logPath: null,
          logError: `The session log stopped: it could not be written to ${event.path} (${event.reason}).`,
        });
        break;
      case "alert":
        this.onAlert?.(event.alert);
        break;
    }
  };

  private onOutput = (data: Uint8Array) => {
    this.term.write(data);
    this.showMaskedOutput(data);
  };

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
        // SS-04, AP-06: a vault password for a host where no saved session sends it yet asks for the vault password.
        const opened = await withVaultPassword((vaultPassword) =>
          api.terminalQuickConnect({ ...opener.request, vaultPassword }, cols, rows, this.onOutput, this.onEvent),
        );
        id = opened.id;
        // A saved quick connection is a session from now on: reconnects and splits follow it.
        this.opener = opened.session ? { kind: "session", sessionId: opened.session.id } : null;
        if (opened.session) this.update({ sessionId: opened.session.id });
      } else if (opener.kind === "container") {
        const opened = await api.containerShellOpen(
          opener.sessionId,
          opener.engine,
          opener.containerId,
          cols,
          rows,
          this.onOutput,
          this.onEvent,
        );
        id = opened.id;
      } else {
        id = await api.terminalOpenLike(opener.terminalId, cols, rows, this.onOutput, this.onEvent);
        this.opener = null;
      }
      if (this.closed) {
        void api.terminalClose(id);
        return;
      }
      this.coreId = id;
      if (this.snapshot.tunnels) reportTunnels(id, this.snapshot.tunnels);
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
      this.say(`\r\n\x1b[31m[Not connected: ${message}]\x1b[0m\r\n`);
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
    if (this.coreId) {
      forgetTerminal(this.coreId);
      void api.terminalClose(this.coreId);
    }
    this.stopFollowing();
    this.showReal();
    this.visibility?.disconnect();
    this.dropWebgl();
    this.highlighter.dispose();
    this.term.dispose();
    this.listeners.clear();
    this.onCommandFinished = null;
    this.onAlert = null;
    this.onFileWord = null;
    this.onTunnelAsking = null;
    this.onPasteConfirm = null;
    this.onLink = null;
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
    const screen = (this.masked?.host ?? this.realHost).querySelector(".xterm-screen");
    if (!screen) return null;
    const rect = screen.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return null;
    const shown = this.screen;
    const col = Math.floor(((clientX - rect.left) / rect.width) * shown.cols);
    const row = Math.floor(((clientY - rect.top) / rect.height) * shown.rows);
    if (col < 0 || row < 0 || col >= shown.cols || row >= shown.rows) return null;
    // FD-03: the real file name, under the masked one while presenting.
    const buffer = this.term.buffer.active;
    const offset = buffer.length - shown.buffer.active.length;
    const line = buffer.getLine(shown.buffer.active.viewportY + row + offset);
    return line ? fileWordAt(line.translateToString(false), col) : null;
  }

  // ---- input ----

  /** The user's input: keys, pastes, mouse reports. */
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

  /**
   * SS-10: xterm.js's reply to the host's query (cursor position, device attributes, colours, focus): to this pane's
   * own connection only, never through MultiExec. The core still counts it as text MultiExec did not see on the line.
   */
  private reply(bytes: Uint8Array) {
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
    const shown = this.screen;
    if (ev.ctrlKey && !ev.altKey && key === "c" && (ev.shiftKey || shown.hasSelection())) {
      this.copySelection();
      shown.clearSelection();
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
   * for Enter even when the command has several lines). See `sendCommand` in command-send.ts. Cleaned like any paste
   * (QL-05), but never asked about: the panel shows the command it pastes.
   */
  pasteCommand(command: string) {
    const clean = sanitizePaste(command);
    if (clean) this.pasteText(clean);
  }

  /**
   * QL-05: a paste from the clipboard (keys, right-click, the menu): cleaned (paste.ts), and asked about first when
   * it holds a line break, unless the setting is off. FD-06: `alwaysAsk` (a note's code block) asks whatever the
   * setting, and a paste with a line break and nobody to ask is not made.
   */
  async paste(text: string, { alwaysAsk = false }: { alwaysAsk?: boolean } = {}) {
    const clean = sanitizePaste(text);
    if (!clean || this.closed) return;
    if (alwaysAsk && !this.onPasteConfirm && pasteHasLineBreak(clean)) return;
    if ((this.confirmMultilinePaste || alwaysAsk) && this.onPasteConfirm && pasteHasLineBreak(clean)) {
      const ask = { preview: pastePreview(clean), bracketed: this.screen.modes.bracketedPasteMode };
      const ok = await this.onPasteConfirm(this, ask);
      if (!ok || this.closed) return;
      this.pasteText(clean);
      this.focus();
      return;
    }
    this.pasteText(clean);
  }

  /**
   * Into the terminal on screen, as the user's input: xterm.js turns each CRLF or LF into CR and brackets the text
   * when the shell asked for bracketed paste.
   */
  private pasteText(text: string) {
    const term = this.screen;
    this.origins.get(term)?.mark();
    term.paste(text);
  }

  /** BX-08 Shift+click: runs what was pasted. */
  pressEnter() {
    this.send(encoder.encode("\r"));
  }

  /**
   * QL-06: the core types a vault password or passphrase into this terminal, then Enter, if it shows a password
   * prompt (or `force`). The value never comes here. SS-04, AP-06: `vaultPassword` when the core asked for it.
   */
  async typeSecret(secretId: string, force: boolean, vaultPassword?: string) {
    if (!this.coreId) throw new Error("This terminal has not connected yet.");
    await api.terminalTypeSecret(this.coreId, secretId, force, vaultPassword);
    this.focus();
  }

  /**
   * QL-05 right-click paste. The shell reads the clipboard: the browser's clipboard API would make WebView2 ask
   * for permission, and fail while the window is not focused.
   */
  async pasteFromClipboard() {
    let text: string | null;
    try {
      text = await api.clipboardReadText();
    } catch {
      this.say("\r\n\x1b[2m[Paste with Ctrl+V]\x1b[0m\r\n");
      return;
    }
    if (text) await this.paste(text);
  }

  // ---- QL-05 search ----

  openSearch() {
    this.update({ searching: true });
  }

  closeSearch() {
    this.searchAddon.clearDecorations();
    this.masked?.search.clearDecorations();
    this.update({ searching: false, searchResults: null });
    this.focus();
  }

  // ---- QL-18 search all terminals (scrollback-xterm.ts) ----

  private scan: ScrollbackScan | null = null;
  private revealed: IDisposable[] = [];

  /** The matches in this pane's buffer, read once: the terminal on screen (FD-03: the masked one while presenting). */
  scanScrollback(pattern: RegExp): PaneHits {
    this.endScrollbackSearch();
    if (this.closed) return { hits: [], capped: false, longLines: 0 };
    this.scan = scanTerminal(this.screen, pattern);
    return this.scan.hits;
  }

  /** Scrolls to a match of the last scan and highlights it; why it can't, as a message. */
  revealMatch(hit: LineHit): string | null {
    this.clearReveal();
    if (!this.scan || this.closed) return "Search again: this terminal was not searched";
    const shown = revealHit(this.screen, this.scan, hit);
    if (typeof shown === "string") return shown;
    this.revealed = shown;
    return null;
  }

  /** Takes the highlight of a match off. */
  clearReveal() {
    for (const d of this.revealed) d.dispose();
    this.revealed = [];
  }

  /** The search panel closed. */
  endScrollbackSearch() {
    this.clearReveal();
    endScan(this.scan);
    this.scan = null;
  }

  /** Finds the next (or previous) match; false when there is none. */
  find(text: string, backwards: boolean, options: { caseSensitive: boolean; regex: boolean }) {
    const searchAddon = this.masked?.search ?? this.searchAddon;
    if (!text) {
      searchAddon.clearDecorations();
      this.update({ searchResults: null });
      return false;
    }
    const search = { ...options, decorations: SEARCH_DECORATIONS };
    return backwards ? searchAddon.findPrevious(text, search) : searchAddon.findNext(text, search);
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
    if (path) this.update({ logPath: path, logError: null });
    return path;
  }

  async stopLog() {
    if (!this.coreId) return;
    await api.terminalLogStop(this.coreId);
    this.update({ logPath: null });
  }

  /** SS-11: the notice that the log stopped by itself goes. */
  dismissLogError() {
    this.update({ logError: null });
  }

  // ---- view ----

  setTheme(theme: ResolvedTheme) {
    this.theme = theme;
    this.term.options.theme = TERMINAL_PALETTE[theme];
    this.highlighter.setTheme(theme);
    if (this.masked) {
      this.masked.term.options.theme = TERMINAL_PALETTE[theme];
      this.masked.highlighter.setTheme(theme);
    }
  }

  // ---- QL-17 highlights ----

  private newHighlighter(term: Terminal, theme: ResolvedTheme) {
    return new Highlighter(term, theme, (paused) => {
      if (paused) this.highlightPaused.add(term);
      else this.highlightPaused.delete(term);
      this.showPauseNote();
    });
  }

  /**
   * The rules that highlight in this pane (the page picks them for its scope). The same rules again change nothing;
   * new ones replace what was painted and match the lines near the cursor again, never the whole scrollback.
   */
  setHighlightRules(rules: TerminalRule[]) {
    const key = rulesKey(rules);
    if (key === this.highlightKey || this.closed) return;
    this.highlightKey = key;
    this.highlightRules = compileRules(rules);
    this.highlighter.setRules(this.highlightRules);
    this.masked?.highlighter.setRules(this.highlightRules);
  }

  /** A small note while highlighting is paused in this pane (too much output), so missing colours are explained. */
  private showPauseNote() {
    const paused = this.highlightPaused.size > 0 && !this.closed;
    if (!paused) {
      this.pauseNote?.remove();
      this.pauseNote = null;
      return;
    }
    if (this.pauseNote) return;
    const note = document.createElement("div");
    note.className =
      "pointer-events-none absolute top-1 right-3 z-10 rounded-md border bg-popover/90 px-2 py-0.5 text-xs text-muted-foreground shadow-sm";
    note.setAttribute("role", "status");
    note.textContent = "Highlighting paused: a lot of output";
    this.element.appendChild(note);
    this.pauseNote = note;
  }

  /** QL-05: font size, scrollback, copy-on-select and the paste question, applied to an open pane. */
  setOptions(options: PaneOptions) {
    this.copyOnSelect = options.copyOnSelect;
    this.confirmMultilinePaste = options.confirmMultilinePaste;
    for (const term of [this.term, this.masked?.term]) {
      if (!term) continue;
      if (term.options.fontSize !== options.fontSize) term.options.fontSize = options.fontSize;
      // FD-03: the masked copy keeps less scrollback than the setting.
      const scrollback = term === this.term ? options.scrollback : maskedScrollback(options.scrollback);
      if (term.options.scrollback !== scrollback) term.options.scrollback = scrollback;
    }
    this.fit();
  }

  fit() {
    if (this.element.offsetWidth > 0 && this.element.offsetHeight > 0) {
      try {
        // FD-03: the terminal on screen fits the pane; the real one follows its size (see `wire`).
        (this.masked?.fit ?? this.fitAddon).fit();
      } catch {
        // Not laid out yet.
      }
    }
  }

  focus() {
    this.screen.focus();
  }

  /** Redraws the terminal on screen (after the page moved its element). */
  refresh() {
    this.screen.refresh(0, this.screen.rows - 1);
  }
}
