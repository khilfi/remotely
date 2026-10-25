// SS-10: what a terminal's `onData` carries is either input (keys, IME text, pastes, mouse reports and wheel
// scrolling) or a reply xterm.js makes by itself to a query from the host: a cursor position report (DSR/CPR
// ESC[6n), device attributes (DA, DA2), colour queries (OSC 4, 10, 11, 12), mode reports (DECRQM), settings
// (DECRQSS), window reports (CSI t) and focus reports (ESC[I, ESC[O). Only input goes through MultiExec; a reply goes
// to the pane that was asked, and nowhere else, so one host's query never makes Remotely type its answer into every
// MultiExec terminal.
//
// The bytes alone can't tell them apart: Ctrl+F3 is ESC[1;5R, a cursor position report too. xterm.js 6 knows: all
// data goes through CoreService.triggerDataEvent(data, wasUserInput), which fires `onUserInput` just before `onData`,
// both at once, for keys, IME, pastes and mouse reports, and only `onData` for replies. No public API says so, so
// `InputOrigin` listens to that internal event (term._core.coreService.onUserInput), checked for when the terminal is
// made; a test (terminal-input.test.ts) checks the installed xterm.js still fires it that way. Without it (a later
// xterm.js that moved it), the public `onKey` (fired just before a key's data) and the pane's own pastes mark input,
// and data that came without either counts as a reply only when it looks like one (`isHostReply`): IME text, mouse
// reports and anything unknown stay input, as before.
//
// Mouse reports (and xterm's binary `onBinary`, which carries only mouse reports) are input: they went through
// MultiExec before this and still do, so a click in a full-screen program reaches every terminal with one open, at
// the same cell. Replies written to the pane alone still tell the core the line may hold text MultiExec did not see
// (Terminals::write), so the next MultiExec line is rated as unreliable, as it was when replies went through it.

import type { Terminal } from "@xterm/xterm";

/* eslint-disable no-control-regex -- xterm.js's replies are escape sequences. */
const REPLIES = [
  /\x1b\[\??\d+;\d+(?:;\d+)?R/, // CPR, DECXCPR
  /\x1b\[[03]n/, // DSR: status
  /\x1b\[[?>][\d;]*c/, // DA, DA2
  /\x1b\[\??\d+;\d+\$y/, // DECRQM
  /\x1b\[[IO]/, // focus in, focus out
  /\x1b\[\d+(?:;\d+)*t/, // window reports (CSI 4 t, 6 t, 8 t...)
  /\x1b\](?:4;\d+|1\d);[^\x07\x1b]*(?:\x07|\x1b\\)/, // OSC 4, 10 to 19: colours
  /\x1bP[01][$+]r[^\x1b]*\x1b\\/, // DECRQSS, XTGETTCAP
];
/* eslint-enable no-control-regex */

const REPLY = new RegExp(`^(?:${REPLIES.map((r) => r.source).join("|")})+$`);

/** The data is one or more of the replies xterm.js makes to a host's queries. */
export function isHostReply(data: string): boolean {
  return REPLY.test(data);
}

/**
 * Whether one `onData` event is input: `exact` when xterm.js's own signal is wired (then `marked` is the whole
 * answer); otherwise `marked` is a key event or the pane's own paste, and unmarked data is a reply only when it looks
 * like one.
 */
export function isInput(data: string, { exact, marked }: { exact: boolean; marked: boolean }): boolean {
  if (marked) return true;
  if (exact) return false;
  return !isHostReply(data);
}

/** The narrow piece of xterm.js's internals used: CoreService's `onUserInput`. */
interface UserInputSignal {
  onUserInput(listener: () => void): unknown;
}

function userInputSignal(term: Terminal): UserInputSignal | null {
  const core = (term as unknown as { _core?: { coreService?: { onUserInput?: unknown } } })._core;
  const service = core?.coreService;
  return service && typeof service.onUserInput === "function" ? (service as UserInputSignal) : null;
}

/** Tells one terminal's input from its replies; ask `isInput` once for every `onData` event, in order. */
export class InputOrigin {
  /** xterm.js says itself which data is input. */
  readonly exact: boolean;
  private marked = false;

  constructor(term: Terminal) {
    const signal = userInputSignal(term);
    this.exact = signal !== null;
    if (signal) signal.onUserInput(() => this.mark());
    else term.onKey(() => this.mark());
  }

  /**
   * The next data event is input. It comes at once (xterm.js fires both in the same call), so the mark is dropped
   * once this task ends, in case none followed.
   */
  mark() {
    this.marked = true;
    queueMicrotask(() => {
      this.marked = false;
    });
  }

  /** For one data event: input (true), or a reply to the host (false). */
  isInput(data: string): boolean {
    const marked = this.marked;
    this.marked = false;
    return isInput(data, { exact: this.exact, marked });
  }
}
