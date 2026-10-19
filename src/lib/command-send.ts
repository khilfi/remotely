// BX-08: how a command from the command panel reaches terminals. It goes in as if the user typed it, through
// each pane's own input (xterm.js's paste, bracketed when the shell asked for it, so a multi-line command waits for
// Enter), and Enter only when asked. An interactive shell skips the approval flow, as typing does.
//
// P5 sends to the current pane only. P6's MultiExec will call this with the panes picked for it and must hold the
// Enter until its policy check (read-only goes at once, anything higher shows the approval dialog): `enter` is the
// one place that runs a command, so that check goes here, before `pane.pressEnter()`.

import type { PaneSession } from "@/lib/terminal-session";

export interface SendOptions {
  /** Press Enter after the command (Shift+click), so it runs. */
  enter: boolean;
}

/** Pastes `command` into each connected pane, then presses Enter when asked. Returns how many panes got it. */
export function sendCommand(panes: PaneSession[], command: string, { enter }: SendOptions): number {
  const ready = panes.filter((pane) => pane.connected);
  for (const pane of ready) {
    pane.pasteCommand(command);
    if (enter) pane.pressEnter();
  }
  ready[0]?.focus();
  return ready.length;
}
