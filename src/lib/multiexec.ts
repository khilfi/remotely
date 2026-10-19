// SS-10 MultiExec, the UI side: while it is on, each picked pane hands its keys here instead of writing them to its
// own terminal, and they go to the core one write at a time, in order (keys typed meanwhile are batched). The core
// sends them on to every picked terminal, holds Enter and rates the line (see crates/core/src/terminal/multiexec.rs);
// what it did comes back as an outcome for the page to show (a held line may need the approval dialog).

import { api, type MultiExecOutcome } from "@/lib/api";

export class MultiExecSender {
  private queue: { from: string; bytes: Uint8Array }[] = [];
  private sending = false;

  constructor(
    private readonly onOutcome: (outcome: MultiExecOutcome, from: string) => void,
    private readonly onError: (err: unknown) => void,
  ) {}

  /** Keys typed into terminal `from` (the core's id). */
  send(from: string, bytes: Uint8Array) {
    this.queue.push({ from, bytes });
    this.flush();
  }

  private flush() {
    if (this.sending || this.queue.length === 0) return;
    // Keys typed into the same terminal while a write was in flight go together.
    const from = this.queue[0].from;
    let count = 0;
    while (count < this.queue.length && this.queue[count].from === from) count++;
    const parts = this.queue.splice(0, count);
    const data = new Uint8Array(parts.reduce((n, p) => n + p.bytes.length, 0));
    let at = 0;
    for (const p of parts) {
      data.set(p.bytes, at);
      at += p.bytes.length;
    }
    this.sending = true;
    api
      .multiExecInput(from, data)
      .then((outcome) => this.onOutcome(outcome, from), this.onError)
      .finally(() => {
        this.sending = false;
        this.flush();
      });
  }
}
