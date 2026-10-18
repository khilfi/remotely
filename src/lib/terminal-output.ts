// SS-11: terminals' whole scrollback copied, printed or saved, one terminal or several at once. The text
// is read from xterm.js here; the core scrubs each terminal's login secrets from it first, and saving
// (in a dialog the core opens) and printing are audited there, never the text itself.

import { api, type HostFacts, type SaveLayout, type TerminalText } from "@/lib/api";
import { factsTitle, type PaneSession } from "@/lib/terminal-session";

/** A terminal as the output actions name it: the session's name and what the host said. */
export function paneTitle(name: string, facts: HostFacts | null): string {
  const seen = factsTitle(facts);
  if (!seen) return name;
  if (name === facts?.hostname || name === facts?.ip || name === seen) return seen;
  return `${name} — ${seen}`;
}

export interface NamedPane {
  pane: PaneSession;
  title: string;
}

export function texts(panes: NamedPane[]): TerminalText[] {
  return panes.map(({ pane, title }) => ({ terminalId: pane.terminalId, title, text: pane.bufferText() }));
}

/** Several terminals in one text, each under a header, as the core's combined file has them. */
export function combine(items: TerminalText[]): string {
  if (items.length === 1) return items[0].text;
  return items.map((i) => `===== ${i.title} =====\n${i.text}`).join("\n\n");
}

export async function copyOutput(panes: NamedPane[]) {
  const clean = await api.terminalOutputText(texts(panes));
  await navigator.clipboard.writeText(combine(clean));
}

/** Asks where to save (a file, or a folder for one file each). null when the user cancelled. */
export function saveOutput(panes: NamedPane[], layout: SaveLayout) {
  return api.terminalOutputSave(texts(panes), layout);
}

/** Prints through a hidden frame: a heading and the text per terminal, each from a new page. */
export async function printOutput(panes: NamedPane[]) {
  const clean = await api.terminalOutputPrint(texts(panes));
  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.style.position = "fixed";
  frame.style.width = "0";
  frame.style.height = "0";
  frame.style.border = "0";
  document.body.appendChild(frame);
  const doc = frame.contentDocument;
  const win = frame.contentWindow;
  if (!doc || !win) {
    frame.remove();
    throw new Error("Printing is not available here.");
  }
  doc.title = clean.length === 1 ? clean[0].title : `Output of ${clean.length} terminals`;
  const style = doc.createElement("style");
  style.textContent = `
    body { font-family: 'Cascadia Mono', Consolas, monospace; margin: 0; }
    h1 { font: 600 12pt system-ui, sans-serif; margin: 0 0 6pt; }
    pre { font-size: 8.5pt; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }
    section + section { break-before: page; }
  `;
  doc.head.appendChild(style);
  for (const item of clean) {
    const section = doc.createElement("section");
    const heading = doc.createElement("h1");
    heading.textContent = item.title;
    const pre = doc.createElement("pre");
    // Text only: nothing the host printed can become markup.
    pre.textContent = item.text;
    section.append(heading, pre);
    doc.body.appendChild(section);
  }
  const done = () => window.setTimeout(() => frame.remove(), 500);
  win.addEventListener("afterprint", done, { once: true });
  win.focus();
  win.print();
  // Some print dialogs don't fire afterprint; never leave the frame behind for long.
  window.setTimeout(() => frame.remove(), 60_000);
}
